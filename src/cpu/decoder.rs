use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InstructionPrefix {
    Lock,
    Rep,
    Repne,
    OperandSize,
    AddressSize,
    FsSegment,
    GsSegment,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SegmentRegister {
    Fs,
    Gs,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ByteRegister {
    Al,
    Cl,
    Dl,
    Bl,
    Ah,
    Ch,
    Dh,
    Bh,
    Spl,
    Bpl,
    Sil,
    Dil,
    R8b,
    R9b,
    R10b,
    R11b,
    R12b,
    R13b,
    R14b,
    R15b,
}

impl ByteRegister {
    fn from_modrm(code: u8, rex: Option<RexPrefix>, arch: GuestArch) -> Self {
        match code & 0x0f {
            0 => Self::Al,
            1 => Self::Cl,
            2 => Self::Dl,
            3 => Self::Bl,
            4 => {
                if arch == GuestArch::X64 && rex.is_some() {
                    Self::Spl
                } else {
                    Self::Ah
                }
            }
            5 => {
                if arch == GuestArch::X64 && rex.is_some() {
                    Self::Bpl
                } else {
                    Self::Ch
                }
            }
            6 => {
                if arch == GuestArch::X64 && rex.is_some() {
                    Self::Sil
                } else {
                    Self::Dh
                }
            }
            7 => {
                if arch == GuestArch::X64 && rex.is_some() {
                    Self::Dil
                } else {
                    Self::Bh
                }
            }
            8 => Self::R8b,
            9 => Self::R9b,
            10 => Self::R10b,
            11 => Self::R11b,
            12 => Self::R12b,
            13 => Self::R13b,
            14 => Self::R14b,
            _ => Self::R15b,
        }
    }

    pub fn full_register(self) -> Register {
        match self {
            Self::Al => Register::Rax,
            Self::Cl => Register::Rcx,
            Self::Dl => Register::Rdx,
            Self::Bl => Register::Rbx,
            Self::Ah => Register::Rax,
            Self::Ch => Register::Rcx,
            Self::Dh => Register::Rdx,
            Self::Bh => Register::Rbx,
            Self::Spl => Register::Rsp,
            Self::Bpl => Register::Rbp,
            Self::Sil => Register::Rsi,
            Self::Dil => Register::Rdi,
            Self::R8b => Register::R8,
            Self::R9b => Register::R9,
            Self::R10b => Register::R10,
            Self::R11b => Register::R11,
            Self::R12b => Register::R12,
            Self::R13b => Register::R13,
            Self::R14b => Register::R14,
            Self::R15b => Register::R15,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentBases {
    pub fs: u64,
    pub gs: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RexPrefix {
    pub w: bool,
    pub r: bool,
    pub x: bool,
    pub b: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct VexPrefix {
    pub r: bool,
    pub vvvv: u8,
    pub w: bool,
    pub l: bool,
    pub pp: u8,
    /// Map select for 3-byte VEX: 0=0F, 1=0F38, 2=0F3A.
    /// Always 0 for 2-byte VEX (0xC5).
    pub map_select: u8,
}

impl VexPrefix {
    fn rex(self) -> Option<RexPrefix> {
        Some(RexPrefix {
            w: false,
            r: self.r,
            x: false,
            b: false,
        })
    }

    fn width_bytes(self) -> usize {
        if self.l { 32 } else { 16 }
    }
}

/// EVEX prefix decoded from the 4-byte 0x62 prefix.
/// EVEX byte 0: 0x62 (marker)
/// EVEX byte 1: [R' R X B R'' 0 0 m] — R'=bit7, R=bit6, X=bit5, B=bit4, R''=bit3, m=map_select bit0
/// EVEX byte 2: [W v v v v 1 pp] — W=bit7, vvvv=bits6:3, pp=bits1:0
/// EVEX byte 3: [z L' L b V' a a a] — z=bit7, L'L=bits6:5 (vec len), b=bit4 (bcast), V'=bit3 (vvvv bit4), aaa=bits2:0 (opmask)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvexPrefix {
    pub r: bool,
    pub x: bool,
    pub b: bool,
    pub r_prime: bool,
    pub r_prime2: bool,
    pub vvvv: u8, // 5-bit vvvv (0-31), V'|vvvv
    pub w: bool,
    pub ll: u8,         // 0=128-bit, 1=256-bit, 2=512-bit
    pub pp: u8,         // 00=none, 01=0x66, 10=0xF3, 11=0xF2
    pub z: bool,        // zero-masking
    pub bcast: bool,    // broadcast/rounding
    pub aaa: u8,        // opmask register k0-k7
    pub map_select: u8, // 0=0F, 1=0F38, 2=0F3A
}

impl EvexPrefix {
    fn width_bytes(self) -> usize {
        match self.ll {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryOperand {
    pub base: Option<Register>,
    pub index: Option<Register>,
    pub scale: u8,
    pub displacement: i32,
    pub rip_relative: bool,
    #[serde(default)]
    pub rip_base: u64,
    #[serde(default)]
    pub segment: Option<SegmentRegister>,
    #[serde(default)]
    pub address_size_32: bool,
    /// Full 64-bit absolute address (MOFFS64 form). When `Some`, the address
    /// is used directly (plus segment base if any), bypassing displacement /
    /// base / index / rip_relative computation.
    #[serde(default)]
    pub absolute_address: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Operand {
    Register(Register),
    Register8(ByteRegister),
    ImmediateI64(i64),
    ImmediateU64(u64),
    Memory(MemoryOperand),
    Xmm(u8),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecodedOpcode {
    Cpuid,
    Xgetbv,
    MovImm,
    MovReg,
    MovReg8,
    AddImm,
    AddReg,
    AdcImm,
    AdcReg,
    OrImm,
    SubImm,
    AndImm,
    AndReg,
    AndReg8,
    BitTest,
    RolImm,
    RorImm,
    RclImm,
    RcrImm,
    RolCl,
    RclCl,
    RcrCl,
    ShlImm,
    ShrImm,
    SarImm,
    ShlCl,
    ShrCl,
    RorCl,
    SarCl,
    ShldImm,
    ShldCl,
    ShrdImm,
    ImulImm,
    ImulReg,
    MulAcc,
    Div,
    Idiv,
    SubReg8,
    Neg,
    Not,
    Cdq,
    Movs,
    Stos,
    Lods,
    SubReg,
    SbbReg,
    SbbReg8,
    SbbImm,
    Cmp,
    Test,
    Xchg,
    Bound,
    Movsxd,
    Movzx,
    XorImm,
    XorReg,
    XorReg8,
    OrReg,
    OrReg8,
    IncReg,
    DecReg,
    Cmovcc,
    MovLoad,
    MovLoad8,
    MovStore,
    MovStore8,
    MovStoreImm,
    Nop,
    CallRel,
    CallRegister,
    CallMemory,
    JmpRegister,
    JmpMemory,
    Setcc,
    Jcc,
    JmpRel,
    Lea,
    PushReg,
    PushAll,
    PopAll,
    PushMemory,
    PushImm,
    PushFlags,
    PopReg,
    PopMemory,
    PopFlags,
    Sahf,
    Lahf,
    SetCarryFlag {
        value: bool,
    },
    Cmc,
    LoadSegment {
        segment: u8,
    },
    Cld,
    Leave,
    Ret,
    Popcnt,
    Lzcnt,
    Bsf,
    Movsx,
    MovdToXmm,
    MovdFromXmm,
    Pshufd,
    Pshuflw,
    Psrldq,
    Pslldq,
    Movlhps,
    Cvtpd2ps,
    Cvtdq2pd,
    Addsd,
    Divss,
    Comiss,
    SseArith {
        op: SseArithOp,
        kind: SseFloatKind,
    },
    SseSqrt {
        kind: SseFloatKind,
    },
    SseRcp,
    SseRsqrt,
    CvtIntToFloat,
    CvtFloatToInt,
    Ucomi,
    Pcmpistri,
    ImulAcc,
    XmmMove,
    VectorMove,
    Pxor,
    VectorOr,
    VectorXor,
    Paddd,
    Paddq,
    Psubd,
    Pmulld,
    VectorAddQ,
    VectorCompareEqBytes,
    VectorMoveMaskBytes,
    VectorAnd,
    VectorAndNot,
    VectorIntOp {
        kind: VectorIntKind,
    },
    VzeroUpper,
    Fnclex,
    FldConst,
    FildI32,
    FildI64,
    FldReal32,
    FldReal64,
    Fldcw,
    Fchs,
    Fxch,
    Fstcw,
    FstReal32,
    FstReal64,
    FaddReal64,
    FstpReal32,
    FstpSt,
    FstpReal,
    Fcomi,
    Fcomip,
    Faddp,
    FmulReal64,
    FdivReal64,
    Fmul,
    Fdiv,
    Fdivp,
    Fninit,
    Ldmxcsr,
    Stmxcsr,
    Rdrand,
    Rdseed,
    Rdpmc,
    Rdtsc,
    Bswap,
    Ud2,
    Clflush,
    Clflushopt,
    Clwb,
    Pcommit,
    // TSX/RTM transactional synchronization
    Xbegin,
    Xend,
    Xabort,
    Xtest,
    // SGX enclave instructions (detection-only stubs)
    Encls,
    Enclu,
    // CET shadow stack
    Savesp,
    Rstorssp,
    Incssp,
    Wrss,
    Wruss,
    // MPX bounds checking
    Bndmk,
    Bndcl,
    Bndcu,
    Bndcn,
    Bndmov,
    Prefetch,
    Andn,
    Bextr,
    Blsi,
    Blsmsk,
    Blsr,
    Bzhi,
    Mulx,
    Pdep,
    Pext,
    Rorx,
    Sarx,
    Shrx,
    Shlx,
    // FMA instructions (VEX/EVZX encoded in 0F38 map)
    Vfmadd132ps,
    Vfmadd132pd,
    Vfmadd213ps,
    Vfmadd213pd,
    Vfmadd231ps,
    Vfmadd231pd,
    Vfmsub132ps,
    Vfmsub132pd,
    Vfmsub213ps,
    Vfmsub213pd,
    Vfmsub231ps,
    Vfmsub231pd,
    Vfnmadd132ps,
    Vfnmadd132pd,
    Vfnmadd213ps,
    Vfnmadd213pd,
    Vfnmadd231ps,
    Vfnmadd231pd,
    LockCmpxchg,
    LockCmpxchg8b,
    LockXadd,
    Int3,
    /// `INT imm8` (0xCD) — software interrupt, vector in immediate byte.
    Int {
        vector: u8,
    },
    PushSeg,
    PopSeg,
    Loop,
    // AVX-512 EVEX map_select=2 opcodes (0F3A map)
    Vshufps,
    Vshufpd,
    ValignD,
    ValignQ,
    Vinsertf128,
    Vinsertf256,
    Vinsertf512,
    Vinserti128,
    Vinserti256,
    Vinserti512,
    Vinsertf32x4,
    Vinsertf64x2,
    Vinsertf32x8,
    Vinsertf64x4,
    Vinserti32x4,
    Vinserti64x2,
    Vinserti32x8,
    Vinserti64x4,
    Vextractf128,
    Vextractf256,
    Vextractf512,
    Vextracti128,
    Vextracti256,
    Vextracti512,
    Vextractf32x4,
    Vextractf64x2,
    Vextractf32x8,
    Vextractf64x4,
    Vextracti32x4,
    Vextracti64x2,
    Vextracti32x8,
    Vextracti64x4,
    Vbroadcastf32x4,
    Vbroadcastf64x2,
    Vbroadcastf32x8,
    Vbroadcastf64x4,
    Vbroadcasti32x4,
    Vbroadcasti64x2,
    Vbroadcasti32x8,
    Vbroadcasti64x4,
    Vbroadcastm,
    // AVX-512 EVEX map_select=0 opcodes (0F map) - arithmetic
    Vaddps,
    Vaddpd,
    Vmulps,
    Vmulpd,
    Vsubps,
    Vsubpd,
    Vdivps,
    Vdivpd,
    Vminps,
    Vminpd,
    Vmaxps,
    Vmaxpd,
    Vsqrtps,
    Vsqrtpd,
    Vcmpps,
    Vcmppd,
    Vcvtps2pd,
    Vcvtpd2ps,
    Vcvtps2dq,
    Vcvtdq2ps,
    Vcvtps2qq,
    Vcvtqq2ps,
    Vcvtpd2dq,
    Vcvtdq2pd,
    Vcvtusi2ss,
    Vcvtusi2sd,
    Vcvtss2si,
    Vcvtsd2si,
    Vcvttss2si,
    Vcvttsd2si,
    Vcvtss2usi,
    Vcvtsd2usi,
    // AVX-512 EVEX map_select=1 opcodes (0F38 map) - additional
    Vpermd,
    Vpermq,
    Vpermps,
    Vpermpd,
    Vpermi2d,
    Vpermi2q,
    Vpermi2ps,
    Vpermi2pd,
    Vpermt2d,
    Vpermt2q,
    Vpermt2ps,
    Vpermt2pd,
    Vpermil2ps,
    Vpermil2pd,
    Vpermilps,
    Vpermilpd,
    Vfixupimmps,
    Vfixupimmpd,
    Vgetexpps,
    Vgetexppd,
    Vgetmantps,
    Vgetmantpd,
    Vreduceps,
    Vreducepd,
    Vrangeps,
    Vrangepd,
    Vscalefps,
    Vscalefpd,
    Vfpclassps,
    Vfpclasspd,
    Vpternlogd,
    Vpternlogq,
    Vpconflictd,
    Vpconflictq,
    Vcompressps,
    Vcompresspd,
    Vexpandps,
    Vexpandpd,
    Vgatherdps,
    Vgatherdpd,
    Vgatherqps,
    Vgatherqpd,
    Vscatterdps,
    Vscatterdpd,
    Vscatterqps,
    Vscatterqpd,
    // Mask register operations
    KandB,
    KandW,
    KandD,
    KandQ,
    KorB,
    KorW,
    KorD,
    KorQ,
    KxorB,
    KxorW,
    KxorD,
    KxorQ,
    KnotB,
    KnotW,
    KnotD,
    KnotQ,
    KshiftlB,
    KshiftlW,
    KshiftlD,
    KshiftlQ,
    KshiftrB,
    KshiftrW,
    KshiftrD,
    KshiftrQ,
    KaddB,
    KaddW,
    KaddD,
    KaddQ,
    KtestB,
    KtestW,
    KtestD,
    KtestQ,
    Kunpckbw,
    Kunpckwd,
    Kunpckdq,
    // AES-NI instructions (0x66 0x0F 0x38 0xDC-0xDF, 0xDB; 0x66 0x0F 0x3A 0xDF)
    Aesdec,
    Aesdeclast,
    Aesenc,
    Aesenclast,
    Aesimc,
    Aeskeygenassist,
    // PCLMULQDQ (0x66 0x0F 0x3A 0x44)
    Pclmulqdq,
    // SHA instructions (0x0F 0x38 0xC8-0xCD; 0x0F 0x3A 0xCC)
    Sha1rnds4,
    Sha1nexte,
    Sha1msg1,
    Sha1msg2,
    Sha256rnds2,
    Sha256msg1,
    Sha256msg2,
    // XSAVE/XRSTOR/FXSAVE/FXRSTOR (0x0F 0xAE /0,/1,/4,/5,/6)
    Fxsave,
    Fxrstor,
    Xsave,
    Xsaveopt,
    Xrstor,
    // String compare/scan (0xA6/0xA7 CMPS, 0xAE/0xAF SCAS)
    Cmps,
    Scas,
    // System instructions
    Hlt,
    Cli,
    Sti,
    Std,
    PortIn,
    PortOut,
    // ADX instructions (0x66/F3 0x0F 0x38 0xF6)
    Adcx,
    Adox,
    // Debug register access (0x0F 0x21 MOV r,DR / 0x0F 0x23 MOV DR,r)
    MovFromDr,
    MovToDr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompareOperand {
    Register(Register),
    Register8(ByteRegister),
    Memory(MemoryOperand),
    ImmediateU64(u64),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VectorOperand {
    Register(u8),
    Memory(MemoryOperand),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub address: u64,
    pub size: usize,
    pub prefixes: Vec<InstructionPrefix>,
    pub rex: Option<RexPrefix>,
    pub opcode: DecodedOpcode,
    pub operands: Vec<Operand>,
    pub precise_faulting_memory: bool,
    #[serde(default)]
    pub evex_info: EvexInfo,
}

// ---------------------------------------------------------------------------
// Hot-block decode cache
// ---------------------------------------------------------------------------
//
// Guest blocks are decoded repeatedly (the guest executes the same basic
// blocks thousands of times).  `decode_block` is a pure function of
// `(bytes, start_address, arch)`, so its result is memoised for hot blocks.
// The raw bytes are stored alongside the decoded sequence and compared
// exactly, so a collision or a self-modifying-code update can never return a
// stale decode: different bytes are a miss and replace the entry.

/// Decoded-block cache hits (repeated decode of the same bytes/address/arch).
pub static DECODE_CACHE_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Decoded-block cache misses (first decode, or bytes changed).
pub static DECODE_CACHE_MISSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Decoded-block cache entries evicted to stay within the capacity bound.
pub static DECODE_CACHE_EVICTIONS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Snapshot of the hot-block decode-cache counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DecodeCacheTelemetry {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

/// Read the current hot-block decode-cache counters.
pub fn decode_cache_telemetry() -> DecodeCacheTelemetry {
    use std::sync::atomic::Ordering;
    DecodeCacheTelemetry {
        hits: DECODE_CACHE_HITS.load(Ordering::Relaxed),
        misses: DECODE_CACHE_MISSES.load(Ordering::Relaxed),
        evictions: DECODE_CACHE_EVICTIONS.load(Ordering::Relaxed),
    }
}

/// Reset the hot-block decode-cache counters (test/diagnostic helper).
pub fn reset_decode_cache_telemetry() {
    use std::sync::atomic::Ordering;
    DECODE_CACHE_HITS.store(0, Ordering::Relaxed);
    DECODE_CACHE_MISSES.store(0, Ordering::Relaxed);
    DECODE_CACHE_EVICTIONS.store(0, Ordering::Relaxed);
}

/// Maximum number of decoded blocks retained.  Sized to hold the working set
/// of a hot guest loop plus its callers without unbounded growth.
pub(crate) const DECODE_CACHE_CAPACITY: usize = 1024;

pub(crate) fn guest_arch_tag(arch: GuestArch) -> u8 {
    match arch {
        GuestArch::X64 => 0,
        GuestArch::X86 => 1,
    }
}

pub(crate) struct DecodeCacheEntry {
    /// Exact source bytes; a mismatch invalidates the entry.
    bytes: Box<[u8]>,
    decoded: Arc<Vec<DecodedInstruction>>,
    /// Monotonic last-use stamp for approximate-LRU eviction.
    last_use: u64,
}

pub(crate) struct DecodeCache {
    entries: HashMap<(u64, usize, u8), DecodeCacheEntry>,
    clock: u64,
}

impl DecodeCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            clock: 0,
        }
    }

    pub(crate) fn get(
        &mut self,
        address: u64,
        len: usize,
        arch_tag: u8,
        bytes: &[u8],
    ) -> Option<Arc<Vec<DecodedInstruction>>> {
        let entry = self.entries.get_mut(&(address, len, arch_tag))?;
        if entry.bytes.as_ref() != bytes {
            return None;
        }
        self.clock += 1;
        entry.last_use = self.clock;
        Some(Arc::clone(&entry.decoded))
    }

    pub(crate) fn insert(
        &mut self,
        address: u64,
        len: usize,
        arch_tag: u8,
        bytes: &[u8],
        decoded: Arc<Vec<DecodedInstruction>>,
    ) {
        if self.entries.len() >= DECODE_CACHE_CAPACITY
            && let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_use)
                .map(|(key, _)| *key)
        {
            self.entries.remove(&oldest_key);
            DECODE_CACHE_EVICTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.clock += 1;
        self.entries.insert(
            (address, len, arch_tag),
            DecodeCacheEntry {
                bytes: bytes.to_vec().into_boxed_slice(),
                decoded,
                last_use: self.clock,
            },
        );
    }
}

pub(crate) static DECODE_CACHE: std::sync::LazyLock<Mutex<DecodeCache>> =
    std::sync::LazyLock::new(|| Mutex::new(DecodeCache::new()));

pub fn decode_block(
    bytes: &[u8],
    start_address: u64,
    arch: GuestArch,
) -> AppResult<Vec<DecodedInstruction>> {
    use std::sync::atomic::Ordering;

    // Hot path: exact-bytes memoised decode.
    if let Ok(mut cache) = DECODE_CACHE.lock() {
        if let Some(decoded) = cache.get(start_address, bytes.len(), guest_arch_tag(arch), bytes) {
            DECODE_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
            return Ok((*decoded).clone());
        }
    }
    DECODE_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);

    let decoded = decode_block_uncached(bytes, start_address, arch)?;
    if let Ok(mut cache) = DECODE_CACHE.lock() {
        cache.insert(
            start_address,
            bytes.len(),
            guest_arch_tag(arch),
            bytes,
            Arc::new(decoded.clone()),
        );
    }
    Ok(decoded)
}

pub(crate) fn decode_block_uncached(
    bytes: &[u8],
    start_address: u64,
    arch: GuestArch,
) -> AppResult<Vec<DecodedInstruction>> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();
    while cursor < bytes.len() {
        let address = start_address + cursor as u64;
        let mut prefixes = Vec::new();
        let mut rex = None;
        let mut vex = None;
        let mut local = cursor;
        loop {
            let byte = *bytes.get(local).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    "unexpected end of instruction stream",
                )
            })?;
            match byte {
                0xF0 => prefixes.push(InstructionPrefix::Lock),
                0xF3 => prefixes.push(InstructionPrefix::Rep),
                0xF2 => prefixes.push(InstructionPrefix::Repne),
                0x66 => prefixes.push(InstructionPrefix::OperandSize),
                0x67 => prefixes.push(InstructionPrefix::AddressSize),
                0x26 | 0x2E | 0x36 | 0x3E => {}
                0x64 => prefixes.push(InstructionPrefix::FsSegment),
                0x65 => prefixes.push(InstructionPrefix::GsSegment),
                0x40..=0x4F if arch == GuestArch::X64 => {
                    rex = Some(RexPrefix {
                        w: byte & 0x08 != 0,
                        r: byte & 0x04 != 0,
                        x: byte & 0x02 != 0,
                        b: byte & 0x01 != 0,
                    });
                }
                _ => break,
            }
            local += 1;
        }
        // Check for EVEX prefix (0x62) — only valid in 64-bit mode.
        // In 32-bit mode (X86), 0x62 is the BOUND instruction and must not
        // be consumed as an EVEX prefix.
        let mut evex = None;
        if arch == GuestArch::X64
            && let Some((parsed, consumed)) = decode_evex_prefix(bytes, local)?
        {
            evex = Some(parsed);
            local += consumed;
        }
        if let Some((parsed, consumed)) = parse_vex_prefix(bytes, local, arch)? {
            vex = Some(parsed);
            local += consumed;
        }
        let opcode = *bytes
            .get(local)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, "missing instruction opcode"))?;
        local += 1;
        let address_size_32 =
            arch == GuestArch::X64 && prefixes.contains(&InstructionPrefix::AddressSize);
        let instruction = if let Some(evex) = evex {
            decode_evex_instruction(
                bytes,
                local,
                cursor,
                address,
                &prefixes,
                arch,
                address_size_32,
                evex,
                opcode,
            )?
        } else if let Some(vex) = vex {
            decode_vex_instruction(
                bytes,
                local,
                cursor,
                address,
                &prefixes,
                arch,
                address_size_32,
                vex,
                opcode,
            )?
        } else {
            match opcode {
                0x50..=0x57 => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::PushReg,
                    operands: vec![Operand::Register(Register::from_modrm(
                        ((opcode - 0x50) & 0x07) | rex_register_low(rex),
                    ))],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0x58..=0x5F => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::PopReg,
                    operands: vec![Operand::Register(Register::from_modrm(
                        ((opcode - 0x58) & 0x07) | rex_register_low(rex),
                    ))],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0x9C => {
                    let width = operand_width(rex, &prefixes, arch);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::PushFlags,
                        operands: vec![Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x9D => {
                    let width = operand_width(rex, &prefixes, arch);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::PopFlags,
                        operands: vec![Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x9E => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Sahf,
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0x9F => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Lahf,
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0x60 | 0x61 if arch == GuestArch::X86 => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: if opcode == 0x60 {
                        DecodedOpcode::PushAll
                    } else {
                        DecodedOpcode::PopAll
                    },
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xF5 => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Cmc,
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xF8 => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::SetCarryFlag { value: false },
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xF9 => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::SetCarryFlag { value: true },
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xFC => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Cld,
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0x40..=0x47 if arch == GuestArch::X86 => {
                    let width = operand_width(rex, &prefixes, arch);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::IncReg,
                        operands: vec![
                            Operand::Register(Register::from_modrm(opcode - 0x40)),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x48..=0x4F if arch == GuestArch::X86 => {
                    let width = operand_width(rex, &prefixes, arch);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::DecReg,
                        operands: vec![
                            Operand::Register(Register::from_modrm(opcode - 0x48)),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x68 => {
                    let width = arch.pointer_bytes();
                    let value =
                        sign_extend(read_immediate(bytes, local, 4)?, 4) & width_mask(width);
                    local += 4;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::PushImm,
                        operands: vec![
                            Operand::ImmediateU64(value),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x6A => {
                    let width = arch.pointer_bytes();
                    let value =
                        sign_extend(read_immediate(bytes, local, 1)?, 1) & width_mask(width);
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::PushImm,
                        operands: vec![
                            Operand::ImmediateU64(value),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                // BOUND r16/32, m16&16 / m32&32 — opcode 0x62 (32-bit mode only).
                // In 64-bit mode, 0x62 is the EVEX prefix and is handled above.
                // BOUND checks if a register value is within bounds specified by a
                // memory operand (pair of signed values). If out of bounds, raises #BR (INT 5).
                0x62 => {
                    if arch == GuestArch::X64 {
                        // In 64-bit mode, 0x62 should have been consumed as EVEX prefix.
                        // If we reach here, it means the EVEX decode failed or was skipped.
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "0x62 in 64-bit mode without valid EVEX prefix",
                        ));
                    }
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let reg = Register::from_modrm(modrm.reg);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let Operand::Memory(address_operand) = rm_operand else {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "BOUND requires a memory operand for bounds pair",
                        ));
                    };
                    // Operand size: 16-bit with operand size prefix, otherwise 32-bit
                    let width = if prefixes.contains(&InstructionPrefix::OperandSize) {
                        2
                    } else {
                        4
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Bound,
                        operands: vec![
                            Operand::Register(reg),
                            Operand::Memory(address_operand),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x63 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let src = compare_operand(modrm_operand(
                        &modrm,
                        arch,
                        &prefixes,
                        address + (local - cursor) as u64,
                    ));
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Movsxd,
                        operands: vec![
                            Operand::Register(Register::from_modrm(modrm.reg)),
                            compare_operand_to_operand(src),
                            Operand::ImmediateU64(4),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x90 => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Nop,
                    operands: Vec::new(),
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0x91..=0x97 => {
                    let width = operand_width(rex, &prefixes, arch);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Xchg,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::Register(Register::from_modrm(opcode - 0x90)),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x98 => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Movsxd,
                    operands: vec![
                        Operand::Register(Register::Rax),
                        Operand::Register(Register::Rax),
                        Operand::ImmediateU64(4),
                    ],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xB0..=0xB7 => {
                    let imm = read_immediate(bytes, local, 1)?;
                    local += 1;
                    let dst = ByteRegister::from_modrm(
                        ((opcode - 0xB0) & 0x07) | rex_register_low(rex),
                        rex,
                        arch,
                    );
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::MovImm,
                        operands: vec![Operand::Register8(dst), Operand::ImmediateU64(imm)],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xB8..=0xBF => {
                    let imm_size =
                        if arch == GuestArch::X64 && rex.map(|value| value.w).unwrap_or(false) {
                            8
                        } else {
                            4
                        };
                    let imm = read_immediate(bytes, local, imm_size)?;
                    local += imm_size;
                    let dst =
                        Register::from_modrm(((opcode - 0xB8) & 0x07) | rex_register_low(rex));
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::MovImm,
                        operands: vec![Operand::Register(dst), Operand::ImmediateU64(imm)],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x04 => {
                    let value = read_immediate(bytes, local, 1)?;
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AddImm,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(value),
                            Operand::ImmediateU64(1),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x05 => {
                    let width = operand_width(rex, &prefixes, arch);
                    let value = read_immediate(bytes, local, 4)?;
                    local += 4;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AddImm,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(value),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x14 => {
                    let value = read_immediate(bytes, local, 1)?;
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AdcImm,
                        operands: vec![
                            Operand::Register8(ByteRegister::Al),
                            Operand::ImmediateU64(value),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x15 => {
                    let width = operand_width(rex, &prefixes, arch);
                    let value = read_immediate(bytes, local, 4)?;
                    local += 4;
                    let imm_value = if width == 8 {
                        sign_extend(value, 4)
                    } else {
                        value
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AdcImm,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(imm_value),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x1C => {
                    let value = read_immediate(bytes, local, 1)?;
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::SbbImm,
                        operands: vec![
                            Operand::Register8(ByteRegister::Al),
                            Operand::ImmediateU64(value),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x1D => {
                    let width = operand_width(rex, &prefixes, arch);
                    let value = read_immediate(bytes, local, 4)?;
                    local += 4;
                    let imm_value = if width == 8 {
                        sign_extend(value, 4)
                    } else {
                        value
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::SbbImm,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(imm_value),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x06 | 0x0E | 0x16 => {
                    let width = arch.pointer_bytes();
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::PushSeg,
                        operands: vec![Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x25 => {
                    let width = operand_width(rex, &prefixes, arch);
                    let value = read_immediate(bytes, local, 4)?;
                    local += 4;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AndImm,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(value),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x24 => {
                    let value = read_immediate(bytes, local, 1)?;
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AndImm,
                        operands: vec![
                            Operand::Register8(ByteRegister::Al),
                            Operand::ImmediateU64(value),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x0C => {
                    let imm = read_immediate(bytes, local, 1)?;
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::OrImm,
                        operands: vec![
                            Operand::Register8(ByteRegister::Al),
                            Operand::ImmediateU64(imm),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x0D => {
                    let width = operand_width(rex, &prefixes, arch);
                    let raw = read_immediate(bytes, local, 4)?;
                    local += 4;
                    let value = if width == 8 { sign_extend(raw, 4) } else { raw };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::OrImm,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(value),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x2D => {
                    let width = operand_width(rex, &prefixes, arch);
                    let value = read_immediate(bytes, local, 4)?;
                    local += 4;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::SubImm,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(value),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x2C => {
                    let value = read_immediate(bytes, local, 1)?;
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::SubReg8,
                        operands: vec![
                            Operand::Register8(ByteRegister::Al),
                            Operand::ImmediateU64(value),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x34 => {
                    let value = read_immediate(bytes, local, 1)?;
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::XorImm,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(value),
                            Operand::ImmediateU64(1),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x18 | 0x28 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let src = ByteRegister::from_modrm(modrm.reg, rex, arch);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = match rm_operand {
                        Operand::Register(_) => (
                            vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::Register8(src),
                            ],
                            false,
                        ),
                        Operand::Memory(address_operand) => (
                            vec![Operand::Memory(address_operand), Operand::Register8(src)],
                            true,
                        ),
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unexpected rm operand for opcode {opcode:#x}: {other:?}"),
                            ));
                        }
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: if opcode == 0x18 {
                            DecodedOpcode::SbbReg8
                        } else {
                            DecodedOpcode::SubReg8
                        },
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x19 | 0x1B | 0x29 | 0x2B => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = operand_width(rex, &prefixes, arch);
                    let reg = Register::from_modrm(modrm.reg);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = if opcode == 0x19 || opcode == 0x29 {
                        match rm_operand {
                            Operand::Register(rm) => (
                                vec![
                                    Operand::Register(rm),
                                    Operand::Register(reg),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand)
                                if opcode == 0x29 || opcode == 0x19 =>
                            {
                                (
                                    vec![
                                        Operand::Memory(address_operand),
                                        Operand::Register(reg),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    true,
                                )
                            }
                            Operand::Memory(_) => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "SBB register-to-memory form is not implemented",
                                ));
                            }
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!(
                                        "unexpected rm operand for opcode 0x{opcode:02x}: {other:?}"
                                    ),
                                ));
                            }
                        }
                    } else {
                        (
                            vec![
                                Operand::Register(reg),
                                rm_operand.clone(),
                                Operand::ImmediateU64(width as u64),
                            ],
                            !matches!(rm_operand, Operand::Register(_)),
                        )
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: if opcode == 0x19 || opcode == 0x1B {
                            DecodedOpcode::SbbReg
                        } else {
                            DecodedOpcode::SubReg
                        },
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x01 | 0x03 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = operand_width(rex, &prefixes, arch);
                    let reg = Register::from_modrm(modrm.reg);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = if opcode == 0x01 {
                        match rm_operand {
                            Operand::Register(rm) => (
                                vec![
                                    Operand::Register(rm),
                                    Operand::Register(reg),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![
                                    Operand::Memory(address_operand),
                                    Operand::Register(reg),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x01: {other:?}"),
                                ));
                            }
                        }
                    } else {
                        (
                            vec![
                                Operand::Register(reg),
                                rm_operand.clone(),
                                Operand::ImmediateU64(width as u64),
                            ],
                            !matches!(rm_operand, Operand::Register(_)),
                        )
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AddReg,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x00 | 0x02 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let src = ByteRegister::from_modrm(modrm.reg, rex, arch);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = if opcode == 0x00 {
                        // ADD r/m8, r8: destination is the rm operand.
                        match rm_operand {
                            Operand::Register(_) => (
                                vec![
                                    Operand::Register8(ByteRegister::from_modrm(
                                        modrm.rm_register(),
                                        rex,
                                        arch,
                                    )),
                                    Operand::Register8(src),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![Operand::Memory(address_operand), Operand::Register8(src)],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x00: {other:?}"),
                                ));
                            }
                        }
                    } else {
                        // ADD r8, r/m8: destination is the reg operand.
                        let dst = ByteRegister::from_modrm(modrm.reg, rex, arch);
                        match rm_operand {
                            Operand::Register(_) => (
                                vec![
                                    Operand::Register8(dst),
                                    Operand::Register8(ByteRegister::from_modrm(
                                        modrm.rm_register(),
                                        rex,
                                        arch,
                                    )),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![Operand::Register8(dst), Operand::Memory(address_operand)],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x02: {other:?}"),
                                ));
                            }
                        }
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AddReg,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x13 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = operand_width(rex, &prefixes, arch);
                    let source = compare_operand(modrm_operand(
                        &modrm,
                        arch,
                        &prefixes,
                        address + (local - cursor) as u64,
                    ));
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AdcReg,
                        operands: vec![
                            Operand::Register(Register::from_modrm(modrm.reg)),
                            compare_operand_to_operand(source.clone()),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: !matches!(source, CompareOperand::Register(_)),
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x10 | 0x12 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let src = ByteRegister::from_modrm(modrm.reg, rex, arch);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = if opcode == 0x10 {
                        // ADC r/m8, r8: destination is the rm operand.
                        match rm_operand {
                            Operand::Register(_) => (
                                vec![
                                    Operand::Register8(ByteRegister::from_modrm(
                                        modrm.rm_register(),
                                        rex,
                                        arch,
                                    )),
                                    Operand::Register8(src),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![Operand::Memory(address_operand), Operand::Register8(src)],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x10: {other:?}"),
                                ));
                            }
                        }
                    } else {
                        // ADC r8, r/m8: destination is the reg operand.
                        let dst = ByteRegister::from_modrm(modrm.reg, rex, arch);
                        match rm_operand {
                            Operand::Register(_) => (
                                vec![
                                    Operand::Register8(dst),
                                    Operand::Register8(ByteRegister::from_modrm(
                                        modrm.rm_register(),
                                        rex,
                                        arch,
                                    )),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![Operand::Register8(dst), Operand::Memory(address_operand)],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x12: {other:?}"),
                                ));
                            }
                        }
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AdcReg,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x11 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = operand_width(rex, &prefixes, arch);
                    let reg = Register::from_modrm(modrm.reg);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = match rm_operand {
                        Operand::Register(rm) => (
                            vec![
                                Operand::Register(rm),
                                Operand::Register(reg),
                                Operand::ImmediateU64(width as u64),
                            ],
                            false,
                        ),
                        Operand::Memory(address_operand) => (
                            vec![
                                Operand::Memory(address_operand),
                                Operand::Register(reg),
                                Operand::ImmediateU64(width as u64),
                            ],
                            true,
                        ),
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unexpected rm operand for opcode 0x11: {other:?}"),
                            ));
                        }
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AdcReg,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x1A => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let source = if modrm.mod_bits == 0b11 {
                        Operand::Register8(ByteRegister::from_modrm(modrm.rm_register(), rex, arch))
                    } else {
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::SbbReg8,
                        operands: vec![
                            Operand::Register8(ByteRegister::from_modrm(modrm.reg, rex, arch)),
                            source,
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x35 => {
                    let width = operand_width(rex, &prefixes, arch);
                    let value = read_immediate(bytes, local, 4)?;
                    local += 4;
                    let imm_value = if width == 8 {
                        sign_extend(value, 4)
                    } else {
                        value
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::XorImm,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(imm_value),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x08 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let src = ByteRegister::from_modrm(modrm.reg, rex, arch);
                    match modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                    {
                        Operand::Register(_) if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::OrReg8,
                            operands: vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::Register8(src),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        Operand::Memory(address_operand) => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::OrReg8,
                            operands: vec![
                                Operand::Memory(address_operand),
                                Operand::Register8(src),
                            ],
                            precise_faulting_memory: true,
                            evex_info: EvexInfo::no_mask(),
                        },
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unexpected operand for opcode 0x08: {other:?}"),
                            ));
                        }
                    }
                }
                0x0A => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let dst = ByteRegister::from_modrm(modrm.reg, rex, arch);
                    match modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                    {
                        Operand::Register(_) => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::OrReg8,
                            operands: vec![
                                Operand::Register8(dst),
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        Operand::Memory(address_operand) => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::OrReg8,
                            operands: vec![
                                Operand::Register8(dst),
                                Operand::Memory(address_operand),
                            ],
                            precise_faulting_memory: true,
                            evex_info: EvexInfo::no_mask(),
                        },
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unexpected operand for opcode 0x0a: {other:?}"),
                            ));
                        }
                    }
                }
                0x20 | 0x22 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let src = ByteRegister::from_modrm(modrm.reg, rex, arch);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = if opcode == 0x20 {
                        // AND r/m8, r8: destination is the rm operand.
                        match rm_operand {
                            Operand::Register(_) => (
                                vec![
                                    Operand::Register8(ByteRegister::from_modrm(
                                        modrm.rm_register(),
                                        rex,
                                        arch,
                                    )),
                                    Operand::Register8(src),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![Operand::Memory(address_operand), Operand::Register8(src)],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x20: {other:?}"),
                                ));
                            }
                        }
                    } else {
                        // AND r8, r/m8: destination is the reg operand.
                        let dst = ByteRegister::from_modrm(modrm.reg, rex, arch);
                        match rm_operand {
                            Operand::Register(_) => (
                                vec![
                                    Operand::Register8(dst),
                                    Operand::Register8(ByteRegister::from_modrm(
                                        modrm.rm_register(),
                                        rex,
                                        arch,
                                    )),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![Operand::Register8(dst), Operand::Memory(address_operand)],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x22: {other:?}"),
                                ));
                            }
                        }
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AndReg8,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x30 | 0x32 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let src = ByteRegister::from_modrm(modrm.reg, rex, arch);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = if opcode == 0x30 {
                        // XOR r/m8, r8: destination is the rm operand.
                        match rm_operand {
                            Operand::Register(_) => (
                                vec![
                                    Operand::Register8(ByteRegister::from_modrm(
                                        modrm.rm_register(),
                                        rex,
                                        arch,
                                    )),
                                    Operand::Register8(src),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![Operand::Memory(address_operand), Operand::Register8(src)],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x30: {other:?}"),
                                ));
                            }
                        }
                    } else {
                        // XOR r8, r/m8: destination is the reg operand.
                        let dst = ByteRegister::from_modrm(modrm.reg, rex, arch);
                        match rm_operand {
                            Operand::Register(_) => (
                                vec![
                                    Operand::Register8(dst),
                                    Operand::Register8(ByteRegister::from_modrm(
                                        modrm.rm_register(),
                                        rex,
                                        arch,
                                    )),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![Operand::Register8(dst), Operand::Memory(address_operand)],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x32: {other:?}"),
                                ));
                            }
                        }
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::XorReg8,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x2A => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let source = if modrm.mod_bits == 0b11 {
                        Operand::Register8(ByteRegister::from_modrm(modrm.rm_register(), rex, arch))
                    } else {
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::SubReg8,
                        operands: vec![
                            Operand::Register8(ByteRegister::from_modrm(modrm.reg, rex, arch)),
                            source,
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x21 | 0x23 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = operand_width(rex, &prefixes, arch);
                    let reg = Register::from_modrm(modrm.reg);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = if opcode == 0x21 {
                        match rm_operand {
                            Operand::Register(rm) => (
                                vec![
                                    Operand::Register(rm),
                                    Operand::Register(reg),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![
                                    Operand::Memory(address_operand),
                                    Operand::Register(reg),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x21: {other:?}"),
                                ));
                            }
                        }
                    } else {
                        (
                            vec![
                                Operand::Register(reg),
                                rm_operand.clone(),
                                Operand::ImmediateU64(width as u64),
                            ],
                            !matches!(rm_operand, Operand::Register(_)),
                        )
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AndReg,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x09 | 0x0B => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = operand_width(rex, &prefixes, arch);
                    let reg = Register::from_modrm(modrm.reg);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = if opcode == 0x09 {
                        match rm_operand {
                            Operand::Register(rm) => (
                                vec![
                                    Operand::Register(rm),
                                    Operand::Register(reg),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![
                                    Operand::Memory(address_operand),
                                    Operand::Register(reg),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x09: {other:?}"),
                                ));
                            }
                        }
                    } else {
                        (
                            vec![
                                Operand::Register(reg),
                                rm_operand.clone(),
                                Operand::ImmediateU64(width as u64),
                            ],
                            !matches!(rm_operand, Operand::Register(_)),
                        )
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::OrReg,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x31 | 0x33 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = operand_width(rex, &prefixes, arch);
                    let reg = Register::from_modrm(modrm.reg);
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = if opcode == 0x31 {
                        match rm_operand {
                            Operand::Register(rm) => (
                                vec![
                                    Operand::Register(rm),
                                    Operand::Register(reg),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                vec![
                                    Operand::Memory(address_operand),
                                    Operand::Register(reg),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                true,
                            ),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected rm operand for opcode 0x31: {other:?}"),
                                ));
                            }
                        }
                    } else {
                        (
                            vec![
                                Operand::Register(reg),
                                rm_operand.clone(),
                                Operand::ImmediateU64(width as u64),
                            ],
                            !matches!(rm_operand, Operand::Register(_)),
                        )
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::XorReg,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x84 | 0x85 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = if opcode == 0x84 {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch)
                    };
                    let reg = if width == 1 {
                        CompareOperand::Register8(ByteRegister::from_modrm(modrm.reg, rex, arch))
                    } else {
                        CompareOperand::Register(Register::from_modrm(modrm.reg))
                    };
                    let rm = if width == 1 && modrm.mod_bits == 0b11 {
                        CompareOperand::Register8(ByteRegister::from_modrm(
                            modrm.rm_register(),
                            rex,
                            arch,
                        ))
                    } else {
                        compare_operand(modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ))
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Test,
                        operands: vec![
                            compare_operand_to_operand(rm),
                            compare_operand_to_operand(reg),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xA8 => {
                    let imm = read_immediate(bytes, local, 1)?;
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Test,
                        operands: vec![
                            Operand::Register8(ByteRegister::Al),
                            Operand::ImmediateU64(imm),
                            Operand::ImmediateU64(1),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xA9 => {
                    let width = operand_width(rex, &prefixes, arch);
                    let imm = read_immediate(bytes, local, if width == 8 { 4 } else { width })?;
                    local += if width == 8 { 4 } else { width };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Test,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(if width == 8 {
                                sign_extend(imm, 4)
                            } else {
                                imm
                            }),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xA4 | 0xA5 => {
                    let width = if opcode == 0xA4 {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch)
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Movs,
                        operands: vec![Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xAA | 0xAB => {
                    let width = if opcode == 0xAA {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch)
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Stos,
                        operands: vec![Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xAC | 0xAD => {
                    let width = if opcode == 0xAC {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch)
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Lods,
                        operands: vec![Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xA6 | 0xA7 => {
                    let width = if opcode == 0xA6 {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch)
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Cmps,
                        operands: vec![Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xAE | 0xAF => {
                    let width = if opcode == 0xAE {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch)
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Scas,
                        operands: vec![Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xF4 => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Hlt,
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xFA => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Cli,
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xFB => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Sti,
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xFD => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Std,
                    operands: vec![],
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xE4 | 0xE5 | 0xEC | 0xED => {
                    // IN AL/eAX, imm8 (0xE4/0xE5) or IN AL/eAX, DX (0xEC/0xED)
                    let width = if opcode == 0xE4 || opcode == 0xEC {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch).min(4)
                    };
                    let operands = if opcode == 0xE4 || opcode == 0xE5 {
                        // Capture the imm8 port operand.
                        let port = bytes.get(local).copied().unwrap_or(0) as u64;
                        local += 1;
                        vec![
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(port),
                        ]
                    } else {
                        // Indirect form: port comes from DX at runtime.
                        vec![Operand::ImmediateU64(width as u64)]
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::PortIn,
                        operands,
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xE6 | 0xE7 | 0xEE | 0xEF => {
                    // OUT imm8, AL/eAX (0xE6/0xE7) or OUT DX, AL/eAX (0xEE/0xEF)
                    let width = if opcode == 0xE6 || opcode == 0xEE {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch).min(4)
                    };
                    let operands = if opcode == 0xE6 || opcode == 0xE7 {
                        // Capture the imm8 port operand.
                        let port = bytes.get(local).copied().unwrap_or(0) as u64;
                        local += 1;
                        vec![
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(port),
                        ]
                    } else {
                        // Indirect form: port comes from DX at runtime.
                        vec![Operand::ImmediateU64(width as u64)]
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::PortOut,
                        operands,
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xA0 | 0xA2 => {
                    let is_moffs64 = arch == GuestArch::X64 && !address_size_32;
                    let imm_size = if is_moffs64 { 8 } else { 4 };
                    let absolute = read_immediate(bytes, local, imm_size)?;
                    local += imm_size;
                    let address_operand = MemoryOperand {
                        base: None,
                        index: None,
                        scale: 1,
                        displacement: absolute as i32,
                        rip_relative: false,
                        rip_base: 0,
                        segment: segment_from_prefixes(&prefixes),
                        address_size_32,
                        absolute_address: if is_moffs64 { Some(absolute) } else { None },
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: if opcode == 0xA0 {
                            DecodedOpcode::MovLoad8
                        } else {
                            DecodedOpcode::MovStore8
                        },
                        operands: if opcode == 0xA0 {
                            vec![
                                Operand::Register8(ByteRegister::Al),
                                Operand::Memory(address_operand),
                                Operand::ImmediateU64(1),
                            ]
                        } else {
                            vec![
                                Operand::Memory(address_operand),
                                Operand::Register8(ByteRegister::Al),
                                Operand::ImmediateU64(1),
                            ]
                        },
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xA1 | 0xA3 => {
                    let is_moffs64 = arch == GuestArch::X64 && !address_size_32;
                    let imm_size = if is_moffs64 { 8 } else { 4 };
                    let absolute = read_immediate(bytes, local, imm_size)?;
                    local += imm_size;
                    let address_operand = MemoryOperand {
                        base: None,
                        index: None,
                        scale: 1,
                        displacement: absolute as i32,
                        rip_relative: false,
                        rip_base: 0,
                        segment: segment_from_prefixes(&prefixes),
                        address_size_32,
                        absolute_address: if is_moffs64 { Some(absolute) } else { None },
                    };
                    let width = operand_width(rex, &prefixes, arch);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: if opcode == 0xA1 {
                            DecodedOpcode::MovLoad
                        } else {
                            DecodedOpcode::MovStore
                        },
                        operands: if opcode == 0xA1 {
                            vec![
                                Operand::Register(Register::Rax),
                                Operand::Memory(address_operand),
                                Operand::ImmediateU64(width as u64),
                            ]
                        } else {
                            vec![
                                Operand::Memory(address_operand),
                                Operand::Register(Register::Rax),
                                Operand::ImmediateU64(width as u64),
                            ]
                        },
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x38..=0x3B => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = if matches!(opcode, 0x38 | 0x3A) {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch)
                    };
                    let reg = if width == 1 {
                        CompareOperand::Register8(ByteRegister::from_modrm(modrm.reg, rex, arch))
                    } else {
                        CompareOperand::Register(Register::from_modrm(modrm.reg))
                    };
                    let rm = if width == 1 && modrm.mod_bits == 0b11 {
                        CompareOperand::Register8(ByteRegister::from_modrm(
                            modrm.rm_register(),
                            rex,
                            arch,
                        ))
                    } else {
                        compare_operand(modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ))
                    };
                    let (lhs, rhs) = if matches!(opcode, 0x38 | 0x39) {
                        (rm, reg)
                    } else {
                        (reg, rm)
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Cmp,
                        operands: vec![
                            compare_operand_to_operand(lhs),
                            compare_operand_to_operand(rhs),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x3C => {
                    let raw = read_immediate(bytes, local, 1)?;
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Cmp,
                        operands: vec![
                            Operand::Register8(ByteRegister::Al),
                            Operand::ImmediateU64(raw),
                            Operand::ImmediateU64(1),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x3D => {
                    let width = operand_width(rex, &prefixes, arch);
                    let raw = read_immediate(bytes, local, 4)?;
                    local += 4;
                    let value = if width == 8 { sign_extend(raw, 4) } else { raw };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Cmp,
                        operands: vec![
                            Operand::Register(Register::Rax),
                            Operand::ImmediateU64(value),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x69 | 0x6B => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = operand_width(rex, &prefixes, arch);
                    let imm = if opcode == 0x69 {
                        let value = read_immediate(bytes, local, 4)?;
                        local += 4;
                        value
                    } else {
                        let value = *bytes.get(local).ok_or_else(|| {
                            AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "truncated imm8 for opcode 0x6b",
                            )
                        })? as i8 as i64 as u64;
                        local += 1;
                        value
                    };
                    let src = compare_operand(modrm_operand(
                        &modrm,
                        arch,
                        &prefixes,
                        address + (local - cursor) as u64,
                    ));
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::ImulImm,
                        operands: vec![
                            Operand::Register(Register::from_modrm(modrm.reg)),
                            compare_operand_to_operand(src),
                            Operand::ImmediateU64(imm),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x83 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let imm = *bytes.get(local).ok_or_else(|| {
                        AppError::new(ReasonCode::RcUnimplInsn, "truncated imm8 for opcode 0x83")
                    })? as i8 as i64 as u64;
                    local += 1;
                    let width = operand_width(rex, &prefixes, arch);
                    if modrm.reg == 3 && modrm.mod_bits != 0b11 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "opcode 0x83 /3 currently requires a register destination",
                        ));
                    }
                    let opcode_kind = match modrm.reg {
                        0 => DecodedOpcode::AddImm,
                        1 => DecodedOpcode::OrImm,
                        2 => DecodedOpcode::AdcImm,
                        3 => DecodedOpcode::SbbReg,
                        4 => DecodedOpcode::AndImm,
                        5 => DecodedOpcode::SubImm,
                        6 => DecodedOpcode::XorImm,
                        7 => DecodedOpcode::Cmp,
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode 0x83 group selector {other}"),
                            ));
                        }
                    };
                    if opcode_kind == DecodedOpcode::Cmp {
                        let lhs = compare_operand(modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ));
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Cmp,
                            operands: vec![
                                compare_operand_to_operand(lhs),
                                Operand::ImmediateU64(imm),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: modrm.mod_bits != 0b11,
                            evex_info: EvexInfo::no_mask(),
                        }
                    } else {
                        let destination = modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        );
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: opcode_kind,
                            operands: vec![
                                destination,
                                Operand::ImmediateU64(imm),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: modrm.mod_bits != 0b11,
                            evex_info: EvexInfo::no_mask(),
                        }
                    }
                }
                0xC0 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let imm = read_immediate(bytes, local, 1)?;
                    local += 1;
                    let opcode_kind = match modrm.reg {
                        0 => DecodedOpcode::RolImm,
                        1 => DecodedOpcode::RorImm,
                        2 => DecodedOpcode::RclImm,
                        3 => DecodedOpcode::RcrImm,
                        4 => DecodedOpcode::ShlImm,
                        5 => DecodedOpcode::ShrImm,
                        7 => DecodedOpcode::SarImm,
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode 0xc0 group selector {other}"),
                            ));
                        }
                    };
                    let destination =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: opcode_kind,
                        operands: vec![
                            destination,
                            Operand::ImmediateU64(imm),
                            Operand::ImmediateU64(1),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xC1 | 0xD1 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let imm = if opcode == 0xC1 {
                        let value = read_immediate(bytes, local, 1)?;
                        local += 1;
                        value
                    } else {
                        1
                    };
                    let opcode_kind = match modrm.reg {
                        0 => DecodedOpcode::RolImm,
                        1 => DecodedOpcode::RorImm,
                        2 => DecodedOpcode::RclImm,
                        3 => DecodedOpcode::RcrImm,
                        4 => DecodedOpcode::ShlImm,
                        5 => DecodedOpcode::ShrImm,
                        7 => DecodedOpcode::SarImm,
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode {opcode:#x} group selector {other}"),
                            ));
                        }
                    };
                    let width = operand_width(rex, &prefixes, arch);
                    let destination =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: opcode_kind,
                        operands: vec![
                            destination,
                            Operand::ImmediateU64(imm),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xD0 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let opcode_kind = match modrm.reg {
                        0 => DecodedOpcode::RolImm,
                        1 => DecodedOpcode::RorImm,
                        2 => DecodedOpcode::RclImm,
                        3 => DecodedOpcode::RcrImm,
                        4 => DecodedOpcode::ShlImm,
                        5 => DecodedOpcode::ShrImm,
                        7 => DecodedOpcode::SarImm,
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode 0xd0 group selector {other}"),
                            ));
                        }
                    };
                    let destination =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: opcode_kind,
                        operands: vec![
                            destination,
                            Operand::ImmediateU64(1),
                            Operand::ImmediateU64(1),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xD2 | 0xD3 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = if opcode == 0xD2 {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch)
                    };
                    let opcode_kind = match modrm.reg {
                        0 => DecodedOpcode::RolCl,
                        1 => DecodedOpcode::RorCl,
                        2 => DecodedOpcode::RclCl,
                        3 => DecodedOpcode::RcrCl,
                        4 => DecodedOpcode::ShlCl,
                        5 => DecodedOpcode::ShrCl,
                        7 => DecodedOpcode::SarCl,
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode {opcode:#x} group selector {other}"),
                            ));
                        }
                    };
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (operands, precise_faulting_memory) = match rm_operand {
                        Operand::Register(_) => (
                            vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::ImmediateU64(width as u64),
                            ],
                            false,
                        ),
                        Operand::Memory(address_operand) => (
                            vec![
                                Operand::Memory(address_operand),
                                Operand::ImmediateU64(width as u64),
                            ],
                            true,
                        ),
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unexpected rm operand for opcode {opcode:#x}: {other:?}"),
                            ));
                        }
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: opcode_kind,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xF6 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    match modrm.reg {
                        0 => {
                            let imm = read_immediate(bytes, local, 1)?;
                            local += 1;
                            let lhs = compare_operand(modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Test,
                                operands: vec![
                                    compare_operand_to_operand(lhs),
                                    Operand::ImmediateU64(imm),
                                    Operand::ImmediateU64(1),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        2 if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Not,
                            operands: vec![Operand::Register8(ByteRegister::from_modrm(
                                modrm.rm_register(),
                                rex,
                                arch,
                            ))],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        3 if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Neg,
                            operands: vec![Operand::Register8(ByteRegister::from_modrm(
                                modrm.rm_register(),
                                rex,
                                arch,
                            ))],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        4 => {
                            let operand = compare_operand(modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::MulAcc,
                                operands: vec![
                                    compare_operand_to_operand(operand),
                                    Operand::ImmediateU64(1),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        5 => {
                            let operand = compare_operand(modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::ImulAcc,
                                operands: vec![
                                    compare_operand_to_operand(operand),
                                    Operand::ImmediateU64(1),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        6 => {
                            let operand = compare_operand(modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Div,
                                operands: vec![
                                    compare_operand_to_operand(operand),
                                    Operand::ImmediateU64(1),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        7 => {
                            let operand = compare_operand(modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Idiv,
                                operands: vec![
                                    compare_operand_to_operand(operand),
                                    Operand::ImmediateU64(1),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode 0xf6 group selector {other}"),
                            ));
                        }
                    }
                }
                0xF7 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = operand_width(rex, &prefixes, arch);
                    let operand = compare_operand(modrm_operand(
                        &modrm,
                        arch,
                        &prefixes,
                        address + (local - cursor) as u64,
                    ));
                    match modrm.reg {
                        0 => {
                            let imm =
                                read_immediate(bytes, local, if width == 8 { 4 } else { width })?;
                            local += if width == 8 { 4 } else { width };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Test,
                                operands: vec![
                                    compare_operand_to_operand(operand),
                                    Operand::ImmediateU64(if width == 8 {
                                        sign_extend(imm, 4)
                                    } else {
                                        imm
                                    }),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        2 => match modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ) {
                            Operand::Register(_) if modrm.mod_bits == 0b11 => DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Not,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.rm_register())),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            },
                            Operand::Memory(address_operand) => DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Not,
                                operands: vec![
                                    Operand::Memory(address_operand),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: true,
                                evex_info: EvexInfo::no_mask(),
                            },
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected operand for opcode 0xf7 /2: {other:?}"),
                                ));
                            }
                        },
                        3 if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Neg,
                            operands: vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        4 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::MulAcc,
                            operands: vec![
                                compare_operand_to_operand(operand),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: modrm.mod_bits != 0b11,
                            evex_info: EvexInfo::no_mask(),
                        },
                        5 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::ImulAcc,
                            operands: vec![
                                compare_operand_to_operand(operand),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: modrm.mod_bits != 0b11,
                            evex_info: EvexInfo::no_mask(),
                        },
                        6 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Div,
                            operands: vec![
                                compare_operand_to_operand(operand),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: modrm.mod_bits != 0b11,
                            evex_info: EvexInfo::no_mask(),
                        },
                        7 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Idiv,
                            operands: vec![
                                compare_operand_to_operand(operand),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: modrm.mod_bits != 0b11,
                            evex_info: EvexInfo::no_mask(),
                        },
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode 0xf7 group selector {other}"),
                            ));
                        }
                    }
                }
                0x99 => {
                    let width = operand_width(rex, &prefixes, arch);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Cdq,
                        operands: vec![Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x80..=0x82 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    if opcode == 0x82 && arch == GuestArch::X64 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "opcode 0x82 is invalid in 64-bit mode",
                        ));
                    }
                    let byte_form = opcode == 0x80 || opcode == 0x82;
                    let width = if byte_form {
                        1
                    } else {
                        operand_width(rex, &prefixes, arch)
                    };
                    let immediate_width = if byte_form { 1 } else { 4 };
                    let imm = read_immediate(bytes, local, immediate_width)?;
                    local += immediate_width;
                    let imm_value = if opcode == 0x81 && width == 8 {
                        sign_extend(imm, 4)
                    } else {
                        imm
                    };
                    match modrm.reg {
                        0 if byte_form && modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::AddImm,
                            operands: vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::ImmediateU64(imm),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        0 if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::AddImm,
                            operands: vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::ImmediateU64(imm_value),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        0 => {
                            let destination = modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            );
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::AddImm,
                                operands: vec![
                                    destination,
                                    Operand::ImmediateU64(imm_value),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: true,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        1 if byte_form && modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::OrImm,
                            operands: vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::ImmediateU64(imm),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        1 if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::OrImm,
                            operands: vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::ImmediateU64(imm_value),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        1 => {
                            let destination = modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            );
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::OrImm,
                                operands: vec![
                                    destination,
                                    Operand::ImmediateU64(imm_value),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: true,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        2 if byte_form && modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::AdcImm,
                            operands: vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::ImmediateU64(imm),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        2 if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::AdcImm,
                            operands: vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::ImmediateU64(imm_value),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        2 => {
                            let destination = modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            );
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::AdcImm,
                                operands: vec![
                                    destination,
                                    Operand::ImmediateU64(imm_value),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: true,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        3 if byte_form && modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::SbbReg8,
                            operands: vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::ImmediateU64(imm),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        3 if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::SbbReg,
                            operands: vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::ImmediateU64(imm_value),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        3 => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!(
                                    "opcode 0x{opcode:02x} /3 currently requires a register destination"
                                ),
                            ));
                        }
                        4 if byte_form && modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::AndImm,
                            operands: vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::ImmediateU64(imm),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        4 if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::AndImm,
                            operands: vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::ImmediateU64(imm_value),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        4 => {
                            let destination = modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            );
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::AndImm,
                                operands: vec![
                                    destination,
                                    Operand::ImmediateU64(imm_value),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: true,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        5 if byte_form && modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::SubImm,
                            operands: vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::ImmediateU64(imm),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        5 if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::SubImm,
                            operands: vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::ImmediateU64(imm_value),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        5 => {
                            let destination = modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            );
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::SubImm,
                                operands: vec![
                                    destination,
                                    Operand::ImmediateU64(imm_value),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: true,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        6 if byte_form && modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::XorImm,
                            operands: vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::ImmediateU64(imm),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        6 if modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::XorImm,
                            operands: vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::ImmediateU64(imm_value),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        6 => {
                            let destination = modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            );
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::XorImm,
                                operands: vec![
                                    destination,
                                    Operand::ImmediateU64(imm_value),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: true,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        7 if byte_form && modrm.mod_bits == 0b11 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Cmp,
                            operands: vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::ImmediateU64(imm),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        7 => {
                            let lhs = compare_operand(modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Cmp,
                                operands: vec![
                                    compare_operand_to_operand(lhs),
                                    Operand::ImmediateU64(imm),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode {opcode:#x} group selector {other}"),
                            ));
                        }
                    }
                }
                0x86 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let reg = ByteRegister::from_modrm(modrm.reg, rex, arch);
                    if modrm.mod_bits == 0b11 {
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Xchg,
                            operands: vec![
                                Operand::Register8(ByteRegister::from_modrm(
                                    modrm.rm_register(),
                                    rex,
                                    arch,
                                )),
                                Operand::Register8(reg),
                                Operand::ImmediateU64(1),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        }
                    } else {
                        let Operand::Memory(address_operand) = modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ) else {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "XCHG r/m8 requires a memory or register operand",
                            ));
                        };
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Xchg,
                            operands: vec![
                                Operand::Memory(address_operand),
                                Operand::Register8(reg),
                                Operand::ImmediateU64(1),
                            ],
                            precise_faulting_memory: true,
                            evex_info: EvexInfo::no_mask(),
                        }
                    }
                }
                0x87 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let width = operand_width(rex, &prefixes, arch);
                    let reg = Register::from_modrm(modrm.reg);
                    if modrm.mod_bits == 0b11 {
                        // XCHG reg, reg (register-to-register form)
                        // Emit a DMB barrier for x86 memory ordering semantics.
                        // x86 XCHG (even without LOCK) has implicit acquire/release semantics.
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Xchg,
                            operands: vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::Register(reg),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        }
                    } else {
                        let Operand::Memory(address_operand) = modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ) else {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "XCHG requires a memory or register operand",
                            ));
                        };
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Xchg,
                            operands: vec![
                                Operand::Memory(address_operand),
                                Operand::Register(reg),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: true,
                            evex_info: EvexInfo::no_mask(),
                        }
                    }
                }
                0x88..=0x8B => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let rm_operand =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                    let (opcode_kind, operands, precise_faulting_memory) = match opcode {
                        0x88 => {
                            let reg = ByteRegister::from_modrm(modrm.reg, rex, arch);
                            match rm_operand {
                                Operand::Register(_) => (
                                    DecodedOpcode::MovReg8,
                                    vec![
                                        Operand::Register8(ByteRegister::from_modrm(
                                            modrm.rm_register(),
                                            rex,
                                            arch,
                                        )),
                                        Operand::Register8(reg),
                                        Operand::ImmediateU64(1),
                                    ],
                                    false,
                                ),
                                Operand::Memory(address_operand) => (
                                    DecodedOpcode::MovStore8,
                                    vec![
                                        Operand::Memory(address_operand),
                                        Operand::Register8(reg),
                                        Operand::ImmediateU64(1),
                                    ],
                                    true,
                                ),
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unexpected rm operand for opcode 0x88: {other:?}"),
                                    ));
                                }
                            }
                        }
                        0x8A => {
                            let reg = ByteRegister::from_modrm(modrm.reg, rex, arch);
                            match rm_operand {
                                Operand::Register(_) => (
                                    DecodedOpcode::MovReg8,
                                    vec![
                                        Operand::Register8(reg),
                                        Operand::Register8(ByteRegister::from_modrm(
                                            modrm.rm_register(),
                                            rex,
                                            arch,
                                        )),
                                        Operand::ImmediateU64(1),
                                    ],
                                    false,
                                ),
                                Operand::Memory(address_operand) => (
                                    DecodedOpcode::MovLoad8,
                                    vec![
                                        Operand::Register8(reg),
                                        Operand::Memory(address_operand),
                                        Operand::ImmediateU64(1),
                                    ],
                                    true,
                                ),
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unexpected rm operand for opcode 0x8a: {other:?}"),
                                    ));
                                }
                            }
                        }
                        0x8B => {
                            let width = operand_width(rex, &prefixes, arch);
                            let reg = Register::from_modrm(modrm.reg);
                            match rm_operand {
                                Operand::Register(src) => (
                                    DecodedOpcode::MovReg,
                                    vec![
                                        Operand::Register(reg),
                                        Operand::Register(src),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    false,
                                ),
                                other => (
                                    DecodedOpcode::MovLoad,
                                    vec![
                                        Operand::Register(reg),
                                        other,
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    true,
                                ),
                            }
                        }
                        0x89 => {
                            let width = operand_width(rex, &prefixes, arch);
                            let reg = Register::from_modrm(modrm.reg);
                            match rm_operand {
                                Operand::Register(dst) => (
                                    DecodedOpcode::MovReg,
                                    vec![
                                        Operand::Register(dst),
                                        Operand::Register(reg),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    false,
                                ),
                                other => (
                                    DecodedOpcode::MovStore,
                                    vec![
                                        other,
                                        Operand::Register(reg),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    true,
                                ),
                            }
                        }
                        _ => unreachable!("unexpected mov opcode {opcode:#x}"),
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: opcode_kind,
                        operands,
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x8C => {
                    if arch != GuestArch::X86 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "MOV r/m16,Sreg is only implemented for x86",
                        ));
                    }
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let Operand::Memory(address_operand) =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                    else {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "MOV r/m16,Sreg currently requires a memory destination",
                        ));
                    };
                    let Some(selector) = x86_segment_selector_value(modrm.reg) else {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported segment register selector {}", modrm.reg),
                        ));
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::MovStoreImm,
                        operands: vec![
                            Operand::Memory(address_operand),
                            Operand::ImmediateU64(selector as u64),
                            Operand::ImmediateU64(2),
                        ],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x8E => {
                    if arch != GuestArch::X86 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "MOV Sreg,r/m16 is only implemented for x86",
                        ));
                    }
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    if modrm.reg > 5 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported segment register selector {}", modrm.reg),
                        ));
                    }
                    let source = if modrm.mod_bits == 0b11 {
                        Operand::Register(Register::from_modrm(modrm.rm_register()))
                    } else {
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::LoadSegment { segment: modrm.reg },
                        operands: vec![source],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x8F => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    if modrm.reg != 0 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported opcode 0x8f group selector {}", modrm.reg),
                        ));
                    }
                    let width = operand_width(rex, &prefixes, arch);
                    let Operand::Memory(address_operand) =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                    else {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "POP r/m currently requires a memory destination",
                        ));
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::PopMemory,
                        operands: vec![
                            Operand::Memory(address_operand),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xC6 | 0xC7 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    // XABORT: 0xC6 F8 ib (ModRM = 0xF8 = mod=11, reg=7, rm=0)
                    if opcode == 0xC6 && modrm.reg == 7 && modrm.mod_bits == 0b11 {
                        let imm = read_immediate(bytes, local, 1)?;
                        local += 1;
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Xabort,
                            operands: vec![Operand::ImmediateU64(imm)],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        }
                    } else if opcode == 0xC7 && modrm.reg == 0 && modrm.mod_bits == 0b11 {
                        // XBEGIN rel32: C7 /0 rel32 with mod=11, reg=0, rm=0 (ModRM = 0xF0)
                        // The fallthrough target is after the relocation offset
                        let rel_type = if prefixes.contains(&InstructionPrefix::OperandSize) {
                            2u32
                        } else {
                            4u32
                        };
                        let rel_raw = read_immediate(bytes, local, rel_type as usize)?;
                        local += rel_type as usize;
                        let fallthrough = address + (local - cursor) as u64;
                        let target = (fallthrough as i128 + (rel_raw as i32) as i128) as u64;
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Xbegin,
                            operands: vec![Operand::ImmediateU64(target)],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        }
                    } else if modrm.reg != 0 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported opcode {opcode:#x} group selector {}",
                                modrm.reg
                            ),
                        ));
                    } else {
                        // MOV r/m, imm (reg must be 0)
                        let width = if opcode == 0xC6 {
                            1
                        } else {
                            operand_width(rex, &prefixes, arch)
                        };
                        let immediate_width = if opcode == 0xC6 {
                            1
                        } else if width == 2 {
                            2
                        } else {
                            4
                        };
                        let imm = read_immediate(bytes, local, immediate_width)?;
                        local += immediate_width;
                        let Operand::Memory(address_operand) = modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ) else {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!(
                                    "opcode {opcode:#x} currently requires a memory destination"
                                ),
                            ));
                        };
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::MovStoreImm,
                            operands: vec![
                                Operand::Memory(address_operand),
                                Operand::ImmediateU64(imm),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: true,
                            evex_info: EvexInfo::no_mask(),
                        }
                    }
                }
                0x8D => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    let Operand::Memory(address_operand) =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                    else {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "LEA requires a memory addressing mode",
                        ));
                    };
                    let width = operand_width(rex, &prefixes, arch);
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Lea,
                        operands: vec![
                            Operand::Register(Register::from_modrm(modrm.reg)),
                            Operand::Memory(address_operand),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x9B => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Nop,
                    operands: Vec::new(),
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xC2 => {
                    let stack_adjust = read_immediate(bytes, local, 2)?;
                    local += 2;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Ret,
                        operands: vec![Operand::ImmediateU64(stack_adjust)],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xC9 => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Leave,
                    operands: Vec::new(),
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xC3 => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Ret,
                    operands: Vec::new(),
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                0xCC => DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Int3,
                    operands: Vec::new(),
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                },
                // INT imm8 (0xCD <vector>) — software interrupt. In the primary
                // opcode table 0xCD is the INT instruction, distinct from its
                // appearance in the 0x0F 0x38 sub-table (SHA256MSG2).
                0xCD => {
                    let vector = *bytes.get(local).ok_or_else(|| {
                        AppError::new(ReasonCode::RcUnimplInsn, "missing vector for INT imm8")
                    })?;
                    local += 1;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Int { vector },
                        operands: vec![Operand::ImmediateU64(vector as u64)],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xDB => {
                    let secondary = *bytes.get(local).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "missing secondary opcode for 0xdb",
                        )
                    })?;
                    match secondary {
                        0xE2 => {
                            local += 1;
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Fnclex,
                                operands: Vec::new(),
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xE3 => {
                            local += 1;
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Fninit,
                                operands: Vec::new(),
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        _ => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits == 0b11 && modrm.reg == 6 {
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::Fcomi,
                                    operands: vec![Operand::ImmediateU64(u64::from(modrm.rm))],
                                    precise_faulting_memory: false,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            } else {
                                if modrm.reg != 0 || modrm.mod_bits == 0b11 {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unsupported opcode 0xdb /{}", modrm.reg),
                                    ));
                                }
                                let Operand::Memory(address_operand) = modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                ) else {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        "opcode 0xdb /0 requires a memory operand",
                                    ));
                                };
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::FildI32,
                                    operands: vec![Operand::Memory(address_operand)],
                                    precise_faulting_memory: true,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            }
                        }
                    }
                }
                0xD8 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    if modrm.mod_bits != 0b11 || !matches!(modrm.reg, 1 | 6) {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported opcode 0xd8 reg={} mod={}",
                                modrm.reg, modrm.mod_bits
                            ),
                        ));
                    }
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: if modrm.reg == 1 {
                            DecodedOpcode::Fmul
                        } else {
                            DecodedOpcode::Fdiv
                        },
                        operands: vec![Operand::ImmediateU64(u64::from(modrm.rm))],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xDC => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    if modrm.mod_bits == 0b11 || !matches!(modrm.reg, 0 | 1 | 6) {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported opcode 0xdc reg={} mod={}",
                                modrm.reg, modrm.mod_bits
                            ),
                        ));
                    }
                    let Operand::Memory(address_operand) =
                        modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                    else {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "opcode 0xdc /1 requires a memory operand",
                        ));
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: match modrm.reg {
                            0 => DecodedOpcode::FaddReal64,
                            1 => DecodedOpcode::FmulReal64,
                            _ => DecodedOpcode::FdivReal64,
                        },
                        operands: vec![Operand::Memory(address_operand)],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xD9 => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    if modrm.mod_bits == 0b11 {
                        if modrm.reg == 1 {
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Fxch,
                                operands: vec![Operand::ImmediateU64(u64::from(modrm.rm))],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        } else if modrm.reg == 4 && modrm.rm == 0 {
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Fchs,
                                operands: Vec::new(),
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        } else {
                            let constant = if modrm.reg == 5 {
                                match modrm.rm {
                                    0 => Some(1.0),
                                    1 => Some(std::f64::consts::LOG2_10),
                                    2 => Some(std::f64::consts::LOG2_E),
                                    3 => Some(std::f64::consts::PI),
                                    4 => Some(std::f64::consts::LOG10_2),
                                    5 => Some(std::f64::consts::LN_2),
                                    6 => Some(0.0),
                                    _ => None,
                                }
                            } else {
                                None
                            };
                            let Some(constant) = constant else {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!(
                                        "unsupported opcode 0xd9 register form reg={} rm={}",
                                        modrm.reg, modrm.rm
                                    ),
                                ));
                            };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::FldConst,
                                operands: vec![Operand::ImmediateU64(constant.to_bits())],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                    } else {
                        if !matches!(modrm.reg, 0 | 2 | 3 | 5 | 7) {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode 0xd9 /{}", modrm.reg),
                            ));
                        }
                        let Operand::Memory(address_operand) = modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ) else {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "opcode 0xd9 /7 requires a memory operand",
                            ));
                        };
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: match modrm.reg {
                                0 => DecodedOpcode::FldReal32,
                                2 => DecodedOpcode::FstReal32,
                                3 => DecodedOpcode::FstpReal32,
                                5 => DecodedOpcode::Fldcw,
                                _ => DecodedOpcode::Fstcw,
                            },
                            operands: vec![Operand::Memory(address_operand)],
                            precise_faulting_memory: true,
                            evex_info: EvexInfo::no_mask(),
                        }
                    }
                }
                0xDD => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    if !matches!(modrm.reg, 0..=3) {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported opcode 0xdd /{}", modrm.reg),
                        ));
                    }
                    if modrm.mod_bits == 0b11 {
                        if modrm.reg != 3 {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!(
                                    "unsupported opcode 0xdd register form reg={} rm={}",
                                    modrm.reg, modrm.rm
                                ),
                            ));
                        }
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::FstpSt,
                            operands: vec![Operand::ImmediateU64(u64::from(modrm.rm))],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        }
                    } else {
                        let Operand::Memory(address_operand) = modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ) else {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "opcode 0xdd /3 requires a memory operand",
                            ));
                        };
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: match modrm.reg {
                                0 => DecodedOpcode::FldReal64,
                                1 | 2 => DecodedOpcode::FstReal64,
                                _ => DecodedOpcode::FstpReal,
                            },
                            operands: vec![Operand::Memory(address_operand)],
                            precise_faulting_memory: true,
                            evex_info: EvexInfo::no_mask(),
                        }
                    }
                }
                0xDE => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    if modrm.mod_bits != 0b11 || !matches!(modrm.reg, 0 | 6) {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported opcode 0xde reg={} mod={}",
                                modrm.reg, modrm.mod_bits
                            ),
                        ));
                    }
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: if modrm.reg == 0 {
                            DecodedOpcode::Faddp
                        } else {
                            DecodedOpcode::Fdivp
                        },
                        operands: vec![Operand::ImmediateU64(u64::from(modrm.rm))],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xDF => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    if modrm.mod_bits == 0b11 && modrm.reg == 6 {
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Fcomip,
                            operands: vec![Operand::ImmediateU64(u64::from(modrm.rm))],
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        }
                    } else if modrm.reg != 5 || modrm.mod_bits == 0b11 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported opcode 0xdf /{}", modrm.reg),
                        ));
                    } else {
                        let Operand::Memory(address_operand) = modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ) else {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "opcode 0xdf /5 requires a memory operand",
                            ));
                        };
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::FildI64,
                            operands: vec![Operand::Memory(address_operand)],
                            precise_faulting_memory: true,
                            evex_info: EvexInfo::no_mask(),
                        }
                    }
                }
                0xE0..=0xE3 => {
                    // LOOP/LOOPE/LOOPNE/JCXZ: 2-byte instruction (opcode + rel8 displacement)
                    // Lowered to Nop for now; proper execution requires ECX/RCX decrement and conditional jump
                    local += 1; // skip displacement byte
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Loop,
                        operands: Vec::new(),
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xE8 => {
                    let displacement = read_i32(bytes, local)?;
                    local += 4;
                    let return_address = address + (local - cursor) as u64;
                    let target = (return_address as i128 + displacement as i128) as u64;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::CallRel,
                        operands: vec![
                            Operand::ImmediateU64(target),
                            Operand::ImmediateU64(return_address),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xE9 => {
                    let displacement = read_i32(bytes, local)?;
                    local += 4;
                    let target =
                        ((address + (local - cursor) as u64) as i128 + displacement as i128) as u64;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::JmpRel,
                        operands: vec![Operand::ImmediateU64(target)],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0xEB => {
                    let displacement = *bytes.get(local).ok_or_else(|| {
                        AppError::new(ReasonCode::RcUnimplInsn, "truncated rel8 for opcode 0xeb")
                    })? as i8 as i64;
                    local += 1;
                    let target =
                        ((address + (local - cursor) as u64) as i128 + displacement as i128) as u64;
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::JmpRel,
                        operands: vec![Operand::ImmediateU64(target)],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x70..=0x7F => {
                    let displacement = *bytes.get(local).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "truncated rel8 for conditional jump",
                        )
                    })? as i8 as i64;
                    local += 1;
                    let fallthrough = address + (local - cursor) as u64;
                    let target = (fallthrough as i128 + displacement as i128) as u64;
                    let condition = match opcode {
                        0x70 => 12,
                        0x71 => 13,
                        0x72 => 2,
                        0x73 => 3,
                        0x77 => 4,
                        0x76 => 5,
                        0x78 => 6,
                        0x79 => 7,
                        0x7A => 14,
                        0x7B => 15,
                        0x7C => 8,
                        0x7D => 9,
                        0x7E => 10,
                        0x7F => 11,
                        0x74 => 0,
                        0x75 => 1,
                        _ => unreachable!("covered conditional jump opcode"),
                    };
                    DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Jcc,
                        operands: vec![
                            Operand::ImmediateU64(condition),
                            Operand::ImmediateU64(target),
                            Operand::ImmediateU64(fallthrough),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    }
                }
                0x0F => {
                    let next = *bytes.get(local).ok_or_else(|| {
                        AppError::new(ReasonCode::RcUnimplInsn, "missing secondary opcode")
                    })?;
                    local += 1;
                    match next {
                        0x01 => {
                            let tertiary = *bytes.get(local).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "missing tertiary opcode for 0x0f 0x01",
                                )
                            })?;
                            local += 1;
                            match tertiary {
                                0xD0 => DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::Xgetbv,
                                    operands: Vec::new(),
                                    precise_faulting_memory: false,
                                    evex_info: EvexInfo::no_mask(),
                                },
                                0xD5 if prefixes.contains(&InstructionPrefix::Rep) => {
                                    // XEND: F3 0F 01 D5 — TSX transactional end
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Xend,
                                        operands: Vec::new(),
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xD6 if prefixes.contains(&InstructionPrefix::Repne) => {
                                    // XTEST: F2 0F 01 D6 — TSX test if in transaction
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Xtest,
                                        operands: Vec::new(),
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                // SGX enclosure instructions (detection-only stubs)
                                // ENCLS: 0x0F 0x01 CF-FF (privileged, reg field encodes leaf)
                                // ENCLU: 0x0F 0x01 E0-FF or D8-FF (unprivileged, reg field encodes leaf)
                                // NOTE: SGX requires NO prefix (F2/F3 conflict with CET/XEND/XTEST)
                                0xC8..=0xDF
                                    if !prefixes.contains(&InstructionPrefix::Rep)
                                        && !prefixes.contains(&InstructionPrefix::Repne) =>
                                {
                                    // ENCLS leaf (reg=0,1,2,3 in ModRM)
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Encls,
                                        operands: Vec::new(),
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xE0..=0xFF
                                    if !prefixes.contains(&InstructionPrefix::Rep)
                                        && !prefixes.contains(&InstructionPrefix::Repne) =>
                                {
                                    // ENCLU leaf (reg=4,5,6,7 in ModRM)
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Enclu,
                                        operands: Vec::new(),
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                other => {
                                    // The byte we read as "tertiary" might actually be a ModRM byte
                                    // for CET shadow stack instructions (with F3 prefix) or WRUSS (66 prefix).
                                    // Back up so we can parse it properly as a ModRM.
                                    local -= 1;
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;

                                    if prefixes.contains(&InstructionPrefix::Rep) {
                                        // F3 0F 01 /r: CET shadow stack instructions and WRSS
                                        match modrm.reg {
                                            0 => {
                                                // INCSSP r/m64: F3 0F 01 /0 (with F3 prefix)
                                                let src = if modrm.mod_bits == 0b11 {
                                                    Operand::Register(Register::from_modrm(
                                                        modrm.rm_register(),
                                                    ))
                                                } else {
                                                    modrm_operand(
                                                        &modrm,
                                                        arch,
                                                        &prefixes,
                                                        address + (local - cursor) as u64,
                                                    )
                                                };
                                                DecodedInstruction {
                                                    address,
                                                    size: local - cursor,
                                                    prefixes,
                                                    rex,
                                                    opcode: DecodedOpcode::Incssp,
                                                    operands: vec![src],
                                                    precise_faulting_memory: modrm.mod_bits != 0b11,
                                                    evex_info: EvexInfo::no_mask(),
                                                }
                                            }
                                            6 if modrm.mod_bits == 0b11 => {
                                                // SAVESSP: F3 0F 01 /6 (register-direct form, no memory operand)
                                                DecodedInstruction {
                                                    address,
                                                    size: local - cursor,
                                                    prefixes,
                                                    rex,
                                                    opcode: DecodedOpcode::Savesp,
                                                    operands: Vec::new(),
                                                    precise_faulting_memory: false,
                                                    evex_info: EvexInfo::no_mask(),
                                                }
                                            }
                                            6 => {
                                                // WRSS r32, m32: F3 0F 01 /6 (memory form)
                                                let address_operand = match modrm_operand(
                                                    &modrm,
                                                    arch,
                                                    &prefixes,
                                                    address + (local - cursor) as u64,
                                                ) {
                                                    Operand::Memory(m) => m,
                                                    _ => {
                                                        return Err(AppError::new(
                                                            ReasonCode::RcUnimplInsn,
                                                            "WRSS requires a memory destination",
                                                        ));
                                                    }
                                                };
                                                DecodedInstruction {
                                                    address,
                                                    size: local - cursor,
                                                    prefixes,
                                                    rex,
                                                    opcode: DecodedOpcode::Wrss,
                                                    operands: vec![
                                                        Operand::Memory(address_operand),
                                                        Operand::Register(Register::from_modrm(
                                                            modrm.rm_register(),
                                                        )),
                                                    ],
                                                    precise_faulting_memory: true,
                                                    evex_info: EvexInfo::no_mask(),
                                                }
                                            }
                                            7 => {
                                                // RSTORSSP m64: F3 0F 01 /7
                                                let address_operand = match modrm_operand(
                                                    &modrm,
                                                    arch,
                                                    &prefixes,
                                                    address + (local - cursor) as u64,
                                                ) {
                                                    Operand::Memory(m) => m,
                                                    _ => {
                                                        return Err(AppError::new(
                                                            ReasonCode::RcUnimplInsn,
                                                            "RSTORSSP requires a memory operand",
                                                        ));
                                                    }
                                                };
                                                DecodedInstruction {
                                                    address,
                                                    size: local - cursor,
                                                    prefixes,
                                                    rex,
                                                    opcode: DecodedOpcode::Rstorssp,
                                                    operands: vec![Operand::Memory(
                                                        address_operand,
                                                    )],
                                                    precise_faulting_memory: true,
                                                    evex_info: EvexInfo::no_mask(),
                                                }
                                            }
                                            _ => {
                                                return Err(AppError::new(
                                                    ReasonCode::RcUnimplInsn,
                                                    format!("unsupported F3 0F 01 /{}", modrm.reg),
                                                ));
                                            }
                                        }
                                    } else if prefixes.contains(&InstructionPrefix::OperandSize)
                                        && modrm.reg == 7
                                    {
                                        // WRUSS r32, m32: 66 0F 01 /7
                                        let address_operand = match modrm_operand(
                                            &modrm,
                                            arch,
                                            &prefixes,
                                            address + (local - cursor) as u64,
                                        ) {
                                            Operand::Memory(m) => m,
                                            _ => {
                                                return Err(AppError::new(
                                                    ReasonCode::RcUnimplInsn,
                                                    "WRUSS requires a memory destination",
                                                ));
                                            }
                                        };
                                        DecodedInstruction {
                                            address,
                                            size: local - cursor,
                                            prefixes,
                                            rex,
                                            opcode: DecodedOpcode::Wruss,
                                            operands: vec![
                                                Operand::Memory(address_operand),
                                                Operand::Register(Register::from_modrm(
                                                    modrm.rm_register(),
                                                )),
                                            ],
                                            precise_faulting_memory: true,
                                            evex_info: EvexInfo::no_mask(),
                                        }
                                    } else if prefixes.contains(&InstructionPrefix::Rep)
                                        && modrm.reg == 0
                                    {
                                        // Also handle INCSSP here for completeness
                                        let src = if modrm.mod_bits == 0b11 {
                                            Operand::Register(Register::from_modrm(
                                                modrm.rm_register(),
                                            ))
                                        } else {
                                            modrm_operand(
                                                &modrm,
                                                arch,
                                                &prefixes,
                                                address + (local - cursor) as u64,
                                            )
                                        };
                                        DecodedInstruction {
                                            address,
                                            size: local - cursor,
                                            prefixes,
                                            rex,
                                            opcode: DecodedOpcode::Incssp,
                                            operands: vec![src],
                                            precise_faulting_memory: modrm.mod_bits != 0b11,
                                            evex_info: EvexInfo::no_mask(),
                                        }
                                    } else {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            format!(
                                                "unsupported opcode 0x0f 0x01 tertiary {other:#x}"
                                            ),
                                        ));
                                    }
                                }
                            }
                        }
                        0x3A => {
                            let tertiary = *bytes.get(local).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "missing tertiary opcode for 0x0f 0x3a",
                                )
                            })?;
                            local += 1;
                            match tertiary {
                                0x63 if prefixes.contains(&InstructionPrefix::OperandSize) => {
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    let rhs = if modrm.mod_bits == 0b11 {
                                        Operand::Xmm(modrm.rm)
                                    } else {
                                        modrm_operand(
                                            &modrm,
                                            arch,
                                            &prefixes,
                                            address + (local - cursor) as u64,
                                        )
                                    };
                                    let precise_faulting_memory = !matches!(rhs, Operand::Xmm(_));
                                    let imm = read_immediate(bytes, local, 1)? as u8;
                                    local += 1;
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Pcmpistri,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            rhs,
                                            Operand::ImmediateU64(u64::from(imm)),
                                        ],
                                        precise_faulting_memory,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0x44 if prefixes.contains(&InstructionPrefix::OperandSize) => {
                                    // PCLMULQDQ: 0x66 0x0F 0x3A 0x44
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "PCLMULQDQ currently requires register operands",
                                        ));
                                    }
                                    let imm = read_immediate(bytes, local, 1)?;
                                    local += 1;
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Pclmulqdq,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                            Operand::ImmediateU64(imm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xCC => {
                                    // SHA1RNDS4: 0x0F 0x3A 0xCC
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "SHA1RNDS4 currently requires register operands",
                                        ));
                                    }
                                    let imm = read_immediate(bytes, local, 1)?;
                                    local += 1;
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Sha1rnds4,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                            Operand::ImmediateU64(imm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xDF if prefixes.contains(&InstructionPrefix::OperandSize) => {
                                    // AESKEYGENASSIST: 0x66 0x0F 0x3A 0xDF
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "AESKEYGENASSIST currently requires register operands",
                                        ));
                                    }
                                    let imm = read_immediate(bytes, local, 1)?;
                                    local += 1;
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Aeskeygenassist,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                            Operand::ImmediateU64(imm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unsupported opcode 0x0f 0x3a tertiary {other:#x}"),
                                    ));
                                }
                            }
                        }
                        0x21 | 0x23 => {
                            // MOV r32/r64, DRn (0x21) / MOV DRn, r32/r64 (0x23).
                            // The reg field selects DR0-DR7; rm selects the GPR. The
                            // control/debug register move form is always register-direct.
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let gpr = Register::from_modrm(modrm.rm);
                            let index = (modrm.reg & 0x07) as u64;
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: if next == 0x21 {
                                    DecodedOpcode::MovFromDr
                                } else {
                                    DecodedOpcode::MovToDr
                                },
                                operands: vec![
                                    Operand::Register(gpr),
                                    Operand::ImmediateU64(index),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xAE => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits == 0b11 {
                                if matches!((modrm.reg, modrm.rm_register()), (5..=7, 0)) {
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Nop,
                                        operands: Vec::new(),
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                } else {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unsupported opcode 0x0f 0xae /{}", modrm.reg),
                                    ));
                                }
                            } else {
                                match modrm.reg {
                                    2 | 3 => {
                                        let Operand::Memory(address_operand) = modrm_operand(
                                            &modrm,
                                            arch,
                                            &prefixes,
                                            address + (local - cursor) as u64,
                                        ) else {
                                            return Err(AppError::new(
                                                ReasonCode::RcUnimplInsn,
                                                "opcode 0x0f 0xae /2,/3 requires a memory operand",
                                            ));
                                        };
                                        DecodedInstruction {
                                            address,
                                            size: local - cursor,
                                            prefixes,
                                            rex,
                                            opcode: if modrm.reg == 2 {
                                                DecodedOpcode::Ldmxcsr
                                            } else {
                                                DecodedOpcode::Stmxcsr
                                            },
                                            operands: vec![Operand::Memory(address_operand)],
                                            precise_faulting_memory: true,
                                            evex_info: EvexInfo::no_mask(),
                                        }
                                    }
                                    6 => {
                                        // 0F AE /6: XSAVEOPT (no prefix) or CLWB
                                        // (66 0F AE /6). The OperandSize (66)
                                        // prefix selects CLWB; the bare form is
                                        // XSAVEOPT.
                                        let Operand::Memory(address_operand) = modrm_operand(
                                            &modrm,
                                            arch,
                                            &prefixes,
                                            address + (local - cursor) as u64,
                                        ) else {
                                            return Err(AppError::new(
                                                ReasonCode::RcUnimplInsn,
                                                "opcode 0x0f 0xae /6 requires a memory operand",
                                            ));
                                        };
                                        let is_clwb =
                                            prefixes.contains(&InstructionPrefix::OperandSize);
                                        DecodedInstruction {
                                            address,
                                            size: local - cursor,
                                            prefixes,
                                            rex,
                                            opcode: if is_clwb {
                                                DecodedOpcode::Clwb
                                            } else {
                                                DecodedOpcode::Xsaveopt
                                            },
                                            operands: vec![Operand::Memory(address_operand)],
                                            precise_faulting_memory: false,
                                            evex_info: EvexInfo::no_mask(),
                                        }
                                    }
                                    7 => {
                                        // CLFLUSH (no prefix) or CLFLUSHOPT (F3 prefix) - no-op on Apple Silicon
                                        let Operand::Memory(address_operand) = modrm_operand(
                                            &modrm,
                                            arch,
                                            &prefixes,
                                            address + (local - cursor) as u64,
                                        ) else {
                                            return Err(AppError::new(
                                                ReasonCode::RcUnimplInsn,
                                                "opcode 0x0f 0xae /7 requires a memory operand",
                                            ));
                                        };
                                        let has_f3 = prefixes.contains(&InstructionPrefix::Rep);
                                        DecodedInstruction {
                                            address,
                                            size: local - cursor,
                                            prefixes,
                                            rex,
                                            opcode: if has_f3 {
                                                DecodedOpcode::Clflushopt
                                            } else {
                                                DecodedOpcode::Clflush
                                            },
                                            operands: vec![Operand::Memory(address_operand)],
                                            precise_faulting_memory: false,
                                            evex_info: EvexInfo::no_mask(),
                                        }
                                    }
                                    8 => {
                                        // PCOMMIT: persistent commit (no-op on Apple Silicon)
                                        DecodedInstruction {
                                            address,
                                            size: local - cursor,
                                            prefixes,
                                            rex,
                                            opcode: DecodedOpcode::Pcommit,
                                            operands: Vec::new(),
                                            precise_faulting_memory: false,
                                            evex_info: EvexInfo::no_mask(),
                                        }
                                    }
                                    0 | 1 | 4 | 5 => {
                                        // FXSAVE(/0) FXRSTOR(/1) XSAVE(/4) XRSTOR(/5)
                                        let Operand::Memory(address_operand) = modrm_operand(
                                            &modrm,
                                            arch,
                                            &prefixes,
                                            address + (local - cursor) as u64,
                                        ) else {
                                            return Err(AppError::new(
                                                ReasonCode::RcUnimplInsn,
                                                "opcode 0x0f 0xae /0,/1,/4,/5 requires a memory operand",
                                            ));
                                        };
                                        DecodedInstruction {
                                            address,
                                            size: local - cursor,
                                            prefixes,
                                            rex,
                                            opcode: match modrm.reg {
                                                0 => DecodedOpcode::Fxsave,
                                                1 => DecodedOpcode::Fxrstor,
                                                4 => DecodedOpcode::Xsave,
                                                _ => DecodedOpcode::Xrstor,
                                            },
                                            operands: vec![Operand::Memory(address_operand)],
                                            precise_faulting_memory: true,
                                            evex_info: EvexInfo::no_mask(),
                                        }
                                    }
                                    other => {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            format!("unsupported opcode 0x0f 0xae /{}", other),
                                        ));
                                    }
                                }
                            }
                        }
                        0x40..=0x4F => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let width = operand_width(rex, &prefixes, arch);
                            let source =
                                compare_operand_to_operand(compare_operand(modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Cmovcc,
                                operands: vec![
                                    Operand::ImmediateU64(match next {
                                        0x40 => 12,
                                        0x41 => 13,
                                        0x42 => 2,
                                        0x43 => 3,
                                        0x44 => 0,
                                        0x45 => 1,
                                        0x46 => 5,
                                        0x47 => 4,
                                        0x48 => 6,
                                        0x49 => 7,
                                        0x4A => 14,
                                        0x4B => 15,
                                        0x4C => 8,
                                        0x4D => 9,
                                        0x4E => 10,
                                        0x4F => 11,
                                        _ => unreachable!("covered cmov opcode"),
                                    }),
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    source,
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x80..=0x8F => {
                            let displacement = read_i32(bytes, local)?;
                            local += 4;
                            let fallthrough = address + (local - cursor) as u64;
                            let target = (fallthrough as i128 + displacement as i128) as u64;
                            let condition = match next {
                                0x80 => 12,
                                0x81 => 13,
                                0x82 => 2,
                                0x83 => 3,
                                0x87 => 4,
                                0x86 => 5,
                                0x88 => 6,
                                0x89 => 7,
                                0x8A => 14,
                                0x8B => 15,
                                0x8C => 8,
                                0x8D => 9,
                                0x8E => 10,
                                0x8F => 11,
                                0x84 => 0,
                                0x85 => 1,
                                _ => unreachable!("covered conditional jump opcode"),
                            };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Jcc,
                                operands: vec![
                                    Operand::ImmediateU64(condition),
                                    Operand::ImmediateU64(target),
                                    Operand::ImmediateU64(fallthrough),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xC8..=0xCF => {
                            // BSWAP r32/r64: reverse byte order. In 64-bit mode the
                            // default width is 32 bits (with REX.W → 64 bits); the
                            // 66 prefix makes BSWAP undefined on modern CPUs, so
                            // it is treated as 32-bit here.
                            let width = if arch == GuestArch::X64
                                && rex.map(|value| value.w).unwrap_or(false)
                            {
                                8
                            } else {
                                4
                            };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Bswap,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(next - 0xC8)),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xA2 => DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Cpuid,
                            operands: Vec::new(),
                            precise_faulting_memory: false,
                            evex_info: EvexInfo::no_mask(),
                        },
                        0xB6 | 0xB7 => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let src = compare_operand(modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Movzx,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    compare_operand_to_operand(src),
                                    Operand::ImmediateU64(if next == 0xB6 { 1 } else { 2 }),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xBE | 0xBF => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let src = compare_operand(modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ));
                            let dst_width = if rex.map(|value| value.w).unwrap_or(false) {
                                8
                            } else {
                                4
                            };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Movsx,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    compare_operand_to_operand(src),
                                    Operand::ImmediateU64(if next == 0xBE { 1 } else { 2 }),
                                    Operand::ImmediateU64(dst_width),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xB8 => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Popcnt,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    Operand::Register(Register::from_modrm(modrm.rm_register())),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xBD => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Lzcnt,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    Operand::Register(Register::from_modrm(modrm.rm_register())),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xBC if !prefixes.contains(&InstructionPrefix::OperandSize)
                            && !prefixes.contains(&InstructionPrefix::Rep)
                            && !prefixes.contains(&InstructionPrefix::Repne) =>
                        {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "BSF currently requires register operands",
                                ));
                            }
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Bsf,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    Operand::Register(Register::from_modrm(modrm.rm_register())),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x90..=0x9F => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let rm_operand = modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            );
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Setcc,
                                operands: {
                                    let condition = Operand::ImmediateU64(match next {
                                        0x90 => 12,
                                        0x91 => 13,
                                        0x92 => 2,
                                        0x93 => 3,
                                        0x97 => 4,
                                        0x96 => 5,
                                        0x98 => 6,
                                        0x99 => 7,
                                        0x9A => 14,
                                        0x9B => 15,
                                        0x9C => 8,
                                        0x9D => 9,
                                        0x9E => 10,
                                        0x9F => 11,
                                        0x94 => 0,
                                        0x95 => 1,
                                        _ => unreachable!("covered setcc opcode"),
                                    });
                                    match rm_operand {
                                        Operand::Register(_) => vec![
                                            condition,
                                            Operand::Register8(ByteRegister::from_modrm(
                                                modrm.rm_register(),
                                                rex,
                                                arch,
                                            )),
                                        ],
                                        Operand::Memory(address_operand) => {
                                            vec![condition, Operand::Memory(address_operand)]
                                        }
                                        other => {
                                            return Err(AppError::new(
                                                ReasonCode::RcUnimplInsn,
                                                format!(
                                                    "unexpected rm operand for setcc: {other:?}"
                                                ),
                                            ));
                                        }
                                    }
                                },
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x18 => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            // PREFETCHT0 (reg=0), PREFETCHT1 (reg=1), PREFETCHT2 (reg=2), PREFETCHNTA (reg=3)
                            // All are no-ops on Apple Silicon.
                            match modrm.reg {
                                0..=3 => {
                                    let address_operand = if modrm.mod_bits == 0b11 {
                                        None
                                    } else {
                                        match modrm_operand(
                                            &modrm,
                                            arch,
                                            &prefixes,
                                            address + (local - cursor) as u64,
                                        ) {
                                            Operand::Memory(m) => Some(m),
                                            _ => None,
                                        }
                                    };
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Prefetch,
                                        operands: if let Some(m) = address_operand {
                                            vec![Operand::Memory(m)]
                                        } else {
                                            Vec::new()
                                        },
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unsupported opcode 0x0f 0x18 /{}", other),
                                    ));
                                }
                            }
                        }
                        // MPX boundary instructions (0x0F 0x1A/0x1B)
                        // BNDMK:   F2 0F 1A /r — Make bounds from memory
                        // BNDMOV:  66 0F 1A /r — Load bounds register from bnd/m128
                        0x1A => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if prefixes.contains(&InstructionPrefix::Repne) {
                                // BNDMK: F2 0F 1A /r — requires memory operand
                                if modrm.mod_bits == 0b11 {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        "BNDMK requires a memory operand",
                                    ));
                                }
                                let address_operand = match modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                ) {
                                    Operand::Memory(m) => m,
                                    _ => {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "BNDMK requires a memory operand",
                                        ));
                                    }
                                };
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::Bndmk,
                                    operands: vec![
                                        Operand::ImmediateU64(u64::from(modrm.reg)),
                                        Operand::Memory(address_operand),
                                    ],
                                    precise_faulting_memory: true,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            } else if prefixes.contains(&InstructionPrefix::OperandSize) {
                                // BNDMOV bnd1, bnd2/m128: 66 0F 1A /r — load bounds
                                if modrm.mod_bits == 0b11 {
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Bndmov,
                                        operands: vec![
                                            Operand::ImmediateU64(u64::from(modrm.reg)),
                                            Operand::ImmediateU64(u64::from(modrm.rm)),
                                            Operand::ImmediateU64(0), // 0 = load
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                } else {
                                    let address_operand = match modrm_operand(
                                        &modrm,
                                        arch,
                                        &prefixes,
                                        address + (local - cursor) as u64,
                                    ) {
                                        Operand::Memory(m) => m,
                                        _ => {
                                            return Err(AppError::new(
                                                ReasonCode::RcUnimplInsn,
                                                "BNDMOV requires a memory or register operand",
                                            ));
                                        }
                                    };
                                    // Memory form: load bounds from memory into bnd register
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Bndmov,
                                        operands: vec![
                                            Operand::ImmediateU64(u64::from(modrm.reg)),
                                            Operand::Memory(address_operand),
                                            Operand::ImmediateU64(0), // 0 = load
                                        ],
                                        precise_faulting_memory: true,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                            } else {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "unsupported 0x0f 0x1a prefix combination".to_string(),
                                ));
                            }
                        }
                        // BNDCL:   F2 0F 1B /r — Check lower bound
                        // BNDCN:   66 0F 1B /r — Check upper bound (unsigned)
                        // BNDMOV:  66 0F 1B /r — Store bounds to bnd/m128
                        0x1B => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if prefixes.contains(&InstructionPrefix::Repne) {
                                // BNDCL: F2 0F 1B /r — compare lower bound
                                let src = if modrm.mod_bits == 0b11 {
                                    Operand::ImmediateU64(u64::from(modrm.rm))
                                } else {
                                    let addr = match modrm_operand(
                                        &modrm,
                                        arch,
                                        &prefixes,
                                        address + (local - cursor) as u64,
                                    ) {
                                        Operand::Memory(m) => m,
                                        _ => {
                                            return Err(AppError::new(
                                                ReasonCode::RcUnimplInsn,
                                                "BNDCL requires a memory or register operand",
                                            ));
                                        }
                                    };
                                    Operand::Memory(addr)
                                };
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::Bndcl,
                                    operands: vec![
                                        Operand::ImmediateU64(u64::from(modrm.reg)),
                                        src,
                                    ],
                                    precise_faulting_memory: modrm.mod_bits != 0b11,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            } else if prefixes.contains(&InstructionPrefix::OperandSize) {
                                // BNDCN: 66 0F 1B /r — compare upper bound (unsigned)
                                // or BNDMOV store: 66 0F 1B /r — bnd/m128, bnd
                                // Both share same encoding; modrm.reg = bnd register
                                let src = if modrm.mod_bits == 0b11 {
                                    Operand::ImmediateU64(u64::from(modrm.rm))
                                } else {
                                    let addr = match modrm_operand(
                                        &modrm,
                                        arch,
                                        &prefixes,
                                        address + (local - cursor) as u64,
                                    ) {
                                        Operand::Memory(m) => m,
                                        _ => {
                                            return Err(AppError::new(
                                                ReasonCode::RcUnimplInsn,
                                                "BNDCN requires a memory or register operand",
                                            ));
                                        }
                                    };
                                    Operand::Memory(addr)
                                };
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::Bndcn,
                                    operands: vec![
                                        Operand::ImmediateU64(u64::from(modrm.reg)),
                                        src,
                                    ],
                                    precise_faulting_memory: modrm.mod_bits != 0b11,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            } else {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "unsupported 0x0f 0x1b prefix combination".to_string(),
                                ));
                            }
                        }
                        0x1F => {
                            let (_modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Nop,
                                operands: Vec::new(),
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x6E if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "MOVD xmm, r/m32 currently requires register operands",
                                ));
                            }
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::MovdToXmm,
                                operands: vec![
                                    Operand::Xmm(modrm.reg),
                                    Operand::Register(Register::from_modrm(modrm.rm_register())),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x70 if prefixes.contains(&InstructionPrefix::OperandSize)
                            || prefixes.contains(&InstructionPrefix::Repne) =>
                        {
                            let opcode = if prefixes.contains(&InstructionPrefix::OperandSize) {
                                DecodedOpcode::Pshufd
                            } else {
                                DecodedOpcode::Pshuflw
                            };
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    if prefixes.contains(&InstructionPrefix::OperandSize) {
                                        "PSHUFD currently requires register operands"
                                    } else {
                                        "PSHUFLW currently requires register operands"
                                    },
                                ));
                            }
                            let imm = read_immediate(bytes, local, 1)? as u8;
                            local += 1;
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode,
                                operands: vec![
                                    Operand::Xmm(modrm.reg),
                                    Operand::Xmm(modrm.rm),
                                    Operand::ImmediateU64(imm.into()),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x73 if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "PSRLDQ/PSLLDQ currently requires register operands",
                                ));
                            }
                            let imm = read_immediate(bytes, local, 1)? as u8;
                            local += 1;
                            let opcode = match modrm.reg {
                                3 => DecodedOpcode::Psrldq,
                                7 => DecodedOpcode::Pslldq,
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unsupported 0x66 0x0f 0x73 selector {other}"),
                                    ));
                                }
                            };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode,
                                operands: vec![
                                    Operand::Xmm(modrm.rm),
                                    Operand::ImmediateU64(u64::from(imm)),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x16 if !prefixes.contains(&InstructionPrefix::OperandSize)
                            && !prefixes.contains(&InstructionPrefix::Rep)
                            && !prefixes.contains(&InstructionPrefix::Repne) =>
                        {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "MOVHPS currently requires register operands",
                                ));
                            }
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Movlhps,
                                operands: vec![Operand::Xmm(modrm.reg), Operand::Xmm(modrm.rm)],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x10 | 0x11
                            if prefixes.contains(&InstructionPrefix::Rep)
                                || prefixes.contains(&InstructionPrefix::Repne) =>
                        {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if next == 0x10 {
                                if modrm.mod_bits == 0b11 {
                                    Operand::Xmm(modrm.rm)
                                } else {
                                    modrm_operand(
                                        &modrm,
                                        arch,
                                        &prefixes,
                                        address + (local - cursor) as u64,
                                    )
                                }
                            } else {
                                Operand::Xmm(modrm.reg)
                            };
                            let destination = if next == 0x10 {
                                Operand::Xmm(modrm.reg)
                            } else if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_))
                                || !matches!(destination, Operand::Xmm(_));
                            let width = if prefixes.contains(&InstructionPrefix::Rep) {
                                4
                            } else {
                                8
                            };
                            if matches!(source, Operand::Memory(_))
                                || matches!(destination, Operand::Memory(_))
                            {
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::VectorMove,
                                    operands: vec![
                                        destination,
                                        source,
                                        Operand::ImmediateU64(width),
                                    ],
                                    precise_faulting_memory,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            } else {
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::XmmMove,
                                    operands: vec![destination, source],
                                    precise_faulting_memory,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            }
                        }
                        0x10 | 0x11 | 0x28 | 0x29 | 0x6F | 0x7F => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if next == 0x10 || next == 0x28 || next == 0x6F {
                                if modrm.mod_bits == 0b11 {
                                    Operand::Xmm(modrm.rm)
                                } else {
                                    modrm_operand(
                                        &modrm,
                                        arch,
                                        &prefixes,
                                        address + (local - cursor) as u64,
                                    )
                                }
                            } else {
                                Operand::Xmm(modrm.reg)
                            };
                            let destination = if next == 0x10 || next == 0x28 || next == 0x6F {
                                Operand::Xmm(modrm.reg)
                            } else if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_))
                                || !matches!(destination, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::XmmMove,
                                operands: vec![destination, source],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xD6 if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let destination = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(destination, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::VectorMove,
                                operands: vec![
                                    destination,
                                    Operand::Xmm(modrm.reg),
                                    Operand::ImmediateU64(8),
                                ],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x7E if prefixes.contains(&InstructionPrefix::Rep) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::VectorMove,
                                operands: vec![
                                    Operand::Xmm(modrm.reg),
                                    source,
                                    Operand::ImmediateU64(8),
                                ],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x7E if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let destination = if modrm.mod_bits == 0b11 {
                                Operand::Register(Register::from_modrm(modrm.rm_register()))
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::MovdFromXmm,
                                operands: vec![destination, Operand::Xmm(modrm.reg)],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x5A if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Cvtpd2ps,
                                operands: vec![Operand::Xmm(modrm.reg), source],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xE6 if prefixes.contains(&InstructionPrefix::Rep) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Cvtdq2pd,
                                operands: vec![Operand::Xmm(modrm.reg), source],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x58 if prefixes.contains(&InstructionPrefix::Repne) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Addsd,
                                operands: vec![Operand::Xmm(modrm.reg), source],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x5E if prefixes.contains(&InstructionPrefix::Rep) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Divss,
                                operands: vec![Operand::Xmm(modrm.reg), source],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x2A if prefixes.contains(&InstructionPrefix::Rep)
                            || prefixes.contains(&InstructionPrefix::Repne) =>
                        {
                            // F3 = CVTSI2SS xmm, r/m32; F2 = CVTSI2SD xmm, r/m32.
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Register(Register::from_modrm(modrm.rm_register()))
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::CvtIntToFloat,
                                operands: vec![Operand::Xmm(modrm.reg), source],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x2C | 0x2D
                            if prefixes.contains(&InstructionPrefix::Rep)
                                || prefixes.contains(&InstructionPrefix::Repne) =>
                        {
                            // 0x2C F3 = CVTTSS2SI, F2 = CVTTSD2SI;
                            // 0x2D F3 = CVTSS2SI, F2 = CVTSD2SI.
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::CvtFloatToInt,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    source,
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x2E if !prefixes.contains(&InstructionPrefix::OperandSize)
                            && !prefixes.contains(&InstructionPrefix::Rep)
                            && !prefixes.contains(&InstructionPrefix::Repne) =>
                        {
                            // UCOMISS xmm, xmm/m32.
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let rhs = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(rhs, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Ucomi,
                                operands: vec![Operand::Xmm(modrm.reg), rhs],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x2F if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            // UCOMISD xmm, xmm/m64.
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let rhs = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(rhs, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Ucomi,
                                operands: vec![Operand::Xmm(modrm.reg), rhs],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x51 => {
                            // SQRTPS (plain), SQRTSS (F3), SQRTPD (66), SQRTSD (F2).
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_));
                            let kind = sse_float_kind(&prefixes);
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::SseSqrt { kind },
                                operands: vec![Operand::Xmm(modrm.reg), source],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x52 if !prefixes.contains(&InstructionPrefix::OperandSize)
                            && !prefixes.contains(&InstructionPrefix::Repne) =>
                        {
                            // RSQRTPS (plain), RSQRTSS (F3).
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::SseRsqrt,
                                operands: vec![Operand::Xmm(modrm.reg), source],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x53 if !prefixes.contains(&InstructionPrefix::OperandSize)
                            && !prefixes.contains(&InstructionPrefix::Repne) =>
                        {
                            // RCPPS (plain), RCPSS (F3).
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::SseRcp,
                                operands: vec![Operand::Xmm(modrm.reg), source],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x58 | 0x59 | 0x5C | 0x5D | 0x5E | 0x5F
                            if !(next == 0x58 && prefixes.contains(&InstructionPrefix::Repne)
                                || next == 0x5E && prefixes.contains(&InstructionPrefix::Rep)) =>
                        {
                            // Packed/scalar float arithmetic: ADDPS/ADDSS/ADDPD
                            // (0x58), MULPS/MULSS/MULPD (0x59), SUBPS/SUBSS/SUBPD
                            // (0x5C), MINPS/MINSS/MINPD (0x5D), DIVPS/DIVPD (0x5E),
                            // MAXPS/MAXSS/MAXPD (0x5F). The F2 0x58 (ADDSD) and
                            // F3 0x5E (DIVSS) forms are handled by dedicated arms.
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(source, Operand::Xmm(_));
                            let op = match next {
                                0x58 => SseArithOp::Add,
                                0x59 => SseArithOp::Mul,
                                0x5C => SseArithOp::Sub,
                                0x5D => SseArithOp::Min,
                                0x5E => SseArithOp::Div,
                                0x5F => SseArithOp::Max,
                                _ => unreachable!("covered sse arithmetic opcode"),
                            };
                            let kind = sse_float_kind(&prefixes);
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::SseArith { op, kind },
                                operands: vec![Operand::Xmm(modrm.reg), source],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x2F if !prefixes.contains(&InstructionPrefix::OperandSize)
                            && !prefixes.contains(&InstructionPrefix::Rep)
                            && !prefixes.contains(&InstructionPrefix::Repne) =>
                        {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let rhs = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(rhs, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Comiss,
                                operands: vec![Operand::Xmm(modrm.reg), rhs],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x74 if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let rhs = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(rhs, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::VectorCompareEqBytes,
                                operands: vec![
                                    Operand::Xmm(modrm.reg),
                                    Operand::Xmm(modrm.reg),
                                    rhs.clone(),
                                    Operand::ImmediateU64(16),
                                ],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xD7 if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "PMOVMSKB currently requires a register source",
                                ));
                            }
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::VectorMoveMaskBytes,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    Operand::Xmm(modrm.rm),
                                    Operand::ImmediateU64(16),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xEB if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let rhs = if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let precise_faulting_memory = !matches!(rhs, Operand::Xmm(_));
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::VectorOr,
                                operands: vec![
                                    Operand::Xmm(modrm.reg),
                                    Operand::Xmm(modrm.reg),
                                    rhs.clone(),
                                    Operand::ImmediateU64(16),
                                ],
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xEF => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Pxor,
                                operands: vec![Operand::Xmm(modrm.reg), Operand::Xmm(modrm.rm)],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x57 => {
                            // XORPS (plain) / XORPD (66): bitwise XOR of the low
                            // 128 bits; register or memory source.
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits == 0b11 {
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::Pxor,
                                    operands: vec![Operand::Xmm(modrm.reg), Operand::Xmm(modrm.rm)],
                                    precise_faulting_memory: false,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            } else {
                                let Operand::Memory(address_operand) = modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                ) else {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        "unexpected operand for opcode 0x0f 0x57",
                                    ));
                                };
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::VectorXor,
                                    operands: vec![
                                        Operand::Xmm(modrm.reg),
                                        Operand::Xmm(modrm.reg),
                                        Operand::Memory(address_operand),
                                        Operand::ImmediateU64(16),
                                    ],
                                    precise_faulting_memory: true,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            }
                        }
                        0xAF => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let source = if modrm.mod_bits == 0b11 {
                                Operand::Register(Register::from_modrm(modrm.rm_register()))
                            } else {
                                modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                )
                            };
                            let width = operand_width(rex, &prefixes, arch);
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::ImulReg,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    source.clone(),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: !matches!(source, Operand::Register(_)),
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xB0 | 0xB1 => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let width = if next == 0xB0 {
                                1
                            } else {
                                operand_width(rex, &prefixes, arch)
                            };
                            let source_reg = if width == 1 {
                                ByteRegister::from_modrm(modrm.reg, rex, arch).full_register()
                            } else {
                                Register::from_modrm(modrm.reg)
                            };
                            let rm_operand = modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            );
                            let (operands, precise_faulting_memory) = match rm_operand {
                                Operand::Register(_) => (
                                    vec![
                                        Operand::Register(Register::from_modrm(
                                            modrm.rm_register(),
                                        )),
                                        Operand::Register(source_reg),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    false,
                                ),
                                Operand::Memory(address_operand) => (
                                    vec![
                                        Operand::Memory(address_operand),
                                        Operand::Register(source_reg),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    true,
                                ),
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!(
                                            "unexpected rm operand for 0x0f 0x{next:02x}: {other:?}"
                                        ),
                                    ));
                                }
                            };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::LockCmpxchg,
                                operands,
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xD4 => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Paddq,
                                operands: vec![Operand::Xmm(modrm.reg), Operand::Xmm(modrm.rm)],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xFA if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "PSUBD currently requires register operands",
                                ));
                            }
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Psubd,
                                operands: vec![Operand::Xmm(modrm.reg), Operand::Xmm(modrm.rm)],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xFE if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "PADDD currently requires register operands",
                                ));
                            }
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Paddd,
                                operands: vec![Operand::Xmm(modrm.reg), Operand::Xmm(modrm.rm)],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x38 if prefixes.contains(&InstructionPrefix::OperandSize) => {
                            let third = *bytes.get(local).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "missing tertiary opcode after 0x0f 0x38",
                                )
                            })?;
                            local += 1;
                            match third {
                                0x40 => {
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "PMULLD currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Pmulld,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xDB => {
                                    // AESIMC: 0x66 0x0F 0x38 0xDB
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "AESIMC currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Aesimc,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xDC => {
                                    // AESENC: 0x66 0x0F 0x38 0xDC
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "AESENC currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Aesenc,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xDD => {
                                    // AESENCLAST: 0x66 0x0F 0x38 0xDD
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "AESENCLAST currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Aesenclast,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xDE => {
                                    // AESDEC: 0x66 0x0F 0x38 0xDE
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "AESDEC currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Aesdec,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xDF => {
                                    // AESDECLAST: 0x66 0x0F 0x38 0xDF
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "AESDECLAST currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Aesdeclast,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                _ => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unsupported 0x0f 0x38 opcode 0x{third:02x}"),
                                    ));
                                }
                            }
                        }
                        0x38 => {
                            // SHA instructions: 0x0F 0x38 without 0x66 prefix
                            let third = *bytes.get(local).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "missing tertiary opcode after 0x0f 0x38",
                                )
                            })?;
                            local += 1;
                            match third {
                                0xC8 => {
                                    // SHA1NEXTE: 0x0F 0x38 0xC8
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "SHA1NEXTE currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Sha1nexte,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xC9 => {
                                    // SHA1MSG1: 0x0F 0x38 0xC9
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "SHA1MSG1 currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Sha1msg1,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xCA => {
                                    // SHA1MSG2: 0x0F 0x38 0xCA
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "SHA1MSG2 currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Sha1msg2,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xCB => {
                                    // SHA256RNDS2: 0x0F 0x38 0xCB
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "SHA256RNDS2 currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Sha256rnds2,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xCC => {
                                    // SHA256MSG1: 0x0F 0x38 0xCC
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "SHA256MSG1 currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Sha256msg1,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                0xCD => {
                                    // SHA256MSG2: 0x0F 0x38 0xCD
                                    let (modrm, consumed) =
                                        parse_modrm(bytes, local, arch, rex, address_size_32)?;
                                    local += consumed;
                                    if modrm.mod_bits != 0b11 {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "SHA256MSG2 currently requires register operands",
                                        ));
                                    }
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Sha256msg2,
                                        operands: vec![
                                            Operand::Xmm(modrm.reg),
                                            Operand::Xmm(modrm.rm),
                                        ],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                _ => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unsupported 0x0f 0x38 opcode 0x{third:02x}"),
                                    ));
                                }
                            }
                        }
                        0xC0 | 0xC1 => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            let width = if next == 0xC0 {
                                1
                            } else {
                                operand_width(rex, &prefixes, arch)
                            };
                            let src_reg = if width == 1 {
                                ByteRegister::from_modrm(modrm.reg, rex, arch).full_register()
                            } else {
                                Register::from_modrm(modrm.reg)
                            };
                            let rm_operand = modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            );
                            let (operands, precise_faulting_memory) = match rm_operand {
                                Operand::Register(_) => (
                                    vec![
                                        Operand::Register(Register::from_modrm(
                                            modrm.rm_register(),
                                        )),
                                        Operand::Register(src_reg),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    false,
                                ),
                                Operand::Memory(address_operand) => (
                                    vec![
                                        Operand::Memory(address_operand),
                                        Operand::Register(src_reg),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    true,
                                ),
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!(
                                            "unexpected rm operand for 0x0f 0x{next:02x}: {other:?}"
                                        ),
                                    ));
                                }
                            };
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::LockXadd,
                                operands,
                                precise_faulting_memory,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xC7 => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            match modrm.reg {
                                1 => {
                                    let Operand::Memory(address_operand) = modrm_operand(
                                        &modrm,
                                        arch,
                                        &prefixes,
                                        address + (local - cursor) as u64,
                                    ) else {
                                        return Err(AppError::new(
                                            ReasonCode::RcUnimplInsn,
                                            "CMPXCHG8B currently requires a memory destination",
                                        ));
                                    };
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::LockCmpxchg8b,
                                        operands: vec![Operand::Memory(address_operand)],
                                        precise_faulting_memory: true,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                6 => {
                                    let dst = if modrm.mod_bits == 0b11 {
                                        Register::from_modrm(modrm.rm_register())
                                    } else {
                                        Register::Rax
                                    };
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Rdrand,
                                        operands: vec![Operand::Register(dst)],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                7 => {
                                    let dst = if modrm.mod_bits == 0b11 {
                                        Register::from_modrm(modrm.rm_register())
                                    } else {
                                        Register::Rax
                                    };
                                    DecodedInstruction {
                                        address,
                                        size: local - cursor,
                                        prefixes,
                                        rex,
                                        opcode: DecodedOpcode::Rdseed,
                                        operands: vec![Operand::Register(dst)],
                                        precise_faulting_memory: false,
                                        evex_info: EvexInfo::no_mask(),
                                    }
                                }
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unsupported opcode 0x0f 0xc7 /{}", other),
                                    ));
                                }
                            }
                        }
                        0xA3 => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "BT currently requires register operands",
                                ));
                            }
                            let width = operand_width(rex, &prefixes, arch);
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::BitTest,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.rm_register())),
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xBA => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.reg != 4 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unsupported 0x0fba group selector {}", modrm.reg),
                                ));
                            }
                            let imm = read_immediate(bytes, local, 1)?;
                            local += 1;
                            let width = operand_width(rex, &prefixes, arch);
                            let operand = modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            );
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::BitTest,
                                operands: vec![
                                    operand,
                                    Operand::ImmediateU64(imm),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: modrm.mod_bits != 0b11,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xA4 => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "SHLD currently requires register operands",
                                ));
                            }
                            let count = *bytes.get(local).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "missing immediate for SHLD",
                                )
                            })?;
                            local += 1;
                            let width = operand_width(rex, &prefixes, arch);
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::ShldImm,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.rm_register())),
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    Operand::ImmediateU64(u64::from(count)),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xA5 => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "SHLD currently requires register operands",
                                ));
                            }
                            let width = operand_width(rex, &prefixes, arch);
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::ShldCl,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.rm_register())),
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0xAC => {
                            let (modrm, consumed) =
                                parse_modrm(bytes, local, arch, rex, address_size_32)?;
                            local += consumed;
                            if modrm.mod_bits != 0b11 {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "SHRD currently requires register operands",
                                ));
                            }
                            let count = *bytes.get(local).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "missing immediate for SHRD",
                                )
                            })?;
                            local += 1;
                            let width = operand_width(rex, &prefixes, arch);
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::ShrdImm,
                                operands: vec![
                                    Operand::Register(Register::from_modrm(modrm.rm_register())),
                                    Operand::Register(Register::from_modrm(modrm.reg)),
                                    Operand::ImmediateU64(u64::from(count)),
                                    Operand::ImmediateU64(width as u64),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x0B => {
                            // UD2: guaranteed undefined instruction — decode cleanly
                            // and fault at execution so MSVC __assume(0)/assert paths
                            // surface as guest faults rather than decode errors.
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Ud2,
                                operands: vec![],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x31 => {
                            // RDTSC: read host timestamp counter into EDX:EAX.
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Rdtsc,
                                operands: vec![],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        0x33 => {
                            // RDPMC: read performance counter selected by ECX into EDX:EAX.
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::Rdpmc,
                                operands: vec![],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            }
                        }
                        _ => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported secondary opcode 0x{next:02x}"),
                            ));
                        }
                    }
                }
                0xFF => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    match modrm.reg {
                        0 => {
                            let width = operand_width(rex, &prefixes, arch);
                            match modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ) {
                                Operand::Register(dst) => DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::IncReg,
                                    operands: vec![
                                        Operand::Register(dst),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    precise_faulting_memory: false,
                                    evex_info: EvexInfo::no_mask(),
                                },
                                Operand::Memory(address_operand) => DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::IncReg,
                                    operands: vec![
                                        Operand::Memory(address_operand),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    precise_faulting_memory: true,
                                    evex_info: EvexInfo::no_mask(),
                                },
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unexpected operand for opcode 0xff /0: {other:?}"),
                                    ));
                                }
                            }
                        }
                        1 => {
                            let width = operand_width(rex, &prefixes, arch);
                            match modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ) {
                                Operand::Register(dst) => DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::DecReg,
                                    operands: vec![
                                        Operand::Register(dst),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    precise_faulting_memory: false,
                                    evex_info: EvexInfo::no_mask(),
                                },
                                Operand::Memory(address_operand) => DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::DecReg,
                                    operands: vec![
                                        Operand::Memory(address_operand),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    precise_faulting_memory: true,
                                    evex_info: EvexInfo::no_mask(),
                                },
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unexpected operand for opcode 0xff /1: {other:?}"),
                                    ));
                                }
                            }
                        }
                        2 => {
                            if modrm.mod_bits != 0b11 {
                                let Operand::Memory(address_operand) = modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                ) else {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        "opcode 0xff call requires a memory addressing mode",
                                    ));
                                };
                                let return_address = address + (local - cursor) as u64;
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::CallMemory,
                                    operands: vec![
                                        Operand::Memory(address_operand),
                                        Operand::ImmediateU64(return_address),
                                    ],
                                    precise_faulting_memory: true,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            } else {
                                let return_address = address + (local - cursor) as u64;
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::CallRegister,
                                    operands: vec![
                                        Operand::Register(Register::from_modrm(
                                            modrm.rm_register(),
                                        )),
                                        Operand::ImmediateU64(return_address),
                                    ],
                                    precise_faulting_memory: false,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            }
                        }
                        4 => {
                            if modrm.mod_bits != 0b11 {
                                let Operand::Memory(address_operand) = modrm_operand(
                                    &modrm,
                                    arch,
                                    &prefixes,
                                    address + (local - cursor) as u64,
                                ) else {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        "opcode 0xff jmp requires a memory addressing mode",
                                    ));
                                };
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::JmpMemory,
                                    operands: vec![Operand::Memory(address_operand)],
                                    precise_faulting_memory: true,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            } else {
                                DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::JmpRegister,
                                    operands: vec![Operand::Register(Register::from_modrm(
                                        modrm.rm_register(),
                                    ))],
                                    precise_faulting_memory: false,
                                    evex_info: EvexInfo::no_mask(),
                                }
                            }
                        }
                        6 => {
                            let width = operand_width(rex, &prefixes, arch);
                            match modrm_operand(
                                &modrm,
                                arch,
                                &prefixes,
                                address + (local - cursor) as u64,
                            ) {
                                Operand::Register(src) => DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::PushReg,
                                    operands: vec![Operand::Register(src)],
                                    precise_faulting_memory: false,
                                    evex_info: EvexInfo::no_mask(),
                                },
                                Operand::Memory(address_operand) => DecodedInstruction {
                                    address,
                                    size: local - cursor,
                                    prefixes,
                                    rex,
                                    opcode: DecodedOpcode::PushMemory,
                                    operands: vec![
                                        Operand::Memory(address_operand),
                                        Operand::ImmediateU64(width as u64),
                                    ],
                                    precise_faulting_memory: true,
                                    evex_info: EvexInfo::no_mask(),
                                },
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcUnimplInsn,
                                        format!("unexpected operand for opcode 0xff /6: {other:?}"),
                                    ));
                                }
                            }
                        }
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode 0xff group selector {other}"),
                            ));
                        }
                    }
                }
                0xFE => {
                    let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                    local += consumed;
                    match modrm.reg {
                        0 => match modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ) {
                            Operand::Register(_) if modrm.mod_bits == 0b11 => DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::IncReg,
                                operands: vec![
                                    Operand::Register8(ByteRegister::from_modrm(
                                        modrm.rm_register(),
                                        rex,
                                        arch,
                                    )),
                                    Operand::ImmediateU64(1),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            },
                            Operand::Memory(address_operand) => DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::IncReg,
                                operands: vec![
                                    Operand::Memory(address_operand),
                                    Operand::ImmediateU64(1),
                                ],
                                precise_faulting_memory: true,
                                evex_info: EvexInfo::no_mask(),
                            },
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected operand for opcode 0xfe /0: {other:?}"),
                                ));
                            }
                        },
                        1 => match modrm_operand(
                            &modrm,
                            arch,
                            &prefixes,
                            address + (local - cursor) as u64,
                        ) {
                            Operand::Register(_) if modrm.mod_bits == 0b11 => DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::DecReg,
                                operands: vec![
                                    Operand::Register8(ByteRegister::from_modrm(
                                        modrm.rm_register(),
                                        rex,
                                        arch,
                                    )),
                                    Operand::ImmediateU64(1),
                                ],
                                precise_faulting_memory: false,
                                evex_info: EvexInfo::no_mask(),
                            },
                            Operand::Memory(address_operand) => DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::DecReg,
                                operands: vec![
                                    Operand::Memory(address_operand),
                                    Operand::ImmediateU64(1),
                                ],
                                precise_faulting_memory: true,
                                evex_info: EvexInfo::no_mask(),
                            },
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    format!("unexpected operand for opcode 0xfe /1: {other:?}"),
                                ));
                            }
                        },
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported opcode 0xfe group selector {other}"),
                            ));
                        }
                    }
                }
                _ => {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!("unsupported opcode 0x{opcode:02x}"),
                    ));
                }
            }
        };
        cursor += instruction.size;
        decoded.push(instruction);
    }
    Ok(decoded)
}

pub(crate) fn parse_vex_prefix(
    bytes: &[u8],
    offset: usize,
    arch: GuestArch,
) -> AppResult<Option<(VexPrefix, usize)>> {
    // VEX prefix encoding is identical for IA-32e (x64) and IA-32 (x86) modes,
    // so the arch parameter is used for validation only.
    debug_assert!(
        arch == GuestArch::X86 || arch == GuestArch::X64,
        "VEX prefix parsing requires x86 family arch"
    );
    match bytes.get(offset).copied() {
        Some(0xC5) => {
            let second = *bytes.get(offset + 1).ok_or_else(|| {
                AppError::new(ReasonCode::RcUnimplInsn, "truncated two-byte VEX prefix")
            })?;
            Ok(Some((
                VexPrefix {
                    r: second & 0x80 == 0,
                    vvvv: (!(second >> 3)) & 0x0f,
                    w: false,
                    l: second & 0x04 != 0,
                    pp: second & 0x03,
                    map_select: 0,
                },
                2,
            )))
        }
        Some(0xC4) => {
            let byte1 = *bytes.get(offset + 1).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    "truncated three-byte VEX prefix byte 1",
                )
            })?;
            let byte2 = *bytes.get(offset + 2).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    "truncated three-byte VEX prefix byte 2",
                )
            })?;
            let map_select = byte1 & 0x1f;
            if map_select == 0 || map_select > 2 {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unsupported VEX map_select {map_select}"),
                ));
            }
            Ok(Some((
                VexPrefix {
                    r: byte1 & 0x80 == 0,
                    vvvv: (!(byte2 >> 3)) & 0x0f,
                    w: byte2 & 0x80 != 0,
                    l: byte2 & 0x04 != 0,
                    pp: byte2 & 0x03,
                    map_select,
                },
                3,
            )))
        }
        _ => Ok(None),
    }
}

/// Decode a 4-byte EVEX prefix (0x62 + 3 payload bytes) at the given offset.
/// Returns the parsed EvexPrefix and number of bytes consumed (4 on success).
pub(crate) fn decode_evex_prefix(
    bytes: &[u8],
    offset: usize,
) -> AppResult<Option<(EvexPrefix, usize)>> {
    match bytes.get(offset).copied() {
        Some(0x62) => {
            let b1 = *bytes.get(offset + 1).ok_or_else(|| {
                AppError::new(ReasonCode::RcUnimplInsn, "truncated EVEX prefix byte 1")
            })?;
            let b2 = *bytes.get(offset + 2).ok_or_else(|| {
                AppError::new(ReasonCode::RcUnimplInsn, "truncated EVEX prefix byte 2")
            })?;
            let b3 = *bytes.get(offset + 3).ok_or_else(|| {
                AppError::new(ReasonCode::RcUnimplInsn, "truncated EVEX prefix byte 3")
            })?;

            // Byte 1: [R' R X B R'' 0 0 m]
            let r_prime = b1 & 0x80 == 0; // R' inverted
            let r = b1 & 0x40 == 0; // R inverted
            let x = b1 & 0x20 == 0; // X inverted
            let b = b1 & 0x10 == 0; // B inverted
            let r_prime2 = b1 & 0x08 == 0; // R'' inverted
            let m_bit = b1 & 0x01; // map_select bit 0

            // Byte 2: [W v v v v 1 pp]
            let w = b2 & 0x80 != 0;
            let vvvv_low = (!(b2 >> 3)) & 0x0f; // bits 6:3 inverted
            let pp = b2 & 0x03;

            // Byte 3: [z L' L b V' a a a]
            let z = b3 & 0x80 != 0;
            let ll = (b3 >> 5) & 0x03;
            let bcast = b3 & 0x10 != 0;
            let v_prime = (!(b3 >> 3)) & 0x01; // V' inverted, bit 4 of vvvv
            let aaa = b3 & 0x07;

            let vvvv = (v_prime << 4) | vvvv_low; // 5-bit vvvv

            // map_select from m bit; EVEX uses bits [2:0] of byte 1 but only m bit is map
            // pp distinguishes further maps when needed
            let map_select = m_bit;

            if ll > 2 {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unsupported EVEX vector length LL={ll}"),
                ));
            }

            Ok(Some((
                EvexPrefix {
                    r,
                    x,
                    b,
                    r_prime,
                    r_prime2,
                    vvvv,
                    w,
                    ll,
                    pp,
                    z,
                    bcast,
                    aaa,
                    map_select,
                },
                4,
            )))
        }
        _ => Ok(None),
    }
}

pub(crate) fn vex_vvvv_to_register(vvvv: u8) -> Register {
    match vvvv & 0x0f {
        0 => Register::Rax,
        1 => Register::Rcx,
        2 => Register::Rdx,
        3 => Register::Rbx,
        4 => Register::Rsp,
        5 => Register::Rbp,
        6 => Register::Rsi,
        7 => Register::Rdi,
        8 => Register::R8,
        9 => Register::R9,
        10 => Register::R10,
        11 => Register::R11,
        12 => Register::R12,
        13 => Register::R13,
        14 => Register::R14,
        15 => Register::R15,
        _ => unreachable!(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_vex_instruction(
    bytes: &[u8],
    mut local: usize,
    cursor: usize,
    address: u64,
    prefixes: &[InstructionPrefix],
    arch: GuestArch,
    address_size_32: bool,
    vex: VexPrefix,
    opcode: u8,
) -> AppResult<DecodedInstruction> {
    match vex.map_select {
        0 => {
            // 0x0F opcode map — existing SSE/AVX vector instruction handling
            let width = vex.width_bytes();
            match opcode {
                0x77 if !vex.l && vex.pp == 0 => Ok(DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes: prefixes.to_vec(),
                    rex: vex.rex(),
                    opcode: DecodedOpcode::VzeroUpper,
                    operands: Vec::new(),
                    precise_faulting_memory: false,
                    evex_info: EvexInfo::no_mask(),
                }),
                0x10 | 0x11 | 0x28 | 0x29 | 0x6F | 0x7F => {
                    let valid_prefix = match opcode {
                        0x10 | 0x11 | 0x28 | 0x29 => vex.pp <= 1,
                        0x6F | 0x7F => vex.pp == 1,
                        _ => false,
                    };
                    if !valid_prefix {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported VEX move prefix pp={} for opcode 0x{opcode:02x}",
                                vex.pp
                            ),
                        ));
                    }
                    let (modrm, consumed) =
                        parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
                    local += consumed;
                    let source = if matches!(opcode, 0x10 | 0x28 | 0x6F) {
                        if modrm.mod_bits == 0b11 {
                            Operand::Xmm(modrm.rm)
                        } else {
                            modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                        }
                    } else {
                        Operand::Xmm(modrm.reg)
                    };
                    let destination = if matches!(opcode, 0x10 | 0x28 | 0x6F) {
                        Operand::Xmm(modrm.reg)
                    } else if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let precise_faulting_memory = !matches!(source, Operand::Xmm(_))
                        || !matches!(destination, Operand::Xmm(_));
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::VectorMove,
                        operands: vec![destination, source, Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                0x57 => {
                    if vex.pp > 1 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported VEX XOR prefix pp={} for opcode 0x57", vex.pp),
                        ));
                    }
                    let (modrm, consumed) =
                        parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
                    local += consumed;
                    let rhs = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::VectorXor,
                        operands: vec![
                            Operand::Xmm(modrm.reg),
                            Operand::Xmm(vex.vvvv),
                            rhs.clone(),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: !matches!(rhs, Operand::Xmm(_)),
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                0xEF => {
                    if vex.pp != 1 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported VEX integer XOR prefix pp={} for opcode 0xef",
                                vex.pp
                            ),
                        ));
                    }
                    let (modrm, consumed) =
                        parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
                    local += consumed;
                    let rhs = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::VectorXor,
                        operands: vec![
                            Operand::Xmm(modrm.reg),
                            Operand::Xmm(vex.vvvv),
                            rhs.clone(),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: !matches!(rhs, Operand::Xmm(_)),
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                0xD4 => {
                    if vex.pp != 1 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported VEX integer add prefix pp={} for opcode 0xd4",
                                vex.pp
                            ),
                        ));
                    }
                    let (modrm, consumed) =
                        parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
                    local += consumed;
                    let rhs = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::VectorAddQ,
                        operands: vec![
                            Operand::Xmm(modrm.reg),
                            Operand::Xmm(vex.vvvv),
                            rhs.clone(),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: !matches!(rhs, Operand::Xmm(_)),
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                0x74 => {
                    if vex.pp != 1 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported VEX byte compare prefix pp={} for opcode 0x74",
                                vex.pp
                            ),
                        ));
                    }
                    let (modrm, consumed) =
                        parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
                    local += consumed;
                    let rhs = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::VectorCompareEqBytes,
                        operands: vec![
                            Operand::Xmm(modrm.reg),
                            Operand::Xmm(vex.vvvv),
                            rhs.clone(),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: !matches!(rhs, Operand::Xmm(_)),
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                0xD7 => {
                    if vex.pp != 1 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported VEX movemask prefix pp={} for opcode 0xd7",
                                vex.pp
                            ),
                        ));
                    }
                    let (modrm, consumed) =
                        parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
                    local += consumed;
                    if modrm.mod_bits != 0b11 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "VPMOVMSKB currently requires a register source",
                        ));
                    }
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::VectorMoveMaskBytes,
                        operands: vec![
                            Operand::Register(Register::from_modrm(modrm.reg)),
                            Operand::Xmm(modrm.rm),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                // AVX2 VEX.256 integer ops (0x0F map, pp=1 i.e. 0x66 prefix)
                // VPAND (0xDB), VPANDN (0xDF), VPOR (0xEB)
                0xDB | 0xDF | 0xEB => {
                    if vex.pp != 1 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported VEX integer op prefix pp={} for opcode 0x{opcode:02x}",
                                vex.pp
                            ),
                        ));
                    }
                    let (modrm, consumed) =
                        parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
                    local += consumed;
                    let rhs = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let opcode = match opcode {
                        0xDB => DecodedOpcode::VectorAnd,
                        0xDF => DecodedOpcode::VectorAndNot,
                        0xEB => DecodedOpcode::VectorOr,
                        _ => unreachable!(),
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode,
                        operands: vec![
                            Operand::Xmm(modrm.reg),
                            Operand::Xmm(vex.vvvv),
                            rhs.clone(),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: !matches!(rhs, Operand::Xmm(_)),
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                // VPADDB (0xFC), VPADDW (0xFD), VPADDD (0xFE) with pp=1
                // VPSUBB (0xF8), VPSUBW (0xF9), VPSUBD (0xFA), VPSUBQ (0xFB) with pp=1
                0xF8..=0xFE => {
                    if vex.pp != 1 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported VEX integer add/sub prefix pp={} for opcode 0x{opcode:02x}",
                                vex.pp
                            ),
                        ));
                    }
                    let (modrm, consumed) =
                        parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
                    local += consumed;
                    let rhs = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let vector_kind = match opcode {
                        0xFC => VectorIntKind::Paddb,
                        0xFD => VectorIntKind::Paddw,
                        0xFE => VectorIntKind::Paddd,
                        0xF8 => VectorIntKind::Psubb,
                        0xF9 => VectorIntKind::Psubw,
                        0xFA => VectorIntKind::Psubd,
                        0xFB => VectorIntKind::Psubq,
                        _ => unreachable!(),
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::VectorIntOp { kind: vector_kind },
                        operands: vec![
                            Operand::Xmm(modrm.reg),
                            Operand::Xmm(vex.vvvv),
                            rhs.clone(),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: !matches!(rhs, Operand::Xmm(_)),
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                // VPSLLW (0xF1), VPSLLD (0xF2), VPSLLQ (0xF3) with pp=1
                // VPSRLW (0xD1), VPSRLD (0xD2), VPSRLQ (0xD3) with pp=1
                // VPSRAW (0xE1), VPSRAD (0xE2) with pp=1
                0xF1 | 0xF2 | 0xF3 | 0xD1 | 0xD2 | 0xD3 | 0xE1 | 0xE2 => {
                    if vex.pp != 1 {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "unsupported VEX shift prefix pp={} for opcode 0x{opcode:02x}",
                                vex.pp
                            ),
                        ));
                    }
                    let (modrm, consumed) =
                        parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
                    local += consumed;
                    let rhs = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let vector_kind = match opcode {
                        0xF1 => VectorIntKind::Psllw,
                        0xF2 => VectorIntKind::Pslld,
                        0xF3 => VectorIntKind::Psllq,
                        0xD1 => VectorIntKind::Psrlw,
                        0xD2 => VectorIntKind::Psrld,
                        0xD3 => VectorIntKind::Psrlq,
                        0xE1 => VectorIntKind::Psraw,
                        0xE2 => VectorIntKind::Psrad,
                        _ => unreachable!(),
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::VectorIntOp { kind: vector_kind },
                        operands: vec![
                            Operand::Xmm(modrm.reg),
                            Operand::Xmm(vex.vvvv),
                            rhs.clone(),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: !matches!(rhs, Operand::Xmm(_)),
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                other => Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unsupported VEX opcode 0x{other:02x}"),
                )),
            }
        }
        1 => {
            // 0x0F38 opcode map — BMI1/BMI2/ADX instructions
            let _width = if vex.w { 8 } else { 4 };
            let (modrm, consumed) = parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
            local += consumed;
            let dst = Register::from_modrm(modrm.reg);
            let src = |modrm: &ParsedModrm| -> Operand {
                if modrm.mod_bits == 0b11 {
                    Operand::Register(Register::from_modrm(modrm.rm_register()))
                } else {
                    modrm_operand(modrm, arch, prefixes, address + (local - cursor) as u64)
                }
            };
            match (vex.pp, opcode) {
                (0, 0xF2) => {
                    // ANDN: dst=ModRM.reg, src1=VEX.vvvv, src2=ModRM.r/m
                    let lhs = vex_vvvv_to_register(vex.vvvv);
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Andn,
                        operands: vec![Operand::Register(dst), Operand::Register(lhs), src(&modrm)],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                (0, 0xF7) => {
                    // BEXTR: dst=ModRM.reg, src=ModRM.r/m, range=VEX.vvvv
                    let range = vex_vvvv_to_register(vex.vvvv);
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Bextr,
                        operands: vec![
                            Operand::Register(dst),
                            src(&modrm),
                            Operand::Register(range),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                (2, 0xF3) => {
                    // BLSI (reg=3), BLSMSK (reg=2), BLSR (reg=1)
                    let opcode_kind = match modrm.reg & 0x07 {
                        1 => DecodedOpcode::Blsr,
                        2 => DecodedOpcode::Blsmsk,
                        3 => DecodedOpcode::Blsi,
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported BMI group opcode /{} for 0x0f38 F3", other),
                            ));
                        }
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: opcode_kind,
                        operands: vec![Operand::Register(dst), src(&modrm)],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                (0, 0xF5) => {
                    // BZHI: dst=ModRM.reg, src=ModRM.r/m, index=VEX.vvvv
                    let index = vex_vvvv_to_register(vex.vvvv);
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Bzhi,
                        operands: vec![
                            Operand::Register(dst),
                            src(&modrm),
                            Operand::Register(index),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                (3, 0xF6) => {
                    // MULX: dst_lo=VEX.vvvv, dst_hi=ModRM.reg, src=ModRM.r/m
                    let dst_lo = vex_vvvv_to_register(vex.vvvv);
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Mulx,
                        operands: vec![
                            Operand::Register(dst_lo),
                            Operand::Register(dst),
                            src(&modrm),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                (3, 0xF5) => {
                    // PDEP: dst=ModRM.reg, src=VEX.vvvv, mask=ModRM.r/m
                    let vvvv_src = vex_vvvv_to_register(vex.vvvv);
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Pdep,
                        operands: vec![
                            Operand::Register(dst),
                            Operand::Register(vvvv_src),
                            src(&modrm),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                (2, 0xF5) => {
                    // PEXT: dst=ModRM.reg, src=VEX.vvvv, mask=ModRM.r/m
                    let vvvv_src = vex_vvvv_to_register(vex.vvvv);
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Pext,
                        operands: vec![
                            Operand::Register(dst),
                            Operand::Register(vvvv_src),
                            src(&modrm),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                (2, 0xF7) => {
                    // SARX: dst=ModRM.reg, src=ModRM.r/m, shift=VEX.vvvv
                    let shift = vex_vvvv_to_register(vex.vvvv);
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Sarx,
                        operands: vec![
                            Operand::Register(dst),
                            src(&modrm),
                            Operand::Register(shift),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                (3, 0xF7) => {
                    // SHRX: dst=ModRM.reg, src=ModRM.r/m, shift=VEX.vvvv
                    let shift = vex_vvvv_to_register(vex.vvvv);
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Shrx,
                        operands: vec![
                            Operand::Register(dst),
                            src(&modrm),
                            Operand::Register(shift),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                (1, 0xF7) => {
                    // SHLX: dst=ModRM.reg, src=ModRM.r/m, shift=VEX.vvvv
                    let shift = vex_vvvv_to_register(vex.vvvv);
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Shlx,
                        operands: vec![
                            Operand::Register(dst),
                            src(&modrm),
                            Operand::Register(shift),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                // ADX instructions: ADCX (pp=1=0x66), ADOX (pp=2=0xF3)
                // Both use opcode 0xF6 in 0F38 map, GPR operands
                (1, 0xF6) => {
                    // ADCX: dst=ModRM.reg, src=ModRM.r/m
                    let width: usize = if vex.w { 8 } else { 4 };
                    let dst = Register::from_modrm(modrm.reg);
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Register(Register::from_modrm(modrm.rm_register()))
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Adcx,
                        operands: vec![
                            Operand::Register(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                (2, 0xF6) => {
                    // ADOX: dst=ModRM.reg, src=ModRM.r/m
                    let width: usize = if vex.w { 8 } else { 4 };
                    let dst = Register::from_modrm(modrm.reg);
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Register(Register::from_modrm(modrm.rm_register()))
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Adox,
                        operands: vec![
                            Operand::Register(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                // FMA opcodes in 0F38 map with pp=1 (0x66)
                (1, 0x98)
                | (1, 0x9A)
                | (1, 0x9C)
                | (1, 0xA8)
                | (1, 0xAA)
                | (1, 0xAC)
                | (1, 0xB8)
                | (1, 0xBA)
                | (1, 0xBC) => {
                    let width = vex.width_bytes();
                    let dst = modrm.reg;
                    let src1 = vex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let fma_opcode = match (vex.pp, opcode, vex.w) {
                        (1, 0x98, false) => DecodedOpcode::Vfmadd132ps,
                        (1, 0x98, true) => DecodedOpcode::Vfmadd132pd,
                        (1, 0x9A, false) => DecodedOpcode::Vfmsub132ps,
                        (1, 0x9A, true) => DecodedOpcode::Vfmsub132pd,
                        (1, 0x9C, false) => DecodedOpcode::Vfnmadd132ps,
                        (1, 0x9C, true) => DecodedOpcode::Vfnmadd132pd,
                        (1, 0xA8, false) => DecodedOpcode::Vfmadd213ps,
                        (1, 0xA8, true) => DecodedOpcode::Vfmadd213pd,
                        (1, 0xAA, false) => DecodedOpcode::Vfmsub213ps,
                        (1, 0xAA, true) => DecodedOpcode::Vfmsub213pd,
                        (1, 0xAC, false) => DecodedOpcode::Vfnmadd213ps,
                        (1, 0xAC, true) => DecodedOpcode::Vfnmadd213pd,
                        (1, 0xB8, false) => DecodedOpcode::Vfmadd231ps,
                        (1, 0xB8, true) => DecodedOpcode::Vfmadd231pd,
                        (1, 0xBA, false) => DecodedOpcode::Vfmsub231ps,
                        (1, 0xBA, true) => DecodedOpcode::Vfmsub231pd,
                        (1, 0xBC, false) => DecodedOpcode::Vfnmadd231ps,
                        (1, 0xBC, true) => DecodedOpcode::Vfnmadd231pd,
                        _ => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!(
                                    "unsupported FMA VEX pp={} opcode=0x{opcode:02x} w={}",
                                    vex.pp, vex.w
                                ),
                            ));
                        }
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: fma_opcode,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if vex.w { 1 } else { 0 }), // element_kind: 0=PS, 1=PD
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                _ => Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "unsupported VEX 0F38 opcode pp={} opcode=0x{opcode:02x}",
                        vex.pp
                    ),
                )),
            }
        }
        2 => {
            // 0x0F3A opcode map — RORX
            let _width = if vex.w { 8 } else { 4 };
            let (modrm, consumed) = parse_modrm(bytes, local, arch, vex.rex(), address_size_32)?;
            local += consumed;
            let imm = read_immediate(bytes, local, 1)? as u8;
            local += 1;
            match (opcode, vex.pp) {
                (0xF0, 0) => {
                    // RORX: dst=ModRM.reg, src=ModRM.r/m, imm8
                    let dst = Register::from_modrm(modrm.reg);
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Register(Register::from_modrm(modrm.rm_register()))
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: vex.rex(),
                        opcode: DecodedOpcode::Rorx,
                        operands: vec![
                            Operand::Register(dst),
                            src,
                            Operand::ImmediateU64(u64::from(imm)),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                _ => Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "unsupported VEX 0F3A opcode pp={} opcode=0x{opcode:02x}",
                        vex.pp
                    ),
                )),
            }
        }
        _ => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported VEX map_select {}", vex.map_select),
        )),
    }
}

/// Decode an instruction using an EVEX prefix.
/// Currently supports FMA instructions (map_select 1 = 0x0F38).
/// Additional EVEX-coded instructions (AVX-512) can be added here.
#[allow(unreachable_patterns)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_evex_instruction(
    bytes: &[u8],
    mut local: usize,
    cursor: usize,
    address: u64,
    prefixes: &[InstructionPrefix],
    arch: GuestArch,
    address_size_32: bool,
    evex: EvexPrefix,
    opcode: u8,
) -> AppResult<DecodedInstruction> {
    match evex.map_select {
        1 => {
            // 0x0F38 opcode map — EVEX-coded FMA and AVX-512 instructions
            let width = evex.width_bytes();
            let (modrm, consumed) = parse_modrm(bytes, local, arch, None, address_size_32)?;
            local += consumed;
            match (evex.pp, opcode) {
                // FMA opcodes with EVEX prefix (same opcodes as VEX 0F38.66)
                (1, 0x98)
                | (1, 0x9A)
                | (1, 0x9C)
                | (1, 0xA8)
                | (1, 0xAA)
                | (1, 0xAC)
                | (1, 0xB8)
                | (1, 0xBA)
                | (1, 0xBC) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let fma_opcode = match (evex.pp, opcode, evex.w) {
                        (1, 0x98, false) => DecodedOpcode::Vfmadd132ps,
                        (1, 0x98, true) => DecodedOpcode::Vfmadd132pd,
                        (1, 0x9A, false) => DecodedOpcode::Vfmsub132ps,
                        (1, 0x9A, true) => DecodedOpcode::Vfmsub132pd,
                        (1, 0x9C, false) => DecodedOpcode::Vfnmadd132ps,
                        (1, 0x9C, true) => DecodedOpcode::Vfnmadd132pd,
                        (1, 0xA8, false) => DecodedOpcode::Vfmadd213ps,
                        (1, 0xA8, true) => DecodedOpcode::Vfmadd213pd,
                        (1, 0xAA, false) => DecodedOpcode::Vfmsub213ps,
                        (1, 0xAA, true) => DecodedOpcode::Vfmsub213pd,
                        (1, 0xAC, false) => DecodedOpcode::Vfnmadd213ps,
                        (1, 0xAC, true) => DecodedOpcode::Vfnmadd213pd,
                        (1, 0xB8, false) => DecodedOpcode::Vfmadd231ps,
                        (1, 0xB8, true) => DecodedOpcode::Vfmadd231pd,
                        (1, 0xBA, false) => DecodedOpcode::Vfmsub231ps,
                        (1, 0xBA, true) => DecodedOpcode::Vfmsub231pd,
                        (1, 0xBC, false) => DecodedOpcode::Vfnmadd231ps,
                        (1, 0xBC, true) => DecodedOpcode::Vfnmadd231pd,
                        _ => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!(
                                    "unsupported FMA EVEX pp={} opcode=0x{opcode:02x} w={}",
                                    evex.pp, evex.w
                                ),
                            ));
                        }
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: fma_opcode,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(evex.width_bytes() as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VPERMD/VPERMPS (0F38 16/36) - pp=01 (0x66), W=0
                (1, 0x16) if !evex.w => {
                    // VPERMPS: dst=ModRM.reg, src1=vvvv (indices), src2=ModRM.r/m
                    let dst = modrm.reg;
                    let indices = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermps,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(indices),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(0), // element_size=4 (f32)
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x36) if !evex.w => {
                    // VPERMD: dst=ModRM.reg, src1=vvvv (indices), src2=ModRM.r/m
                    let dst = modrm.reg;
                    let indices = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermd,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(indices),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(0), // element_size=4
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VPERMQ/VPERMPD (0F38 16/36) - pp=01, W=1
                (1, 0x16) if evex.w => {
                    // VPERMPD: dst=ModRM.reg, src=ModRM.r/m, indices=vvvv (imm)
                    let dst = modrm.reg;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermpd,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(evex.vvvv),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(1), // element_size=8 (f64)
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x36) if evex.w => {
                    // VPERMQ: dst=ModRM.reg, src=ModRM.r/m, indices=vvvv (imm)
                    let dst = modrm.reg;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermq,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(evex.vvvv),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(1), // element_size=8
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VPERMI2* (0F38 66-76)
                (1, 0x76) if !evex.w => {
                    // VPERMI2D: dst=ModRM.reg, src1=vvvv (idx), src2=ModRM.r/m
                    let dst = modrm.reg;
                    let idx = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermi2d,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(idx),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(0),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x76) if evex.w => {
                    let dst = modrm.reg;
                    let idx = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermi2q,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(idx),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(1),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x77) if !evex.w => {
                    let dst = modrm.reg;
                    let idx = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermi2ps,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(idx),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(0),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x77) if evex.w => {
                    let dst = modrm.reg;
                    let idx = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermi2pd,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(idx),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(1),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VPERMT2* (0F38 7E/7F)
                (1, 0x7E) if !evex.w => {
                    let dst = modrm.reg;
                    let idx = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermt2d,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(idx),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(0),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x7E) if evex.w => {
                    let dst = modrm.reg;
                    let idx = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermt2q,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(idx),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(1),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x7F) if !evex.w => {
                    let dst = modrm.reg;
                    let idx = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermt2ps,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(idx),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(0),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x7F) if evex.w => {
                    let dst = modrm.reg;
                    let idx = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vpermt2pd,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(idx),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(1),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VFIXUPIMMPS/PD (0F38 54)
                (1, 0x54) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vfixupimmps
                        } else {
                            DecodedOpcode::Vfixupimmpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VGETEXPPS/PD (0F38 42/43)
                (1, 0x42) => {
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vgetexpps
                        } else {
                            DecodedOpcode::Vgetexppd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x43) => {
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vgetmantps
                        } else {
                            DecodedOpcode::Vgetmantpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VREDUCEPS/PD (0F38 56)
                (1, 0x56) => {
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vreduceps
                        } else {
                            DecodedOpcode::Vreducepd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VRANGEPS/PD (0F38 50)
                (1, 0x50) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vrangeps
                        } else {
                            DecodedOpcode::Vrangepd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VSCALEFPS/PD (0F38 2C/2D)
                (1, 0x2C) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vscalefps
                        } else {
                            DecodedOpcode::Vscalefpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x2D) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vscalefps
                        } else {
                            DecodedOpcode::Vscalefpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VFPCLASSPS/PD (0F38 66/67)
                (1, 0x66) => {
                    let dst = modrm.reg; // k register
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vfpclassps
                        } else {
                            DecodedOpcode::Vfpclasspd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (1, 0x67) => {
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vfpclassps
                        } else {
                            DecodedOpcode::Vfpclasspd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VPTERNLOG D/Q (0F38 25)
                (1, 0x25) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vpternlogd
                        } else {
                            DecodedOpcode::Vpternlogq
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VPCONFLICT D/Q (0F38 C4)
                (1, 0xC4) => {
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vpconflictd
                        } else {
                            DecodedOpcode::Vpconflictq
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VCOMPRESS PS/PD (0F38 8A)
                (1, 0x8A) => {
                    let dst = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let src = modrm.reg;
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vcompressps
                        } else {
                            DecodedOpcode::Vcompresspd
                        },
                        operands: vec![
                            dst,
                            Operand::Xmm(src),
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VEXPAND PS/PD (0F38 89)
                (1, 0x89) => {
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::Vexpandps
                        } else {
                            DecodedOpcode::Vexpandpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VGATHERDPS/QPS (0F38 92/93) - VSIB addressing
                (1, 0x92) | (1, 0x93) | (1, 0xA2) | (1, 0xA3) => {
                    // Gather: VSIB addressing where ModRM.r/m encodes base+index
                    let dst = modrm.reg;
                    let vsib_reg = modrm.rm;
                    let (element_size, op) = match (opcode, evex.w) {
                        (0x92, false) => (4u8, DecodedOpcode::Vgatherdps),
                        (0x92, true) => (8u8, DecodedOpcode::Vgatherdpd),
                        (0x93, false) => (4u8, DecodedOpcode::Vgatherqps),
                        (0x93, true) => (8u8, DecodedOpcode::Vgatherqpd),
                        (0xA2, false) => (4u8, DecodedOpcode::Vgatherdps),
                        (0xA2, true) => (8u8, DecodedOpcode::Vgatherdpd),
                        (0xA3, false) => (4u8, DecodedOpcode::Vgatherqps),
                        (0xA3, true) => (8u8, DecodedOpcode::Vgatherqpd),
                        _ => unreachable!(),
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: op,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(vsib_reg), // base+index in VSIB
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(element_size as u64),
                        ],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VSCATTERDPS/QPS (0F38 A0/A1)
                (1, 0xA0) | (1, 0xA1) | (1, 0xB0) | (1, 0xB1) => {
                    let src = modrm.reg;
                    let vsib_reg = modrm.rm;
                    let (element_size, op) = match (opcode, evex.w) {
                        (0xA0, false) => (4u8, DecodedOpcode::Vscatterdps),
                        (0xA0, true) => (8u8, DecodedOpcode::Vscatterdpd),
                        (0xA1, false) => (4u8, DecodedOpcode::Vscatterqps),
                        (0xA1, true) => (8u8, DecodedOpcode::Vscatterqpd),
                        (0xB0, false) => (4u8, DecodedOpcode::Vscatterdps),
                        (0xB0, true) => (8u8, DecodedOpcode::Vscatterdpd),
                        (0xB1, false) => (4u8, DecodedOpcode::Vscatterqps),
                        (0xB1, true) => (8u8, DecodedOpcode::Vscatterqpd),
                        _ => unreachable!(),
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: op,
                        operands: vec![
                            Operand::Xmm(vsib_reg),
                            Operand::Xmm(src),
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(element_size as u64),
                        ],
                        precise_faulting_memory: true,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                _ => Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "unsupported EVEX 0F38 opcode pp={} opcode=0x{opcode:02x} w={}",
                        evex.pp, evex.w
                    ),
                )),
            }
        }
        0 => {
            // 0x0F opcode map — EVEX-coded vector instructions (AVX-512 mask-enabled versions)
            let width = evex.width_bytes();
            let (modrm, consumed) = parse_modrm(bytes, local, arch, None, address_size_32)?;
            local += consumed;
            match (evex.pp, opcode) {
                // VMOVAPS / VMOVAPD / VMOVUPS / VMOVUPD (EVEX mask versions)
                (0, 0x10) | (0, 0x11) | (0, 0x28) | (0, 0x29) | (1, 0x6F) | (1, 0x7F) => {
                    let destination = if matches!(opcode, 0x10 | 0x28 | 0x6F) {
                        Operand::Xmm(modrm.reg)
                    } else if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let source = if matches!(opcode, 0x10 | 0x28 | 0x6F) {
                        if modrm.mod_bits == 0b11 {
                            Operand::Xmm(modrm.rm)
                        } else {
                            modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                        }
                    } else {
                        Operand::Xmm(modrm.reg)
                    };
                    let precise_faulting_memory = !matches!(source, Operand::Xmm(_))
                        || !matches!(destination, Operand::Xmm(_));
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::VectorMove,
                        operands: vec![destination, source, Operand::ImmediateU64(width as u64)],
                        precise_faulting_memory,
                        evex_info: EvexInfo::no_mask(),
                    })
                }
                // VXORPS / VXORPD — EVEX mask versions
                (0, 0x57) | (1, 0xEF) if evex.pp <= 1 => {
                    let rhs = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::VectorXor,
                        operands: vec![
                            Operand::Xmm(modrm.reg),
                            Operand::Xmm(evex.vvvv),
                            rhs.clone(),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: !matches!(rhs, Operand::Xmm(_)),
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // Arithmetic: VADDPS/PD (0F 58)
                (0, 0x58) | (1, 0x58) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vaddps
                        } else {
                            DecodedOpcode::Vaddpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // Arithmetic: VMULPS/PD (0F 59)
                (0, 0x59) | (1, 0x59) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vmulps
                        } else {
                            DecodedOpcode::Vmulpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // Arithmetic: VSUBPS/PD (0F 5C)
                (0, 0x5C) | (1, 0x5C) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vsubps
                        } else {
                            DecodedOpcode::Vsubpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // Arithmetic: VDIVPS/PD (0F 5E)
                (0, 0x5E) | (1, 0x5E) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vdivps
                        } else {
                            DecodedOpcode::Vdivpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // Arithmetic: VMINPS/PD (0F 5D)
                (0, 0x5D) | (1, 0x5D) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vminps
                        } else {
                            DecodedOpcode::Vminpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // Arithmetic: VMAXPS/PD (0F 5F)
                (0, 0x5F) | (1, 0x5F) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vmaxps
                        } else {
                            DecodedOpcode::Vmaxpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // Arithmetic: VSQRTPS/PD (0F 51)
                (0, 0x51) | (1, 0x51) => {
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vsqrtps
                        } else {
                            DecodedOpcode::Vsqrtpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VCMPPS/PD (0F C2) — requires immediate byte
                (0, 0xC2) | (1, 0xC2) => {
                    let imm = read_immediate(bytes, local, 1)? as u8;
                    local += 1;
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vcmpps
                        } else {
                            DecodedOpcode::Vcmppd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                            Operand::ImmediateU64(imm as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // Conversions
                (0, 0x5A) | (1, 0x5A) => {
                    // VCVTPS2PD / VCVTPD2PS
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vcvtps2pd
                        } else {
                            DecodedOpcode::Vcvtpd2ps
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (0, 0x5B) | (1, 0x5B) => {
                    // VCVTPS2DQ / VCVTDQ2PS
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vcvtps2dq
                        } else {
                            DecodedOpcode::Vcvtdq2ps
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(if evex.w { 1 } else { 0 }),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // Scalar conversions with F3/F2 prefixes
                (2, 0x2A) => {
                    // VCVTSI2SS: dst=ModRM.reg, src=ModRM.r/m (also uses vvvv but ignore for scalar)
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Register(Register::from_modrm(modrm.rm_register()))
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vcvtusi2ss,
                        operands: vec![Operand::Xmm(dst), src, Operand::ImmediateU64(4)],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (2, 0x2D) => {
                    // VCVTSS2SI
                    let dst = Register::from_modrm(modrm.reg);
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vcvtss2si,
                        operands: vec![Operand::Register(dst), src],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (2, 0x2C) => {
                    // VCVTTSS2SI
                    let dst = Register::from_modrm(modrm.reg);
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vcvttss2si,
                        operands: vec![Operand::Register(dst), src],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                _ => Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "unsupported EVEX 0F opcode pp={} opcode=0x{opcode:02x} w={}",
                        evex.pp, evex.w
                    ),
                )),
            }
        }
        2 => {
            // 0x0F3A opcode map — EVEX-coded instructions with immediate byte
            let width = evex.width_bytes();
            let (modrm, consumed) = parse_modrm(bytes, local, arch, None, address_size_32)?;
            local += consumed;
            let imm = read_immediate(bytes, local, 1)? as u8;
            local += 1;
            let _evex_info = EvexInfo::from_evex(&evex);
            match (evex.pp, opcode) {
                // VSHUFPS/PD (0F3A C6) - Wait, VSHUFPS is actually 0F C6 (not 0F3A!)
                // Actually let's handle properly:
                // VSHUFPS: EVEX.NDS.128.66.0F.W0 C6 /r ib  → map_select=0, pp=01
                // VSHUFPD: EVEX.NDS.128.66.0F.W1 C6 /r ib  → map_select=0, pp=01
                // These are handled above in map_select=0. For 0F3A:

                // VINSERTF128/256/512 (0F3A 18/19/1A/1B)
                (0, 0x18) | (0, 0x19) | (0, 0x1A) | (0, 0x1B) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let (op, elem_size) = match (opcode, evex.w, width) {
                        (0x18, false, _) => (DecodedOpcode::Vinsertf128, 16u8),
                        (0x18, true, _) => (DecodedOpcode::Vinserti128, 16u8),
                        (0x19, false, _) => (DecodedOpcode::Vinsertf256, 32u8),
                        (0x19, true, _) => (DecodedOpcode::Vinserti256, 32u8),
                        (0x1A, false, _) => (DecodedOpcode::Vinsertf32x4, 16u8),
                        (0x1A, true, _) => (DecodedOpcode::Vinserti32x4, 16u8),
                        (0x1B, false, 64) => (DecodedOpcode::Vinsertf64x4, 32u8),
                        (0x1B, true, 64) => (DecodedOpcode::Vinserti64x4, 32u8),
                        (0x1B, false, 32) => (DecodedOpcode::Vinsertf32x8, 32u8),
                        (0x1B, true, 32) => (DecodedOpcode::Vinserti32x8, 32u8),
                        _ => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!(
                                    "unsupported VINSERT opcode=0x{opcode:02x} w={} width={}",
                                    evex.w, width
                                ),
                            ));
                        }
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: op,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(imm as u64),
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(elem_size as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VEXTRACTF128/256/512 (0F3A 19/1B/1F)
                (0, 0x19) => {
                    let dst = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let src = modrm.reg;
                    let (op, elem_size) = if !evex.w {
                        (DecodedOpcode::Vextractf128, 16u8)
                    } else {
                        (DecodedOpcode::Vextracti128, 16u8)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: op,
                        operands: vec![
                            dst,
                            Operand::Xmm(src),
                            Operand::ImmediateU64(imm as u64),
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(elem_size as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                (0, 0x1B) => {
                    let dst = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let src = modrm.reg;
                    let (op, elem_size) = if !evex.w {
                        (DecodedOpcode::Vextractf256, 32u8)
                    } else {
                        (DecodedOpcode::Vextracti256, 32u8)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: op,
                        operands: vec![
                            dst,
                            Operand::Xmm(src),
                            Operand::ImmediateU64(imm as u64),
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(elem_size as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VEXTRACTF32X4 / VEXTRACTI32X4 / VEXTRACTF64X2 / VEXTRACTI64X2
                (0, 0x1A) | (0, 0x1C) | (0, 0x1D) | (0, 0x1E) | (0, 0x1F) => {
                    let dst = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let src = modrm.reg;
                    let (op, elem_size) = match (opcode, evex.w) {
                        (0x1A, false) => (DecodedOpcode::Vextractf32x4, 16u8),
                        (0x1A, true) => (DecodedOpcode::Vextracti32x4, 16u8),
                        (0x1C, false) => (DecodedOpcode::Vextractf64x2, 16u8),
                        (0x1C, true) => (DecodedOpcode::Vextracti64x2, 16u8),
                        (0x1D, false) => (DecodedOpcode::Vextractf32x8, 32u8),
                        (0x1D, true) => (DecodedOpcode::Vextracti32x8, 32u8),
                        (0x1E, false) => (DecodedOpcode::Vextractf64x4, 32u8),
                        (0x1E, true) => (DecodedOpcode::Vextracti64x4, 32u8),
                        (0x1F, _) => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "VEXTRACTF512 not in 0F3A",
                            ));
                        }
                        _ => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!("unsupported VEXTRACT opcode=0x{opcode:02x}"),
                            ));
                        }
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: op,
                        operands: vec![
                            dst,
                            Operand::Xmm(src),
                            Operand::ImmediateU64(imm as u64),
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(elem_size as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VBROADCASTF32X4/F64X2/F32X8/F64X4 (0F3A 5A/5B/5C/5D)
                (0, 0x5A) | (0, 0x5B) | (0, 0x5C) | (0, 0x5D) => {
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    let (op, elem_size) = match (opcode, evex.w) {
                        (0x5A, false) => (DecodedOpcode::Vbroadcastf32x4, 16u8),
                        (0x5A, true) => (DecodedOpcode::Vbroadcasti32x4, 16u8),
                        (0x5B, false) => (DecodedOpcode::Vbroadcastf64x2, 16u8),
                        (0x5B, true) => (DecodedOpcode::Vbroadcasti64x2, 16u8),
                        (0x5C, false) => (DecodedOpcode::Vbroadcastf32x8, 32u8),
                        (0x5C, true) => (DecodedOpcode::Vbroadcasti32x8, 32u8),
                        (0x5D, false) => (DecodedOpcode::Vbroadcastf64x4, 32u8),
                        (0x5D, true) => (DecodedOpcode::Vbroadcasti64x4, 32u8),
                        _ => unreachable!(),
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: op,
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(width as u64),
                            Operand::ImmediateU64(elem_size as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VBROADCASTM (0F3A 7C) — broadcast mask to vector
                (0, 0x7C) => {
                    let dst = modrm.reg;
                    let src = evex.vvvv; // mask register (k0-k7)
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: DecodedOpcode::Vbroadcastm,
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::ImmediateU64(src as u64),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: false,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VALIGND/Q (0F3A 03)
                (0, 0x03) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if !evex.w {
                            DecodedOpcode::ValignD
                        } else {
                            DecodedOpcode::ValignQ
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(imm as u64),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VPERMIL2PS/PD (0F3A 48/49) - note: actually these are VEX-only, but handle for completeness
                (0, 0x48) | (0, 0x49) => {
                    let dst = modrm.reg;
                    let src1 = evex.vvvv;
                    let src2 = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vpermil2ps
                        } else {
                            DecodedOpcode::Vpermil2pd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            Operand::Xmm(src1),
                            src2,
                            Operand::ImmediateU64(imm as u64),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                // VPERMILPS/PD (0F3A 0C/0D) — immediate forms
                (0, 0x0C) | (0, 0x0D) => {
                    let dst = modrm.reg;
                    let src = if modrm.mod_bits == 0b11 {
                        Operand::Xmm(modrm.rm)
                    } else {
                        modrm_operand(&modrm, arch, prefixes, address + (local - cursor) as u64)
                    };
                    Ok(DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes: prefixes.to_vec(),
                        rex: None,
                        opcode: if evex.pp == 0 {
                            DecodedOpcode::Vpermilps
                        } else {
                            DecodedOpcode::Vpermilpd
                        },
                        operands: vec![
                            Operand::Xmm(dst),
                            src,
                            Operand::ImmediateU64(imm as u64),
                            Operand::ImmediateU64(width as u64),
                        ],
                        precise_faulting_memory: modrm.mod_bits != 0b11,
                        evex_info: EvexInfo::from_evex(&evex),
                    })
                }
                _ => Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "unsupported EVEX 0F3A opcode pp={} opcode=0x{opcode:02x} w={} imm=0x{imm:02x}",
                        evex.pp, evex.w
                    ),
                )),
            }
        }
        _ => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported EVEX map_select {}", evex.map_select),
        )),
    }
}

/// Map a mask-register opcode to its bit-width: B→8, W→16, D→32, Q→64.
pub(crate) fn mask_op_size(opcode: &DecodedOpcode) -> u8 {
    match opcode {
        DecodedOpcode::KandB
        | DecodedOpcode::KorB
        | DecodedOpcode::KxorB
        | DecodedOpcode::KnotB
        | DecodedOpcode::KshiftlB
        | DecodedOpcode::KshiftrB
        | DecodedOpcode::KaddB
        | DecodedOpcode::KtestB
        | DecodedOpcode::Kunpckbw => 8,
        DecodedOpcode::KandW
        | DecodedOpcode::KorW
        | DecodedOpcode::KxorW
        | DecodedOpcode::KnotW
        | DecodedOpcode::KshiftlW
        | DecodedOpcode::KshiftrW
        | DecodedOpcode::KaddW
        | DecodedOpcode::KtestW
        | DecodedOpcode::Kunpckwd => 16,
        DecodedOpcode::KandD
        | DecodedOpcode::KorD
        | DecodedOpcode::KxorD
        | DecodedOpcode::KnotD
        | DecodedOpcode::KshiftlD
        | DecodedOpcode::KshiftrD
        | DecodedOpcode::KaddD
        | DecodedOpcode::KtestD
        | DecodedOpcode::Kunpckdq => 32,
        DecodedOpcode::KandQ
        | DecodedOpcode::KorQ
        | DecodedOpcode::KxorQ
        | DecodedOpcode::KnotQ
        | DecodedOpcode::KshiftlQ
        | DecodedOpcode::KshiftrQ
        | DecodedOpcode::KaddQ
        | DecodedOpcode::KtestQ => 64,
        _ => 8,
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedModrm {
    reg: u8,
    rm: u8,
    mod_bits: u8,
    sib: Option<ParsedSib>,
    displacement: i32,
    no_base: bool,
    rip_relative: bool,
}

impl ParsedModrm {
    fn rm_register(self) -> u8 {
        if self.mod_bits == 0b11 {
            self.rm
        } else {
            self.rm & 0x0f
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedSib {
    scale: u8,
    index: u8,
    base: u8,
    no_base: bool,
}

pub(crate) fn parse_modrm(
    bytes: &[u8],
    offset: usize,
    arch: GuestArch,
    rex: Option<RexPrefix>,
    address_size_32: bool,
) -> AppResult<(ParsedModrm, usize)> {
    let modrm = *bytes
        .get(offset)
        .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, "missing ModRM byte"))?;
    let mod_bits = modrm >> 6;
    let mut reg = (modrm >> 3) & 0x07;
    let mut rm = modrm & 0x07;
    if let Some(rex) = rex {
        if rex.r {
            reg |= 0x08;
        }
        if rex.b {
            rm |= 0x08;
        }
    }
    let mut consumed = 1usize;
    let mut displacement = 0_i32;
    let mut sib = None;
    let rip_relative =
        arch == GuestArch::X64 && !address_size_32 && mod_bits == 0 && (modrm & 0x07) == 0x05;
    let no_base = !rip_relative && mod_bits == 0 && (modrm & 0x07) == 0x05;
    if mod_bits != 0b11 && (modrm & 0x07) == 0x04 {
        let sib_byte = *bytes
            .get(offset + consumed)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, "missing SIB byte"))?;
        consumed += 1;
        let mut index = (sib_byte >> 3) & 0x07;
        let mut base = sib_byte & 0x07;
        if let Some(rex) = rex {
            if rex.x {
                index |= 0x08;
            }
            if rex.b {
                base |= 0x08;
            }
        }
        sib = Some(ParsedSib {
            scale: 1 << ((sib_byte >> 6) & 0x03),
            index,
            base,
            no_base: mod_bits == 0 && (sib_byte & 0x07) == 0x05,
        });
        if mod_bits == 0 && (sib_byte & 0x07) == 0x05 {
            displacement = read_i32(bytes, offset + consumed)?;
            consumed += 4;
        }
    }
    if rip_relative || (mod_bits == 0 && (modrm & 0x07) == 0x05) {
        displacement = read_i32(bytes, offset + consumed)?;
        consumed += 4;
    } else if mod_bits == 0b01 {
        displacement = *bytes
            .get(offset + consumed)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, "missing disp8"))?
            as i8 as i32;
        consumed += 1;
    } else if mod_bits == 0b10 {
        displacement = read_i32(bytes, offset + consumed)?;
        consumed += 4;
    }
    Ok((
        ParsedModrm {
            reg,
            rm,
            mod_bits,
            sib,
            displacement,
            no_base,
            rip_relative,
        },
        consumed,
    ))
}

pub(crate) fn modrm_operand(
    modrm: &ParsedModrm,
    _arch: GuestArch,
    prefixes: &[InstructionPrefix],
    rip_base: u64,
) -> Operand {
    if modrm.mod_bits == 0b11 {
        Operand::Register(Register::from_modrm(modrm.rm))
    } else {
        Operand::Memory(MemoryOperand {
            base: if modrm.rip_relative {
                None
            } else if let Some(sib) = modrm.sib {
                (!sib.no_base).then(|| Register::from_modrm(sib.base))
            } else if modrm.no_base {
                None
            } else {
                Some(Register::from_modrm(modrm.rm))
            },
            index: modrm
                .sib
                .and_then(|sib| (sib.index != 0x04).then(|| Register::from_modrm(sib.index))),
            scale: modrm.sib.map(|sib| sib.scale).unwrap_or(1),
            displacement: modrm.displacement,
            rip_relative: modrm.rip_relative,
            rip_base,
            segment: segment_from_prefixes(prefixes),
            address_size_32: prefixes.contains(&InstructionPrefix::AddressSize),
            absolute_address: None,
        })
    }
}

pub(crate) fn segment_from_prefixes(prefixes: &[InstructionPrefix]) -> Option<SegmentRegister> {
    prefixes.iter().rev().find_map(|prefix| match prefix {
        InstructionPrefix::FsSegment => Some(SegmentRegister::Fs),
        InstructionPrefix::GsSegment => Some(SegmentRegister::Gs),
        _ => None,
    })
}

pub(crate) fn x86_segment_selector_value(segment: u8) -> Option<u16> {
    match segment {
        0 => Some(0x23),
        1 => Some(0x1b),
        2 => Some(0x23),
        3 => Some(0x23),
        4 => Some(0x3b),
        5 => Some(0x00),
        _ => None,
    }
}

pub(crate) fn operand_width(
    rex: Option<RexPrefix>,
    prefixes: &[InstructionPrefix],
    arch: GuestArch,
) -> usize {
    if arch == GuestArch::X64 && rex.map(|value| value.w).unwrap_or(false) {
        8
    } else if prefixes.contains(&InstructionPrefix::OperandSize) {
        2
    } else {
        4
    }
}

pub(crate) fn compare_operand(operand: Operand) -> CompareOperand {
    match operand {
        Operand::Register(register) => CompareOperand::Register(register),
        Operand::Register8(register) => CompareOperand::Register8(register),
        Operand::Memory(memory) => CompareOperand::Memory(memory),
        Operand::ImmediateU64(value) => CompareOperand::ImmediateU64(value),
        other => unreachable!("unsupported compare operand {other:?}"),
    }
}

/// Map legacy prefixes to the SSE float element kind:
/// no prefix = PS (packed single), 66 = PD (packed double),
/// F3 = SS (scalar single), F2 = SD (scalar double).
pub(crate) fn sse_float_kind(prefixes: &[InstructionPrefix]) -> SseFloatKind {
    if prefixes.contains(&InstructionPrefix::Rep) {
        SseFloatKind::Ss
    } else if prefixes.contains(&InstructionPrefix::Repne) {
        SseFloatKind::Sd
    } else if prefixes.contains(&InstructionPrefix::OperandSize) {
        SseFloatKind::Pd
    } else {
        SseFloatKind::Ps
    }
}

pub(crate) fn compare_operand_to_operand(operand: CompareOperand) -> Operand {
    match operand {
        CompareOperand::Register(register) => Operand::Register(register),
        CompareOperand::Register8(register) => Operand::Register8(register),
        CompareOperand::Memory(memory) => Operand::Memory(memory),
        CompareOperand::ImmediateU64(value) => Operand::ImmediateU64(value),
    }
}

pub(crate) fn rex_register_low(rex: Option<RexPrefix>) -> u8 {
    rex.map(|value| if value.b { 8 } else { 0 }).unwrap_or(0)
}

pub(crate) fn read_immediate(bytes: &[u8], offset: usize, size: usize) -> AppResult<u64> {
    let slice = bytes
        .get(offset..offset + size)
        .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, "truncated immediate"))?;
    Ok(match size {
        1 => slice[0] as u64,
        2 => u16::from_le_bytes(slice.try_into().expect("immediate width")) as u64,
        4 => u32::from_le_bytes(slice.try_into().expect("immediate width")) as u64,
        8 => u64::from_le_bytes(slice.try_into().expect("immediate width")),
        _ => {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unsupported immediate width {size}"),
            ));
        }
    })
}

pub(crate) fn read_i32(bytes: &[u8], offset: usize) -> AppResult<i32> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, "truncated displacement"))?;
    Ok(i32::from_le_bytes(slice.try_into().expect("disp32 width")))
}

pub(crate) fn decode_condition(value: u64) -> AppResult<ConditionCode> {
    match value {
        0 => Ok(ConditionCode::Equal),
        1 => Ok(ConditionCode::NotEqual),
        12 => Ok(ConditionCode::Overflow),
        13 => Ok(ConditionCode::NotOverflow),
        2 => Ok(ConditionCode::Below),
        3 => Ok(ConditionCode::NotBelow),
        4 => Ok(ConditionCode::Above),
        5 => Ok(ConditionCode::NotAbove),
        6 => Ok(ConditionCode::Sign),
        7 => Ok(ConditionCode::NotSign),
        8 => Ok(ConditionCode::Less),
        9 => Ok(ConditionCode::GreaterEqual),
        10 => Ok(ConditionCode::LessEqual),
        11 => Ok(ConditionCode::Greater),
        14 => Ok(ConditionCode::Parity),
        15 => Ok(ConditionCode::NotParity),
        other => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported condition code {other}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Checked byte-slice extraction helpers
//
// SIMD / vector operations frequently extract 4- or 8-byte lanes from a
// `Vec<u8>` produced by `read_vector_bytes` / `read_vector_operand_bytes`.
// Direct slice indexing (`bytes[off..off+4].try_into().unwrap()`) panics on
// out-of-bounds.  These helpers return `AppResult` instead, propagating a
// descriptive error that includes the offset and slice length for diagnostics.
// ---------------------------------------------------------------------------

/// Extract exactly 4 bytes from `bytes` at `offset` in little-endian order.
pub(crate) fn checked_le_bytes_4(bytes: &[u8], offset: usize) -> AppResult<[u8; 4]> {
    bytes
        .get(offset..offset + 4)
        .map(|s| s.try_into().expect("4-byte slice"))
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "byte slice too short for 4-byte read at offset {offset} (len={})",
                    bytes.len()
                ),
            )
        })
}

/// Extract exactly 8 bytes from `bytes` at `offset` in little-endian order.
pub(crate) fn checked_le_bytes_8(bytes: &[u8], offset: usize) -> AppResult<[u8; 8]> {
    bytes
        .get(offset..offset + 8)
        .map(|s| s.try_into().expect("8-byte slice"))
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "byte slice too short for 8-byte read at offset {offset} (len={})",
                    bytes.len()
                ),
            )
        })
}

/// Read a `u32` from a byte slice at the given offset in little-endian order.
pub(crate) fn checked_u32_le(bytes: &[u8], offset: usize) -> AppResult<u32> {
    Ok(u32::from_le_bytes(checked_le_bytes_4(bytes, offset)?))
}

/// Read a `u64` from a byte slice at the given offset in little-endian order.
pub(crate) fn checked_u64_le(bytes: &[u8], offset: usize) -> AppResult<u64> {
    Ok(u64::from_le_bytes(checked_le_bytes_8(bytes, offset)?))
}

/// Read an `f32` from a byte slice at the given offset in little-endian order.
pub(crate) fn checked_f32_le(bytes: &[u8], offset: usize) -> AppResult<f32> {
    Ok(f32::from_le_bytes(checked_le_bytes_4(bytes, offset)?))
}

/// Read an `f64` from a byte slice at the given offset in little-endian order.
pub(crate) fn checked_f64_le(bytes: &[u8], offset: usize) -> AppResult<f64> {
    Ok(f64::from_le_bytes(checked_le_bytes_8(bytes, offset)?))
}
