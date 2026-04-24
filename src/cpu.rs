use crate::error::{AppError, AppResult};
use crate::ge::CpuProfile;
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
pub const EXCEPTION_INT_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
pub const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum GuestArch {
    X64,
    X86,
}

impl GuestArch {
    pub const fn pointer_bytes(self) -> usize {
        match self {
            Self::X64 => 8,
            Self::X86 => 4,
        }
    }

    pub const fn register_mask(self) -> u64 {
        match self {
            Self::X64 => u64::MAX,
            Self::X86 => u32::MAX as u64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuFeatureSet {
    pub baseline_x86_64: bool,
    pub sse2: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse41: bool,
    pub sse42: bool,
    pub popcnt: bool,
    pub lzcnt: bool,
    pub bmi1: bool,
    pub bmi2: bool,
    pub x87: bool,
}

impl CpuFeatureSet {
    pub fn for_arch(arch: GuestArch) -> Self {
        Self {
            baseline_x86_64: arch == GuestArch::X64,
            sse2: true,
            sse3: true,
            ssse3: true,
            sse41: true,
            sse42: true,
            popcnt: true,
            lzcnt: true,
            bmi1: true,
            bmi2: true,
            x87: true,
        }
    }

    pub fn apply_mask(&mut self, mask: &str) -> AppResult<()> {
        if mask.trim().is_empty() {
            return Ok(());
        }
        for assignment in mask.split(',').filter(|entry| !entry.trim().is_empty()) {
            let (key, value) = assignment.split_once('=').ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("invalid CPU feature override {assignment}"),
                )
            })?;
            let enabled = parse_bool(value.trim())?;
            self.set_feature(key.trim(), enabled)?;
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> String {
        self.enabled_features().join(",")
    }

    fn set_feature(&mut self, name: &str, enabled: bool) -> AppResult<()> {
        match normalize_feature_name(name).as_str() {
            "baseline_x86_64" | "x86_64" => self.baseline_x86_64 = enabled,
            "sse2" => self.sse2 = enabled,
            "sse3" => self.sse3 = enabled,
            "ssse3" => self.ssse3 = enabled,
            "sse41" | "sse4_1" => self.sse41 = enabled,
            "sse42" | "sse4_2" => self.sse42 = enabled,
            "popcnt" => self.popcnt = enabled,
            "lzcnt" | "abm" => self.lzcnt = enabled,
            "bmi1" => self.bmi1 = enabled,
            "bmi2" => self.bmi2 = enabled,
            "x87" => self.x87 = enabled,
            other => {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("unknown CPU feature {other}"),
                ))
            }
        }
        Ok(())
    }

    fn enabled_features(&self) -> Vec<&'static str> {
        [
            (self.baseline_x86_64, "baseline_x86_64"),
            (self.sse2, "sse2"),
            (self.sse3, "sse3"),
            (self.ssse3, "ssse3"),
            (self.sse41, "sse41"),
            (self.sse42, "sse42"),
            (self.popcnt, "popcnt"),
            (self.lzcnt, "lzcnt"),
            (self.bmi1, "bmi1"),
            (self.bmi2, "bmi2"),
            (self.x87, "x87"),
        ]
        .into_iter()
        .filter_map(|(enabled, name)| enabled.then_some(name))
        .collect()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuidLeaf {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuVirtualization {
    pub arch: GuestArch,
    pub features: CpuFeatureSet,
    pub dbt_flags: BTreeSet<String>,
}

impl CpuVirtualization {
    pub fn from_profile(arch: GuestArch, profile: Option<&CpuProfile>) -> AppResult<Self> {
        let mut features = CpuFeatureSet::for_arch(arch);
        let mut dbt_flags = BTreeSet::new();
        if let Some(profile) = profile {
            features.apply_mask(&profile.cpuid_mask)?;
            dbt_flags.extend(profile.dbt_flags.iter().map(|value| value.to_ascii_lowercase()));
        }
        if arch == GuestArch::X86 {
            features.baseline_x86_64 = false;
            features.sse2 = true;
        }
        Ok(Self {
            arch,
            features,
            dbt_flags,
        })
    }

    pub fn leaf(&self, leaf: u32, subleaf: u32) -> CpuidLeaf {
        match (leaf, subleaf) {
            (0, 0) => CpuidLeaf {
                eax: 7,
                ebx: 0x4361_7361,
                ecx: 0x3143_5055,
                edx: 0x2020_2020,
            },
            (1, 0) => {
                let mut ecx = 0_u32;
                let mut edx = 0_u32;
                if self.features.sse3 {
                    ecx |= 1 << 0;
                }
                if self.features.ssse3 {
                    ecx |= 1 << 9;
                }
                if self.features.sse41 {
                    ecx |= 1 << 19;
                }
                if self.features.sse42 {
                    ecx |= 1 << 20;
                }
                if self.features.popcnt {
                    ecx |= 1 << 23;
                }
                if self.features.x87 {
                    edx |= 1 << 0;
                }
                if self.features.sse2 {
                    edx |= 1 << 26;
                }
                CpuidLeaf {
                    eax: if self.arch == GuestArch::X64 { 0x0003_06A9 } else { 0x0001_06A9 },
                    ebx: 0,
                    ecx,
                    edx,
                }
            }
            (7, 0) => {
                let mut ebx = 0_u32;
                if self.features.bmi1 {
                    ebx |= 1 << 3;
                }
                if self.features.bmi2 {
                    ebx |= 1 << 8;
                }
                CpuidLeaf {
                    eax: 0,
                    ebx,
                    ecx: 0,
                    edx: 0,
                }
            }
            (0x8000_0000, 0) => CpuidLeaf {
                eax: 0x8000_0001,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
            (0x8000_0001, 0) => {
                let mut ecx = 0_u32;
                if self.features.lzcnt {
                    ecx |= 1 << 5;
                }
                CpuidLeaf {
                    eax: 0,
                    ebx: 0,
                    ecx,
                    edx: 0,
                }
            }
            _ => CpuidLeaf {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
        }
    }

    pub fn profile_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(match self.arch {
            GuestArch::X64 => b"x64".as_slice(),
            GuestArch::X86 => b"x86".as_slice(),
        });
        hasher.update(self.features.fingerprint());
        for flag in &self.dbt_flags {
            hasher.update(flag.as_bytes());
        }
        hex_bytes(&hasher.finalize())
    }
}

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
    fn index(self) -> usize {
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

    fn from_modrm(code: u8) -> Self {
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Flags {
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct XmmValue {
    pub low: u64,
    pub high: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum X87RoundingMode {
    Nearest,
    Down,
    Up,
    TowardZero,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct X87State {
    pub stack: Vec<f64>,
    pub rounding_mode: X87RoundingMode,
    pub divide_by_zero: bool,
    pub precision: bool,
}

impl Default for X87State {
    fn default() -> Self {
        Self {
            stack: Vec::new(),
            rounding_mode: X87RoundingMode::Nearest,
            divide_by_zero: false,
            precision: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CpuState {
    pub arch: GuestArch,
    pub gpr: [u64; 16],
    pub xmm: [XmmValue; 16],
    pub flags: Flags,
    pub x87: X87State,
    #[serde(default)]
    pub segment_bases: SegmentBases,
    pub rip: u64,
}

impl CpuState {
    pub fn new(arch: GuestArch) -> Self {
        Self {
            arch,
            gpr: [0; 16],
            xmm: [XmmValue { low: 0, high: 0 }; 16],
            flags: Flags {
                cf: false,
                pf: false,
                af: false,
                zf: false,
                sf: false,
                of: false,
            },
            x87: X87State::default(),
            segment_bases: SegmentBases::default(),
            rip: 0,
        }
    }

    pub fn get(&self, reg: Register) -> u64 {
        self.gpr[reg.index()] & self.arch.register_mask()
    }

    pub fn set(&mut self, reg: Register, value: u64) {
        self.gpr[reg.index()] = value & self.arch.register_mask();
    }

    pub fn get_byte(&self, reg: ByteRegister) -> u8 {
        (self.get(reg.full_register()) & 0xff) as u8
    }

    pub fn set_byte(&mut self, reg: ByteRegister, value: u8) {
        let full = reg.full_register();
        let next = (self.get(full) & !0xff) | value as u64;
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryImage {
    bytes: BTreeMap<u64, u8>,
}

impl MemoryImage {
    pub fn map_bytes(&mut self, address: u64, bytes: &[u8]) {
        for (offset, byte) in bytes.iter().enumerate() {
            self.bytes.insert(address + offset as u64, *byte);
        }
    }

    pub fn read_u8(&self, address: u64) -> AppResult<u8> {
        self.bytes.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unmapped guest memory at {address:#x}"),
            )
        })
    }

    pub fn map_u64(&mut self, address: u64, value: u64) {
        self.map_bytes(address, &value.to_le_bytes());
    }

    pub fn map_xmm(&mut self, address: u64, value: XmmValue) {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&value.low.to_le_bytes());
        bytes.extend_from_slice(&value.high.to_le_bytes());
        self.map_bytes(address, &bytes);
    }

    pub fn read_u64(&self, address: u64) -> AppResult<u64> {
        let mut bytes = [0_u8; 8];
        for (offset, slot) in bytes.iter_mut().enumerate() {
            *slot = *self.bytes.get(&(address + offset as u64)).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unmapped guest memory at {address:#x}"),
                )
            })?;
        }
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn read_xmm(&self, address: u64) -> AppResult<XmmValue> {
        let low = self.read_u64(address)?;
        let high = self.read_u64(address + 8)?;
        Ok(XmmValue { low, high })
    }

    pub fn write_u64(&mut self, address: u64, value: u64) {
        self.map_u64(address, value);
    }

    pub fn stable_hash(&self) -> String {
        let mut hasher = Sha256::new();
        for (address, byte) in &self.bytes {
            hasher.update(address.to_le_bytes());
            hasher.update([*byte]);
        }
        hex_bytes(&hasher.finalize())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InstructionPrefix {
    Lock,
    Rep,
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
    fn from_modrm(code: u8) -> Self {
        match code & 0x0f {
            0 => Self::Al,
            1 => Self::Cl,
            2 => Self::Dl,
            3 => Self::Bl,
            4 => Self::Spl,
            5 => Self::Bpl,
            6 => Self::Sil,
            7 => Self::Dil,
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

    fn full_register(self) -> Register {
        match self {
            Self::Al => Register::Rax,
            Self::Cl => Register::Rcx,
            Self::Dl => Register::Rdx,
            Self::Bl => Register::Rbx,
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
pub enum ConditionCode {
    Equal,
    NotEqual,
    Below,
    NotBelow,
    Above,
    NotAbove,
    Sign,
    NotSign,
    LessEqual,
    Greater,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RexPrefix {
    pub w: bool,
    pub r: bool,
    pub x: bool,
    pub b: bool,
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
    MovImm,
    MovReg,
    MovReg8,
    AddImm,
    AddReg,
    AdcImm,
    OrImm,
    SubImm,
    AndImm,
    AndReg8,
    BitTest,
    ShlImm,
    ShrImm,
    SarImm,
    ShlCl,
    ShrCl,
    SarCl,
    ImulImm,
    ImulReg,
    SubReg,
    SbbReg,
    Cmp,
    Test,
    Xchg,
    Movsxd,
    Movzx,
    XorImm,
    XorReg,
    OrReg,
    OrReg8,
    IncReg,
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
    PopReg,
    Ret,
    Popcnt,
    Lzcnt,
    Movsx,
    XmmMove,
    Pxor,
    Paddq,
    Fninit,
    LockCmpxchg,
    LockXadd,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompareOperand {
    Register(Register),
    Register8(ByteRegister),
    Memory(MemoryOperand),
    ImmediateU64(u64),
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IrInstruction {
    MovImm { dst: Register, value: u64 },
    MovReg { dst: Register, src: Register, width: usize },
    MovReg8 { dst: ByteRegister, src: ByteRegister },
    AddImm { dst: Register, value: u64, width: usize },
    AddOperand { dst: Register, src: CompareOperand, width: usize },
    AddMemory { address: MemoryOperand, src: Register, width: usize },
    AddImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    AdcImm { dst: Register, value: u64, width: usize },
    AdcImm8 { dst: ByteRegister, value: u8 },
    AdcImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    OrImm { dst: Register, value: u64, width: usize },
    OrImm8 { dst: ByteRegister, value: u8 },
    OrImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    SubImm { dst: Register, value: u64, width: usize },
    SubImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    AndImm { dst: Register, value: u64, width: usize },
    AndImmMemory {
        address: MemoryOperand,
        value: u64,
        width: usize,
    },
    ShlImm { dst: Register, count: u8, width: usize },
    ShrImm { dst: Register, count: u8, width: usize },
    SarImm { dst: Register, count: u8, width: usize },
    ShlCl { dst: Register, width: usize },
    ShrCl { dst: Register, width: usize },
    SarCl { dst: Register, width: usize },
    ImulImm {
        dst: Register,
        src: CompareOperand,
        imm: u64,
        width: usize,
    },
    ImulReg {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    SubOperand { dst: Register, src: CompareOperand, width: usize },
    SbbOperand { dst: Register, src: CompareOperand, width: usize },
    Compare {
        lhs: CompareOperand,
        rhs: CompareOperand,
        width: usize,
    },
    Test {
        lhs: CompareOperand,
        rhs: CompareOperand,
        width: usize,
    },
    ExchangeMemory {
        address: MemoryOperand,
        register: Register,
        width: usize,
    },
    SignExtendTo64 {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    SignExtend {
        dst: Register,
        src: CompareOperand,
        src_width: usize,
        dst_width: usize,
    },
    ZeroExtendTo64 {
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    XorImm { dst: Register, value: u64 },
    XorReg { dst: Register, src: Register },
    OrReg { dst: Register, src: CompareOperand, width: usize },
    OrMemory { address: MemoryOperand, src: Register, width: usize },
    AndReg8 { dst: ByteRegister, src: ByteRegister },
    BitTest { base: Register, bit: Register, width: usize },
    OrReg8 { dst: ByteRegister, src: ByteRegister },
    IncReg { dst: Register, width: usize },
    Cmov {
        condition: ConditionCode,
        dst: Register,
        src: CompareOperand,
        width: usize,
    },
    LoadMemory8 { dst: ByteRegister, address: MemoryOperand },
    LoadMemory { dst: Register, address: MemoryOperand, width: usize },
    StoreMemory8 { src: ByteRegister, address: MemoryOperand },
    StoreMemory { src: Register, address: MemoryOperand, width: usize },
    StoreImmediate { address: MemoryOperand, value: u64, width: usize },
    Call { target: u64, return_address: u64 },
    CallRegister { src: Register, return_address: u64 },
    CallMemory { address: MemoryOperand, return_address: u64 },
    JumpRegister { src: Register },
    JumpMemory { address: MemoryOperand },
    Setcc { condition: ConditionCode, dst: ByteRegister },
    JumpIf {
        condition: ConditionCode,
        target: u64,
        fallthrough: u64,
    },
    Jump { target: u64 },
    Nop,
    LoadEffectiveAddress { dst: Register, address: MemoryOperand, width: usize },
    PushReg { src: Register },
    PopReg { dst: Register },
    Return,
    Popcnt { dst: Register, src: Register },
    Lzcnt { dst: Register, src: Register },
    MoveXmm { dst: u8, src: u8 },
    LoadXmm { dst: u8, address: MemoryOperand },
    StoreXmm { src: u8, address: MemoryOperand },
    Pxor { dst: u8, src: u8 },
    Paddq { dst: u8, src: u8 },
    X87Init,
    HaddPs { dst: u8, src: u8 },
    Pshufb { dst: u8, mask: u8 },
    BlendD { dst: u8, src: u8, mask: u8 },
    Crc32 { dst: Register, src: Register },
    Andn { dst: Register, lhs: Register, rhs: Register },
    Pdep { dst: Register, src: Register, mask: Register },
    Pext { dst: Register, src: Register, mask: Register },
    LockCmpxchg {
        address: MemoryOperand,
        src: Register,
        width: usize,
    },
    LockXadd { address: u64, src: Register },
    Mfence,
    X87LoadConst { value: f64 },
    X87Add,
    X87Div,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionSummary {
    pub flags: Flags,
    pub memory_hash: String,
    pub ordering_log: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockCacheKey {
    pub source_hash: String,
    pub os_build: String,
    pub macwin_version: String,
    pub cpu_profile: String,
    pub arch: GuestArch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TranslationTier {
    Tier0,
    Tier1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JitPolicy {
    pub map_jit_preferred: bool,
    pub uses_wx_toggle: bool,
    pub rwx_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnwindInfo {
    pub begin: u64,
    pub end: u64,
    pub stack_allocation: u32,
    pub saved_registers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Arm64Block {
    pub instructions: Vec<String>,
    pub policy: JitPolicy,
    pub unwind: UnwindInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TranslatedBlock {
    pub key: BlockCacheKey,
    pub decoded: Vec<DecodedInstruction>,
    pub ir: Vec<IrInstruction>,
    pub arm64: Arm64Block,
    pub touched_pages: BTreeSet<u64>,
    pub tier: TranslationTier,
    pub persistent: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TranslationCache {
    pub blocks: BTreeMap<BlockCacheKey, TranslatedBlock>,
    pub unwind_registry: BTreeMap<BlockCacheKey, UnwindInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuEngineConfig {
    pub arch: GuestArch,
    pub os_build: String,
    pub macwin_version: String,
    pub virtualization: CpuVirtualization,
}

impl CpuEngineConfig {
    pub fn from_profile(
        arch: GuestArch,
        os_build: impl Into<String>,
        macwin_version: impl Into<String>,
        profile: Option<&CpuProfile>,
    ) -> AppResult<Self> {
        Ok(Self {
            arch,
            os_build: os_build.into(),
            macwin_version: macwin_version.into(),
            virtualization: CpuVirtualization::from_profile(arch, profile)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsException {
    pub code: u32,
    pub address: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HostSignal {
    Segv,
    Bus,
    Ill,
    FpeIntDivideByZero,
    Trap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExceptionDisposition {
    ContinueExecution,
    ContinueSearch,
    ExecuteHandler(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExceptionHandler {
    pub name: String,
    pub handles_code: Option<u32>,
    pub disposition: ExceptionDisposition,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExceptionDispatcher {
    veh: Vec<ExceptionHandler>,
    seh: Vec<ExceptionHandler>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DispatchTrace {
    pub visited: Vec<String>,
    pub result: ExceptionDisposition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CpuExecutionEngine {
    pub config: CpuEngineConfig,
    pub cache: TranslationCache,
    pub dispatcher: ExceptionDispatcher,
}

impl CpuExecutionEngine {
    pub fn new(config: CpuEngineConfig) -> Self {
        Self {
            config,
            cache: TranslationCache::default(),
            dispatcher: ExceptionDispatcher::default(),
        }
    }

    pub fn cpuid_leaf(&self, leaf: u32, subleaf: u32) -> CpuidLeaf {
        self.config.virtualization.leaf(leaf, subleaf)
    }

    pub fn decode_block(&self, bytes: &[u8], start_address: u64) -> AppResult<Vec<DecodedInstruction>> {
        decode_block(bytes, start_address, self.config.arch)
    }

    pub fn translate_block(&mut self, bytes: &[u8], start_address: u64) -> AppResult<TranslatedBlock> {
        self.cache.translate(bytes, start_address, &self.config)
    }

    pub fn promote_trace(&mut self, key: &BlockCacheKey) -> AppResult<()> {
        self.cache.promote(key)
    }

    pub fn invalidate_code_write(&mut self, address: u64, length: usize) -> Vec<BlockCacheKey> {
        self.cache.invalidate_code_write(address, length)
    }

    pub fn execute_ir(
        &self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        ir: &[IrInstruction],
    ) -> AppResult<ExecutionSummary> {
        execute_ir(state, memory, ir)
    }

    pub fn execute_ir_without_memory_hash(
        &self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        ir: &[IrInstruction],
    ) -> AppResult<ExecutionSummary> {
        execute_ir_with_hashing(state, memory, ir, false)
    }

    pub fn execute_ir_with_memory_hash(
        &self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        ir: &[IrInstruction],
    ) -> AppResult<ExecutionSummary> {
        execute_ir_with_hashing(state, memory, ir, true)
    }

    pub fn register_veh(&mut self, handler: ExceptionHandler) {
        self.dispatcher.veh.push(handler);
    }

    pub fn register_seh(&mut self, handler: ExceptionHandler) {
        self.dispatcher.seh.push(handler);
    }

    pub fn dispatch_exception(&self, exception: &WindowsException) -> DispatchTrace {
        self.dispatcher.dispatch(exception)
    }
}

impl TranslationCache {
    pub fn translate(
        &mut self,
        bytes: &[u8],
        start_address: u64,
        config: &CpuEngineConfig,
    ) -> AppResult<TranslatedBlock> {
        let key = build_cache_key(bytes, config);
        if let Some(existing) = self.blocks.get(&key) {
            return Ok(existing.clone());
        }
        let decoded = decode_block(bytes, start_address, config.arch)?;
        let ir = lower_to_ir(&decoded)?;
        let touched_pages = touched_pages(start_address, bytes.len());
        let unwind = UnwindInfo {
            begin: start_address,
            end: start_address + bytes.len() as u64,
            stack_allocation: 32,
            saved_registers: vec!["fp".to_string(), "lr".to_string()],
        };
        let block = TranslatedBlock {
            key: key.clone(),
            decoded,
            ir: ir.clone(),
            arm64: Arm64Block {
                instructions: lower_to_arm64(&ir),
                policy: JitPolicy {
                    map_jit_preferred: true,
                    uses_wx_toggle: true,
                    rwx_enabled: false,
                },
                unwind: unwind.clone(),
            },
            touched_pages,
            tier: TranslationTier::Tier0,
            persistent: false,
        };
        self.unwind_registry.insert(key.clone(), unwind);
        self.blocks.insert(key, block.clone());
        Ok(block)
    }

    pub fn promote(&mut self, key: &BlockCacheKey) -> AppResult<()> {
        let block = self.blocks.get_mut(key).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("missing translated block {}", key.source_hash),
            )
        })?;
        block.tier = TranslationTier::Tier1;
        block.persistent = true;
        Ok(())
    }

    pub fn invalidate_code_write(&mut self, address: u64, length: usize) -> Vec<BlockCacheKey> {
        let dirty_pages = touched_pages(address, length);
        let keys = self
            .blocks
            .iter()
            .filter(|(_, block)| !block.touched_pages.is_disjoint(&dirty_pages))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in &keys {
            self.blocks.remove(key);
            self.unwind_registry.remove(key);
        }
        keys
    }
}

impl ExceptionDispatcher {
    pub fn dispatch(&self, exception: &WindowsException) -> DispatchTrace {
        let mut visited = Vec::new();
        for handler in &self.veh {
            visited.push(format!("veh:{}", handler.name));
            if handler.handles_code.is_none() || handler.handles_code == Some(exception.code) {
                if handler.disposition != ExceptionDisposition::ContinueSearch {
                    return DispatchTrace {
                        visited,
                        result: handler.disposition.clone(),
                    };
                }
            }
        }
        for handler in self.seh.iter().rev() {
            visited.push(format!("seh:{}", handler.name));
            if handler.handles_code.is_none() || handler.handles_code == Some(exception.code) {
                if handler.disposition != ExceptionDisposition::ContinueSearch {
                    return DispatchTrace {
                        visited,
                        result: handler.disposition.clone(),
                    };
                }
            }
        }
        DispatchTrace {
            visited,
            result: ExceptionDisposition::ContinueSearch,
        }
    }
}

pub fn decode_block(bytes: &[u8], start_address: u64, arch: GuestArch) -> AppResult<Vec<DecodedInstruction>> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();
    while cursor < bytes.len() {
        let address = start_address + cursor as u64;
        let mut prefixes = Vec::new();
        let mut rex = None;
        let mut local = cursor;
        loop {
            let byte = *bytes.get(local).ok_or_else(|| {
                AppError::new(ReasonCode::RcUnimplInsn, "unexpected end of instruction stream")
            })?;
            match byte {
                0xF0 => prefixes.push(InstructionPrefix::Lock),
                0xF3 => prefixes.push(InstructionPrefix::Rep),
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
        let opcode = *bytes.get(local).ok_or_else(|| {
            AppError::new(ReasonCode::RcUnimplInsn, "missing instruction opcode")
        })?;
        local += 1;
        let address_size_32 = arch == GuestArch::X64 && prefixes.contains(&InstructionPrefix::AddressSize);
        let instruction = match opcode {
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
            },
            0x63 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                let src = compare_operand(modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64));
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
            },
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
            },
            0xB8..=0xBF => {
                let imm_size = if arch == GuestArch::X64 && rex.map(|value| value.w).unwrap_or(false) {
                    8
                } else {
                    4
                };
                let imm = read_immediate(bytes, local, imm_size)?;
                local += imm_size;
                let dst = Register::from_modrm(((opcode - 0xB8) & 0x07) | rex_register_low(rex));
                DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::MovImm,
                    operands: vec![Operand::Register(dst), Operand::ImmediateU64(imm)],
                    precise_faulting_memory: false,
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
                }
            }
            0x19 | 0x1B | 0x29 | 0x2B => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                let width = operand_width(rex, &prefixes, arch);
                let reg = Register::from_modrm(modrm.reg);
                let rm_operand = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                let (dst, src, precise_faulting_memory) = if opcode == 0x19 || opcode == 0x29 {
                    let Operand::Register(rm) = rm_operand else {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            if opcode == 0x19 {
                                "SBB register-to-memory form is not implemented"
                            } else {
                                "SUB register-to-memory form is not implemented"
                            },
                        ));
                    };
                    (rm, Operand::Register(reg), false)
                } else {
                    (reg, rm_operand.clone(), !matches!(rm_operand, Operand::Register(_)))
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
                    operands: vec![
                        Operand::Register(dst),
                        src,
                        Operand::ImmediateU64(width as u64),
                    ],
                    precise_faulting_memory,
                }
            }
            0x01 | 0x03 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                let width = operand_width(rex, &prefixes, arch);
                let reg = Register::from_modrm(modrm.reg);
                let rm_operand = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
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
                        other => panic!("unexpected rm operand for opcode 0x01: {other:?}"),
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
                }
            }
            0x35 => {
                let value = read_immediate(bytes, local, 4)?;
                local += 4;
                DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::XorImm,
                    operands: vec![Operand::Register(Register::Rax), Operand::ImmediateU64(value)],
                    precise_faulting_memory: false,
                }
            }
            0x08 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                if modrm.mod_bits != 0b11 {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        "opcode 0x08 currently requires register operands",
                    ));
                }
                DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::OrReg8,
                    operands: vec![
                        Operand::Register8(ByteRegister::from_modrm(modrm.rm_register())),
                        Operand::Register8(ByteRegister::from_modrm(modrm.reg)),
                    ],
                    precise_faulting_memory: false,
                }
            }
            0x20 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                if modrm.mod_bits != 0b11 {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        "opcode 0x20 currently requires register operands",
                    ));
                }
                DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::AndReg8,
                    operands: vec![
                        Operand::Register8(ByteRegister::from_modrm(modrm.rm_register())),
                        Operand::Register8(ByteRegister::from_modrm(modrm.reg)),
                    ],
                    precise_faulting_memory: false,
                }
            }
            0x09 | 0x0B => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                let width = operand_width(rex, &prefixes, arch);
                let reg = Register::from_modrm(modrm.reg);
                let rm_operand = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
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
                        other => panic!("unexpected rm operand for opcode 0x09: {other:?}"),
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
                }
            }
            0x31 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                if modrm.mod_bits != 0b11 {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        "XOR register/memory form currently requires register operands",
                    ));
                }
                DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::XorReg,
                    operands: vec![
                        Operand::Register(Register::from_modrm(modrm.rm_register())),
                        Operand::Register(Register::from_modrm(modrm.reg)),
                    ],
                    precise_faulting_memory: false,
                }
            }
            0x84 | 0x85 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                let width = if opcode == 0x84 { 1 } else { operand_width(rex, &prefixes, arch) };
                let reg = CompareOperand::Register(Register::from_modrm(modrm.reg));
                let rm = compare_operand(modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64));
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
                }
            }
            0x39 | 0x3B => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                let width = operand_width(rex, &prefixes, arch);
                let reg = CompareOperand::Register(Register::from_modrm(modrm.reg));
                let rm = compare_operand(modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64));
                let (lhs, rhs) = if opcode == 0x39 { (rm, reg) } else { (reg, rm) };
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
                    precise_faulting_memory: true,
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
                }
            }
            0x69 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                let width = operand_width(rex, &prefixes, arch);
                let imm = read_immediate(bytes, local, 4)?;
                local += 4;
                let src = compare_operand(modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64));
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
                let opcode_kind = match modrm.reg {
                    0 => DecodedOpcode::AddImm,
                    1 => DecodedOpcode::OrImm,
                    2 => DecodedOpcode::AdcImm,
                    4 => DecodedOpcode::AndImm,
                    5 => DecodedOpcode::SubImm,
                    7 => DecodedOpcode::Cmp,
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported opcode 0x83 group selector {other}"),
                        ))
                    }
                };
                if opcode_kind == DecodedOpcode::Cmp {
                    let lhs = compare_operand(modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64));
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
                    }
                } else {
                    let destination = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
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
                    }
                }
            }
            0xC1 | 0xD1 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                if modrm.mod_bits != 0b11 {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!("opcode {opcode:#x} currently requires register operands"),
                    ));
                }
                let imm = if opcode == 0xC1 {
                    let value = read_immediate(bytes, local, 1)?;
                    local += 1;
                    value
                } else {
                    1
                };
                let opcode_kind = match modrm.reg {
                    4 => DecodedOpcode::ShlImm,
                    5 => DecodedOpcode::ShrImm,
                    7 => DecodedOpcode::SarImm,
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported opcode {opcode:#x} group selector {other}"),
                        ))
                    }
                };
                let width = operand_width(rex, &prefixes, arch);
                DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: opcode_kind,
                    operands: vec![
                        Operand::Register(Register::from_modrm(modrm.rm_register())),
                        Operand::ImmediateU64(imm),
                        Operand::ImmediateU64(width as u64),
                    ],
                    precise_faulting_memory: false,
                }
            }
            0xD3 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                if modrm.mod_bits != 0b11 {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        "opcode 0xd3 currently requires register operands",
                    ));
                }
                let opcode_kind = match modrm.reg {
                    4 => DecodedOpcode::ShlCl,
                    5 => DecodedOpcode::ShrCl,
                    7 => DecodedOpcode::SarCl,
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported opcode 0xd3 group selector {other}"),
                        ))
                    }
                };
                let width = operand_width(rex, &prefixes, arch);
                DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: opcode_kind,
                    operands: vec![
                        Operand::Register(Register::from_modrm(modrm.rm_register())),
                        Operand::ImmediateU64(width as u64),
                    ],
                    precise_faulting_memory: false,
                }
            }
            0xF6 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                if modrm.reg != 0 {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!("unsupported opcode 0xf6 group selector {}", modrm.reg),
                    ));
                }
                let imm = read_immediate(bytes, local, 1)?;
                local += 1;
                let lhs = compare_operand(modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64));
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
                }
            }
            0xF7 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                if modrm.reg != 0 {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!("unsupported opcode 0xf7 group selector {}", modrm.reg),
                    ));
                }
                let width = operand_width(rex, &prefixes, arch);
                let imm = read_immediate(bytes, local, if width == 8 { 4 } else { width })?;
                local += if width == 8 { 4 } else { width };
                let lhs = compare_operand(modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64));
                DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::Test,
                    operands: vec![
                        compare_operand_to_operand(lhs),
                        Operand::ImmediateU64(if width == 8 { sign_extend(imm, 4) } else { imm }),
                        Operand::ImmediateU64(width as u64),
                    ],
                    precise_faulting_memory: modrm.mod_bits != 0b11,
                }
            }
            0x80 | 0x81 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                let width = if opcode == 0x80 { 1 } else { operand_width(rex, &prefixes, arch) };
                let immediate_width = if opcode == 0x80 { 1 } else { 4 };
                let imm = read_immediate(bytes, local, immediate_width)?;
                local += immediate_width;
                let imm_value = if opcode == 0x81 && width == 8 {
                    sign_extend(imm, 4)
                } else {
                    imm
                };
                match modrm.reg {
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
                    },
                    0 => {
                        let destination = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
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
                        }
                    },
                    1 if opcode == 0x80 && modrm.mod_bits == 0b11 => DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::OrImm,
                        operands: vec![
                            Operand::Register8(ByteRegister::from_modrm(modrm.rm_register())),
                            Operand::ImmediateU64(imm),
                        ],
                        precise_faulting_memory: false,
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
                    },
                    1 => {
                        let destination = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
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
                        }
                    },
                    2 if opcode == 0x80 && modrm.mod_bits == 0b11 => DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::AdcImm,
                        operands: vec![
                            Operand::Register8(ByteRegister::from_modrm(modrm.rm_register())),
                            Operand::ImmediateU64(imm),
                        ],
                        precise_faulting_memory: false,
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
                    },
                    2 => {
                        let destination = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
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
                        }
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
                    },
                    4 => {
                        let destination = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
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
                        }
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
                    },
                    5 => {
                        let destination = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
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
                        }
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
                        }
                    },
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported opcode {opcode:#x} group selector {other}"),
                        ))
                    }
                }
            }
            0x87 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                if modrm.mod_bits == 0b11 {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        "XCHG register/register form is not implemented",
                    ));
                }
                let width = operand_width(rex, &prefixes, arch);
                let Operand::Memory(address_operand) = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64) else {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        "XCHG currently requires a memory operand",
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
                        Operand::Register(Register::from_modrm(modrm.reg)),
                        Operand::ImmediateU64(width as u64),
                    ],
                    precise_faulting_memory: true,
                }
            }
            0x88 | 0x8A | 0x8B | 0x89 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                let rm_operand = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                let (opcode_kind, operands, precise_faulting_memory) = match opcode {
                    0x88 => {
                        let reg = ByteRegister::from_modrm(modrm.reg);
                        match rm_operand {
                            Operand::Register(_) => (
                                DecodedOpcode::MovReg8,
                                vec![
                                    Operand::Register8(ByteRegister::from_modrm(modrm.rm_register())),
                                    Operand::Register8(reg),
                                    Operand::ImmediateU64(1),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                DecodedOpcode::MovStore8,
                                vec![Operand::Memory(address_operand), Operand::Register8(reg), Operand::ImmediateU64(1)],
                                true,
                            ),
                            other => panic!("unexpected rm operand for opcode 0x88: {other:?}"),
                        }
                    }
                    0x8A => {
                        let reg = ByteRegister::from_modrm(modrm.reg);
                        match rm_operand {
                            Operand::Register(_) => (
                                DecodedOpcode::MovReg8,
                                vec![
                                    Operand::Register8(reg),
                                    Operand::Register8(ByteRegister::from_modrm(modrm.rm_register())),
                                    Operand::ImmediateU64(1),
                                ],
                                false,
                            ),
                            Operand::Memory(address_operand) => (
                                DecodedOpcode::MovLoad8,
                                vec![Operand::Register8(reg), Operand::Memory(address_operand), Operand::ImmediateU64(1)],
                                true,
                            ),
                            other => panic!("unexpected rm operand for opcode 0x8a: {other:?}"),
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
                                vec![Operand::Register(reg), other, Operand::ImmediateU64(width as u64)],
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
                                vec![other, Operand::Register(reg), Operand::ImmediateU64(width as u64)],
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
                }
            }
            0xC6 | 0xC7 => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                if modrm.reg != 0 {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!("unsupported opcode {opcode:#x} group selector {}", modrm.reg),
                    ));
                }
                let width = if opcode == 0xC6 { 1 } else { operand_width(rex, &prefixes, arch) };
                let immediate_width = if opcode == 0xC6 {
                    1
                } else if width == 2 {
                    2
                } else {
                    4
                };
                let imm = read_immediate(bytes, local, immediate_width)?;
                local += immediate_width;
                let Operand::Memory(address_operand) = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64) else {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!("opcode {opcode:#x} currently requires a memory destination"),
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
                }
            }
            0x8D => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                let Operand::Memory(address_operand) = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64) else {
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
                }
            }
            0xC3 => DecodedInstruction {
                address,
                size: local - cursor,
                prefixes,
                rex,
                opcode: DecodedOpcode::Ret,
                operands: Vec::new(),
                precise_faulting_memory: false,
            },
            0xDB => {
                let secondary = *bytes.get(local).ok_or_else(|| {
                    AppError::new(ReasonCode::RcUnimplInsn, "missing secondary opcode for 0xdb")
                })?;
                local += 1;
                match secondary {
                    0xE3 => DecodedInstruction {
                        address,
                        size: local - cursor,
                        prefixes,
                        rex,
                        opcode: DecodedOpcode::Fninit,
                        operands: Vec::new(),
                        precise_faulting_memory: false,
                    },
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported opcode 0xdb secondary {other:#x}"),
                        ))
                    }
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
                    operands: vec![Operand::ImmediateU64(target), Operand::ImmediateU64(return_address)],
                    precise_faulting_memory: false,
                }
            }
            0xE9 => {
                let displacement = read_i32(bytes, local)?;
                local += 4;
                let target = ((address + (local - cursor) as u64) as i128 + displacement as i128) as u64;
                DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::JmpRel,
                    operands: vec![Operand::ImmediateU64(target)],
                    precise_faulting_memory: false,
                }
            }
            0xEB => {
                let displacement = *bytes.get(local).ok_or_else(|| {
                    AppError::new(ReasonCode::RcUnimplInsn, "truncated rel8 for opcode 0xeb")
                })? as i8 as i64;
                local += 1;
                let target = ((address + (local - cursor) as u64) as i128 + displacement as i128) as u64;
                DecodedInstruction {
                    address,
                    size: local - cursor,
                    prefixes,
                    rex,
                    opcode: DecodedOpcode::JmpRel,
                    operands: vec![Operand::ImmediateU64(target)],
                    precise_faulting_memory: false,
                }
            }
            0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7E | 0x7F => {
                let displacement = *bytes.get(local).ok_or_else(|| {
                    AppError::new(ReasonCode::RcUnimplInsn, "truncated rel8 for conditional jump")
                })? as i8 as i64;
                local += 1;
                let fallthrough = address + (local - cursor) as u64;
                let target = (fallthrough as i128 + displacement as i128) as u64;
                let condition = match opcode {
                    0x72 => 2,
                    0x73 => 3,
                    0x77 => 4,
                    0x76 => 5,
                    0x78 => 6,
                    0x79 => 7,
                    0x7E => 8,
                    0x7F => 9,
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
                }
            }
            0x0F => {
                let next = *bytes.get(local).ok_or_else(|| {
                    AppError::new(ReasonCode::RcUnimplInsn, "missing secondary opcode")
                })?;
                local += 1;
                match next {
                    0x42 | 0x43 | 0x44 | 0x45 => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        let width = operand_width(rex, &prefixes, arch);
                        let source = compare_operand_to_operand(compare_operand(modrm_operand(
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
                                    0x42 => 2,
                                    0x43 => 3,
                                    0x44 => 0,
                                    0x45 => 1,
                                    _ => unreachable!("covered cmov opcode"),
                                }),
                                Operand::Register(Register::from_modrm(modrm.reg)),
                                source,
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: modrm.mod_bits != 0b11,
                        }
                    }
                    0x82 | 0x83 | 0x84 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8E | 0x8F => {
                        let displacement = read_i32(bytes, local)?;
                        local += 4;
                        let fallthrough = address + (local - cursor) as u64;
                        let target = (fallthrough as i128 + displacement as i128) as u64;
                        let condition = match next {
                            0x82 => 2,
                            0x83 => 3,
                            0x87 => 4,
                            0x86 => 5,
                            0x88 => 6,
                            0x89 => 7,
                            0x8E => 8,
                            0x8F => 9,
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
                        }
                    }
                    0xB6 | 0xB7 => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        let src = compare_operand(modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64));
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
                        }
                    }
                    0xBE | 0xBF => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        let src = compare_operand(modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64));
                        let dst_width = if rex.map(|value| value.w).unwrap_or(false) { 8 } else { 4 };
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
                        }
                    }
                    0xB8 => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
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
                        }
                    }
                    0xBD => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
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
                        }
                    }
                    0x92 | 0x93 | 0x94 | 0x95 | 0x96 | 0x97 | 0x98 | 0x99 | 0x9E | 0x9F => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        if modrm.mod_bits != 0b11 {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "SETcc currently requires register operands",
                            ));
                        }
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Setcc,
                            operands: vec![
                                Operand::ImmediateU64(match next {
                                    0x92 => 2,
                                    0x93 => 3,
                                    0x97 => 4,
                                    0x96 => 5,
                                    0x98 => 6,
                                    0x99 => 7,
                                    0x9E => 8,
                                    0x9F => 9,
                                    0x94 => 0,
                                    0x95 => 1,
                                    _ => unreachable!("covered setcc opcode"),
                                }),
                                Operand::Register8(ByteRegister::from_modrm(modrm.rm_register())),
                            ],
                            precise_faulting_memory: false,
                        }
                    }
                    0x1F => {
                        let (_modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Nop,
                            operands: Vec::new(),
                            precise_faulting_memory: false,
                        }
                    }
                    0x10 | 0x11 | 0x28 | 0x29 | 0x6F | 0x7F => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        let source = if next == 0x10 || next == 0x28 || next == 0x6F {
                            if modrm.mod_bits == 0b11 {
                                Operand::Xmm(modrm.rm)
                            } else {
                                modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                            }
                        } else {
                            Operand::Xmm(modrm.reg)
                        };
                        let destination = if next == 0x10 || next == 0x28 || next == 0x6F {
                            Operand::Xmm(modrm.reg)
                        } else if modrm.mod_bits == 0b11 {
                            Operand::Xmm(modrm.rm)
                        } else {
                            modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
                        };
                        let precise_faulting_memory = !matches!(source, Operand::Xmm(_)) || !matches!(destination, Operand::Xmm(_));
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::XmmMove,
                            operands: vec![destination, source],
                            precise_faulting_memory,
                        }
                    }
                    0xEF => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Pxor,
                            operands: vec![Operand::Xmm(modrm.reg), Operand::Xmm(modrm.rm)],
                            precise_faulting_memory: false,
                        }
                    }
                    0x57 => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        if modrm.mod_bits != 0b11 {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "XORPS currently requires register operands",
                            ));
                        }
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Pxor,
                            operands: vec![Operand::Xmm(modrm.reg), Operand::Xmm(modrm.rm)],
                            precise_faulting_memory: false,
                        }
                    }
                    0xAF => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        let source = if modrm.mod_bits == 0b11 {
                            Operand::Register(Register::from_modrm(modrm.rm_register()))
                        } else {
                            modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64)
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
                        }
                    }
                    0xB1 => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        let Operand::Memory(address_operand) = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64) else {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "CMPXCHG currently requires a memory destination",
                            ));
                        };
                        let width = operand_width(rex, &prefixes, arch);
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::LockCmpxchg,
                            operands: vec![
                                Operand::Memory(address_operand),
                                Operand::Register(Register::from_modrm(modrm.reg)),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: true,
                        }
                    }
                    0xD4 => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::Paddq,
                            operands: vec![Operand::Xmm(modrm.reg), Operand::Xmm(modrm.rm)],
                            precise_faulting_memory: false,
                        }
                    }
                    0xC1 => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                        local += consumed;
                        let memory = modrm_operand(&modrm, arch, &prefixes, address + (local - cursor) as u64);
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::LockXadd,
                            operands: vec![memory, Operand::Register(Register::from_modrm(modrm.reg))],
                            precise_faulting_memory: true,
                        }
                    }
                    0xA3 => {
                        let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
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
                        }
                    }
                    _ => {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported secondary opcode 0x{next:02x}"),
                        ))
                    }
                }
            }
            0xFF => {
                let (modrm, consumed) = parse_modrm(bytes, local, arch, rex, address_size_32)?;
                local += consumed;
                match modrm.reg {
                    0 if modrm.mod_bits == 0b11 => {
                        let width = operand_width(rex, &prefixes, arch);
                        DecodedInstruction {
                            address,
                            size: local - cursor,
                            prefixes,
                            rex,
                            opcode: DecodedOpcode::IncReg,
                            operands: vec![
                                Operand::Register(Register::from_modrm(modrm.rm_register())),
                                Operand::ImmediateU64(width as u64),
                            ],
                            precise_faulting_memory: false,
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
                                    Operand::Register(Register::from_modrm(modrm.rm_register())),
                                    Operand::ImmediateU64(return_address),
                                ],
                                precise_faulting_memory: false,
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
                            }
                        } else {
                            DecodedInstruction {
                                address,
                                size: local - cursor,
                                prefixes,
                                rex,
                                opcode: DecodedOpcode::JmpRegister,
                                operands: vec![Operand::Register(Register::from_modrm(modrm.rm_register()))],
                                precise_faulting_memory: false,
                            }
                        }
                    }
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported opcode 0xff group selector {other}"),
                        ))
                    }
                }
            }
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unsupported opcode 0x{opcode:02x}"),
                ))
            }
        };
        cursor = local;
        decoded.push(instruction);
    }
    Ok(decoded)
}

pub fn lower_to_ir(decoded: &[DecodedInstruction]) -> AppResult<Vec<IrInstruction>> {
    let mut ir = Vec::new();
    for instruction in decoded {
        match instruction.opcode {
            DecodedOpcode::MovImm => {
                if let [Operand::Register(dst), Operand::ImmediateU64(value)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::MovImm {
                        dst: *dst,
                        value: *value,
                    });
                }
            }
            DecodedOpcode::MovReg => {
                if let [Operand::Register(dst), Operand::Register(src), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::MovReg {
                        dst: *dst,
                        src: *src,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::MovReg8 => {
                if let [Operand::Register8(dst), Operand::Register8(src), ..] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::MovReg8 { dst: *dst, src: *src });
                }
            }
            DecodedOpcode::AddImm => {
                match instruction.operands.as_slice() {
                    [Operand::Register(dst), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::AddImm {
                            dst: *dst,
                            value: *value,
                            width: *width as usize,
                        });
                    }
                    [Operand::Memory(address), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::AddImmMemory {
                            address: *address,
                            value: *value,
                            width: *width as usize,
                        });
                    }
                    _ => {}
                }
            }
            DecodedOpcode::AdcImm => {
                match instruction.operands.as_slice() {
                    [Operand::Register(dst), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::AdcImm {
                            dst: *dst,
                            value: *value,
                            width: *width as usize,
                        });
                    }
                    [Operand::Register8(dst), Operand::ImmediateU64(value)] => {
                        ir.push(IrInstruction::AdcImm8 {
                            dst: *dst,
                            value: *value as u8,
                        });
                    }
                    [Operand::Memory(address), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::AdcImmMemory {
                            address: *address,
                            value: *value,
                            width: *width as usize,
                        });
                    }
                    _ => {}
                }
            }
            DecodedOpcode::OrImm => {
                match instruction.operands.as_slice() {
                    [Operand::Register(dst), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::OrImm {
                            dst: *dst,
                            value: *value,
                            width: *width as usize,
                        });
                    }
                    [Operand::Register8(dst), Operand::ImmediateU64(value)] => {
                        ir.push(IrInstruction::OrImm8 {
                            dst: *dst,
                            value: *value as u8,
                        });
                    }
                    [Operand::Memory(address), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::OrImmMemory {
                            address: *address,
                            value: *value,
                            width: *width as usize,
                        });
                    }
                    _ => {}
                }
            }
            DecodedOpcode::AddReg => {
                match instruction.operands.as_slice() {
                    [Operand::Register(dst), src, Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::AddOperand {
                            dst: *dst,
                            src: compare_operand(src.clone()),
                            width: *width as usize,
                        });
                    }
                    [Operand::Memory(address), Operand::Register(src), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::AddMemory {
                            address: *address,
                            src: *src,
                            width: *width as usize,
                        });
                    }
                    _ => {}
                }
            }
            DecodedOpcode::SubImm => {
                match instruction.operands.as_slice() {
                    [Operand::Register(dst), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::SubImm {
                            dst: *dst,
                            value: *value,
                            width: *width as usize,
                        });
                    }
                    [Operand::Memory(address), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::SubImmMemory {
                            address: *address,
                            value: *value,
                            width: *width as usize,
                        });
                    }
                    _ => {}
                }
            }
            DecodedOpcode::AndImm => {
                match instruction.operands.as_slice() {
                    [Operand::Register(dst), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::AndImm {
                            dst: *dst,
                            value: *value,
                            width: *width as usize,
                        });
                    }
                    [Operand::Memory(address), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::AndImmMemory {
                            address: *address,
                            value: *value,
                            width: *width as usize,
                        });
                    }
                    _ => {}
                }
            }
            DecodedOpcode::AndReg8 => {
                if let [Operand::Register8(dst), Operand::Register8(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::AndReg8 { dst: *dst, src: *src });
                }
            }
            DecodedOpcode::BitTest => {
                if let [Operand::Register(base), Operand::Register(bit), Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::BitTest {
                        base: *base,
                        bit: *bit,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ShlImm => {
                if let [Operand::Register(dst), Operand::ImmediateU64(count), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::ShlImm {
                        dst: *dst,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ShrImm => {
                if let [Operand::Register(dst), Operand::ImmediateU64(count), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::ShrImm {
                        dst: *dst,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::SarImm => {
                if let [Operand::Register(dst), Operand::ImmediateU64(count), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::SarImm {
                        dst: *dst,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ShlCl => {
                if let [Operand::Register(dst), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::ShlCl {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ShrCl => {
                if let [Operand::Register(dst), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::ShrCl {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::SarCl => {
                if let [Operand::Register(dst), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::SarCl {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ImulImm => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(imm), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::ImulImm {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        imm: *imm,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ImulReg => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::ImulReg {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::SubReg => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::SubOperand {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::SbbReg => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::SbbOperand {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Cmp => {
                if let [lhs, rhs, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Compare {
                        lhs: compare_operand(lhs.clone()),
                        rhs: compare_operand(rhs.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Test => {
                if let [lhs, rhs, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Test {
                        lhs: compare_operand(lhs.clone()),
                        rhs: compare_operand(rhs.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Xchg => {
                if let [Operand::Memory(address), Operand::Register(register), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::ExchangeMemory {
                        address: *address,
                        register: *register,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Movsxd => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::SignExtendTo64 {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Movsx => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(src_width), Operand::ImmediateU64(dst_width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::SignExtend {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        src_width: *src_width as usize,
                        dst_width: *dst_width as usize,
                    });
                }
            }
            DecodedOpcode::Movzx => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::ZeroExtendTo64 {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::XorImm => {
                if let [Operand::Register(dst), Operand::ImmediateU64(value)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::XorImm {
                        dst: *dst,
                        value: *value,
                    });
                }
            }
            DecodedOpcode::XorReg => {
                if let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::XorReg {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::OrReg => {
                match instruction.operands.as_slice() {
                    [Operand::Register(dst), src, Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::OrReg {
                            dst: *dst,
                            src: compare_operand(src.clone()),
                            width: *width as usize,
                        });
                    }
                    [Operand::Memory(address), Operand::Register(src), Operand::ImmediateU64(width)] => {
                        ir.push(IrInstruction::OrMemory {
                            address: *address,
                            src: *src,
                            width: *width as usize,
                        });
                    }
                    _ => {}
                }
            }
            DecodedOpcode::OrReg8 => {
                if let [Operand::Register8(dst), Operand::Register8(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::OrReg8 { dst: *dst, src: *src });
                }
            }
            DecodedOpcode::IncReg => {
                if let [Operand::Register(dst), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::IncReg {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Cmovcc => {
                if let [Operand::ImmediateU64(condition), Operand::Register(dst), src, Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Cmov {
                        condition: decode_condition(*condition)?,
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::MovLoad => {
                if let [Operand::Register(dst), Operand::Memory(address), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::LoadMemory {
                        dst: *dst,
                        address: *address,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::MovLoad8 => {
                if let [Operand::Register8(dst), Operand::Memory(address), Operand::ImmediateU64(_width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::LoadMemory8 {
                        dst: *dst,
                        address: *address,
                    });
                }
            }
            DecodedOpcode::MovStore => {
                if let [Operand::Memory(address), Operand::Register(src), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::StoreMemory {
                        src: *src,
                        address: *address,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::MovStore8 => {
                if let [Operand::Memory(address), Operand::Register8(src), Operand::ImmediateU64(_width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::StoreMemory8 {
                        src: *src,
                        address: *address,
                    });
                }
            }
            DecodedOpcode::MovStoreImm => {
                if let [Operand::Memory(address), Operand::ImmediateU64(value), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::StoreImmediate {
                        address: *address,
                        value: *value,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Nop => ir.push(IrInstruction::Nop),
            DecodedOpcode::CallRel => {
                if let [Operand::ImmediateU64(target), Operand::ImmediateU64(return_address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Call {
                        target: *target,
                        return_address: *return_address,
                    });
                }
            }
            DecodedOpcode::CallRegister => {
                if let [Operand::Register(src), Operand::ImmediateU64(return_address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::CallRegister {
                        src: *src,
                        return_address: *return_address,
                    });
                }
            }
            DecodedOpcode::CallMemory => {
                if let [Operand::Memory(address), Operand::ImmediateU64(return_address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::CallMemory {
                        address: *address,
                        return_address: *return_address,
                    });
                }
            }
            DecodedOpcode::JmpRegister => {
                if let [Operand::Register(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::JumpRegister { src: *src });
                }
            }
            DecodedOpcode::JmpMemory => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::JumpMemory { address: *address });
                }
            }
            DecodedOpcode::Setcc => {
                if let [Operand::ImmediateU64(condition), Operand::Register8(dst)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Setcc {
                        condition: decode_condition(*condition)?,
                        dst: *dst,
                    });
                }
            }
            DecodedOpcode::Jcc => {
                if let [Operand::ImmediateU64(condition), Operand::ImmediateU64(target), Operand::ImmediateU64(fallthrough)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::JumpIf {
                        condition: decode_condition(*condition)?,
                        target: *target,
                        fallthrough: *fallthrough,
                    });
                }
            }
            DecodedOpcode::JmpRel => {
                if let [Operand::ImmediateU64(target)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Jump { target: *target });
                }
            }
            DecodedOpcode::Lea => {
                if let [Operand::Register(dst), Operand::Memory(address), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::LoadEffectiveAddress {
                        dst: *dst,
                        address: *address,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::PushReg => {
                if let [Operand::Register(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::PushReg { src: *src });
                }
            }
            DecodedOpcode::PopReg => {
                if let [Operand::Register(dst)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::PopReg { dst: *dst });
                }
            }
            DecodedOpcode::Ret => ir.push(IrInstruction::Return),
            DecodedOpcode::Popcnt => {
                if let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Popcnt {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Lzcnt => {
                if let [Operand::Register(dst), Operand::Register(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Lzcnt {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::XmmMove => match instruction.operands.as_slice() {
                [Operand::Xmm(dst), Operand::Xmm(src)] => {
                    ir.push(IrInstruction::MoveXmm { dst: *dst, src: *src });
                }
                [Operand::Xmm(dst), Operand::Memory(address)] => {
                    ir.push(IrInstruction::LoadXmm {
                        dst: *dst,
                        address: *address,
                    });
                }
                [Operand::Memory(address), Operand::Xmm(src)] => {
                    ir.push(IrInstruction::StoreXmm {
                        src: *src,
                        address: *address,
                    });
                }
                _ => {}
            },
            DecodedOpcode::Pxor => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Pxor { dst: *dst, src: *src });
                }
            }
            DecodedOpcode::Paddq => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Paddq { dst: *dst, src: *src });
                }
            }
            DecodedOpcode::Fninit => ir.push(IrInstruction::X87Init),
            DecodedOpcode::LockCmpxchg => {
                if let [Operand::Memory(address), Operand::Register(src), Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::LockCmpxchg {
                        address: *address,
                        src: *src,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::LockXadd => {
                if let [Operand::Memory(address), Operand::Register(src)] = instruction.operands.as_slice() {
                    if address.base.is_none() && address.index.is_none() {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            "LOCK XADD requires a concrete base address",
                        ));
                    }
                    let absolute = address.displacement as i64 as u64;
                    ir.push(IrInstruction::LockXadd {
                        address: absolute,
                        src: *src,
                    });
                }
            }
        }
    }
    Ok(ir)
}

pub fn execute_ir(
    state: &mut CpuState,
    memory: &mut MemoryImage,
    ir: &[IrInstruction],
) -> AppResult<ExecutionSummary> {
    execute_ir_with_hashing(state, memory, ir, false)
}

pub fn execute_ir_with_memory_hash(
    state: &mut CpuState,
    memory: &mut MemoryImage,
    ir: &[IrInstruction],
) -> AppResult<ExecutionSummary> {
    execute_ir_with_hashing(state, memory, ir, true)
}

fn execute_ir_with_hashing(
    state: &mut CpuState,
    memory: &mut MemoryImage,
    ir: &[IrInstruction],
    capture_memory_hash: bool,
) -> AppResult<ExecutionSummary> {
    let mut ordering_log = Vec::new();
    for instruction in ir {
        match instruction {
            IrInstruction::MovImm { dst, value } => state.set(*dst, *value),
            IrInstruction::MovReg { dst, src, width } => {
                let mask = width_mask(*width);
                let value = state.get(*src) & mask;
                let next = match width {
                    8 => value,
                    4 => zero_extend(value, *width),
                    2 => (state.get(*dst) & !mask) | value,
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("unsupported mov reg width {other}"),
                        ))
                    }
                };
                state.set(*dst, next);
            }
            IrInstruction::MovReg8 { dst, src } => state.set_byte(*dst, state.get_byte(*src)),
            IrInstruction::AddImm { dst, value, width } => {
                let mask = width_mask(*width);
                let lhs = state.get(*dst) & mask;
                let rhs = *value & mask;
                let result = lhs.wrapping_add(rhs) & mask;
                state.set(*dst, zero_extend(result, *width));
                state.flags = add_flags(lhs, rhs, result, *width * 8);
            }
            IrInstruction::AdcImm { dst, value, width } => {
                let mask = width_mask(*width);
                let lhs = state.get(*dst) & mask;
                let rhs = *value & mask;
                let carry = u64::from(state.flags.cf);
                let result = lhs.wrapping_add(rhs).wrapping_add(carry) & mask;
                state.set(*dst, zero_extend(result, *width));
                state.flags = adc_flags(lhs, rhs, carry, result, *width * 8);
            }
            IrInstruction::AdcImm8 { dst, value } => {
                let lhs = state.get_byte(*dst);
                let rhs = *value;
                let carry = u8::from(state.flags.cf);
                let result = lhs.wrapping_add(rhs).wrapping_add(carry);
                state.set_byte(*dst, result);
                state.flags = adc_flags(lhs as u64, rhs as u64, carry as u64, result as u64, 8);
            }
            IrInstruction::AddOperand { dst, src, width } => {
                let mask = width_mask(*width);
                let lhs = state.get(*dst) & mask;
                let rhs = read_compare_operand(state, memory, src, *width)? & mask;
                let result = lhs.wrapping_add(rhs) & mask;
                state.set(*dst, zero_extend(result, *width));
                state.flags = add_flags(lhs, rhs, result, *width * 8);
            }
            IrInstruction::AddMemory { address, src, width } => {
                let mask = width_mask(*width);
                let target = resolve_memory_operand(state, address, *width)?;
                let lhs = read_memory_value(memory, target, *width)? & mask;
                let rhs = state.get(*src) & mask;
                let result = lhs.wrapping_add(rhs) & mask;
                write_memory_value(memory, target, result, *width)?;
                state.flags = add_flags(lhs, rhs, result, *width * 8);
            }
            IrInstruction::AddImmMemory { address, value, width } => {
                let mask = width_mask(*width);
                let target = resolve_memory_operand(state, address, *width)?;
                let lhs = read_memory_value(memory, target, *width)? & mask;
                let rhs = *value & mask;
                let result = lhs.wrapping_add(rhs) & mask;
                write_memory_value(memory, target, result, *width)?;
                state.flags = add_flags(lhs, rhs, result, *width * 8);
            }
            IrInstruction::AdcImmMemory { address, value, width } => {
                let mask = width_mask(*width);
                let target = resolve_memory_operand(state, address, *width)?;
                let lhs = read_memory_value(memory, target, *width)? & mask;
                let rhs = *value & mask;
                let carry = u64::from(state.flags.cf);
                let result = lhs.wrapping_add(rhs).wrapping_add(carry) & mask;
                write_memory_value(memory, target, result, *width)?;
                state.flags = adc_flags(lhs, rhs, carry, result, *width * 8);
            }
            IrInstruction::OrImm { dst, value, width } => {
                let result = (state.get(*dst) | *value) & width_mask(*width);
                state.set(*dst, zero_extend(result, *width));
                state.flags = logic_flags(result, *width * 8);
            }
            IrInstruction::OrImm8 { dst, value } => {
                let result = state.get_byte(*dst) | *value;
                state.set_byte(*dst, result);
                state.flags = logic_flags(result as u64, 8);
            }
            IrInstruction::OrImmMemory { address, value, width } => {
                let target = resolve_memory_operand(state, address, *width)?;
                let result = read_memory_value(memory, target, *width)? | (*value & width_mask(*width));
                let result = result & width_mask(*width);
                write_memory_value(memory, target, result, *width)?;
                state.flags = logic_flags(result, *width * 8);
            }
            IrInstruction::SubImm { dst, value, width } => {
                let mask = width_mask(*width);
                let lhs = state.get(*dst) & mask;
                let rhs = *value & mask;
                let result = lhs.wrapping_sub(rhs) & mask;
                state.set(*dst, zero_extend(result, *width));
                state.flags = sub_flags(lhs, rhs, result, *width * 8);
            }
            IrInstruction::SubImmMemory { address, value, width } => {
                let mask = width_mask(*width);
                let target = resolve_memory_operand(state, address, *width)?;
                let lhs = read_memory_value(memory, target, *width)? & mask;
                let rhs = *value & mask;
                let result = lhs.wrapping_sub(rhs) & mask;
                write_memory_value(memory, target, result, *width)?;
                state.flags = sub_flags(lhs, rhs, result, *width * 8);
            }
            IrInstruction::AndImm { dst, value, width } => {
                let mask = width_mask(*width);
                let lhs = state.get(*dst) & mask;
                let result = lhs & (*value & mask);
                state.set(*dst, zero_extend(result, *width));
                state.flags = logic_flags(result, *width * 8);
            }
            IrInstruction::AndImmMemory { address, value, width } => {
                let mask = width_mask(*width);
                let target = resolve_memory_operand(state, address, *width)?;
                let lhs = read_memory_value(memory, target, *width)? & mask;
                let result = lhs & (*value & mask);
                write_memory_value(memory, target, result, *width)?;
                state.flags = logic_flags(result, *width * 8);
            }
            IrInstruction::ShlImm { dst, count, width } => {
                let bits = (*width * 8) as u32;
                let shift = (u32::from(*count)) & if bits == 64 { 63 } else { 31 };
                if shift != 0 {
                    let mask = width_mask(*width);
                    let lhs = state.get(*dst) & mask;
                    let result = (lhs << shift) & mask;
                    let sign_bit = 1_u64 << (bits - 1);
                    state.set(*dst, zero_extend(result, *width));
                    state.flags = Flags {
                        cf: ((lhs >> (bits - shift)) & 1) != 0,
                        pf: parity(result as u8),
                        af: false,
                        zf: result == 0,
                        sf: (result & sign_bit) != 0,
                        of: shift == 1 && ((lhs ^ result) & sign_bit) != 0,
                    };
                }
            }
            IrInstruction::ShrImm { dst, count, width } => {
                let bits = (*width * 8) as u32;
                let shift = (u32::from(*count)) & if bits == 64 { 63 } else { 31 };
                if shift != 0 {
                    let mask = width_mask(*width);
                    let lhs = state.get(*dst) & mask;
                    let result = lhs >> shift;
                    let sign_bit = 1_u64 << (bits - 1);
                    state.set(*dst, zero_extend(result, *width));
                    state.flags = Flags {
                        cf: ((lhs >> (shift - 1)) & 1) != 0,
                        pf: parity(result as u8),
                        af: false,
                        zf: result == 0,
                        sf: (result & sign_bit) != 0,
                        of: shift == 1 && (lhs & sign_bit) != 0,
                    };
                }
            }
            IrInstruction::SarImm { dst, count, width } => {
                let bits = (*width * 8) as u32;
                let shift = (u32::from(*count)) & if bits == 64 { 63 } else { 31 };
                if shift != 0 {
                    let mask = width_mask(*width);
                    let lhs = state.get(*dst) & mask;
                    let signed = sign_extend(lhs, *width) as i64;
                    let result = ((signed >> shift) as u64) & mask;
                    let sign_bit = 1_u64 << (bits - 1);
                    state.set(*dst, zero_extend(result, *width));
                    state.flags = Flags {
                        cf: ((lhs >> (shift - 1)) & 1) != 0,
                        pf: parity(result as u8),
                        af: false,
                        zf: result == 0,
                        sf: (result & sign_bit) != 0,
                        of: false,
                    };
                }
            }
            IrInstruction::ShlCl { dst, width } => {
                let count = state.get_byte(ByteRegister::Cl);
                execute_ir_with_hashing(
                    state,
                    memory,
                    &[IrInstruction::ShlImm {
                        dst: *dst,
                        count,
                        width: *width,
                    }],
                    false,
                )?;
            }
            IrInstruction::ShrCl { dst, width } => {
                let count = state.get_byte(ByteRegister::Cl);
                execute_ir_with_hashing(
                    state,
                    memory,
                    &[IrInstruction::ShrImm {
                        dst: *dst,
                        count,
                        width: *width,
                    }],
                    false,
                )?;
            }
            IrInstruction::SarCl { dst, width } => {
                let count = state.get_byte(ByteRegister::Cl);
                execute_ir_with_hashing(
                    state,
                    memory,
                    &[IrInstruction::SarImm {
                        dst: *dst,
                        count,
                        width: *width,
                    }],
                    false,
                )?;
            }
            IrInstruction::ImulImm { dst, src, imm, width } => {
                let lhs = sign_extend(read_compare_operand(state, memory, src, *width)?, *width) as i64 as i128;
                let rhs = sign_extend(*imm, 4) as i64 as i128;
                let product = lhs * rhs;
                let truncated = (product as u64) & width_mask(*width);
                state.set(*dst, zero_extend(truncated, *width));
                let overflow = product != sign_extend(truncated, *width) as i64 as i128;
                state.flags = Flags {
                    cf: overflow,
                    pf: false,
                    af: false,
                    zf: false,
                    sf: false,
                    of: overflow,
                };
            }
            IrInstruction::ImulReg { dst, src, width } => {
                let lhs = sign_extend(state.get(*dst), *width) as i64 as i128;
                let rhs = sign_extend(read_compare_operand(state, memory, src, *width)?, *width) as i64 as i128;
                let product = lhs * rhs;
                let truncated = (product as u64) & width_mask(*width);
                state.set(*dst, zero_extend(truncated, *width));
                let overflow = product != sign_extend(truncated, *width) as i64 as i128;
                state.flags = Flags {
                    cf: overflow,
                    pf: false,
                    af: false,
                    zf: false,
                    sf: false,
                    of: overflow,
                };
            }
            IrInstruction::SubOperand { dst, src, width } => {
                let mask = width_mask(*width);
                let lhs = state.get(*dst) & mask;
                let rhs = read_compare_operand(state, memory, src, *width)? & mask;
                let result = lhs.wrapping_sub(rhs) & mask;
                state.set(*dst, zero_extend(result, *width));
                state.flags = sub_flags(lhs, rhs, result, *width * 8);
            }
            IrInstruction::SbbOperand { dst, src, width } => {
                let mask = width_mask(*width);
                let lhs = state.get(*dst) & mask;
                let rhs = read_compare_operand(state, memory, src, *width)? & mask;
                let borrow = u64::from(state.flags.cf);
                let result = lhs.wrapping_sub(rhs).wrapping_sub(borrow) & mask;
                state.set(*dst, zero_extend(result, *width));
                state.flags = sbb_flags(lhs, rhs, borrow, result, *width * 8);
            }
            IrInstruction::Compare { lhs, rhs, width } => {
                let lhs_value = read_compare_operand(state, memory, lhs, *width)?;
                let rhs_value = read_compare_operand(state, memory, rhs, *width)?;
                let mask = width_mask(*width);
                let result = lhs_value.wrapping_sub(rhs_value) & mask;
                state.flags = sub_flags(lhs_value & mask, rhs_value & mask, result, *width * 8);
            }
            IrInstruction::Test { lhs, rhs, width } => {
                let lhs_value = read_compare_operand(state, memory, lhs, *width)?;
                let rhs_value = read_compare_operand(state, memory, rhs, *width)?;
                let result = (lhs_value & rhs_value) & width_mask(*width);
                state.flags = logic_flags(result, *width * 8);
            }
            IrInstruction::ExchangeMemory {
                address,
                register,
                width,
            } => {
                let target = resolve_memory_operand(state, address, *width)?;
                let memory_value = read_memory_value(memory, target, *width)?;
                let register_value = state.get(*register) & width_mask(*width);
                write_memory_value(memory, target, register_value, *width)?;
                state.set(*register, zero_extend(memory_value, *width));
            }
            IrInstruction::SignExtendTo64 { dst, src, width } => {
                let value = read_compare_operand(state, memory, src, *width)?;
                state.set(*dst, sign_extend(value, *width));
            }
            IrInstruction::SignExtend { dst, src, src_width, dst_width } => {
                let value = read_compare_operand(state, memory, src, *src_width)?;
                let extended = sign_extend(value, *src_width) & width_mask(*dst_width);
                state.set(*dst, zero_extend(extended, *dst_width));
            }
            IrInstruction::ZeroExtendTo64 { dst, src, width } => {
                let value = read_compare_operand(state, memory, src, *width)?;
                state.set(*dst, zero_extend(value, *width));
            }
            IrInstruction::XorImm { dst, value } => {
                let result = state.get(*dst) ^ *value;
                state.set(*dst, result);
                state.flags = logic_flags(result, state.arch.pointer_bytes() * 8);
            }
            IrInstruction::XorReg { dst, src } => {
                let result = state.get(*dst) ^ state.get(*src);
                state.set(*dst, result);
                state.flags = logic_flags(result, state.arch.pointer_bytes() * 8);
            }
            IrInstruction::AndReg8 { dst, src } => {
                let result = state.get_byte(*dst) & state.get_byte(*src);
                state.set_byte(*dst, result);
                state.flags = logic_flags(result as u64, 8);
            }
            IrInstruction::BitTest { base, bit, width } => {
                let value = state.get(*base) & width_mask(*width);
                let bit_width = (*width * 8) as u64;
                let index = if bit_width == 0 {
                    0
                } else {
                    state.get(*bit) % bit_width
                };
                state.flags.cf = ((value >> index) & 1) != 0;
            }
            IrInstruction::OrReg { dst, src, width } => {
                let lhs = state.get(*dst) & width_mask(*width);
                let rhs = read_compare_operand(state, memory, src, *width)? & width_mask(*width);
                let result = (lhs | rhs) & width_mask(*width);
                state.set(*dst, zero_extend(result, *width));
                state.flags = logic_flags(result, width * 8);
            }
            IrInstruction::OrMemory { address, src, width } => {
                let target = resolve_memory_operand(state, address, *width)?;
                let lhs = read_memory_value(memory, target, *width)? & width_mask(*width);
                let rhs = state.get(*src) & width_mask(*width);
                let result = (lhs | rhs) & width_mask(*width);
                write_memory_value(memory, target, result, *width)?;
                state.flags = logic_flags(result, width * 8);
            }
            IrInstruction::OrReg8 { dst, src } => {
                let result = state.get_byte(*dst) | state.get_byte(*src);
                state.set_byte(*dst, result);
                state.flags = logic_flags(result as u64, 8);
            }
            IrInstruction::IncReg { dst, width } => {
                let lhs = state.get(*dst) & width_mask(*width);
                let result = lhs.wrapping_add(1) & width_mask(*width);
                let carry = state.flags.cf;
                state.set(*dst, zero_extend(result, *width));
                state.flags = add_flags(lhs, 1, result, *width);
                state.flags.cf = carry;
            }
            IrInstruction::Cmov {
                condition,
                dst,
                src,
                width,
            } => {
                if condition_holds(state.flags, *condition) {
                    let value = read_compare_operand(state, memory, src, *width)?;
                    state.set(*dst, zero_extend(value, *width));
                }
            }
            IrInstruction::LoadMemory8 { dst, address } => {
                let target = resolve_memory_operand(state, address, 1)?;
                let value = read_memory_value(memory, target, 1)?;
                state.set_byte(*dst, value as u8);
            }
            IrInstruction::LoadMemory { dst, address, width } => {
                let target = resolve_memory_operand(state, address, *width)?;
                let value = read_memory_value(memory, target, *width)?;
                state.set(*dst, zero_extend(value, *width));
            }
            IrInstruction::StoreMemory8 { src, address } => {
                let target = resolve_memory_operand(state, address, 1)?;
                write_memory_value(memory, target, u64::from(state.get_byte(*src)), 1)?;
            }
            IrInstruction::StoreMemory { src, address, width } => {
                let target = resolve_memory_operand(state, address, *width)?;
                write_memory_value(memory, target, state.get(*src), *width)?;
            }
            IrInstruction::StoreImmediate { address, value, width } => {
                let target = resolve_memory_operand(state, address, *width)?;
                write_memory_value(memory, target, *value, *width)?;
            }
            IrInstruction::Call { target, return_address } => {
                let next_rsp = state.get(Register::Rsp).wrapping_sub(state.arch.pointer_bytes() as u64);
                memory.write_u64(next_rsp, *return_address);
                state.set(Register::Rsp, next_rsp);
                state.rip = *target;
            }
            IrInstruction::CallRegister { src, return_address } => {
                let next_rsp = state.get(Register::Rsp).wrapping_sub(state.arch.pointer_bytes() as u64);
                memory.write_u64(next_rsp, *return_address);
                state.set(Register::Rsp, next_rsp);
                state.rip = state.get(*src);
            }
            IrInstruction::CallMemory { address, return_address } => {
                let target_ptr = resolve_memory_operand(state, address, state.arch.pointer_bytes())?;
                let target = read_memory_value(memory, target_ptr, state.arch.pointer_bytes())?;
                let next_rsp = state.get(Register::Rsp).wrapping_sub(state.arch.pointer_bytes() as u64);
                memory.write_u64(next_rsp, *return_address);
                state.set(Register::Rsp, next_rsp);
                state.rip = target;
            }
            IrInstruction::JumpRegister { src } => {
                state.rip = state.get(*src);
            }
            IrInstruction::JumpMemory { address } => {
                let target_ptr = resolve_memory_operand(state, address, state.arch.pointer_bytes())?;
                state.rip = read_memory_value(memory, target_ptr, state.arch.pointer_bytes())?;
            }
            IrInstruction::Setcc { condition, dst } => {
                state.set_byte(*dst, condition_holds(state.flags, *condition) as u8);
            }
            IrInstruction::JumpIf {
                condition,
                target,
                fallthrough,
            } => {
                state.rip = if condition_holds(state.flags, *condition) {
                    *target
                } else {
                    *fallthrough
                };
            }
            IrInstruction::Jump { target } => state.rip = *target,
            IrInstruction::Nop => {}
            IrInstruction::LoadEffectiveAddress { dst, address, width } => {
                let target = resolve_memory_operand(state, address, 8)?;
                state.set(*dst, zero_extend(target, *width));
            }
            IrInstruction::PushReg { src } => {
                let next_rsp = state.get(Register::Rsp).wrapping_sub(state.arch.pointer_bytes() as u64);
                memory.write_u64(next_rsp, state.get(*src));
                state.set(Register::Rsp, next_rsp);
            }
            IrInstruction::PopReg { dst } => {
                let rsp = state.get(Register::Rsp);
                let value = memory.read_u64(rsp)?;
                state.set(*dst, value);
                state.set(Register::Rsp, rsp.wrapping_add(state.arch.pointer_bytes() as u64));
            }
            IrInstruction::Return => {}
            IrInstruction::Popcnt { dst, src } => {
                let value = state.get(*src);
                let result = value.count_ones() as u64;
                state.set(*dst, result);
                state.flags = Flags {
                    cf: false,
                    pf: false,
                    af: false,
                    zf: value == 0,
                    sf: false,
                    of: false,
                };
            }
            IrInstruction::Lzcnt { dst, src } => {
                let value = state.get(*src);
                let width = (state.arch.pointer_bytes() * 8) as u32;
                let result = if width == 64 {
                    value.leading_zeros() as u64
                } else {
                    (value as u32).leading_zeros() as u64
                };
                state.set(*dst, result);
                state.flags = Flags {
                    cf: value == 0,
                    pf: false,
                    af: false,
                    zf: result == 0,
                    sf: false,
                    of: false,
                };
            }
            IrInstruction::MoveXmm { dst, src } => {
                state.set_xmm(*dst, state.get_xmm(*src));
            }
            IrInstruction::LoadXmm { dst, address } => {
                let target = resolve_memory_operand(state, address, 16)?;
                state.set_xmm(*dst, memory.read_xmm(target)?);
            }
            IrInstruction::StoreXmm { src, address } => {
                let target = resolve_memory_operand(state, address, 16)?;
                memory.map_xmm(target, state.get_xmm(*src));
            }
            IrInstruction::Pxor { dst, src } => {
                let lhs = state.get_xmm(*dst);
                let rhs = state.get_xmm(*src);
                state.set_xmm(
                    *dst,
                    XmmValue {
                        low: lhs.low ^ rhs.low,
                        high: lhs.high ^ rhs.high,
                    },
                );
            }
            IrInstruction::Paddq { dst, src } => {
                let lhs = state.get_xmm(*dst);
                let rhs = state.get_xmm(*src);
                state.set_xmm(
                    *dst,
                    XmmValue {
                        low: lhs.low.wrapping_add(rhs.low),
                        high: lhs.high.wrapping_add(rhs.high),
                    },
                );
            }
            IrInstruction::HaddPs { dst, src } => {
                let lhs = xmm_to_f32x4(state.get_xmm(*dst));
                let rhs = xmm_to_f32x4(state.get_xmm(*src));
                state.set_xmm(
                    *dst,
                    f32x4_to_xmm([
                        lhs[0] + lhs[1],
                        lhs[2] + lhs[3],
                        rhs[0] + rhs[1],
                        rhs[2] + rhs[3],
                    ]),
                );
            }
            IrInstruction::Pshufb { dst, mask } => {
                let mut source = xmm_to_bytes(state.get_xmm(*dst));
                let selector = xmm_to_bytes(state.get_xmm(*mask));
                let mut output = [0_u8; 16];
                for index in 0..16 {
                    let mask_byte = selector[index];
                    output[index] = if mask_byte & 0x80 != 0 {
                        0
                    } else {
                        source[(mask_byte & 0x0f) as usize]
                    };
                }
                state.set_xmm(*dst, bytes_to_xmm(output));
                source.fill(0);
            }
            IrInstruction::BlendD { dst, src, mask } => {
                let mut dst_words = xmm_to_u32x4(state.get_xmm(*dst));
                let src_words = xmm_to_u32x4(state.get_xmm(*src));
                for index in 0..4 {
                    if (mask >> index) & 1 == 1 {
                        dst_words[index as usize] = src_words[index as usize];
                    }
                }
                state.set_xmm(*dst, u32x4_to_xmm(dst_words));
            }
            IrInstruction::Crc32 { dst, src } => {
                let crc = crc32_u64(state.get(*dst) as u32, state.get(*src));
                state.set(*dst, crc as u64);
                state.flags = logic_flags(crc as u64, 32);
            }
            IrInstruction::Andn { dst, lhs, rhs } => {
                state.set(*dst, (!state.get(*lhs)) & state.get(*rhs));
            }
            IrInstruction::Pdep { dst, src, mask } => {
                let deposited = bit_deposit(state.get(*src), state.get(*mask));
                state.set(*dst, deposited);
            }
            IrInstruction::Pext { dst, src, mask } => {
                let extracted = bit_extract(state.get(*src), state.get(*mask));
                state.set(*dst, extracted);
            }
            IrInstruction::LockCmpxchg { address, src, width } => {
                let target = resolve_memory_operand(state, address, *width)?;
                let original = read_memory_value(memory, target, *width)?;
                let accumulator = state.get(Register::Rax) & width_mask(*width);
                let source = state.get(*src) & width_mask(*width);
                let result = accumulator.wrapping_sub(original) & width_mask(*width);
                state.flags = sub_flags(accumulator, original, result, *width * 8);
                if accumulator == original {
                    write_memory_value(memory, target, source, *width)?;
                    state.flags.zf = true;
                } else {
                    let updated_rax = (state.get(Register::Rax) & !width_mask(*width)) | original;
                    state.set(Register::Rax, updated_rax);
                    state.flags.zf = false;
                }
                ordering_log.push(format!("cmpxchg:{target:#x}"));
            }
            IrInstruction::LockXadd { address, src } => {
                let original = memory.read_u64(*address)?;
                let source = state.get(*src);
                let next = original.wrapping_add(source);
                memory.write_u64(*address, next);
                state.set(*src, original);
                ordering_log.push(format!("ldaxr:{address:#x}"));
                ordering_log.push(format!("stlxr:{address:#x}"));
            }
            IrInstruction::Mfence => ordering_log.push("dmb ish".to_string()),
            IrInstruction::X87Init => state.x87 = X87State::default(),
            IrInstruction::X87LoadConst { value } => state.x87.stack.push(*value),
            IrInstruction::X87Add => {
                let rhs = state.x87.stack.pop().ok_or_else(|| {
                    AppError::new(ReasonCode::RcUnimplInsn, "x87 stack underflow")
                })?;
                let lhs = state.x87.stack.pop().ok_or_else(|| {
                    AppError::new(ReasonCode::RcUnimplInsn, "x87 stack underflow")
                })?;
                let result = apply_rounding(lhs + rhs, state.x87.rounding_mode);
                state.x87.precision |= result != lhs + rhs;
                state.x87.stack.push(result);
            }
            IrInstruction::X87Div => {
                let rhs = state.x87.stack.pop().ok_or_else(|| {
                    AppError::new(ReasonCode::RcUnimplInsn, "x87 stack underflow")
                })?;
                let lhs = state.x87.stack.pop().ok_or_else(|| {
                    AppError::new(ReasonCode::RcUnimplInsn, "x87 stack underflow")
                })?;
                if rhs == 0.0 {
                    state.x87.divide_by_zero = true;
                    state.x87.stack.push(f64::INFINITY);
                } else {
                    let result = apply_rounding(lhs / rhs, state.x87.rounding_mode);
                    state.x87.precision |= result != lhs / rhs;
                    state.x87.stack.push(result);
                }
            }
        }
    }
    Ok(ExecutionSummary {
        flags: state.flags,
        memory_hash: if capture_memory_hash {
            memory.stable_hash()
        } else {
            String::new()
        },
        ordering_log,
    })
}

pub fn map_host_signal(signal: HostSignal, address: u64) -> WindowsException {
    let code = match signal {
        HostSignal::Segv | HostSignal::Bus => EXCEPTION_ACCESS_VIOLATION,
        HostSignal::Ill => EXCEPTION_ILLEGAL_INSTRUCTION,
        HostSignal::FpeIntDivideByZero => EXCEPTION_INT_DIVIDE_BY_ZERO,
        HostSignal::Trap => EXCEPTION_BREAKPOINT,
    };
    WindowsException { code, address }
}

fn normalize_feature_name(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(['.', '-', ' '], "_")
}

fn parse_bool(value: &str) -> AppResult<bool> {
    match value {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("invalid boolean value {other}"),
        )),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    match value & 0x0f {
        0..=9 => (b'0' + (value & 0x0f)) as char,
        other => (b'a' + (other - 10)) as char,
    }
}

fn build_cache_key(bytes: &[u8], config: &CpuEngineConfig) -> BlockCacheKey {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    BlockCacheKey {
        source_hash: hex_bytes(&hasher.finalize()),
        os_build: config.os_build.clone(),
        macwin_version: config.macwin_version.clone(),
        cpu_profile: config.virtualization.profile_fingerprint(),
        arch: config.arch,
    }
}

fn touched_pages(address: u64, length: usize) -> BTreeSet<u64> {
    let start = address & !0xfff;
    let end = (address + length.max(1) as u64 - 1) & !0xfff;
    let mut pages = BTreeSet::new();
    let mut current = start;
    while current <= end {
        pages.insert(current);
        current += 0x1000;
    }
    pages
}

fn lower_to_arm64(ir: &[IrInstruction]) -> Vec<String> {
    let mut instructions = Vec::new();
    for op in ir {
        match op {
            IrInstruction::MovImm { dst, value } => {
                instructions.push(format!("movz x{}, #{:#x}", dst.index(), value & 0xffff));
            }
            IrInstruction::MovReg { dst, src, width } => {
                let register_class = if *width == 8 { 'x' } else { 'w' };
                instructions.push(format!("mov {register_class}{}, {register_class}{}", dst.index(), src.index()));
            }
            IrInstruction::MovReg8 { dst, src } => {
                instructions.push(format!("mov w{}, w{}", dst.full_register().index(), src.full_register().index()));
            }
            IrInstruction::AddImm { dst, value, .. } => {
                instructions.push(format!("add x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::AdcImm { dst, value, .. } => {
                instructions.push(format!("adcs x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::AdcImm8 { dst, value } => {
                instructions.push(format!("adcs w{}, w{}, #{:#x}", dst.full_register().index(), dst.full_register().index(), value));
            }
            IrInstruction::AddOperand { dst, .. } => {
                instructions.push(format!("add x{}, x{}, xadd_src", dst.index(), dst.index()));
            }
            IrInstruction::AddMemory { src, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; add xtmp, xtmp, x{}; str xtmp, [mem]", src.index()));
            }
            IrInstruction::AddImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; add xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            IrInstruction::AdcImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; adcs xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            IrInstruction::OrImm { dst, value, .. } => {
                instructions.push(format!("orr x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::OrImm8 { dst, value } => {
                instructions.push(format!("orr w{}, w{}, #{:#x}", dst.full_register().index(), dst.full_register().index(), value));
            }
            IrInstruction::OrImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; orr xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            IrInstruction::SubImm { dst, value, .. } => {
                instructions.push(format!("sub x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::SubImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; sub xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            IrInstruction::SbbOperand { dst, .. } => {
                instructions.push(format!("sbc x{}, x{}, xsrc", dst.index(), dst.index()));
            }
            IrInstruction::AndImm { dst, value, .. } => {
                instructions.push(format!("and x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::AndImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; and xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            IrInstruction::ShlImm { dst, count, .. } => {
                instructions.push(format!("lsl x{}, x{}, #{count}", dst.index(), dst.index()));
            }
            IrInstruction::ShrImm { dst, count, .. } => {
                instructions.push(format!("lsr x{}, x{}, #{count}", dst.index(), dst.index()));
            }
            IrInstruction::SarImm { dst, count, .. } => {
                instructions.push(format!("asr x{}, x{}, #{count}", dst.index(), dst.index()));
            }
            IrInstruction::ShlCl { dst, .. } => {
                instructions.push(format!("lsl x{}, x{}, wcl", dst.index(), dst.index()));
            }
            IrInstruction::ShrCl { dst, .. } => {
                instructions.push(format!("lsr x{}, x{}, wcl", dst.index(), dst.index()));
            }
            IrInstruction::SarCl { dst, .. } => {
                instructions.push(format!("asr x{}, x{}, wcl", dst.index(), dst.index()));
            }
            IrInstruction::ImulImm { dst, imm, .. } => {
                instructions.push(format!("mul x{}, ximul_src, #{imm:#x}", dst.index()));
            }
            IrInstruction::ImulReg { dst, .. } => {
                instructions.push(format!("mul x{}, x{}, ximul_src", dst.index(), dst.index()));
            }
            IrInstruction::SubOperand { dst, .. } => {
                instructions.push(format!("sub x{}, x{}, xsub_src", dst.index(), dst.index()));
            }
            IrInstruction::Compare { .. } => instructions.push("cmp xcmp_lhs, xcmp_rhs".to_string()),
            IrInstruction::Test { .. } => instructions.push("tst xtest_lhs, xtest_rhs".to_string()),
            IrInstruction::ExchangeMemory { .. } => instructions.push("swp xswap_src, xswap_dst, [mem]".to_string()),
            IrInstruction::SignExtendTo64 { dst, .. } => {
                instructions.push(format!("sxtw x{}, wsrc", dst.index()));
            }
            IrInstruction::SignExtend { dst, .. } => {
                instructions.push(format!("sxt x{}, wsrc", dst.index()));
            }
            IrInstruction::ZeroExtendTo64 { dst, .. } => {
                instructions.push(format!("uxtw x{}, wsrc", dst.index()));
            }
            IrInstruction::XorImm { dst, value } => {
                instructions.push(format!("eor x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::XorReg { dst, src } => {
                instructions.push(format!("eor x{}, x{}, x{}", dst.index(), dst.index(), src.index()));
            }
            IrInstruction::AndReg8 { dst, src } => {
                instructions.push(format!(
                    "and w{}, w{}, w{}",
                    dst.full_register().index(),
                    dst.full_register().index(),
                    src.full_register().index()
                ));
            }
            IrInstruction::BitTest { base, bit, .. } => {
                instructions.push(format!("ubfx xcf, x{}, x{}, #1", base.index(), bit.index()));
            }
            IrInstruction::OrReg { dst, .. } => {
                instructions.push(format!("orr x{}, x{}, xorr_src", dst.index(), dst.index()));
            }
            IrInstruction::OrMemory { src, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; orr xtmp, xtmp, x{}; str xtmp, [mem]", src.index()));
            }
            IrInstruction::OrReg8 { dst, src } => {
                instructions.push(format!("orr w{}, w{}, w{}", dst.full_register().index(), dst.full_register().index(), src.full_register().index()));
            }
            IrInstruction::IncReg { dst, .. } => {
                instructions.push(format!("add x{}, x{}, #1", dst.index(), dst.index()));
            }
            IrInstruction::Cmov { dst, .. } => {
                instructions.push(format!("csel x{}, xcmov_src, x{}, eq", dst.index(), dst.index()));
            }
            IrInstruction::LoadMemory8 { dst, .. } => {
                instructions.push(format!("ldrb w{}, [mem]", dst.full_register().index()));
            }
            IrInstruction::LoadMemory { dst, .. } => {
                instructions.push(format!("ldr x{}, [mem]", dst.index()));
            }
            IrInstruction::StoreMemory8 { src, .. } => {
                instructions.push(format!("strb w{}, [mem]", src.full_register().index()));
            }
            IrInstruction::StoreMemory { src, .. } => {
                instructions.push(format!("str x{}, [mem]", src.index()));
            }
            IrInstruction::StoreImmediate { value, width, .. } => {
                instructions.push(format!("mov imm_store_{width}, #{value:#x}"));
            }
            IrInstruction::Call { target, .. } => {
                instructions.push(format!("bl {target:#x}"));
            }
            IrInstruction::CallRegister { src, .. } => {
                instructions.push(format!("blr x{}", src.index()));
            }
            IrInstruction::CallMemory { .. } => {
                instructions.push("blr xmem_target".to_string());
            }
            IrInstruction::JumpRegister { src } => {
                instructions.push(format!("br x{}", src.index()));
            }
            IrInstruction::JumpMemory { .. } => {
                instructions.push("br xmem_target".to_string());
            }
            IrInstruction::Setcc { dst, .. } => {
                instructions.push(format!("cset w{}, eq", dst.full_register().index()));
            }
            IrInstruction::JumpIf { target, .. } => instructions.push(format!("b.cond {target:#x}")),
            IrInstruction::Jump { target } => instructions.push(format!("b {target:#x}")),
            IrInstruction::Nop => instructions.push("nop".to_string()),
            IrInstruction::LoadEffectiveAddress { dst, .. } => {
                instructions.push(format!("add x{}, xzr, #lea", dst.index()));
            }
            IrInstruction::PushReg { src } => {
                instructions.push(format!("str x{}, [sp, #-8]!", src.index()));
            }
            IrInstruction::PopReg { dst } => {
                instructions.push(format!("ldr x{}, [sp], #8", dst.index()));
            }
            IrInstruction::Return => instructions.push("ret".to_string()),
            IrInstruction::Popcnt { dst, src } => {
                instructions.push(format!("cnt x{}, x{}", dst.index(), src.index()));
            }
            IrInstruction::Lzcnt { dst, src } => {
                instructions.push(format!("clz x{}, x{}", dst.index(), src.index()));
            }
            IrInstruction::MoveXmm { dst, src } => {
                instructions.push(format!("mov v{dst}.16b, v{src}.16b"));
            }
            IrInstruction::LoadXmm { dst, .. } => {
                instructions.push(format!("ldr q{dst}, [mem]"));
            }
            IrInstruction::StoreXmm { src, .. } => {
                instructions.push(format!("str q{src}, [mem]"));
            }
            IrInstruction::Pxor { dst, src } => {
                instructions.push(format!("eor v{dst}.16b, v{dst}.16b, v{src}.16b"));
            }
            IrInstruction::Paddq { dst, src } => {
                instructions.push(format!("add v{dst}.2d, v{dst}.2d, v{src}.2d"));
            }
            IrInstruction::X87Init => instructions.push("bl __casa1_x87_init".to_string()),
            IrInstruction::HaddPs { dst, src } => {
                instructions.push(format!("faddp v{dst}.4s, v{dst}.4s, v{src}.4s"));
            }
            IrInstruction::Pshufb { dst, mask } => {
                instructions.push(format!("tbl v{dst}.16b, {{v{dst}.16b}}, v{mask}.16b"));
            }
            IrInstruction::BlendD { dst, src, mask } => {
                instructions.push(format!("bsl v{dst}.16b, v{src}.16b, #0x{mask:02x}"));
            }
            IrInstruction::Crc32 { dst, src } => {
                instructions.push(format!("crc32x w{}, w{}, x{}", dst.index(), dst.index(), src.index()));
            }
            IrInstruction::Andn { dst, lhs, rhs } => {
                instructions.push(format!("bic x{}, x{}, x{}", dst.index(), rhs.index(), lhs.index()));
            }
            IrInstruction::Pdep { dst, .. } => {
                instructions.push(format!("bl __casa1_pdep -> x{}", dst.index()));
            }
            IrInstruction::Pext { dst, .. } => {
                instructions.push(format!("bl __casa1_pext -> x{}", dst.index()));
            }
            IrInstruction::LockCmpxchg { .. } => instructions.push("bl __casa1_cmpxchg".to_string()),
            IrInstruction::LockXadd { address, .. } => {
                instructions.push(format!("ldaxr x9, [{address:#x}]"));
                instructions.push(format!("stlxr w10, x11, [{address:#x}]"));
            }
            IrInstruction::Mfence => instructions.push("dmb ish".to_string()),
            IrInstruction::X87LoadConst { .. } => instructions.push("bl __casa1_x87_push".to_string()),
            IrInstruction::X87Add => instructions.push("bl __casa1_x87_add".to_string()),
            IrInstruction::X87Div => instructions.push("bl __casa1_x87_div".to_string()),
        }
    }
    instructions
}

#[derive(Debug, Clone, Copy)]
struct ParsedModrm {
    reg: u8,
    rm: u8,
    mod_bits: u8,
    sib: Option<ParsedSib>,
    displacement: i32,
    rip_relative: bool,
}

impl ParsedModrm {
    fn rm_register(self) -> u8 {
        if self.mod_bits == 0b11 { self.rm } else { self.rm & 0x0f }
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedSib {
    scale: u8,
    index: u8,
    base: u8,
    no_base: bool,
}

fn parse_modrm(
    bytes: &[u8],
    offset: usize,
    arch: GuestArch,
    rex: Option<RexPrefix>,
    address_size_32: bool,
) -> AppResult<(ParsedModrm, usize)> {
    let modrm = *bytes.get(offset).ok_or_else(|| {
        AppError::new(ReasonCode::RcUnimplInsn, "missing ModRM byte")
    })?;
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
    let rip_relative = arch == GuestArch::X64 && !address_size_32 && mod_bits == 0 && (modrm & 0x07) == 0x05;
    if mod_bits != 0b11 && (modrm & 0x07) == 0x04 {
        let sib_byte = *bytes.get(offset + consumed).ok_or_else(|| {
            AppError::new(ReasonCode::RcUnimplInsn, "missing SIB byte")
        })?;
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
        displacement = *bytes.get(offset + consumed).ok_or_else(|| {
            AppError::new(ReasonCode::RcUnimplInsn, "missing disp8")
        })? as i8 as i32;
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
            rip_relative,
        },
        consumed,
    ))
}

fn modrm_operand(
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
        })
    }
}

fn segment_from_prefixes(prefixes: &[InstructionPrefix]) -> Option<SegmentRegister> {
    prefixes.iter().rev().find_map(|prefix| match prefix {
        InstructionPrefix::FsSegment => Some(SegmentRegister::Fs),
        InstructionPrefix::GsSegment => Some(SegmentRegister::Gs),
        _ => None,
    })
}

fn operand_width(rex: Option<RexPrefix>, prefixes: &[InstructionPrefix], arch: GuestArch) -> usize {
    if arch == GuestArch::X64 && rex.map(|value| value.w).unwrap_or(false) {
        8
    } else if prefixes.contains(&InstructionPrefix::OperandSize) {
        2
    } else {
        4
    }
}

fn compare_operand(operand: Operand) -> CompareOperand {
    match operand {
        Operand::Register(register) => CompareOperand::Register(register),
        Operand::Register8(register) => CompareOperand::Register8(register),
        Operand::Memory(memory) => CompareOperand::Memory(memory),
        Operand::ImmediateU64(value) => CompareOperand::ImmediateU64(value),
        other => panic!("unsupported compare operand {other:?}"),
    }
}

fn compare_operand_to_operand(operand: CompareOperand) -> Operand {
    match operand {
        CompareOperand::Register(register) => Operand::Register(register),
        CompareOperand::Register8(register) => Operand::Register8(register),
        CompareOperand::Memory(memory) => Operand::Memory(memory),
        CompareOperand::ImmediateU64(value) => Operand::ImmediateU64(value),
    }
}

fn rex_register_low(rex: Option<RexPrefix>) -> u8 {
    rex.map(|value| if value.b { 8 } else { 0 }).unwrap_or(0)
}

fn read_immediate(bytes: &[u8], offset: usize, size: usize) -> AppResult<u64> {
    let slice = bytes.get(offset..offset + size).ok_or_else(|| {
        AppError::new(ReasonCode::RcUnimplInsn, "truncated immediate")
    })?;
    Ok(match size {
        1 => slice[0] as u64,
        2 => u16::from_le_bytes(slice.try_into().expect("immediate width")) as u64,
        4 => u32::from_le_bytes(slice.try_into().expect("immediate width")) as u64,
        8 => u64::from_le_bytes(slice.try_into().expect("immediate width")),
        _ => {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unsupported immediate width {size}"),
            ))
        }
    })
}

fn read_i32(bytes: &[u8], offset: usize) -> AppResult<i32> {
    let slice = bytes.get(offset..offset + 4).ok_or_else(|| {
        AppError::new(ReasonCode::RcUnimplInsn, "truncated displacement")
    })?;
    Ok(i32::from_le_bytes(slice.try_into().expect("disp32 width")))
}

fn decode_condition(value: u64) -> AppResult<ConditionCode> {
    match value {
        0 => Ok(ConditionCode::Equal),
        1 => Ok(ConditionCode::NotEqual),
        2 => Ok(ConditionCode::Below),
        3 => Ok(ConditionCode::NotBelow),
        4 => Ok(ConditionCode::Above),
        5 => Ok(ConditionCode::NotAbove),
        6 => Ok(ConditionCode::Sign),
        7 => Ok(ConditionCode::NotSign),
        8 => Ok(ConditionCode::LessEqual),
        9 => Ok(ConditionCode::Greater),
        other => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported condition code {other}"),
        )),
    }
}

fn condition_holds(flags: Flags, condition: ConditionCode) -> bool {
    match condition {
        ConditionCode::Equal => flags.zf,
        ConditionCode::NotEqual => !flags.zf,
        ConditionCode::Below => flags.cf,
        ConditionCode::NotBelow => !flags.cf,
        ConditionCode::Above => !flags.cf && !flags.zf,
        ConditionCode::NotAbove => flags.cf || flags.zf,
        ConditionCode::Sign => flags.sf,
        ConditionCode::NotSign => !flags.sf,
        ConditionCode::LessEqual => flags.zf || (flags.sf != flags.of),
        ConditionCode::Greater => !flags.zf && (flags.sf == flags.of),
    }
}

fn width_mask(width: usize) -> u64 {
    match width {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

fn zero_extend(value: u64, width: usize) -> u64 {
    value & width_mask(width)
}

fn sign_extend(value: u64, width: usize) -> u64 {
    match width {
        1 => (value as i8 as i64) as u64,
        2 => (value as i16 as i64) as u64,
        4 => (value as i32 as i64) as u64,
        8 => value,
        _ => value,
    }
}

fn read_memory_value(memory: &MemoryImage, address: u64, width: usize) -> AppResult<u64> {
    match width {
        1 => Ok(memory.read_u8(address)? as u64),
        2 => {
            let bytes = [memory.read_u8(address)?, memory.read_u8(address + 1)?];
            Ok(u16::from_le_bytes(bytes) as u64)
        }
        4 => {
            let bytes = [
                memory.read_u8(address)?,
                memory.read_u8(address + 1)?,
                memory.read_u8(address + 2)?,
                memory.read_u8(address + 3)?,
            ];
            Ok(u32::from_le_bytes(bytes) as u64)
        }
        8 => memory.read_u64(address),
        other => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported memory width {other}"),
        )),
    }
}

fn write_memory_value(memory: &mut MemoryImage, address: u64, value: u64, width: usize) -> AppResult<()> {
    match width {
        1 => memory.map_bytes(address, &[value as u8]),
        2 => memory.map_bytes(address, &(value as u16).to_le_bytes()),
        4 => memory.map_bytes(address, &(value as u32).to_le_bytes()),
        8 => memory.write_u64(address, value),
        other => {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unsupported memory width {other}"),
            ))
        }
    }
    Ok(())
}

fn read_compare_operand(
    state: &CpuState,
    memory: &MemoryImage,
    operand: &CompareOperand,
    width: usize,
) -> AppResult<u64> {
    match operand {
        CompareOperand::Register(register) => Ok(state.get(*register) & width_mask(width)),
        CompareOperand::Register8(register) => Ok(u64::from(state.get_byte(*register)) & width_mask(width)),
        CompareOperand::Memory(memory_operand) => {
            let address = resolve_memory_operand(state, memory_operand, width)?;
            read_memory_value(memory, address, width)
        }
        CompareOperand::ImmediateU64(value) => Ok(*value & width_mask(width)),
    }
}

fn resolve_memory_operand(state: &CpuState, operand: &MemoryOperand, width: usize) -> AppResult<u64> {
    let _ = width;
    let address = if operand.address_size_32 {
        let mut value = operand.displacement as u32 as u64;
        if operand.rip_relative {
            value = value.wrapping_add((operand.rip_base as u32) as u64);
        }
        if let Some(segment) = operand.segment {
            value = value.wrapping_add((state.segment_base(segment) as u32) as u64);
        }
        if let Some(base) = operand.base {
            value = value.wrapping_add((state.get(base) as u32) as u64);
        }
        if let Some(index) = operand.index {
            value = value.wrapping_add(((state.get(index) as u32) as u64).wrapping_mul(u64::from(operand.scale)));
        }
        value & 0xffff_ffff
    } else {
        let mut value = operand.displacement as i64 as u64;
        if operand.rip_relative {
            value = value.wrapping_add(operand.rip_base);
        }
        if let Some(segment) = operand.segment {
            value = value.wrapping_add(state.segment_base(segment));
        }
        if let Some(base) = operand.base {
            value = value.wrapping_add(state.get(base));
        }
        if let Some(index) = operand.index {
            value = value.wrapping_add(state.get(index).wrapping_mul(u64::from(operand.scale)));
        }
        value
    };
    Ok(address)
}

fn add_flags(lhs: u64, rhs: u64, result: u64, width: usize) -> Flags {
    let sign_bit = 1_u64 << (width - 1);
    Flags {
        cf: result < lhs,
        pf: parity(result as u8),
        af: ((lhs ^ rhs ^ result) & 0x10) != 0,
        zf: result == 0,
        sf: (result & sign_bit) != 0,
        of: ((!(lhs ^ rhs) & (lhs ^ result)) & sign_bit) != 0,
    }
}

fn adc_flags(lhs: u64, rhs: u64, carry: u64, result: u64, width: usize) -> Flags {
    let sign_bit = 1_u64 << (width - 1);
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1_u64 << width) - 1
    };
    let unsigned_sum = lhs as u128 + rhs as u128 + carry as u128;
    let signed_sum = signed_value(lhs, width) + signed_value(rhs, width) + carry as i128;
    let min_signed = -(1_i128 << (width - 1));
    let max_signed = (1_i128 << (width - 1)) - 1;
    Flags {
        cf: unsigned_sum > mask as u128,
        pf: parity(result as u8),
        af: ((lhs & 0x0f) + (rhs & 0x0f) + carry) > 0x0f,
        zf: result == 0,
        sf: (result & sign_bit) != 0,
        of: signed_sum < min_signed || signed_sum > max_signed,
    }
}

fn sub_flags(lhs: u64, rhs: u64, result: u64, width: usize) -> Flags {
    let sign_bit = 1_u64 << (width - 1);
    Flags {
        cf: lhs < rhs,
        pf: parity(result as u8),
        af: ((lhs ^ rhs ^ result) & 0x10) != 0,
        zf: result == 0,
        sf: (result & sign_bit) != 0,
        of: (((lhs ^ rhs) & (lhs ^ result)) & sign_bit) != 0,
    }
}

fn sbb_flags(lhs: u64, rhs: u64, borrow: u64, result: u64, width: usize) -> Flags {
    let sign_bit = 1_u64 << (width - 1);
    let rhs_with_borrow = rhs.wrapping_add(borrow) & width_mask(width / 8);
    Flags {
        cf: (lhs as u128) < (rhs as u128 + borrow as u128),
        pf: parity(result as u8),
        af: ((lhs ^ rhs_with_borrow ^ result) & 0x10) != 0,
        zf: result == 0,
        sf: (result & sign_bit) != 0,
        of: (((lhs ^ rhs_with_borrow) & (lhs ^ result)) & sign_bit) != 0,
    }
}

fn signed_value(value: u64, width: usize) -> i128 {
    let sign_bit = 1_u64 << (width - 1);
    if value & sign_bit != 0 {
        value as i128 - (1_i128 << width)
    } else {
        value as i128
    }
}

fn logic_flags(result: u64, width: usize) -> Flags {
    let sign_bit = 1_u64 << (width - 1);
    Flags {
        cf: false,
        pf: parity(result as u8),
        af: false,
        zf: result == 0,
        sf: (result & sign_bit) != 0,
        of: false,
    }
}

fn parity(value: u8) -> bool {
    value.count_ones() % 2 == 0
}

fn bit_deposit(mut source: u64, mut mask: u64) -> u64 {
    let mut result = 0_u64;
    while mask != 0 {
        let lowest = mask & mask.wrapping_neg();
        if source & 1 != 0 {
            result |= lowest;
        }
        source >>= 1;
        mask &= mask - 1;
    }
    result
}

fn bit_extract(source: u64, mut mask: u64) -> u64 {
    let mut result = 0_u64;
    let mut bit = 0_u32;
    while mask != 0 {
        let lowest = mask & mask.wrapping_neg();
        if source & lowest != 0 {
            result |= 1_u64 << bit;
        }
        mask &= mask - 1;
        bit += 1;
    }
    result
}

fn apply_rounding(value: f64, mode: X87RoundingMode) -> f64 {
    match mode {
        X87RoundingMode::Nearest => value,
        X87RoundingMode::Down => value.floor(),
        X87RoundingMode::Up => value.ceil(),
        X87RoundingMode::TowardZero => value.trunc(),
    }
}

fn xmm_to_bytes(value: XmmValue) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&value.low.to_le_bytes());
    bytes[8..].copy_from_slice(&value.high.to_le_bytes());
    bytes
}

fn bytes_to_xmm(bytes: [u8; 16]) -> XmmValue {
    XmmValue {
        low: u64::from_le_bytes(bytes[..8].try_into().expect("low xmm bytes")),
        high: u64::from_le_bytes(bytes[8..].try_into().expect("high xmm bytes")),
    }
}

fn xmm_to_u32x4(value: XmmValue) -> [u32; 4] {
    let bytes = xmm_to_bytes(value);
    [
        u32::from_le_bytes(bytes[0..4].try_into().expect("u32 lane")),
        u32::from_le_bytes(bytes[4..8].try_into().expect("u32 lane")),
        u32::from_le_bytes(bytes[8..12].try_into().expect("u32 lane")),
        u32::from_le_bytes(bytes[12..16].try_into().expect("u32 lane")),
    ]
}

fn u32x4_to_xmm(words: [u32; 4]) -> XmmValue {
    let mut bytes = [0_u8; 16];
    for (index, word) in words.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes_to_xmm(bytes)
}

fn xmm_to_f32x4(value: XmmValue) -> [f32; 4] {
    let bytes = xmm_to_bytes(value);
    [
        f32::from_le_bytes(bytes[0..4].try_into().expect("f32 lane")),
        f32::from_le_bytes(bytes[4..8].try_into().expect("f32 lane")),
        f32::from_le_bytes(bytes[8..12].try_into().expect("f32 lane")),
        f32::from_le_bytes(bytes[12..16].try_into().expect("f32 lane")),
    ]
}

fn f32x4_to_xmm(words: [f32; 4]) -> XmmValue {
    let mut bytes = [0_u8; 16];
    for (index, word) in words.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes_to_xmm(bytes)
}

fn crc32_u64(seed: u32, value: u64) -> u32 {
    let mut crc = !seed;
    for byte in value.to_le_bytes() {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg() & 0xEDB8_8320;
            crc = (crc >> 1) ^ mask;
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xmm_load_and_store_moves_16_bytes_between_memory_locations() {
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        let constant_address = 0x2000;
        let stack_address = 0x8000;
        let payload = XmmValue {
            low: 0x0000_0000_0000_0001,
            high: 0x0000_0002_0000_0020,
        };

        state.set(Register::Rsp, stack_address);
        memory.map_xmm(constant_address, payload);

        execute_ir(
            &mut state,
            &mut memory,
            &[
                IrInstruction::LoadXmm {
                    dst: 0,
                    address: MemoryOperand {
                        base: None,
                        index: None,
                        scale: 1,
                        displacement: constant_address as i32,
                        rip_relative: false,
                        rip_base: 0,
                        segment: None,
                        address_size_32: false,
                    },
                },
                IrInstruction::StoreXmm {
                    src: 0,
                    address: MemoryOperand {
                        base: Some(Register::Rsp),
                        index: None,
                        scale: 1,
                        displacement: 0x10,
                        rip_relative: false,
                        rip_base: 0,
                        segment: None,
                        address_size_32: false,
                    },
                },
            ],
        )
        .expect("execute xmm move ir");

        assert_eq!(memory.read_u64(stack_address + 0x10).expect("low qword"), payload.low);
        assert_eq!(memory.read_u64(stack_address + 0x18).expect("high qword"), payload.high);
    }

    #[test]
    fn decode_and_execute_movaps_then_movups_updates_stack_memory() {
        let start_address = 0x1000;
        let constant_address = 0x1020;
        let displacement = (constant_address as i64 - (start_address as i64 + 7)) as i32;
        let bytes = [
            0x0f,
            0x28,
            0x05,
            displacement as u8,
            (displacement >> 8) as u8,
            (displacement >> 16) as u8,
            (displacement >> 24) as u8,
            0x0f,
            0x11,
            0x44,
            0x24,
            0x10,
        ];
        let payload = XmmValue {
            low: 0x0000_0000_0000_0001,
            high: 0x0000_0002_0000_0020,
        };
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rsp, 0x8000);
        memory.map_bytes(start_address, &bytes);
        memory.map_xmm(constant_address, payload);

        execute_ir(&mut state, &mut memory, &ir).expect("execute raw xmm moves");

        assert_eq!(memory.read_u64(0x8010).expect("low qword"), payload.low);
        assert_eq!(memory.read_u64(0x8018).expect("high qword"), payload.high);
    }

    #[test]
    fn decode_and_execute_scalar_shift_and_imul_sequence_updates_registers() {
        let start_address = 0x2000;
        let bytes = [
            0xC1, 0xEA, 0x05,
            0x83, 0xE2, 0x07,
            0x69, 0xD2, 0x30, 0xF8, 0x00, 0x00,
            0xC1, 0xFA, 0x10,
            0x77, 0x02,
        ];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rdx, 0x40);
        execute_ir(&mut state, &mut memory, &ir[..4]).expect("execute scalar ops");

        assert_eq!(state.get(Register::Rdx), 1);
        assert!(matches!(decode_condition(4).expect("decode ja"), ConditionCode::Above));
    }

    #[test]
    fn decode_and_execute_add_imm32_then_movzx_low_word_updates_register() {
        let start_address = 0x3000;
        let bytes = [
            0x81, 0xC2, 0xB0, 0x36, 0x00, 0x00,
            0x0F, 0xB7, 0xD2,
        ];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rdx, 0x0001_0000);
        execute_ir(&mut state, &mut memory, &ir).expect("execute add imm32 and movzx");

        assert_eq!(state.get(Register::Rdx), 0x36b0);
    }

    #[test]
    fn execute_lea_with_negative_displacement_wraps_instead_of_faulting() {
        let start_address = 0x4000;
        let bytes = [0x44, 0x8D, 0x42, 0x9F];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rdx, 0x4e);
        execute_ir(&mut state, &mut memory, &ir).expect("execute lea");

        assert_eq!(state.get(Register::R8), 0x0000_0000_ffff_ffed);
    }

    #[test]
    fn decode_and_execute_test_r10b_imm8_updates_zero_flag() {
        let start_address = 0x4000;
        let bytes = [0x41, 0xF6, 0xC2, 0x01];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::R10, 0x2);
        execute_ir(&mut state, &mut memory, &ir).expect("execute test r10b, imm8");
        assert!(state.flags.zf);

        state.set(Register::R10, 0x1);
        execute_ir(&mut state, &mut memory, &ir).expect("execute test r10b, imm8");
        assert!(!state.flags.zf);
    }

    #[test]
    fn decode_and_execute_test_r10d_imm32_updates_zero_flag() {
        let start_address = 0x5000;
        let bytes = [0x41, 0xF7, 0xC2, 0x00, 0x01, 0x00, 0x00];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::R10, 0x2);
        execute_ir(&mut state, &mut memory, &ir).expect("execute test r10d, imm32");
        assert!(state.flags.zf);

        state.set(Register::R10, 0x100);
        execute_ir(&mut state, &mut memory, &ir).expect("execute test r10d, imm32");
        assert!(!state.flags.zf);
    }

    #[test]
    fn decode_and_execute_setae_then_or_reg8_updates_byte_registers() {
        let start_address = 0x6000;
        let bytes = [
            0x41, 0x83, 0xF8, 0x0A,
            0x41, 0x0F, 0x93, 0xC1,
            0x41, 0x0F, 0x93, 0xC3,
            0x45, 0x08, 0xCB,
        ];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::R8, 10);
        execute_ir(&mut state, &mut memory, &ir).expect("execute setae/or sequence");

        assert_eq!(state.get(Register::R9) & 0xff, 1);
        assert_eq!(state.get(Register::R11) & 0xff, 1);
    }

    #[test]
    fn decode_and_execute_and_r10b_r9b_then_cmp_preserves_byte_result() {
        let start_address = 0x20b9_661a_179b;
        let bytes = [0x45, 0x20, 0xCA, 0x41, 0x80, 0xFA, 0x01, 0x75, 0x08];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded[..2]).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::R9, 0x1);
        state.set(Register::R10, 0x3);
        execute_ir(&mut state, &mut memory, &ir).expect("execute and/cmp prefix");

        assert_eq!(state.get(Register::R10) & 0xff, 1);
        assert!(state.flags.zf);

        state.set(Register::R9, 0x2);
        state.set(Register::R10, 0x3);
        execute_ir(&mut state, &mut memory, &ir).expect("execute and/cmp prefix with zero result");

        assert_eq!(state.get(Register::R10) & 0xff, 0x2);
        assert!(!state.flags.zf);
    }

    #[test]
    fn decode_and_execute_bt_edx_ecx_then_jae_uses_carry_flag() {
        let start_address = 0x2099_f66b_1989;
        let bytes = [0x0F, 0xA3, 0xCA, 0x73, 0x23];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rdx, 0x100);
        state.set(Register::Rcx, 8);
        execute_ir(&mut state, &mut memory, &ir).expect("execute bt/jcc when tested bit is set");
        assert!(state.flags.cf);
        assert_eq!(state.rip, start_address + 5);

        state.set(Register::Rdx, 0x100);
        state.set(Register::Rcx, 0);
        execute_ir(&mut state, &mut memory, &ir).expect("execute bt/jcc when tested bit is clear");
        assert!(!state.flags.cf);
        assert_eq!(state.rip, start_address + 0x28);
    }

    #[test]
    fn decode_and_execute_and_r13d_imm32_then_jne_uses_zero_flag() {
        let start_address = 0x2057_c70b_1a36;
        let bytes = [0x41, 0x81, 0xE5, 0x00, 0x00, 0x00, 0x80, 0x0F, 0x85, 0x2D, 0xFF, 0xFF, 0xFF];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        let fallthrough = start_address + bytes.len() as u64;
        let taken = ((fallthrough as i128) + i32::from_le_bytes([0x2D, 0xFF, 0xFF, 0xFF]) as i128) as u64;

        state.set(Register::R13, 0xffff_ffff_8000_0001);
        execute_ir(&mut state, &mut memory, &ir).expect("execute and/jne with non-zero result");
        assert_eq!(state.get(Register::R13), 0x8000_0000);
        assert!(!state.flags.zf);
        assert_eq!(state.rip, taken);

        state.set(Register::R13, 0x7fff_ffff);
        execute_ir(&mut state, &mut memory, &ir).expect("execute and/jne with zero result");
        assert_eq!(state.get(Register::R13), 0);
        assert!(state.flags.zf);
        assert_eq!(state.rip, fallthrough);
    }

    #[test]
    fn decode_and_execute_add_ebx_r9d_then_cmp_updates_flags() {
        let start_address = 0x2041_b6b7_216b;
        let bytes = [0x44, 0x01, 0xCB, 0x83, 0xFB, 0x14];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rbx, 10);
        state.set(Register::R9, 10);
        execute_ir(&mut state, &mut memory, &ir).expect("execute add/cmp with equality");
        assert_eq!(state.get(Register::Rbx), 20);
        assert!(state.flags.zf);
        assert!(!state.flags.cf);

        state.set(Register::Rbx, 5);
        state.set(Register::R9, 10);
        execute_ir(&mut state, &mut memory, &ir).expect("execute add/cmp with below result");
        assert_eq!(state.get(Register::Rbx), 15);
        assert!(!state.flags.zf);
        assert!(state.flags.cf);
    }

    #[test]
    fn decode_and_execute_rip_relative_add_ecx_to_memory_updates_memory_and_flags() {
        let start_address = 0x21ab_e554_23eb;
        let bytes = [0x01, 0x0D, 0x33, 0x2D, 0x00, 0x00];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        let target_address = start_address + bytes.len() as u64 + 0x2d33;

        state.set(Register::Rcx, 3);
        memory.map_bytes(target_address, &5_u32.to_le_bytes());

        execute_ir(&mut state, &mut memory, &ir).expect("execute rip-relative add to memory");

        assert_eq!(read_memory_value(&memory, target_address, 4).expect("read dword"), 8);
        assert!(!state.flags.zf);
        assert!(!state.flags.cf);
    }

    #[test]
    fn decode_and_execute_mov_r8b_to_sib_disp8_memory_writes_byte() {
        let start_address = 0x21fc_baa4_218d;
        let bytes = [0x46, 0x88, 0x44, 0x17, 0x40];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rdi, 0x2000);
        state.set(Register::R10, 0x30);
        state.set(Register::R8, 0xABCD);

        execute_ir(&mut state, &mut memory, &ir).expect("execute byte mov store");

        assert_eq!(memory.read_u8(0x2070).expect("read stored byte"), 0xCD);
    }

    #[test]
    fn decode_and_execute_shr_r13d_cl_then_test_and_jz_uses_shifted_value() {
        let start_address = 0x206c_0a30_19b4;
        let bytes = [0x41, 0xD3, 0xED, 0x41, 0xF6, 0xC5, 0x02, 0x74, 0x23];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rcx, 1);
        state.set(Register::R13, 0x4);
        execute_ir(&mut state, &mut memory, &ir).expect("execute shr/test/jz with set bit");
        assert_eq!(state.get(Register::R13), 0x2);
        assert!(!state.flags.zf);
        assert_eq!(state.rip, start_address + 9);

        state.set(Register::Rcx, 1);
        state.set(Register::R13, 0x2);
        execute_ir(&mut state, &mut memory, &ir).expect("execute shr/test/jz with cleared bit");
        assert_eq!(state.get(Register::R13), 0x1);
        assert!(state.flags.zf);
        assert_eq!(state.rip, start_address + 0x2c);
    }

    #[test]
    fn decode_and_execute_or_r9d_edx_zero_extends_result() {
        let start_address = 0x7000;
        let bytes = [0x41, 0x09, 0xD1];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::R9, 0xffff_ffff_0000_0001);
        state.set(Register::Rdx, 0x2);
        execute_ir(&mut state, &mut memory, &ir).expect("execute or r9d, edx");

        assert_eq!(state.get(Register::R9), 0x3);
        assert!(!state.flags.zf);
    }

    #[test]
    fn decode_and_execute_or_ebx_stack_dword_zero_extends_result() {
        let start_address = 0x1912_2493_3e70;
        let bytes = [0x0B, 0x5C, 0x24, 0x28];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rsp, 0x4000);
        state.set(Register::Rbx, 0xffff_ffff_1234_5678);
        memory.map_bytes(0x4028, &0x8000_0000_u32.to_le_bytes());

        execute_ir(&mut state, &mut memory, &ir).expect("execute or ebx, dword ptr [rsp+0x28]");

        assert_eq!(state.get(Register::Rbx), 0x0000_0000_9234_5678);
        assert!(!state.flags.zf);
    }

    #[test]
    fn decode_and_execute_or_stack_dword_ebx_updates_memory() {
        let start_address = 0x1912_2493_5000;
        let bytes = [0x09, 0x5C, 0x24, 0x28];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rsp, 0x5000);
        state.set(Register::Rbx, 0x8000_0001);
        memory.map_bytes(0x5028, &0x1234_5678_u32.to_le_bytes());

        execute_ir(&mut state, &mut memory, &ir).expect("execute or dword ptr [rsp+0x28], ebx");

        assert_eq!(read_memory_value(&memory, 0x5028, 4).expect("updated dword"), 0x9234_5679);
        assert!(!state.flags.zf);
    }

    #[test]
    fn decode_and_execute_inc_edi_preserves_carry_flag() {
        let start_address = 0x8000;
        let bytes = [0xFF, 0xC7];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rdi, 0xffff_ffff_0000_0000);
        state.flags.cf = true;
        execute_ir(&mut state, &mut memory, &ir).expect("execute inc edi");

        assert_eq!(state.get(Register::Rdi), 1);
        assert!(state.flags.cf);
    }

    #[test]
    fn decode_and_execute_jmp_rax_updates_rip() {
        let start_address = 0x1ec5_ec83_1468;
        let bytes = [0xFF, 0xE0];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rax, 0x1ec5_ec83_14ef);

        execute_ir(&mut state, &mut memory, &ir).expect("execute jmp rax");

        assert_eq!(state.rip, 0x1ec5_ec83_14ef);
    }

    #[test]
    fn decode_and_execute_sbb_edi_memory_uses_carry_flag() {
        let start_address = 0x1e95_ea9e_14f1;
        let bytes = [0x1B, 0x3C, 0x00];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rax, 0x2000);
        state.set(Register::Rdi, 0x10);
        state.flags.cf = true;
        memory.map_bytes(0x4000, &5_u32.to_le_bytes());

        execute_ir(&mut state, &mut memory, &ir).expect("execute sbb edi, dword ptr [rax+rax]");

        assert_eq!(state.get(Register::Rdi), 10);
        assert!(!state.flags.cf);
        assert!(!state.flags.zf);
    }

    #[test]
    fn decode_and_execute_adc_ecx_imm8_uses_carry_flag() {
        let start_address = 0x21ba_1574_2718;
        let bytes = [0x83, 0xD1, 0x00];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rcx, u32::MAX as u64);
        state.flags.cf = true;

        execute_ir(&mut state, &mut memory, &ir).expect("execute adc ecx, 0");

        assert_eq!(state.get(Register::Rcx), 0);
        assert!(state.flags.cf);
        assert!(state.flags.zf);
    }

    #[test]
    fn decode_and_execute_or_r10b_imm8_preserves_upper_bits() {
        let start_address = 0x266b_ceb3_2749;
        let bytes = [0x41, 0x80, 0xCA, 0x30];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::R10, 0x1234_5678_9abc_00cd);

        execute_ir(&mut state, &mut memory, &ir).expect("execute or r10b, 0x30");

        assert_eq!(state.get(Register::R10), 0x1234_5678_9abc_00fd);
        assert!(!state.flags.cf);
        assert!(!state.flags.zf);
    }

    #[test]
    fn decode_and_execute_mov_ecx_r8d_zero_extends_to_32_bits() {
        let start_address = 0x2685_c669_275b;
        let bytes = [0x44, 0x89, 0xC1];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::R8, 0x1234_5678_9abc_def0);
        state.set(Register::Rcx, 0xffff_ffff_0000_0000);

        execute_ir(&mut state, &mut memory, &ir).expect("execute mov ecx, r8d");

        assert_eq!(state.get(Register::Rcx), 0x0000_0000_9abc_def0);
    }

    #[test]
    fn execute_decimal_format_loop_body_reduces_ecx_and_emits_digits() {
        let start_address = 0x277f_9d1b_2720;
        let bytes = [
            0xBA, 0xCD, 0xCC, 0xCC, 0xCC,
            0x41, 0x89, 0xC8,
            0x4C, 0x0F, 0xAF, 0xC2,
            0x49, 0xC1, 0xE8, 0x23,
            0x47, 0x8D, 0x0C, 0x00,
            0x47, 0x8D, 0x0C, 0x89,
            0x41, 0x89, 0xCA,
            0x45, 0x29, 0xCA,
            0x41, 0x80, 0xCA, 0x30,
            0x44, 0x88, 0x50, 0x01,
            0x48, 0x83, 0xC0, 0x01,
            0x83, 0xC7, 0x01,
            0x83, 0xF9, 0x09,
            0x44, 0x89, 0xC1,
        ];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        memory.map_bytes(0x5000, &[0; 8]);
        state.set(Register::Rax, 0x5000);
        state.set(Register::Rcx, 35);
        state.set(Register::Rdi, 1);

        execute_ir(&mut state, &mut memory, &ir).expect("execute decimal format body first pass");

        assert_eq!(state.get(Register::Rcx), 3);
        assert_eq!(state.get(Register::Rdi), 2);
        assert_eq!(state.get(Register::Rax), 0x5001);
        assert_eq!(memory.read_u8(0x5001).expect("first digit"), b'5');
        assert!(condition_holds(state.flags, ConditionCode::Above));

        execute_ir(&mut state, &mut memory, &ir).expect("execute decimal format body second pass");

        assert_eq!(state.get(Register::Rcx), 0);
        assert_eq!(state.get(Register::Rdi), 3);
        assert_eq!(state.get(Register::Rax), 0x5002);
        assert_eq!(memory.read_u8(0x5002).expect("second digit"), b'3');
        assert!(!condition_holds(state.flags, ConditionCode::Above));
    }

    #[test]
    fn execute_decimal_format_snippet_loops_and_terminates() {
        let start_address = 0x277f_9d1b_271b;
        let bytes = [
            0x48, 0x8D, 0x44, 0x24, 0x5F,
            0xBA, 0xCD, 0xCC, 0xCC, 0xCC,
            0x41, 0x89, 0xC8,
            0x4C, 0x0F, 0xAF, 0xC2,
            0x49, 0xC1, 0xE8, 0x23,
            0x47, 0x8D, 0x0C, 0x00,
            0x47, 0x8D, 0x0C, 0x89,
            0x41, 0x89, 0xCA,
            0x45, 0x29, 0xCA,
            0x41, 0x80, 0xCA, 0x30,
            0x44, 0x88, 0x50, 0x01,
            0x48, 0x83, 0xC0, 0x01,
            0x83, 0xC7, 0x01,
            0x83, 0xF9, 0x09,
            0x44, 0x89, 0xC1,
            0x77, 0xD0,
            0x0F, 0xB6, 0x08,
            0x88, 0x0E,
            0x48, 0x83, 0xC6, 0x01,
            0x83, 0xC7, 0xFF,
            0x48, 0x83, 0xC0, 0xFF,
            0x83, 0xFF, 0x01,
            0x7F, 0xEB,
            0xC6, 0x06, 0x00,
        ];

        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x7000, &[0; 8]);
        memory.map_bytes(0x8000, &[0; 0x100]);

        state.rip = start_address;
        state.set(Register::Rsp, 0x8000);
        state.set(Register::Rsi, 0x7000);
        state.set(Register::Rcx, 35);
        state.set(Register::Rdi, 1);

        for _ in 0..64 {
            if state.rip == start_address + bytes.len() as u64 {
                break;
            }
            let offset = (state.rip - start_address) as usize;
            let decoded = decode_block(&bytes[offset..], state.rip, GuestArch::X64).expect("decode step");
            let instruction = decoded.first().expect("instruction").clone();
            let fallthrough = state.rip + instruction.size as u64;
            let ir = lower_to_ir(&[instruction]).expect("lower step");
            let previous_rip = state.rip;

            execute_ir(&mut state, &mut memory, &ir).expect("execute step");

            if state.rip == previous_rip {
                state.rip = fallthrough;
            }
        }

        assert_eq!(state.rip, start_address + bytes.len() as u64);
        assert_eq!(memory.read_u8(0x7000).expect("dest[0]"), b'3');
        assert_eq!(memory.read_u8(0x7001).expect("dest[1]"), b'5');
        assert_eq!(memory.read_u8(0x7002).expect("dest terminator"), 0);
    }

    #[test]
    fn decode_and_execute_rip_relative_add_imm8_to_memory_updates_memory_and_flags() {
        let start_address = 0x9000;
        let target_address = 0x9040;
        let displacement = (target_address as i64 - (start_address as i64 + 7)) as i32;
        let bytes = [
            0x83,
            0x05,
            displacement as u8,
            (displacement >> 8) as u8,
            (displacement >> 16) as u8,
            (displacement >> 24) as u8,
            0x01,
        ];
        let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
        let ir = lower_to_ir(&decoded).expect("lower ir");
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        memory.map_bytes(target_address, &5_u32.to_le_bytes());
        execute_ir(&mut state, &mut memory, &ir).expect("execute add dword ptr [rip+disp32], 1");

        assert_eq!(read_memory_value(&memory, target_address, 4).expect("updated dword"), 6);
        assert!(!state.flags.zf);
        assert!(!state.flags.cf);
    }
}