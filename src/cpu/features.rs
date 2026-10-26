use super::*;

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
    pub avx: bool,
    pub avx2: bool,
    pub popcnt: bool,
    pub lzcnt: bool,
    pub bmi1: bool,
    pub bmi2: bool,
    pub x87: bool,
    pub avx512f: bool,
    pub avx512dq: bool,
    pub avx512bw: bool,
    pub avx512vl: bool,
    pub avx512cd: bool,
    pub aes: bool,
    pub sha: bool,
    pub pclmulqdq: bool,
    pub fxsr: bool,
    pub xsave: bool,
    pub osxsave: bool,
    pub rdrand: bool,
    pub rdseed: bool,
    pub adx: bool,
}

/// True when running on Apple Silicon hardware (aarch64 macOS).  Every Apple
/// Silicon Mac carries the ARMv8 NEON AES/SHA/PMULL instructions the JIT
/// lowers AES-NI/SHA/PCLMULQDQ to, so the crypto advertisement is honest
/// exactly on these hosts.
pub(crate) fn is_apple_silicon_host() -> bool {
    cfg!(all(target_arch = "aarch64", target_os = "macos"))
}

impl CpuFeatureSet {
    /// Returns an honest feature set for the given guest architecture.
    ///
    /// Only features with *real* ARMv8 lowering (via JIT NEON emission or
    /// well-tested interpreter paths) are advertised.  AES/SHA/PCLMULQDQ are
    /// advertised only on hosts that guarantee the native ARMv8 NEON crypto
    /// instructions the JIT lowers them to — i.e. Apple Silicon (aarch64
    /// macOS always carries the AES/SHA/PMULL hardware).  On any other host
    /// they are **false** because there is no guarantee of native ARMv8 NEON
    /// crypto instructions at JIT time.
    pub fn for_arch(arch: GuestArch) -> Self {
        let mut features = Self::for_arch_generic(arch);
        if is_apple_silicon_host() {
            // Production and the Apple-Silicon-optimised advertisement agree:
            // the JIT can emit real ARM64 NEON crypto instructions here.
            features.aes = true;
            features.sha = true;
            features.pclmulqdq = true;
        }
        features
    }

    /// Core feature set before host-crypto advertisement is applied.
    fn for_arch_generic(arch: GuestArch) -> Self {
        Self {
            baseline_x86_64: arch == GuestArch::X64,
            sse2: true,
            sse3: true,
            ssse3: true,
            sse41: true,
            sse42: true,
            avx: true,
            avx2: true,
            popcnt: true,
            lzcnt: true,
            bmi1: true,
            bmi2: true,
            x87: true,
            // AVX-512: EVEX decode, ZMM register file, vector arithmetic ops (AddPacked etc.),
            // mask register ops (Kand/Kor/etc.), and FMA are fully implemented in execute_ir.
            avx512f: true,
            avx512dq: true,
            avx512bw: true,
            avx512vl: true,
            avx512cd: true,
            // HONEST: AES-NI is implemented via software interpretation but ARMv8 NEON
            // lowering is NOT guaranteed on non-Apple-Silicon hosts → false
            aes: false,
            // HONEST: SHA is implemented via software interpretation but ARMv8 NEON
            // lowering is NOT guaranteed on non-Apple-Silicon hosts → false
            sha: false,
            // HONEST: PCLMULQDQ is implemented via software interpretation but ARMv8
            // NEON PMULL lowering is NOT guaranteed on non-Apple-Silicon hosts → false
            pclmulqdq: false,
            // FXSAVE/FXRSTOR are implemented in the interpreter (state serialization).
            fxsr: true,
            // XSAVE/XRSTOR are implemented in the interpreter (x87+SSE+AVX state).
            xsave: true,
            // OS XSAVE support is advertised since XSAVE/XRSTOR work.
            osxsave: true,
            // RDRAND/RDSEED are implemented via the host CSPRNG (getrandom).
            rdrand: true,
            rdseed: true,
            adx: true,
        }
    }

    /// Returns an Apple Silicon-optimised feature set where AES/SHA/PCLMULQDQ
    /// are advertised because the JIT can emit real ARM64 NEON crypto
    /// instructions.  Routes through [`CpuFeatureSet::for_arch`] so the
    /// advertised flags never drift from the production path.
    pub fn for_apple_silicon() -> Self {
        let mut features = Self::for_arch(GuestArch::X64);
        // Explicitly request the Apple-Silicon advertisement regardless of
        // the host this binary happens to run on (the caller asked for it).
        features.aes = true;
        features.sha = true;
        features.pclmulqdq = true;
        features
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
            "avx" => self.avx = enabled,
            "avx2" => self.avx2 = enabled,
            "popcnt" => self.popcnt = enabled,
            "lzcnt" | "abm" => self.lzcnt = enabled,
            "bmi1" => self.bmi1 = enabled,
            "bmi2" => self.bmi2 = enabled,
            "x87" => self.x87 = enabled,
            "avx512f" | "avx512_f" => self.avx512f = enabled,
            "avx512dq" | "avx512_dq" => self.avx512dq = enabled,
            "avx512bw" | "avx512_bw" => self.avx512bw = enabled,
            "avx512vl" | "avx512_vl" => self.avx512vl = enabled,
            "avx512cd" | "avx512_cd" => self.avx512cd = enabled,
            "aes" | "aes_ni" => self.aes = enabled,
            "sha" => self.sha = enabled,
            "pclmulqdq" | "pclmul" => self.pclmulqdq = enabled,
            "fxsr" | "fxsave" => self.fxsr = enabled,
            "xsave" => self.xsave = enabled,
            "osxsave" => self.osxsave = enabled,
            "rdrand" => self.rdrand = enabled,
            "rdseed" => self.rdseed = enabled,
            "adx" => self.adx = enabled,
            other => {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("unknown CPU feature {other}"),
                ));
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
            (self.avx, "avx"),
            (self.avx2, "avx2"),
            (self.popcnt, "popcnt"),
            (self.lzcnt, "lzcnt"),
            (self.bmi1, "bmi1"),
            (self.bmi2, "bmi2"),
            (self.x87, "x87"),
            (self.avx512f, "avx512f"),
            (self.avx512dq, "avx512dq"),
            (self.avx512bw, "avx512bw"),
            (self.avx512vl, "avx512vl"),
            (self.avx512cd, "avx512cd"),
            (self.aes, "aes"),
            (self.sha, "sha"),
            (self.pclmulqdq, "pclmulqdq"),
            (self.fxsr, "fxsr"),
            (self.xsave, "xsave"),
            (self.osxsave, "osxsave"),
            (self.rdrand, "rdrand"),
            (self.rdseed, "rdseed"),
            (self.adx, "adx"),
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
            dbt_flags.extend(
                profile
                    .dbt_flags
                    .iter()
                    .map(|value| value.to_ascii_lowercase()),
            );
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

    /// Returns an honest XCR0 value based on what is actually implemented.
    ///
    /// XCR0: the state components enabled for XSAVE/XRSTOR.
    ///
    /// XCR0 bit assignment:
    ///   Bit 0 (x87):         always enabled
    ///   Bit 1 (SSE):         always enabled
    ///   Bit 2 (AVX):         enabled if `features.avx` is set (YMM upper halves)
    ///   Bits 3-4 (MPX):      never enabled (not implemented)
    ///   Bits 5+ (AVX-512 OPMASK/ZMM, PKRU, CET, ...): never enabled — the
    ///         XSAVE area serializes only x87/SSE/AVX, so no other component
    ///         may be claimed. XCR0 is masked to the serialized layout so
    ///         XSTATE_BV can never announce state that is not saved.
    pub fn xcr0(&self) -> u64 {
        let mut val = 0x3_u64; // x87 (bit 0) + SSE (bit 1) – always present
        if self.features.avx {
            val |= 0x4; // YMM upper halves (bit 2)
        }
        val & XSAVE_SUPPORTED_STATE
    }

    pub fn leaf(&self, leaf: u32, subleaf: u32) -> CpuidLeaf {
        match (leaf, subleaf) {
            (0, 0) => CpuidLeaf {
                eax: 0xD,
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
                if self.features.pclmulqdq {
                    ecx |= 1 << 1;
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
                if self.features.fxsr {
                    ecx |= 1 << 24;
                }
                if self.features.aes {
                    ecx |= 1 << 25;
                }
                if self.features.avx {
                    // The original code set these bits together: when AVX is present,
                    // XSAVE (bit 26) and OSXSAVE (bit 27) are also reported as available,
                    // since real hardware always enables them together.
                    ecx |= 1 << 26; // XSAVE
                    ecx |= 1 << 27; // OSXSAVE
                    ecx |= 1 << 28; // AVX
                }
                if self.features.rdrand {
                    ecx |= 1 << 30;
                }
                if self.features.x87 {
                    edx |= 1 << 0;
                }
                if self.features.sse2 {
                    edx |= 1 << 26;
                }
                CpuidLeaf {
                    eax: if self.arch == GuestArch::X64 {
                        0x0003_06A9
                    } else {
                        0x0001_06A9
                    },
                    ebx: 0,
                    ecx,
                    edx,
                }
            }
            (7, 0) => {
                let mut ebx = 0_u32;
                let ecx = 0_u32;
                let edx = 0_u32;
                if self.features.bmi1 {
                    ebx |= 1 << 3;
                }
                if self.features.avx2 {
                    ebx |= 1 << 5;
                }
                if self.features.bmi2 {
                    ebx |= 1 << 8;
                }
                // AVX-512 feature flags (leaf 7, EBX)
                if self.features.avx512f {
                    ebx |= 1 << 16; // AVX512F
                }
                if self.features.avx512dq {
                    ebx |= 1 << 17; // AVX512DQ
                }
                if self.features.rdseed {
                    ebx |= 1 << 18; // RDSEED
                }
                if self.features.adx {
                    ebx |= 1 << 19; // ADX
                }
                if self.features.avx512cd {
                    ebx |= 1 << 28; // AVX512CD
                }
                if self.features.sha {
                    ebx |= 1 << 29; // SHA
                }
                if self.features.avx512bw {
                    ebx |= 1 << 30; // AVX512BW
                }
                if self.features.avx512vl {
                    ebx |= 1 << 31; // AVX512VL
                }
                CpuidLeaf {
                    eax: 0,
                    ebx,
                    ecx,
                    edx,
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
            (0xD, 0) => {
                // Sub-leaf 0: XCR0 (the serialized component mask) and the
                // total XSAVE area size matching the actual serialized
                // layout: 512-byte legacy region + 64-byte header +
                // 256-byte AVX YMM region (when AVX is enabled) = 832 bytes.
                // Software derives the sub-leaf count from the highest XCR0
                // bit, which is 3 for the serialized components (sub-leaves
                // 0..=2: XCR0/size, instruction support, AVX).
                let xsa_size = if self.features.avx {
                    832
                } else {
                    576 // 512 legacy + 64 header
                };
                CpuidLeaf {
                    eax: self.xcr0() as u32,
                    ebx: xsa_size,
                    ecx: xsa_size,
                    edx: (self.xcr0() >> 32) as u32,
                }
            }
            (0xD, 1) => {
                // Sub-leaf 1: XSAVE-family instruction support. Bit 0
                // (XSAVEOPT) is advertised because the emulator implements
                // it (0F AE /6, full-save semantics). XSAVEC, XGETBV1 and
                // XSAVES are not implemented and are not advertised.
                CpuidLeaf {
                    eax: 0b001,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                }
            }
            (0xD, 2) => {
                // Sub-leaf 2: AVX YMM upper-half component — 256 bytes at
                // offset 576, matching the XSAVE area written by the
                // interpreter. ECX bit 0 = enabled in XCR0.
                let in_use = u32::from(self.features.avx);
                CpuidLeaf {
                    eax: 256,
                    ebx: 576,
                    ecx: in_use,
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

pub(crate) fn normalize_feature_name(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(['.', '-', ' '], "_")
}

pub(crate) fn parse_bool(value: &str) -> AppResult<bool> {
    match value {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("invalid boolean value {other}"),
        )),
    }
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

pub(crate) fn hex_digit(value: u8) -> char {
    match value & 0x0f {
        0..=9 => (b'0' + (value & 0x0f)) as char,
        other => (b'a' + (other - 10)) as char,
    }
}
