use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Flags {
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
}

// ---------------------------------------------------------------------------
// Lazy x86 flag materialisation
// ---------------------------------------------------------------------------
//
// The interpreter used to compute the full x86 flag set eagerly after every
// arithmetic instruction, even when the next instructions overwrote the flags
// before ever reading them.  Instead, an ALU result is *parked* in
// `CpuState::pending_flags`; the six flags are computed on the first read
// (conditional branch, pushf, adc/sbb, ...) or when the block ends.  Parking
// costs a few stores; evaluating costs a parity fold plus a handful of
// comparisons, so chains of flag-dead ALU ops (the common case in compiled
// guest code) get materially cheaper.

/// Arithmetic operation whose flag set is parked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlagOp {
    Add,
    Sub,
    Logic,
}

/// A flag computation that has been deferred: the operands, width-masked
/// result, and the operation that produced it.  `CpuState::flags` is stale
/// while this is `Some`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingFlags {
    pub(crate) lhs: u64,
    pub(crate) rhs: u64,
    pub(crate) result: u64,
    pub(crate) op: FlagOp,
    pub(crate) width_bits: u8,
}

impl PendingFlags {
    #[inline]
    pub(crate) fn evaluate(self) -> Flags {
        match self.op {
            FlagOp::Add => add_flags(self.lhs, self.rhs, self.result, self.width_bits as usize),
            FlagOp::Sub => sub_flags(self.lhs, self.rhs, self.result, self.width_bits as usize),
            FlagOp::Logic => logic_flags(self.result, self.width_bits as usize),
        }
    }
}

/// Per-execution lazy-flag counters, flushed to the global telemetry
/// atomics once at the end of `execute_ir_with_hashing`.  Keeping the
/// counters in plain locals keeps the hot path free of atomic operations.
/// `deferred` is derived as `materialised + skipped` (every parked flag set
/// is either computed later or discarded when overwritten), so parking a
/// flag costs no counter update in the common case.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LazyFlagStats {
    pub materialised: u64,
    pub skipped: u64,
}

/// Number of ALU results whose flags were parked instead of computed eagerly.
pub static LAZY_FLAGS_DEFERRED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Number of parked flag sets computed on demand (first flag read / block end).
pub static LAZY_FLAGS_MATERIALISED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// Number of parked flag sets discarded without computation because a later
/// flag producer overwrote them first — the eager work that was skipped.
pub static LAZY_FLAGS_SKIPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Snapshot of the lazy-flag counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LazyFlagTelemetry {
    pub deferred: u64,
    pub materialised: u64,
    pub skipped: u64,
}

/// Read the current lazy-flag materialisation counters.
pub fn lazy_flag_telemetry() -> LazyFlagTelemetry {
    use std::sync::atomic::Ordering;
    LazyFlagTelemetry {
        deferred: LAZY_FLAGS_DEFERRED.load(Ordering::Relaxed),
        materialised: LAZY_FLAGS_MATERIALISED.load(Ordering::Relaxed),
        skipped: LAZY_FLAGS_SKIPPED.load(Ordering::Relaxed),
    }
}

/// Reset the lazy-flag materialisation counters (test/diagnostic helper).
pub fn reset_lazy_flag_telemetry() {
    use std::sync::atomic::Ordering;
    LAZY_FLAGS_DEFERRED.store(0, Ordering::Relaxed);
    LAZY_FLAGS_MATERIALISED.store(0, Ordering::Relaxed);
    LAZY_FLAGS_SKIPPED.store(0, Ordering::Relaxed);
}

pub(crate) fn flush_lazy_flag_stats(stats: LazyFlagStats) {
    use std::sync::atomic::Ordering;
    // Every parked flag set is later materialised or discarded; the total is
    // therefore derivable without touching a counter on the hot path.
    let deferred = stats.materialised + stats.skipped;
    if deferred != 0 {
        LAZY_FLAGS_DEFERRED.fetch_add(deferred, Ordering::Relaxed);
    }
    if stats.materialised != 0 {
        LAZY_FLAGS_MATERIALISED.fetch_add(stats.materialised, Ordering::Relaxed);
    }
    if stats.skipped != 0 {
        LAZY_FLAGS_SKIPPED.fetch_add(stats.skipped, Ordering::Relaxed);
    }
}

pub(crate) const EFLAGS_CF: u64 = 1 << 0;
pub(crate) const EFLAGS_PF: u64 = 1 << 2;
pub(crate) const EFLAGS_AF: u64 = 1 << 4;
pub(crate) const EFLAGS_ZF: u64 = 1 << 6;
pub(crate) const EFLAGS_SF: u64 = 1 << 7;
pub(crate) const EFLAGS_OF: u64 = 1 << 11;
pub(crate) const EFLAGS_ALWAYS_SET: u64 = 1 << 1;
pub(crate) const EFLAGS_ARITHMETIC_MASK: u64 =
    EFLAGS_CF | EFLAGS_PF | EFLAGS_AF | EFLAGS_ZF | EFLAGS_SF | EFLAGS_OF;

pub(crate) fn pack_eflags(state: &CpuState) -> u64 {
    let mut value =
        EFLAGS_ALWAYS_SET | (state.eflags_extra & !(EFLAGS_ARITHMETIC_MASK | EFLAGS_ALWAYS_SET));
    if state.flags.cf {
        value |= EFLAGS_CF;
    }
    if state.flags.pf {
        value |= EFLAGS_PF;
    }
    if state.flags.af {
        value |= EFLAGS_AF;
    }
    if state.flags.zf {
        value |= EFLAGS_ZF;
    }
    if state.flags.sf {
        value |= EFLAGS_SF;
    }
    if state.flags.of {
        value |= EFLAGS_OF;
    }
    value
}

pub(crate) fn unpack_eflags(state: &mut CpuState, value: u64) {
    // The popped flags supersede any parked arithmetic computation.
    state.pending_flags = None;
    state.flags.cf = value & EFLAGS_CF != 0;
    state.flags.pf = value & EFLAGS_PF != 0;
    state.flags.af = value & EFLAGS_AF != 0;
    state.flags.zf = value & EFLAGS_ZF != 0;
    state.flags.sf = value & EFLAGS_SF != 0;
    state.flags.of = value & EFLAGS_OF != 0;
    state.eflags_extra = value & !(EFLAGS_ARITHMETIC_MASK | EFLAGS_ALWAYS_SET);
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConditionCode {
    Equal,
    NotEqual,
    Overflow,
    NotOverflow,
    Below,
    NotBelow,
    Above,
    NotAbove,
    Sign,
    NotSign,
    Less,
    GreaterEqual,
    LessEqual,
    Greater,
    Parity,
    NotParity,
}

/// Evaluate an x86 condition code against the current flags.  Used by the JIT
/// dispatcher's EXIT_COND_BRANCH handler to decide whether a conditional jump
/// is taken (the JIT block emits EXIT_COND_BRANCH because it can't easily read
/// the Flags field offset from native code).
pub fn evaluate_condition(condition: ConditionCode, flags: &Flags) -> bool {
    match condition {
        ConditionCode::Equal => flags.zf,
        ConditionCode::NotEqual => !flags.zf,
        ConditionCode::Overflow => flags.of,
        ConditionCode::NotOverflow => !flags.of,
        ConditionCode::Below => flags.cf,                // CF=1
        ConditionCode::NotBelow => !flags.cf,            // CF=0
        ConditionCode::Above => !flags.cf && !flags.zf,  // CF=0 and ZF=0
        ConditionCode::NotAbove => flags.cf || flags.zf, // CF=1 or ZF=1
        ConditionCode::Sign => flags.sf,
        ConditionCode::NotSign => !flags.sf,
        ConditionCode::Less => flags.sf != flags.of, // SF != OF
        ConditionCode::GreaterEqual => flags.sf == flags.of, // SF == OF
        ConditionCode::LessEqual => flags.zf || flags.sf != flags.of,
        ConditionCode::Greater => !flags.zf && flags.sf == flags.of,
        ConditionCode::Parity => flags.pf,
        ConditionCode::NotParity => !flags.pf,
    }
}

pub(crate) fn condition_holds(flags: Flags, condition: ConditionCode) -> bool {
    match condition {
        ConditionCode::Equal => flags.zf,
        ConditionCode::NotEqual => !flags.zf,
        ConditionCode::Overflow => flags.of,
        ConditionCode::NotOverflow => !flags.of,
        ConditionCode::Below => flags.cf,
        ConditionCode::NotBelow => !flags.cf,
        ConditionCode::Above => !flags.cf && !flags.zf,
        ConditionCode::NotAbove => flags.cf || flags.zf,
        ConditionCode::Sign => flags.sf,
        ConditionCode::NotSign => !flags.sf,
        ConditionCode::Less => flags.sf != flags.of,
        ConditionCode::GreaterEqual => flags.sf == flags.of,
        ConditionCode::LessEqual => flags.zf || (flags.sf != flags.of),
        ConditionCode::Greater => !flags.zf && (flags.sf == flags.of),
        ConditionCode::Parity => flags.pf,
        ConditionCode::NotParity => !flags.pf,
    }
}

pub(crate) fn add_flags(lhs: u64, rhs: u64, result: u64, width: usize) -> Flags {
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

pub(crate) fn adc_flags(lhs: u64, rhs: u64, carry: u64, result: u64, width: usize) -> Flags {
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

pub(crate) fn sub_flags(lhs: u64, rhs: u64, result: u64, width: usize) -> Flags {
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

pub(crate) fn sbb_flags(lhs: u64, rhs: u64, borrow: u64, result: u64, width: usize) -> Flags {
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

pub(crate) fn signed_value(value: u64, width: usize) -> i128 {
    let sign_bit = 1_u64 << (width - 1);
    if value & sign_bit != 0 {
        value as i128 - (1_i128 << width)
    } else {
        value as i128
    }
}

pub(crate) fn logic_flags(result: u64, width: usize) -> Flags {
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

pub(crate) fn parity(value: u8) -> bool {
    value.count_ones().is_multiple_of(2)
}

pub(crate) fn bit_deposit(mut source: u64, mut mask: u64) -> u64 {
    let mut result = 0_u64;
    while mask != 0 {
        let lowest = mask.isolate_lowest_one();
        if source & 1 != 0 {
            result |= lowest;
        }
        source >>= 1;
        mask &= mask - 1;
    }
    result
}

pub(crate) fn bit_extract(source: u64, mut mask: u64) -> u64 {
    let mut result = 0_u64;
    let mut bit = 0_u32;
    while mask != 0 {
        let lowest = mask.isolate_lowest_one();
        if source & lowest != 0 {
            result |= 1_u64 << bit;
        }
        mask &= mask - 1;
        bit += 1;
    }
    result
}
