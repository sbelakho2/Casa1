use super::*;

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

// === FXSAVE/FXRSTOR/XSAVE/XRSTOR state serialization helpers ===

/// Convert an IEEE-754 double into an 80-bit x87 extended-precision value.
/// Returns `(sign_exp, mantissa)` where `sign_exp` is the 16-bit sign+exponent
/// word and `mantissa` is the 64-bit significand including the explicit
/// integer bit (bit 63).
pub(crate) fn f64_to_f80(value: f64) -> (u16, u64) {
    let bits = value.to_bits();
    let sign = ((bits >> 63) & 1) as u16;
    let exp = ((bits >> 52) & 0x7ff) as i32;
    let frac = bits & 0x000f_ffff_ffff_ffff;
    if exp == 0x7ff {
        // Infinity or NaN: integer bit set, fraction carried up.
        let ext_mant = 0x8000_0000_0000_0000u64 | (frac << 11);
        return ((sign << 15) | 0x7fff, ext_mant);
    }
    if exp == 0 && frac == 0 {
        // Signed zero.
        return (sign << 15, 0);
    }
    let (ext_exp, ext_mant) = if exp == 0 {
        // Subnormal double: normalize so the leading 1 sits at bit 63.
        let lz = frac.leading_zeros();
        let ext_mant = frac << lz;
        let ext_exp = (15372 - lz as i32) as u16;
        (ext_exp, ext_mant)
    } else {
        // Normal double: explicit integer bit + 52-bit fraction shifted up by 11.
        let ext_mant = (1u64 << 63) | (frac << 11);
        let ext_exp = (exp + 15360) as u16;
        (ext_exp, ext_mant)
    };
    ((sign << 15) | (ext_exp & 0x7fff), ext_mant)
}

/// Convert an 80-bit x87 extended-precision value back into an IEEE-754 double.
/// `sign_exp` is the 16-bit sign+exponent word; `mant` is the 64-bit significand
/// (including the explicit integer bit). The result is rounded to double
/// precision, matching the precision of the modeled x87 stack.
pub(crate) fn f80_to_f64(sign_exp: u16, mant: u64) -> f64 {
    let sign = (sign_exp >> 15) & 1;
    let exp = (sign_exp & 0x7fff) as i32;
    let magnitude = if exp == 0x7fff {
        let frac = mant & 0x7fff_ffff_ffff_ffff;
        if frac == 0 { f64::INFINITY } else { f64::NAN }
    } else if exp == 0 && mant == 0 {
        0.0
    } else {
        // value = mant * 2^(exp - bias - 63). Exact for doubles, with powi
        // overflowing to INF or underflowing to 0/subnormal as appropriate.
        (mant as f64) * 2f64.powi(exp - 16383 - 63)
    };
    if sign == 1 { -magnitude } else { magnitude }
}

/// Encode the x87 status word. The top-of-stack pointer is fixed at 0 (the
/// modeled stack stores ST(0) at slot 0), and the carried exception flags map
/// to the divide-by-zero and precision status bits.
pub(crate) fn x87_status_word(state: &CpuState) -> u16 {
    let mut sw = 0u16;
    if state.x87.divide_by_zero {
        sw |= 1 << 2; // ZE
    }
    if state.x87.precision {
        sw |= 1 << 5; // PE
    }
    sw
}

/// Write the 512-byte legacy FXSAVE area (x87 + SSE state) at `base`.
pub(crate) fn fxsave_to_memory(
    state: &CpuState,
    memory: &mut MemoryImage,
    base: u64,
) -> AppResult<()> {
    // Control/status/tag/opcode header.
    write_memory_value(memory, base, x87_control_word(&state.x87) as u64, 2)?;
    write_memory_value(memory, base + 2, x87_status_word(state) as u64, 2)?;

    // Abridged tag word (Intel/AMD spec): bit i set (=1) if ST(i) is EMPTY,
    // cleared (=0) if ST(i) is non-empty (Valid, Zero, or Special).
    let depth = state.x87.stack.len().min(8);
    let ftw = if depth >= 8 {
        0u8 // all registers non-empty
    } else {
        (!0u8) << depth // bits 0..depth-1 = 0 (non-empty), bits depth..7 = 1 (empty)
    };
    write_memory_value(memory, base + 4, ftw as u64, 1)?;
    write_memory_value(memory, base + 5, 0, 1)?; // reserved
    write_memory_value(memory, base + 6, 0, 2)?; // FOP
    write_memory_value(memory, base + 8, 0, 8)?; // FIP / FCS
    write_memory_value(memory, base + 16, 0, 8)?; // FDP / FDS

    // MXCSR and its mask. MXCSR_MASK advertises the writable MXCSR bits;
    // both FXSAVE/XSAVE write it and FXRSTOR/XRSTOR restore MXCSR through it
    // (non-writable bits keep their previous value), mirroring real hardware.
    write_memory_value(memory, base + 24, state.mxcsr as u64, 4)?;
    write_memory_value(memory, base + 28, MXCSR_MASK as u64, 4)?;

    // ST(0)..ST(7) as 80-bit extended values (16-byte slots).
    for i in 0..8 {
        let slot = base + 32 + (i as u64) * 16;
        let value = if i < depth {
            state.x87.stack[depth - 1 - i]
        } else {
            0.0
        };
        let (sign_exp, mant) = f64_to_f80(value);
        write_memory_value(memory, slot, mant, 8)?;
        write_memory_value(memory, slot + 8, sign_exp as u64, 2)?;
        write_memory_value(memory, slot + 10, 0, 2)?;
        write_memory_value(memory, slot + 12, 0, 4)?;
    }

    // XMM0..XMM15 (16-byte slots).
    for i in 0..16 {
        let slot = base + 160 + (i as u64) * 16;
        write_memory_value(memory, slot, state.xmm[i].low, 8)?;
        write_memory_value(memory, slot + 8, state.xmm[i].high, 8)?;
    }

    Ok(())
}

/// Restore CPU state from a 512-byte legacy FXSAVE area at `base`.
pub(crate) fn fxrstor_from_memory(
    state: &mut CpuState,
    memory: &MemoryImage,
    base: u64,
) -> AppResult<()> {
    let fcw = read_memory_value(memory, base, 2)? as u16;
    let fsw = read_memory_value(memory, base + 2, 2)? as u16;
    let ftw = read_memory_value(memory, base + 4, 1)? as u8;

    // Rounding control from FCW bits 10-11.
    state.x87.rounding_mode = match (fcw >> 10) & 0x3 {
        0 => X87RoundingMode::Nearest,
        1 => X87RoundingMode::Down,
        2 => X87RoundingMode::Up,
        _ => X87RoundingMode::TowardZero,
    };
    state.x87.divide_by_zero = (fsw & (1 << 2)) != 0;
    state.x87.precision = (fsw & (1 << 5)) != 0;

    // Rebuild the x87 stack with ST(0) on top.
    // Abridged tag: bit=0 means non-empty, bit=1 means empty.
    let mut stack = Vec::new();
    for i in (0..8usize).rev() {
        if ftw & (1 << i) == 0 {
            let slot = base + 32 + (i as u64) * 16;
            let mant = read_memory_value(memory, slot, 8)?;
            let sign_exp = read_memory_value(memory, slot + 8, 2)? as u16;
            stack.push(f80_to_f64(sign_exp, mant));
        }
    }
    state.x87.stack = stack;

    // MXCSR: only the writable bits (per MXCSR_MASK) are restored; reserved
    // bits keep their previous value, as on real hardware.
    let saved_mxcsr = read_memory_value(memory, base + 24, 4)? as u32;
    state.mxcsr = (saved_mxcsr & MXCSR_MASK) | (state.mxcsr & !MXCSR_MASK);

    // XMM0..XMM15.
    for i in 0..16 {
        let slot = base + 160 + (i as u64) * 16;
        state.xmm[i].low = read_memory_value(memory, slot, 8)?;
        state.xmm[i].high = read_memory_value(memory, slot + 8, 8)?;
    }

    Ok(())
}

/// MXCSR writable-bit mask. Emulator and guest agree on 0x0000_FFFF (every
/// MXCSR bit is writable in this implementation).
pub(crate) const MXCSR_MASK: u32 = 0x0000_FFFF;

/// State components the emulator actually serializes in the XSAVE area.
///
/// XCR0/XSTATE_BV bit assignment for the serialized layout:
///   Bit 0 (x87):   the 512-byte legacy region's x87 area (offset 0, 160 bytes)
///   Bit 1 (SSE):   the legacy region's XMM area (offset 160, 256 bytes)
///   Bit 2 (AVX):   YMM upper halves (offset 576, 256 bytes)
/// No other components (MPX, PKRU, CET, AVX-512 OPMASK/ZMM, ...) are
/// serialized, so no other XCR0/XSTATE_BV bits are ever claimed.
pub(crate) const XSAVE_SUPPORTED_STATE: u64 = 0b111;

/// XSAVE/XRSTOR require the memory operand to be 64-byte aligned.
pub(crate) fn require_xsave_alignment(base: u64) -> AppResult<()> {
    if !base.is_multiple_of(64) {
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            format!("XSAVE/XRSTOR memory operand {base:#x} is not 64-byte aligned"),
        ));
    }
    Ok(())
}

/// Write an XSAVE area for exactly the state components in `requested`
/// (masked by the supported-state mask): the 512-byte legacy region (x87 +
/// SSE), the 64-byte XSAVE header, and the AVX YMM region.
///
/// XSTATE_BV announces exactly the components written: bit 0 = x87, bit 1 =
/// SSE, bit 2 = AVX — no other bits, because no other state is serialized.
pub(crate) fn xsave_to_memory(
    state: &CpuState,
    memory: &mut MemoryImage,
    base: u64,
    requested: u64,
) -> AppResult<()> {
    require_xsave_alignment(base)?;
    // Requesting a component the processor does not support is a #GP on real
    // hardware; the emulator surfaces it as an error instead.
    if requested & !XSAVE_SUPPORTED_STATE != 0 {
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            format!(
                "XSAVE requested mask {requested:#x} includes unsupported state \
                 components (supported: {XSAVE_SUPPORTED_STATE:#x})"
            ),
        ));
    }
    // XSAVE only touches the components whose bits are set in the mask.
    let mask = requested & XSAVE_SUPPORTED_STATE;

    // Legacy x87 + SSE region (bits 0 and 1).
    if mask & 0b11 != 0 {
        fxsave_to_memory(state, memory, base)?;
    }

    // XSAVE header at offset 512: XSTATE_BV / XCOMP_BV / reserved.
    // XSTATE_BV announces exactly the components written above.
    write_memory_value(memory, base + 512, mask, 8)?;
    write_memory_value(memory, base + 520, 0, 8)?; // XCOMP_BV (standard format)
    for off in (528..576).step_by(8) {
        write_memory_value(memory, base + off, 0, 8)?; // reserved header bytes
    }

    // Bit 2 (AVX): YMM upper 128 bits at offset 576 (16 registers).
    if mask & 0b100 != 0 {
        for i in 0..16 {
            let slot = base + 576 + (i as u64) * 16;
            write_memory_value(memory, slot, state.ymm_upper[i].low, 8)?;
            write_memory_value(memory, slot + 8, state.ymm_upper[i].high, 8)?;
        }
    }

    Ok(())
}

/// Restore CPU state from an XSAVE area, honoring the XSTATE_BV bitmap.
///
/// Only components enabled in the supported-state mask are restored; bits
/// for unsupported components are ignored (as on real hardware, where
/// XRSTOR ignores XSTATE_BV bits not enabled in XCR0).
pub(crate) fn xrstor_from_memory(
    state: &mut CpuState,
    memory: &MemoryImage,
    base: u64,
) -> AppResult<()> {
    require_xsave_alignment(base)?;
    let xcomp_bv = read_memory_value(memory, base + 520, 8)?;
    if xcomp_bv != 0 {
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            "XRSTOR: XCOMP_BV is nonzero (compacted format) but XCR0.B[63] \
             is not set; compacted format is unsupported",
        ));
    }
    let xstate_bv = read_memory_value(memory, base + 512, 8)? & XSAVE_SUPPORTED_STATE;

    // Bits 0 (x87) and 1 (SSE) live in the legacy region.
    if xstate_bv & 0b11 != 0 {
        fxrstor_from_memory(state, memory, base)?;
    }

    // Bit 2 (AVX): YMM upper halves at offset 576.
    if xstate_bv & 0b100 != 0 {
        for i in 0..16 {
            let slot = base + 576 + (i as u64) * 16;
            state.ymm_upper[i].low = read_memory_value(memory, slot, 8)?;
            state.ymm_upper[i].high = read_memory_value(memory, slot + 8, 8)?;
        }
    }

    Ok(())
}

pub(crate) fn apply_rounding(value: f64, mode: X87RoundingMode) -> f64 {
    match mode {
        X87RoundingMode::Nearest => value,
        X87RoundingMode::Down => value.floor(),
        X87RoundingMode::Up => value.ceil(),
        X87RoundingMode::TowardZero => value.trunc(),
    }
}

pub(crate) fn x87_control_word(state: &X87State) -> u16 {
    let rounding_bits = match state.rounding_mode {
        X87RoundingMode::Nearest => 0x0000,
        X87RoundingMode::Down => 0x0400,
        X87RoundingMode::Up => 0x0800,
        X87RoundingMode::TowardZero => 0x0c00,
    };
    0x037f | rounding_bits
}

/// Convert an 80-bit x87 extended-precision float (10 bytes, 1:15:64 format)
/// to a standard f64 (1:11:52 format).
///
/// `raw_mantissa` is the low 8 bytes (bits 63-0 = 64-bit mantissa with explicit integer bit).
/// `raw_high` is the high 2 bytes: bit 15 = sign, bits 14-0 = exponent (bias 16383).
pub(crate) fn x87_extended_to_f64(raw_mantissa: u64, raw_high: u16) -> f64 {
    let sign = (raw_high >> 15) & 0x1;
    let x87_exp = (raw_high & 0x7FFF) as i32;
    // Full 64-bit mantissa field: bit 63 = integer bit, bits 62-0 = fraction
    let x87_mantissa = raw_mantissa;

    if x87_exp == 0x7FFF {
        // NaN or Infinity
        if x87_mantissa == 0 {
            // Infinity
            if sign == 0 {
                f64::INFINITY
            } else {
                f64::NEG_INFINITY
            }
        } else {
            // NaN
            f64::NAN
        }
    } else if x87_exp == 0 {
        // Zero or denormal
        if x87_mantissa == 0 {
            0.0
        } else {
            // Denormal — for simplicity, round to zero
            0.0
        }
    } else {
        // Normal number: value = (-1)^sign * 2^(x87_exp-16383) * 1.mantissa
        // Extract 63-bit fraction from mantissa bits [62:0], then narrow to 52 bits for f64
        let f64_exp = x87_exp - 16383 + 1023;
        let x87_fraction = x87_mantissa & 0x7FFF_FFFF_FFFF_FFFF; // 63 bits
        let f64_fraction = x87_fraction >> 11; // 63 -> 52 bits (drop 11 LSBs)

        if f64_exp >= 2047 {
            // Overflow to infinity
            if sign == 0 {
                f64::INFINITY
            } else {
                f64::NEG_INFINITY
            }
        } else if f64_exp <= 0 {
            // Underflow to zero
            0.0
        } else {
            let f64_bits = ((sign as u64) << 63)
                | ((f64_exp as u64) << 52)
                | (f64_fraction & 0x000F_FFFF_FFFF_FFFF);
            f64::from_bits(f64_bits)
        }
    }
}
