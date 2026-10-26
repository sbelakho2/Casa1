use super::*;

pub(crate) fn xmm_to_bytes(value: XmmValue) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&value.low.to_le_bytes());
    bytes[8..].copy_from_slice(&value.high.to_le_bytes());
    bytes
}

pub(crate) fn ymm_to_bytes(value: YmmValue) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[..16].copy_from_slice(&xmm_to_bytes(value.low));
    bytes[16..].copy_from_slice(&xmm_to_bytes(value.high));
    bytes
}

pub(crate) fn zmm_to_bytes(value: ZmmValue) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&ymm_to_bytes(value.low));
    bytes[32..].copy_from_slice(&ymm_to_bytes(value.high));
    bytes
}

pub(crate) fn bytes_to_xmm(bytes: [u8; 16]) -> XmmValue {
    XmmValue {
        low: u64::from_le_bytes(bytes[..8].try_into().expect("low xmm bytes")),
        high: u64::from_le_bytes(bytes[8..].try_into().expect("high xmm bytes")),
    }
}

pub(crate) fn bytes_to_ymm(bytes: [u8; 32]) -> YmmValue {
    YmmValue {
        low: bytes_to_xmm(bytes[..16].try_into().expect("low ymm bytes")),
        high: bytes_to_xmm(bytes[16..].try_into().expect("high ymm bytes")),
    }
}

pub(crate) fn bytes_to_zmm(bytes: [u8; 64]) -> ZmmValue {
    let low_bytes: [u8; 32] = bytes[..32].try_into().expect("low zmm bytes");
    let high_bytes: [u8; 32] = bytes[32..].try_into().expect("high zmm bytes");
    ZmmValue {
        low: bytes_to_ymm(low_bytes),
        high: bytes_to_ymm(high_bytes),
    }
}

pub(crate) fn implicit_string_len_u8(bytes: &[u8; 16]) -> usize {
    bytes.iter().position(|byte| *byte == 0).unwrap_or(16)
}

pub(crate) fn execute_pcmpistri_implicit_u8(
    lhs: [u8; 16],
    rhs: [u8; 16],
    imm: u8,
) -> AppResult<(u64, Flags)> {
    // imm8 control byte decomposition:
    // [1:0] = format/sign: 0=unsigned bytes, 1=signed bytes, 2=unsigned words (bit 1 ignored for bytes)
    // [3:2] = aggregation: 0=equal any, 1=ranges, 2=equal each, 3=equal ordered
    // [5:4] = comparison: 0=equals, 1=greater-than, 2=less-than, 3=reserved
    // [6]   = polarity: 0=normal, 1=negate result
    // [7]   = reserved (must be 0)
    let _format = imm & 0x03; // bits [1:0] — byte/word format
    let aggregation = (imm >> 2) & 0x03; // bits [3:2]
    let comparison = (imm >> 4) & 0x03; // bits [5:4]
    let polarity = (imm >> 6) & 0x01; // bit [6]

    let lhs_len = implicit_string_len_u8(&lhs);
    let rhs_len = implicit_string_len_u8(&rhs);
    let mut bitmask = 0_u16;

    // For unsigned byte format (format==0), each byte is a value.
    // For signed byte format (format==1), treat as i8 for comparison.
    // We handle unsigned bytes here; the comparison type affects the predicate.
    match aggregation {
        0x00 => {
            // Equal Any: for each position in rhs, set bit if any lhs byte matches
            for (index, &byte) in rhs[..rhs_len].iter().enumerate() {
                let matches = match comparison {
                    0 => lhs[..lhs_len].contains(&byte),
                    1 => {
                        // Greater-than: rhs byte > any lhs byte (signed or unsigned)
                        lhs[..lhs_len]
                            .iter()
                            .any(|&needle| (byte as i8) > (needle as i8))
                    }
                    2 => {
                        // Less-than: rhs byte < any lhs byte
                        lhs[..lhs_len]
                            .iter()
                            .any(|&needle| (byte as i8) < (needle as i8))
                    }
                    _ => false,
                };
                if matches {
                    bitmask |= 1_u16 << index;
                }
            }
        }
        0x01 => {
            // Equal Each / Ranges: for each position i, compare lhs[i] with rhs[i]
            let min_len = lhs_len.min(rhs_len);
            for i in 0..min_len {
                let matches = match comparison {
                    0 => lhs[i] == rhs[i],
                    1 => (rhs[i] as i8) > (lhs[i] as i8),
                    2 => (rhs[i] as i8) < (lhs[i] as i8),
                    _ => false,
                };
                if matches {
                    bitmask |= 1_u16 << i;
                }
            }
        }
        0x02 => {
            // Equal Each (same as 0x01 in Intel docs, also uses per-index comparison)
            let min_len = lhs_len.min(rhs_len);
            for i in 0..min_len {
                let matches = match comparison {
                    0 => lhs[i] == rhs[i],
                    1 => (rhs[i] as i8) > (lhs[i] as i8),
                    2 => (rhs[i] as i8) < (lhs[i] as i8),
                    _ => false,
                };
                if matches {
                    bitmask |= 1_u16 << i;
                }
            }
        }
        0x03 => {
            // Equal Ordered: substring search (Ranges in Intel terminology)
            if lhs_len == 0 {
                bitmask = 1;
            } else if lhs_len <= rhs_len {
                for start in 0..=rhs_len - lhs_len {
                    let matches = match comparison {
                        0 => lhs[..lhs_len] == rhs[start..start + lhs_len],
                        _ => {
                            // For GT/LT comparison in ordered mode, compare element-wise
                            lhs[..lhs_len].iter().zip(&rhs[start..start + lhs_len]).all(
                                |(&l, &r)| match comparison {
                                    1 => (r as i8) > (l as i8),
                                    2 => (r as i8) < (l as i8),
                                    _ => true,
                                },
                            )
                        }
                    };
                    if matches {
                        bitmask |= 1_u16 << start;
                    }
                }
            }
        }
        _ => unreachable!(),
    }

    // Apply polarity: if bit[6]=1, negate each bit of the result
    if polarity == 1 {
        bitmask = !bitmask;
    }

    // Determine the least-significant or most-significant set bit index
    let index = if bitmask == 0 {
        16
    } else if (imm & 0x40) == 0 {
        // Polarity bit is bit 6, but the LSB/MSB select is actually controlled
        // by bit 6 of imm8 in PCMPISTRI (bit 6 IS the polarity)
        // Actually: in Intel docs, the polarity bit and the LSB/MSB select
        // are the same bit. Polarity=0 => true polarity = result, polarity=1 => ~result
        // and the index is always the least-significant set bit.
        u64::from(bitmask.trailing_zeros())
    } else {
        15_u64 - u64::from(bitmask.leading_zeros())
    };

    Ok((
        index,
        Flags {
            cf: (bitmask & 0x0001) != 0,
            pf: (bitmask & 0x0002) != 0,
            af: false,
            zf: rhs_len < 16,
            sf: lhs_len < 16,
            of: (bitmask & 0x0001) != 0,
        },
    ))
}

pub(crate) fn xmm_to_u32x4(value: XmmValue) -> [u32; 4] {
    let bytes = xmm_to_bytes(value);
    [
        u32::from_le_bytes(bytes[0..4].try_into().expect("u32 lane")),
        u32::from_le_bytes(bytes[4..8].try_into().expect("u32 lane")),
        u32::from_le_bytes(bytes[8..12].try_into().expect("u32 lane")),
        u32::from_le_bytes(bytes[12..16].try_into().expect("u32 lane")),
    ]
}

pub(crate) fn u32x4_to_xmm(words: [u32; 4]) -> XmmValue {
    let mut bytes = [0_u8; 16];
    for (index, word) in words.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes_to_xmm(bytes)
}

pub(crate) fn xmm_to_f32x4(value: XmmValue) -> [f32; 4] {
    let bytes = xmm_to_bytes(value);
    [
        f32::from_le_bytes(bytes[0..4].try_into().expect("f32 lane")),
        f32::from_le_bytes(bytes[4..8].try_into().expect("f32 lane")),
        f32::from_le_bytes(bytes[8..12].try_into().expect("f32 lane")),
        f32::from_le_bytes(bytes[12..16].try_into().expect("f32 lane")),
    ]
}

pub(crate) fn f32x4_to_xmm(words: [f32; 4]) -> XmmValue {
    let mut bytes = [0_u8; 16];
    for (index, word) in words.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes_to_xmm(bytes)
}

#[allow(dead_code)] // SIMD register conversion helpers for AVX-512 emulation; not yet wired
pub(crate) fn ymm_to_f32x8(value: YmmValue) -> [f32; 8] {
    let bytes = ymm_to_bytes(value);
    let mut lanes = [0.0_f32; 8];
    for (index, lane) in lanes.iter_mut().enumerate() {
        let start = index * 4;
        *lane = f32::from_le_bytes(bytes[start..start + 4].try_into().expect("f32 lane"));
    }
    lanes
}

#[allow(dead_code)] // SIMD register conversion helpers for AVX-512 emulation; not yet wired
pub(crate) fn f32x8_to_ymm(words: [f32; 8]) -> YmmValue {
    let mut bytes = [0_u8; 32];
    for (index, word) in words.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes_to_ymm(bytes)
}

#[allow(dead_code)] // SIMD register conversion helpers for AVX-512 emulation; not yet wired
pub(crate) fn f32x16_to_zmm(words: [f32; 16]) -> ZmmValue {
    let mut bytes = [0_u8; 64];
    for (index, word) in words.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes_to_zmm(bytes)
}

#[allow(dead_code)] // SIMD register conversion helpers for AVX-512 emulation; not yet wired
pub(crate) fn zmm_to_f32x16(value: ZmmValue) -> [f32; 16] {
    let bytes = zmm_to_bytes(value);
    let mut lanes = [0.0_f32; 16];
    for (index, lane) in lanes.iter_mut().enumerate() {
        let start = index * 4;
        *lane = f32::from_le_bytes(bytes[start..start + 4].try_into().expect("f32 lane"));
    }
    lanes
}

pub(crate) fn xmm_to_f64x2(value: XmmValue) -> [f64; 2] {
    [f64::from_bits(value.low), f64::from_bits(value.high)]
}

pub(crate) fn f64x2_to_xmm(words: [f64; 2]) -> XmmValue {
    XmmValue {
        low: words[0].to_bits(),
        high: words[1].to_bits(),
    }
}

#[allow(dead_code)] // SIMD register conversion helpers for AVX-512 emulation; not yet wired
pub(crate) fn ymm_to_f64x4(value: YmmValue) -> [f64; 4] {
    let bytes = ymm_to_bytes(value);
    let mut lanes = [0.0_f64; 4];
    for (index, lane) in lanes.iter_mut().enumerate() {
        let start = index * 8;
        *lane = f64::from_le_bytes(bytes[start..start + 8].try_into().expect("f64 lane"));
    }
    lanes
}

#[allow(dead_code)] // SIMD register conversion helpers for AVX-512 emulation; not yet wired
pub(crate) fn f64x4_to_ymm(words: [f64; 4]) -> YmmValue {
    YmmValue {
        low: XmmValue {
            low: words[0].to_bits(),
            high: words[1].to_bits(),
        },
        high: XmmValue {
            low: words[2].to_bits(),
            high: words[3].to_bits(),
        },
    }
}

#[allow(dead_code)] // SIMD register conversion helpers for AVX-512 emulation; not yet wired
pub(crate) fn f64x8_to_zmm(words: [f64; 8]) -> ZmmValue {
    let mut bytes = [0_u8; 64];
    for (index, word) in words.into_iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes_to_zmm(bytes)
}

#[allow(dead_code)] // SIMD register conversion helpers for AVX-512 emulation; not yet wired
pub(crate) fn zmm_to_f64x8(value: ZmmValue) -> [f64; 8] {
    let bytes = zmm_to_bytes(value);
    let mut lanes = [0.0_f64; 8];
    for (index, lane) in lanes.iter_mut().enumerate() {
        let start = index * 8;
        *lane = f64::from_le_bytes(bytes[start..start + 8].try_into().expect("f64 lane"));
    }
    lanes
}

pub(crate) fn read_vector_register(
    state: &CpuState,
    index: u8,
    width: usize,
) -> AppResult<YmmValue> {
    match width {
        4 => Ok(YmmValue {
            low: XmmValue {
                low: state.get_xmm(index).low & 0xffff_ffff,
                high: 0,
            },
            high: XmmValue::default(),
        }),
        8 => Ok(YmmValue {
            low: XmmValue {
                low: state.get_xmm(index).low,
                high: 0,
            },
            high: XmmValue::default(),
        }),
        16 => Ok(YmmValue {
            low: state.get_xmm(index),
            high: XmmValue::default(),
        }),
        32 => Ok(state.get_ymm(index)),
        other => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported vector register width {other}"),
        )),
    }
}

pub(crate) fn write_vector_register(
    state: &mut CpuState,
    index: u8,
    value: YmmValue,
    width: usize,
) -> AppResult<()> {
    match width {
        4 => {
            state.set_xmm(
                index,
                XmmValue {
                    low: value.low.low & 0xffff_ffff,
                    high: 0,
                },
            );
            state.clear_ymm_upper(index);
        }
        8 => {
            state.set_xmm(
                index,
                XmmValue {
                    low: value.low.low,
                    high: 0,
                },
            );
            state.clear_ymm_upper(index);
        }
        16 => {
            state.set_xmm(index, value.low);
            state.clear_ymm_upper(index);
        }
        32 => state.set_ymm(index, value),
        other => {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unsupported vector register width {other}"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn read_vector_memory(
    memory: &MemoryImage,
    address: u64,
    width: usize,
) -> AppResult<YmmValue> {
    match width {
        4 => Ok(YmmValue {
            low: XmmValue {
                low: read_memory_value(memory, address, 4)?,
                high: 0,
            },
            high: XmmValue::default(),
        }),
        8 => Ok(YmmValue {
            low: XmmValue {
                low: read_memory_value(memory, address, 8)?,
                high: 0,
            },
            high: XmmValue::default(),
        }),
        16 => Ok(YmmValue {
            low: memory.read_xmm(address)?,
            high: XmmValue::default(),
        }),
        32 => memory.read_ymm(address),
        other => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported vector memory width {other}"),
        )),
    }
}

pub(crate) fn write_vector_memory(
    memory: &mut MemoryImage,
    address: u64,
    value: YmmValue,
    width: usize,
) -> AppResult<()> {
    match width {
        4 | 8 | 16 | 32 => {
            let bytes = ymm_to_bytes(value);
            write_guest_bytes(memory, address, &bytes[..width])
        }
        other => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported vector memory width {other}"),
        )),
    }
}

pub(crate) fn read_vector_operand(
    state: &CpuState,
    memory: &MemoryImage,
    operand: &VectorOperand,
    width: usize,
) -> AppResult<YmmValue> {
    match operand {
        VectorOperand::Register(index) => read_vector_register(state, *index, width),
        VectorOperand::Memory(address) => {
            let target = resolve_memory_operand(state, address, width)?;
            read_vector_memory(memory, target, width)
        }
    }
}

pub(crate) fn read_vector_bytes(state: &CpuState, index: u8, width: usize) -> AppResult<Vec<u8>> {
    match width {
        4 | 8 | 16 | 32 => {
            let val = read_vector_register(state, index, width)?;
            let bytes = ymm_to_bytes(val);
            Ok(bytes[..width].to_vec())
        }
        64 => {
            let zmm = state.get_zmm(index);
            Ok(zmm_to_bytes(zmm).to_vec())
        }
        _ => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported vector byte read width {width}"),
        )),
    }
}

pub(crate) fn write_vector_bytes(
    state: &mut CpuState,
    index: u8,
    bytes: &[u8],
    width: usize,
) -> AppResult<()> {
    match width {
        4 | 8 | 16 | 32 => {
            let mut buf = [0_u8; 32];
            buf[..width].copy_from_slice(bytes);
            let val = bytes_to_ymm(buf);
            write_vector_register(state, index, val, width)
        }
        64 => {
            let mut buf = [0_u8; 64];
            buf.copy_from_slice(bytes);
            let zmm = bytes_to_zmm(buf);
            state.set_zmm(index, zmm);
            Ok(())
        }
        _ => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported vector byte write width {width}"),
        )),
    }
}

pub(crate) fn read_vector_operand_bytes(
    state: &CpuState,
    memory: &MemoryImage,
    operand: &VectorOperand,
    width: usize,
) -> AppResult<Vec<u8>> {
    match operand {
        VectorOperand::Register(index) => read_vector_bytes(state, *index, width),
        VectorOperand::Memory(address) => {
            let target = resolve_memory_operand(state, address, width)?;
            match width {
                4 | 8 | 16 | 32 => {
                    let val = read_vector_memory(memory, target, width)?;
                    let bytes = ymm_to_bytes(val);
                    Ok(bytes[..width].to_vec())
                }
                64 => {
                    let zmm = memory.read_zmm(target)?;
                    Ok(zmm_to_bytes(zmm).to_vec())
                }
                _ => Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unsupported vector operand byte read width {width}"),
                )),
            }
        }
    }
}

pub(crate) fn write_vector_operand_bytes(
    state: &mut CpuState,
    memory: &mut MemoryImage,
    operand: &VectorOperand,
    bytes: &[u8],
    width: usize,
) -> AppResult<()> {
    match operand {
        VectorOperand::Register(index) => write_vector_bytes(state, *index, bytes, width),
        VectorOperand::Memory(address) => {
            let target = resolve_memory_operand(state, address, width)?;
            write_guest_bytes(memory, target, bytes)
        }
    }
}

/// Apply AVX-512 mask register (opmask) to a computed vector result.
///
/// If `evex.mask` is `None` or `Some(0)` (k0), no masking is applied.
/// For merge-masking (`evex.zm == false`), lanes with mask bit 0 retain
/// the original destination value. For zero-masking (`evex.zm == true`),
/// lanes with mask bit 0 are zeroed.
pub(crate) fn apply_opmask(
    state: &CpuState,
    dst: u8,
    result_bytes: &mut [u8],
    width: usize,
    element_size: usize,
    evex: &EvexInfo,
) -> AppResult<()> {
    let mask_reg = match evex.mask {
        None | Some(0) => return Ok(()),
        Some(reg) => reg,
    };
    let mask_val = state.opmask[mask_reg as usize];
    let lane_count = width / element_size;
    let original = read_vector_bytes(state, dst, width)?;
    for i in 0..lane_count {
        let bit = (mask_val >> i) & 1;
        if bit == 0 {
            let off = i * element_size;
            if evex.zm {
                // Zero-mask: zero out this lane
                result_bytes[off..off + element_size].fill(0);
            } else {
                // Merge-mask: keep original destination value
                result_bytes[off..off + element_size]
                    .copy_from_slice(&original[off..off + element_size]);
            }
        }
    }
    Ok(())
}

/// Read a vector source operand, optionally applying EVEX broadcast.
///
/// When `evex.bcast` is true and the operand is memory, only `element_size`
/// bytes are read from memory and replicated across all `width / element_size`
/// lanes. Register operands are returned as-is (broadcast does not apply to
/// register sources per the AVX-512 spec).
pub(crate) fn read_source_with_broadcast(
    state: &CpuState,
    memory: &MemoryImage,
    operand: &VectorOperand,
    width: usize,
    element_size: usize,
    evex: &EvexInfo,
) -> AppResult<Vec<u8>> {
    if !evex.bcast {
        return read_vector_operand_bytes(state, memory, operand, width);
    }
    match operand {
        VectorOperand::Register(index) => {
            // Broadcast does not apply to register sources
            read_vector_bytes(state, *index, width)
        }
        VectorOperand::Memory(address) => {
            let target = resolve_memory_operand(state, address, element_size)?;
            let element_bytes = memory.read_bytes(target, element_size)?;
            let lane_count = width / element_size;
            let mut result = vec![0u8; width];
            for i in 0..lane_count {
                let off = i * element_size;
                result[off..off + element_size].copy_from_slice(&element_bytes);
            }
            Ok(result)
        }
    }
}

/// Apply EVEX embedded rounding (EVEX.RC') to floating-point result bytes.
///
/// When `evex.er` is `Some(mode)`, each lane's value is rounded according to:
/// - 0: RN (round to nearest, ties to even) — default f32/f64 behaviour
/// - 1: RD (round down, toward -inf)
/// - 2: RU (round up, toward +inf)
/// - 3: RZ (round toward zero)
///
/// When `evex.er` is `None`, no rounding is applied.
pub(crate) fn apply_evex_rounding(
    result_bytes: &mut [u8],
    width: usize,
    element_size: usize,
    evex: &EvexInfo,
) -> AppResult<()> {
    let mode = match evex.er {
        None => return Ok(()),
        Some(mode) => mode,
    };
    if mode == 0 {
        return Ok(()); // RN is the default IEEE rounding
    }
    let lane_count = width / element_size;
    for i in 0..lane_count {
        let off = i * element_size;
        if element_size == 4 {
            let v = checked_f32_le(result_bytes, off)?;
            let rounded = match mode {
                1 => v.floor(),
                2 => v.ceil(),
                3 => v.trunc(),
                _ => v,
            };
            result_bytes[off..off + 4].copy_from_slice(&rounded.to_le_bytes());
        } else {
            let v = checked_f64_le(result_bytes, off)?;
            let rounded = match mode {
                1 => v.floor(),
                2 => v.ceil(),
                3 => v.trunc(),
                _ => v,
            };
            result_bytes[off..off + 8].copy_from_slice(&rounded.to_le_bytes());
        }
    }
    Ok(())
}

pub(crate) fn compare_f32(a: f32, b: f32, predicate: u8) -> bool {
    match predicate {
        0 => a == b,
        1 => a < b,
        2 => a <= b,
        3 => a.is_nan() || b.is_nan(),
        4 => a != b,
        5 => a.partial_cmp(&b) != Some(std::cmp::Ordering::Less),
        6 => matches!(a.partial_cmp(&b), Some(std::cmp::Ordering::Greater) | None),
        7 => a.is_nan() && b.is_nan(),
        _ => false,
    }
}

pub(crate) fn compare_f64(a: f64, b: f64, predicate: u8) -> bool {
    match predicate {
        0 => a == b,
        1 => a < b,
        2 => a <= b,
        3 => a.is_nan() || b.is_nan(),
        4 => a != b,
        5 => a.partial_cmp(&b) != Some(std::cmp::Ordering::Less),
        6 => matches!(a.partial_cmp(&b), Some(std::cmp::Ordering::Greater) | None),
        7 => a.is_nan() && b.is_nan(),
        _ => false,
    }
}

pub(crate) fn fpclassify_f32(v: f32, class_mask: u8) -> bool {
    let bits = v.to_bits();
    let sign_bit = (bits >> 31) & 1;
    let exp = (bits >> 23) & 0xff;
    let mant = bits & 0x7fffff;
    let is_qnan = exp == 0xff && mant >= 0x400000;
    let is_snan = exp == 0xff && mant != 0 && mant < 0x400000;
    let is_inf = exp == 0xff && mant == 0;
    let is_zero = exp == 0 && mant == 0;
    let _is_denorm = exp == 0 && mant != 0;
    let is_finite = exp != 0 && exp != 0xff;
    let mut result = false;
    if class_mask & 0x01 != 0 && is_finite && sign_bit == 0 {
        result = true;
    }
    if class_mask & 0x02 != 0 && is_finite && sign_bit == 1 {
        result = true;
    }
    if class_mask & 0x04 != 0 && is_inf && sign_bit == 0 {
        result = true;
    }
    if class_mask & 0x08 != 0 && is_inf && sign_bit == 1 {
        result = true;
    }
    if class_mask & 0x10 != 0 && is_qnan {
        result = true;
    }
    if class_mask & 0x20 != 0 && is_snan {
        result = true;
    }
    if class_mask & 0x40 != 0 && is_zero && sign_bit == 0 {
        result = true;
    }
    if class_mask & 0x80 != 0 && is_zero && sign_bit == 1 {
        result = true;
    }
    result
}

pub(crate) fn fpclassify_f64(v: f64, class_mask: u8) -> bool {
    let bits = v.to_bits();
    let sign_bit = (bits >> 63) & 1;
    let exp = (bits >> 52) & 0x7ff;
    let mant = bits & 0x000fffffffffffff;
    let is_qnan = exp == 0x7ff && mant >= 0x8000000000000;
    let is_snan = exp == 0x7ff && mant != 0 && mant < 0x8000000000000;
    let is_inf = exp == 0x7ff && mant == 0;
    let is_zero = exp == 0 && mant == 0;
    let _is_denorm = exp == 0 && mant != 0;
    let is_finite = exp != 0 && exp != 0x7ff;
    let mut result = false;
    if class_mask & 0x01 != 0 && is_finite && sign_bit == 0 {
        result = true;
    }
    if class_mask & 0x02 != 0 && is_finite && sign_bit == 1 {
        result = true;
    }
    if class_mask & 0x04 != 0 && is_inf && sign_bit == 0 {
        result = true;
    }
    if class_mask & 0x08 != 0 && is_inf && sign_bit == 1 {
        result = true;
    }
    if class_mask & 0x10 != 0 && is_qnan {
        result = true;
    }
    if class_mask & 0x20 != 0 && is_snan {
        result = true;
    }
    if class_mask & 0x40 != 0 && is_zero && sign_bit == 0 {
        result = true;
    }
    if class_mask & 0x80 != 0 && is_zero && sign_bit == 1 {
        result = true;
    }
    result
}

pub(crate) fn ymm_to_u64x4(value: YmmValue) -> [u64; 4] {
    [
        value.low.low,
        value.low.high,
        value.high.low,
        value.high.high,
    ]
}

pub(crate) fn u64x4_to_ymm(words: [u64; 4]) -> YmmValue {
    YmmValue {
        low: XmmValue {
            low: words[0],
            high: words[1],
        },
        high: XmmValue {
            low: words[2],
            high: words[3],
        },
    }
}

pub(crate) fn crc32_u64(seed: u32, value: u64) -> u32 {
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

// ──────────────────────────────────────────────────────────
// AES-NI software implementation helpers
// ──────────────────────────────────────────────────────────

pub(crate) const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[allow(dead_code)] // reference AES implementation for future AES-NI instruction emulation
pub(crate) const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES SubWord: applies S-box to each byte of a 32-bit word.
pub(crate) fn aes_sub_word(word: u32) -> u32 {
    let b = word.to_le_bytes();
    u32::from_le_bytes([
        AES_SBOX[b[0] as usize],
        AES_SBOX[b[1] as usize],
        AES_SBOX[b[2] as usize],
        AES_SBOX[b[3] as usize],
    ])
}

/// AES SubBytes: applies S-box to each byte of the 16-byte state.
#[allow(dead_code)] // reference AES implementation for future AES-NI instruction emulation
pub(crate) fn aes_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = AES_SBOX[*byte as usize];
    }
}

/// AES InvSubBytes: applies inverse S-box to each byte.
#[allow(dead_code)] // reference AES implementation for future AES-NI instruction emulation
pub(crate) fn aes_inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = AES_INV_SBOX[*byte as usize];
    }
}

/// AES ShiftRows: cyclically shifts rows of the 4x4 state matrix.
/// State is stored column-major: state[0..4] = column 0, state[4..8] = column 1, etc.
#[allow(dead_code)] // reference AES implementation for future AES-NI instruction emulation
pub(crate) fn aes_shift_rows(state: &mut [u8; 16]) {
    // Row 0: no shift
    // Row 1: shift left by 1 byte
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;
    // Row 2: shift left by 2 bytes
    let t0 = state[2];
    let t1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t0;
    state[14] = t1;
    // Row 3: shift left by 3 bytes (right by 1)
    let t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t;
}

/// AES InvShiftRows: cyclically shifts rows right.
#[allow(dead_code)] // reference AES implementation for future AES-NI instruction emulation
pub(crate) fn aes_inv_shift_rows(state: &mut [u8; 16]) {
    // Row 0: no shift
    // Row 1: shift right by 1 byte
    let t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t;
    // Row 2: shift right by 2 bytes
    let t0 = state[2];
    let t1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t0;
    state[14] = t1;
    // Row 3: shift right by 3 bytes (left by 1)
    let t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t;
}

/// GF(2^8) multiplication by 2 (xtime).
#[allow(dead_code)] // reference AES implementation for future AES-NI instruction emulation
pub(crate) fn xtime(a: u8) -> u8 {
    (a << 1) ^ (if (a & 0x80) != 0 { 0x1b } else { 0 })
}

/// AES MixColumns: multiplies each column by a fixed polynomial in GF(2^8).
/// State is column-major: column c = state[4*c .. 4*c+4].
#[allow(dead_code)] // reference AES implementation for future AES-NI instruction emulation
pub(crate) fn aes_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];
        state[i] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
        state[i + 1] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
        state[i + 2] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
        state[i + 3] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
    }
}

/// AES InvMixColumns: inverse MixColumns for decryption.
#[allow(dead_code)] // reference AES implementation for future AES-NI instruction emulation
pub(crate) fn aes_inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];
        // Use multiplication by 9, 11, 13, 14 in GF(2^8)
        let xtime_s0 = xtime(s0);
        let xtime_s1 = xtime(s1);
        let xtime_s2 = xtime(s2);
        let xtime_s3 = xtime(s3);
        let xt2_s0 = xtime(xtime_s0);
        let xt2_s1 = xtime(xtime_s1);
        let xt2_s2 = xtime(xtime_s2);
        let xt2_s3 = xtime(xtime_s3);
        let xt3_s0 = xtime(xt2_s0);
        let xt3_s1 = xtime(xt2_s1);
        let xt3_s2 = xtime(xt2_s2);
        let xt3_s3 = xtime(xt2_s3);
        // Multiply by 14 = 0x0E
        let e0 = xt3_s0 ^ xt2_s0 ^ xtime_s0;
        let e1 = xt3_s1 ^ xt2_s1 ^ xtime_s1;
        let e2 = xt3_s2 ^ xt2_s2 ^ xtime_s2;
        let e3 = xt3_s3 ^ xt2_s3 ^ xtime_s3;
        // Multiply by 9 = 0x09
        let n0 = xt3_s0 ^ s0;
        let n1 = xt3_s1 ^ s1;
        let n2 = xt3_s2 ^ s2;
        let n3 = xt3_s3 ^ s3;
        // Multiply by 13 = 0x0D
        let d0 = xt3_s0 ^ xt2_s0 ^ s0;
        let d1 = xt3_s1 ^ xt2_s1 ^ s1;
        let d2 = xt3_s2 ^ xt2_s2 ^ s2;
        let d3 = xt3_s3 ^ xt2_s3 ^ s3;
        // Multiply by 11 = 0x0B
        let b0 = xt3_s0 ^ xtime_s0 ^ s0;
        let b1 = xt3_s1 ^ xtime_s1 ^ s1;
        let b2 = xt3_s2 ^ xtime_s2 ^ s2;
        let b3 = xt3_s3 ^ xtime_s3 ^ s3;

        state[i] = e0 ^ b1 ^ d2 ^ n3;
        state[i + 1] = n0 ^ e1 ^ b2 ^ d3;
        state[i + 2] = d0 ^ n1 ^ e2 ^ b3;
        state[i + 3] = b0 ^ d1 ^ n2 ^ e3;
    }
}

/// AES AddRoundKey: XOR state with round key.
#[allow(dead_code)] // reference AES implementation for future AES-NI instruction emulation
pub(crate) fn aes_add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

// ──────────────────────────────────────────────────────────
// PCLMULQDQ: carry-less multiply of two 64-bit values → 128-bit result
// ──────────────────────────────────────────────────────────

/// Carry-less multiply (PCLMULQDQ): multiply two 64-bit values without carries,
/// producing a 128-bit result. Uses schoolbook multiplication on 16-bit chunks.
pub(crate) fn pclmulqdq(a: u64, b: u64) -> u128 {
    let a_lo = (a & 0xFFFF_FFFF) as u128;
    let a_hi = (a >> 32) as u128;
    let b_lo = (b & 0xFFFF_FFFF) as u128;
    let b_hi = (b >> 32) as u128;

    let _ll = a_lo * b_lo;
    let _lh = a_lo * b_hi;
    let _hl = a_hi * b_lo;
    let _hh = a_hi * b_hi;

    // Karatsuba-style: result = hh << 64 + (lh + hl) << 32 + ll
    // But this is carry-less, so we need to be more careful with overlapping bits.
    // Use the schoolbook approach with 16-bit limbs for correctness.

    let a_limbs: [u16; 4] = [
        (a & 0xFFFF) as u16,
        ((a >> 16) & 0xFFFF) as u16,
        ((a >> 32) & 0xFFFF) as u16,
        ((a >> 48) & 0xFFFF) as u16,
    ];
    let b_limbs: [u16; 4] = [
        (b & 0xFFFF) as u16,
        ((b >> 16) & 0xFFFF) as u16,
        ((b >> 32) & 0xFFFF) as u16,
        ((b >> 48) & 0xFFFF) as u16,
    ];

    let mut result: [u16; 8] = [0; 8];
    for (i, &a_limb) in a_limbs.iter().enumerate() {
        for (j, &b_limb) in b_limbs.iter().enumerate() {
            let product = (a_limb as u32) * (b_limb as u32);
            // In carry-less multiplication, the product of two 16-bit values
            // is XOR'd (not added with carry) into the appropriate position.
            let shift = i + j;
            result[shift] ^= (product & 0xFFFF) as u16;
            if shift + 1 < 8 {
                result[shift + 1] ^= (product >> 16) as u16;
            }
        }
    }

    let low = (result[0] as u64)
        | ((result[1] as u64) << 16)
        | ((result[2] as u64) << 32)
        | ((result[3] as u64) << 48);
    let high = (result[4] as u64)
        | ((result[5] as u64) << 16)
        | ((result[6] as u64) << 32)
        | ((result[7] as u64) << 48);
    (high as u128) << 64 | (low as u128)
}

// ──────────────────────────────────────────────────────────
// SHA-1 software implementation helpers
// ──────────────────────────────────────────────────────────

/// Execute 4 rounds of SHA-1 using the given message schedule words and round constant.
/// Returns the updated (a, b, c, d, e) state.
pub(crate) fn sha1_rounds(
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    w: [u32; 4],
    k: u32,
) -> (u32, u32, u32, u32, u32) {
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;
    let mut e = e;

    for &w_round in w.iter() {
        let f = (b & c) | (!b & d);
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w_round);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    (a, b, c, d, e)
}

// ──────────────────────────────────────────────────────────
// SHA-256 software implementation helpers
// ──────────────────────────────────────────────────────────

/// Execute 2 rounds of SHA-256 using the given message schedule words.
/// Returns the updated (a, b, c, d, e, f, g, h) state.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)] // reference SHA-256 implementation for future SHA instruction emulation
pub(crate) fn sha256_rounds(
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    f: u32,
    g: u32,
    h: u32,
    w: [u32; 2],
    _k: u32,
) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;
    let mut e = e;
    let mut f = f;
    let mut g = g;
    let mut h = h;

    // SHA-256 K constants for rounds 0-1 (first two rounds)
    // K[0] = 0x428A2F98, K[1] = 0x71374491
    const K256: [u32; 2] = [0x428A2F98, 0x71374491];

    for round in 0..2 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K256[round])
            .wrapping_add(w[round]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    (a, b, c, d, e, f, g, h)
}
