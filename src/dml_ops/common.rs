//! Common portion of the DML operator implementation.

use super::*;

pub(crate) fn expect_dtype(
    desc: &DmlTensorDesc,
    allowed: &[u32],
    ty: u32,
    role: &str,
) -> DmlResult<()> {
    if !allowed.contains(&desc.data_type) {
        return Err(DmlError::invalid(format!(
            "DML_OPERATOR_TYPE {ty} {role} tensor has unsupported DML_TENSOR_DATA_TYPE {}",
            desc.data_type
        )));
    }
    Ok(())
}

pub(crate) fn expect_same_dtype(
    desc: &DmlTensorDesc,
    expected: u32,
    ty: u32,
    role: &str,
) -> DmlResult<()> {
    if desc.data_type != expected {
        return Err(DmlError::invalid(format!(
            "DML_OPERATOR_TYPE {ty} {role} tensor must have DataType {expected}, got {}",
            desc.data_type
        )));
    }
    Ok(())
}

pub(crate) fn expect_index_dtype(desc: &DmlTensorDesc, ty: u32, role: &str) -> DmlResult<()> {
    expect_dtype(
        desc,
        &[DML_TENSOR_DATA_TYPE_UINT32, DML_TENSOR_DATA_TYPE_INT32],
        ty,
        role,
    )
}

pub(crate) fn validate_dtype(desc: &DmlTensorDesc, ty: u32, allow_f16: bool) -> DmlResult<()> {
    let supported = match desc.data_type {
        DML_TENSOR_DATA_TYPE_FLOAT32 => true,
        DML_TENSOR_DATA_TYPE_FLOAT16 => allow_f16,
        _ => false,
    };
    if !supported {
        return Err(DmlError::invalid(format!(
            "DML_TENSOR_DATA_TYPE {} is not supported for DML_OPERATOR_TYPE {ty}",
            desc.data_type
        )));
    }
    Ok(())
}

pub(crate) fn validate_layout(desc: &DmlTensorDesc, ty: u32) -> DmlResult<()> {
    if desc.sizes.len() != desc.strides.len() {
        return Err(DmlError::invalid(format!(
            "DML_OPERATOR_TYPE {ty} tensor Sizes and Strides ranks differ"
        )));
    }
    if desc.sizes.is_empty() || desc.sizes.len() > super::DML_TENSOR_MAX_DIMENSIONS as usize {
        return Err(DmlError::invalid(format!(
            "tensor DimensionCount {} is outside the supported 1..={} range",
            desc.sizes.len(),
            super::DML_TENSOR_MAX_DIMENSIONS
        )));
    }
    if desc.sizes.iter().any(|size| *size == 0) {
        return Err(DmlError::invalid("tensor dimensions must be non-zero"));
    }
    let count = checked_product(&desc.sizes)?;
    let implied = checked_implied_size(desc)?;
    if desc.total_size_in_bytes < implied {
        return Err(DmlError::invalid(format!(
            "tensor TotalTensorSizeInBytes {} is smaller than the implied {implied} bytes",
            desc.total_size_in_bytes
        )));
    }
    desc.validate()?;
    if count > u32::MAX as u64 {
        return Err(DmlError::invalid(format!(
            "tensor element count {count} exceeds the 32-bit kernel index limit"
        )));
    }
    Ok(())
}

pub(crate) fn checked_product(sizes: &[u32]) -> DmlResult<u64> {
    let mut product = 1u64;
    for size in sizes {
        product = product
            .checked_mul(*size as u64)
            .ok_or_else(|| DmlError::invalid("tensor element count overflows u64"))?;
    }
    Ok(product)
}

pub(crate) fn checked_implied_size(desc: &DmlTensorDesc) -> DmlResult<u64> {
    let element_bits = if desc.is_4bit() {
        4u64
    } else {
        desc.element_size()?.saturating_mul(8)
    };
    let mut max_element = 0u64;
    for (size, stride) in desc.sizes.iter().zip(&desc.strides) {
        let term = (*size as u64 - 1)
            .checked_mul(*stride as u64)
            .ok_or_else(|| DmlError::invalid("tensor stride range overflows u64"))?;
        max_element = max_element
            .checked_add(term)
            .ok_or_else(|| DmlError::invalid("tensor stride range overflows u64"))?;
    }
    max_element
        .checked_add(1)
        .and_then(|elements| elements.checked_mul(element_bits))
        .map(|bits| bits.div_ceil(8))
        .ok_or_else(|| DmlError::invalid("tensor stride range overflows u64"))
}

pub(crate) fn convolution_output_size(
    input: u32,
    window: u32,
    stride: u32,
    dilation: u32,
    start_padding: u32,
    end_padding: u32,
    output_padding: u32,
) -> DmlResult<u32> {
    let effective_window = (window as u64 - 1)
        .checked_mul(dilation as u64)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| DmlError::invalid("convolution effective window overflows u64"))?;
    let padded = input as u64 + start_padding as u64 + end_padding as u64;
    if padded < effective_window {
        return Err(DmlError::invalid(format!(
            "convolution window {effective_window} does not fit padded input {padded}"
        )));
    }
    let size = (padded - effective_window) / stride as u64 + 1 + output_padding as u64;
    if size == 0 || size > u32::MAX as u64 {
        return Err(DmlError::invalid("convolution output size is out of range"));
    }
    Ok(size as u32)
}

pub(crate) fn pooling_output_size(
    input: u32,
    window: u32,
    stride: u32,
    start_padding: u32,
    end_padding: u32,
) -> DmlResult<u32> {
    let padded = input as u64 + start_padding as u64 + end_padding as u64;
    if padded < window as u64 {
        return Err(DmlError::invalid(format!(
            "pooling window {window} does not fit padded input {padded}"
        )));
    }
    let size = (padded - window as u64) / stride as u64 + 1;
    if size == 0 || size > u32::MAX as u64 {
        return Err(DmlError::invalid("pooling output size is out of range"));
    }
    Ok(size as u32)
}

pub(crate) fn pooling_output_size_dilated(
    input: u32,
    window: u32,
    stride: u32,
    start_padding: u32,
    end_padding: u32,
    dilation: u32,
    label: &str,
) -> DmlResult<u32> {
    let effective_window = (window as u64 - 1)
        .checked_mul(dilation as u64)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| DmlError::invalid(format!("{label} effective window overflows u64")))?;
    let padded = input as u64 + start_padding as u64 + end_padding as u64;
    if padded < effective_window {
        return Err(DmlError::invalid(format!(
            "{label} window {effective_window} does not fit padded input {padded}"
        )));
    }
    let size = (padded - effective_window) / stride as u64 + 1;
    if size == 0 || size > u32::MAX as u64 {
        return Err(DmlError::invalid(format!(
            "{label} output size is out of range"
        )));
    }
    Ok(size as u32)
}

/// Validate a Metal/DirectML buffer binding range.
///
/// DirectML buffer bindings must be aligned to
/// [`DML_TENSOR_MIN_ALIGNMENT`](super::DML_TENSOR_MIN_ALIGNMENT) and cover the
/// tensor's declared `TotalTensorSizeInBytes`.
pub fn validate_buffer_binding(offset: u64, size: u64, required: u64) -> DmlResult<()> {
    if offset % DML_TENSOR_MIN_ALIGNMENT != 0 {
        return Err(DmlError::invalid(format!(
            "buffer binding offset {offset} is not {DML_TENSOR_MIN_ALIGNMENT}-byte aligned"
        )));
    }
    if size < required {
        return Err(DmlError::invalid(format!(
            "buffer binding size {size} is smaller than the required {required} bytes"
        )));
    }
    if offset.checked_add(size).is_none() {
        return Err(DmlError::invalid("buffer binding range overflows"));
    }
    Ok(())
}

pub(crate) fn msl_float(value: f32) -> String {
    if value.is_nan() {
        "NAN".to_string()
    } else if value == f32::INFINITY {
        "INFINITY".to_string()
    } else if value == f32::NEG_INFINITY {
        "-INFINITY".to_string()
    } else {
        format!("{value:?}f")
    }
}

pub(crate) fn msl_scalar(data_type: u32, ty: u32) -> DmlResult<&'static str> {
    match data_type {
        DML_TENSOR_DATA_TYPE_FLOAT32 => Ok("float"),
        DML_TENSOR_DATA_TYPE_FLOAT16 => Ok("half"),
        DML_TENSOR_DATA_TYPE_UINT32 => Ok("uint"),
        DML_TENSOR_DATA_TYPE_INT32 => Ok("int"),
        DML_TENSOR_DATA_TYPE_UINT8 => Ok("uchar"),
        DML_TENSOR_DATA_TYPE_INT8 => Ok("char"),
        DML_TENSOR_DATA_TYPE_UINT4 | DML_TENSOR_DATA_TYPE_INT4 => Ok("uchar"),
        other => Err(DmlError::invalid(format!(
            "DML_TENSOR_DATA_TYPE {other} is not supported for DML_OPERATOR_TYPE {ty}"
        ))),
    }
}

pub(crate) fn packed_read_4bit(pointer: &str, index: &str, signed: bool) -> String {
    let byte = format!("({index}) / 2u");
    let shift = format!("((({index}) % 2u) * 4u)");
    let raw = format!("(({pointer}[{byte}] >> {shift}) & 0x0fu)");
    if signed {
        format!("((int({raw}) & 8) != 0 ? int({raw}) - 16 : int({raw}))")
    } else {
        format!("int({raw})")
    }
}

pub(crate) fn packed_store_4bit(low: &str, high: &str, signed: bool) -> String {
    let (minimum, maximum) = if signed { (-8.0, 7.0) } else { (0.0, 15.0) };
    format!(
        "(uchar)((int(clamp(rint({low}), {minimum:?}f, {maximum:?}f)) & 15) | ((int(clamp(rint({high}), {minimum:?}f, {maximum:?}f)) & 15) << 4))"
    )
}

pub(crate) fn msl_type_unchecked(data_type: u32) -> &'static str {
    match data_type {
        DML_TENSOR_DATA_TYPE_FLOAT16 => "half",
        DML_TENSOR_DATA_TYPE_UINT32 => "uint",
        DML_TENSOR_DATA_TYPE_INT32 => "int",
        DML_TENSOR_DATA_TYPE_UINT8 => "uchar",
        DML_TENSOR_DATA_TYPE_INT8 => "char",
        DML_TENSOR_DATA_TYPE_UINT4 | DML_TENSOR_DATA_TYPE_INT4 => "uchar",
        _ => "float",
    }
}

/// MSL expression that reads one logical element as `float`.
pub(crate) fn msl_load_float(desc: &DmlTensorDesc, pointer: &str, index: &str) -> String {
    if desc.is_4bit() {
        format!(
            "float({})",
            packed_read_4bit(pointer, index, desc.data_type == DML_TENSOR_DATA_TYPE_INT4)
        )
    } else {
        format!("float({pointer}[{index}])")
    }
}

/// MSL expression that reads one logical element in its native scalar type.
pub(crate) fn msl_load_native(desc: &DmlTensorDesc, pointer: &str, index: &str) -> String {
    if desc.is_4bit() {
        packed_read_4bit(pointer, index, desc.data_type == DML_TENSOR_DATA_TYPE_INT4)
    } else {
        format!("{pointer}[{index}]")
    }
}

pub(crate) fn msl_header(plan: &DmlOpPlan, scalar: &str) -> String {
    let mut source = String::from("#include <metal_stdlib>\nusing namespace metal;\n");
    source.push_str("kernel void dml_op(");
    for index in 0..plan.inputs.len() {
        let input_scalar = msl_type_unchecked(plan.inputs[index].data_type);
        source.push_str(&format!(
            "device const {input_scalar}* in{index} [[buffer({index})]], "
        ));
    }
    source.push_str(&format!(
        "device {scalar}* out [[buffer({})]], uint gid [[thread_position_in_grid]]) {{\n",
        plan.inputs.len()
    ));
    source
}

pub(crate) fn msl_header_outputs(
    plan: &DmlOpPlan,
    _input_scalar: &str,
    output_scalars: &[&str],
) -> String {
    let mut source = String::from("#include <metal_stdlib>\nusing namespace metal;\n");
    source.push_str("kernel void dml_op(");
    for index in 0..plan.inputs.len() {
        let input_scalar = msl_type_unchecked(plan.inputs[index].data_type);
        source.push_str(&format!(
            "device const {input_scalar}* in{index} [[buffer({index})]], "
        ));
    }
    let first_output = plan.inputs.len();
    for (index, scalar) in output_scalars.iter().enumerate() {
        source.push_str(&format!(
            "device {scalar}* out{index} [[buffer({})]], ",
            first_output + index
        ));
    }
    let scratch = if matches!(
        plan.kind,
        DmlOpKind::Rnn { .. } | DmlOpKind::Gru { .. } | DmlOpKind::Lstm { .. }
    ) {
        format!(
            "device float* scratch [[buffer({})]], ",
            first_output + output_scalars.len()
        )
    } else {
        String::new()
    };
    source.push_str(&format!(
        "{scratch}uint gid [[thread_position_in_grid]]) {{\n"
    ));
    source
}

/// Wrap the final output assignment of a single-output kernel with the plan's
/// fused activation. Templates with several output assignments are rejected by
/// validation before lowering.
pub(crate) fn inject_fused_activation(
    source: &mut String,
    scalar: &str,
    activation: DmlActivation,
) {
    let Some(start) = source.rfind("    out[") else {
        return;
    };
    let marker = format!("= ({scalar})(");
    let Some(marker_offset) = source[start..].find(&marker) else {
        return;
    };
    let value_start = start + marker_offset + marker.len();
    let Some(end_offset) = source[value_start..].rfind(");") else {
        return;
    };
    let value_end = value_start + end_offset;
    let value = source[value_start..value_end].to_string();
    let replacement = activation_msl(activation, 0.0, &format!("({value})"));
    source.replace_range(value_start..value_end, &replacement);
}

pub(crate) fn push_guard(source: &mut String, output: &DmlTensorDesc) {
    let count = output.element_count();
    source.push_str(&format!("    if (gid >= {count}u) return;\n"));
}

pub(crate) fn push_output_coords(source: &mut String, output: &DmlTensorDesc) {
    for (index, size) in output.sizes.iter().enumerate() {
        let divisor: u64 = output.sizes[index + 1..]
            .iter()
            .map(|value| *value as u64)
            .product();
        source.push_str(&format!(
            "    uint o{index} = (gid / {divisor}u) % {size}u;\n"
        ));
    }
}

pub(crate) fn output_index_expr(output: &DmlTensorDesc) -> String {
    if output.is_contiguous() {
        return "gid".to_string();
    }
    linear_index(output, &coord_names(output.sizes.len()))
}

pub(crate) fn linear_index(desc: &DmlTensorDesc, coords: &[String]) -> String {
    if coords.is_empty() {
        return "0u".to_string();
    }
    coords
        .iter()
        .zip(&desc.strides)
        .map(|(coord, stride)| format!("({coord}) * {stride}u"))
        .collect::<Vec<_>>()
        .join(" + ")
}

pub(crate) fn coord_names(rank: usize) -> Vec<String> {
    (0..rank).map(|index| format!("o{index}")).collect()
}

pub(crate) fn broadcast_index(desc: &DmlTensorDesc) -> String {
    let mut terms = Vec::with_capacity(desc.sizes.len());
    for (index, (size, stride)) in desc.sizes.iter().zip(&desc.strides).enumerate() {
        if *size == 1 {
            terms.push("0u".to_string());
        } else {
            terms.push(format!("o{index} * {stride}u"));
        }
    }
    if terms.is_empty() {
        "0u".to_string()
    } else {
        terms.join(" + ")
    }
}

/// Index expression for a quantization scale/zero-point tensor. A scalar is
/// broadcast everywhere; a tensor either matches the output rank with
/// broadcast dimensions or is a per-axis vector mapped to the output channel
/// (axis 1) or last axis.
pub(crate) fn quantization_tensor_index(
    desc: &DmlTensorDesc,
    output: &DmlTensorDesc,
    coords: &[String],
) -> DmlResult<String> {
    if desc.element_count() == 1 {
        return Ok("0".to_string());
    }
    if desc.sizes.len() == output.sizes.len() {
        let mut terms = Vec::with_capacity(desc.sizes.len());
        for dimension in 0..desc.sizes.len() {
            if desc.sizes[dimension] == 1 {
                continue;
            }
            if desc.sizes[dimension] != output.sizes[dimension] {
                return Err(DmlError::invalid(format!(
                    "quantization tensor dimension {dimension} size {} does not match the output size {}",
                    desc.sizes[dimension], output.sizes[dimension]
                )));
            }
            terms.push(format!(
                "({}) * {}u",
                coords[dimension], desc.strides[dimension]
            ));
        }
        return Ok(if terms.is_empty() {
            "0".to_string()
        } else {
            terms.join(" + ")
        });
    }
    if desc.sizes.len() == 1 {
        let size = desc.sizes[0];
        let axis = if output.sizes.len() >= 2 && output.sizes[1] == size {
            1
        } else if *output.sizes.last().expect("non-empty output") == size {
            output.sizes.len() - 1
        } else {
            output
                .sizes
                .iter()
                .position(|candidate| *candidate == size)
                .ok_or_else(|| {
                    DmlError::invalid(format!(
                        "quantization tensor axis size {size} does not match any output dimension"
                    ))
                })?
        };
        return Ok(format!("({}) * {}u", coords[axis], desc.strides[0]));
    }
    Err(DmlError::invalid(
        "quantization tensor must be scalar, per-axis, or broadcastable to the output rank",
    ))
}

pub(crate) fn quantization_index_for_linear(
    desc: &DmlTensorDesc,
    output: &DmlTensorDesc,
    index: &str,
) -> DmlResult<String> {
    let mut coords = Vec::with_capacity(output.sizes.len());
    for dimension in 0..output.sizes.len() {
        let divisor: u64 = output.sizes[dimension + 1..]
            .iter()
            .map(|size| *size as u64)
            .product();
        coords.push(format!(
            "(({index}) / {divisor}u % {}u)",
            output.sizes[dimension]
        ));
    }
    quantization_tensor_index(desc, output, &coords)
}

pub(crate) fn broadcast_index_with(desc: &DmlTensorDesc, rank: usize) -> String {
    let mut terms = Vec::new();
    for dimension in 0..rank {
        let size = desc.sizes.get(dimension).copied().unwrap_or(1);
        let stride = desc.strides.get(dimension).copied().unwrap_or(0);
        if size == 1 {
            terms.push("0u".to_string());
        } else {
            terms.push(format!("o{dimension} * {stride}u"));
        }
    }
    terms.join(" + ")
}

/// Convert raw FLOAT16 bits to FLOAT32 (used by guest descriptor parsing).
pub fn f16_bits_to_f32(bits: u16) -> f32 {
    f16_to_f32(bits)
}

pub(crate) fn f16_to_f32(bits: u16) -> f32 {
    let sign = ((bits >> 15) & 1) as u32;
    let exponent = ((bits >> 10) & 0x1f) as u32;
    let fraction = (bits & 0x3ff) as u32;
    let value = if exponent == 0 {
        if fraction == 0 {
            sign << 31
        } else {
            let mut exponent = 127 - 15 + 1;
            let mut mantissa = fraction;
            while mantissa & 0x400 == 0 {
                mantissa <<= 1;
                exponent -= 1;
            }
            (sign << 31) | ((exponent as u32) << 23) | ((mantissa & 0x3ff) << 13)
        }
    } else if exponent == 0x1f {
        (sign << 31) | (0xff << 23) | (fraction << 13)
    } else {
        (sign << 31) | ((exponent + 127 - 15) << 23) | (fraction << 13)
    };
    f32::from_bits(value)
}

pub(crate) fn f32_to_f16(value: f32) -> u16 {
    let bits = value.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exponent = ((bits >> 23) & 0xff) as i32;
    let fraction = bits & 0x7f_ffff;
    if exponent == 0xff {
        let payload = if fraction != 0 {
            ((fraction >> 13) as u16) | 0x200
        } else {
            0
        };
        return sign | 0x7c00 | payload;
    }
    let unbiased = exponent - 127;
    if unbiased > 15 {
        return sign | 0x7c00;
    }
    if unbiased >= -14 {
        let mut half_exponent = (unbiased + 15) as u32;
        let mut mantissa = fraction >> 13;
        let remainder = fraction & 0x1fff;
        let round_up = remainder > 0x1000 || (remainder == 0x1000 && (mantissa & 1) == 1);
        if round_up {
            mantissa += 1;
        }
        if mantissa == 0x400 {
            mantissa = 0;
            half_exponent += 1;
        }
        if half_exponent >= 0x1f {
            return sign | 0x7c00;
        }
        return sign | ((half_exponent as u16) << 10) | (mantissa as u16);
    }
    if unbiased < -24 {
        return sign;
    }
    let scaled = (value.abs() * 16_777_216.0).round_ties_even();
    if scaled >= 1024.0 {
        return sign | 0x0400;
    }
    sign | (scaled as u16)
}

pub(crate) fn load_scalar(bytes: &[u8], index: u64, data_type: u32) -> f32 {
    let index = index as usize;
    match data_type {
        DML_TENSOR_DATA_TYPE_FLOAT32 => f32::from_le_bytes(
            bytes[index * 4..index * 4 + 4]
                .try_into()
                .expect("f32 slice"),
        ),
        DML_TENSOR_DATA_TYPE_FLOAT16 => f16_to_f32(u16::from_le_bytes(
            bytes[index * 2..index * 2 + 2]
                .try_into()
                .expect("f16 slice"),
        )),
        DML_TENSOR_DATA_TYPE_UINT32 => u32::from_le_bytes(
            bytes[index * 4..index * 4 + 4]
                .try_into()
                .expect("u32 slice"),
        ) as f32,
        DML_TENSOR_DATA_TYPE_INT32 => i32::from_le_bytes(
            bytes[index * 4..index * 4 + 4]
                .try_into()
                .expect("i32 slice"),
        ) as f32,
        DML_TENSOR_DATA_TYPE_UINT8 => bytes[index] as f32,
        DML_TENSOR_DATA_TYPE_INT8 => (bytes[index] as i8) as f32,
        DML_TENSOR_DATA_TYPE_UINT4 => ((bytes[index / 2] >> ((index % 2) * 4)) & 0x0f) as f32,
        DML_TENSOR_DATA_TYPE_INT4 => {
            let raw = ((bytes[index / 2] >> ((index % 2) * 4)) & 0x0f) as i8;
            if raw & 0x08 != 0 {
                raw as f32 - 16.0
            } else {
                raw as f32
            }
        }
        _ => 0.0,
    }
}

pub(crate) fn load_integer(bytes: &[u8], index: u64, data_type: u32) -> i64 {
    let index = index as usize;
    match data_type {
        DML_TENSOR_DATA_TYPE_UINT32 => u32::from_le_bytes(
            bytes[index * 4..index * 4 + 4]
                .try_into()
                .expect("u32 slice"),
        ) as i64,
        DML_TENSOR_DATA_TYPE_INT32 => i32::from_le_bytes(
            bytes[index * 4..index * 4 + 4]
                .try_into()
                .expect("i32 slice"),
        ) as i64,
        DML_TENSOR_DATA_TYPE_UINT8 => bytes[index] as i64,
        DML_TENSOR_DATA_TYPE_INT8 => (bytes[index] as i8) as i64,
        DML_TENSOR_DATA_TYPE_FLOAT32 => load_scalar(bytes, index as u64, data_type) as i64,
        DML_TENSOR_DATA_TYPE_FLOAT16 => load_scalar(bytes, index as u64, data_type) as i64,
        _ => 0,
    }
}

pub(crate) fn store_integer(bytes: &mut [u8], index: u64, data_type: u32, value: i64) {
    let index = index as usize;
    match data_type {
        DML_TENSOR_DATA_TYPE_UINT32 => {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
        DML_TENSOR_DATA_TYPE_INT32 => {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&(value as i32).to_le_bytes());
        }
        DML_TENSOR_DATA_TYPE_UINT8 => {
            bytes[index] = value.clamp(0, 255) as u8;
        }
        DML_TENSOR_DATA_TYPE_INT8 => {
            bytes[index] = value.clamp(-128, 127) as i8 as u8;
        }
        _ => {}
    }
}

pub(crate) fn store_quantized(bytes: &mut [u8], index: u64, data_type: u32, value: f32) {
    let index = index as usize;
    match data_type {
        DML_TENSOR_DATA_TYPE_UINT8 => {
            bytes[index] = value.round_ties_even().clamp(0.0, 255.0) as u8;
        }
        DML_TENSOR_DATA_TYPE_INT8 => {
            bytes[index] = value.round_ties_even().clamp(-128.0, 127.0) as i8 as u8;
        }
        DML_TENSOR_DATA_TYPE_UINT4 | DML_TENSOR_DATA_TYPE_INT4 => {
            let range = if data_type == DML_TENSOR_DATA_TYPE_INT4 {
                (-8.0, 7.0)
            } else {
                (0.0, 15.0)
            };
            let quantized = value.round_ties_even().clamp(range.0, range.1) as i32 & 0x0f;
            let shift = (index % 2) * 4;
            bytes[index / 2] = (bytes[index / 2] & !(0x0f << shift)) | ((quantized as u8) << shift);
        }
        _ => store_scalar(bytes, index as u64, data_type, value),
    }
}

pub(crate) fn store_cast(bytes: &mut [u8], index: u64, data_type: u32, value: f32) {
    match data_type {
        DML_TENSOR_DATA_TYPE_INT32 => {
            let index = index as usize;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&(value as i32).to_le_bytes());
        }
        DML_TENSOR_DATA_TYPE_UINT32 => {
            let index = index as usize;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
        DML_TENSOR_DATA_TYPE_INT8 => {
            bytes[index as usize] = value as i8 as u8;
        }
        DML_TENSOR_DATA_TYPE_UINT8 => {
            bytes[index as usize] = value as u8;
        }
        _ => store_scalar(bytes, index, data_type, value),
    }
}

pub(crate) fn store_scalar(bytes: &mut [u8], index: u64, data_type: u32, value: f32) {
    let index = index as usize;
    match data_type {
        DML_TENSOR_DATA_TYPE_FLOAT32 => {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        DML_TENSOR_DATA_TYPE_FLOAT16 => {
            bytes[index * 2..index * 2 + 2].copy_from_slice(&f32_to_f16(value).to_le_bytes());
        }
        _ => {}
    }
}

pub(crate) fn coords_of(mut linear: u64, sizes: &[u32]) -> Vec<u64> {
    let mut coords = vec![0u64; sizes.len()];
    for index in (0..sizes.len()).rev() {
        coords[index] = linear % sizes[index] as u64;
        linear /= sizes[index] as u64;
    }
    coords
}

pub(crate) fn index_of(coords: &[u64], strides: &[u32]) -> u64 {
    coords
        .iter()
        .zip(strides)
        .map(|(coord, stride)| coord * *stride as u64)
        .sum()
}

pub(crate) fn row_major_index(coords: &[u64], sizes: &[u32]) -> u64 {
    let mut index = 0u64;
    let mut stride = 1u64;
    for (coord, size) in coords.iter().zip(sizes).rev() {
        index += coord * stride;
        stride *= *size as u64;
    }
    index
}

pub(crate) fn channel_offset(desc: &DmlTensorDesc, channel: u64) -> u64 {
    if desc.sizes.len() == 1 {
        return channel * desc.strides[0] as u64;
    }
    let mut coords = vec![0u64; desc.sizes.len()];
    if desc.sizes.len() > 1 {
        coords[1] = channel.min(desc.sizes[1] as u64 - 1);
    }
    index_of(&coords, &desc.strides)
}

pub(crate) fn quantization_element_index(
    desc: &DmlTensorDesc,
    output: &DmlTensorDesc,
    output_coords: &[u64],
) -> u64 {
    if desc.element_count() == 1 {
        return 0;
    }
    if desc.sizes.len() == output.sizes.len() {
        let mapped = desc
            .sizes
            .iter()
            .enumerate()
            .map(|(dimension, size)| {
                if *size == 1 {
                    0
                } else {
                    output_coords[dimension]
                }
            })
            .collect::<Vec<_>>();
        return index_of(&mapped, &desc.strides);
    }
    if desc.sizes.len() == 1 {
        let size = desc.sizes[0];
        let axis = if output.sizes.len() >= 2 && output.sizes[1] == size {
            1
        } else if *output.sizes.last().expect("non-empty output") == size {
            output.sizes.len() - 1
        } else {
            output
                .sizes
                .iter()
                .position(|candidate| *candidate == size)
                .unwrap_or(0)
        };
        return output_coords[axis] * desc.strides[0] as u64;
    }
    0
}

pub(crate) fn output_index(desc: &DmlTensorDesc, gid: u64) -> u64 {
    if desc.is_contiguous() {
        gid
    } else {
        index_of(&coords_of(gid, &desc.sizes), &desc.strides)
    }
}

pub(crate) fn broadcast_coords(desc: &DmlTensorDesc, output_coords: &[u64]) -> Vec<u64> {
    desc.sizes
        .iter()
        .enumerate()
        .map(|(dimension, size)| {
            if *size == 1 {
                0
            } else {
                output_coords[dimension]
            }
        })
        .collect()
}

pub(crate) fn decode_reduced_coords(t: u64, axes: &[u32], sizes: &[u32], base: &[u64]) -> Vec<u64> {
    let mut coords = base.to_vec();
    let mut rem = t;
    for axis in axes {
        let index = *axis as usize;
        coords[index] = rem % sizes[index] as u64;
        rem /= sizes[index] as u64;
    }
    coords
}
