//! Elementwise portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_unary(&self, op: DmlUnaryOp) -> DmlResult<()> {
        self.require_input_count(1)?;
        if self.inputs[0].sizes != self.output.sizes {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} input and output sizes must match",
                op.operator_type()
            )));
        }
        match op {
            DmlUnaryOp::Clip { min, max } => {
                if !min.is_finite() || !max.is_finite() || min > max {
                    return Err(DmlError::invalid(format!(
                        "clip bounds must be finite and min <= max, got {min} and {max}"
                    )));
                }
            }
            DmlUnaryOp::Threshold { min } | DmlUnaryOp::ConstantPow { exponent: min } => {
                if !min.is_finite() {
                    return Err(DmlError::invalid(
                        "element-wise scalar parameter must be finite",
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn validate_if(&self) -> DmlResult<()> {
        self.require_input_count(3)?;
        let [condition, a, b] = [&self.inputs[0], &self.inputs[1], &self.inputs[2]];
        if condition.sizes.len() != a.sizes.len() || a.sizes.len() != b.sizes.len() {
            return Err(DmlError::invalid(
                "IF condition, A, and B tensors must have the same rank",
            ));
        }
        let mut expected = Vec::with_capacity(a.sizes.len());
        for dimension in 0..a.sizes.len() {
            let sizes = [
                condition.sizes[dimension],
                a.sizes[dimension],
                b.sizes[dimension],
            ];
            let largest = *sizes.iter().max().expect("three sizes");
            if sizes.iter().any(|size| *size != largest && *size != 1) {
                return Err(DmlError::invalid(format!(
                    "IF tensor sizes are not broadcast-compatible at dimension {dimension}: {:?}",
                    sizes
                )));
            }
            expected.push(largest);
        }
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "IF output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_bitwise(&self, count: bool) -> DmlResult<()> {
        self.require_input_count(1)?;
        if self.inputs[0].sizes != self.output.sizes {
            return Err(DmlError::invalid(
                "bitwise input and output sizes must match",
            ));
        }
        if count
            && self.output.data_type != DML_TENSOR_DATA_TYPE_UINT32
            && self.output.data_type != DML_TENSOR_DATA_TYPE_UINT8
        {
            return Err(DmlError::invalid(
                "bit count output DataType must be UINT32 or UINT8",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_value_scale(
        &self,
        scale: f32,
        channel_count: u32,
        bias: &[f32],
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        if input.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "value scale 2D requires a rank-4 NCHW input",
            ));
        }
        if self.output.sizes != input.sizes {
            return Err(DmlError::invalid(
                "value scale 2D input and output sizes must match",
            ));
        }
        if channel_count != 1 && channel_count != 3 {
            return Err(DmlError::invalid(format!(
                "value scale 2D ChannelCount must be 1 or 3, got {channel_count}"
            )));
        }
        if input.sizes[1] != channel_count {
            return Err(DmlError::invalid(format!(
                "value scale 2D ChannelCount {} must match the input channel size {}",
                channel_count, input.sizes[1]
            )));
        }
        if bias.len() != channel_count as usize {
            return Err(DmlError::invalid(format!(
                "value scale 2D bias must contain {channel_count} values, got {}",
                bias.len()
            )));
        }
        if !scale.is_finite() || bias.iter().any(|value| !value.is_finite()) {
            return Err(DmlError::invalid(
                "value scale 2D scale and bias must be finite",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_clip1(
        &self,
        min: f32,
        max: f32,
        scale: f32,
        bias: f32,
        has_scale_bias: bool,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        if self.inputs[0].sizes != self.output.sizes {
            return Err(DmlError::invalid("clip1 input and output sizes must match"));
        }
        if !min.is_finite() || !max.is_finite() || min > max {
            return Err(DmlError::invalid(format!(
                "clip1 bounds must be finite and min <= max, got {min} and {max}"
            )));
        }
        if has_scale_bias && (!scale.is_finite() || !bias.is_finite()) {
            return Err(DmlError::invalid("clip1 scale and bias must be finite"));
        }
        Ok(())
    }

    pub(crate) fn validate_elementwise_grad(&self, name: &str) -> DmlResult<()> {
        self.require_input_count(2)?;
        for desc in &self.inputs[..2] {
            if desc.sizes != self.output.sizes {
                return Err(DmlError::invalid(format!(
                    "{name} gradient input tensors must match the output sizes",
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_clip_grad(&self, min: f32, max: f32) -> DmlResult<()> {
        self.validate_elementwise_grad("clip")?;
        if !min.is_finite() || !max.is_finite() || min > max {
            return Err(DmlError::invalid(format!(
                "clip gradient bounds must be finite and min <= max, got {min} and {max}"
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_binary(&self) -> DmlResult<()> {
        self.require_input_count(2)?;
        let a = &self.inputs[0];
        let b = &self.inputs[1];
        if a.sizes.len() != b.sizes.len() {
            return Err(DmlError::invalid(
                "binary input tensors must have the same rank",
            ));
        }
        let mut expected = Vec::with_capacity(a.sizes.len());
        for (dimension, (a_size, b_size)) in a.sizes.iter().zip(&b.sizes).enumerate() {
            let size = if a_size == b_size {
                *a_size
            } else if *a_size == 1 {
                *b_size
            } else if *b_size == 1 {
                *a_size
            } else {
                return Err(DmlError::invalid(format!(
                    "binary input sizes are not broadcast-compatible at dimension {dimension}: {a_size} vs {b_size}"
                )));
            };
            expected.push(size);
        }
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "binary output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }
}

pub(crate) fn emit_scalar_binary(op: DmlBinaryOp) -> &'static str {
    match op {
        DmlBinaryOp::Add => "a + b",
        DmlBinaryOp::Subtract => "a - b",
        DmlBinaryOp::Multiply => "a * b",
        DmlBinaryOp::Divide => "a / b",
        DmlBinaryOp::Min => "fmin(a, b)",
        DmlBinaryOp::Max => "fmax(a, b)",
        DmlBinaryOp::Pow => "pow(a, b)",
        DmlBinaryOp::ModulusTruncate => "fmod(a, b)",
        DmlBinaryOp::ModulusFloor => "a - b * floor(a / b)",
        DmlBinaryOp::DifferenceSquare => "(a - b) * (a - b)",
        DmlBinaryOp::AtanYx => "atan2(a, b)",
        DmlBinaryOp::LogicalAnd => "(a != 0.0f && b != 0.0f) ? 1.0f : 0.0f",
        DmlBinaryOp::LogicalOr => "(a != 0.0f || b != 0.0f) ? 1.0f : 0.0f",
        DmlBinaryOp::LogicalXor => "((a != 0.0f) != (b != 0.0f)) ? 1.0f : 0.0f",
        DmlBinaryOp::LogicalEquals => "a == b ? 1.0f : 0.0f",
        DmlBinaryOp::LogicalGreaterThan => "a > b ? 1.0f : 0.0f",
        DmlBinaryOp::LogicalLessThan => "a < b ? 1.0f : 0.0f",
        DmlBinaryOp::LogicalGreaterThanOrEqual => "a >= b ? 1.0f : 0.0f",
        DmlBinaryOp::LogicalLessThanOrEqual => "a <= b ? 1.0f : 0.0f",
        DmlBinaryOp::BitAnd => "float(as_type<uint>(int(a)) & as_type<uint>(int(b)))",
        DmlBinaryOp::BitOr => "float(as_type<uint>(int(a)) | as_type<uint>(int(b)))",
        DmlBinaryOp::BitXor => "float(as_type<uint>(int(a)) ^ as_type<uint>(int(b)))",
        DmlBinaryOp::BitShiftLeft => {
            "float(as_type<uint>(int(a)) << (as_type<uint>(int(b)) & 31u))"
        }
        DmlBinaryOp::BitShiftRight => {
            "float(as_type<uint>(int(a)) >> (as_type<uint>(int(b)) & 31u))"
        }
        DmlBinaryOp::Mean => "(a + b) * 0.5f",
    }
}

pub(crate) fn apply_binary(op: DmlBinaryOp, left: f32, right: f32) -> f32 {
    match op {
        DmlBinaryOp::Add => left + right,
        DmlBinaryOp::Subtract => left - right,
        DmlBinaryOp::Multiply => left * right,
        DmlBinaryOp::Divide => left / right,
        DmlBinaryOp::Min => left.min(right),
        DmlBinaryOp::Max => left.max(right),
        DmlBinaryOp::Pow => left.powf(right),
        DmlBinaryOp::ModulusTruncate => left % right,
        DmlBinaryOp::ModulusFloor => left - right * (left / right).floor(),
        DmlBinaryOp::DifferenceSquare => (left - right) * (left - right),
        DmlBinaryOp::AtanYx => left.atan2(right),
        DmlBinaryOp::LogicalAnd => ((left != 0.0) && (right != 0.0)) as u8 as f32,
        DmlBinaryOp::LogicalOr => ((left != 0.0) || (right != 0.0)) as u8 as f32,
        DmlBinaryOp::LogicalXor => ((left != 0.0) != (right != 0.0)) as u8 as f32,
        DmlBinaryOp::LogicalEquals => (left == right) as u8 as f32,
        DmlBinaryOp::LogicalGreaterThan => (left > right) as u8 as f32,
        DmlBinaryOp::LogicalLessThan => (left < right) as u8 as f32,
        DmlBinaryOp::LogicalGreaterThanOrEqual => (left >= right) as u8 as f32,
        DmlBinaryOp::LogicalLessThanOrEqual => (left <= right) as u8 as f32,
        DmlBinaryOp::BitAnd => ((left as i64 as u32) & (right as i64 as u32)) as f32,
        DmlBinaryOp::BitOr => ((left as i64 as u32) | (right as i64 as u32)) as f32,
        DmlBinaryOp::BitXor => ((left as i64 as u32) ^ (right as i64 as u32)) as f32,
        DmlBinaryOp::BitShiftLeft => {
            (left as i64 as u32).wrapping_shl((right as i64 as u32) & 31) as f32
        }
        DmlBinaryOp::BitShiftRight => ((left as i64 as u32) >> ((right as i64 as u32) & 31)) as f32,
        DmlBinaryOp::Mean => (left + right) * 0.5,
    }
}

pub(crate) fn unary_msl(op: DmlUnaryOp, x: &str) -> String {
    let inner = format!("({x})");
    match op {
        DmlUnaryOp::Acos => format!("acos({inner})"),
        DmlUnaryOp::Asin => format!("asin({inner})"),
        DmlUnaryOp::Atan => format!("atan({inner})"),
        DmlUnaryOp::Abs => format!("abs({inner})"),
        DmlUnaryOp::Ceil => format!("ceil({inner})"),
        DmlUnaryOp::Cos => format!("cos({inner})"),
        DmlUnaryOp::Exp => format!("exp({inner})"),
        DmlUnaryOp::Floor => format!("floor({inner})"),
        DmlUnaryOp::Log => format!("log({inner})"),
        DmlUnaryOp::Sin => format!("sin({inner})"),
        DmlUnaryOp::Sqrt => format!("sqrt({inner})"),
        DmlUnaryOp::Tan => format!("tan({inner})"),
        DmlUnaryOp::Identity => inner,
        DmlUnaryOp::Reciprocal => format!("1.0f / {inner}"),
        DmlUnaryOp::Sign => {
            format!("({inner}) > 0.0f ? 1.0f : (({inner}) < 0.0f ? -1.0f : ({inner}))")
        }
        DmlUnaryOp::IsNan => {
            format!("((as_type<uint>(float({inner})) & 0x7fffffffu) > 0x7f800000u) ? 1.0f : 0.0f")
        }
        DmlUnaryOp::Erf => format!("erf({inner})"),
        DmlUnaryOp::Sinh => format!("sinh({inner})"),
        DmlUnaryOp::Cosh => format!("cosh({inner})"),
        DmlUnaryOp::Tanh => format!("tanh({inner})"),
        DmlUnaryOp::Asinh => format!("asinh({inner})"),
        DmlUnaryOp::Acosh => format!("acosh({inner})"),
        DmlUnaryOp::Atanh => format!("atanh({inner})"),
        DmlUnaryOp::Round => format!("rint({inner})"),
        DmlUnaryOp::IsInfinity => {
            format!("abs(float({inner})) == INFINITY ? 1.0f : 0.0f")
        }
        DmlUnaryOp::Negate => format!("-{inner}"),
        DmlUnaryOp::Clip { min, max } => {
            format!("clamp({inner}, {}, {})", msl_float(min), msl_float(max))
        }
        DmlUnaryOp::Threshold { min } => format!("{inner} > {} ? {inner} : 0.0f", msl_float(min)),
        DmlUnaryOp::ConstantPow { exponent } => {
            format!("pow({inner}, {})", msl_float(exponent))
        }
        DmlUnaryOp::LogicalNot => format!("({inner}) == 0.0f ? 1.0f : 0.0f"),
    }
}

pub(crate) fn unary_cpu(op: DmlUnaryOp, x: f32) -> f32 {
    match op {
        DmlUnaryOp::Acos => x.acos(),
        DmlUnaryOp::Asin => x.asin(),
        DmlUnaryOp::Atan => x.atan(),
        DmlUnaryOp::Abs => x.abs(),
        DmlUnaryOp::Ceil => x.ceil(),
        DmlUnaryOp::Cos => x.cos(),
        DmlUnaryOp::Exp => x.exp(),
        DmlUnaryOp::Floor => x.floor(),
        DmlUnaryOp::Log => x.ln(),
        DmlUnaryOp::Sin => x.sin(),
        DmlUnaryOp::Sqrt => x.sqrt(),
        DmlUnaryOp::Tan => x.tan(),
        DmlUnaryOp::Identity => x,
        DmlUnaryOp::Reciprocal => 1.0 / x,
        DmlUnaryOp::Sign => {
            if x > 0.0 {
                1.0
            } else if x < 0.0 {
                -1.0
            } else {
                x
            }
        }
        DmlUnaryOp::IsNan => {
            if x.is_nan() {
                1.0
            } else {
                0.0
            }
        }
        DmlUnaryOp::Erf => erf_approx(x),
        DmlUnaryOp::Sinh => x.sinh(),
        DmlUnaryOp::Cosh => x.cosh(),
        DmlUnaryOp::Tanh => x.tanh(),
        DmlUnaryOp::Asinh => x.asinh(),
        DmlUnaryOp::Acosh => x.acosh(),
        DmlUnaryOp::Atanh => x.atanh(),
        DmlUnaryOp::Round => x.round_ties_even(),
        DmlUnaryOp::IsInfinity => {
            if x.is_infinite() {
                1.0
            } else {
                0.0
            }
        }
        DmlUnaryOp::Negate => -x,
        DmlUnaryOp::Clip { min, max } => x.clamp(min, max),
        DmlUnaryOp::Threshold { min } => {
            if x > min {
                x
            } else {
                0.0
            }
        }
        DmlUnaryOp::ConstantPow { exponent } => x.powf(exponent),
        DmlUnaryOp::LogicalNot => {
            if x == 0.0 {
                1.0
            } else {
                0.0
            }
        }
    }
}

/// Deterministic erf approximation used by the CPU reference path. The Metal
/// path uses the system `erf`; the tolerance used by numeric tests covers the
/// difference.
pub(crate) fn erf_approx(x: f32) -> f32 {
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.327_591_1 * x);
    let y = 1.0
        - (((((1.061_405_4 * t - 1.453_152_1) * t + 1.421_413_7) * t - 0.284_496_72) * t
            + 0.254_829_6)
            * t)
            * (-x * x).exp();
    sign * y
}

pub(crate) fn emit_unary_msl(plan: &DmlOpPlan, op: DmlUnaryOp) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    float x = {};\n",
        msl_load_float(&plan.inputs[0], "in0", &broadcast_index(&plan.inputs[0]))
    ));
    source.push_str(&format!(
        "    out[{}] = ({scalar})({});\n",
        output_index_expr(&plan.output),
        unary_msl(op, "x")
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_cast_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    let mut input_coords = Vec::new();
    for (index, size) in input.sizes.iter().enumerate() {
        let divisor: u64 = input.sizes[index + 1..]
            .iter()
            .map(|value| *value as u64)
            .product();
        source.push_str(&format!(
            "    uint i{index} = (gid / {divisor}u) % {size}u;\n"
        ));
        input_coords.push(format!("i{index}"));
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})({});\n",
        output_index_expr(&plan.output),
        msl_load_float(input, "in0", &linear_index(input, &input_coords))
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_if_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let condition = &plan.inputs[0];
    let a = &plan.inputs[1];
    let b = &plan.inputs[2];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    bool take_a = in0[{}] != 0;\n",
        broadcast_index(condition)
    ));
    source.push_str(&format!(
        "    float va = float(in1[{}]);\n",
        broadcast_index(a)
    ));
    source.push_str(&format!(
        "    float vb = float(in2[{}]);\n",
        broadcast_index(b)
    ));
    source.push_str(&format!(
        "    out[{}] = ({scalar})(take_a ? va : vb);\n}}\n",
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

pub(crate) fn emit_bitwise_msl(plan: &DmlOpPlan, count: bool) -> DmlResult<String> {
    let output_scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, output_scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let index = linear_index(input, &coord_names(input.sizes.len()));
    if count {
        let cast = match input.data_type {
            DML_TENSOR_DATA_TYPE_UINT8 | DML_TENSOR_DATA_TYPE_INT8 => {
                "popcount((uint)(uchar)".to_string()
            }
            _ => "popcount((uint)".to_string(),
        };
        source.push_str(&format!(
            "    out[{}] = ({output_scalar}){cast}in0[{index}]);\n}}\n",
            output_index_expr(&plan.output)
        ));
    } else {
        source.push_str(&format!(
            "    out[{}] = ({output_scalar})(~in0[{index}]);\n}}\n",
            output_index_expr(&plan.output)
        ));
    }
    Ok(source)
}

pub(crate) fn emit_value_scale_msl(
    plan: &DmlOpPlan,
    scale: f32,
    _channel_count: u32,
    bias: &[f32],
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    float x = float(in0[{}]);\n",
        linear_index(input, &coord_names(input.sizes.len()))
    ));
    let bias_terms = bias
        .iter()
        .enumerate()
        .map(|(index, value)| format!("(o1 == {index}u ? {} : 0.0f)", msl_float(*value)))
        .collect::<Vec<_>>()
        .join(" + ");
    let bias_expr = if bias.is_empty() {
        "0.0f".to_string()
    } else {
        bias_terms
    };
    source.push_str(&format!(
        "    out[{}] = ({scalar})(x * {} + ({bias_expr}));\n}}\n",
        output_index_expr(&plan.output),
        msl_float(scale)
    ));
    Ok(source)
}

pub(crate) fn emit_clip1_msl(
    plan: &DmlOpPlan,
    min: f32,
    max: f32,
    scale: f32,
    bias: f32,
    has_scale_bias: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let index = linear_index(input, &coord_names(input.sizes.len()));
    source.push_str(&format!("    float x = float(in0[{index}]);\n"));
    if has_scale_bias {
        source.push_str(&format!(
            "    x = x * {} + {};\n",
            msl_float(scale),
            msl_float(bias)
        ));
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})fmin(fmax(x, {}), {});\n}}\n",
        output_index_expr(&plan.output),
        msl_float(min),
        msl_float(max)
    ));
    Ok(source)
}

pub(crate) fn emit_clip_grad_msl(plan: &DmlOpPlan, min: f32, max: f32) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let index = broadcast_index(&plan.inputs[0]);
    let gradient = broadcast_index(&plan.inputs[1]);
    source.push_str(&format!(
        "    float x = float(in0[{index}]);\n    float g = float(in1[{gradient}]);\n    bool inside = x >= {} && x <= {};\n    out[{}] = ({scalar})(inside ? g : 0.0f);\n}}\n",
        msl_float(min),
        msl_float(max),
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

pub(crate) fn emit_elementwise_msl(plan: &DmlOpPlan, op: DmlBinaryOp) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    float a = float(in0[{}]);\n",
        broadcast_index(&plan.inputs[0])
    ));
    source.push_str(&format!(
        "    float b = float(in1[{}]);\n",
        broadcast_index(&plan.inputs[1])
    ));
    source.push_str(&format!(
        "    out[{}] = ({scalar})({});\n",
        output_index_expr(&plan.output),
        emit_scalar_binary(op)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn execute_if_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
) -> DmlResult<()> {
    let dtype = plan.output.data_type;
    let [condition, a, b] = [&plan.inputs[0], &plan.inputs[1], &plan.inputs[2]];
    for gid in 0..plan.output.element_count() {
        let coords = coords_of(gid, &plan.output.sizes);
        let condition_value = load_scalar(
            inputs[0],
            index_of(&broadcast_coords(condition, &coords), &condition.strides),
            condition.data_type,
        );
        let source = if condition_value != 0.0 { 1 } else { 2 };
        let desc = &plan.inputs[source];
        let value = load_scalar(
            inputs[source],
            index_of(&broadcast_coords(desc, &coords), &desc.strides),
            dtype,
        );
        let _ = (a, b);
        store_scalar(output, output_index(&plan.output, gid), dtype, value);
    }
    Ok(())
}

pub(crate) fn execute_bitwise_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    count: bool,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let output_dtype = plan.output.data_type;
    for gid in 0..plan.output.element_count() {
        let coords = coords_of(gid, &plan.output.sizes);
        let index = index_of(&coords, &input.strides);
        let raw = load_integer(input_bytes, index, input.data_type);
        let value = if count {
            match input.data_type {
                DML_TENSOR_DATA_TYPE_UINT8 | DML_TENSOR_DATA_TYPE_INT8 => {
                    (raw as u8).count_ones() as i64
                }
                _ => (raw as u32).count_ones() as i64,
            }
        } else {
            match input.data_type {
                DML_TENSOR_DATA_TYPE_UINT8 => (!(raw as u8)) as i64,
                DML_TENSOR_DATA_TYPE_INT8 => (!(raw as i8)) as i64,
                DML_TENSOR_DATA_TYPE_UINT32 => (!(raw as u32)) as i64,
                DML_TENSOR_DATA_TYPE_INT32 => (!(raw as i32)) as i64,
                _ => raw,
            }
        };
        store_integer(output, output_index(&plan.output, gid), output_dtype, value);
    }
    Ok(())
}

pub(crate) fn execute_value_scale_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    scale: f32,
    _channel_count: u32,
    bias: &[f32],
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let dtype = plan.output.data_type;
    for gid in 0..plan.output.element_count() {
        let coords = coords_of(gid, &plan.output.sizes);
        let value = load_scalar(input_bytes, index_of(&coords, &input.strides), dtype);
        let channel = coords[1] as usize;
        let bias = bias.get(channel).copied().unwrap_or(0.0);
        store_scalar(
            output,
            output_index(&plan.output, gid),
            dtype,
            value * scale + bias,
        );
    }
    Ok(())
}

pub(crate) fn execute_clip1_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    min: f32,
    max: f32,
    scale: f32,
    bias: f32,
    has_scale_bias: bool,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let dtype = plan.output.data_type;
    for gid in 0..plan.output.element_count() {
        let coords = coords_of(gid, &plan.output.sizes);
        let mut value = load_scalar(input_bytes, index_of(&coords, &input.strides), dtype);
        if has_scale_bias {
            value = value * scale + bias;
        }
        store_scalar(
            output,
            output_index(&plan.output, gid),
            dtype,
            value.clamp(min, max),
        );
    }
    Ok(())
}

pub(crate) fn execute_clip_grad_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    min: f32,
    max: f32,
) -> DmlResult<()> {
    let dtype = plan.output.data_type;
    for gid in 0..plan.output.element_count() {
        let coords = coords_of(gid, &plan.output.sizes);
        let x = load_scalar(
            inputs[0],
            index_of(
                &broadcast_coords(&plan.inputs[0], &coords),
                &plan.inputs[0].strides,
            ),
            dtype,
        );
        let g = load_scalar(
            inputs[1],
            index_of(
                &broadcast_coords(&plan.inputs[1], &coords),
                &plan.inputs[1].strides,
            ),
            dtype,
        );
        store_scalar(
            output,
            output_index(&plan.output, gid),
            dtype,
            if x >= min && x <= max { g } else { 0.0 },
        );
    }
    Ok(())
}

pub(crate) fn execute_binary_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    op: DmlBinaryOp,
) -> DmlResult<()> {
    let dtype = plan.output.data_type;
    let count = plan.output.element_count();
    let a = &plan.inputs[0];
    let b = &plan.inputs[1];
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let mut a_coords = coords.clone();
        let mut b_coords = coords.clone();
        for (dimension, coord) in coords.iter().enumerate() {
            if a.sizes[dimension] == 1 {
                a_coords[dimension] = 0;
            }
            if b.sizes[dimension] == 1 {
                b_coords[dimension] = 0;
            }
            let _ = coord;
        }
        let left = load_scalar(inputs[0], index_of(&a_coords, &a.strides), a.data_type);
        let right = load_scalar(inputs[1], index_of(&b_coords, &b.strides), b.data_type);
        store_scalar(
            output,
            output_index(&plan.output, gid),
            dtype,
            apply_binary(op, left, right),
        );
    }
    Ok(())
}
