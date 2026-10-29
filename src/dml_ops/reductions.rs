//! Reductions portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_reduce(&self, reduce: DmlReduceKind, axes: &[u32]) -> DmlResult<()> {
        if reduce.is_index_reduction() {
            return Err(DmlError::invalid(
                "DML_REDUCE_FUNCTION argmin/argmax requires DML_OPERATOR_ARGMIN or DML_OPERATOR_ARGMAX, not DML_OPERATOR_REDUCE",
            ));
        }
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if axes.is_empty() {
            return Err(DmlError::invalid("reduce requires at least one axis"));
        }
        let mut seen = Vec::with_capacity(axes.len());
        for axis in axes {
            if *axis as usize >= rank {
                return Err(DmlError::invalid(format!(
                    "reduce axis {axis} is out of range for rank {rank}"
                )));
            }
            if seen.contains(axis) {
                return Err(DmlError::invalid(format!(
                    "reduce axis {axis} appears more than once"
                )));
            }
            seen.push(*axis);
        }
        if self.output.sizes.len() != rank {
            return Err(DmlError::invalid(
                "reduce output must have the same rank as the input",
            ));
        }
        for dimension in 0..rank {
            let expected = if seen.contains(&(dimension as u32)) {
                1
            } else {
                input.sizes[dimension]
            };
            if self.output.sizes[dimension] != expected {
                return Err(DmlError::invalid(format!(
                    "reduce output size at dimension {dimension} must be {expected}, got {}",
                    self.output.sizes[dimension]
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_arg_reduce(
        &self,
        axes: &[u32],
        _direction: DmlAxisDirection,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if axes.is_empty() {
            return Err(DmlError::invalid(
                "argmin/argmax requires at least one axis",
            ));
        }
        let mut seen = Vec::with_capacity(axes.len());
        for axis in axes {
            if *axis as usize >= rank {
                return Err(DmlError::invalid(format!(
                    "argmin/argmax axis {axis} is out of range for rank {rank}"
                )));
            }
            if seen.contains(axis) {
                return Err(DmlError::invalid(format!(
                    "argmin/argmax axis {axis} appears more than once"
                )));
            }
            seen.push(*axis);
        }
        if self.output.sizes.len() != rank {
            return Err(DmlError::invalid(
                "argmin/argmax output must have the same rank as the input",
            ));
        }
        for dimension in 0..rank {
            let expected = if seen.contains(&(dimension as u32)) {
                1
            } else {
                input.sizes[dimension]
            };
            if self.output.sizes[dimension] != expected {
                return Err(DmlError::invalid(format!(
                    "argmin/argmax output size at dimension {dimension} must be {expected}, got {}",
                    self.output.sizes[dimension]
                )));
            }
        }
        if self.output.data_type != DML_TENSOR_DATA_TYPE_UINT32 {
            return Err(DmlError::invalid(
                "argmin/argmax output tensor must have DataType UINT32",
            ));
        }
        if self.output_count() != 1 {
            return Err(DmlError::invalid(
                "argmin/argmax requires exactly one output tensor",
            ));
        }
        Ok(())
    }
}

pub(crate) fn emit_reduce_msl(
    plan: &DmlOpPlan,
    reduce: DmlReduceKind,
    axes: &[u32],
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut base_terms = Vec::new();
    for dimension in 0..rank {
        if !axes.contains(&(dimension as u32)) {
            base_terms.push(format!("o{dimension} * {}u", input.strides[dimension]));
        }
    }
    let base = if base_terms.is_empty() {
        "0u".to_string()
    } else {
        base_terms.join(" + ")
    };
    let reduction_count: u64 = axes
        .iter()
        .map(|axis| input.sizes[*axis as usize] as u64)
        .product();
    source.push_str(&format!("    uint base = {base};\n"));
    match reduce {
        DmlReduceKind::Multiply => {
            source.push_str("    float acc = 1.0f;\n");
        }
        DmlReduceKind::Max | DmlReduceKind::Min => {
            source.push_str("    float acc = 0.0f;\n");
            source.push_str(if reduce == DmlReduceKind::Max {
                "    float best = -INFINITY;\n"
            } else {
                "    float best = INFINITY;\n"
            });
        }
        DmlReduceKind::LogSumExp => {
            source.push_str("    float acc = 0.0f;\n");
            source.push_str("    float lse = -INFINITY;\n");
        }
        _ => {
            source.push_str("    float acc = 0.0f;\n");
        }
    }
    source.push_str("    bool saw_nan = false;\n");
    source.push_str(&format!(
        "    for (uint r = 0u; r < {reduction_count}u; ++r) {{\n"
    ));
    source.push_str("        uint rem = r;\n");
    let mut index_expr = String::from("base");
    for axis in axes {
        let size = input.sizes[*axis as usize];
        let stride = input.strides[*axis as usize];
        source.push_str(&format!("        uint c{axis} = rem % {size}u;\n"));
        source.push_str(&format!("        rem /= {size}u;\n"));
        index_expr.push_str(&format!(" + c{axis} * {stride}u"));
    }
    source.push_str(&format!("        float v = float(in0[{index_expr}]);\n"));
    source.push_str("        bool v_nan = ((as_type<uint>(v) & 0x7fffffffu) > 0x7f800000u);\n");
    source.push_str("        if (v_nan) saw_nan = true;\n");
    match reduce {
        DmlReduceKind::Sum
        | DmlReduceKind::Mean
        | DmlReduceKind::LogSum
        | DmlReduceKind::LogSumExp => {
            source.push_str("        acc += v;\n");
        }
        DmlReduceKind::Multiply => {
            source.push_str("        acc *= v;\n");
        }
        DmlReduceKind::SumSquare | DmlReduceKind::L2 => {
            source.push_str("        acc += v * v;\n");
        }
        DmlReduceKind::L1 => {
            source.push_str("        acc += abs(v);\n");
        }
        DmlReduceKind::Max => {
            source.push_str("        if (!v_nan) best = fmax(best, v);\n");
        }
        DmlReduceKind::Min => {
            source.push_str("        if (!v_nan) best = fmin(best, v);\n");
        }
        DmlReduceKind::ArgMin | DmlReduceKind::ArgMax => {
            return Err(DmlError::invalid(
                "DML_REDUCE_FUNCTION argmin/argmax is not lowered through DML_OPERATOR_REDUCE",
            ));
        }
    }
    if reduce == DmlReduceKind::LogSumExp {
        source.push_str("        if (!v_nan) {\n");
        source.push_str("            float previous = lse;\n");
        source.push_str("            float current = v;\n");
        source.push_str("            lse = previous > current ? previous + log1p(exp(current - previous)) : current + log1p(exp(previous - current));\n");
        source.push_str("        }\n");
    }
    source.push_str("    }\n");
    let value = match reduce {
        DmlReduceKind::Sum => "acc".to_string(),
        DmlReduceKind::Mean => format!("acc / {reduction_count}.0f"),
        DmlReduceKind::Multiply => "acc".to_string(),
        DmlReduceKind::SumSquare => "acc".to_string(),
        DmlReduceKind::L1 => "acc".to_string(),
        DmlReduceKind::L2 => "sqrt(acc)".to_string(),
        DmlReduceKind::LogSum => "log(acc)".to_string(),
        DmlReduceKind::LogSumExp => "saw_nan ? NAN : lse".to_string(),
        DmlReduceKind::Max => "saw_nan ? NAN : best".to_string(),
        DmlReduceKind::Min => "saw_nan ? NAN : best".to_string(),
        DmlReduceKind::ArgMin | DmlReduceKind::ArgMax => {
            return Err(DmlError::invalid(
                "DML_REDUCE_FUNCTION argmin/argmax is not lowered through DML_OPERATOR_REDUCE",
            ));
        }
    };
    source.push_str(&format!(
        "    out[{}] = ({scalar})({value});\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_arg_reduce_msl(
    plan: &DmlOpPlan,
    axes: &[u32],
    direction: DmlAxisDirection,
    is_min: bool,
) -> DmlResult<String> {
    let input = &plan.inputs[0];
    let input_scalar = msl_scalar(input.data_type, plan.operator_type())?;
    let mut source = msl_header_outputs(plan, input_scalar, &["uint"]);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let rank = input.sizes.len();
    let reduction_count: u64 = axes
        .iter()
        .map(|axis| input.sizes[*axis as usize] as u64)
        .product();
    source.push_str("    float best = ");
    source.push_str(if is_min { "INFINITY" } else { "-INFINITY" });
    source.push_str(";\n    uint best_index = 0u;\n");
    source.push_str(&format!(
        "    for (uint r = 0u; r < {reduction_count}u; ++r) {{\n"
    ));
    source.push_str("        uint rem = r;\n");
    let mut coord_expr = Vec::with_capacity(rank);
    for dimension in 0..rank {
        if axes.contains(&(dimension as u32)) {
            let size = input.sizes[dimension];
            source.push_str(&format!("        uint c{dimension} = rem % {size}u;\n"));
            source.push_str(&format!("        rem /= {size}u;\n"));
            if direction == DmlAxisDirection::Decreasing {
                source.push_str(&format!(
                    "        c{dimension} = {}u - c{dimension};\n",
                    size - 1
                ));
            }
            coord_expr.push(format!("c{dimension}"));
        } else {
            coord_expr.push(format!("o{dimension}"));
        }
    }
    let index = linear_index(input, &coord_expr);
    source.push_str("        uint logical = 0u;\n");
    let mut basis = 1u32;
    for axis in axes {
        source.push_str(&format!("        logical += c{axis} * {basis}u;\n"));
        basis = basis.saturating_mul(input.sizes[*axis as usize]);
    }
    source.push_str(&format!("        float v = float(in0[{index}]);\n"));
    source.push_str("        if (!isnan(v) && ");
    source.push_str(if is_min { "v < best" } else { "v > best" });
    source.push_str(") {\n            best = v;\n            best_index = logical;\n        }\n");
    source.push_str("    }\n");
    source.push_str(&format!(
        "    out0[{}] = best_index;\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn execute_arg_reduce_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    axes: &[u32],
    direction: DmlAxisDirection,
    is_min: bool,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let count = plan.output.element_count();
    let reduction_count: u64 = axes
        .iter()
        .map(|axis| input.sizes[*axis as usize] as u64)
        .product();
    for gid in 0..count {
        let base = coords_of(gid, &plan.output.sizes);
        let mut best = if is_min {
            f32::INFINITY
        } else {
            f32::NEG_INFINITY
        };
        let mut best_index = 0u32;
        for step in 0..reduction_count {
            let mut input_coords = base.clone();
            let mut remainder = step;
            for axis in axes {
                let axis = *axis as usize;
                let size = input.sizes[axis];
                let mut coordinate = remainder % size as u64;
                remainder /= size as u64;
                if direction == DmlAxisDirection::Decreasing {
                    coordinate = size as u64 - 1 - coordinate;
                }
                input_coords[axis] = coordinate;
            }
            let value = load_scalar(
                input_bytes,
                index_of(&input_coords, &input.strides),
                input.data_type,
            );
            if value.is_nan() {
                continue;
            }
            let better = if is_min { value < best } else { value > best };
            if better {
                best = value;
                let mut logical = 0u32;
                let mut basis = 1u32;
                for axis in axes {
                    let axis = *axis as usize;
                    logical += input_coords[axis] as u32 * basis;
                    basis = basis.saturating_mul(input.sizes[axis]);
                }
                best_index = logical;
            }
        }
        store_integer(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            best_index as i64,
        );
    }
    Ok(())
}
