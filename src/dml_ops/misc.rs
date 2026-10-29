//! Misc portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_random_generator(&self, generator_type: u32) -> DmlResult<()> {
        self.require_input_count(1)?;
        if generator_type != 0 {
            return Err(DmlError::invalid(format!(
                "random generator type {generator_type} is not PHILOX_4X32_10"
            )));
        }
        if self.inputs[0].element_count() != 6 {
            return Err(DmlError::invalid(
                "Philox random generator state must contain exactly 6 UINT32 values",
            ));
        }
        if self.output.element_count() == 0 {
            return Err(DmlError::invalid(
                "random generator output must contain at least one element",
            ));
        }
        if self.extra_outputs.len() > 1 {
            return Err(DmlError::invalid(
                "random generator supports at most one output state tensor",
            ));
        }
        if let Some(state) = self.extra_outputs.first() {
            if state.element_count() != 6 {
                return Err(DmlError::invalid(
                    "Philox random generator output state must contain exactly 6 UINT32 values",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_nonzero(&self) -> DmlResult<()> {
        self.require_input_count(1)?;
        if self.extra_outputs.len() != 1 {
            return Err(DmlError::invalid(
                "nonzero coordinates requires count and coordinate outputs",
            ));
        }
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        let coordinates = &self.extra_outputs[0];
        if self.output.element_count() != 1 {
            return Err(DmlError::invalid(
                "nonzero count output must contain exactly one element",
            ));
        }
        if coordinates.sizes.len() != 2 || coordinates.sizes[1] != rank as u32 {
            return Err(DmlError::invalid(format!(
                "nonzero coordinate output must be rank-2 with {rank} columns"
            )));
        }
        let maximum = input.element_count();
        if (coordinates.sizes[0] as u64) < maximum {
            return Err(DmlError::invalid(format!(
                "nonzero coordinate output provides {} rows but the input can produce up to {maximum}",
                coordinates.sizes[0]
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_diagonal1(
        &self,
        offset_begin: i32,
        offset_end: i32,
        value: f32,
    ) -> DmlResult<()> {
        if !(2..=4).contains(&self.output.sizes.len()) {
            return Err(DmlError::invalid(
                "diagonal matrix1 output must have rank 2 to 4",
            ));
        }
        if self.inputs.len() > 1 {
            return Err(DmlError::invalid(
                "diagonal matrix1 accepts at most one input tensor",
            ));
        }
        if let Some(input) = self.inputs.first() {
            if input.sizes != self.output.sizes {
                return Err(DmlError::invalid(
                    "diagonal matrix1 input and output sizes must match",
                ));
            }
        }
        if !value.is_finite() {
            return Err(DmlError::invalid("diagonal matrix1 value must be finite"));
        }
        let _ = (offset_begin, offset_end);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_mha(
        &self,
        scale: f32,
        mask_filter_value: f32,
        query_head_count: u32,
        key_value_head_count: u32,
        mask_type: u32,
        layout: DmlMhaLayout,
        has_bias: bool,
        has_mask: bool,
    ) -> DmlResult<()> {
        if layout != DmlMhaLayout::Separate {
            return Err(DmlError::invalid(
                "multi-head attention stacked query/key/value tensors are not supported",
            ));
        }
        if !scale.is_finite() || !mask_filter_value.is_finite() {
            return Err(DmlError::invalid(
                "multi-head attention scale and mask filter value must be finite",
            ));
        }
        if query_head_count == 0 || key_value_head_count == 0 {
            return Err(DmlError::invalid(
                "multi-head attention head counts must be non-zero",
            ));
        }
        if query_head_count % key_value_head_count != 0 {
            return Err(DmlError::invalid(format!(
                "multi-head attention query head count {query_head_count} must be a multiple of key/value head count {key_value_head_count}"
            )));
        }
        if mask_type > 4 {
            return Err(DmlError::invalid(format!(
                "multi-head attention mask type {mask_type} is undefined"
            )));
        }
        if mask_type == 3 {
            return Err(DmlError::invalid(
                "multi-head attention mask type 3 is not supported",
            ));
        }
        if has_mask && mask_type == 0 {
            return Err(DmlError::invalid(
                "multi-head attention mask tensor requires a non-NONE mask type",
            ));
        }
        if !has_mask && mask_type != 0 {
            return Err(DmlError::invalid(
                "multi-head attention mask type requires a mask tensor",
            ));
        }
        let expected = 3 + usize::from(has_bias) + usize::from(has_mask);
        if self.inputs.len() != expected {
            return Err(DmlError::invalid(format!(
                "multi-head attention expects {expected} input tensors, got {}",
                self.inputs.len()
            )));
        }
        if !self.extra_outputs.is_empty() {
            return Err(DmlError::invalid(
                "multi-head attention present key/value outputs are not supported",
            ));
        }
        let query = &self.inputs[0];
        let key = &self.inputs[1];
        let value = &self.inputs[2];
        if query.sizes.len() < 3
            || key.sizes.len() != query.sizes.len()
            || value.sizes.len() != query.sizes.len()
        {
            return Err(DmlError::invalid(
                "multi-head attention query, key, and value tensors must have the same rank >= 3",
            ));
        }
        let rank = query.sizes.len();
        for tensor in [query, key, value] {
            if tensor.sizes[..rank - 3].iter().any(|size| *size != 1) {
                return Err(DmlError::invalid(
                    "multi-head attention leading dimensions must be 1",
                ));
            }
        }
        let batch = query.sizes[rank - 3];
        let sequence = query.sizes[rank - 2];
        let query_hidden = query.sizes[rank - 1];
        if key.sizes[rank - 3] != batch || value.sizes[rank - 3] != batch {
            return Err(DmlError::invalid(
                "multi-head attention batch sizes must match",
            ));
        }
        let key_sequence = key.sizes[rank - 2];
        if value.sizes[rank - 2] != key_sequence {
            return Err(DmlError::invalid(
                "multi-head attention key and value sequence lengths must match",
            ));
        }
        if query_hidden % query_head_count != 0 {
            return Err(DmlError::invalid(
                "multi-head attention query hidden size must be divisible by the query head count",
            ));
        }
        if key.sizes[rank - 1] != query_hidden {
            return Err(DmlError::invalid(
                "multi-head attention query and key hidden sizes must match",
            ));
        }
        let value_hidden = value.sizes[rank - 1];
        if value_hidden % key_value_head_count != 0 {
            return Err(DmlError::invalid(
                "multi-head attention value hidden size must be divisible by the key/value head count",
            ));
        }
        if self.output.sizes.len() != rank {
            return Err(DmlError::invalid(
                "multi-head attention output rank must match the query rank",
            ));
        }
        let expected_output = [batch, sequence, value_hidden];
        if self.output.sizes[rank - 3..] != expected_output {
            return Err(DmlError::invalid(format!(
                "multi-head attention output trailing sizes must be {expected_output:?}, got {:?}",
                &self.output.sizes[rank - 3..]
            )));
        }
        if self.output.sizes[..rank - 3].iter().any(|size| *size != 1) {
            return Err(DmlError::invalid(
                "multi-head attention output leading dimensions must be 1",
            ));
        }
        if has_bias {
            let bias = &self.inputs[3];
            let expected_bias = query_hidden as u64 * 2 + value_hidden as u64;
            if bias.element_count() != expected_bias {
                return Err(DmlError::invalid(format!(
                    "multi-head attention bias must contain {expected_bias} elements, got {}",
                    bias.element_count()
                )));
            }
        }
        if has_mask {
            let mask = &self.inputs[3 + usize::from(has_bias)];
            let mask_elements = mask.element_count();
            let expected_mask = match mask_type {
                1 => key_sequence as u64,
                2 => 2,
                3 => 2,
                4 => {
                    if mask.sizes.len() != rank {
                        return Err(DmlError::invalid(
                            "multi-head attention boolean mask rank must match the query rank",
                        ));
                    }
                    batch as u64 * query_head_count as u64 * sequence as u64 * key_sequence as u64
                }
                _ => 0,
            };
            if mask_type == 4 && mask_elements != expected_mask {
                return Err(DmlError::invalid(format!(
                    "multi-head attention boolean mask must contain {expected_mask} elements, got {mask_elements}"
                )));
            }
            if mask_type != 4 && mask_elements == 0 {
                return Err(DmlError::invalid(
                    "multi-head attention mask must not be empty",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_one_hot(&self, axis: u32) -> DmlResult<()> {
        self.require_input_count(2)?;
        let indices = &self.inputs[0];
        let values = &self.inputs[1];
        let expected_rank = indices.sizes.len() + 1;
        if self.output.sizes.len() != expected_rank {
            return Err(DmlError::invalid(format!(
                "one-hot output rank {} must be indices rank {} plus one",
                self.output.sizes.len(),
                indices.sizes.len()
            )));
        }
        if axis as usize >= expected_rank {
            return Err(DmlError::invalid(format!(
                "one-hot axis {axis} is out of range for output rank {expected_rank}"
            )));
        }
        let depth = values.element_count();
        if depth != 2 {
            return Err(DmlError::invalid(format!(
                "one-hot values tensor must contain exactly 2 elements, got {depth}"
            )));
        }
        if self.output.sizes[axis as usize] != depth as u32 {
            return Err(DmlError::invalid(format!(
                "one-hot output axis {axis} size {} must equal the values count {depth}",
                self.output.sizes[axis as usize]
            )));
        }
        let mut source = 0;
        for (dimension, size) in self.output.sizes.iter().enumerate() {
            if dimension == axis as usize {
                continue;
            }
            if *size != indices.sizes[source] {
                return Err(DmlError::invalid(format!(
                    "one-hot output dimension {dimension} size {size} must match indices dimension {source} size {}",
                    indices.sizes[source]
                )));
            }
            source += 1;
        }
        Ok(())
    }

    pub(crate) fn validate_cumulative(&self, axis: u32) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        if input.sizes != self.output.sizes {
            return Err(DmlError::invalid(
                "cumulative input and output sizes must match",
            ));
        }
        if axis as usize >= input.sizes.len() {
            return Err(DmlError::invalid(format!(
                "cumulative axis {axis} is out of range for rank {}",
                input.sizes.len()
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_reverse(&self, axis: u32) -> DmlResult<()> {
        self.require_input_count(2)?;
        let input = &self.inputs[0];
        if input.sizes != self.output.sizes {
            return Err(DmlError::invalid(
                "reverse input and output sizes must match",
            ));
        }
        if axis as usize >= input.sizes.len() {
            return Err(DmlError::invalid(format!(
                "reverse axis {axis} is out of range for rank {}",
                input.sizes.len()
            )));
        }
        let sequence_count = input.sizes.iter().take(axis as usize).product::<u32>();
        if self.inputs[1].element_count() != sequence_count.max(1) as u64 {
            return Err(DmlError::invalid(format!(
                "reverse sequence lengths must contain {} elements, got {}",
                sequence_count.max(1),
                self.inputs[1].element_count()
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_adam(
        &self,
        learning_rate: f32,
        beta1: f32,
        beta2: f32,
        epsilon: f32,
    ) -> DmlResult<()> {
        if self.inputs.len() != 5 {
            return Err(DmlError::invalid(format!(
                "Adam optimizer requires 5 input tensors, got {}",
                self.inputs.len()
            )));
        }
        if self.output_count() != 3 {
            return Err(DmlError::invalid(
                "Adam optimizer requires parameter, first moment, and second moment outputs",
            ));
        }
        let sizes = self.inputs[0].sizes.clone();
        for (index, input) in self.inputs[..4].iter().enumerate() {
            if !input.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "Adam input {index} must be contiguous"
                )));
            }
            if input.sizes != sizes {
                return Err(DmlError::invalid(format!(
                    "Adam input {index} sizes must match the parameters sizes {sizes:?}"
                )));
            }
        }
        if self.inputs[4].element_count() != 1 || !self.inputs[4].is_contiguous() {
            return Err(DmlError::invalid(
                "Adam training step must be a single contiguous element",
            ));
        }
        for (index, output) in self.outputs().enumerate() {
            if !output.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "Adam output {index} must be contiguous"
                )));
            }
            if output.sizes != sizes {
                return Err(DmlError::invalid(format!(
                    "Adam output {index} sizes must match the parameters sizes {sizes:?}"
                )));
            }
        }
        if !learning_rate.is_finite() || learning_rate <= 0.0 {
            return Err(DmlError::invalid(
                "Adam learning rate must be finite and positive",
            ));
        }
        if !(0.0..1.0).contains(&beta1) || !(0.0..1.0).contains(&beta2) {
            return Err(DmlError::invalid("Adam beta1 and beta2 must be in [0, 1)"));
        }
        if !epsilon.is_finite() || epsilon <= 0.0 {
            return Err(DmlError::invalid(
                "Adam epsilon must be finite and positive",
            ));
        }
        Ok(())
    }
}

pub(crate) fn emit_fill_msl(
    plan: &DmlOpPlan,
    value: f32,
    step: f32,
    sequence: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    let expression = if sequence {
        format!("{} + gid * {}", msl_float(value), msl_float(step))
    } else {
        msl_float(value)
    };
    source.push_str(&format!(
        "    out[{}] = ({scalar})({expression});\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_one_hot_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let indices = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut coords = Vec::new();
    for dimension in 0..plan.output.sizes.len() {
        if dimension != axis as usize {
            coords.push(format!("o{dimension}"));
        }
    }
    source.push_str(&format!(
        "    int index = int({});\n",
        msl_load_native(indices, "in0", &linear_index(indices, &coords))
    ));
    source.push_str(&format!(
        "    uint depth = {}u;\n",
        plan.output.sizes[axis as usize]
    ));
    source.push_str("    float on_value = float(in1[0]);\n");
    source.push_str("    float off_value = float(in1[1]);\n");
    source.push_str("    bool valid = index >= 0 && uint(index) < depth;\n");
    source.push_str(&format!(
        "    out[{}] = ({scalar})(valid && uint(index) == o{axis} ? on_value : off_value);\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_cumulative_msl(
    plan: &DmlOpPlan,
    product: bool,
    axis: u32,
    reverse: bool,
    exclusive: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut base = Vec::new();
    for dimension in 0..input.sizes.len() {
        if dimension != axis as usize {
            base.push(format!("o{dimension} * {}u", input.strides[dimension]));
        }
    }
    let base = if base.is_empty() {
        "0u".to_string()
    } else {
        base.join(" + ")
    };
    let axis_size = input.sizes[axis as usize];
    let axis_stride = input.strides[axis as usize];
    source.push_str(&format!("    uint base = {base};\n"));
    source.push_str(&format!("    uint axis = o{axis};\n"));
    source.push_str(&format!(
        "    float acc = {};\n",
        if product { "1.0f" } else { "0.0f" }
    ));
    if reverse {
        source.push_str(&format!(
            "    for (uint j = axis; j < {axis_size}u; ++j) {{\n"
        ));
        if exclusive {
            source.push_str("        if (j == axis) continue;\n");
        }
    } else {
        source.push_str("    for (uint j = 0u; j <= axis; ++j) {\n");
        if exclusive {
            source.push_str("        if (j == axis) continue;\n");
        }
    }
    source.push_str(&format!(
        "        float v = {};\n",
        msl_load_float(input, "in0", &format!("base + j * {axis_stride}u"))
    ));
    source.push_str(if product {
        "        acc *= v;\n"
    } else {
        "        acc += v;\n"
    });
    source.push_str("    }\n");
    source.push_str(&format!(
        "    out[{}] = ({scalar})acc;\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_reverse_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let lengths = &plan.inputs[1];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut sequence = Vec::new();
    for dimension in 0..axis as usize {
        sequence.push(format!("o{dimension} * {}u", lengths.strides[dimension]));
    }
    let sequence_index = if sequence.is_empty() {
        "0u".to_string()
    } else {
        sequence.join(" + ")
    };
    source.push_str(&format!(
        "    uint length = uint({});\n",
        msl_load_native(lengths, "in1", &sequence_index)
    ));
    source.push_str(&format!("    uint reversed = o{axis};\n"));
    source.push_str(&format!(
        "    if (o{axis} < length) reversed = length - 1u - o{axis};\n"
    ));
    let mut coords = Vec::new();
    for dimension in 0..input.sizes.len() {
        if dimension == axis as usize {
            coords.push("reversed".to_string());
        } else {
            coords.push(format!("o{dimension}"));
        }
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})({});\n",
        output_index_expr(&plan.output),
        msl_load_float(input, "in0", &linear_index(input, &coords))
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_diagonal_matrix_msl(
    plan: &DmlOpPlan,
    offset: i32,
    value: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    bool selected = (int(o1) - int(o0)) == {offset};\n"
    ));
    source.push_str(&format!(
        "    out[{}] = ({scalar})(selected ? {} : 0.0f);\n",
        output_index_expr(&plan.output),
        msl_float(value)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_random_generator_msl(
    plan: &DmlOpPlan,
    _generator_type: u32,
) -> DmlResult<String> {
    let mut output_scalars = vec!["uint"];
    if !plan.extra_outputs.is_empty() {
        output_scalars.push("uint");
    }
    let mut source = msl_header_outputs(plan, "uint", &output_scalars);
    push_guard(&mut source, &plan.output);
    source.push_str("    uint total = ");
    source.push_str(&plan.output.element_count().to_string());
    source.push_str("u;\n");
    source.push_str("    uint blocks = (total + 3u) / 4u;\n");
    source.push_str("    uint add = gid / 4u;\n    uint c0 = in0[0] + add;\n    uint carry = c0 < in0[0] ? 1u : 0u;\n    uint c1 = in0[1] + carry;\n    carry = c1 < in0[1] ? 1u : 0u;\n    uint c2 = in0[2] + carry;\n    carry = c2 < in0[2] ? 1u : 0u;\n    uint c3 = in0[3] + carry;\n");
    source.push_str("    uint k0 = in0[4];\n    uint k1 = in0[5];\n");
    source.push_str(
        "    uint component = gid % 4u;\n    uint m0 = 0xD2511F53u;\n    uint m1 = 0xCD9E8D57u;\n",
    );
    source.push_str("    for (uint round = 0u; round < 10u; ++round) {\n");
    source.push_str("        ulong p0 = ulong(m0) * ulong(c0);\n        ulong p1 = ulong(m1) * ulong(c2);\n        uint hi0 = uint(p0 >> 32);\n        uint lo0 = uint(p0);\n        uint hi1 = uint(p1 >> 32);\n        uint lo1 = uint(p1);\n        uint n0 = hi1 ^ c1 ^ k0;\n        uint n1 = lo1;\n        uint n2 = hi0 ^ c3 ^ k1;\n        uint n3 = lo0;\n        c0 = n0; c1 = n1; c2 = n2; c3 = n3;\n        k0 += 0x9E3779B9u;\n        k1 += 0xBB67AE85u;\n    }\n");
    source.push_str("    uint value = component == 0u ? c0 : (component == 1u ? c1 : (component == 2u ? c2 : c3));\n");
    source.push_str(&format!(
        "    out0[{}] = value;\n",
        output_index_expr(&plan.output)
    ));
    if !plan.extra_outputs.is_empty() {
        source.push_str("    if (gid == 0u) {\n");
        source.push_str("        uint a0 = in0[0] + blocks;\n        uint carry0 = a0 < in0[0] ? 1u : 0u;\n        uint a1 = in0[1] + carry0;\n        uint carry1 = a1 < in0[1] ? 1u : 0u;\n        uint a2 = in0[2] + carry1;\n        uint carry2 = a2 < in0[2] ? 1u : 0u;\n        uint a3 = in0[3] + carry2;\n");
        source.push_str(
            "        out1[0u] = a0;\n        out1[1u] = a1;\n        out1[2u] = a2;\n        out1[3u] = a3;\n        out1[4u] = in0[4];\n        out1[5u] = in0[5];\n",
        );
        source.push_str("    }\n");
    }
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_nonzero_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let count = input.element_count();
    let mut source = msl_header_outputs(plan, "uint", &["uint", "uint"]);
    source.push_str("    if (gid != 0u) return;\n    uint found = 0u;\n");
    source.push_str(&format!("    for (uint i = 0u; i < {count}u; ++i) {{\n"));
    let mut coords = Vec::with_capacity(rank);
    for dimension in 0..rank {
        let divisor: u64 = input.sizes[dimension + 1..]
            .iter()
            .map(|value| *value as u64)
            .product();
        source.push_str(&format!(
            "        uint c{dimension} = (i / {divisor}u) % {}u;\n",
            input.sizes[dimension]
        ));
        coords.push(format!("c{dimension}"));
    }
    source.push_str(&format!(
        "        if (in0[{}] != 0) {{\n",
        linear_index(input, &coords)
    ));
    let coordinate_stride = plan.extra_outputs[0].strides[0];
    let coordinate_inner = plan.extra_outputs[0].strides[1];
    for dimension in 0..rank {
        source.push_str(&format!(
            "            out1[found * {coordinate_stride}u + {dimension} * {coordinate_inner}u] = c{dimension};\n"
        ));
    }
    source.push_str("            found += 1u;\n        }\n    }\n");
    source.push_str(&format!(
        "    out0[{}] = found;\n}}\n",
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

pub(crate) fn emit_diagonal1_msl(
    plan: &DmlOpPlan,
    offset_begin: i32,
    offset_end: i32,
    value: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let output = &plan.output;
    let rank = output.sizes.len();
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, output);
    push_output_coords(&mut source, output);
    let reversed = offset_begin > offset_end;
    let low = offset_begin.min(offset_end);
    let high = offset_begin.max(offset_end);
    source.push_str(&format!(
        "    int diagonal = int(o{}) - int(o{});\n    bool inside = diagonal >= {low} && diagonal < {high};\n    bool fill = {};\n",
        rank - 1,
        rank - 2,
        if reversed { "!inside" } else { "inside" }
    ));
    if plan.inputs.is_empty() {
        source.push_str(&format!(
            "    out[{}] = ({scalar})(fill ? {} : 0.0f);\n}}\n",
            output_index_expr(output),
            msl_float(value)
        ));
    } else {
        source.push_str(&format!(
            "    out[{}] = ({scalar})(fill ? {} : float(in0[{}]));\n}}\n",
            output_index_expr(output),
            msl_float(value),
            linear_index(&plan.inputs[0], &coord_names(rank))
        ));
    }
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_mha_msl(
    plan: &DmlOpPlan,
    scale: f32,
    mask_filter_value: f32,
    query_head_count: u32,
    key_value_head_count: u32,
    mask_type: u32,
    has_bias: bool,
    has_mask: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let query = &plan.inputs[0];
    let key = &plan.inputs[1];
    let value = &plan.inputs[2];
    let rank = query.sizes.len();
    let batch = query.sizes[rank - 3];
    let sequence = query.sizes[rank - 2];
    let query_hidden = query.sizes[rank - 1];
    let key_sequence = key.sizes[rank - 2];
    let value_hidden = value.sizes[rank - 1];
    let query_head_size = query_hidden / query_head_count;
    let value_head_size = value_hidden / key_value_head_count;
    let group = query_head_count / key_value_head_count;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let bias_index = 3;
    let mask_index = 3 + usize::from(has_bias);
    source.push_str(&format!(
        "    uint head = o{} / {value_head_size}u;\n    uint value_column = o{} % {value_head_size}u;\n    uint query_head = head * {group}u;\n",
        rank - 1,
        rank - 1
    ));
    source.push_str("    float max_score = -INFINITY;\n");
    source.push_str(&format!(
        "    for (uint kv = 0u; kv < {key_sequence}u; ++kv) {{\n"
    ));
    source.push_str("        float score = 0.0f;\n");
    source.push_str(&format!(
        "        for (uint d = 0u; d < {query_head_size}u; ++d) {{\n"
    ));
    let q_index = format!(
        "o{} * {}u + o{} * {}u + query_head * {query_head_size}u + d",
        rank - 3,
        query.strides[rank - 3],
        rank - 2,
        query.strides[rank - 2],
        query_head_size = query_head_size
    );
    let k_index = format!(
        "o{} * {}u + kv * {}u + head * {query_head_size}u + d",
        rank - 3,
        key.strides[rank - 3],
        key.strides[rank - 2],
        query_head_size = query_head_size
    );
    if has_bias {
        source.push_str(&format!(
            "            float q = float(in0[{q_index}]) + float(in{bias}[query_head * {query_head_size}u + d]);\n            float k = float(in1[{k_index}]) + float(in{bias}[{query_hidden}u + head * {query_head_size}u + d]);\n            score += q * k;\n",
            bias = bias_index
        ));
    } else {
        source.push_str(&format!(
            "            score += float(in0[{q_index}]) * float(in1[{k_index}]);\n"
        ));
    }
    source.push_str("        }\n");
    source.push_str(&format!("        score *= {};\n", msl_float(scale)));
    if has_mask {
        match mask_type {
            4 => {
                source.push_str(&format!(
                    "        uint mask_index = (((o{} * {query_head_count}u + query_head) * {sequence}u + o{}) * {key_sequence}u + kv);\n        if (in{mask}[mask_index] == 0) score = {filter};\n",
                    rank - 3,
                    rank - 2,
                    mask = mask_index,
                    filter = msl_float(mask_filter_value)
                ));
            }
            1 => {
                source.push_str(&format!(
                    "        uint length = uint(in{mask}[o{} * {stride}u]);\n        if (kv >= length) score = {filter};\n",
                    rank - 3,
                    mask = mask_index,
                    stride = plan.inputs[mask_index].strides[rank - 3],
                    filter = msl_float(mask_filter_value)
                ));
            }
            2 => {
                source.push_str(&format!(
                    "        uint mask_base = o{} * {stride}u;\n        uint start = uint(in{mask}[mask_base]);\n        uint end = uint(in{mask}[mask_base + 1u]);\n        if (kv < start || kv >= end) score = {filter};\n",
                    rank - 3,
                    mask = mask_index,
                    stride = plan.inputs[mask_index].strides[rank - 3],
                    filter = msl_float(mask_filter_value)
                ));
            }
            _ => {
                source.push_str(&format!(
                    "        score = {filter};\n",
                    filter = msl_float(mask_filter_value)
                ));
            }
        }
    }
    source.push_str("        max_score = fmax(max_score, score);\n    }\n");
    source.push_str("    float sum = 0.0f;\n");
    source.push_str(&format!(
        "    for (uint kv = 0u; kv < {key_sequence}u; ++kv) {{\n"
    ));
    source.push_str("        float score = 0.0f;\n");
    source.push_str(&format!(
        "        for (uint d = 0u; d < {query_head_size}u; ++d) {{\n"
    ));
    if has_bias {
        source.push_str(&format!(
            "            float q = float(in0[{q_index}]) + float(in{bias}[query_head * {query_head_size}u + d]);\n            float k = float(in1[{k_index}]) + float(in{bias}[{query_hidden}u + head * {query_head_size}u + d]);\n            score += q * k;\n",
            bias = bias_index
        ));
    } else {
        source.push_str(&format!(
            "            score += float(in0[{q_index}]) * float(in1[{k_index}]);\n"
        ));
    }
    source.push_str("        }\n");
    source.push_str(&format!("        score *= {};\n", msl_float(scale)));
    if has_mask {
        match mask_type {
            4 => {
                source.push_str(&format!(
                    "        uint mask_index = (((o{} * {query_head_count}u + query_head) * {sequence}u + o{}) * {key_sequence}u + kv);\n        if (in{mask}[mask_index] == 0) score = {filter};\n",
                    rank - 3,
                    rank - 2,
                    mask = mask_index,
                    filter = msl_float(mask_filter_value)
                ));
            }
            1 => {
                source.push_str(&format!(
                    "        uint length = uint(in{mask}[o{} * {stride}u]);\n        if (kv >= length) score = {filter};\n",
                    rank - 3,
                    mask = mask_index,
                    stride = plan.inputs[mask_index].strides[rank - 3],
                    filter = msl_float(mask_filter_value)
                ));
            }
            2 => {
                source.push_str(&format!(
                    "        uint mask_base = o{} * {stride}u;\n        uint start = uint(in{mask}[mask_base]);\n        uint end = uint(in{mask}[mask_base + 1u]);\n        if (kv < start || kv >= end) score = {filter};\n",
                    rank - 3,
                    mask = mask_index,
                    stride = plan.inputs[mask_index].strides[rank - 3],
                    filter = msl_float(mask_filter_value)
                ));
            }
            _ => {
                source.push_str(&format!(
                    "        score = {filter};\n",
                    filter = msl_float(mask_filter_value)
                ));
            }
        }
    }
    source.push_str("        sum += exp(score - max_score);\n    }\n");
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!(
        "    for (uint kv = 0u; kv < {key_sequence}u; ++kv) {{\n"
    ));
    source.push_str("        float score = 0.0f;\n");
    source.push_str(&format!(
        "        for (uint d = 0u; d < {query_head_size}u; ++d) {{\n"
    ));
    if has_bias {
        source.push_str(&format!(
            "            float q = float(in0[{q_index}]) + float(in{bias}[query_head * {query_head_size}u + d]);\n            float k = float(in1[{k_index}]) + float(in{bias}[{query_hidden}u + head * {query_head_size}u + d]);\n            score += q * k;\n",
            bias = bias_index
        ));
    } else {
        source.push_str(&format!(
            "            score += float(in0[{q_index}]) * float(in1[{k_index}]);\n"
        ));
    }
    source.push_str("        }\n");
    source.push_str(&format!("        score *= {};\n", msl_float(scale)));
    if has_mask {
        match mask_type {
            4 => {
                source.push_str(&format!(
                    "        uint mask_index = (((o{} * {query_head_count}u + query_head) * {sequence}u + o{}) * {key_sequence}u + kv);\n        if (in{mask}[mask_index] == 0) score = {filter};\n",
                    rank - 3,
                    rank - 2,
                    mask = mask_index,
                    filter = msl_float(mask_filter_value)
                ));
            }
            1 => {
                source.push_str(&format!(
                    "        uint length = uint(in{mask}[o{} * {stride}u]);\n        if (kv >= length) score = {filter};\n",
                    rank - 3,
                    mask = mask_index,
                    stride = plan.inputs[mask_index].strides[rank - 3],
                    filter = msl_float(mask_filter_value)
                ));
            }
            2 => {
                source.push_str(&format!(
                    "        uint mask_base = o{} * {stride}u;\n        uint start = uint(in{mask}[mask_base]);\n        uint end = uint(in{mask}[mask_base + 1u]);\n        if (kv < start || kv >= end) score = {filter};\n",
                    rank - 3,
                    mask = mask_index,
                    stride = plan.inputs[mask_index].strides[rank - 3],
                    filter = msl_float(mask_filter_value)
                ));
            }
            _ => {
                source.push_str(&format!(
                    "        score = {filter};\n",
                    filter = msl_float(mask_filter_value)
                ));
            }
        }
    }
    let v_index = format!(
        "o{} * {}u + kv * {}u + head * {value_head_size}u + value_column",
        rank - 3,
        value.strides[rank - 3],
        value.strides[rank - 2],
        value_head_size = value_head_size
    );
    if has_bias {
        source.push_str(&format!(
            "        float v = float(in2[{v_index}]) + float(in{bias}[{offset}u + head * {value_head_size}u + value_column]);\n        acc += exp(score - max_score) / sum * v;\n",
            bias = bias_index,
            offset = query_hidden as u64 * 2,
            value_head_size = value_head_size
        ));
    } else {
        source.push_str(&format!(
            "        acc += exp(score - max_score) / sum * float(in2[{v_index}]);\n"
        ));
    }
    source.push_str("    }\n");
    source.push_str(&format!(
        "    out[{}] = ({scalar})acc;\n}}\n",
        output_index_expr(&plan.output)
    ));
    let _ = batch;
    Ok(source)
}

pub(crate) fn emit_adam_msl(
    plan: &DmlOpPlan,
    learning_rate: f32,
    beta1: f32,
    beta2: f32,
    epsilon: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let scalars = vec![scalar; 3];
    let mut source = msl_header_outputs(plan, scalar, &scalars);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str("    float step = float(in4[0]);\n");
    source.push_str(&format!(
        "    float correction1 = 1.0f - pow({}, step);\n",
        msl_float(beta1)
    ));
    source.push_str(&format!(
        "    float correction2 = 1.0f - pow({}, step);\n",
        msl_float(beta2)
    ));
    source.push_str(&format!(
        "    float first = {} * float(in1[gid]) + (1.0f - {}) * float(in3[gid]);\n",
        msl_float(beta1),
        msl_float(beta1)
    ));
    source.push_str(&format!(
        "    float second = {} * float(in2[gid]) + (1.0f - {}) * float(in3[gid]) * float(in3[gid]);\n",
        msl_float(beta2),
        msl_float(beta2)
    ));
    source.push_str(&format!(
        "    float adjusted = {0} * sqrt(correction2) / correction1;\n",
        msl_float(learning_rate)
    ));
    source.push_str(&format!(
        "    float updated = float(in0[gid]) - adjusted * first / (sqrt(second) + {});\n",
        msl_float(epsilon)
    ));
    source.push_str(&format!(
        "    out0[gid] = ({scalar})updated;\n    out1[gid] = ({scalar})first;\n    out2[gid] = ({scalar})second;\n"
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn philox_4x32_10(
    mut c0: u32,
    mut c1: u32,
    mut c2: u32,
    mut c3: u32,
    k0: u32,
    k1: u32,
) -> [u32; 4] {
    const M0: u32 = 0xD251_1F53;
    const M1: u32 = 0xCD9E_8D57;
    let mut k0 = k0;
    let mut k1 = k1;
    for _ in 0..10 {
        let p0 = (M0 as u64) * c0 as u64;
        let p1 = (M1 as u64) * c2 as u64;
        let hi0 = (p0 >> 32) as u32;
        let lo0 = p0 as u32;
        let hi1 = (p1 >> 32) as u32;
        let lo1 = p1 as u32;
        let n0 = hi1 ^ c1 ^ k0;
        let n1 = lo1;
        let n2 = hi0 ^ c3 ^ k1;
        let n3 = lo0;
        c0 = n0;
        c1 = n1;
        c2 = n2;
        c3 = n3;
        k0 = k0.wrapping_add(0x9E37_79B9);
        k1 = k1.wrapping_add(0xBB67_AE85);
    }
    [c0, c1, c2, c3]
}

pub(crate) fn execute_random_generator_cpu(
    plan: &DmlOpPlan,
    input_state: &[u8],
    output: &mut [u8],
    extras: &mut [&mut [u8]],
) -> DmlResult<()> {
    let state = &plan.inputs[0];
    let mut words = [0u32; 6];
    for (index, word) in words.iter_mut().enumerate() {
        *word = load_integer(input_state, index as u64, state.data_type) as u32;
    }
    let count = plan.output.element_count();
    for gid in 0..count {
        let block = gid / 4;
        let component = (gid % 4) as usize;
        let mut counter = [words[0], words[1], words[2], words[3]];
        let mut carry = block as u64;
        for word in counter.iter_mut() {
            let sum = *word as u64 + carry;
            *word = sum as u32;
            carry = sum >> 32;
        }
        let result = philox_4x32_10(
            counter[0], counter[1], counter[2], counter[3], words[4], words[5],
        );
        let coords = coords_of(gid, &plan.output.sizes);
        store_integer(
            output,
            index_of(&coords, &plan.output.strides),
            plan.output.data_type,
            result[component] as i64,
        );
    }
    if let Some(destination) = extras.first_mut() {
        let blocks = (count + 3) / 4;
        let mut counter = [words[0], words[1], words[2], words[3]];
        let mut carry = blocks as u64;
        for word in counter.iter_mut() {
            let sum = *word as u64 + carry;
            *word = sum as u32;
            carry = sum >> 32;
        }
        let values = [
            counter[0], counter[1], counter[2], counter[3], words[4], words[5],
        ];
        let state_desc = &plan.extra_outputs[0];
        let mut coords = vec![0u64; state_desc.sizes.len()];
        for (index, value) in values.iter().enumerate() {
            if let Some(last) = coords.last_mut() {
                *last = index as u64;
            }
            store_integer(
                destination,
                index_of(&coords, &state_desc.strides),
                state_desc.data_type,
                *value as i64,
            );
        }
    }
    Ok(())
}

pub(crate) fn execute_nonzero_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    coordinates: &mut [u8],
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let coordinates_desc = &plan.extra_outputs[0];
    let rank = input.sizes.len();
    let mut found = 0u64;
    for gid in 0..input.element_count() {
        let coords = coords_of(gid, &input.sizes);
        let value = load_scalar(
            input_bytes,
            index_of(&coords, &input.strides),
            input.data_type,
        );
        if value != 0.0 {
            for dimension in 0..rank {
                let index = (found as usize * coordinates_desc.strides[0] as usize)
                    + (dimension * coordinates_desc.strides[1] as usize);
                store_integer(
                    coordinates,
                    index as u64,
                    coordinates_desc.data_type,
                    coords[dimension] as i64,
                );
            }
            found += 1;
        }
    }
    store_integer(
        output,
        output_index(&plan.output, 0),
        plan.output.data_type,
        found as i64,
    );
    Ok(())
}

pub(crate) fn execute_diagonal1_cpu(
    plan: &DmlOpPlan,
    input_bytes: Option<&[u8]>,
    output: &mut [u8],
    offset_begin: i32,
    offset_end: i32,
    value: f32,
) -> DmlResult<()> {
    let output_desc = &plan.output;
    let dtype = output_desc.data_type;
    let rank = output_desc.sizes.len();
    let reversed = offset_begin > offset_end;
    let low = offset_begin.min(offset_end) as i64;
    let high = offset_begin.max(offset_end) as i64;
    for gid in 0..output_desc.element_count() {
        let coords = coords_of(gid, &output_desc.sizes);
        let diagonal = coords[rank - 1] as i64 - coords[rank - 2] as i64;
        let inside = diagonal >= low && diagonal < high;
        let fill = if reversed { !inside } else { inside };
        let result = if fill {
            value
        } else if let (Some(bytes), Some(input)) = (input_bytes, plan.inputs.first()) {
            load_scalar(bytes, index_of(&coords, &input.strides), dtype)
        } else {
            0.0
        };
        store_scalar(output, output_index(output_desc, gid), dtype, result);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_mha_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    scale: f32,
    mask_filter_value: f32,
    query_head_count: u32,
    key_value_head_count: u32,
    mask_type: u32,
    has_bias: bool,
    has_mask: bool,
) -> DmlResult<()> {
    let query = &plan.inputs[0];
    let key = &plan.inputs[1];
    let value = &plan.inputs[2];
    let dtype = plan.output.data_type;
    let rank = query.sizes.len();
    let batch = query.sizes[rank - 3];
    let sequence = query.sizes[rank - 2];
    let query_hidden = query.sizes[rank - 1];
    let key_sequence = key.sizes[rank - 2];
    let value_hidden = value.sizes[rank - 1];
    let query_head_size = query_hidden / query_head_count;
    let value_head_size = value_hidden / key_value_head_count;
    let group = query_head_count / key_value_head_count;
    let bias_index = 3;
    let mask_index = 3 + usize::from(has_bias);
    for gid in 0..plan.output.element_count() {
        let coords = coords_of(gid, &plan.output.sizes);
        let b = coords[rank - 3];
        let query_position = coords[rank - 2];
        let value_column = coords[rank - 1];
        let head = value_column / value_head_size as u64;
        let local_value = value_column % value_head_size as u64;
        let query_head = head * group as u64;
        let mut scores = Vec::with_capacity(key_sequence as usize);
        let mut max_score = f32::NEG_INFINITY;
        for kv in 0..key_sequence as u64 {
            let mut score = 0.0f32;
            for d in 0..query_head_size as u64 {
                let q_coords = [b, query_position, query_head * query_head_size as u64 + d];
                let k_coords = [b, kv, head * query_head_size as u64 + d];
                let mut q = load_scalar(inputs[0], index_of(&q_coords, &query.strides), dtype);
                let mut k = load_scalar(inputs[1], index_of(&k_coords, &key.strides), dtype);
                if has_bias {
                    let q_bias = query_head * query_head_size as u64 + d;
                    let k_bias = query_hidden as u64 + head * query_head_size as u64 + d;
                    q += load_scalar(inputs[bias_index], q_bias, dtype);
                    k += load_scalar(inputs[bias_index], k_bias, dtype);
                }
                score += q * k;
            }
            score *= scale;
            if has_mask {
                let mask = &plan.inputs[mask_index];
                let filtered = match mask_type {
                    4 => {
                        let index = (((b * query_head_count as u64 + query_head)
                            * sequence as u64
                            + query_position)
                            * key_sequence as u64)
                            + kv;
                        load_scalar(inputs[mask_index], index, mask.data_type) == 0.0
                    }
                    1 => {
                        let length = load_scalar(
                            inputs[mask_index],
                            index_of(&[b], &mask.strides),
                            mask.data_type,
                        );
                        kv as f32 >= length
                    }
                    2 => {
                        let start = load_scalar(
                            inputs[mask_index],
                            index_of(&[b, 0], &mask.strides),
                            mask.data_type,
                        );
                        let end = load_scalar(
                            inputs[mask_index],
                            index_of(&[b, 1], &mask.strides),
                            mask.data_type,
                        );
                        (kv as f32) < start || (kv as f32) >= end
                    }
                    _ => true,
                };
                if filtered {
                    score = mask_filter_value;
                }
            }
            max_score = max_score.max(score);
            scores.push(score);
        }
        let sum: f64 = scores
            .iter()
            .map(|score| ((*score - max_score) as f64).exp())
            .sum();
        let mut acc = 0.0f64;
        for (kv, score) in scores.iter().enumerate() {
            let weight = ((*score - max_score) as f64).exp() / sum;
            let v_coords = [b, kv as u64, head * value_head_size as u64 + local_value];
            let mut v = load_scalar(inputs[2], index_of(&v_coords, &value.strides), dtype);
            if has_bias {
                let bias_offset =
                    query_hidden as u64 * 2 + head * value_head_size as u64 + local_value;
                v += load_scalar(inputs[bias_index], bias_offset, dtype);
            }
            acc += weight * v as f64;
        }
        store_scalar(output, output_index(&plan.output, gid), dtype, acc as f32);
    }
    let _ = (batch, has_mask);
    Ok(())
}

pub(crate) fn execute_adam_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    extras: &mut [&mut [u8]],
    learning_rate: f32,
    beta1: f32,
    beta2: f32,
    epsilon: f32,
) -> DmlResult<()> {
    let count = plan.output.element_count();
    let step = load_scalar(inputs[4], 0, plan.inputs[4].data_type);
    let correction1 = 1.0 - beta1.powf(step);
    let correction2 = 1.0 - beta2.powf(step);
    let adjusted = learning_rate * correction2.sqrt() / correction1;
    for gid in 0..count {
        let parameter = load_scalar(inputs[0], gid, plan.inputs[0].data_type);
        let first_old = load_scalar(inputs[1], gid, plan.inputs[1].data_type);
        let second_old = load_scalar(inputs[2], gid, plan.inputs[2].data_type);
        let gradient = load_scalar(inputs[3], gid, plan.inputs[3].data_type);
        let first = beta1 * first_old + (1.0 - beta1) * gradient;
        let second = beta2 * second_old + (1.0 - beta2) * gradient * gradient;
        let updated = parameter - adjusted * first / (second.sqrt() + epsilon);
        let index = output_index(&plan.output, gid);
        store_scalar(output, index, plan.output.data_type, updated);
        let first_desc = &plan.extra_outputs[0];
        let second_desc = &plan.extra_outputs[1];
        store_scalar(
            extras[0],
            output_index(first_desc, gid),
            first_desc.data_type,
            first,
        );
        store_scalar(
            extras[1],
            output_index(second_desc, gid),
            second_desc.data_type,
            second,
        );
    }
    Ok(())
}
