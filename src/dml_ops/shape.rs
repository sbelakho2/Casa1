//! Shape portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_space_depth(
        &self,
        to_depth: bool,
        block_size: u32,
        order: u32,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        if input.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "space/depth requires rank-4 NCHW tensors",
            ));
        }
        if block_size == 0 {
            return Err(DmlError::invalid("space/depth block size must be non-zero"));
        }
        if order > 1 {
            return Err(DmlError::invalid(format!(
                "space/depth order {order} is undefined"
            )));
        }
        let block = block_size as u64 * block_size as u64;
        let expected = if to_depth {
            if input.sizes[2] % block_size != 0 || input.sizes[3] % block_size != 0 {
                return Err(DmlError::invalid(
                    "space-to-depth input spatial dimensions must be divisible by the block size",
                ));
            }
            let channels = (input.sizes[1] as u64)
                .checked_mul(block)
                .ok_or_else(|| DmlError::invalid("space-to-depth channel count overflows"))?;
            if channels > u32::MAX as u64 {
                return Err(DmlError::invalid(
                    "space-to-depth channel count is out of range",
                ));
            }
            vec![
                input.sizes[0],
                channels as u32,
                input.sizes[2] / block_size,
                input.sizes[3] / block_size,
            ]
        } else {
            if input.sizes[1] as u64 % block != 0 {
                return Err(DmlError::invalid(
                    "depth-to-space input channels must be divisible by block size squared",
                ));
            }
            let height = input.sizes[2] as u64 * block_size as u64;
            let width = input.sizes[3] as u64 * block_size as u64;
            if height > u32::MAX as u64 || width > u32::MAX as u64 {
                return Err(DmlError::invalid(
                    "depth-to-space spatial dimensions are out of range",
                ));
            }
            vec![
                input.sizes[0],
                (input.sizes[1] as u64 / block) as u32,
                height as u32,
                width as u32,
            ]
        };
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "space/depth output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_slice_ex(
        &self,
        offsets: &[u32],
        sizes: &[u32],
        strides: &[i32],
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if offsets.len() != rank || sizes.len() != rank || strides.len() != rank {
            return Err(DmlError::invalid(format!(
                "slice1 offsets, sizes, and strides must have {rank} entries"
            )));
        }
        if self.output.sizes != sizes {
            return Err(DmlError::invalid(format!(
                "slice1 output sizes must be {sizes:?}, got {:?}",
                self.output.sizes
            )));
        }
        for dimension in 0..rank {
            if sizes[dimension] == 0 {
                return Err(DmlError::invalid(format!(
                    "slice1 size at axis {dimension} must be non-zero"
                )));
            }
            if strides[dimension] == 0 {
                return Err(DmlError::invalid(format!(
                    "slice1 stride at axis {dimension} must be non-zero"
                )));
            }
            let offset = offsets[dimension] as i64;
            let step = strides[dimension] as i64;
            let last = offset
                .checked_add((sizes[dimension] as i64 - 1).saturating_mul(step))
                .ok_or_else(|| DmlError::invalid("slice1 window overflows the input index"))?;
            if offset < 0
                || offset >= input.sizes[dimension] as i64
                || last < 0
                || last >= input.sizes[dimension] as i64
            {
                return Err(DmlError::invalid(format!(
                    "slice1 window at axis {dimension} exceeds input size {}",
                    input.sizes[dimension]
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_resample_grad(
        &self,
        mode: DmlInterpolationMode,
        _rounding: DmlAxisDirection,
        scales: &[f32],
        input_offsets: &[f32],
        output_offsets: &[f32],
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let gradient = &self.inputs[0];
        let rank = gradient.sizes.len();
        if scales.len() != rank || input_offsets.len() != rank || output_offsets.len() != rank {
            return Err(DmlError::invalid(format!(
                "resample gradient scales and pixel offsets must have {rank} entries"
            )));
        }
        if scales
            .iter()
            .any(|scale| !scale.is_finite() || *scale <= 0.0)
        {
            return Err(DmlError::invalid(
                "resample gradient scales must be finite and positive",
            ));
        }
        if input_offsets
            .iter()
            .chain(output_offsets)
            .any(|offset| !offset.is_finite())
        {
            return Err(DmlError::invalid(
                "resample gradient pixel offsets must be finite",
            ));
        }
        let _ = mode;
        if self.output.sizes.len() != rank {
            return Err(DmlError::invalid(
                "resample gradient output must have the same rank as the input gradient",
            ));
        }
        if gradient.sizes[0] != self.output.sizes[0] || gradient.sizes[1] != self.output.sizes[1] {
            return Err(DmlError::invalid(
                "resample gradient batch and channel sizes must match the output",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_slice_grad(
        &self,
        offsets: &[u32],
        sizes: &[u32],
        strides: &[i32],
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let gradient = &self.inputs[0];
        let rank = self.output.sizes.len();
        if gradient.sizes.len() != rank
            || offsets.len() != rank
            || sizes.len() != rank
            || strides.len() != rank
        {
            return Err(DmlError::invalid(format!(
                "slice gradient tensors and parameters must have {rank} entries"
            )));
        }
        if gradient.sizes != sizes {
            return Err(DmlError::invalid(format!(
                "slice gradient input gradient sizes must be {sizes:?}, got {:?}",
                gradient.sizes
            )));
        }
        for dimension in 0..rank {
            if sizes[dimension] == 0 || strides[dimension] == 0 {
                return Err(DmlError::invalid(format!(
                    "slice gradient size and stride at axis {dimension} must be non-zero"
                )));
            }
            let offset = offsets[dimension] as i64;
            let step = strides[dimension] as i64;
            let last = offset
                .checked_add((sizes[dimension] as i64 - 1).saturating_mul(step))
                .ok_or_else(|| {
                    DmlError::invalid("slice gradient window overflows the input index")
                })?;
            if offset < 0
                || offset >= self.output.sizes[dimension] as i64
                || last < 0
                || last >= self.output.sizes[dimension] as i64
            {
                return Err(DmlError::invalid(format!(
                    "slice gradient window at axis {dimension} exceeds output size {}",
                    self.output.sizes[dimension]
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_transpose(&self, permutation: &[u32]) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if permutation.len() != rank {
            return Err(DmlError::invalid(format!(
                "transpose permutation must have {rank} entries, got {}",
                permutation.len()
            )));
        }
        let mut seen = Vec::with_capacity(rank);
        for axis in permutation {
            if *axis as usize >= rank {
                return Err(DmlError::invalid(format!(
                    "transpose axis {axis} is out of range for rank {rank}"
                )));
            }
            if seen.contains(axis) {
                return Err(DmlError::invalid(format!(
                    "transpose axis {axis} appears more than once"
                )));
            }
            seen.push(*axis);
        }
        let expected: Vec<u32> = permutation
            .iter()
            .map(|axis| input.sizes[*axis as usize])
            .collect();
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "transpose output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_concat(&self, axis: u32) -> DmlResult<()> {
        let first = &self.inputs[0];
        let rank = first.sizes.len();
        if axis as usize >= rank {
            return Err(DmlError::invalid(format!(
                "concat axis {axis} is out of range for rank {rank}"
            )));
        }
        let mut axis_total = 0u64;
        for (index, input) in self.inputs.iter().enumerate() {
            if input.sizes.len() != rank {
                return Err(DmlError::invalid(format!(
                    "concat input {index} has rank {}, expected {rank}",
                    input.sizes.len()
                )));
            }
            for dimension in 0..rank {
                if dimension as u32 != axis && input.sizes[dimension] != first.sizes[dimension] {
                    return Err(DmlError::invalid(
                        "concat input sizes must match on non-axis dimensions",
                    ));
                }
            }
            axis_total += input.sizes[axis as usize] as u64;
        }
        if axis_total > u32::MAX as u64 {
            return Err(DmlError::invalid("concat output axis size overflows u32"));
        }
        let mut expected = first.sizes.clone();
        expected[axis as usize] = axis_total as u32;
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "concat output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_slice(
        &self,
        offsets: &[u32],
        sizes: &[u32],
        strides: &[u32],
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if offsets.len() != rank || sizes.len() != rank || strides.len() != rank {
            return Err(DmlError::invalid(format!(
                "slice offsets, sizes, and strides must have {rank} entries"
            )));
        }
        if self.output.sizes != sizes {
            return Err(DmlError::invalid(format!(
                "slice output sizes must be {sizes:?}, got {:?}",
                self.output.sizes
            )));
        }
        for dimension in 0..rank {
            if sizes[dimension] == 0 {
                return Err(DmlError::invalid(format!(
                    "slice size at axis {dimension} must be non-zero"
                )));
            }
            if strides[dimension] == 0 {
                return Err(DmlError::invalid(format!(
                    "slice stride at axis {dimension} must be non-zero"
                )));
            }
            let offset = offsets[dimension] as u64;
            let span = (sizes[dimension] as u64 - 1)
                .checked_mul(strides[dimension] as u64)
                .and_then(|value| offset.checked_add(value))
                .ok_or_else(|| {
                    DmlError::invalid(format!(
                        "slice window at axis {dimension} overflows the input index"
                    ))
                })?;
            if span >= input.sizes[dimension] as u64 {
                return Err(DmlError::invalid(format!(
                    "slice window at axis {dimension} exceeds input size {}",
                    input.sizes[dimension]
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_padding(
        &self,
        mode: DmlPaddingMode,
        start_padding: &[u32],
        end_padding: &[u32],
        _value: f32,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if start_padding.len() != rank || end_padding.len() != rank {
            return Err(DmlError::invalid(format!(
                "padding start and end padding must have {rank} entries"
            )));
        }
        let mut expected = vec![0u32; rank];
        for dimension in 0..rank {
            let padded = input.sizes[dimension] as u64
                + start_padding[dimension] as u64
                + end_padding[dimension] as u64;
            if padded == 0 || padded > u32::MAX as u64 {
                return Err(DmlError::invalid("padding output size is out of range"));
            }
            expected[dimension] = padded as u32;
            if matches!(mode, DmlPaddingMode::Reflection) {
                if start_padding[dimension] >= input.sizes[dimension]
                    || end_padding[dimension] >= input.sizes[dimension]
                {
                    return Err(DmlError::invalid(format!(
                        "reflection padding at axis {dimension} must be smaller than the input size {}",
                        input.sizes[dimension]
                    )));
                }
            }
            if matches!(mode, DmlPaddingMode::Symmetric) {
                if start_padding[dimension] > input.sizes[dimension]
                    || end_padding[dimension] > input.sizes[dimension]
                {
                    return Err(DmlError::invalid(format!(
                        "symmetric padding at axis {dimension} must not exceed the input size {}",
                        input.sizes[dimension]
                    )));
                }
            }
        }
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "padding output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_resample(
        &self,
        mode: DmlInterpolationMode,
        scales: &[f32],
        input_offsets: &[f32],
        output_offsets: &[f32],
        antialiased: bool,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if scales.len() != rank || input_offsets.len() != rank || output_offsets.len() != rank {
            return Err(DmlError::invalid(format!(
                "resample scales and pixel offsets must have {rank} entries"
            )));
        }
        if scales
            .iter()
            .any(|scale| !scale.is_finite() || *scale <= 0.0)
        {
            return Err(DmlError::invalid(
                "resample scales must be finite and positive",
            ));
        }
        if input_offsets
            .iter()
            .chain(output_offsets)
            .any(|offset| !offset.is_finite())
        {
            return Err(DmlError::invalid("resample pixel offsets must be finite"));
        }
        if antialiased && mode != DmlInterpolationMode::Linear {
            return Err(DmlError::invalid(
                "antialiased resample requires linear interpolation",
            ));
        }
        if self.output.sizes.len() != rank {
            return Err(DmlError::invalid(
                "resample output must have the same rank as the input",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_top_k(
        &self,
        axis: u32,
        k: u32,
        _direction: DmlAxisDirection,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if axis as usize >= rank {
            return Err(DmlError::invalid(format!(
                "top-k axis {axis} is out of range for rank {rank}"
            )));
        }
        if k == 0 || k > input.sizes[axis as usize] {
            return Err(DmlError::invalid(format!(
                "top-k K {k} must be in 1..={}",
                input.sizes[axis as usize]
            )));
        }
        let mut expected = input.sizes.clone();
        expected[axis as usize] = k;
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "top-k value output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        if self.extra_outputs.len() != 1 {
            return Err(DmlError::invalid(
                "top-k requires exactly one index output tensor",
            ));
        }
        if self.extra_outputs[0].sizes != expected {
            return Err(DmlError::invalid(format!(
                "top-k index output sizes must be {expected:?}, got {:?}",
                self.extra_outputs[0].sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_tile(&self, repeats: &[u32]) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if repeats.len() != rank {
            return Err(DmlError::invalid(format!(
                "tile repeats must have {rank} entries, got {}",
                repeats.len()
            )));
        }
        let mut expected = Vec::with_capacity(rank);
        for dimension in 0..rank {
            if repeats[dimension] == 0 {
                return Err(DmlError::invalid(format!(
                    "tile repeat at axis {dimension} must be non-zero"
                )));
            }
            let size = input.sizes[dimension] as u64 * repeats[dimension] as u64;
            if size == 0 || size > u32::MAX as u64 {
                return Err(DmlError::invalid("tile output size is out of range"));
            }
            expected.push(size as u32);
        }
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "tile output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_split(&self, axis: u32) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if axis as usize >= rank {
            return Err(DmlError::invalid(format!(
                "split axis {axis} is out of range for rank {rank}"
            )));
        }
        let output_count = self.output_count();
        if output_count == 0 {
            return Err(DmlError::invalid("split requires at least one output"));
        }
        if input.sizes[axis as usize] as u64 % output_count as u64 != 0 {
            return Err(DmlError::invalid(format!(
                "split axis size {} is not divisible by the output count {output_count}",
                input.sizes[axis as usize]
            )));
        }
        let chunk = input.sizes[axis as usize] / output_count as u32;
        for (index, output) in self.outputs().enumerate() {
            if output.sizes.len() != rank {
                return Err(DmlError::invalid(format!(
                    "split output {index} has rank {}, expected {rank}",
                    output.sizes.len()
                )));
            }
            for dimension in 0..rank {
                let expected = if dimension as u32 == axis {
                    chunk
                } else {
                    input.sizes[dimension]
                };
                if output.sizes[dimension] != expected {
                    return Err(DmlError::invalid(format!(
                        "split output {index} size at dimension {dimension} must be {expected}, got {}",
                        output.sizes[dimension]
                    )));
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn emit_space_depth_msl(
    plan: &DmlOpPlan,
    to_depth: bool,
    block_size: u32,
    order: u32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let block = block_size as u64;
    let output_channels = plan.output.sizes[1];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    if to_depth {
        let channels = input.sizes[1];
        let (i_expr, j_expr) = if order == 0 {
            (format!("t / {block}u"), format!("t % {block}u"))
        } else {
            (format!("t % {block}u"), format!("t / {block}u"))
        };
        source.push_str(&format!(
            "    uint c_in = o1 % {channels}u;\n    uint t = o1 / {channels}u;\n    uint i = {i_expr};\n    uint j = {j_expr};\n    uint h_in = o2 * {block}u + i;\n    uint w_in = o3 * {block}u + j;\n"
        ));
        let index = format!(
            "uint(o0) * {}u + c_in * {}u + h_in * {}u + w_in * {}u",
            input.strides[0], input.strides[1], input.strides[2], input.strides[3]
        );
        source.push_str(&format!(
            "    out[{}] = ({scalar})in0[{index}];\n}}\n",
            output_index_expr(&plan.output)
        ));
    } else {
        source.push_str(&format!(
            "    uint i = o2 % {block}u;\n    uint j = o3 % {block}u;\n    uint h = o2 / {block}u;\n    uint w = o3 / {block}u;\n"
        ));
        let (ci, cj) = if order == 0 { ("i", "j") } else { ("j", "i") };
        source.push_str(&format!(
            "    uint c_in = {ci} * {b}u * {output_channels}u + {cj} * {output_channels}u + o1;\n",
            b = block
        ));
        let index = format!(
            "uint(o0) * {}u + c_in * {}u + h * {}u + w * {}u",
            input.strides[0], input.strides[1], input.strides[2], input.strides[3]
        );
        source.push_str(&format!(
            "    out[{}] = ({scalar})in0[{index}];\n}}\n",
            output_index_expr(&plan.output)
        ));
    }
    Ok(source)
}

pub(crate) fn emit_slice_ex_msl(
    plan: &DmlOpPlan,
    offsets: &[u32],
    _sizes: &[u32],
    strides: &[i32],
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut coords = Vec::with_capacity(rank);
    for dimension in 0..rank {
        source.push_str(&format!(
            "    uint i{dimension} = uint({} + int(o{dimension}) * {});\n",
            offsets[dimension], strides[dimension]
        ));
        coords.push(format!("i{dimension}"));
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})in0[{}];\n}}\n",
        output_index_expr(&plan.output),
        linear_index(input, &coords)
    ));
    Ok(source)
}

pub(crate) fn emit_resample_grad_msl(
    plan: &DmlOpPlan,
    mode: DmlInterpolationMode,
    rounding: DmlAxisDirection,
    scales: &[f32],
    input_offsets: &[f32],
    output_offsets: &[f32],
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let gradient = &plan.inputs[0];
    let output = &plan.output;
    let rank = output.sizes.len();
    let gradient_count = gradient.element_count();
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, output);
    push_output_coords(&mut source, output);
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!(
        "    for (uint t = 0u; t < {gradient_count}u; ++t) {{\n"
    ));
    for dimension in 0..rank {
        let divisor: u64 = gradient.sizes[dimension + 1..]
            .iter()
            .map(|value| *value as u64)
            .product();
        source.push_str(&format!(
            "        uint g{dimension} = (t / {divisor}u) % {}u;\n",
            gradient.sizes[dimension]
        ));
        source.push_str(&format!(
            "        float s{dimension} = (float(g{dimension}) + {}) * {} + {};\n",
            msl_float(output_offsets[dimension]),
            msl_float(1.0 / scales[dimension]),
            msl_float(input_offsets[dimension])
        ));
    }
    source.push_str("        float weight = 0.0f;\n");
    if mode == DmlInterpolationMode::NearestNeighbor {
        let mut terms = Vec::new();
        for dimension in 0..rank {
            let round = match rounding {
                DmlAxisDirection::Increasing => format!("floor(s{dimension} + 0.5f)"),
                DmlAxisDirection::Decreasing => format!("ceil(s{dimension} - 0.5f)"),
            };
            source.push_str(&format!(
                "        int p{dimension} = clamp(int({round}), 0, {});\n",
                output.sizes[dimension] - 1
            ));
            terms.push(format!("p{dimension} == int(o{dimension})"));
        }
        source.push_str(&format!(
            "        weight = ({}) ? 1.0f : 0.0f;\n",
            terms.join(" && ")
        ));
    } else {
        source.push_str(&format!(
            "        for (uint mask = 0u; mask < {}u; ++mask) {{\n",
            1u32 << rank
        ));
        source.push_str("            float w = 1.0f;\n            bool match = true;\n");
        for dimension in 0..rank {
            source.push_str(&format!(
                "            int base{dimension} = int(floor(s{dimension}));\n            float f{dimension} = s{dimension} - floor(s{dimension});\n"
            ));
            source.push_str(&format!(
                "            uint b{dimension} = (mask >> {dimension}u) & 1u;\n"
            ));
            source.push_str(&format!(
                "            w *= b{dimension} != 0u ? f{dimension} : (1.0f - f{dimension});\n"
            ));
            source.push_str(&format!(
                "            int q{dimension} = clamp(base{dimension} + int(b{dimension}), 0, {});\n            if (q{dimension} != int(o{dimension})) match = false;\n",
                output.sizes[dimension] - 1
            ));
        }
        source.push_str("            if (match) weight += w;\n        }\n");
    }
    let gradient_coords = (0..rank)
        .map(|dimension| format!("uint(g{dimension})"))
        .collect::<Vec<_>>();
    source.push_str(&format!(
        "        acc += weight * float(in0[{}]);\n    }}\n    out[{}] = ({scalar})acc;\n}}\n",
        linear_index(gradient, &gradient_coords),
        output_index_expr(output)
    ));
    Ok(source)
}

pub(crate) fn emit_slice_grad_msl(
    plan: &DmlOpPlan,
    offsets: &[u32],
    sizes: &[u32],
    strides: &[i32],
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let gradient = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str("    bool valid = true;\n");
    let mut coords = Vec::with_capacity(sizes.len());
    for dimension in 0..sizes.len() {
        let step = strides[dimension];
        source.push_str(&format!(
            "    int d{dimension} = int(o{dimension}) - {};\n",
            offsets[dimension]
        ));
        if step > 0 {
            source.push_str(&format!(
                "    if (d{dimension} < 0 || d{dimension} % {step} != 0 || uint(d{dimension}) / {step}u >= {}u) valid = false;\n",
                sizes[dimension]
            ));
            coords.push(format!("uint(d{dimension}) / {step}u"));
        } else {
            source.push_str(&format!(
                "    if (d{dimension} > 0 || d{dimension} % {} != 0 || uint(-d{dimension}) / {}u >= {}u) valid = false;\n",
                -step as i64,
                -step as i64,
                sizes[dimension]
            ));
            coords.push(format!("uint(-d{dimension}) / {}u", -step as i64));
        }
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})(valid ? float(in0[{}]) : 0.0f);\n}}\n",
        output_index_expr(&plan.output),
        linear_index(gradient, &coords)
    ));
    Ok(source)
}

pub(crate) fn emit_reshape_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    if !plan.output.is_contiguous() {
        push_output_coords(&mut source, &plan.output);
    }
    for (index, size) in input.sizes.iter().enumerate() {
        let divisor: u64 = input.sizes[index + 1..]
            .iter()
            .map(|value| *value as u64)
            .product();
        source.push_str(&format!(
            "    uint i{index} = (gid / {divisor}u) % {size}u;\n"
        ));
    }
    let input_coords = (0..input.sizes.len())
        .map(|index| format!("i{index}"))
        .collect::<Vec<_>>();
    let index_expr = linear_index(input, &input_coords);
    source.push_str(&format!(
        "    out[{}] = in0[{index_expr}];\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_transpose_msl(plan: &DmlOpPlan, permutation: &[u32]) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut input_coords = vec![String::new(); permutation.len()];
    for (output_dimension, input_dimension) in permutation.iter().enumerate() {
        input_coords[*input_dimension as usize] = format!("o{output_dimension}");
    }
    let index_expr = linear_index(input, &input_coords);
    source.push_str(&format!(
        "    out[{}] = in0[{index_expr}];\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_concat_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let out_index = output_index_expr(&plan.output);
    source.push_str(&format!("    out[{out_index}] = ({scalar})0;\n"));
    let mut offset = 0u64;
    for (index, input) in plan.inputs.iter().enumerate() {
        let size = input.sizes[axis as usize] as u64;
        let mut coords = coord_names(input.sizes.len());
        coords[axis as usize] = if offset == 0 {
            format!("o{axis}")
        } else {
            format!("o{axis} - {offset}u")
        };
        let input_index = linear_index(input, &coords);
        if offset == 0 {
            source.push_str(&format!(
                "    if (o{axis} < {}u) out[{out_index}] = in{index}[{input_index}];\n",
                size
            ));
        } else {
            source.push_str(&format!(
                "    if (o{axis} >= {offset}u && o{axis} < {}u) out[{out_index}] = in{index}[{input_index}];\n",
                offset + size
            ));
        }
        offset += size;
    }
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_slice_msl(
    plan: &DmlOpPlan,
    offsets: &[u32],
    sizes: &[u32],
    strides: &[u32],
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let input_coords = (0..sizes.len())
        .map(|dimension| {
            if offsets[dimension] == 0 && strides[dimension] == 1 {
                format!("o{dimension}")
            } else {
                format!(
                    "o{dimension} * {}u + {}u",
                    strides[dimension], offsets[dimension]
                )
            }
        })
        .collect::<Vec<_>>();
    let index_expr = linear_index(input, &input_coords);
    source.push_str(&format!(
        "    out[{}] = in0[{index_expr}];\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_padding_msl(
    plan: &DmlOpPlan,
    mode: DmlPaddingMode,
    start_padding: &[u32],
    _end_padding: &[u32],
    value: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut coord_expr = Vec::with_capacity(input.sizes.len());
    let mut outside = Vec::new();
    for dimension in 0..input.sizes.len() {
        let size = input.sizes[dimension];
        let start = start_padding[dimension];
        source.push_str(&format!(
            "    int s{dimension} = int(o{dimension}) - {start};\n"
        ));
        match mode {
            DmlPaddingMode::Constant => {
                outside.push(format!("(s{dimension} < 0 || s{dimension} >= {size})"));
                source.push_str(&format!(
                    "    int p{dimension} = clamp(s{dimension}, 0, {});\n",
                    size - 1
                ));
            }
            DmlPaddingMode::Edge => {
                source.push_str(&format!(
                    "    int p{dimension} = clamp(s{dimension}, 0, {});\n",
                    size - 1
                ));
            }
            DmlPaddingMode::Reflection => {
                source.push_str(&format!(
                    "    while (s{dimension} < 0 || s{dimension} >= {size}) s{dimension} = s{dimension} < 0 ? -s{dimension} : {size} * 2 - 2 - s{dimension};\n"
                ));
                source.push_str(&format!("    int p{dimension} = s{dimension};\n"));
            }
            DmlPaddingMode::Symmetric => {
                source.push_str(&format!(
                    "    while (s{dimension} < 0 || s{dimension} >= {size}) s{dimension} = s{dimension} < 0 ? -s{dimension} - 1 : {size} * 2 - 1 - s{dimension};\n"
                ));
                source.push_str(&format!("    int p{dimension} = s{dimension};\n"));
            }
            DmlPaddingMode::Wrap => {
                source.push_str(&format!(
                    "    int p{dimension} = ((s{dimension} % {size}) + {size}) % {size};\n"
                ));
            }
        }
        coord_expr.push(format!("uint(p{dimension})"));
    }
    if mode == DmlPaddingMode::Constant {
        source.push_str(&format!(
            "    if ({}) {{ out[{}] = ({scalar})({}); return; }}\n",
            outside.join(" || "),
            output_index_expr(&plan.output),
            msl_float(value)
        ));
    }
    let index = linear_index(input, &coord_expr);
    source.push_str(&format!(
        "    out[{}] = in0[{index}];\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_resample_msl(
    plan: &DmlOpPlan,
    mode: DmlInterpolationMode,
    scales: &[f32],
    input_offsets: &[f32],
    output_offsets: &[f32],
    rounding: DmlAxisDirection,
    antialiased: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    for dimension in 0..rank {
        source.push_str(&format!(
            "    float s{dimension} = (float(o{dimension}) + {}) * {} + {};\n",
            msl_float(output_offsets[dimension]),
            msl_float(1.0 / scales[dimension]),
            msl_float(input_offsets[dimension])
        ));
    }
    let out_index = output_index_expr(&plan.output);
    if antialiased {
        for dimension in 0..rank {
            source.push_str(&format!(
                "    float r{dimension} = fmax(0.5f, 0.5f / {});\n",
                msl_float(scales[dimension])
            ));
            source.push_str(&format!(
                "    int start{dimension} = int(floor(s{dimension} - r{dimension}));\n"
            ));
            source.push_str(&format!(
                "    int end{dimension} = int(ceil(s{dimension} + r{dimension}));\n"
            ));
        }
        source.push_str("    float result = 0.0f;\n    float total = 0.0f;\n");
        let mut indent = String::from("    ");
        for dimension in 0..rank {
            source.push_str(&format!(
                "{indent}for (int q{dimension} = start{dimension}; q{dimension} <= end{dimension}; ++q{dimension}) {{\n"
            ));
            source.push_str(&format!(
                "{indent}    if (q{dimension} < 0 || q{dimension} >= {}) continue;\n",
                input.sizes[dimension]
            ));
            source.push_str(&format!(
                "{indent}    float w{dimension} = 1.0f - fabs(float(q{dimension}) - s{dimension}) / r{dimension};\n"
            ));
            source.push_str(&format!(
                "{indent}    if (w{dimension} <= 0.0f) continue;\n"
            ));
            indent.push_str("    ");
        }
        let index = linear_index(
            input,
            &(0..rank)
                .map(|dimension| format!("uint(q{dimension})"))
                .collect::<Vec<_>>(),
        );
        let weight = (0..rank)
            .map(|dimension| format!("w{dimension}"))
            .collect::<Vec<_>>()
            .join(" * ");
        source.push_str(&format!(
            "{indent}float weight = {weight};\n{indent}result += weight * float(in0[{index}]);\n{indent}total += weight;\n"
        ));
        for _ in 0..rank {
            indent.truncate(indent.len().saturating_sub(4));
            source.push_str(&format!("{indent}}}\n"));
        }
        source.push_str(&format!(
            "    out[{out_index}] = total <= 0.0f ? ({scalar})0 : ({scalar})(result / total);\n"
        ));
    } else if mode == DmlInterpolationMode::NearestNeighbor {
        let mut coords = Vec::with_capacity(rank);
        for dimension in 0..rank {
            let size = input.sizes[dimension];
            let round = match rounding {
                DmlAxisDirection::Increasing => format!("floor(s{dimension} + 0.5f)"),
                DmlAxisDirection::Decreasing => format!("ceil(s{dimension} - 0.5f)"),
            };
            source.push_str(&format!(
                "    int p{dimension} = clamp(int({round}), 0, {});\n",
                size - 1
            ));
            coords.push(format!("uint(p{dimension})"));
        }
        source.push_str(&format!(
            "    out[{out_index}] = in0[{}];\n",
            linear_index(input, &coords)
        ));
    } else {
        let mut coords = Vec::with_capacity(rank);
        for dimension in 0..rank {
            source.push_str(&format!(
                "    int p0_{dimension} = int(floor(s{dimension}));\n"
            ));
            source.push_str(&format!(
                "    float f{dimension} = s{dimension} - floor(s{dimension});\n"
            ));
            coords.push(format!("p0_{dimension}"));
        }
        source.push_str("    float result = 0.0f;\n");
        source.push_str(&format!(
            "    for (uint mask = 0u; mask < {}u; ++mask) {{\n",
            1u32 << rank
        ));
        source.push_str("        float weight = 1.0f;\n        uint index = 0u;\n");
        for dimension in 0..rank {
            let size = input.sizes[dimension];
            let stride = input.strides[dimension];
            source.push_str(&format!(
                "        uint b{dimension} = (mask >> {dimension}u) & 1u;\n"
            ));
            source.push_str(&format!(
                "        weight *= b{dimension} != 0u ? f{dimension} : (1.0f - f{dimension});\n"
            ));
            source.push_str(&format!(
                "        index += uint(clamp(p0_{dimension} + int(b{dimension}), 0, {})) * {stride}u;\n",
                size - 1
            ));
        }
        source.push_str("        result += weight * float(in0[index]);\n    }\n");
        source.push_str(&format!("    out[{out_index}] = ({scalar})result;\n"));
    }
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_top_k_msl(
    plan: &DmlOpPlan,
    axis: u32,
    k: u32,
    direction: DmlAxisDirection,
) -> DmlResult<String> {
    let input = &plan.inputs[0];
    let value_scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let mut source = msl_header_outputs(plan, value_scalar, &[value_scalar, "uint"]);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let axis_size = input.sizes[axis as usize];
    let axis_stride = input.strides[axis as usize];
    let mut base_terms = Vec::new();
    for dimension in 0..input.sizes.len() {
        if dimension as u32 != axis {
            base_terms.push(format!("o{dimension} * {}u", input.strides[dimension]));
        }
    }
    let base = if base_terms.is_empty() {
        "0u".to_string()
    } else {
        base_terms.join(" + ")
    };
    source.push_str(&format!("    uint base = {base};\n"));
    source.push_str(&format!("    uint position = o{axis};\n"));
    source.push_str("    uint chosen = 0u;\n    float chosen_value = 0.0f;\n");
    source.push_str(&format!(
        "    for (uint candidate = 0u; candidate < {axis_size}u; ++candidate) {{\n"
    ));
    source.push_str(&format!(
        "        float v = float(in0[base + candidate * {axis_stride}u]);\n"
    ));
    source.push_str("        uint rank = 0u;\n");
    source.push_str(&format!(
        "        for (uint other = 0u; other < {axis_size}u; ++other) {{\n"
    ));
    source.push_str(&format!(
        "            float w = float(in0[base + other * {axis_stride}u]);\n"
    ));
    source.push_str("            bool v_nan = isnan(v);\n            bool w_nan = isnan(w);\n");
    let before = match direction {
        DmlAxisDirection::Decreasing => {
            "((!v_nan && w_nan) || (!v_nan && !w_nan && (w > v || (w == v && other < candidate))) || (v_nan && w_nan && other < candidate))"
        }
        DmlAxisDirection::Increasing => {
            "((v_nan && !w_nan) || (!v_nan && !w_nan && (w < v || (w == v && other < candidate))) || (v_nan && w_nan && other < candidate))"
        }
    };
    source.push_str(&format!("            if ({before}) rank += 1u;\n"));
    source.push_str("        }\n");
    source.push_str("        if (rank == position) { chosen = candidate; chosen_value = v; }\n");
    source.push_str("    }\n");
    source.push_str(&format!(
        "    out0[{}] = ({value_scalar})chosen_value;\n",
        output_index_expr(&plan.output)
    ));
    src_push_index_output(&mut source, plan, "out1", "chosen");
    source.push_str("}\n");
    let _ = k;
    Ok(source)
}

pub(crate) fn src_push_index_output(
    source: &mut String,
    plan: &DmlOpPlan,
    name: &str,
    value: &str,
) {
    let output = &plan.extra_outputs[0];
    let index = output_index_expr(output);
    // The coordinates were computed for the primary output, whose sizes match
    // the index tensor for all top-k shapes.
    source.push_str(&format!("    {name}[{index}] = {value};\n"));
}

pub(crate) fn emit_tile_msl(plan: &DmlOpPlan, repeats: &[u32]) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut coords = Vec::with_capacity(input.sizes.len());
    for dimension in 0..input.sizes.len() {
        let size = input.sizes[dimension];
        let _ = repeats[dimension];
        coords.push(format!("(o{dimension} % {size}u)"));
    }
    source.push_str(&format!(
        "    out[{}] = in0[{}];\n",
        output_index_expr(&plan.output),
        linear_index(input, &coords)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_split_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let chunk = plan.output.sizes[axis as usize];
    let scalars = vec![scalar; plan.output_count()];
    let mut source = msl_header_outputs(plan, scalar, &scalars);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    for index in 0..plan.output_count() {
        let mut coords = coord_names(input.sizes.len());
        coords[axis as usize] = format!("o{axis} + {}u", chunk as u64 * index as u64);
        source.push_str(&format!(
            "    out{index}[{}] = in0[{}];\n",
            output_index_expr(&plan.outputs().nth(index).expect("output exists")),
            linear_index(input, &coords)
        ));
    }
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn execute_space_depth_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    to_depth: bool,
    block_size: u32,
    order: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let output_desc = &plan.output;
    let dtype = output_desc.data_type;
    let block = block_size as u64;
    let output_channels = output_desc.sizes[1];
    for gid in 0..output_desc.element_count() {
        let coords = coords_of(gid, &output_desc.sizes);
        let mut input_coords = vec![0u64; 4];
        if to_depth {
            let channels = input.sizes[1] as u64;
            let c_in = coords[1] % channels;
            let t = coords[1] / channels;
            let (i, j) = if order == 0 {
                (t / block, t % block)
            } else {
                (t % block, t / block)
            };
            input_coords = vec![
                coords[0],
                c_in,
                coords[2] * block + i,
                coords[3] * block + j,
            ];
        } else {
            let i = coords[2] % block;
            let j = coords[3] % block;
            let (ci, cj) = if order == 0 { (i, j) } else { (j, i) };
            let c_in =
                ci * block * output_channels as u64 + cj * output_channels as u64 + coords[1];
            input_coords = vec![coords[0], c_in, coords[2] / block, coords[3] / block];
        }
        let value = load_scalar(input_bytes, index_of(&input_coords, &input.strides), dtype);
        store_scalar(output, output_index(output_desc, gid), dtype, value);
    }
    Ok(())
}

pub(crate) fn execute_slice_ex_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    offsets: &[u32],
    _sizes: &[u32],
    strides: &[i32],
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let dtype = plan.output.data_type;
    for gid in 0..plan.output.element_count() {
        let base = coords_of(gid, &plan.output.sizes);
        let coords: Vec<u64> = (0..base.len())
            .map(|dimension| {
                (offsets[dimension] as i64 + base[dimension] as i64 * strides[dimension] as i64)
                    as u64
            })
            .collect();
        store_scalar(
            output,
            output_index(&plan.output, gid),
            dtype,
            load_scalar(input_bytes, index_of(&coords, &input.strides), dtype),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_resample_grad_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    mode: DmlInterpolationMode,
    rounding: DmlAxisDirection,
    scales: &[f32],
    input_offsets: &[f32],
    output_offsets: &[f32],
) -> DmlResult<()> {
    let gradient = &plan.inputs[0];
    let output_desc = &plan.output;
    let rank = output_desc.sizes.len();
    let dtype = output_desc.data_type;
    let gradient_count = gradient.element_count();
    for gid in 0..output_desc.element_count() {
        let own = coords_of(gid, &output_desc.sizes);
        let mut acc = 0.0f64;
        for t in 0..gradient_count {
            let g = coords_of(t, &gradient.sizes);
            let source: Vec<f64> = (0..rank)
                .map(|dimension| {
                    (g[dimension] as f64 + output_offsets[dimension] as f64)
                        / scales[dimension] as f64
                        + input_offsets[dimension] as f64
                })
                .collect();
            let weight = match mode {
                DmlInterpolationMode::NearestNeighbor => {
                    let mut matches = true;
                    for dimension in 0..rank {
                        let rounded = match rounding {
                            DmlAxisDirection::Increasing => (source[dimension] + 0.5).floor(),
                            DmlAxisDirection::Decreasing => (source[dimension] - 0.5).ceil(),
                        }
                        .clamp(0.0, output_desc.sizes[dimension] as f64 - 1.0)
                            as u64;
                        if rounded != own[dimension] {
                            matches = false;
                            break;
                        }
                    }
                    if matches { 1.0 } else { 0.0 }
                }
                DmlInterpolationMode::Linear => {
                    let mut weight = 0.0f64;
                    for mask in 0..(1usize << rank) {
                        let mut product = 1.0f64;
                        let mut matches = true;
                        for dimension in 0..rank {
                            let base = source[dimension].floor();
                            let fraction = source[dimension] - base;
                            let bit = (mask >> dimension) & 1;
                            product *= if bit != 0 { fraction } else { 1.0 - fraction };
                            let coordinate = (base as i64 + bit as i64)
                                .clamp(0, output_desc.sizes[dimension] as i64 - 1)
                                as u64;
                            if coordinate != own[dimension] {
                                matches = false;
                                break;
                            }
                        }
                        if matches {
                            weight += product;
                        }
                    }
                    weight
                }
            };
            if weight != 0.0 {
                acc += weight * load_scalar(input_bytes, t, gradient.data_type) as f64;
            }
        }
        store_scalar(output, output_index(output_desc, gid), dtype, acc as f32);
    }
    Ok(())
}

pub(crate) fn execute_slice_grad_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    offsets: &[u32],
    sizes: &[u32],
    strides: &[i32],
) -> DmlResult<()> {
    let gradient = &plan.inputs[0];
    let dtype = plan.output.data_type;
    for gid in 0..plan.output.element_count() {
        let own = coords_of(gid, &plan.output.sizes);
        let mut coords = Vec::with_capacity(own.len());
        let mut valid = true;
        for dimension in 0..own.len() {
            let delta = own[dimension] as i64 - offsets[dimension] as i64;
            let step = strides[dimension] as i64;
            let position = if step > 0 {
                if delta < 0 || delta % step != 0 {
                    valid = false;
                    break;
                }
                delta / step
            } else {
                if delta > 0 || delta % step != 0 {
                    valid = false;
                    break;
                }
                -delta / -step
            };
            if position < 0 || position >= sizes[dimension] as i64 {
                valid = false;
                break;
            }
            coords.push(position as u64);
        }
        let value = if valid {
            load_scalar(input_bytes, index_of(&coords, &gradient.strides), dtype)
        } else {
            0.0
        };
        store_scalar(output, output_index(&plan.output, gid), dtype, value);
    }
    Ok(())
}

pub(crate) fn execute_padding_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    mode: DmlPaddingMode,
    start_padding: &[u32],
    _end_padding: &[u32],
    value: f32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let mut input_coords = Vec::with_capacity(input.sizes.len());
        let mut outside = false;
        for dimension in 0..input.sizes.len() {
            let size = input.sizes[dimension] as i64;
            let mut source = output_coords[dimension] as i64 - start_padding[dimension] as i64;
            match mode {
                DmlPaddingMode::Constant => {
                    if source < 0 || source >= size {
                        outside = true;
                    }
                    source = source.clamp(0, size - 1);
                }
                DmlPaddingMode::Edge => source = source.clamp(0, size - 1),
                DmlPaddingMode::Reflection => {
                    while source < 0 || source >= size {
                        source = if source < 0 {
                            -source
                        } else {
                            size * 2 - 2 - source
                        };
                    }
                }
                DmlPaddingMode::Symmetric => {
                    while source < 0 || source >= size {
                        source = if source < 0 {
                            -source - 1
                        } else {
                            size * 2 - 1 - source
                        };
                    }
                }
                DmlPaddingMode::Wrap => {
                    source = ((source % size) + size) % size;
                }
            }
            input_coords.push(source as u64);
        }
        let result = if mode == DmlPaddingMode::Constant && outside {
            value
        } else {
            load_scalar(
                input_bytes,
                index_of(&input_coords, &input.strides),
                input.data_type,
            )
        };
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            result,
        );
    }
    Ok(())
}

pub(crate) fn execute_resample_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    mode: DmlInterpolationMode,
    scales: &[f32],
    input_offsets: &[f32],
    output_offsets: &[f32],
    rounding: DmlAxisDirection,
    antialiased: bool,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let coords: Vec<f64> = (0..rank)
            .map(|dimension| {
                if antialiased {
                    (output_coords[dimension] as f64 + output_offsets[dimension] as f64 + 0.5)
                        / scales[dimension] as f64
                        + input_offsets[dimension] as f64
                        - 0.5
                } else {
                    (output_coords[dimension] as f64 + output_offsets[dimension] as f64)
                        / scales[dimension] as f64
                        + input_offsets[dimension] as f64
                }
            })
            .collect();
        let value = if antialiased {
            let radii: Vec<f64> = scales
                .iter()
                .map(|scale| (0.5f64 / *scale as f64).max(0.5))
                .collect();
            let starts: Vec<i64> = (0..rank)
                .map(|dimension| (coords[dimension] - radii[dimension]).floor() as i64)
                .collect();
            let ends: Vec<i64> = (0..rank)
                .map(|dimension| (coords[dimension] + radii[dimension]).ceil() as i64)
                .collect();
            let mut taps: Vec<i64> = starts.clone();
            let mut result = 0.0f64;
            let mut total = 0.0f64;
            let mut done = false;
            while !done {
                let mut weight = 1.0f64;
                let mut in_bounds = true;
                for dimension in 0..rank {
                    if taps[dimension] < 0 || taps[dimension] >= input.sizes[dimension] as i64 {
                        in_bounds = false;
                        break;
                    }
                    let tap_weight =
                        1.0 - (taps[dimension] as f64 - coords[dimension]).abs() / radii[dimension];
                    if tap_weight <= 0.0 {
                        in_bounds = false;
                        break;
                    }
                    weight *= tap_weight;
                }
                if in_bounds {
                    let input_coords: Vec<u64> = taps.iter().map(|tap| *tap as u64).collect();
                    result += weight
                        * load_scalar(
                            input_bytes,
                            index_of(&input_coords, &input.strides),
                            input.data_type,
                        ) as f64;
                    total += weight;
                }
                let mut dimension = rank;
                loop {
                    if dimension == 0 {
                        done = true;
                        break;
                    }
                    dimension -= 1;
                    if taps[dimension] < ends[dimension] {
                        taps[dimension] += 1;
                        break;
                    }
                    taps[dimension] = starts[dimension];
                }
            }
            if total <= 0.0 {
                0.0
            } else {
                (result / total) as f32
            }
        } else if mode == DmlInterpolationMode::NearestNeighbor {
            let mut input_coords = Vec::with_capacity(rank);
            for dimension in 0..rank {
                let rounded = match rounding {
                    DmlAxisDirection::Increasing => (coords[dimension] + 0.5).floor(),
                    DmlAxisDirection::Decreasing => (coords[dimension] - 0.5).ceil(),
                };
                input_coords
                    .push((rounded as i64).clamp(0, input.sizes[dimension] as i64 - 1) as u64);
            }
            load_scalar(
                input_bytes,
                index_of(&input_coords, &input.strides),
                input.data_type,
            )
        } else {
            let mut result = 0.0f64;
            for mask in 0..(1usize << rank) {
                let mut weight = 1.0f64;
                let mut input_coords = Vec::with_capacity(rank);
                for dimension in 0..rank {
                    let bit = (mask >> dimension) & 1;
                    let base = coords[dimension].floor();
                    let fraction = coords[dimension] - base;
                    weight *= if bit != 0 { fraction } else { 1.0 - fraction };
                    let coordinate = (base as i64 + bit as i64)
                        .clamp(0, input.sizes[dimension] as i64 - 1)
                        as u64;
                    input_coords.push(coordinate);
                }
                result += weight
                    * load_scalar(
                        input_bytes,
                        index_of(&input_coords, &input.strides),
                        input.data_type,
                    ) as f64;
            }
            result as f32
        };
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            value,
        );
    }
    Ok(())
}

pub(crate) fn execute_top_k_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    index_output: &mut [u8],
    axis: u32,
    _k: u32,
    direction: DmlAxisDirection,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let count = plan.output.element_count();
    let axis_size = input.sizes[axis as usize];
    let index_desc = &plan.extra_outputs[0];
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let position = output_coords[axis as usize];
        let mut chosen = 0u64;
        let mut chosen_value = 0.0f32;
        for candidate in 0..axis_size as u64 {
            let mut candidate_coords = output_coords.clone();
            candidate_coords[axis as usize] = candidate;
            let value = load_scalar(
                input_bytes,
                index_of(&candidate_coords, &input.strides),
                input.data_type,
            );
            let mut rank = 0u64;
            for other in 0..axis_size as u64 {
                let mut other_coords = output_coords.clone();
                other_coords[axis as usize] = other;
                let other_value = load_scalar(
                    input_bytes,
                    index_of(&other_coords, &input.strides),
                    input.data_type,
                );
                let before = match direction {
                    DmlAxisDirection::Decreasing => {
                        (!value.is_nan() && other_value.is_nan())
                            || (!value.is_nan()
                                && !other_value.is_nan()
                                && (other_value > value
                                    || (other_value == value && other < candidate)))
                            || (value.is_nan() && other_value.is_nan() && other < candidate)
                    }
                    DmlAxisDirection::Increasing => {
                        (value.is_nan() && !other_value.is_nan())
                            || (!value.is_nan()
                                && !other_value.is_nan()
                                && (other_value < value
                                    || (other_value == value && other < candidate)))
                            || (value.is_nan() && other_value.is_nan() && other < candidate)
                    }
                };
                if before {
                    rank += 1;
                }
            }
            if rank == position {
                chosen = candidate;
                chosen_value = value;
            }
        }
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            chosen_value,
        );
        store_integer(
            index_output,
            output_index(index_desc, gid),
            index_desc.data_type,
            chosen as i64,
        );
    }
    Ok(())
}

pub(crate) fn execute_tile_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    _repeats: &[u32],
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let input_coords: Vec<u64> = output_coords
            .iter()
            .enumerate()
            .map(|(dimension, coordinate)| coordinate % input.sizes[dimension] as u64)
            .collect();
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            load_scalar(
                input_bytes,
                index_of(&input_coords, &input.strides),
                input.data_type,
            ),
        );
    }
    Ok(())
}

pub(crate) fn execute_split_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    extras: &mut [&mut [u8]],
    axis: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let chunk = plan.output.sizes[axis as usize];
    for (index, desc) in plan.outputs().enumerate() {
        let count = desc.element_count();
        let buffer: &mut [u8] = if index == 0 {
            output
        } else {
            extras[index - 1]
        };
        for gid in 0..count {
            let output_coords = coords_of(gid, &desc.sizes);
            let mut input_coords = output_coords.clone();
            input_coords[axis as usize] += chunk as u64 * index as u64;
            store_scalar(
                buffer,
                output_index(desc, gid),
                desc.data_type,
                load_scalar(
                    input_bytes,
                    index_of(&input_coords, &input.strides),
                    input.data_type,
                ),
            );
        }
    }
    Ok(())
}
