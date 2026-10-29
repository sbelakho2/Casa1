//! Quantized portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_quantized_dtypes(&self, ty: u32, _mode: u32) -> DmlResult<()> {
        for desc in &self.inputs {
            let supported = matches!(
                desc.data_type,
                DML_TENSOR_DATA_TYPE_FLOAT32
                    | DML_TENSOR_DATA_TYPE_UINT32
                    | DML_TENSOR_DATA_TYPE_INT32
                    | DML_TENSOR_DATA_TYPE_UINT8
                    | DML_TENSOR_DATA_TYPE_INT8
                    | DML_TENSOR_DATA_TYPE_UINT4
                    | DML_TENSOR_DATA_TYPE_INT4
            );
            if !supported {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} has an unsupported quantized DML_TENSOR_DATA_TYPE {}",
                    desc.data_type
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_quantize_linear(&self) -> DmlResult<()> {
        if !(2..=3).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "linear quantize expects 2 or 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let coords = coord_names(self.output.sizes.len());
        let scale = &self.inputs[1];
        if !scale.is_contiguous() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} scale tensor must be contiguous",
                self.operator_type()
            )));
        }
        quantization_tensor_index(scale, &self.output, &coords).map_err(|error| {
            DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} scale tensor is not broadcastable: {}",
                self.operator_type(),
                error.message
            ))
        })?;
        if self.inputs.len() == 3 {
            let zero_point = &self.inputs[2];
            if !zero_point.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {} zero point tensor must be contiguous",
                    self.operator_type()
                )));
            }
            quantization_tensor_index(zero_point, &self.output, &coords).map_err(|error| {
                DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {} zero point tensor is not broadcastable: {}",
                    self.operator_type(),
                    error.message
                ))
            })?;
        }
        if self.output.sizes != self.inputs[0].sizes {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} output sizes must match the input sizes",
                self.operator_type()
            )));
        }
        if !self.inputs[0].is_contiguous() || !self.output.is_contiguous() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} requires contiguous input and output tensors",
                self.operator_type()
            )));
        }
        if self.output_count() != 1 {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} requires exactly one output tensor",
                self.operator_type()
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_dynamic_quantize(&self) -> DmlResult<()> {
        self.require_input_count(1)?;
        if self.output.sizes != self.inputs[0].sizes {
            return Err(DmlError::invalid(
                "dynamic quantize output sizes must match the input sizes",
            ));
        }
        if !self.inputs[0].is_contiguous() || !self.output.is_contiguous() {
            return Err(DmlError::invalid(
                "dynamic quantize requires contiguous input and output tensors",
            ));
        }
        if self.extra_outputs.len() != 2 {
            return Err(DmlError::invalid(
                "dynamic quantize requires scale and zero point outputs",
            ));
        }
        for (role, output) in ["scale", "zero point"].into_iter().zip(&self.extra_outputs) {
            if output.element_count() != 1 || !output.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "dynamic quantize {role} output must be a single contiguous element"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_quantized_add(&self) -> DmlResult<()> {
        if !(5..=8).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "quantized linear add expects 5 to 8 input tensors, got {}",
                self.inputs.len()
            )));
        }
        self.require_scalar_quantization_tensors()?;
        if self.inputs[0].sizes != self.inputs[self.a_tensor_index()].sizes {
            return Err(DmlError::invalid(
                "quantized linear add A and B tensors must have identical sizes",
            ));
        }
        if self.output.sizes != self.inputs[0].sizes {
            return Err(DmlError::invalid(
                "quantized linear add output sizes must match the A tensor sizes",
            ));
        }
        for (name, desc) in [
            ("A", &self.inputs[0]),
            ("B", &self.inputs[self.a_tensor_index()]),
            ("output", &self.output),
        ] {
            if !desc.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "quantized linear add {name} tensor must be contiguous"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn a_tensor_index(&self) -> usize {
        match &self.kind {
            DmlOpKind::QuantizedLinearAdd { a_zero_point, .. } => 3 + usize::from(*a_zero_point),
            _ => 0,
        }
    }

    pub(crate) fn require_scalar_quantization_tensors(&self) -> DmlResult<()> {
        let roles = self.input_roles();
        let dummy = coord_names(self.output.sizes.len());
        for (index, desc) in self.inputs.iter().enumerate() {
            let role = roles.get(index).copied().unwrap_or("input");
            if role.contains("scale") {
                if desc.data_type != DML_TENSOR_DATA_TYPE_FLOAT32 || !desc.is_contiguous() {
                    return Err(DmlError::invalid(format!(
                        "quantized operator scale input {index} ({role}) must be a contiguous FLOAT32 tensor"
                    )));
                }
                quantization_tensor_index(desc, &self.output, &dummy).map_err(|error| {
                    DmlError::invalid(format!(
                        "quantized operator scale input {index} ({role}) is not broadcastable: {}",
                        error.message
                    ))
                })?;
            }
            if role.contains("zero point") {
                if !matches!(
                    desc.data_type,
                    DML_TENSOR_DATA_TYPE_UINT8
                        | DML_TENSOR_DATA_TYPE_INT8
                        | DML_TENSOR_DATA_TYPE_UINT4
                        | DML_TENSOR_DATA_TYPE_INT4
                ) || !desc.is_contiguous()
                {
                    return Err(DmlError::invalid(format!(
                        "quantized operator zero point input {index} ({role}) must be a contiguous UINT8, INT8, UINT4, or INT4 tensor"
                    )));
                }
                quantization_tensor_index(desc, &self.output, &dummy).map_err(|error| {
                    DmlError::invalid(format!(
                        "quantized operator zero point input {index} ({role}) is not broadcastable: {}",
                        error.message
                    ))
                })?;
            }
        }
        Ok(())
    }

    pub(crate) fn validate_matmul_integer(&self, quantized_output: bool) -> DmlResult<()> {
        if self.inputs.len() < 2 {
            return Err(DmlError::invalid(
                "integer matrix multiply requires two input tensors",
            ));
        }
        let a_index = self
            .input_roles()
            .iter()
            .position(|role| *role == "A")
            .expect("matrix multiply A role");
        let b_index = self
            .input_roles()
            .iter()
            .position(|role| *role == "B")
            .expect("matrix multiply B role");
        let a = &self.inputs[a_index];
        let b = &self.inputs[b_index];
        if a.sizes.len() < 2 || b.sizes.len() < 2 {
            return Err(DmlError::invalid(
                "integer matrix multiply tensors must have rank >= 2",
            ));
        }
        let rank = a.sizes.len();
        if a.sizes[rank - 1] != b.sizes[b.sizes.len() - 2] {
            return Err(DmlError::invalid(format!(
                "integer matrix multiply inner dimensions do not match: A K={}, B K={}",
                a.sizes[rank - 1],
                b.sizes[b.sizes.len() - 2]
            )));
        }
        let a_batch = &a.sizes[..rank - 2];
        let b_batch = &b.sizes[..b.sizes.len() - 2];
        if a_batch != b_batch {
            return Err(DmlError::invalid(format!(
                "integer matrix multiply batch dimensions do not match: A {:?}, B {:?}",
                a_batch, b_batch
            )));
        }
        let mut expected = a.sizes.clone();
        expected[rank - 1] = b.sizes[b.sizes.len() - 1];
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "integer matrix multiply output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        self.require_scalar_quantization_tensors()?;
        if quantized_output && self.output_count() != 1 {
            return Err(DmlError::invalid(
                "quantized matrix multiply requires exactly one output tensor",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_convolution_integer(
        &self,
        strides: &[u32],
        dilations: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
        group_count: u32,
        quantized_output: bool,
    ) -> DmlResult<()> {
        if !(2..=8).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "integer convolution requires 2 to 8 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let filter_index = self
            .input_roles()
            .iter()
            .position(|role| *role == "filter")
            .unwrap_or(1);
        let filter = &self.inputs[filter_index];
        if input.sizes.len() != 4 || filter.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "integer convolution requires rank-4 NCHW tensors",
            ));
        }
        for (name, values) in [("strides", strides), ("dilations", dilations)] {
            if values.len() != 2 || values.contains(&0) {
                return Err(DmlError::invalid(format!(
                    "integer convolution {name} must contain two non-zero entries"
                )));
            }
        }
        if start_padding.len() != 2 || end_padding.len() != 2 {
            return Err(DmlError::invalid(
                "integer convolution padding must contain two entries",
            ));
        }
        if group_count == 0
            || input.sizes[1] % group_count != 0
            || filter.sizes[0] % group_count != 0
        {
            return Err(DmlError::invalid(
                "integer convolution group count must divide input and filter channels",
            ));
        }
        let oh = convolution_output_size(
            input.sizes[2],
            filter.sizes[2],
            strides[0],
            dilations[0],
            start_padding[0],
            end_padding[0],
            0,
        )?;
        let ow = convolution_output_size(
            input.sizes[3],
            filter.sizes[3],
            strides[1],
            dilations[1],
            start_padding[1],
            end_padding[1],
            0,
        )?;
        let expected = [input.sizes[0], filter.sizes[0], oh, ow];
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "integer convolution output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        self.require_scalar_quantization_tensors()?;
        if quantized_output && self.output_count() != 1 {
            return Err(DmlError::invalid(
                "quantized convolution requires exactly one output tensor",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_quantized_avg_pool(
        &self,
        strides: &[u32],
        window: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
        dilations: &[u32],
        include_padding: bool,
    ) -> DmlResult<()> {
        if !(3..=5).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "quantized average pooling expects 3 to 5 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        if input.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "quantized average pooling requires rank-4 NCHW tensors",
            ));
        }
        for (name, values) in [
            ("strides", strides),
            ("window", window),
            ("dilations", dilations),
            ("start padding", start_padding),
            ("end padding", end_padding),
        ] {
            if values.len() != 2 {
                return Err(DmlError::invalid(format!(
                    "quantized average pooling {name} must contain two entries"
                )));
            }
        }
        if strides.contains(&0) || window.contains(&0) || dilations.contains(&0) {
            return Err(DmlError::invalid(
                "quantized average pooling strides, window, and dilations must be non-zero",
            ));
        }
        let effective_h = (window[0] as u64 - 1) * dilations[0] as u64 + 1;
        let effective_w = (window[1] as u64 - 1) * dilations[1] as u64 + 1;
        let padded_h = input.sizes[2] as u64 + start_padding[0] as u64 + end_padding[0] as u64;
        let padded_w = input.sizes[3] as u64 + start_padding[1] as u64 + end_padding[1] as u64;
        if padded_h < effective_h || padded_w < effective_w {
            return Err(DmlError::invalid(
                "quantized average pooling window does not fit the padded input",
            ));
        }
        let oh = (padded_h - effective_h) / strides[0] as u64 + 1;
        let ow = (padded_w - effective_w) / strides[1] as u64 + 1;
        let expected = [input.sizes[0], input.sizes[1], oh as u32, ow as u32];
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "quantized average pooling output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        let _ = include_padding;
        self.require_scalar_quantization_tensors()?;
        Ok(())
    }

    pub(crate) fn validate_mmi_to_float(&self) -> DmlResult<()> {
        if self.inputs.len() < 4 {
            return Err(DmlError::invalid(
                "integer-to-float matrix multiply requires A, A scale, B, and B scale inputs",
            ));
        }
        self.validate_matmul_integer(false)?;
        self.require_scalar_quantization_tensors()?;
        if let Some(index) = quantized_input_index(self, "bias") {
            let bias = &self.inputs[index];
            let output_width = *self.output.sizes.last().unwrap_or(&1) as u64;
            if bias.element_count() != 1 && bias.element_count() != output_width {
                return Err(DmlError::invalid(format!(
                    "integer-to-float matrix multiply bias must contain 1 or {output_width} elements"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_quantize(&self, quantization_type: u32) -> DmlResult<()> {
        let expected_tensors = match quantization_type {
            0 => 0,
            1 => 1,
            2 => 2,
            other => {
                return Err(DmlError::invalid(format!(
                    "DML_QUANTIZATION_TYPE {other} is not supported"
                )));
            }
        };
        if self.inputs.len() != 1 + expected_tensors {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} with DML_QUANTIZATION_TYPE {quantization_type} requires {} input tensor(s), got {}",
                self.operator_type(),
                1 + expected_tensors,
                self.inputs.len()
            )));
        }
        let coords = coord_names(self.output.sizes.len());
        for desc in &self.inputs[1..] {
            if desc.data_type != DML_TENSOR_DATA_TYPE_FLOAT32 || !desc.is_contiguous() {
                return Err(DmlError::invalid(
                    "quantize/dequantize quantization tensors must be contiguous FLOAT32",
                ));
            }
            quantization_tensor_index(desc, &self.output, &coords).map_err(|error| {
                DmlError::invalid(format!(
                    "quantize/dequantize quantization tensor is not broadcastable: {}",
                    error.message
                ))
            })?;
        }
        if self.output.sizes != self.inputs[0].sizes {
            return Err(DmlError::invalid(
                "quantize/dequantize output sizes must match the input sizes",
            ));
        }
        if !self.inputs[0].is_contiguous() || !self.output.is_contiguous() {
            return Err(DmlError::invalid(
                "quantize/dequantize requires contiguous input and output tensors",
            ));
        }
        Ok(())
    }
}

/// Lower an extended operator to MSL source.
pub(crate) fn quantized_store(scalar: &str, value: &str) -> String {
    match scalar {
        "uchar" => format!("(uchar)clamp(rint({value}), 0.0f, 255.0f)"),
        "char" => format!("(char)clamp(rint({value}), -128.0f, 127.0f)"),
        other => format!("({other})({value})"),
    }
}

pub(crate) fn emit_quantize_linear_msl(plan: &DmlOpPlan, dequantize: bool) -> DmlResult<String> {
    let out_scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let in_scalar = msl_scalar(plan.inputs[0].data_type, plan.operator_type())?;
    let out_4bit = plan.output.is_4bit();
    let in_4bit = plan.inputs[0].is_4bit();
    let count = plan.output.element_count();
    let mut source = msl_header_outputs(plan, in_scalar, &[out_scalar]);
    let zero_desc = plan.inputs.get(2);
    if out_4bit && !dequantize {
        source.push_str(&format!(
            "    uint base = gid * 2u;\n    if (base >= {count}u) return;\n"
        ));
        let signed = plan.output.data_type == DML_TENSOR_DATA_TYPE_INT4;
        let mut values = Vec::new();
        for offset in 0..2u64 {
            let index = if offset == 0 {
                "base".to_string()
            } else {
                "(base + 1u)".to_string()
            };
            let scale = quantization_index_for_linear(&plan.inputs[1], &plan.output, &index)?;
            let zero = match zero_desc {
                Some(desc) => {
                    let expr = quantization_index_for_linear(desc, &plan.output, &index)?;
                    if desc.is_4bit() {
                        format!(
                            "float({})",
                            packed_read_4bit(
                                "in2",
                                &expr,
                                desc.data_type == DML_TENSOR_DATA_TYPE_INT4
                            )
                        )
                    } else {
                        format!("float(in2[{expr}])")
                    }
                }
                None => "0.0f".to_string(),
            };
            let guard = if offset == 0 {
                String::new()
            } else {
                format!("(base + 1u) < {count}u ? ")
            };
            let term = format!("{guard}(rint(float(in0[{index}]) / float(in1[{scale}])) + {zero})");
            let term = if offset == 0 {
                term
            } else {
                format!("{term} : 0.0f")
            };
            values.push(term);
        }
        source.push_str(&format!(
            "    out0[gid] = {};\n}}\n",
            packed_store_4bit(&values[0], &values[1], signed)
        ));
        return Ok(source);
    }
    push_guard(&mut source, &plan.output);
    let scale = quantization_index_for_linear(&plan.inputs[1], &plan.output, "gid")?;
    let zero_point = match zero_desc {
        Some(desc) => {
            let expr = quantization_index_for_linear(desc, &plan.output, "gid")?;
            if desc.is_4bit() {
                format!(
                    "float({})",
                    packed_read_4bit("in2", &expr, desc.data_type == DML_TENSOR_DATA_TYPE_INT4)
                )
            } else {
                format!("float(in2[{expr}])")
            }
        }
        None => "0.0f".to_string(),
    };
    let input_value = if in_4bit {
        let signed = plan.inputs[0].data_type == DML_TENSOR_DATA_TYPE_INT4;
        let read = packed_read_4bit("in0", "gid", signed);
        format!("float({read})")
    } else {
        "float(in0[gid])".to_string()
    };
    if dequantize {
        source.push_str(&format!(
            "    float value = ({input_value} - {zero_point}) * float(in1[{scale}]);\n"
        ));
    } else {
        source.push_str(&format!(
            "    float value = rint({input_value} / float(in1[{scale}])) + {zero_point};\n"
        ));
    }
    source.push_str(&format!(
        "    out0[gid] = {};\n}}\n",
        quantized_store(out_scalar, "value")
    ));
    Ok(source)
}

pub(crate) fn emit_dynamic_quantize_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let input_count = plan.inputs[0].element_count();
    let mut source = msl_header_outputs(plan, "float", &["uchar", "float", "uchar"]);
    source.push_str("    if (gid != 0u) return;\n");
    source.push_str("    float minimum = 0.0f;\n    float maximum = 0.0f;\n");
    source.push_str(&format!(
        "    for (uint i = 0u; i < {input_count}u; ++i) {{ float v = float(in0[i]); if (v < minimum) minimum = v; if (v > maximum) maximum = v; }}\n"
    ));
    source.push_str("    float range = maximum - minimum;\n");
    source.push_str("    float scale = range == 0.0f ? 1.0f : range / 255.0f;\n");
    source.push_str("    float zero = clamp(rint(-minimum / scale), 0.0f, 255.0f);\n");
    source.push_str(&format!(
        "    for (uint i = 0u; i < {input_count}u; ++i) {{ out0[i] = (uchar)clamp(rint(float(in0[i]) / scale) + zero, 0.0f, 255.0f); }}\n"
    ));
    source.push_str("    out1[0] = scale;\n    out2[0] = (uchar)zero;\n}\n");
    Ok(source)
}

pub(crate) fn quantized_input_index(plan: &DmlOpPlan, role: &str) -> Option<usize> {
    plan.input_roles()
        .iter()
        .position(|candidate| *candidate == role)
}

pub(crate) fn emit_quantized_add_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let out_scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let a_scalar = msl_scalar(plan.inputs[0].data_type, plan.operator_type())?;
    let mut source = msl_header_outputs(plan, a_scalar, &[out_scalar]);
    push_guard(&mut source, &plan.output);
    let a_index = 0;
    let a_scale = quantized_input_index(plan, "A scale").expect("A scale");
    let a_zero = quantized_input_index(plan, "A zero point");
    let b_index = quantized_input_index(plan, "B").expect("B");
    let b_scale = quantized_input_index(plan, "B scale").expect("B scale");
    let b_zero = quantized_input_index(plan, "B zero point");
    let out_scale = quantized_input_index(plan, "output scale").expect("output scale");
    let out_zero = quantized_input_index(plan, "output zero point");
    let quantizer = |index: usize| {
        quantization_index_for_linear(&plan.inputs[index], &plan.output, "gid")
            .expect("quantization tensor validated")
    };
    source.push_str(&format!(
        "    float a = (float(in{a_index}[gid]) - {}) * float(in{a_scale}[{}]);\n",
        a_zero
            .map(|i| format!("float(in{i}[{}])", quantizer(i)))
            .unwrap_or_else(|| "0.0f".to_string()),
        quantizer(a_scale)
    ));
    source.push_str(&format!(
        "    float b = (float(in{b_index}[gid]) - {}) * float(in{b_scale}[{}]);\n",
        b_zero
            .map(|i| format!("float(in{i}[{}])", quantizer(i)))
            .unwrap_or_else(|| "0.0f".to_string()),
        quantizer(b_scale)
    ));
    source.push_str(&format!(
        "    float value = (a + b) / float(in{out_scale}[{}]) + {};\n",
        quantizer(out_scale),
        out_zero
            .map(|i| format!("float(in{i}[{}])", quantizer(i)))
            .unwrap_or_else(|| "0.0f".to_string())
    ));
    source.push_str(&format!(
        "    out0[gid] = {};\n}}\n",
        quantized_store(out_scalar, "value")
    ));
    Ok(source)
}

pub(crate) fn emit_integer_matmul_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let DmlOpKind::MatrixMultiplyInteger {
        quantized_output, ..
    } = &plan.kind
    else {
        unreachable!("integer matmul emitter");
    };
    let out_scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let a_scalar = msl_scalar(plan.inputs[0].data_type, plan.operator_type())?;
    let mut source = msl_header_outputs(plan, a_scalar, &[out_scalar]);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let a_index = 0;
    let a_scale = quantized_input_index(plan, "A scale");
    let a_zero = quantized_input_index(plan, "A zero point");
    let b_index = quantized_input_index(plan, "B").expect("B");
    let b_scale = quantized_input_index(plan, "B scale");
    let b_zero = quantized_input_index(plan, "B zero point");
    let out_scale = quantized_input_index(plan, "output scale");
    let out_zero = quantized_input_index(plan, "output zero point");
    let a = &plan.inputs[a_index];
    let b = &plan.inputs[b_index];
    let rank = a.sizes.len();
    let m = plan.output.sizes[rank - 2];
    let n = plan.output.sizes[rank - 1];
    let k = a.sizes[rank - 1];
    source.push_str(&format!(
        "    uint inner = gid % {}u;\n    uint m = inner / {n}u;\n    uint n = inner % {n}u;\n",
        m as u64 * n as u64
    ));
    let mut batch_terms_a = Vec::new();
    let mut batch_terms_b = Vec::new();
    if rank > 2 {
        source.push_str(&format!(
            "    uint batch = gid / {}u;\n",
            m as u64 * n as u64
        ));
        source.push_str("    uint rem = batch;\n");
        for dimension in 0..rank - 2 {
            let size = plan.output.sizes[dimension];
            source.push_str(&format!("    uint bc{dimension} = rem % {size}u;\n"));
            source.push_str(&format!("    rem /= {size}u;\n"));
            batch_terms_a.push(format!("bc{dimension} * {}u", a.strides[dimension]));
            batch_terms_b.push(format!("bc{dimension} * {}u", b.strides[dimension]));
        }
    }
    let a_base = if batch_terms_a.is_empty() {
        "0u".to_string()
    } else {
        batch_terms_a.join(" + ")
    };
    let b_base = if batch_terms_b.is_empty() {
        "0u".to_string()
    } else {
        batch_terms_b.join(" + ")
    };
    let output_coords: Vec<String> = (0..rank)
        .map(|dimension| {
            if dimension + 2 < rank {
                format!("bc{dimension}")
            } else if dimension + 2 == rank {
                "m".to_string()
            } else {
                "n".to_string()
            }
        })
        .collect();
    let quant = |index: usize| {
        quantization_tensor_index(&plan.inputs[index], &plan.output, &output_coords)
            .expect("quantization tensor validated")
    };
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!("    for (uint kk = 0u; kk < {k}u; ++kk) {{\n"));
    source.push_str(&format!(
        "        float av = float(in{a_index}[{a_base} + m * {}u + kk * {}u]);\n",
        a.strides[rank - 2],
        a.strides[rank - 1]
    ));
    source.push_str(&format!(
        "        float bv = float(in{b_index}[{b_base} + kk * {}u + n * {}u]);\n",
        b.strides[b.sizes.len() - 2],
        b.strides[b.sizes.len() - 1]
    ));
    if let Some(index) = a_zero {
        source.push_str(&format!(
            "        av -= float(in{index}[{}]);\n",
            quant(index)
        ));
    }
    if let Some(index) = b_zero {
        source.push_str(&format!(
            "        bv -= float(in{index}[{}]);\n",
            quant(index)
        ));
    }
    source.push_str("        acc += av * bv;\n    }\n");
    if *quantized_output {
        if let Some(index) = a_scale {
            source.push_str(&format!("    acc *= float(in{index}[{}]);\n", quant(index)));
        }
        if let Some(index) = b_scale {
            source.push_str(&format!("    acc *= float(in{index}[{}]);\n", quant(index)));
        }
        if let Some(index) = out_scale {
            source.push_str(&format!("    acc /= float(in{index}[{}]);\n", quant(index)));
        }
        if let Some(index) = out_zero {
            source.push_str(&format!("    acc += float(in{index}[{}]);\n", quant(index)));
        }
        source.push_str(&format!(
            "    out0[{}] = {};\n}}\n",
            output_index_expr(&plan.output),
            quantized_store(out_scalar, "acc")
        ));
    } else {
        source.push_str(&format!(
            "    out0[{}] = (int)rint(acc);\n}}\n",
            output_index_expr(&plan.output)
        ));
    }
    Ok(source)
}

pub(crate) fn emit_integer_matmul_to_float_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let a_scalar = msl_scalar(plan.inputs[0].data_type, plan.operator_type())?;
    let mut source = msl_header_outputs(plan, a_scalar, &["float"]);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let a = &plan.inputs[0];
    let b_index = quantized_input_index(plan, "B").expect("B");
    let b = &plan.inputs[b_index];
    let a_scale = quantized_input_index(plan, "A scale");
    let b_scale = quantized_input_index(plan, "B scale");
    let a_zero = quantized_input_index(plan, "A zero point");
    let b_zero = quantized_input_index(plan, "B zero point");
    let bias = quantized_input_index(plan, "bias");
    let rank = a.sizes.len();
    let m = plan.output.sizes[rank - 2];
    let n = plan.output.sizes[rank - 1];
    let k = a.sizes[rank - 1];
    source.push_str(&format!(
        "    uint inner = gid % {}u;\n    uint m = inner / {n}u;\n    uint n = inner % {n}u;\n",
        m as u64 * n as u64
    ));
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!("    for (uint kk = 0u; kk < {k}u; ++kk) {{\n"));
    source.push_str(&format!(
        "        float av = float(in0[m * {}u + kk * {}u]);\n",
        a.strides[rank - 2],
        a.strides[rank - 1]
    ));
    source.push_str(&format!(
        "        float bv = float(in{b_index}[kk * {}u + n * {}u]);\n",
        b.strides[b.sizes.len() - 2],
        b.strides[b.sizes.len() - 1]
    ));
    let output_coords = coord_names(rank);
    let quant = |index: usize| {
        quantization_tensor_index(&plan.inputs[index], &plan.output, &output_coords)
            .expect("quantization tensor validated")
    };
    if let Some(index) = a_zero {
        source.push_str(&format!(
            "        av -= float(in{index}[{}]);\n",
            quant(index)
        ));
    }
    if let Some(index) = b_zero {
        source.push_str(&format!(
            "        bv -= float(in{index}[{}]);\n",
            quant(index)
        ));
    }
    source.push_str("        acc += av * bv;\n    }\n");
    if let Some(index) = a_scale {
        source.push_str(&format!("    acc *= float(in{index}[{}]);\n", quant(index)));
    }
    if let Some(index) = b_scale {
        source.push_str(&format!("    acc *= float(in{index}[{}]);\n", quant(index)));
    }
    if let Some(index) = bias {
        source.push_str(&format!("    acc += float(in{index}[{}]);\n", quant(index)));
    }
    source.push_str(&format!(
        "    out0[{}] = acc;\n}}\n",
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

pub(crate) fn emit_integer_convolution_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let DmlOpKind::ConvolutionInteger {
        strides,
        dilations,
        start_padding,
        group_count,
        quantized_output,
        ..
    } = &plan.kind
    else {
        unreachable!("integer convolution emitter");
    };
    let out_scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input_scalar = msl_scalar(plan.inputs[0].data_type, plan.operator_type())?;
    let mut source = msl_header_outputs(plan, input_scalar, &[out_scalar]);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let input = &plan.inputs[0];
    let filter_index = quantized_input_index(plan, "filter").unwrap_or(1);
    let filter = &plan.inputs[filter_index];
    let input_scale = quantized_input_index(plan, "input scale");
    let input_zero = quantized_input_index(plan, "input zero point");
    let filter_scale = quantized_input_index(plan, "filter scale");
    let filter_zero = quantized_input_index(plan, "filter zero point");
    let bias_index = quantized_input_index(plan, "bias");
    let out_scale = quantized_input_index(plan, "output scale");
    let out_zero = quantized_input_index(plan, "output zero point");
    let channels_per_group = input.sizes[1] / group_count;
    let filters_per_group = plan.output.sizes[1] / group_count;
    source.push_str(&format!("    uint group = o1 / {filters_per_group}u;\n"));
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!(
        "    for (uint cg = 0u; cg < {channels_per_group}u; ++cg) {{\n"
    ));
    source.push_str(&format!(
        "        for (uint fy = 0u; fy < {}u; ++fy) {{\n",
        filter.sizes[2]
    ));
    source.push_str(&format!(
        "            int iy = int(o2) * {} - {} + int(fy) * {};\n",
        strides[0], start_padding[0], dilations[0]
    ));
    source.push_str(&format!(
        "            if (iy < 0 || iy >= {}) continue;\n",
        input.sizes[2]
    ));
    source.push_str(&format!(
        "            for (uint fx = 0u; fx < {}u; ++fx) {{\n",
        filter.sizes[3]
    ));
    source.push_str(&format!(
        "                int ix = int(o3) * {} - {} + int(fx) * {};\n",
        strides[1], start_padding[1], dilations[1]
    ));
    source.push_str(&format!(
        "                if (ix < 0 || ix >= {}) continue;\n",
        input.sizes[3]
    ));
    source.push_str(&format!(
        "                uint ic = group * {channels_per_group}u + cg;\n"
    ));
    source.push_str(&format!(
        "                float av = float(in0[o0 * {}u + ic * {}u + uint(iy) * {}u + uint(ix) * {}u]);\n",
        input.strides[0], input.strides[1], input.strides[2], input.strides[3]
    ));
    source.push_str(&format!(
        "                float bv = float(in{filter_index}[o1 * {}u + cg * {}u + fy * {}u + fx * {}u]);\n",
        filter.strides[0], filter.strides[1], filter.strides[2], filter.strides[3]
    ));
    let input_quant_coords = vec![
        "o0".to_string(),
        "ic".to_string(),
        "o2".to_string(),
        "o3".to_string(),
    ];
    let filter_quant_coords = coord_names(4);
    let input_quant = |index: usize| {
        quantization_tensor_index(&plan.inputs[index], &plan.output, &input_quant_coords)
            .expect("quantization tensor validated")
    };
    let filter_quant = |index: usize| {
        quantization_tensor_index(&plan.inputs[index], &plan.output, &filter_quant_coords)
            .expect("quantization tensor validated")
    };
    if let Some(index) = input_zero {
        source.push_str(&format!(
            "                av -= float(in{index}[{}]);\n",
            input_quant(index)
        ));
    }
    if let Some(index) = filter_zero {
        source.push_str(&format!(
            "                bv -= float(in{index}[{}]);\n",
            filter_quant(index)
        ));
    }
    if *quantized_output && let Some(index) = input_scale {
        source.push_str(&format!(
            "                av *= float(in{index}[{}]);\n",
            input_quant(index)
        ));
    }
    source.push_str("                acc += av * bv;\n            }\n        }\n    }\n");
    if *quantized_output {
        let _ = input_scale;
        if let Some(index) = filter_scale {
            source.push_str(&format!(
                "    acc *= float(in{index}[{}]);\n",
                filter_quant(index)
            ));
        }
        if let Some(index) = bias_index {
            source.push_str(&format!("    acc += float(in{index}[o1]);\n"));
        }
        if let Some(index) = out_scale {
            source.push_str(&format!(
                "    acc /= float(in{index}[{}]);\n",
                filter_quant(index)
            ));
        }
        if let Some(index) = out_zero {
            source.push_str(&format!(
                "    acc += float(in{index}[{}]);\n",
                filter_quant(index)
            ));
        }
        source.push_str(&format!(
            "    out0[{}] = {};\n}}\n",
            output_index_expr(&plan.output),
            quantized_store(out_scalar, "acc")
        ));
    } else {
        source.push_str(&format!(
            "    out0[{}] = (int)rint(acc);\n}}\n",
            output_index_expr(&plan.output)
        ));
    }
    Ok(source)
}

pub(crate) fn emit_quantized_avg_pool_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let DmlOpKind::QuantizedLinearAveragePooling {
        strides,
        window,
        start_padding,
        dilations,
        include_padding,
        ..
    } = &plan.kind
    else {
        unreachable!("quantized average pooling emitter");
    };
    let out_scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input_scalar = msl_scalar(plan.inputs[0].data_type, plan.operator_type())?;
    let mut source = msl_header_outputs(plan, input_scalar, &[out_scalar]);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let input = &plan.inputs[0];
    let input_scale = quantized_input_index(plan, "input scale").unwrap_or(1);
    let input_zero = quantized_input_index(plan, "input zero point");
    let out_scale = quantized_input_index(plan, "output scale").unwrap_or(3);
    let out_zero = quantized_input_index(plan, "output zero point");
    let divisor = window[0] as u64 * window[1] as u64;
    source.push_str("    float acc = 0.0f;\n    uint valid = 0u;\n");
    source.push_str(&format!(
        "    for (uint wy = 0u; wy < {}u; ++wy) {{\n",
        window[0]
    ));
    source.push_str(&format!(
        "        int iy = int(o2) * {} - {} + int(wy) * {};\n",
        strides[0], start_padding[0], dilations[0]
    ));
    source.push_str(&format!(
        "        if (iy < 0 || iy >= {}) continue;\n",
        input.sizes[2]
    ));
    source.push_str(&format!(
        "        for (uint wx = 0u; wx < {}u; ++wx) {{\n",
        window[1]
    ));
    source.push_str(&format!(
        "            int ix = int(o3) * {} - {} + int(wx) * {};\n",
        strides[1], start_padding[1], dilations[1]
    ));
    source.push_str(&format!(
        "            if (ix < 0 || ix >= {}) continue;\n",
        input.sizes[3]
    ));
    let channel_coords = coord_names(4);
    let input_quant = |index: usize| {
        quantization_tensor_index(&plan.inputs[index], &plan.output, &channel_coords)
            .expect("quantization tensor validated")
    };
    source.push_str(&format!(
        "            float value = (float(in0[o0 * {}u + o1 * {}u + uint(iy) * {}u + uint(ix) * {}u]) - {}) * float(in{input_scale}[{}]);\n",
        input.strides[0], input.strides[1], input.strides[2], input.strides[3],
        input_zero.map(|i| format!("float(in{i}[{}])", input_quant(i))).unwrap_or_else(|| "0.0f".to_string()),
        input_quant(input_scale)
    ));
    source.push_str("            acc += value;\n            valid += 1u;\n        }\n    }\n");
    let divisor_value = if *include_padding {
        format!("{}", divisor)
    } else {
        "valid".to_string()
    };
    source.push_str(&format!(
        "    float mean = valid == 0u ? 0.0f : acc / float({divisor_value});\n"
    ));
    source.push_str(&format!(
        "    float value = mean / float(in{out_scale}[{}]) + {};\n",
        input_quant(out_scale),
        out_zero
            .map(|i| format!("float(in{i}[{}])", input_quant(i)))
            .unwrap_or_else(|| "0.0f".to_string())
    ));
    source.push_str(&format!(
        "    out0[{}] = {};\n}}\n",
        output_index_expr(&plan.output),
        quantized_store(out_scalar, "value")
    ));
    Ok(source)
}

pub(crate) fn emit_generic_quantize_msl(
    plan: &DmlOpPlan,
    quantization_type: u32,
    dequantize: bool,
) -> DmlResult<String> {
    let out_scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let in_scalar = msl_scalar(plan.inputs[0].data_type, plan.operator_type())?;
    let out_4bit = plan.output.is_4bit();
    let in_4bit = plan.inputs[0].is_4bit();
    let count = plan.output.element_count();
    let mut source = msl_header_outputs(plan, in_scalar, &[out_scalar]);
    let scale_at = |index: &str| -> DmlResult<String> {
        if quantization_type >= 1 {
            Ok(format!(
                "float(in1[{}])",
                quantization_index_for_linear(&plan.inputs[1], &plan.output, index)?
            ))
        } else {
            Ok("1.0f".to_string())
        }
    };
    let zero_at = |index: &str| -> DmlResult<String> {
        if quantization_type >= 2 {
            let desc = &plan.inputs[2];
            let element = quantization_index_for_linear(desc, &plan.output, index)?;
            if desc.is_4bit() {
                Ok(format!(
                    "float({})",
                    packed_read_4bit("in2", &element, desc.data_type == DML_TENSOR_DATA_TYPE_INT4)
                ))
            } else {
                Ok(format!("float(in2[{element}])"))
            }
        } else {
            Ok("0.0f".to_string())
        }
    };
    if out_4bit && !dequantize {
        source.push_str(&format!(
            "    uint base = gid * 2u;\n    if (base >= {count}u) return;\n"
        ));
        let signed = plan.output.data_type == DML_TENSOR_DATA_TYPE_INT4;
        let mut values = Vec::new();
        for offset in 0..2u64 {
            let index = if offset == 0 {
                "base".to_string()
            } else {
                "(base + 1u)".to_string()
            };
            let scale = scale_at(&index)?;
            let zero = zero_at(&index)?;
            let term = format!("(rint(float(in0[{index}]) / {scale}) + {zero})");
            let term = if offset == 0 {
                term
            } else {
                format!("(base + 1u) < {count}u ? {term} : 0.0f")
            };
            values.push(term);
        }
        source.push_str(&format!(
            "    out0[gid] = {};\n}}\n",
            packed_store_4bit(&values[0], &values[1], signed)
        ));
        return Ok(source);
    }
    push_guard(&mut source, &plan.output);
    let scale = scale_at("gid")?;
    let zero = zero_at("gid")?;
    let input_value = if in_4bit {
        let signed = plan.inputs[0].data_type == DML_TENSOR_DATA_TYPE_INT4;
        format!("float({})", packed_read_4bit("in0", "gid", signed))
    } else {
        "float(in0[gid])".to_string()
    };
    if dequantize {
        source.push_str(&format!(
            "    float value = ({input_value} - {zero}) * {scale};\n"
        ));
    } else {
        source.push_str(&format!(
            "    float value = rint({input_value} / {scale}) + {zero};\n"
        ));
    }
    source.push_str(&format!(
        "    out0[gid] = {};\n}}\n",
        quantized_store(out_scalar, "value")
    ));
    Ok(source)
}

pub(crate) fn execute_quantize_linear_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    dequantize: bool,
) -> DmlResult<()> {
    let count = plan.output.element_count();
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let scale_index = quantization_element_index(&plan.inputs[1], &plan.output, &coords);
        let scale = load_scalar(inputs[1], scale_index, plan.inputs[1].data_type);
        let zero = if plan.inputs.len() == 3 {
            let index = quantization_element_index(&plan.inputs[2], &plan.output, &coords);
            load_scalar(inputs[2], index, plan.inputs[2].data_type)
        } else {
            0.0
        };
        let source = load_scalar(inputs[0], gid, plan.inputs[0].data_type);
        let value = if dequantize {
            (source - zero) * scale
        } else {
            (source / scale).round_ties_even() + zero
        };
        let index = output_index(&plan.output, gid);
        if dequantize {
            store_scalar(output, index, plan.output.data_type, value);
        } else {
            store_quantized(output, index, plan.output.data_type, value);
        }
    }
    Ok(())
}

pub(crate) fn execute_dynamic_quantize_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    extras: &mut [&mut [u8]],
) -> DmlResult<()> {
    let count = plan.output.element_count();
    let mut minimum = 0.0f32;
    let mut maximum = 0.0f32;
    for gid in 0..count {
        let value = load_scalar(input_bytes, gid, plan.inputs[0].data_type);
        minimum = minimum.min(value);
        maximum = maximum.max(value);
    }
    let range = maximum - minimum;
    let scale = if range == 0.0 { 1.0 } else { range / 255.0 };
    let zero = (-minimum / scale).round_ties_even().clamp(0.0, 255.0);
    for gid in 0..count {
        let value = load_scalar(input_bytes, gid, plan.inputs[0].data_type);
        store_quantized(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            (value / scale).round_ties_even() + zero,
        );
    }
    let scale_desc = &plan.extra_outputs[0];
    let zero_desc = &plan.extra_outputs[1];
    store_scalar(extras[0], 0, scale_desc.data_type, scale);
    store_quantized(extras[1], 0, zero_desc.data_type, zero);
    Ok(())
}

pub(crate) fn execute_quantized_add_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
) -> DmlResult<()> {
    let count = plan.output.element_count();
    let a_index = quantized_input_index(plan, "A").expect("A");
    let a_scale = quantized_input_index(plan, "A scale").expect("A scale");
    let a_zero = quantized_input_index(plan, "A zero point");
    let b_index = quantized_input_index(plan, "B").expect("B");
    let b_scale = quantized_input_index(plan, "B scale").expect("B scale");
    let b_zero = quantized_input_index(plan, "B zero point");
    let out_scale = quantized_input_index(plan, "output scale").expect("output scale");
    let out_zero = quantized_input_index(plan, "output zero point");
    let quant = |index: usize, coords: &[u64]| {
        let element = quantization_element_index(&plan.inputs[index], &plan.output, coords);
        load_scalar(inputs[index], element, plan.inputs[index].data_type)
    };
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let a = (load_scalar(inputs[a_index], gid, plan.inputs[a_index].data_type)
            - a_zero.map(|index| quant(index, &coords)).unwrap_or(0.0))
            * quant(a_scale, &coords);
        let b = (load_scalar(inputs[b_index], gid, plan.inputs[b_index].data_type)
            - b_zero.map(|index| quant(index, &coords)).unwrap_or(0.0))
            * quant(b_scale, &coords);
        store_quantized(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            (a + b) / quant(out_scale, &coords)
                + out_zero.map(|index| quant(index, &coords)).unwrap_or(0.0),
        );
    }
    Ok(())
}

pub(crate) fn execute_integer_matmul_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
) -> DmlResult<()> {
    let DmlOpKind::MatrixMultiplyInteger {
        quantized_output, ..
    } = &plan.kind
    else {
        unreachable!("integer matmul CPU");
    };
    let a = &plan.inputs[0];
    let b_index = quantized_input_index(plan, "B").expect("B");
    let b = &plan.inputs[b_index];
    let a_scale = quantized_input_index(plan, "A scale");
    let b_scale = quantized_input_index(plan, "B scale");
    let a_zero = quantized_input_index(plan, "A zero point");
    let b_zero = quantized_input_index(plan, "B zero point");
    let out_scale = quantized_input_index(plan, "output scale");
    let out_zero = quantized_input_index(plan, "output zero point");
    let count = plan.output.element_count();
    let rank = a.sizes.len();
    let inner = a.sizes[rank - 1];
    let n = plan.output.sizes[rank - 1];
    let quant = |index: usize, coords: &[u64]| {
        let element = quantization_element_index(&plan.inputs[index], &plan.output, coords);
        load_scalar(inputs[index], element, plan.inputs[index].data_type) as f64
    };
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let batch = coords[..rank - 2].to_vec();
        let m = coords[rank - 2];
        let column = coords[rank - 1];
        let a_zero_value = a_zero.map(|index| quant(index, &coords));
        let b_zero_value = b_zero.map(|index| quant(index, &coords));
        let mut acc = 0.0f64;
        for kk in 0..inner as u64 {
            let mut a_coords = batch.clone();
            a_coords.push(m);
            a_coords.push(kk);
            let mut b_coords = batch.clone();
            b_coords.push(kk);
            b_coords.push(column);
            let mut av =
                load_scalar(inputs[0], index_of(&a_coords, &a.strides), a.data_type) as f64;
            let mut bv = load_scalar(
                inputs[b_index],
                index_of(&b_coords, &b.strides),
                b.data_type,
            ) as f64;
            if let Some(zero) = a_zero_value {
                av -= zero;
            }
            if let Some(zero) = b_zero_value {
                bv -= zero;
            }
            acc += av * bv;
        }
        let index = output_index(&plan.output, gid);
        if *quantized_output {
            if let Some(index) = a_scale {
                acc *= quant(index, &coords);
            }
            if let Some(index) = b_scale {
                acc *= quant(index, &coords);
            }
            if let Some(index) = out_scale {
                acc /= quant(index, &coords);
            }
            if let Some(index) = out_zero {
                acc += quant(index, &coords);
            }
            store_quantized(output, index, plan.output.data_type, acc as f32);
        } else {
            store_integer(output, index, plan.output.data_type, acc.round() as i64);
        }
        let _ = n;
    }
    Ok(())
}

pub(crate) fn execute_integer_convolution_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
) -> DmlResult<()> {
    let DmlOpKind::ConvolutionInteger {
        strides,
        dilations,
        start_padding,
        group_count,
        quantized_output,
        ..
    } = &plan.kind
    else {
        unreachable!("integer convolution CPU");
    };
    let input = &plan.inputs[0];
    let filter_index = quantized_input_index(plan, "filter").expect("filter");
    let filter = &plan.inputs[filter_index];
    let input_scale = quantized_input_index(plan, "input scale");
    let input_zero = quantized_input_index(plan, "input zero point");
    let filter_scale = quantized_input_index(plan, "filter scale");
    let filter_zero = quantized_input_index(plan, "filter zero point");
    let bias_index = quantized_input_index(plan, "bias");
    let out_scale = quantized_input_index(plan, "output scale");
    let out_zero = quantized_input_index(plan, "output zero point");
    let count = plan.output.element_count();
    let channels_per_group = input.sizes[1] / group_count;
    let filters_per_group = plan.output.sizes[1] / group_count;
    let quant = |index: usize, coords: &[u64]| {
        let element = quantization_element_index(&plan.inputs[index], &plan.output, coords);
        load_scalar(inputs[index], element, plan.inputs[index].data_type) as f64
    };
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let [batch, out_channel, oh, ow] = [coords[0], coords[1], coords[2], coords[3]];
        let group = out_channel / filters_per_group as u64;
        let mut acc = 0.0f64;
        for cg in 0..channels_per_group as u64 {
            let input_channel = group * channels_per_group as u64 + cg;
            let input_quant_coords = [batch, input_channel, oh, ow];
            for fy in 0..filter.sizes[2] as u64 {
                let iy = oh as i64 * strides[0] as i64 - start_padding[0] as i64
                    + fy as i64 * dilations[0] as i64;
                if iy < 0 || iy >= input.sizes[2] as i64 {
                    continue;
                }
                for fx in 0..filter.sizes[3] as u64 {
                    let ix = ow as i64 * strides[1] as i64 - start_padding[1] as i64
                        + fx as i64 * dilations[1] as i64;
                    if ix < 0 || ix >= input.sizes[3] as i64 {
                        continue;
                    }
                    let mut av = load_scalar(
                        inputs[0],
                        index_of(
                            &[batch, input_channel, iy as u64, ix as u64],
                            &input.strides,
                        ),
                        input.data_type,
                    ) as f64;
                    let mut bv = load_scalar(
                        inputs[filter_index],
                        index_of(&[out_channel, cg, fy, fx], &filter.strides),
                        filter.data_type,
                    ) as f64;
                    if let Some(index) = input_zero {
                        av -= quant(index, &input_quant_coords);
                    }
                    if let Some(index) = filter_zero {
                        bv -= quant(index, &coords);
                    }
                    if let Some(index) = input_scale {
                        av *= quant(index, &input_quant_coords);
                    }
                    acc += av * bv;
                }
            }
        }
        let index = output_index(&plan.output, gid);
        if *quantized_output {
            let _ = input_scale;
            if let Some(index) = filter_scale {
                acc *= quant(index, &coords);
            }
            if let Some(index) = bias_index {
                acc += load_scalar(inputs[index], out_channel, plan.inputs[index].data_type) as f64;
            }
            if let Some(index) = out_scale {
                acc /= quant(index, &coords);
            }
            if let Some(index) = out_zero {
                acc += quant(index, &coords);
            }
            store_quantized(output, index, plan.output.data_type, acc as f32);
        } else {
            store_integer(output, index, plan.output.data_type, acc.round() as i64);
        }
    }
    Ok(())
}

pub(crate) fn execute_quantized_avg_pool_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
) -> DmlResult<()> {
    let DmlOpKind::QuantizedLinearAveragePooling {
        strides,
        window,
        start_padding,
        dilations,
        include_padding,
        ..
    } = &plan.kind
    else {
        unreachable!("quantized average pooling CPU");
    };
    let input = &plan.inputs[0];
    let input_scale = quantized_input_index(plan, "input scale").expect("input scale");
    let input_zero = quantized_input_index(plan, "input zero point");
    let out_scale = quantized_input_index(plan, "output scale").expect("output scale");
    let out_zero = quantized_input_index(plan, "output zero point");
    let count = plan.output.element_count();
    let divisor = window[0] as u64 * window[1] as u64;
    let quant = |index: usize, coords: &[u64]| {
        let element = quantization_element_index(&plan.inputs[index], &plan.output, coords);
        load_scalar(inputs[index], element, plan.inputs[index].data_type)
    };
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let [batch, channel, oh, ow] = [coords[0], coords[1], coords[2], coords[3]];
        let input_scale_value = quant(input_scale, &coords);
        let input_zero_value = input_zero.map(|index| quant(index, &coords)).unwrap_or(0.0);
        let out_scale_value = quant(out_scale, &coords);
        let out_zero_value = out_zero.map(|index| quant(index, &coords)).unwrap_or(0.0);
        let mut sum = 0.0f64;
        let mut valid = 0u64;
        for wy in 0..window[0] as u64 {
            let iy = oh as i64 * strides[0] as i64 - start_padding[0] as i64
                + wy as i64 * dilations[0] as i64;
            if iy < 0 || iy >= input.sizes[2] as i64 {
                continue;
            }
            for wx in 0..window[1] as u64 {
                let ix = ow as i64 * strides[1] as i64 - start_padding[1] as i64
                    + wx as i64 * dilations[1] as i64;
                if ix < 0 || ix >= input.sizes[3] as i64 {
                    continue;
                }
                let value = load_scalar(
                    inputs[0],
                    index_of(&[batch, channel, iy as u64, ix as u64], &input.strides),
                    input.data_type,
                ) - input_zero_value;
                sum += (value * input_scale_value) as f64;
                valid += 1;
            }
        }
        let mean = if valid == 0 {
            0.0
        } else if *include_padding {
            sum / divisor as f64
        } else {
            sum / valid as f64
        };
        store_quantized(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            (mean as f32) / out_scale_value + out_zero_value,
        );
    }
    Ok(())
}

pub(crate) fn execute_integer_matmul_to_float_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
) -> DmlResult<()> {
    let a = &plan.inputs[0];
    let b_index = quantized_input_index(plan, "B").expect("B");
    let b = &plan.inputs[b_index];
    let a_scale = quantized_input_index(plan, "A scale");
    let b_scale = quantized_input_index(plan, "B scale");
    let a_zero = quantized_input_index(plan, "A zero point");
    let b_zero = quantized_input_index(plan, "B zero point");
    let bias = quantized_input_index(plan, "bias");
    let count = plan.output.element_count();
    let rank = a.sizes.len();
    let inner = a.sizes[rank - 1];
    let quant = |index: usize, coords: &[u64]| {
        let element = quantization_element_index(&plan.inputs[index], &plan.output, coords);
        load_scalar(inputs[index], element, plan.inputs[index].data_type) as f64
    };
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let batch = coords[..rank - 2].to_vec();
        let m = coords[rank - 2];
        let column = coords[rank - 1];
        let a_zero_value = a_zero.map(|index| quant(index, &coords));
        let b_zero_value = b_zero.map(|index| quant(index, &coords));
        let mut acc = 0.0f64;
        for kk in 0..inner as u64 {
            let mut a_coords = batch.clone();
            a_coords.push(m);
            a_coords.push(kk);
            let mut b_coords = batch.clone();
            b_coords.push(kk);
            b_coords.push(column);
            let mut av =
                load_scalar(inputs[0], index_of(&a_coords, &a.strides), a.data_type) as f64;
            let mut bv = load_scalar(
                inputs[b_index],
                index_of(&b_coords, &b.strides),
                b.data_type,
            ) as f64;
            if let Some(zero) = a_zero_value {
                av -= zero;
            }
            if let Some(zero) = b_zero_value {
                bv -= zero;
            }
            acc += av * bv;
        }
        if let Some(index) = a_scale {
            acc *= quant(index, &coords);
        }
        if let Some(index) = b_scale {
            acc *= quant(index, &coords);
        }
        if let Some(index) = bias {
            acc += quant(index, &coords);
        }
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            acc as f32,
        );
    }
    Ok(())
}

pub(crate) fn execute_generic_quantize_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    quantization_type: u32,
    dequantize: bool,
) -> DmlResult<()> {
    let count = plan.output.element_count();
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let scale = if quantization_type >= 1 {
            let element = quantization_element_index(&plan.inputs[1], &plan.output, &coords);
            load_scalar(inputs[1], element, plan.inputs[1].data_type)
        } else {
            1.0
        };
        let zero = if quantization_type == 2 {
            let element = quantization_element_index(&plan.inputs[2], &plan.output, &coords);
            load_scalar(inputs[2], element, plan.inputs[2].data_type)
        } else {
            0.0
        };
        let source = load_scalar(inputs[0], gid, plan.inputs[0].data_type);
        let index = output_index(&plan.output, gid);
        if dequantize {
            store_scalar(
                output,
                index,
                plan.output.data_type,
                (source - zero) * scale,
            );
        } else {
            store_quantized(
                output,
                index,
                plan.output.data_type,
                (source / scale).round_ties_even() + zero,
            );
        }
    }
    Ok(())
}
