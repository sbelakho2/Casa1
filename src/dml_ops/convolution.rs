//! Convolution portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_convolution(
        &self,
        mode: u32,
        strides: &[u32],
        dilations: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
        output_padding: &[u32],
        group_count: u32,
    ) -> DmlResult<()> {
        if mode != DML_CONVOLUTION_MODE_CONVOLUTION
            && mode != DML_CONVOLUTION_MODE_CROSS_CORRELATION
        {
            return Err(DmlError::invalid(format!(
                "convolution mode {mode} is not supported"
            )));
        }
        if !(2..=3).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "convolution requires 2 or 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let filter = &self.inputs[1];
        if input.sizes.len() != 4 || filter.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "convolution requires rank-4 NCHW tensors",
            ));
        }
        for (name, values) in [
            ("strides", strides),
            ("dilations", dilations),
            ("start padding", start_padding),
            ("end padding", end_padding),
            ("output padding", output_padding),
        ] {
            if values.len() != 2 {
                return Err(DmlError::invalid(format!(
                    "convolution {name} must have 2 entries"
                )));
            }
        }
        if strides.contains(&0) {
            return Err(DmlError::invalid("convolution strides must be non-zero"));
        }
        if dilations.contains(&0) {
            return Err(DmlError::invalid("convolution dilations must be non-zero"));
        }
        if group_count == 0 {
            return Err(DmlError::invalid(
                "convolution group count must be non-zero",
            ));
        }
        let [n, c, h, w] = [
            input.sizes[0],
            input.sizes[1],
            input.sizes[2],
            input.sizes[3],
        ];
        let [k, filter_c, kh, kw] = [
            filter.sizes[0],
            filter.sizes[1],
            filter.sizes[2],
            filter.sizes[3],
        ];
        if c % group_count != 0 || k % group_count != 0 {
            return Err(DmlError::invalid(
                "convolution group count must divide both input and filter channels",
            ));
        }
        if filter_c != c / group_count {
            return Err(DmlError::invalid(format!(
                "convolution filter channel count {filter_c} must equal input channels / groups ({})",
                c / group_count
            )));
        }
        let oh = convolution_output_size(
            h,
            kh,
            strides[0],
            dilations[0],
            start_padding[0],
            end_padding[0],
            output_padding[0],
        )?;
        let ow = convolution_output_size(
            w,
            kw,
            strides[1],
            dilations[1],
            start_padding[1],
            end_padding[1],
            output_padding[1],
        )?;
        let expected = [n, k, oh, ow];
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "convolution output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        if let Some(bias) = self.inputs.get(2) {
            if bias.element_count() != k as u64 {
                return Err(DmlError::invalid(format!(
                    "convolution bias element count {} must equal output channels {k}",
                    bias.element_count()
                )));
            }
            if !bias.is_contiguous() {
                return Err(DmlError::invalid(
                    "convolution bias tensor must be contiguous",
                ));
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_convolution_msl(
    plan: &DmlOpPlan,
    mode: u32,
    strides: &[u32],
    dilations: &[u32],
    start_padding: &[u32],
    group_count: u32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let filter = &plan.inputs[1];
    let k = plan.output.sizes[1];
    let [_in_n, c, ih, iw] = [
        input.sizes[0],
        input.sizes[1],
        input.sizes[2],
        input.sizes[3],
    ];
    let [kh, kw] = [filter.sizes[2], filter.sizes[3]];
    let channels_per_group = c / group_count;
    let filters_per_group = k / group_count;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!("    uint group = o1 / {filters_per_group}u;\n"));
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!(
        "    for (uint cg = 0u; cg < {channels_per_group}u; ++cg) {{\n"
    ));
    source.push_str(&format!(
        "        for (uint fy = 0u; fy < {kh}u; ++fy) {{\n"
    ));
    source.push_str(&format!(
        "            int iy = int(o2) * {} - {} + int(fy) * {};\n",
        strides[0], start_padding[0], dilations[0]
    ));
    source.push_str(&format!(
        "            if (iy < 0 || iy >= {ih}) continue;\n"
    ));
    source.push_str(&format!(
        "            for (uint fx = 0u; fx < {kw}u; ++fx) {{\n"
    ));
    source.push_str(&format!(
        "                int ix = int(o3) * {} - {} + int(fx) * {};\n",
        strides[1], start_padding[1], dilations[1]
    ));
    source.push_str(&format!(
        "                if (ix < 0 || ix >= {iw}) continue;\n"
    ));
    source.push_str(&format!(
        "                uint ic = group * {channels_per_group}u + cg;\n"
    ));
    let input_index = format!(
        "o0 * {}u + ic * {}u + uint(iy) * {}u + uint(ix) * {}u",
        input.strides[0], input.strides[1], input.strides[2], input.strides[3]
    );
    let (filter_y, filter_x) = if mode == DML_CONVOLUTION_MODE_CONVOLUTION {
        (format!("({kh}u - 1u - fy)"), format!("({kw}u - 1u - fx)"))
    } else {
        ("fy".to_string(), "fx".to_string())
    };
    let filter_index = format!(
        "o1 * {}u + cg * {}u + {filter_y} * {}u + {filter_x} * {}u",
        filter.strides[0], filter.strides[1], filter.strides[2], filter.strides[3]
    );
    source.push_str(&format!(
        "                acc += {} * {};\n",
        msl_load_float(input, "in0", &input_index),
        msl_load_float(filter, "in1", &filter_index)
    ));
    source.push_str("            }\n");
    source.push_str("        }\n");
    source.push_str("    }\n");
    if plan.inputs.len() == 3 {
        source.push_str(&format!(
            "    acc += float(in2[{}]);\n",
            if plan.inputs[2].is_contiguous() {
                "o1".to_string()
            } else {
                format!("o1 * {}u", plan.inputs[2].strides[0])
            }
        ));
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})acc;\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}
