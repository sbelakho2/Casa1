//! Pooling portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_lp_pooling(
        &self,
        p: u32,
        strides: &[u32],
        window: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
        dilations: &[u32],
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        if input.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid("LP pooling requires rank-4 NCHW tensors"));
        }
        let dimensions = input.sizes.len() - 2;
        for (name, values) in [
            ("strides", strides),
            ("window", window),
            ("start padding", start_padding),
            ("end padding", end_padding),
        ] {
            if values.len() != dimensions {
                return Err(DmlError::invalid(format!(
                    "LP pooling {name} must have {dimensions} entries"
                )));
            }
        }
        if !dilations.is_empty() && dilations.len() != dimensions {
            return Err(DmlError::invalid(format!(
                "LP pooling dilations must have {dimensions} entries"
            )));
        }
        if p == 0 {
            return Err(DmlError::invalid("LP pooling P must be non-zero"));
        }
        if strides.contains(&0) || window.contains(&0) {
            return Err(DmlError::invalid(
                "LP pooling strides and window must be non-zero",
            ));
        }
        if dilations.contains(&0) {
            return Err(DmlError::invalid("LP pooling dilations must be non-zero"));
        }
        let mut expected = vec![input.sizes[0], input.sizes[1]];
        for dimension in 0..dimensions {
            let dilation = dilations.get(dimension).copied().unwrap_or(1);
            expected.push(pooling_output_size_dilated(
                input.sizes[dimension + 2],
                window[dimension],
                strides[dimension],
                start_padding[dimension],
                end_padding[dimension],
                dilation,
                "LP pooling",
            )?);
        }
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "LP pooling output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_average_pooling1(
        &self,
        strides: &[u32],
        window: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
        dilations: &[u32],
        _include_padding: bool,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        if input.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "average pooling1 requires rank-4 NCHW tensors",
            ));
        }
        let dimensions = input.sizes.len() - 2;
        for (name, values) in [
            ("strides", strides),
            ("window", window),
            ("start padding", start_padding),
            ("end padding", end_padding),
            ("dilations", dilations),
        ] {
            if values.len() != dimensions {
                return Err(DmlError::invalid(format!(
                    "average pooling1 {name} must have {dimensions} entries"
                )));
            }
        }
        if strides.contains(&0) || window.contains(&0) || dilations.contains(&0) {
            return Err(DmlError::invalid(
                "average pooling1 strides, window, and dilations must be non-zero",
            ));
        }
        let mut expected = vec![input.sizes[0], input.sizes[1]];
        for dimension in 0..dimensions {
            expected.push(pooling_output_size_dilated(
                input.sizes[dimension + 2],
                window[dimension],
                strides[dimension],
                start_padding[dimension],
                end_padding[dimension],
                dilations[dimension],
                "average pooling1",
            )?);
        }
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "average pooling1 output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_max_pooling_ex(
        &self,
        strides: &[u32],
        window: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
        dilations: &[u32],
        has_indices: bool,
        _dilations_supported: bool,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        if input.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "max pooling requires rank-4 NCHW tensors",
            ));
        }
        let dimensions = input.sizes.len() - 2;
        for (name, values) in [
            ("strides", strides),
            ("window", window),
            ("start padding", start_padding),
            ("end padding", end_padding),
        ] {
            if values.len() != dimensions {
                return Err(DmlError::invalid(format!(
                    "max pooling {name} must have {dimensions} entries"
                )));
            }
        }
        if dilations.len() != dimensions {
            return Err(DmlError::invalid(format!(
                "max pooling dilations must have {dimensions} entries"
            )));
        }
        if strides.contains(&0) || window.contains(&0) || dilations.contains(&0) {
            return Err(DmlError::invalid(
                "max pooling strides, window, and dilations must be non-zero",
            ));
        }
        let mut expected = vec![input.sizes[0], input.sizes[1]];
        for dimension in 0..dimensions {
            expected.push(pooling_output_size_dilated(
                input.sizes[dimension + 2],
                window[dimension],
                strides[dimension],
                start_padding[dimension],
                end_padding[dimension],
                dilations[dimension],
                "max pooling",
            )?);
        }
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "max pooling output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        if has_indices {
            if self.extra_outputs.len() != 1 {
                return Err(DmlError::invalid(
                    "max pooling with indices requires exactly one index output",
                ));
            }
            if self.extra_outputs[0].sizes != self.output.sizes {
                return Err(DmlError::invalid(
                    "max pooling index output sizes must match the value output",
                ));
            }
        } else if !self.extra_outputs.is_empty() {
            return Err(DmlError::invalid(
                "max pooling without indices must not have additional outputs",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_max_unpooling(&self) -> DmlResult<()> {
        self.require_input_count(2)?;
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        if input.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "max unpooling requires rank-4 NCHW tensors",
            ));
        }
        if input.sizes != indices.sizes {
            return Err(DmlError::invalid(
                "max unpooling input and index sizes must match",
            ));
        }
        if input.sizes[0] != self.output.sizes[0] || input.sizes[1] != self.output.sizes[1] {
            return Err(DmlError::invalid(
                "max unpooling output batch and channel sizes must match the input",
            ));
        }
        if self.output.sizes[2] < input.sizes[2] || self.output.sizes[3] < input.sizes[3] {
            return Err(DmlError::invalid(
                "max unpooling output spatial dimensions must be at least the input dimensions",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_avg_pool_grad(
        &self,
        strides: &[u32],
        window: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
        _include_padding: bool,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let gradient = &self.inputs[0];
        if gradient.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "average pooling gradient requires rank-4 NCHW tensors",
            ));
        }
        let dimensions = 2;
        for (name, values) in [
            ("strides", strides),
            ("window", window),
            ("start padding", start_padding),
            ("end padding", end_padding),
        ] {
            if values.len() != dimensions {
                return Err(DmlError::invalid(format!(
                    "average pooling gradient {name} must have {dimensions} entries"
                )));
            }
        }
        if strides.contains(&0) || window.contains(&0) {
            return Err(DmlError::invalid(
                "average pooling gradient strides and window must be non-zero",
            ));
        }
        if gradient.sizes[0] != self.output.sizes[0] || gradient.sizes[1] != self.output.sizes[1] {
            return Err(DmlError::invalid(
                "average pooling gradient batch and channel sizes must match the output",
            ));
        }
        if self.output.sizes[2] == 0 || self.output.sizes[3] == 0 {
            return Err(DmlError::invalid(
                "average pooling gradient output spatial dimensions must be non-zero",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_max_pool_grad(
        &self,
        strides: &[u32],
        window: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
        dilations: &[u32],
    ) -> DmlResult<()> {
        self.require_input_count(2)?;
        let input = &self.inputs[0];
        let gradient = &self.inputs[1];
        if input.sizes.len() != 4 || gradient.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "max pooling gradient requires rank-4 NCHW tensors",
            ));
        }
        let dimensions = 2;
        for (name, values) in [
            ("strides", strides),
            ("window", window),
            ("start padding", start_padding),
            ("end padding", end_padding),
            ("dilations", dilations),
        ] {
            if values.len() != dimensions {
                return Err(DmlError::invalid(format!(
                    "max pooling gradient {name} must have {dimensions} entries"
                )));
            }
        }
        if strides.contains(&0) || window.contains(&0) || dilations.contains(&0) {
            return Err(DmlError::invalid(
                "max pooling gradient strides, window, and dilations must be non-zero",
            ));
        }
        if input.sizes != self.output.sizes {
            return Err(DmlError::invalid(
                "max pooling gradient input and output sizes must match",
            ));
        }
        let mut expected = vec![input.sizes[0], input.sizes[1]];
        for dimension in 0..dimensions {
            expected.push(pooling_output_size_dilated(
                input.sizes[dimension + 2],
                window[dimension],
                strides[dimension],
                start_padding[dimension],
                end_padding[dimension],
                dilations[dimension],
                "max pooling gradient",
            )?);
        }
        if gradient.sizes != expected {
            return Err(DmlError::invalid(format!(
                "max pooling gradient input gradient sizes must be {expected:?}, got {:?}",
                gradient.sizes
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_roi_align_grad(
        &self,
        reduction: DmlReduceKind,
        _mode: DmlInterpolationMode,
        spatial_scale_x: f32,
        spatial_scale_y: f32,
        input_pixel_offset: f32,
        output_pixel_offset: f32,
        minimum_samples_per_output: u32,
        maximum_samples_per_output: u32,
        align_regions_to_corners: bool,
    ) -> DmlResult<()> {
        if !(3..=4).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "ROI align gradient expects 3 or 4 input tensors, got {}",
                self.inputs.len()
            )));
        }
        if !self.extra_outputs.is_empty() {
            return Err(DmlError::invalid(
                "ROI align gradient ROI coordinate gradients are not supported",
            ));
        }
        let (gradient_index, roi_index) = if self.inputs.len() == 4 {
            (1usize, 2usize)
        } else {
            (0usize, 1usize)
        };
        let batch_index = roi_index + 1;
        let gradient = &self.inputs[gradient_index];
        let roi = &self.inputs[roi_index];
        if gradient.sizes.len() != 4 || roi.sizes.len() != 2 {
            return Err(DmlError::invalid(
                "ROI align gradient requires a rank-4 input gradient and rank-2 ROI tensor",
            ));
        }
        if roi.sizes[1] != 4 {
            return Err(DmlError::invalid(format!(
                "ROI align gradient ROI tensor must have 4 columns, got {}",
                roi.sizes[1]
            )));
        }
        if self.inputs[batch_index].element_count() != roi.sizes[0] as u64 {
            return Err(DmlError::invalid(format!(
                "ROI align gradient batch indices must contain {} elements",
                roi.sizes[0]
            )));
        }
        if !matches!(reduction, DmlReduceKind::Max | DmlReduceKind::Mean) {
            return Err(DmlError::invalid(
                "ROI align gradient supports only max and average reduction",
            ));
        }
        if reduction == DmlReduceKind::Max && self.inputs.len() != 4 {
            return Err(DmlError::invalid(
                "ROI align max gradient requires the forward input tensor",
            ));
        }
        if !spatial_scale_x.is_finite()
            || !spatial_scale_y.is_finite()
            || !input_pixel_offset.is_finite()
            || !output_pixel_offset.is_finite()
        {
            return Err(DmlError::invalid(
                "ROI align gradient scales and offsets must be finite",
            ));
        }
        if minimum_samples_per_output == 0
            || maximum_samples_per_output < minimum_samples_per_output
            || maximum_samples_per_output > 64
        {
            return Err(DmlError::invalid(format!(
                "ROI align gradient sample counts must satisfy 1 <= minimum <= maximum <= 64, got {minimum_samples_per_output}..{maximum_samples_per_output}"
            )));
        }
        let _ = align_regions_to_corners;
        if self.output.sizes.len() != 4 {
            return Err(DmlError::invalid(
                "ROI align gradient output must be a rank-4 tensor",
            ));
        }
        if gradient.sizes[0] != self.output.sizes[0] || gradient.sizes[1] != self.output.sizes[1] {
            return Err(DmlError::invalid(
                "ROI align gradient batch and channel sizes must match the output",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_pooling(
        &self,
        strides: &[u32],
        window: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        if input.sizes.len() != 4 || self.output.sizes.len() != 4 {
            return Err(DmlError::invalid("pooling requires rank-4 NCHW tensors"));
        }
        if strides.len() != 2 || window.len() != 2 {
            return Err(DmlError::invalid(
                "pooling strides and window must have 2 entries",
            ));
        }
        if start_padding.len() != 2 || end_padding.len() != 2 {
            return Err(DmlError::invalid("pooling padding must have 2 entries"));
        }
        if strides.contains(&0) {
            return Err(DmlError::invalid("pooling strides must be non-zero"));
        }
        if window.contains(&0) {
            return Err(DmlError::invalid("pooling window must be non-zero"));
        }
        let [n, c, h, w] = [
            input.sizes[0],
            input.sizes[1],
            input.sizes[2],
            input.sizes[3],
        ];
        let oh = pooling_output_size(h, window[0], strides[0], start_padding[0], end_padding[0])?;
        let ow = pooling_output_size(w, window[1], strides[1], start_padding[1], end_padding[1])?;
        let expected = [n, c, oh, ow];
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "pooling output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_roi_pooling(&self, spatial_scale: f32, pooled: &[u32]) -> DmlResult<()> {
        if self.inputs.len() != 2 {
            return Err(DmlError::invalid(format!(
                "ROI pooling requires 2 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let roi = &self.inputs[1];
        if input.sizes.len() != 4 || roi.sizes.len() != 2 {
            return Err(DmlError::invalid(
                "ROI pooling requires a rank-4 input and rank-2 ROI tensor",
            ));
        }
        if roi.sizes[1] != 5 {
            return Err(DmlError::invalid(format!(
                "ROI pooling ROI tensor must have 5 columns, got {}",
                roi.sizes[1]
            )));
        }
        if pooled.len() != 2 || pooled.contains(&0) {
            return Err(DmlError::invalid(
                "ROI pooling PooledSize must contain two non-zero entries",
            ));
        }
        if !spatial_scale.is_finite() || spatial_scale < 0.0 {
            return Err(DmlError::invalid(
                "ROI pooling SpatialScale must be finite and non-negative",
            ));
        }
        let expected = [roi.sizes[0], input.sizes[1], pooled[0], pooled[1]];
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "ROI pooling output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_roi_align(
        &self,
        reduction: DmlReduceKind,
        _mode: DmlInterpolationMode,
        spatial_scale_x: f32,
        spatial_scale_y: f32,
        input_pixel_offset: f32,
        output_pixel_offset: f32,
        out_of_bounds_value: f32,
        minimum_samples_per_output: u32,
        maximum_samples_per_output: u32,
        _align_regions_to_corners: bool,
    ) -> DmlResult<()> {
        if self.inputs.len() != 3 {
            return Err(DmlError::invalid(format!(
                "ROI align requires 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let roi = &self.inputs[1];
        let batch_indices = &self.inputs[2];
        if input.sizes.len() != 4 || roi.sizes.len() != 2 {
            return Err(DmlError::invalid(
                "ROI align requires a rank-4 input and rank-2 ROI tensor",
            ));
        }
        if roi.sizes[1] != 4 {
            return Err(DmlError::invalid(format!(
                "ROI align ROI tensor must have 4 columns, got {}",
                roi.sizes[1]
            )));
        }
        if batch_indices.element_count() != roi.sizes[0] as u64 || !batch_indices.is_contiguous() {
            return Err(DmlError::invalid(format!(
                "ROI align batch indices must contain {} contiguous elements",
                roi.sizes[0]
            )));
        }
        if !matches!(reduction, DmlReduceKind::Max | DmlReduceKind::Mean) {
            return Err(DmlError::invalid(
                "ROI align supports only max and average reduction",
            ));
        }
        if !spatial_scale_x.is_finite()
            || !spatial_scale_y.is_finite()
            || !input_pixel_offset.is_finite()
            || !output_pixel_offset.is_finite()
            || !out_of_bounds_value.is_finite()
        {
            return Err(DmlError::invalid(
                "ROI align scales, offsets, and out-of-bounds value must be finite",
            ));
        }
        if minimum_samples_per_output == 0
            || maximum_samples_per_output < minimum_samples_per_output
            || maximum_samples_per_output > 64
        {
            return Err(DmlError::invalid(format!(
                "ROI align sample counts must satisfy 1 <= minimum <= maximum <= 64, got {minimum_samples_per_output}..{maximum_samples_per_output}"
            )));
        }
        let expected = [
            roi.sizes[0],
            input.sizes[1],
            self.output.sizes[2],
            self.output.sizes[3],
        ];
        if self.output.sizes.len() != 4 || self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "ROI align output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        if expected[2] == 0 || expected[3] == 0 {
            return Err(DmlError::invalid(
                "ROI align output spatial sizes must be non-zero",
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_average_pooling1_msl(
    plan: &DmlOpPlan,
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    _end_padding: &[u32],
    dilations: &[u32],
    include_padding: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str("    float acc = 0.0f;\n    uint valid = 0u;\n");
    for dimension in 0..2 {
        source.push_str(&format!(
            "    for (uint w{dimension} = 0u; w{dimension} < {}u; ++w{dimension}) {{\n",
            window[dimension]
        ));
        source.push_str(&format!(
            "        int i{dimension} = int(o{}) * {} - {} + int(w{dimension}) * {};\n",
            dimension + 2,
            strides[dimension],
            start_padding[dimension],
            dilations[dimension]
        ));
        source.push_str(&format!(
            "        if (i{dimension} < 0 || i{dimension} >= {}) continue;\n",
            input.sizes[dimension + 2]
        ));
    }
    let index = format!(
        "o0 * {}u + o1 * {}u + uint(i0) * {}u + uint(i1) * {}u",
        input.strides[0], input.strides[1], input.strides[2], input.strides[3]
    );
    source.push_str(&format!(
        "        acc += float(in0[{index}]);\n        valid += 1u;\n    }}\n    }}\n"
    ));
    let divisor = if include_padding {
        format!("{}u", window[0] as u64 * window[1] as u64)
    } else {
        "valid".to_string()
    };
    source.push_str(&format!(
        "    out[{}] = ({scalar})({divisor} == 0u ? 0.0f : acc / float({divisor}));\n}}\n",
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_lp_pooling_msl(
    plan: &DmlOpPlan,
    p: u32,
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    _end_padding: &[u32],
    dilations: &[u32],
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let dimensions = rank - 2;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str("    float acc = 0.0f;\n");
    let mut indent = String::from("    ");
    for dimension in 0..dimensions {
        let dilation = dilations.get(dimension).copied().unwrap_or(1);
        source.push_str(&format!(
            "{indent}for (uint w{dimension} = 0u; w{dimension} < {}u; ++w{dimension}) {{\n",
            window[dimension]
        ));
        source.push_str(&format!(
            "{indent}    int i{dimension} = int(o{}) * {} - {} + int(w{dimension}) * {dilation};\n",
            dimension + 2,
            strides[dimension],
            start_padding[dimension]
        ));
        source.push_str(&format!(
            "{indent}    if (i{dimension} < 0 || i{dimension} >= {}) continue;\n",
            input.sizes[dimension + 2]
        ));
        indent.push_str("    ");
    }
    let mut coords = coord_names(rank);
    for dimension in 0..dimensions {
        coords[dimension + 2] = format!("uint(i{dimension})");
    }
    source.push_str(&format!(
        "{indent}float v = float(in0[{}]);\n{indent}acc += pow(fabs(v), {}.0f);\n",
        linear_index(input, &coords),
        p
    ));
    for _ in 0..dimensions {
        indent.truncate(indent.len().saturating_sub(4));
        source.push_str(&format!("{indent}}}\n"));
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})pow(acc, 1.0f / {}.0f);\n}}\n",
        output_index_expr(&plan.output),
        p
    ));
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_max_pooling_ex_msl(
    plan: &DmlOpPlan,
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    _end_padding: &[u32],
    dilations: &[u32],
    has_indices: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut output_scalars = vec![scalar];
    if has_indices {
        output_scalars.push("uint");
    }
    let mut source = msl_header_outputs(plan, scalar, &output_scalars);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(
        "    float best = -INFINITY;\n    bool saw_nan = false;\n    uint best_index = 0u;\n",
    );
    for dimension in 0..2 {
        source.push_str(&format!(
            "    for (uint w{dimension} = 0u; w{dimension} < {}u; ++w{dimension}) {{\n",
            window[dimension]
        ));
        source.push_str(&format!(
            "        int i{dimension} = int(o{}) * {} - {} + int(w{dimension}) * {};\n",
            dimension + 2,
            strides[dimension],
            start_padding[dimension],
            dilations[dimension]
        ));
        source.push_str(&format!(
            "        if (i{dimension} < 0 || i{dimension} >= {}) continue;\n",
            input.sizes[dimension + 2]
        ));
    }
    let index = format!(
        "o0 * {}u + o1 * {}u + uint(i0) * {}u + uint(i1) * {}u",
        input.strides[0], input.strides[1], input.strides[2], input.strides[3]
    );
    source.push_str(&format!("        float v = float(in0[{index}]);\n"));
    source.push_str("        if (isnan(v)) saw_nan = true;\n");
    source.push_str(&format!(
        "        if (!isnan(v) && v > best) {{ best = v; best_index = (o0 * {}u + o1 * {}u + uint(i0) * {}u + uint(i1)) ; }}\n",
        input.sizes[1] as u64 * input.sizes[2] as u64 * input.sizes[3] as u64,
        input.sizes[2] as u64 * input.sizes[3] as u64,
        input.sizes[3]
    ));
    source.push_str("    }\n    }\n");
    let out_index = output_index_expr(&plan.output);
    source.push_str(&format!(
        "    out0[{out_index}] = ({scalar})(saw_nan ? NAN : best);\n"
    ));
    if has_indices {
        let index_output = plan.extra_outputs.first().expect("pooling index output");
        source.push_str(&format!(
            "    out1[{}] = best_index;\n",
            linear_index(index_output, &coord_names(plan.output.sizes.len()))
        ));
    }
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_max_unpooling_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let output = &plan.output;
    let mut source = msl_header(plan, scalar);
    let input_count = plan.inputs[0].element_count();
    source.push_str(&format!("    if (gid >= {input_count}u) return;\n"));
    source.push_str("    uint idx = in1[gid];\n");
    let mut coords = Vec::with_capacity(output.sizes.len());
    for dimension in 0..output.sizes.len() {
        let divisor: u64 = output.sizes[dimension + 1..]
            .iter()
            .map(|value| *value as u64)
            .product();
        source.push_str(&format!(
            "    uint u{dimension} = (idx / {divisor}u) % {}u;\n",
            output.sizes[dimension]
        ));
        coords.push(format!("u{dimension}"));
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})in0[gid];\n}}\n",
        linear_index(output, &coords)
    ));
    Ok(source)
}

pub(crate) fn emit_avg_pool_grad_msl(
    plan: &DmlOpPlan,
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    _end_padding: &[u32],
    include_padding: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let output = &plan.output;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, output);
    push_output_coords(&mut source, output);
    let [oh, ow] = [input.sizes[2], input.sizes[3]];
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!("    for (uint gh = 0u; gh < {oh}u; ++gh) {{\n"));
    source.push_str(&format!(
        "        int base_h = int(gh) * {} - {};\n",
        strides[0], start_padding[0]
    ));
    source.push_str(&format!(
        "        int rel_h = int(o2) - base_h;\n        bool h_ok = rel_h >= 0 && rel_h < {}u;\n        if (!h_ok) continue;\n",
        window[0]
    ));
    source.push_str(&format!(
        "        for (uint gw = 0u; gw < {ow}u; ++gw) {{\n"
    ));
    source.push_str(&format!(
        "            int base_w = int(gw) * {} - {};\n",
        strides[1], start_padding[1]
    ));
    source.push_str(&format!(
        "            int rel_w = int(o3) - base_w;\n            bool w_ok = rel_w >= 0 && rel_w < {}u;\n            if (!w_ok) continue;\n",
        window[1]
    ));
    source.push_str("            uint valid = 0u;\n");
    source.push_str(&format!(
        "            for (uint wy = 0u; wy < {}u; ++wy) {{\n                int iy = base_h + int(wy);\n                if (iy < 0 || iy >= {}) continue;\n",
        window[0], output.sizes[2]
    ));
    source.push_str(&format!(
        "                for (uint wx = 0u; wx < {}u; ++wx) {{\n                    int ix = base_w + int(wx);\n                    if (ix < 0 || ix >= {}) continue;\n                    valid += 1u;\n                }}\n            }}\n",
        window[1], output.sizes[3]
    ));
    let divisor = if include_padding {
        format!("{}u", window[0] as u64 * window[1] as u64)
    } else {
        "valid".to_string()
    };
    source.push_str(&format!(
        "            if ({divisor} == 0u) continue;\n            float g = float(in0[o0 * {}u + o1 * {}u + gh * {}u + gw * {}u]);\n            acc += g / float({divisor});\n        }}\n    }}\n",
        input.strides[0], input.strides[1], input.strides[2], input.strides[3]
    ));
    source.push_str(&format!(
        "    out[{}] = ({scalar})acc;\n}}\n",
        output_index_expr(output)
    ));
    Ok(source)
}

pub(crate) fn emit_max_pool_grad_msl(
    plan: &DmlOpPlan,
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    _end_padding: &[u32],
    dilations: &[u32],
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let gradient = &plan.inputs[1];
    let output = &plan.output;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, output);
    push_output_coords(&mut source, output);
    let [oh, ow] = [gradient.sizes[2], gradient.sizes[3]];
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!("    for (uint gh = 0u; gh < {oh}u; ++gh) {{\n"));
    source.push_str(&format!(
        "        for (uint gw = 0u; gw < {ow}u; ++gw) {{\n"
    ));
    source.push_str(
        "            float best = -INFINITY;\n            int bh = -1;\n            int bw = -1;\n",
    );
    source.push_str(&format!(
        "            for (uint wy = 0u; wy < {}u; ++wy) {{\n                int iy = int(gh) * {} - {} + int(wy) * {};\n                if (iy < 0 || iy >= {}) continue;\n",
        window[0], strides[0], start_padding[0], dilations[0], input.sizes[2]
    ));
    source.push_str(&format!(
        "                for (uint wx = 0u; wx < {}u; ++wx) {{\n                    int ix = int(gw) * {} - {} + int(wx) * {};\n                    if (ix < 0 || ix >= {}) continue;\n",
        window[1], strides[1], start_padding[1], dilations[1], input.sizes[3]
    ));
    source.push_str(&format!(
        "                    float v = float(in0[o0 * {}u + o1 * {}u + uint(iy) * {}u + uint(ix) * {}u]);\n                    if (!isnan(v) && v > best) {{ best = v; bh = iy; bw = ix; }}\n                }}\n            }}\n",
        input.strides[0], input.strides[1], input.strides[2], input.strides[3]
    ));
    source.push_str(&format!(
        "            if (bh == int(o2) && bw == int(o3)) {{ acc += float(in1[o0 * {}u + o1 * {}u + gh * {}u + gw * {}u]); }}\n",
        gradient.strides[0], gradient.strides[1], gradient.strides[2], gradient.strides[3]
    ));
    source.push_str("        }\n    }\n");
    source.push_str(&format!(
        "    out[{}] = ({scalar})acc;\n}}\n",
        output_index_expr(output)
    ));
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_roi_align_grad_msl(
    plan: &DmlOpPlan,
    reduction: DmlReduceKind,
    mode: DmlInterpolationMode,
    spatial_scale_x: f32,
    spatial_scale_y: f32,
    input_pixel_offset: f32,
    output_pixel_offset: f32,
    minimum_samples: u32,
    maximum_samples: u32,
    align_regions_to_corners: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let output = &plan.output;
    let (input_index, gradient_index) = if plan.inputs.len() == 4 {
        (Some(0usize), 1usize)
    } else {
        (None, 0usize)
    };
    let gradient = &plan.inputs[gradient_index];
    let roi_index = gradient_index + 1;
    let batch_index = gradient_index + 2;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, output);
    push_output_coords(&mut source, output);
    let [rois, _channels, out_h, out_w] = [
        gradient.sizes[0],
        gradient.sizes[1],
        gradient.sizes[2],
        gradient.sizes[3],
    ];
    let width = output.sizes[3];
    let height = output.sizes[2];
    let corner = if align_regions_to_corners {
        " - 0.5f"
    } else {
        ""
    };
    let grad_index = |_y: &str, _x: &str| {
        format!(
            "in{gradient}[r * {}u + o1 * {}u + sy * {}u + sx * {}u]",
            gradient.strides[0],
            gradient.strides[1],
            gradient.strides[2],
            gradient.strides[3],
            gradient = gradient_index
        )
    };
    let weight_code = |indent: &str, y: &str, x: &str| -> String {
        let mut code = String::new();
        match mode {
            DmlInterpolationMode::NearestNeighbor => {
                code.push_str(&format!(
                    "{indent}int xi = int({x} >= 0.0f ? floor({x} + 0.5f) : ceil({x} - 0.5f));\n{indent}int yi = int({y} >= 0.0f ? floor({y} + 0.5f) : ceil({y} - 0.5f));\n{indent}if (xi == int(o3) && yi == int(o2)) acc += float({});\n",
                    grad_index("uint(yi)", "uint(xi)")
                ));
            }
            DmlInterpolationMode::Linear => {
                code.push_str(&format!(
                    "{indent}int x0 = int(floor({x}));\n{indent}int y0 = int(floor({y}));\n{indent}float fx = {x} - floor({x});\n{indent}float fy = {y} - floor({y});\n{indent}float w = 0.0f;\n"
                ));
                for (yy, xx, w) in [
                    ("y0", "x0", "(1.0f - fx) * (1.0f - fy)"),
                    ("y0", "x0 + 1", "fx * (1.0f - fy)"),
                    ("y0 + 1", "x0", "(1.0f - fx) * fy"),
                    ("y0 + 1", "x0 + 1", "fx * fy"),
                ] {
                    code.push_str(&format!(
                        "{indent}if (uint({xx}) == o3 && uint({yy}) == o2) w += {w};\n"
                    ));
                }
                code.push_str(&format!(
                    "{indent}acc += w * float({});\n",
                    grad_index("uint(y0)", "uint(x0)")
                ));
            }
        }
        code
    };
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!("    for (uint r = 0u; r < {rois}u; ++r) {{\n"));
    source.push_str(&format!(
        "        if (uint(in{batch}[r * {batch_stride}u]) != o0) continue;\n",
        batch = batch_index,
        batch_stride = plan.inputs[batch_index].strides[0]
    ));
    source.push_str(&format!(
        "        float x1 = float(in{roi}[r * {roi_stride}u + 0u]) * {} + {}{corner};\n        float y1 = float(in{roi}[r * {roi_stride}u + 1u]) * {} + {}{corner};\n        float x2 = float(in{roi}[r * {roi_stride}u + 2u]) * {} + {}{corner};\n        float y2 = float(in{roi}[r * {roi_stride}u + 3u]) * {} + {}{corner};\n",
        msl_float(spatial_scale_x),
        msl_float(input_pixel_offset),
        msl_float(spatial_scale_y),
        msl_float(input_pixel_offset),
        msl_float(spatial_scale_x),
        msl_float(input_pixel_offset),
        msl_float(spatial_scale_y),
        msl_float(input_pixel_offset),
        roi = roi_index,
        roi_stride = plan.inputs[roi_index].strides[0]
    ));
    source.push_str(&format!(
        "        float bin_w = (x2 - x1) / {out_w}.0f;\n        float bin_h = (y2 - y1) / {out_h}.0f;\n"
    ));
    source.push_str(&format!(
        "        uint samples_x = uint(clamp(ceil(bin_w), {}, {}));\n        uint samples_y = uint(clamp(ceil(bin_h), {}, {}));\n",
        msl_float(minimum_samples as f32),
        msl_float(maximum_samples as f32),
        msl_float(minimum_samples as f32),
        msl_float(maximum_samples as f32)
    ));
    if reduction == DmlReduceKind::Max {
        let input_index = input_index.expect("max ROI gradient requires input");
        let sample_index = |y: &str, x: &str| {
            format!(
                "in{input}[o0 * {}u + o1 * {}u + uint({y}) * {}u + uint({x}) * {}u]",
                plan.inputs[input_index].strides[0],
                plan.inputs[input_index].strides[1],
                plan.inputs[input_index].strides[2],
                plan.inputs[input_index].strides[3],
                input = input_index
            )
        };
        source.push_str("        float best = -INFINITY;\n        uint best_sy = 0u;\n        uint best_sx = 0u;\n");
        source.push_str("        for (uint sy = 0u; sy < samples_y; ++sy) {\n");
        source.push_str(&format!(
            "            float y = y1 + (float(sy) + 0.5f) * bin_h / float(samples_y) + {};\n",
            msl_float(output_pixel_offset)
        ));
        source.push_str("            for (uint sx = 0u; sx < samples_x; ++sx) {\n");
        source.push_str(&format!(
            "                float x = x1 + (float(sx) + 0.5f) * bin_w / float(samples_x) + {};\n",
            msl_float(output_pixel_offset)
        ));
        match mode {
            DmlInterpolationMode::NearestNeighbor => {
                source.push_str("                int xi = int(x >= 0.0f ? floor(x + 0.5f) : ceil(x - 0.5f));\n                int yi = int(y >= 0.0f ? floor(y + 0.5f) : ceil(y - 0.5f));\n                bool inside = xi >= 0 && yi >= 0 && xi < ");
                source.push_str(&format!("{width} && yi < {height};\n"));
                source.push_str(&format!(
                    "                float sample = inside ? float({}) : 0.0f;\n",
                    sample_index("yi", "xi")
                ));
            }
            DmlInterpolationMode::Linear => {
                source.push_str("                int x0 = int(floor(x));\n                int y0 = int(floor(y));\n                float fx = x - floor(x);\n                float fy = y - floor(y);\n                bool inside = x0 >= 0 && y0 >= 0 && x0 + 1 < ");
                source.push_str(&format!("{width} && y0 + 1 < {height};\n"));
                source.push_str(&format!(
                    "                float sample = inside ? (1.0f - fx) * (1.0f - fy) * float({}) + fx * (1.0f - fy) * float({}) + (1.0f - fx) * fy * float({}) + fx * fy * float({}) : 0.0f;\n",
                    sample_index("y0", "x0"),
                    sample_index("y0", "x0 + 1"),
                    sample_index("y0 + 1", "x0"),
                    sample_index("y0 + 1", "x0 + 1")
                ));
            }
        }
        source.push_str("                if (!isnan(sample) && sample > best) { best = sample; best_sy = sy; best_sx = sx; }\n");
        source.push_str("            }\n        }\n");
        source.push_str("        uint sy = best_sy;\n        uint sx = best_sx;\n");
        source.push_str(&format!(
            "        float y = y1 + (float(sy) + 0.5f) * bin_h / float(samples_y) + {};\n        float x = x1 + (float(sx) + 0.5f) * bin_w / float(samples_x) + {};\n",
            msl_float(output_pixel_offset),
            msl_float(output_pixel_offset)
        ));
        source.push_str(&weight_code("        ", "y", "x"));
    } else {
        source.push_str("        for (uint sy = 0u; sy < samples_y; ++sy) {\n");
        source.push_str(&format!(
            "            float y = y1 + (float(sy) + 0.5f) * bin_h / float(samples_y) + {};\n",
            msl_float(output_pixel_offset)
        ));
        source.push_str("            for (uint sx = 0u; sx < samples_x; ++sx) {\n");
        source.push_str(&format!(
            "                float x = x1 + (float(sx) + 0.5f) * bin_w / float(samples_x) + {};\n",
            msl_float(output_pixel_offset)
        ));
        source.push_str(&weight_code("                ", "y", "x"));
        source.push_str("            }\n        }\n");
        source.push_str("        acc /= float(samples_x * samples_y);\n");
    }
    source.push_str("    }\n");
    source.push_str(&format!(
        "    out[{}] = ({scalar})acc;\n}}\n",
        output_index_expr(output)
    ));
    Ok(source)
}

pub(crate) fn emit_pooling_msl(
    plan: &DmlOpPlan,
    kind: DmlPoolingKind,
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    include_padding: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let [ih, iw] = [input.sizes[2], input.sizes[3]];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str("    float acc = 0.0f;\n");
    source.push_str("    bool saw_nan = false;\n");
    source.push_str("    uint valid = 0u;\n");
    if kind == DmlPoolingKind::Max {
        source.push_str("    float best = -INFINITY;\n");
    }
    source.push_str(&format!(
        "    for (uint wy = 0u; wy < {}u; ++wy) {{\n",
        window[0]
    ));
    source.push_str(&format!(
        "        int iy = int(o2) * {} - {} + int(wy);\n",
        strides[0], start_padding[0]
    ));
    source.push_str(&format!("        if (iy < 0 || iy >= {ih}) continue;\n"));
    source.push_str(&format!(
        "        for (uint wx = 0u; wx < {}u; ++wx) {{\n",
        window[1]
    ));
    source.push_str(&format!(
        "            int ix = int(o3) * {} - {} + int(wx);\n",
        strides[1], start_padding[1]
    ));
    source.push_str(&format!(
        "            if (ix < 0 || ix >= {iw}) continue;\n"
    ));
    let index = format!(
        "o0 * {}u + o1 * {}u + uint(iy) * {}u + uint(ix) * {}u",
        input.strides[0], input.strides[1], input.strides[2], input.strides[3]
    );
    source.push_str(&format!("            float v = float(in0[{index}]);\n"));
    source.push_str("            bool v_nan = ((as_type<uint>(v) & 0x7fffffffu) > 0x7f800000u);\n");
    source.push_str("            if (v_nan) saw_nan = true;\n");
    if kind == DmlPoolingKind::Max {
        source.push_str("            if (!v_nan) best = fmax(best, v);\n");
    } else {
        source.push_str("            acc += v;\n");
    }
    source.push_str("            valid += 1u;\n");
    source.push_str("        }\n");
    source.push_str("    }\n");
    let value = if kind == DmlPoolingKind::Max {
        "saw_nan ? NAN : best".to_string()
    } else if include_padding {
        let divisor = window[0] as u64 * window[1] as u64;
        format!("valid == 0u ? 0.0f : acc / {divisor}.0f")
    } else {
        "valid == 0u ? 0.0f : acc / float(valid)".to_string()
    };
    source.push_str(&format!(
        "    out[{}] = ({scalar})({value});\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_roi_pooling_msl(
    plan: &DmlOpPlan,
    spatial_scale: f32,
    pooled: &[u32],
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let [_, _, height, width] = [
        input.sizes[0],
        input.sizes[1],
        input.sizes[2],
        input.sizes[3],
    ];
    source.push_str("    uint roi = o0 * 5u;\n    uint batch = uint(in1[roi]);\n");
    source.push_str(&format!(
        "    float x1 = rint(in1[roi + 1u] * {});\n",
        msl_float(spatial_scale)
    ));
    source.push_str(&format!(
        "    float y1 = rint(in1[roi + 2u] * {});\n",
        msl_float(spatial_scale)
    ));
    source.push_str(&format!(
        "    float x2 = rint(in1[roi + 3u] * {});\n",
        msl_float(spatial_scale)
    ));
    source.push_str(&format!(
        "    float y2 = rint(in1[roi + 4u] * {});\n",
        msl_float(spatial_scale)
    ));
    source.push_str(&format!(
        "    float bin_w = (x2 - x1 + 1.0f) / {};\n",
        msl_float(pooled[1] as f32)
    ));
    source.push_str(&format!(
        "    float bin_h = (y2 - y1 + 1.0f) / {};\n",
        msl_float(pooled[0] as f32)
    ));
    source.push_str(&format!(
        "    int start_x = clamp(int(floor(x1 + float(o3) * bin_w)), 0, {});\n",
        width.saturating_sub(1)
    ));
    source.push_str(&format!(
        "    int end_x = clamp(int(ceil(x1 + float(o3 + 1u) * bin_w)), 0, {});\n",
        width
    ));
    source.push_str(&format!(
        "    int start_y = clamp(int(floor(y1 + float(o2) * bin_h)), 0, {});\n",
        height.saturating_sub(1)
    ));
    source.push_str(&format!(
        "    int end_y = clamp(int(ceil(y1 + float(o2 + 1u) * bin_h)), 0, {});\n",
        height
    ));
    source.push_str("    float best = -INFINITY;\n    bool saw_nan = false;\n");
    source.push_str("    for (int y = start_y; y < end_y; ++y) {\n");
    source.push_str("        for (int x = start_x; x < end_x; ++x) {\n");
    source.push_str(&format!(
        "            float v = float(in0[batch * {}u + o1 * {}u + uint(y) * {}u + uint(x) * {}u]);\n",
        input.strides[0], input.strides[1], input.strides[2], input.strides[3]
    ));
    source.push_str("            if (isnan(v)) saw_nan = true; else best = fmax(best, v);\n");
    source.push_str("        }\n    }\n");
    source.push_str(&format!(
        "    out[{}] = ({scalar})(saw_nan ? NAN : (best == -INFINITY ? 0.0f : best));\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_roi_align_msl(
    plan: &DmlOpPlan,
    reduction: DmlReduceKind,
    mode: DmlInterpolationMode,
    spatial_scale_x: f32,
    spatial_scale_y: f32,
    input_pixel_offset: f32,
    output_pixel_offset: f32,
    out_of_bounds_value: f32,
    minimum_samples: u32,
    maximum_samples: u32,
    align_regions_to_corners: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let [_, _, height, width] = [
        input.sizes[0],
        input.sizes[1],
        input.sizes[2],
        input.sizes[3],
    ];
    source.push_str("    uint roi = o0 * 4u;\n");
    source.push_str("    uint batch = in2[o0];\n");
    source.push_str(&format!(
        "    float x1 = in1[roi] * {} + {}{};\n",
        msl_float(spatial_scale_x),
        msl_float(input_pixel_offset),
        if align_regions_to_corners {
            " - 0.5f"
        } else {
            ""
        }
    ));
    source.push_str(&format!(
        "    float y1 = in1[roi + 1u] * {} + {}{};\n",
        msl_float(spatial_scale_y),
        msl_float(input_pixel_offset),
        if align_regions_to_corners {
            " - 0.5f"
        } else {
            ""
        }
    ));
    source.push_str(&format!(
        "    float x2 = in1[roi + 2u] * {} + {}{};\n",
        msl_float(spatial_scale_x),
        msl_float(input_pixel_offset),
        if align_regions_to_corners {
            " - 0.5f"
        } else {
            ""
        }
    ));
    source.push_str(&format!(
        "    float y2 = in1[roi + 3u] * {} + {}{};\n",
        msl_float(spatial_scale_y),
        msl_float(input_pixel_offset),
        if align_regions_to_corners {
            " - 0.5f"
        } else {
            ""
        }
    ));
    source.push_str(&format!(
        "    float bin_w = (x2 - x1) / {};\n    float bin_h = (y2 - y1) / {};\n",
        msl_float(plan.output.sizes[3] as f32),
        msl_float(plan.output.sizes[2] as f32)
    ));
    source.push_str(&format!(
        "    uint samples_x = uint(clamp(ceil(bin_w), {}.0f, {}.0f));\n",
        msl_float(minimum_samples as f32),
        msl_float(maximum_samples as f32)
    ));
    source.push_str(&format!(
        "    uint samples_y = uint(clamp(ceil(bin_h), {}.0f, {}.0f));\n",
        msl_float(minimum_samples as f32),
        msl_float(maximum_samples as f32)
    ));
    source.push_str("    float acc = 0.0f;\n    float best = -INFINITY;\n    bool saw_nan = false;\n    uint count = 0u;\n");
    source.push_str("    for (uint sy = 0u; sy < samples_y; ++sy) {\n");
    source.push_str("        float y = y1 + (float(sy) + 0.5f) * bin_h / float(samples_y) + ");
    source.push_str(&msl_float(output_pixel_offset));
    source.push_str(";\n");
    source.push_str("        for (uint sx = 0u; sx < samples_x; ++sx) {\n");
    source.push_str("            float x = x1 + (float(sx) + 0.5f) * bin_w / float(samples_x) + ");
    source.push_str(&msl_float(output_pixel_offset));
    source.push_str(";\n");
    source.push_str("            float sample = 0.0f;\n");
    if mode == DmlInterpolationMode::Linear {
        source
            .push_str("            int x0 = int(floor(x));\n            int y0 = int(floor(y));\n");
        source.push_str(
            "            float fx = x - floor(x);\n            float fy = y - floor(y);\n",
        );
        source.push_str("            bool inside = x0 >= 0 && y0 >= 0 && x0 + 1 < ");
        source.push_str(&format!("{width} && y0 + 1 < {height};\n"));
        source.push_str(&format!(
            "            if (inside) {{ sample = (1.0f - fx) * (1.0f - fy) * float(in0[batch * {}u + o1 * {}u + uint(y0) * {}u + uint(x0) * {}u]) + fx * (1.0f - fy) * float(in0[batch * {}u + o1 * {}u + uint(y0) * {}u + uint(x0 + 1) * {}u]) + (1.0f - fx) * fy * float(in0[batch * {}u + o1 * {}u + uint(y0 + 1) * {}u + uint(x0) * {}u]) + fx * fy * float(in0[batch * {}u + o1 * {}u + uint(y0 + 1) * {}u + uint(x0 + 1) * {}u]); }} else {{ sample = {}; }}\n",
            input.strides[0], input.strides[1], input.strides[2], input.strides[3],
            input.strides[0], input.strides[1], input.strides[2], input.strides[3],
            input.strides[0], input.strides[1], input.strides[2], input.strides[3],
            input.strides[0], input.strides[1], input.strides[2], input.strides[3],
            msl_float(out_of_bounds_value)
        ));
    } else {
        source.push_str("            int xi = int(rint(x));\n            int yi = int(rint(y));\n");
        source.push_str(&format!(
            "            bool inside = xi >= 0 && yi >= 0 && xi < {width} && yi < {height};\n"
        ));
        source.push_str(&format!(
            "            sample = inside ? float(in0[batch * {}u + o1 * {}u + uint(yi) * {}u + uint(xi) * {}u]) : {};\n",
            input.strides[0], input.strides[1], input.strides[2], input.strides[3],
            msl_float(out_of_bounds_value)
        ));
    }
    source.push_str("            if (isnan(sample)) saw_nan = true;\n");
    if reduction == DmlReduceKind::Max {
        source.push_str("            best = fmax(best, sample);\n");
    } else {
        source.push_str("            acc += sample;\n");
    }
    source.push_str("            count += 1u;\n");
    source.push_str("        }\n    }\n");
    let value = if reduction == DmlReduceKind::Max {
        "saw_nan ? NAN : (count == 0u ? 0.0f : best)".to_string()
    } else {
        "saw_nan ? NAN : (count == 0u ? 0.0f : acc / float(count))".to_string()
    };
    source.push_str(&format!(
        "    out[{}] = ({scalar})({value});\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_average_pooling1_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    _end_padding: &[u32],
    dilations: &[u32],
    include_padding: bool,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let dtype = plan.output.data_type;
    for gid in 0..plan.output.element_count() {
        let base = coords_of(gid, &plan.output.sizes);
        let mut acc = 0.0f64;
        let mut valid = 0u64;
        let total: u64 = window.iter().map(|size| *size as u64).product();
        for combination in 0..total {
            let mut rem = combination;
            let mut coords = base.clone();
            let mut in_bounds = true;
            for dimension in 0..2 {
                let offset = rem % window[dimension] as u64;
                rem /= window[dimension] as u64;
                let position = base[dimension + 2] as i64 * strides[dimension] as i64
                    - start_padding[dimension] as i64
                    + offset as i64 * dilations[dimension] as i64;
                if position < 0 || position >= input.sizes[dimension + 2] as i64 {
                    in_bounds = false;
                    break;
                }
                coords[dimension + 2] = position as u64;
            }
            if !in_bounds {
                continue;
            }
            acc += load_scalar(input_bytes, index_of(&coords, &input.strides), dtype) as f64;
            valid += 1;
        }
        let divisor = if include_padding {
            window[0] as u64 * window[1] as u64
        } else {
            valid
        };
        let value = if divisor == 0 {
            0.0
        } else {
            (acc / divisor as f64) as f32
        };
        store_scalar(output, output_index(&plan.output, gid), dtype, value);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_lp_pooling_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    p: u32,
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    _end_padding: &[u32],
    dilations: &[u32],
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let dtype = plan.output.data_type;
    let rank = input.sizes.len();
    let dimensions = rank - 2;
    for gid in 0..plan.output.element_count() {
        let base = coords_of(gid, &plan.output.sizes);
        let mut acc = 0.0f64;
        let total: u64 = window.iter().map(|size| *size as u64).product();
        for combination in 0..total {
            let mut rem = combination;
            let mut coords = base.clone();
            let mut valid = true;
            for dimension in 0..dimensions {
                let offset = rem % window[dimension] as u64;
                rem /= window[dimension] as u64;
                let dilation = dilations.get(dimension).copied().unwrap_or(1) as i64;
                let position = base[dimension + 2] as i64 * strides[dimension] as i64
                    - start_padding[dimension] as i64
                    + offset as i64 * dilation;
                if position < 0 || position >= input.sizes[dimension + 2] as i64 {
                    valid = false;
                    break;
                }
                coords[dimension + 2] = position as u64;
            }
            if !valid {
                continue;
            }
            let value = load_scalar(input_bytes, index_of(&coords, &input.strides), dtype);
            acc += (value as f64).abs().powi(p as i32);
        }
        let value = acc.powf(1.0 / p as f64) as f32;
        store_scalar(output, output_index(&plan.output, gid), dtype, value);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_max_pooling_ex_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    mut indices: Option<&mut [u8]>,
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    _end_padding: &[u32],
    dilations: &[u32],
    has_indices: bool,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let dtype = plan.output.data_type;
    for gid in 0..plan.output.element_count() {
        let base = coords_of(gid, &plan.output.sizes);
        let mut best = f32::NEG_INFINITY;
        let mut saw_nan = false;
        let mut best_index = 0u64;
        let total: u64 = window.iter().map(|size| *size as u64).product();
        for combination in 0..total {
            let mut rem = combination;
            let mut coords = base.clone();
            let mut valid = true;
            for dimension in 0..2 {
                let offset = rem % window[dimension] as u64;
                rem /= window[dimension] as u64;
                let position = base[dimension + 2] as i64 * strides[dimension] as i64
                    - start_padding[dimension] as i64
                    + offset as i64 * dilations[dimension] as i64;
                if position < 0 || position >= input.sizes[dimension + 2] as i64 {
                    valid = false;
                    break;
                }
                coords[dimension + 2] = position as u64;
            }
            if !valid {
                continue;
            }
            let value = load_scalar(input_bytes, index_of(&coords, &input.strides), dtype);
            if value.is_nan() {
                saw_nan = true;
                continue;
            }
            if value > best {
                best = value;
                best_index = row_major_index(&coords, &input.sizes);
            }
        }
        let value = if saw_nan { f32::NAN } else { best };
        let output_index = output_index(&plan.output, gid);
        store_scalar(output, output_index, dtype, value);
        if has_indices {
            let buffer = indices
                .as_deref_mut()
                .ok_or_else(|| DmlError::invalid("max pooling indices output is missing"))?;
            let index_desc = &plan.extra_outputs[0];
            store_integer(
                buffer,
                output_index_of(index_desc, gid),
                DML_TENSOR_DATA_TYPE_UINT32,
                best_index as i64,
            );
        }
    }
    Ok(())
}

pub(crate) fn execute_max_unpooling_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
) -> DmlResult<()> {
    validate_max_unpooling_indices(plan, inputs)?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let dtype = plan.output.data_type;
    output.fill(0);
    let output_count = plan.output.element_count();
    for gid in 0..input.element_count() {
        let coords = coords_of(gid, &input.sizes);
        let index = load_integer(
            inputs[1],
            index_of(&coords, &indices.strides),
            indices.data_type,
        );
        if index < 0 || index as u64 >= output_count {
            return Err(DmlError::invalid(format!(
                "max unpooling index {index} is outside the output element count {output_count}"
            )));
        }
        let target_coords = coords_of(index as u64, &plan.output.sizes);
        let value = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
        store_scalar(
            output,
            index_of(&target_coords, &plan.output.strides),
            dtype,
            value,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_avg_pool_grad_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    _end_padding: &[u32],
    include_padding: bool,
) -> DmlResult<()> {
    let gradient = &plan.inputs[0];
    let dtype = plan.output.data_type;
    let [oh, ow] = [gradient.sizes[2], gradient.sizes[3]];
    for gid in 0..plan.output.element_count() {
        let coords = coords_of(gid, &plan.output.sizes);
        let [batch, channel, y, x] = [coords[0], coords[1], coords[2], coords[3]];
        let mut acc = 0.0f64;
        for gh in 0..oh as u64 {
            let base_h = gh as i64 * strides[0] as i64 - start_padding[0] as i64;
            let rel_h = y as i64 - base_h;
            if rel_h < 0 || rel_h >= window[0] as i64 {
                continue;
            }
            for gw in 0..ow as u64 {
                let base_w = gw as i64 * strides[1] as i64 - start_padding[1] as i64;
                let rel_w = x as i64 - base_w;
                if rel_w < 0 || rel_w >= window[1] as i64 {
                    continue;
                }
                let mut valid = 0u64;
                for wy in 0..window[0] {
                    let iy = base_h + wy as i64;
                    if iy < 0 || iy >= plan.output.sizes[2] as i64 {
                        continue;
                    }
                    for wx in 0..window[1] {
                        let ix = base_w + wx as i64;
                        if ix < 0 || ix >= plan.output.sizes[3] as i64 {
                            continue;
                        }
                        valid += 1;
                    }
                }
                let divisor = if include_padding {
                    window[0] as u64 * window[1] as u64
                } else {
                    valid
                };
                if divisor == 0 {
                    continue;
                }
                let gradient_coords = [batch, channel, gh, gw];
                let value = load_scalar(
                    input_bytes,
                    index_of(&gradient_coords, &gradient.strides),
                    dtype,
                );
                acc += value as f64 / divisor as f64;
            }
        }
        store_scalar(output, output_index(&plan.output, gid), dtype, acc as f32);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_max_pool_grad_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    strides: &[u32],
    window: &[u32],
    start_padding: &[u32],
    _end_padding: &[u32],
    dilations: &[u32],
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let gradient = &plan.inputs[1];
    let dtype = plan.output.data_type;
    let [oh, ow] = [gradient.sizes[2], gradient.sizes[3]];
    for gid in 0..plan.output.element_count() {
        let coords = coords_of(gid, &plan.output.sizes);
        let [batch, channel, y, x] = [coords[0], coords[1], coords[2], coords[3]];
        let mut acc = 0.0f64;
        for gh in 0..oh as u64 {
            for gw in 0..ow as u64 {
                let mut best = f32::NEG_INFINITY;
                let mut best_position = (i64::MIN, i64::MIN);
                for wy in 0..window[0] as u64 {
                    let iy = gh as i64 * strides[0] as i64 - start_padding[0] as i64
                        + wy as i64 * dilations[0] as i64;
                    if iy < 0 || iy >= input.sizes[2] as i64 {
                        continue;
                    }
                    for wx in 0..window[1] as u64 {
                        let ix = gw as i64 * strides[1] as i64 - start_padding[1] as i64
                            + wx as i64 * dilations[1] as i64;
                        if ix < 0 || ix >= input.sizes[3] as i64 {
                            continue;
                        }
                        let value = load_scalar(
                            inputs[0],
                            index_of(&[batch, channel, iy as u64, ix as u64], &input.strides),
                            dtype,
                        );
                        if !value.is_nan() && value > best {
                            best = value;
                            best_position = (iy, ix);
                        }
                    }
                }
                if best_position == (y as i64, x as i64) {
                    acc += load_scalar(
                        inputs[1],
                        index_of(&[batch, channel, gh, gw], &gradient.strides),
                        dtype,
                    ) as f64;
                }
            }
        }
        store_scalar(output, output_index(&plan.output, gid), dtype, acc as f32);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_roi_align_grad_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    reduction: DmlReduceKind,
    mode: DmlInterpolationMode,
    spatial_scale_x: f32,
    spatial_scale_y: f32,
    input_pixel_offset: f32,
    output_pixel_offset: f32,
    minimum_samples: u32,
    maximum_samples: u32,
    align_regions_to_corners: bool,
) -> DmlResult<()> {
    let (input_index, gradient_index) = if plan.inputs.len() == 4 {
        (Some(0usize), 1usize)
    } else {
        (None, 0usize)
    };
    let gradient = &plan.inputs[gradient_index];
    let roi = &plan.inputs[gradient_index + 1];
    let batch_indices = &plan.inputs[gradient_index + 2];
    let dtype = plan.output.data_type;
    let [rois, _, out_h, out_w] = [
        gradient.sizes[0],
        gradient.sizes[1],
        gradient.sizes[2],
        gradient.sizes[3],
    ];
    let [_, _, height, width] = [
        plan.output.sizes[0],
        plan.output.sizes[1],
        plan.output.sizes[2],
        plan.output.sizes[3],
    ];
    let corner_offset = if align_regions_to_corners { -0.5 } else { 0.0 };
    for gid in 0..plan.output.element_count() {
        let own = coords_of(gid, &plan.output.sizes);
        let mut acc = 0.0f64;
        for r in 0..rois as u64 {
            let batch = load_integer(
                inputs[gradient_index + 2],
                index_of(&[r], &batch_indices.strides),
                batch_indices.data_type,
            ) as u64;
            if batch != own[0] {
                continue;
            }
            let x1 = load_scalar(
                inputs[gradient_index + 1],
                index_of(&[r, 0], &roi.strides),
                dtype,
            ) * spatial_scale_x
                + input_pixel_offset
                + corner_offset;
            let y1 = load_scalar(
                inputs[gradient_index + 1],
                index_of(&[r, 1], &roi.strides),
                dtype,
            ) * spatial_scale_y
                + input_pixel_offset
                + corner_offset;
            let x2 = load_scalar(
                inputs[gradient_index + 1],
                index_of(&[r, 2], &roi.strides),
                dtype,
            ) * spatial_scale_x
                + input_pixel_offset
                + corner_offset;
            let y2 = load_scalar(
                inputs[gradient_index + 1],
                index_of(&[r, 3], &roi.strides),
                dtype,
            ) * spatial_scale_y
                + input_pixel_offset
                + corner_offset;
            let bin_w = (x2 - x1) / out_w as f32;
            let bin_h = (y2 - y1) / out_h as f32;
            let samples_x = (bin_w.ceil() as u32)
                .clamp(minimum_samples, maximum_samples)
                .max(1);
            let samples_y = (bin_h.ceil() as u32)
                .clamp(minimum_samples, maximum_samples)
                .max(1);
            if reduction == DmlReduceKind::Max {
                let input_index = input_index.expect("max ROI gradient requires input");
                let mut best = f32::NEG_INFINITY;
                let mut best_sample = (0u32, 0u32);
                for sy in 0..samples_y {
                    let y = y1 + (sy as f32 + 0.5) * bin_h / samples_y as f32 + output_pixel_offset;
                    for sx in 0..samples_x {
                        let x =
                            x1 + (sx as f32 + 0.5) * bin_w / samples_x as f32 + output_pixel_offset;
                        let value = roi_sample(
                            inputs[input_index],
                            &plan.inputs[input_index],
                            own[0],
                            own[1],
                            x,
                            y,
                            width,
                            height,
                            mode,
                            0.0,
                        );
                        if !value.is_nan() && value > best {
                            best = value;
                            best_sample = (sy, sx);
                        }
                    }
                }
                let (sy, sx) = best_sample;
                let y = y1 + (sy as f32 + 0.5) * bin_h / samples_y as f32 + output_pixel_offset;
                let x = x1 + (sx as f32 + 0.5) * bin_w / samples_x as f32 + output_pixel_offset;
                let gradient_value = load_scalar(
                    inputs[gradient_index],
                    index_of(&[r, own[1], sy as u64, sx as u64], &gradient.strides),
                    dtype,
                );
                acc += roi_grad_weight(own[2] as i64, own[3] as i64, x, y, mode, gradient_value);
            } else {
                for sy in 0..samples_y {
                    let y = y1 + (sy as f32 + 0.5) * bin_h / samples_y as f32 + output_pixel_offset;
                    for sx in 0..samples_x {
                        let x =
                            x1 + (sx as f32 + 0.5) * bin_w / samples_x as f32 + output_pixel_offset;
                        let gradient_value = load_scalar(
                            inputs[gradient_index],
                            index_of(&[r, own[1], sy as u64, sx as u64], &gradient.strides),
                            dtype,
                        );
                        acc += roi_grad_weight(
                            own[2] as i64,
                            own[3] as i64,
                            x,
                            y,
                            mode,
                            gradient_value,
                        );
                    }
                }
                acc /= (samples_x * samples_y) as f64;
            }
        }
        store_scalar(output, output_index(&plan.output, gid), dtype, acc as f32);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn roi_sample(
    bytes: &[u8],
    desc: &DmlTensorDesc,
    batch: u64,
    channel: u64,
    x: f32,
    y: f32,
    width: u32,
    height: u32,
    mode: DmlInterpolationMode,
    out_of_bounds: f32,
) -> f32 {
    match mode {
        DmlInterpolationMode::NearestNeighbor => {
            let xi = x.round() as i64;
            let yi = y.round() as i64;
            if xi >= 0 && yi >= 0 && xi < width as i64 && yi < height as i64 {
                load_scalar(
                    bytes,
                    index_of(&[batch, channel, yi as u64, xi as u64], &desc.strides),
                    desc.data_type,
                )
            } else {
                out_of_bounds
            }
        }
        DmlInterpolationMode::Linear => {
            let x0 = x.floor() as i64;
            let y0 = y.floor() as i64;
            let fx = x - x.floor();
            let fy = y - y.floor();
            if x0 >= 0 && y0 >= 0 && x0 + 1 < width as i64 && y0 + 1 < height as i64 {
                let p00 = load_scalar(
                    bytes,
                    index_of(&[batch, channel, y0 as u64, x0 as u64], &desc.strides),
                    desc.data_type,
                );
                let p10 = load_scalar(
                    bytes,
                    index_of(&[batch, channel, y0 as u64, (x0 + 1) as u64], &desc.strides),
                    desc.data_type,
                );
                let p01 = load_scalar(
                    bytes,
                    index_of(&[batch, channel, (y0 + 1) as u64, x0 as u64], &desc.strides),
                    desc.data_type,
                );
                let p11 = load_scalar(
                    bytes,
                    index_of(
                        &[batch, channel, (y0 + 1) as u64, (x0 + 1) as u64],
                        &desc.strides,
                    ),
                    desc.data_type,
                );
                (1.0 - fx) * (1.0 - fy) * p00
                    + fx * (1.0 - fy) * p10
                    + (1.0 - fx) * fy * p01
                    + fx * fy * p11
            } else {
                out_of_bounds
            }
        }
    }
}

pub(crate) fn roi_grad_weight(
    own_y: i64,
    own_x: i64,
    x: f32,
    y: f32,
    mode: DmlInterpolationMode,
    gradient: f32,
) -> f64 {
    match mode {
        DmlInterpolationMode::NearestNeighbor => {
            if x.round() as i64 == own_x && y.round() as i64 == own_y {
                gradient as f64
            } else {
                0.0
            }
        }
        DmlInterpolationMode::Linear => {
            let x0 = x.floor() as i64;
            let y0 = y.floor() as i64;
            let fx = x - x.floor();
            let fy = y - y.floor();
            let mut weight = 0.0f64;
            if x0 == own_x && y0 == own_y {
                weight += ((1.0 - fx) * (1.0 - fy)) as f64;
            }
            if x0 + 1 == own_x && y0 == own_y {
                weight += (fx * (1.0 - fy)) as f64;
            }
            if x0 == own_x && y0 + 1 == own_y {
                weight += ((1.0 - fx) * fy) as f64;
            }
            if x0 + 1 == own_x && y0 + 1 == own_y {
                weight += (fx * fy) as f64;
            }
            weight * gradient as f64
        }
    }
}

pub(crate) fn execute_roi_pooling_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    spatial_scale: f32,
    pooled: &[u32],
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let roi = &plan.inputs[1];
    let count = plan.output.element_count();
    let [_, _, height, width] = [
        input.sizes[0],
        input.sizes[1],
        input.sizes[2],
        input.sizes[3],
    ];
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let [roi_index, channel, ph, pw] = [
            output_coords[0],
            output_coords[1],
            output_coords[2],
            output_coords[3],
        ];
        let roi_offset = roi_index * 5;
        let batch = load_scalar(inputs[1], roi_offset, roi.data_type) as u64;
        let x1 = (load_scalar(inputs[1], roi_offset + 1, roi.data_type) * spatial_scale).round();
        let y1 = (load_scalar(inputs[1], roi_offset + 2, roi.data_type) * spatial_scale).round();
        let x2 = (load_scalar(inputs[1], roi_offset + 3, roi.data_type) * spatial_scale).round();
        let y2 = (load_scalar(inputs[1], roi_offset + 4, roi.data_type) * spatial_scale).round();
        let bin_w = (x2 - x1 + 1.0) / pooled[1] as f32;
        let bin_h = (y2 - y1 + 1.0) / pooled[0] as f32;
        let start_x = (x1 + pw as f32 * bin_w).floor() as i64;
        let end_x = (x1 + (pw as f32 + 1.0) * bin_w).ceil() as i64;
        let start_y = (y1 + ph as f32 * bin_h).floor() as i64;
        let end_y = (y1 + (ph as f32 + 1.0) * bin_h).ceil() as i64;
        let mut best = f32::NEG_INFINITY;
        let mut saw_nan = false;
        for y in start_y.max(0)..end_y.min(height as i64) {
            for x in start_x.max(0)..end_x.min(width as i64) {
                let value = load_scalar(
                    inputs[0],
                    index_of(&[batch, channel, y as u64, x as u64], &input.strides),
                    input.data_type,
                );
                if value.is_nan() {
                    saw_nan = true;
                } else {
                    best = best.max(value);
                }
            }
        }
        let value = if saw_nan {
            f32::NAN
        } else if best == f32::NEG_INFINITY {
            0.0
        } else {
            best
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_roi_align_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    reduction: DmlReduceKind,
    mode: DmlInterpolationMode,
    spatial_scale_x: f32,
    spatial_scale_y: f32,
    input_pixel_offset: f32,
    output_pixel_offset: f32,
    out_of_bounds_value: f32,
    minimum_samples: u32,
    maximum_samples: u32,
    align_regions_to_corners: bool,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let roi = &plan.inputs[1];
    let batch_indices = &plan.inputs[2];
    let count = plan.output.element_count();
    let [_, _, height, width] = [
        input.sizes[0],
        input.sizes[1],
        input.sizes[2],
        input.sizes[3],
    ];
    let corner_offset = if align_regions_to_corners { -0.5 } else { 0.0 };
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let [roi_index, channel, ..] = [
            output_coords[0],
            output_coords[1],
            output_coords[2],
            output_coords[3],
        ];
        let batch = load_integer(
            inputs[2],
            index_of(&[roi_index], &batch_indices.strides),
            batch_indices.data_type,
        ) as u64;
        let roi_offset = roi_index * 4;
        let x1 = load_scalar(inputs[1], roi_offset, roi.data_type) * spatial_scale_x
            + input_pixel_offset
            + corner_offset;
        let y1 = load_scalar(inputs[1], roi_offset + 1, roi.data_type) * spatial_scale_y
            + input_pixel_offset
            + corner_offset;
        let x2 = load_scalar(inputs[1], roi_offset + 2, roi.data_type) * spatial_scale_x
            + input_pixel_offset
            + corner_offset;
        let y2 = load_scalar(inputs[1], roi_offset + 3, roi.data_type) * spatial_scale_y
            + input_pixel_offset
            + corner_offset;
        let bin_w = (x2 - x1) / plan.output.sizes[3] as f32;
        let bin_h = (y2 - y1) / plan.output.sizes[2] as f32;
        let samples_x = (bin_w.ceil() as u32)
            .clamp(minimum_samples, maximum_samples)
            .max(1);
        let samples_y = (bin_h.ceil() as u32)
            .clamp(minimum_samples, maximum_samples)
            .max(1);
        let mut acc = 0.0f64;
        let mut best = f32::NEG_INFINITY;
        let mut saw_nan = false;
        let mut samples = 0u64;
        for sy in 0..samples_y {
            let y = y1 + (sy as f32 + 0.5) * bin_h / samples_y as f32 + output_pixel_offset;
            for sx in 0..samples_x {
                let x = x1 + (sx as f32 + 0.5) * bin_w / samples_x as f32 + output_pixel_offset;
                let sample = match mode {
                    DmlInterpolationMode::Linear => {
                        let x0 = x.floor() as i64;
                        let y0 = y.floor() as i64;
                        let fx = x - x.floor();
                        let fy = y - y.floor();
                        if x0 >= 0 && y0 >= 0 && x0 + 1 < width as i64 && y0 + 1 < height as i64 {
                            let p00 = load_scalar(
                                inputs[0],
                                index_of(&[batch, channel, y0 as u64, x0 as u64], &input.strides),
                                input.data_type,
                            );
                            let p10 = load_scalar(
                                inputs[0],
                                index_of(
                                    &[batch, channel, y0 as u64, (x0 + 1) as u64],
                                    &input.strides,
                                ),
                                input.data_type,
                            );
                            let p01 = load_scalar(
                                inputs[0],
                                index_of(
                                    &[batch, channel, (y0 + 1) as u64, x0 as u64],
                                    &input.strides,
                                ),
                                input.data_type,
                            );
                            let p11 = load_scalar(
                                inputs[0],
                                index_of(
                                    &[batch, channel, (y0 + 1) as u64, (x0 + 1) as u64],
                                    &input.strides,
                                ),
                                input.data_type,
                            );
                            (1.0 - fx) * (1.0 - fy) * p00
                                + fx * (1.0 - fy) * p10
                                + (1.0 - fx) * fy * p01
                                + fx * fy * p11
                        } else {
                            out_of_bounds_value
                        }
                    }
                    DmlInterpolationMode::NearestNeighbor => {
                        let xi = x.round() as i64;
                        let yi = y.round() as i64;
                        if xi >= 0 && yi >= 0 && xi < width as i64 && yi < height as i64 {
                            load_scalar(
                                inputs[0],
                                index_of(&[batch, channel, yi as u64, xi as u64], &input.strides),
                                input.data_type,
                            )
                        } else {
                            out_of_bounds_value
                        }
                    }
                };
                if sample.is_nan() {
                    saw_nan = true;
                }
                if reduction == DmlReduceKind::Max {
                    best = best.max(sample);
                } else {
                    acc += sample as f64;
                }
                samples += 1;
            }
        }
        let value = if saw_nan {
            f32::NAN
        } else if samples == 0 {
            0.0
        } else if reduction == DmlReduceKind::Max {
            best
        } else {
            (acc / samples as f64) as f32
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
