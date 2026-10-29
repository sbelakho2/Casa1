//! Activations portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub(crate) fn validate_softmax_ex(&self, kind: DmlSoftmaxKind, axes: &[u32]) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        if input.sizes != self.output.sizes {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} input and output sizes must match",
                kind.operator_type()
            )));
        }
        let rank = input.sizes.len();
        if axes.is_empty() {
            return Err(DmlError::invalid(
                "softmax-family operator requires at least one axis",
            ));
        }
        let mut seen = Vec::with_capacity(axes.len());
        for axis in axes {
            if *axis as usize >= rank {
                return Err(DmlError::invalid(format!(
                    "softmax-family axis {axis} is out of range for rank {rank}"
                )));
            }
            if seen.contains(axis) {
                return Err(DmlError::invalid(format!(
                    "softmax-family axis {axis} appears more than once"
                )));
            }
            seen.push(*axis);
        }
        Ok(())
    }

    pub(crate) fn validate_ex_activation(&self, activation: DmlExActivation) -> DmlResult<()> {
        let ty = activation.operator_type();
        match activation {
            DmlExActivation::ParameterizedRelu => {
                self.require_input_count(2)?;
                if self.inputs[0].sizes != self.inputs[1].sizes {
                    return Err(DmlError::invalid(
                        "parameterized ReLU input and slope sizes must match",
                    ));
                }
            }
            DmlExActivation::ReluGrad => {
                self.require_input_count(2)?;
                if self.inputs[0].sizes != self.inputs[1].sizes {
                    return Err(DmlError::invalid(
                        "ReLU gradient input and input gradient sizes must match",
                    ));
                }
            }
            DmlExActivation::ParametricSoftplus { alpha, beta } => {
                self.require_input_count(1)?;
                if !alpha.is_finite() || !beta.is_finite() {
                    return Err(DmlError::invalid(
                        "parametric softplus alpha and beta must be finite",
                    ));
                }
            }
            DmlExActivation::ScaledElu { alpha, gamma } => {
                self.require_input_count(1)?;
                if !alpha.is_finite() || !gamma.is_finite() {
                    return Err(DmlError::invalid(
                        "scaled ELU alpha and gamma must be finite",
                    ));
                }
            }
            DmlExActivation::Shrink { bias, threshold } => {
                self.require_input_count(1)?;
                if !bias.is_finite() || !threshold.is_finite() {
                    return Err(DmlError::invalid(
                        "shrink bias and threshold must be finite",
                    ));
                }
            }
            DmlExActivation::Celu { alpha } => {
                self.require_input_count(1)?;
                if !alpha.is_finite() || alpha <= 0.0 {
                    return Err(DmlError::invalid("CELU alpha must be finite and positive"));
                }
            }
        }
        if self.inputs[0].sizes != self.output.sizes {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} input and output sizes must match"
            )));
        }
        Ok(())
    }

    pub(crate) fn validate_lp_normalization(
        &self,
        axis: u32,
        epsilon: f32,
        p: u32,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        if axis as usize >= input.sizes.len() {
            return Err(DmlError::invalid(format!(
                "LP normalization axis {axis} is out of range for rank {}",
                input.sizes.len()
            )));
        }
        if !epsilon.is_finite() || epsilon < 0.0 {
            return Err(DmlError::invalid(
                "LP normalization epsilon must be finite and non-negative",
            ));
        }
        if p != 1 && p != 2 {
            return Err(DmlError::invalid(format!(
                "LP normalization P must be 1 or 2, got {p}"
            )));
        }
        if self.output.sizes != input.sizes {
            return Err(DmlError::invalid(
                "LP normalization input and output sizes must match",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_lrn_grad(
        &self,
        _cross_channel: bool,
        local_size: u32,
        alpha: f32,
        beta: f32,
        bias: f32,
    ) -> DmlResult<()> {
        self.validate_elementwise_grad("local response normalization")?;
        if local_size == 0 {
            return Err(DmlError::invalid(
                "local response normalization gradient local size must be non-zero",
            ));
        }
        if !alpha.is_finite() || !beta.is_finite() || !bias.is_finite() {
            return Err(DmlError::invalid(
                "local response normalization gradient parameters must be finite",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_bn_grad(&self, epsilon: f32, training: bool) -> DmlResult<()> {
        self.require_input_count(5)?;
        if self.extra_outputs.len() != 2 {
            return Err(DmlError::invalid(
                "batch normalization gradient requires gradient, scale gradient, and bias gradient outputs",
            ));
        }
        let input = &self.inputs[0];
        let gradient = &self.inputs[1];
        if input.sizes.len() < 2 {
            return Err(DmlError::invalid(
                "batch normalization gradient input must have rank >= 2",
            ));
        }
        if input.sizes != gradient.sizes || input.sizes != self.output.sizes {
            return Err(DmlError::invalid(
                "batch normalization gradient input, input gradient, and output sizes must match",
            ));
        }
        for parameter in &self.inputs[2..] {
            if parameter.sizes.len() != input.sizes.len() {
                return Err(DmlError::invalid(
                    "batch normalization gradient parameter tensors must have the input rank",
                ));
            }
            for (dimension, size) in parameter.sizes.iter().enumerate() {
                let expected = if dimension == 1 { input.sizes[1] } else { 1 };
                if *size != expected && *size != input.sizes[dimension] {
                    return Err(DmlError::invalid(format!(
                        "batch normalization gradient parameter size at dimension {dimension} must be 1 or the input size"
                    )));
                }
            }
        }
        for extra in &self.extra_outputs {
            if extra.element_count() != input.sizes[1] as u64 {
                return Err(DmlError::invalid(
                    "batch normalization gradient scale and bias gradients must have one element per channel",
                ));
            }
        }
        if !epsilon.is_finite() || epsilon < 0.0 {
            return Err(DmlError::invalid(
                "batch normalization gradient epsilon must be finite and non-negative",
            ));
        }
        let _ = training;
        Ok(())
    }

    pub(crate) fn validate_bn_training(&self, epsilon: f32, _training: bool) -> DmlResult<()> {
        if !(3..=4).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "batch normalization training expects 3 or 4 input tensors, got {}",
                self.inputs.len()
            )));
        }
        if self.extra_outputs.len() != 2 {
            return Err(DmlError::invalid(
                "batch normalization training requires output, mean, and variance tensors",
            ));
        }
        let input = &self.inputs[0];
        if input.sizes.len() < 2 {
            return Err(DmlError::invalid(
                "batch normalization training input must have rank >= 2",
            ));
        }
        if self.output.sizes != input.sizes {
            return Err(DmlError::invalid(
                "batch normalization training input and output sizes must match",
            ));
        }
        for parameter in &self.inputs[1..] {
            if parameter.sizes.len() != input.sizes.len() {
                return Err(DmlError::invalid(
                    "batch normalization training parameter tensors must have the input rank",
                ));
            }
            for (dimension, size) in parameter.sizes.iter().enumerate() {
                let expected = if dimension == 1 { input.sizes[1] } else { 1 };
                if *size != expected && *size != input.sizes[dimension] {
                    return Err(DmlError::invalid(format!(
                        "batch normalization training parameter size at dimension {dimension} must be 1 or the input size"
                    )));
                }
            }
        }
        for extra in &self.extra_outputs {
            if extra.element_count() != input.sizes[1] as u64 {
                return Err(DmlError::invalid(
                    "batch normalization training mean and variance outputs must have one element per channel",
                ));
            }
        }
        if !epsilon.is_finite() || epsilon < 0.0 {
            return Err(DmlError::invalid(
                "batch normalization training epsilon must be finite and non-negative",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_batch_normalization(
        &self,
        spatial: bool,
        epsilon: f32,
    ) -> DmlResult<()> {
        if self.inputs.len() != 5 {
            return Err(DmlError::invalid(format!(
                "batch normalization requires 5 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        if input.sizes.len() < 2 {
            return Err(DmlError::invalid(
                "batch normalization input must have rank >= 2",
            ));
        }
        if self.output.sizes != input.sizes {
            return Err(DmlError::invalid(
                "batch normalization input and output sizes must match",
            ));
        }
        if !epsilon.is_finite() || epsilon < 0.0 {
            return Err(DmlError::invalid(
                "batch normalization epsilon must be finite and non-negative",
            ));
        }
        let roles = self.input_roles();
        for (index, parameter) in self.inputs[1..].iter().enumerate() {
            if parameter.sizes.len() != input.sizes.len() {
                return Err(DmlError::invalid(format!(
                    "batch normalization parameter {} must have the same rank as the input",
                    roles[index + 1]
                )));
            }
            if spatial {
                for (dimension, size) in parameter.sizes.iter().enumerate() {
                    let expected = if dimension == 1 { input.sizes[1] } else { 1 };
                    if *size != expected {
                        return Err(DmlError::invalid(format!(
                            "batch normalization spatial parameter {} at dimension {dimension} must have size {expected}, got {size}",
                            roles[index + 1]
                        )));
                    }
                }
            } else if parameter.sizes != input.sizes {
                return Err(DmlError::invalid(format!(
                    "batch normalization non-spatial parameter {} must match the input sizes",
                    roles[index + 1]
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_lrn(
        &self,
        _cross_channel: bool,
        local_size: u32,
        alpha: f32,
        beta: f32,
        bias: f32,
    ) -> DmlResult<()> {
        self.require_input_count(1)?;
        let input = &self.inputs[0];
        if input.sizes.len() < 3 {
            return Err(DmlError::invalid(
                "local response normalization requires rank >= 3",
            ));
        }
        if local_size == 0 {
            return Err(DmlError::invalid(
                "local response normalization local size must be non-zero",
            ));
        }
        if !alpha.is_finite() || !beta.is_finite() || !bias.is_finite() {
            return Err(DmlError::invalid(
                "local response normalization alpha, beta, and bias must be finite",
            ));
        }
        if self.output.sizes != input.sizes {
            return Err(DmlError::invalid(
                "local response normalization input and output sizes must match",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_mvn(
        &self,
        axes: &[u32],
        _normalize_variance: bool,
        _use_mean: bool,
        epsilon: f32,
    ) -> DmlResult<()> {
        if !(1..=3).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "mean variance normalization expects 1 to 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let rank = input.sizes.len();
        if axes.is_empty() {
            return Err(DmlError::invalid(
                "mean variance normalization requires at least one axis",
            ));
        }
        let mut seen = Vec::with_capacity(axes.len());
        for axis in axes {
            if *axis as usize >= rank {
                return Err(DmlError::invalid(format!(
                    "mean variance normalization axis {axis} is out of range for rank {rank}"
                )));
            }
            if seen.contains(axis) {
                return Err(DmlError::invalid(format!(
                    "mean variance normalization axis {axis} appears more than once"
                )));
            }
            seen.push(*axis);
        }
        if !epsilon.is_finite() || epsilon < 0.0 {
            return Err(DmlError::invalid(
                "mean variance normalization epsilon must be finite and non-negative",
            ));
        }
        for (index, parameter) in self.inputs[1..].iter().enumerate() {
            if parameter.sizes.len() != rank {
                return Err(DmlError::invalid(format!(
                    "mean variance normalization parameter {index} must have the same rank as the input"
                )));
            }
            for dimension in 0..rank {
                if parameter.sizes[dimension] != 1
                    && parameter.sizes[dimension] != input.sizes[dimension]
                {
                    return Err(DmlError::invalid(format!(
                        "mean variance normalization parameter {index} size at dimension {dimension} must be 1 or {}",
                        input.sizes[dimension]
                    )));
                }
            }
        }
        if self.output.sizes != input.sizes {
            return Err(DmlError::invalid(
                "mean variance normalization input and output sizes must match",
            ));
        }
        Ok(())
    }
}

pub(crate) fn activation_msl(activation: DmlActivation, fallback_alpha: f32, x: &str) -> String {
    match activation {
        DmlActivation::Relu => format!("fmax({x}, 0.0f)"),
        DmlActivation::LeakyRelu { alpha } => {
            format!("({x}) >= 0.0f ? ({x}) : ({x}) * {}", msl_float(alpha))
        }
        DmlActivation::Sigmoid => format!("1.0f / (1.0f + exp(-({x})))"),
        DmlActivation::Tanh => format!("tanh({x})"),
        DmlActivation::Identity => format!("({x})"),
        DmlActivation::Elu { alpha } => format!(
            "({x}) >= 0.0f ? ({x}) : {} * (exp(({x})) - 1.0f)",
            msl_float(alpha)
        ),
        DmlActivation::Linear { alpha, beta } => {
            format!("{} * ({x}) + {}", msl_float(alpha), msl_float(beta))
        }
        DmlActivation::Softplus { steepness } => format!(
            "log(1.0f + exp({} * ({x}))) / {}",
            msl_float(steepness),
            msl_float(steepness)
        ),
        DmlActivation::Softsign => format!("({x}) / (1.0f + abs({x}))"),
        DmlActivation::Gelu => format!(
            "0.5f * ({x}) * (1.0f + tanh(0.7978845608f * (({x}) + 0.044715f * ({x}) * ({x}) * ({x}))))"
        ),
        DmlActivation::Swish { scale } => {
            format!("({x}) / (1.0f + exp(-{} * ({x})))", msl_float(scale))
        }
        DmlActivation::HardSwish { alpha, beta } => format!(
            "({x}) * clamp({} * ({x}) + {}, 0.0f, 1.0f)",
            msl_float(alpha),
            msl_float(beta)
        ),
        DmlActivation::HardSigmoid { alpha, beta } => format!(
            "clamp({} * ({x}) + {}, 0.0f, 1.0f)",
            msl_float(alpha),
            msl_float(beta)
        ),
        DmlActivation::ScaledTanh { alpha, beta } => {
            format!("{} * tanh({} * ({x}))", msl_float(alpha), msl_float(beta))
        }
        DmlActivation::ThresholdedRelu { alpha } => {
            let _ = fallback_alpha;
            format!("({x}) > {} ? ({x}) : 0.0f", msl_float(alpha))
        }
    }
}

pub(crate) fn activation_cpu(activation: DmlActivation, x: f32) -> f32 {
    match activation {
        DmlActivation::Relu => x.max(0.0),
        DmlActivation::LeakyRelu { alpha } => {
            if x >= 0.0 {
                x
            } else {
                x * alpha
            }
        }
        DmlActivation::Sigmoid => 1.0 / (1.0 + (-x).exp()),
        DmlActivation::Tanh => x.tanh(),
        DmlActivation::Identity => x,
        DmlActivation::Elu { alpha } => {
            if x >= 0.0 {
                x
            } else {
                alpha * (x.exp() - 1.0)
            }
        }
        DmlActivation::Linear { alpha, beta } => alpha * x + beta,
        DmlActivation::Softplus { steepness } => (1.0 + (steepness * x).exp()).ln() / steepness,
        DmlActivation::Softsign => x / (1.0 + x.abs()),
        DmlActivation::Gelu => {
            0.5 * x * (1.0 + (0.797_884_56 * (x + 0.044_715 * x * x * x)).tanh())
        }
        DmlActivation::Swish { scale } => x / (1.0 + (-scale * x).exp()),
        DmlActivation::HardSwish { alpha, beta } => x * (alpha * x + beta).clamp(0.0, 1.0),
        DmlActivation::HardSigmoid { alpha, beta } => (alpha * x + beta).clamp(0.0, 1.0),
        DmlActivation::ScaledTanh { alpha, beta } => alpha * (beta * x).tanh(),
        DmlActivation::ThresholdedRelu { alpha } => {
            if x > alpha {
                x
            } else {
                0.0
            }
        }
    }
}

pub(crate) fn emit_softmax_ex_msl(
    plan: &DmlOpPlan,
    kind: DmlSoftmaxKind,
    axes: &[u32],
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let total: u64 = axes
        .iter()
        .map(|axis| input.sizes[*axis as usize] as u64)
        .product();
    let index_for = |coords: &[String]| linear_index(input, coords);
    source.push_str("    float max_value = -INFINITY;\n    uint best_t = 0u;\n");
    source.push_str(&format!("    for (uint t = 0u; t < {total}u; ++t) {{\n"));
    source.push_str("        uint rem = t;\n");
    let mut coord_expr = Vec::with_capacity(rank);
    for dimension in 0..rank {
        if axes.contains(&(dimension as u32)) {
            let size = input.sizes[dimension];
            source.push_str(&format!("        uint c{dimension} = rem % {size}u;\n"));
            source.push_str(&format!("        rem /= {size}u;\n"));
            coord_expr.push(format!("c{dimension}"));
        } else {
            coord_expr.push(format!("o{dimension}"));
        }
    }
    source.push_str(&format!(
        "        float v = float(in0[{}]);\n",
        index_for(&coord_expr)
    ));
    source.push_str(
        "        if (!isnan(v) && (t == 0u || v > max_value)) { max_value = v; best_t = t; }\n    }\n",
    );
    let own_index = index_for(&coord_names(rank));
    if kind == DmlSoftmaxKind::Hardmax || kind == DmlSoftmaxKind::Hardmax1 {
        source.push_str("    uint best_rem = best_t;\n");
        for dimension in 0..rank {
            if axes.contains(&(dimension as u32)) {
                let size = input.sizes[dimension];
                source.push_str(&format!(
                    "    uint best{dimension} = best_rem % {size}u;\n    best_rem /= {size}u;\n"
                ));
            }
        }
        let terms = (0..rank)
            .map(|dimension| {
                if axes.contains(&(dimension as u32)) {
                    format!("o{dimension} == best{dimension}")
                } else {
                    format!("o{dimension} == o{dimension}")
                }
            })
            .collect::<Vec<_>>()
            .join(" && ");
        source.push_str(&format!(
            "    out[{}] = ({scalar})(({terms}) ? 1.0f : 0.0f);\n}}\n",
            output_index_expr(&plan.output)
        ));
        return Ok(source);
    }
    source.push_str("    float sum = 0.0f;\n");
    source.push_str(&format!("    for (uint t = 0u; t < {total}u; ++t) {{\n"));
    source.push_str("        uint rem = t;\n");
    for dimension in 0..rank {
        if axes.contains(&(dimension as u32)) {
            let size = input.sizes[dimension];
            source.push_str(&format!("        uint c{dimension} = rem % {size}u;\n"));
            source.push_str(&format!("        rem /= {size}u;\n"));
        }
    }
    source.push_str(&format!(
        "        sum += exp(float(in0[{}]) - max_value);\n    }}\n",
        index_for(&coord_expr)
    ));
    let value = if kind == DmlSoftmaxKind::LogSoftmax || kind == DmlSoftmaxKind::LogSoftmax1 {
        format!("float(in0[{own_index}]) - max_value - log(sum)")
    } else {
        format!("exp(float(in0[{own_index}]) - max_value) / sum")
    };
    source.push_str(&format!(
        "    out[{}] = ({scalar})({value});\n}}\n",
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

pub(crate) fn emit_ex_activation_msl(
    plan: &DmlOpPlan,
    activation: DmlExActivation,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let index = broadcast_index(&plan.inputs[0]);
    let (preamble, expression) = match activation {
        DmlExActivation::ParameterizedRelu => {
            let slope = broadcast_index(&plan.inputs[1]);
            (
                format!("    float x = float(in0[{index}]);\n    float s = float(in1[{slope}]);\n"),
                "x >= 0.0f ? x : s * x".to_string(),
            )
        }
        DmlExActivation::ReluGrad => {
            let gradient = broadcast_index(&plan.inputs[1]);
            (
                format!(
                    "    float x = float(in0[{index}]);\n    float g = float(in1[{gradient}]);\n"
                ),
                "x > 0.0f ? g : 0.0f".to_string(),
            )
        }
        DmlExActivation::ParametricSoftplus { alpha, beta } => (
            format!(
                "    float x = float(in0[{index}]);\n    float z = {} * x;\n",
                msl_float(beta)
            ),
            format!(
                "z > 20.0f ? {} * z : {} * log(1.0f + exp(z))",
                msl_float(alpha),
                msl_float(alpha)
            ),
        ),
        DmlExActivation::ScaledElu { alpha, gamma } => (
            format!("    float x = float(in0[{index}]);\n"),
            format!(
                "{} * (x >= 0.0f ? x : {} * (exp(x) - 1.0f))",
                msl_float(gamma),
                msl_float(alpha)
            ),
        ),
        DmlExActivation::Shrink { bias, threshold } => (
            format!("    float x = float(in0[{index}]);\n"),
            format!(
                "x < -{} ? x + {} : (x > {} ? x - {} : 0.0f)",
                msl_float(threshold),
                msl_float(bias),
                msl_float(threshold),
                msl_float(bias)
            ),
        ),
        DmlExActivation::Celu { alpha } => (
            format!("    float x = float(in0[{index}]);\n"),
            format!(
                "fmax(0.0f, x) + fmin(0.0f, {} * (exp(x / {}) - 1.0f))",
                msl_float(alpha),
                msl_float(alpha)
            ),
        ),
    };
    source.push_str(&preamble);
    source.push_str(&format!("    float value = {expression};\n"));
    source.push_str(&format!(
        "    out[{}] = ({scalar})value;\n}}\n",
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

pub(crate) fn emit_lp_normalization_msl(
    plan: &DmlOpPlan,
    axis: u32,
    epsilon: f32,
    p: u32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let axis_size = input.sizes[axis as usize];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut coords = coord_names(rank);
    source.push_str("    float sum = 0.0f;\n");
    source.push_str(&format!(
        "    for (uint j = 0u; j < {axis_size}u; ++j) {{\n"
    ));
    coords[axis as usize] = "j".to_string();
    source.push_str(&format!(
        "        float v = float(in0[{}]);\n        sum += pow(fabs(v), {}.0f);\n    }}\n",
        linear_index(input, &coords),
        p
    ));
    coords[axis as usize] = format!("o{axis}");
    source.push_str(&format!(
        "    float x = float(in0[{}]);\n    float denom = pow({} + sum, 1.0f / {}.0f);\n    out[{}] = ({scalar})(x / denom);\n}}\n",
        linear_index(input, &coords),
        msl_float(epsilon),
        p,
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

pub(crate) fn emit_relu_grad_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let index = broadcast_index(&plan.inputs[0]);
    let gradient = broadcast_index(&plan.inputs[1]);
    source.push_str(&format!(
        "    float x = float(in0[{index}]);\n    float g = float(in1[{gradient}]);\n    out[{}] = ({scalar})(x > 0.0f ? g : 0.0f);\n}}\n",
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_lrn_grad_msl(
    plan: &DmlOpPlan,
    cross_channel: bool,
    local_size: u32,
    alpha: f32,
    beta: f32,
    bias: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let count = input.element_count();
    let half = (local_size / 2) as i64;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let own = coord_names(rank);
    let own_index = linear_index(input, &own);
    let sum_window = |center: &[String]| -> (String, u64) {
        if cross_channel {
            let size = input.sizes[1];
            let mut coords = center.to_vec();
            coords[1] = format!("uint(clamp(int({}) + delta, 0, {}))", center[1], size - 1);
            (
                format!(
                    "for (int delta = {}; delta <= {}; ++delta) {{ float sv = float(in0[{}]); sum += sv * sv; }}",
                    -half,
                    half,
                    linear_index(input, &coords)
                ),
                0,
            )
        } else {
            let mut coords = center.to_vec();
            coords[rank - 2] = format!(
                "uint(clamp(int({}) + dy, 0, {}))",
                center[rank - 2],
                input.sizes[rank - 2] - 1
            );
            coords[rank - 1] = format!(
                "uint(clamp(int({}) + dx, 0, {}))",
                center[rank - 1],
                input.sizes[rank - 1] - 1
            );
            (
                format!(
                    "for (int dy = {}; dy <= {}; ++dy) {{ for (int dx = {}; dx <= {}; ++dx) {{ float sv = float(in0[{}]); sum += sv * sv; }} }}",
                    -half,
                    half,
                    -half,
                    half,
                    linear_index(input, &coords)
                ),
                0,
            )
        }
    };
    let (own_loop, _) = sum_window(&own);
    source.push_str("    float sum = 0.0f;\n");
    source.push_str(&format!("    {own_loop}\n"));
    source.push_str(&format!(
        "    float own_sum = sum;\n    float own_s = {} + {} * own_sum / {};\n    float own_x = float(in0[{own_index}]);\n    float own_g = float(in1[{own_index}]);\n    float result = own_g / pow(own_s, {});\n    float coefficient = {} * {} * 2.0f * own_x;\n",
        msl_float(bias),
        msl_float(alpha),
        msl_float(local_size as f32),
        msl_float(beta),
        msl_float(beta),
        msl_float(alpha / local_size as f32)
    ));
    source.push_str(&format!("    for (uint i = 0u; i < {count}u; ++i) {{\n"));
    let mut coords = Vec::with_capacity(rank);
    for dimension in 0..rank {
        let divisor: u64 = input.sizes[dimension + 1..]
            .iter()
            .map(|value| *value as u64)
            .product();
        source.push_str(&format!(
            "        uint q{dimension} = (i / {divisor}u) % {}u;\n",
            input.sizes[dimension]
        ));
        coords.push(format!("q{dimension}"));
    }
    if cross_channel {
        source.push_str(&format!(
            "        int distance = int(q1) - int(o1);\n        if (distance < -{} || distance > {}) continue;\n",
            half, half
        ));
    } else {
        source.push_str(&format!(
            "        int dy = int(q{}) - int(o{});\n        int dx = int(q{}) - int(o{});\n        if (dy < -{} || dy > {} || dx < -{} || dx > {}) continue;\n",
            rank - 2,
            rank - 2,
            rank - 1,
            rank - 1,
            half,
            half,
            half,
            half
        ));
    }
    let (window_loop, _) = sum_window(&coords);
    source.push_str("        float sum = 0.0f;\n");
    source.push_str(&format!("        {window_loop}\n"));
    source.push_str(&format!(
        "        float s = {} + {} * sum / {};\n        float y = float(in0[{}]) / pow(s, {});\n        float g = float(in1[{}]);\n        result -= g * y * coefficient / s;\n    }}\n",
        msl_float(bias),
        msl_float(alpha),
        msl_float(local_size as f32),
        linear_index(input, &coords),
        msl_float(beta),
        linear_index(input, &coords)
    ));
    source.push_str(&format!(
        "    out[{}] = ({scalar})result;\n}}\n",
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

pub(crate) fn emit_batch_normalization_training_msl(
    plan: &DmlOpPlan,
    epsilon: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let batch = input.sizes[0];
    let channels = input.sizes[1];
    let mut source = msl_header_outputs(plan, scalar, &[scalar, scalar, scalar]);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str("    float sum = 0.0f;\n    float sumsq = 0.0f;\n");
    source.push_str(&format!("    for (uint b = 0u; b < {batch}u; ++b) {{\n"));
    let mut indent = String::from("        ");
    let mut coords = vec!["b".to_string(), "o1".to_string()];
    for dimension in 2..rank {
        source.push_str(&format!(
            "{indent}for (uint s{dimension} = 0u; s{dimension} < {}u; ++s{dimension}) {{\n",
            input.sizes[dimension]
        ));
        coords.push(format!("s{dimension}"));
        indent.push_str("    ");
    }
    source.push_str(&format!(
        "{indent}float v = float(in0[{}]);\n{indent}sum += v;\n{indent}sumsq += v * v;\n",
        linear_index(input, &coords)
    ));
    for _ in 2..rank {
        indent.truncate(indent.len().saturating_sub(4));
        source.push_str(&format!("{indent}}}\n"));
    }
    source.push_str("    }\n");
    let spatial_count: u64 = input.sizes[2..].iter().map(|size| *size as u64).product();
    let total = batch as u64 * spatial_count;
    source.push_str(&format!(
        "    const float count = {};\n    float mean = sum / count;\n    float variance = fmax(0.0f, sumsq / count - mean * mean);\n",
        msl_float(total as f32)
    ));
    let mut own_coords = vec!["o0".to_string(), "o1".to_string()];
    for dimension in 2..rank {
        own_coords.push(format!("o{dimension}"));
    }
    source.push_str(&format!(
        "    float x = float(in0[{}]);\n",
        linear_index(input, &own_coords)
    ));
    if plan.inputs.len() == 4 {
        source.push_str(&format!(
            "    x += float(in3[{}]);\n",
            linear_index(&plan.inputs[3], &own_coords)
        ));
    }
    source.push_str(&format!(
        "    float scale = float(in1[o1 * {}u]);\n    float bias = float(in2[o1 * {}u]);\n    float y = (x - mean) * rsqrt(variance + {}) * scale + bias;\n    out0[{}] = ({scalar})y;\n",
        plan.inputs[1].strides[1],
        plan.inputs[2].strides[1],
        msl_float(epsilon),
        output_index_expr(&plan.output)
    ));
    let mut condition = "o0 == 0u".to_string();
    for dimension in 2..rank {
        condition.push_str(&format!(" && o{dimension} == 0u"));
    }
    source.push_str(&format!(
        "    if ({condition}) {{\n        out1[o1 * {}u] = ({scalar})mean;\n        out2[o1 * {}u] = ({scalar})variance;\n    }}\n",
        plan.extra_outputs[0].strides[1],
        plan.extra_outputs[1].strides[1]
    ));
    source.push_str("}\n");
    let _ = channels;
    Ok(source)
}

pub(crate) fn emit_batch_normalization_grad_msl(
    plan: &DmlOpPlan,
    epsilon: f32,
) -> DmlResult<String> {
    emit_batch_normalization_grad_body_msl(plan, epsilon, false)
}

pub(crate) fn emit_batch_normalization_training_grad_msl(
    plan: &DmlOpPlan,
    epsilon: f32,
) -> DmlResult<String> {
    emit_batch_normalization_grad_body_msl(plan, epsilon, true)
}

pub(crate) fn emit_batch_normalization_grad_body_msl(
    plan: &DmlOpPlan,
    epsilon: f32,
    training: bool,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let gradient = &plan.inputs[1];
    let mean_tensor = &plan.inputs[2];
    let variance_tensor = &plan.inputs[3];
    let scale_tensor = &plan.inputs[4];
    let rank = input.sizes.len();
    let batch = input.sizes[0];
    let mut source = msl_header_outputs(plan, scalar, &[scalar, scalar, scalar]);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let spatial_count: u64 = input.sizes[2..].iter().map(|size| *size as u64).product();
    let total = batch as u64 * spatial_count;
    source.push_str(&format!(
        "    float mean = float(in2[o1 * {}u]);\n    float variance = float(in3[o1 * {}u]);\n    float scale = float(in4[o1 * {}u]);\n    float inv_std = rsqrt(variance + {});\n",
        mean_tensor.strides[1],
        variance_tensor.strides[1],
        scale_tensor.strides[1],
        msl_float(epsilon)
    ));
    let mut own_coords = vec!["o0".to_string(), "o1".to_string()];
    for dimension in 2..rank {
        own_coords.push(format!("o{dimension}"));
    }
    if training {
        source.push_str("    float sum_g = 0.0f;\n    float sum_gx = 0.0f;\n");
        source.push_str(&format!("    for (uint b = 0u; b < {batch}u; ++b) {{\n"));
        let mut indent = String::from("        ");
        let mut coords = vec!["b".to_string(), "o1".to_string()];
        for dimension in 2..rank {
            source.push_str(&format!(
                "{indent}for (uint s{dimension} = 0u; s{dimension} < {}u; ++s{dimension}) {{\n",
                input.sizes[dimension]
            ));
            coords.push(format!("s{dimension}"));
            indent.push_str("    ");
        }
        source.push_str(&format!(
            "{indent}float xv = (float(in0[{}]) - mean) * inv_std;\n{indent}sum_g += float(in1[{}]);\n{indent}sum_gx += float(in1[{}]) * xv;\n",
            linear_index(input, &coords),
            linear_index(gradient, &coords),
            linear_index(gradient, &coords)
        ));
        for _ in 2..rank {
            indent.truncate(indent.len().saturating_sub(4));
            source.push_str(&format!("{indent}}}\n"));
        }
        source.push_str("    }\n");
        source.push_str(&format!(
            "    float n = {};\n    float xhat = (float(in0[{}]) - mean) * inv_std;\n    float g = float(in1[{}]);\n    float dx = (scale * inv_std / n) * (n * g - sum_g - xhat * sum_gx);\n    out0[{}] = ({scalar})dx;\n",
            msl_float(total as f32),
            linear_index(input, &own_coords),
            linear_index(gradient, &own_coords),
            output_index_expr(&plan.output)
        ));
    } else {
        source.push_str(&format!(
            "    float g = float(in1[{}]);\n    out0[{}] = ({scalar})(g * scale * inv_std);\n",
            linear_index(gradient, &own_coords),
            output_index_expr(&plan.output)
        ));
    }
    let mut condition = "o0 == 0u".to_string();
    for dimension in 2..rank {
        condition.push_str(&format!(" && o{dimension} == 0u"));
    }
    source.push_str(&format!("    if ({condition}) {{\n"));
    source.push_str("        float dscale = 0.0f;\n        float dbias = 0.0f;\n");
    source.push_str(&format!(
        "        for (uint b = 0u; b < {batch}u; ++b) {{\n"
    ));
    let mut indent = String::from("            ");
    let mut coords = vec!["b".to_string(), "o1".to_string()];
    for dimension in 2..rank {
        source.push_str(&format!(
            "{indent}for (uint s{dimension} = 0u; s{dimension} < {}u; ++s{dimension}) {{\n",
            input.sizes[dimension]
        ));
        coords.push(format!("s{dimension}"));
        indent.push_str("    ");
    }
    source.push_str(&format!(
        "{indent}float xv = (float(in0[{}]) - mean) * inv_std;\n{indent}float gv = float(in1[{}]);\n{indent}dscale += gv * xv;\n{indent}dbias += gv;\n",
        linear_index(input, &coords),
        linear_index(gradient, &coords)
    ));
    for _ in 2..rank {
        indent.truncate(indent.len().saturating_sub(4));
        source.push_str(&format!("{indent}}}\n"));
    }
    source.push_str("        }\n");
    source.push_str(&format!(
        "        out1[o1 * {}u] = ({scalar})dscale;\n        out2[o1 * {}u] = ({scalar})dbias;\n    }}\n",
        plan.extra_outputs[0].strides[1],
        plan.extra_outputs[1].strides[1]
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_activation_msl(
    plan: &DmlOpPlan,
    activation: DmlActivation,
    alpha: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    float x = float(in0[{}]);\n",
        broadcast_index(&plan.inputs[0])
    ));
    let value = activation_msl(activation, alpha, "x");
    source.push_str(&format!(
        "    out[{}] = ({scalar})({value});\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_batch_normalization_msl(
    plan: &DmlOpPlan,
    spatial: bool,
    epsilon: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!("    uint x_idx = {};\n", broadcast_index(input)));
    let parameter_index = |desc: &DmlTensorDesc| -> String {
        if spatial {
            let mut terms = Vec::new();
            for (dimension, (size, stride)) in desc.sizes.iter().zip(&desc.strides).enumerate() {
                if *size != 1 {
                    terms.push(format!("o{dimension} * {stride}u"));
                }
            }
            if terms.is_empty() {
                "0u".to_string()
            } else {
                terms.join(" + ")
            }
        } else {
            broadcast_index(desc)
        }
    };
    source.push_str(&format!(
        "    float mean = float(in1[{}]);\n",
        parameter_index(&plan.inputs[1])
    ));
    source.push_str(&format!(
        "    float variance = float(in2[{}]);\n",
        parameter_index(&plan.inputs[2])
    ));
    source.push_str(&format!(
        "    float scale = float(in3[{}]);\n",
        parameter_index(&plan.inputs[3])
    ));
    source.push_str(&format!(
        "    float bias = float(in4[{}]);\n",
        parameter_index(&plan.inputs[4])
    ));
    source.push_str(&format!(
        "    float value = (float(in0[x_idx]) - mean) * rsqrt(variance + {}) * scale + bias;\n",
        msl_float(epsilon)
    ));
    source.push_str(&format!(
        "    out[{}] = ({scalar})value;\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_softmax_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let last = rank - 1;
    let axis = input.sizes[last];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let input_base = (0..last)
        .map(|dimension| format!("o{dimension} * {}u", input.strides[dimension]))
        .collect::<Vec<_>>()
        .join(" + ");
    let input_base = if input_base.is_empty() {
        "0u".to_string()
    } else {
        input_base
    };
    let output_base = (0..last)
        .map(|dimension| format!("o{dimension} * {}u", plan.output.strides[dimension]))
        .collect::<Vec<_>>()
        .join(" + ");
    let output_base = if output_base.is_empty() {
        "0u".to_string()
    } else {
        output_base
    };
    let input_axis_stride = input.strides[last];
    let output_axis_stride = plan.output.strides[last];
    source.push_str(&format!("    uint base_in = {input_base};\n"));
    source.push_str(&format!("    uint base_out = {output_base};\n"));
    source.push_str("    float max_value = -INFINITY;\n");
    source.push_str(&format!("    for (uint j = 0u; j < {axis}u; ++j) {{\n"));
    source.push_str(&format!(
        "        max_value = fmax(max_value, float(in0[base_in + j * {input_axis_stride}u]));\n"
    ));
    source.push_str("    }\n");
    source.push_str("    float sum = 0.0f;\n");
    source.push_str(&format!("    for (uint j = 0u; j < {axis}u; ++j) {{\n"));
    source.push_str(&format!(
        "        sum += exp(float(in0[base_in + j * {input_axis_stride}u]) - max_value);\n"
    ));
    source.push_str("    }\n");
    source.push_str(&format!("    uint j = o{last};\n"));
    source.push_str(&format!(
        "    float value = exp(float(in0[base_in + j * {input_axis_stride}u]) - max_value) / sum;\n"
    ));
    source.push_str(&format!(
        "    out[base_out + j * {output_axis_stride}u] = ({scalar})value;\n"
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn emit_lrn_msl(
    plan: &DmlOpPlan,
    cross_channel: bool,
    local_size: u32,
    alpha: f32,
    beta: f32,
    bias: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let half = (local_size / 2) as i64;
    let center = coord_names(rank);
    source.push_str("    float sum = 0.0f;\n");
    if cross_channel {
        let size = input.sizes[1];
        source.push_str(&format!(
            "    for (int offset = {}; offset <= {}; ++offset) {{\n",
            -half, half
        ));
        let mut coords = center.clone();
        coords[1] = format!("uint(clamp(int(o1) + offset, 0, {}))", size - 1);
        source.push_str(&format!(
            "        float v = float(in0[{}]);\n        sum += v * v;\n    }}\n",
            linear_index(input, &coords)
        ));
    } else {
        source.push_str(&format!(
            "    for (int offset_y = {}; offset_y <= {}; ++offset_y) {{\n",
            -half, half
        ));
        source.push_str(&format!(
            "        for (int offset_x = {}; offset_x <= {}; ++offset_x) {{\n",
            -half, half
        ));
        let mut coords = center.clone();
        coords[rank - 2] = format!(
            "uint(clamp(int(o{}) + offset_y, 0, {}))",
            rank - 2,
            input.sizes[rank - 2] - 1
        );
        coords[rank - 1] = format!(
            "uint(clamp(int(o{}) + offset_x, 0, {}))",
            rank - 1,
            input.sizes[rank - 1] - 1
        );
        source.push_str(&format!(
            "            float v = float(in0[{}]);\n            sum += v * v;\n        }}\n    }}\n",
            linear_index(input, &coords)
        ));
    }
    source.push_str(&format!(
        "    float value = float(in0[{}]) / pow({} + {} * sum / {}, {});\n",
        linear_index(input, &center),
        msl_float(bias),
        msl_float(alpha),
        msl_float(local_size as f32),
        msl_float(beta)
    ));
    source.push_str(&format!(
        "    out[{}] = ({scalar})value;\n}}\n",
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

pub(crate) fn emit_mvn_msl(
    plan: &DmlOpPlan,
    axes: &[u32],
    normalize_variance: bool,
    use_mean: bool,
    epsilon: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let reduction_count: u64 = axes
        .iter()
        .map(|axis| input.sizes[*axis as usize] as u64)
        .product();
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
    source.push_str(&format!("    uint base = {base};\n"));
    source.push_str("    float sum = 0.0f;\n    float sum_sq = 0.0f;\n");
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
    source.push_str(&format!(
        "        float v = float(in0[{index_expr}]);\n        sum += v;\n        sum_sq += v * v;\n    }}\n"
    ));
    if use_mean {
        source.push_str(&format!("    float mean = sum / {reduction_count}.0f;\n"));
    } else {
        source.push_str("    float mean = 0.0f;\n");
    }
    let normalized = if normalize_variance {
        format!(
            "(float(in0[{}]) - mean) * rsqrt(sum_sq / {reduction_count}.0f - mean * mean + {})",
            linear_index(input, &coord_names(rank)),
            msl_float(epsilon)
        )
    } else {
        format!(
            "(float(in0[{}]) - mean)",
            linear_index(input, &coord_names(rank))
        )
    };
    source.push_str(&format!("    float value = {normalized};\n"));
    if plan.inputs.len() >= 2 {
        let scale = &plan.inputs[1];
        source.push_str(&format!(
            "    value *= float(in1[{}]);\n",
            broadcast_index_with(scale, rank)
        ));
    }
    if plan.inputs.len() >= 3 {
        let bias = &plan.inputs[2];
        source.push_str(&format!(
            "    value += float(in2[{}]);\n",
            broadcast_index_with(bias, rank)
        ));
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})value;\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

pub(crate) fn execute_softmax_ex_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    kind: DmlSoftmaxKind,
    axes: &[u32],
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let dtype = plan.output.data_type;
    let total: u64 = axes
        .iter()
        .map(|axis| input.sizes[*axis as usize] as u64)
        .product();
    for gid in 0..plan.output.element_count() {
        let base = coords_of(gid, &plan.output.sizes);
        let mut max_value = f32::NEG_INFINITY;
        let mut best_t = 0u64;
        for t in 0..total {
            let coords = decode_reduced_coords(t, axes, &input.sizes, &base);
            let value = load_scalar(input_bytes, index_of(&coords, &input.strides), dtype);
            if !value.is_nan() && (t == 0 || value > max_value) {
                max_value = value;
                best_t = t;
            }
        }
        let value = match kind {
            DmlSoftmaxKind::Hardmax | DmlSoftmaxKind::Hardmax1 => {
                let best = decode_reduced_coords(best_t, axes, &input.sizes, &base);
                let selected = axes
                    .iter()
                    .all(|axis| base[*axis as usize] == best[*axis as usize]);
                if selected { 1.0 } else { 0.0 }
            }
            DmlSoftmaxKind::LogSoftmax | DmlSoftmaxKind::LogSoftmax1 => {
                let mut sum = 0.0f64;
                for t in 0..total {
                    let coords = decode_reduced_coords(t, axes, &input.sizes, &base);
                    let value = load_scalar(input_bytes, index_of(&coords, &input.strides), dtype);
                    sum += ((value - max_value) as f64).exp();
                }
                let own = load_scalar(input_bytes, index_of(&base, &input.strides), dtype);
                own - max_value - (sum as f32).ln()
            }
            DmlSoftmaxKind::Softmax1 => {
                let mut sum = 0.0f64;
                for t in 0..total {
                    let coords = decode_reduced_coords(t, axes, &input.sizes, &base);
                    let value = load_scalar(input_bytes, index_of(&coords, &input.strides), dtype);
                    sum += ((value - max_value) as f64).exp();
                }
                let own = load_scalar(input_bytes, index_of(&base, &input.strides), dtype);
                (((own - max_value) as f64).exp() / sum) as f32
            }
        };
        store_scalar(output, output_index(&plan.output, gid), dtype, value);
    }
    Ok(())
}

pub(crate) fn execute_ex_activation_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    activation: DmlExActivation,
) -> DmlResult<()> {
    let dtype = plan.output.data_type;
    for gid in 0..plan.output.element_count() {
        let coords = coords_of(gid, &plan.output.sizes);
        let input = &plan.inputs[0];
        let x = load_scalar(
            inputs[0],
            index_of(&broadcast_coords(input, &coords), &input.strides),
            dtype,
        );
        let value = match activation {
            DmlExActivation::ParameterizedRelu => {
                let slope_desc = &plan.inputs[1];
                let slope = load_scalar(
                    inputs[1],
                    index_of(&broadcast_coords(slope_desc, &coords), &slope_desc.strides),
                    dtype,
                );
                if x >= 0.0 { x } else { slope * x }
            }
            DmlExActivation::ReluGrad => {
                let gradient_desc = &plan.inputs[1];
                let gradient = load_scalar(
                    inputs[1],
                    index_of(
                        &broadcast_coords(gradient_desc, &coords),
                        &gradient_desc.strides,
                    ),
                    dtype,
                );
                if x > 0.0 { gradient } else { 0.0 }
            }
            DmlExActivation::ParametricSoftplus { alpha, beta } => {
                let z = beta * x;
                if z > 20.0 {
                    alpha * z
                } else {
                    alpha * (1.0 + z.exp()).ln()
                }
            }
            DmlExActivation::ScaledElu { alpha, gamma } => {
                let e = if x >= 0.0 { x } else { alpha * (x.exp() - 1.0) };
                gamma * e
            }
            DmlExActivation::Shrink { bias, threshold } => {
                if x < -threshold {
                    x + bias
                } else if x > threshold {
                    x - bias
                } else {
                    0.0
                }
            }
            DmlExActivation::Celu { alpha } => {
                x.max(0.0) + (alpha * ((x / alpha).exp() - 1.0)).min(0.0)
            }
        };
        store_scalar(output, output_index(&plan.output, gid), dtype, value);
    }
    Ok(())
}

pub(crate) fn execute_lp_normalization_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    axis: u32,
    epsilon: f32,
    p: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let dtype = plan.output.data_type;
    let axis = axis as usize;
    for gid in 0..plan.output.element_count() {
        let mut coords = coords_of(gid, &plan.output.sizes);
        let mut sum = 0.0f64;
        for position in 0..input.sizes[axis] as u64 {
            coords[axis] = position;
            let value = load_scalar(input_bytes, index_of(&coords, &input.strides), dtype);
            sum += (value as f64).abs().powi(p as i32);
        }
        coords[axis] = coords_of(gid, &plan.output.sizes)[axis];
        let own = load_scalar(input_bytes, index_of(&coords, &input.strides), dtype);
        let denominator = (epsilon as f64 + sum).powf(1.0 / p as f64);
        let value = (own as f64 / denominator) as f32;
        store_scalar(output, output_index(&plan.output, gid), dtype, value);
    }
    Ok(())
}

pub(crate) fn execute_relu_grad_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
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
            if x > 0.0 { g } else { 0.0 },
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_lrn_grad_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    cross_channel: bool,
    local_size: u32,
    alpha: f32,
    beta: f32,
    bias: f32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let dtype = plan.output.data_type;
    let rank = input.sizes.len();
    let half = (local_size / 2) as i64;
    let mut window = |coords: &mut Vec<u64>| -> Vec<u64> {
        if cross_channel {
            let center = coords[1] as i64;
            coords[1] = (center - half).clamp(0, input.sizes[1] as i64 - 1) as u64;
            coords.to_vec()
        } else {
            let cy = coords[rank - 2] as i64;
            let cx = coords[rank - 1] as i64;
            coords[rank - 2] = (cy - half).clamp(0, input.sizes[rank - 2] as i64 - 1) as u64;
            coords[rank - 1] = (cx - half).clamp(0, input.sizes[rank - 1] as i64 - 1) as u64;
            coords.to_vec()
        }
    };
    let _ = &mut window;
    for gid in 0..plan.output.element_count() {
        let own = coords_of(gid, &plan.output.sizes);
        let own_x = load_scalar(inputs[0], index_of(&own, &input.strides), dtype);
        let mut own_sum = 0.0f64;
        if cross_channel {
            for offset in -half..=half {
                let mut coords = own.clone();
                coords[1] = (own[1] as i64 + offset).clamp(0, input.sizes[1] as i64 - 1) as u64;
                let value = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype) as f64;
                own_sum += value * value;
            }
        } else {
            for offset_y in -half..=half {
                for offset_x in -half..=half {
                    let mut coords = own.clone();
                    coords[rank - 2] = (own[rank - 2] as i64 + offset_y)
                        .clamp(0, input.sizes[rank - 2] as i64 - 1)
                        as u64;
                    coords[rank - 1] = (own[rank - 1] as i64 + offset_x)
                        .clamp(0, input.sizes[rank - 1] as i64 - 1)
                        as u64;
                    let value =
                        load_scalar(inputs[0], index_of(&coords, &input.strides), dtype) as f64;
                    own_sum += value * value;
                }
            }
        }
        let own_s = bias as f64 + alpha as f64 * own_sum / local_size as f64;
        let own_g = load_scalar(inputs[1], index_of(&own, &input.strides), dtype) as f64;
        let mut result = own_g / own_s.powf(beta as f64);
        let count = if cross_channel {
            (2 * half + 1) as u64
        } else {
            ((2 * half + 1) as u64) * ((2 * half + 1) as u64)
        };
        for i in 0..input.element_count() {
            let i_coords = coords_of(i, &input.sizes);
            let mut contains = true;
            if cross_channel {
                let distance = (i_coords[1] as i64 - own[1] as i64).abs();
                if distance > half {
                    contains = false;
                }
            } else {
                let dy = (i_coords[rank - 2] as i64 - own[rank - 2] as i64).abs();
                let dx = (i_coords[rank - 1] as i64 - own[rank - 1] as i64).abs();
                if dy > half || dx > half {
                    contains = false;
                }
            }
            if !contains {
                continue;
            }
            let i_x = load_scalar(inputs[0], i, dtype) as f64;
            let i_g = load_scalar(inputs[1], i, dtype) as f64;
            let mut sum = 0.0f64;
            if cross_channel {
                for offset in -half..=half {
                    let mut coords = i_coords.clone();
                    coords[1] =
                        (i_coords[1] as i64 + offset).clamp(0, input.sizes[1] as i64 - 1) as u64;
                    let value =
                        load_scalar(inputs[0], index_of(&coords, &input.strides), dtype) as f64;
                    sum += value * value;
                }
            } else {
                for offset_y in -half..=half {
                    for offset_x in -half..=half {
                        let mut coords = i_coords.clone();
                        coords[rank - 2] = (i_coords[rank - 2] as i64 + offset_y)
                            .clamp(0, input.sizes[rank - 2] as i64 - 1)
                            as u64;
                        coords[rank - 1] = (i_coords[rank - 1] as i64 + offset_x)
                            .clamp(0, input.sizes[rank - 1] as i64 - 1)
                            as u64;
                        let value =
                            load_scalar(inputs[0], index_of(&coords, &input.strides), dtype) as f64;
                        sum += value * value;
                    }
                }
            }
            let s = bias as f64 + alpha as f64 * sum / local_size as f64;
            let y = i_x / s.powf(beta as f64);
            result -=
                i_g * y * beta as f64 * (alpha as f64 / local_size as f64) * 2.0 * own_x as f64 / s;
        }
        let _ = count;
        store_scalar(
            output,
            output_index(&plan.output, gid),
            dtype,
            result as f32,
        );
    }
    Ok(())
}

pub(crate) fn execute_batch_normalization_training_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    extras: &mut [&mut [u8]],
    epsilon: f32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let dtype = plan.output.data_type;
    let batch = input.sizes[0];
    let channels = input.sizes[1];
    let spatial_count: u64 = input.sizes[2..].iter().map(|size| *size as u64).product();
    let total = batch as u64 * spatial_count;
    let mut means = vec![0.0f32; channels as usize];
    let mut variances = vec![0.0f32; channels as usize];
    for channel in 0..channels as u64 {
        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        for b in 0..batch as u64 {
            for s in 0..spatial_count {
                let mut coords = vec![b, channel];
                coords.extend(coords_of(s, &input.sizes[2..]));
                let value = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype) as f64;
                sum += value;
                sum_sq += value * value;
            }
        }
        let mean = sum / total as f64;
        means[channel as usize] = mean as f32;
        variances[channel as usize] = (sum_sq / total as f64 - mean * mean).max(0.0) as f32;
    }
    let scale = &plan.inputs[1];
    let bias = &plan.inputs[2];
    for gid in 0..plan.output.element_count() {
        let coords = coords_of(gid, &plan.output.sizes);
        let channel = coords[1];
        let mut value = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
        if plan.inputs.len() == 4 {
            value += load_scalar(inputs[3], index_of(&coords, &plan.inputs[3].strides), dtype);
        }
        let parameter_coords = broadcast_coords(scale, &coords);
        let scale_value = load_scalar(
            inputs[1],
            index_of(&parameter_coords, &scale.strides),
            dtype,
        );
        let bias_value = load_scalar(
            inputs[2],
            index_of(&broadcast_coords(bias, &coords), &bias.strides),
            dtype,
        );
        let normalized = (value - means[channel as usize])
            * (variances[channel as usize] + epsilon).sqrt().recip();
        store_scalar(
            output,
            output_index(&plan.output, gid),
            dtype,
            normalized * scale_value + bias_value,
        );
    }
    for (index, values) in [&means, &variances].iter().enumerate() {
        let destination = &mut *extras[index];
        for (channel, value) in values.iter().enumerate() {
            let offset = channel_offset(&plan.extra_outputs[index], channel as u64);
            store_scalar(destination, offset, dtype, *value);
        }
    }
    Ok(())
}

pub(crate) fn execute_batch_normalization_grad_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    extras: &mut [&mut [u8]],
    epsilon: f32,
    training: bool,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let gradient = &plan.inputs[1];
    let mean_tensor = &plan.inputs[2];
    let variance_tensor = &plan.inputs[3];
    let scale_tensor = &plan.inputs[4];
    let dtype = plan.output.data_type;
    let batch = input.sizes[0];
    let channels = input.sizes[1];
    let spatial_count: u64 = input.sizes[2..].iter().map(|size| *size as u64).product();
    let total = batch as u64 * spatial_count;
    let mut scale_gradients = vec![0.0f32; channels as usize];
    let mut bias_gradients = vec![0.0f32; channels as usize];
    for channel in 0..channels as u64 {
        let mut mean = 0.0f32;
        let mut variance = 0.0f32;
        for b in 0..batch as u64 {
            let mut coords = vec![b, channel];
            coords.extend(coords_of(0, &input.sizes[2..]));
            mean = load_scalar(
                inputs[2],
                index_of(
                    &broadcast_coords(mean_tensor, &coords),
                    &mean_tensor.strides,
                ),
                dtype,
            );
            variance = load_scalar(
                inputs[3],
                index_of(
                    &broadcast_coords(variance_tensor, &coords),
                    &variance_tensor.strides,
                ),
                dtype,
            );
            break;
        }
        let inv_std = (variance + epsilon).sqrt().recip();
        let mut sum_g = 0.0f64;
        let mut sum_gx = 0.0f64;
        for b in 0..batch as u64 {
            for s in 0..spatial_count {
                let mut coords = vec![b, channel];
                coords.extend(coords_of(s, &input.sizes[2..]));
                let x = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
                let g = load_scalar(inputs[1], index_of(&coords, &gradient.strides), dtype);
                let xhat = (x - mean) * inv_std;
                sum_g += g as f64;
                sum_gx += g as f64 * xhat as f64;
            }
        }
        scale_gradients[channel as usize] = sum_gx as f32;
        bias_gradients[channel as usize] = sum_g as f32;
        let scale_value = {
            let coords = broadcast_coords(scale_tensor, &vec![0, channel]);
            load_scalar(inputs[4], index_of(&coords, &scale_tensor.strides), dtype)
        };
        for b in 0..batch as u64 {
            for s in 0..spatial_count {
                let mut coords = vec![b, channel];
                coords.extend(coords_of(s, &input.sizes[2..]));
                let x = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
                let g = load_scalar(inputs[1], index_of(&coords, &gradient.strides), dtype);
                let xhat = (x - mean) * inv_std;
                let dx = if training {
                    (scale_value * inv_std / total as f32)
                        * (total as f32 * g - sum_g as f32 - xhat * sum_gx as f32)
                } else {
                    g * scale_value * inv_std
                };
                store_scalar(output, index_of(&coords, &plan.output.strides), dtype, dx);
            }
        }
    }
    for (index, values) in [&scale_gradients, &bias_gradients].iter().enumerate() {
        let destination = &mut *extras[index];
        for (channel, value) in values.iter().enumerate() {
            let offset = channel_offset(&plan.extra_outputs[index], channel as u64);
            store_scalar(destination, offset, dtype, *value);
        }
    }
    Ok(())
}

pub(crate) fn execute_lrn_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    cross_channel: bool,
    local_size: u32,
    alpha: f32,
    beta: f32,
    bias: f32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let count = plan.output.element_count();
    let half = (local_size / 2) as i64;
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let mut sum = 0.0f64;
        if cross_channel {
            for offset in -half..=half {
                let coordinate =
                    (coords[1] as i64 + offset).clamp(0, input.sizes[1] as i64 - 1) as u64;
                let mut window = coords.clone();
                window[1] = coordinate;
                let value = load_scalar(
                    input_bytes,
                    index_of(&window, &input.strides),
                    input.data_type,
                );
                sum += (value as f64) * (value as f64);
            }
        } else {
            for offset_y in -half..=half {
                for offset_x in -half..=half {
                    let mut window = coords.clone();
                    window[rank - 2] = (coords[rank - 2] as i64 + offset_y)
                        .clamp(0, input.sizes[rank - 2] as i64 - 1)
                        as u64;
                    window[rank - 1] = (coords[rank - 1] as i64 + offset_x)
                        .clamp(0, input.sizes[rank - 1] as i64 - 1)
                        as u64;
                    let value = load_scalar(
                        input_bytes,
                        index_of(&window, &input.strides),
                        input.data_type,
                    );
                    sum += (value as f64) * (value as f64);
                }
            }
        }
        let x = load_scalar(
            input_bytes,
            index_of(&coords, &input.strides),
            input.data_type,
        );
        let value = x / (bias + alpha * sum as f32 / local_size as f32).powf(beta);
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            value,
        );
    }
    Ok(())
}

pub(crate) fn execute_mvn_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    axes: &[u32],
    normalize_variance: bool,
    use_mean: bool,
    epsilon: f32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let count = plan.output.element_count();
    let reduction_count: u64 = axes
        .iter()
        .map(|axis| input.sizes[*axis as usize] as u64)
        .product();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        for step in 0..reduction_count {
            let mut coords = output_coords.clone();
            let mut remainder = step;
            for axis in axes {
                let axis = *axis as usize;
                coords[axis] = remainder % input.sizes[axis] as u64;
                remainder /= input.sizes[axis] as u64;
            }
            let value = load_scalar(
                inputs[0],
                index_of(&coords, &input.strides),
                input.data_type,
            ) as f64;
            sum += value;
            sum_sq += value * value;
        }
        let mean = if use_mean {
            sum / reduction_count as f64
        } else {
            0.0
        };
        let x = load_scalar(
            inputs[0],
            index_of(&output_coords, &input.strides),
            input.data_type,
        ) as f64;
        let mut value = x - mean;
        if normalize_variance {
            let variance = (sum_sq / reduction_count as f64 - mean * mean).max(0.0);
            value /= (variance + epsilon as f64).sqrt();
        }
        if plan.inputs.len() >= 2 {
            let scale = &plan.inputs[1];
            let mut coords = Vec::with_capacity(rank);
            for dimension in 0..rank {
                coords.push(if scale.sizes[dimension] == 1 {
                    0
                } else {
                    output_coords[dimension]
                });
            }
            value *= load_scalar(
                inputs[1],
                index_of(&coords, &scale.strides),
                scale.data_type,
            ) as f64;
        }
        if plan.inputs.len() >= 3 {
            let bias = &plan.inputs[2];
            let mut coords = Vec::with_capacity(rank);
            for dimension in 0..rank {
                coords.push(if bias.sizes[dimension] == 1 {
                    0
                } else {
                    output_coords[dimension]
                });
            }
            value +=
                load_scalar(inputs[2], index_of(&coords, &bias.strides), bias.data_type) as f64;
        }
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            value as f32,
        );
    }
    Ok(())
}
