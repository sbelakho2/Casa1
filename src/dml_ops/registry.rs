//! Registry portion of the DML operator implementation.

use super::*;

impl DmlOpPlan {
    pub fn operator_type(&self) -> u32 {
        self.kind.operator_type()
    }

    pub fn output_count(&self) -> usize {
        1 + self.extra_outputs.len()
    }

    /// Number of kernel invocations. Recurrent kernels use one thread per
    /// batch element; a quantized output packs two 4-bit elements per thread;
    /// every other kernel uses one thread per output element.
    pub fn dispatch_count(&self) -> u64 {
        match &self.kind {
            DmlOpKind::Rnn { .. } | DmlOpKind::Gru { .. } | DmlOpKind::Lstm { .. } => {
                self.inputs[0].sizes.get(1).copied().unwrap_or(1) as u64
            }
            DmlOpKind::QuantizeLinear if self.output.is_4bit() => {
                self.output.element_count().div_ceil(2)
            }
            DmlOpKind::Quantize { .. } if self.output.is_4bit() => {
                self.output.element_count().div_ceil(2)
            }
            DmlOpKind::MaxUnpooling => self.inputs[0].element_count(),
            _ => self.output.element_count(),
        }
    }

    pub fn outputs(&self) -> impl Iterator<Item = &DmlTensorDesc> {
        std::iter::once(&self.output).chain(self.extra_outputs.iter())
    }

    pub fn output_roles(&self) -> Vec<&'static str> {
        match &self.kind {
            DmlOpKind::TopK { .. } => vec!["values", "indices"],
            DmlOpKind::Split { .. } => vec!["output"; self.output_count()],
            DmlOpKind::DynamicQuantizeLinear => vec!["output", "scale", "zero point"],
            DmlOpKind::Adam { .. } => {
                vec!["parameters", "first moment", "second moment"]
            }
            DmlOpKind::Rnn { outputs, .. }
            | DmlOpKind::Gru { outputs, .. }
            | DmlOpKind::Lstm { outputs, .. } => outputs
                .iter()
                .map(|output| match output {
                    DmlRecurrentOutput::Sequence => "sequence",
                    DmlRecurrentOutput::Single => "single output",
                    DmlRecurrentOutput::CellSingle => "cell state",
                })
                .collect(),
            DmlOpKind::MaxPoolingEx { has_indices, .. } => {
                if *has_indices {
                    vec!["output", "indices"]
                } else {
                    vec!["output"]
                }
            }
            DmlOpKind::NonZeroCoordinates => vec!["count", "coordinates"],
            DmlOpKind::RandomGenerator { .. } => {
                if self.extra_outputs.is_empty() {
                    vec!["output"]
                } else {
                    vec!["output", "output state"]
                }
            }
            DmlOpKind::BatchNormalizationTraining { .. } => {
                vec!["output", "mean", "variance"]
            }
            DmlOpKind::BatchNormalizationGrad { .. }
            | DmlOpKind::BatchNormalizationTrainingGrad { .. } => {
                vec!["gradient", "scale gradient", "bias gradient"]
            }
            _ => vec!["output"],
        }
    }

    pub fn input_roles(&self) -> Vec<&'static str> {
        match &self.kind {
            DmlOpKind::Gemm { .. } => {
                if self.inputs.len() == 3 {
                    vec!["A", "B", "C"]
                } else {
                    vec!["A", "B"]
                }
            }
            DmlOpKind::Convolution { .. } => {
                if self.inputs.len() == 3 {
                    vec!["input", "filter", "bias"]
                } else {
                    vec!["input", "filter"]
                }
            }
            DmlOpKind::BatchNormalization { .. } => {
                vec!["input", "mean", "variance", "scale", "bias"]
            }
            DmlOpKind::Binary { .. } | DmlOpKind::Add1 => vec!["A", "B"],
            DmlOpKind::Concat { .. } => vec!["input"; self.inputs.len()],
            DmlOpKind::Rnn { options, .. }
            | DmlOpKind::Gru { options, .. }
            | DmlOpKind::Lstm { options, .. } => (0..self.inputs.len())
                .map(|index| options.role(index))
                .collect(),
            DmlOpKind::Gather { .. } | DmlOpKind::GatherElements { .. } => {
                vec!["input", "indices"]
            }
            DmlOpKind::GatherNd { .. } => vec!["input", "indices"],
            DmlOpKind::Scatter { .. } | DmlOpKind::ScatterNd { .. } => {
                vec!["input", "indices", "updates"]
            }
            DmlOpKind::RoiPooling { .. } => vec!["input", "ROI"],
            DmlOpKind::RoiAlign { .. } => vec!["input", "ROI", "batch indices"],
            DmlOpKind::LocalResponseNormalization { .. } => vec!["input"],
            DmlOpKind::MeanVarianceNormalization { .. } => {
                let mut roles = vec!["input"];
                for _ in 1..self.inputs.len() {
                    roles.push(if self.inputs.len() == 3 && roles.len() == 2 {
                        "scale"
                    } else {
                        "bias"
                    });
                }
                roles
            }
            DmlOpKind::Adam { .. } => vec![
                "parameters",
                "first moment",
                "second moment",
                "gradient",
                "training step",
            ],
            DmlOpKind::QuantizeLinear | DmlOpKind::DequantizeLinear => {
                if self.inputs.len() == 3 {
                    vec!["input", "scale", "zero point"]
                } else {
                    vec!["input", "scale"]
                }
            }
            DmlOpKind::DynamicQuantizeLinear => vec!["input"],
            DmlOpKind::QuantizedLinearAdd {
                a_zero_point,
                b_zero_point,
                output_zero_point,
            } => {
                let mut roles = vec!["A", "A scale"];
                if *a_zero_point {
                    roles.push("A zero point");
                }
                roles.push("B");
                roles.push("B scale");
                if *b_zero_point {
                    roles.push("B zero point");
                }
                roles.push("output scale");
                if *output_zero_point {
                    roles.push("output zero point");
                }
                roles
            }
            DmlOpKind::MatrixMultiplyInteger {
                quantized_output,
                a_zero_point,
                b_zero_point,
                output_scale,
                output_zero_point,
            } => {
                let mut roles = vec!["A"];
                if *quantized_output {
                    roles.push("A scale");
                }
                if *a_zero_point {
                    roles.push("A zero point");
                }
                roles.push("B");
                if *quantized_output {
                    roles.push("B scale");
                }
                if *b_zero_point {
                    roles.push("B zero point");
                }
                if *output_scale {
                    roles.push("output scale");
                }
                if *output_zero_point {
                    roles.push("output zero point");
                }
                roles
            }
            DmlOpKind::ConvolutionInteger {
                quantized_output,
                input_zero_point,
                filter_zero_point,
                bias,
                output_scale,
                output_zero_point,
                ..
            } => {
                let mut roles = vec!["input"];
                if *quantized_output {
                    roles.push("input scale");
                }
                if *input_zero_point {
                    roles.push("input zero point");
                }
                roles.push("filter");
                if *quantized_output {
                    roles.push("filter scale");
                }
                if *filter_zero_point {
                    roles.push("filter zero point");
                }
                if *bias {
                    roles.push("bias");
                }
                if *output_scale {
                    roles.push("output scale");
                }
                if *output_zero_point {
                    roles.push("output zero point");
                }
                roles
            }
            DmlOpKind::QuantizedLinearAveragePooling {
                input_zero_point,
                output_zero_point,
                ..
            } => {
                let mut roles = vec!["input", "input scale"];
                if *input_zero_point {
                    roles.push("input zero point");
                }
                roles.push("output scale");
                if *output_zero_point {
                    roles.push("output zero point");
                }
                roles
            }
            DmlOpKind::MatrixMultiplyIntegerToFloat {
                a_zero_point,
                b_zero_point,
                bias,
            } => {
                let mut roles = vec!["A", "A scale"];
                if *a_zero_point {
                    roles.push("A zero point");
                }
                roles.push("B");
                roles.push("B scale");
                if *b_zero_point {
                    roles.push("B zero point");
                }
                if *bias {
                    roles.push("bias");
                }
                roles
            }
            DmlOpKind::Quantize { quantization_type }
            | DmlOpKind::Dequantize { quantization_type } => {
                let mut roles = vec!["input"];
                if *quantization_type >= 1 {
                    roles.push("scale");
                }
                if *quantization_type >= 2 {
                    roles.push("zero point");
                }
                roles
            }
            DmlOpKind::ExActivation {
                activation: DmlExActivation::ParameterizedRelu,
            } => vec!["input", "slope"],
            DmlOpKind::ExActivation {
                activation: DmlExActivation::ReluGrad,
            }
            | DmlOpKind::ReluGrad => vec!["input", "input gradient"],
            DmlOpKind::If => vec!["condition", "A", "B"],
            DmlOpKind::MaxPoolingEx { .. } => vec!["input"],
            DmlOpKind::MaxUnpooling => vec!["input", "indices"],
            DmlOpKind::AveragePoolingGrad { .. } => vec!["input gradient"],
            DmlOpKind::MaxPoolingGrad { .. } => vec!["input", "input gradient"],
            DmlOpKind::ResampleGrad { .. } => vec!["input gradient"],
            DmlOpKind::SliceGrad { .. } => vec!["input gradient"],
            DmlOpKind::ClipGrad { .. } => vec!["input", "input gradient"],
            DmlOpKind::LrnGrad { .. } => vec!["input", "input gradient"],
            DmlOpKind::BatchNormalizationGrad { .. } => {
                vec!["input", "input gradient", "mean", "variance", "scale"]
            }
            DmlOpKind::BatchNormalizationTraining { .. } => {
                if self.inputs.len() == 4 {
                    vec!["input", "scale", "bias", "fused add"]
                } else {
                    vec!["input", "scale", "bias"]
                }
            }
            DmlOpKind::BatchNormalizationTrainingGrad { .. } => {
                vec!["input", "input gradient", "mean", "variance", "scale"]
            }
            DmlOpKind::RoiAlignGrad { .. } => {
                if self.inputs.len() == 4 {
                    vec!["input", "input gradient", "ROI", "batch indices"]
                } else {
                    vec!["input gradient", "ROI", "batch indices"]
                }
            }
            DmlOpKind::RandomGenerator { .. } => vec!["input state"],
            DmlOpKind::NonZeroCoordinates => vec!["input"],
            DmlOpKind::MultiHeadAttention {
                layout,
                has_bias,
                has_mask,
                ..
            } => {
                let mut roles = match layout {
                    DmlMhaLayout::Separate => vec!["query", "key", "value"],
                    DmlMhaLayout::StackedQueryKey => vec!["stacked query/key"],
                    DmlMhaLayout::StackedKeyValue => vec!["stacked key/value"],
                    DmlMhaLayout::StackedQueryKeyValue => vec!["stacked query/key/value"],
                };
                if *has_bias {
                    roles.push("bias");
                }
                if *has_mask {
                    roles.push("mask");
                }
                roles
            }
            _ => vec!["input"],
        }
    }

    pub(crate) fn validate_dtypes(&self) -> DmlResult<()> {
        let ty = self.operator_type();
        match &self.kind {
            DmlOpKind::Gemm { .. } | DmlOpKind::Convolution { .. } => {
                let allow_f16 = self.kind.allows_float16();
                validate_dtype(&self.inputs[0], ty, allow_f16)?;
                validate_dtype(&self.output, ty, allow_f16)?;
                if self.inputs[0].data_type != self.output.data_type {
                    return Err(DmlError::invalid(
                        "input and output tensors must have the same DataType",
                    ));
                }
                // A packed 4-bit weight/filter tensor is a real DirectML
                // layout: the activation stays float while the weights read
                // two signed/unsigned nibbles per byte.
                let weight = &self.inputs[1];
                expect_dtype(
                    weight,
                    &[
                        self.output.data_type,
                        DML_TENSOR_DATA_TYPE_UINT4,
                        DML_TENSOR_DATA_TYPE_INT4,
                    ],
                    ty,
                    "weight",
                )?;
                for tensor in self.inputs.iter().skip(2).chain(&self.extra_outputs) {
                    validate_dtype(tensor, ty, allow_f16)?;
                    if tensor.data_type != self.output.data_type {
                        return Err(DmlError::invalid(
                            "additional input and output tensors must have the output DataType",
                        ));
                    }
                }
            }
            DmlOpKind::Unary { .. }
            | DmlOpKind::Fill { .. }
            | DmlOpKind::Cumulative { .. }
            | DmlOpKind::DiagonalMatrix { .. } => {
                let allow_f16 = self.kind.allows_float16();
                for desc in self.inputs.iter().chain(self.outputs()) {
                    validate_dtype(desc, ty, allow_f16)?;
                    if desc.data_type != self.output.data_type {
                        return Err(DmlError::invalid(
                            "input and output tensors must have the same DataType",
                        ));
                    }
                }
            }
            DmlOpKind::Reverse { .. } => {
                let allow_f16 = self.kind.allows_float16();
                validate_dtype(&self.inputs[0], ty, allow_f16)?;
                validate_dtype(&self.output, ty, allow_f16)?;
                if self.inputs[0].data_type != self.output.data_type {
                    return Err(DmlError::invalid(
                        "reverse input and output tensors must have the same DataType",
                    ));
                }
                expect_dtype(
                    &self.inputs[1],
                    &[
                        DML_TENSOR_DATA_TYPE_UINT32,
                        DML_TENSOR_DATA_TYPE_INT32,
                        DML_TENSOR_DATA_TYPE_UINT8,
                        DML_TENSOR_DATA_TYPE_INT8,
                    ],
                    ty,
                    "reverse sequence lengths",
                )?;
            }
            DmlOpKind::OneHot { .. } => {
                expect_dtype(
                    &self.inputs[0],
                    &[
                        DML_TENSOR_DATA_TYPE_UINT8,
                        DML_TENSOR_DATA_TYPE_INT8,
                        DML_TENSOR_DATA_TYPE_UINT32,
                        DML_TENSOR_DATA_TYPE_INT32,
                    ],
                    ty,
                    "one-hot indices",
                )?;
                validate_dtype(&self.inputs[1], ty, true)?;
                validate_dtype(&self.output, ty, true)?;
                if self.inputs[1].data_type != self.output.data_type {
                    return Err(DmlError::invalid(
                        "one-hot values and output must have the same DataType",
                    ));
                }
            }
            DmlOpKind::Cast => {
                let allowed = [
                    DML_TENSOR_DATA_TYPE_FLOAT32,
                    DML_TENSOR_DATA_TYPE_FLOAT16,
                    DML_TENSOR_DATA_TYPE_INT32,
                    DML_TENSOR_DATA_TYPE_UINT32,
                    DML_TENSOR_DATA_TYPE_INT8,
                    DML_TENSOR_DATA_TYPE_UINT8,
                ];
                expect_dtype(&self.inputs[0], &allowed, ty, "cast input")?;
                expect_dtype(&self.output, &allowed, ty, "cast output")?;
            }
            DmlOpKind::Pooling { .. }
            | DmlOpKind::AveragePooling1 { .. }
            | DmlOpKind::Activation { .. }
            | DmlOpKind::BatchNormalization { .. }
            | DmlOpKind::Softmax
            | DmlOpKind::Binary { .. }
            | DmlOpKind::Reduce { .. }
            | DmlOpKind::Reshape
            | DmlOpKind::Transpose { .. }
            | DmlOpKind::Concat { .. }
            | DmlOpKind::Slice { .. }
            | DmlOpKind::Add1 => {
                let allow_f16 = self.kind.allows_float16();
                for desc in self.inputs.iter().chain(self.outputs()) {
                    validate_dtype(desc, ty, allow_f16)?;
                }
                let output_dtype = self.output.data_type;
                for input in &self.inputs {
                    if input.data_type != output_dtype {
                        return Err(DmlError::invalid(
                            "input and output tensors must have the same DataType",
                        ));
                    }
                }
                for extra in &self.extra_outputs {
                    if extra.data_type != output_dtype {
                        return Err(DmlError::invalid(
                            "additional output tensors must have the output DataType",
                        ));
                    }
                }
            }
            DmlOpKind::SoftmaxEx { .. }
            | DmlOpKind::ExActivation { .. }
            | DmlOpKind::LpPooling { .. }
            | DmlOpKind::LpNormalization { .. }
            | DmlOpKind::ValueScale2D { .. }
            | DmlOpKind::SpaceDepth { .. }
            | DmlOpKind::SliceEx { .. }
            | DmlOpKind::Clip1 { .. }
            | DmlOpKind::ReluGrad
            | DmlOpKind::AveragePoolingGrad { .. }
            | DmlOpKind::MaxPoolingGrad { .. }
            | DmlOpKind::ResampleGrad { .. }
            | DmlOpKind::SliceGrad { .. }
            | DmlOpKind::ClipGrad { .. }
            | DmlOpKind::LrnGrad { .. }
            | DmlOpKind::BatchNormalizationGrad { .. }
            | DmlOpKind::BatchNormalizationTraining { .. }
            | DmlOpKind::BatchNormalizationTrainingGrad { .. } => {
                let allow_f16 = self.kind.allows_float16();
                for desc in self.inputs.iter().chain(self.outputs()) {
                    validate_dtype(desc, ty, allow_f16)?;
                    if desc.data_type != self.output.data_type {
                        return Err(DmlError::invalid(
                            "input and output tensors must have the same DataType",
                        ));
                    }
                }
            }
            DmlOpKind::MaxPoolingEx { has_indices, .. } => {
                for desc in &self.inputs {
                    expect_dtype(desc, &[DML_TENSOR_DATA_TYPE_FLOAT32], ty, "pooling input")?;
                }
                expect_dtype(
                    &self.output,
                    &[DML_TENSOR_DATA_TYPE_FLOAT32],
                    ty,
                    "pooling output",
                )?;
                if *has_indices {
                    if self.extra_outputs.len() != 1 {
                        return Err(DmlError::invalid(
                            "max pooling with indices requires exactly one index output",
                        ));
                    }
                    expect_dtype(
                        &self.extra_outputs[0],
                        &[DML_TENSOR_DATA_TYPE_UINT32],
                        ty,
                        "pooling indices",
                    )?;
                }
            }
            DmlOpKind::MaxUnpooling => {
                expect_dtype(
                    &self.inputs[0],
                    &[DML_TENSOR_DATA_TYPE_FLOAT32],
                    ty,
                    "unpooling input",
                )?;
                expect_dtype(
                    &self.inputs[1],
                    &[DML_TENSOR_DATA_TYPE_UINT32],
                    ty,
                    "unpooling indices",
                )?;
                expect_dtype(
                    &self.output,
                    &[DML_TENSOR_DATA_TYPE_FLOAT32],
                    ty,
                    "unpooling output",
                )?;
            }
            DmlOpKind::If => {
                expect_dtype(
                    &self.inputs[0],
                    &[
                        DML_TENSOR_DATA_TYPE_UINT8,
                        DML_TENSOR_DATA_TYPE_INT8,
                        DML_TENSOR_DATA_TYPE_UINT32,
                        DML_TENSOR_DATA_TYPE_INT32,
                    ],
                    ty,
                    "condition",
                )?;
                let allow_f16 = self.kind.allows_float16();
                for desc in self.inputs.iter().skip(1).chain(self.outputs()) {
                    validate_dtype(desc, ty, allow_f16)?;
                    if desc.data_type != self.output.data_type {
                        return Err(DmlError::invalid(
                            "IF A, B, and output tensors must share a DataType",
                        ));
                    }
                }
            }
            DmlOpKind::BitNot => {
                let allowed = [
                    DML_TENSOR_DATA_TYPE_UINT32,
                    DML_TENSOR_DATA_TYPE_INT32,
                    DML_TENSOR_DATA_TYPE_UINT8,
                    DML_TENSOR_DATA_TYPE_INT8,
                ];
                expect_dtype(&self.inputs[0], &allowed, ty, "bitwise input")?;
                expect_same_dtype(&self.output, self.inputs[0].data_type, ty, "bitwise output")?;
            }
            DmlOpKind::BitCount => {
                expect_dtype(
                    &self.inputs[0],
                    &[
                        DML_TENSOR_DATA_TYPE_UINT32,
                        DML_TENSOR_DATA_TYPE_INT32,
                        DML_TENSOR_DATA_TYPE_UINT8,
                        DML_TENSOR_DATA_TYPE_INT8,
                    ],
                    ty,
                    "bit count input",
                )?;
                expect_dtype(
                    &self.output,
                    &[DML_TENSOR_DATA_TYPE_UINT32, DML_TENSOR_DATA_TYPE_UINT8],
                    ty,
                    "bit count output",
                )?;
            }
            DmlOpKind::RandomGenerator { .. } => {
                expect_dtype(
                    &self.inputs[0],
                    &[DML_TENSOR_DATA_TYPE_UINT32],
                    ty,
                    "random generator state",
                )?;
                expect_dtype(
                    &self.output,
                    &[DML_TENSOR_DATA_TYPE_UINT32],
                    ty,
                    "random generator output",
                )?;
                for extra in &self.extra_outputs {
                    expect_dtype(
                        extra,
                        &[DML_TENSOR_DATA_TYPE_UINT32],
                        ty,
                        "random generator output state",
                    )?;
                }
            }
            DmlOpKind::NonZeroCoordinates => {
                expect_dtype(
                    &self.inputs[0],
                    &[
                        DML_TENSOR_DATA_TYPE_FLOAT32,
                        DML_TENSOR_DATA_TYPE_FLOAT16,
                        DML_TENSOR_DATA_TYPE_INT32,
                        DML_TENSOR_DATA_TYPE_INT8,
                        DML_TENSOR_DATA_TYPE_UINT32,
                        DML_TENSOR_DATA_TYPE_UINT8,
                    ],
                    ty,
                    "nonzero input",
                )?;
                expect_dtype(
                    &self.output,
                    &[DML_TENSOR_DATA_TYPE_UINT32],
                    ty,
                    "nonzero count",
                )?;
                if self.extra_outputs.len() != 1 {
                    return Err(DmlError::invalid(
                        "nonzero coordinates requires exactly one coordinate output",
                    ));
                }
                expect_dtype(
                    &self.extra_outputs[0],
                    &[DML_TENSOR_DATA_TYPE_UINT32],
                    ty,
                    "nonzero coordinates",
                )?;
            }
            DmlOpKind::RoiAlignGrad { .. } => {
                let gradient_index = if self.inputs.len() == 4 { 1 } else { 0 };
                for (index, desc) in self.inputs.iter().enumerate() {
                    if index == gradient_index + 2 {
                        expect_dtype(
                            desc,
                            &[DML_TENSOR_DATA_TYPE_UINT32, DML_TENSOR_DATA_TYPE_INT32],
                            ty,
                            "batch indices",
                        )?;
                    } else {
                        expect_dtype(
                            desc,
                            &[DML_TENSOR_DATA_TYPE_FLOAT32, DML_TENSOR_DATA_TYPE_FLOAT16],
                            ty,
                            "ROI align gradient",
                        )?;
                    }
                }
                if self.inputs[gradient_index].data_type != self.output.data_type {
                    return Err(DmlError::invalid(
                        "ROI align gradient input gradient and output must share a DataType",
                    ));
                }
            }
            DmlOpKind::MultiHeadAttention {
                layout,
                has_bias,
                has_mask,
                ..
            } => {
                let data_inputs = match layout {
                    DmlMhaLayout::Separate => 3,
                    DmlMhaLayout::StackedQueryKey
                    | DmlMhaLayout::StackedKeyValue
                    | DmlMhaLayout::StackedQueryKeyValue => 1,
                };
                for desc in self.inputs.iter().take(data_inputs).chain(self.outputs()) {
                    expect_dtype(
                        desc,
                        &[DML_TENSOR_DATA_TYPE_FLOAT32, DML_TENSOR_DATA_TYPE_FLOAT16],
                        ty,
                        "multi-head attention",
                    )?;
                    if desc.data_type != self.output.data_type {
                        return Err(DmlError::invalid(
                            "multi-head attention tensors must share a DataType",
                        ));
                    }
                }
                let mut index = data_inputs;
                if *has_bias {
                    let bias = &self.inputs[index];
                    expect_same_dtype(bias, self.output.data_type, ty, "bias")?;
                    index += 1;
                }
                if *has_mask {
                    expect_dtype(
                        &self.inputs[index],
                        &[
                            DML_TENSOR_DATA_TYPE_UINT8,
                            DML_TENSOR_DATA_TYPE_UINT32,
                            DML_TENSOR_DATA_TYPE_INT32,
                        ],
                        ty,
                        "mask",
                    )?;
                }
            }
            DmlOpKind::DiagonalMatrix1 { .. } => {
                let allow_f16 = self.kind.allows_float16();
                for desc in self.inputs.iter().chain(self.outputs()) {
                    validate_dtype(desc, ty, allow_f16)?;
                    if desc.data_type != self.output.data_type {
                        return Err(DmlError::invalid(
                            "diagonal matrix input and output tensors must have the same DataType",
                        ));
                    }
                }
            }
            DmlOpKind::Rnn { options, .. }
            | DmlOpKind::Gru { options, .. }
            | DmlOpKind::Lstm { options, .. } => {
                let sequence_index = if options.sequence_lengths {
                    Some(
                        3 + usize::from(options.bias)
                            + usize::from(options.hidden_init)
                            + usize::from(options.cell_init),
                    )
                } else {
                    None
                };
                for (index, desc) in self.inputs.iter().enumerate() {
                    if Some(index) == sequence_index {
                        expect_index_dtype(desc, ty, "sequence lengths")?;
                    } else {
                        expect_dtype(
                            desc,
                            &[DML_TENSOR_DATA_TYPE_FLOAT32, DML_TENSOR_DATA_TYPE_FLOAT16],
                            ty,
                            "recurrent",
                        )?;
                    }
                }
                for output in self.outputs() {
                    expect_dtype(
                        output,
                        &[DML_TENSOR_DATA_TYPE_FLOAT32, DML_TENSOR_DATA_TYPE_FLOAT16],
                        ty,
                        "recurrent output",
                    )?;
                }
            }
            DmlOpKind::ArgMin { .. } | DmlOpKind::ArgMax { .. } => {
                validate_dtype(&self.inputs[0], ty, true)?;
                expect_dtype(
                    &self.output,
                    &[DML_TENSOR_DATA_TYPE_UINT32],
                    ty,
                    "argmin/argmax output",
                )?;
            }
            DmlOpKind::Padding { .. }
            | DmlOpKind::Resample { .. }
            | DmlOpKind::Tile { .. }
            | DmlOpKind::Split { .. }
            | DmlOpKind::LocalResponseNormalization { .. } => {
                let allow_f16 = self.kind.allows_float16();
                for desc in self.inputs.iter().chain(self.outputs()) {
                    validate_dtype(desc, ty, allow_f16)?;
                }
                for desc in self.inputs.iter().chain(self.outputs()) {
                    if desc.data_type != self.output.data_type {
                        return Err(DmlError::invalid(
                            "input and output tensors must have the same DataType",
                        ));
                    }
                }
            }
            DmlOpKind::TopK { .. } => {
                validate_dtype(&self.inputs[0], ty, true)?;
                if self.output.data_type != self.inputs[0].data_type {
                    return Err(DmlError::invalid(
                        "top-k value output must have the input DataType",
                    ));
                }
                if self.extra_outputs.len() != 1 {
                    return Err(DmlError::invalid("top-k requires one index output tensor"));
                }
                expect_dtype(
                    &self.extra_outputs[0],
                    &[DML_TENSOR_DATA_TYPE_UINT32],
                    ty,
                    "top-k index output",
                )?;
            }
            DmlOpKind::Gather { .. }
            | DmlOpKind::GatherElements { .. }
            | DmlOpKind::GatherNd { .. } => {
                validate_dtype(&self.inputs[0], ty, true)?;
                if self.inputs[1].data_type != DML_TENSOR_DATA_TYPE_UINT32
                    && self.inputs[1].data_type != DML_TENSOR_DATA_TYPE_INT32
                {
                    return Err(DmlError::invalid(format!(
                        "DML_OPERATOR_TYPE {ty} indices tensor must be UINT32 or INT32"
                    )));
                }
                if self.output.data_type != self.inputs[0].data_type {
                    return Err(DmlError::invalid(
                        "gather output must have the input DataType",
                    ));
                }
            }
            DmlOpKind::Scatter { .. } | DmlOpKind::ScatterNd { .. } => {
                validate_dtype(&self.inputs[0], ty, true)?;
                if self.inputs[1].data_type != DML_TENSOR_DATA_TYPE_UINT32
                    && self.inputs[1].data_type != DML_TENSOR_DATA_TYPE_INT32
                {
                    return Err(DmlError::invalid(format!(
                        "DML_OPERATOR_TYPE {ty} indices tensor must be UINT32 or INT32"
                    )));
                }
                for desc in [&self.inputs[0], &self.inputs[2]]
                    .into_iter()
                    .chain(self.outputs())
                {
                    if desc.data_type != self.inputs[0].data_type {
                        return Err(DmlError::invalid(
                            "scatter input, updates, and output must share a DataType",
                        ));
                    }
                }
            }
            DmlOpKind::RoiPooling { .. } | DmlOpKind::RoiAlign { .. } => {
                let roi_index = 1;
                for (index, desc) in self.inputs.iter().enumerate() {
                    if index == roi_index {
                        expect_dtype(desc, &[DML_TENSOR_DATA_TYPE_FLOAT32], ty, "ROI")?;
                    } else if matches!(self.kind, DmlOpKind::RoiAlign { .. }) && index == 2 {
                        expect_dtype(desc, &[DML_TENSOR_DATA_TYPE_UINT32], ty, "batch indices")?;
                    } else {
                        expect_dtype(desc, &[DML_TENSOR_DATA_TYPE_FLOAT32], ty, "ROI input")?;
                    }
                }
                expect_dtype(
                    &self.output,
                    &[DML_TENSOR_DATA_TYPE_FLOAT32],
                    ty,
                    "ROI output",
                )?;
            }
            DmlOpKind::MeanVarianceNormalization { .. } => {
                let allow_f16 = self.kind.allows_float16();
                for desc in self.inputs.iter().chain(self.outputs()) {
                    validate_dtype(desc, ty, allow_f16)?;
                }
                if self.inputs[0].data_type != self.output.data_type {
                    return Err(DmlError::invalid(
                        "mean variance normalization input and output DataTypes must match",
                    ));
                }
            }
            DmlOpKind::Adam { .. } => {
                for desc in &self.inputs[..4] {
                    expect_dtype(desc, &[DML_TENSOR_DATA_TYPE_FLOAT32], ty, "Adam")?;
                }
                expect_dtype(
                    &self.inputs[4],
                    &[DML_TENSOR_DATA_TYPE_UINT32, DML_TENSOR_DATA_TYPE_INT32],
                    ty,
                    "training step",
                )?;
                for output in self.outputs() {
                    expect_dtype(output, &[DML_TENSOR_DATA_TYPE_FLOAT32], ty, "Adam output")?;
                }
            }
            DmlOpKind::QuantizeLinear => {
                expect_dtype(
                    &self.inputs[0],
                    &[DML_TENSOR_DATA_TYPE_FLOAT32],
                    ty,
                    "input",
                )?;
                expect_dtype(
                    &self.inputs[1],
                    &[DML_TENSOR_DATA_TYPE_FLOAT32],
                    ty,
                    "scale",
                )?;
                expect_dtype(
                    &self.output,
                    &[
                        DML_TENSOR_DATA_TYPE_UINT8,
                        DML_TENSOR_DATA_TYPE_INT8,
                        DML_TENSOR_DATA_TYPE_UINT4,
                        DML_TENSOR_DATA_TYPE_INT4,
                    ],
                    ty,
                    "output",
                )?;
                if self.inputs.len() == 3 {
                    expect_dtype(
                        &self.inputs[2],
                        &[
                            DML_TENSOR_DATA_TYPE_UINT8,
                            DML_TENSOR_DATA_TYPE_INT8,
                            DML_TENSOR_DATA_TYPE_UINT4,
                            DML_TENSOR_DATA_TYPE_INT4,
                        ],
                        ty,
                        "zero point",
                    )?;
                    if self.inputs[2].data_type != self.output.data_type {
                        return Err(DmlError::invalid(
                            "quantize zero point and output DataTypes must match",
                        ));
                    }
                } else if self.output.data_type != DML_TENSOR_DATA_TYPE_UINT8
                    && self.output.data_type != DML_TENSOR_DATA_TYPE_UINT4
                {
                    return Err(DmlError::invalid(
                        "quantize without a zero point tensor must produce UINT8 or UINT4",
                    ));
                }
            }
            DmlOpKind::DequantizeLinear => {
                expect_dtype(
                    &self.inputs[0],
                    &[
                        DML_TENSOR_DATA_TYPE_UINT8,
                        DML_TENSOR_DATA_TYPE_INT8,
                        DML_TENSOR_DATA_TYPE_UINT4,
                        DML_TENSOR_DATA_TYPE_INT4,
                    ],
                    ty,
                    "input",
                )?;
                expect_dtype(
                    &self.inputs[1],
                    &[DML_TENSOR_DATA_TYPE_FLOAT32],
                    ty,
                    "scale",
                )?;
                if self.inputs.len() == 3 {
                    expect_dtype(
                        &self.inputs[2],
                        &[
                            DML_TENSOR_DATA_TYPE_UINT8,
                            DML_TENSOR_DATA_TYPE_INT8,
                            DML_TENSOR_DATA_TYPE_UINT4,
                            DML_TENSOR_DATA_TYPE_INT4,
                        ],
                        ty,
                        "zero point",
                    )?;
                }
                expect_dtype(&self.output, &[DML_TENSOR_DATA_TYPE_FLOAT32], ty, "output")?;
            }
            DmlOpKind::DynamicQuantizeLinear => {
                expect_dtype(
                    &self.inputs[0],
                    &[DML_TENSOR_DATA_TYPE_FLOAT32],
                    ty,
                    "input",
                )?;
                expect_dtype(&self.output, &[DML_TENSOR_DATA_TYPE_UINT8], ty, "output")?;
                if self.extra_outputs.len() != 2 {
                    return Err(DmlError::invalid(
                        "dynamic quantize requires scale and zero point outputs",
                    ));
                }
                expect_dtype(
                    &self.extra_outputs[0],
                    &[DML_TENSOR_DATA_TYPE_FLOAT32],
                    ty,
                    "scale output",
                )?;
                expect_dtype(
                    &self.extra_outputs[1],
                    &[DML_TENSOR_DATA_TYPE_UINT8],
                    ty,
                    "zero point output",
                )?;
            }
            DmlOpKind::QuantizedLinearAdd { .. } => {
                self.validate_quantized_dtypes(ty, 2)?;
                self.require_scalar_quantization_tensors()?;
                let a = &self.inputs[0];
                let b_index = quantized_input_index(self, "B").expect("B");
                expect_same_dtype(&self.inputs[b_index], a.data_type, ty, "quantized add B")?;
                expect_same_dtype(&self.output, a.data_type, ty, "quantized add output")?;
                if !matches!(
                    a.data_type,
                    DML_TENSOR_DATA_TYPE_UINT8 | DML_TENSOR_DATA_TYPE_INT8
                ) {
                    return Err(DmlError::invalid(
                        "quantized linear add inputs must be UINT8 or INT8",
                    ));
                }
                for index in [
                    quantized_input_index(self, "A zero point"),
                    quantized_input_index(self, "B zero point"),
                    quantized_input_index(self, "output zero point"),
                ]
                .into_iter()
                .flatten()
                {
                    expect_same_dtype(
                        &self.inputs[index],
                        a.data_type,
                        ty,
                        "quantized add zero point",
                    )?;
                }
                for index in [
                    quantized_input_index(self, "A scale"),
                    quantized_input_index(self, "B scale"),
                    quantized_input_index(self, "output scale"),
                ]
                .into_iter()
                .flatten()
                {
                    expect_dtype(
                        &self.inputs[index],
                        &[DML_TENSOR_DATA_TYPE_FLOAT32],
                        ty,
                        "quantized add scale",
                    )?;
                }
            }
            DmlOpKind::MatrixMultiplyInteger {
                quantized_output, ..
            } => {
                self.validate_quantized_dtypes(ty, 1)?;
                self.require_scalar_quantization_tensors()?;
                let a = &self.inputs[0];
                let b_index = quantized_input_index(self, "B").expect("B");
                expect_same_dtype(
                    &self.inputs[b_index],
                    a.data_type,
                    ty,
                    "integer matrix multiply B",
                )?;
                if !matches!(
                    a.data_type,
                    DML_TENSOR_DATA_TYPE_UINT8 | DML_TENSOR_DATA_TYPE_INT8
                ) {
                    return Err(DmlError::invalid(
                        "integer matrix multiply inputs must be UINT8 or INT8",
                    ));
                }
                for index in [
                    quantized_input_index(self, "A zero point"),
                    quantized_input_index(self, "B zero point"),
                ]
                .into_iter()
                .flatten()
                {
                    expect_same_dtype(
                        &self.inputs[index],
                        a.data_type,
                        ty,
                        "integer matrix multiply zero point",
                    )?;
                }
                for index in [
                    quantized_input_index(self, "A scale"),
                    quantized_input_index(self, "B scale"),
                    quantized_input_index(self, "output scale"),
                ]
                .into_iter()
                .flatten()
                {
                    expect_dtype(
                        &self.inputs[index],
                        &[DML_TENSOR_DATA_TYPE_FLOAT32],
                        ty,
                        "integer matrix multiply scale",
                    )?;
                }
                if *quantized_output {
                    expect_dtype(
                        &self.output,
                        &[DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_INT8],
                        ty,
                        "output",
                    )?;
                } else {
                    expect_dtype(&self.output, &[DML_TENSOR_DATA_TYPE_INT32], ty, "output")?;
                }
            }
            DmlOpKind::ConvolutionInteger {
                quantized_output, ..
            } => {
                self.require_scalar_quantization_tensors()?;
                let input_dtype = self.inputs[0].data_type;
                let filter_index = quantized_input_index(self, "filter").expect("filter");
                expect_same_dtype(
                    &self.inputs[filter_index],
                    input_dtype,
                    ty,
                    "integer convolution filter",
                )?;
                for desc in [&self.inputs[0], &self.inputs[filter_index]] {
                    expect_dtype(
                        desc,
                        &[DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_INT8],
                        ty,
                        "convolution integer",
                    )?;
                }
                for index in [
                    quantized_input_index(self, "input zero point"),
                    quantized_input_index(self, "filter zero point"),
                    quantized_input_index(self, "output zero point"),
                ]
                .into_iter()
                .flatten()
                {
                    expect_same_dtype(
                        &self.inputs[index],
                        input_dtype,
                        ty,
                        "integer convolution zero point",
                    )?;
                }
                for index in [
                    quantized_input_index(self, "input scale"),
                    quantized_input_index(self, "filter scale"),
                    quantized_input_index(self, "output scale"),
                ]
                .into_iter()
                .flatten()
                {
                    expect_dtype(
                        &self.inputs[index],
                        &[DML_TENSOR_DATA_TYPE_FLOAT32],
                        ty,
                        "integer convolution scale",
                    )?;
                }
                if let Some(index) = quantized_input_index(self, "bias") {
                    expect_dtype(
                        &self.inputs[index],
                        &[DML_TENSOR_DATA_TYPE_FLOAT32],
                        ty,
                        "integer convolution bias",
                    )?;
                }
                if *quantized_output {
                    expect_same_dtype(&self.output, input_dtype, ty, "integer convolution output")?;
                }
                if *quantized_output {
                    expect_dtype(
                        &self.output,
                        &[DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_INT8],
                        ty,
                        "output",
                    )?;
                } else {
                    expect_dtype(&self.output, &[DML_TENSOR_DATA_TYPE_INT32], ty, "output")?;
                }
            }
            DmlOpKind::QuantizedLinearAveragePooling { .. } => {
                self.require_scalar_quantization_tensors()?;
                expect_dtype(
                    &self.inputs[0],
                    &[DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_INT8],
                    ty,
                    "input",
                )?;
                expect_same_dtype(
                    &self.output,
                    self.inputs[0].data_type,
                    ty,
                    "quantized average pooling output",
                )?;
                for index in [
                    quantized_input_index(self, "input zero point"),
                    quantized_input_index(self, "output zero point"),
                ]
                .into_iter()
                .flatten()
                {
                    expect_same_dtype(
                        &self.inputs[index],
                        self.inputs[0].data_type,
                        ty,
                        "quantized average pooling zero point",
                    )?;
                }
            }
            DmlOpKind::MatrixMultiplyIntegerToFloat { .. } => {
                let b_index = self
                    .input_roles()
                    .iter()
                    .position(|role| *role == "B")
                    .expect("matrix multiply B role");
                for desc in [&self.inputs[0], &self.inputs[b_index]] {
                    expect_dtype(
                        desc,
                        &[DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_INT8],
                        ty,
                        "matrix multiply",
                    )?;
                }
                expect_dtype(&self.output, &[DML_TENSOR_DATA_TYPE_FLOAT32], ty, "output")?;
            }
            DmlOpKind::Quantize { .. } | DmlOpKind::Dequantize { .. } => {
                let quantizing = matches!(self.kind, DmlOpKind::Quantize { .. });
                if quantizing {
                    expect_dtype(
                        &self.inputs[0],
                        &[DML_TENSOR_DATA_TYPE_FLOAT32],
                        ty,
                        "input",
                    )?;
                    expect_dtype(
                        &self.output,
                        &[
                            DML_TENSOR_DATA_TYPE_UINT8,
                            DML_TENSOR_DATA_TYPE_INT8,
                            DML_TENSOR_DATA_TYPE_UINT4,
                            DML_TENSOR_DATA_TYPE_INT4,
                        ],
                        ty,
                        "output",
                    )?;
                } else {
                    expect_dtype(
                        &self.inputs[0],
                        &[
                            DML_TENSOR_DATA_TYPE_UINT8,
                            DML_TENSOR_DATA_TYPE_INT8,
                            DML_TENSOR_DATA_TYPE_UINT4,
                            DML_TENSOR_DATA_TYPE_INT4,
                        ],
                        ty,
                        "input",
                    )?;
                    expect_dtype(&self.output, &[DML_TENSOR_DATA_TYPE_FLOAT32], ty, "output")?;
                }
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> DmlResult<()> {
        let ty = self.operator_type();
        if self.inputs.is_empty()
            && !matches!(
                self.kind,
                DmlOpKind::Fill { .. }
                    | DmlOpKind::DiagonalMatrix { .. }
                    | DmlOpKind::DiagonalMatrix1 { .. }
            )
        {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} requires at least one input tensor"
            )));
        }
        for desc in &self.inputs {
            validate_layout(desc, ty)?;
        }
        for desc in self.outputs() {
            validate_layout(desc, ty)?;
            if desc.strides.contains(&0) {
                return Err(DmlError::invalid("output tensor strides must be non-zero"));
            }
        }
        self.validate_dtypes()?;
        if let Some(activation) = self.fused_activation {
            if !self.kind.supports_fused_activation() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} does not support a fused activation"
                )));
            }
            activation.validate(activation.operator_type())?;
            if activation.operator_type() == DML_OPERATOR_ACTIVATION_SOFTMAX {
                return Err(DmlError::invalid(
                    "softmax cannot be used as a fused activation",
                ));
            }
        }
        match &self.kind {
            DmlOpKind::Gemm {
                trans_a,
                trans_b,
                beta,
                ..
            } => self.validate_gemm(*trans_a, *trans_b, *beta),
            DmlOpKind::Convolution {
                mode,
                strides,
                dilations,
                start_padding,
                end_padding,
                output_padding,
                group_count,
            } => self.validate_convolution(
                *mode,
                strides,
                dilations,
                start_padding,
                end_padding,
                output_padding,
                *group_count,
            ),
            DmlOpKind::Pooling {
                strides,
                window,
                start_padding,
                end_padding,
                ..
            } => self.validate_pooling(strides, window, start_padding, end_padding),
            DmlOpKind::AveragePooling1 {
                strides,
                window,
                start_padding,
                end_padding,
                dilations,
                include_padding,
            } => self.validate_average_pooling1(
                strides,
                window,
                start_padding,
                end_padding,
                dilations,
                *include_padding,
            ),
            DmlOpKind::Activation { .. } => {
                self.require_input_count(1)?;
                if self.inputs[0].sizes != self.output.sizes {
                    return Err(DmlError::invalid(
                        "activation input and output sizes must match",
                    ));
                }
                Ok(())
            }
            DmlOpKind::BatchNormalization { spatial, epsilon } => {
                self.validate_batch_normalization(*spatial, *epsilon)
            }
            DmlOpKind::Softmax => {
                self.require_input_count(1)?;
                if self.inputs[0].sizes != self.output.sizes {
                    return Err(DmlError::invalid(
                        "softmax input and output sizes must match",
                    ));
                }
                Ok(())
            }
            DmlOpKind::Binary { .. } => self.validate_binary(),
            DmlOpKind::Reduce { reduce, axes } => self.validate_reduce(*reduce, axes),
            DmlOpKind::Reshape => {
                self.require_input_count(1)?;
                let input_count = checked_product(&self.inputs[0].sizes)?;
                let output_count = checked_product(&self.output.sizes)?;
                if input_count != output_count {
                    return Err(DmlError::invalid(format!(
                        "reshape input and output element counts differ: {input_count} != {output_count}"
                    )));
                }
                Ok(())
            }
            DmlOpKind::Transpose { permutation } => self.validate_transpose(permutation),
            DmlOpKind::Concat { axis } => self.validate_concat(*axis),
            DmlOpKind::Slice {
                offsets,
                sizes,
                strides,
            } => self.validate_slice(offsets, sizes, strides),
            DmlOpKind::Add1 => self.validate_binary(),
            DmlOpKind::Rnn {
                direction,
                activations,
                options,
                outputs,
            } => self.validate_recurrent(
                DML_OPERATOR_RNN,
                *direction,
                activations,
                *options,
                outputs,
                1,
            ),
            DmlOpKind::Gru {
                direction,
                activations,
                options,
                outputs,
                linear_before_reset,
            } => {
                let _ = linear_before_reset;
                self.validate_recurrent(
                    DML_OPERATOR_GRU,
                    *direction,
                    activations,
                    *options,
                    outputs,
                    3,
                )
            }
            DmlOpKind::Lstm {
                direction,
                activations,
                options,
                outputs,
                clip_threshold,
                use_clip_threshold,
                couple_input_forget,
            } => {
                if *use_clip_threshold && (!clip_threshold.is_finite() || *clip_threshold <= 0.0) {
                    return Err(DmlError::invalid(
                        "LSTM clip threshold must be finite and positive when enabled",
                    ));
                }
                if *couple_input_forget {
                    // Supported by the forward implementation; validated for shape.
                }
                self.validate_recurrent(
                    DML_OPERATOR_LSTM,
                    *direction,
                    activations,
                    *options,
                    outputs,
                    4,
                )
            }
            DmlOpKind::ArgMin { axes, direction } | DmlOpKind::ArgMax { axes, direction } => {
                self.validate_arg_reduce(axes, *direction)
            }
            DmlOpKind::Padding {
                mode,
                start_padding,
                end_padding,
                value,
            } => self.validate_padding(*mode, start_padding, end_padding, *value),
            DmlOpKind::Resample {
                mode,
                scales,
                input_offsets,
                output_offsets,
                antialiased,
                ..
            } => self.validate_resample(*mode, scales, input_offsets, output_offsets, *antialiased),
            DmlOpKind::TopK { axis, k, direction } => self.validate_top_k(*axis, *k, *direction),
            DmlOpKind::Tile { repeats } => self.validate_tile(repeats),
            DmlOpKind::Split { axis } => self.validate_split(*axis),
            DmlOpKind::Gather {
                axis,
                index_dimensions,
            } => self.validate_gather(*axis, *index_dimensions),
            DmlOpKind::GatherElements { axis } => self.validate_gather_elements(*axis),
            DmlOpKind::GatherNd {
                input_dimension_count,
                indices_dimension_count,
                batch_dimension_count,
            } => self.validate_gather_nd(
                *input_dimension_count,
                *indices_dimension_count,
                *batch_dimension_count,
            ),
            DmlOpKind::Scatter { axis } => self.validate_scatter(*axis),
            DmlOpKind::ScatterNd {
                input_dimension_count,
                indices_dimension_count,
            } => self.validate_scatter_nd(*input_dimension_count, *indices_dimension_count),
            DmlOpKind::RoiPooling {
                spatial_scale,
                pooled,
            } => self.validate_roi_pooling(*spatial_scale, pooled),
            DmlOpKind::RoiAlign {
                reduction,
                mode,
                spatial_scale_x,
                spatial_scale_y,
                input_pixel_offset,
                output_pixel_offset,
                out_of_bounds_value,
                minimum_samples_per_output,
                maximum_samples_per_output,
                align_regions_to_corners,
            } => self.validate_roi_align(
                *reduction,
                *mode,
                *spatial_scale_x,
                *spatial_scale_y,
                *input_pixel_offset,
                *output_pixel_offset,
                *out_of_bounds_value,
                *minimum_samples_per_output,
                *maximum_samples_per_output,
                *align_regions_to_corners,
            ),
            DmlOpKind::LocalResponseNormalization {
                cross_channel,
                local_size,
                alpha,
                beta,
                bias,
            } => self.validate_lrn(*cross_channel, *local_size, *alpha, *beta, *bias),
            DmlOpKind::MeanVarianceNormalization {
                axes,
                normalize_variance,
                use_mean,
                epsilon,
            } => self.validate_mvn(axes, *normalize_variance, *use_mean, *epsilon),
            DmlOpKind::Adam {
                learning_rate,
                beta1,
                beta2,
                epsilon,
            } => self.validate_adam(*learning_rate, *beta1, *beta2, *epsilon),
            DmlOpKind::QuantizeLinear | DmlOpKind::DequantizeLinear => {
                self.validate_quantize_linear()
            }
            DmlOpKind::DynamicQuantizeLinear => self.validate_dynamic_quantize(),
            DmlOpKind::QuantizedLinearAdd { .. } => self.validate_quantized_add(),
            DmlOpKind::MatrixMultiplyInteger {
                quantized_output, ..
            } => self.validate_matmul_integer(*quantized_output),
            DmlOpKind::ConvolutionInteger {
                strides,
                dilations,
                start_padding,
                end_padding,
                group_count,
                quantized_output,
                ..
            } => self.validate_convolution_integer(
                strides,
                dilations,
                start_padding,
                end_padding,
                *group_count,
                *quantized_output,
            ),
            DmlOpKind::QuantizedLinearAveragePooling {
                strides,
                window,
                start_padding,
                end_padding,
                dilations,
                include_padding,
                ..
            } => self.validate_quantized_avg_pool(
                strides,
                window,
                start_padding,
                end_padding,
                dilations,
                *include_padding,
            ),
            DmlOpKind::MatrixMultiplyIntegerToFloat { .. } => self.validate_mmi_to_float(),
            DmlOpKind::Quantize { quantization_type }
            | DmlOpKind::Dequantize { quantization_type } => {
                self.validate_quantize(*quantization_type)
            }
            DmlOpKind::Unary { op } => self.validate_unary(*op),
            DmlOpKind::Fill { value, step, .. } => {
                if self.inputs.is_empty() && !value.is_finite() {
                    return Err(DmlError::invalid("fill value must be finite"));
                }
                if !step.is_finite() {
                    return Err(DmlError::invalid("fill sequence step must be finite"));
                }
                Ok(())
            }
            DmlOpKind::OneHot { axis } => self.validate_one_hot(*axis),
            DmlOpKind::Cumulative { axis, .. } => self.validate_cumulative(*axis),
            DmlOpKind::Reverse { axis } => self.validate_reverse(*axis),
            DmlOpKind::DiagonalMatrix { offset, value } => {
                if !value.is_finite() {
                    return Err(DmlError::invalid("diagonal matrix value must be finite"));
                }
                if self.output.sizes.len() != 2 {
                    return Err(DmlError::invalid("diagonal matrix output must be rank-2"));
                }
                let (rows, columns) = (self.output.sizes[0] as i64, self.output.sizes[1] as i64);
                if i64::from(*offset) >= columns || i64::from(*offset) <= -rows {
                    return Err(DmlError::invalid(format!(
                        "diagonal matrix offset {offset} lies outside the {rows}x{columns} output"
                    )));
                }
                Ok(())
            }
            DmlOpKind::Cast => {
                self.require_input_count(1)?;
                let input = &self.inputs[0];
                if checked_product(&input.sizes)? != checked_product(&self.output.sizes)? {
                    return Err(DmlError::invalid(
                        "cast input and output element counts must match",
                    ));
                }
                Ok(())
            }
            DmlOpKind::SoftmaxEx { kind, axes } => self.validate_softmax_ex(*kind, axes),
            DmlOpKind::ExActivation { activation } => self.validate_ex_activation(*activation),
            DmlOpKind::If => self.validate_if(),
            DmlOpKind::BitNot => self.validate_bitwise(false),
            DmlOpKind::BitCount => self.validate_bitwise(true),
            DmlOpKind::LpPooling {
                p,
                strides,
                window,
                start_padding,
                end_padding,
                dilations,
                ..
            } => {
                self.validate_lp_pooling(*p, strides, window, start_padding, end_padding, dilations)
            }
            DmlOpKind::LpNormalization { axis, epsilon, p } => {
                self.validate_lp_normalization(*axis, *epsilon, *p)
            }
            DmlOpKind::ValueScale2D {
                scale,
                channel_count,
                bias,
            } => self.validate_value_scale(*scale, *channel_count, bias),
            DmlOpKind::SpaceDepth {
                to_depth,
                block_size,
                order,
                ..
            } => self.validate_space_depth(*to_depth, *block_size, *order),
            DmlOpKind::MaxPoolingEx {
                strides,
                window,
                start_padding,
                end_padding,
                dilations,
                has_indices,
                dilations_supported,
            } => self.validate_max_pooling_ex(
                strides,
                window,
                start_padding,
                end_padding,
                dilations,
                *has_indices,
                *dilations_supported,
            ),
            DmlOpKind::MaxUnpooling => self.validate_max_unpooling(),
            DmlOpKind::SliceEx {
                offsets,
                sizes,
                strides,
            } => self.validate_slice_ex(offsets, sizes, strides),
            DmlOpKind::Clip1 {
                min,
                max,
                scale,
                bias,
                has_scale_bias,
            } => self.validate_clip1(*min, *max, *scale, *bias, *has_scale_bias),
            DmlOpKind::ReluGrad => self.validate_elementwise_grad("RELU"),
            DmlOpKind::AveragePoolingGrad {
                strides,
                window,
                start_padding,
                end_padding,
                include_padding,
            } => self.validate_avg_pool_grad(
                strides,
                window,
                start_padding,
                end_padding,
                *include_padding,
            ),
            DmlOpKind::MaxPoolingGrad {
                strides,
                window,
                start_padding,
                end_padding,
                dilations,
            } => {
                self.validate_max_pool_grad(strides, window, start_padding, end_padding, dilations)
            }
            DmlOpKind::ResampleGrad {
                mode,
                rounding,
                scales,
                input_offsets,
                output_offsets,
                ..
            } => {
                self.validate_resample_grad(*mode, *rounding, scales, input_offsets, output_offsets)
            }
            DmlOpKind::SliceGrad {
                offsets,
                sizes,
                strides,
            } => self.validate_slice_grad(offsets, sizes, strides),
            DmlOpKind::ClipGrad { min, max, .. } => self.validate_clip_grad(*min, *max),
            DmlOpKind::LrnGrad {
                cross_channel,
                local_size,
                alpha,
                beta,
                bias,
            } => self.validate_lrn_grad(*cross_channel, *local_size, *alpha, *beta, *bias),
            DmlOpKind::BatchNormalizationGrad { epsilon } => self.validate_bn_grad(*epsilon, false),
            DmlOpKind::BatchNormalizationTraining { epsilon } => {
                self.validate_bn_training(*epsilon, false)
            }
            DmlOpKind::BatchNormalizationTrainingGrad { epsilon } => {
                self.validate_bn_grad(*epsilon, true)
            }
            DmlOpKind::RoiAlignGrad {
                reduction,
                mode,
                spatial_scale_x,
                spatial_scale_y,
                input_pixel_offset,
                output_pixel_offset,
                minimum_samples_per_output,
                maximum_samples_per_output,
                align_regions_to_corners,
            } => self.validate_roi_align_grad(
                *reduction,
                *mode,
                *spatial_scale_x,
                *spatial_scale_y,
                *input_pixel_offset,
                *output_pixel_offset,
                *minimum_samples_per_output,
                *maximum_samples_per_output,
                *align_regions_to_corners,
            ),
            DmlOpKind::RandomGenerator { generator_type } => {
                self.validate_random_generator(*generator_type)
            }
            DmlOpKind::NonZeroCoordinates => self.validate_nonzero(),
            DmlOpKind::DiagonalMatrix1 {
                offset_begin,
                offset_end,
                value,
            } => self.validate_diagonal1(*offset_begin, *offset_end, *value),
            DmlOpKind::MultiHeadAttention {
                scale,
                mask_filter_value,
                query_head_count,
                key_value_head_count,
                mask_type,
                layout,
                has_bias,
                has_mask,
                ..
            } => self.validate_mha(
                *scale,
                *mask_filter_value,
                *query_head_count,
                *key_value_head_count,
                *mask_type,
                *layout,
                *has_bias,
                *has_mask,
            ),
        }
    }

    pub(crate) fn require_input_count(&self, expected: usize) -> DmlResult<()> {
        if self.inputs.len() != expected {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} requires {expected} input tensor(s), got {}",
                self.operator_type(),
                self.inputs.len()
            )));
        }
        Ok(())
    }
}

pub fn emit_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    plan.validate()?;
    let mut source = match &plan.kind {
        DmlOpKind::Gemm {
            trans_a,
            trans_b,
            alpha,
            beta,
        } => emit_gemm_msl(plan, *trans_a, *trans_b, *alpha, *beta),
        DmlOpKind::Convolution {
            mode,
            strides,
            dilations,
            start_padding,
            group_count,
            ..
        } => emit_convolution_msl(plan, *mode, strides, dilations, start_padding, *group_count),
        DmlOpKind::AveragePooling1 {
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            include_padding,
        } => emit_average_pooling1_msl(
            plan,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            *include_padding,
        ),
        DmlOpKind::Pooling {
            kind,
            strides,
            window,
            start_padding,
            include_padding,
            ..
        } => emit_pooling_msl(
            plan,
            *kind,
            strides,
            window,
            start_padding,
            *include_padding,
        ),
        DmlOpKind::Activation { activation, alpha } => {
            emit_activation_msl(plan, *activation, *alpha)
        }
        DmlOpKind::BatchNormalization { spatial, epsilon } => {
            emit_batch_normalization_msl(plan, *spatial, *epsilon)
        }
        DmlOpKind::Softmax => emit_softmax_msl(plan),
        DmlOpKind::Binary { op } => emit_elementwise_msl(plan, *op),
        DmlOpKind::Add1 => emit_elementwise_msl(plan, DmlBinaryOp::Add),
        DmlOpKind::Reduce { reduce, axes } => emit_reduce_msl(plan, *reduce, axes),
        DmlOpKind::Reshape => emit_reshape_msl(plan),
        DmlOpKind::Transpose { permutation } => emit_transpose_msl(plan, permutation),
        DmlOpKind::Concat { axis } => emit_concat_msl(plan, *axis),
        DmlOpKind::Slice {
            offsets,
            sizes,
            strides,
        } => emit_slice_msl(plan, offsets, sizes, strides),
        DmlOpKind::Rnn {
            direction,
            activations,
            options,
            outputs,
        } => emit_recurrent_msl(
            plan,
            DML_OPERATOR_RNN,
            *direction,
            activations,
            *options,
            outputs,
            RecurrentExtras::default(),
        ),
        DmlOpKind::Gru {
            direction,
            activations,
            options,
            outputs,
            linear_before_reset,
        } => emit_recurrent_msl(
            plan,
            DML_OPERATOR_GRU,
            *direction,
            activations,
            *options,
            outputs,
            RecurrentExtras {
                linear_before_reset: *linear_before_reset,
                ..RecurrentExtras::default()
            },
        ),
        DmlOpKind::Lstm {
            direction,
            activations,
            options,
            outputs,
            clip_threshold,
            use_clip_threshold,
            couple_input_forget,
        } => emit_recurrent_msl(
            plan,
            DML_OPERATOR_LSTM,
            *direction,
            activations,
            *options,
            outputs,
            RecurrentExtras {
                clip_threshold: *clip_threshold,
                use_clip_threshold: *use_clip_threshold,
                couple_input_forget: *couple_input_forget,
                ..RecurrentExtras::default()
            },
        ),
        DmlOpKind::ArgMin { axes, direction } => emit_arg_reduce_msl(plan, axes, *direction, true),
        DmlOpKind::ArgMax { axes, direction } => emit_arg_reduce_msl(plan, axes, *direction, false),
        DmlOpKind::Padding {
            mode,
            start_padding,
            end_padding,
            value,
        } => emit_padding_msl(plan, *mode, start_padding, end_padding, *value),
        DmlOpKind::Resample {
            mode,
            scales,
            input_offsets,
            output_offsets,
            rounding,
            antialiased,
        } => emit_resample_msl(
            plan,
            *mode,
            scales,
            input_offsets,
            output_offsets,
            *rounding,
            *antialiased,
        ),
        DmlOpKind::TopK { axis, k, direction } => emit_top_k_msl(plan, *axis, *k, *direction),
        DmlOpKind::Tile { repeats } => emit_tile_msl(plan, repeats),
        DmlOpKind::Split { axis } => emit_split_msl(plan, *axis),
        DmlOpKind::Gather {
            axis,
            index_dimensions,
        } => emit_gather_msl(plan, *axis, *index_dimensions),
        DmlOpKind::GatherElements { axis } => emit_gather_elements_msl(plan, *axis),
        DmlOpKind::GatherNd {
            input_dimension_count,
            indices_dimension_count,
            batch_dimension_count,
        } => emit_gather_nd_msl(
            plan,
            *input_dimension_count,
            *indices_dimension_count,
            *batch_dimension_count,
        ),
        DmlOpKind::Scatter { axis } => emit_scatter_msl(plan, *axis),
        DmlOpKind::ScatterNd {
            input_dimension_count,
            indices_dimension_count,
        } => emit_scatter_nd_msl(plan, *input_dimension_count, *indices_dimension_count),
        DmlOpKind::RoiPooling {
            spatial_scale,
            pooled,
        } => emit_roi_pooling_msl(plan, *spatial_scale, pooled),
        DmlOpKind::RoiAlign {
            reduction,
            mode,
            spatial_scale_x,
            spatial_scale_y,
            input_pixel_offset,
            output_pixel_offset,
            out_of_bounds_value,
            minimum_samples_per_output,
            maximum_samples_per_output,
            align_regions_to_corners,
        } => emit_roi_align_msl(
            plan,
            *reduction,
            *mode,
            *spatial_scale_x,
            *spatial_scale_y,
            *input_pixel_offset,
            *output_pixel_offset,
            *out_of_bounds_value,
            *minimum_samples_per_output,
            *maximum_samples_per_output,
            *align_regions_to_corners,
        ),
        DmlOpKind::LocalResponseNormalization {
            cross_channel,
            local_size,
            alpha,
            beta,
            bias,
        } => emit_lrn_msl(plan, *cross_channel, *local_size, *alpha, *beta, *bias),
        DmlOpKind::MeanVarianceNormalization {
            axes,
            normalize_variance,
            use_mean,
            epsilon,
        } => emit_mvn_msl(plan, axes, *normalize_variance, *use_mean, *epsilon),
        DmlOpKind::Adam {
            learning_rate,
            beta1,
            beta2,
            epsilon,
        } => emit_adam_msl(plan, *learning_rate, *beta1, *beta2, *epsilon),
        DmlOpKind::QuantizeLinear => emit_quantize_linear_msl(plan, false),
        DmlOpKind::DequantizeLinear => emit_quantize_linear_msl(plan, true),
        DmlOpKind::DynamicQuantizeLinear => emit_dynamic_quantize_msl(plan),
        DmlOpKind::QuantizedLinearAdd { .. } => emit_quantized_add_msl(plan),
        DmlOpKind::MatrixMultiplyInteger { .. } => emit_integer_matmul_msl(plan),
        DmlOpKind::ConvolutionInteger { .. } => emit_integer_convolution_msl(plan),
        DmlOpKind::QuantizedLinearAveragePooling { .. } => emit_quantized_avg_pool_msl(plan),
        DmlOpKind::MatrixMultiplyIntegerToFloat { .. } => emit_integer_matmul_to_float_msl(plan),
        DmlOpKind::Quantize { quantization_type } => {
            emit_generic_quantize_msl(plan, *quantization_type, false)
        }
        DmlOpKind::Dequantize { quantization_type } => {
            emit_generic_quantize_msl(plan, *quantization_type, true)
        }
        DmlOpKind::Unary { op } => emit_unary_msl(plan, *op),
        DmlOpKind::Fill {
            value,
            step,
            sequence,
        } => emit_fill_msl(plan, *value, *step, *sequence),
        DmlOpKind::OneHot { axis } => emit_one_hot_msl(plan, *axis),
        DmlOpKind::Cumulative {
            product,
            axis,
            reverse,
            exclusive,
        } => emit_cumulative_msl(plan, *product, *axis, *reverse, *exclusive),
        DmlOpKind::Reverse { axis } => emit_reverse_msl(plan, *axis),
        DmlOpKind::DiagonalMatrix { offset, value } => {
            emit_diagonal_matrix_msl(plan, *offset, *value)
        }
        DmlOpKind::SoftmaxEx { kind, axes } => emit_softmax_ex_msl(plan, *kind, axes),
        DmlOpKind::ExActivation { activation } => emit_ex_activation_msl(plan, *activation),
        DmlOpKind::If => emit_if_msl(plan),
        DmlOpKind::BitNot => emit_bitwise_msl(plan, false),
        DmlOpKind::BitCount => emit_bitwise_msl(plan, true),
        DmlOpKind::LpPooling {
            p,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            ..
        } => emit_lp_pooling_msl(
            plan,
            *p,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
        ),
        DmlOpKind::LpNormalization { axis, epsilon, p } => {
            emit_lp_normalization_msl(plan, *axis, *epsilon, *p)
        }
        DmlOpKind::ValueScale2D {
            scale,
            channel_count,
            bias,
        } => emit_value_scale_msl(plan, *scale, *channel_count, bias),
        DmlOpKind::SpaceDepth {
            to_depth,
            block_size,
            order,
            ..
        } => emit_space_depth_msl(plan, *to_depth, *block_size, *order),
        DmlOpKind::MaxPoolingEx {
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            has_indices,
            ..
        } => emit_max_pooling_ex_msl(
            plan,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            *has_indices,
        ),
        DmlOpKind::MaxUnpooling => emit_max_unpooling_msl(plan),
        DmlOpKind::SliceEx {
            offsets,
            sizes,
            strides,
        } => emit_slice_ex_msl(plan, offsets, sizes, strides),
        DmlOpKind::Clip1 {
            min,
            max,
            scale,
            bias,
            has_scale_bias,
        } => emit_clip1_msl(plan, *min, *max, *scale, *bias, *has_scale_bias),
        DmlOpKind::ReluGrad => emit_relu_grad_msl(plan),
        DmlOpKind::AveragePoolingGrad {
            strides,
            window,
            start_padding,
            end_padding,
            include_padding,
        } => emit_avg_pool_grad_msl(
            plan,
            strides,
            window,
            start_padding,
            end_padding,
            *include_padding,
        ),
        DmlOpKind::MaxPoolingGrad {
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
        } => emit_max_pool_grad_msl(plan, strides, window, start_padding, end_padding, dilations),
        DmlOpKind::ResampleGrad {
            mode,
            rounding,
            scales,
            input_offsets,
            output_offsets,
            ..
        } => emit_resample_grad_msl(
            plan,
            *mode,
            *rounding,
            scales,
            input_offsets,
            output_offsets,
        ),
        DmlOpKind::SliceGrad {
            offsets,
            sizes,
            strides,
        } => emit_slice_grad_msl(plan, offsets, sizes, strides),
        DmlOpKind::ClipGrad { min, max, .. } => emit_clip_grad_msl(plan, *min, *max),
        DmlOpKind::LrnGrad {
            cross_channel,
            local_size,
            alpha,
            beta,
            bias,
        } => emit_lrn_grad_msl(plan, *cross_channel, *local_size, *alpha, *beta, *bias),
        DmlOpKind::BatchNormalizationGrad { epsilon } => {
            emit_batch_normalization_grad_msl(plan, *epsilon)
        }
        DmlOpKind::BatchNormalizationTraining { epsilon } => {
            emit_batch_normalization_training_msl(plan, *epsilon)
        }
        DmlOpKind::BatchNormalizationTrainingGrad { epsilon } => {
            emit_batch_normalization_training_grad_msl(plan, *epsilon)
        }
        DmlOpKind::RoiAlignGrad {
            reduction,
            mode,
            spatial_scale_x,
            spatial_scale_y,
            input_pixel_offset,
            output_pixel_offset,
            minimum_samples_per_output,
            maximum_samples_per_output,
            align_regions_to_corners,
        } => emit_roi_align_grad_msl(
            plan,
            *reduction,
            *mode,
            *spatial_scale_x,
            *spatial_scale_y,
            *input_pixel_offset,
            *output_pixel_offset,
            *minimum_samples_per_output,
            *maximum_samples_per_output,
            *align_regions_to_corners,
        ),
        DmlOpKind::RandomGenerator { generator_type } => {
            emit_random_generator_msl(plan, *generator_type)
        }
        DmlOpKind::NonZeroCoordinates => emit_nonzero_msl(plan),
        DmlOpKind::DiagonalMatrix1 {
            offset_begin,
            offset_end,
            value,
        } => emit_diagonal1_msl(plan, *offset_begin, *offset_end, *value),
        DmlOpKind::MultiHeadAttention {
            scale,
            mask_filter_value,
            query_head_count,
            key_value_head_count,
            mask_type,
            has_bias,
            has_mask,
            ..
        } => emit_mha_msl(
            plan,
            *scale,
            *mask_filter_value,
            *query_head_count,
            *key_value_head_count,
            *mask_type,
            *has_bias,
            *has_mask,
        ),
        DmlOpKind::Cast => emit_cast_msl(plan),
    }?;
    if let Some(activation) = plan.fused_activation {
        let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
        inject_fused_activation(&mut source, scalar, activation);
    }
    Ok(source)
}

/// Whether a guest `DML_OPERATOR_TYPE` is parsed into a [`DmlOpPlan`].
///
/// The element-wise identity/abs/exp/... operators keep their dedicated
/// descriptor path; everything with a tensor graph in [`DmlOpKind`] is parsed
/// here so guest `IDMLDevice::CreateOperator` reaches the extended set.
pub fn is_extended_operator(ty: u32) -> bool {
    matches!(
        ty,
        DML_OPERATOR_ELEMENT_WISE_ACOS
            | DML_OPERATOR_ELEMENT_WISE_ASIN
            | DML_OPERATOR_ELEMENT_WISE_ATAN
            | DML_OPERATOR_ELEMENT_WISE_CLIP
            | DML_OPERATOR_ELEMENT_WISE_CONSTANT_POW
            | DML_OPERATOR_ELEMENT_WISE_RECIP
            | DML_OPERATOR_ELEMENT_WISE_THRESHOLD
            | DML_OPERATOR_ELEMENT_WISE_SIGN
            | DML_OPERATOR_ELEMENT_WISE_IS_NAN
            | DML_OPERATOR_ELEMENT_WISE_ERF
            | DML_OPERATOR_ELEMENT_WISE_SINH
            | DML_OPERATOR_ELEMENT_WISE_COSH
            | DML_OPERATOR_ELEMENT_WISE_TANH
            | DML_OPERATOR_ELEMENT_WISE_ASINH
            | DML_OPERATOR_ELEMENT_WISE_ACOSH
            | DML_OPERATOR_ELEMENT_WISE_ATANH
            | DML_OPERATOR_ELEMENT_WISE_LOGICAL_NOT
            | DML_OPERATOR_ELEMENT_WISE_ROUND
            | DML_OPERATOR_ELEMENT_WISE_IS_INFINITY
            | DML_OPERATOR_ELEMENT_WISE_NEGATE
            | DML_OPERATOR_ELEMENT_WISE_MODULUS_TRUNCATE
            | DML_OPERATOR_ELEMENT_WISE_MODULUS_FLOOR
            | DML_OPERATOR_ELEMENT_WISE_DIFFERENCE_SQUARE
            | DML_OPERATOR_ELEMENT_WISE_ATAN_YX
            | DML_OPERATOR_ELEMENT_WISE_MEAN
            | DML_OPERATOR_ELEMENT_WISE_LOGICAL_AND
            | DML_OPERATOR_ELEMENT_WISE_LOGICAL_OR
            | DML_OPERATOR_ELEMENT_WISE_LOGICAL_XOR
            | DML_OPERATOR_ELEMENT_WISE_LOGICAL_EQUALS
            | DML_OPERATOR_ELEMENT_WISE_LOGICAL_GREATER_THAN
            | DML_OPERATOR_ELEMENT_WISE_LOGICAL_LESS_THAN
            | DML_OPERATOR_ELEMENT_WISE_LOGICAL_GREATER_THAN_OR_EQUAL
            | DML_OPERATOR_ELEMENT_WISE_LOGICAL_LESS_THAN_OR_EQUAL
            | DML_OPERATOR_ELEMENT_WISE_BIT_AND
            | DML_OPERATOR_ELEMENT_WISE_BIT_OR
            | DML_OPERATOR_ELEMENT_WISE_BIT_XOR
            | DML_OPERATOR_ELEMENT_WISE_BIT_SHIFT_LEFT
            | DML_OPERATOR_ELEMENT_WISE_BIT_SHIFT_RIGHT
            | DML_OPERATOR_CAST
            | DML_OPERATOR_FILL_VALUE_CONSTANT
            | DML_OPERATOR_FILL_VALUE_SEQUENCE
            | DML_OPERATOR_ONE_HOT
            | DML_OPERATOR_CUMULATIVE_SUMMATION
            | DML_OPERATOR_CUMULATIVE_PRODUCT
            | DML_OPERATOR_REVERSE_SUBSEQUENCES
            | DML_OPERATOR_DIAGONAL_MATRIX
            | DML_OPERATOR_ELEMENT_WISE_QUANTIZE_LINEAR
            | DML_OPERATOR_ELEMENT_WISE_DEQUANTIZE_LINEAR
            | DML_OPERATOR_ACTIVATION_ELU
            | DML_OPERATOR_ACTIVATION_HARD_SIGMOID
            | DML_OPERATOR_ACTIVATION_IDENTITY
            | DML_OPERATOR_ACTIVATION_LEAKY_RELU
            | DML_OPERATOR_ACTIVATION_LINEAR
            | DML_OPERATOR_ACTIVATION_RELU
            | DML_OPERATOR_ACTIVATION_SCALED_TANH
            | DML_OPERATOR_ACTIVATION_SIGMOID
            | DML_OPERATOR_ACTIVATION_SOFTMAX
            | DML_OPERATOR_ACTIVATION_SOFTPLUS
            | DML_OPERATOR_ACTIVATION_SOFTSIGN
            | DML_OPERATOR_ACTIVATION_TANH
            | DML_OPERATOR_ACTIVATION_THRESHOLDED_RELU
            | DML_OPERATOR_CONVOLUTION
            | DML_OPERATOR_GEMM
            | DML_OPERATOR_REDUCE
            | DML_OPERATOR_AVERAGE_POOLING
            | DML_OPERATOR_MAX_POOLING
            | DML_OPERATOR_ROI_POOLING
            | DML_OPERATOR_SLICE
            | DML_OPERATOR_SPLIT
            | DML_OPERATOR_JOIN
            | DML_OPERATOR_PADDING
            | DML_OPERATOR_UPSAMPLE_2D
            | DML_OPERATOR_GATHER
            | DML_OPERATOR_TILE
            | DML_OPERATOR_TOP_K
            | DML_OPERATOR_BATCH_NORMALIZATION
            | DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION
            | DML_OPERATOR_LOCAL_RESPONSE_NORMALIZATION
            | DML_OPERATOR_RNN
            | DML_OPERATOR_LSTM
            | DML_OPERATOR_GRU
            | DML_OPERATOR_ELEMENT_WISE_ADD1
            | DML_OPERATOR_SCATTER
            | DML_OPERATOR_RESAMPLE
            | DML_OPERATOR_GATHER_ELEMENTS
            | DML_OPERATOR_GATHER_ND
            | DML_OPERATOR_SCATTER_ND
            | DML_OPERATOR_TOP_K1
            | DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION1
            | DML_OPERATOR_RESAMPLE1
            | DML_OPERATOR_MATRIX_MULTIPLY_INTEGER
            | DML_OPERATOR_QUANTIZED_LINEAR_MATRIX_MULTIPLY
            | DML_OPERATOR_CONVOLUTION_INTEGER
            | DML_OPERATOR_QUANTIZED_LINEAR_CONVOLUTION
            | DML_OPERATOR_ADAM_OPTIMIZER
            | DML_OPERATOR_ARGMIN
            | DML_OPERATOR_ARGMAX
            | DML_OPERATOR_ROI_ALIGN
            | DML_OPERATOR_GATHER_ND1
            | DML_OPERATOR_ELEMENT_WISE_QUANTIZED_LINEAR_ADD
            | DML_OPERATOR_DYNAMIC_QUANTIZE_LINEAR
            | DML_OPERATOR_ROI_ALIGN1
            | DML_OPERATOR_PADDING1
            | DML_OPERATOR_ACTIVATION_GELU
            | DML_OPERATOR_RESAMPLE2
            | DML_OPERATOR_ACTIVATION_SWISH
            | DML_OPERATOR_ACTIVATION_HARD_SWISH
            | DML_OPERATOR_QUANTIZED_LINEAR_AVERAGE_POOLING
            | DML_OPERATOR_MATRIX_MULTIPLY_INTEGER_TO_FLOAT
            | DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION2
            | DML_OPERATOR_QUANTIZE
            | DML_OPERATOR_DEQUANTIZE
            | DML_OPERATOR_ACTIVATION_HARDMAX
            | DML_OPERATOR_ACTIVATION_LOG_SOFTMAX
            | DML_OPERATOR_ACTIVATION_PARAMETERIZED_RELU
            | DML_OPERATOR_ACTIVATION_PARAMETRIC_SOFTPLUS
            | DML_OPERATOR_ACTIVATION_SCALED_ELU
            | DML_OPERATOR_ACTIVATION_SHRINK
            | DML_OPERATOR_ACTIVATION_CELU
            | DML_OPERATOR_ACTIVATION_RELU_GRAD
            | DML_OPERATOR_LP_POOLING
            | DML_OPERATOR_LP_POOLING1
            | DML_OPERATOR_LP_NORMALIZATION
            | DML_OPERATOR_VALUE_SCALE_2D
            | DML_OPERATOR_SPACE_TO_DEPTH
            | DML_OPERATOR_DEPTH_TO_SPACE
            | DML_OPERATOR_SPACE_TO_DEPTH1
            | DML_OPERATOR_DEPTH_TO_SPACE1
            | DML_OPERATOR_ELEMENT_WISE_IF
            | DML_OPERATOR_ELEMENT_WISE_BIT_NOT
            | DML_OPERATOR_ELEMENT_WISE_BIT_COUNT
            | DML_OPERATOR_MAX_POOLING1
            | DML_OPERATOR_MAX_POOLING2
            | DML_OPERATOR_MAX_UNPOOLING
            | DML_OPERATOR_SLICE1
            | DML_OPERATOR_ELEMENT_WISE_CLIP1
            | DML_OPERATOR_AVERAGE_POOLING_GRAD
            | DML_OPERATOR_MAX_POOLING_GRAD
            | DML_OPERATOR_RESAMPLE_GRAD
            | DML_OPERATOR_RESAMPLE_GRAD1
            | DML_OPERATOR_SLICE_GRAD
            | DML_OPERATOR_ELEMENT_WISE_CLIP_GRAD
            | DML_OPERATOR_ELEMENT_WISE_CLIP_GRAD1
            | DML_OPERATOR_LOCAL_RESPONSE_NORMALIZATION_GRAD
            | DML_OPERATOR_BATCH_NORMALIZATION_GRAD
            | DML_OPERATOR_BATCH_NORMALIZATION_TRAINING
            | DML_OPERATOR_BATCH_NORMALIZATION_TRAINING_GRAD
            | DML_OPERATOR_ROI_ALIGN_GRAD
            | DML_OPERATOR_RANDOM_GENERATOR
            | DML_OPERATOR_NONZERO_COORDINATES
            | DML_OPERATOR_DIAGONAL_MATRIX1
            | DML_OPERATOR_ACTIVATION_SOFTMAX1
            | DML_OPERATOR_ACTIVATION_LOG_SOFTMAX1
            | DML_OPERATOR_ACTIVATION_HARDMAX1
            | DML_OPERATOR_MULTIHEAD_ATTENTION
            | DML_OPERATOR_MULTIHEAD_ATTENTION1
            | DML_OPERATOR_AVERAGE_POOLING1
    )
}
