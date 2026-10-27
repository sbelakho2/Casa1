//! Extended DirectML operator set lowered to real Metal compute pipelines.
//!
//! `d3d12_directml` models the DirectML object surface; this module owns the
//! non-element-wise operator implementations. Every operator is described by
//! real DML tensor descriptors (sizes *and* strides), validated with checked
//! arithmetic, lowered to MSL, compiled into a Metal compute pipeline, and
//! dispatched with one buffer binding per tensor plus a readback buffer.
//!
//! A CPU execution path exists only for a device that was explicitly created
//! on [`DmlExecutionDevice::Cpu`]; a Metal device never silently falls back to
//! host math.

use super::{
    DML_TENSOR_DATA_TYPE_FLOAT16, DML_TENSOR_DATA_TYPE_FLOAT32, DML_TENSOR_DATA_TYPE_INT8,
    DML_TENSOR_DATA_TYPE_INT32, DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_UINT32,
    DML_TENSOR_MIN_ALIGNMENT, DmlError, DmlResult, DmlTensorDesc, E_FAIL,
};
use crate::metal_backend::MetalDevice;

pub const DML_OPERATOR_ELEMENT_WISE_QUANTIZE_LINEAR: u32 = 33;
pub const DML_OPERATOR_ELEMENT_WISE_DEQUANTIZE_LINEAR: u32 = 34;
pub const DML_OPERATOR_ACTIVATION_ELU: u32 = 35;
pub const DML_OPERATOR_ACTIVATION_HARD_SIGMOID: u32 = 37;
pub const DML_OPERATOR_ACTIVATION_IDENTITY: u32 = 38;
pub const DML_OPERATOR_ACTIVATION_LEAKY_RELU: u32 = 39;
pub const DML_OPERATOR_ACTIVATION_LINEAR: u32 = 40;
pub const DML_OPERATOR_ACTIVATION_RELU: u32 = 44;
pub const DML_OPERATOR_ACTIVATION_SCALED_TANH: u32 = 46;
pub const DML_OPERATOR_ACTIVATION_SIGMOID: u32 = 47;
pub const DML_OPERATOR_ACTIVATION_SOFTMAX: u32 = 48;
pub const DML_OPERATOR_ACTIVATION_SOFTPLUS: u32 = 49;
pub const DML_OPERATOR_ACTIVATION_SOFTSIGN: u32 = 50;
pub const DML_OPERATOR_ACTIVATION_TANH: u32 = 51;
pub const DML_OPERATOR_ACTIVATION_THRESHOLDED_RELU: u32 = 52;
pub const DML_OPERATOR_CONVOLUTION: u32 = 53;
pub const DML_OPERATOR_GEMM: u32 = 54;
pub const DML_OPERATOR_REDUCE: u32 = 55;
pub const DML_OPERATOR_AVERAGE_POOLING: u32 = 56;
pub const DML_OPERATOR_MAX_POOLING: u32 = 58;
pub const DML_OPERATOR_ROI_POOLING: u32 = 59;
pub const DML_OPERATOR_SLICE: u32 = 60;
pub const DML_OPERATOR_SPLIT: u32 = 62;
pub const DML_OPERATOR_JOIN: u32 = 63;
pub const DML_OPERATOR_PADDING: u32 = 64;
pub const DML_OPERATOR_UPSAMPLE_2D: u32 = 66;
pub const DML_OPERATOR_GATHER: u32 = 67;
pub const DML_OPERATOR_TILE: u32 = 70;
pub const DML_OPERATOR_TOP_K: u32 = 71;
pub const DML_OPERATOR_BATCH_NORMALIZATION: u32 = 72;
pub const DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION: u32 = 73;
pub const DML_OPERATOR_LOCAL_RESPONSE_NORMALIZATION: u32 = 74;
pub const DML_OPERATOR_RNN: u32 = 76;
pub const DML_OPERATOR_LSTM: u32 = 77;
pub const DML_OPERATOR_GRU: u32 = 78;
pub const DML_OPERATOR_ELEMENT_WISE_ADD1: u32 = 89;
pub const DML_OPERATOR_SCATTER: u32 = 94;
pub const DML_OPERATOR_SCATTER_ELEMENTS: u32 = DML_OPERATOR_SCATTER;
pub const DML_OPERATOR_RESAMPLE: u32 = 96;
pub const DML_OPERATOR_GATHER_ELEMENTS: u32 = 107;
pub const DML_OPERATOR_GATHER_ND: u32 = 108;
pub const DML_OPERATOR_SCATTER_ND: u32 = 109;
pub const DML_OPERATOR_TOP_K1: u32 = 112;
pub const DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION1: u32 = 115;
pub const DML_OPERATOR_RESAMPLE1: u32 = 116;
pub const DML_OPERATOR_MATRIX_MULTIPLY_INTEGER: u32 = 117;
pub const DML_OPERATOR_QUANTIZED_LINEAR_MATRIX_MULTIPLY: u32 = 118;
pub const DML_OPERATOR_CONVOLUTION_INTEGER: u32 = 119;
pub const DML_OPERATOR_QUANTIZED_LINEAR_CONVOLUTION: u32 = 120;
pub const DML_OPERATOR_ADAM_OPTIMIZER: u32 = 136;
pub const DML_OPERATOR_ARGMIN: u32 = 137;
pub const DML_OPERATOR_ARGMAX: u32 = 138;
pub const DML_OPERATOR_ROI_ALIGN: u32 = 139;
pub const DML_OPERATOR_GATHER_ND1: u32 = 140;
pub const DML_OPERATOR_ELEMENT_WISE_QUANTIZED_LINEAR_ADD: u32 = 147;
pub const DML_OPERATOR_DYNAMIC_QUANTIZE_LINEAR: u32 = 148;
pub const DML_OPERATOR_ROI_ALIGN1: u32 = 149;
pub const DML_OPERATOR_PADDING1: u32 = 155;
pub const DML_OPERATOR_ACTIVATION_GELU: u32 = 157;
pub const DML_OPERATOR_RESAMPLE2: u32 = 161;
pub const DML_OPERATOR_ACTIVATION_SWISH: u32 = 167;
pub const DML_OPERATOR_ACTIVATION_HARD_SWISH: u32 = 168;
pub const DML_OPERATOR_QUANTIZED_LINEAR_AVERAGE_POOLING: u32 = 169;
pub const DML_OPERATOR_MATRIX_MULTIPLY_INTEGER_TO_FLOAT: u32 = 170;
pub const DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION2: u32 = 171;
pub const DML_OPERATOR_QUANTIZE: u32 = 173;
pub const DML_OPERATOR_DEQUANTIZE: u32 = 174;
pub const DML_OPERATOR_RESAMPLE3: u32 = 175;

pub const DML_CONVOLUTION_MODE_CONVOLUTION: u32 = 0;
pub const DML_CONVOLUTION_MODE_CROSS_CORRELATION: u32 = 1;
pub const DML_CONVOLUTION_DIRECTION_FORWARD: u32 = 0;

// DirectML represents reshape/transpose through tensor strides rather than a
// dedicated operator id. These values are bridge-local ids for those two
// descriptor-level operations.
pub const DML_OPERATOR_RESHAPE: u32 = 0x1000;
pub const DML_OPERATOR_TRANSPOSE: u32 = 0x1001;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DmlExecutionDevice {
    #[default]
    Metal,
    Cpu,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmlActivation {
    Relu,
    LeakyRelu { alpha: f32 },
    Sigmoid,
    Tanh,
    Identity,
    Elu { alpha: f32 },
    Linear { alpha: f32, beta: f32 },
    Softplus { steepness: f32 },
    Softsign,
    Gelu,
    Swish { scale: f32 },
    HardSwish { alpha: f32, beta: f32 },
    HardSigmoid { alpha: f32, beta: f32 },
    ScaledTanh { alpha: f32, beta: f32 },
    ThresholdedRelu { alpha: f32 },
}

impl DmlActivation {
    pub fn operator_type(self) -> u32 {
        match self {
            Self::Relu => DML_OPERATOR_ACTIVATION_RELU,
            Self::LeakyRelu { .. } => DML_OPERATOR_ACTIVATION_LEAKY_RELU,
            Self::Sigmoid => DML_OPERATOR_ACTIVATION_SIGMOID,
            Self::Tanh => DML_OPERATOR_ACTIVATION_TANH,
            Self::Identity => DML_OPERATOR_ACTIVATION_IDENTITY,
            Self::Elu { .. } => DML_OPERATOR_ACTIVATION_ELU,
            Self::Linear { .. } => DML_OPERATOR_ACTIVATION_LINEAR,
            Self::Softplus { .. } => DML_OPERATOR_ACTIVATION_SOFTPLUS,
            Self::Softsign => DML_OPERATOR_ACTIVATION_SOFTSIGN,
            Self::Gelu => DML_OPERATOR_ACTIVATION_GELU,
            Self::Swish { .. } => DML_OPERATOR_ACTIVATION_SWISH,
            Self::HardSwish { .. } => DML_OPERATOR_ACTIVATION_HARD_SWISH,
            Self::HardSigmoid { .. } => DML_OPERATOR_ACTIVATION_HARD_SIGMOID,
            Self::ScaledTanh { .. } => DML_OPERATOR_ACTIVATION_SCALED_TANH,
            Self::ThresholdedRelu { .. } => DML_OPERATOR_ACTIVATION_THRESHOLDED_RELU,
        }
    }

    fn validate(self, ty: u32) -> DmlResult<()> {
        let parameters: &[f32] = match self {
            Self::LeakyRelu { alpha } | Self::Elu { alpha } => &[alpha],
            Self::Linear { alpha, beta } => &[alpha, beta],
            Self::Softplus { steepness } => &[steepness],
            Self::Swish { scale } => &[scale],
            Self::HardSwish { alpha, beta } => &[alpha, beta],
            Self::HardSigmoid { alpha, beta } => &[alpha, beta],
            Self::ScaledTanh { alpha, beta } => &[alpha, beta],
            Self::ThresholdedRelu { alpha } => &[alpha],
            _ => &[],
        };
        if parameters.iter().any(|value| !value.is_finite()) {
            return Err(DmlError::invalid(format!(
                "activation parameters for DML_OPERATOR_TYPE {ty} must be finite"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlBinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Min,
    Max,
    Pow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlPoolingKind {
    Max,
    Average,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlReduceKind {
    Sum,
    Mean,
    Max,
    Min,
    Multiply,
    SumSquare,
    L1,
    L2,
    LogSum,
    LogSumExp,
    ArgMin,
    ArgMax,
}

impl DmlReduceKind {
    /// DirectML `DML_REDUCE_FUNCTION` values, used by guest descriptors.
    pub fn from_reduce_function(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::ArgMax),
            1 => Some(Self::ArgMin),
            2 => Some(Self::Mean),
            3 => Some(Self::L1),
            4 => Some(Self::L2),
            5 => Some(Self::LogSum),
            6 => Some(Self::LogSumExp),
            7 => Some(Self::Max),
            8 => Some(Self::Min),
            9 => Some(Self::Multiply),
            10 => Some(Self::Sum),
            11 => Some(Self::SumSquare),
            _ => None,
        }
    }

    pub fn is_index_reduction(self) -> bool {
        matches!(self, Self::ArgMin | Self::ArgMax)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlAxisDirection {
    Increasing,
    Decreasing,
}

impl DmlAxisDirection {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Increasing),
            1 => Some(Self::Decreasing),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlInterpolationMode {
    NearestNeighbor,
    Linear,
}

impl DmlInterpolationMode {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::NearestNeighbor),
            1 => Some(Self::Linear),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlPaddingMode {
    Constant,
    Edge,
    Reflection,
    Symmetric,
    Wrap,
}

impl DmlPaddingMode {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Constant),
            1 => Some(Self::Edge),
            2 => Some(Self::Reflection),
            3 => Some(Self::Symmetric),
            4 => Some(Self::Wrap),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlRecurrentDirection {
    Forward,
    Backward,
    Bidirectional,
}

impl DmlRecurrentDirection {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Forward),
            1 => Some(Self::Backward),
            2 => Some(Self::Bidirectional),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlRecurrentOutput {
    Sequence,
    Single,
    CellSingle,
}

/// Optional recurrent-network inputs. The ordered input list is:
/// input, weight, recurrence, [bias], [hidden init], [cell init],
/// [sequence lengths], [peephole].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DmlRecurrentOptions {
    pub bias: bool,
    pub hidden_init: bool,
    pub cell_init: bool,
    pub sequence_lengths: bool,
    pub peephole: bool,
}

impl DmlRecurrentOptions {
    fn input_count(self) -> usize {
        3 + usize::from(self.bias)
            + usize::from(self.hidden_init)
            + usize::from(self.cell_init)
            + usize::from(self.sequence_lengths)
            + usize::from(self.peephole)
    }

    /// Role name for an input slot (used by binding errors).
    fn role(self, index: usize) -> &'static str {
        let mut slot = 3;
        if self.bias {
            if index == slot {
                return "bias";
            }
            slot += 1;
        }
        if self.hidden_init {
            if index == slot {
                return "hidden init";
            }
            slot += 1;
        }
        if self.cell_init {
            if index == slot {
                return "cell init";
            }
            slot += 1;
        }
        if self.sequence_lengths {
            if index == slot {
                return "sequence lengths";
            }
            slot += 1;
        }
        if self.peephole && index == slot {
            return "peephole";
        }
        let _ = slot;
        match index {
            0 => "input",
            1 => "weight",
            2 => "recurrence",
            _ => "input",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DmlOpKind {
    Gemm {
        trans_a: bool,
        trans_b: bool,
        alpha: f32,
        beta: f32,
    },
    Convolution {
        strides: Vec<u32>,
        dilations: Vec<u32>,
        start_padding: Vec<u32>,
        end_padding: Vec<u32>,
        output_padding: Vec<u32>,
        group_count: u32,
    },
    Pooling {
        kind: DmlPoolingKind,
        strides: Vec<u32>,
        window: Vec<u32>,
        start_padding: Vec<u32>,
        end_padding: Vec<u32>,
        include_padding: bool,
    },
    Activation {
        activation: DmlActivation,
        alpha: f32,
    },
    BatchNormalization {
        spatial: bool,
        epsilon: f32,
    },
    Softmax,
    Binary {
        op: DmlBinaryOp,
    },
    Reduce {
        reduce: DmlReduceKind,
        axes: Vec<u32>,
    },
    Reshape,
    Transpose {
        permutation: Vec<u32>,
    },
    Concat {
        axis: u32,
    },
    Slice {
        offsets: Vec<u32>,
        sizes: Vec<u32>,
        strides: Vec<u32>,
    },
    Rnn {
        direction: DmlRecurrentDirection,
        activations: Vec<DmlActivation>,
        options: DmlRecurrentOptions,
        outputs: Vec<DmlRecurrentOutput>,
    },
    Gru {
        direction: DmlRecurrentDirection,
        activations: Vec<DmlActivation>,
        options: DmlRecurrentOptions,
        outputs: Vec<DmlRecurrentOutput>,
        linear_before_reset: bool,
    },
    Lstm {
        direction: DmlRecurrentDirection,
        activations: Vec<DmlActivation>,
        options: DmlRecurrentOptions,
        outputs: Vec<DmlRecurrentOutput>,
        clip_threshold: f32,
        use_clip_threshold: bool,
        couple_input_forget: bool,
    },
    ArgMin {
        axes: Vec<u32>,
        direction: DmlAxisDirection,
    },
    ArgMax {
        axes: Vec<u32>,
        direction: DmlAxisDirection,
    },
    Padding {
        mode: DmlPaddingMode,
        start_padding: Vec<u32>,
        end_padding: Vec<u32>,
        value: f32,
    },
    Resample {
        mode: DmlInterpolationMode,
        scales: Vec<f32>,
        input_offsets: Vec<f32>,
        output_offsets: Vec<f32>,
        rounding: DmlAxisDirection,
        antialiased: bool,
    },
    TopK {
        axis: u32,
        k: u32,
        direction: DmlAxisDirection,
    },
    Tile {
        repeats: Vec<u32>,
    },
    Split {
        axis: u32,
    },
    Gather {
        axis: u32,
        index_dimensions: u32,
    },
    GatherElements {
        axis: u32,
    },
    GatherNd {
        input_dimension_count: u32,
        indices_dimension_count: u32,
        batch_dimension_count: u32,
    },
    Scatter {
        axis: u32,
    },
    ScatterNd {
        input_dimension_count: u32,
        indices_dimension_count: u32,
    },
    RoiPooling {
        spatial_scale: f32,
        pooled: Vec<u32>,
    },
    RoiAlign {
        reduction: DmlReduceKind,
        mode: DmlInterpolationMode,
        spatial_scale_x: f32,
        spatial_scale_y: f32,
        input_pixel_offset: f32,
        output_pixel_offset: f32,
        out_of_bounds_value: f32,
        minimum_samples_per_output: u32,
        maximum_samples_per_output: u32,
        align_regions_to_corners: bool,
    },
    LocalResponseNormalization {
        cross_channel: bool,
        local_size: u32,
        alpha: f32,
        beta: f32,
        bias: f32,
    },
    MeanVarianceNormalization {
        axes: Vec<u32>,
        normalize_variance: bool,
        epsilon: f32,
    },
    Adam {
        learning_rate: f32,
        beta1: f32,
        beta2: f32,
        epsilon: f32,
    },
    QuantizeLinear,
    DequantizeLinear,
    DynamicQuantizeLinear,
    QuantizedLinearAdd {
        a_zero_point: bool,
        b_zero_point: bool,
        output_zero_point: bool,
    },
    MatrixMultiplyInteger {
        quantized_output: bool,
        a_zero_point: bool,
        b_zero_point: bool,
        output_scale: bool,
        output_zero_point: bool,
    },
    ConvolutionInteger {
        strides: Vec<u32>,
        dilations: Vec<u32>,
        start_padding: Vec<u32>,
        end_padding: Vec<u32>,
        group_count: u32,
        quantized_output: bool,
        input_zero_point: bool,
        filter_zero_point: bool,
        bias: bool,
        output_scale: bool,
        output_zero_point: bool,
    },
    QuantizedLinearAveragePooling {
        strides: Vec<u32>,
        window: Vec<u32>,
        start_padding: Vec<u32>,
        end_padding: Vec<u32>,
        dilations: Vec<u32>,
        include_padding: bool,
        input_zero_point: bool,
        output_zero_point: bool,
    },
    MatrixMultiplyIntegerToFloat {
        a_zero_point: bool,
        b_zero_point: bool,
        bias: bool,
    },
    Quantize {
        quantization_type: u32,
    },
    Dequantize {
        quantization_type: u32,
    },
    Add1,
}

impl DmlOpKind {
    pub fn operator_type(&self) -> u32 {
        match self {
            Self::Gemm { .. } => DML_OPERATOR_GEMM,
            Self::Convolution { .. } => DML_OPERATOR_CONVOLUTION,
            Self::Pooling { kind, .. } => match kind {
                DmlPoolingKind::Max => DML_OPERATOR_MAX_POOLING,
                DmlPoolingKind::Average => DML_OPERATOR_AVERAGE_POOLING,
            },
            Self::Activation { activation, .. } => activation.operator_type(),
            Self::BatchNormalization { .. } => DML_OPERATOR_BATCH_NORMALIZATION,
            Self::Softmax => DML_OPERATOR_ACTIVATION_SOFTMAX,
            Self::Binary { op } => match op {
                DmlBinaryOp::Add => super::DML_OPERATOR_ELEMENT_WISE_ADD,
                DmlBinaryOp::Subtract => super::DML_OPERATOR_ELEMENT_WISE_SUBTRACT,
                DmlBinaryOp::Multiply => super::DML_OPERATOR_ELEMENT_WISE_MULTIPLY,
                DmlBinaryOp::Divide => super::DML_OPERATOR_ELEMENT_WISE_DIVIDE,
                DmlBinaryOp::Min => super::DML_OPERATOR_ELEMENT_WISE_MIN,
                DmlBinaryOp::Max => super::DML_OPERATOR_ELEMENT_WISE_MAX,
                DmlBinaryOp::Pow => super::DML_OPERATOR_ELEMENT_WISE_POW,
            },
            Self::Reduce { .. } => DML_OPERATOR_REDUCE,
            Self::Reshape => DML_OPERATOR_RESHAPE,
            Self::Transpose { .. } => DML_OPERATOR_TRANSPOSE,
            Self::Concat { .. } => DML_OPERATOR_JOIN,
            Self::Slice { .. } => DML_OPERATOR_SLICE,
            Self::Rnn { .. } => DML_OPERATOR_RNN,
            Self::Gru { .. } => DML_OPERATOR_GRU,
            Self::Lstm { .. } => DML_OPERATOR_LSTM,
            Self::ArgMin { .. } => DML_OPERATOR_ARGMIN,
            Self::ArgMax { .. } => DML_OPERATOR_ARGMAX,
            Self::Padding { .. } => DML_OPERATOR_PADDING,
            Self::Resample { .. } => DML_OPERATOR_RESAMPLE1,
            Self::TopK { .. } => DML_OPERATOR_TOP_K1,
            Self::Tile { .. } => DML_OPERATOR_TILE,
            Self::Split { .. } => DML_OPERATOR_SPLIT,
            Self::Gather { .. } => DML_OPERATOR_GATHER,
            Self::GatherElements { .. } => DML_OPERATOR_GATHER_ELEMENTS,
            Self::GatherNd { .. } => DML_OPERATOR_GATHER_ND1,
            Self::Scatter { .. } => DML_OPERATOR_SCATTER,
            Self::ScatterNd { .. } => DML_OPERATOR_SCATTER_ND,
            Self::RoiPooling { .. } => DML_OPERATOR_ROI_POOLING,
            Self::RoiAlign { .. } => DML_OPERATOR_ROI_ALIGN1,
            Self::LocalResponseNormalization { .. } => DML_OPERATOR_LOCAL_RESPONSE_NORMALIZATION,
            Self::MeanVarianceNormalization { .. } => DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION1,
            Self::Adam { .. } => DML_OPERATOR_ADAM_OPTIMIZER,
            Self::QuantizeLinear => DML_OPERATOR_ELEMENT_WISE_QUANTIZE_LINEAR,
            Self::DequantizeLinear => DML_OPERATOR_ELEMENT_WISE_DEQUANTIZE_LINEAR,
            Self::DynamicQuantizeLinear => DML_OPERATOR_DYNAMIC_QUANTIZE_LINEAR,
            Self::QuantizedLinearAdd { .. } => DML_OPERATOR_ELEMENT_WISE_QUANTIZED_LINEAR_ADD,
            Self::MatrixMultiplyInteger {
                quantized_output, ..
            } => {
                if *quantized_output {
                    DML_OPERATOR_QUANTIZED_LINEAR_MATRIX_MULTIPLY
                } else {
                    DML_OPERATOR_MATRIX_MULTIPLY_INTEGER
                }
            }
            Self::ConvolutionInteger {
                quantized_output, ..
            } => {
                if *quantized_output {
                    DML_OPERATOR_QUANTIZED_LINEAR_CONVOLUTION
                } else {
                    DML_OPERATOR_CONVOLUTION_INTEGER
                }
            }
            Self::QuantizedLinearAveragePooling { .. } => {
                DML_OPERATOR_QUANTIZED_LINEAR_AVERAGE_POOLING
            }
            Self::MatrixMultiplyIntegerToFloat { .. } => {
                DML_OPERATOR_MATRIX_MULTIPLY_INTEGER_TO_FLOAT
            }
            Self::Quantize { .. } => DML_OPERATOR_QUANTIZE,
            Self::Dequantize { .. } => DML_OPERATOR_DEQUANTIZE,
            Self::Add1 => DML_OPERATOR_ELEMENT_WISE_ADD1,
        }
    }

    /// The DirectML feature level that introduced this operator type.
    pub fn minimum_feature_level(&self) -> u32 {
        match self {
            Self::Rnn { .. }
            | Self::Gru { .. }
            | Self::Lstm { .. }
            | Self::RoiPooling { .. }
            | Self::Padding { .. }
            | Self::Tile { .. }
            | Self::Gather { .. }
            | Self::Scatter { .. }
            | Self::LocalResponseNormalization { .. }
            | Self::Split { .. } => super::DML_FEATURE_LEVEL_2_0,
            Self::GatherElements { .. }
            | Self::GatherNd { .. }
            | Self::ScatterNd { .. }
            | Self::MatrixMultiplyInteger { .. }
            | Self::ConvolutionInteger { .. }
            | Self::Resample { .. }
            | Self::TopK { .. }
            | Self::MeanVarianceNormalization { .. } => super::DML_FEATURE_LEVEL_2_1,
            Self::ArgMin { .. } | Self::ArgMax { .. } | Self::Adam { .. } => {
                super::DML_FEATURE_LEVEL_3_0
            }
            Self::RoiAlign { .. }
            | Self::QuantizedLinearAdd { .. }
            | Self::DynamicQuantizeLinear => super::DML_FEATURE_LEVEL_4_0,
            Self::QuantizedLinearAveragePooling { .. }
            | Self::MatrixMultiplyIntegerToFloat { .. } => super::DML_FEATURE_LEVEL_6_2,
            Self::Quantize { .. } | Self::Dequantize { .. } => super::DML_FEATURE_LEVEL_6_3,
            Self::Activation { activation, .. } => match activation {
                DmlActivation::Gelu => super::DML_FEATURE_LEVEL_5_1,
                DmlActivation::Swish { .. } | DmlActivation::HardSwish { .. } => {
                    super::DML_FEATURE_LEVEL_6_2
                }
                _ => super::DML_FEATURE_LEVEL_1_0,
            },
            _ => super::DML_FEATURE_LEVEL_1_0,
        }
    }

    fn allows_float16(&self) -> bool {
        !matches!(
            self,
            Self::Convolution { .. }
                | Self::Pooling { .. }
                | Self::BatchNormalization { .. }
                | Self::Rnn { .. }
                | Self::Gru { .. }
                | Self::Lstm { .. }
                | Self::RoiPooling { .. }
                | Self::RoiAlign { .. }
                | Self::Adam { .. }
                | Self::QuantizeLinear
                | Self::DequantizeLinear
                | Self::DynamicQuantizeLinear
                | Self::QuantizedLinearAdd { .. }
                | Self::MatrixMultiplyInteger { .. }
                | Self::ConvolutionInteger { .. }
                | Self::QuantizedLinearAveragePooling { .. }
                | Self::MatrixMultiplyIntegerToFloat { .. }
                | Self::Quantize { .. }
                | Self::Dequantize { .. }
        )
    }

    fn supports_fused_activation(&self) -> bool {
        matches!(
            self,
            Self::Gemm { .. }
                | Self::Convolution { .. }
                | Self::BatchNormalization { .. }
                | Self::MeanVarianceNormalization { .. }
                | Self::Add1
                | Self::Binary { .. }
        )
    }
}

/// A complete extended operator: kind, ordered input tensors, primary output
/// tensor, and any additional outputs (index tensors, recurrent outputs, split
/// slices, quantizer outputs).
///
/// Input order follows the DirectML descriptor:
/// - GEMM: A, B, [C]
/// - Convolution: input, filter, [bias]
/// - Pooling/Activation/Softmax/Reduce/Reshape/Transpose/Slice: input
/// - BatchNormalization: input, mean, variance, scale, bias
/// - Binary/Add1: A, B
/// - Concat: input 0..N
/// - Recurrent: input, weight, recurrence, then the optional inputs declared
///   by [`DmlRecurrentOptions`] in that order.
#[derive(Debug, Clone, PartialEq)]
pub struct DmlOpPlan {
    pub kind: DmlOpKind,
    pub inputs: Vec<DmlTensorDesc>,
    pub output: DmlTensorDesc,
    pub extra_outputs: Vec<DmlTensorDesc>,
    pub fused_activation: Option<DmlActivation>,
}

impl DmlOpPlan {
    pub fn operator_type(&self) -> u32 {
        self.kind.operator_type()
    }

    pub fn output_count(&self) -> usize {
        1 + self.extra_outputs.len()
    }

    /// Number of kernel invocations. Recurrent kernels use one thread per
    /// batch element; every other kernel uses one thread per output element.
    pub fn dispatch_count(&self) -> u64 {
        match &self.kind {
            DmlOpKind::Rnn { .. } | DmlOpKind::Gru { .. } | DmlOpKind::Lstm { .. } => {
                self.inputs[0].sizes.get(1).copied().unwrap_or(1) as u64
            }
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
            _ => vec!["input"],
        }
    }

    fn validate_dtypes(&self) -> DmlResult<()> {
        let ty = self.operator_type();
        match &self.kind {
            DmlOpKind::Gemm { .. }
            | DmlOpKind::Convolution { .. }
            | DmlOpKind::Pooling { .. }
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
                        expect_dtype(desc, &[DML_TENSOR_DATA_TYPE_FLOAT32], ty, "recurrent")?;
                    }
                }
                for output in self.outputs() {
                    expect_dtype(
                        output,
                        &[DML_TENSOR_DATA_TYPE_FLOAT32],
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
                if self.inputs.len() == 3 {
                    expect_dtype(
                        &self.inputs[2],
                        &[DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_INT8],
                        ty,
                        "zero point",
                    )?;
                    if self.inputs[2].data_type != self.output.data_type {
                        return Err(DmlError::invalid(
                            "quantize zero point and output DataTypes must match",
                        ));
                    }
                } else if self.output.data_type != DML_TENSOR_DATA_TYPE_UINT8 {
                    return Err(DmlError::invalid(
                        "quantize without a zero point tensor must produce UINT8",
                    ));
                }
            }
            DmlOpKind::DequantizeLinear => {
                expect_dtype(
                    &self.inputs[0],
                    &[DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_INT8],
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
                        &[DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_INT8],
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
                        &[DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_INT8],
                        ty,
                        "output",
                    )?;
                } else {
                    expect_dtype(
                        &self.inputs[0],
                        &[DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_INT8],
                        ty,
                        "input",
                    )?;
                    expect_dtype(&self.output, &[DML_TENSOR_DATA_TYPE_FLOAT32], ty, "output")?;
                }
            }
        }
        Ok(())
    }

    fn validate_quantized_dtypes(&self, ty: u32, _mode: u32) -> DmlResult<()> {
        for desc in &self.inputs {
            let supported = matches!(
                desc.data_type,
                DML_TENSOR_DATA_TYPE_FLOAT32
                    | DML_TENSOR_DATA_TYPE_UINT32
                    | DML_TENSOR_DATA_TYPE_INT32
                    | DML_TENSOR_DATA_TYPE_UINT8
                    | DML_TENSOR_DATA_TYPE_INT8
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

    pub fn validate(&self) -> DmlResult<()> {
        let ty = self.operator_type();
        if self.inputs.is_empty() {
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
                strides,
                dilations,
                start_padding,
                end_padding,
                output_padding,
                group_count,
            } => self.validate_convolution(
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
                epsilon,
            } => self.validate_mvn(axes, *normalize_variance, *epsilon),
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
        }
    }

    fn require_input_count(&self, expected: usize) -> DmlResult<()> {
        if self.inputs.len() != expected {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} requires {expected} input tensor(s), got {}",
                self.operator_type(),
                self.inputs.len()
            )));
        }
        Ok(())
    }

    fn validate_gemm(&self, trans_a: bool, trans_b: bool, beta: f32) -> DmlResult<()> {
        if !(2..=3).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "GEMM requires 2 or 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let a = &self.inputs[0];
        let b = &self.inputs[1];
        let rank = a.sizes.len();
        if rank < 2 {
            return Err(DmlError::invalid("GEMM tensors must have rank >= 2"));
        }
        if b.sizes.len() != rank || self.output.sizes.len() != rank {
            return Err(DmlError::invalid(
                "GEMM input and output tensors must have the same rank",
            ));
        }
        let (m, k) = if trans_a {
            (a.sizes[rank - 1], a.sizes[rank - 2])
        } else {
            (a.sizes[rank - 2], a.sizes[rank - 1])
        };
        let (b_k, n) = if trans_b {
            (b.sizes[rank - 1], b.sizes[rank - 2])
        } else {
            (b.sizes[rank - 2], b.sizes[rank - 1])
        };
        if k != b_k {
            return Err(DmlError::invalid(format!(
                "GEMM inner dimensions do not match: A K={k}, B K={b_k}"
            )));
        }
        if self.output.sizes[rank - 2] != m || self.output.sizes[rank - 1] != n {
            return Err(DmlError::invalid(format!(
                "GEMM output sizes must be [{m}, {n}], got [{}, {}]",
                self.output.sizes[rank - 2],
                self.output.sizes[rank - 1]
            )));
        }
        if a.sizes[..rank - 2] != b.sizes[..rank - 2]
            || a.sizes[..rank - 2] != self.output.sizes[..rank - 2]
        {
            return Err(DmlError::invalid(
                "GEMM batch dimensions must match across A, B, and output",
            ));
        }
        if beta != 0.0 && self.inputs.len() == 2 {
            return Err(DmlError::invalid(
                "GEMM beta is non-zero but no C tensor was provided",
            ));
        }
        if let Some(c) = self.inputs.get(2) {
            if c.sizes.len() != rank {
                return Err(DmlError::invalid(
                    "GEMM C tensor must have the same rank as the output",
                ));
            }
            if c.sizes != self.output.sizes {
                return Err(DmlError::invalid(
                    "GEMM C tensor must have the output sizes",
                ));
            }
        }
        Ok(())
    }

    fn validate_convolution(
        &self,
        strides: &[u32],
        dilations: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
        output_padding: &[u32],
        group_count: u32,
    ) -> DmlResult<()> {
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

    fn validate_pooling(
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

    fn validate_batch_normalization(&self, spatial: bool, epsilon: f32) -> DmlResult<()> {
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

    fn validate_binary(&self) -> DmlResult<()> {
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

    fn validate_reduce(&self, reduce: DmlReduceKind, axes: &[u32]) -> DmlResult<()> {
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

    fn validate_transpose(&self, permutation: &[u32]) -> DmlResult<()> {
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

    fn validate_concat(&self, axis: u32) -> DmlResult<()> {
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

    fn validate_slice(&self, offsets: &[u32], sizes: &[u32], strides: &[u32]) -> DmlResult<()> {
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

    fn validate_recurrent(
        &self,
        ty: u32,
        direction: DmlRecurrentDirection,
        activations: &[DmlActivation],
        options: DmlRecurrentOptions,
        outputs: &[DmlRecurrentOutput],
        gates: u32,
    ) -> DmlResult<()> {
        if direction != DmlRecurrentDirection::Forward {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} only supports DML_RECURRENT_NETWORK_DIRECTION_FORWARD"
            )));
        }
        if self.inputs.len() != options.input_count() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} expects {} input tensor(s), got {}",
                options.input_count(),
                self.inputs.len()
            )));
        }
        if options.peephole {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} peephole tensors are not supported"
            )));
        }
        let input = &self.inputs[0];
        let weight = &self.inputs[1];
        let recurrence = &self.inputs[2];
        if input.sizes.len() != 3 || weight.sizes.len() != 3 || recurrence.sizes.len() != 3 {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} input, weight, and recurrence tensors must be rank 3"
            )));
        }
        let [sequence, batch, input_size] = [input.sizes[0], input.sizes[1], input.sizes[2]];
        if weight.sizes[0] != gates {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} weight gate count must be {gates}, got {}",
                weight.sizes[0]
            )));
        }
        if weight.sizes[2] != input_size {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} weight input size must be {input_size}, got {}",
                weight.sizes[2]
            )));
        }
        let hidden = weight.sizes[1];
        if hidden == 0 {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} hidden size must be non-zero"
            )));
        }
        if recurrence.sizes != [gates, hidden, hidden] {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} recurrence sizes must be [{gates}, {hidden}, {hidden}], got {:?}",
                recurrence.sizes
            )));
        }
        let mut slot = 3;
        if options.bias {
            let bias = &self.inputs[slot];
            if bias.element_count() != gates as u64 * hidden as u64 || !bias.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} bias must be a contiguous tensor with {} elements",
                    gates as u64 * hidden as u64
                )));
            }
            slot += 1;
        }
        if options.hidden_init {
            let hidden_init = &self.inputs[slot];
            if !hidden_init.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} hidden init must be contiguous"
                )));
            }
            if hidden_init.sizes != [1, batch, hidden] {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} hidden init sizes must be [1, {batch}, {hidden}], got {:?}",
                    hidden_init.sizes
                )));
            }
            slot += 1;
        }
        if options.cell_init {
            let cell_init = &self.inputs[slot];
            if !cell_init.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} cell init must be contiguous"
                )));
            }
            if cell_init.sizes != [1, batch, hidden] {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} cell init sizes must be [1, {batch}, {hidden}], got {:?}",
                    cell_init.sizes
                )));
            }
            slot += 1;
        }
        if options.sequence_lengths {
            let lengths = &self.inputs[slot];
            if lengths.element_count() != batch as u64 || !lengths.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} sequence lengths must contain {batch} contiguous elements"
                )));
            }
        }
        let expected_activations = match ty {
            DML_OPERATOR_RNN => 1..=2,
            DML_OPERATOR_GRU => 2..=2,
            _ => 3..=3,
        };
        if !activations.is_empty() && !expected_activations.contains(&activations.len()) {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} expects {} activation descriptor(s), got {}",
                expected_activations.start(),
                activations.len()
            )));
        }
        for activation in activations {
            activation.validate(activation.operator_type())?;
        }
        if outputs.is_empty() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} requires at least one output tensor"
            )));
        }
        if self.output_count() != outputs.len() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} declares {} output role(s) but has {} output tensor(s)",
                outputs.len(),
                self.output_count()
            )));
        }
        for output in self.outputs() {
            if !output.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} recurrent outputs must be contiguous"
                )));
            }
        }
        let mut seen = Vec::new();
        for (role, output) in outputs.iter().zip(self.outputs()) {
            if seen.contains(role) {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} output role is declared more than once"
                )));
            }
            seen.push(*role);
            let expected = match role {
                DmlRecurrentOutput::Sequence => {
                    if output.sizes != [sequence, batch, hidden] {
                        return Err(DmlError::invalid(format!(
                            "DML_OPERATOR_TYPE {ty} output sequence sizes must be [{sequence}, {batch}, {hidden}], got {:?}",
                            output.sizes
                        )));
                    }
                    continue;
                }
                DmlRecurrentOutput::Single | DmlRecurrentOutput::CellSingle => [1, batch, hidden],
            };
            if output.sizes != expected {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} output sizes must be {expected:?}, got {:?}",
                    output.sizes
                )));
            }
        }
        if ty == DML_OPERATOR_LSTM
            && seen.contains(&DmlRecurrentOutput::CellSingle)
            && !seen.contains(&DmlRecurrentOutput::Single)
        {
            return Err(DmlError::invalid(
                "LSTM cell state output requires a single output tensor",
            ));
        }
        if !seen.contains(&DmlRecurrentOutput::Single)
            && !seen.contains(&DmlRecurrentOutput::Sequence)
        {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} requires a sequence or single hidden-state output"
            )));
        }
        Ok(())
    }

    fn validate_arg_reduce(&self, axes: &[u32], _direction: DmlAxisDirection) -> DmlResult<()> {
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

    fn validate_padding(
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

    fn validate_resample(
        &self,
        _mode: DmlInterpolationMode,
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
        if antialiased {
            return Err(DmlError::invalid("antialiased resample is not supported"));
        }
        if self.output.sizes.len() != rank {
            return Err(DmlError::invalid(
                "resample output must have the same rank as the input",
            ));
        }
        Ok(())
    }

    fn validate_top_k(&self, axis: u32, k: u32, _direction: DmlAxisDirection) -> DmlResult<()> {
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

    fn validate_tile(&self, repeats: &[u32]) -> DmlResult<()> {
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

    fn validate_split(&self, axis: u32) -> DmlResult<()> {
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

    fn validate_gather(&self, axis: u32, index_dimensions: u32) -> DmlResult<()> {
        if self.inputs.len() != 2 {
            return Err(DmlError::invalid(format!(
                "gather requires 2 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        let rank = input.sizes.len();
        if axis as usize >= rank {
            return Err(DmlError::invalid(format!(
                "gather axis {axis} is out of range for rank {rank}"
            )));
        }
        if index_dimensions != 1 || indices.sizes.len() != 1 {
            return Err(DmlError::invalid(
                "gather supports only a rank-1 indices tensor with IndexDimensions 1",
            ));
        }
        if !indices.is_contiguous() {
            return Err(DmlError::invalid(
                "gather indices tensor must be contiguous",
            ));
        }
        let mut expected = input.sizes.clone();
        expected[axis as usize] = indices.sizes[0];
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "gather output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    fn validate_gather_elements(&self, axis: u32) -> DmlResult<()> {
        if self.inputs.len() != 2 {
            return Err(DmlError::invalid(format!(
                "gather elements requires 2 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        if input.sizes.len() != indices.sizes.len() {
            return Err(DmlError::invalid(
                "gather elements input and indices must have the same rank",
            ));
        }
        if axis as usize >= input.sizes.len() {
            return Err(DmlError::invalid(format!(
                "gather elements axis {axis} is out of range for rank {}",
                input.sizes.len()
            )));
        }
        if self.output.sizes != indices.sizes {
            return Err(DmlError::invalid(format!(
                "gather elements output sizes must equal the indices sizes {:?}, got {:?}",
                indices.sizes, self.output.sizes
            )));
        }
        Ok(())
    }

    fn validate_gather_nd(
        &self,
        input_dimension_count: u32,
        indices_dimension_count: u32,
        batch_dimension_count: u32,
    ) -> DmlResult<()> {
        if self.inputs.len() != 2 {
            return Err(DmlError::invalid(format!(
                "gather-nd requires 2 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        let input_rank = input.sizes.len();
        let indices_rank = indices.sizes.len();
        if indices_rank < 1 {
            return Err(DmlError::invalid(
                "gather-nd indices tensor must have rank >= 1",
            ));
        }
        if input_dimension_count != 0 && input_dimension_count != input_rank as u32 {
            return Err(DmlError::invalid(format!(
                "gather-nd InputDimensionCount {input_dimension_count} must be 0 or {input_rank}"
            )));
        }
        if indices_dimension_count != 0 && indices_dimension_count != indices_rank as u32 {
            return Err(DmlError::invalid(format!(
                "gather-nd IndicesDimensionCount {indices_dimension_count} must be 0 or {indices_rank}"
            )));
        }
        if batch_dimension_count != 0 {
            return Err(DmlError::invalid(
                "gather-nd batched indices (BatchDimensionCount != 0) are not supported",
            ));
        }
        let indexed = indices.sizes[indices_rank - 1];
        if indexed as usize > input_rank {
            return Err(DmlError::invalid(format!(
                "gather-nd indices last dimension {indexed} exceeds the input rank {input_rank}"
            )));
        }
        let mut expected = indices.sizes[..indices_rank - 1].to_vec();
        expected.extend_from_slice(&input.sizes[indexed as usize..]);
        if self.output.sizes != expected {
            return Err(DmlError::invalid(format!(
                "gather-nd output sizes must be {expected:?}, got {:?}",
                self.output.sizes
            )));
        }
        Ok(())
    }

    fn validate_scatter(&self, axis: u32) -> DmlResult<()> {
        if self.inputs.len() != 3 {
            return Err(DmlError::invalid(format!(
                "scatter requires 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        let updates = &self.inputs[2];
        let rank = input.sizes.len();
        if axis as usize >= rank {
            return Err(DmlError::invalid(format!(
                "scatter axis {axis} is out of range for rank {rank}"
            )));
        }
        if indices.sizes != updates.sizes {
            return Err(DmlError::invalid(
                "scatter indices and updates must have identical sizes",
            ));
        }
        if indices.sizes.len() != rank {
            return Err(DmlError::invalid(
                "scatter indices must have the same rank as the input",
            ));
        }
        for dimension in 0..rank {
            if dimension as u32 != axis && indices.sizes[dimension] != input.sizes[dimension] {
                return Err(DmlError::invalid(
                    "scatter indices sizes must match the input on non-axis dimensions",
                ));
            }
        }
        if self.output.sizes != input.sizes {
            return Err(DmlError::invalid(
                "scatter output sizes must equal the input sizes",
            ));
        }
        Ok(())
    }

    fn validate_scatter_nd(
        &self,
        input_dimension_count: u32,
        indices_dimension_count: u32,
    ) -> DmlResult<()> {
        if self.inputs.len() != 3 {
            return Err(DmlError::invalid(format!(
                "scatter-nd requires 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let indices = &self.inputs[1];
        let updates = &self.inputs[2];
        let input_rank = input.sizes.len();
        let indices_rank = indices.sizes.len();
        if indices_rank < 1 {
            return Err(DmlError::invalid(
                "scatter-nd indices tensor must have rank >= 1",
            ));
        }
        if input_dimension_count != 0 && input_dimension_count != input_rank as u32 {
            return Err(DmlError::invalid(format!(
                "scatter-nd InputDimensionCount {input_dimension_count} must be 0 or {input_rank}"
            )));
        }
        if indices_dimension_count != 0 && indices_dimension_count != indices_rank as u32 {
            return Err(DmlError::invalid(format!(
                "scatter-nd IndicesDimensionCount {indices_dimension_count} must be 0 or {indices_rank}"
            )));
        }
        let indexed = indices.sizes[indices_rank - 1];
        if indexed as usize > input_rank {
            return Err(DmlError::invalid(format!(
                "scatter-nd indices last dimension {indexed} exceeds the input rank {input_rank}"
            )));
        }
        let mut expected_updates = indices.sizes[..indices_rank - 1].to_vec();
        expected_updates.extend_from_slice(&input.sizes[indexed as usize..]);
        if updates.sizes != expected_updates {
            return Err(DmlError::invalid(format!(
                "scatter-nd updates sizes must be {expected_updates:?}, got {:?}",
                updates.sizes
            )));
        }
        if self.output.sizes != input.sizes {
            return Err(DmlError::invalid(
                "scatter-nd output sizes must equal the input sizes",
            ));
        }
        Ok(())
    }

    fn validate_roi_pooling(&self, spatial_scale: f32, pooled: &[u32]) -> DmlResult<()> {
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
    fn validate_roi_align(
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

    fn validate_lrn(
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

    fn validate_mvn(&self, axes: &[u32], _normalize_variance: bool, epsilon: f32) -> DmlResult<()> {
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

    fn validate_adam(
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

    fn validate_quantize_linear(&self) -> DmlResult<()> {
        if !(2..=3).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "linear quantize expects 2 or 3 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let scale = &self.inputs[1];
        if scale.element_count() != 1 || !scale.is_contiguous() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} supports only a scalar scale tensor",
                self.operator_type()
            )));
        }
        if self.inputs.len() == 3 {
            let zero_point = &self.inputs[2];
            if zero_point.element_count() != 1 || !zero_point.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {} supports only a scalar zero point tensor",
                    self.operator_type()
                )));
            }
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

    fn validate_dynamic_quantize(&self) -> DmlResult<()> {
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

    fn validate_quantized_add(&self) -> DmlResult<()> {
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

    fn a_tensor_index(&self) -> usize {
        match &self.kind {
            DmlOpKind::QuantizedLinearAdd { a_zero_point, .. } => 3 + usize::from(*a_zero_point),
            _ => 0,
        }
    }

    fn require_scalar_quantization_tensors(&self) -> DmlResult<()> {
        let roles = self.input_roles();
        for (index, desc) in self.inputs.iter().enumerate() {
            let role = roles.get(index).copied().unwrap_or("input");
            if role.contains("scale") {
                if desc.data_type != DML_TENSOR_DATA_TYPE_FLOAT32
                    || desc.element_count() != 1
                    || !desc.is_contiguous()
                {
                    return Err(DmlError::invalid(format!(
                        "quantized operator scale input {index} ({role}) must be a scalar FLOAT32 tensor"
                    )));
                }
            }
            if role.contains("zero point") {
                if !matches!(
                    desc.data_type,
                    DML_TENSOR_DATA_TYPE_UINT8 | DML_TENSOR_DATA_TYPE_INT8
                ) || desc.element_count() != 1
                    || !desc.is_contiguous()
                {
                    return Err(DmlError::invalid(format!(
                        "quantized operator zero point input {index} ({role}) must be a scalar UINT8 or INT8 tensor"
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_matmul_integer(&self, quantized_output: bool) -> DmlResult<()> {
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

    fn validate_convolution_integer(
        &self,
        strides: &[u32],
        dilations: &[u32],
        start_padding: &[u32],
        end_padding: &[u32],
        group_count: u32,
        quantized_output: bool,
    ) -> DmlResult<()> {
        if !(2..=4).contains(&self.inputs.len()) {
            return Err(DmlError::invalid(format!(
                "integer convolution requires 2 to 4 input tensors, got {}",
                self.inputs.len()
            )));
        }
        let input = &self.inputs[0];
        let filter = &self.inputs[1];
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

    fn validate_quantized_avg_pool(
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

    fn validate_mmi_to_float(&self) -> DmlResult<()> {
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

    fn validate_quantize(&self, quantization_type: u32) -> DmlResult<()> {
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
        for desc in &self.inputs[1..] {
            if desc.data_type != DML_TENSOR_DATA_TYPE_FLOAT32
                || desc.element_count() != 1
                || !desc.is_contiguous()
            {
                return Err(DmlError::invalid(
                    "quantize/dequantize quantization tensors must be scalar FLOAT32",
                ));
            }
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

fn expect_dtype(desc: &DmlTensorDesc, allowed: &[u32], ty: u32, role: &str) -> DmlResult<()> {
    if !allowed.contains(&desc.data_type) {
        return Err(DmlError::invalid(format!(
            "DML_OPERATOR_TYPE {ty} {role} tensor has unsupported DML_TENSOR_DATA_TYPE {}",
            desc.data_type
        )));
    }
    Ok(())
}

fn expect_same_dtype(desc: &DmlTensorDesc, expected: u32, ty: u32, role: &str) -> DmlResult<()> {
    if desc.data_type != expected {
        return Err(DmlError::invalid(format!(
            "DML_OPERATOR_TYPE {ty} {role} tensor must have DataType {expected}, got {}",
            desc.data_type
        )));
    }
    Ok(())
}

fn expect_index_dtype(desc: &DmlTensorDesc, ty: u32, role: &str) -> DmlResult<()> {
    expect_dtype(
        desc,
        &[DML_TENSOR_DATA_TYPE_UINT32, DML_TENSOR_DATA_TYPE_INT32],
        ty,
        role,
    )
}

fn validate_dtype(desc: &DmlTensorDesc, ty: u32, allow_f16: bool) -> DmlResult<()> {
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

fn validate_layout(desc: &DmlTensorDesc, ty: u32) -> DmlResult<()> {
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

fn checked_product(sizes: &[u32]) -> DmlResult<u64> {
    let mut product = 1u64;
    for size in sizes {
        product = product
            .checked_mul(*size as u64)
            .ok_or_else(|| DmlError::invalid("tensor element count overflows u64"))?;
    }
    Ok(product)
}

fn checked_implied_size(desc: &DmlTensorDesc) -> DmlResult<u64> {
    let element_size = desc.element_size()?;
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
        .and_then(|elements| elements.checked_mul(element_size))
        .ok_or_else(|| DmlError::invalid("tensor stride range overflows u64"))
}

fn convolution_output_size(
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

fn pooling_output_size(
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

// ---------------------------------------------------------------------------
// MSL lowering
// ---------------------------------------------------------------------------

fn msl_float(value: f32) -> String {
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

fn msl_scalar(data_type: u32, ty: u32) -> DmlResult<&'static str> {
    match data_type {
        DML_TENSOR_DATA_TYPE_FLOAT32 => Ok("float"),
        DML_TENSOR_DATA_TYPE_FLOAT16 => Ok("half"),
        DML_TENSOR_DATA_TYPE_UINT32 => Ok("uint"),
        DML_TENSOR_DATA_TYPE_INT32 => Ok("int"),
        DML_TENSOR_DATA_TYPE_UINT8 => Ok("uchar"),
        DML_TENSOR_DATA_TYPE_INT8 => Ok("char"),
        other => Err(DmlError::invalid(format!(
            "DML_TENSOR_DATA_TYPE {other} is not supported for DML_OPERATOR_TYPE {ty}"
        ))),
    }
}

fn msl_type_unchecked(data_type: u32) -> &'static str {
    match data_type {
        DML_TENSOR_DATA_TYPE_FLOAT16 => "half",
        DML_TENSOR_DATA_TYPE_UINT32 => "uint",
        DML_TENSOR_DATA_TYPE_INT32 => "int",
        DML_TENSOR_DATA_TYPE_UINT8 => "uchar",
        DML_TENSOR_DATA_TYPE_INT8 => "char",
        _ => "float",
    }
}

fn msl_header(plan: &DmlOpPlan, scalar: &str) -> String {
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

fn msl_header_outputs(plan: &DmlOpPlan, _input_scalar: &str, output_scalars: &[&str]) -> String {
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
fn inject_fused_activation(source: &mut String, scalar: &str, activation: DmlActivation) {
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

fn push_guard(source: &mut String, output: &DmlTensorDesc) {
    let count = output.element_count();
    source.push_str(&format!("    if (gid >= {count}u) return;\n"));
}

fn push_output_coords(source: &mut String, output: &DmlTensorDesc) {
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

fn output_index_expr(output: &DmlTensorDesc) -> String {
    if output.is_contiguous() {
        return "gid".to_string();
    }
    linear_index(output, &coord_names(output.sizes.len()))
}

fn linear_index(desc: &DmlTensorDesc, coords: &[String]) -> String {
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

fn coord_names(rank: usize) -> Vec<String> {
    (0..rank).map(|index| format!("o{index}")).collect()
}

fn broadcast_index(desc: &DmlTensorDesc) -> String {
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

fn emit_scalar_binary(op: DmlBinaryOp) -> &'static str {
    match op {
        DmlBinaryOp::Add => "a + b",
        DmlBinaryOp::Subtract => "a - b",
        DmlBinaryOp::Multiply => "a * b",
        DmlBinaryOp::Divide => "a / b",
        DmlBinaryOp::Min => "fmin(a, b)",
        DmlBinaryOp::Max => "fmax(a, b)",
        DmlBinaryOp::Pow => "pow(a, b)",
    }
}

fn activation_msl(activation: DmlActivation, fallback_alpha: f32, x: &str) -> String {
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

fn activation_cpu(activation: DmlActivation, x: f32) -> f32 {
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

fn emit_elementwise_msl(plan: &DmlOpPlan, op: DmlBinaryOp) -> DmlResult<String> {
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

fn emit_activation_msl(
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

fn emit_gemm_msl(
    plan: &DmlOpPlan,
    trans_a: bool,
    trans_b: bool,
    alpha: f32,
    beta: f32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let a = &plan.inputs[0];
    let b = &plan.inputs[1];
    let rank = a.sizes.len();
    let m = plan.output.sizes[rank - 2];
    let n = plan.output.sizes[rank - 1];
    let k = if trans_a {
        a.sizes[rank - 2]
    } else {
        a.sizes[rank - 1]
    };
    let (a_m_stride, a_k_stride) = if trans_a {
        (a.strides[rank - 1], a.strides[rank - 2])
    } else {
        (a.strides[rank - 2], a.strides[rank - 1])
    };
    let (b_k_stride, b_n_stride) = if trans_b {
        (b.strides[rank - 1], b.strides[rank - 2])
    } else {
        (b.strides[rank - 2], b.strides[rank - 1])
    };
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    uint inner = gid % {}u;\n",
        m as u64 * n as u64
    ));
    source.push_str(&format!("    uint m = inner / {n}u;\n"));
    source.push_str(&format!("    uint n = inner % {n}u;\n"));
    source.push_str(&format!(
        "    uint batch = gid / {}u;\n",
        m as u64 * n as u64
    ));
    let mut a_batch = vec!["0u".to_string()];
    let mut b_batch = vec!["0u".to_string()];
    let mut c_batch = vec!["0u".to_string()];
    if rank > 2 {
        source.push_str("    uint rem = batch;\n");
        for dimension in 0..rank - 2 {
            let size = plan.output.sizes[dimension];
            source.push_str(&format!("    uint bc{dimension} = rem % {size}u;\n"));
            source.push_str(&format!("    rem /= {size}u;\n"));
            a_batch.push(format!("bc{dimension} * {}u", a.strides[dimension]));
            b_batch.push(format!("bc{dimension} * {}u", b.strides[dimension]));
            if let Some(c) = plan.inputs.get(2) {
                c_batch.push(format!("bc{dimension} * {}u", c.strides[dimension]));
            }
        }
    }
    let a_batch_expr = a_batch.join(" + ");
    let b_batch_expr = b_batch.join(" + ");
    let c_batch_expr = c_batch.join(" + ");
    source.push_str("    float acc = 0.0f;\n");
    source.push_str(&format!("    for (uint kk = 0u; kk < {k}u; ++kk) {{\n"));
    let a_terms = format!("m * {a_m_stride}u + kk * {a_k_stride}u");
    let b_terms = format!("kk * {b_k_stride}u + n * {b_n_stride}u");
    source.push_str(&format!(
        "        uint a_idx = {a_batch_expr} + {a_terms};\n"
    ));
    source.push_str(&format!(
        "        uint b_idx = {b_batch_expr} + {b_terms};\n"
    ));
    source.push_str("        acc += float(in0[a_idx]) * float(in1[b_idx]);\n");
    source.push_str("    }\n");
    source.push_str(&format!("    float value = {} * acc;\n", msl_float(alpha)));
    if plan.inputs.len() == 3 {
        let c = &plan.inputs[2];
        source.push_str(&format!(
            "    uint c_idx = {c_batch_expr} + m * {}u + n * {}u;\n",
            c.strides[rank - 2],
            c.strides[rank - 1]
        ));
        source.push_str(&format!(
            "    value += {} * float(in2[c_idx]);\n",
            msl_float(beta)
        ));
    }
    source.push_str(&format!(
        "    out[{}] = ({scalar})value;\n",
        output_index_expr(&plan.output)
    ));
    source.push_str("}\n");
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
fn emit_convolution_msl(
    plan: &DmlOpPlan,
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
    let filter_index = format!(
        "o1 * {}u + cg * {}u + fy * {}u + fx * {}u",
        filter.strides[0], filter.strides[1], filter.strides[2], filter.strides[3]
    );
    source.push_str(&format!(
        "                acc += float(in0[{input_index}]) * float(in1[{filter_index}]);\n"
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

fn emit_pooling_msl(
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

fn emit_batch_normalization_msl(
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

fn emit_softmax_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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

fn emit_reduce_msl(plan: &DmlOpPlan, reduce: DmlReduceKind, axes: &[u32]) -> DmlResult<String> {
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

fn emit_reshape_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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

fn emit_transpose_msl(plan: &DmlOpPlan, permutation: &[u32]) -> DmlResult<String> {
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

fn emit_concat_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
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

fn emit_slice_msl(
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

/// Lower an extended operator to MSL source.
fn quantized_store(scalar: &str, value: &str) -> String {
    match scalar {
        "uchar" => format!("(uchar)clamp(rint({value}), 0.0f, 255.0f)"),
        "char" => format!("(char)clamp(rint({value}), -128.0f, 127.0f)"),
        other => format!("({other})({value})"),
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RecurrentExtras {
    linear_before_reset: bool,
    clip_threshold: f32,
    use_clip_threshold: bool,
    couple_input_forget: bool,
}

fn emit_arg_reduce_msl(
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

fn emit_padding_msl(
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

fn emit_resample_msl(
    plan: &DmlOpPlan,
    mode: DmlInterpolationMode,
    scales: &[f32],
    input_offsets: &[f32],
    output_offsets: &[f32],
    rounding: DmlAxisDirection,
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
    if mode == DmlInterpolationMode::NearestNeighbor {
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

fn emit_top_k_msl(
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

fn src_push_index_output(source: &mut String, plan: &DmlOpPlan, name: &str, value: &str) {
    let output = &plan.extra_outputs[0];
    let index = output_index_expr(output);
    // The coordinates were computed for the primary output, whose sizes match
    // the index tensor for all top-k shapes.
    source.push_str(&format!("    {name}[{index}] = {value};\n"));
}

fn emit_tile_msl(plan: &DmlOpPlan, repeats: &[u32]) -> DmlResult<String> {
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

fn emit_split_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
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

fn emit_gather_msl(plan: &DmlOpPlan, axis: u32, _index_dimensions: u32) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!("    int index = int(in1[o{axis}]);\n"));
    let mut coords = coord_names(input.sizes.len());
    let valid = format!("index >= 0 && index < {}", input.sizes[axis as usize]);
    coords[axis as usize] = "uint(index)".to_string();
    source.push_str(&format!(
        "    out[{}] = {valid} ? in0[{}] : ({scalar})0;\n",
        output_index_expr(&plan.output),
        linear_index(input, &coords)
    ));
    source.push_str("}\n");
    let _ = indices;
    Ok(source)
}

fn emit_gather_elements_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let index_coords = coord_names(indices.sizes.len());
    source.push_str(&format!(
        "    int index = int(in1[{}]);\n",
        linear_index(indices, &index_coords)
    ));
    let mut coords = coord_names(input.sizes.len());
    coords[axis as usize] = "uint(index)".to_string();
    source.push_str(&format!(
        "    out[{}] = (index >= 0 && index < {}) ? in0[{}] : ({scalar})0;\n",
        output_index_expr(&plan.output),
        input.sizes[axis as usize],
        linear_index(input, &coords)
    ));
    source.push_str("}\n");
    Ok(source)
}

fn emit_gather_nd_msl(
    plan: &DmlOpPlan,
    _input_dimension_count: u32,
    _indices_dimension_count: u32,
    _batch_dimension_count: u32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let indices_rank = indices.sizes.len();
    let indexed = indices.sizes[indices_rank - 1] as usize;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut input_coords = Vec::with_capacity(input.sizes.len());
    for dimension in 0..input.sizes.len() {
        if dimension < indexed {
            let mut idx_coords = vec![String::new(); indices_rank];
            for (position, coordinate) in idx_coords.iter_mut().take(indices_rank - 1).enumerate() {
                *coordinate = format!("o{position}");
            }
            idx_coords[indices_rank - 1] = format!("{dimension}u");
            let index_expr = linear_index(indices, &idx_coords);
            source.push_str(&format!("    int i{dimension} = int(in1[{index_expr}]);\n"));
            input_coords.push(format!(
                "uint(clamp(i{dimension}, 0, {}))",
                input.sizes[dimension] - 1
            ));
        } else {
            input_coords.push(format!("o{}", indices_rank - 1 + dimension - indexed));
        }
    }
    let mut valid_terms = Vec::new();
    for dimension in 0..indexed {
        valid_terms.push(format!(
            "i{dimension} >= 0 && i{dimension} < {}",
            input.sizes[dimension]
        ));
    }
    source.push_str(&format!(
        "    out[{}] = ({}) ? in0[{}] : ({scalar})0;\n",
        output_index_expr(&plan.output),
        valid_terms.join(" && "),
        linear_index(input, &input_coords)
    ));
    source.push_str("}\n");
    Ok(source)
}

fn emit_scatter_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let updates = &plan.inputs[2];
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    out[{}] = in0[{}];\n",
        output_index_expr(&plan.output),
        linear_index(input, &coord_names(input.sizes.len()))
    ));
    let axis_size = indices.sizes[axis as usize];
    source.push_str(&format!(
        "    for (uint i = 0u; i < {axis_size}u; ++i) {{\n"
    ));
    let mut index_coords = coord_names(indices.sizes.len());
    index_coords[axis as usize] = "i".to_string();
    let mut update_coords = coord_names(updates.sizes.len());
    update_coords[axis as usize] = "i".to_string();
    source.push_str(&format!(
        "        int index = int(in1[{}]);\n",
        linear_index(indices, &index_coords)
    ));
    source.push_str(&format!(
        "        if (index == int(o{axis})) out[{}] = in2[{}];\n",
        output_index_expr(&plan.output),
        linear_index(updates, &update_coords)
    ));
    source.push_str("    }\n}\n");
    Ok(source)
}

fn emit_scatter_nd_msl(
    plan: &DmlOpPlan,
    _input_dimension_count: u32,
    _indices_dimension_count: u32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let updates = &plan.inputs[2];
    let indices_rank = indices.sizes.len();
    let indexed = indices.sizes[indices_rank - 1] as usize;
    let update_count: u64 = indices.sizes[..indices_rank - 1]
        .iter()
        .map(|v| *v as u64)
        .product();
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    source.push_str(&format!(
        "    out[{}] = in0[{}];\n",
        output_index_expr(&plan.output),
        linear_index(input, &coord_names(input.sizes.len()))
    ));
    source.push_str(&format!(
        "    for (uint u = 0u; u < {update_count}u; ++u) {{\n"
    ));
    source.push_str("        uint rem = u;\n");
    let mut update_coords = Vec::with_capacity(indices_rank);
    for dimension in 0..indices_rank - 1 {
        let size = indices.sizes[dimension];
        source.push_str(&format!("        uint uc{dimension} = rem % {size}u;\n"));
        source.push_str(&format!("        rem /= {size}u;\n"));
        update_coords.push(format!("uc{dimension}"));
    }
    source.push_str("        bool match = true;\n");
    for dimension in 0..indexed {
        let mut index_coords = update_coords.clone();
        index_coords.push(format!("{dimension}u"));
        source.push_str(&format!(
            "        match = match && int(in1[{}]) == int(o{dimension});\n",
            linear_index(indices, &index_coords)
        ));
    }
    let mut update_data_coords = Vec::new();
    for dimension in 0..indices_rank - 1 {
        update_data_coords.push(format!("uc{dimension}"));
    }
    for dimension in indexed..updates.sizes.len() {
        update_data_coords.push(format!("o{dimension}"));
    }
    source.push_str(&format!(
        "        if (match) out[{}] = in2[{}];\n",
        output_index_expr(&plan.output),
        linear_index(updates, &update_data_coords)
    ));
    source.push_str("    }\n}\n");
    Ok(source)
}

fn emit_roi_pooling_msl(plan: &DmlOpPlan, spatial_scale: f32, pooled: &[u32]) -> DmlResult<String> {
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
fn emit_roi_align_msl(
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

fn emit_lrn_msl(
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

fn emit_mvn_msl(
    plan: &DmlOpPlan,
    axes: &[u32],
    normalize_variance: bool,
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
    source.push_str(&format!("    float mean = sum / {reduction_count}.0f;\n"));
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

fn broadcast_index_with(desc: &DmlTensorDesc, rank: usize) -> String {
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

fn emit_adam_msl(
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

fn emit_quantize_linear_msl(plan: &DmlOpPlan, dequantize: bool) -> DmlResult<String> {
    let out_scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let in_scalar = msl_scalar(plan.inputs[0].data_type, plan.operator_type())?;
    let mut source = msl_header_outputs(plan, in_scalar, &[out_scalar]);
    push_guard(&mut source, &plan.output);
    source.push_str("    float scale = float(in1[0]);\n");
    let zero_point = if plan.inputs.len() == 3 {
        "float(in2[0])"
    } else {
        "0.0f"
    };
    if dequantize {
        source.push_str(&format!(
            "    float value = (float(in0[gid]) - {zero_point}) * scale;\n"
        ));
    } else {
        source.push_str(&format!(
            "    float value = rint(float(in0[gid]) / scale) + {zero_point};\n"
        ));
    }
    source.push_str(&format!(
        "    out0[gid] = {};\n}}\n",
        quantized_store(out_scalar, "value")
    ));
    Ok(source)
}

fn emit_dynamic_quantize_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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

fn quantized_input_index(plan: &DmlOpPlan, role: &str) -> Option<usize> {
    plan.input_roles()
        .iter()
        .position(|candidate| *candidate == role)
}

fn emit_quantized_add_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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
    source.push_str(&format!(
        "    float a = (float(in{a_index}[gid]) - {}) * float(in{a_scale}[0]);\n",
        a_zero
            .map(|i| format!("float(in{i}[0])"))
            .unwrap_or_else(|| "0.0f".to_string())
    ));
    source.push_str(&format!(
        "    float b = (float(in{b_index}[gid]) - {}) * float(in{b_scale}[0]);\n",
        b_zero
            .map(|i| format!("float(in{i}[0])"))
            .unwrap_or_else(|| "0.0f".to_string())
    ));
    source.push_str(&format!(
        "    float value = (a + b) / float(in{out_scale}[0]) + {};\n",
        out_zero
            .map(|i| format!("float(in{i}[0])"))
            .unwrap_or_else(|| "0.0f".to_string())
    ));
    source.push_str(&format!(
        "    out0[gid] = {};\n}}\n",
        quantized_store(out_scalar, "value")
    ));
    Ok(source)
}

fn emit_integer_matmul_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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
        source.push_str(&format!("        av -= float(in{index}[0]);\n"));
    }
    if let Some(index) = b_zero {
        source.push_str(&format!("        bv -= float(in{index}[0]);\n"));
    }
    source.push_str("        acc += av * bv;\n    }\n");
    if *quantized_output {
        if let Some(index) = a_scale {
            source.push_str(&format!("    acc *= float(in{index}[0]);\n"));
        }
        if let Some(index) = b_scale {
            source.push_str(&format!("    acc *= float(in{index}[0]);\n"));
        }
        if let Some(index) = out_scale {
            source.push_str(&format!("    acc /= float(in{index}[0]);\n"));
        }
        if let Some(index) = out_zero {
            source.push_str(&format!("    acc += float(in{index}[0]);\n"));
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

fn emit_integer_matmul_to_float_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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
    if let Some(index) = a_zero {
        source.push_str(&format!("        av -= float(in{index}[0]);\n"));
    }
    if let Some(index) = b_zero {
        source.push_str(&format!("        bv -= float(in{index}[0]);\n"));
    }
    source.push_str("        acc += av * bv;\n    }\n");
    if let Some(index) = a_scale {
        source.push_str(&format!("    acc *= float(in{index}[0]);\n"));
    }
    if let Some(index) = b_scale {
        source.push_str(&format!("    acc *= float(in{index}[0]);\n"));
    }
    if let Some(index) = bias {
        let bias_index = if plan.inputs[index].element_count() == 1 {
            "0u".to_string()
        } else {
            "n".to_string()
        };
        source.push_str(&format!("    acc += float(in{index}[{bias_index}]);\n"));
    }
    source.push_str(&format!(
        "    out0[{}] = acc;\n}}\n",
        output_index_expr(&plan.output)
    ));
    Ok(source)
}

fn emit_integer_convolution_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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
    if let Some(index) = input_zero {
        source.push_str(&format!("                av -= float(in{index}[0]);\n"));
    }
    if let Some(index) = filter_zero {
        source.push_str(&format!("                bv -= float(in{index}[0]);\n"));
    }
    source.push_str("                acc += av * bv;\n            }\n        }\n    }\n");
    if *quantized_output {
        if let Some(index) = input_scale {
            source.push_str(&format!("    acc *= float(in{index}[0]);\n"));
        }
        if let Some(index) = filter_scale {
            source.push_str(&format!("    acc *= float(in{index}[0]);\n"));
        }
        if let Some(index) = bias_index {
            source.push_str(&format!("    acc += float(in{index}[o1]);\n"));
        }
        if let Some(index) = out_scale {
            source.push_str(&format!("    acc /= float(in{index}[0]);\n"));
        }
        if let Some(index) = out_zero {
            source.push_str(&format!("    acc += float(in{index}[0]);\n"));
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

fn emit_quantized_avg_pool_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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
    source.push_str(&format!(
        "            float value = (float(in0[o0 * {}u + o1 * {}u + uint(iy) * {}u + uint(ix) * {}u]) - {}) * float(in{input_scale}[0]);\n",
        input.strides[0], input.strides[1], input.strides[2], input.strides[3],
        input_zero.map(|i| format!("float(in{i}[0])")).unwrap_or_else(|| "0.0f".to_string())
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
        "    float value = mean / float(in{out_scale}[0]) + {};\n",
        out_zero
            .map(|i| format!("float(in{i}[0])"))
            .unwrap_or_else(|| "0.0f".to_string())
    ));
    source.push_str(&format!(
        "    out0[{}] = {};\n}}\n",
        output_index_expr(&plan.output),
        quantized_store(out_scalar, "value")
    ));
    Ok(source)
}

fn emit_generic_quantize_msl(
    plan: &DmlOpPlan,
    quantization_type: u32,
    dequantize: bool,
) -> DmlResult<String> {
    let out_scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let in_scalar = msl_scalar(plan.inputs[0].data_type, plan.operator_type())?;
    let mut source = msl_header_outputs(plan, in_scalar, &[out_scalar]);
    push_guard(&mut source, &plan.output);
    let scale = if quantization_type >= 1 {
        "float(in1[0])"
    } else {
        "1.0f"
    };
    let zero = if quantization_type == 2 {
        "float(in2[0])"
    } else {
        "0.0f"
    };
    if dequantize {
        source.push_str(&format!(
            "    float value = (float(in0[gid]) - {zero}) * {scale};\n"
        ));
    } else {
        source.push_str(&format!(
            "    float value = rint(float(in0[gid]) / {scale}) + {zero};\n"
        ));
    }
    source.push_str(&format!(
        "    out0[gid] = {};\n}}\n",
        quantized_store(out_scalar, "value")
    ));
    Ok(source)
}

fn recurrent_activation(
    activations: &[DmlActivation],
    index: usize,
    default: DmlActivation,
) -> DmlActivation {
    activations.get(index).copied().unwrap_or(default)
}

#[allow(clippy::too_many_arguments)]
fn emit_recurrent_msl(
    plan: &DmlOpPlan,
    ty: u32,
    direction: DmlRecurrentDirection,
    activations: &[DmlActivation],
    options: DmlRecurrentOptions,
    outputs: &[DmlRecurrentOutput],
    extras: RecurrentExtras,
) -> DmlResult<String> {
    let _ = direction;
    let input = &plan.inputs[0];
    let weight = &plan.inputs[1];
    let recurrence = &plan.inputs[2];
    let [sequence, batch_size, input_size] = [input.sizes[0], input.sizes[1], input.sizes[2]];
    let hidden = weight.sizes[1];
    let hidden_usize = hidden as usize;
    let scalars = vec!["float"; plan.output_count()];
    let mut source = msl_header_outputs(plan, "float", &scalars);
    source.push_str("    uint b = gid;\n");
    source.push_str(&format!(
        "    if (b >= {batch_size}u) return;\n    uint hidden = {hidden}u;\n"
    ));
    source.push_str(&format!(
        "    uint h0 = b * hidden;\n    uint h1 = ({batch_size}u + b) * hidden;\n    uint c0 = (2u * {batch_size}u + b) * hidden;\n    uint gate_base = (3u * {batch_size}u) * hidden + b * hidden * 4u;\n"
    ));
    let bias_index = if options.bias { Some(3) } else { None };
    let hidden_init_index = 3 + usize::from(options.bias);
    let cell_init_index = hidden_init_index + usize::from(options.hidden_init);
    let sequence_lengths_index = cell_init_index + usize::from(options.cell_init);

    source.push_str("    for (uint j = 0u; j < hidden; ++j) {\n");
    if options.hidden_init {
        source.push_str(&format!(
            "        scratch[h0 + j] = float(in{hidden_init_index}[b * hidden + j]);\n"
        ));
    } else {
        source.push_str("        scratch[h0 + j] = 0.0f;\n");
    }
    if options.cell_init {
        source.push_str(&format!(
            "        scratch[c0 + j] = float(in{cell_init_index}[b * hidden + j]);\n"
        ));
    } else {
        source.push_str("        scratch[c0 + j] = 0.0f;\n");
    }
    source.push_str("    }\n");
    if options.sequence_lengths {
        source.push_str(&format!(
            "    uint t_end = min({sequence}u, uint(max(int(in{sequence_lengths_index}[b]), 0)));\n"
        ));
    } else {
        source.push_str(&format!("    uint t_end = {sequence}u;\n"));
    }
    let sequence_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::Sequence)
        .map(|index| format!("out{index}"));
    let single_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::Single)
        .map(|index| format!("out{index}"));
    let cell_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::CellSingle)
        .map(|index| format!("out{index}"));
    source.push_str(&format!("    for (uint t = 0u; t < {sequence}u; ++t) {{\n"));
    source.push_str("        if (t < t_end) {\n");
    match ty {
        DML_OPERATOR_RNN => {
            let activation = recurrent_activation(activations, 0, DmlActivation::Tanh);
            source.push_str("            for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str(&format!(
                "                float sum = 0.0f;\n                for (uint i = 0u; i < {input_size}u; ++i) sum += float(in0[(t * {batch_size}u + b) * {input_size}u + i]) * float(in1[j * {}u + i * {}u]);\n",
                weight.strides[1], weight.strides[2]
            ));
            source.push_str(&format!(
                "                for (uint i = 0u; i < hidden; ++i) sum += scratch[h0 + i] * float(in2[j * {}u + i * {}u]);\n",
                recurrence.strides[1], recurrence.strides[2]
            ));
            if let Some(index) = bias_index {
                source.push_str(&format!("                sum += float(in{index}[j]);\n"));
            }
            source.push_str(&format!(
                "                scratch[h1 + j] = {};\n            }}\n",
                activation_msl(activation, 0.0, "sum")
            ));
        }
        DML_OPERATOR_GRU => {
            let gate_activation = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
            let candidate_activation = recurrent_activation(activations, 1, DmlActivation::Tanh);
            source.push_str("            for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str(&format!(
                "                float z = 0.0f, r = 0.0f;\n                for (uint i = 0u; i < {input_size}u; ++i) {{ float xv = float(in0[(t * {batch_size}u + b) * {input_size}u + i]); z += xv * float(in1[j * {}u + i * {}u]); r += xv * float(in1[(hidden + j) * {}u + i * {}u]); }}\n",
                weight.strides[1], weight.strides[2], weight.strides[1], weight.strides[2]
            ));
            source.push_str(&format!(
                "                for (uint i = 0u; i < hidden; ++i) {{ float hv = scratch[h0 + i]; z += hv * float(in2[j * {}u + i * {}u]); r += hv * float(in2[(hidden + j) * {}u + i * {}u]); }}\n",
                recurrence.strides[1], recurrence.strides[2], recurrence.strides[1], recurrence.strides[2]
            ));
            if let Some(index) = bias_index {
                source.push_str(&format!(
                    "                z += float(in{index}[j]); r += float(in{index}[hidden + j]);\n"
                ));
            }
            source.push_str(&format!(
                "                z = {}; r = {};\n                scratch[gate_base + j] = z; scratch[gate_base + hidden + j] = r;\n",
                activation_msl(gate_activation, 0.0, "z"),
                activation_msl(gate_activation, 0.0, "r")
            ));
            source.push_str("            }\n");
            source.push_str("            for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str("                float reset = scratch[gate_base + hidden + j];\n");
            source.push_str(&format!(
                "                float candidate = 0.0f;\n                for (uint i = 0u; i < {input_size}u; ++i) candidate += float(in0[(t * {batch_size}u + b) * {input_size}u + i]) * float(in1[(2u * hidden + j) * {}u + i * {}u]);\n",
                weight.strides[1], weight.strides[2]
            ));
            if extras.linear_before_reset {
                source.push_str(&format!(
                    "                for (uint i = 0u; i < hidden; ++i) candidate += scratch[h0 + i] * float(in2[(2u * hidden + j) * {}u + i * {}u]);\n",
                    recurrence.strides[1], recurrence.strides[2]
                ));
                if let Some(index) = bias_index {
                    source.push_str(&format!(
                        "                candidate += float(in{index}[2u * hidden + j]);\n"
                    ));
                }
                source.push_str(&format!(
                    "                candidate = {};\n",
                    activation_msl(candidate_activation, 0.0, "candidate")
                ));
            } else {
                source.push_str(&format!(
                    "                float recurrent = 0.0f;\n                for (uint i = 0u; i < hidden; ++i) recurrent += scratch[h0 + i] * float(in2[(2u * hidden + j) * {}u + i * {}u]);\n",
                    recurrence.strides[1], recurrence.strides[2]
                ));
                if let Some(index) = bias_index {
                    source.push_str(&format!(
                        "                candidate += float(in{index}[2u * hidden + j]);\n"
                    ));
                }
                source.push_str(&format!(
                    "                candidate = {};\n",
                    activation_msl(candidate_activation, 0.0, "candidate + reset * recurrent")
                ));
            }
            source.push_str("                float update = scratch[gate_base + j];\n");
            source.push_str("                scratch[h1 + j] = (1.0f - update) * scratch[h0 + j] + update * candidate;\n            }\n");
        }
        _ => {
            let gate_activation = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
            let cell_activation = recurrent_activation(activations, 1, DmlActivation::Tanh);
            let output_activation = recurrent_activation(activations, 2, DmlActivation::Tanh);
            let gate_names = ["i_gate", "o_gate", "f_gate", "c_gate"];
            source.push_str("            for (uint j = 0u; j < hidden; ++j) {\n");
            for (gate, name) in gate_names.iter().enumerate() {
                source.push_str(&format!("                float {name} = 0.0f;\n"));
                source.push_str(&format!(
                    "                for (uint i = 0u; i < {input_size}u; ++i) {name} += float(in0[(t * {batch_size}u + b) * {input_size}u + i]) * float(in1[({gate}u * hidden + j) * {}u + i * {}u]);\n",
                    weight.strides[1], weight.strides[2]
                ));
                source.push_str(&format!(
                    "                for (uint i = 0u; i < hidden; ++i) {name} += scratch[h0 + i] * float(in2[({gate}u * hidden + j) * {}u + i * {}u]);\n",
                    recurrence.strides[1], recurrence.strides[2]
                ));
                if let Some(index) = bias_index {
                    source.push_str(&format!(
                        "                {name} += float(in{index}[{}u * hidden + j]);\n",
                        gate
                    ));
                }
            }
            source.push_str(&format!(
                "                i_gate = {};\n                f_gate = {};\n                c_gate = {};\n                o_gate = {};\n",
                activation_msl(gate_activation, 0.0, "i_gate"),
                activation_msl(gate_activation, 0.0, "f_gate"),
                activation_msl(cell_activation, 0.0, "c_gate"),
                activation_msl(gate_activation, 0.0, "o_gate")
            ));
            if extras.couple_input_forget {
                source.push_str("                f_gate = 1.0f - i_gate;\n");
            }
            source.push_str(
                "                float cell = f_gate * scratch[c0 + j] + i_gate * c_gate;\n",
            );
            if extras.use_clip_threshold {
                source.push_str(&format!(
                    "                cell = clamp(cell, -{}, {});\n",
                    msl_float(extras.clip_threshold),
                    msl_float(extras.clip_threshold)
                ));
            }
            source.push_str(&format!(
                "                scratch[gate_base + j] = cell;\n                scratch[h1 + j] = o_gate * {};\n            }}\n",
                activation_msl(output_activation, 0.0, "cell")
            ));
        }
    }
    source.push_str("        } else {\n            for (uint j = 0u; j < hidden; ++j) scratch[h1 + j] = scratch[h0 + j];\n        }\n");
    if let Some(sequence_output) = &sequence_output {
        source.push_str("        for (uint j = 0u; j < hidden; ++j) {\n");
        source.push_str(&format!(
            "            {sequence_output}[(t * {batch_size}u + b) * hidden + j] = scratch[h1 + j];\n"
        ));
        source.push_str("        }\n");
    }
    source.push_str(
        "        for (uint j = 0u; j < hidden; ++j) scratch[h0 + j] = scratch[h1 + j];\n",
    );
    if ty == DML_OPERATOR_LSTM {
        source.push_str("        if (t < t_end) for (uint j = 0u; j < hidden; ++j) scratch[c0 + j] = scratch[gate_base + j];\n");
    }
    source.push_str("    }\n");
    if let Some(single_output) = &single_output {
        source.push_str(&format!(
            "    for (uint j = 0u; j < hidden; ++j) {single_output}[b * hidden + j] = scratch[h0 + j];\n"
        ));
    }
    if let Some(cell_output) = &cell_output {
        source.push_str(&format!(
            "    for (uint j = 0u; j < hidden; ++j) {cell_output}[b * hidden + j] = scratch[c0 + j];\n"
        ));
    }
    let _ = hidden_usize;
    source.push_str("}\n");
    Ok(source)
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
            strides,
            dilations,
            start_padding,
            group_count,
            ..
        } => emit_convolution_msl(plan, strides, dilations, start_padding, *group_count),
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
            ..
        } => emit_resample_msl(
            plan,
            *mode,
            scales,
            input_offsets,
            output_offsets,
            *rounding,
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
            epsilon,
        } => emit_mvn_msl(plan, axes, *normalize_variance, *epsilon),
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
    }?;
    if let Some(activation) = plan.fused_activation {
        let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
        inject_fused_activation(&mut source, scalar, activation);
    }
    Ok(source)
}

/// Compile the emitted MSL into a real Metal compute pipeline.
pub fn compile_msl(source: &str) -> DmlResult<()> {
    let device = MetalDevice::system_default().map_err(|error| {
        DmlError::unsupported_feature(format!("no Metal device available: {error}"))
    })?;
    let library = device
        .compile_shader_library(source)
        .map_err(|error| DmlError::new(E_FAIL, format!("Metal compilation failed: {error}")))?;
    let function = library
        .get_function("dml_op", None)
        .map_err(|error| DmlError::new(E_FAIL, format!("dml_op function missing: {error}")))?;
    device
        .metal_device()
        .new_compute_pipeline_state_with_function(&function)
        .map_err(|error| DmlError::new(E_FAIL, format!("pipeline creation failed: {error}")))?;
    Ok(())
}

/// Execute a validated operator plan on the selected backend.
pub fn execute_plan(
    plan: &DmlOpPlan,
    backend: DmlExecutionDevice,
    inputs: &[&[u8]],
    output: &mut [u8],
) -> DmlResult<()> {
    let mut outputs = [output];
    execute_plan_outputs(plan, backend, inputs, &mut outputs)
}

/// Execute a validated operator plan with one buffer per output tensor.
///
/// Multi-output operators (split, top-k, dynamic quantize, recurrent networks,
/// Adam) require exactly [`DmlOpPlan::output_count`] buffers.
pub fn execute_plan_outputs(
    plan: &DmlOpPlan,
    backend: DmlExecutionDevice,
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) -> DmlResult<()> {
    plan.validate()?;
    let roles = plan.input_roles();
    if inputs.len() != plan.inputs.len() {
        return Err(DmlError::invalid(format!(
            "operator expects {} input buffers, got {}",
            plan.inputs.len(),
            inputs.len()
        )));
    }
    for (index, (buffer, desc)) in inputs.iter().zip(&plan.inputs).enumerate() {
        let required = desc.total_size_in_bytes as usize;
        if buffer.len() < required {
            return Err(DmlError::invalid(format!(
                "input {} buffer is {} bytes, tensor requires {required}",
                roles[index],
                buffer.len()
            )));
        }
    }
    if outputs.len() != plan.output_count() {
        return Err(DmlError::invalid(format!(
            "operator expects {} output buffers, got {}",
            plan.output_count(),
            outputs.len()
        )));
    }
    let output_roles = plan.output_roles();
    for (index, (output, desc)) in outputs.iter().zip(plan.outputs()).enumerate() {
        let required = desc.total_size_in_bytes as usize;
        if output.len() < required {
            let label = if index == 0 && output_roles[index] == "output" {
                "output".to_string()
            } else {
                format!("output {}", output_roles[index])
            };
            return Err(DmlError::invalid(format!(
                "{label} buffer is {} bytes, tensor requires {required}",
                output.len()
            )));
        }
    }
    match backend {
        DmlExecutionDevice::Metal => execute_metal(plan, inputs, outputs),
        DmlExecutionDevice::Cpu => execute_cpu(plan, inputs, outputs),
    }
}

fn execute_metal(plan: &DmlOpPlan, inputs: &[&[u8]], outputs: &mut [&mut [u8]]) -> DmlResult<()> {
    let device = MetalDevice::system_default().map_err(|error| {
        DmlError::unsupported_feature(format!("no Metal device available: {error}"))
    })?;
    let source = emit_msl(plan)?;
    let library = device
        .compile_shader_library(&source)
        .map_err(|error| DmlError::new(E_FAIL, error.to_string()))?;
    let function = library
        .get_function("dml_op", None)
        .map_err(|error| DmlError::new(E_FAIL, format!("dml_op not found: {error}")))?;
    let pipeline = device
        .metal_device()
        .new_compute_pipeline_state_with_function(&function)
        .map_err(|error| DmlError::new(E_FAIL, format!("pipeline creation failed: {error}")))?;
    let queue = device.create_command_queue();
    let input_buffers: Vec<_> = inputs
        .iter()
        .zip(&plan.inputs)
        .map(|(data, desc)| {
            let length = desc.total_size_in_bytes as usize;
            device.create_buffer_with_data(
                &data[..length],
                metal::MTLResourceOptions::StorageModeShared,
            )
        })
        .collect();
    let output_buffers: Vec<_> = plan
        .outputs()
        .map(|desc| {
            device.create_buffer(
                desc.total_size_in_bytes,
                metal::MTLResourceOptions::StorageModeShared,
            )
        })
        .collect();
    let scratch_buffer = match plan.kind {
        DmlOpKind::Rnn { .. } | DmlOpKind::Gru { .. } | DmlOpKind::Lstm { .. } => {
            let batch = plan.inputs[0].sizes[1] as u64;
            let hidden = plan.inputs[1].sizes[1] as u64;
            Some(device.create_buffer(
                batch * hidden * 7 * 4,
                metal::MTLResourceOptions::StorageModeShared,
            ))
        }
        _ => None,
    };
    let command_buffer = queue.new_command_buffer();
    {
        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&pipeline);
        for (index, buffer) in input_buffers.iter().enumerate() {
            encoder.set_buffer(index as u64, Some(buffer), 0);
        }
        let output_start = input_buffers.len() as u64;
        for (index, buffer) in output_buffers.iter().enumerate() {
            encoder.set_buffer(output_start + index as u64, Some(buffer), 0);
        }
        if let Some(scratch) = &scratch_buffer {
            encoder.set_buffer(output_start + output_buffers.len() as u64, Some(scratch), 0);
        }
        let count = plan.dispatch_count();
        let max_threads = pipeline.max_total_threads_per_threadgroup();
        let threadgroup = max_threads.clamp(1, 256);
        encoder.dispatch_threads(
            metal::MTLSize::new(count, 1, 1),
            metal::MTLSize::new(threadgroup, 1, 1),
        );
        encoder.end_encoding();
    }
    command_buffer.commit();
    command_buffer.wait_until_completed();
    if command_buffer.status() == metal::MTLCommandBufferStatus::Error {
        return Err(DmlError::new(
            E_FAIL,
            "Metal command buffer failed while executing the DirectML operator",
        ));
    }
    for (output, buffer) in outputs.iter_mut().zip(&output_buffers) {
        let length = buffer.length() as usize;
        let contents =
            unsafe { std::slice::from_raw_parts(buffer.contents() as *const u8, length) };
        output[..length].copy_from_slice(contents);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CPU execution (only for an explicit CPU device)
// ---------------------------------------------------------------------------

/// Convert raw FLOAT16 bits to FLOAT32 (used by guest descriptor parsing).
pub fn f16_bits_to_f32(bits: u16) -> f32 {
    f16_to_f32(bits)
}

fn f16_to_f32(bits: u16) -> f32 {
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

fn f32_to_f16(value: f32) -> u16 {
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

fn load_scalar(bytes: &[u8], index: u64, data_type: u32) -> f32 {
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
        _ => 0.0,
    }
}

fn load_integer(bytes: &[u8], index: u64, data_type: u32) -> i64 {
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

fn store_integer(bytes: &mut [u8], index: u64, data_type: u32, value: i64) {
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

fn store_quantized(bytes: &mut [u8], index: u64, data_type: u32, value: f32) {
    let index = index as usize;
    match data_type {
        DML_TENSOR_DATA_TYPE_UINT8 => {
            bytes[index] = value.round_ties_even().clamp(0.0, 255.0) as u8;
        }
        DML_TENSOR_DATA_TYPE_INT8 => {
            bytes[index] = value.round_ties_even().clamp(-128.0, 127.0) as i8 as u8;
        }
        _ => store_scalar(bytes, index as u64, data_type, value),
    }
}

fn store_scalar(bytes: &mut [u8], index: u64, data_type: u32, value: f32) {
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

fn coords_of(mut linear: u64, sizes: &[u32]) -> Vec<u64> {
    let mut coords = vec![0u64; sizes.len()];
    for index in (0..sizes.len()).rev() {
        coords[index] = linear % sizes[index] as u64;
        linear /= sizes[index] as u64;
    }
    coords
}

fn index_of(coords: &[u64], strides: &[u32]) -> u64 {
    coords
        .iter()
        .zip(strides)
        .map(|(coord, stride)| coord * *stride as u64)
        .sum()
}

fn output_index(desc: &DmlTensorDesc, gid: u64) -> u64 {
    if desc.is_contiguous() {
        gid
    } else {
        index_of(&coords_of(gid, &desc.sizes), &desc.strides)
    }
}

fn execute_cpu(plan: &DmlOpPlan, inputs: &[&[u8]], outputs: &mut [&mut [u8]]) -> DmlResult<()> {
    let (primary, extras) = outputs.split_first_mut().expect("output count validated");
    let output = &mut **primary;
    let dtype = plan.output.data_type;
    let count = plan.output.element_count();
    match &plan.kind {
        DmlOpKind::Gemm {
            trans_a,
            trans_b,
            alpha,
            beta,
        } => {
            let a = &plan.inputs[0];
            let b = &plan.inputs[1];
            let rank = a.sizes.len();
            let k = if *trans_a {
                a.sizes[rank - 2]
            } else {
                a.sizes[rank - 1]
            };
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let batch = coords[..rank - 2].to_vec();
                let m_index = coords[rank - 2];
                let n_index = coords[rank - 1];
                let mut acc = 0.0f64;
                for kk in 0..k as u64 {
                    let mut a_coords = batch.clone();
                    if *trans_a {
                        a_coords.push(kk);
                        a_coords.push(m_index);
                    } else {
                        a_coords.push(m_index);
                        a_coords.push(kk);
                    }
                    let mut b_coords = batch.clone();
                    if *trans_b {
                        b_coords.push(n_index);
                        b_coords.push(kk);
                    } else {
                        b_coords.push(kk);
                        b_coords.push(n_index);
                    }
                    acc += load_scalar(inputs[0], index_of(&a_coords, &a.strides), dtype) as f64
                        * load_scalar(inputs[1], index_of(&b_coords, &b.strides), dtype) as f64;
                }
                let mut value = *alpha as f64 * acc;
                if plan.inputs.len() == 3 {
                    value += *beta as f64
                        * load_scalar(inputs[2], index_of(&coords, &plan.inputs[2].strides), dtype)
                            as f64;
                }
                store_scalar(output, output_index(&plan.output, gid), dtype, value as f32);
            }
        }
        DmlOpKind::Convolution {
            strides,
            dilations,
            start_padding,
            group_count,
            ..
        } => {
            let input = &plan.inputs[0];
            let filter = &plan.inputs[1];
            let channels_per_group = input.sizes[1] / group_count;
            let filters_per_group = plan.output.sizes[1] / group_count;
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let [batch, out_channel, oh, ow] = [coords[0], coords[1], coords[2], coords[3]];
                let group = out_channel / filters_per_group as u64;
                let mut acc = 0.0f64;
                for cg in 0..channels_per_group as u64 {
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
                            let input_coords = [
                                batch,
                                group * channels_per_group as u64 + cg,
                                iy as u64,
                                ix as u64,
                            ];
                            let filter_coords = [out_channel, cg, fy, fx];
                            acc += load_scalar(
                                inputs[0],
                                index_of(&input_coords, &input.strides),
                                dtype,
                            ) as f64
                                * load_scalar(
                                    inputs[1],
                                    index_of(&filter_coords, &filter.strides),
                                    dtype,
                                ) as f64;
                        }
                    }
                }
                if plan.inputs.len() == 3 {
                    acc += load_scalar(inputs[2], out_channel, dtype) as f64;
                }
                store_scalar(output, output_index(&plan.output, gid), dtype, acc as f32);
            }
        }
        DmlOpKind::Pooling {
            kind,
            strides,
            window,
            start_padding,
            include_padding,
            ..
        } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let [batch, channel, oh, ow] = [coords[0], coords[1], coords[2], coords[3]];
                let mut sum = 0.0f64;
                let mut valid = 0u64;
                let mut best = f32::NEG_INFINITY;
                let mut saw_nan = false;
                for wy in 0..window[0] as u64 {
                    let iy = oh as i64 * strides[0] as i64 - start_padding[0] as i64 + wy as i64;
                    if iy < 0 || iy >= input.sizes[2] as i64 {
                        continue;
                    }
                    for wx in 0..window[1] as u64 {
                        let ix =
                            ow as i64 * strides[1] as i64 - start_padding[1] as i64 + wx as i64;
                        if ix < 0 || ix >= input.sizes[3] as i64 {
                            continue;
                        }
                        let input_coords = [batch, channel, iy as u64, ix as u64];
                        let value =
                            load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype);
                        if value.is_nan() {
                            saw_nan = true;
                        }
                        if *kind == DmlPoolingKind::Max {
                            if !value.is_nan() {
                                best = best.max(value);
                            }
                        } else {
                            sum += value as f64;
                        }
                        valid += 1;
                    }
                }
                let value = if *kind == DmlPoolingKind::Max {
                    if saw_nan { f32::NAN } else { best }
                } else if valid == 0 {
                    0.0
                } else if *include_padding {
                    (sum / (window[0] as u64 * window[1] as u64) as f64) as f32
                } else {
                    (sum / valid as f64) as f32
                };
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::Activation { activation, alpha } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let value = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
                let _ = alpha;
                let value = activation_cpu(*activation, value);
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::BatchNormalization { spatial, epsilon } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let x = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
                let parameter_coords: Vec<u64> = if *spatial {
                    coords
                        .iter()
                        .enumerate()
                        .map(|(dimension, coord)| if dimension == 1 { *coord } else { 0 })
                        .collect()
                } else {
                    coords.clone()
                };
                let mean = load_scalar(
                    inputs[1],
                    index_of(&parameter_coords, &plan.inputs[1].strides),
                    dtype,
                );
                let variance = load_scalar(
                    inputs[2],
                    index_of(&parameter_coords, &plan.inputs[2].strides),
                    dtype,
                );
                let scale = load_scalar(
                    inputs[3],
                    index_of(&parameter_coords, &plan.inputs[3].strides),
                    dtype,
                );
                let bias = load_scalar(
                    inputs[4],
                    index_of(&parameter_coords, &plan.inputs[4].strides),
                    dtype,
                );
                let value = (x - mean) * (variance + epsilon).sqrt().recip() * scale + bias;
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::Softmax => {
            let input = &plan.inputs[0];
            let rank = input.sizes.len();
            let axis = input.sizes[rank - 1] as u64;
            let rows = count / axis;
            for row in 0..rows {
                let base_coords = coords_of(row, &input.sizes[..rank - 1]);
                let input_base = index_of(&base_coords, &input.strides[..rank - 1]);
                let mut max_value = f32::NEG_INFINITY;
                for j in 0..axis {
                    let value = load_scalar(
                        inputs[0],
                        input_base + j * input.strides[rank - 1] as u64,
                        dtype,
                    );
                    max_value = max_value.max(value);
                }
                let mut sum = 0.0f64;
                for j in 0..axis {
                    let value = load_scalar(
                        inputs[0],
                        input_base + j * input.strides[rank - 1] as u64,
                        dtype,
                    );
                    sum += ((value - max_value) as f64).exp();
                }
                let mut output_coords = base_coords.clone();
                for j in 0..axis {
                    output_coords.push(j);
                    let output_index = index_of(&output_coords, &plan.output.strides);
                    output_coords.pop();
                    let value = load_scalar(
                        inputs[0],
                        input_base + j * input.strides[rank - 1] as u64,
                        dtype,
                    );
                    store_scalar(
                        output,
                        output_index,
                        dtype,
                        (((value - max_value) as f64).exp() / sum) as f32,
                    );
                }
            }
        }
        DmlOpKind::Binary { op } => {
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
                let left = load_scalar(inputs[0], index_of(&a_coords, &a.strides), dtype);
                let right = load_scalar(inputs[1], index_of(&b_coords, &b.strides), dtype);
                let value = match op {
                    DmlBinaryOp::Add => left + right,
                    DmlBinaryOp::Subtract => left - right,
                    DmlBinaryOp::Multiply => left * right,
                    DmlBinaryOp::Divide => left / right,
                    DmlBinaryOp::Min => left.min(right),
                    DmlBinaryOp::Max => left.max(right),
                    DmlBinaryOp::Pow => left.powf(right),
                };
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::Reduce { reduce, axes } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let reduction_count: u64 = axes
                    .iter()
                    .map(|axis| input.sizes[*axis as usize] as u64)
                    .product();
                let mut sum = if *reduce == DmlReduceKind::Multiply {
                    1.0f64
                } else {
                    0.0f64
                };
                let mut best = if *reduce == DmlReduceKind::Min {
                    f32::INFINITY
                } else {
                    f32::NEG_INFINITY
                };
                let mut lse = f64::NEG_INFINITY;
                let mut saw_nan = false;
                for reduced in 0..reduction_count {
                    let mut input_coords = coords.clone();
                    let mut remainder = reduced;
                    for axis in axes {
                        let axis = *axis as usize;
                        input_coords[axis] = remainder % input.sizes[axis] as u64;
                        remainder /= input.sizes[axis] as u64;
                    }
                    let value =
                        load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype);
                    if value.is_nan() {
                        saw_nan = true;
                    }
                    match reduce {
                        DmlReduceKind::Sum
                        | DmlReduceKind::Mean
                        | DmlReduceKind::LogSum
                        | DmlReduceKind::LogSumExp => sum += value as f64,
                        DmlReduceKind::Multiply => sum *= value as f64,
                        DmlReduceKind::SumSquare | DmlReduceKind::L2 => {
                            sum += (value as f64) * (value as f64)
                        }
                        DmlReduceKind::L1 => sum += (value as f64).abs(),
                        DmlReduceKind::Max => {
                            if !value.is_nan() {
                                best = best.max(value);
                            }
                        }
                        DmlReduceKind::Min => {
                            if !value.is_nan() {
                                best = best.min(value);
                            }
                        }
                        DmlReduceKind::ArgMin | DmlReduceKind::ArgMax => {
                            return Err(DmlError::invalid(
                                "DML_REDUCE_FUNCTION argmin/argmax is not lowered through DML_OPERATOR_REDUCE",
                            ));
                        }
                    }
                    if *reduce == DmlReduceKind::LogSumExp && !value.is_nan() {
                        let current = value as f64;
                        lse = if lse > current {
                            lse + (current - lse).exp().ln_1p()
                        } else if lse.is_infinite() && lse.is_sign_negative() {
                            current
                        } else {
                            current + (lse - current).exp().ln_1p()
                        };
                    }
                }
                let value = match reduce {
                    DmlReduceKind::Sum => sum as f32,
                    DmlReduceKind::Mean => (sum / reduction_count as f64) as f32,
                    DmlReduceKind::Multiply => sum as f32,
                    DmlReduceKind::SumSquare => sum as f32,
                    DmlReduceKind::L1 => sum as f32,
                    DmlReduceKind::L2 => sum.sqrt() as f32,
                    DmlReduceKind::LogSum => (sum as f32).ln(),
                    DmlReduceKind::LogSumExp => {
                        if saw_nan {
                            f32::NAN
                        } else {
                            lse as f32
                        }
                    }
                    DmlReduceKind::Max => {
                        if saw_nan {
                            f32::NAN
                        } else {
                            best
                        }
                    }
                    DmlReduceKind::Min => {
                        if saw_nan {
                            f32::NAN
                        } else {
                            best
                        }
                    }
                    DmlReduceKind::ArgMin | DmlReduceKind::ArgMax => {
                        return Err(DmlError::invalid(
                            "DML_REDUCE_FUNCTION argmin/argmax is not lowered through DML_OPERATOR_REDUCE",
                        ));
                    }
                };
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::Reshape => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let input_coords = coords_of(gid, &input.sizes);
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype),
                );
            }
        }
        DmlOpKind::Transpose { permutation } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let output_coords = coords_of(gid, &plan.output.sizes);
                let mut input_coords = vec![0u64; permutation.len()];
                for (output_dimension, input_dimension) in permutation.iter().enumerate() {
                    input_coords[*input_dimension as usize] = output_coords[output_dimension];
                }
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype),
                );
            }
        }
        DmlOpKind::Concat { axis } => {
            let axis = *axis as usize;
            let mut offsets = Vec::with_capacity(plan.inputs.len());
            let mut offset = 0u64;
            for input in &plan.inputs {
                offsets.push(offset);
                offset += input.sizes[axis] as u64;
            }
            for gid in 0..count {
                let output_coords = coords_of(gid, &plan.output.sizes);
                let position = output_coords[axis];
                let mut selected = 0;
                for (index, input) in plan.inputs.iter().enumerate() {
                    if position < offsets[index] + input.sizes[axis] as u64 {
                        selected = index;
                        break;
                    }
                }
                let mut input_coords = output_coords.clone();
                input_coords[axis] = position - offsets[selected];
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    load_scalar(
                        inputs[selected],
                        index_of(&input_coords, &plan.inputs[selected].strides),
                        dtype,
                    ),
                );
            }
        }
        DmlOpKind::Slice {
            offsets, strides, ..
        } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let output_coords = coords_of(gid, &plan.output.sizes);
                let input_coords: Vec<u64> = output_coords
                    .iter()
                    .enumerate()
                    .map(|(dimension, coord)| {
                        coord * strides[dimension] as u64 + offsets[dimension] as u64
                    })
                    .collect();
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype),
                );
            }
        }
        DmlOpKind::Add1 => execute_binary_cpu(plan, inputs, output, DmlBinaryOp::Add)?,
        DmlOpKind::Rnn {
            direction,
            activations,
            options,
            outputs: roles,
        } => {
            let mut all: Vec<&mut [u8]> = Vec::with_capacity(1 + extras.len());
            all.push(&mut *output);
            for extra in extras.iter_mut() {
                all.push(&mut **extra);
            }
            execute_recurrent_cpu(
                plan,
                inputs,
                &mut all,
                DML_OPERATOR_RNN,
                *direction,
                activations,
                *options,
                roles,
                RecurrentExtras::default(),
            )?
        }
        DmlOpKind::Gru {
            direction,
            activations,
            options,
            outputs: roles,
            linear_before_reset,
        } => {
            let mut all: Vec<&mut [u8]> = Vec::with_capacity(1 + extras.len());
            all.push(&mut *output);
            for extra in extras.iter_mut() {
                all.push(&mut **extra);
            }
            execute_recurrent_cpu(
                plan,
                inputs,
                &mut all,
                DML_OPERATOR_GRU,
                *direction,
                activations,
                *options,
                roles,
                RecurrentExtras {
                    linear_before_reset: *linear_before_reset,
                    ..RecurrentExtras::default()
                },
            )?
        }
        DmlOpKind::Lstm {
            direction,
            activations,
            options,
            outputs: roles,
            clip_threshold,
            use_clip_threshold,
            couple_input_forget,
        } => {
            let mut all: Vec<&mut [u8]> = Vec::with_capacity(1 + extras.len());
            all.push(&mut *output);
            for extra in extras.iter_mut() {
                all.push(&mut **extra);
            }
            execute_recurrent_cpu(
                plan,
                inputs,
                &mut all,
                DML_OPERATOR_LSTM,
                *direction,
                activations,
                *options,
                roles,
                RecurrentExtras {
                    clip_threshold: *clip_threshold,
                    use_clip_threshold: *use_clip_threshold,
                    couple_input_forget: *couple_input_forget,
                    ..RecurrentExtras::default()
                },
            )?
        }
        DmlOpKind::ArgMin { axes, direction } => {
            execute_arg_reduce_cpu(plan, inputs[0], output, axes, *direction, true)?
        }
        DmlOpKind::ArgMax { axes, direction } => {
            execute_arg_reduce_cpu(plan, inputs[0], output, axes, *direction, false)?
        }
        DmlOpKind::Padding {
            mode,
            start_padding,
            end_padding,
            value,
        } => execute_padding_cpu(
            plan,
            inputs[0],
            output,
            *mode,
            start_padding,
            end_padding,
            *value,
        )?,
        DmlOpKind::Resample {
            mode,
            scales,
            input_offsets,
            output_offsets,
            rounding,
            ..
        } => execute_resample_cpu(
            plan,
            inputs[0],
            output,
            *mode,
            scales,
            input_offsets,
            output_offsets,
            *rounding,
        )?,
        DmlOpKind::TopK { axis, k, direction } => execute_top_k_cpu(
            plan,
            inputs[0],
            output,
            &mut *extras[0],
            *axis,
            *k,
            *direction,
        )?,
        DmlOpKind::Tile { repeats } => execute_tile_cpu(plan, inputs[0], output, repeats)?,
        DmlOpKind::Split { axis } => execute_split_cpu(plan, inputs[0], output, extras, *axis)?,
        DmlOpKind::Gather {
            axis,
            index_dimensions,
        } => execute_gather_cpu(plan, inputs, output, *axis, *index_dimensions)?,
        DmlOpKind::GatherElements { axis } => {
            execute_gather_elements_cpu(plan, inputs, output, *axis)?
        }
        DmlOpKind::GatherNd {
            input_dimension_count,
            indices_dimension_count,
            batch_dimension_count,
        } => execute_gather_nd_cpu(
            plan,
            inputs,
            output,
            *input_dimension_count,
            *indices_dimension_count,
            *batch_dimension_count,
        )?,
        DmlOpKind::Scatter { axis } => execute_scatter_cpu(plan, inputs, output, *axis)?,
        DmlOpKind::ScatterNd {
            input_dimension_count,
            indices_dimension_count,
        } => execute_scatter_nd_cpu(
            plan,
            inputs,
            output,
            *input_dimension_count,
            *indices_dimension_count,
        )?,
        DmlOpKind::RoiPooling {
            spatial_scale,
            pooled,
        } => execute_roi_pooling_cpu(plan, inputs, output, *spatial_scale, pooled)?,
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
        } => execute_roi_align_cpu(
            plan,
            inputs,
            output,
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
        )?,
        DmlOpKind::LocalResponseNormalization {
            cross_channel,
            local_size,
            alpha,
            beta,
            bias,
        } => execute_lrn_cpu(
            plan,
            inputs[0],
            output,
            *cross_channel,
            *local_size,
            *alpha,
            *beta,
            *bias,
        )?,
        DmlOpKind::MeanVarianceNormalization {
            axes,
            normalize_variance,
            epsilon,
        } => execute_mvn_cpu(plan, inputs, output, axes, *normalize_variance, *epsilon)?,
        DmlOpKind::Adam {
            learning_rate,
            beta1,
            beta2,
            epsilon,
        } => execute_adam_cpu(
            plan,
            inputs,
            output,
            extras,
            *learning_rate,
            *beta1,
            *beta2,
            *epsilon,
        )?,
        DmlOpKind::QuantizeLinear => execute_quantize_linear_cpu(plan, inputs, output, false)?,
        DmlOpKind::DequantizeLinear => execute_quantize_linear_cpu(plan, inputs, output, true)?,
        DmlOpKind::DynamicQuantizeLinear => {
            execute_dynamic_quantize_cpu(plan, inputs[0], output, extras)?
        }
        DmlOpKind::QuantizedLinearAdd { .. } => execute_quantized_add_cpu(plan, inputs, output)?,
        DmlOpKind::MatrixMultiplyInteger { .. } => {
            execute_integer_matmul_cpu(plan, inputs, output)?
        }
        DmlOpKind::ConvolutionInteger { .. } => {
            execute_integer_convolution_cpu(plan, inputs, output)?
        }
        DmlOpKind::QuantizedLinearAveragePooling { .. } => {
            execute_quantized_avg_pool_cpu(plan, inputs, output)?
        }
        DmlOpKind::MatrixMultiplyIntegerToFloat { .. } => {
            execute_integer_matmul_to_float_cpu(plan, inputs, output)?
        }
        DmlOpKind::Quantize { quantization_type } => {
            execute_generic_quantize_cpu(plan, inputs, output, *quantization_type, false)?
        }
        DmlOpKind::Dequantize { quantization_type } => {
            execute_generic_quantize_cpu(plan, inputs, output, *quantization_type, true)?
        }
    }
    if let Some(activation) = plan.fused_activation {
        for gid in 0..count {
            let index = output_index(&plan.output, gid);
            let value = load_scalar(output, index, dtype);
            store_scalar(output, index, dtype, activation_cpu(activation, value));
        }
    }
    Ok(())
}

fn execute_binary_cpu(
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
        let value = match op {
            DmlBinaryOp::Add => left + right,
            DmlBinaryOp::Subtract => left - right,
            DmlBinaryOp::Multiply => left * right,
            DmlBinaryOp::Divide => left / right,
            DmlBinaryOp::Min => left.min(right),
            DmlBinaryOp::Max => left.max(right),
            DmlBinaryOp::Pow => left.powf(right),
        };
        store_scalar(output, output_index(&plan.output, gid), dtype, value);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_recurrent_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
    ty: u32,
    direction: DmlRecurrentDirection,
    activations: &[DmlActivation],
    options: DmlRecurrentOptions,
    roles: &[DmlRecurrentOutput],
    extras: RecurrentExtras,
) -> DmlResult<()> {
    if direction != DmlRecurrentDirection::Forward {
        return Err(DmlError::invalid(format!(
            "DML_OPERATOR_TYPE {ty} only supports DML_RECURRENT_NETWORK_DIRECTION_FORWARD"
        )));
    }
    let input = &plan.inputs[0];
    let weight = &plan.inputs[1];
    let recurrence = &plan.inputs[2];
    let [sequence, batch, input_size] = [input.sizes[0], input.sizes[1], input.sizes[2]];
    let hidden = weight.sizes[1] as usize;
    let batch_usize = batch as usize;
    let input_size_usize = input_size as usize;
    let bias_index = if options.bias { Some(3) } else { None };
    let hidden_init_index = 3 + usize::from(options.bias);
    let cell_init_index = hidden_init_index + usize::from(options.hidden_init);
    let sequence_lengths_index = cell_init_index + usize::from(options.cell_init);
    let sequence_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::Sequence);
    let single_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::Single);
    let cell_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::CellSingle);
    let mut hidden_state = vec![vec![0.0f32; hidden]; batch_usize];
    let mut cell_state = vec![vec![0.0f32; hidden]; batch_usize];
    if options.hidden_init {
        let desc = &plan.inputs[hidden_init_index];
        for b in 0..batch_usize {
            for j in 0..hidden {
                hidden_state[b][j] = load_scalar(
                    inputs[hidden_init_index],
                    index_of(&[0, b as u64, j as u64], &desc.strides),
                    desc.data_type,
                );
            }
        }
    }
    if options.cell_init {
        let desc = &plan.inputs[cell_init_index];
        for b in 0..batch_usize {
            for j in 0..hidden {
                cell_state[b][j] = load_scalar(
                    inputs[cell_init_index],
                    index_of(&[0, b as u64, j as u64], &desc.strides),
                    desc.data_type,
                );
            }
        }
    }
    let gate_activation = recurrent_activation(activations, 0, DmlActivation::Tanh);
    for b in 0..batch_usize {
        let t_end = if options.sequence_lengths {
            let desc = &plan.inputs[sequence_lengths_index];
            load_integer(inputs[sequence_lengths_index], b as u64, desc.data_type)
                .clamp(0, sequence as i64) as u32
        } else {
            sequence
        };
        for t in 0..sequence {
            if t < t_end {
                let mut next = vec![0.0f32; hidden];
                match ty {
                    DML_OPERATOR_RNN => {
                        for j in 0..hidden {
                            let mut sum = 0.0f64;
                            for i in 0..input_size_usize {
                                let x = load_scalar(
                                    inputs[0],
                                    index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                    input.data_type,
                                );
                                let w = load_scalar(
                                    inputs[1],
                                    index_of(&[0, j as u64, i as u64], &weight.strides),
                                    weight.data_type,
                                );
                                sum += x as f64 * w as f64;
                            }
                            for i in 0..hidden {
                                let h = hidden_state[b][i];
                                let r = load_scalar(
                                    inputs[2],
                                    index_of(&[0, j as u64, i as u64], &recurrence.strides),
                                    recurrence.data_type,
                                );
                                sum += h as f64 * r as f64;
                            }
                            if let Some(index) = bias_index {
                                sum += load_scalar(
                                    inputs[index],
                                    (j as u64) as u64,
                                    plan.inputs[index].data_type,
                                ) as f64;
                            }
                            next[j] = activation_cpu(gate_activation, sum as f32);
                        }
                    }
                    DML_OPERATOR_GRU => {
                        let gate = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
                        let candidate_activation =
                            recurrent_activation(activations, 1, DmlActivation::Tanh);
                        let hidden_now = hidden_state[b].clone();
                        let mut z = vec![0.0f32; hidden];
                        let mut r = vec![0.0f32; hidden];
                        for j in 0..hidden {
                            let mut z_sum = 0.0f64;
                            let mut r_sum = 0.0f64;
                            for i in 0..input_size_usize {
                                let x = load_scalar(
                                    inputs[0],
                                    index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                    input.data_type,
                                ) as f64;
                                z_sum += x * load_scalar(
                                    inputs[1],
                                    index_of(&[0, j as u64, i as u64], &weight.strides),
                                    weight.data_type,
                                ) as f64;
                                r_sum += x * load_scalar(
                                    inputs[1],
                                    index_of(&[1, j as u64, i as u64], &weight.strides),
                                    weight.data_type,
                                ) as f64;
                            }
                            for i in 0..hidden {
                                let h = hidden_now[i] as f64;
                                z_sum += h * load_scalar(
                                    inputs[2],
                                    index_of(&[0, j as u64, i as u64], &recurrence.strides),
                                    recurrence.data_type,
                                ) as f64;
                                r_sum += h * load_scalar(
                                    inputs[2],
                                    index_of(&[1, j as u64, i as u64], &recurrence.strides),
                                    recurrence.data_type,
                                ) as f64;
                            }
                            if let Some(index) = bias_index {
                                z_sum += load_scalar(
                                    inputs[index],
                                    j as u64,
                                    plan.inputs[index].data_type,
                                ) as f64;
                                r_sum += load_scalar(
                                    inputs[index],
                                    (hidden + j) as u64,
                                    plan.inputs[index].data_type,
                                ) as f64;
                            }
                            z[j] = activation_cpu(gate, z_sum as f32);
                            r[j] = activation_cpu(gate, r_sum as f32);
                        }
                        for j in 0..hidden {
                            let mut input_term = 0.0f64;
                            for i in 0..input_size_usize {
                                input_term += load_scalar(
                                    inputs[0],
                                    index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                    input.data_type,
                                ) as f64
                                    * load_scalar(
                                        inputs[1],
                                        index_of(&[2, j as u64, i as u64], &weight.strides),
                                        weight.data_type,
                                    ) as f64;
                            }
                            if let Some(index) = bias_index {
                                input_term += load_scalar(
                                    inputs[index],
                                    (2 * hidden + j) as u64,
                                    plan.inputs[index].data_type,
                                ) as f64;
                            }
                            let mut recurrent_term = 0.0f64;
                            for i in 0..hidden {
                                recurrent_term += hidden_state[b][i] as f64
                                    * load_scalar(
                                        inputs[2],
                                        index_of(&[2, j as u64, i as u64], &recurrence.strides),
                                        recurrence.data_type,
                                    ) as f64;
                            }
                            let combined = if extras.linear_before_reset {
                                input_term + r[j] as f64 * recurrent_term
                            } else {
                                input_term + r[j] as f64 * recurrent_term
                            };
                            let candidate = activation_cpu(candidate_activation, combined as f32);
                            next[j] = (1.0 - z[j]) * hidden_state[b][j] + z[j] * candidate;
                        }
                    }
                    _ => {
                        let gate = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
                        let cell_gate = recurrent_activation(activations, 1, DmlActivation::Tanh);
                        let output_activation =
                            recurrent_activation(activations, 2, DmlActivation::Tanh);
                        let hidden_now = hidden_state[b].clone();
                        for j in 0..hidden {
                            let mut sums = [0.0f64; 4];
                            for (gate_index, sum) in sums.iter_mut().enumerate() {
                                for i in 0..input_size_usize {
                                    *sum += load_scalar(
                                        inputs[0],
                                        index_of(&[t as u64, b as u64, i as u64], &input.strides),
                                        input.data_type,
                                    ) as f64
                                        * load_scalar(
                                            inputs[1],
                                            index_of(
                                                &[gate_index as u64, j as u64, i as u64],
                                                &weight.strides,
                                            ),
                                            weight.data_type,
                                        ) as f64;
                                }
                                for i in 0..hidden {
                                    *sum += hidden_now[i] as f64
                                        * load_scalar(
                                            inputs[2],
                                            index_of(
                                                &[gate_index as u64, j as u64, i as u64],
                                                &recurrence.strides,
                                            ),
                                            recurrence.data_type,
                                        ) as f64;
                                }
                                if let Some(index) = bias_index {
                                    *sum += load_scalar(
                                        inputs[index],
                                        (gate_index * hidden + j) as u64,
                                        plan.inputs[index].data_type,
                                    ) as f64;
                                }
                            }
                            let i_gate = activation_cpu(gate, sums[0] as f32);
                            let o_gate = activation_cpu(gate, sums[1] as f32);
                            let mut f_gate = activation_cpu(gate, sums[2] as f32);
                            let c_gate = activation_cpu(cell_gate, sums[3] as f32);
                            if extras.couple_input_forget {
                                f_gate = 1.0 - i_gate;
                            }
                            let mut cell = f_gate * cell_state[b][j] + i_gate * c_gate;
                            if extras.use_clip_threshold {
                                cell = cell.clamp(-extras.clip_threshold, extras.clip_threshold);
                            }
                            cell_state[b][j] = cell;
                            next[j] = o_gate * activation_cpu(output_activation, cell);
                        }
                    }
                }
                hidden_state[b] = next;
            }
            if let Some(role) = sequence_role {
                let desc = &plan.outputs().nth(role).expect("role output").clone();
                for j in 0..hidden {
                    let index = index_of(&[t as u64, b as u64, j as u64], &desc.strides);
                    store_scalar(
                        &mut outputs[role][..],
                        index,
                        desc.data_type,
                        hidden_state[b][j],
                    );
                }
            }
        }
        if let Some(role) = single_role {
            let desc = plan.outputs().nth(role).expect("role output").clone();
            for j in 0..hidden {
                let index = index_of(&[0, b as u64, j as u64], &desc.strides);
                store_scalar(
                    &mut outputs[role][..],
                    index,
                    desc.data_type,
                    hidden_state[b][j],
                );
            }
        }
        if let Some(role) = cell_role {
            let desc = plan.outputs().nth(role).expect("role output").clone();
            for j in 0..hidden {
                let index = index_of(&[0, b as u64, j as u64], &desc.strides);
                store_scalar(
                    &mut outputs[role][..],
                    index,
                    desc.data_type,
                    cell_state[b][j],
                );
            }
        }
    }
    Ok(())
}

fn execute_arg_reduce_cpu(
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

fn execute_padding_cpu(
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

fn execute_resample_cpu(
    plan: &DmlOpPlan,
    input_bytes: &[u8],
    output: &mut [u8],
    mode: DmlInterpolationMode,
    scales: &[f32],
    input_offsets: &[f32],
    output_offsets: &[f32],
    rounding: DmlAxisDirection,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let rank = input.sizes.len();
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let coords: Vec<f32> = (0..rank)
            .map(|dimension| {
                (output_coords[dimension] as f32 + output_offsets[dimension]) / scales[dimension]
                    + input_offsets[dimension]
            })
            .collect();
        let value = if mode == DmlInterpolationMode::NearestNeighbor {
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
            let mut result = 0.0f32;
            for mask in 0..(1usize << rank) {
                let mut weight = 1.0f32;
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
                    );
            }
            result
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

fn execute_top_k_cpu(
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

fn execute_tile_cpu(
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

fn execute_split_cpu(
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

fn execute_gather_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    axis: u32,
    _index_dimensions: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let index = load_integer(inputs[1], output_coords[axis as usize], indices.data_type);
        let mut input_coords = output_coords.clone();
        input_coords[axis as usize] = index as u64;
        let value = if index >= 0 && (index as u64) < input.sizes[axis as usize] as u64 {
            load_scalar(
                inputs[0],
                index_of(&input_coords, &input.strides),
                input.data_type,
            )
        } else {
            0.0
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

fn execute_gather_elements_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    axis: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let index = load_integer(
            inputs[1],
            index_of(&output_coords, &indices.strides),
            indices.data_type,
        );
        let mut input_coords = output_coords.clone();
        input_coords[axis as usize] = index as u64;
        let value = if index >= 0 && (index as u64) < input.sizes[axis as usize] as u64 {
            load_scalar(
                inputs[0],
                index_of(&input_coords, &input.strides),
                input.data_type,
            )
        } else {
            0.0
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

fn execute_gather_nd_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    _input_dimension_count: u32,
    _indices_dimension_count: u32,
    _batch_dimension_count: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let indices_rank = indices.sizes.len();
    let indexed = indices.sizes[indices_rank - 1] as usize;
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let mut input_coords = Vec::with_capacity(input.sizes.len());
        let mut valid = true;
        for dimension in 0..indexed {
            let mut index_coords = Vec::with_capacity(indices_rank);
            index_coords.extend_from_slice(&output_coords[..indices_rank - 1]);
            index_coords.push(dimension as u64);
            let index = load_integer(
                inputs[1],
                index_of(&index_coords, &indices.strides),
                indices.data_type,
            );
            if index < 0 || index as u64 >= input.sizes[dimension] as u64 {
                valid = false;
                input_coords.push(0);
            } else {
                input_coords.push(index as u64);
            }
        }
        for dimension in indexed..input.sizes.len() {
            input_coords.push(output_coords[indices_rank - 1 + dimension - indexed]);
        }
        let value = if valid {
            load_scalar(
                inputs[0],
                index_of(&input_coords, &input.strides),
                input.data_type,
            )
        } else {
            0.0
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

fn execute_scatter_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    axis: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let updates = &plan.inputs[2];
    let count = plan.output.element_count();
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            load_scalar(
                inputs[0],
                index_of(&coords, &input.strides),
                input.data_type,
            ),
        );
    }
    let update_count = indices.element_count();
    for gid in 0..update_count {
        let index_coords = coords_of(gid, &indices.sizes);
        let index = load_integer(
            inputs[1],
            index_of(&index_coords, &indices.strides),
            indices.data_type,
        );
        if index < 0 || index as u64 >= input.sizes[axis as usize] as u64 {
            continue;
        }
        let mut output_coords = index_coords.clone();
        output_coords[axis as usize] = index as u64;
        let output_index = index_of(&output_coords, &plan.output.strides);
        store_scalar(
            output,
            output_index,
            plan.output.data_type,
            load_scalar(
                inputs[2],
                index_of(&index_coords, &updates.strides),
                updates.data_type,
            ),
        );
    }
    Ok(())
}

fn execute_scatter_nd_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    _input_dimension_count: u32,
    _indices_dimension_count: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let updates = &plan.inputs[2];
    let indices_rank = indices.sizes.len();
    let indexed = indices.sizes[indices_rank - 1] as usize;
    let count = plan.output.element_count();
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        store_scalar(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            load_scalar(
                inputs[0],
                index_of(&coords, &input.strides),
                input.data_type,
            ),
        );
    }
    let update_leading_count: u64 = indices.sizes[..indices_rank - 1]
        .iter()
        .map(|size| *size as u64)
        .product();
    for leading_index in 0..update_leading_count {
        let leading = coords_of(leading_index, &indices.sizes[..indices_rank - 1]);
        let mut output_prefix = Vec::with_capacity(indexed);
        let mut valid = true;
        for dimension in 0..indexed {
            let mut index_coords = leading.clone();
            index_coords.push(dimension as u64);
            let index = load_integer(
                inputs[1],
                index_of(&index_coords, &indices.strides),
                indices.data_type,
            );
            if index < 0 || index as u64 >= input.sizes[dimension] as u64 {
                valid = false;
                break;
            }
            output_prefix.push(index as u64);
        }
        if !valid {
            continue;
        }
        let trailing_sizes = &input.sizes[indexed..];
        let trailing_count: u64 = trailing_sizes.iter().map(|size| *size as u64).product();
        for trailing_index in 0..trailing_count {
            let trailing = coords_of(trailing_index, trailing_sizes);
            let mut output_coords = output_prefix.clone();
            output_coords.extend_from_slice(&trailing);
            let mut update_coords = leading.clone();
            update_coords.extend_from_slice(&trailing);
            store_scalar(
                output,
                index_of(&output_coords, &plan.output.strides),
                plan.output.data_type,
                load_scalar(
                    inputs[2],
                    index_of(&update_coords, &updates.strides),
                    updates.data_type,
                ),
            );
        }
    }
    Ok(())
}

fn execute_roi_pooling_cpu(
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
fn execute_roi_align_cpu(
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

fn execute_lrn_cpu(
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

fn execute_mvn_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    axes: &[u32],
    normalize_variance: bool,
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
        let mean = sum / reduction_count as f64;
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

fn execute_adam_cpu(
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

fn execute_quantize_linear_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    dequantize: bool,
) -> DmlResult<()> {
    let count = plan.output.element_count();
    let scale = load_scalar(inputs[1], 0, plan.inputs[1].data_type);
    let zero = if plan.inputs.len() == 3 {
        load_scalar(inputs[2], 0, plan.inputs[2].data_type)
    } else {
        0.0
    };
    for gid in 0..count {
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

fn execute_dynamic_quantize_cpu(
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

fn execute_quantized_add_cpu(
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
    let a_scale_value = load_scalar(inputs[a_scale], 0, plan.inputs[a_scale].data_type);
    let b_scale_value = load_scalar(inputs[b_scale], 0, plan.inputs[b_scale].data_type);
    let out_scale_value = load_scalar(inputs[out_scale], 0, plan.inputs[out_scale].data_type);
    let a_zero_value = a_zero
        .map(|index| load_scalar(inputs[index], 0, plan.inputs[index].data_type))
        .unwrap_or(0.0);
    let b_zero_value = b_zero
        .map(|index| load_scalar(inputs[index], 0, plan.inputs[index].data_type))
        .unwrap_or(0.0);
    let out_zero_value = out_zero
        .map(|index| load_scalar(inputs[index], 0, plan.inputs[index].data_type))
        .unwrap_or(0.0);
    for gid in 0..count {
        let a = (load_scalar(inputs[a_index], gid, plan.inputs[a_index].data_type) - a_zero_value)
            * a_scale_value;
        let b = (load_scalar(inputs[b_index], gid, plan.inputs[b_index].data_type) - b_zero_value)
            * b_scale_value;
        store_quantized(
            output,
            output_index(&plan.output, gid),
            plan.output.data_type,
            (a + b) / out_scale_value + out_zero_value,
        );
    }
    Ok(())
}

fn execute_integer_matmul_cpu(
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
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let batch = coords[..rank - 2].to_vec();
        let m = coords[rank - 2];
        let column = coords[rank - 1];
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
            if let Some(index) = a_zero {
                av -= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            if let Some(index) = b_zero {
                bv -= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            acc += av * bv;
        }
        let index = output_index(&plan.output, gid);
        if *quantized_output {
            if let Some(index) = a_scale {
                acc *= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            if let Some(index) = b_scale {
                acc *= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            if let Some(index) = out_scale {
                acc /= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            if let Some(index) = out_zero {
                acc += load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            store_quantized(output, index, plan.output.data_type, acc as f32);
        } else {
            store_integer(output, index, plan.output.data_type, acc.round() as i64);
        }
        let _ = n;
    }
    Ok(())
}

fn execute_integer_convolution_cpu(
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
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let [batch, out_channel, oh, ow] = [coords[0], coords[1], coords[2], coords[3]];
        let group = out_channel / filters_per_group as u64;
        let mut acc = 0.0f64;
        for cg in 0..channels_per_group as u64 {
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
                            &[
                                batch,
                                group * channels_per_group as u64 + cg,
                                iy as u64,
                                ix as u64,
                            ],
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
                        av -= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
                    }
                    if let Some(index) = filter_zero {
                        bv -= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
                    }
                    acc += av * bv;
                }
            }
        }
        let index = output_index(&plan.output, gid);
        if *quantized_output {
            if let Some(index) = input_scale {
                acc *= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            if let Some(index) = filter_scale {
                acc *= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            if let Some(index) = bias_index {
                acc += load_scalar(inputs[index], out_channel, plan.inputs[index].data_type) as f64;
            }
            if let Some(index) = out_scale {
                acc /= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            if let Some(index) = out_zero {
                acc += load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            store_quantized(output, index, plan.output.data_type, acc as f32);
        } else {
            store_integer(output, index, plan.output.data_type, acc.round() as i64);
        }
    }
    Ok(())
}

fn execute_quantized_avg_pool_cpu(
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
    let input_scale_value = load_scalar(inputs[input_scale], 0, plan.inputs[input_scale].data_type);
    let out_scale_value = load_scalar(inputs[out_scale], 0, plan.inputs[out_scale].data_type);
    let input_zero_value = input_zero
        .map(|index| load_scalar(inputs[index], 0, plan.inputs[index].data_type))
        .unwrap_or(0.0);
    let out_zero_value = out_zero
        .map(|index| load_scalar(inputs[index], 0, plan.inputs[index].data_type))
        .unwrap_or(0.0);
    let count = plan.output.element_count();
    let divisor = window[0] as u64 * window[1] as u64;
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let [batch, channel, oh, ow] = [coords[0], coords[1], coords[2], coords[3]];
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

fn execute_integer_matmul_to_float_cpu(
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
    for gid in 0..count {
        let coords = coords_of(gid, &plan.output.sizes);
        let batch = coords[..rank - 2].to_vec();
        let m = coords[rank - 2];
        let column = coords[rank - 1];
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
            if let Some(index) = a_zero {
                av -= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            if let Some(index) = b_zero {
                bv -= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
            }
            acc += av * bv;
        }
        if let Some(index) = a_scale {
            acc *= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
        }
        if let Some(index) = b_scale {
            acc *= load_scalar(inputs[index], 0, plan.inputs[index].data_type) as f64;
        }
        if let Some(index) = bias {
            let bias_index = if plan.inputs[index].element_count() == 1 {
                0
            } else {
                column
            };
            acc += load_scalar(inputs[index], bias_index, plan.inputs[index].data_type) as f64;
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

fn execute_generic_quantize_cpu(
    plan: &DmlOpPlan,
    inputs: &[&[u8]],
    output: &mut [u8],
    quantization_type: u32,
    dequantize: bool,
) -> DmlResult<()> {
    let count = plan.output.element_count();
    let scale = if quantization_type >= 1 {
        load_scalar(inputs[1], 0, plan.inputs[1].data_type)
    } else {
        1.0
    };
    let zero = if quantization_type == 2 {
        load_scalar(inputs[2], 0, plan.inputs[2].data_type)
    } else {
        0.0
    };
    for gid in 0..count {
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

/// Whether a guest `DML_OPERATOR_TYPE` is parsed into a [`DmlOpPlan`].
///
/// The element-wise identity/abs/exp/... operators keep their dedicated
/// descriptor path; everything with a tensor graph in [`DmlOpKind`] is parsed
/// here so guest `IDMLDevice::CreateOperator` reaches the extended set.
pub fn is_extended_operator(ty: u32) -> bool {
    matches!(
        ty,
        DML_OPERATOR_ELEMENT_WISE_QUANTIZE_LINEAR
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
            | DML_OPERATOR_RESAMPLE3
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::d3d12::directml::DML_TENSOR_DATA_TYPE_UINT8;

    fn tensor(data_type: u32, sizes: &[u32], strides: Option<&[u32]>) -> DmlTensorDesc {
        let element_size = match data_type {
            DML_TENSOR_DATA_TYPE_FLOAT16 => 2,
            DML_TENSOR_DATA_TYPE_UINT8 | DML_TENSOR_DATA_TYPE_INT8 => 1,
            _ => 4,
        };
        let strides = strides.map(|value| value.to_vec()).unwrap_or_else(|| {
            let mut out = vec![1u32; sizes.len()];
            let mut stride = 1u32;
            for index in (0..sizes.len()).rev() {
                out[index] = stride;
                stride = stride.saturating_mul(sizes[index]);
            }
            out
        });
        let implied = sizes
            .iter()
            .zip(&strides)
            .map(|(size, stride)| (*size as u64).saturating_sub(1) * *stride as u64)
            .sum::<u64>()
            + 1;
        DmlTensorDesc {
            data_type,
            flags: 0,
            sizes: sizes.to_vec(),
            strides,
            total_size_in_bytes: implied.saturating_mul(element_size),
            guaranteed_base_offset_alignment: 0,
        }
    }

    fn plan(kind: DmlOpKind, inputs: Vec<DmlTensorDesc>, output: DmlTensorDesc) -> DmlOpPlan {
        DmlOpPlan {
            kind,
            inputs,
            output,
            extra_outputs: Vec::new(),
            fused_activation: None,
        }
    }

    fn f32_bytes(values: &[f32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    fn read_f32(bytes: &[u8]) -> Vec<f32> {
        bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    fn f16_bytes(values: &[f32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| f32_to_f16(*value).to_le_bytes())
            .collect()
    }

    fn read_f16(bytes: &[u8]) -> Vec<f32> {
        bytes
            .chunks_exact(2)
            .map(|chunk| f16_to_f32(u16::from_le_bytes(chunk.try_into().unwrap())))
            .collect()
    }

    fn assert_close(actual: f32, expected: f32, tolerance: f32) {
        assert!(
            (actual - expected).abs() <= tolerance,
            "expected {expected}, got {actual}"
        );
    }

    fn assert_values(actual: &[f32], expected: &[f32], tolerance: f32) {
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected) {
            if expected.is_nan() {
                assert_eq!(actual.is_nan(), true);
            } else if expected.is_infinite() {
                assert_eq!(actual.is_infinite(), true);
                assert_eq!(actual.is_sign_negative(), expected.is_sign_negative());
            } else {
                assert_close(*actual, *expected, tolerance);
            }
        }
    }

    fn metal_available() -> bool {
        MetalDevice::system_default().is_ok()
    }

    fn run_both(plan: &DmlOpPlan, inputs: &[&[u8]], expected: &[f32], tolerance: f32) {
        let mut cpu = vec![0u8; plan.output.total_size_in_bytes as usize];
        execute_plan(plan, DmlExecutionDevice::Cpu, inputs, &mut cpu).expect("cpu execution");
        let cpu_values = read_f32(&cpu);
        assert_values(&cpu_values, expected, tolerance);
        if metal_available() {
            let mut accelerated = vec![0u8; plan.output.total_size_in_bytes as usize];
            execute_plan(plan, DmlExecutionDevice::Metal, inputs, &mut accelerated)
                .expect("metal execution");
            let metal_values = read_f32(&accelerated);
            assert_values(&metal_values, expected, tolerance);
        }
    }

    fn activation_plan(input: &DmlTensorDesc, activation: DmlActivation, alpha: f32) -> DmlOpPlan {
        plan(
            DmlOpKind::Activation { activation, alpha },
            vec![input.clone()],
            input.clone(),
        )
    }

    #[test]
    fn dml_extended_rejects_shape_stride_overflow_empty_and_dtype_errors() {
        let a = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let b = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 2], None);
        let out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let gemm = plan(
            DmlOpKind::Gemm {
                trans_a: false,
                trans_b: false,
                alpha: 1.0,
                beta: 0.0,
            },
            vec![a, b],
            out,
        );
        assert_eq!(
            gemm.validate().unwrap_err().message,
            "GEMM inner dimensions do not match: A K=2, B K=3"
        );

        let huge = DmlTensorDesc {
            data_type: DML_TENSOR_DATA_TYPE_FLOAT32,
            flags: 0,
            sizes: vec![u32::MAX, u32::MAX],
            strides: vec![u32::MAX, u32::MAX],
            total_size_in_bytes: u64::MAX,
            guaranteed_base_offset_alignment: 0,
        };
        let overflow = activation_plan(&huge, DmlActivation::Relu, 0.0);
        assert_eq!(
            overflow.validate().unwrap_err().message,
            "tensor stride range overflows u64"
        );

        let empty = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 0], None);
        let empty_plan = activation_plan(&empty, DmlActivation::Relu, 0.0);
        assert_eq!(
            empty_plan.validate().unwrap_err().message,
            "tensor dimensions must be non-zero"
        );

        let unsupported = tensor(DML_TENSOR_DATA_TYPE_UINT8, &[2, 2], None);
        let unsupported_plan = activation_plan(&unsupported, DmlActivation::Relu, 0.0);
        assert_eq!(
            unsupported_plan.validate().unwrap_err().message,
            "DML_TENSOR_DATA_TYPE 5 is not supported for DML_OPERATOR_TYPE 44"
        );

        let half = tensor(DML_TENSOR_DATA_TYPE_FLOAT16, &[1, 1, 2, 2], None);
        let filter = tensor(DML_TENSOR_DATA_TYPE_FLOAT16, &[1, 1, 1, 1], None);
        let convolution = plan(
            DmlOpKind::Convolution {
                strides: vec![1, 1],
                dilations: vec![1, 1],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                output_padding: vec![0, 0],
                group_count: 1,
            },
            vec![half.clone(), filter],
            half,
        );
        assert_eq!(
            convolution.validate().unwrap_err().message,
            "DML_TENSOR_DATA_TYPE 2 is not supported for DML_OPERATOR_TYPE 53"
        );

        let mut zero_stride = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        zero_stride.strides = vec![0, 1];
        let zero_stride_plan = activation_plan(&zero_stride, DmlActivation::Relu, 0.0);
        assert_eq!(
            zero_stride_plan.validate().unwrap_err().message,
            "output tensor strides must be non-zero"
        );
    }

    #[test]
    fn dml_extended_rejects_invalid_descriptor_shapes_exactly() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 3, 3], None);
        let filter = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 2, 2], None);
        let out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None);
        let convolution = plan(
            DmlOpKind::Convolution {
                strides: vec![1, 1],
                dilations: vec![1, 1],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                output_padding: vec![0, 0],
                group_count: 1,
            },
            vec![input.clone(), filter],
            out,
        );
        assert_eq!(
            convolution.validate().unwrap_err().message,
            "convolution filter channel count 2 must equal input channels / groups (1)"
        );

        let pool_out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None);
        let pooling = plan(
            DmlOpKind::Pooling {
                kind: DmlPoolingKind::Max,
                strides: vec![1, 1],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                include_padding: false,
            },
            vec![input.clone()],
            pool_out,
        );
        assert_eq!(
            pooling.validate().unwrap_err().message,
            "pooling output sizes must be [1, 1, 2, 2], got [1, 1, 1, 1]"
        );

        let reduce_out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 3, 3], None);
        let reduce = plan(
            DmlOpKind::Reduce {
                reduce: DmlReduceKind::Sum,
                axes: vec![4],
            },
            vec![input.clone()],
            reduce_out,
        );
        assert_eq!(
            reduce.validate().unwrap_err().message,
            "reduce axis 4 is out of range for rank 4"
        );

        let transpose_out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 3, 3], None);
        let transpose = plan(
            DmlOpKind::Transpose {
                permutation: vec![0, 0, 2, 3],
            },
            vec![input.clone()],
            transpose_out,
        );
        assert_eq!(
            transpose.validate().unwrap_err().message,
            "transpose axis 0 appears more than once"
        );

        let concat_a = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let concat_b = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 2], None);
        let concat_out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 4], None);
        let concat = plan(
            DmlOpKind::Concat { axis: 1 },
            vec![concat_a, concat_b],
            concat_out,
        );
        assert_eq!(
            concat.validate().unwrap_err().message,
            "concat input sizes must match on non-axis dimensions"
        );

        let slice_out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let slice = plan(
            DmlOpKind::Slice {
                offsets: vec![0, 3],
                sizes: vec![2, 2],
                strides: vec![1, 1],
            },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 4], None)],
            slice_out,
        );
        assert_eq!(
            slice.validate().unwrap_err().message,
            "slice window at axis 1 exceeds input size 4"
        );

        let reshape = plan(
            DmlOpKind::Reshape,
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None)],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None),
        );
        assert_eq!(
            reshape.validate().unwrap_err().message,
            "reshape input and output element counts differ: 6 != 4"
        );

        let batch = plan(
            DmlOpKind::BatchNormalization {
                spatial: true,
                epsilon: 1e-5,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 3, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 1], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 1], None),
        );
        assert_eq!(
            batch.validate().unwrap_err().message,
            "batch normalization spatial parameter mean at dimension 1 must have size 2, got 3"
        );
    }

    #[test]
    fn dml_extended_execute_rejects_malformed_bindings() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let relu = activation_plan(&input, DmlActivation::Relu, 0.0);
        let data = f32_bytes(&[1.0, -2.0, 3.0, -4.0]);
        let mut out = [0u8; 16];
        assert_eq!(
            execute_plan(&relu, DmlExecutionDevice::Cpu, &[], &mut out)
                .unwrap_err()
                .message,
            "operator expects 1 input buffers, got 0"
        );
        assert_eq!(
            execute_plan(&relu, DmlExecutionDevice::Cpu, &[&data[..8]], &mut out)
                .unwrap_err()
                .message,
            "input input buffer is 8 bytes, tensor requires 16"
        );
        assert_eq!(
            execute_plan(&relu, DmlExecutionDevice::Cpu, &[&data], &mut out[..8])
                .unwrap_err()
                .message,
            "output buffer is 8 bytes, tensor requires 16"
        );

        assert_eq!(
            validate_buffer_binding(8, 16, 16).unwrap_err().message,
            "buffer binding offset 8 is not 16-byte aligned"
        );
        assert_eq!(
            validate_buffer_binding(16, 4, 16).unwrap_err().message,
            "buffer binding size 4 is smaller than the required 16 bytes"
        );
        assert_eq!(
            validate_buffer_binding(u64::MAX - 15, 32, 16)
                .unwrap_err()
                .message,
            "buffer binding range overflows"
        );
        validate_buffer_binding(16, 16, 16).expect("valid binding");
    }

    #[test]
    fn dml_gemm_and_convolution_metal_numeric_readback_edge_values() {
        let a = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None);
        let b = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 2], None);
        let out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let gemm = plan(
            DmlOpKind::Gemm {
                trans_a: false,
                trans_b: false,
                alpha: 1.0,
                beta: 0.0,
            },
            vec![a, b],
            out,
        );
        assert_eq!(gemm.operator_type(), DML_OPERATOR_GEMM);
        let a_data = f32_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let b_data = f32_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        run_both(&gemm, &[&a_data, &b_data], &[22.0, 28.0, 49.0, 64.0], 1e-5);

        let transposed = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], Some(&[1, 2]));
        let transposed_plan = plan(
            DmlOpKind::Gemm {
                trans_a: true,
                trans_b: true,
                alpha: 2.0,
                beta: 0.0,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None),
        );
        let ta = f32_bytes(&[1.0, 4.0, 2.0, 5.0, 3.0, 6.0]);
        let tb = f32_bytes(&[1.0, 3.0, 5.0, 2.0, 4.0, 6.0]);
        run_both(
            &transposed_plan,
            &[&ta, &tb],
            &[44.0, 56.0, 98.0, 128.0],
            1e-4,
        );
        let _ = transposed;

        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 3, 3], None);
        let filter = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None);
        let bias = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None);
        let output = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None);
        let convolution = plan(
            DmlOpKind::Convolution {
                strides: vec![1, 1],
                dilations: vec![1, 1],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                output_padding: vec![0, 0],
                group_count: 1,
            },
            vec![input, filter, bias],
            output,
        );
        let image = f32_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]);
        let kernel = f32_bytes(&[1.0, 0.0, 0.0, -1.0]);
        let bias_data = f32_bytes(&[10.0]);
        run_both(
            &convolution,
            &[&image, &kernel, &bias_data],
            &[6.0, 6.0, 6.0, 6.0],
            1e-5,
        );
    }

    #[test]
    fn dml_pooling_activation_batchnorm_metal_numeric_readback_edge_values() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None);
        let output = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None);
        let max_pool = plan(
            DmlOpKind::Pooling {
                kind: DmlPoolingKind::Max,
                strides: vec![2, 2],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                include_padding: false,
            },
            vec![input.clone()],
            output.clone(),
        );
        assert_eq!(max_pool.operator_type(), DML_OPERATOR_MAX_POOLING);
        let values = f32_bytes(&[1.0, 2.0, 3.0, f32::NAN]);
        run_both(&max_pool, &[&values], &[f32::NAN], 0.0);

        let avg_pool = plan(
            DmlOpKind::Pooling {
                kind: DmlPoolingKind::Average,
                strides: vec![2, 2],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                include_padding: false,
            },
            vec![input],
            output,
        );
        let numbers = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        run_both(&avg_pool, &[&numbers], &[2.5], 1e-6);

        let activation_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4], None);
        let leaky = activation_plan(
            &activation_input,
            DmlActivation::LeakyRelu { alpha: 0.1 },
            0.1,
        );
        let leaky_data = f32_bytes(&[f32::NAN, f32::INFINITY, -2.0, 3.0]);
        run_both(
            &leaky,
            &[&leaky_data],
            &[f32::NAN, f32::INFINITY, -0.2, 3.0],
            1e-6,
        );

        let sigmoid = activation_plan(&activation_input, DmlActivation::Sigmoid, 0.0);
        let sigmoid_data = f32_bytes(&[0.0, f32::INFINITY, f32::NEG_INFINITY, -1.0]);
        run_both(
            &sigmoid,
            &[&sigmoid_data],
            &[0.5, 1.0, 0.0, 0.268_941_42],
            1e-6,
        );

        let tanh_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None);
        let tanh = activation_plan(&tanh_input, DmlActivation::Tanh, 0.0);
        let tanh_data = f32_bytes(&[0.0, 1.0]);
        run_both(&tanh, &[&tanh_data], &[0.0, 0.761_594_2], 1e-6);

        let batch_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 1], None);
        let batch = plan(
            DmlOpKind::BatchNormalization {
                spatial: true,
                epsilon: 0.0,
            },
            vec![
                batch_input.clone(),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 1], None),
            ],
            batch_input,
        );
        let batch_data = f32_bytes(&[1.0, 2.0]);
        let mean = f32_bytes(&[1.0, 2.0]);
        let variance = f32_bytes(&[1.0, 4.0]);
        let scale = f32_bytes(&[1.0, 1.0]);
        let bias = f32_bytes(&[0.0, 1.0]);
        run_both(
            &batch,
            &[&batch_data, &mean, &variance, &scale, &bias],
            &[0.0, 1.0],
            1e-6,
        );
    }

    #[test]
    fn dml_softmax_reduce_binary_metal_numeric_readback_edge_values() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 3], None);
        let softmax = plan(DmlOpKind::Softmax, vec![input.clone()], input);
        assert_eq!(softmax.operator_type(), DML_OPERATOR_ACTIVATION_SOFTMAX);
        let values = f32_bytes(&[1000.0, 1001.0, 1002.0]);
        let exp0 = (-2.0f64).exp();
        let exp1 = (-1.0f64).exp();
        let exp2 = 1.0f64;
        let sum = exp0 + exp1 + exp2;
        run_both(
            &softmax,
            &[&values],
            &[
                (exp0 / sum) as f32,
                (exp1 / sum) as f32,
                (exp2 / sum) as f32,
            ],
            1e-6,
        );

        let reduce_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None);
        let sum_plan = plan(
            DmlOpKind::Reduce {
                reduce: DmlReduceKind::Sum,
                axes: vec![1],
            },
            vec![reduce_input.clone()],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 1], None),
        );
        let reduce_values = f32_bytes(&[1.0, 2.0, 3.0, f32::NAN, 5.0, 6.0]);
        run_both(&sum_plan, &[&reduce_values], &[6.0, f32::NAN], 1e-6);

        let mean_plan = plan(
            DmlOpKind::Reduce {
                reduce: DmlReduceKind::Mean,
                axes: vec![1],
            },
            vec![reduce_input.clone()],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 1], None),
        );
        let finite = f32_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        run_both(&mean_plan, &[&finite], &[2.0, 5.0], 1e-6);

        let max_plan = plan(
            DmlOpKind::Reduce {
                reduce: DmlReduceKind::Max,
                axes: vec![1],
            },
            vec![reduce_input],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 1], None),
        );
        run_both(&max_plan, &[&reduce_values], &[3.0, f32::NAN], 0.0);

        let broadcast_a = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let broadcast_b = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None);
        let add = plan(
            DmlOpKind::Binary {
                op: DmlBinaryOp::Add,
            },
            vec![broadcast_a.clone(), broadcast_b],
            broadcast_a,
        );
        let left = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        let right = f32_bytes(&[10.0, 20.0]);
        run_both(&add, &[&left, &right], &[11.0, 22.0, 13.0, 24.0], 1e-6);

        let div = plan(
            DmlOpKind::Binary {
                op: DmlBinaryOp::Divide,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
        );
        let numerator = f32_bytes(&[1.0, 0.0]);
        let denominator = f32_bytes(&[0.0, 1.0]);
        run_both(
            &div,
            &[&numerator, &denominator],
            &[f32::INFINITY, 0.0],
            0.0,
        );

        let pow = plan(
            DmlOpKind::Binary {
                op: DmlBinaryOp::Pow,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
        );
        let base = f32_bytes(&[2.0, 4.0]);
        let exponent = f32_bytes(&[3.0, 0.5]);
        run_both(&pow, &[&base, &exponent], &[8.0, 2.0], 1e-6);

        let min_max = plan(
            DmlOpKind::Binary {
                op: DmlBinaryOp::Max,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
        );
        let first = f32_bytes(&[f32::NEG_INFINITY, -1.0]);
        let second = f32_bytes(&[f32::INFINITY, -2.0]);
        run_both(&min_max, &[&first, &second], &[f32::INFINITY, -1.0], 0.0);

        for (op, left_values, right_values, expected) in [
            (
                DmlBinaryOp::Subtract,
                [1.0f32, 3.0],
                [2.0f32, 1.0],
                [-1.0f32, 2.0],
            ),
            (
                DmlBinaryOp::Multiply,
                [2.0f32, 3.0],
                [4.0f32, 5.0],
                [8.0f32, 15.0],
            ),
            (
                DmlBinaryOp::Min,
                [1.0f32, -1.0],
                [2.0f32, -2.0],
                [1.0f32, -2.0],
            ),
        ] {
            let binary = plan(
                DmlOpKind::Binary { op },
                vec![
                    tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
                    tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
                ],
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
            );
            let left = f32_bytes(&left_values);
            let right = f32_bytes(&right_values);
            run_both(&binary, &[&left, &right], &expected, 1e-6);
        }
    }

    #[test]
    fn dml_reshape_transpose_concat_slice_metal_numeric_readback_edge_values() {
        let reshape_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None);
        let reshape = plan(
            DmlOpKind::Reshape,
            vec![reshape_input],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 2], None),
        );
        assert_eq!(reshape.operator_type(), DML_OPERATOR_RESHAPE);
        let values = f32_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        run_both(&reshape, &[&values], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0], 0.0);

        let transpose = plan(
            DmlOpKind::Transpose {
                permutation: vec![1, 0],
            },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None)],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 2], None),
        );
        run_both(&transpose, &[&values], &[1.0, 4.0, 2.0, 5.0, 3.0, 6.0], 0.0);

        let concat = plan(
            DmlOpKind::Concat { axis: 1 },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 4], None),
        );
        let first = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        let second = f32_bytes(&[5.0, 6.0, 7.0, 8.0]);
        run_both(
            &concat,
            &[&first, &second],
            &[1.0, 2.0, 5.0, 6.0, 3.0, 4.0, 7.0, 8.0],
            0.0,
        );

        let slice = plan(
            DmlOpKind::Slice {
                offsets: vec![1, 1],
                sizes: vec![2, 2],
                strides: vec![1, 2],
            },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 4], None)],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None),
        );
        let grid = f32_bytes(&[
            1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0,
        ]);
        run_both(&slice, &[&grid], &[6.0, 8.0, 10.0, 12.0], 0.0);
    }

    #[test]
    fn dml_gemm_float16_metal_numeric_readback_edge_values() {
        let a = tensor(DML_TENSOR_DATA_TYPE_FLOAT16, &[2, 3], None);
        let b = tensor(DML_TENSOR_DATA_TYPE_FLOAT16, &[3, 2], None);
        let out = tensor(DML_TENSOR_DATA_TYPE_FLOAT16, &[2, 2], None);
        let gemm = plan(
            DmlOpKind::Gemm {
                trans_a: false,
                trans_b: false,
                alpha: 1.0,
                beta: 0.0,
            },
            vec![a, b],
            out,
        );
        let a_data = f16_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let b_data = f16_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let mut cpu = vec![0u8; gemm.output.total_size_in_bytes as usize];
        execute_plan(
            &gemm,
            DmlExecutionDevice::Cpu,
            &[&a_data, &b_data],
            &mut cpu,
        )
        .expect("cpu f16 gemm");
        assert_eq!(read_f16(&cpu), vec![22.0, 28.0, 49.0, 64.0]);

        if metal_available() {
            let mut accelerated = vec![0u8; gemm.output.total_size_in_bytes as usize];
            execute_plan(
                &gemm,
                DmlExecutionDevice::Metal,
                &[&a_data, &b_data],
                &mut accelerated,
            )
            .expect("metal f16 gemm");
            let accelerated_values = read_f16(&accelerated);
            for (actual, expected) in accelerated_values.iter().zip([22.0, 28.0, 49.0, 64.0]) {
                assert_close(*actual, expected, 1e-2);
            }
        }
    }

    #[test]
    fn dml_float16_conversion_roundtrip_edge_values() {
        for bits in [
            0x0000u16, 0x8000, 0x3c00, 0xbc00, 0x0001, 0x03ff, 0x0400, 0x7bff,
        ] {
            let value = f16_to_f32(bits);
            assert_eq!(f32_to_f16(value), bits);
        }
        assert_eq!(f16_to_f32(0x0001), 2.0f32.powi(-24));
        assert_eq!(f32_to_f16(65_504.0), 0x7bff);
        assert_eq!(f32_to_f16(65_520.0), 0x7c00);
        assert_eq!(f32_to_f16(f32::NAN) & 0x7c00, 0x7c00);
        assert_eq!(f32_to_f16(f32::INFINITY), 0x7c00);
        assert_eq!(f32_to_f16(f32::NEG_INFINITY), 0xfc00);
    }

    #[test]
    fn dml_runtime_cpu_device_rejects_cross_device_and_executes_real_math() {
        use crate::d3d12::directml::{
            DML_FEATURE_LEVEL_1_0, DmlBufferBinding, DmlRuntime, IID_IDMLDEVICE,
        };

        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4], None);
        let relu = activation_plan(&input, DmlActivation::Relu, 0.0);
        let data = f32_bytes(&[-2.0, -1.0, 0.0, 3.0]);
        let mut runtime = DmlRuntime::new();
        let device = runtime
            .create_device_on(
                1,
                0,
                DML_FEATURE_LEVEL_1_0,
                IID_IDMLDEVICE,
                DmlExecutionDevice::Cpu,
            )
            .expect("cpu dml device");
        let operation = runtime.create_operation(device, relu).expect("operation");
        assert_eq!(
            runtime
                .compile_operation(device, operation, 0x8)
                .unwrap_err()
                .message,
            "DML_EXECUTION_FLAGS 0x8 contain undefined bits"
        );
        let compiled = runtime
            .compile_operation(device, operation, 0)
            .expect("compile cpu operation");
        let mut output = [0u8; 16];
        runtime
            .execute_operation(compiled, &[&data], &mut output)
            .expect("execute cpu operation");
        assert_eq!(read_f32(&output), vec![0.0, 0.0, 0.0, 3.0]);
        assert_eq!(runtime.operation_binding_count(compiled).unwrap(), 2);

        assert_eq!(
            runtime
                .binding_properties_for_dispatchable(compiled)
                .unwrap()
                .required_descriptor_count,
            2
        );
        let recorder = runtime
            .create_command_recorder(device)
            .expect("command recorder");
        let table = runtime
            .create_binding_table(device, compiled, 2)
            .expect("binding table");
        runtime
            .set_binding_table_inputs(
                table,
                vec![DmlBufferBinding {
                    resource: 1,
                    offset: 0,
                    size: 16,
                }],
            )
            .unwrap();
        runtime
            .set_binding_table_outputs(
                table,
                vec![DmlBufferBinding {
                    resource: 2,
                    offset: 0,
                    size: 16,
                }],
            )
            .unwrap();
        runtime
            .record_dispatch_from_binding_table(recorder, compiled, table)
            .expect("record extended dispatch");
        assert_eq!(runtime.dispatches().len(), 1);

        let other = runtime
            .create_device_on(
                2,
                0,
                DML_FEATURE_LEVEL_1_0,
                IID_IDMLDEVICE,
                DmlExecutionDevice::Cpu,
            )
            .unwrap();
        assert_eq!(
            runtime
                .compile_operation(other, operation, 0)
                .unwrap_err()
                .message,
            "operation was created by a different DirectML device"
        );
        assert_eq!(
            runtime.operation(0x9999).unwrap_err().message,
            "unknown DML operation 0x9999"
        );
        assert_eq!(
            runtime.operation_compiled(0x9999).unwrap_err().message,
            "unknown compiled DML operation 0x9999"
        );
        runtime
            .destroy_operation(operation)
            .expect("destroy operation");
        assert_eq!(
            runtime.operation_compiled(compiled).unwrap_err().message,
            format!("unknown compiled DML operation {compiled:#x}")
        );
        assert_eq!(
            runtime
                .destroy_operation_compiled(compiled)
                .unwrap_err()
                .message,
            format!("unknown compiled DML operation {compiled:#x}")
        );
    }

    fn run_cpu(plan: &DmlOpPlan, inputs: &[&[u8]]) -> Vec<f32> {
        let mut output = vec![0u8; plan.output.total_size_in_bytes as usize];
        execute_plan(plan, DmlExecutionDevice::Cpu, inputs, &mut output).expect("cpu execution");
        read_f32(&output)
    }

    fn run_cpu_outputs(plan: &DmlOpPlan, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut buffers: Vec<Vec<u8>> = plan
            .outputs()
            .map(|desc| vec![0u8; desc.total_size_in_bytes as usize])
            .collect();
        let mut slices: Vec<&mut [u8]> = buffers
            .iter_mut()
            .map(|buffer| buffer.as_mut_slice())
            .collect();
        execute_plan_outputs(plan, DmlExecutionDevice::Cpu, inputs, &mut slices)
            .expect("cpu execution");
        buffers
    }

    fn rounded(value: f32) -> i64 {
        if value.is_nan() {
            return i64::MIN;
        }
        if value.is_infinite() {
            return if value.is_sign_negative() {
                i64::MIN + 1
            } else {
                i64::MAX
            };
        }
        (value as f64 * 10_000.0).round() as i64
    }

    fn base_plan(
        kind: DmlOpKind,
        inputs: Vec<DmlTensorDesc>,
        outputs: Vec<DmlTensorDesc>,
    ) -> DmlOpPlan {
        let mut outputs = outputs.into_iter();
        DmlOpPlan {
            kind,
            inputs,
            output: outputs.next().expect("primary output"),
            extra_outputs: outputs.collect(),
            fused_activation: None,
        }
    }

    #[test]
    fn argmin_argmax_edge_reduction_nan_inf_and_invalid_axis() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None);
        let values = f32_bytes(&[1.0, 3.0, 3.0, f32::NAN, 2.0, f32::NEG_INFINITY]);
        let max_output = tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2, 1], None);
        let max_plan = plan(
            DmlOpKind::ArgMax {
                axes: vec![1],
                direction: DmlAxisDirection::Increasing,
            },
            vec![input.clone()],
            max_output.clone(),
        );
        let indices = run_cpu_outputs(&max_plan, &[&values])[0]
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(indices, vec![1, 1]);

        let min_plan = plan(
            DmlOpKind::ArgMin {
                axes: vec![1],
                direction: DmlAxisDirection::Decreasing,
            },
            vec![input],
            max_output,
        );
        let indices = run_cpu_outputs(&min_plan, &[&values])[0]
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(indices, vec![0, 2]);

        let bad = plan(
            DmlOpKind::ArgMax {
                axes: vec![2],
                direction: DmlAxisDirection::Increasing,
            },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None)],
            tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2, 1], None),
        );
        assert_eq!(
            bad.validate().unwrap_err().message,
            "argmin/argmax axis 2 is out of range for rank 2"
        );
    }

    #[test]
    fn padding_edge_wrap_reflection_and_invalid_reflection_rejected() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 3], None);
        let values = f32_bytes(&[1.0, 2.0, 3.0]);
        for (mode, expected) in [
            (DmlPaddingMode::Wrap, [3.0, 1.0, 2.0, 3.0, 1.0]),
            (DmlPaddingMode::Reflection, [2.0, 1.0, 2.0, 3.0, 2.0]),
        ] {
            let output = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 5], None);
            let plan = plan(
                DmlOpKind::Padding {
                    mode,
                    start_padding: vec![0, 1],
                    end_padding: vec![0, 1],
                    value: 0.0,
                },
                vec![input.clone()],
                output,
            );
            let actual = run_cpu(&plan, &[&values]);
            assert_eq!(
                actual.iter().copied().map(rounded).collect::<Vec<_>>(),
                expected.iter().copied().map(rounded).collect::<Vec<_>>()
            );
        }
        let invalid = plan(
            DmlOpKind::Padding {
                mode: DmlPaddingMode::Reflection,
                start_padding: vec![0, 3],
                end_padding: vec![0, 0],
                value: 0.0,
            },
            vec![input],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 6], None),
        );
        assert_eq!(
            invalid.validate().unwrap_err().message,
            "reflection padding at axis 1 must be smaller than the input size 3"
        );
    }

    #[test]
    fn resample_linear_nearest_edge_and_invalid_scale() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None);
        let values = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        let output = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 3, 3], None);
        let linear = plan(
            DmlOpKind::Resample {
                mode: DmlInterpolationMode::Linear,
                scales: vec![1.0, 1.0, 2.0, 2.0],
                input_offsets: vec![0.0; 4],
                output_offsets: vec![0.0; 4],
                rounding: DmlAxisDirection::Increasing,
                antialiased: false,
            },
            vec![input.clone()],
            output.clone(),
        );
        assert_eq!(
            run_cpu(&linear, &[&values])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![
                10000, 15000, 20000, 20000, 25000, 30000, 30000, 35000, 40000
            ]
        );
        let nearest = plan(
            DmlOpKind::Resample {
                mode: DmlInterpolationMode::NearestNeighbor,
                scales: vec![1.0, 1.0, 2.0, 2.0],
                input_offsets: vec![0.0; 4],
                output_offsets: vec![0.0; 4],
                rounding: DmlAxisDirection::Increasing,
                antialiased: false,
            },
            vec![input.clone()],
            output,
        );
        assert_eq!(
            run_cpu(&nearest, &[&values])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![
                10000, 20000, 20000, 30000, 40000, 40000, 30000, 40000, 40000
            ]
        );
        let invalid = plan(
            DmlOpKind::Resample {
                mode: DmlInterpolationMode::Linear,
                scales: vec![1.0, 1.0, 0.0, 2.0],
                input_offsets: vec![0.0; 4],
                output_offsets: vec![0.0; 4],
                rounding: DmlAxisDirection::Increasing,
                antialiased: false,
            },
            vec![input],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 3, 3], None),
        );
        assert_eq!(
            invalid.validate().unwrap_err().message,
            "resample scales must be finite and positive"
        );
    }

    #[test]
    fn topk_edge_ties_nan_and_invalid_k() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None);
        let values = f32_bytes(&[1.0, 3.0, 3.0, f32::NAN, 2.0, f32::NEG_INFINITY]);
        let value_output = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let index_output = tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2, 2], None);
        let top = base_plan(
            DmlOpKind::TopK {
                axis: 1,
                k: 2,
                direction: DmlAxisDirection::Decreasing,
            },
            vec![input.clone()],
            vec![value_output, index_output],
        );
        let buffers = run_cpu_outputs(&top, &[&values]);
        let selected = read_f32(&buffers[0]);
        assert_eq!(selected[0], 3.0);
        assert_eq!(selected[1], 3.0);
        assert_eq!(selected[2].is_nan(), true);
        assert_eq!(selected[3], 2.0);
        let indices = buffers[1]
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(indices, vec![1, 2, 0, 1]);
        let invalid = base_plan(
            DmlOpKind::TopK {
                axis: 1,
                k: 4,
                direction: DmlAxisDirection::Decreasing,
            },
            vec![input],
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 4], None),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2, 4], None),
            ],
        );
        assert_eq!(
            invalid.validate().unwrap_err().message,
            "top-k K 4 must be in 1..=3"
        );
    }

    #[test]
    fn tile_split_edge_overflow_and_invalid_divisibility() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 4], None);
        let values = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        let tile = plan(
            DmlOpKind::Tile {
                repeats: vec![1, 2],
            },
            vec![input.clone()],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 8], None),
        );
        let actual = run_cpu(&tile, &[&values]);
        assert_eq!(
            actual.iter().copied().map(rounded).collect::<Vec<_>>(),
            vec![10000, 20000, 30000, 40000, 10000, 20000, 30000, 40000]
        );
        let split = base_plan(
            DmlOpKind::Split { axis: 1 },
            vec![input.clone()],
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None),
            ],
        );
        let outputs = run_cpu_outputs(&split, &[&values]);
        assert_eq!(read_f32(&outputs[0]), vec![1.0, 2.0]);
        assert_eq!(read_f32(&outputs[1]), vec![3.0, 4.0]);
        let invalid_split = base_plan(
            DmlOpKind::Split { axis: 1 },
            vec![input],
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None),
            ],
        );
        assert_eq!(
            invalid_split.validate().unwrap_err().message,
            "split axis size 4 is not divisible by the output count 3"
        );
        let overflow = plan(
            DmlOpKind::Tile {
                repeats: vec![u32::MAX, u32::MAX],
            },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None)],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1], None),
        );
        assert_eq!(
            overflow.validate().unwrap_err().message,
            "tile output size is out of range"
        );
    }

    #[test]
    fn gather_scatter_edge_out_of_bounds_and_nd_nan() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3], None);
        let values = f32_bytes(&[1.0, f32::NAN, 3.0]);
        let indices = tensor(DML_TENSOR_DATA_TYPE_UINT32, &[3], None);
        let gather_indices = [2u32, 7, 0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>();
        let gather = plan(
            DmlOpKind::Gather {
                axis: 0,
                index_dimensions: 1,
            },
            vec![input.clone(), indices.clone()],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3], None),
        );
        let gathered = run_cpu(&gather, &[&values, &gather_indices]);
        assert_eq!(gathered[0], 3.0);
        assert_eq!(gathered[1], 0.0);
        assert_eq!(gathered[2], 1.0);

        let updates = f32_bytes(&[9.0, 8.0, 7.0]);
        let scatter = plan(
            DmlOpKind::Scatter { axis: 0 },
            vec![
                input,
                indices,
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3], None),
        );
        let scattered = run_cpu(&scatter, &[&values, &gather_indices, &updates]);
        assert_eq!(scattered[0], 7.0);
        assert_eq!(scattered[1].is_nan(), true);
        assert_eq!(scattered[2], 9.0);

        let nd_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let nd_values = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        let nd_indices = tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2, 2], None);
        let nd_index_values = [0u32, 1, 1, 0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>();
        let gather_nd = plan(
            DmlOpKind::GatherNd {
                input_dimension_count: 2,
                indices_dimension_count: 2,
                batch_dimension_count: 0,
            },
            vec![nd_input, nd_indices],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
        );
        assert_eq!(
            run_cpu(&gather_nd, &[&nd_values, &nd_index_values]),
            vec![2.0, 3.0]
        );
        let unsupported_batch = plan(
            DmlOpKind::GatherNd {
                input_dimension_count: 2,
                indices_dimension_count: 0,
                batch_dimension_count: 1,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 2], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None),
        );
        assert_eq!(
            unsupported_batch.validate().unwrap_err().message,
            "gather-nd batched indices (BatchDimensionCount != 0) are not supported"
        );
    }

    #[test]
    fn roi_pooling_align_edge_out_of_bounds_value() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None);
        let values = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        let roi = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 5], None);
        let roi_values = f32_bytes(&[0.0, 0.0, 0.0, 1.0, 1.0]);
        let pooling = plan(
            DmlOpKind::RoiPooling {
                spatial_scale: 1.0,
                pooled: vec![2, 2],
            },
            vec![input.clone(), roi],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None),
        );
        assert_eq!(
            run_cpu(&pooling, &[&values, &roi_values]),
            vec![1.0, 2.0, 3.0, 4.0]
        );

        let align_roi = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 4], None);
        let align_values = f32_bytes(&[0.0, 0.0, 1.0, 1.0]);
        let batch = tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None);
        let batch_values = 0u32.to_le_bytes();
        let align = plan(
            DmlOpKind::RoiAlign {
                reduction: DmlReduceKind::Mean,
                mode: DmlInterpolationMode::Linear,
                spatial_scale_x: 1.0,
                spatial_scale_y: 1.0,
                input_pixel_offset: 0.0,
                output_pixel_offset: 0.0,
                out_of_bounds_value: -7.0,
                minimum_samples_per_output: 1,
                maximum_samples_per_output: 1,
                align_regions_to_corners: false,
            },
            vec![input, align_roi, batch],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None),
        );
        assert_eq!(
            run_cpu(&align, &[&values, &align_values, &batch_values]),
            vec![2.5]
        );
        let invalid_samples = plan(
            DmlOpKind::RoiAlign {
                reduction: DmlReduceKind::Max,
                mode: DmlInterpolationMode::NearestNeighbor,
                spatial_scale_x: 1.0,
                spatial_scale_y: 1.0,
                input_pixel_offset: 0.0,
                output_pixel_offset: 0.0,
                out_of_bounds_value: 0.0,
                minimum_samples_per_output: 3,
                maximum_samples_per_output: 2,
                align_regions_to_corners: true,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 4], None),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None),
        );
        assert_eq!(
            invalid_samples.validate().unwrap_err().message,
            "ROI align sample counts must satisfy 1 <= minimum <= maximum <= 64, got 3..2"
        );
    }

    #[test]
    fn lrn_mvn_edge_nan_and_invalid_axes() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 3], None);
        let values = f32_bytes(&[1.0, 2.0, 3.0]);
        let lrn = plan(
            DmlOpKind::LocalResponseNormalization {
                cross_channel: false,
                local_size: 1,
                alpha: 1.0,
                beta: 1.0,
                bias: 1.0,
            },
            vec![input.clone()],
            input.clone(),
        );
        assert_eq!(
            run_cpu(&lrn, &[&values])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![5000, 4000, 3000]
        );
        let mvn_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 2], None);
        let mvn_values = f32_bytes(&[1.0, 3.0, 2.0, 6.0]);
        let mvn = plan(
            DmlOpKind::MeanVarianceNormalization {
                axes: vec![2, 3],
                normalize_variance: true,
                epsilon: 0.0,
            },
            vec![mvn_input.clone()],
            mvn_input,
        );
        assert_eq!(
            run_cpu(&mvn, &[&mvn_values])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![-10000, 10000, -10000, 10000]
        );
        let invalid = plan(
            DmlOpKind::MeanVarianceNormalization {
                axes: vec![4],
                normalize_variance: true,
                epsilon: 0.0,
            },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 2], None)],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 2], None),
        );
        assert_eq!(
            invalid.validate().unwrap_err().message,
            "mean variance normalization axis 4 is out of range for rank 4"
        );
    }

    #[test]
    fn adam_edge_hyperparameters_and_readback() {
        let parameters = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None);
        let step = tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None);
        let outputs = vec![parameters.clone(), parameters.clone(), parameters.clone()];
        let adam = base_plan(
            DmlOpKind::Adam {
                learning_rate: 0.1,
                beta1: 0.9,
                beta2: 0.999,
                epsilon: 1e-8,
            },
            vec![
                parameters.clone(),
                parameters.clone(),
                parameters.clone(),
                parameters.clone(),
                step,
            ],
            outputs,
        );
        let param_values = f32_bytes(&[1.0, 2.0]);
        let zero_values = f32_bytes(&[0.0, 0.0]);
        let gradient_values = f32_bytes(&[0.1, 0.2]);
        let step_values = 1u32.to_le_bytes();
        let result = run_cpu_outputs(
            &adam,
            &[
                &param_values,
                &zero_values,
                &zero_values,
                &gradient_values,
                &step_values,
            ],
        );
        assert_eq!(
            read_f32(&result[0])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![9000, 19000]
        );
        assert_eq!(
            read_f32(&result[1])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![100, 200]
        );
        let invalid = base_plan(
            DmlOpKind::Adam {
                learning_rate: 0.1,
                beta1: 1.0,
                beta2: 0.999,
                epsilon: 1e-8,
            },
            vec![
                parameters.clone(),
                parameters.clone(),
                parameters.clone(),
                parameters.clone(),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None),
            ],
            vec![parameters.clone(), parameters.clone(), parameters.clone()],
        );
        assert_eq!(
            invalid.validate().unwrap_err().message,
            "Adam beta1 and beta2 must be in [0, 1)"
        );
    }

    #[test]
    fn quantized_linear_edge_zero_scale_and_unsupported_per_channel_layout() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4], None);
        let values = f32_bytes(&[0.0, 0.5, 1.0, 2.0]);
        let scale = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None);
        let scale_values = f32_bytes(&[0.5]);
        let zero = tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 1, 1, 1], None);
        let zero_values = [3u8];
        let output = tensor(DML_TENSOR_DATA_TYPE_UINT8, &[4], None);
        let quantize = plan(
            DmlOpKind::QuantizeLinear,
            vec![input.clone(), scale.clone(), zero.clone()],
            output.clone(),
        );
        let result = run_cpu_outputs(&quantize, &[&values, &scale_values, &zero_values]);
        assert_eq!(result[0], vec![3u8, 4, 5, 7]);

        let dequantize = plan(
            DmlOpKind::DequantizeLinear,
            vec![output, scale.clone(), zero],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4], None),
        );
        assert_eq!(
            run_cpu(&dequantize, &[&[3u8, 4, 5, 7], &scale_values, &zero_values]),
            vec![0.0, 0.5, 1.0, 2.0]
        );
        let per_channel = plan(
            DmlOpKind::QuantizeLinear,
            vec![input, tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4], None)],
            tensor(DML_TENSOR_DATA_TYPE_UINT8, &[4], None),
        );
        assert_eq!(
            per_channel.validate().unwrap_err().message,
            "DML_OPERATOR_TYPE 33 supports only a scalar scale tensor"
        );
    }

    #[test]
    fn integer_matmul_conv_and_pooling_edge_readback() {
        let a = tensor(DML_TENSOR_DATA_TYPE_INT8, &[2, 2], None);
        let b = tensor(DML_TENSOR_DATA_TYPE_INT8, &[2, 2], None);
        let a_values = [1i8, 2, 3, 4].iter().map(|v| *v as u8).collect::<Vec<_>>();
        let b_values = [5i8, 6, 7, 8].iter().map(|v| *v as u8).collect::<Vec<_>>();
        let matmul = plan(
            DmlOpKind::MatrixMultiplyInteger {
                quantized_output: false,
                a_zero_point: false,
                b_zero_point: false,
                output_scale: false,
                output_zero_point: false,
            },
            vec![a.clone(), b.clone()],
            tensor(DML_TENSOR_DATA_TYPE_INT32, &[2, 2], None),
        );
        let result = run_cpu_outputs(&matmul, &[&a_values, &b_values]);
        let ints = result[0]
            .chunks_exact(4)
            .map(|chunk| i32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(ints, vec![19, 22, 43, 50]);

        let conv_input = tensor(DML_TENSOR_DATA_TYPE_INT8, &[1, 1, 2, 2], None);
        let conv_filter = tensor(DML_TENSOR_DATA_TYPE_INT8, &[1, 1, 1, 1], None);
        let conv_values = [1i8, 2, 3, 4].iter().map(|v| *v as u8).collect::<Vec<_>>();
        let filter_values = [1i8].iter().map(|v| *v as u8).collect::<Vec<_>>();
        let conv = plan(
            DmlOpKind::ConvolutionInteger {
                strides: vec![1, 1],
                dilations: vec![1, 1],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                group_count: 1,
                quantized_output: false,
                input_zero_point: false,
                filter_zero_point: false,
                bias: false,
                output_scale: false,
                output_zero_point: false,
            },
            vec![conv_input, conv_filter],
            tensor(DML_TENSOR_DATA_TYPE_INT32, &[1, 1, 2, 2], None),
        );
        let result = run_cpu_outputs(&conv, &[&conv_values, &filter_values]);
        let ints = result[0]
            .chunks_exact(4)
            .map(|chunk| i32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(ints, vec![1, 2, 3, 4]);

        let pool_input = tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 1, 2, 2], None);
        let scale = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None);
        let scale_one = f32_bytes(&[1.0]);
        let out_scale = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None);
        let pool = plan(
            DmlOpKind::QuantizedLinearAveragePooling {
                strides: vec![2, 2],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![1, 1],
                include_padding: false,
                input_zero_point: false,
                output_zero_point: false,
            },
            vec![pool_input, scale.clone(), out_scale.clone()],
            tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 1, 1, 1], None),
        );
        let pool_values = [1u8, 2, 3, 4];
        let result = run_cpu_outputs(&pool, &[&pool_values, &scale_one, &scale_one]);
        assert_eq!(result[0], vec![2u8]);

        let dilated_input = tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 1, 3, 3], None);
        let dilated = plan(
            DmlOpKind::QuantizedLinearAveragePooling {
                strides: vec![1, 1],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![2, 2],
                include_padding: false,
                input_zero_point: false,
                output_zero_point: false,
            },
            vec![dilated_input, scale.clone(), out_scale.clone()],
            tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 1, 1, 1], None),
        );
        let dilated_values = (1u8..=9).collect::<Vec<_>>();
        let result = run_cpu_outputs(&dilated, &[&dilated_values, &scale_one, &scale_one]);
        assert_eq!(result[0], vec![5u8]);

        let mmi_a = tensor(DML_TENSOR_DATA_TYPE_INT8, &[1, 2], None);
        let mmi_b = tensor(DML_TENSOR_DATA_TYPE_INT8, &[2, 1], None);
        let bias = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None);
        let mmi2f = plan(
            DmlOpKind::MatrixMultiplyIntegerToFloat {
                a_zero_point: false,
                b_zero_point: false,
                bias: true,
            },
            vec![mmi_a, scale.clone(), mmi_b, out_scale, bias],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1], None),
        );
        let a_bits = [1i8, 2].iter().map(|v| *v as u8).collect::<Vec<_>>();
        let b_bits = [3i8, 4].iter().map(|v| *v as u8).collect::<Vec<_>>();
        let bias_values = f32_bytes(&[0.5]);
        assert_eq!(
            run_cpu(
                &mmi2f,
                &[&a_bits, &scale_one, &b_bits, &scale_one, &bias_values]
            ),
            vec![11.5]
        );

        let unsupported = plan(
            DmlOpKind::MatrixMultiplyInteger {
                quantized_output: true,
                a_zero_point: false,
                b_zero_point: false,
                output_scale: true,
                output_zero_point: false,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_INT8, &[2, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4], None),
                tensor(DML_TENSOR_DATA_TYPE_INT8, &[2, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_INT8, &[2, 2], None),
        );
        assert_eq!(
            unsupported.validate().unwrap_err().message,
            "quantized operator scale input 1 (A scale) must be a scalar FLOAT32 tensor"
        );
    }

    fn recurrent_plan(
        ty: u32,
        gates: u32,
        output_roles: Vec<DmlRecurrentOutput>,
        input: &DmlTensorDesc,
        weight_sizes: &[u32],
        output_sizes: &[u32],
    ) -> DmlOpPlan {
        let weight = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, weight_sizes, None);
        let recurrence = tensor(
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[gates, weight_sizes[1], weight_sizes[1]],
            None,
        );
        let options = DmlRecurrentOptions::default();
        let outputs = output_roles
            .iter()
            .map(|role| match role {
                DmlRecurrentOutput::Sequence => {
                    tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, output_sizes[0]], None)
                }
                _ => tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, output_sizes[0]], None),
            })
            .collect::<Vec<_>>();
        let mut outputs_iter = outputs.into_iter();
        let primary = outputs_iter.next().expect("primary output");
        let extras = outputs_iter.collect();
        let kind = match ty {
            DML_OPERATOR_RNN => DmlOpKind::Rnn {
                direction: DmlRecurrentDirection::Forward,
                activations: Vec::new(),
                options,
                outputs: output_roles,
            },
            DML_OPERATOR_GRU => DmlOpKind::Gru {
                direction: DmlRecurrentDirection::Forward,
                activations: Vec::new(),
                options,
                outputs: output_roles,
                linear_before_reset: false,
            },
            _ => DmlOpKind::Lstm {
                direction: DmlRecurrentDirection::Forward,
                activations: Vec::new(),
                options,
                outputs: output_roles,
                clip_threshold: 0.0,
                use_clip_threshold: false,
                couple_input_forget: false,
            },
        };
        DmlOpPlan {
            kind,
            inputs: vec![input.clone(), weight, recurrence],
            output: primary,
            extra_outputs: extras,
            fused_activation: None,
        }
    }

    #[test]
    fn recurrent_edge_nan_and_invalid_direction_rejected() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1], None);
        let input_values = f32_bytes(&[1.0]);
        let rnn = recurrent_plan(
            DML_OPERATOR_RNN,
            1,
            vec![DmlRecurrentOutput::Single],
            &input,
            &[1, 1, 1],
            &[1],
        );
        let weight = f32_bytes(&[1.0]);
        let recurrence = f32_bytes(&[0.0]);
        let result = run_cpu_outputs(&rnn, &[&input_values, &weight, &recurrence]);
        assert_eq!(
            read_f32(&result[0])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![7616]
        );

        let gru = recurrent_plan(
            DML_OPERATOR_GRU,
            3,
            vec![DmlRecurrentOutput::Single],
            &input,
            &[3, 1, 1],
            &[1],
        );
        let gru_weight = f32_bytes(&[0.0, 0.0, 1.0]);
        let gru_recurrence = f32_bytes(&[0.0, 0.0, 0.0]);
        let result = run_cpu_outputs(&gru, &[&input_values, &gru_weight, &gru_recurrence]);
        assert_eq!(
            read_f32(&result[0])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![3808]
        );

        let lstm = recurrent_plan(
            DML_OPERATOR_LSTM,
            4,
            vec![DmlRecurrentOutput::Single],
            &input,
            &[4, 1, 1],
            &[1],
        );
        let lstm_weight = f32_bytes(&[1.0, 1.0, 1.0, 1.0]);
        let lstm_recurrence = f32_bytes(&[0.0, 0.0, 0.0, 0.0]);
        let result = run_cpu_outputs(&lstm, &[&input_values, &lstm_weight, &lstm_recurrence]);
        assert_eq!(
            read_f32(&result[0])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![3696]
        );

        let mut invalid = rnn.clone();
        invalid.kind = DmlOpKind::Rnn {
            direction: DmlRecurrentDirection::Backward,
            activations: Vec::new(),
            options: DmlRecurrentOptions::default(),
            outputs: vec![DmlRecurrentOutput::Single],
        };
        assert_eq!(
            invalid.validate().unwrap_err().message,
            "DML_OPERATOR_TYPE 76 only supports DML_RECURRENT_NETWORK_DIRECTION_FORWARD"
        );
    }

    #[test]
    fn fused_activation_edge_and_unsupported_fusion_rejected() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1], None);
        let values = f32_bytes(&[-1.0]);
        let mut add = plan(
            DmlOpKind::Add1,
            vec![input.clone(), input.clone()],
            input.clone(),
        );
        add.fused_activation = Some(DmlActivation::Sigmoid);
        assert_eq!(
            rounded(run_cpu(&add, &[&values, &f32_bytes(&[0.0])])[0]),
            2689
        );
        let mut unsupported = plan(DmlOpKind::Reshape, vec![input.clone()], input);
        unsupported.fused_activation = Some(DmlActivation::Relu);
        assert_eq!(
            unsupported.validate().unwrap_err().message,
            format!("DML_OPERATOR_TYPE {DML_OPERATOR_RESHAPE} does not support a fused activation")
        );
    }

    fn run_metal_outputs(plan: &DmlOpPlan, inputs: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut buffers: Vec<Vec<u8>> = plan
            .outputs()
            .map(|desc| vec![0u8; desc.total_size_in_bytes as usize])
            .collect();
        let mut slices: Vec<&mut [u8]> = buffers
            .iter_mut()
            .map(|buffer| buffer.as_mut_slice())
            .collect();
        execute_plan_outputs(plan, DmlExecutionDevice::Metal, inputs, &mut slices)
            .expect("metal execution");
        buffers
    }

    #[test]
    fn recurrent_metal_numeric_edge_readback() {
        if !metal_available() {
            return;
        }
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1], None);
        let input_values = f32_bytes(&[1.0]);
        let cases = [
            (DML_OPERATOR_RNN, 1, vec![1.0], 7616),
            (DML_OPERATOR_GRU, 3, vec![0.0, 0.0, 1.0], 3808),
            (DML_OPERATOR_LSTM, 4, vec![1.0, 1.0, 1.0, 1.0], 3696),
        ];
        for (ty, gates, weights, expected) in cases {
            let recurrent = recurrent_plan(
                ty,
                gates,
                vec![DmlRecurrentOutput::Single],
                &input,
                &[gates, 1, 1],
                &[1],
            );
            let weight_values = f32_bytes(&weights);
            let recurrence_values = f32_bytes(&vec![0.0; gates as usize]);
            let outputs = run_metal_outputs(
                &recurrent,
                &[&input_values, &weight_values, &recurrence_values],
            );
            assert_eq!(
                read_f32(&outputs[0])
                    .iter()
                    .copied()
                    .map(rounded)
                    .collect::<Vec<_>>(),
                vec![expected]
            );
        }
    }

    #[test]
    fn topk_split_metal_multi_output_edge_readback() {
        if !metal_available() {
            return;
        }
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None);
        let values = f32_bytes(&[1.0, 3.0, 3.0, f32::NAN, 2.0, f32::NEG_INFINITY]);
        let top = base_plan(
            DmlOpKind::TopK {
                axis: 1,
                k: 2,
                direction: DmlAxisDirection::Decreasing,
            },
            vec![input],
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2, 2], None),
            ],
        );
        let outputs = run_metal_outputs(&top, &[&values]);
        assert_eq!(read_f32(&outputs[0])[0], 3.0);
        assert_eq!(read_f32(&outputs[0])[1], 3.0);
        assert_eq!(read_f32(&outputs[0])[2].is_nan(), true);
        assert_eq!(
            outputs[1]
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>(),
            vec![1, 2, 0, 1]
        );

        let split = base_plan(
            DmlOpKind::Split { axis: 1 },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 4], None)],
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None),
            ],
        );
        let split_values = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        let outputs = run_metal_outputs(&split, &[&split_values]);
        assert_eq!(read_f32(&outputs[0]), vec![1.0, 2.0]);
        assert_eq!(read_f32(&outputs[1]), vec![3.0, 4.0]);

        let argmax = plan(
            DmlOpKind::ArgMax {
                axes: vec![1],
                direction: DmlAxisDirection::Increasing,
            },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None)],
            tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2, 1], None),
        );
        let max_values = f32_bytes(&[1.0, 3.0, 3.0, f32::NAN, 2.0, f32::NEG_INFINITY]);
        let outputs = run_metal_outputs(&argmax, &[&max_values]);
        assert_eq!(
            outputs[0]
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>(),
            vec![1, 1]
        );
        let argmin = plan(
            DmlOpKind::ArgMin {
                axes: vec![1],
                direction: DmlAxisDirection::Decreasing,
            },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None)],
            tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2, 1], None),
        );
        let outputs = run_metal_outputs(&argmin, &[&max_values]);
        assert_eq!(
            outputs[0]
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
    }

    #[test]
    fn roi_lrn_mvn_metal_numeric_edge_readback() {
        if !metal_available() {
            return;
        }
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None);
        let values = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        let roi = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 5], None);
        let roi_values = f32_bytes(&[0.0, 0.0, 0.0, 1.0, 1.0]);
        let pooling = plan(
            DmlOpKind::RoiPooling {
                spatial_scale: 1.0,
                pooled: vec![2, 2],
            },
            vec![input, roi],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None),
        );
        assert_eq!(
            run_metal_outputs(&pooling, &[&values, &roi_values])[0]
                .chunks_exact(4)
                .map(|chunk| f32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>(),
            vec![1.0, 2.0, 3.0, 4.0]
        );

        let lrn_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 3], None);
        let lrn = plan(
            DmlOpKind::LocalResponseNormalization {
                cross_channel: false,
                local_size: 1,
                alpha: 1.0,
                beta: 1.0,
                bias: 1.0,
            },
            vec![lrn_input.clone()],
            lrn_input,
        );
        let lrn_values = f32_bytes(&[1.0, 2.0, 3.0]);
        assert_eq!(
            run_metal_outputs(&lrn, &[&lrn_values])[0]
                .chunks_exact(4)
                .map(|chunk| rounded(f32::from_le_bytes(chunk.try_into().unwrap())))
                .collect::<Vec<_>>(),
            vec![5000, 4000, 3000]
        );

        let mvn_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 2], None);
        let mvn = plan(
            DmlOpKind::MeanVarianceNormalization {
                axes: vec![2, 3],
                normalize_variance: true,
                epsilon: 0.0,
            },
            vec![mvn_input.clone()],
            mvn_input,
        );
        let mvn_values = f32_bytes(&[1.0, 3.0, 2.0, 6.0]);
        assert_eq!(
            run_metal_outputs(&mvn, &[&mvn_values])[0]
                .chunks_exact(4)
                .map(|chunk| rounded(f32::from_le_bytes(chunk.try_into().unwrap())))
                .collect::<Vec<_>>(),
            vec![-10000, 10000, -10000, 10000]
        );
    }

    #[test]
    fn quantized_metal_numeric_edge_readback() {
        if !metal_available() {
            return;
        }
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4], None);
        let values = f32_bytes(&[0.0, 0.5, 1.0, 2.0]);
        let scale = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None);
        let scale_values = f32_bytes(&[0.5]);
        let zero = tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 1, 1, 1], None);
        let zero_values = [3u8];
        let quantize = plan(
            DmlOpKind::QuantizeLinear,
            vec![input, scale, zero],
            tensor(DML_TENSOR_DATA_TYPE_UINT8, &[4], None),
        );
        let outputs = run_metal_outputs(&quantize, &[&values, &scale_values, &zero_values]);
        assert_eq!(outputs[0], vec![3u8, 4, 5, 7]);

        let a = tensor(DML_TENSOR_DATA_TYPE_INT8, &[2, 2], None);
        let b = tensor(DML_TENSOR_DATA_TYPE_INT8, &[2, 2], None);
        let a_values = [1i8, 2, 3, 4].iter().map(|v| *v as u8).collect::<Vec<_>>();
        let b_values = [5i8, 6, 7, 8].iter().map(|v| *v as u8).collect::<Vec<_>>();
        let matmul = plan(
            DmlOpKind::MatrixMultiplyInteger {
                quantized_output: false,
                a_zero_point: false,
                b_zero_point: false,
                output_scale: false,
                output_zero_point: false,
            },
            vec![a, b],
            tensor(DML_TENSOR_DATA_TYPE_INT32, &[2, 2], None),
        );
        let outputs = run_metal_outputs(&matmul, &[&a_values, &b_values]);
        assert_eq!(
            outputs[0]
                .chunks_exact(4)
                .map(|chunk| i32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>(),
            vec![19, 22, 43, 50]
        );
        let mmi2f = plan(
            DmlOpKind::MatrixMultiplyIntegerToFloat {
                a_zero_point: false,
                b_zero_point: false,
                bias: true,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_INT8, &[1, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_INT8, &[2, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1], None),
        );
        let a_bits = [1i8, 2].iter().map(|v| *v as u8).collect::<Vec<_>>();
        let b_bits = [3i8, 4].iter().map(|v| *v as u8).collect::<Vec<_>>();
        let one = f32_bytes(&[1.0]);
        let bias = f32_bytes(&[0.5]);
        assert_eq!(
            read_f32(&run_metal_outputs(&mmi2f, &[&a_bits, &one, &b_bits, &one, &bias])[0]),
            vec![11.5]
        );
    }
}
