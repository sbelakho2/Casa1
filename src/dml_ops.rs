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
    DML_TENSOR_DATA_TYPE_FLOAT16, DML_TENSOR_DATA_TYPE_FLOAT32, DML_TENSOR_DATA_TYPE_INT4,
    DML_TENSOR_DATA_TYPE_INT8, DML_TENSOR_DATA_TYPE_INT32, DML_TENSOR_DATA_TYPE_UINT4,
    DML_TENSOR_DATA_TYPE_UINT8, DML_TENSOR_DATA_TYPE_UINT32, DML_TENSOR_MIN_ALIGNMENT, DmlError,
    DmlResult, DmlTensorDesc, E_FAIL,
};
use crate::metal_backend::MetalDevice;

pub const DML_OPERATOR_ELEMENT_WISE_ACOS: u32 = 3;
pub const DML_OPERATOR_ELEMENT_WISE_ASIN: u32 = 5;
pub const DML_OPERATOR_ELEMENT_WISE_ATAN: u32 = 6;
pub const DML_OPERATOR_ELEMENT_WISE_CLIP: u32 = 8;
pub const DML_OPERATOR_ELEMENT_WISE_LOGICAL_AND: u32 = 14;
pub const DML_OPERATOR_ELEMENT_WISE_LOGICAL_EQUALS: u32 = 15;
pub const DML_OPERATOR_ELEMENT_WISE_LOGICAL_GREATER_THAN: u32 = 16;
pub const DML_OPERATOR_ELEMENT_WISE_LOGICAL_LESS_THAN: u32 = 17;
pub const DML_OPERATOR_ELEMENT_WISE_LOGICAL_NOT: u32 = 18;
pub const DML_OPERATOR_ELEMENT_WISE_LOGICAL_OR: u32 = 19;
pub const DML_OPERATOR_ELEMENT_WISE_LOGICAL_XOR: u32 = 20;
pub const DML_OPERATOR_ELEMENT_WISE_MEAN: u32 = 22;
pub const DML_OPERATOR_ELEMENT_WISE_CONSTANT_POW: u32 = 26;
pub const DML_OPERATOR_ELEMENT_WISE_RECIP: u32 = 27;
pub const DML_OPERATOR_ELEMENT_WISE_THRESHOLD: u32 = 32;
pub const DML_OPERATOR_ELEMENT_WISE_QUANTIZE_LINEAR: u32 = 33;
pub const DML_OPERATOR_ELEMENT_WISE_DEQUANTIZE_LINEAR: u32 = 34;
pub const DML_OPERATOR_ACTIVATION_ELU: u32 = 35;
pub const DML_OPERATOR_ACTIVATION_HARDMAX: u32 = 36;
pub const DML_OPERATOR_ACTIVATION_HARD_SIGMOID: u32 = 37;
pub const DML_OPERATOR_ACTIVATION_IDENTITY: u32 = 38;
pub const DML_OPERATOR_ACTIVATION_LEAKY_RELU: u32 = 39;
pub const DML_OPERATOR_ACTIVATION_LINEAR: u32 = 40;
pub const DML_OPERATOR_ACTIVATION_LOG_SOFTMAX: u32 = 41;
pub const DML_OPERATOR_ACTIVATION_PARAMETERIZED_RELU: u32 = 42;
pub const DML_OPERATOR_ACTIVATION_PARAMETRIC_SOFTPLUS: u32 = 43;
pub const DML_OPERATOR_ACTIVATION_RELU: u32 = 44;
pub const DML_OPERATOR_ACTIVATION_SCALED_ELU: u32 = 45;
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
pub const DML_OPERATOR_LP_POOLING: u32 = 57;
pub const DML_OPERATOR_MAX_POOLING: u32 = 58;
pub const DML_OPERATOR_ROI_POOLING: u32 = 59;
pub const DML_OPERATOR_SLICE: u32 = 60;
pub const DML_OPERATOR_SPLIT: u32 = 62;
pub const DML_OPERATOR_JOIN: u32 = 63;
pub const DML_OPERATOR_PADDING: u32 = 64;
pub const DML_OPERATOR_VALUE_SCALE_2D: u32 = 65;
pub const DML_OPERATOR_UPSAMPLE_2D: u32 = 66;
pub const DML_OPERATOR_GATHER: u32 = 67;
pub const DML_OPERATOR_SPACE_TO_DEPTH: u32 = 68;
pub const DML_OPERATOR_DEPTH_TO_SPACE: u32 = 69;
pub const DML_OPERATOR_TILE: u32 = 70;
pub const DML_OPERATOR_TOP_K: u32 = 71;
pub const DML_OPERATOR_BATCH_NORMALIZATION: u32 = 72;
pub const DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION: u32 = 73;
pub const DML_OPERATOR_LOCAL_RESPONSE_NORMALIZATION: u32 = 74;
pub const DML_OPERATOR_LP_NORMALIZATION: u32 = 75;
pub const DML_OPERATOR_RNN: u32 = 76;
pub const DML_OPERATOR_LSTM: u32 = 77;
pub const DML_OPERATOR_GRU: u32 = 78;
pub const DML_OPERATOR_ELEMENT_WISE_SIGN: u32 = 79;
pub const DML_OPERATOR_ELEMENT_WISE_IS_NAN: u32 = 80;
pub const DML_OPERATOR_ELEMENT_WISE_ERF: u32 = 81;
pub const DML_OPERATOR_ELEMENT_WISE_SINH: u32 = 82;
pub const DML_OPERATOR_ELEMENT_WISE_COSH: u32 = 83;
pub const DML_OPERATOR_ELEMENT_WISE_TANH: u32 = 84;
pub const DML_OPERATOR_ELEMENT_WISE_ASINH: u32 = 85;
pub const DML_OPERATOR_ELEMENT_WISE_ACOSH: u32 = 86;
pub const DML_OPERATOR_ELEMENT_WISE_ATANH: u32 = 87;
pub const DML_OPERATOR_ELEMENT_WISE_IF: u32 = 88;
pub const DML_OPERATOR_ELEMENT_WISE_ADD1: u32 = 89;
pub const DML_OPERATOR_ACTIVATION_SHRINK: u32 = 90;
pub const DML_OPERATOR_MAX_POOLING1: u32 = 91;
pub const DML_OPERATOR_MAX_UNPOOLING: u32 = 92;
pub const DML_OPERATOR_DIAGONAL_MATRIX: u32 = 93;
pub const DML_OPERATOR_SCATTER: u32 = 94;
pub const DML_OPERATOR_SCATTER_ELEMENTS: u32 = DML_OPERATOR_SCATTER;
pub const DML_OPERATOR_ONE_HOT: u32 = 95;
pub const DML_OPERATOR_RESAMPLE: u32 = 96;
pub const DML_OPERATOR_ELEMENT_WISE_BIT_SHIFT_LEFT: u32 = 97;
pub const DML_OPERATOR_ELEMENT_WISE_BIT_SHIFT_RIGHT: u32 = 98;
pub const DML_OPERATOR_ELEMENT_WISE_ROUND: u32 = 99;
pub const DML_OPERATOR_ELEMENT_WISE_IS_INFINITY: u32 = 100;
pub const DML_OPERATOR_ELEMENT_WISE_MODULUS_TRUNCATE: u32 = 101;
pub const DML_OPERATOR_ELEMENT_WISE_MODULUS_FLOOR: u32 = 102;
pub const DML_OPERATOR_FILL_VALUE_CONSTANT: u32 = 103;
pub const DML_OPERATOR_FILL_VALUE_SEQUENCE: u32 = 104;
pub const DML_OPERATOR_CUMULATIVE_SUMMATION: u32 = 105;
pub const DML_OPERATOR_REVERSE_SUBSEQUENCES: u32 = 106;
pub const DML_OPERATOR_GATHER_ELEMENTS: u32 = 107;
pub const DML_OPERATOR_GATHER_ND: u32 = 108;
pub const DML_OPERATOR_SCATTER_ND: u32 = 109;
pub const DML_OPERATOR_MAX_POOLING2: u32 = 110;
pub const DML_OPERATOR_SLICE1: u32 = 111;
pub const DML_OPERATOR_TOP_K1: u32 = 112;
pub const DML_OPERATOR_DEPTH_TO_SPACE1: u32 = 113;
pub const DML_OPERATOR_SPACE_TO_DEPTH1: u32 = 114;
pub const DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION1: u32 = 115;
pub const DML_OPERATOR_RESAMPLE1: u32 = 116;
pub const DML_OPERATOR_MATRIX_MULTIPLY_INTEGER: u32 = 117;
pub const DML_OPERATOR_QUANTIZED_LINEAR_MATRIX_MULTIPLY: u32 = 118;
pub const DML_OPERATOR_CONVOLUTION_INTEGER: u32 = 119;
pub const DML_OPERATOR_QUANTIZED_LINEAR_CONVOLUTION: u32 = 120;
pub const DML_OPERATOR_ELEMENT_WISE_BIT_AND: u32 = 121;
pub const DML_OPERATOR_ELEMENT_WISE_BIT_OR: u32 = 122;
pub const DML_OPERATOR_ELEMENT_WISE_BIT_XOR: u32 = 123;
pub const DML_OPERATOR_ELEMENT_WISE_BIT_NOT: u32 = 124;
pub const DML_OPERATOR_ELEMENT_WISE_BIT_COUNT: u32 = 125;
pub const DML_OPERATOR_ELEMENT_WISE_LOGICAL_GREATER_THAN_OR_EQUAL: u32 = 126;
pub const DML_OPERATOR_ELEMENT_WISE_LOGICAL_LESS_THAN_OR_EQUAL: u32 = 127;
pub const DML_OPERATOR_ACTIVATION_CELU: u32 = 128;
pub const DML_OPERATOR_ACTIVATION_RELU_GRAD: u32 = 129;
pub const DML_OPERATOR_AVERAGE_POOLING_GRAD: u32 = 130;
pub const DML_OPERATOR_MAX_POOLING_GRAD: u32 = 131;
pub const DML_OPERATOR_RANDOM_GENERATOR: u32 = 132;
pub const DML_OPERATOR_NONZERO_COORDINATES: u32 = 133;
pub const DML_OPERATOR_RESAMPLE_GRAD: u32 = 134;
pub const DML_OPERATOR_SLICE_GRAD: u32 = 135;
pub const DML_OPERATOR_ADAM_OPTIMIZER: u32 = 136;
pub const DML_OPERATOR_ARGMIN: u32 = 137;
pub const DML_OPERATOR_ARGMAX: u32 = 138;
pub const DML_OPERATOR_ROI_ALIGN: u32 = 139;
pub const DML_OPERATOR_GATHER_ND1: u32 = 140;
pub const DML_OPERATOR_ELEMENT_WISE_ATAN_YX: u32 = 141;
pub const DML_OPERATOR_ELEMENT_WISE_CLIP_GRAD: u32 = 142;
pub const DML_OPERATOR_ELEMENT_WISE_DIFFERENCE_SQUARE: u32 = 143;
pub const DML_OPERATOR_LOCAL_RESPONSE_NORMALIZATION_GRAD: u32 = 144;
pub const DML_OPERATOR_CUMULATIVE_PRODUCT: u32 = 145;
pub const DML_OPERATOR_BATCH_NORMALIZATION_GRAD: u32 = 146;
pub const DML_OPERATOR_ELEMENT_WISE_QUANTIZED_LINEAR_ADD: u32 = 147;
pub const DML_OPERATOR_DYNAMIC_QUANTIZE_LINEAR: u32 = 148;
pub const DML_OPERATOR_ROI_ALIGN1: u32 = 149;
pub const DML_OPERATOR_ROI_ALIGN_GRAD: u32 = 150;
pub const DML_OPERATOR_BATCH_NORMALIZATION_TRAINING: u32 = 151;
pub const DML_OPERATOR_BATCH_NORMALIZATION_TRAINING_GRAD: u32 = 152;
pub const DML_OPERATOR_ELEMENT_WISE_CLIP1: u32 = 153;
pub const DML_OPERATOR_ELEMENT_WISE_CLIP_GRAD1: u32 = 154;
pub const DML_OPERATOR_PADDING1: u32 = 155;
pub const DML_OPERATOR_ELEMENT_WISE_NEGATE: u32 = 156;
pub const DML_OPERATOR_ACTIVATION_GELU: u32 = 157;
pub const DML_OPERATOR_ACTIVATION_SOFTMAX1: u32 = 158;
pub const DML_OPERATOR_ACTIVATION_LOG_SOFTMAX1: u32 = 159;
pub const DML_OPERATOR_ACTIVATION_HARDMAX1: u32 = 160;
pub const DML_OPERATOR_RESAMPLE2: u32 = 161;
pub const DML_OPERATOR_RESAMPLE_GRAD1: u32 = 162;
pub const DML_OPERATOR_DIAGONAL_MATRIX1: u32 = 163;
pub const DML_OPERATOR_MULTIHEAD_ATTENTION: u32 = 164;
pub const DML_OPERATOR_LP_POOLING1: u32 = 165;
pub const DML_OPERATOR_AVERAGE_POOLING1: u32 = 166;
pub const DML_OPERATOR_ACTIVATION_SWISH: u32 = 167;
pub const DML_OPERATOR_ACTIVATION_HARD_SWISH: u32 = 168;
pub const DML_OPERATOR_QUANTIZED_LINEAR_AVERAGE_POOLING: u32 = 169;
pub const DML_OPERATOR_MATRIX_MULTIPLY_INTEGER_TO_FLOAT: u32 = 170;
pub const DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION2: u32 = 171;
pub const DML_OPERATOR_MULTIHEAD_ATTENTION1: u32 = 172;
pub const DML_OPERATOR_QUANTIZE: u32 = 173;
pub const DML_OPERATOR_DEQUANTIZE: u32 = 174;
pub const DML_OPERATOR_RESAMPLE3: u32 = 175;
pub const DML_OPERATOR_FOLD: u32 = 176;
pub const DML_OPERATOR_UNFOLD: u32 = 177;
pub const DML_OPERATOR_CAST: u32 = 61;

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
    ModulusTruncate,
    ModulusFloor,
    DifferenceSquare,
    AtanYx,
    LogicalAnd,
    LogicalOr,
    LogicalXor,
    LogicalEquals,
    LogicalGreaterThan,
    LogicalLessThan,
    LogicalGreaterThanOrEqual,
    LogicalLessThanOrEqual,
    BitAnd,
    BitOr,
    BitXor,
    BitShiftLeft,
    BitShiftRight,
    Mean,
}

impl DmlBinaryOp {
    /// The `DML_OPERATOR_TYPE` this binary op lowers to.
    pub fn operator_type(self) -> u32 {
        match self {
            Self::Add => super::DML_OPERATOR_ELEMENT_WISE_ADD,
            Self::Subtract => super::DML_OPERATOR_ELEMENT_WISE_SUBTRACT,
            Self::Multiply => super::DML_OPERATOR_ELEMENT_WISE_MULTIPLY,
            Self::Divide => super::DML_OPERATOR_ELEMENT_WISE_DIVIDE,
            Self::Min => super::DML_OPERATOR_ELEMENT_WISE_MIN,
            Self::Max => super::DML_OPERATOR_ELEMENT_WISE_MAX,
            Self::Pow => super::DML_OPERATOR_ELEMENT_WISE_POW,
            Self::ModulusTruncate => DML_OPERATOR_ELEMENT_WISE_MODULUS_TRUNCATE,
            Self::ModulusFloor => DML_OPERATOR_ELEMENT_WISE_MODULUS_FLOOR,
            Self::DifferenceSquare => DML_OPERATOR_ELEMENT_WISE_DIFFERENCE_SQUARE,
            Self::AtanYx => DML_OPERATOR_ELEMENT_WISE_ATAN_YX,
            Self::LogicalAnd => DML_OPERATOR_ELEMENT_WISE_LOGICAL_AND,
            Self::LogicalOr => DML_OPERATOR_ELEMENT_WISE_LOGICAL_OR,
            Self::LogicalXor => DML_OPERATOR_ELEMENT_WISE_LOGICAL_XOR,
            Self::LogicalEquals => DML_OPERATOR_ELEMENT_WISE_LOGICAL_EQUALS,
            Self::LogicalGreaterThan => DML_OPERATOR_ELEMENT_WISE_LOGICAL_GREATER_THAN,
            Self::LogicalLessThan => DML_OPERATOR_ELEMENT_WISE_LOGICAL_LESS_THAN,
            Self::LogicalGreaterThanOrEqual => {
                DML_OPERATOR_ELEMENT_WISE_LOGICAL_GREATER_THAN_OR_EQUAL
            }
            Self::LogicalLessThanOrEqual => DML_OPERATOR_ELEMENT_WISE_LOGICAL_LESS_THAN_OR_EQUAL,
            Self::BitAnd => DML_OPERATOR_ELEMENT_WISE_BIT_AND,
            Self::BitOr => DML_OPERATOR_ELEMENT_WISE_BIT_OR,
            Self::BitXor => DML_OPERATOR_ELEMENT_WISE_BIT_XOR,
            Self::BitShiftLeft => DML_OPERATOR_ELEMENT_WISE_BIT_SHIFT_LEFT,
            Self::BitShiftRight => DML_OPERATOR_ELEMENT_WISE_BIT_SHIFT_RIGHT,
            Self::Mean => DML_OPERATOR_ELEMENT_WISE_MEAN,
        }
    }

    pub fn from_operator_type(ty: u32) -> Option<Self> {
        Some(match ty {
            super::DML_OPERATOR_ELEMENT_WISE_ADD => Self::Add,
            super::DML_OPERATOR_ELEMENT_WISE_SUBTRACT => Self::Subtract,
            super::DML_OPERATOR_ELEMENT_WISE_MULTIPLY => Self::Multiply,
            super::DML_OPERATOR_ELEMENT_WISE_DIVIDE => Self::Divide,
            super::DML_OPERATOR_ELEMENT_WISE_MIN => Self::Min,
            super::DML_OPERATOR_ELEMENT_WISE_MAX => Self::Max,
            super::DML_OPERATOR_ELEMENT_WISE_POW => Self::Pow,
            DML_OPERATOR_ELEMENT_WISE_MODULUS_TRUNCATE => Self::ModulusTruncate,
            DML_OPERATOR_ELEMENT_WISE_MODULUS_FLOOR => Self::ModulusFloor,
            DML_OPERATOR_ELEMENT_WISE_DIFFERENCE_SQUARE => Self::DifferenceSquare,
            DML_OPERATOR_ELEMENT_WISE_ATAN_YX => Self::AtanYx,
            DML_OPERATOR_ELEMENT_WISE_LOGICAL_AND => Self::LogicalAnd,
            DML_OPERATOR_ELEMENT_WISE_LOGICAL_OR => Self::LogicalOr,
            DML_OPERATOR_ELEMENT_WISE_LOGICAL_XOR => Self::LogicalXor,
            DML_OPERATOR_ELEMENT_WISE_LOGICAL_EQUALS => Self::LogicalEquals,
            DML_OPERATOR_ELEMENT_WISE_LOGICAL_GREATER_THAN => Self::LogicalGreaterThan,
            DML_OPERATOR_ELEMENT_WISE_LOGICAL_LESS_THAN => Self::LogicalLessThan,
            DML_OPERATOR_ELEMENT_WISE_LOGICAL_GREATER_THAN_OR_EQUAL => {
                Self::LogicalGreaterThanOrEqual
            }
            DML_OPERATOR_ELEMENT_WISE_LOGICAL_LESS_THAN_OR_EQUAL => Self::LogicalLessThanOrEqual,
            DML_OPERATOR_ELEMENT_WISE_BIT_AND => Self::BitAnd,
            DML_OPERATOR_ELEMENT_WISE_BIT_OR => Self::BitOr,
            DML_OPERATOR_ELEMENT_WISE_BIT_XOR => Self::BitXor,
            DML_OPERATOR_ELEMENT_WISE_BIT_SHIFT_LEFT => Self::BitShiftLeft,
            DML_OPERATOR_ELEMENT_WISE_BIT_SHIFT_RIGHT => Self::BitShiftRight,
            DML_OPERATOR_ELEMENT_WISE_MEAN => Self::Mean,
            _ => return None,
        })
    }

    pub fn minimum_feature_level(self) -> u32 {
        match self {
            Self::ModulusTruncate
            | Self::ModulusFloor
            | Self::BitShiftLeft
            | Self::BitShiftRight => super::DML_FEATURE_LEVEL_2_1,
            Self::DifferenceSquare | Self::AtanYx => super::DML_FEATURE_LEVEL_3_1,
            Self::LogicalGreaterThanOrEqual
            | Self::LogicalLessThanOrEqual
            | Self::BitAnd
            | Self::BitOr
            | Self::BitXor => super::DML_FEATURE_LEVEL_3_0,
            _ => super::DML_FEATURE_LEVEL_1_0,
        }
    }
}

/// Element-wise unary operators that are not covered by [`DmlActivation`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmlUnaryOp {
    Acos,
    Asin,
    Atan,
    Abs,
    Ceil,
    Cos,
    Exp,
    Floor,
    Log,
    Sin,
    Sqrt,
    Tan,
    Identity,
    Reciprocal,
    Sign,
    IsNan,
    Erf,
    Sinh,
    Cosh,
    Tanh,
    Asinh,
    Acosh,
    Atanh,
    Round,
    IsInfinity,
    Negate,
    Clip { min: f32, max: f32 },
    Threshold { min: f32 },
    ConstantPow { exponent: f32 },
    LogicalNot,
}

impl DmlUnaryOp {
    pub fn operator_type(self) -> u32 {
        match self {
            Self::Acos => DML_OPERATOR_ELEMENT_WISE_ACOS,
            Self::Asin => DML_OPERATOR_ELEMENT_WISE_ASIN,
            Self::Atan => DML_OPERATOR_ELEMENT_WISE_ATAN,
            Self::Abs => super::DML_OPERATOR_ELEMENT_WISE_ABS,
            Self::Ceil => super::DML_OPERATOR_ELEMENT_WISE_CEIL,
            Self::Cos => super::DML_OPERATOR_ELEMENT_WISE_COS,
            Self::Exp => super::DML_OPERATOR_ELEMENT_WISE_EXP,
            Self::Floor => super::DML_OPERATOR_ELEMENT_WISE_FLOOR,
            Self::Log => super::DML_OPERATOR_ELEMENT_WISE_LOG,
            Self::Sin => super::DML_OPERATOR_ELEMENT_WISE_SIN,
            Self::Sqrt => super::DML_OPERATOR_ELEMENT_WISE_SQRT,
            Self::Tan => super::DML_OPERATOR_ELEMENT_WISE_TAN,
            Self::Identity => super::DML_OPERATOR_ELEMENT_WISE_IDENTITY,
            Self::Reciprocal => DML_OPERATOR_ELEMENT_WISE_RECIP,
            Self::Sign => DML_OPERATOR_ELEMENT_WISE_SIGN,
            Self::IsNan => DML_OPERATOR_ELEMENT_WISE_IS_NAN,
            Self::Erf => DML_OPERATOR_ELEMENT_WISE_ERF,
            Self::Sinh => DML_OPERATOR_ELEMENT_WISE_SINH,
            Self::Cosh => DML_OPERATOR_ELEMENT_WISE_COSH,
            Self::Tanh => DML_OPERATOR_ELEMENT_WISE_TANH,
            Self::Asinh => DML_OPERATOR_ELEMENT_WISE_ASINH,
            Self::Acosh => DML_OPERATOR_ELEMENT_WISE_ACOSH,
            Self::Atanh => DML_OPERATOR_ELEMENT_WISE_ATANH,
            Self::Round => DML_OPERATOR_ELEMENT_WISE_ROUND,
            Self::IsInfinity => DML_OPERATOR_ELEMENT_WISE_IS_INFINITY,
            Self::Negate => DML_OPERATOR_ELEMENT_WISE_NEGATE,
            Self::Clip { .. } => DML_OPERATOR_ELEMENT_WISE_CLIP,
            Self::Threshold { .. } => DML_OPERATOR_ELEMENT_WISE_THRESHOLD,
            Self::ConstantPow { .. } => DML_OPERATOR_ELEMENT_WISE_CONSTANT_POW,
            Self::LogicalNot => DML_OPERATOR_ELEMENT_WISE_LOGICAL_NOT,
        }
    }

    pub fn from_operator_type(
        ty: u32,
        mut parameter: impl FnMut(u64) -> DmlResult<f32>,
    ) -> DmlResult<Self> {
        Ok(match ty {
            DML_OPERATOR_ELEMENT_WISE_ACOS => Self::Acos,
            DML_OPERATOR_ELEMENT_WISE_ASIN => Self::Asin,
            DML_OPERATOR_ELEMENT_WISE_ATAN => Self::Atan,
            DML_OPERATOR_ELEMENT_WISE_RECIP => Self::Reciprocal,
            DML_OPERATOR_ELEMENT_WISE_SIGN => Self::Sign,
            DML_OPERATOR_ELEMENT_WISE_IS_NAN => Self::IsNan,
            DML_OPERATOR_ELEMENT_WISE_ERF => Self::Erf,
            DML_OPERATOR_ELEMENT_WISE_SINH => Self::Sinh,
            DML_OPERATOR_ELEMENT_WISE_COSH => Self::Cosh,
            DML_OPERATOR_ELEMENT_WISE_TANH => Self::Tanh,
            DML_OPERATOR_ELEMENT_WISE_ASINH => Self::Asinh,
            DML_OPERATOR_ELEMENT_WISE_ACOSH => Self::Acosh,
            DML_OPERATOR_ELEMENT_WISE_ATANH => Self::Atanh,
            DML_OPERATOR_ELEMENT_WISE_ROUND => Self::Round,
            DML_OPERATOR_ELEMENT_WISE_IS_INFINITY => Self::IsInfinity,
            DML_OPERATOR_ELEMENT_WISE_NEGATE => Self::Negate,
            DML_OPERATOR_ELEMENT_WISE_CLIP => Self::Clip {
                min: parameter(24)?,
                max: parameter(28)?,
            },
            DML_OPERATOR_ELEMENT_WISE_THRESHOLD => Self::Threshold {
                min: parameter(24)?,
            },
            DML_OPERATOR_ELEMENT_WISE_CONSTANT_POW => Self::ConstantPow {
                exponent: parameter(24)?,
            },
            DML_OPERATOR_ELEMENT_WISE_LOGICAL_NOT => Self::LogicalNot,
            other => return Err(DmlError::unsupported_operator(other)),
        })
    }

    pub fn minimum_feature_level(self) -> u32 {
        match self {
            Self::Reciprocal
            | Self::Sign
            | Self::IsNan
            | Self::Erf
            | Self::Sinh
            | Self::Cosh
            | Self::Tanh
            | Self::Asinh
            | Self::Acosh
            | Self::Atanh => super::DML_FEATURE_LEVEL_2_0,
            Self::Round | Self::IsInfinity | Self::ConstantPow { .. } => {
                super::DML_FEATURE_LEVEL_2_1
            }
            Self::Negate => super::DML_FEATURE_LEVEL_5_0,
            _ => super::DML_FEATURE_LEVEL_1_0,
        }
    }
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

/// Softmax-family normalization mode. The `*1` operator variants carry an
/// explicit axis list; the legacy variants normalize over the last axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlSoftmaxKind {
    Hardmax,
    LogSoftmax,
    Softmax1,
    LogSoftmax1,
    Hardmax1,
}

impl DmlSoftmaxKind {
    pub fn operator_type(self) -> u32 {
        match self {
            Self::Hardmax => DML_OPERATOR_ACTIVATION_HARDMAX,
            Self::LogSoftmax => DML_OPERATOR_ACTIVATION_LOG_SOFTMAX,
            Self::Softmax1 => DML_OPERATOR_ACTIVATION_SOFTMAX1,
            Self::LogSoftmax1 => DML_OPERATOR_ACTIVATION_LOG_SOFTMAX1,
            Self::Hardmax1 => DML_OPERATOR_ACTIVATION_HARDMAX1,
        }
    }
}

/// Parameterized activations that are not covered by [`DmlActivation`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmlExActivation {
    /// `DML_ACTIVATION_PARAMETERIZED_RELU`: slope comes from a tensor input.
    ParameterizedRelu,
    ParametricSoftplus {
        alpha: f32,
        beta: f32,
    },
    ScaledElu {
        alpha: f32,
        gamma: f32,
    },
    Shrink {
        bias: f32,
        threshold: f32,
    },
    Celu {
        alpha: f32,
    },
    /// `DML_ACTIVATION_RELU_GRAD`: input is `(input, input_gradient)`.
    ReluGrad,
}

impl DmlExActivation {
    pub fn operator_type(self) -> u32 {
        match self {
            Self::ParameterizedRelu => DML_OPERATOR_ACTIVATION_PARAMETERIZED_RELU,
            Self::ParametricSoftplus { .. } => DML_OPERATOR_ACTIVATION_PARAMETRIC_SOFTPLUS,
            Self::ScaledElu { .. } => DML_OPERATOR_ACTIVATION_SCALED_ELU,
            Self::Shrink { .. } => DML_OPERATOR_ACTIVATION_SHRINK,
            Self::Celu { .. } => DML_OPERATOR_ACTIVATION_CELU,
            Self::ReluGrad => DML_OPERATOR_ACTIVATION_RELU_GRAD,
        }
    }

    fn minimum_feature_level(self) -> u32 {
        match self {
            Self::ParameterizedRelu => super::DML_FEATURE_LEVEL_5_1,
            Self::Shrink { .. } => super::DML_FEATURE_LEVEL_2_0,
            Self::Celu { .. } | Self::ReluGrad => super::DML_FEATURE_LEVEL_3_0,
            Self::ParametricSoftplus { .. } | Self::ScaledElu { .. } => {
                super::DML_FEATURE_LEVEL_1_0
            }
        }
    }
}

/// Which mutually-exclusive input arrangement a multi-head attention
/// descriptor uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlMhaLayout {
    /// Separate query/key/value tensors.
    Separate,
    /// `[batch, sequence, heads, 2, head]` stacked query/key.
    StackedQueryKey,
    /// `[batch, sequence, heads, 2, head]` stacked key/value.
    StackedKeyValue,
    /// `[batch, sequence, heads, 3, head]` stacked query/key/value.
    StackedQueryKeyValue,
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
        mode: u32,
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
    AveragePooling1 {
        strides: Vec<u32>,
        window: Vec<u32>,
        start_padding: Vec<u32>,
        end_padding: Vec<u32>,
        dilations: Vec<u32>,
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
        use_mean: bool,
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
    Unary {
        op: DmlUnaryOp,
    },
    Fill {
        value: f32,
        step: f32,
        sequence: bool,
    },
    OneHot {
        axis: u32,
    },
    Cumulative {
        product: bool,
        axis: u32,
        reverse: bool,
        exclusive: bool,
    },
    Reverse {
        axis: u32,
    },
    DiagonalMatrix {
        offset: i32,
        value: f32,
    },
    DiagonalMatrix1 {
        offset_begin: i32,
        offset_end: i32,
        value: f32,
    },
    SoftmaxEx {
        kind: DmlSoftmaxKind,
        axes: Vec<u32>,
    },
    ExActivation {
        activation: DmlExActivation,
    },
    If,
    BitNot,
    BitCount,
    LpPooling {
        is_v1: bool,
        p: u32,
        strides: Vec<u32>,
        window: Vec<u32>,
        start_padding: Vec<u32>,
        end_padding: Vec<u32>,
        dilations: Vec<u32>,
    },
    LpNormalization {
        axis: u32,
        epsilon: f32,
        p: u32,
    },
    ValueScale2D {
        scale: f32,
        channel_count: u32,
        bias: Vec<f32>,
    },
    SpaceDepth {
        is_v1: bool,
        to_depth: bool,
        block_size: u32,
        order: u32,
    },
    MaxPoolingEx {
        strides: Vec<u32>,
        window: Vec<u32>,
        start_padding: Vec<u32>,
        end_padding: Vec<u32>,
        dilations: Vec<u32>,
        has_indices: bool,
        dilations_supported: bool,
    },
    MaxUnpooling,
    SliceEx {
        offsets: Vec<u32>,
        sizes: Vec<u32>,
        strides: Vec<i32>,
    },
    Clip1 {
        min: f32,
        max: f32,
        scale: f32,
        bias: f32,
        has_scale_bias: bool,
    },
    ReluGrad,
    AveragePoolingGrad {
        strides: Vec<u32>,
        window: Vec<u32>,
        start_padding: Vec<u32>,
        end_padding: Vec<u32>,
        include_padding: bool,
    },
    MaxPoolingGrad {
        strides: Vec<u32>,
        window: Vec<u32>,
        start_padding: Vec<u32>,
        end_padding: Vec<u32>,
        dilations: Vec<u32>,
    },
    ResampleGrad {
        is_v1: bool,
        mode: DmlInterpolationMode,
        rounding: DmlAxisDirection,
        scales: Vec<f32>,
        input_offsets: Vec<f32>,
        output_offsets: Vec<f32>,
    },
    SliceGrad {
        offsets: Vec<u32>,
        sizes: Vec<u32>,
        strides: Vec<i32>,
    },
    ClipGrad {
        is_v1: bool,
        min: f32,
        max: f32,
    },
    LrnGrad {
        cross_channel: bool,
        local_size: u32,
        alpha: f32,
        beta: f32,
        bias: f32,
    },
    BatchNormalizationGrad {
        epsilon: f32,
    },
    BatchNormalizationTraining {
        epsilon: f32,
    },
    BatchNormalizationTrainingGrad {
        epsilon: f32,
    },
    RoiAlignGrad {
        reduction: DmlReduceKind,
        mode: DmlInterpolationMode,
        spatial_scale_x: f32,
        spatial_scale_y: f32,
        input_pixel_offset: f32,
        output_pixel_offset: f32,
        minimum_samples_per_output: u32,
        maximum_samples_per_output: u32,
        align_regions_to_corners: bool,
    },
    RandomGenerator {
        generator_type: u32,
    },
    NonZeroCoordinates,
    MultiHeadAttention {
        scale: f32,
        mask_filter_value: f32,
        query_head_count: u32,
        key_value_head_count: u32,
        mask_type: u32,
        layout: DmlMhaLayout,
        has_bias: bool,
        has_mask: bool,
        is_v1: bool,
    },
    Cast,
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
            Self::AveragePooling1 { .. } => DML_OPERATOR_AVERAGE_POOLING1,
            Self::Activation { activation, .. } => activation.operator_type(),
            Self::BatchNormalization { .. } => DML_OPERATOR_BATCH_NORMALIZATION,
            Self::Softmax => DML_OPERATOR_ACTIVATION_SOFTMAX,
            Self::Binary { op } => op.operator_type(),
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
            Self::Resample { antialiased, .. } => {
                if *antialiased {
                    DML_OPERATOR_RESAMPLE3
                } else {
                    DML_OPERATOR_RESAMPLE1
                }
            }
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
            Self::Unary { op } => op.operator_type(),
            Self::Fill { sequence, .. } => {
                if *sequence {
                    DML_OPERATOR_FILL_VALUE_SEQUENCE
                } else {
                    DML_OPERATOR_FILL_VALUE_CONSTANT
                }
            }
            Self::OneHot { .. } => DML_OPERATOR_ONE_HOT,
            Self::Cumulative { product, .. } => {
                if *product {
                    DML_OPERATOR_CUMULATIVE_PRODUCT
                } else {
                    DML_OPERATOR_CUMULATIVE_SUMMATION
                }
            }
            Self::Reverse { .. } => DML_OPERATOR_REVERSE_SUBSEQUENCES,
            Self::DiagonalMatrix { .. } => DML_OPERATOR_DIAGONAL_MATRIX,
            Self::DiagonalMatrix1 { .. } => DML_OPERATOR_DIAGONAL_MATRIX1,
            Self::SoftmaxEx { kind, .. } => match kind {
                DmlSoftmaxKind::Hardmax => DML_OPERATOR_ACTIVATION_HARDMAX,
                DmlSoftmaxKind::LogSoftmax => DML_OPERATOR_ACTIVATION_LOG_SOFTMAX,
                DmlSoftmaxKind::Softmax1 => DML_OPERATOR_ACTIVATION_SOFTMAX1,
                DmlSoftmaxKind::LogSoftmax1 => DML_OPERATOR_ACTIVATION_LOG_SOFTMAX1,
                DmlSoftmaxKind::Hardmax1 => DML_OPERATOR_ACTIVATION_HARDMAX1,
            },
            Self::ExActivation { activation } => activation.operator_type(),
            Self::If => DML_OPERATOR_ELEMENT_WISE_IF,
            Self::BitNot => DML_OPERATOR_ELEMENT_WISE_BIT_NOT,
            Self::BitCount => DML_OPERATOR_ELEMENT_WISE_BIT_COUNT,
            Self::LpPooling { is_v1, .. } => {
                if *is_v1 {
                    DML_OPERATOR_LP_POOLING1
                } else {
                    DML_OPERATOR_LP_POOLING
                }
            }
            Self::LpNormalization { .. } => DML_OPERATOR_LP_NORMALIZATION,
            Self::ValueScale2D { .. } => DML_OPERATOR_VALUE_SCALE_2D,
            Self::SpaceDepth {
                to_depth, order, ..
            } => {
                if *order != 0 {
                    if *to_depth {
                        DML_OPERATOR_SPACE_TO_DEPTH1
                    } else {
                        DML_OPERATOR_DEPTH_TO_SPACE1
                    }
                } else if *to_depth {
                    DML_OPERATOR_SPACE_TO_DEPTH
                } else {
                    DML_OPERATOR_DEPTH_TO_SPACE
                }
            }
            Self::MaxPoolingEx {
                dilations_supported,
                ..
            } => {
                if *dilations_supported {
                    DML_OPERATOR_MAX_POOLING2
                } else {
                    DML_OPERATOR_MAX_POOLING1
                }
            }
            Self::MaxUnpooling => DML_OPERATOR_MAX_UNPOOLING,
            Self::SliceEx { .. } => DML_OPERATOR_SLICE1,
            Self::Clip1 { .. } => DML_OPERATOR_ELEMENT_WISE_CLIP1,
            Self::ReluGrad => DML_OPERATOR_ACTIVATION_RELU_GRAD,
            Self::AveragePoolingGrad { .. } => DML_OPERATOR_AVERAGE_POOLING_GRAD,
            Self::MaxPoolingGrad { .. } => DML_OPERATOR_MAX_POOLING_GRAD,
            Self::ResampleGrad { is_v1, .. } => {
                if *is_v1 {
                    DML_OPERATOR_RESAMPLE_GRAD1
                } else {
                    DML_OPERATOR_RESAMPLE_GRAD
                }
            }
            Self::SliceGrad { .. } => DML_OPERATOR_SLICE_GRAD,
            Self::ClipGrad { is_v1, .. } => {
                if *is_v1 {
                    DML_OPERATOR_ELEMENT_WISE_CLIP_GRAD1
                } else {
                    DML_OPERATOR_ELEMENT_WISE_CLIP_GRAD
                }
            }
            Self::LrnGrad { .. } => DML_OPERATOR_LOCAL_RESPONSE_NORMALIZATION_GRAD,
            Self::BatchNormalizationGrad { .. } => DML_OPERATOR_BATCH_NORMALIZATION_GRAD,
            Self::BatchNormalizationTraining { .. } => DML_OPERATOR_BATCH_NORMALIZATION_TRAINING,
            Self::BatchNormalizationTrainingGrad { .. } => {
                DML_OPERATOR_BATCH_NORMALIZATION_TRAINING_GRAD
            }
            Self::RoiAlignGrad { .. } => DML_OPERATOR_ROI_ALIGN_GRAD,
            Self::RandomGenerator { .. } => DML_OPERATOR_RANDOM_GENERATOR,
            Self::NonZeroCoordinates => DML_OPERATOR_NONZERO_COORDINATES,
            Self::MultiHeadAttention { is_v1, .. } => {
                if *is_v1 {
                    DML_OPERATOR_MULTIHEAD_ATTENTION1
                } else {
                    DML_OPERATOR_MULTIHEAD_ATTENTION
                }
            }
            Self::Cast => DML_OPERATOR_CAST,
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
            | Self::ScatterNd { .. }
            | Self::MatrixMultiplyInteger { .. }
            | Self::ConvolutionInteger { .. }
            | Self::TopK { .. }
            | Self::MeanVarianceNormalization { .. } => super::DML_FEATURE_LEVEL_2_1,
            Self::Resample { antialiased, .. } => {
                if *antialiased {
                    // DML_OPERATOR_RESAMPLE3 is a feature level 6.4 operator.
                    super::DML_FEATURE_LEVEL_6_4
                } else {
                    super::DML_FEATURE_LEVEL_2_1
                }
            }
            Self::GatherNd { .. } => super::DML_FEATURE_LEVEL_6_0,
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
            Self::Unary { op } => op.minimum_feature_level(),
            Self::Fill { .. } | Self::Cumulative { .. } | Self::Reverse { .. } => {
                super::DML_FEATURE_LEVEL_2_1
            }
            Self::OneHot { .. } | Self::DiagonalMatrix { .. } => super::DML_FEATURE_LEVEL_2_0,
            Self::SoftmaxEx { kind, .. } => match kind {
                DmlSoftmaxKind::Softmax1
                | DmlSoftmaxKind::LogSoftmax1
                | DmlSoftmaxKind::Hardmax1 => super::DML_FEATURE_LEVEL_5_1,
                DmlSoftmaxKind::Hardmax | DmlSoftmaxKind::LogSoftmax => {
                    super::DML_FEATURE_LEVEL_1_0
                }
            },
            Self::ExActivation { activation } => activation.minimum_feature_level(),
            Self::If | Self::MaxUnpooling => super::DML_FEATURE_LEVEL_2_0,
            Self::BitNot | Self::BitCount => super::DML_FEATURE_LEVEL_3_0,
            Self::LpPooling { is_v1, .. } => {
                if *is_v1 {
                    super::DML_FEATURE_LEVEL_6_2
                } else {
                    super::DML_FEATURE_LEVEL_1_0
                }
            }
            Self::AveragePooling1 { .. } => super::DML_FEATURE_LEVEL_6_2,
            Self::LpNormalization { .. } => super::DML_FEATURE_LEVEL_3_1,
            Self::ValueScale2D { .. } => super::DML_FEATURE_LEVEL_1_0,
            Self::SpaceDepth { .. } | Self::MaxPoolingEx { .. } | Self::SliceEx { .. } => {
                super::DML_FEATURE_LEVEL_2_1
            }
            Self::Clip1 { .. } => super::DML_FEATURE_LEVEL_5_0,
            Self::ReluGrad
            | Self::AveragePoolingGrad { .. }
            | Self::MaxPoolingGrad { .. }
            | Self::RandomGenerator { .. }
            | Self::NonZeroCoordinates => super::DML_FEATURE_LEVEL_3_0,
            Self::ResampleGrad { is_v1, .. } => {
                if *is_v1 {
                    super::DML_FEATURE_LEVEL_5_1
                } else {
                    super::DML_FEATURE_LEVEL_3_0
                }
            }
            Self::SliceGrad { .. } | Self::LrnGrad { .. } | Self::BatchNormalizationGrad { .. } => {
                super::DML_FEATURE_LEVEL_3_1
            }
            Self::ClipGrad { is_v1, .. } => {
                if *is_v1 {
                    super::DML_FEATURE_LEVEL_5_0
                } else {
                    super::DML_FEATURE_LEVEL_3_1
                }
            }
            Self::BatchNormalizationTraining { .. }
            | Self::BatchNormalizationTrainingGrad { .. }
            | Self::RoiAlignGrad { .. } => super::DML_FEATURE_LEVEL_4_1,
            Self::DiagonalMatrix1 { .. } => super::DML_FEATURE_LEVEL_5_1,
            Self::MultiHeadAttention { is_v1, .. } => {
                if *is_v1 {
                    super::DML_FEATURE_LEVEL_6_3
                } else {
                    super::DML_FEATURE_LEVEL_6_1
                }
            }
            Self::Cast => super::DML_FEATURE_LEVEL_1_0,
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
                | Self::LpPooling { .. }
                | Self::AveragePooling1 { .. }
                | Self::MaxPoolingEx { .. }
                | Self::MaxUnpooling
                | Self::AveragePoolingGrad { .. }
                | Self::MaxPoolingGrad { .. }
                | Self::ResampleGrad { .. }
                | Self::LrnGrad { .. }
                | Self::BatchNormalizationGrad { .. }
                | Self::BatchNormalizationTraining { .. }
                | Self::BatchNormalizationTrainingGrad { .. }
                | Self::RoiAlignGrad { .. }
                | Self::MultiHeadAttention { .. }
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

    fn validate_dtypes(&self) -> DmlResult<()> {
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

    fn validate_quantized_dtypes(&self, ty: u32, _mode: u32) -> DmlResult<()> {
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

    fn validate_unary(&self, op: DmlUnaryOp) -> DmlResult<()> {
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

    fn validate_softmax_ex(&self, kind: DmlSoftmaxKind, axes: &[u32]) -> DmlResult<()> {
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

    fn validate_ex_activation(&self, activation: DmlExActivation) -> DmlResult<()> {
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

    fn validate_if(&self) -> DmlResult<()> {
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

    fn validate_bitwise(&self, count: bool) -> DmlResult<()> {
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

    fn validate_lp_pooling(
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

    fn validate_average_pooling1(
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

    fn validate_lp_normalization(&self, axis: u32, epsilon: f32, p: u32) -> DmlResult<()> {
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

    fn validate_value_scale(&self, scale: f32, channel_count: u32, bias: &[f32]) -> DmlResult<()> {
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

    fn validate_space_depth(&self, to_depth: bool, block_size: u32, order: u32) -> DmlResult<()> {
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

    fn validate_max_pooling_ex(
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

    fn validate_max_unpooling(&self) -> DmlResult<()> {
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

    fn validate_slice_ex(&self, offsets: &[u32], sizes: &[u32], strides: &[i32]) -> DmlResult<()> {
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

    fn validate_clip1(
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

    fn validate_elementwise_grad(&self, name: &str) -> DmlResult<()> {
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

    fn validate_avg_pool_grad(
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

    fn validate_max_pool_grad(
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

    fn validate_resample_grad(
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

    fn validate_slice_grad(
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

    fn validate_clip_grad(&self, min: f32, max: f32) -> DmlResult<()> {
        self.validate_elementwise_grad("clip")?;
        if !min.is_finite() || !max.is_finite() || min > max {
            return Err(DmlError::invalid(format!(
                "clip gradient bounds must be finite and min <= max, got {min} and {max}"
            )));
        }
        Ok(())
    }

    fn validate_lrn_grad(
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

    fn validate_bn_grad(&self, epsilon: f32, training: bool) -> DmlResult<()> {
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

    fn validate_bn_training(&self, epsilon: f32, _training: bool) -> DmlResult<()> {
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

    #[allow(clippy::too_many_arguments)]
    fn validate_roi_align_grad(
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

    fn validate_random_generator(&self, generator_type: u32) -> DmlResult<()> {
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

    fn validate_nonzero(&self) -> DmlResult<()> {
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

    fn validate_diagonal1(&self, offset_begin: i32, offset_end: i32, value: f32) -> DmlResult<()> {
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
    fn validate_mha(
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

    fn validate_one_hot(&self, axis: u32) -> DmlResult<()> {
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

    fn validate_cumulative(&self, axis: u32) -> DmlResult<()> {
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

    fn validate_reverse(&self, axis: u32) -> DmlResult<()> {
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
        let directions = match direction {
            DmlRecurrentDirection::Forward | DmlRecurrentDirection::Backward => 1u32,
            DmlRecurrentDirection::Bidirectional => 2u32,
        };
        let gate_count = gates * directions;
        if self.inputs.len() != options.input_count() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} expects {} input tensor(s), got {}",
                options.input_count(),
                self.inputs.len()
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
        if weight.sizes[0] != gate_count {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} weight gate count must be {gate_count}, got {}",
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
        if recurrence.sizes != [gate_count, hidden, hidden] {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} recurrence sizes must be [{gate_count}, {hidden}, {hidden}], got {:?}",
                recurrence.sizes
            )));
        }
        let mut slot = 3;
        if options.bias {
            let bias = &self.inputs[slot];
            if bias.element_count() != gate_count as u64 * hidden as u64 || !bias.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} bias must be a contiguous tensor with {} elements",
                    gate_count as u64 * hidden as u64
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
            slot += 1;
        }
        if options.peephole {
            let peephole = &self.inputs[slot];
            let expected = directions as u64 * 3 * hidden as u64;
            if ty != DML_OPERATOR_LSTM {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} does not accept a peephole tensor"
                )));
            }
            if peephole.element_count() != expected || !peephole.is_contiguous() {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} peephole tensor must contain {expected} contiguous elements (directions x 3 gates x hidden)"
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
        let hidden_output = hidden * directions;
        let mut seen = Vec::new();
        for (role, output) in outputs.iter().zip(self.outputs()) {
            if seen.contains(role) {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} output role is declared more than once"
                )));
            }
            seen.push(*role);
            if output.sizes.len() != 3 {
                return Err(DmlError::invalid(format!(
                    "DML_OPERATOR_TYPE {ty} recurrent outputs must be rank 3"
                )));
            }
            let expected = match role {
                DmlRecurrentOutput::Sequence => [sequence, batch, hidden_output],
                DmlRecurrentOutput::Single | DmlRecurrentOutput::CellSingle => {
                    [1, batch, hidden_output]
                }
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
        let batch = batch_dimension_count as usize;
        if batch >= indices_rank {
            return Err(DmlError::invalid(format!(
                "gather-nd BatchDimensionCount {batch_dimension_count} leaves no index dimensions in a rank-{indices_rank} indices tensor"
            )));
        }
        if batch > input_rank {
            return Err(DmlError::invalid(format!(
                "gather-nd BatchDimensionCount {batch_dimension_count} exceeds the input rank {input_rank}"
            )));
        }
        if indices.sizes[..batch] != input.sizes[..batch] {
            return Err(DmlError::invalid(format!(
                "gather-nd batch dimensions {:?} must match the input batch dimensions {:?}",
                &indices.sizes[..batch],
                &input.sizes[..batch]
            )));
        }
        let indexed = indices.sizes[indices_rank - 1];
        if indexed as usize > input_rank - batch {
            return Err(DmlError::invalid(format!(
                "gather-nd indices last dimension {indexed} exceeds the indexed input rank {}",
                input_rank - batch
            )));
        }
        let mut expected = indices.sizes[..indices_rank - 1].to_vec();
        expected.extend_from_slice(&input.sizes[batch + indexed as usize..]);
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

    fn validate_mvn(
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
    let element_bits = if desc.is_4bit() {
        4u64
    } else {
        desc.element_size()?.saturating_mul(8)
    };
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
        .and_then(|elements| elements.checked_mul(element_bits))
        .map(|bits| bits.div_ceil(8))
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

fn pooling_output_size_dilated(
    input: u32,
    window: u32,
    stride: u32,
    start_padding: u32,
    end_padding: u32,
    dilation: u32,
    label: &str,
) -> DmlResult<u32> {
    let effective_window = (window as u64 - 1)
        .checked_mul(dilation as u64)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| DmlError::invalid(format!("{label} effective window overflows u64")))?;
    let padded = input as u64 + start_padding as u64 + end_padding as u64;
    if padded < effective_window {
        return Err(DmlError::invalid(format!(
            "{label} window {effective_window} does not fit padded input {padded}"
        )));
    }
    let size = (padded - effective_window) / stride as u64 + 1;
    if size == 0 || size > u32::MAX as u64 {
        return Err(DmlError::invalid(format!(
            "{label} output size is out of range"
        )));
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
        DML_TENSOR_DATA_TYPE_UINT4 | DML_TENSOR_DATA_TYPE_INT4 => Ok("uchar"),
        other => Err(DmlError::invalid(format!(
            "DML_TENSOR_DATA_TYPE {other} is not supported for DML_OPERATOR_TYPE {ty}"
        ))),
    }
}

fn packed_read_4bit(pointer: &str, index: &str, signed: bool) -> String {
    let byte = format!("({index}) / 2u");
    let shift = format!("((({index}) % 2u) * 4u)");
    let raw = format!("(({pointer}[{byte}] >> {shift}) & 0x0fu)");
    if signed {
        format!("((int({raw}) & 8) != 0 ? int({raw}) - 16 : int({raw}))")
    } else {
        format!("int({raw})")
    }
}

fn packed_store_4bit(low: &str, high: &str, signed: bool) -> String {
    let (minimum, maximum) = if signed { (-8.0, 7.0) } else { (0.0, 15.0) };
    format!(
        "(uchar)((int(clamp(rint({low}), {minimum:?}f, {maximum:?}f)) & 15) | ((int(clamp(rint({high}), {minimum:?}f, {maximum:?}f)) & 15) << 4))"
    )
}

fn msl_type_unchecked(data_type: u32) -> &'static str {
    match data_type {
        DML_TENSOR_DATA_TYPE_FLOAT16 => "half",
        DML_TENSOR_DATA_TYPE_UINT32 => "uint",
        DML_TENSOR_DATA_TYPE_INT32 => "int",
        DML_TENSOR_DATA_TYPE_UINT8 => "uchar",
        DML_TENSOR_DATA_TYPE_INT8 => "char",
        DML_TENSOR_DATA_TYPE_UINT4 | DML_TENSOR_DATA_TYPE_INT4 => "uchar",
        _ => "float",
    }
}

/// MSL expression that reads one logical element as `float`.
fn msl_load_float(desc: &DmlTensorDesc, pointer: &str, index: &str) -> String {
    if desc.is_4bit() {
        format!(
            "float({})",
            packed_read_4bit(pointer, index, desc.data_type == DML_TENSOR_DATA_TYPE_INT4)
        )
    } else {
        format!("float({pointer}[{index}])")
    }
}

/// MSL expression that reads one logical element in its native scalar type.
fn msl_load_native(desc: &DmlTensorDesc, pointer: &str, index: &str) -> String {
    if desc.is_4bit() {
        packed_read_4bit(pointer, index, desc.data_type == DML_TENSOR_DATA_TYPE_INT4)
    } else {
        format!("{pointer}[{index}]")
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

/// Index expression for a quantization scale/zero-point tensor. A scalar is
/// broadcast everywhere; a tensor either matches the output rank with
/// broadcast dimensions or is a per-axis vector mapped to the output channel
/// (axis 1) or last axis.
fn quantization_tensor_index(
    desc: &DmlTensorDesc,
    output: &DmlTensorDesc,
    coords: &[String],
) -> DmlResult<String> {
    if desc.element_count() == 1 {
        return Ok("0".to_string());
    }
    if desc.sizes.len() == output.sizes.len() {
        let mut terms = Vec::with_capacity(desc.sizes.len());
        for dimension in 0..desc.sizes.len() {
            if desc.sizes[dimension] == 1 {
                continue;
            }
            if desc.sizes[dimension] != output.sizes[dimension] {
                return Err(DmlError::invalid(format!(
                    "quantization tensor dimension {dimension} size {} does not match the output size {}",
                    desc.sizes[dimension], output.sizes[dimension]
                )));
            }
            terms.push(format!(
                "({}) * {}u",
                coords[dimension], desc.strides[dimension]
            ));
        }
        return Ok(if terms.is_empty() {
            "0".to_string()
        } else {
            terms.join(" + ")
        });
    }
    if desc.sizes.len() == 1 {
        let size = desc.sizes[0];
        let axis = if output.sizes.len() >= 2 && output.sizes[1] == size {
            1
        } else if *output.sizes.last().expect("non-empty output") == size {
            output.sizes.len() - 1
        } else {
            output
                .sizes
                .iter()
                .position(|candidate| *candidate == size)
                .ok_or_else(|| {
                    DmlError::invalid(format!(
                        "quantization tensor axis size {size} does not match any output dimension"
                    ))
                })?
        };
        return Ok(format!("({}) * {}u", coords[axis], desc.strides[0]));
    }
    Err(DmlError::invalid(
        "quantization tensor must be scalar, per-axis, or broadcastable to the output rank",
    ))
}

fn quantization_index_for_linear(
    desc: &DmlTensorDesc,
    output: &DmlTensorDesc,
    index: &str,
) -> DmlResult<String> {
    let mut coords = Vec::with_capacity(output.sizes.len());
    for dimension in 0..output.sizes.len() {
        let divisor: u64 = output.sizes[dimension + 1..]
            .iter()
            .map(|size| *size as u64)
            .product();
        coords.push(format!(
            "(({index}) / {divisor}u % {}u)",
            output.sizes[dimension]
        ));
    }
    quantization_tensor_index(desc, output, &coords)
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

fn apply_binary(op: DmlBinaryOp, left: f32, right: f32) -> f32 {
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

fn unary_msl(op: DmlUnaryOp, x: &str) -> String {
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

fn unary_cpu(op: DmlUnaryOp, x: f32) -> f32 {
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
fn erf_approx(x: f32) -> f32 {
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

fn emit_unary_msl(plan: &DmlOpPlan, op: DmlUnaryOp) -> DmlResult<String> {
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

fn emit_fill_msl(plan: &DmlOpPlan, value: f32, step: f32, sequence: bool) -> DmlResult<String> {
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

fn emit_one_hot_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
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

fn emit_cumulative_msl(
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

fn emit_reverse_msl(plan: &DmlOpPlan, axis: u32) -> DmlResult<String> {
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

fn emit_diagonal_matrix_msl(plan: &DmlOpPlan, offset: i32, value: f32) -> DmlResult<String> {
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

fn emit_cast_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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

fn emit_softmax_ex_msl(plan: &DmlOpPlan, kind: DmlSoftmaxKind, axes: &[u32]) -> DmlResult<String> {
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

fn emit_ex_activation_msl(plan: &DmlOpPlan, activation: DmlExActivation) -> DmlResult<String> {
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

fn emit_if_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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

fn emit_bitwise_msl(plan: &DmlOpPlan, count: bool) -> DmlResult<String> {
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

#[allow(clippy::too_many_arguments)]
fn emit_average_pooling1_msl(
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
fn emit_lp_pooling_msl(
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

fn emit_lp_normalization_msl(
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

fn emit_value_scale_msl(
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

fn emit_space_depth_msl(
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

#[allow(clippy::too_many_arguments)]
fn emit_max_pooling_ex_msl(
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

fn emit_max_unpooling_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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

fn emit_slice_ex_msl(
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

fn emit_clip1_msl(
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

fn emit_relu_grad_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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

fn emit_avg_pool_grad_msl(
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

fn emit_max_pool_grad_msl(
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

fn emit_resample_grad_msl(
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

fn emit_slice_grad_msl(
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

fn emit_clip_grad_msl(plan: &DmlOpPlan, min: f32, max: f32) -> DmlResult<String> {
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

#[allow(clippy::too_many_arguments)]
fn emit_lrn_grad_msl(
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

fn emit_batch_normalization_training_msl(plan: &DmlOpPlan, epsilon: f32) -> DmlResult<String> {
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

fn emit_batch_normalization_grad_msl(plan: &DmlOpPlan, epsilon: f32) -> DmlResult<String> {
    emit_batch_normalization_grad_body_msl(plan, epsilon, false)
}

fn emit_batch_normalization_training_grad_msl(plan: &DmlOpPlan, epsilon: f32) -> DmlResult<String> {
    emit_batch_normalization_grad_body_msl(plan, epsilon, true)
}

fn emit_batch_normalization_grad_body_msl(
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

#[allow(clippy::too_many_arguments)]
fn emit_roi_align_grad_msl(
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

fn emit_random_generator_msl(plan: &DmlOpPlan, _generator_type: u32) -> DmlResult<String> {
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

fn emit_nonzero_msl(plan: &DmlOpPlan) -> DmlResult<String> {
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

fn emit_diagonal1_msl(
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
fn emit_mha_msl(
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
    source.push_str(&format!(
        "        acc += {} * {};\n",
        msl_load_float(&plan.inputs[0], "in0", "a_idx"),
        msl_load_float(&plan.inputs[1], "in1", "b_idx")
    ));
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
    batch_dimension_count: u32,
) -> DmlResult<String> {
    let scalar = msl_scalar(plan.output.data_type, plan.operator_type())?;
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let indices_rank = indices.sizes.len();
    let batch = batch_dimension_count as usize;
    let indexed = indices.sizes[indices_rank - 1] as usize;
    let mut source = msl_header(plan, scalar);
    push_guard(&mut source, &plan.output);
    push_output_coords(&mut source, &plan.output);
    let mut input_coords = Vec::with_capacity(input.sizes.len());
    for dimension in 0..input.sizes.len() {
        if dimension < batch {
            input_coords.push(format!("o{dimension}"));
        } else if dimension < batch + indexed {
            let index_dimension = dimension - batch;
            let mut idx_coords = vec![String::new(); indices_rank];
            for (position, coordinate) in idx_coords.iter_mut().take(indices_rank - 1).enumerate() {
                *coordinate = format!("o{position}");
            }
            idx_coords[indices_rank - 1] = format!("{index_dimension}u");
            let index_expr = linear_index(indices, &idx_coords);
            source.push_str(&format!("    int i{dimension} = int(in1[{index_expr}]);\n"));
            input_coords.push(format!(
                "uint(clamp(i{dimension}, 0, {}))",
                input.sizes[dimension] - 1
            ));
        } else {
            input_coords.push(format!(
                "o{}",
                indices_rank - 1 + dimension - batch - indexed
            ));
        }
    }
    let mut valid_terms = Vec::new();
    for dimension in 0..indexed {
        valid_terms.push(format!(
            "i{} >= 0 && i{} < {}",
            batch + dimension,
            batch + dimension,
            input.sizes[batch + dimension]
        ));
    }
    let condition = if valid_terms.is_empty() {
        "true".to_string()
    } else {
        valid_terms.join(" && ")
    };
    source.push_str(&format!(
        "    out[{}] = ({condition}) ? in0[{}] : ({scalar})0;\n",
        output_index_expr(&plan.output),
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

fn emit_generic_quantize_msl(
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

fn recurrent_activation(
    activations: &[DmlActivation],
    index: usize,
    default: DmlActivation,
) -> DmlActivation {
    activations.get(index).copied().unwrap_or(default)
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn emit_recurrent_msl_legacy(
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

fn emit_recurrent_msl(
    plan: &DmlOpPlan,
    ty: u32,
    direction: DmlRecurrentDirection,
    activations: &[DmlActivation],
    options: DmlRecurrentOptions,
    outputs: &[DmlRecurrentOutput],
    extras: RecurrentExtras,
) -> DmlResult<String> {
    let directions = match direction {
        DmlRecurrentDirection::Forward | DmlRecurrentDirection::Backward => 1u32,
        DmlRecurrentDirection::Bidirectional => 2u32,
    };
    let gates = match ty {
        DML_OPERATOR_RNN => 1u32,
        DML_OPERATOR_GRU => 3u32,
        _ => 4u32,
    };
    let input = &plan.inputs[0];
    let weight = &plan.inputs[1];
    let recurrence = &plan.inputs[2];
    let [sequence, batch_size, input_size] = [input.sizes[0], input.sizes[1], input.sizes[2]];
    let hidden = weight.sizes[1];
    let gate_span = gates * hidden;
    let output_scalars = plan
        .outputs()
        .map(|output| msl_scalar(output.data_type, ty))
        .collect::<DmlResult<Vec<_>>>()?;
    let mut source = msl_header_outputs(plan, "float", &output_scalars);
    source.push_str("    uint b = gid;\n");
    source.push_str(&format!(
        "    if (b >= {batch_size}u) return;\n    uint hidden = {hidden}u;\n"
    ));
    source.push_str(&format!(
        "    for (uint dir = 0u; dir < {directions}u; ++dir) {{\n"
    ));
    let scratch_span = 7u64 * batch_size as u64 * hidden as u64;
    source.push_str(&format!("        uint sbase = dir * {scratch_span}u;\n"));
    source.push_str(&format!(
        "        uint h0 = sbase + b * hidden;\n        uint h1 = sbase + ({batch_size}u + b) * hidden;\n        uint c0 = sbase + (2u * {batch_size}u + b) * hidden;\n        uint gb = sbase + 3u * {batch_size}u * hidden + b * hidden * 4u;\n"
    ));
    let bias_index = if options.bias { Some(3) } else { None };
    let hidden_init_index = 3 + usize::from(options.bias);
    let cell_init_index = hidden_init_index + usize::from(options.hidden_init);
    let sequence_lengths_index = cell_init_index + usize::from(options.cell_init);
    let peephole_index = sequence_lengths_index + usize::from(options.sequence_lengths);
    source.push_str("        for (uint j = 0u; j < hidden; ++j) {\n");
    if options.hidden_init {
        let desc = &plan.inputs[hidden_init_index];
        source.push_str(&format!(
            "            scratch[h0 + j] = float(in{hidden_init_index}[b * {}u + j * {}u]);\n",
            desc.strides[1], desc.strides[2]
        ));
    } else {
        source.push_str("            scratch[h0 + j] = 0.0f;\n");
    }
    if options.cell_init {
        let desc = &plan.inputs[cell_init_index];
        source.push_str(&format!(
            "            scratch[c0 + j] = float(in{cell_init_index}[b * {}u + j * {}u]);\n",
            desc.strides[1], desc.strides[2]
        ));
    } else {
        source.push_str("            scratch[c0 + j] = 0.0f;\n");
    }
    source.push_str("        }\n");
    if options.sequence_lengths {
        let desc = &plan.inputs[sequence_lengths_index];
        source.push_str(&format!(
            "        uint t_end = min({sequence}u, uint(max(int(in{sequence_lengths_index}[b * {}u]), 0)));\n",
            desc.strides[0]
        ));
    } else {
        source.push_str(&format!("        uint t_end = {sequence}u;\n"));
    }
    let reverse = match direction {
        DmlRecurrentDirection::Forward => "false",
        DmlRecurrentDirection::Backward => "true",
        DmlRecurrentDirection::Bidirectional => "dir == 1u",
    };
    let sequence_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::Sequence);
    let single_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::Single);
    let cell_output = outputs
        .iter()
        .position(|output| *output == DmlRecurrentOutput::CellSingle);
    source.push_str(&format!(
        "        for (uint step = 0u; step < {sequence}u; ++step) {{\n"
    ));
    source.push_str(&format!(
        "            uint t = ({reverse}) ? ({sequence}u - 1u - step) : step;\n"
    ));
    source.push_str("            if (t < t_end) {\n");
    let weight_index = |gate: u32| {
        format!(
            "in1[((dir * {gate_span}u + {}u + j) * {}u + i * {}u)]",
            gate * hidden,
            weight.strides[0],
            weight.strides[2]
        )
    };
    let recurrence_index = |gate: u32| {
        format!(
            "in2[((dir * {gate_span}u + {}u + j) * {}u + i * {}u)]",
            gate * hidden,
            recurrence.strides[0],
            recurrence.strides[2]
        )
    };
    let bias_index_expr = |gate: u32| {
        bias_index.map(|index| {
            format!(
                "float(in{index}[dir * {gate_span}u + {}u + j])",
                gate * hidden
            )
        })
    };
    let input_index = format!(
        "in0[t * {}u + b * {}u + i * {}u]",
        input.strides[0], input.strides[1], input.strides[2]
    );
    match ty {
        DML_OPERATOR_RNN => {
            let activation = recurrent_activation(activations, 0, DmlActivation::Tanh);
            source.push_str("                for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str("                    float sum = 0.0f;\n");
            source.push_str(&format!(
                "                    for (uint i = 0u; i < {input_size}u; ++i) sum += float({input_index}) * float({});\n",
                weight_index(0)
            ));
            source.push_str(&format!(
                "                    for (uint i = 0u; i < hidden; ++i) sum += scratch[h0 + i] * float({});\n",
                recurrence_index(0)
            ));
            if let Some(bias) = bias_index_expr(0) {
                source.push_str(&format!("                    sum += {bias};\n"));
            }
            source.push_str(&format!(
                "                    scratch[h1 + j] = {};\n                }}\n",
                activation_msl(activation, 0.0, "sum")
            ));
        }
        DML_OPERATOR_GRU => {
            let gate_activation = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
            let candidate_activation = recurrent_activation(activations, 1, DmlActivation::Tanh);
            source.push_str("                for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str("                    float z = 0.0f, r = 0.0f;\n");
            source.push_str(&format!(
                "                    for (uint i = 0u; i < {input_size}u; ++i) {{ float xv = float({input_index}); z += xv * float({}); r += xv * float({}); }}\n",
                weight_index(0),
                weight_index(1)
            ));
            source.push_str(&format!(
                "                    for (uint i = 0u; i < hidden; ++i) {{ float hv = scratch[h0 + i]; z += hv * float({}); r += hv * float({}); }}\n",
                recurrence_index(0),
                recurrence_index(1)
            ));
            if let (Some(z_bias), Some(r_bias)) = (bias_index_expr(0), bias_index_expr(1)) {
                source.push_str(&format!(
                    "                    z += {z_bias}; r += {r_bias};\n"
                ));
            }
            source.push_str(&format!(
                "                    z = {}; r = {};\n                    scratch[gb + j] = z; scratch[gb + hidden + j] = r;\n",
                activation_msl(gate_activation, 0.0, "z"),
                activation_msl(gate_activation, 0.0, "r")
            ));
            source.push_str("                }\n");
            source.push_str("                for (uint j = 0u; j < hidden; ++j) {\n");
            source.push_str("                    float reset = scratch[gb + hidden + j];\n");
            source.push_str("                    float candidate = 0.0f;\n");
            source.push_str(&format!(
                "                    for (uint i = 0u; i < {input_size}u; ++i) candidate += float({input_index}) * float({});\n",
                weight_index(2)
            ));
            source.push_str("                    float recurrent = 0.0f;\n");
            source.push_str(&format!(
                "                    for (uint i = 0u; i < hidden; ++i) recurrent += scratch[h0 + i] * float({});\n",
                recurrence_index(2)
            ));
            if let Some(bias) = bias_index_expr(2) {
                source.push_str(&format!("                    candidate += {bias};\n"));
            }
            let _ = extras.linear_before_reset;
            source.push_str(&format!(
                "                    candidate = {};\n",
                activation_msl(candidate_activation, 0.0, "candidate + reset * recurrent")
            ));
            source.push_str(
                "                    float update = scratch[gb + j];\n                    scratch[h1 + j] = (1.0f - update) * scratch[h0 + j] + update * candidate;\n                }\n",
            );
        }
        _ => {
            let gate_activation = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
            let cell_activation = recurrent_activation(activations, 1, DmlActivation::Tanh);
            let output_activation = recurrent_activation(activations, 2, DmlActivation::Tanh);
            let gate_names = ["i_gate", "o_gate", "f_gate", "c_gate"];
            source.push_str("                for (uint j = 0u; j < hidden; ++j) {\n");
            for (gate, name) in gate_names.iter().enumerate() {
                source.push_str(&format!("                    float {name} = 0.0f;\n"));
                source.push_str(&format!(
                    "                    for (uint i = 0u; i < {input_size}u; ++i) {name} += float({input_index}) * float({});\n",
                    weight_index(gate as u32)
                ));
                source.push_str(&format!(
                    "                    for (uint i = 0u; i < hidden; ++i) {name} += scratch[h0 + i] * float({});\n",
                    recurrence_index(gate as u32)
                ));
                if let Some(bias) = bias_index_expr(gate as u32) {
                    source.push_str(&format!("                    {name} += {bias};\n"));
                }
            }
            source.push_str(&format!(
                "                    i_gate = {};\n                    o_gate = {};\n                    f_gate = {};\n                    c_gate = {};\n",
                activation_msl(gate_activation, 0.0, "i_gate"),
                activation_msl(gate_activation, 0.0, "o_gate"),
                activation_msl(gate_activation, 0.0, "f_gate"),
                activation_msl(cell_activation, 0.0, "c_gate")
            ));
            if options.peephole {
                source.push_str(&format!(
                    "                    i_gate += float(in{peephole_index}[dir * {}u + j]) * scratch[c0 + j];\n                    f_gate += float(in{peephole_index}[dir * {}u + hidden + j]) * scratch[c0 + j];\n",
                    3 * hidden,
                    3 * hidden
                ));
                source.push_str(&format!(
                    "                    i_gate = {};\n                    f_gate = {};\n",
                    activation_msl(gate_activation, 0.0, "i_gate"),
                    activation_msl(gate_activation, 0.0, "f_gate")
                ));
            }
            if extras.couple_input_forget {
                source.push_str("                    f_gate = 1.0f - i_gate;\n");
            }
            source.push_str(
                "                    float cell = f_gate * scratch[c0 + j] + i_gate * c_gate;\n",
            );
            if extras.use_clip_threshold {
                source.push_str(&format!(
                    "                    cell = clamp(cell, -{}, {});\n",
                    msl_float(extras.clip_threshold),
                    msl_float(extras.clip_threshold)
                ));
            }
            source.push_str("                    scratch[gb + j] = cell;\n");
            if options.peephole {
                source.push_str(&format!(
                    "                    float o_gate_peep = float(in{peephole_index}[dir * {}u + 2u * hidden + j]);\n                    float o_gate_value = {} + o_gate_peep * cell;\n                    scratch[h1 + j] = {} * {};\n",
                    3 * hidden,
                    activation_msl(gate_activation, 0.0, "o_gate"),
                    activation_msl(gate_activation, 0.0, "o_gate_value"),
                    activation_msl(output_activation, 0.0, "cell")
                ));
            } else {
                source.push_str(&format!(
                    "                    scratch[h1 + j] = o_gate * {};\n",
                    activation_msl(output_activation, 0.0, "cell")
                ));
            }
            source.push_str("                }\n");
        }
    }
    source.push_str(
        "            } else {\n                for (uint j = 0u; j < hidden; ++j) scratch[h1 + j] = scratch[h0 + j];\n            }\n",
    );
    if let Some(role) = sequence_output {
        let output = plan.outputs().nth(role).expect("sequence output");
        let scalar = output_scalars[role];
        source.push_str("            for (uint j = 0u; j < hidden; ++j) {\n");
        source.push_str(&format!(
            "                out{role}[t * {}u + b * {}u + (dir * hidden + j) * {}u] = ({scalar})scratch[h1 + j];\n",
            output.strides[0], output.strides[1], output.strides[2]
        ));
        source.push_str("            }\n");
    }
    source.push_str(
        "            for (uint j = 0u; j < hidden; ++j) scratch[h0 + j] = scratch[h1 + j];\n",
    );
    if ty == DML_OPERATOR_LSTM {
        source.push_str("            if (t < t_end) for (uint j = 0u; j < hidden; ++j) scratch[c0 + j] = scratch[gb + j];\n");
    }
    source.push_str("        }\n");
    for (role, output) in [(single_output, "single"), (cell_output, "cell")] {
        let Some(role) = role else { continue };
        let desc = plan.outputs().nth(role).expect("recurrent output");
        let scalar = output_scalars[role];
        let source_state = if output == "cell" { "c0" } else { "h0" };
        source.push_str("        for (uint j = 0u; j < hidden; ++j) {\n");
        source.push_str(&format!(
            "            out{role}[b * {}u + (dir * hidden + j) * {}u] = ({scalar})scratch[{source_state} + j];\n",
            desc.strides[1], desc.strides[2]
        ));
        source.push_str("        }\n");
    }
    source.push_str("    }\n");
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

#[derive(Debug, Clone, Copy)]
enum GraphSource {
    Input(usize),
    Node(u32, usize),
}

fn graph_wiring(
    graph: &super::DmlGraphPlan,
) -> DmlResult<(
    Vec<Vec<Option<GraphSource>>>,
    Vec<Option<GraphSource>>,
    Vec<u64>,
)> {
    let mut inputs: Vec<Vec<Option<GraphSource>>> = graph
        .nodes
        .iter()
        .map(|node| vec![None; node.inputs.len()])
        .collect();
    for edge in &graph.input_edges {
        let slot = inputs
            .get_mut(edge.to_node as usize)
            .and_then(|node| node.get_mut(edge.to_node_input as usize))
            .ok_or_else(|| {
                DmlError::invalid(format!(
                    "input edge targets node {} input {}, which does not exist",
                    edge.to_node, edge.to_node_input
                ))
            })?;
        *slot = Some(GraphSource::Input(edge.graph_input as usize));
    }
    for edge in &graph.intermediate_edges {
        if edge.from_node as usize >= graph.nodes.len() {
            return Err(DmlError::invalid(format!(
                "intermediate edge references node {}, which does not exist",
                edge.from_node
            )));
        }
        let slot = inputs
            .get_mut(edge.to_node as usize)
            .and_then(|node| node.get_mut(edge.to_node_input as usize))
            .ok_or_else(|| {
                DmlError::invalid(format!(
                    "intermediate edge targets node {} input {}, which does not exist",
                    edge.to_node, edge.to_node_input
                ))
            })?;
        *slot = Some(GraphSource::Node(
            edge.from_node,
            edge.from_node_output as usize,
        ));
    }
    for (node_index, node) in graph.nodes.iter().enumerate() {
        for (input_index, source) in inputs[node_index].iter().enumerate() {
            if source.is_none() {
                return Err(DmlError::invalid(format!(
                    "graph node {node_index} input {input_index} is not connected"
                )));
            }
        }
        for (input_index, desc) in node.inputs.iter().enumerate() {
            if let Some(GraphSource::Node(from_node, from_output)) = inputs[node_index][input_index]
            {
                let source = graph
                    .nodes
                    .get(from_node as usize)
                    .and_then(|node| node.outputs().nth(from_output));
                let Some(source) = source else {
                    return Err(DmlError::invalid(format!(
                        "graph edge references node {from_node} output {from_output}, which does not exist"
                    )));
                };
                if source.total_size_in_bytes < desc.total_size_in_bytes {
                    return Err(DmlError::invalid(format!(
                        "graph node {node_index} input {input_index} requires {} bytes but node {from_node} output {from_output} provides {}",
                        desc.total_size_in_bytes, source.total_size_in_bytes
                    )));
                }
            }
        }
    }
    let mut outputs = vec![None; graph.output_count as usize];
    for edge in &graph.output_edges {
        if edge.graph_output as usize >= outputs.len() {
            return Err(DmlError::invalid(format!(
                "graph output {} is out of range",
                edge.graph_output
            )));
        }
        let exists = graph
            .nodes
            .get(edge.from_node as usize)
            .and_then(|node| node.outputs().nth(edge.from_node_output as usize))
            .is_some();
        if !exists {
            return Err(DmlError::invalid(format!(
                "output edge references node {} output {}, which does not exist",
                edge.from_node, edge.from_node_output
            )));
        }
        outputs[edge.graph_output as usize] = Some(GraphSource::Node(
            edge.from_node,
            edge.from_node_output as usize,
        ));
    }
    for (index, source) in outputs.iter().enumerate() {
        if source.is_none() {
            return Err(DmlError::invalid(format!(
                "graph output {index} is not connected"
            )));
        }
    }
    let mut input_sizes = vec![0u64; graph.input_count as usize];
    for (node_index, node) in graph.nodes.iter().enumerate() {
        for (input_index, source) in inputs[node_index].iter().enumerate() {
            if let Some(GraphSource::Input(index)) = source {
                input_sizes[*index] =
                    input_sizes[*index].max(node.inputs[input_index].total_size_in_bytes);
            }
        }
    }
    for (index, size) in input_sizes.iter().enumerate() {
        if *size == 0 {
            return Err(DmlError::invalid(format!(
                "graph input {index} is not connected"
            )));
        }
    }
    Ok((inputs, outputs, input_sizes))
}

/// Execute a validated DirectML graph. Nodes run in topological order; the
/// Metal backend compiles every node into one MSL library and records all
/// kernels on a single command buffer, wiring node outputs directly into
/// downstream input buffers (no host round-trip between nodes).
pub fn execute_graph_plan(
    graph: &super::DmlGraphPlan,
    backend: DmlExecutionDevice,
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) -> DmlResult<()> {
    let (wiring, output_sources, input_sizes) = graph_wiring(graph)?;
    let mut seen = vec![false; graph.nodes.len()];
    for node in &graph.execution_order {
        let Some(flag) = seen.get_mut(*node as usize) else {
            return Err(DmlError::invalid(format!(
                "graph execution order references node {node}, which does not exist"
            )));
        };
        if *flag {
            return Err(DmlError::invalid(format!(
                "graph execution order contains node {node} more than once"
            )));
        }
        *flag = true;
    }
    if let Some(index) = seen.iter().position(|value| !value) {
        return Err(DmlError::invalid(format!(
            "graph execution order does not include node {index}"
        )));
    }
    if inputs.len() != graph.input_count as usize {
        return Err(DmlError::invalid(format!(
            "graph expects {} input buffers, got {}",
            graph.input_count,
            inputs.len()
        )));
    }
    if outputs.len() != graph.output_count as usize {
        return Err(DmlError::invalid(format!(
            "graph expects {} output buffers, got {}",
            graph.output_count,
            outputs.len()
        )));
    }
    for (index, (buffer, size)) in inputs.iter().zip(&input_sizes).enumerate() {
        if buffer.len() < *size as usize {
            return Err(DmlError::invalid(format!(
                "graph input {index} buffer is {} bytes, graph requires {size}",
                buffer.len()
            )));
        }
    }
    for (index, (buffer, source)) in outputs.iter().zip(&output_sources).enumerate() {
        let Some(GraphSource::Node(node, output)) = source else {
            return Err(DmlError::invalid(format!(
                "graph output {index} has no source"
            )));
        };
        let desc = graph.nodes[*node as usize]
            .outputs()
            .nth(*output)
            .ok_or_else(|| DmlError::invalid("graph output source is missing"))?;
        if buffer.len() < desc.total_size_in_bytes as usize {
            return Err(DmlError::invalid(format!(
                "graph output {index} buffer is {} bytes, graph requires {}",
                buffer.len(),
                desc.total_size_in_bytes
            )));
        }
    }
    match backend {
        DmlExecutionDevice::Cpu => {
            execute_graph_cpu(graph, &wiring, &output_sources, inputs, outputs)
        }
        DmlExecutionDevice::Metal => {
            execute_graph_metal(graph, &wiring, &output_sources, inputs, outputs)
        }
    }
}

fn execute_graph_cpu(
    graph: &super::DmlGraphPlan,
    wiring: &[Vec<Option<GraphSource>>],
    output_sources: &[Option<GraphSource>],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) -> DmlResult<()> {
    let mut produced: std::collections::BTreeMap<(u32, usize), Vec<u8>> =
        std::collections::BTreeMap::new();
    for node_index in &graph.execution_order {
        let node = &graph.nodes[*node_index as usize];
        let input_buffers: Vec<&[u8]> = wiring[*node_index as usize]
            .iter()
            .map(|source| match source.expect("graph wiring validated") {
                GraphSource::Input(index) => Ok(inputs[index]),
                GraphSource::Node(node, output) => produced
                    .get(&(node, output))
                    .map(|buffer| buffer.as_slice())
                    .ok_or_else(|| {
                        DmlError::invalid(format!(
                            "graph node {node} output {output} is not available"
                        ))
                    }),
            })
            .collect::<DmlResult<Vec<_>>>()?;
        let mut node_outputs: Vec<Vec<u8>> = node
            .outputs()
            .map(|desc| vec![0u8; desc.total_size_in_bytes as usize])
            .collect();
        {
            let mut slices: Vec<&mut [u8]> = node_outputs
                .iter_mut()
                .map(|buffer| buffer.as_mut_slice())
                .collect();
            execute_plan_outputs(node, DmlExecutionDevice::Cpu, &input_buffers, &mut slices)?;
        }
        for (output, buffer) in node_outputs.into_iter().enumerate() {
            produced.insert((*node_index, output), buffer);
        }
    }
    for (index, source) in output_sources.iter().enumerate() {
        let Some(GraphSource::Node(node, output)) = source else {
            return Err(DmlError::invalid("graph output source is missing"));
        };
        let buffer = produced
            .get(&(*node, *output))
            .ok_or_else(|| DmlError::invalid("graph output was not produced"))?;
        outputs[index][..buffer.len()].copy_from_slice(buffer);
    }
    Ok(())
}

/// Whether a node can participate in a cross-node elementwise fusion.
///
/// Fusion is deliberately limited to FLOAT32 single-output element-wise nodes
/// with identical output shapes. That guarantees the fused kernel performs the
/// exact same float arithmetic as the wired per-node kernels (no intermediate
/// half rounding), while the wired path remains the fallback for everything
/// else.
fn fusion_candidate(node: &DmlOpPlan, sizes: &[u32]) -> bool {
    if node.output.data_type != DML_TENSOR_DATA_TYPE_FLOAT32
        || !node.extra_outputs.is_empty()
        || node.output.sizes != sizes
        || node.fused_activation.is_some()
    {
        return false;
    }
    if node.inputs.iter().any(|desc| {
        desc.data_type != DML_TENSOR_DATA_TYPE_FLOAT32
            || desc.sizes.len() != sizes.len()
            || desc
                .sizes
                .iter()
                .zip(sizes)
                .any(|(input, output)| *input != *output && *input != 1)
    }) {
        return false;
    }
    matches!(
        node.kind,
        DmlOpKind::Activation { .. }
            | DmlOpKind::Unary { .. }
            | DmlOpKind::Binary { .. }
            | DmlOpKind::Add1
    )
}

/// Build the graph input slot list and emit one MSL kernel for a fused chain.
fn emit_fused_chain_msl(
    name: &str,
    graph: &super::DmlGraphPlan,
    wiring: &[Vec<Option<GraphSource>>],
    nodes: &[usize],
) -> DmlResult<(String, Vec<usize>)> {
    let root = &graph.nodes[nodes[0]];
    let sizes = root.output.sizes.clone();
    let mut used_inputs: Vec<usize> = Vec::new();
    let mut source = String::from("#include <metal_stdlib>\nusing namespace metal;\n");
    source.push_str(&format!("kernel void {name}("));
    // The input list is discovered while emitting, so emit the body first into
    // a temporary buffer and prepend the signature afterwards.
    let mut body = String::new();
    let count = root.output.element_count();
    body.push_str(&format!("    if (gid >= {count}u) return;\n"));
    for (index, size) in sizes.iter().enumerate() {
        let divisor: u64 = sizes[index + 1..]
            .iter()
            .map(|value| *value as u64)
            .product();
        body.push_str(&format!(
            "    uint o{index} = (gid / {divisor}u) % {size}u;\n"
        ));
    }
    let register_input = |graph_input: usize, used_inputs: &mut Vec<usize>| -> usize {
        if let Some(slot) = used_inputs.iter().position(|value| *value == graph_input) {
            slot
        } else {
            used_inputs.push(graph_input);
            used_inputs.len() - 1
        }
    };
    let mut value_name: Option<String> = None;
    for (step, node_index) in nodes.iter().enumerate() {
        let node = &graph.nodes[*node_index];
        let previous = value_name.clone();
        let load = |input_index: usize, used_inputs: &mut Vec<usize>| -> DmlResult<String> {
            match wiring[*node_index][input_index].expect("graph wiring validated") {
                GraphSource::Input(graph_input) => {
                    let slot = register_input(graph_input, used_inputs);
                    Ok(msl_load_float(
                        &node.inputs[input_index],
                        &format!("in{slot}"),
                        &broadcast_index(&node.inputs[input_index]),
                    ))
                }
                GraphSource::Node(node_id, _) => {
                    if step > 0 && node_id as usize == nodes[step - 1] {
                        Ok(previous.clone().expect("previous value"))
                    } else {
                        Err(DmlError::invalid(format!(
                            "fused graph node {node_index} has a non-fusable input"
                        )))
                    }
                }
            }
        };
        let value = match &node.kind {
            DmlOpKind::Activation { activation, alpha } => {
                let input = load(0, &mut used_inputs)?;
                format!(
                    "    float v{step} = {};\n",
                    activation_msl(*activation, *alpha, &format!("({input})"))
                )
            }
            DmlOpKind::Unary { op } => {
                let input = load(0, &mut used_inputs)?;
                format!(
                    "    float v{step} = {};\n",
                    unary_msl(*op, &format!("({input})"))
                )
            }
            DmlOpKind::Binary { op } => {
                let left = load(0, &mut used_inputs)?;
                let right = load(1, &mut used_inputs)?;
                format!(
                    "    float v{step};\n    {{\n        float fa{step} = {left};\n        float fb{step} = {right};\n        float a = fa{step};\n        float b = fb{step};\n        v{step} = ({});\n    }}\n",
                    emit_scalar_binary(*op)
                )
            }
            DmlOpKind::Add1 => {
                let left = load(0, &mut used_inputs)?;
                let right = load(1, &mut used_inputs)?;
                format!(
                    "    float v{step};\n    {{\n        float fa{step} = {left};\n        float fb{step} = {right};\n        float a = fa{step};\n        float b = fb{step};\n        v{step} = (a + b);\n    }}\n"
                )
            }
            _ => {
                return Err(DmlError::invalid(
                    "node is not a fusable element-wise operator",
                ));
            }
        };
        body.push_str(&value);
        value_name = Some(format!("v{step}"));
    }
    for (slot, _) in used_inputs.iter().enumerate() {
        source.push_str(&format!(
            "device const float* in{slot} [[buffer({slot})]], "
        ));
    }
    source.push_str(&format!(
        "device float* out [[buffer({})]], uint gid [[thread_position_in_grid]]) {{\n",
        used_inputs.len()
    ));
    source.push_str(&body);
    let last = value_name.expect("fused chain non-empty");
    source.push_str(&format!(
        "    out[{}] = {last};\n",
        output_index_expr(&root.output)
    ));
    source.push_str("}\n");
    Ok((source, used_inputs))
}

/// Select maximal single-consumer element-wise chains.
fn find_fusion_chains(
    graph: &super::DmlGraphPlan,
    wiring: &[Vec<Option<GraphSource>>],
    output_sources: &[Option<GraphSource>],
) -> Vec<Vec<usize>> {
    let mut consumers: std::collections::BTreeMap<(usize, usize), Vec<(usize, usize)>> =
        std::collections::BTreeMap::new();
    let mut graph_outputs = std::collections::BTreeSet::new();
    for (node_index, inputs) in wiring.iter().enumerate() {
        for (input_index, source) in inputs.iter().enumerate() {
            if let Some(GraphSource::Node(node, output)) = source {
                consumers
                    .entry((*node as usize, *output))
                    .or_default()
                    .push((node_index, input_index));
            }
        }
    }
    for source in output_sources.iter().flatten() {
        if let GraphSource::Node(node, output) = source {
            graph_outputs.insert((*node as usize, *output));
        }
    }
    let mut fused = std::collections::BTreeSet::new();
    let mut chains = Vec::new();
    for node_index in &graph.execution_order {
        let index = *node_index as usize;
        if fused.contains(&index) {
            continue;
        }
        let sizes = graph.nodes[index].output.sizes.clone();
        if !fusion_candidate(&graph.nodes[index], &sizes)
            || wiring[index]
                .iter()
                .any(|source| !matches!(source, Some(GraphSource::Input(_))))
        {
            continue;
        }
        let mut chain = vec![index];
        loop {
            let last = *chain.last().expect("chain");
            if graph_outputs.contains(&(last, 0)) {
                break;
            }
            let Some(next) = consumers.get(&(last, 0)) else {
                break;
            };
            if next.len() != 1 {
                break;
            }
            let (next_node, _next_input) = next[0];
            if fused.contains(&next_node)
                || chain.contains(&next_node)
                || !fusion_candidate(&graph.nodes[next_node], &sizes)
            {
                break;
            }
            // Every other input must be a graph input; the chain link must be
            // wired into the candidate node.
            let mut saw_link = false;
            let mut ok = true;
            for source in &wiring[next_node] {
                match source.expect("graph wiring validated") {
                    GraphSource::Input(_) => {}
                    GraphSource::Node(node, output) => {
                        if node as usize == last && output == 0 {
                            saw_link = true;
                        } else {
                            ok = false;
                        }
                    }
                }
            }
            if !ok || !saw_link {
                break;
            }
            chain.push(next_node);
        }
        if chain.len() >= 2 {
            for node in &chain {
                fused.insert(*node);
            }
            chains.push(chain);
        }
    }
    chains
}

fn execute_graph_metal(
    graph: &super::DmlGraphPlan,
    wiring: &[Vec<Option<GraphSource>>],
    output_sources: &[Option<GraphSource>],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
) -> DmlResult<()> {
    let device = MetalDevice::system_default().map_err(|error| {
        DmlError::unsupported_feature(format!("no Metal device available: {error}"))
    })?;
    let chains = find_fusion_chains(graph, wiring, output_sources);
    let mut chain_of = vec![None; graph.nodes.len()];
    let mut fused_sources = Vec::with_capacity(chains.len());
    for (chain_index, chain) in chains.iter().enumerate() {
        for node in chain {
            chain_of[*node] = Some(chain_index);
        }
        let (source, used_inputs) =
            emit_fused_chain_msl(&format!("dml_fused{chain_index}"), graph, wiring, chain)?;
        fused_sources.push((source, used_inputs));
    }
    let mut combined = String::new();
    for (source, _) in &fused_sources {
        combined.push_str(source);
    }
    for (index, node) in graph.nodes.iter().enumerate() {
        let source = emit_msl(node)?;
        combined.push_str(&source.replace(
            "kernel void dml_op(",
            &format!("kernel void dml_node{index}("),
        ));
    }
    let library = device.compile_shader_library(&combined).map_err(|error| {
        DmlError::new(E_FAIL, format!("graph Metal compilation failed: {error}"))
    })?;
    let (_, _, input_sizes) = graph_wiring(graph)?;
    let input_buffers: Vec<_> = inputs
        .iter()
        .zip(&input_sizes)
        .map(|(data, size)| {
            device.create_buffer_with_data(
                &data[..*size as usize],
                metal::MTLResourceOptions::StorageModeShared,
            )
        })
        .collect();
    let mut node_buffers: Vec<Vec<metal::Buffer>> = Vec::with_capacity(graph.nodes.len());
    for node in &graph.nodes {
        node_buffers.push(
            node.outputs()
                .map(|desc| {
                    device.create_buffer(
                        desc.total_size_in_bytes,
                        metal::MTLResourceOptions::StorageModeShared,
                    )
                })
                .collect(),
        );
    }
    let mut scratch_buffers: Vec<Option<metal::Buffer>> = Vec::with_capacity(graph.nodes.len());
    for node in &graph.nodes {
        let scratch = match &node.kind {
            DmlOpKind::Rnn { direction, .. }
            | DmlOpKind::Gru { direction, .. }
            | DmlOpKind::Lstm { direction, .. } => {
                let batch = node.inputs[0].sizes[1] as u64;
                let hidden = node.inputs[1].sizes[1] as u64;
                let directions = if *direction == DmlRecurrentDirection::Bidirectional {
                    2
                } else {
                    1
                };
                Some(device.create_buffer(
                    batch * hidden * 7 * 4 * directions,
                    metal::MTLResourceOptions::StorageModeShared,
                ))
            }
            _ => None,
        };
        scratch_buffers.push(scratch);
    }
    let queue = device.create_command_queue();
    let command_buffer = queue.new_command_buffer();
    {
        let encoder = command_buffer.new_compute_command_encoder();
        for node_index in &graph.execution_order {
            let index = *node_index as usize;
            if let Some(chain_index) = chain_of[index] {
                let chain = &chains[chain_index];
                if chain.last() == Some(&index) {
                    let (_, used_inputs) = &fused_sources[chain_index];
                    let function = library
                        .get_function(&format!("dml_fused{chain_index}"), None)
                        .map_err(|error| {
                            DmlError::new(
                                E_FAIL,
                                format!("dml_fused{chain_index} not found: {error}"),
                            )
                        })?;
                    let pipeline = device
                        .metal_device()
                        .new_compute_pipeline_state_with_function(&function)
                        .map_err(|error| {
                            DmlError::new(E_FAIL, format!("pipeline creation failed: {error}"))
                        })?;
                    encoder.set_compute_pipeline_state(&pipeline);
                    for (slot, graph_input) in used_inputs.iter().enumerate() {
                        encoder.set_buffer(slot as u64, Some(&input_buffers[*graph_input]), 0);
                    }
                    encoder.set_buffer(used_inputs.len() as u64, Some(&node_buffers[index][0]), 0);
                    let count = graph.nodes[index].output.element_count();
                    let max_threads = pipeline.max_total_threads_per_threadgroup();
                    let threadgroup = max_threads.clamp(1, 256);
                    encoder.dispatch_threads(
                        metal::MTLSize::new(count.max(1), 1, 1),
                        metal::MTLSize::new(threadgroup, 1, 1),
                    );
                }
                continue;
            }
            let node = &graph.nodes[index];
            let function = library
                .get_function(&format!("dml_node{index}"), None)
                .map_err(|error| {
                    DmlError::new(E_FAIL, format!("dml_node{index} not found: {error}"))
                })?;
            let pipeline = device
                .metal_device()
                .new_compute_pipeline_state_with_function(&function)
                .map_err(|error| {
                    DmlError::new(E_FAIL, format!("pipeline creation failed: {error}"))
                })?;
            encoder.set_compute_pipeline_state(&pipeline);
            for (input_index, source) in wiring[index].iter().enumerate() {
                let buffer = match source.expect("graph wiring validated") {
                    GraphSource::Input(graph_input) => &input_buffers[graph_input],
                    GraphSource::Node(node, output) => &node_buffers[node as usize][output],
                };
                encoder.set_buffer(input_index as u64, Some(buffer), 0);
            }
            let output_start = node.inputs.len() as u64;
            for (output_index, buffer) in node_buffers[index].iter().enumerate() {
                encoder.set_buffer(output_start + output_index as u64, Some(buffer), 0);
            }
            if let Some(scratch) = &scratch_buffers[index] {
                encoder.set_buffer(
                    output_start + node_buffers[index].len() as u64,
                    Some(scratch),
                    0,
                );
            }
            let count = node.dispatch_count();
            let max_threads = pipeline.max_total_threads_per_threadgroup();
            let threadgroup = max_threads.clamp(1, 256);
            encoder.dispatch_threads(
                metal::MTLSize::new(count.max(1), 1, 1),
                metal::MTLSize::new(threadgroup, 1, 1),
            );
        }
        encoder.end_encoding();
    }
    command_buffer.commit();
    command_buffer.wait_until_completed();
    if command_buffer.status() == metal::MTLCommandBufferStatus::Error {
        return Err(DmlError::new(
            E_FAIL,
            "Metal command buffer failed while executing the DirectML graph",
        ));
    }
    for (index, source) in output_sources.iter().enumerate() {
        let Some(GraphSource::Node(node, output)) = source else {
            return Err(DmlError::invalid("graph output source is missing"));
        };
        let buffer = &node_buffers[*node as usize][*output];
        let length = buffer.length() as usize;
        let contents =
            unsafe { std::slice::from_raw_parts(buffer.contents() as *const u8, length) };
        outputs[index][..length].copy_from_slice(contents);
    }
    Ok(())
}

fn validate_max_unpooling_indices(plan: &DmlOpPlan, inputs: &[&[u8]]) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
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
    }
    Ok(())
}

fn execute_metal(plan: &DmlOpPlan, inputs: &[&[u8]], outputs: &mut [&mut [u8]]) -> DmlResult<()> {
    if matches!(plan.kind, DmlOpKind::MaxUnpooling) {
        validate_max_unpooling_indices(plan, inputs)?;
    }
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
    let scratch_buffer = match &plan.kind {
        DmlOpKind::Rnn { direction, .. }
        | DmlOpKind::Gru { direction, .. }
        | DmlOpKind::Lstm { direction, .. } => {
            let batch = plan.inputs[0].sizes[1] as u64;
            let hidden = plan.inputs[1].sizes[1] as u64;
            let directions = if *direction == DmlRecurrentDirection::Bidirectional {
                2
            } else {
                1
            };
            Some(device.create_buffer(
                batch * hidden * 7 * 4 * directions,
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
        DML_TENSOR_DATA_TYPE_UINT4 => ((bytes[index / 2] >> ((index % 2) * 4)) & 0x0f) as f32,
        DML_TENSOR_DATA_TYPE_INT4 => {
            let raw = ((bytes[index / 2] >> ((index % 2) * 4)) & 0x0f) as i8;
            if raw & 0x08 != 0 {
                raw as f32 - 16.0
            } else {
                raw as f32
            }
        }
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
        DML_TENSOR_DATA_TYPE_UINT4 | DML_TENSOR_DATA_TYPE_INT4 => {
            let range = if data_type == DML_TENSOR_DATA_TYPE_INT4 {
                (-8.0, 7.0)
            } else {
                (0.0, 15.0)
            };
            let quantized = value.round_ties_even().clamp(range.0, range.1) as i32 & 0x0f;
            let shift = (index % 2) * 4;
            bytes[index / 2] = (bytes[index / 2] & !(0x0f << shift)) | ((quantized as u8) << shift);
        }
        _ => store_scalar(bytes, index as u64, data_type, value),
    }
}

fn store_cast(bytes: &mut [u8], index: u64, data_type: u32, value: f32) {
    match data_type {
        DML_TENSOR_DATA_TYPE_INT32 => {
            let index = index as usize;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&(value as i32).to_le_bytes());
        }
        DML_TENSOR_DATA_TYPE_UINT32 => {
            let index = index as usize;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
        DML_TENSOR_DATA_TYPE_INT8 => {
            bytes[index as usize] = value as i8 as u8;
        }
        DML_TENSOR_DATA_TYPE_UINT8 => {
            bytes[index as usize] = value as u8;
        }
        _ => store_scalar(bytes, index, data_type, value),
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

fn row_major_index(coords: &[u64], sizes: &[u32]) -> u64 {
    let mut index = 0u64;
    let mut stride = 1u64;
    for (coord, size) in coords.iter().zip(sizes).rev() {
        index += coord * stride;
        stride *= *size as u64;
    }
    index
}

fn channel_offset(desc: &DmlTensorDesc, channel: u64) -> u64 {
    if desc.sizes.len() == 1 {
        return channel * desc.strides[0] as u64;
    }
    let mut coords = vec![0u64; desc.sizes.len()];
    if desc.sizes.len() > 1 {
        coords[1] = channel.min(desc.sizes[1] as u64 - 1);
    }
    index_of(&coords, &desc.strides)
}

fn quantization_element_index(
    desc: &DmlTensorDesc,
    output: &DmlTensorDesc,
    output_coords: &[u64],
) -> u64 {
    if desc.element_count() == 1 {
        return 0;
    }
    if desc.sizes.len() == output.sizes.len() {
        let mapped = desc
            .sizes
            .iter()
            .enumerate()
            .map(|(dimension, size)| {
                if *size == 1 {
                    0
                } else {
                    output_coords[dimension]
                }
            })
            .collect::<Vec<_>>();
        return index_of(&mapped, &desc.strides);
    }
    if desc.sizes.len() == 1 {
        let size = desc.sizes[0];
        let axis = if output.sizes.len() >= 2 && output.sizes[1] == size {
            1
        } else if *output.sizes.last().expect("non-empty output") == size {
            output.sizes.len() - 1
        } else {
            output
                .sizes
                .iter()
                .position(|candidate| *candidate == size)
                .unwrap_or(0)
        };
        return output_coords[axis] * desc.strides[0] as u64;
    }
    0
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
                    acc += load_scalar(inputs[0], index_of(&a_coords, &a.strides), a.data_type)
                        as f64
                        * load_scalar(inputs[1], index_of(&b_coords, &b.strides), b.data_type)
                            as f64;
                }
                let mut value = *alpha as f64 * acc;
                if plan.inputs.len() == 3 {
                    value += *beta as f64
                        * load_scalar(
                            inputs[2],
                            index_of(&coords, &plan.inputs[2].strides),
                            plan.inputs[2].data_type,
                        ) as f64;
                }
                store_scalar(output, output_index(&plan.output, gid), dtype, value as f32);
            }
        }
        DmlOpKind::Convolution {
            mode,
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
                            let filter_coords = if *mode == DML_CONVOLUTION_MODE_CONVOLUTION {
                                [
                                    out_channel,
                                    cg,
                                    filter.sizes[2] as u64 - 1 - fy,
                                    filter.sizes[3] as u64 - 1 - fx,
                                ]
                            } else {
                                [out_channel, cg, fy, fx]
                            };
                            acc += load_scalar(
                                inputs[0],
                                index_of(&input_coords, &input.strides),
                                input.data_type,
                            ) as f64
                                * load_scalar(
                                    inputs[1],
                                    index_of(&filter_coords, &filter.strides),
                                    filter.data_type,
                                ) as f64;
                        }
                    }
                }
                if plan.inputs.len() == 3 {
                    acc += load_scalar(inputs[2], out_channel, plan.inputs[2].data_type) as f64;
                }
                store_scalar(output, output_index(&plan.output, gid), dtype, acc as f32);
            }
        }
        DmlOpKind::AveragePooling1 {
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            include_padding,
        } => execute_average_pooling1_cpu(
            plan,
            inputs[0],
            output,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            *include_padding,
        )?,
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
                let left = load_scalar(inputs[0], index_of(&a_coords, &a.strides), a.data_type);
                let right = load_scalar(inputs[1], index_of(&b_coords, &b.strides), b.data_type);
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    apply_binary(*op, left, right),
                );
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
            antialiased,
        } => execute_resample_cpu(
            plan,
            inputs[0],
            output,
            *mode,
            scales,
            input_offsets,
            output_offsets,
            *rounding,
            *antialiased,
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
            use_mean,
            epsilon,
        } => execute_mvn_cpu(
            plan,
            inputs,
            output,
            axes,
            *normalize_variance,
            *use_mean,
            *epsilon,
        )?,
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
        DmlOpKind::Unary { op } => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let mut input_coords = coords.clone();
                for (dimension, coord) in coords.iter().enumerate() {
                    if input.sizes[dimension] == 1 {
                        input_coords[dimension] = 0;
                    }
                    let _ = coord;
                }
                let value = load_scalar(inputs[0], index_of(&input_coords, &input.strides), dtype);
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    unary_cpu(*op, value),
                );
            }
        }
        DmlOpKind::Fill {
            value,
            step,
            sequence,
        } => {
            for gid in 0..count {
                let element = if *sequence {
                    *value + *step * gid as f32
                } else {
                    *value
                };
                store_scalar(output, output_index(&plan.output, gid), dtype, element);
            }
        }
        DmlOpKind::OneHot { axis } => {
            let indices = &plan.inputs[0];
            let on_value = load_scalar(inputs[1], 0, plan.inputs[1].data_type);
            let off_value = load_scalar(inputs[1], 1, plan.inputs[1].data_type);
            let depth = plan.output.sizes[*axis as usize] as i64;
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let mut index_coords = Vec::with_capacity(coords.len() - 1);
                for (dimension, coord) in coords.iter().enumerate() {
                    if dimension != *axis as usize {
                        index_coords.push(*coord);
                    }
                }
                let index = load_scalar(
                    inputs[0],
                    index_of(&index_coords, &indices.strides),
                    indices.data_type,
                ) as i64;
                let on = index >= 0 && index < depth && index == coords[*axis as usize] as i64;
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    if on { on_value } else { off_value },
                );
            }
        }
        DmlOpKind::Cumulative {
            product,
            axis,
            reverse,
            exclusive,
        } => {
            let input = &plan.inputs[0];
            let axis = *axis as usize;
            for gid in 0..count {
                let mut coords = coords_of(gid, &plan.output.sizes);
                let position = coords[axis];
                let size = input.sizes[axis];
                let (start, end) = if *reverse {
                    (position, size as u64)
                } else {
                    (0, position + 1)
                };
                let mut acc = if *product { 1.0f32 } else { 0.0f32 };
                for j in start..end {
                    if *exclusive && j == position {
                        continue;
                    }
                    coords[axis] = j;
                    let value = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
                    if *product {
                        acc *= value;
                    } else {
                        acc += value;
                    }
                }
                store_scalar(output, output_index(&plan.output, gid), dtype, acc);
            }
        }
        DmlOpKind::Reverse { axis } => {
            let input = &plan.inputs[0];
            let lengths = &plan.inputs[1];
            let axis = *axis as usize;
            for gid in 0..count {
                let mut coords = coords_of(gid, &plan.output.sizes);
                let sequence_coords = &coords[..axis];
                let length = load_scalar(
                    inputs[1],
                    index_of(sequence_coords, &lengths.strides),
                    lengths.data_type,
                ) as u64;
                if coords[axis] < length {
                    coords[axis] = length - 1 - coords[axis];
                }
                let value = load_scalar(inputs[0], index_of(&coords, &input.strides), dtype);
                store_scalar(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::DiagonalMatrix { offset, value } => {
            for gid in 0..count {
                let coords = coords_of(gid, &plan.output.sizes);
                let selected = coords[1] as i64 - coords[0] as i64 == *offset as i64;
                store_scalar(
                    output,
                    output_index(&plan.output, gid),
                    dtype,
                    if selected { *value } else { 0.0 },
                );
            }
        }
        DmlOpKind::Cast => {
            let input = &plan.inputs[0];
            for gid in 0..count {
                let coords = coords_of(gid, &input.sizes);
                let value = load_scalar(
                    inputs[0],
                    index_of(&coords, &input.strides),
                    input.data_type,
                );
                store_cast(output, output_index(&plan.output, gid), dtype, value);
            }
        }
        DmlOpKind::SoftmaxEx { kind, axes } => {
            execute_softmax_ex_cpu(plan, inputs[0], output, *kind, axes)?
        }
        DmlOpKind::ExActivation { activation } => {
            execute_ex_activation_cpu(plan, inputs, output, *activation)?
        }
        DmlOpKind::If => execute_if_cpu(plan, inputs, output)?,
        DmlOpKind::BitNot => execute_bitwise_cpu(plan, inputs[0], output, false)?,
        DmlOpKind::BitCount => execute_bitwise_cpu(plan, inputs[0], output, true)?,
        DmlOpKind::LpPooling {
            p,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            ..
        } => execute_lp_pooling_cpu(
            plan,
            inputs[0],
            output,
            *p,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
        )?,
        DmlOpKind::LpNormalization { axis, epsilon, p } => {
            execute_lp_normalization_cpu(plan, inputs[0], output, *axis, *epsilon, *p)?
        }
        DmlOpKind::ValueScale2D {
            scale,
            channel_count,
            bias,
        } => execute_value_scale_cpu(plan, inputs[0], output, *scale, *channel_count, bias)?,
        DmlOpKind::SpaceDepth {
            to_depth,
            block_size,
            order,
            ..
        } => execute_space_depth_cpu(plan, inputs[0], output, *to_depth, *block_size, *order)?,
        DmlOpKind::MaxPoolingEx {
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            has_indices,
            ..
        } => execute_max_pooling_ex_cpu(
            plan,
            inputs[0],
            output,
            extras.first_mut().map(|value| &mut **value),
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
            *has_indices,
        )?,
        DmlOpKind::MaxUnpooling => execute_max_unpooling_cpu(plan, inputs, output)?,
        DmlOpKind::SliceEx {
            offsets,
            sizes,
            strides,
        } => execute_slice_ex_cpu(plan, inputs[0], output, offsets, sizes, strides)?,
        DmlOpKind::Clip1 {
            min,
            max,
            scale,
            bias,
            has_scale_bias,
        } => execute_clip1_cpu(
            plan,
            inputs[0],
            output,
            *min,
            *max,
            *scale,
            *bias,
            *has_scale_bias,
        )?,
        DmlOpKind::ReluGrad => execute_relu_grad_cpu(plan, inputs, output)?,
        DmlOpKind::AveragePoolingGrad {
            strides,
            window,
            start_padding,
            end_padding,
            include_padding,
        } => execute_avg_pool_grad_cpu(
            plan,
            inputs[0],
            output,
            strides,
            window,
            start_padding,
            end_padding,
            *include_padding,
        )?,
        DmlOpKind::MaxPoolingGrad {
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
        } => execute_max_pool_grad_cpu(
            plan,
            inputs,
            output,
            strides,
            window,
            start_padding,
            end_padding,
            dilations,
        )?,
        DmlOpKind::ResampleGrad {
            mode,
            rounding,
            scales,
            input_offsets,
            output_offsets,
            ..
        } => execute_resample_grad_cpu(
            plan,
            inputs[0],
            output,
            *mode,
            *rounding,
            scales,
            input_offsets,
            output_offsets,
        )?,
        DmlOpKind::SliceGrad {
            offsets,
            sizes,
            strides,
        } => execute_slice_grad_cpu(plan, inputs[0], output, offsets, sizes, strides)?,
        DmlOpKind::ClipGrad { min, max, .. } => {
            execute_clip_grad_cpu(plan, inputs, output, *min, *max)?
        }
        DmlOpKind::LrnGrad {
            cross_channel,
            local_size,
            alpha,
            beta,
            bias,
        } => execute_lrn_grad_cpu(
            plan,
            inputs,
            output,
            *cross_channel,
            *local_size,
            *alpha,
            *beta,
            *bias,
        )?,
        DmlOpKind::BatchNormalizationGrad { epsilon } => {
            execute_batch_normalization_grad_cpu(plan, inputs, output, extras, *epsilon, false)?
        }
        DmlOpKind::BatchNormalizationTraining { epsilon } => {
            execute_batch_normalization_training_cpu(plan, inputs, output, extras, *epsilon)?
        }
        DmlOpKind::BatchNormalizationTrainingGrad { epsilon } => {
            execute_batch_normalization_grad_cpu(plan, inputs, output, extras, *epsilon, true)?
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
        } => execute_roi_align_grad_cpu(
            plan,
            inputs,
            output,
            *reduction,
            *mode,
            *spatial_scale_x,
            *spatial_scale_y,
            *input_pixel_offset,
            *output_pixel_offset,
            *minimum_samples_per_output,
            *maximum_samples_per_output,
            *align_regions_to_corners,
        )?,
        DmlOpKind::RandomGenerator { .. } => {
            execute_random_generator_cpu(plan, inputs[0], output, extras)?
        }
        DmlOpKind::NonZeroCoordinates => {
            execute_nonzero_cpu(plan, inputs[0], output, &mut *extras[0])?
        }
        DmlOpKind::DiagonalMatrix1 {
            offset_begin,
            offset_end,
            value,
        } => execute_diagonal1_cpu(
            plan,
            inputs.first().copied(),
            output,
            *offset_begin,
            *offset_end,
            *value,
        )?,
        DmlOpKind::MultiHeadAttention {
            scale,
            mask_filter_value,
            query_head_count,
            key_value_head_count,
            mask_type,
            has_bias,
            has_mask,
            ..
        } => execute_mha_cpu(
            plan,
            inputs,
            output,
            *scale,
            *mask_filter_value,
            *query_head_count,
            *key_value_head_count,
            *mask_type,
            *has_bias,
            *has_mask,
        )?,
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

fn broadcast_coords(desc: &DmlTensorDesc, output_coords: &[u64]) -> Vec<u64> {
    desc.sizes
        .iter()
        .enumerate()
        .map(|(dimension, size)| {
            if *size == 1 {
                0
            } else {
                output_coords[dimension]
            }
        })
        .collect()
}

fn decode_reduced_coords(t: u64, axes: &[u32], sizes: &[u32], base: &[u64]) -> Vec<u64> {
    let mut coords = base.to_vec();
    let mut rem = t;
    for axis in axes {
        let index = *axis as usize;
        coords[index] = rem % sizes[index] as u64;
        rem /= sizes[index] as u64;
    }
    coords
}

fn execute_softmax_ex_cpu(
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

fn execute_ex_activation_cpu(
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

fn execute_if_cpu(plan: &DmlOpPlan, inputs: &[&[u8]], output: &mut [u8]) -> DmlResult<()> {
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

fn execute_bitwise_cpu(
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

#[allow(clippy::too_many_arguments)]
fn execute_average_pooling1_cpu(
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
fn execute_lp_pooling_cpu(
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

fn execute_lp_normalization_cpu(
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

fn execute_value_scale_cpu(
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

fn execute_space_depth_cpu(
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

#[allow(clippy::too_many_arguments)]
fn execute_max_pooling_ex_cpu(
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

fn execute_max_unpooling_cpu(
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

fn execute_slice_ex_cpu(
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

fn execute_clip1_cpu(
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

fn execute_relu_grad_cpu(plan: &DmlOpPlan, inputs: &[&[u8]], output: &mut [u8]) -> DmlResult<()> {
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
fn execute_avg_pool_grad_cpu(
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
fn execute_max_pool_grad_cpu(
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
fn execute_resample_grad_cpu(
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

fn execute_slice_grad_cpu(
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

fn execute_clip_grad_cpu(
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

#[allow(clippy::too_many_arguments)]
fn execute_lrn_grad_cpu(
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

fn execute_batch_normalization_training_cpu(
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

fn execute_batch_normalization_grad_cpu(
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

#[allow(clippy::too_many_arguments)]
fn execute_roi_align_grad_cpu(
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
fn roi_sample(
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

fn roi_grad_weight(
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

fn philox_4x32_10(
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

fn execute_random_generator_cpu(
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

fn execute_nonzero_cpu(
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

fn execute_diagonal1_cpu(
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
fn execute_mha_cpu(
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

fn output_index_of(desc: &DmlTensorDesc, gid: u64) -> u64 {
    let coords = coords_of(gid, &desc.sizes);
    index_of(&coords, &desc.strides)
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
        store_scalar(
            output,
            output_index(&plan.output, gid),
            dtype,
            apply_binary(op, left, right),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn execute_recurrent_cpu_legacy(
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
    let directions = match direction {
        DmlRecurrentDirection::Forward | DmlRecurrentDirection::Backward => 1u32,
        DmlRecurrentDirection::Bidirectional => 2u32,
    };
    let gates = match ty {
        DML_OPERATOR_RNN => 1u32,
        DML_OPERATOR_GRU => 3u32,
        _ => 4u32,
    };
    let input = &plan.inputs[0];
    let weight = &plan.inputs[1];
    let recurrence = &plan.inputs[2];
    let [sequence, batch, input_size] = [input.sizes[0], input.sizes[1], input.sizes[2]];
    let hidden = weight.sizes[1] as usize;
    let batch_usize = batch as usize;
    let input_size_usize = input_size as usize;
    let gate_span = gates * hidden as u32;
    let bias_index = if options.bias { Some(3) } else { None };
    let hidden_init_index = 3 + usize::from(options.bias);
    let cell_init_index = hidden_init_index + usize::from(options.hidden_init);
    let sequence_lengths_index = cell_init_index + usize::from(options.cell_init);
    let peephole_index = sequence_lengths_index + usize::from(options.sequence_lengths);
    let sequence_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::Sequence);
    let single_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::Single);
    let cell_role = roles
        .iter()
        .position(|role| *role == DmlRecurrentOutput::CellSingle);
    for dir in 0..directions {
        let reverse = match direction {
            DmlRecurrentDirection::Forward => false,
            DmlRecurrentDirection::Backward => true,
            DmlRecurrentDirection::Bidirectional => dir == 1,
        };
        let gate_offset = dir * gate_span;
        let gate_origin = (dir * gates) as u64;
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
                load_integer(
                    inputs[sequence_lengths_index],
                    index_of(&[b as u64], &desc.strides),
                    desc.data_type,
                )
                .clamp(0, sequence as i64) as u32
            } else {
                sequence
            };
            for step in 0..sequence {
                let t = if reverse { sequence - 1 - step } else { step };
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
                                        index_of(
                                            &[gate_origin, j as u64, i as u64],
                                            &weight.strides,
                                        ),
                                        weight.data_type,
                                    );
                                    sum += x as f64 * w as f64;
                                }
                                for i in 0..hidden {
                                    let hsv = hidden_state[b][i];
                                    let r = load_scalar(
                                        inputs[2],
                                        index_of(
                                            &[gate_origin, j as u64, i as u64],
                                            &recurrence.strides,
                                        ),
                                        recurrence.data_type,
                                    );
                                    sum += hsv as f64 * r as f64;
                                }
                                if let Some(index) = bias_index {
                                    sum += load_scalar(
                                        inputs[index],
                                        (gate_offset + j as u32) as u64,
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
                                        index_of(
                                            &[gate_origin, j as u64, i as u64],
                                            &weight.strides,
                                        ),
                                        weight.data_type,
                                    ) as f64;
                                    r_sum += x * load_scalar(
                                        inputs[1],
                                        index_of(
                                            &[gate_origin + 1, j as u64, i as u64],
                                            &weight.strides,
                                        ),
                                        weight.data_type,
                                    ) as f64;
                                }
                                for i in 0..hidden {
                                    let hsv = hidden_now[i] as f64;
                                    z_sum += hsv
                                        * load_scalar(
                                            inputs[2],
                                            index_of(
                                                &[gate_origin, j as u64, i as u64],
                                                &recurrence.strides,
                                            ),
                                            recurrence.data_type,
                                        ) as f64;
                                    r_sum += hsv
                                        * load_scalar(
                                            inputs[2],
                                            index_of(
                                                &[gate_origin + 1, j as u64, i as u64],
                                                &recurrence.strides,
                                            ),
                                            recurrence.data_type,
                                        ) as f64;
                                }
                                if let Some(index) = bias_index {
                                    z_sum += load_scalar(
                                        inputs[index],
                                        (gate_offset + j as u32) as u64,
                                        plan.inputs[index].data_type,
                                    ) as f64;
                                    r_sum += load_scalar(
                                        inputs[index],
                                        (gate_offset + hidden as u32 + j as u32) as u64,
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
                                            index_of(
                                                &[gate_origin + 2, j as u64, i as u64],
                                                &weight.strides,
                                            ),
                                            weight.data_type,
                                        ) as f64;
                                }
                                let mut recurrent_term = 0.0f64;
                                for i in 0..hidden {
                                    recurrent_term += hidden_now[i] as f64
                                        * load_scalar(
                                            inputs[2],
                                            index_of(
                                                &[gate_origin + 2, j as u64, i as u64],
                                                &recurrence.strides,
                                            ),
                                            recurrence.data_type,
                                        ) as f64;
                                }
                                if let Some(index) = bias_index {
                                    input_term += load_scalar(
                                        inputs[index],
                                        (gate_offset + 2 * hidden as u32 + j as u32) as u64,
                                        plan.inputs[index].data_type,
                                    ) as f64;
                                }
                                let combined = input_term + r[j] as f64 * recurrent_term;
                                let candidate =
                                    activation_cpu(candidate_activation, combined as f32);
                                next[j] = (1.0 - z[j]) * hidden_now[j] + z[j] * candidate;
                            }
                        }
                        _ => {
                            let gate = recurrent_activation(activations, 0, DmlActivation::Sigmoid);
                            let cell_gate =
                                recurrent_activation(activations, 1, DmlActivation::Tanh);
                            let output_activation =
                                recurrent_activation(activations, 2, DmlActivation::Tanh);
                            let hidden_now = hidden_state[b].clone();
                            for j in 0..hidden {
                                let mut sums = [0.0f64; 4];
                                for (gate_index, sum) in sums.iter_mut().enumerate() {
                                    let gate_coord = gate_origin + gate_index as u64;
                                    for i in 0..input_size_usize {
                                        *sum += load_scalar(
                                            inputs[0],
                                            index_of(
                                                &[t as u64, b as u64, i as u64],
                                                &input.strides,
                                            ),
                                            input.data_type,
                                        ) as f64
                                            * load_scalar(
                                                inputs[1],
                                                index_of(
                                                    &[gate_coord, j as u64, i as u64],
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
                                                    &[gate_coord, j as u64, i as u64],
                                                    &recurrence.strides,
                                                ),
                                                recurrence.data_type,
                                            ) as f64;
                                    }
                                    if let Some(index) = bias_index {
                                        let row = gate_offset
                                            + gate_index as u32 * hidden as u32
                                            + j as u32;
                                        *sum += load_scalar(
                                            inputs[index],
                                            row as u64,
                                            plan.inputs[index].data_type,
                                        ) as f64;
                                    }
                                }
                                let mut i_gate = activation_cpu(gate, sums[0] as f32);
                                let mut f_gate = activation_cpu(gate, sums[2] as f32);
                                let c_gate = activation_cpu(cell_gate, sums[3] as f32);
                                if options.peephole {
                                    let desc = &plan.inputs[peephole_index];
                                    let base = dir as u64 * 3 * hidden as u64;
                                    i_gate += load_scalar(
                                        inputs[peephole_index],
                                        base + j as u64,
                                        desc.data_type,
                                    ) * cell_state[b][j];
                                    f_gate += load_scalar(
                                        inputs[peephole_index],
                                        base + hidden as u64 + j as u64,
                                        desc.data_type,
                                    ) * cell_state[b][j];
                                    i_gate = activation_cpu(gate, i_gate);
                                    f_gate = activation_cpu(gate, f_gate);
                                }
                                if extras.couple_input_forget {
                                    f_gate = 1.0 - i_gate;
                                }
                                let mut cell = f_gate * cell_state[b][j] + i_gate * c_gate;
                                if extras.use_clip_threshold {
                                    cell =
                                        cell.clamp(-extras.clip_threshold, extras.clip_threshold);
                                }
                                cell_state[b][j] = cell;
                                let mut o_gate = activation_cpu(gate, sums[1] as f32);
                                if options.peephole {
                                    let desc = &plan.inputs[peephole_index];
                                    let base = dir as u64 * 3 * hidden as u64;
                                    o_gate += load_scalar(
                                        inputs[peephole_index],
                                        base + 2 * hidden as u64 + j as u64,
                                        desc.data_type,
                                    ) * cell;
                                    o_gate = activation_cpu(gate, o_gate);
                                }
                                next[j] = o_gate * activation_cpu(output_activation, cell);
                            }
                        }
                    }
                    hidden_state[b] = next;
                }
                if let Some(role) = sequence_role {
                    let desc = &plan.outputs().nth(role).expect("role output").clone();
                    for j in 0..hidden {
                        let index = index_of(
                            &[t as u64, b as u64, (dir as usize * hidden + j) as u64],
                            &desc.strides,
                        );
                        store_scalar(
                            &mut outputs[role][..],
                            index,
                            desc.data_type,
                            hidden_state[b][j],
                        );
                    }
                }
            }
            let column_offset = dir as usize * hidden;
            if let Some(role) = single_role {
                let desc = plan.outputs().nth(role).expect("role output").clone();
                for j in 0..hidden {
                    let index = index_of(&[0, b as u64, (column_offset + j) as u64], &desc.strides);
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
                    let index = index_of(&[0, b as u64, (column_offset + j) as u64], &desc.strides);
                    store_scalar(
                        &mut outputs[role][..],
                        index,
                        desc.data_type,
                        cell_state[b][j],
                    );
                }
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
    batch_dimension_count: u32,
) -> DmlResult<()> {
    let input = &plan.inputs[0];
    let indices = &plan.inputs[1];
    let indices_rank = indices.sizes.len();
    let batch = batch_dimension_count as usize;
    let indexed = indices.sizes[indices_rank - 1] as usize;
    let count = plan.output.element_count();
    for gid in 0..count {
        let output_coords = coords_of(gid, &plan.output.sizes);
        let mut input_coords = Vec::with_capacity(input.sizes.len());
        let mut valid = true;
        for dimension in 0..batch {
            input_coords.push(output_coords[dimension]);
        }
        for dimension in 0..indexed {
            let mut index_coords = Vec::with_capacity(indices_rank);
            index_coords.extend_from_slice(&output_coords[..indices_rank - 1]);
            index_coords.push(dimension as u64);
            let index = load_integer(
                inputs[1],
                index_of(&index_coords, &indices.strides),
                indices.data_type,
            );
            if index < 0 || index as u64 >= input.sizes[batch + dimension] as u64 {
                valid = false;
                input_coords.push(0);
            } else {
                input_coords.push(index as u64);
            }
        }
        for dimension in batch + indexed..input.sizes.len() {
            input_coords.push(output_coords[indices_rank - 1 + dimension - batch - indexed]);
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

fn execute_generic_quantize_cpu(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::d3d12::directml::DML_TENSOR_DATA_TYPE_UINT8;

    fn tensor(data_type: u32, sizes: &[u32], strides: Option<&[u32]>) -> DmlTensorDesc {
        let element_size = match data_type {
            DML_TENSOR_DATA_TYPE_FLOAT16 => 2,
            DML_TENSOR_DATA_TYPE_UINT8
            | DML_TENSOR_DATA_TYPE_INT8
            | DML_TENSOR_DATA_TYPE_UINT4
            | DML_TENSOR_DATA_TYPE_INT4 => 1,
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
        let total_size_in_bytes =
            if data_type == DML_TENSOR_DATA_TYPE_UINT4 || data_type == DML_TENSOR_DATA_TYPE_INT4 {
                implied.div_ceil(2)
            } else {
                implied.saturating_mul(element_size)
            };
        DmlTensorDesc {
            data_type,
            flags: 0,
            sizes: sizes.to_vec(),
            strides,
            total_size_in_bytes,
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
                mode: DML_CONVOLUTION_MODE_CROSS_CORRELATION,
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
                mode: DML_CONVOLUTION_MODE_CROSS_CORRELATION,
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
                mode: DML_CONVOLUTION_MODE_CROSS_CORRELATION,
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
        let mismatched_batch = plan(
            DmlOpKind::GatherNd {
                input_dimension_count: 2,
                indices_dimension_count: 0,
                batch_dimension_count: 1,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[3, 1, 2], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 1, 2], None),
        );
        assert_eq!(
            mismatched_batch.validate().unwrap_err().message,
            "gather-nd batch dimensions [3] must match the input batch dimensions [2]"
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
                use_mean: true,
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
                use_mean: true,
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
            vec![input, tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3], None)],
            tensor(DML_TENSOR_DATA_TYPE_UINT8, &[4], None),
        );
        assert_eq!(
            per_channel.validate().unwrap_err().message,
            "DML_OPERATOR_TYPE 33 scale tensor is not broadcastable: quantization tensor dimension 0 size 3 does not match the output size 4"
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
            "quantized operator scale input 1 (A scale) is not broadcastable: quantization tensor axis size 4 does not match any output dimension"
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
            direction: DmlRecurrentDirection::Bidirectional,
            activations: Vec::new(),
            options: DmlRecurrentOptions::default(),
            outputs: vec![DmlRecurrentOutput::Single],
        };
        assert_eq!(
            invalid.validate().unwrap_err().message,
            "DML_OPERATOR_TYPE 76 weight gate count must be 2, got 1"
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
                use_mean: true,
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

    #[test]
    fn recurrent_backward_bidirectional_peephole_f16_and_noncontiguous_edge() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 1, 1], None);
        let weight = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1], None);
        let recurrence = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1], None);
        let sequence_output = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 1, 1], None);
        let backward = DmlOpPlan {
            kind: DmlOpKind::Rnn {
                direction: DmlRecurrentDirection::Backward,
                activations: vec![DmlActivation::Identity],
                options: DmlRecurrentOptions::default(),
                outputs: vec![DmlRecurrentOutput::Sequence],
            },
            inputs: vec![input.clone(), weight.clone(), recurrence.clone()],
            output: sequence_output.clone(),
            extra_outputs: Vec::new(),
            fused_activation: None,
        };
        let values = f32_bytes(&[1.0, 2.0, 3.0]);
        let one = f32_bytes(&[1.0]);
        assert_eq!(
            run_cpu(&backward, &[&values, &one, &one]),
            vec![6.0, 5.0, 3.0]
        );

        let bidirectional = DmlOpPlan {
            kind: DmlOpKind::Rnn {
                direction: DmlRecurrentDirection::Bidirectional,
                activations: vec![DmlActivation::Identity],
                options: DmlRecurrentOptions::default(),
                outputs: vec![DmlRecurrentOutput::Sequence],
            },
            inputs: vec![
                input,
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 1, 1], None),
            ],
            output: tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 1, 2], None),
            extra_outputs: Vec::new(),
            fused_activation: None,
        };
        let both = f32_bytes(&[1.0, 1.0]);
        assert_eq!(
            run_cpu(&bidirectional, &[&values, &both, &both]),
            vec![1.0, 6.0, 3.0, 5.0, 6.0, 3.0]
        );

        let f16_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT16, &[3, 1, 1], None);
        let f16_weight = tensor(DML_TENSOR_DATA_TYPE_FLOAT16, &[1, 1, 1], None);
        let f16_recurrence = tensor(DML_TENSOR_DATA_TYPE_FLOAT16, &[1, 1, 1], None);
        let f16_output = tensor(DML_TENSOR_DATA_TYPE_FLOAT16, &[3, 1, 1], None);
        let f16_plan = DmlOpPlan {
            kind: DmlOpKind::Rnn {
                direction: DmlRecurrentDirection::Backward,
                activations: vec![DmlActivation::Identity],
                options: DmlRecurrentOptions::default(),
                outputs: vec![DmlRecurrentOutput::Sequence],
            },
            inputs: vec![f16_input, f16_weight, f16_recurrence],
            output: f16_output,
            extra_outputs: Vec::new(),
            fused_activation: None,
        };
        let mut f16_result = vec![0u8; 6];
        execute_plan(
            &f16_plan,
            DmlExecutionDevice::Cpu,
            &[
                &f16_bytes(&[1.0, 2.0, 3.0]),
                &f16_bytes(&[1.0]),
                &f16_bytes(&[1.0]),
            ],
            &mut f16_result,
        )
        .expect("f16 recurrent execution");
        assert_eq!(read_f16(&f16_result), vec![6.0, 5.0, 3.0]);

        let strided_output = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 1, 2], Some(&[3, 1, 2]));
        let strided = DmlOpPlan {
            kind: DmlOpKind::Rnn {
                direction: DmlRecurrentDirection::Forward,
                activations: vec![DmlActivation::Identity],
                options: DmlRecurrentOptions::default(),
                outputs: vec![DmlRecurrentOutput::Sequence],
            },
            inputs: vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 2], None),
            ],
            output: strided_output,
            extra_outputs: Vec::new(),
            fused_activation: None,
        };
        let weights = f32_bytes(&[1.0, 0.0]);
        let recurrent = f32_bytes(&[0.0, 0.0, 0.0, 0.0]);
        let mut strided_result = vec![0u8; 24];
        execute_plan(
            &strided,
            DmlExecutionDevice::Cpu,
            &[&f32_bytes(&[1.0, 2.0]), &weights, &recurrent],
            &mut strided_result,
        )
        .expect("strided recurrent execution");
        let strided_values = read_f32(&strided_result);
        assert_eq!((strided_values[0], strided_values[2]), (1.0, 0.0));
        assert_eq!((strided_values[3], strided_values[5]), (2.0, 0.0));

        let peephole_lstm = DmlOpPlan {
            kind: DmlOpKind::Lstm {
                direction: DmlRecurrentDirection::Forward,
                activations: Vec::new(),
                options: DmlRecurrentOptions {
                    peephole: true,
                    ..DmlRecurrentOptions::default()
                },
                outputs: vec![DmlRecurrentOutput::Single],
                clip_threshold: 0.0,
                use_clip_threshold: false,
                couple_input_forget: false,
            },
            inputs: vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
            ],
            output: tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1], None),
            extra_outputs: Vec::new(),
            fused_activation: None,
        };
        assert_eq!(
            peephole_lstm.validate().unwrap_err().message,
            "DML_OPERATOR_TYPE 77 peephole tensor must contain 3 contiguous elements (directions x 3 gates x hidden)"
        );
    }

    #[test]
    fn quantized_per_channel_4bit_and_malformed_layout_edge_cases() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4], None);
        let per_channel = plan(
            DmlOpKind::QuantizeLinear,
            vec![
                input.clone(),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[4], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_UINT8, &[4], None),
        );
        let values = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        let scale = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        assert_eq!(
            run_cpu_outputs(&per_channel, &[&values, &scale])[0],
            vec![1u8, 1, 1, 1]
        );

        let packed = plan(
            DmlOpKind::QuantizeLinear,
            vec![
                input.clone(),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_UINT4, &[4], None),
        );
        assert_eq!(
            run_cpu_outputs(
                &packed,
                &[&f32_bytes(&[0.0, 1.0, 15.0, 16.0]), &f32_bytes(&[1.0])]
            )[0],
            vec![0x10u8, 0xff]
        );

        let signed = plan(
            DmlOpKind::DequantizeLinear,
            vec![
                tensor(DML_TENSOR_DATA_TYPE_INT4, &[2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
        );
        assert_eq!(
            run_cpu(&signed, &[&[0x8fu8], &f32_bytes(&[1.0])]),
            vec![-1.0, -8.0]
        );

        let mut malformed = tensor(DML_TENSOR_DATA_TYPE_UINT4, &[4], None);
        malformed.total_size_in_bytes = 1;
        let malformed_plan = plan(
            DmlOpKind::QuantizeLinear,
            vec![input, tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1], None)],
            malformed,
        );
        assert_eq!(
            malformed_plan.validate().unwrap_err().message,
            "tensor TotalTensorSizeInBytes 1 is smaller than the implied 2 bytes"
        );

        let quantized_matmul = plan(
            DmlOpKind::MatrixMultiplyInteger {
                quantized_output: true,
                a_zero_point: false,
                b_zero_point: false,
                output_scale: true,
                output_zero_point: false,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_INT8, &[1, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1], None),
                tensor(DML_TENSOR_DATA_TYPE_INT8, &[2, 2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 2], None),
        );
        let a_values = [1i8, 1]
            .iter()
            .map(|value| *value as u8)
            .collect::<Vec<_>>();
        let b_values = [1i8, 2, 3, 4]
            .iter()
            .map(|value| *value as u8)
            .collect::<Vec<_>>();
        assert_eq!(
            run_cpu_outputs(
                &quantized_matmul,
                &[
                    &a_values,
                    &f32_bytes(&[1.0]),
                    &b_values,
                    &f32_bytes(&[1.0, 2.0]),
                    &f32_bytes(&[1.0]),
                ]
            )[0],
            vec![4u8, 12]
        );

        let quantized_conv = plan(
            DmlOpKind::ConvolutionInteger {
                strides: vec![1, 1],
                dilations: vec![1, 1],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                group_count: 1,
                quantized_output: true,
                input_zero_point: false,
                filter_zero_point: false,
                bias: false,
                output_scale: true,
                output_zero_point: false,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 2, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
                tensor(DML_TENSOR_DATA_TYPE_UINT8, &[2, 2, 1, 1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 2, 1, 1], None),
        );
        assert_eq!(
            run_cpu_outputs(
                &quantized_conv,
                &[
                    &[1u8, 2],
                    &f32_bytes(&[1.0, 2.0]),
                    &[1u8, 0, 0, 1],
                    &f32_bytes(&[1.0]),
                    &f32_bytes(&[1.0]),
                ]
            )[0],
            vec![1u8, 4]
        );
    }

    #[test]
    fn batched_gathernd_antialias_convolution_mode_and_mvn_no_mean_edge() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None);
        let indices = tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2, 2, 1], None);
        let batched = plan(
            DmlOpKind::GatherNd {
                input_dimension_count: 2,
                indices_dimension_count: 3,
                batch_dimension_count: 1,
            },
            vec![input, indices],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None),
        );
        let input_values = f32_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let index_values = [0u32, 2, 1, 1]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        assert_eq!(
            run_cpu(&batched, &[&input_values, &index_values]),
            vec![1.0, 3.0, 5.0, 5.0]
        );

        let resample_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 4, 4], None);
        let antialiased = plan(
            DmlOpKind::Resample {
                mode: DmlInterpolationMode::Linear,
                scales: vec![1.0, 1.0, 0.5, 0.5],
                input_offsets: vec![0.0; 4],
                output_offsets: vec![0.0; 4],
                rounding: DmlAxisDirection::Increasing,
                antialiased: true,
            },
            vec![resample_input],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None),
        );
        let pixels = (1..=16).map(|value| value as f32).collect::<Vec<_>>();
        assert_eq!(
            run_cpu(&antialiased, &[&f32_bytes(&pixels)])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![35000, 55000, 115000, 135000]
        );

        let conv_input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 3, 3], None);
        let filter = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None);
        let image = f32_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]);
        let kernel = f32_bytes(&[1.0, 2.0, 3.0, 4.0]);
        let mut outputs = Vec::new();
        for mode in [
            DML_CONVOLUTION_MODE_CONVOLUTION,
            DML_CONVOLUTION_MODE_CROSS_CORRELATION,
        ] {
            let convolution = plan(
                DmlOpKind::Convolution {
                    mode,
                    strides: vec![1, 1],
                    dilations: vec![1, 1],
                    start_padding: vec![0, 0],
                    end_padding: vec![0, 0],
                    output_padding: vec![0, 0],
                    group_count: 1,
                },
                vec![conv_input.clone(), filter.clone()],
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None),
            );
            outputs.push(run_cpu(&convolution, &[&image, &kernel])[0]);
        }
        assert_eq!(outputs, vec![23.0, 37.0]);

        let mvn = plan(
            DmlOpKind::MeanVarianceNormalization {
                axes: vec![2, 3],
                normalize_variance: true,
                use_mean: false,
                epsilon: 0.0,
            },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 2], None)],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2, 1, 2], None),
        );
        assert_eq!(
            run_cpu(&mvn, &[&f32_bytes(&[1.0, 3.0, 2.0, 6.0])])
                .iter()
                .copied()
                .map(rounded)
                .collect::<Vec<_>>(),
            vec![4472, 13416, 4472, 13416]
        );

        let invalid_mode = plan(
            DmlOpKind::Convolution {
                mode: 2,
                strides: vec![1, 1],
                dilations: vec![1, 1],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                output_padding: vec![0, 0],
                group_count: 1,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 3, 3], None),
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None),
        );
        assert_eq!(
            invalid_mode.validate().unwrap_err().message,
            "convolution mode 2 is not supported"
        );
        let invalid_antialiased = plan(
            DmlOpKind::Resample {
                mode: DmlInterpolationMode::NearestNeighbor,
                scales: vec![1.0, 1.0, 0.5, 0.5],
                input_offsets: vec![0.0; 4],
                output_offsets: vec![0.0; 4],
                rounding: DmlAxisDirection::Increasing,
                antialiased: true,
            },
            vec![tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 4, 4], None)],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 2, 2], None),
        );
        assert_eq!(
            invalid_antialiased.validate().unwrap_err().message,
            "antialiased resample requires linear interpolation"
        );
    }
    fn packed_int4(values: &[i8]) -> Vec<u8> {
        let mut bytes = vec![0u8; values.len().div_ceil(2)];
        for (index, value) in values.iter().enumerate() {
            let nibble = (*value as i32 & 0x0f) as u8;
            bytes[index / 2] |= nibble << ((index % 2) * 4);
        }
        bytes
    }

    #[test]
    fn dml_packed_int4_weight_layout_edge_values_are_exact() {
        let a = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None);
        let b = tensor(DML_TENSOR_DATA_TYPE_INT4, &[2, 2], None);
        let out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 2], None);
        let gemm = plan(
            DmlOpKind::Gemm {
                trans_a: false,
                trans_b: false,
                alpha: 1.0,
                beta: 0.0,
            },
            vec![a.clone(), b.clone()],
            out.clone(),
        );
        let a_values = f32_bytes(&[1.0, 2.0]);
        let b_values = packed_int4(&[1, -2, -3, 4]);
        let mut cpu = vec![0u8; out.total_size_in_bytes as usize];
        execute_plan(
            &gemm,
            DmlExecutionDevice::Cpu,
            &[&a_values, &b_values],
            &mut cpu,
        )
        .expect("cpu int4 gemm");
        assert_eq!(read_f32(&cpu), vec![-5.0, 6.0]);
        if metal_available() {
            let mut accelerated = vec![0u8; out.total_size_in_bytes as usize];
            execute_plan(
                &gemm,
                DmlExecutionDevice::Metal,
                &[&a_values, &b_values],
                &mut accelerated,
            )
            .expect("metal int4 gemm");
            assert_eq!(read_f32(&accelerated), vec![-5.0, 6.0]);
        }

        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 3], None);
        let filter = tensor(DML_TENSOR_DATA_TYPE_UINT4, &[1, 1, 1, 3], None);
        let conv_out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None);
        let convolution = plan(
            DmlOpKind::Convolution {
                mode: DML_CONVOLUTION_MODE_CROSS_CORRELATION,
                strides: vec![1, 1],
                dilations: vec![1, 1],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                output_padding: vec![0, 0],
                group_count: 1,
            },
            vec![input.clone(), filter.clone()],
            conv_out.clone(),
        );
        let input_values = f32_bytes(&[1.0, 2.0, 3.0]);
        let filter_values = packed_int4(&[1, 2, 15, 0])[..2].to_vec();
        let mut cpu = vec![0u8; conv_out.total_size_in_bytes as usize];
        execute_plan(
            &convolution,
            DmlExecutionDevice::Cpu,
            &[&input_values, &filter_values],
            &mut cpu,
        )
        .expect("cpu uint4 convolution");
        assert_eq!(read_f32(&cpu), vec![50.0]);
        if metal_available() {
            let mut accelerated = vec![0u8; conv_out.total_size_in_bytes as usize];
            execute_plan(
                &convolution,
                DmlExecutionDevice::Metal,
                &[&input_values, &filter_values],
                &mut accelerated,
            )
            .expect("metal uint4 convolution");
            assert_eq!(read_f32(&accelerated), vec![50.0]);
        }
    }

    #[test]
    fn dml_packed_int4_malformed_weight_size_is_rejected_exactly() {
        let mut filter = tensor(DML_TENSOR_DATA_TYPE_INT4, &[1, 1, 1, 3], None);
        filter.total_size_in_bytes = 1;
        let convolution = plan(
            DmlOpKind::Convolution {
                mode: DML_CONVOLUTION_MODE_CROSS_CORRELATION,
                strides: vec![1, 1],
                dilations: vec![1, 1],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                output_padding: vec![0, 0],
                group_count: 1,
            },
            vec![
                tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 3], None),
                filter,
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 1, 1, 1], None),
        );
        assert_eq!(
            convolution.validate().unwrap_err().message,
            "tensor TotalTensorSizeInBytes 1 is smaller than the implied 2 bytes"
        );
    }

    #[test]
    fn dml_cross_node_fusion_edge_matches_wired_and_preserves_nan() {
        let input = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None);
        let add = plan(
            DmlOpKind::Binary {
                op: DmlBinaryOp::Add,
            },
            vec![input.clone(), input.clone()],
            input.clone(),
        );
        let negate = plan(
            DmlOpKind::Unary {
                op: DmlUnaryOp::Negate,
            },
            vec![input.clone()],
            input.clone(),
        );
        let graph = super::super::DmlGraphPlan {
            input_count: 2,
            output_count: 1,
            nodes: vec![add.clone(), add, negate],
            input_edges: vec![
                super::super::DmlGraphInputEdge {
                    graph_input: 0,
                    to_node: 0,
                    to_node_input: 0,
                },
                super::super::DmlGraphInputEdge {
                    graph_input: 1,
                    to_node: 0,
                    to_node_input: 1,
                },
                super::super::DmlGraphInputEdge {
                    graph_input: 0,
                    to_node: 1,
                    to_node_input: 1,
                },
            ],
            output_edges: vec![super::super::DmlGraphOutputEdge {
                from_node: 2,
                from_node_output: 0,
                graph_output: 0,
            }],
            intermediate_edges: vec![
                super::super::DmlGraphIntermediateEdge {
                    from_node: 0,
                    from_node_output: 0,
                    to_node: 1,
                    to_node_input: 0,
                },
                super::super::DmlGraphIntermediateEdge {
                    from_node: 1,
                    from_node_output: 0,
                    to_node: 2,
                    to_node_input: 0,
                },
            ],
            execution_order: vec![0, 1, 2],
        };
        let (wiring, output_sources, _) = graph_wiring(&graph).expect("graph wiring");
        let chains = find_fusion_chains(&graph, &wiring, &output_sources);
        assert_eq!(chains, vec![vec![0, 1, 2]]);
        let first = f32_bytes(&[-1.0, 2.0]);
        let second = f32_bytes(&[10.0, 20.0]);
        let mut cpu = vec![0u8; 8];
        execute_graph_plan(
            &graph,
            DmlExecutionDevice::Cpu,
            &[&first, &second],
            &mut [&mut cpu],
        )
        .expect("cpu graph");
        assert_eq!(read_f32(&cpu), vec![-8.0, -24.0]);
        if metal_available() {
            let mut metal = vec![0u8; 8];
            execute_graph_plan(
                &graph,
                DmlExecutionDevice::Metal,
                &[&first, &second],
                &mut [&mut metal],
            )
            .expect("fused metal graph");
            assert_eq!(read_f32(&metal), vec![-8.0, -24.0]);
        }

        let nan_values = f32_bytes(&[1.0, f32::NAN]);
        let zeros = f32_bytes(&[0.0, 0.0]);
        let mut cpu_nan = vec![0u8; 8];
        execute_graph_plan(
            &graph,
            DmlExecutionDevice::Cpu,
            &[&nan_values, &zeros],
            &mut [&mut cpu_nan],
        )
        .expect("cpu nan graph");
        let cpu_nan = read_f32(&cpu_nan);
        assert_eq!(cpu_nan[0], -2.0);
        assert_eq!(cpu_nan[1].is_nan(), true);
        if metal_available() {
            let mut metal_nan = vec![0u8; 8];
            execute_graph_plan(
                &graph,
                DmlExecutionDevice::Metal,
                &[&nan_values, &zeros],
                &mut [&mut metal_nan],
            )
            .expect("fused metal nan graph");
            let metal_nan = read_f32(&metal_nan);
            assert_eq!(metal_nan[0], -2.0);
            assert_eq!(metal_nan[1].is_nan(), true);
        }
    }

    #[test]
    fn dml_new_operator_families_numeric_and_malformed_edges() {
        let output = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let fill = plan(
            DmlOpKind::Fill {
                value: 1.0,
                step: 2.0,
                sequence: true,
            },
            Vec::new(),
            output.clone(),
        );
        assert_eq!(run_cpu(&fill, &[]), vec![1.0, 3.0, 5.0, 7.0]);
        let bad_fill = plan(
            DmlOpKind::Fill {
                value: 0.0,
                step: f32::INFINITY,
                sequence: true,
            },
            Vec::new(),
            output.clone(),
        );
        assert_eq!(
            bad_fill.validate().unwrap_err().message,
            "fill sequence step must be finite"
        );

        let indices = tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2], None);
        let values = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None);
        let one_hot_out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let one_hot = plan(
            DmlOpKind::OneHot { axis: 1 },
            vec![indices.clone(), values.clone()],
            one_hot_out.clone(),
        );
        let index_values: Vec<u8> = [0u32, 2]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let on_off = f32_bytes(&[5.0, -1.0]);
        assert_eq!(
            run_cpu(&one_hot, &[&index_values, &on_off]),
            vec![5.0, -1.0, -1.0, -1.0]
        );
        let bad_one_hot = plan(
            DmlOpKind::OneHot { axis: 2 },
            vec![indices, values],
            one_hot_out,
        );
        assert_eq!(
            bad_one_hot.validate().unwrap_err().message,
            "one-hot axis 2 is out of range for output rank 2"
        );

        let cumulative_out = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None);
        let cumulative = plan(
            DmlOpKind::Cumulative {
                product: false,
                axis: 1,
                reverse: true,
                exclusive: true,
            },
            vec![cumulative_out.clone()],
            cumulative_out.clone(),
        );
        assert_eq!(
            run_cpu(&cumulative, &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])]),
            vec![2.0, 0.0, 4.0, 0.0]
        );
        let bad_cumulative = plan(
            DmlOpKind::Cumulative {
                product: true,
                axis: 2,
                reverse: false,
                exclusive: false,
            },
            vec![cumulative_out.clone()],
            cumulative_out,
        );
        assert_eq!(
            bad_cumulative.validate().unwrap_err().message,
            "cumulative axis 2 is out of range for rank 2"
        );

        let sequence_values = tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 3], None);
        let lengths = tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None);
        let reverse = plan(
            DmlOpKind::Reverse { axis: 1 },
            vec![sequence_values.clone(), lengths.clone()],
            sequence_values.clone(),
        );
        assert_eq!(
            run_cpu(
                &reverse,
                &[&f32_bytes(&[1.0, 2.0, 3.0]), &2u32.to_le_bytes()]
            ),
            vec![2.0, 1.0, 3.0]
        );
        let bad_reverse = plan(
            DmlOpKind::Reverse { axis: 1 },
            vec![
                sequence_values,
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2], None),
            ],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[1, 3], None),
        );
        assert_eq!(
            bad_reverse.validate().unwrap_err().message,
            "reverse sequence lengths must contain 1 elements, got 2"
        );

        let diagonal = plan(
            DmlOpKind::DiagonalMatrix {
                offset: 1,
                value: 3.0,
            },
            Vec::new(),
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None),
        );
        assert_eq!(run_cpu(&diagonal, &[]), vec![0.0, 3.0, 0.0, 0.0, 0.0, 3.0]);
        let bad_diagonal = plan(
            DmlOpKind::DiagonalMatrix {
                offset: 3,
                value: 3.0,
            },
            Vec::new(),
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 3], None),
        );
        assert_eq!(
            bad_diagonal.validate().unwrap_err().message,
            "diagonal matrix offset 3 lies outside the 2x3 output"
        );

        let cast = plan(
            DmlOpKind::Cast,
            vec![tensor(DML_TENSOR_DATA_TYPE_INT32, &[2], None)],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
        );
        let int_values: Vec<u8> = [-7i32, 9]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        assert_eq!(run_cpu(&cast, &[&int_values]), vec![-7.0, 9.0]);
        let bad_cast = plan(
            DmlOpKind::Cast,
            vec![tensor(DML_TENSOR_DATA_TYPE_INT32, &[2], None)],
            tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3], None),
        );
        assert_eq!(
            bad_cast.validate().unwrap_err().message,
            "cast input and output element counts must match"
        );
    }
    fn f32_tensor(sizes: &[u32]) -> DmlTensorDesc {
        tensor(DML_TENSOR_DATA_TYPE_FLOAT32, sizes, None)
    }

    fn f32_plan(kind: DmlOpKind, inputs: Vec<DmlTensorDesc>, output: DmlTensorDesc) -> DmlOpPlan {
        plan(kind, inputs, output)
    }

    #[test]
    fn dml_extended_family_numeric_readback_edge_values_are_exact() {
        let hardmax = f32_plan(
            DmlOpKind::SoftmaxEx {
                kind: DmlSoftmaxKind::Hardmax,
                axes: vec![3],
            },
            vec![f32_tensor(&[1, 1, 1, 4])],
            f32_tensor(&[1, 1, 1, 4]),
        );
        assert_eq!(
            run_cpu(&hardmax, &[&f32_bytes(&[1.0, 2.0, 3.0, 1.0])]),
            vec![0.0, 0.0, 1.0, 0.0]
        );

        let log_softmax = f32_plan(
            DmlOpKind::SoftmaxEx {
                kind: DmlSoftmaxKind::LogSoftmax,
                axes: vec![3],
            },
            vec![f32_tensor(&[1, 1, 1, 4])],
            f32_tensor(&[1, 1, 1, 4]),
        );
        let values = [1.0f32, 2.0, 3.0, 1.0];
        let expected: Vec<f32> = values
            .iter()
            .map(|value| value - 3.0 - (2.0f32.exp().recip() * 2.0 + (-1.0f32).exp() + 1.0).ln())
            .collect();
        assert_values(
            &run_cpu(&log_softmax, &[&f32_bytes(&values)]),
            &expected,
            1e-6,
        );

        let softmax1 = f32_plan(
            DmlOpKind::SoftmaxEx {
                kind: DmlSoftmaxKind::Softmax1,
                axes: vec![2, 3],
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 2, 2]),
        );
        let values = [1.0f32, 2.0, 3.0, 4.0];
        let total: f32 = values.iter().map(|value| (value - 4.0).exp()).sum();
        let expected: Vec<f32> = values
            .iter()
            .map(|value| (value - 4.0).exp() / total)
            .collect();
        assert_values(&run_cpu(&softmax1, &[&f32_bytes(&values)]), &expected, 1e-6);

        let parameterized_relu = f32_plan(
            DmlOpKind::ExActivation {
                activation: DmlExActivation::ParameterizedRelu,
            },
            vec![f32_tensor(&[1, 1, 1, 3]), f32_tensor(&[1, 1, 1, 3])],
            f32_tensor(&[1, 1, 1, 3]),
        );
        assert_values(
            &run_cpu(
                &parameterized_relu,
                &[&f32_bytes(&[-2.0, 0.0, 3.0]), &f32_bytes(&[0.5, 0.5, 2.0])],
            ),
            &[-1.0, 0.0, 3.0],
            1e-6,
        );

        let softplus = f32_plan(
            DmlOpKind::ExActivation {
                activation: DmlExActivation::ParametricSoftplus {
                    alpha: 1.0,
                    beta: 1.0,
                },
            },
            vec![f32_tensor(&[1, 1, 1, 2])],
            f32_tensor(&[1, 1, 1, 2]),
        );
        assert_values(
            &run_cpu(&softplus, &[&f32_bytes(&[0.0, 1.0])]),
            &[2.0f32.ln(), (1.0f32 + 1.0f32.exp()).ln()],
            1e-6,
        );

        let scaled_elu = f32_plan(
            DmlOpKind::ExActivation {
                activation: DmlExActivation::ScaledElu {
                    alpha: 1.0,
                    gamma: 2.0,
                },
            },
            vec![f32_tensor(&[1, 1, 1, 3])],
            f32_tensor(&[1, 1, 1, 3]),
        );
        assert_values(
            &run_cpu(&scaled_elu, &[&f32_bytes(&[-1.0, 0.0, 1.0])]),
            &[2.0 * ((-1.0f32).exp() - 1.0), 0.0, 2.0],
            1e-6,
        );

        let shrink = f32_plan(
            DmlOpKind::ExActivation {
                activation: DmlExActivation::Shrink {
                    bias: 0.5,
                    threshold: 1.0,
                },
            },
            vec![f32_tensor(&[1, 1, 1, 5])],
            f32_tensor(&[1, 1, 1, 5]),
        );
        assert_values(
            &run_cpu(&shrink, &[&f32_bytes(&[-2.0, -0.5, 0.0, 0.5, 2.0])]),
            &[-1.5, 0.0, 0.0, 0.0, 1.5],
            1e-6,
        );

        let celu = f32_plan(
            DmlOpKind::ExActivation {
                activation: DmlExActivation::Celu { alpha: 1.0 },
            },
            vec![f32_tensor(&[1, 1, 1, 3])],
            f32_tensor(&[1, 1, 1, 3]),
        );
        assert_values(
            &run_cpu(&celu, &[&f32_bytes(&[-1.0, 0.0, 1.0])]),
            &[(-1.0f32).exp() - 1.0, 0.0, 1.0],
            1e-6,
        );

        let relu_grad = f32_plan(
            DmlOpKind::ReluGrad,
            vec![f32_tensor(&[1, 1, 1, 3]), f32_tensor(&[1, 1, 1, 3])],
            f32_tensor(&[1, 1, 1, 3]),
        );
        assert_values(
            &run_cpu(
                &relu_grad,
                &[&f32_bytes(&[-1.0, 0.0, 1.0]), &f32_bytes(&[2.0, 3.0, 4.0])],
            ),
            &[0.0, 0.0, 4.0],
            0.0,
        );

        let if_plan = f32_plan(
            DmlOpKind::If,
            vec![
                tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 1, 2, 2], None),
                f32_tensor(&[1, 1, 2, 2]),
                f32_tensor(&[1, 1, 2, 2]),
            ],
            f32_tensor(&[1, 1, 2, 2]),
        );
        assert_eq!(
            run_cpu(
                &if_plan,
                &[
                    &[0u8, 1, 2, 0],
                    &f32_bytes(&[10.0, 20.0, 30.0, 40.0]),
                    &f32_bytes(&[1.0, 2.0, 3.0, 4.0])
                ],
            ),
            vec![1.0, 20.0, 30.0, 4.0]
        );

        let bit_not = plan(
            DmlOpKind::BitNot,
            vec![tensor(DML_TENSOR_DATA_TYPE_UINT8, &[2], None)],
            tensor(DML_TENSOR_DATA_TYPE_UINT8, &[2], None),
        );
        assert_eq!(
            run_cpu_outputs(&bit_not, &[&[0x0f, 0xf0]])[0],
            vec![0xf0, 0x0f]
        );

        let bit_count = plan(
            DmlOpKind::BitCount,
            vec![tensor(DML_TENSOR_DATA_TYPE_UINT8, &[2], None)],
            tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2], None),
        );
        let counted = run_cpu_outputs(&bit_count, &[&[0x0f, 0xff]])[0]
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(counted, vec![4, 8]);

        let lp_pool = f32_plan(
            DmlOpKind::LpPooling {
                is_v1: false,
                p: 2,
                strides: vec![1, 1],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![],
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        assert_values(
            &run_cpu(&lp_pool, &[&f32_bytes(&[1.0, -2.0, 3.0, -4.0])]),
            &[30.0f32.sqrt()],
            1e-6,
        );

        let lp_pool1 = f32_plan(
            DmlOpKind::LpPooling {
                is_v1: true,
                p: 2,
                strides: vec![1, 1],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![2, 2],
            },
            vec![f32_tensor(&[1, 1, 3, 3])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        assert_values(
            &run_cpu(
                &lp_pool1,
                &[&f32_bytes(&[1.0, 0.0, 2.0, 0.0, 0.0, 0.0, 3.0, 0.0, 4.0])],
            ),
            &[30.0f32.sqrt()],
            1e-6,
        );

        let lp_norm = f32_plan(
            DmlOpKind::LpNormalization {
                axis: 3,
                epsilon: 0.0,
                p: 2,
            },
            vec![f32_tensor(&[1, 1, 1, 2])],
            f32_tensor(&[1, 1, 1, 2]),
        );
        assert_values(
            &run_cpu(&lp_norm, &[&f32_bytes(&[3.0, 4.0])]),
            &[0.6, 0.8],
            1e-6,
        );

        let value_scale = f32_plan(
            DmlOpKind::ValueScale2D {
                scale: 2.0,
                channel_count: 1,
                bias: vec![3.0],
            },
            vec![f32_tensor(&[1, 1, 1, 4])],
            f32_tensor(&[1, 1, 1, 4]),
        );
        assert_values(
            &run_cpu(&value_scale, &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])]),
            &[5.0, 7.0, 9.0, 11.0],
            0.0,
        );

        let depth_to_space = f32_plan(
            DmlOpKind::SpaceDepth {
                is_v1: false,
                to_depth: false,
                block_size: 2,
                order: 0,
            },
            vec![f32_tensor(&[1, 4, 1, 1])],
            f32_tensor(&[1, 1, 2, 2]),
        );
        assert_values(
            &run_cpu(&depth_to_space, &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])]),
            &[1.0, 2.0, 3.0, 4.0],
            0.0,
        );
        let space_to_depth = f32_plan(
            DmlOpKind::SpaceDepth {
                is_v1: false,
                to_depth: true,
                block_size: 2,
                order: 0,
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 4, 1, 1]),
        );
        assert_values(
            &run_cpu(&space_to_depth, &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])]),
            &[1.0, 2.0, 3.0, 4.0],
            0.0,
        );
        let space_to_depth_order1 = f32_plan(
            DmlOpKind::SpaceDepth {
                is_v1: false,
                to_depth: true,
                block_size: 2,
                order: 1,
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 4, 1, 1]),
        );
        assert_values(
            &run_cpu(&space_to_depth_order1, &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])]),
            &[1.0, 3.0, 2.0, 4.0],
            0.0,
        );

        let max_pool = plan(
            DmlOpKind::MaxPoolingEx {
                strides: vec![2, 2],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![1, 1],
                has_indices: true,
                dilations_supported: false,
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        let max_pool_plan = DmlOpPlan {
            extra_outputs: vec![tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 1], None)],
            ..max_pool
        };
        let outputs = run_cpu_outputs(&max_pool_plan, &[&f32_bytes(&[1.0, 4.0, 2.0, 3.0])]);
        assert_eq!(read_f32(&outputs[0]), vec![4.0]);
        assert_eq!(u32::from_le_bytes(outputs[1][..4].try_into().unwrap()), 1);

        let max_pool2 = plan(
            DmlOpKind::MaxPoolingEx {
                strides: vec![1, 1],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![2, 2],
                has_indices: false,
                dilations_supported: true,
            },
            vec![f32_tensor(&[1, 1, 3, 3])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        assert_eq!(
            run_cpu(
                &max_pool2,
                &[&f32_bytes(&[0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0])]
            ),
            vec![8.0]
        );

        let max_unpool = plan(
            DmlOpKind::MaxUnpooling,
            vec![
                f32_tensor(&[1, 1, 1, 1]),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 1], None),
            ],
            f32_tensor(&[1, 1, 2, 2]),
        );
        assert_eq!(
            run_cpu_outputs(&max_unpool, &[&f32_bytes(&[5.0]), &[3u8, 0, 0, 0]])[0]
                .chunks_exact(4)
                .map(|chunk| f32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>(),
            vec![0.0, 0.0, 0.0, 5.0]
        );
        assert_eq!(
            execute_plan(
                &max_unpool,
                DmlExecutionDevice::Cpu,
                &[&f32_bytes(&[5.0]), &[4u8, 0, 0, 0]],
                &mut vec![0u8; 16],
            )
            .unwrap_err()
            .message,
            "max unpooling index 4 is outside the output element count 4"
        );

        let slice1 = f32_plan(
            DmlOpKind::SliceEx {
                offsets: vec![0, 0, 1, 1],
                sizes: vec![1, 1, 2, 2],
                strides: vec![1, 1, 1, -1],
            },
            vec![f32_tensor(&[1, 1, 3, 3])],
            f32_tensor(&[1, 1, 2, 2]),
        );
        assert_values(
            &run_cpu(
                &slice1,
                &[&f32_bytes(&[0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0])],
            ),
            &[4.0, 3.0, 7.0, 6.0],
            0.0,
        );

        let clip1 = f32_plan(
            DmlOpKind::Clip1 {
                min: 0.0,
                max: 3.0,
                scale: 2.0,
                bias: 1.0,
                has_scale_bias: true,
            },
            vec![f32_tensor(&[1, 1, 1, 3])],
            f32_tensor(&[1, 1, 1, 3]),
        );
        assert_values(
            &run_cpu(&clip1, &[&f32_bytes(&[-2.0, 0.0, 2.0])]),
            &[0.0, 1.0, 3.0],
            0.0,
        );

        let avg_pool1 = f32_plan(
            DmlOpKind::AveragePooling1 {
                strides: vec![1, 1],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![1, 1],
                include_padding: false,
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        assert_values(
            &run_cpu(&avg_pool1, &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])]),
            &[2.5],
            0.0,
        );
    }

    #[test]
    fn dml_gradient_and_training_families_edge_values_are_exact() {
        let avg_grad = f32_plan(
            DmlOpKind::AveragePoolingGrad {
                strides: vec![2, 2],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                include_padding: false,
            },
            vec![f32_tensor(&[1, 1, 1, 1])],
            f32_tensor(&[1, 1, 2, 2]),
        );
        assert_eq!(
            run_cpu(&avg_grad, &[&f32_bytes(&[1.0])]),
            vec![0.25, 0.25, 0.25, 0.25]
        );
        run_both(
            &avg_grad,
            &[&f32_bytes(&[1.0])],
            &[0.25, 0.25, 0.25, 0.25],
            0.0,
        );

        let max_grad = f32_plan(
            DmlOpKind::MaxPoolingGrad {
                strides: vec![2, 2],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![1, 1],
            },
            vec![f32_tensor(&[1, 1, 2, 2]), f32_tensor(&[1, 1, 1, 1])],
            f32_tensor(&[1, 1, 2, 2]),
        );
        run_both(
            &max_grad,
            &[&f32_bytes(&[1.0, 4.0, 2.0, 3.0]), &f32_bytes(&[5.0])],
            &[0.0, 5.0, 0.0, 0.0],
            0.0,
        );

        let clip1 = f32_plan(
            DmlOpKind::Clip1 {
                min: 0.0,
                max: 3.0,
                scale: 2.0,
                bias: 1.0,
                has_scale_bias: true,
            },
            vec![f32_tensor(&[1, 1, 1, 3])],
            f32_tensor(&[1, 1, 1, 3]),
        );
        run_both(
            &clip1,
            &[&f32_bytes(&[-2.0, 0.0, 2.0])],
            &[0.0, 1.0, 3.0],
            0.0,
        );

        let value_scale = f32_plan(
            DmlOpKind::ValueScale2D {
                scale: 2.0,
                channel_count: 1,
                bias: vec![3.0],
            },
            vec![f32_tensor(&[1, 1, 1, 4])],
            f32_tensor(&[1, 1, 1, 4]),
        );
        run_both(
            &value_scale,
            &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])],
            &[5.0, 7.0, 9.0, 11.0],
            0.0,
        );

        let lp_norm = f32_plan(
            DmlOpKind::LpNormalization {
                axis: 3,
                epsilon: 0.0,
                p: 2,
            },
            vec![f32_tensor(&[1, 1, 1, 2])],
            f32_tensor(&[1, 1, 1, 2]),
        );
        run_both(&lp_norm, &[&f32_bytes(&[3.0, 4.0])], &[0.6, 0.8], 1e-6);

        let avg_pool1 = f32_plan(
            DmlOpKind::AveragePooling1 {
                strides: vec![1, 1],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![1, 1],
                include_padding: false,
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        run_both(
            &avg_pool1,
            &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])],
            &[2.5],
            0.0,
        );

        let bn_grad = DmlOpPlan {
            kind: DmlOpKind::BatchNormalizationGrad { epsilon: 0.0 },
            inputs: vec![
                f32_tensor(&[1, 2, 1, 2]),
                f32_tensor(&[1, 2, 1, 2]),
                f32_tensor(&[1, 2, 1, 1]),
                f32_tensor(&[1, 2, 1, 1]),
                f32_tensor(&[1, 2, 1, 1]),
            ],
            output: f32_tensor(&[1, 2, 1, 2]),
            extra_outputs: vec![f32_tensor(&[1, 2, 1, 1]), f32_tensor(&[1, 2, 1, 1])],
            fused_activation: None,
        };
        let bn_inputs: [&[u8]; 5] = [
            &f32_bytes(&[1.0, 3.0, 2.0, 6.0]),
            &f32_bytes(&[1.0, 1.0, 1.0, 1.0]),
            &f32_bytes(&[2.0, 4.0]),
            &f32_bytes(&[1.0, 4.0]),
            &f32_bytes(&[1.0, 1.0]),
        ];
        let cpu_outputs = run_cpu_outputs(&bn_grad, &bn_inputs);
        let metal_outputs = run_metal_outputs(&bn_grad, &bn_inputs);
        assert_values(
            &read_f32(&metal_outputs[0]),
            &read_f32(&cpu_outputs[0]),
            1e-6,
        );
        assert_values(
            &read_f32(&metal_outputs[1]),
            &read_f32(&cpu_outputs[1]),
            1e-6,
        );
        assert_values(
            &read_f32(&metal_outputs[2]),
            &read_f32(&cpu_outputs[2]),
            1e-6,
        );

        let bn_training_grad = DmlOpPlan {
            kind: DmlOpKind::BatchNormalizationTrainingGrad { epsilon: 0.0 },
            inputs: vec![
                f32_tensor(&[1, 2, 1, 2]),
                f32_tensor(&[1, 2, 1, 2]),
                f32_tensor(&[1, 2, 1, 1]),
                f32_tensor(&[1, 2, 1, 1]),
                f32_tensor(&[1, 2, 1, 1]),
            ],
            output: f32_tensor(&[1, 2, 1, 2]),
            extra_outputs: vec![f32_tensor(&[1, 2, 1, 1]), f32_tensor(&[1, 2, 1, 1])],
            fused_activation: None,
        };
        let cpu_outputs = run_cpu_outputs(&bn_training_grad, &bn_inputs);
        let metal_outputs = run_metal_outputs(&bn_training_grad, &bn_inputs);
        assert_values(
            &read_f32(&metal_outputs[0]),
            &read_f32(&cpu_outputs[0]),
            1e-6,
        );
        assert_values(
            &read_f32(&metal_outputs[1]),
            &read_f32(&cpu_outputs[1]),
            1e-6,
        );
        assert_values(
            &read_f32(&metal_outputs[2]),
            &read_f32(&cpu_outputs[2]),
            1e-6,
        );

        let roi_grad = f32_plan(
            DmlOpKind::RoiAlignGrad {
                reduction: DmlReduceKind::Mean,
                mode: DmlInterpolationMode::NearestNeighbor,
                spatial_scale_x: 1.0,
                spatial_scale_y: 1.0,
                input_pixel_offset: 0.0,
                output_pixel_offset: 0.0,
                minimum_samples_per_output: 1,
                maximum_samples_per_output: 1,
                align_regions_to_corners: false,
            },
            vec![
                f32_tensor(&[1, 1, 1, 1]),
                f32_tensor(&[1, 4]),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None),
            ],
            f32_tensor(&[1, 1, 2, 2]),
        );
        assert_values(
            &run_cpu(
                &roi_grad,
                &[
                    &f32_bytes(&[1.0]),
                    &f32_bytes(&[0.0, 0.0, 1.0, 1.0]),
                    &[0u8, 0, 0, 0],
                ],
            ),
            &[0.0, 0.0, 0.0, 1.0],
            1e-6,
        );

        let roi_grad_max = f32_plan(
            DmlOpKind::RoiAlignGrad {
                reduction: DmlReduceKind::Max,
                mode: DmlInterpolationMode::NearestNeighbor,
                spatial_scale_x: 1.0,
                spatial_scale_y: 1.0,
                input_pixel_offset: 0.0,
                output_pixel_offset: 0.0,
                minimum_samples_per_output: 1,
                maximum_samples_per_output: 1,
                align_regions_to_corners: false,
            },
            vec![
                f32_tensor(&[1, 1, 2, 2]),
                f32_tensor(&[1, 1, 1, 1]),
                f32_tensor(&[1, 4]),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None),
            ],
            f32_tensor(&[1, 1, 2, 2]),
        );
        assert_eq!(
            run_cpu(
                &roi_grad_max,
                &[
                    &f32_bytes(&[1.0, 4.0, 2.0, 3.0]),
                    &f32_bytes(&[1.0]),
                    &f32_bytes(&[0.0, 0.0, 1.0, 1.0]),
                    &[0u8, 0, 0, 0],
                ],
            ),
            vec![0.0, 0.0, 0.0, 1.0]
        );
    }

    #[test]
    fn dml_random_nonzero_diagonal_and_mha_edge_values_are_exact() {
        let random = plan(
            DmlOpKind::RandomGenerator { generator_type: 0 },
            vec![tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 6], None)],
            tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 4], None),
        );
        let random_plan = DmlOpPlan {
            extra_outputs: vec![tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 6], None)],
            ..random
        };
        let state = vec![0u8; 24];
        let first = run_cpu_outputs(&random_plan, &[&state]);
        let second = run_cpu_outputs(&random_plan, &[&state]);
        assert_eq!(first[0], second[0]);
        assert_eq!(
            first[1]
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>(),
            vec![1, 0, 0, 0, 0, 0]
        );
        assert_eq!(first[0].iter().any(|byte| *byte != 0), true);

        let nonzero = plan(
            DmlOpKind::NonZeroCoordinates,
            vec![tensor(DML_TENSOR_DATA_TYPE_UINT8, &[2, 2], None)],
            tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None),
        );
        let nonzero_plan = DmlOpPlan {
            extra_outputs: vec![tensor(DML_TENSOR_DATA_TYPE_UINT32, &[4, 2], None)],
            ..nonzero
        };
        let outputs = run_cpu_outputs(&nonzero_plan, &[&[0u8, 3, 0, 4]]);
        assert_eq!(u32::from_le_bytes(outputs[0][..4].try_into().unwrap()), 2);
        assert_eq!(
            outputs[1]
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>(),
            vec![0, 1, 1, 1, 0, 0, 0, 0]
        );

        let diagonal = f32_plan(
            DmlOpKind::DiagonalMatrix1 {
                offset_begin: 0,
                offset_end: 1,
                value: 7.0,
            },
            Vec::new(),
            f32_tensor(&[2, 3]),
        );
        assert_values(
            &run_cpu(&diagonal, &[]),
            &[7.0, 0.0, 0.0, 0.0, 7.0, 0.0],
            0.0,
        );
        let diagonal_input = f32_plan(
            DmlOpKind::DiagonalMatrix1 {
                offset_begin: 1,
                offset_end: 0,
                value: 0.0,
            },
            vec![f32_tensor(&[2, 2])],
            f32_tensor(&[2, 2]),
        );
        assert_values(
            &run_cpu(&diagonal_input, &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])]),
            &[1.0, 0.0, 0.0, 4.0],
            0.0,
        );

        let mha = f32_plan(
            DmlOpKind::MultiHeadAttention {
                scale: 1.0,
                mask_filter_value: -1000.0,
                query_head_count: 1,
                key_value_head_count: 1,
                mask_type: 0,
                layout: DmlMhaLayout::Separate,
                has_bias: false,
                has_mask: false,
                is_v1: false,
            },
            vec![
                f32_tensor(&[1, 1, 2]),
                f32_tensor(&[1, 1, 2]),
                f32_tensor(&[1, 1, 2]),
            ],
            f32_tensor(&[1, 1, 2]),
        );
        assert_values(
            &run_cpu(
                &mha,
                &[
                    &f32_bytes(&[1.0, 2.0]),
                    &f32_bytes(&[1.0, 2.0]),
                    &f32_bytes(&[1.0, 2.0]),
                ],
            ),
            &[1.0, 2.0],
            1e-6,
        );
        let mha1 = f32_plan(
            DmlOpKind::MultiHeadAttention {
                scale: 2.0,
                mask_filter_value: -1000.0,
                query_head_count: 2,
                key_value_head_count: 1,
                mask_type: 0,
                layout: DmlMhaLayout::Separate,
                has_bias: false,
                has_mask: false,
                is_v1: true,
            },
            vec![
                f32_tensor(&[1, 1, 4]),
                f32_tensor(&[1, 1, 4]),
                f32_tensor(&[1, 1, 2]),
            ],
            f32_tensor(&[1, 1, 2]),
        );
        assert_values(
            &run_cpu(
                &mha1,
                &[
                    &f32_bytes(&[1.0, 2.0, 3.0, 4.0]),
                    &f32_bytes(&[1.0, 2.0, 3.0, 4.0]),
                    &f32_bytes(&[5.0, 6.0]),
                ],
            ),
            &[5.0, 6.0],
            1e-6,
        );
    }

    #[test]
    fn dml_new_operator_malformed_inputs_fail_exactly() {
        let bad_lp = f32_plan(
            DmlOpKind::LpPooling {
                is_v1: false,
                p: 0,
                strides: vec![1, 1],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![],
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        assert_eq!(
            bad_lp.validate().unwrap_err().message,
            "LP pooling P must be non-zero"
        );

        let bad_if = f32_plan(
            DmlOpKind::If,
            vec![
                tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 1, 1, 2], None),
                f32_tensor(&[1, 1, 1, 3]),
                f32_tensor(&[1, 1, 1, 3]),
            ],
            f32_tensor(&[1, 1, 1, 3]),
        );
        assert_eq!(
            bad_if.validate().unwrap_err().message,
            "IF tensor sizes are not broadcast-compatible at dimension 3: [2, 3, 3]"
        );

        let bad_slice = f32_plan(
            DmlOpKind::SliceEx {
                offsets: vec![0, 0, 0, 0],
                sizes: vec![1, 1, 1, 1],
                strides: vec![1, 1, 1, 0],
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        assert_eq!(
            bad_slice.validate().unwrap_err().message,
            "slice1 stride at axis 3 must be non-zero"
        );

        let bad_value_scale = f32_plan(
            DmlOpKind::ValueScale2D {
                scale: 1.0,
                channel_count: 2,
                bias: vec![0.0, 0.0],
            },
            vec![f32_tensor(&[1, 1, 1, 1])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        assert_eq!(
            bad_value_scale.validate().unwrap_err().message,
            "value scale 2D ChannelCount must be 1 or 3, got 2"
        );

        let bad_random = plan(
            DmlOpKind::RandomGenerator { generator_type: 0 },
            vec![tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 5], None)],
            tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 4], None),
        );
        assert_eq!(
            bad_random.validate().unwrap_err().message,
            "Philox random generator state must contain exactly 6 UINT32 values"
        );

        let bad_mha = f32_plan(
            DmlOpKind::MultiHeadAttention {
                scale: 1.0,
                mask_filter_value: 0.0,
                query_head_count: 3,
                key_value_head_count: 2,
                mask_type: 0,
                layout: DmlMhaLayout::Separate,
                has_bias: false,
                has_mask: false,
                is_v1: true,
            },
            vec![
                f32_tensor(&[1, 1, 6]),
                f32_tensor(&[1, 1, 6]),
                f32_tensor(&[1, 1, 4]),
            ],
            f32_tensor(&[1, 1, 4]),
        );
        assert_eq!(
            bad_mha.validate().unwrap_err().message,
            "multi-head attention query head count 3 must be a multiple of key/value head count 2"
        );

        let bad_bit_count = plan(
            DmlOpKind::BitCount,
            vec![tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None)],
            f32_tensor(&[1]),
        );
        assert_eq!(
            bad_bit_count.validate().unwrap_err().message,
            "DML_OPERATOR_TYPE 125 bit count output tensor has unsupported DML_TENSOR_DATA_TYPE 1"
        );
    }
    #[test]
    fn dml_extended_family_metal_edge_readback_matches_cpu() {
        if !metal_available() {
            return;
        }
        let hardmax = f32_plan(
            DmlOpKind::SoftmaxEx {
                kind: DmlSoftmaxKind::Hardmax,
                axes: vec![3],
            },
            vec![f32_tensor(&[1, 1, 1, 4])],
            f32_tensor(&[1, 1, 1, 4]),
        );
        run_both(
            &hardmax,
            &[&f32_bytes(&[1.0, 3.0, 3.0, 1.0])],
            &[0.0, 1.0, 0.0, 0.0],
            0.0,
        );

        let if_plan = f32_plan(
            DmlOpKind::If,
            vec![
                tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 1, 2, 2], None),
                f32_tensor(&[1, 1, 2, 2]),
                f32_tensor(&[1, 1, 2, 2]),
            ],
            f32_tensor(&[1, 1, 2, 2]),
        );
        run_both(
            &if_plan,
            &[
                &[0u8, 1, 1, 0],
                &f32_bytes(&[10.0, 20.0, 30.0, 40.0]),
                &f32_bytes(&[1.0, 2.0, 3.0, 4.0]),
            ],
            &[1.0, 20.0, 30.0, 4.0],
            0.0,
        );

        let lp_pool = f32_plan(
            DmlOpKind::LpPooling {
                is_v1: false,
                p: 2,
                strides: vec![1, 1],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![],
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        run_both(
            &lp_pool,
            &[&f32_bytes(&[1.0, -2.0, 3.0, -4.0])],
            &[30.0f32.sqrt()],
            1e-5,
        );

        let space_depth = f32_plan(
            DmlOpKind::SpaceDepth {
                is_v1: false,
                to_depth: false,
                block_size: 2,
                order: 0,
            },
            vec![f32_tensor(&[1, 4, 1, 1])],
            f32_tensor(&[1, 1, 2, 2]),
        );
        run_both(
            &space_depth,
            &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])],
            &[1.0, 2.0, 3.0, 4.0],
            0.0,
        );

        let max_pool = plan(
            DmlOpKind::MaxPoolingEx {
                strides: vec![2, 2],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![1, 1],
                has_indices: true,
                dilations_supported: false,
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        let max_pool = DmlOpPlan {
            extra_outputs: vec![tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 1], None)],
            ..max_pool
        };
        let cpu_outputs = run_cpu_outputs(&max_pool, &[&f32_bytes(&[1.0, 4.0, 2.0, 3.0])]);
        let metal_outputs = run_metal_outputs(&max_pool, &[&f32_bytes(&[1.0, 4.0, 2.0, 3.0])]);
        assert_eq!(cpu_outputs, metal_outputs);

        let bn_training = f32_plan(
            DmlOpKind::BatchNormalizationTraining { epsilon: 0.0 },
            vec![
                f32_tensor(&[1, 2, 1, 2]),
                f32_tensor(&[1, 2, 1, 1]),
                f32_tensor(&[1, 2, 1, 1]),
            ],
            f32_tensor(&[1, 2, 1, 2]),
        );
        let bn_training = DmlOpPlan {
            extra_outputs: vec![f32_tensor(&[1, 2, 1, 1]), f32_tensor(&[1, 2, 1, 1])],
            ..bn_training
        };
        let inputs: [&[u8]; 3] = [
            &f32_bytes(&[1.0, 3.0, 2.0, 6.0]),
            &f32_bytes(&[1.0, 1.0]),
            &f32_bytes(&[0.0, 0.0]),
        ];
        let cpu_outputs = run_cpu_outputs(&bn_training, &inputs);
        let metal_outputs = run_metal_outputs(&bn_training, &inputs);
        assert_eq!(read_f32(&cpu_outputs[0]), read_f32(&metal_outputs[0]));
        assert_eq!(read_f32(&cpu_outputs[1]), read_f32(&metal_outputs[1]));
        assert_eq!(read_f32(&cpu_outputs[2]), read_f32(&metal_outputs[2]));
    }

    #[test]
    fn dml_gradient_and_aux_metal_edge_readback_matches_cpu() {
        if !metal_available() {
            return;
        }
        let log_softmax = f32_plan(
            DmlOpKind::SoftmaxEx {
                kind: DmlSoftmaxKind::LogSoftmax1,
                axes: vec![2, 3],
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 2, 2]),
        );
        let values = [1.0f32, 2.0, 3.0, 4.0];
        let total: f32 = values.iter().map(|value| (value - 4.0).exp()).sum();
        let expected: Vec<f32> = values
            .iter()
            .map(|value| value - 4.0 - total.ln())
            .collect();
        run_both(&log_softmax, &[&f32_bytes(&values)], &expected, 1e-5);

        let shrink = f32_plan(
            DmlOpKind::ExActivation {
                activation: DmlExActivation::Shrink {
                    bias: 0.5,
                    threshold: 1.0,
                },
            },
            vec![f32_tensor(&[1, 1, 1, 5])],
            f32_tensor(&[1, 1, 1, 5]),
        );
        run_both(
            &shrink,
            &[&f32_bytes(&[-2.0, -0.5, 0.0, 0.5, 2.0])],
            &[-1.5, 0.0, 0.0, 0.0, 1.5],
            0.0,
        );

        let slice1 = f32_plan(
            DmlOpKind::SliceEx {
                offsets: vec![0, 0, 1, 1],
                sizes: vec![1, 1, 2, 2],
                strides: vec![1, 1, 1, -1],
            },
            vec![f32_tensor(&[1, 1, 3, 3])],
            f32_tensor(&[1, 1, 2, 2]),
        );
        run_both(
            &slice1,
            &[&f32_bytes(&[0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0])],
            &[4.0, 3.0, 7.0, 6.0],
            0.0,
        );

        let slice_grad = f32_plan(
            DmlOpKind::SliceGrad {
                offsets: vec![0, 0, 1, 1],
                sizes: vec![1, 1, 2, 2],
                strides: vec![1, 1, 1, -1],
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 3, 3]),
        );
        run_both(
            &slice_grad,
            &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])],
            &[0.0, 0.0, 0.0, 2.0, 1.0, 0.0, 4.0, 3.0, 0.0],
            0.0,
        );

        let resample_grad = f32_plan(
            DmlOpKind::ResampleGrad {
                is_v1: false,
                mode: DmlInterpolationMode::NearestNeighbor,
                rounding: DmlAxisDirection::Increasing,
                scales: vec![1.0, 1.0, 2.0, 2.0],
                input_offsets: vec![0.0; 4],
                output_offsets: vec![0.0; 4],
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 4, 4]),
        );
        run_both(
            &resample_grad,
            &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])],
            &[
                1.0, 2.0, 0.0, 0.0, 3.0, 4.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            ],
            0.0,
        );

        let lrn_grad = f32_plan(
            DmlOpKind::LrnGrad {
                cross_channel: true,
                local_size: 1,
                alpha: 1.0,
                beta: 1.0,
                bias: 1.0,
            },
            vec![f32_tensor(&[1, 2, 1]), f32_tensor(&[1, 2, 1])],
            f32_tensor(&[1, 2, 1]),
        );
        run_both(
            &lrn_grad,
            &[&f32_bytes(&[1.0, 2.0]), &f32_bytes(&[1.0, 1.0])],
            &[0.0, -0.12],
            1e-5,
        );

        let random = DmlOpPlan {
            kind: DmlOpKind::RandomGenerator { generator_type: 0 },
            inputs: vec![tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 6], None)],
            output: tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 4], None),
            extra_outputs: vec![tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 6], None)],
            fused_activation: None,
        };
        let state = vec![0u8; 24];
        assert_eq!(
            run_cpu_outputs(&random, &[&state]),
            run_metal_outputs(&random, &[&state])
        );

        let nonzero = DmlOpPlan {
            kind: DmlOpKind::NonZeroCoordinates,
            inputs: vec![tensor(DML_TENSOR_DATA_TYPE_UINT8, &[2, 2], None)],
            output: tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None),
            extra_outputs: vec![tensor(DML_TENSOR_DATA_TYPE_UINT32, &[4, 2], None)],
            fused_activation: None,
        };
        assert_eq!(
            run_cpu_outputs(&nonzero, &[&[0u8, 3, 0, 4]]),
            run_metal_outputs(&nonzero, &[&[0u8, 3, 0, 4]])
        );

        let diagonal = f32_plan(
            DmlOpKind::DiagonalMatrix1 {
                offset_begin: 1,
                offset_end: 0,
                value: 0.0,
            },
            vec![f32_tensor(&[2, 2])],
            f32_tensor(&[2, 2]),
        );
        run_both(
            &diagonal,
            &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])],
            &[1.0, 0.0, 0.0, 4.0],
            0.0,
        );

        let mha = f32_plan(
            DmlOpKind::MultiHeadAttention {
                scale: 1.0,
                mask_filter_value: -1000.0,
                query_head_count: 1,
                key_value_head_count: 1,
                mask_type: 0,
                layout: DmlMhaLayout::Separate,
                has_bias: false,
                has_mask: false,
                is_v1: false,
            },
            vec![
                f32_tensor(&[1, 2, 2]),
                f32_tensor(&[1, 2, 2]),
                f32_tensor(&[1, 2, 2]),
            ],
            f32_tensor(&[1, 2, 2]),
        );
        let cpu = run_cpu(
            &mha,
            &[
                &f32_bytes(&[1.0, 0.0, 0.0, 1.0]),
                &f32_bytes(&[1.0, 0.0, 0.0, 1.0]),
                &f32_bytes(&[1.0, 2.0, 3.0, 4.0]),
            ],
        );
        let mut metal = vec![0u8; mha.output.total_size_in_bytes as usize];
        execute_plan(
            &mha,
            DmlExecutionDevice::Metal,
            &[
                &f32_bytes(&[1.0, 0.0, 0.0, 1.0]),
                &f32_bytes(&[1.0, 0.0, 0.0, 1.0]),
                &f32_bytes(&[1.0, 2.0, 3.0, 4.0]),
            ],
            &mut metal,
        )
        .expect("metal execution");
        assert_values(&read_f32(&metal), &cpu, 1e-5);

        let masked_mha = f32_plan(
            DmlOpKind::MultiHeadAttention {
                scale: 1.0,
                mask_filter_value: -1000.0,
                query_head_count: 1,
                key_value_head_count: 1,
                mask_type: 4,
                layout: DmlMhaLayout::Separate,
                has_bias: false,
                has_mask: true,
                is_v1: false,
            },
            vec![
                f32_tensor(&[1, 2, 2]),
                f32_tensor(&[1, 2, 2]),
                f32_tensor(&[1, 2, 2]),
                tensor(DML_TENSOR_DATA_TYPE_UINT8, &[1, 2, 2], None),
            ],
            f32_tensor(&[1, 2, 2]),
        );
        let masked_inputs: [&[u8]; 4] = [
            &f32_bytes(&[1.0, 0.0, 0.0, 1.0]),
            &f32_bytes(&[1.0, 0.0, 0.0, 1.0]),
            &f32_bytes(&[1.0, 2.0, 3.0, 4.0]),
            &[1u8, 0, 1, 1],
        ];
        let cpu = run_cpu(&masked_mha, &masked_inputs);
        let mut metal = vec![0u8; masked_mha.output.total_size_in_bytes as usize];
        execute_plan(
            &masked_mha,
            DmlExecutionDevice::Metal,
            &masked_inputs,
            &mut metal,
        )
        .expect("metal execution");
        assert_values(&read_f32(&metal), &cpu, 1e-5);

        let avg_grad = f32_plan(
            DmlOpKind::AveragePoolingGrad {
                strides: vec![2, 2],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                include_padding: false,
            },
            vec![f32_tensor(&[1, 1, 1, 1])],
            f32_tensor(&[1, 1, 2, 2]),
        );
        assert_eq!(
            run_cpu(&avg_grad, &[&f32_bytes(&[1.0])]),
            vec![0.25, 0.25, 0.25, 0.25]
        );

        let max_grad = f32_plan(
            DmlOpKind::MaxPoolingGrad {
                strides: vec![2, 2],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![1, 1],
            },
            vec![f32_tensor(&[1, 1, 2, 2]), f32_tensor(&[1, 1, 1, 1])],
            f32_tensor(&[1, 1, 2, 2]),
        );
        assert_values(
            &run_cpu(
                &max_grad,
                &[&f32_bytes(&[1.0, 4.0, 2.0, 3.0]), &f32_bytes(&[5.0])],
            ),
            &[0.0, 5.0, 0.0, 0.0],
            0.0,
        );

        let resample_grad = f32_plan(
            DmlOpKind::ResampleGrad {
                is_v1: false,
                mode: DmlInterpolationMode::NearestNeighbor,
                rounding: DmlAxisDirection::Increasing,
                scales: vec![1.0, 1.0, 2.0, 2.0],
                input_offsets: vec![0.0; 4],
                output_offsets: vec![0.0; 4],
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 4, 4]),
        );
        assert_values(
            &run_cpu(&resample_grad, &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])]),
            &[
                1.0, 2.0, 0.0, 0.0, 3.0, 4.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            ],
            0.0,
        );

        let slice_grad = f32_plan(
            DmlOpKind::SliceGrad {
                offsets: vec![0, 0, 1, 1],
                sizes: vec![1, 1, 2, 2],
                strides: vec![1, 1, 1, -1],
            },
            vec![f32_tensor(&[1, 1, 2, 2])],
            f32_tensor(&[1, 1, 3, 3]),
        );
        assert_values(
            &run_cpu(&slice_grad, &[&f32_bytes(&[1.0, 2.0, 3.0, 4.0])]),
            &[0.0, 0.0, 0.0, 2.0, 1.0, 0.0, 4.0, 3.0, 0.0],
            0.0,
        );

        let clip_grad = f32_plan(
            DmlOpKind::ClipGrad {
                is_v1: false,
                min: -0.5,
                max: 0.5,
            },
            vec![f32_tensor(&[1, 1, 1, 3]), f32_tensor(&[1, 1, 1, 3])],
            f32_tensor(&[1, 1, 1, 3]),
        );
        assert_values(
            &run_cpu(
                &clip_grad,
                &[&f32_bytes(&[-1.0, 0.0, 1.0]), &f32_bytes(&[2.0, 3.0, 4.0])],
            ),
            &[0.0, 3.0, 0.0],
            0.0,
        );

        let lrn_grad = f32_plan(
            DmlOpKind::LrnGrad {
                cross_channel: true,
                local_size: 1,
                alpha: 1.0,
                beta: 1.0,
                bias: 1.0,
            },
            vec![f32_tensor(&[1, 2, 1]), f32_tensor(&[1, 2, 1])],
            f32_tensor(&[1, 2, 1]),
        );
        assert_values(
            &run_cpu(
                &lrn_grad,
                &[&f32_bytes(&[1.0, 2.0]), &f32_bytes(&[1.0, 1.0])],
            ),
            &[0.0, -0.12],
            1e-6,
        );

        let max_pool2 = f32_plan(
            DmlOpKind::MaxPoolingEx {
                strides: vec![1, 1],
                window: vec![2, 2],
                start_padding: vec![0, 0],
                end_padding: vec![0, 0],
                dilations: vec![2, 2],
                has_indices: false,
                dilations_supported: true,
            },
            vec![f32_tensor(&[1, 1, 3, 3])],
            f32_tensor(&[1, 1, 1, 1]),
        );
        run_both(
            &max_pool2,
            &[&f32_bytes(&[0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0])],
            &[8.0],
            0.0,
        );

        let max_unpool = f32_plan(
            DmlOpKind::MaxUnpooling,
            vec![
                f32_tensor(&[1, 1, 1, 1]),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1, 1, 1, 1], None),
            ],
            f32_tensor(&[1, 1, 2, 2]),
        );
        run_both(
            &max_unpool,
            &[&f32_bytes(&[5.0]), &[3u8, 0, 0, 0]],
            &[0.0, 0.0, 0.0, 5.0],
            0.0,
        );
        assert_eq!(
            execute_plan(
                &max_unpool,
                DmlExecutionDevice::Metal,
                &[&f32_bytes(&[5.0]), &[4u8, 0, 0, 0]],
                &mut vec![0u8; 16][..],
            )
            .unwrap_err()
            .message,
            "max unpooling index 4 is outside the output element count 4"
        );

        let bn_training = f32_plan(
            DmlOpKind::BatchNormalizationTraining { epsilon: 0.0 },
            vec![
                f32_tensor(&[1, 2, 1, 2]),
                f32_tensor(&[1, 2, 1, 1]),
                f32_tensor(&[1, 2, 1, 1]),
            ],
            f32_tensor(&[1, 2, 1, 2]),
        );
        let bn_training_plan = DmlOpPlan {
            extra_outputs: vec![f32_tensor(&[1, 2, 1, 1]), f32_tensor(&[1, 2, 1, 1])],
            ..bn_training
        };
        let outputs = run_cpu_outputs(
            &bn_training_plan,
            &[
                &f32_bytes(&[1.0, 3.0, 2.0, 6.0]),
                &f32_bytes(&[1.0, 1.0]),
                &f32_bytes(&[0.0, 0.0]),
            ],
        );
        assert_values(&read_f32(&outputs[0]), &[-1.0, 1.0, -1.0, 1.0], 1e-6);
        assert_values(&read_f32(&outputs[1]), &[2.0, 4.0], 1e-6);
        assert_values(&read_f32(&outputs[2]), &[1.0, 4.0], 1e-6);

        let bn_grad = f32_plan(
            DmlOpKind::BatchNormalizationGrad { epsilon: 0.0 },
            vec![
                f32_tensor(&[1, 2, 1, 2]),
                f32_tensor(&[1, 2, 1, 2]),
                f32_tensor(&[1, 2, 1, 1]),
                f32_tensor(&[1, 2, 1, 1]),
                f32_tensor(&[1, 2, 1, 1]),
            ],
            f32_tensor(&[1, 2, 1, 2]),
        );
        let bn_grad_plan = DmlOpPlan {
            extra_outputs: vec![f32_tensor(&[1, 2, 1, 1]), f32_tensor(&[1, 2, 1, 1])],
            ..bn_grad
        };
        let outputs = run_cpu_outputs(
            &bn_grad_plan,
            &[
                &f32_bytes(&[1.0, 3.0, 2.0, 6.0]),
                &f32_bytes(&[1.0, 1.0, 1.0, 1.0]),
                &f32_bytes(&[2.0, 4.0]),
                &f32_bytes(&[1.0, 4.0]),
                &f32_bytes(&[1.0, 1.0]),
            ],
        );
        assert_values(&read_f32(&outputs[0]), &[1.0, 1.0, 0.5, 0.5], 1e-6);
        assert_values(&read_f32(&outputs[1]), &[0.0, 0.0], 1e-6);
        assert_values(&read_f32(&outputs[2]), &[2.0, 2.0], 1e-6);

        let bn_training_grad = f32_plan(
            DmlOpKind::BatchNormalizationTrainingGrad { epsilon: 0.0 },
            vec![
                f32_tensor(&[1, 2, 1, 2]),
                f32_tensor(&[1, 2, 1, 2]),
                f32_tensor(&[1, 2, 1, 1]),
                f32_tensor(&[1, 2, 1, 1]),
                f32_tensor(&[1, 2, 1, 1]),
            ],
            f32_tensor(&[1, 2, 1, 2]),
        );
        let bn_training_grad_plan = DmlOpPlan {
            extra_outputs: vec![f32_tensor(&[1, 2, 1, 1]), f32_tensor(&[1, 2, 1, 1])],
            ..bn_training_grad
        };
        let outputs = run_cpu_outputs(
            &bn_training_grad_plan,
            &[
                &f32_bytes(&[1.0, 3.0, 2.0, 6.0]),
                &f32_bytes(&[1.0, 1.0, 1.0, 1.0]),
                &f32_bytes(&[2.0, 4.0]),
                &f32_bytes(&[1.0, 4.0]),
                &f32_bytes(&[1.0, 1.0]),
            ],
        );
        assert_values(&read_f32(&outputs[0]), &[0.0, 0.0, 0.0, 0.0], 1e-6);
        assert_values(&read_f32(&outputs[1]), &[0.0, 0.0], 1e-6);
        assert_values(&read_f32(&outputs[2]), &[2.0, 2.0], 1e-6);

        let roi_grad = f32_plan(
            DmlOpKind::RoiAlignGrad {
                reduction: DmlReduceKind::Mean,
                mode: DmlInterpolationMode::NearestNeighbor,
                spatial_scale_x: 1.0,
                spatial_scale_y: 1.0,
                input_pixel_offset: 0.0,
                output_pixel_offset: 0.0,
                minimum_samples_per_output: 1,
                maximum_samples_per_output: 1,
                align_regions_to_corners: false,
            },
            vec![
                f32_tensor(&[1, 1, 1, 1]),
                f32_tensor(&[1, 4]),
                tensor(DML_TENSOR_DATA_TYPE_UINT32, &[1], None),
            ],
            f32_tensor(&[1, 1, 2, 2]),
        );
        run_both(
            &roi_grad,
            &[
                &f32_bytes(&[1.0]),
                &f32_bytes(&[0.0, 0.0, 1.0, 1.0]),
                &[0u8, 0, 0, 0],
            ],
            &[0.0, 0.0, 0.0, 1.0],
            1e-5,
        );
    }
}
