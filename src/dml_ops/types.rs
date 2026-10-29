//! Types portion of the DML operator implementation.

use super::*;

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

    pub(crate) fn validate(self, ty: u32) -> DmlResult<()> {
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
    pub(crate) fn input_count(self) -> usize {
        3 + usize::from(self.bias)
            + usize::from(self.hidden_init)
            + usize::from(self.cell_init)
            + usize::from(self.sequence_lengths)
            + usize::from(self.peephole)
    }

    /// Role name for an input slot (used by binding errors).
    pub(crate) fn role(self, index: usize) -> &'static str {
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

    pub(crate) fn minimum_feature_level(self) -> u32 {
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

    pub(crate) fn allows_float16(&self) -> bool {
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

    pub(crate) fn supports_fused_activation(&self) -> bool {
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
