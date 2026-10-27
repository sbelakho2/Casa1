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
    DML_TENSOR_DATA_TYPE_FLOAT16, DML_TENSOR_DATA_TYPE_FLOAT32, DML_TENSOR_MIN_ALIGNMENT, DmlError,
    DmlResult, DmlTensorDesc, E_FAIL,
};
use crate::metal_backend::MetalDevice;

pub const DML_OPERATOR_GEMM: u32 = 54;
pub const DML_OPERATOR_CONVOLUTION: u32 = 53;
pub const DML_OPERATOR_REDUCE: u32 = 55;
pub const DML_OPERATOR_AVERAGE_POOLING: u32 = 56;
pub const DML_OPERATOR_MAX_POOLING: u32 = 58;
pub const DML_OPERATOR_ACTIVATION_LEAKY_RELU: u32 = 39;
pub const DML_OPERATOR_ACTIVATION_RELU: u32 = 44;
pub const DML_OPERATOR_ACTIVATION_SIGMOID: u32 = 47;
pub const DML_OPERATOR_ACTIVATION_SOFTMAX: u32 = 48;
pub const DML_OPERATOR_ACTIVATION_TANH: u32 = 51;
pub const DML_OPERATOR_BATCH_NORMALIZATION: u32 = 72;
pub const DML_OPERATOR_JOIN: u32 = 63;
pub const DML_OPERATOR_SLICE: u32 = 60;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlActivation {
    Relu,
    LeakyRelu,
    Sigmoid,
    Tanh,
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
            Self::Activation { activation, .. } => match activation {
                DmlActivation::Relu => DML_OPERATOR_ACTIVATION_RELU,
                DmlActivation::LeakyRelu => DML_OPERATOR_ACTIVATION_LEAKY_RELU,
                DmlActivation::Sigmoid => DML_OPERATOR_ACTIVATION_SIGMOID,
                DmlActivation::Tanh => DML_OPERATOR_ACTIVATION_TANH,
            },
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
        }
    }

    fn allows_float16(&self) -> bool {
        !matches!(
            self,
            Self::Convolution { .. } | Self::Pooling { .. } | Self::BatchNormalization { .. }
        )
    }
}

/// A complete extended operator: kind, ordered input tensors, output tensor.
///
/// Input order follows the DirectML descriptor:
/// - GEMM: A, B, [C]
/// - Convolution: input, filter, [bias]
/// - Pooling/Activation/Softmax/Reduce/Reshape/Transpose/Slice: input
/// - BatchNormalization: input, mean, variance, scale, bias
/// - Binary: A, B
/// - Concat: input 0..N
#[derive(Debug, Clone, PartialEq)]
pub struct DmlOpPlan {
    pub kind: DmlOpKind,
    pub inputs: Vec<DmlTensorDesc>,
    pub output: DmlTensorDesc,
}

impl DmlOpPlan {
    pub fn operator_type(&self) -> u32 {
        self.kind.operator_type()
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
            DmlOpKind::Binary { .. } => vec!["A", "B"],
            DmlOpKind::Concat { .. } => vec!["input"; self.inputs.len()],
            _ => vec!["input"],
        }
    }

    pub fn validate(&self) -> DmlResult<()> {
        let ty = self.operator_type();
        if self.inputs.is_empty() {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {ty} requires at least one input tensor"
            )));
        }
        let allow_f16 = self.kind.allows_float16();
        for desc in self.inputs.iter().chain(std::iter::once(&self.output)) {
            validate_dtype(desc, ty, allow_f16)?;
        }
        for desc in &self.inputs {
            validate_layout(desc, ty)?;
        }
        validate_layout(&self.output, ty)?;
        for input in &self.inputs {
            if input.data_type != self.output.data_type {
                return Err(DmlError::invalid(
                    "input and output tensors must have the same DataType",
                ));
            }
        }
        if self.output.strides.contains(&0) {
            return Err(DmlError::invalid("output tensor strides must be non-zero"));
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
            DmlOpKind::Reduce { axes, .. } => self.validate_reduce(axes),
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

    fn validate_reduce(&self, axes: &[u32]) -> DmlResult<()> {
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
        other => Err(DmlError::invalid(format!(
            "DML_TENSOR_DATA_TYPE {other} is not supported for DML_OPERATOR_TYPE {ty}"
        ))),
    }
}

fn msl_header(plan: &DmlOpPlan, scalar: &str) -> String {
    let mut source = String::from("#include <metal_stdlib>\nusing namespace metal;\n");
    source.push_str("kernel void dml_op(");
    for index in 0..plan.inputs.len() {
        source.push_str(&format!(
            "device const {scalar}* in{index} [[buffer({index})]], "
        ));
    }
    source.push_str(&format!(
        "device {scalar}* out [[buffer({})]], uint gid [[thread_position_in_grid]]) {{\n",
        plan.inputs.len()
    ));
    source
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
    let value = match activation {
        DmlActivation::Relu => "fmax(x, 0.0f)".to_string(),
        DmlActivation::LeakyRelu => format!("x >= 0.0f ? x : x * {}", msl_float(alpha)),
        DmlActivation::Sigmoid => "1.0f / (1.0f + exp(-x))".to_string(),
        DmlActivation::Tanh => "tanh(x)".to_string(),
    };
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
    source.push_str("    float acc = 0.0f;\n");
    source.push_str("    float best = -INFINITY;\n");
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
        DmlReduceKind::Sum | DmlReduceKind::Mean => {
            source.push_str("        acc += v;\n");
        }
        DmlReduceKind::Max => {
            source.push_str("        if (!v_nan) best = fmax(best, v);\n");
        }
    }
    source.push_str("    }\n");
    let value = match reduce {
        DmlReduceKind::Sum => "acc".to_string(),
        DmlReduceKind::Mean => format!("acc / {reduction_count}.0f"),
        DmlReduceKind::Max => "saw_nan ? NAN : best".to_string(),
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
pub fn emit_msl(plan: &DmlOpPlan) -> DmlResult<String> {
    plan.validate()?;
    match &plan.kind {
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
        DmlOpKind::Reduce { reduce, axes } => emit_reduce_msl(plan, *reduce, axes),
        DmlOpKind::Reshape => emit_reshape_msl(plan),
        DmlOpKind::Transpose { permutation } => emit_transpose_msl(plan, permutation),
        DmlOpKind::Concat { axis } => emit_concat_msl(plan, *axis),
        DmlOpKind::Slice {
            offsets,
            sizes,
            strides,
        } => emit_slice_msl(plan, offsets, sizes, strides),
    }
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
    let required_output = plan.output.total_size_in_bytes as usize;
    if output.len() < required_output {
        return Err(DmlError::invalid(format!(
            "output buffer is {} bytes, tensor requires {required_output}",
            output.len()
        )));
    }
    match backend {
        DmlExecutionDevice::Metal => execute_metal(plan, inputs, output),
        DmlExecutionDevice::Cpu => execute_cpu(plan, inputs, output),
    }
}

fn execute_metal(plan: &DmlOpPlan, inputs: &[&[u8]], output: &mut [u8]) -> DmlResult<()> {
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
    let output_length = plan.output.total_size_in_bytes as usize;
    let output_buffer = device.create_buffer(
        output_length as u64,
        metal::MTLResourceOptions::StorageModeShared,
    );
    let command_buffer = queue.new_command_buffer();
    {
        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&pipeline);
        for (index, buffer) in input_buffers.iter().enumerate() {
            encoder.set_buffer(index as u64, Some(buffer), 0);
        }
        encoder.set_buffer(input_buffers.len() as u64, Some(&output_buffer), 0);
        let count = plan.output.element_count();
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
    let contents =
        unsafe { std::slice::from_raw_parts(output_buffer.contents() as *const u8, output_length) };
    output[..output_length].copy_from_slice(contents);
    Ok(())
}

// ---------------------------------------------------------------------------
// CPU execution (only for an explicit CPU device)
// ---------------------------------------------------------------------------

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
        _ => 0.0,
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

fn execute_cpu(plan: &DmlOpPlan, inputs: &[&[u8]], output: &mut [u8]) -> DmlResult<()> {
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
                let value = match activation {
                    DmlActivation::Relu => value.max(0.0),
                    DmlActivation::LeakyRelu => {
                        if value >= 0.0 {
                            value
                        } else {
                            value * alpha
                        }
                    }
                    DmlActivation::Sigmoid => 1.0 / (1.0 + (-value).exp()),
                    DmlActivation::Tanh => value.tanh(),
                };
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
                let mut sum = 0.0f64;
                let mut best = f32::NEG_INFINITY;
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
                        DmlReduceKind::Sum | DmlReduceKind::Mean => sum += value as f64,
                        DmlReduceKind::Max => {
                            if !value.is_nan() {
                                best = best.max(value);
                            }
                        }
                    }
                }
                let value = match reduce {
                    DmlReduceKind::Sum => sum as f32,
                    DmlReduceKind::Mean => (sum / reduction_count as f64) as f32,
                    DmlReduceKind::Max => {
                        if saw_nan {
                            f32::NAN
                        } else {
                            best
                        }
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
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::d3d12::directml::DML_TENSOR_DATA_TYPE_UINT8;

    fn tensor(data_type: u32, sizes: &[u32], strides: Option<&[u32]>) -> DmlTensorDesc {
        let element_size = match data_type {
            DML_TENSOR_DATA_TYPE_FLOAT16 => 2,
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
            total_size_in_bytes: implied * element_size,
            guaranteed_base_offset_alignment: 0,
        }
    }

    fn plan(kind: DmlOpKind, inputs: Vec<DmlTensorDesc>, output: DmlTensorDesc) -> DmlOpPlan {
        DmlOpPlan {
            kind,
            inputs,
            output,
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
        let leaky = activation_plan(&activation_input, DmlActivation::LeakyRelu, 0.1);
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
}
