//! DML operator test suite.

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
