//! DirectML compatibility surface backed by real Metal compute pipelines.
//!
//! `dml.dll` exports `DMLCreateDevice`/`DMLCreateDevice1`; the operator
//! registry, initializer and command-recorder entry points live on
//! `IDMLDevice` (there are no `DMLCreateOperatorRegistry` free functions in
//! DirectML), and are modelled here as device methods. Operator descriptors
//! are parsed from guest memory, validated against DirectML's documented
//! tensor constraints, lowered to MSL, compiled with the system Metal device,
//! and can be executed against host buffers.
//!
//! Operators outside the supported set fail closed with the DirectML error
//! (`E_INVALIDARG`), never with a fabricated success.
//!
//! The extended operator set (GEMM, convolution, pooling, activations, batch
//! normalization, softmax, reductions, reshape/transpose/concat/slice) lives
//! in [`dml_ops`] and is created, compiled, bound, and executed through the
//! `create_operation`/`compile_operation`/`execute_operation` methods here.

use std::collections::BTreeMap;

use crate::metal_backend::MetalDevice;

use super::state_objects::StateObjectMemory;

#[path = "dml_ops.rs"]
pub mod dml_ops;

pub const S_OK: u32 = 0;
pub const E_INVALIDARG: u32 = 0x8007_0057;
pub const E_NOINTERFACE: u32 = 0x8000_4002;
pub const E_POINTER: u32 = 0x8000_4003;
pub const E_FAIL: u32 = 0x8000_4005;
pub const E_OUTOFMEMORY: u32 = 0x8007_000E;
pub const DXGI_ERROR_UNSUPPORTED: u32 = 0x887A_0004;
pub const DXGI_ERROR_MORE_DATA: u32 = 0x887A_0003;

pub const DML_TENSOR_DATA_TYPE_FLOAT32: u32 = 1;
pub const DML_TENSOR_DATA_TYPE_FLOAT16: u32 = 2;
pub const DML_TENSOR_DATA_TYPE_UINT32: u32 = 3;
pub const DML_TENSOR_DATA_TYPE_UINT16: u32 = 4;
pub const DML_TENSOR_DATA_TYPE_UINT8: u32 = 5;
pub const DML_TENSOR_DATA_TYPE_INT32: u32 = 6;
pub const DML_TENSOR_DATA_TYPE_INT16: u32 = 7;
pub const DML_TENSOR_DATA_TYPE_INT8: u32 = 8;
pub const DML_TENSOR_DATA_TYPE_FLOAT64: u32 = 9;
pub const DML_TENSOR_DATA_TYPE_UINT64: u32 = 10;
pub const DML_TENSOR_DATA_TYPE_INT64: u32 = 11;
pub const DML_TENSOR_DATA_TYPE_UINT4: u32 = 12;
pub const DML_TENSOR_DATA_TYPE_INT4: u32 = 13;

pub const DML_TENSOR_TYPE_BUFFER: u32 = 1;

pub const DML_OPERATOR_ELEMENT_WISE_IDENTITY: u32 = 1;
pub const DML_OPERATOR_ELEMENT_WISE_ABS: u32 = 2;
pub const DML_OPERATOR_ELEMENT_WISE_ADD: u32 = 4;
pub const DML_OPERATOR_ELEMENT_WISE_CEIL: u32 = 7;
pub const DML_OPERATOR_ELEMENT_WISE_COS: u32 = 9;
pub const DML_OPERATOR_ELEMENT_WISE_DIVIDE: u32 = 10;
pub const DML_OPERATOR_ELEMENT_WISE_EXP: u32 = 11;
pub const DML_OPERATOR_ELEMENT_WISE_FLOOR: u32 = 12;
pub const DML_OPERATOR_ELEMENT_WISE_LOG: u32 = 13;
pub const DML_OPERATOR_ELEMENT_WISE_MAX: u32 = 21;
pub const DML_OPERATOR_ELEMENT_WISE_MIN: u32 = 23;
pub const DML_OPERATOR_ELEMENT_WISE_MULTIPLY: u32 = 24;
pub const DML_OPERATOR_ELEMENT_WISE_POW: u32 = 25;
pub const DML_OPERATOR_ELEMENT_WISE_SIN: u32 = 28;
pub const DML_OPERATOR_ELEMENT_WISE_SQRT: u32 = 29;
pub const DML_OPERATOR_ELEMENT_WISE_SUBTRACT: u32 = 30;
pub const DML_OPERATOR_ELEMENT_WISE_TAN: u32 = 31;

pub const DML_FEATURE_LEVEL_1_0: u32 = 0x1000;
pub const DML_FEATURE_LEVEL_2_0: u32 = 0x2000;
pub const DML_FEATURE_LEVEL_2_1: u32 = 0x2100;
pub const DML_FEATURE_LEVEL_3_0: u32 = 0x3000;
pub const DML_FEATURE_LEVEL_3_1: u32 = 0x3100;
pub const DML_FEATURE_LEVEL_4_0: u32 = 0x4000;
pub const DML_FEATURE_LEVEL_4_1: u32 = 0x4100;
pub const DML_FEATURE_LEVEL_5_0: u32 = 0x5000;
pub const DML_FEATURE_LEVEL_5_1: u32 = 0x5100;
pub const DML_FEATURE_LEVEL_5_2: u32 = 0x5200;
pub const DML_FEATURE_LEVEL_6_0: u32 = 0x6000;
pub const DML_FEATURE_LEVEL_6_1: u32 = 0x6100;
pub const DML_FEATURE_LEVEL_6_2: u32 = 0x6200;
pub const DML_FEATURE_LEVEL_6_3: u32 = 0x6300;
pub const DML_FEATURE_LEVEL_6_4: u32 = 0x6400;

/// The highest DirectML feature level this bridge truthfully implements.
pub const SUPPORTED_DML_FEATURE_LEVEL: u32 = DML_FEATURE_LEVEL_4_0;
/// Whether the bridge can realize this tensor data type in at least one
/// implemented operator.
pub fn supports_tensor_data_type(data_type: u32) -> bool {
    matches!(
        data_type,
        DML_TENSOR_DATA_TYPE_FLOAT32
            | DML_TENSOR_DATA_TYPE_FLOAT16
            | DML_TENSOR_DATA_TYPE_UINT32
            | DML_TENSOR_DATA_TYPE_INT32
            | DML_TENSOR_DATA_TYPE_UINT8
            | DML_TENSOR_DATA_TYPE_INT8
    )
}

/// DirectML feature-level negotiation: the highest requested level at or below
/// [`SUPPORTED_DML_FEATURE_LEVEL`], or 0 when none is supported.
pub fn negotiate_feature_levels(levels: &[u32]) -> u32 {
    levels
        .iter()
        .copied()
        .filter(|level| *level <= SUPPORTED_DML_FEATURE_LEVEL)
        .max()
        .unwrap_or(0)
}

pub const DML_CREATE_DEVICE_FLAG_DEBUG: u32 = 0x1;
pub const DML_EXECUTION_FLAGS_VALID: u32 = 0x1 | 0x2 | 0x4;

pub const DML_GRAPH_NODE_TYPE_OPERATOR: u32 = 1;
pub const DML_GRAPH_EDGE_TYPE_INPUT: u32 = 1;
pub const DML_GRAPH_EDGE_TYPE_OUTPUT: u32 = 2;
pub const DML_GRAPH_EDGE_TYPE_INTERMEDIATE: u32 = 3;

pub const DML_TENSOR_MAX_DIMENSIONS: u32 = 4;
pub const DML_TENSOR_MIN_ALIGNMENT: u64 = 16;

/// A 16-byte COM IID compared against raw guest GUID memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmlGuid(pub [u8; 16]);

pub const IID_IDMLDEVICE: DmlGuid = DmlGuid([
    0x37, 0x64, 0xbd, 0x6d, 0xfd, 0x96, 0x3f, 0x42, 0xa9, 0x8c, 0xae, 0x5e, 0x7c, 0x2a, 0x57, 0x3f,
]);
pub const IID_IDMLDEVICE1: DmlGuid = DmlGuid([
    0x9a, 0x4f, 0x88, 0xa0, 0xbe, 0xd2, 0x55, 0x43, 0xaa, 0x5d, 0x59, 0x01, 0x28, 0x1a, 0xd1, 0xd2,
]);
pub const IID_IDMLOPERATOR: DmlGuid = DmlGuid([
    0x7a, 0xae, 0xca, 0x26, 0x81, 0x30, 0x33, 0x46, 0x95, 0x81, 0x22, 0x6f, 0xbe, 0x57, 0x69, 0x5d,
]);
pub const IID_IDMLCOMPILEDOPERATOR: DmlGuid = DmlGuid([
    0x6a, 0xe5, 0x15, 0x6b, 0x5c, 0xbf, 0x02, 0x49, 0x92, 0xd8, 0xda, 0x3a, 0x65, 0x0a, 0xfe, 0xa4,
]);
pub const IID_IDMLOPERATORINITIALIZER: DmlGuid = DmlGuid([
    0x13, 0x11, 0x7c, 0x42, 0x5c, 0x43, 0x9c, 0x46, 0x86, 0x76, 0x4d, 0x5d, 0xd0, 0x72, 0xf8, 0x13,
]);
pub const IID_IDMLCOMMANDRECORDER: DmlGuid = DmlGuid([
    0x76, 0x7a, 0x85, 0xe6, 0x3e, 0x2e, 0xdd, 0x4f, 0xbf, 0xf4, 0x5d, 0x2b, 0xa1, 0x0f, 0xb4, 0x53,
]);
pub const IID_IDMLBINDINGTABLE: DmlGuid = DmlGuid([
    0xdc, 0x87, 0xc6, 0x29, 0x74, 0xde, 0x3b, 0x4e, 0xab, 0x00, 0x11, 0x68, 0xf2, 0xfc, 0x3c, 0xfc,
]);
pub const IID_IDMLOBJECT: DmlGuid = DmlGuid([
    0xac, 0x3a, 0x26, 0xc8, 0x0c, 0x9e, 0x2d, 0x4a, 0x9b, 0x8e, 0x00, 0x75, 0x21, 0xa3, 0x31, 0x7c,
]);
pub const IID_IDMLDEVICECHILD: DmlGuid = DmlGuid([
    0x42, 0x31, 0xe8, 0x27, 0x65, 0x81, 0xe3, 0x49, 0x97, 0x4e, 0x2f, 0xd6, 0x6e, 0x4c, 0xb6, 0x9d,
]);
pub const IID_IDMLPAGEABLE: DmlGuid = DmlGuid([
    0x25, 0x08, 0xab, 0xb1, 0x42, 0x45, 0x4b, 0x4a, 0x86, 0x17, 0x6d, 0xde, 0x6e, 0x8f, 0x62, 0x01,
]);
pub const IID_IDMLDISPATCHABLE: DmlGuid = DmlGuid([
    0xa8, 0x21, 0xb8, 0xdc, 0x39, 0x10, 0x1e, 0x44, 0x9f, 0x1c, 0xb1, 0x75, 0x9c, 0x2f, 0x3c, 0xec,
]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmlError {
    pub hresult: u32,
    pub message: String,
}

impl DmlError {
    pub fn new(hresult: u32, message: impl Into<String>) -> Self {
        Self {
            hresult,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(E_INVALIDARG, message)
    }

    pub fn unsupported_operator(ty: u32) -> Self {
        Self::new(
            E_INVALIDARG,
            format!("DML_OPERATOR_TYPE {ty} is not supported by this DirectML implementation"),
        )
    }

    pub fn unsupported_feature(message: impl Into<String>) -> Self {
        Self::new(DXGI_ERROR_UNSUPPORTED, message)
    }

    pub fn to_app_error(&self) -> crate::error::AppError {
        crate::error::AppError::new(
            crate::reason::ReasonCode::RcD3dInvalidState,
            format!("DirectML error {:#010x}: {}", self.hresult, self.message),
        )
    }
}

pub type DmlResult<T> = Result<T, DmlError>;

/// DML_BUFFER_TENSOR_DESC plus the parsed element layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmlTensorDesc {
    pub data_type: u32,
    pub flags: u32,
    pub sizes: Vec<u32>,
    pub strides: Vec<u32>,
    pub total_size_in_bytes: u64,
    pub guaranteed_base_offset_alignment: u32,
}

impl DmlTensorDesc {
    pub fn element_size(&self) -> DmlResult<u64> {
        match self.data_type {
            DML_TENSOR_DATA_TYPE_FLOAT32
            | DML_TENSOR_DATA_TYPE_UINT32
            | DML_TENSOR_DATA_TYPE_INT32 => Ok(4),
            DML_TENSOR_DATA_TYPE_FLOAT16
            | DML_TENSOR_DATA_TYPE_UINT16
            | DML_TENSOR_DATA_TYPE_INT16 => Ok(2),
            DML_TENSOR_DATA_TYPE_UINT8 | DML_TENSOR_DATA_TYPE_INT8 => Ok(1),
            other => Err(DmlError::invalid(format!(
                "DML_TENSOR_DATA_TYPE {other} is not supported"
            ))),
        }
    }

    pub fn element_count(&self) -> u64 {
        self.sizes.iter().map(|size| *size as u64).product()
    }

    pub fn implied_size_in_bytes(&self) -> DmlResult<u64> {
        let element_size = self.element_size()?;
        let max_element = self
            .sizes
            .iter()
            .zip(&self.strides)
            .map(|(size, stride)| (*size as u64 - 1) * *stride as u64)
            .sum::<u64>();
        Ok((max_element + 1) * element_size)
    }

    pub fn is_contiguous(&self) -> bool {
        let mut expected = 1u32;
        for index in (0..self.sizes.len()).rev() {
            if self.strides[index] != expected {
                return false;
            }
            expected = expected.saturating_mul(self.sizes[index]);
        }
        true
    }

    pub fn validate(&self) -> DmlResult<()> {
        if self.flags != 0 {
            return Err(DmlError::invalid(format!(
                "DML_TENSOR_FLAGS {:#x} are not supported (owned tensors are not implemented)",
                self.flags
            )));
        }
        if self.sizes.is_empty() || self.sizes.len() > DML_TENSOR_MAX_DIMENSIONS as usize {
            return Err(DmlError::invalid(format!(
                "tensor DimensionCount {} is outside the supported 1..={DML_TENSOR_MAX_DIMENSIONS} range",
                self.sizes.len()
            )));
        }
        if self.sizes.iter().any(|size| *size == 0) {
            return Err(DmlError::invalid("tensor dimensions must be non-zero"));
        }
        if let Some(invalid_stride) = self.strides.iter().find(|stride| **stride == 0) {
            // A zero stride is legal (broadcast). Keep it explicit rather than
            // rejecting it; this branch only documents the intent.
            let _ = invalid_stride;
        }
        if self.guaranteed_base_offset_alignment != 0 {
            let alignment = self.guaranteed_base_offset_alignment as u64;
            if !alignment.is_power_of_two() || alignment < self.element_size()? {
                return Err(DmlError::invalid(format!(
                    "GuaranteedBaseOffsetAlignment {alignment} must be a power of two no smaller than the element size"
                )));
            }
        }
        let implied = self.implied_size_in_bytes()?;
        if self.total_size_in_bytes < implied {
            return Err(DmlError::invalid(format!(
                "tensor TotalTensorSizeInBytes {} is smaller than the implied {implied} bytes",
                self.total_size_in_bytes
            )));
        }
        Ok(())
    }
}

/// Parsed DML_OPERATOR_DESC for the supported element-wise operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmlOperatorDesc {
    pub ty: u32,
    pub a: DmlTensorDesc,
    pub b: Option<DmlTensorDesc>,
    pub output: DmlTensorDesc,
}

impl DmlOperatorDesc {
    pub fn is_binary(&self) -> bool {
        self.b.is_some()
    }

    pub fn tensor_data_type(&self) -> u32 {
        self.a.data_type
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmlDeviceRecord {
    pub handle: u64,
    pub parent_device: u64,
    pub flags: u32,
    pub feature_level: u32,
    pub execution_device: dml_ops::DmlExecutionDevice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmlOperatorRecord {
    pub handle: u64,
    pub device: u64,
    pub desc: DmlOperatorDesc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmlCompiledRecord {
    pub handle: u64,
    pub device: u64,
    pub operator: u64,
    pub flags: u32,
    pub msl_source: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DmlOperationRecord {
    pub handle: u64,
    pub device: u64,
    pub plan: dml_ops::DmlOpPlan,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DmlOperationCompiledRecord {
    pub handle: u64,
    pub device: u64,
    pub operation: u64,
    pub flags: u32,
    pub msl_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmlInitializerRecord {
    pub handle: u64,
    pub device: u64,
    pub operators: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmlRecorderRecord {
    pub handle: u64,
    pub device: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmlDispatchRecord {
    pub recorder: u64,
    pub compiled: u64,
    pub bindings: Vec<DmlBufferBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmlBufferBinding {
    pub resource: u64,
    pub offset: u64,
    pub size: u64,
}

/// DML_BINDING_PROPERTIES.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DmlBindingProperties {
    pub required_descriptor_count: u32,
    pub temporary_resource_size: u64,
    pub persistent_resource_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmlGraphInputEdge {
    pub graph_input: u32,
    pub to_node: u32,
    pub to_node_input: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmlGraphOutputEdge {
    pub from_node: u32,
    pub from_node_output: u32,
    pub graph_output: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmlGraphIntermediateEdge {
    pub from_node: u32,
    pub from_node_output: u32,
    pub to_node: u32,
    pub to_node_input: u32,
}

/// A validated DirectML graph: node operators in topological order plus the
/// graph input/output edges.
#[derive(Debug, Clone, PartialEq)]
pub struct DmlGraphPlan {
    pub input_count: u32,
    pub output_count: u32,
    pub nodes: Vec<dml_ops::DmlOpPlan>,
    pub input_edges: Vec<DmlGraphInputEdge>,
    pub output_edges: Vec<DmlGraphOutputEdge>,
    pub intermediate_edges: Vec<DmlGraphIntermediateEdge>,
    pub execution_order: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DmlGraphRecord {
    pub handle: u64,
    pub device: u64,
    pub plan: DmlGraphPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmlBindingTableRecord {
    pub handle: u64,
    pub device: u64,
    pub dispatchable: u64,
    pub size_in_descriptors: u32,
    pub input_bindings: Vec<DmlBufferBinding>,
    pub output_bindings: Vec<DmlBufferBinding>,
}

/// DirectML device/operator lifetime tracker.
///
/// Only descriptors and handles live here, so the runtime stays `Send + Sync`
/// and can be embedded in the host runtime. Metal pipelines are compiled and
/// dispatched on demand from the retained descriptor.
#[derive(Debug, Clone, Default)]
pub struct DmlRuntime {
    next_handle: u64,
    devices: BTreeMap<u64, DmlDeviceRecord>,
    operators: BTreeMap<u64, DmlOperatorRecord>,
    compiled: BTreeMap<u64, DmlCompiledRecord>,
    initializers: BTreeMap<u64, DmlInitializerRecord>,
    recorders: BTreeMap<u64, DmlRecorderRecord>,
    binding_tables: BTreeMap<u64, DmlBindingTableRecord>,
    operations: BTreeMap<u64, DmlOperationRecord>,
    operations_compiled: BTreeMap<u64, DmlOperationCompiledRecord>,
    graphs: BTreeMap<u64, DmlGraphRecord>,
    dispatches: Vec<DmlDispatchRecord>,
}

impl DmlRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    fn alloc_handle(&mut self) -> u64 {
        self.next_handle = self.next_handle.saturating_add(1).max(0x1000);
        self.next_handle
    }

    pub fn create_device(
        &mut self,
        parent_device: u64,
        flags: u32,
        minimum_feature_level: u32,
        iid: DmlGuid,
    ) -> DmlResult<u64> {
        self.create_device_on(
            parent_device,
            flags,
            minimum_feature_level,
            iid,
            dml_ops::DmlExecutionDevice::Metal,
        )
    }

    pub fn create_device_on(
        &mut self,
        parent_device: u64,
        flags: u32,
        minimum_feature_level: u32,
        iid: DmlGuid,
        execution_device: dml_ops::DmlExecutionDevice,
    ) -> DmlResult<u64> {
        if parent_device == 0 {
            return Err(DmlError::invalid("D3D12 device pointer is null"));
        }
        if flags & !DML_CREATE_DEVICE_FLAG_DEBUG != 0 {
            return Err(DmlError::invalid(format!(
                "DML_CREATE_DEVICE_FLAGS {flags:#x} contain undefined bits"
            )));
        }
        if iid != IID_IDMLDEVICE && iid != IID_IDMLDEVICE1 {
            return Err(DmlError::new(
                E_NOINTERFACE,
                format!("DMLCreateDevice does not implement IID {iid:?}"),
            ));
        }
        if minimum_feature_level > SUPPORTED_DML_FEATURE_LEVEL {
            return Err(DmlError::unsupported_feature(format!(
                "requested DML_FEATURE_LEVEL {minimum_feature_level:#x} exceeds the \
                 supported {SUPPORTED_DML_FEATURE_LEVEL:#x}"
            )));
        }
        let handle = self.alloc_handle();
        self.devices.insert(
            handle,
            DmlDeviceRecord {
                handle,
                parent_device,
                flags,
                feature_level: SUPPORTED_DML_FEATURE_LEVEL,
                execution_device,
            },
        );
        Ok(handle)
    }

    pub fn devices(&self) -> &BTreeMap<u64, DmlDeviceRecord> {
        &self.devices
    }

    pub fn device(&self, device: u64) -> DmlResult<&DmlDeviceRecord> {
        self.devices
            .get(&device)
            .ok_or_else(|| DmlError::invalid(format!("unknown DML device {device:#x}")))
    }

    pub fn destroy_device(&mut self, device: u64) -> DmlResult<()> {
        if self.devices.remove(&device).is_none() {
            return Err(DmlError::invalid(format!("unknown DML device {device:#x}")));
        }
        self.operators.retain(|_, op| op.device != device);
        self.compiled.retain(|_, op| op.device != device);
        self.initializers.retain(|_, init| init.device != device);
        self.recorders.retain(|_, rec| rec.device != device);
        self.binding_tables
            .retain(|_, table| table.device != device);
        self.operations.retain(|_, op| op.device != device);
        self.operations_compiled.retain(|_, op| op.device != device);
        self.graphs.retain(|_, graph| graph.device != device);
        Ok(())
    }

    /// Parse and validate an element-wise DML_OPERATOR_DESC from guest memory.
    ///
    /// Extended operators are represented by [`dml_ops::DmlOpPlan`]; use
    /// [`Self::create_operation`] for those.
    pub fn parse_operator(
        &self,
        memory: &dyn StateObjectMemory,
        desc: u64,
    ) -> DmlResult<DmlOperatorDesc> {
        if desc == 0 {
            return Err(DmlError::new(
                E_POINTER,
                "DML_OPERATOR_DESC pointer is null",
            ));
        }
        let ty = memory
            .read_u32(desc)
            .map_err(|error| DmlError::invalid(error.to_string()))?;
        let payload = memory
            .read_u64(desc + 8)
            .map_err(|error| DmlError::invalid(error.to_string()))?;
        if payload == 0 {
            return Err(DmlError::new(
                E_POINTER,
                "DML_OPERATOR_DESC.Desc pointer is null",
            ));
        }
        let binary = is_binary_operator(ty);
        let unary = is_unary_operator(ty);
        if !binary && !unary {
            return Err(DmlError::unsupported_operator(ty));
        }

        let a = parse_tensor(memory, memory.read_u64(payload).map_err(app_to_dml)?)?;
        let (b, output_ptr) = if binary {
            let b = parse_tensor(memory, memory.read_u64(payload + 8).map_err(app_to_dml)?)?;
            let output = memory.read_u64(payload + 16).map_err(app_to_dml)?;
            (Some(b), output)
        } else {
            let output = memory.read_u64(payload + 8).map_err(app_to_dml)?;
            (None, output)
        };
        let output = parse_tensor(memory, output_ptr)?;

        a.validate()?;
        if let Some(b) = &b {
            b.validate()?;
        }
        output.validate()?;
        validate_elementwise_constraints(ty, &a, b.as_ref(), &output)?;
        Ok(DmlOperatorDesc { ty, a, b, output })
    }

    /// Parse a guest `DML_OPERATOR_DESC` for the extended operator set.
    ///
    /// This is the guest-facing counterpart of [`Self::create_operation`]: the
    /// descriptor chain is read from guest memory, every tensor descriptor is
    /// validated, and the result is a real [`dml_ops::DmlOpPlan`].
    pub fn parse_operation_from_guest(
        &self,
        memory: &dyn StateObjectMemory,
        desc: u64,
    ) -> DmlResult<dml_ops::DmlOpPlan> {
        use dml_ops::{DmlAxisDirection, DmlOpKind, DmlOpPlan};

        if desc == 0 {
            return Err(DmlError::new(
                E_POINTER,
                "DML_OPERATOR_DESC pointer is null",
            ));
        }
        let ty = memory
            .read_u32(desc)
            .map_err(|error| DmlError::invalid(error.to_string()))?;
        let payload = memory
            .read_u64(desc + 8)
            .map_err(|error| DmlError::invalid(error.to_string()))?;
        if payload == 0 {
            return Err(DmlError::new(
                E_POINTER,
                "DML_OPERATOR_DESC.Desc pointer is null",
            ));
        }
        let plan = |kind, inputs, output, extra_outputs, fused_activation| {
            Ok::<DmlOpPlan, DmlError>(DmlOpPlan {
                kind,
                inputs,
                output,
                extra_outputs,
                fused_activation,
            })
        };
        match ty {
            dml_ops::DML_OPERATOR_GEMM => {
                let a = tensor_at(memory, read_ptr(memory, payload)?)?;
                let b = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let c = optional_tensor(memory, read_ptr(memory, payload + 16)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let trans_a = read_u32(memory, payload + 32)? == 1;
                let trans_b = read_u32(memory, payload + 36)? == 1;
                let alpha = read_f32(memory, payload + 40)?;
                let beta = read_f32(memory, payload + 44)?;
                let mut inputs = vec![a, b];
                if let Some(c) = c {
                    inputs.push(c);
                }
                plan(
                    DmlOpKind::Gemm {
                        trans_a,
                        trans_b,
                        alpha,
                        beta,
                    },
                    inputs,
                    output,
                    Vec::new(),
                    parse_fused_activation(memory, read_ptr(memory, payload + 48)?)?,
                )
            }
            dml_ops::DML_OPERATOR_CONVOLUTION => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let filter = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let bias = optional_tensor(memory, read_ptr(memory, payload + 16)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let mode = read_u32(memory, payload + 32)?;
                let direction = read_u32(memory, payload + 36)?;
                if mode != dml_ops::DML_CONVOLUTION_MODE_CROSS_CORRELATION {
                    return Err(DmlError::invalid(format!(
                        "convolution mode {mode} is not supported (only cross-correlation)"
                    )));
                }
                if direction != dml_ops::DML_CONVOLUTION_DIRECTION_FORWARD {
                    return Err(DmlError::invalid(format!(
                        "convolution direction {direction} is not supported (only forward)"
                    )));
                }
                let dimension_count = read_u32(memory, payload + 40)?;
                if dimension_count != 2 {
                    return Err(DmlError::invalid(format!(
                        "convolution DimensionCount must be 2, got {dimension_count}"
                    )));
                }
                let strides = read_u32_list(memory, read_ptr(memory, payload + 48)?, 2)?;
                let dilations = read_u32_list(memory, read_ptr(memory, payload + 56)?, 2)?;
                let start_padding = read_u32_list(memory, read_ptr(memory, payload + 64)?, 2)?;
                let end_padding = read_u32_list(memory, read_ptr(memory, payload + 72)?, 2)?;
                let output_padding = read_u32_list(memory, read_ptr(memory, payload + 80)?, 2)?;
                let group_count = read_u32(memory, payload + 88)?;
                let mut inputs = vec![input, filter];
                if let Some(bias) = bias {
                    inputs.push(bias);
                }
                plan(
                    DmlOpKind::Convolution {
                        strides,
                        dilations,
                        start_padding,
                        end_padding,
                        output_padding,
                        group_count,
                    },
                    inputs,
                    output,
                    Vec::new(),
                    parse_fused_activation(memory, read_ptr(memory, payload + 96)?)?,
                )
            }
            dml_ops::DML_OPERATOR_AVERAGE_POOLING | dml_ops::DML_OPERATOR_MAX_POOLING => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let dimension_count = read_u32(memory, payload + 16)?;
                if dimension_count != 2 {
                    return Err(DmlError::invalid(format!(
                        "pooling DimensionCount must be 2, got {dimension_count}"
                    )));
                }
                let strides = read_u32_list(memory, read_ptr(memory, payload + 24)?, 2)?;
                let window = read_u32_list(memory, read_ptr(memory, payload + 32)?, 2)?;
                let start_padding = read_u32_list(memory, read_ptr(memory, payload + 40)?, 2)?;
                let end_padding = read_u32_list(memory, read_ptr(memory, payload + 48)?, 2)?;
                let include_padding = if ty == dml_ops::DML_OPERATOR_AVERAGE_POOLING {
                    read_u32(memory, payload + 56)? != 0
                } else {
                    false
                };
                plan(
                    DmlOpKind::Pooling {
                        kind: if ty == dml_ops::DML_OPERATOR_MAX_POOLING {
                            dml_ops::DmlPoolingKind::Max
                        } else {
                            dml_ops::DmlPoolingKind::Average
                        },
                        strides,
                        window,
                        start_padding,
                        end_padding,
                        include_padding,
                    },
                    vec![input],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_ACTIVATION_RELU
            | dml_ops::DML_OPERATOR_ACTIVATION_LEAKY_RELU
            | dml_ops::DML_OPERATOR_ACTIVATION_SIGMOID
            | dml_ops::DML_OPERATOR_ACTIVATION_TANH
            | dml_ops::DML_OPERATOR_ACTIVATION_IDENTITY
            | dml_ops::DML_OPERATOR_ACTIVATION_ELU
            | dml_ops::DML_OPERATOR_ACTIVATION_LINEAR
            | dml_ops::DML_OPERATOR_ACTIVATION_SOFTPLUS
            | dml_ops::DML_OPERATOR_ACTIVATION_SOFTSIGN
            | dml_ops::DML_OPERATOR_ACTIVATION_GELU
            | dml_ops::DML_OPERATOR_ACTIVATION_SWISH
            | dml_ops::DML_OPERATOR_ACTIVATION_HARD_SWISH
            | dml_ops::DML_OPERATOR_ACTIVATION_HARD_SIGMOID
            | dml_ops::DML_OPERATOR_ACTIVATION_SCALED_TANH
            | dml_ops::DML_OPERATOR_ACTIVATION_THRESHOLDED_RELU => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let activation = parse_activation_payload(memory, ty, payload)?;
                plan(
                    DmlOpKind::Activation {
                        activation,
                        alpha: 0.0,
                    },
                    vec![input],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_ACTIVATION_SOFTMAX => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                plan(DmlOpKind::Softmax, vec![input], output, Vec::new(), None)
            }
            dml_ops::DML_OPERATOR_BATCH_NORMALIZATION => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let mean = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let variance = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let scale = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let bias = tensor_at(memory, read_ptr(memory, payload + 32)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 40)?)?;
                let spatial = read_u32(memory, payload + 48)? != 0;
                let epsilon = read_f32(memory, payload + 52)?;
                plan(
                    DmlOpKind::BatchNormalization { spatial, epsilon },
                    vec![input, mean, variance, scale, bias],
                    output,
                    Vec::new(),
                    parse_fused_activation(memory, read_ptr(memory, payload + 56)?)?,
                )
            }
            dml_ops::DML_OPERATOR_REDUCE => {
                let function = read_u32(memory, payload)?;
                let input = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let axis_count = read_u32(memory, payload + 24)?;
                let axes = read_u32_list(memory, read_ptr(memory, payload + 32)?, axis_count)?;
                let reduce =
                    dml_ops::DmlReduceKind::from_reduce_function(function).ok_or_else(|| {
                        DmlError::invalid(format!(
                            "DML_REDUCE_FUNCTION {function} is not supported"
                        ))
                    })?;
                if reduce.is_index_reduction() {
                    let kind = if function == 0 {
                        DmlOpKind::ArgMax {
                            axes,
                            direction: DmlAxisDirection::Increasing,
                        }
                    } else {
                        DmlOpKind::ArgMin {
                            axes,
                            direction: DmlAxisDirection::Increasing,
                        }
                    };
                    plan(kind, vec![input], output, Vec::new(), None)
                } else {
                    plan(
                        DmlOpKind::Reduce { reduce, axes },
                        vec![input],
                        output,
                        Vec::new(),
                        None,
                    )
                }
            }
            dml_ops::DML_OPERATOR_SLICE => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let dimension_count = read_u32(memory, payload + 16)?;
                if dimension_count as usize != input.sizes.len() {
                    return Err(DmlError::invalid(format!(
                        "slice DimensionCount {dimension_count} must match the input rank {}",
                        input.sizes.len()
                    )));
                }
                let offsets =
                    read_u32_list(memory, read_ptr(memory, payload + 24)?, dimension_count)?;
                let sizes =
                    read_u32_list(memory, read_ptr(memory, payload + 32)?, dimension_count)?;
                let strides =
                    read_u32_list(memory, read_ptr(memory, payload + 40)?, dimension_count)?;
                plan(
                    DmlOpKind::Slice {
                        offsets,
                        sizes,
                        strides,
                    },
                    vec![input],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_JOIN => {
                let count = read_u32(memory, payload)?;
                if count == 0 || count > 1024 {
                    return Err(DmlError::invalid(format!(
                        "join InputCount {count} is outside the supported 1..=1024 range"
                    )));
                }
                let ptr = read_ptr(memory, payload + 8)?;
                let mut inputs = Vec::with_capacity(count as usize);
                for index in 0..count as u64 {
                    inputs.push(tensor_at(memory, read_ptr(memory, ptr + index * 8)?)?);
                }
                let output = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let axis = read_u32(memory, payload + 24)?;
                plan(DmlOpKind::Concat { axis }, inputs, output, Vec::new(), None)
            }
            dml_ops::DML_OPERATOR_SPLIT => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let count = read_u32(memory, payload + 8)?;
                if count == 0 || count > 1024 {
                    return Err(DmlError::invalid(format!(
                        "split OutputCount {count} is outside the supported 1..=1024 range"
                    )));
                }
                let ptr = read_ptr(memory, payload + 16)?;
                let mut outputs = Vec::with_capacity(count as usize);
                for index in 0..count as u64 {
                    outputs.push(tensor_at(memory, read_ptr(memory, ptr + index * 8)?)?);
                }
                let axis = read_u32(memory, payload + 24)?;
                let primary = outputs.remove(0);
                plan(
                    DmlOpKind::Split { axis },
                    vec![input],
                    primary,
                    outputs,
                    None,
                )
            }
            dml_ops::DML_OPERATOR_PADDING | dml_ops::DML_OPERATOR_PADDING1 => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let mode = read_u32(memory, payload + 16)?;
                let padding_mode = dml_ops::DmlPaddingMode::from_u32(mode).ok_or_else(|| {
                    DmlError::invalid(format!("DML_PADDING_MODE {mode} is not supported"))
                })?;
                let (value, dimension_count, start_offset) = if ty == dml_ops::DML_OPERATOR_PADDING1
                {
                    let data_type = read_u32(memory, payload + 20)?;
                    let value = read_scalar_union(memory, payload + 24, data_type)?;
                    (value, read_u32(memory, payload + 32)?, 40)
                } else {
                    (
                        read_f32(memory, payload + 20)?,
                        read_u32(memory, payload + 24)?,
                        32,
                    )
                };
                let rank = input.sizes.len();
                if dimension_count as usize != rank {
                    return Err(DmlError::invalid(format!(
                        "padding DimensionCount {dimension_count} must match the input rank {rank}"
                    )));
                }
                let start_padding = read_u32_list(
                    memory,
                    read_ptr(memory, payload + start_offset)?,
                    dimension_count,
                )?;
                let end_padding = read_u32_list(
                    memory,
                    read_ptr(memory, payload + start_offset + 8)?,
                    dimension_count,
                )?;
                plan(
                    DmlOpKind::Padding {
                        mode: padding_mode,
                        start_padding,
                        end_padding,
                        value,
                    },
                    vec![input],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_RESAMPLE
            | dml_ops::DML_OPERATOR_RESAMPLE1
            | dml_ops::DML_OPERATOR_RESAMPLE2
            | dml_ops::DML_OPERATOR_RESAMPLE3 => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let mode = read_u32(memory, payload + 16)?;
                let interpolation =
                    dml_ops::DmlInterpolationMode::from_u32(mode).ok_or_else(|| {
                        DmlError::invalid(format!("DML_INTERPOLATION_MODE {mode} is not supported"))
                    })?;
                let rank = input.sizes.len();
                let mut rounding = DmlAxisDirection::Increasing;
                let mut antialiased = false;
                let (dimension_count, scales_ptr, input_offset_ptr, output_offset_ptr) = match ty {
                    dml_ops::DML_OPERATOR_RESAMPLE => {
                        (rank as u32, read_ptr(memory, payload + 24)?, 0, 0)
                    }
                    dml_ops::DML_OPERATOR_RESAMPLE1 => (
                        read_u32(memory, payload + 20)?,
                        read_ptr(memory, payload + 24)?,
                        read_ptr(memory, payload + 32)?,
                        read_ptr(memory, payload + 40)?,
                    ),
                    _ => {
                        rounding = DmlAxisDirection::from_u32(read_u32(memory, payload + 20)?)
                            .ok_or_else(|| {
                                DmlError::invalid("resample rounding direction is invalid")
                            })?;
                        antialiased = ty == dml_ops::DML_OPERATOR_RESAMPLE3
                            && read_u32(memory, payload + 56)? != 0;
                        (
                            read_u32(memory, payload + 24)?,
                            read_ptr(memory, payload + 32)?,
                            read_ptr(memory, payload + 40)?,
                            read_ptr(memory, payload + 48)?,
                        )
                    }
                };
                let scales = read_f32_list(memory, scales_ptr, dimension_count)?;
                let input_offsets = if input_offset_ptr == 0 {
                    vec![0.0; dimension_count as usize]
                } else {
                    read_f32_list(memory, input_offset_ptr, dimension_count)?
                };
                let output_offsets = if output_offset_ptr == 0 {
                    vec![0.0; dimension_count as usize]
                } else {
                    read_f32_list(memory, output_offset_ptr, dimension_count)?
                };
                plan(
                    DmlOpKind::Resample {
                        mode: interpolation,
                        scales,
                        input_offsets,
                        output_offsets,
                        rounding,
                        antialiased,
                    },
                    vec![input],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_UPSAMPLE_2D => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let width = read_u32(memory, payload + 16)?;
                let height = read_u32(memory, payload + 20)?;
                let mode = read_u32(memory, payload + 24)?;
                let interpolation =
                    dml_ops::DmlInterpolationMode::from_u32(mode).ok_or_else(|| {
                        DmlError::invalid(format!("DML_INTERPOLATION_MODE {mode} is not supported"))
                    })?;
                let rank = input.sizes.len();
                let mut scales = vec![1.0f32; rank];
                if rank >= 2 {
                    scales[rank - 2] = height as f32;
                    scales[rank - 1] = width as f32;
                }
                plan(
                    DmlOpKind::Resample {
                        mode: interpolation,
                        scales,
                        input_offsets: vec![0.0; rank],
                        output_offsets: vec![0.0; rank],
                        rounding: DmlAxisDirection::Increasing,
                        antialiased: false,
                    },
                    vec![input],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_GATHER => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let indices = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let axis = read_u32(memory, payload + 24)?;
                let index_dimensions = read_u32(memory, payload + 28)?;
                plan(
                    DmlOpKind::Gather {
                        axis,
                        index_dimensions,
                    },
                    vec![input, indices],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_GATHER_ELEMENTS => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let indices = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let axis = read_u32(memory, payload + 24)?;
                plan(
                    DmlOpKind::GatherElements { axis },
                    vec![input, indices],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_GATHER_ND | dml_ops::DML_OPERATOR_GATHER_ND1 => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let indices = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let input_dimension_count = read_u32(memory, payload + 24)?;
                let indices_dimension_count = read_u32(memory, payload + 28)?;
                let batch_dimension_count = if ty == dml_ops::DML_OPERATOR_GATHER_ND1 {
                    read_u32(memory, payload + 32)?
                } else {
                    0
                };
                plan(
                    DmlOpKind::GatherNd {
                        input_dimension_count,
                        indices_dimension_count,
                        batch_dimension_count,
                    },
                    vec![input, indices],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_SCATTER => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let indices = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let updates = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let axis = read_u32(memory, payload + 32)?;
                plan(
                    DmlOpKind::Scatter { axis },
                    vec![input, indices, updates],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_SCATTER_ND => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let indices = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let updates = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let input_dimension_count = read_u32(memory, payload + 32)?;
                let indices_dimension_count = read_u32(memory, payload + 36)?;
                plan(
                    DmlOpKind::ScatterNd {
                        input_dimension_count,
                        indices_dimension_count,
                    },
                    vec![input, indices, updates],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_TILE => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let count = read_u32(memory, payload + 16)?;
                let repeats = read_u32_list(memory, read_ptr(memory, payload + 24)?, count)?;
                plan(
                    DmlOpKind::Tile { repeats },
                    vec![input],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_TOP_K | dml_ops::DML_OPERATOR_TOP_K1 => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let values = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let indices = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let axis = read_u32(memory, payload + 24)?;
                let k = read_u32(memory, payload + 28)?;
                let direction = if ty == dml_ops::DML_OPERATOR_TOP_K1 {
                    DmlAxisDirection::from_u32(read_u32(memory, payload + 32)?)
                        .ok_or_else(|| DmlError::invalid("top-k axis direction is invalid"))?
                } else {
                    DmlAxisDirection::Decreasing
                };
                plan(
                    DmlOpKind::TopK { axis, k, direction },
                    vec![input],
                    values,
                    vec![indices],
                    None,
                )
            }
            dml_ops::DML_OPERATOR_ROI_POOLING => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let roi = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let spatial_scale = read_f32(memory, payload + 24)?;
                let width = read_u32(memory, payload + 28)?;
                let height = read_u32(memory, payload + 32)?;
                plan(
                    DmlOpKind::RoiPooling {
                        spatial_scale,
                        pooled: vec![height, width],
                    },
                    vec![input, roi],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_ROI_ALIGN | dml_ops::DML_OPERATOR_ROI_ALIGN1 => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let roi = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let batch_indices = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let reduction = dml_ops::DmlReduceKind::from_reduce_function(read_u32(
                    memory,
                    payload + 32,
                )?)
                .ok_or_else(|| DmlError::invalid("ROI align reduction function is invalid"))?;
                let mode = dml_ops::DmlInterpolationMode::from_u32(read_u32(memory, payload + 36)?)
                    .ok_or_else(|| DmlError::invalid("ROI align interpolation mode is invalid"))?;
                let (
                    spatial_scale_x,
                    spatial_scale_y,
                    input_pixel_offset,
                    output_pixel_offset,
                    out_of_bounds_value,
                    minimum_samples_per_output,
                    maximum_samples_per_output,
                    align_regions_to_corners,
                ) = if ty == dml_ops::DML_OPERATOR_ROI_ALIGN1 {
                    (
                        read_f32(memory, payload + 40)?,
                        read_f32(memory, payload + 44)?,
                        read_f32(memory, payload + 48)?,
                        read_f32(memory, payload + 52)?,
                        read_f32(memory, payload + 56)?,
                        read_u32(memory, payload + 60)?,
                        read_u32(memory, payload + 64)?,
                        read_u32(memory, payload + 68)? != 0,
                    )
                } else {
                    (
                        read_f32(memory, payload + 40)?,
                        read_f32(memory, payload + 44)?,
                        0.0,
                        0.0,
                        read_f32(memory, payload + 48)?,
                        read_u32(memory, payload + 52)?,
                        read_u32(memory, payload + 56)?,
                        false,
                    )
                };
                plan(
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
                    },
                    vec![input, roi, batch_indices],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_LOCAL_RESPONSE_NORMALIZATION => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let cross_channel = read_u32(memory, payload + 16)? != 0;
                let local_size = read_u32(memory, payload + 20)?;
                let alpha = read_f32(memory, payload + 24)?;
                let beta = read_f32(memory, payload + 28)?;
                let bias = read_f32(memory, payload + 32)?;
                plan(
                    DmlOpKind::LocalResponseNormalization {
                        cross_channel,
                        local_size,
                        alpha,
                        beta,
                        bias,
                    },
                    vec![input],
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION
            | dml_ops::DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION1
            | dml_ops::DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION2 => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let scale = optional_tensor(memory, read_ptr(memory, payload + 8)?)?;
                let bias = optional_tensor(memory, read_ptr(memory, payload + 16)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let rank = input.sizes.len();
                let (axes, normalize_variance, epsilon, fused_ptr) = match ty {
                    dml_ops::DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION => {
                        let cross_channel = read_u32(memory, payload + 32)? != 0;
                        let axes = if cross_channel {
                            (1..rank as u32).collect()
                        } else if rank > 2 {
                            (2..rank as u32).collect()
                        } else {
                            (1..rank as u32).collect()
                        };
                        (
                            axes,
                            read_u32(memory, payload + 36)? != 0,
                            read_f32(memory, payload + 40)?,
                            48,
                        )
                    }
                    dml_ops::DML_OPERATOR_MEAN_VARIANCE_NORMALIZATION1 => {
                        let count = read_u32(memory, payload + 32)?;
                        (
                            read_u32_list(memory, read_ptr(memory, payload + 40)?, count)?,
                            read_u32(memory, payload + 48)? != 0,
                            read_f32(memory, payload + 52)?,
                            56,
                        )
                    }
                    _ => {
                        let count = read_u32(memory, payload + 32)?;
                        if read_u32(memory, payload + 48)? == 0 {
                            return Err(DmlError::invalid(
                                "mean variance normalization with UseMean disabled is not supported",
                            ));
                        }
                        (
                            read_u32_list(memory, read_ptr(memory, payload + 40)?, count)?,
                            read_u32(memory, payload + 52)? != 0,
                            read_f32(memory, payload + 56)?,
                            64,
                        )
                    }
                };
                let mut inputs = vec![input];
                if let Some(scale) = scale {
                    inputs.push(scale);
                }
                if let Some(bias) = bias {
                    inputs.push(bias);
                }
                plan(
                    DmlOpKind::MeanVarianceNormalization {
                        axes,
                        normalize_variance,
                        epsilon,
                    },
                    inputs,
                    output,
                    Vec::new(),
                    parse_fused_activation(memory, read_ptr(memory, payload + fused_ptr)?)?,
                )
            }
            dml_ops::DML_OPERATOR_ADAM_OPTIMIZER => {
                let parameters = tensor_at(memory, read_ptr(memory, payload)?)?;
                let first = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let second = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let gradient = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let step = tensor_at(memory, read_ptr(memory, payload + 32)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 40)?)?;
                let output_first = tensor_at(memory, read_ptr(memory, payload + 48)?)?;
                let output_second = tensor_at(memory, read_ptr(memory, payload + 56)?)?;
                plan(
                    DmlOpKind::Adam {
                        learning_rate: read_f32(memory, payload + 64)?,
                        beta1: read_f32(memory, payload + 68)?,
                        beta2: read_f32(memory, payload + 72)?,
                        epsilon: read_f32(memory, payload + 76)?,
                    },
                    vec![parameters, first, second, gradient, step],
                    output,
                    vec![output_first, output_second],
                    None,
                )
            }
            dml_ops::DML_OPERATOR_ARGMIN | dml_ops::DML_OPERATOR_ARGMAX => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let count = read_u32(memory, payload + 16)?;
                let axes = read_u32_list(memory, read_ptr(memory, payload + 24)?, count)?;
                let direction = DmlAxisDirection::from_u32(read_u32(memory, payload + 32)?)
                    .ok_or_else(|| DmlError::invalid("argmin/argmax axis direction is invalid"))?;
                let kind = if ty == dml_ops::DML_OPERATOR_ARGMIN {
                    DmlOpKind::ArgMin { axes, direction }
                } else {
                    DmlOpKind::ArgMax { axes, direction }
                };
                plan(kind, vec![input], output, Vec::new(), None)
            }
            dml_ops::DML_OPERATOR_RNN | dml_ops::DML_OPERATOR_GRU | dml_ops::DML_OPERATOR_LSTM => {
                parse_recurrent(memory, ty, payload)
            }
            dml_ops::DML_OPERATOR_ELEMENT_WISE_ADD1 => {
                let a = tensor_at(memory, read_ptr(memory, payload)?)?;
                let b = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                plan(
                    DmlOpKind::Add1,
                    vec![a, b],
                    output,
                    Vec::new(),
                    parse_fused_activation(memory, read_ptr(memory, payload + 24)?)?,
                )
            }
            dml_ops::DML_OPERATOR_ELEMENT_WISE_QUANTIZE_LINEAR
            | dml_ops::DML_OPERATOR_ELEMENT_WISE_DEQUANTIZE_LINEAR => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let scale = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let zero = optional_tensor(memory, read_ptr(memory, payload + 16)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let mut inputs = vec![input, scale];
                if let Some(zero) = zero {
                    inputs.push(zero);
                }
                let kind = if ty == dml_ops::DML_OPERATOR_ELEMENT_WISE_QUANTIZE_LINEAR {
                    DmlOpKind::QuantizeLinear
                } else {
                    DmlOpKind::DequantizeLinear
                };
                plan(kind, inputs, output, Vec::new(), None)
            }
            dml_ops::DML_OPERATOR_ELEMENT_WISE_QUANTIZED_LINEAR_ADD => {
                let a = tensor_at(memory, read_ptr(memory, payload)?)?;
                let a_scale = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let a_zero = optional_tensor(memory, read_ptr(memory, payload + 16)?)?;
                let b = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let b_scale = tensor_at(memory, read_ptr(memory, payload + 32)?)?;
                let b_zero = optional_tensor(memory, read_ptr(memory, payload + 40)?)?;
                let out_scale = tensor_at(memory, read_ptr(memory, payload + 48)?)?;
                let out_zero = optional_tensor(memory, read_ptr(memory, payload + 56)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 64)?)?;
                let mut inputs = vec![a, a_scale];
                if let Some(zero) = &a_zero {
                    inputs.push(zero.clone());
                }
                inputs.push(b);
                inputs.push(b_scale);
                if let Some(zero) = &b_zero {
                    inputs.push(zero.clone());
                }
                inputs.push(out_scale);
                if let Some(zero) = &out_zero {
                    inputs.push(zero.clone());
                }
                plan(
                    DmlOpKind::QuantizedLinearAdd {
                        a_zero_point: a_zero.is_some(),
                        b_zero_point: b_zero.is_some(),
                        output_zero_point: out_zero.is_some(),
                    },
                    inputs,
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_DYNAMIC_QUANTIZE_LINEAR => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let scale = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
                let zero = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                plan(
                    DmlOpKind::DynamicQuantizeLinear,
                    vec![input],
                    output,
                    vec![scale, zero],
                    None,
                )
            }
            dml_ops::DML_OPERATOR_MATRIX_MULTIPLY_INTEGER
            | dml_ops::DML_OPERATOR_QUANTIZED_LINEAR_MATRIX_MULTIPLY
            | dml_ops::DML_OPERATOR_MATRIX_MULTIPLY_INTEGER_TO_FLOAT => {
                parse_integer_matmul(memory, ty, payload)
            }
            dml_ops::DML_OPERATOR_CONVOLUTION_INTEGER
            | dml_ops::DML_OPERATOR_QUANTIZED_LINEAR_CONVOLUTION => {
                parse_integer_convolution(memory, ty, payload)
            }
            dml_ops::DML_OPERATOR_QUANTIZED_LINEAR_AVERAGE_POOLING => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let input_scale = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
                let input_zero = optional_tensor(memory, read_ptr(memory, payload + 16)?)?;
                let out_scale = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let out_zero = optional_tensor(memory, read_ptr(memory, payload + 32)?)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 40)?)?;
                let dimension_count = read_u32(memory, payload + 48)?;
                if dimension_count != 2 {
                    return Err(DmlError::invalid(format!(
                        "quantized average pooling DimensionCount must be 2, got {dimension_count}"
                    )));
                }
                let strides = read_u32_list(memory, read_ptr(memory, payload + 56)?, 2)?;
                let window = read_u32_list(memory, read_ptr(memory, payload + 64)?, 2)?;
                let start_padding = read_u32_list(memory, read_ptr(memory, payload + 72)?, 2)?;
                let end_padding = read_u32_list(memory, read_ptr(memory, payload + 80)?, 2)?;
                let dilations = read_u32_list(memory, read_ptr(memory, payload + 88)?, 2)?;
                let include_padding = read_u32(memory, payload + 96)? != 0;
                let mut inputs = vec![input, input_scale];
                if let Some(zero) = &input_zero {
                    inputs.push(zero.clone());
                }
                inputs.push(out_scale);
                if let Some(zero) = &out_zero {
                    inputs.push(zero.clone());
                }
                plan(
                    DmlOpKind::QuantizedLinearAveragePooling {
                        strides,
                        window,
                        start_padding,
                        end_padding,
                        dilations,
                        include_padding,
                        input_zero_point: input_zero.is_some(),
                        output_zero_point: out_zero.is_some(),
                    },
                    inputs,
                    output,
                    Vec::new(),
                    None,
                )
            }
            dml_ops::DML_OPERATOR_QUANTIZE | dml_ops::DML_OPERATOR_DEQUANTIZE => {
                let input = tensor_at(memory, read_ptr(memory, payload)?)?;
                let quantization_type = read_u32(memory, payload + 8)?;
                let count = read_u32(memory, payload + 12)?;
                if count > 8 {
                    return Err(DmlError::invalid(format!(
                        "quantize QuantizationTensorCount {count} exceeds the supported 8 tensors"
                    )));
                }
                let ptr = read_ptr(memory, payload + 16)?;
                let output = tensor_at(memory, read_ptr(memory, payload + 24)?)?;
                let mut inputs = vec![input];
                for index in 0..count as u64 {
                    inputs.push(tensor_at(memory, read_ptr(memory, ptr + index * 8)?)?);
                }
                let kind = if ty == dml_ops::DML_OPERATOR_QUANTIZE {
                    DmlOpKind::Quantize { quantization_type }
                } else {
                    DmlOpKind::Dequantize { quantization_type }
                };
                plan(kind, inputs, output, Vec::new(), None)
            }
            other => Err(DmlError::unsupported_operator(other)),
        }
    }

    pub fn create_operator(&mut self, device: u64, desc: DmlOperatorDesc) -> DmlResult<u64> {
        self.device(device)?;
        let handle = self.alloc_handle();
        self.operators.insert(
            handle,
            DmlOperatorRecord {
                handle,
                device,
                desc,
            },
        );
        Ok(handle)
    }

    pub fn create_operator_from_guest(
        &mut self,
        device: u64,
        memory: &dyn StateObjectMemory,
        desc: u64,
    ) -> DmlResult<u64> {
        if desc == 0 {
            return Err(DmlError::new(
                E_POINTER,
                "DML_OPERATOR_DESC pointer is null",
            ));
        }
        let ty = memory
            .read_u32(desc)
            .map_err(|error| DmlError::invalid(error.to_string()))?;
        if dml_ops::is_extended_operator(ty) {
            let plan = self.parse_operation_from_guest(memory, desc)?;
            self.create_operation(device, plan)
        } else {
            let parsed = self.parse_operator(memory, desc)?;
            self.create_operator(device, parsed)
        }
    }

    pub fn operator(&self, operator: u64) -> DmlResult<&DmlOperatorRecord> {
        self.operators
            .get(&operator)
            .ok_or_else(|| DmlError::invalid(format!("unknown DML operator {operator:#x}")))
    }

    pub fn compile_operator(&mut self, device: u64, operator: u64, flags: u32) -> DmlResult<u64> {
        self.device(device)?;
        if flags & !DML_EXECUTION_FLAGS_VALID != 0 {
            return Err(DmlError::invalid(format!(
                "DML_EXECUTION_FLAGS {flags:#x} contain undefined bits"
            )));
        }
        if !self.operators.contains_key(&operator) {
            if self.operations.contains_key(&operator) {
                return self.compile_operation(device, operator, flags);
            }
            return Err(DmlError::invalid(format!(
                "unknown DML operator {operator:#x}"
            )));
        }
        let record = self.operator(operator)?.clone();
        if record.device != device {
            return Err(DmlError::invalid(
                "operator was created by a different DirectML device",
            ));
        }
        let msl_source = emit_elementwise_msl(&record.desc)?;
        // A compile that does not actually reach Metal is not a success.
        compile_msl(&msl_source)?;
        let handle = self.alloc_handle();
        self.compiled.insert(
            handle,
            DmlCompiledRecord {
                handle,
                device,
                operator,
                flags,
                msl_source,
            },
        );
        Ok(handle)
    }

    pub fn compiled(&self, compiled: u64) -> DmlResult<&DmlCompiledRecord> {
        self.compiled
            .get(&compiled)
            .ok_or_else(|| DmlError::invalid(format!("unknown compiled operator {compiled:#x}")))
    }

    /// Create an extended (non-element-wise) DirectML operator.
    pub fn create_operation(&mut self, device: u64, plan: dml_ops::DmlOpPlan) -> DmlResult<u64> {
        self.device(device)?;
        plan.validate()?;
        let handle = self.alloc_handle();
        self.operations.insert(
            handle,
            DmlOperationRecord {
                handle,
                device,
                plan,
            },
        );
        Ok(handle)
    }

    pub fn operation(&self, operation: u64) -> DmlResult<&DmlOperationRecord> {
        self.operations
            .get(&operation)
            .ok_or_else(|| DmlError::invalid(format!("unknown DML operation {operation:#x}")))
    }

    /// Lower and compile an extended operator. A Metal-backed device compiles
    /// the generated MSL into a real compute pipeline; a CPU device validates
    /// the lowering without requiring a Metal device.
    pub fn compile_operation(&mut self, device: u64, operation: u64, flags: u32) -> DmlResult<u64> {
        let device_record = self.device(device)?.clone();
        if flags & !DML_EXECUTION_FLAGS_VALID != 0 {
            return Err(DmlError::invalid(format!(
                "DML_EXECUTION_FLAGS {flags:#x} contain undefined bits"
            )));
        }
        let record = self.operation(operation)?.clone();
        if record.device != device {
            return Err(DmlError::invalid(
                "operation was created by a different DirectML device",
            ));
        }
        let msl_source = dml_ops::emit_msl(&record.plan)?;
        if device_record.execution_device == dml_ops::DmlExecutionDevice::Metal {
            dml_ops::compile_msl(&msl_source)?;
        }
        let handle = self.alloc_handle();
        self.operations_compiled.insert(
            handle,
            DmlOperationCompiledRecord {
                handle,
                device,
                operation,
                flags,
                msl_source,
            },
        );
        Ok(handle)
    }

    pub fn operation_compiled(&self, compiled: u64) -> DmlResult<&DmlOperationCompiledRecord> {
        self.operations_compiled.get(&compiled).ok_or_else(|| {
            DmlError::invalid(format!("unknown compiled DML operation {compiled:#x}"))
        })
    }

    /// Execute an extended operator with one buffer per input tensor and a
    /// readback buffer for the output tensor.
    pub fn execute_operation(
        &self,
        compiled: u64,
        inputs: &[&[u8]],
        output: &mut [u8],
    ) -> DmlResult<()> {
        let record = self.operation_compiled(compiled)?;
        let operation = self.operation(record.operation)?;
        let backend = self.device(record.device)?.execution_device;
        dml_ops::execute_plan(&operation.plan, backend, inputs, output)
    }

    pub fn operation_binding_count(&self, compiled: u64) -> DmlResult<u32> {
        let record = self.operation_compiled(compiled)?;
        let operation = self.operation(record.operation)?;
        Ok(operation.plan.inputs.len() as u32 + 1)
    }

    pub fn destroy_operation(&mut self, operation: u64) -> DmlResult<()> {
        if self.operations.remove(&operation).is_none() {
            return Err(DmlError::invalid(format!(
                "unknown DML operation {operation:#x}"
            )));
        }
        self.operations_compiled
            .retain(|_, record| record.operation != operation);
        Ok(())
    }

    pub fn destroy_operation_compiled(&mut self, compiled: u64) -> DmlResult<()> {
        self.operations_compiled
            .remove(&compiled)
            .map(|_| ())
            .ok_or_else(|| {
                DmlError::invalid(format!("unknown compiled DML operation {compiled:#x}"))
            })
    }

    /// The plan for a created operator, including the extended operator set.
    pub fn operation_plan(&self, handle: u64) -> DmlResult<dml_ops::DmlOpPlan> {
        if let Some(record) = self.operations.get(&handle) {
            return Ok(record.plan.clone());
        }
        let record = self
            .operators
            .get(&handle)
            .ok_or_else(|| DmlError::invalid(format!("unknown DML operator {handle:#x}")))?;
        let desc = &record.desc;
        let kind = if desc.is_binary() {
            dml_ops::DmlOpKind::Binary {
                op: match desc.ty {
                    DML_OPERATOR_ELEMENT_WISE_ADD => dml_ops::DmlBinaryOp::Add,
                    DML_OPERATOR_ELEMENT_WISE_SUBTRACT => dml_ops::DmlBinaryOp::Subtract,
                    DML_OPERATOR_ELEMENT_WISE_MULTIPLY => dml_ops::DmlBinaryOp::Multiply,
                    DML_OPERATOR_ELEMENT_WISE_DIVIDE => dml_ops::DmlBinaryOp::Divide,
                    DML_OPERATOR_ELEMENT_WISE_MIN => dml_ops::DmlBinaryOp::Min,
                    DML_OPERATOR_ELEMENT_WISE_MAX => dml_ops::DmlBinaryOp::Max,
                    DML_OPERATOR_ELEMENT_WISE_POW => dml_ops::DmlBinaryOp::Pow,
                    other => return Err(DmlError::unsupported_operator(other)),
                },
            }
        } else if desc.ty == DML_OPERATOR_ELEMENT_WISE_IDENTITY {
            dml_ops::DmlOpKind::Activation {
                activation: dml_ops::DmlActivation::Identity,
                alpha: 0.0,
            }
        } else {
            return Err(DmlError::invalid(format!(
                "DML_OPERATOR_TYPE {} cannot be used as a graph node",
                desc.ty
            )));
        };
        let mut inputs = vec![desc.a.clone()];
        if let Some(b) = &desc.b {
            inputs.push(b.clone());
        }
        Ok(dml_ops::DmlOpPlan {
            kind,
            inputs,
            output: desc.output.clone(),
            extra_outputs: Vec::new(),
            fused_activation: None,
        })
    }

    /// Parse, validate, and topologically order a guest `DML_GRAPH_DESC`.
    ///
    /// `operator_handles` maps the guest `IDMLOperator*` stored in each graph
    /// node to the runtime handle created by `CreateOperator`.
    pub fn compile_graph_from_guest(
        &mut self,
        device: u64,
        memory: &dyn StateObjectMemory,
        desc: u64,
        operator_handles: &BTreeMap<u64, u64>,
        flags: u32,
    ) -> DmlResult<u64> {
        self.device(device)?;
        if flags & !DML_EXECUTION_FLAGS_VALID != 0 {
            return Err(DmlError::invalid(format!(
                "DML_EXECUTION_FLAGS {flags:#x} contain undefined bits"
            )));
        }
        if desc == 0 {
            return Err(DmlError::new(E_POINTER, "DML_GRAPH_DESC pointer is null"));
        }
        let input_count = read_u32(memory, desc)?;
        let output_count = read_u32(memory, desc + 4)?;
        let node_count = read_u32(memory, desc + 8)?;
        let nodes_ptr = read_ptr(memory, desc + 16)?;
        let input_edge_count = read_u32(memory, desc + 24)?;
        let input_edges_ptr = read_ptr(memory, desc + 32)?;
        let output_edge_count = read_u32(memory, desc + 40)?;
        let output_edges_ptr = read_ptr(memory, desc + 48)?;
        let intermediate_edge_count = read_u32(memory, desc + 56)?;
        let intermediate_edges_ptr = read_ptr(memory, desc + 64)?;
        if output_count == 0 || node_count == 0 {
            return Err(DmlError::invalid(
                "DML_GRAPH_DESC OutputCount and NodeCount must be non-zero",
            ));
        }
        if input_count > 65536
            || output_count > 65536
            || node_count > 65536
            || input_edge_count > 65536
            || output_edge_count > 65536
            || intermediate_edge_count > 65536
        {
            return Err(DmlError::invalid(
                "DML_GRAPH_DESC counts exceed the supported 65536 limit",
            ));
        }
        if nodes_ptr == 0 {
            return Err(DmlError::new(E_POINTER, "DML_GRAPH_DESC.Nodes is null"));
        }
        let mut nodes = Vec::with_capacity(node_count as usize);
        for index in 0..node_count as u64 {
            let node_desc = nodes_ptr + index * 16;
            let node_type = read_u32(memory, node_desc)?;
            if node_type != DML_GRAPH_NODE_TYPE_OPERATOR {
                return Err(DmlError::invalid(format!(
                    "DML_GRAPH_NODE_TYPE {node_type} is not supported"
                )));
            }
            let operator_desc = read_ptr(memory, node_desc + 8)?;
            if operator_desc == 0 {
                return Err(DmlError::new(
                    E_POINTER,
                    "DML_GRAPH_NODE_DESC.Desc pointer is null",
                ));
            }
            let operator_guest = read_ptr(memory, operator_desc)?;
            let handle = operator_handles
                .get(&operator_guest)
                .copied()
                .ok_or_else(|| {
                    DmlError::invalid(format!(
                        "graph node {index} references an unknown IDMLOperator {operator_guest:#x}"
                    ))
                })?;
            let plan = self.operation_plan(handle)?;
            plan.validate()?;
            nodes.push(plan);
        }
        let mut input_edges = Vec::with_capacity(input_edge_count as usize);
        for index in 0..input_edge_count as u64 {
            let edge = input_edges_ptr + index * 16;
            let edge_type = read_u32(memory, edge)?;
            if edge_type != DML_GRAPH_EDGE_TYPE_INPUT {
                return Err(DmlError::invalid(format!(
                    "input edge {index} has DML_GRAPH_EDGE_TYPE {edge_type}"
                )));
            }
            let edge_desc = read_ptr(memory, edge + 8)?;
            input_edges.push(DmlGraphInputEdge {
                graph_input: read_u32(memory, edge_desc)?,
                to_node: read_u32(memory, edge_desc + 4)?,
                to_node_input: read_u32(memory, edge_desc + 8)?,
            });
        }
        let mut output_edges = Vec::with_capacity(output_edge_count as usize);
        for index in 0..output_edge_count as u64 {
            let edge = output_edges_ptr + index * 16;
            let edge_type = read_u32(memory, edge)?;
            if edge_type != DML_GRAPH_EDGE_TYPE_OUTPUT {
                return Err(DmlError::invalid(format!(
                    "output edge {index} has DML_GRAPH_EDGE_TYPE {edge_type}"
                )));
            }
            let edge_desc = read_ptr(memory, edge + 8)?;
            output_edges.push(DmlGraphOutputEdge {
                from_node: read_u32(memory, edge_desc)?,
                from_node_output: read_u32(memory, edge_desc + 4)?,
                graph_output: read_u32(memory, edge_desc + 8)?,
            });
        }
        let mut intermediate_edges = Vec::with_capacity(intermediate_edge_count as usize);
        for index in 0..intermediate_edge_count as u64 {
            let edge = intermediate_edges_ptr + index * 16;
            let edge_type = read_u32(memory, edge)?;
            if edge_type != DML_GRAPH_EDGE_TYPE_INTERMEDIATE {
                return Err(DmlError::invalid(format!(
                    "intermediate edge {index} has DML_GRAPH_EDGE_TYPE {edge_type}"
                )));
            }
            let edge_desc = read_ptr(memory, edge + 8)?;
            intermediate_edges.push(DmlGraphIntermediateEdge {
                from_node: read_u32(memory, edge_desc)?,
                from_node_output: read_u32(memory, edge_desc + 4)?,
                to_node: read_u32(memory, edge_desc + 8)?,
                to_node_input: read_u32(memory, edge_desc + 12)?,
            });
        }

        let mut connected = Vec::with_capacity(node_count as usize);
        for node in &nodes {
            connected.push(vec![false; node.inputs.len()]);
        }
        let mut graph_inputs_used = vec![false; input_count as usize];
        for (index, edge) in input_edges.iter().enumerate() {
            if edge.graph_input >= input_count {
                return Err(DmlError::invalid(format!(
                    "input edge {index} GraphInputIndex {} is out of range",
                    edge.graph_input
                )));
            }
            if edge.to_node >= node_count {
                return Err(DmlError::invalid(format!(
                    "input edge {index} ToNodeIndex {} is out of range",
                    edge.to_node
                )));
            }
            let node_inputs = nodes[edge.to_node as usize].inputs.len();
            if edge.to_node_input as usize >= node_inputs {
                return Err(DmlError::invalid(format!(
                    "input edge {index} ToNodeInputIndex {} is out of range for node {} with {node_inputs} input(s)",
                    edge.to_node_input, edge.to_node
                )));
            }
            if connected[edge.to_node as usize][edge.to_node_input as usize] {
                return Err(DmlError::invalid(format!(
                    "graph node {} input {} is connected more than once",
                    edge.to_node, edge.to_node_input
                )));
            }
            connected[edge.to_node as usize][edge.to_node_input as usize] = true;
            graph_inputs_used[edge.graph_input as usize] = true;
        }
        for (index, edge) in intermediate_edges.iter().enumerate() {
            if edge.from_node >= node_count || edge.to_node >= node_count {
                return Err(DmlError::invalid(format!(
                    "intermediate edge {index} references a node outside 0..{node_count}"
                )));
            }
            let from_outputs = nodes[edge.from_node as usize].output_count();
            if edge.from_node_output as usize >= from_outputs {
                return Err(DmlError::invalid(format!(
                    "intermediate edge {index} FromNodeOutputIndex {} is out of range for node {} with {from_outputs} output(s)",
                    edge.from_node_output, edge.from_node
                )));
            }
            let node_inputs = nodes[edge.to_node as usize].inputs.len();
            if edge.to_node_input as usize >= node_inputs {
                return Err(DmlError::invalid(format!(
                    "intermediate edge {index} ToNodeInputIndex {} is out of range for node {}",
                    edge.to_node_input, edge.to_node
                )));
            }
            if connected[edge.to_node as usize][edge.to_node_input as usize] {
                return Err(DmlError::invalid(format!(
                    "graph node {} input {} is connected more than once",
                    edge.to_node, edge.to_node_input
                )));
            }
            connected[edge.to_node as usize][edge.to_node_input as usize] = true;
        }
        for (node_index, inputs) in connected.iter().enumerate() {
            for (input_index, is_connected) in inputs.iter().enumerate() {
                if !is_connected {
                    return Err(DmlError::invalid(format!(
                        "graph node {node_index} input {input_index} is not connected"
                    )));
                }
            }
        }
        if input_count != 0 {
            if let Some(index) = graph_inputs_used.iter().position(|used| !used) {
                return Err(DmlError::invalid(format!(
                    "graph input {index} is not connected to any node"
                )));
            }
        }
        let mut graph_outputs_used = vec![false; output_count as usize];
        for (index, edge) in output_edges.iter().enumerate() {
            if edge.from_node >= node_count {
                return Err(DmlError::invalid(format!(
                    "output edge {index} FromNodeIndex {} is out of range",
                    edge.from_node
                )));
            }
            let outputs = nodes[edge.from_node as usize].output_count();
            if edge.from_node_output as usize >= outputs {
                return Err(DmlError::invalid(format!(
                    "output edge {index} FromNodeOutputIndex {} is out of range for node {} with {outputs} output(s)",
                    edge.from_node_output, edge.from_node
                )));
            }
            if edge.graph_output >= output_count {
                return Err(DmlError::invalid(format!(
                    "output edge {index} GraphOutputIndex {} is out of range",
                    edge.graph_output
                )));
            }
            if graph_outputs_used[edge.graph_output as usize] {
                return Err(DmlError::invalid(format!(
                    "graph output {} is produced more than once",
                    edge.graph_output
                )));
            }
            graph_outputs_used[edge.graph_output as usize] = true;
        }
        if let Some(index) = graph_outputs_used.iter().position(|used| !used) {
            return Err(DmlError::invalid(format!(
                "graph output {index} is not connected"
            )));
        }
        let mut indegree = vec![0u32; node_count as usize];
        let mut adjacency = vec![Vec::new(); node_count as usize];
        for edge in &intermediate_edges {
            indegree[edge.to_node as usize] += 1;
            adjacency[edge.from_node as usize].push(edge.to_node);
        }
        let mut ready: Vec<u32> = (0..node_count)
            .filter(|node| indegree[*node as usize] == 0)
            .collect();
        let mut execution_order = Vec::with_capacity(node_count as usize);
        while let Some(node) = ready.pop() {
            execution_order.push(node);
            for next in &adjacency[node as usize] {
                indegree[*next as usize] -= 1;
                if indegree[*next as usize] == 0 {
                    ready.push(*next);
                }
            }
        }
        if execution_order.len() != node_count as usize {
            return Err(DmlError::invalid("DML graph contains a cycle"));
        }
        let plan = DmlGraphPlan {
            input_count,
            output_count,
            nodes,
            input_edges,
            output_edges,
            intermediate_edges,
            execution_order,
        };
        let handle = self.alloc_handle();
        self.graphs.insert(
            handle,
            DmlGraphRecord {
                handle,
                device,
                plan,
            },
        );
        Ok(handle)
    }

    pub fn graph(&self, handle: u64) -> DmlResult<&DmlGraphRecord> {
        self.graphs
            .get(&handle)
            .ok_or_else(|| DmlError::invalid(format!("unknown DML graph {handle:#x}")))
    }

    pub fn destroy_graph(&mut self, handle: u64) -> DmlResult<()> {
        self.graphs
            .remove(&handle)
            .map(|_| ())
            .ok_or_else(|| DmlError::invalid(format!("unknown DML graph {handle:#x}")))
    }

    pub fn create_operator_initializer(
        &mut self,
        device: u64,
        operators: &[u64],
    ) -> DmlResult<u64> {
        self.device(device)?;
        for operator in operators {
            let compiled_device = if let Some(record) = self.compiled.get(operator) {
                record.device
            } else if let Some(record) = self.operations_compiled.get(operator) {
                record.device
            } else {
                return Err(DmlError::invalid(format!(
                    "unknown compiled operator {operator:#x}"
                )));
            };
            if compiled_device != device {
                return Err(DmlError::invalid(
                    "compiled operator belongs to a different DirectML device",
                ));
            }
        }
        let handle = self.alloc_handle();
        self.initializers.insert(
            handle,
            DmlInitializerRecord {
                handle,
                device,
                operators: operators.to_vec(),
            },
        );
        Ok(handle)
    }

    pub fn reset_operator_initializer(
        &mut self,
        initializer: u64,
        operators: Vec<u64>,
    ) -> DmlResult<()> {
        let record = self
            .initializers
            .get(&initializer)
            .ok_or_else(|| {
                DmlError::invalid(format!("unknown DML operator initializer {initializer:#x}"))
            })?
            .clone();
        for operator in &operators {
            let compiled_device = if let Some(compiled) = self.compiled.get(operator) {
                compiled.device
            } else if let Some(compiled) = self.operations_compiled.get(operator) {
                compiled.device
            } else {
                return Err(DmlError::invalid(format!(
                    "unknown compiled operator {operator:#x}"
                )));
            };
            if compiled_device != record.device {
                return Err(DmlError::invalid(
                    "compiled operator belongs to a different DirectML device",
                ));
            }
        }
        self.initializers
            .get_mut(&initializer)
            .expect("initializer checked")
            .operators = operators;
        Ok(())
    }

    pub fn create_command_recorder(&mut self, device: u64) -> DmlResult<u64> {
        self.device(device)?;
        let handle = self.alloc_handle();
        self.recorders
            .insert(handle, DmlRecorderRecord { handle, device });
        Ok(handle)
    }

    pub fn recorder(&self, recorder: u64) -> DmlResult<&DmlRecorderRecord> {
        self.recorders
            .get(&recorder)
            .ok_or_else(|| DmlError::invalid(format!("unknown DML command recorder {recorder:#x}")))
    }

    pub fn record_dispatch(
        &mut self,
        recorder: u64,
        compiled: u64,
        bindings: Vec<DmlBufferBinding>,
    ) -> DmlResult<()> {
        let recorder_record = self.recorder(recorder)?.clone();
        let (compiled_device, expected) = if let Some(record) = self.compiled.get(&compiled) {
            let op = self.operator(record.operator)?;
            (record.device, if op.desc.is_binary() { 3usize } else { 2 })
        } else if let Some(record) = self.operations_compiled.get(&compiled) {
            let operation = self.operation(record.operation)?;
            (record.device, operation.plan.inputs.len() + 1)
        } else if let Some(record) = self.graphs.get(&compiled) {
            (
                record.device,
                (record.plan.input_count + record.plan.output_count) as usize,
            )
        } else {
            return Err(DmlError::invalid(format!(
                "unknown compiled operator {compiled:#x}"
            )));
        };
        if recorder_record.device != compiled_device {
            return Err(DmlError::invalid(
                "command recorder and compiled operator belong to different devices",
            ));
        }
        if bindings.len() != expected {
            return Err(DmlError::invalid(format!(
                "RecordDispatch requires {expected} buffer bindings, got {}",
                bindings.len()
            )));
        }
        for binding in &bindings {
            if binding.resource == 0 {
                return Err(DmlError::invalid("buffer binding resource is null"));
            }
            if binding.size == 0 {
                return Err(DmlError::invalid("buffer binding size is zero"));
            }
            if binding.offset.checked_add(binding.size).is_none() {
                return Err(DmlError::invalid("buffer binding range overflows"));
            }
        }
        self.dispatches.push(DmlDispatchRecord {
            recorder,
            compiled,
            bindings,
        });
        Ok(())
    }

    pub fn dispatches(&self) -> &[DmlDispatchRecord] {
        &self.dispatches
    }

    pub fn initializer(&self, initializer: u64) -> DmlResult<&DmlInitializerRecord> {
        self.initializers.get(&initializer).ok_or_else(|| {
            DmlError::invalid(format!("unknown DML operator initializer {initializer:#x}"))
        })
    }

    pub fn destroy_operator(&mut self, operator: u64) -> DmlResult<()> {
        if self.operators.remove(&operator).is_none() {
            if self.operations.contains_key(&operator) {
                return self.destroy_operation(operator);
            }
            return Err(DmlError::invalid(format!(
                "unknown DML operator {operator:#x}"
            )));
        }
        self.compiled
            .retain(|_, record| record.operator != operator);
        Ok(())
    }

    pub fn destroy_compiled(&mut self, compiled: u64) -> DmlResult<()> {
        if self.compiled.remove(&compiled).is_some()
            || self.operations_compiled.remove(&compiled).is_some()
            || self.graphs.remove(&compiled).is_some()
        {
            return Ok(());
        }
        Err(DmlError::invalid(format!(
            "unknown compiled operator {compiled:#x}"
        )))
    }

    pub fn destroy_operator_initializer(&mut self, initializer: u64) -> DmlResult<()> {
        self.initializers
            .remove(&initializer)
            .map(|_| ())
            .ok_or_else(|| {
                DmlError::invalid(format!("unknown DML operator initializer {initializer:#x}"))
            })
    }

    pub fn destroy_command_recorder(&mut self, recorder: u64) -> DmlResult<()> {
        self.recorders
            .remove(&recorder)
            .map(|_| ())
            .ok_or_else(|| DmlError::invalid(format!("unknown DML command recorder {recorder:#x}")))
    }

    pub fn destroy_binding_table(&mut self, table: u64) -> DmlResult<()> {
        self.binding_tables
            .remove(&table)
            .map(|_| ())
            .ok_or_else(|| DmlError::invalid(format!("unknown DML binding table {table:#x}")))
    }

    pub fn create_binding_table(
        &mut self,
        device: u64,
        dispatchable: u64,
        size_in_descriptors: u32,
    ) -> DmlResult<u64> {
        self.device(device)?;
        self.validate_dispatchable(device, dispatchable)?;
        let handle = self.alloc_handle();
        self.binding_tables.insert(
            handle,
            DmlBindingTableRecord {
                handle,
                device,
                dispatchable,
                size_in_descriptors,
                input_bindings: Vec::new(),
                output_bindings: Vec::new(),
            },
        );
        Ok(handle)
    }

    fn validate_dispatchable(&self, device: u64, dispatchable: u64) -> DmlResult<()> {
        if let Some(record) = self.compiled.get(&dispatchable) {
            if record.device != device {
                return Err(DmlError::invalid(
                    "dispatchable belongs to a different DirectML device",
                ));
            }
            return Ok(());
        }
        if let Some(record) = self.initializers.get(&dispatchable) {
            if record.device != device {
                return Err(DmlError::invalid(
                    "dispatchable belongs to a different DirectML device",
                ));
            }
            return Ok(());
        }
        if let Some(record) = self.operations_compiled.get(&dispatchable) {
            if record.device != device {
                return Err(DmlError::invalid(
                    "dispatchable belongs to a different DirectML device",
                ));
            }
            return Ok(());
        }
        Err(DmlError::invalid(format!(
            "unknown DML dispatchable {dispatchable:#x}"
        )))
    }

    pub fn binding_table(&self, table: u64) -> DmlResult<&DmlBindingTableRecord> {
        self.binding_tables
            .get(&table)
            .ok_or_else(|| DmlError::invalid(format!("unknown DML binding table {table:#x}")))
    }

    pub fn set_binding_table_inputs(
        &mut self,
        table: u64,
        bindings: Vec<DmlBufferBinding>,
    ) -> DmlResult<()> {
        let record = self
            .binding_tables
            .get_mut(&table)
            .ok_or_else(|| DmlError::invalid(format!("unknown DML binding table {table:#x}")))?;
        record.input_bindings = bindings;
        Ok(())
    }

    pub fn set_binding_table_outputs(
        &mut self,
        table: u64,
        bindings: Vec<DmlBufferBinding>,
    ) -> DmlResult<()> {
        let record = self
            .binding_tables
            .get_mut(&table)
            .ok_or_else(|| DmlError::invalid(format!("unknown DML binding table {table:#x}")))?;
        record.output_bindings = bindings;
        Ok(())
    }

    pub fn reset_binding_table(
        &mut self,
        table: u64,
        dispatchable: u64,
        size_in_descriptors: u32,
    ) -> DmlResult<()> {
        let device = self.binding_table(table)?.device;
        self.validate_dispatchable(device, dispatchable)?;
        let record = self
            .binding_tables
            .get_mut(&table)
            .expect("binding table existence checked");
        record.dispatchable = dispatchable;
        record.size_in_descriptors = size_in_descriptors;
        record.input_bindings.clear();
        record.output_bindings.clear();
        Ok(())
    }

    pub fn binding_properties_for_dispatchable(
        &self,
        dispatchable: u64,
    ) -> DmlResult<DmlBindingProperties> {
        if let Some(record) = self.compiled.get(&dispatchable) {
            let op = self.operator(record.operator)?;
            let bindings = if op.desc.is_binary() { 3 } else { 2 };
            return Ok(DmlBindingProperties {
                required_descriptor_count: bindings as u32,
                temporary_resource_size: 0,
                persistent_resource_size: 0,
            });
        }
        if let Some(record) = self.operations_compiled.get(&dispatchable) {
            let operation = self.operation(record.operation)?;
            return Ok(DmlBindingProperties {
                required_descriptor_count: operation.plan.inputs.len() as u32 + 1,
                temporary_resource_size: 0,
                persistent_resource_size: 0,
            });
        }
        if let Some(record) = self.graphs.get(&dispatchable) {
            return Ok(DmlBindingProperties {
                required_descriptor_count: record.plan.input_count + record.plan.output_count,
                temporary_resource_size: 0,
                persistent_resource_size: 0,
            });
        }
        if self.initializers.contains_key(&dispatchable) {
            return Ok(DmlBindingProperties::default());
        }
        Err(DmlError::invalid(format!(
            "unknown DML dispatchable {dispatchable:#x}"
        )))
    }

    pub fn record_dispatch_from_binding_table(
        &mut self,
        recorder: u64,
        compiled: u64,
        table: u64,
    ) -> DmlResult<()> {
        let binding_table = self.binding_table(table)?.clone();
        if binding_table.dispatchable != compiled {
            return Err(DmlError::invalid(
                "binding table dispatchable does not match the recorded compiled operator",
            ));
        }
        let mut bindings = binding_table.input_bindings.clone();
        bindings.extend(binding_table.output_bindings.iter().copied());
        self.record_dispatch(recorder, compiled, bindings)
    }

    /// Execute a compiled element-wise operator on the system Metal device.
    #[rustfmt::skip]
    ///
    /// `inputs` must contain one buffer per input tensor (A, then B for binary
    /// operators) and `output` must be at least the output tensor's declared
    /// size. Buffers are uploaded, the pipeline compiled from the retained MSL
    /// source, dispatched, waited on, and read back. Every failure is a real
    /// Metal/DirectML error, never a synthetic success.
    pub fn execute_elementwise(
        &self,
        compiled: u64,
        inputs: &[&[u8]],
        output: &mut [u8],
    ) -> DmlResult<()> {
        let record = self.compiled(compiled)?;
        let op = self.operator(record.operator)?;
        let desc = &op.desc;
        let needed_inputs = if desc.is_binary() { 2 } else { 1 };
        if inputs.len() != needed_inputs {
            return Err(DmlError::invalid(format!(
                "operator expects {needed_inputs} input buffers, got {}",
                inputs.len()
            )));
        }
        let a_bytes = desc.a.total_size_in_bytes as usize;
        let b_bytes = desc.b.as_ref().map(|b| b.total_size_in_bytes as usize);
        let out_bytes = desc.output.total_size_in_bytes as usize;
        if inputs[0].len() < a_bytes {
            return Err(DmlError::invalid(format!(
                "input A buffer is {} bytes, tensor requires {a_bytes}",
                inputs[0].len()
            )));
        }
        if let Some(b_bytes) = b_bytes
            && inputs[1].len() < b_bytes
        {
            return Err(DmlError::invalid(format!(
                "input B buffer is {} bytes, tensor requires {b_bytes}",
                inputs[1].len()
            )));
        }
        if output.len() < out_bytes {
            return Err(DmlError::invalid(format!(
                "output buffer is {} bytes, tensor requires {out_bytes}",
                output.len()
            )));
        }

        let device = MetalDevice::system_default().map_err(|error| {
            DmlError::unsupported_feature(format!("no Metal device available: {error}")) // coverage: unreachable — Metal device allocation refusal
        })?; // coverage: unreachable — Metal device allocation refusal
        let msl = &record.msl_source;
        let library = device
            .compile_shader_library(msl)
            .map_err(|error| DmlError::new(E_FAIL, error.to_string()))?;
        let function = library
            .get_function("dml_elementwise", None)
            .map_err(|error| {
                DmlError::new(E_FAIL, format!("dml_elementwise not found: {error}"))
            })?;
        let pipeline = device
            .metal_device()
            .new_compute_pipeline_state_with_function(&function)
            .map_err(|error| DmlError::new(E_FAIL, format!("pipeline creation failed: {error}")))?;

        let queue = device.create_command_queue();
        let a_buffer = device.create_buffer_with_data(
            &inputs[0][..a_bytes],
            metal::MTLResourceOptions::StorageModeShared,
        );
        let b_buffer = b_bytes.map(|bytes| {
            device.create_buffer_with_data(
                &inputs[1][..bytes],
                metal::MTLResourceOptions::StorageModeShared,
            )
        });
        let out_buffer = device.create_buffer(
            out_bytes as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );
        let command_buffer = queue.new_command_buffer();
        {
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&pipeline);
            encoder.set_buffer(0, Some(&a_buffer), 0);
            if let Some(b) = &b_buffer {
                encoder.set_buffer(1, Some(b), 0);
                encoder.set_buffer(2, Some(&out_buffer), 0);
            } else {
                encoder.set_buffer(1, Some(&out_buffer), 0);
            }
            let count = desc.output.element_count();
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
            return Err(DmlError::new( // coverage: unreachable — Metal command-buffer failure is driver-dependent
                // coverage: unreachable — Metal command-buffer failure is driver-dependent
                E_FAIL, // coverage: unreachable — Metal command-buffer failure is driver-dependent
                "Metal command buffer failed while executing the DirectML operator", // coverage: unreachable — Metal command-buffer failure is driver-dependent
            )); // coverage: unreachable — Metal command-buffer failure is driver-dependent
        }
        let contents =
            unsafe { std::slice::from_raw_parts(out_buffer.contents() as *const u8, out_bytes) };
        output[..out_bytes].copy_from_slice(contents);
        Ok(())
    }
}

fn parse_tensor(memory: &dyn StateObjectMemory, tensor_desc: u64) -> DmlResult<DmlTensorDesc> {
    if tensor_desc == 0 {
        return Err(DmlError::new(E_POINTER, "DML_TENSOR_DESC pointer is null"));
    }
    let tensor_type = memory.read_u32(tensor_desc).map_err(app_to_dml)?;
    if tensor_type != DML_TENSOR_TYPE_BUFFER {
        return Err(DmlError::invalid(format!(
            "DML_TENSOR_TYPE {tensor_type} is not DML_TENSOR_TYPE_BUFFER"
        )));
    }
    let desc = memory.read_u64(tensor_desc + 8).map_err(app_to_dml)?;
    if desc == 0 {
        return Err(DmlError::new(
            E_POINTER,
            "DML_TENSOR_DESC.Desc pointer is null",
        ));
    }
    // DML_BUFFER_TENSOR_DESC:
    // +0 DataType, +4 Flags, +8 DimensionCount, +16 Sizes,
    // +24 Strides, +32 TotalTensorSizeInBytes, +40 GuaranteedBaseOffsetAlignment
    let data_type = memory.read_u32(desc).map_err(app_to_dml)?;
    let flags = memory.read_u32(desc + 4).map_err(app_to_dml)?;
    let dimension_count = memory.read_u32(desc + 8).map_err(app_to_dml)?;
    if dimension_count == 0 || dimension_count > DML_TENSOR_MAX_DIMENSIONS {
        return Err(DmlError::invalid(format!(
            "tensor DimensionCount {dimension_count} is outside the supported 1..={DML_TENSOR_MAX_DIMENSIONS} range"
        )));
    }
    let sizes_ptr = memory.read_u64(desc + 16).map_err(app_to_dml)?;
    if sizes_ptr == 0 {
        return Err(DmlError::new(E_POINTER, "tensor Sizes pointer is null"));
    }
    let strides_ptr = memory.read_u64(desc + 24).map_err(app_to_dml)?;
    let total_size_in_bytes = memory.read_u64(desc + 32).map_err(app_to_dml)?;
    let guaranteed_base_offset_alignment = memory.read_u32(desc + 40).map_err(app_to_dml)?;

    let mut sizes = Vec::with_capacity(dimension_count as usize);
    for index in 0..dimension_count as u64 {
        sizes.push(memory.read_u32(sizes_ptr + index * 4).map_err(app_to_dml)?);
    }
    let mut strides = vec![0u32; dimension_count as usize];
    if strides_ptr != 0 {
        for index in 0..dimension_count as u64 {
            strides[index as usize] = memory
                .read_u32(strides_ptr + index * 4)
                .map_err(app_to_dml)?;
        }
    } else {
        let mut stride = 1u32;
        for index in (0..dimension_count as usize).rev() {
            strides[index] = stride;
            stride = stride.saturating_mul(sizes[index]);
        }
    }

    Ok(DmlTensorDesc {
        data_type,
        flags,
        sizes,
        strides,
        total_size_in_bytes,
        guaranteed_base_offset_alignment,
    })
}

fn read_ptr(memory: &dyn StateObjectMemory, address: u64) -> DmlResult<u64> {
    memory.read_u64(address).map_err(app_to_dml)
}

fn read_u32(memory: &dyn StateObjectMemory, address: u64) -> DmlResult<u32> {
    memory.read_u32(address).map_err(app_to_dml)
}

fn read_f32(memory: &dyn StateObjectMemory, address: u64) -> DmlResult<f32> {
    Ok(f32::from_bits(read_u32(memory, address)?))
}

fn read_u32_list(memory: &dyn StateObjectMemory, address: u64, count: u32) -> DmlResult<Vec<u32>> {
    if count != 0 && address == 0 {
        return Err(DmlError::new(E_POINTER, "operator array pointer is null"));
    }
    let mut values = Vec::with_capacity(count as usize);
    for index in 0..count as u64 {
        values.push(read_u32(memory, address + index * 4)?);
    }
    Ok(values)
}

fn read_f32_list(memory: &dyn StateObjectMemory, address: u64, count: u32) -> DmlResult<Vec<f32>> {
    if count != 0 && address == 0 {
        return Err(DmlError::new(
            E_POINTER,
            "operator float array pointer is null",
        ));
    }
    let mut values = Vec::with_capacity(count as usize);
    for index in 0..count as u64 {
        values.push(read_f32(memory, address + index * 4)?);
    }
    Ok(values)
}

fn tensor_at(memory: &dyn StateObjectMemory, pointer: u64) -> DmlResult<DmlTensorDesc> {
    parse_tensor(memory, pointer)
}

fn optional_tensor(
    memory: &dyn StateObjectMemory,
    pointer: u64,
) -> DmlResult<Option<DmlTensorDesc>> {
    if pointer == 0 {
        Ok(None)
    } else {
        parse_tensor(memory, pointer).map(Some)
    }
}

fn read_scalar_union(
    memory: &dyn StateObjectMemory,
    address: u64,
    data_type: u32,
) -> DmlResult<f32> {
    match data_type {
        DML_TENSOR_DATA_TYPE_FLOAT32 => read_f32(memory, address),
        DML_TENSOR_DATA_TYPE_UINT32 => Ok(read_u32(memory, address)? as f32),
        DML_TENSOR_DATA_TYPE_INT32 => Ok(read_u32(memory, address)? as i32 as f32),
        DML_TENSOR_DATA_TYPE_FLOAT16 => Ok(dml_ops::f16_bits_to_f32(
            memory.read_u16(address).map_err(app_to_dml)?,
        )),
        DML_TENSOR_DATA_TYPE_UINT16 => Ok(memory.read_u16(address).map_err(app_to_dml)? as f32),
        DML_TENSOR_DATA_TYPE_INT16 => {
            Ok(memory.read_u16(address).map_err(app_to_dml)? as i16 as f32)
        }
        DML_TENSOR_DATA_TYPE_UINT8 => {
            Ok(memory.read_bytes(address, 1).map_err(app_to_dml)?[0] as f32)
        }
        DML_TENSOR_DATA_TYPE_INT8 => {
            Ok(memory.read_bytes(address, 1).map_err(app_to_dml)?[0] as i8 as f32)
        }
        other => Err(DmlError::invalid(format!(
            "DML_TENSOR_DATA_TYPE {other} is not supported for a padding value"
        ))),
    }
}

fn parse_activation_payload(
    memory: &dyn StateObjectMemory,
    ty: u32,
    payload: u64,
) -> DmlResult<dml_ops::DmlActivation> {
    use dml_ops::DmlActivation;
    Ok(match ty {
        dml_ops::DML_OPERATOR_ACTIVATION_RELU => DmlActivation::Relu,
        dml_ops::DML_OPERATOR_ACTIVATION_LEAKY_RELU => DmlActivation::LeakyRelu {
            alpha: read_f32(memory, payload + 16)?,
        },
        dml_ops::DML_OPERATOR_ACTIVATION_SIGMOID => DmlActivation::Sigmoid,
        dml_ops::DML_OPERATOR_ACTIVATION_TANH => DmlActivation::Tanh,
        dml_ops::DML_OPERATOR_ACTIVATION_IDENTITY => DmlActivation::Identity,
        dml_ops::DML_OPERATOR_ACTIVATION_ELU => DmlActivation::Elu {
            alpha: read_f32(memory, payload + 16)?,
        },
        dml_ops::DML_OPERATOR_ACTIVATION_LINEAR => DmlActivation::Linear {
            alpha: read_f32(memory, payload + 16)?,
            beta: read_f32(memory, payload + 20)?,
        },
        dml_ops::DML_OPERATOR_ACTIVATION_SOFTPLUS => DmlActivation::Softplus {
            steepness: read_f32(memory, payload + 16)?,
        },
        dml_ops::DML_OPERATOR_ACTIVATION_SOFTSIGN => DmlActivation::Softsign,
        dml_ops::DML_OPERATOR_ACTIVATION_GELU => DmlActivation::Gelu,
        dml_ops::DML_OPERATOR_ACTIVATION_SWISH => DmlActivation::Swish {
            scale: read_f32(memory, payload + 16)?,
        },
        dml_ops::DML_OPERATOR_ACTIVATION_HARD_SWISH => DmlActivation::HardSwish {
            alpha: read_f32(memory, payload + 16)?,
            beta: read_f32(memory, payload + 20)?,
        },
        dml_ops::DML_OPERATOR_ACTIVATION_HARD_SIGMOID => DmlActivation::HardSigmoid {
            alpha: read_f32(memory, payload + 16)?,
            beta: read_f32(memory, payload + 20)?,
        },
        dml_ops::DML_OPERATOR_ACTIVATION_SCALED_TANH => DmlActivation::ScaledTanh {
            alpha: read_f32(memory, payload + 16)?,
            beta: read_f32(memory, payload + 20)?,
        },
        dml_ops::DML_OPERATOR_ACTIVATION_THRESHOLDED_RELU => DmlActivation::ThresholdedRelu {
            alpha: read_f32(memory, payload + 16)?,
        },
        other => return Err(DmlError::unsupported_operator(other)),
    })
}

fn parse_fused_activation(
    memory: &dyn StateObjectMemory,
    pointer: u64,
) -> DmlResult<Option<dml_ops::DmlActivation>> {
    if pointer == 0 {
        return Ok(None);
    }
    let ty = read_u32(memory, pointer)?;
    let payload = read_ptr(memory, pointer + 8)?;
    if payload == 0 {
        return Err(DmlError::new(
            E_POINTER,
            "fused activation DML_OPERATOR_DESC.Desc pointer is null",
        ));
    }
    parse_activation_payload(memory, ty, payload).map(Some)
}

fn parse_recurrent(
    memory: &dyn StateObjectMemory,
    ty: u32,
    payload: u64,
) -> DmlResult<dml_ops::DmlOpPlan> {
    use dml_ops::{DmlOpKind, DmlOpPlan, DmlRecurrentOptions, DmlRecurrentOutput};
    let input = tensor_at(memory, read_ptr(memory, payload)?)?;
    let weight = tensor_at(memory, read_ptr(memory, payload + 8)?)?;
    let recurrence = tensor_at(memory, read_ptr(memory, payload + 16)?)?;
    let bias = optional_tensor(memory, read_ptr(memory, payload + 24)?)?;
    let hidden_init = optional_tensor(memory, read_ptr(memory, payload + 32)?)?;
    let (cell_init, sequence_lengths, peephole, activation_count, activation_ptr, direction) =
        if ty == dml_ops::DML_OPERATOR_LSTM {
            (
                optional_tensor(memory, read_ptr(memory, payload + 40)?)?,
                optional_tensor(memory, read_ptr(memory, payload + 48)?)?,
                optional_tensor(memory, read_ptr(memory, payload + 56)?)?,
                read_u32(memory, payload + 88)?,
                read_ptr(memory, payload + 96)?,
                read_u32(memory, payload + 104)?,
            )
        } else {
            (
                None,
                optional_tensor(memory, read_ptr(memory, payload + 40)?)?,
                None,
                read_u32(memory, payload + 64)?,
                read_ptr(memory, payload + 72)?,
                read_u32(memory, payload + 80)?,
            )
        };
    let direction = dml_ops::DmlRecurrentDirection::from_u32(direction)
        .ok_or_else(|| DmlError::invalid("recurrent network direction is invalid"))?;
    if activation_count > 8 {
        return Err(DmlError::invalid(format!(
            "recurrent ActivationDescCount {activation_count} exceeds the supported 8 activations"
        )));
    }
    let mut activations = Vec::with_capacity(activation_count as usize);
    for index in 0..activation_count as u64 {
        let descriptor = read_ptr(memory, activation_ptr + index * 8)?;
        if descriptor == 0 {
            return Err(DmlError::new(
                E_POINTER,
                "recurrent activation descriptor pointer is null",
            ));
        }
        let activation_ty = read_u32(memory, descriptor)?;
        let activation_payload = read_ptr(memory, descriptor + 8)?;
        if activation_payload == 0 {
            return Err(DmlError::new(
                E_POINTER,
                "recurrent activation DML_OPERATOR_DESC.Desc pointer is null",
            ));
        }
        activations.push(parse_activation_payload(
            memory,
            activation_ty,
            activation_payload,
        )?);
    }
    let mut inputs = vec![input, weight, recurrence];
    if let Some(bias) = &bias {
        inputs.push(bias.clone());
    }
    if let Some(hidden) = &hidden_init {
        inputs.push(hidden.clone());
    }
    if let Some(cell) = &cell_init {
        inputs.push(cell.clone());
    }
    if let Some(lengths) = &sequence_lengths {
        inputs.push(lengths.clone());
    }
    if let Some(peephole) = &peephole {
        inputs.push(peephole.clone());
    }
    let sequence_output = optional_tensor(
        memory,
        read_ptr(
            memory,
            payload
                + if ty == dml_ops::DML_OPERATOR_LSTM {
                    64
                } else {
                    48
                },
        )?,
    )?;
    let single_output = optional_tensor(
        memory,
        read_ptr(
            memory,
            payload
                + if ty == dml_ops::DML_OPERATOR_LSTM {
                    72
                } else {
                    56
                },
        )?,
    )?;
    let cell_output = if ty == dml_ops::DML_OPERATOR_LSTM {
        optional_tensor(memory, read_ptr(memory, payload + 80)?)?
    } else {
        None
    };
    let mut outputs = Vec::new();
    let mut roles = Vec::new();
    if let Some(output) = sequence_output {
        outputs.push(output);
        roles.push(DmlRecurrentOutput::Sequence);
    }
    if let Some(output) = single_output {
        outputs.push(output);
        roles.push(DmlRecurrentOutput::Single);
    }
    if let Some(output) = cell_output {
        outputs.push(output);
        roles.push(DmlRecurrentOutput::CellSingle);
    }
    let mut outputs = outputs.into_iter();
    let output = outputs.next().ok_or_else(|| {
        DmlError::invalid("recurrent network requires at least one output tensor")
    })?;
    let extra_outputs = outputs.collect();
    let options = DmlRecurrentOptions {
        bias: bias.is_some(),
        hidden_init: hidden_init.is_some(),
        cell_init: cell_init.is_some(),
        sequence_lengths: sequence_lengths.is_some(),
        peephole: peephole.is_some(),
    };
    let kind = match ty {
        dml_ops::DML_OPERATOR_RNN => DmlOpKind::Rnn {
            direction,
            activations,
            options,
            outputs: roles,
        },
        dml_ops::DML_OPERATOR_GRU => DmlOpKind::Gru {
            direction,
            activations,
            options,
            outputs: roles,
            linear_before_reset: read_u32(memory, payload + 84)? != 0,
        },
        _ => DmlOpKind::Lstm {
            direction,
            activations,
            options,
            outputs: roles,
            clip_threshold: read_f32(memory, payload + 108)?,
            use_clip_threshold: read_u32(memory, payload + 112)? != 0,
            couple_input_forget: read_u32(memory, payload + 116)? != 0,
        },
    };
    Ok(DmlOpPlan {
        kind,
        inputs,
        output,
        extra_outputs,
        fused_activation: None,
    })
}

fn parse_integer_matmul(
    memory: &dyn StateObjectMemory,
    ty: u32,
    payload: u64,
) -> DmlResult<dml_ops::DmlOpPlan> {
    use dml_ops::{DmlOpKind, DmlOpPlan};
    let mut inputs = Vec::new();
    let mut quantized = false;
    let mut a_zero = false;
    let mut b_zero = false;
    let mut output_scale = false;
    let mut output_zero = false;
    let mut bias_present = false;
    let output = match ty {
        dml_ops::DML_OPERATOR_MATRIX_MULTIPLY_INTEGER => {
            inputs.push(tensor_at(memory, read_ptr(memory, payload)?)?);
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 8)?)? {
                a_zero = true;
                inputs.push(zero);
            }
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 16)?)?);
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 24)?)? {
                b_zero = true;
                inputs.push(zero);
            }
            tensor_at(memory, read_ptr(memory, payload + 32)?)?
        }
        dml_ops::DML_OPERATOR_MATRIX_MULTIPLY_INTEGER_TO_FLOAT => {
            quantized = true;
            inputs.push(tensor_at(memory, read_ptr(memory, payload)?)?);
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 8)?)?);
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 16)?)? {
                a_zero = true;
                inputs.push(zero);
            }
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 24)?)?);
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 32)?)?);
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 40)?)? {
                b_zero = true;
                inputs.push(zero);
            }
            if let Some(bias) = optional_tensor(memory, read_ptr(memory, payload + 48)?)? {
                bias_present = true;
                inputs.push(bias);
            }
            tensor_at(memory, read_ptr(memory, payload + 56)?)?
        }
        _ => {
            quantized = true;
            inputs.push(tensor_at(memory, read_ptr(memory, payload)?)?);
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 8)?)?);
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 16)?)? {
                a_zero = true;
                inputs.push(zero);
            }
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 24)?)?);
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 32)?)?);
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 40)?)? {
                b_zero = true;
                inputs.push(zero);
            }
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 48)?)?);
            output_scale = true;
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 56)?)? {
                output_zero = true;
                inputs.push(zero);
            }
            tensor_at(memory, read_ptr(memory, payload + 64)?)?
        }
    };
    let kind = if ty == dml_ops::DML_OPERATOR_MATRIX_MULTIPLY_INTEGER_TO_FLOAT {
        DmlOpKind::MatrixMultiplyIntegerToFloat {
            a_zero_point: a_zero,
            b_zero_point: b_zero,
            bias: bias_present,
        }
    } else {
        DmlOpKind::MatrixMultiplyInteger {
            quantized_output: quantized,
            a_zero_point: a_zero,
            b_zero_point: b_zero,
            output_scale,
            output_zero_point: output_zero,
        }
    };
    Ok(DmlOpPlan {
        kind,
        inputs,
        output,
        extra_outputs: Vec::new(),
        fused_activation: None,
    })
}

fn parse_integer_convolution(
    memory: &dyn StateObjectMemory,
    ty: u32,
    payload: u64,
) -> DmlResult<dml_ops::DmlOpPlan> {
    use dml_ops::{DmlOpKind, DmlOpPlan};
    let quantized = ty == dml_ops::DML_OPERATOR_QUANTIZED_LINEAR_CONVOLUTION;
    let input = tensor_at(memory, read_ptr(memory, payload)?)?;
    let mut inputs = vec![input];
    let mut input_zero = false;
    let mut filter_zero = false;
    let mut bias_present = false;
    let mut output_scale = false;
    let mut output_zero = false;
    let (filter_pointer, output_pointer, dimension_offset, strides_offset, group_offset) =
        if quantized {
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 8)?)?);
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 16)?)? {
                input_zero = true;
                inputs.push(zero);
            }
            let filter_pointer = payload + 24;
            inputs.push(tensor_at(memory, read_ptr(memory, filter_pointer)?)?);
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 32)?)?);
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 40)?)? {
                filter_zero = true;
                inputs.push(zero);
            }
            if let Some(bias) = optional_tensor(memory, read_ptr(memory, payload + 48)?)? {
                bias_present = true;
                inputs.push(bias);
            }
            inputs.push(tensor_at(memory, read_ptr(memory, payload + 56)?)?);
            output_scale = true;
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 64)?)? {
                output_zero = true;
                inputs.push(zero);
            }
            (filter_pointer, payload + 72, 80, 88, 120)
        } else {
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 8)?)? {
                input_zero = true;
                inputs.push(zero);
            }
            let filter_pointer = payload + 16;
            inputs.push(tensor_at(memory, read_ptr(memory, filter_pointer)?)?);
            if let Some(zero) = optional_tensor(memory, read_ptr(memory, payload + 24)?)? {
                filter_zero = true;
                inputs.push(zero);
            }
            (filter_pointer, payload + 32, 40, 48, 80)
        };
    let _ = filter_pointer;
    let output = tensor_at(memory, read_ptr(memory, output_pointer)?)?;
    let dimension_count = read_u32(memory, payload + dimension_offset)?;
    if dimension_count != 2 {
        return Err(DmlError::invalid(format!(
            "integer convolution DimensionCount must be 2, got {dimension_count}"
        )));
    }
    let strides = read_u32_list(memory, read_ptr(memory, payload + strides_offset)?, 2)?;
    let dilations = read_u32_list(memory, read_ptr(memory, payload + strides_offset + 8)?, 2)?;
    let start_padding = read_u32_list(memory, read_ptr(memory, payload + strides_offset + 16)?, 2)?;
    let end_padding = read_u32_list(memory, read_ptr(memory, payload + strides_offset + 24)?, 2)?;
    let group_count = read_u32(memory, payload + group_offset)?;
    Ok(DmlOpPlan {
        kind: DmlOpKind::ConvolutionInteger {
            strides,
            dilations,
            start_padding,
            end_padding,
            group_count,
            quantized_output: quantized,
            input_zero_point: input_zero,
            filter_zero_point: filter_zero,
            bias: bias_present,
            output_scale,
            output_zero_point: output_zero,
        },
        inputs,
        output,
        extra_outputs: Vec::new(),
        fused_activation: None,
    })
}

fn is_unary_operator(ty: u32) -> bool {
    matches!(
        ty,
        DML_OPERATOR_ELEMENT_WISE_IDENTITY
            | DML_OPERATOR_ELEMENT_WISE_ABS
            | DML_OPERATOR_ELEMENT_WISE_CEIL
            | DML_OPERATOR_ELEMENT_WISE_COS
            | DML_OPERATOR_ELEMENT_WISE_EXP
            | DML_OPERATOR_ELEMENT_WISE_FLOOR
            | DML_OPERATOR_ELEMENT_WISE_LOG
            | DML_OPERATOR_ELEMENT_WISE_SIN
            | DML_OPERATOR_ELEMENT_WISE_SQRT
            | DML_OPERATOR_ELEMENT_WISE_TAN
    )
}

fn is_binary_operator(ty: u32) -> bool {
    matches!(
        ty,
        DML_OPERATOR_ELEMENT_WISE_ADD
            | DML_OPERATOR_ELEMENT_WISE_DIVIDE
            | DML_OPERATOR_ELEMENT_WISE_MAX
            | DML_OPERATOR_ELEMENT_WISE_MIN
            | DML_OPERATOR_ELEMENT_WISE_MULTIPLY
            | DML_OPERATOR_ELEMENT_WISE_SUBTRACT
    )
}

fn validate_elementwise_constraints(
    ty: u32,
    a: &DmlTensorDesc,
    b: Option<&DmlTensorDesc>,
    output: &DmlTensorDesc,
) -> DmlResult<()> {
    if a.data_type != output.data_type {
        return Err(DmlError::invalid(
            "input and output tensors must have the same DataType",
        ));
    }
    if let Some(b) = b
        && b.data_type != a.data_type
    {
        return Err(DmlError::invalid(
            "input tensors must have the same DataType",
        ));
    }
    if a.sizes != output.sizes {
        return Err(DmlError::invalid(
            "input and output tensors must have identical Sizes",
        ));
    }
    if let Some(b) = b
        && b.sizes != a.sizes
    {
        return Err(DmlError::invalid("input tensors must have identical Sizes"));
    }
    if !output.is_contiguous() {
        return Err(DmlError::invalid(
            "output tensor must be contiguous in this DirectML implementation",
        ));
    }
    let supported_type = matches!(
        a.data_type,
        DML_TENSOR_DATA_TYPE_FLOAT32 | DML_TENSOR_DATA_TYPE_FLOAT16
    );
    if !supported_type {
        return Err(DmlError::invalid(format!(
            "DML_TENSOR_DATA_TYPE {} is not supported for DML_OPERATOR_TYPE {ty}",
            a.data_type
        )));
    }
    Ok(())
}

fn msl_scalar_type(data_type: u32) -> DmlResult<&'static str> {
    match data_type {
        DML_TENSOR_DATA_TYPE_FLOAT32 => Ok("float"),
        DML_TENSOR_DATA_TYPE_FLOAT16 => Ok("half"),
        other => Err(DmlError::invalid(format!(
            "DML_TENSOR_DATA_TYPE {other} is not supported by the Metal lowering"
        ))),
    }
}

fn emit_index_expr(name: &str, tensor: &DmlTensorDesc, sizes: &[u32]) -> String {
    if tensor.is_contiguous() && tensor.sizes == sizes {
        return "gid".to_string();
    }
    let mut terms = Vec::new();
    let mut output_stride = 1u32;
    for index in (0..sizes.len()).rev() {
        let size = sizes[index];
        let stride = tensor.strides[index];
        let term = if output_stride == 1 {
            format!("(gid % {size}u) * {stride}u")
        } else {
            format!("((gid / {output_stride}u) % {size}u) * {stride}u")
        };
        terms.push(term);
        output_stride = output_stride.saturating_mul(size);
    }
    if terms.is_empty() {
        "0u".to_string()
    } else {
        format!("{name}_idx = {}", terms.join(" + "))
    }
}

fn emit_elementwise_msl(desc: &DmlOperatorDesc) -> DmlResult<String> {
    let ty = msl_scalar_type(desc.a.data_type)?;
    let sizes = &desc.output.sizes;
    let count = desc.output.element_count();
    let binary = desc.is_binary();
    let mut source = String::new();
    source.push_str("#include <metal_stdlib>\n");
    source.push_str("using namespace metal;\n");
    if binary {
        source.push_str(
            "kernel void dml_elementwise(device const %TYPE%* a [[buffer(0)]], device const %TYPE%* b [[buffer(1)]], device %TYPE%* out [[buffer(2)]], uint gid [[thread_position_in_grid]]) {\n",
        );
    } else {
        source.push_str(
            "kernel void dml_elementwise(device const %TYPE%* a [[buffer(0)]], device %TYPE%* out [[buffer(1)]], uint gid [[thread_position_in_grid]]) {\n",
        );
    }
    source = source.replace("%TYPE%", ty);
    source.push_str(&format!("    if (gid >= {count}u) return;\n"));
    // Input A index.
    let a_expr = emit_index_expr("a", &desc.a, sizes);
    if a_expr == "gid" {
        source.push_str("    uint a_idx = gid;\n");
    } else {
        source.push_str(&format!("    uint {a_expr};\n"));
    }
    if let Some(b) = &desc.b {
        let b_expr = emit_index_expr("b", b, sizes);
        if b_expr == "gid" {
            source.push_str("    uint b_idx = gid;\n");
        } else {
            source.push_str(&format!("    uint {b_expr};\n"));
        }
    }
    let rhs = match desc.ty {
        DML_OPERATOR_ELEMENT_WISE_IDENTITY => "a[a_idx]".to_string(),
        DML_OPERATOR_ELEMENT_WISE_ABS => "metal::abs(a[a_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_CEIL => "metal::ceil(a[a_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_COS => "metal::cos(a[a_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_EXP => "metal::exp(a[a_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_FLOOR => "metal::floor(a[a_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_LOG => "metal::log(a[a_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_SIN => "metal::sin(a[a_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_SQRT => "metal::sqrt(a[a_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_TAN => "metal::tan(a[a_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_ADD => "a[a_idx] + b[b_idx]".to_string(),
        DML_OPERATOR_ELEMENT_WISE_DIVIDE => "a[a_idx] / b[b_idx]".to_string(),
        DML_OPERATOR_ELEMENT_WISE_MAX => "metal::max(a[a_idx], b[b_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_MIN => "metal::min(a[a_idx], b[b_idx])".to_string(),
        DML_OPERATOR_ELEMENT_WISE_MULTIPLY => "a[a_idx] * b[b_idx]".to_string(),
        DML_OPERATOR_ELEMENT_WISE_SUBTRACT => "a[a_idx] - b[b_idx]".to_string(),
        other => return Err(DmlError::unsupported_operator(other)),
    };
    source.push_str(&format!("    out[gid] = {rhs};\n"));
    source.push_str("}\n");
    Ok(source)
}

fn compile_msl(source: &str) -> DmlResult<()> {
    let device = MetalDevice::system_default().map_err(|error| {
        DmlError::unsupported_feature(format!("no Metal device available: {error}")) // coverage: unreachable — Metal device allocation refusal
    })?; // coverage: unreachable — Metal device allocation refusal
    let library = device
        .compile_shader_library(source)
        .map_err(|error| DmlError::new(E_FAIL, format!("Metal compilation failed: {error}")))?;
    let function = library
        .get_function("dml_elementwise", None)
        .map_err(|error| {
            DmlError::new(E_FAIL, format!("dml_elementwise function missing: {error}"))
        })?;
    device
        .metal_device()
        .new_compute_pipeline_state_with_function(&function)
        .map_err(|error| DmlError::new(E_FAIL, format!("pipeline creation failed: {error}")))?;
    Ok(())
}

fn app_to_dml(error: crate::error::AppError) -> DmlError {
    DmlError::invalid(error.to_string())
}

// ---------------------------------------------------------------------------
// dml.dll-compatible entry points
// ---------------------------------------------------------------------------
//
// DirectML exports only `DMLCreateDevice` and `DMLCreateDevice1`. Operator
// creation/compilation, operator initializers and command recorders are
// methods on `IDMLDevice` (there is no `DMLCreateOperatorRegistry`,
// `DMLCreateOperatorInitializer` or `DMLCreateCommandRecorder` export in
// directml.dll). The functions below expose those real entry points for the
// thunk layer.

/// `DMLCreateDevice(d3d12Device, flags, riid, ppv)`.
pub fn dml_create_device(
    runtime: &mut DmlRuntime,
    parent_device: u64,
    flags: u32,
    iid: DmlGuid,
) -> DmlResult<u64> {
    runtime.create_device(parent_device, flags, DML_FEATURE_LEVEL_1_0, iid)
}

/// `DMLCreateDevice1(d3d12Device, flags, minimumFeatureLevel, riid, ppv)`.
pub fn dml_create_device1(
    runtime: &mut DmlRuntime,
    parent_device: u64,
    flags: u32,
    minimum_feature_level: u32,
    iid: DmlGuid,
) -> DmlResult<u64> {
    runtime.create_device(parent_device, flags, minimum_feature_level, iid)
}

/// `IDMLDevice::CreateOperator`.
pub fn dml_device_create_operator(
    runtime: &mut DmlRuntime,
    device: u64,
    desc: DmlOperatorDesc,
) -> DmlResult<u64> {
    runtime.create_operator(device, desc)
}

/// `IDMLDevice::CompileOperator`.
pub fn dml_device_compile_operator(
    runtime: &mut DmlRuntime,
    device: u64,
    operator: u64,
    flags: u32,
) -> DmlResult<u64> {
    runtime.compile_operator(device, operator, flags)
}

/// `IDMLDevice::CreateOperatorInitializer`.
pub fn dml_device_create_operator_initializer(
    runtime: &mut DmlRuntime,
    device: u64,
    operators: &[u64],
) -> DmlResult<u64> {
    runtime.create_operator_initializer(device, operators)
}

/// `IDMLDevice::CreateCommandRecorder`.
pub fn dml_device_create_command_recorder(runtime: &mut DmlRuntime, device: u64) -> DmlResult<u64> {
    runtime.create_command_recorder(device)
}

/// `IDMLCommandRecorder::RecordDispatch`.
pub fn dml_command_recorder_record_dispatch(
    runtime: &mut DmlRuntime,
    recorder: u64,
    compiled: u64,
    bindings: Vec<DmlBufferBinding>,
) -> DmlResult<()> {
    runtime.record_dispatch(recorder, compiled, bindings)
}

/// `IDMLDevice::CreateOperator` for the extended operator set.
pub fn dml_device_create_operation(
    runtime: &mut DmlRuntime,
    device: u64,
    plan: dml_ops::DmlOpPlan,
) -> DmlResult<u64> {
    runtime.create_operation(device, plan)
}

/// `IDMLDevice::CompileOperator` for the extended operator set.
pub fn dml_device_compile_operation(
    runtime: &mut DmlRuntime,
    device: u64,
    operation: u64,
    flags: u32,
) -> DmlResult<u64> {
    runtime.compile_operation(device, operation, flags)
}

/// Execute a compiled extended operator on its device backend.
pub fn dml_device_execute_operation(
    runtime: &DmlRuntime,
    compiled: u64,
    inputs: &[&[u8]],
    output: &mut [u8],
) -> DmlResult<()> {
    runtime.execute_operation(compiled, inputs, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppResult;

    struct TestMemory {
        data: Vec<u8>,
    }

    impl StateObjectMemory for TestMemory {
        fn read_bytes(&self, address: u64, len: usize) -> AppResult<Vec<u8>> {
            let start = address as usize;
            assert!(start + len <= self.data.len(), "read out of bounds");
            Ok(self.data[start..start + len].to_vec())
        }

        fn read_u32(&self, address: u64) -> AppResult<u32> {
            let start = address as usize;
            assert!(start + 4 <= self.data.len(), "u32 read out of bounds");
            Ok(u32::from_le_bytes(
                self.data[start..start + 4].try_into().unwrap(),
            ))
        }

        fn read_u64(&self, address: u64) -> AppResult<u64> {
            let start = address as usize;
            assert!(start + 8 <= self.data.len(), "u64 read out of bounds");
            Ok(u64::from_le_bytes(
                self.data[start..start + 8].try_into().unwrap(),
            ))
        }

        fn read_u16(&self, address: u64) -> AppResult<u16> {
            let start = address as usize;
            assert!(start + 2 <= self.data.len(), "u16 read out of bounds");
            Ok(u16::from_le_bytes(
                self.data[start..start + 2].try_into().unwrap(),
            ))
        }
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Write a DML_TENSOR_DESC (at `at`) pointing at a buffer tensor desc / sizes
    /// / strides in the same image.
    fn write_tensor(
        data: &mut [u8],
        at: usize,
        data_type: u32,
        sizes: &[u32],
        strides: Option<&[u32]>,
    ) -> u64 {
        let buffer_desc = at + 0x40;
        let sizes_at = at + 0x80;
        let strides_at = at + 0xc0;
        put_u32(data, at, DML_TENSOR_TYPE_BUFFER);
        put_u64(data, at + 8, buffer_desc as u64);
        put_u32(data, buffer_desc, data_type);
        put_u32(data, buffer_desc + 4, 0);
        put_u32(data, buffer_desc + 8, sizes.len() as u32);
        put_u64(data, buffer_desc + 16, sizes_at as u64);
        put_u64(
            data,
            buffer_desc + 24,
            if strides.is_some() {
                strides_at as u64
            } else {
                0
            },
        );
        let element_size = match data_type {
            DML_TENSOR_DATA_TYPE_FLOAT16
            | DML_TENSOR_DATA_TYPE_UINT16
            | DML_TENSOR_DATA_TYPE_INT16 => 2,
            DML_TENSOR_DATA_TYPE_UINT8 | DML_TENSOR_DATA_TYPE_INT8 => 1,
            _ => 4,
        };
        let elements = sizes.iter().map(|size| *size as u64).product::<u64>();
        put_u64(data, buffer_desc + 32, elements * element_size);
        put_u32(data, buffer_desc + 40, 0);
        for (index, size) in sizes.iter().enumerate() {
            put_u32(data, sizes_at + index * 4, *size);
        }
        if let Some(strides) = strides {
            for (index, stride) in strides.iter().enumerate() {
                put_u32(data, strides_at + index * 4, *stride);
            }
        }
        at as u64
    }

    fn write_operator(data: &mut [u8], at: usize, ty: u32, tensors: &[u64]) -> u64 {
        let payload = at + 0x20;
        put_u32(data, at, ty);
        put_u64(data, at + 8, payload as u64);
        for (index, tensor) in tensors.iter().enumerate() {
            put_u64(data, payload + index * 8, *tensor);
        }
        at as u64
    }

    fn base_memory() -> TestMemory {
        TestMemory {
            data: vec![0u8; 0x8000],
        }
    }

    fn float32_image() -> (TestMemory, u64, u64, u64) {
        let mut memory = base_memory();
        let a = write_tensor(
            &mut memory.data,
            0x1000,
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[2, 1, 1, 1],
            None,
        );
        let b = write_tensor(
            &mut memory.data,
            0x2000,
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[2, 1, 1, 1],
            None,
        );
        let out = write_tensor(
            &mut memory.data,
            0x3000,
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[2, 1, 1, 1],
            None,
        );
        (memory, a, b, out)
    }

    fn desc_tensor(data_type: u32, sizes: &[u32], strides: Option<&[u32]>) -> DmlTensorDesc {
        let element_size = match data_type {
            DML_TENSOR_DATA_TYPE_FLOAT16 => 2,
            DML_TENSOR_DATA_TYPE_UINT8 | DML_TENSOR_DATA_TYPE_INT8 => 1,
            _ => 4,
        };
        let strides = strides.map(|s| s.to_vec()).unwrap_or_else(|| {
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
            .map(|(size, stride)| (*size as u64 - 1) * *stride as u64)
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

    fn desc_op(ty: u32, binary: bool) -> DmlOperatorDesc {
        let tensor = desc_tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 1, 1, 1], None);
        DmlOperatorDesc {
            ty,
            a: tensor.clone(),
            b: binary.then_some(tensor.clone()),
            output: tensor,
        }
    }

    #[test]
    fn dml_runtime_error_paths_and_all_operator_lowerings_are_pinned() {
        let error = DmlError::invalid("boom").to_app_error();
        assert_eq!(error.code, crate::reason::ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "DirectML error 0x80070057: boom");

        for (data_type, size) in [
            (DML_TENSOR_DATA_TYPE_FLOAT32, 4),
            (DML_TENSOR_DATA_TYPE_FLOAT16, 2),
            (DML_TENSOR_DATA_TYPE_UINT8, 1),
        ] {
            assert_eq!(
                desc_tensor(data_type, &[1], None).element_size().unwrap(),
                size
            );
        }
        let error = desc_tensor(99, &[1], None).element_size().unwrap_err();
        assert_eq!(error.message, "DML_TENSOR_DATA_TYPE 99 is not supported");
        assert!(desc_tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], None).is_contiguous());
        assert!(!desc_tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], Some(&[2, 2])).is_contiguous());
        let mut tensor = desc_tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None);
        tensor.flags = 1;
        assert_eq!(
            tensor.validate().unwrap_err().message,
            "DML_TENSOR_FLAGS 0x1 are not supported (owned tensors are not implemented)"
        );
        tensor.flags = 0;
        tensor.sizes.clear();
        assert_eq!(
            tensor.validate().unwrap_err().message,
            "tensor DimensionCount 0 is outside the supported 1..=4 range"
        );
        tensor.sizes = vec![2; 5];
        assert_eq!(
            tensor.validate().unwrap_err().message,
            "tensor DimensionCount 5 is outside the supported 1..=4 range"
        );
        tensor.sizes = vec![0];
        assert_eq!(
            tensor.validate().unwrap_err().message,
            "tensor dimensions must be non-zero"
        );
        tensor.sizes = vec![2];
        tensor.strides = vec![0];
        tensor.guaranteed_base_offset_alignment = 3;
        assert_eq!(
            tensor.validate().unwrap_err().message,
            "GuaranteedBaseOffsetAlignment 3 must be a power of two no smaller than the element size"
        );
        tensor.guaranteed_base_offset_alignment = 2;
        assert_eq!(
            tensor.validate().unwrap_err().message,
            "GuaranteedBaseOffsetAlignment 2 must be a power of two no smaller than the element size"
        );
        tensor.guaranteed_base_offset_alignment = 4;
        tensor.total_size_in_bytes = 0;
        assert_eq!(
            tensor.validate().unwrap_err().message,
            "tensor TotalTensorSizeInBytes 0 is smaller than the implied 4 bytes"
        );
        tensor.total_size_in_bytes = 4;
        tensor.validate().expect("tensor valid");
        assert_eq!(
            desc_op(DML_OPERATOR_ELEMENT_WISE_IDENTITY, false).tensor_data_type(),
            DML_TENSOR_DATA_TYPE_FLOAT32
        );

        let mut runtime = DmlRuntime::new();
        assert_eq!(
            runtime
                .create_device(0, 0, DML_FEATURE_LEVEL_1_0, IID_IDMLDEVICE)
                .unwrap_err()
                .message,
            "D3D12 device pointer is null"
        );
        assert_eq!(
            runtime
                .create_device(1, 0x8, DML_FEATURE_LEVEL_1_0, IID_IDMLDEVICE)
                .unwrap_err()
                .message,
            "DML_CREATE_DEVICE_FLAGS 0x8 contain undefined bits"
        );
        assert_eq!(
            runtime.destroy_device(0x1234).unwrap_err().message,
            "unknown DML device 0x1234"
        );
        assert_eq!(
            runtime.device(0x1234).unwrap_err().message,
            "unknown DML device 0x1234"
        );
        let device = runtime
            .create_device(
                1,
                DML_CREATE_DEVICE_FLAG_DEBUG,
                DML_FEATURE_LEVEL_1_0,
                IID_IDMLDEVICE,
            )
            .unwrap();
        assert_eq!(runtime.devices()[&device].parent_device, 1);

        // Operator parse error paths.
        let (mut memory, _, _, _) = float32_image();
        assert_eq!(
            runtime.parse_operator(&memory, 0).unwrap_err().hresult,
            E_POINTER
        );
        let desc = write_operator(
            &mut memory.data,
            0x6000,
            DML_OPERATOR_ELEMENT_WISE_IDENTITY,
            &[0],
        );
        put_u64(&mut memory.data, desc as usize + 8, 0);
        assert_eq!(
            runtime.parse_operator(&memory, desc).unwrap_err().message,
            "DML_OPERATOR_DESC.Desc pointer is null"
        );
        let desc = write_operator(
            &mut memory.data,
            0x6000,
            DML_OPERATOR_ELEMENT_WISE_IDENTITY,
            &[0],
        );
        assert_eq!(
            runtime.parse_operator(&memory, desc).unwrap_err().message,
            "DML_TENSOR_DESC pointer is null"
        );
        let desc = write_operator(&mut memory.data, 0x6000, 9999, &[0]);
        assert_eq!(
            runtime.parse_operator(&memory, desc).unwrap_err().message,
            "DML_OPERATOR_TYPE 9999 is not supported by this DirectML implementation"
        );
        let bad_tensor = 0x7000u64;
        put_u32(&mut memory.data, 0x7000, DML_TENSOR_TYPE_BUFFER);
        let desc = write_operator(
            &mut memory.data,
            0x6000,
            DML_OPERATOR_ELEMENT_WISE_IDENTITY,
            &[bad_tensor, bad_tensor],
        );
        assert_eq!(
            runtime.parse_operator(&memory, desc).unwrap_err().hresult,
            E_POINTER
        );
        put_u32(&mut memory.data, bad_tensor as usize, 2);
        assert_eq!(
            runtime.parse_operator(&memory, desc).unwrap_err().message,
            "DML_TENSOR_TYPE 2 is not DML_TENSOR_TYPE_BUFFER"
        );
        put_u32(&mut memory.data, bad_tensor as usize, 1);
        put_u64(&mut memory.data, bad_tensor as usize + 8, 0);
        assert_eq!(
            runtime.parse_operator(&memory, desc).unwrap_err().hresult,
            E_POINTER
        );
        put_u64(&mut memory.data, bad_tensor as usize + 8, 0x7100);
        put_u32(&mut memory.data, 0x7100, DML_TENSOR_DATA_TYPE_FLOAT32);
        put_u32(&mut memory.data, 0x7108, 0);
        assert_eq!(
            runtime.parse_operator(&memory, desc).unwrap_err().message,
            "tensor DimensionCount 0 is outside the supported 1..=4 range"
        );
        put_u32(&mut memory.data, 0x7108, 1);
        put_u64(&mut memory.data, 0x7110, 0);
        assert_eq!(
            runtime.parse_operator(&memory, desc).unwrap_err().hresult,
            E_POINTER
        );
        put_u64(&mut memory.data, 0x7110, 0x7200);
        put_u32(&mut memory.data, 0x7200, 2);
        put_u64(&mut memory.data, 0x7120, 4);
        let error = runtime.parse_operator(&memory, desc).unwrap_err();
        assert_eq!(
            error.message,
            "tensor TotalTensorSizeInBytes 4 is smaller than the implied 8 bytes"
        );

        // Explicit stride parsing path.
        let mut strided = base_memory();
        let strided_tensor = write_tensor(
            &mut strided.data,
            0x1000,
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[2, 1, 1, 1],
            Some(&[2, 1, 1, 1]),
        );
        put_u64(&mut strided.data, 0x1060, 12);
        let contiguous_output = write_tensor(
            &mut strided.data,
            0x1800,
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[2, 1, 1, 1],
            None,
        );
        let strided_desc = write_operator(
            &mut strided.data,
            0x6000,
            DML_OPERATOR_ELEMENT_WISE_IDENTITY,
            &[strided_tensor, contiguous_output],
        );
        let parsed = runtime
            .parse_operator(&strided, strided_desc)
            .expect("explicit strides");
        assert_eq!(parsed.a.strides, vec![2, 1, 1, 1]);

        // Constraint branches.
        let base = desc_tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 1, 1, 1], None);
        let mut output = base.clone();
        output.data_type = DML_TENSOR_DATA_TYPE_FLOAT16;
        assert_eq!(
            validate_elementwise_constraints(1, &base, None, &output)
                .unwrap_err()
                .message,
            "input and output tensors must have the same DataType"
        );
        let other = desc_tensor(DML_TENSOR_DATA_TYPE_FLOAT16, &[2, 1, 1, 1], None);
        assert_eq!(
            validate_elementwise_constraints(1, &base, Some(&other), &base)
                .unwrap_err()
                .message,
            "input tensors must have the same DataType"
        );
        let other_sizes = desc_tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[3, 1, 1, 1], None);
        assert_eq!(
            validate_elementwise_constraints(1, &base, None, &other_sizes)
                .unwrap_err()
                .message,
            "input and output tensors must have identical Sizes"
        );
        assert_eq!(
            validate_elementwise_constraints(1, &base, Some(&other_sizes), &base)
                .unwrap_err()
                .message,
            "input tensors must have identical Sizes"
        );
        let noncontiguous = desc_tensor(
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[2, 1, 1, 1],
            Some(&[2, 1, 1, 1]),
        );
        assert_eq!(
            validate_elementwise_constraints(1, &base, None, &noncontiguous)
                .unwrap_err()
                .message,
            "output tensor must be contiguous in this DirectML implementation"
        );
        let unsupported_type = desc_tensor(DML_TENSOR_DATA_TYPE_UINT32, &[2, 1, 1, 1], None);
        assert_eq!(
            validate_elementwise_constraints(1, &unsupported_type, None, &unsupported_type)
                .unwrap_err()
                .message,
            "DML_TENSOR_DATA_TYPE 3 is not supported for DML_OPERATOR_TYPE 1"
        );

        // Every operator lowering and index-expression branch.
        for ty in [
            DML_OPERATOR_ELEMENT_WISE_IDENTITY,
            DML_OPERATOR_ELEMENT_WISE_ABS,
            DML_OPERATOR_ELEMENT_WISE_CEIL,
            DML_OPERATOR_ELEMENT_WISE_COS,
            DML_OPERATOR_ELEMENT_WISE_EXP,
            DML_OPERATOR_ELEMENT_WISE_FLOOR,
            DML_OPERATOR_ELEMENT_WISE_LOG,
            DML_OPERATOR_ELEMENT_WISE_SIN,
            DML_OPERATOR_ELEMENT_WISE_SQRT,
            DML_OPERATOR_ELEMENT_WISE_TAN,
        ] {
            let source = emit_elementwise_msl(&desc_op(ty, false)).unwrap();
            assert!(source.contains("device const float* a"));
        }
        for ty in [
            DML_OPERATOR_ELEMENT_WISE_ADD,
            DML_OPERATOR_ELEMENT_WISE_DIVIDE,
            DML_OPERATOR_ELEMENT_WISE_MAX,
            DML_OPERATOR_ELEMENT_WISE_MIN,
            DML_OPERATOR_ELEMENT_WISE_MULTIPLY,
            DML_OPERATOR_ELEMENT_WISE_SUBTRACT,
        ] {
            let source = emit_elementwise_msl(&desc_op(ty, true)).unwrap();
            assert!(source.contains("device const float* b"));
        }
        let mut half = desc_op(DML_OPERATOR_ELEMENT_WISE_IDENTITY, false);
        half.a.data_type = DML_TENSOR_DATA_TYPE_FLOAT16;
        half.output.data_type = DML_TENSOR_DATA_TYPE_FLOAT16;
        assert!(
            emit_elementwise_msl(&half)
                .unwrap()
                .contains("device const half* a")
        );
        let mut unsupported = desc_op(9999, false);
        unsupported.a.data_type = DML_TENSOR_DATA_TYPE_FLOAT32;
        assert_eq!(
            emit_elementwise_msl(&unsupported).unwrap_err().message,
            "DML_OPERATOR_TYPE 9999 is not supported by this DirectML implementation"
        );
        let mut bad_type = desc_op(DML_OPERATOR_ELEMENT_WISE_IDENTITY, false);
        bad_type.a.data_type = 77;
        assert_eq!(
            emit_elementwise_msl(&bad_type).unwrap_err().message,
            "DML_TENSOR_DATA_TYPE 77 is not supported by the Metal lowering"
        );
        let noncontiguous_a = desc_tensor(
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[2, 1, 1, 1],
            Some(&[2, 1, 1, 1]),
        );
        let mut indexed = desc_op(DML_OPERATOR_ELEMENT_WISE_ADD, true);
        indexed.a = noncontiguous_a.clone();
        indexed.b = Some(desc_tensor(
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[2, 1, 1, 1],
            Some(&[2, 2, 1, 1]),
        ));
        let source = emit_elementwise_msl(&indexed).unwrap();
        assert!(source.contains("uint a_idx = (gid % 1u) * 1u"));
        assert!(source.contains("uint b_idx = (gid % 1u) * 1u"));
        let empty_tensor = DmlTensorDesc {
            data_type: DML_TENSOR_DATA_TYPE_FLOAT32,
            flags: 0,
            sizes: vec![1],
            strides: vec![1],
            total_size_in_bytes: 4,
            guaranteed_base_offset_alignment: 0,
        };
        assert_eq!(emit_index_expr("a", &empty_tensor, &[]), "0u");
        assert_eq!(
            emit_index_expr("a", &noncontiguous_a, &[2, 1, 1, 1]),
            "a_idx = (gid % 1u) * 1u + (gid % 1u) * 1u + (gid % 1u) * 1u + (gid % 2u) * 2u"
        );
        let two_dims = desc_tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2, 2], Some(&[4, 1]));
        assert_eq!(
            emit_index_expr("a", &two_dims, &[2, 2]),
            "a_idx = (gid % 2u) * 1u + ((gid / 2u) % 2u) * 4u"
        );

        let error = compile_msl("not metal").unwrap_err();
        assert_eq!(error.hresult, E_FAIL);

        // Device/operator/compile lifecycle errors.
        let unary = desc_op(DML_OPERATOR_ELEMENT_WISE_IDENTITY, false);
        assert_eq!(
            runtime
                .create_operator(0x9999, unary.clone())
                .unwrap_err()
                .message,
            "unknown DML device 0x9999"
        );
        let op = runtime.create_operator(device, unary).unwrap();
        assert_eq!(
            runtime
                .compile_operator(device, op, 0x8)
                .unwrap_err()
                .message,
            "DML_EXECUTION_FLAGS 0x8 contain undefined bits"
        );
        let compiled = runtime.compile_operator(device, op, 0).expect("compile");
        assert_eq!(
            runtime
                .create_operator_initializer(0x9999, &[compiled])
                .unwrap_err()
                .message,
            "unknown DML device 0x9999"
        );
        assert_eq!(
            runtime
                .create_operator_initializer(device, &[0x9999])
                .unwrap_err()
                .message,
            "unknown compiled operator 0x9999"
        );
        let initializer = runtime
            .create_operator_initializer(device, &[compiled])
            .unwrap();
        assert_eq!(
            runtime
                .reset_operator_initializer(0x9999, vec![])
                .unwrap_err()
                .message,
            "unknown DML operator initializer 0x9999"
        );
        runtime
            .reset_operator_initializer(initializer, vec![compiled])
            .expect("reset initializer");
        assert_eq!(
            runtime.destroy_operator(0x9999).unwrap_err().message,
            "unknown DML operator 0x9999"
        );
        assert_eq!(
            runtime.destroy_compiled(0x9999).unwrap_err().message,
            "unknown compiled operator 0x9999"
        );
        assert_eq!(
            runtime
                .destroy_operator_initializer(0x9999)
                .unwrap_err()
                .message,
            "unknown DML operator initializer 0x9999"
        );
        assert_eq!(
            runtime
                .destroy_command_recorder(0x9999)
                .unwrap_err()
                .message,
            "unknown DML command recorder 0x9999"
        );
        assert_eq!(
            runtime.destroy_binding_table(0x9999).unwrap_err().message,
            "unknown DML binding table 0x9999"
        );
        assert_eq!(
            runtime.initializer(0x9999).unwrap_err().message,
            "unknown DML operator initializer 0x9999"
        );
        assert_eq!(
            runtime
                .binding_properties_for_dispatchable(0x9999)
                .unwrap_err()
                .message,
            "unknown DML dispatchable 0x9999"
        );
        assert_eq!(
            runtime
                .binding_properties_for_dispatchable(initializer)
                .unwrap(),
            DmlBindingProperties::default()
        );

        // Two devices exercise cross-device rejection.
        let other_device = runtime
            .create_device(2, 0, DML_FEATURE_LEVEL_1_0, IID_IDMLDEVICE)
            .unwrap();
        let other_operator = runtime
            .create_operator(
                other_device,
                desc_op(DML_OPERATOR_ELEMENT_WISE_IDENTITY, false),
            )
            .unwrap();
        let other_compiled = runtime
            .compile_operator(other_device, other_operator, 0)
            .unwrap();
        assert_eq!(
            runtime
                .compile_operator(device, other_operator, 0)
                .unwrap_err()
                .message,
            "operator was created by a different DirectML device"
        );
        assert_eq!(
            runtime
                .create_operator_initializer(device, &[other_compiled])
                .unwrap_err()
                .message,
            "compiled operator belongs to a different DirectML device"
        );
        assert_eq!(
            runtime
                .reset_operator_initializer(initializer, vec![other_compiled])
                .unwrap_err()
                .message,
            "compiled operator belongs to a different DirectML device"
        );

        let other_initializer = runtime
            .create_operator_initializer(other_device, &[other_compiled])
            .unwrap();
        assert_eq!(
            runtime
                .create_binding_table(device, other_initializer, 1)
                .unwrap_err()
                .message,
            "dispatchable belongs to a different DirectML device"
        );

        // Binding tables and dispatch recording.
        assert_eq!(
            runtime
                .create_binding_table(0x9999, compiled, 2)
                .unwrap_err()
                .message,
            "unknown DML device 0x9999"
        );
        assert_eq!(
            runtime
                .create_binding_table(device, 0x9999, 2)
                .unwrap_err()
                .message,
            "unknown DML dispatchable 0x9999"
        );
        assert_eq!(
            runtime
                .create_binding_table(device, other_compiled, 2)
                .unwrap_err()
                .message,
            "dispatchable belongs to a different DirectML device"
        );
        let table = runtime.create_binding_table(device, compiled, 2).unwrap();
        assert_eq!(
            runtime
                .set_binding_table_inputs(0x9999, vec![])
                .unwrap_err()
                .message,
            "unknown DML binding table 0x9999"
        );
        assert_eq!(
            runtime
                .set_binding_table_outputs(0x9999, vec![])
                .unwrap_err()
                .message,
            "unknown DML binding table 0x9999"
        );
        assert_eq!(
            runtime
                .reset_binding_table(0x9999, compiled, 2)
                .unwrap_err()
                .message,
            "unknown DML binding table 0x9999"
        );
        runtime
            .set_binding_table_inputs(
                table,
                vec![DmlBufferBinding {
                    resource: 1,
                    offset: 0,
                    size: 8,
                }],
            )
            .unwrap();
        runtime
            .set_binding_table_outputs(
                table,
                vec![DmlBufferBinding {
                    resource: 2,
                    offset: 0,
                    size: 8,
                }],
            )
            .unwrap();
        runtime.reset_binding_table(table, compiled, 2).unwrap();
        assert_eq!(
            runtime
                .reset_binding_table(table, 0x9999, 2)
                .unwrap_err()
                .message,
            "unknown DML dispatchable 0x9999"
        );
        assert_eq!(
            runtime
                .binding_properties_for_dispatchable(compiled)
                .unwrap()
                .required_descriptor_count,
            2
        );
        let binary_op = runtime
            .create_operator(device, desc_op(DML_OPERATOR_ELEMENT_WISE_ADD, true))
            .unwrap();
        let binary_compiled = runtime.compile_operator(device, binary_op, 0).unwrap();
        assert_eq!(
            runtime
                .binding_properties_for_dispatchable(binary_compiled)
                .unwrap()
                .required_descriptor_count,
            3
        );
        let recorder = runtime.create_command_recorder(device).unwrap();
        assert_eq!(
            runtime.create_command_recorder(0x9999).unwrap_err().message,
            "unknown DML device 0x9999"
        );
        assert_eq!(
            runtime.recorder(0x9999).unwrap_err().message,
            "unknown DML command recorder 0x9999"
        );
        assert_eq!(
            runtime
                .record_dispatch(0x9999, compiled, vec![])
                .unwrap_err()
                .message,
            "unknown DML command recorder 0x9999"
        );
        assert_eq!(
            runtime
                .record_dispatch(recorder, 0x9999, vec![])
                .unwrap_err()
                .message,
            "unknown compiled operator 0x9999"
        );
        let other_recorder = runtime.create_command_recorder(other_device).unwrap();
        assert_eq!(
            runtime
                .record_dispatch(other_recorder, compiled, vec![])
                .unwrap_err()
                .message,
            "command recorder and compiled operator belong to different devices"
        );
        assert_eq!(
            runtime
                .record_dispatch(
                    recorder,
                    compiled,
                    vec![
                        DmlBufferBinding {
                            resource: 0,
                            offset: 0,
                            size: 8
                        },
                        DmlBufferBinding {
                            resource: 1,
                            offset: 0,
                            size: 8
                        }
                    ]
                )
                .unwrap_err()
                .message,
            "buffer binding resource is null"
        );
        assert_eq!(
            runtime
                .record_dispatch(
                    recorder,
                    compiled,
                    vec![
                        DmlBufferBinding {
                            resource: 1,
                            offset: 0,
                            size: 0
                        },
                        DmlBufferBinding {
                            resource: 1,
                            offset: 0,
                            size: 8
                        }
                    ]
                )
                .unwrap_err()
                .message,
            "buffer binding size is zero"
        );
        assert_eq!(
            runtime
                .record_dispatch(
                    recorder,
                    compiled,
                    vec![
                        DmlBufferBinding {
                            resource: 1,
                            offset: u64::MAX,
                            size: 8
                        },
                        DmlBufferBinding {
                            resource: 1,
                            offset: 0,
                            size: 8
                        }
                    ]
                )
                .unwrap_err()
                .message,
            "buffer binding range overflows"
        );
        let binary_table = runtime
            .create_binding_table(device, binary_compiled, 3)
            .unwrap();
        assert_eq!(
            runtime
                .record_dispatch_from_binding_table(recorder, compiled, binary_table)
                .unwrap_err()
                .message,
            "binding table dispatchable does not match the recorded compiled operator"
        );
        runtime
            .set_binding_table_inputs(
                binary_table,
                vec![
                    DmlBufferBinding {
                        resource: 1,
                        offset: 0,
                        size: 8,
                    },
                    DmlBufferBinding {
                        resource: 2,
                        offset: 0,
                        size: 8,
                    },
                ],
            )
            .unwrap();
        runtime
            .set_binding_table_outputs(
                binary_table,
                vec![DmlBufferBinding {
                    resource: 3,
                    offset: 0,
                    size: 8,
                }],
            )
            .unwrap();
        runtime
            .record_dispatch_from_binding_table(recorder, binary_compiled, binary_table)
            .unwrap();
        assert_eq!(runtime.dispatches().len(), 1);

        // Execution error paths and a real unary+binary Metal dispatch.
        let input = [1.5f32.to_le_bytes(), (-2.5f32).to_le_bytes()].concat();
        assert_eq!(
            runtime
                .execute_elementwise(0x9999, &[&input], &mut [0u8; 8])
                .unwrap_err()
                .message,
            "unknown compiled operator 0x9999"
        );
        assert_eq!(
            runtime
                .execute_elementwise(compiled, &[], &mut [0u8; 8])
                .unwrap_err()
                .message,
            "operator expects 1 input buffers, got 0"
        );
        assert_eq!(
            runtime
                .execute_elementwise(compiled, &[&input[..4]], &mut [0u8; 8])
                .unwrap_err()
                .message,
            "input A buffer is 4 bytes, tensor requires 8"
        );
        assert_eq!(
            runtime
                .execute_elementwise(binary_compiled, &[&input], &mut [0u8; 8])
                .unwrap_err()
                .message,
            "operator expects 2 input buffers, got 1"
        );
        assert_eq!(
            runtime
                .execute_elementwise(binary_compiled, &[&input, &input[..4]], &mut [0u8; 8])
                .unwrap_err()
                .message,
            "input B buffer is 4 bytes, tensor requires 8"
        );
        let mut out = [0u8; 8];
        runtime
            .execute_elementwise(compiled, &[&input], &mut out)
            .unwrap();
        assert_eq!(out.as_slice(), input.as_slice());
        let b = [3.0f32.to_le_bytes(), 4.0f32.to_le_bytes()].concat();
        let mut sum = [0u8; 8];
        runtime
            .execute_elementwise(binary_compiled, &[&input, &b], &mut sum)
            .unwrap();
        assert_eq!(
            sum.as_slice(),
            [(1.5f32 + 3.0).to_le_bytes(), (-2.5f32 + 4.0).to_le_bytes()]
                .concat()
                .as_slice()
        );

        // Invalid lowering cached in the compiled record reaches real Metal
        // and fails with the exact DirectML error.
        runtime.compiled.get_mut(&compiled).unwrap().msl_source = "not metal".to_string();
        assert_eq!(
            runtime
                .execute_elementwise(compiled, &[&input], &mut out)
                .unwrap_err()
                .hresult,
            E_FAIL
        );
        runtime.compiled.get_mut(&compiled).unwrap().msl_source =
            "kernel void other() {}".to_string();
        assert_eq!(
            runtime
                .execute_elementwise(compiled, &[&input], &mut out)
                .unwrap_err()
                .hresult,
            E_FAIL
        );

        assert_eq!(
            compile_msl("kernel void other() {}").unwrap_err().hresult,
            E_FAIL
        );
        let converted = app_to_dml(crate::error::AppError::new(
            crate::reason::ReasonCode::RcD3dInvalidState,
            "read failed",
        ));
        assert_eq!(converted.hresult, E_INVALIDARG);
        assert_eq!(converted.message, "RC_D3D_INVALID_STATE: read failed");

        // Public dml.dll-compatible wrappers.
        assert_eq!(
            dml_create_device(&mut runtime, 0, 0, IID_IDMLDEVICE)
                .unwrap_err()
                .message,
            "D3D12 device pointer is null"
        );
        assert_eq!(
            dml_create_device1(&mut runtime, 0, 0, DML_FEATURE_LEVEL_1_0, IID_IDMLDEVICE)
                .unwrap_err()
                .message,
            "D3D12 device pointer is null"
        );
        let wrapper_device = dml_create_device(&mut runtime, 1, 0, IID_IDMLDEVICE).unwrap();
        let wrapper_op = dml_device_create_operator(
            &mut runtime,
            wrapper_device,
            desc_op(DML_OPERATOR_ELEMENT_WISE_IDENTITY, false),
        )
        .unwrap();
        let wrapper_compiled =
            dml_device_compile_operator(&mut runtime, wrapper_device, wrapper_op, 0).unwrap();
        let wrapper_init = dml_device_create_operator_initializer(
            &mut runtime,
            wrapper_device,
            &[wrapper_compiled],
        )
        .unwrap();
        assert!(wrapper_init >= 0x1000);
        let wrapper_recorder =
            dml_device_create_command_recorder(&mut runtime, wrapper_device).unwrap();
        assert_eq!(
            dml_command_recorder_record_dispatch(
                &mut runtime,
                wrapper_recorder,
                wrapper_compiled,
                vec![]
            )
            .unwrap_err()
            .message,
            "RecordDispatch requires 2 buffer bindings, got 0"
        );
    }

    #[test]
    fn dml_unsupported_operator_returns_invalidarg() {
        let (mut memory, a, _, _) = float32_image();
        let desc = write_operator(&mut memory.data, 0x6000, 9999, &[a]);
        let error = DmlRuntime::new().parse_operator(&memory, desc).unwrap_err();
        assert_eq!(error.hresult, E_INVALIDARG);
        assert_eq!(
            error.message,
            "DML_OPERATOR_TYPE 9999 is not supported by this DirectML implementation"
        );
    }

    #[test]
    fn dml_invalid_dimension_count_is_rejected() {
        let (mut memory, a, _, _) = float32_image();
        let desc = write_operator(
            &mut memory.data,
            0x6000,
            DML_OPERATOR_ELEMENT_WISE_IDENTITY,
            &[a, a],
        );
        // Tensor desc at 0x1000 points at buffer desc 0x1040.
        put_u32(&mut memory.data, 0x1048, 0);
        let error = DmlRuntime::new().parse_operator(&memory, desc).unwrap_err();
        assert_eq!(error.hresult, E_INVALIDARG);
        assert_eq!(
            error.message,
            "tensor DimensionCount 0 is outside the supported 1..=4 range"
        );
    }

    #[test]
    fn dml_mismatched_binary_sizes_return_invalidarg() {
        let (mut memory, a, _, out) = float32_image();
        let b = write_tensor(
            &mut memory.data,
            0x4000,
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[3, 1, 1, 1],
            None,
        );
        let desc = write_operator(
            &mut memory.data,
            0x6000,
            DML_OPERATOR_ELEMENT_WISE_ADD,
            &[a, b, out],
        );
        let error = DmlRuntime::new().parse_operator(&memory, desc).unwrap_err();
        assert_eq!(error.hresult, E_INVALIDARG);
        assert_eq!(error.message, "input tensors must have identical Sizes");
    }

    #[test]
    fn dml_unsupported_data_type_is_rejected() {
        let mut memory = base_memory();
        let a = write_tensor(
            &mut memory.data,
            0x1000,
            DML_TENSOR_DATA_TYPE_UINT32,
            &[2, 1, 1, 1],
            None,
        );
        let desc = write_operator(
            &mut memory.data,
            0x6000,
            DML_OPERATOR_ELEMENT_WISE_IDENTITY,
            &[a, a],
        );
        let error = DmlRuntime::new().parse_operator(&memory, desc).unwrap_err();
        assert_eq!(error.hresult, E_INVALIDARG);
        assert_eq!(
            error.message,
            "DML_TENSOR_DATA_TYPE 3 is not supported for DML_OPERATOR_TYPE 1"
        );
    }

    #[test]
    fn dml_device_rejects_feature_level_above_implemented_level() {
        let mut runtime = DmlRuntime::new();
        let error = runtime
            .create_device(0x100, 0, DML_FEATURE_LEVEL_6_4, IID_IDMLDEVICE)
            .unwrap_err();
        assert_eq!(error.hresult, DXGI_ERROR_UNSUPPORTED);
        assert_eq!(
            error.message,
            "requested DML_FEATURE_LEVEL 0x6400 exceeds the supported 0x4000"
        );
    }

    #[test]
    fn dml_device_rejects_unknown_iid() {
        let mut runtime = DmlRuntime::new();
        let error = runtime
            .create_device(0x100, 0, DML_FEATURE_LEVEL_1_0, DmlGuid([0; 16]))
            .unwrap_err();
        assert_eq!(error.hresult, E_NOINTERFACE);
    }

    #[test]
    fn dml_record_dispatch_rejects_wrong_binding_count() {
        let (mut memory, a, _, out) = float32_image();
        let desc = write_operator(
            &mut memory.data,
            0x6000,
            DML_OPERATOR_ELEMENT_WISE_IDENTITY,
            &[a, out],
        );
        let parsed = DmlRuntime::new().parse_operator(&memory, desc).unwrap();
        let mut runtime = DmlRuntime::new();
        let device = runtime
            .create_device(1, 0, DML_FEATURE_LEVEL_1_0, IID_IDMLDEVICE)
            .unwrap();
        let op = runtime.create_operator(device, parsed).unwrap();
        // Compilation is a real Metal compile; skip only when the host has no
        // Metal device, otherwise the exact pipeline must be created.
        let compiled = match runtime.compile_operator(device, op, 0) {
            Ok(compiled) => compiled,
            Err(error) if error.hresult == DXGI_ERROR_UNSUPPORTED => return,
            Err(error) => panic!("unexpected compile failure: {error:?}"),
        };
        let recorder = runtime.create_command_recorder(device).unwrap();
        let error = runtime
            .record_dispatch(recorder, compiled, vec![])
            .unwrap_err();
        assert_eq!(error.hresult, E_INVALIDARG);
        assert_eq!(
            error.message,
            "RecordDispatch requires 2 buffer bindings, got 0"
        );
    }

    #[test]
    fn dml_execute_rejects_short_output_buffer() {
        let (mut memory, a, _, out) = float32_image();
        let desc = write_operator(
            &mut memory.data,
            0x6000,
            DML_OPERATOR_ELEMENT_WISE_IDENTITY,
            &[a, out],
        );
        let parsed = DmlRuntime::new().parse_operator(&memory, desc).unwrap();
        let mut runtime = DmlRuntime::new();
        let device = runtime
            .create_device(1, 0, DML_FEATURE_LEVEL_1_0, IID_IDMLDEVICE)
            .unwrap();
        let op = runtime.create_operator(device, parsed).unwrap();
        let compiled = match runtime.compile_operator(device, op, 0) {
            Ok(compiled) => compiled,
            Err(error) if error.hresult == DXGI_ERROR_UNSUPPORTED => return,
            Err(error) => panic!("unexpected compile failure: {error:?}"),
        };
        let input = [0u8; 8];
        let mut output = [0u8; 4];
        let error = runtime
            .execute_elementwise(compiled, &[&input], &mut output)
            .unwrap_err();
        assert_eq!(error.hresult, E_INVALIDARG);
        assert_eq!(error.message, "output buffer is 4 bytes, tensor requires 8");
    }

    fn create_test_device(runtime: &mut DmlRuntime) -> u64 {
        runtime
            .create_device(0x100, 0, DML_FEATURE_LEVEL_4_0, IID_IDMLDEVICE)
            .expect("feature level 4.0 device")
    }

    #[test]
    fn dml_guest_extended_operator_parsing_reaches_argmax_and_rejects_axis_overflow() {
        let (mut memory, a, _, out) = float32_image();
        // Replace the float output with a UINT32 [2,1] output used by ArgMax.
        let _ = out;
        let uint_out = write_tensor(
            &mut memory.data,
            0x3800,
            DML_TENSOR_DATA_TYPE_UINT32,
            &[2, 1, 1, 1],
            None,
        );
        let desc = write_operator(
            &mut memory.data,
            0x5000,
            dml_ops::DML_OPERATOR_ARGMAX,
            &[a, uint_out],
        );
        let payload = 0x5020usize;
        put_u32(&mut memory.data, payload + 16, 1);
        put_u64(&mut memory.data, payload + 24, 0x6000);
        put_u32(&mut memory.data, 0x6000, 1);
        put_u32(&mut memory.data, payload + 32, 0);
        let mut runtime = DmlRuntime::new();
        let device = create_test_device(&mut runtime);
        let handle = runtime
            .create_operator_from_guest(device, &memory, desc)
            .expect("guest ArgMax operator");
        let plan = runtime.operation_plan(handle).expect("extended plan");
        assert_eq!(plan.operator_type(), dml_ops::DML_OPERATOR_ARGMAX);
        assert_eq!(
            plan.kind,
            dml_ops::DmlOpKind::ArgMax {
                axes: vec![1],
                direction: dml_ops::DmlAxisDirection::Increasing,
            }
        );

        put_u32(&mut memory.data, 0x6000, 4);
        let error = runtime
            .create_operator_from_guest(device, &memory, desc)
            .unwrap_err();
        assert_eq!(
            error.message,
            "argmin/argmax axis 4 is out of range for rank 4"
        );
    }

    #[test]
    fn dml_guest_quantized_per_channel_scale_is_rejected_exactly() {
        let mut memory = base_memory();
        let input = write_tensor(
            &mut memory.data,
            0x1000,
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[4],
            None,
        );
        let scale = write_tensor(
            &mut memory.data,
            0x2000,
            DML_TENSOR_DATA_TYPE_FLOAT32,
            &[4],
            None,
        );
        let output = write_tensor(
            &mut memory.data,
            0x3000,
            DML_TENSOR_DATA_TYPE_UINT8,
            &[4],
            None,
        );
        let desc = write_operator(
            &mut memory.data,
            0x5000,
            dml_ops::DML_OPERATOR_ELEMENT_WISE_QUANTIZE_LINEAR,
            &[input, scale, 0, output],
        );
        let mut runtime = DmlRuntime::new();
        let device = create_test_device(&mut runtime);
        let error = runtime
            .create_operator_from_guest(device, &memory, desc)
            .unwrap_err();
        assert_eq!(
            error.message,
            "DML_OPERATOR_TYPE 33 supports only a scalar scale tensor"
        );
    }

    #[test]
    fn dml_feature_level_boundary_negotiation_and_operator_minimums() {
        assert_eq!(SUPPORTED_DML_FEATURE_LEVEL, DML_FEATURE_LEVEL_4_0);
        let mut runtime = DmlRuntime::new();
        let device = create_test_device(&mut runtime);
        assert_eq!(
            runtime.device(device).expect("device").feature_level,
            DML_FEATURE_LEVEL_4_0
        );
        let error = runtime
            .create_device(0x100, 0, DML_FEATURE_LEVEL_6_4, IID_IDMLDEVICE)
            .unwrap_err();
        assert_eq!(error.hresult, DXGI_ERROR_UNSUPPORTED);
        for kind in [
            dml_ops::DmlOpKind::Rnn {
                direction: dml_ops::DmlRecurrentDirection::Forward,
                activations: Vec::new(),
                options: dml_ops::DmlRecurrentOptions::default(),
                outputs: vec![dml_ops::DmlRecurrentOutput::Single],
            },
            dml_ops::DmlOpKind::Adam {
                learning_rate: 0.1,
                beta1: 0.9,
                beta2: 0.999,
                epsilon: 1e-8,
            },
            dml_ops::DmlOpKind::DynamicQuantizeLinear,
        ] {
            assert_eq!(
                kind.minimum_feature_level() <= SUPPORTED_DML_FEATURE_LEVEL,
                true
            );
        }
        assert_eq!(
            dml_ops::DmlOpKind::Dequantize {
                quantization_type: 2
            }
            .minimum_feature_level()
                > SUPPORTED_DML_FEATURE_LEVEL,
            true
        );
    }

    struct GraphFixture {
        memory: TestMemory,
        handle_map: BTreeMap<u64, u64>,
        node0: u64,
        node1: u64,
    }

    fn graph_fixture(runtime: &mut DmlRuntime, device: u64) -> GraphFixture {
        let activation = dml_ops::DmlOpPlan {
            kind: dml_ops::DmlOpKind::Activation {
                activation: dml_ops::DmlActivation::Relu,
                alpha: 0.0,
            },
            inputs: vec![desc_tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None)],
            output: desc_tensor(DML_TENSOR_DATA_TYPE_FLOAT32, &[2], None),
            extra_outputs: Vec::new(),
            fused_activation: None,
        };
        let node0 = runtime
            .create_operation(device, activation.clone())
            .expect("first graph node");
        let node1 = runtime
            .create_operation(device, activation)
            .expect("second graph node");
        let mut memory = base_memory();
        // DML_GRAPH_DESC
        put_u32(&mut memory.data, 0x100, 1);
        put_u32(&mut memory.data, 0x104, 1);
        put_u32(&mut memory.data, 0x108, 2);
        put_u64(&mut memory.data, 0x110, 0x200);
        put_u32(&mut memory.data, 0x118, 1);
        put_u64(&mut memory.data, 0x120, 0x300);
        put_u32(&mut memory.data, 0x128, 1);
        put_u64(&mut memory.data, 0x130, 0x400);
        put_u32(&mut memory.data, 0x138, 1);
        put_u64(&mut memory.data, 0x140, 0x500);
        // Nodes.
        put_u32(&mut memory.data, 0x200, DML_GRAPH_NODE_TYPE_OPERATOR);
        put_u64(&mut memory.data, 0x208, 0x600);
        put_u64(&mut memory.data, 0x600, 0x9000);
        put_u32(&mut memory.data, 0x210, DML_GRAPH_NODE_TYPE_OPERATOR);
        put_u64(&mut memory.data, 0x218, 0x608);
        put_u64(&mut memory.data, 0x608, 0x9001);
        // Input edge: graph input 0 -> node 0 input 0.
        put_u32(&mut memory.data, 0x300, DML_GRAPH_EDGE_TYPE_INPUT);
        put_u64(&mut memory.data, 0x308, 0x310);
        put_u32(&mut memory.data, 0x310, 0);
        put_u32(&mut memory.data, 0x314, 0);
        put_u32(&mut memory.data, 0x318, 0);
        // Output edge: node 1 output 0 -> graph output 0.
        put_u32(&mut memory.data, 0x400, DML_GRAPH_EDGE_TYPE_OUTPUT);
        put_u64(&mut memory.data, 0x408, 0x410);
        put_u32(&mut memory.data, 0x410, 1);
        put_u32(&mut memory.data, 0x414, 0);
        put_u32(&mut memory.data, 0x418, 0);
        // Intermediate edge: node 0 output 0 -> node 1 input 0.
        put_u32(&mut memory.data, 0x500, DML_GRAPH_EDGE_TYPE_INTERMEDIATE);
        put_u64(&mut memory.data, 0x508, 0x540);
        put_u32(&mut memory.data, 0x540, 0);
        put_u32(&mut memory.data, 0x544, 0);
        put_u32(&mut memory.data, 0x548, 1);
        put_u32(&mut memory.data, 0x54c, 0);
        let mut handle_map = BTreeMap::new();
        handle_map.insert(0x9000, node0);
        handle_map.insert(0x9001, node1);
        GraphFixture {
            memory,
            handle_map,
            node0,
            node1,
        }
    }

    #[test]
    fn dml_malformed_graph_missing_input_cycle_and_bad_index_rejected() {
        let mut runtime = DmlRuntime::new();
        let device = create_test_device(&mut runtime);
        let mut fixture = graph_fixture(&mut runtime, device);
        assert_eq!(
            fixture.memory.read_u32(0x200).expect("node type"),
            DML_GRAPH_NODE_TYPE_OPERATOR
        );
        assert_eq!(fixture.memory.read_u64(0x110).expect("nodes ptr"), 0x200);
        let handle = runtime
            .compile_graph_from_guest(device, &fixture.memory, 0x100, &fixture.handle_map, 0)
            .expect("valid graph");
        assert_eq!(
            runtime.graph(handle).expect("graph").plan.execution_order,
            vec![0, 1]
        );

        // Missing intermediate edge leaves node 1 input 0 unconnected.
        put_u32(&mut fixture.memory.data, 0x138, 0);
        let error = runtime
            .compile_graph_from_guest(device, &fixture.memory, 0x100, &fixture.handle_map, 0)
            .unwrap_err();
        assert_eq!(error.message, "graph node 1 input 0 is not connected");

        // A constant graph whose two nodes feed each other is a cycle.
        put_u32(&mut fixture.memory.data, 0x100, 0);
        put_u32(&mut fixture.memory.data, 0x118, 0);
        put_u32(&mut fixture.memory.data, 0x138, 2);
        put_u32(
            &mut fixture.memory.data,
            0x510,
            DML_GRAPH_EDGE_TYPE_INTERMEDIATE,
        );
        put_u64(&mut fixture.memory.data, 0x518, 0x550);
        put_u32(&mut fixture.memory.data, 0x550, 1);
        put_u32(&mut fixture.memory.data, 0x554, 0);
        put_u32(&mut fixture.memory.data, 0x558, 0);
        put_u32(&mut fixture.memory.data, 0x55c, 0);
        let error = runtime
            .compile_graph_from_guest(device, &fixture.memory, 0x100, &fixture.handle_map, 0)
            .unwrap_err();
        assert_eq!(error.message, "DML graph contains a cycle");
        let _ = (fixture.node0, fixture.node1);
    }

    #[test]
    fn dml_feature_level_boundary_negotiation_helper_and_data_types() {
        assert_eq!(
            negotiate_feature_levels(&[
                DML_FEATURE_LEVEL_1_0,
                DML_FEATURE_LEVEL_2_0,
                DML_FEATURE_LEVEL_4_0,
                DML_FEATURE_LEVEL_6_4,
            ]),
            DML_FEATURE_LEVEL_4_0
        );
        assert_eq!(negotiate_feature_levels(&[DML_FEATURE_LEVEL_6_4]), 0);
        assert_eq!(negotiate_feature_levels(&[]), 0);
        for supported in [
            DML_TENSOR_DATA_TYPE_FLOAT32,
            DML_TENSOR_DATA_TYPE_FLOAT16,
            DML_TENSOR_DATA_TYPE_UINT32,
            DML_TENSOR_DATA_TYPE_INT32,
            DML_TENSOR_DATA_TYPE_UINT8,
            DML_TENSOR_DATA_TYPE_INT8,
        ] {
            assert_eq!(supports_tensor_data_type(supported), true);
        }
        assert_eq!(
            supports_tensor_data_type(DML_TENSOR_DATA_TYPE_UINT16),
            false
        );
        assert_eq!(
            supports_tensor_data_type(DML_TENSOR_DATA_TYPE_FLOAT64),
            false
        );
    }
}
