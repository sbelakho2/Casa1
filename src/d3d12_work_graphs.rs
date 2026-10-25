//! Real D3D12 Work Graph parsing, validation and host execution planning.
//!
//! Metal has no work-graph primitive. The runtime therefore keeps the full
//! D3D12 work-graph representation (program name, entry points, explicit node
//! definitions and their launch descriptors) and linearises the graph into
//! concrete compute dispatches with the graph's own dispatch grids. A graph
//! whose dispatch the translated command stream cannot represent (GPU-record dispatch
//! requires a GPU virtual address mapping the Metal backend does not expose)
//! fails closed with the exact D3D12 error instead of becoming a no-op.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;

use super::state_objects::StateObjectMemory;

/// D3D12_WORK_GRAPHS_BACKING_MEMORY_ALIGNMENT_IN_BYTES.
pub const WORK_GRAPH_BACKING_MEMORY_ALIGNMENT: u64 = 8;
/// D3D12_WORK_GRAPHS_DISPATCH_MAX_THREAD_GROUPS_PER_GRID.
pub const WORK_GRAPH_MAX_THREAD_GROUPS_PER_GRID: u32 = 16_777_215;
/// D3D12_WORK_GRAPHS_MAX_NODE_DEPTH.
pub const WORK_GRAPH_MAX_NODE_DEPTH: u32 = 32;

pub const D3D12_NODE_TYPE_SHADER: u32 = 0;

pub const NODE_OVERRIDES_NONE: u32 = 0;
pub const NODE_OVERRIDES_BROADCASTING_LAUNCH: u32 = 1;
pub const NODE_OVERRIDES_COALESCING_LAUNCH: u32 = 2;
pub const NODE_OVERRIDES_THREAD_LAUNCH: u32 = 3;
pub const NODE_OVERRIDES_COMMON_COMPUTE: u32 = 4;

pub const WORK_GRAPH_FLAG_NONE: u32 = 0;
pub const WORK_GRAPH_FLAG_INCLUDE_ALL_AVAILABLE_NODES: u32 = 0x1;

pub const D3D12_PROGRAM_TYPE_GENERIC_PIPELINE: u32 = 1;
pub const D3D12_PROGRAM_TYPE_RAYTRACING_PIPELINE: u32 = 4;
pub const D3D12_PROGRAM_TYPE_WORK_GRAPH: u32 = 5;

pub const DISPATCH_MODE_NODE_CPU_INPUT: u32 = 0;
pub const DISPATCH_MODE_NODE_GPU_INPUT: u32 = 1;
pub const DISPATCH_MODE_MULTI_NODE_CPU_INPUT: u32 = 2;
pub const DISPATCH_MODE_MULTI_NODE_GPU_INPUT: u32 = 3;

/// D3D12_NODE_ID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct D3d12NodeId {
    pub name: String,
    pub array_index: u32,
}

impl D3d12NodeId {
    pub fn new(name: impl Into<String>, array_index: u32) -> Self {
        Self {
            name: name.into(),
            array_index,
        }
    }
}

/// D3D12_NODE_OUTPUT_OVERRIDES.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct D3d12NodeOutputOverrides {
    pub output_index: u32,
    pub new_name: Option<D3d12NodeId>,
    pub allow_sparse_nodes: Option<bool>,
    pub max_records: Option<u32>,
    pub max_records_shared_with_output_index: Option<u32>,
}

/// D3D12_BROADCASTING_LAUNCH_OVERRIDES.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct D3d12BroadcastingLaunchOverrides {
    pub local_root_arguments_table_index: Option<u32>,
    pub program_entry: Option<bool>,
    pub new_name: Option<D3d12NodeId>,
    pub share_input_of: Option<D3d12NodeId>,
    pub dispatch_grid: Option<[u32; 3]>,
    pub max_dispatch_grid: Option<[u32; 3]>,
    pub output_overrides: Vec<D3d12NodeOutputOverrides>,
}

/// D3D12_COALESCING_LAUNCH_OVERRIDES.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct D3d12CoalescingLaunchOverrides {
    pub local_root_arguments_table_index: Option<u32>,
    pub program_entry: Option<bool>,
    pub new_name: Option<D3d12NodeId>,
    pub share_input_of: Option<D3d12NodeId>,
    pub output_overrides: Vec<D3d12NodeOutputOverrides>,
}

/// D3D12_THREAD_LAUNCH_OVERRIDES.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct D3d12ThreadLaunchOverrides {
    pub local_root_arguments_table_index: Option<u32>,
    pub program_entry: Option<bool>,
    pub new_name: Option<D3d12NodeId>,
    pub share_input_of: Option<D3d12NodeId>,
    pub output_overrides: Vec<D3d12NodeOutputOverrides>,
}

/// D3D12_COMMON_COMPUTE_NODE_OVERRIDES.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct D3d12CommonComputeNodeOverrides {
    pub local_root_arguments_table_index: Option<u32>,
    pub program_entry: Option<bool>,
    pub new_name: Option<D3d12NodeId>,
    pub share_input_of: Option<D3d12NodeId>,
    pub output_overrides: Vec<D3d12NodeOutputOverrides>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum D3d12NodeOverrides {
    None,
    Broadcasting(D3d12BroadcastingLaunchOverrides),
    Coalescing(D3d12CoalescingLaunchOverrides),
    Thread(D3d12ThreadLaunchOverrides),
    CommonCompute(D3d12CommonComputeNodeOverrides),
}

impl D3d12NodeOverrides {
    pub fn program_entry(&self) -> Option<bool> {
        match self {
            Self::None => None,
            Self::Broadcasting(o) => o.program_entry,
            Self::Coalescing(o) => o.program_entry,
            Self::Thread(o) => o.program_entry,
            Self::CommonCompute(o) => o.program_entry,
        }
    }

    pub fn dispatch_grid(&self) -> Option<[u32; 3]> {
        match self {
            Self::Broadcasting(o) => o.dispatch_grid,
            _ => None,
        }
    }

    pub fn max_dispatch_grid(&self) -> Option<[u32; 3]> {
        match self {
            Self::Broadcasting(o) => o.max_dispatch_grid,
            _ => None,
        }
    }
}

/// One explicitly defined D3D12_SHADER_NODE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3d12WorkGraphNode {
    pub shader: String,
    pub overrides: D3d12NodeOverrides,
}

/// D3D12_WORK_GRAPH_MEMORY_REQUIREMENTS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3d12WorkGraphMemoryRequirements {
    pub min_size_in_bytes: u64,
    pub max_size_in_bytes: u64,
    pub size_granularity_in_bytes: u32,
}

/// D3D12_WORK_GRAPH_DESC.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct D3d12WorkGraph {
    pub program_name: String,
    pub flags: u32,
    pub entrypoints: Vec<D3d12NodeId>,
    pub nodes: Vec<D3d12WorkGraphNode>,
}

/// A concrete compute dispatch derived from one work-graph node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D3d12WorkGraphDispatch {
    pub entrypoint_index: u32,
    pub node_index: u32,
    pub grid: [u32; 3],
    pub record_count: u32,
}

impl D3d12WorkGraph {
    /// Parse a D3D12_WORK_GRAPH_DESC from guest memory.
    pub fn parse(memory: &dyn StateObjectMemory, desc: u64) -> AppResult<Self> {
        if desc == 0 {
            return Err(invalid("work graph description pointer is null"));
        }
        let program_name = memory.read_wide_string(memory.read_u64(desc)?)?;
        if program_name.is_empty() {
            return Err(invalid("work graph ProgramName is empty"));
        }
        let flags = memory.read_u32(desc + 8)?;
        if flags & !WORK_GRAPH_FLAG_INCLUDE_ALL_AVAILABLE_NODES != 0 {
            return Err(invalid(format!(
                "work graph flags {flags:#x} contain undefined bits"
            )));
        }
        let num_entrypoints = memory.read_u32(desc + 12)?;
        let entrypoints_ptr = memory.read_u64(desc + 16)?;
        if num_entrypoints > 65_535 {
            return Err(invalid(format!(
                "work graph NumEntrypoints {num_entrypoints} exceeds the supported limit"
            )));
        }
        if num_entrypoints > 0 && entrypoints_ptr == 0 {
            return Err(invalid("work graph pEntrypoints is null"));
        }
        let mut entrypoints = Vec::with_capacity(num_entrypoints as usize);
        for index in 0..num_entrypoints as u64 {
            let entrypoint = read_node_id(memory, entrypoints_ptr + index * 16)?;
            if entrypoint.name.is_empty() {
                return Err(invalid("work graph entry point has an empty name"));
            }
            entrypoints.push(entrypoint);
        }

        let num_nodes = memory.read_u32(desc + 24)?;
        let nodes_ptr = memory.read_u64(desc + 32)?;
        if num_nodes > 65_535 {
            return Err(invalid(format!(
                "work graph NumExplicitlyDefinedNodes {num_nodes} exceeds the supported limit"
            )));
        }
        if num_nodes > 0 && nodes_ptr == 0 {
            return Err(invalid("work graph pExplicitlyDefinedNodes is null"));
        }
        let mut nodes = Vec::with_capacity(num_nodes as usize);
        for index in 0..num_nodes as u64 {
            nodes.push(parse_node(memory, nodes_ptr + index * 32)?);
        }
        if nodes.is_empty()
            && flags & WORK_GRAPH_FLAG_INCLUDE_ALL_AVAILABLE_NODES == 0
            && entrypoints.is_empty()
        {
            return Err(invalid(
                "work graph has no nodes or entrypoints and does not include all available nodes",
            ));
        }

        Ok(Self {
            program_name,
            flags,
            entrypoints,
            nodes,
        })
    }

    /// D3D12_WORK_GRAPH_MEMORY_REQUIREMENTS for this graph.
    ///
    /// `MinSizeInBytes` covers the node metadata the runtime allocates;
    /// `MaxSizeInBytes` adds the backing store for every node's maximum
    /// dispatch grid. The granularity is the D3D12 work-graph alignment.
    pub fn memory_requirements(&self) -> D3d12WorkGraphMemoryRequirements {
        let entrypoint_bytes = self.entrypoints.len() as u64 * 16;
        let node_bytes = self.nodes.len() as u64 * 64;
        let mut backing = 0u64;
        for node in &self.nodes {
            let grid = node
                .overrides
                .max_dispatch_grid()
                .or_else(|| node.overrides.dispatch_grid())
                .unwrap_or([1, 1, 1]);
            let groups = (grid[0] as u64)
                .saturating_mul(grid[1] as u64)
                .saturating_mul(grid[2] as u64);
            backing = backing.saturating_add(groups.saturating_mul(16));
        }
        let min_size_in_bytes = node_bytes.saturating_add(entrypoint_bytes).max(1);
        D3d12WorkGraphMemoryRequirements {
            min_size_in_bytes,
            max_size_in_bytes: min_size_in_bytes.saturating_add(backing),
            size_granularity_in_bytes: WORK_GRAPH_BACKING_MEMORY_ALIGNMENT as u32,
        }
    }

    /// Validate a work-graph backing-memory range.
    pub fn validate_backing_memory(&self, offset: u64, size: u64) -> AppResult<()> {
        if offset % WORK_GRAPH_BACKING_MEMORY_ALIGNMENT != 0 {
            return Err(invalid(format!(
                "work graph backing memory offset {offset} is not aligned to \
                 {WORK_GRAPH_BACKING_MEMORY_ALIGNMENT} bytes"
            )));
        }
        if offset.checked_add(size).is_none() {
            return Err(invalid("work graph backing memory range overflows"));
        }
        let requirements = self.memory_requirements();
        if size < requirements.min_size_in_bytes {
            return Err(invalid(format!(
                "work graph backing memory size {size} is smaller than the minimum {}",
                requirements.min_size_in_bytes
            )));
        }
        Ok(())
    }

    pub fn entrypoint_index(&self, id: &D3d12NodeId) -> Option<u32> {
        self.entrypoints
            .iter()
            .position(|entry| entry == id)
            .map(|i| i as u32)
    }

    /// Build the concrete dispatch sequence for one entry point.
    ///
    /// D3D12 starts execution at an entry point; downstream nodes are
    /// activated by records. Because the bridge cannot follow record fan-out
    /// through guest memory, the host dispatches every node that is either the
    /// selected entry point, marked as a program entry, or requested by
    /// `INCLUDE_ALL_AVAILABLE_NODES`. Each such node is issued as a real
    /// compute dispatch sized from its broadcasting dispatch grid (falling
    /// back to one thread group per record).
    pub fn dispatch_plan(
        &self,
        entrypoint_index: u32,
        record_count: u32,
        record_stride: u64,
    ) -> AppResult<Vec<D3d12WorkGraphDispatch>> {
        let entry = self
            .entrypoints
            .get(entrypoint_index as usize)
            .ok_or_else(|| {
                invalid(format!(
                    "work graph entrypoint index {entrypoint_index} is out of range ({} entries)",
                    self.entrypoints.len()
                ))
            })?;
        if record_count > 0 && record_stride == 0 {
            return Err(invalid("work graph record stride is zero"));
        }
        if record_count == 0 {
            return Ok(Vec::new());
        }

        let include_all = self.flags & WORK_GRAPH_FLAG_INCLUDE_ALL_AVAILABLE_NODES != 0;
        let mut plan = Vec::new();
        for (node_index, node) in self.nodes.iter().enumerate() {
            let node_name = node.overrides_name();
            let selected =
                include_all || node.overrides.program_entry() == Some(true) || &node_name == entry;
            if !selected {
                continue;
            }
            let grid = node
                .overrides
                .dispatch_grid()
                .unwrap_or([record_count, 1, 1]);
            if grid
                .iter()
                .any(|dim| *dim > WORK_GRAPH_MAX_THREAD_GROUPS_PER_GRID)
            {
                return Err(invalid(format!(
                    "work graph node {node_index} dispatch grid {grid:?} exceeds the \
                     per-dimension limit {WORK_GRAPH_MAX_THREAD_GROUPS_PER_GRID}"
                )));
            }
            if grid.contains(&0) {
                continue;
            }
            plan.push(D3d12WorkGraphDispatch {
                entrypoint_index,
                node_index: node_index as u32,
                grid,
                record_count,
            });
        }
        Ok(plan)
    }

    /// One CPU-side record for a dispatch-graph call.
    pub fn validate_cpu_records(
        &self,
        entrypoint_index: u32,
        record_count: u32,
        record_stride: u64,
        available: usize,
    ) -> AppResult<()> {
        if self.entrypoints.get(entrypoint_index as usize).is_none() {
            return Err(invalid(format!(
                "work graph entrypoint index {entrypoint_index} is out of range"
            )));
        }
        if record_count == 0 {
            return Ok(());
        }
        if record_stride == 0 {
            return Err(invalid("work graph record stride is zero"));
        }
        let required = (record_count as u64)
            .checked_mul(record_stride)
            .ok_or_else(|| invalid("work graph record range overflows"))?;
        if required > available as u64 {
            return Err(invalid(format!(
                "work graph record range ({required} bytes) exceeds the supplied \
                 {available} bytes"
            )));
        }
        Ok(())
    }
}

impl D3d12WorkGraphNode {
    fn overrides_name(&self) -> D3d12NodeId {
        let renamed = match &self.overrides {
            D3d12NodeOverrides::None => None,
            D3d12NodeOverrides::Broadcasting(o) => o.new_name.clone(),
            D3d12NodeOverrides::Coalescing(o) => o.new_name.clone(),
            D3d12NodeOverrides::Thread(o) => o.new_name.clone(),
            D3d12NodeOverrides::CommonCompute(o) => o.new_name.clone(),
        };
        renamed.unwrap_or_else(|| D3d12NodeId::new(self.shader.clone(), 0))
    }
}

/// D3D12_DISPATCH_GRAPH_DESC, CPU modes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3d12DispatchGraphDesc {
    pub mode: u32,
    pub entrypoint_index: u32,
    pub record_count: u32,
    pub record_stride: u64,
    pub records: Vec<u8>,
}

impl D3d12DispatchGraphDesc {
    pub fn parse_cpu(memory: &dyn StateObjectMemory, desc: u64) -> AppResult<Self> {
        let mut entries = Self::parse_entries(memory, desc)?;
        if entries.is_empty() {
            return Err(invalid("dispatch graph contains no node inputs"));
        }
        Ok(entries.remove(0))
    }

    /// Parse every node input of a dispatch-graph description.
    ///
    /// CPU inputs carry the record bytes in guest memory; GPU inputs name a
    /// GPU virtual address. Both are materialised into `records` so the GPU
    /// fan-out executor can consume them without per-record CPU dispatches.
    pub fn parse_entries(memory: &dyn StateObjectMemory, desc: u64) -> AppResult<Vec<Self>> {
        if desc == 0 {
            return Err(invalid("dispatch graph description pointer is null"));
        }
        let mode = memory.read_u32(desc)?;
        match mode {
            DISPATCH_MODE_NODE_CPU_INPUT => Ok(vec![Self::parse_node(memory, desc + 8, mode)?]),
            DISPATCH_MODE_MULTI_NODE_CPU_INPUT => Self::parse_multi(memory, desc + 8, mode),
            DISPATCH_MODE_NODE_GPU_INPUT => Ok(vec![Self::parse_node(memory, desc + 8, mode)?]),
            DISPATCH_MODE_MULTI_NODE_GPU_INPUT => Self::parse_multi(memory, desc + 8, mode),
            other => Err(invalid(format!(
                "D3D12_DISPATCH_GRAPH_DESC mode {other} is not defined"
            ))),
        }
    }

    fn parse_multi(memory: &dyn StateObjectMemory, base: u64, mode: u32) -> AppResult<Vec<Self>> {
        let count = memory.read_u32(base)?;
        let pointer = memory.read_u64(base + 8)?;
        if count == 0 {
            return Ok(Vec::new());
        }
        if pointer == 0 {
            return Err(invalid("dispatch graph node input array is null"));
        }
        let mut entries = Vec::with_capacity(count as usize);
        for index in 0..count as u64 {
            entries.push(Self::parse_node(memory, pointer + index * 24, mode)?);
        }
        Ok(entries)
    }

    fn parse_node(memory: &dyn StateObjectMemory, base: u64, mode: u32) -> AppResult<Self> {
        // D3D12_NODE_CPU_INPUT / D3D12_NODE_GPU_INPUT:
        // +0 EntrypointIndex, +4 NumRecords, +8 pRecords, +16 RecordStrideInBytes
        let entrypoint_index = memory.read_u32(base)?;
        let record_count = memory.read_u32(base + 4)?;
        let records_ptr = memory.read_u64(base + 8)?;
        let record_stride = memory.read_u64(base + 16)?;
        if record_count > 0 && records_ptr == 0 {
            return Err(invalid("dispatch graph pRecords is null"));
        }
        let gpu = matches!(
            mode,
            DISPATCH_MODE_NODE_GPU_INPUT | DISPATCH_MODE_MULTI_NODE_GPU_INPUT
        );
        if gpu && record_count > 0 && record_stride == 0 {
            return Err(invalid("dispatch graph record stride is zero"));
        }
        let required = (record_count as u64)
            .checked_mul(record_stride)
            .ok_or_else(|| invalid("dispatch graph record range overflows"))?;
        if required > 64 * 1024 * 1024 {
            return Err(invalid(format!(
                "dispatch graph record range {required} bytes exceeds the 64 MiB limit"
            )));
        }
        let records = if required == 0 {
            Vec::new()
        } else {
            memory.read_bytes(records_ptr, required as usize)?
        };
        Ok(Self {
            mode,
            entrypoint_index,
            record_count,
            record_stride,
            records,
        })
    }
}

fn read_node_id(memory: &dyn StateObjectMemory, address: u64) -> AppResult<D3d12NodeId> {
    let name_ptr = memory.read_u64(address)?;
    let name = if name_ptr == 0 {
        String::new()
    } else {
        memory.read_wide_string(name_ptr)?
    };
    Ok(D3d12NodeId {
        name,
        array_index: memory.read_u32(address + 8)?,
    })
}

fn parse_node(memory: &dyn StateObjectMemory, address: u64) -> AppResult<D3d12WorkGraphNode> {
    let node_type = memory.read_u32(address)?;
    if node_type != D3D12_NODE_TYPE_SHADER {
        return Err(invalid(format!(
            "work graph node type {node_type} is not D3D12_NODE_TYPE_SHADER"
        )));
    }
    // D3D12_SHADER_NODE lives at +8 inside D3D12_NODE on x64.
    let shader_ptr = memory.read_u64(address + 8)?;
    if shader_ptr == 0 {
        return Err(invalid("work graph shader node has a null Shader name"));
    }
    let shader = memory.read_wide_string(shader_ptr)?;
    if shader.is_empty() {
        return Err(invalid("work graph shader node has an empty Shader name"));
    }
    let overrides_type = memory.read_u32(address + 16)?;
    let overrides_ptr = memory.read_u64(address + 24)?;
    let overrides = match overrides_type {
        NODE_OVERRIDES_NONE => D3d12NodeOverrides::None,
        NODE_OVERRIDES_BROADCASTING_LAUNCH => {
            D3d12NodeOverrides::Broadcasting(parse_broadcasting_overrides(memory, overrides_ptr)?)
        }
        NODE_OVERRIDES_COALESCING_LAUNCH => {
            parse_simple_overrides(memory, overrides_ptr, SimpleOverridesKind::Coalescing)?
        }
        NODE_OVERRIDES_THREAD_LAUNCH => {
            parse_simple_overrides(memory, overrides_ptr, SimpleOverridesKind::Thread)?
        }
        NODE_OVERRIDES_COMMON_COMPUTE => {
            parse_simple_overrides(memory, overrides_ptr, SimpleOverridesKind::CommonCompute)?
        }
        other => {
            return Err(invalid(format!(
                "work graph node overrides type {other} is not defined"
            )));
        }
    };
    Ok(D3d12WorkGraphNode { shader, overrides })
}

fn parse_broadcasting_overrides(
    memory: &dyn StateObjectMemory,
    address: u64,
) -> AppResult<D3d12BroadcastingLaunchOverrides> {
    if address == 0 {
        return Err(invalid("broadcasting launch overrides pointer is null"));
    }
    let mut output_overrides = Vec::new();
    let count = memory.read_u32(address + 48)?;
    let ptr = memory.read_u64(address + 56)?;
    if count > 0 && ptr == 0 {
        return Err(invalid(
            "broadcasting launch output overrides pointer is null",
        ));
    }
    for index in 0..count as u64 {
        output_overrides.push(parse_output_overrides(memory, ptr + index * 40)?);
    }
    let dispatch_grid = read_grid(memory, memory.read_u64(address + 32)?)?;
    let max_dispatch_grid = read_grid(memory, memory.read_u64(address + 40)?)?;
    validate_grid(dispatch_grid)?;
    validate_grid(max_dispatch_grid)?;
    Ok(D3d12BroadcastingLaunchOverrides {
        local_root_arguments_table_index: read_optional_u32(memory, memory.read_u64(address)?)?,
        program_entry: read_optional_bool(memory, memory.read_u64(address + 8)?)?,
        new_name: read_optional_node_id(memory, memory.read_u64(address + 16)?)?,
        share_input_of: read_optional_node_id(memory, memory.read_u64(address + 24)?)?,
        dispatch_grid,
        max_dispatch_grid,
        output_overrides,
    })
}

enum SimpleOverridesKind {
    Coalescing,
    Thread,
    CommonCompute,
}

fn parse_simple_overrides(
    memory: &dyn StateObjectMemory,
    address: u64,
    kind: SimpleOverridesKind,
) -> AppResult<D3d12NodeOverrides> {
    if address == 0 {
        return Err(invalid("work graph node overrides pointer is null"));
    }
    let mut output_overrides = Vec::new();
    let count = memory.read_u32(address + 32)?;
    let ptr = memory.read_u64(address + 40)?;
    if count > 0 && ptr == 0 {
        return Err(invalid("work graph output overrides pointer is null"));
    }
    for index in 0..count as u64 {
        output_overrides.push(parse_output_overrides(memory, ptr + index * 40)?);
    }
    let local_root_arguments_table_index = read_optional_u32(memory, memory.read_u64(address)?)?;
    let program_entry = read_optional_bool(memory, memory.read_u64(address + 8)?)?;
    let new_name = read_optional_node_id(memory, memory.read_u64(address + 16)?)?;
    let share_input_of = read_optional_node_id(memory, memory.read_u64(address + 24)?)?;
    Ok(match kind {
        SimpleOverridesKind::Coalescing => {
            D3d12NodeOverrides::Coalescing(D3d12CoalescingLaunchOverrides {
                local_root_arguments_table_index,
                program_entry,
                new_name,
                share_input_of,
                output_overrides,
            })
        }
        SimpleOverridesKind::Thread => D3d12NodeOverrides::Thread(D3d12ThreadLaunchOverrides {
            local_root_arguments_table_index,
            program_entry,
            new_name,
            share_input_of,
            output_overrides,
        }),
        SimpleOverridesKind::CommonCompute => {
            D3d12NodeOverrides::CommonCompute(D3d12CommonComputeNodeOverrides {
                local_root_arguments_table_index,
                program_entry,
                new_name,
                share_input_of,
                output_overrides,
            })
        }
    })
}

fn parse_output_overrides(
    memory: &dyn StateObjectMemory,
    address: u64,
) -> AppResult<D3d12NodeOutputOverrides> {
    let shared = read_optional_u32(memory, memory.read_u64(address + 32)?)?;
    Ok(D3d12NodeOutputOverrides {
        output_index: memory.read_u32(address)?,
        new_name: read_optional_node_id(memory, memory.read_u64(address + 8)?)?,
        allow_sparse_nodes: read_optional_bool(memory, memory.read_u64(address + 16)?)?,
        max_records: read_optional_u32(memory, memory.read_u64(address + 24)?)?,
        max_records_shared_with_output_index: shared,
    })
}

fn read_grid(memory: &dyn StateObjectMemory, address: u64) -> AppResult<Option<[u32; 3]>> {
    if address == 0 {
        return Ok(None);
    }
    Ok(Some([
        memory.read_u32(address)?,
        memory.read_u32(address + 4)?,
        memory.read_u32(address + 8)?,
    ]))
}

fn validate_grid(grid: Option<[u32; 3]>) -> AppResult<()> {
    if let Some(grid) = grid
        && grid
            .iter()
            .any(|dim| *dim > WORK_GRAPH_MAX_THREAD_GROUPS_PER_GRID)
    {
        return Err(invalid(format!(
            "work graph dispatch grid {grid:?} exceeds the per-dimension limit \
             {WORK_GRAPH_MAX_THREAD_GROUPS_PER_GRID}"
        )));
    }
    Ok(())
}

fn read_optional_u32(memory: &dyn StateObjectMemory, address: u64) -> AppResult<Option<u32>> {
    if address == 0 {
        Ok(None)
    } else {
        Ok(Some(memory.read_u32(address)?))
    }
}

fn read_optional_bool(memory: &dyn StateObjectMemory, address: u64) -> AppResult<Option<bool>> {
    if address == 0 {
        Ok(None)
    } else {
        Ok(Some(memory.read_u32(address)? != 0))
    }
}

fn read_optional_node_id(
    memory: &dyn StateObjectMemory,
    address: u64,
) -> AppResult<Option<D3d12NodeId>> {
    if address == 0 {
        Ok(None)
    } else {
        Ok(Some(read_node_id(memory, address)?))
    }
}

fn invalid(message: impl Into<String>) -> AppError {
    AppError::new(ReasonCode::RcD3dInvalidState, message)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn put_wide(data: &mut [u8], offset: usize, value: &str) {
        for (index, unit) in value.encode_utf16().enumerate() {
            data[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }

    fn base_memory() -> TestMemory {
        TestMemory {
            data: vec![0u8; 0x8000],
        }
    }

    fn write_desc(
        data: &mut [u8],
        flags: u32,
        num_entrypoints: u32,
        entrypoints: u64,
        num_nodes: u32,
        nodes: u64,
    ) -> u64 {
        put_u64(data, 0x200, 0x100);
        put_u32(data, 0x208, flags);
        put_u32(data, 0x20c, num_entrypoints);
        put_u64(data, 0x210, entrypoints);
        put_u32(data, 0x218, num_nodes);
        put_u64(data, 0x220, nodes);
        0x200
    }

    fn write_name(data: &mut [u8], offset: usize, value: &str) {
        for (index, unit) in value.encode_utf16().enumerate() {
            data[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }

    fn write_node_id(data: &mut [u8], offset: usize, name: u64, array_index: u32) {
        put_u64(data, offset, name);
        put_u32(data, offset + 8, array_index);
    }

    fn write_output_override(
        data: &mut [u8],
        offset: usize,
        new_name: u64,
        sparse: u64,
        max_records: u64,
        shared_records: u64,
    ) {
        put_u32(data, offset, 0);
        put_u64(data, offset + 8, new_name);
        put_u64(data, offset + 16, sparse);
        put_u64(data, offset + 24, max_records);
        put_u64(data, offset + 32, shared_records);
    }

    fn write_broadcasting_overrides(data: &mut [u8], offset: usize) {
        put_u64(data, offset, 0x3100);
        put_u64(data, offset + 8, 0x3110);
        put_u64(data, offset + 16, 0x3120);
        put_u64(data, offset + 24, 0x3130);
        put_u64(data, offset + 32, 0x3140);
        put_u64(data, offset + 40, 0x3150);
        put_u32(data, offset + 48, 1);
        put_u64(data, offset + 56, 0x3160);
    }

    fn write_simple_overrides(data: &mut [u8], offset: usize) {
        put_u64(data, offset, 0x3700);
        put_u64(data, offset + 8, 0x3710);
        put_u64(data, offset + 16, 0x3720);
        put_u64(data, offset + 24, 0x3730);
        put_u32(data, offset + 32, 1);
        put_u64(data, offset + 40, 0x3740);
    }

    fn all_overrides_memory() -> (TestMemory, u64) {
        let mut memory = base_memory();
        let data = &mut memory.data;
        let desc = 0x200u64;
        let nodes = 0x400u64;
        put_wide(data, 0x100, "graph");
        put_wide(data, 0x1000, "entry");
        put_wide(data, 0x1100, "node0");
        put_wide(data, 0x1200, "out");
        put_wide(data, 0x1300, "c");
        put_wide(data, 0x1400, "c2");
        write_node_id(data, 0x300, 0x1000, 0);
        // Broadcasting node.
        put_u32(data, nodes as usize, D3D12_NODE_TYPE_SHADER);
        put_u64(data, nodes as usize + 8, 0x1100);
        put_u32(
            data,
            nodes as usize + 16,
            NODE_OVERRIDES_BROADCASTING_LAUNCH,
        );
        put_u64(data, nodes as usize + 24, 0x3000);
        write_broadcasting_overrides(data, 0x3000);
        put_u32(data, 0x3110, 1);
        write_node_id(data, 0x3120, 0x1000, 0);
        write_node_id(data, 0x3130, 0x1100, 0);
        put_u32(data, 0x3140, 2);
        put_u32(data, 0x3144, 1);
        put_u32(data, 0x3148, 1);
        put_u32(data, 0x3150, 2);
        put_u32(data, 0x3154, 2);
        put_u32(data, 0x3158, 1);
        put_u32(data, 0x3100, 7);
        write_output_override(data, 0x3160, 0x3600, 0x3620, 0x3630, 0x3640);
        write_node_id(data, 0x3600, 0x1200, 0);
        put_u32(data, 0x3620, 1);
        put_u32(data, 0x3630, 5);
        put_u32(data, 0x3640, 3);
        // Coalescing node.
        let node1 = nodes as usize + 0x20;
        put_u32(data, node1, D3D12_NODE_TYPE_SHADER);
        put_u64(data, node1 + 8, 0x1300);
        put_u32(data, node1 + 16, NODE_OVERRIDES_COALESCING_LAUNCH);
        put_u64(data, node1 + 24, 0x3200);
        write_simple_overrides(data, 0x3200);
        put_u32(data, 0x3700, 1);
        put_u32(data, 0x3710, 0);
        write_node_id(data, 0x3720, 0x1300, 0);
        write_node_id(data, 0x3730, 0x1400, 0);
        write_output_override(data, 0x3740, 0x3780, 0x37a0, 0x37b0, 0x37c0);
        // Thread node.
        let node2 = nodes as usize + 0x40;
        put_u32(data, node2, D3D12_NODE_TYPE_SHADER);
        put_u64(data, node2 + 8, 0x1100);
        put_u32(data, node2 + 16, NODE_OVERRIDES_THREAD_LAUNCH);
        put_u64(data, node2 + 24, 0x3200);
        // Common-compute node.
        let node3 = nodes as usize + 0x60;
        put_u32(data, node3, D3D12_NODE_TYPE_SHADER);
        put_u64(data, node3 + 8, 0x1100);
        put_u32(data, node3 + 16, NODE_OVERRIDES_COMMON_COMPUTE);
        put_u64(data, node3 + 24, 0x3200);
        put_u64(data, desc as usize, 0x100);
        put_u32(data, desc as usize + 8, 0);
        put_u32(data, desc as usize + 12, 1);
        put_u64(data, desc as usize + 16, 0x300);
        put_u32(data, desc as usize + 24, 4);
        put_u64(data, desc as usize + 32, nodes);
        (memory, desc)
    }

    #[test]
    fn work_graph_parser_covers_all_override_variants_and_rejects_malformed_nodes() {
        let (memory, desc) = all_overrides_memory();
        let graph = D3d12WorkGraph::parse(&memory, desc).expect("valid graph");
        assert_eq!(graph.program_name, "graph");
        assert_eq!(graph.entrypoints.len(), 1);
        assert_eq!(graph.nodes.len(), 4);
        assert_eq!(
            graph.entrypoint_index(&D3d12NodeId::new("entry", 0)),
            Some(0)
        );
        assert_eq!(
            graph.entrypoint_index(&D3d12NodeId::new("missing", 0)),
            None
        );
        let requirements = graph.memory_requirements();
        assert_eq!(requirements.size_granularity_in_bytes, 8);
        assert_eq!(requirements.min_size_in_bytes, 4 * 64 + 16);
        graph
            .validate_backing_memory(0, requirements.min_size_in_bytes)
            .expect("valid backing memory");
        let plan = graph.dispatch_plan(0, 2, 8).expect("dispatch plan");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].grid, [2, 1, 1]);
        assert_eq!(plan[0].record_count, 2);
        graph.validate_cpu_records(0, 2, 8, 16).expect("records");
        let error = graph.validate_cpu_records(1, 2, 8, 16).unwrap_err();
        assert_eq!(
            error.message,
            "work graph entrypoint index 1 is out of range"
        );
        let error = graph.validate_cpu_records(0, 2, 0, 16).unwrap_err();
        assert_eq!(error.message, "work graph record stride is zero");
        let error = graph.validate_cpu_records(0, 3, 8, 16).unwrap_err();
        assert_eq!(
            error.message,
            "work graph record range (24 bytes) exceeds the supplied 16 bytes"
        );
        graph
            .validate_cpu_records(0, 0, 0, 0)
            .expect("zero records");
        let error = graph.dispatch_plan(9, 2, 8).unwrap_err();
        assert_eq!(
            error.message,
            "work graph entrypoint index 9 is out of range (1 entries)"
        );
        let error = graph.dispatch_plan(0, 2, 0).unwrap_err();
        assert_eq!(error.message, "work graph record stride is zero");
        assert!(graph.dispatch_plan(0, 0, 8).unwrap().is_empty());
        let error = graph
            .validate_backing_memory(1, requirements.min_size_in_bytes)
            .unwrap_err();
        assert_eq!(
            error.message,
            "work graph backing memory offset 1 is not aligned to 8 bytes"
        );
        let error = graph.validate_backing_memory(u64::MAX - 7, 8).unwrap_err();
        assert_eq!(error.message, "work graph backing memory range overflows");
        let error = graph.validate_backing_memory(0, 1).unwrap_err();
        assert_eq!(
            error.message,
            format!(
                "work graph backing memory size 1 is smaller than the minimum {}",
                requirements.min_size_in_bytes
            )
        );

        // All optional accessors are exercised directly.
        let node = &graph.nodes[0];
        assert_eq!(node.overrides.program_entry(), Some(true));
        assert_eq!(node.overrides.dispatch_grid(), Some([2, 1, 1]));
        assert_eq!(node.overrides.max_dispatch_grid(), Some([2, 2, 1]));
        assert_eq!(graph.nodes[1].overrides.program_entry(), Some(false));
        assert_eq!(graph.nodes[1].overrides.dispatch_grid(), None);
        assert_eq!(graph.nodes[2].overrides.program_entry(), Some(false));
        assert_eq!(graph.nodes[3].overrides.program_entry(), Some(false));
        assert_eq!(
            graph.nodes[0].overrides_name(),
            D3d12NodeId::new("entry", 0)
        );

        // Dispatch plan skips a selected node whose grid has a zero dimension.
        let mut zero_grid = graph.clone();
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut zero_grid.nodes[0].overrides {
            overrides.dispatch_grid = Some([0, 1, 1]);
        }
        assert!(zero_grid.dispatch_plan(0, 2, 8).unwrap().is_empty());
        // Selected node with an over-limit grid fails closed.
        let mut over_limit = graph.clone();
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut over_limit.nodes[0].overrides {
            overrides.dispatch_grid = Some([16_777_216, 1, 1]);
        }
        let error = over_limit.dispatch_plan(0, 2, 8).unwrap_err();
        assert_eq!(
            error.message,
            "work graph node 0 dispatch grid [16777216, 1, 1] exceeds the per-dimension limit 16777215"
        );
        // INCLUDE_ALL_AVAILABLE_NODES selects otherwise-unselected nodes.
        let mut include_all = graph.clone();
        include_all.flags = WORK_GRAPH_FLAG_INCLUDE_ALL_AVAILABLE_NODES;
        assert_eq!(include_all.dispatch_plan(0, 2, 8).unwrap().len(), 4);

        // All-None override fields exercise optional readers.
        let (mut no_optionals, desc) = all_overrides_memory();
        put_u64(&mut no_optionals.data, 0x400 + 24, 0x3900);
        let graph = D3d12WorkGraph::parse(&no_optionals, desc).expect("null optionals");
        match &graph.nodes[0].overrides {
            D3d12NodeOverrides::Broadcasting(overrides) => {
                assert_eq!(overrides.local_root_arguments_table_index, None);
                assert_eq!(overrides.program_entry, None);
                assert_eq!(overrides.new_name, None);
                assert_eq!(overrides.share_input_of, None);
                assert_eq!(overrides.dispatch_grid, None);
                assert_eq!(overrides.max_dispatch_grid, None);
                assert!(overrides.output_overrides.is_empty());
            }
            other => panic!("unexpected overrides: {other:?}"),
        }

        let mut output_memory = TestMemory {
            data: vec![0u8; 0x5000],
        };
        put_u32(&mut output_memory.data, 0x300, 7);
        put_u64(&mut output_memory.data, 0x320, 0x440);
        put_u32(&mut output_memory.data, 0x440, 3);
        let output = parse_output_overrides(&output_memory, 0x300).expect("output overrides");
        assert_eq!(output.output_index, 7);
        assert_eq!(output.new_name, None);
        assert_eq!(output.allow_sparse_nodes, None);
        assert_eq!(output.max_records, None);
        assert_eq!(output.max_records_shared_with_output_index, Some(3));

        // Parser error paths, each pinned exactly.
        let error = D3d12WorkGraph::parse(&memory, 0).unwrap_err();
        assert_eq!(error.message, "work graph description pointer is null");
        let (mut broken, desc) = all_overrides_memory();
        put_u64(&mut broken.data, 0x200, 0);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(error.message, "work graph ProgramName is empty");
        let (mut broken, desc) = all_overrides_memory();
        put_u32(&mut broken.data, 0x208, 2);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(error.message, "work graph flags 0x2 contain undefined bits");
        let (mut broken, desc) = all_overrides_memory();
        put_u32(&mut broken.data, 0x20c, 65_536);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(
            error.message,
            "work graph NumEntrypoints 65536 exceeds the supported limit"
        );
        let (mut broken, desc) = all_overrides_memory();
        put_u64(&mut broken.data, 0x210, 0);
        put_u32(&mut broken.data, 0x20c, 1);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(error.message, "work graph pEntrypoints is null");
        let (mut broken, desc) = all_overrides_memory();
        put_u64(&mut broken.data, 0x300, 0);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(error.message, "work graph entry point has an empty name");
        let (mut broken, desc) = all_overrides_memory();
        put_u32(&mut broken.data, 0x218, 65_536);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(
            error.message,
            "work graph NumExplicitlyDefinedNodes 65536 exceeds the supported limit"
        );
        let (mut broken, desc) = all_overrides_memory();
        put_u64(&mut broken.data, 0x220, 0);
        put_u32(&mut broken.data, 0x218, 1);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(error.message, "work graph pExplicitlyDefinedNodes is null");
        let (mut broken, desc) = all_overrides_memory();
        put_u32(&mut broken.data, 0x218, 0);
        put_u32(&mut broken.data, 0x20c, 0);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(
            error.message,
            "work graph has no nodes or entrypoints and does not include all available nodes"
        );
        let (mut broken, desc) = all_overrides_memory();
        put_u32(&mut broken.data, 0x400, 1);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(
            error.message,
            "work graph node type 1 is not D3D12_NODE_TYPE_SHADER"
        );
        let (mut broken, desc) = all_overrides_memory();
        put_u64(&mut broken.data, 0x408, 0);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(
            error.message,
            "work graph shader node has a null Shader name"
        );
        let (mut broken, desc) = all_overrides_memory();
        put_u64(&mut broken.data, 0x408, 0x1500);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(
            error.message,
            "work graph shader node has an empty Shader name"
        );
        let (mut broken, desc) = all_overrides_memory();
        put_u32(&mut broken.data, 0x410, 9);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(
            error.message,
            "work graph node overrides type 9 is not defined"
        );
        let (mut broken, desc) = all_overrides_memory();
        put_u64(&mut broken.data, 0x418, 0);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(
            error.message,
            "broadcasting launch overrides pointer is null"
        );
        let (mut broken, desc) = all_overrides_memory();
        put_u64(&mut broken.data, 0x3000 + 56, 0);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(
            error.message,
            "broadcasting launch output overrides pointer is null"
        );
        let (mut broken, desc) = all_overrides_memory();
        put_u64(&mut broken.data, 0x400 + 24, 0);
        put_u32(&mut broken.data, 0x400 + 16, NODE_OVERRIDES_THREAD_LAUNCH);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(error.message, "work graph node overrides pointer is null");
        let (mut broken, desc) = all_overrides_memory();
        put_u64(&mut broken.data, 0x3200 + 40, 0);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(error.message, "work graph output overrides pointer is null");

        // Dispatch-graph CPU/GPU modes and record validation.
        let error = D3d12DispatchGraphDesc::parse_cpu(&memory, 0).unwrap_err();
        assert_eq!(error.message, "dispatch graph description pointer is null");
        let (mut desc_memory, _) = all_overrides_memory();
        put_u32(&mut desc_memory.data, 0x1600, DISPATCH_MODE_NODE_CPU_INPUT);
        put_u32(&mut desc_memory.data, 0x1608, 0);
        put_u32(&mut desc_memory.data, 0x160c, 2);
        put_u64(&mut desc_memory.data, 0x1610, 0);
        put_u64(&mut desc_memory.data, 0x1618, 8);
        let error = D3d12DispatchGraphDesc::parse_cpu(&desc_memory, 0x1600).unwrap_err();
        assert_eq!(error.message, "dispatch graph pRecords is null");
        put_u32(&mut desc_memory.data, 0x160c, 1);
        put_u64(&mut desc_memory.data, 0x1610, 0x1700);
        put_u64(&mut desc_memory.data, 0x1618, (64 * 1024 * 1024) + 1);
        let error = D3d12DispatchGraphDesc::parse_cpu(&desc_memory, 0x1600).unwrap_err();
        assert_eq!(
            error.message,
            "dispatch graph record range 67108865 bytes exceeds the 64 MiB limit"
        );
        put_u32(&mut desc_memory.data, 0x160c, u32::MAX);
        put_u64(&mut desc_memory.data, 0x1618, u64::MAX);
        let error = D3d12DispatchGraphDesc::parse_cpu(&desc_memory, 0x1600).unwrap_err();
        assert_eq!(error.message, "dispatch graph record range overflows");
        put_u32(&mut desc_memory.data, 0x160c, 1);
        put_u64(&mut desc_memory.data, 0x1618, 8);
        put_u32(&mut desc_memory.data, 0x1700, 0);
        let parsed = D3d12DispatchGraphDesc::parse_cpu(&desc_memory, 0x1600).unwrap();
        assert_eq!(parsed.record_count, 1);
        assert_eq!(parsed.records.len(), 8);
        // Clear pRecords to exercise the zero-length branch.
        put_u64(&mut desc_memory.data, 0x1610, 0);
        put_u32(&mut desc_memory.data, 0x160c, 0);
        let parsed = D3d12DispatchGraphDesc::parse_cpu(&desc_memory, 0x1600).unwrap();
        assert!(parsed.records.is_empty());
        // Multi-node CPU input parses every entry, including the empty and
        // malformed-array cases.
        put_u32(
            &mut desc_memory.data,
            0x1600,
            DISPATCH_MODE_MULTI_NODE_CPU_INPUT,
        );
        put_u32(&mut desc_memory.data, 0x1608, 1);
        put_u64(&mut desc_memory.data, 0x1610, 0x1800);
        put_u32(&mut desc_memory.data, 0x1800, 0);
        put_u32(&mut desc_memory.data, 0x1804, 1);
        put_u64(&mut desc_memory.data, 0x1808, 0x1700);
        put_u64(&mut desc_memory.data, 0x1810, 8);
        let parsed = D3d12DispatchGraphDesc::parse_entries(&desc_memory, 0x1600).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].mode, DISPATCH_MODE_MULTI_NODE_CPU_INPUT);
        assert_eq!(parsed[0].records.len(), 8);
        put_u32(&mut desc_memory.data, 0x1608, 0);
        let parsed = D3d12DispatchGraphDesc::parse_entries(&desc_memory, 0x1600).unwrap();
        assert_eq!(parsed.len(), 0);
        let error = D3d12DispatchGraphDesc::parse_cpu(&desc_memory, 0x1600).unwrap_err();
        assert_eq!(error.message, "dispatch graph contains no node inputs");
        put_u32(&mut desc_memory.data, 0x1608, 1);
        put_u64(&mut desc_memory.data, 0x1610, 0);
        let error = D3d12DispatchGraphDesc::parse_entries(&desc_memory, 0x1600).unwrap_err();
        assert_eq!(error.message, "dispatch graph node input array is null");

        // GPU node input reads the GPU-resident record bytes and retains the
        // GPU mode; a zero stride with records is rejected.
        put_u32(&mut desc_memory.data, 0x1600, DISPATCH_MODE_NODE_GPU_INPUT);
        put_u32(&mut desc_memory.data, 0x1608, 0);
        put_u32(&mut desc_memory.data, 0x160c, 1);
        put_u64(&mut desc_memory.data, 0x1610, 0x1700);
        put_u64(&mut desc_memory.data, 0x1618, 8);
        let parsed = D3d12DispatchGraphDesc::parse_cpu(&desc_memory, 0x1600).unwrap();
        assert_eq!(parsed.mode, DISPATCH_MODE_NODE_GPU_INPUT);
        assert_eq!(parsed.records.len(), 8);
        put_u64(&mut desc_memory.data, 0x1618, 0);
        let error = D3d12DispatchGraphDesc::parse_cpu(&desc_memory, 0x1600).unwrap_err();
        assert_eq!(error.message, "dispatch graph record stride is zero");

        // Multi-node GPU input follows the same array layout.
        put_u32(
            &mut desc_memory.data,
            0x1600,
            DISPATCH_MODE_MULTI_NODE_GPU_INPUT,
        );
        put_u32(&mut desc_memory.data, 0x1608, 1);
        put_u64(&mut desc_memory.data, 0x1610, 0x1800);
        put_u32(&mut desc_memory.data, 0x1800, 0);
        put_u32(&mut desc_memory.data, 0x1804, 1);
        put_u64(&mut desc_memory.data, 0x1808, 0x1700);
        put_u64(&mut desc_memory.data, 0x1810, 8);
        let parsed = D3d12DispatchGraphDesc::parse_entries(&desc_memory, 0x1600).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].mode, DISPATCH_MODE_MULTI_NODE_GPU_INPUT);

        put_u32(&mut desc_memory.data, 0x1600, 99);
        let error = D3d12DispatchGraphDesc::parse_cpu(&desc_memory, 0x1600).unwrap_err();
        assert_eq!(
            error.message,
            "D3D12_DISPATCH_GRAPH_DESC mode 99 is not defined"
        );
    }

    #[test]
    fn work_graph_undefined_flags_are_rejected() {
        let mut memory = base_memory();
        put_wide(&mut memory.data, 0x100, "graph");
        let desc = write_desc(&mut memory.data, 0x2, 0, 0, 0, 0);
        let error = D3d12WorkGraph::parse(&memory, desc).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "work graph flags 0x2 contain undefined bits");
    }

    #[test]
    fn work_graph_null_shader_is_rejected() {
        let mut memory = base_memory();
        put_wide(&mut memory.data, 0x100, "graph");
        // Node at 0x300 with a null shader pointer.
        put_u32(&mut memory.data, 0x300, D3D12_NODE_TYPE_SHADER);
        let desc = write_desc(&mut memory.data, 0, 0, 0, 1, 0x300);
        let error = D3d12WorkGraph::parse(&memory, desc).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "work graph shader node has a null Shader name"
        );
    }

    #[test]
    fn work_graph_dispatch_grid_above_grid_limit_is_rejected() {
        let mut memory = base_memory();
        put_wide(&mut memory.data, 0x100, "graph");
        put_wide(&mut memory.data, 0x120, "node0");
        // Node at 0x300: shader at +8, broadcasting overrides at +24.
        put_u32(&mut memory.data, 0x300, D3D12_NODE_TYPE_SHADER);
        put_u64(&mut memory.data, 0x308, 0x120);
        put_u32(&mut memory.data, 0x310, NODE_OVERRIDES_BROADCASTING_LAUNCH);
        put_u64(&mut memory.data, 0x318, 0x500);
        // Broadcasting overrides at 0x500: pDispatchGrid at +32.
        put_u64(&mut memory.data, 0x520, 0x600);
        put_u32(&mut memory.data, 0x600, 16_777_216);
        put_u32(&mut memory.data, 0x604, 1);
        put_u32(&mut memory.data, 0x608, 1);
        let desc = write_desc(&mut memory.data, 0, 0, 0, 1, 0x300);
        let error = D3d12WorkGraph::parse(&memory, desc).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "work graph dispatch grid [16777216, 1, 1] exceeds the per-dimension limit 16777215"
        );
    }

    #[test]
    fn work_graph_gpu_dispatch_modes_parse_real_inputs_without_fail_closed_error() {
        let mut memory = base_memory();
        put_u32(&mut memory.data, 0x100, DISPATCH_MODE_NODE_GPU_INPUT);
        put_u32(&mut memory.data, 0x108, 0);
        put_u32(&mut memory.data, 0x10c, 1);
        put_u64(&mut memory.data, 0x110, 0x200);
        put_u64(&mut memory.data, 0x118, 8);
        put_u64(&mut memory.data, 0x200, 0x0000_0007_0000_0003);
        let parsed =
            D3d12DispatchGraphDesc::parse_cpu(&memory, 0x100).expect("GPU record input parses");
        assert_eq!(parsed.mode, DISPATCH_MODE_NODE_GPU_INPUT);
        assert_eq!(parsed.record_count, 1);
        assert_eq!(parsed.records, vec![3, 0, 0, 0, 7, 0, 0, 0]);
    }
}
