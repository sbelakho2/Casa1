//! Real D3D12 Work Graph parsing, validation and host execution planning.
//!
//! Metal has no work-graph primitive. The runtime keeps the full D3D12
//! work-graph representation (program name, entry points, explicit node
//! definitions and their launch descriptors), follows the declared node/output
//! edges, and executes CPU and GPU record modes. CPU records become concrete
//! compute or mesh dispatches with the graph's own dispatch grids; GPU records
//! run a real staged Metal fan-out whose record counts and indices are written
//! on the GPU. Validation failures fail closed with an exact D3D12 error.

use std::collections::{BTreeMap, BTreeSet};

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
/// `D3D12_NODE_TYPE_PROGRAM`: program node (mesh launch is the supported form).
pub const D3D12_NODE_TYPE_PROGRAM: u32 = 1;

pub const PROGRAM_NODE_OVERRIDES_NONE: u32 = 0;
pub const PROGRAM_NODE_OVERRIDES_MESH_LAUNCH: u32 = 3;

/// Maximum number of declared node outputs.
pub const WORK_GRAPH_MAX_NODE_OUTPUTS: u32 = 1024;
/// Maximum record stride accepted by the bridge.
pub const WORK_GRAPH_MAX_RECORD_SIZE: u64 = 32 * 1024;
/// A node/output record begins with two 32-bit words.
pub const WORK_GRAPH_RECORD_HEADER_SIZE: u64 = 8;
/// Record marker that terminates a chain without launching work.
pub const WORK_GRAPH_EMPTY_RECORD: u32 = u32::MAX;

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

/// D3D12_MESH_LAUNCH_OVERRIDES.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct D3d12MeshLaunchOverrides {
    pub local_root_arguments_table_index: Option<u32>,
    pub program_entry: Option<bool>,
    pub new_name: Option<D3d12NodeId>,
    pub share_input_of: Option<D3d12NodeId>,
    pub dispatch_grid: Option<[u32; 3]>,
    pub max_dispatch_grid: Option<[u32; 3]>,
    pub max_input_records_per_graph_entry_record: Option<(u32, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum D3d12NodeOverrides {
    None,
    Broadcasting(D3d12BroadcastingLaunchOverrides),
    Coalescing(D3d12CoalescingLaunchOverrides),
    Thread(D3d12ThreadLaunchOverrides),
    CommonCompute(D3d12CommonComputeNodeOverrides),
    Mesh(D3d12MeshLaunchOverrides),
}

impl D3d12NodeOverrides {
    pub fn program_entry(&self) -> Option<bool> {
        match self {
            Self::None => None,
            Self::Broadcasting(o) => o.program_entry,
            Self::Coalescing(o) => o.program_entry,
            Self::Thread(o) => o.program_entry,
            Self::CommonCompute(o) => o.program_entry,
            Self::Mesh(o) => o.program_entry,
        }
    }

    pub fn local_root_arguments_table_index(&self) -> Option<u32> {
        match self {
            Self::None => None,
            Self::Broadcasting(o) => o.local_root_arguments_table_index,
            Self::Coalescing(o) => o.local_root_arguments_table_index,
            Self::Thread(o) => o.local_root_arguments_table_index,
            Self::CommonCompute(o) => o.local_root_arguments_table_index,
            Self::Mesh(o) => o.local_root_arguments_table_index,
        }
    }

    pub fn share_input_of(&self) -> Option<&D3d12NodeId> {
        match self {
            Self::None => None,
            Self::Broadcasting(o) => o.share_input_of.as_ref(),
            Self::Coalescing(o) => o.share_input_of.as_ref(),
            Self::Thread(o) => o.share_input_of.as_ref(),
            Self::CommonCompute(o) => o.share_input_of.as_ref(),
            Self::Mesh(o) => o.share_input_of.as_ref(),
        }
    }

    pub fn dispatch_grid(&self) -> Option<[u32; 3]> {
        match self {
            Self::Broadcasting(o) => o.dispatch_grid,
            Self::Mesh(o) => o.dispatch_grid,
            _ => None,
        }
    }

    pub fn max_dispatch_grid(&self) -> Option<[u32; 3]> {
        match self {
            Self::Broadcasting(o) => o.max_dispatch_grid,
            Self::Mesh(o) => o.max_dispatch_grid,
            _ => None,
        }
    }

    pub fn output_overrides(&self) -> &[D3d12NodeOutputOverrides] {
        match self {
            Self::None | Self::Mesh(_) => &[],
            Self::Broadcasting(o) => &o.output_overrides,
            Self::Coalescing(o) => &o.output_overrides,
            Self::Thread(o) => &o.output_overrides,
            Self::CommonCompute(o) => &o.output_overrides,
        }
    }
}

/// One explicitly defined D3D12_NODE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3d12WorkGraphNode {
    /// `D3D12_NODE_TYPE_SHADER` or `D3D12_NODE_TYPE_PROGRAM`.
    pub node_type: u32,
    /// Shader export name, or program name for a program node.
    pub shader: String,
    pub overrides: D3d12NodeOverrides,
}

impl D3d12WorkGraphNode {
    pub fn is_mesh(&self) -> bool {
        matches!(self.overrides, D3d12NodeOverrides::Mesh(_))
    }

    /// Number of outputs declared by this node.
    ///
    /// Shader metadata is not available through `D3D12_WORK_GRAPH_DESC`, so
    /// outputs are inferred from the output overrides; a node with no
    /// overrides has the single default output `0`.
    pub fn output_count(&self) -> u32 {
        if self.is_mesh() {
            return 0;
        }
        self.overrides
            .output_overrides()
            .iter()
            .map(|output| output.output_index)
            .max()
            .map_or(1, |index| index.saturating_add(1))
    }

    /// Output that owns the record budget for `output_index`.
    ///
    /// `MaxRecordsSharedWithOutputIndex` makes several outputs draw from one
    /// budget; this returns the index of the output that declares the limit.
    pub fn output_limit_slot(&self, output_index: u32) -> u32 {
        let overrides = self.overrides.output_overrides();
        let mut current = output_index;
        let mut visited = Vec::new();
        loop {
            let Some(output) = overrides
                .iter()
                .find(|output| output.output_index == current)
            else {
                return output_index;
            };
            if output.max_records.is_some() {
                return current;
            }
            match output.max_records_shared_with_output_index {
                Some(next) if !visited.contains(&next) => {
                    visited.push(current);
                    current = next;
                }
                _ => return current,
            }
        }
    }

    /// Effective `MaxRecords` limit for one output, following shared limits.
    pub fn output_limit(&self, output_index: u32) -> Option<u32> {
        let overrides = self.overrides.output_overrides();
        let output = overrides
            .iter()
            .find(|output| output.output_index == output_index)?;
        if let Some(max) = output.max_records {
            return Some(max);
        }
        let mut shared = output.max_records_shared_with_output_index;
        let mut visited = Vec::new();
        while let Some(index) = shared {
            if visited.contains(&index) {
                return None;
            }
            visited.push(index);
            let referenced = overrides
                .iter()
                .find(|candidate| candidate.output_index == index)?;
            if let Some(max) = referenced.max_records {
                return Some(max);
            }
            shared = referenced.max_records_shared_with_output_index;
        }
        None
    }
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
    pub mesh: bool,
}

/// One work-graph record: a node index plus the output it emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D3d12WorkGraphRecord {
    pub node_index: u32,
    pub output_index: u32,
}

impl D3d12WorkGraphRecord {
    pub fn is_empty(&self) -> bool {
        self.node_index == WORK_GRAPH_EMPTY_RECORD && self.output_index == WORK_GRAPH_EMPTY_RECORD
    }
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

    /// Whether this graph needs record-driven execution rather than the
    /// legacy single-node linearisation.
    pub fn uses_record_semantics(&self) -> bool {
        self.nodes.len() > 1
            || self
                .nodes
                .iter()
                .any(|node| node.is_mesh() || !node.overrides.output_overrides().is_empty())
    }

    pub fn entrypoint_index(&self, id: &D3d12NodeId) -> Option<u32> {
        self.entrypoints
            .iter()
            .position(|entry| entry == id)
            .map(|i| i as u32)
    }

    /// Node ID (after overrides) for one explicit node.
    pub fn node_id(&self, index: u32) -> Option<D3d12NodeId> {
        self.nodes
            .get(index as usize)
            .map(D3d12WorkGraphNode::overrides_name)
    }

    /// Number of elements in a node array (at least one when present).
    pub fn node_array_size(&self, name: &str) -> u32 {
        self.nodes
            .iter()
            .filter(|node| node.overrides_name().name == name)
            .map(|node| node.overrides_name().array_index)
            .max()
            .map_or(0, |index| index.saturating_add(1))
    }

    /// Resolve a node ID, including sparse node arrays.
    ///
    /// An explicitly defined element always wins. A missing (sparse) element
    /// falls back to element 0 of the same array, matching the D3D12 rule that
    /// sparse arrays share the base node definition.
    pub fn resolve_node(&self, id: &D3d12NodeId) -> Option<u32> {
        if let Some(index) = self
            .nodes
            .iter()
            .position(|node| &node.overrides_name() == id)
        {
            return Some(index as u32);
        }
        self.nodes
            .iter()
            .position(|node| {
                let candidate = node.overrides_name();
                candidate.name == id.name
                    && candidate.array_index == 0
                    && id.array_index < self.node_array_size(&id.name)
            })
            .map(|index| index as u32)
    }

    /// Resolve an entrypoint index to a concrete explicit node.
    pub fn validate_entrypoint(&self, entrypoint_index: u32) -> AppResult<u32> {
        let entry = self
            .entrypoints
            .get(entrypoint_index as usize)
            .ok_or_else(|| {
                invalid(format!(
                    "work graph entrypoint index {entrypoint_index} is out of range ({} entries)",
                    self.entrypoints.len()
                ))
            })?;
        self.resolve_node(entry).ok_or_else(|| {
            invalid(format!(
                "work graph entrypoint {:?}[{}] does not name a node",
                entry.name, entry.array_index
            ))
        })
    }

    /// Resolve the target node of one output, if the output fans out.
    pub fn edge_target(&self, node_index: u32, output_index: u32) -> Option<u32> {
        let node = self.nodes.get(node_index as usize)?;
        if output_index >= node.output_count() {
            return None;
        }
        let output = node
            .overrides
            .output_overrides()
            .iter()
            .find(|output| output.output_index == output_index)?;
        self.resolve_node(output.new_name.as_ref()?)
    }

    /// Validate node/output structure, limits, arrays, cycles and depth.
    pub fn validate(&self) -> AppResult<()> {
        let mut defined = BTreeSet::new();
        for (node_index, node) in self.nodes.iter().enumerate() {
            let id = node.overrides_name();
            if id.name.is_empty() {
                return Err(invalid(format!(
                    "work graph node {node_index} has an empty name"
                )));
            }
            if !defined.insert((id.name.clone(), id.array_index)) {
                return Err(invalid(format!(
                    "work graph node {:?}[{}] is defined more than once",
                    id.name, id.array_index
                )));
            }
            match node.node_type {
                D3D12_NODE_TYPE_SHADER => {
                    if node.is_mesh() {
                        return Err(invalid(format!(
                            "work graph shader node {:?}[{}] cannot use mesh launch overrides",
                            id.name, id.array_index
                        )));
                    }
                }
                D3D12_NODE_TYPE_PROGRAM => {
                    if !node.is_mesh() {
                        return Err(invalid(format!(
                            "work graph program node {:?}[{}] requires mesh launch overrides",
                            id.name, id.array_index
                        )));
                    }
                }
                other => {
                    return Err(invalid(format!(
                        "work graph node type {other} is not D3D12_NODE_TYPE_SHADER or D3D12_NODE_TYPE_PROGRAM"
                    )));
                }
            }

            let mut outputs = BTreeSet::new();
            for output in node.overrides.output_overrides() {
                if output.output_index >= WORK_GRAPH_MAX_NODE_OUTPUTS {
                    return Err(invalid(format!(
                        "work graph node {:?}[{}] output index {} exceeds the {} output limit",
                        id.name, id.array_index, output.output_index, WORK_GRAPH_MAX_NODE_OUTPUTS
                    )));
                }
                if !outputs.insert(output.output_index) {
                    return Err(invalid(format!(
                        "work graph node {:?}[{}] defines output {} more than once",
                        id.name, id.array_index, output.output_index
                    )));
                }
                if output.max_records.is_some()
                    && output.max_records_shared_with_output_index.is_some()
                {
                    return Err(invalid(format!(
                        "work graph node {:?}[{}] output {} sets both MaxRecords and \
                         MaxRecordsSharedWithOutputIndex",
                        id.name, id.array_index, output.output_index
                    )));
                }
                if output.max_records == Some(0) {
                    return Err(invalid(format!(
                        "work graph node {:?}[{}] output {} MaxRecords is zero",
                        id.name, id.array_index, output.output_index
                    )));
                }
                if let Some(shared) = output.max_records_shared_with_output_index {
                    if shared == output.output_index {
                        return Err(invalid(format!(
                            "work graph node {:?}[{}] output {} shares records with itself",
                            id.name, id.array_index, output.output_index
                        )));
                    }
                    if shared >= node.output_count() {
                        return Err(invalid(format!(
                            "work graph node {:?}[{}] output {} shares records with undefined \
                             output {}",
                            id.name, id.array_index, output.output_index, shared
                        )));
                    }
                }
                if let Some(target) = &output.new_name
                    && target.name.is_empty()
                {
                    return Err(invalid(format!(
                        "work graph node {:?}[{}] output {} has an empty target name",
                        id.name, id.array_index, output.output_index
                    )));
                }
                if let Some(target) = &output.new_name
                    && self.resolve_node(target).is_none()
                    && output.allow_sparse_nodes != Some(true)
                {
                    return Err(invalid(format!(
                        "work graph node {:?}[{}] output {} targets undefined node {:?}[{}]",
                        id.name,
                        id.array_index,
                        output.output_index,
                        target.name,
                        target.array_index
                    )));
                }
            }
            if let Some(shared) = node.overrides.share_input_of() {
                if shared.name.is_empty() {
                    return Err(invalid(format!(
                        "work graph node {:?}[{}] shares input with an empty node name",
                        id.name, id.array_index
                    )));
                }
                if self.resolve_node(shared).is_none() {
                    return Err(invalid(format!(
                        "work graph node {:?}[{}] shares input with undefined node {:?}[{}]",
                        id.name, id.array_index, shared.name, shared.array_index
                    )));
                }
            }
        }

        self.validate_cycles()?;
        self.validate_depth()
    }

    fn validate_cycles(&self) -> AppResult<()> {
        let mut adjacency = vec![Vec::new(); self.nodes.len()];
        for node_index in 0..self.nodes.len() as u32 {
            let node = &self.nodes[node_index as usize];
            for output in node.overrides.output_overrides() {
                if let Some(target) = self.edge_target(node_index, output.output_index)
                    && target != node_index
                {
                    adjacency[node_index as usize].push(target as usize);
                }
            }
        }
        let mut state = vec![0u8; self.nodes.len()];
        for start in 0..self.nodes.len() {
            if state[start] != 0 {
                continue;
            }
            if self.visit_cycle(start, &adjacency, &mut state)? {
                let id = self.nodes[start].overrides_name();
                return Err(invalid(format!(
                    "work graph contains a cycle through node {:?}[{}]; only self-recursion is allowed",
                    id.name, id.array_index
                )));
            }
        }
        Ok(())
    }

    fn visit_cycle(
        &self,
        node: usize,
        adjacency: &[Vec<usize>],
        state: &mut [u8],
    ) -> AppResult<bool> {
        state[node] = 1;
        for &target in &adjacency[node] {
            if state[target] == 1 {
                return Ok(true);
            }
            if state[target] == 0 && self.visit_cycle(target, adjacency, state)? {
                return Ok(true);
            }
        }
        state[node] = 2;
        Ok(false)
    }

    fn validate_depth(&self) -> AppResult<()> {
        let roots: Vec<usize> = if self.entrypoints.is_empty() {
            (0..self.nodes.len()).collect()
        } else {
            self.entrypoints
                .iter()
                .filter_map(|entry| self.resolve_node(entry))
                .map(|index| index as usize)
                .collect()
        };
        let mut memo = vec![None; self.nodes.len()];
        let mut depth = 0;
        for root in roots {
            depth = depth.max(self.node_depth(root, &mut memo));
        }
        if depth > WORK_GRAPH_MAX_NODE_DEPTH {
            return Err(invalid(format!(
                "work graph depth {depth} exceeds D3D12_WORK_GRAPHS_MAX_NODE_DEPTH \
                 ({WORK_GRAPH_MAX_NODE_DEPTH})"
            )));
        }
        Ok(())
    }

    fn node_depth(&self, node: usize, memo: &mut [Option<u32>]) -> u32 {
        if let Some(depth) = memo[node] {
            return depth;
        }
        let mut child_depth = 0;
        for output_index in 0..self.nodes[node].output_count() {
            if let Some(target) = self.edge_target(node as u32, output_index)
                && target as usize != node
            {
                child_depth = child_depth.max(self.node_depth(target as usize, memo));
            }
        }
        let depth = child_depth.saturating_add(1);
        memo[node] = Some(depth);
        depth
    }

    /// Build the concrete dispatch sequence for one entry point.
    ///
    /// D3D12 starts execution at an entry point; downstream nodes are
    /// activated by records. The bridge follows those edges through the
    /// explicitly declared output overrides (`pNewName` names the target node)
    /// and also honours program-entry nodes and
    /// `INCLUDE_ALL_AVAILABLE_NODES`. Each reached node is issued as a real
    /// compute or mesh dispatch sized from its launch overrides.
    pub fn dispatch_plan(
        &self,
        entrypoint_index: u32,
        record_count: u32,
        record_stride: u64,
    ) -> AppResult<Vec<D3d12WorkGraphDispatch>> {
        let entry_node = self.validate_entrypoint(entrypoint_index)?;
        self.validate_record_layout(record_count, record_stride, u64::MAX)?;
        if record_count == 0 {
            return Ok(Vec::new());
        }

        let include_all = self.flags & WORK_GRAPH_FLAG_INCLUDE_ALL_AVAILABLE_NODES != 0;
        let mut selected = vec![false; self.nodes.len()];
        let mut order = Vec::new();
        let push = |index: usize, selected: &mut Vec<bool>, order: &mut Vec<usize>| {
            if !selected[index] {
                selected[index] = true;
                order.push(index);
            }
        };
        push(entry_node as usize, &mut selected, &mut order);
        for (index, node) in self.nodes.iter().enumerate() {
            if include_all || node.overrides.program_entry() == Some(true) {
                push(index, &mut selected, &mut order);
            }
        }
        let mut cursor = 0;
        while cursor < order.len() {
            let node_index = order[cursor];
            cursor += 1;
            let output_count = self.nodes[node_index].output_count();
            for output_index in 0..output_count {
                if let Some(target) = self.edge_target(node_index as u32, output_index) {
                    push(target as usize, &mut selected, &mut order);
                }
            }
        }

        let mut plan = Vec::new();
        for node_index in order {
            if let Some(dispatch) =
                self.dispatch_for_node(entrypoint_index, node_index as u32, record_count)?
            {
                plan.push(dispatch);
            }
        }
        Ok(plan)
    }

    /// Dispatch sequence for CPU records carrying per-output node indices.
    pub fn record_plan(
        &self,
        entrypoint_index: u32,
        records: &[D3d12WorkGraphRecord],
    ) -> AppResult<Vec<D3d12WorkGraphDispatch>> {
        let entry_node = self.validate_entrypoint(entrypoint_index)?;
        if records.is_empty() {
            return Ok(Vec::new());
        }
        for (index, record) in records.iter().enumerate() {
            if record.node_index != entry_node {
                return Err(invalid(format!(
                    "work graph record {index} targets node {} but entrypoint {entrypoint_index} \
                     resolves to node {entry_node}",
                    record.node_index
                )));
            }
            let entry = &self.nodes[entry_node as usize];
            if !entry.is_mesh() && record.output_index >= entry.output_count() {
                return Err(invalid(format!(
                    "work graph record {index} output index {} is out of range for node \
                     {:?} output count {}",
                    record.output_index,
                    entry.overrides_name().name,
                    entry.output_count()
                )));
            }
        }

        let mut counts = vec![0u32; self.nodes.len()];
        let mut first_reach = vec![false; self.nodes.len()];
        let mut order = vec![entry_node as usize];
        first_reach[entry_node as usize] = true;
        counts[entry_node as usize] = records.len() as u32;
        let mut pending = BTreeMap::new();
        for record in records {
            *pending
                .entry((entry_node, record.output_index))
                .or_insert(0u32) += 1;
        }

        let mut depth = 0u32;
        while !pending.is_empty() {
            if depth >= WORK_GRAPH_MAX_NODE_DEPTH {
                return Err(invalid(format!(
                    "work graph recursion depth exceeds D3D12_WORK_GRAPHS_MAX_NODE_DEPTH \
                     ({WORK_GRAPH_MAX_NODE_DEPTH})"
                )));
            }
            let mut usage = BTreeMap::new();
            for ((node_index, output_index), count) in &pending {
                let slot = self.nodes[*node_index as usize].output_limit_slot(*output_index);
                *usage.entry((*node_index, slot)).or_insert(0u32) += *count;
            }
            for ((node_index, slot), total) in usage {
                let node = &self.nodes[node_index as usize];
                if let Some(limit) = node.output_limit(slot)
                    && total > limit
                {
                    let id = node.overrides_name();
                    return Err(invalid(format!(
                        "work graph node {:?}[{}] output {slot} received {total} records \
                         but MaxRecords is {limit}",
                        id.name, id.array_index
                    )));
                }
            }
            let mut next = BTreeMap::new();
            for ((node_index, output_index), count) in pending {
                if let Some(target) = self.edge_target(node_index, output_index) {
                    if !first_reach[target as usize] {
                        first_reach[target as usize] = true;
                        order.push(target as usize);
                        counts[target as usize] = count;
                    } else {
                        counts[target as usize] = counts[target as usize].saturating_add(count);
                    }
                    let queued = next.entry((target, 0u32)).or_insert(0u32);
                    *queued = queued.saturating_add(count);
                }
            }
            pending = next;
            depth += 1;
        }

        let mut plan = Vec::new();
        for node_index in order {
            if counts[node_index] == 0 {
                continue;
            }
            if let Some(dispatch) =
                self.dispatch_for_node(entrypoint_index, node_index as u32, counts[node_index])?
            {
                plan.push(dispatch);
            }
        }
        Ok(plan)
    }

    pub(crate) fn dispatch_for_node(
        &self,
        entrypoint_index: u32,
        node_index: u32,
        record_count: u32,
    ) -> AppResult<Option<D3d12WorkGraphDispatch>> {
        let node = &self.nodes[node_index as usize];
        let grid = node.overrides.dispatch_grid().or_else(|| {
            node.overrides.max_dispatch_grid().map(|grid| {
                if grid.iter().all(|dim| *dim == 0) {
                    [record_count.max(1), 1, 1]
                } else {
                    grid
                }
            })
        });
        let grid = grid.unwrap_or_else(|| match &node.overrides {
            D3d12NodeOverrides::Coalescing(_) | D3d12NodeOverrides::CommonCompute(_) => {
                [record_count.max(1).div_ceil(64), 1, 1]
            }
            _ => [record_count.max(1), 1, 1],
        });
        if grid
            .iter()
            .any(|dim| *dim > WORK_GRAPH_MAX_THREAD_GROUPS_PER_GRID)
        {
            return Err(invalid(format!(
                "work graph node {node_index} dispatch grid {grid:?} exceeds the \
                 per-dimension limit {WORK_GRAPH_MAX_THREAD_GROUPS_PER_GRID}"
            )));
        }
        let groups = (grid[0] as u64)
            .saturating_mul(grid[1] as u64)
            .saturating_mul(grid[2] as u64);
        if groups > WORK_GRAPH_MAX_THREAD_GROUPS_PER_GRID as u64 {
            return Err(invalid(format!(
                "work graph node {node_index} dispatch grid {grid:?} exceeds the total \
                 thread-group limit {WORK_GRAPH_MAX_THREAD_GROUPS_PER_GRID}"
            )));
        }
        if grid.contains(&0) {
            return Ok(None);
        }
        Ok(Some(D3d12WorkGraphDispatch {
            entrypoint_index,
            node_index,
            grid,
            record_count,
            mesh: node.is_mesh(),
        }))
    }

    /// Parse CPU/GPU record bytes into validated node/output records.
    pub fn parse_records(
        &self,
        records: &[u8],
        record_count: u32,
        record_stride: u64,
    ) -> AppResult<Vec<D3d12WorkGraphRecord>> {
        self.validate_record_layout(record_count, record_stride, records.len() as u64)?;
        if record_count == 0 {
            return Ok(Vec::new());
        }
        let mut parsed = Vec::with_capacity(record_count as usize);
        for index in 0..record_count as usize {
            let offset = index * record_stride as usize;
            let record = D3d12WorkGraphRecord {
                node_index: u32::from_le_bytes(
                    records[offset..offset + 4]
                        .try_into()
                        .expect("4-byte node index"),
                ),
                output_index: u32::from_le_bytes(
                    records[offset + 4..offset + 8]
                        .try_into()
                        .expect("4-byte output index"),
                ),
            };
            if record.is_empty() {
                continue;
            }
            let Some(node) = self.nodes.get(record.node_index as usize) else {
                return Err(invalid(format!(
                    "work graph record {index} node index {} is out of range for {} nodes",
                    record.node_index,
                    self.nodes.len()
                )));
            };
            if !node.is_mesh() && record.output_index >= node.output_count() {
                return Err(invalid(format!(
                    "work graph record {index} output index {} is out of range for node \
                     {:?}[{}] output count {}",
                    record.output_index,
                    node.overrides_name().name,
                    node.overrides_name().array_index,
                    node.output_count()
                )));
            }
            parsed.push(record);
        }
        Ok(parsed)
    }

    fn validate_record_layout(
        &self,
        record_count: u32,
        record_stride: u64,
        available: u64,
    ) -> AppResult<u64> {
        if record_count == 0 {
            return Ok(0);
        }
        if record_stride == 0 {
            return Err(invalid("work graph record stride is zero"));
        }
        if record_stride < WORK_GRAPH_RECORD_HEADER_SIZE {
            return Err(invalid(format!(
                "work graph record stride {record_stride} is smaller than the 8-byte \
                 node/output record"
            )));
        }
        if record_stride % 4 != 0 {
            return Err(invalid(format!(
                "work graph record stride {record_stride} is not a multiple of 4"
            )));
        }
        if record_stride > WORK_GRAPH_MAX_RECORD_SIZE {
            return Err(invalid(format!(
                "work graph record stride {record_stride} exceeds the 32 KiB node record limit"
            )));
        }
        let required = (record_count as u64) * record_stride;
        if required > available {
            return Err(invalid(format!(
                "work graph record range ({required} bytes) exceeds the supplied {available} bytes"
            )));
        }
        Ok(required)
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
        self.validate_record_layout(record_count, record_stride, available as u64)?;
        Ok(())
    }

    /// Validate a bound node-local root arguments table against this graph.
    pub fn validate_local_root_arguments(&self, table: &D3d12GpuRangeAndStride) -> AppResult<()> {
        let mut max_index = None;
        for node in &self.nodes {
            if let Some(index) = node.overrides.local_root_arguments_table_index()
                && index != u32::MAX
            {
                max_index = Some(max_index.map_or(index, |current: u32| current.max(index)));
            }
        }
        let Some(max_index) = max_index else {
            return Ok(());
        };
        if table.stride == 0 {
            if max_index > 0 {
                return Err(invalid(format!(
                    "node local root arguments table stride is zero but a node uses table index \
                     {max_index}"
                )));
            }
            return Ok(());
        }
        let required = (max_index as u64)
            .checked_mul(table.stride)
            .ok_or_else(|| invalid("node local root arguments table range overflows"))?
            .checked_add(4)
            .ok_or_else(|| invalid("node local root arguments table range overflows"))?;
        if required > table.size {
            return Err(invalid(format!(
                "node local root arguments table size {} is smaller than the {required} bytes \
                 required by table index {max_index}",
                table.size
            )));
        }
        Ok(())
    }
}

/// A GPU virtual-address range with an element stride.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D3d12GpuRangeAndStride {
    pub start: u64,
    pub size: u64,
    pub stride: u64,
}

impl D3d12GpuRangeAndStride {
    pub fn validate(&self) -> AppResult<()> {
        if self.start % 4 != 0 {
            return Err(invalid(format!(
                "node local root arguments table address {:#x} is not 4-byte aligned",
                self.start
            )));
        }
        if self.size % 4 != 0 {
            return Err(invalid(format!(
                "node local root arguments table size {} is not a multiple of 4",
                self.size
            )));
        }
        if self.stride % 4 != 0 {
            return Err(invalid(format!(
                "node local root arguments table stride {} is not a multiple of 4",
                self.stride
            )));
        }
        if self.start.checked_add(self.size).is_none() {
            return Err(invalid("node local root arguments table range overflows"));
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
            D3d12NodeOverrides::Mesh(o) => o.new_name.clone(),
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
    match node_type {
        D3D12_NODE_TYPE_SHADER => parse_shader_node(memory, address),
        D3D12_NODE_TYPE_PROGRAM => parse_program_node(memory, address),
        other => Err(invalid(format!(
            "work graph node type {other} is not a supported D3D12_NODE_TYPE"
        ))),
    }
}

fn parse_shader_node(
    memory: &dyn StateObjectMemory,
    address: u64,
) -> AppResult<D3d12WorkGraphNode> {
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
    Ok(D3d12WorkGraphNode {
        node_type: D3D12_NODE_TYPE_SHADER,
        shader,
        overrides,
    })
}

fn parse_program_node(
    memory: &dyn StateObjectMemory,
    address: u64,
) -> AppResult<D3d12WorkGraphNode> {
    // D3D12_PROGRAM_NODE shares the D3D12_SHADER_NODE field layout.
    let program_ptr = memory.read_u64(address + 8)?;
    if program_ptr == 0 {
        return Err(invalid("work graph program node has a null Program name"));
    }
    let shader = memory.read_wide_string(program_ptr)?;
    if shader.is_empty() {
        return Err(invalid("work graph program node has an empty Program name"));
    }
    let overrides_type = memory.read_u32(address + 16)?;
    let overrides_ptr = memory.read_u64(address + 24)?;
    let overrides = match overrides_type {
        PROGRAM_NODE_OVERRIDES_NONE => {
            D3d12NodeOverrides::Mesh(D3d12MeshLaunchOverrides::default())
        }
        PROGRAM_NODE_OVERRIDES_MESH_LAUNCH => {
            D3d12NodeOverrides::Mesh(parse_mesh_overrides(memory, overrides_ptr)?)
        }
        other => {
            return Err(invalid(format!(
                "work graph program node overrides type {other} is not \
                 D3D12_PROGRAM_NODE_OVERRIDES_TYPE_MESH_LAUNCH"
            )));
        }
    };
    Ok(D3d12WorkGraphNode {
        node_type: D3D12_NODE_TYPE_PROGRAM,
        shader,
        overrides,
    })
}

fn parse_mesh_overrides(
    memory: &dyn StateObjectMemory,
    address: u64,
) -> AppResult<D3d12MeshLaunchOverrides> {
    if address == 0 {
        return Err(invalid("mesh launch overrides pointer is null"));
    }
    let dispatch_grid = read_grid(memory, memory.read_u64(address + 32)?)?;
    let max_dispatch_grid = read_grid(memory, memory.read_u64(address + 40)?)?;
    validate_grid(dispatch_grid)?;
    validate_grid(max_dispatch_grid)?;
    let max_input = memory.read_u64(address + 48)?;
    let max_input_records_per_graph_entry_record = if max_input == 0 {
        None
    } else {
        Some((
            memory.read_u32(max_input)?,
            memory.read_u32(max_input + 4)? != 0,
        ))
    };
    Ok(D3d12MeshLaunchOverrides {
        local_root_arguments_table_index: read_optional_u32(memory, memory.read_u64(address)?)?,
        program_entry: read_optional_bool(memory, memory.read_u64(address + 8)?)?,
        new_name: read_optional_node_id(memory, memory.read_u64(address + 16)?)?,
        share_input_of: read_optional_node_id(memory, memory.read_u64(address + 24)?)?,
        dispatch_grid,
        max_dispatch_grid,
        max_input_records_per_graph_entry_record,
    })
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
        put_u32(&mut broken.data, 0x400, 2);
        let error = D3d12WorkGraph::parse(&broken, desc).unwrap_err();
        assert_eq!(
            error.message,
            "work graph node type 2 is not a supported D3D12_NODE_TYPE"
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

    fn node_id(name: &str) -> D3d12NodeId {
        D3d12NodeId::new(name, 0)
    }

    fn shader_node(name: &str, overrides: D3d12NodeOverrides) -> D3d12WorkGraphNode {
        D3d12WorkGraphNode {
            node_type: D3D12_NODE_TYPE_SHADER,
            shader: name.to_string(),
            overrides,
        }
    }

    fn mesh_node(name: &str, grid: Option<[u32; 3]>) -> D3d12WorkGraphNode {
        D3d12WorkGraphNode {
            node_type: D3D12_NODE_TYPE_PROGRAM,
            shader: name.to_string(),
            overrides: D3d12NodeOverrides::Mesh(D3d12MeshLaunchOverrides {
                program_entry: Some(true),
                new_name: Some(node_id(name)),
                dispatch_grid: grid,
                ..Default::default()
            }),
        }
    }

    fn output(
        index: u32,
        target: Option<&str>,
        max_records: Option<u32>,
    ) -> D3d12NodeOutputOverrides {
        D3d12NodeOutputOverrides {
            output_index: index,
            new_name: target.map(node_id),
            max_records,
            ..Default::default()
        }
    }

    fn chain_graph(count: u32) -> D3d12WorkGraph {
        let mut nodes = Vec::new();
        for index in 0..count {
            let name = format!("n{index}");
            let overrides = D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                new_name: Some(node_id(&name)),
                output_overrides: if index + 1 < count {
                    vec![output(0, Some(&format!("n{}", index + 1)), None)]
                } else {
                    Vec::new()
                },
                ..Default::default()
            });
            nodes.push(shader_node(&name, overrides));
        }
        D3d12WorkGraph {
            program_name: "graph".to_string(),
            flags: 0,
            entrypoints: vec![node_id("n0")],
            nodes,
        }
    }

    fn record_bytes(records: &[(u32, u32)]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(records.len() * 8);
        for (node, output) in records {
            bytes.extend_from_slice(&node.to_le_bytes());
            bytes.extend_from_slice(&output.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn work_graph_chain_selects_launch_modes_arrays_and_mesh_nodes() {
        let graph = D3d12WorkGraph {
            program_name: "graph".to_string(),
            flags: 0,
            entrypoints: vec![node_id("root")],
            nodes: vec![
                shader_node(
                    "root",
                    D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                        new_name: Some(node_id("root")),
                        dispatch_grid: Some([2, 1, 1]),
                        output_overrides: vec![output(0, Some("stage1"), Some(4))],
                        ..Default::default()
                    }),
                ),
                shader_node(
                    "stage1",
                    D3d12NodeOverrides::Coalescing(D3d12CoalescingLaunchOverrides {
                        new_name: Some(node_id("stage1")),
                        output_overrides: vec![output(0, Some("mesh"), None)],
                        ..Default::default()
                    }),
                ),
                mesh_node("mesh", Some([3, 1, 1])),
            ],
        };
        graph.validate().expect("valid chain");
        assert!(graph.uses_record_semantics());
        assert_eq!(graph.node_array_size("root"), 1);
        assert_eq!(graph.resolve_node(&node_id("stage1")), Some(1));
        assert_eq!(graph.resolve_node(&node_id("missing")), None);
        assert_eq!(graph.edge_target(0, 0), Some(1));
        assert_eq!(graph.edge_target(1, 0), Some(2));
        assert_eq!(graph.edge_target(2, 0), None);
        assert_eq!(graph.nodes[0].output_limit(0), Some(4));
        assert_eq!(graph.nodes[2].output_count(), 0);

        let records = vec![
            D3d12WorkGraphRecord {
                node_index: 0,
                output_index: 0,
            };
            2
        ];
        let plan = graph.record_plan(0, &records).expect("record plan");
        assert_eq!(plan.len(), 3);
        assert_eq!((plan[0].node_index, plan[0].grid), (0, [2, 1, 1]));
        assert_eq!((plan[1].node_index, plan[1].grid), (1, [1, 1, 1]));
        assert_eq!((plan[2].node_index, plan[2].grid), (2, [3, 1, 1]));
        assert!(plan[2].mesh);
        assert_eq!(plan[1].record_count, 2);
        assert_eq!(graph.dispatch_plan(0, 2, 8).expect("static plan").len(), 3);
        let parsed = graph
            .parse_records(&record_bytes(&[(0, 0), (0, 0)]), 2, 8)
            .expect("records");
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            graph
                .parse_records(&record_bytes(&[(0, 9)]), 1, 8)
                .unwrap_err()
                .message,
            "work graph record 0 output index 9 is out of range for node \"root\"[0] output count 1"
        );

        // Node arrays: an explicitly defined element wins, and a sparse
        // element falls back to element 0.
        let mut array_graph = chain_graph(1);
        for array_index in [0u32, 2] {
            array_graph.nodes.push(shader_node(
                "bin",
                D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                    new_name: Some(D3d12NodeId::new("bin", array_index)),
                    ..Default::default()
                }),
            ));
        }
        array_graph.entrypoints = vec![D3d12NodeId::new("bin", 2)];
        assert_eq!(array_graph.node_array_size("bin"), 3);
        assert_eq!(
            array_graph.resolve_node(&D3d12NodeId::new("bin", 2)),
            Some(2)
        );
        assert_eq!(
            array_graph.resolve_node(&D3d12NodeId::new("bin", 1)),
            Some(1)
        );
        assert_eq!(array_graph.validate_entrypoint(0).expect("array entry"), 2);
    }

    #[test]
    fn work_graph_validation_rejects_limits_cycles_and_excess_depth() {
        let mut duplicate = chain_graph(2);
        duplicate.nodes[1].overrides =
            D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                new_name: Some(node_id("n0")),
                ..Default::default()
            });
        duplicate.nodes[0].overrides =
            D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                new_name: Some(node_id("n0")),
                ..Default::default()
            });
        assert_eq!(
            duplicate.validate().unwrap_err().message,
            "work graph node \"n0\"[0] is defined more than once"
        );

        let mut too_many_outputs = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) =
            &mut too_many_outputs.nodes[0].overrides
        {
            overrides.output_overrides = vec![output(1024, Some("n1"), None)];
        }
        assert_eq!(
            too_many_outputs.validate().unwrap_err().message,
            "work graph node \"n0\"[0] output index 1024 exceeds the 1024 output limit"
        );

        let mut duplicated_output = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) =
            &mut duplicated_output.nodes[0].overrides
        {
            overrides.output_overrides =
                vec![output(0, Some("n1"), None), output(0, Some("n1"), None)];
        }
        assert_eq!(
            duplicated_output.validate().unwrap_err().message,
            "work graph node \"n0\"[0] defines output 0 more than once"
        );

        let mut both_limits = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut both_limits.nodes[0].overrides {
            overrides.output_overrides[0].max_records = Some(2);
            overrides.output_overrides[0].max_records_shared_with_output_index = Some(1);
        }
        assert_eq!(
            both_limits.validate().unwrap_err().message,
            "work graph node \"n0\"[0] output 0 sets both MaxRecords and \
             MaxRecordsSharedWithOutputIndex"
        );

        let mut zero_limit = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut zero_limit.nodes[0].overrides {
            overrides.output_overrides[0].max_records = Some(0);
        }
        assert_eq!(
            zero_limit.validate().unwrap_err().message,
            "work graph node \"n0\"[0] output 0 MaxRecords is zero"
        );

        let mut self_share = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut self_share.nodes[0].overrides {
            overrides.output_overrides[0].max_records_shared_with_output_index = Some(0);
        }
        assert_eq!(
            self_share.validate().unwrap_err().message,
            "work graph node \"n0\"[0] output 0 shares records with itself"
        );

        let mut undefined_share = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut undefined_share.nodes[0].overrides
        {
            overrides.output_overrides[0].max_records_shared_with_output_index = Some(4);
        }
        assert_eq!(
            undefined_share.validate().unwrap_err().message,
            "work graph node \"n0\"[0] output 0 shares records with undefined output 4"
        );

        let mut undefined_target = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) =
            &mut undefined_target.nodes[0].overrides
        {
            overrides.output_overrides[0].new_name = Some(node_id("missing"));
        }
        assert_eq!(
            undefined_target.validate().unwrap_err().message,
            "work graph node \"n0\"[0] output 0 targets undefined node \"missing\"[0]"
        );

        let mut sparse_target = undefined_target.clone();
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut sparse_target.nodes[0].overrides {
            overrides.output_overrides[0].allow_sparse_nodes = Some(true);
        }
        sparse_target.validate().expect("sparse target is allowed");

        let mut cycle = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut cycle.nodes[1].overrides {
            overrides.output_overrides = vec![output(0, Some("n0"), None)];
        }
        assert_eq!(
            cycle.validate().unwrap_err().message,
            "work graph contains a cycle through node \"n0\"[0]; only self-recursion is allowed"
        );

        let mut self_recursive = chain_graph(1);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut self_recursive.nodes[0].overrides
        {
            overrides.output_overrides = vec![output(0, Some("n0"), None)];
        }
        self_recursive
            .validate()
            .expect("self recursion is allowed");

        assert_eq!(
            chain_graph(33).validate().unwrap_err().message,
            "work graph depth 33 exceeds D3D12_WORK_GRAPHS_MAX_NODE_DEPTH (32)"
        );

        let mut bad_type = chain_graph(1);
        bad_type.nodes[0].node_type = 9;
        assert_eq!(
            bad_type.validate().unwrap_err().message,
            "work graph node type 9 is not D3D12_NODE_TYPE_SHADER or \
             D3D12_NODE_TYPE_PROGRAM"
        );

        let mut shader_mesh = chain_graph(1);
        shader_mesh.nodes[0].overrides =
            D3d12NodeOverrides::Mesh(D3d12MeshLaunchOverrides::default());
        assert_eq!(
            shader_mesh.validate().unwrap_err().message,
            "work graph shader node \"n0\"[0] cannot use mesh launch overrides"
        );

        let mut program_shader = mesh_node("mesh", None);
        program_shader.overrides =
            D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides::default());
        let program_graph = D3d12WorkGraph {
            program_name: "graph".to_string(),
            flags: 0,
            entrypoints: vec![node_id("mesh")],
            nodes: vec![program_shader],
        };
        assert_eq!(
            program_graph.validate().unwrap_err().message,
            "work graph program node \"mesh\"[0] requires mesh launch overrides"
        );
    }

    #[test]
    fn work_graph_record_layout_entrypoints_and_root_tables_are_pinned() {
        let graph = chain_graph(2);
        assert_eq!(
            graph.validate_entrypoint(9).unwrap_err().message,
            "work graph entrypoint index 9 is out of range (1 entries)"
        );
        let mut missing = graph.clone();
        missing.entrypoints = vec![node_id("missing")];
        assert_eq!(
            missing.validate_entrypoint(0).unwrap_err().message,
            "work graph entrypoint \"missing\"[0] does not name a node"
        );

        let bytes = record_bytes(&[(0, 0), (0, 0)]);
        assert_eq!(
            graph.parse_records(&bytes, 2, 4).unwrap_err().message,
            "work graph record stride 4 is smaller than the 8-byte node/output record"
        );
        assert_eq!(
            graph.parse_records(&bytes, 2, 9).unwrap_err().message,
            "work graph record stride 9 is not a multiple of 4"
        );
        assert_eq!(
            graph.parse_records(&bytes, 2, 32_772).unwrap_err().message,
            "work graph record stride 32772 exceeds the 32 KiB node record limit"
        );
        assert_eq!(
            graph.parse_records(&bytes[..8], 2, 8).unwrap_err().message,
            "work graph record range (16 bytes) exceeds the supplied 8 bytes"
        );
        assert_eq!(
            graph
                .parse_records(&record_bytes(&[(5, 0)]), 1, 8)
                .unwrap_err()
                .message,
            "work graph record 0 node index 5 is out of range for 2 nodes"
        );
        assert_eq!(
            graph
                .parse_records(&record_bytes(&[(0, 3)]), 1, 8)
                .unwrap_err()
                .message,
            "work graph record 0 output index 3 is out of range for node \"n0\"[0] output count 1"
        );
        assert!(
            graph
                .parse_records(
                    &record_bytes(&[(WORK_GRAPH_EMPTY_RECORD, WORK_GRAPH_EMPTY_RECORD)]),
                    1,
                    8
                )
                .expect("empty record")
                .is_empty()
        );
        assert_eq!(
            graph
                .record_plan(
                    0,
                    &[D3d12WorkGraphRecord {
                        node_index: 1,
                        output_index: 0,
                    }]
                )
                .unwrap_err()
                .message,
            "work graph record 0 targets node 1 but entrypoint 0 resolves to node 0"
        );

        let mut limited = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut limited.nodes[0].overrides {
            overrides.output_overrides[0].max_records = Some(1);
        }
        let records = vec![
            D3d12WorkGraphRecord {
                node_index: 0,
                output_index: 0,
            };
            2
        ];
        assert_eq!(
            limited.record_plan(0, &records).unwrap_err().message,
            "work graph node \"n0\"[0] output 0 received 2 records but MaxRecords is 1"
        );

        let mut recursive = chain_graph(1);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut recursive.nodes[0].overrides {
            overrides.output_overrides = vec![output(0, Some("n0"), None)];
        }
        assert_eq!(
            recursive
                .record_plan(
                    0,
                    &[D3d12WorkGraphRecord {
                        node_index: 0,
                        output_index: 0,
                    }]
                )
                .unwrap_err()
                .message,
            "work graph recursion depth exceeds D3D12_WORK_GRAPHS_MAX_NODE_DEPTH (32)"
        );

        let mut rooted = chain_graph(1);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut rooted.nodes[0].overrides {
            overrides.local_root_arguments_table_index = Some(2);
        }
        assert_eq!(
            rooted
                .validate_local_root_arguments(&D3d12GpuRangeAndStride {
                    start: 0,
                    size: 16,
                    stride: 8,
                })
                .unwrap_err()
                .message,
            "node local root arguments table size 16 is smaller than the 20 bytes required \
             by table index 2"
        );
        assert_eq!(
            rooted
                .validate_local_root_arguments(&D3d12GpuRangeAndStride {
                    start: 0,
                    size: 16,
                    stride: 0,
                })
                .unwrap_err()
                .message,
            "node local root arguments table stride is zero but a node uses table index 2"
        );
        let mut auto = chain_graph(1);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut auto.nodes[0].overrides {
            overrides.local_root_arguments_table_index = Some(u32::MAX);
        }
        auto.validate_local_root_arguments(&D3d12GpuRangeAndStride::default())
            .expect("auto-assigned table index is ignored");
        assert_eq!(
            rooted
                .validate_local_root_arguments(&D3d12GpuRangeAndStride {
                    start: 0,
                    size: 4,
                    stride: u64::MAX - 3,
                })
                .unwrap_err()
                .message,
            "node local root arguments table range overflows"
        );
        D3d12GpuRangeAndStride {
            start: 4,
            size: 4,
            stride: 0,
        }
        .validate()
        .expect("aligned table");
        assert_eq!(
            D3d12GpuRangeAndStride {
                start: 2,
                size: 4,
                stride: 0,
            }
            .validate()
            .unwrap_err()
            .message,
            "node local root arguments table address 0x2 is not 4-byte aligned"
        );
        assert_eq!(
            D3d12GpuRangeAndStride {
                start: 0,
                size: 2,
                stride: 0,
            }
            .validate()
            .unwrap_err()
            .message,
            "node local root arguments table size 2 is not a multiple of 4"
        );
        assert_eq!(
            D3d12GpuRangeAndStride {
                start: 0,
                size: 4,
                stride: 2,
            }
            .validate()
            .unwrap_err()
            .message,
            "node local root arguments table stride 2 is not a multiple of 4"
        );
        assert_eq!(
            D3d12GpuRangeAndStride {
                start: u64::MAX - 3,
                size: 8,
                stride: 0,
            }
            .validate()
            .unwrap_err()
            .message,
            "node local root arguments table range overflows"
        );

        assert!(!chain_graph(1).uses_record_semantics());
        assert!(graph.uses_record_semantics());
    }

    #[test]
    fn work_graph_plan_edge_cases_and_override_accessors_are_pinned() {
        let none = D3d12NodeOverrides::None;
        assert_eq!(none.local_root_arguments_table_index(), None);
        assert_eq!(none.share_input_of(), None);
        let shared = D3d12NodeId::new("shared", 0);
        let variants = [
            D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                local_root_arguments_table_index: Some(1),
                share_input_of: Some(shared.clone()),
                ..Default::default()
            }),
            D3d12NodeOverrides::Coalescing(D3d12CoalescingLaunchOverrides {
                local_root_arguments_table_index: Some(1),
                share_input_of: Some(shared.clone()),
                ..Default::default()
            }),
            D3d12NodeOverrides::Thread(D3d12ThreadLaunchOverrides {
                local_root_arguments_table_index: Some(1),
                share_input_of: Some(shared.clone()),
                ..Default::default()
            }),
            D3d12NodeOverrides::CommonCompute(D3d12CommonComputeNodeOverrides {
                local_root_arguments_table_index: Some(1),
                share_input_of: Some(shared.clone()),
                ..Default::default()
            }),
            D3d12NodeOverrides::Mesh(D3d12MeshLaunchOverrides {
                local_root_arguments_table_index: Some(1),
                share_input_of: Some(shared.clone()),
                ..Default::default()
            }),
        ];
        for overrides in variants {
            assert_eq!(overrides.local_root_arguments_table_index(), Some(1));
            assert_eq!(overrides.share_input_of(), Some(&shared));
        }

        let mut limits = chain_graph(1);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut limits.nodes[0].overrides {
            overrides.output_overrides = vec![
                D3d12NodeOutputOverrides {
                    output_index: 0,
                    max_records_shared_with_output_index: Some(1),
                    ..Default::default()
                },
                D3d12NodeOutputOverrides {
                    output_index: 1,
                    max_records: Some(3),
                    ..Default::default()
                },
                D3d12NodeOutputOverrides {
                    output_index: 2,
                    max_records_shared_with_output_index: Some(3),
                    ..Default::default()
                },
                D3d12NodeOutputOverrides {
                    output_index: 3,
                    max_records_shared_with_output_index: Some(4),
                    ..Default::default()
                },
                D3d12NodeOutputOverrides {
                    output_index: 4,
                    max_records_shared_with_output_index: Some(3),
                    ..Default::default()
                },
            ];
        }
        assert_eq!(limits.nodes[0].output_limit(0), Some(3));
        assert_eq!(limits.nodes[0].output_limit(1), Some(3));
        assert_eq!(limits.nodes[0].output_limit(2), None);
        assert_eq!(limits.nodes[0].output_limit(3), None);
        assert_eq!(limits.nodes[0].output_limit(9), None);
        assert_eq!(limits.node_id(0), Some(node_id("n0")));
        assert_eq!(limits.node_id(9), None);

        let mut valid_shared = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut valid_shared.nodes[0].overrides {
            overrides.output_overrides = vec![
                D3d12NodeOutputOverrides {
                    output_index: 0,
                    new_name: Some(node_id("n1")),
                    max_records_shared_with_output_index: Some(1),
                    ..Default::default()
                },
                D3d12NodeOutputOverrides {
                    output_index: 1,
                    new_name: Some(node_id("n1")),
                    max_records: Some(3),
                    ..Default::default()
                },
            ];
        }
        valid_shared
            .validate()
            .expect("shared limit and concrete target");
        let mut shared_budget = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut shared_budget.nodes[0].overrides {
            overrides.output_overrides = vec![
                D3d12NodeOutputOverrides {
                    output_index: 0,
                    new_name: Some(node_id("n1")),
                    max_records_shared_with_output_index: Some(1),
                    ..Default::default()
                },
                D3d12NodeOutputOverrides {
                    output_index: 1,
                    new_name: Some(node_id("n1")),
                    max_records: Some(1),
                    ..Default::default()
                },
            ];
        }
        assert_eq!(
            shared_budget
                .record_plan(
                    0,
                    &[
                        D3d12WorkGraphRecord {
                            node_index: 0,
                            output_index: 0,
                        },
                        D3d12WorkGraphRecord {
                            node_index: 0,
                            output_index: 1,
                        },
                    ],
                )
                .unwrap_err()
                .message,
            "work graph node \"n0\"[0] output 1 received 2 records but MaxRecords is 1"
        );

        let mut unnamed = chain_graph(1);
        unnamed.nodes[0].overrides = D3d12NodeOverrides::None;
        unnamed.nodes[0].shader = String::new();
        assert_eq!(
            unnamed.validate().unwrap_err().message,
            "work graph node 0 has an empty name"
        );

        let mut empty_target = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut empty_target.nodes[0].overrides {
            overrides.output_overrides[0].new_name = Some(D3d12NodeId::new("", 0));
        }
        assert_eq!(
            empty_target.validate().unwrap_err().message,
            "work graph node \"n0\"[0] output 0 has an empty target name"
        );

        let mut bad_share = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut bad_share.nodes[1].overrides {
            overrides.share_input_of = Some(D3d12NodeId::new("missing", 0));
        }
        assert_eq!(
            bad_share.validate().unwrap_err().message,
            "work graph node \"n1\"[0] shares input with undefined node \"missing\"[0]"
        );
        let mut empty_share = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut empty_share.nodes[1].overrides {
            overrides.share_input_of = Some(D3d12NodeId::new("", 0));
        }
        assert_eq!(
            empty_share.validate().unwrap_err().message,
            "work graph node \"n1\"[0] shares input with an empty node name"
        );
        let mut good_share = chain_graph(2);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut good_share.nodes[1].overrides {
            overrides.share_input_of = Some(node_id("n0"));
        }
        good_share.validate().expect("share input resolves");

        let mut no_entry = chain_graph(2);
        no_entry.entrypoints.clear();
        no_entry.validate().expect("all nodes are depth roots");

        let mut diamond = chain_graph(4);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut diamond.nodes[0].overrides {
            overrides.output_overrides =
                vec![output(0, Some("n1"), None), output(1, Some("n1"), None)];
        }
        diamond.validate().expect("diamond depth memoises");

        assert!(limits.record_plan(0, &[]).unwrap().is_empty());
        assert_eq!(
            limits
                .record_plan(
                    0,
                    &[D3d12WorkGraphRecord {
                        node_index: 0,
                        output_index: 9,
                    }]
                )
                .unwrap_err()
                .message,
            "work graph record 0 output index 9 is out of range for node \"n0\" output count 5"
        );

        let mut max_grid = chain_graph(1);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut max_grid.nodes[0].overrides {
            overrides.dispatch_grid = None;
            overrides.max_dispatch_grid = Some([0, 0, 0]);
        }
        assert_eq!(max_grid.dispatch_plan(0, 1, 8).unwrap()[0].grid, [1, 1, 1]);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut max_grid.nodes[0].overrides {
            overrides.max_dispatch_grid = Some([2, 2, 2]);
        }
        assert_eq!(max_grid.dispatch_plan(0, 1, 8).unwrap()[0].grid, [2, 2, 2]);
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut max_grid.nodes[0].overrides {
            overrides.dispatch_grid = Some([WORK_GRAPH_MAX_THREAD_GROUPS_PER_GRID; 3]);
        }
        assert_eq!(
            max_grid.dispatch_plan(0, 1, 8).unwrap_err().message,
            "work graph node 0 dispatch grid [16777215, 16777215, 16777215] exceeds the total \
             thread-group limit 16777215"
        );

        assert!(max_grid.parse_records(&[], 0, 0).unwrap().is_empty());
        if let D3d12NodeOverrides::Broadcasting(overrides) = &mut max_grid.nodes[0].overrides {
            overrides.dispatch_grid = Some([1, 1, 1]);
            overrides.local_root_arguments_table_index = Some(0);
        }
        max_grid
            .validate_local_root_arguments(&D3d12GpuRangeAndStride {
                start: 4,
                size: 4,
                stride: 0,
            })
            .expect("table index zero needs no stride");
    }

    #[test]
    fn work_graph_mesh_program_nodes_parse_with_overrides() {
        let mut memory = base_memory();
        put_wide(&mut memory.data, 0x100, "graph");
        put_wide(&mut memory.data, 0x120, "meshprog");
        put_wide(&mut memory.data, 0x140, "mesh");
        put_u32(&mut memory.data, 0x300, D3D12_NODE_TYPE_PROGRAM);
        put_u64(&mut memory.data, 0x308, 0x120);
        put_u32(&mut memory.data, 0x310, PROGRAM_NODE_OVERRIDES_MESH_LAUNCH);
        put_u64(&mut memory.data, 0x318, 0x500);
        put_u64(&mut memory.data, 0x500, 0x600);
        put_u32(&mut memory.data, 0x600, 1);
        put_u64(&mut memory.data, 0x508, 0x610);
        put_u32(&mut memory.data, 0x610, 1);
        put_u64(&mut memory.data, 0x510, 0x620);
        write_node_id(&mut memory.data, 0x620, 0x140, 0);
        put_u64(&mut memory.data, 0x520, 0x640);
        put_u32(&mut memory.data, 0x640, 2);
        put_u32(&mut memory.data, 0x644, 3);
        put_u32(&mut memory.data, 0x648, 1);
        put_u64(&mut memory.data, 0x528, 0x650);
        put_u32(&mut memory.data, 0x650, 4);
        put_u32(&mut memory.data, 0x654, 5);
        put_u32(&mut memory.data, 0x658, 1);
        put_u64(&mut memory.data, 0x530, 0x660);
        put_u32(&mut memory.data, 0x660, 7);
        put_u32(&mut memory.data, 0x664, 1);
        let desc = write_desc(&mut memory.data, 0, 1, 0x280, 1, 0x300);
        write_node_id(&mut memory.data, 0x280, 0x140, 0);
        let graph = D3d12WorkGraph::parse(&memory, desc).expect("mesh graph");
        let node = &graph.nodes[0];
        assert!(node.is_mesh());
        assert_eq!(node.shader, "meshprog");
        assert_eq!(node.output_count(), 0);
        assert_eq!(node.overrides.local_root_arguments_table_index(), Some(1));
        assert_eq!(node.overrides.share_input_of(), None);
        match &node.overrides {
            D3d12NodeOverrides::Mesh(overrides) => {
                assert_eq!(overrides.local_root_arguments_table_index, Some(1));
                assert_eq!(overrides.program_entry, Some(true));
                assert_eq!(overrides.new_name, Some(node_id("mesh")));
                assert_eq!(overrides.dispatch_grid, Some([2, 3, 1]));
                assert_eq!(overrides.max_dispatch_grid, Some([4, 5, 1]));
                assert_eq!(
                    overrides.max_input_records_per_graph_entry_record,
                    Some((7, true))
                );
            }
            other => panic!("unexpected overrides: {other:?}"),
        }
        graph.validate().expect("valid mesh graph");

        put_u64(&mut memory.data, 0x530, 0);
        let graph = D3d12WorkGraph::parse(&memory, desc).expect("mesh without input cap");
        match &graph.nodes[0].overrides {
            D3d12NodeOverrides::Mesh(overrides) => {
                assert_eq!(overrides.max_input_records_per_graph_entry_record, None);
            }
            other => panic!("unexpected overrides: {other:?}"),
        }

        put_u64(&mut memory.data, 0x308, 0);
        assert_eq!(
            D3d12WorkGraph::parse(&memory, desc).unwrap_err().message,
            "work graph program node has a null Program name"
        );
        put_u64(&mut memory.data, 0x308, 0x160);
        put_u32(&mut memory.data, 0x160, 0);
        assert_eq!(
            D3d12WorkGraph::parse(&memory, desc).unwrap_err().message,
            "work graph program node has an empty Program name"
        );
        put_u64(&mut memory.data, 0x308, 0x120);
        put_u32(&mut memory.data, 0x310, 1);
        assert_eq!(
            D3d12WorkGraph::parse(&memory, desc).unwrap_err().message,
            "work graph program node overrides type 1 is not \
             D3D12_PROGRAM_NODE_OVERRIDES_TYPE_MESH_LAUNCH"
        );
        put_u32(&mut memory.data, 0x310, PROGRAM_NODE_OVERRIDES_MESH_LAUNCH);
        put_u64(&mut memory.data, 0x318, 0);
        assert_eq!(
            D3d12WorkGraph::parse(&memory, desc).unwrap_err().message,
            "mesh launch overrides pointer is null"
        );
        put_u32(&mut memory.data, 0x300, D3D12_NODE_TYPE_PROGRAM);
        put_u32(&mut memory.data, 0x310, PROGRAM_NODE_OVERRIDES_NONE);
        put_u64(&mut memory.data, 0x318, 0);
        let graph = D3d12WorkGraph::parse(&memory, desc).expect("mesh node without overrides");
        assert!(graph.nodes[0].is_mesh());
        graph
            .validate()
            .expect("mesh node without overrides validates");
    }
}
