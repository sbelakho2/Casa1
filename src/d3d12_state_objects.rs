//! Real D3D12 state-object parsing and lifetime support.
//!
//! The runtime materialises `ID3D12StateObject` contents from the guest's
//! `D3D12_STATE_OBJECT_DESC`: every subobject is parsed from guest memory,
//! validated against the documented D3D12 layouts, and retained with a real
//! reference-counted lifetime. Raytracing state objects expose shader
//! identifiers and pipeline configuration; work-graph state objects retain the
//! parsed graph representation from [`super::work_graphs`].

use std::collections::BTreeMap;

use crate::cpu::MemoryImage;
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;

use super::work_graphs::D3d12WorkGraph;

// D3D12_STATE_OBJECT_TYPE.
pub const STATE_OBJECT_TYPE_COLLECTION: u32 = 0;
pub const STATE_OBJECT_TYPE_RAYTRACING_PIPELINE: u32 = 3;
pub const STATE_OBJECT_TYPE_EXECUTABLE: u32 = 4;

// D3D12_STATE_SUBOBJECT_TYPE.
pub const SUBOBJECT_STATE_OBJECT_CONFIG: u32 = 0;
pub const SUBOBJECT_GLOBAL_ROOT_SIGNATURE: u32 = 1;
pub const SUBOBJECT_LOCAL_ROOT_SIGNATURE: u32 = 2;
pub const SUBOBJECT_NODE_MASK: u32 = 3;
pub const SUBOBJECT_DXIL_LIBRARY: u32 = 5;
pub const SUBOBJECT_EXISTING_COLLECTION: u32 = 6;
pub const SUBOBJECT_TO_EXPORTS_ASSOCIATION: u32 = 7;
pub const SUBOBJECT_DXIL_SUBOBJECT_TO_EXPORTS_ASSOCIATION: u32 = 8;
pub const SUBOBJECT_RAYTRACING_SHADER_CONFIG: u32 = 9;
pub const SUBOBJECT_RAYTRACING_PIPELINE_CONFIG: u32 = 10;
pub const SUBOBJECT_HIT_GROUP: u32 = 11;
pub const SUBOBJECT_RAYTRACING_PIPELINE_CONFIG1: u32 = 12;
pub const SUBOBJECT_WORK_GRAPH: u32 = 13;
pub const SUBOBJECT_GENERIC_PROGRAM: u32 = 29;
pub const SUBOBJECT_MAX_VALID: u32 = 37;

pub const STATE_OBJECT_FLAG_NONE: u32 = 0;
pub const STATE_OBJECT_FLAG_ALLOW_LOCAL_DEPENDENCIES_ON_EXTERNAL_DEFINITIONS: u32 = 0x1;
pub const STATE_OBJECT_FLAG_ALLOW_EXTERNAL_DEPENDENCIES_ON_LOCAL_DEFINITIONS: u32 = 0x2;
pub const STATE_OBJECT_FLAG_ALLOW_STATE_OBJECT_ADDITIONS: u32 = 0x4;
pub const STATE_OBJECT_FLAGS_VALID: u32 = 0x7;

pub const HIT_GROUP_TYPE_TRIANGLES: u32 = 0;
pub const HIT_GROUP_TYPE_PROCEDURAL_PRIMITIVE: u32 = 1;

pub const RAYTRACING_MAX_ATTRIBUTE_SIZE_IN_BYTES: u32 = 32;
pub const RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH: u32 = 31;
pub const RAYTRACING_PIPELINE_FLAGS_VALID: u32 = 0x100 | 0x200 | 0x400;
pub const SHADER_IDENTIFIER_SIZE_IN_BYTES: usize = 32;

/// Read-only guest memory view used by the state-object/work-graph parsers.
pub trait StateObjectMemory {
    fn read_bytes(&self, address: u64, len: usize) -> AppResult<Vec<u8>>;
    fn read_u32(&self, address: u64) -> AppResult<u32>;
    fn read_u64(&self, address: u64) -> AppResult<u64>;
    fn read_u16(&self, address: u64) -> AppResult<u16>;

    fn read_wide_string(&self, address: u64) -> AppResult<String> {
        if address == 0 {
            return Ok(String::new());
        }
        let mut units = Vec::new();
        let mut cursor = address;
        loop {
            if units.len() >= 4096 {
                return Err(invalid(format!(
                    "UTF-16 string at {address:#x} exceeds the 4096-unit limit"
                )));
            }
            let unit = self.read_u16(cursor)?;
            if unit == 0 {
                break;
            }
            units.push(unit);
            cursor = cursor
                .checked_add(2)
                .ok_or_else(|| invalid("UTF-16 string pointer overflow"))?;
        }
        Ok(String::from_utf16_lossy(&units))
    }
}

impl StateObjectMemory for MemoryImage {
    fn read_bytes(&self, address: u64, len: usize) -> AppResult<Vec<u8>> {
        MemoryImage::read_bytes(self, address, len)
    }

    fn read_u32(&self, address: u64) -> AppResult<u32> {
        MemoryImage::read_u32(self, address)
    }

    fn read_u64(&self, address: u64) -> AppResult<u64> {
        MemoryImage::read_u64(self, address)
    }

    fn read_u16(&self, address: u64) -> AppResult<u16> {
        MemoryImage::read_u16(self, address)
    }
}

/// A parsed D3D12_DXIL_LIBRARY_DESC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3d12DxilLibrary {
    pub bytecode: Vec<u8>,
    pub exports: Vec<D3d12ExportDesc>,
}

/// A parsed D3D12_EXPORT_DESC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3d12ExportDesc {
    pub name: String,
    pub export_to_rename: Option<String>,
    pub flags: u32,
}

/// A parsed D3D12_EXISTING_COLLECTION_DESC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3d12ExistingCollection {
    pub collection: u64,
    pub exports: Vec<D3d12ExportDesc>,
}

/// A parsed D3D12_HIT_GROUP_DESC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3d12HitGroup {
    pub name: String,
    pub ty: u32,
    pub any_hit: Option<String>,
    pub closest_hit: Option<String>,
    pub intersection: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum D3d12StateSubobject {
    StateObjectConfig {
        flags: u32,
    },
    GlobalRootSignature {
        object: u64,
    },
    LocalRootSignature {
        object: u64,
    },
    NodeMask {
        mask: u32,
    },
    DxilLibrary(D3d12DxilLibrary),
    ExistingCollection(D3d12ExistingCollection),
    SubobjectToExportsAssociation {
        subobject: u64,
        exports: Vec<String>,
    },
    RaytracingShaderConfig {
        max_payload_size: u32,
        max_attribute_size: u32,
    },
    RaytracingPipelineConfig {
        max_trace_recursion_depth: u32,
    },
    RaytracingPipelineConfig1 {
        max_trace_recursion_depth: u32,
        flags: u32,
    },
    HitGroup(D3d12HitGroup),
    WorkGraph(D3d12WorkGraph),
    GenericProgram {
        program_name: String,
        exports: Vec<String>,
    },
    /// A defined D3D12 subobject type that this bridge retains but does not
    /// interpret yet. It is never silently dropped: the type is recorded so
    /// the owning state object can report it.
    Unsupported {
        ty: u32,
    },
}

/// A parsed D3D12_STATE_OBJECT_DESC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3d12StateObjectDesc {
    pub object_type: u32,
    pub subobjects: Vec<D3d12StateSubobject>,
}

/// A live state object with reference-counted lifetime.
#[derive(Debug, Clone)]
pub struct D3d12StateObject {
    pub handle: u64,
    pub object_type: u32,
    pub subobjects: Vec<D3d12StateSubobject>,
    pub ref_count: u32,
    pub exported_shaders: BTreeMap<String, [u8; SHADER_IDENTIFIER_SIZE_IN_BYTES]>,
    pub pipeline_config: Option<(u32, u32)>,
    pub shader_config: Option<(u32, u32)>,
    pub work_graphs: Vec<D3d12WorkGraph>,
}

impl D3d12StateObject {
    pub fn is_collection(&self) -> bool {
        self.object_type == STATE_OBJECT_TYPE_COLLECTION
    }

    pub fn allow_additions(&self) -> bool {
        self.subobjects.iter().any(|subobject| {
            matches!(
                subobject,
                D3d12StateSubobject::StateObjectConfig { flags }
                    if flags & STATE_OBJECT_FLAG_ALLOW_STATE_OBJECT_ADDITIONS != 0
            )
        })
    }

    pub fn shader_identifier(&self, export: &str) -> Option<[u8; SHADER_IDENTIFIER_SIZE_IN_BYTES]> {
        self.exported_shaders.get(export).copied()
    }

    pub fn first_dxil(&self) -> Option<&[u8]> {
        self.subobjects
            .iter()
            .find_map(|subobject| match subobject {
                D3d12StateSubobject::DxilLibrary(library) => Some(library.bytecode.as_slice()),
                _ => None,
            })
    }
}

/// Parse a D3D12_STATE_OBJECT_DESC from guest memory.
pub fn parse_state_object(
    memory: &dyn StateObjectMemory,
    address: u64,
) -> AppResult<D3d12StateObjectDesc> {
    if address == 0 {
        return Err(invalid("state object description pointer is null"));
    }
    let object_type = memory.read_u32(address)?;
    if !matches!(
        object_type,
        STATE_OBJECT_TYPE_COLLECTION
            | STATE_OBJECT_TYPE_RAYTRACING_PIPELINE
            | STATE_OBJECT_TYPE_EXECUTABLE
    ) {
        return Err(invalid(format!(
            "D3D12_STATE_OBJECT_TYPE {object_type} is not defined"
        )));
    }
    let num_subobjects = memory.read_u32(address + 4)?;
    let subobjects_ptr = memory.read_u64(address + 8)?;
    if num_subobjects > 1_000_000 {
        return Err(invalid(format!(
            "state object NumSubobjects {num_subobjects} exceeds the supported limit"
        )));
    }
    if num_subobjects > 0 && subobjects_ptr == 0 {
        return Err(invalid("state object pSubobjects is null"));
    }

    let mut subobjects = Vec::with_capacity(num_subobjects as usize);
    for index in 0..num_subobjects as u64 {
        // D3D12_STATE_SUBOBJECT is 16 bytes on x64: Type at +0, pDesc at +8.
        let subobject = subobjects_ptr + index * 16;
        let ty = memory.read_u32(subobject)?;
        let desc = memory.read_u64(subobject + 8)?;
        if ty >= SUBOBJECT_MAX_VALID {
            return Err(invalid(format!(
                "D3D12_STATE_SUBOBJECT_TYPE {ty} is outside the defined 0..{SUBOBJECT_MAX_VALID} range"
            )));
        }
        if !is_defined_subobject_type(ty) {
            return Err(invalid(format!(
                "D3D12_STATE_SUBOBJECT_TYPE {ty} is not defined"
            )));
        }
        if desc == 0 {
            return Err(invalid(format!(
                "state subobject type {ty} has a null description pointer"
            )));
        }
        subobjects.push(parse_subobject(memory, ty, desc)?);
    }

    Ok(D3d12StateObjectDesc {
        object_type,
        subobjects,
    })
}

fn is_defined_subobject_type(ty: u32) -> bool {
    matches!(
        ty,
        0 | 1
            | 2
            | 3
            | 5
            | 6
            | 7
            | 8
            | 9
            | 10
            | 11
            | 12
            | 13
            | 14
            | 15
            | 16
            | 17
            | 18
            | 19
            | 20
            | 21
            | 22
            | 23
            | 24
            | 26
            | 27
            | 28
            | 29
            | 30
            | 31
            | 32
            | 33
            | 36
    )
}

fn parse_subobject(
    memory: &dyn StateObjectMemory,
    ty: u32,
    desc: u64,
) -> AppResult<D3d12StateSubobject> {
    match ty {
        SUBOBJECT_STATE_OBJECT_CONFIG => {
            let flags = memory.read_u32(desc)?;
            if flags & !STATE_OBJECT_FLAGS_VALID != 0 {
                return Err(invalid(format!(
                    "D3D12_STATE_OBJECT_FLAGS {flags:#x} contain undefined bits"
                )));
            }
            Ok(D3d12StateSubobject::StateObjectConfig { flags })
        }
        SUBOBJECT_GLOBAL_ROOT_SIGNATURE => {
            let object = memory.read_u64(desc)?;
            if object == 0 {
                return Err(invalid("global root signature pointer is null"));
            }
            Ok(D3d12StateSubobject::GlobalRootSignature { object })
        }
        SUBOBJECT_LOCAL_ROOT_SIGNATURE => {
            let object = memory.read_u64(desc)?;
            if object == 0 {
                return Err(invalid("local root signature pointer is null"));
            }
            Ok(D3d12StateSubobject::LocalRootSignature { object })
        }
        SUBOBJECT_NODE_MASK => Ok(D3d12StateSubobject::NodeMask {
            mask: memory.read_u32(desc)?,
        }),
        SUBOBJECT_DXIL_LIBRARY => Ok(D3d12StateSubobject::DxilLibrary(parse_dxil_library(
            memory, desc,
        )?)),
        SUBOBJECT_EXISTING_COLLECTION => Ok(D3d12StateSubobject::ExistingCollection(
            parse_existing_collection(memory, desc)?,
        )),
        SUBOBJECT_TO_EXPORTS_ASSOCIATION | SUBOBJECT_DXIL_SUBOBJECT_TO_EXPORTS_ASSOCIATION => {
            // D3D12_SUBOBJECT_TO_EXPORTS_ASSOCIATION:
            // +0 pSubobjectToAssociate, +8 NumExports, +16 pExports
            let subobject = memory.read_u64(desc)?;
            if subobject == 0 {
                return Err(invalid("subobject-to-exports association pointer is null"));
            }
            let num_exports = memory.read_u32(desc + 8)?;
            let exports_ptr = memory.read_u64(desc + 16)?;
            let exports = read_export_names(memory, exports_ptr, num_exports)?;
            Ok(D3d12StateSubobject::SubobjectToExportsAssociation { subobject, exports })
        }
        SUBOBJECT_RAYTRACING_SHADER_CONFIG => {
            let max_payload_size = memory.read_u32(desc)?;
            let max_attribute_size = memory.read_u32(desc + 4)?;
            if max_attribute_size > RAYTRACING_MAX_ATTRIBUTE_SIZE_IN_BYTES {
                return Err(invalid(format!(
                    "raytracing MaxAttributeSizeInBytes {max_attribute_size} exceeds \
                     D3D12_RAYTRACING_MAX_ATTRIBUTE_SIZE_IN_BYTES \
                     ({RAYTRACING_MAX_ATTRIBUTE_SIZE_IN_BYTES})"
                )));
            }
            if !max_attribute_size.is_multiple_of(4) {
                return Err(invalid(format!(
                    "raytracing MaxAttributeSizeInBytes {max_attribute_size} is not a multiple of 4"
                )));
            }
            Ok(D3d12StateSubobject::RaytracingShaderConfig {
                max_payload_size,
                max_attribute_size,
            })
        }
        SUBOBJECT_RAYTRACING_PIPELINE_CONFIG => {
            let depth = memory.read_u32(desc)?;
            if depth > RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH {
                return Err(invalid(format!(
                    "raytracing MaxTraceRecursionDepth {depth} exceeds \
                     D3D12_RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH \
                     ({RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH})"
                )));
            }
            Ok(D3d12StateSubobject::RaytracingPipelineConfig {
                max_trace_recursion_depth: depth,
            })
        }
        SUBOBJECT_RAYTRACING_PIPELINE_CONFIG1 => {
            let depth = memory.read_u32(desc)?;
            let flags = memory.read_u32(desc + 4)?;
            if depth > RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH {
                return Err(invalid(format!(
                    "raytracing MaxTraceRecursionDepth {depth} exceeds the defined limit"
                )));
            }
            if flags & !RAYTRACING_PIPELINE_FLAGS_VALID != 0 {
                return Err(invalid(format!(
                    "D3D12_RAYTRACING_PIPELINE_FLAGS {flags:#x} contain undefined bits"
                )));
            }
            Ok(D3d12StateSubobject::RaytracingPipelineConfig1 {
                max_trace_recursion_depth: depth,
                flags,
            })
        }
        SUBOBJECT_HIT_GROUP => Ok(D3d12StateSubobject::HitGroup(parse_hit_group(
            memory, desc,
        )?)),
        SUBOBJECT_WORK_GRAPH => Ok(D3d12StateSubobject::WorkGraph(D3d12WorkGraph::parse(
            memory, desc,
        )?)),
        SUBOBJECT_GENERIC_PROGRAM => parse_generic_program(memory, desc),
        other => Ok(D3d12StateSubobject::Unsupported { ty: other }),
    }
}

fn parse_dxil_library(memory: &dyn StateObjectMemory, desc: u64) -> AppResult<D3d12DxilLibrary> {
    // D3D12_DXIL_LIBRARY_DESC:
    // +0 DXILLibrary.pShaderBytecode, +8 BytecodeLength,
    // +16 NumExports, +24 pExports
    let bytecode_ptr = memory.read_u64(desc)?;
    let bytecode_len = memory.read_u64(desc + 8)?;
    if bytecode_ptr == 0 || bytecode_len == 0 {
        return Err(invalid("DXIL library bytecode is empty"));
    }
    if bytecode_len > 64 * 1024 * 1024 {
        return Err(invalid(format!(
            "DXIL library bytecode length {bytecode_len} exceeds the 64 MiB limit"
        )));
    }
    let bytecode = memory.read_bytes(bytecode_ptr, bytecode_len as usize)?;
    let num_exports = memory.read_u32(desc + 16)?;
    let exports_ptr = memory.read_u64(desc + 24)?;
    if num_exports > 65_535 {
        return Err(invalid(format!(
            "DXIL library NumExports {num_exports} exceeds the supported limit"
        )));
    }
    let mut exports = Vec::with_capacity(num_exports as usize);
    if num_exports > 0 && exports_ptr == 0 {
        return Err(invalid("DXIL library pExports is null"));
    }
    for index in 0..num_exports as u64 {
        // D3D12_EXPORT_DESC is 24 bytes: Name +0, ExportToRename +8, Flags +16.
        let export = exports_ptr + index * 24;
        let name = memory.read_wide_string(memory.read_u64(export)?)?;
        if name.is_empty() {
            return Err(invalid("DXIL export has an empty name"));
        }
        let rename_ptr = memory.read_u64(export + 8)?;
        exports.push(D3d12ExportDesc {
            name,
            export_to_rename: if rename_ptr == 0 {
                None
            } else {
                Some(memory.read_wide_string(rename_ptr)?)
            },
            flags: memory.read_u32(export + 16)?,
        });
    }
    Ok(D3d12DxilLibrary { bytecode, exports })
}

fn parse_existing_collection(
    memory: &dyn StateObjectMemory,
    desc: u64,
) -> AppResult<D3d12ExistingCollection> {
    let collection = memory.read_u64(desc)?;
    if collection == 0 {
        return Err(invalid("existing collection pointer is null"));
    }
    let num_exports = memory.read_u32(desc + 8)?;
    let exports_ptr = memory.read_u64(desc + 16)?;
    if num_exports > 65_535 {
        return Err(invalid(format!(
            "existing collection NumExports {num_exports} exceeds the supported limit"
        )));
    }
    if num_exports > 0 && exports_ptr == 0 {
        return Err(invalid("existing collection pExports is null"));
    }
    let mut exports = Vec::with_capacity(num_exports as usize);
    for index in 0..num_exports as u64 {
        let export = exports_ptr + index * 24;
        let name = memory.read_wide_string(memory.read_u64(export)?)?;
        if name.is_empty() {
            return Err(invalid("existing collection export has an empty name"));
        }
        let rename_ptr = memory.read_u64(export + 8)?;
        exports.push(D3d12ExportDesc {
            name,
            export_to_rename: if rename_ptr == 0 {
                None
            } else {
                Some(memory.read_wide_string(rename_ptr)?)
            },
            flags: memory.read_u32(export + 16)?,
        });
    }
    Ok(D3d12ExistingCollection {
        collection,
        exports,
    })
}

fn parse_hit_group(memory: &dyn StateObjectMemory, desc: u64) -> AppResult<D3d12HitGroup> {
    // D3D12_HIT_GROUP_DESC (x64):
    // +0 HitGroupExport, +8 Type, +16 AnyHitShaderImport,
    // +24 ClosestHitShaderImport, +32 IntersectionShaderImport
    let name = memory.read_wide_string(memory.read_u64(desc)?)?;
    if name.is_empty() {
        return Err(invalid("hit group HitGroupExport is empty"));
    }
    let ty = memory.read_u32(desc + 8)?;
    if !matches!(
        ty,
        HIT_GROUP_TYPE_TRIANGLES | HIT_GROUP_TYPE_PROCEDURAL_PRIMITIVE
    ) {
        return Err(invalid(format!("D3D12_HIT_GROUP_TYPE {ty} is not defined")));
    }
    let any_hit = optional_string(memory, memory.read_u64(desc + 16)?)?;
    let closest_hit = optional_string(memory, memory.read_u64(desc + 24)?)?;
    let intersection = optional_string(memory, memory.read_u64(desc + 32)?)?;
    if ty == HIT_GROUP_TYPE_PROCEDURAL_PRIMITIVE && intersection.is_none() {
        return Err(invalid(
            "procedural hit group requires an intersection shader import",
        ));
    }
    Ok(D3d12HitGroup {
        name,
        ty,
        any_hit,
        closest_hit,
        intersection,
    })
}

fn parse_generic_program(
    memory: &dyn StateObjectMemory,
    desc: u64,
) -> AppResult<D3d12StateSubobject> {
    // D3D12_GENERIC_PROGRAM_DESC:
    // +0 ProgramName, +8 NumExports, +16 pExports,
    // +24 NumSubobjects, +32 ppSubobjects
    let program_name = memory.read_wide_string(memory.read_u64(desc)?)?;
    if program_name.is_empty() {
        return Err(invalid("generic program ProgramName is empty"));
    }
    let num_exports = memory.read_u32(desc + 8)?;
    let exports_ptr = memory.read_u64(desc + 16)?;
    if num_exports > 65_535 {
        return Err(invalid(
            "generic program NumExports exceeds the supported limit",
        ));
    }
    if num_exports > 0 && exports_ptr == 0 {
        return Err(invalid("generic program pExports is null"));
    }
    let exports = read_export_names(memory, exports_ptr, num_exports)?;
    let num_subobjects = memory.read_u32(desc + 24)?;
    let subobjects_ptr = memory.read_u64(desc + 32)?;
    if num_subobjects > 0 && subobjects_ptr == 0 {
        return Err(invalid("generic program ppSubobjects is null"));
    }
    for index in 0..num_subobjects as u64 {
        let pointer = memory.read_u64(subobjects_ptr + index * 8)?;
        if pointer == 0 {
            return Err(invalid("generic program subobject pointer is null"));
        }
    }
    Ok(D3d12StateSubobject::GenericProgram {
        program_name,
        exports,
    })
}

fn read_export_names(
    memory: &dyn StateObjectMemory,
    exports_ptr: u64,
    count: u32,
) -> AppResult<Vec<String>> {
    if count > 65_535 {
        return Err(invalid("export list exceeds the supported limit"));
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    if exports_ptr == 0 {
        return Err(invalid("export list pointer is null"));
    }
    let mut exports = Vec::with_capacity(count as usize);
    for index in 0..count as u64 {
        let name = memory.read_wide_string(memory.read_u64(exports_ptr + index * 8)?)?;
        if name.is_empty() {
            return Err(invalid("export list contains an empty name"));
        }
        exports.push(name);
    }
    Ok(exports)
}

fn optional_string(memory: &dyn StateObjectMemory, address: u64) -> AppResult<Option<String>> {
    if address == 0 {
        Ok(None)
    } else {
        let value = memory.read_wide_string(address)?;
        if value.is_empty() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }
}

fn invalid(message: impl Into<String>) -> AppError {
    AppError::new(ReasonCode::RcD3dInvalidState, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
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

    fn base_memory() -> TestMemory {
        TestMemory {
            data: vec![0u8; 0x2000],
        }
    }

    fn write_desc(data: &mut [u8], object_type: u32, subobjects: &[(u32, u64)]) -> u64 {
        put_u32(data, 0x100, object_type);
        put_u32(data, 0x104, subobjects.len() as u32);
        put_u64(data, 0x108, 0x200);
        for (index, (ty, desc)) in subobjects.iter().enumerate() {
            put_u32(data, 0x200 + index * 16, *ty);
            put_u64(data, 0x208 + index * 16, *desc);
        }
        0x100
    }

    fn write_name(data: &mut [u8], offset: usize, value: &str) {
        for (index, unit) in value.encode_utf16().enumerate() {
            data[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }

    fn write_export(data: &mut [u8], offset: usize, name: u64, rename: u64) {
        put_u64(data, offset, name);
        put_u64(data, offset + 8, rename);
        put_u32(data, offset + 16, 2);
    }

    fn all_subobjects_memory() -> TestMemory {
        let mut memory = base_memory();
        memory.data = vec![0u8; 0x10000];
        let data = &mut memory.data;
        let desc = 0x1000u64;
        let subobjects = 0x1100u64;
        let types = [0u32, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 29, 36];
        let descs = [
            0x2700u64, 0x2710, 0x2720, 0x2730, 0x2000, 0x2100, 0x2200, 0x2200, 0x2300, 0x2310,
            0x2400, 0x2440, 0x2500, 0x2740, 0x2600, 0x2740,
        ];
        put_u32(data, desc as usize, STATE_OBJECT_TYPE_EXECUTABLE);
        put_u32(data, desc as usize + 4, types.len() as u32);
        put_u64(data, desc as usize + 8, subobjects);
        for (index, (ty, payload)) in types.iter().zip(descs).enumerate() {
            put_u32(data, subobjects as usize + index * 16, *ty);
            put_u64(data, subobjects as usize + index * 16 + 8, payload);
        }
        put_u32(data, 0x2700, 0x7);
        put_u64(data, 0x2710, 0x1234);
        put_u64(data, 0x2720, 0x5678);
        put_u32(data, 0x2730, 3);
        // DXIL library.
        put_u64(data, 0x2000, 0x5000);
        put_u64(data, 0x2008, 4);
        put_u32(data, 0x2010, 1);
        put_u64(data, 0x2018, 0x3000);
        for (index, byte) in [0x44u8, 0x58, 0x42, 0x43].iter().enumerate() {
            data[0x5000 + index] = *byte;
        }
        write_name(data, 0x4000, "export");
        write_name(data, 0x4100, "rename");
        write_export(data, 0x3000, 0x4000, 0x4100);
        // Existing collection.
        put_u64(data, 0x2100, 0x9999);
        put_u32(data, 0x2108, 1);
        put_u64(data, 0x2110, 0x3040);
        write_export(data, 0x3040, 0x4000, 0);
        // Subobject-to-exports association.
        put_u64(data, 0x2200, 0x1200);
        put_u32(data, 0x2208, 1);
        put_u64(data, 0x2210, 0x3080);
        put_u64(data, 0x3080, 0x4000);
        put_u32(data, 0x2300, 16);
        put_u32(data, 0x2304, 8);
        put_u32(data, 0x2310, 1);
        put_u32(data, 0x2440, 2);
        put_u32(data, 0x2444, 0x100);
        // Hit group.
        write_name(data, 0x4200, "hit");
        write_name(data, 0x4300, "any");
        write_name(data, 0x4400, "closest");
        write_name(data, 0x4500, "inter");
        put_u64(data, 0x2400, 0x4200);
        put_u32(data, 0x2408, HIT_GROUP_TYPE_TRIANGLES);
        put_u64(data, 0x2410, 0x4300);
        put_u64(data, 0x2418, 0x4400);
        put_u64(data, 0x2420, 0x4500);
        // Work graph.
        write_name(data, 0x4600, "graph");
        write_name(data, 0x4700, "node0");
        put_u64(data, 0x2500, 0x4600);
        put_u32(data, 0x2508, 0);
        put_u32(data, 0x250c, 1);
        put_u64(data, 0x2510, 0x6100);
        put_u32(data, 0x2518, 1);
        put_u64(data, 0x2520, 0x6200);
        put_u64(data, 0x6100, 0x4700);
        put_u32(data, 0x6108, 0);
        put_u32(data, 0x6200, 0);
        put_u64(data, 0x6208, 0x4700);
        put_u32(data, 0x6210, 0);
        put_u64(data, 0x6218, 0);
        // Generic program.
        write_name(data, 0x4800, "gen");
        put_u64(data, 0x2600, 0x4800);
        put_u32(data, 0x2608, 1);
        put_u64(data, 0x2610, 0x30c0);
        put_u32(data, 0x2618, 0);
        put_u64(data, 0x2620, 0);
        put_u64(data, 0x30c0, 0x4000);
        memory
    }

    fn expect_state_error(
        mut memory: TestMemory,
        mutate: impl FnOnce(&mut TestMemory),
        message: &str,
    ) {
        mutate(&mut memory);
        let error = parse_state_object(&memory, 0x1000).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, message);
    }

    #[test]
    fn state_object_parser_covers_all_subobjects_and_rejects_malformed_payloads() {
        let memory = all_subobjects_memory();
        let parsed = parse_state_object(&memory, 0x1000).expect("all subobjects");
        assert_eq!(parsed.subobjects.len(), 16);
        assert!(matches!(
            parsed.subobjects[0],
            D3d12StateSubobject::StateObjectConfig { flags: 0x7 }
        ));
        assert!(matches!(
            parsed.subobjects[1],
            D3d12StateSubobject::GlobalRootSignature { object: 0x1234 }
        ));
        assert!(matches!(
            parsed.subobjects[2],
            D3d12StateSubobject::LocalRootSignature { object: 0x5678 }
        ));
        assert!(matches!(
            parsed.subobjects[3],
            D3d12StateSubobject::NodeMask { mask: 3 }
        ));
        assert!(matches!(
            parsed.subobjects[4],
            D3d12StateSubobject::DxilLibrary(_)
        ));
        assert!(matches!(
            parsed.subobjects[5],
            D3d12StateSubobject::ExistingCollection(_)
        ));
        assert!(matches!(
            parsed.subobjects[6],
            D3d12StateSubobject::SubobjectToExportsAssociation { .. }
        ));
        assert!(matches!(
            parsed.subobjects[7],
            D3d12StateSubobject::SubobjectToExportsAssociation { .. }
        ));
        assert!(matches!(
            parsed.subobjects[8],
            D3d12StateSubobject::RaytracingShaderConfig { .. }
        ));
        assert!(matches!(
            parsed.subobjects[9],
            D3d12StateSubobject::RaytracingPipelineConfig {
                max_trace_recursion_depth: 1
            }
        ));
        assert!(matches!(
            parsed.subobjects[10],
            D3d12StateSubobject::HitGroup(_)
        ));
        assert!(matches!(
            parsed.subobjects[11],
            D3d12StateSubobject::RaytracingPipelineConfig1 {
                max_trace_recursion_depth: 2,
                flags: 0x100
            }
        ));
        assert!(matches!(
            parsed.subobjects[12],
            D3d12StateSubobject::WorkGraph(_)
        ));
        assert!(matches!(
            parsed.subobjects[13],
            D3d12StateSubobject::Unsupported { ty: 14 }
        ));
        assert!(matches!(
            parsed.subobjects[14],
            D3d12StateSubobject::GenericProgram { .. }
        ));
        assert!(matches!(
            parsed.subobjects[15],
            D3d12StateSubobject::Unsupported { ty: 36 }
        ));
        let object = D3d12StateObject {
            handle: 1,
            object_type: parsed.object_type,
            subobjects: parsed.subobjects.clone(),
            ref_count: 1,
            exported_shaders: BTreeMap::new(),
            pipeline_config: None,
            shader_config: None,
            work_graphs: Vec::new(),
        };
        assert!(object.allow_additions());
        assert_eq!(object.first_dxil(), Some(&[0x44, 0x58, 0x42, 0x43][..]));
        assert_eq!(object.shader_identifier("export"), None);

        // UTF-16 reader branches, including the overflow guard.
        assert_eq!(memory.read_wide_string(0).unwrap(), "");
        assert_eq!(memory.read_wide_string(0x4000).unwrap(), "export");
        let mut too_long = TestMemory {
            data: vec![0x41; 4096 * 2 + 2],
        };
        let error = too_long.read_wide_string(1).unwrap_err();
        assert_eq!(
            error.message,
            "UTF-16 string at 0x1 exceeds the 4096-unit limit"
        );
        too_long.data.clear();
        struct Unbounded;
        impl StateObjectMemory for Unbounded {
            fn read_bytes(&self, _: u64, _: usize) -> AppResult<Vec<u8>> {
                unreachable!()
            }
            fn read_u32(&self, _: u64) -> AppResult<u32> {
                unreachable!()
            }
            fn read_u64(&self, _: u64) -> AppResult<u64> {
                unreachable!()
            }
            fn read_u16(&self, _: u64) -> AppResult<u16> {
                Ok(0x41)
            }
        }
        let error = Unbounded.read_wide_string(u64::MAX - 8188).unwrap_err();
        assert_eq!(error.message, "UTF-16 string pointer overflow");

        // Top-level descriptor validation.
        let error = parse_state_object(&memory, 0).unwrap_err();
        assert_eq!(error.message, "state object description pointer is null");
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x1000, 2),
            "D3D12_STATE_OBJECT_TYPE 2 is not defined",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x1004, 1_000_001),
            "state object NumSubobjects 1000001 exceeds the supported limit",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| {
                put_u32(&mut m.data, 0x1004, 1);
                put_u64(&mut m.data, 0x1008, 0);
            },
            "state object pSubobjects is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x1100, 40),
            "D3D12_STATE_SUBOBJECT_TYPE 40 is outside the defined 0..37 range",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x1100, 4),
            "D3D12_STATE_SUBOBJECT_TYPE 4 is not defined",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x1108, 0),
            "state subobject type 0 has a null description pointer",
        );

        // Payload validation for every parsed subobject kind.
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2700, 0x8),
            "D3D12_STATE_OBJECT_FLAGS 0x8 contain undefined bits",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2710, 0),
            "global root signature pointer is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2720, 0),
            "local root signature pointer is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2000, 0),
            "DXIL library bytecode is empty",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2008, 64 * 1024 * 1024 + 1),
            "DXIL library bytecode length 67108865 exceeds the 64 MiB limit",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2010, 65_536),
            "DXIL library NumExports 65536 exceeds the supported limit",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2018, 0),
            "DXIL library pExports is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x3000, 0),
            "DXIL export has an empty name",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2100, 0),
            "existing collection pointer is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2108, 65_536),
            "existing collection NumExports 65536 exceeds the supported limit",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2110, 0),
            "existing collection pExports is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x3040, 0),
            "existing collection export has an empty name",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2200, 0),
            "subobject-to-exports association pointer is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2208, 65_536),
            "export list exceeds the supported limit",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2210, 0),
            "export list pointer is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x3080, 0),
            "export list contains an empty name",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2304, 36),
            "raytracing MaxAttributeSizeInBytes 36 exceeds D3D12_RAYTRACING_MAX_ATTRIBUTE_SIZE_IN_BYTES (32)",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2304, 3),
            "raytracing MaxAttributeSizeInBytes 3 is not a multiple of 4",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2310, 32),
            "raytracing MaxTraceRecursionDepth 32 exceeds D3D12_RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH (31)",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2440, 32),
            "raytracing MaxTraceRecursionDepth 32 exceeds the defined limit",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2444, 0x1000),
            "D3D12_RAYTRACING_PIPELINE_FLAGS 0x1000 contain undefined bits",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2400, 0),
            "hit group HitGroupExport is empty",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2408, 2),
            "D3D12_HIT_GROUP_TYPE 2 is not defined",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| {
                put_u32(&mut m.data, 0x2408, HIT_GROUP_TYPE_PROCEDURAL_PRIMITIVE);
                put_u64(&mut m.data, 0x2420, 0);
            },
            "procedural hit group requires an intersection shader import",
        );
        // Existing collection exports can rename a shader.
        let mut renamed = all_subobjects_memory();
        put_u64(&mut renamed.data, 0x3048, 0x4100);
        let parsed = parse_state_object(&renamed, 0x1000).expect("renamed collection export");
        match &parsed.subobjects[5] {
            D3d12StateSubobject::ExistingCollection(collection) => {
                assert_eq!(
                    collection.exports[0].export_to_rename.as_deref(),
                    Some("rename")
                );
            }
            other => panic!("unexpected collection: {other:?}"),
        }
        // Generic program with zero exports takes the empty-list branch.
        let mut empty_exports = all_subobjects_memory();
        put_u32(&mut empty_exports.data, 0x2608, 0);
        put_u64(&mut empty_exports.data, 0x2610, 0);
        let parsed = parse_state_object(&empty_exports, 0x1000).expect("empty generic exports");
        match &parsed.subobjects[14] {
            D3d12StateSubobject::GenericProgram { exports, .. } => assert!(exports.is_empty()),
            other => panic!("unexpected generic program: {other:?}"),
        }
        let mut generic_subobject = all_subobjects_memory();
        put_u32(&mut generic_subobject.data, 0x2618, 1);
        put_u64(&mut generic_subobject.data, 0x2620, 0x6400);
        put_u64(&mut generic_subobject.data, 0x6400, 0x4000);
        let parsed = parse_state_object(&generic_subobject, 0x1000).expect("generic subobject");
        match &parsed.subobjects[14] {
            D3d12StateSubobject::GenericProgram { .. } => {}
            other => panic!("unexpected generic program: {other:?}"),
        }
        let mut empty_optional = all_subobjects_memory();
        put_u64(&mut empty_optional.data, 0x2410, 0x4900);
        let parsed = parse_state_object(&empty_optional, 0x1000).expect("empty optional shader");
        match &parsed.subobjects[10] {
            D3d12StateSubobject::HitGroup(group) => {
                assert_eq!(group.any_hit, None);
                assert_eq!(group.closest_hit.as_deref(), Some("closest"));
            }
            other => panic!("unexpected hit group: {other:?}"),
        }
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2600, 0),
            "generic program ProgramName is empty",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u32(&mut m.data, 0x2608, 65_536),
            "generic program NumExports exceeds the supported limit",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2610, 0),
            "generic program pExports is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| {
                put_u32(&mut m.data, 0x2618, 1);
                put_u64(&mut m.data, 0x2620, 0);
            },
            "generic program ppSubobjects is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| {
                put_u32(&mut m.data, 0x2618, 1);
                put_u64(&mut m.data, 0x2620, 0x6400);
            },
            "generic program subobject pointer is null",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x30c0, 0),
            "export list contains an empty name",
        );
        expect_state_error(
            all_subobjects_memory(),
            |m| put_u64(&mut m.data, 0x2500, 0),
            "work graph ProgramName is empty",
        );
    }

    #[test]
    fn state_object_undefined_subobject_type_is_rejected() {
        let mut memory = base_memory();
        let desc = write_desc(
            &mut memory.data,
            STATE_OBJECT_TYPE_COLLECTION,
            &[(40, 0x300)],
        );
        let error = parse_state_object(&memory, desc).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "D3D12_STATE_SUBOBJECT_TYPE 40 is outside the defined 0..37 range"
        );
    }

    #[test]
    fn state_object_invalid_object_type_is_rejected() {
        let mut memory = base_memory();
        let desc = write_desc(&mut memory.data, 1, &[]);
        let error = parse_state_object(&memory, desc).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "D3D12_STATE_OBJECT_TYPE 1 is not defined");
    }

    #[test]
    fn dxil_library_uses_documented_bytecode_offset() {
        let mut memory = base_memory();
        // D3D12_DXIL_LIBRARY_DESC at 0x300: bytecode ptr +0, length +8.
        // A null pointer at +0 must be rejected even if +24 is non-null.
        put_u64(&mut memory.data, 0x318, 0x400);
        put_u32(&mut memory.data, 0x310, 1);
        let desc = write_desc(
            &mut memory.data,
            STATE_OBJECT_TYPE_COLLECTION,
            &[(SUBOBJECT_DXIL_LIBRARY, 0x300)],
        );
        let error = parse_state_object(&memory, desc).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "DXIL library bytecode is empty");
    }

    #[test]
    fn procedural_hit_group_requires_intersection_shader() {
        let mut memory = base_memory();
        // Hit group at 0x300: name +0, type +8, intersection +32 (null).
        for (index, unit) in "hg".encode_utf16().enumerate() {
            memory.data[0x400 + index * 2..0x402 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        put_u64(&mut memory.data, 0x300, 0x400);
        put_u32(&mut memory.data, 0x308, HIT_GROUP_TYPE_PROCEDURAL_PRIMITIVE);
        let desc = write_desc(
            &mut memory.data,
            STATE_OBJECT_TYPE_COLLECTION,
            &[(SUBOBJECT_HIT_GROUP, 0x300)],
        );
        let error = parse_state_object(&memory, desc).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "procedural hit group requires an intersection shader import"
        );
    }

    #[test]
    fn raytracing_pipeline_recursion_limit_is_enforced() {
        let mut memory = base_memory();
        put_u32(&mut memory.data, 0x300, 32);
        let desc = write_desc(
            &mut memory.data,
            STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
            &[(SUBOBJECT_RAYTRACING_PIPELINE_CONFIG, 0x300)],
        );
        let error = parse_state_object(&memory, desc).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "raytracing MaxTraceRecursionDepth 32 exceeds D3D12_RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH (31)"
        );
    }
}
