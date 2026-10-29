//! D3D11/DXGI/D3D12 descriptor readers.

use super::*;

pub(crate) fn read_d3d12_command_queue_desc(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<(u32, i32, u32, u32)> {
    Ok((
        read_guest_u32(memory, address)?,
        read_guest_u32(memory, address + 4)? as i32,
        read_guest_u32(memory, address + 8)?,
        read_guest_u32(memory, address + 12)?,
    ))
}

pub(crate) fn read_d3d12_descriptor_heap_desc(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<(DescriptorHeapType, usize, u32, u32)> {
    let heap_type = match read_guest_u32(memory, address)? {
        0 => DescriptorHeapType::CbvSrvUav,
        1 => DescriptorHeapType::Sampler,
        2 => DescriptorHeapType::Rtv,
        3 => DescriptorHeapType::Dsv,
        other => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported D3D12 descriptor heap type {other}"),
            ));
        }
    };
    Ok((
        heap_type,
        read_guest_u32(memory, address + 4)? as usize,
        read_guest_u32(memory, address + 8)?,
        read_guest_u32(memory, address + 12)?,
    ))
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct D3d12TransitionBarrierDesc {
    pub(crate) resource_object: u64,
    pub(crate) subresource: u32,
    pub(crate) state_before: u32,
    pub(crate) state_after: u32,
}

pub(crate) fn read_d3d12_resource_barrier(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<D3d12TransitionBarrierDesc> {
    let barrier_type = read_guest_u32(memory, address)?;
    if barrier_type != 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported D3D12 resource barrier type {barrier_type}"),
        ));
    }
    let resource_object = memory.read_u64(address + 8)?;
    if resource_object == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "D3D12 transition barriers must reference a non-null resource object",
        ));
    }
    Ok(D3d12TransitionBarrierDesc {
        resource_object,
        subresource: read_guest_u32(memory, address + 16)?,
        state_before: read_guest_u32(memory, address + 20)?,
        state_after: read_guest_u32(memory, address + 24)?,
    })
}

pub(crate) fn map_d3d12_resource_state(
    raw: u32,
    resource: GuestD3d12Resource,
    current: Option<ResourceState>,
    prefer_current_if_common: bool,
) -> AppResult<ResourceState> {
    match raw {
        0 => {
            if prefer_current_if_common {
                current.ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "missing current resource state for D3D12 common/present barrier mapping",
                    )
                })
            } else if resource.swapchain_backbuffer {
                Ok(ResourceState::Present)
            } else {
                Ok(ResourceState::Common)
            }
        }
        0x0000_0004 => Ok(ResourceState::RenderTarget),
        0x0000_0008 => Ok(ResourceState::UnorderedAccess),
        0x0000_0010 => Ok(ResourceState::DepthWrite),
        0x0000_0400 => Ok(ResourceState::CopyDest),
        0x0000_0800 => Ok(ResourceState::CopySource),
        0x0000_0080 => Ok(ResourceState::PixelShaderResource),
        0x0000_0001 | 0x0000_0002 | 0x0000_0040 | 0x0000_0200 | 0x0000_0AC3 => {
            Ok(ResourceState::GenericRead)
        }
        other => Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported D3D12 resource state {other:#x}"),
        )),
    }
}

pub(crate) fn read_d3d_feature_levels(
    memory: &MemoryImage,
    address: u64,
    count: u32,
) -> AppResult<Vec<FeatureLevel>> {
    if count == 0 {
        return Ok(vec![FeatureLevel::Level10_1]);
    }
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "feature level array pointer must not be null when a non-zero feature level count is supplied",
        ));
    }
    let mut levels = Vec::with_capacity(count as usize);
    for index in 0..count as u64 {
        let value = read_guest_u32(memory, address + index * 4)?;
        levels.push(match value {
            0xa100 => FeatureLevel::Level10_1,
            0xb000 => FeatureLevel::Level11_0,
            other => {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("unsupported D3D feature level {other:#x}"),
                ));
            }
        });
    }
    Ok(levels)
}

pub(crate) fn d3d_feature_level_value(level: FeatureLevel) -> u32 {
    match level {
        FeatureLevel::Level10_1 => 0xa100,
        FeatureLevel::Level11_0 => 0xb000,
    }
}

pub(crate) fn supported_d3d12_feature_level(device_info: &crate::d3d12::D3d12DeviceInfo) -> u32 {
    if device_info.features.mesh_shaders {
        D3D_FEATURE_LEVEL_12_2
    } else {
        D3D_FEATURE_LEVEL_12_1
    }
}

pub(crate) fn supported_d3d12_shader_model(device_info: &crate::d3d12::D3d12DeviceInfo) -> u32 {
    if device_info.features.mesh_shaders {
        D3D_SHADER_MODEL_6_6
    } else {
        D3D_SHADER_MODEL_6_5
    }
}

pub(crate) fn write_d3d12_feature_support(
    memory: &mut MemoryImage,
    feature: u32,
    address: u64,
    size: usize,
    device_info: &crate::d3d12::D3d12DeviceInfo,
    telemetry: Option<&TelemetryCollector>,
) -> AppResult<Option<BTreeMap<String, Value>>> {
    let capabilities = &device_info.features;
    match feature {
        D3D12_FEATURE_D3D12_OPTIONS => {
            if size < 60 {
                return Ok(None);
            }
            write_u32(memory, address, bool_to_u32(false));
            write_u32(memory, address + 4, bool_to_u32(true));
            write_u32(memory, address + 8, 0);
            write_u32(memory, address + 12, D3D12_TILED_RESOURCES_TIER_2);
            write_u32(memory, address + 16, D3D12_RESOURCE_BINDING_TIER_3);
            write_u32(memory, address + 20, bool_to_u32(false));
            write_u32(memory, address + 24, bool_to_u32(true));
            write_u32(memory, address + 28, bool_to_u32(false));
            write_u32(
                memory,
                address + 32,
                D3D12_CONSERVATIVE_RASTERIZATION_TIER_1,
            );
            write_u32(memory, address + 36, 40);
            write_u32(memory, address + 40, bool_to_u32(true));
            write_u32(memory, address + 44, 0);
            write_u32(memory, address + 48, bool_to_u32(false));
            write_u32(memory, address + 52, bool_to_u32(false));
            write_u32(memory, address + 56, D3D12_RESOURCE_HEAP_TIER_2);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("D3D12_OPTIONS")),
                (
                    "resource_binding_tier".to_string(),
                    json!(D3D12_RESOURCE_BINDING_TIER_3),
                ),
                (
                    "resource_heap_tier".to_string(),
                    json!(D3D12_RESOURCE_HEAP_TIER_2),
                ),
            ])))
        }
        D3D12_FEATURE_FEATURE_LEVELS => {
            if size < 24 {
                return Ok(None);
            }
            let count = read_guest_u32(memory, address)? as usize;
            let levels_ptr = read_guest_u64(memory, address + 8)?;
            let max_supported = match select_supported_d3d12_feature_level(
                memory,
                levels_ptr,
                count,
                supported_d3d12_feature_level(device_info),
            )? {
                Some(level) => level,
                None => return Ok(None),
            };
            write_u32(memory, address + 16, max_supported);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("FEATURE_LEVELS")),
                (
                    "max_feature_level".to_string(),
                    json!(format!("0x{max_supported:04x}")),
                ),
            ])))
        }
        D3D12_FEATURE_SHADER_MODEL => {
            if size < 4 {
                return Ok(None);
            }
            let requested = read_guest_u32(memory, address)?;
            if requested != 0 && !is_known_shader_model(requested) {
                return Ok(None);
            }
            let supported = supported_d3d12_shader_model(device_info);
            let highest = if requested == 0 {
                supported
            } else {
                requested.min(supported)
            };
            if let Some(t) = telemetry {
                t.record_unsupported_shader_model(requested, supported);
            }
            write_u32(memory, address, highest);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("SHADER_MODEL")),
                (
                    "highest_shader_model".to_string(),
                    json!(format!("0x{highest:02x}")),
                ),
            ])))
        }
        D3D12_FEATURE_ROOT_SIGNATURE => {
            if size < 4 {
                return Ok(None);
            }
            let requested = read_guest_u32(memory, address)?;
            if requested != 0 && requested < D3D12_ROOT_SIGNATURE_VERSION_1 {
                return Ok(None);
            }
            let highest = if requested == 0 {
                D3D12_ROOT_SIGNATURE_VERSION_1_1
            } else {
                requested.min(D3D12_ROOT_SIGNATURE_VERSION_1_1)
            };
            write_u32(memory, address, highest);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("ROOT_SIGNATURE")),
                ("highest_version".to_string(), json!(highest)),
            ])))
        }
        D3D12_FEATURE_ARCHITECTURE1 => {
            if size < 20 {
                return Ok(None);
            }
            let node_index = read_guest_u32(memory, address)?;
            write_u32(
                memory,
                address + 4,
                bool_to_u32(capabilities.memoryless_render_targets),
            );
            write_u32(
                memory,
                address + 8,
                bool_to_u32(capabilities.unified_memory),
            );
            write_u32(
                memory,
                address + 12,
                bool_to_u32(capabilities.unified_memory),
            );
            write_u32(memory, address + 16, bool_to_u32(false));
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("ARCHITECTURE1")),
                ("node_index".to_string(), json!(node_index)),
                ("uma".to_string(), json!(capabilities.unified_memory)),
            ])))
        }
        D3D12_FEATURE_D3D12_OPTIONS5 => {
            if size < 12 {
                return Ok(None);
            }
            let raytracing_tier = if capabilities.raytracing {
                D3D12_RAYTRACING_TIER_1_1
            } else {
                D3D12_RAYTRACING_TIER_NOT_SUPPORTED
            };
            write_u32(memory, address, bool_to_u32(false));
            write_u32(memory, address + 4, D3D12_RENDER_PASS_TIER_1);
            write_u32(memory, address + 8, raytracing_tier);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("D3D12_OPTIONS5")),
                (
                    "render_pass_tier".to_string(),
                    json!(D3D12_RENDER_PASS_TIER_1),
                ),
                ("raytracing_tier".to_string(), json!(raytracing_tier)),
            ])))
        }
        D3D12_FEATURE_D3D12_OPTIONS7 => {
            if size < 8 {
                return Ok(None);
            }
            let mesh_shader_tier = if capabilities.mesh_shaders {
                D3D12_MESH_SHADER_TIER_1
            } else {
                D3D12_MESH_SHADER_TIER_NOT_SUPPORTED
            };
            write_u32(memory, address, mesh_shader_tier);
            write_u32(
                memory,
                address + 4,
                D3D12_SAMPLER_FEEDBACK_TIER_NOT_SUPPORTED,
            );
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("D3D12_OPTIONS7")),
                ("mesh_shader_tier".to_string(), json!(mesh_shader_tier)),
            ])))
        }
        _ => Ok(None),
    }
}

pub(crate) fn select_supported_d3d12_feature_level(
    memory: &MemoryImage,
    address: u64,
    count: usize,
    supported: u32,
) -> AppResult<Option<u32>> {
    if count == 0 {
        return Ok(Some(supported));
    }
    if address == 0 {
        return Ok(None);
    }
    let mut best = 0;
    for index in 0..count as u64 {
        let requested = read_guest_u32(memory, address + index * 4)?;
        if !is_known_d3d12_feature_level(requested) {
            return Ok(None);
        }
        if requested <= supported && requested > best {
            best = requested;
        }
    }
    Ok(Some(best))
}

pub(crate) fn is_known_d3d12_feature_level(value: u32) -> bool {
    matches!(
        value,
        D3D_FEATURE_LEVEL_11_0
            | D3D_FEATURE_LEVEL_11_1
            | D3D_FEATURE_LEVEL_12_0
            | D3D_FEATURE_LEVEL_12_1
            | D3D_FEATURE_LEVEL_12_2
    )
}

pub(crate) fn is_known_shader_model(value: u32) -> bool {
    value == 0x51 || (0x60..=0x69).contains(&value)
}

pub(crate) fn bool_to_u32(value: bool) -> u32 {
    if value { 1 } else { 0 }
}

pub(crate) fn build_dxgi_adapter_desc_bytes(
    adapter: &crate::d3d12::AdapterInfo,
    unified_memory: bool,
    extended: bool,
) -> Vec<u8> {
    let total_len = if extended { 308 } else { 304 };
    let mut bytes = vec![0_u8; total_len];
    for (index, unit) in adapter
        .name
        .encode_utf16()
        .take(DXGI_ADAPTER_DESC_DESCRIPTION_CHARS.saturating_sub(1))
        .enumerate()
    {
        let offset = index * 2;
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    let gpu_identity = &crate::hardware_identity::host_identity().gpu;
    bytes[256..260].copy_from_slice(&adapter.vendor_id.to_le_bytes());
    bytes[260..264].copy_from_slice(&adapter.device_id.to_le_bytes());
    bytes[264..268].copy_from_slice(&gpu_identity.subsys_id.to_le_bytes());
    bytes[268..272].copy_from_slice(&gpu_identity.revision.to_le_bytes());
    let dedicated_video_memory = if unified_memory {
        0_u64
    } else {
        8 * 1024 * 1024 * 1024
    };
    let dedicated_system_memory = 0_u64;
    let shared_system_memory = if unified_memory {
        16 * 1024 * 1024 * 1024_u64
    } else {
        2 * 1024 * 1024 * 1024_u64
    };
    bytes[272..280].copy_from_slice(&dedicated_video_memory.to_le_bytes());
    bytes[280..288].copy_from_slice(&dedicated_system_memory.to_le_bytes());
    bytes[288..296].copy_from_slice(&shared_system_memory.to_le_bytes());
    // AdapterLuid: the same LUID the D3DKMT surface reports, derived from the
    // real Metal registryID + device name, so DXGI and D3DKMT agree.
    bytes[296..300].copy_from_slice(&gpu_identity.luid_low.to_le_bytes());
    bytes[300..304].copy_from_slice(&(gpu_identity.luid_high as u32).to_le_bytes());
    if extended {
        bytes[304..308].copy_from_slice(&0_u32.to_le_bytes());
    }
    bytes
}

pub(crate) fn read_swapchain_desc(memory: &MemoryImage, address: u64) -> AppResult<SwapchainDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "swapchain descriptor pointer must not be null",
        ));
    }
    let width = read_guest_u32(memory, address)?;
    let height = read_guest_u32(memory, address + 4)?;
    let format = map_dxgi_format(read_guest_u32(memory, address + 16)?)?;
    let sample_count = read_guest_u32(memory, address + 28)?;
    let sample_quality = read_guest_u32(memory, address + 32)?;
    let buffer_count = read_guest_u32(memory, address + 40)?;
    let output_window = memory.read_u64(address + 48)?;
    if sample_count != 1 || sample_quality != 0 || output_window == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!(
                "only single-sample windowed DXGI swapchains with a valid output window are currently supported (sample_count={sample_count}, sample_quality={sample_quality}, output_window={output_window:#x})"
            ),
        ));
    }
    Ok(SwapchainDesc {
        width,
        height,
        format,
        buffer_count,
    })
}

pub(crate) fn read_swapchain_desc1(memory: &MemoryImage, address: u64) -> AppResult<SwapchainDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "swapchain descriptor pointer must not be null",
        ));
    }
    let width = read_guest_u32(memory, address)?;
    let height = read_guest_u32(memory, address + 4)?;
    let format = map_dxgi_format(read_guest_u32(memory, address + 8)?)?;
    let sample_count = read_guest_u32(memory, address + 16)?;
    let sample_quality = read_guest_u32(memory, address + 20)?;
    let buffer_count = read_guest_u32(memory, address + 28)?;
    if sample_count != 1 || sample_quality != 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!(
                "only single-sample DXGI swapchain desc1 values are currently supported (sample_count={sample_count}, sample_quality={sample_quality})"
            ),
        ));
    }
    Ok(SwapchainDesc {
        width,
        height,
        format,
        buffer_count,
    })
}

pub(crate) fn map_dxgi_format(value: u32) -> AppResult<DxgiFormat> {
    match value {
        28 => Ok(DxgiFormat::R8G8B8A8Unorm),
        87 => Ok(DxgiFormat::B8G8R8A8Unorm),
        45 => Ok(DxgiFormat::D24UnormS8Uint),
        other => Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported DXGI format {other}"),
        )),
    }
}

pub(crate) fn read_d3d11_buffer_byte_width(memory: &MemoryImage, address: u64) -> AppResult<usize> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "buffer descriptor pointer must not be null",
        ));
    }
    let byte_width = read_guest_u32(memory, address)? as usize;
    if byte_width == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "buffer byte width must be greater than zero",
        ));
    }
    Ok(byte_width)
}

pub(crate) fn read_d3d11_buffer_usage(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<(String, ResourceUsageHint)> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "buffer descriptor pointer must not be null",
        ));
    }
    let usage = read_guest_u32(memory, address + 4)?;
    let bind_flags = read_guest_u32(memory, address + 8)?;
    let cpu_access_flags = read_guest_u32(memory, address + 12)?;
    let role = if bind_flags & 0x4 != 0 {
        BufferRole::Constant
    } else if bind_flags & 0x1 != 0 {
        BufferRole::Vertex
    } else if bind_flags & 0x2 != 0 {
        BufferRole::Index
    } else {
        BufferRole::Generic
    };
    let cpu_write_frequent = usage == 2 || (cpu_access_flags & 0x0001_0000) != 0;
    let label = match (role, cpu_write_frequent) {
        (BufferRole::Constant, true) => "guest-dynamic-constant-buffer",
        (BufferRole::Constant, false) => "guest-constant-buffer",
        (BufferRole::Vertex, true) => "guest-dynamic-vertex-buffer",
        (BufferRole::Vertex, false) => "guest-vertex-buffer",
        (BufferRole::Index, true) => "guest-dynamic-index-buffer",
        (BufferRole::Index, false) => "guest-index-buffer",
        (BufferRole::Generic, true) => "guest-dynamic-buffer",
        (BufferRole::Generic, false) => "guest-buffer",
    };
    Ok((
        label.to_string(),
        ResourceUsageHint::Buffer {
            role,
            cpu_write_frequent,
        },
    ))
}

pub(crate) struct GuestTexture2dDesc {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) format: DxgiFormat,
    pub(crate) byte_width: usize,
    pub(crate) label: String,
    pub(crate) usage_hint: ResourceUsageHint,
}

pub(crate) fn read_d3d11_texture2d_desc(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<GuestTexture2dDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "texture2d descriptor pointer must not be null",
        ));
    }
    let width = read_guest_u32(memory, address)?;
    let height = read_guest_u32(memory, address + 4)?;
    let mip_levels = read_guest_u32(memory, address + 8)?;
    let array_size = read_guest_u32(memory, address + 12)?;
    let format = map_dxgi_format(read_guest_u32(memory, address + 16)?)?;
    let sample_count = read_guest_u32(memory, address + 20)?;
    let usage = read_guest_u32(memory, address + 28)?;
    let bind_flags = read_guest_u32(memory, address + 32)?;
    let cpu_access_flags = read_guest_u32(memory, address + 36)?;
    if width == 0 || height == 0 || mip_levels > 1 || array_size != 1 || sample_count != 1 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "only simple 2D textures with one mip, one array slice, and sample count 1 are supported",
        ));
    }
    let cpu_write_frequent = usage == 2 || (cpu_access_flags & 0x0001_0000) != 0;
    let render_target = (bind_flags & 0x20) != 0;
    let depth_stencil = (bind_flags & 0x40) != 0;
    let sampled = (bind_flags & 0x8) != 0;
    let label = if depth_stencil {
        "guest-depth-texture"
    } else if render_target && sampled {
        "guest-renderable-sampled-texture"
    } else if render_target {
        "guest-render-target-texture"
    } else if sampled && cpu_write_frequent {
        "guest-streamed-shader-resource-texture"
    } else if sampled {
        "guest-shader-resource-texture"
    } else {
        "guest-texture2d"
    };
    let usage_hint = if depth_stencil {
        ResourceUsageHint::Texture {
            sampled,
            render_target,
            depth_stencil: true,
            cpu_write_frequent,
        }
    } else {
        ResourceUsageHint::Texture {
            sampled,
            render_target,
            depth_stencil: false,
            cpu_write_frequent,
        }
    };
    Ok(GuestTexture2dDesc {
        width,
        height,
        format,
        byte_width: width as usize * height as usize * 4,
        label: label.to_string(),
        usage_hint,
    })
}

pub(crate) fn read_d3d11_view_format(
    memory: &MemoryImage,
    address: u64,
    default_format: DxgiFormat,
) -> AppResult<DxgiFormat> {
    if address == 0 {
        return Ok(default_format);
    }
    let raw = read_guest_u32(memory, address)?;
    if raw == 0 {
        return Ok(default_format);
    }
    map_dxgi_format(raw)
}

pub(crate) fn read_d3d11_blend_desc(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<BlendStateDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "blend state descriptor pointer must not be null",
        ));
    }
    let alpha_to_coverage_enable = read_guest_u32(memory, address)? != 0;
    let independent_blend_enable = false; // D3D11_1+ feature, default to false
    // Read first render target blend desc at offset 4 (D3D11_BLEND_DESC layout:
    //   [0..4) AlphaToCoverageEnable (BOOL)
    //   [4..8) IndependentBlendEnable (BOOL)
    //   [8..40) RenderTarget[0] (8 DWORDs: BlendEnable, SrcBlend, DestBlend, BlendOp,
    //           SrcBlendAlpha, DestBlendAlpha, BlendOpAlpha, RenderTargetWriteMask)
    //   ... more render targets follow
    // We read render target 0 only for compatibility; guest apps typically use RT0.
    let rt_blend_enable = read_guest_u32(memory, address + 8)? != 0;
    let src_blend = read_guest_u32(memory, address + 12)?;
    let dest_blend = read_guest_u32(memory, address + 16)?;
    let blend_op = read_guest_u32(memory, address + 20)?;
    let src_blend_alpha = read_guest_u32(memory, address + 24)?;
    let dest_blend_alpha = read_guest_u32(memory, address + 28)?;
    let blend_op_alpha = read_guest_u32(memory, address + 32)?;
    let render_target_write_mask = read_guest_u32(memory, address + 36)? as u8;
    let rt0 = crate::d3d11::RenderTargetBlendDesc {
        blend_enable: rt_blend_enable,
        src_blend,
        dest_blend,
        blend_op,
        src_blend_alpha,
        dest_blend_alpha,
        blend_op_alpha,
        render_target_write_mask,
    };
    Ok(BlendStateDesc {
        alpha_to_coverage_enable,
        independent_blend_enable,
        render_target: [rt0; 8],
    })
}

pub(crate) fn read_d3d11_depth_stencil_desc(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<DepthStencilStateDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "depth-stencil descriptor pointer must not be null",
        ));
    }
    let depth_enable = read_guest_u32(memory, address)? != 0;
    let depth_write_mask = read_guest_u32(memory, address + 4)? as u8;
    let depth_func = read_guest_u32(memory, address + 8)?;
    let stencil_enable = read_guest_u32(memory, address + 12)? != 0;
    let stencil_read_mask = read_guest_u32(memory, address + 16)? as u8;
    let stencil_write_mask = read_guest_u32(memory, address + 20)? as u8;
    // Front stencil ops at offset 24
    let front_stencil_fail_op = read_guest_u32(memory, address + 24)?;
    let front_stencil_depth_fail_op = read_guest_u32(memory, address + 28)?;
    let front_stencil_pass_op = read_guest_u32(memory, address + 32)?;
    let front_stencil_func = read_guest_u32(memory, address + 36)?;
    // Back stencil ops at offset 40
    let back_stencil_fail_op = read_guest_u32(memory, address + 40)?;
    let back_stencil_depth_fail_op = read_guest_u32(memory, address + 44)?;
    let back_stencil_pass_op = read_guest_u32(memory, address + 48)?;
    let back_stencil_func = read_guest_u32(memory, address + 52)?;
    Ok(DepthStencilStateDesc {
        depth_enable,
        depth_write_mask,
        depth_func,
        stencil_enable,
        stencil_read_mask,
        stencil_write_mask,
        front_stencil_fail_op,
        front_stencil_depth_fail_op,
        front_stencil_pass_op,
        front_stencil_func,
        back_stencil_fail_op,
        back_stencil_depth_fail_op,
        back_stencil_pass_op,
        back_stencil_func,
    })
}

pub(crate) fn read_d3d11_rasterizer_desc(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<RasterizerStateDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "rasterizer descriptor pointer must not be null",
        ));
    }
    let fill_mode = match read_guest_u32(memory, address)? {
        2 => "wireframe",
        3 => "solid",
        raw => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported fill mode {raw}"),
            ));
        }
    };
    let cull_mode = match read_guest_u32(memory, address + 4)? {
        1 => "none",
        2 => "front",
        3 => "back",
        raw => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported cull mode {raw}"),
            ));
        }
    };
    // D3D11_RASTERIZER_DESC layout after FillMode+CullMode:
    // [8] FrontCounterClockwise (BOOL)
    // [12] DepthBias (INT)
    // [16] DepthBiasClamp (FLOAT)
    // [20] SlopeScaledDepthBias (FLOAT)
    // [24] DepthClipEnable (BOOL)
    // [28] ScissorEnable (BOOL)
    // [32] MultisampleEnable (BOOL)
    // [36] AntialiasedLineEnable (BOOL)
    let front_counter_clockwise = read_guest_u32(memory, address + 8)? != 0;
    let depth_bias = read_guest_i32(memory, address + 12)?;
    let depth_bias_clamp = f32::from_bits(read_guest_u32(memory, address + 16)?);
    let slope_scaled_depth_bias = f32::from_bits(read_guest_u32(memory, address + 20)?);
    let depth_clip_enable = read_guest_u32(memory, address + 24)? != 0;
    let scissor_enable = read_guest_u32(memory, address + 28)? != 0;
    let multisample_enable = read_guest_u32(memory, address + 32)? != 0;
    let antialiased_line_enable = read_guest_u32(memory, address + 36)? != 0;
    Ok(RasterizerStateDesc {
        fill_mode: fill_mode.to_string(),
        cull_mode: cull_mode.to_string(),
        front_counter_clockwise,
        depth_bias,
        depth_bias_clamp,
        slope_scaled_depth_bias,
        depth_clip_enable,
        scissor_enable,
        multisample_enable,
        antialiased_line_enable,
    })
}

pub(crate) fn read_d3d11_sampler_desc(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<SamplerStateDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "sampler descriptor pointer must not be null",
        ));
    }
    let filter = match read_guest_u32(memory, address)? {
        0 => crate::gfx::FilterMode::Point,
        21 => crate::gfx::FilterMode::Linear,
        raw => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported sampler filter {raw}"),
            ));
        }
    };
    let address_u = map_d3d11_texture_address_mode(read_guest_u32(memory, address + 4)?)?;
    let address_v = map_d3d11_texture_address_mode(read_guest_u32(memory, address + 8)?)?;
    // D3D11_SAMPLER_DESC layout:
    // [0] Filter (D3D11_FILTER enum)
    // [4] AddressU (D3D11_TEXTURE_ADDRESS_MODE)
    // [8] AddressV (D3D11_TEXTURE_ADDRESS_MODE)
    // [12] AddressW (D3D11_TEXTURE_ADDRESS_MODE)
    // [16] MipLODBias (FLOAT)
    // [20] MaxAnisotropy (UINT)
    // [24] ComparisonFunc (D3D11_COMPARISON_FUNC)
    // [28..44) BorderColor[4] (FLOAT[4])
    // [44] MinLOD (FLOAT)
    // [48] MaxLOD (FLOAT)
    let address_w = map_d3d11_texture_address_mode(read_guest_u32(memory, address + 12)?)?;
    let mip_lod_bias = f32::from_bits(read_guest_u32(memory, address + 16)?);
    let max_anisotropy = read_guest_u32(memory, address + 20)?;
    let comparison_func = read_guest_u32(memory, address + 24)?;
    let border_color = [
        f32::from_bits(read_guest_u32(memory, address + 28)?),
        f32::from_bits(read_guest_u32(memory, address + 32)?),
        f32::from_bits(read_guest_u32(memory, address + 36)?),
        f32::from_bits(read_guest_u32(memory, address + 40)?),
    ];
    let min_lod = f32::from_bits(read_guest_u32(memory, address + 44)?);
    let max_lod = f32::from_bits(read_guest_u32(memory, address + 48)?);
    Ok(SamplerStateDesc {
        filter,
        address_u,
        address_v,
        address_w,
        mip_lod_bias,
        max_anisotropy,
        comparison_func,
        border_color,
        min_lod,
        max_lod,
    })
}

pub(crate) fn map_d3d11_texture_address_mode(value: u32) -> AppResult<String> {
    match value {
        1 => Ok("wrap".to_string()),
        3 => Ok("clamp".to_string()),
        raw => Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported texture address mode {raw}"),
        )),
    }
}

pub(crate) fn read_d3d11_viewport(memory: &MemoryImage, address: u64) -> AppResult<Viewport> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "viewport pointer must not be null",
        ));
    }
    let width = read_guest_f32(memory, address + 8)?;
    let height = read_guest_f32(memory, address + 12)?;
    if width <= 0.0 || height <= 0.0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "viewport width and height must be positive",
        ));
    }
    Ok(Viewport {
        x: read_guest_f32(memory, address)?,
        y: read_guest_f32(memory, address + 4)?,
        width,
        height,
    })
}

pub(crate) fn read_d3d11_scissor_rect(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<ScissorRect> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "scissor rect pointer must not be null",
        ));
    }
    let rect = ScissorRect {
        left: read_guest_i32(memory, address)?,
        top: read_guest_i32(memory, address + 4)?,
        right: read_guest_i32(memory, address + 8)?,
        bottom: read_guest_i32(memory, address + 12)?,
    };
    if rect.right <= rect.left || rect.bottom <= rect.top {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "scissor rect must have positive width and height",
        ));
    }
    Ok(rect)
}

pub(crate) fn read_d3d11_input_layout_desc(
    memory: &MemoryImage,
    address: u64,
    count: u32,
) -> AppResult<InputLayoutDesc> {
    if address == 0 || count == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "input layout elements pointer and count must describe at least one element",
        ));
    }
    let mut elements = Vec::with_capacity(count as usize);
    for index in 0..count as u64 {
        let element_address = address + index * 32;
        let semantic_name_ptr = read_guest_u64(memory, element_address)?;
        if semantic_name_ptr == 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("input element {index} semantic name pointer must not be null"),
            ));
        }
        let semantic =
            String::from_utf8_lossy(&read_c_string_limit(memory, semantic_name_ptr, 64)?)
                .to_string();
        let format = map_dxgi_format(read_guest_u32(memory, element_address + 12)?)?;
        let slot = read_guest_u32(memory, element_address + 16)?;
        elements.push(InputElementDesc {
            semantic,
            format,
            slot,
        });
    }
    Ok(InputLayoutDesc { elements })
}

pub(crate) fn read_guest_pointer_array(
    memory: &MemoryImage,
    address: u64,
    count: usize,
) -> AppResult<Vec<u64>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "guest pointer array must not be null when count is non-zero",
        ));
    }
    let mut pointers = Vec::with_capacity(count);
    for index in 0..count as u64 {
        pointers.push(read_guest_u64(memory, address + index * 8)?);
    }
    Ok(pointers)
}

pub(crate) fn linearize_texture_update(
    memory: &MemoryImage,
    src_ptr: u64,
    row_pitch: usize,
    _depth_pitch: usize,
    desc: &crate::d3d11::D3d11ResourceDesc,
) -> AppResult<Vec<u8>> {
    if src_ptr == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "source upload pointer must not be null",
        ));
    }
    match desc.dimension {
        ResourceDimension::Buffer => read_guest_bytes(memory, src_ptr, desc.byte_width),
        ResourceDimension::Texture2D => {
            let bytes_per_pixel = match desc.format {
                DxgiFormat::R8G8B8A8Unorm
                | DxgiFormat::B8G8R8A8Unorm
                | DxgiFormat::D24UnormS8Uint => 4,
                _ => {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!("unsupported upload format {:?}", desc.format),
                    ));
                }
            };
            let expected_row_pitch = desc.width as usize * bytes_per_pixel;
            if row_pitch < expected_row_pitch {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "row pitch {row_pitch} is smaller than the expected row pitch {expected_row_pitch}"
                    ),
                ));
            }
            let mut bytes = Vec::with_capacity(desc.byte_width);
            for row in 0..desc.height as usize {
                let row_ptr = src_ptr + (row * row_pitch) as u64;
                bytes.extend(read_guest_bytes(memory, row_ptr, expected_row_pitch)?);
            }
            Ok(bytes)
        }
        _ => Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported resource upload dimension {:?}", desc.dimension),
        )),
    }
}
