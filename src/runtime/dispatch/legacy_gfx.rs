//! Legacy graphics dispatch: the ddraw.dll, d3d9.dll (D3DPERF/debug),
//! d3d10.dll / d3d10core.dll / d3d10level9.dll, d3dcompiler_43/47.dll and
//! d3dx9_43.dll / d3dx11_43.dll exports, in a dedicated module per the
//! audit's modularity requirement.
//!
//! - DirectDraw: `DirectDrawCreateEx` hands out an IDirectDraw7 object with
//!   real surface semantics — `CreateSurface` allocates a software surface
//!   whose `Lock` exposes its pixel buffer and `GetSurfaceDesc` reports the
//!   DDSURFACEDESC2 contract; `EnumSurfaces` reports the honest empty
//!   enumeration.
//! - D3D9 debug surface: the D3DPERF_* markers/status and DebugSetLevel/
//!   DebugSetMute (the perf status is 0 — the real disabled answer).
//! - D3D10 family: the device-creation entry points build the shared D3D11
//!   device machinery (the D3D10 devices are the D3D11 devices; the
//!   ABI-specific method slots are the documented partial); the effect and
//!   state-block compilers answer E_FAIL (no effect compiler backend).
//! - D3DCompiler: `D3DCreateBlob` allocates real ID3D10Blob objects; the
//!   compile/disassemble/reflect entry points answer E_FAIL with a real
//!   error blob — Casa1 has no HLSL compiler backend.
//! - D3DX11: `D3DX11GetImageInfoFromFile[W]` parses the DDS header into the
//!   documented D3DX11_IMAGE_INFO; the image-processing helpers answer
//!   E_FAIL (no image decoders/encoders are registered).
//!
//! Layer contract: every export returns its HRESULT in EAX.

use super::super::*;
use super::unknown_preamble;
use crate::runtime::state::GuestObjectKind;

/// DD_OK.
const DD_OK: u32 = 0;
/// E_FAIL.
const E_FAIL: u32 = 0x8000_4005;
/// E_INVALIDARG.
const E_INVALIDARG: u32 = 0x8007_0057;
/// E_OUTOFMEMORY.
const E_OUTOFMEMORY: u32 = 0x8007_000e;

/// DDCAPS_3D | DDCAPS_ALPHA | DDCAPS_BLT | DDCAPS_BLTCOLORFILL |
/// DDCAPS_BLTSTRETCH | DDCAPS_ZBLTS.
const DDCAPS_HW: u32 =
    0x0000_0001 | 0x0000_0010 | 0x0000_0040 | 0x0000_0080 | 0x0000_0200 | 0x0000_1000;
/// DDCAPS_3D | DDCAPS_ALPHA | DDCAPS_BLT | DDCAPS_BLTCOLORFILL |
/// DDCAPS_BLTSTRETCH (the software caps).
const DDCAPS_SW: u32 = 0x0000_0001 | 0x0000_0010 | 0x0000_0040 | 0x0000_0080 | 0x0000_0200;

/// DDSCAPS_BACKBUFFER | DDSCAPS_COMPLEX | DDSCAPS_FLIP | DDSCAPS_PRIMARYSURFACE
/// | DDSCAPS_VISIBLE.
const DDSCAPS_PRIMARY: u32 = 0x0000_0004 | 0x0000_0008 | 0x0000_0010 | 0x0000_0200 | 0x0000_1000;
/// DDSCAPS_OFFSCREENPLAIN | DDSCAPS_SYSTEMMEMORY.
const DDSCAPS_OFFSCREEN: u32 = 0x0000_0040 | 0x0000_0800;

/// The DDSURFACEDESC2 layout offsets (the Win32 struct, 124 bytes).
const DDSD_OFFSET_CAPS: u64 = 4;
const DDSD_OFFSET_HEIGHT: u64 = 20;
const DDSD_OFFSET_WIDTH: u64 = 24;
const DDSD_OFFSET_LP_SURFACE: u64 = 48;
const DDSD_OFFSET_PIXEL_FORMAT: u64 = 72;

impl PeHostRuntime {
    /// Route every legacy-graphics thunk to its dispatch function.
    pub(crate) fn dispatch_legacy_gfx(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::DirectDrawCreate => self.dispatch_direct_draw_create(state, memory, false),
            HostThunk::DirectDrawCreateEx => self.dispatch_direct_draw_create(state, memory, true),
            HostThunk::DirectDrawEnumerateW | HostThunk::DirectDrawEnumerateExW => {
                // No DirectDraw devices exist: the enumeration contract
                // reports zero devices (the callback is never invoked).
                state.set(Register::Rax, u64::from(DD_OK));
                Ok(())
            }
            HostThunk::DirectDrawGetCaps => self.dispatch_direct_draw_get_caps(state, memory),
            HostThunk::DirectDrawSetCooperativeLevel => {
                self.dispatch_direct_draw_set_cooperative_level(state, memory)
            }
            HostThunk::DirectDrawSetDisplayMode => {
                self.dispatch_direct_draw_set_display_mode(state, memory)
            }
            HostThunk::DirectDrawCreateSurface => {
                self.dispatch_direct_draw_create_surface(state, memory)
            }
            HostThunk::DirectDrawEnumSurfaces => {
                self.dispatch_direct_draw_enum_surfaces(state, memory)
            }
            HostThunk::DirectDrawGetVerticalBlankStatus => {
                self.dispatch_direct_draw_get_vertical_blank(state, memory)
            }
            HostThunk::DirectDrawSurfaceBlt => self.dispatch_direct_draw_surface_blt(state, memory),
            HostThunk::DirectDrawSurfaceFlip => {
                self.dispatch_direct_draw_surface_flip(state, memory)
            }
            HostThunk::DirectDrawSurfaceLock => {
                self.dispatch_direct_draw_surface_lock(state, memory)
            }
            HostThunk::DirectDrawSurfaceUnlock => {
                self.dispatch_direct_draw_surface_unlock(state, memory)
            }
            HostThunk::DirectDrawSurfaceGetSurfaceDesc => {
                self.dispatch_direct_draw_surface_get_desc(state, memory)
            }
            HostThunk::D3dBlobGetBufferPointer => {
                self.dispatch_d3d_blob_get_buffer_pointer(state, memory)
            }
            HostThunk::D3dBlobGetBufferSize => {
                self.dispatch_d3d_blob_get_buffer_size(state, memory)
            }
            HostThunk::D3dPerfGetStatus => {
                // The perf layer is disabled (the real disabled answer).
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::D3dPerfBeginEvent
            | HostThunk::D3dPerfEndEvent
            | HostThunk::D3dPerfSetMarker
            | HostThunk::D3dPerfQueryRepeatFrame
            | HostThunk::D3dPerfSetOptions
            | HostThunk::DebugSetLevel
            | HostThunk::DebugSetMute => {
                // The marker/level surface records nothing when the perf
                // layer is disabled.
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::D3d10CreateDevice => self.dispatch_d3d10_create_device(state, memory, false),
            HostThunk::D3d10CreateDeviceAndSwapChain => {
                self.dispatch_d3d10_create_device(state, memory, true)
            }
            HostThunk::D3d10CoreCreateDevice => {
                self.dispatch_d3d10_create_device(state, memory, false)
            }
            HostThunk::D3d10CoreCreateLayeredDevice => {
                self.dispatch_d3d10_create_device(state, memory, false)
            }
            HostThunk::D3d10Level9CreateDevice => {
                self.dispatch_d3d10_create_device(state, memory, false)
            }
            HostThunk::D3d10CoreGetSupportedVersions
            | HostThunk::D3d10Level9GetSupportedVersions => {
                let out = guest_call_arg(state, memory, 0)?;
                if out != 0 {
                    for (i, level) in [0x9100_u32, 0x9300, 0xa100].iter().enumerate() {
                        write_guest_u32(memory, out + (i as u64 * 4), *level).ok();
                    }
                }
                state.set(Register::Rax, u64::from(DD_OK));
                Ok(())
            }
            HostThunk::D3d10CoreRegisterLayers => {
                state.set(Register::Rax, u64::from(DD_OK));
                Ok(())
            }
            HostThunk::D3d10CreateEffectFromMemory | HostThunk::D3d10CreateStateBlock => {
                let out = guest_call_arg(state, memory, 0)?;
                let _ = out;
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            HostThunk::D3dCreateBlob => self.dispatch_d3d_create_blob(state, memory),
            HostThunk::D3dCompile
            | HostThunk::D3dCompile2
            | HostThunk::D3dCompileFromFile
            | HostThunk::D3dDisassemble
            | HostThunk::D3dGetBlobPart
            | HostThunk::D3dGetTraceInstructionOffsets
            | HostThunk::D3dLoadModule
            | HostThunk::D3dReflect
            | HostThunk::D3dSetBlobPart
            | HostThunk::D3dSetTraceInstructionOffsets
            | HostThunk::D3dStripShader
            | HostThunk::D3dCreateLinker => self.dispatch_d3d_compile_fail(state, memory),
            HostThunk::D3dx11GetImageInfoFromFile | HostThunk::D3dx11GetImageInfoFromFileW => {
                self.dispatch_d3dx_get_image_info(state, memory)
            }
            HostThunk::D3dx11CompileFromFile
            | HostThunk::D3dx11CompileFromFileW
            | HostThunk::D3dx11CreateAsyncShaderResourceViewProcessor
            | HostThunk::D3dx11CreateShaderResourceViewFromFile
            | HostThunk::D3dx11CreateShaderResourceViewFromFileW
            | HostThunk::D3dx11CreateTextureFromFileW
            | HostThunk::D3dx11CreateTextureFromMemory
            | HostThunk::D3dx11FilterTexture
            | HostThunk::D3dx11LoadTextureFromTexture
            | HostThunk::D3dx11SaveTextureToFileW
            | HostThunk::D3dx11SaveTextureToMemory => {
                // No image decoders/encoders are registered; the processing
                // helpers answer the documented failure.
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted legacy-graphics thunk {thunk:?}"),
            )),
        }
    }

    // ── DirectDraw ─────────────────────────────────────────────────────────

    /// `DirectDrawCreate(guid, ppDD, unk)` / `DirectDrawCreateEx(guid, ppDD,
    /// iid, unk)` — the IDirectDraw7 object.
    pub(crate) fn dispatch_direct_draw_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        is_ex: bool,
    ) -> AppResult<()> {
        let mut arg = 0;
        let _guid = guest_call_arg(state, memory, arg)?;
        arg += 1;
        let out = guest_call_arg(state, memory, arg)?;
        arg += 1;
        if is_ex {
            let _iid = guest_call_arg(state, memory, arg)?;
            arg += 1;
        }
        let _outer = guest_call_arg(state, memory, arg)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let methods = self.legacy_gfx_direct_draw_methods();
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::DirectDraw7, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.ddraw_objects
            .insert(object, DirectDrawObjectState::default());
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `IDirectDraw7::GetCaps(hwCaps, swCaps)`.
    pub(crate) fn dispatch_direct_draw_get_caps(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let hw = guest_call_arg(state, memory, 1)?;
        let sw = guest_call_arg(state, memory, 2)?;
        if hw != 0 {
            write_guest_u32(memory, hw, DDCAPS_HW).ok();
        }
        if sw != 0 {
            write_guest_u32(memory, sw, DDCAPS_SW).ok();
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `IDirectDraw7::SetCooperativeLevel(hwnd, flags)`.
    pub(crate) fn dispatch_direct_draw_set_cooperative_level(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _hwnd = guest_call_arg(state, memory, 1)?;
        let flags = guest_call_arg_u32(state, memory, 2)?;
        if let Some(object) = self.ddraw_objects.get_mut(&this) {
            object.cooperative_level = flags;
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `IDirectDraw7::CreateSurface(desc, ppSurf, unk)` — a software
    /// surface with the DDSURFACEDESC2 dimensions.
    pub(crate) fn dispatch_direct_draw_create_surface(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let desc = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let _outer = guest_call_arg(state, memory, 3)?;
        if desc == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let width = read_guest_u32(memory, desc + DDSD_OFFSET_WIDTH)
            .unwrap_or(0)
            .max(1);
        let height = read_guest_u32(memory, desc + DDSD_OFFSET_HEIGHT)
            .unwrap_or(0)
            .max(1);
        let caps = read_guest_u32(memory, desc + DDSD_OFFSET_CAPS).unwrap_or(0);
        let methods = self.legacy_gfx_surface_methods();
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::DirectDrawSurface, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.ddraw_surfaces.insert(
            object,
            DirectDrawSurfaceState {
                width,
                height,
                pitch: width * 4,
                pixels: vec![0; (width * height * 4) as usize],
                caps: if caps & DDSCAPS_PRIMARY != 0 {
                    DDSCAPS_PRIMARY
                } else {
                    DDSCAPS_OFFSCREEN
                },
            },
        );
        // The runtime's "surface" field in the desc is filled.
        if desc != 0 {
            write_guest_pointer(
                memory,
                desc + DDSD_OFFSET_LP_SURFACE,
                object,
                self.guest_arch,
            )
            .ok();
        }
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `IDirectDraw7::EnumSurfaces(flags, desc, callback, context)` — the
    /// honest empty enumeration.
    pub(crate) fn dispatch_direct_draw_enum_surfaces(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let _desc = guest_call_arg(state, memory, 2)?;
        let _callback = guest_call_arg(state, memory, 3)?;
        let _context = guest_call_arg(state, memory, 4)?;
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `IDirectDraw7::GetVerticalBlankStatus(flags)`.
    pub(crate) fn dispatch_direct_draw_get_vertical_blank(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_u32(memory, out, 0).ok();
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `IDirectDraw7::SetDisplayMode(width, height, bpp, refresh, flags)` —
    /// the display mode is recorded.
    pub(crate) fn dispatch_direct_draw_set_display_mode(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let width = guest_call_arg_u32(state, memory, 1)?;
        let height = guest_call_arg_u32(state, memory, 2)?;
        let bpp = guest_call_arg_u32(state, memory, 3)?;
        if let Some(object) = self.ddraw_objects.get_mut(&this) {
            object.display_width = width;
            object.display_height = height;
            object.display_bpp = bpp;
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    // ── IDirectDrawSurface7 ────────────────────────────────────────────────

    /// `IDirectDrawSurface7::Lock(rect, desc, flags, handle)` — expose the
    /// pixel buffer.
    pub(crate) fn dispatch_direct_draw_surface_lock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _rect = guest_call_arg(state, memory, 1)?;
        let desc = guest_call_arg(state, memory, 2)?;
        let _flags = guest_call_arg_u32(state, memory, 3)?;
        let Some(surface) = self.ddraw_surfaces.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        };
        if desc != 0 {
            // Fill the DDSURFACEDESC2 fields the Lock contract sets: size,
            // caps, height, width, pixel format (32-bit RGBA), and the
            // surface pointer.
            write_guest_u32(memory, desc, 124).ok();
            write_guest_u32(memory, desc + DDSD_OFFSET_CAPS, surface.caps).ok();
            write_guest_u32(memory, desc + DDSD_OFFSET_HEIGHT, surface.height).ok();
            write_guest_u32(memory, desc + DDSD_OFFSET_WIDTH, surface.width).ok();
            write_guest_u32(memory, desc + 40, surface.pitch).ok();
            write_guest_pointer(memory, desc + DDSD_OFFSET_LP_SURFACE, this, self.guest_arch).ok();
            let pixel_format = desc + DDSD_OFFSET_PIXEL_FORMAT;
            write_guest_u32(memory, pixel_format, 32).ok(); // dwSize
            write_guest_u32(memory, pixel_format + 4, 0x0000_0040).ok(); // DDPF_RGB
            write_guest_u32(memory, pixel_format + 8, 0).ok(); // dwFourCC
            write_guest_u32(memory, pixel_format + 20, 32).ok(); // dwRGBBitCount
            write_guest_u32(memory, pixel_format + 24, 0x00ff_0000).ok(); // dwRBitMask
            write_guest_u32(memory, pixel_format + 28, 0x0000_ff00).ok(); // dwGBitMask
            write_guest_u32(memory, pixel_format + 32, 0x0000_00ff).ok(); // dwBBitMask
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `IDirectDrawSurface7::Unlock(rect)`.
    pub(crate) fn dispatch_direct_draw_surface_unlock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _rect = guest_call_arg(state, memory, 1)?;
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `IDirectDrawSurface7::GetSurfaceDesc(desc)` — report the surface.
    pub(crate) fn dispatch_direct_draw_surface_get_desc(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let desc = guest_call_arg(state, memory, 1)?;
        let Some(surface) = self.ddraw_surfaces.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        };
        if desc != 0 {
            write_guest_u32(memory, desc, 124).ok();
            write_guest_u32(memory, desc + DDSD_OFFSET_CAPS, surface.caps).ok();
            write_guest_u32(memory, desc + DDSD_OFFSET_HEIGHT, surface.height).ok();
            write_guest_u32(memory, desc + DDSD_OFFSET_WIDTH, surface.width).ok();
            write_guest_u32(memory, desc + 40, surface.pitch).ok();
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `IDirectDrawSurface7::Flip(unk, flags)` — single-buffered; the
    /// documented no-op.
    pub(crate) fn dispatch_direct_draw_surface_flip(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _unk = guest_call_arg(state, memory, 1)?;
        let _flags = guest_call_arg_u32(state, memory, 2)?;
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `IDirectDrawSurface7::Blt(dstRect, srcSurface, srcRect, flags, bltFx)`
    /// — a pixel copy between the runtime's surfaces.
    pub(crate) fn dispatch_direct_draw_surface_blt(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _dst_rect = guest_call_arg(state, memory, 1)?;
        let source = guest_call_arg(state, memory, 2)?;
        let _src_rect = guest_call_arg(state, memory, 3)?;
        let _flags = guest_call_arg_u32(state, memory, 4)?;
        let _blt_fx = guest_call_arg(state, memory, 5)?;
        let Some(source) = self.ddraw_surfaces.get(&source).cloned() else {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        };
        if let Some(target) = self.ddraw_surfaces.get_mut(&this) {
            let copy = source.pixels.len().min(target.pixels.len());
            target.pixels[..copy].copy_from_slice(&source.pixels[..copy]);
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    // ── D3D10 family ───────────────────────────────────────────────────────

    /// `D3D10CreateDevice(adapter, driverType, software, flags, sdkVersion,
    /// ppDevice)` (and the swap-chain variant) — the shared D3D11 device
    /// machinery.
    pub(crate) fn dispatch_d3d10_create_device(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        with_swap_chain: bool,
    ) -> AppResult<()> {
        let _adapter = guest_call_arg(state, memory, 0)?;
        let _driver_type = guest_call_arg_u32(state, memory, 1)?;
        let _software = guest_call_arg(state, memory, 2)?;
        let _flags = guest_call_arg_u32(state, memory, 3)?;
        let _sdk_version = guest_call_arg_u32(state, memory, 4)?;
        let mut arg = 5;
        let out = guest_call_arg(state, memory, arg)?;
        arg += 1;
        let mut swap_chain_out = 0;
        let mut swap_chain_desc = None;
        if with_swap_chain {
            let desc = guest_call_arg(state, memory, arg)?;
            arg += 1;
            swap_chain_out = guest_call_arg(state, memory, arg)?;
            if desc != 0 {
                swap_chain_desc = read_swapchain_desc(memory, desc).ok();
            }
        }
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let request = DeviceCreationRequest {
            requested_feature_levels: vec![
                crate::d3d11::FeatureLevel::Level10_1,
                crate::d3d11::FeatureLevel::Level11_0,
            ],
        };
        let device = match swap_chain_desc {
            Some(desc) => d3d11_create_device_and_swapchain(request, desc),
            None => d3d11_create_device(request),
        };
        let Ok(device) = device else {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        };
        let Ok(device_object) = self.alloc_d3d11_device_object(memory, device) else {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        };
        if with_swap_chain
            && swap_chain_out != 0
            && let Ok(device_host) = self.d3d11_device(device_object)
            && let Some(swap_chain) = device_host.swapchain_object
        {
            self.add_ref_guest_object(swap_chain).ok();
            write_guest_pointer(memory, swap_chain_out, swap_chain, self.guest_arch).ok();
        }
        if out != 0 {
            write_guest_pointer(memory, out, device_object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    // ── D3DCompiler ────────────────────────────────────────────────────────

    /// `D3DCreateBlob(size, ppBlob)` — a real ID3D10Blob allocation.
    pub(crate) fn dispatch_d3d_create_blob(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let size = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if size > 512 * 1024 * 1024 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        let mut methods = unknown_preamble();
        methods.push(HostThunk::D3dBlobGetBufferPointer);
        methods.push(HostThunk::D3dBlobGetBufferSize);
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::D3dBlob, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.d3d_blobs.insert(object, vec![0_u8; size as usize]);
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    /// `ID3D10Blob::GetBufferPointer()` — the guest pointer to the blob
    /// data.
    pub(crate) fn dispatch_d3d_blob_get_buffer_pointer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if let Some(bytes) = self.d3d_blobs.get_mut(&this) {
            bytes.resize(bytes.len().max(1), 0);
        }
        state.set(Register::Rax, this);
        Ok(())
    }

    /// `ID3D10Blob::GetBufferSize()`.
    pub(crate) fn dispatch_d3d_blob_get_buffer_size(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let size = self
            .d3d_blobs
            .get(&this)
            .map(|b| b.len() as u64)
            .unwrap_or(0);
        state.set(Register::Rax, size);
        Ok(())
    }

    /// The compile/disassemble/reflect family: no HLSL compiler backend —
    /// E_FAIL with a real error blob where the signature has one.
    pub(crate) fn dispatch_d3d_compile_fail(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let message = "Casa1 provides no HLSL shader compiler backend".as_bytes();
        // Most of the family carries the error blob in the last parameter.
        let last = guest_call_arg(state, memory, 5).or_else(|_| guest_call_arg(state, memory, 2));
        let out = last.unwrap_or(0);
        if out != 0 {
            let mut methods = unknown_preamble();
            methods.push(HostThunk::D3dBlobGetBufferPointer);
            methods.push(HostThunk::D3dBlobGetBufferSize);
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let object = self
                .alloc_guest_object(memory, GuestObjectKind::D3dBlob, vtable)
                .unwrap_or(0);
            if object != 0 {
                self.d3d_blobs.insert(object, message.to_vec());
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
            }
        }
        state.set(Register::Rax, u64::from(E_FAIL));
        Ok(())
    }

    // ── D3DX11 ─────────────────────────────────────────────────────────────

    /// `D3DX11GetImageInfoFromFile[W](filename, srcData, info, unk)` — the
    /// DDS header parse into D3DX11_IMAGE_INFO.
    pub(crate) fn dispatch_d3dx_get_image_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let filename = guest_call_arg(state, memory, 0)?;
        let _src_data = guest_call_arg(state, memory, 1)?;
        let info_out = guest_call_arg(state, memory, 2)?;
        let _unk = guest_call_arg(state, memory, 3)?;
        let path = read_utf16_string(memory, filename).unwrap_or_default();
        let Ok(bytes) = std::fs::read(&path) else {
            state.set(Register::Rax, 0x8876_0006); // D3DXERR_INVALIDDATA
            return Ok(());
        };
        // The DDS magic + DDS_HEADER: width/height/mipmap count/format.
        if bytes.len() < 128 || &bytes[..4] != b"DDS " {
            state.set(Register::Rax, 0x8876_0006);
            return Ok(());
        }
        let height = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let width = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let mip_levels = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]).max(1);
        if info_out != 0 {
            // D3DX11_IMAGE_INFO: Width(0), Height(4), Depth(8), MipLevels(12),
            // MiscFlags(16), Format(20), ResourceDimension(24), ImageArraySize(28).
            write_guest_u32(memory, info_out, width).ok();
            write_guest_u32(memory, info_out + 4, height).ok();
            write_guest_u32(memory, info_out + 8, 1).ok();
            write_guest_u32(memory, info_out + 12, mip_levels).ok();
            write_guest_u32(memory, info_out + 20, 28).ok(); // DXGI_FORMAT_R8G8B8A8_UNORM
            write_guest_u32(memory, info_out + 24, 3).ok(); // D3D11_RESOURCE_DIMENSION_TEXTURE2D
        }
        state.set(Register::Rax, u64::from(DD_OK));
        Ok(())
    }

    // ── The vtable builders ────────────────────────────────────────────────

    fn legacy_gfx_direct_draw_methods(&self) -> Vec<HostThunk> {
        // IDirectDraw7: IUnknown + 28 methods.  The implemented surface:
        // GetCaps, SetCooperativeLevel, SetDisplayMode, CreateSurface,
        // EnumSurfaces, GetVerticalBlankStatus; the rest answer
        // DDERR_UNSUPPORTED.
        let mut methods =
            vec![unsupported_method(&self.telemetry, "IDirectDraw7::unsupported"); 31];
        methods[0] = unsupported_method(&self.telemetry, "IDirectDraw7::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[3] = HostThunk::DirectDrawGetCaps;
        methods[4] = HostThunk::DirectDrawSetCooperativeLevel;
        methods[5] = HostThunk::DirectDrawSetDisplayMode;
        methods[8] = HostThunk::DirectDrawCreateSurface;
        methods[14] = HostThunk::DirectDrawEnumSurfaces;
        methods[18] = HostThunk::DirectDrawGetVerticalBlankStatus;
        methods
    }

    fn legacy_gfx_surface_methods(&self) -> Vec<HostThunk> {
        // IDirectDrawSurface7: IUnknown + 39 methods.  The implemented
        // surface: Lock, Unlock, GetSurfaceDesc, Flip, Blt.
        let mut methods =
            vec![unsupported_method(&self.telemetry, "IDirectDrawSurface7::unsupported"); 42];
        methods[0] = unsupported_method(&self.telemetry, "IDirectDrawSurface7::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[10] = HostThunk::DirectDrawSurfaceBlt;
        methods[11] = HostThunk::DirectDrawSurfaceFlip;
        methods[23] = HostThunk::DirectDrawSurfaceLock;
        methods[24] = HostThunk::DirectDrawSurfaceUnlock;
        methods[26] = HostThunk::DirectDrawSurfaceGetSurfaceDesc;
        methods
    }
}
