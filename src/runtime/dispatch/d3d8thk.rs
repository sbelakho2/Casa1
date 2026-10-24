//! D3D8 kernel dispatch: the d3d8thk.dll exports mapped onto the synthetic
//! WDDM personality in [`crate::wddm`].  Every entry point reads its guest
//! descriptor with the architecture's pointer width, validates the handle
//! against the facade object table, calls the facade, and writes the
//! documented output fields back.  Nothing answers a fabricated success:
//! unmodelled KMT operations return `STATUS_NOT_SUPPORTED`, malformed
//! descriptors return `STATUS_INVALID_PARAMETER`, and stale handles return the
//! facade's exact `STATUS_INVALID_HANDLE`/`STATUS_GRAPHICS_*` value.
//!
//! The facade is a process-wide host-GPU personality (one adapter table per
//! process, like a real display driver).
//!
//! # Guest layouts
//!
//! `D3DKMT_HANDLE` is a `u32`, `LUID` is `{ LowPart: u32, HighPart: i32 }`
//! (8 bytes), and guest pointers are 4 bytes on x86 / 8 bytes on x64 with the
//! pointer field naturally aligned.  Structures that exist in the Windows SDK
//! use their documented WDK layouts (`D3DKMT_OPENADAPTERFROMLUID`,
//! `D3DKMT_OPENADAPTERFROMHDC`, `D3DKMT_ENUMADAPTERS2`/`D3DKMT_ADAPTERINFO`,
//! `D3DKMT_QUERYADAPTERINFO`, `D3DKMT_CREATEDEVICE`, `D3DKMT_DESTROYDEVICE`,
//! `D3DKMT_DESTROYALLOCATION`, `D3DKMT_QUERYALLOCATIONRESIDENCY`,
//! `D3DKMT_QUERYSTATISTICS`).  The allocation/fence/swapchain descriptors are
//! the synthetic driver's public contract because the facade's sizes,
//! segments, fence values and present counters have no public WDK equivalent;
//! their offsets are pinned below and in the tests.
//!
//! Additional synthetic descriptors (pinned by tests):
//! - create-context: `{ hDevice u32, NodeOrdinal u32, Priority u32, hContext out u32 }`
//! - render: `{ hDevice u32, hContext u32, Allocations ptr, Count u32, Fill u32,
//!   FenceHandle u32, pad u32, FenceValue u64, BytesOut u64, FenceOut u64,
//!   PriorityOut u32, ContextIdOut u64 }` with each pointer/u64 aligned at 8.
//! - open-resource/2: `{ hDevice, hResource, hOpened out, pad, [pPrivateData,
//!   PrivateSize] }` for type 2.
//! - open-keyed-mutex/2: `{ hDevice, hResource, Key u64, hMutex out, Flags u32,
//!   [pPrivateData, PrivateSize] }` for type 2.
//! - acquire/release-keyed-mutex: `{ hDevice, hMutex, Key u64, TimeoutNs u64 }`.
//! - signal-2: `{ hDevice, ObjectCount, Objects ptr, FenceValue u64,
//!   BroadcastContextCount u32, BroadcastContexts ptr }`.
//! - wait-2: `{ hDevice, ObjectCount, Objects ptr, Values ptr, TimeoutNs u64 }`.
//! - display-mode list: `{ hAdapter, ModeCount in/out, Modes ptr, Flags u32 }`
//!   with 20-byte entries `{ width, height, refresh_num, refresh_den, flags }`.
//! - output enumeration: `{ hAdapter, OutputCount in/out, Outputs ptr, Flags u32 }`
//!   with 24-byte entries
//!   `{ output_id, source_id, target_id, dpi_x, dpi_y, mode_count }`.
//! - per-source display-mode list: `{ hAdapter, VidPnSourceId, ModeCount in/out,
//!   pad, Modes ptr, Flags u32 }` with the same 20-byte mode entries.
//! - gamma ramp: `{ hAdapter, OutputId, Type, EntryCount, RampPtr }`; type 1
//!   carries 256 `u16` red entries, then green, then blue (1536 bytes).
//! - cursor position: `{ hAdapter, OutputId, X i32, Y i32 }`.
//! - cursor shape: `{ hAdapter, OutputId, Visible, Width, Height, HotX, HotY,
//!   pad, PixelsPtr }` with `width * height` `u32` ARGB pixels.
//! - PnP start/stop: `{ hAdapter }`; power component:
//!   `{ hAdapter, Component, PowerState }`.
//! - allocation priority: `{ hDevice, AllocationCount, Allocations ptr, Priority u32 }`.
//! - private driver format: `{ hAdapter, VidPnSourceId, Attribute u32 }`.
//! - statistics: `{ Size u32 (120 or 136), Type u32, hAdapter u32,
//!   NodeOrdinal u32, [ProcessId u64, SegmentId u32, SegmentGroup u32 for 136],
//!   13 u64 counters }` using the documented `D3DKMT_QUERYSTATISTICS_TYPE`
//!   values. In the 120-byte form `NodeOrdinal` doubles as the PROCESS process
//!   id, the SEGMENT segment id and the NODE ordinal. The 136-byte form is
//!   required for process+segment, process+node and process+segment-group
//!   classes and carries the full `u64` process id.
//!
//! Layer contract: every export returns its NTSTATUS in EAX (0 =
//! STATUS_SUCCESS).

use super::super::*;
use crate::host_thunks::write_guest_bytes_checked;
use crate::wddm::{
    AdapterHandle, AllocationDesc, AllocationHandle, ContextHandle, CreateAllocationsRequest,
    CreateContextRequest, CreateDeviceRequest, CreateSwapChainRequest,
    D3DKMT_QUERYSTATISTICS_PROCESS_NODE, D3DKMT_QUERYSTATISTICS_PROCESS_NODE2,
    D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT, D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP,
    D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP2, D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT2,
    D3DKMT_QUERYSTATISTICS_SEGMENT, D3DKMT_QUERYSTATISTICS_SEGMENT2, DeviceHandle,
    GAMMA_RAMP_ENTRIES, GAMMA_RAMP_TYPE_RAMP, KeyedMutexHandle, Luid, MAX_KMT_ARRAY,
    MAX_SCHEDULING_PRIORITY, PresentRequest, RenderRequest, SegmentId, SwapChainHandle,
    SyncObjectHandle, WddmStatisticsSnapshot, WddmSubsystem,
};
#[cfg(test)]
use crate::wddm::{
    D3DKMT_QUERYSTATISTICS_ADAPTER, D3DKMT_QUERYSTATISTICS_ADAPTER2,
    D3DKMT_QUERYSTATISTICS_HISTOGRAM, D3DKMT_QUERYSTATISTICS_NODE, D3DKMT_QUERYSTATISTICS_NODE2,
    D3DKMT_QUERYSTATISTICS_PROCESS, D3DKMT_QUERYSTATISTICS_VIDPNSOURCE, GAMMA_RAMP_TYPE_IDENTITY,
    MAX_CURSOR_DIMENSION, POWER_COMPONENT_GPU, POWER_STATE_D0, POWER_STATE_D3, WddmPnpEvent,
};
use std::sync::OnceLock;

/// STATUS_SUCCESS.
const STATUS_SUCCESS: u32 = 0;
/// STATUS_TIMEOUT.
#[cfg(test)]
const STATUS_TIMEOUT: u32 = 0x0000_0102;
/// STATUS_INVALID_HANDLE.
#[cfg(test)]
const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
/// STATUS_INVALID_PARAMETER.
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
/// STATUS_BUFFER_TOO_SMALL.
const STATUS_BUFFER_TOO_SMALL: u32 = 0xc000_0023;
/// STATUS_ACCESS_DENIED.
#[cfg(test)]
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
/// STATUS_OBJECT_NAME_COLLISION.
#[cfg(test)]
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xc000_0035;
/// STATUS_NOT_SUPPORTED.
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
/// STATUS_INVALID_DEVICE_STATE.
#[cfg(test)]
const STATUS_INVALID_DEVICE_STATE: u32 = 0xc000_0184;
/// STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER.
const STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER: u32 = 0xc01e_0002;
/// STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE.
#[cfg(test)]
const STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE: u32 = 0xc01e_0003;
/// STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET.
#[cfg(test)]
const STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET: u32 = 0xc01e_0004;
/// STATUS_GRAPHICS_PRESENT_INVALID_WINDOW.
#[cfg(test)]
const STATUS_GRAPHICS_PRESENT_INVALID_WINDOW: u32 = 0xc01e_000f;
/// STATUS_GRAPHICS_NO_VIDEO_MEMORY.
#[cfg(test)]
const STATUS_GRAPHICS_NO_VIDEO_MEMORY: u32 = 0xc01e_0100;
/// STATUS_GRAPHICS_ALLOCATION_BUSY.
#[cfg(test)]
const STATUS_GRAPHICS_ALLOCATION_BUSY: u32 = 0xc01e_0102;
/// STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE.
#[cfg(test)]
const STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE: u32 = 0xc01e_0114;
/// STATUS_GRAPHICS_INVALID_PIXELFORMAT.
const STATUS_GRAPHICS_INVALID_PIXELFORMAT: u32 = 0xc01e_033d;

/// `D3DKMT_ADAPTERINFO` size (hAdapter + LUID + NumOfSources + flags).
const ADAPTERINFO_SIZE: u64 = 20;
/// `D3DKMT_ADAPTERREGISTRYINFO` size (four `WCHAR[MAX_PATH]` strings).
const REGISTRY_INFO_SIZE: u32 = 4 * 260 * 2;
/// Synthetic `D3DKMT_QUERYSTATISTICS` descriptor size (16-byte header plus a
/// 104-byte counter union for the documented ADAPTER/ADAPTER2/NODE types).
const STATISTICS_SIZE: u32 = 120;
/// Extended statistics descriptor: 32-byte header (process/segment ids) plus
/// the same 104-byte counter union.
const STATISTICS_EXTENDED_SIZE: u32 = 136;
/// Synthetic display-mode entry: width, height, refresh numerator/denominator,
/// and flags.
const DISPLAY_MODE_SIZE: u64 = 20;
/// Synthetic output entry: output/source/target ids, DPI and mode count.
const OUTPUT_ENTRY_SIZE: u64 = 24;
/// `D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME.DeviceName` length in `WCHAR`s.
const GDI_DISPLAY_NAME_UNITS: usize = 32;
/// `D3DKMT_OPENADAPTERFROMDEVICENAME.DeviceName` length in `WCHAR`s.
const DEVICE_NAME_UNITS: usize = 260;
/// `D3DKMT_CREATEDEVICE.Flags` bit requesting a shareable device object.
const CREATEDEVICE_FLAG_SHAREABLE: u32 = 0x8000_0000;
/// Synthetic create-allocation flag: the allocation may be shared.
const CREATEALLOCATION_FLAG_SHARED: u32 = 0x1;
/// Synthetic present flag: tearing is allowed at interval zero.
const PRESENT_FLAG_ALLOW_TEARING: u32 = 0x1;
/// `D3DDDI_SYNCHRONIZATIONOBJECTTYPE` fence.
const SYNCOBJECT_TYPE_FENCE: u32 = 3;

/// `KMTQAITYPE_GETSEGMENTSIZE`.
const KMTQAITYPE_GETSEGMENTSIZE: u32 = 3;
/// `KMTQAITYPE_ADAPTERGUID`.
const KMTQAITYPE_ADAPTERGUID: u32 = 4;
/// `KMTQAITYPE_ADAPTERADDRESS`.
const KMTQAITYPE_ADAPTERADDRESS: u32 = 6;
/// `KMTQAITYPE_ADAPTERREGISTRYINFO`.
const KMTQAITYPE_ADAPTERREGISTRYINFO: u32 = 8;
/// `KMTQAITYPE_DRIVERVERSION`.
const KMTQAITYPE_DRIVERVERSION: u32 = 13;
/// `KMTQAITYPE_ADAPTERTYPE`.
const KMTQAITYPE_ADAPTERTYPE: u32 = 15;

type KmtResult<T> = Result<T, u32>;

/// Reset the shared WDDM facade between tests (test-only).
#[cfg(test)]
pub(crate) fn reset_test_facade() {
    wddm().reset_for_tests();
}

fn wddm() -> &'static WddmSubsystem {
    static SUBSYSTEM: OnceLock<WddmSubsystem> = OnceLock::new();
    SUBSYSTEM.get_or_init(WddmSubsystem::new)
}

fn kmt_invalid_pointer() -> u32 {
    STATUS_INVALID_PARAMETER
}

fn kmt_read_u32(memory: &MemoryImage, address: u64) -> KmtResult<u32> {
    read_guest_u32(memory, address).map_err(|_| kmt_invalid_pointer())
}

fn kmt_read_u64(memory: &MemoryImage, address: u64) -> KmtResult<u64> {
    read_guest_u64(memory, address).map_err(|_| kmt_invalid_pointer())
}

fn kmt_read_pointer(memory: &MemoryImage, address: u64, arch: GuestArch) -> KmtResult<u64> {
    read_guest_pointer(memory, address, arch).map_err(|_| kmt_invalid_pointer())
}

fn kmt_write_u32(memory: &mut MemoryImage, address: u64, value: u32) -> KmtResult<()> {
    write_guest_bytes_checked(memory, address, &value.to_le_bytes())
        .map_err(|_| kmt_invalid_pointer())
}

fn kmt_write_u64(memory: &mut MemoryImage, address: u64, value: u64) -> KmtResult<()> {
    write_guest_bytes_checked(memory, address, &value.to_le_bytes())
        .map_err(|_| kmt_invalid_pointer())
}

fn kmt_write_bytes(memory: &mut MemoryImage, address: u64, bytes: &[u8]) -> KmtResult<()> {
    write_guest_bytes_checked(memory, address, bytes).map_err(|_| kmt_invalid_pointer())
}

fn kmt_align8(value: u64) -> u64 {
    (value + 7) & !7
}

fn kmt_read_inline_wide(memory: &MemoryImage, address: u64, units: usize) -> Option<String> {
    let mut wide = Vec::with_capacity(units);
    let mut terminated = false;
    for index in 0..units {
        let unit = read_guest_u16(memory, address + index as u64 * 2).ok()?;
        if unit == 0 {
            terminated = true;
            break;
        }
        wide.push(unit);
    }
    if !terminated {
        return None;
    }
    String::from_utf16(&wide).ok()
}

fn kmt_encode_fixed_utf16(buffer: &mut [u8], offset: usize, value: &str) {
    let mut units = value.encode_utf16();
    for index in 0..260 {
        let unit = units.next().unwrap_or(0);
        let at = offset + index * 2;
        buffer[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
}

impl PeHostRuntime {
    /// Route every D3D8-kernel thunk to its dispatch function.
    pub(crate) fn dispatch_d3d8thk(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let outcome = match thunk {
            HostThunk::D3DKMTEnumAdapters => self.d3d8thk_enum_adapters(state, memory),
            HostThunk::D3DKMTOpenAdapterFromLuid => {
                self.d3d8thk_open_adapter_from_luid(state, memory)
            }
            HostThunk::D3DKMTOpenAdapterFromHdc => {
                self.d3d8thk_open_adapter_from_hdc(state, memory)
            }
            HostThunk::D3DKMTCloseAdapter => self.d3d8thk_close_adapter(state, memory),
            HostThunk::D3DKMTCreateDevice => self.d3d8thk_create_device(state, memory),
            HostThunk::D3DKMTOpenDevice => self.d3d8thk_open_device(state, memory),
            HostThunk::D3DKMTDestroyDevice => self.d3d8thk_destroy_device(state, memory),
            HostThunk::D3DKMTQueryAdapterInfo => self.d3d8thk_query_adapter_info(state, memory),
            HostThunk::D3DKMTCreateAllocation => self.d3d8thk_create_allocation(state, memory),
            HostThunk::D3DKMTDestroyAllocation => self.d3d8thk_destroy_allocation(state, memory),
            HostThunk::D3DKMTMakeResident => self.d3d8thk_make_resident(state, memory),
            HostThunk::D3DKMTEvict => self.d3d8thk_evict(state, memory),
            HostThunk::D3DKMTQueryAllocationResidency => {
                self.d3d8thk_query_allocation_residency(state, memory)
            }
            HostThunk::D3DKMTCreateSynchronizationObject => {
                self.d3d8thk_create_synchronization_object(state, memory)
            }
            HostThunk::D3DKMTSignalSynchronizationObject => {
                self.d3d8thk_signal_synchronization_object(state, memory)
            }
            HostThunk::D3DKMTSignalSynchronizationObject2 => {
                self.d3d8thk_signal_synchronization_object2(state, memory)
            }
            HostThunk::D3DKMTWaitForSynchronizationObject => {
                self.d3d8thk_wait_for_synchronization_object(state, memory)
            }
            HostThunk::D3DKMTWaitForSynchronizationObject2 => {
                self.d3d8thk_wait_for_synchronization_object2(state, memory)
            }
            HostThunk::D3DKMTDestroySynchronizationObject => {
                self.d3d8thk_destroy_synchronization_object(state, memory)
            }
            HostThunk::D3DKMTCreateContext => self.d3d8thk_create_context(state, memory),
            HostThunk::D3DKMTDestroyContext => self.d3d8thk_destroy_context(state, memory),
            HostThunk::D3DKMTRender => self.d3d8thk_render(state, memory),
            HostThunk::D3DKMTOpenResource => self.d3d8thk_open_resource(state, memory, false),
            HostThunk::D3DKMTOpenResource2 => self.d3d8thk_open_resource(state, memory, true),
            HostThunk::D3DKMTOpenKeyedMutex => self.d3d8thk_open_keyed_mutex(state, memory, false),
            HostThunk::D3DKMTOpenKeyedMutex2 => self.d3d8thk_open_keyed_mutex(state, memory, true),
            HostThunk::D3DKMTAcquireKeyedMutex | HostThunk::D3DKMTAcquireKeyedMutex2 => {
                self.d3d8thk_acquire_keyed_mutex(state, memory)
            }
            HostThunk::D3DKMTReleaseKeyedMutex | HostThunk::D3DKMTReleaseKeyedMutex2 => {
                self.d3d8thk_release_keyed_mutex(state, memory)
            }
            HostThunk::D3DKMTGetDisplayModeList => {
                self.d3d8thk_get_display_mode_list(state, memory)
            }
            HostThunk::D3DKMTGetDisplayModeList2 => {
                self.d3d8thk_get_display_mode_list2(state, memory)
            }
            HostThunk::D3DKMTEnumOutputs => self.d3d8thk_enum_outputs(state, memory),
            HostThunk::D3DKMTSetGammaRamp => self.d3d8thk_set_gamma_ramp(state, memory),
            HostThunk::D3DKMTGetGammaRamp => self.d3d8thk_get_gamma_ramp(state, memory),
            HostThunk::D3DKMTSetCursorPosition => self.d3d8thk_set_cursor_position(state, memory),
            HostThunk::D3DKMTSetCursor => self.d3d8thk_set_cursor(state, memory),
            HostThunk::D3DKMTPnPStart => self.d3d8thk_pnp_start(state, memory),
            HostThunk::D3DKMTPnPStop => self.d3d8thk_pnp_stop(state, memory),
            HostThunk::D3DKMTPowerComponent => self.d3d8thk_power_component(state, memory),
            HostThunk::D3DKMTSetAllocationPriority => {
                self.d3d8thk_set_allocation_priority(state, memory)
            }
            HostThunk::D3DKMTSetDisplayPrivateDriverFormat => {
                self.d3d8thk_set_display_private_driver_format(state, memory)
            }
            HostThunk::D3DKMTOpenAdapterFromGdiDisplayName => {
                self.d3d8thk_open_adapter_from_name(state, memory, true)
            }
            HostThunk::D3DKMTOpenAdapterFromDeviceName => {
                self.d3d8thk_open_adapter_from_name(state, memory, false)
            }
            HostThunk::D3DKMTCreateSwapChain => self.d3d8thk_create_swapchain(state, memory),
            HostThunk::D3DKMTPresent => self.d3d8thk_present(state, memory),
            HostThunk::D3DKMTQuerySwapChainInfo => self.d3d8thk_query_swapchain_info(state, memory),
            HostThunk::D3DKMTDestroySwapchain => self.d3d8thk_destroy_swapchain(state, memory),
            HostThunk::D3DKMTQueryStatistics => self.d3d8thk_query_statistics(state, memory),
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unrouted D3D8-kernel thunk {thunk:?}"),
                ));
            }
        };
        state.set(
            Register::Rax,
            u64::from(match outcome {
                Ok(()) => STATUS_SUCCESS,
                Err(status) => status,
            }),
        );
        Ok(())
    }

    fn d3d8thk_enum_adapters(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let arch = self.guest_arch;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let capacity = kmt_read_u32(memory, info)?;
        let list = kmt_read_pointer(memory, info + arch.pointer_bytes() as u64, arch)?;
        let adapters = wddm().d3dkmt_enum_adapters();
        let count = adapters.len() as u32;
        if list == 0 {
            if capacity != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            return kmt_write_u32(memory, info, count);
        }
        if capacity < count {
            kmt_write_u32(memory, info, count)?;
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        for (index, adapter) in adapters.iter().enumerate() {
            let at = list + index as u64 * ADAPTERINFO_SIZE;
            kmt_write_u32(memory, at, 0)?;
            kmt_write_u32(memory, at + 4, adapter.luid.LowPart)?;
            kmt_write_u32(memory, at + 8, adapter.luid.HighPart as u32)?;
            kmt_write_u32(memory, at + 12, 1)?;
            kmt_write_u32(memory, at + 16, 0)?;
        }
        kmt_write_u32(memory, info, count)
    }

    fn d3d8thk_open_adapter_from_luid(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let luid = Luid {
            LowPart: kmt_read_u32(memory, info)?,
            HighPart: kmt_read_u32(memory, info + 4)? as i32,
        };
        let handle = kmt_facade(wddm().d3dkmt_open_adapter_from_luid(luid))?;
        if let Err(status) = kmt_write_u32(memory, info + 8, handle.0) {
            let _ = wddm().d3dkmt_close_adapter(handle);
            return Err(status);
        }
        Ok(())
    }

    fn d3d8thk_open_adapter_from_hdc(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        if kmt_read_pointer(memory, info, arch)? == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let adapter = wddm()
            .d3dkmt_enum_adapters()
            .into_iter()
            .next()
            .ok_or(STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER)?;
        let handle = kmt_facade(wddm().d3dkmt_open_adapter_from_luid(adapter.luid))?;
        let at = info + arch.pointer_bytes() as u64;
        let written = kmt_write_u32(memory, at, handle.0).and_then(|()| {
            kmt_write_u32(memory, at + 4, adapter.luid.LowPart)?;
            kmt_write_u32(memory, at + 8, adapter.luid.HighPart as u32)?;
            kmt_write_u32(memory, at + 12, 0)
        });
        if let Err(status) = written {
            let _ = wddm().d3dkmt_close_adapter(handle);
            return Err(status);
        }
        Ok(())
    }

    fn d3d8thk_close_adapter(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let handle = AdapterHandle(kmt_read_u32(memory, info)?);
        kmt_facade(wddm().d3dkmt_close_adapter(handle))
    }

    fn d3d8thk_create_device(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let arch = self.guest_arch;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let flags = kmt_read_u32(memory, info + arch.pointer_bytes() as u64)?;
        let handle = kmt_facade(wddm().d3dkmt_create_device(CreateDeviceRequest {
            adapter,
            shareable: flags & CREATEDEVICE_FLAG_SHAREABLE != 0,
            owner_process: u64::from(self.guest_pid),
        }))?;
        if let Err(status) = kmt_write_u32(memory, info + arch.pointer_bytes() as u64 + 4, handle.0)
        {
            let _ = wddm().d3dkmt_destroy_device(handle);
            return Err(status);
        }
        Ok(())
    }

    fn d3d8thk_open_device(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let opened =
            kmt_facade(wddm().d3dkmt_open_device(DeviceHandle(kmt_read_u32(memory, info)?)))?;
        kmt_write_u32(memory, info + 4, opened.0)
    }

    fn d3d8thk_destroy_device(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        kmt_facade(wddm().d3dkmt_destroy_device(DeviceHandle(kmt_read_u32(memory, info)?)))
    }

    fn d3d8thk_query_adapter_info(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let query_type = kmt_read_u32(memory, info + 4)?;
        let data = kmt_read_pointer(memory, info + 8, arch)?;
        let size = kmt_read_u32(memory, info + 8 + arch.pointer_bytes() as u64)?;
        if data == 0 || size == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let snapshot = kmt_facade(wddm().d3dkmt_query_adapter_info(adapter))?;
        match query_type {
            KMTQAITYPE_GETSEGMENTSIZE => {
                if size < 24 {
                    return Err(STATUS_BUFFER_TOO_SMALL);
                }
                let mut bytes = [0_u8; 24];
                let local = snapshot
                    .segments
                    .first()
                    .map(|segment| segment.budget)
                    .unwrap_or(0);
                let non_local = snapshot
                    .segments
                    .get(1)
                    .map(|segment| segment.budget)
                    .unwrap_or(0);
                bytes[0..8].copy_from_slice(&local.to_le_bytes());
                bytes[8..16].copy_from_slice(&non_local.to_le_bytes());
                kmt_write_bytes(memory, data, &bytes)
            }
            KMTQAITYPE_ADAPTERGUID => {
                if size < 16 {
                    return Err(STATUS_BUFFER_TOO_SMALL);
                }
                let mut bytes = [0_u8; 16];
                bytes[0..4].copy_from_slice(&snapshot.luid.LowPart.to_le_bytes());
                bytes[4..8].copy_from_slice(&(snapshot.luid.HighPart as u32).to_le_bytes());
                bytes[8..16].copy_from_slice(&snapshot.registry_id.to_le_bytes());
                kmt_write_bytes(memory, data, &bytes)
            }
            KMTQAITYPE_ADAPTERADDRESS => {
                if size < 12 {
                    return Err(STATUS_BUFFER_TOO_SMALL);
                }
                kmt_write_bytes(memory, data, &[0_u8; 12])
            }
            KMTQAITYPE_ADAPTERREGISTRYINFO => {
                if size < REGISTRY_INFO_SIZE {
                    return Err(STATUS_BUFFER_TOO_SMALL);
                }
                let mut bytes = vec![0_u8; REGISTRY_INFO_SIZE as usize];
                kmt_encode_fixed_utf16(&mut bytes, 0, &snapshot.name);
                kmt_encode_fixed_utf16(&mut bytes, 520, "Casa1");
                kmt_encode_fixed_utf16(&mut bytes, 1040, "Metal");
                kmt_encode_fixed_utf16(&mut bytes, 1560, &snapshot.metal_family);
                kmt_write_bytes(memory, data, &bytes)
            }
            KMTQAITYPE_DRIVERVERSION => {
                if size < 4 {
                    return Err(STATUS_BUFFER_TOO_SMALL);
                }
                kmt_write_u32(memory, data, 1200)
            }
            KMTQAITYPE_ADAPTERTYPE => {
                if size < 4 {
                    return Err(STATUS_BUFFER_TOO_SMALL);
                }
                kmt_write_u32(memory, data, 0x3)
            }
            _ => Err(STATUS_NOT_SUPPORTED),
        }
    }

    fn d3d8thk_open_adapter_from_name(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
        gdi: bool,
    ) -> KmtResult<()> {
        let descriptor = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let units = if gdi {
            GDI_DISPLAY_NAME_UNITS
        } else {
            DEVICE_NAME_UNITS
        };
        let name = match kmt_read_inline_wide(memory, descriptor, units) {
            Some(name) if !name.is_empty() => name,
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        let handle = if gdi {
            kmt_facade(wddm().d3dkmt_open_adapter_from_display_name(&name))?
        } else {
            kmt_facade(wddm().d3dkmt_open_adapter_from_device_name(&name))?
        };
        let snapshot = kmt_facade(wddm().d3dkmt_query_adapter_info(handle))?;
        let out = descriptor + (units * 2) as u64;
        let written = kmt_write_u32(memory, out, handle.0).and_then(|()| {
            kmt_write_u32(memory, out + 4, snapshot.luid.LowPart)?;
            kmt_write_u32(memory, out + 8, snapshot.luid.HighPart as u32)?;
            kmt_write_u32(memory, out + 12, 0)
        });
        if let Err(status) = written {
            let _ = wddm().d3dkmt_close_adapter(handle);
            return Err(status);
        }
        Ok(())
    }

    fn d3d8thk_create_context(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let node_ordinal = kmt_read_u32(memory, info + 4)?;
        let priority = kmt_read_u32(memory, info + 8)?;
        let context = kmt_facade(wddm().d3dkmt_create_context(CreateContextRequest {
            device,
            node_ordinal,
            priority,
        }))?;
        if let Err(status) = kmt_write_u32(memory, info + 12, context.0) {
            let _ = wddm().d3dkmt_destroy_context(context);
            return Err(status);
        }
        Ok(())
    }

    fn d3d8thk_destroy_context(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        kmt_facade(
            wddm()
                .d3dkmt_destroy_context_on(device, ContextHandle(kmt_read_u32(memory, info + 4)?)),
        )
    }

    fn d3d8thk_render(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let context = ContextHandle(kmt_read_u32(memory, info + 4)?);
        let list = kmt_read_pointer(memory, info + 8, arch)?;
        let count = kmt_read_u32(memory, info + 8 + ps)?;
        if list == 0 || count == 0 || count as usize > MAX_KMT_ARRAY {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut allocations = Vec::with_capacity(count as usize);
        for index in 0..u64::from(count) {
            allocations.push(AllocationHandle(kmt_read_u32(memory, list + index * 4)?));
        }
        let fill_value = kmt_read_u32(memory, info + 12 + ps)? as u8;
        let fence_handle = kmt_read_u32(memory, info + 16 + ps)?;
        let fence_value = kmt_read_u64(memory, info + kmt_align8(24 + ps))?;
        let fence = (fence_handle != 0).then_some((SyncObjectHandle(fence_handle), fence_value));
        let rendered = kmt_facade(wddm().d3dkmt_render(RenderRequest {
            device,
            context,
            allocations,
            fill_value,
            fence,
        }))?;
        kmt_write_u64(memory, info + 32 + ps, rendered.bytes_filled)?;
        kmt_write_u64(memory, info + 40 + ps, rendered.fence_value)?;
        kmt_write_u32(memory, info + 48 + ps, rendered.effective_priority)?;
        kmt_write_u64(memory, info + 56 + ps, rendered.context_id)
    }

    fn d3d8thk_open_resource(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
        second: bool,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let resource = AllocationHandle(kmt_read_u32(memory, info + 4)?);
        kmt_facade(wddm().device_info(device))?;
        if second {
            let data = kmt_read_pointer(memory, info + 16, arch)?;
            let size = kmt_read_u32(memory, info + 16 + arch.pointer_bytes() as u64)?;
            if (data == 0) != (size == 0) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let opened = kmt_facade(wddm().d3dkmt_open_resource2(device, resource))?;
            if let Err(status) = kmt_write_u32(memory, info + 8, opened.0) {
                let _ = wddm().d3dkmt_destroy_allocation(opened);
                return Err(status);
            }
            return Ok(());
        }
        let opened = kmt_facade(wddm().d3dkmt_open_resource(device, resource))?;
        if let Err(status) = kmt_write_u32(memory, info + 8, opened.0) {
            let _ = wddm().d3dkmt_destroy_allocation(opened);
            return Err(status);
        }
        Ok(())
    }

    fn d3d8thk_open_keyed_mutex(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
        second: bool,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let resource = AllocationHandle(kmt_read_u32(memory, info + 4)?);
        let key = kmt_read_u64(memory, info + 8)?;
        kmt_facade(wddm().device_info(device))?;
        if second {
            let data = kmt_read_pointer(memory, info + 24, arch)?;
            let size = kmt_read_u32(memory, info + 24 + arch.pointer_bytes() as u64)?;
            if (data == 0) != (size == 0) {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }
        let opened = if second {
            kmt_facade(wddm().d3dkmt_open_keyed_mutex2(device, resource, key))?
        } else {
            kmt_facade(wddm().d3dkmt_open_keyed_mutex(device, resource, key))?
        };
        if let Err(status) = kmt_write_u32(memory, info + 16, opened.0) {
            let _ = wddm().d3dkmt_destroy_keyed_mutex(opened);
            return Err(status);
        }
        Ok(())
    }

    fn d3d8thk_acquire_keyed_mutex(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let mutex = KeyedMutexHandle(kmt_read_u32(memory, info + 4)?);
        let key = kmt_read_u64(memory, info + 8)?;
        let timeout_ns = kmt_read_u64(memory, info + 16)?;
        kmt_facade(wddm().device_info(device))?;
        kmt_facade(wddm().d3dkmt_acquire_keyed_mutex(
            mutex,
            key,
            timeout_ns,
            u64::from(self.guest_pid),
        ))
    }

    fn d3d8thk_release_keyed_mutex(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let mutex = KeyedMutexHandle(kmt_read_u32(memory, info + 4)?);
        let key = kmt_read_u64(memory, info + 8)?;
        kmt_facade(wddm().device_info(device))?;
        kmt_facade(wddm().d3dkmt_release_keyed_mutex(mutex, key, u64::from(self.guest_pid)))
    }

    fn d3d8thk_destroy_synchronization_object(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let object = SyncObjectHandle(kmt_read_u32(memory, info + 4)?);
        kmt_facade(wddm().d3dkmt_destroy_synchronization_object(device, object))
    }

    fn d3d8thk_signal_synchronization_object2(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let count = kmt_read_u32(memory, info + 4)?;
        let list = kmt_read_pointer(memory, info + 8, arch)?;
        let value_at = kmt_align8(8 + ps);
        let value = kmt_read_u64(memory, info + value_at)?;
        let context_count = kmt_read_u32(memory, info + value_at + 8)?;
        let context_list = kmt_read_pointer(memory, info + kmt_align8(value_at + 12), arch)?;
        if list == 0 || count == 0 || count as usize > MAX_KMT_ARRAY {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if context_count as usize > MAX_KMT_ARRAY || (context_count != 0 && context_list == 0) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut objects = Vec::with_capacity(count as usize);
        for index in 0..u64::from(count) {
            objects.push(SyncObjectHandle(kmt_read_u32(memory, list + index * 4)?));
        }
        let mut contexts = Vec::with_capacity(context_count as usize);
        for index in 0..u64::from(context_count) {
            contexts.push(ContextHandle(kmt_read_u32(
                memory,
                context_list + index * 4,
            )?));
        }
        kmt_facade(wddm().d3dkmt_signal_synchronization_objects(device, &objects, &contexts, value))
    }

    fn d3d8thk_wait_for_synchronization_object2(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let count = kmt_read_u32(memory, info + 4)?;
        let list = kmt_read_pointer(memory, info + 8, arch)?;
        let values_at = kmt_align8(8 + ps);
        let values = kmt_read_pointer(memory, info + values_at, arch)?;
        let timeout_ns = kmt_read_u64(memory, info + kmt_align8(values_at + ps))?;
        if list == 0 || values == 0 || count == 0 || count as usize > MAX_KMT_ARRAY {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut objects = Vec::with_capacity(count as usize);
        let mut values_vec = Vec::with_capacity(count as usize);
        for index in 0..u64::from(count) {
            objects.push(SyncObjectHandle(kmt_read_u32(memory, list + index * 4)?));
            values_vec.push(kmt_read_u64(memory, values + index * 8)?);
        }
        kmt_facade(wddm().d3dkmt_wait_for_synchronization_objects(
            device,
            &objects,
            &values_vec,
            timeout_ns,
        ))
    }

    fn d3d8thk_get_display_mode_list(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let capacity = kmt_read_u32(memory, info + 4)?;
        let list = kmt_read_pointer(memory, info + 8, arch)?;
        let _flags = kmt_read_u32(memory, info + 8 + ps)?;
        let modes = kmt_facade(wddm().d3dkmt_display_modes(adapter))?;
        let required = modes.len() as u32;
        if list == 0 || capacity < required {
            kmt_write_u32(memory, info + 4, required)?;
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        for (index, mode) in modes.iter().enumerate() {
            let at = list + index as u64 * DISPLAY_MODE_SIZE;
            kmt_write_u32(memory, at, mode.width)?;
            kmt_write_u32(memory, at + 4, mode.height)?;
            kmt_write_u32(memory, at + 8, mode.refresh_numerator)?;
            kmt_write_u32(memory, at + 12, mode.refresh_denominator)?;
            kmt_write_u32(memory, at + 16, 0)?;
        }
        kmt_write_u32(memory, info + 4, required)
    }

    fn d3d8thk_get_display_mode_list2(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let source = kmt_read_u32(memory, info + 4)?;
        let capacity = kmt_read_u32(memory, info + 8)?;
        let list = kmt_read_pointer(memory, info + 16, arch)?;
        let _flags = kmt_read_u32(memory, info + 16 + ps)?;
        let modes = kmt_facade(wddm().d3dkmt_source_display_modes(adapter, source))?;
        let required = modes.len() as u32;
        if list == 0 || capacity < required {
            kmt_write_u32(memory, info + 8, required)?;
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        for (index, mode) in modes.iter().enumerate() {
            let at = list + index as u64 * DISPLAY_MODE_SIZE;
            kmt_write_u32(memory, at, mode.width)?;
            kmt_write_u32(memory, at + 4, mode.height)?;
            kmt_write_u32(memory, at + 8, mode.refresh_numerator)?;
            kmt_write_u32(memory, at + 12, mode.refresh_denominator)?;
            kmt_write_u32(memory, at + 16, 0)?;
        }
        kmt_write_u32(memory, info + 8, required)
    }

    fn d3d8thk_enum_outputs(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let capacity = kmt_read_u32(memory, info + 4)?;
        let list = kmt_read_pointer(memory, info + 8, arch)?;
        let _flags = kmt_read_u32(memory, info + 8 + ps)?;
        let outputs = kmt_facade(wddm().d3dkmt_enum_outputs(adapter))?;
        let required = outputs.len() as u32;
        if list == 0 {
            if capacity != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            return kmt_write_u32(memory, info + 4, required);
        }
        if capacity < required {
            kmt_write_u32(memory, info + 4, required)?;
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        for (index, output) in outputs.iter().enumerate() {
            let at = list + index as u64 * OUTPUT_ENTRY_SIZE;
            kmt_write_u32(memory, at, output.output_id)?;
            kmt_write_u32(memory, at + 4, output.vidpn_source_id)?;
            kmt_write_u32(memory, at + 8, output.vidpn_target_id)?;
            kmt_write_u32(memory, at + 12, output.dpi_x)?;
            kmt_write_u32(memory, at + 16, output.dpi_y)?;
            kmt_write_u32(memory, at + 20, output.modes.len() as u32)?;
        }
        kmt_write_u32(memory, info + 4, required)
    }

    fn d3d8thk_set_gamma_ramp(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let output = kmt_read_u32(memory, info + 4)?;
        let ramp_type = kmt_read_u32(memory, info + 8)?;
        let entries = kmt_read_u32(memory, info + 12)?;
        let ramp = kmt_read_pointer(memory, info + 16, arch)?;
        let _pad = kmt_read_u32(memory, info + 16 + ps)?;
        if ramp_type == GAMMA_RAMP_TYPE_RAMP {
            if entries as usize != GAMMA_RAMP_ENTRIES {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if ramp == 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let mut red = Vec::with_capacity(GAMMA_RAMP_ENTRIES);
            let mut green = Vec::with_capacity(GAMMA_RAMP_ENTRIES);
            let mut blue = Vec::with_capacity(GAMMA_RAMP_ENTRIES);
            for index in 0..GAMMA_RAMP_ENTRIES as u64 {
                red.push(
                    read_guest_u16(memory, ramp + index * 2).map_err(|_| kmt_invalid_pointer())?,
                );
                green.push(
                    read_guest_u16(memory, ramp + GAMMA_RAMP_ENTRIES as u64 * 2 + index * 2)
                        .map_err(|_| kmt_invalid_pointer())?,
                );
                blue.push(
                    read_guest_u16(memory, ramp + GAMMA_RAMP_ENTRIES as u64 * 4 + index * 2)
                        .map_err(|_| kmt_invalid_pointer())?,
                );
            }
            kmt_facade(
                wddm().d3dkmt_set_gamma_ramp(adapter, output, ramp_type, &red, &green, &blue),
            )
        } else {
            if entries != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            kmt_facade(wddm().d3dkmt_set_gamma_ramp(adapter, output, ramp_type, &[], &[], &[]))
        }
    }

    fn d3d8thk_get_gamma_ramp(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let output = kmt_read_u32(memory, info + 4)?;
        let ramp_type = kmt_read_u32(memory, info + 8)?;
        let capacity = kmt_read_u32(memory, info + 12)?;
        let ramp = kmt_read_pointer(memory, info + 16, arch)?;
        let _pad = kmt_read_u32(memory, info + 16 + ps)?;
        let stored = kmt_facade(wddm().d3dkmt_get_gamma_ramp(adapter, output))?;
        if ramp_type == 0 {
            return kmt_write_u32(memory, info + 12, 0);
        }
        if ramp_type != GAMMA_RAMP_TYPE_RAMP {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if capacity as usize != GAMMA_RAMP_ENTRIES {
            kmt_write_u32(memory, info + 12, GAMMA_RAMP_ENTRIES as u32)?;
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        if ramp == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for (index, value) in stored.red.iter().enumerate() {
            write_guest_u16(memory, ramp + index as u64 * 2, *value)
                .map_err(|_| kmt_invalid_pointer())?;
        }
        for (index, value) in stored.green.iter().enumerate() {
            write_guest_u16(
                memory,
                ramp + GAMMA_RAMP_ENTRIES as u64 * 2 + index as u64 * 2,
                *value,
            )
            .map_err(|_| kmt_invalid_pointer())?;
        }
        for (index, value) in stored.blue.iter().enumerate() {
            write_guest_u16(
                memory,
                ramp + GAMMA_RAMP_ENTRIES as u64 * 4 + index as u64 * 2,
                *value,
            )
            .map_err(|_| kmt_invalid_pointer())?;
        }
        kmt_write_u32(memory, info + 12, GAMMA_RAMP_ENTRIES as u32)
    }

    fn d3d8thk_set_cursor_position(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let output = kmt_read_u32(memory, info + 4)?;
        let x = kmt_read_u32(memory, info + 8)? as i32;
        let y = kmt_read_u32(memory, info + 12)? as i32;
        kmt_facade(wddm().d3dkmt_set_cursor_position(adapter, output, x, y))
    }

    fn d3d8thk_set_cursor(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let output = kmt_read_u32(memory, info + 4)?;
        let visible = kmt_read_u32(memory, info + 8)? != 0;
        let width = kmt_read_u32(memory, info + 12)?;
        let height = kmt_read_u32(memory, info + 16)?;
        let hot_x = kmt_read_u32(memory, info + 20)?;
        let hot_y = kmt_read_u32(memory, info + 24)?;
        let pixels_ptr = kmt_read_pointer(memory, info + 32, arch)?;
        let _pad = kmt_read_u32(memory, info + 32 + ps)?;
        let count = u64::from(width) * u64::from(height);
        if count > 0 && pixels_ptr == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut pixels = Vec::new();
        if count > 0 {
            pixels.reserve(count as usize);
            for index in 0..count {
                pixels.push(
                    read_guest_u32(memory, pixels_ptr + index * 4)
                        .map_err(|_| kmt_invalid_pointer())?,
                );
            }
        }
        kmt_facade(wddm().d3dkmt_set_cursor(
            adapter, output, visible, width, height, hot_x, hot_y, &pixels,
        ))
    }

    fn d3d8thk_pnp_start(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        kmt_facade(wddm().d3dkmt_pnp_start(adapter))
    }

    fn d3d8thk_pnp_stop(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        kmt_facade(wddm().d3dkmt_pnp_stop(adapter))
    }

    fn d3d8thk_power_component(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let component = kmt_read_u32(memory, info + 4)?;
        let power_state = kmt_read_u32(memory, info + 8)?;
        kmt_facade(wddm().d3dkmt_power_component(adapter, component, power_state))
    }

    fn d3d8thk_set_allocation_priority(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let count = kmt_read_u32(memory, info + 4)?;
        let list = kmt_read_pointer(memory, info + 8, arch)?;
        let priority = kmt_read_u32(memory, info + 8 + ps)?;
        if list == 0 || count == 0 || count as usize > MAX_KMT_ARRAY {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if priority > MAX_SCHEDULING_PRIORITY {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut allocations = Vec::with_capacity(count as usize);
        for index in 0..u64::from(count) {
            allocations.push(AllocationHandle(kmt_read_u32(memory, list + index * 4)?));
        }
        kmt_facade(wddm().d3dkmt_set_allocation_priority(device, &allocations, priority))
    }

    fn d3d8thk_set_display_private_driver_format(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info)?);
        let source = kmt_read_u32(memory, info + 4)?;
        let attribute = kmt_read_u32(memory, info + 8)?;
        kmt_facade(wddm().d3dkmt_set_display_private_driver_format(adapter, source, attribute))
    }

    fn d3d8thk_create_allocation(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let resource_id = u64::from(kmt_read_u32(memory, info + 4)?);
        let allocation_info = kmt_read_pointer(memory, info + 8, arch)?;
        let allocation_count = kmt_read_u32(memory, info + 8 + arch.pointer_bytes() as u64)?;
        let flags = kmt_read_u32(memory, info + 12 + arch.pointer_bytes() as u64)?;
        if allocation_info == 0
            || allocation_count == 0
            || allocation_count as usize > MAX_KMT_ARRAY
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut allocations = Vec::with_capacity(allocation_count as usize);
        for index in 0..u64::from(allocation_count) {
            let entry = allocation_info + index * 24;
            allocations.push(AllocationDesc {
                size: kmt_read_u64(memory, entry + 8)?,
                segment: SegmentId(kmt_read_u32(memory, entry + 16)?),
            });
        }
        let handles = kmt_facade(wddm().d3dkmt_create_allocations(CreateAllocationsRequest {
            device,
            allocations,
            resource_id_base: u64::from(resource_id),
            shareable: flags & CREATEALLOCATION_FLAG_SHARED != 0,
            owner_process: u64::from(self.guest_pid),
        }))?;
        for (index, handle) in handles.iter().enumerate() {
            if let Err(status) =
                kmt_write_u32(memory, allocation_info + index as u64 * 24, handle.0)
            {
                for created in &handles {
                    let _ = wddm().d3dkmt_destroy_allocation(*created);
                }
                return Err(status);
            }
        }
        Ok(())
    }

    fn d3d8thk_destroy_allocation(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let list = kmt_read_pointer(memory, info + 8, arch)?;
        let count = kmt_read_u32(memory, info + 8 + arch.pointer_bytes() as u64)?;
        kmt_facade(wddm().device_info(device))?;
        if list == 0 || count == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for index in 0..count {
            let handle = AllocationHandle(kmt_read_u32(memory, list + u64::from(index) * 4)?);
            kmt_facade(wddm().d3dkmt_destroy_allocation(handle))?;
        }
        Ok(())
    }

    fn d3d8thk_make_resident(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let arch = self.guest_arch;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let count = kmt_read_u32(memory, info + 4)?;
        let list = kmt_read_pointer(memory, info + 8, arch)?;
        kmt_facade(wddm().device_info(device))?;
        if list == 0 || count == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for index in 0..count {
            let handle = AllocationHandle(kmt_read_u32(memory, list + u64::from(index) * 4)?);
            kmt_facade(wddm().d3dkmt_make_resident(handle, u64::from(self.guest_pid)))?;
        }
        kmt_write_u64(memory, info + 16, 0)
    }

    fn d3d8thk_evict(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let arch = self.guest_arch;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let count = kmt_read_u32(memory, info + 4)?;
        let list = kmt_read_pointer(memory, info + 8, arch)?;
        let _flags = kmt_read_u32(memory, info + 16)?;
        kmt_facade(wddm().device_info(device))?;
        if list == 0 || count == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for index in 0..count {
            let handle = AllocationHandle(kmt_read_u32(memory, list + u64::from(index) * 4)?);
            kmt_facade(wddm().d3dkmt_evict(handle, u64::from(self.guest_pid)))?;
        }
        kmt_write_u64(memory, info + 24, 0)
    }

    fn d3d8thk_query_allocation_residency(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let arch = self.guest_arch;
        let ps = arch.pointer_bytes() as u64;
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let list = kmt_read_pointer(memory, info + 8, arch)?;
        let count = kmt_read_u32(memory, info + 8 + ps)?;
        let status_list = kmt_read_pointer(memory, info + kmt_align8(8 + ps + 4), arch)?;
        kmt_facade(wddm().device_info(device))?;
        if list == 0 || count == 0 || status_list == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for index in 0..count {
            let handle = AllocationHandle(kmt_read_u32(memory, list + u64::from(index) * 4)?);
            let allocation = kmt_facade(wddm().allocation_info(handle))?;
            let status = if allocation.residency == 0 {
                3
            } else if allocation.segment.0 == 0 {
                1
            } else {
                2
            };
            kmt_write_u32(memory, status_list + u64::from(index) * 4, status)?;
        }
        Ok(())
    }

    fn d3d8thk_create_synchronization_object(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let object_type = kmt_read_u32(memory, info + 4)?;
        let initial_value = kmt_read_u64(memory, info + 8)?;
        kmt_facade(wddm().device_info(device))?;
        if object_type != SYNCOBJECT_TYPE_FENCE {
            return Err(STATUS_NOT_SUPPORTED);
        }
        let handle =
            kmt_facade(wddm().d3dkmt_create_synchronization_object(device, initial_value))?;
        kmt_write_u32(memory, info + 16, handle.0)
    }

    fn d3d8thk_signal_synchronization_object(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let object = SyncObjectHandle(kmt_read_u32(memory, info + 4)?);
        let value = kmt_read_u64(memory, info + 8)?;
        kmt_facade(wddm().device_info(device))?;
        kmt_facade(wddm().d3dkmt_signal_synchronization_object(object, value))
    }

    fn d3d8thk_wait_for_synchronization_object(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        let object = SyncObjectHandle(kmt_read_u32(memory, info + 4)?);
        let value = kmt_read_u64(memory, info + 8)?;
        let timeout_ns = kmt_read_u64(memory, info + 16)?;
        kmt_facade(wddm().device_info(device))?;
        kmt_facade(wddm().d3dkmt_wait_for_synchronization_object(object, value, timeout_ns))
    }

    fn d3d8thk_create_swapchain(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        kmt_facade(wddm().device_info(device))?;
        let width = kmt_read_u32(memory, info + 4)?;
        let height = kmt_read_u32(memory, info + 8)?;
        let raw_format = kmt_read_u32(memory, info + 12)?;
        let buffer_count = kmt_read_u32(memory, info + 16)?;
        let _flags = kmt_read_u32(memory, info + 20)?;
        let format = DxgiFormat::from_u32_checked(raw_format)
            .map_err(|_| STATUS_GRAPHICS_INVALID_PIXELFORMAT)?;
        let handle = kmt_facade(wddm().d3dkmt_create_swapchain(CreateSwapChainRequest {
            device,
            width,
            height,
            format,
            buffer_count,
        }))?;
        if let Err(status) = kmt_write_u32(memory, info + 24, handle.0) {
            let _ = wddm().d3dkmt_destroy_swapchain(handle);
            return Err(status);
        }
        Ok(())
    }

    fn d3d8thk_present(&self, state: &CpuState, memory: &mut MemoryImage) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let device = DeviceHandle(kmt_read_u32(memory, info)?);
        kmt_facade(wddm().device_info(device))?;
        let swapchain = SwapChainHandle(kmt_read_u32(memory, info + 4)?);
        let sync_interval = kmt_read_u32(memory, info + 8)?;
        let flags = kmt_read_u32(memory, info + 12)?;
        let presented = kmt_facade(wddm().d3dkmt_present(PresentRequest {
            swapchain,
            sync_interval,
            allow_tearing: flags & PRESENT_FLAG_ALLOW_TEARING != 0,
        }))?;
        kmt_write_u64(memory, info + 16, presented.present_count)?;
        kmt_write_u64(memory, info + 24, presented.refresh_count)?;
        kmt_write_u32(memory, info + 32, presented.flip_index)?;
        kmt_write_u64(memory, info + 40, presented.displayed_frame_index)?;
        kmt_write_u64(memory, info + 48, presented.frame_time_ns)
    }

    fn d3d8thk_query_swapchain_info(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let swapchain = SwapChainHandle(kmt_read_u32(memory, info)?);
        let snapshot = kmt_facade(wddm().d3dkmt_query_swapchain_info(swapchain))?;
        kmt_write_u32(memory, info + 8, snapshot.width)?;
        kmt_write_u32(memory, info + 12, snapshot.height)?;
        kmt_write_u32(memory, info + 16, snapshot.buffer_count)?;
        kmt_write_u32(memory, info + 20, snapshot.flip_index)?;
        kmt_write_u64(memory, info + 24, snapshot.present_count)?;
        kmt_write_u64(memory, info + 32, snapshot.refresh_count)
    }

    fn d3d8thk_destroy_swapchain(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let handle = SwapChainHandle(kmt_read_u32(memory, info)?);
        kmt_facade(wddm().d3dkmt_destroy_swapchain(handle))
    }

    fn d3d8thk_query_statistics(
        &self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> KmtResult<()> {
        let info = guest_call_arg(state, memory, 0).map_err(|_| kmt_invalid_pointer())?;
        let size = kmt_read_u32(memory, info)?;
        if size != STATISTICS_SIZE && size != STATISTICS_EXTENDED_SIZE {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let query_type = kmt_read_u32(memory, info + 4)?;
        let adapter = AdapterHandle(kmt_read_u32(memory, info + 8)?);
        let node_ordinal = kmt_read_u32(memory, info + 12)?;
        let extended = size == STATISTICS_EXTENDED_SIZE;
        if !extended
            && matches!(
                query_type,
                D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT
                    | D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT2
                    | D3DKMT_QUERYSTATISTICS_PROCESS_NODE
                    | D3DKMT_QUERYSTATISTICS_PROCESS_NODE2
                    | D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP
                    | D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP2
            )
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let (process_id, segment_id, segment_group, counters_at) = if extended {
            (
                kmt_read_u64(memory, info + 16)?,
                kmt_read_u32(memory, info + 24)?,
                kmt_read_u32(memory, info + 28)?,
                32_u64,
            )
        } else {
            (u64::from(node_ordinal), node_ordinal, node_ordinal, 16_u64)
        };
        let sub_object = match query_type {
            D3DKMT_QUERYSTATISTICS_SEGMENT
            | D3DKMT_QUERYSTATISTICS_SEGMENT2
            | D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT
            | D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT2 => segment_id,
            D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP
            | D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP2 => segment_group,
            _ => node_ordinal,
        };
        let snapshot = kmt_facade(
            wddm().d3dkmt_query_statistics_typed(adapter, query_type, process_id, sub_object),
        )?;
        let counters = match snapshot {
            WddmStatisticsSnapshot::Adapter(statistics) => [
                statistics.present_count,
                statistics.refresh_count,
                statistics.flip_count,
                statistics.allocation_count,
                statistics.allocated_bytes,
                statistics.resident_count,
                statistics.resident_bytes,
                statistics.signal_count,
                statistics.wait_count,
                statistics.timeout_count,
                statistics.last_frame_time_ns,
                statistics.last_displayed_frame_index,
                statistics.context_count,
            ],
            WddmStatisticsSnapshot::Process(statistics) => [
                statistics.process_id,
                statistics.allocation_count,
                statistics.allocated_bytes,
                statistics.committed_bytes,
                statistics.resident_count,
                statistics.resident_bytes,
                statistics.context_count,
                statistics.render_count,
                statistics.render_bytes,
                u64::from(statistics.segment_id),
                u64::from(statistics.node_ordinal),
                statistics.segment_budget,
                statistics.segment_used,
            ],
            WddmStatisticsSnapshot::Segment(statistics) => [
                u64::from(statistics.segment_id),
                statistics.budget,
                statistics.used,
                statistics.allocation_count,
                statistics.allocated_bytes,
                statistics.committed_bytes,
                statistics.resident_count,
                statistics.resident_bytes,
                0,
                0,
                0,
                0,
                0,
            ],
            WddmStatisticsSnapshot::Node(statistics) => [
                statistics.render_count,
                statistics.render_bytes,
                statistics.context_count,
                u64::from(statistics.node_ordinal),
                statistics.allocation_count,
                statistics.allocated_bytes,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        };
        let mut bytes = [0_u8; 104];
        for (index, counter) in counters.iter().enumerate() {
            let at = index * 8;
            bytes[at..at + 8].copy_from_slice(&counter.to_le_bytes());
        }
        kmt_write_bytes(memory, info + counters_at, &bytes)
    }
}

fn kmt_facade<T>(result: crate::wddm::WddmResult<T>) -> KmtResult<T> {
    result.map_err(|error| error.status())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    const SCRATCH: u64 = 0x10_000;
    const SCRATCH_SIZE: usize = 0x30_000;

    fn test_runtime(arch: GuestArch) -> (PeHostRuntime, TempDir) {
        let directory = TempDir::new().expect("temp dir");
        let environment =
            GameEnvironment::create_in(directory.path(), "d3d8thk-kmt", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(environment, true, Vec::new(), None, None);
        runtime.set_guest_arch(arch);
        (runtime, directory)
    }

    fn with_big_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(body)
            .expect("spawn big-stack thread")
            .join()
            .expect("big-stack thread panicked")
    }

    fn map_scratch(memory: &mut MemoryImage) {
        memory.map_bytes(SCRATCH, &vec![0_u8; SCRATCH_SIZE]);
    }

    fn dispatch_x86(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thunk: u64,
        args: &[u32],
    ) -> u64 {
        let stack = 0x50_000;
        memory.map_bytes(stack, &[0_u8; 0x200]);
        write_guest_u32(memory, stack, 0xDEAD_BEEF).expect("return address");
        for (index, arg) in args.iter().enumerate() {
            write_guest_u32(memory, stack + 4 + index as u64 * 4, *arg).expect("x86 argument");
        }
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, stack);
        runtime
            .dispatch_import(thunk, &mut state, memory)
            .expect("dispatch x86 thunk");
        state.get(Register::Rax)
    }

    fn dispatch_x64(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thunk: u64,
        args: &[u64],
    ) -> u64 {
        let stack = 0x60_000;
        memory.map_bytes(stack, &[0_u8; 0x200]);
        write_guest_u64(memory, stack, 0xDEAD_BEEF).expect("return address");
        let registers = [Register::Rcx, Register::Rdx, Register::R8, Register::R9];
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, stack);
        for (index, arg) in args.iter().enumerate() {
            if index < registers.len() {
                state.set(registers[index], *arg);
            } else {
                write_guest_u64(memory, stack + 0x20 + (index as u64 - 4) * 8, *arg)
                    .expect("x64 stack argument");
            }
        }
        runtime
            .dispatch_import(thunk, &mut state, memory)
            .expect("dispatch x64 thunk");
        state.get(Register::Rax)
    }

    fn call_thunk(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thunk: HostThunk,
        args: &[u64],
    ) -> u64 {
        let address = runtime.alloc_host_thunk(thunk);
        if runtime.guest_arch == GuestArch::X86 {
            let args32 = args.iter().map(|arg| *arg as u32).collect::<Vec<_>>();
            dispatch_x86(runtime, memory, address, &args32)
        } else {
            dispatch_x64(runtime, memory, address, args)
        }
    }

    fn call_status(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thunk: HostThunk,
        args: &[u64],
    ) -> u32 {
        call_thunk(runtime, memory, thunk, args) as u32
    }

    fn store_u32(memory: &mut MemoryImage, address: u64, value: u32) {
        write_guest_u32(memory, address, value).expect("guest u32 write");
    }

    fn store_u64(memory: &mut MemoryImage, address: u64, value: u64) {
        write_guest_u64(memory, address, value).expect("guest u64 write");
    }

    fn store_ptr(memory: &mut MemoryImage, address: u64, value: u64, arch: GuestArch) {
        write_guest_pointer(memory, address, value, arch).expect("guest pointer write");
    }

    fn store_wide(memory: &mut MemoryImage, address: u64, value: &str) {
        for (index, unit) in value.encode_utf16().chain(std::iter::once(0)).enumerate() {
            write_guest_u16(memory, address + index as u64 * 2, unit).expect("guest wide write");
        }
    }

    fn load_u32(memory: &MemoryImage, address: u64) -> u32 {
        read_guest_u32(memory, address).expect("guest u32 read")
    }

    fn load_u64(memory: &MemoryImage, address: u64) -> u64 {
        read_guest_u64(memory, address).expect("guest u64 read")
    }

    fn pointer_size(runtime: &PeHostRuntime) -> u64 {
        runtime.guest_arch.pointer_bytes() as u64
    }

    fn open_adapter(runtime: &mut PeHostRuntime, memory: &mut MemoryImage) -> u32 {
        let arch = runtime.guest_arch;
        let ps = pointer_size(runtime);
        let info = SCRATCH + 0x100;
        let list = SCRATCH + 0x200;
        store_u32(memory, info, 1);
        store_ptr(memory, info + ps, list, arch);
        assert_eq!(
            call_status(runtime, memory, HostThunk::D3DKMTEnumAdapters, &[info]),
            0
        );
        assert_eq!(load_u32(memory, info), 1, "one host adapter");
        let open = SCRATCH + 0x300;
        store_u32(memory, open, load_u32(memory, list + 4));
        store_u32(memory, open + 4, load_u32(memory, list + 8));
        assert_eq!(
            call_status(
                runtime,
                memory,
                HostThunk::D3DKMTOpenAdapterFromLuid,
                &[open]
            ),
            0
        );
        let adapter = load_u32(memory, open + 8);
        assert_ne!(adapter, 0, "open adapter returns a handle");
        adapter
    }

    fn create_device(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        adapter: u32,
        shareable: bool,
    ) -> u32 {
        let ps = pointer_size(runtime);
        let info = SCRATCH + 0x400;
        store_u32(memory, info, adapter);
        store_u32(
            memory,
            info + ps,
            if shareable {
                CREATEDEVICE_FLAG_SHAREABLE
            } else {
                0
            },
        );
        assert_eq!(
            call_status(runtime, memory, HostThunk::D3DKMTCreateDevice, &[info]),
            0
        );
        let device = load_u32(memory, info + ps + 4);
        assert_ne!(device, 0, "create device returns a handle");
        device
    }

    fn allocation_descriptor(
        runtime: &PeHostRuntime,
        memory: &mut MemoryImage,
        device: u32,
        resource_id: u32,
        size: u64,
        segment: u32,
        flags: u32,
        count: u32,
    ) -> u64 {
        let ps = pointer_size(runtime);
        let info = SCRATCH + 0x600;
        let descriptor = SCRATCH + 0x500;
        store_u32(memory, descriptor, device);
        store_u32(memory, descriptor + 4, resource_id);
        store_ptr(memory, descriptor + 8, info, runtime.guest_arch);
        store_u32(memory, descriptor + 8 + ps, count);
        store_u32(memory, descriptor + 12 + ps, flags);
        store_u64(memory, info + 8, size);
        store_u32(memory, info + 16, segment);
        descriptor
    }

    fn create_allocation(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device: u32,
        resource_id: u32,
        size: u64,
        segment: u32,
        shareable: bool,
    ) -> u32 {
        let descriptor = allocation_descriptor(
            runtime,
            memory,
            device,
            resource_id,
            size,
            segment,
            if shareable {
                CREATEALLOCATION_FLAG_SHARED
            } else {
                0
            },
            1,
        );
        assert_eq!(
            call_status(
                runtime,
                memory,
                HostThunk::D3DKMTCreateAllocation,
                &[descriptor]
            ),
            0
        );
        let handle = load_u32(memory, SCRATCH + 0x600);
        assert_ne!(handle, 0, "create allocation returns a handle");
        handle
    }

    fn residency_descriptor(
        runtime: &PeHostRuntime,
        memory: &mut MemoryImage,
        device: u32,
        allocations: &[u32],
    ) -> u64 {
        let list = SCRATCH + 0x700;
        let descriptor = SCRATCH + 0x780;
        for (index, allocation) in allocations.iter().enumerate() {
            store_u32(memory, list + index as u64 * 4, *allocation);
        }
        store_u32(memory, descriptor, device);
        store_u32(memory, descriptor + 4, allocations.len() as u32);
        store_ptr(memory, descriptor + 8, list, runtime.guest_arch);
        store_u32(memory, descriptor + 16, 0);
        store_u64(memory, descriptor + 24, 0);
        descriptor
    }

    fn residency_query_descriptor(
        runtime: &PeHostRuntime,
        memory: &mut MemoryImage,
        device: u32,
        allocations: &[u32],
    ) -> u64 {
        let ps = pointer_size(runtime);
        let list = SCRATCH + 0x800;
        let statuses = SCRATCH + 0x880;
        let descriptor = SCRATCH + 0x900;
        for (index, allocation) in allocations.iter().enumerate() {
            store_u32(memory, list + index as u64 * 4, *allocation);
        }
        store_u32(memory, descriptor, device);
        store_u32(memory, descriptor + 4, 0);
        store_ptr(memory, descriptor + 8, list, runtime.guest_arch);
        store_u32(memory, descriptor + 8 + ps, allocations.len() as u32);
        store_ptr(
            memory,
            descriptor + kmt_align8(8 + ps + 4),
            statuses,
            runtime.guest_arch,
        );
        descriptor
    }

    fn destroy_allocation_descriptor(
        runtime: &PeHostRuntime,
        memory: &mut MemoryImage,
        device: u32,
        allocations: &[u32],
    ) -> u64 {
        let ps = pointer_size(runtime);
        let list = SCRATCH + 0xA00;
        let descriptor = SCRATCH + 0xA80;
        for (index, allocation) in allocations.iter().enumerate() {
            store_u32(memory, list + index as u64 * 4, *allocation);
        }
        store_u32(memory, descriptor, device);
        store_u32(memory, descriptor + 4, 0);
        store_ptr(memory, descriptor + 8, list, runtime.guest_arch);
        store_u32(memory, descriptor + 8 + ps, allocations.len() as u32);
        descriptor
    }

    fn create_fence(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device: u32,
        initial_value: u64,
    ) -> u32 {
        let info = SCRATCH + 0xB00;
        store_u32(memory, info, device);
        store_u32(memory, info + 4, SYNCOBJECT_TYPE_FENCE);
        store_u64(memory, info + 8, initial_value);
        assert_eq!(
            call_status(
                runtime,
                memory,
                HostThunk::D3DKMTCreateSynchronizationObject,
                &[info]
            ),
            0
        );
        let handle = load_u32(memory, info + 16);
        assert_ne!(handle, 0, "create fence returns a handle");
        handle
    }

    fn signal_descriptor(memory: &mut MemoryImage, device: u32, fence: u32, value: u64) -> u64 {
        let info = SCRATCH + 0xB80;
        store_u32(memory, info, device);
        store_u32(memory, info + 4, fence);
        store_u64(memory, info + 8, value);
        info
    }

    fn wait_descriptor(
        memory: &mut MemoryImage,
        device: u32,
        fence: u32,
        value: u64,
        timeout_ns: u64,
    ) -> u64 {
        let info = SCRATCH + 0xC00;
        store_u32(memory, info, device);
        store_u32(memory, info + 4, fence);
        store_u64(memory, info + 8, value);
        store_u64(memory, info + 16, timeout_ns);
        info
    }

    fn swapchain_descriptor(
        memory: &mut MemoryImage,
        device: u32,
        width: u32,
        height: u32,
        format: u32,
        buffer_count: u32,
    ) -> u64 {
        let descriptor = SCRATCH + 0xC80;
        store_u32(memory, descriptor, device);
        store_u32(memory, descriptor + 4, width);
        store_u32(memory, descriptor + 8, height);
        store_u32(memory, descriptor + 12, format);
        store_u32(memory, descriptor + 16, buffer_count);
        store_u32(memory, descriptor + 20, 0);
        descriptor
    }

    fn create_swapchain(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device: u32,
        width: u32,
        height: u32,
        buffer_count: u32,
    ) -> u32 {
        let descriptor = swapchain_descriptor(memory, device, width, height, 87, buffer_count);
        assert_eq!(
            call_status(
                runtime,
                memory,
                HostThunk::D3DKMTCreateSwapChain,
                &[descriptor]
            ),
            0
        );
        let handle = load_u32(memory, descriptor + 24);
        assert_ne!(handle, 0, "create swapchain returns a handle");
        handle
    }

    fn present_descriptor(
        memory: &mut MemoryImage,
        device: u32,
        swapchain: u32,
        sync_interval: u32,
        flags: u32,
    ) -> u64 {
        let descriptor = SCRATCH + 0xD00;
        store_u32(memory, descriptor, device);
        store_u32(memory, descriptor + 4, swapchain);
        store_u32(memory, descriptor + 8, sync_interval);
        store_u32(memory, descriptor + 12, flags);
        descriptor
    }

    fn statistics_descriptor(
        memory: &mut MemoryImage,
        size: u32,
        query_type: u32,
        adapter: u32,
        node_ordinal: u32,
        process_id: u64,
        segment_id: u32,
    ) -> u64 {
        let info = SCRATCH + 0x2000;
        store_u32(memory, info, size);
        store_u32(memory, info + 4, query_type);
        store_u32(memory, info + 8, adapter);
        store_u32(memory, info + 12, node_ordinal);
        if size == STATISTICS_EXTENDED_SIZE {
            store_u64(memory, info + 16, process_id);
            store_u32(memory, info + 24, segment_id);
            store_u32(memory, info + 28, 0);
        }
        info
    }

    fn gamma_ramp_descriptor(
        memory: &mut MemoryImage,
        adapter: u32,
        output: u32,
        ramp_type: u32,
        entries: u32,
        ramp: u64,
    ) -> u64 {
        let info = SCRATCH + 0x2600;
        store_u32(memory, info, adapter);
        store_u32(memory, info + 4, output);
        store_u32(memory, info + 8, ramp_type);
        store_u32(memory, info + 12, entries);
        store_ptr(memory, info + 16, ramp, GuestArch::X86);
        store_u32(memory, info + 20, 0);
        info
    }

    fn load_ramp_channel(memory: &MemoryImage, base: u64, channel: u64) -> u16 {
        read_guest_u16(memory, base + channel * GAMMA_RAMP_ENTRIES as u64 * 2)
            .expect("gamma ramp entry")
    }

    #[test]
    fn d3d8thk_luid_open_rejects_unknown_and_closed_adapter_handles() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let ps = pointer_size(&runtime);

            let open = SCRATCH + 0x300;
            store_u32(&mut memory, open, 0xDEAD_BEEF);
            store_u32(&mut memory, open + 4, 0x0BAD_F00D);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromLuid,
                    &[open]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );

            let adapter = open_adapter(&mut runtime, &mut memory);
            let snapshot = wddm().d3dkmt_enum_adapters().into_iter().next().unwrap();

            let query = SCRATCH + 0x340;
            let data = SCRATCH + 0x380;
            store_u32(&mut memory, query, adapter);
            store_u32(&mut memory, query + 4, KMTQAITYPE_ADAPTERADDRESS);
            store_ptr(&mut memory, query + 8, data, GuestArch::X86);
            store_u32(&mut memory, query + 8 + ps, 12);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                0
            );
            assert_eq!(load_u32(&memory, data), 0, "bus number");

            store_u32(&mut memory, query + 4, KMTQAITYPE_ADAPTERGUID);
            store_u32(&mut memory, query + 8 + ps, 16);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                0
            );
            assert_eq!(load_u32(&memory, data), snapshot.luid.LowPart);
            assert_eq!(load_u32(&memory, data + 4), snapshot.luid.HighPart as u32);

            store_u32(&mut memory, query + 4, KMTQAITYPE_GETSEGMENTSIZE);
            store_u32(&mut memory, query + 8 + ps, 24);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                0
            );
            assert_eq!(load_u64(&memory, data), snapshot.segments[0].budget);

            store_u32(&mut memory, query + 4, KMTQAITYPE_ADAPTERREGISTRYINFO);
            store_u32(&mut memory, query + 8 + ps, REGISTRY_INFO_SIZE);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                0
            );
            let first_unit = snapshot.name.encode_utf16().next().unwrap_or(0);
            assert_eq!(
                read_guest_u16(&memory, data).expect("adapter registry string"),
                first_unit
            );

            store_u32(&mut memory, query + 4, KMTQAITYPE_DRIVERVERSION);
            store_u32(&mut memory, query + 8 + ps, 4);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                0
            );
            assert_eq!(load_u32(&memory, data), 1200);

            store_u32(&mut memory, query + 4, KMTQAITYPE_ADAPTERTYPE);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                0
            );
            assert_eq!(load_u32(&memory, data), 0x3);

            let close = SCRATCH + 0x3C0;
            store_u32(&mut memory, close, adapter);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCloseAdapter,
                    &[close]
                ),
                0
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCloseAdapter,
                    &[close]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );

            let device = SCRATCH + 0x400;
            store_u32(&mut memory, device, adapter);
            store_u32(&mut memory, device + ps, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateDevice,
                    &[device]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );
        });
    }

    #[test]
    fn d3d8thk_enum_adapters_rejects_null_and_short_buffers() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let ps = pointer_size(&runtime);
            let info = SCRATCH + 0x100;
            let list = SCRATCH + 0x200;

            store_u32(&mut memory, info, 0);
            store_ptr(&mut memory, info + ps, 0, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumAdapters,
                    &[info]
                ),
                0
            );
            let count = load_u32(&memory, info);
            assert_ne!(count, 0, "host exposes at least one adapter");

            store_u32(&mut memory, info, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumAdapters,
                    &[info]
                ),
                STATUS_INVALID_PARAMETER
            );

            store_u32(&mut memory, info, 0);
            store_ptr(&mut memory, info + ps, list, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumAdapters,
                    &[info]
                ),
                STATUS_BUFFER_TOO_SMALL
            );
            assert_eq!(load_u32(&memory, info), count, "required count written");

            let short = 0x90_000;
            memory.map_bytes(short, &[0_u8; 8]);
            store_u32(&mut memory, info, 1);
            store_ptr(&mut memory, info + ps, short, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumAdapters,
                    &[info]
                ),
                STATUS_INVALID_PARAMETER
            );

            store_u32(&mut memory, info, count);
            store_ptr(&mut memory, info + ps, list, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumAdapters,
                    &[info]
                ),
                0
            );
            assert_eq!(load_u32(&memory, info), count);
            let snapshot = wddm().d3dkmt_enum_adapters().into_iter().next().unwrap();
            assert_eq!(load_u32(&memory, list + 4), snapshot.luid.LowPart);
            assert_eq!(load_u32(&memory, list + 12), 1, "one VidPn source");
        });
    }

    #[test]
    fn d3d8thk_device_open_rejects_private_and_stale_handles() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let ps = pointer_size(&runtime);

            let create = SCRATCH + 0x400;
            store_u32(&mut memory, create, 0xDEAD);
            store_u32(&mut memory, create + ps, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateDevice,
                    &[create]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );

            let private = create_device(&mut runtime, &mut memory, adapter, false);
            let open = SCRATCH + 0x440;
            store_u32(&mut memory, open, private);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenDevice,
                    &[open]
                ),
                STATUS_ACCESS_DENIED
            );
            store_u32(&mut memory, open, 0xFFFF_FFFF);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenDevice,
                    &[open]
                ),
                STATUS_INVALID_HANDLE
            );

            let shared = create_device(&mut runtime, &mut memory, adapter, true);
            store_u32(&mut memory, open, shared);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenDevice,
                    &[open]
                ),
                0
            );
            let second = load_u32(&memory, open + 4);
            assert_ne!(second, shared, "open device creates a second handle");

            let destroy = SCRATCH + 0x480;
            store_u32(&mut memory, destroy, shared);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[destroy]
                ),
                0
            );
            let allocation =
                create_allocation(&mut runtime, &mut memory, second, 9, 4096, 0, false);
            assert_ne!(
                allocation, 0,
                "object survives until its last handle closes"
            );

            store_u32(&mut memory, destroy, second);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[destroy]
                ),
                0
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[destroy]
                ),
                STATUS_INVALID_HANDLE
            );
            let descriptor =
                allocation_descriptor(&runtime, &mut memory, second, 10, 4096, 0, 0, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateAllocation,
                    &[descriptor]
                ),
                STATUS_INVALID_HANDLE
            );

            store_u32(&mut memory, destroy, private);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[destroy]
                ),
                0
            );
            let close = SCRATCH + 0x4C0;
            store_u32(&mut memory, close, adapter);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCloseAdapter,
                    &[close]
                ),
                0
            );
            store_u32(&mut memory, create, adapter);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateDevice,
                    &[create]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );
        });
    }

    #[test]
    fn d3d8thk_allocation_residency_rejects_budget_overrun_and_double_destroy() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let ps = pointer_size(&runtime);
            let device = create_device(&mut runtime, &mut memory, adapter, false);

            let query = SCRATCH + 0x340;
            let data = SCRATCH + 0x380;
            store_u32(&mut memory, query, adapter);
            store_u32(&mut memory, query + 4, KMTQAITYPE_GETSEGMENTSIZE);
            store_ptr(&mut memory, query + 8, data, GuestArch::X86);
            store_u32(&mut memory, query + 8 + ps, 24);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                0
            );
            let budget = load_u64(&memory, data);

            let oversized = create_allocation(
                &mut runtime,
                &mut memory,
                device,
                1,
                budget.saturating_add(1),
                0,
                false,
            );
            let resident = residency_descriptor(&runtime, &mut memory, device, &[oversized]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTMakeResident,
                    &[resident]
                ),
                STATUS_GRAPHICS_NO_VIDEO_MEMORY
            );

            let allocation =
                create_allocation(&mut runtime, &mut memory, device, 42, 4096, 0, true);
            let duplicate = allocation_descriptor(&runtime, &mut memory, device, 42, 1, 1, 0, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateAllocation,
                    &[duplicate]
                ),
                STATUS_OBJECT_NAME_COLLISION
            );
            let zero_size = allocation_descriptor(&runtime, &mut memory, device, 43, 0, 0, 0, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateAllocation,
                    &[zero_size]
                ),
                STATUS_INVALID_PARAMETER
            );
            let bad_segment = allocation_descriptor(&runtime, &mut memory, device, 44, 1, 9, 0, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateAllocation,
                    &[bad_segment]
                ),
                STATUS_INVALID_PARAMETER
            );
            let no_allocations =
                allocation_descriptor(&runtime, &mut memory, device, 45, 1, 0, 0, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateAllocation,
                    &[no_allocations]
                ),
                STATUS_INVALID_PARAMETER
            );

            let resident = residency_descriptor(&runtime, &mut memory, device, &[allocation]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTMakeResident,
                    &[resident]
                ),
                0
            );
            assert_eq!(load_u64(&memory, resident + 16), 0, "trim budget");
            let statuses = residency_query_descriptor(&runtime, &mut memory, device, &[allocation]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAllocationResidency,
                    &[statuses]
                ),
                0
            );
            assert_eq!(
                load_u32(&memory, SCRATCH + 0x880),
                1,
                "resident in GPU memory"
            );

            let evict = residency_descriptor(&runtime, &mut memory, device, &[allocation]);
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTEvict, &[evict]),
                0
            );
            assert_eq!(load_u64(&memory, evict + 24), 0, "trim budget");
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTEvict, &[evict]),
                STATUS_GRAPHICS_ALLOCATION_BUSY
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAllocationResidency,
                    &[statuses]
                ),
                0
            );
            assert_eq!(load_u32(&memory, SCRATCH + 0x880), 3, "fully evicted");

            let destroy =
                destroy_allocation_descriptor(&runtime, &mut memory, device, &[allocation]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyAllocation,
                    &[destroy]
                ),
                0
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyAllocation,
                    &[destroy]
                ),
                STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTMakeResident,
                    &[resident]
                ),
                STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
            );
            let empty = destroy_allocation_descriptor(&runtime, &mut memory, device, &[]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyAllocation,
                    &[empty]
                ),
                STATUS_INVALID_PARAMETER
            );
            let invalid_device =
                residency_descriptor(&runtime, &mut memory, 0xFFFF_FFFF, &[oversized]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTMakeResident,
                    &[invalid_device]
                ),
                STATUS_INVALID_HANDLE
            );

            let non_local = create_allocation(&mut runtime, &mut memory, device, 50, 1, 1, false);
            let resident = residency_descriptor(&runtime, &mut memory, device, &[non_local]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTMakeResident,
                    &[resident]
                ),
                0
            );
            let statuses = residency_query_descriptor(&runtime, &mut memory, device, &[non_local]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAllocationResidency,
                    &[statuses]
                ),
                0
            );
            assert_eq!(
                load_u32(&memory, SCRATCH + 0x880),
                2,
                "resident in shared memory"
            );
            let cleanup =
                destroy_allocation_descriptor(&runtime, &mut memory, device, &[non_local]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyAllocation,
                    &[cleanup]
                ),
                0
            );

            let cleanup =
                destroy_allocation_descriptor(&runtime, &mut memory, device, &[oversized]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyAllocation,
                    &[cleanup]
                ),
                0
            );
        });
    }

    #[test]
    fn d3d8thk_sync_wait_rejects_backwards_signal_and_times_out_exactly_once() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let device = create_device(&mut runtime, &mut memory, adapter, false);

            let descriptor = SCRATCH + 0xB00;
            store_u32(&mut memory, descriptor, 0xFFFF_FFFF);
            store_u32(&mut memory, descriptor + 4, SYNCOBJECT_TYPE_FENCE);
            store_u64(&mut memory, descriptor + 8, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateSynchronizationObject,
                    &[descriptor]
                ),
                STATUS_INVALID_HANDLE
            );
            store_u32(&mut memory, descriptor, device);
            store_u32(&mut memory, descriptor + 4, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateSynchronizationObject,
                    &[descriptor]
                ),
                STATUS_NOT_SUPPORTED
            );

            let fence = create_fence(&mut runtime, &mut memory, device, 0);
            let signal = signal_descriptor(&mut memory, device, 0xFFFF_FFFF, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject,
                    &[signal]
                ),
                STATUS_INVALID_HANDLE
            );
            let wait = wait_descriptor(&mut memory, device, fence, 1, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait]
                ),
                STATUS_TIMEOUT
            );
            let started = Instant::now();
            let wait_short = wait_descriptor(&mut memory, device, fence, 1, 10_000_000);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait_short]
                ),
                STATUS_TIMEOUT
            );
            assert!(started.elapsed() >= Duration::from_millis(5));

            let signal = signal_descriptor(&mut memory, device, fence, 2);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject,
                    &[signal]
                ),
                0
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject,
                    &[signal]
                ),
                STATUS_INVALID_PARAMETER,
                "fence values must increase"
            );
            let wait = wait_descriptor(&mut memory, device, fence, 1, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait]
                ),
                0
            );

            let signal_value = 3;
            let signal_thread = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                wddm()
                    .d3dkmt_signal_synchronization_object(SyncObjectHandle(fence), signal_value)
                    .expect("signal from waiter thread")
            });
            let wait = wait_descriptor(&mut memory, device, fence, signal_value, 2_000_000_000);
            let started = Instant::now();
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait]
                ),
                0
            );
            assert!(started.elapsed() < Duration::from_secs(1));
            assert_eq!(signal_thread.join().expect("signal thread"), ());
            let wait = wait_descriptor(&mut memory, device, fence, signal_value, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait]
                ),
                0,
                "signalled state persists until the next signal"
            );
            let wait = wait_descriptor(&mut memory, device, fence, signal_value + 1, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait]
                ),
                STATUS_TIMEOUT
            );
        });
    }

    #[test]
    fn d3d8thk_present_rejects_invalid_and_closed_swapchains_and_advances_flip() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let device = create_device(&mut runtime, &mut memory, adapter, false);

            let invalid_device = swapchain_descriptor(&mut memory, 0xFFFF_FFFF, 8, 8, 87, 2);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateSwapChain,
                    &[invalid_device]
                ),
                STATUS_INVALID_HANDLE
            );
            let zero_width = swapchain_descriptor(&mut memory, device, 0, 8, 87, 2);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateSwapChain,
                    &[zero_width]
                ),
                STATUS_INVALID_PARAMETER
            );
            let short_chain = swapchain_descriptor(&mut memory, device, 8, 8, 87, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateSwapChain,
                    &[short_chain]
                ),
                STATUS_INVALID_PARAMETER
            );
            let bad_format = swapchain_descriptor(&mut memory, device, 8, 8, 9999, 2);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateSwapChain,
                    &[bad_format]
                ),
                STATUS_GRAPHICS_INVALID_PIXELFORMAT
            );

            let swapchain = create_swapchain(&mut runtime, &mut memory, device, 8, 8, 3);
            let present = present_descriptor(&mut memory, 0xFFFF_FFFF, swapchain, 0, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPresent,
                    &[present]
                ),
                STATUS_INVALID_HANDLE
            );
            let present = present_descriptor(&mut memory, device, 0xFFFF_FFFF, 0, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPresent,
                    &[present]
                ),
                STATUS_GRAPHICS_PRESENT_INVALID_WINDOW
            );
            let present = present_descriptor(&mut memory, device, swapchain, 5, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPresent,
                    &[present]
                ),
                STATUS_INVALID_PARAMETER
            );

            let present = present_descriptor(
                &mut memory,
                device,
                swapchain,
                0,
                PRESENT_FLAG_ALLOW_TEARING,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPresent,
                    &[present]
                ),
                0
            );
            assert_eq!(load_u64(&memory, present + 16), 1);
            assert_eq!(load_u64(&memory, present + 24), 1);
            assert_eq!(load_u32(&memory, present + 32), 1);
            let present = present_descriptor(&mut memory, device, swapchain, 2, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPresent,
                    &[present]
                ),
                0
            );
            assert_eq!(load_u64(&memory, present + 16), 2);
            assert_eq!(load_u64(&memory, present + 24), 3);
            assert_eq!(load_u32(&memory, present + 32), 2);

            let query = SCRATCH + 0xD80;
            store_u32(&mut memory, query, swapchain);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQuerySwapChainInfo,
                    &[query]
                ),
                0
            );
            assert_eq!(load_u32(&memory, query + 8), 8);
            assert_eq!(load_u32(&memory, query + 12), 8);
            assert_eq!(load_u32(&memory, query + 16), 3);
            assert_eq!(load_u32(&memory, query + 20), 2);
            assert_eq!(load_u64(&memory, query + 24), 2);
            assert_eq!(load_u64(&memory, query + 32), 3);

            let destroy = SCRATCH + 0xDC0;
            store_u32(&mut memory, destroy, swapchain);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroySwapchain,
                    &[destroy]
                ),
                0
            );
            let present = present_descriptor(&mut memory, device, swapchain, 0, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPresent,
                    &[present]
                ),
                STATUS_GRAPHICS_PRESENT_INVALID_WINDOW
            );
            let query = SCRATCH + 0xD80;
            store_u32(&mut memory, query, swapchain);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQuerySwapChainInfo,
                    &[query]
                ),
                STATUS_GRAPHICS_PRESENT_INVALID_WINDOW
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroySwapchain,
                    &[destroy]
                ),
                STATUS_INVALID_HANDLE
            );

            let survivor = create_swapchain(&mut runtime, &mut memory, device, 4, 4, 2);
            let device_info = SCRATCH + 0x480;
            store_u32(&mut memory, device_info, device);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[device_info]
                ),
                0
            );
            let present = present_descriptor(&mut memory, device, survivor, 0, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPresent,
                    &[present]
                ),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroySwapchain,
                    &[SCRATCH + 0xDC0]
                ),
                STATUS_INVALID_HANDLE
            );
        });
    }

    #[test]
    fn d3d8thk_descriptors_reject_null_and_unmapped_guest_pointers() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let ps = pointer_size(&runtime);
            let device = create_device(&mut runtime, &mut memory, adapter, false);

            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromLuid,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromHdc,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumAdapters,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateDevice,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateAllocation,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyAllocation,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTMakeResident,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTEvict, &[0]),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAllocationResidency,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateSynchronizationObject,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateSwapChain,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTPresent, &[0]),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQuerySwapChainInfo,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroySwapchain,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[0]
                ),
                STATUS_INVALID_PARAMETER
            );

            let query = SCRATCH + 0x340;
            let data = SCRATCH + 0x380;
            store_u32(&mut memory, query, adapter);
            store_u32(&mut memory, query + 4, KMTQAITYPE_ADAPTERADDRESS);
            store_ptr(&mut memory, query + 8, 0, GuestArch::X86);
            store_u32(&mut memory, query + 8 + ps, 12);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_ptr(&mut memory, query + 8, data, GuestArch::X86);
            store_u32(&mut memory, query + 8 + ps, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                STATUS_INVALID_PARAMETER
            );

            let short = 0x91_000;
            memory.map_bytes(short, &[0_u8; 8]);
            store_u32(&mut memory, query + 4, KMTQAITYPE_GETSEGMENTSIZE);
            store_ptr(&mut memory, query + 8, short, GuestArch::X86);
            store_u32(&mut memory, query + 8 + ps, 24);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, query + 4, KMTQAITYPE_ADAPTERREGISTRYINFO);
            store_u32(&mut memory, query + 8 + ps, 4);
            store_ptr(&mut memory, query + 8, data, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                STATUS_BUFFER_TOO_SMALL
            );

            let statistics = SCRATCH + 0xE00;
            store_u32(&mut memory, statistics, 8);
            store_u32(&mut memory, statistics + 4, D3DKMT_QUERYSTATISTICS_ADAPTER);
            store_u32(&mut memory, statistics + 8, adapter);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[statistics]
                ),
                STATUS_INVALID_PARAMETER
            );
            let short_statistics = 0x92_000;
            memory.map_bytes(short_statistics, &[0_u8; 16]);
            store_u32(&mut memory, short_statistics, STATISTICS_SIZE);
            store_u32(
                &mut memory,
                short_statistics + 4,
                D3DKMT_QUERYSTATISTICS_ADAPTER,
            );
            store_u32(&mut memory, short_statistics + 8, adapter);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[short_statistics]
                ),
                STATUS_INVALID_PARAMETER
            );
            let statistics = SCRATCH + 0xE00;
            store_u32(&mut memory, statistics, STATISTICS_SIZE);
            store_u32(&mut memory, statistics + 4, D3DKMT_QUERYSTATISTICS_ADAPTER);
            store_u32(&mut memory, statistics + 8, adapter);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[statistics]
                ),
                0
            );

            for (query_type, size) in [
                (KMTQAITYPE_GETSEGMENTSIZE, 23),
                (KMTQAITYPE_ADAPTERGUID, 15),
                (KMTQAITYPE_ADAPTERADDRESS, 11),
                (KMTQAITYPE_ADAPTERREGISTRYINFO, 4),
                (KMTQAITYPE_DRIVERVERSION, 3),
                (KMTQAITYPE_ADAPTERTYPE, 3),
            ] {
                store_u32(&mut memory, query + 4, query_type);
                store_ptr(&mut memory, query + 8, data, GuestArch::X86);
                store_u32(&mut memory, query + 8 + ps, size);
                assert_eq!(
                    call_status(
                        &mut runtime,
                        &mut memory,
                        HostThunk::D3DKMTQueryAdapterInfo,
                        &[query]
                    ),
                    STATUS_BUFFER_TOO_SMALL
                );
            }

            let luid_partial = 0x93_000;
            memory.map_bytes(luid_partial, &[0_u8; 8]);
            let snapshot = wddm().d3dkmt_enum_adapters().into_iter().next().unwrap();
            store_u32(&mut memory, luid_partial, snapshot.luid.LowPart);
            store_u32(&mut memory, luid_partial + 4, snapshot.luid.HighPart as u32);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromLuid,
                    &[luid_partial]
                ),
                STATUS_INVALID_PARAMETER
            );

            let hdc_partial = 0x94_000;
            memory.map_bytes(hdc_partial, &[0_u8; 4]);
            store_ptr(&mut memory, hdc_partial, 0x1234, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromHdc,
                    &[hdc_partial]
                ),
                STATUS_INVALID_PARAMETER
            );

            let device_partial = 0x95_000;
            memory.map_bytes(device_partial, &[0_u8; 8]);
            store_u32(&mut memory, device_partial, adapter);
            store_u32(&mut memory, device_partial + 4, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateDevice,
                    &[device_partial]
                ),
                STATUS_INVALID_PARAMETER
            );

            let allocation_partial = 0x97_000;
            let allocation_info = 0x96_000;
            memory.map_bytes(allocation_partial, &[0_u8; 20]);
            memory.map_bytes(allocation_info + 8, &[0_u8; 16]);
            store_u32(&mut memory, allocation_partial, device);
            store_u32(&mut memory, allocation_partial + 4, 60);
            store_ptr(
                &mut memory,
                allocation_partial + 8,
                allocation_info,
                GuestArch::X86,
            );
            store_u32(&mut memory, allocation_partial + 12, 1);
            store_u32(&mut memory, allocation_partial + 16, 0);
            store_u64(&mut memory, allocation_info + 8, 4096);
            store_u32(&mut memory, allocation_info + 16, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateAllocation,
                    &[allocation_partial]
                ),
                STATUS_INVALID_PARAMETER
            );

            let swapchain_partial = 0x98_000;
            memory.map_bytes(swapchain_partial, &[0_u8; 24]);
            store_u32(&mut memory, swapchain_partial, device);
            store_u32(&mut memory, swapchain_partial + 4, 8);
            store_u32(&mut memory, swapchain_partial + 8, 8);
            store_u32(&mut memory, swapchain_partial + 12, 87);
            store_u32(&mut memory, swapchain_partial + 16, 2);
            store_u32(&mut memory, swapchain_partial + 20, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateSwapChain,
                    &[swapchain_partial]
                ),
                STATUS_INVALID_PARAMETER
            );

            let residency = SCRATCH + 0xF00;
            store_u32(&mut memory, residency, device);
            store_u32(&mut memory, residency + 4, 1);
            store_ptr(&mut memory, residency + 8, 0, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTMakeResident,
                    &[residency]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, residency + 16, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEvict,
                    &[residency]
                ),
                STATUS_INVALID_PARAMETER
            );
            let residency_query = SCRATCH + 0xF20;
            store_u32(&mut memory, residency_query, device);
            store_ptr(&mut memory, residency_query + 8, 0, GuestArch::X86);
            store_u32(&mut memory, residency_query + 12, 1);
            store_ptr(
                &mut memory,
                residency_query + 16,
                SCRATCH + 0xF80,
                GuestArch::X86,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAllocationResidency,
                    &[residency_query]
                ),
                STATUS_INVALID_PARAMETER
            );

            let hdc = SCRATCH + 0xE80;
            store_ptr(&mut memory, hdc, 0, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromHdc,
                    &[hdc]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_ptr(&mut memory, hdc, 0x1234, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromHdc,
                    &[hdc]
                ),
                0
            );
            assert_ne!(load_u32(&memory, hdc + 4), 0, "hAdapter at pointer width");
            let snapshot = wddm().d3dkmt_enum_adapters().into_iter().next().unwrap();
            assert_eq!(load_u32(&memory, hdc + 8), snapshot.luid.LowPart, "LUID");
            let opened = load_u32(&memory, hdc + 4);
            let close = SCRATCH + 0xEC0;
            store_u32(&mut memory, close, opened);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCloseAdapter,
                    &[close]
                ),
                STATUS_GRAPHICS_ALLOCATION_BUSY
            );
            let destroy = SCRATCH + 0xEC8;
            store_u32(&mut memory, destroy, device);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[destroy]
                ),
                0
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCloseAdapter,
                    &[close]
                ),
                0
            );
            store_u32(&mut memory, close, adapter);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCloseAdapter,
                    &[close]
                ),
                0
            );
        });
    }

    #[test]
    fn d3d8thk_unknown_kmt_types_and_unimplemented_thunks_return_exact_status() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let ps = pointer_size(&runtime);

            let query = SCRATCH + 0x340;
            let data = SCRATCH + 0x380;
            store_u32(&mut memory, query, adapter);
            store_u32(&mut memory, query + 4, 0xFFFF);
            store_ptr(&mut memory, query + 8, data, GuestArch::X86);
            store_u32(&mut memory, query + 8 + ps, 4);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                STATUS_NOT_SUPPORTED
            );

            for thunk in [
                HostThunk::D3DKMTGetDisplayModeList,
                HostThunk::D3DKMTRender,
                HostThunk::D3DKMTSetAllocationPriority,
                HostThunk::D3DKMTOpenResource,
                HostThunk::D3DKMTOpenResource2,
                HostThunk::D3DKMTOpenKeyedMutex,
                HostThunk::D3DKMTOpenKeyedMutex2,
                HostThunk::D3DKMTSetDisplayPrivateDriverFormat,
                HostThunk::D3DKMTCreateContext,
                HostThunk::D3DKMTDestroyContext,
                HostThunk::D3DKMTOpenAdapterFromGdiDisplayName,
                HostThunk::D3DKMTOpenAdapterFromDeviceName,
                HostThunk::D3DKMTDestroySynchronizationObject,
                HostThunk::D3DKMTSignalSynchronizationObject2,
                HostThunk::D3DKMTWaitForSynchronizationObject2,
                HostThunk::D3DKMTAcquireKeyedMutex,
                HostThunk::D3DKMTReleaseKeyedMutex,
            ] {
                assert_eq!(
                    call_status(&mut runtime, &mut memory, thunk, &[0]),
                    STATUS_INVALID_PARAMETER
                );
            }

            for name in [
                "D3DKMTCreateSwapChain",
                "D3DKMTDestroyAllocation",
                "D3DKMTDestroySwapchain",
                "D3DKMTEvict",
                "D3DKMTMakeResident",
                "D3DKMTOpenAdapterFromLuid",
                "D3DKMTOpenAdapterFromGdiDisplayName",
                "D3DKMTOpenAdapterFromDeviceName",
                "D3DKMTOpenDevice",
                "D3DKMTQueryStatistics",
                "D3DKMTQuerySwapChainInfo",
                "D3DKMTSignalSynchronizationObject",
                "D3DKMTSignalSynchronizationObject2",
                "D3DKMTWaitForSynchronizationObject",
                "D3DKMTWaitForSynchronizationObject2",
                "D3DKMTDestroySynchronizationObject",
                "D3DKMTOpenResource2",
                "D3DKMTOpenKeyedMutex2",
                "D3DKMTAcquireKeyedMutex",
                "D3DKMTAcquireKeyedMutex2",
                "D3DKMTReleaseKeyedMutex",
                "D3DKMTReleaseKeyedMutex2",
            ] {
                let symbol = ImportSymbol::ByName {
                    hint: 0,
                    name: name.to_string(),
                };
                assert!(
                    is_import_supported("d3d8thk.dll", &symbol),
                    "import table wires {name}"
                );
            }
            let unknown = ImportSymbol::ByName {
                hint: 0,
                name: "D3DKMTNotAThunk".to_string(),
            };
            assert!(!is_import_supported("d3d8thk.dll", &unknown));

            let mut state = CpuState::new(GuestArch::X86);
            state.set(Register::Rsp, 0);
            let error = runtime
                .dispatch_d3d8thk(&HostThunk::CreateFileW, &mut state, &mut memory)
                .unwrap_err();
            assert_eq!(error.code, ReasonCode::RcUnimplInsn);
            assert_eq!(error.message, "unrouted D3D8-kernel thunk CreateFileW");
        });
    }

    #[test]
    fn d3d8thk_x64_descriptors_reject_bad_luid_and_round_trip_handles() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X64);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let ps = pointer_size(&runtime);
            assert_eq!(ps, 8);

            let info = SCRATCH + 0x100;
            store_u32(&mut memory, info, 0);
            store_ptr(&mut memory, info + ps, 0, GuestArch::X64);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumAdapters,
                    &[info]
                ),
                0
            );
            assert_eq!(load_u32(&memory, info), 1);

            let open = SCRATCH + 0x300;
            store_u32(&mut memory, open, 1);
            store_u32(&mut memory, open + 4, 2);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromLuid,
                    &[open]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );

            let adapter = open_adapter(&mut runtime, &mut memory);
            let device = create_device(&mut runtime, &mut memory, adapter, true);
            let open_device = SCRATCH + 0x440;
            store_u32(&mut memory, open_device, device);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenDevice,
                    &[open_device]
                ),
                0
            );
            let second = load_u32(&memory, open_device + 4);
            assert_ne!(second, device);

            let query = SCRATCH + 0x340;
            let data = SCRATCH + 0x380;
            store_u32(&mut memory, query, adapter);
            store_u32(&mut memory, query + 4, KMTQAITYPE_GETSEGMENTSIZE);
            store_ptr(&mut memory, query + 8, data, GuestArch::X64);
            store_u32(&mut memory, query + 8 + ps, 24);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryAdapterInfo,
                    &[query]
                ),
                0
            );
            assert_ne!(load_u64(&memory, data), 0, "x64 segment budget");

            let allocation =
                create_allocation(&mut runtime, &mut memory, second, 77, 4096, 0, true);
            let resident = residency_descriptor(&runtime, &mut memory, second, &[allocation]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTMakeResident,
                    &[resident]
                ),
                0
            );

            let swapchain = create_swapchain(&mut runtime, &mut memory, second, 8, 8, 2);
            let present = present_descriptor(&mut memory, second, swapchain, 0, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPresent,
                    &[present]
                ),
                0
            );
            assert_eq!(load_u64(&memory, present + 16), 1);
            assert_eq!(load_u32(&memory, present + 32), 1);

            let statistics = SCRATCH + 0xE00;
            store_u32(&mut memory, statistics, STATISTICS_SIZE);
            store_u32(&mut memory, statistics + 4, D3DKMT_QUERYSTATISTICS_ADAPTER);
            store_u32(&mut memory, statistics + 8, adapter);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[statistics]
                ),
                0
            );
            assert!(
                load_u64(&memory, statistics + 16 + 24) >= 1,
                "live allocation count"
            );

            let destroy = SCRATCH + 0x480;
            store_u32(&mut memory, destroy, second);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[destroy]
                ),
                0
            );
            store_u32(&mut memory, destroy, device);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[destroy]
                ),
                0
            );
            let close = SCRATCH + 0x4C0;
            store_u32(&mut memory, close, adapter);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCloseAdapter,
                    &[close]
                ),
                0
            );
        });
    }

    #[test]
    fn d3d8thk_context_render_modes_priority_and_statistics_errors_are_exact() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let ps = pointer_size(&runtime);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let device = create_device(&mut runtime, &mut memory, adapter, false);
            let other = create_device(&mut runtime, &mut memory, adapter, false);
            let allocation = create_allocation(&mut runtime, &mut memory, device, 1, 4096, 0, true);

            let gdi = SCRATCH + 0x1900;
            store_wide(&mut memory, gdi, "\\\\.\\DISPLAY9");
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromGdiDisplayName,
                    &[gdi]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );
            store_wide(&mut memory, gdi, "\\\\.\\DISPLAY1");
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromGdiDisplayName,
                    &[gdi]
                ),
                0
            );
            let gdi_adapter = load_u32(&memory, gdi + 64);
            assert_ne!(gdi_adapter, 0);
            let device_name = SCRATCH + 0x1A00;
            let snapshot = wddm().d3dkmt_enum_adapters().into_iter().next().unwrap();
            store_wide(&mut memory, device_name, &snapshot.name);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromDeviceName,
                    &[device_name]
                ),
                0
            );
            let named_adapter = load_u32(&memory, device_name + 520);
            assert_ne!(named_adapter, 0);
            let empty_name = SCRATCH + 0x1D80;
            store_wide(&mut memory, empty_name, "");
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromGdiDisplayName,
                    &[empty_name]
                ),
                STATUS_INVALID_PARAMETER
            );
            let unterminated = SCRATCH + 0x1E00;
            for index in 0..DEVICE_NAME_UNITS {
                write_guest_u16(&mut memory, unterminated + index as u64 * 2, 0x41)
                    .expect("unterminated name");
            }
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromDeviceName,
                    &[unterminated]
                ),
                STATUS_INVALID_PARAMETER
            );

            let array_info = SCRATCH + 0x1B00;
            store_u64(&mut memory, array_info + 8, 64);
            store_u32(&mut memory, array_info + 16, 0);
            store_u64(&mut memory, array_info + 24 + 8, 128);
            store_u32(&mut memory, array_info + 40, 1);
            let array = SCRATCH + 0x1C00;
            store_u32(&mut memory, array, device);
            store_u32(&mut memory, array + 4, 50);
            store_ptr(&mut memory, array + 8, array_info, GuestArch::X86);
            store_u32(&mut memory, array + 8 + ps, 2);
            store_u32(&mut memory, array + 12 + ps, CREATEALLOCATION_FLAG_SHARED);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateAllocation,
                    &[array]
                ),
                0
            );
            let array_first = load_u32(&memory, array_info);
            let array_second = load_u32(&memory, array_info + 24);
            assert_ne!(array_first, 0);
            assert_ne!(array_second, 0);
            assert_eq!(
                wddm()
                    .allocation_info(AllocationHandle(array_second))
                    .expect("array allocation")
                    .size,
                128
            );
            let destroy_array = destroy_allocation_descriptor(
                &runtime,
                &mut memory,
                device,
                &[array_first, array_second],
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyAllocation,
                    &[destroy_array]
                ),
                0
            );

            let context = SCRATCH + 0x1000;
            store_u32(&mut memory, context, device);
            store_u32(&mut memory, context + 4, 1);
            store_u32(&mut memory, context + 8, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateContext,
                    &[context]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, context + 4, 0);
            store_u32(&mut memory, context + 8, MAX_SCHEDULING_PRIORITY + 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateContext,
                    &[context]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, context + 8, MAX_SCHEDULING_PRIORITY);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateContext,
                    &[context]
                ),
                0
            );
            let context_handle = load_u32(&memory, context + 12);

            let list = SCRATCH + 0x1100;
            store_u32(&mut memory, list, allocation);
            let render = SCRATCH + 0x1200;
            store_u32(&mut memory, render, device);
            store_u32(&mut memory, render + 4, 0xFFFF_FFFF);
            store_ptr(&mut memory, render + 8, list, GuestArch::X86);
            store_u32(&mut memory, render + 8 + ps, 1);
            store_u32(&mut memory, render + 12 + ps, 0x41);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTRender,
                    &[render]
                ),
                STATUS_INVALID_HANDLE
            );
            store_u32(&mut memory, render + 4, context_handle);
            store_ptr(&mut memory, render + 8, 0, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTRender,
                    &[render]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_ptr(&mut memory, render + 8, list, GuestArch::X86);
            store_u32(&mut memory, render + 8 + ps, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTRender,
                    &[render]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, list, 0xFFFF_FFFF);
            store_u32(&mut memory, render + 8 + ps, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTRender,
                    &[render]
                ),
                STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
            );
            store_u32(&mut memory, list, allocation);
            store_u32(&mut memory, render + 16 + ps, 0);
            store_u64(&mut memory, render + 32, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTRender,
                    &[render]
                ),
                0
            );
            assert_eq!(load_u64(&memory, render + 32 + ps), 4096);
            assert_eq!(load_u32(&memory, render + 48 + ps), MAX_SCHEDULING_PRIORITY);

            let priority = SCRATCH + 0x1300;
            store_u32(&mut memory, priority, device);
            store_u32(&mut memory, priority + 4, 1);
            store_ptr(&mut memory, priority + 8, list, GuestArch::X86);
            store_u32(&mut memory, priority + 8 + ps, MAX_SCHEDULING_PRIORITY + 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetAllocationPriority,
                    &[priority]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, priority + 4, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetAllocationPriority,
                    &[priority]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, priority + 4, 1);
            store_u32(&mut memory, priority + 8 + ps, MAX_SCHEDULING_PRIORITY);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetAllocationPriority,
                    &[priority]
                ),
                0
            );

            let modes = SCRATCH + 0x1400;
            store_u32(&mut memory, modes, adapter);
            store_u32(&mut memory, modes + 4, 0);
            store_ptr(&mut memory, modes + 8, 0, GuestArch::X86);
            store_u32(&mut memory, modes + 8 + ps, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetDisplayModeList,
                    &[modes]
                ),
                STATUS_BUFFER_TOO_SMALL
            );
            let mode_count = load_u32(&memory, modes + 4);
            assert!(mode_count >= 1, "backend reports display modes");
            let mode_list = SCRATCH + 0x1500;
            store_u32(&mut memory, modes + 4, mode_count - 1);
            store_ptr(&mut memory, modes + 8, mode_list, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetDisplayModeList,
                    &[modes]
                ),
                STATUS_BUFFER_TOO_SMALL
            );
            store_u32(&mut memory, modes + 4, mode_count);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetDisplayModeList,
                    &[modes]
                ),
                0
            );
            assert_ne!(load_u32(&memory, mode_list), 0);
            assert_ne!(load_u32(&memory, mode_list + 4), 0);

            let format = SCRATCH + 0x1600;
            store_u32(&mut memory, format, adapter);
            store_u32(&mut memory, format + 4, u32::MAX);
            store_u32(&mut memory, format + 8, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetDisplayPrivateDriverFormat,
                    &[format]
                ),
                STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE
            );
            store_u32(&mut memory, format + 4, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetDisplayPrivateDriverFormat,
                    &[format]
                ),
                0
            );

            let statistics = SCRATCH + 0x1700;
            store_u32(&mut memory, statistics, STATISTICS_SIZE);
            store_u32(
                &mut memory,
                statistics + 4,
                D3DKMT_QUERYSTATISTICS_HISTOGRAM,
            );
            store_u32(&mut memory, statistics + 8, adapter);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[statistics]
                ),
                STATUS_NOT_SUPPORTED
            );
            store_u32(&mut memory, statistics + 4, 99);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[statistics]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, statistics + 4, D3DKMT_QUERYSTATISTICS_NODE);
            store_u32(&mut memory, statistics + 12, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[statistics]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, statistics + 12, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[statistics]
                ),
                0
            );
            assert!(load_u64(&memory, statistics + 16) >= 1, "node render count");
            store_u32(&mut memory, statistics + 4, D3DKMT_QUERYSTATISTICS_ADAPTER);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[statistics]
                ),
                0
            );
            assert!(
                load_u64(&memory, statistics + 16 + 24) >= 1,
                "live allocation count"
            );
            store_u32(&mut memory, statistics + 4, D3DKMT_QUERYSTATISTICS_ADAPTER2);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[statistics]
                ),
                0
            );
            store_u32(&mut memory, statistics, STATISTICS_SIZE - 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[statistics]
                ),
                STATUS_INVALID_PARAMETER
            );

            let fence = create_fence(&mut runtime, &mut memory, device, 0);
            let signal = SCRATCH + 0x1F00;
            let signal_list = SCRATCH + 0x1FA0;
            let context_list = SCRATCH + 0x1FC0;
            store_u32(&mut memory, signal_list, fence);
            store_u32(&mut memory, context_list, context_handle);
            store_u32(&mut memory, signal, device);
            store_u32(&mut memory, signal + 4, 1);
            store_ptr(&mut memory, signal + 8, signal_list, GuestArch::X86);
            store_u64(&mut memory, signal + 16, 9);
            store_u32(&mut memory, signal + 24, 1);
            store_ptr(&mut memory, signal + 32, context_list, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject2,
                    &[signal]
                ),
                0
            );
            let wait = SCRATCH + 0x1F80;
            store_u32(&mut memory, wait, device);
            store_u32(&mut memory, wait + 4, fence);
            store_u64(&mut memory, wait + 8, 9);
            store_u64(&mut memory, wait + 16, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait]
                ),
                0
            );

            let destroy = SCRATCH + 0x1800;
            store_u32(&mut memory, destroy, other);
            store_u32(&mut memory, destroy + 4, context_handle);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyContext,
                    &[destroy]
                ),
                STATUS_INVALID_HANDLE
            );
            store_u32(&mut memory, destroy, device);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyContext,
                    &[destroy]
                ),
                0
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyContext,
                    &[destroy]
                ),
                STATUS_INVALID_HANDLE
            );
            for handle in [device, other] {
                let destroy_device = SCRATCH + 0x1D00;
                store_u32(&mut memory, destroy_device, handle);
                assert_eq!(
                    call_status(
                        &mut runtime,
                        &mut memory,
                        HostThunk::D3DKMTDestroyDevice,
                        &[destroy_device]
                    ),
                    0
                );
            }
            let close = SCRATCH + 0x1980;
            for handle in [gdi_adapter, named_adapter] {
                store_u32(&mut memory, close, handle);
                assert_eq!(
                    call_status(
                        &mut runtime,
                        &mut memory,
                        HostThunk::D3DKMTCloseAdapter,
                        &[close]
                    ),
                    0
                );
            }
        });
    }

    #[test]
    fn d3d8thk_resource_mutex_and_sync_arrays_reject_collisions_and_timeouts() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let ps = pointer_size(&runtime);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let device = create_device(&mut runtime, &mut memory, adapter, true);
            let second = create_device(&mut runtime, &mut memory, adapter, false);
            let third = create_device(&mut runtime, &mut memory, adapter, false);
            let shared = create_allocation(&mut runtime, &mut memory, device, 1, 4096, 0, true);
            let private = create_allocation(&mut runtime, &mut memory, device, 2, 4096, 0, false);

            let open = SCRATCH + 0x2000;
            store_u32(&mut memory, open, third);
            store_u32(&mut memory, open + 4, private);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource,
                    &[open]
                ),
                STATUS_ACCESS_DENIED
            );
            store_u32(&mut memory, open + 4, shared);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource,
                    &[open]
                ),
                0
            );
            let opened = load_u32(&memory, open + 8);
            assert_ne!(opened, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource,
                    &[open]
                ),
                STATUS_OBJECT_NAME_COLLISION
            );
            let open2 = SCRATCH + 0x2040;
            store_u32(&mut memory, open2, second);
            store_u32(&mut memory, open2 + 4, shared);
            store_ptr(&mut memory, open2 + 16, 0, GuestArch::X86);
            store_u32(&mut memory, open2 + 16 + ps, 4);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource2,
                    &[open2]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, open2 + 16 + ps, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource2,
                    &[open2]
                ),
                0
            );
            let opened_on_second = load_u32(&memory, open2 + 8);
            assert_ne!(opened_on_second, 0);

            let mutex = SCRATCH + 0x2100;
            store_u32(&mut memory, mutex, second);
            store_u32(&mut memory, mutex + 4, opened_on_second);
            store_u64(&mut memory, mutex + 8, 0xCAFE);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenKeyedMutex,
                    &[mutex]
                ),
                0
            );
            let mutex_handle = load_u32(&memory, mutex + 16);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenKeyedMutex,
                    &[mutex]
                ),
                STATUS_OBJECT_NAME_COLLISION
            );
            store_u32(&mut memory, mutex, device);
            store_u32(&mut memory, mutex + 4, shared);
            store_u64(&mut memory, mutex + 8, 0xBEEF);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenKeyedMutex,
                    &[mutex]
                ),
                STATUS_ACCESS_DENIED
            );
            store_u32(&mut memory, mutex, second);
            store_u32(&mut memory, mutex + 4, private);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenKeyedMutex,
                    &[mutex]
                ),
                STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
            );
            store_u32(&mut memory, mutex + 4, shared);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenKeyedMutex,
                    &[mutex]
                ),
                STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
            );
            store_u32(&mut memory, mutex + 4, opened_on_second);
            store_u64(&mut memory, mutex + 8, 0xCAFE);
            let acquire = SCRATCH + 0x2180;
            store_u32(&mut memory, acquire, second);
            store_u32(&mut memory, acquire + 4, mutex_handle);
            store_u64(&mut memory, acquire + 8, 0xCAFE);
            store_u64(&mut memory, acquire + 16, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTAcquireKeyedMutex,
                    &[acquire]
                ),
                0
            );
            store_u64(&mut memory, acquire + 8, 0xBEEF);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTAcquireKeyedMutex,
                    &[acquire]
                ),
                STATUS_ACCESS_DENIED
            );
            let guest_owner = u64::from(runtime.guest_pid);
            let other_owner = guest_owner ^ 1;
            assert_eq!(
                wddm().d3dkmt_release_keyed_mutex(
                    KeyedMutexHandle(mutex_handle),
                    0xCAFE,
                    guest_owner
                ),
                Ok(())
            );
            assert_eq!(
                wddm().d3dkmt_acquire_keyed_mutex(
                    KeyedMutexHandle(mutex_handle),
                    0xCAFE,
                    0,
                    other_owner
                ),
                Ok(())
            );
            store_u64(&mut memory, acquire + 8, 0xCAFE);
            store_u64(&mut memory, acquire + 16, 1_000_000);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTAcquireKeyedMutex,
                    &[acquire]
                ),
                STATUS_TIMEOUT
            );
            assert_eq!(
                wddm().d3dkmt_release_keyed_mutex(
                    KeyedMutexHandle(mutex_handle),
                    0xCAFE,
                    other_owner
                ),
                Ok(())
            );
            store_u64(&mut memory, acquire + 16, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTAcquireKeyedMutex,
                    &[acquire]
                ),
                0
            );
            let release = SCRATCH + 0x2200;
            store_u32(&mut memory, release, second);
            store_u32(&mut memory, release + 4, mutex_handle);
            store_u64(&mut memory, release + 8, 0xCAFE);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTReleaseKeyedMutex,
                    &[release]
                ),
                0
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTReleaseKeyedMutex,
                    &[release]
                ),
                STATUS_ACCESS_DENIED
            );

            let first = create_fence(&mut runtime, &mut memory, second, 0);
            let dead = create_fence(&mut runtime, &mut memory, second, 0);
            let destroy = SCRATCH + 0x2300;
            store_u32(&mut memory, destroy, second);
            store_u32(&mut memory, destroy + 4, dead);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroySynchronizationObject,
                    &[destroy]
                ),
                0
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroySynchronizationObject,
                    &[destroy]
                ),
                STATUS_INVALID_HANDLE
            );
            let signal = SCRATCH + 0x2380;
            store_u32(&mut memory, signal, second);
            store_u32(&mut memory, signal + 4, 0);
            store_ptr(&mut memory, signal + 8, 0, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject2,
                    &[signal]
                ),
                STATUS_INVALID_PARAMETER
            );
            let signal_list = SCRATCH + 0x2400;
            store_u32(&mut memory, signal_list, first);
            store_u32(&mut memory, signal + 4, 1);
            store_ptr(&mut memory, signal + 8, signal_list, GuestArch::X86);
            store_u64(&mut memory, signal + 16, 3);
            store_u32(&mut memory, signal + 24, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject2,
                    &[signal]
                ),
                0
            );
            let values = SCRATCH + 0x2480;
            store_u64(&mut memory, values, 3);
            let wait = SCRATCH + 0x2500;
            store_u32(&mut memory, wait, second);
            store_u32(&mut memory, wait + 4, 1);
            store_ptr(&mut memory, wait + 8, signal_list, GuestArch::X86);
            store_ptr(&mut memory, wait + 16, values, GuestArch::X86);
            store_u64(&mut memory, wait + 24, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject2,
                    &[wait]
                ),
                0
            );
            store_u64(&mut memory, values, 4);
            store_u64(&mut memory, wait + 24, 1_000_000);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject2,
                    &[wait]
                ),
                STATUS_TIMEOUT
            );
            store_u32(&mut memory, wait + 4, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject2,
                    &[wait]
                ),
                STATUS_INVALID_PARAMETER
            );
            let destroy = SCRATCH + 0x2580;
            store_u32(&mut memory, destroy, device);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[destroy]
                ),
                0
            );
            let destroy = SCRATCH + 0x25C0;
            store_u32(&mut memory, destroy, second);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[destroy]
                ),
                0
            );
            let destroy = SCRATCH + 0x2600;
            store_u32(&mut memory, destroy, third);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroyDevice,
                    &[destroy]
                ),
                0
            );
            assert_eq!(
                wddm()
                    .allocation_info(AllocationHandle(opened))
                    .unwrap_err()
                    .status(),
                STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
            );
        });
    }

    #[test]
    fn d3d8thk_x64_new_descriptors_render_modes_and_arrays_round_trip() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X64);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let ps = pointer_size(&runtime);
            assert_eq!(ps, 8);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let device = create_device(&mut runtime, &mut memory, adapter, false);
            let allocation = create_allocation(&mut runtime, &mut memory, device, 1, 8192, 0, true);

            let context = SCRATCH + 0x2700;
            store_u32(&mut memory, context, device);
            store_u32(&mut memory, context + 4, 0);
            store_u32(&mut memory, context + 8, 7);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateContext,
                    &[context]
                ),
                0
            );
            let handle = load_u32(&memory, context + 12);
            let list = SCRATCH + 0x2780;
            store_u32(&mut memory, list, allocation);
            let render = SCRATCH + 0x2800;
            store_u32(&mut memory, render, device);
            store_u32(&mut memory, render + 4, handle);
            store_ptr(&mut memory, render + 8, list, GuestArch::X64);
            store_u32(&mut memory, render + 16, 1);
            store_u32(&mut memory, render + 20, 0x7F);
            store_u32(&mut memory, render + 24, 0);
            store_u64(&mut memory, render + 32, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTRender,
                    &[render]
                ),
                0
            );
            assert_eq!(load_u64(&memory, render + 40), 8192);
            assert_eq!(load_u64(&memory, render + 48), 0);
            assert_eq!(load_u32(&memory, render + 56), 7);
            assert!(load_u64(&memory, render + 64) >= 1);

            let modes = SCRATCH + 0x2900;
            store_u32(&mut memory, modes, adapter);
            store_u32(&mut memory, modes + 4, 0);
            store_ptr(&mut memory, modes + 8, 0, GuestArch::X64);
            store_u32(&mut memory, modes + 16, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetDisplayModeList,
                    &[modes]
                ),
                STATUS_BUFFER_TOO_SMALL
            );
            let required = load_u32(&memory, modes + 4);
            assert!(required >= 1);
            let out = SCRATCH + 0x2A00;
            store_u32(&mut memory, modes + 4, required);
            store_ptr(&mut memory, modes + 8, out, GuestArch::X64);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetDisplayModeList,
                    &[modes]
                ),
                0
            );
            assert_ne!(load_u32(&memory, out), 0);

            let open = SCRATCH + 0x2B00;
            store_u32(&mut memory, open, device);
            store_u32(&mut memory, open + 4, allocation);
            store_ptr(&mut memory, open + 16, out, GuestArch::X64);
            store_u32(&mut memory, open + 24, 4);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource2,
                    &[open]
                ),
                STATUS_OBJECT_NAME_COLLISION
            );
            store_u32(&mut memory, open + 24, 0);
            store_ptr(&mut memory, open + 16, 0, GuestArch::X64);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource2,
                    &[open]
                ),
                STATUS_OBJECT_NAME_COLLISION
            );

            let second = create_device(&mut runtime, &mut memory, adapter, false);
            let open_second = SCRATCH + 0x2E00;
            store_u32(&mut memory, open_second, second);
            store_u32(&mut memory, open_second + 4, allocation);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource,
                    &[open_second]
                ),
                0
            );
            let opened_second = load_u32(&memory, open_second + 8);
            assert_ne!(opened_second, 0);
            let mutex = SCRATCH + 0x2E80;
            store_u32(&mut memory, mutex, second);
            store_u32(&mut memory, mutex + 4, opened_second);
            store_u64(&mut memory, mutex + 8, 0);
            store_ptr(&mut memory, mutex + 24, out, GuestArch::X64);
            store_u32(&mut memory, mutex + 32, 4);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenKeyedMutex2,
                    &[mutex]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u64(&mut memory, mutex + 8, 0x77);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenKeyedMutex2,
                    &[mutex]
                ),
                0
            );
            let mutex_handle = load_u32(&memory, mutex + 16);
            let acquire = SCRATCH + 0x2F00;
            store_u32(&mut memory, acquire, second);
            store_u32(&mut memory, acquire + 4, mutex_handle);
            store_u64(&mut memory, acquire + 8, 0x77);
            store_u64(&mut memory, acquire + 16, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTAcquireKeyedMutex2,
                    &[acquire]
                ),
                0
            );
            let release = SCRATCH + 0x2F80;
            store_u32(&mut memory, release, second);
            store_u32(&mut memory, release + 4, mutex_handle);
            store_u64(&mut memory, release + 8, 0x77);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTReleaseKeyedMutex2,
                    &[release]
                ),
                0
            );
            let dead_fence = create_fence(&mut runtime, &mut memory, second, 0);
            let destroy_sync = SCRATCH + 0x3000;
            store_u32(&mut memory, destroy_sync, second);
            store_u32(&mut memory, destroy_sync + 4, dead_fence);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTDestroySynchronizationObject,
                    &[destroy_sync]
                ),
                0
            );
            let fence = create_fence(&mut runtime, &mut memory, device, 0);
            let sync_list = SCRATCH + 0x2C80;
            store_u32(&mut memory, sync_list, fence);
            let signal = SCRATCH + 0x2C00;
            store_u32(&mut memory, signal, device);
            store_u32(&mut memory, signal + 4, 1);
            store_ptr(&mut memory, signal + 8, sync_list, GuestArch::X64);
            store_u64(&mut memory, signal + 16, 1);
            store_u32(&mut memory, signal + 24, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject2,
                    &[signal]
                ),
                0
            );
            let wait = SCRATCH + 0x2D00;
            store_u32(&mut memory, wait, device);
            store_u32(&mut memory, wait + 4, fence);
            store_u64(&mut memory, wait + 8, 1);
            store_u64(&mut memory, wait + 16, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait]
                ),
                0
            );
        });
    }

    #[test]
    fn d3d8thk_descriptor_write_failures_cleanup_and_reject_exactly() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let device = create_device(&mut runtime, &mut memory, adapter, false);
            let second = create_device(&mut runtime, &mut memory, adapter, false);
            let third = create_device(&mut runtime, &mut memory, adapter, false);
            let shared = create_allocation(&mut runtime, &mut memory, device, 1, 4096, 0, true);

            let mut gdi_name = Vec::new();
            for unit in "DISPLAY1".encode_utf16().chain(std::iter::once(0)) {
                gdi_name.extend_from_slice(&unit.to_le_bytes());
            }
            let name_descriptor = 0x500_000;
            memory.map_bytes(name_descriptor, &gdi_name);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenAdapterFromGdiDisplayName,
                    &[name_descriptor]
                ),
                STATUS_INVALID_PARAMETER
            );

            let context = 0x501_000;
            memory.map_bytes(context, &[0_u8; 12]);
            store_u32(&mut memory, context, device);
            store_u32(&mut memory, context + 4, 0);
            store_u32(&mut memory, context + 8, 7);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateContext,
                    &[context]
                ),
                STATUS_INVALID_PARAMETER
            );

            let open = 0x502_000;
            memory.map_bytes(open, &[0_u8; 8]);
            store_u32(&mut memory, open, second);
            store_u32(&mut memory, open + 4, shared);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource,
                    &[open]
                ),
                STATUS_INVALID_PARAMETER
            );
            memory.map_bytes(open + 8, &[0_u8; 4]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource,
                    &[open]
                ),
                0
            );
            assert_ne!(load_u32(&memory, open + 8), 0);

            let open2 = 0x503_000;
            memory.map_bytes(open2, &[0_u8; 8]);
            memory.map_bytes(open2 + 16, &[0_u8; 8]);
            store_u32(&mut memory, open2, third);
            store_u32(&mut memory, open2 + 4, shared);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource2,
                    &[open2]
                ),
                STATUS_INVALID_PARAMETER
            );
            memory.map_bytes(open2 + 8, &[0_u8; 4]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenResource2,
                    &[open2]
                ),
                0
            );
            let opened_on_third = load_u32(&memory, open2 + 8);
            assert_ne!(opened_on_third, 0);

            let mutex2 = 0x504_000;
            memory.map_bytes(mutex2, &[0_u8; 16]);
            memory.map_bytes(mutex2 + 24, &[0_u8; 8]);
            store_u32(&mut memory, mutex2, third);
            store_u32(&mut memory, mutex2 + 4, opened_on_third);
            store_u64(&mut memory, mutex2 + 8, 0x55);
            store_u32(&mut memory, mutex2 + 24, 0);
            store_u32(&mut memory, mutex2 + 28, 4);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenKeyedMutex2,
                    &[mutex2]
                ),
                STATUS_INVALID_PARAMETER
            );

            let mutex = 0x505_000;
            memory.map_bytes(mutex, &[0_u8; 16]);
            store_u32(&mut memory, mutex, third);
            store_u32(&mut memory, mutex + 4, opened_on_third);
            store_u64(&mut memory, mutex + 8, 0x66);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenKeyedMutex,
                    &[mutex]
                ),
                STATUS_INVALID_PARAMETER
            );
            memory.map_bytes(mutex + 16, &[0_u8; 4]);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTOpenKeyedMutex,
                    &[mutex]
                ),
                0
            );
            assert_ne!(load_u32(&memory, mutex + 16), 0);
        });
    }

    #[test]
    fn d3d8thk_signal_array_context_errors_reject_before_signal() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let device = create_device(&mut runtime, &mut memory, adapter, false);
            let fence = create_fence(&mut runtime, &mut memory, device, 0);
            let objects = SCRATCH + 0x3200;
            store_u32(&mut memory, objects, fence);
            let signal = SCRATCH + 0x3280;
            store_u32(&mut memory, signal, device);
            store_u32(&mut memory, signal + 4, 1);
            store_ptr(&mut memory, signal + 8, objects, GuestArch::X86);
            store_u64(&mut memory, signal + 16, 2);
            store_u32(&mut memory, signal + 24, 1);
            store_ptr(&mut memory, signal + 32, 0, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject2,
                    &[signal]
                ),
                STATUS_INVALID_PARAMETER
            );
            let wait = SCRATCH + 0x3300;
            store_u32(&mut memory, wait, device);
            store_u32(&mut memory, wait + 4, fence);
            store_u64(&mut memory, wait + 8, 1);
            store_u64(&mut memory, wait + 16, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait]
                ),
                STATUS_TIMEOUT
            );
            let contexts = SCRATCH + 0x3380;
            store_u32(&mut memory, contexts, 0xFFFF_FFFF);
            store_ptr(&mut memory, signal + 32, contexts, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject2,
                    &[signal]
                ),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait]
                ),
                STATUS_TIMEOUT
            );
            store_ptr(&mut memory, signal + 32, 0x900_000, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSignalSynchronizationObject2,
                    &[signal]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTWaitForSynchronizationObject,
                    &[wait]
                ),
                STATUS_TIMEOUT
            );
        });
    }

    #[test]
    fn d3d8thk_statistics_process_segment_aliases_and_unsupported_classes_are_exact() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let ps = pointer_size(&runtime);
            let guest_pid = u64::from(runtime.guest_pid);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let device = create_device(&mut runtime, &mut memory, adapter, false);
            let allocation = create_allocation(&mut runtime, &mut memory, device, 1, 4096, 0, true);
            assert_eq!(
                wddm().d3dkmt_make_resident(AllocationHandle(allocation), guest_pid),
                Ok(1)
            );
            let context_descriptor = SCRATCH + 0x2100;
            store_u32(&mut memory, context_descriptor, device);
            store_u32(&mut memory, context_descriptor + 4, 0);
            store_u32(&mut memory, context_descriptor + 8, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTCreateContext,
                    &[context_descriptor]
                ),
                0
            );
            let context = load_u32(&memory, context_descriptor + 12);
            let render_list = SCRATCH + 0x2140;
            store_u32(&mut memory, render_list, allocation);
            let render = SCRATCH + 0x2180;
            store_u32(&mut memory, render, device);
            store_u32(&mut memory, render + 4, context);
            store_ptr(&mut memory, render + 8, render_list, GuestArch::X86);
            store_u32(&mut memory, render + 8 + ps, 1);
            store_u32(&mut memory, render + 12 + ps, 0x22);
            store_u32(&mut memory, render + 16 + ps, 0);
            store_u64(&mut memory, render + 32, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTRender,
                    &[render]
                ),
                0
            );

            let process = statistics_descriptor(
                &mut memory,
                STATISTICS_SIZE,
                D3DKMT_QUERYSTATISTICS_PROCESS,
                adapter,
                runtime.guest_pid,
                0,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[process]
                ),
                0
            );
            assert_eq!(load_u64(&memory, process + 16), guest_pid);
            assert!(load_u64(&memory, process + 24) >= 1, "process allocations");
            assert!(load_u64(&memory, process + 32) >= 4096, "process commit");
            assert!(load_u64(&memory, process + 48) >= 1, "process residency");
            assert!(load_u64(&memory, process + 64) >= 1, "process contexts");
            assert!(load_u64(&memory, process + 72) >= 1, "process renders");

            let unknown_process = statistics_descriptor(
                &mut memory,
                STATISTICS_SIZE,
                D3DKMT_QUERYSTATISTICS_PROCESS,
                adapter,
                0xDEAD_BEEF,
                0,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[unknown_process]
                ),
                0
            );
            assert_eq!(load_u64(&memory, unknown_process + 16), 0xDEAD_BEEF);
            for index in 1..9 {
                assert_eq!(load_u64(&memory, unknown_process + 16 + index * 8), 0);
            }
            assert_eq!(load_u64(&memory, unknown_process + 16 + 9 * 8), 0xFFFF_FFFF);
            assert_eq!(
                load_u64(&memory, unknown_process + 16 + 10 * 8),
                0xFFFF_FFFF
            );
            assert_eq!(load_u64(&memory, unknown_process + 16 + 11 * 8), 0);
            assert_eq!(load_u64(&memory, unknown_process + 16 + 12 * 8), 0);

            let wide_process = statistics_descriptor(
                &mut memory,
                STATISTICS_EXTENDED_SIZE,
                D3DKMT_QUERYSTATISTICS_PROCESS,
                adapter,
                0,
                0x1_0000_0007,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[wide_process]
                ),
                0
            );
            assert_eq!(load_u64(&memory, wide_process + 32), 0x1_0000_0007);
            for index in 1..9 {
                assert_eq!(load_u64(&memory, wide_process + 32 + index * 8), 0);
            }
            assert_eq!(load_u64(&memory, wide_process + 32 + 9 * 8), 0xFFFF_FFFF);
            assert_eq!(load_u64(&memory, wide_process + 32 + 10 * 8), 0xFFFF_FFFF);
            assert_eq!(load_u64(&memory, wide_process + 32 + 11 * 8), 0);
            assert_eq!(load_u64(&memory, wide_process + 32 + 12 * 8), 0);

            let adapter_info = wddm()
                .d3dkmt_query_adapter_info(AdapterHandle(adapter))
                .expect("adapter info");
            let budget = adapter_info.segments[0].budget;
            let segment = statistics_descriptor(
                &mut memory,
                STATISTICS_SIZE,
                D3DKMT_QUERYSTATISTICS_SEGMENT,
                adapter,
                0,
                0,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[segment]
                ),
                0
            );
            assert_eq!(load_u64(&memory, segment + 16), 0);
            assert_eq!(load_u64(&memory, segment + 24), budget);
            assert!(load_u64(&memory, segment + 32) <= budget, "segment used");
            assert!(load_u64(&memory, segment + 40) >= 1, "segment allocations");
            let segment2 = statistics_descriptor(
                &mut memory,
                STATISTICS_SIZE,
                D3DKMT_QUERYSTATISTICS_SEGMENT2,
                adapter,
                0,
                0,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[segment2]
                ),
                0
            );
            assert_eq!(load_u64(&memory, segment2 + 16), 0);
            assert_eq!(load_u64(&memory, segment2 + 24), budget);

            let node = statistics_descriptor(
                &mut memory,
                STATISTICS_SIZE,
                D3DKMT_QUERYSTATISTICS_NODE,
                adapter,
                0,
                0,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[node]
                ),
                0
            );
            assert_eq!(load_u64(&memory, node + 40), 0);
            assert!(load_u64(&memory, node + 32) >= 1, "node contexts");
            assert!(load_u64(&memory, node + 16) >= 1, "node renders");
            let node2 = statistics_descriptor(
                &mut memory,
                STATISTICS_SIZE,
                D3DKMT_QUERYSTATISTICS_NODE2,
                adapter,
                0,
                0,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[node2]
                ),
                0
            );
            assert_eq!(load_u64(&memory, node2 + 40), 0);
            assert!(load_u64(&memory, node2 + 32) >= 1, "node2 contexts");

            let legacy_scoped = statistics_descriptor(
                &mut memory,
                STATISTICS_SIZE,
                D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT,
                adapter,
                0,
                0,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[legacy_scoped]
                ),
                STATUS_INVALID_PARAMETER
            );
            let scoped = statistics_descriptor(
                &mut memory,
                STATISTICS_EXTENDED_SIZE,
                D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT,
                adapter,
                0,
                guest_pid,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[scoped]
                ),
                0
            );
            assert_eq!(load_u64(&memory, scoped + 32), guest_pid);
            assert!(load_u64(&memory, scoped + 40) >= 1, "scoped allocations");
            assert_eq!(load_u64(&memory, scoped + 32 + 9 * 8), 0);
            assert_eq!(load_u64(&memory, scoped + 32 + 10 * 8), 0xFFFF_FFFF);
            assert_eq!(load_u64(&memory, scoped + 32 + 11 * 8), budget);
            let noded = statistics_descriptor(
                &mut memory,
                STATISTICS_EXTENDED_SIZE,
                D3DKMT_QUERYSTATISTICS_PROCESS_NODE,
                adapter,
                0,
                guest_pid,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[noded]
                ),
                0
            );
            assert_eq!(load_u64(&memory, noded + 32), guest_pid);
            assert_eq!(load_u64(&memory, noded + 32 + 10 * 8), 0);
            assert!(
                load_u64(&memory, noded + 32 + 6 * 8) >= 1,
                "process contexts"
            );
            let grouped = statistics_descriptor(
                &mut memory,
                STATISTICS_EXTENDED_SIZE,
                D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP,
                adapter,
                0,
                guest_pid,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[grouped]
                ),
                0
            );
            assert_eq!(load_u64(&memory, grouped + 32), guest_pid);
            assert_eq!(load_u64(&memory, grouped + 32 + 9 * 8), 0);
            assert_eq!(load_u64(&memory, grouped + 32 + 11 * 8), budget);

            for query_type in [
                D3DKMT_QUERYSTATISTICS_HISTOGRAM,
                D3DKMT_QUERYSTATISTICS_VIDPNSOURCE,
            ] {
                let unsupported = statistics_descriptor(
                    &mut memory,
                    STATISTICS_SIZE,
                    query_type,
                    adapter,
                    0,
                    0,
                    0,
                );
                assert_eq!(
                    call_status(
                        &mut runtime,
                        &mut memory,
                        HostThunk::D3DKMTQueryStatistics,
                        &[unsupported]
                    ),
                    STATUS_NOT_SUPPORTED
                );
            }
            let undocumented =
                statistics_descriptor(&mut memory, STATISTICS_SIZE, 99, adapter, 0, 0, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[undocumented]
                ),
                STATUS_INVALID_PARAMETER
            );
            let wrong_size = statistics_descriptor(
                &mut memory,
                STATISTICS_EXTENDED_SIZE + 1,
                D3DKMT_QUERYSTATISTICS_ADAPTER,
                adapter,
                0,
                0,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[wrong_size]
                ),
                STATUS_INVALID_PARAMETER
            );
            let bad_adapter = statistics_descriptor(
                &mut memory,
                STATISTICS_SIZE,
                D3DKMT_QUERYSTATISTICS_ADAPTER,
                0xFFFF_FFFF,
                0,
                0,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTQueryStatistics,
                    &[bad_adapter]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );
        });
    }

    #[test]
    fn d3d8thk_display_gamma_cursor_pnp_and_mode_buffer_errors_are_exact() {
        wddm().reset_for_tests();
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime(GuestArch::X86);
            let mut memory = MemoryImage::default();
            map_scratch(&mut memory);
            let ps = pointer_size(&runtime);
            let adapter = open_adapter(&mut runtime, &mut memory);
            let events = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&events);
            wddm().install_pnp_hooks(Arc::new(move |event| {
                sink.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(event);
            }));

            let outputs = SCRATCH + 0x2200;
            let output_list = SCRATCH + 0x2300;
            store_u32(&mut memory, outputs, adapter);
            store_u32(&mut memory, outputs + 4, 0);
            store_ptr(&mut memory, outputs + 8, 0, GuestArch::X86);
            store_u32(&mut memory, outputs + 12, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumOutputs,
                    &[outputs]
                ),
                0
            );
            let output_count = load_u32(&memory, outputs + 4);
            assert!(output_count >= 1, "backend exposes display outputs");
            store_u32(&mut memory, outputs + 4, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumOutputs,
                    &[outputs]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, outputs + 4, output_count - 1);
            store_ptr(&mut memory, outputs + 8, output_list, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumOutputs,
                    &[outputs]
                ),
                STATUS_BUFFER_TOO_SMALL
            );
            assert_eq!(load_u32(&memory, outputs + 4), output_count);
            store_u32(&mut memory, outputs + 4, output_count);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumOutputs,
                    &[outputs]
                ),
                0
            );
            for index in 0..output_count as u64 {
                let at = output_list + index * OUTPUT_ENTRY_SIZE;
                assert_eq!(load_u32(&memory, at), index as u32);
                assert_eq!(load_u32(&memory, at + 4), index as u32);
                assert_eq!(load_u32(&memory, at + 8), index as u32);
                assert!(load_u32(&memory, at + 20) >= 1);
            }
            store_u32(&mut memory, outputs, 0xFFFF_FFFF);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTEnumOutputs,
                    &[outputs]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );

            let modes2 = SCRATCH + 0x2400;
            let mode_list = SCRATCH + 0x2480;
            store_u32(&mut memory, modes2, adapter);
            store_u32(&mut memory, modes2 + 4, 0);
            store_u32(&mut memory, modes2 + 8, 0);
            store_u32(&mut memory, modes2 + 12, 0);
            store_ptr(&mut memory, modes2 + 16, 0, GuestArch::X86);
            store_u32(&mut memory, modes2 + 16 + ps, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetDisplayModeList2,
                    &[modes2]
                ),
                STATUS_BUFFER_TOO_SMALL
            );
            let mode_count = load_u32(&memory, modes2 + 8);
            assert!(mode_count >= 1, "source exposes display modes");
            store_u32(&mut memory, modes2 + 8, mode_count - 1);
            store_ptr(&mut memory, modes2 + 16, mode_list, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetDisplayModeList2,
                    &[modes2]
                ),
                STATUS_BUFFER_TOO_SMALL
            );
            assert_eq!(load_u32(&memory, modes2 + 8), mode_count);
            store_u32(&mut memory, modes2 + 8, mode_count);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetDisplayModeList2,
                    &[modes2]
                ),
                0
            );
            assert_ne!(load_u32(&memory, mode_list), 0);
            assert_ne!(load_u32(&memory, mode_list + 4), 0);
            assert_ne!(load_u32(&memory, mode_list + 12), 0);
            store_u32(&mut memory, modes2 + 4, u32::MAX);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetDisplayModeList2,
                    &[modes2]
                ),
                STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE
            );
            store_u32(&mut memory, modes2 + 4, 0);
            store_u32(&mut memory, modes2, 0xFFFF_FFFF);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetDisplayModeList2,
                    &[modes2]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );

            let ramp = SCRATCH + 0x2800;
            let readback = SCRATCH + 0x2E00;
            for index in 0..GAMMA_RAMP_ENTRIES {
                write_guest_u16(&mut memory, ramp + index as u64 * 2, index as u16)
                    .expect("red ramp entry");
                write_guest_u16(
                    &mut memory,
                    ramp + GAMMA_RAMP_ENTRIES as u64 * 2 + index as u64 * 2,
                    (255 - index) as u16,
                )
                .expect("green ramp entry");
                write_guest_u16(
                    &mut memory,
                    ramp + GAMMA_RAMP_ENTRIES as u64 * 4 + index as u64 * 2,
                    (index * 2) as u16,
                )
                .expect("blue ramp entry");
            }
            let short_ramp =
                gamma_ramp_descriptor(&mut memory, adapter, 0, GAMMA_RAMP_TYPE_RAMP, 255, ramp);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetGammaRamp,
                    &[short_ramp]
                ),
                STATUS_INVALID_PARAMETER
            );
            let null_ramp = gamma_ramp_descriptor(
                &mut memory,
                adapter,
                0,
                GAMMA_RAMP_TYPE_RAMP,
                GAMMA_RAMP_ENTRIES as u32,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetGammaRamp,
                    &[null_ramp]
                ),
                STATUS_INVALID_PARAMETER
            );
            let bad_type = gamma_ramp_descriptor(&mut memory, adapter, 0, 2, 0, ramp);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetGammaRamp,
                    &[bad_type]
                ),
                STATUS_INVALID_PARAMETER
            );
            let identity_with_data =
                gamma_ramp_descriptor(&mut memory, adapter, 0, GAMMA_RAMP_TYPE_IDENTITY, 1, ramp);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetGammaRamp,
                    &[identity_with_data]
                ),
                STATUS_INVALID_PARAMETER
            );
            let bad_output =
                gamma_ramp_descriptor(&mut memory, adapter, 99, GAMMA_RAMP_TYPE_IDENTITY, 0, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetGammaRamp,
                    &[bad_output]
                ),
                STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET
            );
            let set_ramp = gamma_ramp_descriptor(
                &mut memory,
                adapter,
                0,
                GAMMA_RAMP_TYPE_RAMP,
                GAMMA_RAMP_ENTRIES as u32,
                ramp,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetGammaRamp,
                    &[set_ramp]
                ),
                0
            );
            let short_readback =
                gamma_ramp_descriptor(&mut memory, adapter, 0, GAMMA_RAMP_TYPE_RAMP, 255, readback);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetGammaRamp,
                    &[short_readback]
                ),
                STATUS_BUFFER_TOO_SMALL
            );
            assert_eq!(
                load_u32(&memory, short_readback + 12),
                GAMMA_RAMP_ENTRIES as u32
            );
            let null_readback = gamma_ramp_descriptor(
                &mut memory,
                adapter,
                0,
                GAMMA_RAMP_TYPE_RAMP,
                GAMMA_RAMP_ENTRIES as u32,
                0,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetGammaRamp,
                    &[null_readback]
                ),
                STATUS_INVALID_PARAMETER
            );
            let get_ramp = gamma_ramp_descriptor(
                &mut memory,
                adapter,
                0,
                GAMMA_RAMP_TYPE_RAMP,
                GAMMA_RAMP_ENTRIES as u32,
                readback,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetGammaRamp,
                    &[get_ramp]
                ),
                0
            );
            assert_eq!(load_u32(&memory, get_ramp + 12), GAMMA_RAMP_ENTRIES as u32);
            assert_eq!(load_ramp_channel(&memory, readback, 0), 0);
            assert_eq!(load_ramp_channel(&memory, readback, 1), 255);
            assert_eq!(load_ramp_channel(&memory, readback, 2), 0);
            assert_eq!(
                read_guest_u16(&memory, readback + 255 * 2).expect("last red entry"),
                255
            );
            let identity_read =
                gamma_ramp_descriptor(&mut memory, adapter, 0, GAMMA_RAMP_TYPE_IDENTITY, 99, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetGammaRamp,
                    &[identity_read]
                ),
                0
            );
            assert_eq!(load_u32(&memory, identity_read + 12), 0);
            let bad_read_type = gamma_ramp_descriptor(&mut memory, adapter, 0, 2, 0, readback);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetGammaRamp,
                    &[bad_read_type]
                ),
                STATUS_INVALID_PARAMETER
            );
            let bad_read_output = gamma_ramp_descriptor(
                &mut memory,
                adapter,
                99,
                GAMMA_RAMP_TYPE_RAMP,
                GAMMA_RAMP_ENTRIES as u32,
                readback,
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTGetGammaRamp,
                    &[bad_read_output]
                ),
                STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET
            );

            let output_info = wddm()
                .d3dkmt_output_info(AdapterHandle(adapter), 0)
                .expect("output info");
            let max_width = output_info
                .modes
                .iter()
                .map(|mode| mode.width)
                .max()
                .expect("display mode");
            let position = SCRATCH + 0x2500;
            store_u32(&mut memory, position, adapter);
            store_u32(&mut memory, position + 4, 0);
            store_u32(&mut memory, position + 8, max_width);
            store_u32(&mut memory, position + 12, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetCursorPosition,
                    &[position]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, position + 8, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetCursorPosition,
                    &[position]
                ),
                0
            );
            store_u32(&mut memory, position + 4, 99);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetCursorPosition,
                    &[position]
                ),
                STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET
            );

            let pixels = SCRATCH + 0x3400;
            for index in 0..257_u64 {
                store_u32(&mut memory, pixels + index * 4, index as u32);
            }
            let cursor = SCRATCH + 0x2540;
            store_u32(&mut memory, cursor, adapter);
            store_u32(&mut memory, cursor + 4, 0);
            store_u32(&mut memory, cursor + 8, 1);
            store_u32(&mut memory, cursor + 12, 2);
            store_u32(&mut memory, cursor + 16, 2);
            store_u32(&mut memory, cursor + 20, 0);
            store_u32(&mut memory, cursor + 24, 0);
            store_u32(&mut memory, cursor + 28, 0);
            store_ptr(&mut memory, cursor + 32, pixels, GuestArch::X86);
            store_u32(&mut memory, cursor + 32 + ps, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetCursor,
                    &[cursor]
                ),
                0
            );
            store_ptr(&mut memory, cursor + 32, 0, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetCursor,
                    &[cursor]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_ptr(&mut memory, cursor + 32, pixels, GuestArch::X86);
            store_u32(&mut memory, cursor + 20, 2);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetCursor,
                    &[cursor]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, cursor + 20, 0);
            store_u32(&mut memory, cursor + 12, MAX_CURSOR_DIMENSION + 1);
            store_u32(&mut memory, cursor + 16, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetCursor,
                    &[cursor]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, cursor + 12, 0);
            store_u32(&mut memory, cursor + 16, 0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetCursor,
                    &[cursor]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, cursor + 8, 0);
            store_ptr(&mut memory, cursor + 32, 0, GuestArch::X86);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetCursor,
                    &[cursor]
                ),
                0
            );
            store_u32(&mut memory, cursor + 4, 99);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTSetCursor,
                    &[cursor]
                ),
                STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET
            );

            let pnp = SCRATCH + 0x2580;
            store_u32(&mut memory, pnp, adapter);
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTPnPStop, &[pnp]),
                STATUS_INVALID_DEVICE_STATE
            );
            let power = SCRATCH + 0x2590;
            store_u32(&mut memory, power, adapter);
            store_u32(&mut memory, power + 4, POWER_COMPONENT_GPU);
            store_u32(&mut memory, power + 8, POWER_STATE_D0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPowerComponent,
                    &[power]
                ),
                STATUS_INVALID_DEVICE_STATE
            );
            store_u32(&mut memory, power + 4, 1);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPowerComponent,
                    &[power]
                ),
                STATUS_INVALID_PARAMETER
            );
            store_u32(&mut memory, power + 4, POWER_COMPONENT_GPU);
            store_u32(&mut memory, power + 8, 2);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPowerComponent,
                    &[power]
                ),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTPnPStart, &[pnp]),
                0
            );
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTPnPStart, &[pnp]),
                STATUS_INVALID_DEVICE_STATE
            );
            store_u32(&mut memory, power + 8, POWER_STATE_D0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPowerComponent,
                    &[power]
                ),
                STATUS_INVALID_DEVICE_STATE
            );
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTPnPStop, &[pnp]),
                0
            );
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTPnPStart, &[pnp]),
                0
            );
            store_u32(&mut memory, power + 8, POWER_STATE_D3);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPowerComponent,
                    &[power]
                ),
                0
            );
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPowerComponent,
                    &[power]
                ),
                STATUS_INVALID_DEVICE_STATE
            );
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTPnPStop, &[pnp]),
                0
            );
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTPnPStop, &[pnp]),
                STATUS_INVALID_DEVICE_STATE
            );
            store_u32(&mut memory, pnp, 0xFFFF_FFFF);
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTPnPStart, &[pnp]),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );
            assert_eq!(
                call_status(&mut runtime, &mut memory, HostThunk::D3DKMTPnPStop, &[pnp]),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );
            store_u32(&mut memory, power, 0xFFFF_FFFF);
            store_u32(&mut memory, power + 4, POWER_COMPONENT_GPU);
            store_u32(&mut memory, power + 8, POWER_STATE_D0);
            assert_eq!(
                call_status(
                    &mut runtime,
                    &mut memory,
                    HostThunk::D3DKMTPowerComponent,
                    &[power]
                ),
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
            );
            assert_eq!(
                *events
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
                vec![
                    WddmPnpEvent::EvtDeviceD0Entry { adapter_id: 0 },
                    WddmPnpEvent::EvtDeviceD0Exit { adapter_id: 0 },
                    WddmPnpEvent::EvtDeviceD0Entry { adapter_id: 0 },
                    WddmPnpEvent::EvtDeviceD0Exit { adapter_id: 0 },
                ]
            );
        });
    }

    #[test]
    fn d3d8thk_unknown_kmt_imports_are_rejected_and_new_names_are_mapped() {
        wddm().reset_for_tests();
        use crate::pe::{ExportSymbol, ExportTarget, ImportSymbol, ResolvedImport};

        fn resolve(name: &str) -> &'static str {
            let symbol = ImportSymbol::ByName {
                hint: 0,
                name: name.to_string(),
            };
            let import = ResolvedImport {
                requested_module: "d3d8thk.dll".to_string(),
                resolved_module: "d3d8thk.dll".to_string(),
                symbol,
                iat_rva: 0,
                export: ExportSymbol {
                    ordinal: 0,
                    name: Some(name.to_string()),
                    target: ExportTarget::Rva(0),
                },
            };
            match HostThunk::from_import(&import) {
                HostThunk::D3DKMTEnumOutputs => "enum-outputs",
                HostThunk::D3DKMTGetDisplayModeList2 => "display-mode-list2",
                HostThunk::D3DKMTGetGammaRamp => "get-gamma-ramp",
                HostThunk::D3DKMTPnPStart => "pnp-start",
                HostThunk::D3DKMTPnPStop => "pnp-stop",
                HostThunk::D3DKMTPowerComponent => "power-component",
                HostThunk::D3DKMTSetCursor => "set-cursor",
                HostThunk::D3DKMTSetCursorPosition => "set-cursor-position",
                HostThunk::D3DKMTSetGammaRamp => "set-gamma-ramp",
                HostThunk::Unsupported { .. } => "unsupported",
                _ => "other",
            }
        }

        assert_eq!(resolve("D3DKMTEnumOutputs"), "enum-outputs");
        assert_eq!(resolve("D3DKMTGetDisplayModeList2"), "display-mode-list2");
        assert_eq!(resolve("D3DKMTGetGammaRamp"), "get-gamma-ramp");
        assert_eq!(resolve("D3DKMTPnPStart"), "pnp-start");
        assert_eq!(resolve("D3DKMTPnPStop"), "pnp-stop");
        assert_eq!(resolve("D3DKMTPowerComponent"), "power-component");
        assert_eq!(resolve("D3DKMTSetCursor"), "set-cursor");
        assert_eq!(resolve("D3DKMTSetCursorPosition"), "set-cursor-position");
        assert_eq!(resolve("D3DKMTSetGammaRamp"), "set-gamma-ramp");
        assert_eq!(resolve("D3DKMTNotARealEntryPoint"), "unsupported");
    }
}
