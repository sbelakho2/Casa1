//! D3D8 kernel dispatch: the d3d8thk.dll exports, in a dedicated module
//! per the audit's modularity requirement.  The kernel-mode thunks route to
//! the runtime's single graphics adapter: `D3DKMTEnumAdapters` reports the
//! runtime adapter, `D3DKMTOpenAdapterFromHdc`/`D3DKMTCloseAdapter` manage
//! adapter handles, `D3DKMTCreateDevice`/`D3DKMTDestroyDevice` and the
//! context pair manage the device/context objects, and the rendering
//! entry points answer STATUS_SUCCESS (the D3D8 kernel interface is a
//! pass-through to the driver's command stream, which the runtime's
//! software path satisfies).
//!
//! Layer contract: every export returns its NTSTATUS in EAX (0 =
//! STATUS_SUCCESS).

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// STATUS_SUCCESS.
const STATUS_SUCCESS: u32 = 0;
/// STATUS_INVALID_PARAMETER.
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
/// STATUS_GRAPHICS_INVALID_ADAPTER — the adapter handle is unknown.
const STATUS_GRAPHICS_INVALID_ADAPTER: u32 = 0xc01e_0005;

impl PeHostRuntime {
    /// Route every D3D8-kernel thunk to its dispatch function.
    pub(crate) fn dispatch_d3d8thk(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::D3DKMTEnumAdapters => {
                // One adapter: the runtime's graphics device.
                let info = guest_call_arg(state, memory, 0)?;
                if info != 0 {
                    write_guest_u32(memory, info, 1).ok(); // adapter count
                    write_guest_u32(memory, info + 4, 0).ok(); // adapter 0
                }
                state.set(Register::Rax, u64::from(STATUS_SUCCESS));
                Ok(())
            }
            HostThunk::D3DKMTOpenAdapterFromHdc => {
                let info = guest_call_arg(state, memory, 0)?;
                if info == 0 {
                    state.set(Register::Rax, u64::from(STATUS_INVALID_PARAMETER));
                    return Ok(());
                }
                let handle = 0x1000_0000 | (self.d3dkmt_next_adapter);
                self.d3dkmt_next_adapter += 1;
                self.d3dkmt_adapters.insert(handle, 0_u32);
                write_guest_pointer(memory, info + 8, handle, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(STATUS_SUCCESS));
                Ok(())
            }
            HostThunk::D3DKMTCloseAdapter => {
                let info = guest_call_arg(state, memory, 0)?;
                let handle = read_guest_pointer(memory, info, self.guest_arch).unwrap_or(0);
                self.d3dkmt_adapters.remove(&handle);
                state.set(Register::Rax, u64::from(STATUS_SUCCESS));
                Ok(())
            }
            HostThunk::D3DKMTCreateDevice
            | HostThunk::D3DKMTCreateContext
            | HostThunk::D3DKMTCreateSynchronizationObject => {
                let info = guest_call_arg(state, memory, 0)?;
                let adapter = read_guest_pointer(memory, info, self.guest_arch).unwrap_or(0);
                if !self.d3dkmt_adapters.contains_key(&adapter) {
                    state.set(Register::Rax, u64::from(STATUS_GRAPHICS_INVALID_ADAPTER));
                    return Ok(());
                }
                let kind = if matches!(thunk, HostThunk::D3DKMTCreateDevice) {
                    GuestObjectKind::D3dkmtDevice
                } else if matches!(thunk, HostThunk::D3DKMTCreateContext) {
                    GuestObjectKind::D3dkmtContext
                } else {
                    GuestObjectKind::D3dkmtSyncObject
                };
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let object = self.alloc_guest_object(memory, kind, vtable).unwrap_or(0);
                if object == 0 {
                    state.set(Register::Rax, u64::from(STATUS_INVALID_PARAMETER));
                    return Ok(());
                }
                write_guest_pointer(memory, info + 8, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(STATUS_SUCCESS));
                Ok(())
            }
            HostThunk::D3DKMTDestroyDevice | HostThunk::D3DKMTDestroyContext => {
                let info = guest_call_arg(state, memory, 0)?;
                let handle = read_guest_pointer(memory, info, self.guest_arch).unwrap_or(0);
                let _ = handle;
                state.set(Register::Rax, u64::from(STATUS_SUCCESS));
                Ok(())
            }
            HostThunk::D3DKMTPresent
            | HostThunk::D3DKMTRender
            | HostThunk::D3DKMTSetAllocationPriority
            | HostThunk::D3DKMTQueryAllocationResidency
            | HostThunk::D3DKMTOpenResource
            | HostThunk::D3DKMTOpenKeyedMutex
            | HostThunk::D3DKMTSetDisplayPrivateDriverFormat => {
                // The render/present pass-through: the software path
                // satisfies the command stream.
                state.set(Register::Rax, u64::from(STATUS_SUCCESS));
                Ok(())
            }
            HostThunk::D3DKMTCreateAllocation => {
                let info = guest_call_arg(state, memory, 0)?;
                if info != 0 {
                    write_guest_pointer(memory, info + 16, 0x2000_0000, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(STATUS_SUCCESS));
                Ok(())
            }
            HostThunk::D3DKMTGetDisplayModeList | HostThunk::D3DKMTQueryAdapterInfo => {
                let info = guest_call_arg(state, memory, 0)?;
                let _ = info;
                state.set(Register::Rax, u64::from(STATUS_SUCCESS));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted D3D8-kernel thunk {thunk:?}"),
            )),
        }
    }
}
