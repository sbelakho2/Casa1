//! Wireless-LAN dispatch: the wlanapi.dll exports, in a dedicated module
//! per the audit's modularity requirement.  `WlanOpenHandle`/`WlanCloseHandle`
//! manage a real client handle; no wireless interfaces exist, so the
//! interface operations report the honest zero-interface results
//! (`WlanEnumInterfaces` lists zero interfaces, `WlanGetAvailableNetworkList`
//! zero networks, and the connect/scan operations answer ERROR_NOT_FOUND).
//!
//! Layer contract: every export returns its ERROR_* code in EAX.

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// ERROR_SUCCESS.
const ERROR_SUCCESS: u32 = 0;
/// ERROR_INVALID_PARAMETER.
const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_NOT_FOUND — no wireless interfaces exist.
const ERROR_NOT_FOUND: u32 = 1168;

impl PeHostRuntime {
    /// Route every WLAN thunk to its dispatch function.
    pub(crate) fn dispatch_wlanapi(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::WlanOpenHandle => {
                let _version = guest_call_arg_u32(state, memory, 0)?;
                let _reserved = guest_call_arg(state, memory, 1)?;
                let version_out = guest_call_arg(state, memory, 2)?;
                let handle_out = guest_call_arg(state, memory, 3)?;
                if version_out == 0 || handle_out == 0 {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                }
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let handle = self
                    .alloc_guest_object(memory, GuestObjectKind::WlanClient, vtable)
                    .unwrap_or(0);
                if handle == 0 {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                }
                self.wlan_clients.insert(handle, 0_u32);
                write_guest_u32(memory, version_out, 2).ok();
                write_guest_pointer(memory, handle_out, handle, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::WlanCloseHandle => {
                let handle = guest_call_arg(state, memory, 0)?;
                let _reserved = guest_call_arg(state, memory, 1)?;
                self.wlan_clients.remove(&handle);
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::WlanEnumInterfaces => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let _reserved = guest_call_arg(state, memory, 1)?;
                let list_out = guest_call_arg(state, memory, 2)?;
                if list_out != 0 {
                    // WLAN_INTERFACE_INFO_LIST with zero interfaces.
                    write_guest_u32(memory, list_out, 8).ok(); // dwNumberOfItems
                    write_guest_u32(memory, list_out + 4, 0).ok(); // dwIndex
                    write_guest_u32(memory, list_out + 8, 0).ok(); // the list is empty
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::WlanGetAvailableNetworkList => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let _interface = guest_call_arg(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                let _reserved = guest_call_arg(state, memory, 3)?;
                let list_out = guest_call_arg(state, memory, 4)?;
                if list_out != 0 {
                    // WLAN_AVAILABLE_NETWORK_LIST with zero networks.
                    write_guest_u32(memory, list_out, 0).ok();
                    write_guest_u32(memory, list_out + 4, 0).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::WlanQueryInterface => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let _interface = guest_call_arg(state, memory, 1)?;
                let _kind = guest_call_arg_u32(state, memory, 2)?;
                let _reserved = guest_call_arg(state, memory, 3)?;
                let data_size = guest_call_arg(state, memory, 4)?;
                let _data = guest_call_arg(state, memory, 5)?;
                let _data_source = guest_call_arg(state, memory, 6)?;
                if data_size != 0 {
                    write_guest_u32(memory, data_size, 0).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_NOT_FOUND));
                Ok(())
            }
            HostThunk::WlanScan | HostThunk::WlanConnect | HostThunk::WlanDisconnect => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let _interface = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, u64::from(ERROR_NOT_FOUND));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted WLAN thunk {thunk:?}"),
            )),
        }
    }
}
