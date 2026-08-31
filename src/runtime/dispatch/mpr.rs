//! Network-provider dispatch: the mpr.dll exports, in a dedicated module
//! per the audit's modularity requirement.  No network providers are
//! registered, so the surface answers the documented no-network semantics:
//! `WNetGetConnectionW`/`WNetGetUserW` report WN_NOT_CONNECTED, the
//! enumeration entry points report WN_NO_NETWORK, and the connection
//! functions report WN_NET_ERROR.
//!
//! Layer contract: every export returns its WN_* code in EAX.

use super::super::*;

/// WN_SUCCESS.
const WN_SUCCESS: u32 = 0;
/// WN_NOT_CONNECTED.
const WN_NOT_CONNECTED: u32 = 0x0248;
/// WN_NO_NETWORK.
const WN_NO_NETWORK: u32 = 0x0249;
/// WN_NET_ERROR.
const WN_NET_ERROR: u32 = 0x0251;
/// WN_BAD_HANDLE.
const WN_BAD_HANDLE: u32 = 0x024c;

impl PeHostRuntime {
    /// Route every network-provider thunk to its dispatch function.
    pub(crate) fn dispatch_mpr(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::WNetGetConnectionW | HostThunk::WNetGetUserW => {
                // No drive is connected to a network resource.
                let _name = guest_call_arg(state, memory, 0)?;
                let _buffer = guest_call_arg(state, memory, 1)?;
                let size = guest_call_arg(state, memory, 2)?;
                if size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                state.set(Register::Rax, u64::from(WN_NOT_CONNECTED));
                Ok(())
            }
            HostThunk::WNetOpenEnumW => {
                let _scope = guest_call_arg_u32(state, memory, 0)?;
                let _type = guest_call_arg_u32(state, memory, 1)?;
                let _usage = guest_call_arg_u32(state, memory, 2)?;
                let _net_resource = guest_call_arg(state, memory, 3)?;
                let handle = guest_call_arg(state, memory, 4)?;
                if handle != 0 {
                    write_guest_pointer(memory, handle, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(WN_NO_NETWORK));
                Ok(())
            }
            HostThunk::WNetEnumResourceW => {
                let handle = guest_call_arg(state, memory, 0)?;
                let _count = guest_call_arg(state, memory, 1)?;
                let _buffer = guest_call_arg(state, memory, 2)?;
                let _size = guest_call_arg(state, memory, 3)?;
                state.set(
                    Register::Rax,
                    u64::from(if handle == 0 {
                        WN_BAD_HANDLE
                    } else {
                        WN_NO_NETWORK
                    }),
                );
                Ok(())
            }
            HostThunk::WNetCloseEnum => {
                let _handle = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(WN_SUCCESS));
                Ok(())
            }
            HostThunk::WNetAddConnection2W | HostThunk::WNetCancelConnection2W => {
                state.set(Register::Rax, u64::from(WN_NET_ERROR));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted network-provider thunk {thunk:?}"),
            )),
        }
    }
}
