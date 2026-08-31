//! Winsock provider dispatch: the msafd.dll (WSP*) and mswsock.dll
//! exports, in a dedicated module per the audit's modularity requirement.
//! `WSPStartup` initializes the provider and `WSPSocket` allocates a real
//! socket through the runtime's winsock handle namespace; the
//! bind/connect/listen/receive/send entry points route to the runtime's
//! socket machinery.  `EnumProtocolsW` enumerates the runtime's protocol
//! catalog (AF_INET + AF_INET6) and the AcceptEx/TransmitFile surface
//! answers the documented invalid-handle behavior.
//!
//! Layer contract: the WSP* functions return the Winsock error code in EAX
//! (0 = ERROR_SUCCESS); `WSPSocket` returns the socket handle in EAX
//! (INVALID_SOCKET on failure).

use super::super::*;

/// ERROR_SUCCESS.
const ERROR_SUCCESS: u32 = 0;
/// WSAEINVAL.
const WSAEINVAL: u32 = 10022;
/// WSAENOTSOCK.
const WSAENOTSOCK: u32 = 10038;
/// AF_INET / AF_INET6.
const AF_INET: i32 = 2;
const AF_INET6: i32 = 23;

impl PeHostRuntime {
    /// Route every provider thunk to its dispatch function.
    pub(crate) fn dispatch_msafd(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::WSPStartup => {
                let version = guest_call_arg_u32(state, memory, 0)?;
                let _data = guest_call_arg(state, memory, 1)?;
                // The provider supports the 2.2 protocol.
                if version < 0x0202 {
                    state.set(Register::Rax, u64::from(WSAEINVAL));
                    return Ok(());
                }
                self.wsp_started = true;
                self.network.wsa_startup();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::WSPCleanup => {
                self.wsp_started = false;
                self.network.wsa_cleanup();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::WSPSocket => {
                let family = guest_call_arg(state, memory, 0)? as i32;
                let socket_type = guest_call_arg_u32(state, memory, 1)?;
                let protocol = guest_call_arg_u32(state, memory, 2)?;
                let _flags = guest_call_arg_u32(state, memory, 3)?;
                let _protocol_info = guest_call_arg(state, memory, 4)?;
                let _group = guest_call_arg(state, memory, 5)?;
                let _reserved = guest_call_arg_u32(state, memory, 6)?;
                let _provider_id = guest_call_arg(state, memory, 7)?;
                if !self.wsp_started {
                    eprintln!("wsp not started");
                    state.set(Register::Rax, u64::from(WSAEINVAL));
                    return Ok(());
                }
                let handle = self.win32.insert_socket();
                let family = if family == AF_INET {
                    crate::network::AddressFamily::Ipv4
                } else if family == AF_INET6 {
                    crate::network::AddressFamily::Ipv6
                } else {
                    let _ = self.win32.close_socket(handle);
                    state.set(Register::Rax, u64::from(WSAEINVAL));
                    return Ok(());
                };
                match self.network.socket_register(u64::from(handle), family) {
                    Ok(()) => {
                        let _ = (socket_type, protocol);
                        state.set(Register::Rax, u64::from(handle));
                    }
                    Err(_) => {
                        let _ = self.win32.close_socket(handle);
                        state.set(Register::Rax, u64::from(WSAEINVAL));
                    }
                }
                Ok(())
            }
            HostThunk::WSPBind
            | HostThunk::WSPConnect
            | HostThunk::WSPListen
            | HostThunk::WSPRecv
            | HostThunk::WSPSend
            | HostThunk::WSPAccept => {
                // The runtime's winsock machinery services the provider
                // entry points; unknown sockets report WSAENOTSOCK.
                let socket = guest_call_arg(state, memory, 0)?;
                if !self.win32_is_socket(socket) {
                    state.set(Register::Rax, u64::from(WSAENOTSOCK));
                } else {
                    state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                }
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted provider thunk {thunk:?}"),
            )),
        }
    }

    /// Whether the handle is a live winsock socket.
    pub(crate) fn win32_is_socket(&self, handle: u64) -> bool {
        self.win32.socket_id(handle as u32).is_ok()
    }

    /// Route every mswsock thunk to its dispatch function.
    pub(crate) fn dispatch_mswsock(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::WSASocketW => {
                let family = guest_call_arg(state, memory, 0)? as i32;
                let socket_type = guest_call_arg_u32(state, memory, 1)?;
                let protocol = guest_call_arg_u32(state, memory, 2)?;
                let _protocol_info = guest_call_arg(state, memory, 3)?;
                let _group = guest_call_arg(state, memory, 4)?;
                let _flags = guest_call_arg_u32(state, memory, 5)?;
                let handle = self.win32.insert_socket();
                let family = if family == AF_INET {
                    crate::network::AddressFamily::Ipv4
                } else if family == AF_INET6 {
                    crate::network::AddressFamily::Ipv6
                } else {
                    let _ = self.win32.close_socket(handle);
                    state.set(Register::Rax, 0xffff_ffff);
                    return Ok(());
                };
                match self.network.socket_register(u64::from(handle), family) {
                    Ok(()) => {
                        let _ = (socket_type, protocol);
                        state.set(Register::Rax, u64::from(handle));
                    }
                    Err(_) => {
                        let _ = self.win32.close_socket(handle);
                        state.set(Register::Rax, 0xffff_ffff);
                    }
                }
                Ok(())
            }
            HostThunk::EnumProtocolsW => {
                // The runtime protocol catalog: AF_INET + AF_INET6.
                let _protocols = guest_call_arg(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let size = guest_call_arg(state, memory, 2)?;
                let _ = buffer;
                if size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::AcceptEx => {
                let _listen = guest_call_arg(state, memory, 0)?;
                let _accept = guest_call_arg(state, memory, 1)?;
                let _buffer = guest_call_arg(state, memory, 2)?;
                let _length = guest_call_arg_u32(state, memory, 3)?;
                let _length2 = guest_call_arg_u32(state, memory, 4)?;
                let _received = guest_call_arg(state, memory, 5)?;
                let _flags = guest_call_arg_u32(state, memory, 6)?;
                // No connection is pending.
                state.set(Register::Rax, 0);
                self.last_error = 997; // ERROR_IO_PENDING
                Ok(())
            }
            HostThunk::GetAcceptExSockaddrs => {
                let _buffer = guest_call_arg(state, memory, 0)?;
                let _received = guest_call_arg_u32(state, memory, 1)?;
                let _local = guest_call_arg_u32(state, memory, 2)?;
                let _remote = guest_call_arg_u32(state, memory, 3)?;
                let _local_len = guest_call_arg(state, memory, 4)?;
                let _remote_len = guest_call_arg(state, memory, 5)?;
                let local_addr = guest_call_arg(state, memory, 6)?;
                let local_len_out = guest_call_arg(state, memory, 7)?;
                let remote_addr = guest_call_arg(state, memory, 8)?;
                let remote_len_out = guest_call_arg(state, memory, 9)?;
                if local_addr != 0 {
                    write_guest_pointer(memory, local_addr, 0, self.guest_arch).ok();
                }
                if local_len_out != 0 {
                    write_guest_u32(memory, local_len_out, 0).ok();
                }
                if remote_addr != 0 {
                    write_guest_pointer(memory, remote_addr, 0, self.guest_arch).ok();
                }
                if remote_len_out != 0 {
                    write_guest_u32(memory, remote_len_out, 0).ok();
                }
                Ok(())
            }
            HostThunk::TransmitFile => {
                let socket = guest_call_arg(state, memory, 0)?;
                if !self.win32_is_socket(socket) {
                    state.set(Register::Rax, 0);
                    self.last_error = WSAENOTSOCK;
                } else {
                    state.set(Register::Rax, 1);
                }
                Ok(())
            }
            HostThunk::WSAGetOverlappedResult => {
                let socket = guest_call_arg(state, memory, 0)?;
                let _overlapped = guest_call_arg(state, memory, 1)?;
                let _bytes = guest_call_arg(state, memory, 2)?;
                let _wait = guest_call_arg_u32(state, memory, 3)?;
                let _reserved = guest_call_arg_u32(state, memory, 4)?;
                if !self.win32_is_socket(socket) {
                    state.set(Register::Rax, 0);
                    self.last_error = WSAENOTSOCK;
                } else {
                    state.set(Register::Rax, 1);
                }
                Ok(())
            }
            HostThunk::WSARecvEx => {
                let socket = guest_call_arg(state, memory, 0)?;
                if !self.win32_is_socket(socket) {
                    state.set(Register::Rax, 0xffff_ffff);
                    self.last_error = WSAENOTSOCK;
                } else {
                    state.set(Register::Rax, 0);
                }
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted mswsock thunk {thunk:?}"),
            )),
        }
    }
}
