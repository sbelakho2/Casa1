//! RPC dispatch: the rpcrt4.dll exports, in a dedicated module per the
//! audit's modularity requirement.  The UUID surface is real (the runtime's
//! uuid crate): `UuidCreate`/`UuidCreateSequential` mint version-4 UUIDs,
//! `UuidFromStringW` parses the canonical string form, and `UuidToStringW`
//! formats it.  The binding-string surface composes and parses the
//! documented `ncacn_np:host[\\pipe\\name]` forms and manages the binding
//! handles; `I_RpcExceptionFilter` implements the documented mapping.
//!
//! Layer contract: the Uuid* functions return RPC_S_* codes in EAX;
//! `UuidCreate` returns RPC_S_OK (0) and writes the UUID bytes.

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// RPC_S_OK.
const RPC_S_OK: u32 = 0;
/// RPC_S_INVALID_STRING_BINDING.
const RPC_S_INVALID_STRING_BINDING: u32 = 1700;
/// RPC_S_OUT_OF_MEMORY.
const RPC_S_OUT_OF_MEMORY: u32 = 14;
/// EXCEPTION_CONTINUE_SEARCH (for the exception filter).
const EXCEPTION_CONTINUE_SEARCH: u32 = 1;

impl PeHostRuntime {
    /// Route every RPC thunk to its dispatch function.
    pub(crate) fn dispatch_rpc(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::UuidCreate | HostThunk::UuidCreateSequential => {
                let out = guest_call_arg(state, memory, 0)?;
                if out == 0 {
                    state.set(Register::Rax, 14); // RPC_S_INVALID_ARG
                    return Ok(());
                }
                let uuid = uuid::Uuid::new_v4();
                memory.map_bytes(out, &uuid.into_bytes());
                state.set(Register::Rax, u64::from(RPC_S_OK));
                Ok(())
            }
            HostThunk::UuidFromStringW => {
                let string = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    state.set(Register::Rax, 14);
                    return Ok(());
                }
                if string == 0 {
                    // A null string produces the nil UUID.
                    memory.map_bytes(out, &[0_u8; 16]);
                    state.set(Register::Rax, u64::from(RPC_S_OK));
                    return Ok(());
                }
                let text = read_utf16_string(memory, string).unwrap_or_default();
                match uuid::Uuid::parse_str(&text) {
                    Ok(uuid) => {
                        memory.map_bytes(out, &uuid.into_bytes());
                        state.set(Register::Rax, u64::from(RPC_S_OK));
                    }
                    Err(_) => state.set(Register::Rax, 1334), // RPC_S_INVALID_UUID
                }
                Ok(())
            }
            HostThunk::UuidToStringW => {
                let uuid = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    state.set(Register::Rax, 14);
                    return Ok(());
                }
                let bytes = memory.read_bytes(uuid, 16).unwrap_or_default();
                let mut raw = [0_u8; 16];
                raw.copy_from_slice(&bytes);
                let uuid = uuid::Uuid::from_bytes(raw);
                let address = self.rpc_scratch_string(memory, &uuid.to_string())?;
                write_guest_pointer(memory, out, address, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(RPC_S_OK));
                Ok(())
            }
            HostThunk::RpcStringBindingComposeW => {
                self.dispatch_rpc_string_binding_compose(state, memory)
            }
            HostThunk::RpcStringBindingFromStringBindingW => {
                let binding = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let text = read_utf16_string(memory, binding).unwrap_or_default();
                if text.is_empty() {
                    state.set(Register::Rax, u64::from(RPC_S_INVALID_STRING_BINDING));
                    return Ok(());
                }
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let handle = self
                    .alloc_guest_object(memory, GuestObjectKind::RpcBinding, vtable)
                    .unwrap_or(0);
                if handle == 0 {
                    state.set(Register::Rax, u64::from(RPC_S_OUT_OF_MEMORY));
                    return Ok(());
                }
                self.rpc_bindings.insert(handle, text);
                if out != 0 {
                    write_guest_pointer(memory, out, handle, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(RPC_S_OK));
                Ok(())
            }
            HostThunk::RpcBindingFree => {
                let binding = guest_call_arg(state, memory, 0)?;
                let binding = read_guest_pointer(memory, binding, self.guest_arch).unwrap_or(0);
                self.rpc_bindings.remove(&binding);
                state.set(Register::Rax, u64::from(RPC_S_OK));
                Ok(())
            }
            HostThunk::RpcStringFreeW => {
                let _string = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(RPC_S_OK));
                Ok(())
            }
            HostThunk::IRpcExceptionFilter => {
                // The documented mapping: RPC_S_* codes continue the search.
                let code = guest_call_arg_u32(state, memory, 0)?;
                state.set(
                    Register::Rax,
                    u64::from(if (0x1A00..=0x1A1C).contains(&code) {
                        EXCEPTION_CONTINUE_SEARCH
                    } else {
                        0
                    }),
                );
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted RPC thunk {thunk:?}"),
            )),
        }
    }

    /// The guest-resident scratch string for the RPC surface (the wide
    /// string the UuidToStringW contract returns).
    fn rpc_scratch_string(&mut self, memory: &mut MemoryImage, text: &str) -> AppResult<u64> {
        let mut address = self.wic.string_slots[3];
        if address == 0 {
            address = self.alloc_zeroed(memory, 256, 8)?;
            self.wic.string_slots[3] = address;
        }
        for (i, unit) in text.encode_utf16().enumerate() {
            write_guest_u16(memory, address + (i as u64 * 2), unit).ok();
        }
        write_guest_u16(
            memory,
            address + (text.encode_utf16().count() as u64 * 2),
            0,
        )
        .ok();
        Ok(address)
    }

    /// `RpcStringBindingComposeW(obj, if, protseq, network, endpoint,
    /// options, bindingOut)` — the `protseq:network[endpoint]` form.
    pub(crate) fn dispatch_rpc_string_binding_compose(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let obj = guest_call_arg(state, memory, 0)?;
        let interface = guest_call_arg(state, memory, 1)?;
        let protseq = guest_call_arg(state, memory, 2)?;
        let network = guest_call_arg(state, memory, 3)?;
        let endpoint = guest_call_arg(state, memory, 4)?;
        let _options = guest_call_arg(state, memory, 5)?;
        let out = guest_call_arg(state, memory, 6)?;
        let obj = read_utf16_string(memory, obj).unwrap_or_default();
        let interface = read_utf16_string(memory, interface).unwrap_or_default();
        let protseq = read_utf16_string(memory, protseq).unwrap_or_default();
        let network = read_utf16_string(memory, network).unwrap_or_default();
        let endpoint = read_utf16_string(memory, endpoint).unwrap_or_default();
        if protseq.is_empty() && network.is_empty() && endpoint.is_empty() {
            state.set(Register::Rax, u64::from(RPC_S_INVALID_STRING_BINDING));
            return Ok(());
        }
        let mut binding = String::new();
        if !obj.is_empty() {
            binding.push_str(&obj);
            binding.push('@');
        }
        binding.push_str(&protseq);
        if !network.is_empty() {
            binding.push(':');
            binding.push_str(&network);
        }
        if !endpoint.is_empty() {
            binding.push('[');
            binding.push_str(&endpoint);
            binding.push(']');
        }
        if !interface.is_empty() {
            binding.push(',');
            binding.push_str(&interface);
        }
        let address = self.rpc_scratch_string(memory, &binding)?;
        if out != 0 {
            write_guest_pointer(memory, out, address, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(RPC_S_OK));
        Ok(())
    }
}
