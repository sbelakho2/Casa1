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
/// RPC_S_PROTSEQ_NOT_SUPPORTED.
const RPC_S_PROTSEQ_NOT_SUPPORTED: u32 = 1703;
/// RPC_S_INVALID_RPC_PROTSEQ.
const RPC_S_INVALID_RPC_PROTSEQ: u32 = 1704;
/// RPC_S_INVALID_STRING_UUID.
const RPC_S_INVALID_STRING_UUID: u32 = 1705;
/// RPC_S_INVALID_ENDPOINT_FORMAT.
const RPC_S_INVALID_ENDPOINT_FORMAT: u32 = 1706;
/// RPC_S_OUT_OF_MEMORY.
const RPC_S_OUT_OF_MEMORY: u32 = 14;
/// EXCEPTION_CONTINUE_SEARCH (for the exception filter).
const EXCEPTION_CONTINUE_SEARCH: u32 = 1;

/// The protocol sequences the binding-string surface recognizes.
const SUPPORTED_PROTSEQS: &[&str] = &[
    "ncacn_np",
    "ncacn_ip_tcp",
    "ncacn_http",
    "ncacn_spx",
    "ncacn_at_dsp",
    "ncacn_dnet_nsp",
    "ncacn_vns_spp",
    "ncacn_nb_tcp",
    "ncacn_nb_nb",
    "ncacn_nb_ipx",
    "ncadg_ip_udp",
    "ncadg_ipx",
    "ncadg_mq",
    "ncalrpc",
];

/// The components of a parsed string binding
/// (`obj@protseq:network[endpoint,options]`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StringBinding {
    object: String,
    protseq: String,
    network: String,
    endpoint: String,
    options: String,
}

impl StringBinding {
    /// Format the binding back into the documented string form.
    fn to_string_binding(&self) -> String {
        let mut text = String::new();
        if !self.object.is_empty() {
            text.push_str(&self.object);
            text.push('@');
        }
        text.push_str(&self.protseq);
        text.push(':');
        text.push_str(&self.network);
        if !self.endpoint.is_empty() || !self.options.is_empty() {
            text.push('[');
            text.push_str(&self.endpoint);
            if !self.options.is_empty() {
                text.push(',');
                text.push_str(&self.options);
            }
            text.push(']');
        }
        text
    }
}

/// Parse `[obj@]protseq:network[endpoint[,options]]` (the brace-less
/// canonical form).  Returns the components or the RPC status of the first
/// violated rule.
fn parse_string_binding(text: &str) -> Result<StringBinding, u32> {
    let (object, rest) = match text.split_once('@') {
        Some((object, rest)) => {
            if object.is_empty()
                || uuid::Uuid::parse_str(object.trim_matches(|c| c == '{' || c == '}')).is_err()
            {
                return Err(RPC_S_INVALID_STRING_UUID);
            }
            (object.to_string(), rest)
        }
        None => (String::new(), text),
    };
    let (protseq, rest) = match rest.split_once(':') {
        Some(parts) => parts,
        None => return Err(RPC_S_INVALID_STRING_BINDING),
    };
    if protseq.is_empty() {
        return Err(RPC_S_INVALID_RPC_PROTSEQ);
    }
    if !SUPPORTED_PROTSEQS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(protseq))
    {
        return Err(RPC_S_PROTSEQ_NOT_SUPPORTED);
    }
    let (network, suffix) = match rest.find('[') {
        Some(bracket) => (&rest[..bracket], &rest[bracket..]),
        None => (rest, ""),
    };
    if suffix.is_empty() {
        return Ok(StringBinding {
            object,
            protseq: protseq.to_string(),
            network: network.to_string(),
            endpoint: String::new(),
            options: String::new(),
        });
    }
    if !suffix.ends_with(']') || suffix.len() < 2 {
        return Err(RPC_S_INVALID_STRING_BINDING);
    }
    let inner = &suffix[1..suffix.len() - 1];
    let (endpoint, options) = match inner.split_once(',') {
        Some((endpoint, options)) => (endpoint.to_string(), options.to_string()),
        None => (inner.to_string(), String::new()),
    };
    Ok(StringBinding {
        object,
        protseq: protseq.to_string(),
        network: network.to_string(),
        endpoint,
        options,
    })
}

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
                let parsed = match parse_string_binding(&text) {
                    Ok(parsed) => parsed,
                    Err(status) => {
                        state.set(Register::Rax, u64::from(status));
                        return Ok(());
                    }
                };
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let handle = self
                    .alloc_guest_object(memory, GuestObjectKind::RpcBinding, vtable)
                    .unwrap_or(0);
                if handle == 0 {
                    state.set(Register::Rax, u64::from(RPC_S_OUT_OF_MEMORY));
                    return Ok(());
                }
                self.rpc_bindings.insert(handle, parsed.to_string_binding());
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

    /// `RpcStringBindingComposeW(objUuid, protseq, network, endpoint,
    /// options, bindingOut)` — the documented
    /// `obj@protseq:network[endpoint,options]` form (six arguments; the
    /// ABI has no interface parameter).
    pub(crate) fn dispatch_rpc_string_binding_compose(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let obj = guest_call_arg(state, memory, 0)?;
        let protseq = guest_call_arg(state, memory, 1)?;
        let network = guest_call_arg(state, memory, 2)?;
        let endpoint = guest_call_arg(state, memory, 3)?;
        let options = guest_call_arg(state, memory, 4)?;
        let out = guest_call_arg(state, memory, 5)?;
        let object = read_utf16_string(memory, obj).unwrap_or_default();
        let protseq = read_utf16_string(memory, protseq).unwrap_or_default();
        let network = read_utf16_string(memory, network).unwrap_or_default();
        let endpoint = read_utf16_string(memory, endpoint).unwrap_or_default();
        let options = read_utf16_string(memory, options).unwrap_or_default();
        if protseq.is_empty() {
            state.set(Register::Rax, u64::from(RPC_S_INVALID_RPC_PROTSEQ));
            return Ok(());
        }
        if !object.is_empty()
            && uuid::Uuid::parse_str(object.trim_matches(|c| c == '{' || c == '}')).is_err()
        {
            state.set(Register::Rax, u64::from(RPC_S_INVALID_STRING_UUID));
            return Ok(());
        }
        if !SUPPORTED_PROTSEQS
            .iter()
            .any(|known| known.eq_ignore_ascii_case(&protseq))
        {
            state.set(Register::Rax, u64::from(RPC_S_PROTSEQ_NOT_SUPPORTED));
            return Ok(());
        }
        if endpoint.contains(',') {
            state.set(Register::Rax, u64::from(RPC_S_INVALID_ENDPOINT_FORMAT));
            return Ok(());
        }
        let binding = StringBinding {
            object,
            protseq,
            network,
            endpoint,
            options,
        };
        let address = self.rpc_scratch_string(memory, &binding.to_string_binding())?;
        if out != 0 {
            write_guest_pointer(memory, out, address, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(RPC_S_OK));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{Fixture, dispatch_x86, with_big_stack, x86_fixture};
    use super::*;

    const OBJ: u64 = 0x41_000;
    const PROTSEQ: u64 = 0x41_100;
    const NETWORK: u64 = 0x41_200;
    const ENDPOINT: u64 = 0x41_300;
    const OPTIONS: u64 = 0x41_400;
    const BINDING_OUT: u64 = 0x41_500;
    const BINDING_IN: u64 = 0x41_600;
    const HANDLE_OUT: u64 = 0x41_700;

    fn write_wide(fixture: &mut Fixture, address: u64, text: &str) {
        if text.is_empty() {
            fixture.memory.map_bytes(address, &[0_u8; 2]);
            return;
        }
        let mut bytes = Vec::new();
        for unit in text.encode_utf16().chain([0]) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        fixture.memory.map_bytes(address, &bytes);
    }

    fn read_binding(fixture: &Fixture, out: u64) -> String {
        let pointer = read_guest_pointer(&fixture.memory, out, GuestArch::X86).unwrap();
        assert_ne!(pointer, 0);
        read_utf16_string(&fixture.memory, pointer).unwrap()
    }

    #[test]
    fn compose_writes_the_documented_binding_form() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("rpc-compose");
            fixture.memory.map_bytes(BINDING_OUT, &[0_u8; 8]);

            write_wide(&mut fixture, OBJ, "6B29FC40-CA47-1067-B31D-00DD010662DA");
            write_wide(&mut fixture, PROTSEQ, "ncacn_np");
            write_wide(&mut fixture, NETWORK, "\\\\server");
            write_wide(&mut fixture, ENDPOINT, "\\pipe\\ep");
            write_wide(&mut fixture, OPTIONS, "Security=impersonation static true");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::RpcStringBindingComposeW,
                    &[
                        OBJ as u32,
                        PROTSEQ as u32,
                        NETWORK as u32,
                        ENDPOINT as u32,
                        OPTIONS as u32,
                        BINDING_OUT as u32,
                    ]
                ),
                0
            );
            assert_eq!(
                read_binding(&fixture, BINDING_OUT),
                "6B29FC40-CA47-1067-B31D-00DD010662DA@ncacn_np:\\\\server[\\pipe\\ep,Security=impersonation static true]"
            );

            // Options with an empty endpoint use the documented `[,opts]`.
            write_wide(&mut fixture, OBJ, "");
            write_wide(&mut fixture, PROTSEQ, "ncacn_http");
            write_wide(&mut fixture, NETWORK, "host");
            write_wide(&mut fixture, ENDPOINT, "");
            write_wide(&mut fixture, OPTIONS, "HttpProxy=proxy:80");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::RpcStringBindingComposeW,
                    &[
                        OBJ as u32,
                        PROTSEQ as u32,
                        NETWORK as u32,
                        ENDPOINT as u32,
                        OPTIONS as u32,
                        BINDING_OUT as u32,
                    ]
                ),
                0
            );
            assert_eq!(
                read_binding(&fixture, BINDING_OUT),
                "ncacn_http:host[,HttpProxy=proxy:80]"
            );

            // Real failure modes: unknown protocol, malformed UUID.
            write_wide(&mut fixture, PROTSEQ, "bogus_protseq");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::RpcStringBindingComposeW,
                    &[
                        OBJ as u32,
                        PROTSEQ as u32,
                        NETWORK as u32,
                        ENDPOINT as u32,
                        OPTIONS as u32,
                        BINDING_OUT as u32,
                    ]
                ),
                u64::from(RPC_S_PROTSEQ_NOT_SUPPORTED)
            );
            write_wide(&mut fixture, PROTSEQ, "ncacn_np");
            write_wide(&mut fixture, OBJ, "not-a-uuid");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::RpcStringBindingComposeW,
                    &[
                        OBJ as u32,
                        PROTSEQ as u32,
                        NETWORK as u32,
                        ENDPOINT as u32,
                        OPTIONS as u32,
                        BINDING_OUT as u32,
                    ]
                ),
                u64::from(RPC_S_INVALID_STRING_UUID)
            );
        })
    }

    #[test]
    fn from_string_binding_validates_and_free_releases() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("rpc-from-string");
            fixture.memory.map_bytes(HANDLE_OUT, &[0_u8; 8]);
            write_wide(&mut fixture, BINDING_IN, "ncacn_np:\\\\server[\\pipe\\ep]");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::RpcStringBindingFromStringBindingW,
                    &[BINDING_IN as u32, HANDLE_OUT as u32]
                ),
                0
            );
            let handle = read_guest_pointer(&fixture.memory, HANDLE_OUT, GuestArch::X86).unwrap();
            assert_ne!(handle, 0);
            assert_eq!(
                fixture
                    .runtime
                    .rpc_bindings
                    .get(&handle)
                    .map(String::as_str),
                Some("ncacn_np:\\\\server[\\pipe\\ep]")
            );

            // Malformed bindings answer the documented statuses.
            write_wide(&mut fixture, BINDING_IN, "no-colon-here");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::RpcStringBindingFromStringBindingW,
                    &[BINDING_IN as u32, HANDLE_OUT as u32]
                ),
                u64::from(RPC_S_INVALID_STRING_BINDING)
            );
            write_wide(&mut fixture, BINDING_IN, "bogus_protseq:host[endpoint]");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::RpcStringBindingFromStringBindingW,
                    &[BINDING_IN as u32, HANDLE_OUT as u32]
                ),
                u64::from(RPC_S_PROTSEQ_NOT_SUPPORTED)
            );

            // RpcBindingFree reads the handle through its pointer argument.
            fixture
                .memory
                .map_bytes(ENDPOINT, &(handle as u32).to_le_bytes());
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::RpcBindingFree, &[ENDPOINT as u32]),
                0
            );
            assert!(!fixture.runtime.rpc_bindings.contains_key(&handle));
        })
    }
}
