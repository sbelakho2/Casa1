//! LDAP dispatch: the wldap32.dll exports, in a dedicated module per the
//! audit's modularity requirement.  `ldap_init` allocates a real session
//! handle; with no LDAP servers reachable the connection-dependent
//! operations answer LDAP_SERVER_DOWN, and the result-walk functions
//! answer the honest empty-result semantics (no entries, null values).
//!
//! Layer contract: the search functions return the LDAP_* message/code in
//! EAX; the walk functions return pointers in EAX (0 for empty results).

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// LDAP_SUCCESS.
const LDAP_SUCCESS: u32 = 0;
/// LDAP_SERVER_DOWN — the server is unreachable.
const LDAP_SERVER_DOWN: u32 = 0x51;
/// LDAP_NO_RESULTS_RETURNED.
/// LDAP_RES_SEARCH_ENTRY / LDAP_RES_SEARCH_RESULT.
const LDAP_RES_SEARCH_RESULT: u32 = 0x65;

impl PeHostRuntime {
    /// Route every LDAP thunk to its dispatch function.
    pub(crate) fn dispatch_ldap(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::LdapInit => {
                let host = guest_call_arg(state, memory, 0)?;
                let port = guest_call_arg_u32(state, memory, 1)?;
                let host_text = read_utf16_string(memory, host).unwrap_or_default();
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let session = self
                    .alloc_guest_object(memory, GuestObjectKind::LdapSession, vtable)
                    .unwrap_or(0);
                if session == 0 {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                self.ldap_sessions.insert(
                    session,
                    crate::runtime::state::LdapSessionState {
                        host: host_text,
                        port,
                    },
                );
                state.set(Register::Rax, session);
                Ok(())
            }
            HostThunk::LdapUnbind => {
                let session = guest_call_arg(state, memory, 0)?;
                self.ldap_sessions.remove(&session);
                state.set(Register::Rax, u64::from(LDAP_SUCCESS));
                Ok(())
            }
            HostThunk::LdapBindS => {
                let session = guest_call_arg(state, memory, 0)?;
                let _dn = guest_call_arg(state, memory, 1)?;
                let _credential = guest_call_arg(state, memory, 2)?;
                let _method = guest_call_arg_u32(state, memory, 3)?;
                if !self.ldap_sessions.contains_key(&session) {
                    state.set(Register::Rax, u64::from(LDAP_SERVER_DOWN));
                    return Ok(());
                }
                // No server is reachable.
                state.set(Register::Rax, u64::from(LDAP_SERVER_DOWN));
                Ok(())
            }
            HostThunk::LdapSearchS | HostThunk::LdapSearch => {
                let session = guest_call_arg(state, memory, 0)?;
                let _base = guest_call_arg(state, memory, 1)?;
                let _scope = guest_call_arg_u32(state, memory, 2)?;
                let _filter = guest_call_arg(state, memory, 3)?;
                let _attrs = guest_call_arg(state, memory, 4)?;
                let _attr_only = guest_call_arg_u32(state, memory, 5)?;
                let message_out = guest_call_arg(state, memory, 6)?;
                if !self.ldap_sessions.contains_key(&session) {
                    state.set(Register::Rax, u64::from(LDAP_SERVER_DOWN));
                    return Ok(());
                }
                if message_out != 0 {
                    write_guest_pointer(memory, message_out, 0, self.guest_arch).ok();
                }
                // The search result: an empty message with the
                // LDAP_RES_SEARCH_RESULT type.
                let message = 0x1000_0000 | session;
                self.ldap_messages.insert(message, 0_u32);
                state.set(Register::Rax, message);
                Ok(())
            }
            HostThunk::LdapResult => {
                let session = guest_call_arg(state, memory, 0)?;
                let _message = guest_call_arg_u32(state, memory, 1)?;
                let _all = guest_call_arg_u32(state, memory, 2)?;
                let _timeout = guest_call_arg(state, memory, 3)?;
                let message_out = guest_call_arg(state, memory, 4)?;
                if !self.ldap_sessions.contains_key(&session) {
                    state.set(Register::Rax, u64::from(LDAP_SERVER_DOWN));
                    return Ok(());
                }
                let message = 0x1000_0000 | session;
                self.ldap_messages.insert(message, 0_u32);
                if message_out != 0 {
                    write_guest_pointer(memory, message_out, message, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(LDAP_RES_SEARCH_RESULT));
                Ok(())
            }
            HostThunk::LdapCountEntries | HostThunk::LdapFirstEntry | HostThunk::LdapNextEntry => {
                // The empty result: zero entries, null entry pointers.
                let _session = guest_call_arg(state, memory, 0)?;
                let _message = guest_call_arg_u32(state, memory, 1)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::LdapGetDn | HostThunk::LdapGetValues => {
                let _session = guest_call_arg(state, memory, 0)?;
                let _entry = guest_call_arg(state, memory, 1)?;
                // No entries: a null pointer.
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::LdapMemfree | HostThunk::LdapMsgfree | HostThunk::LdapValueFreeLen => {
                let _block = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(LDAP_SUCCESS));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted LDAP thunk {thunk:?}"),
            )),
        }
    }
}
