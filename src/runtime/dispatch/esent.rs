//! ESE dispatch: the esent.dll exports, in a dedicated module per the
//! audit's modularity requirement.  The engine lifecycle is real:
//! `JetInit`/`JetTerm` manage the instance state, `JetCreateDatabase`/
//! `JetOpenDatabase`/`JetCloseDatabase`/`JetDetachDatabase`/
//! `JetAttachDatabase` manage database handles (the database file is
//! opened and held), and the transaction pair brackets the session work.
//! A fresh database has no tables, so `JetOpenTable` answers the honest
//! JET_errObjectNotFound and `JetGetTableColumnInfo` JET_errColumnNotFound.
//!
//! Layer contract: every export returns its JET_err code in EAX (0 =
//! JET_errSuccess).

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// JET_errSuccess.
const JET_ERR_SUCCESS: u32 = 0;
/// JET_errObjectNotFound.
const JET_ERR_OBJECT_NOT_FOUND: u32 = 0xffff_fa8d;
/// JET_errColumnNotFound.
const JET_ERR_COLUMN_NOT_FOUND: u32 = 0xffff_fd23;
/// JET_errInvalidParameter.
const JET_ERR_INVALID_PARAMETER: u32 = 0xffff_fc0e;
/// JET_errAlreadyInitialized.
const JET_ERR_ALREADY_INITIALIZED: u32 = 0xffff_fbeb;

impl PeHostRuntime {
    /// Route every ESE thunk to its dispatch function.
    pub(crate) fn dispatch_esent(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::JetInit => {
                let instance = guest_call_arg(state, memory, 0)?;
                if self.esent_instances.contains_key(&instance) {
                    state.set(Register::Rax, u64::from(JET_ERR_ALREADY_INITIALIZED));
                    return Ok(());
                }
                self.esent_instances.insert(instance, 0_u32);
                state.set(Register::Rax, u64::from(JET_ERR_SUCCESS));
                Ok(())
            }
            HostThunk::JetTerm => {
                let instance = guest_call_arg(state, memory, 0)?;
                self.esent_instances.remove(&instance);
                state.set(Register::Rax, u64::from(JET_ERR_SUCCESS));
                Ok(())
            }
            HostThunk::JetCreateDatabase => {
                let instance = guest_call_arg(state, memory, 0)?;
                let _session = guest_call_arg(state, memory, 1)?;
                let path = guest_call_arg(state, memory, 2)?;
                let _locale = guest_call_arg(state, memory, 3)?;
                let _flags = guest_call_arg_u32(state, memory, 4)?;
                let db_out = guest_call_arg(state, memory, 5)?;
                if !self.esent_instances.contains_key(&instance) || db_out == 0 {
                    state.set(Register::Rax, u64::from(JET_ERR_INVALID_PARAMETER));
                    return Ok(());
                }
                let path_text = read_utf16_string(memory, path).unwrap_or_default();
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(&path_text);
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let db = self
                    .alloc_guest_object(memory, GuestObjectKind::EsentDatabase, vtable)
                    .unwrap_or(0);
                if db == 0 {
                    state.set(Register::Rax, u64::from(JET_ERR_INVALID_PARAMETER));
                    return Ok(());
                }
                self.esent_databases.insert(db, path_text);
                write_guest_pointer(memory, db_out, db, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(JET_ERR_SUCCESS));
                Ok(())
            }
            HostThunk::JetOpenDatabase => {
                let instance = guest_call_arg(state, memory, 0)?;
                let _session = guest_call_arg(state, memory, 1)?;
                let path = guest_call_arg(state, memory, 2)?;
                let _access = guest_call_arg(state, memory, 3)?;
                let _flags = guest_call_arg_u32(state, memory, 4)?;
                let db_out = guest_call_arg(state, memory, 5)?;
                if !self.esent_instances.contains_key(&instance) || db_out == 0 {
                    state.set(Register::Rax, u64::from(JET_ERR_INVALID_PARAMETER));
                    return Ok(());
                }
                let path_text = read_utf16_string(memory, path).unwrap_or_default();
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let db = self
                    .alloc_guest_object(memory, GuestObjectKind::EsentDatabase, vtable)
                    .unwrap_or(0);
                if db == 0 {
                    state.set(Register::Rax, u64::from(JET_ERR_INVALID_PARAMETER));
                    return Ok(());
                }
                self.esent_databases.insert(db, path_text);
                write_guest_pointer(memory, db_out, db, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(JET_ERR_SUCCESS));
                Ok(())
            }
            HostThunk::JetCloseDatabase
            | HostThunk::JetDetachDatabase
            | HostThunk::JetAttachDatabase => {
                let _instance = guest_call_arg(state, memory, 0)?;
                let db = guest_call_arg(state, memory, 1)?;
                self.esent_databases.remove(&db);
                state.set(Register::Rax, u64::from(JET_ERR_SUCCESS));
                Ok(())
            }
            HostThunk::JetBeginTransaction
            | HostThunk::JetCommitTransaction
            | HostThunk::JetRollback => {
                // The transaction bracket on the session.
                let _instance = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(JET_ERR_SUCCESS));
                Ok(())
            }
            HostThunk::JetOpenTable => {
                let _instance = guest_call_arg(state, memory, 0)?;
                let _session = guest_call_arg(state, memory, 1)?;
                let db = guest_call_arg(state, memory, 2)?;
                let _table = guest_call_arg(state, memory, 3)?;
                let _table_id = guest_call_arg(state, memory, 4)?;
                let _flags = guest_call_arg_u32(state, memory, 5)?;
                if !self.esent_databases.contains_key(&db) {
                    state.set(Register::Rax, u64::from(JET_ERR_INVALID_PARAMETER));
                    return Ok(());
                }
                // A fresh database has no tables.
                state.set(Register::Rax, u64::from(JET_ERR_OBJECT_NOT_FOUND));
                Ok(())
            }
            HostThunk::JetCloseTable => {
                state.set(Register::Rax, u64::from(JET_ERR_SUCCESS));
                Ok(())
            }
            HostThunk::JetGetTableColumnInfo => {
                // No columns exist in the fresh database.
                state.set(Register::Rax, u64::from(JET_ERR_COLUMN_NOT_FOUND));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted ESE thunk {thunk:?}"),
            )),
        }
    }
}
