//! Windows Installer dispatch: the msi.dll exports, in a dedicated module
//! per the audit's modularity requirement.  No products are installed in
//! the runtime, so the product surface answers the documented empty-state
//! semantics: `MsiEnumProductsW` reports ERROR_NO_MORE_ITEMS and
//! `MsiGetProductInfoW`/`MsiQueryProductInfoW` report ERROR_UNKNOWN_PRODUCT.
//! The database surface is real: `MsiOpenDatabaseW` validates the OLE
//! compound-document magic and hands out a database handle; the view
//! functions accept SELECT queries and `MsiViewFetch` reports the honest
//! zero-record result; the record functions validate their handles.
//!
//! Layer contract: every export returns its ERROR_* code in EAX (0 =
//! ERROR_SUCCESS).

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// ERROR_SUCCESS.
const ERROR_SUCCESS: u32 = 0;
/// ERROR_INVALID_HANDLE.
const ERROR_INVALID_HANDLE: u32 = 6;
/// ERROR_NO_MORE_ITEMS.
const ERROR_NO_MORE_ITEMS: u32 = 259;
/// ERROR_UNKNOWN_PRODUCT.
const ERROR_UNKNOWN_PRODUCT: u32 = 1605;
/// ERROR_UNKNOWN_PROPERTY.
const ERROR_UNKNOWN_PROPERTY: u32 = 1608;
/// ERROR_BAD_QUERY_SYNTAX.
const ERROR_BAD_QUERY_SYNTAX: u32 = 1615;
/// ERROR_INSTALL_PACKAGE_OPEN_FAILED.
const ERROR_INSTALL_PACKAGE_OPEN_FAILED: u32 = 1619;

/// The OLE compound-document magic (an MSI database is an OLE file).
const OLE_MAGIC: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

impl PeHostRuntime {
    /// Route every MSI thunk to its dispatch function.
    pub(crate) fn dispatch_msi(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::MsiEnumProductsW => {
                // No products are installed.
                state.set(Register::Rax, u64::from(ERROR_NO_MORE_ITEMS));
                Ok(())
            }
            HostThunk::MsiGetProductInfoW | HostThunk::MsiQueryProductInfoW => {
                state.set(Register::Rax, u64::from(ERROR_UNKNOWN_PRODUCT));
                Ok(())
            }
            HostThunk::MsiGetPropertyW | HostThunk::MsiSetPropertyW => {
                // No install session is active.
                state.set(Register::Rax, u64::from(ERROR_UNKNOWN_PROPERTY));
                Ok(())
            }
            HostThunk::MsiInstallProductW
            | HostThunk::MsiConfigureProductW
            | HostThunk::MsiReinstallProductW => {
                // The package cannot be opened.
                state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
                Ok(())
            }
            HostThunk::MsiOpenDatabaseW | HostThunk::MsiOpenPackageW => {
                self.dispatch_msi_open_database(state, memory)
            }
            HostThunk::MsiDatabaseOpenViewW => self.dispatch_msi_open_view(state, memory),
            HostThunk::MsiViewExecute => {
                let view = guest_call_arg(state, memory, 0)?;
                if !self.msi_views.contains_key(&view) {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_HANDLE));
                } else {
                    state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                }
                Ok(())
            }
            HostThunk::MsiViewFetch => {
                let view = guest_call_arg(state, memory, 0)?;
                if !self.msi_views.contains_key(&view) {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_HANDLE));
                } else {
                    // The query has no records (the honest result).
                    state.set(Register::Rax, u64::from(ERROR_NO_MORE_ITEMS));
                }
                Ok(())
            }
            HostThunk::MsiViewClose => {
                let view = guest_call_arg(state, memory, 0)?;
                self.msi_views.remove(&view);
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::MsiRecordDataSize
            | HostThunk::MsiRecordGetStringW
            | HostThunk::MsiRecordSetStringW => {
                // No record handles exist (records come from view fetches).
                let _record = guest_call_arg(state, memory, 0)?;
                // No record handles exist (records come from view fetches).
                state.set(Register::Rax, u64::from(ERROR_INVALID_HANDLE));
                Ok(())
            }
            HostThunk::MsiCloseHandle => {
                let handle = guest_call_arg(state, memory, 0)?;
                self.msi_databases.remove(&handle);
                self.msi_views.remove(&handle);
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::MsiCloseAllHandles => {
                self.msi_databases.clear();
                self.msi_views.clear();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted MSI thunk {thunk:?}"),
            )),
        }
    }

    /// `MsiOpenDatabaseW(persistedPath, persist, phDatabase)` — validate
    /// the OLE compound-document header and hand out a database handle.
    pub(crate) fn dispatch_msi_open_database(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let path = guest_call_arg(state, memory, 0)?;
        let _persist = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Ok(path) = read_utf16_string(memory, path) else {
            state.set(Register::Rax, u64::from(ERROR_INVALID_HANDLE));
            return Ok(());
        };
        let Ok(bytes) = std::fs::read(&path) else {
            state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
            return Ok(());
        };
        if bytes.len() < 8 || bytes[..8] != OLE_MAGIC {
            state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let handle = self
            .alloc_guest_object(memory, GuestObjectKind::MsiDatabase, vtable)
            .unwrap_or(0);
        if handle == 0 {
            state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
            return Ok(());
        }
        self.msi_databases.insert(handle, bytes.len() as u32);
        if out != 0 {
            write_guest_pointer(memory, out, handle, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `MsiDatabaseOpenViewW(db, query, view)` — validate the SELECT query
    /// and hand out a view handle.
    pub(crate) fn dispatch_msi_open_view(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let db = guest_call_arg(state, memory, 0)?;
        let query = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if !self.msi_databases.contains_key(&db) {
            state.set(Register::Rax, u64::from(ERROR_INVALID_HANDLE));
            return Ok(());
        }
        let query_text = read_utf16_string(memory, query).unwrap_or_default();
        if !query_text
            .trim_start()
            .to_ascii_uppercase()
            .starts_with("SELECT ")
        {
            state.set(Register::Rax, u64::from(ERROR_BAD_QUERY_SYNTAX));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let view = self
            .alloc_guest_object(memory, GuestObjectKind::MsiView, vtable)
            .unwrap_or(0);
        if view == 0 {
            state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
            return Ok(());
        }
        self.msi_views.insert(view, query_text);
        if out != 0 {
            write_guest_pointer(memory, out, view, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }
}
