// Stage-3 canonical-state surface: the Win32Subsystem integration that consumes these types is the next work item; removing this allowance is part of that integration.
//! Canonical handle table.
//!
//! ONE generation-protected handle table backs the `Win32Subsystem`: handle
//! values are minted here (recycling closed values FIFO like Windows),
//! generation counters are bumped on every close so stale references are
//! detectable, `DuplicateHandle` / `CloseHandle` mechanics and
//! `Get/SetHandleInformation` semantics live here.
//!
//! A [`HandleEntry`] never owns object state: it references a kernel object
//! by [`ObjectId`](crate::runtime::object_manager::ObjectId) in the
//! [`ObjectManager`](crate::runtime::object_manager::ObjectManager).

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::runtime::object_manager::{ObjectId, ObjectType};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Sentinel value used by Win32 to indicate an invalid handle.
/// All bits set (0xFFFF_FFFF).
pub const INVALID_HANDLE_VALUE: u32 = u32::MAX;

/// A win32 handle value.
pub type Handle = u32;

/// The `SetHandleInformation` flag mask values.
pub const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
pub const HANDLE_FLAG_PROTECT_FROM_CLOSE: u32 = 0x0000_0002;

/// One live handle: references an object by id, carries the granted access
/// mask, the inheritance flag, the close-protection flag and the generation
/// of this handle-value incarnation.
#[derive(Debug, Clone)]
pub struct HandleEntry {
    pub object_id: ObjectId,
    /// Monotonically increasing generation counter.  Incremented every time
    /// the same handle value is reused so that stale references (cached
    /// before the handle was closed) can be detected.
    pub generation: u32,
    pub access_mask: u32,
    pub inheritable: bool,
    pub protect_from_close: bool,
}

/// The canonical handle table.
#[derive(Debug, Clone)]
pub struct HandleTable {
    entries: BTreeMap<Handle, HandleEntry>,
    /// Per-handle-value generation counters.  When a handle value is reused
    /// after being closed, the generation is incremented so that stale
    /// references can be detected.
    generations: BTreeMap<Handle, u32>,
    /// Closed handle values recycled by `insert` (FIFO, so the oldest freed
    /// value is reused first, which keeps generations meaningful).
    closed_handle_values: VecDeque<Handle>,
    /// Handles protected from close via `HANDLE_FLAG_PROTECT_FROM_CLOSE`.
    protected_close_handles: BTreeSet<Handle>,
    /// Handle-type history for diagnostics: every handle value ever
    /// allocated maps to its most recent object type.
    handle_history: BTreeMap<Handle, ObjectType>,
    /// Recently closed (handle, type) pairs for diagnostics.
    recently_closed_handles: VecDeque<(Handle, ObjectType)>,
    /// Next fresh handle value (used only when no closed value is recycled).
    next_handle: Handle,
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // Stage-3 integration pending
impl HandleTable {
    #[allow(dead_code)] // Stage-3 integration pending
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            generations: BTreeMap::new(),
            closed_handle_values: VecDeque::new(),
            protected_close_handles: BTreeSet::new(),
            handle_history: BTreeMap::new(),
            recently_closed_handles: VecDeque::new(),
            next_handle: 4,
        }
    }

    /// Allocate a handle referencing `object_id`, recycling closed values
    /// (FIFO) like Windows does, so closed values are reused and generation
    /// counters can detect stale references.
    pub fn insert(&mut self, object_id: ObjectId, access_mask: u32, inheritable: bool) -> Handle {
        let handle = if let Some(handle) = self.closed_handle_values.pop_front() {
            handle
        } else {
            let handle = self.next_handle;
            self.next_handle = self.next_handle.saturating_add(4);
            handle
        };
        let generation = self.generations.get(&handle).copied().unwrap_or(0);
        self.entries.insert(
            handle,
            HandleEntry {
                object_id,
                generation,
                access_mask,
                inheritable,
                protect_from_close: false,
            },
        );
        handle
    }

    /// Record (or refresh) the object-type history of a handle value after
    /// insertion, for `invalid_handle_error` diagnostics.
    pub fn record_history(&mut self, handle: Handle, object_type: ObjectType) {
        self.handle_history.insert(handle, object_type);
        // Keep only recent history for diagnostics; it grows one entry per
        // handle value ever allocated.
        if self.handle_history.len() > 1024 {
            self.handle_history.pop_first();
        }
    }

    /// The entry for a live handle, or an invalid-handle error.
    pub fn entry(&self, handle: Handle) -> AppResult<&HandleEntry> {
        self.entries
            .get(&handle)
            .ok_or_else(|| self.invalid_handle_error(handle))
    }

    /// Mutable entry access for a live handle.
    pub fn entry_mut(&mut self, handle: Handle) -> AppResult<&mut HandleEntry> {
        if self.entries.contains_key(&handle) {
            Ok(self.entries.get_mut(&handle).expect("checked contains_key"))
        } else {
            Err(self.invalid_handle_error(handle))
        }
    }

    pub fn get(&self, handle: Handle) -> Option<&HandleEntry> {
        self.entries.get(&handle)
    }

    pub fn get_mut(&mut self, handle: Handle) -> Option<&mut HandleEntry> {
        self.entries.get_mut(&handle)
    }

    pub fn is_live(&self, handle: Handle) -> bool {
        self.entries.contains_key(&handle)
    }

    /// Iterate the live entries (handle value, entry).
    pub fn iter(&self) -> impl Iterator<Item = (Handle, &HandleEntry)> {
        self.entries.iter().map(|(handle, entry)| (*handle, entry))
    }

    /// Iterate the live entries mutably.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (Handle, &mut HandleEntry)> {
        self.entries
            .iter_mut()
            .map(|(handle, entry)| (*handle, entry))
    }

    /// The generation of a live handle's entry.
    pub fn handle_generation(&self, handle: Handle) -> Option<u32> {
        self.entries.get(&handle).map(|entry| entry.generation)
    }

    /// The next fresh handle value (diagnostics: anonymous-pipe name
    /// derivation in the subsystem).
    pub fn next_handle_value(&self) -> Handle {
        self.next_handle
    }

    /// Validate that a cached `(handle, generation)` pair still matches the
    /// live entry.  Returns `Ok(())` if the handle is alive and its
    /// generation has not changed, or an `RcHandleStaleOrInvalid` error
    /// otherwise.
    pub fn validate_handle_generation(
        &self,
        handle: Handle,
        expected_generation: u32,
    ) -> AppResult<()> {
        match self.entries.get(&handle) {
            Some(entry) if entry.generation == expected_generation => Ok(()),
            Some(_) => Err(AppError::new(
                ReasonCode::RcHandleStaleOrInvalid,
                format!("handle {handle} generation mismatch — stale reference detected"),
            )),
            None => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid handle {handle}"),
            )),
        }
    }

    /// `SetHandleInformation` / `GetHandleInformation`-style flag mutation.
    /// `mask` selects the flags (`HANDLE_FLAG_INHERIT`,
    /// `HANDLE_FLAG_PROTECT_FROM_CLOSE`) to change; `flags` supplies the new
    /// values.  Unhandled mask bits are ignored.
    pub fn set_handle_information(
        &mut self,
        handle: Handle,
        mask: u32,
        flags: u32,
    ) -> AppResult<()> {
        if mask & HANDLE_FLAG_INHERIT != 0 {
            self.entry_mut(handle)?.inheritable = flags & HANDLE_FLAG_INHERIT != 0;
        }
        if mask & HANDLE_FLAG_PROTECT_FROM_CLOSE != 0 {
            if flags & HANDLE_FLAG_PROTECT_FROM_CLOSE != 0 {
                self.protected_close_handles.insert(handle);
            } else {
                self.protected_close_handles.remove(&handle);
            }
        }
        Ok(())
    }

    /// True when the handle is protected from close.
    pub fn is_protected(&self, handle: Handle) -> bool {
        self.protected_close_handles.contains(&handle)
    }

    /// Remove the close protection of a handle (used when a protected
    /// handle closes successfully).
    fn clear_protection(&mut self, handle: Handle) {
        self.protected_close_handles.remove(&handle);
    }

    /// `CloseHandle` mechanics: removes the entry, bumps the generation of
    /// the handle value, recycles the value, records the close history.
    /// Sockets are rejected here too — they are winsock handles, not kernel
    /// handles: `CloseHandle` on a SOCKET fails with ERROR_INVALID_HANDLE
    /// (with the unified namespace this is enforced by type, so a socket
    /// value can never close a recycled win32 object).
    ///
    /// The caller receives the removed entry so subsystem-level teardown
    /// (file/pipe cleanup, thread state cleanup) can run against the object
    /// BEFORE the object manager drops it.
    pub fn close(&mut self, handle: Handle, object_type: ObjectType) -> AppResult<HandleEntry> {
        if self.is_protected(handle) {
            return Err(AppError::new(
                ReasonCode::RcHelperPermissionDenied,
                format!("handle {handle} is protected from close"),
            ));
        }
        if object_type == ObjectType::Socket {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("handle {handle} is a socket, not a kernel handle"),
            ));
        }
        self.close_raw(handle)
    }

    /// Removal mechanics without the socket rejection — the winsock
    /// `closesocket` path.  Close protection is still enforced (Windows
    /// `closesocket` honors `HANDLE_FLAG_PROTECT_FROM_CLOSE`).
    pub fn close_raw(&mut self, handle: Handle) -> AppResult<HandleEntry> {
        if self.is_protected(handle) {
            return Err(AppError::new(
                ReasonCode::RcHelperPermissionDenied,
                format!("handle {handle} is protected from close"),
            ));
        }
        let entry = self.entries.remove(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid handle {handle}"),
            )
        })?;
        self.clear_protection(handle);
        let generation = self.generations.entry(handle).or_insert(0);
        *generation = generation.saturating_add(1);
        self.closed_handle_values.push_back(handle);
        self.recently_closed_handles
            .push_back((handle, ObjectType::Socket));
        while self.recently_closed_handles.len() > 32 {
            self.recently_closed_handles.pop_front();
        }
        Ok(entry)
    }

    /// `DuplicateHandle` mechanics: validates the source and mints a new
    /// handle with the computed access mask referencing the SAME object.
    /// Closing the source (when requested) is the subsystem adapter's job so
    /// its domain teardown side effects run.
    pub fn duplicate(
        &mut self,
        source_handle: Handle,
        access_mask: u32,
        inheritable: bool,
    ) -> AppResult<Handle> {
        let source = self.entry(source_handle)?.clone();
        Ok(self.insert(source.object_id, access_mask, inheritable))
    }

    /// The invalid-handle error for `handle`, decorated with diagnostics
    /// from the type history / recently-closed list when available.
    pub fn invalid_handle_error(&self, handle: Handle) -> AppError {
        let mut message = format!("invalid handle {handle}");
        if let Some(object_type) = self.handle_history.get(&handle) {
            message.push_str(&format!(" (known as {object_type:?})"));
        } else if let Some((_, object_type)) = self
            .recently_closed_handles
            .iter()
            .rev()
            .find(|(closed_handle, _)| *closed_handle == handle)
        {
            message.push_str(&format!(" (recently closed {object_type:?})"));
        }
        AppError::new(ReasonCode::RcWin32InvalidHandle, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_with_objects() -> (HandleTable, Handle) {
        let mut table = HandleTable::new();
        let id = ObjectId(42);
        let handle = table.insert(id, 0x1F0003, false);
        table.record_history(handle, ObjectType::Event);
        (table, handle)
    }

    #[test]
    fn generations_start_at_zero_and_increment_on_close() {
        let (mut table, handle) = table_with_objects();
        assert_eq!(table.handle_generation(handle), Some(0));
        assert!(table.validate_handle_generation(handle, 0).is_ok());
        assert!(table.validate_handle_generation(handle, 1).is_err());

        table
            .close(handle, ObjectType::Event)
            .expect("close handle");
        assert!(table.handle_generation(handle).is_none(), "handle closed");
        assert!(table.validate_handle_generation(handle, 0).is_err());
    }

    #[test]
    fn closed_values_are_recycled_with_a_fresh_generation() {
        let mut table = HandleTable::new();
        let id = ObjectId(7);
        let first = table.insert(id, 0, false);
        table.record_history(first, ObjectType::File);
        table.close(first, ObjectType::File).expect("close");
        let second = table.insert(id, 0, false);
        table.record_history(second, ObjectType::File);
        assert_eq!(second, first, "closed values are recycled FIFO");
        assert_eq!(
            table.handle_generation(second),
            Some(1),
            "reuse gets a fresh generation"
        );
        assert!(
            table.validate_handle_generation(second, 0).is_err(),
            "a stale (value, generation) pair is rejected"
        );
        assert!(table.validate_handle_generation(second, 1).is_ok());
    }

    #[test]
    fn protected_handles_cannot_be_closed() {
        let (mut table, handle) = table_with_objects();
        table
            .set_handle_information(
                handle,
                HANDLE_FLAG_PROTECT_FROM_CLOSE,
                HANDLE_FLAG_PROTECT_FROM_CLOSE,
            )
            .expect("protect");
        let error = table.close(handle, ObjectType::Event).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcHelperPermissionDenied);
        assert!(table.is_live(handle), "protected handle survives");
        table
            .set_handle_information(handle, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0)
            .expect("unprotect");
        table.close(handle, ObjectType::Event).expect("close now");
    }

    #[test]
    fn sockets_are_rejected_by_close_and_duplicate_is_generation_safe() {
        let mut table = HandleTable::new();
        let id = ObjectId(9);
        let socket = table.insert(id, 0, false);
        table.record_history(socket, ObjectType::Socket);
        let error = table.close(socket, ObjectType::Socket).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcWin32InvalidHandle);
        assert!(table.is_live(socket));

        let source = table.insert(ObjectId(10), 0x1F0003, false);
        let dup = table.duplicate(source, 0x1F0003, true).expect("dup");
        assert_ne!(dup, source);
        assert_eq!(table.get(dup).expect("dup entry").object_id, ObjectId(10));
        assert!(table.get(dup).expect("dup entry").inheritable);
        table
            .close(source, ObjectType::Mutex)
            .expect("close source");
        assert!(table.is_live(dup), "duplicate survives source close");
    }

    #[test]
    fn set_handle_information_mutates_inheritable_flag() {
        let (mut table, handle) = table_with_objects();
        assert!(!table.get(handle).expect("entry").inheritable);
        table
            .set_handle_information(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
            .expect("set inherit");
        assert!(table.get(handle).expect("entry").inheritable);
        table
            .set_handle_information(handle, HANDLE_FLAG_INHERIT, 0)
            .expect("clear inherit");
        assert!(!table.get(handle).expect("entry").inheritable);
    }

    #[test]
    fn invalid_handle_error_records_history_and_recent_closes() {
        let table = HandleTable::new();
        let message = table.invalid_handle_error(0x1234).to_string();
        assert!(message.contains("invalid handle 4660"));

        let mut table = HandleTable::new();
        let handle = table.insert(ObjectId(5), 0, false);
        table.record_history(handle, ObjectType::Timer);
        table.close(handle, ObjectType::Timer).expect("close");
        let message = table.invalid_handle_error(handle).to_string();
        assert!(
            message.contains("Timer"),
            "diagnostics carry the object type: {message}"
        );
        // A handle value that was NEVER allocated has no diagnostics.
        let message = table.invalid_handle_error(0x0BAD).to_string();
        assert!(!message.contains("known as"), "diagnostics: {message}");
    }
}
