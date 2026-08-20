//! Stage-4 NTDLL — the Ldr loader surface: `LdrLoadDll`,
//! `LdrUnloadDll`, `LdrGetDllHandle`, `LdrGetProcedureAddress`, the
//! loader-lock protocol (`LdrLockLoaderLock` / `LdrUnlockLoaderLock`) and
//! the refcount primitives (`LdrAddRefDll` / `LdrRemoveRefDll`).
//!
//! ONE loader: every Ldr entry point here is a thin semantic wrapper over
//! the SAME machinery the Win32 `LoadLibraryW` / `GetProcAddress` /
//! `FreeLibrary` thunks use (`crate::runtime::loader` — the
//! `resolve_load_library_handle` / `lookup_module_handle` /
//! `resolve_proc_address` / `search_dll_paths` / `load_real_dll` surface and
//! the pending-DllMain queue).  There is exactly ONE implementation of "how
//! a module loads"; the Ldr layer only adds the native protocol: NTSTATUS
//! results, `UNICODE_STRING` / `ANSI_STRING` names, the loader-lock cookie
//! protocol and the explicit refcount primitives.
//!
//! Documented semantics and divergences:
//! - `LdrLoadDll` resolves through `resolve_load_library_handle`
//!   (synthetic modules, real on-disk DLLs, forwarders) and returns the
//!   module handle.  A newly loaded real DLL's `DLL_PROCESS_ATTACH` + TLS
//!   callbacks are queued by the loader itself (the loader queues the
//!   entry-point call at the TAIL of the FIFO `pending_dll_main_calls`, so
//!   a later `LdrLoadDll` appends AFTER the currently loaded modules — the
//!   drain fires TLS callbacks and DllMain in load order).  An already
//!   loaded module returns the SAME handle and only increments the
//!   refcount — `DllMain` is never re-fired.  `DllCharacteristics` is
//!   ignored-but-accepted; `SearchPath` is ignored (module-name resolution
//!   routes through the same dll-path search as `LoadLibraryW`).
//! - `LdrUnloadDll` decrements the refcount; at 0 it queues
//!   `DLL_PROCESS_DETACH` (+ TLS callbacks, fired by the drain AFTER
//!   DllMain, matching Windows) and removes the module (the handle is no
//!   longer findable).  Real host-backed DLLs keep their `libloading`
//!   library alive in a detach-only list — the runtime never closes host
//!   library handles (mirrors the existing teardown).  The DllInfo record
//!   is kept as a tombstone so the QUEUED detach drain still finds the
//!   module's TLS callbacks.
//! - Unloading the main module is REFUSED: `STATUS_INVALID_PARAMETER`
//!   (never fires `DLL_PROCESS_DETACH` for the main image).  Real Windows
//!   pins the main image (`LoadCount == 0xFFFFFFFF`); Wine and ReactOS
//!   treat the pinned image as a silent no-op and no authoritative NTSTATUS
//!   for the failure is documented, so per the loader-spec fallback the
//!   wrapper fails with `STATUS_INVALID_PARAMETER` (documented choice).
//! - `LdrGetDllHandle` NEVER loads: it is `lookup_module_handle` +
//!   `STATUS_DLL_NOT_FOUND` (0xC0000135) for a module that is not loaded.
//!   Comparison is case-insensitive (normalized like the loader does).
//! - `LdrGetProcedureAddress` resolves through `resolve_proc_address`
//!   (names and ordinals use the SAME machinery import resolution uses:
//!   real-DLL export maps, synthetic export tables, forwarder chains).
//!   Unknown exports → `STATUS_ENTRYPOINT_NOT_FOUND` (0xC0000139); an
//!   unknown module handle → `STATUS_DLL_NOT_FOUND` (Wine behavior).
//!   Ordinal resolution for real host-backed DLLs is limited to the named
//!   exports `load_real_dll` thunked (ordinal-only exports are not indexed
//!   by that path — the same limitation import resolution has).
//! - Loader-lock protocol: the runtime models the process-wide loader lock
//!   implicitly (single-threaded guest context pump); the Ldr lock is the
//!   PROTOCOL boundary — a synthetic owner cookie + reentrancy depth.
//!   `LdrLockLoaderLock` is reentrant (recursive acquires succeed, each
//!   minting a thread-keyed cookie like ReactOS's `LdrpMakeCookie`);
//!   `LdrUnlockLoaderLock` validates the cookie's thread bits and decrements
//!   the depth (0 releases).  A `LdrLoadDll`/`LdrUnloadDll` inside a locked
//!   region still works — the cooperative model serializes anyway.
//! - `LdrAddRefDll` / `LdrRemoveRefDll` are the refcount primitives:
//!   `LDR_ADDREF_DLL_PIN` pins a module (it can no longer reach 0),
//!   `LDR_REMOVE_REF_DLL_PIN` unpins; the plain forms increment/decrement
//!   the load count exactly like the Win32 `LoadLibrary`/`FreeLibrary`
//!   thunks count (both tracks — `DllInfo::load_count` AND
//!   `RealDllState::refcount` — stay in step).  Removing the last
//!   reference queues `DLL_PROCESS_DETACH` like `FreeLibrary`; the module
//!   itself stays loaded (only `LdrUnloadDll` removes it).
//! - `LdrGetDllDirectory` / `LdrSetDllDirectory` are NOT implemented: the
//!   loader machinery has no dll-search-path override concept
//!   (`search_dll_paths` is a fixed app→System32→Windows→PATH walk).
//! - `LdrInitializeThunk` is NOT added: the runtime's process bootstrap
//!   (`stage_main_module` / `seed_process_state` / the main-image TLS
//!   attach path) already covers first-module initialization; there is no
//!   explicit LdrInitializeThunk path and a fake one would not be honest.

use crate::ntdll::{
    LDR_ADDREF_DLL_FLAG_MASK, LDR_ADDREF_DLL_PIN, LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED,
    LDR_REMOVE_REF_DLL_FLAG_MASK, LDR_REMOVE_REF_DLL_PIN, NtStatus, STATUS_DLL_NOT_FOUND,
    STATUS_ENTRYPOINT_NOT_FOUND, STATUS_INVALID_PARAMETER,
};
use crate::pe::ImportSymbol;
use crate::runtime::{DLL_PROCESS_DETACH, PeHostRuntime, normalize_module_name};

impl PeHostRuntime {
    /// `LdrLoadDll` — the native load entry point.
    ///
    /// Resolves the module through the shared loader machinery
    /// ([`PeHostRuntime::resolve_load_library_handle`]: synthetic +
    /// real-dll paths), returns the module handle.  DllMain/TLS firing is
    /// the loader's deferred FIFO behavior (see the module docs): a NEW
    /// load appends its `DLL_PROCESS_ATTACH` AFTER everything queued
    /// before it; an ALREADY loaded module gets the same handle and only a
    /// refcount increment.
    pub(crate) fn ldr_load_dll(&mut self, module_name: &str) -> Result<u64, NtStatus> {
        if module_name.trim().is_empty() {
            // An empty module name has nothing to resolve.
            return Err(STATUS_DLL_NOT_FOUND);
        }
        let (handle, last_error) = self.resolve_load_library_handle(module_name);
        if handle == 0 {
            // The machinery reports ERROR_MOD_NOT_FOUND for a failed
            // search; the native surface maps it to STATUS_DLL_NOT_FOUND.
            return Err(crate::ntdll::dos_error_to_nt_status(last_error));
        }
        Ok(handle)
    }

    /// `LdrUnloadDll` — decrement the refcount; at 0 queue
    /// `DLL_PROCESS_DETACH` (+ TLS callbacks through the pending queue) and
    /// remove the module.  See the module docs for the main-module refusal
    /// and the detach-only host-library list.
    pub(crate) fn ldr_unload_dll(&mut self, module_handle: u64) -> Result<(), NtStatus> {
        // The main module is pinned and can never be unloaded (the loader
        // must never fire DLL_PROCESS_DETACH for the main image).
        if module_handle == self.mapped_image_base {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some(module_name) = self.module_names_by_handle.get(&module_handle).cloned() else {
            return Err(STATUS_DLL_NOT_FOUND);
        };
        let normalized = normalize_module_name(&module_name);

        let mut last_release = false;
        if let Some(info) = self.dll_info_table.get_mut(&module_handle) {
            if info.load_count != u32::MAX && info.load_count > 0 {
                info.load_count -= 1;
            }
            if info.load_count == 0 {
                last_release = true;
                // Queue DLL_PROCESS_DETACH: the drain fires TLS callbacks
                // AFTER DllMain for detach reasons, matching Windows.  The
                // DllInfo record stays as a tombstone so the queued drain
                // still finds the TLS callbacks.
                if info.entry_point_rva != 0 {
                    self.pending_dll_main_calls.push_back((
                        module_handle,
                        info.entry_point_rva,
                        DLL_PROCESS_DETACH,
                    ));
                }
            }
        }
        if let Some(state) = self.loaded_real_dlls.get_mut(&normalized) {
            if state.refcount > 0 {
                state.refcount -= 1;
            }
            if state.refcount == 0 {
                last_release = true;
            }
        }

        if last_release {
            // Real host-backed DLLs: the guest module is gone, but the
            // libloading host library stays alive in the detach-only list
            // (the runtime never closes host library handles).
            if let Some(state) = self.loaded_real_dlls.remove(&normalized) {
                self.detached_real_dlls.push(state);
            }
            self.module_handles.remove(&normalized);
            self.module_names_by_handle.remove(&module_handle);
            self.module_paths_by_handle.remove(&module_handle);
            self.synthetic_module_handles.remove(&module_handle);
            self.materialized_synthetic_modules.remove(&module_handle);
        }
        Ok(())
    }

    /// `LdrGetDllHandle` — find a loaded module by name; NEVER loads.
    /// Not-found is `STATUS_DLL_NOT_FOUND`; the comparison is
    /// case-insensitive through the loader's normalization.
    pub(crate) fn ldr_get_dll_handle(&self, module_name: &str) -> Result<u64, NtStatus> {
        if module_name.trim().is_empty() {
            // A caller bug: no module name to search for.
            return Err(STATUS_INVALID_PARAMETER);
        }
        match self.lookup_module_handle(module_name) {
            Some(handle) => Ok(handle),
            None => Err(STATUS_DLL_NOT_FOUND),
        }
    }

    /// `LdrGetProcedureAddress` — resolve an export by name or ordinal
    /// through the loader's `resolve_proc_address` (the SAME machinery
    /// static import resolution and `GetProcAddress` use).  Unknown exports
    /// are `STATUS_ENTRYPOINT_NOT_FOUND`; an unknown module handle is
    /// `STATUS_DLL_NOT_FOUND` (Wine behavior).
    pub(crate) fn ldr_get_procedure_address(
        &mut self,
        module_handle: u64,
        symbol: ImportSymbol,
    ) -> Result<u64, NtStatus> {
        if module_handle != self.mapped_image_base
            && !self.module_names_by_handle.contains_key(&module_handle)
        {
            return Err(STATUS_DLL_NOT_FOUND);
        }
        let address = self.resolve_proc_address(module_handle, symbol);
        if address == 0 {
            return Err(STATUS_ENTRYPOINT_NOT_FOUND);
        }
        Ok(address)
    }

    /// `LdrLockLoaderLock` — the loader-lock protocol boundary (see the
    /// module docs: the runtime serializes cooperatively; the lock is the
    /// protocol).  Returns `(cookie, disposition)`; the disposition is
    /// always LOCK_ACQUIRED because the cooperative model never contends.
    pub(crate) fn ldr_lock_loader_lock(&mut self) -> (u64, u32) {
        let lock = &mut self.loader_lock;
        lock.sequence = lock.sequence.wrapping_add(1);
        // Thread-keyed cookie like ReactOS's LdrpMakeCookie: the high bits
        // stay clear (cookie & 0xF0000000 == 0 is the validity test).
        let cookie =
            ((u64::from(self.win32.current_thread_id()) & 0xFFF) << 16) | (lock.sequence & 0xFFFF);
        lock.cookie = cookie;
        lock.depth = lock.depth.saturating_add(1);
        (cookie, LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED)
    }

    /// `LdrUnlockLoaderLock` — validate the cookie's thread bits and
    /// decrement the reentrancy depth; depth 0 releases the lock.
    pub(crate) fn ldr_unlock_loader_lock(&mut self, cookie: u64) -> Result<(), NtStatus> {
        if cookie == 0 {
            // A NULL cookie is an explicit no-op unlock.
            return Ok(());
        }
        let lock = &mut self.loader_lock;
        if lock.depth == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // The cookie's thread bits must match the locking thread.
        let thread_bits = (u64::from(self.win32.current_thread_id()) & 0xFFF) << 16;
        if cookie & 0xF000_0000 != 0 || cookie & 0x000F_0000 != thread_bits {
            return Err(STATUS_INVALID_PARAMETER);
        }
        lock.depth -= 1;
        if lock.depth == 0 {
            lock.cookie = 0;
        }
        Ok(())
    }

    /// `LdrAddRefDll` — the refcount primitive: `LDR_ADDREF_DLL_PIN` pins
    /// the module; otherwise the load count increments on BOTH refcount
    /// tracks (the same two tracks the Win32 LoadLibrary/FreeLibrary
    /// thunks count).
    pub(crate) fn ldr_add_ref_dll(
        &mut self,
        flags: u32,
        module_handle: u64,
    ) -> Result<(), NtStatus> {
        if flags & !LDR_ADDREF_DLL_FLAG_MASK != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some(info) = self.dll_info_table.get_mut(&module_handle) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        if flags & LDR_ADDREF_DLL_PIN != 0 {
            // Pinned modules can never be unloaded (Windows models this as
            // LoadCount == -1).
            info.load_count = u32::MAX;
        } else if info.load_count != u32::MAX {
            info.load_count = info.load_count.saturating_add(1);
        }
        if let Some(module_name) = self.module_names_by_handle.get(&module_handle)
            && let Some(state) = self
                .loaded_real_dlls
                .get_mut(&normalize_module_name(module_name))
        {
            state.refcount = state.refcount.saturating_add(1);
        }
        Ok(())
    }

    /// `LdrRemoveRefDll` — the refcount primitive mirror: unpins with
    /// `LDR_REMOVE_REF_DLL_PIN`, otherwise decrements both refcount tracks
    /// and queues `DLL_PROCESS_DETACH` when the count reaches 0 (like the
    /// Win32 FreeLibrary thunk).  The module itself stays loaded — only
    /// [`PeHostRuntime::ldr_unload_dll`] removes it.
    pub(crate) fn ldr_remove_ref_dll(
        &mut self,
        flags: u32,
        module_handle: u64,
    ) -> Result<(), NtStatus> {
        if flags & !LDR_REMOVE_REF_DLL_FLAG_MASK != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some(info) = self.dll_info_table.get_mut(&module_handle) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        if flags & LDR_REMOVE_REF_DLL_PIN != 0 {
            if info.load_count == u32::MAX {
                // Unpin: restore a normal load count.
                info.load_count = 1;
            }
        } else if info.load_count != u32::MAX && info.load_count > 0 {
            info.load_count -= 1;
            if info.load_count == 0 && info.entry_point_rva != 0 {
                self.pending_dll_main_calls.push_back((
                    module_handle,
                    info.entry_point_rva,
                    DLL_PROCESS_DETACH,
                ));
            }
        }
        if let Some(module_name) = self.module_names_by_handle.get(&module_handle)
            && let Some(state) = self
                .loaded_real_dlls
                .get_mut(&normalize_module_name(module_name))
            && state.refcount > 0
        {
            state.refcount -= 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use tempfile::TempDir;

    fn setup() -> (TempDir, PeHostRuntime) {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "ntdll-ldr", GeArch::X64, "win11-23h2")
                .expect("create GE");
        let runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        (temp_dir, runtime)
    }

    #[test]
    fn loader_lock_round_trips_with_reentrancy_depth() {
        let (_tmp, mut runtime) = setup();
        let (cookie1, disposition) = runtime.ldr_lock_loader_lock();
        assert_eq!(disposition, LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED);
        assert_ne!(cookie1, 0);
        assert_eq!(runtime.loader_lock.depth, 1);
        // Reentrant acquire: succeeds, depth grows.
        let (cookie2, _) = runtime.ldr_lock_loader_lock();
        assert_ne!(cookie2, 0);
        assert_eq!(runtime.loader_lock.depth, 2);
        // Release both levels; the cookie thread bits stay valid.
        assert!(runtime.ldr_unlock_loader_lock(cookie2).is_ok());
        assert_eq!(runtime.loader_lock.depth, 1);
        assert!(runtime.ldr_unlock_loader_lock(cookie1).is_ok());
        assert_eq!(runtime.loader_lock.depth, 0);
        // A NULL cookie is a no-op success.
        assert!(runtime.ldr_unlock_loader_lock(0).is_ok());
        // A bogus cookie fails.
        assert_eq!(
            runtime.ldr_unlock_loader_lock(0x1234_5678),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn add_ref_pins_and_remove_ref_unpins() {
        let (_tmp, mut runtime) = setup();
        let handle = runtime.get_or_create_module_handle("pinned.dll");
        runtime
            .ldr_add_ref_dll(LDR_ADDREF_DLL_PIN, handle)
            .expect("pin");
        assert_eq!(
            runtime.dll_info_table.get(&handle).unwrap().load_count,
            u32::MAX
        );
        runtime
            .ldr_remove_ref_dll(LDR_REMOVE_REF_DLL_PIN, handle)
            .expect("unpin");
        assert_eq!(runtime.dll_info_table.get(&handle).unwrap().load_count, 1);
        // Invalid flags fail.
        assert_eq!(
            runtime.ldr_add_ref_dll(0x10, handle),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            runtime.ldr_remove_ref_dll(0x10, handle),
            Err(STATUS_INVALID_PARAMETER)
        );
        // Unknown module fails.
        assert_eq!(
            runtime.ldr_add_ref_dll(0, 0x7777),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}
