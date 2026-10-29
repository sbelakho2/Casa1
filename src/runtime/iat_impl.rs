//! IAT patch bookkeeping and fast-thunk registration helpers.

use super::*;

impl PeHostRuntime {
    /// Register a fast-thunk for the given host thunk address.
    ///
    /// Creates an ARM64 trampoline that calls [`dispatch_import`] for this
    /// thunk address. JIT-compiled blocks can call the trampoline directly
    /// instead of exiting to the dispatch loop, and the dispatch hot path
    /// (`dispatch_import_if_present`) may also use it as a shortcut.
    pub(crate) fn register_fast_thunk(&mut self, thunk_address: u64) {
        // Fast-thunks (direct ARM64 trampoline calls from JIT-compiled code
        // into a single `fast_thunk_host_dispatcher` bridge) are DISABLED.
        //
        // The bridge crashes on a subset of thunks ("fast-thunk dispatch
        // failed for thunk 0x…"), taking down the whole guest — observed on
        // the Tetris smoke guest right after window creation.  The normal
        // `EXIT_THUNK` path (JIT block returns to the dispatcher, which runs
        // the full dispatch_import match) is correct for every thunk, so we
        // route all host calls through it.  JIT-compiled compute blocks still
        // run natively; only host calls pay the dispatcher round-trip.
        let _ = (self, thunk_address);
    }

    /// Mirror the direct thunk addresses that the loader just wrote into the
    /// guest IAT.  The guest image remains the source of truth (readable and
    /// writable); the table is used to re-resolve and invalidate entries when
    /// a thunk changes or a module unloads.
    pub(crate) fn record_iat_bindings(
        &mut self,
        selected_base: u64,
        memory: &mut MemoryImage,
        imports: &[ResolvedImport],
    ) {
        let arch = self.guest_arch;
        for import in imports {
            let slot_va = selected_base.wrapping_add(u64::from(import.iat_rva));
            let Ok(value) = read_guest_pointer(memory, slot_va, arch) else {
                continue;
            };
            if value == 0 {
                continue;
            }
            // Re-assert the direct host-thunk address in the guest IAT.  This
            // is idempotent after the loader's normal binding, but it makes the
            // patch an explicit, observable guest-memory write.
            if write_guest_pointer(memory, slot_va, value, arch).is_err() {
                continue;
            }
            if let Some(thunk) = self.host_thunks.get(&value)
                && let Some(api) = crate::jit::InlineApi::from_thunk(thunk)
            {
                crate::jit::register_inline_api_target(value, api);
            }
            let module_handle = self
                .module_handles
                .iter()
                .find(|(name, _)| {
                    normalize_module_name(name) == normalize_module_name(&import.resolved_module)
                })
                .map(|(_, handle)| *handle)
                .unwrap_or(0);
            self.iat_patches.patch(IatPatchEntry {
                slot_va,
                selected_base,
                iat_rva: import.iat_rva,
                module: import.resolved_module.clone(),
                symbol: import.symbol.clone(),
                bound_value: value,
                patched_value: value,
                module_handle,
            });
        }
    }

    /// Record a delay-load resolution (the first call has just overwritten the
    /// slot with the resolved host address).
    pub(crate) fn record_iat_resolution(
        &mut self,
        resolved_module: &str,
        symbol: ImportSymbol,
        iat_rva: u32,
        selected_base: u64,
        resolved_value: u64,
        memory: &MemoryImage,
    ) {
        let slot_va = selected_base.wrapping_add(u64::from(iat_rva));
        let bound_value =
            read_guest_pointer(memory, slot_va, self.guest_arch).unwrap_or(resolved_value);
        let module_handle = self
            .module_handles
            .iter()
            .find(|(name, _)| normalize_module_name(name) == normalize_module_name(resolved_module))
            .map(|(_, handle)| *handle)
            .unwrap_or(0);
        self.iat_patches.patch(IatPatchEntry {
            slot_va,
            selected_base,
            iat_rva,
            module: resolved_module.to_string(),
            symbol,
            bound_value,
            patched_value: resolved_value,
            module_handle,
        });
    }

    /// Propagate a replaced host thunk into every still-patched IAT slot.
    /// Slots the guest itself rewrote are left untouched (the IAT is guest
    /// memory and guest writes win).
    #[allow(dead_code)]
    pub fn re_resolve_iat_thunk(
        &mut self,
        old_thunk: u64,
        new_thunk: u64,
        memory: &mut MemoryImage,
    ) -> AppResult<usize> {
        let slots = self.iat_patches.slots_for_target(old_thunk);
        let arch = self.guest_arch;
        let mut written = 0;
        for slot in slots {
            let Ok(current) = read_guest_pointer(memory, slot, arch) else {
                continue;
            };
            // Guest writes win: a slot the guest changed is left alone and the
            // tracking entry keeps describing the value actually in memory.
            if current != old_thunk {
                continue;
            }
            self.iat_patches.set_patched_value(slot, new_thunk);
            write_guest_pointer(memory, slot, new_thunk, arch)?;
            written += 1;
        }
        Ok(written)
    }

    /// Invalidate every patched slot that belongs to `module_handle`.  The slot
    /// is re-armed with a fresh `DelayLoadResolve` thunk, so the next call
    /// re-resolves the module instead of jumping into unloaded code.
    pub(crate) fn invalidate_module_iat(
        &mut self,
        module_handle: u64,
        memory: &mut MemoryImage,
    ) -> AppResult<usize> {
        let slots = self.iat_patches.slots_for_module(module_handle);
        let arch = self.guest_arch;
        let mut invalidated = 0;
        for slot in slots {
            let Some(entry) = self.iat_patches.entry(slot).cloned() else {
                continue;
            };
            let Ok(current) = read_guest_pointer(memory, slot, arch) else {
                continue;
            };
            if current != entry.patched_value {
                continue;
            }
            let resolver = self.alloc_host_thunk(HostThunk::DelayLoadResolve {
                resolved_module: entry.module.clone(),
                symbol: entry.symbol.clone(),
                iat_rva: entry.iat_rva,
                selected_base: entry.selected_base,
            });
            write_guest_pointer(memory, slot, resolver, arch)?;
            self.iat_patches.unpatch(slot);
            self.iat_patches.invalidated += 1;
            invalidated += 1;
        }
        Ok(invalidated)
    }

    #[allow(dead_code)]
    pub fn iat_metrics(&self) -> IatMetrics {
        self.iat_patches.metrics()
    }
}
