//! KMDF object model.

use super::*;

impl IslandState {
    /// Parse a `WDF_OBJECT_ATTRIBUTES` block for this architecture.  The
    /// `Size` field bounds which trailing members are honored, matching KMDF's
    /// forward-compatible structure sizing.
    pub(crate) fn parse_object_attributes(
        &self,
        memory: &MemoryImage,
        attributes: u64,
    ) -> AppResult<KmdfObjectAttributes> {
        let mut parsed = KmdfObjectAttributes::default();
        if attributes == 0 {
            return Ok(parsed);
        }
        let pointer_bytes = self.arch.pointer_bytes() as u64;
        let size = memory.read_u32(attributes)? as u64;
        let minimum = match self.arch {
            GuestArch::X64 => 0x38,
            GuestArch::X86 => 0x20,
        };
        if size < 8
            || crate::host_thunks::validate_guest_pointer(
                memory,
                attributes,
                size.min(minimum) as usize,
            )
            .is_err()
        {
            return Ok(parsed);
        }
        let (cleanup_offset, destroy_offset, parent_offset, override_offset, type_offset) =
            match self.arch {
                GuestArch::X64 => (0x08, 0x10, 0x20, 0x28, 0x30),
                GuestArch::X86 => (0x04, 0x08, 0x14, 0x18, 0x1C),
            };
        if size >= cleanup_offset + pointer_bytes {
            parsed.evt_cleanup =
                read_guest_pointer(memory, attributes + cleanup_offset, self.arch)?;
        }
        if size >= destroy_offset + pointer_bytes {
            parsed.evt_destroy =
                read_guest_pointer(memory, attributes + destroy_offset, self.arch)?;
        }
        if size >= parent_offset + pointer_bytes {
            let parent = read_guest_pointer(memory, attributes + parent_offset, self.arch)?;
            parsed.parent = (parent != 0).then_some(parent);
        }
        if size >= override_offset + pointer_bytes {
            parsed.context_size_override =
                read_guest_pointer(memory, attributes + override_offset, self.arch)? as usize;
        }
        if size >= type_offset + pointer_bytes {
            parsed.context_type_info =
                read_guest_pointer(memory, attributes + type_offset, self.arch)?;
        }
        Ok(parsed)
    }

    /// Read the `ContextSize` member of a `WDF_OBJECT_CONTEXT_TYPE_INFO`.
    pub(crate) fn context_type_size(
        &self,
        memory: &MemoryImage,
        type_info: u64,
    ) -> AppResult<usize> {
        if type_info == 0 {
            return Ok(0);
        }
        let offset = match self.arch {
            GuestArch::X64 => 0x10,
            GuestArch::X86 => 0x08,
        };
        let size = read_guest_pointer(memory, type_info + offset, self.arch)? as usize;
        Ok(size)
    }

    /// Create one framework object with its per-kind context slot and attach it
    /// to the requested parent.  The handle block is `0x80` bytes and the
    /// context follows it, so `WdfObjectGetTypedContext` can return a stable
    /// guest pointer for the object's lifetime.
    pub(crate) fn create_kmdf_object(
        &mut self,
        memory: &mut MemoryImage,
        kind: KmdfObjectKind,
        attributes: u64,
    ) -> AppResult<u64> {
        let parsed = self.parse_object_attributes(memory, attributes)?;
        let (default_size, _align) = kind.layout();
        let type_size = self.context_type_size(memory, parsed.context_type_info)?;
        let context_size = if parsed.context_size_override > 0 {
            parsed.context_size_override
        } else if type_size > 0 {
            type_size
        } else {
            default_size
        }
        .clamp(8, 0x10_000);
        let handle = self.arena.alloc(memory, 0x80 + context_size, 16)?;
        let context_guest = handle + 0x80;
        memory.map_bytes(context_guest, &vec![0_u8; context_size]);
        let parent = parsed
            .parent
            .filter(|parent| self.kmdf.objects.contains_key(parent));
        let object = KmdfObject {
            kind,
            parent,
            children: BTreeSet::new(),
            context_guest,
            context_size,
            context_type: parsed.context_type_info,
            extra_contexts: Vec::new(),
            evt_cleanup: parsed.evt_cleanup,
            evt_destroy: parsed.evt_destroy,
            deleted: false,
            references: 0,
            delete_pending: false,
        };
        if let Some(parent) = parent {
            let parent_object = self
                .kmdf
                .objects
                .get_mut(&parent)
                .expect("parent object must exist for a validated parent handle");
            parent_object.children.insert(handle);
        }
        self.kmdf.objects.insert(handle, object);
        Ok(handle)
    }

    /// Collect the cleanup/destroy callbacks for `handle` and its children in
    /// post-order, removing each object from its domain maps.  The object
    /// metadata itself survives until `purge_deleted_objects` so callbacks can
    /// still resolve their typed context.
    pub(crate) fn collect_delete_callbacks(
        &mut self,
        handle: u64,
        callbacks: &mut Vec<GuestCallback>,
    ) {
        let Some(object) = self.kmdf.objects.get(&handle) else {
            return;
        };
        if object.deleted {
            return;
        }
        if object.references > 0 {
            // Outstanding `WdfObjectReference`s defer this object (and its
            // subtree) until the last reference is released.
            if let Some(object) = self.kmdf.objects.get_mut(&handle) {
                object.delete_pending = true;
            }
            return;
        }
        let children = object.children.iter().copied().collect::<Vec<_>>();
        for child in children {
            self.collect_delete_callbacks(child, callbacks);
        }
        let (kind, parent, evt_cleanup, evt_destroy) = {
            let object = self.kmdf.objects.get(&handle).expect("object");
            (
                object.kind,
                object.parent,
                object.evt_cleanup,
                object.evt_destroy,
            )
        };
        if let Some(parent) = parent {
            if let Some(parent_object) = self.kmdf.objects.get_mut(&parent) {
                parent_object.children.remove(&handle);
            }
        }
        if kind == KmdfObjectKind::Driver
            && self.kmdf.evt_driver_unload != 0
            && !self.kmdf.driver_unload_ran
        {
            self.kmdf.driver_unload_ran = true;
            self.kmdf.driver_unload_calls += 1;
            callbacks.push(GuestCallback {
                entry: self.kmdf.evt_driver_unload,
                args: vec![handle],
                label: "EvtDriverUnload",
            });
        }
        if evt_cleanup != 0 {
            callbacks.push(GuestCallback {
                entry: evt_cleanup,
                args: vec![handle],
                label: "EvtCleanup",
            });
        }
        if evt_destroy != 0 {
            callbacks.push(GuestCallback {
                entry: evt_destroy,
                args: vec![handle],
                label: "EvtDestroy",
            });
        }
        if let Some(object) = self.kmdf.objects.get_mut(&handle) {
            object.deleted = true;
        }
        self.remove_object_domain(handle);
    }

    pub(crate) fn remove_object_domain(&mut self, handle: u64) {
        if let Some(device) = self.kmdf.devices.remove(&handle) {
            self.kmdf.devices_by_object.remove(&device.object_guest);
            if let Some(id) = self.device_ids.remove(&device.object_guest) {
                let _ = self.io.delete_device(id);
            }
            if let Some(record) = self
                .devices
                .iter_mut()
                .find(|record| record.guest_pointer == device.object_guest)
            {
                record.deleted = true;
            }
        }
        if let Some(queue) = self.kmdf.queues.remove(&handle) {
            let requests = queue
                .queued
                .iter()
                .chain(queue.in_flight.iter())
                .copied()
                .collect::<Vec<_>>();
            for request in requests {
                self.force_cancel_request(request);
            }
        }
        if let Some(request) = self.kmdf.requests.remove(&handle) {
            if !request.completed {
                let _ = self.io.cancel_irp(request.irp);
            }
            if self.kmdf.current_request == handle {
                self.kmdf.current_request = 0;
            }
        }
        self.kmdf.device_inits.remove(&handle);
        self.kmdf.iotargets.remove(&handle);
        self.kmdf.memories.remove(&handle);
        self.kmdf.strings.remove(&handle);
        self.kmdf.spinlocks.remove(&handle);
        self.kmdf.timers.remove(&handle);
        self.kmdf.work_items.remove(&handle);
        self.kmdf.collections.remove(&handle);
        if let Some(block) = self.kmdf.lookaside_blocks.remove(&handle) {
            if let Some(lookaside) = self.kmdf.lookasides.get_mut(&block.lookaside) {
                lookaside.in_use = lookaside.in_use.saturating_sub(1);
                if lookaside.free.len() < lookaside.max_depth {
                    lookaside.free.push(block.block);
                }
            }
        }
        self.kmdf.lookasides.remove(&handle);
        if let Some(interrupt) = self.kmdf.interrupts.remove(&handle) {
            if interrupt.connected {
                let _ = self.interrupts.disconnect(interrupt.controller);
            }
        }
        self.kmdf.dma_enablers.remove(&handle);
        self.kmdf.dma_transactions.remove(&handle);
        if self.kmdf.usb_targets.remove(&handle).is_some() {
            let pipes = self
                .kmdf
                .usb_pipes
                .iter()
                .filter_map(|(pipe, record)| (record.target == handle).then_some(*pipe))
                .collect::<Vec<_>>();
            for pipe in pipes {
                self.kmdf.usb_pipes.remove(&pipe);
            }
        }
        self.kmdf.usb_pipes.remove(&handle);
        if self.kmdf.child_lists.remove(&handle).is_some() {
            let stale = self
                .kmdf
                .child_iterators
                .iter()
                .filter_map(|(id, iterator)| (iterator.list == handle).then_some(*id))
                .collect::<Vec<_>>();
            for id in stale {
                self.kmdf.child_iterators.remove(&id);
            }
        }
        self.kmdf.child_iterators.remove(&handle);
        self.kmdf.cm_resource_lists.remove(&handle);
        if let Some(lock) = self.kmdf.wait_locks.remove(&handle) {
            let (gate, wake) = &*lock.gate;
            if let Ok(mut locked) = gate.lock() {
                *locked = false;
                wake.notify_all();
            }
        }
    }

    pub(crate) fn purge_deleted_objects(&mut self) {
        let deleted = self
            .kmdf
            .objects
            .iter()
            .filter_map(|(handle, object)| object.deleted.then_some(*handle))
            .collect::<Vec<_>>();
        for handle in deleted {
            self.kmdf.objects.remove(&handle);
        }
    }

    pub(crate) fn wdf_object_get_typed_context(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let type_info = guest_arg(state, memory, 1)?;
        let Some(object) = self.kmdf.objects.get(&handle) else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        if type_info == 0 {
            state.set(Register::Rax, object.context_guest);
            return Ok(());
        }
        let type_info_size = match self.arch {
            GuestArch::X64 => 0x18,
            GuestArch::X86 => 0x0C,
        };
        let type_size = if crate::host_thunks::validate_guest_pointer(
            memory,
            type_info,
            type_info_size,
        )
        .is_ok()
        {
            self.context_type_size(memory, type_info)?
        } else {
            0
        };
        let extra = object
            .extra_contexts
            .iter()
            .find_map(|(registered_type, context, size)| {
                (*registered_type == type_info && *size >= type_size).then_some(*context)
            });
        if let Some(context) = extra {
            state.set(Register::Rax, context);
            return Ok(());
        }
        if type_size > object.context_size {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        state.set(Register::Rax, object.context_guest);
        Ok(())
    }

    pub(crate) fn wdf_object_delete(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let handle = guest_arg(state, memory, 0)?;
        if !self.kmdf.objects.contains_key(&handle) {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        }
        if self
            .kmdf
            .objects
            .get(&handle)
            .is_some_and(|object| object.deleted || object.delete_pending)
        {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        }
        let mut callbacks = Vec::new();
        self.collect_delete_callbacks(handle, &mut callbacks);
        // A delete-pending object implies a loaded driver, so the chain
        // rebuild always has a driver object to write.
        self.rebuild_device_chain(memory)?;
        set_status(state, STATUS_SUCCESS);
        if callbacks.is_empty() {
            self.purge_deleted_objects();
        }
        Ok(Self::callbacks_pending(callbacks, false))
    }

    /// `WdfObjectReference`: takes an outstanding reference; the object (and
    /// its subtree) survives `WdfObjectDelete` until every reference is
    /// released.
    pub(crate) fn wdf_object_reference(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let Some(object) = self.kmdf.objects.get_mut(&handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        if object.deleted || object.delete_pending {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        }
        object.references = object.references.saturating_add(1);
        self.kmdf.object_references += 1;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfObjectDereference`: releasing the final reference of a
    /// delete-pending object completes the deferred deletion with its
    /// cleanup/destroy cascade.  Unbalanced dereferences are rejected rather
    /// than underflowing.
    pub(crate) fn wdf_object_dereference(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let handle = guest_arg(state, memory, 0)?;
        let Some(object) = self.kmdf.objects.get_mut(&handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        if object.references == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        object.references -= 1;
        if object.references > 0 || !object.delete_pending {
            set_status(state, STATUS_SUCCESS);
            return Ok(None);
        }
        // Final reference of a delete-pending object: complete the deferred
        // deletion now.
        let mut callbacks = Vec::new();
        self.collect_delete_callbacks(handle, &mut callbacks);
        if self.driver_object_guest != 0 {
            self.rebuild_device_chain(memory)?;
        }
        set_status(state, STATUS_SUCCESS);
        if callbacks.is_empty() {
            self.purge_deleted_objects();
        }
        Ok(Self::callbacks_pending(callbacks, false))
    }

    pub(crate) fn wdf_object_allocate_context(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let type_info = guest_arg(state, memory, 1)?;
        let context_out = guest_arg(state, memory, 2)?;
        if context_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                context_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(kind) = self.kmdf.objects.get(&handle).map(|object| object.kind) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let type_size = self.context_type_size(memory, type_info)?;
        let size = if type_size > 0 {
            type_size
        } else {
            kind.layout().0
        }
        .clamp(8, 0x10_000);
        let context_guest = self.arena.alloc(memory, size, 8)?;
        if let Some(object) = self.kmdf.objects.get_mut(&handle) {
            object.extra_contexts.push((type_info, context_guest, size));
        }
        write_guest_pointer(memory, context_out, context_guest, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Resolve the exact error for a KMDF handle that must have `kind`.
    pub(crate) fn kmdf_expect_kind(&self, handle: u64, kind: KmdfObjectKind) -> Result<(), i32> {
        match self.kmdf.objects.get(&handle) {
            None => Err(STATUS_INVALID_HANDLE),
            Some(object) if object.deleted || object.delete_pending => Err(STATUS_INVALID_HANDLE),
            Some(object) if object.kind != kind => Err(STATUS_OBJECT_TYPE_MISMATCH),
            Some(_) => Ok(()),
        }
    }
}
