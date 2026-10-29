//! KMDF object model.

use super::*;

impl IslandState {
    /// Validate a `WDFCOLLECTION` handle.
    pub(crate) fn kmdf_collection(&self, handle: u64) -> Result<&KmdfCollection, i32> {
        self.kmdf_expect_kind(handle, KmdfObjectKind::Collection)?;
        self.kmdf
            .collections
            .get(&handle)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// `WdfCollectionCreate`.
    pub(crate) fn wdf_collection_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let attributes = guest_arg(state, memory, 0)?;
        let _callbacks = guest_arg(state, memory, 1)?;
        let collection_out = guest_arg(state, memory, 2)?;
        if collection_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                collection_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Collection, attributes)?;
        self.attach_kmdf_parent(handle, self.kmdf.driver_handle);
        self.kmdf.collections.insert(
            handle,
            KmdfCollection {
                items: Vec::new(),
                max_size: 1024,
            },
        );
        write_guest_pointer(memory, collection_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfCollectionAdd`: insertion-ordered; duplicates are rejected with
    /// `STATUS_OBJECT_NAME_COLLISION` exactly like the KMDF framework.
    pub(crate) fn wdf_collection_add(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let collection = guest_arg(state, memory, 0)?;
        let object = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_collection(collection) {
            set_status(state, status);
            return Ok(());
        }
        if object == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let record = self
            .kmdf
            .collections
            .get_mut(&collection)
            .expect("collection was validated");
        if record.items.contains(&object) {
            set_status(state, STATUS_OBJECT_NAME_COLLISION);
            return Ok(());
        }
        if record.items.len() >= record.max_size {
            set_status(state, STATUS_INSUFFICIENT_RESOURCES);
            return Ok(());
        }
        record.items.push(object);
        self.kmdf.collection_adds += 1;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfCollectionRemove`: removing a non-member fails with
    /// `STATUS_NOT_FOUND`.
    pub(crate) fn wdf_collection_remove(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let collection = guest_arg(state, memory, 0)?;
        let object = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_collection(collection) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .collections
            .get_mut(&collection)
            .expect("collection was validated");
        let Some(position) = record.items.iter().position(|item| *item == object) else {
            set_status(state, STATUS_NOT_FOUND);
            return Ok(());
        };
        record.items.remove(position);
        self.kmdf.collection_removes += 1;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfCollectionRemoveAll`.
    pub(crate) fn wdf_collection_remove_all(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let collection = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_collection(collection) {
            set_status(state, status);
            return Ok(());
        }
        self.kmdf
            .collections
            .get_mut(&collection)
            .expect("collection was validated")
            .items
            .clear();
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfCollectionGetItem`: out-of-range returns NULL without an error
    /// status, matching the framework.
    pub(crate) fn wdf_collection_get_item(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let collection = guest_arg(state, memory, 0)?;
        let index = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_collection(collection) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .collections
            .get(&collection)
            .expect("collection was validated");
        // On this host `usize` is 64-bit, so every `u64` index is
        // representable; only the range check can fail.
        let item = record
            .items
            .get(usize::try_from(index).unwrap_or(usize::MAX))
            .copied()
            .unwrap_or(0);
        // `WdfCollectionGetItem` returns the object (or NULL) in Rax; no
        // status write on the success path.
        state.set(Register::Rax, item);
        Ok(())
    }

    /// `WdfCollectionGetCount`.
    pub(crate) fn wdf_collection_get_count(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let collection = guest_arg(state, memory, 0)?;
        match self.kmdf_collection(collection) {
            Ok(record) => state.set(Register::Rax, record.items.len() as u64),
            Err(status) => set_status(state, status),
        }
        Ok(())
    }

    /// `WdfCollectionContains2`.
    pub(crate) fn wdf_collection_contains(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let collection = guest_arg(state, memory, 0)?;
        let object = guest_arg(state, memory, 1)?;
        match self.kmdf_collection(collection) {
            Ok(record) => state.set(Register::Rax, u64::from(record.items.contains(&object))),
            Err(status) => set_status(state, status),
        }
        Ok(())
    }
}
