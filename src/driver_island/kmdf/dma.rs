//! KMDF object model.

use super::*;

impl IslandState {
    /// `WdfDmaEnablerCreate` with `WDF_DMA_ENABLER_CONFIG` parsing:
    /// `Size`, `Profile` (`WDF_DMA_PROFILE`), `MaximumLength`.
    pub(crate) fn wdf_dma_enabler_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let config = guest_arg(state, memory, 2)?;
        let enabler_out = guest_arg(state, memory, 3)?;
        if !self.kmdf.devices.contains_key(&device)
            || config == 0
            || enabler_out == 0
            || crate::host_thunks::validate_guest_pointer(memory, config, 16).is_err()
            || crate::host_thunks::validate_guest_pointer(
                memory,
                enabler_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let size = memory.read_u32(config)?;
        if size < 16 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let profile_raw = memory.read_u32(config + 4)?;
        let profile = match profile_raw {
            0 => KmdfDmaProfile::Short,
            1 => KmdfDmaProfile::Long,
            2 => KmdfDmaProfile::ScatterGather,
            _ => {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
        };
        let maximum_length = match self.arch {
            GuestArch::X64 => memory.read_u64(config + 8)?,
            GuestArch::X86 => u64::from(memory.read_u32(config + 8)?),
        };
        if maximum_length == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::DmaEnabler, attributes)?;
        self.attach_kmdf_parent(handle, device);
        self.kmdf.dma_enablers.insert(
            handle,
            KmdfDmaEnabler {
                config: KmdfDmaEnablerConfig {
                    profile,
                    maximum_length,
                },
                device,
                active_transactions: 0,
                completed_transactions: 0,
                transferred_bytes: 0,
            },
        );
        write_guest_pointer(memory, enabler_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// The mini-DMA channel's maximum transfer length for a profile.
    pub(crate) fn dma_maximum_transfer(&self, enabler: &KmdfDmaEnabler) -> u64 {
        match enabler.config.profile {
            // Short single-segment transfers are capped at 64 KB.
            KmdfDmaProfile::Short => enabler.config.maximum_length.min(0x1_0000),
            KmdfDmaProfile::Long | KmdfDmaProfile::ScatterGather => enabler.config.maximum_length,
        }
    }

    /// `WdfDmaEnablerCalculateMaximumTransferSize`.
    pub(crate) fn wdf_dma_max_transfer_size(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let enabler = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(enabler, KmdfObjectKind::DmaEnabler) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .dma_enablers
            .get(&enabler)
            .expect("enabler was validated");
        // `WdfDmaEnablerCalculateMaximumTransferSize` returns the length in
        // Rax; no status write on the success path.
        state.set(Register::Rax, self.dma_maximum_transfer(record));
        Ok(())
    }

    /// `WdfDmaTransactionCreate`.
    pub(crate) fn wdf_dma_transaction_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let enabler = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let transaction_out = guest_arg(state, memory, 2)?;
        if let Err(status) = self.kmdf_expect_kind(enabler, KmdfObjectKind::DmaEnabler) {
            set_status(state, status);
            return Ok(());
        }
        if transaction_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                transaction_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::DmaTransaction, attributes)?;
        self.attach_kmdf_parent(handle, enabler);
        self.kmdf.dma_transactions.insert(
            handle,
            KmdfDmaTransaction {
                enabler,
                phase: KmdfDmaPhase::Created,
                direction: 0,
                length: 0,
                transferred: 0,
                segments: 0,
            },
        );
        write_guest_pointer(memory, transaction_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfDmaTransactionInitialize`: validates the transfer against the
    /// profile's maximum and records segment counts for scatter/gather.
    pub(crate) fn wdf_dma_transaction_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let transaction = guest_arg(state, memory, 0)?;
        let direction = guest_arg(state, memory, 1)? as u32;
        let _transfer_descriptor = guest_arg(state, memory, 2)?;
        let length = guest_arg(state, memory, 3)?;
        let _maximum_mapping_length = guest_arg(state, memory, 4)?;
        if let Err(status) = self.kmdf_expect_kind(transaction, KmdfObjectKind::DmaTransaction) {
            set_status(state, status);
            return Ok(());
        }
        if direction > 1 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if length == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let record = self
            .kmdf
            .dma_transactions
            .get(&transaction)
            .expect("transaction was validated");
        if record.phase != KmdfDmaPhase::Created && record.phase != KmdfDmaPhase::Released {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        // Transactions are children of their enabler, so a live transaction
        // always has a live enabler record.
        let enabler = self
            .kmdf
            .dma_enablers
            .get(&record.enabler)
            .cloned()
            .expect("transaction enabler exists");
        let maximum = self.dma_maximum_transfer(&enabler);
        if length > maximum {
            set_status(state, STATUS_BUFFER_TOO_SMALL);
            return Ok(());
        }
        let segments = if enabler.config.profile == KmdfDmaProfile::ScatterGather {
            length.div_ceil(0x1_0000)
        } else {
            1
        };
        let record = self
            .kmdf
            .dma_transactions
            .get_mut(&transaction)
            .expect("transaction was validated");
        record.phase = KmdfDmaPhase::Initialized;
        record.direction = direction;
        record.length = length;
        record.transferred = 0;
        record.segments = segments;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfDmaTransactionExecute`: the mini-DMA channel completes the
    /// transfer synchronously and reports the transferred length.
    pub(crate) fn wdf_dma_transaction_execute(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let transaction = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(transaction, KmdfObjectKind::DmaTransaction) {
            set_status(state, status);
            return Ok(None);
        }
        let record = self
            .kmdf
            .dma_transactions
            .get_mut(&transaction)
            .expect("transaction was validated");
        if record.phase != KmdfDmaPhase::Initialized {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(None);
        }
        record.phase = KmdfDmaPhase::Executed;
        record.transferred = record.length;
        let enabler = record.enabler;
        let transferred = record.transferred;
        if let Some(enabler) = self.kmdf.dma_enablers.get_mut(&enabler) {
            enabler.active_transactions = enabler.active_transactions.saturating_sub(1);
            enabler.completed_transactions += 1;
            enabler.transferred_bytes += transferred;
        }
        self.kmdf.dma_executions += 1;
        set_status(state, STATUS_SUCCESS);
        Ok(None)
    }

    /// `WdfDmaTransactionRelease`.
    pub(crate) fn wdf_dma_transaction_release(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let transaction = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(transaction, KmdfObjectKind::DmaTransaction) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .dma_transactions
            .get_mut(&transaction)
            .expect("transaction was validated");
        if record.phase == KmdfDmaPhase::Released {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        record.phase = KmdfDmaPhase::Released;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfDmaTransactionCancel`: returns TRUE when an initialized
    /// transaction was cancelled back to the created phase.
    pub(crate) fn wdf_dma_transaction_cancel(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let transaction = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(transaction, KmdfObjectKind::DmaTransaction) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .dma_transactions
            .get_mut(&transaction)
            .expect("transaction was validated");
        if record.phase == KmdfDmaPhase::Initialized {
            record.phase = KmdfDmaPhase::Created;
            // `WdfDmaTransactionCancel` returns TRUE in Rax; no status
            // write on the success path.
            state.set(Register::Rax, 1);
        } else {
            state.set(Register::Rax, 0);
        }
        Ok(())
    }
}
