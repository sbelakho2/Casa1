//! CLR/TBS and device integration glue (runtime methods).

use super::*;

impl PeHostRuntime {
    pub(crate) fn ensure_tbs_adapter(&mut self) -> Result<&mut crate::tpm::tbs::TbsAdapter, u32> {
        if self.tbs.is_none() {
            let root = self.win32.ge().root.clone();
            match crate::tpm::tbs::TbsAdapter::open_environment(&root) {
                Ok(adapter) => self.tbs = Some(adapter),
                Err(error) => return Err(error.code()),
            }
        }
        Ok(self.tbs.as_mut().expect("TBS adapter initialized"))
    }

    pub(crate) fn write_guest_bytes(
        &self,
        memory: &mut MemoryImage,
        address: u64,
        bytes: &[u8],
    ) -> AppResult<()> {
        for (offset, byte) in bytes.iter().enumerate() {
            memory.write_u8(address + offset as u64, *byte);
        }
        Ok(())
    }

    pub(crate) fn dispatch_tbs_context_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::tpm::tbs::{TBS_E_INVALID_OUTPUT_POINTER, TbsContextParams};
        let params_ptr = guest_call_arg(state, memory, 0)?;
        let out_ptr = guest_call_arg(state, memory, 1)?;
        if out_ptr == 0 {
            state.set(Register::Rax, u64::from(TBS_E_INVALID_OUTPUT_POINTER));
            return Ok(());
        }
        if params_ptr == 0 {
            state.set(
                Register::Rax,
                u64::from(crate::tpm::tbs::TBS_E_BAD_PARAMETER),
            );
            return Ok(());
        }
        let version = memory.read_u32(params_ptr)?;
        let flags = if version == crate::tpm::tbs::TBS_CONTEXT_VERSION_TWO {
            memory.read_u32(params_ptr + 4)?
        } else {
            0
        };
        let params = TbsContextParams { version, flags };
        let adapter = match self.ensure_tbs_adapter() {
            Ok(adapter) => adapter,
            Err(code) => {
                state.set(Register::Rax, u64::from(code));
                return Ok(());
            }
        };
        match adapter.context_create(&params) {
            Ok(context) => {
                write_guest_pointer(memory, out_ptr, context, self.guest_arch)?;
                state.set(Register::Rax, 0);
            }
            Err(error) => state.set(Register::Rax, u64::from(error.code())),
        }
        Ok(())
    }

    pub(crate) fn dispatch_tbs_submit_command(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::tpm::tbs::{
            TBS_E_BAD_PARAMETER, TBS_E_INSUFFICIENT_BUFFER, TBS_E_INVALID_OUTPUT_POINTER,
            TbsPriority,
        };
        let context = guest_call_arg(state, memory, 0)?;
        let locality = guest_call_arg_u32(state, memory, 1)?;
        let priority = guest_call_arg_u32(state, memory, 2)?;
        let command_ptr = guest_call_arg(state, memory, 3)?;
        let command_len = guest_call_arg_u32(state, memory, 4)? as usize;
        let response_ptr = guest_call_arg(state, memory, 5)?;
        let response_len_ptr = guest_call_arg(state, memory, 6)?;
        if response_len_ptr == 0 {
            state.set(Register::Rax, u64::from(TBS_E_INVALID_OUTPUT_POINTER));
            return Ok(());
        }
        if command_ptr == 0 && command_len != 0 {
            state.set(Register::Rax, u64::from(TBS_E_BAD_PARAMETER));
            return Ok(());
        }
        if command_len > crate::tpm::constants::MAX_COMMAND_SIZE {
            state.set(
                Register::Rax,
                u64::from(crate::tpm::tbs::TBS_E_BUFFER_TOO_LARGE),
            );
            return Ok(());
        }
        let Some(priority) = TbsPriority::from_u32(priority) else {
            state.set(Register::Rax, u64::from(TBS_E_BAD_PARAMETER));
            return Ok(());
        };
        let requested = memory.read_u32(response_len_ptr)? as usize;
        let command = if command_len == 0 {
            Vec::new()
        } else {
            memory.read_bytes(command_ptr, command_len)?
        };
        let adapter = match self.ensure_tbs_adapter() {
            Ok(adapter) => adapter,
            Err(code) => {
                state.set(Register::Rax, u64::from(code));
                return Ok(());
            }
        };
        let mut response = vec![0_u8; crate::tpm::constants::MAX_COMMAND_SIZE.max(requested)];
        match adapter.submit_command(context, locality as u8, priority, &command, &mut response) {
            Ok(length) => {
                if length > requested || response_ptr == 0 {
                    memory.write_u32(response_len_ptr, length as u32);
                    state.set(Register::Rax, u64::from(TBS_E_INSUFFICIENT_BUFFER));
                } else {
                    self.write_guest_bytes(memory, response_ptr, &response[..length])?;
                    memory.write_u32(response_len_ptr, length as u32);
                    state.set(Register::Rax, 0);
                }
            }
            Err(error) => state.set(Register::Rax, u64::from(error.code())),
        }
        Ok(())
    }

    pub(crate) fn dispatch_tbs_context_close(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let context = guest_call_arg(state, memory, 0)?;
        let adapter = match self.ensure_tbs_adapter() {
            Ok(adapter) => adapter,
            Err(code) => {
                state.set(Register::Rax, u64::from(code));
                return Ok(());
            }
        };
        match adapter.context_close(context) {
            Ok(()) => state.set(Register::Rax, 0),
            Err(error) => state.set(Register::Rax, u64::from(error.code())),
        }
        Ok(())
    }

    pub(crate) fn dispatch_import_if_present(
        &mut self,
        thunk_address: u64,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<Option<i32>>> {
        // A call that arrives at a directly-patched IAT thunk has bypassed the
        // generic name-resolution path.
        self.iat_patches.record_dispatch(thunk_address);
        // Fast-thunk hot path: if a fast-thunk ARM64 trampoline has been
        // registered for this thunk address, call it directly. This skips
        // the dispatch_import match entirely for JIT-compiled call sites
        // and provides a measurable speed-up for frequently-called thunks.
        if let Some(idx) = self.thunk_to_fast_index.get(&thunk_address)
            && let Some(jit) = self.jit_runtime.as_ref()
            && let Some(trampoline) = jit.lookup_thunk_address(*idx)
        {
            emit_live_ui_debug(format!(
                "fast-thunk dispatch for thunk {:#x} (idx={})",
                thunk_address, idx
            ));
            // SAFETY: the trampoline calls fast_thunk_host_dispatcher
            // with the same signature. We pass `self` as a raw pointer;
            // the bridge re-borrows it synchronously, so there is no
            // aliasing.
            //
            // The transmute converts a JIT-compiled code pointer (usize)
            // to a function pointer with the correct ABI:
            //   (runtime_ptr, cpu_state_ptr, memory_ptr, thunk_addr) -> i32
            // This is valid because:
            // 1. `trampoline` was produced by JitRuntime::lookup_thunk_address
            //    which returns the address of JIT-compiled ARM64 code.
            // 2. The JIT compiler emits code conforming to this exact
            //    calling convention (4 arguments in x0-x3, return in x0).
            // 3. The function pointer signature matches the JIT-emitted
            //    prologue/epilogue and argument passing.
            // 4. No guest-controlled data influences the function pointer
            //    value — it comes from the trusted thunk table.
            let result: i32 = unsafe {
                let func: unsafe extern "C" fn(
                    *mut std::ffi::c_void,
                    *mut CpuState,
                    *mut MemoryImage,
                    u64,
                ) -> i32 = std::mem::transmute(trampoline);
                func(
                    self as *mut Self as *mut std::ffi::c_void,
                    state as *mut CpuState,
                    memory as *mut MemoryImage,
                    thunk_address,
                )
            };
            return match result {
                -1 => Ok(Some(None)), // Continue execution
                -2 => Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("fast-thunk dispatch failed for thunk {thunk_address:#x}"),
                )),
                code => Ok(Some(Some(code))), // Guest exit code
            };
        }

        // Fallback: check the standard host_thunks table
        let Some(thunk) = self.host_thunks.get(&thunk_address).cloned() else {
            // Not a thunk - regular guest instruction, continue decoding
            return Ok(None);
        };
        // Dispatch to the actual host thunk — log via live_trace
        crate::live::live_trace(&format!(
            "[pe] DISPATCHING thunk at {:#x} ({thunk:?})",
            thunk_address,
        ));
        // Re-insert the thunk for dispatch_import to find (it does its own lookup)
        self.host_thunks.insert(thunk_address, thunk);
        let result = self.dispatch_import(thunk_address, state, memory).map(Some);
        crate::live::live_trace(&format!(
            "[pe] DISPATCH_RETURN thunk at {:#x}",
            thunk_address,
        ));
        result
    }

    /// Steam run instrumentation (no behavior change): record the FIRST
    /// filesystem failure for the run (guest_pc from `state.rip`, error code
    /// from `self.last_error`).  Later failures in the same category are
    /// ignored by the shared milestone static.
    pub(crate) fn record_fs_first_failure(
        &self,
        state: &CpuState,
        api: &str,
        detail: &str,
        path: &str,
        params: Option<String>,
    ) {
        crate::steam_milestones::record_first_failure(
            crate::steam_milestones::FailureCategory::Fs,
            state.rip as u32,
            self.win32.current_thread_id(),
            Some(api.to_string()),
            (self.last_error != 0).then_some(self.last_error),
            detail.to_string(),
            Some(path.to_string()),
            params,
        );
    }

    /// Steam run instrumentation (no behavior change): build the milestone
    /// evidence for the current guest dispatch site.  `process_id` is the
    /// guest-visible current process id and `guest_tick` is the guest tick
    /// count at the observation site (both observable here).
    pub(crate) fn milestone_evidence(
        &self,
        state: &CpuState,
        api: &str,
        path: Option<&str>,
        detail: &str,
    ) -> crate::steam_milestones::MilestoneEvidence {
        crate::steam_milestones::MilestoneEvidence {
            guest_pc: state.rip,
            thread_id: self.win32.current_thread_id(),
            process_id: self.win32.current_process_id(),
            guest_tick: self.win32.get_tick_count64(),
            api: Some(api.to_string()),
            path: path.map(str::to_string),
            detail: Some(detail.to_string()),
            observed: true,
        }
    }
}
