//! Guest thread lifecycle: state tags, pending-thread records, APC
//! delivery, thread entry preparation.
use super::*;

/// Lifecycle state of a cooperative guest thread.
///
/// Created threads enter `Runnable`; yielding through `Sleep`/alertable waits
/// moves them to `Waiting`/`AlertableWaiting`; `ExitThread`/`_endthreadex`/
/// `TerminateThread` move the active thread to `Exiting`; the pump completes
/// the exit with `Exited`.  Queued threads terminated from another thread are
/// marked `Exited` so they never run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestThreadState {
    Runnable,
    Waiting,
    #[allow(dead_code)] // thread state tag (state-model completeness)
    AlertableWaiting,
    Exiting,
    Exited,
}

impl PeHostRuntime {
    pub(crate) fn take_pumped_guest_thread_yield_request(&mut self) -> bool {
        if self.yield_pumped_guest_thread {
            self.yield_pumped_guest_thread = false;
            true
        } else {
            false
        }
    }
}

impl PeHostRuntime {
    /// Deliver pending APCs for the CURRENT guest thread (alertable wait
    /// points: `SleepEx`/`WaitForSingleObjectEx`).  Each queued APC callback
    /// is executed in the guest via the standard callback machinery; returns
    /// true when at least one APC was delivered, in which case the caller
    /// must report WAIT_IO_COMPLETION (0xC0).
    ///
    /// The queue is keyed by the guest thread ID (`QueueUserAPC` resolves
    /// the target handle to a thread ID), and `current_thread_id` reflects
    /// the pumped thread's identity, so an APC queued for a pumped worker is
    /// delivered while that worker is active.
    pub(crate) fn deliver_current_thread_apcs(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<bool> {
        let current_tid = self.win32.current_thread_id() as u64;
        // `deliver_apcs(max_count)` allocates a Vec with `max_count`
        // capacity, so the count must stay sane (usize::MAX overflows);
        // pending_count() bounds it to what the queue actually holds.
        let apc_entries = self
            .apc_queues
            .get_mut(&current_tid)
            .map(|queue| {
                let count = queue.pending_count().max(1);
                queue.deliver_apcs(count)
            })
            .unwrap_or_default();
        if apc_entries.is_empty() {
            return Ok(false);
        }
        for apc in apc_entries {
            let _ = self.execute_guest_callback(
                state,
                memory,
                apc.callback,
                &[apc.context],
                "ApcCallback",
            );
        }
        Ok(true)
    }
}

pub(crate) struct PendingGuestThread {
    pub(crate) handle: u32,
    pub(crate) thread_id: u32,
    pub(crate) start_address: u64,
    pub(crate) parameter: u64,
    pub(crate) initial_rsp: u64,
    pub(crate) started: bool,
    /// Thread suspend count (Windows semantics): a thread created with
    /// CREATE_SUSPENDED starts at 1 and the pump skips it until every
    /// suspension has been released by ResumeThread.  N SuspendThread calls
    /// need N ResumeThread calls.
    pub(crate) suspended: u32,
    pub(crate) wake_tick: u64,
    pub(crate) teb_base: u64,
    pub(crate) tls_vector_ptr: u64,
    pub(crate) tls_slots: BTreeMap<u32, u64>,
    pub(crate) fls_slots: BTreeMap<u32, u64>,
    pub(crate) state: CpuState,
    /// Guest-thread lifecycle state (see `GuestThreadState`).
    pub(crate) state_machine: GuestThreadState,
    /// Exit code recorded by an explicit exit API (`ExitThread`,
    /// `_endthreadex`, `_endthread`, `TerminateThread`).  When the pump
    /// reaches the thread-end path it uses
    /// `exit_code_override.or(Some(RAX))`: an explicit exit is noreturn, so
    /// the procedure's return value only matters when no explicit exit ran.
    pub(crate) exit_code_override: Option<u32>,
    /// Scheduler wait descriptor when the thread is parked in a wait
    /// (`None` for plain timeslice yields).
    pub(crate) wait: Option<GuestWait>,
    /// Result to apply on resume (RAX + last_error), set by the pump's
    /// readiness pass.
    pub(crate) wait_resume: Option<WaitResume>,
}

impl PeHostRuntime {
    pub(crate) fn prepare_guest_thread_entry(
        &mut self,
        memory: &mut MemoryImage,
        thread_handle: u32,
        stack_size: u64,
        start_address: u64,
        parameter: u64,
    ) -> AppResult<PendingGuestThread> {
        if self.guest_arch != GuestArch::X86 {
            // Steam run instrumentation (no behavior change): the host
            // refused to schedule a guest thread — an illegal host-side
            // termination, recorded as both a counter and the thread
            // first-failure (should be 0 on Steam's x86 guest).
            crate::steam_milestones::note_illegal_host_termination();
            crate::steam_milestones::record_first_failure(
                crate::steam_milestones::FailureCategory::Thread,
                0,
                self.win32.current_thread_id(),
                Some("CreateThread".to_string()),
                None,
                "guest thread scheduling refused on non-x86 guest".to_string(),
                None,
                None,
            );
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "CreateThread guest scheduling is only implemented for x86: {start_address:#x}"
                ),
            ));
        }

        let thread_id = self.win32.thread_id_for_handle(thread_handle)?;
        let current_tls_slots = self.tls_slots.clone();
        let current_fls_slots = self.fls_slots.clone();
        let stack_bytes = align_up_u64(stack_size.max(STACK_SIZE as u64), 0x1000) as usize;
        let stack_limit = self.alloc_private_pages(memory, 0, stack_bytes)?;
        let stack_base = stack_limit + stack_bytes as u64;
        let teb_base = self.alloc_zeroed(memory, 0x100, 16)?;
        let tls_vector_ptr =
            self.alloc_zeroed(memory, 4096 * self.guest_arch.pointer_bytes(), 16)?;

        let mut thread_tls_slots = current_tls_slots
            .keys()
            .copied()
            .map(|slot| (slot, 0_u64))
            .collect::<BTreeMap<_, _>>();
        if let Some(main_static_tls_block) = current_tls_slots
            .get(&0)
            .copied()
            .filter(|value| *value != 0)
        {
            let static_tls_bytes = read_window(memory, main_static_tls_block, 0x2000)?;
            let static_tls_block = self.alloc_zeroed(memory, static_tls_bytes.len(), 16)?;
            memory.map_bytes(static_tls_block, &static_tls_bytes);
            thread_tls_slots.insert(0, static_tls_block);
        }
        // Patch 6b: each guest thread gets its own zeroed errno/doserrno int
        // in the reserved CRT TLS slots (per-thread errno semantics).
        for slot in [self.crt_errno_slot, self.crt_doserrno_slot] {
            if slot != 0 {
                let storage = self.alloc_zeroed(memory, 4, 4)?;
                thread_tls_slots.insert(slot, storage);
            }
        }
        let thread_fls_slots = current_fls_slots
            .keys()
            .copied()
            .map(|slot| (slot, 0_u64))
            .collect::<BTreeMap<_, _>>();

        write_u32(memory, teb_base, X86_EXCEPTION_CHAIN_END as u32);
        write_u32(memory, teb_base + 0x04, stack_base as u32);
        write_u32(memory, teb_base + 0x08, stack_limit as u32);
        write_guest_pointer(memory, teb_base + 0x18, teb_base, self.guest_arch)?;
        write_guest_pointer(memory, teb_base + 0x2c, tls_vector_ptr, self.guest_arch)?;
        write_guest_pointer(memory, teb_base + 0x30, self.peb_base, self.guest_arch)?;

        for (&slot, &value) in &thread_tls_slots {
            let slot_address =
                tls_vector_ptr + (slot as u64 * self.guest_arch.pointer_bytes() as u64);
            write_guest_pointer(memory, slot_address, value, self.guest_arch)?;
        }

        let mut thread_state = CpuState::new(GuestArch::X86);
        thread_state.segment_bases.fs = teb_base;
        let initial_rsp = stack_base.wrapping_sub(self.guest_arch.pointer_bytes() as u64);
        write_guest_pointer(memory, initial_rsp, 0, self.guest_arch)?;
        thread_state.set(Register::Rsp, initial_rsp);
        // The first pump runs the thread through execute_guest_callback_inner,
        // whose x86 branch pushes a synthetic return address of 0 and the
        // thread parameter above the thread's initial stack top (the pump
        // always passes exactly one argument — the CreateThread parameter):
        //   callback_rsp = initial_rsp - (1 arg + 1 ret) * ptr
        //   [callback_rsp]     = 0       (return address)
        //   [callback_rsp + 4] = param   (lpParameter)
        // Give the thread a conventional EBP frame pointing at that synthetic
        // frame (saved EBP at [ebp], return address at [ebp+4], thread
        // parameter at [ebp+8]). Thread starts that are mid-function labels
        // (e.g. Steam's bootstrapper at 0x4dcee0, inside `pushl 0x54(%eax)`)
        // address locals via [ebp±x] before ever running a prologue; with
        // EBP left at 0 every [ebp-x] access fetches from low unmapped
        // memory. A frame pointer into the thread's own fresh stack keeps
        // those accesses within the mapped stack area.
        let thread_callback_args: u64 = 1;
        let callback_rsp = initial_rsp
            .wrapping_sub((thread_callback_args + 1) * self.guest_arch.pointer_bytes() as u64);
        let thread_frame_ebp = callback_rsp.wrapping_sub(self.guest_arch.pointer_bytes() as u64);
        thread_state.set(Register::Rbp, thread_frame_ebp);

        Ok(PendingGuestThread {
            handle: thread_handle,
            thread_id,
            start_address,
            parameter,
            initial_rsp,
            started: false,
            suspended: 0,
            wake_tick: self.win32.get_tick_count64(),
            teb_base,
            tls_vector_ptr,
            tls_slots: thread_tls_slots,
            fls_slots: thread_fls_slots,
            state: thread_state,
            state_machine: GuestThreadState::Runnable,
            exit_code_override: None,
            wait: None,
            wait_resume: None,
        })
    }
}
