//! Guest callback invocation and window-message dispatch.
use super::*;

impl PeHostRuntime {
    pub(crate) fn dispatch_queued_message(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        message: &Message,
        label: &str,
    ) -> AppResult<i64> {
        if let Some(hwnd) = message.hwnd {
            return self.dispatch_window_message(
                state,
                memory,
                hwnd,
                message_id(message.kind),
                message.wparam,
                message.lparam,
                label,
            );
        }
        self.user32.dispatch_message_w(message)
    }

    /// Steam run instrumentation (no behavior change): when a mouse or
    /// keyboard message was ACTUALLY delivered to a guest window procedure
    /// (the callbacks above returned), record the first guest input
    /// consumption.  Queued-but-undispatched messages never reach here.
    pub(crate) fn record_guest_input_consumed(&self, state: &CpuState, message_id: u32) {
        if !is_guest_input_message_id(message_id) {
            return;
        }
        crate::steam_milestones::note_input_consumed(self.milestone_evidence(
            state,
            "DispatchMessageW",
            None,
            "mouse/keyboard message delivered to a guest window procedure",
        ));
    }
}

impl PeHostRuntime {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_window_message(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        hwnd: u32,
        message_id: u32,
        wparam: i64,
        lparam: i64,
        label: &str,
    ) -> AppResult<i64> {
        // Phase 1 diagnostic: trace message dispatch flow
        let class_name = self
            .window_preview(hwnd)
            .map(|p| p.class_name)
            .unwrap_or_default();
        emit_window_msg_debug(format!(
            "DWM hwnd={hwnd:#x} msg=0x{message_id:04x} wp={wparam:#x} lp={lparam:#x} class={class_name:?} label={label}"
        ));

        // Windows DispatchMessage semantics for WM_TIMER: when the message
        // carries a TIMERPROC in lParam (SetTimer with a non-null callback),
        // the timer proc is invoked instead of the window proc:
        //   TIMERPROC(hwnd, WM_TIMER, idTimer, time)
        if message_id == crate::user32::WM_TIMER && lparam != 0 {
            let timer_proc = lparam as u64;
            let id_timer = wparam as u64;
            let time = self.win32.get_tick_count64();
            emit_window_msg_debug(format!(
                "DWM -> timer_proc={timer_proc:#x} hwnd={hwnd:#x} idTimer={id_timer} time={time}"
            ));
            let result = self.execute_guest_callback(
                state,
                memory,
                timer_proc,
                &[u64::from(hwnd), u64::from(message_id), id_timer, time],
                label,
            )? as i64;
            if let Some(code) = self.process_exit_requested {
                return Ok(code as i64);
            }
            return Ok(result);
        }

        if let Some(dialog_proc) = self.dialog_procs.get(&hwnd).copied() {
            emit_window_msg_debug(format!(
                "DWM -> dialog_proc={dialog_proc:#x} hwnd={hwnd:#x} msg=0x{message_id:04x}"
            ));
            let result = self.execute_guest_callback(
                state,
                memory,
                dialog_proc,
                &[
                    u64::from(hwnd),
                    message_id as u64,
                    wparam as u64,
                    lparam as u64,
                ],
                label,
            )? as i64;
            self.record_guest_input_consumed(state, message_id);
            if let Some(code) = self.process_exit_requested {
                return Ok(code as i64);
            }
            return Ok(result);
        }
        if let Some(window_proc) = self.user32.get_window_long_w(hwnd, GWL_WNDPROC) {
            if window_proc != 0 {
                emit_window_msg_debug(format!(
                    "DWM -> GWL_WNDPROC={window_proc:#x} hwnd={hwnd:#x} msg=0x{message_id:04x}"
                ));
                let result = self.execute_guest_callback(
                    state,
                    memory,
                    window_proc,
                    &[
                        u64::from(hwnd),
                        message_id as u64,
                        wparam as u64,
                        lparam as u64,
                    ],
                    label,
                )? as i64;
                self.record_guest_input_consumed(state, message_id);
                // An unhandled exception raised inside the window proc must
                // terminate the process at the raise (the caller chain must
                // not continue into the guest's error path after the raise).
                if let Some(code) = self.process_exit_requested {
                    return Ok(code as i64);
                }
                return Ok(result);
            } else {
                emit_window_msg_debug(format!(
                    "DWM -> GWL_WNDPROC=0 (cleared) hwnd={hwnd:#x} msg=0x{message_id:04x}"
                ));
            }
        } else {
            emit_window_msg_debug(format!(
                "DWM -> no GWL_WNDPROC set hwnd={hwnd:#x} msg=0x{message_id:04x}"
            ));
        }
        if let Some(result) =
            self.dispatch_builtin_window_message(hwnd, message_id, wparam, lparam)?
        {
            emit_window_msg_debug(format!(
                "DWM -> builtin hwnd={hwnd:#x} msg=0x{message_id:04x} result={result}"
            ));
            return Ok(result);
        }
        if let Ok(kind) = message_kind(message_id) {
            emit_window_msg_debug(format!(
                "DWM -> default user32 hwnd={hwnd:#x} msg=0x{message_id:04x} kind={kind:?}"
            ));
            if self.user32.has_window(hwnd) {
                self.user32.send_message_w(hwnd, kind, wparam, lparam)
            } else {
                Ok(0)
            }
        } else {
            let default_result: i64 = match message_id {
                0x00F3 | 0x040F => 1,
                _ => 0,
            };
            emit_window_msg_debug(format!(
                "DWM -> unknown msg hwnd={hwnd:#x} msg=0x{message_id:04x} result={default_result}"
            ));
            Ok(default_result)
        }
    }

    pub(crate) fn run_modal_dialog_loop(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        hwnd: u32,
    ) -> AppResult<Option<i64>> {
        loop {
            if let Some(dialog_result) = self.user32.take_dialog_result(hwnd) {
                return Ok(Some(dialog_result));
            }
            self.poll_live_input()?;
            let Some(message) = self.user32.get_message_w() else {
                return Ok(None);
            };
            self.dispatch_queued_message(
                state,
                memory,
                &message,
                "DialogBoxParamW::DispatchMessage",
            )?;
            if let Some(code) = self.process_exit_requested {
                return Ok(Some(code as i64));
            }
            if message.kind == MessageKind::Quit {
                self.user32.post_quit_message(message.wparam as i32)?;
                return Ok(None);
            }
        }
    }
}

impl PeHostRuntime {
    pub(crate) fn execute_guest_callback(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        entrypoint: u64,
        args: &[u64],
        label: &str,
    ) -> AppResult<u64> {
        match self
            .execute_guest_callback_inner(state, memory, entrypoint, args, label, false, None)?
        {
            GuestCallbackDisposition::Returned(value) => Ok(value),
            GuestCallbackDisposition::Yielded => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("guest callback unexpectedly yielded: {label}"),
            )),
        }
    }

    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_guest_callback_inner(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        entrypoint: u64,
        args: &[u64],
        label: &str,
        allow_yield: bool,
        resume_rsp: Option<u64>,
    ) -> AppResult<GuestCallbackDisposition> {
        let config = CpuEngineConfig::from_profile(
            self.guest_arch,
            &self.win32.ge().config.winver,
            env!("CARGO_PKG_VERSION"),
            None,
        )?;
        let mut engine = CpuExecutionEngine::new(config);
        let instruction_budget = self.current_instruction_budget()?;
        let guest_pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let original_rsp = resume_rsp.unwrap_or_else(|| state.get(Register::Rsp));
        if resume_rsp.is_none() {
            match self.guest_arch {
                GuestArch::X86 => {
                    // 32-bit stdcall/cdecl: all arguments are pushed on the
                    // stack above a synthetic return address of 0.
                    let callback_rsp =
                        original_rsp.wrapping_sub((args.len() as u64 + 1) * guest_pointer_bytes);
                    write_guest_pointer(memory, callback_rsp, 0, self.guest_arch)?;
                    for (index, arg) in args.iter().enumerate() {
                        write_guest_pointer(
                            memory,
                            callback_rsp + guest_pointer_bytes * (index as u64 + 1),
                            *arg,
                            self.guest_arch,
                        )?;
                    }
                    state.set(Register::Rsp, callback_rsp);
                    state.rip = entrypoint;
                }
                GuestArch::X64 => {
                    // Microsoft x64 calling convention: the first four integer
                    // or pointer arguments are passed in RCX, RDX, R8, R9; any
                    // further arguments are placed on the stack above a 32-byte
                    // shadow (home) region. A synthetic return address of 0 sits
                    // at [rsp] so the callback's terminating `ret` breaks the
                    // loop. Entry RSP must satisfy `rsp % 16 == 8` per the ABI.
                    let num_stack_args = args.len().saturating_sub(4) as u64;
                    let region = 8 + 32 + num_stack_args * 8;
                    let mut callback_rsp = original_rsp.wrapping_sub(region);
                    callback_rsp = (callback_rsp & !0xF) | 0x8;
                    write_guest_pointer(memory, callback_rsp, 0, self.guest_arch)?;
                    for (index, arg) in args.iter().skip(4).enumerate() {
                        write_guest_pointer(
                            memory,
                            callback_rsp + 8 + 32 + index as u64 * 8,
                            *arg,
                            self.guest_arch,
                        )?;
                    }
                    let reg_args = [Register::Rcx, Register::Rdx, Register::R8, Register::R9];
                    for (reg, arg) in reg_args.iter().zip(args.iter()) {
                        state.set(*reg, *arg);
                    }
                    state.set(Register::Rsp, callback_rsp);
                    state.rip = entrypoint;
                }
            }
        }

        let mut steps = 0_u64;
        // Spin detection for the nested callback loop: the main loop has
        // same-RIP detection, but a guest spin INSIDE a window callback
        // (message dispatch) never returns there.  Record where the guest
        // is stuck so the artifact's first-failure diagnostics localize it.
        let mut nested_same_rip: u32 = 0;
        let mut nested_last_rip: u64 = 0;
        loop {
            // The callback was invoked with a synthetic return address of 0
            // pushed at [rsp]; the guest's terminating `ret` sets RIP to that
            // 0.  Treat RIP==0 as "callback returned" unconditionally — this
            // catches the sentinel whether the ret was the block's last
            // instruction (handled below) or reached via an indirect jump/call
            // that resolves to the sentinel, so we never try to decode/execute
            // at address 0 (which faults as unmapped guest memory).
            if state.rip == 0 {
                break;
            }
            if let Some(result) = self.dispatch_import_if_present(state.rip, state, memory)? {
                advance_runtime_steps(
                    self,
                    &mut steps,
                    instruction_budget,
                    1,
                    memory,
                    state,
                    label,
                )?;
                if let Some(code) = result {
                    state.set(Register::Rax, code as u64);
                    break;
                }
                if allow_yield && self.take_pumped_guest_thread_yield_request() {
                    return Ok(GuestCallbackDisposition::Yielded);
                }
                continue;
            }

            let opcode = memory
                .read_u8(state.rip)
                .map_err(|error| annotate_guest_fault(error, memory, state))?;
            match opcode {
                0xFF if self.guest_arch == GuestArch::X86 => match memory.read_u8(state.rip + 1)? {
                    0x15 | 0x25 => {
                        advance_runtime_steps(
                            self,
                            &mut steps,
                            instruction_budget,
                            1,
                            memory,
                            state,
                            label,
                        )?;
                        let next_rip = state.rip + 6;
                        let slot_address = read_u32(memory, state.rip + 2)? as u64;
                        let target = read_guest_pointer(memory, slot_address, self.guest_arch)?;
                        let is_call = memory.read_u8(state.rip + 1)? == 0x15;

                        if is_call {
                            let call_rsp =
                                state.get(Register::Rsp).wrapping_sub(guest_pointer_bytes);
                            write_guest_pointer(memory, call_rsp, next_rip, self.guest_arch)?;
                            state.set(Register::Rsp, call_rsp);
                        }

                        if let Some(result) =
                            self.dispatch_import_if_present(target, state, memory)?
                        {
                            if let Some(code) = result {
                                state.set(Register::Rax, code as u64);
                                break;
                            }
                            if allow_yield && self.take_pumped_guest_thread_yield_request() {
                                return Ok(GuestCallbackDisposition::Yielded);
                            }
                        } else {
                            state.rip = target;
                        }
                        continue;
                    }
                    _ => {}
                },
                _ => {}
            }

            let cached_block = decode_basic_block_cached(
                &mut engine,
                memory,
                &mut self.instruction_cache,
                &mut self.instruction_cache_lru,
                &mut self.instruction_cache_generation,
                INSTRUCTION_CACHE_LIMIT,
                &mut self.basic_block_cache,
                &mut self.basic_block_cache_lru,
                &mut self.basic_block_cache_generation,
                BASIC_BLOCK_CACHE_LIMIT,
                state.rip,
            )
            .map_err(|error| annotate_guest_fault(error, memory, state))?;
            let consumed_instructions = cached_block.translated.decoded.len().max(1) as u64;
            advance_runtime_steps(
                self,
                &mut steps,
                instruction_budget,
                consumed_instructions,
                memory,
                state,
                label,
            )?;
            if self
                .execute_ir_with_guest_exception_delivery(
                    &engine,
                    state,
                    memory,
                    &cached_block.translated.ir,
                    label,
                )
                .map_err(|error| annotate_guest_fault(error, memory, state))?
            {
                continue;
            }

            // --- Adaptive tiered compilation ---
            if let Some(jit) = self.jit_runtime.as_mut() {
                let block_start = cached_block.start_rip;
                if let Some(_tier) = self.tiered_compiler.record_execution(block_start) {
                    let ir = &cached_block.translated.ir;
                    if jit
                        .get_or_compile(ir, block_start, engine.config.arch, None)
                        .is_ok()
                    {
                        // Sync updated unwind info to the SEH subsystem so that
                        // RtlVirtualUnwind can find newly compiled JIT blocks.
                        if jit.is_unwind_dirty() {
                            jit.unwind_table.register_with_seh(&mut self.seh);
                        }

                        if let Some(crate::cpu::IrInstruction::Jump { target }) = ir.last()
                            && *target > block_start
                            && jit.is_compiled(*target)
                        {
                            let _ = jit.chain_blocks(block_start, *target);
                        }
                    }
                }
            }

            let last_instruction = cached_block.translated.decoded.last().ok_or_else(|| {
                AppError::new(ReasonCode::RcUnimplInsn, "translated basic block was empty")
            })?;
            if last_instruction.opcode == DecodedOpcode::Ret {
                if state.rip == 0 {
                    break;
                }
            } else if !instruction_controls_rip(last_instruction.opcode) {
                state.rip = cached_block.end_rip;
            }

            // Spin detection INSIDE the callback loop: a guest spin in a
            // window callback never returns to the main loop's own
            // same-RIP detector; record where the guest is stuck.
            if state.rip == nested_last_rip {
                nested_same_rip += 1;
                if nested_same_rip == 100_000 {
                    crate::steam_milestones::record_first_failure(
                        crate::steam_milestones::FailureCategory::Thread,
                        state.rip as u32,
                        self.win32.current_thread_id(),
                        Some(format!("guest spin in {label}")),
                        None,
                        format!(
                            "guest spun {nested_same_rip} iterations at the same RIP inside a callback"
                        ),
                        None,
                        None,
                    );
                }
            } else {
                nested_last_rip = state.rip;
                nested_same_rip = 0;
            }
        }

        state.set(Register::Rsp, original_rsp);
        Ok(GuestCallbackDisposition::Returned(state.get(Register::Rax)))
    }
}

pub(crate) enum GuestCallbackDisposition {
    Returned(u64),
    Yielded,
}
