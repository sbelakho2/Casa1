//! Guest exception delivery, timers, safepoints, and tracing helpers.

use super::*;

impl PeHostRuntime {
    /// Invoke a guest vectored exception handler callback.
    ///
    /// Serializes the exception record and context into guest memory as
    /// EXCEPTION_POINTERS, EXCEPTION_RECORD, and CONTEXT structs, then
    /// calls the guest callback with a pointer to the EXCEPTION_POINTERS.
    pub(crate) fn invoke_guest_veh_callback(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        callback: u64,
        record: &crate::seh::ExceptionRecord,
        context: &crate::seh::X64Context,
    ) -> AppResult<()> {
        if callback == 0 {
            return Ok(());
        }
        let pointer_size = match self.guest_arch {
            GuestArch::X86 => 4u64,
            GuestArch::X64 => 8u64,
        };
        // Layout in guest memory:
        //   [EXCEPTION_RECORD]  [CONTEXT]  [EXCEPTION_POINTERS]
        //
        // EXCEPTION_RECORD (x86):
        //   +0x00 ExceptionCode        (u32)
        //   +0x04 ExceptionFlags        (u32)
        //   +0x08 ExceptionRecord       (ptr)
        //   +0x0C ExceptionAddress      (ptr)
        //   +0x10 NumberParameters      (u32)
        //   +0x14 ExceptionInformation  (ptr[15])
        //   Total (x86): 0x14 + 4*15 = 0x50 = 80 bytes
        //
        // EXCEPTION_RECORD (x64):
        //   +0x00 ExceptionCode        (u32)
        //   +0x04 ExceptionFlags        (u32)
        //   +0x08 ExceptionRecord       (ptr)
        //   +0x10 ExceptionAddress      (ptr)
        //   +0x18 NumberParameters      (u32)
        //   +0x20 ExceptionInformation  (ptr[15])
        //   Total (x64): 0x20 + 8*15 = 0x98 = 152 bytes
        //
        // CONTEXT is the X64Context struct (same layout regardless of guest arch
        // for simplicity — we store the host-side X64Context as-is).
        let context_size = std::mem::size_of::<crate::seh::X64Context>() as u64;
        let record_size = if pointer_size == 8 { 152u64 } else { 80u64 };
        let pointers_size = pointer_size * 2; // ExceptionRecord ptr + ContextRecord ptr
        let total_size = record_size + context_size + pointers_size;
        let base = self.alloc_heap(memory, total_size as usize, true)?;
        let record_addr = base;
        let context_addr = base + record_size;
        let pointers_addr = base + record_size + context_size;
        // Write EXCEPTION_RECORD (all write methods return () — no ? needed)
        memory.write_u32(record_addr, record.code);
        memory.write_u32(record_addr + 4, record.flags);
        if pointer_size == 8 {
            write_guest_pointer(memory, record_addr + 8, 0, self.guest_arch)?; // ExceptionRecord (next)
            write_guest_pointer(memory, record_addr + 0x10, record.address, self.guest_arch)?;
            memory.write_u32(record_addr + 0x18, 0); // NumberParameters
            // Zero out ExceptionInformation (all zeros)
            for i in 0..15 {
                write_guest_pointer(memory, record_addr + 0x20 + i * 8, 0, self.guest_arch)?;
            }
        } else {
            memory.write_u32(record_addr + 8, 0); // ExceptionRecord (next)
            memory.write_u32(record_addr + 0x0C, record.address as u32);
            memory.write_u32(record_addr + 0x10, 0); // NumberParameters
            for i in 0..15 {
                memory.write_u32(record_addr + 0x14 + i * 4, 0);
            }
        }
        // Write CONTEXT (X64Context as raw bytes, byte-by-byte)
        // SAFETY: context is a valid reference to X64Context; the pointer cast
        // and size_of produce a valid read-only byte slice of the struct.
        let context_bytes = unsafe {
            std::slice::from_raw_parts(
                context as *const crate::seh::X64Context as *const u8,
                std::mem::size_of::<crate::seh::X64Context>(),
            )
        };
        for (i, &byte) in context_bytes.iter().enumerate() {
            memory.write_u8(context_addr + i as u64, byte);
        }
        // Write EXCEPTION_POINTERS
        if pointer_size == 8 {
            memory.write_u64(pointers_addr, record_addr);
            memory.write_u64(pointers_addr + 8, context_addr);
        } else {
            memory.write_u32(pointers_addr, record_addr as u32);
            memory.write_u32(pointers_addr + 4, context_addr as u32);
        }
        // Invoke the guest callback with the EXCEPTION_POINTERS pointer
        let _result = self.execute_guest_callback(
            state,
            memory,
            callback,
            &[pointers_addr],
            "VectoredExceptionHandler",
        )?;
        Ok(())
    }

    /// Cooperative wait on a single handle: poll the signaled state, pump
    /// pending guest threads (one per cycle, honoring wake_tick), and when
    /// nothing could be pumped host-sleep 1 ms while advancing the guest
    /// clock so sleeping workers become runnable.
    ///
    /// For a THREAD target the wait never reports WAIT_TIMEOUT for INFINITE
    /// while the target thread is still queued (a sleeping worker's wake_tick
    /// lies in the future, so the pump cannot run it yet) — it keeps polling
    /// until the thread reaches `Exited` or a finite timeout expires.
    /// Non-thread kernel objects keep the historical single-pass behavior for
    /// INFINITE (pump while the queue is non-empty, then report the timeout)
    /// so guests that busy-poll objects in a loop (Steam/CEF) stay responsive.
    ///
    /// Alertable waits (`alertable == true`) re-check the waiting thread's
    /// APC queue after every pump iteration and deliver any APC queued during
    /// the wait (e.g. by a pumped worker via QueueUserAPC), returning
    /// `PumpWaitOutcome::IoCompletion` so the thunk reports WAIT_IO_COMPLETION.
    ///
    /// Documented divergence: joining the CURRENTLY ACTIVE pumped thread
    /// (a nested pump where thread B is active and dispatches thread A, and
    /// A waits INFINITE on B's handle) cannot make progress — B is not in
    /// `pending_guest_threads` (it was removed when its pump began) and B
    /// cannot reach `Exited` while it is dispatching A.  On Windows this
    /// resolves because threads are preemptively scheduled; in the
    /// cooperative model we return WAIT_TIMEOUT immediately so the guest can
    /// retry the join (a plain self-join would deadlock on Windows too).
    ///
    /// Returns `PumpWaitOutcome::ProcessExit` when a pumped thread requested
    /// Drain the shared timer work sink and execute each expired timer
    /// callback in the guest context.
    ///
    /// This is called from the main message loop (e.g. inside `GetMessageW`)
    /// so that timer and wait callbacks created by `CreateTimerQueueTimer`
    /// and `RegisterWaitForSingleObject` are dispatched cooperatively.
    ///
    /// A timer callback that requests process exit (ExitProcess/exit/_exit/
    /// abort sets `process_exit_requested`) stops the drain; the caller must
    /// propagate the code so the run ends (a process-exit API never
    /// returns, so remaining callbacks must not run).
    pub(crate) fn drain_timer_work_queue(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<bool> {
        let mut did_work = false;
        loop {
            let item = {
                let mut sink = self.timer_work_sink.lock().unwrap();
                sink.pop_front()
            };
            match item {
                Some((callback, parameter)) => {
                    did_work = true;
                    let _ = self.execute_guest_callback(
                        state,
                        memory,
                        callback,
                        &[parameter],
                        "TimerQueueCallback",
                    );
                    if self.process_exit_requested.is_some() {
                        // A timer callback requested process exit — stop
                        // draining so the caller can end the run.
                        break;
                    }
                }
                None => break,
            }
        }
        Ok(did_work)
    }

    /// Run the host-side block-dispatch safepoint body.
    ///
    /// Services the guest scheduler from between-block dispatch contexts
    /// (the main execution loop's periodic safepoint):
    ///
    /// 1. pump one pending guest thread (if any is ready — the pump runs
    ///    its guest code to the next yield/exit);
    /// 2. drain the shared timer work sink (`CreateTimerQueueTimer` /
    ///    `RegisterWaitForSingleObject` callbacks);
    /// 3. deliver APCs queued for the current (main) thread;
    /// 4. poll due `SetTimer` timers and post WM_TIMER messages;
    /// 5. advance the guest clock by the measured wall `elapsed_ms` since
    ///    the previous safepoint (capped at 100 ms so a host stall cannot
    ///    jump the clock; only advanced when > 0 ms).
    ///
    /// The clock advance gives Windows semantics to guest spins — a
    /// spinning thread's time still moves, so GetTickCount/QPC advance and
    /// Sleeping workers' `wake_tick`s expire — which is what lets a
    /// `Sleep(20)` worker finish while the main thread spins.
    ///
    /// Returns the process exit code when a pumped thread or timer
    /// callback requested process exit; the caller must end the run with
    /// that code (a process-exit API never returns, so remaining work
    /// must not run).
    ///
    /// The caller must NOT invoke this while a pumped guest thread is
    /// active (`active_pumped_guest_thread.is_some()`): pumping nests
    /// guest execution, and running the safepoint inside it would recurse
    /// into another pump.  The guard below is defense-in-depth for direct
    /// callers (the main loop checks before calling).
    pub(crate) fn run_block_dispatch_safepoint(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        elapsed_ms: u64,
    ) -> AppResult<Option<i32>> {
        if self.active_pumped_guest_thread.is_some() {
            return Ok(None);
        }
        let pump_outcome = self.pump_pending_guest_thread(memory)?;
        if let Some(code) = pump_outcome.process_exit {
            return Ok(Some(code));
        }
        if self.drain_timer_work_queue(state, memory)? {
            // A timer callback may have requested process exit — propagate
            // the code so the caller ends the run.
            if let Some(code) = self.process_exit_requested {
                return Ok(Some(code as i32));
            }
        }
        let _ = self.deliver_current_thread_apcs(state, memory)?;
        let _ = self.poll_guest_timers()?;
        // Audio-interface activation completions (ActivateAudioInterfaceAsync)
        // are delivered here — asynchronously, from the runtime servicing
        // point, never inline inside the activating call.
        let _ = self.drain_pending_audio_activations(state, memory)?;
        let _ = self.drain_pending_audio_notifications(state, memory)?;
        // MF asynchronous completions (BeginGetEvent/BeginRead/BeginWrite) are
        // delivered from the same servicing point: the parked guest callback
        // fires after the Begin call returned.
        let _ = self.drain_pending_mf_async_completions(state, memory)?;
        // DirectPlay8 engine events (datagrams, connect/send completions,
        // player create/destroy, session lost) are delivered to the guest
        // message handler from this servicing point, never inline.
        let _ = self.drain_pending_dplay_events(state, memory)?;
        // Event-driven WASAPI clients are driven from the same servicing
        // point: a running client whose buffer has free space raises its
        // ready event so a guest blocked in WaitForSingleObject wakes.
        self.tick_audio_client_events();
        // Windows semantics: a spinning thread's time still moves.  Advance
        // the guest clock by the measured wall elapsed (capped) so
        // GetTickCount/QPC advance during guest spins and Sleeping
        // workers' wake_ticks expire.
        let advance_ms = elapsed_ms.min(100);
        if advance_ms > 0 {
            self.win32.record_sleep_observation(advance_ms, advance_ms);
        }
        Ok(None)
    }

    /// One GetMessageW/GetMessageA retrieval iteration: poll live input,
    /// drain the XAudio2 engines (audio keeps playing during message-loop
    /// idle), pull the first message for `thread_id` out of the queue (if
    /// any), and otherwise service the guest scheduler — pump pending guest
    /// threads, fire due `SetTimer` timers, drain expired timer/wait
    /// callbacks, then yield the CPU and return to the caller's loop.
    ///
    /// A retrieved message is written into the guest MSG structure at
    /// `msg_ptr` (x86 or x64 layout per `state.arch`).  When a pumped
    /// thread or timer callback requested process exit, the code is
    /// returned as [`GetMessagePumpOutcome::ProcessExit`] so the caller
    /// propagates it and the run terminates.
    pub(crate) fn get_message_pump(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        msg_ptr: u64,
        thread_id: u32,
    ) -> AppResult<GetMessagePumpOutcome> {
        self.poll_live_input()?;
        // Drain all XAudio2 engines to keep audio playing during
        // the message loop even when no Windows messages arrive.
        let engine_keys: Vec<u64> = self.xaudio_engines.keys().copied().collect();
        for &engine_object in &engine_keys {
            let _ = self.drain_xaudio2_engine(engine_object);
        }
        if let Some(message) = self.user32.get_message_for_thread(thread_id) {
            match state.arch {
                GuestArch::X64 => write_win64_msg(memory, msg_ptr, &message)?,
                GuestArch::X86 => write_win32_msg(memory, msg_ptr, &message)?,
            }
            return Ok(GetMessagePumpOutcome::Retrieved(message));
        }
        let pump_outcome = self.pump_pending_guest_thread(memory)?;
        if let Some(code) = pump_outcome.process_exit {
            // A pumped thread requested process exit — propagate
            // the code so the main loop terminates the run.
            return Ok(GetMessagePumpOutcome::ProcessExit(code));
        }
        if pump_outcome.did_work {
            return Ok(GetMessagePumpOutcome::Idle);
        }
        // Poll due SetTimer timers and post WM_TIMER messages so
        // guest timers fire during message-loop idle — not only
        // at block-dispatch safepoints.
        if self.poll_guest_timers()? {
            return Ok(GetMessagePumpOutcome::Idle);
        }
        // Drain expired timer and wait callbacks from the
        // background timer_work_sink (filled by CreateTimerQueueTimer
        // and RegisterWaitForSingleObject background threads).
        if self.drain_timer_work_queue(state, memory)? {
            // A timer callback may have requested process exit —
            // propagate the code so the main loop ends the run.
            if let Some(code) = self.process_exit_requested {
                return Ok(GetMessagePumpOutcome::ProcessExit(code as i32));
            }
            return Ok(GetMessagePumpOutcome::Idle);
        }
        // Deliver audio-interface activation completions
        // (ActivateAudioInterfaceAsync) during message-loop idle — the
        // same servicing point the timer/wait callbacks use.
        let _ = self.drain_pending_audio_activations(state, memory)?;
        let _ = self.drain_pending_audio_notifications(state, memory)?;
        // MF asynchronous completions (BeginGetEvent/BeginRead/BeginWrite) are
        // delivered from the same servicing point: the parked guest callback
        // fires after the Begin call returned.
        let _ = self.drain_pending_mf_async_completions(state, memory)?;
        let _ = self.drain_pending_dplay_events(state, memory)?;
        self.tick_audio_client_events();
        self.win32.sleep_ex(16, false, None)?;
        // Always yield the CPU between GetMessageW polls to prevent
        // 99% CPU usage.  Use a shorter sleep (1 ms) when a live
        // session is active so audio/frame processing isn't starved;
        // use a longer sleep (16 ms) when fully idle.
        if self.live_session.is_some() || self.dtm {
            std::thread::sleep(std::time::Duration::from_millis(1));
        } else {
            std::thread::sleep(std::time::Duration::from_millis(16));
        }
        Ok(GetMessagePumpOutcome::Idle)
    }

    /// Poll due `SetTimer` timers and post WM_TIMER messages for them to
    /// the owning thread's message queue.
    ///
    /// Returns true when at least one WM_TIMER was posted.  Called from
    /// the GetMessageW idle drain and from the block-dispatch safepoint so
    /// guest timers fire during message-loop idle, guest spins and other
    /// waits — not only at the wait sites the guest itself enters.
    ///
    /// A timer registered with a guest TIMERPROC fires as a WM_TIMER
    /// message whose lParam carries the proc; DispatchMessage invokes it
    /// (Windows semantics).
    pub(crate) fn poll_guest_timers(&mut self) -> AppResult<bool> {
        let due = self.user32.poll_timers();
        let mut posted = false;
        for (hwnd, timer_id) in due {
            let callback = self.user32.timer_callback(hwnd, timer_id);
            if self
                .user32
                .post_timer_message(hwnd, timer_id, callback)
                .is_ok()
            {
                posted = true;
            }
        }
        Ok(posted)
    }

    /// Diagnose a decrementing copy loop entered with a huge/negative count.
    ///
    /// Steam's CRT `memcpy` (`mov edx,[esi]; mov [edi],edx; ...; sub ecx,1`)
    /// reached with ECX >= 0x8000_0000 writes past the heap block.  Record the
    /// block, count, source/dest, the bounded API history ring and the guest
    /// EBP chain — diagnostic only; the fault is still delivered.
    /// Opt-in bounded `thiscall`/ECX trace (`CASA1_ECX_TRACE=1`).
    ///
    /// Records ECX (and the guest call site from [ESP]) at entry to the MSVC
    /// `std::string` helpers and the protobuf parser, so a wrong `this`
    /// pointer is attributable to the caller's `mov ecx,...`/`lea ecx,...`
    /// rather than guessed.
    fn maybe_trace_thiscall(&mut self, state: &CpuState, memory: &MemoryImage) {
        use std::sync::atomic::Ordering;
        static ECX_TRACE_REPORTS: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(0);
        const ECX_TRACE_LIMIT: u32 = 4096;
        if self.guest_arch != GuestArch::X86 || std::env::var_os("CASA1_ECX_TRACE").is_none() {
            return;
        }
        let rva = state.rip.saturating_sub(self.mapped_image_base);
        let watched = matches!(
            rva,
            0x6cf90
                | 0x76430
                | 0x6d420
                | 0x14e980
                | 0x192c00
                | 0x192c20
                | 0x1a2980
                | 0x1a2ae0
                | 0x14ee00
                | 0x14ee87
        );
        if !watched {
            return;
        }
        if ECX_TRACE_REPORTS.fetch_add(1, Ordering::Relaxed) >= ECX_TRACE_LIMIT {
            return;
        }
        let esp = state.get(Register::Rsp);
        let return_address = crate::runtime::guest_memory::read_u32(memory, esp)
            .ok()
            .map(u64::from);
        let mut args = Vec::new();
        for slot in 0..4_u64 {
            if let Ok(raw) = crate::runtime::guest_memory::read_u32(memory, esp + 4 + slot * 4) {
                args.push(format!("{raw:#x}"));
            }
        }
        let record = BTreeMap::from([
            ("rva".to_string(), json!(format!("{rva:#x}"))),
            (
                "ecx".to_string(),
                json!(format!("{:#x}", state.get(Register::Rcx))),
            ),
            (
                "edx".to_string(),
                json!(format!("{:#x}", state.get(Register::Rdx))),
            ),
            (
                "eax".to_string(),
                json!(format!("{:#x}", state.get(Register::Rax))),
            ),
            ("esp".to_string(), json!(format!("{esp:#x}"))),
            (
                "ebp".to_string(),
                json!(format!("{:#x}", state.get(Register::Rbp))),
            ),
            (
                "call_site_rva".to_string(),
                json!(return_address.map(|value| {
                    format!("{:#x}", value.saturating_sub(self.mapped_image_base))
                })),
            ),
            ("stack_args".to_string(), json!(args)),
        ]);
        eprintln!(
            "[thiscall] rva={rva:#x} ecx={:#x} call_site={} edx={:#x} eax={:#x}",
            state.get(Register::Rcx),
            return_address
                .map(|value| format!("{:#x}", value.saturating_sub(self.mapped_image_base)))
                .unwrap_or_else(|| "<none>".to_string()),
            state.get(Register::Rdx),
            state.get(Register::Rax),
        );
        self.push_trace("process", "ThiscallTrace", record, json!(null));
    }

    fn maybe_report_huge_copy(&mut self, state: &CpuState, memory: &MemoryImage) {
        use std::sync::atomic::Ordering;
        static HUGE_COPY_REPORTS: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(0);
        const HUGE_COPY_REPORT_LIMIT: u32 = 8;
        if self.guest_arch != GuestArch::X86 || state.get(Register::Rcx) < 0x8000_0000 {
            return;
        }
        let Ok(bytes) = memory.read_bytes(state.rip, 16) else {
            return;
        };
        let is_copy_loop = bytes
            .windows(4)
            .any(|window| window == [0x83, 0xe9, 0x01, 0x75])
            || bytes.windows(2).any(|window| {
                matches!(
                    window,
                    [0xf3, 0xa4] | [0xf3, 0xa5] | [0xf2, 0xa4] | [0xf2, 0xa5]
                )
            });
        if !is_copy_loop {
            return;
        }
        if HUGE_COPY_REPORTS.fetch_add(1, Ordering::Relaxed) >= HUGE_COPY_REPORT_LIMIT {
            return;
        }
        let mut frames = Vec::new();
        let mut frame = state.get(Register::Rbp);
        for _ in 0..8 {
            if frame < 0x1_0000 {
                break;
            }
            let ret = crate::runtime::guest_memory::read_u32(memory, frame + 4)
                .ok()
                .map(u64::from);
            let mut args = Vec::new();
            for slot in 0..4_u64 {
                if let Ok(raw) =
                    crate::runtime::guest_memory::read_u32(memory, frame + 8 + slot * 4)
                {
                    args.push(format!("{raw:#x}"));
                }
            }
            frames.push(json!({
                "ebp": format!("{frame:#x}"),
                "ret": ret.map(|value| format!("{value:#x}")),
                "ret_rva": ret.map(|value| {
                    format!("{:#x}", value.saturating_sub(self.mapped_image_base))
                }),
                "args": args,
            }));
            let next =
                u64::from(crate::runtime::guest_memory::read_u32(memory, frame).unwrap_or(0));
            if next <= frame {
                break;
            }
            frame = next;
        }
        let history: Vec<serde_json::Value> = self
            .api_history
            .iter()
            .map(|entry| serde_json::from_str(entry).unwrap_or(serde_json::Value::Null))
            .collect();
        let mut record = BTreeMap::new();
        record.insert(
            "block_rva".to_string(),
            json!(format!(
                "{:#x}",
                state.rip.saturating_sub(self.mapped_image_base)
            )),
        );
        record.insert("block".to_string(), json!(format!("{:#x}", state.rip)));
        record.insert(
            "count".to_string(),
            json!(format!("{:#x}", state.get(Register::Rcx))),
        );
        record.insert(
            "source".to_string(),
            json!(format!("{:#x}", state.get(Register::Rsi))),
        );
        record.insert(
            "destination".to_string(),
            json!(format!("{:#x}", state.get(Register::Rdi))),
        );
        record.insert(
            "first_bytes".to_string(),
            json!(
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join("")
            ),
        );
        record.insert("api_history".to_string(), json!(history));
        record.insert("frames".to_string(), json!(frames));
        record.insert(
            "last_thunk".to_string(),
            json!(crate::steam_milestones::snapshot_last_thunk()),
        );
        eprintln!(
            "[huge-copy] block_rva={:#x} count={:#x} src={:#x} dst={:#x} last_api={}",
            state.rip.saturating_sub(self.mapped_image_base),
            state.get(Register::Rcx),
            state.get(Register::Rsi),
            state.get(Register::Rdi),
            self.api_history
                .back()
                .cloned()
                .unwrap_or_else(|| "<none>".to_string()),
        );
        self.push_trace("process", "HugeCopyCount", record, json!(null));
    }

    pub(crate) fn execute_ir_with_guest_exception_delivery(
        &mut self,
        engine: &CpuExecutionEngine,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        ir: &[crate::cpu::IrInstruction],
        label: &str,
    ) -> AppResult<bool> {
        self.maybe_trace_thiscall(state, memory);
        self.maybe_report_huge_copy(state, memory);
        crate::jit::set_pe_runtime_pointer(self as *mut PeHostRuntime as *mut libc::c_void);
        let result = engine.execute_with_jit(state, memory, ir, self.jit_runtime.as_mut());
        crate::jit::set_pe_runtime_pointer(std::ptr::null_mut());
        match result {
            Ok(_) => Ok(false),
            Err(error) => {
                if self.try_deliver_x86_access_violation(state, memory, &error, label)? {
                    return Ok(true);
                }
                // ── x64 SEH / VEH Exception Dispatch ────────────────────────────
                // If the guest is x64 and the fault is an unmapped guest memory
                // access, try the SEH/VEH subsystem before propagating the error.
                if self.guest_arch == GuestArch::X64 {
                    if let Some(fault_address) = guest_access_violation_address(&error) {
                        let ctx = crate::seh::X64Context {
                            rax: state.gpr[0],
                            rcx: state.gpr[1],
                            rdx: state.gpr[2],
                            rbx: state.gpr[3],
                            rsp: state.gpr[4],
                            rbp: state.gpr[5],
                            rsi: state.gpr[6],
                            rdi: state.gpr[7],
                            r8: state.gpr[8],
                            r9: state.gpr[9],
                            r10: state.gpr[10],
                            r11: state.gpr[11],
                            r12: state.gpr[12],
                            r13: state.gpr[13],
                            r14: state.gpr[14],
                            r15: state.gpr[15],
                            rip: state.rip,
                            xmm: {
                                let mut xmm = [crate::seh::Xmm128::default(); 16];
                                for (i, slot) in xmm.iter_mut().enumerate() {
                                    *slot = crate::seh::Xmm128 {
                                        low: state.xmm[i].low,
                                        high: state.xmm[i].high,
                                    };
                                }
                                xmm
                            },
                        };
                        // Guest-stack memory reader: the SEH unwinder reads
                        // return addresses and saved non-volatile registers
                        // from the real guest stack (outside the image), so it
                        // must read absolute guest addresses from `memory`.
                        let mem_ref: &MemoryImage = memory;
                        let stack_reader = |addr: u64, buf: &mut [u8]| -> bool {
                            mem_ref.read_into(addr, buf).is_ok()
                        };
                        let seh_handled = self
                            .seh
                            .dispatch(
                                crate::seh::STATUS_ACCESS_VIOLATION,
                                fault_address,
                                &ctx,
                                self.mapped_image_base,
                                &stack_reader,
                            )
                            .is_ok();

                        // ── Guest VEH Callback Invocation ────────────────────
                        // After SEH/VEH dispatch, drain any pending guest VEH
                        // callbacks that were queued by the VEH closures. These
                        // callbacks represent guest-registered vectored exception
                        // handlers that need to be invoked with the exception
                        // pointers serialized to guest memory.
                        let pending_veh = crate::seh::drain_pending_guest_veh();
                        for (veh_callback, veh_record, veh_context) in &pending_veh {
                            self.invoke_guest_veh_callback(
                                state,
                                memory,
                                *veh_callback,
                                veh_record,
                                veh_context,
                            )?;
                        }

                        // If SEH claimed the exception, return success regardless
                        // of guest VEH callbacks (SEH takes priority).
                        if seh_handled {
                            return Ok(true);
                        }
                    }
                    // ── x64 Breakpoint Dispatch ──────────────────────────────────
                    // CPU breakpoints (int 0xCC, int 0x2d, int 0x03) produce an
                    // error via IrInstruction::Breakpoint; route through SEH as
                    // STATUS_BREAKPOINT so that __except(filter) / VEH catches it.
                    if let Some(fault_address) = guest_breakpoint_address(&error) {
                        let ctx = crate::seh::X64Context {
                            rax: state.gpr[0],
                            rcx: state.gpr[1],
                            rdx: state.gpr[2],
                            rbx: state.gpr[3],
                            rsp: state.gpr[4],
                            rbp: state.gpr[5],
                            rsi: state.gpr[6],
                            rdi: state.gpr[7],
                            r8: state.gpr[8],
                            r9: state.gpr[9],
                            r10: state.gpr[10],
                            r11: state.gpr[11],
                            r12: state.gpr[12],
                            r13: state.gpr[13],
                            r14: state.gpr[14],
                            r15: state.gpr[15],
                            rip: state.rip,
                            xmm: {
                                let mut xmm = [crate::seh::Xmm128::default(); 16];
                                for (i, slot) in xmm.iter_mut().enumerate() {
                                    *slot = crate::seh::Xmm128 {
                                        low: state.xmm[i].low,
                                        high: state.xmm[i].high,
                                    };
                                }
                                xmm
                            },
                        };
                        let mem_ref: &MemoryImage = memory;
                        let stack_reader = |addr: u64, buf: &mut [u8]| -> bool {
                            mem_ref.read_into(addr, buf).is_ok()
                        };
                        let seh_handled = self
                            .seh
                            .dispatch(
                                crate::seh::STATUS_BREAKPOINT,
                                fault_address,
                                &ctx,
                                self.mapped_image_base,
                                &stack_reader,
                            )
                            .is_ok();

                        let pending_veh = crate::seh::drain_pending_guest_veh();
                        for (veh_callback, veh_record, veh_context) in &pending_veh {
                            self.invoke_guest_veh_callback(
                                state,
                                memory,
                                *veh_callback,
                                veh_record,
                                veh_context,
                            )?;
                        }

                        if seh_handled {
                            return Ok(true);
                        }
                    }
                    // ── x64 General CPU Fault → SEH Catch-all ─────────────────
                    // Any remaining RcUnimplInsn errors (divide-by-zero,
                    // unimplemented opcodes, etc.) are mapped to their
                    // corresponding NTSTATUS and dispatched through SEH so that
                    // the guest's __except / VEH handlers can attempt recovery.
                    if let Some((code, fault_address)) = map_cpu_error_to_exception(&error) {
                        let ctx = crate::seh::X64Context {
                            rax: state.gpr[0],
                            rcx: state.gpr[1],
                            rdx: state.gpr[2],
                            rbx: state.gpr[3],
                            rsp: state.gpr[4],
                            rbp: state.gpr[5],
                            rsi: state.gpr[6],
                            rdi: state.gpr[7],
                            r8: state.gpr[8],
                            r9: state.gpr[9],
                            r10: state.gpr[10],
                            r11: state.gpr[11],
                            r12: state.gpr[12],
                            r13: state.gpr[13],
                            r14: state.gpr[14],
                            r15: state.gpr[15],
                            rip: state.rip,
                            xmm: {
                                let mut xmm = [crate::seh::Xmm128::default(); 16];
                                for (i, slot) in xmm.iter_mut().enumerate() {
                                    *slot = crate::seh::Xmm128 {
                                        low: state.xmm[i].low,
                                        high: state.xmm[i].high,
                                    };
                                }
                                xmm
                            },
                        };
                        let mem_ref: &MemoryImage = memory;
                        let stack_reader = |addr: u64, buf: &mut [u8]| -> bool {
                            mem_ref.read_into(addr, buf).is_ok()
                        };
                        let seh_handled = self
                            .seh
                            .dispatch(
                                code,
                                fault_address,
                                &ctx,
                                self.mapped_image_base,
                                &stack_reader,
                            )
                            .is_ok();

                        let pending_veh = crate::seh::drain_pending_guest_veh();
                        for (veh_callback, veh_record, veh_context) in &pending_veh {
                            self.invoke_guest_veh_callback(
                                state,
                                memory,
                                *veh_callback,
                                veh_record,
                                veh_context,
                            )?;
                        }

                        if seh_handled {
                            return Ok(true);
                        }
                    }
                }
                Err(error)
            }
        }
    }

    pub(crate) fn try_deliver_x86_access_violation(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        error: &AppError,
        label: &str,
    ) -> AppResult<bool> {
        if self.guest_arch != GuestArch::X86 || self.delivering_guest_exception {
            self.push_trace(
                "process",
                "GuestExceptionAttempt",
                BTreeMap::from([
                    ("label".to_string(), json!(label)),
                    ("reason".to_string(), json!("arch_or_reentrant")),
                    (
                        "guest_arch".to_string(),
                        json!(format!("{:?}", self.guest_arch)),
                    ),
                    (
                        "delivering_guest_exception".to_string(),
                        json!(self.delivering_guest_exception),
                    ),
                    ("fault_message".to_string(), json!(error.message.clone())),
                ]),
                json!(false),
            );
            return Ok(false);
        }
        let Some(fault_address) = guest_access_violation_address(error) else {
            self.push_trace(
                "process",
                "GuestExceptionAttempt",
                BTreeMap::from([
                    ("label".to_string(), json!(label)),
                    ("reason".to_string(), json!("not_access_violation")),
                    ("fault_message".to_string(), json!(error.message.clone())),
                ]),
                json!(false),
            );
            return Ok(false);
        };
        if state.segment_bases.fs == 0 {
            self.push_trace(
                "process",
                "GuestExceptionAttempt",
                BTreeMap::from([
                    ("label".to_string(), json!(label)),
                    ("reason".to_string(), json!("missing_fs_base")),
                    (
                        "fault_address".to_string(),
                        json!(format!("{fault_address:#x}")),
                    ),
                    ("fault_rip".to_string(), json!(format!("{:#x}", state.rip))),
                ]),
                json!(false),
            );
            return Ok(false);
        }
        // The Steam bootstrapper's 32-bit `memcpy` loop
        // (`mov edx,[esi]; mov [edi],edx; add edi,4; add esi,4; sub ecx,1`)
        // faulting means a negative byte count was passed.  Record the EBP
        // chain so the guest caller that supplied the length is identifiable.
        if let Ok(bytes) = memory.read_bytes(state.rip, 6)
            && bytes == [0x8b, 0x16, 0x89, 0x17, 0x83, 0xc7]
        {
            let mut frames = Vec::new();
            let mut frame = state.get(Register::Rbp);
            for _ in 0..8 {
                if frame < 0x1_0000 {
                    break;
                }
                let ret = crate::runtime::guest_memory::read_u32(memory, frame + 4)
                    .ok()
                    .map(u64::from);
                let mut args = Vec::new();
                for slot in 0..4_u64 {
                    if let Ok(raw) =
                        crate::runtime::guest_memory::read_u32(memory, frame + 8 + slot * 4)
                    {
                        args.push(format!("{raw:#x}"));
                    }
                }
                frames.push(json!({
                    "ebp": format!("{frame:#x}"),
                    "ret": ret.map(|value| format!("{value:#x}")),
                    "ret_rva": ret.map(|value| {
                        format!("{:#x}", value.saturating_sub(self.mapped_image_base))
                    }),
                    "args": args,
                }));
                let next =
                    u64::from(crate::runtime::guest_memory::read_u32(memory, frame).unwrap_or(0));
                if next <= frame {
                    break;
                }
                frame = next;
            }
            self.push_trace(
                "process",
                "X86AccessViolationFrames",
                BTreeMap::from([
                    (
                        "fault_address".to_string(),
                        json!(format!("{fault_address:#x}")),
                    ),
                    ("fault_rip".to_string(), json!(format!("{:#x}", state.rip))),
                    (
                        "fault_rip_rva".to_string(),
                        json!(format!(
                            "{:#x}",
                            state.rip.saturating_sub(self.mapped_image_base)
                        )),
                    ),
                    (
                        "ecx".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rcx))),
                    ),
                    (
                        "esi".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rsi))),
                    ),
                    (
                        "edi".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rdi))),
                    ),
                    ("frames".to_string(), json!(frames)),
                ]),
                json!(null),
            );
        }
        self.dispatch_x86_exception(
            state,
            memory,
            crate::cpu::EXCEPTION_ACCESS_VIOLATION,
            fault_address,
            label,
            &[],
        )
    }

    /// Walk the guest's x86 FS:0 SEH chain and invoke handlers for `code`
    /// (an access violation fault or an explicit RaiseException).  Returns
    /// (capped at 15 entries, the Windows limit).
    pub(crate) fn dispatch_x86_exception(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        code: u32,
        fault_address: u64,
        label: &str,
        parameters: &[u32],
    ) -> AppResult<bool> {
        if self.delivering_guest_exception {
            return Ok(false);
        }
        if state.segment_bases.fs == 0 {
            return Ok(false);
        }
        let mut registration =
            match read_guest_pointer(memory, state.segment_bases.fs, GuestArch::X86) {
                Ok(value) => value,
                Err(_err) => {
                    return Ok(false);
                }
            };
        self.push_trace(
            "process",
            "GuestExceptionAttempt",
            BTreeMap::from([
                ("label".to_string(), json!(label)),
                ("reason".to_string(), json!("dispatch_entry")),
                (
                    "fault_address".to_string(),
                    json!(format!("{fault_address:#x}")),
                ),
                ("fault_rip".to_string(), json!(format!("{:#x}", state.rip))),
                (
                    "registration".to_string(),
                    json!(format!("{registration:#x}")),
                ),
                (
                    "fs_base".to_string(),
                    json!(format!("{:#x}", state.segment_bases.fs)),
                ),
            ]),
            json!(true),
        );
        while registration != 0 && registration != X86_EXCEPTION_CHAIN_END {
            let next = match read_guest_u32(memory, registration) {
                Ok(value) => u64::from(value),
                Err(_) => {
                    return Ok(false);
                }
            };
            let handler = match read_guest_u32(memory, registration + 4) {
                Ok(value) => u64::from(value),
                Err(_) => {
                    return Ok(false);
                }
            };
            if handler == 0 {
                registration = next;
                continue;
            }
            let exception_record =
                self.alloc_zeroed(memory, X86_EXCEPTION_RECORD_SIZE as usize, 4)?;
            let context_record = self.alloc_zeroed(memory, X86_CONTEXT_SIZE as usize, 4)?;
            write_x86_exception_record(
                memory,
                exception_record,
                code,
                fault_address,
                state.rip as u32,
                parameters,
            );
            write_x86_context(memory, context_record, state);
            let saved_state = state.clone();

            let was_delivering = std::mem::replace(&mut self.delivering_guest_exception, true);
            let disposition = self.execute_guest_callback(
                state,
                memory,
                handler,
                &[exception_record, registration, context_record, 0],
                label,
            );
            self.delivering_guest_exception = was_delivering;
            let disposition = match disposition {
                Ok(value) => value as u32,
                Err(error) => {
                    *state = saved_state;
                    self.delivering_guest_exception = was_delivering;
                    return Err(error);
                }
            };
            let context_eip = read_guest_u32(memory, context_record + X86_CONTEXT_OFFSET_EIP)
                .ok()
                .map(u64::from);
            self.push_trace(
                "process",
                "GuestExceptionDispatch",
                BTreeMap::from([
                    (
                        "fault_address".to_string(),
                        json!(format!("{fault_address:#x}")),
                    ),
                    (
                        "fault_rip".to_string(),
                        json!(format!("{:#x}", saved_state.rip)),
                    ),
                    (
                        "registration".to_string(),
                        json!(format!("{registration:#x}")),
                    ),
                    ("handler".to_string(), json!(format!("{handler:#x}"))),
                    ("disposition".to_string(), json!(disposition)),
                    (
                        "context_eip".to_string(),
                        json!(
                            context_eip
                                .map(|value| format!("{value:#x}"))
                                .unwrap_or_else(|| "<unavailable>".to_string())
                        ),
                    ),
                ]),
                json!(disposition),
            );

            match disposition {
                X86_EXCEPTION_CONTINUE_EXECUTION => {
                    read_x86_context(memory, context_record, state)?;
                    state.segment_bases = saved_state.segment_bases;
                    if state.rip == 0 {
                        *state = saved_state;
                        return Ok(false);
                    }
                    return Ok(true);
                }
                X86_EXCEPTION_CONTINUE_SEARCH => {
                    *state = saved_state;
                    registration = next;
                }
                _ => {
                    *state = saved_state;
                    return Ok(false);
                }
            }
        }
        Ok(false)
    }

    pub(crate) fn push_trace(
        &mut self,
        category: &str,
        call_id: &str,
        parameters: BTreeMap<String, Value>,
        return_value: Value,
    ) {
        if let Some(allowed_trace_categories) = &self.allowed_trace_categories
            && !allowed_trace_categories.contains(category)
        {
            return;
        }
        self.trace_events.push(trace_event(
            self.next_trace_index,
            category,
            call_id,
            parameters,
            return_value,
            Vec::new(),
        ));
        self.next_trace_index += 1;
    }

    pub(crate) fn trace_steam_critical_section_state(
        &mut self,
        site: &str,
        caller_rva: u64,
        address: u64,
        before: Option<usize>,
        after: Option<usize>,
    ) {
        self.push_trace(
            "process",
            "SteamCriticalSectionState",
            BTreeMap::from([
                ("site".to_string(), json!(site)),
                ("caller_rva".to_string(), json!(format!("{caller_rva:#x}"))),
                (
                    "critical_section".to_string(),
                    json!(format!("{address:#x}")),
                ),
                ("before".to_string(), json!(before)),
                ("after".to_string(), json!(after)),
                ("known_before".to_string(), json!(before.is_some())),
                ("known_after".to_string(), json!(after.is_some())),
            ]),
            json!(after.unwrap_or(0)),
        );
    }

    pub(crate) fn trace_steam_pre_report_pointer_state(
        &mut self,
        memory: &MemoryImage,
        state: &CpuState,
        block_rva: u32,
    ) {
        if self.guest_arch != GuestArch::X86 {
            return;
        }

        if !matches!(block_rva, 0x0016_de51 | 0x0016_de6d | 0x0016_e0c0) {
            return;
        }

        let cookie_address = self.mapped_image_base + 0x003c_bfd4;
        let cookie = probe_read_guest_u32(memory, cookie_address);
        let decode_field = |raw: u32, cookie: u32| (raw ^ cookie).rotate_right(cookie & 31);
        match block_rva {
            0x0016_de51 => {
                let context_ptr = state.get(Register::Rcx);
                let first_ptr = probe_read_guest_u32(memory, context_ptr).map(u64::from);
                let second_ptr = first_ptr
                    .and_then(|value| probe_read_guest_u32(memory, value))
                    .map(u64::from);
                self.push_trace(
                    "process",
                    "SteamPreReportPointerState",
                    BTreeMap::from([
                        ("site".to_string(), json!(format!("{block_rva:#x}"))),
                        (
                            "cookie_address".to_string(),
                            json!(format!("{cookie_address:#x}")),
                        ),
                        (
                            "cookie".to_string(),
                            json!(
                                cookie
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                            ),
                        ),
                        (
                            "context_ptr".to_string(),
                            json!(format!("{context_ptr:#x}")),
                        ),
                        (
                            "first_ptr".to_string(),
                            json!(
                                first_ptr
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                            ),
                        ),
                        (
                            "second_ptr".to_string(),
                            json!(
                                second_ptr
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                            ),
                        ),
                    ]),
                    json!(format!("{block_rva:#x}")),
                );
            }
            0x0016_de6d => {
                let node_ptr = state.get(Register::Rsi);
                let raw_values = (0..3)
                    .map(|slot| probe_read_guest_u32(memory, node_ptr + slot * 4))
                    .collect::<Vec<_>>();
                let raw_fields = raw_values
                    .iter()
                    .map(|value| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    })
                    .collect::<Vec<_>>();
                let decoded_values = if let Some(cookie) = cookie {
                    raw_values
                        .iter()
                        .map(|value| value.map(|value| decode_field(value, cookie)))
                        .collect::<Vec<_>>()
                } else {
                    vec![None, None, None]
                };
                let decoded_fields = decoded_values
                    .iter()
                    .map(|value| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    })
                    .collect::<Vec<_>>();
                let probe_addresses = [
                    decoded_values.first().copied().flatten(),
                    decoded_values
                        .get(1)
                        .copied()
                        .flatten()
                        .and_then(|value| value.checked_sub(4)),
                    decoded_values
                        .get(2)
                        .copied()
                        .flatten()
                        .and_then(|value| value.checked_sub(4)),
                ];
                let decoded_probe_readable = probe_addresses
                    .iter()
                    .map(|address| {
                        address
                            .map(|address| {
                                probe_read_guest_u32(memory, u64::from(address)).is_some()
                            })
                            .unwrap_or(false)
                    })
                    .collect::<Vec<_>>();
                let decoded_probe_addresses = probe_addresses
                    .iter()
                    .map(|address| {
                        address
                            .map(|address| format!("{address:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    })
                    .collect::<Vec<_>>();
                self.push_trace(
                    "process",
                    "SteamPreReportPointerState",
                    BTreeMap::from([
                        ("site".to_string(), json!(format!("{block_rva:#x}"))),
                        (
                            "cookie_address".to_string(),
                            json!(format!("{cookie_address:#x}")),
                        ),
                        (
                            "cookie".to_string(),
                            json!(
                                cookie
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                            ),
                        ),
                        ("node_ptr".to_string(), json!(format!("{node_ptr:#x}"))),
                        ("raw_fields".to_string(), json!(raw_fields)),
                        ("decoded_fields".to_string(), json!(decoded_fields)),
                        (
                            "decoded_probe_addresses".to_string(),
                            json!(decoded_probe_addresses),
                        ),
                        (
                            "decoded_probe_readable".to_string(),
                            json!(decoded_probe_readable),
                        ),
                    ]),
                    json!(format!("{block_rva:#x}")),
                );
            }
            0x0016_e0c0 => {
                let stack_arg0 =
                    probe_read_guest_u32(memory, state.get(Register::Rsp) + 4).map(u64::from);
                let stack_arg1 =
                    probe_read_guest_u32(memory, state.get(Register::Rsp) + 8).map(u64::from);
                self.push_trace(
                    "process",
                    "SteamPreReportPointerState",
                    BTreeMap::from([
                        ("site".to_string(), json!(format!("{block_rva:#x}"))),
                        (
                            "cookie".to_string(),
                            json!(
                                cookie
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                            ),
                        ),
                        (
                            "stack_arg0".to_string(),
                            json!(
                                stack_arg0
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                            ),
                        ),
                        (
                            "stack_arg1".to_string(),
                            json!(
                                stack_arg1
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                            ),
                        ),
                    ]),
                    json!(format!("{block_rva:#x}")),
                );
            }
            _ => {}
        }
    }
}
