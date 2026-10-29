//! CRT runtime helpers: errno/TLS model, stdio stream bookkeeping, formatted
//! output/scanning, file open/read/write, qsort and locale mapping.  Moved out
//! of the runtime monolith as inherent `PeHostRuntime` impls; the dispatch
//! match arms keep calling the same methods.

use super::super::*;

impl PeHostRuntime {
    // ── Patch 6b: CRT errno / doserrno model ──────────────────────────────────
    // The errno int lives in guest memory at a stable per-thread address.  For
    // x86 guests the address is stored in a dedicated TLS vector slot (found
    // with the same first-free search as `TlsAlloc`, so it never collides with
    // guest-allocated slots), which `prepare_guest_thread_entry` re-creates
    // per thread.  For x64 guests (no TLS vector) a single stable allocation is
    // used.  `_errno`/`_doserrno` return this address; the guest reads and
    // writes the int through it directly.
    pub(crate) fn allocate_crt_tls_storage(
        &mut self,
        memory: &mut MemoryImage,
        seed: u32,
    ) -> AppResult<u32> {
        let storage = self.alloc_u32(memory, seed)?;
        let slot = (1_u32..4096)
            .find(|candidate| !self.tls_slots.contains_key(candidate))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    "CRT TLS slot space exhausted (4096 slots)",
                )
            })?;
        self.tls_slots.insert(slot, storage);
        self.sync_guest_tls_slot(memory, slot, storage)?;
        Ok(slot)
    }

    pub(crate) fn crt_tls_storage(&self, memory: &MemoryImage, slot: u32) -> AppResult<u64> {
        if self.tls_vector_ptr != 0 && slot != 0 {
            let slot_address = self
                .tls_vector_ptr
                .wrapping_add(slot as u64 * self.guest_arch.pointer_bytes() as u64);
            return read_guest_pointer(memory, slot_address, self.guest_arch);
        }
        Ok(0)
    }

    /// Guest pointer to the current thread's errno int (allocating it on first
    /// use).  Fresh storage is seeded with the host-side mirror so values set
    /// via `set_crt_errno` before the slot was allocated are not lost.
    pub(crate) fn crt_errno_ptr(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        if self.crt_errno_slot == 0 {
            if self.tls_vector_ptr == 0 {
                if self.crt_errno_storage == 0 {
                    self.crt_errno_storage = self.alloc_u32(memory, self.crt_errno_value as u32)?;
                }
                return Ok(self.crt_errno_storage);
            }
            self.crt_errno_slot =
                self.allocate_crt_tls_storage(memory, self.crt_errno_value as u32)?;
        }
        let ptr = self.crt_tls_storage(memory, self.crt_errno_slot)?;
        if ptr != 0 {
            return Ok(ptr);
        }
        let storage = self.alloc_u32(memory, self.crt_errno_value as u32)?;
        self.tls_slots.insert(self.crt_errno_slot, storage);
        self.sync_guest_tls_slot(memory, self.crt_errno_slot, storage)?;
        Ok(storage)
    }

    /// Guest pointer to the current thread's doserrno int (allocating it on
    /// first use).  Fresh storage is seeded with the host-side mirror.
    pub(crate) fn crt_doserrno_ptr(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        if self.crt_doserrno_slot == 0 {
            if self.tls_vector_ptr == 0 {
                if self.crt_doserrno_storage == 0 {
                    self.crt_doserrno_storage =
                        self.alloc_u32(memory, self.crt_doserrno_value as u32)?;
                }
                return Ok(self.crt_doserrno_storage);
            }
            self.crt_doserrno_slot =
                self.allocate_crt_tls_storage(memory, self.crt_doserrno_value as u32)?;
        }
        let ptr = self.crt_tls_storage(memory, self.crt_doserrno_slot)?;
        if ptr != 0 {
            return Ok(ptr);
        }
        let storage = self.alloc_u32(memory, self.crt_doserrno_value as u32)?;
        self.tls_slots.insert(self.crt_doserrno_slot, storage);
        self.sync_guest_tls_slot(memory, self.crt_doserrno_slot, storage)?;
        Ok(storage)
    }

    /// Host-side helper used by failing CRT thunks: records `value` as the
    /// current thread's errno, both in the guest-visible int (if the TLS
    /// storage is initialised) and in the host mirror.  CRT functions do NOT
    /// set GetLastError.
    pub(crate) fn write_crt_errno_value(&self, memory: &mut MemoryImage, ptr: u64, value: i32) {
        if ptr != 0 {
            memory.map_bytes(ptr, &value.to_le_bytes());
        }
    }

    pub(crate) fn set_crt_errno(&mut self, memory: &mut MemoryImage, value: i32) {
        self.crt_errno_value = value;
        if self.tls_vector_ptr != 0 && self.crt_errno_slot != 0 {
            let ptr = self
                .crt_tls_storage(memory, self.crt_errno_slot)
                .unwrap_or(0);
            if ptr != 0 {
                self.write_crt_errno_value(memory, ptr, value);
                return;
            }
        }
        self.write_crt_errno_value(memory, self.crt_errno_storage, value);
    }

    /// Host-side helper mirroring `set_crt_errno` for `_doserrno`.
    pub(crate) fn set_crt_doserrno(&mut self, memory: &mut MemoryImage, value: i32) {
        self.crt_doserrno_value = value;
        if self.tls_vector_ptr != 0 && self.crt_doserrno_slot != 0 {
            let ptr = self
                .crt_tls_storage(memory, self.crt_doserrno_slot)
                .unwrap_or(0);
            if ptr != 0 {
                self.write_crt_errno_value(memory, ptr, value);
                return;
            }
        }
        self.write_crt_errno_value(memory, self.crt_doserrno_storage, value);
    }

    /// Current errno value for the running thread (guest storage wins when
    /// present — the guest may have written to the `_errno()` int directly).
    pub(crate) fn crt_errno_get(&mut self, memory: &mut MemoryImage) -> i32 {
        let mut value = self.crt_errno_value;
        let ptr = if self.tls_vector_ptr != 0 && self.crt_errno_slot != 0 {
            self.crt_tls_storage(memory, self.crt_errno_slot).ok()
        } else if self.crt_errno_storage != 0 {
            Some(self.crt_errno_storage)
        } else {
            None
        };
        if let Some(ptr) = ptr
            && ptr != 0
            && let Ok(bytes) = memory.read_bytes(ptr, 4)
        {
            value = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        self.crt_errno_value = value;
        value
    }

    /// Invoke the guest's `_invalid_parameter_handler` (installed via
    /// `_set_invalid_parameter_handler`) with the standard "noinfo" argument
    /// list (expression, function, file, line, reserved), then — because the
    /// Windows CRT terminates after a returning handler — report that the
    /// guest should be aborted.  With no handler installed the guest is
    /// aborted immediately (emulating the default Watson/abort behavior).
    ///
    /// Returns `true` when the caller must terminate the guest (abort).
    pub(crate) fn raise_invalid_parameter(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        expression: u64,
        file: u64,
        line: u32,
    ) -> AppResult<bool> {
        let handler = self.invalid_parameter_handler;
        // Persist the complete invalid-parameter context BEFORE invoking the
        // guest handler: the handler may terminate the process, and the
        // expression/function/file/line arguments are otherwise lost.
        let mut record = BTreeMap::new();
        record.insert(
            "expression_pointer".to_string(),
            json!(format!("{expression:#x}")),
        );
        record.insert(
            "expression".to_string(),
            json!(describe_guest_string(memory, expression).unwrap_or_default()),
        );
        record.insert("file_pointer".to_string(), json!(format!("{file:#x}")));
        record.insert(
            "file".to_string(),
            json!(describe_guest_string(memory, file).unwrap_or_default()),
        );
        record.insert("line".to_string(), json!(line));
        record.insert("handler".to_string(), json!(format!("{handler:#x}")));
        record.insert("caller_rip".to_string(), json!(format!("{:#x}", state.rip)));
        self.push_trace("process", "InvalidParameter", record, json!(null));
        if handler != 0 {
            let _ = self.execute_guest_callback(
                state,
                memory,
                handler,
                &[expression, 0, file, u64::from(line), 0],
                "invalid_parameter_handler",
            )?;
        }
        Ok(true)
    }

    /// Capture the guest `EXCEPTION_POINTERS` at an unhandled exception so a
    /// guest-side UCRT `_invalid_parameter` report is diagnosable.
    ///
    /// A statically linked CRT does not import `_invalid_parameter`; it calls
    /// its own copy, then `_invoke_watson` → `UnhandledExceptionFilter` →
    /// `TerminateProcess(STATUS_INVALID_CRUNTIME_PARAMETER)`.  At that point
    /// the expression/function/file/line arguments are still in the caller
    /// frames on the guest stack, so record the exception record, the x86
    /// CONTEXT, and an EBP-chain dump with printable pointer arguments
    /// decoded.  This is observational only: the guest still terminates.
    pub(crate) fn capture_unhandled_exception_context(
        &mut self,
        state: &CpuState,
        memory: &MemoryImage,
        exception_info: u64,
    ) {
        use crate::runtime::guest_memory::read_u32;
        if self.guest_arch != GuestArch::X86 || exception_info == 0 {
            return;
        }
        let mut context = BTreeMap::new();
        context.insert(
            "exception_info".to_string(),
            json!(format!("{exception_info:#x}")),
        );
        let record_ptr = u64::from(read_u32(memory, exception_info).unwrap_or(0));
        if record_ptr != 0 {
            let code = read_u32(memory, record_ptr).unwrap_or(0);
            let flags = read_u32(memory, record_ptr + 4).unwrap_or(0);
            let address = u64::from(read_u32(memory, record_ptr + 12).unwrap_or(0));
            let nparams = read_u32(memory, record_ptr + 16).unwrap_or(0).min(15);
            let mut params = Vec::new();
            for i in 0..nparams {
                params.push(format!(
                    "{:#x}",
                    read_u32(memory, record_ptr + 20 + u64::from(i) * 4).unwrap_or(0)
                ));
            }
            context.insert("code".to_string(), json!(format!("{code:#x}")));
            context.insert(
                "code_name".to_string(),
                json!(match code {
                    0xC000_0417 => "STATUS_INVALID_CRUNTIME_PARAMETER",
                    0xC000_0005 => "STATUS_ACCESS_VIOLATION",
                    0x8000_0003 => "STATUS_BREAKPOINT",
                    _ => "other",
                }),
            );
            context.insert("flags".to_string(), json!(format!("{flags:#x}")));
            context.insert("address".to_string(), json!(format!("{address:#x}")));
            context.insert(
                "address_rva".to_string(),
                json!(format!(
                    "{:#x}",
                    address.saturating_sub(self.mapped_image_base)
                )),
            );
            context.insert("parameters".to_string(), json!(params));
            let mut raw = Vec::new();
            for index in 0..16_u64 {
                raw.push(format!(
                    "{:#x}",
                    read_u32(memory, record_ptr + index * 4).unwrap_or(0)
                ));
            }
            context.insert("record_dwords".to_string(), json!(raw));
        }
        let ctx_ptr = u64::from(read_u32(memory, exception_info + 4).unwrap_or(0));
        let mut ebp_from_context = 0_u64;
        let mut esp_from_context = 0_u64;
        if ctx_ptr != 0 {
            let regs = [
                ("edi", 0x9C_u64),
                ("esi", 0xA0),
                ("ebx", 0xA4),
                ("edx", 0xA8),
                ("ecx", 0xAC),
                ("eax", 0xB0),
                ("ebp", 0xB4),
                ("eip", 0xB8),
                ("esp", 0xC4),
            ];
            let mut recorded = BTreeMap::new();
            for (name, offset) in regs {
                let value = u64::from(read_u32(memory, ctx_ptr + offset).unwrap_or(0));
                let rendered = if matches!(name, "ebp" | "eip" | "esp") {
                    format!(
                        "{value:#x} (rva {:#x})",
                        value.saturating_sub(self.mapped_image_base)
                    )
                } else {
                    format!("{value:#x}")
                };
                recorded.insert(name.to_string(), json!(rendered));
                if name == "ebp" {
                    ebp_from_context = value;
                }
                if name == "esp" {
                    esp_from_context = value;
                }
            }
            context.insert("context".to_string(), json!(recorded));
        }
        if esp_from_context != 0 {
            let mut stack = Vec::new();
            for index in 0..24_u64 {
                let Ok(raw) = read_u32(memory, esp_from_context + index * 4) else {
                    break;
                };
                let mut slot = BTreeMap::new();
                slot.insert("value".to_string(), json!(format!("{raw:#x}")));
                if let Some(text) = describe_guest_string(memory, u64::from(raw)) {
                    slot.insert("text".to_string(), json!(text));
                }
                stack.push(json!(slot));
            }
            context.insert("stack_esp".to_string(), json!(stack));
        }
        for (label, mut frame) in [
            ("context", ebp_from_context),
            ("live", state.get(Register::Rbp)),
        ] {
            if frame == 0 {
                continue;
            }
            let mut frames = Vec::new();
            for _ in 0..8 {
                if frame < 0x1_0000 {
                    break;
                }
                let ret = read_u32(memory, frame + 4).ok().map(u64::from);
                let mut args = Vec::new();
                let mut raws = Vec::new();
                for slot in 0..4_u64 {
                    let Ok(raw) = read_u32(memory, frame + 8 + slot * 4) else {
                        break;
                    };
                    raws.push(raw);
                    let mut arg = BTreeMap::new();
                    arg.insert("value".to_string(), json!(format!("{raw:#x}")));
                    if let Some(text) = describe_guest_string(memory, u64::from(raw)) {
                        arg.insert("text".to_string(), json!(text));
                    }
                    args.push(json!(arg));
                }
                let mut probe = BTreeMap::new();
                if raws.len() >= 3 && raws[1] != 0 && raws[1] < 0x1_0000 {
                    if let Ok(bytes) = memory.read_bytes(u64::from(raws[2]), 128) {
                        let first_nul = bytes.iter().position(|&byte| byte == 0);
                        probe.insert("src".to_string(), json!(format!("{:#x}", raws[2])));
                        probe.insert("declared_size".to_string(), json!(raws[1]));
                        probe.insert("first_nul".to_string(), json!(first_nul));
                        probe.insert(
                            "raw_hex".to_string(),
                            json!(
                                bytes
                                    .iter()
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect::<Vec<_>>()
                                    .join("")
                            ),
                        );
                    }
                }
                frames.push(json!({
                    "ebp": format!("{frame:#x}"),
                    "ret": ret.map(|value| format!("{value:#x}")),
                    "ret_rva": ret.map(|value| {
                        format!("{:#x}", value.saturating_sub(self.mapped_image_base))
                    }),
                    "args": args,
                    "copy_probe": probe,
                }));
                let next = u64::from(read_u32(memory, frame).unwrap_or(0));
                if next <= frame {
                    break;
                }
                frame = next;
            }
            context.insert(format!("frames_{label}"), json!(frames));
        }
        crate::runtime::emit_live_ui_debug(format!(
            "[crt] unhandled exception context: {}",
            serde_json::to_string(&context).unwrap_or_default()
        ));
        self.push_trace("process", "UnhandledExceptionContext", context, json!(null));
    }

    /// Convenience: raise the invalid-parameter handler and set errno; used by
    /// the `*_s` family when the caller MUST be aborted on return.
    pub(crate) fn crt_invalid_parameter(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        errno_value: i32,
    ) -> AppResult<Option<i32>> {
        // Steam run instrumentation (no behavior change): record the first
        // CRT invalid-parameter invocation for the run.
        crate::steam_milestones::record_first_failure(
            crate::steam_milestones::FailureCategory::Crt,
            state.rip as u32,
            self.win32.current_thread_id(),
            Some("_invalid_parameter_handler".to_string()),
            Some(errno_value.unsigned_abs()),
            "CRT invalid-parameter handler invoked".to_string(),
            None,
            None,
        );
        self.set_crt_errno(memory, errno_value);
        if self.raise_invalid_parameter(state, memory, 0, 0, 0)? {
            state.set(Register::Rax, errno_value as u64);
            return Ok(Some(134)); // abort()
        }
        Ok(None)
    }

    /// Patch 6c: raise the MSVC C++ exception (0xE06D7363) through the guest
    /// SEH chain — the `_CxxThrowException` shape the `_X*` / `std::_Throw_*`
    /// helpers use.  A handler claiming the exception resumes the caller with
    /// the code as the result; an unhandled throw terminates the process with
    /// the exception code (Windows semantics), recording the throw-info token
    /// for the report.
    pub(crate) fn crt_raise_cpp_exception(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        api_name: &str,
        throw_info: u64,
    ) -> AppResult<Option<i32>> {
        let code = 0xE06D_7363;
        let handled = if self.guest_arch == GuestArch::X86 {
            self.dispatch_x86_exception(state, memory, code, throw_info, api_name, &[])?
        } else if self.guest_arch == GuestArch::X64 {
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
            let stack_reader =
                |addr: u64, buf: &mut [u8]| -> bool { mem_ref.read_into(addr, buf).is_ok() };
            self.seh
                .dispatch(code, 0, &ctx, self.mapped_image_base, &stack_reader)
                .is_ok()
        } else {
            false
        };
        if handled {
            // A handler claimed the throw: the caller resumes with the code.
            state.set(Register::Rax, u64::from(code));
            self.last_error = 0;
            Ok(None)
        } else {
            // Unhandled C++ throw: terminate the process with the exception
            // code (the structured termination is GuestException).
            self.unhandled_guest_exception = Some(code);
            self.emit_event(crate::runtime_events::RuntimeEvent::GuestException {
                code,
                guest_pc: state.rip,
                thread_id: self.win32.current_thread_id(),
            });
            crate::steam_milestones::record_first_failure(
                crate::steam_milestones::FailureCategory::Crt,
                state.rip as u32,
                self.win32.current_thread_id(),
                Some(api_name.to_string()),
                Some(code),
                format!("unhandled C++ exception from {api_name}"),
                None,
                Some(format!("{{\"throw_info\":{throw_info:#x}}}")),
            );
            state.set(Register::Rax, u64::from(code));
            self.process_exit_requested = Some(code);
            Ok(Some(code as i32))
        }
    }

    // ── Patch 6b: CRT FILE* model ─────────────────────────────────────────────
    /// Allocate a guest FILE block (zeroed 0x80 bytes, mirroring the
    /// `__acrt_iob_func` blocks) and register host state for it.  The fd is
    /// written at offset 0x10 (the `_iobuf::_file` field offset on x86) so
    /// `_fileno` and guest code reading the struct directly agree.  The block
    /// is carved from the guest heap so `fclose` can free it (see
    /// `crt_close_stream`); repeated fopen/fclose cycles therefore do not
    /// leak guest memory.
    pub(crate) fn crt_alloc_file(
        &mut self,
        memory: &mut MemoryImage,
        state: &CrtFileState,
    ) -> AppResult<u64> {
        let file_ptr = self.alloc_heap(memory, 0x80, true)?;
        memory.map_bytes(file_ptr + 0x10, &state.handle.to_le_bytes());
        self.crt_files.insert(file_ptr, state.clone());
        Ok(file_ptr)
    }

    pub(crate) fn crt_stream_state(&self, stream: u64) -> Option<CrtFileState> {
        self.crt_files.get(&stream).cloned()
    }

    /// True when `stream` is one of the standard iob streams (stdin/stdout/
    /// stderr).  Returns the stream index (0/1/2) when it is.
    pub(crate) fn crt_iob_index(&self, stream: u64) -> Option<usize> {
        self.globals
            .iob_streams
            .iter()
            .position(|iob| *iob == stream)
    }

    /// The win32 handle for a stream, or None for the iob streams / unknown
    /// streams.
    pub(crate) fn crt_stream_handle(&self, stream: u64) -> Option<u32> {
        self.crt_stream_state(stream).map(|state| state.handle)
    }

    pub(crate) fn crt_close_stream(&mut self, stream: u64) -> AppResult<bool> {
        if let Some(state) = self.crt_files.remove(&stream) {
            let _ = self.win32.close_handle(state.handle);
            // Free the guest FILE block (0x80-byte heap allocation) so
            // repeated fopen/fclose cycles do not leak guest memory.
            self.heap_allocations.remove(&stream);
            return Ok(true);
        }
        Ok(false)
    }

    // ── Patch 6b: printf engine ───────────────────────────────────────────────
    /// Parse a UCRT `__stdio_common_*` format specification starting at the
    /// `%` in a wide format string and render one conversion.  `va` is the
    /// x86-cdecl vararg cursor; `out` receives the rendered bytes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn crt_render_conversion(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
        format: &[u16],
        index: &mut usize,
        va: &mut CrtVaReader,
        out: &mut Vec<u8>,
        guest_arch: GuestArch,
    ) -> AppResult<()> {
        let mut flags_minus = false;
        let mut flags_plus = false;
        let mut flags_zero = false;
        let mut flags_space = false;
        let mut flags_hash = false;
        *index += 1;
        while *index < format.len() {
            match format[*index] {
                0x2D => flags_minus = true,
                0x2B => flags_plus = true,
                0x30 => flags_zero = true,
                0x20 => flags_space = true,
                0x23 => flags_hash = true,
                _ => break,
            }
            *index += 1;
        }
        let mut width: i32 = -1;
        while *index < format.len() && (format[*index] as u8).is_ascii_digit() {
            width = width
                .max(0)
                .saturating_mul(10)
                .saturating_add(i32::from(format[*index] - b'0' as u16));
            *index += 1;
        }
        let mut precision: i32 = -1;
        if *index < format.len() && format[*index] == 0x2E {
            *index += 1;
            precision = 0;
            while *index < format.len() && (format[*index] as u8).is_ascii_digit() {
                precision = precision
                    .saturating_mul(10)
                    .saturating_add(i32::from(format[*index] - b'0' as u16));
                *index += 1;
            }
        }
        let mut length = CrtLengthModifier::None;
        if *index < format.len() {
            match format[*index] {
                0x68 => {
                    *index += 1;
                    if *index < format.len() && format[*index] == 0x68 {
                        length = CrtLengthModifier::Hh;
                        *index += 1;
                    } else {
                        length = CrtLengthModifier::H;
                    }
                }
                0x6C => {
                    *index += 1;
                    if *index < format.len() && format[*index] == 0x6C {
                        length = CrtLengthModifier::Ll;
                        *index += 1;
                    } else {
                        length = CrtLengthModifier::L;
                    }
                }
                0x49 => {
                    // I64
                    if *index + 2 < format.len()
                        && format[*index + 1] == 0x36
                        && format[*index + 2] == 0x34
                    {
                        length = CrtLengthModifier::Ll;
                        *index += 3;
                    } else {
                        *index += 1;
                    }
                }
                0x77 => {
                    length = CrtLengthModifier::L;
                    *index += 1;
                }
                _ => {}
            }
        }
        let conversion = *format.get(*index).unwrap_or(&0);
        *index += 1;

        let pad =
            |rendered: &mut Vec<u8>, width: i32, flags_minus: bool, flags_zero: bool| -> Vec<u8> {
                let width = width.max(rendered.len() as i32) as usize;
                if flags_minus {
                    let mut padded = rendered.clone();
                    padded.resize(width, b' ');
                    padded
                } else {
                    let mut padded = vec![b' '; width];
                    let start = width - rendered.len();
                    if flags_zero {
                        // Zero padding must only fill the DIGIT region: the sign
                        // ('-', '+', ' ') and hex prefix ("0x"/"0X") stay at the
                        // front, so "%05d" of -12 → "-0012" (not "-0-12") and
                        // "%#08x" of 0xCAFE → "0x00cafe" (not "00xcafe").
                        let mut head: Vec<u8> = Vec::new();
                        let mut digits = rendered.as_slice();
                        if let Some(&first) = rendered.first()
                            && matches!(first, b'-' | b'+' | b' ')
                        {
                            head.push(first);
                            digits = &rendered[1..];
                        }
                        if digits.starts_with(b"0x") || digits.starts_with(b"0X") {
                            head.extend_from_slice(&digits[..2]);
                            digits = &digits[2..];
                        }
                        let digit_start = start + head.len();
                        for slot in padded.iter_mut().take(digit_start).skip(head.len()) {
                            *slot = b'0';
                        }
                        padded[..head.len()].copy_from_slice(&head);
                        padded[digit_start..].copy_from_slice(digits);
                    } else {
                        padded[start..].copy_from_slice(rendered);
                    }
                    padded
                }
            };

        let sign_prefix =
            |rendered: &mut Vec<u8>, negative: bool, flags_plus: bool, flags_space: bool| {
                if negative {
                    rendered.insert(0, b'-');
                } else if flags_plus {
                    rendered.insert(0, b'+');
                } else if flags_space {
                    rendered.insert(0, b' ');
                }
            };

        let hex_digit = |digit: u8, upper: bool| -> u8 {
            if digit < 10 {
                b'0' + digit
            } else if upper {
                b'A' + digit - 10
            } else {
                b'a' + digit - 10
            }
        };

        match conversion {
            0x64 | 0x69 => {
                // %d %i — signed integer
                let (value, negative) = match length {
                    CrtLengthModifier::None | CrtLengthModifier::L => {
                        let raw = va.read_u32(memory)? as i32;
                        (raw.unsigned_abs() as u64, raw < 0)
                    }
                    CrtLengthModifier::H => {
                        let raw = (va.read_u32(memory)? as u16 as i16) as i32;
                        (raw.unsigned_abs() as u64, raw < 0)
                    }
                    CrtLengthModifier::Hh => {
                        let raw = (va.read_u32(memory)? as u8 as i8) as i32;
                        (raw.unsigned_abs() as u64, raw < 0)
                    }
                    CrtLengthModifier::Ll => {
                        let raw = va.read_u64(memory)? as i64;
                        (raw.unsigned_abs(), raw < 0)
                    }
                };
                let mut digits = Vec::new();
                let mut remaining = value;
                if remaining == 0 {
                    digits.push(b'0');
                }
                while remaining > 0 {
                    digits.push(b'0' + (remaining % 10) as u8);
                    remaining /= 10;
                }
                digits.reverse();
                if precision >= 0 {
                    while digits.len() < precision as usize {
                        digits.insert(0, b'0');
                    }
                    if precision == 0 && value == 0 {
                        digits.clear();
                    }
                }
                let mut rendered = digits;
                if !(rendered.is_empty() && precision == 0 && value == 0) {
                    sign_prefix(&mut rendered, negative, flags_plus, flags_space);
                }
                out.extend(pad(
                    &mut rendered,
                    width,
                    flags_minus,
                    precision < 0 && flags_zero,
                ));
            }
            0x75 => {
                let value = match length {
                    CrtLengthModifier::None | CrtLengthModifier::L => va.read_u32(memory)? as u64,
                    CrtLengthModifier::H => u64::from(va.read_u32(memory)? as u16),
                    CrtLengthModifier::Hh => u64::from(va.read_u32(memory)? as u8),
                    CrtLengthModifier::Ll => va.read_u64(memory)?,
                };
                let mut digits = Vec::new();
                let mut remaining = value;
                if remaining == 0 {
                    digits.push(b'0');
                }
                while remaining > 0 {
                    digits.push(b'0' + (remaining % 10) as u8);
                    remaining /= 10;
                }
                digits.reverse();
                if precision >= 0 {
                    while digits.len() < precision as usize {
                        digits.insert(0, b'0');
                    }
                    if precision == 0 && value == 0 {
                        digits.clear();
                    }
                }
                let mut rendered = digits;
                if flags_space && !flags_plus && !rendered.is_empty() {
                    rendered.insert(0, b' ');
                }
                out.extend(pad(
                    &mut rendered,
                    width,
                    flags_minus,
                    precision < 0 && flags_zero,
                ));
            }
            0x78 | 0x58 => {
                let value = match length {
                    CrtLengthModifier::None | CrtLengthModifier::L => va.read_u32(memory)? as u64,
                    CrtLengthModifier::H => u64::from(va.read_u32(memory)? as u16),
                    CrtLengthModifier::Hh => u64::from(va.read_u32(memory)? as u8),
                    CrtLengthModifier::Ll => va.read_u64(memory)?,
                };
                let upper = conversion == 0x58;
                let mut digits = Vec::new();
                let mut remaining = value;
                if remaining == 0 {
                    digits.push(b'0');
                }
                while remaining > 0 {
                    digits.push(hex_digit((remaining % 16) as u8, upper));
                    remaining /= 16;
                }
                digits.reverse();
                if precision >= 0 {
                    while digits.len() < precision as usize {
                        digits.insert(0, b'0');
                    }
                    if precision == 0 && value == 0 {
                        digits.clear();
                    }
                }
                let mut rendered = digits;
                if flags_hash && value != 0 {
                    rendered.insert(0, if upper { b'X' } else { b'x' });
                    rendered.insert(0, b'0');
                }
                out.extend(pad(
                    &mut rendered,
                    width,
                    flags_minus,
                    precision < 0 && flags_zero,
                ));
            }
            0x6F => {
                let value = match length {
                    CrtLengthModifier::None | CrtLengthModifier::L => va.read_u32(memory)? as u64,
                    CrtLengthModifier::H => u64::from(va.read_u32(memory)? as u16),
                    CrtLengthModifier::Hh => u64::from(va.read_u32(memory)? as u8),
                    CrtLengthModifier::Ll => va.read_u64(memory)?,
                };
                let mut digits = Vec::new();
                let mut remaining = value;
                if remaining == 0 {
                    digits.push(b'0');
                }
                while remaining > 0 {
                    digits.push(b'0' + (remaining % 8) as u8);
                    remaining /= 8;
                }
                digits.reverse();
                if precision >= 0 {
                    while digits.len() < precision as usize {
                        digits.insert(0, b'0');
                    }
                    if precision == 0 && value == 0 {
                        digits.clear();
                    }
                }
                let mut rendered = digits;
                if flags_hash && value != 0 && !rendered.starts_with(b"0") {
                    rendered.insert(0, b'0');
                }
                out.extend(pad(
                    &mut rendered,
                    width,
                    flags_minus,
                    precision < 0 && flags_zero,
                ));
            }
            0x63 => {
                let raw = va.read_u32(memory)?;
                if length == CrtLengthModifier::L {
                    // %lc — wide char (2-byte unit), converted to UTF-8.
                    let ch = char::from_u32(u32::from(raw as u16)).unwrap_or('\u{FFFD}');
                    let mut encoded = [0_u8; 4];
                    let mut bytes = ch.encode_utf8(&mut encoded).as_bytes().to_vec();
                    out.extend(pad(&mut bytes, width, flags_minus, false));
                } else {
                    // %c / %hc — narrow char.
                    out.extend(pad(&mut [raw as u8].to_vec(), width, flags_minus, false));
                }
            }
            0x73 => {
                // %s / %hs — narrow (ANSI) guest string; %ls — wide string
                // (2-byte units).  NULL prints "(null)" per UCRT.
                let ptr = va.read_pointer(memory)?;
                let max = if precision >= 0 {
                    precision as usize
                } else {
                    usize::MAX
                };
                if length == CrtLengthModifier::L {
                    if ptr == 0 {
                        out.extend(pad(&mut b"(null)".to_vec(), width, flags_minus, false));
                    } else {
                        let wide = read_utf16_string(memory, ptr)?;
                        let wide_units = wide.encode_utf16().collect::<Vec<_>>();
                        let mut bytes = self
                            .win32
                            .wide_char_to_multi_byte(DEFAULT_ANSI_CODE_PAGE, &wide_units)
                            .unwrap_or_else(|_| wide.as_bytes().to_vec());
                        if precision >= 0 {
                            bytes.truncate(precision as usize);
                        }
                        out.extend(pad(&mut bytes, width, flags_minus, false));
                    }
                } else {
                    let mut rendered = if ptr == 0 {
                        b"(null)".to_vec()
                    } else {
                        read_c_string_limit(memory, ptr, max)?
                    };
                    if precision >= 0 {
                        rendered.truncate(precision as usize);
                    }
                    out.extend(pad(&mut rendered, width, flags_minus, false));
                }
            }
            0x53 => {
                // %S — wide guest string, narrowed to the ANSI page.  NULL
                // prints "(null)" per UCRT.
                let ptr = va.read_pointer(memory)?;
                if ptr == 0 {
                    out.extend(pad(&mut b"(null)".to_vec(), width, flags_minus, false));
                } else {
                    let wide = read_utf16_string(memory, ptr)?;
                    let wide_units = wide.encode_utf16().collect::<Vec<_>>();
                    let mut bytes = self
                        .win32
                        .wide_char_to_multi_byte(DEFAULT_ANSI_CODE_PAGE, &wide_units)
                        .unwrap_or_else(|_| wide.as_bytes().to_vec());
                    if precision >= 0 {
                        bytes.truncate(precision as usize);
                    }
                    out.extend(pad(&mut bytes, width, flags_minus, false));
                }
            }
            0x6E => {
                // %n — writes the count of chars emitted so far into the
                // int* argument (%hn → short, %hhn → char).  A NULL target is
                // EINVAL + invalid-parameter handler per UCRT.
                let target = va.read_pointer(memory)?;
                if target == 0 {
                    self.set_crt_errno(memory, EINVAL);
                    let _ = self.raise_invalid_parameter(state, memory, 0, 0, 0);
                    return Ok(());
                }
                let count = out.len() as u64;
                match length {
                    CrtLengthModifier::Hh => memory.write_u8(target, count as u8),
                    CrtLengthModifier::H => memory.write_u16(target, count as u16),
                    _ => write_u32(memory, target, count as u32),
                }
            }
            0x70 => {
                let ptr = va.read_pointer(memory)?;
                let digits = if guest_arch == GuestArch::X64 { 16 } else { 8 };
                let mut rendered = format!("{:0width$X}", ptr, width = digits).into_bytes();
                out.extend(pad(&mut rendered, width, flags_minus, true));
            }
            0x25 => {
                out.push(b'%');
            }
            0x66 | 0x65 | 0x67 | 0x46 | 0x45 | 0x47 => {
                let value = va.read_f64(memory)?;
                let precision_explicit = precision >= 0;
                let precision = if precision < 0 { 6 } else { precision };
                let uppercase = conversion == 0x46 || conversion == 0x45 || conversion == 0x47;
                let negative = value.is_sign_negative() && value != 0.0;
                let magnitude = value.abs();
                let conversion_lower = char::from_u32(u32::from(conversion))
                    .map(|ch| ch.to_ascii_lowercase() as u32)
                    .unwrap_or(u32::from(conversion));
                let mut rendered = match conversion_lower {
                    0x66 => crt_format_fixed(magnitude, precision),
                    0x65 => crt_format_exponential(magnitude, precision, uppercase),
                    _ => crt_format_general(magnitude, precision, uppercase, flags_hash),
                };
                if flags_hash && !rendered.contains(&b'.') {
                    rendered.push(b'.');
                }
                if negative {
                    rendered.insert(0, b'-');
                } else if flags_plus {
                    rendered.insert(0, b'+');
                } else if flags_space {
                    rendered.insert(0, b' ');
                }
                out.extend(pad(
                    &mut rendered,
                    width,
                    flags_minus,
                    !precision_explicit && flags_zero,
                ));
            }
            _ => {
                // Unknown conversion: UCRT renders the '%' and the offending
                // character literally.  This deliberately covers %a (hex
                // float) and the %z/%t length prefixes, which are
                // DOCUMENTED-UNSUPPORTED in this engine: they are left
                // literal rather than silently mis-rendered.
                out.push(b'%');
                if conversion != 0 {
                    let mut bytes = [0_u8; 2];
                    let mut encoded = [0_u8; 4];
                    let s = char::from_u32(u32::from(conversion)).unwrap_or('\u{FFFD}');
                    let n = s.encode_utf8(&mut encoded).len();
                    bytes[..n].copy_from_slice(&encoded[..n]);
                    out.extend_from_slice(&bytes[..n]);
                }
            }
        }
        Ok(())
    }

    /// Shared printf engine: renders the wide format with the x86-cdecl
    /// vararg list at `argptr` and returns the produced narrow bytes.
    pub(crate) fn crt_vfprintf_render(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        format_ptr: u64,
        argptr: u64,
    ) -> AppResult<Vec<u8>> {
        if format_ptr == 0 {
            self.set_crt_errno(memory, EINVAL);
            return Ok(Vec::new());
        }
        let wide = read_utf16_string(memory, format_ptr)?;
        let format_units = wide.encode_utf16().collect::<Vec<_>>();
        let mut va = CrtVaReader::new(argptr, self.guest_arch);
        let mut out = Vec::new();
        let mut index = 0_usize;
        while index < format_units.len() {
            if format_units[index] == 0x25 {
                self.crt_render_conversion(
                    &mut *memory,
                    state,
                    &format_units,
                    &mut index,
                    &mut va,
                    &mut out,
                    self.guest_arch,
                )?;
            } else {
                let mut encoded = [0_u8; 4];
                if let Some(ch) = char::from_u32(u32::from(format_units[index])) {
                    out.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
                }
                index += 1;
            }
        }
        Ok(out)
    }

    /// Deliver rendered printf output to a stream: iob streams go to the
    /// runtime stdout/stderr buffers; CRT-opened FILE* streams go through the
    /// win32 handle; a NULL stream is treated as stdout (best-effort).
    pub(crate) fn crt_vfprintf_deliver(
        &mut self,
        memory: &mut MemoryImage,
        stream: u64,
        bytes: &[u8],
    ) -> AppResult<u64> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if stream == 0 || self.crt_iob_index(stream).is_some() {
            let text = String::from_utf8_lossy(bytes);
            if self.crt_iob_index(stream) == Some(2) {
                crate::runtime::trace_guest_stderr(&text);
                self.stderr.push_str(&text);
            } else {
                self.stdout.push_str(&text);
            }
            return Ok(bytes.len() as u64);
        }
        if let Some(state) = self.crt_stream_state(stream) {
            if !state.writable {
                self.set_crt_errno(memory, EBADF);
                return Ok((EOF as i64) as u64);
            }
            if state.append {
                let _ =
                    self.win32
                        .set_file_pointer_ex(state.handle, 0, crate::win32::SeekOrigin::End);
            }
            match self.win32.write_file(state.handle, bytes) {
                Ok(_) => Ok(bytes.len() as u64),
                Err(_) => {
                    self.set_crt_errno(memory, EIO);
                    Ok((EOF as i64) as u64)
                }
            }
        } else {
            self.set_crt_errno(memory, EBADF);
            Ok((EOF as i64) as u64)
        }
    }

    // ── Patch 6c: msvcrt narrow printf / sprintf / sscanf ───────────────────
    /// Render a NARROW (ANSI) printf format through the shared UCRT format
    /// engine: the narrow format is widened to UTF-16 units and rendered with
    /// the exact same conversion machinery as `crt_vfprintf_render` (the C
    /// locale is ASCII-compatible, so byte-widening is faithful).
    pub(crate) fn crt_vfprintf_render_narrow(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        format_ptr: u64,
        argptr: u64,
    ) -> AppResult<Vec<u8>> {
        if format_ptr == 0 {
            self.set_crt_errno(memory, EINVAL);
            return Ok(Vec::new());
        }
        let bytes = read_c_string_limit(memory, format_ptr, usize::MAX)?;
        let format_units = bytes
            .iter()
            .map(|byte| u16::from(*byte))
            .collect::<Vec<_>>();
        let mut va = CrtVaReader::new(argptr, self.guest_arch);
        let mut out = Vec::new();
        let mut index = 0_usize;
        while index < format_units.len() {
            if format_units[index] == 0x25 {
                self.crt_render_conversion(
                    &mut *memory,
                    state,
                    &format_units,
                    &mut index,
                    &mut va,
                    &mut out,
                    self.guest_arch,
                )?;
            } else {
                let mut encoded = [0_u8; 4];
                if let Some(ch) = char::from_u32(u32::from(format_units[index])) {
                    out.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
                }
                index += 1;
            }
        }
        Ok(out)
    }

    /// `sscanf` core: scan the NARROW input per the NARROW format, assigning
    /// through the vararg out-params (the shared `CrtVaReader`).  Returns the
    /// number of assigned items, or -1 (EOF) when an input failure occurs
    /// before the first assignment.  Integer conversions reuse
    /// `crt_parse_strtol_full`; float conversions reuse `crt_parse_strtod`.
    pub(crate) fn crt_sscanf_impl(
        &mut self,
        memory: &mut MemoryImage,
        input_ptr: u64,
        format_ptr: u64,
        argptr: u64,
    ) -> AppResult<i32> {
        if input_ptr == 0 || format_ptr == 0 {
            self.set_crt_errno(memory, EINVAL);
            return Ok(-1);
        }
        let input = read_c_string_limit(memory, input_ptr, usize::MAX)?;
        let format = read_c_string_limit(memory, format_ptr, usize::MAX)?;
        let mut va = CrtVaReader::new(argptr, self.guest_arch);
        let mut pos = 0_usize;
        let mut f = 0_usize;
        let mut assigned = 0_i32;
        let mut input_failure = false;
        let skip_ws = |input: &[u8], pos: usize| -> usize {
            let mut pos = pos;
            while pos < input.len() && input[pos].is_ascii_whitespace() {
                pos += 1;
            }
            pos
        };
        while f < format.len() {
            let directive = format[f];
            match directive {
                b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C => {
                    pos = skip_ws(&input, pos);
                    f += 1;
                }
                b'%' => {
                    let mut f2 = f + 1;
                    let suppress = f2 < format.len() && format[f2] == b'*';
                    if suppress {
                        f2 += 1;
                    }
                    let mut width: Option<usize> = None;
                    while f2 < format.len() && format[f2].is_ascii_digit() {
                        width = Some(
                            width
                                .unwrap_or(0)
                                .saturating_mul(10)
                                .saturating_add(usize::from(format[f2] - b'0')),
                        );
                        f2 += 1;
                    }
                    let mut length = CrtLengthModifier::None;
                    if f2 < format.len() {
                        match format[f2] {
                            b'h' => {
                                f2 += 1;
                                if f2 < format.len() && format[f2] == b'h' {
                                    length = CrtLengthModifier::Hh;
                                    f2 += 1;
                                } else {
                                    length = CrtLengthModifier::H;
                                }
                            }
                            b'l' => {
                                f2 += 1;
                                if f2 < format.len() && format[f2] == b'l' {
                                    length = CrtLengthModifier::Ll;
                                    f2 += 1;
                                } else {
                                    length = CrtLengthModifier::L;
                                }
                            }
                            b'L' => {
                                // long double: scanned as double (the runtime
                                // has no extended-precision model).
                                length = CrtLengthModifier::L;
                                f2 += 1;
                            }
                            _ => {}
                        }
                    }
                    let Some(&conv) = format.get(f2) else {
                        break;
                    };
                    f2 += 1;
                    let max = width.unwrap_or(usize::MAX);
                    match conv {
                        b'%' => {
                            if pos < input.len() && input[pos] == b'%' {
                                pos += 1;
                            } else {
                                input_failure = true;
                                break;
                            }
                        }
                        b'n' => {
                            // %n stores the count of characters consumed so
                            // far; it never counts as an assignment.
                            if !suppress {
                                let target = va.read_pointer(memory)?;
                                if target != 0 {
                                    match length {
                                        CrtLengthModifier::Hh => memory.write_u8(target, pos as u8),
                                        CrtLengthModifier::H => {
                                            memory.write_u16(target, pos as u16)
                                        }
                                        CrtLengthModifier::L | CrtLengthModifier::Ll => {
                                            memory.write_u64(target, pos as u64)
                                        }
                                        CrtLengthModifier::None => {
                                            write_u32(memory, target, pos as u32)
                                        }
                                    }
                                }
                            }
                        }
                        b'c' => {
                            // %c matches exactly `width` (default 1) chars
                            // INCLUDING whitespace; no NUL is appended.
                            let take = max.min(input.len().saturating_sub(pos));
                            if take == 0 {
                                input_failure = true;
                                break;
                            }
                            let start = pos;
                            pos += take;
                            if !suppress {
                                let target = va.read_pointer(memory)?;
                                if target != 0 {
                                    memory.map_bytes(target, &input[start..pos]);
                                }
                                assigned += 1;
                            }
                        }
                        b's' => {
                            // %s skips whitespace, matches non-whitespace up
                            // to `width`, and appends a NUL.
                            pos = skip_ws(&input, pos);
                            if pos >= input.len() {
                                input_failure = true;
                                break;
                            }
                            let start = pos;
                            let mut end = pos;
                            while end < input.len()
                                && end - start < max
                                && !input[end].is_ascii_whitespace()
                            {
                                end += 1;
                            }
                            if end == start {
                                input_failure = true;
                                break;
                            }
                            pos = end;
                            if !suppress {
                                let target = va.read_pointer(memory)?;
                                if target != 0 {
                                    memory.map_bytes(target, &input[start..end]);
                                    memory.write_u8(target + (end - start) as u64, 0);
                                }
                                assigned += 1;
                            }
                        }
                        b'[' => {
                            // Scanset: %[...] (or %[^...]).  A leading ']' is
                            // part of the set; '-' between two chars is a
                            // range ("a-z"); a leading or trailing '-' is
                            // literal; unterminated sets stop the scan.
                            let negated = f2 < format.len() && format[f2] == b'^';
                            if negated {
                                f2 += 1;
                            }
                            let set_start = f2;
                            let mut set_end = f2;
                            if set_end < format.len() && format[set_end] == b']' {
                                set_end += 1;
                            }
                            while set_end < format.len() && format[set_end] != b']' {
                                set_end += 1;
                            }
                            if set_end >= format.len() {
                                break;
                            }
                            let set = &format[set_start..set_end];
                            let mut member = [false; 256];
                            let mut set_i = 0_usize;
                            while set_i < set.len() {
                                if set[set_i] == b'-' && set_i > 0 && set_i + 1 < set.len() {
                                    let lo = set[set_i - 1];
                                    let hi = set[set_i + 1];
                                    for byte in lo..=hi {
                                        member[byte as usize] = true;
                                    }
                                    set_i += 2;
                                } else {
                                    member[set[set_i] as usize] = true;
                                    set_i += 1;
                                }
                            }
                            pos = skip_ws(&input, pos);
                            if pos >= input.len() {
                                input_failure = true;
                                break;
                            }
                            let start = pos;
                            let mut end = pos;
                            while end < input.len()
                                && end - start < max
                                && member[input[end] as usize] != negated
                            {
                                end += 1;
                            }
                            if end == start {
                                input_failure = true;
                                break;
                            }
                            pos = end;
                            if !suppress {
                                let target = va.read_pointer(memory)?;
                                if target != 0 {
                                    memory.map_bytes(target, &input[start..end]);
                                    memory.write_u8(target + (end - start) as u64, 0);
                                }
                                assigned += 1;
                            }
                            f2 = set_end + 1;
                        }
                        b'd' | b'i' | b'u' | b'x' | b'X' | b'o' => {
                            pos = skip_ws(&input, pos);
                            if pos >= input.len() {
                                input_failure = true;
                                break;
                            }
                            let end = pos.saturating_add(max).min(input.len());
                            let base = match conv {
                                b'x' | b'X' => 16,
                                b'o' => 8,
                                b'i' => 0,
                                _ => 10,
                            };
                            let text = String::from_utf8_lossy(&input[pos..end]);
                            let (value, consumed, _overflow) = crt_parse_strtol_full(&text, base);
                            if consumed == 0 {
                                // Matching failure (chars remain but none
                                // convert) vs input failure (input ended).
                                if pos >= input.len() {
                                    input_failure = true;
                                }
                                break;
                            }
                            pos += consumed;
                            if !suppress {
                                let target = va.read_pointer(memory)?;
                                if target != 0 {
                                    match conv {
                                        b'u' | b'x' | b'X' | b'o' => {
                                            let bits = value as u32;
                                            match length {
                                                CrtLengthModifier::Hh => {
                                                    memory.write_u8(target, bits as u8)
                                                }
                                                CrtLengthModifier::H => {
                                                    memory.write_u16(target, bits as u16)
                                                }
                                                CrtLengthModifier::L | CrtLengthModifier::Ll => {
                                                    memory.write_u64(target, value as u64)
                                                }
                                                CrtLengthModifier::None => {
                                                    write_u32(memory, target, bits)
                                                }
                                            }
                                        }
                                        _ => match length {
                                            CrtLengthModifier::Hh => {
                                                memory.write_u8(target, value as u8)
                                            }
                                            CrtLengthModifier::H => {
                                                memory.write_u16(target, value as u16)
                                            }
                                            CrtLengthModifier::L | CrtLengthModifier::Ll => {
                                                memory.write_u64(target, value as u64)
                                            }
                                            CrtLengthModifier::None => {
                                                write_u32(memory, target, value as u32)
                                            }
                                        },
                                    }
                                }
                                assigned += 1;
                            }
                        }
                        b'f' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                            pos = skip_ws(&input, pos);
                            if pos >= input.len() {
                                input_failure = true;
                                break;
                            }
                            let end = pos.saturating_add(max).min(input.len());
                            let consumed = crt_scan_float_consumed(&input[pos..end]);
                            if consumed == 0 {
                                if pos >= input.len() {
                                    input_failure = true;
                                }
                                break;
                            }
                            let text = String::from_utf8_lossy(&input[pos..pos + consumed]);
                            let value = crt_parse_strtod(&text);
                            pos += consumed;
                            if !suppress {
                                let target = va.read_pointer(memory)?;
                                if target != 0 {
                                    match length {
                                        // %lf / %Lf write a double (8 bytes).
                                        CrtLengthModifier::L => {
                                            memory.write_u64(target, value.to_bits())
                                        }
                                        // %f / %e / %g write a float (4 bytes).
                                        _ => write_u32(memory, target, (value as f32).to_bits()),
                                    }
                                }
                                assigned += 1;
                            }
                        }
                        _ => break,
                    }
                    f = f2;
                }
                _ => {
                    // Literal directive: must match exactly one input char.
                    if pos < input.len() && input[pos] == directive {
                        pos += 1;
                    } else {
                        input_failure = true;
                        break;
                    }
                    f += 1;
                }
            }
        }
        if input_failure && assigned == 0 {
            Ok(-1)
        } else {
            Ok(assigned)
        }
    }

    // ── Patch 6b: fopen-family implementation ─────────────────────────────────
    /// Parse a CRT fopen mode string: base r/w/a, optional '+', optional
    /// b/t (ignored), and the S/D/N/c flags (ignored).  Returns
    /// (readable, writable, append, update, base) where `base` is the mode
    /// character that drives the creation disposition.
    pub(crate) fn crt_parse_fopen_mode(mode: &str) -> Option<(bool, bool, bool, bool, char)> {
        let mode = mode.trim();
        let mut chars = mode.chars();
        let base = chars.next()?;
        let (readable, writable) = match base {
            'r' => (true, false),
            'w' => (false, true),
            'a' => (false, true),
            _ => return None,
        };
        let append = base == 'a';
        let mut update = false;
        for ch in chars {
            match ch {
                '+' => update = true,
                'b' | 't' | 'S' | 'D' | 'N' | 'c' | 'R' | 'T' => {}
                _ => return None,
            }
        }
        let (readable, writable) = if update {
            (true, true)
        } else {
            (readable, writable)
        };
        Some((readable, writable, append, update, base))
    }

    /// Open a CRT stream: parse the mode, open the file via the win32
    /// create-file path, allocate a guest FILE block, and register it.  On
    /// failure returns Ok(None) with errno set.
    pub(crate) fn crt_fopen_impl(
        &mut self,
        memory: &mut MemoryImage,
        path: &str,
        mode: &str,
    ) -> AppResult<Option<u64>> {
        self.crt_fopen_impl_at(memory, path, mode, None)
    }

    /// Like `crt_fopen_impl`, but when `existing_ptr` is Some the FILE block at
    /// that address is reused (freopen semantics: the same FILE* is returned).
    pub(crate) fn crt_fopen_impl_at(
        &mut self,
        memory: &mut MemoryImage,
        path: &str,
        mode: &str,
        existing_ptr: Option<u64>,
    ) -> AppResult<Option<u64>> {
        let resolved = resolve_guest_path(&self.current_directory, path);
        let Some((readable, writable, append, update, base)) = Self::crt_parse_fopen_mode(mode)
        else {
            self.set_crt_errno(memory, EINVAL);
            return Ok(None);
        };
        // Append streams additionally grant read access so the model's
        // seek-to-EOF (which needs FILE_READ_ATTRIBUTES for the size query)
        // works with write-only "a" modes.
        let access = crate::ge::FileAccess {
            read: readable || append,
            write: writable,
            delete: false,
        };
        let share = crate::ge::ShareMode {
            read: true,
            write: true,
            delete: false,
        };
        // The BASE mode character drives the disposition: r → open existing,
        // w → create always (truncate), a → open always (append).
        let creation = match base {
            'w' => crate::win32::CreationDisposition::CreateAlways,
            'a' => crate::win32::CreationDisposition::OpenAlways,
            _ => crate::win32::CreationDisposition::OpenExisting,
        };
        let handle = match self
            .win32
            .create_file_w(&resolved, access, share, creation, false, false, false)
        {
            Ok(handle) => handle,
            Err(error) => {
                self.set_crt_doserrno(memory, last_error_from_app_error(&error) as i32);
                self.set_crt_errno(
                    memory,
                    match error.code {
                        ReasonCode::RcFsNotFound => ENOENT,
                        ReasonCode::RcFsAlreadyExists => EEXIST,
                        ReasonCode::RcFsPathInvalid => ENOENT,
                        ReasonCode::RcIo => EACCES,
                        _ => EACCES,
                    },
                );
                return Ok(None);
            }
        };
        if append {
            let _ = self
                .win32
                .set_file_pointer_ex(handle, 0, crate::win32::SeekOrigin::End);
        }
        let file_state = CrtFileState {
            handle,
            path: resolved,
            readable,
            writable,
            append,
            update,
        };
        let file_ptr = match existing_ptr {
            Some(ptr) => {
                memory.map_bytes(ptr + 0x10, &handle.to_le_bytes());
                ptr
            }
            None => self.crt_alloc_file(memory, &file_state)?,
        };
        self.crt_files.insert(file_ptr, file_state);
        Ok(Some(file_ptr))
    }

    /// fread core: read up to `size*count` bytes at the stream position.
    /// Returns the number of complete items read.
    pub(crate) fn crt_fread_impl(
        &mut self,
        memory: &mut MemoryImage,
        buffer: u64,
        size: u64,
        count: u64,
        stream: u64,
    ) -> AppResult<u64> {
        let total = match size.checked_mul(count) {
            Some(total) if total <= 0x7FFF_FFFF => total as usize,
            _ => {
                self.set_crt_errno(memory, EINVAL);
                return Ok(0);
            }
        };
        if buffer == 0 || total == 0 {
            return Ok(0);
        }
        if let Some(index) = self.crt_iob_index(stream) {
            // stdin has no backing data in this model.
            let _ = index;
            return Ok(0);
        }
        let Some(state) = self.crt_stream_state(stream) else {
            self.set_crt_errno(memory, EBADF);
            return Ok(0);
        };
        if !state.readable {
            self.set_crt_errno(memory, EBADF);
            return Ok(0);
        }
        match self.win32.read_file(state.handle, total) {
            Ok(bytes) => {
                if !bytes.is_empty() {
                    memory.map_bytes(buffer, &bytes);
                }
                let items = (bytes.len() as u64).checked_div(size).unwrap_or(0);
                Ok(items)
            }
            Err(_) => {
                self.set_crt_errno(memory, EIO);
                Ok(0)
            }
        }
    }

    /// fwrite core: write `size*count` bytes at the stream position (append
    /// streams seek to EOF first).  Returns the number of complete items.
    pub(crate) fn crt_fwrite_impl(
        &mut self,
        memory: &mut MemoryImage,
        buffer: u64,
        size: u64,
        count: u64,
        stream: u64,
    ) -> AppResult<u64> {
        let total = match size.checked_mul(count) {
            Some(total) if total <= 0x7FFF_FFFF => total as usize,
            _ => {
                self.set_crt_errno(memory, EINVAL);
                return Ok(0);
            }
        };
        if buffer == 0 || total == 0 {
            return Ok(0);
        }
        let bytes = memory.read_bytes(buffer, total)?;
        if let Some(index) = self.crt_iob_index(stream) {
            let text = String::from_utf8_lossy(&bytes);
            if index == 2 {
                crate::runtime::trace_guest_stderr(&text);
                self.stderr.push_str(&text);
            } else {
                self.stdout.push_str(&text);
            }
            return Ok(count);
        }
        let Some(state) = self.crt_stream_state(stream) else {
            self.set_crt_errno(memory, EBADF);
            return Ok(0);
        };
        if !state.writable {
            self.set_crt_errno(memory, EBADF);
            return Ok(0);
        }
        if state.append {
            let _ = self
                .win32
                .set_file_pointer_ex(state.handle, 0, crate::win32::SeekOrigin::End);
        }
        match self.win32.write_file(state.handle, &bytes) {
            Ok(written) => {
                let items = u64::from(written).checked_div(size).unwrap_or(0);
                Ok(items)
            }
            Err(_) => {
                self.set_crt_errno(memory, EIO);
                Ok(0)
            }
        }
    }

    /// qsort core: heap sort of `num` elements of `size` bytes at `base`,
    /// comparing via the guest comparator (x86 cdecl, two pointer args).
    pub(crate) fn crt_qsort_impl(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        base: u64,
        num: usize,
        size: usize,
        compare: u64,
    ) -> AppResult<()> {
        if num < 2 || size == 0 {
            return Ok(());
        }
        let compare_at = |runtime: &mut Self,
                          memory: &mut MemoryImage,
                          state: &mut CpuState,
                          a: usize,
                          b: usize|
         -> AppResult<i32> {
            let pa = base.wrapping_add((a as u64).wrapping_mul(size as u64));
            let pb = base.wrapping_add((b as u64).wrapping_mul(size as u64));
            let result = runtime.execute_guest_callback(
                state,
                memory,
                compare,
                &[pa, pb],
                "qsort_compare",
            )?;
            Ok(result as i32)
        };
        let swap = |memory: &mut MemoryImage, a: usize, b: usize| -> AppResult<()> {
            let pa = base.wrapping_add((a as u64).wrapping_mul(size as u64));
            let pb = base.wrapping_add((b as u64).wrapping_mul(size as u64));
            let bytes_a = memory.read_bytes(pa, size)?;
            let bytes_b = memory.read_bytes(pb, size)?;
            memory.map_bytes(pa, &bytes_b);
            memory.map_bytes(pb, &bytes_a);
            Ok(())
        };
        // Heap sort (in-place, O(n log n) comparisons).
        let sift_down = |runtime: &mut Self,
                         memory: &mut MemoryImage,
                         state: &mut CpuState,
                         root: usize,
                         bottom: usize|
         -> AppResult<()> {
            let mut root = root;
            loop {
                let mut child = root * 2 + 1;
                if child >= bottom {
                    return Ok(());
                }
                if child + 1 < bottom && compare_at(runtime, memory, state, child, child + 1)? < 0 {
                    child += 1;
                }
                if compare_at(runtime, memory, state, root, child)? < 0 {
                    swap(memory, root, child)?;
                    root = child;
                } else {
                    return Ok(());
                }
            }
        };
        for start in (0..num / 2).rev() {
            sift_down(self, memory, state, start, num)?;
        }
        for end in (1..num).rev() {
            swap(memory, 0, end)?;
            sift_down(self, memory, state, 0, end)?;
        }
        Ok(())
    }

    pub(crate) fn lcmap_string(
        &mut self,
        memory: &mut MemoryImage,
        flags: u32,
        source_ptr: u64,
        source_len: i32,
        destination_ptr: u64,
        destination_len: i32,
    ) -> AppResult<u64> {
        if source_ptr == 0
            || source_len == 0
            || (flags & (LCMAP_LOWERCASE | LCMAP_UPPERCASE)) == (LCMAP_LOWERCASE | LCMAP_UPPERCASE)
        {
            self.last_error = ERROR_INVALID_PARAMETER;
            return Ok(0);
        }

        let source_units = if source_len < 0 {
            read_utf16_string(memory, source_ptr)?
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>()
        } else {
            (0..source_len as usize)
                .map(|index| read_guest_u16(memory, source_ptr + (index as u64 * 2)))
                .collect::<AppResult<Vec<_>>>()?
        };
        let mapped_units = if flags & (LCMAP_LOWERCASE | LCMAP_UPPERCASE) != 0 {
            source_units
                .iter()
                .copied()
                .map(|unit| {
                    let Some(original) = char::from_u32(unit as u32) else {
                        return unit;
                    };
                    let mapped = if flags & LCMAP_UPPERCASE != 0 {
                        original.to_uppercase().collect::<Vec<_>>()
                    } else {
                        original.to_lowercase().collect::<Vec<_>>()
                    };
                    let Some(&candidate) = mapped.first() else {
                        return unit;
                    };
                    if mapped.len() != 1 {
                        return unit;
                    }
                    let mut encoded = [0_u16; 2];
                    if candidate.encode_utf16(&mut encoded).len() != 1 {
                        return unit;
                    }
                    if self
                        .win32
                        .wide_char_to_multi_byte(DEFAULT_ANSI_CODE_PAGE, &encoded[..1])
                        .is_err()
                    {
                        return unit;
                    }
                    encoded[0]
                })
                .collect::<Vec<_>>()
        } else {
            source_units.clone()
        };
        let required = mapped_units.len() as u32;
        if destination_ptr == 0 || destination_len == 0 {
            self.last_error = 0;
            return Ok(required as u64);
        }
        if destination_len < required as i32 {
            self.last_error = ERROR_INSUFFICIENT_BUFFER;
            return Ok(0);
        }

        let encoded = mapped_units
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        if !encoded.is_empty() {
            memory.map_bytes(destination_ptr, &encoded);
        }
        self.last_error = 0;
        Ok(required as u64)
    }
}

/// Decode a guest pointer as a printable ASCII or UTF-16LE string, bounded to
/// 96 bytes so an arbitrary stack dword cannot turn diagnostics into an
/// unbounded read.  Used only for invalid-parameter/exception reporting.
fn describe_guest_string(memory: &MemoryImage, pointer: u64) -> Option<String> {
    if pointer < 0x1_0000 {
        return None;
    }
    let bytes = memory.read_bytes(pointer, 96).ok()?;
    if let Some(end) = bytes.iter().position(|&byte| byte == 0)
        && end >= 3
    {
        let text = String::from_utf8_lossy(&bytes[..end]).to_string();
        if text.is_ascii() && text.chars().all(|character| !character.is_control()) {
            return Some(format!("ascii:{text}"));
        }
    }
    let mut units = Vec::new();
    let mut index = 0;
    while index + 1 < bytes.len() {
        let unit = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        index += 2;
    }
    if units.len() >= 3 {
        let text = String::from_utf16_lossy(&units);
        if text.chars().all(|character| !character.is_control()) {
            return Some(format!("wide:{text}"));
        }
    }
    None
}
