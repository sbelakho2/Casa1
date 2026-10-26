use super::*;

/// A port-I/O bus servicing guest IN/OUT instructions.
///
/// # Unmapped-port behavior (the documented default)
/// When no bus is configured on the engine, an unmapped port read returns
/// 0xFF per byte (the classic ISA-bus float-high behavior of real PC
/// hardware, which Windows-compatible software expects), while a handful of
/// known system ports keep their defined values (0x80 POST, PIC 0x20/0xA0,
/// reset-control 0xCF9 → 0x00). Reads deliberately never return
/// 0xFFFFFFFF unconditionally for every port — real hardware does not, and
/// Windows does not. When a bus IS configured, it is consulted for every
/// port access (including the known ports above), so e.g. a test bus that
/// returns 0 for unmapped ports overrides the default.
pub trait IoPortBus {
    /// Read one byte from `port`.
    fn read_u8(&self, port: u16) -> u8;
    /// Read one 16-bit word from `port`.
    fn read_u16(&self, port: u16) -> u16;
    /// Read one 32-bit dword from `port`.
    fn read_u32(&self, port: u16) -> u32;
    /// Write one byte to `port`.
    fn write_u8(&mut self, port: u16, value: u8);
    /// Write one 16-bit word to `port`.
    fn write_u16(&mut self, port: u16, value: u16);
    /// Write one 32-bit dword to `port`.
    fn write_u32(&mut self, port: u16, value: u32);
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CpuExecutionEngine {
    pub config: CpuEngineConfig,
    pub cache: TranslationCache,
    pub dispatcher: ExceptionDispatcher,
    /// Optional guest port-I/O bus for IN/OUT. When `None`, the documented
    /// default unmapped-port behavior applies (see [`IoPortBus`]).
    #[serde(skip)]
    pub port_bus: Option<Arc<Mutex<dyn IoPortBus + Send + Sync>>>,
}

impl fmt::Debug for CpuExecutionEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpuExecutionEngine")
            .field("config", &self.config)
            .field("cache", &self.cache)
            .field("dispatcher", &self.dispatcher)
            .field(
                "port_bus",
                &self
                    .port_bus
                    .as_ref()
                    .map(|bus| format!("IoPortBus({bus:p})")),
            )
            .finish()
    }
}

impl PartialEq for CpuExecutionEngine {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
            && self.cache == other.cache
            && self.dispatcher == other.dispatcher
    }
}

impl CpuExecutionEngine {
    pub fn new(config: CpuEngineConfig) -> Self {
        Self {
            config,
            cache: TranslationCache::default(),
            dispatcher: ExceptionDispatcher::default(),
            port_bus: None,
        }
    }

    /// Attach a port-I/O bus that IN/OUT instructions consult for every
    /// port access.
    pub fn with_port_bus(mut self, port_bus: Arc<Mutex<dyn IoPortBus + Send + Sync>>) -> Self {
        self.port_bus = Some(port_bus);
        self
    }

    pub fn cpuid_leaf(&self, leaf: u32, subleaf: u32) -> CpuidLeaf {
        self.config.virtualization.leaf(leaf, subleaf)
    }

    pub fn decode_block(
        &self,
        bytes: &[u8],
        start_address: u64,
    ) -> AppResult<Vec<DecodedInstruction>> {
        decode_block(bytes, start_address, self.config.arch)
    }

    pub fn translate_block(
        &mut self,
        bytes: &[u8],
        start_address: u64,
    ) -> AppResult<TranslatedBlock> {
        self.cache.translate(bytes, start_address, &self.config)
    }

    pub fn promote_trace(&mut self, key: &BlockCacheKey) -> AppResult<()> {
        self.cache.promote(key)
    }

    pub fn invalidate_code_write(&mut self, address: u64, length: usize) -> Vec<BlockCacheKey> {
        self.cache.invalidate_code_write(address, length)
    }

    pub fn execute_ir(
        &self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        ir: &[IrInstruction],
    ) -> AppResult<ExecutionSummary> {
        execute_ir_with_hashing(
            state,
            memory,
            ir,
            Some(&self.config.virtualization),
            false,
            self.port_bus.as_deref(),
        )
    }

    pub fn execute_ir_without_memory_hash(
        &self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        ir: &[IrInstruction],
    ) -> AppResult<ExecutionSummary> {
        execute_ir_with_hashing(
            state,
            memory,
            ir,
            Some(&self.config.virtualization),
            false,
            self.port_bus.as_deref(),
        )
    }

    pub fn execute_ir_with_memory_hash(
        &self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        ir: &[IrInstruction],
    ) -> AppResult<ExecutionSummary> {
        execute_ir_with_hashing(
            state,
            memory,
            ir,
            Some(&self.config.virtualization),
            true,
            self.port_bus.as_deref(),
        )
    }

    /// Execute a block via JIT if available, falling back to IR interpretation.
    /// The JIT runtime is optional — if None is provided, this is equivalent to
    /// `execute_ir_without_memory_hash`.
    ///
    /// # Optimised memory model (v2)
    /// Instead of bulk-syncing ALL committed pages before/after every block
    /// (O(N) per block where N = total committed pages), this version uses:
    ///
    /// 1. **Incremental sync** — only new pages (not yet in `synced_pages`)
    ///    are copied from MemoryImage → flat memory before each block.
    /// 2. **Persistent SIGBUS handler** — installed once and kept active
    ///    across blocks, eliminating two `sigaction` syscalls per block.
    /// 3. **Batch SIGBUS handler** — syncs 16 neighbouring pages on each
    ///    SIGBUS, amortising the signal-delivery cost.
    /// 4. **Targeted write-back** — only pages in the `synced_pages` set
    ///    are written back from flat memory → MemoryImage after each block.
    ///
    /// Execute a block of IR instructions, preferring a JIT-compiled native
    /// block when the runtime has one for `state.rip`; otherwise this is the
    /// AOT-compiled execution engine (the match dispatch is native code
    /// compiled by rustc at build time, with no interpreter).
    ///
    /// The compiled block runs its straight-line prefix natively and exits
    /// with a control-flow code for its terminator (Jump / JumpIf / Call /
    /// Ret / safepoint).  This dispatcher applies the terminator semantics
    /// that the AOT path would have applied inside the IR:
    ///
    /// - `Normal` — straight-line block; the caller advances `rip` past the
    ///   block as usual.
    /// - `Safepoint` — the block's prologue polled the host safepoint flag
    ///   and returned WITHOUT running the body; the flag is cleared and the
    ///   whole block is executed through the AOT path (no instructions are
    ///   skipped).
    /// - `Jump` / `ConditionalBranch` — `rip` is set to the target (the
    ///   condition was already evaluated from the live flags).
    /// - `Return` / `ThunkDispatch` / `IndirectCall` — the terminator
    ///   instruction itself is executed through the AOT single-instruction
    ///   path (it reads the guest stack / pushes the return address), so
    ///   `rip` and the stack end up exactly as in AOT execution.
    ///
    /// Any error during native execution falls back to AOT for the whole
    /// block.  Only blocks admitted by the JIT-safe gate
    /// ([`crate::jit::JitCompiler::can_compile_block`]) are ever compiled,
    /// so mid-block exits (unimplemented/cpuid) cannot occur.
    pub fn execute_with_jit(
        &self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        ir: &[IrInstruction],
        jit_runtime: Option<&mut crate::jit::JitRuntime>,
    ) -> AppResult<ExecutionSummary> {
        if let Some(jit) = jit_runtime {
            let guest_address = state.rip;
            if jit.is_compiled(guest_address)
                && let Some(block) = jit.block_cache.get(&guest_address).cloned()
            {
                // The flat view aliases the image's canonical pages, so
                // attaching is an O(1) identity check — there is no mirror to
                // refresh from the interpreter.  The SIGBUS handler remains
                // installed only as a fallback for pages the guest has not
                // committed yet.
                jit.attach_guest_memory(memory);
                jit.ensure_sigbus_handler(memory);

                // SAFETY: block.entry() points into this runtime's MAP_JIT code
                // pages (finalized executable); state/memory are the live
                // guest objects for the duration of the call.
                let reason = unsafe { jit.execute_block(&block, state, memory) };

                // Fault channel: `jit_helper_load` / `jit_helper_store` cannot
                // propagate errors through the extern "C" ABI, so a guest
                // access violation sets `jit_pending_fault` and the compiled
                // block exits IMMEDIATELY via EXIT_GUEST_FAULT (the emitted
                // post-helper flag test aborts the block at the faulting
                // instruction — later instructions never run).  Convert the
                // pending fault into the exact error the interpreter raises
                // for the same access violation — the caller's
                // `annotate_guest_fault` wrapping then applies identically.
                match &reason {
                    crate::jit::JitExitReason::GuestFault => {
                        // Precise access violation: fault address + access
                        // type recorded by the helper, guest RIP is the block
                        // entry (`state.rip` — the compiled block never
                        // advances it; the faulting instruction's own
                        // address is the block start, the best available
                        // without per-instruction IR metadata).
                        let fault_address = state.jit_pending_fault.take().unwrap_or(state.rip);
                        // Access type (read/write) recorded for diagnostics /
                        // future precise exception parameters; the error
                        // message shape stays byte-identical to the
                        // interpreter's so SEH dispatch is indistinguishable.
                        state.jit_pending_fault_write = false;
                        return Err(MemoryImage::unmapped_memory_error(fault_address));
                    }
                    // Defensive: a pending fault must NEVER be observed as a
                    // successful block, whatever exit reason it took (e.g. a
                    // fault raised by the universal interpreter helper whose
                    // error could not be propagated).  The immediate exit
                    // makes this unreachable in practice.
                    _ if state.jit_pending_fault.is_some() => {
                        let fault_address = state.jit_pending_fault.take().unwrap();
                        state.jit_pending_fault_write = false;
                        return Err(MemoryImage::unmapped_memory_error(fault_address));
                    }
                    _ => {}
                }

                // Dispatcher: apply the terminator semantics the compiled
                // block deferred to the host.  The JIT-safe gate guarantees
                // only these exits; an unexpected one is a hard error (the
                // prefix already ran — silently re-running the block AOT
                // would double-execute guest side effects).
                match reason {
                    crate::jit::JitExitReason::Normal { .. } => {}
                    crate::jit::JitExitReason::Safepoint => {
                        // The block's prologue polled the host safepoint flag
                        // and returned WITHOUT running the body.  Clear the
                        // request and execute the whole block through the AOT
                        // path (the safepoint body runs between dispatches in
                        // the caller), so no guest instructions are skipped.
                        crate::jit::JIT_SAFEPOINT_REQUESTED
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        return execute_ir_with_hashing(
                            state,
                            memory,
                            ir,
                            Some(&self.config.virtualization),
                            false,
                            self.port_bus.as_deref(),
                        );
                    }
                    crate::jit::JitExitReason::Jump { target } => {
                        state.rip = target;
                    }
                    crate::jit::JitExitReason::ConditionalBranch { taken, .. } => match ir.last() {
                        Some(IrInstruction::JumpIf {
                            target,
                            fallthrough,
                            ..
                        }) => {
                            state.rip = if taken { *target } else { *fallthrough };
                        }
                        _ => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "JIT conditional exit without a JumpIf terminator",
                            ));
                        }
                    },
                    crate::jit::JitExitReason::ConditionalTaken { .. }
                    | crate::jit::JitExitReason::ConditionalNotTaken { .. } => {
                        let taken =
                            matches!(&reason, crate::jit::JitExitReason::ConditionalTaken { .. });
                        match ir.last() {
                            Some(IrInstruction::JumpIf {
                                target,
                                fallthrough,
                                ..
                            }) => {
                                state.rip = if taken { *target } else { *fallthrough };
                            }
                            _ => {
                                return Err(AppError::new(
                                    ReasonCode::RcUnimplInsn,
                                    "JIT conditional exit without a JumpIf terminator",
                                ));
                            }
                        }
                    }
                    // The prologue guard stopped before the body ran.  RIP was
                    // set to the guarded block; the outer dispatcher re-enters
                    // it after this call returns.  SMC invalidation already ran
                    // inside `execute_block`.
                    crate::jit::JitExitReason::LinkBudget { .. }
                    | crate::jit::JitExitReason::CodeEpoch { .. } => {}
                    crate::jit::JitExitReason::Return { .. }
                    | crate::jit::JitExitReason::ThunkDispatch { .. }
                    | crate::jit::JitExitReason::IndirectCall { .. } => match ir.last() {
                        Some(terminator) => {
                            execute_ir_with_hashing(
                                state,
                                memory,
                                std::slice::from_ref(terminator),
                                Some(&self.config.virtualization),
                                false,
                                self.port_bus.as_deref(),
                            )?;
                        }
                        None => {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                "JIT control-flow exit without a terminator instruction",
                            ));
                        }
                    },
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("JIT block exited with an unhandled reason: {other:?}"),
                        ));
                    }
                }
                return Ok(ExecutionSummary {
                    flags: state.flags,
                    memory_hash: String::new(),
                    ordering_log: Vec::new(),
                });
            }
        }
        // Direct AOT execution (no JIT path / block not compiled / fallback).
        execute_ir_with_hashing(
            state,
            memory,
            ir,
            Some(&self.config.virtualization),
            false,
            self.port_bus.as_deref(),
        )
    }

    pub fn register_veh(&mut self, handler: ExceptionHandler) {
        self.dispatcher.veh.push(handler);
    }

    pub fn register_seh(&mut self, handler: ExceptionHandler) {
        self.dispatcher.seh.push(handler);
    }

    pub fn dispatch_exception(&self, exception: &WindowsException) -> DispatchTrace {
        self.dispatcher.dispatch(exception)
    }
}

pub(crate) fn build_cache_key(
    _bytes: &[u8],
    start_address: u64,
    config: &CpuEngineConfig,
) -> BlockCacheKey {
    // Skip SHA256 hash — it's expensive (~5µs per call) and the basic_block_cache
    // already uses start_address as the key.  The hash is only needed for the
    // TranslationCache.blocks HashMap, which is redundant with basic_block_cache.
    BlockCacheKey {
        start_address,
        source_hash: String::new(),
        os_build: config.os_build.clone(),
        macwin_version: config.macwin_version.clone(),
        cpu_profile: config.virtualization.profile_fingerprint(),
        arch: config.arch,
    }
}

pub(crate) fn touched_pages(address: u64, length: usize) -> BTreeSet<u64> {
    let start = address & !0xfff;
    let end = (address + length.max(1) as u64 - 1) & !0xfff;
    let mut pages = BTreeSet::new();
    let mut current = start;
    while current <= end {
        pages.insert(current);
        current += 0x1000;
    }
    pages
}
