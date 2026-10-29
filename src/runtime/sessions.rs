//! Integration-test harness sessions driving the real dispatch path.

use super::*;

// ---------------------------------------------------------------------------
// Thunk-level Steam manifest gate (public test harness)
// ---------------------------------------------------------------------------

/// Outcome of driving the Steam manifest gate through the host-thunk
/// dispatch layer (used by the section-38 thunk-level manifest gate).
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct ThunkManifestGateResult {
    /// Bytes read back from the manifest via the `ReadFile` thunk.
    pub manifest_bytes: Vec<u8>,
    /// `CreateFileW` on the manifest returned a valid handle.
    pub manifest_open_ok: bool,
    /// `ReadFile` on the manifest handle reported success.
    pub manifest_read_ok: bool,
    /// The `C:\.crash` writability probe create succeeded.
    pub probe_create_ok: bool,
    /// The `C:\.crash` writability probe delete succeeded.
    pub probe_delete_ok: bool,
    /// Milestone evidence recorded by the instrumentation hooks during the
    /// cycle (manifest open/read, writability probe).
    pub milestones: crate::steam_milestones::SteamMilestones,
}

/// Drive the Steam manifest open/read/close cycle AND the `C:\.crash`
/// drive-root writability probe through the real host-thunk dispatch layer
/// (`alloc_host_thunk` + `dispatch_import` on an x86 guest state) rather
/// than calling `Win32Subsystem` methods directly.  The checked-in
/// `steam-live-run-x86` GE is expected.  The file layer emits generic
/// runtime events during the cycle; the Steam milestone observer (attached
/// here via the `steam_milestones` compatibility shim — this test harness
/// is part of the Steam workload, not of the generic runtime) infers the
/// milestone evidence, returned in `ThunkManifestGateResult::milestones`.
#[doc(hidden)]
pub fn thunk_drive_manifest_gate(ge: GameEnvironment) -> AppResult<ThunkManifestGateResult> {
    thunk_drive_manifest_gate_with_observers(
        ge,
        vec![Box::new(
            crate::steam_milestones::SteamMilestoneObserver::default(),
        )],
    )
}

/// `thunk_drive_manifest_gate` with caller-provided runtime-event observers
/// (test harness for the generic runtime-events layer).
#[doc(hidden)]
pub fn thunk_drive_manifest_gate_with_observers(
    ge: GameEnvironment,
    observers: Vec<Box<dyn crate::runtime_events::RuntimeObserver>>,
) -> AppResult<ThunkManifestGateResult> {
    let mut runtime = PeHostRuntime::new(ge, false, Vec::new(), None, None);
    for observer in observers {
        runtime.add_observer(observer);
    }
    runtime.guest_arch = GuestArch::X86;
    runtime.next_thunk_address = thunk_base_for_arch(GuestArch::X86);
    runtime.next_data_address = data_base_for_arch(GuestArch::X86);
    runtime.next_heap_address = heap_base_for_arch(GuestArch::X86);
    runtime
        .win32
        .reset_address_space(private_pages_base_for_arch(GuestArch::X86));
    runtime.x86_heap_region = 0;
    let mut memory = MemoryImage::default();

    fn call(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thunk: u64,
        args: &[u32],
    ) -> AppResult<u64> {
        let stack = 0x50_000;
        memory.map_bytes(stack, &[0_u8; 0x200]);
        write_u32(memory, stack, 0xDEAD_BEEF);
        for (index, arg) in args.iter().enumerate() {
            write_u32(memory, stack + 4 + (index as u64 * 4), *arg);
        }
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, stack);
        runtime.dispatch_import(thunk, &mut state, memory)?;
        Ok(state.get(Register::Rax))
    }

    let mut result = ThunkManifestGateResult::default();
    crate::steam_milestones::reset_milestones();

    // ── Manifest open/read/close via CreateFileW/ReadFile/CloseHandle ──
    let manifest_path = r"C:\package\steam_client_win32.installed";
    let path_ptr = runtime.alloc_utf16_string(&mut memory, manifest_path)?;
    let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
    let handle = call(
        &mut runtime,
        &mut memory,
        create_file,
        &[
            path_ptr as u32,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            0,
            OPEN_EXISTING,
            0,
            0,
        ],
    )?;
    result.manifest_open_ok = handle != 0 && handle != INVALID_HANDLE_VALUE;
    if result.manifest_open_ok {
        let buffer_ptr = 0x60_000_u64;
        // OUTSIDE the buffer region: the ReadFile thunk writes the transfer
        // count here and must not clobber manifest bytes in the buffer.
        let bytes_read_ptr = 0x61_000_u64;
        memory.map_bytes(buffer_ptr, &[0_u8; 0x200]);
        let read_file = runtime.alloc_host_thunk(HostThunk::ReadFile);
        let read_ok = call(
            &mut runtime,
            &mut memory,
            read_file,
            &[
                handle as u32,
                buffer_ptr as u32,
                4096,
                bytes_read_ptr as u32,
                0,
            ],
        )? == 1;
        result.manifest_read_ok = read_ok;
        let bytes_read = if read_ok {
            read_u32(&memory, bytes_read_ptr)? as usize
        } else {
            0
        };
        let mut bytes = Vec::with_capacity(bytes_read);
        for index in 0..bytes_read {
            bytes.push(memory.read_u8(buffer_ptr + index as u64)?);
        }
        result.manifest_bytes = bytes;
        let close_handle = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        let _ = call(&mut runtime, &mut memory, close_handle, &[handle as u32])?;
    }

    // ── Steam's drive-root writability probe: create/close/delete C:\.crash ──
    let probe_path = r"\\?\C:\.crash";
    let probe_ptr = runtime.alloc_utf16_string(&mut memory, probe_path)?;
    let probe_handle = call(
        &mut runtime,
        &mut memory,
        create_file,
        &[probe_ptr as u32, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0],
    )?;
    result.probe_create_ok = probe_handle != 0 && probe_handle != INVALID_HANDLE_VALUE;
    if result.probe_create_ok {
        let close_handle = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        let _ = call(
            &mut runtime,
            &mut memory,
            close_handle,
            &[probe_handle as u32],
        )?;
        let delete_file = runtime.alloc_host_thunk(HostThunk::DeleteFileW);
        result.probe_delete_ok =
            call(&mut runtime, &mut memory, delete_file, &[probe_ptr as u32])? == 1;
    }

    result.milestones = crate::steam_milestones::snapshot_milestones();
    Ok(result)
}

/// Drive `dispatch_import` with an UNREGISTERED thunk address — the
/// unsupported-call fallback path of the generic runtime-events layer (test
/// harness).  The dispatch fails with `RcUnimplInsn`; the `UnsupportedCall`
/// event must have been emitted to the attached observers.  Returns the
/// error message and the observer list so the caller can inspect what the
/// observers received.
#[doc(hidden)]
pub fn thunk_drive_unknown_thunk(
    ge: GameEnvironment,
    observers: Vec<Box<dyn crate::runtime_events::RuntimeObserver>>,
) -> (String, Vec<Box<dyn crate::runtime_events::RuntimeObserver>>) {
    let mut runtime = PeHostRuntime::new(ge, false, Vec::new(), None, None);
    for observer in observers {
        runtime.add_observer(observer);
    }
    let mut memory = MemoryImage::default();
    let mut state = CpuState::new(GuestArch::X86);
    let error = runtime
        .dispatch_import(0x0000_0000_DEAD_BEEF, &mut state, &mut memory)
        .expect_err("dispatch_import must fail for an unregistered thunk");
    let taken = std::mem::take(&mut runtime.observers);
    let observers = taken
        .lock()
        .map(|mut guard| guard.drain(..).collect())
        .unwrap_or_default();
    (error.message, observers)
}

// ---------------------------------------------------------------------------
// Oracle VM session — the `virtual_memory` differential runtime executor
// ---------------------------------------------------------------------------

/// A scratch private-memory VM session driving the REAL
/// VirtualAlloc/VirtualFree/VirtualProtect/VirtualQuery thunk arms (the
/// page-granular private-pages/private-reservations model) through the host
/// thunk dispatch layer (`alloc_host_thunk` + `dispatch_import`), exactly
/// like a guest program would.  Used by the `virtual_memory` differential
/// oracle's runtime executor so the comparison validates the runtime's own
/// VM semantics; the session persists across vectors just like the
/// reference process's address space persists across vectors.
#[doc(hidden)]
pub struct OracleVmSession {
    runtime: PeHostRuntime,
    memory: MemoryImage,
    pub(crate) thunk_virtual_alloc: u64,
    pub(crate) thunk_virtual_free: u64,
    pub(crate) thunk_virtual_protect: u64,
    pub(crate) thunk_virtual_query: u64,
    stack: u64,
    pub(crate) mbi_buffer: u64,
    pub(crate) old_protect_buffer: u64,
}

/// MEMORY_BASIC_INFORMATION fields read back from a VirtualQuery thunk call.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleVmQuery {
    pub base_address: u64,
    pub allocation_base: u64,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
}

impl OracleVmSession {
    /// Create a fresh session on a scratch X64 runtime.  The guest address
    /// space starts empty: the first reservation's base is the runtime's
    /// deterministic private-pages base.
    #[doc(hidden)]
    pub fn new(ge: GameEnvironment) -> Self {
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.set_guest_arch(GuestArch::X64);
        let mut memory = MemoryImage::default();
        let stack = 0x10_000;
        memory.map_bytes(stack, &[0_u8; 0x1000]);
        let mbi_buffer = 0x30_000;
        memory.map_bytes(mbi_buffer, &[0_u8; 0x100]);
        let old_protect_buffer = 0x31_000;
        memory.map_bytes(old_protect_buffer, &[0_u8; 0x10]);
        let thunk_virtual_alloc = runtime.alloc_host_thunk(HostThunk::VirtualAlloc);
        let thunk_virtual_free = runtime.alloc_host_thunk(HostThunk::VirtualFree);
        let thunk_virtual_protect = runtime.alloc_host_thunk(HostThunk::VirtualProtect);
        let thunk_virtual_query = runtime.alloc_host_thunk(HostThunk::VirtualQuery);
        OracleVmSession {
            runtime,
            memory,
            thunk_virtual_alloc,
            thunk_virtual_free,
            thunk_virtual_protect,
            thunk_virtual_query,
            stack,
            mbi_buffer,
            old_protect_buffer,
        }
    }

    /// Drive one host thunk with the x64 calling convention and return RAX.
    /// The runtime's `last_error` carries the GetLastError value.
    pub(crate) fn call(&mut self, thunk: u64, args: &[u64]) -> u64 {
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, self.stack);
        write_u64(&mut self.memory, self.stack, 0xDEAD_BEEF_DEAD_BEEF);
        for (index, arg) in args.iter().copied().enumerate() {
            match index {
                0 => state.set(Register::Rcx, arg),
                1 => state.set(Register::Rdx, arg),
                2 => state.set(Register::R8, arg),
                3 => state.set(Register::R9, arg),
                _ => {
                    write_u64(
                        &mut self.memory,
                        self.stack + 0x28 + ((index - 4) as u64 * 8),
                        arg,
                    );
                }
            }
        }
        let runtime = &mut self.runtime;
        let memory = &mut self.memory;
        let _ = runtime.dispatch_import(thunk, &mut state, memory);
        state.get(Register::Rax)
    }

    /// Real VirtualAlloc semantics; returns (returned base, last_error).
    #[doc(hidden)]
    pub fn virtual_alloc(
        &mut self,
        address: u64,
        size: u64,
        allocation_type: u32,
        protect: u32,
    ) -> (u64, u32) {
        let rax = self.call(
            self.thunk_virtual_alloc,
            &[
                address,
                size,
                u64::from(allocation_type),
                u64::from(protect),
            ],
        );
        (rax, self.runtime.last_error)
    }

    /// Real VirtualFree semantics; returns (success, last_error).
    #[doc(hidden)]
    pub fn virtual_free(&mut self, address: u64, size: u64, free_type: u32) -> (u64, u32) {
        let rax = self.call(
            self.thunk_virtual_free,
            &[address, size, u64::from(free_type)],
        );
        (rax, self.runtime.last_error)
    }

    /// Real VirtualProtect semantics; returns (success, last_error, old
    /// protection reported through the old-protect out parameter).
    #[doc(hidden)]
    pub fn virtual_protect(
        &mut self,
        address: u64,
        size: u64,
        new_protect: u32,
    ) -> (u64, u32, u32) {
        let rax = self.call(
            self.thunk_virtual_protect,
            &[
                address,
                size,
                u64::from(new_protect),
                self.old_protect_buffer,
            ],
        );
        let old = read_u32(&self.memory, self.old_protect_buffer).unwrap_or(0);
        (rax, self.runtime.last_error, old)
    }

    /// Real VirtualQuery semantics at `address`.
    #[doc(hidden)]
    pub fn virtual_query(&mut self, address: u64) -> OracleVmQuery {
        self.call(
            self.thunk_virtual_query,
            &[address, self.mbi_buffer, MEMORY_BASIC_INFORMATION64_SIZE],
        );
        OracleVmQuery {
            base_address: read_u64(&self.memory, self.mbi_buffer).unwrap_or(0),
            allocation_base: read_u64(&self.memory, self.mbi_buffer + 8).unwrap_or(0),
            region_size: read_u64(&self.memory, self.mbi_buffer + 24).unwrap_or(0),
            state: read_u32(&self.memory, self.mbi_buffer + 32).unwrap_or(0),
            protect: read_u32(&self.memory, self.mbi_buffer + 36).unwrap_or(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Stage-4 NTDLL test driver — dispatch-level access for integration tests
// ---------------------------------------------------------------------------

/// A scratch X64 runtime that integration tests drive through the REAL
/// `dispatch_import` path, with the canonical VM attached to the memory
/// image exactly like a live run.  The Nt*/Rtl* thunks allocate their thunk
/// addresses here (`alloc_thunk`) and are then invoked with the x64 calling
/// convention; the session exposes the runtime state the Stage-4 tests
/// assert against (the canonical VM, the live handle namespace, the guest
/// pid, the scheduler wait queue).
#[doc(hidden)]
pub struct NtThunkSession {
    pub(crate) runtime: PeHostRuntime,
    pub(crate) memory: MemoryImage,
    pub(crate) stack: u64,
}

impl NtThunkSession {
    /// Create a fresh session on a scratch X64 runtime with the canonical
    /// VM attached and a mapped test arena.
    #[doc(hidden)]
    pub fn new(ge: GameEnvironment) -> Self {
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.set_guest_arch(GuestArch::X64);
        let mut memory = MemoryImage::default();
        memory.set_vm(runtime.win32.address_space_mut());
        let stack = 0x10_000;
        memory.map_bytes(stack, &[0_u8; 0x1000]);
        // The scratch test arena (stack + guest buffers for in/out
        // parameters), registered in the canonical VM like a live loader
        // region so the checked accessors validate it.
        runtime.win32.address_space_mut().register(
            0x10_000,
            0x60_000,
            crate::vm::VmRegionKind::Private,
        );
        runtime.win32.address_space_mut().commit(
            0x10_000,
            0x60_000,
            crate::vm::VmProtection::READ_WRITE,
            false,
        );
        for (address, size) in [
            (0x10_000_u64, 0x1000_u64),
            (0x30_000, 0x1000),
            (0x40_000, 0x1000),
            (0x50_000, 0x1000),
        ] {
            memory.map_bytes(address, &vec![0_u8; size as usize]);
        }
        NtThunkSession {
            runtime,
            memory,
            stack,
        }
    }

    /// Allocate a host thunk for a dispatch variant and return its guest
    /// address.
    #[doc(hidden)]
    pub fn alloc_thunk(&mut self, thunk: HostThunk) -> u64 {
        self.runtime.alloc_host_thunk(thunk)
    }

    /// Drive one host thunk with the x64 calling convention and return RAX.
    #[doc(hidden)]
    pub fn call(&mut self, thunk: u64, args: &[u64]) -> u64 {
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, self.stack);
        write_u64(&mut self.memory, self.stack, 0xDEAD_BEEF_DEAD_BEEF);
        for (index, arg) in args.iter().copied().enumerate() {
            match index {
                0 => state.set(Register::Rcx, arg),
                1 => state.set(Register::Rdx, arg),
                2 => state.set(Register::R8, arg),
                3 => state.set(Register::R9, arg),
                _ => {
                    write_u64(
                        &mut self.memory,
                        self.stack + 0x28 + ((index - 4) as u64 * 8),
                        arg,
                    );
                }
            }
        }
        let runtime = &mut self.runtime;
        let memory = &mut self.memory;
        let _ = runtime.dispatch_import(thunk, &mut state, memory);
        state.get(Register::Rax)
    }

    /// The runtime's `last_error` (Win32-visible state; the Nt layer does
    /// not use it, but the session keeps it observable).
    #[doc(hidden)]
    pub fn last_error(&self) -> u32 {
        self.runtime.last_error
    }

    /// The GUEST process id of this session (never the host pid).
    #[doc(hidden)]
    pub fn guest_pid(&self) -> u32 {
        self.runtime.guest_pid
    }

    /// The canonical virtual-memory layer (the subsystem's address
    /// space — the one VirtualMemory interpreter/JIT/win32 share).
    #[doc(hidden)]
    pub fn vm(&self) -> &crate::vm::VirtualMemory {
        self.runtime.win32.address_space()
    }

    /// The live Win32 subsystem (the one handle namespace).
    #[doc(hidden)]
    pub fn win32(&self) -> &Win32Subsystem {
        &self.runtime.win32
    }

    /// The live Win32 subsystem, mutable.
    #[doc(hidden)]
    pub fn win32_mut(&mut self) -> &mut Win32Subsystem {
        &mut self.runtime.win32
    }

    /// The guest memory image (raw page map + canonical-VM validation).
    #[doc(hidden)]
    pub fn memory(&self) -> &MemoryImage {
        &self.memory
    }

    /// Map bytes into the guest arena.
    #[doc(hidden)]
    pub fn map_guest(&mut self, address: u64, bytes: &[u8]) {
        self.memory.map_bytes(address, bytes);
    }

    /// Read bytes from guest memory.
    #[doc(hidden)]
    pub fn read_guest(&self, address: u64, len: usize) -> Vec<u8> {
        self.memory.read_bytes(address, len).unwrap_or_default()
    }

    /// The number of threads parked in the scheduler wait queue.
    #[doc(hidden)]
    pub fn parked_waiter_count(&self) -> usize {
        self.runtime.pending_guest_threads.len()
    }

    /// The scheduler's suspend count for a pending guest thread handle
    /// (the record the pump gate reads).
    #[doc(hidden)]
    pub fn pending_thread_suspend_count(&self, thread_handle: u32) -> Option<u32> {
        self.runtime
            .pending_guest_threads
            .iter()
            .find(|thread| thread.handle == thread_handle)
            .map(|thread| thread.suspended)
    }

    /// Switch the guest architecture of this session.  Thread creation only
    /// queues scheduler records for x86 guests, so suspend/wait tests run
    /// with `GuestArch::X86`.  The arch switch rebuilds the canonical VM,
    /// so the scratch arena is re-registered and the image re-wired exactly
    /// as the constructor does.
    #[doc(hidden)]
    pub fn set_guest_arch(&mut self, guest_arch: GuestArch) {
        self.runtime.set_guest_arch(guest_arch);
        self.runtime.win32.address_space_mut().register(
            0x10_000,
            0x60_000,
            crate::vm::VmRegionKind::Private,
        );
        self.runtime.win32.address_space_mut().commit(
            0x10_000,
            0x60_000,
            crate::vm::VmProtection::READ_WRITE,
            false,
        );
        self.memory.set_vm(self.runtime.win32.address_space_mut());
    }

    /// Drive one host thunk with the x86 stack calling convention (return
    /// address at `[esp]`, args below it) and return EAX.
    #[doc(hidden)]
    pub fn call_x86(&mut self, thunk: u64, args: &[u32]) -> u32 {
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, self.stack);
        write_u32(&mut self.memory, self.stack, 0xDEAD_BEEF);
        for (index, arg) in args.iter().copied().enumerate() {
            write_u32(&mut self.memory, self.stack + 4 + (index as u64 * 4), arg);
        }
        let _ = self
            .runtime
            .dispatch_import(thunk, &mut state, &mut self.memory);
        state.get(Register::Rax) as u32
    }

    /// Run one scheduler pump cycle: runs a ready guest thread, or reports
    /// false when nothing was runnable (suspended / parked threads are not
    /// runnable).
    #[doc(hidden)]
    pub fn pump_pending_guest_thread(&mut self) -> bool {
        self.runtime
            .pump_pending_guest_thread(&mut self.memory)
            .map(|outcome| outcome.did_work)
            .unwrap_or(false)
    }

    /// The scheduler readiness probe for the parked waiter: true when the
    /// pump's readiness pass would resume it right now (the wait descriptor
    /// became satisfiable — an event was signaled, an APC arrived or the
    /// deadline expired).
    #[doc(hidden)]
    pub fn parked_waiter_satisfiable(&self) -> bool {
        self.runtime
            .pending_guest_threads
            .iter()
            .any(|thread| self.runtime.wait_satisfiable(thread))
    }

    /// Advance the guest clock by `milliseconds` (the same clock the
    /// scheduler deadlines read).
    #[doc(hidden)]
    pub fn advance_guest_clock(&mut self, milliseconds: u64) {
        self.runtime.win32.sleep(milliseconds);
    }

    /// The runtime's mapped-image base (0 in scratch sessions).
    #[doc(hidden)]
    pub fn mapped_image_base(&self) -> u64 {
        self.runtime.mapped_image_base
    }

    // ── Stage-4 Ldr loader-chain helpers (tests/section48_ldr.rs) ─────────

    /// Drain the pending DllMain/TLS-callback queue through the real
    /// `drain_pending_dll_main_calls` machinery (the same drain the main
    /// execution loop runs after a host thunk returns).  Returns the number
    /// of calls drained.
    #[doc(hidden)]
    pub fn drain_dll_main_calls(&mut self) -> usize {
        let mut state = CpuState::new(GuestArch::X64);
        // The callback ABI carves its frame below RSP (synthetic return
        // address + shadow space); park RSP near the TOP of the mapped
        // stack page so the frame stays inside it.
        state.set(Register::Rsp, self.stack + 0xFF0);
        let drained = self.runtime.pending_dll_main_calls.len();
        let runtime = &mut self.runtime;
        let memory = &mut self.memory;
        let _ = runtime.drain_pending_dll_main_calls(&mut state, memory);
        drained
    }

    /// The number of pending DllMain/TLS-callback calls queued by the
    /// loader (the FIFO order they will be drained in).
    #[doc(hidden)]
    pub fn pending_dll_main_calls_len(&self) -> usize {
        self.runtime.pending_dll_main_calls.len()
    }

    /// The pending DllMain queue snapshot: (image_base, entry_point_rva,
    /// reason) in drain order.
    #[doc(hidden)]
    pub fn pending_dll_main_calls(&self) -> Vec<(u64, u32, u32)> {
        self.runtime
            .pending_dll_main_calls
            .iter()
            .copied()
            .collect()
    }

    /// Register + commit a guest range in the canonical VM (so guest code
    /// placed there — TLS callbacks, DllMain stubs — can execute).
    #[doc(hidden)]
    pub fn vm_register_commit(&mut self, base: u64, size: u64) {
        let address_space = self.runtime.win32.address_space_mut();
        address_space.register(base, size, crate::vm::VmRegionKind::Image);
        address_space.commit(
            base,
            size,
            crate::vm::VmProtection::READ_WRITE_EXECUTE,
            false,
        );
    }

    /// Install a main module (the pinned image LdrUnloadDll must refuse).
    /// Mirrors the real bootstrap: `set_main_module` + the mapped image
    /// base assignment `seed_process_state` performs.
    #[doc(hidden)]
    pub fn install_main_module(&mut self, image_base: u64, module_name: &str) {
        self.runtime.mapped_image_base = image_base;
        self.runtime
            .set_main_module(module_name, image_base, &[], &[]);
    }

    /// Look up a loaded module handle by name (the LdrGetDllHandle view).
    #[doc(hidden)]
    pub fn module_handle(&self, name: &str) -> Option<u64> {
        self.runtime.lookup_module_handle(name)
    }

    /// True when the module handle is still registered as loaded.
    #[doc(hidden)]
    pub fn is_module_loaded(&self, handle: u64) -> bool {
        handle != 0
            && (handle == self.runtime.mapped_image_base
                || self.runtime.module_names_by_handle.contains_key(&handle))
    }

    /// The loader-lock reentrancy depth (0 = unlocked).
    #[doc(hidden)]
    pub fn loader_lock_depth(&self) -> u32 {
        self.runtime.loader_lock.depth
    }

    /// The DllInfo load count of a module (u32::MAX = pinned).
    #[doc(hidden)]
    pub fn dll_info_load_count(&self, handle: u64) -> Option<u32> {
        self.runtime
            .dll_info_table
            .get(&handle)
            .map(|info| info.load_count)
    }

    /// The RealDllState refcount track of a loaded real DLL.
    #[doc(hidden)]
    pub fn real_dll_refcount(&self, name: &str) -> Option<u32> {
        self.runtime
            .loaded_real_dlls
            .get(&crate::runtime::normalize_module_name(name))
            .map(|state| state.refcount)
    }

    /// The number of real host-backed DLL states parked in the detach-only
    /// list (unloaded guest modules whose libloading host library stays
    /// alive).
    #[doc(hidden)]
    pub fn detached_real_dll_count(&self) -> usize {
        self.runtime.detached_real_dlls.len()
    }
}
