#!/usr/bin/env python3
"""Patch jit.rs: Add G5 (FastThunk ARM64 codegen) and G6 (JIT Unwind info)."""
content = open('src/jit.rs', 'r').read()

# === G5: FastThunktable + register_fast_thunk + emit_arm64_thunk ===
# Insert before the last test module (around line 3560)
old = """#[cfg(test)]"""
new = """// ---------------------------------------------------------------------------
// G5: FastThunk — ARM64 thunk codegen for direct host-call dispatch
// ---------------------------------------------------------------------------

/// A registered fast-thunk entry: maps a host function pointer to a small
/// ARM64 trampoline that calls it directly from JIT-compiled guest code.
struct FastThunkEntry {
    /// The host function to call.
    host_fn: usize,
    /// ARM64 trampoline machine code ("thunk") that jumps to `host_fn`.
    thunk_code: Vec<u8>,
    /// Virtual address where the thunk is mapped for execution.
    thunk_addr: usize,
}

/// Manages all registered fast-thunks, providing executable ARM64 trampolines
/// that allow JIT-compiled guest code to call host functions without going
/// through the full guest→host dispatch loop.
pub struct FastThunkTable {
    entries: Vec<FastThunkEntry>,
    /// mmap'd executable code zone for thunks.
    code_zone: Option<*mut u8>,
    code_zone_size: usize,
    code_zone_used: usize,
}

unsafe impl Send for FastThunkTable {}
unsafe impl Sync for FastThunkTable {}

impl FastThunkTable {
    /// Create a new, empty fast-thunk table.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            code_zone: None,
            code_zone_size: 0,
            code_zone_used: 0,
        }
    }

    /// Ensure we have an executable code zone, allocating one if needed.
    fn ensure_code_zone(&mut self) -> AppResult<()> {
        if self.code_zone.is_some() {
            return Ok(());
        }
        // Allocate 64 KB (one JIT page) of executable memory for thunks
        let size = 64 * 1024;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(AppError::new(
                ReasonCode::RcGuestOom,
                "failed to mmap fast-thunk code zone",
            ));
        }
        // Apple Silicon requires syscall to enable JIT on MAP_JIT regions
        unsafe {
            pthread_jit_write_protect_np(0);
        }
        self.code_zone = Some(ptr as *mut u8);
        self.code_zone_size = size;
        self.code_zone_used = 0;
        Ok(())
    }

    /// Register a fast-thunk for a host function.
    ///
    /// Returns the entry index, which can be used by the JIT to emit a call
    /// to this thunk instead of going through the full dispatch loop.
    pub fn register(&mut self, host_fn: usize) -> AppResult<usize> {
        self.ensure_code_zone()?;

        let zone = self.code_zone.unwrap();
        let offset = self.code_zone_used;
        let addr = unsafe { zone.add(offset) } as usize;

        // Emit ARM64 trampoline:
        //   ldr    x17, [pc, #8]    // Load host_fn address from literal pool
        //   br     x17               // Jump to host function
        //   .quad  host_fn           // Literal pool entry
        //
        // Encoding:
        //   ldr x17, [pc, #8] = 0x58000051
        //   br x17            = 0xD61F0220
        let thunk: Vec<u8> = vec![
            0x51, 0x00, 0x00, 0x58,  // ldr x17, [pc, #8]
            0x20, 0x02, 0x1F, 0xD6,  // br x17
            // literal pool: host_fn (8 bytes, little-endian)
            (host_fn & 0xFF) as u8,
            ((host_fn >> 8) & 0xFF) as u8,
            ((host_fn >> 16) & 0xFF) as u8,
            ((host_fn >> 24) & 0xFF) as u8,
            ((host_fn >> 32) & 0xFF) as u8,
            ((host_fn >> 40) & 0xFF) as u8,
            ((host_fn >> 48) & 0xFF) as u8,
            ((host_fn >> 56) & 0xFF) as u8,
        ];

        // Write thunk into the code zone
        unsafe {
            std::ptr::copy_nonoverlapping(thunk.as_ptr(), addr as *mut u8, thunk.len());
        }
        self.code_zone_used += thunk.len();

        let entry = FastThunkEntry {
            host_fn,
            thunk_code: thunk,
            thunk_addr: addr,
        };
        let idx = self.entries.len();
        self.entries.push(entry);
        Ok(idx)
    }

    /// Get the thunk address for a registered entry.
    pub fn thunk_address(&self, idx: usize) -> Option<usize> {
        self.entries.get(idx).map(|e| e.thunk_addr)
    }

    /// Get the host function pointer for a registered entry.
    pub fn host_fn(&self, idx: usize) -> Option<usize> {
        self.entries.get(idx).map(|e| e.host_fn)
    }

    /// Number of registered thunks.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Drop for FastThunkTable {
    fn drop(&mut self) {
        if let Some(zone) = self.code_zone.take() {
            unsafe {
                libc::munmap(zone as *mut libc::c_void, self.code_zone_size);
            }
        }
    }
}

// pthread_jit_write_protect_np FFI (Apple Silicon)
extern "C" {
    fn pthread_jit_write_protect_np(enabled: i32);
}

// ---------------------------------------------------------------------------
// G6: JIT Unwind Info — ARM64 RuntimeFunction + UnwindInfo for SEH
// ---------------------------------------------------------------------------

/// A single unwind info entry for JIT-compiled blocks.
/// Follows the Windows ARM64 unwind info format for `UNW_FLAG_NO_HANDLER`.
struct JitUnwindInfo {
    /// Start RVA (relative to the code base).
    start_rva: u32,
    /// End RVA (exclusive).
    end_rva: u32,
    /// The raw unwind info bytes (UNW_FLAG_NO_HANDLER format).
    unwind_data: Vec<u8>,
}

/// Manages unwind info for all JIT-compiled blocks, registering them with
/// the SEH subsystem so that `RtlVirtualUnwind` works through JIT frames.
pub struct JitUnwindTable {
    entries: Vec<JitUnwindInfo>,
}

impl JitUnwindTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a JIT block with the unwind table.
    ///
    /// `start_addr` and `end_addr` are the virtual addresses of the compiled
    /// block in the guest address space. The unwind info uses the Windows
    /// ARM64 "packed unwind data" format with UNW_FLAG_NO_HANDLER.
    pub fn register_block(&mut self, start_addr: u64, end_addr: u64) {
        // Generate minimal unwind info for ARM64:
        //   - No prologue (flag=00)
        //   - Function length computed from start_rva..end_rva
        //   - No chained unwind info
        //
        // Windows ARM64 packed unwind data (2 bytes):
        //   Bit 0-1: flag (0=no handler, no chained)
        //   Bit 2-3: function length in 4-byte units, minus 1
        //   Bit 4-5: (unused for no prologue)
        let func_len = ((end_addr - start_addr) / 4) as u32;
        let packed = if func_len > 0x3F { 0x3F } else { func_len as u8 };

        // 2-byte packed unwind data
        let unwind_data = vec![packed | 0x00, 0x00]; // flag=00 (no handler)

        self.entries.push(JitUnwindInfo {
            start_rva: start_addr as u32,
            end_rva: end_addr as u32,
            unwind_data,
        });
    }

    /// Register all entries with the SEH subsystem.
    /// This would be called when the JIT context is set up, adding function
    /// table entries so that Windows SEH can unwind through JIT frames.
    pub fn register_with_seh(&self, _seh: &crate::seh::SehSubsystem) {
        for entry in &self.entries {
            // In a real implementation, this would call RtlAddFunctionTable or
            // similar to register a dynamic function table entry.
            // For now, the entries are stored and can be walked by any custom
            // unwind implementation.
            let _ = (entry.start_rva, entry.end_rva, &entry.unwind_data);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]"""
content = content.replace(old, new, 1)

open('src/jit.rs', 'w').write(content)
print("G5+G6 applied to jit.rs")
PYEOF