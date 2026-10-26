#![allow(unused_imports)]

use super::*;
use crate::cpu::{
    ConditionCode, CpuState, GuestArch, GuestMemoryFault, GuestMemoryStore, IrInstruction,
    MemoryImage, Register,
};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

// SAFETY: pthread_jit_write_protect_np is a system function on Apple
// Silicon that toggles W^X permissions on MAP_JIT pages. The FFI
// declaration matches the C prototype: void pthread_jit_write_protect_np(int).
// It is always available on macOS with Apple Silicon.
unsafe extern "C" {
    #[allow(dead_code)] // platform FFI declaration (ABI surface); flagged for the API database
    fn pthread_jit_write_protect_np(enabled: i32);
}

// ---------------------------------------------------------------------------
// G6: JIT Unwind Info — ARM64 RuntimeFunction + UnwindInfo for SEH
// ---------------------------------------------------------------------------

/// A single unwind info entry for JIT-compiled blocks.
/// Follows the Windows ARM64 unwind info format for `UNW_FLAG_NO_HANDLER`.
#[allow(dead_code)] // unwind-info payload for future unwinding support
pub(super) struct JitUnwindInfo {
    /// Start RVA (relative to the code base).
    pub(super) start_rva: u32,
    /// End RVA (exclusive).
    pub(super) end_rva: u32,
    /// The raw unwind info bytes (UNW_FLAG_NO_HANDLER format).
    pub(super) unwind_data: Vec<u8>,
}

/// Manages unwind info for all JIT-compiled blocks, registering them with
/// the SEH subsystem so that `RtlVirtualUnwind` works through JIT frames.
pub struct JitUnwindTable {
    pub(super) entries: Vec<JitUnwindInfo>,
    /// Tracks whether entries have changed since the last `register_with_seh()` call.
    /// Used by the caller to avoid redundant SEH syncs.
    pub(super) dirty: bool,
}

impl Default for JitUnwindTable {
    fn default() -> Self {
        Self::new()
    }
}

impl JitUnwindTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            dirty: false,
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
        let packed = if func_len > 0x3F {
            0x3F
        } else {
            func_len as u8
        };

        // 2-byte packed unwind data
        let unwind_data = vec![packed, 0x00]; // flag=00 (no handler)

        self.entries.push(JitUnwindInfo {
            start_rva: start_addr as u32,
            end_rva: end_addr as u32,
            unwind_data,
        });
        self.dirty = true;

        eprintln!(
            "[jit] unwind: registered block {:#x}..{:#x} ({} entries)",
            start_addr,
            end_addr,
            self.entries.len()
        );
    }

    /// Remove a JIT block from the unwind table by guest address.
    ///
    /// Returns `true` if the entry was found and removed.
    pub fn unregister_block(&mut self, guest_address: u64) -> bool {
        let rva = guest_address as u32;
        let before = self.entries.len();
        self.entries.retain(|e| e.start_rva != rva);
        let removed = self.entries.len() != before;
        if removed {
            self.dirty = true;
            eprintln!(
                "[jit] unwind: unregistered block {:#x} ({} entries remaining)",
                guest_address,
                self.entries.len()
            );
        }
        removed
    }

    /// Remove all entries from the unwind table.
    pub fn clear(&mut self) {
        if !self.entries.is_empty() {
            let count = self.entries.len();
            self.entries.clear();
            self.dirty = true;
            eprintln!("[jit] unwind: cleared all {count} entries");
        }
    }

    /// Returns `true` if entries have changed since the last `register_with_seh()` call.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Register all entries with the SEH subsystem.
    ///
    /// Builds a `.pdata`-format function table and x64-compatible UNWIND_INFO
    /// blocks from the JIT entries and registers them with the SEH subsystem
    /// so that `RtlVirtualUnwind` can unwind through JIT-compiled frames.
    ///
    /// Uses `JIT_IMAGE_BASE` (0) as the image base — the JIT entries store
    /// RVA-sized address ranges that are looked up directly without subtraction.
    ///
    /// Each JIT entry generates:
    /// - A 12-byte `RUNTIME_FUNCTION` entry (3 × u32 LE: `begin_rva`, `end_rva`,
    ///   `unwind_info_rva`)
    /// - A 4-byte x64 `UNWIND_INFO` with `UNW_FLAG_NO_HANDLER` (version=1,
    ///   flags=0, no prolog, no unwind codes) — this tells `virtual_unwind` to
    ///   simply pop the return address from the stack.
    ///
    /// If called multiple times (e.g. after adding more blocks), the previous
    /// registration is overwritten. Callers should batch all `register_block()`
    /// calls before a single `register_with_seh()` call.
    pub fn register_with_seh(&mut self, seh: &mut crate::seh::SehSubsystem) {
        if self.entries.is_empty() {
            eprintln!("[jit] unwind: register_with_seh called with no entries (skipping)");
            // Still clear the dirty flag so we don't retry on every check
            self.dirty = false;
            return;
        }

        // Image base for JIT code. Since entries store RVA-sized values,
        // using 0 means the SEH lookup (rip - image_base) preserves the
        // stored RVAs directly.
        const JIT_IMAGE_BASE: u64 = 0;

        // Each RUNTIME_FUNCTION entry is 12 bytes (3 × u32 LE).
        let mut pdata_bytes = Vec::with_capacity(self.entries.len() * 12);

        // Build a concatenated x64 UNWIND_INFO blob. Each entry gets a 4-byte
        // UNW_FLAG_NO_HANDLER descriptor so that parse_unwind_info() can
        // successfully parse it and virtual_unwind() can pop the return address.
        //
        // x64 UNWIND_INFO layout (4 bytes):
        //   [0]: version(3 bits) | flags(5 bits)  — 0x01 = v1, UNW_FLAG_NO_HANDLER
        //   [1]: prolog_size                      — 0x00 (no prologue)
        //   [2]: code_count                       — 0x00 (no unwind codes)
        //   [3]: frame_register(4) | frame_offset(4) — 0x00
        let mut unwind_data = Vec::new();

        for entry in &self.entries {
            // RVA to this entry's unwind info within the concatenated blob.
            let unwind_info_rva = unwind_data.len() as u32;

            // Append the RUNTIME_FUNCTION entry (begin_rva, end_rva, unwind_info_rva).
            pdata_bytes.extend_from_slice(&entry.start_rva.to_le_bytes());
            pdata_bytes.extend_from_slice(&entry.end_rva.to_le_bytes());
            pdata_bytes.extend_from_slice(&unwind_info_rva.to_le_bytes());

            // Append a 4-byte x64 UNWIND_INFO (UNW_FLAG_NO_HANDLER, no codes).
            unwind_data.push(0x01); // version=1, flags=0
            unwind_data.push(0x00); // prolog_size=0
            unwind_data.push(0x00); // code_count=0
            unwind_data.push(0x00); // frame_register=0, frame_offset=0
        }

        // Register the function table and unwind data with the SEH subsystem
        // under the JIT image base. This enables find_runtime_function() to
        // locate JIT entries and get_unwind_info() to parse the unwind data.
        let unwind_data_len = unwind_data.len();
        let pdata_len = pdata_bytes.len();
        let entry_count = self.entries.len();

        seh.register_pdata(JIT_IMAGE_BASE, &pdata_bytes);
        seh.register_unwind_data(JIT_IMAGE_BASE, unwind_data);
        self.dirty = false;

        eprintln!(
            "[jit] unwind: registered {} blocks with SEH (pdata={} bytes, unwind_data={} bytes)",
            entry_count, pdata_len, unwind_data_len
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
