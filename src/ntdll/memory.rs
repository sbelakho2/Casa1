//! Stage-4 NTDLL — the virtual-memory surface (`Nt*VirtualMemory`).
//!
//! Every function in this module operates on the canonical single VM
//! ([`crate::vm::VirtualMemory`]) — the same instance the interpreter, the
//! JIT and the Win32 VirtualAlloc-family thunks use.  Reservation /
//! commitment / decommit / release / protection / query semantics are those
//! of the canonical layer (see [`crate::vm`]); the Nt* wrappers add the
//! Windows argument validation (allocation-type combos, region-size rules,
//! in/out contract) and the NTSTATUS result domain.
//!
//! Raw guest pages are NEVER created by the Nt layer itself: the dispatch
//! wiring materializes committed ranges in the `MemoryImage` page map, and
//! [`nt_read_virtual_memory`] / [`nt_write_virtual_memory`] go through the
//! checked accessors (`guest_read_checked` / `guest_write_checked`) that
//! fault on unmapped/reserved/guarded ranges instead of allocating pages.

use crate::cpu::MemoryImage;
use crate::ntdll::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE, NtStatus, PAGE_GUARD, PAGE_NOCACHE,
    STATUS_ACCESS_VIOLATION, STATUS_CONFLICTING_ADDRESSES, STATUS_INVALID_PARAMETER,
    STATUS_SUCCESS, protection_from_page_flags,
};
use crate::vm::{VirtualMemory, VmProtection, VmRegionKind, VmState};

/// `STATUS_PARTIAL_COPY` — part of the requested range was transferred before
/// the first inaccessible page was reached.
pub const STATUS_PARTIAL_COPY: NtStatus = NtStatus(0x8000_001Bu32 as i32);

/// The x64 `MEMORY_BASIC_INFORMATION` layout (48 bytes):
///
/// ```text
/// +0x00 BaseAddress        u64
/// +0x08 AllocationBase     u64
/// +0x10 AllocationProtect  u32
/// +0x14 (padding)
/// +0x18 RegionSize         u64
/// +0x20 State              u32
/// +0x24 Protect            u32
/// +0x28 Type               u32
/// +0x2C (padding)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtMemoryBasicInformation {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub ty: u32,
}

impl NtMemoryBasicInformation {
    /// Serialize into the canonical x64 structure bytes (48 bytes).
    pub fn serialize_x64(&self) -> [u8; 48] {
        let mut bytes = [0_u8; 48];
        bytes[0..8].copy_from_slice(&self.base_address.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.allocation_base.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.allocation_protect.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.region_size.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.state.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.protect.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.ty.to_le_bytes());
        bytes
    }
}

/// `NtAllocateVirtualMemory` — reserve and/or commit `region_size` bytes in
/// the canonical VM, exactly like the Win32 VirtualAlloc thunk routes onto
/// it.  Returns `Ok((base, aligned_size))` or the NTSTATUS failure.
///
/// Windows argument contract enforced here:
/// - `region_size == 0` or no MEM_COMMIT/MEM_RESERVE bit → invalid.
/// - `MEM_RESERVE` with a specific base that overlaps an existing
///   reservation → `STATUS_CONFLICTING_ADDRESSES`.
/// - `MEM_COMMIT` at a specific base outside an existing private
///   reservation → `STATUS_INVALID_PARAMETER`.
pub fn nt_allocate_virtual_memory(
    vm: &mut VirtualMemory,
    requested_base: u64,
    zero_bits: u32,
    region_size: u64,
    allocation_type: u32,
    protect: u32,
) -> Result<(u64, u64), NtStatus> {
    nt_allocate_virtual_memory_inner(
        vm,
        None,
        requested_base,
        zero_bits,
        region_size,
        allocation_type,
        protect,
    )
}

/// Commit `region_size` bytes at `base` and zero ONLY the pages that were not
/// already committed.  Existing committed contents are preserved, exactly as
/// `MEM_COMMIT` requires; a previous `MEM_DECOMMIT` leaves stale raw bytes
/// behind, so newly committed pages are zeroed in place (never with a
/// `vec![0; size]` temporary).
fn commit_zeroing_new_pages(
    vm: &mut VirtualMemory,
    memory: &mut Option<&mut MemoryImage>,
    base: u64,
    region_size: u64,
    protection: VmProtection,
) {
    let start = base & crate::vm::VM_PAGE_MASK;
    // Windows computes the committed end as align_up(base + size); using
    // base + align_up(size) over-commits when base is page-unaligned.
    let end = align_up(base.saturating_add(region_size.max(1)));
    let mut page = start;
    while page < end {
        let already_committed = vm.query(page).state == VmState::Committed;
        if !already_committed && let Some(memory) = memory.as_deref_mut() {
            // Zero in place: the page may still hold raw bytes from a
            // previous decommit.  This creates/backfills only this page.
            memory.zero_range(page, crate::vm::VM_PAGE_SIZE as usize);
        }
        page = page.saturating_add(crate::vm::VM_PAGE_SIZE);
    }
    vm.commit(start, end.saturating_sub(start), protection, false);
}

fn nt_allocate_virtual_memory_inner(
    vm: &mut VirtualMemory,
    mut memory: Option<&mut MemoryImage>,
    requested_base: u64,
    zero_bits: u32,
    region_size: u64,
    allocation_type: u32,
    protect: u32,
) -> Result<(u64, u64), NtStatus> {
    if region_size == 0 || allocation_type & (MEM_COMMIT | MEM_RESERVE) == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let commits = allocation_type & MEM_COMMIT != 0;
    let reserves = allocation_type & MEM_RESERVE != 0;
    let aligned = align_up(region_size);
    let protection = protection_from_page_flags(protect);
    // MEM_TOP_DOWN / MEM_WRITE_WATCH are accepted and ignored (the canonical
    // VM's cursor already grows upward; write-watch is not modelled).
    let _ = zero_bits;
    let base = if !commits {
        // MEM_RESERVE only: the pages stay absent (Reserved state).
        let base = vm.reserve((requested_base != 0).then_some(requested_base), aligned);
        if base == 0 {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        base
    } else if requested_base != 0 {
        // MEM_COMMIT at a specific address.  `MEM_RESERVE | MEM_COMMIT` with a
        // fixed base is a legal single call: reserve the range first when no
        // reservation covers it, then commit.  A bare MEM_COMMIT must find an
        // existing private reservation.
        let base = requested_base & crate::vm::VM_PAGE_MASK;
        if vm.region_size(base).is_none() {
            if reserves {
                let reserved = vm.reserve(Some(base), aligned);
                if reserved == 0 {
                    return Err(STATUS_CONFLICTING_ADDRESSES);
                }
            }
        }
        if !vm.can_commit(base, aligned) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        commit_zeroing_new_pages(vm, &mut memory, base, region_size, protection);
        base
    } else {
        // Reserve + commit a fresh region through the canonical cursor.
        let base = vm.reserve(None, aligned);
        if base == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        commit_zeroing_new_pages(vm, &mut memory, base, region_size, protection);
        base
    };
    Ok((base, aligned))
}

/// `NtAllocateVirtualMemory` for the dispatch layer: like
/// [`nt_allocate_virtual_memory`] but also materialises newly committed pages
/// in the guest page map, zeroing only those pages.
pub fn nt_allocate_virtual_memory_with_pages(
    vm: &mut VirtualMemory,
    memory: &mut MemoryImage,
    requested_base: u64,
    zero_bits: u32,
    region_size: u64,
    allocation_type: u32,
    protect: u32,
) -> Result<(u64, u64), NtStatus> {
    nt_allocate_virtual_memory_inner(
        vm,
        Some(memory),
        requested_base,
        zero_bits,
        region_size,
        allocation_type,
        protect,
    )
}

/// `NtFreeVirtualMemory` — release (MEM_RELEASE) or decommit (MEM_DECOMMIT)
/// a range in the canonical VM.  Returns `Ok((base, range_size))` where the
/// caller writes BOTH out-parameters back to zero afterwards (Windows zeroes
/// `BaseAddress` and `RegionSize` on success; the returned pair carries the
/// range that was affected before that).
pub fn nt_free_virtual_memory(
    vm: &mut VirtualMemory,
    base: u64,
    region_size: u64,
    free_type: u32,
) -> Result<(u64, u64), NtStatus> {
    if free_type & MEM_RELEASE != 0 {
        if region_size != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some(size) = vm.region_size(base) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        if !vm.release(base) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok((0, size))
    } else if free_type & MEM_DECOMMIT != 0 {
        if base == 0 || region_size == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let start = base & crate::vm::VM_PAGE_MASK;
        // Windows end is align_up(base + RegionSize), not base + aligned size.
        let end = align_up(base.saturating_add(region_size));
        if end <= start {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // The range must lie inside an existing reservation; decommitting
        // free or partially-outside addresses fails without side effects.
        let query = vm.query(start);
        if query.state == VmState::Free {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some(region) = vm.region_size(query.base) else {
            // `query` only reports a non-free page for a region; if the
            // reservation lookup disagrees, fail closed.
            return Err(STATUS_INVALID_PARAMETER);
        };
        let region_end = query.base.saturating_add(region);
        if end > region_end {
            return Err(STATUS_INVALID_PARAMETER);
        }
        vm.decommit(start, end.saturating_sub(start));
        Ok((0, end.saturating_sub(start)))
    } else {
        Err(STATUS_INVALID_PARAMETER)
    }
}

/// `NtProtectVirtualMemory` — change the protection of the committed pages
/// in `[base, base + size)`.  Returns `Ok((range_size, old_protection))`.
/// The range must lie inside a reservation (Windows fails the call
/// otherwise); the old protection reported is that of the first page.
pub fn nt_protect_virtual_memory(
    vm: &mut VirtualMemory,
    base: u64,
    size: u64,
    new_protect: u32,
) -> Result<(u64, u32), NtStatus> {
    if base == 0 || size == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let start = base & crate::vm::VM_PAGE_MASK;
    let aligned = align_up(size);
    let first = vm.query(start);
    if first.state == VmState::Free {
        // The range is not inside any reservation.
        return Err(STATUS_INVALID_PARAMETER);
    }
    let new_protection = protection_from_page_flags(new_protect);
    let old = vm
        .protect(start, aligned, new_protection)
        .unwrap_or(VmProtection::NONE);
    Ok((aligned, crate::ntdll::page_flags_from_protection(&old)))
}

/// `NtQueryVirtualMemory` (MemoryBasicInformation) — the canonical VM answers
/// every query with the same coalesced page runs the Win32 VirtualQuery
/// reports.  `base_address`/`allocation_base` follow the canonical query
/// (the coalesced run start; free memory reports 0/0 exactly like the
/// canonical `VirtualMemory::query`).
pub fn nt_query_virtual_memory(vm: &VirtualMemory, address: u64) -> NtMemoryBasicInformation {
    let query = vm.query(address);
    let state = match query.state {
        VmState::Free => crate::ntdll::MEM_FREE,
        VmState::Reserved => crate::ntdll::MEM_RESERVE_STATE,
        VmState::Committed => crate::ntdll::MEM_COMMIT_STATE,
    };
    let ty = match query.kind {
        VmRegionKind::Image => crate::ntdll::MEM_IMAGE,
        _ => crate::ntdll::MEM_PRIVATE,
    };
    let protect = if query.state == VmState::Committed {
        crate::ntdll::page_flags_from_protection(&query.protection)
    } else {
        crate::ntdll::PAGE_NOACCESS
    };
    NtMemoryBasicInformation {
        base_address: query.base,
        allocation_base: query.base,
        allocation_protect: if query.state == VmState::Committed {
            protect
        } else {
            crate::ntdll::PAGE_NOACCESS
        },
        region_size: query.region_size,
        state,
        protect,
        ty,
    }
}

/// `NtReadVirtualMemory` — checked guest read that NEVER creates pages.
/// The canonical VM (when attached to the `MemoryImage`) is consulted first,
/// exactly like `guest_read_checked`.  Faults map to `STATUS_ACCESS_VIOLATION`.
pub fn nt_read_virtual_memory(
    memory: &MemoryImage,
    address: u64,
    buffer: &mut [u8],
) -> Result<usize, NtStatus> {
    if buffer.is_empty() {
        return Ok(0);
    }
    memory
        .guest_read_checked(address, buffer)
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    Ok(buffer.len())
}

/// `NtWriteVirtualMemory` — checked guest write that NEVER creates pages.
/// The whole range is validated before any byte is written; an unmapped,
/// reserved, guarded or write-protected target faults with
/// `STATUS_ACCESS_VIOLATION` and nothing is written.
pub fn nt_write_virtual_memory(
    memory: &mut MemoryImage,
    address: u64,
    buffer: &[u8],
) -> Result<usize, NtStatus> {
    if buffer.is_empty() {
        return Ok(0);
    }
    memory
        .guest_write_checked(address, buffer)
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    Ok(buffer.len())
}

/// Page-by-page `NtReadVirtualMemory` transfer used by the dispatch layer.
///
/// The requested length is never used to pre-allocate a buffer: bytes are
/// copied one guest page at a time and the transfer stops at the first
/// inaccessible page.  A transfer that stops after at least one byte
/// returns [`STATUS_PARTIAL_COPY`]; a fault before the first byte returns
/// [`STATUS_ACCESS_VIOLATION`].
pub fn nt_read_virtual_memory_paged(
    memory: &MemoryImage,
    address: u64,
    length: usize,
) -> (NtStatus, Vec<u8>) {
    let mut out = Vec::new();
    let mut chunk = [0_u8; crate::vm::VM_PAGE_SIZE as usize];
    while out.len() < length {
        let current = address.wrapping_add(out.len() as u64);
        let page_offset = (current & (crate::vm::VM_PAGE_SIZE - 1)) as usize;
        let chunk_len = (crate::vm::VM_PAGE_SIZE as usize - page_offset).min(length - out.len());
        match memory.guest_read_checked(current, &mut chunk[..chunk_len]) {
            Ok(()) => out.extend_from_slice(&chunk[..chunk_len]),
            Err(_) => {
                let status = if out.is_empty() {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_PARTIAL_COPY
                };
                return (status, out);
            }
        }
    }
    (STATUS_SUCCESS, out)
}

/// Page-by-page `NtWriteVirtualMemory` transfer used by the dispatch layer.
///
/// `buffer` is only as large as the bytes actually read from the guest
/// source, so the destination is never asked to accept an unbounded
/// allocation.  A fault after at least one byte returns
/// [`STATUS_PARTIAL_COPY`] with the number of bytes written.
pub fn nt_write_virtual_memory_paged(
    memory: &mut MemoryImage,
    address: u64,
    buffer: &[u8],
) -> (NtStatus, usize) {
    let mut written = 0usize;
    while written < buffer.len() {
        let current = address.wrapping_add(written as u64);
        let page_offset = (current & (crate::vm::VM_PAGE_SIZE - 1)) as usize;
        let chunk_len =
            (crate::vm::VM_PAGE_SIZE as usize - page_offset).min(buffer.len() - written);
        match memory.guest_write_checked(current, &buffer[written..written + chunk_len]) {
            Ok(()) => written += chunk_len,
            Err(_) => {
                let status = if written == 0 {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_PARTIAL_COPY
                };
                return (status, written);
            }
        }
    }
    (STATUS_SUCCESS, written)
}

fn align_up(value: u64) -> u64 {
    // Saturating so a request that reaches the top of the address space
    // yields the last page instead of wrapping (or overflowing a debug
    // build) — callers then see `end <= start` and fail the call.
    value.saturating_add(crate::vm::VM_PAGE_SIZE - 1) & crate::vm::VM_PAGE_MASK
}

/// Guard-page bit kept separate from the protection conversion helpers.
#[allow(dead_code)]
const _: u32 = PAGE_GUARD | PAGE_NOCACHE;

/// A successful NTSTATUS for the memory surface.
#[allow(dead_code)]
const _: NtStatus = STATUS_SUCCESS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::VirtualMemory;

    fn test_vm() -> VirtualMemory {
        VirtualMemory::new(0x7fff_0000_0000)
    }

    #[test]
    fn reserve_only_leaves_pages_reserved() {
        let mut vm = test_vm();
        let (base, size) = nt_allocate_virtual_memory(
            &mut vm,
            0,
            0,
            0x2000,
            MEM_RESERVE,
            crate::ntdll::PAGE_READWRITE,
        )
        .expect("reserve");
        assert_eq!(size, 0x2000);
        assert_eq!(vm.query(base).state, VmState::Reserved);
        assert!(!vm.is_mapped(base));
    }

    #[test]
    fn allocate_validates_arguments() {
        let mut vm = test_vm();
        // Zero size is invalid.
        assert_eq!(
            nt_allocate_virtual_memory(&mut vm, 0, 0, 0, MEM_RESERVE, crate::ntdll::PAGE_READWRITE),
            Err(STATUS_INVALID_PARAMETER)
        );
        // No type bits is invalid.
        assert_eq!(
            nt_allocate_virtual_memory(&mut vm, 0, 0, 0x1000, 0, crate::ntdll::PAGE_READWRITE),
            Err(STATUS_INVALID_PARAMETER)
        );
        // Overlapping specific reservation fails.
        let (base, _) = nt_allocate_virtual_memory(
            &mut vm,
            0,
            0,
            0x2000,
            MEM_RESERVE,
            crate::ntdll::PAGE_READWRITE,
        )
        .expect("first");
        assert_eq!(
            nt_allocate_virtual_memory(
                &mut vm,
                base,
                0,
                0x1000,
                MEM_RESERVE,
                crate::ntdll::PAGE_READWRITE,
            ),
            Err(STATUS_CONFLICTING_ADDRESSES)
        );
        // Commit outside any reservation fails.
        assert_eq!(
            nt_allocate_virtual_memory(
                &mut vm,
                base + 0x10_000,
                0,
                0x1000,
                MEM_COMMIT,
                crate::ntdll::PAGE_READWRITE,
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn free_releases_or_decommits() {
        let mut vm = test_vm();
        let (base, size) = nt_allocate_virtual_memory(
            &mut vm,
            0,
            0,
            0x3000,
            MEM_COMMIT | MEM_RESERVE,
            crate::ntdll::PAGE_READWRITE,
        )
        .expect("allocate");
        // Decommit the middle page range.
        let (_, range) =
            nt_free_virtual_memory(&mut vm, base + 0x1000, 0x1000, MEM_DECOMMIT).expect("decommit");
        assert_eq!(range, 0x1000);
        assert_eq!(vm.query(base).state, VmState::Committed);
        assert_eq!(vm.query(base + 0x1000).state, VmState::Reserved);
        // Release the whole reservation (size must be 0).
        assert_eq!(
            nt_free_virtual_memory(&mut vm, base, 0x1000, MEM_RELEASE),
            Err(STATUS_INVALID_PARAMETER),
            "MEM_RELEASE requires RegionSize == 0"
        );
        let (_, released) = nt_free_virtual_memory(&mut vm, base, 0, MEM_RELEASE).expect("release");
        assert_eq!(released, size);
        assert_eq!(vm.query(base).state, VmState::Free);
    }

    #[test]
    fn protect_changes_protection_and_reports_old() {
        let mut vm = test_vm();
        let (base, _) = nt_allocate_virtual_memory(
            &mut vm,
            0,
            0,
            0x2000,
            MEM_COMMIT | MEM_RESERVE,
            crate::ntdll::PAGE_READWRITE,
        )
        .expect("allocate");
        let (range, old) =
            nt_protect_virtual_memory(&mut vm, base, 0x1000, crate::ntdll::PAGE_READONLY)
                .expect("protect");
        assert_eq!(range, 0x1000);
        assert_eq!(old, crate::ntdll::PAGE_READWRITE);
        assert_eq!(
            vm.query(base).protection,
            VmProtection::READ,
            "the canonical VM carries the new protection"
        );
        // Protection outside a reservation fails.
        assert_eq!(
            nt_protect_virtual_memory(&mut vm, 0x1000, 0x1000, crate::ntdll::PAGE_READONLY),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn allocate_reserves_and_commits_through_the_canonical_vm() {
        let mut vm = test_vm();
        let (base, size) = nt_allocate_virtual_memory(
            &mut vm,
            0,
            0,
            0x4000,
            MEM_COMMIT | MEM_RESERVE,
            crate::ntdll::PAGE_READWRITE,
        )
        .expect("allocate");
        assert_ne!(base, 0);
        assert_eq!(base & crate::vm::VM_PAGE_MASK, base);
        assert_eq!(size, 0x4000);
        // The canonical VM reflects the reservation + commitment.
        let query = vm.query(base);
        assert_eq!(query.state, VmState::Committed);
        assert_eq!(query.region_size, 0x4000);
        assert_eq!(query.protection, VmProtection::READ_WRITE);
        assert!(vm.is_mapped(base));
    }

    /// MEM_COMMIT semantics: re-committing an already-committed range keeps
    /// its contents, while a page that was decommitted is zeroed IN PLACE
    /// (stale raw bytes from before the decommit must never resurface).
    #[test]
    fn mem_commit_zeroes_only_new_pages_and_preserves_committed_contents() {
        let mut vm = test_vm();
        let mut memory = MemoryImage::default();
        let (base, size) = nt_allocate_virtual_memory_with_pages(
            &mut vm,
            &mut memory,
            0,
            0,
            0x2000,
            MEM_COMMIT | MEM_RESERVE,
            crate::ntdll::PAGE_READWRITE,
        )
        .expect("initial commit");
        assert_eq!(size, 0x2000);
        memory.map_bytes(base, &[0xAA; 8]);
        memory.map_bytes(base + 0x1000, &[0xBB; 8]);
        // Re-commit of the full range: already-committed pages are NOT zeroed.
        let (again, again_size) = nt_allocate_virtual_memory_with_pages(
            &mut vm,
            &mut memory,
            base,
            0,
            0x2000,
            MEM_COMMIT,
            crate::ntdll::PAGE_READWRITE,
        )
        .expect("re-commit");
        assert_eq!((again, again_size), (base, 0x2000));
        assert_eq!(
            memory.read_u64(base).expect("page 0 contents"),
            u64::from_le_bytes([0xAA; 8]),
            "MEM_COMMIT preserves already-committed contents"
        );
        // Decommit page 0 in the VM only, then leave stale raw bytes behind.
        nt_free_virtual_memory(&mut vm, base, 0x1000, MEM_DECOMMIT).expect("decommit page 0");
        memory.map_bytes(base, &[0xCC; 8]);
        // Re-commit page 0: the stale 0xCC bytes must be zeroed in place.
        nt_allocate_virtual_memory_with_pages(
            &mut vm,
            &mut memory,
            base,
            0,
            0x1000,
            MEM_COMMIT,
            crate::ntdll::PAGE_READWRITE,
        )
        .expect("re-commit page 0");
        assert_eq!(
            memory.read_u64(base).expect("recommitted page 0"),
            0,
            "a newly committed page is zeroed in place, not left stale"
        );
        assert_eq!(
            memory.read_u64(base + 0x1000).expect("page 1 contents"),
            u64::from_le_bytes([0xBB; 8]),
            "the untouched committed page keeps its contents"
        );
    }

    /// A fixed-base `MEM_RESERVE | MEM_COMMIT` reserves the free range first
    /// and reports `STATUS_CONFLICTING_ADDRESSES` when that range overlaps an
    /// existing reservation.
    #[test]
    fn fixed_base_reserve_and_commit_conflicts_with_overlapping_reservation() {
        let mut vm = test_vm();
        // An existing cursor reservation to collide with.
        let occupied = vm.reserve(None, 0x1000);
        assert_ne!(occupied, 0);
        // Overlap: the fixed range [occupied - 0x1000, +0x2000) covers it.
        assert_eq!(
            nt_allocate_virtual_memory(
                &mut vm,
                occupied - 0x1000,
                0,
                0x2000,
                MEM_COMMIT | MEM_RESERVE,
                crate::ntdll::PAGE_READWRITE,
            ),
            Err(STATUS_CONFLICTING_ADDRESSES),
            "a fixed reserve+commit overlapping a live reservation conflicts"
        );
        // A free fixed base succeeds: reserve first, then commit.
        let fixed = 0x7FF0_0000_0000_u64;
        assert_eq!(vm.region_size(fixed), None, "precondition: base is free");
        let (base, size) = nt_allocate_virtual_memory(
            &mut vm,
            fixed,
            0,
            0x2000,
            MEM_COMMIT | MEM_RESERVE,
            crate::ntdll::PAGE_READWRITE,
        )
        .expect("fixed reserve+commit");
        assert_eq!((base, size), (fixed, 0x2000));
        assert_eq!(vm.query(fixed).state, VmState::Committed);
    }

    /// MEM_DECOMMIT validation edges: zero/absent arguments, a range whose
    /// aligned end wraps off the top of the address space, free pages,
    /// ranges extending past the reservation, and a committed run whose base
    /// is not the reservation base (fail closed).
    #[test]
    fn decommit_rejects_wrapping_end_free_pages_and_out_of_region_ranges() {
        let mut vm = test_vm();
        let (base, _) = nt_allocate_virtual_memory(
            &mut vm,
            0,
            0,
            0x3000,
            MEM_COMMIT | MEM_RESERVE,
            crate::ntdll::PAGE_READWRITE,
        )
        .expect("allocate");
        assert_eq!(
            nt_free_virtual_memory(&mut vm, base, 0, MEM_DECOMMIT),
            Err(STATUS_INVALID_PARAMETER),
            "MEM_DECOMMIT with RegionSize 0 is invalid"
        );
        assert_eq!(
            nt_free_virtual_memory(&mut vm, 0, 0x1000, MEM_DECOMMIT),
            Err(STATUS_INVALID_PARAMETER),
            "MEM_DECOMMIT with a null base is invalid"
        );
        assert_eq!(
            nt_free_virtual_memory(&mut vm, u64::MAX - 0x800, 0x1000, MEM_DECOMMIT),
            Err(STATUS_INVALID_PARAMETER),
            "a decommit whose aligned end wraps the address space is invalid"
        );
        assert_eq!(
            nt_free_virtual_memory(&mut vm, 0x1000, 0x1000, MEM_DECOMMIT),
            Err(STATUS_INVALID_PARAMETER),
            "decommitting free memory is invalid"
        );
        assert_eq!(
            nt_free_virtual_memory(&mut vm, base + 0x2000, 0x2000, MEM_DECOMMIT),
            Err(STATUS_INVALID_PARAMETER),
            "a decommit extending past the reservation is invalid"
        );
        // Decommit the first page; page 0's absence makes the committed run
        // of pages 1..3 start mid-reservation, so a further decommit of
        // page 2 must fail closed instead of corrupting the region.
        nt_free_virtual_memory(&mut vm, base, 0x1000, MEM_DECOMMIT).expect("decommit page 0");
        assert_eq!(
            nt_free_virtual_memory(&mut vm, base + 0x2000, 0x1000, MEM_DECOMMIT),
            Err(STATUS_INVALID_PARAMETER),
            "a committed run that does not start at the reservation base fails closed"
        );
        assert_eq!(
            nt_free_virtual_memory(&mut vm, base + 0x10_000, 0, MEM_RELEASE),
            Err(STATUS_INVALID_PARAMETER),
            "MEM_RELEASE of a never-reserved base is invalid"
        );
        assert_eq!(
            nt_free_virtual_memory(&mut vm, base, 0x1000, 0),
            Err(STATUS_INVALID_PARAMETER),
            "a free type without MEM_RELEASE/MEM_DECOMMIT is invalid"
        );
    }

    /// Page-by-page transfers stop at the first inaccessible page: a fault
    /// before any byte is `STATUS_ACCESS_VIOLATION`, a fault after at least
    /// one byte is `STATUS_PARTIAL_COPY`, and unaligned starts chunk to the
    /// page boundary.
    #[test]
    fn paged_transfers_stop_at_first_inaccessible_page_with_partial_status() {
        let mut memory = MemoryImage::default();
        let page = 0x8000_u64;
        memory.map_bytes(page, &[0x5A; 0x1000]);
        // Unaligned start 16 bytes before the page end: first chunk succeeds,
        // the next page is unmapped → partial copy of exactly 16 bytes.
        let (status, bytes) = nt_read_virtual_memory_paged(&memory, page + 0xFF0, 0x20);
        assert_eq!(status, STATUS_PARTIAL_COPY, "mid-transfer fault is partial");
        assert_eq!(
            bytes,
            vec![0x5A; 16],
            "only the accessible chunk is returned"
        );
        // A fault before the first byte is a straight access violation.
        let (status, bytes) = nt_read_virtual_memory_paged(&memory, 0x9000, 0x10);
        assert_eq!(status, STATUS_ACCESS_VIOLATION, "immediate fault is AV");
        assert_eq!(
            bytes.len(),
            0,
            "no bytes are returned on an immediate fault"
        );
        // A fully accessible range succeeds.
        let (status, bytes) = nt_read_virtual_memory_paged(&memory, page + 0x10, 0x20);
        assert_eq!(status, STATUS_SUCCESS, "accessible read succeeds");
        assert_eq!(bytes, vec![0x5A; 0x20]);
        // Zero length never touches memory.
        let (status, bytes) = nt_read_virtual_memory_paged(&memory, page, 0);
        assert_eq!(status, STATUS_SUCCESS, "zero-length read succeeds");
        assert_eq!(bytes.len(), 0);
        // Writes mirror the read semantics.
        let (status, written) =
            nt_write_virtual_memory_paged(&mut memory, page + 0xFF0, &[0x11; 0x20]);
        assert_eq!(
            status, STATUS_PARTIAL_COPY,
            "mid-transfer write fault is partial"
        );
        assert_eq!(written, 16, "only the accessible chunk is written");
        let (status, written) = nt_write_virtual_memory_paged(&mut memory, 0x9000, &[0x22; 8]);
        assert_eq!(
            status, STATUS_ACCESS_VIOLATION,
            "immediate write fault is AV"
        );
        assert_eq!(written, 0, "no bytes are written on an immediate fault");
        let (status, written) = nt_write_virtual_memory_paged(&mut memory, page, &[0x33; 8]);
        assert_eq!(status, STATUS_SUCCESS, "accessible write succeeds");
        assert_eq!(written, 8);
        assert_eq!(
            memory.read_u8(page).expect("byte"),
            0x33,
            "the write landed"
        );
    }
}
