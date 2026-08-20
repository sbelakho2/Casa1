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
    if region_size == 0 || allocation_type & (MEM_COMMIT | MEM_RESERVE) == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let commits = allocation_type & MEM_COMMIT != 0;
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
        // MEM_COMMIT at a specific address: interior commit inside an
        // existing PRIVATE reservation.
        let base = requested_base & crate::vm::VM_PAGE_MASK;
        if !vm.can_commit(base, aligned) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        vm.commit(base, aligned, protection, false);
        base
    } else {
        // Reserve + commit a fresh region through the canonical cursor.
        let base = vm.reserve(None, aligned);
        if base == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        vm.commit(base, aligned, protection, false);
        base
    };
    Ok((base, aligned))
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
        let aligned = align_up(region_size);
        vm.decommit(start, aligned);
        Ok((0, aligned))
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

fn align_up(value: u64) -> u64 {
    (value + (crate::vm::VM_PAGE_SIZE - 1)) & crate::vm::VM_PAGE_MASK
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
    fn query_reports_free_reserved_and_committed_runs() {
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
        let committed = nt_query_virtual_memory(&vm, base);
        assert_eq!(committed.state, crate::ntdll::MEM_COMMIT_STATE);
        assert_eq!(committed.protect, crate::ntdll::PAGE_READWRITE);
        assert_eq!(committed.region_size, 0x3000);
        assert_eq!(committed.ty, crate::ntdll::MEM_PRIVATE);

        let (reserved_base, _) = nt_allocate_virtual_memory(
            &mut vm,
            0,
            0,
            0x1000,
            MEM_RESERVE,
            crate::ntdll::PAGE_NOACCESS,
        )
        .expect("reserve");
        let reserved = nt_query_virtual_memory(&vm, reserved_base);
        assert_eq!(reserved.state, crate::ntdll::MEM_RESERVE_STATE);

        let free = nt_query_virtual_memory(&vm, 0x1000);
        assert_eq!(free.state, crate::ntdll::MEM_FREE);
        let serialized = free.serialize_x64();
        assert_eq!(serialized.len(), 48);
        assert_eq!(u64::from_le_bytes(serialized[0..8].try_into().unwrap()), 0);
    }
}
