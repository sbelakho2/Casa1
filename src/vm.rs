//! Canonical guest virtual-memory subsystem.
//!
//! ONE authoritative layer for reservation / commit / protection / query /
//! guard semantics shared by the interpreter, the JIT memory helpers and the
//! VirtualAlloc-family host thunks.  The CPU's [`crate::cpu::MemoryImage`]
//! keeps the raw page storage (the loader's `map_bytes` stays the only
//! raw-page allocator), but every page-STATE decision routes through this
//! layer: `MemoryImage` holds a handle to the live [`VirtualMemory`] and its
//! checked accessors consult [`VirtualMemory::check_access`] FIRST, so a
//! stray raw page can never be read or written when the canonical layer says
//! the address is unmapped or guarded.
//!
//! Model:
//! - [`VirtualMemory::regions`] is a set of [`VmRegion`]s keyed by their
//!   page-aligned base.  A region is a reservation (image / stack / heap /
//!   private).  Regions may nest (the growing CRT data area contains
//!   synthetic module images); address resolution always picks the innermost
//!   containing region (highest base).
//! - Within a region, pages absent from `pages` are Reserved; a present
//!   [`VmPageState`] is a committed page carrying its protection and guard
//!   flag.
//! - [`VirtualMemory::query`] coalesces adjacent pages with identical state
//!   (and, for committed pages, identical protection + guard) exactly like
//!   the page-granular Windows `VirtualQuery`.
//! - [`VirtualMemory::check_access`] is the single validation every access
//!   path calls: unmapped / reserved / guard / protection-violation faults
//!   are reported identically to the interpreter, the JIT and the thunks.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Guest page size (Windows 4 KiB pages).
pub const VM_PAGE_SIZE: u64 = 0x1000;
/// Page-alignment mask for guest addresses.
pub const VM_PAGE_MASK: u64 = !(VM_PAGE_SIZE - 1);

fn align_up(value: u64, align: u64) -> u64 {
    value.wrapping_add(align - 1) & !(align - 1)
}

/// Read / write / execute access permissions for a committed page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl VmProtection {
    /// PAGE_NOACCESS.
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };
    /// PAGE_READONLY.
    pub const READ: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    /// PAGE_READWRITE.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    /// PAGE_EXECUTE_READ.
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    /// PAGE_EXECUTE_READWRITE.
    pub const READ_WRITE_EXECUTE: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
}

/// What kind of guest memory a [`VmRegion`] backs.  The VirtualQuery thunk
/// maps `Image` to `MEM_IMAGE` and everything else to `MEM_PRIVATE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VmRegionKind {
    Private,
    Image,
    Heap,
    Stack,
}

/// State of one committed page inside a [`VmRegion`].  Absent entries are
/// reserved (uncommitted) pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmPageState {
    pub protection: VmProtection,
    /// Guard page: any access faults with a guard fault.
    pub guard: bool,
    pub committed: bool,
}

/// A contiguous guest address reservation.
#[derive(Debug, Clone)]
pub struct VmRegion {
    pub base: u64,
    pub size: u64,
    pub kind: VmRegionKind,
    pub pages: BTreeMap<u64, VmPageState>,
}

impl VmRegion {
    fn end(&self) -> u64 {
        self.base + self.size
    }

    fn contains(&self, address: u64) -> bool {
        address >= self.base && address - self.base < self.size
    }
}

/// Memory state reported by [`VirtualMemory::query`], mirroring the
/// page-granular Windows `MEMORY_BASIC_INFORMATION` semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Free,
    Reserved,
    Committed,
}

/// Result of a coalesced [`VirtualMemory::query`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmQueryResult {
    /// Base of the allocation containing the queried address (the region
    /// base for reserved/committed pages, the page base for free memory).
    pub base: u64,
    /// Run of adjacent pages with identical state (and, when committed,
    /// identical protection and guard) starting at the queried page.
    pub region_size: u64,
    pub state: VmState,
    pub protection: VmProtection,
    pub kind: VmRegionKind,
    pub guard: bool,
}

/// A rejected guest memory access, produced by [`VirtualMemory::check_access`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmAccessFault {
    /// The precise faulting address (the address that was checked).
    pub address: u64,
    pub write: bool,
    /// True when the page is a guard page (guard-page fault).
    pub guard: bool,
}

/// A mapped file-view record: the section backing storage and the offset
/// into it where the view starts.  The region at the view base is a normal
/// committed reservation; the mapping record ties it to the section's
/// backing so `MapViewOfFile` / `UnmapViewOfFile` bookkeeping lives HERE
/// (sections own their storage; the mapping state lives in the VM).
#[derive(Debug, Clone)]
pub struct VmMapping {
    /// Offset into the section backing where this view starts.
    pub offset: u64,
    /// Shared byte storage of the mapped section.
    pub backing: Arc<Mutex<Vec<u8>>>,
}

/// The canonical guest virtual-memory layer.
#[derive(Debug)]
pub struct VirtualMemory {
    /// Reservations keyed by page-aligned base.  Regions may nest; address
    /// resolution picks the innermost containing region.
    regions: BTreeMap<u64, VmRegion>,
    /// Cursor for [`VirtualMemory::reserve`] with `base = None`.
    next_region_address: u64,
    /// Section-backed file views keyed by their (page-aligned) view base.
    mappings: BTreeMap<u64, VmMapping>,
}

impl Default for VirtualMemory {
    fn default() -> Self {
        Self {
            regions: BTreeMap::new(),
            next_region_address: 0x0000_7fff_8400_0000,
            mappings: BTreeMap::new(),
        }
    }
}

impl VirtualMemory {
    /// Create an empty canonical VM whose anonymous reservations
    /// (`reserve(None, …)`) start at `private_region_cursor`.
    pub fn new(private_region_cursor: u64) -> Self {
        Self {
            regions: BTreeMap::new(),
            next_region_address: align_up(private_region_cursor, VM_PAGE_SIZE),
            mappings: BTreeMap::new(),
        }
    }

    /// The innermost region containing `address` (highest base among the
    /// regions whose range covers it).
    fn region_containing(&self, address: u64) -> Option<&VmRegion> {
        self.regions
            .range(..=address)
            .rev()
            .find(|(_, region)| region.contains(address))
            .map(|(_, region)| region)
    }

    fn region_containing_mut(&mut self, address: u64) -> Option<&mut VmRegion> {
        self.regions
            .range_mut(..=address)
            .rev()
            .find(|(_, region)| region.contains(address))
            .map(|(_, region)| region)
    }

    fn overlaps_any(&self, base: u64, size: u64) -> bool {
        let Some(end) = base.checked_add(size) else {
            return true;
        };
        self.regions.values().any(|region| {
            let region_end = region.base + region.size;
            base < region_end && region.base < end
        })
    }

    /// Reserve a private region of `size` bytes (rounded up to pages).
    ///
    /// With `base = None` the address is taken from the internal cursor
    /// (and the cursor advances past the region).  With `Some(base)` the
    /// address is used page-aligned, and the reservation FAILS (returns 0)
    /// if it overlaps any existing region — Windows semantics.
    pub fn reserve(&mut self, base: Option<u64>, size: u64) -> u64 {
        let size = align_up(size.max(1), VM_PAGE_SIZE);
        let address = match base {
            Some(requested) => {
                let candidate = requested & VM_PAGE_MASK;
                if candidate == 0 || self.overlaps_any(candidate, size) {
                    return 0;
                }
                candidate
            }
            None => {
                let candidate = align_up(self.next_region_address, VM_PAGE_SIZE);
                let Some(end) = candidate.checked_add(size) else {
                    return 0;
                };
                self.next_region_address = end;
                candidate
            }
        };
        self.regions.insert(
            address,
            VmRegion {
                base: address,
                size,
                kind: VmRegionKind::Private,
                pages: BTreeMap::new(),
            },
        );
        address
    }

    /// Register (or grow) a region of the given kind at `base`.
    ///
    /// Used for the loader-mapped image, the guest stack, the CRT data
    /// area and heap area: areas the loader/allocators populate with raw
    /// pages and that the guest can then access.  When a region already
    /// exists at `base` it is extended to cover `size` (the bump
    /// allocators grow their areas monotonically).  Returns `false` only
    /// on address-space overflow.
    pub fn register(&mut self, base: u64, size: u64, kind: VmRegionKind) -> bool {
        let base = base & VM_PAGE_MASK;
        let size = align_up(size.max(1), VM_PAGE_SIZE);
        if let Some(region) = self.regions.get_mut(&base) {
            if region.size < size {
                region.size = size;
            }
            return true;
        }
        let Some(end) = base.checked_add(size) else {
            return false;
        };
        if end < base {
            return false;
        }
        self.regions.insert(
            base,
            VmRegion {
                base,
                size,
                kind,
                pages: BTreeMap::new(),
            },
        );
        true
    }

    /// Commit `size` bytes at `base` inside the containing reservation(s),
    /// setting the pages' protection and guard flag.  Pages outside any
    /// reservation are left untouched (Windows fails commits outside a
    /// reservation; the thunks validate with [`VirtualMemory::can_commit`]
    /// first).
    pub fn commit(&mut self, base: u64, size: u64, protection: VmProtection, guard: bool) {
        let start = base & VM_PAGE_MASK;
        let end = start.saturating_add(align_up(size.max(1), VM_PAGE_SIZE));
        let mut page = start;
        while page < end {
            if let Some(region) = self.region_containing_mut(page) {
                region.pages.insert(
                    page,
                    VmPageState {
                        protection,
                        guard,
                        committed: true,
                    },
                );
            }
            page = page.saturating_add(VM_PAGE_SIZE);
        }
    }

    /// Decommit `size` bytes at `base`: the pages become reserved again
    /// (absent from their region) while the reservation itself is kept.
    pub fn decommit(&mut self, base: u64, size: u64) {
        let start = base & VM_PAGE_MASK;
        let end = start.saturating_add(align_up(size.max(1), VM_PAGE_SIZE));
        let mut page = start;
        while page < end {
            if let Some(region) = self.region_containing_mut(page) {
                region.pages.remove(&page);
            }
            page = page.saturating_add(VM_PAGE_SIZE);
        }
    }

    /// Release the reservation whose base is exactly `base`, freeing the
    /// whole region.  The `size` parameter of `VirtualFree(MEM_RELEASE)`
    /// is a thunk-level validation concern (must be 0); the canonical
    /// release operates on the region alone.  Returns `false` when no
    /// region starts at `base`.
    pub fn release(&mut self, base: u64) -> bool {
        self.regions.remove(&(base & VM_PAGE_MASK)).is_some()
    }

    /// The total size of the reservation starting exactly at `base`, or
    /// `None` when no region starts there.  Lets callers unmap the raw
    /// pages of a region before releasing it.
    pub fn region_size(&self, base: u64) -> Option<u64> {
        self.regions
            .get(&(base & VM_PAGE_MASK))
            .map(|region| region.size)
    }

    /// True when the page-aligned `[base, base + size)` range lies entirely
    /// inside a single PRIVATE reservation — the Windows precondition for
    /// committing inside an existing reservation.
    pub fn can_commit(&self, base: u64, size: u64) -> bool {
        let start = base & VM_PAGE_MASK;
        let size = align_up(size.max(1), VM_PAGE_SIZE);
        let Some(end) = start.checked_add(size) else {
            return false;
        };
        let Some(region) = self.region_containing(start) else {
            return false;
        };
        region.kind == VmRegionKind::Private && end <= region.end()
    }

    /// Change the protection of the COMMITTED pages in the range only
    /// (reserved pages keep their state).  Returns the previous protection
    /// of the first page in the range (`None` when that page is not
    /// committed).
    pub fn protect(
        &mut self,
        base: u64,
        size: u64,
        protection: VmProtection,
    ) -> Option<VmProtection> {
        let start = base & VM_PAGE_MASK;
        let end = start.saturating_add(align_up(size.max(1), VM_PAGE_SIZE));
        let mut first_old = None;
        let mut page = start;
        while page < end {
            if let Some(region) = self.region_containing_mut(page)
                && let Some(state) = region.pages.get_mut(&page)
            {
                if first_old.is_none() {
                    first_old = Some(state.protection);
                }
                state.protection = protection;
            }
            page = page.saturating_add(VM_PAGE_SIZE);
        }
        first_old
    }

    /// Coalesced page-granular query: reports the run of adjacent pages
    /// with identical state — and, for committed pages, identical
    /// protection and guard — starting at the page containing `address`,
    /// exactly like the page-granular Windows `VirtualQuery`.
    pub fn query(&self, address: u64) -> VmQueryResult {
        let page = address & VM_PAGE_MASK;
        let Some(region) = self.region_containing(address) else {
            // Windows VirtualQuery on free memory: NULL base and 0 size.
            return VmQueryResult {
                base: 0,
                region_size: 0,
                state: VmState::Free,
                protection: VmProtection::NONE,
                kind: VmRegionKind::Private,
                guard: false,
            };
        };
        if let Some(state) = region.pages.get(&page) {
            // Windows VirtualQuery semantics: BaseAddress is the START of
            // the coalesced run of pages with identical state/protection
            // containing the queried page — for a partially committed
            // reservation that is the first page of the committed run, NOT
            // the reservation base.  Walk backward to find it.
            let mut run_start = page;
            while run_start > region.base {
                let prev = run_start - VM_PAGE_SIZE;
                match region.pages.get(&prev) {
                    Some(prev_state)
                        if prev_state.committed
                            && prev_state.protection == state.protection
                            && prev_state.guard == state.guard =>
                    {
                        run_start = prev;
                    }
                    _ => break,
                }
            }
            let mut run_end = page + VM_PAGE_SIZE;
            loop {
                match region.pages.get(&run_end) {
                    Some(next)
                        if next.committed
                            && next.protection == state.protection
                            && next.guard == state.guard =>
                    {
                        run_end += VM_PAGE_SIZE;
                    }
                    _ => break,
                }
            }
            VmQueryResult {
                base: run_start,
                region_size: run_end - run_start,
                state: VmState::Committed,
                protection: state.protection,
                kind: region.kind,
                guard: state.guard,
            }
        } else {
            // Reserved run: coalesce backward over absent pages too.
            let mut run_start = page;
            while run_start > region.base {
                let prev = run_start - VM_PAGE_SIZE;
                if region.pages.contains_key(&prev) {
                    break;
                }
                run_start = prev;
            }
            let mut run_end = page + VM_PAGE_SIZE;
            let region_end = region.end();
            while run_end < region_end && !region.pages.contains_key(&run_end) {
                run_end += VM_PAGE_SIZE;
            }
            VmQueryResult {
                base: run_start,
                region_size: run_end - run_start,
                state: VmState::Reserved,
                protection: VmProtection::NONE,
                kind: region.kind,
                guard: false,
            }
        }
    }

    /// The SINGLE access validation for the interpreter, the JIT memory
    /// helpers and the VirtualAlloc-family thunks.  Faults when the
    /// address is unmapped (no containing region), reserved, a guard page,
    /// or the protection denies the requested access.
    pub fn check_access(
        &self,
        address: u64,
        write: bool,
        execute: bool,
    ) -> Result<(), VmAccessFault> {
        let page = address & VM_PAGE_MASK;
        let fault = |guard| VmAccessFault {
            address,
            write,
            guard,
        };
        let Some(region) = self.region_containing(address) else {
            return Err(fault(false));
        };
        let Some(state) = region.pages.get(&page) else {
            return Err(fault(false));
        };
        if !state.committed {
            return Err(fault(false));
        }
        if state.guard {
            return Err(fault(true));
        }
        let allowed = (execute && state.protection.execute)
            || (write && state.protection.write)
            || (!execute && !write && state.protection.read);
        if allowed { Ok(()) } else { Err(fault(false)) }
    }

    /// True when the page containing `address` is committed and not a
    /// guard page.
    pub fn is_mapped(&self, address: u64) -> bool {
        let page = address & VM_PAGE_MASK;
        self.region_containing(address)
            .and_then(|region| region.pages.get(&page))
            .is_some_and(|state| state.committed && !state.guard)
    }

    // ── Section-backed file views ────────────────────────────────────────────

    /// Record a section-backed file view at `base` (a committed reservation
    /// created with `reserve` + `commit`).  Returns `false` when `base` is
    /// already a mapped view.
    pub fn map_view(&mut self, base: u64, offset: u64, backing: Arc<Mutex<Vec<u8>>>) -> bool {
        let base = base & VM_PAGE_MASK;
        if self.mappings.contains_key(&base) {
            return false;
        }
        self.mappings.insert(base, VmMapping { offset, backing });
        true
    }

    /// Remove the mapping record of a view (the reservation itself is
    /// released separately via [`Self::release`]).  Returns `false` when
    /// `base` is not a mapped view.
    pub fn unmap_view(&mut self, base: u64) -> bool {
        self.mappings.remove(&(base & VM_PAGE_MASK)).is_some()
    }

    /// The mapping record of a section-backed view at `base`, if any.
    pub fn mapped_view(&self, base: u64) -> Option<&VmMapping> {
        self.mappings.get(&(base & VM_PAGE_MASK))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_commit_query_coherence() {
        let mut vm = VirtualMemory::new(0x7400_0000);
        let base = vm.reserve(None, 0x2000);
        assert_ne!(base, 0);
        assert_eq!(base & VM_PAGE_MASK, base);
        vm.commit(base, 0x2000, VmProtection::READ_WRITE, false);

        let result = vm.query(base);
        assert_eq!(result.base, base);
        assert_eq!(result.region_size, 0x2000);
        assert_eq!(result.state, VmState::Committed);
        assert_eq!(result.protection, VmProtection::READ_WRITE);
        assert_eq!(result.kind, VmRegionKind::Private);
        assert!(!result.guard);

        // The uncommitted tail of the NEXT reservation is Reserved.
        let second = vm.reserve(None, 0x1000);
        assert_eq!(second, base + 0x2000);
        assert_eq!(vm.query(second).state, VmState::Reserved);
        // And past the last reservation everything is Free.
        assert_eq!(vm.query(second + 0x1000).state, VmState::Free);
    }

    #[test]
    fn interior_commit_of_a_reservation() {
        let mut vm = VirtualMemory::new(0x7400_0000);
        let reservation = vm.reserve(Some(0x7400_0000), 0x4000);
        assert_eq!(reservation, 0x7400_0000);
        assert!(vm.can_commit(reservation + 0x1000, 0x2000));
        assert!(
            !vm.can_commit(reservation + 0x3000, 0x2000),
            "past the reservation"
        );

        vm.commit(
            reservation + 0x1000,
            0x2000,
            VmProtection::READ_WRITE,
            false,
        );
        let committed = vm.query(reservation + 0x1000);
        assert_eq!(committed.state, VmState::Committed);
        assert_eq!(committed.region_size, 0x2000);
        assert_eq!(committed.protection, VmProtection::READ_WRITE);
        // Windows: BaseAddress is the START of the coalesced committed run
        // (the first committed page), not the reservation base.
        assert_eq!(committed.base, reservation + 0x1000);

        let tail = vm.query(reservation + 0x3000);
        assert_eq!(tail.state, VmState::Reserved);
        assert_eq!(tail.region_size, 0x1000);
        assert_eq!(tail.protection, VmProtection::NONE);
    }

    #[test]
    fn partial_decommit_leaves_untouched_pages_committed() {
        let mut vm = VirtualMemory::new(0x7400_0000);
        let base = vm.reserve(Some(0x7400_0000), 0x3000);
        vm.commit(base, 0x3000, VmProtection::READ_WRITE, false);

        vm.decommit(base, 0x1000);
        assert_eq!(vm.query(base).state, VmState::Reserved);
        let untouched = vm.query(base + 0x1000);
        assert_eq!(untouched.state, VmState::Committed);
        assert_eq!(untouched.region_size, 0x2000);
        assert_eq!(untouched.protection, VmProtection::READ_WRITE);

        // Decommitting a range that is only partially committed.
        vm.decommit(base + 0x2000, 0x2000);
        assert_eq!(vm.query(base + 0x1000).state, VmState::Committed);
        assert_eq!(vm.query(base + 0x2000).state, VmState::Reserved);
    }

    #[test]
    fn protect_changes_only_the_range_and_reports_old_protection() {
        let mut vm = VirtualMemory::new(0x7400_0000);
        let base = vm.reserve(Some(0x7400_0000), 0x2000);
        vm.commit(base, 0x2000, VmProtection::READ_WRITE, false);

        let old = vm.protect(base, 0x1000, VmProtection::READ);
        assert_eq!(old, Some(VmProtection::READ_WRITE));
        let first = vm.query(base);
        assert_eq!(first.protection, VmProtection::READ);
        assert_eq!(
            first.region_size, 0x1000,
            "coalescing breaks at the protection boundary"
        );
        let second = vm.query(base + 0x1000);
        assert_eq!(second.protection, VmProtection::READ_WRITE);

        // Protecting a range that starts on a reserved page reports None
        // and does not commit it.
        let old = vm.protect(base + 0x1000, 0x2000, VmProtection::READ);
        assert_eq!(old, Some(VmProtection::READ_WRITE));
        vm.decommit(base + 0x1000, 0x1000);
        let old = vm.protect(base + 0x1000, 0x1000, VmProtection::READ);
        assert_eq!(old, None);
        assert_eq!(vm.query(base + 0x1000).state, VmState::Reserved);
    }

    #[test]
    fn query_coalesces_adjacent_same_state_pages() {
        let mut vm = VirtualMemory::new(0x7400_0000);
        let reservation = vm.reserve(Some(0x7400_0000), 0x5000);
        vm.commit(reservation, 0x3000, VmProtection::READ_WRITE, false);

        // The committed run spans the three committed pages.
        let committed = vm.query(reservation);
        assert_eq!(committed.state, VmState::Committed);
        assert_eq!(committed.region_size, 0x3000);
        assert_eq!(committed.base, reservation);
        // A query in the middle of the committed run reports the FULL
        // coalesced run (Windows: BaseAddress + RegionSize describe the
        // whole run containing the queried address).
        let committed = vm.query(reservation + 0x1000);
        assert_eq!(committed.state, VmState::Committed);
        assert_eq!(committed.region_size, 0x3000);
        assert_eq!(committed.base, reservation);

        // The reserved tail run starts at the first uncommitted page and
        // spans to the reservation end.
        let reserved = vm.query(reservation + 0x3000);
        assert_eq!(reserved.state, VmState::Reserved);
        assert_eq!(reserved.region_size, 0x2000);
        assert_eq!(reserved.base, reservation + 0x3000);

        // A query in the middle of the reserved run reports the same
        // coalesced run (base = the run start).
        let reserved = vm.query(reservation + 0x4000);
        assert_eq!(reserved.state, VmState::Reserved);
        assert_eq!(reserved.region_size, 0x2000);
        assert_eq!(reserved.base, reservation + 0x3000);
    }

    #[test]
    fn check_access_faults_on_unmapped_guard_and_write_to_read_only() {
        let mut vm = VirtualMemory::new(0x7400_0000);
        let base = vm.reserve(Some(0x7400_0000), 0x3000);
        vm.commit(base, 0x1000, VmProtection::READ, false);
        vm.commit(base + 0x1000, 0x1000, VmProtection::READ_WRITE, true);

        // Unmapped.
        let fault = vm.check_access(0x1000, false, false).expect_err("unmapped");
        assert_eq!(fault.address, 0x1000);
        assert!(!fault.guard);

        // Reserved page inside a reservation.
        let fault = vm
            .check_access(base + 0x2000, false, false)
            .expect_err("reserved");
        assert_eq!(fault.address, base + 0x2000);
        assert!(!fault.guard);

        // Guard page.
        let fault = vm
            .check_access(base + 0x1000, false, false)
            .expect_err("guard");
        assert!(fault.guard);
        assert_eq!(fault.address, base + 0x1000);

        // Write to a read-only page.
        let fault = vm
            .check_access(base, true, false)
            .expect_err("read-only write");
        assert!(!fault.guard);
        assert!(fault.write);

        // Read from a read-only page succeeds.
        assert!(vm.check_access(base, false, false).is_ok());
        // Execute on a non-executable page faults.
        assert!(vm.check_access(base, false, true).is_err());

        // Write to a writable page succeeds.
        vm.commit(base + 0x1000, 0x1000, VmProtection::READ_WRITE, false);
        assert!(vm.check_access(base + 0x1000, true, false).is_ok());
        // Execute on an executable page succeeds.
        vm.commit(base, 0x1000, VmProtection::READ_EXECUTE, false);
        assert!(vm.check_access(base, false, true).is_ok());

        assert!(vm.is_mapped(base));
        assert!(!vm.is_mapped(base + 0x2000), "reserved page is not mapped");
        assert!(!vm.is_mapped(0x5000), "unmapped address is not mapped");
    }

    #[test]
    fn release_frees_the_whole_reservation_regardless_of_size() {
        let mut vm = VirtualMemory::new(0x7400_0000);
        let base = vm.reserve(Some(0x7400_0000), 0x3000);
        vm.commit(base, 0x1000, VmProtection::READ_WRITE, false);
        assert!(vm.is_mapped(base));

        // The thunk rejects MEM_RELEASE with size != 0; the canonical layer
        // itself releases the region no matter what size the caller would
        // have passed (release has no size parameter).
        assert_eq!(vm.region_size(base), Some(0x3000));
        assert!(vm.release(base));
        assert!(!vm.release(base), "second release of the same base fails");
        assert_eq!(vm.query(base).state, VmState::Free);
        assert!(!vm.is_mapped(base));
        assert!(vm.check_access(base, false, false).is_err());

        // Releasing a base that is not a region base fails.
        let base = vm.reserve(Some(0x7400_0000), 0x1000);
        assert!(!vm.release(base + 0x1000));
        assert_eq!(vm.query(base).state, VmState::Reserved);
    }

    #[test]
    fn reserve_rejects_overlapping_regions_and_regions_may_nest() {
        let mut vm = VirtualMemory::new(0x7400_0000);
        let base = vm.reserve(Some(0x7400_0000), 0x2000);
        assert_eq!(base, 0x7400_0000);
        assert_eq!(
            vm.reserve(Some(0x7400_1000), 0x1000),
            0,
            "interior overlap rejected"
        );
        assert_eq!(
            vm.reserve(Some(0x7400_2000), 0x1000),
            0x7400_2000,
            "adjacent OK"
        );

        // register() allows nesting: a synthetic module image inside the
        // growing CRT data area resolves to the innermost region.
        vm.register(0x7300_0000, 0x1000, VmRegionKind::Heap);
        vm.register(0x7300_0000, 0x3000, VmRegionKind::Heap);
        assert_eq!(
            vm.region_size(0x7300_0000),
            Some(0x3000),
            "register grows the region"
        );
        vm.register(0x7300_1000, 0x1000, VmRegionKind::Image);
        vm.commit(0x7300_1000, 0x1000, VmProtection::READ, false);
        assert!(vm.check_access(0x7300_1000, false, false).is_ok());
        let query = vm.query(0x7300_1000);
        assert_eq!(query.kind, VmRegionKind::Image, "innermost region wins");
        assert!(
            vm.check_access(0x7300_2000, false, false).is_err(),
            "outer heap area still reserved"
        );
    }
}
