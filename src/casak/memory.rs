//! Virtual-memory, section and MDL executive for CasaK.
//!
//! The manager implements real reservation/commit/decommit/protection state,
//! page-level residency accounting, section objects backed by real bytes,
//! shared and copy-on-write mapped views, and an MDL table whose locks are
//! validated against the committed mapping state.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::casak::status::{
    STATUS_ACCESS_VIOLATION, STATUS_ALREADY_COMMITTED, STATUS_COMMITMENT_LIMIT,
    STATUS_CONFLICTING_ADDRESSES, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_ADDRESS,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER,
    STATUS_INVALID_VIEW_SIZE, STATUS_NO_MEMORY, STATUS_NOT_COMMITTED, STATUS_SECTION_TOO_BIG,
};

/// The granularity of every VM operation.
pub const PAGE_SIZE: u64 = 4096;
/// Largest single section the executive accepts.
pub const MAX_SECTION_SIZE: u64 = 256 * 1024 * 1024;
/// Largest single reservation accepted.
pub const MAX_REGION_SIZE: u64 = 1 << 32;
const DEFAULT_BASE: u64 = 0x1_0000;
const USER_LIMIT: u64 = 0x7FFF_FFFF_0000;

/// A page protection mask (`PAGE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Protection(pub u32);

impl Protection {
    pub const NOACCESS: Protection = Protection(0x01);
    pub const READONLY: Protection = Protection(0x02);
    pub const READWRITE: Protection = Protection(0x04);
    pub const EXECUTE: Protection = Protection(0x10);
    pub const EXECUTE_READ: Protection = Protection(0x20);
    pub const EXECUTE_READWRITE: Protection = Protection(0x40);

    pub const fn bits(self) -> u32 {
        self.0
    }

    fn valid(self) -> bool {
        matches!(
            self,
            Self::NOACCESS
                | Self::READONLY
                | Self::READWRITE
                | Self::EXECUTE
                | Self::EXECUTE_READ
                | Self::EXECUTE_READWRITE
        )
    }

    pub const fn readable(self) -> bool {
        matches!(
            self,
            Self::READONLY | Self::READWRITE | Self::EXECUTE_READ | Self::EXECUTE_READWRITE
        )
    }

    pub const fn writable(self) -> bool {
        matches!(self, Self::READWRITE | Self::EXECUTE_READWRITE)
    }
}

/// Where the backing bytes of a mapped view come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewKind {
    Image,
    Data,
    Pagefile,
}

/// A section object backed by real bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub id: SectionId,
    pub kind: ViewKind,
    pub size: u64,
    backing: Vec<u8>,
}

/// Monotonic section identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SectionId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mapping {
    section: SectionId,
    offset: u64,
    cow: bool,
}

#[derive(Debug, Clone)]
struct Vad {
    base: u64,
    size: u64,
    protection: Protection,
    pages: BTreeMap<u64, Protection>,
    private: BTreeMap<u64, Vec<u8>>,
    mapping: Option<Mapping>,
}

impl Vad {
    fn end(&self) -> u64 {
        self.base + self.size
    }
}

/// VM state reported by [`MemoryManager::query`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryState {
    Reserved,
    Committed,
}

/// A memory-region query result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryInfo {
    pub base: u64,
    pub size: u64,
    pub protection: Protection,
    pub state: MemoryState,
    pub mapped: Option<SectionId>,
}

/// The VM manager.
#[derive(Debug)]
pub struct MemoryManager {
    page_size: u64,
    vads: BTreeMap<u64, Vad>,
    sections: BTreeMap<SectionId, Section>,
    next_section: u64,
    next_base: u64,
    committed_bytes: u64,
    mapped_bytes: u64,
    max_commit: u64,
    max_sections: usize,
    resident: BTreeSet<u64>,
    resident_order: VecDeque<u64>,
    max_working_set: usize,
}

impl MemoryManager {
    /// Creates a manager with a commit budget, section cap and working-set
    /// cap (all in pages for the working set).
    pub fn new(max_commit: u64, max_sections: usize, max_working_set: usize) -> Self {
        Self {
            page_size: PAGE_SIZE,
            vads: BTreeMap::new(),
            sections: BTreeMap::new(),
            next_section: 1,
            next_base: DEFAULT_BASE,
            committed_bytes: 0,
            mapped_bytes: 0,
            max_commit,
            max_sections,
            resident: BTreeSet::new(),
            resident_order: VecDeque::new(),
            max_working_set,
        }
    }

    pub fn page_size(&self) -> u64 {
        self.page_size
    }

    pub fn committed_bytes(&self) -> u64 {
        self.committed_bytes
    }

    pub fn mapped_bytes(&self) -> u64 {
        self.mapped_bytes
    }

    pub fn reserved_count(&self) -> usize {
        self.vads.len()
    }

    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    pub fn working_set_pages(&self) -> usize {
        self.resident.len()
    }

    /// Reserves `size` bytes at `base` (or at the next free address).  The
    /// result is page-aligned and contains no committed pages.
    pub fn reserve(&mut self, base: Option<u64>, size: u64) -> Result<u64, i32> {
        if size == 0 || size > MAX_REGION_SIZE {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let size = align_up(size, self.page_size).ok_or(STATUS_INVALID_PARAMETER)?;
        let base = match base {
            Some(base) => {
                if base == 0 || base % self.page_size != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                if self.overlaps(base, size) {
                    return Err(STATUS_CONFLICTING_ADDRESSES);
                }
                base
            }
            None => self.find_free_base(size)?,
        };
        let end = base.checked_add(size).ok_or(STATUS_INVALID_PARAMETER)?;
        if end > USER_LIMIT {
            return Err(STATUS_NO_MEMORY);
        }
        self.vads.insert(
            base,
            Vad {
                base,
                size,
                protection: Protection::READWRITE,
                pages: BTreeMap::new(),
                private: BTreeMap::new(),
                mapping: None,
            },
        );
        self.next_base = self.next_base.max(end);
        Ok(base)
    }

    /// Commits a range inside one reservation.  A partially committed range
    /// is rejected atomically with `STATUS_ALREADY_COMMITTED`.
    pub fn commit(&mut self, base: u64, size: u64, protection: Protection) -> Result<(), i32> {
        if !protection.valid() {
            return Err(STATUS_INVALID_PAGE_PROTECTION);
        }
        let range = self.validate_range(base, size)?;
        let (vad_base, existing) = {
            let vad = self.find_vad(range.0)?;
            if vad.mapping.is_some() {
                return Err(STATUS_ALREADY_COMMITTED);
            }
            let overlap = range_pages(range)
                .filter(|page| vad.pages.contains_key(page))
                .count();
            (vad.base, overlap)
        };
        if existing != 0 {
            return Err(STATUS_ALREADY_COMMITTED);
        }
        let pages = range_pages(range).count() as u64;
        let charge = pages
            .checked_mul(self.page_size)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if self.committed_bytes.saturating_add(charge) > self.max_commit {
            return Err(STATUS_COMMITMENT_LIMIT);
        }
        let vad = self
            .vads
            .get_mut(&vad_base)
            .expect("commit resolves a reserved VAD");
        for page in range_pages(range) {
            vad.pages.insert(page, protection);
            vad.private.insert(page, vec![0; self.page_size as usize]);
        }
        vad.protection = protection;
        self.committed_bytes += charge;
        Ok(())
    }

    /// Decommits a committed range.  Ranges with no committed pages fail with
    /// `STATUS_NOT_COMMITTED` and leave the reservation unchanged.
    pub fn decommit(&mut self, base: u64, size: u64) -> Result<(), i32> {
        let range = self.validate_range(base, size)?;
        let (vad_base, committed) = {
            let vad = self.find_vad(range.0)?;
            if vad.mapping.is_some() {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let committed = range_pages(range)
                .filter(|page| vad.pages.contains_key(page))
                .count();
            if committed == 0 {
                return Err(STATUS_NOT_COMMITTED);
            }
            (vad.base, committed as u64)
        };
        let vad = self
            .vads
            .get_mut(&vad_base)
            .expect("decommit resolves a reserved VAD");
        for page in range_pages(range) {
            vad.pages.remove(&page);
            vad.private.remove(&page);
            self.resident.remove(&page);
            self.resident_order.retain(|candidate| *candidate != page);
        }
        self.committed_bytes = self
            .committed_bytes
            .saturating_sub(committed * self.page_size);
        Ok(())
    }

    /// Applies `protection` to a committed range and returns the affected page
    /// count.  Uncommitted private pages fail with `STATUS_NOT_COMMITTED`.
    pub fn protect(&mut self, base: u64, size: u64, protection: Protection) -> Result<usize, i32> {
        if !protection.valid() {
            return Err(STATUS_INVALID_PAGE_PROTECTION);
        }
        let range = self.validate_range(base, size)?;
        let vad_base = self.find_vad(range.0)?.base;
        let vad = self
            .vads
            .get(&vad_base)
            .expect("protect resolves a reserved VAD");
        for page in range_pages(range) {
            if !vad.pages.contains_key(&page) {
                return Err(STATUS_NOT_COMMITTED);
            }
        }
        let count = range_pages(range).count();
        let vad = self
            .vads
            .get_mut(&vad_base)
            .expect("protect resolves a reserved VAD");
        vad.protection = protection;
        for page in range_pages(range) {
            vad.pages.insert(page, protection);
        }
        Ok(count)
    }

    /// Releases a whole reservation.  `size` must be zero or the exact
    /// reservation size; interior release is rejected.
    pub fn release(&mut self, base: u64, size: u64) -> Result<u64, i32> {
        let vad = self.vads.get(&base).ok_or(STATUS_INVALID_ADDRESS)?;
        if size != 0 && size != vad.size {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let released = vad.size;
        let committed = vad.pages.len() as u64 * self.page_size;
        let mapped = if vad.mapping.is_some() { vad.size } else { 0 };
        let pages: Vec<u64> = vad.pages.keys().copied().collect();
        self.vads.remove(&base);
        self.committed_bytes = self.committed_bytes.saturating_sub(committed);
        self.mapped_bytes = self.mapped_bytes.saturating_sub(mapped);
        for page in pages {
            self.resident.remove(&page);
            self.resident_order.retain(|candidate| *candidate != page);
        }
        Ok(released)
    }

    /// Queries the region containing `address`.
    pub fn query(&self, address: u64) -> Result<MemoryInfo, i32> {
        let vad = self.find_vad(address)?;
        Ok(MemoryInfo {
            base: vad.base,
            size: vad.size,
            protection: vad.protection,
            state: if vad.pages.is_empty() {
                MemoryState::Reserved
            } else {
                MemoryState::Committed
            },
            mapped: vad.mapping.map(|mapping| mapping.section),
        })
    }

    /// Copies bytes out of the virtual address space, faulting on reserved,
    /// decommitted or read-protected pages.
    pub fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, i32> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let end = address
            .checked_add(length as u64)
            .ok_or(STATUS_INVALID_ADDRESS)?;
        self.check_access(address, end, false)?;
        let vad_base = self.find_vad(address)?.base;
        let mut output = Vec::with_capacity(length);
        let mut cursor = address;
        while cursor < end {
            let page = (cursor / self.page_size) * self.page_size;
            let offset = (cursor % self.page_size) as usize;
            let take = ((self.page_size as usize) - offset).min((end - cursor) as usize);
            output.extend_from_slice(&self.page_bytes(vad_base, page)?[offset..offset + take]);
            self.touch(page);
            cursor += take as u64;
        }
        Ok(output)
    }

    /// Copies bytes into the virtual address space, applying COW for mapped
    /// views and faulting on read-only/uncommitted pages.
    pub fn write(&mut self, address: u64, data: &[u8]) -> Result<(), i32> {
        if data.is_empty() {
            return Ok(());
        }
        let end = address
            .checked_add(data.len() as u64)
            .ok_or(STATUS_INVALID_ADDRESS)?;
        self.check_access(address, end, true)?;
        let vad_base = self.find_vad(address)?.base;
        let mut cursor = address;
        let mut written = 0;
        while cursor < end {
            let page = (cursor / self.page_size) * self.page_size;
            let offset = (cursor % self.page_size) as usize;
            let take = ((self.page_size as usize) - offset).min(data.len() - written);
            self.write_page(vad_base, page, offset, &data[written..written + take])?;
            self.touch(page);
            cursor += take as u64;
            written += take;
        }
        Ok(())
    }

    /// Reads the backing bytes of a section.
    pub fn section_bytes(
        &self,
        section: SectionId,
        offset: usize,
        length: usize,
    ) -> Result<&[u8], i32> {
        let record = self.sections.get(&section).ok_or(STATUS_INVALID_HANDLE)?;
        let end = offset.checked_add(length).ok_or(STATUS_INVALID_PARAMETER)?;
        record
            .backing
            .get(offset..end)
            .ok_or(STATUS_INVALID_PARAMETER)
    }

    /// Creates a section object.  `initial` must fit inside `size`.
    pub fn create_section(
        &mut self,
        kind: ViewKind,
        size: u64,
        initial: &[u8],
    ) -> Result<SectionId, i32> {
        if size == 0 || initial.len() as u64 > size {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if size > MAX_SECTION_SIZE {
            return Err(STATUS_SECTION_TOO_BIG);
        }
        if self.sections.len() >= self.max_sections {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let id = SectionId(self.next_section);
        self.next_section += 1;
        let mut backing = vec![0; size as usize];
        backing[..initial.len()].copy_from_slice(initial);
        self.sections.insert(
            id,
            Section {
                id,
                kind,
                size,
                backing,
            },
        );
        Ok(id)
    }

    /// Deletes a section that has no mapped views.
    pub fn delete_section(&mut self, section: SectionId) -> Result<(), i32> {
        if self.vads.values().any(|vad| {
            vad.mapping
                .is_some_and(|mapping| mapping.section == section)
        }) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.sections
            .remove(&section)
            .map(|_| ())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Maps a section view.  `cow` views copy a page on its first write while
    /// shared views write through to the section backing.
    pub fn map_section(
        &mut self,
        section: SectionId,
        base: Option<u64>,
        size: u64,
        protection: Protection,
        cow: bool,
    ) -> Result<u64, i32> {
        if !protection.valid() {
            return Err(STATUS_INVALID_PAGE_PROTECTION);
        }
        let record = self.sections.get(&section).ok_or(STATUS_INVALID_HANDLE)?;
        if size == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if size > record.size {
            return Err(STATUS_INVALID_VIEW_SIZE);
        }
        let aligned = align_up(size, self.page_size).ok_or(STATUS_INVALID_PARAMETER)?;
        if aligned > record.size {
            return Err(STATUS_INVALID_VIEW_SIZE);
        }
        let base = self.reserve(base, aligned)?;
        let pages: Vec<u64> = (0..aligned / self.page_size)
            .map(|index| base + index * self.page_size)
            .collect();
        let vad = self
            .vads
            .get_mut(&base)
            .expect("map_section reserves its view base");
        vad.protection = protection;
        for page in &pages {
            vad.pages.insert(*page, protection);
        }
        vad.mapping = Some(Mapping {
            section,
            offset: 0,
            cow,
        });
        self.mapped_bytes += aligned;
        Ok(base)
    }

    /// Unmaps a mapped view created by [`Self::map_section`].
    pub fn unmap_section(&mut self, base: u64) -> Result<u64, i32> {
        let mapped = self
            .vads
            .get(&base)
            .ok_or(STATUS_INVALID_ADDRESS)?
            .mapping
            .is_some();
        if !mapped {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.release(base, 0)
    }

    /// Trims the resident set to at most `target` pages and returns the number
    /// of pages evicted.
    pub fn trim_working_set(&mut self, target: usize) -> usize {
        let mut evicted = 0;
        while self.resident.len() > target {
            let page = self
                .resident_order
                .pop_front()
                .expect("resident order tracks the resident set");
            self.resident.remove(&page);
            evicted += 1;
        }
        evicted
    }

    fn touch(&mut self, page: u64) {
        if self.resident.insert(page) {
            self.resident_order.push_back(page);
            while self.resident.len() > self.max_working_set {
                let victim = self
                    .resident_order
                    .pop_front()
                    .expect("resident order tracks the resident set");
                self.resident.remove(&victim);
            }
        }
    }

    fn check_access(&self, start: u64, end: u64, write: bool) -> Result<(), i32> {
        let vad = self.find_vad(start)?;
        if end > vad.end() {
            return Err(STATUS_INVALID_ADDRESS);
        }
        for page in range_pages((start, end)) {
            let protection = *vad.pages.get(&page).ok_or(STATUS_ACCESS_VIOLATION)?;
            if write {
                if !protection.writable() {
                    return Err(STATUS_ACCESS_VIOLATION);
                }
            } else if !protection.readable() {
                return Err(STATUS_ACCESS_VIOLATION);
            }
        }
        Ok(())
    }

    fn page_bytes(&self, vad_base: u64, page: u64) -> Result<Vec<u8>, i32> {
        let vad = self.vads.get(&vad_base).ok_or(STATUS_INVALID_ADDRESS)?;
        if let Some(private) = vad.private.get(&page) {
            return Ok(private.clone());
        }
        let mapping = vad
            .mapping
            .expect("a page outside the private map belongs to a section view");
        let section = self
            .sections
            .get(&mapping.section)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let start = mapping.offset as usize + (page - vad.base) as usize;
        Ok(section.backing[start..start + self.page_size as usize].to_vec())
    }

    fn write_page(
        &mut self,
        vad_base: u64,
        page: u64,
        offset: usize,
        data: &[u8],
    ) -> Result<(), i32> {
        let mapping = self
            .vads
            .get(&vad_base)
            .ok_or(STATUS_INVALID_ADDRESS)?
            .mapping;
        match mapping {
            Some(mapping) if mapping.cow => {
                let source = self.page_bytes(vad_base, page)?;
                let vad = self.vads.get_mut(&vad_base).ok_or(STATUS_INVALID_ADDRESS)?;
                let target = vad.private.entry(page).or_insert_with(|| source.clone());
                target[offset..offset + data.len()].copy_from_slice(data);
                Ok(())
            }
            Some(mapping) => {
                let start = mapping.offset as usize + (page - vad_base) as usize + offset;
                let section = self
                    .sections
                    .get_mut(&mapping.section)
                    .ok_or(STATUS_INVALID_HANDLE)?;
                let target = section
                    .backing
                    .get_mut(start..start + data.len())
                    .ok_or(STATUS_INVALID_ADDRESS)?;
                target.copy_from_slice(data);
                Ok(())
            }
            None => {
                let vad = self.vads.get_mut(&vad_base).ok_or(STATUS_INVALID_ADDRESS)?;
                let target = vad
                    .private
                    .get_mut(&page)
                    .expect("committed private pages own backing bytes");
                target[offset..offset + data.len()].copy_from_slice(data);
                Ok(())
            }
        }
    }

    fn validate_range(&self, base: u64, size: u64) -> Result<(u64, u64), i32> {
        if base == 0 || size == 0 || base % self.page_size != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let aligned = align_up(size, self.page_size).ok_or(STATUS_INVALID_PARAMETER)?;
        let end = base.checked_add(aligned).ok_or(STATUS_INVALID_PARAMETER)?;
        let vad = self.find_vad(base)?;
        if end > vad.end() {
            return Err(STATUS_INVALID_ADDRESS);
        }
        Ok((base, end))
    }

    fn find_vad(&self, address: u64) -> Result<&Vad, i32> {
        let (_, vad) = self
            .vads
            .range(..=address)
            .next_back()
            .ok_or(STATUS_INVALID_ADDRESS)?;
        if address >= vad.end() {
            return Err(STATUS_INVALID_ADDRESS);
        }
        Ok(vad)
    }

    fn overlaps(&self, base: u64, size: u64) -> bool {
        let end = base.saturating_add(size);
        self.vads
            .values()
            .any(|vad| base < vad.end() && vad.base < end)
    }

    fn find_free_base(&mut self, size: u64) -> Result<u64, i32> {
        let mut candidate = self.next_base;
        loop {
            let end = candidate
                .checked_add(size)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            if end > USER_LIMIT {
                return Err(STATUS_NO_MEMORY);
            }
            if let Some(vad) = self
                .vads
                .range(..end)
                .next_back()
                .map(|(_, vad)| vad)
                .filter(|vad| vad.end() > candidate)
            {
                candidate = vad.end();
                continue;
            }
            self.next_base = end;
            return Ok(candidate);
        }
    }
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::new(64 * 1024 * 1024, 64, 64)
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment - 1;
    value.checked_add(mask).map(|value| value & !mask)
}

fn range_pages(range: (u64, u64)) -> impl Iterator<Item = u64> {
    let first = range.0 / PAGE_SIZE;
    let last = (range.1 + PAGE_SIZE - 1) / PAGE_SIZE;
    (first..last).map(|index| index * PAGE_SIZE)
}

/// Monotonic MDL identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MdlId(pub u64);

/// A locked memory descriptor list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mdl {
    pub id: MdlId,
    pub virtual_address: u64,
    pub byte_count: usize,
    pub write_access: bool,
    pub locked: bool,
    pub page_count: usize,
}

/// MDL table with real lock accounting.
#[derive(Debug)]
pub struct MdlTable {
    mdls: BTreeMap<MdlId, Mdl>,
    next_id: u64,
    locked_pages: usize,
    peak_locked_pages: usize,
}

impl MdlTable {
    pub fn new() -> Self {
        Self {
            mdls: BTreeMap::new(),
            next_id: 1,
            locked_pages: 0,
            peak_locked_pages: 0,
        }
    }

    /// Allocates an MDL after validating that the range is committed.  A
    /// zero/oversized request is rejected without touching the table.
    pub fn allocate(
        &mut self,
        memory: &MemoryManager,
        virtual_address: u64,
        byte_count: usize,
        write_access: bool,
    ) -> Result<MdlId, i32> {
        if byte_count == 0 || byte_count > u32::MAX as usize {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let end = virtual_address
            .checked_add(byte_count as u64)
            .ok_or(STATUS_INVALID_ADDRESS)?;
        memory.check_access(virtual_address, end, write_access)?;
        let pages = ((virtual_address % PAGE_SIZE) as usize + byte_count + PAGE_SIZE as usize - 1)
            / PAGE_SIZE as usize;
        let id = MdlId(self.next_id);
        self.next_id += 1;
        self.mdls.insert(
            id,
            Mdl {
                id,
                virtual_address,
                byte_count,
                write_access,
                locked: false,
                page_count: pages,
            },
        );
        Ok(id)
    }

    /// Locks an MDL, charging its pages.  Double locking fails with
    /// `STATUS_INVALID_DEVICE_STATE`; a write lock requires writable backing.
    pub fn probe_and_lock(
        &mut self,
        memory: &MemoryManager,
        id: MdlId,
        write_access: bool,
    ) -> Result<(), i32> {
        let record = *self.mdls.get(&id).ok_or(STATUS_INVALID_HANDLE)?;
        if record.locked {
            return Err(crate::casak::status::STATUS_INVALID_DEVICE_STATE);
        }
        if write_access && !record.write_access {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let end = record
            .virtual_address
            .checked_add(record.byte_count as u64)
            .ok_or(STATUS_INVALID_ADDRESS)?;
        memory.check_access(record.virtual_address, end, write_access)?;
        if let Some(entry) = self.mdls.get_mut(&id) {
            entry.locked = true;
        }
        self.locked_pages += record.page_count;
        self.peak_locked_pages = self.peak_locked_pages.max(self.locked_pages);
        Ok(())
    }

    /// Unlocks a locked MDL.
    pub fn unlock(&mut self, id: MdlId) -> Result<(), i32> {
        let record = *self.mdls.get(&id).ok_or(STATUS_INVALID_HANDLE)?;
        if !record.locked {
            return Err(crate::casak::status::STATUS_INVALID_DEVICE_STATE);
        }
        if let Some(entry) = self.mdls.get_mut(&id) {
            entry.locked = false;
        }
        self.locked_pages = self.locked_pages.saturating_sub(record.page_count);
        Ok(())
    }

    /// Frees an unlocked MDL.  Freeing a locked MDL is rejected.
    pub fn free(&mut self, id: MdlId) -> Result<(), i32> {
        let record = *self.mdls.get(&id).ok_or(STATUS_INVALID_HANDLE)?;
        if record.locked {
            return Err(crate::casak::status::STATUS_INVALID_DEVICE_STATE);
        }
        self.mdls.remove(&id);
        Ok(())
    }

    pub fn query(&self, id: MdlId) -> Result<Mdl, i32> {
        self.mdls.get(&id).copied().ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn locked_pages(&self) -> usize {
        self.locked_pages
    }

    pub fn peak_locked_pages(&self) -> usize {
        self.peak_locked_pages
    }

    pub fn len(&self) -> usize {
        self.mdls.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mdls.is_empty()
    }
}

impl Default for MdlTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casak::status::STATUS_INVALID_DEVICE_STATE;

    fn committed_manager(pages: u64) -> (MemoryManager, u64) {
        let mut manager = MemoryManager::new(4 * PAGE_SIZE * pages, 4, 4);
        let base = manager
            .reserve(Some(DEFAULT_BASE), pages * PAGE_SIZE)
            .unwrap();
        manager
            .commit(base, pages * PAGE_SIZE, Protection::READWRITE)
            .unwrap();
        (manager, base)
    }

    #[test]
    fn reserve_rejects_invalid_sizes_alignments_and_overlaps() {
        assert_eq!(MemoryManager::default().committed_bytes(), 0);
        assert!(MdlTable::default().is_empty());
        assert_eq!(Protection::READONLY.bits(), 2);
        assert_eq!(Protection::READONLY.readable(), true);
        assert_eq!(Protection::EXECUTE.readable(), false);
        assert_eq!(Protection::READONLY.writable(), false);
        let mut manager = MemoryManager::new(64 * PAGE_SIZE, 2, 4);
        assert_eq!(manager.reserve(None, 0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            manager.reserve(None, MAX_REGION_SIZE + 1),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.reserve(Some(PAGE_SIZE + 1), PAGE_SIZE),
            Err(STATUS_INVALID_PARAMETER)
        );
        let _base = manager.reserve(Some(DEFAULT_BASE), PAGE_SIZE).unwrap();
        assert_eq!(
            manager.reserve(Some(DEFAULT_BASE), PAGE_SIZE),
            Err(STATUS_CONFLICTING_ADDRESSES)
        );
        assert_eq!(
            manager.reserve(Some(u64::MAX & !(PAGE_SIZE - 1)), PAGE_SIZE),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.reserve(Some(USER_LIMIT), PAGE_SIZE),
            Err(STATUS_NO_MEMORY)
        );
        assert_eq!(manager.reserved_count(), 1);
        assert_eq!(manager.page_size(), PAGE_SIZE);
        assert_eq!(manager.query(_base).unwrap().state, MemoryState::Reserved);

        let mut limited = MemoryManager::new(64 * PAGE_SIZE, 2, 4);
        limited.next_base = USER_LIMIT - PAGE_SIZE + 1;
        assert_eq!(limited.reserve(None, PAGE_SIZE), Err(STATUS_NO_MEMORY));

        let mut gapped = MemoryManager::new(64 * PAGE_SIZE, 2, 4);
        let first = gapped.reserve(Some(DEFAULT_BASE), PAGE_SIZE).unwrap();
        gapped.next_base = first;
        let second = gapped.reserve(None, PAGE_SIZE * 2).unwrap();
        assert_eq!(second, first + PAGE_SIZE);
    }

    #[test]
    fn commit_and_decommit_boundaries_are_exact() {
        let mut manager = MemoryManager::new(4 * PAGE_SIZE, 4, 8);
        let base = manager.reserve(None, 3 * PAGE_SIZE).unwrap();
        assert_eq!(
            manager.commit(base, PAGE_SIZE, Protection(0x80)),
            Err(STATUS_INVALID_PAGE_PROTECTION)
        );
        assert_eq!(
            manager.commit(base, 0, Protection::READWRITE),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.commit(base + 1, PAGE_SIZE, Protection::READWRITE),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.commit(base, 4 * PAGE_SIZE, Protection::READWRITE),
            Err(STATUS_INVALID_ADDRESS)
        );
        assert_eq!(
            manager.commit(base, PAGE_SIZE, Protection::READWRITE),
            Ok(())
        );
        assert_eq!(
            manager.commit(base, PAGE_SIZE, Protection::READWRITE),
            Err(STATUS_ALREADY_COMMITTED)
        );
        assert_eq!(
            manager.commit(base, 2 * PAGE_SIZE, Protection::READWRITE),
            Err(STATUS_ALREADY_COMMITTED)
        );
        assert_eq!(manager.committed_bytes(), PAGE_SIZE);

        assert_eq!(manager.decommit(base, PAGE_SIZE), Ok(()));
        assert_eq!(manager.committed_bytes(), 0);
        assert_eq!(manager.decommit(base, PAGE_SIZE), Err(STATUS_NOT_COMMITTED));
        assert_eq!(
            manager.decommit(base + 1, PAGE_SIZE),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(manager.decommit(base, 0), Err(STATUS_INVALID_PARAMETER));
        manager
            .commit(base, 2 * PAGE_SIZE, Protection::READWRITE)
            .unwrap();
        assert_eq!(manager.decommit(base + PAGE_SIZE, PAGE_SIZE), Ok(()));
        assert_eq!(manager.committed_bytes(), PAGE_SIZE);
    }

    #[test]
    fn commit_limit_exhaustion_is_atomic() {
        let mut manager = MemoryManager::new(PAGE_SIZE, 1, 4);
        let base = manager.reserve(None, 2 * PAGE_SIZE).unwrap();
        assert_eq!(
            manager.commit(base, 2 * PAGE_SIZE, Protection::READWRITE),
            Err(STATUS_COMMITMENT_LIMIT)
        );
        assert_eq!(manager.committed_bytes(), 0);
        assert_eq!(
            manager.commit(base, PAGE_SIZE, Protection::READWRITE),
            Ok(())
        );
        assert_eq!(
            manager.commit(base + PAGE_SIZE, PAGE_SIZE, Protection::READWRITE),
            Err(STATUS_COMMITMENT_LIMIT)
        );
    }

    #[test]
    fn protect_rejects_invalid_and_uncommitted_ranges() {
        let mut manager = MemoryManager::new(4 * PAGE_SIZE, 4, 8);
        let base = manager.reserve(None, 2 * PAGE_SIZE).unwrap();
        assert_eq!(
            manager.protect(base, PAGE_SIZE, Protection(0x80)),
            Err(STATUS_INVALID_PAGE_PROTECTION)
        );
        assert_eq!(
            manager.protect(base, PAGE_SIZE, Protection::READONLY),
            Err(STATUS_NOT_COMMITTED)
        );
        manager
            .commit(base, PAGE_SIZE, Protection::READWRITE)
            .unwrap();
        assert_eq!(
            manager.protect(base, 2 * PAGE_SIZE, Protection::READONLY),
            Err(STATUS_NOT_COMMITTED)
        );
        assert_eq!(
            manager.protect(base, PAGE_SIZE, Protection::READONLY),
            Ok(1)
        );
        assert_eq!(
            manager.query(base).unwrap().protection,
            Protection::READONLY
        );
        assert_eq!(
            manager.release(base, PAGE_SIZE),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(manager.release(base, 0), Ok(2 * PAGE_SIZE));
        assert_eq!(manager.release(base, 0), Err(STATUS_INVALID_ADDRESS));
    }

    #[test]
    fn read_write_faults_on_reserved_readonly_and_cross_vad_ranges() {
        let mut manager = MemoryManager::new(4 * PAGE_SIZE, 4, 8);
        let first = manager.reserve(Some(DEFAULT_BASE), PAGE_SIZE).unwrap();
        assert_eq!(manager.read(first, 1), Err(STATUS_ACCESS_VIOLATION));
        manager
            .commit(first, PAGE_SIZE, Protection::READONLY)
            .unwrap();
        assert_eq!(
            manager.write(first, std::slice::from_ref(&1_u8)),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(manager.write(first, &[]), Ok(()));
        assert_eq!(manager.read(first, 0).unwrap(), Vec::<u8>::new());
        let second = manager.reserve(Some(first + PAGE_SIZE), PAGE_SIZE).unwrap();
        manager
            .commit(second, PAGE_SIZE, Protection::READWRITE)
            .unwrap();
        assert_eq!(
            manager.read(first, PAGE_SIZE as usize + 1),
            Err(STATUS_INVALID_ADDRESS)
        );
        assert_eq!(
            manager.write(first, &[0; PAGE_SIZE as usize + 1]),
            Err(STATUS_INVALID_ADDRESS)
        );
        assert_eq!(manager.read(u64::MAX, 2), Err(STATUS_INVALID_ADDRESS));
        manager
            .protect(first, PAGE_SIZE, Protection::READWRITE)
            .unwrap();
        manager.write(first + 3, &[1, 2, 3, 4]).unwrap();
        assert_eq!(
            manager.read(first, 8).unwrap(),
            vec![0, 0, 0, 1, 2, 3, 4, 0]
        );
        assert_eq!(manager.query(first).unwrap().state, MemoryState::Committed);
        assert_eq!(manager.query(second).unwrap().base, second);
        assert_eq!(
            manager.query(USER_LIMIT - PAGE_SIZE),
            Err(STATUS_INVALID_ADDRESS)
        );
        let no_access = manager.reserve(None, PAGE_SIZE).unwrap();
        manager
            .commit(no_access, PAGE_SIZE, Protection::NOACCESS)
            .unwrap();
        assert_eq!(manager.read(no_access, 1), Err(STATUS_ACCESS_VIOLATION));
        manager.release(no_access, 0).unwrap();
    }

    #[test]
    fn section_creation_and_delete_reject_invalid_inputs() {
        let mut manager = MemoryManager::new(64 * PAGE_SIZE, 1, 8);
        assert_eq!(
            manager.create_section(ViewKind::Data, 0, &[]),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.create_section(ViewKind::Data, 4, &[1, 2, 3, 4, 5]),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.create_section(ViewKind::Data, MAX_SECTION_SIZE + 1, &[]),
            Err(STATUS_SECTION_TOO_BIG)
        );
        let section = manager
            .create_section(ViewKind::Data, 2 * PAGE_SIZE, &[9, 8, 7])
            .unwrap();
        assert_eq!(
            manager.create_section(ViewKind::Data, PAGE_SIZE, &[]),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(manager.section_count(), 1);
        assert_eq!(manager.section_bytes(section, 0, 3).unwrap(), &[9, 8, 7]);
        assert_eq!(
            manager.section_bytes(section, 2 * PAGE_SIZE as usize, 1),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.section_bytes(SectionId(404), 0, 1),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.map_section(section, None, 0, Protection::READWRITE, false),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.map_section(section, None, PAGE_SIZE, Protection(0x80), false),
            Err(STATUS_INVALID_PAGE_PROTECTION)
        );
        assert_eq!(
            manager.map_section(
                section,
                None,
                2 * PAGE_SIZE + 1,
                Protection::READWRITE,
                false
            ),
            Err(STATUS_INVALID_VIEW_SIZE)
        );
        assert_eq!(
            manager.map_section(
                SectionId(404),
                None,
                PAGE_SIZE,
                Protection::READWRITE,
                false
            ),
            Err(STATUS_INVALID_HANDLE)
        );
        let mut short = MemoryManager::new(64 * PAGE_SIZE, 2, 8);
        let short_section = short.create_section(ViewKind::Data, 100, &[]).unwrap();
        assert_eq!(
            short.map_section(short_section, None, 100, Protection::READWRITE, false),
            Err(STATUS_INVALID_VIEW_SIZE)
        );
        let plain = short.reserve(None, PAGE_SIZE).unwrap();
        assert_eq!(short.unmap_section(plain), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            manager.unmap_section(DEFAULT_BASE),
            Err(STATUS_INVALID_ADDRESS)
        );
        let view = manager
            .map_section(section, None, PAGE_SIZE, Protection::READWRITE, false)
            .unwrap();
        assert_eq!(
            manager.unmap_section(view + PAGE_SIZE),
            Err(STATUS_INVALID_ADDRESS)
        );
        assert_eq!(
            manager.map_section(section, Some(view), PAGE_SIZE, Protection::READWRITE, false),
            Err(STATUS_CONFLICTING_ADDRESSES)
        );
        assert_eq!(
            manager.delete_section(section),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(manager.unmap_section(view), Ok(PAGE_SIZE));
        assert_eq!(manager.delete_section(section), Ok(()));
        assert_eq!(manager.delete_section(section), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn shared_views_never_alias_cow_and_invalid_unmaps_reject() {
        let mut manager = MemoryManager::new(64 * PAGE_SIZE, 4, 8);
        let section = manager
            .create_section(ViewKind::Image, 2 * PAGE_SIZE, &[1, 2, 3, 4])
            .unwrap();
        let shared_a = manager
            .map_section(section, None, 2 * PAGE_SIZE, Protection::READWRITE, false)
            .unwrap();
        let shared_b = manager
            .map_section(section, None, 2 * PAGE_SIZE, Protection::READWRITE, false)
            .unwrap();
        let cow = manager
            .map_section(section, None, 2 * PAGE_SIZE, Protection::READWRITE, true)
            .unwrap();
        assert_eq!(
            manager.commit(shared_a, PAGE_SIZE, Protection::READWRITE),
            Err(STATUS_ALREADY_COMMITTED)
        );
        assert_eq!(
            manager.decommit(shared_a, PAGE_SIZE),
            Err(STATUS_INVALID_PARAMETER)
        );
        manager.write(shared_a, &[9, 9]).unwrap();
        assert_eq!(manager.read(shared_b, 2).unwrap(), vec![9, 9]);
        assert_eq!(manager.read(cow, 2).unwrap(), vec![9, 9]);
        manager.write(cow, &[7, 7]).unwrap();
        assert_eq!(manager.read(shared_a, 2).unwrap(), vec![9, 9]);
        assert_eq!(manager.read(cow, 2).unwrap(), vec![7, 7]);
        assert_eq!(manager.section_bytes(section, 0, 2).unwrap(), &[9, 9]);
        assert_eq!(manager.mapped_bytes(), 6 * PAGE_SIZE);
        manager.unmap_section(shared_a).unwrap();
        manager.unmap_section(shared_b).unwrap();
        manager.unmap_section(cow).unwrap();
        assert_eq!(manager.mapped_bytes(), 0);
        assert_eq!(manager.unmap_section(shared_a), Err(STATUS_INVALID_ADDRESS));
        assert_eq!(manager.delete_section(section), Ok(()));
    }

    #[test]
    fn mapping_short_section_tails_zero_fills_and_protection_is_enforced() {
        let mut manager = MemoryManager::new(64 * PAGE_SIZE, 4, 8);
        let section = manager
            .create_section(ViewKind::Pagefile, PAGE_SIZE + 4, &[5, 6, 7, 8])
            .unwrap();
        let base = manager
            .map_section(section, None, PAGE_SIZE, Protection::READONLY, false)
            .unwrap();
        assert_eq!(manager.read(base, 4).unwrap(), vec![5, 6, 7, 8]);
        assert_eq!(manager.write(base, &[1]), Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(
            manager.protect(base, PAGE_SIZE, Protection::READWRITE),
            Ok(1)
        );
        manager.write(base, &[1, 2, 3, 4]).unwrap();
        assert_eq!(manager.section_bytes(section, 0, 4).unwrap(), &[1, 2, 3, 4]);
        manager.unmap_section(base).unwrap();
        let tail = manager
            .map_section(section, None, PAGE_SIZE, Protection::READONLY, false)
            .unwrap();
        assert_eq!(manager.read(tail + 4, 4).unwrap(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn working_set_tracks_touches_evicts_and_trim_is_exact() {
        let mut manager = MemoryManager::new(8 * PAGE_SIZE, 4, 2);
        let base = manager.reserve(None, 4 * PAGE_SIZE).unwrap();
        manager
            .commit(base, 4 * PAGE_SIZE, Protection::READWRITE)
            .unwrap();
        assert_eq!(manager.working_set_pages(), 0);
        for page in 0..4 {
            manager.read(base + page * PAGE_SIZE, 1).unwrap();
        }
        assert_eq!(manager.working_set_pages(), 2);
        assert_eq!(manager.trim_working_set(0), 2);
        assert_eq!(manager.working_set_pages(), 0);
        assert_eq!(manager.trim_working_set(0), 0);
        manager.write(base, &[1]).unwrap();
        assert_eq!(manager.working_set_pages(), 1);
        manager.decommit(base, PAGE_SIZE).unwrap();
        assert_eq!(manager.working_set_pages(), 0);
        manager.write(base + PAGE_SIZE, &[1]).unwrap();
        manager.release(base, 0).unwrap();
        assert_eq!(manager.working_set_pages(), 0);
    }

    #[test]
    fn mdl_lifecycle_rejects_invalid_and_double_operations() {
        let (mut memory, base) = committed_manager(2);
        let mut table = MdlTable::new();
        assert!(table.is_empty());
        assert_eq!(
            table.allocate(&memory, base, 0, false),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            table.allocate(&memory, base, u32::MAX as usize + 1, false),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            table.allocate(&memory, base + 2 * PAGE_SIZE, 1, false),
            Err(STATUS_INVALID_ADDRESS)
        );
        assert_eq!(
            table.allocate(&memory, u64::MAX, 2, false),
            Err(STATUS_INVALID_ADDRESS)
        );
        let read_only = table.allocate(&memory, base, 8, false).unwrap();
        assert_eq!(
            table.probe_and_lock(&memory, read_only, true),
            Err(STATUS_ACCESS_VIOLATION)
        );
        let writable = table.allocate(&memory, base + 1, 8, true).unwrap();
        assert_eq!(table.query(writable).unwrap().page_count, 1);
        assert_eq!(table.probe_and_lock(&memory, writable, true), Ok(()));
        assert_eq!(table.locked_pages(), 1);
        assert_eq!(table.peak_locked_pages(), 1);
        assert_eq!(
            table.probe_and_lock(&memory, writable, true),
            Err(STATUS_INVALID_DEVICE_STATE)
        );
        assert_eq!(table.free(writable), Err(STATUS_INVALID_DEVICE_STATE));
        assert_eq!(table.unlock(writable), Ok(()));
        assert_eq!(table.unlock(writable), Err(STATUS_INVALID_DEVICE_STATE));
        assert_eq!(table.free(writable), Ok(()));
        assert_eq!(table.free(writable), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.unlock(writable), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            table.probe_and_lock(&memory, writable, false),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(table.query(writable), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.locked_pages(), 0);
        assert_eq!(table.len(), 1);
        table.free(read_only).unwrap();
        assert!(table.is_empty());
        memory.release(base, 0).unwrap();
    }

    #[test]
    fn mdl_lock_failure_after_allocation_does_not_charge_pages() {
        let (mut memory, base) = committed_manager(1);
        let mut table = MdlTable::new();
        let mdl = table
            .allocate(&memory, base, PAGE_SIZE as usize, true)
            .unwrap();
        memory
            .protect(base, PAGE_SIZE, Protection::READONLY)
            .unwrap();
        assert_eq!(
            table.probe_and_lock(&memory, mdl, true),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(table.locked_pages(), 0);
        assert_eq!(table.peak_locked_pages(), 0);
        memory.release(base, 0).unwrap();
    }
}
