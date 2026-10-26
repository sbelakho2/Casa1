use super::*;

pub(crate) const MEMORY_PAGE_SIZE: usize = 4096;
pub(crate) const MEMORY_PAGE_SHIFT: usize = 12;
pub(crate) const MEMORY_PAGE_BITMAP_WORDS: usize = MEMORY_PAGE_SIZE / 64;
pub(crate) const MEMORY_PAGE_MASK: u64 = !(MEMORY_PAGE_SIZE as u64 - 1);
pub(crate) const PAGE_DIRECTORY_CHUNK_SHIFT: u64 = 21; // 2 MiB chunks
pub(crate) const PAGE_DIRECTORY_CHUNK_ENTRIES: usize =
    1 << (PAGE_DIRECTORY_CHUNK_SHIFT as usize - MEMORY_PAGE_SHIFT);
pub(crate) const PAGE_DIRECTORY_MISSING: u32 = u32::MAX;

/// Preferred size of the flat guest window shared with the JIT: 256 GiB
/// (power of two).
///
/// The canonical store owns one `mmap` of this size when the host can reserve
/// it; otherwise it falls back to [`GUEST_FLAT_MIN_SIZE`].  Guest pages below
/// the window are addressed as `flat_base + guest_address`; pages above it
/// (e.g. a PE image loaded at 0x1800_0000_0000) are backed by individually
/// allocated 4 KiB frames owned by the same store.  Both views therefore read
/// and write the SAME bytes; there is no mirror to synchronise.
pub(crate) const GUEST_FLAT_SIZE: usize = 1 << 38;

/// Minimum direct window guaranteed on every supported host: 128 GiB.  This
/// keeps the 64 GiB (`0x10_0000_0000`) boundary inside the direct window even
/// when the preferred 256 GiB reservation is unavailable.
pub(crate) const GUEST_FLAT_MIN_SIZE: usize = 1 << 37;

/// Alignment of the flat window base.  The mapping is over-reserved and the
/// unaligned prefix/suffix are released, so `flat_base` stays aligned even
/// when the kernel returns a lower-aligned address.
pub(crate) const GUEST_FLAT_ALIGN: usize = 16 * 1024 * 1024;

/// Reserve `size` bytes of sparse anonymous memory with `base` aligned to
/// `align` (a power of two).  Returns null when the reservation is impossible.
///
/// # Safety
/// The returned pointer is owned by the caller and must be released with
/// `munmap(pointer, size)` exactly once.
pub(crate) unsafe fn reserve_flat_window(size: usize, align: usize) -> *mut u8 {
    debug_assert!(align.is_power_of_two());
    let Some(total) = size.checked_add(align - 1) else {
        return std::ptr::null_mut();
    };
    // SAFETY: plain anonymous mmap; fd=-1 with MAP_ANONYMOUS is valid.
    // MAP_NORESERVE keeps the window virtual until a page is actually
    // committed, so sparse guests do not reserve swap.
    let raw = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            total,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return std::ptr::null_mut();
    }
    let raw_address = raw as usize;
    let aligned_address = (raw_address + (align - 1)) & !(align - 1);
    let prefix = aligned_address - raw_address;
    let suffix = total - prefix - size;
    // SAFETY: prefix/suffix are sub-ranges of the live reservation and do not
    // overlap the [aligned_address, aligned_address + size) window.
    unsafe {
        if prefix != 0 {
            libc::munmap(raw, prefix);
        }
        if suffix != 0 {
            libc::munmap((aligned_address + size) as *mut libc::c_void, suffix);
        }
    }
    aligned_address as *mut u8
}

/// Reserve the first size in `sizes` that fits, returning the chosen size and
/// its aligned base (null base when every candidate failed).
pub(crate) fn reserve_flat_window_candidates(sizes: &[usize], align: usize) -> (usize, *mut u8) {
    for &size in sizes {
        // SAFETY: the returned mapping is owned by the caller and released
        // with `munmap(base, size)`.
        let base = unsafe { reserve_flat_window(size, align) };
        if !base.is_null() {
            return (size, base);
        }
    }
    (sizes[0], std::ptr::null_mut())
}

/// Canonical guest-memory store.
///
/// This is the single owner of guest bytes for one [`MemoryImage`].  The
/// interpreter's page table stores direct pointers into this store, and the
/// JIT's flat window is the very same mapping (not a copy), so a store made
/// through either view is immediately visible through the other.
///
/// Resident memory is strictly sparse: the flat window is mapped with
/// `MAP_NORESERVE` and only pages actually committed by the guest are ever
/// touched.  Addresses outside the flat window receive one aligned frame each.
pub(crate) struct GuestMemoryStore {
    flat_base: *mut u8,
    flat_size: usize,
    valid: bool,
    /// One bit per flat 4 KiB page: set when the page has been committed.
    /// Atomics keep the SIGBUS path async-signal-safe.
    materialised: Box<[std::sync::atomic::AtomicU64]>,
    /// Number of page commitments (a page removed with `unmap_range` and
    /// committed again is counted again; repeated writes are not).
    materialisations: std::sync::atomic::AtomicU64,
    /// Frames for guest addresses outside the flat window.  The map is only
    /// consulted when creating or releasing a page, never on a data access.
    high_pages: Mutex<HashMap<u64, *mut u8>>,
}

// SAFETY: the raw pointers refer to process-wide mappings/frames owned by the
// store; every data access is bounds-checked by the page table before the
// pointer is formed, and mutations of the two metadata structures are either
// atomic or mutex-protected.
unsafe impl Send for GuestMemoryStore {}
// SAFETY: same as `Send`: the flat window is a stable mapping and all mutable
// metadata uses atomics or a mutex.
unsafe impl Sync for GuestMemoryStore {}

impl GuestMemoryStore {
    pub(crate) fn new() -> Self {
        // Try the full 256 GiB window first and degrade to the guaranteed
        // 64 GiB minimum when the host refuses the larger reservation.
        let (reserved_size, flat_base) = reserve_flat_window_candidates(
            &[GUEST_FLAT_SIZE, GUEST_FLAT_MIN_SIZE],
            GUEST_FLAT_ALIGN,
        );
        let valid = !flat_base.is_null();
        let flat_size = reserved_size;
        let bitmap_words = flat_size.div_ceil(MEMORY_PAGE_SIZE * 64);
        let materialised = (0..bitmap_words)
            .map(|_| std::sync::atomic::AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            flat_base,
            flat_size,
            valid,
            materialised,
            materialisations: std::sync::atomic::AtomicU64::new(0),
            high_pages: Mutex::new(HashMap::new()),
        }
    }

    #[inline]
    pub(crate) fn flat_base(&self) -> u64 {
        self.flat_base as u64
    }

    #[inline]
    pub(crate) fn flat_size(&self) -> usize {
        self.flat_size
    }

    #[inline]
    pub(crate) fn is_valid(&self) -> bool {
        self.valid
    }

    #[inline]
    fn flat_page_bit(&self, page_base: u64) -> Option<(usize, u64)> {
        if !self.valid || page_base >= self.flat_size as u64 || !page_base.is_multiple_of(4096) {
            return None;
        }
        let page = page_base as usize / MEMORY_PAGE_SIZE;
        Some((page / 64, 1_u64 << (page % 64)))
    }

    /// Commit `page_base` and return its canonical bytes.
    ///
    /// This is the ONLY place a guest page is materialised.  The flat-window
    /// case zeroes the mapped page (a re-committed page must not expose stale
    /// bytes); the high-address case allocates a zeroed aligned frame.
    pub(crate) fn materialise_page(&self, page_base: u64) -> *mut u8 {
        let pointer = if self.valid && page_base < self.flat_size as u64 {
            // SAFETY: page_base < flat_size and the mapping is live for the
            // store's lifetime, so this page is inside the mapping.
            let pointer = unsafe { self.flat_base.add(page_base as usize) };
            // SAFETY: the page is inside the direct-window mapping and correctly
            // aligned (page_base is a multiple of 4096).
            unsafe {
                std::ptr::write_bytes(pointer, 0, MEMORY_PAGE_SIZE);
            }
            if let Some((word, bit)) = self.flat_page_bit(page_base) {
                self.materialised[word].fetch_or(bit, std::sync::atomic::Ordering::Relaxed);
            }
            pointer
        } else {
            let layout = std::alloc::Layout::from_size_align(MEMORY_PAGE_SIZE, MEMORY_PAGE_SIZE)
                .expect("page layout is valid");
            // SAFETY: non-zero layout; `alloc_zeroed` returns a 4096-byte,
            // 4096-aligned frame or null.
            let pointer = std::ptr::NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) })
                .expect("guest page allocation failed")
                .as_ptr();
            let mut high_pages = self
                .high_pages
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            high_pages.insert(page_base, pointer);
            pointer
        };
        self.materialisations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        pointer
    }

    /// Release the backing frame for a page removed from the guest page table.
    /// Flat-window pages stay mapped (their address is part of the JIT
    /// window); a later commit zeroes them.
    pub(crate) fn release_page(&self, page_base: u64) {
        if self.valid && page_base < self.flat_size as u64 {
            if let Some((word, bit)) = self.flat_page_bit(page_base) {
                self.materialised[word].fetch_and(!bit, std::sync::atomic::Ordering::Relaxed);
            }
            return;
        }
        let mut high_pages = self
            .high_pages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(pointer) = high_pages.remove(&page_base) {
            let layout = std::alloc::Layout::from_size_align(MEMORY_PAGE_SIZE, MEMORY_PAGE_SIZE)
                .expect("page layout is valid");
            // SAFETY: the pointer was returned by `alloc_zeroed` with this
            // exact layout and has just been removed from the map.
            unsafe {
                std::alloc::dealloc(pointer, layout);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn is_page_materialised(&self, page_base: u64) -> bool {
        if self.valid && page_base < self.flat_size as u64 {
            match self.flat_page_bit(page_base) {
                Some((word, bit)) => {
                    self.materialised[word].load(std::sync::atomic::Ordering::Relaxed) & bit != 0
                }
                None => false,
            }
        } else {
            self.high_pages
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key(&page_base)
        }
    }

    pub(crate) fn materialised_page_count(&self) -> u64 {
        let flat: u64 = self
            .materialised
            .iter()
            .map(|word| word.load(std::sync::atomic::Ordering::Relaxed).count_ones() as u64)
            .sum();
        let high = self
            .high_pages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len() as u64;
        flat + high
    }

    #[cfg(test)]
    pub(crate) fn materialisation_count(&self) -> u64 {
        self.materialisations
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn high_page_count(&self) -> usize {
        self.high_pages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    #[cfg(test)]
    pub(crate) fn resident_flat_page_count(&self) -> usize {
        if !self.valid {
            return 0;
        }
        let mut resident = vec![0_u8; self.flat_size.div_ceil(MEMORY_PAGE_SIZE)];
        // SAFETY: `flat_base` is a live mapping of `flat_size` bytes and the
        // vector has one byte per page, as `mincore` requires.
        let result = unsafe {
            libc::mincore(
                self.flat_base as *const libc::c_void,
                self.flat_size,
                resident.as_mut_ptr() as *mut libc::c_char,
            )
        };
        assert_eq!(result, 0, "mincore must describe the flat guest window");
        resident.iter().filter(|byte| **byte & 1 != 0).count()
    }
}

#[cfg(test)]
impl GuestMemoryStore {
    /// A store whose flat window could not be mapped; used to exercise the
    /// invalid-view guards without depending on mmap failing in the test host.
    pub(crate) fn invalid_for_test() -> Self {
        let bitmap_words = GUEST_FLAT_SIZE.div_ceil(MEMORY_PAGE_SIZE * 64);
        Self {
            flat_base: std::ptr::null_mut(),
            flat_size: GUEST_FLAT_SIZE,
            valid: false,
            materialised: (0..bitmap_words)
                .map(|_| std::sync::atomic::AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            materialisations: std::sync::atomic::AtomicU64::new(0),
            high_pages: Mutex::new(HashMap::new()),
        }
    }
}

impl std::fmt::Debug for GuestMemoryStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuestMemoryStore")
            .field("flat_base", &self.flat_base)
            .field("flat_size", &self.flat_size)
            .field("valid", &self.valid)
            .field("materialised_pages", &self.materialised_page_count())
            .finish()
    }
}

impl Drop for GuestMemoryStore {
    fn drop(&mut self) {
        let high_pages = self
            .high_pages
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let layout = std::alloc::Layout::from_size_align(MEMORY_PAGE_SIZE, MEMORY_PAGE_SIZE)
            .expect("page layout is valid");
        for pointer in high_pages.drain().map(|(_, pointer)| pointer) {
            // SAFETY: every map entry was allocated with this exact layout in
            // `materialise_page` and is not used after the store is dropped.
            unsafe {
                std::alloc::dealloc(pointer, layout);
            }
        }
        if self.valid && !self.flat_base.is_null() {
            // SAFETY: the mapping was returned by the successful mmap in
            // `new`; no page table entry survives the store.
            unsafe {
                libc::munmap(self.flat_base as *mut libc::c_void, self.flat_size);
            }
        }
    }
}

/// Bytes of one guest page, permanently aliased into the canonical store.
#[derive(Clone, Copy)]
pub(crate) struct GuestPageBytes(*mut u8);

impl GuestPageBytes {
    #[inline]
    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.0
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        // SAFETY: the pointer comes from `GuestMemoryStore::materialise_page`
        // and is valid for exactly MEMORY_PAGE_SIZE bytes for the lifetime of
        // the store that outlives this page.
        unsafe { std::slice::from_raw_parts(self.0, MEMORY_PAGE_SIZE) }
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: same as `as_slice`; `&mut MemoryPage` guarantees unique
        // access while this slice is alive.
        unsafe { std::slice::from_raw_parts_mut(self.0, MEMORY_PAGE_SIZE) }
    }

    #[inline]
    fn fill(&mut self, value: u8) {
        self.as_mut_slice().fill(value);
    }
}

impl std::ops::Index<usize> for GuestPageBytes {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl std::ops::Index<std::ops::Range<usize>> for GuestPageBytes {
    type Output = [u8];

    #[inline]
    fn index(&self, range: std::ops::Range<usize>) -> &Self::Output {
        &self.as_slice()[range]
    }
}

impl std::ops::Index<std::ops::RangeFull> for GuestPageBytes {
    type Output = [u8];

    #[inline]
    fn index(&self, _range: std::ops::RangeFull) -> &Self::Output {
        self.as_slice()
    }
}

impl std::ops::IndexMut<usize> for GuestPageBytes {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.as_mut_slice()[index]
    }
}

impl std::ops::IndexMut<std::ops::Range<usize>> for GuestPageBytes {
    #[inline]
    fn index_mut(&mut self, range: std::ops::Range<usize>) -> &mut Self::Output {
        &mut self.as_mut_slice()[range]
    }
}

impl std::fmt::Debug for GuestPageBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuestPageBytes")
            .field("ptr", &self.0)
            .finish()
    }
}

impl PartialEq for GuestPageBytes {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for GuestPageBytes {}

#[derive(Debug)]
pub(crate) struct MemoryPage {
    pub(crate) bytes: GuestPageBytes,
    mapped: Box<[u64; MEMORY_PAGE_BITMAP_WORDS]>,
    fully_mapped: bool,
}

pub(crate) type PageLookup = HashMap<u64, usize>;

impl PartialEq for MemoryPage {
    fn eq(&self, other: &Self) -> bool {
        self.mapped == other.mapped
            && self.fully_mapped == other.fully_mapped
            && self.bytes == other.bytes
    }
}

impl Eq for MemoryPage {}

impl MemoryPage {
    fn new(bytes: *mut u8) -> Self {
        Self {
            bytes: GuestPageBytes(bytes),
            mapped: Box::new([0; MEMORY_PAGE_BITMAP_WORDS]),
            fully_mapped: false,
        }
    }

    fn snapshot(&self, page_base: u64, store: &GuestMemoryStore) -> Self {
        let pointer = store.materialise_page(page_base);
        // SAFETY: both pages are exactly MEMORY_PAGE_SIZE bytes; the new
        // snapshot store is unique and does not overlap the source.
        unsafe {
            std::ptr::copy_nonoverlapping(self.bytes.as_ptr(), pointer, MEMORY_PAGE_SIZE);
        }
        Self {
            bytes: GuestPageBytes(pointer),
            mapped: self.mapped.clone(),
            fully_mapped: self.fully_mapped,
        }
    }
    fn bit_mask(start_bit: usize, end_bit: usize) -> u64 {
        let width = end_bit - start_bit;
        if width == 64 {
            u64::MAX
        } else {
            ((1_u64 << width) - 1) << start_bit
        }
    }

    fn is_mapped(&self, offset: usize) -> bool {
        (self.mapped[offset / 64] & (1_u64 << (offset % 64))) != 0
    }

    fn mark_mapped_range(&mut self, start: usize, len: usize) {
        if len == 0 {
            return;
        }

        if self.fully_mapped {
            return;
        }

        if start == 0 && len == MEMORY_PAGE_SIZE {
            self.mark_fully_mapped();
            return;
        }

        let end = start + len;
        let start_word = start / 64;
        let end_word = (end - 1) / 64;
        if start_word == end_word {
            self.mapped[start_word] |= Self::bit_mask(start % 64, ((end - 1) % 64) + 1);
            self.fully_mapped = self.mapped.iter().all(|word| *word == u64::MAX);
            return;
        }
        for word_index in start_word..=end_word {
            let word_start = if word_index == start_word {
                start % 64
            } else {
                0
            };
            let word_end = if word_index == end_word {
                ((end - 1) % 64) + 1
            } else {
                64
            };
            self.mapped[word_index] |= Self::bit_mask(word_start, word_end);
        }
        self.fully_mapped = self.mapped.iter().all(|word| *word == u64::MAX);
    }

    fn first_unmapped_offset(&self, start: usize, len: usize) -> Option<usize> {
        if len == 0 {
            return None;
        }

        let end = start + len;
        let start_word = start / 64;
        let end_word = (end - 1) / 64;
        for word_index in start_word..=end_word {
            let word_start = if word_index == start_word {
                start % 64
            } else {
                0
            };
            let word_end = if word_index == end_word {
                ((end - 1) % 64) + 1
            } else {
                64
            };
            let mask = Self::bit_mask(word_start, word_end);
            let missing_bits = (!self.mapped[word_index]) & mask;
            if missing_bits != 0 {
                return Some(word_index * 64 + missing_bits.trailing_zeros() as usize);
            }
        }
        None
    }

    fn range_is_mapped(&self, start: usize, len: usize) -> bool {
        // Zero-length range is trivially mapped
        if len == 0 {
            return true;
        }

        // Page marked fully mapped — all bytes in this page are present
        if self.fully_mapped {
            return true;
        }

        let end = start + len;
        let start_word = start / 64;
        let end_word = (end - 1) / 64;
        if start_word == end_word {
            let mask = Self::bit_mask(start % 64, ((end - 1) % 64) + 1);
            return self.mapped[start_word] & mask == mask;
        }
        for word_index in start_word..=end_word {
            let word_start = if word_index == start_word {
                start % 64
            } else {
                0
            };
            let word_end = if word_index == end_word {
                ((end - 1) % 64) + 1
            } else {
                64
            };
            let mask = Self::bit_mask(word_start, word_end);
            if self.mapped[word_index] & mask != mask {
                return false;
            }
        }
        true
    }

    pub(crate) fn is_fully_mapped(&self) -> bool {
        self.fully_mapped
    }

    fn mark_fully_mapped(&mut self) {
        self.mapped.fill(u64::MAX);
        self.fully_mapped = true;
    }
}

/// Two-level sparse page directory covering the direct window.
///
/// The top level has one entry per 2 MiB chunk of the window (512 KiB for a
/// 256 GiB window); a second-level table is allocated only when a page in that
/// chunk is committed.  Lookups are two array indexes, never a hash, and the
/// directory stays proportional to the touched chunks rather than the window.
#[derive(Clone)]
pub(crate) struct PageDirectory {
    top: Box<[u32]>,
    #[allow(clippy::vec_box)]
    tables: Vec<Box<[u32; PAGE_DIRECTORY_CHUNK_ENTRIES]>>,
}

impl std::fmt::Debug for PageDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PageDirectory")
            .field("chunk_slots", &self.top.len())
            .field("allocated_tables", &self.tables.len())
            .finish()
    }
}

impl PageDirectory {
    fn new(window_size: usize) -> Self {
        let pages = window_size.div_ceil(MEMORY_PAGE_SIZE) as u64;
        let chunks = pages.div_ceil(PAGE_DIRECTORY_CHUNK_ENTRIES as u64) as usize;
        Self {
            top: vec![PAGE_DIRECTORY_MISSING; chunks].into_boxed_slice(),
            tables: Vec::new(),
        }
    }

    #[inline]
    fn chunk_of(&self, page_base: u64) -> Option<(usize, usize)> {
        let page = page_base >> MEMORY_PAGE_SHIFT;
        let chunk = page >> (PAGE_DIRECTORY_CHUNK_SHIFT - MEMORY_PAGE_SHIFT as u64);
        if chunk >= self.top.len() as u64 {
            return None;
        }
        let entry = (page & (PAGE_DIRECTORY_CHUNK_ENTRIES as u64 - 1)) as usize;
        Some((chunk as usize, entry))
    }

    #[inline]
    fn covers(&self, page_base: u64) -> bool {
        self.chunk_of(page_base).is_some()
    }

    #[inline]
    fn get(&self, page_base: u64) -> Option<usize> {
        let (chunk, entry) = self.chunk_of(page_base)?;
        let table_index = self.top[chunk];
        if table_index == PAGE_DIRECTORY_MISSING {
            return None;
        }
        let index = self.tables.get(table_index as usize)?[entry];
        (index != PAGE_DIRECTORY_MISSING).then_some(index as usize)
    }

    fn insert(&mut self, page_base: u64, index: usize) {
        let (chunk, entry) = self
            .chunk_of(page_base)
            .expect("page directory insert requires an in-window page");
        let mut table_index = self.top[chunk];
        if table_index == PAGE_DIRECTORY_MISSING {
            table_index = self.tables.len() as u32;
            self.tables.push(Box::new(
                [PAGE_DIRECTORY_MISSING; PAGE_DIRECTORY_CHUNK_ENTRIES],
            ));
            self.top[chunk] = table_index;
        }
        self.tables[table_index as usize][entry] = index as u32;
    }

    fn clear(&mut self) {
        self.top.fill(PAGE_DIRECTORY_MISSING);
        self.tables.clear();
    }
}

#[derive(Debug)]
pub struct MemoryImage {
    pages: Vec<(u64, MemoryPage)>,
    high_page_lookup: PageLookup,
    page_directory: PageDirectory,
    /// Canonical storage shared with the JIT's flat window.  Every page's
    /// bytes live here; the page table only records which bytes are mapped.
    store: Arc<GuestMemoryStore>,
    /// Handle to the canonical virtual-memory layer
    /// ([`crate::vm::VirtualMemory`]).  The loader keeps this null (raw
    /// page-map validation only); the PE runtime attaches its live VM with
    /// [`MemoryImage::set_vm`] so every guest access is validated by the
    /// canonical layer FIRST and the page map is used ONLY for the actual
    /// bytes.
    vm: *mut crate::vm::VirtualMemory,
}

/// A guest access violation raised by the checked memory accessors
/// ([`MemoryImage::guest_read_checked`] / [`MemoryImage::guest_write_checked`]).
/// Carries the precise faulting address (the first unmapped byte of the
/// access), the access type, and the length of the requested access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestMemoryFault {
    pub address: u64,
    pub write: bool,
    pub read_len: usize,
}

impl Clone for MemoryImage {
    fn clone(&self) -> Self {
        // A clone is a snapshot: it gets its own canonical store and copies
        // every committed page.  It must never alias the live image.
        let store = GuestMemoryStore::new();
        let pages: Vec<(u64, MemoryPage)> = self
            .pages
            .iter()
            .map(|(page_base, page)| (*page_base, page.snapshot(*page_base, &store)))
            .collect();
        // Rebuild the lookup against the clone's own window: the clone's
        // reservation may have fallen back to a smaller size than the source.
        let mut page_directory = PageDirectory::new(store.flat_size());
        let mut high_page_lookup = PageLookup::default();
        for (index, (page_base, _)) in pages.iter().enumerate() {
            if page_directory.covers(*page_base) {
                page_directory.insert(*page_base, index);
            } else {
                high_page_lookup.insert(*page_base, index);
            }
        }
        Self {
            pages,
            high_page_lookup,
            page_directory,
            store: Arc::new(store),
            vm: self.vm,
        }
    }
}

impl Default for MemoryImage {
    fn default() -> Self {
        let store = Arc::new(GuestMemoryStore::new());
        let page_directory = PageDirectory::new(store.flat_size());
        Self {
            pages: Vec::new(),
            high_page_lookup: PageLookup::default(),
            page_directory,
            store,
            vm: std::ptr::null_mut(),
        }
    }
}

impl PartialEq for MemoryImage {
    fn eq(&self, other: &Self) -> bool {
        self.pages.len() == other.pages.len()
            && self
                .pages
                .iter()
                .all(|(page_base, page)| matches!(other.page(*page_base), Some(other_page) if other_page == page))
    }
}

impl Eq for MemoryImage {}

impl MemoryImage {
    fn page_lookup_index(&self, page_base: u64) -> Option<usize> {
        let index = if self.page_directory.covers(page_base) {
            self.page_directory.get(page_base)?
        } else {
            *self.high_page_lookup.get(&page_base)?
        };
        let (mapped_base, _) = self.pages.get(index)?;
        if *mapped_base != page_base {
            return None;
        }
        Some(index)
    }

    fn record_page_index(&mut self, page_base: u64, index: usize) {
        if self.page_directory.covers(page_base) {
            self.page_directory.insert(page_base, index);
        } else {
            self.high_page_lookup.insert(page_base, index);
        }
    }

    pub(crate) fn page_index(&self, page_base: u64) -> Option<usize> {
        self.page_lookup_index(page_base)
    }

    pub(crate) fn page(&self, page_base: u64) -> Option<&MemoryPage> {
        self.page_index(page_base).map(|index| &self.pages[index].1)
    }

    /// Borrow an existing page mutably WITHOUT creating it when absent.
    /// Checked guest writes use this so a store can never materialize memory.
    fn page_mut(&mut self, page_base: u64) -> Option<&mut MemoryPage> {
        self.page_index(page_base)
            .map(|index| &mut self.pages[index].1)
    }

    fn page_mut_or_insert(&mut self, page_base: u64) -> &mut MemoryPage {
        if let Some(index) = self.page_index(page_base) {
            return &mut self.pages[index].1;
        }

        let pointer = self.store.materialise_page(page_base);
        let index = self.pages.len();
        self.pages.push((page_base, MemoryPage::new(pointer)));
        self.record_page_index(page_base, index);
        &mut self.pages[index].1
    }

    /// The canonical store backing this image.  The JIT attaches its flat
    /// window to this exact store, so both views alias the same bytes.
    pub(crate) fn canonical_store(&self) -> &Arc<GuestMemoryStore> {
        &self.store
    }

    /// True when the page exists and every byte in it is mapped.  Used by the
    /// JIT materialisation pass and the SIGBUS fallback; never allocates.
    pub(crate) fn page_is_fully_mapped(&self, page_base: u64) -> bool {
        self.page(page_base)
            .is_some_and(MemoryPage::is_fully_mapped)
    }

    /// True when the page exists (even partially mapped); never allocates.
    pub(crate) fn page_exists(&self, page_base: u64) -> bool {
        self.page(page_base).is_some()
    }

    /// Signal-safe check for the SIGBUS fallback: is `offset` inside the
    /// page's mapped byte bitmap?  Never allocates and never takes a lock
    /// beyond the page table lookup.
    pub(crate) fn page_byte_is_mapped(&self, page_base: u64, offset: usize) -> bool {
        self.page(page_base)
            .is_some_and(|page| offset < MEMORY_PAGE_SIZE && page.is_mapped(offset))
    }

    /// Returns the base addresses of all committed (allocated) pages in the
    /// sparse guest memory. Used by the JIT subsystem to bulk-sync pages into
    /// the flat memory region before JIT execution.
    pub fn committed_page_addresses(&self) -> Vec<u64> {
        self.pages.iter().map(|(base, _)| *base).collect()
    }

    pub fn map_bytes(&mut self, address: u64, bytes: &[u8]) {
        let mut current_address = address;
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let page_base = current_address & MEMORY_PAGE_MASK;
            let page_offset = (current_address - page_base) as usize;
            let chunk_len = (MEMORY_PAGE_SIZE - page_offset).min(remaining.len());
            let page = self.page_mut_or_insert(page_base);
            page.bytes[page_offset..page_offset + chunk_len]
                .copy_from_slice(&remaining[..chunk_len]);
            page.mark_mapped_range(page_offset, chunk_len);
            current_address = current_address.wrapping_add(chunk_len as u64);
            remaining = &remaining[chunk_len..];
        }
    }

    pub fn map_zeroed_if_unmapped(&mut self, address: u64, len: usize) {
        let mut current_address = address;
        let mut remaining = len;
        while remaining != 0 {
            let page_base = current_address & MEMORY_PAGE_MASK;
            let page_offset = (current_address - page_base) as usize;
            let chunk_len = (MEMORY_PAGE_SIZE - page_offset).min(remaining);
            let page = self.page_mut_or_insert(page_base);
            for offset in page_offset..page_offset + chunk_len {
                if !page.is_mapped(offset) {
                    page.bytes[offset] = 0;
                }
            }
            page.mark_mapped_range(page_offset, chunk_len);
            current_address = current_address.wrapping_add(chunk_len as u64);
            remaining -= chunk_len;
        }
    }

    pub fn commit_zeroed_pages(&mut self, address: u64, len: usize) -> AppResult<()> {
        let mut current_address = address;
        let mut remaining = len;
        while remaining != 0 {
            let page_base = current_address & MEMORY_PAGE_MASK;
            let page_offset = (current_address - page_base) as usize;
            let chunk_len = (MEMORY_PAGE_SIZE - page_offset).min(remaining);
            // Use page_mut_or_insert to create the page if it doesn't exist.
            // This handles the case where a page was previously allocated and then
            // decommitted (via VirtualFree / MEM_DECOMMIT), which calls unmap_range
            // and removes the page from the sparse page table. When the guest later
            // writes to that address, we must recreate the (zeroed) page rather than
            // failing with "unmapped guest memory."
            let page = self.page_mut_or_insert(page_base);
            if !page.is_fully_mapped() {
                page.mark_fully_mapped();
            }
            current_address = current_address.wrapping_add(chunk_len as u64);
            remaining -= chunk_len;
        }
        Ok(())
    }

    /// Zero the specified address range and keep pages in the table.
    ///
    /// Unlike `unmap_range` (which removes pages entirely), this method
    /// creates any missing pages, zeroes their bytes, and marks them as
    /// fully mapped. This is used by `VirtualFree` / `MEM_DECOMMIT` to
    /// keep the address range reserved while making it read-as-zero,
    /// matching the pragmatic semantics expected by guest code (e.g.,
    /// reading from a decommitted CRT heap region should return zero
    /// rather than raising an unrecoverable "unmapped guest memory"
    /// error).
    pub fn zero_range(&mut self, address: u64, len: usize) {
        if len == 0 {
            return;
        }
        let mut current_address = address;
        let remaining = len.max(MEMORY_PAGE_SIZE);
        let end = current_address.wrapping_add(remaining as u64);
        while current_address < end {
            let page_base = current_address & MEMORY_PAGE_MASK;
            let page = self.page_mut_or_insert(page_base);
            // Zero the entire page contents
            page.bytes.fill(0);
            if !page.is_fully_mapped() {
                page.mark_fully_mapped();
            }
            current_address = current_address.wrapping_add(MEMORY_PAGE_SIZE as u64);
        }
    }

    /// Remove all pages whose base address falls in the inclusive range
    /// `[address, address + len)`, effectively freeing the guest-physical
    /// memory. Used by `VirtualFree` / `MEM_RELEASE`.
    pub fn unmap_range(&mut self, address: u64, len: usize) {
        if len == 0 {
            return;
        }
        let start_page = address & MEMORY_PAGE_MASK;
        let end = address.wrapping_add(len as u64);
        let end_page = if end == 0 {
            MEMORY_PAGE_MASK
        } else {
            (end - 1) & MEMORY_PAGE_MASK
        };
        // Collect indices to remove (reverse order to keep indices stable)
        let mut to_remove: Vec<usize> = self
            .pages
            .iter()
            .enumerate()
            .filter(|(_, (base, _))| *base >= start_page && *base <= end_page)
            .map(|(i, _)| i)
            .collect();
        to_remove.sort_unstable_by(|a, b| b.cmp(a)); // reverse
        for idx in to_remove {
            let (page_base, _) = self.pages.swap_remove(idx);
            // High-address frames are owned by the store; release them now.
            // Flat-window pages remain part of the JIT window and are zeroed
            // again when re-committed.
            self.store.release_page(page_base);
        }
        // Rebuild lookup tables by collecting entries first to avoid
        // borrowing self.pages immutably while calling record_page_index.
        let entries: Vec<(u64, usize)> = self
            .pages
            .iter()
            .enumerate()
            .map(|(i, (base, _))| (*base, i))
            .collect();
        self.high_page_lookup.clear();
        self.page_directory.clear();
        for (base, index) in entries {
            self.record_page_index(base, index);
        }
    }

    /// The interpreter's guest access-violation error for an unmapped read.
    /// Shared with the JIT dispatcher so a JIT-detected fault is
    /// indistinguishable from an interpreter-detected one (and the caller's
    /// `annotate_guest_fault` wrapping applies identically).
    pub(crate) fn unmapped_memory_error(address: u64) -> AppError {
        AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unmapped guest memory at {address:#x}"),
        )
    }

    /// Attach the canonical virtual-memory layer: from here on every guest
    /// access is validated by [`crate::vm::VirtualMemory::check_access`]
    /// FIRST, with the raw page map used only for the actual bytes.
    /// `vm` must outlive this image.
    pub fn set_vm(&mut self, vm: &mut crate::vm::VirtualMemory) {
        self.vm = vm;
    }

    /// The attached canonical VM, or `None` when the loader has not wired
    /// one up (standalone / test images fall back to raw page-map
    /// validation).
    fn canonical_vm(&self) -> Option<&crate::vm::VirtualMemory> {
        if self.vm.is_null() {
            None
        } else {
            // SAFETY: `set_vm` requires the VM to outlive this image, and
            // the PE runtime only attaches VMs it keeps alive for the whole
            // run.
            Some(unsafe { &*self.vm })
        }
    }

    /// Validate `address` against the canonical VM when one is attached;
    /// no-op otherwise.  Faults surface as the interpreter's standard
    /// guest access-violation error carrying the precise fault address.
    fn check_canonical_access(&self, address: u64, write: bool, execute: bool) -> AppResult<()> {
        if let Some(vm) = self.canonical_vm()
            && let Err(fault) = vm.check_access(address, write, execute)
        {
            return Err(Self::unmapped_memory_error(fault.address));
        }
        Ok(())
    }

    /// First unmapped byte in `[address, address + len)`, or `None` when the
    /// whole range is mapped.  Never allocates or inserts pages.
    fn first_unmapped_in_range(&self, address: u64, len: usize) -> Option<u64> {
        if len == 0 {
            return None;
        }
        let mut checked = 0;
        let mut current_address = address;
        while checked < len {
            let page_base = current_address & MEMORY_PAGE_MASK;
            let page_offset = (current_address - page_base) as usize;
            let chunk_len = (MEMORY_PAGE_SIZE - page_offset).min(len - checked);
            let Some(page) = self.page(page_base) else {
                return Some(current_address);
            };
            if !page.range_is_mapped(page_offset, chunk_len) {
                let missing_offset = page
                    .first_unmapped_offset(page_offset, chunk_len)
                    .expect("range_is_mapped mismatch");
                return Some(page_base + missing_offset as u64);
            }
            checked += chunk_len;
            current_address = current_address.wrapping_add(chunk_len as u64);
        }
        None
    }

    /// Checked guest read: copies `buf.len()` bytes from `address` only when
    /// every byte is already mapped.  Unlike [`MemoryImage::read_into`] this
    /// returns a structured [`GuestMemoryFault`] (carrying the precise fault
    /// address and access length) and NEVER allocates or inserts pages.
    ///
    /// When a canonical VM is attached it is consulted FIRST (and is
    /// authoritative): a stray raw page can never satisfy the read if the VM
    /// says the address is unmapped, reserved, guarded or read-protected.
    pub fn guest_read_checked(&self, address: u64, buf: &mut [u8]) -> Result<(), GuestMemoryFault> {
        if let Some(vm) = self.canonical_vm()
            && let Err(fault) = vm.check_access(address, false, false)
        {
            return Err(GuestMemoryFault {
                address: fault.address,
                write: false,
                read_len: buf.len(),
            });
        }
        if let Some(fault_address) = self.first_unmapped_in_range(address, buf.len()) {
            return Err(GuestMemoryFault {
                address: fault_address,
                write: false,
                read_len: buf.len(),
            });
        }
        self.read_into(address, buf)
            .expect("validated range must be readable");
        Ok(())
    }

    /// Checked guest write: writes `buf` to `address` only when every byte is
    /// already mapped.  The whole range is validated BEFORE any byte is
    /// written (no partial writes on fault), and no page is ever created or
    /// marked mapped by this method.  Guest CPU writes must go through this
    /// (or [`MemoryImage::write_fixed`]-free equivalents) so that a store
    /// through a null/unmapped pointer raises an access violation instead of
    /// materializing memory.  Loader / VirtualAlloc / heap / kernel paths
    /// keep using the allocating APIs (`map_bytes`, `commit_zeroed_pages`,
    /// `page_mut_or_insert`).
    ///
    /// When a canonical VM is attached it is consulted FIRST (and is
    /// authoritative): a stray raw page can never satisfy the write if the
    /// VM says the address is unmapped, reserved, guarded or write-protected.
    pub fn guest_write_checked(
        &mut self,
        address: u64,
        buf: &[u8],
    ) -> Result<(), GuestMemoryFault> {
        if let Some(vm) = self.canonical_vm()
            && let Err(fault) = vm.check_access(address, true, false)
        {
            return Err(GuestMemoryFault {
                address: fault.address,
                write: true,
                read_len: buf.len(),
            });
        }
        if let Some(fault_address) = self.first_unmapped_in_range(address, buf.len()) {
            return Err(GuestMemoryFault {
                address: fault_address,
                write: true,
                read_len: buf.len(),
            });
        }
        let mut copied = 0;
        let mut current_address = address;
        while copied < buf.len() {
            let page_base = current_address & MEMORY_PAGE_MASK;
            let page_offset = (current_address - page_base) as usize;
            let chunk_len = (MEMORY_PAGE_SIZE - page_offset).min(buf.len() - copied);
            let page = self
                .page_mut(page_base)
                .expect("validated range must be present");
            page.bytes[page_offset..page_offset + chunk_len]
                .copy_from_slice(&buf[copied..copied + chunk_len]);
            copied += chunk_len;
            current_address = current_address.wrapping_add(chunk_len as u64);
        }
        Ok(())
    }

    fn read_fixed<const N: usize>(&self, address: u64) -> AppResult<[u8; N]> {
        let mut bytes = [0_u8; N];
        self.read_into(address, &mut bytes)?;
        Ok(bytes)
    }

    fn write_fixed<const N: usize>(&mut self, address: u64, bytes: [u8; N]) {
        let page_base = address & MEMORY_PAGE_MASK;
        let page_offset = (address - page_base) as usize;
        if page_offset + N <= MEMORY_PAGE_SIZE {
            if let Some(index) = self.page_index(page_base) {
                let page = &mut self.pages[index].1;
                page.bytes[page_offset..page_offset + N].copy_from_slice(&bytes);
                page.mark_mapped_range(page_offset, N);
                return;
            }
            let page = self.page_mut_or_insert(page_base);
            page.bytes[page_offset..page_offset + N].copy_from_slice(&bytes);
            page.mark_mapped_range(page_offset, N);
            return;
        }
        self.map_bytes(address, &bytes);
    }

    pub fn read_into(&self, address: u64, target: &mut [u8]) -> AppResult<()> {
        if target.is_empty() {
            return Ok(());
        }

        let mut copied = 0;
        let mut current_address = address;
        while copied < target.len() {
            let page_base = current_address & MEMORY_PAGE_MASK;
            let page_offset = (current_address - page_base) as usize;
            let chunk_len = (MEMORY_PAGE_SIZE - page_offset).min(target.len() - copied);
            self.check_canonical_access(current_address, false, false)?;
            let page = self
                .page(page_base)
                .ok_or_else(|| Self::unmapped_memory_error(current_address))?;
            if !page.range_is_mapped(page_offset, chunk_len) {
                let missing_offset = page
                    .first_unmapped_offset(page_offset, chunk_len)
                    .expect("range_is_mapped mismatch");
                return Err(Self::unmapped_memory_error(
                    page_base + missing_offset as u64,
                ));
            }
            target[copied..copied + chunk_len]
                .copy_from_slice(&page.bytes[page_offset..page_offset + chunk_len]);
            copied += chunk_len;
            current_address = current_address.wrapping_add(chunk_len as u64);
        }
        Ok(())
    }

    /// Signal-safe page read: copies a single 4 KiB page into `target` without
    /// any heap allocation or error formatting. Returns `true` if the page
    /// exists and is mapped, `false` otherwise.
    ///
    /// Designed for use inside a SIGBUS handler where `read_into` must not be
    /// called because its error path formats a string (heap allocation).
    pub fn read_page_signal_safe(&self, page_base: u64, target: &mut [u8; 4096]) -> bool {
        let Some(index) = self.page_index(page_base) else {
            return false;
        };
        let page = &self.pages[index].1;
        if !page.range_is_mapped(0, 4096) {
            return false;
        }
        target.copy_from_slice(&page.bytes[..]);
        true
    }

    /// Signal-safe direct page copy: copies a fully-mapped 4 KiB guest page
    /// straight into `dst` with no intermediate buffer, no allocation and no
    /// error formatting, and returns `true`. Returns `false` (leaving `dst`
    /// untouched) when the page is absent or not fully mapped.
    ///
    /// Designed for the SIGBUS page-sync handler, which must be
    /// async-signal-safe and wants to avoid the double copy of
    /// `read_page_signal_safe` + `sync_from_memory_image`: the lookup is a
    /// page-table read and the copy is one `copy_nonoverlapping`.
    ///
    /// # Safety
    ///
    /// `dst` must be valid for [`MEMORY_PAGE_SIZE`] bytes of writes.
    pub unsafe fn copy_page_to_raw(&self, page_base: u64, dst: *mut u8) -> bool {
        let Some(index) = self.page_index(page_base) else {
            return false;
        };
        let page = &self.pages[index].1;
        if !page.is_fully_mapped() {
            return false;
        }
        // SAFETY: the caller guarantees `dst` is valid for MEMORY_PAGE_SIZE
        // bytes; `page.bytes` is exactly that size.
        unsafe {
            std::ptr::copy_nonoverlapping(page.bytes.as_ptr(), dst, MEMORY_PAGE_SIZE);
        }
        true
    }

    pub fn read_into_slice(&self, address: u64, target: &mut [u8]) -> AppResult<()> {
        self.read_into(address, target)
    }

    pub fn is_range_mapped(&self, address: u64, len: usize) -> bool {
        // Zero-length range is trivially mapped
        if len == 0 {
            return true;
        }

        let mut checked = 0;
        let mut current_address = address;
        while checked < len {
            let page_base = current_address & MEMORY_PAGE_MASK;
            let page_offset = (current_address - page_base) as usize;
            let chunk_len = (MEMORY_PAGE_SIZE - page_offset).min(len - checked);
            let Some(page) = self.page(page_base) else {
                return false;
            };
            if !page.range_is_mapped(page_offset, chunk_len) {
                return false;
            }
            checked += chunk_len;
            current_address = current_address.wrapping_add(chunk_len as u64);
        }

        true
    }

    pub fn read_bytes(&self, address: u64, len: usize) -> AppResult<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut bytes = vec![0; len];
        self.read_into(address, &mut bytes)?;
        Ok(bytes)
    }

    pub fn read_u8(&self, address: u64) -> AppResult<u8> {
        self.check_canonical_access(address, false, false)?;
        let page_base = address & MEMORY_PAGE_MASK;
        let page_offset = (address - page_base) as usize;
        if let Some(index) = self.page_index(page_base) {
            let page = &self.pages[index].1;
            if !page.is_mapped(page_offset) {
                return Err(Self::unmapped_memory_error(address));
            }
            return Ok(page.bytes[page_offset]);
        }
        let page = self
            .page(page_base)
            .ok_or_else(|| Self::unmapped_memory_error(address))?;
        if !page.is_mapped(page_offset) {
            return Err(Self::unmapped_memory_error(address));
        }
        Ok(page.bytes[page_offset])
    }

    pub fn read_u16(&self, address: u64) -> AppResult<u16> {
        self.check_canonical_access(address, false, false)?;
        let page_base = address & MEMORY_PAGE_MASK;
        let page_offset = (address - page_base) as usize;
        if page_offset + 2 <= MEMORY_PAGE_SIZE {
            if let Some(index) = self.page_index(page_base) {
                let page = &self.pages[index].1;
                if page.range_is_mapped(page_offset, 2) {
                    return Ok(u16::from_le_bytes([
                        page.bytes[page_offset],
                        page.bytes[page_offset + 1],
                    ]));
                }
                let missing_offset = page
                    .first_unmapped_offset(page_offset, 2)
                    .expect("range_is_mapped mismatch");
                return Err(Self::unmapped_memory_error(
                    page_base + missing_offset as u64,
                ));
            }
            if let Some(page) = self.page(page_base) {
                if page.range_is_mapped(page_offset, 2) {
                    return Ok(u16::from_le_bytes([
                        page.bytes[page_offset],
                        page.bytes[page_offset + 1],
                    ]));
                }
                let missing_offset = page
                    .first_unmapped_offset(page_offset, 2)
                    .expect("range_is_mapped mismatch");
                return Err(Self::unmapped_memory_error(
                    page_base + missing_offset as u64,
                ));
            }
        }
        Ok(u16::from_le_bytes(self.read_fixed::<2>(address)?))
    }

    pub fn read_u32(&self, address: u64) -> AppResult<u32> {
        self.check_canonical_access(address, false, false)?;
        let page_base = address & MEMORY_PAGE_MASK;
        let page_offset = (address - page_base) as usize;
        if page_offset + 4 <= MEMORY_PAGE_SIZE {
            if let Some(index) = self.page_index(page_base) {
                let page = &self.pages[index].1;
                if page.range_is_mapped(page_offset, 4) {
                    return Ok(u32::from_le_bytes([
                        page.bytes[page_offset],
                        page.bytes[page_offset + 1],
                        page.bytes[page_offset + 2],
                        page.bytes[page_offset + 3],
                    ]));
                }
                let missing_offset = page
                    .first_unmapped_offset(page_offset, 4)
                    .expect("range_is_mapped mismatch");
                return Err(Self::unmapped_memory_error(
                    page_base + missing_offset as u64,
                ));
            }
            if let Some(page) = self.page(page_base) {
                if page.range_is_mapped(page_offset, 4) {
                    return Ok(u32::from_le_bytes([
                        page.bytes[page_offset],
                        page.bytes[page_offset + 1],
                        page.bytes[page_offset + 2],
                        page.bytes[page_offset + 3],
                    ]));
                }
                let missing_offset = page
                    .first_unmapped_offset(page_offset, 4)
                    .expect("range_is_mapped mismatch");
                return Err(Self::unmapped_memory_error(
                    page_base + missing_offset as u64,
                ));
            }
        }
        Ok(u32::from_le_bytes(self.read_fixed::<4>(address)?))
    }

    pub fn write_u8(&mut self, address: u64, value: u8) {
        self.write_fixed(address, [value]);
    }

    pub fn write_u16(&mut self, address: u64, value: u16) {
        self.write_fixed(address, value.to_le_bytes());
    }

    pub fn write_u32(&mut self, address: u64, value: u32) {
        self.write_fixed(address, value.to_le_bytes());
    }

    pub fn map_u64(&mut self, address: u64, value: u64) {
        self.write_u64(address, value);
    }

    pub fn map_xmm(&mut self, address: u64, value: XmmValue) {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&value.low.to_le_bytes());
        bytes.extend_from_slice(&value.high.to_le_bytes());
        self.map_bytes(address, &bytes);
    }

    pub fn map_ymm(&mut self, address: u64, value: YmmValue) {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&value.low.low.to_le_bytes());
        bytes.extend_from_slice(&value.low.high.to_le_bytes());
        bytes.extend_from_slice(&value.high.low.to_le_bytes());
        bytes.extend_from_slice(&value.high.high.to_le_bytes());
        self.map_bytes(address, &bytes);
    }

    pub fn read_u64(&self, address: u64) -> AppResult<u64> {
        self.check_canonical_access(address, false, false)?;
        let page_base = address & MEMORY_PAGE_MASK;
        let page_offset = (address - page_base) as usize;
        if page_offset + 8 <= MEMORY_PAGE_SIZE {
            if let Some(index) = self.page_index(page_base) {
                let page = &self.pages[index].1;
                if page.range_is_mapped(page_offset, 8) {
                    return Ok(u64::from_le_bytes([
                        page.bytes[page_offset],
                        page.bytes[page_offset + 1],
                        page.bytes[page_offset + 2],
                        page.bytes[page_offset + 3],
                        page.bytes[page_offset + 4],
                        page.bytes[page_offset + 5],
                        page.bytes[page_offset + 6],
                        page.bytes[page_offset + 7],
                    ]));
                }
                let missing_offset = page
                    .first_unmapped_offset(page_offset, 8)
                    .expect("range_is_mapped mismatch");
                return Err(Self::unmapped_memory_error(
                    page_base + missing_offset as u64,
                ));
            }
            if let Some(page) = self.page(page_base) {
                if page.range_is_mapped(page_offset, 8) {
                    return Ok(u64::from_le_bytes([
                        page.bytes[page_offset],
                        page.bytes[page_offset + 1],
                        page.bytes[page_offset + 2],
                        page.bytes[page_offset + 3],
                        page.bytes[page_offset + 4],
                        page.bytes[page_offset + 5],
                        page.bytes[page_offset + 6],
                        page.bytes[page_offset + 7],
                    ]));
                }
                let missing_offset = page
                    .first_unmapped_offset(page_offset, 8)
                    .expect("range_is_mapped mismatch");
                return Err(Self::unmapped_memory_error(
                    page_base + missing_offset as u64,
                ));
            }
        }
        Ok(u64::from_le_bytes(self.read_fixed::<8>(address)?))
    }

    pub fn read_xmm(&self, address: u64) -> AppResult<XmmValue> {
        let low = self.read_u64(address)?;
        let high = self.read_u64(address + 8)?;
        Ok(XmmValue { low, high })
    }

    pub fn read_ymm(&self, address: u64) -> AppResult<YmmValue> {
        Ok(YmmValue {
            low: self.read_xmm(address)?,
            high: self.read_xmm(address + 16)?,
        })
    }

    pub fn read_zmm(&self, address: u64) -> AppResult<ZmmValue> {
        Ok(ZmmValue {
            low: self.read_ymm(address)?,
            high: self.read_ymm(address + 32)?,
        })
    }

    pub fn map_zmm(&mut self, address: u64, value: ZmmValue) {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&ymm_to_bytes(value.low));
        bytes.extend_from_slice(&ymm_to_bytes(value.high));
        self.map_bytes(address, &bytes);
    }

    pub fn write_u64(&mut self, address: u64, value: u64) {
        self.write_fixed(address, value.to_le_bytes());
    }

    /// Serialized fallback for unaligned interlocked access (Windows x86
    /// tolerates unaligned lock-prefixed operations; x64 requires 32-bit
    /// alignment — the fallback keeps an unaligned guest call well-defined
    /// instead of faulting).
    fn unaligned_interlocked<F>(&self, address: u64, op: F) -> AppResult<u32>
    where
        F: FnOnce(u32) -> u32,
    {
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        let previous = self.read_u32(address)?;
        let page_base = address & MEMORY_PAGE_MASK;
        let page_offset = (address - page_base) as usize;
        let index = self.page_index(page_base).expect("range validated above");
        let page = &self.pages[index].1;
        let replacement = op(previous).to_le_bytes();
        // SAFETY: the range was validated readable/mapped by read_u32 above
        // and the LOCK excludes every other fallback writer; the mapping is
        // never mutated by this accessor, so the raw store cannot reallocate.
        unsafe {
            std::ptr::copy_nonoverlapping(
                replacement.as_ptr(),
                page.bytes.as_ptr().add(page_offset) as *mut u8,
                4,
            );
        }
        Ok(previous)
    }

    /// Resolve a 4-byte aligned, fully-mapped guest range as an
    /// [`AtomicU32`] view over the page bytes.
    ///
    /// The pointer stays valid for the lifetime of the page buffer: the
    /// pages vector is only reallocated through `&mut` methods, while the
    /// interlocked accessors take `&self` and never mutate the mapping.
    pub(crate) fn atomic_u32_at(&self, address: u64) -> AppResult<&std::sync::atomic::AtomicU32> {
        self.check_canonical_access(address, false, false)?;
        let page_base = address & MEMORY_PAGE_MASK;
        let page_offset = (address - page_base) as usize;
        if !page_offset.is_multiple_of(4) || page_offset + 4 > MEMORY_PAGE_SIZE {
            return Err(Self::unmapped_memory_error(address));
        }
        let Some(index) = self.page_index(page_base) else {
            return Err(Self::unmapped_memory_error(address));
        };
        let page = &self.pages[index].1;
        if !page.range_is_mapped(page_offset, 4) {
            return Err(Self::unmapped_memory_error(address));
        }
        // SAFETY: the reference covers the 4 mapped bytes of a committed
        // guest page (validated above); atomic access needs no `&mut`, and
        // the underlying allocation is never freed while `&self` is alive.
        Ok(unsafe {
            &*(page.bytes.as_ptr().add(page_offset) as *const std::sync::atomic::AtomicU32)
        })
    }

    /// Atomic 32-bit exchange on guest memory (InterlockedExchange).
    ///
    /// SeqCst so the interlocked semantics hold even when guest threads are
    /// driven by concurrent host threads; returns the PREVIOUS value.
    pub fn interlocked_exchange_u32(&self, address: u64, value: u32) -> AppResult<u32> {
        if !address.is_multiple_of(4) {
            return self.unaligned_interlocked(address, |_| value);
        }
        Ok(self
            .atomic_u32_at(address)?
            .swap(value, std::sync::atomic::Ordering::SeqCst))
    }

    /// Atomic 32-bit compare-and-exchange on guest memory
    /// (InterlockedCompareExchange): stores `exchange` when the current
    /// value equals `comparand`; returns the PREVIOUS value either way.
    pub fn interlocked_compare_exchange_u32(
        &self,
        address: u64,
        exchange: u32,
        comparand: u32,
    ) -> AppResult<u32> {
        if !address.is_multiple_of(4) {
            return self.unaligned_interlocked(address, |current| {
                if current == comparand {
                    exchange
                } else {
                    current
                }
            });
        }
        let previous = match self.atomic_u32_at(address)?.compare_exchange(
            comparand,
            exchange,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(previous) | Err(previous) => previous,
        };
        Ok(previous)
    }

    /// Atomic 32-bit add on guest memory (InterlockedExchangeAdd): adds
    /// `addend` and returns the PREVIOUS value.
    pub fn interlocked_exchange_add_u32(&self, address: u64, addend: u32) -> AppResult<u32> {
        if !address.is_multiple_of(4) {
            return self.unaligned_interlocked(address, |current| current.wrapping_add(addend));
        }
        Ok(self
            .atomic_u32_at(address)?
            .fetch_add(addend, std::sync::atomic::Ordering::SeqCst))
    }

    /// Atomic 32-bit increment on guest memory (InterlockedIncrement):
    /// increments and returns the NEW value.
    pub fn interlocked_increment_u32(&self, address: u64) -> AppResult<u32> {
        if !address.is_multiple_of(4) {
            return self.unaligned_interlocked(address, |current| current.wrapping_add(1));
        }
        Ok(self
            .atomic_u32_at(address)?
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .wrapping_add(1))
    }

    /// Atomic 32-bit decrement on guest memory (InterlockedDecrement):
    /// decrements and returns the NEW value.
    pub fn interlocked_decrement_u32(&self, address: u64) -> AppResult<u32> {
        if !address.is_multiple_of(4) {
            return self.unaligned_interlocked(address, |current| current.wrapping_sub(1));
        }
        Ok(self
            .atomic_u32_at(address)?
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
            .wrapping_sub(1))
    }

    pub fn stable_hash(&self) -> String {
        let mut hasher = Sha256::new();
        let mut pages = self.pages.iter().collect::<Vec<_>>();
        pages.sort_unstable_by_key(|(page_base, _)| *page_base);
        for (page_base, page) in pages {
            for (word_index, word) in page.mapped.iter().copied().enumerate() {
                let mut remaining = word;
                while remaining != 0 {
                    let bit_index = remaining.trailing_zeros() as usize;
                    let offset = word_index * 64 + bit_index;
                    hasher.update((page_base + offset as u64).to_le_bytes());
                    hasher.update([page.bytes[offset]]);
                    remaining &= remaining - 1;
                }
            }
        }
        hex_bytes(&hasher.finalize())
    }
}

pub(crate) fn read_memory_value(
    memory: &MemoryImage,
    address: u64,
    width: usize,
) -> AppResult<u64> {
    match width {
        1 => Ok(memory.read_u8(address)? as u64),
        2 => Ok(memory.read_u16(address)? as u64),
        4 => Ok(memory.read_u32(address)? as u64),
        8 => memory.read_u64(address),
        other => Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unsupported memory width {other}"),
        )),
    }
}

/// Checked guest write of an arbitrary byte buffer: faults (with the
/// interpreter's access-violation error carrying the precise fault address)
/// instead of creating pages when the destination is not already mapped.
/// Used by interpreter IR store paths and vector stores; the loader and
/// kernel paths keep the allocating APIs.
pub(crate) fn write_guest_bytes(
    memory: &mut MemoryImage,
    address: u64,
    bytes: &[u8],
) -> AppResult<()> {
    memory
        .guest_write_checked(address, bytes)
        .map_err(|fault| MemoryImage::unmapped_memory_error(fault.address))
}

pub(crate) fn write_memory_value(
    memory: &mut MemoryImage,
    address: u64,
    value: u64,
    width: usize,
) -> AppResult<()> {
    let mut bytes = [0_u8; 8];
    match width {
        1 => bytes[..1].copy_from_slice(&(value as u8).to_le_bytes()),
        2 => bytes[..2].copy_from_slice(&(value as u16).to_le_bytes()),
        4 => bytes[..4].copy_from_slice(&(value as u32).to_le_bytes()),
        8 => bytes.copy_from_slice(&value.to_le_bytes()),
        other => {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unsupported memory width {other}"),
            ));
        }
    }
    write_guest_bytes(memory, address, &bytes[..width])
}

pub(crate) fn resolve_memory_operand(
    state: &CpuState,
    operand: &MemoryOperand,
    width: usize,
) -> AppResult<u64> {
    // width does not affect the linear address computation — it determines
    // the access size for the caller, not the base address itself.
    let _ = width;
    // MOFFS64 absolute address: use the full 64-bit value directly.
    if let Some(abs_addr) = operand.absolute_address {
        return if let Some(segment) = operand.segment {
            Ok(abs_addr.wrapping_add(state.segment_base(segment)))
        } else {
            Ok(abs_addr)
        };
    }
    let address = if state.arch == GuestArch::X86 {
        // 32-bit mode: the entire linear address is 32 bits wide.
        let mut value = operand.displacement as u32 as u64;
        if operand.rip_relative {
            value = value.wrapping_add((operand.rip_base as u32) as u64);
        }
        if let Some(segment) = operand.segment {
            value = value.wrapping_add((state.segment_base(segment) as u32) as u64);
        }
        if let Some(base) = operand.base {
            value = value.wrapping_add((state.get(base) as u32) as u64);
        }
        if let Some(index) = operand.index {
            value = value.wrapping_add(
                ((state.get(index) as u32) as u64).wrapping_mul(u64::from(operand.scale)),
            );
        }
        value & 0xffff_ffff
    } else if operand.address_size_32 {
        // 64-bit mode with a 0x67 address-size override: per the Intel SDM, the
        // effective address (displacement + base + index) is computed using
        // 32-bit registers and truncated to 32 bits, but the FS/GS segment base
        // is then added at its full 64-bit width to form the final 64-bit linear
        // address. Truncating the segment base (e.g. the GS/TEB base) to 32 bits
        // would corrupt TEB-relative accesses such as `mov rax, gs:[eax]`.
        let mut ea = operand.displacement as u32 as u64;
        if operand.rip_relative {
            ea = ea.wrapping_add((operand.rip_base as u32) as u64);
        }
        if let Some(base) = operand.base {
            ea = ea.wrapping_add((state.get(base) as u32) as u64);
        }
        if let Some(index) = operand.index {
            ea = ea.wrapping_add(
                ((state.get(index) as u32) as u64).wrapping_mul(u64::from(operand.scale)),
            );
        }
        ea &= 0xffff_ffff;
        if let Some(segment) = operand.segment {
            ea = ea.wrapping_add(state.segment_base(segment));
        }
        ea
    } else {
        let mut value = operand.displacement as i64 as u64;
        if operand.rip_relative {
            value = value.wrapping_add(operand.rip_base);
        }
        if let Some(segment) = operand.segment {
            value = value.wrapping_add(state.segment_base(segment));
        }
        if let Some(base) = operand.base {
            value = value.wrapping_add(state.get(base));
        }
        if let Some(index) = operand.index {
            value = value.wrapping_add(state.get(index).wrapping_mul(u64::from(operand.scale)));
        }
        value
    };
    Ok(address)
}
