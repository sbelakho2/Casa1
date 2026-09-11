//! Executive support primitives for the CasaK kernel shim.
//!
//! This module implements three real executive facilities:
//!
//! - a tagged pool allocator with per-tag byte/count accounting, a hard byte
//!   budget that fails with `STATUS_INSUFFICIENT_RESOURCES`, and double-free
//!   detection (`STATUS_INVALID_ADDRESS`)
//! - a lookaside list that caches freed blocks and provably reuses them (the
//!   reused buffer has the same address, checked by pointer identity)
//! - a DPC queue that really executes deferred calls in FIFO order with a
//!   monotonic sequence number per enqueue
//!
//! All allocations are real heap buffers (`Box<[u8]>`), so pointer identity
//! and accounting are observable, while no guest code is required.

use std::collections::{HashMap, VecDeque};

use crate::casak::object::{
    NtStatus, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_ADDRESS, STATUS_NOT_FOUND,
};

/// A four-character pool tag, as used by Windows pool allocations.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PoolTag {
    bytes: [u8; 4],
}

impl PoolTag {
    /// Creates a tag from exactly four bytes.
    pub const fn new(bytes: &[u8; 4]) -> Self {
        Self { bytes: *bytes }
    }

    /// The raw tag bytes.
    pub const fn bytes(self) -> [u8; 4] {
        self.bytes
    }
}

impl std::fmt::Debug for PoolTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PoolTag({:?})", String::from_utf8_lossy(&self.bytes))
    }
}

impl std::fmt::Display for PoolTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.bytes))
    }
}

impl From<&[u8; 4]> for PoolTag {
    fn from(bytes: &[u8; 4]) -> Self {
        Self::new(bytes)
    }
}

/// A live allocation handed out by [`TaggedPool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolBlock {
    /// Address of the backing buffer; also the identity used for free().
    pub ptr: usize,
    /// Requested (non-zero) size in bytes.
    pub size: usize,
    /// Tag the block was allocated under.
    pub tag: PoolTag,
}

/// Per-tag accounting snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TagStats {
    pub bytes: usize,
    pub count: usize,
}

/// A tagged pool allocator with a hard byte budget.
#[derive(Debug)]
pub struct TaggedPool {
    budget: usize,
    used: usize,
    peak: usize,
    allocations: usize,
    frees: usize,
    tag_stats: HashMap<PoolTag, TagStats>,
    live: HashMap<usize, (PoolBlock, Box<[u8]>)>,
}

impl TaggedPool {
    /// Creates a pool that may hold at most `budget` bytes at a time.
    pub fn new(budget: usize) -> Self {
        Self {
            budget,
            used: 0,
            peak: 0,
            allocations: 0,
            frees: 0,
            tag_stats: HashMap::new(),
            live: HashMap::new(),
        }
    }

    pub fn budget(&self) -> usize {
        self.budget
    }

    pub fn used_bytes(&self) -> usize {
        self.used
    }

    pub fn peak_bytes(&self) -> usize {
        self.peak
    }

    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    pub fn allocation_count(&self) -> usize {
        self.allocations
    }

    pub fn free_count(&self) -> usize {
        self.frees
    }

    pub fn tag_stats(&self, tag: PoolTag) -> TagStats {
        self.tag_stats.get(&tag).copied().unwrap_or_default()
    }

    /// Allocates `size` bytes (at least one) under `tag`.
    ///
    /// Fails with [`STATUS_INSUFFICIENT_RESOURCES`] when the budget would be
    /// exceeded, without changing any accounting.
    pub fn allocate(&mut self, tag: PoolTag, size: usize) -> Result<PoolBlock, NtStatus> {
        let size = size.max(1);
        if self.used.saturating_add(size) > self.budget {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let buffer = vec![0u8; size].into_boxed_slice();
        let ptr = buffer.as_ptr() as usize;
        let block = PoolBlock { ptr, size, tag };
        self.live.insert(ptr, (block, buffer));
        self.used += size;
        self.peak = self.peak.max(self.used);
        self.allocations += 1;
        let stats = self.tag_stats.entry(tag).or_default();
        stats.bytes += size;
        stats.count += 1;
        Ok(block)
    }

    /// Frees a block. Detects double frees and foreign blocks, returning
    /// [`STATUS_INVALID_ADDRESS`] and leaving the pool unchanged.
    pub fn free(&mut self, block: PoolBlock) -> Result<(), NtStatus> {
        let (stored, buffer) = self.live.remove(&block.ptr).ok_or(STATUS_INVALID_ADDRESS)?;
        if stored.size != block.size || stored.tag != block.tag {
            self.live.insert(stored.ptr, (stored, buffer));
            return Err(STATUS_INVALID_ADDRESS);
        }
        self.used = self.used.saturating_sub(stored.size);
        self.frees += 1;
        if let Some(stats) = self.tag_stats.get_mut(&stored.tag) {
            stats.bytes = stats.bytes.saturating_sub(stored.size);
            stats.count = stats.count.saturating_sub(1);
        }
        drop(buffer);
        Ok(())
    }
}

/// A block handed out by [`LookasideList`]. `epoch` guards against stale
/// frees after a buffer has been reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookasideBlock {
    pub ptr: usize,
    pub size: usize,
    pub epoch: u64,
    pub tag: PoolTag,
}

/// A lookaside list that caches freed buffers and reuses them by address.
#[derive(Debug)]
pub struct LookasideList {
    tag: PoolTag,
    max_depth: usize,
    budget: usize,
    held_bytes: usize,
    hits: usize,
    misses: usize,
    depth_high_water: usize,
    next_epoch: u64,
    free: Vec<(u64, Box<[u8]>)>,
    outstanding: HashMap<usize, (u64, Box<[u8]>)>,
}

impl LookasideList {
    /// Creates a lookaside list for `tag` that keeps at most `max_depth`
    /// cached buffers and holds at most `budget` bytes of live memory.
    pub fn new(tag: PoolTag, max_depth: usize, budget: usize) -> Self {
        Self {
            tag,
            max_depth,
            budget,
            held_bytes: 0,
            hits: 0,
            misses: 0,
            depth_high_water: 0,
            next_epoch: 1,
            free: Vec::new(),
            outstanding: HashMap::new(),
        }
    }

    pub fn tag(&self) -> PoolTag {
        self.tag
    }

    pub fn budget(&self) -> usize {
        self.budget
    }

    pub fn held_bytes(&self) -> usize {
        self.held_bytes
    }

    pub fn hits(&self) -> usize {
        self.hits
    }

    pub fn misses(&self) -> usize {
        self.misses
    }

    pub fn free_depth(&self) -> usize {
        self.free.len()
    }

    pub fn depth_high_water(&self) -> usize {
        self.depth_high_water
    }

    pub fn in_use(&self) -> usize {
        self.outstanding.len()
    }

    /// Allocates at least `size` bytes, reusing a cached buffer when possible.
    /// Reuse is observable: the returned pointer equals the freed one.
    pub fn allocate(&mut self, size: usize) -> Result<LookasideBlock, NtStatus> {
        let size = size.max(1);
        if let Some(index) = self
            .free
            .iter()
            .position(|(_, buffer)| buffer.len() == size)
            .or_else(|| {
                self.free
                    .iter()
                    .position(|(_, buffer)| buffer.len() >= size)
            })
        {
            let (epoch, buffer) = self.free.swap_remove(index);
            let ptr = buffer.as_ptr() as usize;
            let epoch = epoch + 1;
            self.hits += 1;
            self.outstanding.insert(ptr, (epoch, buffer));
            return Ok(LookasideBlock {
                ptr,
                size,
                epoch,
                tag: self.tag,
            });
        }
        if self.held_bytes.saturating_add(size) > self.budget {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let buffer = vec![0u8; size].into_boxed_slice();
        let ptr = buffer.as_ptr() as usize;
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        self.misses += 1;
        self.held_bytes += size;
        self.outstanding.insert(ptr, (epoch, buffer));
        Ok(LookasideBlock {
            ptr,
            size,
            epoch,
            tag: self.tag,
        })
    }

    /// Returns a block to the cache. Stale or double frees are rejected with
    /// [`STATUS_INVALID_ADDRESS`]; cached buffers beyond `max_depth` are
    /// released back to the allocator.
    pub fn free(&mut self, block: LookasideBlock) -> Result<(), NtStatus> {
        let (epoch, buffer) = self
            .outstanding
            .remove(&block.ptr)
            .ok_or(STATUS_INVALID_ADDRESS)?;
        if epoch != block.epoch || block.tag != self.tag {
            self.outstanding.insert(block.ptr, (epoch, buffer));
            return Err(STATUS_INVALID_ADDRESS);
        }
        if self.free.len() < self.max_depth {
            self.free.push((epoch, buffer));
            self.depth_high_water = self.depth_high_water.max(self.free.len());
        } else {
            self.held_bytes = self.held_bytes.saturating_sub(buffer.len());
        }
        Ok(())
    }
}

/// A deferred procedure call queued on a [`DpcQueue`].
pub struct DpcObject {
    sequence: u64,
    callback: Option<Box<dyn FnOnce()>>,
}

impl DpcObject {
    /// Builds a DPC with an explicit sequence number.
    pub fn new(sequence: u64, callback: impl FnOnce() + 'static) -> Self {
        Self {
            sequence,
            callback: Some(Box::new(callback)),
        }
    }

    /// Monotonic sequence assigned at enqueue time (starts at 1).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Runs this call exactly once; returns `false` on repeated invocation.
    pub fn invoke(&mut self) -> bool {
        match self.callback.take() {
            Some(callback) => {
                callback();
                true
            }
            None => false,
        }
    }
}

impl std::fmt::Debug for DpcObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpcObject")
            .field("sequence", &self.sequence)
            .field("pending", &self.callback.is_some())
            .finish()
    }
}

/// A FIFO deferred-procedure-call queue with a real executor and a monotonic
/// sequence per enqueued DPC.
#[derive(Default)]
pub struct DpcQueue {
    next_sequence: u64,
    pending: VecDeque<DpcObject>,
    executed: u64,
    cancelled: u64,
}

impl DpcQueue {
    /// Creates an empty queue. Sequence numbers start at 1.
    pub fn new() -> Self {
        Self {
            next_sequence: 1,
            pending: VecDeque::new(),
            executed: 0,
            cancelled: 0,
        }
    }

    /// Enqueues a deferred call, returning its monotonic sequence number.
    pub fn queue(&mut self, callback: impl FnOnce() + 'static) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.pending.push_back(DpcObject {
            sequence,
            callback: Some(Box::new(callback)),
        });
        sequence
    }

    /// Enqueues a pre-built DPC object, preserving its sequence.
    pub fn queue_object(&mut self, dpc: DpcObject) {
        self.next_sequence = self.next_sequence.max(dpc.sequence + 1);
        self.pending.push_back(dpc);
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn executed_count(&self) -> u64 {
        self.executed
    }

    pub fn cancelled_count(&self) -> u64 {
        self.cancelled
    }

    /// Next sequence number that will be handed out.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Executes all pending DPCs in FIFO order; returns how many ran.
    pub fn execute_pending(&mut self) -> usize {
        let mut ran = 0;
        while let Some(mut dpc) = self.pending.pop_front() {
            if dpc.invoke() {
                ran += 1;
                self.executed += 1;
            }
        }
        ran
    }

    /// Cancels a pending DPC by sequence number.
    pub fn cancel(&mut self, sequence: u64) -> Result<(), NtStatus> {
        let index = self
            .pending
            .iter()
            .position(|dpc| dpc.sequence == sequence)
            .ok_or(STATUS_NOT_FOUND)?;
        self.pending.remove(index);
        self.cancelled += 1;
        Ok(())
    }

    /// Drains and returns the sequence numbers still pending, in order.
    pub fn pending_sequences(&self) -> Vec<u64> {
        self.pending.iter().map(DpcObject::sequence).collect()
    }
}
