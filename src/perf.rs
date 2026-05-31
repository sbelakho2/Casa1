//! Performance optimization for Casa1.
//!
//! Implements block chaining, lazy JIT compilation, memory access translation
//! cache, parallel shader compilation, Metal command batching, GPU upload
//! streaming, and frame pacing for AAA game performance targeting 60 FPS.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ===========================================================================
// Block Chaining
// ===========================================================================

/// A translated block in the JIT cache.
#[derive(Debug, Clone)]
pub struct TranslatedBlock {
    /// Guest address of the block entry.
    pub guest_address: u64,
    /// Host address of the translated code.
    pub host_address: u64,
    /// Size of the translated code in bytes.
    pub code_size: usize,
    /// Number of times this block has been executed.
    pub execution_count: u64,
    /// Guest address of the likely successor block (for chaining).
    pub fallthrough_target: Option<u64>,
    /// Whether this block has been patched with a chain to its successor.
    pub is_chained: bool,
    /// Instruction count in this block.
    pub instruction_count: usize,
}

/// Block chain link: connects two translated blocks.
#[derive(Debug, Clone)]
pub struct BlockChain {
    pub from_address: u64,
    pub to_address: u64,
    pub patch_offset: usize,
    pub is_active: bool,
}

/// Manages block chaining for the JIT compiler.
///
/// Block chaining eliminates the interpreter dispatch overhead between
/// translated blocks by patching the exit of one block to jump directly
/// to the entry of the next block.
pub struct BlockChainingCache {
    blocks: HashMap<u64, TranslatedBlock>,
    chains: Vec<BlockChain>,
    total_chains_active: u64,
    total_chains_broken: u64,
}

impl BlockChainingCache {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            chains: Vec::new(),
            total_chains_active: 0,
            total_chains_broken: 0,
        }
    }

    /// Register a translated block.
    pub fn register_block(
        &mut self,
        guest_address: u64,
        host_address: u64,
        code_size: usize,
        instruction_count: usize,
    ) {
        self.blocks.insert(
            guest_address,
            TranslatedBlock {
                guest_address,
                host_address,
                code_size,
                execution_count: 0,
                fallthrough_target: None,
                is_chained: false,
                instruction_count,
            },
        );
    }

    /// Record a block execution and attempt chaining.
    pub fn record_execution(&mut self, guest_address: u64, next_address: u64) -> AppResult<()> {
        // First, read the current state
        let (is_chained, current_target) = {
            let block = self.blocks.get(&guest_address).ok_or_else(|| {
                AppError::new(ReasonCode::RcUnimplInsn, format!("block at {guest_address:#x} not found"))
            })?;
            (block.is_chained, block.fallthrough_target)
        };

        // Break chain if target changed and currently chained
        if current_target != Some(next_address) && is_chained {
            self.break_chain(guest_address);
        }

        // Update the block
        let block = self.blocks.get_mut(&guest_address).ok_or_else(|| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("block at {guest_address:#x} not found"))
        })?;
        block.execution_count += 1;
        block.fallthrough_target = Some(next_address);

        Ok(())
    }

    /// Try to chain a block to its fallthrough target.
    ///
    /// Returns true if chaining was successful.
    pub fn try_chain(&mut self, guest_address: u64) -> bool {
        let target_address = match self.blocks.get(&guest_address).and_then(|b| b.fallthrough_target) {
            Some(addr) => addr,
            None => return false,
        };

        // Check if target block exists
        if !self.blocks.contains_key(&target_address) {
            return false;
        }

        // Check if execution count is high enough (hot path)
        let execution_count = self.blocks.get(&guest_address).map(|b| b.execution_count).unwrap_or(0);
        if execution_count < 10 {
            return false;
        }

        // Create chain
        let patch_offset = self.compute_patch_offset(guest_address, target_address);
        let chain = BlockChain {
            from_address: guest_address,
            to_address: target_address,
            patch_offset,
            is_active: true,
        };
        self.chains.push(chain);
        self.total_chains_active += 1;

        if let Some(block) = self.blocks.get_mut(&guest_address) {
            block.is_chained = true;
        }

        true
    }

    /// Break an existing chain from a block.
    pub fn break_chain(&mut self, from_address: u64) {
        for chain in &mut self.chains {
            if chain.from_address == from_address && chain.is_active {
                chain.is_active = false;
                self.total_chains_broken += 1;
            }
        }
        if let Some(block) = self.blocks.get_mut(&from_address) {
            block.is_chained = false;
        }
    }

    /// Get a block by guest address.
    pub fn get_block(&self, guest_address: u64) -> Option<&TranslatedBlock> {
        self.blocks.get(&guest_address)
    }

    /// Get the total number of registered blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Get the number of active chains.
    pub fn active_chain_count(&self) -> usize {
        self.chains.iter().filter(|c| c.is_active).count()
    }

    /// Get the total chains created.
    pub fn total_chains_created(&self) -> u64 {
        self.total_chains_active
    }

    /// Get the total chains broken.
    pub fn total_chains_broken(&self) -> u64 {
        self.total_chains_broken
    }

    /// Get hot blocks (execution count above threshold).
    pub fn hot_blocks(&self, threshold: u64) -> Vec<&TranslatedBlock> {
        self.blocks
            .values()
            .filter(|b| b.execution_count >= threshold)
            .collect()
    }

    /// Compute the patch offset from one block to its target.
    ///
    /// Returns the difference between the end of `from_address`'s code and the
    /// start of `patch_target`'s code. Falls back to 0 if either block is not found.
    pub fn compute_patch_offset(&self, from_address: u64, patch_target: u64) -> usize {
        if let Some(target_block) = self.blocks.get(&patch_target) {
            if let Some(from_block) = self.blocks.get(&from_address) {
                // The patch offset is the distance from the end of the current block
                // to the start of the target block's host code.
                let from_end = from_block.host_address.saturating_add(from_block.code_size as u64);
                if from_end <= target_block.host_address {
                    (target_block.host_address - from_end) as usize
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        }
    }

    /// Invalidate all blocks and chains (e.g., on self-modifying code).
    pub fn invalidate_all(&mut self) {
        self.blocks.clear();
        self.chains.clear();
    }

    /// Invalidate blocks in a specific address range.
    pub fn invalidate_range(&mut self, start: u64, end: u64) {
        let to_remove: Vec<u64> = self
            .blocks
            .keys()
            .filter(|&&addr| addr >= start && addr < end)
            .copied()
            .collect();

        for addr in to_remove {
            self.break_chain(addr);
            self.blocks.remove(&addr);
        }
    }
}

// ===========================================================================
// Lazy JIT Compilation
// ===========================================================================

/// Compilation tier for lazy JIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilationTier {
    /// Not yet compiled — will be interpreted.
    Uncompiled,
    /// Compiled with minimal optimization (tier 1).
    Baseline,
    /// Compiled with full optimization (tier 2).
    Optimized,
}

/// Profile data for a guest code block.
#[derive(Debug, Clone)]
pub struct BlockProfile {
    pub guest_address: u64,
    pub execution_count: u64,
    pub tier: CompilationTier,
    pub last_compiled: Option<Instant>,
    pub compile_time_us: u64,
    pub instruction_count: usize,
}

/// Lazy JIT compiler with profile-guided tiered compilation.
///
/// Blocks start uncompiled (interpreted). After exceeding the hot threshold,
/// they are compiled at the baseline tier. After exceeding the optimization
/// threshold, they are recompiled at the optimized tier.
pub struct LazyJitProfiler {
    profiles: HashMap<u64, BlockProfile>,
    /// Execution count threshold for baseline compilation.
    hot_threshold: u64,
    /// Execution count threshold for optimized compilation.
    optimize_threshold: u64,
    /// Total time spent compiling (microseconds).
    total_compile_time_us: AtomicU64,
    /// Number of blocks compiled.
    total_compiled: AtomicU32,
}

impl LazyJitProfiler {
    pub fn new(hot_threshold: u64, optimize_threshold: u64) -> Self {
        Self {
            profiles: HashMap::new(),
            hot_threshold,
            optimize_threshold,
            total_compile_time_us: AtomicU64::new(0),
            total_compiled: AtomicU32::new(0),
        }
    }

    /// Record a block execution. Returns the recommended compilation tier.
    pub fn record_execution(&mut self, guest_address: u64, instruction_count: usize) -> CompilationTier {
        let profile = self.profiles.entry(guest_address).or_insert_with(|| BlockProfile {
            guest_address,
            execution_count: 0,
            tier: CompilationTier::Uncompiled,
            last_compiled: None,
            compile_time_us: 0,
            instruction_count,
        });

        profile.execution_count += 1;

        let recommended_tier = if profile.execution_count >= self.optimize_threshold {
            CompilationTier::Optimized
        } else if profile.execution_count >= self.hot_threshold {
            CompilationTier::Baseline
        } else {
            CompilationTier::Uncompiled
        };

        recommended_tier
    }

    /// Mark a block as compiled at a given tier.
    pub fn mark_compiled(&mut self, guest_address: u64, tier: CompilationTier, compile_time_us: u64) {
        self.total_compile_time_us.fetch_add(compile_time_us, Ordering::Relaxed);
        self.total_compiled.fetch_add(1, Ordering::Relaxed);
        if let Some(profile) = self.profiles.get_mut(&guest_address) {
            profile.tier = tier;
            profile.last_compiled = Some(Instant::now());
            profile.compile_time_us += compile_time_us;
        }
    }

    /// Get the profile for a block.
    pub fn get_profile(&self, guest_address: u64) -> Option<&BlockProfile> {
        self.profiles.get(&guest_address)
    }

    /// Get the compilation tier for a block.
    pub fn get_tier(&self, guest_address: u64) -> CompilationTier {
        self.profiles.get(&guest_address).map(|p| p.tier).unwrap_or(CompilationTier::Uncompiled)
    }

    /// Get the total number of profiled blocks.
    pub fn profiled_count(&self) -> usize {
        self.profiles.len()
    }

    /// Get the number of blocks at each tier.
    pub fn tier_counts(&self) -> (usize, usize, usize) {
        let mut uncompiled = 0;
        let mut baseline = 0;
        let mut optimized = 0;
        for profile in self.profiles.values() {
            match profile.tier {
                CompilationTier::Uncompiled => uncompiled += 1,
                CompilationTier::Baseline => baseline += 1,
                CompilationTier::Optimized => optimized += 1,
            }
        }
        (uncompiled, baseline, optimized)
    }

    /// Get the total compile time in microseconds.
    pub fn total_compile_time_us(&self) -> u64 {
        self.total_compile_time_us.load(Ordering::Relaxed)
    }

    /// Get the total number of compiled blocks.
    pub fn total_compiled(&self) -> u32 {
        self.total_compiled.load(Ordering::Relaxed)
    }
}

// ===========================================================================
// Memory Access Translation Cache
// ===========================================================================

/// A cached guest-to-host address translation.
#[derive(Debug, Clone)]
pub struct AddressTranslation {
    pub guest_address: u64,
    pub host_address: u64,
    pub size: usize,
    pub protection: u32,
    pub hits: u64,
    /// Access count for LRU eviction tracking.
    pub access_count: u64,
}

/// Cache for guest-to-host address translations.
///
/// Avoids repeated page table walks by caching the most recent translations.
pub struct AddressTranslationCache {
    translations: HashMap<u64, AddressTranslation>,
    /// Maximum cache entries before eviction.
    max_entries: usize,
    total_hits: AtomicU64,
    total_misses: AtomicU64,
}

impl AddressTranslationCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            translations: HashMap::new(),
            max_entries,
            total_hits: AtomicU64::new(0),
            total_misses: AtomicU64::new(0),
        }
    }

    /// Look up a guest address in the cache.
    ///
    /// Increments the access counter for LRU tracking.
    pub fn lookup(&mut self, guest_address: u64) -> Option<&AddressTranslation> {
        // Check existence first to avoid borrow conflicts
        if self.translations.contains_key(&guest_address) {
            if let Some(entry) = self.translations.get_mut(&guest_address) {
                entry.access_count += 1;
                entry.hits += 1;
            }
        }
        // Return immutable reference (mutable borrow is released)
        self.translations.get(&guest_address)
    }

    /// Insert a translation into the cache.
    ///
    /// Evicts the least-recently-used entry (lowest `access_count`) when the
    /// cache is at capacity.
    pub fn insert(&mut self, guest_address: u64, host_address: u64, size: usize, protection: u32) {
        // Evict the LRU entry if at capacity
        if self.translations.len() >= self.max_entries && !self.translations.contains_key(&guest_address) {
            if let Some((&lru_key, _)) = self
                .translations
                .iter()
                .min_by_key(|(_, v)| v.access_count)
            {
                self.translations.remove(&lru_key);
            }
        }

        self.translations.insert(
            guest_address,
            AddressTranslation {
                guest_address,
                host_address,
                size,
                protection,
                hits: 0,
                access_count: 0,
            },
        );
    }

    /// Record a cache hit.
    pub fn record_hit(&self) {
        self.total_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss.
    pub fn record_miss(&self) {
        self.total_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the cache hit rate (0.0 to 1.0).
    pub fn hit_rate(&self) -> f64 {
        let hits = self.total_hits.load(Ordering::Relaxed) as f64;
        let misses = self.total_misses.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        if total == 0.0 {
            0.0
        } else {
            hits / total
        }
    }

    /// Get the number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.translations.len()
    }

    /// Invalidate all entries.
    pub fn invalidate_all(&mut self) {
        self.translations.clear();
    }

    /// Invalidate entries for a specific address range.
    pub fn invalidate_range(&mut self, start: u64, end: u64) {
        self.translations.retain(|_, t| t.guest_address < start || t.guest_address >= end);
    }
}

// ===========================================================================
// Parallel Shader Compilation
// ===========================================================================

/// Status of a shader compilation job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShaderCompileStatus {
    Pending,
    Compiling,
    Completed,
    Failed(String),
}

/// A shader compilation job.
#[derive(Debug, Clone)]
pub struct ShaderCompileJob {
    pub id: u64,
    pub shader_hash: String,
    pub stage: String,
    pub entry_point: String,
    pub status: ShaderCompileStatus,
    pub submit_time: Instant,
    pub complete_time: Option<Instant>,
}

/// Manages parallel shader compilation.
///
/// Shader compilation is CPU-intensive and can be parallelized across
/// multiple threads. Jobs are submitted to a queue and processed in order.
pub struct ParallelShaderCompiler {
    jobs: BTreeMap<u64, ShaderCompileJob>,
    next_job_id: AtomicU64,
    max_concurrent: usize,
    completed_count: AtomicU32,
    failed_count: AtomicU32,
}

impl ParallelShaderCompiler {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            jobs: BTreeMap::new(),
            next_job_id: AtomicU64::new(1),
            max_concurrent,
            completed_count: AtomicU32::new(0),
            failed_count: AtomicU32::new(0),
        }
    }

    /// Submit a shader compilation job.
    pub fn submit_job(&mut self, shader_hash: String, stage: String, entry_point: String) -> u64 {
        let id = self.next_job_id.fetch_add(1, Ordering::Relaxed);
        self.jobs.insert(id, ShaderCompileJob {
            id,
            shader_hash,
            stage,
            entry_point,
            status: ShaderCompileStatus::Pending,
            submit_time: Instant::now(),
            complete_time: None,
        });
        id
    }

    /// Mark a job as compiling.
    pub fn mark_compiling(&mut self, job_id: u64) -> AppResult<()> {
        let job = self.jobs.get_mut(&job_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcDxilInvalid, format!("shader job {job_id} not found"))
        })?;
        job.status = ShaderCompileStatus::Compiling;
        Ok(())
    }

    /// Mark a job as completed.
    pub fn mark_completed(&mut self, job_id: u64) -> AppResult<()> {
        let job = self.jobs.get_mut(&job_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcDxilInvalid, format!("shader job {job_id} not found"))
        })?;
        job.status = ShaderCompileStatus::Completed;
        job.complete_time = Some(Instant::now());
        self.completed_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Mark a job as failed.
    pub fn mark_failed(&mut self, job_id: u64, error: String) -> AppResult<()> {
        let job = self.jobs.get_mut(&job_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcDxilInvalid, format!("shader job {job_id} not found"))
        })?;
        job.status = ShaderCompileStatus::Failed(error);
        job.complete_time = Some(Instant::now());
        self.failed_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Get pending jobs that can be started (up to max_concurrent).
    pub fn pending_jobs(&self) -> Vec<&ShaderCompileJob> {
        let compiling_count = self.jobs.values()
            .filter(|j| j.status == ShaderCompileStatus::Compiling)
            .count();
        let available = self.max_concurrent.saturating_sub(compiling_count);

        self.jobs.values()
            .filter(|j| j.status == ShaderCompileStatus::Pending)
            .take(available)
            .collect()
    }

    /// Get a job by ID.
    pub fn get_job(&self, job_id: u64) -> Option<&ShaderCompileJob> {
        self.jobs.get(&job_id)
    }

    /// Get the total number of jobs.
    pub fn job_count(&self) -> usize {
        self.jobs.len()
    }

    /// Get the number of completed jobs.
    pub fn completed_count(&self) -> u32 {
        self.completed_count.load(Ordering::Relaxed)
    }

    /// Get the number of failed jobs.
    pub fn failed_count(&self) -> u32 {
        self.failed_count.load(Ordering::Relaxed)
    }
}

// ===========================================================================
// Metal Command Batching
// ===========================================================================

/// A batched draw call group.
#[derive(Debug, Clone)]
pub struct DrawBatch {
    pub pipeline_state_id: u64,
    pub draw_calls: Vec<BatchedDrawCall>,
    pub total_vertices: u32,
    pub total_indices: u32,
}

impl DrawBatch {
    fn with_capacity(pipeline_state_id: u64, capacity: usize) -> Self {
        Self {
            pipeline_state_id,
            draw_calls: Vec::with_capacity(capacity),
            total_vertices: 0,
            total_indices: 0,
        }
    }
}

/// A single draw call within a batch.
#[derive(Debug, Clone)]
pub struct BatchedDrawCall {
    pub vertex_count: u32,
    pub index_count: u32,
    pub instance_count: u32,
    pub start_vertex: u32,
    pub base_index: u32,
}

/// Statistics for Metal command batching.
#[derive(Debug, Clone, Default)]
pub struct BatchingStats {
    pub total_draw_calls: u64,
    pub batched_draw_calls: u64,
    pub render_pass_breaks: u64,
    pub pipeline_changes: u64,
    pub vertices_drawn: u64,
    pub indices_drawn: u64,
}

/// Batches Metal draw calls to minimize render pass breaks and pipeline changes.
pub struct MetalCommandBatcher {
    current_pipeline: Option<u64>,
    current_batch: Option<DrawBatch>,
    completed_batches: Vec<DrawBatch>,
    stats: BatchingStats,
    max_batch_size: usize,
}

impl MetalCommandBatcher {
    pub fn new(max_batch_size: usize) -> Self {
        Self {
            current_pipeline: None,
            current_batch: None,
            completed_batches: Vec::new(),
            stats: BatchingStats::default(),
            max_batch_size,
        }
    }

    /// Record a draw call. Automatically batches with the current pipeline state.
    pub fn record_draw(
        &mut self,
        pipeline_state_id: u64,
        vertex_count: u32,
        index_count: u32,
        instance_count: u32,
        start_vertex: u32,
        base_index: u32,
    ) {
        self.stats.total_draw_calls += 1;
        self.stats.vertices_drawn += vertex_count as u64 * instance_count as u64;
        self.stats.indices_drawn += index_count as u64 * instance_count as u64;

        // Check if we need to flush the current batch
        let pipeline_changed = self.current_pipeline != Some(pipeline_state_id);
        if pipeline_changed {
            self.flush_current_batch();
            self.stats.pipeline_changes += 1;
            self.current_pipeline = Some(pipeline_state_id);
        }

        // Add to current batch (pre-allocate to avoid repeated resizing)
        let batch = self.current_batch.get_or_insert_with(|| {
            DrawBatch::with_capacity(pipeline_state_id, self.max_batch_size)
        });

        batch.draw_calls.push(BatchedDrawCall {
            vertex_count,
            index_count,
            instance_count,
            start_vertex,
            base_index,
        });
        batch.total_vertices += vertex_count;
        batch.total_indices += index_count;
        self.stats.batched_draw_calls += 1;

        // Flush if batch is full
        if batch.draw_calls.len() >= self.max_batch_size {
            self.flush_current_batch();
        }
    }

    /// Flush the current batch, starting a new render pass.
    pub fn flush_current_batch(&mut self) {
        if let Some(batch) = self.current_batch.take() {
            if !batch.draw_calls.is_empty() {
                self.completed_batches.push(batch);
                self.stats.render_pass_breaks += 1;
            }
        }
    }

    /// Get completed batches and reset.
    pub fn drain_batches(&mut self) -> Vec<DrawBatch> {
        self.flush_current_batch();
        std::mem::take(&mut self.completed_batches)
    }

    /// Get the batching statistics.
    pub fn stats(&self) -> &BatchingStats {
        &self.stats
    }

    /// Get the average batch size.
    pub fn average_batch_size(&self) -> f64 {
        if self.stats.render_pass_breaks == 0 {
            0.0
        } else {
            self.stats.batched_draw_calls as f64 / self.stats.render_pass_breaks as f64
        }
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = BatchingStats::default();
    }
}

// ===========================================================================
// GPU Upload Streaming
// ===========================================================================

/// A persistent mapped buffer for streaming data to the GPU.
#[derive(Debug, Clone)]
pub struct StreamingBuffer {
    pub id: u64,
    pub size: usize,
    pub frame_used: u64,
    pub write_offset: usize,
    pub total_uploaded: u64,
}

/// Manages persistent mapped buffers for GPU upload streaming.
///
/// Instead of creating new buffers for each frame's dynamic data, pre-allocate
/// a ring buffer and sub-allocate from it each frame.
pub struct GpuUploadStreamer {
    buffers: HashMap<u64, StreamingBuffer>,
    next_buffer_id: AtomicU64,
    current_frame: AtomicU64,
    ring_buffer_size: usize,
    total_bytes_uploaded: AtomicU64,
}

impl GpuUploadStreamer {
    pub fn new(ring_buffer_size: usize) -> Self {
        Self {
            buffers: HashMap::new(),
            next_buffer_id: AtomicU64::new(1),
            current_frame: AtomicU64::new(0),
            ring_buffer_size,
            total_bytes_uploaded: AtomicU64::new(0),
        }
    }

    /// Create a new streaming buffer.
    pub fn create_streaming_buffer(&mut self, size: usize) -> u64 {
        let id = self.next_buffer_id.fetch_add(1, Ordering::Relaxed);
        let frame = self.current_frame.load(Ordering::Relaxed);
        self.buffers.insert(id, StreamingBuffer {
            id,
            size,
            frame_used: frame,
            write_offset: 0,
            total_uploaded: 0,
        });
        id
    }

    /// Allocate space from a streaming buffer for the current frame.
    pub fn allocate(&mut self, buffer_id: u64, size: usize) -> AppResult<usize> {
        let buffer = self.buffers.get_mut(&buffer_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("streaming buffer {buffer_id} not found"))
        })?;

        let frame = self.current_frame.load(Ordering::Relaxed);

        // Reset write offset on new frame
        if buffer.frame_used != frame {
            buffer.write_offset = 0;
            buffer.frame_used = frame;
        }

        // Check if there's enough space in the buffer
        if buffer.write_offset + size > buffer.size {
            // Wrap around if possible
            if size <= buffer.size {
                buffer.write_offset = 0;
            } else {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("streaming allocation {size} exceeds buffer size {}", buffer.size),
                ));
            }
        }

        // Validate that the allocation does not exceed the ring buffer total
        if buffer.write_offset + size > self.ring_buffer_size {
            if size <= self.ring_buffer_size {
                buffer.write_offset = 0;
            } else {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "streaming allocation {size} exceeds ring buffer size {}",
                        self.ring_buffer_size
                    ),
                ));
            }
        }

        let offset = buffer.write_offset;
        buffer.write_offset += size;
        buffer.total_uploaded += size as u64;
        self.total_bytes_uploaded.fetch_add(size as u64, Ordering::Relaxed);

        Ok(offset)
    }

    /// Advance to the next frame.
    pub fn advance_frame(&self) {
        self.current_frame.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the ring buffer size in bytes.
    pub fn ring_buffer_size(&self) -> usize {
        self.ring_buffer_size
    }

    /// Get the current frame number.
    pub fn current_frame(&self) -> u64 {
        self.current_frame.load(Ordering::Relaxed)
    }

    /// Get the total bytes uploaded.
    pub fn total_bytes_uploaded(&self) -> u64 {
        self.total_bytes_uploaded.load(Ordering::Relaxed)
    }

    /// Get the number of streaming buffers.
    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }

    /// Destroy a streaming buffer.
    pub fn destroy_buffer(&mut self, buffer_id: u64) {
        self.buffers.remove(&buffer_id);
    }
}

// ===========================================================================
// Frame Pacing
// ===========================================================================

/// Frame pacing configuration.
#[derive(Debug, Clone)]
pub struct FramePacingConfig {
    /// Target FPS (e.g., 60).
    pub target_fps: u32,
    /// Whether vsync is enabled.
    pub vsync_enabled: bool,
    /// Maximum frame latency (1 = single buffer, 2 = double, 3 = triple).
    pub max_frame_latency: u32,
}

impl Default for FramePacingConfig {
    fn default() -> Self {
        Self {
            target_fps: 60,
            vsync_enabled: true,
            max_frame_latency: 2,
        }
    }
}

/// Frame timing statistics.
#[derive(Debug, Clone, Default)]
pub struct FrameTimingStats {
    pub frames_rendered: u64,
    pub frames_dropped: u64,
    pub total_frame_time_ms: f64,
    pub min_frame_time_ms: f64,
    pub max_frame_time_ms: f64,
    pub last_frame_time_ms: f64,
}

/// Manages frame pacing for smooth rendering.
///
/// Aligns frame presentation with vsync intervals and manages the swap
/// chain latency to achieve the target frame rate.
pub struct FramePacer {
    config: FramePacingConfig,
    stats: FrameTimingStats,
    last_frame_start: Option<Instant>,
    frame_history: VecDeque<f64>, // Last N frame times in ms
    max_history: usize,
}

impl FramePacer {
    pub fn new(config: FramePacingConfig) -> Self {
        Self {
            config,
            stats: FrameTimingStats {
                min_frame_time_ms: f64::MAX,
                max_frame_time_ms: 0.0,
                ..Default::default()
            },
            last_frame_start: None,
            frame_history: VecDeque::new(),
            max_history: 120,
        }
    }

    /// Begin a new frame. Returns the time since last frame start.
    pub fn begin_frame(&mut self) -> Duration {
        let now = Instant::now();
        let delta = self.last_frame_start
            .map(|last| now.duration_since(last))
            .unwrap_or(Duration::ZERO);
        self.last_frame_start = Some(now);
        delta
    }

    /// End the current frame and record timing.
    pub fn end_frame(&mut self) {
        if let Some(start) = self.last_frame_start {
            let elapsed = start.elapsed();
            let frame_time_ms = elapsed.as_secs_f64() * 1000.0;

            self.stats.frames_rendered += 1;
            self.stats.total_frame_time_ms += frame_time_ms;
            self.stats.last_frame_time_ms = frame_time_ms;
            self.stats.min_frame_time_ms = self.stats.min_frame_time_ms.min(frame_time_ms);
            self.stats.max_frame_time_ms = self.stats.max_frame_time_ms.max(frame_time_ms);

            self.frame_history.push_back(frame_time_ms);
            if self.frame_history.len() > self.max_history {
                self.frame_history.pop_front();
            }

            // Check if frame was too slow (dropped)
            let target_ms = 1000.0 / self.config.target_fps as f64;
            if frame_time_ms > target_ms * 1.5 {
                self.stats.frames_dropped += 1;
            }
        }
    }

    /// Calculate the sleep time needed to maintain target FPS.
    pub fn frame_remaining_time(&self) -> Duration {
        let target_ms = 1000.0 / self.config.target_fps as f64;
        if let Some(start) = self.last_frame_start {
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            let remaining_ms = target_ms - elapsed_ms;
            if remaining_ms > 0.0 {
                Duration::from_secs_f64(remaining_ms / 1000.0)
            } else {
                Duration::ZERO
            }
        } else {
            Duration::ZERO
        }
    }

    /// Get the current average FPS.
    pub fn average_fps(&self) -> f64 {
        if self.stats.frames_rendered == 0 {
            return 0.0;
        }
        let avg_frame_time = self.stats.total_frame_time_ms / self.stats.frames_rendered as f64;
        if avg_frame_time > 0.0 {
            1000.0 / avg_frame_time
        } else {
            0.0
        }
    }

    /// Get the 1% low FPS (worst 1% of frames).
    pub fn one_percent_low_fps(&self) -> f64 {
        if self.frame_history.is_empty() {
            return 0.0;
        }
        let mut times: Vec<f64> = self.frame_history.iter().copied().collect();
        times.sort_by(|a, b| b.partial_cmp(a).unwrap()); // Descending
        let count = (times.len() as f64 * 0.01).max(1.0) as usize;
        let worst: f64 = times[..count].iter().sum();
        1000.0 / (worst / count as f64)
    }

    /// Get the frame timing statistics.
    pub fn stats(&self) -> &FrameTimingStats {
        &self.stats
    }

    /// Get the frame pacing configuration.
    pub fn config(&self) -> &FramePacingConfig {
        &self.config
    }

    /// Update the frame pacing configuration.
    pub fn set_config(&mut self, config: FramePacingConfig) {
        self.config = config;
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = FrameTimingStats {
            min_frame_time_ms: f64::MAX,
            max_frame_time_ms: 0.0,
            ..Default::default()
        };
        self.frame_history.clear();
        self.last_frame_start = None;
    }
}

// ===========================================================================
// Phase 7: Async File I/O
// ===========================================================================

/// A pending async read request.
#[derive(Debug, Clone)]
pub struct PendingRead {
    /// File path to read from.
    pub path: PathBuf,
    /// Byte offset within the file.
    pub offset: u64,
    /// Number of bytes to read.
    pub size: usize,
}

/// A completed async read result.
#[derive(Debug, Clone)]
pub struct CompletedRead {
    /// Data read from the file.
    pub data: Vec<u8>,
    /// Time taken for the read in microseconds.
    pub elapsed_us: u64,
}

/// Manages asynchronous file read operations.
///
/// # Performance Impact
/// Synchronous file I/O blocks the calling thread, wasting CPU cycles while
/// waiting for disk. By submitting reads asynchronously, the main emulation
/// thread can continue executing guest code while I/O happens in the
/// background, reducing frame stalls during asset loading.
pub struct AsyncFileReader {
    /// Pending read requests keyed by request ID.
    pub pending_reads: BTreeMap<u64, PendingRead>,
    /// Completed read results keyed by request ID.
    pub completed_reads: BTreeMap<u64, CompletedRead>,
    /// Next unique request ID.
    pub next_request_id: u64,
    /// Thread handles for in-flight async reads.
    handles: HashMap<u64, std::thread::JoinHandle<CompletedRead>>,
}

impl AsyncFileReader {
    /// Create a new async file reader.
    pub fn new() -> Self {
        Self {
            pending_reads: BTreeMap::new(),
            completed_reads: BTreeMap::new(),
            next_request_id: 1,
            handles: HashMap::new(),
        }
    }

    /// Submit an asynchronous read request.
    ///
    /// Returns the unique request ID that can be used to poll for completion.
    /// The read is performed on a background thread, allowing the caller to
    /// continue execution while I/O completes.
    pub fn submit_read(&mut self, path: PathBuf, offset: u64, size: usize) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;

        self.pending_reads.insert(
            id,
            PendingRead {
                path: path.clone(),
                offset,
                size,
            },
        );

        let handle = std::thread::spawn(move || {
            let start = Instant::now();
            let data = match std::fs::read(&path) {
                Ok(contents) => {
                    let start_idx = offset as usize;
                    let end_idx = (offset as usize).saturating_add(size).min(contents.len());
                    if start_idx < contents.len() {
                        contents[start_idx..end_idx].to_vec()
                    } else {
                        Vec::new()
                    }
                }
                Err(_) => Vec::new(),
            };
            let elapsed_us = start.elapsed().as_micros() as u64;

            CompletedRead { data, elapsed_us }
        });

        self.handles.insert(id, handle);
        id
    }

    /// Poll for completed reads.
    ///
    /// Returns all completed reads as `(request_id, data)` pairs and removes
    /// them from the completed queue.
    pub fn poll_completed(&mut self) -> Vec<(u64, Vec<u8>)> {
        let ids: Vec<u64> = self.completed_reads.keys().copied().collect();
        let mut results = Vec::new();
        for id in ids {
            if let Some(completed) = self.completed_reads.remove(&id) {
                results.push((id, completed.data));
            }
        }
        results
    }

    /// Wait for a specific read request to complete.
    ///
    /// Blocks until the background thread completes the read and returns
    /// the data. The `timeout_ms` parameter is preserved for API compatibility.
    pub fn wait_for(&mut self, request_id: u64, _timeout_ms: u64) -> AppResult<Vec<u8>> {
        // If the result is already available from a previous join, return it
        if let Some(completed) = self.completed_reads.remove(&request_id) {
            return Ok(completed.data);
        }

        // Join the background thread if it's still running
        if let Some(handle) = self.handles.remove(&request_id) {
            match handle.join() {
                Ok(completed) => {
                    let data = completed.data.clone();
                    self.completed_reads.insert(request_id, completed);
                    Ok(data)
                }
                Err(_) => Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("async read {request_id}: thread panicked"),
                )),
            }
        } else {
            Err(AppError::new(
                ReasonCode::RcWin32Timeout,
                format!("async read {request_id} not found"),
            ))
        }
    }
}

// ===========================================================================
// Phase 7: File Caching
// ===========================================================================

/// A cached file entry.
#[derive(Debug, Clone)]
pub struct FileCacheEntry {
    /// Cached file data.
    pub data: Vec<u8>,
    /// Timestamp of last access (monotonic counter).
    pub last_access: u64,
    /// Number of times this entry has been accessed.
    pub access_count: u64,
}

/// Caches frequently accessed file data in memory.
///
/// # Performance Impact
/// Game engines often read the same files repeatedly (configuration, shaders,
/// texture headers). Caching eliminates redundant disk I/O and filesystem
/// overhead, reducing latency for hot-path file accesses from milliseconds
/// to nanoseconds.
pub struct FileCache {
    /// Cached entries keyed by file path.
    pub entries: BTreeMap<String, FileCacheEntry>,
    /// Maximum total cache size in bytes.
    pub max_size_bytes: usize,
    /// Currently used bytes.
    pub used_bytes: usize,
    /// Total cache hits.
    pub hits: u64,
    /// Total cache misses.
    pub misses: u64,
    /// Monotonic access counter for LRU tracking.
    access_counter: u64,
}

impl FileCache {
    /// Create a new file cache with the given maximum size in bytes.
    pub fn new(max_size_bytes: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_size_bytes,
            used_bytes: 0,
            hits: 0,
            misses: 0,
            access_counter: 0,
        }
    }

    /// Get cached file data by path.
    ///
    /// Returns `Some(data)` on cache hit, `None` on miss.
    pub fn get(&mut self, path: &str) -> Option<&[u8]> {
        self.access_counter += 1;
        if let Some(entry) = self.entries.get_mut(path) {
            entry.last_access = self.access_counter;
            entry.access_count += 1;
            self.hits += 1;
            Some(&entry.data)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert file data into the cache.
    ///
    /// If the cache is full, LRU entries are evicted until there is enough
    /// space. Returns an error if the data is larger than the entire cache.
    pub fn insert(&mut self, path: &str, data: Vec<u8>) -> AppResult<()> {
        let data_len = data.len();
        if data_len > self.max_size_bytes {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("file cache: data size {data_len} exceeds max cache size {}", self.max_size_bytes),
            ));
        }

        // Remove old entry if present
        if let Some(old) = self.entries.remove(path) {
            self.used_bytes = self.used_bytes.saturating_sub(old.data.len());
        }

        // Evict LRU entries until we have space
        while self.used_bytes + data_len > self.max_size_bytes && !self.entries.is_empty() {
            let lru_key = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone());
            if let Some(key) = lru_key {
                if let Some(old) = self.entries.remove(&key) {
                    self.used_bytes = self.used_bytes.saturating_sub(old.data.len());
                }
            }
        }

        self.access_counter += 1;
        self.used_bytes += data_len;
        self.entries.insert(
            path.to_string(),
            FileCacheEntry {
                data,
                last_access: self.access_counter,
                access_count: 0,
            },
        );

        Ok(())
    }

    /// Invalidate a specific cached file.
    pub fn invalidate(&mut self, path: &str) {
        if let Some(old) = self.entries.remove(path) {
            self.used_bytes = self.used_bytes.saturating_sub(old.data.len());
        }
    }

    /// Invalidate all cached files.
    pub fn invalidate_all(&mut self) {
        self.entries.clear();
        self.used_bytes = 0;
    }

    /// Get cache statistics: (hits, misses, hit_rate).
    pub fn stats(&self) -> (u64, u64, f64) {
        let total = self.hits + self.misses;
        let rate = if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        };
        (self.hits, self.misses, rate)
    }

    /// Get the number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ===========================================================================
// Phase 7: Path Resolution Caching
// ===========================================================================

/// Caches resolved filesystem paths to avoid repeated string operations.
///
/// # Performance Impact
/// Path resolution involves string manipulation, component joining, and
/// potentially filesystem stat calls. By caching resolved paths, we avoid
/// redundant string allocations and filesystem queries for frequently
/// accessed paths.
pub struct PathResolutionCache {
    /// Resolved paths: guest_path → host_path.
    pub cache: BTreeMap<String, PathBuf>,
    /// Total cache hits.
    pub hits: u64,
    /// Total cache misses.
    pub misses: u64,
}

impl PathResolutionCache {
    /// Create a new path resolution cache.
    pub fn new() -> Self {
        Self {
            cache: BTreeMap::new(),
            hits: 0,
            misses: 0,
        }
    }

    /// Resolve a guest path, using the cache when possible.
    ///
    /// On a cache hit, returns the cached host path directly. On a miss,
    /// calls the resolver function and caches the result.
    pub fn resolve<F>(&mut self, guest_path: &str, resolver: F) -> AppResult<PathBuf>
    where
        F: FnOnce(&str) -> AppResult<PathBuf>,
    {
        if let Some(resolved) = self.cache.get(guest_path) {
            self.hits += 1;
            return Ok(resolved.clone());
        }

        self.misses += 1;
        let resolved = resolver(guest_path)?;
        self.cache.insert(guest_path.to_string(), resolved.clone());
        Ok(resolved)
    }

    /// Invalidate a specific cached path.
    pub fn invalidate(&mut self, guest_path: &str) {
        self.cache.remove(guest_path);
    }

    /// Invalidate all cached paths matching a prefix.
    pub fn invalidate_prefix(&mut self, prefix: &str) {
        let keys_to_remove: Vec<String> = self
            .cache
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        for key in keys_to_remove {
            self.cache.remove(&key);
        }
    }

    /// Get cache statistics: (hits, misses, hit_rate).
    pub fn stats(&self) -> (u64, u64, f64) {
        let total = self.hits + self.misses;
        let rate = if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        };
        (self.hits, self.misses, rate)
    }

    /// Get the number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.cache.len()
    }
}

// ===========================================================================
// Phase 7: Memory-Mapped File Support
// ===========================================================================

/// A memory-mapped file for efficient large file reads.
///
/// # Performance Impact
/// For large files (textures, meshes, audio), `mmap` avoids copying data
/// from kernel space to user space. The kernel maps file pages directly
/// into the process address space, enabling zero-copy reads and lazy
/// page-in that reduces peak memory usage.
pub struct MmappedFile {
    /// File path.
    pub path: PathBuf,
    /// Size of the mapped region in bytes.
    pub size: usize,
    /// Pointer to the mapped memory.
    pub ptr: *mut u8,
    /// Whether the file is currently mapped.
    pub mapped: bool,
}

// Safety: MmappedFile is safe to send between threads as long as no two
// threads mutate the mapping simultaneously. The read method only requires
// &self, so concurrent reads are safe.
unsafe impl Send for MmappedFile {}
unsafe impl Sync for MmappedFile {}

impl MmappedFile {
    /// Open a file and memory-map it.
    ///
    /// The entire file is mapped into the process address space. Pages are
    /// loaded on demand (lazy page-in).
    pub fn open(path: &Path) -> AppResult<Self> {
        let file = std::fs::File::open(path).map_err(|e| {
            AppError::from_io(ReasonCode::RcIo, format!("mmap: failed to open {}", path.display()), &e)
        })?;

        let metadata = file.metadata().map_err(|e| {
            AppError::from_io(ReasonCode::RcIo, format!("mmap: failed to stat {}", path.display()), &e)
        })?;

        let size = metadata.len() as usize;

        if size == 0 {
            return Ok(Self {
                path: path.to_path_buf(),
                size: 0,
                ptr: std::ptr::null_mut(),
                mapped: false,
            });
        }

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("mmap: failed to mmap {}", path.display()),
            ));
        }

        Ok(Self {
            path: path.to_path_buf(),
            size,
            ptr: ptr as *mut u8,
            mapped: true,
        })
    }

    /// Read bytes from the mapped memory at the given offset.
    ///
    /// Copies `buf.len()` bytes starting at `offset` from the mapped region
    /// into the provided buffer.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> AppResult<()> {
        if !self.mapped || self.ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcIo,
                "mmap: file is not mapped",
            ));
        }

        if offset.saturating_add(buf.len()) > self.size {
            return Err(AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!("mmap: read at offset {offset} + {} exceeds file size {}", buf.len(), self.size),
            ));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), buf.len());
        }

        Ok(())
    }

    /// Close the memory mapping.
    ///
    /// Unmaps the file and resets the internal state. Must be called before
    /// drop to release the mapping explicitly (though Drop also handles it).
    pub fn close(&mut self) {
        if self.mapped && !self.ptr.is_null() {
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.size);
            }
            self.ptr = std::ptr::null_mut();
            self.mapped = false;
        }
    }
}

impl Drop for MmappedFile {
    fn drop(&mut self) {
        self.close();
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Block Chaining Tests ---

    #[test]
    fn block_chaining_register_and_execute() {
        let mut cache = BlockChainingCache::new();
        cache.register_block(0x1000, 0x2000, 64, 10);
        cache.register_block(0x2000, 0x3000, 32, 5);

        assert_eq!(cache.block_count(), 2);

        // Execute 10 times to reach hot threshold
        for _ in 0..10 {
            cache.record_execution(0x1000, 0x2000).unwrap();
        }

        let block = cache.get_block(0x1000).unwrap();
        assert_eq!(block.execution_count, 10);
        assert_eq!(block.fallthrough_target, Some(0x2000));
    }

    #[test]
    fn block_chaining_creates_chain() {
        let mut cache = BlockChainingCache::new();
        cache.register_block(0x1000, 0x2000, 64, 10);
        cache.register_block(0x2000, 0x3000, 32, 5);

        for _ in 0..10 {
            cache.record_execution(0x1000, 0x2000).unwrap();
        }

        let chained = cache.try_chain(0x1000);
        assert!(chained);
        assert_eq!(cache.active_chain_count(), 1);
    }

    #[test]
    fn block_chaining_no_chain_for_cold_block() {
        let mut cache = BlockChainingCache::new();
        cache.register_block(0x1000, 0x2000, 64, 10);
        cache.register_block(0x2000, 0x3000, 32, 5);

        for _ in 0..5 {
            cache.record_execution(0x1000, 0x2000).unwrap();
        }

        let chained = cache.try_chain(0x1000);
        assert!(!chained);
        assert_eq!(cache.active_chain_count(), 0);
    }

    #[test]
    fn block_chaining_break_chain() {
        let mut cache = BlockChainingCache::new();
        cache.register_block(0x1000, 0x2000, 64, 10);
        cache.register_block(0x2000, 0x3000, 32, 5);

        for _ in 0..10 {
            cache.record_execution(0x1000, 0x2000).unwrap();
        }
        cache.try_chain(0x1000);
        assert_eq!(cache.active_chain_count(), 1);

        cache.break_chain(0x1000);
        assert_eq!(cache.active_chain_count(), 0);
        assert_eq!(cache.total_chains_broken(), 1);
    }

    #[test]
    fn block_chaining_invalidate_range() {
        let mut cache = BlockChainingCache::new();
        cache.register_block(0x1000, 0x2000, 64, 10);
        cache.register_block(0x2000, 0x3000, 32, 5);
        cache.register_block(0x3000, 0x4000, 48, 8);

        cache.invalidate_range(0x1500, 0x2500);
        assert_eq!(cache.block_count(), 2); // 0x1000 and 0x3000 remain
    }

    #[test]
    fn block_chaining_hot_blocks() {
        let mut cache = BlockChainingCache::new();
        cache.register_block(0x1000, 0x2000, 64, 10);
        cache.register_block(0x2000, 0x3000, 32, 5);

        for _ in 0..50 {
            cache.record_execution(0x1000, 0x2000).unwrap();
        }
        for _ in 0..5 {
            cache.record_execution(0x2000, 0x3000).unwrap();
        }

        let hot = cache.hot_blocks(20);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].guest_address, 0x1000);
    }

    // --- Lazy JIT Tests ---

    #[test]
    fn lazy_jit_tier_progression() {
        let mut profiler = LazyJitProfiler::new(10, 100);

        // Below hot threshold
        let tier = profiler.record_execution(0x1000, 5);
        assert_eq!(tier, CompilationTier::Uncompiled);

        // At hot threshold
        for _ in 0..9 {
            profiler.record_execution(0x1000, 5);
        }
        let tier = profiler.record_execution(0x1000, 5);
        assert_eq!(tier, CompilationTier::Baseline);

        // At optimize threshold
        for _ in 0..90 {
            profiler.record_execution(0x1000, 5);
        }
        let tier = profiler.record_execution(0x1000, 5);
        assert_eq!(tier, CompilationTier::Optimized);
    }

    #[test]
    fn lazy_jit_profiled_count() {
        let mut profiler = LazyJitProfiler::new(10, 100);
        profiler.record_execution(0x1000, 5);
        profiler.record_execution(0x2000, 3);
        profiler.record_execution(0x3000, 7);

        assert_eq!(profiler.profiled_count(), 3);
    }

    // --- Address Translation Cache Tests ---

    #[test]
    fn address_translation_cache_insert_and_lookup() {
        let mut cache = AddressTranslationCache::new(100);
        cache.insert(0x1000_0000, 0x2000_0000, 4096, 0x07);

        let translation = cache.lookup(0x1000_0000).unwrap();
        assert_eq!(translation.host_address, 0x2000_0000);
        assert_eq!(translation.size, 4096);
    }

    #[test]
    fn address_translation_cache_eviction() {
        let mut cache = AddressTranslationCache::new(3);
        cache.insert(0x1000, 0x2000, 4096, 0);
        cache.insert(0x2000, 0x3000, 4096, 0);
        cache.insert(0x3000, 0x4000, 4096, 0);
        assert_eq!(cache.entry_count(), 3);

        cache.insert(0x4000, 0x5000, 4096, 0);
        assert_eq!(cache.entry_count(), 3); // One was evicted
    }

    #[test]
    fn address_translation_cache_invalidate_range() {
        let mut cache = AddressTranslationCache::new(100);
        cache.insert(0x1000, 0x2000, 4096, 0);
        cache.insert(0x2000, 0x3000, 4096, 0);
        cache.insert(0x3000, 0x4000, 4096, 0);

        cache.invalidate_range(0x1500, 0x2500);
        assert_eq!(cache.entry_count(), 2); // 0x1000 and 0x3000 remain
    }

    #[test]
    fn address_translation_cache_hit_rate() {
        let cache = AddressTranslationCache::new(100);
        assert_eq!(cache.hit_rate(), 0.0);

        cache.record_hit();
        cache.record_hit();
        cache.record_miss();
        assert!((cache.hit_rate() - 0.6667).abs() < 0.01);
    }

    // --- Parallel Shader Compilation Tests ---

    #[test]
    fn shader_compiler_submit_and_complete() {
        let mut compiler = ParallelShaderCompiler::new(4);
        let id = compiler.submit_job("abc123".to_string(), "vertex".to_string(), "main".to_string());
        assert_eq!(compiler.job_count(), 1);

        compiler.mark_compiling(id).unwrap();
        compiler.mark_completed(id).unwrap();

        assert_eq!(compiler.completed_count(), 1);
        let job = compiler.get_job(id).unwrap();
        assert_eq!(job.status, ShaderCompileStatus::Completed);
    }

    #[test]
    fn shader_compiler_failed_job() {
        let mut compiler = ParallelShaderCompiler::new(4);
        let id = compiler.submit_job("def456".to_string(), "fragment".to_string(), "main".to_string());

        compiler.mark_compiling(id).unwrap();
        compiler.mark_failed(id, "syntax error".to_string()).unwrap();

        assert_eq!(compiler.failed_count(), 1);
        let job = compiler.get_job(id).unwrap();
        assert!(matches!(job.status, ShaderCompileStatus::Failed(_)));
    }

    #[test]
    fn shader_compiler_pending_jobs_respects_concurrency() {
        let mut compiler = ParallelShaderCompiler::new(2);
        let id1 = compiler.submit_job("a".to_string(), "vertex".to_string(), "main".to_string());
        let _id2 = compiler.submit_job("b".to_string(), "vertex".to_string(), "main".to_string());
        let _id3 = compiler.submit_job("c".to_string(), "vertex".to_string(), "main".to_string());

        compiler.mark_compiling(id1).unwrap();

        // Only 1 more slot available (2 max - 1 compiling)
        let pending = compiler.pending_jobs();
        assert_eq!(pending.len(), 1);
    }

    // --- Metal Command Batching Tests ---

    #[test]
    fn command_batcher_batches_same_pipeline() {
        let mut batcher = MetalCommandBatcher::new(100);

        batcher.record_draw(1, 100, 0, 1, 0, 0);
        batcher.record_draw(1, 200, 0, 1, 100, 0);
        batcher.record_draw(1, 50, 0, 1, 300, 0);

        let batches = batcher.drain_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].draw_calls.len(), 3);
        assert_eq!(batches[0].total_vertices, 350);
    }

    #[test]
    fn command_batcher_breaks_on_pipeline_change() {
        let mut batcher = MetalCommandBatcher::new(100);

        batcher.record_draw(1, 100, 0, 1, 0, 0);
        batcher.record_draw(1, 200, 0, 1, 0, 0);
        batcher.record_draw(2, 50, 0, 1, 0, 0); // Pipeline change

        let batches = batcher.drain_batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].draw_calls.len(), 2);
        assert_eq!(batches[1].draw_calls.len(), 1);
    }

    #[test]
    fn command_batcher_respects_max_size() {
        let mut batcher = MetalCommandBatcher::new(2);

        batcher.record_draw(1, 100, 0, 1, 0, 0);
        batcher.record_draw(1, 200, 0, 1, 0, 0);
        batcher.record_draw(1, 50, 0, 1, 0, 0); // Should start new batch

        let batches = batcher.drain_batches();
        assert_eq!(batches.len(), 2);
    }

    #[test]
    fn command_batcher_stats() {
        let mut batcher = MetalCommandBatcher::new(100);
        batcher.record_draw(1, 100, 50, 1, 0, 0);
        batcher.record_draw(1, 200, 100, 2, 0, 0);

        let stats = batcher.stats();
        assert_eq!(stats.total_draw_calls, 2);
        assert_eq!(stats.vertices_drawn, 500); // 100*1 + 200*2
        assert_eq!(stats.indices_drawn, 250);  // 50*1 + 100*2
    }

    // --- GPU Upload Streaming Tests ---

    #[test]
    fn upload_streamer_allocate() {
        let mut streamer = GpuUploadStreamer::new(4096);
        let buf = streamer.create_streaming_buffer(4096);

        let offset1 = streamer.allocate(buf, 1024).unwrap();
        assert_eq!(offset1, 0);

        let offset2 = streamer.allocate(buf, 2048).unwrap();
        assert_eq!(offset2, 1024);

        assert_eq!(streamer.total_bytes_uploaded(), 3072);
    }

    #[test]
    fn upload_streamer_wrap_around() {
        let mut streamer = GpuUploadStreamer::new(1024);
        let buf = streamer.create_streaming_buffer(1024);

        streamer.allocate(buf, 512).unwrap();
        streamer.allocate(buf, 512).unwrap();

        // Buffer is full, next allocation wraps
        let offset = streamer.allocate(buf, 256).unwrap();
        assert_eq!(offset, 0);
    }

    #[test]
    fn upload_streamer_advance_frame_resets() {
        let mut streamer = GpuUploadStreamer::new(4096);
        let buf = streamer.create_streaming_buffer(4096);

        streamer.allocate(buf, 3000).unwrap();
        streamer.advance_frame();

        // New frame should reset write offset
        let offset = streamer.allocate(buf, 100).unwrap();
        assert_eq!(offset, 0);
    }

    // --- Frame Pacing Tests ---

    #[test]
    fn frame_pacer_timing() {
        let config = FramePacingConfig {
            target_fps: 60,
            vsync_enabled: true,
            max_frame_latency: 2,
        };
        let mut pacer = FramePacer::new(config);

        pacer.begin_frame();
        // Simulate some work
        std::thread::sleep(Duration::from_millis(1));
        pacer.end_frame();

        let stats = pacer.stats();
        assert_eq!(stats.frames_rendered, 1);
        assert!(stats.last_frame_time_ms > 0.0);
        assert!(stats.min_frame_time_ms < f64::MAX);
    }

    #[test]
    fn frame_pacer_average_fps() {
        let config = FramePacingConfig::default();
        let mut pacer = FramePacer::new(config);

        for _ in 0..10 {
            pacer.begin_frame();
            std::thread::sleep(Duration::from_millis(1));
            pacer.end_frame();
        }

        let fps = pacer.average_fps();
        assert!(fps > 0.0);
        assert!(fps < 10000.0); // Reasonable range
    }

    #[test]
    fn frame_pacer_config_default() {
        let config = FramePacingConfig::default();
        assert_eq!(config.target_fps, 60);
        assert!(config.vsync_enabled);
        assert_eq!(config.max_frame_latency, 2);
    }

    #[test]
    fn frame_pacer_reset_stats() {
        let config = FramePacingConfig::default();
        let mut pacer = FramePacer::new(config);

        pacer.begin_frame();
        pacer.end_frame();
        assert_eq!(pacer.stats().frames_rendered, 1);

        pacer.reset_stats();
        assert_eq!(pacer.stats().frames_rendered, 0);
    }

    // --- Phase 7: File Cache Tests ---

    #[test]
    fn file_cache_insert_get() {
        let mut cache = FileCache::new(1024);

        // Miss
        assert!(cache.get("test.txt").is_none());
        let (hits, misses, _) = cache.stats();
        assert_eq!(hits, 0);
        assert_eq!(misses, 1);

        // Insert
        cache.insert("test.txt", vec![1, 2, 3, 4]).unwrap();
        assert_eq!(cache.entry_count(), 1);

        // Hit
        let data = cache.get("test.txt").unwrap();
        assert_eq!(data, &[1, 2, 3, 4]);
        let (hits, misses, rate) = cache.stats();
        assert_eq!(hits, 1);
        assert!(rate > 0.0);
    }

    #[test]
    fn file_cache_eviction() {
        let mut cache = FileCache::new(20); // Very small cache

        cache.insert("a.txt", vec![0u8; 10]).unwrap();
        cache.insert("b.txt", vec![0u8; 10]).unwrap();
        assert_eq!(cache.entry_count(), 2);

        // Insert a third file — should evict the LRU (a.txt)
        cache.insert("c.txt", vec![0u8; 10]).unwrap();
        assert_eq!(cache.entry_count(), 2);
        assert!(cache.get("a.txt").is_none(), "a.txt should have been evicted");
        assert!(cache.get("b.txt").is_some(), "b.txt should still be cached");
        assert!(cache.get("c.txt").is_some(), "c.txt should be cached");
    }

    #[test]
    fn file_cache_invalidate() {
        let mut cache = FileCache::new(1024);
        cache.insert("test.txt", vec![1, 2, 3]).unwrap();
        assert!(cache.get("test.txt").is_some());

        cache.invalidate("test.txt");
        assert!(cache.get("test.txt").is_none());
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn file_cache_too_large() {
        let mut cache = FileCache::new(10);
        let result = cache.insert("big.txt", vec![0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn file_cache_stats() {
        let mut cache = FileCache::new(1024);
        cache.insert("a.txt", vec![1]).unwrap();

        cache.get("a.txt"); // hit
        cache.get("a.txt"); // hit
        cache.get("b.txt"); // miss

        let (hits, misses, rate) = cache.stats();
        assert_eq!(hits, 2);
        assert_eq!(misses, 1); // only "b.txt" was a miss
        assert!((rate - (2.0 / 3.0)).abs() < 0.01);
    }

    // --- Phase 7: Path Resolution Cache Tests ---

    #[test]
    fn path_resolution_cache() {
        let mut cache = PathResolutionCache::new();

        let call_count = std::sync::atomic::AtomicUsize::new(0);

        // First call — miss, resolver called
        let result = cache.resolve("C:\\Users\\test.txt", |path| {
            call_count.fetch_add(1, Ordering::Relaxed);
            Ok(PathBuf::from(format!("/host{}", path.replace('\\', "/"))))
        }).unwrap();
        assert_eq!(result, PathBuf::from("/hostC:/Users/test.txt"));
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        // Second call — hit, resolver NOT called
        let result2 = cache.resolve("C:\\Users\\test.txt", |path| {
            call_count.fetch_add(1, Ordering::Relaxed);
            Ok(PathBuf::from(format!("/host{}", path.replace('\\', "/"))))
        }).unwrap();
        assert_eq!(result2, result);
        assert_eq!(call_count.load(Ordering::Relaxed), 1, "resolver should not be called on cache hit");

        let (hits, misses, _) = cache.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }

    #[test]
    fn path_resolution_cache_invalidate_prefix() {
        let mut cache = PathResolutionCache::new();

        cache.resolve("C:\\Windows\\a.txt", |p| Ok(PathBuf::from(p))).unwrap();
        cache.resolve("C:\\Windows\\b.txt", |p| Ok(PathBuf::from(p))).unwrap();
        cache.resolve("C:\\Game\\c.txt", |p| Ok(PathBuf::from(p))).unwrap();

        assert_eq!(cache.entry_count(), 3);

        cache.invalidate_prefix("C:\\Windows");
        assert_eq!(cache.entry_count(), 1);
        assert!(cache.cache.contains_key("C:\\Game\\c.txt"));
    }

    // --- Phase 7: Async File Reader Tests ---

    #[test]
    fn async_file_reader_submit_and_wait() {
        let dir = std::env::temp_dir();
        let path = dir.join("casa1_test_async_read.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let mut reader = AsyncFileReader::new();
        let id = reader.submit_read(path.clone(), 0, 11);

        // Read is performed on a background thread; wait_for joins the thread
        let data = reader.wait_for(id, 1000).unwrap();
        assert_eq!(data, b"hello world");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn async_file_reader_wait_for() {
        let dir = std::env::temp_dir();
        let path = dir.join("casa1_test_async_wait.txt");
        std::fs::write(&path, b"test data 12345").unwrap();

        let mut reader = AsyncFileReader::new();
        let id = reader.submit_read(path.clone(), 0, 15);

        let data = reader.wait_for(id, 1000).unwrap();
        assert_eq!(data, b"test data 12345");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn async_file_reader_wait_timeout() {
        let mut reader = AsyncFileReader::new();
        // Request for non-existent ID should timeout
        let result = reader.wait_for(99999, 10);
        assert!(result.is_err());
    }

    // --- Phase 7: Memory-Mapped File Tests ---

    #[test]
    fn mmapped_file_read() {
        let dir = std::env::temp_dir();
        let path = dir.join("casa1_test_mmap.bin");
        let test_data = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
        std::fs::write(&path, &test_data).unwrap();

        let mf = MmappedFile::open(&path).unwrap();
        assert!(mf.mapped);
        assert_eq!(mf.size, 8);

        let mut buf = [0u8; 4];
        mf.read(0, &mut buf).unwrap();
        assert_eq!(buf, [0xde, 0xad, 0xbe, 0xef]);

        mf.read(4, &mut buf).unwrap();
        assert_eq!(buf, [0xca, 0xfe, 0xba, 0xbe]);

        drop(mf);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn mmapped_file_out_of_bounds() {
        let dir = std::env::temp_dir();
        let path = dir.join("casa1_test_mmap_oob.bin");
        std::fs::write(&path, b"short").unwrap();

        let mf = MmappedFile::open(&path).unwrap();
        let mut buf = [0u8; 100];
        let result = mf.read(0, &mut buf);
        assert!(result.is_err());

        drop(mf);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn mmapped_file_empty_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("casa1_test_mmap_empty.bin");
        std::fs::write(&path, "").unwrap();

        let mf = MmappedFile::open(&path).unwrap();
        assert!(!mf.mapped);
        assert_eq!(mf.size, 0);

        drop(mf);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn mmapped_file_nonexistent() {
        let path = std::path::PathBuf::from("/tmp/casa1_nonexistent_mmap_test_12345");
        let result = MmappedFile::open(&path);
        assert!(result.is_err());
    }
}
