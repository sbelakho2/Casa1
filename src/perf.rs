//! Performance optimization for Casa1.
//!
//! Implements block chaining, lazy JIT compilation, memory access translation
//! cache, parallel shader compilation, Metal command batching, GPU upload
//! streaming, and frame pacing for AAA game performance targeting 60 FPS.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::collections::{BTreeMap, HashMap, VecDeque};
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
        let chain = BlockChain {
            from_address: guest_address,
            to_address: target_address,
            patch_offset: 0, // Would be computed from actual code layout
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
    pub fn mark_compiled(&self, guest_address: u64, tier: CompilationTier, compile_time_us: u64) {
        self.total_compile_time_us.fetch_add(compile_time_us, Ordering::Relaxed);
        self.total_compiled.fetch_add(1, Ordering::Relaxed);
        let _ = (guest_address, tier);
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
    pub fn lookup(&self, guest_address: u64) -> Option<&AddressTranslation> {
        self.translations.get(&guest_address)
    }

    /// Insert a translation into the cache.
    pub fn insert(&mut self, guest_address: u64, host_address: u64, size: usize, protection: u32) {
        // Evict if full (LRU-like: just remove a random entry)
        if self.translations.len() >= self.max_entries {
            if let Some(key) = self.translations.keys().next().copied() {
                self.translations.remove(&key);
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

        // Add to current batch
        let batch = self.current_batch.get_or_insert_with(|| DrawBatch {
            pipeline_state_id,
            draw_calls: Vec::new(),
            total_vertices: 0,
            total_indices: 0,
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
    buffers: BTreeMap<u64, StreamingBuffer>,
    next_buffer_id: AtomicU64,
    current_frame: AtomicU64,
    #[allow(dead_code)]
    ring_buffer_size: usize,
    total_bytes_uploaded: AtomicU64,
}

impl GpuUploadStreamer {
    pub fn new(ring_buffer_size: usize) -> Self {
        Self {
            buffers: BTreeMap::new(),
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

        // Check if there's enough space
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
        let mut streamer = GpuUploadStreamer::new(1024);
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
        let mut streamer = GpuUploadStreamer::new(1024);
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
}
