//! Asynchronous Metal pipeline state compilation.
//!
//! Provides [`AsyncPipelineCompiler`] which submits render and compute pipeline
//! descriptors for background compilation using Metal's native async APIs
//! (`newRenderPipelineStateWithDescriptor:completionHandler:` and
//! `newComputePipelineStateWithDescriptor:completionHandler:`).
//!
//! A pipeline cache avoids recompiling identical pipelines.  Completed
//! compilations are collected via [`poll()`](AsyncPipelineCompiler::poll),
//! failures via [`poll_failures()`](AsyncPipelineCompiler::poll_failures).
//!
//! # Thread safety
//!
//! Internal state is protected by `Arc<Mutex<…>>` so that completion handlers
//! (which run on Metal-internal threads) can safely store results.

use block::{ConcreteBlock, RcBlock};
use metal::foreign_types::ForeignType;
use objc::runtime::Object;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Opaque ID for tracking a pipeline compilation request.
pub type PipelineRequestId = u64;

/// Describes a render or compute pipeline compilation request.
#[derive(Clone)]
pub enum PipelineDescriptor {
    /// A render pipeline descriptor.
    Render(metal::RenderPipelineDescriptor),
    /// A compute pipeline descriptor.
    Compute(metal::ComputePipelineDescriptor),
}

/// The result of a completed pipeline compilation.
#[derive(Clone)]
pub enum PipelineState {
    /// A compiled render pipeline state.
    Render(metal::RenderPipelineState),
    /// A compiled compute pipeline state.
    Compute(metal::ComputePipelineState),
}

/// A pending pipeline compilation request.
#[derive(Clone)]
pub struct PipelineRequest {
    /// Unique identifier for this request.
    pub id: PipelineRequestId,
    /// The descriptor that was submitted.
    pub descriptor: PipelineDescriptor,
    /// When the request was submitted.
    pub submitted_at: Instant,
}

/// A completed pipeline compilation ready to be collected by [`poll`](AsyncPipelineCompiler::poll).
#[derive(Clone)]
pub struct PipelineReady {
    /// The request ID returned by [`submit_render`](AsyncPipelineCompiler::submit_render)
    /// or [`submit_compute`](AsyncPipelineCompiler::submit_compute).
    pub id: PipelineRequestId,
    /// The compiled pipeline state.
    pub state: PipelineState,
}

/// State of a single colour attachment that affects the compiled pipeline.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct ColorAttachmentKey {
    pixel_format: u64,
    blending_enabled: bool,
    source_rgb_blend_factor: u64,
    destination_rgb_blend_factor: u64,
    rgb_blend_operation: u64,
    source_alpha_blend_factor: u64,
    destination_alpha_blend_factor: u64,
    alpha_blend_operation: u64,
    write_mask: u64,
}

/// State of a single vertex buffer layout that affects the compiled pipeline.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct VertexLayoutKey {
    stride: u64,
    step_function: u64,
    step_rate: u64,
}

/// State of a single vertex attribute that affects the compiled pipeline.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct VertexAttributeKey {
    format: u64,
    offset: u64,
    buffer_index: u64,
}

/// Cache key for identifying unique render pipeline configurations.
///
/// Derived from the pipeline descriptor's shader function names, colour
/// attachment pixel formats and blend states, depth/stencil formats, sample
/// counts, rasterization flags, and vertex descriptor layout.  Two descriptors
/// that produce the same key are assumed to produce identical pipelines.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct PipelineCacheKey {
    vertex_function: String,
    fragment_function: String,
    color_attachments: Vec<ColorAttachmentKey>,
    depth_attachment_pixel_format: u64,
    stencil_attachment_pixel_format: u64,
    sample_count: u64,
    raster_sample_count: u64,
    alpha_to_coverage_enabled: bool,
    alpha_to_one_enabled: bool,
    rasterization_enabled: bool,
    input_primitive_topology: u64,
    vertex_layouts: Vec<VertexLayoutKey>,
    vertex_attributes: Vec<VertexAttributeKey>,
}

/// Cache key for compute pipelines: the compute function name plus the
/// thread-group-size-alignment flag from the descriptor.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct ComputeCacheKey {
    compute_function: String,
    thread_group_size_is_multiple_of_thread_execution_width: bool,
}

impl PipelineCacheKey {
    /// Build a cache key from a render pipeline descriptor.
    pub fn from_render_descriptor(desc: &metal::RenderPipelineDescriptorRef) -> Self {
        let vertex_fn = desc
            .vertex_function()
            .map(|f| f.name())
            .unwrap_or_default()
            .to_string();
        let fragment_fn = desc
            .fragment_function()
            .map(|f| f.name())
            .unwrap_or_default()
            .to_string();

        // Metal supports up to 8 color attachments.
        let mut color_attachments = Vec::with_capacity(8);
        let attachments = desc.color_attachments();
        for i in 0..8u64 {
            if let Some(attachment) = attachments.object_at(i) {
                color_attachments.push(ColorAttachmentKey {
                    pixel_format: attachment.pixel_format() as u64,
                    blending_enabled: attachment.is_blending_enabled(),
                    source_rgb_blend_factor: attachment.source_rgb_blend_factor() as u64,
                    destination_rgb_blend_factor: attachment.destination_rgb_blend_factor() as u64,
                    rgb_blend_operation: attachment.rgb_blend_operation() as u64,
                    source_alpha_blend_factor: attachment.source_alpha_blend_factor() as u64,
                    destination_alpha_blend_factor: attachment.destination_alpha_blend_factor()
                        as u64,
                    alpha_blend_operation: attachment.alpha_blend_operation() as u64,
                    write_mask: attachment.write_mask().bits(),
                });
            }
        }

        // Vertex descriptor: hashing the covered layouts/attributes keeps the
        // key deterministic while distinguishing descriptors whose input
        // assembly would produce different pipelines.
        let mut vertex_layouts = Vec::new();
        let mut vertex_attributes = Vec::new();
        if let Some(vertex_descriptor) = desc.vertex_descriptor() {
            let layouts = vertex_descriptor.layouts();
            for i in 0..31u64 {
                if let Some(layout) = layouts.object_at(i) {
                    vertex_layouts.push(VertexLayoutKey {
                        stride: layout.stride(),
                        step_function: layout.step_function() as u64,
                        step_rate: layout.step_rate(),
                    });
                }
            }
            let attributes = vertex_descriptor.attributes();
            for i in 0..31u64 {
                if let Some(attribute) = attributes.object_at(i) {
                    vertex_attributes.push(VertexAttributeKey {
                        format: attribute.format() as u64,
                        offset: attribute.offset(),
                        buffer_index: attribute.buffer_index(),
                    });
                }
            }
        }

        Self {
            vertex_function: vertex_fn,
            fragment_function: fragment_fn,
            color_attachments,
            depth_attachment_pixel_format: desc.depth_attachment_pixel_format() as u64,
            stencil_attachment_pixel_format: desc.stencil_attachment_pixel_format() as u64,
            sample_count: desc.sample_count(),
            raster_sample_count: desc.raster_sample_count(),
            alpha_to_coverage_enabled: desc.is_alpha_to_coverage_enabled(),
            alpha_to_one_enabled: desc.is_alpha_to_one_enabled(),
            rasterization_enabled: desc.is_rasterization_enabled(),
            input_primitive_topology: desc.input_primitive_topology() as u64,
            vertex_layouts,
            vertex_attributes,
        }
    }
}

impl ComputeCacheKey {
    /// Build a compute cache key from a compute pipeline descriptor.
    fn from_compute_descriptor(desc: &metal::ComputePipelineDescriptorRef) -> Self {
        Self {
            compute_function: desc
                .compute_function()
                .map(|f| f.name())
                .unwrap_or_default()
                .to_string(),
            thread_group_size_is_multiple_of_thread_execution_width: desc
                .thread_group_size_is_multiple_of_thread_execution_width(),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal shared state
// ---------------------------------------------------------------------------

/// Thread‑safe shared state between Metal completion handlers and the
/// compiler's `poll()` / `wait_for()` methods.
struct AsyncState {
    ready: Vec<PipelineReady>,
    failed: Vec<u64>,
    next_id: u64,
}

/// A completion handler block that has been heap-copied for Objective‑C.
///
/// We keep the [`RcBlock`] alive on the Rust side until the request
/// completes so that the block’s captured `Arc` values stay valid; once the
/// result (success or failure) is collected, the handle is dropped.
struct BlockHandle<A, R>
where
    A: block::BlockArguments,
{
    id: u64,
    _block: RcBlock<A, R>,
}

// ---------------------------------------------------------------------------
// AsyncPipelineCompiler
// ---------------------------------------------------------------------------

/// Manages asynchronous compilation of Metal pipeline states.
///
/// Uses Metal's native `newRenderPipelineStateWithDescriptor:completionHandler:`
/// and `newComputePipelineStateWithDescriptor:completionHandler:` APIs to
/// compile pipelines in the background.  Completed compilations are collected
/// via [`poll()`](Self::poll), failed compilations via [`poll_failures()`](Self::poll_failures).
/// A pipeline cache avoids recompiling identical pipelines.
///
/// # Thread safety
///
/// Internal state is protected by `Arc<Mutex<…>>` so that completion handlers
/// (which run on Metal-internal threads) can safely store results.
///
/// # Example (render loop integration)
///
/// ```ignore
/// let mut compiler = AsyncPipelineCompiler::new(&device);
///
/// // Submit for async compilation
/// let id = compiler.submit_render(&pipeline_desc);
///
/// // Later, before drawing:
/// for ready in compiler.poll() {
///     match ready.state {
///         PipelineState::Render(ps) => { /* store or use ps */ }
///         _ => {}
///     }
/// }
/// ```
pub struct AsyncPipelineCompiler {
    device: metal::Device,
    in_flight: VecDeque<PipelineRequest>,
    max_concurrent: usize,
    state: Arc<Mutex<AsyncState>>,
    /// Cache key → owned render pipeline state.
    cache: Arc<Mutex<HashMap<PipelineCacheKey, metal::RenderPipelineState>>>,
    /// Compute cache key → owned compute pipeline state.
    compute_cache: Arc<Mutex<HashMap<ComputeCacheKey, metal::ComputePipelineState>>>,
    /// Keep block handles alive so the ObjC blocks don't disappear.
    _block_handles: Vec<BlockHandle<(*mut Object, *mut Object), ()>>,
}

impl AsyncPipelineCompiler {
    /// Create a new async pipeline compiler backed by the given Metal device.
    pub fn new(device: &metal::Device) -> Self {
        Self {
            device: device.to_owned(),
            in_flight: VecDeque::new(),
            max_concurrent: 8,
            state: Arc::new(Mutex::new(AsyncState {
                ready: Vec::new(),
                failed: Vec::new(),
                next_id: 1,
            })),
            cache: Arc::new(Mutex::new(HashMap::new())),
            compute_cache: Arc::new(Mutex::new(HashMap::new())),
            _block_handles: Vec::new(),
        }
    }

    /// Set the maximum number of concurrent in‑flight compilations.
    ///
    /// This is a soft limit: completed requests are drained before new
    /// submissions when the limit is reached, and the caller can additionally
    /// check [`pending_count`](Self::pending_count) and drain via [`poll`](Self::poll).
    pub fn set_max_concurrent(&mut self, max: usize) {
        self.max_concurrent = max;
    }

    // ------------------------------------------------------------------
    // Submission
    // ------------------------------------------------------------------

    /// Submit a render pipeline for asynchronous compilation.
    ///
    /// Returns a [`PipelineRequestId`] that can be used with
    /// [`wait_for`](Self::wait_for) or [`cancel`](Self::cancel).
    ///
    /// If an identical pipeline already exists in the cache, the returned
    /// ID will be available immediately in the next [`poll`](Self::poll)
    /// call.
    pub fn submit_render(
        &mut self,
        descriptor: &metal::RenderPipelineDescriptorRef,
    ) -> PipelineRequestId {
        let key = PipelineCacheKey::from_render_descriptor(descriptor);

        // Enforce the soft concurrency limit by draining completed work
        // before piling on more submissions.
        if self.in_flight.len() >= self.max_concurrent {
            self.poll();
        }

        // Allocate a request ID first so we can use it in the block.
        let id = {
            let mut s = self.state.lock().unwrap(); // lock(): panic on poison is acceptable
            let id = s.next_id;
            s.next_id += 1;
            id
        };

        // Check cache — if already cached, inject an immediately-ready result.
        {
            let cache = self.cache.lock().unwrap(); // lock(): panic on poison is acceptable
            if let Some(cached) = cache.get(&key) {
                let cloned = cached.clone();
                drop(cache);
                let mut s = self.state.lock().unwrap(); // lock(): panic on poison is acceptable
                s.ready.push(PipelineReady {
                    id,
                    state: PipelineState::Render(cloned),
                });
                return id;
            }
        }

        let desc_owned = descriptor.to_owned();
        let state_arc = self.state.clone();
        let cache_arc = self.cache.clone();
        let cache_key = key.clone();

        // Build the Objective‑C completion-handler block.
        //
        // SAFETY: The block receives raw ObjC object pointers from Metal.
        // When `error` is null the compilation succeeded and `pipeline` is
        // a valid `MTLRenderPipelineState` pointer.
        let block = ConcreteBlock::new(move |pipeline: *mut Object, error: *mut Object| {
            if !error.is_null() {
                // Compilation failed — record the failure so `wait_for` /
                // `flush` do not spin forever waiting for a result.
                if let Ok(mut s) = state_arc.lock() {
                    s.failed.push(id);
                }
                return;
            }
            if pipeline.is_null() {
                if let Ok(mut s) = state_arc.lock() {
                    s.failed.push(id);
                }
                return;
            }
            // SAFETY: Metal guarantees the pipeline pointer is valid on success.
            let state = unsafe { metal::RenderPipelineState::from_ptr(pipeline as *mut _) };
            let state_owned = state.to_owned();

            // Populate the cache (clone the key so the closure stays Fn).
            if let Ok(mut cache) = cache_arc.lock() {
                cache.insert(cache_key.clone(), state_owned.clone());
            }

            // Mark the request as ready.
            if let Ok(mut s) = state_arc.lock() {
                s.ready.push(PipelineReady {
                    id,
                    state: PipelineState::Render(state_owned),
                });
            }
        });
        let rc_block = block.copy();

        // Call the async Metal API.
        //
        // SAFETY: `newRenderPipelineStateWithDescriptor:completionHandler:` is
        // a well‑known Metal method that takes a descriptor and a block.
        unsafe {
            let device_obj: *mut Object = self.device.as_ptr() as *mut Object;
            let descriptor_obj: *mut Object = desc_owned.as_ptr() as *mut Object;
            let () = msg_send![device_obj,
                newRenderPipelineStateWithDescriptor: descriptor_obj
                                     completionHandler: &*rc_block
            ];
        }

        // Keep the block handle alive until the request completes.
        self._block_handles.push(BlockHandle {
            id,
            _block: rc_block,
        });

        self.in_flight.push_back(PipelineRequest {
            id,
            descriptor: PipelineDescriptor::Render(desc_owned),
            submitted_at: Instant::now(),
        });

        id
    }

    /// Submit a compute pipeline for asynchronous compilation.
    ///
    /// Returns a [`PipelineRequestId`] that can be used with
    /// [`wait_for`](Self::wait_for) or [`cancel`](Self::cancel).
    ///
    /// If an identical pipeline already exists in the compute cache, the
    /// returned ID will be available immediately in the next [`poll`](Self::poll)
    /// call.
    pub fn submit_compute(
        &mut self,
        descriptor: &metal::ComputePipelineDescriptorRef,
    ) -> PipelineRequestId {
        let key = ComputeCacheKey::from_compute_descriptor(descriptor);

        // Enforce the soft concurrency limit by draining completed work.
        if self.in_flight.len() >= self.max_concurrent {
            self.poll();
        }

        let id = {
            let mut s = self.state.lock().unwrap(); // lock(): panic on poison is acceptable
            let id = s.next_id;
            s.next_id += 1;
            id
        };

        // Check compute cache — if already cached, inject an immediately-ready
        // result instead of recompiling.
        {
            let compute_cache = self.compute_cache.lock().unwrap(); // lock(): panic on poison is acceptable
            if let Some(cached) = compute_cache.get(&key) {
                let cloned = cached.clone();
                drop(compute_cache);
                let mut s = self.state.lock().unwrap(); // lock(): panic on poison is acceptable
                s.ready.push(PipelineReady {
                    id,
                    state: PipelineState::Compute(cloned),
                });
                return id;
            }
        }

        let desc_owned = descriptor.to_owned();
        let state_arc = self.state.clone();
        let compute_cache_arc = self.compute_cache.clone();
        let cache_key = key.clone();

        let block = ConcreteBlock::new(move |pipeline: *mut Object, error: *mut Object| {
            if !error.is_null() || pipeline.is_null() {
                if let Ok(mut s) = state_arc.lock() {
                    s.failed.push(id);
                }
                return;
            }
            // SAFETY: Metal guarantees the compute pipeline pointer is valid on success.
            let state = unsafe { metal::ComputePipelineState::from_ptr(pipeline as *mut _) };
            let state_owned = state.to_owned();

            if let Ok(mut compute_cache) = compute_cache_arc.lock() {
                compute_cache.insert(cache_key.clone(), state_owned.clone());
            }

            if let Ok(mut s) = state_arc.lock() {
                s.ready.push(PipelineReady {
                    id,
                    state: PipelineState::Compute(state_owned),
                });
            }
        });
        let rc_block = block.copy();

        unsafe {
            let device_obj: *mut Object = self.device.as_ptr() as *mut Object;
            let descriptor_obj: *mut Object = desc_owned.as_ptr() as *mut Object;
            let () = msg_send![device_obj,
                newComputePipelineStateWithDescriptor: descriptor_obj
                                      completionHandler: &*rc_block
            ];
        }

        self._block_handles.push(BlockHandle {
            id,
            _block: rc_block,
        });

        self.in_flight.push_back(PipelineRequest {
            id,
            descriptor: PipelineDescriptor::Compute(desc_owned),
            submitted_at: Instant::now(),
        });

        id
    }

    // ------------------------------------------------------------------
    // Collection
    // ------------------------------------------------------------------

    /// Collect all completed pipeline compilations (non‑blocking).
    ///
    /// Returns a `Vec` of [`PipelineReady`] entries, each containing the
    /// request ID and the compiled pipeline state.  Entries are removed
    /// from the in‑flight queue.  Failed compilations are *not* returned
    /// here; collect them via [`poll_failures`](Self::poll_failures).
    pub fn poll(&mut self) -> Vec<PipelineReady> {
        let (ready, failed) = {
            let mut s = self.state.lock().unwrap(); // lock(): panic on poison is acceptable
            (std::mem::take(&mut s.ready), std::mem::take(&mut s.failed))
        };

        // Remove completed request IDs from in_flight and release their
        // block handles so they don't accumulate for the lifetime of the
        // compiler.
        let mut finished: Vec<u64> = ready.iter().map(|r| r.id).collect();
        finished.extend(&failed);
        self.release_finished(&finished);

        ready
    }

    /// Collect the request IDs of failed compilations (non‑blocking).
    ///
    /// A failed request is removed from the in‑flight queue and `wait_for`
    /// returns `None` for it.  Returns the failed request IDs since the last
    /// call.
    pub fn poll_failures(&mut self) -> Vec<u64> {
        let failed = {
            let mut s = self.state.lock().unwrap(); // lock(): panic on poison is acceptable
            std::mem::take(&mut s.failed)
        };
        self.release_finished(&failed);
        failed
    }

    /// Remove finished request IDs from the in‑flight queue and drop their
    /// block handles.
    fn release_finished(&mut self, finished: &[u64]) {
        if finished.is_empty() {
            return;
        }
        self.in_flight.retain(|req| !finished.contains(&req.id));
        self._block_handles.retain(|handle| !finished.contains(&handle.id));
    }

    /// Block the calling thread until a specific compilation completes.
    ///
    /// Spins (with `yield_now`) until the pipeline is ready.  Prefer using
    /// [`poll`](Self::poll) in a render loop and only call `wait_for` when
    /// the pipeline is needed immediately.
    ///
    /// Returns `None` if the request is not (or no longer) in flight: it was
    /// never submitted, was cancelled, or its compilation failed.
    pub fn wait_for(&mut self, id: u64) -> Option<PipelineState> {
        // Fast path: already ready.
        let ready = self.poll();
        for r in ready {
            if r.id == id {
                return Some(r.state);
            }
        }

        // Unknown / cancelled / already-failed id: nothing will ever arrive.
        if !self.in_flight.iter().any(|req| req.id == id) {
            return None;
        }

        // Spin waiting for the specific ID.
        let state_arc = self.state.clone();
        loop {
            std::thread::yield_now();
            let mut s = state_arc.lock().unwrap(); // lock(): panic on poison is acceptable
            if let Some(pos) = s.ready.iter().position(|r| r.id == id) {
                let ready = s.ready.remove(pos);
                self.release_finished(&[id]);
                return Some(ready.state);
            }
            if let Some(pos) = s.failed.iter().position(|f| *f == id) {
                s.failed.remove(pos);
                self.release_finished(&[id]);
                return None;
            }
        }
    }

    // ------------------------------------------------------------------
    // Cancellation / lifecycle
    // ------------------------------------------------------------------

    /// Attempt to cancel a pending compilation request.
    ///
    /// Returns `true` if the request was found and removed from the
    /// in‑flight queue.  **Note:** Metal's API does **not** support
    /// cancelling an already‑submitted compilation; the result will be
    /// silently dropped when it eventually completes.
    pub fn cancel(&mut self, id: u64) -> bool {
        if let Some(pos) = self.in_flight.iter().position(|req| req.id == id) {
            self.in_flight.remove(pos);
            self._block_handles.retain(|handle| handle.id != id);
            true
        } else {
            false
        }
    }

    /// Wait for **all** in‑flight compilations to complete.
    ///
    /// After calling `flush()`, the internal in‑flight queue is empty and
    /// all completed results have been collected into the returned `Vec`.
    /// Failed compilations are dropped from the result; collect their IDs
    /// via [`poll_failures`](Self::poll_failures).
    pub fn flush(&mut self) -> Vec<PipelineReady> {
        let ids: Vec<u64> = self.in_flight.iter().map(|req| req.id).collect();
        let mut all_ready = Vec::new();
        for id in ids {
            if let Some(state) = self.wait_for(id) {
                all_ready.push(PipelineReady { id, state });
            }
        }
        all_ready
    }

    /// Number of pending (in‑flight) compilation requests.
    pub fn pending_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Number of pipelines currently in the render cache.
    pub fn cache_size(&self) -> usize {
        self.cache.lock().unwrap().len() // lock(): panic on poison is acceptable
    }

    /// Number of pipelines currently in the compute cache.
    pub fn compute_cache_size(&self) -> usize {
        self.compute_cache.lock().unwrap().len() // lock(): panic on poison is acceptable
    }

    /// Clear the render and compute pipeline caches.
    pub fn clear_cache(&mut self) {
        self.cache.lock().unwrap().clear(); // lock(): panic on poison is acceptable
        self.compute_cache.lock().unwrap().clear(); // lock(): panic on poison is acceptable
    }

    // ------------------------------------------------------------------
    // Cache query helpers
    // ------------------------------------------------------------------

    /// Look up a render pipeline in the cache without submitting any work.
    ///
    /// Returns `Some(RenderPipelineState)` if a pipeline matching the
    /// descriptor's [`PipelineCacheKey`] is present.
    pub fn get_cached_render_pipeline(
        &self,
        desc: &metal::RenderPipelineDescriptorRef,
    ) -> Option<metal::RenderPipelineState> {
        let key = PipelineCacheKey::from_render_descriptor(desc);
        let cache = self.cache.lock().unwrap(); // lock(): panic on poison is acceptable
        cache.get(&key).cloned()
    }

    /// Insert a pre‑compiled render pipeline into the cache so that future
    /// submissions with an equivalent descriptor will hit the cache.
    pub fn cache_render_pipeline(
        &mut self,
        desc: &metal::RenderPipelineDescriptorRef,
        pipeline: &metal::RenderPipelineState,
    ) {
        let key = PipelineCacheKey::from_render_descriptor(desc);
        let mut cache = self.cache.lock().unwrap(); // lock(): panic on poison is acceptable
        cache.insert(key, pipeline.to_owned());
    }

    /// Look up a compute pipeline in the cache without submitting any work.
    ///
    /// Returns `Some(ComputePipelineState)` if a pipeline matching the
    /// descriptor's cache key is present.
    pub fn get_cached_compute_pipeline(
        &self,
        desc: &metal::ComputePipelineDescriptorRef,
    ) -> Option<metal::ComputePipelineState> {
        let key = ComputeCacheKey::from_compute_descriptor(desc);
        let compute_cache = self.compute_cache.lock().unwrap(); // lock(): panic on poison is acceptable
        compute_cache.get(&key).cloned()
    }

    /// Insert a pre‑compiled compute pipeline into the cache so that future
    /// submissions with an equivalent descriptor will hit the cache.
    pub fn cache_compute_pipeline(
        &mut self,
        desc: &metal::ComputePipelineDescriptorRef,
        pipeline: &metal::ComputePipelineState,
    ) {
        let key = ComputeCacheKey::from_compute_descriptor(desc);
        let mut compute_cache = self.compute_cache.lock().unwrap(); // lock(): panic on poison is acceptable
        compute_cache.insert(key, pipeline.to_owned());
    }
}

// SAFETY: All internal state uses `Arc<Mutex<…>>` for thread safety.
// `metal::Device` is ref‑counted and thread‑safe.
unsafe impl Send for AsyncPipelineCompiler {}
unsafe impl Sync for AsyncPipelineCompiler {}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> PipelineCacheKey {
        PipelineCacheKey {
            vertex_function: "vs_main".into(),
            fragment_function: "fs_main".into(),
            color_attachments: vec![ColorAttachmentKey {
                pixel_format: 80, // BGRA8Unorm
                blending_enabled: false,
                source_rgb_blend_factor: 0,
                destination_rgb_blend_factor: 0,
                rgb_blend_operation: 0,
                source_alpha_blend_factor: 0,
                destination_alpha_blend_factor: 0,
                alpha_blend_operation: 0,
                write_mask: 15,
            }],
            depth_attachment_pixel_format: 0,
            stencil_attachment_pixel_format: 0,
            sample_count: 1,
            raster_sample_count: 1,
            alpha_to_coverage_enabled: false,
            alpha_to_one_enabled: false,
            rasterization_enabled: true,
            input_primitive_topology: 0,
            vertex_layouts: Vec::new(),
            vertex_attributes: Vec::new(),
        }
    }

    /// Verify that `PipelineCacheKey` correctly distinguishes two descriptors
    /// with different functions, attachment formats, blend states, depth
    /// formats, or sample counts.
    #[test]
    fn cache_key_uniqueness() {
        let key_a = sample_key();
        let key_b = sample_key();
        let mut key_c = sample_key();
        key_c.vertex_function = "vs_other".into();
        let mut key_d = sample_key();
        key_d.depth_attachment_pixel_format = 252; // Depth32Float
        let mut key_e = sample_key();
        key_e.color_attachments[0].blending_enabled = true;
        let mut key_f = sample_key();
        key_f.sample_count = 4;

        assert_eq!(key_a, key_b);
        assert_ne!(key_a, key_c);
        assert_ne!(key_a, key_d);
        assert_ne!(key_a, key_e);
        assert_ne!(key_a, key_f);

        let mut map = HashMap::new();
        map.insert(key_a.clone(), "pipeline_1");
        assert_eq!(map.get(&key_b), Some(&"pipeline_1"));
        assert_eq!(map.get(&key_c), None);
    }

    /// Verify `PipelineCacheKey` debug and clone.
    #[test]
    fn cache_key_debug_clone() {
        let key = sample_key();
        let cloned = key.clone();
        assert_eq!(format!("{:?}", key), format!("{:?}", cloned));
    }
}
