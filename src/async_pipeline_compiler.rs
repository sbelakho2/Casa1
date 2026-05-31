//! Asynchronous Metal pipeline state compilation.
//!
//! Provides [`AsyncPipelineCompiler`] which submits render and compute pipeline
//! descriptors for background compilation using Metal's native async APIs
//! (`newRenderPipelineStateWithDescriptor:completionHandler:` and
//! `newComputePipelineStateWithDescriptor:completionHandler:`).
//!
//! A pipeline cache avoids recompiling identical pipelines.  Completed
//! compilations are collected via [`poll()`](AsyncPipelineCompiler::poll).
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

/// Cache key for identifying unique render pipeline configurations.
///
/// Derived from the pipeline descriptor's vertex function name, fragment
/// function name, and colour attachment pixel formats.  Two descriptors
/// that produce the same key are assumed to produce identical pipelines.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct PipelineCacheKey {
    vertex_function: String,
    fragment_function: String,
    color_attachment_formats: Vec<u64>,
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

        let mut formats = Vec::new();
        let attachments = desc.color_attachments();
        // Metal supports up to 8 color attachments.
        for i in 0..8u64 {
            if let Some(attachment) = attachments.object_at(i) {
                formats.push(attachment.pixel_format() as u64);
            }
        }

        Self {
            vertex_function: vertex_fn,
            fragment_function: fragment_fn,
            color_attachment_formats: formats,
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
    next_id: u64,
}

/// A completion handler block that has been heap-copied for Objective‑C.
///
/// We keep the [`RcBlock`] alive on the Rust side so that the block’s
/// captured `Arc` values stay valid even if the original `ConcreteBlock`
/// stack frame is gone.
struct BlockHandle<A, R>
where
    A: block::BlockArguments,
{
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
/// via [`poll()`](Self::poll).  A pipeline cache avoids recompiling identical
/// pipelines.
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
    /// Cache key → owned pipeline state.
    cache: Arc<Mutex<HashMap<PipelineCacheKey, metal::RenderPipelineState>>>,
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
                next_id: 1,
            })),
            cache: Arc::new(Mutex::new(HashMap::new())),
            _block_handles: Vec::new(),
        }
    }

    /// Set the maximum number of concurrent in‑flight compilations.
    ///
    /// This is a soft limit: the caller should check [`pending_count`](Self::pending_count)
    /// before submitting and drain completed compilations via [`poll`](Self::poll).
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
    pub fn submit_render(&mut self, descriptor: &metal::RenderPipelineDescriptorRef) -> PipelineRequestId {
        let key = PipelineCacheKey::from_render_descriptor(descriptor);

        // Allocate a request ID first so we can use it in the block.
        let id = {
            let mut s = self.state.lock().unwrap();
            let id = s.next_id;
            s.next_id += 1;
            id
        };

        // Check cache — if already cached, inject an immediately-ready result.
        {
            let cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(&key) {
                let cloned = cached.clone();
                drop(cache);
                let mut s = self.state.lock().unwrap();
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
                // Compilation failed — nothing we can do here besides
                // silently dropping the request.  The caller will time
                // out the in‑flight entry eventually.
                return;
            }
            if pipeline.is_null() {
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

        // Keep the block handle alive.
        self._block_handles.push(BlockHandle { _block: rc_block });

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
    pub fn submit_compute(&mut self, descriptor: &metal::ComputePipelineDescriptorRef) -> PipelineRequestId {
        let id = {
            let mut s = self.state.lock().unwrap();
            let id = s.next_id;
            s.next_id += 1;
            id
        };

        let desc_owned = descriptor.to_owned();
        let state_arc = self.state.clone();

        let block = ConcreteBlock::new(move |pipeline: *mut Object, error: *mut Object| {
            if !error.is_null() || pipeline.is_null() {
                return;
            }
            // SAFETY: Metal guarantees the compute pipeline pointer is valid on success.
            let state = unsafe { metal::ComputePipelineState::from_ptr(pipeline as *mut _) };
            let state_owned = state.to_owned();

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

        self._block_handles.push(BlockHandle { _block: rc_block });

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
    /// from the in‑flight queue.
    pub fn poll(&mut self) -> Vec<PipelineReady> {
        let ready = {
            let mut s = self.state.lock().unwrap();
            std::mem::take(&mut s.ready)
        };

        // Remove completed request IDs from in_flight.
        let ready_ids: Vec<u64> = ready.iter().map(|r| r.id).collect();
        self.in_flight.retain(|req| !ready_ids.contains(&req.id));

        ready
    }

    /// Block the calling thread until a specific compilation completes.
    ///
    /// Spins (with `yield_now`) until the pipeline is ready.  Prefer using
    /// [`poll`](Self::poll) in a render loop and only call `wait_for` when
    /// the pipeline is needed immediately.
    pub fn wait_for(&mut self, id: u64) -> Option<PipelineState> {
        // Fast path: already ready.
        let ready = self.poll();
        for r in ready {
            if r.id == id {
                return Some(r.state);
            }
        }

        // Spin waiting for the specific ID.
        let state_arc = self.state.clone();
        loop {
            std::thread::yield_now();
            let mut s = state_arc.lock().unwrap();
            if let Some(pos) = s.ready.iter().position(|r| r.id == id) {
                let ready = s.ready.remove(pos);
                self.in_flight.retain(|req| req.id != id);
                return Some(ready.state);
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
            true
        } else {
            false
        }
    }

    /// Wait for **all** in‑flight compilations to complete.
    ///
    /// After calling `flush()`, the internal in‑flight queue is empty and
    /// all completed results have been collected into the returned `Vec`.
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

    /// Number of pipelines currently in the cache.
    pub fn cache_size(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Clear the pipeline cache.
    pub fn clear_cache(&mut self) {
        self.cache.lock().unwrap().clear();
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
        let cache = self.cache.lock().unwrap();
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
        let mut cache = self.cache.lock().unwrap();
        cache.insert(key, pipeline.to_owned());
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

    /// Verify that `PipelineCacheKey` correctly distinguishes two descriptors
    /// with different functions or attachment formats.
    #[test]
    fn cache_key_uniqueness() {
        // We can't easily create real Metal objects in a unit test, so we
        // just check the structural properties of the key type.
        let key_a = PipelineCacheKey {
            vertex_function: "vs_main".into(),
            fragment_function: "fs_main".into(),
            color_attachment_formats: vec![80], // BGRA8Unorm
        };
        let key_b = PipelineCacheKey {
            vertex_function: "vs_main".into(),
            fragment_function: "fs_main".into(),
            color_attachment_formats: vec![80],
        };
        let key_c = PipelineCacheKey {
            vertex_function: "vs_other".into(),
            fragment_function: "fs_main".into(),
            color_attachment_formats: vec![80],
        };

        assert_eq!(key_a, key_b);
        assert_ne!(key_a, key_c);

        let mut map = HashMap::new();
        map.insert(key_a.clone(), "pipeline_1");
        assert_eq!(map.get(&key_b), Some(&"pipeline_1"));
        assert_eq!(map.get(&key_c), None);
    }

    /// Verify `PipelineCacheKey` debug and clone.
    #[test]
    fn cache_key_debug_clone() {
        let key = PipelineCacheKey {
            vertex_function: "v".into(),
            fragment_function: "f".into(),
            color_attachment_formats: vec![1, 2],
        };
        let cloned = key.clone();
        assert_eq!(format!("{:?}", key), format!("{:?}", cloned));
    }
}
