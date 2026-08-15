# AUDIT_FINDINGS.md

- **Batch:** Casa1 code audit — GPU/Metal backend
- **Files:** `src/metal_backend.rs` (whole file, 7614 lines, read in full)
- **Date:** 2026-08-15
- **Method:** full sequential read (4 chunks), whole-crate `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (run to completion; lib and lib-test targets failed on clippy deny-by-default lints — see `## Build`), manual logic/FFI review.

---

## [CRITICAL] D2D vertex layout does not match shader attribute layout (GPU OOB reads, broken rendering)

- File: src/metal_backend.rs:2107 (struct `D2DVertex`), 2229-2294 (pipeline creation without a `vertex_descriptor`), 2378-2424 (`fill_rect`), 2431-2503 (`draw_line`), 2510-2582 (`fill_ellipse`), 2663-2718 (`draw_bitmap` / `TexVertex`)
- Description: `D2DVertex` is `#[repr(C)] { x: f32, y: f32, color: u32 }` = 12 bytes. The vertex shaders declare `float4 pos [[attribute(0)]]; float4 color [[attribute(1)]]` (16+16 bytes per vertex), and no `MTLVertexDescriptor` is ever set on either pipeline, so Metal uses the default descriptor (all attributes `float4`, 16-byte stride). Consequences:
  - `fill_rect`/`draw_line`/`fill_ellipse` upload 4×12=48 (or 6×12=72) byte buffers but the GPU reads 32 bytes per vertex (offset 16 per vertex); the last vertex reads 16 bytes past the end of the buffer → out-of-bounds GPU reads.
  - The packed ARGB `color` u32 lands in `pos.z` as an f32 reinterpretation; `attribute(1)` reads the *next* vertex's bytes, so solid-color primitives render with garbage colors.
  - `TexVertex {x,y,u,v}` (16 bytes) is read as `pos = attribute(0)` (correct xy but uv leaks into pos.zw) and `uv = attribute(1)` at offset 16 reads the *next* vertex's xy — `draw_bitmap` samples with garbage UVs.
- Fix suggestion: Create and assign a proper `MTLVertexDescriptor` on both pipelines — e.g. layout stride 12, `attribute(0) = Float2` at offset 0, `attribute(1) = UChar4Normalized` (or `Float4`) at offset 8 — or change `D2DVertex` to `{ x: f32, y: f32, color: [f32; 4] }` (32 bytes) and match the shader. Same for `TexVertex` (stride 16, `attribute(0)=Float2` offset 0, `attribute(1)=Float2` offset 8).

## [HIGH] create_render_pass_descriptor returns a borrow of a shared, autoreleased MTLRenderPassDescriptor

- File: src/metal_backend.rs:1106-1130
- Description: The function returns `&metal::RenderPassDescriptorRef` whose value comes from `metal::RenderPassDescriptor::new()` — in metal 0.31 this returns `&'a RenderPassDescriptorRef` obtained from the class-level `MTLRenderPassDescriptor renderPassDescriptor`, i.e. an **autoreleased, shared** object with no lifetime tied to the caller. The returned reference (a) dangles after the current autorelease-pool drain unless something retains it, and (b) aliases one shared descriptor, so every caller mutates the same object (`set_texture`/load/store/clear) — passes sharing this "descriptor" pollute each other's state (cross-frame races). Function currently has no callers, but is `pub` API. The doc contract ("Create a render pass descriptor for rendering to a texture") is not met.
- Fix suggestion: Return an owned `metal::RenderPassDescriptor` (the crate's `new_render_command_encoder` accepts `&RenderPassDescriptorRef`; keep a local owned copy at the call site and take `&desc` there), or build the descriptor at the call site.

## [HIGH] draw_bitmap opens a blit encoder (and may commit) while the render encoder is still active

- File: src/metal_backend.rs:2626-2653 (and 2601-2618)
- Description: `draw_bitmap` reuses the *current frame's* command buffer (`self.command_buffer`) to create a blit encoder for the texture upload while `self.encoder` (a render encoder on the same command buffer) is still open and actively being encoded into. Metal forbids two live encoders on one command buffer; this triggers Metal validation errors/faults (or undefined encoder state). Additionally, when no frame buffer exists (`needs_commit == true`) it commits and `wait_until_completed()` inside a draw call — a full pipeline stall in the middle of a frame's draw sequence.
- Fix suggestion: Upload via a dedicated scratch command buffer/queue that is committed and waited before the frame's render encoder is created (or keep a separate upload queue), and never open a second encoder on the command buffer that owns the active render encoder.

## [HIGH] Heap allocations: textures bypass the heap capacity check; buffer allocation underflows `heap.size - heap.used`

- File: src/metal_backend.rs:4935-4975 (`allocate_buffer_from_heap`, `let available = heap.size - heap.used` at 4947), 4978-5023 (`allocate_texture_from_heap`)
- Description: `allocate_texture_from_heap` validates only the type mask — it never checks that `heap.used + size_estimate <= heap.size`, so `heap.used` can exceed `heap.size`. A subsequent `allocate_buffer_from_heap` then computes `available = heap.size - heap.used`, which underflows: debug builds panic, release builds wrap to a huge number and the "heap out of memory" check passes, letting a buffer "succeed" against an overcommitted heap (Metal allocation failure/corruption downstream). Note also `size_estimate` uses approximate `bytes_per_pixel()` (e.g. BC1 = 1 B/px) and is unaligned, so the accounting is wrong even for compressed formats.
- Fix suggestion: In `allocate_texture_from_heap`, compute the real aligned size and reject with `RcIo` when `heap.used + aligned > heap.size` (mirror the buffer path); use `align_up` and checked arithmetic (`heap.size.checked_sub(heap.used)`).

## [HIGH] Acceleration structures are built without vertex/index buffers bound

- File: src/metal_backend.rs:3456-3468 (`create_acceleration_structure`), 3510-3545 (`build_acceleration_structure`), 3556-3598 (`refit_acceleration_structure`)
- Description: `RayTracingGeometryDescriptor.vertex_buffer` (a `u64` handle) and `index_buffer` are never resolved to `metal::Buffer`s and never passed to the Metal geometry descriptors (`set_vertex_buffer`/`set_index_buffer` are never called; only format/stride/triangle_count/opaque are set). The acceleration structure is therefore sized and built against geometry with no vertex data — the build is undefined (Metal validation failure or an empty structure), and the refit path has the same defect. `primitive_count` is also ignored in favor of `triangle_count`.
- Fix suggestion: Pass the actual vertex/index `metal::Buffer` (and offsets) into `create_acceleration_structure`/`build_acceleration_structure` and call `metal_geom.set_vertex_buffer(Some(&vb), 0)` (+ `set_index_buffer` when present) before `device.acceleration_structure_sizes_with_descriptor` and the build.

## [HIGH] resolve_msaa is a silent no-op for every resolve mode

- File: src/metal_backend.rs:4324-4387
- Description: `resolve_msaa` validates the config and source/dest sizes, then every `MsaaResolveMode` branch merely borrows the encoder/textures (`let _enc = ...; let _src_tex = ...;`) and returns `Ok(())`. No resolve is encoded, no compute shader is dispatched, and no resolve texture is configured. Callers get `Ok` and an unresolved MSAA texture — the function's documented contract is not implemented (comments in the code concede the fallbacks are unimplemented). `Sample0/Sample1/Min/Max/Custom` all behave identically (nothing).
- Fix suggestion: Either actually implement the paths (compute encoder + per-sample loop shader for Min/Max/Sample0/Sample1; custom shader dispatch for Custom) or return `AppError`/`Err(RcInvalidState)` when the requested mode cannot be performed, so callers can fall back instead of silently losing the resolve.

## [HIGH] apply_logic_op does nothing for Clear/Set and never compiles/uses the generated shader

- File: src/metal_backend.rs:4521-4559
- Description: `apply_logic_op` returns `Ok(())` for `LogicOp::Copy | Noop` (fine) but also for `Clear | Set` — despite the doc claiming "the framebuffer is cleared" — and for all other ops it only calls `generate_logic_op_shader(op)` and discards the string: no pipeline is compiled, no fullscreen quad is drawn, no shader is bound. The generated shader itself takes `uint4 src [[color(0)]], uint4 dst [[color(1)]]` — both inputs are framebuffer-fetch color attributes; the incoming fragment color is never available there, so even if compiled and run the semantics would be wrong (`src` is not the incoming color).
- Fix suggestion: Implement Clear/Set as actual clear passes (or return a clear load action), and for the remaining ops compile the emulation shader once, bind it to a fullscreen-quad pipeline with a real source texture/constant for `src`, and encode the quad draw. At minimum, return `Err` for modes that are not implemented instead of `Ok`.

## [HIGH] execute_geometry_pass dispatches nothing (geometry shader emulation is a hardcoded stub)

- File: src/metal_backend.rs:4659-4703
- Description: `execute_geometry_pass` binds three buffers and computes `_primitive_count` (prefixed `_`, never used) then returns `Ok(())` — no compute pipeline is set and no `dispatch_thread_groups` is issued. `convert_geometry_shader_to_compute` does not convert anything: it embeds only `gs_source.len()` and emits a fixed dummy kernel (`output_vertices[out_idx].position = float4(0,0,0,1)` for `out_idx < 1024`) that ignores both the input buffer contents and `gs_source`. The `1024` cap is also unrelated to `max_output_vertices/max_output_primitives` from the emulation descriptor.
- Fix suggestion: Generate an actual kernel from `gs_source` honoring `max_output_vertices`/`max_output_primitives` (or return `Err` for unsupported input), set the pipeline state, and dispatch `ceil(vertex_count / input_verts_per_primitive)` threadgroups in `execute_geometry_pass`.

## [HIGH] draw_tessellation_patches ignores tessellation entirely

- File: src/metal_backend.rs:4804-4817, 4771-4801
- Description: `draw_tessellation_patches` binds control-point and factor buffers then issues a plain `draw_primitives(Triangle, 0, patch_count * control_point_count)` — raw control points drawn as triangles, with no post-tessellation vertex shader, no tessellation factor use, and no patch primitives. The `TessellationPipeline` (partition mode, factor, topology) is never consulted; `compute_tessellation_factors` also relies on "whatever pipeline was last bound" when `compute_pso` is `None` (nondeterministic). Hardware tessellation is not implemented.
- Fix suggestion: Use `MTLCommandEncoder`'s tessellation APIs — set a post-tessellation vertex function with a tessellation-factor buffer and `draw_patches(patch_count, patch_start, patch_index_buffer, ...)` — or return `Err` documenting that tessellation is unsupported rather than rendering incorrect triangles.

## [HIGH] D3D12 texture address modes map to the wrong Metal modes (off-by-one table)

- File: src/metal_backend.rs:2886-2894
- Description: The D3D12_TEXTURE_ADDRESS_MODE enumeration is `1=WRAP, 2=MIRROR, 3=CLAMP, 4=BORDER, 5=MIRROR_ONCE`. The mapping here is `1→ClampToEdge, 2→Repeat, 3→MirrorRepeat, 4→ClampToZero` — every entry is shifted: WRAP renders as clamp, MIRROR as wrap, CLAMP as mirror, BORDER as clamp-to-zero. Samplers created via `create_static_sampler` (line 2897-2932) therefore have the wrong address behavior for all modes.
- Fix suggestion: `1 => Repeat, 2 => MirrorRepeat, 3 => ClampToEdge, 4 => ClampToZero (or Border), 5 => MirrorClampToEdge`, `_ => ClampToEdge`.

## [MEDIUM] d3d12_filter_to_metal_sampler computes anisotropy 1, disabling anisotropic filtering

- File: src/metal_backend.rs:2875-2877
- Description: `desc.set_max_anisotropy(std::cmp::min(16, 1.max(filter as u8 >> 6) as u64))` — when the D3D12 anisotropic bit (0x40) is set, `filter as u8 >> 6` is `1`, so `1.max(1) = 1` and `min(16,1) = 1`: max anisotropy is 1, i.e. effectively no anisotropic filtering. (The cast to `u8` is also redundant given the D3D12 filter is 8 bits, but the arithmetic itself is the bug — it never yields 2, 4, 8, or 16.)
- Fix suggestion: Set anisotropy from the descriptor's separate anisotropy field (as `create_static_sampler` correctly does at line 2907-2909) or map the bit to a real value, e.g. `desc.set_max_anisotropy(if anisotropic { 16 } else { 1 })`; do not derive it from the filter bits.

## [MEDIUM] set_inline_data writes at hand-computed offsets that can diverge from the MTLArgumentEncoder layout

- File: src/metal_backend.rs:3242-3266
- Description: Inline data is written at offsets computed by a local walk (`Buffer => 16`, `Texture => 8`, `Sampler => 8`, `align_up(…, 16)` for every entry). The actual offsets used by Metal are those of the `MTLArgumentEncoder` created in `create_argument_buffer` (line 3130); Metal's layout aligns textures/samplers to 8 bytes, not 16, so for mixed layouts the local table can place the inline data at a different offset than Metal expects → the GPU reads stale/garbage inline constants. Buffers/textures/samplers are written through the encoder (correct), only inline data is written manually.
- Fix suggestion: Write inline data through the argument encoder where possible; if manual writes are unavoidable, derive each binding's offset from the encoder (e.g. `set_argument_buffer` bookkeeping / `offset` APIs exposed by Metal) instead of a parallel table, and keep the two layouts in sync.

## [MEDIUM] Intersection function table is created from a dummy non-ray kernel; no functions are ever set

- File: src/metal_backend.rs:3618-3659
- Description: `create_intersection_function_table` compiles `kernel void _dummy_ray_fn() {}` and creates a plain compute pipeline from it, then `new_intersection_function_table_with_descriptor(&descriptor)`. Intersection function tables must come from a pipeline containing real intersection functions; a table created this way yields nil/empty on devices, and nothing ever calls `set_function`/`set_function_at_offset` on the table, so `dispatch_rays`' intersection table binding (line 2054-2062) points at an empty table. Additionally `MetalIntersectionTable.max_instances` is never enforced.
- Fix suggestion: Create the table from a pipeline built with an intersection function (`[[intersection]]`), set the functions via `table.set_function(...)`, and return `Err` when the table is nil or the device lacks raytracing (Apple7+/macOS 13+ gate is missing here).

## [MEDIUM] Mesh pipeline passes payload_size as maxTotalThreadsPerMeshThreadgroup

- File: src/metal_backend.rs:3890-3893
- Description: `mesh_desc.set_max_total_threads_per_mesh_threadgroup(desc.payload_size as u64)` — `maxTotalThreadsPerMeshThreadgroup` is a *thread count*; `payload_size` is bytes of payload memory. Values like 64 or 4 KB either create a pipeline whose threadgroup limit is wrong (fails validation, e.g. payload_size > 1024 is out of range) or silently misconfigure the mesh shader, and the object->mesh payload memory is never sized. This causes the native pipeline to fail creation (falling back to compute emulation) on devices that do support mesh shaders.
- Fix suggestion: Set the threadgroup size from `mesh_thread_group_size`/`max_vertex_count`-derived thread counts and allocate payload via `set_threadgroup_memory_length`, or remove this call and validate `payload_size` against the device's `maxThreadgroupMemoryLength`.

## [MEDIUM] CommandBufferPool recycles in-flight buffers on a 100 ms heuristic and can duplicate handles

- File: src/metal_backend.rs:5090-5148
- Description: `reclaim_completed` (line 5122-5148) moves any in-flight handle older than 100 ms back into `available` without checking the actual GPU completion status — a command buffer that is still executing on the GPU (long frame, debugger pause, slow shader) can be re-acquired and re-submitted → use-after-free/race at the Metal level if this pool is ever wired to real buffers. Separately, `release` (5111-5117) does not check whether the handle was already reclaimed: a late `release()` of a reclaimed handle pushes the same handle into `available` a second time (duplicate), so `acquire` can hand out one handle twice.
- Fix suggestion: Base reclamation on real completion (store the `metal::CommandBuffer`/`status` or completion handler and only recycle when `status == Completed`); make `release`/`reclaim_completed` idempotent (`available.contains` check or a `HashSet`), and return `Err` on double-release.

## [MEDIUM] TextureStreamingManager evicts higher-priority textures first on tie-break

- File: src/metal_backend.rs:5686-5712
- Description: `evict_mip_levels` sorts by `last_access_frame` ascending (LRU first — correct) but the tie-break is `t2.priority.partial_cmp(&t1.priority)` which orders *higher* priority first in the eviction candidate list; the eviction loop then evicts candidates in list order, so among textures with equal access age it evicts the **higher**-priority (more valuable) texture — the opposite of intent (comment says "priority descending" is desired for the kept set). `update_priorities` (5719-5726) also divides by `tex.mip_levels` without a zero guard — `mip_levels == 0` yields NaN priorities.
- Fix suggestion: Use `t1.priority.partial_cmp(&t2.priority)` in the sort so lower priority is evicted first, and guard `update_priorities` with `.max(1)` on `mip_levels`.

## [MEDIUM] Documented emulations that silently do nothing: set_shading_rate, encode_sampler_feedback, depth-bounds patch

- File: src/metal_backend.rs:4072-4097 (`set_shading_rate`), 4190-4202 (`encode_sampler_feedback`), 4413-4468 (`set_depth_bounds` + `patch_fragment_shader_for_depth_bounds`)
- Description: `set_shading_rate` validates and returns `Ok` with no effect on the encoder ("available for future shading rate setup"). `encode_sampler_feedback` ignores the encoder and texture entirely and just zero-fills the CPU-side array. `patch_fragment_shader_for_depth_bounds` merely *appends* a separate `_depth_bounds_wrap` fragment function to the MSL source — the original entry point is not modified, the wrap function is never referenced by any pipeline, and `set_depth_bounds`'s `set_fragment_bytes(254/255)` writes are never read by anything. All three advertise GPU effects that never occur.
- Fix suggestion: Either implement the real behavior (render-pass `set_fragment_shading_rate` on macOS 13+; a feedback-encoding pass; actual shader source injection into the entry point plus pipeline recompilation) or return `Err(RcInvalidState)` / a documented "unsupported" result so callers do not rely on the effect.

## [MEDIUM] upload_rgba_frame_to_io_surface is a safe function that dereferences raw pointers

- File: src/metal_backend.rs:1202-1326
- Description: The public, non-`unsafe` function accepts a raw `*mut c_void` IOSurface pointer and passes it to FFI (IOSurfaceGetWidth/Height/Lock/GetBaseAddress/GetBytesPerRow) and to `unsafe IoSurfaceLockGuard::new`. The null check does not protect against dangling/wrong-typed pointers — a safe API invites safe callers to pass invalid pointers, yielding UB with no `unsafe` contract at the call site. This is also the cause of the seven deny-by-default clippy errors (see `## Clippy`) that break the clippy build.
- Fix suggestion: Mark the function `unsafe` (document the contract: live IOSurfaceRef matching the dimensions), or change the parameter to a safe wrapper type (e.g. `&IoSurfaceRef`), which also clears the clippy errors.

## [LOW] MetalSwapchain pre-allocates back-buffer textures that presentation never uses

- File: src/metal_backend.rs:828-852, 1001-1019, 1057-1060
- Description: `new()` allocates 1 (Discard) or 3 (Sequential) full-screen Private textures (`back_buffers`), but `present()` presents the CAMetalLayer drawable directly; `back_buffers`/`current_back_buffer_index` are only exposed via getters and `advance_back_buffer()` — nothing ever renders into or blits from them, and `in_flight_count` (784) is never updated. For `FlipModel::Sequential` this wastes 3×W×H×4 bytes of GPU memory for the lifetime of the swapchain.
- Fix suggestion: Remove the `back_buffers`/`current_back_buffer_index`/`in_flight_count` tracking (or actually render into the tracked buffers and blit to the drawable); keep only what the flip model genuinely needs.

## [LOW] fill_ellipse builds a vertex fan that is never used (dead code)

- File: src/metal_backend.rs:2526-2544
- Description: The first loop builds `verts` (centre + `segs+1` perimeter vertices) with `Vec::with_capacity((segs + 2) as usize)`, then the function ignores it and rebuilds the same geometry as `tri_verts`. The `verts` computation (including `ccx/ccy` closure calls) is pure dead work, and `segs` is computed twice (2525 and 2547).
- Fix suggestion: Delete the first loop and the duplicate `segs`; keep only the `tri_verts` triangle-fan construction.

## [LOW] CommandBufferPool stores unused opaque device/queue fields

- File: src/metal_backend.rs:5057-5068
- Description: `device` and `command_queue` (`u64`, "stored as opaque u64 for FFI safety") are written once in `new()` and never read anywhere; the pool never touches Metal objects. Dead state that misleads readers into thinking the pool owns real command buffers.
- Fix suggestion: Remove the fields (or store real `metal::Device`/`CommandQueue` if the pool is to be wired to actual command buffers).

## [LOW] AsyncShaderCompiler panics via .expect on thread spawn failure

- File: src/metal_backend.rs:5318-5338
- Description: `std::thread::Builder::new().name(...).spawn(...).expect("failed to spawn shader compiler thread")` — a thread-spawn failure (resource exhaustion, EMFILE) panics. Panics on the shader-compiler path are unnecessary; the failure is reportable through the API.
- Fix suggestion: Return `AppResult<Self>` (or store the spawn error in `failed`) and let the caller degrade gracefully.

## [LOW] ShaderPreCompiler stores MSL source text as "compiled binary"

- File: src/metal_backend.rs:5242-5253 (also 5191-5198)
- Description: `compile_next` "simulates compilation" by storing `request.msl_source.as_bytes().to_vec()` in `PreCompiledShader.binary`, whose doc says "Compiled binary data (serialized MTLLibrary)". Any consumer that feeds `binary` to a real Metal `new_library_with_data` would fail; the precompiler never invokes Metal.
- Fix suggestion: Either actually compile with the device and store a real binary library, or rename/document the field as source passthrough and return `Err` when a real binary is requested.

## [LOW] Texture mip-size math can panic in debug builds on untrusted mip/frame values

- File: src/metal_backend.rs:5603-5613 (`width >> mip`), 5647-5664 (`total_size += ...`, `used_bytes + additional_bytes`), 5719-5726 (NaN priority)
- Description: `mip_level_size` does `width >> mip` — for `mip >= 32` a debug build panics ("attempt to shift right with overflow") and release silently yields 0 (masked by `.max(1)`). `request_mip_level` accepts arbitrary `mip: u32` from callers, and `self.used_bytes + additional_bytes` (5656) can overflow `usize`. `update_priorities` divides by `mip_levels` with no zero guard (NaN).
- Fix suggestion: Clamp `mip` (e.g. `mip.min(31)` or use `u64` shifts), use `checked_add`/`saturating_add` for the budget math, and guard `tex.mip_levels.max(1)`.

## [LOW] MemoryAliasManager::create_alias does not validate resource extents or guard the savings sum

- File: src/metal_backend.rs:5915-5948
- Description: `create_alias` checks lifetime overlap but never verifies `resource.offset + resource.size <= size` for the shared region, and `resources.iter().map(|r| r.size).sum()` can overflow `usize` (debug panic). `free_regions` (5894) is never populated — dead field.
- Fix suggestion: Validate each `offset+size <= size` (checked add), compute `total_individual` with `fold` + `checked_add`, and remove or populate `free_regions`.

## [LOW] readback uses i32 arithmetic for buffer size (overflow for very large targets)

- File: src/metal_backend.rs:2735-2738
- Description: `let stride = (self.width * 4) as i32; let size = (stride * self.height as i32) as usize;` — for `width*height*4 > i32::MAX` (e.g. > ~536 MPix) this wraps to a negative value and `vec![0u8; size]` with the resulting huge `usize` aborts/OOMs; debug builds panic on the multiply.
- Fix suggestion: Compute in `u64`/`usize` with `checked_mul` and error out (or allocate the buffer directly at the GPU-read size) instead of going through `i32`.

## [LOW] dispatch_rays issues a zero-sized dispatch for zero dimensions

- File: src/metal_backend.rs:2087-2093
- Description: For `width == 0` or `height == 0`, `num_groups` becomes `(0, k, d)` and `dispatch_thread_groups` is called with a zero threadgroup count — Metal validation error / no-op rather than a clean early return. `depth as u64` is fine, but zero extents are untrusted input.
- Fix suggestion: Early-return `Ok(())` when `width == 0 || height == 0 || depth == 0` (or clamp to 1).

## [LOW] MetalGpuBackend resource registries grow without bound unless destroy is called

- File: src/metal_backend.rs:1594-1598, 1657-1707, 1806-1820
- Description: `buffers`/`textures`/`libraries`/`render_pipelines`/`compute_pipelines` are `BTreeMap<u64, _>` with no eviction and no cap; `destroy_*` exists but is opt-in, and `libraries` has no destroy function at all. A long-running guest that streams resources (the typical game workload) leaks GPU objects until the maps hold every object ever created. `NEXT_GPU_ID` (42-46) also wraps after 2^64 allocations (practically unreachable).
- Fix suggestion: Add reference counting/eviction (LRU or per-frame `destroy_*` from the guest's `ID3D12`-style release paths), add `destroy_library`, and/or cap the maps.

## [LOW] draw_mesh_threadgroups does not verify a mesh pipeline is bound

- File: src/metal_backend.rs:3936-3952
- Description: `draw_mesh_threadgroups` unconditionally calls `enc.draw_mesh_threadgroups(...)`. If the bound render pipeline is a regular (non-mesh) pipeline — e.g. the compute-emulation fallback from `create_mesh_pipeline` was selected — Metal raises a validation error (device-side fault). The function's own doc admits the caller must guarantee this.
- Fix suggestion: Track the last bound pipeline kind (store whether the active pipeline is a mesh pipeline in `MetalRenderEncoder`) and return `Err` instead of encoding when it is not.

## [PERF] D2D renderer allocates a new MTLBuffer per primitive and stalls on the GPU every frame

- File: src/metal_backend.rs:2416-2420 (`fill_rect`), 2495-2499 (`draw_line`), 2574-2578 (`fill_ellipse`), 2620-2624 + 2702-2716 (`draw_bitmap`), 2721-2730 (`end_frame`)
- Description: Every `fill_rect`/`draw_line`/`fill_ellipse`/`draw_bitmap` call creates one or more `MTLBuffer`s via `new_buffer_with_data` (GPU allocation + copy per draw), and `draw_bitmap` additionally creates a texture and a blit pass per call. `end_frame` then does `wait_until_completed()`, a full CPU–GPU sync that stalls the pipeline to ~1 frame/s for interactive D2D workloads (the main UI/compositing path in this project). Impact: heavy frame-time variance and CPU-side stall for every UI frame with multiple primitives.
- Fix suggestion: Use a ring of persistent vertex/upload buffers (write vertices into a mapped ring, `set_vertex_buffer` with offsets) and commit without `wait_until_completed` (use a completion handler or frame fencing); batch uploads into one blit per frame.

---

## Clippy

Run: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (clippy 1.96.0). Warnings/errors referencing `src/metal_backend.rs`:

**Errors (deny-by-default `clippy::not_unsafe_ptr_arg_deref` — 7 occurrences, break the build):**
- src/metal_backend.rs:1237 (`IOSurfaceGetWidth`), :1238 (`IOSurfaceGetHeight`), :1249 (`IOSurfaceLock`), :1259 (`IoSurfaceLockGuard::new`), :1261 (`IOSurfaceGetBaseAddress`), :1268 (`IOSurfaceGetBytesPerRow`) — safe public fn `upload_rgba_frame_to_io_surface` dereferences raw pointers. See MEDIUM finding above.

**Warnings (20, all non-blocking style lints):**
- `derivable_impls` — 586:1 (`Default for FlipModel`), 607:1 (`Default for ColorSpace`), 630:1 (`Default for FrameStatistics`)
- `manual_div_ceil` — 2088:20, 2089:21 (`dispatch_rays`), 4843:16 (`compute_tessellation_factors`)
- `needless_borrow` — 2344:61, 2369:62 (`MetalD2DRenderer::clear`), 3483:40, 3538:40, 3588:40 (acceleration-structure geometry descriptors)
- `too_many_arguments` — 2590:5 (`draw_bitmap`, 9 args)
- `unnecessary_cast` — 3164:53 (`offset as u64`)
- `new_without_default` — 5217:5 (`ShaderPreCompiler`), 5314:5 (`AsyncShaderCompiler`), 5433:5 (`DescriptorHeapPool`), 5771:5 (`RenderPassMerger`), 5901:5 (`MemoryAliasManager`)
- `collapsible_if` — 5387:9 (`AsyncShaderCompiler::shutdown`)

Note: the same `not_unsafe_ptr_arg_deref` errors appear twice in the log (lib + lib-test compilations). No rustc (type/borrow) errors exist for this file.

## Build

`cargo clippy --all-targets --no-deps` did **not** complete successfully:
- `casa1` (lib): **19 errors, 1271 warnings** — 7 errors in `src/metal_backend.rs` (above), 12 in other files (crash_recovery.rs, d3d11.rs, pe_runtime.rs, security.rs, d2d.rs, denuvo.rs, dwrite.rs — deny-by-default lints such as `absurd_extreme_comparisons`, `approx_constant`, `erasing_op`, `eq_op`, `logic_bug`, `uninit_vec`, `not_unsafe_ptr_arg_deref`).
- `casa1` (lib test): **27 errors, 1415 warnings** — 6 errors in `src/metal_backend.rs` (same lint; one fewer diagnostic than the lib pass), remainder in the other files listed above.
- Because the lib target failed, downstream targets (bins, examples, integration tests, benches) were not compiled in this run. The failure is attributable to deny-by-default clippy lints, not to rustc diagnostics; the crate itself type-checks.
- `--all-features` was intentionally not used (system ffmpeg missing is environmental).

---

### Summary counts
- CRITICAL: 1
- HIGH: 9
- MEDIUM: 8
- LOW: 11
- PERF: 1
- **Total findings: 30** (+ 7 clippy errors and 20 clippy warnings listed above; build failure documented).
