# AUDIT_FINDINGS.md

- Batch: Casa1 graphics-layer audit (batch 1)
- Files: src/gfx.rs (3762 lines), src/d3d12.rs (2165 lines), src/d3d10.rs (1639 lines), src/d2d.rs (1109 lines) — read fully, every line
- Date: 2026-08-15
- Scope: logic errors, panics from untrusted input, unsafe misuse, resource leaks, concurrency, swallowed errors, performance, FFI/spec errors, dead code, clippy

---

## [CRITICAL] Unchecked offset arithmetic in CopyBufferRegion execution can panic or corrupt via wrap-around

- File: src/gfx.rs:2387-2393
- Description: `src_start = *src_offset as usize`, `dst_start = *dst_offset as usize`, `len = *size as usize` are all guest-controlled u64 values from the recorded command. `src_start + len` and `dst_start + len` are plain additions. With `src_offset = u64::MAX` (or any value where start+len overflows `usize`), the sum wraps: debug builds panic on the add; release builds can pass the `<= bytes.len()` guard with a wrapped sum and then `dst_bytes.bytes[dst_start..dst_start + len]` panics with an out-of-range slice index, or copies from a wrong region (silent data corruption). Reachable via `execute_command_lists` on guest-recorded copy commands.
- Fix suggestion: Use `checked_add`/`checked_range` and return `AppError::new(ReasonCode::RcD3dInvalidState, ...)` on overflow or out-of-bounds instead of silently skipping or slicing.

## [CRITICAL] upload_write offset + len overflow panics from untrusted offset

- File: src/gfx.rs:2578-2585
- Description: `let end = offset + bytes.len();` — `offset` is guest-supplied. If `offset + bytes.len()` overflows `usize`, the `end > resource.bytes.len()` guard can pass (wrapped end) and `resource.bytes[offset..end]` then panics ("range start index out of range") because `offset` is huge. Debug builds panic on the add itself.
- Fix suggestion: Compute `offset.checked_add(bytes.len())` and reject with an `AppError` on `None` before the bounds check.

## [HIGH] DxgiFormat::from_u32 table does not match the DXGI ABI and is internally inconsistent

- File: src/gfx.rs:76-148
- Description: The raw-to-enum table disagrees with real `DXGI_FORMAT` values, and with values used elsewhere in this crate (d2d.rs:32-33 defines `DXGI_FORMAT_B8G8R8A8_UNORM = 87` / `_SRGB = 91`, which are the real ABI values, while from_u32 maps 55→B8G8R8A8Unorm and 56→B8G8R8A8UnormSrgb and leaves 87/91 unhandled so they fall through to the `_ => R8G8B8A8Unorm` default). Other mismatches: 1→R32G32B32A32Float (1 is TYPELESS; 2 = FLOAT and 3 = UINT are unhandled), 4→R32G32B32A32Uint (4 is SINT), 29→R8Unorm (29 is R32_UINT), 36/37→R10G10B10A2Unorm (36/37 are R32G8X24_TYPELESS / D32_FLOAT_S8X24_UINT; R10G10B10A2_UNORM is 41), 6→Uint and 7→Float (swapped; 6=FLOAT, 7=UNORM), 100→D24UnormS8Uint (real D24_UNORM_S8_UINT = 33). Any format the guest passes that is missing from the table silently becomes R8G8B8A8Unorm — wrong surface creation, wrong clears, wrong views.
- Fix suggestion: Replace the table with the canonical DXGI_FORMAT enum values from d3dcommon.h (align with d2d.rs 87/91), and make the fallthrough arm return an error or a `Typeless`/`Unknown` representation instead of silently re-mapping to R8G8B8A8Unorm.

## [HIGH] CopyResourceRegion uses dst_y to compute the source row offset and ignores src_x/dst_x

- File: src/gfx.rs:2418-2431
- Description: In the execution of `Command::CopyResourceRegion`, `let src_offset = (*dst_y as usize) * src_stride;` uses the destination y for the source offset (should use `src_y`); `src_x`/`dst_x` are bound to `_` and ignored, and `depth`/`dst_z`/`src_z` are ignored too. Even accepting that this is an "approximate" texture copy, using `dst_y` for the source row is plainly wrong: any copy with dst_y != src_y copies the wrong source rows, and nonzero `src_x`/`dst_x` are silently dropped.
- Fix suggestion: Compute `src_offset = src_y * src_stride + src_x * bpp`, `dst_offset = dst_y * dst_stride + dst_x * bpp` (with checked arithmetic), and loop `row_count` rows; use checked bounds per row.

## [HIGH] d3d12 map_d3d12_address_mode swaps WRAP and CLAMP (and mis-maps MIRROR)

- File: src/d3d12.rs:323-331
- Description: The D3D12_TEXTURE_ADDRESS_MODE mapping is: 1 => "clamp_to_edge", 2 => "repeat", 3 => "mirror_repeat", 4 => "clamp_to_zero". Real D3D12 values are WRAP=1, MIRROR=2, CLAMP=3, BORDER=4. So WRAP becomes clamp, CLAMP becomes mirror_repeat, and MIRROR becomes repeat — every address mode is wrong except BORDER. Compare with the correct mapping in d3d10.rs:515-524 (WRAP→"wrap", MIRROR→"mirror", CLAMP→"clamp", BORDER→"border", MIRROR_ONCE→"mirror_once"). This feeds `static_sampler_to_metal_desc` (d3d12.rs:359-388), so all static-sampler addressing in generated Metal sampler descriptors is wrong.
- Fix suggestion: Map 1→"repeat", 2→"mirror_repeat", 3→"clamp_to_edge", 4→"clamp_to_zero", 5→"mirror_repeat" (or emit the appropriate border semantics), matching d3d10.rs.

## [HIGH] D3D10 view creation hardcodes formats, ignoring the caller's RTV/DSV/SRV desc

- File: src/d3d10.rs:856-886
- Description: `create_render_target_view` always passes `DxgiFormat::R8G8B8A8Unorm`, `create_depth_stencil_view` always passes `DxgiFormat::D24UnormS8Uint`, and `create_shader_resource_view` always passes `R8G8B8A8Unorm`, ignoring `_desc.format` entirely. Any view created on a B8G8R8A8, R16G16B16A16Float, R32Float, D32Float, or other-format resource gets the wrong format — and against backends that validate view format vs. resource format, these calls fail outright for every non-RGBA8 resource.
- Fix suggestion: Thread the `D3d10RenderTargetViewDesc`/`D3d10DepthStencilViewDesc`/`D3d10ShaderResourceViewDesc` `format` (falling back to the resource's format when `None`) into the d3d11 call.

## [HIGH] clear_depth_stencil_view truncates the float depth to u32 via `as`

- File: src/d3d10.rs:1104-1116
- Description: `let depth_val = if clear_flags & D3D10_CLEAR_DEPTH != 0 { depth as u32 } else { 0 };` — casting an f32 depth (e.g. 0.5, 0.75, 1.0) with `as u32` truncates to the integer part: 0.5→0, 1.0→1. A depth clear of 0.5 clears to 0.0, and any fractional depth is destroyed. (If the underlying d3d11 API expects the IEEE-754 bit pattern, `depth.to_bits()` is required; plain `as u32` is wrong under either interpretation.)
- Fix suggestion: Pass the depth as f32 or use `depth.to_bits()` depending on the d3d11 `clear_depth_stencil_view` contract; never `f32 as u32`.

## [HIGH] d2d.rs IID constants are not the real Direct2D interface GUIDs

- File: src/d2d.rs:59-65
- Description: `IID_ID2D1Factory` is declared as `06152206-84C0-47D4-84A3-B44B4F6C14AF`; the real `IID_ID2D1Factory` is `06152247-6F50-465A-9245-118BFD3B6007`. `IID_ID2D1HwndRenderTarget` is declared as `A4738A38-C083-4C44-84F5-4A17FD076632`; the real value is `2CD90691-12E2-11DC-9FED-001143A055F9`. Guest `QueryInterface` calls using the correct GUIDs will fail to match, breaking D2D COM negotiation.
- Fix suggestion: Replace both GUID byte arrays with the canonical D2D1 IIDs (verify against d2d1.h/d2d1_1.h).

## [HIGH] HwndRenderTarget allocation arithmetic overflows i32, causing huge/negative allocations

- File: src/d2d.rs:350-351
- Description: `let stride = (width * 4) as i32;` (u32 multiply can wrap for width >= 2^30) and `let pixel_count = (stride * height as i32) as usize;`. `stride * height` is i32 math: for surfaces above ~2^31/4 pixels (e.g. 24576x24576) it overflows — debug panics, release wraps negative, and `(negative) as usize` produces a huge value, so `vec![0u8; pixel_count]` attempts an absurd allocation (OOM abort) from guest-controlled window dimensions. The buffer is then silently too small for subsequent pixel writes.
- Fix suggestion: Use `usize` math throughout: `let stride = (width as usize) * 4; let pixel_count = stride * height as usize;` and validate dimensions up front.

## [HIGH] D3D10 IID table uses invented GUIDs (0x80-0x8D suffix pattern)

- File: src/d3d10.rs:1318-1396
- Description: `ID3D10DEVICE` ({9B7E4C0F-342C-4106-A19F-4F2704F689F0}) matches the real IID, but all other entries (TEXTURE2D 0x80, BUFFER 0x81, RTV 0x82, DSV 0x83, SRV 0x84, VS 0x85, PS 0x86, GS 0x87, InputLayout 0x88, Sampler 0x89, BlendState 0x8A, Rasterizer 0x8B, DSState 0x8C, Multisample 0x8D) use a fabricated sequential pattern. The real D3D10 interface IIDs are `{9B7E4C01..0x0E-342C-4106-A19F-4F2704F689F0}` (Buffer=01, Texture1D=02, Texture2D=03, Texture3D=04, SRV=05, RTV=06, DSV=07, InputLayout=08, VS=09, GS=0A, PS=0B, Sampler=0C, BlendState=0D, DSState=0E). Guest QI with real GUIDs will fail for every interface except the device.
- Fix suggestion: Replace the 0x80-0x8D byte sequences with the canonical GUID bytes (verify against d3d10.h).

## [MEDIUM] ClearDsv commands are silently dropped by the execution planner

- File: src/gfx.rs:2343
- Description: In `process_execution_command`, `Command::ClearDsv { .. } => {}` is a no-op: it does not split/end the active render pass, does not update the pass plan's load action, and does not clear any bytes. A D3D12 DSV clear recorded by the guest has no effect whatsoever in the execution plan.
- Fix suggestion: Mirror the ClearRtv handling: end/split the active pass or set `load_action = "clear"` on the matching depth pass; at minimum emit a validation error or count it.

## [MEDIUM] present() never rotates backbuffers; presented_frame always returns buffer 0

- File: src/gfx.rs:1351-1395 (presented_backbuffer_index = 0 at 1354, used at 1416-1424)
- Description: `record.presented_backbuffer_index = 0;` on every present, and nothing ever advances it, so `presented_frame()`/PPM export/frame-published callback always report the same (empty, unless the guest wrote) backbuffer. The swapchain emulation tracks `queued_frames` but never simulates buffer rotation or frame content progression.
- Fix suggestion: Rotate `presented_backbuffer_index = (index + 1) % backbuffers.len()` per present, or store the presented frame snapshot explicitly.

## [MEDIUM] No destroy/Release path for swapchains, descriptor heaps, command lists, fences, query heaps, root signatures, pipeline states — unbounded map growth

- File: src/gfx.rs:1277-2660 (create_* APIs); only `destroy_resource` exists (1523-1528)
- Description: The backend exposes `destroy_resource` only. Swapchains (with their backbuffer resources), descriptor heaps, command lists, fences, query heaps, root signatures and PSOs are never removed from the `BTreeMap`s. A guest that creates/destroys resources per frame (typical D3D12 apps recycle heaps and fences) accumulates entries forever — memory growth proportional to guest lifetime.
- Fix suggestion: Add `destroy_*`/`release_*` methods for each object type and wire them to the guest `Release` paths.

## [MEDIUM] resize_buffers destroys old backbuffers before allocating new ones; failure leaves the swapchain broken

- File: src/gfx.rs:1467-1493
- Description: Old backbuffers are destroyed first, then new ones are created via a `collect::<AppResult<Vec<_>>>()?` — if any allocation fails, the swapchain's backbuffer list has already been emptied and the error propagates, leaving `state.backbuffers` pointing at destroyed resources; the next `present`/`presented_frame` fails with "unknown resource".
- Fix suggestion: Allocate the new backbuffers first, then destroy the old ones and swap the lists; on failure keep the old state intact.

## [MEDIUM] Subresource state tracking uses two incompatible key conventions

- File: src/gfx.rs:1576-1577 vs 1924-1945 (and d3d12.rs:164/258-280)
- Description: `transition_resource`/`transition_resource_internal` insert `(resource, 0, subresource)` — the third component is the flat D3D12 subresource index. `set_subresource_state`/`subresource_state` treat the second/third components as (array_slice, mip_level). A transition on subresource 3 of an array texture stores state under mip=3 rather than (array=3/4, mip=...), so lookups via `subresource_state()` return `None` or a stale state for arrayed/mipmapped resources.
- Fix suggestion: Pick one convention; convert the flat D3D12 subresource index to (array_slice, mip_level) (or vice versa) at every call site.

## [MEDIUM] pending_immediate_writes is append-only — never drained, unbounded growth

- File: src/d3d12.rs:1591-1612 (field at 173, initialized 198/229)
- Description: `write_buffer_immediate` pushes `(list, dst_gpu_addr, value_bytes)` onto `pending_immediate_writes`, and no code ever removes entries (comment says they are processed during command list execution, but no draining exists in this module). A guest calling WriteBufferImmediate per frame grows the Vec without bound; the writes are also never actually applied anywhere.
- Fix suggestion: Process and clear the queue in `execute_command_lists` (resolve dst to a resource and apply the 8 bytes), or bound the queue length.

## [MEDIUM] aliasing_overlaps grows without bound and is scanned linearly

- File: src/d3d12.rs:661-736 (also 655-663)
- Description: Every `record_aliasing_barrier`/`record_resource_barrier` pushes to `aliasing_overlaps`; only an explicit `clear_aliasing_overlaps()` empties it (never called internally), and `check_aliasing_overlap` is an O(n) scan. Over a long session this is unbounded memory plus O(n) lookups per barrier check.
- Fix suggestion: Cap or prune entries (e.g. deduplicate by pair, or store a bounded HashSet), and clear on execute.

## [MEDIUM] Timestamp queries never compute begin/end delta; resolve writes nothing to the destination buffer

- File: src/d3d12.rs:910-996 (record_begin_query/record_end_query/record_resolve_query_data)
- Description: `record_begin_query` stores the begin timestamp, then `record_end_query` calls `backend.write_timestamp(heap, idx)` which OVERWRITES the same slot — the result contains only the end timestamp, not `end - begin`. `record_resolve_query_data` ignores `_start`, `_count` and `_dst` and merely calls `resolve_query_data` on the backend, writing no bytes into the guest's readback buffer, so the guest reads stale memory. Also `let ts = self.backend.write_timestamp(heap, idx).unwrap_or(0);` swallows the error (line 933).
- Fix suggestion: Store begin and end in separate slots and write `end - begin`; in `record_resolve_query_data`, copy the resolved values into the destination resource bytes (with bounds checks) honoring start/count.

## [MEDIUM] copy_subresource_region performs a whole-resource copy, ignoring the source box and destination coordinates

- File: src/d3d10.rs:1132-1146
- Description: All region parameters (`_dst_x/_dst_y/_dst_z/_src_subresource/_src_box`) are discarded and the call becomes `copy_resource(src, dst)`. Copying a small sub-rectangle of a texture therefore copies the entire resource — wrong content in every case where the box does not span the whole texture, and silently larger than the guest expects.
- Fix suggestion: Implement row/region copy semantics (or return `RcD3dFeatureUnsupported` for unsupported boxes rather than silently copying everything).

## [MEDIUM] D3D10 input layout conversion drops per-instance data, offsets, and step rates

- File: src/d3d10.rs:717-725
- Description: `D3d10InputElementDesc::to_d3d11` keeps only `semantic_name + semantic_index` and `format`/`slot`; `input_slot_class` (PER_INSTANCE_DATA) and `instance_data_step_rate` are dropped, and `aligned_byte_offset` is dropped. Any instanced draw with per-instance attributes silently becomes per-vertex, and offset-derived layouts read the wrong vertex bytes.
- Fix suggestion: Extend `crate::d3d11::InputElementDesc` with the missing fields (offset, slot_class, step_rate) and map them through.

## [MEDIUM] D3D10 present() targets hardcoded swapchain 0

- File: src/d3d10.rs:1185-1188
- Description: `self.d3d11_device.present_swapchain(0, false, true)?` — the swapchain created by `d3d10_create_device_and_swapchain` is created with the backend's allocator (first id is 1, since `GraphicsBackend::next_id` starts at 1, gfx.rs:1192), so presenting swapchain 0 fails with "unknown swapchain" for device-and-swapchain creation. The entry point also never returns the swapchain handle to the guest.
- Fix suggestion: Store the created swapchain id in `D3d10Device` and present that id; expose the id to the caller of `d3d10_create_device_and_swapchain`.

## [MEDIUM] Gradient brush color_at ignores opacity and extrapolates before the first stop

- File: src/d2d.rs:172-259 (linear 172-218, radial 219-259)
- Description: (1) `D2DBrush::Solid` applies `s.opacity`, but `LinearGradient`/`RadialGradient` never multiply the resolved color by opacity — same brush opacity settings render differently per brush type. (2) When `t` is smaller than the first stop's position (stops[0].position > 0), the search leaves `i = 0`, `next = 1`, and `local_t = (t - stops[0].position)/span` is negative — the color is extrapolated below the first stop instead of clamping to it, producing out-of-range (possibly negative) channel values.
- Fix suggestion: Clamp `t` to the first/last stop positions before interpolating (or clamp the interpolant to [0,1]), and apply the brush opacity to the final color in all three arms.

## [MEDIUM] draw_text with a hardware renderer ends the Metal frame mid-draw, then end_draw flushes again

- File: src/d2d.rs:699-701 (flush inside draw_text) and 469-473 (end_draw → flush_hardware)
- Description: `begin_draw()` calls `hw.begin_frame()`. If `hw_renderer` is Some, every `draw_text` calls `self.flush_hardware()` which calls `hw.end_frame()` (and a GPU readback); the subsequent `end_draw()` calls `flush_hardware()` again — `end_frame()` is invoked twice with no intervening `begin_frame()`, and pixels are read back mid-frame (before text is even blended). Depending on `MetalD2DRenderer`'s state machine this is a double-commit/crash and at minimum a per-text-frame sync stall.
- Fix suggestion: Track an explicit "frame active" flag in `flush_hardware`/`end_draw` (flush only between begin/end), and defer the readback to `end_draw` only.

## [MEDIUM] Split barrier END without a matching BEGIN still applies the transition

- File: src/gfx.rs:1810-1840 (same pattern in d3d12.rs:700-719)
- Description: `record_split_barrier_end` searches `pending_split_barriers` and, if no matching BEGIN is found, still calls `transition_resource_internal` and records the END command. D3D12 debug validation rejects END_ONLY without a pending BEGIN; more importantly the resource state is mutated on a malformed barrier sequence, so subsequent barrier validation sees a state the guest never requested. (Related: `record_transition` also mutates the resource state before pushing the command, so a failure to find the command list leaves the state changed — gfx.rs:1730-1748.)
- Fix suggestion: Return `RcD3dInvalidState` when no matching pending begin exists (or when the command list is unknown), and reorder so the command-list mutation is validated before state is changed.

## [LOW] from_d3d12_bits pushes two different states for the same 0x10000 bit

- File: src/gfx.rs:486-491
- Description: `bits & 0x10000` pushes `ShadingRateSource` and the immediately following `bits & 0x00010000` pushes `VideoDecodeRead` — the two constants are the same value (they alias in d3d12.h, mutually exclusive contexts), so any bitmask with bit 16 set yields both variants in the result vector.
- Fix suggestion: Document the aliasing and push only one variant (or collapse into a single state).

## [LOW] Render-pass merge behavior is gated on mesh_shaders capability

- File: src/gfx.rs:2271-2281
- Description: `pass.can_merge_with(...)` merging is only attempted when `self.capabilities.mesh_shaders` is true. GPU families without mesh shaders (e.g. M1, family 7) never merge adjacent identical passes, producing different pass-plan structure than M3+ hardware for the identical command stream — behavior differs by capability in a way unrelated to merging.
- Fix suggestion: Remove the `mesh_shaders` gate; merging identical load/store passes is valid on all families.

## [LOW] close_command_list may be called repeatedly without error

- File: src/gfx.rs:2215-2222
- Description: A second `close_command_list` on the same list simply re-sets `closed = true` and returns the same (unchanged) command clone; D3D12 returns an error for closing an already-closed list. Also, commands recorded after a close are still executed (the recorders never check `closed`).
- Fix suggestion: Return `RcD3dInvalidState` if `record.closed` is already true; check `closed` in the `record_*` methods.

## [LOW] wait_for_fence ignores the timeout and can busy-return

- File: src/gfx.rs:2560-2563
- Description: `wait_for_fence(fence, value, _timeout_ns)` ignores the timeout entirely and returns `current >= value` immediately. A guest spinning on `WaitForFence` (expecting to block until completion or timeout) gets an instant answer; callers polling in a loop will busy-spin.
- Fix suggestion: If no real blocking primitive exists, at least document/emulate the timeout by tracking fence values and returning `false` on timeout semantics, or sleep briefly on `current < value` when a timeout is provided.

## [LOW] ResourceRecord.live is never set false; live_resource_count is meaningless

- File: src/gfx.rs:1057-1063 (field), 1517 (always true), 1530-1535 (count)
- Description: `live: true` is set at creation and never changed anywhere; `destroy_resource` removes the map entry, so the `live` field and `live_resource_count()` filter are dead bookkeeping.
- Fix suggestion: Remove the field or maintain it (e.g. mark entries from aliasing/place-holder paths).

## [LOW] begin_render_pass sets render_pass_active before the fallible backend call

- File: src/d3d12.rs:1002-1018
- Description: `self.render_pass_active = true;` executes before `self.backend.record_begin_render_pass(...)?`. If the backend call fails, `render_pass_active` remains true, desyncing `is_render_pass_active()`/`reset_render_pass_state()`.
- Fix suggestion: Set the flag after the `?`.

## [LOW] Silent no-op stubs for D3D12 state: front/back stencil ref, depth bias, strip-cut value, atomic copies, meta commands, sample positions

- File: src/d3d12.rs:1464-1512 (omset_front_and_back_stencil_ref, rsset_depth_bias, iaset_index_buffer_strip_cut_value, atomic_copy_buffer_uint/uint64), 1029-1041 (initialize/execute_meta_command), 1531-1544 (set_sample_positions)
- Description: All return `Ok(())` without any effect (except storing trivial state). Games using depth bias, stencil ref, strip-cut or atomic copies render incorrectly with no diagnostic. This is acknowledged stub code but represents unfinished functionality with silent failure.
- Fix suggestion: Emit a validation error / trace when these are called with non-default values, or thread the state through the backend so it reaches the Metal plan.

## [LOW] DXIL raytracing metadata scanner is largely dead and heuristic

- File: src/d3d12.rs:1313-1367
- Description: `std::str::from_utf8(dxil)` on real DXIL (LLVM bitcode) will almost always fail, so the ASCII-line scan almost never runs; the binary scan matches ANY u32 == 19 anywhere in the blob (not a real metadata tag), so values are essentially arbitrary; `dxil.windows(4)` chunks are always length 4, making the `chunk.len() < 4` guard dead. Parsed params are therefore unreliable defaults.
- Fix suggestion: Either remove the scan and use documented defaults, or implement real DXIL metadata parsing; at minimum fix the dead guard.

## [LOW] Dead fields: fence_values and meta_command_params are never read or written meaningfully

- File: src/d3d12.rs:148-153 (fields), 176-231 (init)
- Description: `fence_values` is never populated (wait_for_fence delegates to the backend, 882-885) and `meta_command_params` is never used (initialize_meta_command is a stub). Dead state bloats the struct and invites confusion.
- Fix suggestion: Remove both fields, or wire them to their documented use.

## [LOW] static_sampler_to_metal_desc does not validate max_anisotropy / LOD range

- File: src/d3d12.rs:359-388 (validate exists separately at 391-408 but is not called here)
- Description: `validate_static_sampler` rejects max_anisotropy > 16 and min_lod > max_lod, but `static_sampler_to_metal_desc` never calls it, so a guest-provided sampler with e.g. max_anisotropy 100 emits `max_anisotropy(100)` into the Metal sampler descriptor string, which fails at Metal compile/validation time with a confusing error.
- Fix suggestion: Call `validate_static_sampler` at the start of `static_sampler_to_metal_desc` (or clamp), and return an `AppResult`.

## [LOW] D3D10 parser accepts DXIL magic but cannot parse DXIL containers

- File: src/d3d10.rs:58-68
- Description: `parse_dxbc_bytecode` accepts `DXIL` magic, but DXIL containers have no 12-byte chunk descriptor table; `chunk_count` is read from bytes 12..16 which are hash/bitcode bytes, so the chunk scan (bounded, no panic) will almost always fail with "no SHDR/SHEX chunk found". Accepting DXIL here promises support that does not exist.
- Fix suggestion: Reject DXIL magic with a clear "D3D10 requires DXBC SM4" error, or implement DXIL stage extraction.

## [LOW] MSAA sample_desc is ignored when creating D3D10 textures

- File: src/d3d10.rs:781-808
- Description: `D3d10Texture2dDesc.sample_desc.count` is never forwarded (the d3d11 create call takes no sample count), so multisampled D3D10 resources silently become non-MSAA — resolves then copy single-sampled data.
- Fix suggestion: Forward the sample count into the d3d11/gfx resource creation path, or reject sample_desc.count > 1 with a clear error.

## [LOW] Staging resources are mapped to write-frequent shared buffers instead of readback

- File: src/d3d10.rs:1192-1234
- Description: `map_d3d10_usage_to_hint` treats `D3D10_USAGE_STAGING` as `cpu_write_frequent` (line 1203) and ignores `_cpu_access_flags`; a staging texture used for CPU readback (Map with D3D10_MAP_READ) gets a write-oriented placement, and the Map/Unmap path (1163-1172) clones the whole buffer rather than honoring map flags.
- Fix suggestion: Map STAGING+CPU_ACCESS_READ to a readback-style hint; honor `cpu_access_flags` in the hint derivation.

## [LOW] D3D10 creation flags and driver type are ignored

- File: src/d3d10.rs:1257-1311
- Description: `d3d10_create_device`/`d3d10_create_device_and_swapchain` ignore `driver_type` (WARP vs hardware), `_feature_levels`, and `flags` (other than storing them); every device is Level10_1 on hardware. Debug/ref devices and feature-level selection have no effect.
- Fix suggestion: Thread `driver_type`/feature levels into `DeviceCreationRequest` and validate `flags` (reject unknown flags or honor BGRA).

## [LOW] Silent early-returns when brush/format/bitmap ids are not found

- File: src/d2d.rs:704-707 (draw_text format lookup), 734-737 (draw_bitmap lookup)
- Description: Missing ids return silently with no error/log, so broken guest handles produce invisible rendering with no diagnostic.
- Fix suggestion: Log a warning or return an `AppResult` from these draw calls.

## [LOW] draw_rectangle hardware path draws corners twice

- File: src/d2d.rs:576-586
- Description: The outline is 4 line segments sharing endpoints, so corner pixels are drawn twice (double-alpha blending at corners vs. the gdiplus path).
- Fix suggestion: Clip segments to exclude shared endpoints, or use a single hardware rect-outline primitive.

## [PERF] CopyResource/ResolveSubresource clone the entire source buffer per command

- File: src/gfx.rs:2371-2372, 2439-2440
- Description: Execution of `CopyResource` and `ResolveSubresource` does `self.resource(*src)?.bytes.clone()` then assigns to the destination — a full heap allocation and copy of the whole (potentially multi-MB) buffer for every copy command, per frame. The clone is unnecessary; the bounds-safe path could copy in place, and `execute_command_lists` runs this on the main thread.
- Fix suggestion: Use `dst_bytes.bytes[..] = src_bytes[..]` via `copy_from_slice` with a length check, avoiding the intermediate allocation.

## [PERF] d2d clear() software path is a per-pixel function-call loop

- File: src/d2d.rs:493-506
- Description: Software `clear` iterates every pixel calling `gdiplus_render::put_pixel`, i.e. O(width*height) indirect calls for what is a memset of a constant 4-byte pattern.
- Fix suggestion: Build the ARGB pattern once and fill with a vectorized loop / `chunks_exact_mut` copy, or `fill` a pre-made pattern.

## [PERF] flush_hardware performs a GPU readback + full-surface copy on every end_draw

- File: src/d2d.rs:450-459
- Description: Each `end_draw` (and each `draw_text` with a hardware renderer) calls `hw.readback()` and replaces `self.pixels` — a GPU→CPU sync stall and full-frame copy per frame, defeating GPU acceleration for the common path.
- Fix suggestion: Make readback optional/lazy (only when a caller requests pixel data), and skip the CPU copy when the surface is unchanged.

## [PERF] build_raytracing_acceleration_structure prints via eprintln! on every build

- File: src/d3d12.rs:1115-1120
- Description: Every AS build (which games do per frame) writes an `eprintln!` — unbuffered stderr I/O on the render thread, plus it reveals guest addresses in logs.
- Fix suggestion: Route through the crate's trace/logging at debug level instead of `eprintln!`.

## Clippy

Ran: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt` (output: clippy_out.txt, 21850 lines). Warnings/errors referencing the audited files:

- error: clippy::erasing_op (deny-by-default) — src/d2d.rs:974:20, 974:40 — `0 * target.stride` and `0 * 4` in test `test_d2d1_clear` are always zero (the test still passes since idx = 0, but the expression is misleading).
- warning: clippy::identity_op — src/d2d.rs:974:19
- warning: clippy::new_without_default — src/d2d.rs:334 (`D2DFactory::new` has no `Default`)
- warning: clippy::too_many_arguments — src/d2d.rs:685 (`draw_text`, 8/7), src/d3d10.rs:1132 (`copy_subresource_region`, 9/7), src/d3d12.rs:827 (`record_copy_resource_region`, 13/7), src/gfx.rs:2072 (`record_dispatch_rays`, 9/7), src/gfx.rs:2134 (`record_copy_resource_region`, 13/7), src/gfx.rs:2230 (`process_execution_command`, 10/7)
- warning: clippy::legacy_numeric_constants — src/d3d10.rs:472, 473 (`std::f32::MAX` → `f32::MAX`)
- warning: clippy::collapsible_match — src/d3d12.rs:1170
- warning: clippy::unnecessary_map_or — src/d3d12.rs:1172 (`map_or(false, ...)` → `is_some_and`)
- warning: clippy::manual_pattern_char_comparison — src/d3d12.rs:1331
- warning: clippy::collapsible_if — src/d3d12.rs:1341, 1355; src/gfx.rs:1373
- warning: clippy::derivable_impls — src/gfx.rs:696 (`D3D12ShaderVisibility`), src/gfx.rs:765 (`RootSignatureDesc`)

Note: none of these are logic bugs; the only deny-level errors in scope are the two `erasing_op` in the d2d test.

## Build

`cargo clippy --all-targets --no-deps` did NOT complete cleanly:

- `casa1 (lib)`: FAILED — "could not compile `casa1` (lib) due to 19 previous errors; 1271 warnings emitted" (clippy_out.txt:20322).
- `casa1 (lib test)`: FAILED — "could not compile `casa1` (lib test) due to 27 previous errors; 1415 warnings emitted" (clippy_out.txt:21850). Targets after the lib (bins/tests/examples/benches) were not checked.

In-scope error contributors: src/d2d.rs:974:20 and 974:40 (clippy::erasing_op, deny-by-default — the two test-lint errors listed above).

Out-of-scope error contributors (pre-existing, not part of this audit's files): src/crash_recovery.rs:536, src/seh.rs:1978, src/dwrite.rs:1398, src/pe_runtime.rs:48799, src/metal_backend.rs:1237-1268, src/jit.rs:34-109, src/video_decoder.rs:573, src/cpu.rs:29878/32760/32768, src/real_win32.rs:9474/9708, src/security.rs:3097/5293/5471/6193, src/winhttp.rs:3624, src/audio_format.rs:855, src/d3d11.rs:3687, src/denuvo.rs, src/diagnostics.rs, src/gdiplus_render.rs, src/ge.rs, src/installer.rs.

Because the crate does not compile under clippy's deny-by-default lints, this audit could not get a full clean lint pass; the manual code review above covers the four files completely regardless.

---

## Summary

- CRITICAL: 2
- HIGH: 8
- MEDIUM: 14
- LOW: 16
- PERF: 4
- Total findings: 44 (excluding the Clippy-section listing)
- Report: AUDIT_FINDINGS.md (this file, worktree root)
