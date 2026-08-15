# AUDIT_FINDINGS.md

- **Batch:** audit-d3d11 (batch 1, worktree `audit-d3d11`)
- **Files audited:** `src/d3d11.rs` (only file in scope)
- **Lines:** 5355 (1–5355, read sequentially in full, 3 passes, no lines skipped)
- **Date:** 2026-08-15
- **Auditor:** Senior code auditor (Kilo)
- **Toolchain:** `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (result in `clippy_out.txt`; crate does NOT compile — see `## Build`)

---

## [HIGH] CopySubresourceRegion: unchecked `offset + size` arithmetic can overflow and panic

- File: src/d3d11.rs:2131
- Description: In the command replay at submit time, `src_end = src_offset + size` and `dst_end = dst_offset + size` are computed with plain `+` on `usize`. `src_offset`, `dst_offset` and `size` are game-controlled (passed through `copy_subresource_region`, src/d3d11.rs:1682). In debug builds an overflow panics outright; in release builds the wrap can make `src_end < src_offset`, pass the bounds checks at src/d3d11.rs:2133, and then `&source[src_offset..src_end]` / `destination.bytes[*dst_offset..dst_end]` at src/d3d11.rs:2139-2140 panic on a reversed slice range. This is a panic reachable from untrusted (emulated-game) input.
- Fix suggestion: use `checked_add` for both sums and reject (return `AppError::new(RcD3dInvalidState, ...)`) on `None`, before slicing.

## [HIGH] Deferred-context `update_subresource` skips size validation → OOB slice panic at execution

- File: src/d3d11.rs:3267
- Description: The deferred-context `update_subresource` records `bytes` with no length check (unlike the immediate path which calls `validate_resource_write`, src/d3d11.rs:1631-1632). `validate_command_resources` (src/d3d11.rs:3411) only checks resource *existence*, never size. At execution, `record_sequence_to_command_list` does `record.bytes[..bytes.len()].copy_from_slice(bytes)` (src/d3d11.rs:2106); if the recorded payload is larger than the resource (e.g. `update_subresource(buf_64_bytes, &vec![0; 1_000_000])`), this is an unchecked index/slice → panic during `execute_deferred_command_lists`. Reachable from untrusted input.
- Fix suggestion: in `validate_command_resources` (or at record time), check `bytes.len() <= device.resource(resource)?.bytes.len()` and return the `RcD3dInvalidState` error.

## [HIGH] ClearRenderTargetView CPU-side fill panics when resource byte length is not a multiple of 4

- File: src/d3d11.rs:2148
- Description: `for chunk in resource.bytes.chunks_mut(4) { chunk.copy_from_slice(color); }` — `copy_from_slice` panics if the trailing chunk is shorter than 4 bytes. `create_view` places no dimension/format restriction, so an RTV can be created on a `create_buffer` with arbitrary `byte_width` (e.g. 6 bytes); `om_set_render_targets` + `clear_render_target_view` on it then panics at submit time. All texture creators produce multiples of 4, but buffers do not. Panic reachable from untrusted input.
- Fix suggestion: fill via `chunk[..chunk.len().min(4)].copy_from_slice(&color[..chunk.len().min(4)])` or guard `bytes.len() % 4 != 0` and reject/zero-fill the tail.

## [HIGH] `merge_deferred_command_lists` merges lists containing clears, violating the stated pass-boundary invariant

- File: src/d3d11.rs:1914
- Description: The merge only compares `last.bindings == list.bindings` (src/d3d11.rs:1922) and concatenates commands — it does not inspect command kinds. `submit_sequences_with_signatures` documents (src/d3d11.rs:2252-2258) that clears must remain separate passes ("four deferred lists each clearing the same RTV to a different colour must remain four separate passes"), yet `execute_deferred_command_lists` (src/d3d11.rs:1891) funnels the *merged* lists through this path. Two deferred lists with identical bindings that each clear the same RTV to a different color collapse into one pass with two `ClearRtv` commands; on the Metal side only the first clear per attachment applies, so the second list's clear is silently lost → wrong pixels. Definite wrong behavior that contradicts the code's own comment.
- Fix suggestion: in the merge loop, only merge when `last.commands.iter().chain(list.commands.iter()).all(|c| matches!(c, Draw | DrawIndexed))` (or skip merging when either list contains `ClearRenderTargetView`/`ClearDepthStencilView`/`ResolveSubresource`/`CopyResource`).

## [MEDIUM] `alloc_texture` / `present` compute pixel counts in u32 — overflow for large sizes

- File: src/d3d11.rs:3625
- Description: `let pixel_count = (mip_w * mip_h * 4) as usize;` is entirely u32 arithmetic. For a texture ≥ 32768×32768 (2^30 × 4 = 2^32) it wraps to 0 in release (allocating an empty level that later code may index) and panics in debug. Same pattern at src/d3d11.rs:3651: `vec![0u8; (w * h * 4) as usize]` in `Direct3D9Shim::present`. Sizes are game-controlled. Edge-case bug.
- Fix suggestion: cast to `u64`/`usize` before multiplying (`mip_w as usize * mip_h as usize * 4`), and validate against a sane cap.

## [MEDIUM] DepthStencil default stencil func = LESS (2), D3D11 spec default is ALWAYS (8)

- File: src/d3d11.rs:693
- Description: `front_stencil_func: 2` (and `back_stencil_func: 2`, src/d3d11.rs:697) — the code's own comment admits uncertainty ("actually ALWAYS? spec says always for default"). `D3D11_DEPTH_STENCIL_DESC` defaults are `DepthFunc = D3D11_COMPARISON_LESS (2)`, `StencilFunc = D3D11_COMPARISON_ALWAYS (8)`. Any caller that serializes a default state and relies on spec defaults gets wrong stencil behavior whenever stencil is later enabled.
- Fix suggestion: set both stencil funcs to 8 (`D3D11_COMPARISON_ALWAYS`).

## [MEDIUM] Device creation rejects any request that does not contain Level10_1

- File: src/d3d11.rs:3869
- Description: `requested.iter().copied().find(|level| *level == FeatureLevel::Level10_1).ok_or_else(...)` — a game requesting only `[Level11_0]` (common) fails with `RcD3dFeatureUnsupported` even though the backend can claim mesh/tessellation support (`caps.hull_shader = mesh_shaders`). D3D11 semantics are first-supported-in-request-order, not "must contain 10_1". Definite wrong behavior for 11_0-only requests.
- Fix suggestion: iterate the requested list in order and return the first level the backend can satisfy (e.g. `Level11_0` when `caps.mesh_shaders`, else `Level10_1`).

## [MEDIUM] Predication, counters and class linkage are no-op stubs — conditional rendering executes skipped draws

- File: src/d3d11.rs:2900
- Description: `set_predication` records nothing ("Predication is recorded but not yet evaluated... All draws proceed unconditionally"); `create_counter`/`create_predicate`/`create_class_linkage` (src/d3d11.rs:2804-2837) store state that is never consumed; `generate_mips` (2871), `draw_auto` (2876, always draws 0 vertices), `copy_structure_count` (2886) are no-ops. Games using `SetPredication` will render geometry that D3D11 would skip → definite wrong output; counters never return values. Unfinished logic with behavioral impact.
- Fix suggestion: track the active predicate on the device/context; in `record_sequence_to_command_list`, skip `Draw`/`DrawIndexed` (or record the predication into the plan) when a predicate is bound and false; implement `copy_structure_count` via the recorded counter value.

## [MEDIUM] No destruction/release path for any object — all maps grow unboundedly

- File: src/d3d11.rs:1018
- Description: `D3d11Device` (`resources`, `views`, `blend_states`, `rasterizer_states`, `depth_stencil_states`, `sampler_states`, `input_layouts`, `shaders`, `predicates`, `counters`, `class_linkage`) and `Direct3D9Shim` (`vertex_buffers`, `index_buffers`, `textures`, `devices`, src/d3d11.rs:990-993) only ever insert — there is no `release_*`/destroy API anywhere in this file. Games that allocate per-frame resources (the norm) leak CPU-side `bytes` copies and GPU resources indefinitely → unbounded memory growth, eventual OOM.
- Fix suggestion: add device-level `destroy_resource`/`destroy_view`/`destroy_state`/`release_shader` (removing from maps and calling the backend's resource destruction) and `Direct3D9Shim` buffer/texture release, with ID-reuse-safe allocation (see also len-based IDs at src/d3d11.rs:3585, 3600, 3620, which collide once removal exists).

## [MEDIUM] CS SRV and UAV bindings alias the same storage slot

- File: src/d3d11.rs:1602
- Description: `cs_set_unordered_access_views` stores UAVs in `shader_resources[Cs]` (src/d3d11.rs:2846-2852, also 2863-2868), and `cs_get_unordered_access_views` reads the same slot as `cs_get_shader_resources`. A game binding both CS SRVs and UAVs (normal D3D11 usage) silently loses one set — the later bind overwrites the earlier. Wrong behavior for CS workloads.
- Fix suggestion: add a dedicated `unordered_access_views: BTreeMap<ShaderStage, Vec<D3d11ViewId>>` to `ContextBindings` and bind both independently in the backend plan.

## [MEDIUM] Swallowed error: backbuffer mirror in `present_swapchain` ignores `overwrite_resource_bytes` failure

- File: src/d3d11.rs:1849
- Description: `let _ = self.backend.overwrite_resource_bytes(backbuffer_id, &pixels);` — if the mirror write fails, the presented frame shows stale/black pixels with no error surface. The code's own comment (src/d3d11.rs:1825-1838) says this sync is the only thing that makes the live window show rendered pixels.
- Fix suggestion: collect the first error and return it from `present_swapchain` (or at minimum log it).

## [LOW] `create_buffer` truncates `byte_width` to u32 for the descriptor width

- File: src/d3d11.rs:1096
- Description: `width: byte_width as u32` — buffers ≥ 4 GiB wrap the recorded width while `byte_width` (usize) stays correct, so the descriptor and allocation disagree. Unusual size, but a silent truncation.
- Fix suggestion: store the width in a `u64` field or clamp, and keep the allocation based on `byte_width` only.

## [LOW] Deferred context silently accepts recording after `finish_command_list`

- File: src/d3d11.rs:3366
- Description: `finish_command_list` sets `finished = true`, and a second finish is rejected (src/d3d11.rs:3370-3375) — but every recording setter (e.g. `draw`, src/d3d11.rs:3327; `update_subresource`, 3267) pushes into the (already taken) recording without checking `finished`. D3D11 raises `D3D11_ERROR_INVALID_CALL` on any method after `FinishCommandList`; here commands are silently dropped into a list that will never be returned.
- Fix suggestion: check `recording.finished` in the lock-wrapping helpers and return `RcD3dInvalidState`.

## [LOW] Coalescing path issues a second `BeginRenderPass` per merged sequence

- File: src/d3d11.rs:2284
- Description: In the coalesce branch, `record_sequence_to_command_list` is called once per sequence, but `pass_opened` is a function-local (src/d3d11.rs:2072), so each sequence re-opens the render pass inside the same backend command list. It currently works only because the gfx plan builder merges consecutive `load`-action passes on mesh-capable GPUs (gfx.rs:2271-2281); any change to that merge (or non-mesh fallback) yields spurious extra passes. Fragile rather than incorrect today.
- Fix suggestion: pass `pass_opened` state across sequences in the coalescing loop (begin the pass once, before the loop, when all sequences need it).

## [LOW] Feature caps claim tessellation on mesh GPUs while the device is always 10_1

- File: src/d3d11.rs:3938
- Description: `caps.hull_shader = backend.capabilities().mesh_shaders` (and `domain_shader`, same) while `feature_level` can only ever be `Level10_1` (see the 10_1-only find at src/d3d11.rs:3869) — 10_1 has no tessellation stages. Games querying `check_feature_support` and enabling HS/DS will hit unsupported behavior.
- Fix suggestion: set hull/domain caps false while `feature_level == Level10_1`, or resolve `Level11_0` when the backend supports it.

## [LOW] D3D9 default viewport (800×600) disagrees with default swapchain (640×480)

- File: src/d3d11.rs:500
- Description: `D3d9StateBlock::new` defaults the viewport to 800×600 (src/d3d11.rs:503-504) while `Direct3D9Shim::create_device` defaults `swapchain_width/height` to 640×480 (src/d3d11.rs:3571-3572). A device used with defaults renders with a viewport larger than the backbuffer.
- Fix suggestion: initialize the state-block viewport from the swapchain dims (or unify the defaults at one place).

## [PERF] Per-present full backbuffer copies and per-submission full-resource hashing

- File: src/d3d11.rs:1846
- Description: (a) `present_swapchain` clones every backbuffer's bytes and pushes them into the backend on every present (src/d3d11.rs:1846-1853) — one extra full-buffer allocation+copy per present per backbuffer; (b) `map` returns a full clone of the resource bytes (src/d3d11.rs:1646) — mapping a large texture per-frame doubles memory traffic; (c) in capture mode, `collect_resource_digests` SHA-256s every resource on every submission (src/d3d11.rs:2352-2363) — O(total bytes) per frame. (a) and (b) hit the normal game path; (c) only capture mode.
- Fix suggestion: for (a) reuse a staging allocation instead of `bytes.clone()` per backbuffer; for (b) document/opt-in to full clones or use a single-copy mapping API; for (c) cache digests keyed by (resource, dirty flag) and only rehash after mutation.

---

## Clippy

Run: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt` (output: `clippy_out.txt`). Warnings/errors referencing `src/d3d11.rs`:

- `error: approximate value of f{32,64}::consts::TAU found` — src/d3d11.rs:3687 (`6.2832` in `render_fixed_function_scene`). `#[deny(clippy::approx_constant)]` — **this error is one of the 19 lib errors breaking the build**. Fix: use `std::f32::consts::TAU`.
- `warning: you should consider adding a Default implementation` — src/d3d11.rs:474 (`new_without_default`, `D3d9StateBlock::new`).
- `warning: this impl can be derived` — src/d3d11.rs:620 (`derivable_impls`, `BlendStateDesc`).
- `warning: usage of a legacy numeric constant` — src/d3d11.rs:728, 729 (`legacy_numeric_constants`, `std::f32::MAX` → `f32::MAX`).
- `warning: this if statement can be collapsed` — src/d3d11.rs:1921 (`collapsible_if` in `merge_deferred_command_lists`).
- `warning: clamp-like pattern without using clamp function` — src/d3d11.rs:3683 (`manual_clamp`, `scene.primitive_count.max(1).min(100)`).
- `warning: this function has too many arguments (9/7)` — src/d3d11.rs:4092 (`too_many_arguments`, `build_submission_signature`).

No other d3d11.rs-specific diagnostics were emitted. The remaining 18 lib errors and 26 lib-test errors are in out-of-scope files (`crash_recovery.rs:536`, `d2d.rs:334`, `real_win32.rs:9474/9708`, `dwrite.rs:1398`, `gdiplus_render.rs:1555`, etc.).

## Build

- `cargo clippy --all-targets --no-deps` **FAILED**: `error: could not compile `casa1` (lib) due to 19 previous errors` and `error: could not compile `casa1` (lib test) due to 27 previous errors; 1415 warnings emitted`.
- Of the 19 lib errors, exactly **one is in the audited file**: the `approx_constant` deny-level error at src/d3d11.rs:3687 (the `6.2832` TAU approximation in `render_fixed_function_scene`). The rest are in other files.
- Because the lib and lib-test targets fail to compile, `cargo test` cannot run; findings relying on runtime behavior were verified by static analysis only.
- No `--all-features` flag was used (per instructions; the missing system ffmpeg feature is environmental).

## Summary

- **CRITICAL:** 0
- **HIGH:** 4 (panic/overflow paths at 2131, 3267/2106, 2148; wrong clear semantics in merged deferred lists at 1914)
- **MEDIUM:** 7
- **LOW:** 5
- **PERF:** 1
- **Total findings:** 17
- **Build-blocking issue in scope:** 1 (clippy error src/d3d11.rs:3687)
