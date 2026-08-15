# AUDIT_FINDINGS — src/real_audio.rs

- **Batch**: audit-real-audio (worktree `/Users/sabelakhoua/IdeaProjects/Casa1/.kilo/worktrees/audit-real-audio`)
- **Files**: `src/real_audio.rs` (5002 lines, read in full: 1–2000, 1401–2749, 2750–4049, 4050–5002)
- **Date**: 2026-08-15
- **Scope**: Logic/panic/unsafe/resource/concurrency/FFI/performance audit + whole-crate clippy run (`CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps`, output in `clippy_out.txt`)

---

## [CRITICAL] convert_and_resample panics on untrusted sample buffers (public API crash)

- File: src/real_audio.rs:2243
- Description: In the same-rate branch, `resampled.copy_from_slice(samples)` panics with a length mismatch whenever `samples.len()` is not an exact multiple of `source_channels`. `source_frames = samples.len() / source_channels` floors, so `resampled` (sized `source_frames * source_channels`) is smaller than `samples` when the tail is a partial frame. This is reachable from untrusted game data through the public `push_xaudio2_samples` (195), `push_wasapi_frames` (281), and `push_direct_sound_samples` (438) — any caller submitting an odd/partial sample count (e.g. a DirectSound write of an odd number of samples) crashes the process. Additionally, the `else` branch computes `(source_frames as u64 * dest_rate as u64) / source_rate as u64` (line 2237) which panics on integer division by zero if `source_rate == 0` is passed (also public API).
- Fix suggestion: Guard the inputs: `let usable = samples.len() - samples.len() % source_channels;` and pass `&samples[..usable]` to `copy_from_slice` (and index with it in the resample loop); and reject/defend `source_rate == 0` (e.g. `if source_rate == 0 || dest_rate == 0 { return Vec::new(); }`) before computing `dest_frames`.

## [HIGH] MS ADPCM stereo decode produces roughly half the expected samples per channel

- File: src/real_audio.rs:1491
- Description: The nibble loop is `for i in 0..(remaining.min(nibble_count))` where `remaining = samples_per_block - 2` and `nibble_count = (block_size - header) * 2` (total nibbles across all channels). Each iteration decodes exactly one sample for channel `i % num_channels`. For mono this is correct (each channel = the only channel gets `remaining` nibbles). For stereo, each channel receives only `min(remaining, nibble_count)/2` decoded samples while the contract (`samples_per_block` = samples per channel, doc at 1377) requires `samples_per_block` per channel. The interleaved layout provides each channel `nibble_count/2` nibbles, so the loop should run `remaining` iterations **per channel** (i.e. `remaining * num_channels` total). Net effect: stereo MS ADPCM output is short by ~half of the compressed data (e.g. samples_per_block=6 yields 4 samples per channel, not 6), producing truncated audio. The padding logic at 1571 (`decoded_per_ch = remaining.min(nibble_count) + 2`) then computes `pad = 0` for a full block, so it never compensates. Existing stereo test (4256) only checks the first 6 output values and passes despite the short output.
- Fix suggestion: Bound the loop by `(remaining * num_channels).min(nibble_count)` so each channel gets `remaining` nibbles, and fix `decoded_per_ch` to count per-channel decoded samples (`2 + min(remaining, nibble_count / num_channels)`). Add a stereo test asserting `output.len() == num_channels * samples_per_block`.

## [HIGH] XMA decoder emits planar (channel-major) output instead of interleaved, and silent frames break overlap-add state

- File: src/real_audio.rs:1936 (normal path), 1924 (silent path), 1985–2009
- Description: The per-frame loop is `for sf in 0..num_channels.min(num_subframes) { ... for i in 0..half_frame { output.push(...) } }` — sf-major order pushes all of channel 0's half-frame, then all of channel 1's, i.e. planar, while the API doc (1834) promises "Interleaved 16-bit PCM samples". The final flush (2022–2035) is frame-major interleaved, so stereo output mixes both orderings depending on position. Additionally the `quant_scale == 0` silent path (1924) emits a full `XMA_FRAME_SAMPLES` per channel, does **not** update `prev_frame`, and does not perform overlap-add — mixing silent and normal frames creates discontinuity (length per channel differs: 256 vs 128 samples) and loses the overlap state. Overlap-add indexing `prev_idx = i * num_channels + sf` (1987) is consistent only because both stores and loads use the same planar layout; it is interleaved-agnostic and compounds the ordering bug.
- Fix suggestion: Restructure so output is pushed frame-major: for each frame `i in 0..half_frame`, for each channel `sf` (write from the per-subframe overlap buffers), matching the flush loop at 2022; and make the silent path run through the same overlap-add state machine (store second half into `prev_frame`, emit `half_frame` samples, not `XMA_FRAME_SAMPLES`). Add a stereo test asserting `output.chunks(2)` channel alternation.

## [HIGH] Exclusive-mode streams are fed data resampled to the wrong rate/channel count

- File: src/real_audio.rs:418–423, 713–852
- Description: `push_wasapi_frames_exclusive` delegates to `push_wasapi_frames`, which calls `convert_and_resample(samples, fmt.channels, fmt.sample_rate, device.channels, device.sample_rate)`. `device.sample_rate`/`device.channels` come from the device's **default** output config (enumeration, line 103–104), but `ensure_stream_exclusive` builds the stream at exactly `format.sample_rate` and `format.channels` (748, 768). When the client format differs from the device default (e.g. game requests 44.1 kHz on a 48 kHz-default device), the queue is filled with samples resampled to 48 kHz / default channels while the callback drains them at 44.1 kHz / client channels — wrong playback speed and, if channel counts differ, garbled interleaving. The doc comment claims "no resampling occurs" in exclusive mode, which is only true when formats happen to coincide.
- Fix suggestion: For exclusive clients, bypass `convert_and_resample` and push `samples` verbatim into the queue (the stream format already matches the client format); alternatively track the negotiated stream config per device and resample to that exact config instead of `device.sample_rate`/`device.channels`.

## [MEDIUM] Mutex lock inside the real-time output audio callback

- File: src/real_audio.rs:3852–3882
- Description: `fill_output_f32`/`fill_output_i16`/`fill_output_u16` run on the cpal real-time audio thread and call `queue.lock()` (std Mutex) on every callback. The producer side (`push_xaudio2_samples` etc., lines 210–219) holds the same lock while doing a potentially large `q.extend(converted)` plus a trim loop, so the audio thread can block on contention (priority inversion), causing underruns/glitches. This violates the real-time requirement of no locking in callbacks.
- Fix suggestion: Use a lock-free SPSC queue (e.g. `ringbuf`/`rtrb` crate, or a seqlock/`parking_lot` + pre-allocated ring buffer) so the callback never blocks; or, minimally, push under a short critical section by pre-converting into a scratch buffer and swapping.

## [MEDIUM] Capture callback performs locking, allocation, and O(n) drains on the real-time thread

- File: src/real_audio.rs:921–931, 945–961, 976–988
- Description: The input-stream callbacks lock `capture_buffer`, `extend_from_slice` (may reallocate), convert i16/u16 (pushing one element at a time, which can reallocate), and `buf.drain(0..drain_end)` (memmove of up to ~4 s of audio) — all on the real-time audio thread and all potentially contended with `read_capture_data`/`stop_input_stream` on the app thread. Same real-time violation class as the output callback plus allocation.
- Fix suggestion: Use a pre-allocated ring buffer (lock-free or with a non-blocking try_lock) for capture; move conversion/trimming out of the callback, or at minimum `try_lock()` and pre-reserve capacity so no allocation occurs in the callback.

## [MEDIUM] Device identity keyed by display name: duplicates, renames, and wrong-device fallback

- File: src/real_audio.rs:498–503 (detect_device_changes), 864–877 (find_cpal_device)
- Description: `detect_device_changes` collapses devices with identical names into a single `current_names` entry and re-matches existing devices by name only; a device rename is treated as remove+add (existing stream torn down and a new ID assigned). `find_cpal_device` falls back to the **default** device when the named device is not found, silently routing audio for a stale `device_id` to the wrong physical device instead of returning an error.
- Fix suggestion: Match devices by a stable identity (e.g. cpal device ID string or a serial/UID when available, fallback to name+channels+rate tuple); in `find_cpal_device`, return `RcAudioUnsupported` if the named device is absent instead of silently using the default.

## [MEDIUM] latency_log grows without bound

- File: src/real_audio.rs:70, 270–274, 360–364, 694–698
- Description: Every `open_wasapi_client`, `open_wasapi_client_exclusive`, and `ensure_stream` (stream open) appends a `LatencyRecord`; nothing ever trims the `Vec`. On a long-running emulator session with repeated stream opens (common in games), memory grows monotonically.
- Fix suggestion: Cap the log (e.g. keep the last 256 entries, or evict when `len() > N`).

## [MEDIUM] Exclusive-mode stream reuse returns a fabricated buffer size and ignores format

- File: src/real_audio.rs:718–729
- Description: When a stream already exists for the device, `ensure_stream_exclusive` returns hard-coded `256` (or the first client's `buffer_frames`) without checking the format of the new client. A second exclusive client on the same device then gets a `buffer_frames` that does not match the actual stream, so its strict `push_wasapi_frames_exclusive` length validation (396–414) either rejects valid submissions (`RcAudioBufferSizeMismatch`) or the queue timing is wrong.
- Fix suggestion: Track the negotiated buffer size per (device, format) — store the built stream's config alongside the stream and return the real buffer size; or reject opening a second exclusive client with a different format on the same device.

## [MEDIUM] XAPO_BUFFER: unsafe Send/Sync around a raw guest pointer

- File: src/real_audio.rs:2510–2523
- Description: `unsafe impl Send for XAPO_BUFFER` / `unsafe impl Sync` are blanket-justified for a `#[repr(C)]` struct holding `*const f32` into guest (emulated Windows) memory. If the descriptor outlives the guest buffer (freed/unmapped guest memory) or guest writes occur concurrently with host reads (pe_runtime.rs:16858 dereferences these), this is a dangling/aliasing UB risk. `#[derive(Clone)]` also copies the raw pointer shallowly.
- Fix suggestion: Replace the raw pointer with a host-side owned `Vec<f32>`/slice used only for processing, or confine pointer creation to a small unsafe shim at the FFI boundary with an explicit lifetime contract (buffer must remain mapped during `process`); drop the `Sync` impl (nothing here is safe to share) and remove `Clone` if the pointer is not meant to be copied.

## [MEDIUM] XMA silent frames bypass the overlap-add state machine

- File: src/real_audio.rs:1922–1933
- Description: The `quant_scale == 0` branch pushes `XMA_FRAME_SAMPLES * num_channels` zeros directly, emits a different sample count per channel than normal frames (256 vs 128 per subframe), and leaves `prev_frame`/`frame_index` overlap state inconsistent with the normal path. Mixed silent/non-silent streams produce audible discontinuities and mis-timed output lengths. (Related to the planar-order finding; kept separate because it is an independent state bug.)
- Fix suggestion: Route silent frames through the same overlap-add path using a zero-filled `mdct_coeffs`/`time_samples` (emit `half_frame` samples and store the second half into `prev_frame`), or skip the frame entirely without emitting samples so frame accounting stays consistent.

## [LOW] push_* after close_stream silently succeeds and drops audio

- File: src/real_audio.rs:210–219, 296–304, 453–461, 590–596
- Description: If `close_stream` has removed the queue, `push_xaudio2_samples`/`push_wasapi_frames`/`push_direct_sound_samples` return `Ok(())` with the data discarded (the `if let Some(queue)` block is skipped). Callers cannot distinguish "played" from "dropped", and the converted allocation is wasted.
- Fix suggestion: Return an error (e.g. `RcAudioUnsupported`, "stream not open") when `stream_queues.get(&device_id)` is `None`.

## [LOW] render_xaudio2_to_device: both match arms identical + unwrap_or(1)

- File: src/real_audio.rs:234–240
- Description: `match audio_subsystem.voice_started(mastering_voice) { Ok(true) => ..., _ => ... }` evaluates the same expression in both arms, and `self.default_device_id().unwrap_or(1)` assumes device ID 1 exists (if the device list is empty or device 1 was removed, `device_info(1)` fails later with a confusing error). Dead logic / misleading intent.
- Fix suggestion: Collapse the match to a single `self.default_device_id()?` call, letting the error propagate.

## [LOW] Duplicate identical functions float_to_u8 and float_to_u8_pcm

- File: src/real_audio.rs:1069–1074, 1096–1101
- Description: Two `pub` functions with byte-identical bodies (f32 → u8 centered at 128). `float_to_u8` is used only by a test; the duplication risks drift.
- Fix suggestion: Keep one (e.g. `float_to_u8_pcm`) and have the other delegate, or delete the unused one.

## [LOW] XapoReverb delay-length fields are stored but never used

- File: src/real_audio.rs:2572–2573, 2582–2583, 2676, 2691
- Description: `comb_delays`/`allpass_delays` are only read into `let _delay = ...` and otherwise unused — the effective delay comes from the buffer lengths. Misleading dead state (the fields cannot be reconfigured, yet they appear to matter).
- Fix suggestion: Remove the fields and the `let _delay` bindings, or actually use them (e.g. to recompute buffer sizes on `set_*`), since they imply a feature (dynamic delay) that does not exist.

## [LOW] XapoNormalize::sample_rate() hardcodes 48000

- File: src/real_audio.rs:3183–3185
- Description: `XapoNormalize` has no sample rate, so its `XapoEffect::sample_rate()` returns a hard-coded 48000 while every other effect returns its configured rate — inconsistent values for consumers (e.g. chain/mixers querying rates).
- Fix suggestion: Store the constructor's sample rate (add a `sample_rate: u32` parameter or field defaulting to 48000) and return it.

## [LOW] XapoEqualizer::process lacks an output-length guard (silent truncation)

- File: src/real_audio.rs:3396–3398
- Description: All sibling effects return `Ok(())` early when `output.len() < total`, but `XapoEqualizer::process` only writes `if i < output.len()`, leaving the tail of `output` untouched and returning `Ok` — caller cannot detect truncation, and `process_chain` will pass a partially-written buffer downstream.
- Fix suggestion: Add the same `if output.len() < input.len() { return Ok(()); }` guard as the other effects.

## [LOW] XapoEffectChain::process_chain ignores failed effect processing (stale data flows)

- File: src/real_audio.rs:3524–3537
- Description: `manager.process_instance` returns `false` when a handle was destroyed; `process_chain` ignores it and continues, so the previous `temp_buffer`/`intermediate` content flows through as audio.
- Fix suggestion: When `process_instance` returns `false`, zero the affected buffer (or propagate an error) so stale/garbage samples are not emitted.

## [LOW] XMA frame cap `frame_index > 1024` silently truncates long streams

- File: src/real_audio.rs:2015–2017
- Description: After 1024 frames (~2.1 s at 256 samples/frame @ 48 kHz … actually 1024 × 256 ≈ 5.5 s at 48 kHz), decoding stops without error, silently truncating longer audio. No warning is surfaced to the caller.
- Fix suggestion: Return an error or document the limit; better, remove the arbitrary cap now that parsing is bounds-checked (offset advances monotonically and the while loop terminates on data exhaustion).

## [LOW] Latency record uses the guest format rate with the device buffer size

- File: src/real_audio.rs:686–693, 269
- Description: `measure_latency_ms(format.sample_rate, buffer_frames)` mixes the game's sample rate with the device's buffer size (and 1024 for `BufferSize::Default`); when the rates differ the recorded latency is wrong (e.g. 44.1 kHz game on 48 kHz device).
- Fix suggestion: Use `device.sample_rate` (or the built stream config rate) when computing latency for the device.

## [LOW] `let _event_driven = event_driven;` dead parameter binding

- File: src/real_audio.rs:276
- Description: `open_wasapi_client` takes `event_driven: bool` and immediately discards it into an underscore binding. Either implement event-driven behavior or drop the parameter.
- Fix suggestion: Remove the parameter or use it to select buffer-size strategy.

## [PERF] process_chain allocates a fresh Vec per effect per buffer

- File: src/real_audio.rs:3530
- Description: For every intermediate effect, `let mut intermediate = vec![0.0f32; input.len()];` allocates a new buffer on every `process_chain` call, in the per-buffer audio hot path (e.g. voice graph rendering). `temp_buffer` is reused, but the intermediate is not.
- Fix suggestion: Add a second reusable scratch `Vec<f32>` to `XapoEffectChain` (sized once, grown as needed) and alternate between the two, avoiding per-call allocation.

## [PERF] XapoEqualizer::process allocates coefficient Vec every call

- File: src/real_audio.rs:3371–3380
- Description: `let coeffs: Vec<...> = (0..4).map(peaking_coefficients).collect();` allocates on every process call even though parameters rarely change. Four coefficient tuples could be a stack array, or cached and recomputed only in `set_parameters`.
- Fix suggestion: Use `[(f32, f32, f32, f32, f32); 4]` computed inline, or cache `[f32; 20]` updated in `set_parameters`/`new`.

## [PERF] imdct is O(n²) with a cos() per inner iteration and per-subframe allocations

- File: src/real_audio.rs:2059–2094, 1942, 1981
- Description: `imdct` runs 256 outputs × 128 coefficients = 32,768 `cos()` calls per subframe, plus `vec![0.0f32; n]`/`mdct_coeffs`/`time_samples` allocations per subframe. For XMA decode (potentially large game audio) this is a serious bottleneck (documented as "first-pass", but the quadratic inner loop with transcendentals is avoidable).
- Fix suggestion: Precompute the cosine matrix once (or use a fast DCT-IV via an FFT routine), and reuse buffers across subframes (thread-local or decoder-owned scratch).

---

## Clippy

Run: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt` (rustc 1.96.0 toolchain). Warnings referencing `src/real_audio.rs` (27 instances; no clippy errors in this file):

- `collapsible_if` — src/real_audio.rs:210, 296, 453 (nested `if let Some(queue)`/`if let Ok(mut q)`)
- `manual_checked_ops` (manual checked division) — src/real_audio.rs:399, 572, 1698
- `unnecessary_cast` (`i32 -> i32`) — src/real_audio.rs:1115 (×3), 1135 (×3)
- `needless_range_loop` — src/real_audio.rs:1474, 1477, 1716, 1782, 1961, 1985, 2004, 2078, 2080, 2088, 2387, 3387
- `manual_div_ceil` — src/real_audio.rs:1950
- `manual_range_contains` (test) — src/real_audio.rs:4146
- `bool_assert_comparison` (test) — src/real_audio.rs:4999

All are style-level; none indicates a memory-safety issue.

## Build

- `cargo clippy --all-targets` **failed to complete**: `casa1` (lib) aborted with 19 deny-level errors; `casa1` (lib test) with 27 errors. All errors are in other files (`cpu.rs`, `jit.rs`, `d2d.rs`, `d3d11.rs`, `dwrite.rs`, `mac_window.rs`, `metal_backend.rs`, `pe_runtime.rs`, `real_win32.rs`, `security.rs`, `seh.rs`, `video_decoder.rs`, `winhttp.rs`, `crash_recovery.rs`) — **zero errors reference `src/real_audio.rs`**. `--all-features` was not used (per instructions; missing system ffmpeg is environmental). Because the lib target failed, later targets were not compiled; real_audio.rs warnings listed above were fully emitted.
