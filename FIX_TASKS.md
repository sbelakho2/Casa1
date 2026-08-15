# Audit Findings

- **Batch:** Casa1 full-codebase audit — media/video decode subsystem
- **Files audited (whole files, every line read):**
  - `src/media.rs` (4293 lines)
  - `src/video_decoder.rs` (3290 lines)
- **Date:** 2026-08-15
- **Method:** Sequential full-file read of both files; `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (whole crate, ~13 min); manual analysis of parser/FFI/concurrency paths.

Severity legend: CRITICAL = crash/UB/security/data corruption; HIGH = definite wrong behavior; MEDIUM = edge-case bug; LOW = quality/dead code; PERF = performance with impact note.

---

## [CRITICAL] DecodedFrame stores CVPixelBufferRef without retain and never releases it (UAF + leak)

- File: `src/media.rs:959-965` (callback push), `915-919` (struct), `1238-1281` (consume), `1293-1299` (flush)
- Description: The VT decompression callback receives a `CVPixelBufferRef` that is only valid for the duration of the callback unless retained (CoreVideo ownership rule). `decompression_output_callback` stores the raw pointer in `DecodedFrame` and `process_output` copies pixels out of it later — but the buffer is never retained on enqueue and never released after copy. VT can free the buffer after the callback returns, so `process_output`'s `CVPixelBufferLockBaseAddress`/`from_raw_parts` operate on a dangling pointer → use-after-free/UB. Conversely, buffers that are never popped (decoder dropped, `flush()`) leak the pixel buffer memory forever. `CVPixelBufferRetain`/`Release` are not even declared in this module's FFI block.
- Fix suggestion: `CVPixelBufferRetain(image_buffer)` before `push_back`; `CVPixelBufferRelease(frame.pixel_buffer)` after copying in `process_output`, in `flush()`, and in a `Drop` impl for `H264DecoderMft`; declare both functions in the `media.rs` extern block.

## [CRITICAL] Pixel row-copy in process_output reads out of bounds and assumes BGRA while session requests no format

- File: `src/media.rs:1255-1273`
- Description: `std::slice::from_raw_parts(base_addr, data_size)` is created from `CVPixelBufferGetDataSize`, then the row loop indexes `src[row_start..row_start + width*4]` up to `row = height-1`, i.e. up to `height*bytes_per_row + width*4` bytes — beyond `data_size` when stride differs from `width*4` or when the buffer is smaller than the loop's assumption → panic (slice index) or OOB read. Additionally the copy assumes 4 bytes/pixel (BGRA), but `VTDecompressionSessionCreate` is called with `dest_dict = null` (line 1003), so the output is the decoder-native format (often NV12 `420v`) for typical inputs — the `bytes_per_row == width*4` fast path silently copies wrong data, and the padded path reads `width*4` bytes per row out of an NV12 buffer → wrong frames or UB. The BGRA negotiation code at lines 998-1001 is dead (`_`-prefixed, never passed).
- Fix suggestion: Pass a real `destinationImageBufferAttributes` requesting `kCVPixelFormatType_32BGRA` (or handle NV12 bi-planar planes); validate `data_size >= height * bytes_per_row` and `bytes_per_row >= width*4` before copying; use checked slice ranges.

## [CRITICAL] Wrong FFI signature for `CMVideoFormatDescriptionCreateFromH264ParameterSets` in media.rs

- File: `src/media.rs:1315-1320` (declaration), `1075-1080` (call)
- Description: The real API is `(CFAllocatorRef, size_t parameterSetCount, const size_t *parameterSetSizes, const uint8_t *const *parameterSetPointers, int nalUnitHeaderLength, CMVideoFormatDescriptionRef *out)` — 6 args. The declared extern takes 4 args `(allocator, data, len, out)` and is called with the raw extradata blob and `data.len()`. At runtime the `len` value lands in the `parameterSetCount` register and the blob pointer is interpreted as a `size_t*`/`uint8_t**` array, reading garbage sizes/pointers and a garbage `nalUnitHeaderLength` → crash or corrupt format description. Reached on the primary codec-data path (`MF_MT_MPEG_SEQUENCE_HEADER` / `MF_MT_USER_DATA` present).
- Fix suggestion: Declare the true 6-argument signature, split SPS/PPS out of the avcC blob (or pass Annex B with explicit start-code offsets), and pass `nalUnitHeaderLength = 4` (AVCC) or 1 (Annex B), with `parameterSetCount = 2`.

## [CRITICAL] Wrong FFI signature for `CMVideoFormatDescriptionCreateFromH264ParameterSets` in video_decoder.rs (missing nalUnitHeaderLength, swapped args)

- File: `src/video_decoder.rs:327-334` (declaration), `1012-1019` (call)
- Description: Declared as `(allocator, parameterSetCount, parameterSetPointers, parameterSetSizes, formatDescriptionOut)` — the real API takes `parameterSetSizes` before `parameterSetPointers` and a `nalUnitHeaderLength: i32` before the out param. The call passes SPS/PPS pointers in the sizes slot and sizes in the pointers slot, and `&mut format_desc` lands in the `nalUnitHeaderLength` slot → VT reads garbage sizes/pointers → creates a bogus format description or crashes. This is on the main macOS init path.
- Fix suggestion: Redeclare as `(allocator, count: usize, sizes: *const usize, pointers: *const *const u8, nal_unit_header_length: i32, out)` and call `(null, 2, param_set_sizes.as_ptr(), param_set_pointers.as_ptr(), 4, &mut format_desc)`.

## [CRITICAL] Same C symbol declared twice in one crate with conflicting signatures (clashing extern declarations)

- File: `src/media.rs:1306-1378` vs `src/video_decoder.rs:285-472`
- Description: Both modules declare `CMBlockBufferCreateWithMemoryBlock`, `CMSampleBufferCreate`, `VTDecompressionSessionCreate`, `VTDecompressionSessionDecodeFrame`, `VTDecompressionSessionWaitForAsynchronousFrames`, `CVPixelBuffer*` and a different-arity `CMVideoFormatDescriptionCreateFromH264ParameterSets` in separate `extern "C"` blocks (with differing parameter types, e.g. `usize` vs `i32`, and 4- vs 5-arg variants of the same function). Rust links both to the same C symbol; the compiler may emit/select either signature, and calls made through one block can disagree with the ABI of the other → undefined behavior, silent corruption. `#[allow(clashing_extern_declarations)]` in video_decoder.rs masks the issue instead of fixing it.
- Fix suggestion: Keep exactly one canonical extern block (in `video_decoder::vt_ffi`) with the correct signatures, and have `media.rs`'s `vt_decoder_mft` use it; delete the duplicate `#[link(...)]` extern block.

## [CRITICAL] MP4 stbl parsing indexes `self.file` with untrusted lengths → panic on malformed input

- File: `src/media.rs:2613-2621` (stts), `2625-2633` (stss), `2640-2685` (stsz), `2691-2708` (stco)
- Description: In `read_stbl`, box child scans only guard `self.position + 8 <= file.len()`. When a child's claimed `child_size > 16` but the file ends before `position + 16` (or `position + 12`), the reads `self.file[self.position + 8]`, `[+12]`, `[+16]` panic with index-out-of-bounds. All sizes/counts come from the untrusted container (`child_size`, `sample_count`). `stsz` additionally computes `child_size >= 16 + sample_count * 4` where `sample_count` is untrusted. `read_sample_data` (2740-2754) is properly bounded, so only the table parse panics.
- Fix suggestion: Add a small checked-read helper (e.g. `fn read_u32_at(&self, pos) -> Option<u32>` returning None past EOF) and validate every read and `child_end` against `file.len()`; return `AppResult` errors instead of panicking.

## [CRITICAL] VT output callback dereferences heap context without lifetime protection (use-after-free risk)

- File: `src/video_decoder.rs:1732` (callback), `1047-1102` (Box::into_raw), `1232-1241` (wait error path), `1264-1279` (destroy_session), `1332-1336` (Drop)
- Description: `decompression_output_callback` does `&mut *(outputRefCon as *mut DecoderContext)` with no null check. The `DecoderContext` Box is freed by `destroy_session()` (`self.context.take()` drops the Box). Normally `VTDecompressionSessionWaitForAsynchronousFrames` drains callbacks before returning, but when that call fails (status != 0, line 1233) or when the decoder is dropped/reset while a decode was submitted with `kVTDecodeFrame_EnableAsynchronousDecompression`, the VT internal thread can still invoke the callback after the context is freed → use-after-free (and `frames.lock().unwrap()` panics in a C callback if the mutex is poisoned). `destroy_session` also releases the session immediately after `VTDecompressionSessionInvalidate` without waiting for in-flight callbacks.
- Fix suggestion: Add a reference-counted context (e.g. `Arc<DecoderContext>` stored as the refcon, kept alive by a field in `VideoDecoder`), null-check the refcon, and never free the context until the session is invalidated and all pending callbacks have completed (or use the synchronous flag and always wait, including on error paths).

## [CRITICAL] Division by zero inside the C callback and decode paths when `fps` is fractional < 1.0 → panic in extern "C" (abort/UB)

- File: `src/video_decoder.rs:1775-1781` (callback), `1908-1917` (callback), `966-974` (feed path)
- Description: `1_000_000 / ctx.fps as u64` and `self.frame_number * 1_000_000 / self.config.fps as u64` truncate `fps` to `u64`. For any configured `0.0 < fps < 1.0` (e.g. `MfSourceReader::set_frame_rate(0.5)` or `VideoDecoderConfig { fps: 0.5, .. }`), `fps as u64 == 0` → integer division by zero → panic. In the callback this is a panic inside an `extern "C"` function invoked from a VideoToolbox thread → abort (release) or unwind-across-FFI UB (debug). `fps` is caller-controlled config.
- Fix suggestion: Guard with `fps.max(1.0)` before truncation or compute durations/pts with f64 math: `(1_000_000.0 / fps.max(0.001)) as u64`.

---

## [HIGH] `kCMVideoCodecType_H264` is byte-swapped — wrong FourCC value

- File: `src/media.rs:887`; duplicate: `src/video_decoder.rs:210`
- Description: `const kCMVideoCodecType_H264: u32 = 0x31637661;` — the C multi-char literal `'avc1'` evaluates to `0x61766331` (a=0x61 high byte). `0x31637661` is the byte-swapped value. `CMVideoFormatDescriptionCreate` is called with this wrong codec type in `set_input_type` (line 1083-1090, the "some files work" fallback), so the format description advertises a bogus codec → decode fails or misbehaves. (The `kCVPixelFormatType_32BGRA`/`420v` constants in the same files are correct, confirming the one-off swap.)
- Fix suggestion: Use `0x61766331` in both files.

## [HIGH] AudioToolbox format constants wrong → `AudioConverterNew` always fails; AAC decode never happens

- File: `src/media.rs:1452-1453`, `1617-1621`, `1635-1654`
- Description: `kAudioFormatMPEG4AAC = 0x00001610u32.to_le()` and `kAudioFormatLinearPCM = 0x00000001u32.to_le()` are the Media Foundation `MFAudioFormat_AAC` / WAVE `WAVE_FORMAT_PCM` values, not AudioToolbox FourCCs (`'aac '` = 0x61616320, `'lpcm'` = 0x6C70636D). `AudioConverterNew` therefore fails with an unknown-format error for every input. Even if it succeeded, `process_output` never calls `AudioConverterFillComplexBuffer` (declared with a wrong signature at 1470-1486 and never used): it fabricates 1024 frames of silence per call regardless of input, and `has_output()` returns `true` as soon as a converter exists — so a pull-based pipeline calling `process_output` until `has_output()` is false loops forever emitting silence, and no audio is ever decoded.
- Fix suggestion: Use `'aac '`/`'lpcm'` FourCC constants; implement the actual conversion loop with `AudioConverterFillComplexBuffer` (with the correct FFI types `AudioBufferList*`), or return `MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE` / `Ok(())` without output until real decode is implemented.

## [HIGH] `ensure_decoder_path_trusted` prefix check can be bypassed (sandbox escape)

- File: `src/media.rs:3442-3452`
- Description: `normalized.starts_with(&self.ge_root)` accepts any path whose string begins with the root — e.g. root `/tmp/codecs` also matches `/tmp/codecs_evil/decoder.dylib` and `/tmp/codecs/../lib.dylib` — defeating the decoder-path sandbox. `normalize_path` also lowercases (unexpected on case-sensitive macOS filesystems) and the `builtin://codecs` prefix check has the same prefix-collision weakness.
- Fix suggestion: Compare path components (strip prefix then require the remainder to start with `/` or be empty), and resolve/canonicalize (including `..`) before comparing; use a dedicated enum for `builtin://codecs` rather than a string prefix.

## [HIGH] Unbounded allocation from untrusted container header (OOM DoS)

- File: `src/media.rs:3402-3417` (`decode_golden_clip`), `3492-3502` (`synthesize_audio_samples`)
- Description: `frame_count` and `audio_block_count` are u32 fields parsed from untrusted `container_bytes` with no upper bound. `(0..frame_count).map(...).collect::<Vec<_>>()` allocates `frame_count` SHA-256 strings (up to 4G × ~70 bytes ≈ 300 GB) and `synthesize_audio_samples` builds a `Vec<f32>` of `block_count * 2` elements (up to 34 GB) — OOM abort/DoS from a small crafted input. `parse_container` is also called from `classify_input`/`measure_av_drift_ms` on untrusted bytes.
- Fix suggestion: Validate/saturate counts against a sane cap (e.g. reject frame_count/block_count above 1_000_000) or against the input size, and return `RcMediaInvalid` on violation.

## [HIGH] `stco` maps every sample to the first chunk offset; `stsc`/`stts`/`stss` ignored → wrong sample data for typical MP4s

- File: `src/media.rs:2705-2707`, `2611-2633`
- Description: All samples get `offset = first_chunk_offset`; per-chunk offsets, sample-to-chunk grouping (`stsc`), per-sample durations (`stts`) and sync-sample tables (`stss`) are never applied. `next_sample`/`read_sample_data` then return bytes from the wrong file offsets for every sample not in the first chunk, and PTS/duration are synthesized as the sample index (`pts: i as u64`, `duration: 0`, `is_sync: true`). `SourceReader::read_sample`/`seek` therefore produce wrong frames and broken seeking for real multi-chunk files.
- Fix suggestion: Implement the standard stco/stsc/stts/stss walk (chunk offsets → per-chunk sample counts → per-sample sizes/durations/offsets) or document the demuxer as sample-table-unaware and reject files where `stsc`/`stco` indicate >1 chunk.

## [HIGH] `yuv420p_to_rgba` slices input without length validation → panic on short buffers

- File: `src/video_decoder.rs:2278-2308`
- Description: `u_plane = &yuv[total_pixels..total_pixels + total_pixels/4]` and `v_plane` are direct slices with no length check; a caller passing a buffer shorter than `width*height*5/4` (public function, used on decoded media data) panics with index-out-of-bounds. Also `width*height` in u32 can overflow before the `as usize`.
- Fix suggestion: Validate `yuv.len() >= total_pixels + total_pixels/2` (or use `.get()`/`get_unchecked` with a checked base) and compute `total_pixels` with `u64`/`checked_mul`.

## [HIGH] `prepare_metal_texture_upload` indexes `frame.data` unchecked and overflows u32 dimensions

- File: `src/video_decoder.rs:1362-1369` (BGRA), `1395-1429` (NV12)
- Description: `pixel_count = (width * height) as usize` (u32 multiply, overflows for dimensions ≥ 65536) and `frame.data[si..]` is indexed without verifying `frame.data.len() >= width*height*4` — a caller-supplied short `VideoFrame` panics; a crafted huge `width/height` wraps the allocation size and then indexes out of bounds (panic or wrong memory). The NV12 path also floors odd dimensions (`width/2 * height/2`) producing a UV plane inconsistent with the Y plane for odd sizes.
- Fix suggestion: Use `checked_mul` on u64, reject dimensions where `width % 2 || height % 2` for NV12, and verify `frame.data.len() == width*height*4` before indexing (return `AppResult` error otherwise).

## [HIGH] `MfSourceReader::feed_data` re-feeds the entire buffered stream on every call → duplicated decode

- File: `src/video_decoder.rs:2529-2545`
- Description: After feeding the caller's `data`, the method `mem::take`s `stream_buffer` (the whole file/response loaded in `initialize`, lines 2431/2462) and feeds it too. Since `initialize` preloaded the entire source into `stream_buffer`, the first `feed_data` decodes the caller's chunk and then the *whole file again* — every NAL is decoded twice, PTS/`frame_number` accounting doubles, and frames are duplicated. `seek` (2551-2572) has the same re-feed, and after a seek the buffer is gone so subsequent `feed_data` calls see an empty buffer and silently stop re-feeding (inconsistent behavior).
- Fix suggestion: Feed the preloaded buffer once (e.g. in `initialize` after creating the decoder), or track a consumed offset; don't feed both the argument and the buffer.

## [HIGH] `VideoFrame.metal_texture` raw pointer has no ownership enforcement — leak or double-free

- File: `src/video_decoder.rs:92-113` (struct), `596-606` (retain), `1783-1792` (creation)
- Description: The zero-copy path hands out a +1 retained `id<MTLTexture>` raw pointer documented as "released on drop" — but `VideoFrame` has no `Drop` impl and derives `Clone`, which bit-copies the pointer. If the consumer wraps it in `metal::Texture::from_ptr()` (which takes ownership) the two clones would double-release; if the frame is dropped without wrapping, the texture leaks. Nothing enforces the contract.
- Fix suggestion: Remove `Clone` from `VideoFrame` (or hold the texture as an owned `Option<metal::Texture>` gated on the `metal` feature), and implement `Drop` that releases `metal_texture` when present; document single-ownership.

---

## [MEDIUM] Global `DECODED_FRAMES` queue shared across all decoder instances

- File: `src/media.rs:944-945` (static), `959-965` (push), `1036-1042` (drain), `1293-1299` (flush)
- Description: A single process-wide `LazyLock<Mutex<VecDeque<DecodedFrame>>>` is shared by every `H264DecoderMft` (the `decompressionOutputRefCon` is null and unused). Frames produced by decoder A can be drained by decoder B (`process_output` pops from the same global queue), `flush()` on one decoder discards the other decoders' pending frames, and if a decoder is dropped without `flush`, its retained pixel buffers accumulate in the global queue forever (unbounded growth). `has_output()` also ignores frames still in the global queue.
- Fix suggestion: Move the queue into a per-instance `Arc<Mutex<VecDeque<...>>>` created in `new()` and passed as `decompressionOutputRefCon` (the pattern used in `video_decoder.rs`); clear only that instance's queue in `flush`/`Drop`.

## [MEDIUM] `VTDecompressionSessionWaitForAsynchronousFrames` blocking per frame; status ignored; deadlock risk

- File: `src/media.rs:1221-1223`, `src/video_decoder.rs:1232-1241`
- Description: Each `process_input`/`decode_frame_vt` submits with `kVTDecodeFrame_EnableAsynchronousDecompression` then immediately blocks on `VTDecompressionSessionWaitForAsynchronousFrames`, serializing the pipeline to synchronous speed and ignoring the returned status (`let _wait_status` in media.rs; error path in video_decoder.rs leaves frames pending and then destroys the session). If the hardware decoder stalls, the wait can block indefinitely.
- Fix suggestion: Either use the synchronous decode flag and drop the wait, or wait once per batch/seek; always check the wait status and drain the queue before teardown.

## [MEDIUM] VT session torn down and re-created for every SPS/PPS pair (per-frame re-init for streams with in-band SPS)

- File: `src/video_decoder.rs:944-963`, `media.rs:948-981` (analogous re-init)
- Description: `feed_data_internal` calls `init_session()` whenever both SPS and PPS are non-empty — many real streams repeat SPS/PPS in every access unit (or after each IDR), causing `destroy_session` + `VTDecompressionSessionCreate` per frame: heavy teardown/create churn, dropped output frames, and (in video_decoder.rs) a fresh `MetalVideoTextureCache` per re-init.
- Fix suggestion: Track the SPS/PPS hash; only re-init when the parameter sets actually changed (or on first frame).

## [MEDIUM] `MftTransform::process_message(Drain)` discards all flushed frames

- File: `src/video_decoder.rs:1631-1637`
- Description: `Drain` calls `self.decoder.flush()` which drains `frame_queue` into `remaining`, then `let _remaining = remaining;` drops them — the comment claims "Frames remain in the decoder's queue for ProcessOutput" but the queue is empty afterwards, so `process_output` returns `None` after a drain. Definite wrong behavior for the Drain contract.
- Fix suggestion: Re-append `remaining` to the decoder queue (or return the frames from the message handler).

## [MEDIUM] NV12→RGB uses hardcoded BT.601 matrix while frames are labeled Rec.709; `ColorSpace` unused in decode path

- File: `src/video_decoder.rs:1863-1865`, `1927` (label), `1791`
- Description: The software path converts `420v` with fixed coefficients (1.402/0.344/0.714/1.772 — BT.601 limited-range) but stamps every frame `ColorSpace::Rec709`, and the zero-copy path also labels Rec709 regardless of the source. `prepare_metal_texture_upload`'s NV12 path uses the passed `ColorSpace` — inconsistent: decoded frames converted with 601 coefficients are later labeled 709. Wrong colors for 709/2020 sources.
- Fix suggestion: Carry the SPS-derived color matrix (VUI) into the frame and use it in the conversion; or at least use full-range 709 coefficients consistently with the label.

## [MEDIUM] `from_raw_parts` slices sized `bytes_per_row * height` without verifying the actual allocation

- File: `src/video_decoder.rs:1818`, `1847-1851`
- Description: `std::slice::from_raw_parts(base, bpr * height)` (and `uv_bpr * (height/2)` for the UV plane) create slices of a length that is assumed, not verified — if the pixel buffer allocation is smaller (odd dimensions, padding quirks, planar layouts where plane 1 is smaller than the formula), this is an invalid-slice UB immediately, before the (safe) per-pixel `.get()` guards.
- Fix suggestion: Bound the slice length by `min(bpr*height, CVPixelBufferGetDataSize(...))`/per-plane `GetBytesPerRowOfPlane`-consistent sizes, and use checked arithmetic (`bpr.checked_mul(height)`).

## [MEDIUM] Zero-copy path requests BGRA texture from NV12 (420v) buffers with planeIndex 0

- File: `src/video_decoder.rs:1749-1767`
- Description: For `420v` pixel buffers the callback calls `CVMetalTextureCacheCreateTextureFromImage` with `MTLPixelFormatBGRA8Unorm` and `planeIndex 0` on a bi-planar buffer. CoreVideo only supports conversion for a limited set of pairs; when it "succeeds", the texture contents are undefined/garbage rather than the intended image; otherwise it silently falls back to software. Either way the advertised NV12 zero-copy path never delivers NV12 textures.
- Fix suggestion: Use `MTLPixelFormatNV12` (150) with plane indices 0/1 for 420v buffers, and BGRA only for 32BGRA; verify the returned pixel format before use.

## [MEDIUM] PTS is synthesized from a frame counter instead of using the VT `presentationTimeStamp`

- File: `src/video_decoder.rs:1771-1776`, `1907-1912`, `1201-1204`
- Description: The callback ignores `_presentationTimeStamp`/`_presentationDuration` and computes `pts = frame_num * 1_000_000 / fps`. With frame dropping, reordering (B-frames), or `kVTDecodeInfo_FrameDropped` (also ignored, line 1719), the counter diverges from real PTS → A/V sync drift and duplicated PTS for multiple outputs of one input.
- Fix suggestion: Use `_presentationTimeStamp.value` with the sample timescale (convert to µs), and propagate `kVTDecodeInfo_FrameDropped` to callers.

## [MEDIUM] `parse_h264_sps` u32 overflow and crop underflow on untrusted SPS

- File: `src/video_decoder.rs:2171-2172`, `2189-2190`
- Description: `(pic_width_in_mbs_minus1 + 1) * 16` and `height_in_mbs * 16` overflow u32 for large Exp-Golomb values from a crafted SPS (debug: panic; release: wrapped tiny dims). The crop path computes `width - (crop_left + crop_right) * crop_unit_x` where crop values are untrusted u32 — underflow wraps to huge values, and `width_cropped > 0` accepts the garbage, propagating absurd dimensions into `config.width/height` (later multiplied for allocations).
- Fix suggestion: Use checked/saturating u64 arithmetic and clamp dimensions to a sane range (e.g. 1..=16384); reject SPS where cropping exceeds frame size.

## [MEDIUM] PTS conversion in `SourceReader::read_sample` casts u64 PTS to i64; sample flags misuse

- File: `src/media.rs:2875-2878`
- Description: `sample_info.pts as i64 * 10_000_000` — a crafted MP4 with `pts >= 2^63` produces negative `sample_time`, and `sample_info.duration`/`pts` are currently the sample *index* (see stts finding), not scaled timestamps, so `read_sample` timestamps are wrong. Also `flags |= 1` labels every sync sample as "NEW_STREAM".
- Fix suggestion: Recompute PTS from the stts table (or leave 0 when unknown); use saturating i64 conversion; only set the flag on stream start.

## [MEDIUM] Child-box parsers walk past their parent box boundary

- File: `src/media.rs:2350-2383` (read_moov), `2439-2477` (read_trak), `2484-2554` (read_mdia), `2559-2584` (read_minf)
- Description: All nested readers loop `while self.position < self.file.len()` and only stop on `child_size < 8` or EOF — they never stop at the parent's `child_end`. `child_end = position + child_size` is not validated against `file.len()`, and after a child returns, the parent's `position` may already be past the box; a subsequent sibling (or the next track's `minf`/`stbl`) can be parsed as part of the current box, and overruns beyond `trak` boundaries misattribute boxes to the wrong track. `read_moof` also uses `position + 8 < len` (off-by-one, skips a final 8-byte box).
- Fix suggestion: Pass the parent's end offset into each reader and stop the loop at that bound; validate `child_end <= parent_end` (and `<= file.len()`), erroring out otherwise.

## [MEDIUM] HTTP sources download the entire response into memory with no limit

- File: `src/media.rs:3177-3195`, `src/video_decoder.rs:2455-2488`
- Description: `reqwest::blocking::get(url)` + `response.bytes()` buffer the whole stream (the media.rs comment claims "first few KB" but no truncation happens). A large remote file (or a malicious server) causes unbounded memory growth; also blocks the calling thread.
- Fix suggestion: Read a bounded prefix (e.g. first 1 MiB) for probing and stream the rest, or cap total size with an explicit limit/error.

## [MEDIUM] `set_topology` stores the topology and sets `has_topology` even when resolution fails

- File: `src/media.rs:2106-2116`
- Description: `self.topology = Some(topology)` and `has_topology = true` are set before `topology_loader.load(topology)?`; on failure the error propagates but the session is left with a topology and `TopologyLoaded` is never queued, leaving the event queue inconsistent (setter + loader errors on the same call).
- Fix suggestion: Validate/resolve first, then commit `topology`/`has_topology` and queue `TopologyLoaded` only on success.

## [MEDIUM] `H264DecoderMft`/`AacDecoderMft` have no `Drop`: VT session, format description and converter leak

- File: `src/media.rs:926-1042`, `1504-1527`
- Description: Neither MFT releases its `VTDecompressionSessionRef` (no `VTDecompressionSessionInvalidate`/`CFRelease`), `CMVideoFormatDescriptionRef` (no `CFRelease`), or `AudioConverterRef` (no `AudioConverterDispose`) when dropped, and `set_input_type` re-creation overwrites the old format description without releasing it. Repeated decoder churn (e.g. `MfSourceReader::set_current_media_type` recreating `VideoDecoder`/session) leaks framework objects.
- Fix suggestion: Implement `Drop` for both MFTs calling `VTDecompressionSessionInvalidate`+`CFRelease`, `CFRelease` for format desc, `AudioConverterDispose`, and release the pixel buffers in the queue.

## [MEDIUM] `CFNumberCreate` with `kCFNumberSInt32Type` reads 4 bytes from a 1-byte `u8`

- File: `src/video_decoder.rs:2017-2021`
- Description: `let val: u8 = 1; CFNumberCreate(..., kCFNumberSInt32Type, &val as *const u8 ...)` — CFNumberCreate reads a 32-bit value from the pointer, reading 3 bytes past the 1-byte variable on the stack (out-of-bounds read, indeterminate value). The value should be a `u32`/`i32` (or use `kCFNumberSInt8Type`).
- Fix suggestion: Use `let val: i32 = 1;` (and pass `&val as *const i32`) or `kCFNumberSInt8Type` with a `u8`.

## [MEDIUM] FFmpeg-feature test code does not compile (`decoder`, `pts`, `frames` unresolved)

- File: `src/video_decoder.rs:2780-2794`, `2989-2993`, `3094-3097`
- Description: Under `--features ffmpeg`: `test_decode_packet` binds `let _decoder` then uses `decoder` (2786); `test_frame_pts_ordering` uses `pts` which is never bound (`let _pts` at 2989). Under `cfg(not(any(target_os = "macos", feature = "ffmpeg")))`: `test_video_decoder_flush` binds `let _frames` then asserts on `frames` (3097). These are compile errors for the affected feature/platform targets (not exercised by this run — ffmpeg is environmental).
- Fix suggestion: Rename bindings to the used identifiers and define `pts` in the loop body.

---

## [LOW] Dead code / unfinished markers

- File: `src/media.rs:998-1001` — `_pixel_format_keys`, `_bg_value`, `_bg_values` (intended BGRA negotiation, never used); `2319` — `_header_size`; `934` — `last_pts` written never read; `1508-1511`/`929-930` — `input_type_set`/`output_type_set` written never read (both MFTs); `2908` — `SinkWriter.encoder` never used; `2793` — `SourceReader.position` written never read; `1179` — `_duration_time`; `3085-3095` — `mf_startup`/`mf_shutdown` no-ops (stub).
- File: `src/video_decoder.rs:218-219, 253-254, 259-261` — `kCMBlockBuffer_AssureMemoryNowFlag = 0`, `kVTDecodeInfo_*`, `kVTDecodeFrame_*` constants unused; `395-397` — `CVPixelBufferRetain`/`Release` declared but never called; `1719` — `_infoFlags` (frame-dropped info dropped); `3046-3047` — `set_rate` on `PresentationClock` never affects `get_time` (`rate` field unused).
- Fix suggestion: Delete dead items or wire them up; add `#[allow(dead_code)]` scope to intentional stubs; use the info flags to signal dropped frames.

## [LOW] `ImfMediaBuffer::new` allocates `capacity as usize` bytes (up to 4 GiB) from a caller-controlled u32

- File: `src/media.rs:610-616`
- Description: `vec![0u8; capacity as usize]` with an untrusted `capacity` can attempt a multi-GiB allocation → OOM abort. Callers (`mf_create_memory_buffer`) pass sizes through without validation.
- Fix suggestion: Clamp/validate capacity (e.g. reject > 512 MiB) and return a fallible API.

## [LOW] `detect_container_from_bytes` misclassifies truncated input as Ogg

- File: `src/media.rs:3112-3122`
- Description: `data.len() < 4` returns `ContainerKind::Ogg` (fallback), which routes unknown/truncated data to `ResolvedSource::Unknown` rather than an explicit error; unknown magic also defaults to Ogg. Misleading diagnostics and incorrect routing for genuinely unknown formats.
- Fix suggestion: Return `Option<ContainerKind>`/error for <4 bytes and unknown magic; keep Ogg only for `Ogg ` magic.

## [LOW] `MediaShim::parse_container` uses `expect` on `try_into` (safe only by the length guard)

- File: `src/media.rs:3349-3352`
- Description: `try_into().expect(...)` panics if the guard `bytes.len() < 18` is ever changed/missed. Not currently reachable, but fragile.
- Fix suggestion: Use `?` with a `RcMediaInvalid` error instead of `expect`.

## [LOW] `MfMediaSession::start` from `Playing` re-queues `SessionStarted`; `start` allowed from `Idle` without a topology

- File: `src/media.rs:2006-2018`
- Description: Calling `start()` while already `Playing` returns `Ok` and queues a duplicate `SessionStarted` event; `can_start` also permits `Idle` with no topology set, which real MF would reject. Consumers may see spurious/duplicate events.
- Fix suggestion: No-op without an event when already playing; require `has_topology` for `Idle -> Playing`.

## [LOW] `SinkWriter` accumulates all output in memory until `end_writing`

- File: `src/media.rs:2953-2970`
- Description: `output_data` grows unboundedly with every `write_sample`; a long encode holds the full file in RAM and writes it in one `std::fs::write`. Memory DoS for large streams.
- Fix suggestion: Stream to the file incrementally (or bound the buffer and flush periodically).

## [LOW] `MediaEvent::with_error` hardcodes status -1; `MfEventQueue::with_max(0)` still allows one event

- File: `src/media.rs:580-587`, `764-777`
- Description: Status should map to a real HRESULT; `with_max(0)` pops the front of an empty queue (no-op) then pushes, so a zero-max queue holds 1 event. Trivial edge cases.
- Fix suggestion: Let callers pass the status; make `queue_event` return early when `max_events == 0`.

## [PERF] Per-frame allocations and copies in hot decode paths

- File: `src/media.rs:1263-1273` — full-frame `Vec::with_capacity` + per-frame copy (plus the redundant copy through the global queue); `src/video_decoder.rs:1819-1833` — full RGBA buffer allocated and filled pixel-by-pixel per frame in the callback; `1854-1872` — same for NV12; `1554` — `get_latest_software_frame` clones the entire frame buffer on every call.
- Description: Every decoded frame does a full-resolution allocation + row copy on the VT callback thread (or decoder thread), plus an extra copy in `media.rs` through the global queue. For 1080p60 this is ~8 MB × several copies per frame; the pixel-by-pixel loops also defeat vectorization.
- Fix suggestion: Reuse a preallocated output buffer sized to `bytes_per_row*height` (matching stride), convert with SIMD-friendly row processing, and return a borrow/snapshot instead of cloning the software frame.

## [PERF] `Topology::connect`/`get_node` are O(n) per lookup; demuxer reparses per `read_box` loop

- File: `src/media.rs:1841-1866`, `1869-1871`
- Description: `connect()` scans `self.nodes` twice per call and `find` per node — fine for the current 3-node topologies, but `get_node` is called in validation loops; acceptable now, noted for scale.
- Fix suggestion: Index nodes by id in a `HashMap<u64, usize>` if topologies grow.

---

## Clippy

Command: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (whole crate; lib test target fails to compile — see Build).

Warnings/errors referencing `src/media.rs`:
- `clippy::duplicated_attributes` — media.rs:1303-1305 (`#[link]` duplicated; same crate declares these symbols again in video_decoder.rs:285-287)
- `clippy::new_without_default` — media.rs:756 (`MfEventQueue`), 970 (`H264DecoderMft`), 1516 (`AacDecoderMft`), 1789 (`Topology`), 1911 (`TopologyLoader`), 1985 (`MfMediaSession`)
- `clippy::manual_c_str_literals` — media.rs:999
- `clippy::unnecessary_cast` — media.rs:1078, 1193, 1269, 1270, 1271, 2316, 2339
- `clippy::match_like_matches_macro`-adjacent "match for an equality check" — media.rs:2575
- `clippy::collapsible_if` — media.rs:2690

Warnings/errors referencing `src/video_decoder.rs`:
- `clippy::should_implement_trait` — video_decoder.rs:43 (`ColorSpace::default()` — implement `Default` instead)
- **error: `clippy::not_unsafe_ptr_arg_deref` — video_decoder.rs:573** (`create_texture_from_pixel_buffer` passes a raw pointer into FFI without being `unsafe fn`) — the only error in the audited files
- `clippy::duplicated_attributes` — video_decoder.rs:285-287
- `clippy::needless_return` — video_decoder.rs:891, 919
- `clippy::collapsible_if` — video_decoder.rs:949, 958, 966
- `clippy::unnecessary_cast` — video_decoder.rs:1973, 1974, 2028, 2029
- `clippy::manual_is_multiple_of` — video_decoder.rs:2241
- `clippy::manual_div_ceil` — video_decoder.rs:2244
- `clippy::if_same_then_else` — video_decoder.rs:2345 (`.wmv` branch identical to default), 2595 (`select_stream` identical branches)
- `clippy::manual_repeat_n` — video_decoder.rs:2892 (test)
- `clippy::single_match` — video_decoder.rs:3130 (test)
- `clippy::bool_assert_comparison`-adjacent "binary expression can be simplified" — video_decoder.rs:3243 (test)

Note: most of the 1415 crate-wide warnings are duplicates of the same lints across the codebase (1262 duplicates).

## Build

- `cargo clippy --all-targets --no-deps` completed (~13 min). Result: `error: could not compile casa1 (lib test) due to 27 previous errors; 1415 warnings emitted`.
- 26 of the 27 errors are in other files (metal_backend.rs, jit.rs, crash_recovery.rs, d2d.rs, d3d11.rs, etc.).
- 1 error is in the audited scope: `clippy::not_unsafe_ptr_arg_deref` at `src/video_decoder.rs:573` (see CRITICAL-adjacent finding above; fix: make `create_texture_from_pixel_buffer` an `unsafe fn` or document/validate the pointer).
- Additionally, by inspection, `--features ffmpeg` builds fail on test code in `src/video_decoder.rs` (unresolved `decoder`/`pts` — see MEDIUM finding); not exercised here because system ffmpeg is unavailable (environmental, per instructions).
