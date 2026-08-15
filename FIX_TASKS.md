# AUDIT_FINDINGS.md

- Batch: audio/midi subsystem audit
- Files (all fully read, every line, in order):
  - `src/audio.rs` (3398 lines)
  - `src/midi.rs` (1670 lines)
  - `src/audio_format.rs` (943 lines)
  - `src/audio_ring_buffer.rs` (853 lines)
  - `src/winmm.rs` (2514 lines)
- Tooling: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (whole crate; completed; output in `clippy_out.txt`)
- Date: 2026-08-15

Severity counts: **CRITICAL 5 · HIGH 9 · MEDIUM 19 · LOW 6 · PERF 3** — total **42** findings (includes 2 clippy-pinned items folded into Clippy section).

---

## [CRITICAL] Out-of-bounds panic in `consume_source_frames` for empty looping source buffer

- File: `src/audio.rs:2005-2006` (also 1972-1990)
- Description: If a guest submits a `SourceBuffer` with empty sample data and a loop configured (`loop_begin`/`loop_length` set, `loop_count == 0` or remaining), the queued buffer has `frames == 0`. The inner `while` loop in `consume_source_frames` sees `cursor(0) >= frames(0)`, takes the `will_loop` rewind path, and breaks with `cursor` still `>= frames`. Execution then reaches `&buffer.samples[sample_offset..sample_offset + channels]` on a zero-length slice → guaranteed index-out-of-bounds panic (both debug and release). Guest-reachable via `SubmitSourceBuffer` with an empty buffer + loop params; a panic in the audio path crashes the emulator.
- Fix suggestion: After the rewind `break`, re-check `cursor >= frames` (or reject empty buffers in `submit_source_buffer` with `RcAudioUnsupported`). Also guard the slice with `if buffer.cursor >= buffer.frames { continue; }`.

## [CRITICAL] Division by zero in `wave_out_write` on guest-controlled format (`frame_size() == 0`)

- File: `src/winmm.rs:978-979` (validation gap at 848-876; `frame_size` at 326-328)
- Description: `wave_out_open` validates only `w_format_tag`. A guest can open with `n_channels == 0` or `w_bits_per_sample < 8`, making `frame_size() == n_channels * (bits/8) == 0`. `wave_out_write` then evaluates `(data.len() as u64) / device.format.frame_size() as u64` → division-by-zero panic, reachable from guest input.
- Fix suggestion: Validate `n_channels >= 1` and `w_bits_per_sample >= 8` (and % 8 == 0) in `wave_out_open`/`wave_in_open`, or use `frame_size().max(1)` / `checked_div`.

## [CRITICAL] Division by zero in `MidiStreamPlayer::position` for small time divisions

- File: `src/midi.rs:1279`
- Description: `song_ptr = ticks / (self.time_division.max(1) as u32 / 4)`. When `time_division` is set to 1..3 (guest can set via `set_time_division`/`midiStreamProperty(MIDIPROP_TIMEDIV)`, which only clamp to `>= 1`), `time_division / 4 == 0` → division by zero → panic, regardless of build profile.
- Fix suggestion: `ticks / (self.time_division.max(4) as u32 / 4)` or `ticks / ((self.time_division as u32 / 4).max(1))`.

## [CRITICAL] Panic in `read_hold` when available samples < channel count

- File: `src/audio_ring_buffer.rs:296-305` (underflow at 298)
- Description: When `0 < read_count < channels` (partial frame available; e.g. 1 sample in a stereo buffer), `last_frame_start = read_count - channels` underflows `usize`, then `output[last_frame_start + ch]` indexes out of bounds → guaranteed panic. This runs on the audio callback path (realtime thread); producer writes are not frame-aligned, so a 1-sample availability with stereo is easy to hit.
- Fix suggestion: `let last_frame_start = read_count.saturating_sub(channels);` plus bounds check, or treat `read_count < channels` as silence-fill.

## [CRITICAL] `AudioRingBuffer::write` corrupts ring state on overflow (head advances past tail)

- File: `src/audio_ring_buffer.rs:157-183`
- Description: `available` is computed before any head adjustment; on overflow the code stores `min(len, available)` samples and *then* advances `head` by `overflow`. Whenever `samples.len() > available` (e.g. writing 100 samples into an empty 64-capacity buffer, or into a full buffer), `head` is advanced past `tail`, so `tail - head` wraps to a huge fill value. Result: new data double-dropped (only `capacity - samples.len()` kept), `fill_samples()`/`fill_fraction()` return garbage (>1.0), and the consumer then reads stale/repeated data. The doc comment promises "oldest samples are overwritten" — not what happens.
- Fix suggestion: Advance `head` by `overflow` (if the buffer is full, or `samples.len()` exceeds capacity) *before* computing `write_count`, and clamp: `let head = self.head.load(Acquire); let used = tail.wrapping_sub(head); let free = len - used.min(len); let write_count = samples.len().min(free); ... if write_count + used > len { advance head by (write_count + used - len) }`.

---

## [HIGH] `exit_loop` never exits an infinite loop

- File: `src/audio.rs:832-840`
- Description: `ExitLoop` sets `buffer.loop_count = 0; buffer.played_loops = buffer.loop_count;`. But `loop_count == 0` is the "loop forever" convention used by `will_loop` (`loop_count == 0 || played_loops < loop_count`), so `will_loop` stays true and playback continues looping forever. `ExitLoop` is therefore a no-op exactly when it is needed.
- Fix suggestion: Add a `loop_disabled`/`exit_loop` flag to `QueuedBuffer` checked in `will_loop`, or set `loop_begin = None; loop_length = None` on exit.

## [HIGH] `compute_channel_pan` has `atan2` arguments swapped (front panned hard right)

- File: `src/audio.rs:2560` (compare `compute_hrtf_gains` at 2629 which uses the correct order)
- Description: `let azimuth = fwd_dot.atan2(right_dot);` — `atan2(y, x)` with y=fwd_dot. A source directly in front (fwd_dot=1, right_dot=0) yields π/2 → clamped → pan = +1 (full right); a source to the right yields azimuth 0 → pan 0 (center); a source to the left yields π → full right. Left/right and front/back mappings are wrong; 3D DirectSound buffers are panned incorrectly.
- Fix suggestion: `let azimuth = right_dot.atan2(fwd_dot);` (matching `compute_hrtf_gains`).

## [HIGH] Microsoft ADPCM adaptation table is not the standard table

- File: `src/audio_format.rs:34-36`
- Description: The standard MS ADPCM `AdaptationTable` is symmetric: `230,230,230,230,307,409,512,614, 768,614,512,409,307,230,230,230`. The table here has a non-standard second half (`...,307,409,512,614,768,614,768,1230`), so `decode_adpcm_ms` produces wrong delta scaling and diverges from the encoder's state — decoded audio is incorrect for all non-zero nibbles.
- Fix suggestion: Replace with the canonical 16-entry table above.

## [HIGH] Producer writes `head` — SPSC invariant violated (race on shared-memory ring)

- File: `src/audio_ring_buffer.rs:176-183`
- Description: In a single-producer/single-consumer ring the consumer owns `head`. Here the producer stores `head` on overflow while the consumer concurrently loads `head` (Relaxed) and later stores `head + read_count` (stale value) — the consumer's store can clobber the producer's adjustment, re-exposing dropped data or corrupting fill accounting. Combined with the overflow bug above, `head`/`tail` ordering is undefined between the two threads.
- Fix suggestion: Don't advance `head` from the producer. Instead, keep a per-buffer drop counter or a third atomic (`dropped`) that the consumer folds into its read position, or use a lock-free design where the producer only ever touches `tail`.

## [HIGH] `mmioCreateChunk`/`mmioAscend` never patch the chunk size field

- File: `src/winmm.rs:2152-2190` (create writes placeholder `cksize = 0`), `2027-2063` (ascend seeks to `dw_data_offset + cksize` but never writes the real size back)
- Description: Chunks created with `mmioCreateChunk` are always written to disk with `cksize = 0`; `mmioAscend` does not update the header. Any WAV/RIFF file written through the mmio API is malformed (zero-length chunks), and subsequently `mmioDescend` on the written file will misparse it.
- Fix suggestion: In `mmio_ascend`, seek to `chunk.dw_data_offset - 8` (or `- 12` for RIFF/LIST) and write `(current_pos - header_start - form_type_len)` as the little-endian `cksize`.

## [HIGH] Wrong `kMIDIPropertyDisplayName` constant — endpoint names never resolved

- File: `src/midi.rs:638`
- Description: `K_MIDI_PROPERTY_DISPLAY_NAME: i32 = 164_416_2816` = `0x61FFEF00`. The actual `kMIDIPropertyDisplayName` is FourCC `'name'` = `0x6E616D65` = 1851878757. With the wrong property ID, `MIDIObjectGetStringProperty` fails and every MIDI endpoint falls back to the generic `"MIDI Endpoint N"` name (also, on 64-bit macOS the property ID is a 32-bit value; the sign bit is not an issue for either value).
- Fix suggestion: `pub const K_MIDI_PROPERTY_DISPLAY_NAME: i32 = 0x6E61_6D65; // 'name'`.

## [HIGH] `wave_out_write` marks buffers done/consumed even when the push fails

- File: `src/winmm.rs:958-995`
- Description: `let _ = backend.push_wasapi_frames(...)` swallows the error, then unconditionally advances `total_bytes_consumed`/`total_frames_consumed` by the full input length and sets `last.done = true`. If the backend queue is full or the push fails, data is silently dropped while the guest is told it played — position queries (TIME_BYTES/TIME_SAMPLES/TIME_MS) lie, and the guest may recycle the buffer and overwrite audio that never played. Additionally, when `real_device_id` is `None` (backend init failed) the buffer stays queued forever: no WOM_DONE is ever delivered and the guest can hang.
- Fix suggestion: Check the `push_wasapi_frames` result; only update counters and mark `done` on success. On `None` device, return `MMSYSERR_ERROR`/fire WOM_DONE for the buffer via the callback mechanism rather than silently keeping it queued.

## [HIGH] PlaySound fallback path can never play (AIFF parsed as RIFF/WAV)

- File: `src/winmm.rs:1873` (fallback), `1727-1791` (RIFF-only parser)
- Description: When the requested sound file does not exist, `play_sound_w` falls back to `/System/Library/Sounds/Ping.aiff` and returns TRUE, but `play_sound_file_cpal` rejects anything without a `RIFF`/`WAVE` header — AIFF is not RIFF — so the fallback always fails (and the API claims success).
- Fix suggestion: Play an actual WAV fallback (ship/embed one) or synthesize a beep via the backend instead of pointing at an AIFF.

## [HIGH] `wave_in_close` leaks the capture thread and input stream

- File: `src/winmm.rs:1176-1184` (close never stops the thread), `1259-1334` (start spawns thread, stores stop flag in `wave_in_thread_stop`)
- Description: `wave_in_close` only flips `is_open`/`is_capturing`; it never sets the stop `AtomicBool`, never joins `wave_in_threads[handle]`, and never stops the real input stream. The 20 ms polling thread keeps sleeping forever (thread + `Arc<AtomicBool>` + open cpal input stream leak per open/close cycle), and a later `wave_in_start` on a reused handle cannot join the old thread.
- Fix suggestion: In `wave_in_close` (and on `WinMmSubsystem` drop), mirror `wave_in_stop`: signal `wave_in_thread_stop[handle]`, join `wave_in_threads.remove(handle)`, call `backend.stop_input_stream()`.

---

## [MEDIUM] `lock_direct_sound_buffer` underflows on `offset_bytes > buffer_bytes`

- File: `src/audio.rs:1288-1304`
- Description: For a wrap-around lock the code computes `first_len = buffer_bytes - offset_bytes` and `second_len = length_bytes - first_len` with no bounds checks. Guest-controlled `offset_bytes > buffer_bytes` → arithmetic underflow: panic in debug builds, garbage `usize` lengths in release (stored in `locked_regions`; later misuse if those lengths are consumed).
- Fix suggestion: Clamp `offset_bytes` to `buffer_bytes` and `length_bytes` to remaining, or reject with an error before arithmetic.

## [MEDIUM] `write_direct_sound_buffer_at` overflow on untrusted offset

- File: `src/audio.rs:1255-1260`
- Description: `end = offset_samples + samples.len()` can overflow (debug panic) and `record.samples.resize(end, 0.0)` can attempt a huge allocation for guest-provided offsets (OOM/DoS). No bound to the buffer's declared size.
- Fix suggestion: Use `checked_add`; cap `end` at the buffer capacity (or reject writes beyond capacity per DirectSound semantics).

## [MEDIUM] `DSBPN_OFFSETSTOP` notification fires only once ever

- File: `src/audio.rs:1545-1568`
- Description: `u32::MAX` is pushed into `fired_notifications` when the offset-stop fires, and the wrap-reset at 1564-1568 `retain`s `u32::MAX` entries (only non-MAX are reset). After the first stop, subsequent Play/Stop cycles never re-fire `DSBPN_OFFSETSTOP`.
- Fix suggestion: Clear `u32::MAX` entries when playback (re)starts, e.g. in `play_direct_sound_buffer_ex`.

## [MEDIUM] Loop begin/length interpreted as frames, not samples

- File: `src/audio.rs:715-716` (and `QueuedBuffer` cursor math 2005-2008)
- Description: XAudio2 `XAUDIO2_BUFFER.LoopBegin/LoopLength` are in *samples* (per-channel). Here they are rescaled only by the sample-rate ratio and then treated as frame counts. For multi-channel voices the loop points are off by a factor of `channels`, causing wrong loop behavior for stereo+ sources.
- Fix suggestion: Divide by `source_format.channels` when converting loop points to frames (or keep loop points in samples and compare against `sample_offset`).

## [MEDIUM] 3D listener lookup picks the first DirectSound object on the device

- File: `src/audio.rs:1745-1749`
- Description: `mix_direct_sound_buffer` finds the owning `DirectSoundId` by scanning for any object whose `device_id` matches. With two `IDirectSound8` objects on the same device, the listener state of the wrong object may be applied.
- Fix suggestion: Store the owning `direct_sound` id on the buffer record at creation instead of scanning.

## [MEDIUM] `capture_buffer` grows without bound

- File: `src/audio.rs:2216-2253`
- Description: `on_capture_data` appends converted PCM bytes to `capture_buffer` with no cap while `capture_active`. If the PE runtime does not drain promptly (or at all), memory grows unboundedly for the life of the capture session.
- Fix suggestion: Bound the buffer (drop oldest / return capacity) or require the runtime to consume before adding.

## [MEDIUM] Guest-controlled sizes can cause huge allocations (OOM DoS)

- File: `src/audio.rs:1166-1197` (`create_direct_sound_buffer` allocates `effective_size/4` samples from guest `buffer_size_bytes`), `1775` (`Vec::with_capacity(frames * channels)` in `mix_direct_sound_buffer`), `1069` (drain)
- Description: No upper bound on guest-supplied sizes; a single hostile call can trigger multi-GB allocations.
- Fix suggestion: Clamp buffer size / render frame counts to sane maxima (e.g. 64 MB, or reject > a few seconds of audio).

## [MEDIUM] CoreMIDI client/port/CFString objects are never released

- File: `src/midi.rs:641-655` (CFString create per call, never `CFRelease`), `676-717` (client/port created), `844-849` (Drop does nothing)
- Description: `cf_string_from_str` returns an owned (+1) `CFStringRef` that is never released (leak per `CoreMidiOutput::new`/`CoreMidiInput::new`); `MIDIClientRef`/`MIDIPortRef` are opaque retained objects and the Drop comment ("handles are just u64 IDs") is wrong — CoreMIDI requires `MIDIClientDispose`/`MIDIPortDispose`. Every init of the lazy statics leaks. Client creation happens once per process, but `CoreMidiOutput::new()` can be invoked repeatedly.
- Fix suggestion: Keep the `CFStringRef`s and dispose them; implement `Drop` calling `MIDIClientDispose(client)`; release CFStrings after `MIDIClientCreate`/`MIDIOutputPortCreate`.

## [MEDIUM] Unaligned reads of `MIDIPacket` in the input read proc

- File: `src/midi.rs:1044-1047`
- Description: Packets are advanced by `10 + ((len + 3) & !3)` bytes; the next `MIDIPacket` (which contains a `u64` timestamp) is then dereferenced via `&*packet_ptr`, creating a reference to a misaligned struct — UB per Rust rules (works on x86_64 in practice; can fault on stricter targets).
- Fix suggestion: Use `ptr::read_unaligned`/`copy_nonoverlapping` to read `timestamp` and `length` instead of forming a reference.

## [MEDIUM] Duplicate note-on + sustain leaves a stuck note

- File: `src/midi.rs:198-209`
- Description: With sustain held, a second `note_on` for an already-playing note creates a second `ActiveNote`. `note_off` marks only the *first* matching note `sustained`; on sustain release, `retain(|n| !n.sustained)` removes only that one — the duplicate keeps playing indefinitely (no note-off will ever match cleanly).
- Fix suggestion: On `note_on`, terminate (or replace) existing same-channel/same-note instances, or mark *all* matching notes sustained on note-off.

## [MEDIUM] `wave_in_get_num_devs` reports number of open devices, not available devices

- File: `src/winmm.rs:1132-1134`
- Description: `waveInGetNumDevs` returns `self.wave_in_devices.len()` (0 before any open), whereas it must report the number of *available* input devices (1), like `wave_out_get_num_devs` does. Games enumerating input devices see zero devices.
- Fix suggestion: Return a constant (1) matching the caps/open behavior.

## [MEDIUM] `PlaySoundW` SND_ALIAS / SND_MEMORY / SND_SYNC semantics not implemented

- File: `src/winmm.rs:1861-1866` (any `SND_ALIAS` without `SND_FILENAME` returns FALSE), `1904-1908` (SND_SYNC returns immediately after queueing), `1884-1902`
- Description: Alias playback (`PlaySoundW("SystemAsterisk")`) always fails; synchronous playback does not wait for completion (violates the documented blocking contract); `SND_MEMORY` is treated as a filename. Common guest code paths get silent failures.
- Fix suggestion: Resolve a small set of system aliases to shipped WAVs; for SND_SYNC, block until the backend reports the buffer consumed (or a bounded timeout).

## [MEDIUM] `mmioSeek` is missing from the mmio API

- File: `src/winmm.rs:1924-2204` (open/close/read/write/ascend/descend/createChunk/stringToFOURCC only; no `mmio_seek`), no `mmioSeek` thunk in `src/pe_runtime.rs`
- Description: RIFF parsing without `mmioSeek` is severely limited — guests cannot reposition within files; `mmioDescend`/`mmioAscend` rely on sequential scans. `mmioSeekW` calls will fail to resolve.
- Fix suggestion: Implement `mmio_seek(&mut self, handle, offset: i32, origin: u32)` (SEEK_SET/CUR/END) with `mmio.position` + file cursor updates, and dispatch it.

## [MEDIUM] `unsafe impl Send for RealAudioBackend` with no structural guarantee

- File: `src/winmm.rs:200-204`
- Description: A blanket `unsafe impl Send` is justified only by a comment. The backend owns cpal streams (`!Send` by design); moving streams across threads while callbacks reference them can be UB on some hosts. This is a global assertion with only informal reasoning.
- Fix suggestion: Keep the backend pinned to one thread (e.g. wrap in a dedicated audio thread or use `Mutex<Option<...>>` on the owning thread only), or document and unit-test cross-thread usage; prefer not to override the auto trait for the whole type.

## [MEDIUM] waveIn capture is a stub — WIM_DATA is never delivered

- File: `src/winmm.rs:1305-1317` (polling thread only sleeps), `1409-1416` (`bytes_captured` never advances)
- Description: The capture thread does nothing but sleep; queued `WaveInBuffer`s are never filled and `WIM_DATA` never fires. The real input stream is started but its data is never read. `wave_in_get_position` always reports 0 bytes.
- Fix suggestion: Implement the polling loop to pull captured frames from the backend and write PCM into queued `data_ptr` buffers, set `dw_bytes_recorded`, and surface the callback (or state clearly in dispatch that capture is unsupported and return `MMSYSERR_NOTSUPPORTED` at open).

## [MEDIUM] `wave_out` queued buffers are never removed (unbounded memory growth)

- File: `src/winmm.rs:950-951` (push), `1013-1017` (only `wave_out_reset` clears)
- Description: Every `waveOutWrite` appends to `device.buffers`; nothing pops completed buffers during normal playback (they are marked `done` but retained). Long-running games accumulate one `Vec<u8>` copy per write → unbounded memory growth.
- Fix suggestion: Remove buffers once `done` (e.g. in a subsequent write/position call, drain `done` entries), or drop them when WOM_DONE is delivered.

## [MEDIUM] `decode_adpcm_ms` underflow panic for `samples_per_block == 1`

- File: `src/audio_format.rs:173`
- Description: `encoded_samples_per_channel = samples_per_block - 2` underflows for `samples_per_block == 1` (guard at 155 only excludes 0): panic in debug builds, wrapped `usize::MAX` arithmetic in release. Guest-supplied `nSamplesPerBlock == 1` (malformed WAVE) reaches this directly.
- Fix suggestion: Require `samples_per_block >= 3` (2 initial samples + ≥1 nibble) or use `samples_per_block.saturating_sub(2)`.

## [MEDIUM] `AudioRingBuffer` panics when `channels == 0`

- File: `src/audio_ring_buffer.rs:194` (`fill_samples / channels`), `245-247` (underrun duration divides by `sample_rate * channels`), `src/winmm.rs` callers construct with guest-derived channels
- Description: `AudioRingBuffer::new` accepts `channels == 0` (mask becomes `usize::MAX`); the first `write`/`read` that takes the underrun/pre-buffer path divides by zero → panic on the audio thread.
- Fix suggestion: Reject `channels == 0` in `new` (assert or return `Option`) and use `channels.max(1)` consistently.

## [MEDIUM] `midi_in_start` threads compete for the global CoreMIDI drain

- File: `src/winmm.rs:1617-1635`
- Description: Every `MidiInputDevice` spawns a thread calling `midi::drain_core_midi_input()` on the single global `CORE_MIDI_INPUT` buffer; with ≥2 open input devices, messages are split arbitrarily between devices (each drain takes all pending messages). Also, `drain_received` while the CoreMIDI read proc holds the buffer lock blocks the CoreMIDI callback thread.
- Fix suggestion: Use one shared poller with a per-device fan-out, or hand a per-device subscription into `midi.rs`.

## [MEDIUM] `AudioSubsystem` state maps never bounded / stale entries

- File: `src/audio.rs:341-361` (all `BTreeMap`/`HashMap` + `notifications`/`latency_log` Vecs), `notifications` grows per event
- Description: `notifications` and `latency_log` are append-only and unbounded; a long session grows memory without limit. Low-churn in practice, but no cap exists.
- Fix suggestion: Cap `notifications`/`latency_log` (e.g. drain oldest beyond 10k entries) and remove `ds3d_*` state when buffers/objects are destroyed.

---

## [LOW] Misleading `!caps & FLAG != 0` precedence pattern

- File: `src/audio.rs:1368`, `src/audio.rs:1514`
- Description: `if !record.caps & DSBCAPS_CTRLVOLUME != 0` parses as `((!caps) & FLAG) != 0` — semantically "error if the bit is not set", which happens to be correct, but reads like a negation bug and is fragile to edits (e.g. adding parens around `!record.caps` would invert behavior).
- Fix suggestion: `if record.caps & DSBCAPS_CTRLVOLUME == 0`.

## [LOW] `apply_hrtf_spatialization` is dead code

- File: `src/audio.rs:2684-2701`
- Description: Private function never called anywhere (the crate-level allow(dead_code) masks it). HRTF is computed but never applied to output.
- Fix suggestion: Wire it into `mix_direct_sound_buffer`'s 3D path or delete it.

## [LOW] Redundant channel-range guard in `process_short_msg`

- File: `src/midi.rs:99-102`
- Description: `channel = status & 0x0F` can never be ≥ 16; the check is dead.
- Fix suggestion: Remove the guard (or keep as defensive only with a comment).

## [LOW] Trailing partial ADPCM block silently dropped

- File: `src/audio_format.rs:184-197`
- Description: `num_blocks = data.len() / block_size` discards any trailing partial block instead of decoding what it can (and `block_data = &data[block_start..]` re-slices the remainder, so `block_data.len() < header_size` breaks mid-stream rather than being an error).
- Fix suggestion: Document truncation behavior or decode the partial block up to available bytes.

## [LOW] `wave_out_get_position`/`mmio` values truncate to u32

- File: `src/winmm.rs:1076-1092`, `1985-2021`
- Description: `total_bytes_consumed as u32` and `mmio.position` (u64) exposed as u32 truncate past 4 GiB. Matches Windows' DWORD position semantics for MMTIME, but `mmio_read`/`mmio_write` counts and `mmio_ascend` padding (`pad as usize`) lose precision for >4 GiB files.
- Fix suggestion: Keep u64 internally and truncate only at the guest boundary, or document the limit.

## [LOW] `play_sound_w` drops the async `JoinHandle` without joining

- File: `src/winmm.rs:1877-1882`
- Description: On a new PlaySound, the previous thread handle is `take()`n and dropped after a fixed 50 ms sleep; the old thread may still be running (race: its `push_wasapi_frames` can land after the new sound starts). No join, no termination guarantee.
- Fix suggestion: Keep the `JoinHandle` and join it after signaling `PLAY_SOUND_STOP`, or guard with a generation counter.

---

## [PERF] `generate_samples` — 8 `sin` calls per sample per note

- File: `src/midi.rs:279-305`
- Description: Harmonic synthesis recomputes `sin(phase * harm)` for up to 8 harmonics per sample per active note (plus `t` and `envelope` math) — O(notes × samples × 8 sin). At 48 kHz with even 32 polyphonic voices this is ~12M transcendental ops/sec; the global synth mutex is held the whole time.
- Fix suggestion: Precompute per-note phase increment and harmonic phases incrementally (single `sin` + recurrence), or render via a lookup table; move envelope to per-frame updates.

## [PERF] `MidiStreamPlayer::generate_samples` scans the whole event queue every call

- File: `src/midi.rs:1319-1328`
- Description: Every generate pass does a full `filter` + `retain` over `event_queue` — O(n) per call, O(n²) over a long stream; `queue_event`/`queue_event_absolute` never sort or coalesce.
- Fix suggestion: Keep the queue sorted (binary-search insertion or push-then-sort-once) and process due events with a cursor instead of full rescans.

## [PERF] Realtime callback path performs locks and allocations

- File: `src/audio_ring_buffer.rs:243-252, 260-270` (`std::sync::Mutex` on every consumer read + `Instant::now()`), `src/midi.rs:541-546` (audio callback taking the synth `Mutex` while `generate_samples` allocates)
- Description: The ring buffer advertises "lock-free" but the consumer acquires a mutex up to twice per `read` call (and the producer twice per `write`), and `get_midi_samples` can block behind a long synthesis pass. Real-time-unsafe: priority inversion/glitches if the producer or a `midi_out_short_msg` caller holds the locks.
- Fix suggestion: Move metrics into lock-free atomics (or seqlock); compute underrun duration from a locally captured atomic fill; have the MIDI synth render into a pre-allocated buffer without allocation under the lock.
- Related: `src/audio.rs:1890-1953` — `render_voice_mix` clones `effects_chain`/`kind`/`channel_volumes` per voice per pass and `child_voice_ids` rescans all voices per parent (O(V²) for V voices per render); cache child lists on voice creation.

---

## Clippy

`cargo clippy --all-targets --no-deps` completed; **errors: 19 (lib) / 27 (lib test)** — all in out-of-scope files (`crash_recovery.rs`, `d3d11.rs`, `jit.rs`, `metal_backend.rs`, `pe_runtime.rs`, `security.rs`, `video_decoder.rs`, `winhttp.rs`, `cpu.rs`, `d2d.rs`, `dwrite.rs`, `real_win32.rs`, `seh.rs`). None of the errors reference the five audited files. Warnings for audited files (all `warn`, none deny):

- `src/audio.rs`
  - 1301, 1303 `redundant_field_names` (`length1: length1`, `length2: length2` in `LockedRegion` push)
  - 1770 `manual_checked_ops` (channels>0 + `/ channels`)
  - 1792 `assign_op_pattern` (`fractional_cursor = fractional_cursor % …`)
  - 1803 `same_item_push` (silence fill loop)
  - 2368 `needless_range_loop` (`apply_reverb`)
  - 3171 `derivable_impls` (`XAudio2DebugConfiguration`)
- `src/midi.rs`
  - 638 `inconsistent_digit_grouping` (see HIGH finding on the constant value)
  - 506, 509 `identity_op` (`| (0 << 16)`)
  - 1379, 1396 `collapsible_if` (`send_to_core_midi`/`send_sysex_to_core_midi`)
  - 1494, 1646 `identity_op` (tests)
  - 1594 `manual_repeat_n` (test)
- `src/audio_format.rs`
  - 180, 339, 855, 886 `manual_div_ceil` (nibble byte counts)
  - 204, 213, 219, 225, 232, 235 `needless_range_loop` (MS ADPCM header parse)
  - 250, 380 `manual_is_multiple_of`
- `src/audio_ring_buffer.rs`
  - 44 `derivable_impls` (`RingBufferMetrics`)
  - 68 `manual_checked_ops` (`average_latency_us`)
  - 497, 516, 520, 552, 576, 682, 756, 772 `needless_range_loop` (tests)
- `src/winmm.rs`
  - 1080 `unnecessary_cast` (`total_frames_consumed as u64`)
  - 1354, 1388, 1626, 1844, 1845 `collapsible_if`

## Build

- `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` → **FAILED** (`could not compile casa1 (lib)` — 19 errors; `could not compile casa1 (lib test)` — 27 errors). All build-breaking diagnostics are outside the audited files; the five audited files compile with warnings only. `--all-features` was not used (missing system ffmpeg is environmental).
- No unit-test run was performed (clippy build of the test target fails on out-of-scope files; the tests inside the audited files are straightforward and their `#[cfg(test)]` code was read in full).
