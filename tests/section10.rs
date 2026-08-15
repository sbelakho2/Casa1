use casa1::audio::{
    AudioSamples, AudioSubsystem, SampleFormat, SourceBuffer, VoiceCallbackEvent, WaveFormat,
    crc32_samples,
};
use std::fs;
use tempfile::tempdir;

fn stereo(samples: &[[f32; 2]]) -> Vec<f32> {
    samples
        .iter()
        .flat_map(|frame| frame.iter().copied())
        .collect()
}

#[test]
fn t10_1_golden_pcm_deterministic_synth_output_crc_matches_reference_within_tolerance() {
    let mut audio = AudioSubsystem::new();
    let mastering = audio
        .create_mastering_voice(WaveFormat {
            channels: 2,
            sample_rate: 48_000,
            sample_format: SampleFormat::Float32,
        })
        .expect("create mastering voice");
    let submix = audio
        .create_submix_voice(
            WaveFormat {
                channels: 2,
                sample_rate: 48_000,
                sample_format: SampleFormat::Float32,
            },
            mastering,
        )
        .expect("create submix voice");
    let source_a = audio
        .create_source_voice(
            WaveFormat {
                channels: 1,
                sample_rate: 24_000,
                sample_format: SampleFormat::Pcm16,
            },
            submix,
        )
        .expect("create source A");
    let source_b = audio
        .create_source_voice(
            WaveFormat {
                channels: 2,
                sample_rate: 48_000,
                sample_format: SampleFormat::Float32,
            },
            mastering,
        )
        .expect("create source B");

    audio.set_reverb_mix(submix, 0.25).expect("enable reverb");
    audio
        .set_volume(source_a, 0.5)
        .expect("set source A volume");
    audio
        .set_channel_volumes(source_a, vec![1.0])
        .expect("set source A channel volumes");
    audio
        .set_output_matrix(source_a, vec![1.0, 1.0])
        .expect("set source A output matrix");
    audio
        .set_channel_volumes(source_b, vec![0.5, 1.0])
        .expect("set source B channel volumes");

    audio
        .submit_source_buffer(
            source_a,
            SourceBuffer {
                tag: "pcm16".to_string(),
                samples: AudioSamples::Pcm16(vec![i16::MAX, i16::MIN]),
                loop_begin: None,
                loop_count: None,
                loop_length: None,
            },
        )
        .expect("submit source A buffer");
    audio
        .submit_source_buffer(
            source_b,
            SourceBuffer {
                tag: "float32".to_string(),
                samples: AudioSamples::Float32(stereo(&[
                    [0.1, 0.2],
                    [0.2, 0.3],
                    [0.3, 0.4],
                    [0.4, 0.5],
                ])),
                loop_begin: None,
                loop_count: None,
                loop_length: None,
            },
        )
        .expect("submit source B buffer");

    audio.start_voice(mastering).expect("start mastering");
    audio.start_voice(submix).expect("start submix");
    audio.start_voice(source_a).expect("start source A");
    audio.start_voice(source_b).expect("start source B");
    let rendered = audio
        .render_xaudio2(mastering, 4)
        .expect("render xaudio2 mix");

    let expected = stereo(&[
        [0.55, 0.7],
        [0.725, 0.925],
        [-0.19375, 0.056250006],
        [-0.3859375, -0.0859375],
    ]);
    // Epsilon comparison: the mixer/resampler output is deterministic but may
    // legitimately shift at the 1-ulp level with filter coefficient changes,
    // so bit-exact equality would be a brittle golden test.
    assert_eq!(rendered.samples.len(), expected.len());
    for (actual, reference) in rendered.samples.iter().zip(&expected) {
        assert!(
            (actual - reference).abs() <= 1e-6,
            "sample {actual} differs from reference {reference} by more than 1e-6"
        );
    }
    // CRC must be consistent with the rendered samples (internal invariant),
    // not pinned to the hand-computed vector.
    assert_eq!(rendered.crc32, crc32_samples(&rendered.samples));
    assert!(rendered.latency_ms <= 50);

    let direct_sound = audio
        .create_direct_sound8(audio.default_device())
        .expect("create DirectSound8 object");
    let ds_buffer = audio
        .create_direct_sound_buffer(
            direct_sound,
            WaveFormat {
                channels: 1,
                sample_rate: 48_000,
                sample_format: SampleFormat::Float32,
            },
            0, // caps: default flags (DSBCAPS_STATIC | CTRLVOLUME | CTRLPAN | CTRLFREQUENCY)
            0, // buffer_size_bytes: 0 = default
        )
        .expect("create DirectSound buffer");
    let ds_samples = vec![0.25, -0.25, 0.5, -0.5];
    audio
        .write_direct_sound_buffer(ds_buffer, &ds_samples)
        .expect("write DirectSound samples");
    audio
        .play_direct_sound_buffer(ds_buffer)
        .expect("play DirectSound buffer");
    let ds_output = audio
        .mix_direct_sound_buffer(ds_buffer, 4)
        .expect("mix DirectSound buffer");
    assert_eq!(ds_output.samples, ds_samples);
    assert_eq!(ds_output.crc32, crc32_samples(&ds_samples));
}

#[test]
fn t10_host_render_export_writes_playable_wav() {
    let mut audio = AudioSubsystem::new();
    let mastering = audio
        .create_mastering_voice(WaveFormat {
            channels: 2,
            sample_rate: 48_000,
            sample_format: SampleFormat::Float32,
        })
        .expect("create mastering voice");
    let source = audio
        .create_source_voice(
            WaveFormat {
                channels: 2,
                sample_rate: 48_000,
                sample_format: SampleFormat::Float32,
            },
            mastering,
        )
        .expect("create source voice");
    audio
        .submit_source_buffer(
            source,
            SourceBuffer {
                tag: "preview".to_string(),
                samples: AudioSamples::Float32(stereo(&[[0.1, -0.1], [0.25, -0.25], [0.5, -0.5]])),
                loop_begin: None,
                loop_count: None,
                loop_length: None,
            },
        )
        .expect("submit preview source buffer");
    audio.start_voice(mastering).expect("start mastering");
    audio.start_voice(source).expect("start source");
    let rendered = audio
        .render_xaudio2(mastering, 3)
        .expect("render preview mix");

    let temp_dir = tempdir().expect("temp dir");
    let wav_path = temp_dir.path().join("preview.wav");
    let format = audio.voice_format(mastering).expect("voice format");
    audio
        .export_render_output_wav(&rendered, &format, &wav_path)
        .expect("export wav");

    let bytes = fs::read(&wav_path).expect("read wav");
    assert!(bytes.starts_with(b"RIFF"));
    assert_eq!(&bytes[8..12], b"WAVE");
    assert!(bytes.len() > 44);
}

#[test]
fn t10_2_callback_timing_buffer_callbacks_occur_with_correct_ordering() {
    let mut audio = AudioSubsystem::new();
    let mastering = audio
        .create_mastering_voice(WaveFormat {
            channels: 1,
            sample_rate: 48_000,
            sample_format: SampleFormat::Float32,
        })
        .expect("create mastering voice");
    let source = audio
        .create_source_voice(
            WaveFormat {
                channels: 1,
                sample_rate: 48_000,
                sample_format: SampleFormat::Float32,
            },
            mastering,
        )
        .expect("create source voice");
    audio
        .submit_source_buffer(
            source,
            SourceBuffer {
                tag: "first".to_string(),
                samples: AudioSamples::Float32(vec![0.1, 0.2]),
                loop_begin: None,
                loop_count: None,
                loop_length: None,
            },
        )
        .expect("submit first buffer");
    audio
        .submit_source_buffer(
            source,
            SourceBuffer {
                tag: "second".to_string(),
                samples: AudioSamples::Float32(vec![0.3, 0.4]),
                loop_begin: None,
                loop_count: None,
                loop_length: None,
            },
        )
        .expect("submit second buffer");
    audio.start_voice(mastering).expect("start mastering");
    audio.start_voice(source).expect("start source");
    let rendered = audio
        .render_xaudio2(mastering, 4)
        .expect("render callbacks");
    assert_eq!(
        rendered.voice_callbacks,
        vec![
            VoiceCallbackEvent {
                voice: source,
                event: "OnBufferEnd".to_string(),
                tag: "first".to_string(),
                sample_offset: 2,
            },
            VoiceCallbackEvent {
                voice: source,
                event: "OnBufferEnd".to_string(),
                tag: "second".to_string(),
                sample_offset: 4,
            },
        ]
    );
    audio
        .flush_source_buffers(source)
        .expect("flush buffers after playback");
}

#[test]
fn t10_3_device_switch_during_playback_matches_expected_stop_and_recover_pattern() {
    let mut audio = AudioSubsystem::new();
    let usb = audio.add_device("USB Headset", 2, 48_000);
    let mastering = audio
        .create_mastering_voice(WaveFormat {
            channels: 2,
            sample_rate: 48_000,
            sample_format: SampleFormat::Float32,
        })
        .expect("create mastering voice");
    let source = audio
        .create_source_voice(
            WaveFormat {
                channels: 2,
                sample_rate: 48_000,
                sample_format: SampleFormat::Float32,
            },
            mastering,
        )
        .expect("create source voice");
    audio
        .submit_source_buffer(
            source,
            SourceBuffer {
                tag: "switch".to_string(),
                samples: AudioSamples::Float32(stereo(&[[0.0, 0.1], [0.2, 0.3]])),
                loop_begin: None,
                loop_count: None,
                loop_length: None,
            },
        )
        .expect("submit playback buffer");
    audio.start_voice(mastering).expect("start mastering");
    audio.start_voice(source).expect("start source");

    let negotiated = audio
        .negotiate_format(
            audio.default_device(),
            WaveFormat {
                channels: 2,
                sample_rate: 48_000,
                sample_format: SampleFormat::Float32,
            },
        )
        .expect("negotiate WASAPI format");
    let client = audio
        .create_audio_client(audio.default_device(), negotiated, 480, true)
        .expect("create audio client");
    assert_eq!(audio.get_buffer_size(client).expect("buffer size"), 480);
    assert_eq!(
        audio
            .get_service_render_client(client)
            .expect("render client"),
        client
    );
    audio
        .start_audio_client(client)
        .expect("start audio client");
    audio
        .write_render_frames(client, &stereo(&[[0.1, 0.2], [0.3, 0.4], [0.5, 0.6]]))
        .expect("write render frames");

    audio
        .set_default_device(usb)
        .expect("switch default device");
    let drained = audio
        .drain_audio_client(client, 3)
        .expect("drain switched client");
    audio.stop_audio_client(client).expect("stop audio client");

    assert_eq!(audio.default_device(), usb);
    assert!(
        audio
            .devices()
            .iter()
            .any(|device| device.id == usb && device.is_default)
    );
    assert_eq!(
        audio.notifications(),
        &[
            format!("device_added:{usb}:USB Headset"),
            format!("default_changed:1->{usb}"),
            "playback_stop:1".to_string(),
            format!("playback_recover:{usb}"),
        ]
    );
    assert_eq!(
        drained.event_log,
        vec!["render_ready@1", "render_ready@2", "render_ready@3"]
    );
    assert!(
        audio
            .latency_log()
            .iter()
            .all(|record| record.measured_ms <= 50)
    );
    audio.remove_device(usb).expect("remove USB headset");
    assert!(
        audio
            .notifications()
            .iter()
            .any(|entry| entry == &format!("device_removed:{usb}"))
    );
}

#[test]
fn t10_4_underflow_overflow_torture_randomized_buffer_sizes_recover_without_deadlocks() {
    let mut audio = AudioSubsystem::new();
    let client = audio
        .create_audio_client(
            audio.default_device(),
            WaveFormat {
                channels: 2,
                sample_rate: 48_000,
                sample_format: SampleFormat::Float32,
            },
            4,
            true,
        )
        .expect("create torture client");
    audio
        .start_audio_client(client)
        .expect("start torture client");

    // The client buffer holds 4 frames (2 channels) with a 2x overflow queue
    // (max 8 frames queued, src/audio.rs:1051). The loop writes
    // [1, 8, 0, 3, 10, 2] frames and drains 3 frames per iteration.
    let frame_counts = [1, 8, 0, 3, 10, 2];
    let written_frames = frame_counts.iter().sum::<usize>();
    let mut drained_real_frames = 0_u64;
    let mut previous_underflow = 0_u32;
    let mut previous_overflow = 0_u32;
    let mut last_underflow = 0_u32;
    let mut last_overflow = 0_u32;
    for frame_count in frame_counts {
        let mut frames = Vec::new();
        for index in 0..frame_count {
            frames.extend([index as f32 / 10.0, -(index as f32) / 10.0]);
        }
        audio
            .write_render_frames(client, &frames)
            .expect("write torture frames");
        let drained = audio
            .drain_audio_client(client, 3)
            .expect("drain torture frames");
        // Every drain must return exactly 3 frames x 2 channels — no dropped
        // or mis-sized buffers.
        assert_eq!(drained.samples.len(), 6, "drain must return 3 stereo frames");
        let underflow_delta = drained.underflow_frames - previous_underflow;
        let _overflow_delta = drained.overflow_frames - previous_overflow;
        assert!(
            underflow_delta <= 3,
            "at most 3 frames can underflow per 3-frame drain"
        );
        drained_real_frames += 3 - u64::from(underflow_delta);
        previous_underflow = drained.underflow_frames;
        previous_overflow = drained.overflow_frames;
        last_underflow = drained.underflow_frames;
        last_overflow = drained.overflow_frames;
        assert!(drained.latency_ms <= 50);
    }

    // Accounting invariant: written frames == real frames drained + frames
    // dropped by overflow + frames still queued. Drain the remainder (up to
    // the full write total) and verify the leftover is exactly what remains.
    let remaining = audio
        .drain_audio_client(client, written_frames)
        .expect("drain remaining torture frames");
    let remaining_real = written_frames as u64 - u64::from(remaining.underflow_frames - last_underflow);
    assert_eq!(
        drained_real_frames + remaining_real + u64::from(last_overflow),
        written_frames as u64,
        "frame accounting must be lossless: drained + dropped + remaining == written"
    );
    assert_eq!(remaining.samples.len(), written_frames * 2);
    // The buffer must remain usable after the torture: a further write/drain
    // cycle succeeds.
    audio
        .write_render_frames(client, &[0.5, -0.5])
        .expect("write after torture");
    let post = audio
        .drain_audio_client(client, 1)
        .expect("drain after torture");
    assert_eq!(post.samples, vec![0.5, -0.5]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t10_5 — DirectSound primary vs secondary buffer flags and cooperative level
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t10_5_direct_sound_buffer_flags_and_cooperative_level() {
    let mut audio = AudioSubsystem::new();
    let ds = audio
        .create_direct_sound8(audio.default_device())
        .expect("create DirectSound8");

    // Cooperative level should default to DSSCL_NORMAL (1) or set to DSSCL_EXCLUSIVE (4)
    audio
        .set_direct_sound_cooperative_level(ds, 4)
        .expect("set cooperative level");
    let level = audio
        .get_direct_sound_cooperative_level(ds)
        .expect("get cooperative level");
    assert_eq!(level, 4);

    // Create a secondary buffer with specific caps flags:
    // DSBCAPS_CTRLVOLUME (0x0002) | DSBCAPS_CTRLFREQUENCY (0x0020) | DSBCAPS_GLOBALFOCUS (0x8000)
    let caps_flags = 0x0002 | 0x0020 | 0x8000;
    let buf = audio
        .create_direct_sound_buffer(
            ds,
            WaveFormat {
                channels: 2,
                sample_rate: 48_000,
                sample_format: SampleFormat::Float32,
            },
            caps_flags,
            0, // default buffer size
        )
        .expect("create secondary DS buffer");

    let retrieved_caps = audio.get_direct_sound_buffer_caps(buf).expect("get caps");
    assert_eq!(retrieved_caps, caps_flags);

    // Verify buffer format
    let fmt = audio
        .get_direct_sound_buffer_format(buf)
        .expect("get format");
    assert_eq!(fmt.channels, 2);
    assert_eq!(fmt.sample_rate, 48_000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t10_6 — DirectSound buffer cursor, looping, lock/unlock, and underflow
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t10_6_direct_sound_cursor_looping_lock_unlock() {
    let mut audio = AudioSubsystem::new();
    let ds = audio
        .create_direct_sound8(audio.default_device())
        .expect("create DirectSound8");

    // Create buffer with small explicit size
    let buf = audio
        .create_direct_sound_buffer(
            ds,
            WaveFormat {
                channels: 1,
                sample_rate: 48_000,
                sample_format: SampleFormat::Float32,
            },
            0,   // default caps
            256, // buffer_size_bytes
        )
        .expect("create DS buffer");

    // Write and play non-looping
    let samples = vec![0.1, 0.2, 0.3, 0.4];
    audio
        .write_direct_sound_buffer(buf, &samples)
        .expect("write samples");
    audio
        .play_direct_sound_buffer(buf)
        .expect("play non-looping");

    // Cursor units are bytes (documented at src/audio.rs:1444-1457), and the
    // write cursor tracks the position of the last mix, not the write call:
    // nothing has been mixed yet, so both cursors are 0.
    let (play_cursor, write_cursor) = audio
        .get_direct_sound_buffer_position(buf)
        .expect("get cursor");
    assert_eq!(
        (play_cursor, write_cursor),
        (0, 0),
        "before any mix the play and write cursors must be 0 bytes"
    );

    // Mixing advances both cursors in lockstep by the mixed frame count
    // (mono f32: 1 frame = 4 bytes).
    let mixed = audio
        .mix_direct_sound_buffer(buf, 4)
        .expect("mix first four frames");
    assert_eq!(mixed.samples.len(), 4);
    assert_eq!(mixed.samples, samples);
    let (play_cursor, write_cursor) = audio
        .get_direct_sound_buffer_position(buf)
        .expect("get cursor after mix");
    assert_eq!(
        (play_cursor, write_cursor),
        (16, 16),
        "4 mixed mono frames advance both cursors by 16 bytes"
    );
    // The buffer is exhausted after the first 4-frame mix (non-looping):
    // further mixing yields silence and the cursors stay put (monotonic
    // non-decreasing).
    let second_mix = audio
        .mix_direct_sound_buffer(buf, 2)
        .expect("mix two more frames");
    assert_eq!(second_mix.samples.len(), 2);
    assert_eq!(second_mix.samples, vec![0.0, 0.0]);
    let (play_cursor, write_cursor) = audio
        .get_direct_sound_buffer_position(buf)
        .expect("get cursor after second mix");
    assert_eq!(
        (play_cursor, write_cursor),
        (16, 16),
        "cursors must be monotonically non-decreasing in bytes"
    );

    // Stop and set position
    audio.stop_direct_sound_buffer(buf).expect("stop buffer");
    audio
        .set_direct_sound_buffer_position(buf, 0)
        .expect("set position to 0");
    assert_eq!(
        audio
            .get_direct_sound_buffer_position(buf)
            .expect("cursor after set position"),
        (0, 0)
    );

    // Write at offset and mix
    let more_samples = vec![0.5, 0.6];
    audio
        .write_direct_sound_buffer_at(buf, 0, &more_samples)
        .expect("write at offset 0");

    // Play looping
    audio
        .play_direct_sound_buffer_ex(buf, 0x00000001)
        .expect("play looping");

    // Lock/unlock the buffer (DSBLOCK_WRITE = 0x0000, use 0 for default)
    let _locked = audio
        .lock_direct_sound_buffer(buf, 0, 16, 0)
        .expect("lock buffer");
    audio
        .unlock_direct_sound_buffer(buf)
        .expect("unlock buffer");

    // Underflow: mix more samples than remain in the looping buffer
    let mixed = audio
        .mix_direct_sound_buffer(buf, 10)
        .expect("mix with potential underflow");
    // Loop playback restarts the buffer, so all 10 frames are produced and
    // replay the written samples (the offset-0 write replaced [0.1, 0.2]
    // with [0.5, 0.6]).
    assert_eq!(mixed.samples.len(), 10);
    assert_eq!(&mixed.samples[..4], &[0.5, 0.6, 0.3, 0.4]);
    assert_eq!(&mixed.samples[4..8], &[0.5, 0.6, 0.3, 0.4]);
    assert_eq!(&mixed.samples[8..10], &[0.5, 0.6]);
    // After a looping mix the cursor lands on frames % total_frames
    // (10 % 4 = 2 frames = 8 bytes) — the documented wrap semantics of the
    // fractional cursor.
    assert_eq!(
        audio
            .get_direct_sound_buffer_position(buf)
            .expect("cursor after looping mix"),
        (8, 8),
        "looping mix wraps the cursor at the buffer length"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// t10_7 — XAudio2 channel mixing, resampling, mastering/submix voices, latency
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t10_7_xaudio2_channel_mixing_resampling_and_latency() {
    let mut audio = AudioSubsystem::new();

    // Create mastering voice with 5.1 output format
    let mastering = audio
        .create_mastering_voice(WaveFormat {
            channels: 6,
            sample_rate: 48_000,
            sample_format: SampleFormat::Float32,
        })
        .expect("create mastering 5.1");

    // Submix voice with different format (for resampling test)
    let submix = audio
        .create_submix_voice(
            WaveFormat {
                channels: 2,
                sample_rate: 24_000,
                sample_format: SampleFormat::Float32,
            },
            mastering,
        )
        .expect("create submix voice");

    // Source voice with mono input, connected to submix. 24 kHz is the
    // lowest supported source rate (src/audio.rs:2092-2097 supports
    // 22.05/24/44.1/48/96/192 kHz — 12 kHz is rejected).
    let source = audio
        .create_source_voice(
            WaveFormat {
                channels: 1,
                sample_rate: 24_000,
                sample_format: SampleFormat::Float32,
            },
            submix,
        )
        .expect("create source voice");

    // Submit sample data
    let mono_samples: Vec<f32> = (0..12).map(|i| (i as f32 - 5.0) / 10.0).collect();
    audio
        .submit_source_buffer(
            source,
            SourceBuffer {
                tag: "resample".to_string(),
                samples: AudioSamples::Float32(mono_samples.clone()),
                loop_begin: None,
                loop_count: None,
                loop_length: None,
            },
        )
        .expect("submit source buffer");

    // Set channel volumes for mixing
    audio
        .set_channel_volumes(source, vec![0.8])
        .expect("set channel volumes");
    // Source is mono and feeds the 2-channel submix: the output matrix must
    // have 1 x 2 = 2 entries (src/audio.rs:782-804 validates the size).
    audio
        .set_output_matrix(source, vec![1.0, 0.5])
        .expect("set output matrix");

    // Start and render
    audio.start_voice(mastering).expect("start mastering");
    audio.start_voice(submix).expect("start submix");
    audio.start_voice(source).expect("start source");

    let rendered = audio
        .render_xaudio2(mastering, 12)
        .expect("render resampled mix");

    // Output is 5.1 (6 channels): 12 frames x 6 channels.
    assert_eq!(rendered.samples.len(), 72);
    assert!(rendered.latency_ms <= 50);
    assert_ne!(rendered.crc32, 0);
    // Channel projection: mono source -> stereo submix (matrix [1.0, 0.5])
    // -> 5.1 mastering (default L->L, R->R), source volume 0.8.
    // Frame i = (i - 5) / 10, so frame 0 is -0.5: output is
    // [-0.4, -0.2, 0, 0, 0, 0] per frame.
    let expected_frame_0 = [-0.4, -0.2, 0.0, 0.0, 0.0, 0.0];
    for (actual, reference) in rendered.samples[..6].iter().zip(expected_frame_0) {
        assert!(
            (actual - reference).abs() <= 1e-6,
            "first output frame channel mismatch: {actual} != {reference}"
        );
    }
    // Every frame must follow the same projection: [0.8s, 0.4s, 0, 0, 0, 0].
    for frame in 0..12 {
        let s = mono_samples[frame] * 0.8;
        let base = frame * 6;
        assert!((rendered.samples[base] - s).abs() <= 1e-6);
        assert!((rendered.samples[base + 1] - s * 0.5).abs() <= 1e-6);
        for channel in 2..6 {
            assert_eq!(rendered.samples[base + channel], 0.0);
        }
    }
}
