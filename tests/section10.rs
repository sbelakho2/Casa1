#![allow(dead_code, unused_imports)]
use casa1::audio::{AudioSubsystem, SampleFormat, WaveFormat};

fn stereo(samples: &[[f32; 2]]) -> Vec<f32> {
    samples
        .iter()
        .flat_map(|frame| frame.iter().copied())
        .collect()
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
        assert_eq!(
            drained.samples.len(),
            6,
            "drain must return 3 stereo frames"
        );
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
    let remaining_real =
        written_frames as u64 - u64::from(remaining.underflow_frames - last_underflow);
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

// ═══════════════════════════════════════════════════════════════════════════════
// t10_6 — DirectSound buffer cursor, looping, lock/unlock, and underflow
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t10_7 — XAudio2 channel mixing, resampling, mastering/submix voices, latency
// ═══════════════════════════════════════════════════════════════════════════════
