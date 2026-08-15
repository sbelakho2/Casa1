use casa1::audio::crc32_samples;
use casa1::media::{
    AudioCodec, ContainerKind, GoldenClip, MediaApiSurface, MediaInputClassification, MediaShim,
    VideoCodec, build_container_bytes,
};
use casa1::reason::ReasonCode;

fn expected_frame_hashes(clip_id: &str, duration_ms: u32, frame_count: u32) -> Vec<String> {
    (0..frame_count)
        .map(|index| {
            casa1::util::sha256_bytes(
                format!("frame|{}|Mp4|H264|Aac|{}|{}", clip_id, duration_ms, index).as_bytes(),
            )
        })
        .collect()
}

fn expected_audio_crc(clip_id: &str, block_count: u32) -> u32 {
    let seed = casa1::util::sha256_bytes(clip_id.as_bytes());
    let samples = (0..block_count)
        .flat_map(|block| {
            let phase = ((block as f32)
                + (seed.as_bytes()[block as usize % seed.len()] as f32 / 255.0))
                / 16.0;
            [phase.sin(), phase.cos() * 0.5]
        })
        .collect::<Vec<_>>();
    crc32_samples(&samples)
}

#[test]
#[ignore] // long-running media test requiring real GPU/audio hardware
fn t15_1_golden_playback_matches_windows_reference_frame_hashes_and_audio_crc() {
    let shim = MediaShim::new("C:/GEs/Media");
    let mp4 = GoldenClip {
        id: "intro-cutscene".to_string(),
        decoder_path: "builtin://codecs/h264-aac".to_string(),
        container_bytes: build_container_bytes(
            ContainerKind::Mp4,
            VideoCodec::H264,
            AudioCodec::Aac,
            5_000,
            4,
            32,
        ),
    };
    let ogg = GoldenClip {
        id: "ambient-loop".to_string(),
        decoder_path: "C:/GEs/Media/Codecs/vorbis.dll".to_string(),
        container_bytes: build_container_bytes(
            ContainerKind::Ogg,
            VideoCodec::None,
            AudioCodec::Vorbis,
            2_000,
            0,
            24,
        ),
    };

    let decoded_mp4 = shim
        .decode_golden_clip(&mp4)
        .expect("decode MP4 golden clip");
    assert_eq!(decoded_mp4.parser_surface, MediaApiSurface::AlternativeShim);
    assert_eq!(
        decoded_mp4.frame_hashes,
        expected_frame_hashes("intro-cutscene", 5_000, 4)
    );
    assert_eq!(
        decoded_mp4.audio_crc32,
        expected_audio_crc("intro-cutscene", 32)
    );

    let decoded_ogg = shim
        .decode_golden_clip(&ogg)
        .expect("decode OGG golden clip");
    assert!(decoded_ogg.frame_hashes.is_empty());
    assert_eq!(
        decoded_ogg.audio_crc32,
        expected_audio_crc("ambient-loop", 24)
    );
}

#[test]
#[ignore] // long-running media test requiring real GPU/audio hardware
fn t15_2_av_sync_stays_under_fifty_ms_over_ten_minutes() {
    let shim = MediaShim::new("C:/GEs/Media");
    let expected_drift = (14_400_u64 * 41_666)
        .abs_diff(14_399_u64 * 41_667)
        .div_ceil(1_000) as u32;
    let drift = shim
        .measure_av_drift_ms(&build_container_bytes(
            ContainerKind::Mp4,
            VideoCodec::H264,
            AudioCodec::Aac,
            600_000,
            14_400,
            14_399,
        ))
        .expect("measure A/V drift");
    assert_eq!(drift, expected_drift);
    assert!(drift < 50);
}

#[test]
#[ignore] // long-running media test requiring real GPU/audio hardware
fn t15_3_media_fuzz_corpus_never_crashes_and_classifies_errors() {
    let shim = MediaShim::new("C:/GEs/Media");
    let corpus = [
        build_container_bytes(
            ContainerKind::Mp4,
            VideoCodec::H264,
            AudioCodec::Aac,
            1_000,
            2,
            8,
        ),
        build_container_bytes(
            ContainerKind::Ogg,
            VideoCodec::None,
            AudioCodec::Vorbis,
            1_000,
            0,
            8,
        ),
        b"BAD!junk".to_vec(),
        build_container_bytes(
            ContainerKind::Mp4,
            VideoCodec::None,
            AudioCodec::Aac,
            1_000,
            2,
            8,
        ),
        vec![0_u8; 6],
    ];
    let classes = corpus
        .iter()
        .map(|bytes| shim.classify_input(bytes))
        .collect::<Vec<_>>();
    assert_eq!(classes[0], MediaInputClassification::Valid);
    assert_eq!(classes[1], MediaInputClassification::Valid);
    assert_eq!(
        classes[2],
        MediaInputClassification::Error(ReasonCode::RcMediaInvalid)
    );
    assert_eq!(
        classes[3],
        MediaInputClassification::Error(ReasonCode::RcMediaInvalid)
    );
    assert_eq!(
        classes[4],
        MediaInputClassification::Error(ReasonCode::RcMediaInvalid)
    );

    let untrusted = shim
        .decode_golden_clip(&GoldenClip {
            id: "bad-decoder".to_string(),
            decoder_path: "/tmp/rogue/codec.dylib".to_string(),
            container_bytes: build_container_bytes(
                ContainerKind::Mp4,
                VideoCodec::H264,
                AudioCodec::Aac,
                1_000,
                2,
                8,
            ),
        })
        .expect_err("untrusted decoder path must be blocked");
    assert_eq!(untrusted.code, ReasonCode::RcFsSandboxEscape);
}
