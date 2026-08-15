use casa1::media::{
    AudioCodec, ContainerKind, GoldenClip, MediaApiSurface, MediaInputClassification, MediaShim,
    VideoCodec, build_container_bytes,
};
use casa1::reason::ReasonCode;

// Golden values below are pinned literals captured from a known-good run of the synthetic
// decoder pipeline. They are deliberately NOT recomputed in the test from the
// implementation's own hashing/CRC formulas — previously the test re-derived every
// expected value from the same format strings the implementation uses, which made the
// assertions self-referential (any implementation replaying the formulas passed).
// Pinning the literals turns these into regression guards: any change to the container
// parsing, frame-hash inputs, or sample synthesis breaks the test.

const GOLDEN_MP4_FRAME_HASHES: [&str; 4] = [
    "0137ff276bd1493b2fe1f90e3027b8d30a85117646e66a71e34e281a9a74d8ae",
    "ad50ad7042bdeb9686f020db2437cd6351508058705abddf8a596c4b66e57ebd",
    "1c6cfd8fa4203852675b6b81d091307ed60f0d90b5487275bca8eb8aec0d5ed7",
    "ddd2d265261083f3704177211765865894d0f3393babc65324f94f0b40816da4",
];
const GOLDEN_MP4_AUDIO_CRC: u32 = 3_300_297_471;
const GOLDEN_OGG_AUDIO_CRC: u32 = 2_889_771_887;
const GOLDEN_AV_DRIFT_MS: u32 = 28;

#[test]
fn t15_1_golden_playback_matches_pinned_reference_frame_hashes_and_audio_crc() {
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
        decoded_mp4.frame_hashes.len(),
        GOLDEN_MP4_FRAME_HASHES.len(),
        "frame count must match the pinned golden fixture"
    );
    for (index, (actual, golden)) in decoded_mp4
        .frame_hashes
        .iter()
        .zip(GOLDEN_MP4_FRAME_HASHES.iter())
        .enumerate()
    {
        assert_eq!(
            actual, golden,
            "frame {index} hash drifted from the pinned golden value"
        );
    }
    assert_eq!(
        decoded_mp4.audio_crc32, GOLDEN_MP4_AUDIO_CRC,
        "audio CRC drifted from the pinned golden value"
    );

    let decoded_ogg = shim
        .decode_golden_clip(&ogg)
        .expect("decode OGG golden clip");
    assert!(decoded_ogg.frame_hashes.is_empty());
    assert_eq!(
        decoded_ogg.audio_crc32, GOLDEN_OGG_AUDIO_CRC,
        "audio CRC drifted from the pinned golden value"
    );
}

#[test]
fn t15_2_av_sync_stays_under_fifty_ms_over_ten_minutes() {
    let shim = MediaShim::new("C:/GEs/Media");
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
    // Documented contract: A/V drift must stay under 50 ms for a 10-minute clip. The
    // pinned value is the deterministic expected result for this specific 14_400-frame /
    // 14_399-block input (computed once from a known-good run, not re-derived here).
    assert_eq!(drift, GOLDEN_AV_DRIFT_MS, "AV drift regression");
    assert!(drift < 50, "AV drift {drift} ms violates the 50 ms contract");
}

#[test]
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

    let rogue_path = std::env::temp_dir()
        .join("casa1-rogue")
        .join("codec.dylib");
    let untrusted = shim
        .decode_golden_clip(&GoldenClip {
            id: "bad-decoder".to_string(),
            decoder_path: rogue_path.to_string_lossy().to_string(),
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
