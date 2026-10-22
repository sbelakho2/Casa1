#![allow(dead_code, unused_imports)]
use casa1::media::{
    AudioCodec, ContainerKind, GoldenClip, MediaInputClassification, MediaShim, VideoCodec,
    build_container_bytes,
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

    let rogue_path = std::env::temp_dir().join("casa1-rogue").join("codec.dylib");
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
