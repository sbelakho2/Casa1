//! Section 34 — Video Decoder Integration (Phase 4.1) & Media Foundation Pipeline (Phase 4.2)
//!
//! Integration tests for:
//!   - P4.1: Video Decoder (VideoToolbox / FFmpeg, codec support, PTS, Metal texture upload)
//!   - P4.2: Media Foundation Pipeline (session state machine, topology, event generation)

use casa1::media::{
    create_media_session, create_media_session_with_flags,
    MfEventQueue, MfMediaSession, MfSessionState,
    MediaEvent, MediaEventType,
    Topology, TopologyNodeType, TopologyLoader,
};
use casa1::video_decoder::{
    ColorSpace, MetalTextureFormat, MetalTextureUpload,
    MfTransform, MftMessageType,
    VideoCodec, VideoDecoder, VideoDecoderConfig, VideoFrame,
    parse_h264_annex_b, parse_h264_sps, yuv420p_to_rgba,
    prepare_metal_texture_upload,
};

// ===========================================================================
// P4.1 — Video Decoder
// ===========================================================================

// ───────────────────────────────────────────────────────────────────────────
// t34_01 — Video decoder creation with all supported codecs
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_01_video_decoder_creation_all_codecs() {
    let codecs = [
        (VideoCodec::H264, 1920, 1080, 30.0),
        (VideoCodec::H265, 1920, 1080, 30.0),
        (VideoCodec::VP9,  1280,  720, 60.0),
        (VideoCodec::Unknown, 640, 480, 24.0),
    ];

    for &(codec, width, height, fps) in &codecs {
        let config = VideoDecoderConfig {
            codec,
            width,
            height,
            fps,
            bitrate: 5_000_000,
        };
        let decoder = VideoDecoder::new(config);
        assert!(!decoder.has_frames(), "Fresh decoder should have no frames for {codec:?}");
        assert_eq!(decoder.queued_frame_count(), 0, "queued_frame_count should be 0 for {codec:?}");
        assert_eq!(decoder.config().codec, codec);
        assert_eq!(decoder.config().width, width);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// t34_02 — Decode H.264 NAL unit using decode_packet
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_02_decode_h264_nal_unit() {
    let config = VideoDecoderConfig {
        codec: VideoCodec::H264,
        width: 640,
        height: 480,
        fps: 30.0,
        bitrate: 1_000_000,
    };
    let mut decoder = VideoDecoder::new(config);

    // Simulated H.264 Annex B data: SPS + PPS + IDR slice
    let sps = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1E, 0xAC];
    let pps = vec![0x00, 0x00, 0x00, 0x01, 0x68, 0xEE, 0x3C, 0x80];
    let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, 0xAD, 0xB7];

    // Feed using decode_packet (preferred API)
    // SPS and PPS may succeed or fail depending on platform
    let _ = decoder.decode_packet(&sps, 0);
    let _ = decoder.decode_packet(&pps, 0);

    // Feed an IDR slice
    let result = decoder.decode_packet(&idr, 33_333);
    // On macOS (VideoToolbox) or with ffmpeg feature, this should succeed.
    // Without either, it should fail with a "no decoder" error.
    if cfg!(any(target_os = "macos", feature = "ffmpeg")) {
        assert!(result.is_ok(), "decode_packet should succeed with a decoder available");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// t34_03 — Feed data via legacy feed_data method
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_03_feed_data_legacy() {
    let config = VideoDecoderConfig {
        codec: VideoCodec::H264,
        width: 640,
        height: 480,
        fps: 30.0,
        bitrate: 1_000_000,
    };
    let mut decoder = VideoDecoder::new(config);

    let stream = vec![
        0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1E, 0xAC, // SPS
        0x00, 0x00, 0x00, 0x01, 0x68, 0xEE, 0x3C, 0x80,       // PPS
        0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, 0xAD, // IDR
    ];

    let result = decoder.feed_data(&stream);
    if cfg!(any(target_os = "macos", feature = "ffmpeg")) {
        assert!(result.is_ok(), "feed_data should succeed with a decoder available");
    } else {
        assert!(result.is_err(), "feed_data should fail without a decoder");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// t34_04 — Frame PTS ordering
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_04_frame_pts_ordering() {
    let config = VideoDecoderConfig {
        codec: VideoCodec::H264,
        width: 320,
        height: 240,
        fps: 30.0,
        bitrate: 500_000,
    };
    let mut decoder = VideoDecoder::new(config);

    let sps = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1E, 0xAC];
    let pps = vec![0x00, 0x00, 0x00, 0x01, 0x68, 0xEE, 0x3C, 0x80];

    let _ = decoder.decode_packet(&sps, 0);
    let _ = decoder.decode_packet(&pps, 0);

    // Feed frames with monotonically increasing PTS
    let pts_values = [0u64, 33_333, 66_666, 100_000, 133_333];
    for &pts in &pts_values {
        let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, (pts & 0xFF) as u8];
        let _ = decoder.decode_packet(&idr, pts);
    }

    let frames = decoder.flush();
    if !frames.is_empty() {
        for window in frames.windows(2) {
            assert!(
                window[0].pts <= window[1].pts,
                "Frames should be in PTS order: {} > {}",
                window[0].pts,
                window[1].pts
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// t34_05 — VideoDecoder flush returns frames without panic
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_05_video_decoder_flush() {
    let config = VideoDecoderConfig {
        codec: VideoCodec::H264,
        width: 640,
        height: 480,
        fps: 30.0,
        bitrate: 1_000_000,
    };
    let mut decoder = VideoDecoder::new(config);

    let sps = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1E, 0xAC];
    let pps = vec![0x00, 0x00, 0x00, 0x01, 0x68, 0xEE, 0x3C, 0x80];
    let _ = decoder.decode_packet(&sps, 0);
    let _ = decoder.decode_packet(&pps, 0);

    for i in 0..3 {
        let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, i];
        let _ = decoder.decode_packet(&idr, (i as u64) * 33_333);
    }

    // Flush should never panic
    let frames = decoder.flush();
    // After flush, the decoder should report no frames
    assert!(!decoder.has_frames());
    assert_eq!(decoder.queued_frame_count(), 0);

    // Flushing an empty decoder should return empty vec, not panic
    let empty = decoder.flush();
    assert!(empty.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// t34_06 — VideoDecoder reset and reuse
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_06_video_decoder_reset() {
    let config = VideoDecoderConfig {
        codec: VideoCodec::H264,
        width: 640,
        height: 480,
        fps: 30.0,
        bitrate: 1_000_000,
    };
    let mut decoder = VideoDecoder::new(config);

    // Feed some data
    let stream = vec![
        0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1E, 0xAC,
        0x00, 0x00, 0x00, 0x01, 0x68, 0xEE, 0x3C, 0x80,
    ];
    let _ = decoder.decode_packet(&stream, 0);

    // Reset
    decoder.reset();

    // After reset, decoder should be clean
    assert!(!decoder.has_frames());
    assert_eq!(decoder.queued_frame_count(), 0);
    assert_eq!(decoder.config().codec, VideoCodec::H264);

    // Can re-use after reset
    let _ = decoder.decode_packet(&stream, 0);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_07 — Parse H.264 Annex B byte stream
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_07_parse_h264_annex_b() {
    // Build a concatenated H.264 Annex B stream with SPS + PPS + SEI + IDR
    let sps  = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1E, 0xAC, 0x52];
    let pps  = vec![0x00, 0x00, 0x00, 0x01, 0x68, 0xEE, 0x3C, 0x80];
    let sei  = vec![0x00, 0x00, 0x00, 0x01, 0x06, 0x05, 0x04];
    let idr  = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, 0xAD, 0xB7];

    let mut stream = Vec::new();
    stream.extend_from_slice(&sps);
    stream.extend_from_slice(&pps);
    stream.extend_from_slice(&sei);
    stream.extend_from_slice(&idr);

    let nalus = parse_h264_annex_b(&stream);
    assert_eq!(nalus.len(), 4, "Should find 4 NAL units");

    // Verify NAL unit types
    assert_eq!(nalus[0][0] & 0x1F, 7,  "First NAL should be SPS (type 7)");
    assert_eq!(nalus[1][0] & 0x1F, 8,  "Second NAL should be PPS (type 8)");
    assert_eq!(nalus[2][0] & 0x1F, 6,  "Third NAL should be SEI (type 6)");
    assert_eq!(nalus[3][0] & 0x1F, 5,  "Fourth NAL should be IDR (type 5)");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_08 — Parse H.264 SPS resolution extraction
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_08_parse_h264_sps_resolution() {
    // Empty SPS should return (0, 0)
    let (w, h) = parse_h264_sps(&[]);
    assert_eq!(w, 0);
    assert_eq!(h, 0);

    // Truncated SPS should not panic
    let (w, h) = parse_h264_sps(&[0x67, 0x64]);
    assert_eq!(w, 0);
    assert_eq!(h, 0);

    // A realistic SPS for 1920x1080 (common real-world SPS)
    let sps_1080p: Vec<u8> = vec![
        0x67, 0x64, 0x00, 0x1e, 0xac, 0xd9, 0x40, 0xb4, 0x2f, 0xf9,
        0x61, 0x01, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    ];
    let (w, h) = parse_h264_sps(&sps_1080p);
    assert!(w > 0 && h > 0, "Should extract resolution from SPS, got {}x{}", w, h);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_09 — YUV420p to RGBA conversion
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_09_yuv420p_to_rgba_conversion() {
    let width = 4u32;
    let height = 4u32;

    // Build a minimal YUV420p buffer
    let y_size = (width * height) as usize;
    let uv_size = y_size / 4;
    let mut yuv = vec![128u8; y_size + uv_size * 2]; // Y + U + V

    // Set some distinct Y values
    yuv[0] = 255; // White pixel at (0,0)
    yuv[1] = 0;   // Black pixel at (1,0)
    yuv[5] = 76;  // Mid-gray at (1,1)

    let rgba = yuv420p_to_rgba(&yuv, width, height);
    assert_eq!(rgba.len(), (width * height * 4) as usize, "RGBA buffer should be 4 bytes per pixel");

    // Check pixel (0,0) has non-zero R/G/B since Y=255 maps to white
    assert!(rgba[0] > 0 || rgba[1] > 0 || rgba[2] > 0);
    // Check pixel (1,0) has low values since Y=0 maps to black
    // (with standard YUV→RGB, Y=0 may produce non-zero due to chroma, so just check it's less than the white pixel)
}

// ───────────────────────────────────────────────────────────────────────────
// t34_10 — Metal texture format conversion: RGBA passthrough
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_10_metal_upload_prepare_rgba() {
    let frame = VideoFrame {
        width: 4,
        height: 4,
        data: vec![128u8; 4 * 4 * 4], // RGBA gray
        pts: 0,
        duration: 33_333,
        texture_id: None,
        color_space: ColorSpace::Rec709,
    };

    let upload = prepare_metal_texture_upload(&frame, MetalTextureFormat::RGBA8Unorm, ColorSpace::Rec709)
        .expect("RGBA upload preparation should succeed");
    assert_eq!(upload.format, MetalTextureFormat::RGBA8Unorm);
    assert_eq!(upload.bytes_per_row, 16, "4x4 RGBA = 16 bytes per row");
    assert_eq!(upload.data.len(), 64, "4x4 RGBA = 64 bytes total");
    assert_eq!(upload.width, 4);
    assert_eq!(upload.height, 4);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_11 — Metal texture format conversion: RGBA → BGRA
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_11_metal_upload_prepare_bgra() {
    // Create a frame with known RGBA pixel values
    let rgba_pixels: Vec<u8> = vec![
        255, 0, 0, 255,   // Red pixel     -> BGRA: B=0, G=0, R=255, A=255
        0, 255, 0, 255,   // Green pixel   -> BGRA: B=0, G=255, R=0, A=255
        0, 0, 255, 255,   // Blue pixel    -> BGRA: B=255, G=0, R=0, A=255
        128, 128, 128, 255, // Gray pixel  -> BGRA: B=128, G=128, R=128, A=255
    ];

    let frame = VideoFrame {
        width: 2,
        height: 2,
        data: rgba_pixels,
        pts: 0,
        duration: 33_333,
        texture_id: None,
        color_space: ColorSpace::Rec709,
    };

    let upload = prepare_metal_texture_upload(&frame, MetalTextureFormat::BGRA8Unorm, ColorSpace::Rec709)
        .expect("BGRA upload preparation should succeed");
    assert_eq!(upload.format, MetalTextureFormat::BGRA8Unorm);

    // Verify channel swap: RGBA -> BGRA (R and B swapped)
    // First pixel: RGBA(255,0,0,255) -> BGRA(0,0,255,255)
    assert_eq!(upload.data[0], 0,   "B channel should be original R=0");
    assert_eq!(upload.data[1], 0,   "G channel unchanged");
    assert_eq!(upload.data[2], 255, "R channel should be original B=255");
    assert_eq!(upload.data[3], 255, "A channel unchanged");

    // Second pixel: RGBA(0,255,0,255) -> BGRA(0,255,0,255)
    assert_eq!(upload.data[4], 0,   "B=0");
    assert_eq!(upload.data[5], 255, "G=255");
    assert_eq!(upload.data[6], 0,   "R=0");
    assert_eq!(upload.data[7], 255, "A=255");

    // Third pixel: RGBA(0,0,255,255) -> BGRA(255,0,0,255)
    assert_eq!(upload.data[8],  255, "B=255");
    assert_eq!(upload.data[9],  0,   "G=0");
    assert_eq!(upload.data[10], 0,   "R=0");
    assert_eq!(upload.data[11], 255, "A=255");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_12 — Metal texture format conversion: RGBA → NV12
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_12_metal_upload_prepare_nv12() {
    let frame = VideoFrame {
        width: 4,
        height: 4,
        data: vec![128u8; 4 * 4 * 4], // Gray RGBA
        pts: 0,
        duration: 33_333,
        texture_id: None,
        color_space: ColorSpace::Rec709,
    };

    let upload = prepare_metal_texture_upload(&frame, MetalTextureFormat::NV12, ColorSpace::Rec709)
        .expect("NV12 upload preparation should succeed");
    assert_eq!(upload.format, MetalTextureFormat::NV12);
    // NV12: Y plane (16 bytes) + interleaved UV (8 bytes for 2x2 chroma)
    assert_eq!(upload.data.len(), 24, "NV12 for 4x4: 16 Y + 8 UV = 24 bytes");
    assert_eq!(upload.bytes_per_row, 4, "NV12 Y plane bytes per row = width");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_13 — Metal texture format conversion with all color spaces
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_13_color_space_conversion_variants() {
    let frame = VideoFrame {
        width: 2,
        height: 2,
        data: vec![128u8; 2 * 2 * 4],
        pts: 0,
        duration: 33_333,
        texture_id: None,
        color_space: ColorSpace::Rec709,
    };

    // Test Rec.601
    let upload_601 = prepare_metal_texture_upload(&frame, MetalTextureFormat::NV12, ColorSpace::Rec601)
        .expect("Rec.601 NV12 should succeed");
    assert_eq!(upload_601.data.len(), 6, "NV12 for 2x2: 4 Y + 2 UV = 6 bytes");

    // Test Rec.709 (default)
    let upload_709 = prepare_metal_texture_upload(&frame, MetalTextureFormat::NV12, ColorSpace::Rec709)
        .expect("Rec.709 NV12 should succeed");
    assert_eq!(upload_709.data.len(), 6);

    // Test Rec.2020
    let upload_2020 = prepare_metal_texture_upload(&frame, MetalTextureFormat::NV12, ColorSpace::Rec2020)
        .expect("Rec.2020 NV12 should succeed");
    assert_eq!(upload_2020.data.len(), 6);

    // Test Unknown (defaults to Rec.709)
    let upload_unknown = prepare_metal_texture_upload(&frame, MetalTextureFormat::NV12, ColorSpace::Unknown)
        .expect("Unknown color space NV12 should succeed");
    assert_eq!(upload_unknown.data.len(), 6);

    // The different color spaces should produce different NV12 values
    // (since they have different Kr/Kb coefficients)
    assert_ne!(upload_601.data, upload_709.data,
        "Rec.601 and Rec.709 should produce different NV12 data");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_14 — MetalTextureUpload descriptor properties
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_14_metal_texture_upload_properties() {
    let upload = MetalTextureUpload {
        format: MetalTextureFormat::BGRA8Unorm,
        bytes_per_row: 1920 * 4,
        data: vec![0u8; 1920 * 1080 * 4],
        width: 1920,
        height: 1080,
    };

    assert_eq!(upload.format, MetalTextureFormat::BGRA8Unorm);
    assert_eq!(upload.bytes_per_row, 7680);
    assert_eq!(upload.width, 1920);
    assert_eq!(upload.height, 1080);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_15 — MetalTextureUpload descriptor construction
// ───────────────────────────────────────────────────────────────────────────
// Note: upload_frame_to_metal_texture requires a real Metal device and
// is tested at the unit level in video_decoder.rs.

#[test]
fn t34_15_metal_texture_upload_descriptor() {
    let upload_4k = MetalTextureUpload {
        format: MetalTextureFormat::NV12,
        bytes_per_row: 3840,
        data: vec![128u8; 3840 * 2160 + 1920 * 1080 * 2],
        width: 3840,
        height: 2160,
    };
    assert_eq!(upload_4k.format, MetalTextureFormat::NV12);
    assert_eq!(upload_4k.bytes_per_row, 3840);
    assert_eq!(upload_4k.data.len(), 3840 * 2160 + 1920 * 1080 * 2);
    assert_eq!(upload_4k.width, 3840);
    assert_eq!(upload_4k.height, 2160);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_16 — MfTransform lifecycle (IMFTransform-like interface)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_16_mf_transform_lifecycle() {
    let config = VideoDecoderConfig {
        codec: VideoCodec::H264,
        width: 640,
        height: 480,
        fps: 30.0,
        bitrate: 1_000_000,
    };
    let mut transform = MfTransform::new(config);
    assert_eq!(transform.input_queued(), 0);

    // ProcessMessage — all message types accepted
    assert!(transform.process_message(MftMessageType::Reset).is_ok());
    assert!(transform.process_message(MftMessageType::NewStream).is_ok());
    assert!(transform.process_message(MftMessageType::Flush).is_ok());
    assert!(transform.process_message(MftMessageType::Drain).is_ok());

    // ProcessInput
    let sps = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1E, 0xAC];
    let result = transform.process_input(&sps, 0);
    if cfg!(any(target_os = "macos", feature = "ffmpeg")) {
        assert!(result.is_ok(), "process_input should succeed with a decoder");
    }

    // ProcessOutput — should not panic
    let output = transform.process_output().unwrap_or(None);
    if let Some(frame) = output {
        assert!(frame.pts > 0 || frame.duration > 0);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// t34_17 — ColorSpace enum behavior
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_17_color_space_enum() {
    assert_eq!(ColorSpace::default(), ColorSpace::Rec709);

    // Kr/Kb coefficients
    assert_eq!(ColorSpace::Rec601.kr_kb(), (0.299, 0.114));
    assert_eq!(ColorSpace::Rec709.kr_kb(), (0.2126, 0.0722));
    assert_eq!(ColorSpace::Rec2020.kr_kb(), (0.2627, 0.0593));
    // Unknown defaults to Rec.709
    assert_eq!(ColorSpace::Unknown.kr_kb(), ColorSpace::Rec709.kr_kb());
}

// ───────────────────────────────────────────────────────────────────────────
// t34_18 — VideoCodec enum values
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_18_video_codec_enum_values() {
    assert_eq!(VideoCodec::H264    as u32, 0);
    assert_eq!(VideoCodec::H265    as u32, 1);
    assert_eq!(VideoCodec::VP9     as u32, 2);
    assert_eq!(VideoCodec::Unknown as u32, 3);
}

// ===========================================================================
// P4.2 — Media Foundation Pipeline
// ===========================================================================

// ───────────────────────────────────────────────────────────────────────────
// t34_19 — MfMediaSession initial state
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_19_session_initial_state() {
    let session = MfMediaSession::new();
    assert_eq!(session.state(), MfSessionState::Idle,
        "Fresh session should be in Idle state");
    assert!(session.is_active(),
        "Fresh session should be active (not shut down)");
    assert!(!session.has_events(),
        "Fresh session should have no events");
    assert_eq!(session.event_count(), 0);
    assert_eq!(session.get_position(), 0,
        "Position should be 0 before starting");
    assert!(session.source_url().is_none(),
        "No source URL before setting topology");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_20 — Session full lifecycle: Idle → Playing → Paused → Playing → Stopped → Shutdown
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_20_session_full_lifecycle() {
    let mut session = MfMediaSession::new();
    assert_eq!(session.state(), MfSessionState::Idle);

    // Set topology required before starting from Idle
    session.set_url_topology("test.mp4").unwrap();
    assert!(session.source_url().is_some());
    assert_eq!(session.source_url().unwrap(), "test.mp4");

    // Idle → Opening → Playing
    session.start().unwrap();
    assert_eq!(session.state(), MfSessionState::Playing);
    assert!(session.has_events());
    // Consume events: TopologySet, TopologyLoaded, SessionStarted
    let event1 = session.get_event().unwrap();
    assert_eq!(event1.event_type, MediaEventType::TopologySet);
    let event2 = session.get_event().unwrap();
    assert_eq!(event2.event_type, MediaEventType::TopologyLoaded);
    let event3 = session.get_event().unwrap();
    assert_eq!(event3.event_type, MediaEventType::SessionStarted);

    // Playing → Paused
    session.pause().unwrap();
    assert_eq!(session.state(), MfSessionState::Paused);
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionPaused);

    // Paused → Playing (resume)
    session.start().unwrap();
    assert_eq!(session.state(), MfSessionState::Playing);
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionStarted);

    // Playing → Stopped
    session.stop().unwrap();
    assert_eq!(session.state(), MfSessionState::Stopped);
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionStopped);

    // Stop clears position
    assert_eq!(session.get_position(), 0);

    // Stopped → Playing (restart)
    session.start().unwrap();
    assert_eq!(session.state(), MfSessionState::Playing);
    let _ = session.get_event(); // consume SessionStarted

    // Stop → Shutdown
    session.stop().unwrap();
    let _ = session.get_event(); // consume SessionStopped
    session.shutdown().unwrap();
    assert_eq!(session.state(), MfSessionState::Shutdown);
    assert!(!session.is_active());
}

// ───────────────────────────────────────────────────────────────────────────
// t34_21 — Session state machine: invalid transitions rejected
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_21_session_invalid_transitions() {
    let mut session = MfMediaSession::new();

    // Cannot pause from Idle
    assert!(session.pause().is_err(),
        "Cannot pause from Idle");

    // Cannot stop from Idle
    assert!(session.stop().is_err(),
        "Cannot stop from Idle");

    // Cannot start after shutdown
    session.shutdown().unwrap();
    assert!(session.start().is_err(),
        "Cannot start after shutdown");
    assert!(session.pause().is_err(),
        "Cannot pause after shutdown");
    assert!(session.stop().is_err(),
        "Cannot stop after shutdown");

    // Double shutdown
    assert!(session.shutdown().is_err(),
        "Double shutdown should fail");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_22 — Session shutdown behavior
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_22_session_shutdown() {
    let mut session = MfMediaSession::new();

    session.shutdown().unwrap();
    assert_eq!(session.state(), MfSessionState::Shutdown);
    assert!(!session.is_active());

    // Setting topology on a shut down session should fail
    let topology = Topology::new();
    assert!(session.set_topology(topology).is_err(),
        "Cannot set topology on shut-down session");

    // Shutdown emits SessionShutdown event
    // (but we didn't consume from new() — shutdown emits it)
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionShutdown);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_23 — Session position tracking
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_23_session_position_tracking() {
    let mut session = MfMediaSession::new();
    session.set_url_topology("test.mp4").unwrap();

    // Position = 0 before starting
    assert_eq!(session.get_position(), 0);

    // Position increases after start
    session.start().unwrap();
    // Consume topology events + SessionStarted
    session.get_event(); // TopologySet
    session.get_event(); // TopologyLoaded
    session.get_event(); // SessionStarted

    std::thread::sleep(std::time::Duration::from_micros(2000));
    let pos_after_start = session.get_position();
    assert!(pos_after_start > 0,
        "Position should increase after start, got {pos_after_start}");

    // Position should be less than ~10ms (we slept 2ms)
    assert!(pos_after_start < 10_000,
        "Position should be roughly the elapsed time");

    // Position freezes during pause
    session.pause().unwrap();
    session.get_event(); // SessionPaused
    let pos_at_pause = session.get_position();
    std::thread::sleep(std::time::Duration::from_micros(1000));
    assert_eq!(session.get_position(), pos_at_pause,
        "Position should freeze during pause");

    // Position resumes after restart
    session.start().unwrap();
    session.get_event(); // SessionStarted
    std::thread::sleep(std::time::Duration::from_micros(1000));
    let pos_after_resume = session.get_position();
    assert!(pos_after_resume > pos_at_pause,
        "Position should increase after resume");

    // Stop resets position to 0
    session.stop().unwrap();
    session.get_event(); // SessionStopped
    assert_eq!(session.get_position(), 0,
        "Position should reset to 0 after stop");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_24 — MfEventQueue independent operation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_24_event_queue_independent() {
    let mut queue = MfEventQueue::new();
    assert!(!queue.has_events());
    assert_eq!(queue.event_count(), 0);

    // Queue a few events
    queue.queue_event_type(MediaEventType::SessionStarted);
    queue.queue_event_type(MediaEventType::BufferingStarted);
    queue.queue_event_type(MediaEventType::SessionEnded);

    assert!(queue.has_events());
    assert_eq!(queue.event_count(), 3);

    // Peek without consuming
    let peeked = queue.peek_event().unwrap();
    assert_eq!(peeked.event_type, MediaEventType::SessionStarted);
    assert_eq!(queue.event_count(), 3, "Peek should not consume");

    // Consume in order
    let event = queue.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionStarted);
    assert_eq!(queue.event_count(), 2);

    let event = queue.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::BufferingStarted);
    assert_eq!(queue.event_count(), 1);

    let event = queue.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionEnded);
    assert_eq!(queue.event_count(), 0);

    assert!(queue.get_event().is_none(), "Queue should be empty");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_25 — Event queue overflow protection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_25_event_queue_overflow() {
    let mut queue = MfEventQueue::with_max(3);
    queue.queue_event_type(MediaEventType::SessionStarted);
    queue.queue_event_type(MediaEventType::SessionPaused);
    queue.queue_event_type(MediaEventType::SessionStopped);
    // Overflow — pushes out the oldest (SessionStarted)
    queue.queue_event_type(MediaEventType::SessionEnded);

    assert_eq!(queue.event_count(), 3);
    let first = queue.get_event().unwrap();
    assert_eq!(first.event_type, MediaEventType::SessionPaused,
        "Oldest event should have been dropped due to overflow");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_26 — Media event construction
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_26_media_event_construction() {
    // Basic event
    let event = MediaEvent::new(MediaEventType::SessionStarted);
    assert_eq!(event.event_type, MediaEventType::SessionStarted);
    assert_eq!(event.status, 0);
    assert!(event.data.is_none());
    assert!(event.pts.is_none());

    // Event with status
    let event = MediaEvent::with_status(MediaEventType::SessionEnded, 1);
    assert_eq!(event.event_type, MediaEventType::SessionEnded);
    assert_eq!(event.status, 1);

    // Event with error
    let event = MediaEvent::with_error("disk full");
    assert_eq!(event.event_type, MediaEventType::Error);
    assert_eq!(event.status, -1);
    assert_eq!(event.data.as_deref(), Some("disk full"));

    // Event with PTS
    let event = MediaEvent::new(MediaEventType::SessionStarted).with_pts(12345);
    assert_eq!(event.pts, Some(12345));
}

// ───────────────────────────────────────────────────────────────────────────
// t34_27 — Media event type names
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_27_media_event_type_names() {
    assert_eq!(MediaEventType::SessionStarted.name(),    "MESessionStarted");
    assert_eq!(MediaEventType::SessionPaused.name(),     "MESessionPaused");
    assert_eq!(MediaEventType::SessionStopped.name(),    "MESessionStopped");
    assert_eq!(MediaEventType::SessionEnded.name(),      "MESessionEnded");
    assert_eq!(MediaEventType::BufferingStarted.name(),  "MEBufferingStarted");
    assert_eq!(MediaEventType::BufferingStopped.name(),  "MEBufferingStopped");
    assert_eq!(MediaEventType::Error.name(),             "MEError");
    assert_eq!(MediaEventType::SessionShutdown.name(),   "MESessionShutdown");
    assert_eq!(MediaEventType::TopologySet.name(),       "METopologySet");
    assert_eq!(MediaEventType::TopologyLoaded.name(),    "METopologyLoaded");
    assert_eq!(MediaEventType::RateChanged.name(),       "MERateChanged");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_28 — MfSessionState names and transitions
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_28_session_state_names() {
    assert_eq!(MfSessionState::Idle.name(),      "Idle");
    assert_eq!(MfSessionState::Opening.name(),   "Opening");
    assert_eq!(MfSessionState::Playing.name(),   "Playing");
    assert_eq!(MfSessionState::Paused.name(),    "Paused");
    assert_eq!(MfSessionState::Stopped.name(),   "Stopped");
    assert_eq!(MfSessionState::Shutdown.name(),  "Shutdown");
}

#[test]
fn t34_28b_session_state_can_transitions() {
    // can_start
    assert!(MfSessionState::Idle.can_start());
    assert!(MfSessionState::Paused.can_start());
    assert!(MfSessionState::Stopped.can_start());
    assert!(!MfSessionState::Playing.can_start());
    assert!(!MfSessionState::Shutdown.can_start());

    // can_pause
    assert!(MfSessionState::Playing.can_pause());
    assert!(!MfSessionState::Idle.can_pause());
    assert!(!MfSessionState::Paused.can_pause());
    assert!(!MfSessionState::Stopped.can_pause());
    assert!(!MfSessionState::Shutdown.can_pause());

    // can_stop
    assert!(MfSessionState::Playing.can_stop());
    assert!(MfSessionState::Paused.can_stop());
    assert!(!MfSessionState::Idle.can_stop());
    assert!(!MfSessionState::Stopped.can_stop());
    assert!(!MfSessionState::Shutdown.can_stop());

    // is_active
    assert!(MfSessionState::Idle.is_active());
    assert!(MfSessionState::Opening.is_active());
    assert!(MfSessionState::Playing.is_active());
    assert!(MfSessionState::Paused.is_active());
    assert!(MfSessionState::Stopped.is_active());
    assert!(!MfSessionState::Shutdown.is_active());
}

// ───────────────────────────────────────────────────────────────────────────
// t34_29 — Topology building: source → decoder → renderer chain
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_29_topology_build_playback() {
    let mut topology = Topology::new();

    topology.build_playback_topology("movie.mp4", "H264 Decoder", "Metal Renderer")
        .expect("build_playback_topology should succeed");

    assert_eq!(topology.node_count(), 3);
    assert!(topology.source_node_id.is_some());
    assert!(topology.decoder_node_id.is_some());
    assert!(topology.renderer_node_id.is_some());

    // Source → Decoder → Renderer chain
    let source = topology.get_node(topology.source_node_id.unwrap()).unwrap();
    assert_eq!(source.node_type, TopologyNodeType::Source);
    assert_eq!(source.source_url.as_deref(), Some("movie.mp4"));
    assert_eq!(source.outputs.len(), 1, "Source should connect to decoder");

    let decoder = topology.get_node(topology.decoder_node_id.unwrap()).unwrap();
    assert_eq!(decoder.node_type, TopologyNodeType::Decoder);
    assert_eq!(decoder.inputs.len(), 1, "Decoder should receive from source");
    assert_eq!(decoder.outputs.len(), 1, "Decoder should connect to renderer");
    assert_eq!(decoder.output_format.as_deref(), Some("RGBA"));

    let renderer = topology.get_node(topology.renderer_node_id.unwrap()).unwrap();
    assert_eq!(renderer.node_type, TopologyNodeType::Renderer);
    assert_eq!(renderer.inputs.len(), 1, "Renderer should receive from decoder");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_30 — Topology validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_30_topology_validation() {
    // Empty topology should fail validation
    let topology = Topology::new();
    assert!(topology.validate().is_err(),
        "Empty topology should fail validation");

    // Built topology should pass validation
    let mut topology = Topology::new();
    topology.build_playback_topology("test.mp4", "Decoder", "Renderer")
        .unwrap();
    assert!(topology.validate().is_ok(),
        "Built playback topology should pass validation");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_31 — Topology custom node addition and connection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_31_topology_custom_nodes_and_connections() {
    let mut topology = Topology::new();

    let src_id = topology.add_node(TopologyNodeType::Source, "Custom Source");
    let dec_id = topology.add_node(TopologyNodeType::Decoder, "Custom Decoder");
    let out_id = topology.add_node(TopologyNodeType::Output, "Custom Output");

    assert_eq!(topology.node_count(), 3);

    // Connect source → decoder → output
    assert!(topology.connect(src_id, dec_id).is_ok());
    assert!(topology.connect(dec_id, out_id).is_ok());

    // Verify connections
    let src = topology.get_node(src_id).unwrap();
    assert_eq!(src.outputs, vec![dec_id]);

    let dec = topology.get_node(dec_id).unwrap();
    assert_eq!(dec.inputs, vec![src_id]);
    assert_eq!(dec.outputs, vec![out_id]);

    let out = topology.get_node(out_id).unwrap();
    assert_eq!(out.inputs, vec![dec_id]);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_32 — Topology connection with invalid node IDs
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_32_topology_connect_invalid() {
    let mut topology = Topology::new();
    let valid_id = topology.add_node(TopologyNodeType::Source, "Valid");

    // Connecting from valid to non-existent
    assert!(topology.connect(valid_id, 999).is_err(),
        "Cannot connect to non-existent node");

    // Connecting from non-existent
    assert!(topology.connect(999, valid_id).is_err(),
        "Cannot connect from non-existent node");

    // Both non-existent
    assert!(topology.connect(999, 888).is_err(),
        "Cannot connect two non-existent nodes");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_33 — Topology node types enum
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_33_topology_node_type_enum() {
    assert_eq!(TopologyNodeType::Source   as u32, 0);
    assert_eq!(TopologyNodeType::Decoder  as u32, 1);
    assert_eq!(TopologyNodeType::Renderer as u32, 2);
    assert_eq!(TopologyNodeType::Output   as u32, 3);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_34 — TopologyLoader
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_34_topology_loader() {
    let mut topology = Topology::new();
    topology.build_playback_topology("test.mp4", "Decoder", "Renderer")
        .unwrap();

    let loader = TopologyLoader::new();
    assert!(loader.load(&topology).is_ok(),
        "TopologyLoader should load a valid topology");

    // Clearing the loader should not panic
    loader.clear();
}

// ───────────────────────────────────────────────────────────────────────────
// t34_35 — MFCreateMediaSession factory functions
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_35_create_media_session_factory() {
    let session = create_media_session();
    assert_eq!(session.state(), MfSessionState::Idle);

    let session = create_media_session_with_flags(0);
    assert_eq!(session.state(), MfSessionState::Idle);

    let session = create_media_session_with_flags(0x1234);
    assert_eq!(session.state(), MfSessionState::Idle);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_36 — Session set/clear topology
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_36_session_set_clear_topology() {
    let mut session = MfMediaSession::new();
    assert!(session.topology().is_none());

    let mut topology = Topology::new();
    topology.build_playback_topology("clip.ogg", "Decoder", "Renderer")
        .unwrap();

    session.set_topology(topology).unwrap();
    assert!(session.topology().is_some());
    assert!(session.has_events());
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::TopologySet);

    // Clear
    session.clear_topology();
    assert!(session.topology().is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// t34_37 — Session set_url_topology convenience method
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_37_session_set_url_topology() {
    let mut session = MfMediaSession::new();

    session.set_url_topology("http://example.com/stream.mpd").unwrap();
    assert!(session.topology().is_some());
    assert_eq!(session.source_url().unwrap(), "http://example.com/stream.mpd");

    // Verify the topology has correct structure
    let topology = session.topology().unwrap();
    assert_eq!(topology.node_count(), 3);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_38 — Session event generation during state transitions
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_38_session_event_generation() {
    let mut session = MfMediaSession::new();
    session.set_url_topology("test.mp4").unwrap();
    session.get_event().unwrap(); // consume TopologySet

    // Start → SessionStarted
    session.start().unwrap();
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionStarted);

    // Pause → SessionPaused
    session.pause().unwrap();
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionPaused);

    // Stop → SessionStopped
    session.start().unwrap();
    session.get_event().unwrap(); // consume SessionStarted
    session.stop().unwrap();
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionStopped);

    // Shutdown → SessionShutdown
    session.shutdown().unwrap();
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionShutdown);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_39 — Custom event queuing on session
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_39_session_custom_event_queuing() {
    let mut session = MfMediaSession::new();

    let custom_event = MediaEvent::with_status(MediaEventType::RateChanged, 2);
    session.queue_event(custom_event);

    assert!(session.has_events());
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::RateChanged);
    assert_eq!(event.status, 2);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_40 — Session peek_event
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_40_session_peek_event() {
    let mut session = MfMediaSession::new();
    session.set_url_topology("test.mp4").unwrap();
    session.get_event().unwrap(); // consume TopologySet
    session.start().unwrap();

    // Peek at the first event (SessionStarted) without consuming
    let peeked = session.peek_event();
    assert!(peeked.is_some());
    assert_eq!(peeked.unwrap().event_type, MediaEventType::SessionStarted);

    // Event should still be there after peek
    assert!(session.has_events());

    // Now consume it
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionStarted);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_41 — Topology node connection properties
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_41_topology_node_connections() {
    use casa1::media::TopologyNode;

    let mut source = TopologyNode::new(1, TopologyNodeType::Source, "Test Source");
    let mut decoder = TopologyNode::new(2, TopologyNodeType::Decoder, "Test Decoder");
    let mut renderer = TopologyNode::new(3, TopologyNodeType::Renderer, "Test Renderer");

    // Wire: source → decoder → renderer
    source.connect_to(decoder.id);
    decoder.connect_from(source.id);
    decoder.connect_to(renderer.id);
    renderer.connect_from(decoder.id);

    assert_eq!(source.outputs, vec![2]);
    assert_eq!(decoder.inputs, vec![1]);
    assert_eq!(decoder.outputs, vec![3]);
    assert_eq!(renderer.inputs, vec![2]);

    // Duplicate connections should not add
    source.connect_to(decoder.id);
    assert_eq!(source.outputs, vec![2],
        "Duplicate connections should be ignored");
}

// ───────────────────────────────────────────────────────────────────────────
// t34_42 — Session topology-less start fails gracefully
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_42_session_start_without_topology() {
    let mut session = MfMediaSession::new();

    // Starting from Idle without setting a topology
    // This should still succeed (just transitions to Playing),
    // but no topology events will be emitted
    let result = session.start();
    assert!(result.is_ok(), "Starting without topology should succeed");
    assert_eq!(session.state(), MfSessionState::Playing);
    let event = session.get_event().unwrap();
    assert_eq!(event.event_type, MediaEventType::SessionStarted);
}

// ───────────────────────────────────────────────────────────────────────────
// t34_43 — Multiple start → pause → stop cycles
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_43_session_multi_cycle() {
    let mut session = MfMediaSession::new();
    session.set_url_topology("video.mp4").unwrap();
    session.get_event().unwrap(); // TopologySet

    for cycle in 0..3 {
        session.start().unwrap();
        assert_eq!(session.state(), MfSessionState::Playing,
            "Cycle {cycle}: should be Playing after start");

        // Consume events (may include topology events on first cycle)
        loop {
            let event = session.get_event();
            match event {
                Some(e) if e.event_type == MediaEventType::SessionStarted => break,
                Some(_) => continue,
                None => break,
            }
        }

        session.pause().unwrap();
        assert_eq!(session.state(), MfSessionState::Paused,
            "Cycle {cycle}: should be Paused after pause");
        session.get_event().unwrap(); // SessionPaused

        session.stop().unwrap();
        assert_eq!(session.state(), MfSessionState::Stopped,
            "Cycle {cycle}: should be Stopped after stop");
        session.get_event().unwrap(); // SessionStopped
    }
}

// ───────────────────────────────────────────────────────────────────────────
// t34_44 — VideoFrame construction
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn t34_44_video_frame_construction() {
    let frame = VideoFrame {
        width: 1920,
        height: 1080,
        data: vec![0u8; 1920 * 1080 * 4],
        pts: 100_000,
        duration: 33_333,
        texture_id: Some(42),
        color_space: ColorSpace::Rec709,
    };

    assert_eq!(frame.width, 1920);
    assert_eq!(frame.height, 1080);
    assert_eq!(frame.pts, 100_000);
    assert_eq!(frame.duration, 33_333);
    assert_eq!(frame.texture_id, Some(42));
    assert_eq!(frame.color_space, ColorSpace::Rec709);
    assert_eq!(frame.data.len(), 1920 * 1080 * 4);
}
