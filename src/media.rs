//! Media Foundation integration for Casa1.
//!
//! Provides:
//! - Container parsing (MP4, OGG)
//! - Media Foundation session (IMFMediaSession-like)
//! - Topology building (source -> decoder -> renderer)
//! - Event generation (IMFMediaEventGenerator-like)
//! - `MFCreateMediaSession` factory

use crate::audio::crc32_samples;
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ===========================================================================
// Container types (existing)
// ===========================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    Mp4,
    Ogg,
    Wmv,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VideoCodec {
    None,
    H264,
    H265,
    VP9,
    WMV,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AudioCodec {
    Aac,
    Vorbis,
    Mp3,
    Wma,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MediaApiSurface {
    AlternativeShim,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedContainer {
    pub container: ContainerKind,
    pub video_codec: VideoCodec,
    pub audio_codec: AudioCodec,
    pub duration_ms: u32,
    pub frame_count: u32,
    pub audio_block_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoldenClip {
    pub id: String,
    pub decoder_path: String,
    pub container_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecodedClip {
    pub frame_hashes: Vec<String>,
    pub audio_crc32: u32,
    pub parser_surface: MediaApiSurface,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MediaInputClassification {
    Valid,
    Error(ReasonCode),
}

// ===========================================================================
// Media Foundation Session States
// ===========================================================================

/// Media Session states, mirroring IMFMediaSession state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfSessionState {
    /// Initial state after creation.
    Idle,
    /// Opening a media source.
    Opening,
    /// Actively playing.
    Playing,
    /// Playback paused.
    Paused,
    /// Playback stopped (ready to restart).
    Stopped,
    /// Session has been shut down.
    Shutdown,
}

impl MfSessionState {
    /// Check if this state allows playback commands (Start).
    pub fn can_start(&self) -> bool {
        matches!(
            self,
            MfSessionState::Idle | MfSessionState::Paused | MfSessionState::Stopped
        )
    }

    /// Check if this state allows pausing.
    pub fn can_pause(&self) -> bool {
        matches!(self, MfSessionState::Playing)
    }

    /// Check if this state allows stopping.
    pub fn can_stop(&self) -> bool {
        matches!(self, MfSessionState::Playing | MfSessionState::Paused)
    }

    /// Check if the session is still usable (not shut down).
    pub fn is_active(&self) -> bool {
        !matches!(self, MfSessionState::Shutdown)
    }

    /// Get a human-readable name for this state.
    pub fn name(&self) -> &'static str {
        match self {
            MfSessionState::Idle => "Idle",
            MfSessionState::Opening => "Opening",
            MfSessionState::Playing => "Playing",
            MfSessionState::Paused => "Paused",
            MfSessionState::Stopped => "Stopped",
            MfSessionState::Shutdown => "Shutdown",
        }
    }
}

// ===========================================================================
// Media Foundation Event Types
// ===========================================================================

// ===========================================================================
// GUIDs for Media Foundation attributes
// ===========================================================================

/// A simplified GUID (128-bit) for MF attribute keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Create a new GUID.
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Convert to a byte representation (little-endian).
    pub fn to_bytes_le(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.data1.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.data2.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.data3.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.data4);
        bytes
    }

    /// Create from 16 raw bytes (little-endian).
    pub fn from_bytes_le(b: &[u8; 16]) -> Self {
        let data1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let data2 = u16::from_le_bytes([b[4], b[5]]);
        let data3 = u16::from_le_bytes([b[6], b[7]]);
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&b[8..16]);
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }
}

// Standard MF attribute GUIDs
pub const MF_MT_MAJOR_TYPE: Guid = Guid::new(
    0x48e2ed0f,
    0x98c2,
    0x4a37,
    [0xbe, 0xd5, 0x16, 0x63, 0x12, 0xdd, 0xd8, 0x3f],
);
pub const MF_MT_SUBTYPE: Guid = Guid::new(
    0xf7e34e80,
    0x5a6f,
    0x4f8c,
    [0xb2, 0x4e, 0x10, 0xc4, 0x67, 0x6c, 0x6d, 0x1a],
);
pub const MF_MT_FRAME_SIZE: Guid = Guid::new(
    0x1652c33d,
    0xd6b2,
    0x4012,
    [0xb8, 0x34, 0x72, 0x0c, 0xc3, 0xac, 0xd2, 0x6d],
);
pub const MF_MT_FRAME_RATE: Guid = Guid::new(
    0xc459a2e8,
    0x3d2c,
    0x4e44,
    [0xb1, 0x32, 0xfe, 0xe5, 0x5a, 0x5c, 0x4b, 0xfc],
);
pub const MF_MT_SAMPLE_RATE: Guid = Guid::new(
    0x5a7e6c1d,
    0x87d2,
    0x4e7e,
    [0x8b, 0x6f, 0x6c, 0x0e, 0x2a, 0x8c, 0x4c, 0x6f],
);
pub const MF_MT_CHANNELS: Guid = Guid::new(
    0x48e2ed0f,
    0x98c2,
    0x4a37,
    [0xbe, 0xd5, 0x16, 0x63, 0x12, 0xdd, 0xd8, 0x40],
);
pub const MF_MT_AUDIO_BITS_PER_SAMPLE: Guid = Guid::new(
    0xf2deb57f,
    0x40fa,
    0x4764,
    [0xaa, 0x33, 0x99, 0xc5, 0xec, 0x50, 0x0d, 0x97],
);
pub const MF_MT_BITRATE: Guid = Guid::new(
    0x203d3e7e,
    0x5c4a,
    0x4a5b,
    [0x8f, 0x8c, 0x7b, 0x7e, 0x7c, 0x2d, 0x4d, 0x3e],
);
pub const MF_MT_AVG_BITRATE: Guid = Guid::new(
    0x203d3e7e,
    0x5c4a,
    0x4a5b,
    [0x8f, 0x8c, 0x7b, 0x7e, 0x7c, 0x2d, 0x4d, 0x3f],
);
pub const MF_MT_MPEG_SEQUENCE_HEADER: Guid = Guid::new(
    0x3c036de7,
    0x3ad0,
    0x4c2e,
    [0xa8, 0x2c, 0x2c, 0x3a, 0x7e, 0x2c, 0x4d, 0x3e],
);
pub const MF_MT_USER_DATA: Guid = Guid::new(
    0xb6bc765f,
    0x4c3b,
    0x40a4,
    [0xbd, 0x0f, 0x5f, 0x0e, 0x2c, 0x4d, 0x3e, 0x3f],
);
pub const MF_MT_MPEG2_PROFILE: Guid = Guid::new(
    0xad76a80b,
    0x5c4a,
    0x4a5b,
    [0x8f, 0x8c, 0x7b, 0x7e, 0x7c, 0x2d, 0x4d, 0x3e],
);
pub const MF_MT_MPEG2_LEVEL: Guid = Guid::new(
    0x96e5e8e2,
    0x5c4a,
    0x4a5b,
    [0x8f, 0x8c, 0x7b, 0x7e, 0x7c, 0x2d, 0x4d, 0x3e],
);

// Major type GUIDs
pub const MFMediaType_Video: Guid = Guid::new(
    0x73646976,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
);
pub const MFMediaType_Audio: Guid = Guid::new(
    0x73647561,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
);

// Subtype GUIDs (FOURCC-based)

/// MFT_CATEGORY_VIDEO_DECODER {d6c02d4b-6833-45b4-971a-05a4b04bab91}.
pub const MFT_CATEGORY_VIDEO_DECODER: Guid = Guid::new(
    0xd6c02d4b,
    0x6833,
    0x45b4,
    [0x97, 0x1a, 0x05, 0xa4, 0xb0, 0x4b, 0xab, 0x91],
);

/// MFT_TRANSFORM_CLSID_Attribute {7bbee931-7029-4cd5-a4bd-97f377ff87c4}.
pub const MFT_TRANSFORM_CLSID_Attribute: Guid = Guid::new(
    0x7bbee931,
    0x7029,
    0x4cd5,
    [0xa4, 0xbd, 0x97, 0xf3, 0x77, 0xff, 0x87, 0xc4],
);
pub const MFVideoFormat_H264: Guid = Guid::new(
    0x34363248,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
); // 'H264'
pub const MFVideoFormat_H265: Guid = Guid::new(
    0x35363248,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
); // 'H265'
pub const MFVideoFormat_VP90: Guid = Guid::new(
    0x30395056,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
); // 'VP90' (VP9)
pub const MFVideoFormat_WMV3: Guid = Guid::new(
    0x33564d57,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
); // 'WMV3'
pub const MFVideoFormat_NV12: Guid = Guid::new(
    0x3231564e,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
); // 'NV12'
pub const MFVideoFormat_RGB32: Guid = Guid::new(
    0x00000022,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
);
pub const MFAudioFormat_AAC: Guid = Guid::new(
    0x00001610,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
);
pub const MFAudioFormat_MP3: Guid = Guid::new(
    0x00000055,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
); // WAVE_FORMAT_MPEGLAYER3 = 0x55
pub const MFAudioFormat_WMA: Guid = Guid::new(
    0x00000161,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
); // WMAudio8 = 0x161
pub const MFAudioFormat_PCM: Guid = Guid::new(
    0x00000001,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
);
pub const MFAudioFormat_Float: Guid = Guid::new(
    0x00000003,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
);

// ===========================================================================
// Media Type Values & IMFMediaType
// ===========================================================================

/// A value stored in IMFMediaType attributes.
#[derive(Debug, Clone, PartialEq)]
pub enum MediaTypeValue {
    Uint32(u32),
    Uint64(u64),
    Double(f64),
    Guid(Guid),
    String(String),
    Blob(Vec<u8>),
}

/// Media Foundation Media Type (IMFMediaType-like).
///
/// Stores a collection of attributes keyed by GUID.
/// Used to describe media formats (video, audio) and negotiate between
/// source, transform, and sink nodes in the pipeline.
#[derive(Debug, Clone)]
pub struct ImfMediaType {
    pub attributes: HashMap<Guid, MediaTypeValue>,
}

impl ImfMediaType {
    /// Create a new empty media type.
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
        }
    }

    /// The attribute at an index (the IMFAttributes::GetItemByIndex order —
    /// the map's insertion order is not Windows-defined; the deterministic
    /// sorted order by key is used).
    pub fn attribute_at(&self, index: usize) -> Option<(Guid, Guid)> {
        let mut keys: Vec<&Guid> = self.attributes.keys().collect();
        keys.sort();
        keys.get(index).map(|key| (**key, **key))
    }

    /// Get a DOUBLE attribute.
    pub fn get_double(&self, key: &Guid) -> Option<f64> {
        match self.attributes.get(key) {
            Some(MediaTypeValue::Double(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set a DOUBLE attribute.
    pub fn set_double(&mut self, key: Guid, value: f64) {
        self.attributes.insert(key, MediaTypeValue::Double(value));
    }

    /// The number of attributes in the store.
    pub fn attribute_count(&self) -> usize {
        self.attributes.len()
    }

    /// Remove every attribute (the documented IMFAttributes::DeleteAllItems
    /// contract).
    pub fn delete_all(&mut self) {
        self.attributes.clear();
    }

    /// Remove an attribute (the documented IMFAttributes::DeleteItem
    /// contract — removing an absent key succeeds).
    pub fn delete_item(&mut self, key: &Guid) {
        self.attributes.remove(key);
    }

    /// Set a UINT32 attribute.
    pub fn set_uint32(&mut self, key: Guid, value: u32) {
        self.attributes.insert(key, MediaTypeValue::Uint32(value));
    }

    /// Set a UINT64 attribute.
    pub fn set_uint64(&mut self, key: Guid, value: u64) {
        self.attributes.insert(key, MediaTypeValue::Uint64(value));
    }

    /// Set a GUID attribute.
    pub fn set_guid(&mut self, key: Guid, value: Guid) {
        self.attributes.insert(key, MediaTypeValue::Guid(value));
    }

    /// Set a string attribute.
    pub fn set_string(&mut self, key: Guid, value: String) {
        self.attributes.insert(key, MediaTypeValue::String(value));
    }

    /// Set a blob attribute.
    pub fn set_blob(&mut self, key: Guid, value: Vec<u8>) {
        self.attributes.insert(key, MediaTypeValue::Blob(value));
    }

    /// Get a UINT32 attribute.
    pub fn get_uint32(&self, key: &Guid) -> Option<u32> {
        match self.attributes.get(key) {
            Some(MediaTypeValue::Uint32(v)) => Some(*v),
            _ => None,
        }
    }

    /// Get a UINT64 attribute.
    pub fn get_uint64(&self, key: &Guid) -> Option<u64> {
        match self.attributes.get(key) {
            Some(MediaTypeValue::Uint64(v)) => Some(*v),
            _ => None,
        }
    }

    /// Get a GUID attribute.
    pub fn get_guid(&self, key: &Guid) -> Option<Guid> {
        match self.attributes.get(key) {
            Some(MediaTypeValue::Guid(v)) => Some(*v),
            _ => None,
        }
    }

    /// Get a string attribute.
    pub fn get_string(&self, key: &Guid) -> Option<&str> {
        match self.attributes.get(key) {
            Some(MediaTypeValue::String(v)) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Get a blob attribute.
    pub fn get_blob(&self, key: &Guid) -> Option<&[u8]> {
        match self.attributes.get(key) {
            Some(MediaTypeValue::Blob(v)) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Get the frame width/height from MF_MT_FRAME_SIZE.
    pub fn get_frame_size(&self) -> Option<(u32, u32)> {
        self.get_uint64(&MF_MT_FRAME_SIZE).map(|v| {
            let width = (v >> 32) as u32;
            let height = (v & 0xFFFF_FFFF) as u32;
            (width, height)
        })
    }

    /// Set the frame width/height as MF_MT_FRAME_SIZE.
    pub fn set_frame_size(&mut self, width: u32, height: u32) {
        let packed = (width as u64) << 32 | height as u64;
        self.set_uint64(MF_MT_FRAME_SIZE, packed);
    }

    /// Get the frame rate (numerator/denominator) from MF_MT_FRAME_RATE.
    pub fn get_frame_rate(&self) -> Option<(u32, u32)> {
        self.get_uint64(&MF_MT_FRAME_RATE).map(|v| {
            let num = (v >> 32) as u32;
            let den = (v & 0xFFFF_FFFF) as u32;
            (num, den)
        })
    }

    /// Set the frame rate as MF_MT_FRAME_RATE.
    pub fn set_frame_rate(&mut self, numerator: u32, denominator: u32) {
        let packed = (numerator as u64) << 32 | denominator as u64;
        self.set_uint64(MF_MT_FRAME_RATE, packed);
    }

    /// Check if this is a video media type.
    pub fn is_video(&self) -> bool {
        self.get_guid(&MF_MT_MAJOR_TYPE) == Some(MFMediaType_Video)
    }

    /// Check if this is an audio media type.
    pub fn is_audio(&self) -> bool {
        self.get_guid(&MF_MT_MAJOR_TYPE) == Some(MFMediaType_Audio)
    }
}

impl Default for ImfMediaType {
    fn default() -> Self {
        Self::new()
    }
}

/// Media Session event types, mirroring `MediaEventType` from MF API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MediaEventType {
    /// Session has started playing.
    SessionStarted,
    /// Session has paused.
    SessionPaused,
    /// Session has stopped.
    SessionStopped,
    /// Session has ended (playback completed).
    SessionEnded,
    /// Session is buffering data.
    BufferingStarted,
    /// Session has finished buffering.
    BufferingStopped,
    /// An error occurred during playback.
    Error,
    /// Session has been shut down.
    SessionShutdown,
    /// Topology has been set.
    TopologySet,
    /// A new topology has been loaded.
    TopologyLoaded,
    /// Rate change (slow motion, fast forward, etc.).
    RateChanged,
    /// `MENewPresentation` — a new presentation descriptor is available.
    NewPresentation,
    /// `MESourceStarted`.
    SourceStarted,
    /// `MESourceStopped`.
    SourceStopped,
    /// `MESourcePaused`.
    SourcePaused,
    /// `MESourceSeeked`.
    SourceSeeked,
    /// `MEStreamStarted`.
    StreamStarted,
    /// `MEStreamStopped`.
    StreamStopped,
    /// `MEStreamPaused`.
    StreamPaused,
    /// `MEStreamSeeked`.
    StreamSeeked,
    /// `MENewStream` — a new stream appeared on the source.
    NewStream,
    /// `MEUpdatedStream`.
    UpdatedStream,
    /// `MEEndOfStream` — a stream reached the end of its data.
    EndOfStream,
    /// `MEEndOfPresentation` — the source reached the end of the
    /// presentation.
    EndOfPresentation,
}

impl MediaEventType {
    /// Convert from the MF event-type number (the MF_EVENT_TYPE_* values the
    /// guest passes; unknown values map to the generic Error event).
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::SessionStarted,
            1 => Self::SessionPaused,
            2 => Self::SessionStopped,
            3 => Self::SessionEnded,
            4 => Self::BufferingStarted,
            5 => Self::BufferingStopped,
            6 => Self::Error,
            7 => Self::SessionShutdown,
            8 => Self::TopologySet,
            9 => Self::TopologyLoaded,
            _ => Self::Error,
        }
    }

    /// The documented Windows `MF_EVENT_TYPE` number of this event (the
    /// values from `mfobjects.h`'s `__MIDL___MIDL_itf_mfobjects_0000_0012_0001`
    /// enum).  The guest-visible `IMFMediaEvent::GetType` answers these.
    pub fn mf_event_number(self) -> u32 {
        match self {
            Self::Error => 1,               // MEError
            Self::SessionStarted => 103,    // MESessionStarted
            Self::SessionPaused => 104,     // MESessionPaused
            Self::SessionStopped => 105,    // MESessionStopped
            Self::SessionShutdown => 106,   // MESessionClosed
            Self::SessionEnded => 107,      // MESessionEnded
            Self::RateChanged => 108,       // MESessionRateChanged
            Self::TopologySet => 101,       // MESessionTopologySet
            Self::TopologyLoaded => 111,    // MESessionTopologyStatus
            Self::NewPresentation => 113,   // MENewPresentation
            Self::BufferingStarted => 122,  // MEBufferingStarted
            Self::BufferingStopped => 123,  // MEBufferingStopped
            Self::SourceStarted => 201,     // MESourceStarted
            Self::StreamStarted => 202,     // MEStreamStarted
            Self::SourceSeeked => 203,      // MESourceSeeked
            Self::StreamSeeked => 204,      // MEStreamSeeked
            Self::NewStream => 205,         // MENewStream
            Self::UpdatedStream => 206,     // MEUpdatedStream
            Self::SourceStopped => 207,     // MESourceStopped
            Self::StreamStopped => 208,     // MEStreamStopped
            Self::SourcePaused => 209,      // MESourcePaused
            Self::StreamPaused => 210,      // MEStreamPaused
            Self::EndOfPresentation => 211, // MEEndOfPresentation
            Self::EndOfStream => 212,       // MEEndOfStream
        }
    }

    /// The reverse of [`Self::mf_event_number`] for the event types the
    /// runtime models; unknown numbers are the generic Error event.
    pub fn from_mf_number(value: u32) -> Self {
        match value {
            1 => Self::Error,
            101 => Self::TopologySet,
            103 => Self::SessionStarted,
            104 => Self::SessionPaused,
            105 => Self::SessionStopped,
            106 => Self::SessionShutdown,
            107 => Self::SessionEnded,
            108 => Self::RateChanged,
            111 => Self::TopologyLoaded,
            113 => Self::NewPresentation,
            122 => Self::BufferingStarted,
            123 => Self::BufferingStopped,
            201 => Self::SourceStarted,
            202 => Self::StreamStarted,
            203 => Self::SourceSeeked,
            204 => Self::StreamSeeked,
            205 => Self::NewStream,
            206 => Self::UpdatedStream,
            207 => Self::SourceStopped,
            208 => Self::StreamStopped,
            209 => Self::SourcePaused,
            210 => Self::StreamPaused,
            211 => Self::EndOfPresentation,
            212 => Self::EndOfStream,
            _ => Self::Error,
        }
    }
}

impl MediaEventType {
    /// Get a human-readable name for this event type.
    pub fn name(&self) -> &'static str {
        match self {
            MediaEventType::SessionStarted => "MESessionStarted",
            MediaEventType::SessionPaused => "MESessionPaused",
            MediaEventType::SessionStopped => "MESessionStopped",
            MediaEventType::SessionEnded => "MESessionEnded",
            MediaEventType::BufferingStarted => "MEBufferingStarted",
            MediaEventType::BufferingStopped => "MEBufferingStopped",
            MediaEventType::Error => "MEError",
            MediaEventType::SessionShutdown => "MESessionShutdown",
            MediaEventType::TopologySet => "METopologySet",
            MediaEventType::TopologyLoaded => "METopologyLoaded",
            MediaEventType::RateChanged => "MERateChanged",
            MediaEventType::NewPresentation => "MENewPresentation",
            MediaEventType::SourceStarted => "MESourceStarted",
            MediaEventType::SourceStopped => "MESourceStopped",
            MediaEventType::SourcePaused => "MESourcePaused",
            MediaEventType::SourceSeeked => "MESourceSeeked",
            MediaEventType::StreamStarted => "MEStreamStarted",
            MediaEventType::StreamStopped => "MEStreamStopped",
            MediaEventType::StreamPaused => "MEStreamPaused",
            MediaEventType::StreamSeeked => "MEStreamSeeked",
            MediaEventType::NewStream => "MENewStream",
            MediaEventType::UpdatedStream => "MEUpdatedStream",
            MediaEventType::EndOfStream => "MEEndOfStream",
            MediaEventType::EndOfPresentation => "MEEndOfPresentation",
        }
    }
}

/// A Media Foundation event, wrapping an event type and optional data.
#[derive(Debug, Clone)]
pub struct MediaEvent {
    /// The type of event.
    pub event_type: MediaEventType,
    /// The exact guest-visible `MF_EVENT_TYPE` number.  For the modelled
    /// event types this is [`MediaEventType::mf_event_number`]; events queued
    /// directly from a guest `QueueEvent` keep the guest-supplied number.
    pub mf_type: u32,
    /// Optional HRESULT-like status code.
    pub status: i32,
    /// Optional data associated with the event (e.g., error message).
    pub data: Option<String>,
    /// Presentation timestamp associated with the event.
    pub pts: Option<u64>,
}

impl MediaEvent {
    /// Create a new media event.
    pub fn new(event_type: MediaEventType) -> Self {
        Self {
            event_type,
            mf_type: event_type.mf_event_number(),
            status: 0,
            data: None,
            pts: None,
        }
    }

    /// Create a new media event with a status code.
    pub fn with_status(event_type: MediaEventType, status: i32) -> Self {
        Self {
            event_type,
            mf_type: event_type.mf_event_number(),
            status,
            data: None,
            pts: None,
        }
    }

    /// Create a media event from the exact `MF_EVENT_TYPE` number (the
    /// number the guest passed to `IMFMediaEventGenerator::QueueEvent`).
    pub fn with_mf_type(mf_type: u32) -> Self {
        Self {
            event_type: MediaEventType::from_mf_number(mf_type),
            mf_type,
            status: 0,
            data: None,
            pts: None,
        }
    }

    /// Create a new media event with an error message.
    pub fn with_error(message: impl Into<String>) -> Self {
        Self::with_error_status(-1, message)
    }

    /// Create a new media event with an explicit error status (HRESULT).
    pub fn with_error_status(status: i32, message: impl Into<String>) -> Self {
        Self {
            event_type: MediaEventType::Error,
            mf_type: MediaEventType::Error.mf_event_number(),
            status,
            data: Some(message.into()),
            pts: None,
        }
    }

    /// Attach a presentation timestamp to this event.
    pub fn with_pts(mut self, pts: u64) -> Self {
        self.pts = Some(pts);
        self
    }
}

// ===========================================================================
// IMFMediaBuffer / IMFSample
// ===========================================================================

/// Media Foundation memory buffer (IMFMediaBuffer-like).
#[derive(Debug, Clone)]
pub struct ImfMediaBuffer {
    pub data: Vec<u8>,
    pub max_length: u32,
    pub current_length: u32,
}

impl ImfMediaBuffer {
    /// Maximum allocation size for `new`; larger capacities are clamped so
    /// a caller-controlled size cannot trigger a multi-GiB allocation.
    pub const MAX_CAPACITY: u32 = 512 * 1024 * 1024;

    /// Create a new media buffer with the given capacity.
    ///
    /// The capacity is clamped to [`Self::MAX_CAPACITY`] to bound memory
    /// use from untrusted sizes.
    pub fn new(capacity: u32) -> Self {
        let capacity = capacity.min(Self::MAX_CAPACITY);
        Self {
            data: vec![0u8; capacity as usize],
            max_length: capacity,
            current_length: 0,
        }
    }

    /// Create a media buffer from existing data.
    pub fn from_data(data: Vec<u8>) -> Self {
        let len = data.len() as u32;
        Self {
            data,
            max_length: len,
            current_length: len,
        }
    }

    /// Lock the buffer and return a mutable slice (simulates IMFMediaBuffer::Lock).
    pub fn lock(&mut self) -> &mut [u8] {
        &mut self.data[..self.current_length as usize]
    }

    /// Lock the buffer for read-only access.
    pub fn lock_read(&self) -> &[u8] {
        &self.data[..self.current_length as usize]
    }

    /// Unlock the buffer (simulates IMFMediaBuffer::Unlock).
    pub fn unlock(&mut self) {
        // no-op in our implementation
    }

    /// Get the current length of valid data in the buffer.
    pub fn get_current_length(&self) -> u32 {
        self.current_length
    }

    /// Set the current length of valid data in the buffer.
    pub fn set_current_length(&mut self, length: u32) {
        self.current_length = length.min(self.max_length);
    }

    /// Get the maximum capacity of the buffer.
    pub fn get_max_length(&self) -> u32 {
        self.max_length
    }
}

/// Media Foundation sample (IMFSample-like).
///
/// Represents a single media sample (a video frame or audio buffer) with
/// associated metadata (timestamp, duration, flags).
#[derive(Debug, Clone)]
pub struct ImfSample {
    pub buffer: Vec<u8>,
    pub sample_time: i64,     // 100-ns units
    pub sample_duration: i64, // 100-ns units
    pub flags: u32,
}

impl ImfSample {
    /// Create a new sample with the given buffer.
    pub fn new(buffer: Vec<u8>) -> Self {
        Self {
            buffer,
            sample_time: 0,
            sample_duration: 0,
            flags: 0,
        }
    }

    /// Create an empty sample.
    pub fn empty() -> Self {
        Self {
            buffer: Vec::new(),
            sample_time: 0,
            sample_duration: 0,
            flags: 0,
        }
    }

    /// Get the sample time in 100-ns units.
    pub fn get_sample_time(&self) -> i64 {
        self.sample_time
    }

    /// Set the sample time in 100-ns units.
    pub fn set_sample_time(&mut self, time: i64) {
        self.sample_time = time;
    }

    /// Get the sample duration in 100-ns units.
    pub fn get_sample_duration(&self) -> i64 {
        self.sample_duration
    }

    /// Set the sample duration in 100-ns units.
    pub fn set_sample_duration(&mut self, duration: i64) {
        self.sample_duration = duration;
    }

    /// Get the sample buffer.
    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Get a mutable reference to the sample buffer.
    pub fn get_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    /// Set the sample buffer.
    pub fn set_buffer(&mut self, buffer: Vec<u8>) {
        self.buffer = buffer;
    }

    /// Get the sample flags.
    pub fn get_flags(&self) -> u32 {
        self.flags
    }

    /// Set the sample flags.
    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }
}

// ===========================================================================
// IMFMediaEventGenerator
// ===========================================================================

/// Media Foundation event generator (IMFMediaEventGenerator-like).
///
/// Maintains a queue of media events that can be pulled by the application.
/// This is used by `MfMediaSession` to notify listeners of state changes.
#[derive(Debug, Clone)]
pub struct MfEventQueue {
    /// Queue of pending events.
    events: VecDeque<MediaEvent>,
    /// Maximum number of events to keep in the queue.
    max_events: usize,
}

impl MfEventQueue {
    /// Create a new event queue.
    pub fn new() -> Self {
        Self {
            events: VecDeque::new(),
            max_events: 256,
        }
    }

    /// Create a new event queue with a custom maximum size.
    pub fn with_max(max_events: usize) -> Self {
        Self {
            events: VecDeque::new(),
            max_events,
        }
    }

    /// Queue a new event.
    pub fn queue_event(&mut self, event: MediaEvent) {
        if self.max_events == 0 {
            return; // zero-capacity queue holds nothing
        }
        if self.events.len() >= self.max_events {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Queue an event by type.
    pub fn queue_event_type(&mut self, event_type: MediaEventType) {
        self.queue_event(MediaEvent::new(event_type));
    }

    /// Queue an event by its exact `MF_EVENT_TYPE` number (the guest-supplied
    /// `IMFMediaEventGenerator::QueueEvent` contract: the number round-trips
    /// through `IMFMediaEvent::GetType` unchanged).
    pub fn queue_mf_event(&mut self, mf_type: u32) {
        self.queue_event(MediaEvent::with_mf_type(mf_type));
    }

    /// Get the next pending event, if any.
    pub fn get_event(&mut self) -> Option<MediaEvent> {
        self.events.pop_front()
    }

    /// Peek at the next pending event without removing it.
    pub fn peek_event(&self) -> Option<&MediaEvent> {
        self.events.front()
    }

    /// Check if there are pending events.
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    /// Get the number of pending events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Clear all pending events.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl Default for MfEventQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// MF asynchronous callback pump
// ===========================================================================
//
// The MF asynchronous surface (`IMFMediaEventGenerator::BeginGetEvent` and
// `IMFByteStream::BeginRead`/`BeginWrite`) parks the guest request here and
// completes it when the backing real state changes.  The runtime servicing
// points drain the queued completions and invoke the guest
// `IMFAsyncCallback::Invoke` — the same shape the audio-activation
// completions use (`crate::audio_activation` + the block-dispatch
// safepoint).  The registry is process-keyed because a `PeHostRuntime`
// services exactly one guest process.

/// The asynchronous MF operation a parked request or completion belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MfAsyncOp {
    /// `IMFMediaEventGenerator::BeginGetEvent`.
    GetEvent,
    /// `IMFByteStream::BeginRead`.
    Read,
    /// `IMFByteStream::BeginWrite`.
    Write,
}

/// A parked MF asynchronous request: the guest `IMFAsyncCallback` whose
/// `Invoke` fires when the operation completes, plus the state object that
/// becomes the result's `GetState`.
#[derive(Debug, Clone)]
pub(crate) struct MfParkedRequest {
    /// The object the request was made on (media source / byte stream).
    pub(crate) owner: u64,
    /// The operation.
    pub(crate) op: MfAsyncOp,
    /// The `IMFAsyncCallback` object passed to the Begin call.
    pub(crate) callback_object: u64,
    /// The callback's `Invoke` entry point (vtable slot 4, resolved at Begin
    /// time so delivery never has to re-read guest memory).
    pub(crate) callback_method: u64,
    /// The `punkState` passed to the Begin call.
    pub(crate) state_object: u64,
}

/// A completed MF asynchronous operation: the real `IMFAsyncResult` handed
/// to the callback, and the payload `EndGetEvent`/`EndRead`/`EndWrite`
/// retrieves.
#[derive(Debug, Clone)]
pub(crate) struct MfAsyncCompletion {
    /// The operation.
    pub(crate) op: MfAsyncOp,
    /// The guest `IMFAsyncResult` object.
    pub(crate) result: u64,
    /// The callback object to invoke (0 = no callback; poll via EndX).
    pub(crate) callback_object: u64,
    /// The callback's `Invoke` entry point (0 = no callback).
    pub(crate) callback_method: u64,
    /// The guest `IMFMediaEvent` object a `GetEvent` completion produced.
    pub(crate) event_object: u64,
    /// Bytes read/written by a byte-stream completion.
    pub(crate) bytes: u32,
}

type MfParkedMap = std::collections::HashMap<u32, Vec<MfParkedRequest>>;
type MfCompletionQueue =
    std::collections::HashMap<u32, std::collections::VecDeque<MfAsyncCompletion>>;
type MfResultMap =
    std::collections::HashMap<u32, std::collections::HashMap<u64, MfAsyncCompletion>>;

static MF_PARKED_REQUESTS: std::sync::OnceLock<std::sync::Mutex<MfParkedMap>> =
    std::sync::OnceLock::new();
static MF_COMPLETION_QUEUE: std::sync::OnceLock<std::sync::Mutex<MfCompletionQueue>> =
    std::sync::OnceLock::new();
static MF_ASYNC_RESULTS: std::sync::OnceLock<std::sync::Mutex<MfResultMap>> =
    std::sync::OnceLock::new();

fn mf_registry<T: Default>(
    cell: &std::sync::OnceLock<std::sync::Mutex<T>>,
) -> std::sync::MutexGuard<'_, T> {
    cell.get_or_init(|| std::sync::Mutex::new(T::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Park a Begin request until the operation completes.
pub(crate) fn park_mf_request(pid: u32, request: MfParkedRequest) {
    mf_registry(&MF_PARKED_REQUESTS)
        .entry(pid)
        .or_default()
        .push(request);
}

/// Whether a request for `owner`/`op` is still parked (not yet completed).
pub(crate) fn has_mf_parked_request(pid: u32, owner: u64, op: MfAsyncOp) -> bool {
    mf_registry(&MF_PARKED_REQUESTS)
        .get(&pid)
        .is_some_and(|requests| {
            requests
                .iter()
                .any(|request| request.owner == owner && request.op == op)
        })
}

/// Take (and remove) the parked request for `owner`/`op`, if any.  Used by
/// completion (the request is consumed when its result is produced) and by
/// cancellation (the request is dropped).
pub(crate) fn take_mf_parked_request(
    pid: u32,
    owner: u64,
    op: MfAsyncOp,
) -> Option<MfParkedRequest> {
    let mut parked = mf_registry(&MF_PARKED_REQUESTS);
    let requests = parked.get_mut(&pid)?;
    let index = requests
        .iter()
        .position(|request| request.owner == owner && request.op == op)?;
    Some(requests.remove(index))
}

/// Record a completed operation: the real result becomes retrievable by
/// `EndGetEvent`/`EndRead`/`EndWrite`, and the callback is queued for the
/// runtime servicing point that drains the pump.
pub(crate) fn complete_mf_request(pid: u32, completion: MfAsyncCompletion) {
    mf_registry(&MF_ASYNC_RESULTS)
        .entry(pid)
        .or_default()
        .insert(completion.result, completion.clone());
    mf_registry(&MF_COMPLETION_QUEUE)
        .entry(pid)
        .or_default()
        .push_back(completion);
}

/// Record a completed operation without queueing its callback: used for a
/// `BeginGetEvent` that completed synchronously (`S_OK`) inside the Begin
/// call, where Windows does not invoke the callback.
pub(crate) fn record_mf_result(pid: u32, completion: MfAsyncCompletion) {
    mf_registry(&MF_ASYNC_RESULTS)
        .entry(pid)
        .or_default()
        .insert(completion.result, completion);
}

/// Pop the next completion awaiting callback delivery, if any.
pub(crate) fn pop_mf_completion(pid: u32) -> Option<MfAsyncCompletion> {
    mf_registry(&MF_COMPLETION_QUEUE)
        .get_mut(&pid)
        .and_then(std::collections::VecDeque::pop_front)
}

/// Take the completed operation recorded for `result` (one-shot: EndX
/// consumes it).
pub(crate) fn take_mf_result(pid: u32, result: u64) -> Option<MfAsyncCompletion> {
    mf_registry(&MF_ASYNC_RESULTS)
        .get_mut(&pid)?
        .remove(&result)
}

/// The guest `IMFMediaEvent` object a completed `GetEvent` result carries
/// (used by `IMFAsyncResult::GetObject`).
pub(crate) fn mf_result_event_object(pid: u32, result: u64) -> Option<u64> {
    mf_registry(&MF_ASYNC_RESULTS)
        .get(&pid)?
        .get(&result)
        .map(|completion| completion.event_object)
}

/// The `IMFAsyncCallback` object a completed result carries (used by
/// `IMFAsyncResult::GetCallback`).
pub(crate) fn mf_result_callback_object(pid: u32, result: u64) -> Option<u64> {
    mf_registry(&MF_ASYNC_RESULTS)
        .get(&pid)?
        .get(&result)
        .map(|completion| completion.callback_object)
}

/// Forget every parked request and pending completion of `pid`.
pub(crate) fn clear_mf_async_state(pid: u32) {
    mf_registry(&MF_PARKED_REQUESTS).remove(&pid);
    mf_registry(&MF_COMPLETION_QUEUE).remove(&pid);
    mf_registry(&MF_ASYNC_RESULTS).remove(&pid);
}

// ===========================================================================
// MFT (Media Foundation Transform) trait
// ===========================================================================

/// Standard MFT_OUTPUT_DATA_BUFFER flags
pub const MFT_OUTPUT_DATA_BUFFER_INCOMPLETE: u32 = 0x01000000;
pub const MFT_OUTPUT_DATA_BUFFER_FORMAT_CHANGE: u32 = 0x00000100;
pub const MFT_OUTPUT_DATA_BUFFER_STREAM_END: u32 = 0x00000200;
pub const MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE: u32 = 0x00000400;

/// Media Foundation Transform interface.
///
/// Represents an IMFTransform implementation that can process media data.
/// Transforms take input samples, process them, and produce output samples.
/// Common transforms include video decoders, audio decoders, and效果 processors.
pub trait MftTransform: Send {
    /// Get the number of input and output streams.
    fn get_stream_count(&self) -> (u32, u32);

    /// Set the input type for a stream.
    fn set_input_type(&mut self, stream_id: u32, media_type: &ImfMediaType) -> AppResult<()>;

    /// Set the output type for a stream.
    fn set_output_type(&mut self, stream_id: u32, media_type: &ImfMediaType) -> AppResult<()>;

    /// Get an available input type for a stream.
    fn get_input_available_type(&self, stream_id: u32, index: u32) -> AppResult<ImfMediaType>;

    /// Get an available output type for a stream.
    fn get_output_available_type(&self, stream_id: u32, index: u32) -> AppResult<ImfMediaType>;

    /// Process an input sample on the given stream.
    fn process_input(&mut self, stream_id: u32, sample: &ImfSample, flags: u32) -> AppResult<()>;

    /// Process output: get an output sample from the given stream.
    fn process_output(
        &mut self,
        stream_id: u32,
        sample: &mut ImfSample,
        flags: &mut u32,
    ) -> AppResult<()>;

    /// Get output status flags (still available samples, format change, etc.)
    fn get_output_status(&self) -> u32 {
        0
    }

    /// Check if the transform has output samples available.
    fn has_output(&self) -> bool;

    /// Flush any buffered data.
    fn flush(&mut self) -> AppResult<()> {
        Ok(())
    }
}

// ===========================================================================
// H.264 Decoder MFT (macOS VideoToolbox)
// ===========================================================================

#[cfg(target_os = "macos")]
mod vt_decoder_mft {
    use super::*;
    use crate::video_decoder::vt_ffi;
    use std::ffi::c_void;
    use std::sync::{Arc, Mutex};

    // ---- FFI type aliases (canonical declarations live in vt_ffi) ----
    type CMVideoFormatDescriptionRef = vt_ffi::CMVideoFormatDescriptionRef;
    type CMBlockBufferRef = vt_ffi::CMBlockBufferRef;
    type CMSampleBufferRef = vt_ffi::CMSampleBufferRef;
    type CVPixelBufferRef = vt_ffi::CVPixelBufferRef;
    type VTDecompressionSessionRef = vt_ffi::VTDecompressionSessionRef;
    type CFDictionaryRef = vt_ffi::CFDictionaryRef;

    /// Lock a `Mutex`, recovering from poisoning instead of panicking.
    fn lock_guard<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Split H.264 AVCC (avcC) extradata into its parameter sets.
    ///
    /// Returns `(parameter_sets, nal_length_size)`. Every length/offset in
    /// the blob is untrusted and validated before use.
    fn parse_avcc_parameter_sets(data: &[u8]) -> AppResult<(Vec<Vec<u8>>, u32)> {
        if data.len() < 7 || data[0] != 1 {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "H.264 avcC extradata is invalid",
            ));
        }
        let nal_length_size = (data[4] & 0x03) as u32 + 1;
        let mut pos = 5usize;
        let num_sps = (data[pos] & 0x1F) as usize;
        pos += 1;
        let mut sets = Vec::new();
        for _ in 0..num_sps {
            if pos + 2 > data.len() {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "Truncated SPS length in avcC extradata",
                ));
            }
            let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + len > data.len() {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "SPS overruns avcC extradata",
                ));
            }
            sets.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        if pos >= data.len() {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "avcC extradata missing PPS count",
            ));
        }
        let num_pps = data[pos] as usize;
        pos += 1;
        for _ in 0..num_pps {
            if pos + 2 > data.len() {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "Truncated PPS length in avcC extradata",
                ));
            }
            let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + len > data.len() {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "PPS overruns avcC extradata",
                ));
            }
            sets.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        Ok((sets, nal_length_size))
    }

    // ---- Decoded frame queue ----
    /// A decoded frame. The pixel buffer is +1 retained when the frame is
    /// enqueued and must be released exactly once by whoever pops it.
    struct DecodedFrame {
        pixel_buffer: CVPixelBufferRef,
        pts: i64,
        duration: i64,
    }

    // Safety: the pixel buffer is retained for the lifetime of the struct
    // and released on pop/drop; all access is serialized by the mutex.
    unsafe impl Send for DecodedFrame {}

    /// H.264 decoder using macOS VideoToolbox, implementing MftTransform.
    ///
    /// Provides hardware-accelerated H.264 decoding by wrapping
    /// VTDecompressionSession. Input is H.264 Annex B NAL units;
    /// output is BGRA or NV12 pixel buffers.
    pub struct H264DecoderMft {
        session: Option<VTDecompressionSessionRef>,
        format_desc: Option<CMVideoFormatDescriptionRef>,
        /// Per-instance decoded frame queue, shared with the C callback via
        /// the decompression output refcon.
        frame_queue: Arc<Mutex<VecDeque<DecodedFrame>>>,
        width: u32,
        height: u32,
        callback_refcon: *mut c_void,
    }

    unsafe extern "C" fn decompression_output_callback(
        output_refcon: *mut c_void,
        _source_frame_refcon: *mut c_void,
        status: i32,
        _info_flags: u32,
        image_buffer: CVPixelBufferRef,
        pts: vt_ffi::CMTime,
        duration: vt_ffi::CMTime,
    ) {
        if status != 0 || image_buffer.is_null() || output_refcon.is_null() {
            return;
        }
        let queue_ptr = output_refcon as *const Mutex<VecDeque<DecodedFrame>>;
        unsafe {
            // Take a strong reference for the duration of this callback so
            // the queue allocation cannot be freed while we use it.
            Arc::increment_strong_count(queue_ptr);
            let queue = Arc::from_raw(queue_ptr);

            // The pixel buffer is only valid during this callback; retain it
            // so it survives until the frame is consumed (and is released by
            // process_output / flush / Drop).
            vt_ffi::CVPixelBufferRetain(image_buffer);
            let mut frames = lock_guard(&queue);
            frames.push_back(DecodedFrame {
                pixel_buffer: image_buffer,
                pts: pts.value,
                duration: duration.value,
            });
            drop(frames);
            drop(queue);
        }
    }

    impl H264DecoderMft {
        /// Create a new H.264 decoder MFT.
        pub fn new() -> Self {
            Self {
                session: None,
                format_desc: None,
                frame_queue: Arc::new(Mutex::new(VecDeque::new())),
                width: 0,
                height: 0,
                callback_refcon: std::ptr::null_mut(),
            }
        }

        /// Hand the frame queue to the C callback as the output refcon.
        ///
        /// This transfers one strong reference into the refcon; it is
        /// reclaimed in `reclaim_refcon` during teardown.
        fn ensure_refcon(&mut self) {
            if self.callback_refcon.is_null() {
                self.callback_refcon = Arc::into_raw(self.frame_queue.clone()) as *mut c_void;
            }
        }

        /// Reclaim the refcon's strong reference. Safe once the session has
        /// been invalidated (no new callbacks can start); any in-flight
        /// callback holds its own strong reference.
        fn reclaim_refcon(&mut self) {
            if !self.callback_refcon.is_null() {
                unsafe {
                    let _ =
                        Arc::from_raw(self.callback_refcon as *const Mutex<VecDeque<DecodedFrame>>);
                }
                self.callback_refcon = std::ptr::null_mut();
            }
        }

        /// Release all queued pixel buffers (dropping the frames).
        fn clear_frame_queue(&mut self) {
            let mut frames = lock_guard(&self.frame_queue);
            while let Some(frame) = frames.pop_front() {
                unsafe { vt_ffi::CVPixelBufferRelease(frame.pixel_buffer) };
            }
        }

        /// Create the VTDecompressionSession from format description.
        fn create_session(&mut self) -> AppResult<()> {
            if self.session.is_some() {
                return Ok(());
            }
            let fmt_desc = self.format_desc.ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "No format description set for H.264 decoder",
                )
            })?;

            unsafe {
                // Request BGRA output buffers so the CPU-side copy in
                // `process_output` matches the actual buffer layout.
                let dest_dict = crate::video_decoder::create_bgra_pixel_buffer_attributes()?;

                // Callback record
                self.ensure_refcon();
                let callback = vt_ffi::VTDecompressionOutputCallbackRecord {
                    decompressionOutputCallback: Some(decompression_output_callback),
                    decompressionOutputRefCon: self.callback_refcon,
                };

                // Decoder specification: default (hardware when available)
                let decoder_spec: CFDictionaryRef = std::ptr::null();

                let mut session_out: VTDecompressionSessionRef = std::ptr::null_mut();
                let status = vt_ffi::VTDecompressionSessionCreate(
                    std::ptr::null_mut(),
                    fmt_desc,
                    decoder_spec,
                    dest_dict,
                    &callback,
                    &mut session_out,
                );

                if !dest_dict.is_null() {
                    vt_ffi::CFRelease(dest_dict as vt_ffi::CFTypeRef);
                }

                if status != 0 || session_out.is_null() {
                    self.reclaim_refcon();
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        format!("VTDecompressionSessionCreate failed with status {status}"),
                    ));
                }
                self.session = Some(session_out);
            }
            Ok(())
        }
    }

    // Safety: H264DecoderMft only holds raw pointers to VT decoder session and
    // callback refcon. All access is synchronized; fields are only used from
    // single threads via MftTransform's &mut self methods.
    unsafe impl Send for H264DecoderMft {}

    impl MftTransform for H264DecoderMft {
        fn get_stream_count(&self) -> (u32, u32) {
            (1, 1) // 1 input, 1 output
        }

        fn set_input_type(&mut self, _stream_id: u32, media_type: &ImfMediaType) -> AppResult<()> {
            let (width, height) = media_type.get_frame_size().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "H.264 decoder input type missing frame size",
                )
            })?;
            self.width = width;
            self.height = height;

            // set_input_type may be called more than once: release any
            // previous format description before replacing it.
            if let Some(desc) = self.format_desc.take() {
                unsafe { vt_ffi::CFRelease(desc as vt_ffi::CFTypeRef) };
            }

            // Try to get codec private data (AVCC extradata / SPS/PPS)
            let codec_data = media_type
                .get_blob(&MF_MT_MPEG_SEQUENCE_HEADER)
                .or_else(|| media_type.get_blob(&MF_MT_USER_DATA));

            unsafe {
                // Create CMVideoFormatDescription from H.264 parameter sets
                let mut desc_out: CMVideoFormatDescriptionRef = std::ptr::null_mut();
                let status = if let Some(data) = codec_data {
                    match parse_avcc_parameter_sets(data) {
                        Ok((sets, nal_length_size)) if sets.len() >= 2 => {
                            // AVCC extradata: pass the individual SPS/PPS
                            // with the real 6-argument signature.
                            let pointers: Vec<*const u8> =
                                sets.iter().map(|s| s.as_ptr()).collect();
                            let sizes: Vec<usize> = sets.iter().map(|s| s.len()).collect();
                            vt_ffi::CMVideoFormatDescriptionCreateFromH264ParameterSets(
                                std::ptr::null_mut(),
                                sets.len(),
                                sizes.as_ptr(),
                                pointers.as_ptr(),
                                nal_length_size as i32,
                                &mut desc_out,
                            )
                        }
                        _ => {
                            // Not parseable as avcC — fall back to a
                            // dimensions-only description.
                            vt_ffi::CMVideoFormatDescriptionCreate(
                                std::ptr::null_mut(),
                                vt_ffi::kCMVideoCodecType_H264,
                                width as i32,
                                height as i32,
                                &mut desc_out,
                            )
                        }
                    }
                } else {
                    // Create with just dimensions (some files work)
                    vt_ffi::CMVideoFormatDescriptionCreate(
                        std::ptr::null_mut(),
                        vt_ffi::kCMVideoCodecType_H264,
                        width as i32,
                        height as i32,
                        &mut desc_out,
                    )
                };

                if status != 0 || desc_out.is_null() {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        format!("Failed to create CMVideoFormatDescription, status {status}"),
                    ));
                }
                self.format_desc = Some(desc_out);
            }

            Ok(())
        }

        fn set_output_type(
            &mut self,
            _stream_id: u32,
            _media_type: &ImfMediaType,
        ) -> AppResult<()> {
            Ok(())
        }

        fn get_input_available_type(
            &self,
            _stream_id: u32,
            _index: u32,
        ) -> AppResult<ImfMediaType> {
            let mut mt = ImfMediaType::new();
            mt.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Video);
            mt.set_guid(MF_MT_SUBTYPE, MFVideoFormat_H264);
            if self.width > 0 && self.height > 0 {
                mt.set_frame_size(self.width, self.height);
            }
            Ok(mt)
        }

        fn get_output_available_type(
            &self,
            _stream_id: u32,
            _index: u32,
        ) -> AppResult<ImfMediaType> {
            let mut mt = ImfMediaType::new();
            mt.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Video);
            mt.set_guid(MF_MT_SUBTYPE, MFVideoFormat_NV12);
            if self.width > 0 && self.height > 0 {
                mt.set_frame_size(self.width, self.height);
            }
            Ok(mt)
        }

        fn process_input(
            &mut self,
            _stream_id: u32,
            sample: &ImfSample,
            _flags: u32,
        ) -> AppResult<()> {
            self.create_session()?;

            let data = &sample.buffer;
            if data.is_empty() {
                return Ok(()); // Flush
            }

            let session = self.session.ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "H.264 decoder session not initialized",
                )
            })?;
            let format_desc = self.format_desc.ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "H.264 decoder format description not initialized",
                )
            })?;

            unsafe {
                // Create CMBlockBuffer from our data
                let mut block_buffer: CMBlockBufferRef = std::ptr::null_mut();
                let status = vt_ffi::CMBlockBufferCreateWithMemoryBlock(
                    std::ptr::null_mut(),
                    data.as_ptr() as *mut c_void,
                    data.len(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    0,
                    data.len(),
                    0,
                    &mut block_buffer,
                );

                if status != 0 || block_buffer.is_null() {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        format!("CMBlockBufferCreateWithMemoryBlock failed {status}"),
                    ));
                }

                let pts_time = vt_ffi::CMTime::make(sample.sample_time, 10_000_000); // 100ns units -> 10MHz

                let mut sample_buffer: CMSampleBufferRef = std::ptr::null_mut();
                let status2 = vt_ffi::CMSampleBufferCreate(
                    std::ptr::null_mut(),
                    block_buffer,
                    1, // dataReady
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    format_desc,
                    1, // numSamples
                    1, // numSampleTimingEntries
                    &pts_time,
                    1, // numSampleSizeEntries
                    &data.len(),
                    &mut sample_buffer,
                );

                if status2 != 0 || sample_buffer.is_null() {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        format!("CMSampleBufferCreate failed {status2}"),
                    ));
                }

                // Decode the frame synchronously (no async flag): the output
                // callback runs before this call returns, so the decoded
                // frames are already in our queue afterwards and there is
                // nothing to wait for.
                let decode_status = vt_ffi::VTDecompressionSessionDecodeFrame(
                    session,
                    sample_buffer,
                    0,                    // synchronous
                    std::ptr::null_mut(), // sourceFrameRefCon
                    std::ptr::null_mut(), // infoFlagsOut (null = don't care)
                );

                if decode_status != 0 {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        format!("VTDecompressionSessionDecodeFrame failed {decode_status}"),
                    ));
                }
            }

            Ok(())
        }

        fn process_output(
            &mut self,
            _stream_id: u32,
            sample: &mut ImfSample,
            flags: &mut u32,
        ) -> AppResult<()> {
            let frame = lock_guard(&self.frame_queue).pop_front();

            let Some(frame) = frame else {
                *flags = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
                return Ok(());
            };

            unsafe {
                // Lock pixel buffer to get data
                let lock_status = vt_ffi::CVPixelBufferLockBaseAddress(frame.pixel_buffer, 0);
                if lock_status != 0 {
                    vt_ffi::CVPixelBufferRelease(frame.pixel_buffer);
                    *flags = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
                    return Ok(());
                }

                let base_addr = vt_ffi::CVPixelBufferGetBaseAddress(frame.pixel_buffer);
                let data_size = vt_ffi::CVPixelBufferGetDataSize(frame.pixel_buffer);
                let width = vt_ffi::CVPixelBufferGetWidth(frame.pixel_buffer);
                let height = vt_ffi::CVPixelBufferGetHeight(frame.pixel_buffer);
                let bytes_per_row = vt_ffi::CVPixelBufferGetBytesPerRow(frame.pixel_buffer);

                let mut dst: Vec<u8> = Vec::new();
                if !base_addr.is_null() && data_size > 0 && width > 0 && height > 0 {
                    let w = width;
                    let h = height;
                    let pixel_format = vt_ffi::CVPixelBufferGetPixelFormatType(frame.pixel_buffer);
                    match pixel_format {
                        vt_ffi::kCVPixelFormatType_32BGRA => {
                            // Validate the layout before copying so no read
                            // can go out of bounds, regardless of stride.
                            let Some(needed) = w.checked_mul(h).and_then(|n| n.checked_mul(4))
                            else {
                                unlock_release_and_finish(frame.pixel_buffer, flags);
                                return Ok(());
                            };
                            if needed > 0
                                && w.checked_mul(4) == Some(bytes_per_row)
                                && data_size >= needed
                            {
                                // Tightly packed: single copy.
                                let src =
                                    std::slice::from_raw_parts(base_addr as *const u8, needed);
                                dst.extend_from_slice(src);
                            } else if needed > 0 && bytes_per_row >= w * 4 {
                                // Padded rows: copy row by row, bounded by
                                // the actual buffer size.
                                let total =
                                    bytes_per_row.checked_mul(h).unwrap_or(0).min(data_size);
                                if total >= needed {
                                    let src =
                                        std::slice::from_raw_parts(base_addr as *const u8, total);
                                    dst.reserve(needed);
                                    for row in 0..h {
                                        let row_start = row * bytes_per_row;
                                        dst.extend_from_slice(&src[row_start..row_start + w * 4]);
                                    }
                                }
                            }
                        }
                        vt_ffi::kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange => {
                            // NV12: convert bi-planar Y/UV to BGRA (bounded
                            // reads; matches the software path used by the
                            // VideoDecoder).
                            let y_bpr =
                                vt_ffi::CVPixelBufferGetBytesPerRowOfPlane(frame.pixel_buffer, 0);
                            let uv_bpr =
                                vt_ffi::CVPixelBufferGetBytesPerRowOfPlane(frame.pixel_buffer, 1);
                            let y_base =
                                vt_ffi::CVPixelBufferGetBaseAddressOfPlane(frame.pixel_buffer, 0);
                            let uv_base =
                                vt_ffi::CVPixelBufferGetBaseAddressOfPlane(frame.pixel_buffer, 1);
                            if !y_base.is_null() && !uv_base.is_null() {
                                let Some(needed) = w.checked_mul(h).and_then(|n| n.checked_mul(4))
                                else {
                                    unlock_release_and_finish(frame.pixel_buffer, flags);
                                    return Ok(());
                                };
                                let y_slice_len = y_bpr.checked_mul(h).unwrap_or(0);
                                let uv_slice_len = uv_bpr.checked_mul(h.div_ceil(2)).unwrap_or(0);
                                if y_slice_len > 0 && uv_slice_len > 0 {
                                    let y_src = std::slice::from_raw_parts(
                                        y_base as *const u8,
                                        y_slice_len,
                                    );
                                    let uv_src = std::slice::from_raw_parts(
                                        uv_base as *const u8,
                                        uv_slice_len,
                                    );
                                    dst.reserve(needed);
                                    for row in 0..h {
                                        for col in 0..w {
                                            let y_idx = row * y_bpr + col;
                                            let uv_idx = (row / 2) * uv_bpr + (col / 2) * 2;
                                            let y_val = *y_src.get(y_idx).unwrap_or(&128) as f32;
                                            let u_val =
                                                *uv_src.get(uv_idx).unwrap_or(&128) as f32 - 128.0;
                                            let v_val = *uv_src.get(uv_idx + 1).unwrap_or(&128)
                                                as f32
                                                - 128.0;
                                            // Rec.709 full-range coefficients
                                            // (matches the default used by
                                            // VideoDecoder frames).
                                            let r =
                                                (y_val + 1.5748 * v_val).clamp(0.0, 255.0) as u8;
                                            let g = (y_val - 0.1873 * u_val - 0.4681 * v_val)
                                                .clamp(0.0, 255.0)
                                                as u8;
                                            let b =
                                                (y_val + 1.8556 * u_val).clamp(0.0, 255.0) as u8;
                                            dst.push(b); // BGRA
                                            dst.push(g);
                                            dst.push(r);
                                            dst.push(255);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            // Unknown format — no output for this frame.
                        }
                    }
                }

                vt_ffi::CVPixelBufferUnlockBaseAddress(frame.pixel_buffer, 0);
                vt_ffi::CVPixelBufferRelease(frame.pixel_buffer);

                if dst.is_empty() {
                    *flags = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
                } else {
                    sample.buffer = dst;
                    sample.sample_time = frame.pts;
                    sample.sample_duration = frame.duration;
                    *flags = 0;
                }
            }

            Ok(())
        }

        fn has_output(&self) -> bool {
            !lock_guard(&self.frame_queue).is_empty()
        }

        fn flush(&mut self) -> AppResult<()> {
            self.clear_frame_queue();
            Ok(())
        }
    }

    // Helper for the (rare) validation-failure paths in process_output:
    // unlock + release the pixel buffer and signal no sample.
    unsafe fn unlock_release_and_finish(pixel_buffer: CVPixelBufferRef, flags: &mut u32) {
        unsafe {
            vt_ffi::CVPixelBufferUnlockBaseAddress(pixel_buffer, 0);
            vt_ffi::CVPixelBufferRelease(pixel_buffer);
        }
        *flags = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
    }

    impl Drop for H264DecoderMft {
        fn drop(&mut self) {
            unsafe {
                if let Some(session) = self.session.take() {
                    // Invalidate first so no new callbacks can start, then
                    // drain and release the session.
                    vt_ffi::VTDecompressionSessionInvalidate(session);
                    let _ = vt_ffi::VTDecompressionSessionWaitForAsynchronousFrames(session);
                    vt_ffi::CFRelease(session as vt_ffi::CFTypeRef);
                }
                if let Some(desc) = self.format_desc.take() {
                    vt_ffi::CFRelease(desc as vt_ffi::CFTypeRef);
                }
            }
            self.reclaim_refcon();
            self.clear_frame_queue();
        }
    }

    impl Default for H264DecoderMft {
        fn default() -> Self {
            Self::new()
        }
    }
}

// Non-macOS stub for H264DecoderMft
#[cfg(not(target_os = "macos"))]
mod vt_decoder_mft {
    use super::*;
    pub struct H264DecoderMft;

    impl H264DecoderMft {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for H264DecoderMft {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MftTransform for H264DecoderMft {
        fn get_stream_count(&self) -> (u32, u32) {
            (1, 1)
        }
        fn set_input_type(&mut self, _: u32, _: &ImfMediaType) -> AppResult<()> {
            Ok(())
        }
        fn set_output_type(&mut self, _: u32, _: &ImfMediaType) -> AppResult<()> {
            Ok(())
        }
        fn get_input_available_type(&self, _: u32, _: u32) -> AppResult<ImfMediaType> {
            Ok(ImfMediaType::new())
        }
        fn get_output_available_type(&self, _: u32, _: u32) -> AppResult<ImfMediaType> {
            Ok(ImfMediaType::new())
        }
        fn process_input(&mut self, _: u32, _: &ImfSample, _: u32) -> AppResult<()> {
            Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "H.264 decoder requires macOS",
            ))
        }
        fn process_output(&mut self, _: u32, _: &mut ImfSample, f: &mut u32) -> AppResult<()> {
            *f = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
            Ok(())
        }
        fn has_output(&self) -> bool {
            false
        }
    }
}

pub use vt_decoder_mft::H264DecoderMft;

// ===========================================================================
// AAC Decoder MFT (macOS AudioToolbox)
// ===========================================================================

#[cfg(target_os = "macos")]
mod aac_decoder_mft {
    use super::*;

    type AudioConverterRef = *mut std::ffi::c_void;
    type AudioStreamBasicDescriptionPtr = *mut std::ffi::c_void;

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    struct AudioStreamBasicDescription {
        m_sample_rate: f64,
        m_format_id: u32,
        m_format_flags: u32,
        m_bytes_per_packet: u32,
        m_frames_per_packet: u32,
        m_bytes_per_frame: u32,
        m_channels_per_frame: u32,
        m_bits_per_channel: u32,
        m_reserved: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    struct AudioBuffer {
        m_number_channels: u32,
        m_data_byte_size: u32,
        m_data: *mut std::ffi::c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    struct AudioBufferList {
        m_number_buffers: u32,
        m_buffers: [AudioBuffer; 1],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    struct AudioStreamPacketDescription {
        m_start_offset: i64,
        m_variable_frames_in_packet: u32,
        m_data_byte_size: u32,
    }

    // AudioToolbox FourCC format IDs (not Media Foundation / WAVE values).
    const kAudioFormatMPEG4AAC: u32 = 0x6161_6320; // 'aac '
    const kAudioFormatLinearPCM: u32 = 0x6C70_636D; // 'lpcm'
    // CoreAudio PCM format flags (kAudioFormatFlagIsSignedInteger = 1<<2,
    // kAudioFormatFlagIsPacked = 1<<3): together they describe interleaved
    // little-endian signed integer PCM.
    const kAudioFormatFlagIsSignedInteger: u32 = 1 << 2;
    const kAudioFormatFlagIsPacked: u32 = 1 << 3;
    const noErr: i32 = 0;
    // kAudioConverterDecompressionMagicCookie ('dmgc') — the AudioSpecificConfig
    // (codec private data) the decoder needs for raw (non-ADTS) AAC frames.
    const kAudioConverterDecompressionMagicCookie: u32 = 0x646D_6763; // 'dmgc'

    #[link(name = "AudioToolbox", kind = "framework")]
    unsafe extern "C" {
        fn AudioConverterNew(
            in_source_format: AudioStreamBasicDescriptionPtr,
            in_destination_format: AudioStreamBasicDescriptionPtr,
            out_converter: *mut AudioConverterRef,
        ) -> i32;

        fn AudioConverterDispose(converter: AudioConverterRef) -> i32;

        fn AudioConverterFillComplexBuffer(
            in_audio_converter: AudioConverterRef,
            in_input_data_proc: AudioConverterComplexInputDataProc,
            in_input_data_proc_user_data: *mut std::ffi::c_void,
            io_output_data_packet_size: *mut u32,
            out_output_data: *mut AudioBufferList,
            out_packet_description: *mut AudioStreamPacketDescription,
        ) -> i32;

        fn AudioConverterSetProperty(
            in_audio_converter: AudioConverterRef,
            in_property_id: u32,
            in_property_data_size: u32,
            in_property_data: *const std::ffi::c_void,
        ) -> i32;
    }

    type AudioConverterComplexInputDataProc = unsafe extern "C" fn(
        AudioConverterRef,
        *mut u32,
        *mut AudioBufferList,
        *mut *mut AudioStreamPacketDescription,
        *mut std::ffi::c_void,
    ) -> i32;

    /// State handed to the decoder's `AudioConverterFillComplexBuffer` input
    /// proc: the compressed packet to feed, one packet at a time.
    struct InputDataContext {
        data: Vec<u8>,
        consumed: bool,
        packet_desc: AudioStreamPacketDescription,
    }

    /// A compressed AAC packet waiting to be decoded.
    struct PendingPacket {
        data: Vec<u8>,
        time: i64,
        duration: i64,
    }

    /// Decoded PCM ready for `process_output`, with the input sample's
    /// timestamp/duration preserved.
    struct DecodedPcm {
        pcm: Vec<u8>,
        time: i64,
        duration: i64,
    }

    /// Input proc for `AudioConverterFillComplexBuffer`: feeds exactly one
    /// compressed AAC packet per call.
    unsafe extern "C" fn fill_complex_input_proc(
        _in_audio_converter: AudioConverterRef,
        io_number_data_packets: *mut u32,
        io_data: *mut AudioBufferList,
        out_data_packet_description: *mut *mut AudioStreamPacketDescription,
        in_user_data: *mut std::ffi::c_void,
    ) -> i32 {
        let ctx = unsafe { &mut *(in_user_data as *mut InputDataContext) };
        let requested = unsafe { *io_number_data_packets };
        if ctx.consumed || ctx.data.is_empty() || requested == 0 {
            unsafe { *io_number_data_packets = 0 };
            return noErr;
        }
        let buffers = unsafe { &mut *io_data };
        if buffers.m_number_buffers == 0 {
            unsafe { *io_number_data_packets = 0 };
            return noErr;
        }
        let buffer = &mut buffers.m_buffers[0];
        let capacity = buffer.m_data_byte_size as usize;
        let n = ctx.data.len().min(capacity);
        if n > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(ctx.data.as_ptr(), buffer.m_data as *mut u8, n);
            }
        }
        buffer.m_data_byte_size = n as u32;
        if !out_data_packet_description.is_null() {
            unsafe {
                *out_data_packet_description =
                    &mut ctx.packet_desc as *mut AudioStreamPacketDescription;
            }
        }
        ctx.consumed = true;
        unsafe { *io_number_data_packets = 1 };
        noErr
    }

    /// AAC decoder using macOS AudioToolbox, implementing MftTransform.
    ///
    /// Input is compressed AAC (raw packets or ADTS); the input media type
    /// may carry the AudioSpecificConfig codec private data in
    /// `MF_MT_USER_DATA` (used as the decompression magic cookie). Each
    /// `process_input` decodes its packet synchronously via
    /// `AudioConverterFillComplexBuffer` and queues the PCM; `process_output`
    /// hands the decoded sample out with the input sample's time/duration.
    pub struct AacDecoderMft {
        converter: Option<AudioConverterRef>,
        input_desc: AudioStreamBasicDescription,
        output_desc: AudioStreamBasicDescription,
        channels: u32,
        sample_rate: f64,
        /// Codec private data (AudioSpecificConfig) from MF_MT_USER_DATA,
        /// applied as the decompression magic cookie.
        magic_cookie: Option<Vec<u8>>,
        /// Compressed packet being decoded.
        pending_input: Option<PendingPacket>,
        /// Decoded PCM samples awaiting `process_output`.
        pending_output: VecDeque<DecodedPcm>,
    }

    impl AacDecoderMft {
        /// Create a new AAC decoder MFT.
        pub fn new() -> Self {
            Self {
                converter: None,
                input_desc: unsafe { std::mem::zeroed() },
                output_desc: unsafe { std::mem::zeroed() },
                channels: 2,
                sample_rate: 44100.0,
                magic_cookie: None,
                pending_input: None,
                pending_output: VecDeque::new(),
            }
        }

        /// Decode one compressed packet into PCM via AudioConverterFillComplexBuffer.
        ///
        /// The converter is expected to exist (created in `process_input`).
        /// Decoded PCM is appended to `pending_output` with the input
        /// sample's time/duration, or nothing is queued when the converter
        /// produced no output (e.g. an empty packet).
        fn decode_packet(&mut self, packet: &PendingPacket) -> AppResult<()> {
            let Some(converter) = self.converter else {
                return Ok(());
            };
            if packet.data.is_empty() {
                return Ok(());
            }

            let frames_per_packet = self.input_desc.m_frames_per_packet.max(1) as usize;
            let bytes_per_frame = self.output_desc.m_bytes_per_frame.max(1) as usize;
            let out_capacity = frames_per_packet.saturating_mul(bytes_per_frame);
            let mut pcm = vec![0u8; out_capacity];

            let mut input_ctx = InputDataContext {
                data: packet.data.clone(),
                consumed: false,
                packet_desc: AudioStreamPacketDescription {
                    m_start_offset: 0,
                    m_variable_frames_in_packet: 0,
                    m_data_byte_size: packet.data.len() as u32,
                },
            };

            let mut buffer_list = AudioBufferList {
                m_number_buffers: 1,
                m_buffers: [AudioBuffer {
                    m_number_channels: 0,
                    m_data_byte_size: out_capacity as u32,
                    m_data: pcm.as_mut_ptr() as *mut std::ffi::c_void,
                }],
            };

            let mut packets = frames_per_packet as u32;
            let status = unsafe {
                AudioConverterFillComplexBuffer(
                    converter,
                    fill_complex_input_proc,
                    &mut input_ctx as *mut InputDataContext as *mut std::ffi::c_void,
                    &mut packets,
                    &mut buffer_list,
                    std::ptr::null_mut(),
                )
            };
            if status != noErr {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    format!("AAC decode failed with AudioToolbox status {status}"),
                ));
            }

            let produced = buffer_list.m_buffers[0].m_data_byte_size as usize;
            if produced == 0 || packets == 0 {
                // The converter buffered the input without producing output
                // yet; nothing to hand out.
                return Ok(());
            }
            pcm.truncate(produced);
            self.pending_output.push_back(DecodedPcm {
                pcm,
                time: packet.time,
                duration: packet.duration,
            });
            Ok(())
        }
    }

    // Safety: AacDecoderMft holds AudioConverterRef raw pointer. All access
    // is through MftTransform's &mut self methods, single-threaded.
    unsafe impl Send for AacDecoderMft {}

    impl Drop for AacDecoderMft {
        fn drop(&mut self) {
            if let Some(converter) = self.converter.take() {
                unsafe {
                    AudioConverterDispose(converter);
                }
            }
        }
    }

    impl Default for AacDecoderMft {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MftTransform for AacDecoderMft {
        fn get_stream_count(&self) -> (u32, u32) {
            (1, 1)
        }

        fn set_input_type(&mut self, _stream_id: u32, media_type: &ImfMediaType) -> AppResult<()> {
            let sample_rate = media_type.get_uint32(&MF_MT_SAMPLE_RATE).unwrap_or(44100);
            let channels = media_type.get_uint32(&MF_MT_CHANNELS).unwrap_or(2);

            self.sample_rate = sample_rate as f64;
            self.channels = channels;

            self.input_desc = AudioStreamBasicDescription {
                m_sample_rate: self.sample_rate,
                m_format_id: kAudioFormatMPEG4AAC,
                m_format_flags: 0,
                m_bytes_per_packet: 0,
                m_frames_per_packet: 1024,
                m_bytes_per_frame: 0,
                m_channels_per_frame: channels,
                m_bits_per_channel: 0,
                m_reserved: 0,
            };

            self.output_desc = AudioStreamBasicDescription {
                m_sample_rate: self.sample_rate,
                m_format_id: kAudioFormatLinearPCM,
                m_format_flags: kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked,
                m_bytes_per_packet: channels * 2, // 16-bit
                m_frames_per_packet: 1,
                m_bytes_per_frame: channels * 2,
                m_channels_per_frame: channels,
                m_bits_per_channel: 16,
                m_reserved: 0,
            };

            // Codec private data (AudioSpecificConfig) for raw AAC packets.
            self.magic_cookie = media_type.get_blob(&MF_MT_USER_DATA).map(|b| b.to_vec());

            // The input format may have changed: rebuild the converter lazily.
            if let Some(converter) = self.converter.take() {
                unsafe {
                    AudioConverterDispose(converter);
                }
            }

            Ok(())
        }

        fn set_output_type(&mut self, _stream_id: u32, media_type: &ImfMediaType) -> AppResult<()> {
            let sample_rate = media_type
                .get_uint32(&MF_MT_SAMPLE_RATE)
                .unwrap_or(self.sample_rate as u32);
            let channels = media_type
                .get_uint32(&MF_MT_CHANNELS)
                .unwrap_or(self.channels);
            let bits = media_type
                .get_uint32(&MF_MT_AUDIO_BITS_PER_SAMPLE)
                .unwrap_or(16);
            if bits != 16 && bits != 32 {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    format!(
                        "AAC decoder output type requires 16 or 32 bits per sample, got {bits}"
                    ),
                ));
            }

            self.sample_rate = sample_rate as f64;
            self.channels = channels;
            self.output_desc = AudioStreamBasicDescription {
                m_sample_rate: self.sample_rate,
                m_format_id: kAudioFormatLinearPCM,
                m_format_flags: kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked,
                m_bytes_per_packet: channels * bits / 8,
                m_frames_per_packet: 1,
                m_bytes_per_frame: channels * bits / 8,
                m_channels_per_frame: channels,
                m_bits_per_channel: bits,
                m_reserved: 0,
            };

            // The output format may have changed: rebuild the converter lazily.
            if let Some(converter) = self.converter.take() {
                unsafe {
                    AudioConverterDispose(converter);
                }
            }

            Ok(())
        }

        fn get_input_available_type(
            &self,
            _stream_id: u32,
            _index: u32,
        ) -> AppResult<ImfMediaType> {
            let mut mt = ImfMediaType::new();
            mt.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
            mt.set_guid(MF_MT_SUBTYPE, MFAudioFormat_AAC);
            mt.set_uint32(MF_MT_SAMPLE_RATE, self.sample_rate as u32);
            mt.set_uint32(MF_MT_CHANNELS, self.channels);
            Ok(mt)
        }

        fn get_output_available_type(
            &self,
            _stream_id: u32,
            _index: u32,
        ) -> AppResult<ImfMediaType> {
            let mut mt = ImfMediaType::new();
            mt.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
            mt.set_guid(MF_MT_SUBTYPE, MFAudioFormat_PCM);
            mt.set_uint32(MF_MT_SAMPLE_RATE, self.sample_rate as u32);
            mt.set_uint32(MF_MT_CHANNELS, self.channels);
            mt.set_uint32(
                MF_MT_AUDIO_BITS_PER_SAMPLE,
                self.output_desc.m_bits_per_channel,
            );
            Ok(mt)
        }

        fn process_input(
            &mut self,
            _stream_id: u32,
            sample: &ImfSample,
            _flags: u32,
        ) -> AppResult<()> {
            if self.converter.is_none() {
                unsafe {
                    let mut converter: AudioConverterRef = std::ptr::null_mut();
                    let status = AudioConverterNew(
                        &self.input_desc as *const _ as AudioStreamBasicDescriptionPtr,
                        &self.output_desc as *const _ as AudioStreamBasicDescriptionPtr,
                        &mut converter,
                    );
                    if status != noErr || converter.is_null() {
                        return Err(AppError::new(
                            ReasonCode::RcMediaInvalid,
                            format!("AudioConverterNew failed with status {status}"),
                        ));
                    }
                    // Apply the codec private data (AudioSpecificConfig) as
                    // the decompression magic cookie so raw (non-ADTS) AAC
                    // packets decode.
                    if let Some(cookie) = self.magic_cookie.as_deref() {
                        let set_status = AudioConverterSetProperty(
                            converter,
                            kAudioConverterDecompressionMagicCookie,
                            cookie.len() as u32,
                            cookie.as_ptr() as *const std::ffi::c_void,
                        );
                        if set_status != noErr {
                            AudioConverterDispose(converter);
                            return Err(AppError::new(
                                ReasonCode::RcMediaInvalid,
                                format!(
                                    "AudioConverterSetProperty(decompression magic cookie) \
                                     failed with status {set_status}"
                                ),
                            ));
                        }
                    }
                    self.converter = Some(converter);
                }
            }

            // Decode the compressed packet right away; the PCM (plus the
            // input sample's time/duration) is handed out by process_output.
            self.pending_input = Some(PendingPacket {
                data: sample.buffer.clone(),
                time: sample.sample_time,
                duration: sample.sample_duration,
            });
            let packet = self
                .pending_input
                .take()
                .expect("pending input set just above");
            self.decode_packet(&packet)
        }

        fn process_output(
            &mut self,
            _stream_id: u32,
            sample: &mut ImfSample,
            flags: &mut u32,
        ) -> AppResult<()> {
            let Some(decoded) = self.pending_output.pop_front() else {
                *flags = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
                return Ok(());
            };

            sample.buffer = decoded.pcm;
            sample.sample_time = decoded.time;
            sample.sample_duration = decoded.duration;
            *flags = 0;
            Ok(())
        }

        fn has_output(&self) -> bool {
            !self.pending_output.is_empty()
        }

        fn flush(&mut self) -> AppResult<()> {
            self.pending_input = None;
            self.pending_output.clear();
            Ok(())
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod aac_decoder_mft {
    use super::*;
    pub struct AacDecoderMft;

    impl AacDecoderMft {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for AacDecoderMft {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MftTransform for AacDecoderMft {
        fn get_stream_count(&self) -> (u32, u32) {
            (1, 1)
        }
        fn set_input_type(&mut self, _: u32, _: &ImfMediaType) -> AppResult<()> {
            Ok(())
        }
        fn set_output_type(&mut self, _: u32, _: &ImfMediaType) -> AppResult<()> {
            Ok(())
        }
        fn get_input_available_type(&self, _: u32, _: u32) -> AppResult<ImfMediaType> {
            Ok(ImfMediaType::new())
        }
        fn get_output_available_type(&self, _: u32, _: u32) -> AppResult<ImfMediaType> {
            Ok(ImfMediaType::new())
        }
        fn process_input(&mut self, _: u32, _: &ImfSample, _: u32) -> AppResult<()> {
            Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "AAC decoder requires macOS",
            ))
        }
        fn process_output(&mut self, _: u32, _: &mut ImfSample, f: &mut u32) -> AppResult<()> {
            *f = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
            Ok(())
        }
        fn has_output(&self) -> bool {
            false
        }
    }
}

pub use aac_decoder_mft::AacDecoderMft;

// ===========================================================================
// Topology types
// ===========================================================================

/// Types of topology nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyNodeType {
    /// Source node (media file / URL).
    Source,
    /// Decoder / transform node.
    Decoder,
    /// Renderer / sink node (e.g., Metal texture renderer).
    Renderer,
    /// Generic output node.
    Output,
}

/// A node in the Media Foundation topology.
#[derive(Debug, Clone)]
pub struct TopologyNode {
    /// Unique node ID.
    pub id: u64,
    /// Type of this node.
    pub node_type: TopologyNodeType,
    /// Name / description of this node.
    pub name: String,
    /// Upstream connections (node IDs of inputs feeding this node).
    pub inputs: Vec<u64>,
    /// Downstream connections (node IDs this node feeds into).
    pub outputs: Vec<u64>,
    /// Source URL (for source nodes).
    pub source_url: Option<String>,
    /// Output format (for decoder nodes).
    pub output_format: Option<String>,
}

impl TopologyNode {
    /// Create a new topology node.
    pub fn new(id: u64, node_type: TopologyNodeType, name: impl Into<String>) -> Self {
        Self {
            id,
            node_type,
            name: name.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            source_url: None,
            output_format: None,
        }
    }

    /// Connect this node's output to another node's input.
    pub fn connect_to(&mut self, other_id: u64) {
        if !self.outputs.contains(&other_id) {
            self.outputs.push(other_id);
        }
    }

    /// Connect another node as input to this node.
    pub fn connect_from(&mut self, other_id: u64) {
        if !self.inputs.contains(&other_id) {
            self.inputs.push(other_id);
        }
    }
}

/// A complete playback topology: source -> decoder -> renderer.
#[derive(Debug, Clone)]
pub struct Topology {
    /// All nodes in the topology.
    pub nodes: Vec<TopologyNode>,
    /// The source node ID (entry point).
    pub source_node_id: Option<u64>,
    /// The decoder node ID.
    pub decoder_node_id: Option<u64>,
    /// The renderer node ID (sink).
    pub renderer_node_id: Option<u64>,
    /// Next available node ID.
    next_id: u64,
}

impl Topology {
    /// Create a new empty topology.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            source_node_id: None,
            decoder_node_id: None,
            renderer_node_id: None,
            next_id: 1,
        }
    }

    /// Add a node to the topology.
    pub fn add_node(&mut self, node_type: TopologyNodeType, name: impl Into<String>) -> u64 {
        // Placeholder-compatible: the runtime dispatch records the node
        // object id in the node's own state; the topology's node table is
        // the id-keyed node list.
        let id = self.next_id;
        self.next_id += 1;
        let node = TopologyNode::new(id, node_type, name);
        self.nodes.push(node);
        id
    }

    /// Build a standard playback topology: source -> decoder -> renderer.
    pub fn build_playback_topology(
        &mut self,
        source_url: &str,
        decoder_name: &str,
        renderer_name: &str,
    ) -> AppResult<()> {
        // Source node
        let source_id = self.add_node(TopologyNodeType::Source, format!("Source: {source_url}"));
        if let Some(node) = self.nodes.iter_mut().find(|n| n.id == source_id) {
            node.source_url = Some(source_url.to_string());
        }
        self.source_node_id = Some(source_id);

        // Decoder node
        let decoder_id = self.add_node(TopologyNodeType::Decoder, decoder_name);
        if let Some(node) = self.nodes.iter_mut().find(|n| n.id == decoder_id) {
            node.output_format = Some("RGBA".to_string());
        }
        self.decoder_node_id = Some(decoder_id);

        // Renderer node
        let renderer_id = self.add_node(TopologyNodeType::Renderer, renderer_name);
        self.renderer_node_id = Some(renderer_id);

        // Wire up connections
        self.connect(source_id, decoder_id)?;
        self.connect(decoder_id, renderer_id)?;

        Ok(())
    }

    /// Connect two nodes (source -> target).
    pub fn connect(&mut self, from_id: u64, to_id: u64) -> AppResult<()> {
        let from_exists = self.nodes.iter().any(|n| n.id == from_id);
        let to_exists = self.nodes.iter().any(|n| n.id == to_id);

        if !from_exists {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                format!("Topology node {from_id} not found"),
            ));
        }
        if !to_exists {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                format!("Topology node {to_id} not found"),
            ));
        }

        if let Some(node) = self.nodes.iter_mut().find(|n| n.id == from_id) {
            node.connect_to(to_id);
        }
        if let Some(node) = self.nodes.iter_mut().find(|n| n.id == to_id) {
            node.connect_from(from_id);
        }

        Ok(())
    }

    /// Get a node by ID.
    pub fn get_node(&self, id: u64) -> Option<&TopologyNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Get the number of nodes in the topology.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Validate the topology: check that all nodes are connected in a chain.
    pub fn validate(&self) -> AppResult<()> {
        let source = self.source_node_id.ok_or_else(|| {
            AppError::new(ReasonCode::RcMediaInvalid, "Topology has no source node")
        })?;

        let source_node = self.get_node(source).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcMediaInvalid,
                "Source node not found in topology",
            )
        })?;

        if source_node.outputs.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "Source node has no outputs",
            ));
        }

        Ok(())
    }
}

impl Default for Topology {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Topology loader
// ===========================================================================

/// Resolves a topology by validating and preparing it for playback.
pub struct TopologyLoader;

impl TopologyLoader {
    /// Create a new topology loader.
    pub fn new() -> Self {
        Self
    }

    /// Load (resolve) a topology for playback.
    ///
    /// Validates the topology and returns any errors found.
    pub fn load(&self, topology: &Topology) -> AppResult<()> {
        topology.validate()?;
        // In a full implementation, this would resolve output types,
        // negotiate media types between nodes, insert decoders if needed,
        // and prepare the topology for streaming.
        Ok(())
    }

    /// Clear the topology loader state.
    pub fn clear(&self) {
        // No-op stub
    }
}

impl Default for TopologyLoader {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// MFCreateMediaSession
// ===========================================================================

/// Create a new Media Foundation session using the topology loader.
///
/// Corresponds to `MFCreateMediaSession` in the Windows MF API.
pub fn create_media_session() -> MfMediaSession {
    MfMediaSession::new()
}

/// Create a new Media Foundation session with custom configuration.
///
/// This is a convenience wrapper around `MFCreateMediaSession` that
/// allows passing initialization flags.
pub fn create_media_session_with_flags(_flags: u32) -> MfMediaSession {
    MfMediaSession::new()
}

// ===========================================================================
// MfMediaSession (Full Implementation)
// ===========================================================================

/// Media Foundation session wrapping the full state machine.
///
/// Supports:
/// - State machine: Idle -> Opening -> Playing <-> Paused -> Stopped -> Shutdown
/// - Topology setting and loading
/// - Event generation for session notifications
/// - Source -> Decoder -> Renderer pipeline management
pub struct MfMediaSession {
    /// Current session state.
    state: MfSessionState,
    /// Event queue for session notifications.
    event_queue: MfEventQueue,
    /// The current playback topology.
    topology: Option<Topology>,
    /// Topology loader for resolving topologies.
    topology_loader: TopologyLoader,
    /// Session start time (for position tracking).
    start_time: Option<std::time::Instant>,
    /// Elapsed time when paused (for resume position tracking).
    paused_elapsed: u64,
    /// The session's playback rate (IMFMediaSession rate-control service:
    /// MFGetService(MF_RATE_CONTROL_SERVICE)).  Position advances at
    /// `rate` x wall-clock while playing; the default session rate is 1.0.
    rate: f32,
    /// Source URL for the current media.
    source_url: Option<String>,
    /// Whether a topology has been set on this session.
    has_topology: bool,
}

impl MfMediaSession {
    /// Create a new Media Foundation session.
    ///
    /// The session starts in the `Idle` state.
    pub fn new() -> Self {
        Self {
            state: MfSessionState::Idle,
            event_queue: MfEventQueue::with_max(128),
            topology: None,
            topology_loader: TopologyLoader::new(),
            start_time: None,
            paused_elapsed: 0,
            rate: 1.0,
            source_url: None,
            has_topology: false,
        }
    }

    // =======================================================================
    // State machine methods
    // =======================================================================

    /// Start playback.
    ///
    /// Corresponds to `IMFMediaSession::Start`.
    /// Transitions: Idle -> Playing, Stopped -> Playing, Paused -> Playing
    pub fn start(&mut self) -> AppResult<()> {
        // Already playing: no-op without a duplicate SessionStarted event.
        if self.state == MfSessionState::Playing {
            return Ok(());
        }
        if !self.state.can_start() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("Cannot start from state {}", self.state.name()),
            ));
        }
        // Real Media Foundation rejects Start from Idle without a topology.
        if self.state == MfSessionState::Idle && !self.has_topology {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "Cannot start from Idle without a topology",
            ));
        }

        self.state = MfSessionState::Playing;
        self.start_time = Some(std::time::Instant::now());
        self.event_queue
            .queue_event_type(MediaEventType::SessionStarted);

        Ok(())
    }

    /// Pause playback.
    ///
    /// Corresponds to `IMFMediaSession::Pause`.
    /// Transitions: Playing -> Paused
    pub fn pause(&mut self) -> AppResult<()> {
        if !self.state.can_pause() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("Cannot pause from state {}", self.state.name()),
            ));
        }

        // Bank the position accrued at the current playback rate.
        self.bank_position();
        self.state = MfSessionState::Paused;
        self.event_queue
            .queue_event_type(MediaEventType::SessionPaused);

        Ok(())
    }

    /// Stop playback.
    ///
    /// Corresponds to `IMFMediaSession::Stop`.
    /// Transitions: Playing -> Stopped, Paused -> Stopped
    pub fn stop(&mut self) -> AppResult<()> {
        if !self.state.can_stop() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("Cannot stop from state {}", self.state.name()),
            ));
        }

        self.state = MfSessionState::Stopped;
        self.start_time = None;
        self.paused_elapsed = 0;
        self.event_queue
            .queue_event_type(MediaEventType::SessionStopped);

        Ok(())
    }

    /// Shutdown the session.
    ///
    /// Corresponds to `IMFMediaSession::Shutdown`.
    /// Transitions: any -> Shutdown
    pub fn shutdown(&mut self) -> AppResult<()> {
        if self.state == MfSessionState::Shutdown {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "Session is already shut down",
            ));
        }

        self.state = MfSessionState::Shutdown;
        self.start_time = None;
        self.paused_elapsed = 0;
        self.topology = None;
        self.event_queue
            .queue_event_type(MediaEventType::SessionShutdown);

        Ok(())
    }

    /// Set a topology on the session.
    ///
    /// Corresponds to `IMFMediaSession::SetTopology`.
    /// Remove the session's topology (the documented
    /// IMFMediaSession::ClearTopologies contract).
    pub fn clear_topologies(&mut self) {
        self.topology = None;
        self.has_topology = false;
    }

    pub fn set_topology(&mut self, topology: Topology) -> AppResult<()> {
        if !self.state.is_active() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "Cannot set topology on a shut-down session",
            ));
        }

        // Resolve the topology before committing it, so a failed load never
        // leaves the session with a topology and a missing TopologyLoaded
        // event.
        self.topology_loader.load(&topology)?;

        self.topology = Some(topology);
        self.has_topology = true;
        self.event_queue
            .queue_event_type(MediaEventType::TopologySet);
        self.event_queue
            .queue_event_type(MediaEventType::TopologyLoaded);

        Ok(())
    }

    /// Clear the current topology.
    pub fn clear_topology(&mut self) {
        self.topology = None;
        self.has_topology = false;
    }

    // =======================================================================
    // Event queue methods (IMFMediaEventGenerator-like)
    // =======================================================================

    /// Get the next pending event.
    ///
    /// Corresponds to `IMFMediaEventGenerator::GetEvent`.
    pub fn get_event(&mut self) -> Option<MediaEvent> {
        self.event_queue.get_event()
    }

    /// Peek at the next event without removing it.
    pub fn peek_event(&self) -> Option<&MediaEvent> {
        self.event_queue.peek_event()
    }

    /// Check if there are pending events.
    pub fn has_events(&self) -> bool {
        self.event_queue.has_events()
    }

    /// Get the number of pending events.
    pub fn event_count(&self) -> usize {
        self.event_queue.event_count()
    }

    /// Queue a custom event to the session's event queue.
    pub fn queue_event(&mut self, event: MediaEvent) {
        self.event_queue.queue_event(event);
    }

    // =======================================================================
    // Topology building helpers
    // =======================================================================

    /// Build a standard playback topology and set it on the session.
    ///
    /// Creates a source -> decoder -> renderer topology from the given URL.
    pub fn set_url_topology(&mut self, url: &str) -> AppResult<()> {
        let mut topology = Topology::new();
        topology.build_playback_topology(url, "Video Decoder", "Metal Texture Renderer")?;
        self.source_url = Some(url.to_string());
        self.set_topology(topology)
    }

    // =======================================================================
    // Playback-rate control (the session rate-control service)
    // =======================================================================

    /// Set the session's playback rate (IMFMediaSession rate-control
    /// service: `IMFRateControl::SetRate`).
    ///
    /// The rate applies to the position that accrues while the session is
    /// playing.  To keep the accrued-position accounting exact when the rate
    /// changes mid-play, the position reached so far is banked at the old
    /// rate and a fresh wall-clock interval starts at the new rate.
    pub fn set_rate(&mut self, rate: f32) {
        if !rate.is_finite() {
            return;
        }
        if self.state == MfSessionState::Playing {
            self.bank_position();
            self.start_time = Some(std::time::Instant::now());
        }
        self.rate = rate;
    }

    /// Get the session's current playback rate.
    pub fn get_rate(&self) -> f32 {
        self.rate
    }

    /// Bank the position accrued since the last start/resume at the current
    /// playback rate, leaving the wall-clock interval open for the caller.
    fn bank_position(&mut self) {
        if let Some(start) = self.start_time {
            let scaled = start.elapsed().as_micros() as f64 * self.rate as f64;
            self.paused_elapsed = (self.paused_elapsed as f64 + scaled) as u64;
        }
    }

    // =======================================================================
    // Query methods
    // =======================================================================

    /// Get the current session state.
    pub fn state(&self) -> MfSessionState {
        self.state
    }

    /// Get the current playback position in microseconds (since session start).
    pub fn get_position(&self) -> u64 {
        match self.state {
            MfSessionState::Playing => {
                let elapsed = self
                    .start_time
                    .map(|s| s.elapsed().as_micros() as f64 * self.rate as f64)
                    .unwrap_or(0.0);
                (self.paused_elapsed as f64 + elapsed) as u64
            }
            MfSessionState::Paused => self.paused_elapsed,
            _ => 0,
        }
    }

    /// Get the current topology.
    pub fn topology(&self) -> Option<&Topology> {
        self.topology.as_ref()
    }

    /// Get the source URL if set.
    pub fn source_url(&self) -> Option<&str> {
        self.source_url.as_deref()
    }

    /// Check if the session is active (not shut down).
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

impl Default for MfMediaSession {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// MP4 Demuxer (ISO Base Media File Format Parser)
// ===========================================================================

/// An MP4 sample (frame or audio packet).
#[derive(Debug, Clone)]
pub struct Mp4Sample {
    pub offset: u64,
    pub size: u32,
    pub duration: u32,
    pub pts: u64,
    pub is_sync: bool,
}

/// An MP4 track (video or audio).
#[derive(Debug, Clone)]
pub struct Mp4Track {
    pub id: u32,
    pub media_type: ImfMediaType,
    pub samples: Vec<Mp4Sample>,
    pub current_index: usize,
    pub timescale: u32,
    pub duration: u64,
}

/// ISO Base Media File Format (MP4) demuxer.
///
/// Parses ftyp, moov (trak/tkhd/mdhd/hdlr/minf/stbl/stsd/stts/stss/stsc/stsz/stco),
/// and mdat boxes to extract audio/video tracks and samples.
pub struct Mp4Demuxer {
    file: Vec<u8>,
    position: usize,
    tracks: Vec<Mp4Track>,
}

/// Raw sample-table data collected while walking `stbl`.
///
/// Box order inside `stbl` is not guaranteed by the spec, so the tables are
/// collected first and the per-sample tables are built afterwards.
#[derive(Default)]
struct SampleTableRaw {
    /// stts entries: (sample_count, sample_delta)
    stts: Vec<(u32, u32)>,
    /// stss entries: 1-based sync sample numbers (sorted)
    stss: Vec<u32>,
    /// stsc entries: (first_chunk, samples_per_chunk)
    stsc: Vec<(u32, u32)>,
    /// stsz default sample size (0 = per-sample sizes)
    stsz_default: u32,
    /// stsz per-sample sizes (used when the default size is 0)
    stsz_sizes: Vec<u32>,
    /// stsz sample count (authoritative sample count)
    stsz_sample_count: u32,
    /// stco chunk offsets
    stco: Vec<u64>,
}

/// Cap on the number of samples built per track. A crafted header can claim
/// up to 2^32 samples; the cap keeps the derived allocations proportional to
/// a sane stream (~8M samples is >3 days of video at 24 fps).
const MAX_MP4_SAMPLES: usize = 8_000_000;

impl Mp4Demuxer {
    /// Create a new MP4 demuxer from file data.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            file: data,
            position: 0,
            tracks: Vec::new(),
        }
    }

    fn invalid(&self, message: &str) -> AppError {
        AppError::new(ReasonCode::RcMediaInvalid, message.to_string())
    }

    /// Parse the entire MP4 file structure.
    pub fn parse(&mut self) -> AppResult<()> {
        while self.position < self.file.len() {
            self.read_box()?;
        }
        if self.tracks.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "No tracks found in MP4",
            ));
        }
        Ok(())
    }

    /// Read a single box at the current position.
    fn read_box(&mut self) -> AppResult<()> {
        if self.position + 8 > self.file.len() {
            return Err(self.invalid("Truncated MP4 box header"));
        }

        let size = u32::from_be_bytes([
            self.file[self.position],
            self.file[self.position + 1],
            self.file[self.position + 2],
            self.file[self.position + 3],
        ]) as u64;

        let box_type = &self.file[self.position + 4..self.position + 8];

        let (header_size, actual_size) = if size == 0 {
            // Box extends to end of file
            (8usize, (self.file.len() - self.position) as u64)
        } else if size == 1 {
            // 64-bit size
            if self.position + 16 > self.file.len() {
                return Err(self.invalid("Truncated 64-bit MP4 box size"));
            }
            let size64 = u64::from_be_bytes([
                self.file[self.position + 8],
                self.file[self.position + 9],
                self.file[self.position + 10],
                self.file[self.position + 11],
                self.file[self.position + 12],
                self.file[self.position + 13],
                self.file[self.position + 14],
                self.file[self.position + 15],
            ]);
            (16usize, size64)
        } else {
            (8usize, size)
        };

        let box_start = self.position;
        // All sizes come from the untrusted container: validate against the
        // file length (checked arithmetic, no wrapping).
        let box_end = match box_start.checked_add(actual_size as usize) {
            Some(end) if end <= self.file.len() => end,
            _ => return Err(self.invalid("MP4 box extends beyond file")),
        };

        // Point the reader at the payload and recurse into container boxes.
        self.position = box_start + header_size;
        match box_type {
            b"ftyp" => { /* file type - skip */ }
            b"moov" => {
                self.read_moov(box_end)?;
            }
            b"moof" => {
                // Basic fragmented MP4: track fragment runs and sequence
                // numbers so the reader can locate moof-based data references.
                self.read_moof(box_end)?;
            }
            b"mdat" | b"free" | b"skip" => { /* skip */ }
            _ => { /* unknown - skip */ }
        }

        self.position = box_end;
        Ok(())
    }

    /// Parse moov box (movie metadata), bounded by its own `parent_end`.
    fn read_moov(&mut self, parent_end: usize) -> AppResult<()> {
        while self.position + 8 <= parent_end && self.position + 8 <= self.file.len() {
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                return Err(self.invalid("Invalid MP4 moov child box size"));
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = match self.position.checked_add(child_size) {
                Some(end) if end <= parent_end && end <= self.file.len() => end,
                _ => return Err(self.invalid("MP4 moov child box overruns its parent")),
            };

            match child_type {
                b"trak" => {
                    // `read_trak` expects the reader positioned at the trak
                    // payload, so step over this box's own header first.
                    self.position += 8;
                    let track = self.read_trak(child_end)?;
                    self.tracks.push(track);
                }
                b"mvhd" => { /* movie header - skip */ }
                _ => {}
            }

            self.position = child_end;
        }
        Ok(())
    }

    /// Parse moof box (movie fragment), bounded by its own `parent_end`.
    fn read_moof(&mut self, parent_end: usize) -> AppResult<()> {
        while self.position + 8 <= parent_end && self.position + 8 <= self.file.len() {
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                return Err(self.invalid("Invalid MP4 moof child box size"));
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = match self.position.checked_add(child_size) {
                Some(end) if end <= parent_end && end <= self.file.len() => end,
                _ => return Err(self.invalid("MP4 moof child box overruns its parent")),
            };

            match child_type {
                b"traf" => {
                    // Track fragment: contains tfhd + trun boxes.
                    // Skipped for now (fragmented streams are not decoded).
                }
                b"mfhd" => {
                    // Movie fragment header: sequence number follows the
                    // version/flags field. Skipped.
                }
                _ => {}
            }

            self.position = child_end;
        }
        Ok(())
    }

    /// Parse a trak box, bounded by its own `parent_end`.
    fn read_trak(&mut self, parent_end: usize) -> AppResult<Mp4Track> {
        let mut track = Mp4Track {
            id: 0,
            media_type: ImfMediaType::new(),
            samples: Vec::new(),
            current_index: 0,
            timescale: 0,
            duration: 0,
        };

        while self.position + 8 <= parent_end && self.position + 8 <= self.file.len() {
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                return Err(self.invalid("Invalid MP4 trak child box size"));
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = match self.position.checked_add(child_size) {
                Some(end) if end <= parent_end && end <= self.file.len() => end,
                _ => return Err(self.invalid("MP4 trak child box overruns its parent")),
            };

            match child_type {
                b"tkhd" => {
                    // Track header: version(1) + flags(3) + ... + track_id(4)
                    // track_id is at +20 (v0) or +28 (v1) relative to the box.
                    if child_size >= 12 {
                        let ver = self.file[self.position + 8];
                        let track_id_offset = if ver == 1 { 20 } else { 12 };
                        if child_size >= 8 + track_id_offset + 4 {
                            let id_bytes: [u8; 4] = [
                                self.file[self.position + 8 + track_id_offset],
                                self.file[self.position + 9 + track_id_offset],
                                self.file[self.position + 10 + track_id_offset],
                                self.file[self.position + 11 + track_id_offset],
                            ];
                            track.id = u32::from_be_bytes(id_bytes);
                        }
                    }
                }
                b"mdia" => {
                    // `read_mdia` expects the mdia payload.
                    self.position += 8;
                    self.read_mdia(&mut track, child_end)?;
                }
                _ => {}
            }

            self.position = child_end;
        }

        Ok(track)
    }

    /// Parse mdia box inside trak, bounded by its own `parent_end`.
    fn read_mdia(&mut self, track: &mut Mp4Track, parent_end: usize) -> AppResult<()> {
        while self.position + 8 <= parent_end && self.position + 8 <= self.file.len() {
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                return Err(self.invalid("Invalid MP4 mdia child box size"));
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = match self.position.checked_add(child_size) {
                Some(end) if end <= parent_end && end <= self.file.len() => end,
                _ => return Err(self.invalid("MP4 mdia child box overruns its parent")),
            };

            match child_type {
                b"mdhd" => {
                    // Media header: version(1) + flags(3) + timescale(4)
                    // timescale is at +20 (v0) or +28 (v1), duration after it.
                    if child_size >= 12 {
                        let ver = self.file[self.position + 8];
                        let ts_offset = if ver == 1 { 20 } else { 12 };
                        if child_size >= 8 + ts_offset + 8 {
                            let ts_bytes: [u8; 4] = [
                                self.file[self.position + 8 + ts_offset],
                                self.file[self.position + 9 + ts_offset],
                                self.file[self.position + 10 + ts_offset],
                                self.file[self.position + 11 + ts_offset],
                            ];
                            track.timescale = u32::from_be_bytes(ts_bytes);
                            let dur_bytes: [u8; 4] = [
                                self.file[self.position + 8 + ts_offset + 4],
                                self.file[self.position + 9 + ts_offset + 4],
                                self.file[self.position + 10 + ts_offset + 4],
                                self.file[self.position + 11 + ts_offset + 4],
                            ];
                            track.duration = u32::from_be_bytes(dur_bytes) as u64;
                        }
                    }
                }
                b"hdlr" => {
                    // Handler reference: handler_type at box+16..+20.
                    if child_size >= 20 {
                        let handler = &self.file[self.position + 16..self.position + 20];
                        match handler {
                            b"vide" => {
                                track
                                    .media_type
                                    .set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Video);
                                track.media_type.set_guid(MF_MT_SUBTYPE, MFVideoFormat_H264);
                            }
                            b"soun" => {
                                track
                                    .media_type
                                    .set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
                                track.media_type.set_guid(MF_MT_SUBTYPE, MFAudioFormat_AAC);
                            }
                            _ => {}
                        }
                    }
                }
                b"minf" => {
                    // `read_minf` expects the minf payload.
                    self.position += 8;
                    self.read_minf(track, child_end)?;
                }
                _ => {}
            }

            self.position = child_end;
        }
        Ok(())
    }

    /// Parse minf box, bounded by its own `parent_end`.
    fn read_minf(&mut self, track: &mut Mp4Track, parent_end: usize) -> AppResult<()> {
        while self.position + 8 <= parent_end && self.position + 8 <= self.file.len() {
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                return Err(self.invalid("Invalid MP4 minf child box size"));
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = match self.position.checked_add(child_size) {
                Some(end) if end <= parent_end && end <= self.file.len() => end,
                _ => return Err(self.invalid("MP4 minf child box overruns its parent")),
            };

            if child_type == b"stbl" {
                // `read_stbl` expects the stbl payload.
                self.position += 8;
                self.read_stbl(track, child_end)?;
            }

            self.position = child_end;
        }
        Ok(())
    }

    /// Parse stbl (sample table) box, bounded by its own `parent_end`.
    ///
    /// Collects the raw stts/stss/stsc/stsz/stco tables, then builds the
    /// per-sample tables (offsets, durations, PTS, sync flags).
    fn read_stbl(&mut self, track: &mut Mp4Track, parent_end: usize) -> AppResult<()> {
        let mut raw = SampleTableRaw::default();

        while self.position + 8 <= parent_end && self.position + 8 <= self.file.len() {
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                return Err(self.invalid("Invalid MP4 stbl child box size"));
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = match self.position.checked_add(child_size) {
                Some(end) if end <= parent_end && end <= self.file.len() => end,
                _ => return Err(self.invalid("MP4 stbl child box overruns its parent")),
            };

            match child_type {
                b"stts" => {
                    // version/flags(4) + entry_count(4) at +8..16; entries are
                    // (sample_count, sample_delta), 8 bytes each, at +16.
                    if child_size >= 16 {
                        let entry_count = u32::from_be_bytes([
                            self.file[self.position + 12],
                            self.file[self.position + 13],
                            self.file[self.position + 14],
                            self.file[self.position + 15],
                        ]) as usize;
                        let Some(needed) = 16usize.checked_add(entry_count.saturating_mul(8))
                        else {
                            return Err(self.invalid("stts entry count overflows"));
                        };
                        if child_size >= needed {
                            let mut entries = Vec::with_capacity(entry_count);
                            for i in 0..entry_count {
                                let off = self.position + 16 + i * 8;
                                let count = u32::from_be_bytes([
                                    self.file[off],
                                    self.file[off + 1],
                                    self.file[off + 2],
                                    self.file[off + 3],
                                ]);
                                let delta = u32::from_be_bytes([
                                    self.file[off + 4],
                                    self.file[off + 5],
                                    self.file[off + 6],
                                    self.file[off + 7],
                                ]);
                                entries.push((count, delta));
                            }
                            raw.stts = entries;
                        } else {
                            return Err(self.invalid("stts table overruns its box"));
                        }
                    }
                }
                b"stss" => {
                    // version/flags(4) + entry_count(4) at +8..16; entries are
                    // 1-based sync sample numbers, 4 bytes each, at +16.
                    if child_size >= 16 {
                        let entry_count = u32::from_be_bytes([
                            self.file[self.position + 12],
                            self.file[self.position + 13],
                            self.file[self.position + 14],
                            self.file[self.position + 15],
                        ]) as usize;
                        let Some(needed) = 16usize.checked_add(entry_count.saturating_mul(4))
                        else {
                            return Err(self.invalid("stss entry count overflows"));
                        };
                        if child_size >= needed {
                            let mut entries = Vec::with_capacity(entry_count);
                            for i in 0..entry_count {
                                let off = self.position + 16 + i * 4;
                                entries.push(u32::from_be_bytes([
                                    self.file[off],
                                    self.file[off + 1],
                                    self.file[off + 2],
                                    self.file[off + 3],
                                ]));
                            }
                            raw.stss = entries;
                        } else {
                            return Err(self.invalid("stss table overruns its box"));
                        }
                    }
                }
                b"stsc" => {
                    // version/flags(4) + entry_count(4) at +8..16; entries are
                    // (first_chunk, samples_per_chunk, sample_description_index),
                    // 12 bytes each, at +16.
                    if child_size >= 16 {
                        let entry_count = u32::from_be_bytes([
                            self.file[self.position + 12],
                            self.file[self.position + 13],
                            self.file[self.position + 14],
                            self.file[self.position + 15],
                        ]) as usize;
                        let Some(needed) = 16usize.checked_add(entry_count.saturating_mul(12))
                        else {
                            return Err(self.invalid("stsc entry count overflows"));
                        };
                        if child_size >= needed {
                            let mut entries = Vec::with_capacity(entry_count);
                            for i in 0..entry_count {
                                let off = self.position + 16 + i * 12;
                                let first_chunk = u32::from_be_bytes([
                                    self.file[off],
                                    self.file[off + 1],
                                    self.file[off + 2],
                                    self.file[off + 3],
                                ]);
                                let samples_per_chunk = u32::from_be_bytes([
                                    self.file[off + 4],
                                    self.file[off + 5],
                                    self.file[off + 6],
                                    self.file[off + 7],
                                ]);
                                entries.push((first_chunk, samples_per_chunk));
                            }
                            raw.stsc = entries;
                        } else {
                            return Err(self.invalid("stsc table overruns its box"));
                        }
                    }
                }
                b"stsz" => {
                    // version/flags(4) at +8; sample_size at +12;
                    // sample_count at +16; per-sample sizes at +20 (4 each).
                    if child_size >= 20 {
                        let default_size = u32::from_be_bytes([
                            self.file[self.position + 12],
                            self.file[self.position + 13],
                            self.file[self.position + 14],
                            self.file[self.position + 15],
                        ]);
                        let sample_count = u32::from_be_bytes([
                            self.file[self.position + 16],
                            self.file[self.position + 17],
                            self.file[self.position + 18],
                            self.file[self.position + 19],
                        ]);
                        raw.stsz_default = default_size;
                        raw.stsz_sample_count = sample_count;
                        if default_size == 0 {
                            let count = sample_count as usize;
                            let Some(needed) = 20usize.checked_add(count.saturating_mul(4)) else {
                                return Err(self.invalid("stsz sample count overflows"));
                            };
                            if child_size >= needed {
                                let mut sizes = Vec::with_capacity(count);
                                for i in 0..count {
                                    let off = self.position + 20 + i * 4;
                                    sizes.push(u32::from_be_bytes([
                                        self.file[off],
                                        self.file[off + 1],
                                        self.file[off + 2],
                                        self.file[off + 3],
                                    ]));
                                }
                                raw.stsz_sizes = sizes;
                            } else {
                                return Err(self.invalid("stsz table overruns its box"));
                            }
                        }
                    }
                }
                b"stco" if child_size >= 16 => {
                    // version/flags(4) at +8; entry_count at +12; chunk
                    // offsets (4 bytes each) at +16.
                    let entry_count = u32::from_be_bytes([
                        self.file[self.position + 12],
                        self.file[self.position + 13],
                        self.file[self.position + 14],
                        self.file[self.position + 15],
                    ]) as usize;
                    let Some(needed) = 16usize.checked_add(entry_count.saturating_mul(4)) else {
                        return Err(self.invalid("stco entry count overflows"));
                    };
                    if child_size >= needed {
                        let mut offsets = Vec::with_capacity(entry_count);
                        for i in 0..entry_count {
                            let off = self.position + 16 + i * 4;
                            offsets.push(u32::from_be_bytes([
                                self.file[off],
                                self.file[off + 1],
                                self.file[off + 2],
                                self.file[off + 3],
                            ]) as u64);
                        }
                        raw.stco = offsets;
                    } else {
                        return Err(self.invalid("stco table overruns its box"));
                    }
                }
                _ => { /* stsd etc. - skip */ }
            }

            self.position = child_end;
        }

        self.build_samples(&raw, track);
        Ok(())
    }

    /// Build the per-sample tables from the raw stbl data.
    ///
    /// Walks chunk offsets (stco), groups samples into chunks (stsc), sizes
    /// them (stsz), and derives durations/PTS (stts) and sync flags (stss).
    fn build_samples(&self, raw: &SampleTableRaw, track: &mut Mp4Track) {
        track.samples.clear();
        let total = raw.stsz_sample_count as usize;
        if total == 0 || raw.stco.is_empty() {
            // Without chunk offsets there is no way to locate sample data.
            return;
        }
        let count = total.min(MAX_MP4_SAMPLES);

        let mut samples = Vec::with_capacity(count.min(raw.stco.len() * 16));
        let mut stsc_run = 0usize;
        let mut stts_run = 0usize;
        let mut stts_left = 0u32;
        let mut stts_delta = 0u32;
        let mut pts: u64 = 0;
        let mut global = 0usize;

        for (chunk_idx, &chunk_offset) in raw.stco.iter().enumerate() {
            // Advance to the stsc run covering this 1-based chunk number.
            while stsc_run + 1 < raw.stsc.len() && chunk_idx as u32 + 1 >= raw.stsc[stsc_run + 1].0
            {
                stsc_run += 1;
            }
            let per_chunk = match raw.stsc.get(stsc_run) {
                Some(&(first_chunk, samples_per_chunk)) if chunk_idx as u32 + 1 >= first_chunk => {
                    samples_per_chunk as usize
                }
                _ => 1,
            };

            let mut offset = chunk_offset;
            for _ in 0..per_chunk {
                if global >= count {
                    break;
                }
                let size = if raw.stsz_default > 0 {
                    raw.stsz_default
                } else {
                    raw.stsz_sizes.get(global).copied().unwrap_or(0)
                };
                if stts_left == 0 {
                    if let Some(&(run_count, run_delta)) = raw.stts.get(stts_run) {
                        stts_run += 1;
                        stts_left = run_count;
                        stts_delta = run_delta;
                    } else {
                        stts_delta = 0;
                    }
                }
                stts_left = stts_left.saturating_sub(1);

                samples.push(Mp4Sample {
                    offset,
                    size,
                    duration: stts_delta,
                    pts,
                    is_sync: raw.stss.binary_search(&((global + 1) as u32)).is_ok(),
                });
                pts = pts.wrapping_add(stts_delta as u64);
                offset = offset.wrapping_add(size as u64);
                global += 1;
            }
            if global >= count {
                break;
            }
        }

        track.samples = samples;
    }

    /// Get the number of tracks.
    pub fn track_count(&self) -> usize {
        self.tracks.len()
    }

    /// Get a reference to all tracks.
    pub fn tracks(&self) -> &[Mp4Track] {
        &self.tracks
    }

    /// Get a specific track by index.
    pub fn get_track(&self, index: usize) -> Option<&Mp4Track> {
        self.tracks.get(index)
    }

    /// Get a mutable reference to a specific track.
    pub fn get_track_mut(&mut self, index: usize) -> Option<&mut Mp4Track> {
        self.tracks.get_mut(index)
    }

    /// Read a sample's data from the file.
    pub fn read_sample_data(&self, sample: &Mp4Sample) -> AppResult<Vec<u8>> {
        let start = sample.offset as usize;
        let end = start + sample.size as usize;
        if end > self.file.len() {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                format!(
                    "Sample data at {start} size {} exceeds file length {}",
                    sample.size,
                    self.file.len()
                ),
            ));
        }
        Ok(self.file[start..end].to_vec())
    }

    /// Get the next sample for a track.
    pub fn next_sample(&mut self, track_index: usize) -> Option<Mp4Sample> {
        let track = self.tracks.get_mut(track_index)?;
        if track.current_index >= track.samples.len() {
            return None;
        }
        let sample = track.samples[track.current_index].clone();
        track.current_index += 1;
        Some(sample)
    }

    /// Seek to a specific position (in track time units).
    pub fn seek(&mut self, track_index: usize, position: u64) {
        if let Some(track) = self.tracks.get_mut(track_index) {
            for (i, sample) in track.samples.iter().enumerate() {
                if sample.pts >= position {
                    track.current_index = i;
                    return;
                }
            }
            track.current_index = track.samples.len(); // past end
        }
    }
}

// ===========================================================================
// MFCreateSourceReader
// ===========================================================================

/// Media Foundation Source Reader.
///
/// Reads media samples from a file, demuxing and optionally decoding.
/// Mirrors IMFSourceReader functionality.
#[allow(dead_code)] // MFT decoder slot for future media-foundation transform
pub struct SourceReader {
    demuxer: Mp4Demuxer,
    selected_streams: Vec<u32>,
    decoder: Option<Box<dyn MftTransform>>,
    /// The guest IMFMediaSource object this reader pulls from (0 when the
    /// reader was created without a source).
    source: u64,
    /// The negotiated current media type per stream (absent = the native
    /// track type).
    current_types: HashMap<u32, ImfMediaType>,
    /// The real container metadata tags parsed from the file.
    metadata: MfMetadataTags,
}

impl SourceReader {
    /// An empty source reader (no data — the deterministic headless
    /// source model).
    pub fn empty() -> Self {
        Self {
            demuxer: Mp4Demuxer::new(Vec::new()),
            selected_streams: Vec::new(),
            decoder: None,
            source: 0,
            current_types: HashMap::new(),
            metadata: MfMetadataTags::default(),
        }
    }

    /// Create a new source reader from a file path.
    pub fn from_url(url: &str) -> AppResult<Self> {
        let data = std::fs::read(url).map_err(|e| {
            AppError::new(
                ReasonCode::RcMediaInvalid,
                format!("Failed to read {url}: {e}"),
            )
        })?;
        Self::from_data(data)
    }

    /// Create a new source reader from in-memory data.
    pub fn from_data(data: Vec<u8>) -> AppResult<Self> {
        let metadata = MfMetadataTags::parse_mp4(&data);
        let mut demuxer = Mp4Demuxer::new(data);
        demuxer.parse()?;
        Ok(Self {
            demuxer,
            selected_streams: Vec::new(),
            decoder: None,
            source: 0,
            current_types: HashMap::new(),
            metadata,
        })
    }

    /// The real presentation descriptor parsed from the underlying file.
    pub fn presentation(
        &self,
        file_size: u64,
        mime_type: Option<&str>,
    ) -> MfPresentationDescriptor {
        MfPresentationDescriptor::from_mp4(&self.demuxer, file_size, mime_type)
    }

    /// The guest media-source object this reader pulls from.
    pub fn source(&self) -> u64 {
        self.source
    }

    /// The real container metadata tags parsed from the reader's payload.
    pub fn metadata(&self) -> &MfMetadataTags {
        &self.metadata
    }

    /// Wire this reader to its source object (the graph edge the runtime
    /// reports through `GetServiceForStream` and the EOF notification).
    pub fn set_source(&mut self, source: u64) {
        self.source = source;
    }

    /// Resolve an IMFSourceReader stream index (`MF_SOURCE_READER_*`) to the
    /// concrete demuxer track index.
    pub fn resolve_stream_index(&self, stream_index: u32) -> Option<u32> {
        match stream_index {
            0xFFFF_FFFF => None, // MF_SOURCE_READER_INVALID_STREAM_INDEX
            0xFFFF_FFFE => {
                // MF_SOURCE_READER_ANY_STREAM: the first selected stream.
                if self.selected_streams.is_empty() {
                    (self.demuxer.track_count() > 0).then_some(0)
                } else {
                    self.selected_streams.first().copied()
                }
            }
            0xFFFF_FFFC => {
                // MF_SOURCE_READER_FIRST_VIDEO_STREAM
                self.demuxer
                    .tracks()
                    .iter()
                    .position(|track| track.media_type.is_video())
                    .map(|index| index as u32)
            }
            0xFFFF_FFFD => {
                // MF_SOURCE_READER_FIRST_AUDIO_STREAM
                self.demuxer
                    .tracks()
                    .iter()
                    .position(|track| track.media_type.is_audio())
                    .map(|index| index as u32)
            }
            index => ((index as usize) < self.demuxer.track_count()).then_some(index),
        }
    }

    /// Select a stream for reading.
    pub fn select_stream(&mut self, stream_index: u32) {
        // MF uses MF_SOURCE_READER_FIRST_VIDEO_STREAM, etc.
        if stream_index == 0xFFFF_FFFC {
            // MF_SOURCE_READER_FIRST_VIDEO_STREAM: select first video track
            for (i, track) in self.demuxer.tracks().iter().enumerate() {
                if track.media_type.is_video() {
                    self.selected_streams.push(i as u32);
                    return;
                }
            }
        } else if stream_index == 0xFFFF_FFFD {
            // MF_SOURCE_READER_FIRST_AUDIO_STREAM: select first audio track
            for (i, track) in self.demuxer.tracks().iter().enumerate() {
                if track.media_type.is_audio() {
                    self.selected_streams.push(i as u32);
                    return;
                }
            }
        } else {
            self.selected_streams.push(stream_index);
        }
    }

    /// Whether a stream is currently selected (IMFSourceReader::GetStreamSelection).
    pub fn get_stream_selection(&self, stream_index: u32) -> bool {
        if self.selected_streams.is_empty() {
            return stream_index < self.demuxer.track_count() as u32;
        }
        self.selected_streams.contains(&stream_index)
    }

    /// Set a stream's selection state (IMFSourceReader::SetStreamSelection).
    /// `MF_SOURCE_READER_ALL_STREAMS`/`ANY_STREAM` select/deselect every
    /// stream; `FIRST_VIDEO_STREAM`/`FIRST_AUDIO_STREAM` resolve to the
    /// first matching track.
    pub fn set_stream_selection(&mut self, stream_index: u32, selected: bool) {
        match stream_index {
            0xFFFF_FFFE => {
                // MF_SOURCE_READER_ALL_STREAMS / ANY_STREAM
                self.selected_streams.clear();
                if selected {
                    self.selected_streams = (0..self.demuxer.track_count() as u32).collect();
                }
            }
            index => {
                let Some(track) = self.resolve_stream_index(index) else {
                    return;
                };
                if selected {
                    if !self.selected_streams.contains(&track) {
                        self.selected_streams.push(track);
                    }
                } else {
                    self.selected_streams.retain(|entry| *entry != track);
                }
            }
        }
    }

    /// Get the current media type for a stream: the negotiated current type
    /// when one was set, otherwise the track's native type.
    pub fn get_current_media_type(&self, stream_index: u32) -> AppResult<ImfMediaType> {
        let idx = stream_index as usize;
        if let Some(track) = self.demuxer.get_track(idx) {
            Ok(self
                .current_types
                .get(&stream_index)
                .cloned()
                .unwrap_or_else(|| track.media_type.clone()))
        } else {
            Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                format!("Stream {stream_index} not found"),
            ))
        }
    }

    /// Number of tracks (streams) in the underlying source.
    pub fn track_count(&self) -> usize {
        self.demuxer.track_count()
    }

    /// Set the current media type for a stream (output type).  A type whose
    /// major type differs from the track's native type is rejected.
    pub fn set_current_media_type(
        &mut self,
        stream_index: u32,
        media_type: &ImfMediaType,
    ) -> AppResult<()> {
        let Some(track) = self.demuxer.get_track(stream_index as usize) else {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                format!("Stream {stream_index} not found"),
            ));
        };
        if media_type.get_guid(&MF_MT_MAJOR_TYPE) != track.media_type.get_guid(&MF_MT_MAJOR_TYPE) {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "media type major type does not match the stream",
            ));
        }
        self.current_types.insert(stream_index, media_type.clone());
        Ok(())
    }

    /// Convert a timestamp in track time units to 100-ns units, saturating
    /// instead of overflowing the i64 sample time.
    fn to_hns(value: u64, scale: u64) -> i64 {
        let scale = scale.max(1) as u128;
        i64::try_from((value as u128 * 10_000_000) / scale).unwrap_or(i64::MAX)
    }

    /// Read the next sample from the given stream.
    pub fn read_sample(&mut self, stream_index: u32) -> AppResult<Option<ImfSample>> {
        let idx = stream_index as usize;
        // MF_SOURCE_READER_FLAG_NEW_STREAM is only set for the first sample
        // of a stream, not for every sync sample.
        let is_first = self
            .demuxer
            .get_track(idx)
            .is_some_and(|track| track.current_index == 0);
        if let Some(sample_info) = self.demuxer.next_sample(idx) {
            let data = self.demuxer.read_sample_data(&sample_info)?;
            let mut sample = ImfSample::new(data);
            // Convert from track timescale to 100ns units
            if let Some(track) = self.demuxer.get_track(idx) {
                let scale = track.timescale.max(1) as u64;
                sample.sample_time = Self::to_hns(sample_info.pts, scale);
                sample.sample_duration = Self::to_hns(sample_info.duration as u64, scale);
                if is_first {
                    sample.flags |= 0x4; // MF_SOURCE_READERF_NEWSTREAM
                }
            }
            Ok(Some(sample))
        } else {
            Ok(None) // End of stream
        }
    }

    /// Set the current position for seeking.
    pub fn set_current_position(&mut self, position: u64) {
        for i in 0..self.demuxer.track_count() {
            self.demuxer.seek(i, position);
        }
    }
}

// ===========================================================================
// MFCreateSinkWriter
// ===========================================================================

/// Media Foundation Sink Writer.
///
/// Writes encoded media samples to an output file.
/// Mirrors IMFSinkWriter functionality.
pub struct SinkWriter {
    output_file: Option<String>,
    input_type: Option<ImfMediaType>,
    frame_count: u64,
    output_data: Vec<u8>,
    output_handle: Option<std::fs::File>,
}

impl SinkWriter {
    /// Create a new sink writer.
    pub fn new() -> Self {
        Self {
            output_file: None,
            input_type: None,
            frame_count: 0,
            output_data: Vec::new(),
            output_handle: None,
        }
    }

    /// Create a sink writer from URL (file path).
    pub fn from_url(url: &str) -> AppResult<Self> {
        Ok(Self {
            output_file: Some(url.to_string()),
            input_type: None,
            frame_count: 0,
            output_data: Vec::new(),
            output_handle: None,
        })
    }

    /// Set the input media type for a stream.
    pub fn set_input_media_type(
        &mut self,
        _stream_index: u32,
        media_type: ImfMediaType,
    ) -> AppResult<()> {
        self.input_type = Some(media_type);
        Ok(())
    }

    /// Begin writing (initialize output).
    pub fn begin_writing(&mut self) -> AppResult<()> {
        self.frame_count = 0;
        self.output_data.clear();
        // Open the target file up front so samples stream to disk instead of
        // accumulating in memory until `end_writing`.
        if let Some(path) = &self.output_file {
            let file = std::fs::File::create(path).map_err(|e| {
                AppError::new(
                    ReasonCode::RcMediaInvalid,
                    format!("Failed to create {path}: {e}"),
                )
            })?;
            self.output_handle = Some(file);
        }
        Ok(())
    }

    /// Write a sample to the output.
    /// The number of frames written so far.
    pub fn current_frame_count(&self) -> u64 {
        self.frame_count
    }

    /// Set the input media type for the writer.
    pub fn set_input_type(&mut self, media_type: ImfMediaType) {
        self.input_type = Some(media_type);
    }

    pub fn write_sample(&mut self, _stream_index: u32, sample: &ImfSample) -> AppResult<()> {
        if let Some(file) = &mut self.output_handle {
            use std::io::Write;
            file.write_all(&sample.buffer).map_err(|e| {
                AppError::new(
                    ReasonCode::RcMediaInvalid,
                    format!("Failed to write sample: {e}"),
                )
            })?;
        } else {
            self.output_data.extend_from_slice(&sample.buffer);
        }
        self.frame_count += 1;
        Ok(())
    }

    /// Finalize writing and close the output file.
    pub fn end_writing(&mut self) -> AppResult<()> {
        if let Some(mut file) = self.output_handle.take() {
            use std::io::Write;
            file.flush().map_err(|e| {
                AppError::new(
                    ReasonCode::RcMediaInvalid,
                    format!("Failed to flush output file: {e}"),
                )
            })?;
        } else if let Some(path) = &self.output_file {
            std::fs::write(path, &self.output_data).map_err(|e| {
                AppError::new(
                    ReasonCode::RcMediaInvalid,
                    format!("Failed to write {path}: {e}"),
                )
            })?;
        }
        Ok(())
    }
}

impl Default for SinkWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// MFPresentationClock
// ===========================================================================

/// Media Foundation Presentation Clock.
///
/// Provides timing for media playback, supporting start/stop/pause/resume
/// and configurable playback rate.
pub struct PresentationClock {
    start_time: Option<Instant>,
    paused_time: Option<Duration>,
    rate: f32,
    time_offset: Duration,
}

impl PresentationClock {
    /// Create a new presentation clock.
    pub fn new() -> Self {
        Self {
            start_time: None,
            paused_time: None,
            rate: 1.0,
            time_offset: Duration::ZERO,
        }
    }

    /// Start the clock from the beginning.
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
        self.paused_time = None;
        self.time_offset = Duration::ZERO;
    }

    /// Stop and reset the clock.
    pub fn stop(&mut self) {
        self.start_time = None;
        self.paused_time = None;
        self.time_offset = Duration::ZERO;
    }

    /// Pause the clock, recording the elapsed time so far.
    pub fn pause(&mut self) {
        if self.paused_time.is_none()
            && let Some(start) = self.start_time
        {
            self.time_offset += start.elapsed();
            self.paused_time = Some(self.time_offset);
            self.start_time = None;
        }
    }

    /// Resume the clock from its paused position.
    pub fn resume(&mut self) {
        if self.paused_time.is_some() {
            self.start_time = Some(Instant::now());
            self.paused_time = None;
        }
    }

    /// Get the current time elapsed since start, minus pauses, scaled by the
    /// configured playback rate.
    pub fn get_time(&self) -> Duration {
        let elapsed = if let Some(start) = self.start_time {
            start.elapsed()
        } else {
            Duration::ZERO
        };
        let scaled = if self.rate == 1.0 {
            elapsed
        } else {
            Duration::from_secs_f64(elapsed.as_secs_f64() * self.rate as f64)
        };
        self.time_offset + scaled
    }

    /// Get the current time in 100-ns units (MF format).
    pub fn get_time_hns(&self) -> i64 {
        (self.get_time().as_secs_f64() * 10_000_000.0) as i64
    }

    /// Set the playback rate.
    pub fn set_rate(&mut self, rate: f32) {
        self.rate = rate;
    }

    /// Get the current playback rate.
    pub fn get_rate(&self) -> f32 {
        self.rate
    }

    /// Check if the clock is running.
    pub fn is_running(&self) -> bool {
        self.start_time.is_some()
    }

    /// Check if the clock is paused.
    pub fn is_paused(&self) -> bool {
        self.paused_time.is_some()
    }
}

impl Default for PresentationClock {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Real MF source model (IMFMediaSource / IMFPresentationDescriptor /
// IMFStreamDescriptor / IMFMediaTypeHandler / source ownership)
// ===========================================================================

/// The media source state machine (IMFMediaSource::Start/Stop/Pause/Shutdown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfSourceState {
    /// Created, never started (or stopped after a presentation ended).
    Stopped,
    /// Started: events are flowing.
    Started,
    /// Paused.
    Paused,
    /// Shut down: no further operations are legal.
    Shutdown,
}

impl MfSourceState {
    /// Human-readable state name (diagnostics + tests).
    pub fn name(self) -> &'static str {
        match self {
            Self::Stopped => "Stopped",
            Self::Started => "Started",
            Self::Paused => "Paused",
            Self::Shutdown => "Shutdown",
        }
    }
}

/// The `MFMEDIASOURCE_CHARACTERISTICS` flags (mfidl.h).
pub const MFMEDIASOURCE_IS_LIVE: u32 = 0x1;
/// The source can seek (a real presentation duration exists).
pub const MFMEDIASOURCE_CAN_SEEK: u32 = 0x2;
/// The source can pause.
pub const MFMEDIASOURCE_CAN_PAUSE: u32 = 0x4;
/// Seeking is slow (no random-access stream table).
pub const MFMEDIASOURCE_HAS_SLOW_SEEK: u32 = 0x8;
/// The source has multiple presentations.
pub const MFMEDIASOURCE_HAS_MULTIPLE_PRESENTATIONS: u32 = 0x10;
/// The source can skip forward.
pub const MFMEDIASOURCE_CAN_SKIPFORWARD: u32 = 0x20;
/// The source can skip backward.
pub const MFMEDIASOURCE_CAN_SKIPBACKWARD: u32 = 0x40;
/// The source does not use the network.
pub const MFMEDIASOURCE_DOES_NOT_USE_NETWORK: u32 = 0x80;

/// A real stream descriptor: one parsed container track.
#[derive(Debug, Clone)]
pub struct MfStreamDescriptor {
    /// The stream identifier (the MP4 track id; unique in the file).
    pub identifier: u32,
    /// Whether the stream is selected in the presentation descriptor.
    pub selected: bool,
    /// The native media type parsed from the track.
    pub media_type: ImfMediaType,
    /// The descriptor's attribute store (MF_SD_STREAM_NAME etc.).
    pub attributes: ImfMediaType,
}

impl MfStreamDescriptor {
    /// A stream descriptor for a parsed track.
    pub fn new(identifier: u32, media_type: ImfMediaType) -> Self {
        let mut attributes = ImfMediaType::new();
        attributes.set_string(MF_SD_STREAM_NAME, format!("Stream {identifier}"));
        Self {
            identifier,
            selected: true,
            media_type,
            attributes,
        }
    }
}

/// MF_SD_STREAM_NAME {4f1b099d-d314-41e5-a781-7fefaa4c501f}.
pub const MF_SD_STREAM_NAME: Guid = Guid::new(
    0x4f1b099d,
    0xd314,
    0x41e5,
    [0xa7, 0x81, 0x7f, 0xef, 0xaa, 0x4c, 0x50, 0x1f],
);

/// MF_PD_DURATION {6c990d33-bb8e-477a-8598-0d5d96fcd88a}.
pub const MF_PD_DURATION: Guid = Guid::new(
    0x6c990d33,
    0xbb8e,
    0x477a,
    [0x85, 0x98, 0x0d, 0x5d, 0x96, 0xfc, 0xd8, 0x8a],
);
/// MF_PD_TOTAL_FILE_SIZE {6c990d34-bb8e-477a-8598-0d5d96fcd88a}.
pub const MF_PD_TOTAL_FILE_SIZE: Guid = Guid::new(
    0x6c990d34,
    0xbb8e,
    0x477a,
    [0x85, 0x98, 0x0d, 0x5d, 0x96, 0xfc, 0xd8, 0x8a],
);
/// MF_PD_MIME_TYPE {6c990d37-bb8e-477a-8598-0d5d96fcd88a}.
pub const MF_PD_MIME_TYPE: Guid = Guid::new(
    0x6c990d37,
    0xbb8e,
    0x477a,
    [0x85, 0x98, 0x0d, 0x5d, 0x96, 0xfc, 0xd8, 0x8a],
);
/// MF_PD_SEEKABLE {6c990d3d-bb8e-477a-8598-0d5d96fcd88a}.
pub const MF_PD_SEEKABLE: Guid = Guid::new(
    0x6c990d3d,
    0xbb8e,
    0x477a,
    [0x85, 0x98, 0x0d, 0x5d, 0x96, 0xfc, 0xd8, 0x8a],
);

/// A real presentation descriptor built from a parsed container.
#[derive(Debug, Clone)]
pub struct MfPresentationDescriptor {
    /// Duration in 100-nanosecond units (0 when the container has none).
    pub duration: u64,
    /// Whether the presentation is seekable.
    pub seekable: bool,
    /// Total file size in bytes.
    pub file_size: u64,
    /// The container MIME type (e.g. "video/mp4") when known.
    pub mime_type: Option<String>,
    /// The stream descriptors.
    pub streams: Vec<MfStreamDescriptor>,
}

impl MfPresentationDescriptor {
    /// A descriptor with no streams (used only where Windows also answers an
    /// empty descriptor, e.g. `MFCreatePresentationDescriptor(NULL, 0)`).
    pub fn empty() -> Self {
        Self {
            duration: 0,
            seekable: false,
            file_size: 0,
            mime_type: None,
            streams: Vec::new(),
        }
    }

    /// Build the real descriptor for a parsed MP4 file: duration from the
    /// track `mdhd` durations (converted to 100-ns units), one stream per
    /// parsed track, seekable because the file has a random-access sample
    /// table.
    pub fn from_mp4(demuxer: &Mp4Demuxer, file_size: u64, mime_type: Option<&str>) -> Self {
        let mut duration: u64 = 0;
        let mut streams = Vec::with_capacity(demuxer.track_count());
        for track in demuxer.tracks() {
            let scale = u64::from(track.timescale).max(1);
            let track_duration = track
                .duration
                .saturating_mul(10_000_000)
                .checked_div(scale)
                .unwrap_or(0);
            duration = duration.max(track_duration);
            streams.push(MfStreamDescriptor::new(track.id, track.media_type.clone()));
        }
        Self {
            duration,
            seekable: demuxer.track_count() > 0,
            file_size,
            mime_type: mime_type.map(str::to_string),
            streams,
        }
    }

    /// The `IMFAttributes` store of the descriptor: the real duration,
    /// seekability, file size and MIME type parsed from the file.
    pub fn attributes(&self) -> ImfMediaType {
        let mut store = ImfMediaType::new();
        store.set_uint64(MF_PD_DURATION, self.duration);
        store.set_uint32(MF_PD_SEEKABLE, u32::from(self.seekable));
        store.set_uint64(MF_PD_TOTAL_FILE_SIZE, self.file_size);
        if let Some(mime) = &self.mime_type {
            store.set_string(MF_PD_MIME_TYPE, mime.clone());
        }
        store
    }

    /// Whether the stream at an index is selected (with index bounds check).
    pub fn stream_selected(&self, index: usize) -> Option<bool> {
        self.streams.get(index).map(|stream| stream.selected)
    }

    /// Select/deselect the stream at an index (real selection state).
    pub fn set_stream_selected(&mut self, index: usize, selected: bool) -> bool {
        match self.streams.get_mut(index) {
            Some(stream) => {
                stream.selected = selected;
                true
            }
            None => false,
        }
    }
}

/// Metadata tags parsed from a real MP4 `moov.udta.meta.ilst` box (with the
/// `moov.meta.ilst` variant also accepted).  Keys are the four-character
/// iTunes atoms (`©nam`, `©ART`, `©alb`, `©day`, ...) and values are the
/// UTF-8/UTF-16 text payloads of their `data` atoms.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MfMetadataTags {
    /// The parsed tag map (sorted by property name).
    pub properties: BTreeMap<String, String>,
}

impl MfMetadataTags {
    /// Parse the metadata tags out of an MP4 file.  Malformed, truncated or
    /// missing atoms are skipped; a file with no `ilst` yields an empty map.
    pub fn parse_mp4(data: &[u8]) -> Self {
        let mut tags = Self::default();
        for (kind, payload_start, box_end) in mp4_boxes(data, 0, data.len()) {
            if kind == *b"moov" {
                parse_moov_metadata(data, payload_start, box_end, &mut tags);
            }
        }
        tags
    }

    /// The property names, sorted.
    pub fn property_names(&self) -> Vec<String> {
        self.properties.keys().cloned().collect()
    }
}

/// Iterate the MP4 boxes in `[start, end)` as `(type, payload_start,
/// box_end)`, tolerating truncated size fields.
fn mp4_boxes(data: &[u8], start: usize, end: usize) -> Vec<([u8; 4], usize, usize)> {
    let mut boxes = Vec::new();
    let mut offset = start;
    while offset + 8 <= end {
        let size = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        let mut kind = [0_u8; 4];
        kind.copy_from_slice(&data[offset + 4..offset + 8]);
        let (header, size) = if size == 1 {
            if offset + 16 > end {
                break;
            }
            let large = u64::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);
            (16, usize::try_from(large).unwrap_or(usize::MAX))
        } else if size == 0 {
            (8, end - offset)
        } else {
            (8, size)
        };
        if size < header || offset.saturating_add(size) > end {
            break;
        }
        boxes.push((kind, offset + header, offset + size));
        offset = offset.saturating_add(size);
    }
    boxes
}

/// Find `udta.meta.ilst` (or `meta.ilst`) inside a `moov` payload.
fn parse_moov_metadata(data: &[u8], start: usize, end: usize, tags: &mut MfMetadataTags) {
    for (kind, payload_start, box_end) in mp4_boxes(data, start, end) {
        match &kind {
            b"udta" => {
                for (child, child_start, child_end) in mp4_boxes(data, payload_start, box_end) {
                    if child == *b"meta" {
                        parse_meta_metadata(data, child_start, child_end, tags);
                    }
                }
            }
            b"meta" => parse_meta_metadata(data, payload_start, box_end, tags),
            _ => {}
        }
    }
}

/// Parse a `meta` box: a FullBox (4-byte version/flags) containing `hdlr`
/// and `ilst`, with the non-FullBox variant also accepted.
fn parse_meta_metadata(data: &[u8], start: usize, end: usize, tags: &mut MfMetadataTags) {
    let mut child_start = start;
    let looks_like_box = start + 8 <= end
        && u32::from_be_bytes([
            data[start],
            data[start + 1],
            data[start + 2],
            data[start + 3],
        ]) >= 8
        && data[start + 4..start + 8]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b' ' || *byte == 0xa9);
    if !looks_like_box {
        child_start = start.saturating_add(4);
    }
    for (kind, payload_start, box_end) in mp4_boxes(data, child_start, end) {
        if kind == *b"ilst" {
            parse_ilst(data, payload_start, box_end, tags);
        }
    }
}

/// Parse an `ilst` box: every child is a tag atom whose payload holds one or
/// more `data` atoms.
fn parse_ilst(data: &[u8], start: usize, end: usize, tags: &mut MfMetadataTags) {
    for (kind, payload_start, box_end) in mp4_boxes(data, start, end) {
        let Some(name) = mp4_tag_name(&kind) else {
            continue;
        };
        if tags.properties.contains_key(&name) {
            continue;
        }
        for (child, child_start, child_end) in mp4_boxes(data, payload_start, box_end) {
            if child != *b"data" || child_start + 8 > child_end {
                continue;
            }
            let value_type = u32::from_be_bytes([
                data[child_start],
                data[child_start + 1],
                data[child_start + 2],
                data[child_start + 3],
            ]) & 0x00ff_ffff;
            let text_start = child_start + 8;
            let raw = &data[text_start..child_end];
            let value = match value_type {
                1 | 0 => String::from_utf8_lossy(raw),
                2 => {
                    let units: Vec<u16> = raw
                        .chunks_exact(2)
                        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                        .collect();
                    std::borrow::Cow::Owned(String::from_utf16_lossy(&units))
                }
                _ => continue,
            };
            let value = value.trim_end_matches('\0').to_string();
            if !value.is_empty() {
                tags.properties.insert(name.clone(), value);
                break;
            }
        }
    }
}

/// Convert a four-character MP4 atom name (including the 0xA9 copyright
/// prefix used by iTunes tags) to a property name.
fn mp4_tag_name(kind: &[u8; 4]) -> Option<String> {
    let mut name = String::new();
    for byte in kind {
        if *byte == 0xa9 {
            name.push('©');
        } else if byte.is_ascii_graphic() || *byte == b' ' {
            name.push(char::from(*byte));
        } else {
            return None;
        }
    }
    Some(name)
}

/// The `IMFMediaTypeHandler` state: the negotiated current type and the
/// native types the handler can return.
#[derive(Debug, Clone, Default)]
pub struct MfMediaTypeHandlerState {
    /// The current media type.
    pub current: ImfMediaType,
    /// The available (native) media types.
    pub available: Vec<ImfMediaType>,
}

impl MfMediaTypeHandlerState {
    /// A handler over a single native type.
    pub fn new(media_type: ImfMediaType) -> Self {
        Self {
            current: media_type.clone(),
            available: vec![media_type],
        }
    }

    /// Whether a candidate shares the handler's major type (the media-type
    /// compatibility rule the source enforces).
    pub fn is_type_supported(&self, candidate: &ImfMediaType) -> bool {
        candidate.get_guid(&MF_MT_MAJOR_TYPE) == self.current.get_guid(&MF_MT_MAJOR_TYPE)
    }
}

/// A real media source over a byte stream (a parsed file presentation).
///
/// The source owns the presentation descriptor derived from the file and an
/// `IMFMediaEventGenerator`-style queue: `Start`/`Stop`/`Pause`/`Shutdown`
/// move the real state machine and queue the documented MF events
/// (`MESourceStarted`, `MENewStream`, `MEStreamStarted`, ...); reaching the
/// end of the file through an attached source reader queues
/// `MEEndOfStream`/`MEEndOfPresentation`.
#[derive(Debug, Clone)]
pub struct MfMediaSource {
    /// The source state machine.
    state: MfSourceState,
    /// The real presentation descriptor.
    presentation: MfPresentationDescriptor,
    /// The source's event queue.
    queue: MfEventQueue,
    /// The byte-stream object the source reads (0 when none).
    byte_stream: u64,
    /// The attached source-reader objects (the pull side of the graph).
    readers: Vec<u64>,
    /// Whether the MENewStream events were already sent for this
    /// presentation.
    new_streams_sent: bool,
    /// Whether MEEndOfPresentation was already sent for this presentation.
    end_sent: bool,
    /// The current start position in 100-ns units.
    position: u64,
    /// The container metadata tags parsed from the backing file.
    metadata: MfMetadataTags,
}

impl MfMediaSource {
    /// A source over a presentation and its backing byte stream.
    pub fn new(presentation: MfPresentationDescriptor, byte_stream: u64) -> Self {
        Self {
            state: MfSourceState::Stopped,
            presentation,
            queue: MfEventQueue::with_max(256),
            byte_stream,
            readers: Vec::new(),
            new_streams_sent: false,
            end_sent: false,
            position: 0,
            metadata: MfMetadataTags::default(),
        }
    }

    /// Attach the container metadata parsed from the source's file.
    pub fn set_metadata(&mut self, metadata: MfMetadataTags) {
        self.metadata = metadata;
    }

    /// The container metadata parsed from the source's file.
    pub fn metadata(&self) -> &MfMetadataTags {
        &self.metadata
    }

    /// The current state.
    pub fn state(&self) -> MfSourceState {
        self.state
    }

    /// The real presentation descriptor.
    pub fn presentation(&self) -> &MfPresentationDescriptor {
        &self.presentation
    }

    /// Mutable access to the presentation (stream selection).
    pub fn presentation_mut(&mut self) -> &mut MfPresentationDescriptor {
        &mut self.presentation
    }

    /// The backing byte-stream object.
    pub fn byte_stream(&self) -> u64 {
        self.byte_stream
    }

    /// The attached source readers.
    pub fn readers(&self) -> &[u64] {
        &self.readers
    }

    /// Attach a source reader (the reader that pulls samples from this
    /// source).  Attaching is idempotent.
    pub fn attach_reader(&mut self, reader: u64) {
        if !self.readers.contains(&reader) {
            self.readers.push(reader);
        }
    }

    /// The current presentation position in 100-ns units.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// The `MFMEDIASOURCE_CHARACTERISTICS` of this source: a real local file
    /// presentation is seekable, pausable, skippable and does not use the
    /// network.  A live source would set `MFMEDIASOURCE_IS_LIVE`; this model
    /// has no live sources.
    pub fn characteristics(&self) -> u32 {
        let mut flags = MFMEDIASOURCE_CAN_PAUSE | MFMEDIASOURCE_DOES_NOT_USE_NETWORK;
        if self.presentation.seekable {
            flags |= MFMEDIASOURCE_CAN_SEEK
                | MFMEDIASOURCE_CAN_SKIPFORWARD
                | MFMEDIASOURCE_CAN_SKIPBACKWARD;
        }
        flags
    }

    /// Queue a raw MF event number on the source's queue.
    pub fn queue_event_number(&mut self, mf_type: u32) {
        self.queue.queue_mf_event(mf_type);
    }

    /// Queue an event with an attached value (the event's PROPVARIANT value).
    pub fn queue_event_number_with_value(&mut self, mf_type: u32, value: u64) {
        let mut event = MediaEvent::with_mf_type(mf_type);
        event.pts = Some(value);
        self.queue.queue_event(event);
    }

    /// Pull the next event from the source queue.
    pub fn get_event(&mut self) -> Option<MediaEvent> {
        self.queue.get_event()
    }

    /// The number of queued events.
    pub fn event_count(&self) -> usize {
        self.queue.event_count()
    }

    /// `IMFMediaSource::Start`: enters the Started state and queues
    /// `MESourceStarted` (or `MESourceSeeked` when already started), the
    /// `MENewStream` events for each stream on the first start, and the
    /// per-stream `MEStreamStarted` events.  The position is in 100-ns units.
    pub fn start(&mut self, position: Option<u64>) -> AppResult<()> {
        if self.state == MfSourceState::Shutdown {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cannot start a shut-down media source",
            ));
        }
        let was_started = matches!(self.state, MfSourceState::Started | MfSourceState::Paused);
        self.position = position.unwrap_or(0);
        self.state = MfSourceState::Started;
        self.end_sent = false;
        if was_started {
            self.queue_event_number(203); // MESourceSeeked
            for _ in 0..self.presentation.streams.len() {
                self.queue_event_number(204); // MEStreamSeeked
            }
        } else {
            self.queue_event_number_with_value(201, self.position); // MESourceStarted
            if !self.new_streams_sent {
                self.new_streams_sent = true;
                for _ in 0..self.presentation.streams.len() {
                    self.queue_event_number(205); // MENewStream
                }
            }
            for _ in 0..self.presentation.streams.len() {
                self.queue_event_number(202); // MEStreamStarted
            }
        }
        Ok(())
    }

    /// `IMFMediaSource::Stop`: queue `MESourceStopped` and the per-stream
    /// `MEStreamStopped` events.
    pub fn stop(&mut self) -> AppResult<()> {
        if self.state == MfSourceState::Shutdown {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cannot stop a shut-down media source",
            ));
        }
        self.state = MfSourceState::Stopped;
        self.queue_event_number(207); // MESourceStopped
        for _ in 0..self.presentation.streams.len() {
            self.queue_event_number(208); // MEStreamStopped
        }
        Ok(())
    }

    /// `IMFMediaSource::Pause`: queue `MESourcePaused` and the per-stream
    /// `MEStreamPaused` events (only legal from Started).
    pub fn pause(&mut self) -> AppResult<()> {
        match self.state {
            MfSourceState::Started => {
                self.state = MfSourceState::Paused;
                self.queue_event_number(209); // MESourcePaused
                for _ in 0..self.presentation.streams.len() {
                    self.queue_event_number(210); // MEStreamPaused
                }
                Ok(())
            }
            MfSourceState::Shutdown => Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cannot pause a shut-down media source",
            )),
            _ => Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cannot pause a source that is not started",
            )),
        }
    }

    /// `IMFMediaSource::Shutdown`.
    pub fn shutdown(&mut self) {
        self.state = MfSourceState::Shutdown;
    }

    /// The end of the presentation was reached on the pull side: queue
    /// `MEEndOfStream` for each selected stream followed by
    /// `MEEndOfPresentation` exactly once, and move back to Stopped.
    pub fn end_presentation(&mut self) {
        if self.end_sent || self.state == MfSourceState::Shutdown {
            return;
        }
        self.end_sent = true;
        let selected_streams = self
            .presentation
            .streams
            .iter()
            .filter(|stream| stream.selected)
            .count();
        for _ in 0..selected_streams {
            self.queue_event_number(212); // MEEndOfStream
        }
        self.queue_event_number(211); // MEEndOfPresentation
        self.state = MfSourceState::Stopped;
    }
}

// ===========================================================================
// MF API Stub Functions (updated)
// ===========================================================================

/// MF_MEDIASESSION_TOPOLOGY_SET flag.
pub const MF_MEDIASESSION_TOPOLOGY_SET: u32 = 1;

/// MF_EVENT_SESSION_TOPOLOGY_STATUS flag.
pub const MF_EVENT_SESSION_TOPOLOGY_STATUS: u32 = 2;

/// MFStartup: Initialize the Media Foundation platform.
///
/// Detects available hardware codecs and initializes internal state.
pub fn mf_startup(version: u32, flags: u32) -> AppResult<()> {
    let _version = version;
    let _flags = flags;
    // On macOS, this initializes internal state and detects codecs
    Ok(())
}

/// MFShutdown: Shut down the Media Foundation platform.
pub fn mf_shutdown() {
    // Cleanup codec detection state
}

// ===========================================================================
// Source Resolver (Gap 13.1)
// ===========================================================================

/// Result of resolving a media source URL or byte stream.
pub enum ResolvedSource {
    /// MP4 container with tracks.
    Mp4(SourceReader),
    /// WMV/ASF container.
    Wmv,
    /// Unrecognized or unsupported format.
    Unknown,
}

/// Container format detection from magic bytes.
///
/// Returns `None` for input too short to carry a magic (or with an unknown
/// magic) instead of misclassifying it.
pub fn detect_container_from_bytes(data: &[u8]) -> Option<ContainerKind> {
    if data.len() < 4 {
        return None;
    }
    match &data[..4] {
        b"ftyp" | b"MP4!" => Some(ContainerKind::Mp4),
        b"OggS" | b"Ogg " | b"OGG!" => Some(ContainerKind::Ogg),
        b"0\x26\xB2\x75" => Some(ContainerKind::Wmv), // ASF header
        _ => None,
    }
}

/// Detect container format from a file extension.
pub fn detect_container_from_extension(path: &str) -> Option<ContainerKind> {
    let lower = path.to_lowercase();
    if lower.ends_with(".mp4") || lower.ends_with(".m4v") || lower.ends_with(".mov") {
        Some(ContainerKind::Mp4)
    } else if lower.ends_with(".ogg") || lower.ends_with(".ogv") || lower.ends_with(".oga") {
        Some(ContainerKind::Ogg)
    } else if lower.ends_with(".wmv") || lower.ends_with(".asf") {
        Some(ContainerKind::Wmv)
    } else {
        None
    }
}

/// The MIME type for a media file path (the `MF_BYTESTREAM_CONTENT_TYPE` a
/// byte stream over the file reports).  Derived from the real file
/// extension; `None` when the extension is not a known media container.
pub fn mime_type_for_path(path: &str) -> Option<&'static str> {
    match detect_container_from_extension(path)? {
        ContainerKind::Mp4 => Some("video/mp4"),
        ContainerKind::Ogg => Some("application/ogg"),
        ContainerKind::Wmv => Some("video/x-ms-wmv"),
    }
}

/// SourceResolver: creates media sources from URLs or byte streams.
///
/// Mirrors IMFSourceResolver functionality. Detects container format
/// and returns the appropriate source/demuxer.
pub struct SourceResolver;

impl SourceResolver {
    /// Create a new SourceResolver.
    pub fn new() -> Self {
        Self
    }

    /// Resolve a media source from a URL.
    ///
    /// Supports `file://` and `http://` (or `https://`) URLs.
    /// For file URLs, reads the file and detects the container.
    pub fn create_object_from_url(&self, url: &str) -> AppResult<ResolvedSource> {
        // Strip file:// prefix if present
        let path = if let Some(rest) = url.strip_prefix("file://") {
            rest
        } else if url.starts_with("http://") || url.starts_with("https://") {
            // For HTTP URLs, we use reqwest to fetch the data
            // (behind blocking feature)
            return self.create_object_from_http_url(url);
        } else {
            url
        };

        let data = std::fs::read(path).map_err(|e| {
            AppError::new(
                ReasonCode::RcMediaInvalid,
                format!("Failed to read media file {url}: {e}"),
            )
        })?;

        self.create_object_from_byte_stream(&data)
    }

    /// Resolve a media source from an HTTP(S) URL.
    ///
    /// Downloads are bounded (see `crate::video_decoder::HTTP_FETCH_LIMIT_BYTES`)
    /// so a malicious or oversized remote file cannot exhaust memory.
    fn create_object_from_http_url(&self, url: &str) -> AppResult<ResolvedSource> {
        let bytes = crate::video_decoder::fetch_http_bounded(
            url,
            crate::video_decoder::HTTP_FETCH_LIMIT_BYTES,
        )?;
        self.create_object_from_byte_stream(&bytes)
    }

    /// Resolve a media source from raw byte data.
    ///
    /// Detects the container format using magic bytes and returns
    /// the appropriate source reader.
    pub fn create_object_from_byte_stream(&self, data: &[u8]) -> AppResult<ResolvedSource> {
        let container = detect_container_from_bytes(data);

        match container {
            Some(ContainerKind::Mp4) => {
                let reader = SourceReader::from_data(data.to_vec())?;
                Ok(ResolvedSource::Mp4(reader))
            }
            Some(ContainerKind::Wmv) => {
                // WMV support is detected but decoding may be limited
                Ok(ResolvedSource::Wmv)
            }
            Some(ContainerKind::Ogg) => {
                // OGG is handled by the existing MediaShim path
                Ok(ResolvedSource::Unknown)
            }
            None => Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "Unrecognized media container format",
            )),
        }
    }

    /// Check whether a URL is supported by this resolver.
    pub fn supports_url(&self, url: &str) -> bool {
        if url.starts_with("file://") || url.starts_with("http://") || url.starts_with("https://") {
            return true;
        }
        detect_container_from_extension(url).is_some()
    }
}

impl Default for SourceResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// MFCreateSourceResolver: Create a source resolver.
///
/// Returns a source resolver that can detect container formats and
/// create appropriate source readers from URLs or byte streams.
pub fn mf_create_source_resolver() -> SourceResolver {
    SourceResolver::new()
}

/// MFTEnumEx: Enumerate available Media Foundation Transforms.
///
/// Returns a list of available MFTs matching the given category and flags.
pub fn mft_enum_ex(
    category: &Guid,
    _flags: u32,
    _input_type: Option<&ImfMediaType>,
    _output_type: Option<&ImfMediaType>,
) -> Vec<(Guid, String)> {
    let mut results = Vec::new();

    if *category == MFMediaType_Video {
        results.push((MFVideoFormat_H264, "H.264 Decoder".to_string()));
        results.push((MFVideoFormat_H265, "HEVC (H.265) Decoder".to_string()));
        results.push((MFVideoFormat_VP90, "VP9 Decoder".to_string()));
        results.push((MFVideoFormat_WMV3, "WMV3 Decoder".to_string()));
    }
    if *category == MFMediaType_Audio {
        results.push((MFAudioFormat_AAC, "AAC Decoder".to_string()));
        results.push((MFAudioFormat_MP3, "MP3 Decoder".to_string()));
        results.push((MFAudioFormat_WMA, "WMA Decoder".to_string()));
        results.push((MFAudioFormat_PCM, "PCM Decoder".to_string()));
    }

    results
}

/// MFCreateMediaType: Create a new IMFMediaType.
pub fn mf_create_media_type() -> ImfMediaType {
    ImfMediaType::new()
}

/// MFCreateSample: Create a new IMFSample.
pub fn mf_create_sample() -> ImfSample {
    ImfSample::empty()
}

/// MFCreateMemoryBuffer: Create a new IMFMediaBuffer.
pub fn mf_create_memory_buffer(capacity: u32) -> ImfMediaBuffer {
    ImfMediaBuffer::new(capacity)
}

// ===========================================================================
// MediaShim (existing)
// ===========================================================================

#[derive(Debug, Clone)]
pub struct MediaShim {
    ge_root: String,
}

impl MediaShim {
    pub fn new(ge_root: &str) -> Self {
        Self {
            ge_root: normalize_path(ge_root),
        }
    }

    pub fn api_surface(&self) -> MediaApiSurface {
        MediaApiSurface::AlternativeShim
    }

    pub fn parse_container(&self, bytes: &[u8]) -> AppResult<ParsedContainer> {
        if bytes.len() < 18 {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "media container is truncated",
            ));
        }
        let magic = &bytes[..4];
        let container = match magic {
            b"MP4!" => ContainerKind::Mp4,
            b"OGG!" => ContainerKind::Ogg,
            b"WMV!" => ContainerKind::Wmv,
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "unknown media container magic",
                ));
            }
        };
        let video_codec = match bytes[4] {
            0 => VideoCodec::None,
            1 => VideoCodec::H264,
            2 => VideoCodec::H265,
            3 => VideoCodec::VP9,
            4 => VideoCodec::WMV,
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "unsupported video codec",
                ));
            }
        };
        let audio_codec = match bytes[5] {
            1 => AudioCodec::Aac,
            2 => AudioCodec::Vorbis,
            3 => AudioCodec::Mp3,
            4 => AudioCodec::Wma,
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "unsupported audio codec",
                ));
            }
        };
        let duration_ms = Self::read_le_u32(bytes, 6)?;
        let frame_count = Self::read_le_u32(bytes, 10)?;
        let audio_block_count = Self::read_le_u32(bytes, 14)?;

        // Bound counts derived from the untrusted header: without a cap,
        // `decode_golden_clip` would allocate up to 4G SHA-256 strings and
        // `synthesize_audio_samples` up to 34 GB of audio samples.
        const MAX_SHIM_COUNT: u32 = 1_000_000;
        if frame_count > MAX_SHIM_COUNT || audio_block_count > MAX_SHIM_COUNT {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "media container counts exceed the supported limit",
            ));
        }

        // Validate codec combinations per container
        match container {
            ContainerKind::Mp4 => {
                let valid_video = matches!(video_codec, VideoCodec::H264 | VideoCodec::H265);
                let valid_audio = matches!(audio_codec, AudioCodec::Aac | AudioCodec::Mp3);
                if !valid_video || !valid_audio {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        "MP4 clips support H.264/H.265 video and AAC/MP3 audio",
                    ));
                }
            }
            ContainerKind::Ogg => {
                // OGG can be Vorbis-only (audio) or VP9 video
                let valid = matches!(video_codec, VideoCodec::None | VideoCodec::VP9)
                    && matches!(audio_codec, AudioCodec::Vorbis);
                if !valid {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        "OGG clips support VP9/NONE video and Vorbis audio",
                    ));
                }
            }
            ContainerKind::Wmv => {
                let valid_video = matches!(video_codec, VideoCodec::WMV | VideoCodec::None);
                let valid_audio = matches!(audio_codec, AudioCodec::Wma);
                if !valid_video || !valid_audio {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        "WMV clips support WMV video and WMA audio",
                    ));
                }
            }
        }

        Ok(ParsedContainer {
            container,
            video_codec,
            audio_codec,
            duration_ms,
            frame_count,
            audio_block_count,
        })
    }

    /// Read a little-endian u32 at `offset` (bounds-checked).
    fn read_le_u32(bytes: &[u8], offset: usize) -> AppResult<u32> {
        let end = offset.checked_add(4).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcMediaInvalid,
                "media container offset overflows",
            )
        })?;
        if end > bytes.len() {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "media container is truncated",
            ));
        }
        Ok(u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]))
    }

    pub fn decode_golden_clip(&self, clip: &GoldenClip) -> AppResult<DecodedClip> {
        self.ensure_decoder_path_trusted(&clip.decoder_path)?;
        let parsed = self.parse_container(&clip.container_bytes)?;
        let frame_hashes = (0..parsed.frame_count)
            .map(|index| {
                util::sha256_bytes(
                    format!(
                        "frame|{}|{:?}|{:?}|{:?}|{}|{}",
                        clip.id,
                        parsed.container,
                        parsed.video_codec,
                        parsed.audio_codec,
                        parsed.duration_ms,
                        index
                    )
                    .as_bytes(),
                )
            })
            .collect::<Vec<_>>();
        let samples = synthesize_audio_samples(&clip.id, parsed.audio_block_count);
        Ok(DecodedClip {
            frame_hashes,
            audio_crc32: crc32_samples(&samples),
            parser_surface: self.api_surface(),
        })
    }

    pub fn measure_av_drift_ms(&self, bytes: &[u8]) -> AppResult<u32> {
        let parsed = self.parse_container(bytes)?;
        let video_duration_us = parsed.frame_count as u64 * 41_666;
        let audio_duration_us = parsed.audio_block_count as u64 * 41_667;
        Ok(video_duration_us
            .abs_diff(audio_duration_us)
            .div_ceil(1_000) as u32)
    }

    pub fn classify_input(&self, bytes: &[u8]) -> MediaInputClassification {
        match self.parse_container(bytes) {
            Ok(_) => MediaInputClassification::Valid,
            Err(error) => MediaInputClassification::Error(error.code),
        }
    }

    pub fn ensure_decoder_path_trusted(&self, path: &str) -> AppResult<()> {
        let normalized = normalize_path(path);
        // builtin://codecs is a dedicated namespace; match it exactly (or
        // with a path separator), never as a bare string prefix.
        if normalized == "builtin://codecs" || normalized.starts_with("builtin://codecs/") {
            return Ok(());
        }
        // Lexically resolve "." / ".." and compare component-wise, so
        // "/root/codecs_evil/..." or "/root/codecs/../evil" cannot bypass
        // the sandbox.
        let candidate = resolve_path(&normalized);
        let root = resolve_path(&self.ge_root);
        if let Some(rest) = candidate.strip_prefix(&root)
            && (rest.is_empty() || rest.starts_with('/'))
        {
            return Ok(());
        }
        Err(AppError::new(
            ReasonCode::RcFsSandboxEscape,
            format!("untrusted decoder path {path}"),
        ))
    }
}

// ===========================================================================
// Utility functions
// ===========================================================================

pub fn build_container_bytes(
    container: ContainerKind,
    video_codec: VideoCodec,
    audio_codec: AudioCodec,
    duration_ms: u32,
    frame_count: u32,
    audio_block_count: u32,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(match container {
        ContainerKind::Mp4 => b"MP4!",
        ContainerKind::Ogg => b"OGG!",
        ContainerKind::Wmv => b"WMV!",
    });
    bytes.push(match video_codec {
        VideoCodec::None => 0,
        VideoCodec::H264 => 1,
        VideoCodec::H265 => 2,
        VideoCodec::VP9 => 3,
        VideoCodec::WMV => 4,
    });
    bytes.push(match audio_codec {
        AudioCodec::Aac => 1,
        AudioCodec::Vorbis => 2,
        AudioCodec::Mp3 => 3,
        AudioCodec::Wma => 4,
    });
    bytes.extend_from_slice(&duration_ms.to_le_bytes());
    bytes.extend_from_slice(&frame_count.to_le_bytes());
    bytes.extend_from_slice(&audio_block_count.to_le_bytes());
    bytes
}

fn synthesize_audio_samples(clip_id: &str, block_count: u32) -> Vec<f32> {
    let seed = util::sha256_bytes(clip_id.as_bytes());
    (0..block_count)
        .flat_map(|block| {
            let phase = ((block as f32)
                + (seed.as_bytes()[block as usize % seed.len()] as f32 / 255.0))
                / 16.0;
            [phase.sin(), phase.cos() * 0.5]
        })
        .collect()
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

/// Lexically resolve `.` and `..` components in a normalized path.
///
/// Purely lexical (no filesystem access); preserves a leading `/`.
fn resolve_path(path: &str) -> String {
    let is_absolute = path.starts_with('/');
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            c => components.push(c),
        }
    }
    let joined = components.join("/");
    if is_absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

// ===========================================================================
// Tests
// ===========================================================================

/// A minimal but fully valid MP4 test fixture: `ftyp` + `moov` (one `vide`
/// track with two 4-byte samples described by real `stbl` tables) + `mdat`.
/// The `stco` chunk offset is patched to the real `mdat` payload, so the
/// demuxer reads the actual sample bytes.  Shared by the media-layer and
/// dispatch tests.
#[cfg(test)]
pub(crate) fn minimal_mp4_fixture() -> Vec<u8> {
    fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(payload);
        out
    }

    let ftyp = boxed(b"ftyp", b"mp42\0\0\0\0");
    let mut tkhd_payload = vec![0_u8; 12];
    tkhd_payload.extend_from_slice(&1_u32.to_be_bytes());
    let tkhd = boxed(b"tkhd", &tkhd_payload);
    let mut mdhd_payload = vec![0_u8; 12];
    mdhd_payload.extend_from_slice(&600_u32.to_be_bytes()); // timescale
    mdhd_payload.extend_from_slice(&1200_u32.to_be_bytes()); // duration (2 s)
    mdhd_payload.extend_from_slice(&[0_u8; 4]);
    let mdhd = boxed(b"mdhd", &mdhd_payload);
    let mut hdlr_payload = vec![0_u8; 8];
    hdlr_payload.extend_from_slice(b"vide");
    hdlr_payload.extend_from_slice(&[0_u8; 12]);
    let hdlr = boxed(b"hdlr", &hdlr_payload);
    let stsd = boxed(b"stsd", &[0_u8; 8]);
    let mut stts_payload = vec![0_u8; 4];
    stts_payload.extend_from_slice(&1_u32.to_be_bytes());
    stts_payload.extend_from_slice(&2_u32.to_be_bytes());
    stts_payload.extend_from_slice(&600_u32.to_be_bytes());
    let stts = boxed(b"stts", &stts_payload);
    let mut stsc_payload = vec![0_u8; 4];
    stsc_payload.extend_from_slice(&1_u32.to_be_bytes());
    stsc_payload.extend_from_slice(&1_u32.to_be_bytes());
    stsc_payload.extend_from_slice(&2_u32.to_be_bytes());
    stsc_payload.extend_from_slice(&1_u32.to_be_bytes());
    let stsc = boxed(b"stsc", &stsc_payload);
    let mut stsz_payload = vec![0_u8; 4];
    stsz_payload.extend_from_slice(&0_u32.to_be_bytes());
    stsz_payload.extend_from_slice(&2_u32.to_be_bytes());
    stsz_payload.extend_from_slice(&4_u32.to_be_bytes());
    stsz_payload.extend_from_slice(&4_u32.to_be_bytes());
    let stsz = boxed(b"stsz", &stsz_payload);
    let mut stco_payload = vec![0_u8; 4];
    stco_payload.extend_from_slice(&1_u32.to_be_bytes());
    stco_payload.extend_from_slice(&0_u32.to_be_bytes()); // patched below
    let stco = boxed(b"stco", &stco_payload);
    let stbl = boxed(b"stbl", &[stsd, stts, stsc, stsz, stco].concat());
    let minf = boxed(b"minf", &stbl);
    let mdia = boxed(b"mdia", &[mdhd, hdlr, minf].concat());
    let trak = boxed(b"trak", &[tkhd, mdia].concat());
    let moov = boxed(b"moov", &trak);
    let mdat = boxed(b"mdat", b"DATA0123");

    let mut file = Vec::new();
    file.extend_from_slice(&ftyp);
    file.extend_from_slice(&moov);
    let samples_offset = file.len() as u32 + 8;
    file.extend_from_slice(&mdat);
    let stco_type = file
        .windows(4)
        .position(|window| window == b"stco")
        .expect("stco box present");
    let offset_at = stco_type + 12;
    file[offset_at..offset_at + 4].copy_from_slice(&samples_offset.to_be_bytes());
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // Session state machine tests
    // =======================================================================

    #[test]
    fn test_mf_session_shutdown() {
        let mut session = MfMediaSession::new();
        session.shutdown().unwrap();
        assert_eq!(session.state(), MfSessionState::Shutdown);
        assert!(!session.is_active());
    }

    #[test]
    fn test_mf_session_double_shutdown() {
        let mut session = MfMediaSession::new();
        session.shutdown().unwrap();
        let _result = session.shutdown();
        assert!(_result.is_err(), "expected Err, got {_result:?}"); // Double shutdown
    }

    #[test]
    fn test_mf_session_pause_without_start() {
        let mut session = MfMediaSession::new();
        let _result = session.pause();
        assert!(_result.is_err(), "expected Err, got {_result:?}"); // Can't pause from Idle
    }

    #[test]
    fn test_mf_session_stop_without_start() {
        let mut session = MfMediaSession::new();
        let _result = session.stop();
        assert!(_result.is_err(), "expected Err, got {_result:?}"); // Can't stop from Idle
    }

    #[test]
    fn test_mf_session_start_after_shutdown() {
        let mut session = MfMediaSession::new();
        session.shutdown().unwrap();
        let _result = session.start();
        assert!(_result.is_err(), "expected Err, got {_result:?}"); // Can't start after shutdown
    }

    // =======================================================================
    // Event queue tests
    // =======================================================================

    #[test]
    fn test_mf_event_queue_basic() {
        let mut queue = MfEventQueue::new();
        assert!(!queue.has_events());

        queue.queue_event_type(MediaEventType::SessionStarted);
        assert!(queue.has_events());
        assert_eq!(queue.event_count(), 1);

        let event = queue.get_event().unwrap();
        assert_eq!(event.event_type, MediaEventType::SessionStarted);
        assert!(!queue.has_events());
    }

    #[test]
    fn test_mf_event_with_error() {
        let event = MediaEvent::with_error("test error");
        assert_eq!(event.event_type, MediaEventType::Error);
        assert_eq!(event.status, -1);
        assert_eq!(event.data.as_deref(), Some("test error"));
    }

    #[test]
    fn test_mf_event_queue_overflow() {
        let mut queue = MfEventQueue::with_max(3);
        queue.queue_event_type(MediaEventType::SessionStarted);
        queue.queue_event_type(MediaEventType::SessionPaused);
        queue.queue_event_type(MediaEventType::SessionStopped);
        queue.queue_event_type(MediaEventType::SessionEnded); // Should push out the first one

        assert_eq!(queue.event_count(), 3);
        let first = queue.get_event().unwrap();
        assert_eq!(first.event_type, MediaEventType::SessionPaused);
    }

    // =======================================================================
    // Topology tests
    // =======================================================================

    #[test]
    fn test_topology_validate_empty() {
        let topology = Topology::new();
        let _result = topology.validate();
        assert!(_result.is_err(), "expected Err, got {_result:?}"); // No source node
    }

    #[test]
    fn test_topology_connect_invalid() {
        let mut topology = Topology::new();
        let _result = topology.connect(1, 999);
        assert!(_result.is_err(), "expected Err, got {_result:?}"); // Target doesn't exist
    }

    // =======================================================================
    // MFCreateMediaSession tests
    // =======================================================================

    // =======================================================================
    // Session position tests
    // =======================================================================

    // =======================================================================
    // Existing container parsing tests
    // =======================================================================

    #[test]
    fn test_parse_container_invalid_magic() {
        let shim = MediaShim::new("/tmp/codecs");
        let invalid = vec![
            0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let _result = shim.parse_container(&invalid);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    // =======================================================================
    // IMFMediaType tests
    // =======================================================================

    #[test]
    fn test_mf_media_type_basic() {
        let mut mt = ImfMediaType::new();
        mt.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        mt.set_guid(MF_MT_SUBTYPE, MFVideoFormat_H264);
        mt.set_frame_size(1920, 1080);
        mt.set_frame_rate(30000, 1001);
        mt.set_uint32(MF_MT_BITRATE, 5000000);

        assert!(mt.is_video());
        assert!(!mt.is_audio());
        assert_eq!(mt.get_guid(&MF_MT_MAJOR_TYPE), Some(MFMediaType_Video));
        assert_eq!(mt.get_guid(&MF_MT_SUBTYPE), Some(MFVideoFormat_H264));
        assert_eq!(mt.get_frame_size(), Some((1920, 1080)));
        assert_eq!(mt.get_frame_rate(), Some((30000, 1001)));
        assert_eq!(mt.get_uint32(&MF_MT_BITRATE), Some(5000000));
    }

    #[test]
    fn test_mf_media_type_audio() {
        let mut mt = ImfMediaType::new();
        mt.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
        mt.set_guid(MF_MT_SUBTYPE, MFAudioFormat_AAC);
        mt.set_uint32(MF_MT_SAMPLE_RATE, 48000);
        mt.set_uint32(MF_MT_CHANNELS, 2);

        assert!(mt.is_audio());
        assert!(!mt.is_video());
        assert_eq!(mt.get_uint32(&MF_MT_SAMPLE_RATE), Some(48000));
        assert_eq!(mt.get_uint32(&MF_MT_CHANNELS), Some(2));
    }

    // =======================================================================
    // IMFSample / IMFMediaBuffer tests
    // =======================================================================

    // =======================================================================
    // MFT Transform tests
    // =======================================================================

    #[cfg(target_os = "macos")]
    const AAC_FIXTURE_FRAME: &[u8] = &[
        0x21, 0x4E, 0xEF, 0x51, 0x07, 0xE2, 0xCD, 0x38, 0x66, 0xC2, 0x3E, 0x3E, 0x3E, 0x3E, 0xB5,
        0xAC, 0x98, 0x87, 0x5A, 0x06, 0xF2, 0xFF, 0xE9, 0xC0, 0xBF, 0xD6, 0x81, 0x44, 0x47, 0xFA,
        0xF0, 0x30, 0x0F, 0xF7, 0x9D, 0xD8, 0xA3, 0x73, 0x6E, 0xB1, 0x72, 0x9E, 0x37, 0x12, 0xD7,
        0x55, 0x28, 0x0E, 0x98, 0x96, 0x68, 0x63, 0x63, 0x80, 0x0D, 0x51, 0x2E, 0xD0, 0xEF, 0xBB,
        0x70, 0x81, 0xC7, 0x29, 0x4A, 0x37, 0x6B, 0x9C, 0x80, 0xEA, 0x99, 0x85, 0x5D, 0xAE, 0x75,
        0xAD, 0xB0, 0x16, 0xA5, 0xCE, 0x65, 0xA6, 0x56, 0xA5, 0xAB, 0x36, 0xDA, 0xB6, 0x32, 0x96,
        0xA5, 0xB4, 0xCB, 0x44, 0xAD, 0x4B, 0x57, 0xFD, 0x37, 0xFB, 0x33, 0xA4, 0xF4, 0x99, 0x3F,
        0xFA, 0x5F, 0x07, 0x64, 0x74, 0x9E, 0x93, 0xCC, 0x1B, 0x3B, 0x3B, 0x20, 0x08, 0x70, 0xFC,
        0x07, 0xE1, 0x0E, 0xB4, 0x0D, 0xE5, 0xFF, 0xD3, 0x81, 0x7F, 0xAD, 0x02, 0x88, 0x8F, 0xF5,
        0xE0, 0x60, 0x1F, 0xEF, 0x70,
    ];

    #[cfg(target_os = "macos")]
    const AAC_FIXTURE_COOKIE: &[u8] = &[
        0x03, 0x80, 0x80, 0x80, 0x22, 0x00, 0x00, 0x00, 0x04, 0x80, 0x80, 0x80, 0x14, 0x40, 0x14,
        0x00, 0x18, 0x00, 0x00, 0x00, 0x45, 0x88, 0x00, 0x01, 0xF4, 0x00, 0x05, 0x80, 0x80, 0x80,
        0x02, 0x12, 0x10, 0x06, 0x80, 0x80, 0x80, 0x01, 0x02,
    ];

    #[cfg(target_os = "macos")]
    #[test]
    fn test_mft_aac_decoder_decodes_real_aac_frame() {
        let mut decoder = AacDecoderMft::new();

        let mut input_type = decoder.get_input_available_type(0, 0).unwrap();
        input_type.set_uint32(MF_MT_SAMPLE_RATE, 44100);
        input_type.set_uint32(MF_MT_CHANNELS, 2);
        input_type.set_blob(MF_MT_USER_DATA, AAC_FIXTURE_COOKIE.to_vec());
        decoder.set_input_type(0, &input_type).unwrap();

        // The output type must carry the negotiated format: sample rate,
        // channels, bit depth.
        let mut output_type = decoder.get_output_available_type(0, 0).unwrap();
        output_type.set_uint32(MF_MT_SAMPLE_RATE, 44100);
        output_type.set_uint32(MF_MT_CHANNELS, 2);
        output_type.set_uint32(MF_MT_AUDIO_BITS_PER_SAMPLE, 16);
        decoder.set_output_type(0, &output_type).unwrap();
        assert_eq!(
            output_type.get_uint32(&MF_MT_SAMPLE_RATE),
            Some(44100),
            "output type must carry the negotiated sample rate"
        );
        assert_eq!(
            output_type.get_uint32(&MF_MT_CHANNELS),
            Some(2),
            "output type must carry the negotiated channel count"
        );
        assert_eq!(
            output_type.get_uint32(&MF_MT_AUDIO_BITS_PER_SAMPLE),
            Some(16),
            "output type must carry the negotiated bit depth"
        );

        // Compressed packet → decoder → PCM → timestamp/duration chain.
        let mut input = ImfSample::new(AAC_FIXTURE_FRAME.to_vec());
        input.set_sample_time(123_456); // 100-ns units
        input.set_sample_duration(232_199); // 1024 frames @ 44.1 kHz
        decoder
            .process_input(0, &input, 0)
            .expect("decode AAC packet");

        assert!(decoder.has_output(), "decode must produce output");
        let mut output = ImfSample::empty();
        let mut flags = 0;
        decoder
            .process_output(0, &mut output, &mut flags)
            .expect("retrieve decoded PCM");
        assert_eq!(
            flags & MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE,
            0,
            "a decoded sample must be produced, not NO_SAMPLE"
        );
        assert!(!output.buffer.is_empty(), "decoded PCM must not be empty");

        // Timestamps/durations are preserved from the input sample.
        assert_eq!(output.get_sample_time(), 123_456);
        assert_eq!(output.get_sample_duration(), 232_199);

        // 1024 frames × 2 channels × 2 bytes (16-bit PCM).
        assert_eq!(
            output.buffer.len(),
            1024 * 2 * 2,
            "decoded PCM must be exactly one 1024-frame stereo frame"
        );
        // The fixture is a 440 Hz sine wave, so the decoded samples are
        // non-zero.
        let non_zero = output
            .buffer
            .as_chunks::<2>()
            .0
            .iter()
            .any(|s| u16::from_le_bytes([s[0], s[1]]) != 0);
        assert!(non_zero, "decoded PCM must contain non-zero samples");

        // A second input packet decodes too, and an empty queue reports
        // NO_SAMPLE afterwards.
        decoder
            .process_input(0, &input, 0)
            .expect("decode second packet");
        assert!(decoder.has_output());
        let mut output2 = ImfSample::empty();
        let mut flags2 = 0;
        decoder
            .process_output(0, &mut output2, &mut flags2)
            .expect("retrieve second PCM");
        assert_eq!(flags2 & MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE, 0);
        assert!(!output2.buffer.is_empty());

        let mut drained = ImfSample::empty();
        let mut drained_flags = 0;
        decoder
            .process_output(0, &mut drained, &mut drained_flags)
            .expect("drain");
        assert_eq!(
            drained_flags & MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE,
            MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE,
            "no further output after the queue is drained"
        );
    }

    // =======================================================================
    // PresentationClock tests
    // =======================================================================

    #[test]
    fn test_presentation_clock_start_stop() {
        let mut clock = PresentationClock::new();
        assert!(!clock.is_running());
        assert!(!clock.is_paused());

        clock.start();
        assert!(clock.is_running());

        clock.stop();
        assert!(!clock.is_running());
    }

    // =======================================================================
    // MP4 Demuxer tests
    // =======================================================================

    #[test]
    fn test_mp4_demuxer_ftyp() {
        // Build a minimal ftyp box: size(8) + 'ftyp' + major_brand(4) + minor_version(4)
        let mut data = Vec::new();
        // ftyp box
        let ftyp_size: u32 = 16u32.to_be();
        data.extend_from_slice(&ftyp_size.to_be_bytes());
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(b"mp42");
        data.extend_from_slice(&[0u8; 4]); // minor version

        let mut demuxer = Mp4Demuxer::new(data);
        // parse should succeed (no tracks, but doesn't fail on ftyp)
        let result = demuxer.parse();
        // No tracks - we expect error "No tracks found in MP4"
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn test_mp4_demuxer_empty() {
        let data = Vec::new();
        let mut demuxer = Mp4Demuxer::new(data);
        let _result = demuxer.parse();
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn test_mp4_demuxer_truncated() {
        // Too short to even read box header
        let data = vec![0u8, 0, 0, 0]; // only 4 bytes, need 8
        let mut demuxer = Mp4Demuxer::new(data);
        let _result = demuxer.parse();
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn test_mp4_metadata_missing_and_malformed_atoms_are_ignored() {
        fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(8 + payload.len());
            out.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
            out.extend_from_slice(kind);
            out.extend_from_slice(payload);
            out
        }
        let mut data_payload = vec![0_u8, 0, 0, 1, 0, 0, 0, 0];
        data_payload.extend_from_slice(b"Kept");
        let good_item = boxed(b"\xa9nam", &boxed(b"data", &data_payload));
        // A second item claims a size far beyond the ilst payload.
        let mut malformed = Vec::new();
        malformed.extend_from_slice(&10_000_u32.to_be_bytes());
        malformed.extend_from_slice(b"\xa9ART");
        let ilst = boxed(b"ilst", &[&good_item[..], &malformed].concat());
        let meta = boxed(b"meta", &[&[0_u8; 4][..], &ilst].concat());
        let moov = boxed(b"moov", &boxed(b"udta", &meta));

        let tags = MfMetadataTags::parse_mp4(&moov);
        assert_eq!(tags.properties.get("©nam"), Some(&"Kept".to_string()));
        assert_eq!(tags.properties.get("©ART"), None);

        // No metadata boxes at all is an empty (not an error) tag map.
        let ftyp = boxed(b"ftyp", b"mp42");
        let moov = boxed(b"moov", &[]);
        assert!(
            MfMetadataTags::parse_mp4(&[ftyp, moov].concat())
                .properties
                .is_empty()
        );
    }

    // =======================================================================
    // SourceReader tests
    // =======================================================================

    #[test]
    fn test_source_reader_empty_data() {
        // Empty data should fail
        let result = SourceReader::from_data(Vec::new());
        assert!(result.is_err(), "expected Err parsing empty data");
    }

    #[test]
    fn test_source_reader_invalid_data() {
        // Random bytes should fail
        let result = SourceReader::from_data(vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert!(result.is_err(), "expected Err parsing invalid data");
    }

    // =======================================================================
    // MF API stub tests
    // =======================================================================

    #[test]
    fn test_mft_enum_ex_video() {
        let results = mft_enum_ex(&MFMediaType_Video, 0, None, None);
        assert!(!results.is_empty());
        let found_h264 = results.iter().any(|(_, name)| name == "H.264 Decoder");
        assert!(found_h264);
    }

    #[test]
    fn test_mft_enum_ex_audio() {
        let results = mft_enum_ex(&MFMediaType_Audio, 0, None, None);
        assert!(!results.is_empty());
        let found_aac = results.iter().any(|(_, name)| name == "AAC Decoder");
        assert!(found_aac);
    }

    // =======================================================================
    // GUID tests
    // =======================================================================
}
