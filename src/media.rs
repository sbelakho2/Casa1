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
        }
    }
}

/// A Media Foundation event, wrapping an event type and optional data.
#[derive(Debug, Clone)]
pub struct MediaEvent {
    /// The type of event.
    pub event_type: MediaEventType,
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
            status: 0,
            data: None,
            pts: None,
        }
    }

    /// Create a new media event with a status code.
    pub fn with_status(event_type: MediaEventType, status: i32) -> Self {
        Self {
            event_type,
            status,
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

        // Record elapsed time at pause
        if let Some(start) = self.start_time {
            self.paused_elapsed += start.elapsed().as_micros() as u64;
        }

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
                    .map(|s| s.elapsed().as_micros() as u64)
                    .unwrap_or(0);
                self.paused_elapsed + elapsed
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
}

impl SourceReader {
    /// An empty source reader (no data — the deterministic headless
    /// source model).
    pub fn empty() -> Self {
        Self {
            demuxer: Mp4Demuxer::new(Vec::new()),
            selected_streams: Vec::new(),
            decoder: None,
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
        let mut demuxer = Mp4Demuxer::new(data);
        demuxer.parse()?;
        Ok(Self {
            demuxer,
            selected_streams: Vec::new(),
            decoder: None,
        })
    }

    /// Select a stream for reading.
    pub fn select_stream(&mut self, stream_index: u32) {
        // MF uses MF_SOURCE_READER_FIRST_VIDEO_STREAM, etc.
        if stream_index == 0xFFFFFFFB {
            // MF_SOURCE_READER_FIRST_VIDEO_STREAM: select first video track
            for (i, track) in self.demuxer.tracks().iter().enumerate() {
                if track.media_type.is_video() {
                    self.selected_streams.push(i as u32);
                    return;
                }
            }
        } else if stream_index == 0xFFFFFFFC {
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

    /// Get the current media type for a stream.
    pub fn get_current_media_type(&self, stream_index: u32) -> AppResult<ImfMediaType> {
        let idx = stream_index as usize;
        if let Some(track) = self.demuxer.get_track(idx) {
            Ok(track.media_type.clone())
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

    /// Set the current media type for a stream (output type).
    pub fn set_current_media_type(
        &mut self,
        _stream_index: u32,
        _media_type: &ImfMediaType,
    ) -> AppResult<()> {
        // Would negotiate with decoder here
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
                    sample.flags |= 1; // MF_SOURCE_READER_FLAG_NEW_STREAM
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

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // Session state machine tests
    // =======================================================================

    #[test]
    fn test_mf_session_initial_state() {
        let session = MfMediaSession::new();
        assert_eq!(session.state(), MfSessionState::Idle);
        assert!(session.is_active());
    }

    #[test]
    fn test_mf_session_start() {
        let mut session = MfMediaSession::new();
        session.set_url_topology("test.mp4").unwrap();
        let _result = session.start();
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        assert_eq!(session.state(), MfSessionState::Playing);
        assert!(session.has_events());
    }

    #[test]
    fn test_mf_session_start_pause_stop() {
        let mut session = MfMediaSession::new();
        session.set_url_topology("test.mp4").unwrap();

        // Start
        session.start().unwrap();
        assert_eq!(session.state(), MfSessionState::Playing);

        // Pause
        session.pause().unwrap();
        assert_eq!(session.state(), MfSessionState::Paused);

        // Start again from pause
        session.start().unwrap();
        assert_eq!(session.state(), MfSessionState::Playing);

        // Stop
        session.stop().unwrap();
        assert_eq!(session.state(), MfSessionState::Stopped);
    }

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

    #[test]
    fn test_mf_session_lifecycle_full() {
        let mut session = MfMediaSession::new();
        assert_eq!(session.state(), MfSessionState::Idle);

        // Set topology
        session.set_url_topology("test.mp4").unwrap();
        assert!(session.has_topology);

        // Idle -> Playing
        session.start().unwrap();
        assert_eq!(session.state(), MfSessionState::Playing);

        // Playing -> Paused
        session.pause().unwrap();
        assert_eq!(session.state(), MfSessionState::Paused);

        // Paused -> Playing
        session.start().unwrap();
        assert_eq!(session.state(), MfSessionState::Playing);

        // Playing -> Stopped
        session.stop().unwrap();
        assert_eq!(session.state(), MfSessionState::Stopped);

        // Stopped -> Playing
        session.start().unwrap();
        assert_eq!(session.state(), MfSessionState::Playing);

        // Playing -> Stopped -> Shutdown
        session.stop().unwrap();
        session.shutdown().unwrap();
        assert_eq!(session.state(), MfSessionState::Shutdown);
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
    fn test_mf_session_events() {
        let mut session = MfMediaSession::new();
        session.set_url_topology("test.mp4").unwrap();

        // set_url_topology -> set_topology queues TopologySet + TopologyLoaded
        // Start from Idle -> queues SessionStarted
        session.start().unwrap();
        let event1 = session.get_event().unwrap(); // TopologySet (from set_topology)
        assert_eq!(event1.event_type, MediaEventType::TopologySet);
        let event2 = session.get_event().unwrap(); // TopologyLoaded (from set_topology)
        assert_eq!(event2.event_type, MediaEventType::TopologyLoaded);
        let event3 = session.get_event().unwrap(); // SessionStarted (from start)
        assert_eq!(event3.event_type, MediaEventType::SessionStarted);

        // Pause -> should emit SessionPaused
        session.pause().unwrap();
        let event = session.get_event().unwrap();
        assert_eq!(event.event_type, MediaEventType::SessionPaused);

        // Stop -> should emit SessionStopped
        session.start().unwrap(); // from Paused, no topology resolution needed
        let event = session.get_event().unwrap();
        assert_eq!(event.event_type, MediaEventType::SessionStarted);
        session.stop().unwrap();
        let event = session.get_event().unwrap();
        assert_eq!(event.event_type, MediaEventType::SessionStopped);
    }

    #[test]
    fn test_mf_event_with_error() {
        let event = MediaEvent::with_error("test error");
        assert_eq!(event.event_type, MediaEventType::Error);
        assert_eq!(event.status, -1);
        assert_eq!(event.data.as_deref(), Some("test error"));
    }

    #[test]
    fn test_mf_event_with_pts() {
        let event = MediaEvent::new(MediaEventType::SessionStarted).with_pts(12345);
        assert_eq!(event.pts, Some(12345));
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
    fn test_topology_build_playback() {
        let mut topology = Topology::new();
        topology
            .build_playback_topology("test.mp4", "H264 Decoder", "Metal Renderer")
            .unwrap();

        assert_eq!(topology.node_count(), 3);
        assert!(topology.source_node_id.is_some());
        assert!(topology.decoder_node_id.is_some());
        assert!(topology.renderer_node_id.is_some());

        // Check connections
        let source = topology.get_node(topology.source_node_id.unwrap()).unwrap();
        assert_eq!(source.outputs.len(), 1);

        let decoder = topology
            .get_node(topology.decoder_node_id.unwrap())
            .unwrap();
        assert_eq!(decoder.inputs.len(), 1);
        assert_eq!(decoder.outputs.len(), 1);

        let renderer = topology
            .get_node(topology.renderer_node_id.unwrap())
            .unwrap();
        assert_eq!(renderer.inputs.len(), 1);
    }

    #[test]
    fn test_topology_validate_valid() {
        let mut topology = Topology::new();
        topology
            .build_playback_topology("test.mp4", "Decoder", "Renderer")
            .unwrap();
        let _result = topology.validate();
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    #[test]
    fn test_topology_validate_empty() {
        let topology = Topology::new();
        let _result = topology.validate();
        assert!(_result.is_err(), "expected Err, got {_result:?}"); // No source node
    }

    #[test]
    fn test_topology_add_custom_node() {
        let mut topology = Topology::new();
        let id = topology.add_node(TopologyNodeType::Output, "Custom Output");
        let node = topology.get_node(id).unwrap();
        assert_eq!(node.node_type, TopologyNodeType::Output);
        assert_eq!(node.name, "Custom Output");
    }

    #[test]
    fn test_topology_connect() {
        let mut topology = Topology::new();
        let a = topology.add_node(TopologyNodeType::Source, "A");
        let b = topology.add_node(TopologyNodeType::Decoder, "B");

        let _result = topology.connect(a, b);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");

        let node_a = topology.get_node(a).unwrap();
        assert_eq!(node_a.outputs, vec![b]);

        let node_b = topology.get_node(b).unwrap();
        assert_eq!(node_b.inputs, vec![a]);
    }

    #[test]
    fn test_topology_connect_invalid() {
        let mut topology = Topology::new();
        let _result = topology.connect(1, 999);
        assert!(_result.is_err(), "expected Err, got {_result:?}"); // Target doesn't exist
    }

    #[test]
    fn test_topology_loader() {
        let mut topology = Topology::new();
        topology
            .build_playback_topology("test.mp4", "Decoder", "Renderer")
            .unwrap();

        let loader = TopologyLoader::new();
        let _result = loader.load(&topology);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    // =======================================================================
    // MFCreateMediaSession tests
    // =======================================================================

    #[test]
    fn test_mf_create_media_session() {
        let session = create_media_session();
        assert_eq!(session.state(), MfSessionState::Idle);
    }

    #[test]
    fn test_mf_create_media_session_with_flags() {
        let session = create_media_session_with_flags(0);
        assert_eq!(session.state(), MfSessionState::Idle);
    }

    // =======================================================================
    // Session position tests
    // =======================================================================

    #[test]
    fn test_mf_session_position() {
        let mut session = MfMediaSession::new();
        session.set_url_topology("test.mp4").unwrap();

        // Position should be 0 before starting
        assert_eq!(session.get_position(), 0);

        // Position should increase after start (just verify it's non-zero)
        session.start().unwrap();
        std::thread::sleep(std::time::Duration::from_micros(1000));
        let pos = session.get_position();
        assert!(pos > 0, "Position should increase after start, got {pos}");

        // After pause, position should stay constant
        session.pause().unwrap();
        let paused_pos = session.get_position();
        std::thread::sleep(std::time::Duration::from_micros(500));
        assert_eq!(session.get_position(), paused_pos);
    }

    // =======================================================================
    // Existing container parsing tests
    // =======================================================================

    #[test]
    fn test_parse_container_mp4() {
        let shim = MediaShim::new("/tmp/codecs");
        let bytes = build_container_bytes(
            ContainerKind::Mp4,
            VideoCodec::H264,
            AudioCodec::Aac,
            10000,
            300,
            200,
        );
        let parsed = shim.parse_container(&bytes).unwrap();
        assert_eq!(parsed.container, ContainerKind::Mp4);
        assert_eq!(parsed.video_codec, VideoCodec::H264);
        assert_eq!(parsed.audio_codec, AudioCodec::Aac);
        assert_eq!(parsed.duration_ms, 10000);
        assert_eq!(parsed.frame_count, 300);
    }

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

    #[test]
    fn test_measure_av_drift() {
        let shim = MediaShim::new("/tmp/codecs");
        let bytes = build_container_bytes(
            ContainerKind::Mp4,
            VideoCodec::H264,
            AudioCodec::Aac,
            10000,
            300,
            200,
        );
        let drift = shim.measure_av_drift_ms(&bytes).unwrap();
        // 300 frames * 41666 ≈ 12.5s video, 200 blocks * 41667 ≈ 8.33s audio
        assert!(drift > 0);
    }

    #[test]
    fn test_classify_input_valid() {
        let shim = MediaShim::new("/tmp/codecs");
        let bytes = build_container_bytes(
            ContainerKind::Mp4,
            VideoCodec::H264,
            AudioCodec::Aac,
            5000,
            150,
            100,
        );
        assert_eq!(shim.classify_input(&bytes), MediaInputClassification::Valid);
    }

    #[test]
    fn test_topology_node_types() {
        assert_eq!(TopologyNodeType::Source as u32, 0);
        assert_eq!(TopologyNodeType::Decoder as u32, 1);
        assert_eq!(TopologyNodeType::Renderer as u32, 2);
        assert_eq!(TopologyNodeType::Output as u32, 3);
    }

    #[test]
    fn test_mf_session_state_names() {
        assert_eq!(MfSessionState::Idle.name(), "Idle");
        assert_eq!(MfSessionState::Playing.name(), "Playing");
        assert_eq!(MfSessionState::Paused.name(), "Paused");
        assert_eq!(MfSessionState::Stopped.name(), "Stopped");
        assert_eq!(MfSessionState::Shutdown.name(), "Shutdown");
        assert_eq!(MfSessionState::Opening.name(), "Opening");
    }

    #[test]
    fn test_media_event_type_names() {
        assert_eq!(MediaEventType::SessionStarted.name(), "MESessionStarted");
        assert_eq!(MediaEventType::SessionPaused.name(), "MESessionPaused");
        assert_eq!(MediaEventType::SessionStopped.name(), "MESessionStopped");
        assert_eq!(MediaEventType::SessionEnded.name(), "MESessionEnded");
        assert_eq!(
            MediaEventType::BufferingStarted.name(),
            "MEBufferingStarted"
        );
        assert_eq!(
            MediaEventType::BufferingStopped.name(),
            "MEBufferingStopped"
        );
        assert_eq!(MediaEventType::Error.name(), "MEError");
        assert_eq!(MediaEventType::SessionShutdown.name(), "MESessionShutdown");
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

    #[test]
    fn test_mf_media_type_negotiation() {
        let mut input = ImfMediaType::new();
        input.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        input.set_guid(MF_MT_SUBTYPE, MFVideoFormat_H264);
        input.set_frame_size(1280, 720);

        let mut output = ImfMediaType::new();
        output.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        output.set_guid(MF_MT_SUBTYPE, MFVideoFormat_NV12);
        output.set_frame_size(1280, 720);

        // Verify input type is what an H.264 decoder expects
        assert_eq!(input.get_guid(&MF_MT_SUBTYPE), Some(MFVideoFormat_H264));
        assert_eq!(output.get_guid(&MF_MT_SUBTYPE), Some(MFVideoFormat_NV12));
        assert_eq!(input.get_frame_size(), output.get_frame_size());
    }

    // =======================================================================
    // IMFSample / IMFMediaBuffer tests
    // =======================================================================

    #[test]
    fn test_mf_sample_basic() {
        let data = vec![0u8; 100];
        let mut sample = ImfSample::new(data.clone());
        assert_eq!(sample.get_buffer(), &data);
        assert_eq!(sample.get_sample_time(), 0);
        assert_eq!(sample.get_sample_duration(), 0);

        sample.set_sample_time(1234567);
        sample.set_sample_duration(333333);
        assert_eq!(sample.get_sample_time(), 1234567);
        assert_eq!(sample.get_sample_duration(), 333333);

        sample.set_flags(1);
        assert_eq!(sample.get_flags(), 1);
    }

    #[test]
    fn test_mf_media_buffer() {
        let mut buf = ImfMediaBuffer::new(1024);
        assert_eq!(buf.get_max_length(), 1024);
        assert_eq!(buf.get_current_length(), 0);

        buf.set_current_length(512);
        assert_eq!(buf.get_current_length(), 512);

        let locked = buf.lock();
        assert_eq!(locked.len(), 512);
    }

    #[test]
    fn test_mf_media_buffer_from_data() {
        let data = vec![1u8, 2, 3, 4, 5];
        let buf = ImfMediaBuffer::from_data(data);
        assert_eq!(buf.get_max_length(), 5);
        assert_eq!(buf.get_current_length(), 5);
        assert_eq!(buf.lock_read(), &[1u8, 2, 3, 4, 5]);
    }

    // =======================================================================
    // MFT Transform tests
    // =======================================================================

    #[test]
    fn test_mft_h264_decoder_create() {
        let decoder = H264DecoderMft::new();
        let (in_streams, out_streams) = decoder.get_stream_count();
        assert_eq!(in_streams, 1);
        assert_eq!(out_streams, 1);
    }

    #[test]
    fn test_mft_h264_decoder_type_negotiation() {
        let decoder = H264DecoderMft::new();

        // Check available input types
        let input_type = decoder.get_input_available_type(0, 0).unwrap();
        assert_eq!(
            input_type.get_guid(&MF_MT_MAJOR_TYPE),
            Some(MFMediaType_Video)
        );
        assert_eq!(
            input_type.get_guid(&MF_MT_SUBTYPE),
            Some(MFVideoFormat_H264)
        );

        // Check available output types
        let output_type = decoder.get_output_available_type(0, 0).unwrap();
        assert_eq!(
            output_type.get_guid(&MF_MT_MAJOR_TYPE),
            Some(MFMediaType_Video)
        );
        assert_eq!(
            output_type.get_guid(&MF_MT_SUBTYPE),
            Some(MFVideoFormat_NV12)
        );
    }

    #[test]
    fn test_mft_aac_decoder_create() {
        let decoder = AacDecoderMft::new();
        let (in_streams, out_streams) = decoder.get_stream_count();
        assert_eq!(in_streams, 1);
        assert_eq!(out_streams, 1);
    }

    #[test]
    fn test_mft_aac_decoder_type_negotiation() {
        let decoder = AacDecoderMft::new();

        let input_type = decoder.get_input_available_type(0, 0).unwrap();
        assert_eq!(
            input_type.get_guid(&MF_MT_MAJOR_TYPE),
            Some(MFMediaType_Audio)
        );
        assert_eq!(input_type.get_guid(&MF_MT_SUBTYPE), Some(MFAudioFormat_AAC));

        let output_type = decoder.get_output_available_type(0, 0).unwrap();
        assert_eq!(
            output_type.get_guid(&MF_MT_MAJOR_TYPE),
            Some(MFMediaType_Audio)
        );
        assert_eq!(
            output_type.get_guid(&MF_MT_SUBTYPE),
            Some(MFAudioFormat_PCM)
        );
    }

    /// One real AAC frame (AAC-LC, 44.1 kHz, stereo) produced by the system
    /// AAC encoder (`afconvert -f adts -d aac` on a 440 Hz sine wave), with
    /// the 7-byte ADTS header stripped — a raw AAC data block.
    ///
    /// `AAC_FIXTURE_COOKIE` is the matching AudioSpecificConfig as an
    /// MPEG-4 `esds` descriptor blob, as delivered to
    /// `kAudioConverterDecompressionMagicCookie`. The raw-packet + cookie
    /// pairing is how MF pipelines carry AAC codec private data
    /// (`MF_MT_USER_DATA`).
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

    /// Decode a real AAC frame: feed the canned compressed packet (raw AAC
    /// data block + AudioSpecificConfig cookie via `MF_MT_USER_DATA`) through
    /// the MFT and assert the decode chain produces non-empty PCM with the
    /// negotiated format and preserved timestamps.
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

    #[test]
    fn test_presentation_clock_pause_resume() {
        let mut clock = PresentationClock::new();
        clock.start();

        // Let some time pass
        std::thread::sleep(std::time::Duration::from_millis(5));
        let t1 = clock.get_time();
        assert!(t1.as_millis() >= 4);

        clock.pause();
        assert!(clock.is_paused());

        let t2 = clock.get_time();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let t3 = clock.get_time();
        // Time should not advance while paused
        assert_eq!(t2.as_millis(), t3.as_millis());

        clock.resume();
        assert!(clock.is_running());
        let t4 = clock.get_time();
        assert!(t4 >= t3);
    }

    #[test]
    fn test_presentation_clock_rate() {
        let mut clock = PresentationClock::new();
        assert_eq!(clock.get_rate(), 1.0);

        clock.set_rate(2.0);
        assert_eq!(clock.get_rate(), 2.0);
    }

    #[test]
    fn test_presentation_clock_hns() {
        let mut clock = PresentationClock::new();
        clock.start();
        let hns = clock.get_time_hns();
        // Should be positive after starting
        assert!(hns >= 0);
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
    fn test_mf_startup_shutdown() {
        assert!(mf_startup(0x00020000, 0).is_ok());
        mf_shutdown();
    }

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

    #[test]
    fn test_mf_create_media_type() {
        let mt = mf_create_media_type();
        assert!(mt.attributes.is_empty());
    }

    #[test]
    fn test_mf_create_sample() {
        let sample = mf_create_sample();
        assert!(sample.buffer.is_empty());
    }

    #[test]
    fn test_mf_create_memory_buffer() {
        let buf = mf_create_memory_buffer(1024);
        assert_eq!(buf.get_max_length(), 1024);
        assert_eq!(buf.get_current_length(), 0);
    }

    // =======================================================================
    // GUID tests
    // =======================================================================

    #[test]
    fn test_guid_roundtrip() {
        let guid = Guid::new(
            0x12345678,
            0x9abc,
            0xdef0,
            [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
        );
        let bytes = guid.to_bytes_le();
        let guid2 = Guid::from_bytes_le(&bytes);
        assert_eq!(guid, guid2);
    }

    #[test]
    fn test_standard_guid_constants() {
        // Verify standard GUIDs are non-zero
        assert_ne!(MF_MT_MAJOR_TYPE, Guid::new(0, 0, 0, [0; 8]));
        assert_ne!(MFMediaType_Video, Guid::new(0, 0, 0, [0; 8]));
        assert_ne!(MFVideoFormat_H264, Guid::new(0, 0, 0, [0; 8]));
        assert_ne!(MFAudioFormat_AAC, Guid::new(0, 0, 0, [0; 8]));
    }
}
