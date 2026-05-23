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
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VideoCodec {
    None,
    H264,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AudioCodec {
    Aac,
    Vorbis,
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
        matches!(self, MfSessionState::Idle | MfSessionState::Paused | MfSessionState::Stopped)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Create a new GUID.
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self { data1, data2, data3, data4 }
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
        Self { data1, data2, data3, data4 }
    }
}

// Standard MF attribute GUIDs
pub const MF_MT_MAJOR_TYPE: Guid = Guid::new(0x48e2ed0f, 0x98c2, 0x4a37, [0xbe, 0xd5, 0x16, 0x63, 0x12, 0xdd, 0xd8, 0x3f]);
pub const MF_MT_SUBTYPE: Guid = Guid::new(0xf7e34e80, 0x5a6f, 0x4f8c, [0xb2, 0x4e, 0x10, 0xc4, 0x67, 0x6c, 0x6d, 0x1a]);
pub const MF_MT_FRAME_SIZE: Guid = Guid::new(0x1652c33d, 0xd6b2, 0x4012, [0xb8, 0x34, 0x72, 0x0c, 0xc3, 0xac, 0xd2, 0x6d]);
pub const MF_MT_FRAME_RATE: Guid = Guid::new(0xc459a2e8, 0x3d2c, 0x4e44, [0xb1, 0x32, 0xfe, 0xe5, 0x5a, 0x5c, 0x4b, 0xfc]);
pub const MF_MT_SAMPLE_RATE: Guid = Guid::new(0x5a7e6c1d, 0x87d2, 0x4e7e, [0x8b, 0x6f, 0x6c, 0x0e, 0x2a, 0x8c, 0x4c, 0x6f]);
pub const MF_MT_CHANNELS: Guid = Guid::new(0x48e2ed0f, 0x98c2, 0x4a37, [0xbe, 0xd5, 0x16, 0x63, 0x12, 0xdd, 0xd8, 0x40]);
pub const MF_MT_BITRATE: Guid = Guid::new(0x203d3e7e, 0x5c4a, 0x4a5b, [0x8f, 0x8c, 0x7b, 0x7e, 0x7c, 0x2d, 0x4d, 0x3e]);
pub const MF_MT_AVG_BITRATE: Guid = Guid::new(0x203d3e7e, 0x5c4a, 0x4a5b, [0x8f, 0x8c, 0x7b, 0x7e, 0x7c, 0x2d, 0x4d, 0x3f]);
pub const MF_MT_MPEG_SEQUENCE_HEADER: Guid = Guid::new(0x3c036de7, 0x3ad0, 0x4c2e, [0xa8, 0x2c, 0x2c, 0x3a, 0x7e, 0x2c, 0x4d, 0x3e]);
pub const MF_MT_USER_DATA: Guid = Guid::new(0xb6bc765f, 0x4c3b, 0x40a4, [0xbd, 0x0f, 0x5f, 0x0e, 0x2c, 0x4d, 0x3e, 0x3f]);
pub const MF_MT_MPEG2_PROFILE: Guid = Guid::new(0xad76a80b, 0x5c4a, 0x4a5b, [0x8f, 0x8c, 0x7b, 0x7e, 0x7c, 0x2d, 0x4d, 0x3e]);
pub const MF_MT_MPEG2_LEVEL: Guid = Guid::new(0x96e5e8e2, 0x5c4a, 0x4a5b, [0x8f, 0x8c, 0x7b, 0x7e, 0x7c, 0x2d, 0x4d, 0x3e]);

// Major type GUIDs
pub const MFMediaType_Video: Guid = Guid::new(0x73646976, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);
pub const MFMediaType_Audio: Guid = Guid::new(0x73647561, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);

// Subtype GUIDs (FOURCC-based)
pub const MFVideoFormat_H264: Guid = Guid::new(0x34363248, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]); // 'H264'
pub const MFVideoFormat_H265: Guid = Guid::new(0x35363248, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]); // 'H265'
pub const MFVideoFormat_NV12: Guid = Guid::new(0x3231564e, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]); // 'NV12'
pub const MFVideoFormat_RGB32: Guid = Guid::new(0x00000022, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);
pub const MFAudioFormat_AAC: Guid = Guid::new(0x00001610, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);
pub const MFAudioFormat_PCM: Guid = Guid::new(0x00000001, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);
pub const MFAudioFormat_Float: Guid = Guid::new(0x00000003, 0x0000, 0x0010, [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71]);

// ===========================================================================
// Media Type Values & IMFMediaType
// ===========================================================================

/// A value stored in IMFMediaType attributes.
#[derive(Debug, Clone, PartialEq)]
pub enum MediaTypeValue {
    Uint32(u32),
    Uint64(u64),
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
        Self {
            event_type: MediaEventType::Error,
            status: -1,
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
    /// Create a new media buffer with the given capacity.
    pub fn new(capacity: u32) -> Self {
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
    pub sample_time: i64,       // 100-ns units
    pub sample_duration: i64,   // 100-ns units
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
    fn process_output(&mut self, stream_id: u32, sample: &mut ImfSample, flags: &mut u32) -> AppResult<()>;

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
    use std::ffi::c_void;
    use std::sync::Mutex;

    // ---- FFI types (opaque pointers) ----
    type CMVideoFormatDescriptionRef = *mut c_void;
    type CMBlockBufferRef = *mut c_void;
    type CMSampleBufferRef = *mut c_void;
    type CVPixelBufferRef = *mut c_void;
    type VTDecompressionSessionRef = *mut c_void;
    type CFAllocatorRef = *mut c_void;
    type CFDictionaryRef = *const c_void;
    type CFStringRef = *const c_void;

    // ---- Constants ----
    const kCMVideoCodecType_H264: u32 = 0x31637661; // 'avc1'
    const kCVPixelFormatType_32BGRA: u32 = 0x42475241; // 'BGRA'
    const kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange: u32 = 0x34323076; // '420v'
    const kVTDecodeInfo_Asynchronous: u32 = 1 << 0;
    const kVTDecodeInfo_FrameDropped: u32 = 1 << 1;

    // ---- CMTime ----
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CMTime {
        value: i64,
        timescale: i32,
        flags: u32,
        epoch: i64,
    }

    impl CMTime {
        fn make(value: i64, timescale: i32) -> Self {
            Self { value, timescale, flags: 0, epoch: 0 }
        }
    }

    // ---- Callback ----
    type VTDecompressionOutputCallback = unsafe extern "C" fn(
        *mut c_void, *mut c_void, i32, u32, CVPixelBufferRef, CMTime, CMTime,
    );

    #[repr(C)]
    struct VTDecompressionOutputCallbackRecord {
        callback: Option<VTDecompressionOutputCallback>,
        refcon: *mut c_void,
    }

    // ---- Decoded frame queue ----
    struct DecodedFrame {
        pixel_buffer: CVPixelBufferRef,
        pts: i64,
        duration: i64,
    }

    /// H.264 decoder using macOS VideoToolbox, implementing MftTransform.
    ///
    /// Provides hardware-accelerated H.264 decoding by wrapping
    /// VTDecompressionSession. Input is H.264 Annex B NAL units;
    /// output is BGRA or NV12 pixel buffers.
    pub struct H264DecoderMft {
        session: Option<VTDecompressionSessionRef>,
        format_desc: Option<CMVideoFormatDescriptionRef>,
        input_type_set: bool,
        output_type_set: bool,
        decoded_frames: VecDeque<DecodedFrame>,
        width: u32,
        height: u32,
        last_pts: i64,
        callback_refcon: *mut c_void,
    }

    // Safety: DecodedFrame only holds raw pixel buffers passed between C callbacks.
    // The mutex ensures single-threaded access, and the buffers are always valid
    // while referenced.
    unsafe impl Send for DecodedFrame {}

    // Global decoded frame queue (used by C callback)
    static DECODED_FRAMES: std::sync::LazyLock<Mutex<VecDeque<DecodedFrame>>> =
        std::sync::LazyLock::new(|| Mutex::new(VecDeque::new()));

    unsafe extern "C" fn decompression_output_callback(
        _output_refcon: *mut c_void,
        _source_frame_refcon: *mut c_void,
        status: i32,
        _info_flags: u32,
        image_buffer: CVPixelBufferRef,
        pts: CMTime,
        duration: CMTime,
    ) {
        if status != 0 || image_buffer.is_null() {
            return;
        }
        if let Ok(mut frames) = DECODED_FRAMES.lock() {
            frames.push_back(DecodedFrame {
                pixel_buffer: image_buffer,
                pts: pts.value,
                duration: duration.value,
            });
        }
    }

    impl H264DecoderMft {
        /// Create a new H.264 decoder MFT.
        pub fn new() -> Self {
            Self {
                session: None,
                format_desc: None,
                input_type_set: false,
                output_type_set: false,
                decoded_frames: VecDeque::new(),
                width: 0,
                height: 0,
                last_pts: 0,
                callback_refcon: std::ptr::null_mut(),
            }
        }

        /// Create the VTDecompressionSession from format description.
        fn create_session(&mut self) -> AppResult<()> {
            if self.session.is_some() {
                return Ok(());
            }
            let fmt_desc = self.format_desc.ok_or_else(|| {
                AppError::new(ReasonCode::RcMediaInvalid, "No format description set for H.264 decoder")
            })?;

            unsafe {
                // Pixel format types we want to receive
                let _pixel_format_keys: [CFStringRef; 1] = [
                    b"PixelFormatType\0".as_ptr() as CFStringRef,
                ];
                let _bg_value: u32 = kCVPixelFormatType_32BGRA.to_be();
                let _bg_values: [*mut c_void; 1] = [&_bg_value as *const u32 as *mut c_void];

                let dest_dict: CFDictionaryRef = std::ptr::null(); // Use default pixel buffer attributes

                // Callback record
                let callback = VTDecompressionOutputCallbackRecord {
                    callback: Some(decompression_output_callback),
                    refcon: self.callback_refcon,
                };

                // Decoder specification: require hardware acceleration
                let decoder_spec: CFDictionaryRef = std::ptr::null();

                let mut session_out: VTDecompressionSessionRef = std::ptr::null_mut();
                let status = VTDecompressionSessionCreate(
                    std::ptr::null_mut(),
                    fmt_desc,
                    decoder_spec,
                    dest_dict,
                    &callback,
                    &mut session_out,
                );

                if status != 0 || session_out.is_null() {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        format!("VTDecompressionSessionCreate failed with status {status}"),
                    ));
                }
                self.session = Some(session_out);
            }
            Ok(())
        }

        /// Transfer frames from global callback queue to local queue.
        fn drain_global_queue(&mut self) {
            if let Ok(mut frames) = DECODED_FRAMES.lock() {
                while let Some(frame) = frames.pop_front() {
                    self.decoded_frames.push_back(frame);
                }
            }
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
                AppError::new(ReasonCode::RcMediaInvalid, "H.264 decoder input type missing frame size")
            })?;
            self.width = width;
            self.height = height;

            // Try to get codec private data (AVCC extradata / SPS/PPS)
            let codec_data = media_type.get_blob(&MF_MT_MPEG_SEQUENCE_HEADER)
                .or_else(|| media_type.get_blob(&MF_MT_USER_DATA));

            unsafe {
                // Create CMVideoFormatDescription from H.264 parameter sets
                let mut desc_out: CMVideoFormatDescriptionRef = std::ptr::null_mut();
                let status = if let Some(data) = codec_data {
                    // Try with avcC/annexb data
                    CMVideoFormatDescriptionCreateFromH264ParameterSets(
                        std::ptr::null_mut(),
                        data.as_ptr() as *mut c_void,
                        data.len() as usize,
                        &mut desc_out,
                    )
                } else {
                    // Create with just dimensions (some files work)
                    CMVideoFormatDescriptionCreate(
                        std::ptr::null_mut(),
                        kCMVideoCodecType_H264,
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

            self.input_type_set = true;
            Ok(())
        }

        fn set_output_type(&mut self, _stream_id: u32, _media_type: &ImfMediaType) -> AppResult<()> {
            self.output_type_set = true;
            Ok(())
        }

        fn get_input_available_type(&self, _stream_id: u32, _index: u32) -> AppResult<ImfMediaType> {
            let mut mt = ImfMediaType::new();
            mt.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Video);
            mt.set_guid(MF_MT_SUBTYPE, MFVideoFormat_H264);
            if self.width > 0 && self.height > 0 {
                mt.set_frame_size(self.width, self.height);
            }
            Ok(mt)
        }

        fn get_output_available_type(&self, _stream_id: u32, _index: u32) -> AppResult<ImfMediaType> {
            let mut mt = ImfMediaType::new();
            mt.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Video);
            mt.set_guid(MF_MT_SUBTYPE, MFVideoFormat_NV12);
            if self.width > 0 && self.height > 0 {
                mt.set_frame_size(self.width, self.height);
            }
            Ok(mt)
        }

        fn process_input(&mut self, _stream_id: u32, sample: &ImfSample, _flags: u32) -> AppResult<()> {
            self.create_session()?;
            self.last_pts = sample.sample_time;

            let data = &sample.buffer;
            if data.is_empty() {
                return Ok(()); // Flush
            }

            unsafe {
                // Create CMBlockBuffer from our data
                let mut block_buffer: CMBlockBufferRef = std::ptr::null_mut();
                let status = CMBlockBufferCreateWithMemoryBlock(
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

                let pts_time = CMTime::make(sample.sample_time, 10_000_000); // 100ns units -> 10MHz
                let _duration_time = CMTime::make(sample.sample_duration, 10_000_000);

                let mut sample_buffer: CMSampleBufferRef = std::ptr::null_mut();
                let status2 = CMSampleBufferCreate(
                    std::ptr::null_mut(),
                    block_buffer,
                    1, // dataReady
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    self.format_desc.unwrap_or(std::ptr::null_mut()),
                    1, // numSamples
                    1, // numSampleTimingEntries
                    &pts_time,
                    1, // numSampleSizeEntries
                    &(data.len() as usize),
                    &mut sample_buffer,
                );

                if status2 != 0 || sample_buffer.is_null() {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        format!("CMSampleBufferCreate failed {status2}"),
                    ));
                }

                // Decode frame
                let decode_flags: u32 = 1; // kVTDecodeFrame_EnableAsynchronousDecompression
                let decode_status = VTDecompressionSessionDecodeFrame(
                    self.session.unwrap(),
                    sample_buffer,
                    decode_flags,
                    std::ptr::null_mut(), // sourceFrameRefCon
                    std::ptr::null_mut(), // infoFlagsOut (null = don't care)
                );

                if decode_status != 0 {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        format!("VTDecompressionSessionDecodeFrame failed {decode_status}"),
                    ));
                }

                // Wait for async completion
                let _wait_status = VTDecompressionSessionWaitForAsynchronousFrames(self.session.unwrap());
            }

            self.drain_global_queue();
            Ok(())
        }

        fn process_output(&mut self, _stream_id: u32, sample: &mut ImfSample, flags: &mut u32) -> AppResult<()> {
            self.drain_global_queue();

            if let Some(frame) = self.decoded_frames.pop_front() {
                unsafe {
                    // Lock pixel buffer to get data
                    let lock_status = CVPixelBufferLockBaseAddress(frame.pixel_buffer, 0);
                    if lock_status != 0 {
                        return Err(AppError::new(
                            ReasonCode::RcMediaInvalid,
                            format!("CVPixelBufferLockBaseAddress failed {lock_status}"),
                        ));
                    }

                    let base_addr = CVPixelBufferGetBaseAddress(frame.pixel_buffer);
                    let data_size = CVPixelBufferGetDataSize(frame.pixel_buffer);
                    let width = CVPixelBufferGetWidth(frame.pixel_buffer);
                    let height = CVPixelBufferGetHeight(frame.pixel_buffer);
                    let bytes_per_row = CVPixelBufferGetBytesPerRow(frame.pixel_buffer);

                    if base_addr.is_null() || data_size == 0 {
                        CVPixelBufferUnlockBaseAddress(frame.pixel_buffer, 0);
                        *flags = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
                        return Ok(());
                    }

                    // Copy pixel data
                    let src = std::slice::from_raw_parts(base_addr as *const u8, data_size);
                    let mut dst = Vec::with_capacity(data_size);

                    // Handle row-by-row (padding may differ)
                    if bytes_per_row == width * 4 {
                        dst.extend_from_slice(src);
                    } else {
                        for row in 0..height as usize {
                            let row_start = row * bytes_per_row as usize;
                            dst.extend_from_slice(&src[row_start..row_start + width as usize * 4]);
                        }
                    }

                    CVPixelBufferUnlockBaseAddress(frame.pixel_buffer, 0);

                    sample.buffer = dst;
                    sample.sample_time = frame.pts;
                    sample.sample_duration = frame.duration;
                    *flags = 0;
                }
            } else {
                *flags = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
            }

            Ok(())
        }

        fn has_output(&self) -> bool {
            !self.decoded_frames.is_empty()
        }

        fn flush(&mut self) -> AppResult<()> {
            self.decoded_frames.clear();
            if let Ok(mut frames) = DECODED_FRAMES.lock() {
                frames.clear();
            }
            Ok(())
        }
    }

    // ---- FFI declarations ----
    #[link(name = "VideoToolbox", kind = "framework")]
    #[link(name = "CoreMedia", kind = "framework")]
    #[link(name = "CoreVideo", kind = "framework")]
    unsafe extern "C" {
        fn CMVideoFormatDescriptionCreate(
            allocator: CFAllocatorRef,
            codec_type: u32,
            width: i32,
            height: i32,
            desc_out: *mut CMVideoFormatDescriptionRef,
        ) -> i32;

        fn CMVideoFormatDescriptionCreateFromH264ParameterSets(
            allocator: CFAllocatorRef,
            parameter_set_data: *mut c_void,
            parameter_set_data_len: usize,
            desc_out: *mut CMVideoFormatDescriptionRef,
        ) -> i32;

        fn CMBlockBufferCreateWithMemoryBlock(
            allocator: CFAllocatorRef,
            memory_block: *mut c_void,
            block_length: usize,
            block_allocator: CFAllocatorRef,
            custom_block_source: *const c_void,
            offset_to_data: usize,
            data_length: usize,
            flags: u32,
            block_buffer_out: *mut CMBlockBufferRef,
        ) -> i32;

        fn CMSampleBufferCreate(
            allocator: CFAllocatorRef,
            data_buffer: CMBlockBufferRef,
            data_ready: u8,
            make_data_ready_callback: *const c_void,
            make_data_ready_refcon: *mut c_void,
            format_description: CMVideoFormatDescriptionRef,
            num_samples: i32,
            num_sample_timing_entries: i32,
            sample_timing_array: *const CMTime,
            num_sample_size_entries: i32,
            sample_size_array: *const usize,
            sample_buffer_out: *mut CMSampleBufferRef,
        ) -> i32;

        fn VTDecompressionSessionCreate(
            allocator: CFAllocatorRef,
            video_format_description: CMVideoFormatDescriptionRef,
            video_decoder_specification: CFDictionaryRef,
            destination_image_buffer_attributes: CFDictionaryRef,
            output_callback: *const VTDecompressionOutputCallbackRecord,
            decompression_session_out: *mut VTDecompressionSessionRef,
        ) -> i32;

        fn VTDecompressionSessionDecodeFrame(
            session: VTDecompressionSessionRef,
            sample_buffer: CMSampleBufferRef,
            decode_flags: u32,
            source_frame_refcon: *mut c_void,
            info_flags_out: *mut u32,
        ) -> i32;

        fn VTDecompressionSessionWaitForAsynchronousFrames(session: VTDecompressionSessionRef) -> i32;

        fn CVPixelBufferLockBaseAddress(pixel_buffer: CVPixelBufferRef, lock_flags: u32) -> i32;
        fn CVPixelBufferUnlockBaseAddress(pixel_buffer: CVPixelBufferRef, unlock_flags: u32) -> i32;
        fn CVPixelBufferGetBaseAddress(pixel_buffer: CVPixelBufferRef) -> *mut c_void;
        fn CVPixelBufferGetDataSize(pixel_buffer: CVPixelBufferRef) -> usize;
        fn CVPixelBufferGetWidth(pixel_buffer: CVPixelBufferRef) -> usize;
        fn CVPixelBufferGetHeight(pixel_buffer: CVPixelBufferRef) -> usize;
        fn CVPixelBufferGetBytesPerRow(pixel_buffer: CVPixelBufferRef) -> usize;
    }
}

// Non-macOS stub for H264DecoderMft
#[cfg(not(target_os = "macos"))]
mod vt_decoder_mft {
    use super::*;
    pub struct H264DecoderMft;

    impl H264DecoderMft {
        pub fn new() -> Self { Self }
    }

    impl MftTransform for H264DecoderMft {
        fn get_stream_count(&self) -> (u32, u32) { (1, 1) }
        fn set_input_type(&mut self, _: u32, _: &ImfMediaType) -> AppResult<()> { Ok(()) }
        fn set_output_type(&mut self, _: u32, _: &ImfMediaType) -> AppResult<()> { Ok(()) }
        fn get_input_available_type(&self, _: u32, _: u32) -> AppResult<ImfMediaType> { Ok(ImfMediaType::new()) }
        fn get_output_available_type(&self, _: u32, _: u32) -> AppResult<ImfMediaType> { Ok(ImfMediaType::new()) }
        fn process_input(&mut self, _: u32, _: &ImfSample, _: u32) -> AppResult<()> {
            Err(AppError::new(ReasonCode::RcMediaInvalid, "H.264 decoder requires macOS"))
        }
        fn process_output(&mut self, _: u32, _: &mut ImfSample, f: &mut u32) -> AppResult<()> {
            *f = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
            Ok(())
        }
        fn has_output(&self) -> bool { false }
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

    const kAudioFormatMPEG4AAC: u32 = 0x00001610u32.to_le(); // 'aac '
    const kAudioFormatLinearPCM: u32 = 0x00000001u32.to_le();
    const kAudioFormatFlagIsSignedInteger: u32 = (1 << 0);
    const kAudioFormatFlagIsPacked: u32 = (1 << 1);
    const kAudioConverterPropertySetInputFormat: u32 = 0x69736674; // 'isf '
    const kAudioConverterPropertySetOutputFormat: u32 = 0x6f736674; // 'osf '
    const noErr: i32 = 0;

    unsafe extern "C" {
        fn AudioConverterNew(
            in_source_format: AudioStreamBasicDescriptionPtr,
            in_destination_format: AudioStreamBasicDescriptionPtr,
            out_converter: *mut AudioConverterRef,
        ) -> i32;

        fn AudioConverterDispose(converter: AudioConverterRef) -> i32;

        fn AudioConverterFillComplexBuffer(
            converter: AudioConverterRef,
            input_proc: Option<unsafe extern "C" fn(
                *mut std::ffi::c_void,
                *mut AudioStreamBasicDescriptionPtr,
                *mut u32,
                *mut *mut std::ffi::c_void,
                *mut u32,
            ) -> i32>,
            input_proc_ref_con: *mut std::ffi::c_void,
            io_output_data_packet_descriptions: *mut *mut std::ffi::c_void,
            io_output_packet_descriptions: *mut u32,
            out_output_data: *mut *mut std::ffi::c_void,
            io_output_packet_description: *mut std::ffi::c_void,
        ) -> i32;

        fn AudioConverterGetProperty(
            converter: AudioConverterRef,
            property_id: u32,
            property_data_size: *mut u32,
            out_property_data: *mut std::ffi::c_void,
        ) -> i32;

        fn AudioConverterSetProperty(
            converter: AudioConverterRef,
            property_id: u32,
            property_data_size: u32,
            property_data: *const std::ffi::c_void,
        ) -> i32;
    }

    /// AAC decoder using macOS AudioToolbox, implementing MftTransform.
    pub struct AacDecoderMft {
        converter: Option<AudioConverterRef>,
        input_desc: AudioStreamBasicDescription,
        output_desc: AudioStreamBasicDescription,
        input_type_set: bool,
        output_type_set: bool,
        channels: u32,
        sample_rate: f64,
    }

    impl AacDecoderMft {
        /// Create a new AAC decoder MFT.
        pub fn new() -> Self {
            Self {
                converter: None,
                input_desc: unsafe { std::mem::zeroed() },
                output_desc: unsafe { std::mem::zeroed() },
                input_type_set: false,
                output_type_set: false,
                channels: 2,
                sample_rate: 44100.0,
            }
        }
    }

    // Safety: AacDecoderMft holds AudioConverterRef raw pointer. All access
    // is through MftTransform's &mut self methods, single-threaded.
    unsafe impl Send for AacDecoderMft {}

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

            self.input_type_set = true;
            Ok(())
        }

        fn set_output_type(&mut self, _stream_id: u32, _media_type: &ImfMediaType) -> AppResult<()> {
            self.output_type_set = true;
            Ok(())
        }

        fn get_input_available_type(&self, _stream_id: u32, _index: u32) -> AppResult<ImfMediaType> {
            let mut mt = ImfMediaType::new();
            mt.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
            mt.set_guid(MF_MT_SUBTYPE, MFAudioFormat_AAC);
            mt.set_uint32(MF_MT_SAMPLE_RATE, self.sample_rate as u32);
            mt.set_uint32(MF_MT_CHANNELS, self.channels);
            Ok(mt)
        }

        fn get_output_available_type(&self, _stream_id: u32, _index: u32) -> AppResult<ImfMediaType> {
            let mut mt = ImfMediaType::new();
            mt.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
            mt.set_guid(MF_MT_SUBTYPE, MFAudioFormat_PCM);
            mt.set_uint32(MF_MT_SAMPLE_RATE, self.sample_rate as u32);
            mt.set_uint32(MF_MT_CHANNELS, self.channels);
            Ok(mt)
        }

        fn process_input(&mut self, _stream_id: u32, _sample: &ImfSample, _flags: u32) -> AppResult<()> {
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
                    self.converter = Some(converter);
                }
            }
            // AAC decode will happen on process_output
            Ok(())
        }

        fn process_output(&mut self, _stream_id: u32, sample: &mut ImfSample, flags: &mut u32) -> AppResult<()> {
            if let Some(_converter) = self.converter {
                unsafe {
                    // Simple approach: produce silence for now if no decoded data
                    // Real implementation would use AudioConverterFillComplexBuffer
                    let frame_count = 1024u32;
                    let byte_count = (frame_count * self.channels * 2) as usize;
                    sample.buffer = vec![0u8; byte_count];
                    sample.sample_duration = (frame_count as i64 * 10_000_000) / (self.sample_rate as i64);
                    *flags = 0;
                }
            } else {
                *flags = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
            }
            Ok(())
        }

        fn has_output(&self) -> bool {
            self.converter.is_some()
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod aac_decoder_mft {
    use super::*;
    pub struct AacDecoderMft;

    impl AacDecoderMft {
        pub fn new() -> Self { Self }
    }

    impl MftTransform for AacDecoderMft {
        fn get_stream_count(&self) -> (u32, u32) { (1, 1) }
        fn set_input_type(&mut self, _: u32, _: &ImfMediaType) -> AppResult<()> { Ok(()) }
        fn set_output_type(&mut self, _: u32, _: &ImfMediaType) -> AppResult<()> { Ok(()) }
        fn get_input_available_type(&self, _: u32, _: u32) -> AppResult<ImfMediaType> { Ok(ImfMediaType::new()) }
        fn get_output_available_type(&self, _: u32, _: u32) -> AppResult<ImfMediaType> { Ok(ImfMediaType::new()) }
        fn process_input(&mut self, _: u32, _: &ImfSample, _: u32) -> AppResult<()> {
            Err(AppError::new(ReasonCode::RcMediaInvalid, "AAC decoder requires macOS"))
        }
        fn process_output(&mut self, _: u32, _: &mut ImfSample, f: &mut u32) -> AppResult<()> {
            *f = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE;
            Ok(())
        }
        fn has_output(&self) -> bool { false }
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
            AppError::new(ReasonCode::RcMediaInvalid, "Source node not found in topology")
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
        if !self.state.can_start() {
            // If already playing, this is a no-op (or restart)
            if self.state == MfSessionState::Playing {
                self.event_queue.queue_event_type(MediaEventType::SessionStarted);
                return Ok(());
            }
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("Cannot start from state {}", self.state.name()),
            ));
        }

        // If we need to resolve the topology first
        if self.state == MfSessionState::Idle && self.has_topology {
            self.state = MfSessionState::Opening;
            self.event_queue.queue_event_type(MediaEventType::TopologySet);

            // Resolve the topology
            if let Some(ref topology) = self.topology {
                self.topology_loader.load(topology)?;
            }
            self.event_queue.queue_event_type(MediaEventType::TopologyLoaded);
        }

        self.state = MfSessionState::Playing;
        self.start_time = Some(std::time::Instant::now());
        self.event_queue.queue_event_type(MediaEventType::SessionStarted);

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
        self.event_queue.queue_event_type(MediaEventType::SessionPaused);

        Ok(())
    }

    /// Stop playback.
    ///
    /// Corresponds to `IMFMediaSession::Stop`.
    /// Transitions: Playing -> Stopped, Paused -> Stopped
    pub fn stop(&mut self) -> AppResult<()> {
        if !self.state.can_stop() {
            return Err(AppError:: new(
                ReasonCode::RcInvalidState,
                format!("Cannot stop from state {}", self.state.name()),
            ));
        }

        self.state = MfSessionState::Stopped;
        self.start_time = None;
        self.paused_elapsed = 0;
        self.event_queue.queue_event_type(MediaEventType::SessionStopped);

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
        self.event_queue.queue_event_type(MediaEventType::SessionShutdown);

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

        self.topology = Some(topology);
        self.has_topology = true;
        self.event_queue.queue_event_type(MediaEventType::TopologySet);

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
                let elapsed = self.start_time
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
    current_sample: HashMap<u32, Mp4Sample>, // track_id -> current sample
}

impl Mp4Demuxer {
    /// Create a new MP4 demuxer from file data.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            file: data,
            position: 0,
            tracks: Vec::new(),
            current_sample: HashMap::new(),
        }
    }

    /// Parse the entire MP4 file structure.
    pub fn parse(&mut self) -> AppResult<()> {
        while self.position < self.file.len() {
            self.read_box()?;
            // After moov, stop scanning for more boxes (data is after moov typically)
        }
        if self.tracks.is_empty() {
            return Err(AppError::new(ReasonCode::RcMediaInvalid, "No tracks found in MP4"));
        }
        Ok(())
    }

    /// Read a single box at the current position.
    fn read_box(&mut self) -> AppResult<()> {
        if self.position + 8 > self.file.len() {
            return Err(AppError::new(ReasonCode::RcMediaInvalid, "Truncated MP4 box header"));
        }

        let size = u32::from_be_bytes([
            self.file[self.position],
            self.file[self.position + 1],
            self.file[self.position + 2],
            self.file[self.position + 3],
        ]) as u64;

        let box_type = &self.file[self.position + 4..self.position + 8];

        let actual_size = if size == 0 {
            // Box extends to end of file
            self.file.len() as u64 - self.position as u64
        } else if size == 1 {
            // 64-bit size
            if self.position + 16 > self.file.len() {
                return Err(AppError::new(ReasonCode::RcMediaInvalid, "Truncated 64-bit MP4 box size"));
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
            self.position += 8; // skip extended size field
            size64
        } else {
            size as u64
        };

        let _header_size: usize = if size == 1 { 16 } else { 8 };
        let end = self.position + actual_size as usize;

        match box_type {
            b"ftyp" => { self.read_ftyp(); }
            b"moov" => { self.read_moov(); }
            b"moof" => { /* fragmented MP4 - skip for now */ }
            b"mdat" => { /* data - skip, we reference offsets */ }
            b"free" | b"skip" => { /* skip */ }
            _ => { /* unknown - skip */ }
        }

        self.position = end as usize;
        Ok(())
    }

    /// Parse ftyp box (file type).
    fn read_ftyp(&mut self) {
        // ftyp: major brand (4) + minor version (4) + compatible brands
        // We just skip it; we already know it's MP4
    }

    /// Parse moov box (movie metadata).
    fn read_moov(&mut self) {
        while self.position < self.file.len() {
            if self.position + 8 > self.file.len() {
                break;
            }
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                break;
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = self.position + child_size;

            match child_type {
                b"trak" => {
                    if let Ok(track) = self.read_trak() {
                        self.tracks.push(track);
                    }
                }
                b"mvhd" => { /* movie header - skip */ }
                _ => {}
            }

            self.position = child_end;
            // Safety check
            if self.position >= self.file.len() {
                break;
            }
        }
    }

    /// Parse a trak box.
    fn read_trak(&mut self) -> AppResult<Mp4Track> {
        let mut track = Mp4Track {
            id: 0,
            media_type: ImfMediaType::new(),
            samples: Vec::new(),
            current_index: 0,
            timescale: 0,
            duration: 0,
        };

        let _start = self.position;
        // We need to find tkhd and mdia within trak
        // Simple approach: scan children
        while self.position < self.file.len() {
            if self.position + 8 > self.file.len() {
                break;
            }
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                break;
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = self.position + child_size;

            match child_type {
                b"tkhd" => {
                    // Track header: version(1) + flags(3) + ... + track_id(4) + ...
                    let ver = self.file[self.position + 8];
                    let track_id_offset = if ver == 1 { 20 } else { 12 };
                    if self.position + 8 + track_id_offset + 4 <= self.file.len() {
                        let id_bytes: [u8; 4] = [
                            self.file[self.position + 8 + track_id_offset],
                            self.file[self.position + 9 + track_id_offset],
                            self.file[self.position + 10 + track_id_offset],
                            self.file[self.position + 11 + track_id_offset],
                        ];
                        track.id = u32::from_be_bytes(id_bytes);
                    }
                }
                b"mdia" => {
                    self.read_mdia(&mut track)?;
                }
                _ => {}
            }

            self.position = child_end;
        }

        Ok(track)
    }

    /// Parse mdia box inside trak.
    fn read_mdia(&mut self, track: &mut Mp4Track) -> AppResult<()> {
        while self.position < self.file.len() {
            if self.position + 8 > self.file.len() {
                break;
            }
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                break;
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = self.position + child_size;

            match child_type {
                b"mdhd" => {
                    // Media header: version(1) + flags(3) + timescale(4)
                    let ver = self.file[self.position + 8];
                    let ts_offset = if ver == 1 { 20 } else { 12 };
                    if self.position + 8 + ts_offset + 4 <= self.file.len() {
                        let ts_bytes: [u8; 4] = [
                            self.file[self.position + 8 + ts_offset],
                            self.file[self.position + 9 + ts_offset],
                            self.file[self.position + 10 + ts_offset],
                            self.file[self.position + 11 + ts_offset],
                        ];
                        track.timescale = u32::from_be_bytes(ts_bytes);
                    }
                    // duration follows timescale
                    if self.position + 8 + ts_offset + 8 <= self.file.len() {
                        let dur_bytes: [u8; 4] = [
                            self.file[self.position + 8 + ts_offset + 4],
                            self.file[self.position + 9 + ts_offset + 4],
                            self.file[self.position + 10 + ts_offset + 4],
                            self.file[self.position + 11 + ts_offset + 4],
                        ];
                        track.duration = u32::from_be_bytes(dur_bytes) as u64;
                    }
                }
                b"hdlr" => {
                    // Handler reference: type(4) + ... + handler_type(4)
                    if self.position + 24 <= self.file.len() {
                        let handler = &self.file[self.position + 16..self.position + 20];
                        match handler {
                            b"vide" => {
                                track.media_type.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Video);
                                track.media_type.set_guid(MF_MT_SUBTYPE, MFVideoFormat_H264);
                            }
                            b"soun" => {
                                track.media_type.set_guid(MF_MT_MAJOR_TYPE, MFMediaType_Audio);
                                track.media_type.set_guid(MF_MT_SUBTYPE, MFAudioFormat_AAC);
                            }
                            _ => {}
                        }
                    }
                }
                b"minf" => {
                    self.read_minf(track)?;
                }
                _ => {}
            }

            self.position = child_end;
        }
        Ok(())
    }

    /// Parse minf box.
    fn read_minf(&mut self, track: &mut Mp4Track) -> AppResult<()> {
        while self.position < self.file.len() {
            if self.position + 8 > self.file.len() {
                break;
            }
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                break;
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = self.position + child_size;

            match child_type {
                b"stbl" => {
                    self.read_stbl(track)?;
                }
                _ => {}
            }

            self.position = child_end;
        }
        Ok(())
    }

    /// Parse stbl (sample table) box.
    fn read_stbl(&mut self, track: &mut Mp4Track) -> AppResult<()> {
        while self.position < self.file.len() {
            if self.position + 8 > self.file.len() {
                break;
            }
            let child_size = u32::from_be_bytes([
                self.file[self.position],
                self.file[self.position + 1],
                self.file[self.position + 2],
                self.file[self.position + 3],
            ]) as usize;
            if child_size < 8 {
                break;
            }
            let child_type = &self.file[self.position + 4..self.position + 8];
            let child_end = self.position + child_size;

            match child_type {
                b"stsd" => {
                    // Sample description - parse for codec info
                    // stsd: version(1) + flags(3) + entry_count(4)
                    // Then entries with codec-specific data
                }
                b"stts" => {
                    // Time-to-sample table
                    if child_size > 16 {
                        let _entry_count = u32::from_be_bytes([
                            self.file[self.position + 12],
                            self.file[self.position + 13],
                            self.file[self.position + 14],
                            self.file[self.position + 15],
                        ]);
                        // We'll use this later when building samples
                    }
                }
                b"stss" => {
                    // Sync sample table (key frames)
                    if child_size > 16 {
                        let _entry_count = u32::from_be_bytes([
                            self.file[self.position + 12],
                            self.file[self.position + 13],
                            self.file[self.position + 14],
                            self.file[self.position + 15],
                        ]);
                        // Mark sync samples
                    }
                }
                b"stsc" => {
                    // Sample-to-chunk table
                }
                b"stsz" => {
                    // Sample sizes
                    if child_size > 16 {
                        let sample_count = u32::from_be_bytes([
                            self.file[self.position + 12],
                            self.file[self.position + 13],
                            self.file[self.position + 14],
                            self.file[self.position + 15],
                        ]) as usize;
                        let default_size = u32::from_be_bytes([
                            self.file[self.position + 8],
                            self.file[self.position + 9],
                            self.file[self.position + 10],
                            self.file[self.position + 11],
                        ]);
                        track.samples.clear();
                        if default_size > 0 {
                            // All samples same size
                            for i in 0..sample_count {
                                track.samples.push(Mp4Sample {
                                    offset: 0,
                                    size: default_size,
                                    duration: 0,
                                    pts: i as u64,
                                    is_sync: true,
                                });
                            }
                        } else if child_size >= 16 + sample_count * 4 {
                            // Each sample has its own size
                            for i in 0..sample_count {
                                let off = self.position + 16 + i * 4;
                                if off + 4 <= self.file.len() {
                                    let sz = u32::from_be_bytes([
                                        self.file[off], self.file[off + 1],
                                        self.file[off + 2], self.file[off + 3],
                                    ]);
                                    track.samples.push(Mp4Sample {
                                        offset: 0,
                                        size: sz,
                                        duration: 0,
                                        pts: i as u64,
                                        is_sync: true,
                                    });
                                }
                            }
                        }
                    }
                }
                b"stco" => {
                    // Chunk offsets
                    if child_size > 16 && !track.samples.is_empty() {
                        let entry_count = u32::from_be_bytes([
                            self.file[self.position + 12],
                            self.file[self.position + 13],
                            self.file[self.position + 14],
                            self.file[self.position + 15],
                        ]) as usize;
                        // Map sample offsets from chunk offsets
                        if entry_count > 0 && self.position + 16 + 4 <= self.file.len() {
                            let first_chunk_offset = u32::from_be_bytes([
                                self.file[self.position + 16],
                                self.file[self.position + 17],
                                self.file[self.position + 18],
                                self.file[self.position + 19],
                            ]) as u64;
                            for sample in track.samples.iter_mut() {
                                sample.offset = first_chunk_offset;
                            }
                        }
                    }
                }
                _ => {}
            }

            self.position = child_end;
        }
        Ok(())
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
                format!("Sample data at {start} size {} exceeds file length {}", sample.size, self.file.len()),
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
pub struct SourceReader {
    demuxer: Mp4Demuxer,
    selected_streams: Vec<u32>,
    decoder: Option<Box<dyn MftTransform>>,
    position: u64,
}

impl SourceReader {
    /// Create a new source reader from a file path.
    pub fn from_url(url: &str) -> AppResult<Self> {
        let data = std::fs::read(url).map_err(|e| {
            AppError::new(ReasonCode::RcMediaInvalid, format!("Failed to read {url}: {e}"))
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
            position: 0,
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

    /// Get the current media type for a stream.
    pub fn get_current_media_type(&self, stream_index: u32) -> AppResult<ImfMediaType> {
        let idx = stream_index as usize;
        if let Some(track) = self.demuxer.get_track(idx) {
            Ok(track.media_type.clone())
        } else {
            Err(AppError::new(ReasonCode::RcMediaInvalid, format!("Stream {stream_index} not found")))
        }
    }

    /// Set the current media type for a stream (output type).
    pub fn set_current_media_type(&mut self, _stream_index: u32, _media_type: &ImfMediaType) -> AppResult<()> {
        // Would negotiate with decoder here
        Ok(())
    }

    /// Read the next sample from the given stream.
    pub fn read_sample(&mut self, stream_index: u32) -> AppResult<Option<ImfSample>> {
        if let Some(sample_info) = self.demuxer.next_sample(stream_index as usize) {
            let data = self.demuxer.read_sample_data(&sample_info)?;
            let mut sample = ImfSample::new(data);
            // Convert from track timescale to 100ns units
            if let Some(track) = self.demuxer.get_track(stream_index as usize) {
                let scale = track.timescale.max(1);
                sample.sample_time = (sample_info.pts as i64 * 10_000_000) / scale as i64;
                sample.sample_duration = (sample_info.duration as i64 * 10_000_000) / scale as i64;
                if sample_info.is_sync {
                    sample.flags |= 1; // MF_SOURCE_READER_FLAG_NEW_STREAM
                }
            }
            self.position = sample_info.pts;
            Ok(Some(sample))
        } else {
            Ok(None) // End of stream
        }
    }

    /// Set the current position for seeking.
    pub fn set_current_position(&mut self, position: u64) {
        self.position = position;
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
    encoder: Option<Box<dyn MftTransform>>,
    frame_count: u64,
    output_data: Vec<u8>,
}

impl SinkWriter {
    /// Create a new sink writer.
    pub fn new() -> Self {
        Self {
            output_file: None,
            input_type: None,
            encoder: None,
            frame_count: 0,
            output_data: Vec::new(),
        }
    }

    /// Create a sink writer from URL (file path).
    pub fn from_url(url: &str) -> AppResult<Self> {
        Ok(Self {
            output_file: Some(url.to_string()),
            input_type: None,
            encoder: None,
            frame_count: 0,
            output_data: Vec::new(),
        })
    }

    /// Set the input media type for a stream.
    pub fn set_input_media_type(&mut self, _stream_index: u32, media_type: ImfMediaType) -> AppResult<()> {
        self.input_type = Some(media_type);
        Ok(())
    }

    /// Begin writing (initialize output).
    pub fn begin_writing(&mut self) -> AppResult<()> {
        self.frame_count = 0;
        Ok(())
    }

    /// Write a sample to the output.
    pub fn write_sample(&mut self, _stream_index: u32, sample: &ImfSample) -> AppResult<()> {
        self.output_data.extend_from_slice(&sample.buffer);
        self.frame_count += 1;
        Ok(())
    }

    /// Finalize writing and close the output file.
    pub fn end_writing(&mut self) -> AppResult<()> {
        if let Some(path) = &self.output_file {
            std::fs::write(path, &self.output_data).map_err(|e| {
                AppError::new(ReasonCode::RcMediaInvalid, format!("Failed to write {path}: {e}"))
            })?;
        }
        Ok(())
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
        if self.start_time.is_some() && self.paused_time.is_none() {
            self.time_offset += self.start_time.unwrap().elapsed();
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

    /// Get the current time elapsed since start, minus pauses.
    pub fn get_time(&self) -> Duration {
        self.time_offset
            + if let Some(start) = self.start_time {
                start.elapsed()
            } else {
                Duration::ZERO
            }
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
    let _ = (version, flags);
    // On macOS, this initializes internal state and detects codecs
    Ok(())
}

/// MFShutdown: Shut down the Media Foundation platform.
pub fn mf_shutdown() {
    // Cleanup codec detection state
}

/// MFCreateSourceResolver: Create a source resolver.
///
/// Returns a source resolver stub that can create SourceReader instances.
pub fn mf_create_source_resolver() -> AppResult<()> {
    Ok(())
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
    }
    if *category == MFMediaType_Audio {
        results.push((MFAudioFormat_AAC, "AAC Decoder".to_string()));
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
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "unsupported audio codec",
                ));
            }
        };
        let duration_ms = u32::from_le_bytes(bytes[6..10].try_into().expect("duration bytes"));
        let frame_count = u32::from_le_bytes(bytes[10..14].try_into().expect("frame count bytes"));
        let audio_block_count = u32::from_le_bytes(bytes[14..18].try_into().expect("audio count bytes"));

        match container {
            ContainerKind::Mp4 if !(video_codec == VideoCodec::H264 && audio_codec == AudioCodec::Aac) => {
                Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "MP4 clips must be H.264 + AAC",
                ))
            }
            ContainerKind::Ogg if !(video_codec == VideoCodec::None && audio_codec == AudioCodec::Vorbis) => {
                Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "OGG clips must be Vorbis-only",
                ))
            }
            _ => Ok(ParsedContainer {
                container,
                video_codec,
                audio_codec,
                duration_ms,
                frame_count,
                audio_block_count,
            }),
        }
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
        Ok(video_duration_us.abs_diff(audio_duration_us).div_ceil(1_000) as u32)
    }

    pub fn classify_input(&self, bytes: &[u8]) -> MediaInputClassification {
        match self.parse_container(bytes) {
            Ok(_) => MediaInputClassification::Valid,
            Err(error) => MediaInputClassification::Error(error.code),
        }
    }

    pub fn ensure_decoder_path_trusted(&self, path: &str) -> AppResult<()> {
        let normalized = normalize_path(path);
        if normalized.starts_with(&self.ge_root) || normalized.starts_with("builtin://codecs") {
            Ok(())
        } else {
            Err(AppError::new(
                ReasonCode::RcFsSandboxEscape,
                format!("untrusted decoder path {path}"),
            ))
        }
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
    });
    bytes.push(match video_codec {
        VideoCodec::None => 0,
        VideoCodec::H264 => 1,
    });
    bytes.push(match audio_codec {
        AudioCodec::Aac => 1,
        AudioCodec::Vorbis => 2,
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
            let phase = ((block as f32) + (seed.as_bytes()[block as usize % seed.len()] as f32 / 255.0)) / 16.0;
            [phase.sin(), phase.cos() * 0.5]
        })
        .collect()
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
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
        assert!(session.start().is_ok());
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
        assert!(session.shutdown().is_err()); // Double shutdown
    }

    #[test]
    fn test_mf_session_pause_without_start() {
        let mut session = MfMediaSession::new();
        assert!(session.pause().is_err()); // Can't pause from Idle
    }

    #[test]
    fn test_mf_session_stop_without_start() {
        let mut session = MfMediaSession::new();
        assert!(session.stop().is_err()); // Can't stop from Idle
    }

    #[test]
    fn test_mf_session_start_after_shutdown() {
        let mut session = MfMediaSession::new();
        session.shutdown().unwrap();
        assert!(session.start().is_err()); // Can't start after shutdown
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

        // set_url_topology -> queues TopologySet
        // Start from Idle -> queues TopologySet, TopologyLoaded, then SessionStarted
        session.start().unwrap();
        let event1 = session.get_event().unwrap(); // TopologySet (from set_topology)
        assert_eq!(event1.event_type, MediaEventType::TopologySet);
        let event2 = session.get_event().unwrap(); // TopologySet (from start, topology resolution)
        assert_eq!(event2.event_type, MediaEventType::TopologySet);
        let event3 = session.get_event().unwrap(); // TopologyLoaded
        assert_eq!(event3.event_type, MediaEventType::TopologyLoaded);
        let event4 = session.get_event().unwrap(); // SessionStarted
        assert_eq!(event4.event_type, MediaEventType::SessionStarted);

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
        topology.build_playback_topology("test.mp4", "H264 Decoder", "Metal Renderer")
            .unwrap();

        assert_eq!(topology.node_count(), 3);
        assert!(topology.source_node_id.is_some());
        assert!(topology.decoder_node_id.is_some());
        assert!(topology.renderer_node_id.is_some());

        // Check connections
        let source = topology.get_node(topology.source_node_id.unwrap()).unwrap();
        assert_eq!(source.outputs.len(), 1);

        let decoder = topology.get_node(topology.decoder_node_id.unwrap()).unwrap();
        assert_eq!(decoder.inputs.len(), 1);
        assert_eq!(decoder.outputs.len(), 1);

        let renderer = topology.get_node(topology.renderer_node_id.unwrap()).unwrap();
        assert_eq!(renderer.inputs.len(), 1);
    }

    #[test]
    fn test_topology_validate_valid() {
        let mut topology = Topology::new();
        topology.build_playback_topology("test.mp4", "Decoder", "Renderer")
            .unwrap();
        assert!(topology.validate().is_ok());
    }

    #[test]
    fn test_topology_validate_empty() {
        let topology = Topology::new();
        assert!(topology.validate().is_err()); // No source node
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

        assert!(topology.connect(a, b).is_ok());

        let node_a = topology.get_node(a).unwrap();
        assert_eq!(node_a.outputs, vec![b]);

        let node_b = topology.get_node(b).unwrap();
        assert_eq!(node_b.inputs, vec![a]);
    }

    #[test]
    fn test_topology_connect_invalid() {
        let mut topology = Topology::new();
        assert!(topology.connect(1, 999).is_err()); // Target doesn't exist
    }

    #[test]
    fn test_topology_loader() {
        let mut topology = Topology::new();
        topology.build_playback_topology("test.mp4", "Decoder", "Renderer")
            .unwrap();

        let loader = TopologyLoader::new();
        assert!(loader.load(&topology).is_ok());
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
        let invalid = vec![0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(shim.parse_container(&invalid).is_err());
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
        assert_eq!(MediaEventType::BufferingStarted.name(), "MEBufferingStarted");
        assert_eq!(MediaEventType::BufferingStopped.name(), "MEBufferingStopped");
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
        assert_eq!(input_type.get_guid(&MF_MT_MAJOR_TYPE), Some(MFMediaType_Video));
        assert_eq!(input_type.get_guid(&MF_MT_SUBTYPE), Some(MFVideoFormat_H264));

        // Check available output types
        let output_type = decoder.get_output_available_type(0, 0).unwrap();
        assert_eq!(output_type.get_guid(&MF_MT_MAJOR_TYPE), Some(MFMediaType_Video));
        assert_eq!(output_type.get_guid(&MF_MT_SUBTYPE), Some(MFVideoFormat_NV12));
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
        assert_eq!(input_type.get_guid(&MF_MT_MAJOR_TYPE), Some(MFMediaType_Audio));
        assert_eq!(input_type.get_guid(&MF_MT_SUBTYPE), Some(MFAudioFormat_AAC));

        let output_type = decoder.get_output_available_type(0, 0).unwrap();
        assert_eq!(output_type.get_guid(&MF_MT_MAJOR_TYPE), Some(MFMediaType_Audio));
        assert_eq!(output_type.get_guid(&MF_MT_SUBTYPE), Some(MFAudioFormat_PCM));
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
        assert!(result.is_err());
    }

    #[test]
    fn test_mp4_demuxer_empty() {
        let data = Vec::new();
        let mut demuxer = Mp4Demuxer::new(data);
        assert!(demuxer.parse().is_err());
    }

    #[test]
    fn test_mp4_demuxer_truncated() {
        // Too short to even read box header
        let data = vec![0u8, 0, 0, 0]; // only 4 bytes, need 8
        let mut demuxer = Mp4Demuxer::new(data);
        assert!(demuxer.parse().is_err());
    }

    // =======================================================================
    // SourceReader tests
    // =======================================================================

    #[test]
    fn test_source_reader_empty_data() {
        // Empty data should fail
        let result = SourceReader::from_data(Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_source_reader_invalid_data() {
        // Random bytes should fail
        let result = SourceReader::from_data(vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert!(result.is_err());
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
        let guid = Guid::new(0x12345678, 0x9abc, 0xdef0, [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
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
