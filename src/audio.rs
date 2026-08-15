use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::winmm::{WaveFormatEx, WinMmSubsystem};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::process::{Command as HostCommand, Stdio};
use std::sync::RwLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub type DeviceId = u64;
pub type VoiceId = u64;
pub type AudioClientId = u64;
pub type DirectSoundId = u64;
pub type DirectSoundBufferId = u64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SampleFormat {
    Pcm16,
    Float32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaveFormat {
    pub channels: u16,
    pub sample_rate: u32,
    pub sample_format: SampleFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioDeviceInfo {
    pub id: DeviceId,
    pub name: String,
    pub channels: u16,
    pub sample_rate: u32,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AudioSamples {
    Pcm16(Vec<i16>),
    Float32(Vec<f32>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceBuffer {
    pub tag: String,
    pub samples: AudioSamples,
    pub loop_begin: Option<u32>,
    pub loop_length: Option<u32>,
    pub loop_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoiceCallbackEvent {
    pub voice: VoiceId,
    pub event: String,
    pub tag: String,
    pub sample_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LatencyRecord {
    pub subsystem: String,
    pub device_id: DeviceId,
    pub measured_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RenderOutput {
    pub samples: Vec<f32>,
    pub crc32: u32,
    pub voice_callbacks: Vec<VoiceCallbackEvent>,
    pub event_log: Vec<String>,
    pub latency_ms: u32,
    pub underflow_frames: u32,
    pub overflow_frames: u32,
}

#[derive(Debug, Clone)]
struct AudioDeviceRecord {
    info: AudioDeviceInfo,
    plugged: bool,
}

#[derive(Debug, Clone)]
struct QueuedBuffer {
    tag: String,
    samples: Vec<f32>,
    frames: usize,
    cursor: usize,
    loop_begin: Option<usize>,
    loop_length: Option<usize>,
    loop_count: u32,
    played_loops: u32,
    /// Set by `exit_loop` to stop an otherwise-infinite loop.
    loop_disabled: bool,
}

#[derive(Debug, Clone)]
enum VoiceKind {
    Mastering {
        device_id: DeviceId,
    },
    Submix {
        destination: VoiceId,
        reverb_mix: f32,
    },
    Source {
        destination: VoiceId,
        queue: VecDeque<QueuedBuffer>,
        played_frames: u64,
    },
}

/// Cheap discriminant of [`VoiceKind`] used to avoid cloning the full kind
/// (which owns the sample queue) on every render pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VoiceKindTag {
    Mastering,
    Submix,
    Source,
}

#[derive(Debug, Clone)]
struct VoiceRecord {
    format: WaveFormat,
    started: bool,
    volume: f32,
    channel_volumes: Vec<f32>,
    output_matrix: Vec<f32>,
    frequency_ratio: f32,
    kind: VoiceKind,
    /// Effects chain for this voice (applied during rendering).
    effects_chain: VoiceEffectsChain,
    /// Cached child voice IDs (voices whose destination is this voice),
    /// maintained on create/destroy so renders avoid scanning all voices.
    children: Vec<VoiceId>,
}

#[derive(Debug, Clone)]
struct AudioClientRecord {
    device_id: DeviceId,
    format: WaveFormat,
    buffer_frames: usize,
    event_driven: bool,
    started: bool,
    queue: VecDeque<f32>,
    played_frames: u64,
    underflow_frames: u32,
    overflow_frames: u32,
}

/// DirectSound buffer capability flags (mirrors Windows DSBCAPS_*).
pub const DSBCAPS_PRIMARYBUFFER: u32 = 0x00000001;
pub const DSBCAPS_STATIC: u32 = 0x00000002;
pub const DSBCAPS_LOCHARDWARE: u32 = 0x00000004;
pub const DSBCAPS_LOCSOFTWARE: u32 = 0x00000008;
pub const DSBCAPS_CTRLVOLUME: u32 = 0x00000080;
pub const DSBCAPS_CTRLPAN: u32 = 0x00000040;
pub const DSBCAPS_CTRLFREQUENCY: u32 = 0x00000020;
pub const DSBCAPS_CTRLPOSITIONNOTIFY: u32 = 0x00000100;
pub const DSBCAPS_GLOBALFOCUS: u32 = 0x8000_0000;
pub const DSBCAPS_GETCURRENTPOSITION2: u32 = 0x0001_0000;

/// Default DirectSound buffer size in bytes.
const DSBUFFER_DEFAULT_SIZE: usize = 4096;

/// Upper bound for a single DirectSound buffer allocation (64 MiB), to keep
/// guest-supplied sizes from triggering multi-GB allocations.
const MAX_DS_BUFFER_BYTES: usize = 64 * 1024 * 1024;

/// Upper bound for a single render request (1M frames ≈ 21 s at 48 kHz).
const MAX_RENDER_FRAMES: usize = 1_000_000;

/// Upper bound for the host-side capture buffer (1 MiB ≈ 5.5 s of stereo
/// 16-bit audio at 48 kHz).
const MAX_CAPTURE_BUFFER_BYTES: usize = 1 << 20;

/// Cap for the `notifications` / `latency_log` diagnostic logs.
const MAX_LOG_ENTRIES: usize = 10_000;

/// A single position notification entry (mirrors DSBPOSITIONNOTIFY).
#[derive(Debug, Clone)]
pub struct DsPositionNotify {
    /// Offset in bytes within the buffer at which to fire the notification.
    pub offset: u32,
    /// Event handle (guest-side) to signal.
    pub event_handle: u64,
}

#[derive(Debug, Clone)]
struct DirectSoundRecord {
    device_id: DeviceId,
    /// Primary buffer format (if set via SetFormat).
    primary_format: Option<WaveFormat>,
    /// Cooperative level set by the guest.
    cooperative_level: u32,
}

/// A locked region of a DirectSound buffer.
#[derive(Debug, Clone)]
struct LockedRegion {
    /// Audio pointer index (offset into `samples`) for the first locked part.
    offset: usize,
    /// Number of bytes (samples × sample_size) in the first locked part.
    length1: usize,
    /// Audio pointer index for the second locked part (wrap-around).
    offset2: usize,
    /// Number of bytes in the second locked part.
    length2: usize,
}

#[derive(Debug, Clone)]
struct DirectSoundBufferRecord {
    device_id: DeviceId,
    /// The `IDirectSound8` object that owns this buffer (for listener lookup).
    direct_sound_id: DirectSoundId,
    format: WaveFormat,
    /// Interleaved f32 sample data.
    samples: Vec<f32>,
    /// Current playback cursor (in frames).
    cursor: usize,
    /// Write cursor (for tracking Lock/Unlock positions).
    write_cursor: usize,
    /// Whether the buffer is currently playing.
    playing: bool,
    /// Whether the buffer is looping.
    looping: bool,
    /// Buffer capability flags.
    caps: u32,
    /// Volume in hundredths of a decibel (-10000 = silence, 0 = full).
    volume_db: i32,
    /// Pan in hundredths of a decibel (-10000 = full left, 0 = center, 10000 = full right).
    pan_db: i32,
    /// Frequency in Hz (0 = default = format.sample_rate).
    frequency: u32,
    /// Buffer size in bytes (for position tracking).
    buffer_size_bytes: usize,
    /// Locked regions (for Lock/Unlock).
    locked_regions: Vec<LockedRegion>,
    /// Position notifications.
    notifications: Vec<DsPositionNotify>,
    /// Notifications that have been fired (to avoid re-signalling).
    fired_notifications: Vec<u32>,
    /// Whether the buffer has been lost (e.g., device change).
    lost: bool,
    /// Buffer priority (for SetCooperativeLevel).
    priority: u32,
}

// ── DirectSound3D constants ────────────────────────────────────────────────

/// Default distance factor (meters per world unit).
pub const DS3D_DEFAULT_DISTANCE_FACTOR: f32 = 1.0;
/// Default Doppler factor (normal).
pub const DS3D_DEFAULT_DOPPLER_FACTOR: f32 = 1.0;
/// Default rolloff factor (normal).
pub const DS3D_DEFAULT_ROLLOFF_FACTOR: f32 = 1.0;
/// Default cone inside angle (360° = omnidirectional).
pub const DS3D_DEFAULT_CONE_INSIDE_ANGLE: u32 = 360;
/// Default cone outside angle (360° = omnidirectional).
pub const DS3D_DEFAULT_CONE_OUTSIDE_ANGLE: u32 = 360;
/// Default cone outside volume attenuation (0 dB).
pub const DS3D_DEFAULT_CONE_OUTSIDE_VOLUME: i32 = 0;
/// Default minimum distance.
pub const DS3D_DEFAULT_MIN_DISTANCE: f32 = 1.0;
/// Default maximum distance.
pub const DS3D_DEFAULT_MAX_DISTANCE: f32 = 1_000_000_000.0;
/// Default number of speakers (auto-detect).
pub const DS3D_DEFAULT_NUM_SPEAKERS: i32 = -1;
/// Speed of sound in meters per second (used for Doppler calculation).
pub const DS3D_SPEED_OF_SOUND: f32 = 343.0;

/// DirectSound3D buffer mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ds3dMode {
    /// Normal 3D processing.
    Normal,
    /// 3D processing disabled; no positional effects applied.
    Disable,
    /// Buffer position is relative to the listener's head.
    HeadRelative,
}

/// Per-buffer state for DirectSound3D positional audio.
///
/// Tracks position, velocity, cone angles, distance boundaries, and
/// processing mode for a single `IDirectSound3DBuffer8`.
#[derive(Debug, Clone)]
pub struct Ds3dBufferState {
    /// Position in 3D space (x, y, z) in world units.
    pub position: [f32; 3],
    /// Velocity vector (x, y, z) for Doppler effect.
    pub velocity: [f32; 3],
    /// Cone inner angle in degrees (default 360 = omnidirectional).
    pub cone_inside_angle: u32,
    /// Cone outer angle in degrees.
    pub cone_outside_angle: u32,
    /// Cone outside volume attenuation in dB (negative values).
    pub cone_outside_volume: i32,
    /// Minimum distance before distance attenuation begins.
    pub min_distance: f32,
    /// Maximum distance beyond which no further attenuation occurs.
    pub max_distance: f32,
    /// 3D processing mode.
    pub mode: Ds3dMode,
}

impl Default for Ds3dBufferState {
    fn default() -> Self {
        Self {
            position: [0.0; 3],
            velocity: [0.0; 3],
            cone_inside_angle: DS3D_DEFAULT_CONE_INSIDE_ANGLE,
            cone_outside_angle: DS3D_DEFAULT_CONE_OUTSIDE_ANGLE,
            cone_outside_volume: DS3D_DEFAULT_CONE_OUTSIDE_VOLUME,
            min_distance: DS3D_DEFAULT_MIN_DISTANCE,
            max_distance: DS3D_DEFAULT_MAX_DISTANCE,
            mode: Ds3dMode::Normal,
        }
    }
}

/// Listener state for DirectSound3D positional audio.
///
/// There is one listener per `IDirectSound8` object.  It defines the
/// position, orientation, velocity, and environmental scaling factors
/// used to compute 3D audio effects for all buffers in the same sound
/// object.
#[derive(Debug, Clone)]
pub struct Ds3dListenerState {
    /// Listener position in 3D space (x, y, z).
    pub position: [f32; 3],
    /// Listener velocity vector (x, y, z) for Doppler.
    pub velocity: [f32; 3],
    /// Forward orientation vector (x, y, z) — must be normalised.
    pub forward: [f32; 3],
    /// Up orientation vector (x, y, z) — must be normalised.
    pub up: [f32; 3],
    /// Distance factor (meters per world unit).
    pub distance_factor: f32,
    /// Doppler factor (0 = no Doppler, 1 = normal).
    pub doppler_factor: f32,
    /// Rolloff factor (1 = normal, >1 = steeper attenuation).
    pub rolloff_factor: f32,
    /// Number of stereo speakers (2 for headphones, 2+ for speakers).
    pub num_speakers: i32,
}

impl Default for Ds3dListenerState {
    fn default() -> Self {
        Self {
            position: [0.0; 3],
            velocity: [0.0; 3],
            forward: [0.0, 0.0, 1.0], // +Z forward
            up: [0.0, 1.0, 0.0],      // +Y up
            distance_factor: DS3D_DEFAULT_DISTANCE_FACTOR,
            doppler_factor: DS3D_DEFAULT_DOPPLER_FACTOR,
            rolloff_factor: DS3D_DEFAULT_ROLLOFF_FACTOR,
            num_speakers: DS3D_DEFAULT_NUM_SPEAKERS,
        }
    }
}

#[derive(Debug)]
pub struct AudioSubsystem {
    next_id: u64,
    devices: BTreeMap<DeviceId, AudioDeviceRecord>,
    default_device: DeviceId,
    voices: BTreeMap<VoiceId, VoiceRecord>,
    audio_clients: BTreeMap<AudioClientId, AudioClientRecord>,
    direct_sound: BTreeMap<DirectSoundId, DirectSoundRecord>,
    direct_sound_buffers: BTreeMap<DirectSoundBufferId, DirectSoundBufferRecord>,
    /// Per-buffer DirectSound3D positional state.
    ds3d_buffer_states: HashMap<DirectSoundBufferId, Ds3dBufferState>,
    /// Per-`IDirectSound8` listener state (keyed by DirectSoundId).
    ds3d_listener_state: HashMap<DirectSoundId, Ds3dListenerState>,
    notifications: Vec<String>,
    latency_log: Vec<LatencyRecord>,
    /// WinMM (Windows Multimedia) audio subsystem.
    pub winmm: RwLock<WinMmSubsystem>,
    /// Whether audio capture (microphone/line-in) is active.
    pub capture_active: bool,
    /// Which wave_in device handle is currently capturing.
    pub capture_device_handle: u32,
    /// Ring buffer for captured audio data (PCM bytes).
    pub capture_buffer: Vec<u8>,
}

impl Default for AudioSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioSubsystem {
    pub fn new() -> Self {
        let mut devices = BTreeMap::new();
        devices.insert(
            1,
            AudioDeviceRecord {
                info: AudioDeviceInfo {
                    id: 1,
                    name: "Built-in Speakers".to_string(),
                    channels: 2,
                    sample_rate: 48_000,
                    is_default: true,
                },
                plugged: true,
            },
        );
        devices.insert(
            2,
            AudioDeviceRecord {
                info: AudioDeviceInfo {
                    id: 2,
                    name: "HDMI Output".to_string(),
                    channels: 2,
                    sample_rate: 48_000,
                    is_default: false,
                },
                plugged: true,
            },
        );
        Self {
            next_id: 3,
            devices,
            default_device: 1,
            voices: BTreeMap::new(),
            audio_clients: BTreeMap::new(),
            direct_sound: BTreeMap::new(),
            direct_sound_buffers: BTreeMap::new(),
            ds3d_buffer_states: HashMap::new(),
            ds3d_listener_state: HashMap::new(),
            notifications: Vec::new(),
            latency_log: Vec::new(),
            winmm: RwLock::new(WinMmSubsystem::new()),
            capture_active: false,
            capture_device_handle: 0,
            capture_buffer: Vec::new(),
        }
    }

    // ── DirectSound helper: decibel to linear gain ──────────────────────

    /// Convert DirectSound volume (hundredths of dB) to linear gain [0.0, 1.0].
    /// -10000 = silence, 0 = full volume.
    fn ds_volume_to_gain(volume_db: i32) -> f32 {
        if volume_db <= -10000 {
            0.0
        } else if volume_db >= 0 {
            1.0
        } else {
            10.0_f32.powf(volume_db as f32 / 2000.0)
        }
    }

    /// Convert DirectSound pan (hundredths of dB) to left/right gains.
    /// -10000 = full left, 0 = center, 10000 = full right.
    fn ds_pan_to_gains(pan_db: i32) -> (f32, f32) {
        if pan_db <= -10000 {
            (1.0, 0.0) // Full left
        } else if pan_db >= 10000 {
            (0.0, 1.0) // Full right
        } else if pan_db == 0 {
            (1.0, 1.0) // Center
        } else if pan_db < 0 {
            // Left bias: left stays at 1.0, right is attenuated
            let right_gain = 10.0_f32.powf(pan_db as f32 / 2000.0);
            (1.0, right_gain)
        } else {
            // Right bias: right stays at 1.0, left is attenuated
            let left_gain = 10.0_f32.powf(-pan_db as f32 / 2000.0);
            (left_gain, 1.0)
        }
    }

    /// Convert a byte offset to a frame offset based on the buffer format.
    fn byte_to_frame(byte_offset: usize, channels: usize) -> usize {
        // f32 samples: 4 bytes per sample
        byte_offset / (channels * 4)
    }

    /// Convert a frame offset to a byte offset based on the buffer format.
    fn frame_to_byte(frame_offset: usize, channels: usize) -> usize {
        frame_offset * channels * 4
    }

    pub fn devices(&self) -> Vec<AudioDeviceInfo> {
        self.devices
            .values()
            .filter(|device| device.plugged)
            .map(|device| device.info.clone())
            .collect()
    }

    pub fn default_device(&self) -> DeviceId {
        self.default_device
    }

    pub fn notifications(&self) -> &[String] {
        &self.notifications
    }

    pub fn latency_log(&self) -> &[LatencyRecord] {
        &self.latency_log
    }

    pub fn add_device(&mut self, name: &str, channels: u16, sample_rate: u32) -> DeviceId {
        let id = self.alloc_id();
        self.devices.insert(
            id,
            AudioDeviceRecord {
                info: AudioDeviceInfo {
                    id,
                    name: name.to_string(),
                    channels,
                    sample_rate,
                    is_default: false,
                },
                plugged: true,
            },
        );
        self.push_notification(format!("device_added:{id}:{name}"));
        id
    }

    pub fn remove_device(&mut self, device: DeviceId) -> AppResult<()> {
        let record = self.device_mut(device)?;
        record.plugged = false;
        record.info.is_default = false;
        self.push_notification(format!("device_removed:{device}"));
        if self.default_device == device {
            let replacement = self
                .devices
                .values()
                .find(|candidate| candidate.plugged)
                .map(|candidate| candidate.info.id)
                .ok_or_else(|| {
                    AppError::new(ReasonCode::RcAudioUnsupported, "no audio devices remain")
                })?;
            self.set_default_device(replacement)?;
        }
        Ok(())
    }

    pub fn set_default_device(&mut self, device: DeviceId) -> AppResult<()> {
        self.device(device)?;
        let old_default = self.default_device;
        if old_default == device {
            return Ok(());
        }
        if let Some(old) = self.devices.get_mut(&old_default) {
            old.info.is_default = false;
        }
        if let Some(new_default) = self.devices.get_mut(&device) {
            new_default.info.is_default = true;
        }
        self.default_device = device;
        self.push_notification(format!("default_changed:{old_default}->{device}"));

        let active_mastering = self
            .voices
            .iter()
            .filter_map(|(voice_id, voice)| match voice.kind {
                VoiceKind::Mastering { .. } if voice.started => Some(*voice_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        if !active_mastering.is_empty() {
            self.push_notification(format!("playback_stop:{old_default}"));
            for voice_id in active_mastering {
                if let VoiceKind::Mastering { device_id } = &mut self.voice_mut(voice_id)?.kind {
                    *device_id = device;
                }
            }
            self.push_notification(format!("playback_recover:{device}"));
        }

        for client in self.audio_clients.values_mut() {
            if client.started && client.device_id == old_default {
                client.device_id = device;
            }
        }
        for ds in self.direct_sound.values_mut() {
            if ds.device_id == old_default {
                ds.device_id = device;
            }
        }
        for buffer in self.direct_sound_buffers.values_mut() {
            if buffer.device_id == old_default {
                buffer.device_id = device;
            }
        }
        Ok(())
    }

    pub fn create_mastering_voice(&mut self, format: WaveFormat) -> AppResult<VoiceId> {
        self.validate_format(&format)?;
        let id = self.alloc_id();
        self.voices.insert(
            id,
            VoiceRecord {
                channel_volumes: vec![1.0; format.channels as usize],
                format,
                kind: VoiceKind::Mastering {
                    device_id: self.default_device,
                },
                output_matrix: Vec::new(),
                started: false,
                volume: 1.0,
                frequency_ratio: 1.0,
                effects_chain: VoiceEffectsChain::new(),
                children: Vec::new(),
            },
        );
        Ok(id)
    }

    pub fn create_submix_voice(
        &mut self,
        format: WaveFormat,
        destination: VoiceId,
    ) -> AppResult<VoiceId> {
        self.validate_format(&format)?;
        self.voice(destination)?;
        let id = self.alloc_id();
        self.voices.insert(
            id,
            VoiceRecord {
                channel_volumes: vec![1.0; format.channels as usize],
                format,
                kind: VoiceKind::Submix {
                    destination,
                    reverb_mix: 0.0,
                },
                output_matrix: Vec::new(),
                started: false,
                volume: 1.0,
                frequency_ratio: 1.0,
                effects_chain: VoiceEffectsChain::new(),
                children: Vec::new(),
            },
        );
        // Cache this voice as a child of its destination.
        if let Some(parent) = self.voices.get_mut(&destination) {
            parent.children.push(id);
        }
        Ok(id)
    }

    pub fn create_source_voice(
        &mut self,
        format: WaveFormat,
        destination: VoiceId,
    ) -> AppResult<VoiceId> {
        self.validate_format(&format)?;
        self.voice(destination)?;
        let id = self.alloc_id();
        self.voices.insert(
            id,
            VoiceRecord {
                channel_volumes: vec![1.0; format.channels as usize],
                format,
                kind: VoiceKind::Source {
                    destination,
                    queue: VecDeque::new(),
                    played_frames: 0,
                },
                output_matrix: Vec::new(),
                started: false,
                volume: 1.0,
                effects_chain: VoiceEffectsChain::new(),
                frequency_ratio: 1.0,
                children: Vec::new(),
            },
        );
        // Cache this voice as a child of its destination.
        if let Some(parent) = self.voices.get_mut(&destination) {
            parent.children.push(id);
        }
        Ok(id)
    }

    pub fn voice_format(&self, voice: VoiceId) -> AppResult<WaveFormat> {
        Ok(self.voice(voice)?.format.clone())
    }

    pub fn voice_started(&self, voice: VoiceId) -> AppResult<bool> {
        Ok(self.voice(voice)?.started)
    }

    pub fn queued_source_frames(&self, voice: VoiceId) -> AppResult<usize> {
        match &self.voice(voice)?.kind {
            VoiceKind::Source { queue, .. } => Ok(queue
                .iter()
                .map(|buffer| buffer.frames.saturating_sub(buffer.cursor))
                .sum()),
            _ => Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "queued frame count requires a source voice",
            )),
        }
    }

    pub fn audio_client_format(&self, client: AudioClientId) -> AppResult<WaveFormat> {
        Ok(self.audio_client(client)?.format.clone())
    }

    pub fn start_voice(&mut self, voice: VoiceId) -> AppResult<()> {
        self.voice_mut(voice)?.started = true;
        Ok(())
    }

    pub fn stop_voice(&mut self, voice: VoiceId) -> AppResult<()> {
        self.voice_mut(voice)?.started = false;
        Ok(())
    }

    pub fn submit_source_buffer(&mut self, voice: VoiceId, buffer: SourceBuffer) -> AppResult<()> {
        let (source_format, destination, loop_begin, loop_length, loop_count) = {
            let voice_record = self.voice(voice)?;
            let destination = match voice_record.kind {
                VoiceKind::Source { destination, .. } => destination,
                _ => {
                    return Err(AppError::new(
                        ReasonCode::RcAudioUnsupported,
                        "SubmitSourceBuffer requires a source voice",
                    ));
                }
            };
            (
                voice_record.format.clone(),
                destination,
                buffer.loop_begin,
                buffer.loop_length,
                buffer.loop_count,
            )
        };
        let destination_rate = self.voice(destination)?.format.sample_rate;
        let samples = convert_samples(buffer.samples);
        let resampled = resample_interleaved(
            &samples,
            source_format.channels as usize,
            source_format.sample_rate,
            destination_rate,
        );
        let channels = source_format.channels as usize;
        let frame_count = resampled.len() / channels;
        if frame_count == 0 {
            // An empty buffer with loop parameters would spin forever in the
            // render loop (cursor >= frames is always true); reject it.
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "cannot submit an empty source buffer",
            ));
        }
        let src_to_dst_ratio = destination_rate as f64 / source_format.sample_rate as f64;
        // XAudio2 loop points are in samples (per channel); convert them to
        // frames and clamp into the buffer so the render loop can never
        // rewind to a position at/after the end of the data.
        let loop_begin_frame = loop_begin
            .map(|lb| ((lb as f64 * src_to_dst_ratio) / channels as f64) as usize)
            .map(|lb| lb.min(frame_count.saturating_sub(1)));
        let loop_length_frames = loop_length.map(|ll| {
            (((ll as f64 * src_to_dst_ratio) / channels as f64) as usize)
                .min(frame_count.saturating_sub(loop_begin_frame.unwrap_or(0)))
        });
        let record = self.voice_mut(voice)?;
        match &mut record.kind {
            VoiceKind::Source { queue, .. } => queue.push_back(QueuedBuffer {
                tag: buffer.tag,
                samples: resampled,
                frames: frame_count,
                cursor: 0,
                loop_begin: loop_begin_frame,
                loop_length: loop_length_frames,
                loop_count: loop_count.unwrap_or(0),
                played_loops: 0,
                loop_disabled: false,
            }),
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    "submit_source_buffer requires a source voice",
                ));
            }
        }
        Ok(())
    }

    pub fn flush_source_buffers(&mut self, voice: VoiceId) -> AppResult<()> {
        match &mut self.voice_mut(voice)?.kind {
            VoiceKind::Source { queue, .. } => {
                queue.clear();
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "FlushSourceBuffers requires a source voice",
            )),
        }
    }

    pub fn destroy_voice(&mut self, voice: VoiceId) -> AppResult<()> {
        let children = self.child_voice_ids(voice);
        for child in children {
            self.destroy_voice(child)?;
        }
        // Unlink this voice from its parent's cached child list.
        let parent_id = self.voices.get(&voice).and_then(|record| match record.kind {
            VoiceKind::Submix { destination, .. } | VoiceKind::Source { destination, .. } => {
                Some(destination)
            }
            _ => None,
        });
        if let Some(parent_id) = parent_id
            && let Some(parent) = self.voices.get_mut(&parent_id)
        {
            parent.children.retain(|&child| child != voice);
        }
        self.voices.remove(&voice).map(|_| ()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown voice {voice}"),
            )
        })
    }

    pub fn set_volume(&mut self, voice: VoiceId, volume: f32) -> AppResult<()> {
        self.voice_mut(voice)?.volume = volume;
        Ok(())
    }

    pub fn set_channel_volumes(&mut self, voice: VoiceId, volumes: Vec<f32>) -> AppResult<()> {
        let voice_record = self.voice_mut(voice)?;
        if volumes.len() != voice_record.format.channels as usize {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "channel volume count does not match voice format",
            ));
        }
        voice_record.channel_volumes = volumes;
        Ok(())
    }

    pub fn set_output_matrix(&mut self, voice: VoiceId, matrix: Vec<f32>) -> AppResult<()> {
        let (source_channels, destination) = {
            let record = self.voice(voice)?;
            let destination = match record.kind {
                VoiceKind::Mastering { .. } => None,
                VoiceKind::Submix { destination, .. } | VoiceKind::Source { destination, .. } => {
                    Some(destination)
                }
            };
            (record.format.channels as usize, destination)
        };
        if let Some(destination) = destination {
            let destination_channels = self.voice(destination)?.format.channels as usize;
            if matrix.len() != source_channels * destination_channels {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    "output matrix size does not match source and destination channels",
                ));
            }
        }
        self.voice_mut(voice)?.output_matrix = matrix;
        Ok(())
    }

    pub fn volume(&self, voice: VoiceId) -> AppResult<f32> {
        Ok(self.voice(voice)?.volume)
    }

    pub fn channel_volume(&self, voice: VoiceId, channel: usize) -> AppResult<f32> {
        Ok(self
            .voice(voice)?
            .channel_volumes
            .get(channel)
            .copied()
            .unwrap_or(0.0))
    }

    pub fn set_channel_volume(
        &mut self,
        voice: VoiceId,
        channel: usize,
        volume: f32,
    ) -> AppResult<()> {
        let record = self.voice_mut(voice)?;
        if channel < record.channel_volumes.len() {
            record.channel_volumes[channel] = volume;
        }
        Ok(())
    }

    pub fn exit_loop(&mut self, voice: VoiceId) -> AppResult<()> {
        let record = self.voice_mut(voice)?;
        match &mut record.kind {
            VoiceKind::Source { queue, .. } => {
                if let Some(buffer) = queue.front_mut() {
                    // `loop_count == 0` means "loop forever", so it cannot
                    // be used to disable looping; use an explicit flag.
                    buffer.loop_disabled = true;
                    buffer.loop_count = 0;
                    buffer.played_loops = 0;
                }
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "exit_loop requires a source voice",
            )),
        }
    }

    pub fn played_frames(&self, voice: VoiceId) -> AppResult<u64> {
        match &self.voice(voice)?.kind {
            VoiceKind::Source { played_frames, .. } => Ok(*played_frames),
            _ => Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "played_frames requires a source voice",
            )),
        }
    }

    pub fn frequency_ratio(&self, voice: VoiceId) -> AppResult<f32> {
        Ok(self.voice(voice)?.frequency_ratio)
    }

    pub fn set_frequency_ratio(&mut self, voice: VoiceId, ratio: f32) -> AppResult<()> {
        self.voice_mut(voice)?.frequency_ratio = ratio.clamp(0.5, 2.0);
        Ok(())
    }

    pub fn set_reverb_mix(&mut self, voice: VoiceId, wet: f32) -> AppResult<()> {
        match &mut self.voice_mut(voice)?.kind {
            VoiceKind::Submix { reverb_mix, .. } => {
                *reverb_mix = wet;
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "reverb is only supported on submix voices",
            )),
        }
    }

    /// Set the effects chain for a voice.
    ///
    /// Effects are applied during rendering after volume/matrix processing.
    /// Only submix and mastering voices typically have effects chains.
    pub fn set_effects_chain(&mut self, voice: VoiceId, chain: VoiceEffectsChain) -> AppResult<()> {
        self.voice_mut(voice)?.effects_chain = chain;
        Ok(())
    }

    /// Get a reference to the effects chain for a voice.
    pub fn get_effects_chain(&self, voice: VoiceId) -> AppResult<&VoiceEffectsChain> {
        Ok(&self.voice(voice)?.effects_chain)
    }

    pub fn render_xaudio2(&mut self, mastering: VoiceId, frames: usize) -> AppResult<RenderOutput> {
        Self::check_render_frames(frames)?;
        if !matches!(self.voice(mastering)?.kind, VoiceKind::Mastering { .. }) {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "render_xaudio2 requires a mastering voice",
            ));
        }
        let mut voice_callbacks = Vec::new();
        let mut underflow_frames = 0;
        let samples = self.render_voice_mix(
            mastering,
            frames,
            &mut voice_callbacks,
            &mut underflow_frames,
        )?;
        let device_id = match self.voice(mastering)?.kind {
            VoiceKind::Mastering { device_id } => device_id,
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    "render_xaudio2 requires a mastering voice",
                ));
            }
        };
        let latency_ms = measure_latency_ms(self.voice(mastering)?.format.sample_rate, frames);
        self.push_latency_record(LatencyRecord {
            subsystem: "xaudio2".to_string(),
            device_id,
            measured_ms: latency_ms,
        });
        Ok(RenderOutput {
            crc32: crc32_samples(&samples),
            event_log: Vec::new(),
            latency_ms,
            overflow_frames: 0,
            samples,
            underflow_frames,
            voice_callbacks,
        })
    }

    pub fn export_render_output_wav(
        &self,
        output: &RenderOutput,
        format: &WaveFormat,
        path: &Path,
    ) -> AppResult<()> {
        let wav = render_output_wav(output, format);
        fs::write(path, wav).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to write rendered audio {}", path.display()),
                &error,
            )
        })
    }

    pub fn play_render_output(&self, output: &RenderOutput, format: &WaveFormat) -> AppResult<()> {
        let temp_path = std::env::temp_dir().join(format!(
            "casa1-audio-{}-{}.wav",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0)
        ));
        self.export_render_output_wav(output, format, &temp_path)?;
        let status = HostCommand::new("afplay")
            .arg(&temp_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    "failed to launch afplay for rendered audio",
                    &error,
                )
            })?;
        if let Err(e) = fs::remove_file(&temp_path) {
            eprintln!(
                "[audio] failed to remove temp WAV file '{}': {e}",
                temp_path.display()
            );
        }
        if !status.success() {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("afplay failed while playing rendered audio: {status}"),
            ));
        }
        Ok(())
    }

    pub fn negotiate_format(&self, device: DeviceId, format: WaveFormat) -> AppResult<WaveFormat> {
        self.device(device)?;
        self.validate_format(&format)?;
        Ok(format)
    }

    pub fn create_audio_client(
        &mut self,
        device: DeviceId,
        format: WaveFormat,
        buffer_frames: usize,
        event_driven: bool,
    ) -> AppResult<AudioClientId> {
        self.device(device)?;
        self.validate_format(&format)?;
        let id = self.alloc_id();
        self.audio_clients.insert(
            id,
            AudioClientRecord {
                buffer_frames,
                device_id: device,
                event_driven,
                format,
                overflow_frames: 0,
                played_frames: 0,
                queue: VecDeque::new(),
                started: false,
                underflow_frames: 0,
            },
        );
        Ok(id)
    }

    pub fn get_buffer_size(&self, client: AudioClientId) -> AppResult<usize> {
        Ok(self.audio_client(client)?.buffer_frames)
    }

    pub fn get_service_render_client(&self, client: AudioClientId) -> AppResult<AudioClientId> {
        self.audio_client(client)?;
        Ok(client)
    }

    pub fn start_audio_client(&mut self, client: AudioClientId) -> AppResult<()> {
        self.audio_client_mut(client)?.started = true;
        Ok(())
    }

    pub fn stop_audio_client(&mut self, client: AudioClientId) -> AppResult<()> {
        self.audio_client_mut(client)?.started = false;
        Ok(())
    }

    pub fn write_render_frames(&mut self, client: AudioClientId, samples: &[f32]) -> AppResult<()> {
        let record = self.audio_client_mut(client)?;
        let channels = record.format.channels as usize;
        if !samples.len().is_multiple_of(channels) {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "render frames must align to the client channel count",
            ));
        }
        record.queue.extend(samples.iter().copied());
        let max_samples = record.buffer_frames * channels * 2;
        if record.queue.len() > max_samples {
            let overflow_samples = record.queue.len() - max_samples;
            for _ in 0..overflow_samples {
                record.queue.pop_front();
            }
            record.overflow_frames += (overflow_samples / channels) as u32;
        }
        Ok(())
    }

    pub fn drain_audio_client(
        &mut self,
        client: AudioClientId,
        frames: usize,
    ) -> AppResult<RenderOutput> {
        Self::check_render_frames(frames)?;
        let record = self.audio_client_mut(client)?;
        let channels = record.format.channels as usize;
        let mut samples = Vec::with_capacity(frames * channels);
        let mut event_log = Vec::new();
        for _ in 0..frames {
            if record.queue.len() < channels {
                samples.extend(std::iter::repeat_n(0.0, channels));
                record.underflow_frames += 1;
            } else {
                for _ in 0..channels {
                    samples.push(record.queue.pop_front().expect("client sample"));
                }
                record.played_frames += 1;
                if record.event_driven {
                    event_log.push(format!("render_ready@{}", record.played_frames));
                }
            }
        }
        let latency_ms = measure_latency_ms(record.format.sample_rate, record.buffer_frames);
        let device_id = record.device_id;
        let overflow_frames = record.overflow_frames;
        let underflow_frames = record.underflow_frames;
        self.push_latency_record(LatencyRecord {
            subsystem: "wasapi".to_string(),
            device_id,
            measured_ms: latency_ms,
        });
        Ok(RenderOutput {
            crc32: crc32_samples(&samples),
            event_log,
            latency_ms,
            overflow_frames,
            samples,
            underflow_frames,
            voice_callbacks: Vec::new(),
        })
    }

    /// Create a DirectSound8 object (maps to `DirectSoundCreate`).
    pub fn create_direct_sound8(&mut self, device: DeviceId) -> AppResult<DirectSoundId> {
        self.device(device)?;
        let id = self.alloc_id();
        self.direct_sound.insert(
            id,
            DirectSoundRecord {
                device_id: device,
                primary_format: None,
                cooperative_level: 0,
            },
        );
        Ok(id)
    }

    /// Set the cooperative level for a DirectSound object.
    pub fn set_direct_sound_cooperative_level(
        &mut self,
        ds_id: DirectSoundId,
        level: u32,
    ) -> AppResult<()> {
        let ds = self.direct_sound.get_mut(&ds_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, "unknown DirectSound object")
        })?;
        ds.cooperative_level = level;
        Ok(())
    }

    /// Get the cooperative level for a DirectSound object.
    pub fn get_direct_sound_cooperative_level(&self, ds_id: DirectSoundId) -> AppResult<u32> {
        let ds = self.direct_sound.get(&ds_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, "unknown DirectSound object")
        })?;
        Ok(ds.cooperative_level)
    }

    /// Create a DirectSound buffer with full capabilities
    /// (maps to `IDirectSound::CreateSoundBuffer`).
    ///
    /// `caps` is a combination of `DSBCAPS_*` flags.
    /// `buffer_size_bytes` is the requested buffer size in bytes (0 = default).
    pub fn create_direct_sound_buffer(
        &mut self,
        direct_sound: DirectSoundId,
        format: WaveFormat,
        caps: u32,
        buffer_size_bytes: usize,
    ) -> AppResult<DirectSoundBufferId> {
        let is_primary = (caps & DSBCAPS_PRIMARYBUFFER) != 0;
        if !is_primary {
            self.validate_format(&format)?;
        }
        let device_id = self
            .direct_sound
            .get(&direct_sound)
            .ok_or_else(|| {
                AppError::new(ReasonCode::RcAudioUnsupported, "unknown DirectSound object")
            })?
            .device_id;
        let id = self.alloc_id();

        // Clamp guest-supplied sizes so a single hostile call cannot trigger
        // a multi-GB allocation.
        let effective_size = if buffer_size_bytes > 0 {
            buffer_size_bytes.min(MAX_DS_BUFFER_BYTES)
        } else {
            DSBUFFER_DEFAULT_SIZE
        };
        // Convert bytes to frames then to f32 samples (f32 = 4 bytes).
        // Primary buffers skip format validation, so defend against a
        // zero-channel format here.
        let channels = (format.channels as usize).max(1);
        let frame_count = effective_size / (channels * 4);
        let sample_count = frame_count * channels;

        self.direct_sound_buffers.insert(
            id,
            DirectSoundBufferRecord {
                cursor: 0,
                write_cursor: 0,
                device_id,
                direct_sound_id: direct_sound,
                format: format.clone(),
                playing: false,
                looping: false,
                caps,
                volume_db: 0, // Full volume
                pan_db: 0,    // Center
                frequency: format.sample_rate,
                buffer_size_bytes: effective_size,
                samples: vec![0.0; sample_count],
                locked_regions: Vec::new(),
                notifications: Vec::new(),
                fired_notifications: Vec::new(),
                lost: false,
                priority: 0,
            },
        );
        Ok(id)
    }

    /// Create a DirectSound buffer (legacy API, uses default caps).
    pub fn create_direct_sound_buffer_simple(
        &mut self,
        direct_sound: DirectSoundId,
        format: WaveFormat,
    ) -> AppResult<DirectSoundBufferId> {
        self.create_direct_sound_buffer(
            direct_sound,
            format,
            DSBCAPS_STATIC | DSBCAPS_CTRLVOLUME | DSBCAPS_CTRLPAN | DSBCAPS_CTRLFREQUENCY,
            0,
        )
    }

    /// Write audio data to a DirectSound buffer (replaces entire buffer content).
    pub fn write_direct_sound_buffer(
        &mut self,
        buffer: DirectSoundBufferId,
        samples: &[f32],
    ) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        if record.lost {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound buffer is lost",
            ));
        }
        let channels = record.format.channels as usize;
        if !samples.len().is_multiple_of(channels) {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound writes must align to channel count",
            ));
        }
        record.samples = samples.to_vec();
        record.cursor = 0;
        record.buffer_size_bytes = samples.len() * 4; // f32 = 4 bytes
        Ok(())
    }

    /// Write audio data to a specific offset within a DirectSound buffer.
    pub fn write_direct_sound_buffer_at(
        &mut self,
        buffer: DirectSoundBufferId,
        offset_samples: usize,
        samples: &[f32],
    ) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        if record.lost {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound buffer is lost",
            ));
        }
        // Reject writes that overflow the buffer (or the address space)
        // instead of panicking or growing the buffer without bound.
        let end = offset_samples.checked_add(samples.len()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound write offset overflow",
            )
        })?;
        if end > record.samples.len() {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound write exceeds buffer capacity",
            ));
        }
        record.samples[offset_samples..end].copy_from_slice(samples);
        Ok(())
    }

    /// Lock a region of a DirectSound buffer for writing
    /// (maps to `IDirectSoundBuffer::Lock`).
    ///
    /// Returns `(offset1, length1, offset2, length2)` describing the locked
    /// region(s). If the lock wraps around the end of the buffer, two regions
    /// are returned.
    pub fn lock_direct_sound_buffer(
        &mut self,
        buffer: DirectSoundBufferId,
        offset_bytes: usize,
        length_bytes: usize,
        _flags: u32,
    ) -> AppResult<(usize, usize, usize, usize)> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        if record.lost {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound buffer is lost",
            ));
        }
        let _channels = record.format.channels as usize;
        let buffer_bytes = record.samples.len() * 4;
        if buffer_bytes == 0 {
            return Ok((0, 0, 0, 0));
        }

        // DirectSound Lock wraps offsets beyond the buffer end (modulo),
        // so no arithmetic below can underflow for guest-controlled input.
        let offset_bytes = offset_bytes % buffer_bytes;

        // Determine lock region
        let (offset1, length1, offset2, length2) =
            if offset_bytes.saturating_add(length_bytes) <= buffer_bytes {
                // Single region (no wrap)
                (offset_bytes, length_bytes, 0, 0)
            } else {
                // Wrap-around: two regions
                let first_len = buffer_bytes - offset_bytes;
                let second_len = length_bytes.saturating_sub(first_len);
                (offset_bytes, first_len, 0, second_len)
            };

        // Store the locked region
        record.locked_regions.push(LockedRegion {
            offset: offset1 / 4,
            length1,
            offset2: offset2 / 4,
            length2,
        });

        Ok((offset1, length1, offset2, length2))
    }

    /// Unlock a previously locked region of a DirectSound buffer
    /// (maps to `IDirectSoundBuffer::Unlock`).
    pub fn unlock_direct_sound_buffer(&mut self, buffer: DirectSoundBufferId) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        record.locked_regions.clear();
        Ok(())
    }

    /// Start playback of a DirectSound buffer
    /// (maps to `IDirectSoundBuffer::Play`).
    ///
    /// `flags` can include `DSBPLAY_LOOPING` (0x00000001).
    pub fn play_direct_sound_buffer_ex(
        &mut self,
        buffer: DirectSoundBufferId,
        flags: u32,
    ) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        if record.lost {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound buffer is lost",
            ));
        }
        record.playing = true;
        record.looping = (flags & 0x00000001) != 0; // DSBPLAY_LOOPING
        // Re-arm DSBPN_OFFSETSTOP (u32::MAX) so it fires again on the next
        // stop; ordinary offsets are re-armed on wrap-around.
        record.fired_notifications.retain(|&offset| offset != u32::MAX);
        Ok(())
    }

    /// Start playback of a DirectSound buffer (non-looping).
    pub fn play_direct_sound_buffer(&mut self, buffer: DirectSoundBufferId) -> AppResult<()> {
        self.play_direct_sound_buffer_ex(buffer, 0)
    }

    /// Stop playback of a DirectSound buffer
    /// (maps to `IDirectSoundBuffer::Stop`).
    pub fn stop_direct_sound_buffer(&mut self, buffer: DirectSoundBufferId) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        record.playing = false;
        record.looping = false;
        Ok(())
    }

    /// Set the volume of a DirectSound buffer in hundredths of decibels
    /// (maps to `IDirectSoundBuffer::SetVolume`).
    ///
    /// Range: -10000 (silence) to 0 (full volume).
    pub fn set_direct_sound_buffer_volume(
        &mut self,
        buffer: DirectSoundBufferId,
        volume_db: i32,
    ) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        if record.lost {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound buffer is lost",
            ));
        }
        if record.caps & DSBCAPS_CTRLVOLUME == 0 {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "buffer does not support volume control",
            ));
        }
        record.volume_db = volume_db.clamp(-10000, 0);
        Ok(())
    }

    /// Get the volume of a DirectSound buffer in hundredths of decibels
    /// (maps to `IDirectSoundBuffer::GetVolume`).
    pub fn get_direct_sound_buffer_volume(&self, buffer: DirectSoundBufferId) -> AppResult<i32> {
        let record = self.direct_sound_buffer(buffer)?;
        Ok(record.volume_db)
    }

    /// Set the pan of a DirectSound buffer in hundredths of decibels
    /// (maps to `IDirectSoundBuffer::SetPan`).
    ///
    /// Range: -10000 (full left) to 10000 (full right). 0 = center.
    pub fn set_direct_sound_buffer_pan(
        &mut self,
        buffer: DirectSoundBufferId,
        pan_db: i32,
    ) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        if record.lost {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound buffer is lost",
            ));
        }
        record.pan_db = pan_db.clamp(-10000, 10000);
        Ok(())
    }

    /// Get the pan of a DirectSound buffer in hundredths of decibels
    /// (maps to `IDirectSoundBuffer::GetPan`).
    pub fn get_direct_sound_buffer_pan(&self, buffer: DirectSoundBufferId) -> AppResult<i32> {
        let record = self.direct_sound_buffer(buffer)?;
        Ok(record.pan_db)
    }

    /// Set the frequency of a DirectSound buffer in Hz
    /// (maps to `IDirectSoundBuffer::SetFrequency`).
    ///
    /// 0 = reset to format default.
    pub fn set_direct_sound_buffer_frequency(
        &mut self,
        buffer: DirectSoundBufferId,
        frequency: u32,
    ) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        if record.lost {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound buffer is lost",
            ));
        }
        let effective = if frequency == 0 {
            record.format.sample_rate
        } else {
            frequency.clamp(100, 200_000)
        };
        record.frequency = effective;
        Ok(())
    }

    /// Get the frequency of a DirectSound buffer in Hz
    /// (maps to `IDirectSoundBuffer::GetFrequency`).
    pub fn get_direct_sound_buffer_frequency(&self, buffer: DirectSoundBufferId) -> AppResult<u32> {
        let record = self.direct_sound_buffer(buffer)?;
        Ok(record.frequency)
    }

    /// Get the current playback and write cursor positions in bytes
    /// (maps to `IDirectSoundBuffer::GetCurrentPosition`).
    ///
    /// Returns `(play_cursor_bytes, write_cursor_bytes)`.
    pub fn get_direct_sound_buffer_position(
        &self,
        buffer: DirectSoundBufferId,
    ) -> AppResult<(u32, u32)> {
        let record = self.direct_sound_buffer(buffer)?;
        let channels = record.format.channels as usize;
        let play_bytes = Self::frame_to_byte(record.cursor, channels);
        let write_bytes = Self::frame_to_byte(record.write_cursor, channels);
        Ok((play_bytes as u32, write_bytes as u32))
    }

    /// Set the current playback cursor position in bytes
    /// (maps to `IDirectSoundBuffer::SetCurrentPosition`).
    pub fn set_direct_sound_buffer_position(
        &mut self,
        buffer: DirectSoundBufferId,
        position_bytes: u32,
    ) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        let channels = record.format.channels as usize;
        let frame = Self::byte_to_frame(position_bytes as usize, channels);
        record.cursor = frame.min(record.samples.len() / channels.max(1));
        record.write_cursor = record.cursor;
        // Reset fired notifications when position changes
        record.fired_notifications.clear();
        Ok(())
    }

    /// Restore a lost DirectSound buffer
    /// (maps to `IDirectSoundBuffer::Restore`).
    pub fn restore_direct_sound_buffer(&mut self, buffer: DirectSoundBufferId) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        record.lost = false;
        record.cursor = 0;
        record.write_cursor = 0;
        record.playing = false;
        record.samples.fill(0.0);
        Ok(())
    }

    /// Check if a DirectSound buffer is lost.
    pub fn is_direct_sound_buffer_lost(&self, buffer: DirectSoundBufferId) -> AppResult<bool> {
        Ok(self.direct_sound_buffer(buffer)?.lost)
    }

    /// Get the buffer capability flags.
    pub fn get_direct_sound_buffer_caps(&self, buffer: DirectSoundBufferId) -> AppResult<u32> {
        Ok(self.direct_sound_buffer(buffer)?.caps)
    }

    /// Get the buffer format.
    pub fn get_direct_sound_buffer_format(
        &self,
        buffer: DirectSoundBufferId,
    ) -> AppResult<WaveFormat> {
        Ok(self.direct_sound_buffer(buffer)?.format.clone())
    }

    /// Set notification positions for a DirectSound buffer
    /// (maps to `IDirectSoundNotify::SetNotificationPositions`).
    pub fn set_direct_sound_buffer_notifications(
        &mut self,
        buffer: DirectSoundBufferId,
        notifies: Vec<DsPositionNotify>,
    ) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        if record.caps & DSBCAPS_CTRLPOSITIONNOTIFY == 0 {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "buffer does not support position notification",
            ));
        }
        record.notifications = notifies;
        record.fired_notifications.clear();
        Ok(())
    }

    /// Get the list of notification positions for a DirectSound buffer.
    pub fn get_direct_sound_buffer_notifications(
        &self,
        buffer: DirectSoundBufferId,
    ) -> AppResult<&[DsPositionNotify]> {
        let record = self.direct_sound_buffer(buffer)?;
        Ok(&record.notifications)
    }

    /// Check and return notification events that should be fired based on
    /// the current playback position. Returns a list of event handles.
    pub fn check_buffer_notifications(
        &mut self,
        buffer: DirectSoundBufferId,
    ) -> AppResult<Vec<u64>> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        let channels = record.format.channels as usize;
        let current_byte = Self::frame_to_byte(record.cursor, channels) as u32;
        let mut events = Vec::new();

        for notify in &record.notifications {
            if notify.offset == u32::MAX {
                // DSBPN_OFFSETSTOP — fire when playback stops
                if !record.playing && !record.fired_notifications.contains(&notify.offset) {
                    events.push(notify.event_handle);
                    record.fired_notifications.push(notify.offset);
                }
                continue;
            }
            // Check if we've crossed this notification offset
            if current_byte >= notify.offset && !record.fired_notifications.contains(&notify.offset)
            {
                events.push(notify.event_handle);
                record.fired_notifications.push(notify.offset);
            }
        }

        // Reset fired notifications when we wrap around; DSBPN_OFFSETSTOP
        // (u32::MAX) is re-armed separately when playback (re)starts.
        let buffer_bytes = record.buffer_size_bytes as u32;
        if current_byte < buffer_bytes / 2 {
            record.fired_notifications.clear();
        }

        Ok(events)
    }

    /// Get the primary buffer format for a DirectSound object.
    pub fn get_direct_sound_primary_format(
        &self,
        ds_id: DirectSoundId,
    ) -> AppResult<Option<WaveFormat>> {
        let ds = self.direct_sound.get(&ds_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, "unknown DirectSound object")
        })?;
        Ok(ds.primary_format.clone())
    }

    /// Set the primary buffer format for a DirectSound object
    /// (maps to `IDirectSoundBuffer::SetFormat` on the primary buffer).
    pub fn set_direct_sound_primary_format(
        &mut self,
        ds_id: DirectSoundId,
        format: WaveFormat,
    ) -> AppResult<()> {
        self.validate_format(&format)?;
        let ds = self.direct_sound.get_mut(&ds_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, "unknown DirectSound object")
        })?;
        ds.primary_format = Some(format);
        Ok(())
    }

    /// Mark all DirectSound buffers as lost (e.g., after device change).
    pub fn lose_all_direct_sound_buffers(&mut self) {
        for buffer in self.direct_sound_buffers.values_mut() {
            buffer.lost = true;
            buffer.playing = false;
        }
    }

    /// Get the DirectSound buffer's internal sample data (for reading).
    pub fn get_direct_sound_buffer_samples(
        &self,
        buffer: DirectSoundBufferId,
    ) -> AppResult<&[f32]> {
        let record = self.direct_sound_buffer(buffer)?;
        Ok(&record.samples)
    }

    fn direct_sound_buffer(
        &self,
        buffer: DirectSoundBufferId,
    ) -> AppResult<&DirectSoundBufferRecord> {
        self.direct_sound_buffers.get(&buffer).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown DirectSound buffer {buffer}"),
            )
        })
    }

    // ── DirectSound3D positional audio methods ──────────────────────────

    /// Set the 3D buffer state for a DirectSound buffer.
    ///
    /// Called when the guest calls `IDirectSound3DBuffer8::SetAllParameters`,
    /// `SetPosition`, `SetVelocity`, `SetConeAngles`, `SetMinDistance`,
    /// `SetMaxDistance`, or `SetMode`.
    pub fn set_ds3d_buffer_state(
        &mut self,
        buffer: DirectSoundBufferId,
        state: Ds3dBufferState,
    ) -> AppResult<()> {
        // Validate the buffer exists.
        self.direct_sound_buffer_mut(buffer)?;
        self.ds3d_buffer_states.insert(buffer, state);
        Ok(())
    }

    /// Return the current 3D buffer state for a DirectSound buffer.
    ///
    /// If no state has been set yet, returns the default state.
    pub fn get_ds3d_buffer_state(&self, buffer: DirectSoundBufferId) -> AppResult<Ds3dBufferState> {
        // Validate the buffer exists.
        if !self.direct_sound_buffers.contains_key(&buffer) {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown DirectSound buffer {buffer}"),
            ));
        }
        Ok(self
            .ds3d_buffer_states
            .get(&buffer)
            .cloned()
            .unwrap_or_default())
    }

    /// Set the 3D listener state for a DirectSound object.
    ///
    /// Called when the guest calls `IDirectSound3DListener8::SetAllParameters`,
    /// `SetPosition`, `SetVelocity`, `SetOrientation`, `SetDistanceFactor`,
    /// `SetDopplerFactor`, or `SetRolloffFactor`.
    pub fn set_ds3d_listener_state(
        &mut self,
        direct_sound: DirectSoundId,
        state: Ds3dListenerState,
    ) -> AppResult<()> {
        // Validate the DirectSound object exists.
        if !self.direct_sound.contains_key(&direct_sound) {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown DirectSound object {direct_sound}"),
            ));
        }
        self.ds3d_listener_state.insert(direct_sound, state);
        Ok(())
    }

    /// Return the current 3D listener state for a DirectSound object.
    ///
    /// If no state has been set yet, returns the default state.
    pub fn get_ds3d_listener_state(
        &self,
        direct_sound: DirectSoundId,
    ) -> AppResult<Ds3dListenerState> {
        if !self.direct_sound.contains_key(&direct_sound) {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown DirectSound object {direct_sound}"),
            ));
        }
        Ok(self
            .ds3d_listener_state
            .get(&direct_sound)
            .cloned()
            .unwrap_or_default())
    }

    // ── Mixing ──────────────────────────────────────────────────────────

    pub fn mix_direct_sound_buffer(
        &mut self,
        buffer: DirectSoundBufferId,
        frames: usize,
    ) -> AppResult<RenderOutput> {
        Self::check_render_frames(frames)?;
        // ── Gather immutable state before mutating ──────────────────────
        let (channels, sample_rate, device_id, direct_sound_id, volume_db, pan_db, frequency, looping, is_lost) = {
            let record = self.direct_sound_buffers.get(&buffer).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!("unknown DirectSound buffer {buffer}"),
                )
            })?;
            (
                record.format.channels as usize,
                record.format.sample_rate,
                record.device_id,
                record.direct_sound_id,
                record.volume_db,
                record.pan_db,
                record.frequency,
                record.looping,
                record.lost,
            )
        };

        if is_lost {
            return Ok(RenderOutput {
                crc32: 0,
                event_log: Vec::new(),
                latency_ms: 0,
                overflow_frames: 0,
                samples: vec![0.0; frames * channels],
                underflow_frames: frames as u32,
                voice_callbacks: Vec::new(),
            });
        }

        // Retrieve 3D state from the owning DirectSound object (each buffer
        // records its owner at creation, so the listener of the wrong object
        // is never applied).
        let ds3d_state = self
            .ds3d_buffer_states
            .get(&buffer)
            .cloned()
            .unwrap_or_default();
        let listener = self
            .ds3d_listener_state
            .get(&direct_sound_id)
            .cloned()
            .unwrap_or_default();

        // Pre-compute volume/pan gains
        let volume_gain = Self::ds_volume_to_gain(volume_db);
        let (pan_left, pan_right) = Self::ds_pan_to_gains(pan_db);

        // Compute frequency ratio for pitch shifting
        let freq_ratio = frequency as f64 / sample_rate as f64;

        // ── Generate raw samples (now we can mutably borrow) ────────────
        let record = self.direct_sound_buffer_mut(buffer)?;
        let total_frames = record.samples.len().checked_div(channels).unwrap_or(0);
        let mut samples = Vec::with_capacity(frames * channels);
        let mut fractional_cursor = record.cursor as f64;

        for _ in 0..frames {
            let cursor_frame = fractional_cursor as usize;
            if record.playing && cursor_frame < total_frames {
                for channel in 0..channels {
                    let index = cursor_frame * channels + channel;
                    samples.push(record.samples[index]);
                }
                // Advance cursor with frequency ratio
                fractional_cursor += freq_ratio;
                let new_frame = fractional_cursor as usize;

                // Handle looping or stopping at end
                if new_frame >= total_frames {
                    if looping {
                        fractional_cursor %= total_frames as f64;
                    } else {
                        record.playing = false;
                        record.cursor = total_frames;
                        // Fill remaining frames with silence
                        break;
                    }
                }
            } else {
                // Silence for non-playing or past-end
                samples.extend(std::iter::repeat_n(0.0, channels));
            }
        }

        // Update cursor
        record.cursor = fractional_cursor as usize;
        record.write_cursor = record.cursor;

        // Fill remaining silence if we stopped early
        samples.extend(std::iter::repeat_n(0.0, frames * channels - samples.len()));

        let latency_ms = measure_latency_ms(sample_rate, frames);

        // ── Apply volume and pan ────────────────────────────────────────
        if volume_gain != 1.0 || pan_db != 0 {
            for frame in 0..frames {
                let base = frame * channels;
                // Apply volume to all channels
                for ch in 0..channels {
                    samples[base + ch] *= volume_gain;
                }
                // Apply pan to stereo channels
                if channels >= 2 {
                    samples[base] *= pan_left;
                    samples[base + 1] *= pan_right;
                }
            }
        }

        // ── Apply 3D positional audio effects ───────────────────────────
        if ds3d_state.mode != Ds3dMode::Disable && record.playing {
            // Distance attenuation
            let mut volume_multiplier = compute_distance_attenuation(&ds3d_state, &listener);

            // Cone attenuation
            volume_multiplier *= compute_cone_attenuation(&ds3d_state, &listener);

            // Doppler shift (frequency ratio) – we store it, the guest
            // reads it via IDirectSound3DBuffer8::GetFrequency.
            let _frequency_ratio = compute_doppler_shift(&ds3d_state, &listener);

            // Channel panning: HRTF gains (interaural level + time
            // difference) computed from the buffer position relative to
            // the listener.
            if channels >= 2 {
                let (left_gain, right_gain) = compute_hrtf_gains(&ds3d_state, &listener);
                for frame in 0..frames {
                    let base = frame * channels;
                    // Apply distance & cone volume to all channels
                    for ch in 0..channels {
                        samples[base + ch] *= volume_multiplier;
                    }
                    samples[base] *= left_gain;
                    if channels > 1 {
                        samples[base + 1] *= right_gain;
                    }
                }
            } else {
                // Mono: just apply volume
                for sample in samples.iter_mut() {
                    *sample *= volume_multiplier;
                }
            }
        }

        self.push_latency_record(LatencyRecord {
            subsystem: "directsound".to_string(),
            device_id,
            measured_ms: latency_ms,
        });
        Ok(RenderOutput {
            crc32: crc32_samples(&samples),
            event_log: Vec::new(),
            latency_ms,
            overflow_frames: 0,
            samples,
            underflow_frames: 0,
            voice_callbacks: Vec::new(),
        })
    }

    fn render_voice_mix(
        &mut self,
        voice: VoiceId,
        frames: usize,
        callbacks: &mut Vec<VoiceCallbackEvent>,
        underflow_frames: &mut u32,
    ) -> AppResult<Vec<f32>> {
        // Snapshot only cheap scalars up front; the full `kind` (which owns
        // the sample queue) is never cloned, and the effects chain is
        // applied through a short-lived borrow after recursion.
        let (channels, sample_rate, volume, started, kind_tag, reverb_mix) = {
            let record = self.voice(voice)?;
            (
                record.format.channels as usize,
                record.format.sample_rate,
                record.volume,
                record.started,
                match record.kind {
                    VoiceKind::Mastering { .. } => VoiceKindTag::Mastering,
                    VoiceKind::Submix { .. } => VoiceKindTag::Submix,
                    VoiceKind::Source { .. } => VoiceKindTag::Source,
                },
                match record.kind {
                    VoiceKind::Submix { reverb_mix, .. } => reverb_mix,
                    _ => 0.0,
                },
            )
        };
        if !started {
            return Ok(vec![0.0; frames * channels]);
        }
        let mut mix = match kind_tag {
            VoiceKindTag::Mastering => {
                let child_ids = self.child_voice_ids(voice);
                let mut mix = vec![0.0; frames * channels];
                for child in child_ids {
                    let child_mix =
                        self.render_voice_mix(child, frames, callbacks, underflow_frames)?;
                    let projected = self.project_to_parent(child, &child_mix, channels)?;
                    mix_in_place(&mut mix, &projected);
                }
                mix
            }
            VoiceKindTag::Submix => {
                let child_ids = self.child_voice_ids(voice);
                let mut mix = vec![0.0; frames * channels];
                for child in child_ids {
                    let child_mix =
                        self.render_voice_mix(child, frames, callbacks, underflow_frames)?;
                    let projected = self.project_to_parent(child, &child_mix, channels)?;
                    mix_in_place(&mut mix, &projected);
                }
                if reverb_mix > 0.0 {
                    apply_reverb(&mut mix, channels, reverb_mix);
                }
                mix
            }
            VoiceKindTag::Source => {
                self.consume_source_frames(voice, frames, callbacks, underflow_frames)?
            }
        };
        apply_levels(&mut mix, channels, volume, &self.voice(voice)?.channel_volumes);
        // Apply effects chain (if any effects are registered), borrowing the
        // chain briefly — no recursion happens at this point.
        if !self.voice(voice)?.effects_chain.effect_clsids.is_empty() {
            let record = self.voice(voice)?;
            record
                .effects_chain
                .apply_chain(&mut mix, channels, sample_rate);
        }
        Ok(mix)
    }

    fn consume_source_frames(
        &mut self,
        voice: VoiceId,
        frames: usize,
        callbacks: &mut Vec<VoiceCallbackEvent>,
        underflow_frames: &mut u32,
    ) -> AppResult<Vec<f32>> {
        let channels = self.voice(voice)?.format.channels as usize;
        let mut mix = vec![0.0; frames * channels];
        let voice_record = self.voice_mut(voice)?;
        match &mut voice_record.kind {
            VoiceKind::Source {
                queue,
                played_frames,
                ..
            } => {
                for frame_index in 0..frames {
                    while matches!(queue.front(), Some(buffer) if buffer.cursor >= buffer.frames) {
                        // Buffer completed — fire OnBufferEnd only if no looping
                        // SAFETY: matches! guard above guarantees queue.front() is Some.
                        let finished = queue
                            .front()
                            .expect("queue front verified by matches guard above");
                        if buffer_will_loop(finished) {
                            // Rewind to loop start
                            // SAFETY: matches! guard above guarantees queue.front_mut() is Some.
                            let buf = queue
                                .front_mut()
                                .expect("queue front_mut verified by matches guard above");
                            buf.cursor = buf.loop_begin.unwrap_or(0);
                            buf.played_loops += 1;
                            break;
                        } else {
                            callbacks.push(VoiceCallbackEvent {
                                voice,
                                event: "OnBufferEnd".to_string(),
                                tag: finished.tag.clone(),
                                sample_offset: *played_frames + frame_index as u64,
                            });
                            queue.pop_front();
                        }
                    }
                    let Some(buffer) = queue.front_mut() else {
                        *underflow_frames += 1;
                        continue;
                    };
                    // Guard against a degenerate rewind (e.g. a loop point at
                    // or past the end of an empty/looping buffer): skip the
                    // frame instead of slicing out of bounds.
                    if buffer.cursor >= buffer.frames {
                        *underflow_frames += 1;
                        continue;
                    }
                    let sample_offset = buffer.cursor * channels;
                    let frame_samples = &buffer.samples[sample_offset..sample_offset + channels];
                    let write_offset = frame_index * channels;
                    mix[write_offset..write_offset + channels].copy_from_slice(frame_samples);
                    buffer.cursor += 1;
                }
                // Post-loop: fire callbacks for any buffer that completed on the last frame
                while matches!(queue.front(), Some(buffer) if buffer.cursor >= buffer.frames) {
                    // SAFETY: matches! guard above guarantees queue.front() is Some.
                    let finished = queue
                        .front()
                        .expect("queue front verified by matches guard above");
                    if buffer_will_loop(finished) {
                        // SAFETY: matches! guard above guarantees queue.front_mut() is Some.
                        let buf = queue
                            .front_mut()
                            .expect("queue front_mut verified by matches guard above");
                        buf.cursor = buf.loop_begin.unwrap_or(0);
                        buf.played_loops += 1;
                        break;
                    } else {
                        callbacks.push(VoiceCallbackEvent {
                            voice,
                            event: "OnBufferEnd".to_string(),
                            tag: finished.tag.clone(),
                            sample_offset: *played_frames + frames as u64,
                        });
                        queue.pop_front();
                    }
                }
                *played_frames += frames as u64;
            }
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    "consume_source_frames requires a source voice",
                ));
            }
        }
        Ok(mix)
    }

    fn child_voice_ids(&self, parent: VoiceId) -> Vec<VoiceId> {
        // Children are cached on the parent at creation, so rendering does
        // not rescan all voices per parent.
        self.voice(parent)
            .map(|record| record.children.clone())
            .unwrap_or_default()
    }

    fn project_to_parent(
        &self,
        voice: VoiceId,
        samples: &[f32],
        parent_channels: usize,
    ) -> AppResult<Vec<f32>> {
        let voice_record = self.voice(voice)?;
        let source_channels = voice_record.format.channels as usize;
        let matrix = if voice_record.output_matrix.is_empty() {
            default_output_matrix(source_channels, parent_channels)
        } else {
            voice_record.output_matrix.clone()
        };
        let frames = samples.len() / source_channels;
        let mut projected = vec![0.0; frames * parent_channels];
        for frame in 0..frames {
            for source_channel in 0..source_channels {
                let sample = samples[frame * source_channels + source_channel];
                for dest_channel in 0..parent_channels {
                    let weight = matrix[source_channel * parent_channels + dest_channel];
                    projected[frame * parent_channels + dest_channel] += sample * weight;
                }
            }
        }
        Ok(projected)
    }

    fn validate_format(&self, format: &WaveFormat) -> AppResult<()> {
        // Support common sample rates: 22.05K, 24K, 44.1K, 48K, 96K, 192K
        let sample_rate_supported = matches!(
            format.sample_rate,
            22_050 | 24_000 | 44_100 | 48_000 | 96_000 | 192_000
        );
        // Support 1 (mono), 2 (stereo), 4 (quad), 6 (5.1), 8 (7.1)
        let channels_supported = matches!(format.channels, 1 | 2 | 4 | 6 | 8);
        if !sample_rate_supported || !channels_supported {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!(
                    "unsupported audio format: {} channels, {} Hz",
                    format.channels, format.sample_rate
                ),
            ));
        }
        match format.sample_format {
            SampleFormat::Pcm16 | SampleFormat::Float32 => Ok(()),
        }
    }

    fn device(&self, device: DeviceId) -> AppResult<&AudioDeviceRecord> {
        self.devices
            .get(&device)
            .filter(|device| device.plugged)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!("unknown audio device {device}"),
                )
            })
    }

    fn device_mut(&mut self, device: DeviceId) -> AppResult<&mut AudioDeviceRecord> {
        self.devices.get_mut(&device).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown audio device {device}"),
            )
        })
    }

    fn voice(&self, voice: VoiceId) -> AppResult<&VoiceRecord> {
        self.voices.get(&voice).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown voice {voice}"),
            )
        })
    }

    fn voice_mut(&mut self, voice: VoiceId) -> AppResult<&mut VoiceRecord> {
        self.voices.get_mut(&voice).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown voice {voice}"),
            )
        })
    }

    fn audio_client(&self, client: AudioClientId) -> AppResult<&AudioClientRecord> {
        self.audio_clients.get(&client).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown audio client {client}"),
            )
        })
    }

    fn audio_client_mut(&mut self, client: AudioClientId) -> AppResult<&mut AudioClientRecord> {
        self.audio_clients.get_mut(&client).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown audio client {client}"),
            )
        })
    }

    fn direct_sound_buffer_mut(
        &mut self,
        buffer: DirectSoundBufferId,
    ) -> AppResult<&mut DirectSoundBufferRecord> {
        self.direct_sound_buffers.get_mut(&buffer).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown DirectSound buffer {buffer}"),
            )
        })
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Append a notification, capping the log so long sessions do not grow
    /// memory without bound.
    fn push_notification(&mut self, message: String) {
        self.notifications.push(message);
        if self.notifications.len() > MAX_LOG_ENTRIES {
            self.notifications.drain(0..MAX_LOG_ENTRIES / 10);
        }
    }

    /// Append a latency record, capping the log.
    fn push_latency_record(&mut self, record: LatencyRecord) {
        self.latency_log.push(record);
        if self.latency_log.len() > MAX_LOG_ENTRIES {
            self.latency_log.drain(0..MAX_LOG_ENTRIES / 10);
        }
    }

    /// Reject render requests with guest-controlled frame counts large enough
    /// to trigger multi-GB allocations.
    fn check_render_frames(frames: usize) -> AppResult<()> {
        if frames > MAX_RENDER_FRAMES {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("render request too large: {frames} frames"),
            ));
        }
        Ok(())
    }

    // ── Capture (waveIn) support ─────────────────────────────────────────────

    /// Start audio capture from a wave input device.
    ///
    /// Activates the cpal input stream and prepares to route captured audio
    /// data into the guest's queued buffers.
    pub fn start_capture(&mut self, device_handle: u32, _format: &WaveFormatEx) {
        self.capture_active = true;
        self.capture_device_handle = device_handle;
        self.capture_buffer.clear();
    }

    /// Stop audio capture.
    ///
    /// Deactivates the cpal input stream and resets capture state.
    pub fn stop_capture(&mut self, device_handle: u32) {
        if self.capture_device_handle == device_handle {
            self.capture_active = false;
            self.capture_device_handle = 0;
            self.capture_buffer.clear();
        }
    }

    /// Called when captured audio data arrives from the real audio backend.
    ///
    /// Stores the f32 capture samples in the internal buffer. The PE runtime
    /// dispatch will later convert and write them into guest WAVEHDR buffers.
    pub fn on_capture_data(&mut self, samples: &[f32], _format: &WaveFormatEx) {
        if !self.capture_active {
            return;
        }
        // Convert f32 samples to PCM bytes based on the capture format
        let byte_count = samples.len() * (_format.w_bits_per_sample as usize / 8);
        self.capture_buffer.reserve(byte_count);
        for &sample in samples {
            let clamped = sample.clamp(-1.0, 1.0);
            match _format.w_bits_per_sample {
                8 => {
                    let val = ((clamped + 1.0) * 127.5) as u8;
                    self.capture_buffer.push(val);
                }
                16 => {
                    let val = if clamped <= -1.0 {
                        i16::MIN
                    } else {
                        (clamped * i16::MAX as f32) as i16
                    };
                    self.capture_buffer.extend_from_slice(&val.to_le_bytes());
                }
                32 => {
                    let val: f32 = clamped;
                    self.capture_buffer.extend_from_slice(&val.to_le_bytes());
                }
                _ => {
                    // Default to 16-bit
                    let val = if clamped <= -1.0 {
                        i16::MIN
                    } else {
                        (clamped * i16::MAX as f32) as i16
                    };
                    self.capture_buffer.extend_from_slice(&val.to_le_bytes());
                }
            }
        }
        // Bound the buffer so a guest that never drains capture data cannot
        // grow memory without limit (drop the oldest bytes when full).
        if self.capture_buffer.len() > MAX_CAPTURE_BUFFER_BYTES {
            let excess = self.capture_buffer.len() - MAX_CAPTURE_BUFFER_BYTES;
            self.capture_buffer.drain(0..excess);
        }
    }
}

/// Whether a queued buffer should rewind and loop instead of completing.
///
/// `loop_count == 0` means "loop forever"; `loop_disabled` is set by
/// `exit_loop` and takes precedence so an infinite loop can be stopped.
fn buffer_will_loop(buffer: &QueuedBuffer) -> bool {
    !buffer.loop_disabled
        && buffer.loop_begin.is_some()
        && buffer.loop_length.unwrap_or(0) > 0
        && (buffer.loop_count == 0 || buffer.played_loops < buffer.loop_count)
}

pub fn crc32_samples(samples: &[f32]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for sample in samples {
        for byte in sample.to_le_bytes() {
            crc ^= byte as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg() & 0xedb8_8320;
                crc = (crc >> 1) ^ mask;
            }
        }
    }
    !crc
}

fn render_output_wav(output: &RenderOutput, format: &WaveFormat) -> Vec<u8> {
    let channels = format.channels.max(1) as usize;
    let mut pcm = Vec::with_capacity(output.samples.len() * 2);
    for sample in &output.samples {
        let clamped = sample.clamp(-1.0, 1.0);
        let value = if clamped <= -1.0 {
            i16::MIN
        } else {
            (clamped * i16::MAX as f32) as i16
        };
        pcm.extend_from_slice(&value.to_le_bytes());
    }

    let sample_rate = format.sample_rate;
    let block_align = (channels * 2) as u16;
    let byte_rate = sample_rate * block_align as u32;
    let data_len = pcm.len() as u32;
    let mut wav = Vec::with_capacity(44 + pcm.len());
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + data_len).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16_u32.to_le_bytes());
    wav.extend_from_slice(&1_u16.to_le_bytes());
    wav.extend_from_slice(&(channels as u16).to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    wav.extend_from_slice(&block_align.to_le_bytes());
    wav.extend_from_slice(&16_u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    wav.extend_from_slice(&pcm);
    wav
}

fn convert_samples(samples: AudioSamples) -> Vec<f32> {
    match samples {
        AudioSamples::Pcm16(values) => values
            .into_iter()
            .map(|value| {
                if value == i16::MIN {
                    -1.0
                } else {
                    value as f32 / i16::MAX as f32
                }
            })
            .collect(),
        AudioSamples::Float32(values) => values,
    }
}

fn resample_interleaved(
    samples: &[f32],
    channels: usize,
    source_rate: u32,
    destination_rate: u32,
) -> Vec<f32> {
    if source_rate == destination_rate {
        return samples.to_vec();
    }
    let source_frames = samples.len() / channels;
    let destination_frames =
        ((source_frames as u64 * destination_rate as u64) / source_rate as u64) as usize;
    let mut resampled = vec![0.0; destination_frames * channels];
    for frame in 0..destination_frames {
        let source_frame = ((frame as u64 * source_rate as u64) / destination_rate as u64) as usize;
        let source_frame = source_frame.min(source_frames.saturating_sub(1));
        for channel in 0..channels {
            resampled[frame * channels + channel] = samples[source_frame * channels + channel];
        }
    }
    resampled
}

pub(crate) fn default_output_matrix(
    source_channels: usize,
    destination_channels: usize,
) -> Vec<f32> {
    if source_channels == 1 && destination_channels == 2 {
        return vec![1.0, 1.0];
    }
    let mut matrix = vec![0.0; source_channels * destination_channels];
    for channel in 0..source_channels.min(destination_channels) {
        matrix[channel * destination_channels + channel] = 1.0;
    }
    matrix
}

fn apply_levels(samples: &mut [f32], channels: usize, volume: f32, channel_volumes: &[f32]) {
    for frame in 0..samples.len() / channels {
        for channel in 0..channels {
            samples[frame * channels + channel] *= volume * channel_volumes[channel];
        }
    }
}

fn apply_reverb(samples: &mut [f32], channels: usize, wet: f32) {
    let mut previous = vec![0.0; channels];
    for frame in samples.chunks_exact_mut(channels) {
        for (channel, sample) in frame.iter_mut().enumerate() {
            *sample += previous[channel] * wet;
            previous[channel] = *sample;
        }
    }
}

fn mix_in_place(destination: &mut [f32], source: &[f32]) {
    for (dst, src) in destination.iter_mut().zip(source.iter()) {
        *dst += *src;
    }
}

// ── DirectSound3D positional audio helper functions ─────────────────────

/// Compute the distance-based volume attenuation using inverse-distance
/// clamped rolloff (DS3D default).
///
/// Returns a multiplier in `[0, 1]` that should be applied to all channels.
fn compute_distance_attenuation(state: &Ds3dBufferState, listener: &Ds3dListenerState) -> f32 {
    let dx = state.position[0] - listener.position[0];
    let dy = state.position[1] - listener.position[1];
    let dz = state.position[2] - listener.position[2];
    let distance = (dx * dx + dy * dy + dz * dz).sqrt();

    if distance < state.min_distance {
        return 1.0;
    }
    if distance > state.max_distance {
        return 0.0;
    }

    // Inverse-distance clamped rolloff
    // volume = min_distance / (min_distance + rolloff_factor * (distance - min_distance))
    let rolloff = listener.rolloff_factor;
    let denom = state.min_distance + rolloff * (distance - state.min_distance);
    if denom <= f32::EPSILON {
        return 1.0;
    }
    (state.min_distance / denom).clamp(0.0, 1.0)
}

/// Compute cone attenuation based on the angle between the listener and
/// the buffer's cone orientation.
///
/// The buffer's cone is defined by its inner and outer angles.  If the
/// listener lies within the inner cone, no attenuation is applied.
/// If outside the outer cone, the outside volume (in dB) is applied.
/// Between inner and outer, the attenuation is linearly interpolated.
///
/// Returns a multiplier in `[0, 1]`.
fn compute_cone_attenuation(state: &Ds3dBufferState, listener: &Ds3dListenerState) -> f32 {
    // Omnidirectional — no cone effect.
    if state.cone_inside_angle >= 360 {
        return 1.0;
    }

    // Vector from buffer to listener.
    let dx = listener.position[0] - state.position[0];
    let dy = listener.position[1] - state.position[1];
    let dz = listener.position[2] - state.position[2];
    let len = (dx * dx + dy * dy + dz * dz).sqrt();
    if len <= f32::EPSILON {
        // Listener is at the buffer position — inside the cone.
        return 1.0;
    }

    // DirectSound3D uses the buffer's negative-Z axis as the cone
    // direction (i.e., the sound projects in the -Z direction).
    // The buffer has no explicit cone direction field in the standard
    // DS3DBUFFER; instead the sound's direction is always -Z in the
    // buffer's local space.  For world-space we treat the direction
    // as -Z (since no orientation matrix is stored on the buffer).
    let cone_dir = [0.0, 0.0, -1.0];

    // Normalise the listener-to-buffer vector.
    let nx = dx / len;
    let ny = dy / len;
    let nz = dz / len;

    // Dot product between cone direction and listener direction.
    let dot = nx * cone_dir[0] + ny * cone_dir[1] + nz * cone_dir[2];
    // Clamp to [-1, 1] for numerical safety.
    let dot = dot.clamp(-1.0, 1.0);

    // Angle between cone axis and listener (in degrees).
    let angle_deg = dot.acos().to_degrees();

    let inside = state.cone_inside_angle as f32;
    let outside = state.cone_outside_angle.max(state.cone_inside_angle) as f32;

    if angle_deg <= inside {
        // Inside the inner cone — no attenuation.
        1.0
    } else if angle_deg >= outside {
        // Outside the outer cone — apply outside volume (dB -> linear).
        let db = state.cone_outside_volume as f32;
        if db <= -96.0 {
            0.0
        } else {
            10.0_f32.powf(db / 20.0)
        }
    } else {
        // Between inner and outer — linearly interpolate dB.
        let t = (angle_deg - inside) / (outside - inside);
        let db = t * state.cone_outside_volume as f32;
        if db <= -96.0 {
            0.0
        } else {
            10.0_f32.powf(db / 20.0)
        }
    }
}

/// Compute the Doppler shift frequency ratio.
///
/// Returns a frequency multiplier (e.g., 1.0 = no shift, >1 = higher pitch,
/// <1 = lower pitch).  The guest should read this via
/// `IDirectSound3DBuffer8::GetFrequency`.
fn compute_doppler_shift(state: &Ds3dBufferState, listener: &Ds3dListenerState) -> f32 {
    let doppler = listener.doppler_factor;
    if doppler <= f32::EPSILON {
        return 1.0; // Doppler disabled
    }

    // Vector from listener to source.
    let dx = state.position[0] - listener.position[0];
    let dy = state.position[1] - listener.position[1];
    let dz = state.position[2] - listener.position[2];
    let dist = (dx * dx + dy * dy + dz * dz).sqrt();
    if dist <= f32::EPSILON {
        return 1.0;
    }

    // Normalised direction from listener to source.
    let nx = dx / dist;
    let ny = dy / dist;
    let nz = dz / dist;

    // Project source and listener velocities onto the listener→source axis.
    let v_source = state.velocity[0] * nx + state.velocity[1] * ny + state.velocity[2] * nz;
    let v_listener =
        listener.velocity[0] * nx + listener.velocity[1] * ny + listener.velocity[2] * nz;

    let c = DS3D_SPEED_OF_SOUND;
    let numerator = c + doppler * v_listener;
    let denominator = c + doppler * v_source;

    if denominator <= f32::EPSILON {
        return 1.0;
    }
    (numerator / denominator).clamp(0.5, 2.0)
}

fn measure_latency_ms(sample_rate: u32, buffered_frames: usize) -> u32 {
    ((((buffered_frames as f32 / sample_rate as f32) * 1000.0).round() as u32) + 10).min(50)
}

// ── HRTF-like spatialization for DS3D ────────────────────────────────────

/// Head-related transfer function (HRTF) approximation gains for binaural
/// 3D audio.
///
/// Computes per-channel gains using interaural level difference (ILD) and
/// interaural time difference (ITD) based on the Woodworth formula.
/// Returns `(left_gain, right_gain)` in `[0, 1]`.
///
/// # Model
///
/// The head is modelled as a rigid sphere of radius `r` (default 8.75 cm).
/// The ITD is computed as:
///
/// ```text
/// ITD = (r / c) * (θ + sin(θ))
/// ```
///
/// where `θ` is the azimuth angle and `c` is the speed of sound.
/// The ILD is approximated as a shadow attenuation based on the azimuth.
///
/// For frequencies below ~1.5 kHz, ITD dominates; above, ILD dominates.
/// This implementation combines both for a perceptually plausible result.
pub fn compute_hrtf_gains(
    buffer_state: &Ds3dBufferState,
    listener: &Ds3dListenerState,
) -> (f32, f32) {
    // Vector from listener to buffer
    let dx = buffer_state.position[0] - listener.position[0];
    let dy = buffer_state.position[1] - listener.position[1];
    let dz = buffer_state.position[2] - listener.position[2];
    let distance = (dx * dx + dy * dy + dz * dz).sqrt();

    if distance <= f32::EPSILON {
        return (1.0, 1.0); // At listener position → equal gains
    }

    // Normalise direction
    let nx = dx / distance;
    let ny = dy / distance;
    let nz = dz / distance;

    // Compute right vector from listener orientation
    let fw = listener.forward;
    let up = listener.up;
    let right = [
        fw[1] * up[2] - fw[2] * up[1],
        fw[2] * up[0] - fw[0] * up[2],
        fw[0] * up[1] - fw[1] * up[0],
    ];

    // Compute azimuth angle (angle in the horizontal plane)
    let fwd_dot = nx * fw[0] + ny * fw[1] + nz * fw[2];
    let right_dot = nx * right[0] + ny * right[1] + nz * right[2];

    // Azimuth: 0 = front, π/2 = right, π = behind, -π/2 = left
    let azimuth = right_dot.atan2(fwd_dot);

    // Head radius in metres (average human: ~8.75 cm)
    let head_radius = 0.0875;
    let speed_of_sound = DS3D_SPEED_OF_SOUND;

    // Woodworth ITD formula: ITD = (r/c) * (θ + sin(θ))
    // For θ in [-π, π], we use the absolute azimuth
    let abs_azimuth = azimuth.abs();
    let itd_seconds = (head_radius / speed_of_sound) * (abs_azimuth + abs_azimuth.sin());

    // Convert ITD to a gain difference (simplified model)
    // At maximum ITD (~0.66 ms for 90°), the contralateral ear receives
    // approximately 6 dB less energy at high frequencies.
    let itd_max = head_radius / speed_of_sound * (std::f32::consts::PI + 0.0_f32.sin());
    let itd_ratio = if itd_max > f32::EPSILON {
        (itd_seconds / itd_max).clamp(0.0, 1.0)
    } else {
        0.0
    };

    // ILD: head shadow effect
    // The head blocks high frequencies on the contralateral side.
    // Simplified: ILD ≈ 6 dB * sin(azimuth) for the shadow side
    let ild_db = 6.0 * azimuth.sin();
    let ild_linear = 10.0_f32.powf(ild_db / 20.0);

    // Combine ITD and ILD into per-channel gains
    // For a sound on the right (azimuth > 0):
    //   - Right ear (ipsilateral): higher gain
    //   - Left ear (contralateral): lower gain (shadow + ITD)
    let base_gain = 1.0 - itd_ratio * 0.3; // ITD reduces contralateral gain

    let (left_gain, right_gain) = if azimuth >= 0.0 {
        // Sound is to the right
        (
            base_gain / ild_linear.max(f32::EPSILON),
            ild_linear.min(1.5),
        )
    } else {
        // Sound is to the left
        (
            ild_linear.min(1.5),
            base_gain / ild_linear.max(f32::EPSILON),
        )
    };

    // Clamp gains to reasonable range
    (left_gain.clamp(0.0, 1.5), right_gain.clamp(0.0, 1.5))
}

// ── XAPO effects chain for voice mixing ──────────────────────────────────

/// An effects chain that can be attached to a voice (submix or mastering).
///
/// Each effect in the chain processes the audio buffer in sequence.
/// Effects are identified by their XAPO CLSID.
#[derive(Debug, Clone)]
pub struct VoiceEffectsChain {
    /// Ordered list of effect CLSIDs to apply.
    pub effect_clsids: Vec<[u8; 16]>,
    /// Per-effect parameters (serialized as raw bytes).
    pub effect_params: Vec<Vec<u8>>,
    /// Whether the chain is enabled.
    pub enabled: bool,
}

impl Default for VoiceEffectsChain {
    fn default() -> Self {
        Self {
            effect_clsids: Vec::new(),
            effect_params: Vec::new(),
            enabled: true,
        }
    }
}

impl VoiceEffectsChain {
    /// Create a new empty effects chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an effect to the end of the chain.
    pub fn push_effect(&mut self, clsid: [u8; 16], params: Vec<u8>) {
        self.effect_clsids.push(clsid);
        self.effect_params.push(params);
    }

    /// Remove all effects from the chain.
    pub fn clear(&mut self) {
        self.effect_clsids.clear();
        self.effect_params.clear();
    }

    /// Apply the effects chain to a stereo float buffer.
    ///
    /// This applies each effect in sequence. For now, the built-in effects
    /// are applied directly:
    /// - Reverb: feedback delay with configurable decay
    /// - EQ: 3-band (low, mid, high) parametric equalizer
    /// - Compressor: dynamic range compression
    /// - Low-pass / High-pass: frequency filtering
    pub fn apply_chain(&self, samples: &mut [f32], channels: usize, sample_rate: u32) {
        if !self.enabled || samples.is_empty() {
            return;
        }

        for (idx, clsid) in self.effect_clsids.iter().enumerate() {
            let params = self.effect_params.get(idx).cloned().unwrap_or_default();
            apply_builtin_effect(clsid, &params, samples, channels, sample_rate);
        }
    }
}

/// Apply a single built-in XAPO effect to a sample buffer.
fn apply_builtin_effect(
    clsid: &[u8; 16],
    params: &[u8],
    samples: &mut [f32],
    channels: usize,
    sample_rate: u32,
) {
    // Decode the CLSID to determine which effect to apply.
    // We use the same CLSID mapping as XapoManager in real_audio.rs.
    let effect_id = u32::from_le_bytes([clsid[0], clsid[1], clsid[2], clsid[3]]);

    match effect_id {
        1 => {
            // Reverb: simple feedback delay
            let decay = if params.len() >= 4 {
                f32::from_le_bytes([params[0], params[1], params[2], params[3]]).clamp(0.0, 0.95)
            } else {
                0.5
            };
            let delay_frames = (sample_rate as f32 * 0.03) as usize; // 30ms delay
            apply_reverb_effect(samples, channels, decay, delay_frames);
        }
        2 => {
            // Low-pass filter
            let cutoff = if params.len() >= 4 {
                f32::from_le_bytes([params[0], params[1], params[2], params[3]])
            } else {
                1000.0
            };
            apply_lowpass_effect(samples, channels, cutoff, sample_rate);
        }
        3 => {
            // High-pass filter
            let cutoff = if params.len() >= 4 {
                f32::from_le_bytes([params[0], params[1], params[2], params[3]])
            } else {
                200.0
            };
            apply_highpass_effect(samples, channels, cutoff, sample_rate);
        }
        4 => {
            // Echo / delay
            let delay_ms = if params.len() >= 4 {
                f32::from_le_bytes([params[0], params[1], params[2], params[3]])
            } else {
                100.0
            };
            let feedback = if params.len() >= 8 {
                f32::from_le_bytes([params[4], params[5], params[6], params[7]]).clamp(0.0, 0.9)
            } else {
                0.5
            };
            apply_echo_effect(samples, channels, delay_ms, feedback, sample_rate);
        }
        5 => {
            // Compressor
            let threshold = if params.len() >= 4 {
                f32::from_le_bytes([params[0], params[1], params[2], params[3]])
            } else {
                -6.0
            };
            apply_compressor_effect(samples, channels, threshold);
        }
        7 => {
            // Equalizer (3-band)
            let low_gain = if params.len() >= 4 {
                f32::from_le_bytes([params[0], params[1], params[2], params[3]])
            } else {
                1.0
            };
            let mid_gain = if params.len() >= 8 {
                f32::from_le_bytes([params[4], params[5], params[6], params[7]])
            } else {
                1.0
            };
            let high_gain = if params.len() >= 12 {
                f32::from_le_bytes([params[8], params[9], params[10], params[11]])
            } else {
                1.0
            };
            apply_eq_effect(
                samples,
                channels,
                low_gain,
                mid_gain,
                high_gain,
                sample_rate,
            );
        }
        _ => {
            // Unknown effect — pass through
        }
    }
}

/// Apply a simple reverb effect (feedback delay).
fn apply_reverb_effect(samples: &mut [f32], channels: usize, decay: f32, delay_frames: usize) {
    if delay_frames == 0 || channels == 0 {
        return;
    }
    let frames = samples.len() / channels;
    let mut delay_line = vec![0.0f32; delay_frames * channels];
    let mut write_pos = 0;

    for frame in 0..frames {
        for ch in 0..channels {
            let idx = frame * channels + ch;
            let delayed = delay_line[write_pos * channels + ch];
            let output = samples[idx] + delayed * decay;
            samples[idx] = output.clamp(-1.0, 1.0);
            delay_line[write_pos * channels + ch] = output;
        }
        write_pos = (write_pos + 1) % delay_frames;
    }
}

/// Apply a simple first-order low-pass filter.
fn apply_lowpass_effect(samples: &mut [f32], channels: usize, cutoff_hz: f32, sample_rate: u32) {
    if sample_rate == 0 || cutoff_hz <= 0.0 {
        return;
    }
    let rc = 1.0 / (2.0 * std::f32::consts::PI * cutoff_hz);
    let dt = 1.0 / sample_rate as f32;
    let alpha = dt / (rc + dt);

    for ch in 0..channels {
        let mut prev = 0.0f32;
        for frame in 0..(samples.len() / channels) {
            let idx = frame * channels + ch;
            let input = samples[idx];
            prev = prev + alpha * (input - prev);
            samples[idx] = prev;
        }
    }
}

/// Apply a simple first-order high-pass filter.
fn apply_highpass_effect(samples: &mut [f32], channels: usize, cutoff_hz: f32, sample_rate: u32) {
    if sample_rate == 0 || cutoff_hz <= 0.0 {
        return;
    }
    let rc = 1.0 / (2.0 * std::f32::consts::PI * cutoff_hz);
    let dt = 1.0 / sample_rate as f32;
    let alpha = rc / (rc + dt);

    for ch in 0..channels {
        let mut prev_input = 0.0f32;
        let mut prev_output = 0.0f32;
        for frame in 0..(samples.len() / channels) {
            let idx = frame * channels + ch;
            let input = samples[idx];
            let output = alpha * (prev_output + input - prev_input);
            prev_input = input;
            prev_output = output;
            samples[idx] = output;
        }
    }
}

/// Apply an echo/delay effect.
fn apply_echo_effect(
    samples: &mut [f32],
    channels: usize,
    delay_ms: f32,
    feedback: f32,
    sample_rate: u32,
) {
    if sample_rate == 0 || delay_ms <= 0.0 {
        return;
    }
    let delay_frames = ((delay_ms / 1000.0) * sample_rate as f32) as usize;
    if delay_frames == 0 {
        return;
    }
    let frames = samples.len() / channels;
    let mut delay_line = vec![0.0f32; delay_frames * channels];
    let mut write_pos = 0;

    for frame in 0..frames {
        for ch in 0..channels {
            let idx = frame * channels + ch;
            let delayed = delay_line[write_pos * channels + ch];
            samples[idx] += delayed;
            delay_line[write_pos * channels + ch] = samples[idx] * feedback;
        }
        write_pos = (write_pos + 1) % delay_frames;
    }
}

/// Apply a simple compressor effect.
fn apply_compressor_effect(samples: &mut [f32], _channels: usize, threshold_db: f32) {
    let threshold_linear = 10.0_f32.powf(threshold_db / 20.0);
    let ratio = 4.0; // 4:1 compression ratio

    for sample in samples.iter_mut() {
        let abs_sample = sample.abs();
        if abs_sample > threshold_linear {
            let excess = abs_sample - threshold_linear;
            let compressed = threshold_linear + excess / ratio;
            *sample = if *sample >= 0.0 {
                compressed
            } else {
                -compressed
            };
        }
    }
}

/// Apply a 3-band equalizer effect.
fn apply_eq_effect(
    samples: &mut [f32],
    channels: usize,
    low_gain: f32,
    mid_gain: f32,
    high_gain: f32,
    sample_rate: u32,
) {
    if sample_rate == 0 {
        return;
    }

    // Simple crossover frequencies
    let low_cutoff = 300.0_f32;
    let high_cutoff = 3000.0_f32;

    // Process each channel independently
    for ch in 0..channels {
        // Low-pass for low band
        let rc_low = 1.0 / (2.0 * std::f32::consts::PI * low_cutoff);
        let dt = 1.0 / sample_rate as f32;
        let alpha_low = dt / (rc_low + dt);

        // High-pass for high band
        let rc_high = 1.0 / (2.0 * std::f32::consts::PI * high_cutoff);
        let alpha_high = rc_high / (rc_high + dt);

        let mut low_prev = 0.0f32;
        let mut hp_prev_input = 0.0f32;
        let mut hp_prev_output = 0.0f32;

        for frame in 0..(samples.len() / channels) {
            let idx = frame * channels + ch;
            let input = samples[idx];

            // Low band (low-pass filter output)
            low_prev = low_prev + alpha_low * (input - low_prev);
            let low = low_prev * low_gain;

            // High band (high-pass filter output)
            let high = alpha_high * (hp_prev_output + input - hp_prev_input);
            hp_prev_input = input;
            hp_prev_output = high;
            let high_out = high * high_gain;

            // Mid band = input - low - high (simplified)
            let mid = (input - low_prev - high) * mid_gain;

            samples[idx] = (low + mid + high_out).clamp(-1.0, 1.0);
        }
    }
}

// ---------------------------------------------------------------------------
// XAudio2 Performance Data & Callback Management (Gap 7.8)
// ---------------------------------------------------------------------------

/// XAudio2 engine performance counters.
///
/// Tracks real-time audio processing statistics including CPU usage,
/// memory consumption, latency, and voice counts. Updated on each
/// processing pass by the audio engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct XAudio2PerformanceData {
    /// Total CPU usage of the audio processing thread as a percentage (0–100).
    pub cpu_usage_percent: f32,
    /// Number of active source voices.
    pub active_source_voice_count: u32,
    /// Total source voices ever created.
    pub total_source_voice_count: u32,
    /// Number of active submix voices.
    pub active_submix_voice_count: u32,
    /// Number of active mastering voices (typically 1).
    pub active_mastering_voice_count: u32,
    /// Total audio memory currently in use (bytes).
    pub memory_usage_bytes: u64,
    /// Peak memory usage since engine start (bytes).
    pub peak_memory_usage_bytes: u64,
    /// Current output latency in milliseconds.
    pub current_latency_ms: f32,
    /// Total number of audio glitches (buffer underruns) since start.
    pub glitch_count: u32,
    /// Number of audio frames processed since engine start.
    pub total_frames_processed: u64,
    /// Number of times the processing pass exceeded its time budget.
    pub overdue_count: u32,
}

impl Default for XAudio2PerformanceData {
    fn default() -> Self {
        Self {
            cpu_usage_percent: 0.0,
            active_source_voice_count: 0,
            total_source_voice_count: 0,
            active_submix_voice_count: 0,
            active_mastering_voice_count: 0,
            memory_usage_bytes: 0,
            peak_memory_usage_bytes: 0,
            current_latency_ms: 0.0,
            glitch_count: 0,
            total_frames_processed: 0,
            overdue_count: 0,
        }
    }
}

impl XAudio2PerformanceData {
    /// Create a new zeroed performance data structure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a processing pass: increment frame count and update CPU usage.
    pub fn record_pass(&mut self, frames: u32, cpu_fraction: f32, latency_ms: f32) {
        self.total_frames_processed += frames as u64;
        self.cpu_usage_percent = cpu_fraction * 100.0;
        self.current_latency_ms = latency_ms;
    }

    /// Record a buffer underrun (glitch).
    pub fn record_glitch(&mut self) {
        self.glitch_count += 1;
    }

    /// Record an overdue processing pass.
    pub fn record_overdue(&mut self) {
        self.overdue_count += 1;
    }

    /// Update memory usage tracking.
    pub fn update_memory(&mut self, current_bytes: u64) {
        self.memory_usage_bytes = current_bytes;
        if current_bytes > self.peak_memory_usage_bytes {
            self.peak_memory_usage_bytes = current_bytes;
        }
    }

    /// Update voice counts.
    pub fn update_voice_counts(&mut self, source: u32, submix: u32, mastering: u32) {
        self.active_source_voice_count = source;
        self.active_submix_voice_count = submix;
        self.active_mastering_voice_count = mastering;
    }

    /// Increment total source voice creation count.
    pub fn inc_total_source_voices(&mut self) {
        self.total_source_voice_count += 1;
    }
}

/// Callback event types for the IXAudio2EngineCallback interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XAudio2CallbackEventType {
    /// Called just before the processing pass begins.
    OnProcessingPassStart,
    /// Called just after the processing pass ends.
    OnProcessingPassEnd,
    /// Called when a critical error occurs.
    OnCriticalError,
    /// Called when a buffer underrun is about to occur.
    OnBufferUnderrun,
}

/// A recorded callback event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XAudio2CallbackEvent {
    /// The type of callback event.
    pub event_type: XAudio2CallbackEventType,
    /// Timestamp (monotonic, milliseconds since engine start).
    pub timestamp_ms: u64,
    /// Optional error code for OnCriticalError.
    pub error_code: u32,
    /// The voice ID associated with the callback (if applicable).
    pub voice_id: Option<VoiceId>,
}

/// Debug configuration for the XAudio2 engine.
///
/// Controls logging, break-on-error, and trace masking for debugging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct XAudio2DebugConfiguration {
    /// Log mask: combination of `XA2LOG_*` bits.
    pub log_mask: u32,
    /// Whether to break into the debugger on errors.
    pub break_on_error: bool,
    /// Whether to break into the debugger on memory allocation failures.
    pub break_on_malloc_failure: bool,
    /// Whether to trace function entry/exit.
    pub trace_mask: u32,
    /// Whether logging is enabled at all.
    pub logging_enabled: bool,
}

/// Log mask bits for XAudio2 debug configuration.
pub mod xa2_log_mask {
    /// Log errors.
    pub const ERRORS: u32 = 0x0001;
    /// Log warnings.
    pub const WARNINGS: u32 = 0x0002;
    /// Log informational messages.
    pub const INFO: u32 = 0x0004;
    /// Log detail messages.
    pub const DETAIL: u32 = 0x0008;
    /// Log API function calls.
    pub const API_CALLS: u32 = 0x0010;
    /// Log function entry/exit.
    pub const FUNC_CALLS: u32 = 0x0020;
    /// Log timing information.
    pub const TIMING: u32 = 0x0040;
    /// Lock usage logging.
    pub const LOCKS: u32 = 0x0080;
    /// Memory logging.
    pub const MEMORY: u32 = 0x0100;
    /// Streaming logging.
    pub const STREAMING: u32 = 0x1000;
}

/// Trace mask bits.
pub mod xa2_trace_mask {
    /// Trace API calls.
    pub const API: u32 = 0x0001;
    /// Trace voice processing.
    pub const VOICE: u32 = 0x0002;
    /// Trace effect processing.
    pub const EFFECTS: u32 = 0x0004;
    /// Trace buffer management.
    pub const BUFFERS: u32 = 0x0008;
    /// Trace memory operations.
    pub const MEMORY: u32 = 0x0010;
    /// Trace streaming operations.
    pub const STREAMING: u32 = 0x0020;
}

/// Registered engine callback.
#[derive(Debug, Clone)]
struct RegisteredCallback {
    /// The guest-side callback function pointer.
    fn_ptr: u64,
    /// The guest-side context pointer passed to the callback.
    context: u64,
}

/// XAudio2 engine callback and performance data manager.
///
/// Manages registered engine callbacks, collects performance data,
/// and maintains debug configuration. This is the real implementation
/// backing the IXAudio2 vtable methods RegisterForCallbacks,
/// UnregisterForCallbacks, GetPerformanceData, and SetDebugConfiguration.
#[derive(Debug)]
pub struct XAudio2EngineCallbacks {
    /// Registered engine callbacks.
    callbacks: Vec<RegisteredCallback>,
    /// Current performance data.
    performance: XAudio2PerformanceData,
    /// Current debug configuration.
    debug_config: XAudio2DebugConfiguration,
    /// Engine start time (monotonic).
    start_instant: Instant,
    /// Event log of callback invocations (capped at 1000 entries).
    event_log: Vec<XAudio2CallbackEvent>,
}

impl Default for XAudio2EngineCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

impl XAudio2EngineCallbacks {
    /// Create a new callback manager.
    pub fn new() -> Self {
        Self {
            callbacks: Vec::new(),
            performance: XAudio2PerformanceData::new(),
            debug_config: XAudio2DebugConfiguration::default(),
            start_instant: Instant::now(),
            event_log: Vec::new(),
        }
    }

    // -- Callback registration --

    /// Register an engine callback.
    ///
    /// The callback function pointer and context are stored for later
    /// invocation during processing passes and error conditions.
    /// Returns true on success.
    pub fn register_callback(&mut self, fn_ptr: u64, context: u64) -> bool {
        if fn_ptr == 0 {
            return false;
        }
        // Avoid duplicate registration
        if self.callbacks.iter().any(|cb| cb.fn_ptr == fn_ptr) {
            return true;
        }
        self.callbacks.push(RegisteredCallback { fn_ptr, context });
        true
    }

    /// Unregister a previously registered engine callback.
    ///
    /// Returns true if the callback was found and removed.
    pub fn unregister_callback(&mut self, fn_ptr: u64) -> bool {
        let before = self.callbacks.len();
        self.callbacks.retain(|cb| cb.fn_ptr != fn_ptr);
        self.callbacks.len() < before
    }

    /// Get the list of registered callback function pointers.
    pub fn registered_callbacks(&self) -> Vec<u64> {
        self.callbacks.iter().map(|cb| cb.fn_ptr).collect()
    }

    /// Get the number of registered callbacks.
    pub fn callback_count(&self) -> usize {
        self.callbacks.len()
    }

    // -- Performance data --

    /// Get a reference to the current performance data.
    pub fn performance_data(&self) -> &XAudio2PerformanceData {
        &self.performance
    }

    /// Get a mutable reference to the performance data for updating.
    pub fn performance_data_mut(&mut self) -> &mut XAudio2PerformanceData {
        &mut self.performance
    }

    /// Snapshot the current performance data.
    pub fn snapshot_performance(&self) -> XAudio2PerformanceData {
        self.performance.clone()
    }

    // -- Debug configuration --

    /// Set the debug configuration.
    pub fn set_debug_configuration(&mut self, config: XAudio2DebugConfiguration) {
        self.debug_config = config;
    }

    /// Get a reference to the current debug configuration.
    pub fn debug_configuration(&self) -> &XAudio2DebugConfiguration {
        &self.debug_config
    }

    // -- Event logging --

    /// Record a callback event in the event log.
    fn log_event(
        &mut self,
        event_type: XAudio2CallbackEventType,
        voice_id: Option<VoiceId>,
        error_code: u32,
    ) {
        let elapsed = self.start_instant.elapsed().as_millis() as u64;
        let event = XAudio2CallbackEvent {
            event_type,
            timestamp_ms: elapsed,
            error_code,
            voice_id,
        };
        self.event_log.push(event);
        // Cap the event log at 1000 entries
        if self.event_log.len() > 1000 {
            self.event_log.drain(0..100);
        }
    }

    /// Notify all registered callbacks of a processing pass start.
    ///
    /// Returns the list of (fn_ptr, context) pairs that should be called.
    pub fn notify_processing_pass_start(&mut self) -> Vec<(u64, u64)> {
        self.log_event(XAudio2CallbackEventType::OnProcessingPassStart, None, 0);
        self.callbacks
            .iter()
            .map(|cb| (cb.fn_ptr, cb.context))
            .collect()
    }

    /// Notify all registered callbacks of a processing pass end.
    pub fn notify_processing_pass_end(&mut self) -> Vec<(u64, u64)> {
        self.log_event(XAudio2CallbackEventType::OnProcessingPassEnd, None, 0);
        self.callbacks
            .iter()
            .map(|cb| (cb.fn_ptr, cb.context))
            .collect()
    }

    /// Notify all registered callbacks of a critical error.
    pub fn notify_critical_error(&mut self, error_code: u32) -> Vec<(u64, u64)> {
        self.log_event(XAudio2CallbackEventType::OnCriticalError, None, error_code);
        self.callbacks
            .iter()
            .map(|cb| (cb.fn_ptr, cb.context))
            .collect()
    }

    /// Get the event log.
    pub fn event_log(&self) -> &[XAudio2CallbackEvent] {
        &self.event_log
    }

    /// Clear the event log.
    pub fn clear_event_log(&mut self) {
        self.event_log.clear();
    }
}
