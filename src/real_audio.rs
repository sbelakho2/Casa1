//! Real audio backend for Casa1.
//!
//! Bridges XAudio2 mastering voices, WASAPI audio clients, and DirectSound
//! buffers to real `cpal` output streams on macOS. Provides real device
//! enumeration, format conversion, sample rate conversion, voice callbacks,
//! reverb DSP, and device hotplug detection.

use crate::audio::{
    AudioClientId, AudioDeviceInfo, DeviceId, LatencyRecord, RenderOutput, SampleFormat, VoiceId,
    WaveFormat,
};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Real audio device
// ---------------------------------------------------------------------------

/// Maximum number of latency records kept in the latency log.
///
/// The log is only used for diagnostics; cap it so a long-running emulator
/// session with many stream opens cannot grow memory without bound.
const MAX_LATENCY_LOG_ENTRIES: usize = 256;

// ---------------------------------------------------------------------------
// WASAPI exclusive-mode state
// ---------------------------------------------------------------------------

/// Per-client state for WASAPI exclusive-mode audio streams.
///
/// Tracks the negotiated buffer size, period, and format for an exclusive-mode
/// WASAPI audio client. Exclusive mode uses the exact sample rate (no
/// resampling) and the smallest possible buffer size for low-latency output.
#[derive(Debug, Clone)]
pub struct WasapiExclusiveState {
    /// The cpal device driving this client.
    pub device_id: DeviceId,
    /// The buffer size in frames negotiated with the hardware.
    pub buffer_frames: usize,
    /// The period (latency) in milliseconds.
    pub period_ms: u32,
    /// The audio format negotiated with the hardware.
    pub format: WaveFormat,
}

/// A real audio output device discovered via `cpal`.
#[derive(Debug, Clone)]
pub struct RealAudioDevice {
    pub id: DeviceId,
    /// Stable identity key used to match a device across enumeration calls.
    ///
    /// cpal 0.15 exposes no device ID, so we fall back to a
    /// `name|channels|sample_rate` tuple. This keeps distinct devices with
    /// identical display names separate and survives benign renames only when
    /// the config also changes (in which case the device is re-detected).
    pub key: String,
    pub name: String,
    pub channels: u16,
    pub sample_rate: u32,
    pub is_default: bool,
}

// ---------------------------------------------------------------------------
// Real audio backend
// ---------------------------------------------------------------------------

/// Manages real audio output streams via `cpal`.
///
/// Each XAudio2 mastering voice, WASAPI audio client, or DirectSound buffer
/// that starts playback gets its own `cpal` output stream. Audio data is
/// pushed into a lock-free queue and consumed by the real-time audio callback.
///
/// Also manages a single capture (microphone/line-in) input stream.
pub struct RealAudioBackend {
    host: cpal::Host,
    devices: BTreeMap<DeviceId, RealAudioDevice>,
    next_device_id: DeviceId,
    streams: HashMap<DeviceId, cpal::Stream>,
    stream_queues: HashMap<DeviceId, Arc<Mutex<VecDeque<f32>>>>,
    latency_log: Vec<LatencyRecord>,
    /// Per-client state for WASAPI exclusive-mode streams.
    exclusive_clients: HashMap<AudioClientId, WasapiExclusiveState>,
    /// Negotiated (format, buffer frames) per device for exclusive-mode streams,
    /// so reuse of an exclusive stream returns the real negotiated buffer size.
    exclusive_streams: HashMap<DeviceId, (WaveFormat, usize)>,
    /// Auto-incrementing counter for AudioClientId values.
    next_audio_client_id: AudioClientId,
    /// Active capture (microphone/line-in) input stream, if any.
    input_stream: Option<cpal::Stream>,
    /// Shared buffer for captured audio data from the input stream callback.
    capture_buffer: Arc<Mutex<VecDeque<f32>>>,
}

impl RealAudioBackend {
    /// Create a new real audio backend, enumerating available output devices.
    pub fn new() -> AppResult<Self> {
        let host = cpal::default_host();
        let mut devices = BTreeMap::new();
        let mut next_device_id: DeviceId = 1;

        let default_device = host.default_output_device();

        match host.output_devices() {
            Ok(device_list) => {
                for device in device_list {
                    let key = cpal_device_key(&device);
                    let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
                    let config = match device.default_output_config() {
                        Ok(config) => Some(config),
                        Err(error) => {
                            eprintln!(
                                "[RealAudio] new: failed to get default output config for '{name}': {error}"
                            );
                            None
                        }
                    };
                    let channels = config.as_ref().map(|c| c.channels()).unwrap_or(2);
                    let sample_rate = config.as_ref().map(|c| c.sample_rate().0).unwrap_or(48_000);
                    let is_default = default_device
                        .as_ref()
                        .map(|d| d.name().map(|n| n == name).unwrap_or(false))
                        .unwrap_or(false);

                    devices.insert(
                        next_device_id,
                        RealAudioDevice {
                            id: next_device_id,
                            key,
                            name,
                            channels,
                            sample_rate,
                            is_default,
                        },
                    );
                    next_device_id += 1;
                }
            }
            Err(error) => {
                eprintln!("[RealAudio] new: failed to enumerate output devices: {error}");
            }
        }

        Ok(Self {
            host,
            devices,
            next_device_id,
            streams: HashMap::new(),
            stream_queues: HashMap::new(),
            latency_log: Vec::new(),
            exclusive_clients: HashMap::new(),
            exclusive_streams: HashMap::new(),
            next_audio_client_id: 1,
            input_stream: None,
            capture_buffer: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    /// Enumerate all real output devices.
    pub fn enumerate_devices(&self) -> Vec<AudioDeviceInfo> {
        self.devices
            .values()
            .map(|d| AudioDeviceInfo {
                id: d.id,
                name: d.name.clone(),
                channels: d.channels,
                sample_rate: d.sample_rate,
                is_default: d.is_default,
            })
            .collect()
    }

    /// Get the default output device ID.
    pub fn default_device_id(&self) -> AppResult<DeviceId> {
        self.devices
            .values()
            .find(|d| d.is_default)
            .map(|d| d.id)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    "no default audio output device available",
                )
            })
    }

    /// Get device info by ID.
    pub fn device_info(&self, device_id: DeviceId) -> AppResult<&RealAudioDevice> {
        self.devices.get(&device_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown audio device {device_id}"),
            )
        })
    }

    // -----------------------------------------------------------------------
    // XAudio2 real output
    // -----------------------------------------------------------------------

    /// Open a real output stream for an XAudio2 mastering voice.
    ///
    /// Returns the device ID of the stream. Audio samples pushed via
    /// `push_xaudio2_samples` will be played through the real device.
    pub fn open_xaudio2_master(&mut self, _format: &WaveFormat) -> AppResult<DeviceId> {
        let device_id = self.default_device_id()?;
        self.ensure_stream(device_id, false)?;
        Ok(device_id)
    }

    /// Push mixed XAudio2 samples to the real output stream.
    pub fn push_xaudio2_samples(
        &mut self,
        device_id: DeviceId,
        samples: &[f32],
        source_channels: u16,
        source_rate: u32,
    ) -> AppResult<()> {
        let device = self.device_info(device_id)?;
        if !self.stream_queues.contains_key(&device_id) {
            return Err(stream_not_open_error(device_id));
        }
        let converted = convert_and_resample(
            samples,
            source_channels,
            source_rate,
            device.channels,
            device.sample_rate,
        );
        let max_samples = max_output_queue_samples(device.sample_rate, device.channels);
        self.enqueue_samples(device_id, &converted, max_samples)
    }

    /// Render XAudio2 voice graph and push to real output.
    pub fn render_xaudio2_to_device(
        &mut self,
        mastering_voice: VoiceId,
        frames: usize,
        audio_subsystem: &mut crate::audio::AudioSubsystem,
    ) -> AppResult<RenderOutput> {
        let output = audio_subsystem.render_xaudio2(mastering_voice, frames)?;
        let format = audio_subsystem.voice_format(mastering_voice)?;

        // Play back through the default output device.
        let device_id = self.default_device_id()?;

        if !output.samples.is_empty() {
            self.push_xaudio2_samples(
                device_id,
                &output.samples,
                format.channels,
                format.sample_rate,
            )?;
        }

        Ok(output)
    }

    // -----------------------------------------------------------------------
    // WASAPI real output (shared mode)
    // -----------------------------------------------------------------------

    /// Open a real output stream for a WASAPI audio client.
    ///
    /// `event_driven` selects a small fixed buffer (lower latency) when `true`;
    /// the stream falls back to the device default buffer if the device
    /// rejects the small size.
    pub fn open_wasapi_client(
        &mut self,
        _format: &WaveFormat,
        buffer_frames: usize,
        event_driven: bool,
    ) -> AppResult<DeviceId> {
        let device_id = self.default_device_id()?;
        self.ensure_stream(device_id, event_driven)?;

        // Record latency using the device's actual sample rate so the recorded
        // value is meaningful when the client format differs from the device.
        let device_rate = self.device_info(device_id)?.sample_rate;
        let latency_ms = measure_latency_ms(device_rate, buffer_frames);
        self.push_latency_record(LatencyRecord {
            subsystem: "wasapi".to_string(),
            device_id,
            measured_ms: latency_ms,
        });

        Ok(device_id)
    }

    /// Push WASAPI render frames to the real output stream.
    pub fn push_wasapi_frames(
        &mut self,
        device_id: DeviceId,
        samples: &[f32],
        source_channels: u16,
        source_rate: u32,
    ) -> AppResult<()> {
        let device = self.device_info(device_id)?;
        if !self.stream_queues.contains_key(&device_id) {
            return Err(stream_not_open_error(device_id));
        }
        let converted = convert_and_resample(
            samples,
            source_channels,
            source_rate,
            device.channels,
            device.sample_rate,
        );
        let max_samples = max_output_queue_samples(device.sample_rate, device.channels);
        self.enqueue_samples(device_id, &converted, max_samples)
    }

    // -----------------------------------------------------------------------
    // WASAPI real output (exclusive mode)
    // -----------------------------------------------------------------------

    /// Open a real output stream for a WASAPI audio client in exclusive mode.
    ///
    /// Unlike shared mode (`open_wasapi_client`), exclusive mode negotiates the
    /// **exact** sample rate requested (no resampling) and uses the smallest
    /// possible buffer size (target ≤10 ms latency). This provides lower latency
    /// at the cost of exclusive hardware access.
    ///
    /// Returns an `AudioClientId` that identifies this exclusive-mode client.
    /// Use `push_wasapi_frames_exclusive()` to submit audio data.
    ///
    /// # Errors
    ///
    /// Returns `RcAudioUnsupported` if no supported config matches the requested
    /// format (channels, sample rate, and sample format) on the given device.
    pub fn open_wasapi_client_exclusive(
        &mut self,
        device_id: DeviceId,
        format: WaveFormat,
    ) -> AppResult<AudioClientId> {
        // Validate device
        self.device_info(device_id)?;

        // Create an exclusive-mode cpal stream (exact sample rate, no resampling)
        let buffer_frames = self.ensure_stream_exclusive(device_id, &format)?;

        // Calculate the period in milliseconds
        let period_ms = if format.sample_rate > 0 {
            (((buffer_frames as f32 / format.sample_rate as f32) * 1000.0).round() as u32).max(1)
        } else {
            10
        };

        // Generate a new AudioClientId
        let client_id = self.next_audio_client_id;
        self.next_audio_client_id += 1;

        // Store exclusive-mode state
        self.exclusive_clients.insert(
            client_id,
            WasapiExclusiveState {
                device_id,
                buffer_frames,
                period_ms,
                format: format.clone(),
            },
        );

        // Record latency
        self.push_latency_record(LatencyRecord {
            subsystem: "wasapi_exclusive".to_string(),
            device_id,
            measured_ms: period_ms,
        });

        Ok(client_id)
    }

    /// Push WASAPI render frames to an exclusive-mode audio client.
    ///
    /// # Strict buffer size enforcement
    ///
    /// The caller **must** submit exactly `buffer_frames` worth of samples
    /// (i.e. `samples.len() == buffer_frames * channels`). If the frame count
    /// does not match, `RcAudioBufferSizeMismatch` is returned.
    ///
    /// The exclusive stream is built at exactly the client's format (channels
    /// and sample rate), so samples are queued verbatim without resampling or
    /// channel remapping.
    ///
    /// # Errors
    ///
    /// Returns `RcAudioBufferSizeMismatch` if the sample count does not match
    /// the exclusive-mode buffer size.
    pub fn push_wasapi_frames_exclusive(
        &mut self,
        client: AudioClientId,
        samples: &[f32],
    ) -> AppResult<()> {
        let state = self.exclusive_clients.get(&client).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("unknown exclusive-mode audio client {client}"),
            )
        })?;

        let channels = state.format.channels as usize;
        let expected_samples = state.buffer_frames.saturating_mul(channels);

        if samples.len() != expected_samples {
            let actual_frames = samples.len().checked_div(channels).unwrap_or(0);
            return Err(AppError::new(
                ReasonCode::RcAudioBufferSizeMismatch,
                format!(
                    "exclusive-mode buffer size mismatch: expected {} frames ({} samples), got {} frames ({} samples)",
                    state.buffer_frames,
                    expected_samples,
                    actual_frames,
                    samples.len(),
                ),
            ));
        }

        // The stream was negotiated at exactly `state.format`; queue the
        // samples verbatim so they play back at the correct rate and channel
        // layout (resampling to the device default config would corrupt both).
        let max_samples = max_output_queue_samples(state.format.sample_rate, state.format.channels);
        self.enqueue_samples(state.device_id, samples, max_samples)
    }

    // -----------------------------------------------------------------------
    // DirectSound real output
    // -----------------------------------------------------------------------

    /// Open a real output stream for a DirectSound buffer.
    pub fn open_direct_sound_buffer(&mut self, _format: &WaveFormat) -> AppResult<DeviceId> {
        let device_id = self.default_device_id()?;
        self.ensure_stream(device_id, false)?;
        Ok(device_id)
    }

    /// Push DirectSound buffer samples to the real output stream.
    pub fn push_direct_sound_samples(
        &mut self,
        device_id: DeviceId,
        samples: &[f32],
        source_channels: u16,
        source_rate: u32,
    ) -> AppResult<()> {
        let device = self.device_info(device_id)?;
        if !self.stream_queues.contains_key(&device_id) {
            return Err(stream_not_open_error(device_id));
        }
        let converted = convert_and_resample(
            samples,
            source_channels,
            source_rate,
            device.channels,
            device.sample_rate,
        );
        let max_samples = max_output_queue_samples(device.sample_rate, device.channels);
        self.enqueue_samples(device_id, &converted, max_samples)
    }

    // -----------------------------------------------------------------------
    // Device hotplug
    // -----------------------------------------------------------------------

    /// Refresh the device list, detecting newly connected or removed devices.
    ///
    /// Returns `(added_devices, removed_device_ids)`.
    ///
    /// Devices are matched across enumeration calls by their stable identity
    /// key (name + channels + sample rate); existing stream IDs are preserved
    /// for devices that are still present.
    pub fn detect_device_changes(&mut self) -> AppResult<(Vec<RealAudioDevice>, Vec<DeviceId>)> {
        let mut current: BTreeMap<String, RealAudioDevice> = BTreeMap::new();
        let default_device = self.host.default_output_device();

        match self.host.output_devices() {
            Ok(device_list) => {
                for device in device_list {
                    let key = cpal_device_key(&device);
                    let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
                    let config = match device.default_output_config() {
                        Ok(config) => Some(config),
                        Err(error) => {
                            eprintln!(
                                "[RealAudio] detect_device_changes: failed to get config for '{name}': {error}"
                            );
                            None
                        }
                    };
                    let channels = config.as_ref().map(|c| c.channels()).unwrap_or(2);
                    let sample_rate = config.as_ref().map(|c| c.sample_rate().0).unwrap_or(48_000);
                    let is_default = default_device
                        .as_ref()
                        .map(|d| d.name().map(|n| n == name).unwrap_or(false))
                        .unwrap_or(false);

                    // Use the existing device ID if we already know this device,
                    // otherwise a placeholder; new IDs are assigned below.
                    let existing_id = self
                        .devices
                        .values()
                        .find(|d| d.key == key)
                        .map(|d| d.id)
                        .unwrap_or(0);
                    current.insert(
                        key.clone(),
                        RealAudioDevice {
                            id: existing_id,
                            key,
                            name,
                            channels,
                            sample_rate,
                            is_default,
                        },
                    );
                }
            }
            Err(error) => {
                eprintln!(
                    "[RealAudio] detect_device_changes: failed to enumerate output devices: {error}"
                );
            }
        }

        let current_keys: Vec<String> = current.keys().cloned().collect();
        let mut added = Vec::new();

        // Merge: refresh still-present devices in place, assign IDs to new ones.
        for (key, mut device) in current {
            match self.devices.values_mut().find(|d| d.key == key) {
                Some(existing) => {
                    existing.name = device.name;
                    existing.channels = device.channels;
                    existing.sample_rate = device.sample_rate;
                    existing.is_default = device.is_default;
                }
                None => {
                    device.id = self.next_device_id;
                    self.next_device_id += 1;
                    added.push(device.clone());
                    self.devices.insert(device.id, device);
                }
            }
        }

        // Detect removed devices
        let to_remove: Vec<DeviceId> = self
            .devices
            .iter()
            .filter(|(_, device)| !current_keys.contains(&device.key))
            .map(|(id, _)| *id)
            .collect();

        for id in &to_remove {
            self.devices.remove(id);
            self.streams.remove(id);
            self.stream_queues.remove(id);
            self.exclusive_streams.remove(id);
        }

        Ok((added, to_remove))
    }

    // -----------------------------------------------------------------------
    // Latency measurement
    // -----------------------------------------------------------------------

    /// Get the latency log.
    pub fn latency_log(&self) -> &[LatencyRecord] {
        &self.latency_log
    }

    /// Measure the current output latency in milliseconds for a device.
    pub fn measure_output_latency(&self, device_id: DeviceId) -> AppResult<u32> {
        let device = self.device_info(device_id)?;
        let queued_samples = self
            .stream_queues
            .get(&device_id)
            .map(|q| q.lock().map(|q| q.len()).unwrap_or(0))
            .unwrap_or(0);
        let channels = device.channels as usize;
        let queued_frames = queued_samples.checked_div(channels).unwrap_or(0);
        let latency_ms = if device.sample_rate > 0 {
            ((queued_frames as f32 / device.sample_rate as f32) * 1000.0).round() as u32
        } else {
            0
        };
        Ok(latency_ms.min(50))
    }

    // -----------------------------------------------------------------------
    // Stream management
    // -----------------------------------------------------------------------

    /// Close the output stream for a device.
    pub fn close_stream(&mut self, device_id: DeviceId) {
        self.streams.remove(&device_id);
        self.stream_queues.remove(&device_id);
        // Clean up any exclusive-mode clients and streams using this device
        self.exclusive_clients
            .retain(|_, state| state.device_id != device_id);
        self.exclusive_streams.remove(&device_id);
    }

    /// Close all output streams and exclusive-mode clients.
    pub fn close_all_streams(&mut self) {
        self.streams.clear();
        self.stream_queues.clear();
        self.exclusive_clients.clear();
        self.exclusive_streams.clear();
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Ensure a cpal output stream exists for the given device.
    ///
    /// `prefer_small_buffer` requests a small fixed buffer (lower latency);
    /// if the device rejects it the stream falls back to the default buffer.
    fn ensure_stream(&mut self, device_id: DeviceId, prefer_small_buffer: bool) -> AppResult<()> {
        if self.streams.contains_key(&device_id) {
            return Ok(());
        }

        let device = self.device_info(device_id)?;
        let cpal_device = self.find_cpal_device(device_id)?;
        let supported_config = cpal_device.default_output_config().map_err(|e| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to get audio output config: {e}"),
            )
        })?;
        let sample_format = supported_config.sample_format();

        // Pre-allocate the queue to its maximum size so the producer never
        // reallocates under the lock and the real-time callback stays
        // allocation-free.
        let max_samples = max_output_queue_samples(device.sample_rate, device.channels);
        let queue: Arc<Mutex<VecDeque<f32>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(max_samples)));
        let callback_queue = Arc::clone(&queue);

        let base_config = supported_config.config();
        let mut buffer_size = base_config.buffer_size;
        let stream = if prefer_small_buffer {
            let mut small_config = base_config.clone();
            small_config.buffer_size = cpal::BufferSize::Fixed(256);
            match build_output_stream(
                &cpal_device,
                &small_config,
                sample_format,
                Arc::clone(&callback_queue),
            ) {
                Ok(stream) => {
                    buffer_size = cpal::BufferSize::Fixed(256);
                    stream
                }
                Err(_) => {
                    // Fall back to the device default config.
                    build_output_stream(
                        &cpal_device,
                        &base_config,
                        sample_format,
                        Arc::clone(&callback_queue),
                    )
                    .map_err(|e| {
                        AppError::new(
                            ReasonCode::RcAudioUnsupported,
                            format!("failed to build audio stream: {e}"),
                        )
                    })?
                }
            }
        } else {
            build_output_stream(
                &cpal_device,
                &base_config,
                sample_format,
                Arc::clone(&callback_queue),
            )
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!("failed to build audio stream: {e}"),
                )
            })?
        };

        stream.play().map_err(|e| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to start audio stream: {e}"),
            )
        })?;

        // Steam run instrumentation (no behavior change): the FIRST
        // successful real audio device initialization — a cpal output stream
        // was built AND started on a real device.  Never recorded for stubs
        // or failed opens (both error out above).
        crate::steam_milestones::note_audio_initialized(
            crate::steam_milestones::MilestoneEvidence::context_free(
                "RealAudioBackend::ensure_stream (cpal)",
                Some(&device.name),
                "real audio output stream opened on a host device",
            ),
        );

        // Record initial latency using the device's sample rate (the stream
        // runs at the device rate in shared mode, not necessarily the client
        // format's rate).
        let latency_ms = measure_latency_ms(
            device.sample_rate,
            match buffer_size {
                cpal::BufferSize::Default => 1024,
                cpal::BufferSize::Fixed(v) => v as usize,
            },
        );
        self.push_latency_record(LatencyRecord {
            subsystem: "real_audio".to_string(),
            device_id,
            measured_ms: latency_ms,
        });

        self.streams.insert(device_id, stream);
        self.stream_queues.insert(device_id, queue);
        Ok(())
    }

    /// Ensure a cpal output stream exists for the given device in exclusive mode.
    ///
    /// Unlike `ensure_stream`, this method uses `supported_output_configs()` to
    /// find a config that exactly matches the requested format (channels, sample
    /// rate, and sample format). It tries progressively larger buffer sizes
    /// (starting at 64 frames / ~1.3 ms) until the hardware accepts one.
    ///
    /// Returns the negotiated buffer size in frames.
    fn ensure_stream_exclusive(
        &mut self,
        device_id: DeviceId,
        format: &WaveFormat,
    ) -> AppResult<usize> {
        if let Some((stored_format, buffer_frames)) = self.exclusive_streams.get(&device_id) {
            if stored_format == format {
                // Same format as the existing exclusive stream: reuse it and
                // return the actually negotiated buffer size.
                return Ok(*buffer_frames);
            }
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!(
                    "exclusive-mode stream on device {device_id} is already open with format {} ch, {} Hz, {:?}; requested {} ch, {} Hz, {:?}",
                    stored_format.channels,
                    stored_format.sample_rate,
                    stored_format.sample_format,
                    format.channels,
                    format.sample_rate,
                    format.sample_format,
                ),
            ));
        }

        let cpal_device = self.find_cpal_device(device_id)?;

        // Enumerate supported output configs to find one matching our format
        let supported = cpal_device.supported_output_configs().map_err(|e| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to enumerate audio output configs: {e}"),
            )
        })?;

        let cpal_format = wave_format_to_cpal(format);

        let mut matched_range = None;
        for config in supported {
            if config.channels() == format.channels
                && config.sample_format() == cpal_format
                && format.sample_rate >= config.min_sample_rate().0
                && format.sample_rate <= config.max_sample_rate().0
            {
                matched_range = Some(config);
                break;
            }
        }

        let matched = matched_range.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!(
                    "no supported audio config matches {} channels, {} Hz, {:?}",
                    format.channels, format.sample_rate, format.sample_format
                ),
            )
        })?;

        // Pin to the exact sample rate requested.
        // cpal 0.15's with_sample_rate is infallible — it picks the closest
        // supported rate if the exact one is unavailable.
        let supported_config = matched.with_sample_rate(cpal::SampleRate(format.sample_rate));
        let sample_format = supported_config.sample_format();

        // Pre-allocate the queue to its maximum size (the exclusive stream
        // runs at the client format, so size from that).
        let max_samples = max_output_queue_samples(format.sample_rate, format.channels);
        let queue: Arc<Mutex<VecDeque<f32>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(max_samples)));

        // Try progressively larger buffer sizes (target ≤10ms latency).
        // 64 frames @ 48kHz ≈ 1.3ms, 512 frames @ 48kHz ≈ 10.7ms.
        let buffer_candidates: &[u32] = &[64, 96, 128, 160, 192, 256, 384, 512];
        let mut stream = None;
        let mut chosen_frames: usize = 256;

        for &frames in buffer_candidates {
            let mut stream_config = supported_config.config();
            stream_config.buffer_size = cpal::BufferSize::Fixed(frames);

            match build_output_stream(
                &cpal_device,
                &stream_config,
                sample_format,
                Arc::clone(&queue),
            ) {
                Ok(s) => {
                    stream = Some(s);
                    chosen_frames = frames as usize;
                    break;
                }
                Err(_) => {
                    // Try the next buffer size
                    continue;
                }
            }
        }

        let stream = stream.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                "failed to build exclusive-mode audio stream with any buffer size",
            )
        })?;

        stream.play().map_err(|e| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to start exclusive audio stream: {e}"),
            )
        })?;

        // Steam run instrumentation (no behavior change): the FIRST
        // successful real audio initialization in exclusive mode — a cpal
        // exclusive stream was built AND started on a real device.  Never
        // recorded for stubs or failed opens (both error out above).
        crate::steam_milestones::note_audio_initialized(
            crate::steam_milestones::MilestoneEvidence::context_free(
                "RealAudioBackend::ensure_stream_exclusive (cpal)",
                Some(&self.device_info(device_id)?.name),
                "real exclusive-mode audio stream opened on a host device",
            ),
        );

        self.streams.insert(device_id, stream);
        self.stream_queues.insert(device_id, queue);
        self.exclusive_streams
            .insert(device_id, (format.clone(), chosen_frames));

        Ok(chosen_frames)
    }

    /// Find the cpal device matching our internal device ID.
    fn find_cpal_device(&self, device_id: DeviceId) -> AppResult<cpal::Device> {
        let our_device = self.device_info(device_id)?;
        let devices = self.host.output_devices().map_err(|e| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to enumerate output devices: {e}"),
            )
        })?;

        for device in devices {
            // Match by the stable identity key first, then by display name as
            // a fallback for devices enumerated before keys were recorded.
            if cpal_device_key(&device) == our_device.key
                || device.name().map(|n| n == our_device.name).unwrap_or(false)
            {
                return Ok(device);
            }
        }

        // The device is gone: fail explicitly instead of silently routing
        // audio to whatever the default device happens to be.
        Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("audio device '{}' is no longer available", our_device.name),
        ))
    }

    // -----------------------------------------------------------------------
    // Input (capture) stream support
    // -----------------------------------------------------------------------

    /// Start an input (microphone/line-in) capture stream using cpal.
    ///
    /// Uses the default input device and the given sample rate / channel count.
    /// Captured f32 samples are appended to `self.capture_buffer`.
    pub fn start_input_stream(&mut self, sample_rate: u32, channels: u16) -> AppResult<()> {
        // Drop any existing input stream first
        self.input_stream = None;

        let input_device = self.host.default_input_device().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                "no default audio input device available",
            )
        })?;

        let supported_config = input_device.default_input_config().map_err(|e| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to get audio input config: {e}"),
            )
        })?;

        let capture_buf = Arc::clone(&self.capture_buffer);
        let error_callback = |error: cpal::StreamError| {
            eprintln!("[RealAudio] input stream error: {error}");
        };

        // Build stream config matching requested format
        let stream_config: cpal::StreamConfig = cpal::StreamConfig {
            channels,
            sample_rate: cpal::SampleRate(sample_rate),
            buffer_size: cpal::BufferSize::Default,
        };

        // Pre-reserve the capture buffer to its maximum size so the real-time
        // callback never allocates while appending.
        let max_samples = max_capture_samples(sample_rate, channels);
        if let Ok(mut buf) = self.capture_buffer.lock() {
            buf.reserve(max_samples);
        }

        let stream = match supported_config.sample_format() {
            cpal::SampleFormat::F32 => input_device
                .build_input_stream(
                    &stream_config,
                    move |data: &[f32], _: &cpal::InputCallbackInfo| {
                        // try_lock: never block the real-time audio thread.
                        // On contention the capture data is dropped rather than
                        // risking an audio-thread stall.
                        if let Ok(mut buf) = capture_buf.try_lock() {
                            append_capped(&mut buf, data, max_samples, |&s| s);
                        }
                    },
                    error_callback,
                    None,
                )
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcAudioUnsupported,
                        format!("failed to build f32 input stream: {e}"),
                    )
                })?,
            cpal::SampleFormat::I16 => input_device
                .build_input_stream(
                    &stream_config,
                    move |data: &[i16], _: &cpal::InputCallbackInfo| {
                        if let Ok(mut buf) = capture_buf.try_lock() {
                            // Convert i16 to f32 without per-sample push
                            append_capped(&mut buf, data, max_samples, |&s| {
                                if s == i16::MIN {
                                    -1.0
                                } else {
                                    s as f32 / i16::MAX as f32
                                }
                            });
                        }
                    },
                    error_callback,
                    None,
                )
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcAudioUnsupported,
                        format!("failed to build i16 input stream: {e}"),
                    )
                })?,
            cpal::SampleFormat::U16 => input_device
                .build_input_stream(
                    &stream_config,
                    move |data: &[u16], _: &cpal::InputCallbackInfo| {
                        if let Ok(mut buf) = capture_buf.try_lock() {
                            // Convert u16 to f32 without per-sample push
                            append_capped(&mut buf, data, max_samples, |&s| {
                                (s as f32 / u16::MAX as f32) * 2.0 - 1.0
                            });
                        }
                    },
                    error_callback,
                    None,
                )
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcAudioUnsupported,
                        format!("failed to build u16 input stream: {e}"),
                    )
                })?,
            other => {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!("unsupported host input sample format {other:?}"),
                ));
            }
        };

        stream.play().map_err(|e| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to start input stream: {e}"),
            )
        })?;

        self.input_stream = Some(stream);
        Ok(())
    }

    /// Stop the active input (capture) stream, if any.
    pub fn stop_input_stream(&mut self) {
        if let Some(stream) = self.input_stream.take() {
            eprintln!("[RealAudio] stopping input stream (drop will release resources)");
            drop(stream); // Dropping the stream stops it
        }
        if let Ok(mut buf) = self.capture_buffer.lock() {
            buf.clear();
        }
    }

    /// Read captured audio data from the internal buffer.
    ///
    /// Returns the captured f32 samples and clears the internal buffer.
    pub fn read_capture_data(&mut self) -> Vec<f32> {
        if let Ok(mut buf) = self.capture_buffer.lock() {
            buf.drain(..).collect()
        } else {
            Vec::new()
        }
    }

    /// Append samples to a device's output queue, keeping at most `max_samples`
    /// samples (dropping the oldest excess).
    ///
    /// Runs on the app thread, never on the real-time audio callback thread.
    /// The queue is pre-reserved to its maximum capacity at stream creation, so
    /// appending never reallocates while the lock is held.
    fn enqueue_samples(
        &self,
        device_id: DeviceId,
        samples: &[f32],
        max_samples: usize,
    ) -> AppResult<()> {
        let queue = self
            .stream_queues
            .get(&device_id)
            .ok_or_else(|| stream_not_open_error(device_id))?;
        let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
        append_capped(&mut q, samples, max_samples, |&s| s);
        Ok(())
    }

    /// Append a latency record, evicting the oldest entries once the log
    /// exceeds [`MAX_LATENCY_LOG_ENTRIES`].
    fn push_latency_record(&mut self, record: LatencyRecord) {
        self.latency_log.push(record);
        if self.latency_log.len() > MAX_LATENCY_LOG_ENTRIES {
            let excess = self.latency_log.len() - MAX_LATENCY_LOG_ENTRIES;
            self.latency_log.drain(0..excess);
        }
    }
}

/// Maximum number of queued output samples (~4 seconds of audio) for a stream
/// running at `rate` Hz with `channels` channels.
fn max_output_queue_samples(rate: u32, channels: u16) -> usize {
    (rate.max(1) as usize) * (channels.max(1) as usize) * 4
}

/// Maximum number of captured samples (~4 seconds of audio).
fn max_capture_samples(rate: u32, channels: u16) -> usize {
    max_output_queue_samples(rate, channels)
}

/// Append converted samples to `buf`, keeping only the newest `max_samples`
/// samples.
///
/// Never allocates when `buf` was pre-reserved for `max_samples` capacity:
/// old samples are dropped from the front (O(1) per pop) before appending, and
/// the incoming batch is truncated to the remaining room, so the buffer size
/// never exceeds its capacity. If a single batch alone exceeds the cap, its
/// oldest samples are dropped.
fn append_capped<T>(
    buf: &mut VecDeque<f32>,
    samples: &[T],
    max_samples: usize,
    convert: impl Fn(&T) -> f32,
) {
    if max_samples == 0 {
        buf.clear();
        return;
    }
    let drop = buf
        .len()
        .saturating_add(samples.len())
        .saturating_sub(max_samples);
    for _ in 0..drop.min(buf.len()) {
        buf.pop_front();
    }
    let room = max_samples.saturating_sub(buf.len());
    let take = samples.len().min(room);
    if take > 0 {
        buf.extend(samples[samples.len() - take..].iter().map(convert));
    }
}

/// Error returned when pushing samples to a stream that has been closed.
fn stream_not_open_error(device_id: DeviceId) -> AppError {
    AppError::new(
        ReasonCode::RcAudioUnsupported,
        format!("audio stream {device_id} is not open"),
    )
}

/// Stable identity key for a cpal device: `name|channels|sample_rate`.
///
/// cpal 0.15 exposes no device ID, so this tuple is the most stable identity
/// available: it keeps devices with identical display names but different
/// configs distinct, and preserves IDs across enumeration when the config
/// stays the same.
fn cpal_device_key(device: &cpal::Device) -> String {
    let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
    let config = device.default_output_config().ok();
    let channels = config.as_ref().map(|c| c.channels()).unwrap_or(2);
    let sample_rate = config.as_ref().map(|c| c.sample_rate().0).unwrap_or(48_000);
    format!("{name}|{channels}|{sample_rate}")
}

/// Build an output stream for the given config and sample format, sharing the
/// callback implementations between shared- and exclusive-mode streams.
fn build_output_stream(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    sample_format: cpal::SampleFormat,
    queue: Arc<Mutex<VecDeque<f32>>>,
) -> Result<cpal::Stream, cpal::BuildStreamError> {
    let error_callback = |error: cpal::StreamError| {
        eprintln!("[RealAudio] output stream error: {error}");
    };
    match sample_format {
        cpal::SampleFormat::F32 => device.build_output_stream(
            config,
            move |data: &mut [f32], _| fill_output_f32(data, &queue),
            error_callback,
            None,
        ),
        cpal::SampleFormat::I16 => device.build_output_stream(
            config,
            move |data: &mut [i16], _| fill_output_i16(data, &queue),
            error_callback,
            None,
        ),
        cpal::SampleFormat::U16 => device.build_output_stream(
            config,
            move |data: &mut [u16], _| fill_output_u16(data, &queue),
            error_callback,
            None,
        ),
        _ => Err(cpal::BuildStreamError::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Format conversion
// ---------------------------------------------------------------------------

/// Convert PCM16 samples to f32.
pub fn pcm16_to_float(samples: &[i16]) -> Vec<f32> {
    samples
        .iter()
        .map(|&s| {
            if s == i16::MIN {
                -1.0
            } else {
                s as f32 / i16::MAX as f32
            }
        })
        .collect()
}

/// Convert f32 samples to PCM16.
pub fn float_to_pcm16(samples: &[f32]) -> Vec<i16> {
    samples
        .iter()
        .map(|&s| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16)
        .collect()
}

/// Convert f32 samples to u8 (8-bit unsigned, centered at 128).
pub fn float_to_u8(samples: &[f32]) -> Vec<u8> {
    float_to_u8_pcm(samples)
}

/// Convert AudioSamples from the audio subsystem to f32.
pub fn convert_samples_to_float(samples: &crate::audio::AudioSamples) -> Vec<f32> {
    match samples {
        crate::audio::AudioSamples::Pcm16(values) => pcm16_to_float(values),
        crate::audio::AudioSamples::Float32(values) => values.clone(),
    }
}

/// Convert 8-bit unsigned PCM samples to f32.
///
/// 8-bit PCM uses unsigned representation with 128 as the centre (silence).
/// Range: 0..255 maps to -1.0..+1.0.
pub fn u8_to_float(samples: &[u8]) -> Vec<f32> {
    samples
        .iter()
        .map(|&s| (s as f32 - 128.0) / 128.0)
        .collect()
}

/// Convert f32 samples to 8-bit unsigned PCM.
pub fn float_to_u8_pcm(samples: &[f32]) -> Vec<u8> {
    samples
        .iter()
        .map(|&s| (((s.clamp(-1.0, 1.0) + 1.0) * 0.5) * 255.0) as u8)
        .collect()
}

/// Convert 24-bit PCM samples (packed in 3 bytes, little-endian) to f32.
///
/// 24-bit PCM uses signed two's complement in 3-byte containers.
/// Range: -8388608..8388607 maps to -1.0..+1.0.
pub fn pcm24_to_float(samples: &[u8]) -> Vec<f32> {
    samples
        .chunks_exact(3)
        .map(|chunk| {
            let b0 = chunk[0] as i32;
            let b1 = chunk[1] as i32;
            let b2 = chunk[2] as i32;
            // Little-endian 24-bit: assemble as i32 and sign-extend
            let value = b0 | (b1 << 8) | (b2 << 16);
            // Sign-extend from 24-bit to 32-bit via arithmetic shift
            let value = (value << 8) >> 8;
            value as f32 / 8388608.0
        })
        .collect()
}

/// Convert 24-bit PCM samples (in 4-byte containers, little-endian) to f32.
///
/// Some Windows audio formats store 24-bit samples in 32-bit containers
/// where the most significant byte is zero.
pub fn pcm24_in_32_to_float(samples: &[u8]) -> Vec<f32> {
    samples
        .chunks_exact(4)
        .map(|chunk| {
            let b0 = chunk[0] as i32;
            let b1 = chunk[1] as i32;
            let b2 = chunk[2] as i32;
            // chunk[3] is padding (zero)
            let value = b0 | (b1 << 8) | (b2 << 16);
            // Sign-extend from 24-bit via arithmetic shift
            let value = (value << 8) >> 8;
            value as f32 / 8388608.0
        })
        .collect()
}

/// Convert f32 samples to 24-bit PCM (packed 3 bytes, little-endian).
pub fn float_to_pcm24(samples: &[f32]) -> Vec<u8> {
    let mut output = Vec::with_capacity(samples.len() * 3);
    for &s in samples {
        let clamped = s.clamp(-1.0, 1.0);
        let value = (clamped * 8388608.0) as i32;
        let value = value.clamp(-8388608, 8388607);
        // Store as unsigned 24-bit LE
        let uval = value as u32 & 0xFFFFFF;
        output.push((uval & 0xFF) as u8);
        output.push(((uval >> 8) & 0xFF) as u8);
        output.push(((uval >> 16) & 0xFF) as u8);
    }
    output
}

/// Convert 32-bit signed integer PCM samples to f32.
///
/// Range: -2147483648..2147483647 maps to -1.0..+1.0.
pub fn pcm32_to_float(samples: &[i32]) -> Vec<f32> {
    samples
        .iter()
        .map(|&s| {
            if s == i32::MIN {
                -1.0
            } else {
                s as f32 / i32::MAX as f32
            }
        })
        .collect()
}

/// Convert f32 samples to 32-bit signed integer PCM.
pub fn float_to_pcm32(samples: &[f32]) -> Vec<i32> {
    samples
        .iter()
        .map(|&s| (s.clamp(-1.0, 1.0) * i32::MAX as f32) as i32)
        .collect()
}

/// Convert raw PCM bytes to f32 samples based on the wave format tag and
/// bits-per-sample.
///
/// Handles:
/// - `0x0001` (PCM): 8-bit unsigned, 16-bit signed, 24-bit (packed or in
///   32-bit containers), 32-bit signed
/// - `0x0003` (IEEE float): 32-bit float
///
/// Returns interleaved f32 samples in the range [-1.0, +1.0].
pub fn pcm_bytes_to_float(
    data: &[u8],
    wave_format_tag: u16,
    bits_per_sample: u16,
    _channels: u16,
) -> Vec<f32> {
    match wave_format_tag {
        0x0003 => {
            // IEEE float — 32-bit
            data.chunks_exact(4)
                .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect()
        }
        0x0001 => match bits_per_sample {
            8 => u8_to_float(data),
            16 => {
                let i16_samples: Vec<i16> = data
                    .chunks_exact(2)
                    .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                pcm16_to_float(&i16_samples)
            }
            24 => pcm24_to_float(data),
            32 => {
                let i32_samples: Vec<i32> = data
                    .chunks_exact(4)
                    .map(|chunk| i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect();
                pcm32_to_float(&i32_samples)
            }
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Convert f32 samples to raw PCM bytes based on the wave format tag and
/// bits-per-sample.
///
/// Inverse of [`pcm_bytes_to_float`].
pub fn float_to_pcm_bytes(samples: &[f32], wave_format_tag: u16, bits_per_sample: u16) -> Vec<u8> {
    match wave_format_tag {
        0x0003 => {
            // IEEE float — 32-bit
            let mut bytes = Vec::with_capacity(samples.len() * 4);
            for &s in samples {
                bytes.extend_from_slice(&s.to_le_bytes());
            }
            bytes
        }
        0x0001 => match bits_per_sample {
            8 => float_to_u8_pcm(samples),
            16 => {
                let i16_samples = float_to_pcm16(samples);
                let mut bytes = Vec::with_capacity(i16_samples.len() * 2);
                for s in i16_samples {
                    bytes.extend_from_slice(&s.to_le_bytes());
                }
                bytes
            }
            24 => float_to_pcm24(samples),
            32 => {
                let i32_samples = float_to_pcm32(samples);
                let mut bytes = Vec::with_capacity(i32_samples.len() * 4);
                for s in i32_samples {
                    bytes.extend_from_slice(&s.to_le_bytes());
                }
                bytes
            }
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Audio format detection
// ---------------------------------------------------------------------------

/// Identifies the audio encoding format of a raw data buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioFormat {
    /// 16-bit signed integer PCM.
    Pcm16,
    /// 24-bit signed integer PCM (in 32-bit containers).
    Pcm24,
    /// 32-bit signed integer PCM.
    Pcm32,
    /// 32-bit IEEE float PCM.
    Float32,
    /// Microsoft ADPCM (waveFormatTag 0x0002).
    MsAdpcm,
    /// IMA/DVI ADPCM (waveFormatTag 0x0011).
    ImaAdpcm,
    /// Xbox Media Audio (waveFormatTag 0x0165).
    Xma,
}

/// Detect the [`AudioFormat`] from a Windows wave format tag.
///
/// Standard tags:
/// - `0x0001` → PCM (check bits-per-sample for 16, 24, or 32)
/// - `0x0003` → IEEE float
/// - `0x0002` → Microsoft ADPCM
/// - `0x0011` → IMA ADPCM
/// - `0x0165` → XMA
///
/// Any unrecognised tag falls back to `Pcm16`.
pub fn detect_audio_format(wave_format_tag: u16, bits_per_sample: u16) -> AudioFormat {
    match wave_format_tag {
        0x0001 => match bits_per_sample {
            24 => AudioFormat::Pcm24,
            32 => AudioFormat::Pcm32,
            _ => AudioFormat::Pcm16,
        },
        0x0003 => AudioFormat::Float32,
        0x0002 => AudioFormat::MsAdpcm,
        0x0011 => AudioFormat::ImaAdpcm,
        0x0165 => AudioFormat::Xma,
        _ => AudioFormat::Pcm16,
    }
}

// ---------------------------------------------------------------------------
// ADPCM / XMA decoders
// ---------------------------------------------------------------------------

// ── MS ADPCM tables ──────────────────────────────────────────────────────────

/// Microsoft ADPCM predictor coefficient table (7 entries).
///
/// Each pair `(coeff1, coeff2)` is used for the linear prediction:
/// `predicted = (coeff1 * sample[n-2] + coeff2 * sample[n-1]) / 256`.
const MS_ADPCM_COEFFICIENTS: [(i16, i16); 7] = [
    (256, 0),
    (512, -256),
    (0, 0),
    (192, 64),
    (240, 0),
    (460, -208),
    (392, -232),
];

/// Microsoft ADPCM delta adaptation table (16 entries).
///
/// `delta[n] = (adaptation_table[nibble] * delta[n-1]) / 256`.
const MS_ADPCM_ADAPTATION: [i16; 16] = [
    230, 230, 230, 230, 307, 409, 512, 614, 768, 614, 512, 409, 307, 230, 230, 230,
];

/// Decode Microsoft ADPCM compressed audio to interleaved 16-bit PCM.
///
/// # Format
///
/// MS ADPCM is block-based. Each block contains a per-channel header followed
/// by packed 4-bit nibbles. The header for each channel is:
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0      | 2    | Predictor index (0–6) |
/// | 2      | 2    | Initial delta (≥ 16) |
/// | 4      | 2    | First decoded sample (sample₁) |
/// | 6      | 2    | Second decoded sample (sample₂) |
///
/// For stereo, headers for both channels appear first, then interleaved nibbles
/// (ch1 nibble, ch2 nibble, ch1 nibble, …).
///
/// Decoding per nibble:
///
/// ```text
/// coeff1, coeff2 = MS_ADPCM_COEFFICIENTS[predictor]
/// predicted = (coeff1 * sample[n-2] + coeff2 * sample[n-1]) / 256
/// signed_nibble = (nibble >= 8) ? (nibble as i32 - 16) : nibble as i32
/// sample = predicted + (delta * signed_nibble)
/// sample = clamp(sample, -32768, 32767)
/// delta = (adaptation_table[nibble] * delta) / 256
/// delta = max(delta, 16)
/// ```
///
/// # Parameters
///
/// * `adpcm_data` — Raw block data.
/// * `block_size` — Size of each block in bytes (including headers).
/// * `num_channels` — Number of audio channels (1 or 2).
/// * `samples_per_block` — Number of PCM samples **per channel** produced from
///   one block.
///
/// # Returns
///
/// Interleaved 16-bit PCM samples, one per channel per frame.
pub fn decode_ms_adpcm(
    adpcm_data: &[u8],
    block_size: u16,
    num_channels: u16,
    samples_per_block: u16,
) -> AppResult<Vec<i16>> {
    let num_channels = num_channels as usize;
    let block_size = block_size as usize;
    let samples_per_block = samples_per_block as usize;

    if num_channels != 1 && num_channels != 2 {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("MS ADPCM unsupported channel count: {num_channels}"),
        ));
    }

    if block_size < 8 {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("MS ADPCM block size too small: {block_size}"),
        ));
    }

    // Per-channel header: predictor(2) + delta(2) + sample1(2) + sample2(2) = 8 bytes
    let header_size = num_channels * 8;
    if block_size < header_size {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("MS ADPCM block size {block_size} < header size {header_size}"),
        ));
    }

    // Total number of blocks
    let num_blocks = if block_size > 0 {
        // Reject non-empty data that is smaller than one full block (truncated).
        if !adpcm_data.is_empty() && adpcm_data.len() < block_size {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "MS ADPCM data truncated: fewer bytes than one block",
            ));
        }
        adpcm_data.len() / block_size
    } else {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            "MS ADPCM block_size is zero",
        ));
    };

    let mut output = Vec::with_capacity(num_blocks * samples_per_block * num_channels);

    for block_idx in 0..num_blocks {
        let block_start = block_idx * block_size;
        let block_end = (block_start + block_size).min(adpcm_data.len());
        let block = &adpcm_data[block_start..block_end];

        // Parse per-channel headers and initialise decoder state
        let mut predictors = [0usize; 2];
        let mut deltas = [0i32; 2];
        let mut prev_samples = [[0i32; 2]; 2]; // [channel][0] = sample[n-2], [1] = sample[n-1]

        for ch in 0..num_channels {
            let hdr = ch * 8;
            if hdr + 8 > block.len() {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    "MS ADPCM block truncated",
                ));
            }
            let pred_idx = block[hdr] as usize | ((block[hdr + 1] as usize) << 8);
            if pred_idx >= 7 {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!("MS ADPCM invalid predictor index: {pred_idx}"),
                ));
            }
            predictors[ch] = pred_idx;
            deltas[ch] = (block[hdr + 2] as i32) | ((block[hdr + 3] as i32) << 8);
            if deltas[ch] < 16 {
                deltas[ch] = 16;
            }
            let s1 = (block[hdr + 4] as i32) | ((block[hdr + 5] as i32) << 8);
            let s2 = (block[hdr + 6] as i32) | ((block[hdr + 7] as i32) << 8);
            // sign-extend from i16
            let s1 = s1 as i16 as i32;
            let s2 = s2 as i16 as i32;
            prev_samples[ch][0] = s1; // sample[n-2] = first sample
            prev_samples[ch][1] = s2; // sample[n-1] = second sample
        }

        // Emit the two initial samples per channel
        for channel in prev_samples.iter().take(num_channels) {
            output.push(channel[0] as i16);
        }
        for channel in prev_samples.iter().take(num_channels) {
            output.push(channel[1] as i16);
        }

        // The compressed nibble data starts after headers
        let nibble_start = header_size;
        // Number of PCM samples per channel left to decode in this block
        let remaining = samples_per_block.saturating_sub(2);

        // For mono: all nibbles belong to channel 0 consecutively.
        // For stereo: nibbles are interleaved (ch1, ch2, ch1, ch2, …).
        let bytes_available = block.len().saturating_sub(nibble_start);
        let nibble_count = bytes_available * 2; // 2 nibbles per byte

        // Each iteration decodes exactly one sample for channel `i % num_channels`.
        // Every channel needs `remaining` samples, so the loop must run up to
        // `remaining * num_channels` iterations (or fewer if the block holds
        // fewer nibbles than that).
        let total_iterations = (remaining * num_channels).min(nibble_count);
        for i in 0..total_iterations {
            let ch = if num_channels == 2 {
                i % num_channels
            } else {
                0
            };

            // For stereo, nibbles are interleaved at the nibble level:
            // nibble 0 = ch1, nibble 1 = ch2, nibble 2 = ch1, nibble 3 = ch2, ...
            // The nibble position within the byte stream:
            let nibble_byte_offset: usize;
            let nibble_within_byte: usize;

            if num_channels == 2 {
                // Stereo: ch1 nibbles at even positions, ch2 at odd positions
                // The byte offset and which nibble within the byte depends on the
                // nibble position in the stream.
                // Pair (ch1_nibble, ch2_nibble) = one byte:
                //   low nibble = ch1, high nibble = ch2
                let nibble_pos = i;
                nibble_byte_offset = nibble_start + nibble_pos / 2;
                nibble_within_byte = nibble_pos % 2; // 0 = low nibble (ch1), 1 = high nibble (ch2)
            } else {
                // Mono: all nibbles are for channel 0 sequentially
                let nibble_pos = i;
                nibble_byte_offset = nibble_start + nibble_pos / 2;
                nibble_within_byte = nibble_pos % 2;
            }

            if nibble_byte_offset >= block.len() {
                break;
            }

            let byte_val = block[nibble_byte_offset];
            let nibble_val = if nibble_within_byte == 0 {
                byte_val & 0x0F
            } else {
                (byte_val >> 4) & 0x0F
            };

            // Decode nibble for this channel
            let coeff = MS_ADPCM_COEFFICIENTS[predictors[ch]];
            let coeff1 = coeff.0 as i32;
            let coeff2 = coeff.1 as i32;

            // Linear prediction from previous two samples
            let predicted = (coeff1 * prev_samples[ch][0] + coeff2 * prev_samples[ch][1]) / 256;

            // Signed nibble value (-8 .. 7)
            let signed_nibble = if nibble_val >= 8 {
                nibble_val as i32 - 16
            } else {
                nibble_val as i32
            };

            let mut new_sample = predicted + deltas[ch] * signed_nibble;

            // Clamp to i16 range
            new_sample = new_sample.clamp(i16::MIN as i32, i16::MAX as i32);

            // Update delta
            let adapt_idx = nibble_val as usize;
            if adapt_idx < 16 {
                deltas[ch] = (MS_ADPCM_ADAPTATION[adapt_idx] as i32 * deltas[ch]) / 256;
                if deltas[ch] < 16 {
                    deltas[ch] = 16;
                }
            }

            // Shift history
            prev_samples[ch][0] = prev_samples[ch][1];
            prev_samples[ch][1] = new_sample;

            output.push(new_sample as i16);
        }

        // If we didn't get enough samples per channel, pad with predicted
        // continuation so every block yields exactly `samples_per_block`
        // samples per channel.
        let decoded_per_ch = 2 + remaining.min(nibble_count / num_channels);
        if decoded_per_ch < samples_per_block {
            let pad = samples_per_block - decoded_per_ch;
            // For stereo, pad interleaved
            for _ in 0..pad {
                for ch in 0..num_channels {
                    let coeff = MS_ADPCM_COEFFICIENTS[predictors[ch]];
                    let predicted = (coeff.0 as i32 * prev_samples[ch][0]
                        + coeff.1 as i32 * prev_samples[ch][1])
                        / 256;
                    let sample = predicted.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                    prev_samples[ch][0] = prev_samples[ch][1];
                    prev_samples[ch][1] = sample as i32;
                    output.push(sample);
                }
            }
        }
    }

    Ok(output)
}

// ── IMA ADPCM tables ────────────────────────────────────────────────────────

/// IMA/DVI ADPCM step size table (89 entries).
///
/// Maps a step index (0–88) to a quantisation step size.
const IMA_ADPCM_STEP_TABLE: [i16; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];

/// IMA/DVI ADPCM step index table (16 entries).
///
/// Each 4-bit nibble maps to an index adjustment applied to the step index
/// after decoding a sample.
const IMA_ADPCM_INDEX_TABLE: [i16; 16] = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8];

/// Decode IMA/DVI ADPCM compressed audio to interleaved 16-bit PCM.
///
/// # Format
///
/// IMA ADPCM encodes audio as 4-bit nibbles with an adaptive step size.
/// The initial state for each channel is encoded in a 4-byte header:
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0      | 2    | Initial predictor (i16, little-endian) |
/// | 2      | 1    | Initial step index (0–88) |
/// | 3      | 1    | Reserved / padding |
///
/// For stereo, channels are stored sequentially within each block:
/// `[ch1_header(4B)][ch1_nibbles...][ch2_header(4B)][ch2_nibbles...]`.
///
/// Decoding per nibble:
///
/// ```text
/// step = IMA_ADPCM_STEP_TABLE[step_index]
/// delta = step >> 3
/// if nibble & 1: delta += step >> 2
/// if nibble & 2: delta += step >> 1
/// if nibble & 4: delta += step
/// if nibble & 8: delta = -delta
/// predictor = clamp(predictor + delta, -32768, 32767)
/// step_index = clamp(step_index + INDEX_TABLE[nibble], 0, 88)
/// ```
///
/// # Parameters
///
/// * `adpcm_data` — Raw block data.
/// * `num_channels` — Number of audio channels (1 or 2).
/// * `block_size` — Size of each block in bytes (including headers).
///
/// # Returns
///
/// Interleaved 16-bit PCM samples, one per channel per frame.
pub fn decode_ima_adpcm(
    adpcm_data: &[u8],
    num_channels: u16,
    block_size: u16,
) -> AppResult<Vec<i16>> {
    let num_channels = num_channels as usize;
    let block_size = block_size as usize;

    if num_channels != 1 && num_channels != 2 {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("IMA ADPCM unsupported channel count: {num_channels}"),
        ));
    }

    if block_size < 4 {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("IMA ADPCM block size too small: {block_size}"),
        ));
    }

    let header_size = 4; // per-channel: predictor(2) + step_index(1) + reserved(1)
    let per_channel_data_size = block_size / num_channels;

    if per_channel_data_size < header_size {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!(
                "IMA ADPCM per-channel data size {per_channel_data_size} < header {header_size}"
            ),
        ));
    }

    // Total number of blocks
    let num_blocks = adpcm_data.len().checked_div(block_size).unwrap_or(0);

    // Estimate output capacity: each byte produces 2 samples per channel (4-bit nibbles)
    let samples_per_block = (per_channel_data_size - header_size) * 2 + 1; // +1 for initial sample
    let mut output = Vec::with_capacity(num_blocks * samples_per_block * num_channels);

    for block_idx in 0..num_blocks {
        let block_start = block_idx * block_size;
        let block_end = (block_start + block_size).min(adpcm_data.len());
        let block = &adpcm_data[block_start..block_end];

        // Decode each channel independently
        let mut channel_samples: [Vec<i16>; 2] = [Vec::new(), Vec::new()];

        for (ch, channel_out) in channel_samples.iter_mut().take(num_channels).enumerate() {
            let ch_offset = ch * per_channel_data_size;

            if ch_offset + header_size > block.len() {
                continue;
            }

            // Parse header
            let predictor = (block[ch_offset] as i16) | ((block[ch_offset + 1] as i16) << 8);
            let mut step_index = block[ch_offset + 2] as i16;
            let mut predictor = predictor as i32;

            // Validate step index
            step_index = step_index.clamp(0, 88);

            // Emit initial sample
            let initial_sample = predictor.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            channel_out.push(initial_sample);

            // Decode nibbles
            let nibble_start = ch_offset + header_size;
            let nibble_end = (ch_offset + per_channel_data_size).min(block.len());

            for byte_idx in (nibble_start..nibble_end).step_by(1) {
                let byte_val = block[byte_idx];

                // Each byte contains two nibbles: low nibble first, then high nibble
                for nibble_shift in [0usize, 4usize] {
                    let nibble = (byte_val >> nibble_shift) & 0x0F;
                    let step = IMA_ADPCM_STEP_TABLE[step_index as usize] as i32;

                    // Compute delta from nibble
                    let mut delta = step >> 3;
                    if nibble & 1 != 0 {
                        delta += step >> 2;
                    }
                    if nibble & 2 != 0 {
                        delta += step >> 1;
                    }
                    if nibble & 4 != 0 {
                        delta += step;
                    }
                    if nibble & 8 != 0 {
                        delta = -delta;
                    }

                    predictor += delta;
                    predictor = predictor.clamp(i16::MIN as i32, i16::MAX as i32);

                    let sample = predictor as i16;
                    channel_out.push(sample);

                    // Update step index
                    step_index = (step_index + IMA_ADPCM_INDEX_TABLE[nibble as usize]).clamp(0, 88);
                }
            }
        }

        // Interleave channels into output
        let max_frames = channel_samples[0].len().max(channel_samples[1].len());
        for frame in 0..max_frames {
            for samples in channel_samples.iter().take(num_channels) {
                if frame < samples.len() {
                    output.push(samples[frame]);
                } else {
                    // Pad with last sample if channels are uneven
                    output.push(samples.last().copied().unwrap_or(0));
                }
            }
        }
    }

    Ok(output)
}

// ── XMA decoder ─────────────────────────────────────────────────────────────

/// XMA frame header size in bytes.
const XMA_FRAME_HEADER_SIZE: usize = 4;

/// XMA frame size in samples (256 samples per frame, 50% overlap).
const XMA_FRAME_SAMPLES: usize = 256;

/// Decode Xbox Media Audio (XMA) to interleaved 16-bit PCM.
///
/// # Format
///
/// XMA is a variant of the WMA lossless codec used in Xbox 360 titles.  It
/// uses an MDCT-based transform with overlapping windows (256-sample frames,
/// 50% overlap).  Each frame consists of a 4-byte header followed by packed
/// quantised MDCT coefficient subframes.
///
/// **Frame header (4 bytes, big-endian on Xbox 360):**
///
/// | Bit(s) | Field |
/// |--------|-------|
/// | 31:24  | Number of subframes in this frame |
/// | 23:16  | Quantisation scale index |
/// | 15:8   | Reserved |
/// | 7:0    | Flags |
///
/// **Subframe structure:**
///
/// Each subframe contains `256` frequency-domain MDCT coefficients, each
/// quantised to a variable number of bits (signalled in the subframe header).
///
/// # Parameters
///
/// * `xma_data` — Raw XMA bitstream data (may be big-endian byte-swapped).
/// * `num_channels` — Number of audio channels (1 or 2).
///
/// # Returns
///
/// Interleaved 16-bit PCM samples.
///
/// # Errors
///
/// Returns `RcAudioUnsupported` if the data is empty, the channel count is
/// unsupported, or a parsing error occurs.
pub fn decode_xma(xma_data: &[u8], num_channels: u16) -> AppResult<Vec<i16>> {
    let num_channels = num_channels as usize;

    if xma_data.is_empty() {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            "XMA data is empty",
        ));
    }

    if num_channels != 1 && num_channels != 2 {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("XMA unsupported channel count: {num_channels}"),
        ));
    }

    // Detect byte-swapped (Xbox 360 big-endian) format.
    // Xbox 360 XMA stores data in big-endian byte order; PC XMA2 is little-endian.
    // We detect byte-swapped format by checking if the first frame header
    // makes more sense in big-endian (non-zero subframes, reasonable quant scale).
    let is_big_endian = if xma_data.len() >= 4 {
        // Parse the full 4-byte header as both LE and BE to determine byte order.
        let first_four: [u8; 4] = [xma_data[0], xma_data[1], xma_data[2], xma_data[3]];
        let le_header = u32::from_le_bytes(first_four);
        let be_header = u32::from_be_bytes(first_four);
        let le_subframes = ((le_header >> 24) & 0xFF) as u8;
        let be_subframes = ((be_header >> 24) & 0xFF) as u8;
        // If the big-endian interpretation gives a valid subframe count while
        // the little-endian interpretation does not, assume byte-swapped data.
        be_subframes > 0 && be_subframes <= 16 && !(le_subframes > 0 && le_subframes <= 16)
    } else {
        false
    };

    // For byte-swapped data, swap every four bytes (32-bit word reversal).
    let data: Vec<u8> = if is_big_endian {
        xma_data
            .chunks(4)
            .flat_map(|quad| {
                if quad.len() == 4 {
                    vec![quad[3], quad[2], quad[1], quad[0]]
                } else {
                    quad.to_vec()
                }
            })
            .collect()
    } else {
        xma_data.to_vec()
    };

    // State for overlap-add: per-channel second half of the previous frame.
    let mut prev_frame = [[0.0f32; XMA_FRAME_SAMPLES]; 2];
    let mut output = Vec::new();

    let mut offset = 0;
    let mut frame_index = 0usize;

    while offset + XMA_FRAME_HEADER_SIZE <= data.len() {
        // Parse 4-byte frame header (now little-endian)
        let frame_header_bytes = &data[offset..offset + XMA_FRAME_HEADER_SIZE];
        let frame_header = u32::from_le_bytes([
            frame_header_bytes[0],
            frame_header_bytes[1],
            frame_header_bytes[2],
            frame_header_bytes[3],
        ]);

        let num_subframes = ((frame_header >> 24) & 0xFF) as usize;
        let quant_scale = ((frame_header >> 16) & 0xFF) as usize;
        let _reserved = ((frame_header >> 8) & 0xFF) as usize;
        let _flags = (frame_header & 0xFF) as usize;

        offset += XMA_FRAME_HEADER_SIZE;

        if num_subframes == 0 || num_subframes > 16 {
            // Invalid or padding frame — advance to next frame boundary
            // (XMA frames are aligned to 2048 bytes on Xbox 360, but we
            //  just treat it as end-of-stream for our first-pass decoder)
            break;
        }

        // Decode each subframe's quantised MDCT coefficients into per-channel
        // time-domain samples. A zero quantisation scale marks a silent frame:
        // the buffers stay zero and the frame flows through the same
        // overlap-add state machine below, so mixed silent/non-silent streams
        // keep consistent length and overlap state.
        let mut channel_time = [[0.0f32; XMA_FRAME_SAMPLES]; 2];
        if quant_scale != 0 {
            for channel in channel_time
                .iter_mut()
                .take(num_channels.min(num_subframes))
            {
                // The subframe data contains quantised coefficients.
                // We approximate the bit allocation: each coefficient gets
                // a number of bits proportional to the quant_scale.
                // For simplicity, we treat quant_scale as the number of bits
                // per coefficient (clamped to a reasonable range).
                let bits_per_coeff = quant_scale.clamp(2, 16);
                let bytes_per_coeff = bits_per_coeff.div_ceil(8);
                let subframe_size = XMA_FRAME_SAMPLES * bytes_per_coeff;

                let sf_end = (offset + subframe_size).min(data.len());
                let sf_data = &data[offset..sf_end];

                // Dequantise coefficients from the byte stream.
                // We read bytes_per_coeff bytes per coefficient and treat them
                // as a signed integer, then scale by the quantisation step.
                let quant_step = 1.0f32 / (1u32 << (bits_per_coeff - 1)) as f32;

                let mut mdct_coeffs = [0.0f32; XMA_FRAME_SAMPLES];
                let coeff_count = XMA_FRAME_SAMPLES.min(sf_data.len() / bytes_per_coeff);
                for (i, coeff) in mdct_coeffs.iter_mut().take(coeff_count).enumerate() {
                    let byte_start = i * bytes_per_coeff;
                    let byte_end = (byte_start + bytes_per_coeff).min(sf_data.len());
                    let mut raw_val: i32 = 0;
                    for (j, &b) in sf_data[byte_start..byte_end].iter().enumerate() {
                        raw_val |= (b as i32) << (j * 8);
                    }

                    // Sign-extend based on bits_per_coeff
                    let sign_bit = 1 << (bits_per_coeff - 1);
                    if raw_val & sign_bit != 0 {
                        raw_val |= !((1 << bits_per_coeff) - 1);
                    }

                    *coeff = raw_val as f32 * quant_step;
                }

                offset += subframe_size;

                // Apply inverse MDCT to get time-domain samples
                imdct_into(&mdct_coeffs, channel);
            }
        }

        // Overlap-add with the previous frame, emitting frame-major
        // interleaved PCM (the documented output order).
        let half_frame = XMA_FRAME_SAMPLES / 2;
        if frame_index > 0 {
            for i in 0..half_frame {
                for sf in 0..num_channels {
                    let out_sample = channel_time[sf][i] + prev_frame[sf][i];
                    let clamped = out_sample.clamp(-1.0, 1.0);
                    let pcm = if clamped <= -1.0 {
                        i16::MIN
                    } else {
                        (clamped * i16::MAX as f32) as i16
                    };
                    output.push(pcm);
                }
            }
        }

        // Store the second half for the next frame's overlap
        for sf in 0..num_channels {
            prev_frame[sf][..half_frame].copy_from_slice(&channel_time[sf][half_frame..]);
        }

        frame_index += 1;
    }

    // Flush remaining overlap samples (last half-frame), frame-major
    // interleaved to match the frames above.
    if frame_index > 0 {
        let half_frame = XMA_FRAME_SAMPLES / 2;
        for out_idx in 0..half_frame * num_channels {
            let i = out_idx / num_channels;
            let sf = out_idx % num_channels;
            let clamped = prev_frame[sf][i].clamp(-1.0, 1.0);
            let pcm = if clamped <= -1.0 {
                i16::MIN
            } else {
                (clamped * i16::MAX as f32) as i16
            };
            output.push(pcm);
        }
    }

    if output.is_empty() {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            "XMA decoder produced no output",
        ));
    }

    Ok(output)
}

// ── IMDCT helper ─────────────────────────────────────────────────────────

/// Apply an inverse Modified Discrete Cosine Transform (IMDCT) to a frame of
/// spectral coefficients.
///
/// This implementation uses a Type-IV DCT (DCT-IV) on `N/2` points followed
/// by windowing, which is equivalent to the standard MDCT factorisation for
/// `N = 256` samples.
///
/// The transform takes `N/2` spectral coefficients and produces `N` time-domain
/// samples (with 50% overlap, the output is windowed for overlap-add).
///
/// The cosine matrix and window are precomputed once and shared, so decoding
/// does not evaluate transcendental functions per sample or per subframe.
fn imdct(coefficients: &[f32]) -> Vec<f32> {
    let mut time = vec![0.0f32; XMA_FRAME_SAMPLES];
    imdct_into(coefficients, &mut time);
    time
}

/// Precomputed IMDCT kernel: `matrix[i * half_n + k]` is
/// `cos(pi/N * (i + 0.5 + N/2) * (k + 0.5)) * window[i] * scale`, so each
/// output sample is a plain dot product of coefficients with one matrix row.
static IMDCT_COS_MATRIX: OnceLock<Box<[f32]>> = OnceLock::new();

fn imdct_matrix() -> &'static [f32] {
    IMDCT_COS_MATRIX.get_or_init(|| {
        let n = XMA_FRAME_SAMPLES;
        let half_n = n / 2;
        let pi_over_n = std::f32::consts::PI / n as f32;
        let scale = 2.0 / n as f32;
        let mut matrix = Vec::with_capacity(n * half_n);
        for i in 0..n {
            // Sine window (standard for MDCT-based codecs) folded with the
            // output scale into the matrix row.
            let window = (std::f32::consts::PI * (i as f32 + 0.5) / n as f32).sin() * scale;
            for k in 0..half_n {
                let angle = pi_over_n * (i as f32 + 0.5 + half_n as f32) * (k as f32 + 0.5);
                matrix.push(angle.cos() * window);
            }
        }
        matrix.into_boxed_slice()
    })
}

/// Inverse MDCT writing into a caller-provided buffer (no allocation).
fn imdct_into(coefficients: &[f32], time: &mut [f32]) {
    let half_n = XMA_FRAME_SAMPLES / 2;
    let matrix = imdct_matrix();
    for (i, out) in time.iter_mut().enumerate() {
        let row = &matrix[i * half_n..(i + 1) * half_n];
        let mut sum = 0.0f32;
        for (k, &coeff) in coefficients.iter().take(half_n).enumerate() {
            sum += coeff * row[k];
        }
        *out = sum;
    }
}

// ---------------------------------------------------------------------------
// Convenience: decode any format to f32
// ---------------------------------------------------------------------------

/// Decode any supported audio format to interleaved f32 samples.
///
/// This is the primary entry point for games to convert raw audio data
/// (potentially compressed in ADPCM or XMA formats) into the floating-point
/// format used internally by Casa1's audio pipeline.
///
/// # Parameters
///
/// * `data` — Raw encoded audio bytes.
/// * `format` — The [`AudioFormat`] identifying the encoding.
/// * `num_channels` — Number of audio channels.
/// * `sample_rate` — Sample rate in Hz (unused here, passed for API consistency).
/// * `block_size` — Block size in bytes (used by ADPCM decoders).
/// * `samples_per_block` — Samples per block per channel (used by MS ADPCM).
///
/// # Returns
///
/// Interleaved f32 samples in the range [-1.0, 1.0].
pub fn convert_game_audio_to_float(
    data: &[u8],
    format: AudioFormat,
    num_channels: u16,
    _sample_rate: u32,
    block_size: u16,
    samples_per_block: u16,
) -> AppResult<Vec<f32>> {
    match format {
        AudioFormat::Pcm16 => {
            // Interpret data as raw i16 samples
            let sample_count = data.len() / 2;
            let mut pcm = Vec::with_capacity(sample_count);
            for chunk in data.chunks(2) {
                if chunk.len() == 2 {
                    let sample = i16::from_le_bytes([chunk[0], chunk[1]]);
                    pcm.push(sample);
                }
            }
            Ok(pcm16_to_float(&pcm))
        }
        AudioFormat::Pcm24 => {
            // 24-bit samples stored in 3 bytes (little-endian), sign-extended
            let sample_count = data.len() / 3;
            let mut pcm = Vec::with_capacity(sample_count);
            for chunk in data.chunks(3) {
                if chunk.len() == 3 {
                    let raw =
                        (chunk[0] as i32) | ((chunk[1] as i32) << 8) | ((chunk[2] as i32) << 16);
                    // Sign-extend from 24 bits
                    let sample = if raw & 0x800000 != 0 {
                        raw | !0xFFFFFF
                    } else {
                        raw
                    };
                    // Scale to [-1.0, 1.0] using the 24-bit range
                    let float_val = if sample == -0x800000 {
                        -1.0
                    } else {
                        sample as f32 / 0x7FFFFF as f32
                    };
                    pcm.push(float_val);
                }
            }
            Ok(pcm)
        }
        AudioFormat::Pcm32 => {
            let sample_count = data.len() / 4;
            let mut pcm = Vec::with_capacity(sample_count);
            for chunk in data.chunks(4) {
                if chunk.len() == 4 {
                    let sample = i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let float_val = if sample == i32::MIN {
                        -1.0
                    } else {
                        sample as f32 / i32::MAX as f32
                    };
                    pcm.push(float_val);
                }
            }
            Ok(pcm)
        }
        AudioFormat::Float32 => {
            let sample_count = data.len() / 4;
            let mut float_samples = Vec::with_capacity(sample_count);
            for chunk in data.chunks(4) {
                if chunk.len() == 4 {
                    float_samples
                        .push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                }
            }
            Ok(float_samples)
        }
        AudioFormat::MsAdpcm => {
            let pcm = decode_ms_adpcm(data, block_size, num_channels, samples_per_block)?;
            Ok(pcm16_to_float(&pcm))
        }
        AudioFormat::ImaAdpcm => {
            let pcm = decode_ima_adpcm(data, num_channels, block_size)?;
            Ok(pcm16_to_float(&pcm))
        }
        AudioFormat::Xma => {
            let pcm = decode_xma(data, num_channels)?;
            Ok(pcm16_to_float(&pcm))
        }
    }
}

// ---------------------------------------------------------------------------
// Sample rate conversion
// ---------------------------------------------------------------------------

/// Convert and resample interleaved audio from source format to device format.
///
/// Uses linear interpolation for sample rate conversion and channel
/// remapping for channel count mismatch.
pub fn convert_and_resample(
    samples: &[f32],
    source_channels: u16,
    source_rate: u32,
    dest_channels: u16,
    dest_rate: u32,
) -> Vec<f32> {
    let source_channels = source_channels.max(1) as usize;
    let dest_channels = dest_channels.max(1) as usize;

    if samples.is_empty() || source_rate == 0 || dest_rate == 0 {
        return Vec::new();
    }

    // Drop any trailing partial frame so the sample count is an exact multiple
    // of the channel count; a caller submitting an odd/partial sample count
    // must not crash the process.
    let usable_samples = samples.len() - samples.len() % source_channels;
    let usable = &samples[..usable_samples];

    let source_frames = usable_samples / source_channels;
    if source_frames == 0 {
        return Vec::new();
    }

    // Step 1: Resample (frame count changes)
    let dest_frames = if source_rate == dest_rate {
        source_frames
    } else {
        ((source_frames as u64 * dest_rate as u64) / source_rate as u64).max(1) as usize
    };

    let mut resampled = vec![0.0f32; dest_frames * source_channels];

    if source_rate == dest_rate {
        resampled.copy_from_slice(usable);
    } else {
        // Linear interpolation resampling
        for frame in 0..dest_frames {
            let source_pos = (frame as f64 * source_rate as f64) / dest_rate as f64;
            let frame0 = (source_pos as usize).min(source_frames - 1);
            let frame1 = (frame0 + 1).min(source_frames - 1);
            let frac = source_pos - frame0 as f64;

            for ch in 0..source_channels {
                let s0 = usable[frame0 * source_channels + ch];
                let s1 = usable[frame1 * source_channels + ch];
                resampled[frame * source_channels + ch] = s0 + (s1 - s0) * frac as f32;
            }
        }
    }

    // Step 2: Channel remap
    if source_channels == dest_channels {
        return resampled;
    }

    let mut output = vec![0.0f32; dest_frames * dest_channels];
    for frame in 0..dest_frames {
        let src = &resampled[frame * source_channels..(frame + 1) * source_channels];
        for ch in 0..dest_channels {
            output[frame * dest_channels + ch] = remap_channel(src, ch, dest_channels);
        }
    }

    output
}

/// Remap a single output channel from source channels.
///
/// Standard channel orderings:
///   Stereo (2):       FL, FR
///   5.1 (6):          FL, FR, FC, LFE, RL, RR
///   7.1 (8):          FL, FR, FC, LFE, RL, RR, SL, SR
///   Quad (4):         FL, FR, RL, RR
fn remap_channel(source: &[f32], channel: usize, output_channels: usize) -> f32 {
    match (source.len(), output_channels) {
        (1, _) => source[0],
        (2, 1) => (source[0] + source[1]) * 0.5,
        // 2 ch → 5.1: duplicate stereo to front, silence others
        // LFE (channel 3) uses 0.0 since there is no low-frequency content
        // in a pure stereo source.
        (2, 6) => match channel {
            0 | 2 => source[0], // FL, FC ← FL
            1 => source[1],     // FR ← FR
            3 => 0.0,           // LFE ← 0 (no LFE content in stereo source)
            _ => 0.0,           // RL, RR silent
        },
        // 2 ch → 7.1
        (2, 8) => match channel {
            0 | 2 => source[0],
            1 | 3 => source[1],
            _ => 0.0,
        },
        (2, _) => source[channel.min(1)],
        // Mono from multi-channel: downmix all
        (_, 1) => source.iter().copied().sum::<f32>() / source.len() as f32,
        // 5.1 source (6 ch) → 2 ch stereo: FL+FC, FR+FC with LFE mixed in
        (6, 2) => match channel {
            0 => source[0] + source[2] * 0.5 + source[3] * 0.3, // FL ← FL + 0.5*FC + 0.3*LFE
            1 => source[1] + source[2] * 0.5 + source[3] * 0.3, // FR ← FR + 0.5*FC + 0.3*LFE
            _ => 0.0,
        },
        // 7.1 source (8 ch) → 2 ch stereo
        (8, 2) => match channel {
            0 => source[0] + source[2] * 0.5 + source[3] * 0.3, // FL
            1 => source[1] + source[2] * 0.5 + source[3] * 0.3, // FR
            _ => 0.0,
        },
        // 5.1 source → 5.1 output: pass through
        (6, 6) => source[channel],
        // 7.1 source → 7.1 output: pass through
        (8, 8) => source[channel],
        // 5.1 → 7.1: SL/SR are copied from RL/RR
        (6, 8) => match channel {
            0..=3 => source[channel],
            4 | 6 => source[4], // RL → RL, SL → RL
            5 | 7 => source[5], // RR → RR, SR → RR
            _ => 0.0,
        },
        // 7.1 → 5.1: mix SL into RL, SR into RR
        (8, 6) => match channel {
            0..=3 => source[channel],
            4 => (source[4] + source[6]) * 0.5, // RL ← (RL + SL) * 0.5
            5 => (source[5] + source[7]) * 0.5, // RR ← (RR + SR) * 0.5
            _ => 0.0,
        },
        // Fallback: direct channel or silence
        _ => source.get(channel).copied().unwrap_or(0.0),
    }
}

// ---------------------------------------------------------------------------
// DSP effects
// ---------------------------------------------------------------------------

/// Apply a simple reverb effect to interleaved audio samples.
///
/// Uses a basic feedback delay with configurable wet/dry mix.
/// `delay_frames` controls the reverb tail length in frames.
/// `feedback` controls the reverb intensity (0.0 to 1.0).
pub fn apply_reverb_dsp(
    samples: &mut [f32],
    channels: usize,
    wet: f32,
    delay_frames: usize,
    feedback: f32,
) {
    if delay_frames == 0 || wet <= 0.0 || channels == 0 {
        return;
    }

    let total_frames = samples.len() / channels;
    let _delay_samples = delay_frames * channels;
    let feedback = feedback.clamp(0.0, 0.95);

    // Simple feedback delay: for each frame past the delay, add the delayed
    // sample scaled by wet * feedback
    for frame in delay_frames..total_frames {
        for ch in 0..channels {
            let idx = frame * channels + ch;
            let delayed_idx = (frame - delay_frames) * channels + ch;
            samples[idx] += samples[delayed_idx] * wet * feedback;
        }
    }
}

/// Apply a low-pass filter to interleaved audio samples.
///
/// Simple one-pole IIR low-pass filter. `cutoff` ranges from 0.0 (fully
/// filtered) to 1.0 (no filtering).
pub fn apply_lowpass(samples: &mut [f32], channels: usize, cutoff: f32) {
    if cutoff >= 1.0 || channels == 0 {
        return;
    }
    let alpha = cutoff.clamp(0.0, 1.0);
    let mut previous = vec![0.0f32; channels];

    for frame in 0..samples.len() / channels {
        let base = frame * channels;
        for (ch, prev) in previous.iter_mut().enumerate() {
            let idx = base + ch;
            *prev = *prev + alpha * (samples[idx] - *prev);
            samples[idx] = *prev;
        }
    }
}

/// Normalize audio samples to use the full dynamic range.
pub fn normalize_samples(samples: &mut [f32]) {
    let max_abs = samples.iter().map(|s| s.abs()).fold(0.0f32, f32::max);

    if max_abs > 0.0 && max_abs < 1.0 {
        let scale = 1.0 / max_abs;
        for sample in samples.iter_mut() {
            *sample *= scale;
        }
    }
}

/// Mix multiple audio streams together (sum in-place).
pub fn mix_streams(destination: &mut [f32], source: &[f32]) {
    for (dst, src) in destination.iter_mut().zip(source.iter()) {
        *dst += *src;
    }
}

// ---------------------------------------------------------------------------
// XAPO Audio Effects Processing — COM-style interface
// ---------------------------------------------------------------------------

// ── XAPO GUIDs ─────────────────────────────────────────────────────────────

/// CLSID_XAPO: {5EC3B1C3-5E4B-4f4e-B0E0-7B7D1E7B9E7C}
pub const CLSID_XAPO: [u8; 16] = [
    0xC3, 0xB1, 0xC3, 0x5E, 0x4B, 0x5E, 0x4E, 0x4F, 0xB0, 0xE0, 0x7B, 0x7D, 0x1E, 0x7B, 0x9E, 0x7C,
];

/// IID_IXAPO: {A1109C34-E46B-47c7-8E0F-7B7D1E7B9E7C}
pub const IID_IXAPO: [u8; 16] = [
    0x34, 0x9C, 0x10, 0xA1, 0x6B, 0xE4, 0xC7, 0x47, 0x8E, 0x0F, 0x7B, 0x7D, 0x1E, 0x7B, 0x9E, 0x7C,
];

/// IID_IXAPOParameters: {A1109C35-E46B-47c7-8E0F-7B7D1E7B9E7D}
pub const IID_IXAPOParameters: [u8; 16] = [
    0x35, 0x9C, 0x10, 0xA1, 0x6B, 0xE4, 0xC7, 0x47, 0x8E, 0x0F, 0x7B, 0x7D, 0x1E, 0x7B, 0x9E, 0x7D,
];

// ── XAPO flags ──────────────────────────────────────────────────────────────

/// XAPO effect flag: effect can process in-place (input == output buffer).
pub const XAPO_FLAG_INPLACE: u32 = 0x0001;
/// XAPO effect flag: input and output buffer counts must be equal.
pub const XAPO_FLAG_BUFFERCOUNT_MUST_EQUAL: u32 = 0x0004;

/// XAPO buffer flag: buffer contains silence.
pub const XAPO_BUFFER_SILENT: u32 = 0x0001;
/// XAPO buffer flag: buffer contains valid audio data.
pub const XAPO_BUFFER_VALID: u32 = 0x0002;

// ── XAPO_REGISTRATION_PROPERTIES ────────────────────────────────────────────

/// COM-style registration properties for an XAPO audio effect.
///
/// This struct matches the Windows `XAPO_REGISTRATION_PROPERTIES` layout
/// and can be written directly into guest memory for COM introspection.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct XAPO_REGISTRATION_PROPERTIES {
    /// CLSID identifying the effect type.
    pub clsid: [u8; 16],
    /// Human-readable friendly name (UTF-16, null-terminated).
    pub friendly_name: [u16; 256],
    /// Copyright/licensing info (UTF-16, null-terminated).
    pub copyright_info: [u16; 256],
    /// Major version number.
    pub major_version: u32,
    /// Minor version number.
    pub minor_version: u32,
    /// Capability flags (XAPO_FLAG_*).
    pub flags: u32,
    /// Minimum number of input buffers supported.
    pub min_input_buffer_count: u32,
    /// Maximum number of input buffers supported.
    pub max_input_buffer_count: u32,
    /// Minimum number of output buffers supported.
    pub min_output_buffer_count: u32,
    /// Maximum number of output buffers supported.
    pub max_output_buffer_count: u32,
}

impl XAPO_REGISTRATION_PROPERTIES {
    /// Create a new registration properties value with defaults.
    pub fn new(clsid: [u8; 16], friendly_name: &str, flags: u32) -> Self {
        let mut fn_buf = [0u16; 256];
        let fn_chars: Vec<u16> = friendly_name.encode_utf16().take(255).collect();
        fn_buf[..fn_chars.len()].copy_from_slice(&fn_chars);
        let mut ci_buf = [0u16; 256];
        let ci_str = "Casa1 XAPO Effect";
        let ci_chars: Vec<u16> = ci_str.encode_utf16().take(255).collect();
        ci_buf[..ci_chars.len()].copy_from_slice(&ci_chars);
        Self {
            clsid,
            friendly_name: fn_buf,
            copyright_info: ci_buf,
            major_version: 1,
            minor_version: 0,
            flags,
            min_input_buffer_count: 1,
            max_input_buffer_count: 1,
            min_output_buffer_count: 1,
            max_output_buffer_count: 1,
        }
    }
}

// ── XAPO_BUFFER ──────────────────────────────────────────────────────────────

/// COM-style audio buffer descriptor used by XAPO::Process.
///
/// Matches the Windows `XAPO_BUFFER` layout.
///
/// # Safety
///
/// `buffer` points into guest (emulated Windows) memory. The pointed-to audio
/// data must stay mapped and valid for the duration of the XAPO `process`
/// call; descriptors must not outlive the guest buffer they reference.
/// This type is intentionally neither `Clone` (which would duplicate the raw
/// pointer) nor `Send`/`Sync` (sharing it across threads is unsafe).
#[repr(C)]
#[derive(Debug)]
pub struct XAPO_BUFFER {
    /// Pointer to interleaved float audio samples in guest memory.
    pub buffer: *const f32,
    /// Buffer flags (XAPO_BUFFER_SILENT | XAPO_BUFFER_VALID).
    pub flags: u32,
    /// Number of valid audio frames in the buffer.
    pub valid_frame_count: u32,
}

// ---------------------------------------------------------------------------
// XapoEffect trait
// ---------------------------------------------------------------------------

/// Trait implemented by all XAPO audio effects.
///
/// Effects process interleaved float audio buffers, can be reset, and expose
/// their registration properties for COM introspection. Each effect stores its
/// own channel count, sample rate, and processing state internally.
pub trait XapoEffect: Send {
    /// Process audio data.
    ///
    /// `input` and `output` are interleaved float buffers. For in-place effects
    /// (`XAPO_FLAG_INPLACE`), `input` and `output` may point to the same buffer.
    ///
    /// The effect determines the frame count from `input.len() / self.channels()`
    /// and the channel count from its internal configuration. Returns `Ok(())`
    /// on success, or an error if buffer sizes are incompatible.
    fn process(&mut self, input: &[f32], output: &mut [f32]) -> AppResult<()>;

    /// Reset the effect to its initial state (clear delay lines, envelopes, etc.).
    fn reset(&mut self);

    /// Return a reference to the effect's COM-style registration properties.
    fn registration(&self) -> &XAPO_REGISTRATION_PROPERTIES;

    /// Return the number of audio channels this effect is configured for.
    fn channels(&self) -> u16;

    /// Return the sample rate this effect is configured for.
    fn sample_rate(&self) -> u32;
}

// ---------------------------------------------------------------------------
// Built-in XAPO effects
// ---------------------------------------------------------------------------

/// Schroeder reverb effect.
///
/// Uses 4 parallel comb filters feeding 2 series all-pass filters. This
/// classic DSP design produces a dense, natural-sounding reverb tail.
pub struct XapoReverb {
    /// Wet/dry mix (0.0 = dry only, 1.0 = wet only).
    wet: f32,
    /// Sample rate for delay calculation.
    sample_rate: u32,
    /// Comb filter feedback coefficients.
    comb_feedback: [f32; 4],
    /// All-pass filter feedback coefficient.
    allpass_feedback: f32,
    /// Comb filter delay line buffers.
    comb_buffers: [Vec<f32>; 4],
    /// Comb filter write positions.
    comb_positions: [usize; 4],
    /// All-pass filter delay line buffers.
    allpass_buffers: [Vec<f32>; 2],
    /// All-pass filter write positions.
    allpass_positions: [usize; 2],
    /// Output gain (wet level).
    gain: f32,
    /// Number of channels.
    channels: u16,
    /// COM registration properties.
    registration: XAPO_REGISTRATION_PROPERTIES,
}

impl XapoReverb {
    /// Create a new reverb effect with the given parameters.
    ///
    /// * `wet` — wet/dry mix (0.0–1.0).
    /// * `sample_rate` — audio sample rate in Hz (used for delay calculations).
    /// * `channels` — number of audio channels.
    pub fn new(wet: f32, sample_rate: u32, channels: u16) -> Self {
        // Comb delays (in samples): ~30ms, 37ms, 43ms, 50ms
        let comb_ms = [30.0, 37.0, 43.0, 50.0];
        let comb_delays: [usize; 4] = [
            (comb_ms[0] * sample_rate as f32 / 1000.0).round() as usize,
            (comb_ms[1] * sample_rate as f32 / 1000.0).round() as usize,
            (comb_ms[2] * sample_rate as f32 / 1000.0).round() as usize,
            (comb_ms[3] * sample_rate as f32 / 1000.0).round() as usize,
        ];
        let comb_feedback = [0.84, 0.82, 0.79, 0.77];

        // All-pass delays: ~5ms, 3.5ms
        let allpass_ms = [5.0, 3.5];
        let allpass_delays: [usize; 2] = [
            (allpass_ms[0] * sample_rate as f32 / 1000.0).round() as usize,
            (allpass_ms[1] * sample_rate as f32 / 1000.0).round() as usize,
        ];

        let channels_usize = channels.max(1) as usize;
        let comb_buffers = [
            vec![0.0f32; comb_delays[0] * channels_usize],
            vec![0.0f32; comb_delays[1] * channels_usize],
            vec![0.0f32; comb_delays[2] * channels_usize],
            vec![0.0f32; comb_delays[3] * channels_usize],
        ];
        let allpass_buffers = [
            vec![0.0f32; allpass_delays[0] * channels_usize],
            vec![0.0f32; allpass_delays[1] * channels_usize],
        ];

        let reg = XAPO_REGISTRATION_PROPERTIES::new(
            [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            "Schroeder Reverb",
            XAPO_FLAG_INPLACE,
        );

        Self {
            wet: wet.clamp(0.0, 1.0),
            sample_rate,
            comb_feedback,
            allpass_feedback: 0.5,
            comb_buffers,
            comb_positions: [0; 4],
            allpass_buffers,
            allpass_positions: [0; 2],
            gain: 0.35,
            channels: channels.max(1),
            registration: reg,
        }
    }
}

impl XapoEffect for XapoReverb {
    fn process(&mut self, input: &[f32], output: &mut [f32]) -> AppResult<()> {
        let ch = self.channels.max(1) as usize;
        let total = input.len();
        if output.len() < total || total == 0 {
            return Ok(());
        }
        let frames = total / ch;
        if frames == 0 {
            return Ok(());
        }

        for i in 0..total {
            let sample = input[i];

            // Sum through 4 parallel comb filters
            let mut comb_sum = 0.0f32;
            for c in 0..4 {
                let pos = self.comb_positions[c];
                let buf = &mut self.comb_buffers[c];
                if buf.is_empty() {
                    continue;
                }
                let delayed = buf[pos];
                buf[pos] = sample + delayed * self.comb_feedback[c];
                comb_sum += delayed;
                self.comb_positions[c] = (pos + 1) % buf.len();
            }

            // Feed through 2 series all-pass filters
            let mut ap_out = comb_sum * 0.25;
            for a in 0..2 {
                let pos = self.allpass_positions[a];
                let buf = &mut self.allpass_buffers[a];
                if buf.is_empty() {
                    continue;
                }
                let delayed = buf[pos];
                buf[pos] = ap_out + delayed * self.allpass_feedback;
                ap_out = delayed - ap_out * self.allpass_feedback;
                self.allpass_positions[a] = (pos + 1) % buf.len();
            }

            // Mix: output = (1 - wet) * input + wet * processed * gain
            output[i] = (1.0 - self.wet) * sample + self.wet * ap_out * self.gain;
        }

        Ok(())
    }

    fn reset(&mut self) {
        for buf in self.comb_buffers.iter_mut() {
            buf.fill(0.0);
        }
        for buf in self.allpass_buffers.iter_mut() {
            buf.fill(0.0);
        }
        self.comb_positions = [0; 4];
        self.allpass_positions = [0; 2];
    }

    fn registration(&self) -> &XAPO_REGISTRATION_PROPERTIES {
        &self.registration
    }

    fn channels(&self) -> u16 {
        self.channels
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}

/// One-pole IIR low-pass filter effect.
pub struct XapoLowPass {
    /// Cutoff frequency coefficient (0.0–1.0).
    cutoff: f32,
    /// Per-channel previous output samples for the IIR filter.
    previous: Vec<f32>,
    /// Number of channels.
    channels: u16,
    /// Sample rate.
    sample_rate: u32,
    /// COM registration properties.
    registration: XAPO_REGISTRATION_PROPERTIES,
}

impl XapoLowPass {
    pub fn new(cutoff: f32, channels: u16, sample_rate: u32) -> Self {
        let reg = XAPO_REGISTRATION_PROPERTIES::new(
            [
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02,
            ],
            "One-Pole Low-Pass Filter",
            XAPO_FLAG_INPLACE,
        );
        Self {
            cutoff: cutoff.clamp(0.01, 1.0),
            previous: vec![0.0; channels.max(1) as usize],
            channels: channels.max(1),
            sample_rate,
            registration: reg,
        }
    }
}

impl XapoEffect for XapoLowPass {
    fn process(&mut self, input: &[f32], output: &mut [f32]) -> AppResult<()> {
        let ch = self.channels as usize;
        let total = input.len();
        if output.len() < total || total == 0 {
            return Ok(());
        }
        let frames = total / ch;
        if frames == 0 {
            return Ok(());
        }
        if self.cutoff >= 1.0 {
            output[..total].copy_from_slice(&input[..total]);
            return Ok(());
        }
        let alpha = self.cutoff;

        for frame in 0..frames {
            for c in 0..ch {
                let idx = frame * ch + c;
                let prev = &mut self.previous[c];
                *prev = *prev + alpha * (input[idx] - *prev);
                output[idx] = *prev;
            }
        }

        Ok(())
    }

    fn reset(&mut self) {
        self.previous.fill(0.0);
    }

    fn registration(&self) -> &XAPO_REGISTRATION_PROPERTIES {
        &self.registration
    }

    fn channels(&self) -> u16 {
        self.channels
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}

/// One-pole IIR high-pass filter effect.
pub struct XapoHighPass {
    /// Cutoff frequency coefficient (0.0–1.0).
    cutoff: f32,
    /// Per-channel previous input sample.
    prev_input: Vec<f32>,
    /// Per-channel previous output sample.
    prev_output: Vec<f32>,
    /// Number of channels.
    channels: u16,
    /// Sample rate.
    sample_rate: u32,
    /// COM registration properties.
    registration: XAPO_REGISTRATION_PROPERTIES,
}

impl XapoHighPass {
    pub fn new(cutoff: f32, channels: u16, sample_rate: u32) -> Self {
        let reg = XAPO_REGISTRATION_PROPERTIES::new(
            [
                0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x03,
            ],
            "One-Pole High-Pass Filter",
            XAPO_FLAG_INPLACE,
        );
        Self {
            cutoff: cutoff.clamp(0.01, 1.0),
            prev_input: vec![0.0; channels.max(1) as usize],
            prev_output: vec![0.0; channels.max(1) as usize],
            channels: channels.max(1),
            sample_rate,
            registration: reg,
        }
    }
}

impl XapoEffect for XapoHighPass {
    fn process(&mut self, input: &[f32], output: &mut [f32]) -> AppResult<()> {
        let ch = self.channels as usize;
        let total = input.len();
        if output.len() < total || total == 0 {
            return Ok(());
        }
        let frames = total / ch;
        if frames == 0 {
            return Ok(());
        }
        if self.cutoff >= 1.0 {
            output[..total].copy_from_slice(&input[..total]);
            return Ok(());
        }
        let alpha = self.cutoff;

        for frame in 0..frames {
            for c in 0..ch {
                let idx = frame * ch + c;
                let in_val = input[idx];
                let out_val = alpha * (self.prev_output[c] + in_val - self.prev_input[c]);
                self.prev_input[c] = in_val;
                self.prev_output[c] = out_val;
                output[idx] = out_val;
            }
        }

        Ok(())
    }

    fn reset(&mut self) {
        self.prev_input.fill(0.0);
        self.prev_output.fill(0.0);
    }

    fn registration(&self) -> &XAPO_REGISTRATION_PROPERTIES {
        &self.registration
    }

    fn channels(&self) -> u16 {
        self.channels
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}

/// Echo / delay effect with configurable feedback.
pub struct XapoEcho {
    /// Delay line buffer.
    delay_buffer: Vec<f32>,
    /// Write position in the delay line.
    write_pos: usize,
    /// Delay time in frames.
    delay_frames: usize,
    /// Feedback gain (0.0–1.0).
    feedback: f32,
    /// Wet/dry mix (0.0–1.0).
    wet: f32,
    /// Number of channels.
    channels: u16,
    /// Sample rate.
    sample_rate: u32,
    /// COM registration properties.
    registration: XAPO_REGISTRATION_PROPERTIES,
}

impl XapoEcho {
    pub fn new(delay_ms: f32, feedback: f32, wet: f32, channels: u16, sample_rate: u32) -> Self {
        let ch = channels.max(1) as usize;
        let delay_frames = ((delay_ms.max(1.0) * sample_rate as f32) / 1000.0).round() as usize;
        let reg = XAPO_REGISTRATION_PROPERTIES::new(
            [
                0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x04,
            ],
            "Echo / Delay",
            XAPO_FLAG_INPLACE,
        );
        Self {
            delay_buffer: vec![0.0; delay_frames * ch],
            write_pos: 0,
            delay_frames,
            feedback: feedback.clamp(0.0, 0.95),
            wet: wet.clamp(0.0, 1.0),
            channels: channels.max(1),
            sample_rate,
            registration: reg,
        }
    }
}

impl XapoEffect for XapoEcho {
    fn process(&mut self, input: &[f32], output: &mut [f32]) -> AppResult<()> {
        let _ch = self.channels as usize;
        let total = input.len();
        if output.len() < total || total == 0 || self.delay_buffer.is_empty() {
            return Ok(());
        }
        let buf_len = self.delay_buffer.len();

        for i in 0..total {
            let delayed = self.delay_buffer[self.write_pos];
            self.delay_buffer[self.write_pos] = input[i] + delayed * self.feedback;
            output[i] = (1.0 - self.wet) * input[i] + self.wet * delayed;
            self.write_pos = (self.write_pos + 1) % buf_len;
        }

        Ok(())
    }

    fn reset(&mut self) {
        self.delay_buffer.fill(0.0);
        self.write_pos = 0;
    }

    fn registration(&self) -> &XAPO_REGISTRATION_PROPERTIES {
        &self.registration
    }

    fn channels(&self) -> u16 {
        self.channels
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}

/// Dynamic range compressor effect.
///
/// Applies threshold-based gain reduction with configurable ratio,
/// attack time, and release time.
pub struct XapoCompressor {
    /// Threshold in dB (e.g. -24.0).
    threshold_db: f32,
    /// Compression ratio (e.g. 4.0 = 4:1).
    ratio: f32,
    /// Attack time in seconds.
    attack_s: f32,
    /// Release time in seconds.
    release_s: f32,
    /// Envelope follower state per channel.
    envelope: Vec<f32>,
    /// Makeup gain in dB.
    makeup_gain_db: f32,
    /// Sample rate.
    sample_rate: u32,
    /// Number of channels.
    channels: u16,
    /// COM registration properties.
    registration: XAPO_REGISTRATION_PROPERTIES,
}

impl XapoCompressor {
    pub fn new(
        threshold_db: f32,
        ratio: f32,
        attack_ms: f32,
        release_ms: f32,
        channels: u16,
        sample_rate: u32,
    ) -> Self {
        let reg = XAPO_REGISTRATION_PROPERTIES::new(
            [
                0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x05,
            ],
            "Dynamic Range Compressor",
            XAPO_FLAG_INPLACE,
        );
        Self {
            threshold_db,
            ratio: ratio.max(1.0),
            attack_s: (attack_ms.max(0.1) / 1000.0),
            release_s: (release_ms.max(1.0) / 1000.0),
            envelope: vec![0.0; channels.max(1) as usize],
            makeup_gain_db: 0.0,
            sample_rate,
            channels: channels.max(1),
            registration: reg,
        }
    }
}

impl XapoEffect for XapoCompressor {
    fn process(&mut self, input: &[f32], output: &mut [f32]) -> AppResult<()> {
        let ch = self.channels as usize;
        let total = input.len();
        if output.len() < total || total == 0 {
            return Ok(());
        }
        let frames = total / ch;
        if frames == 0 {
            return Ok(());
        }

        let attack_coeff = (-1.0 / (self.attack_s * self.sample_rate as f32)).exp();
        let release_coeff = (-1.0 / (self.release_s * self.sample_rate as f32)).exp();
        let threshold_linear = 10.0f32.powf(self.threshold_db / 20.0);
        let slope = 1.0 / self.ratio;
        let makeup = 10.0f32.powf(self.makeup_gain_db / 20.0);

        for frame in 0..frames {
            for c in 0..ch {
                let idx = frame * ch + c;
                let sample = input[idx];
                let abs_sample = sample.abs();

                // Envelope follower
                let env = &mut self.envelope[c];
                if abs_sample > *env {
                    *env = *env + (1.0 - attack_coeff) * (abs_sample - *env);
                } else {
                    *env = *env + (1.0 - release_coeff) * (abs_sample - *env);
                }

                // Gain computation
                let gain = if *env > threshold_linear {
                    let db = 20.0 * env.log10();
                    let compressed_db = self.threshold_db + (db - self.threshold_db) * slope;
                    let compressed_linear = 10.0f32.powf(compressed_db / 20.0);
                    if *env > 0.0 {
                        compressed_linear / *env
                    } else {
                        1.0
                    }
                } else {
                    1.0
                };

                output[idx] = sample * gain * makeup;
            }
        }

        Ok(())
    }

    fn reset(&mut self) {
        self.envelope.fill(0.0);
    }

    fn registration(&self) -> &XAPO_REGISTRATION_PROPERTIES {
        &self.registration
    }

    fn channels(&self) -> u16 {
        self.channels
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}

/// Normalize effect — scales audio to a target peak level.
pub struct XapoNormalize {
    /// Target peak amplitude (0.0–1.0).
    target_peak: f32,
    /// Maximum observed amplitude from the previous buffer.
    max_observed: f32,
    /// Number of channels.
    channels: u16,
    /// Sample rate.
    sample_rate: u32,
    /// COM registration properties.
    registration: XAPO_REGISTRATION_PROPERTIES,
}

impl XapoNormalize {
    pub fn new(target_peak: f32, channels: u16, sample_rate: u32) -> Self {
        let reg = XAPO_REGISTRATION_PROPERTIES::new(
            [
                0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x06,
            ],
            "Normalize to Peak",
            XAPO_FLAG_INPLACE,
        );
        Self {
            target_peak: target_peak.clamp(0.01, 1.0),
            max_observed: 0.0,
            channels: channels.max(1),
            sample_rate,
            registration: reg,
        }
    }
}

impl XapoEffect for XapoNormalize {
    fn process(&mut self, input: &[f32], output: &mut [f32]) -> AppResult<()> {
        let _ch = self.channels as usize;
        let total = input.len();
        if output.len() < total || total == 0 {
            return Ok(());
        }

        // Find peak in this buffer
        let mut peak = 0.0f32;
        for &s in input[..total].iter() {
            let abs_s = s.abs();
            if abs_s > peak {
                peak = abs_s;
            }
        }

        let effective_peak = peak.max(self.max_observed);
        self.max_observed = peak * 0.5 + self.max_observed * 0.5; // Smooth the observation

        if effective_peak > 0.0 {
            let scale = (self.target_peak / effective_peak).min(2.0);
            for i in 0..total {
                output[i] = input[i] * scale;
            }
        } else {
            output[..total].copy_from_slice(&input[..total]);
        }

        Ok(())
    }

    fn reset(&mut self) {
        self.max_observed = 0.0;
    }

    fn registration(&self) -> &XAPO_REGISTRATION_PROPERTIES {
        &self.registration
    }

    fn channels(&self) -> u16 {
        self.channels
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}

// ---------------------------------------------------------------------------
// Effect parameter structures
// ---------------------------------------------------------------------------

/// Parameters for the Reverb effect.
#[derive(Debug, Clone)]
pub struct ReverbParameters {
    /// Wet/dry mix (0.0 = dry only, 1.0 = wet only).
    pub wet_dry_mix: f32,
    /// Reverb delay in milliseconds.
    pub delay_ms: f32,
}

impl Default for ReverbParameters {
    fn default() -> Self {
        Self {
            wet_dry_mix: 0.5,
            delay_ms: 50.0,
        }
    }
}

/// Parameters for the Equalizer effect.
#[derive(Debug, Clone)]
pub struct EqualizerParameters {
    /// Band gains in dB (typically -12.0 to +12.0).
    pub band_gains_db: [f32; 4],
    /// Band center frequencies in Hz.
    pub band_frequencies: [f32; 4],
    /// Band Q factors (bandwidth).
    pub band_q: [f32; 4],
}

impl Default for EqualizerParameters {
    fn default() -> Self {
        Self {
            band_gains_db: [0.0, 0.0, 0.0, 0.0],
            band_frequencies: [100.0, 500.0, 2000.0, 8000.0],
            band_q: [1.0, 1.0, 1.0, 1.0],
        }
    }
}

/// Parameters for the Compressor effect.
#[derive(Debug, Clone)]
pub struct CompressorParameters {
    /// Threshold in dB.
    pub threshold_db: f32,
    /// Compression ratio.
    pub ratio: f32,
    /// Attack time in milliseconds.
    pub attack_ms: f32,
    /// Release time in milliseconds.
    pub release_ms: f32,
}

impl Default for CompressorParameters {
    fn default() -> Self {
        Self {
            threshold_db: -24.0,
            ratio: 4.0,
            attack_ms: 5.0,
            release_ms: 50.0,
        }
    }
}

/// Parameters for the Echo effect.
#[derive(Debug, Clone)]
pub struct EchoParameters {
    /// Delay in milliseconds.
    pub delay_ms: f32,
    /// Feedback (0.0–1.0).
    pub feedback: f32,
    /// Wet/dry mix (0.0–1.0).
    pub wet_dry_mix: f32,
}

impl Default for EchoParameters {
    fn default() -> Self {
        Self {
            delay_ms: 200.0,
            feedback: 0.5,
            wet_dry_mix: 0.5,
        }
    }
}

// ---------------------------------------------------------------------------
// Parametric 4-band Equalizer
// ---------------------------------------------------------------------------

/// Parametric 4-band equalizer XAPO effect.
///
/// Implements 4 peaking/notching biquad filters, each with configurable
/// center frequency, gain, and Q factor. The bands are processed in series.
pub struct XapoEqualizer {
    /// Number of channels.
    channels: u16,
    /// Sample rate.
    sample_rate: u32,
    /// Current parameters.
    params: EqualizerParameters,
    /// Per-band biquad state: (x1, x2, y1, y2) for each channel.
    /// Indexed as `band_state[band][channel] = (x1, x2, y1, y2)`.
    band_state: [Vec<(f32, f32, f32, f32)>; 4],
    /// COM registration properties.
    registration: XAPO_REGISTRATION_PROPERTIES,
}

impl XapoEqualizer {
    /// Create a new 4-band parametric equalizer.
    pub fn new(params: EqualizerParameters, channels: u16, sample_rate: u32) -> Self {
        let ch = channels.max(1) as usize;
        let zero_state: Vec<(f32, f32, f32, f32)> = (0..ch).map(|_| (0.0, 0.0, 0.0, 0.0)).collect();

        let mut reg = XAPO_REGISTRATION_PROPERTIES::new(
            [
                0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x07,
            ],
            "Parametric 4-Band Equalizer",
            XAPO_FLAG_INPLACE,
        );
        reg.min_input_buffer_count = 1;
        reg.max_input_buffer_count = 1;
        reg.min_output_buffer_count = 1;
        reg.max_output_buffer_count = 1;

        Self {
            channels: channels.max(1),
            sample_rate,
            params,
            band_state: [
                zero_state.clone(),
                zero_state.clone(),
                zero_state.clone(),
                zero_state,
            ],
            registration: reg,
        }
    }

    /// Update the equalizer parameters.
    pub fn set_parameters(&mut self, params: EqualizerParameters) {
        self.params = params;
    }

    /// Get the current parameters.
    pub fn parameters(&self) -> &EqualizerParameters {
        &self.params
    }

    /// Compute biquad coefficients for a peaking EQ filter.
    fn peaking_coefficients(
        freq: f32,
        gain_db: f32,
        q: f32,
        sample_rate: f32,
    ) -> (f32, f32, f32, f32, f32) {
        let a = 10.0_f32.powf(gain_db / 40.0);
        let w0 = 2.0 * std::f32::consts::PI * freq / sample_rate;
        let cos_w0 = w0.cos();
        let sin_w0 = w0.sin();
        let alpha = sin_w0 / (2.0 * q);

        let b0 = 1.0 + alpha * a;
        let b1 = -2.0 * cos_w0;
        let b2 = 1.0 - alpha * a;
        let a0 = 1.0 + alpha / a;
        let a1 = -2.0 * cos_w0;
        let a2 = 1.0 - alpha / a;

        // Normalize by a0
        (b0 / a0, b1 / a0, b2 / a0, a1 / a0, a2 / a0)
    }
}

impl XapoEffect for XapoEqualizer {
    fn process(&mut self, input: &[f32], output: &mut [f32]) -> AppResult<()> {
        let channels = self.channels as usize;
        if output.len() < input.len() || input.is_empty() || channels == 0 {
            return Ok(());
        }

        // Pre-compute biquad coefficients for each band on the stack (no
        // allocation per call; recomputed every call since parameters can
        // change between buffers).
        let coeffs = [
            Self::peaking_coefficients(
                self.params.band_frequencies[0],
                self.params.band_gains_db[0],
                self.params.band_q[0],
                self.sample_rate as f32,
            ),
            Self::peaking_coefficients(
                self.params.band_frequencies[1],
                self.params.band_gains_db[1],
                self.params.band_q[1],
                self.sample_rate as f32,
            ),
            Self::peaking_coefficients(
                self.params.band_frequencies[2],
                self.params.band_gains_db[2],
                self.params.band_q[2],
                self.sample_rate as f32,
            ),
            Self::peaking_coefficients(
                self.params.band_frequencies[3],
                self.params.band_gains_db[3],
                self.params.band_q[3],
                self.sample_rate as f32,
            ),
        ];

        // Process each sample through all 4 bands in series
        for (i, &sample) in input.iter().enumerate() {
            let ch = i % channels;
            let mut y = sample;

            for (band, &(b0, b1, b2, a1, a2)) in coeffs.iter().enumerate() {
                let (x1, x2, y1, y2) = self.band_state[band][ch];

                let new_y = b0 * y + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;
                self.band_state[band][ch] = (y, x1, new_y, y1);
                y = new_y;
            }

            output[i] = y;
        }

        Ok(())
    }

    fn reset(&mut self) {
        let ch = self.channels as usize;
        for band in 0..4 {
            self.band_state[band] = (0..ch).map(|_| (0.0, 0.0, 0.0, 0.0)).collect();
        }
    }

    fn registration(&self) -> &XAPO_REGISTRATION_PROPERTIES {
        &self.registration
    }

    fn channels(&self) -> u16 {
        self.channels
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}

// ---------------------------------------------------------------------------
// XAPO Effect Chain — processes audio through a sequence of effects
// ---------------------------------------------------------------------------

/// A chain of XAPO effects that processes audio in sequence.
///
/// Used to integrate with the XAudio2 voice graph: each source or submix
/// voice can have an effect chain attached that transforms the audio
/// before passing it to the next voice in the graph.
pub struct XapoEffectChain {
    /// Ordered list of effect instance handles in the chain.
    chain: Vec<u64>,
    /// Temporary buffer for inter-effect processing.
    temp_buffer: Vec<f32>,
    /// Second reusable scratch buffer, alternated with `temp_buffer` so no
    /// intermediate effect allocates on every processed buffer.
    scratch_buffer: Vec<f32>,
}

impl XapoEffectChain {
    /// Create a new empty effect chain.
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            temp_buffer: Vec::new(),
            scratch_buffer: Vec::new(),
        }
    }

    /// Create a chain from a list of effect instance handles.
    pub fn from_handles(handles: Vec<u64>) -> Self {
        Self {
            chain: handles,
            temp_buffer: Vec::new(),
            scratch_buffer: Vec::new(),
        }
    }

    /// Add an effect to the end of the chain.
    pub fn push(&mut self, handle: u64) {
        self.chain.push(handle);
    }

    /// Remove the last effect from the chain.
    pub fn pop(&mut self) -> Option<u64> {
        self.chain.pop()
    }

    /// Insert an effect at a specific position.
    pub fn insert(&mut self, index: usize, handle: u64) {
        if index <= self.chain.len() {
            self.chain.insert(index, handle);
        }
    }

    /// Remove an effect at a specific position.
    pub fn remove(&mut self, index: usize) -> Option<u64> {
        if index < self.chain.len() {
            Some(self.chain.remove(index))
        } else {
            None
        }
    }

    /// Get the number of effects in the chain.
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Get the effect handles in order.
    pub fn handles(&self) -> &[u64] {
        &self.chain
    }

    /// Process audio through the entire effect chain.
    ///
    /// Each effect processes the audio in sequence, with the output of one
    /// becoming the input of the next.
    pub fn process_chain(
        &mut self,
        manager: &mut XapoManager,
        input: &[f32],
        output: &mut [f32],
    ) -> AppResult<()> {
        if self.chain.is_empty() {
            // No effects — pass through
            let copy_len = input.len().min(output.len());
            output[..copy_len].copy_from_slice(&input[..copy_len]);
            return Ok(());
        }

        // Ensure temp buffer is large enough
        if self.temp_buffer.len() < input.len() {
            self.temp_buffer.resize(input.len(), 0.0);
        }

        // Copy input to temp buffer
        self.temp_buffer[..input.len()].copy_from_slice(input);

        // Process through each effect in the chain
        for (i, &handle) in self.chain.iter().enumerate() {
            if i == self.chain.len() - 1 {
                // Last effect writes directly to output
                if !manager.process_instance(handle, &self.temp_buffer[..input.len()], output) {
                    // The instance is gone: zero the output so stale or
                    // partially-written samples do not flow downstream.
                    output.fill(0.0);
                }
            } else {
                // Intermediate effect: reuse the scratch buffer (grown only
                // when the chain is configured with a larger buffer size).
                if self.scratch_buffer.len() < input.len() {
                    self.scratch_buffer.resize(input.len(), 0.0);
                }
                if !manager.process_instance(
                    handle,
                    &self.temp_buffer[..input.len()],
                    &mut self.scratch_buffer[..input.len()],
                ) {
                    self.scratch_buffer[..input.len()].fill(0.0);
                }
                self.temp_buffer[..input.len()]
                    .copy_from_slice(&self.scratch_buffer[..input.len()]);
            }
        }

        Ok(())
    }
}

impl Default for XapoEffectChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// XAPO Voice Graph Integration
// ---------------------------------------------------------------------------

/// Associates an effect chain with a specific voice in the XAudio2 graph.
pub struct VoiceEffectChain {
    /// The voice this chain is attached to.
    voice_id: VoiceId,
    /// The effect chain.
    chain: XapoEffectChain,
    /// Whether the chain is enabled.
    enabled: bool,
}

impl VoiceEffectChain {
    /// Create a new voice effect chain.
    pub fn new(voice_id: VoiceId) -> Self {
        Self {
            voice_id,
            chain: XapoEffectChain::new(),
            enabled: true,
        }
    }

    /// Get the voice ID this chain is attached to.
    pub fn voice_id(&self) -> VoiceId {
        self.voice_id
    }

    /// Get the underlying effect chain.
    pub fn chain(&self) -> &XapoEffectChain {
        &self.chain
    }

    /// Get the mutable underlying effect chain.
    pub fn chain_mut(&mut self) -> &mut XapoEffectChain {
        &mut self.chain
    }

    /// Enable or disable the effect chain.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if the chain is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// ---------------------------------------------------------------------------
// XapoInstance — runtime effect instance
// ---------------------------------------------------------------------------

/// A running XAPO effect instance created from a registered effect type.
pub struct XapoInstance {
    /// The actual effect processing engine.
    pub effect: Box<dyn XapoEffect + Send>,
    /// CLSID of the effect type that was used to create this instance.
    pub clsid: [u8; 16],
}

// ---------------------------------------------------------------------------
// XapoManager — effect registration and instance factory
// ---------------------------------------------------------------------------

/// Type alias for a factory function that creates XAPO effect instances.
type EffectFactory = Box<dyn Fn() -> Box<dyn XapoEffect + Send> + Send>;

/// Manages registration, creation, and lifecycle of XAPO audio effects.
///
/// Effects are registered by CLSID (GUID) and instantiated on demand. Each
/// instance holds its own processing state and can be independently processed,
/// reset, or destroyed.
pub struct XapoManager {
    /// Registered effect factory functions and their registration props, keyed by CLSID.
    registered: HashMap<[u8; 16], (XAPO_REGISTRATION_PROPERTIES, EffectFactory)>,
    /// Active effect instances, keyed by a numeric handle.
    instances: BTreeMap<u64, XapoInstance>,
    /// Next handle to assign for create_instance().
    next_handle: u64,
}

impl XapoManager {
    /// Create a new empty XAPO manager.
    pub fn new() -> Self {
        Self {
            registered: HashMap::new(),
            instances: BTreeMap::new(),
            next_handle: 1,
        }
    }

    /// Register an effect type under the given CLSID.
    ///
    /// The `factory` closure must return a new default-initialised effect
    /// instance each time it is called. The `registration` provides the
    /// COM-style properties for this effect type.
    pub fn register_effect(
        &mut self,
        clsid: [u8; 16],
        registration: XAPO_REGISTRATION_PROPERTIES,
        factory: Box<dyn Fn() -> Box<dyn XapoEffect + Send> + Send>,
    ) {
        self.registered.insert(clsid, (registration, factory));
    }

    /// Register the built-in effects with standard CLSIDs.
    pub fn register_builtins(&mut self) {
        let reverb = XapoReverb::new(0.5, 48000, 2);
        let clsid = reverb.registration().clsid;
        let reg = reverb.registration().clone();
        self.register_effect(
            clsid,
            reg,
            Box::new(|| Box::new(XapoReverb::new(0.5, 48000, 2))),
        );

        let lp = XapoLowPass::new(0.5, 2, 48000);
        let clsid_lp = lp.registration().clsid;
        let reg_lp = lp.registration().clone();
        self.register_effect(
            clsid_lp,
            reg_lp,
            Box::new(|| Box::new(XapoLowPass::new(0.5, 2, 48000))),
        );

        let hp = XapoHighPass::new(0.5, 2, 48000);
        let clsid_hp = hp.registration().clsid;
        let reg_hp = hp.registration().clone();
        self.register_effect(
            clsid_hp,
            reg_hp,
            Box::new(|| Box::new(XapoHighPass::new(0.5, 2, 48000))),
        );

        let echo = XapoEcho::new(200.0, 0.5, 0.5, 2, 48000);
        let clsid_echo = echo.registration().clsid;
        let reg_echo = echo.registration().clone();
        self.register_effect(
            clsid_echo,
            reg_echo,
            Box::new(|| Box::new(XapoEcho::new(200.0, 0.5, 0.5, 2, 48000))),
        );

        let comp = XapoCompressor::new(-24.0, 4.0, 5.0, 50.0, 2, 48000);
        let clsid_comp = comp.registration().clsid;
        let reg_comp = comp.registration().clone();
        self.register_effect(
            clsid_comp,
            reg_comp,
            Box::new(|| Box::new(XapoCompressor::new(-24.0, 4.0, 5.0, 50.0, 2, 48000))),
        );

        let norm = XapoNormalize::new(0.95, 2, 48000);
        let clsid_norm = norm.registration().clsid;
        let reg_norm = norm.registration().clone();
        self.register_effect(
            clsid_norm,
            reg_norm,
            Box::new(|| Box::new(XapoNormalize::new(0.95, 2, 48000))),
        );

        let eq = XapoEqualizer::new(EqualizerParameters::default(), 2, 48000);
        let clsid_eq = eq.registration().clsid;
        let reg_eq = eq.registration().clone();
        self.register_effect(
            clsid_eq,
            reg_eq,
            Box::new(|| Box::new(XapoEqualizer::new(EqualizerParameters::default(), 2, 48000))),
        );
    }

    /// Create a new instance of a registered effect by CLSID.
    ///
    /// Returns a handle that can be used with [`process_instance`],
    /// [`destroy_instance`], and [`reset_instance`].
    ///
    /// Returns `None` if no effect is registered under the given CLSID.
    pub fn create_instance(&mut self, clsid: &[u8; 16]) -> Option<u64> {
        let (_, factory) = self.registered.get(clsid)?;
        let effect = factory();
        let handle = self.next_handle;
        self.next_handle += 1;
        self.instances.insert(
            handle,
            XapoInstance {
                effect,
                clsid: *clsid,
            },
        );
        Some(handle)
    }

    /// Process audio through an effect instance.
    ///
    /// Returns `true` if the instance was found and processed, `false` otherwise.
    pub fn process_instance(&mut self, handle: u64, input: &[f32], output: &mut [f32]) -> bool {
        if let Some(instance) = self.instances.get_mut(&handle) {
            instance.effect.process(input, output).is_ok()
        } else {
            false
        }
    }

    /// Reset an effect instance to its initial state.
    ///
    /// Returns `true` if the instance was found and reset, `false` otherwise.
    pub fn reset_instance(&mut self, handle: u64) -> bool {
        if let Some(instance) = self.instances.get_mut(&handle) {
            instance.effect.reset();
            true
        } else {
            false
        }
    }

    /// Destroy an effect instance and free its resources.
    ///
    /// Returns `true` if the instance was found and destroyed, `false` otherwise.
    pub fn destroy_instance(&mut self, handle: u64) -> bool {
        self.instances.remove(&handle).is_some()
    }

    /// Return the registration properties for a registered effect by CLSID.
    pub fn registration_properties(
        &self,
        clsid: &[u8; 16],
    ) -> Option<&XAPO_REGISTRATION_PROPERTIES> {
        self.registered.get(clsid).map(|(reg, _)| reg)
    }

    /// Return the registration properties for an active instance.
    pub fn instance_registration(&self, handle: u64) -> Option<&XAPO_REGISTRATION_PROPERTIES> {
        self.instances
            .get(&handle)
            .map(|inst| inst.effect.registration())
    }

    /// Return the effect channels for an active instance.
    pub fn instance_channels(&self, handle: u64) -> Option<u16> {
        self.instances
            .get(&handle)
            .map(|inst| inst.effect.channels())
    }

    /// Check if a CLSID has been registered.
    pub fn is_registered(&self, clsid: &[u8; 16]) -> bool {
        self.registered.contains_key(clsid)
    }

    /// Get the number of registered effect types.
    pub fn registered_count(&self) -> usize {
        self.registered.len()
    }

    /// Get the number of active effect instances.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    /// Return a list of all registered CLSIDs.
    pub fn registered_clsids(&self) -> Vec<[u8; 16]> {
        self.registered.keys().copied().collect()
    }
}

impl Default for XapoManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Voice callback timing
// ---------------------------------------------------------------------------

/// Calculate voice callback timing for buffer boundaries.
///
/// Returns a list of `(frame_offset, buffer_tag)` pairs indicating when
/// each buffer's `OnBufferEnd` callback should fire during a render pass.
pub fn calculate_buffer_callbacks(
    buffer_sizes_frames: &[(usize, String)],
    total_render_frames: usize,
) -> Vec<(usize, String)> {
    let mut callbacks = Vec::new();
    let mut accumulated = 0usize;

    for (frames, tag) in buffer_sizes_frames {
        accumulated += frames;
        if accumulated <= total_render_frames {
            callbacks.push((accumulated, tag.clone()));
        }
    }

    callbacks
}

// ---------------------------------------------------------------------------
// Stream callback helpers
// ---------------------------------------------------------------------------

// Runs on the cpal real-time audio thread: must never block or allocate.
// `try_lock` guarantees the callback never blocks on the producer; on the
// rare occasion the lock is contended the callback emits silence instead of
// risking a real-time deadline violation (priority inversion).
fn fill_output_f32(output: &mut [f32], queue: &Arc<Mutex<VecDeque<f32>>>) {
    let Ok(mut samples) = queue.try_lock() else {
        output.fill(0.0);
        return;
    };
    for sample in output.iter_mut() {
        *sample = samples.pop_front().unwrap_or(0.0).clamp(-1.0, 1.0);
    }
}

fn fill_output_i16(output: &mut [i16], queue: &Arc<Mutex<VecDeque<f32>>>) {
    let Ok(mut samples) = queue.try_lock() else {
        output.fill(0);
        return;
    };
    for sample in output.iter_mut() {
        let value = samples.pop_front().unwrap_or(0.0).clamp(-1.0, 1.0);
        *sample = (value * i16::MAX as f32) as i16;
    }
}

fn fill_output_u16(output: &mut [u16], queue: &Arc<Mutex<VecDeque<f32>>>) {
    let Ok(mut samples) = queue.try_lock() else {
        output.fill(u16::MAX / 2);
        return;
    };
    for sample in output.iter_mut() {
        let value = samples.pop_front().unwrap_or(0.0).clamp(-1.0, 1.0);
        *sample = (((value + 1.0) * 0.5) * u16::MAX as f32) as u16;
    }
}

// ---------------------------------------------------------------------------
// Format mapping
// ---------------------------------------------------------------------------

/// Map a `WaveFormat` sample format to the equivalent `cpal::SampleFormat`.
fn wave_format_to_cpal(format: &WaveFormat) -> cpal::SampleFormat {
    match format.sample_format {
        SampleFormat::Float32 => cpal::SampleFormat::F32,
        SampleFormat::Pcm16 => cpal::SampleFormat::I16,
    }
}

// ---------------------------------------------------------------------------
// Latency measurement
// ---------------------------------------------------------------------------

fn measure_latency_ms(sample_rate: u32, buffered_frames: usize) -> u32 {
    ((((buffered_frames as f32 / sample_rate as f32) * 1000.0).round() as u32) + 10).min(50)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires real audio hardware; hangs on headless/CI
    fn real_audio_backend_creates() {
        let backend = RealAudioBackend::new();
        assert!(backend.is_ok(), "expected audio backend to initialize");
        let backend = backend.unwrap();
        let devices = backend.enumerate_devices();
        // On CI or headless systems, there may be no devices
        if !devices.is_empty() {
            assert!(devices.iter().any(|d| d.is_default || !d.name.is_empty()));
        }
    }

    #[test]
    fn pcm16_to_float_and_back() {
        let original: Vec<i16> = vec![0, i16::MAX, i16::MIN, 1000, -1000];
        let float = pcm16_to_float(&original);
        assert_eq!(float.len(), 5);
        assert!((float[0] - 0.0).abs() < 0.001);
        assert!((float[1] - 1.0).abs() < 0.001);
        assert!((float[2] - (-1.0)).abs() < 0.001);

        let back = float_to_pcm16(&float);
        assert_eq!(back.len(), 5);
        assert_eq!(back[0], 0);
        assert_eq!(back[1], i16::MAX);
        // i16::MIN maps to -1.0, but -1.0 * i16::MAX = -32767 (not -32768)
        assert!(back[2] <= i16::MIN + 1);
    }

    #[test]
    fn float_to_u8_conversion() {
        let samples = vec![0.0f32, 1.0, -1.0];
        let u8_samples = float_to_u8(&samples);
        assert_eq!(u8_samples.len(), 3);
        assert!((u8_samples[0] as i32 - 128).abs() <= 1);
        assert_eq!(u8_samples[1], 255);
        assert_eq!(u8_samples[2], 0);
    }

    #[test]
    fn convert_and_resample_identity() {
        let samples = vec![0.5, -0.5, 0.25, -0.25]; // 2 frames, 2 channels
        let result = convert_and_resample(&samples, 2, 48000, 2, 48000);
        assert_eq!(result, samples);
    }

    #[test]
    fn convert_and_resample_upsample() {
        // 2 frames at 24000 Hz → 4 frames at 48000 Hz, mono
        let samples = vec![0.5, -0.5];
        let result = convert_and_resample(&samples, 1, 24000, 1, 48000);
        assert_eq!(result.len(), 4);
        assert!((result[0] - 0.5).abs() < 0.01);
        assert!((result[2] - (-0.5)).abs() < 0.01);
    }

    #[test]
    fn convert_and_resample_downsample() {
        // 4 frames at 48000 Hz → 2 frames at 24000 Hz, mono
        let samples = vec![1.0, 0.5, 0.0, -0.5];
        let result = convert_and_resample(&samples, 1, 48000, 1, 24000);
        assert_eq!(result.len(), 2);
        assert!((result[0] - 1.0).abs() < 0.01);
        assert!((result[1] - 0.0).abs() < 0.01);
    }

    #[test]
    fn convert_and_resample_channel_remapping_mono_to_stereo() {
        let samples = vec![0.5, -0.5]; // 2 frames, mono
        let result = convert_and_resample(&samples, 1, 48000, 2, 48000);
        assert_eq!(result.len(), 4);
        // Mono to stereo: duplicate to both channels
        assert!((result[0] - 0.5).abs() < 0.01);
        assert!((result[1] - 0.5).abs() < 0.01);
        assert!((result[2] - (-0.5)).abs() < 0.01);
        assert!((result[3] - (-0.5)).abs() < 0.01);
    }

    #[test]
    fn convert_and_resample_channel_remapping_stereo_to_mono() {
        let samples = vec![0.8, 0.2, -0.4, -0.6]; // 2 frames, stereo
        let result = convert_and_resample(&samples, 2, 48000, 1, 48000);
        assert_eq!(result.len(), 2);
        // Stereo to mono: average
        assert!((result[0] - 0.5).abs() < 0.01);
        assert!((result[1] - (-0.5)).abs() < 0.01);
    }

    #[test]
    fn convert_and_resample_empty() {
        let result = convert_and_resample(&[], 2, 48000, 2, 48000);
        assert!(result.is_empty());
    }

    #[test]
    fn reverb_dsp_applies_feedback_delay() {
        let mut samples = vec![1.0f32, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]; // 8 frames, mono
        apply_reverb_dsp(&mut samples, 1, 0.5, 2, 0.7);
        // Frame 2 should have feedback from frame 0
        assert!(samples[2].abs() > 0.0);
        // Frame 0 should be unchanged (before delay)
        assert!((samples[0] - 1.0).abs() < 0.001);
    }

    #[test]
    fn reverb_dsp_no_effect_with_zero_wet() {
        let mut samples = vec![1.0f32, 0.0, 0.0, 0.0];
        apply_reverb_dsp(&mut samples, 1, 0.0, 2, 0.5);
        assert_eq!(samples, vec![1.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn lowpass_filter_attenuates_high_frequency() {
        // Alternating signal (high frequency content)
        let mut samples = vec![1.0f32, -1.0, 1.0, -1.0, 1.0, -1.0, 1.0, -1.0];
        apply_lowpass(&mut samples, 1, 0.3);
        // After lowpass, the range should be reduced
        let max_after = samples.iter().map(|s| s.abs()).fold(0.0f32, f32::max);
        assert!(max_after < 1.0);
    }

    #[test]
    fn lowpass_no_effect_at_full_cutoff() {
        let mut samples = vec![1.0f32, -1.0, 1.0, -1.0];
        apply_lowpass(&mut samples, 1, 1.0);
        assert_eq!(samples, vec![1.0, -1.0, 1.0, -1.0]);
    }

    #[test]
    fn normalize_samples_scales_to_full_range() {
        let mut samples = vec![0.1f32, -0.1, 0.05, -0.05];
        normalize_samples(&mut samples);
        let max_abs = samples.iter().map(|s| s.abs()).fold(0.0f32, f32::max);
        assert!((max_abs - 1.0).abs() < 0.001);
    }

    #[test]
    fn normalize_samples_no_change_when_already_full_range() {
        let mut samples = vec![1.0f32, -1.0, 0.5];
        normalize_samples(&mut samples);
        assert_eq!(samples, vec![1.0, -1.0, 0.5]);
    }

    #[test]
    fn mix_streams_adds_samples() {
        let mut dest = vec![0.5f32, -0.3, 0.8];
        let source = vec![0.3f32, 0.2, -0.1];
        mix_streams(&mut dest, &source);
        assert!((dest[0] - 0.8).abs() < 0.001);
        assert!((dest[1] - (-0.1)).abs() < 0.001);
        assert!((dest[2] - 0.7).abs() < 0.001);
    }

    #[test]
    fn calculate_buffer_callbacks_timing() {
        let buffers: Vec<(usize, String)> = vec![
            (100, "buf_a".to_string()),
            (100, "buf_b".to_string()),
            (50, "buf_c".to_string()),
        ];
        let callbacks = calculate_buffer_callbacks(&buffers, 300);
        assert_eq!(callbacks.len(), 3);
        assert_eq!(callbacks[0], (100, "buf_a".to_string()));
        assert_eq!(callbacks[1], (200, "buf_b".to_string()));
        assert_eq!(callbacks[2], (250, "buf_c".to_string()));
    }

    #[test]
    fn calculate_buffer_callbacks_partial_render() {
        let buffers: Vec<(usize, String)> =
            vec![(100, "buf_a".to_string()), (100, "buf_b".to_string())];
        let callbacks = calculate_buffer_callbacks(&buffers, 150);
        // Only buf_a completes within 150 frames
        assert_eq!(callbacks.len(), 1);
        assert_eq!(callbacks[0], (100, "buf_a".to_string()));
    }

    #[test]
    #[ignore] // Requires real audio hardware (no mock device available in CI)
    fn default_device_detection() {
        let backend = RealAudioBackend::new().unwrap();
        let devices = backend.enumerate_devices();
        if !devices.is_empty() {
            let default_id = backend.default_device_id();
            assert!(default_id.is_ok(), "expected Ok, got {default_id:?}");
        }
    }

    #[test]
    #[ignore] // Requires real audio hardware (cannot create stream without physical device)
    fn latency_log_records_entries() {
        let backend = RealAudioBackend::new().unwrap();
        let log = backend.latency_log();
        // The log starts empty; entries are added when streams open
        assert!(log.len() <= 10);
    }

    #[test]
    #[ignore] // Requires real audio hardware (needs hotpluggable physical device to test)
    fn device_hotplug_detect_changes() {
        let mut backend = RealAudioBackend::new().unwrap();
        // Calling detect_device_changes should succeed even if no changes
        let result = backend.detect_device_changes();
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn convert_samples_to_float_from_pcm16() {
        let samples = crate::audio::AudioSamples::Pcm16(vec![0, i16::MAX, i16::MIN]);
        let float = convert_samples_to_float(&samples);
        assert_eq!(float.len(), 3);
        assert!((float[0] - 0.0).abs() < 0.001);
        assert!((float[1] - 1.0).abs() < 0.001);
        assert!((float[2] - (-1.0)).abs() < 0.001);
    }

    #[test]
    fn convert_samples_to_float_from_float32() {
        let samples = crate::audio::AudioSamples::Float32(vec![0.5, -0.5, 0.25]);
        let float = convert_samples_to_float(&samples);
        assert_eq!(float, vec![0.5, -0.5, 0.25]);
    }

    #[test]
    fn measure_latency_ms_clamps_to_50() {
        let latency = measure_latency_ms(48000, 100000);
        assert_eq!(latency, 50);
    }

    #[test]
    fn measure_latency_ms_small_buffer() {
        let latency = measure_latency_ms(48000, 128);
        // 128 frames at 48kHz ≈ 2.67ms + 10ms overhead = ~13ms
        assert!((10..=50).contains(&latency));
    }

    // ── Audio format detection tests ───────────────────────────────────

    #[test]
    fn detect_audio_format_pcm16() {
        assert_eq!(detect_audio_format(0x0001, 16), AudioFormat::Pcm16);
    }

    #[test]
    fn detect_audio_format_pcm24() {
        assert_eq!(detect_audio_format(0x0001, 24), AudioFormat::Pcm24);
    }

    #[test]
    fn detect_audio_format_pcm32() {
        assert_eq!(detect_audio_format(0x0001, 32), AudioFormat::Pcm32);
    }

    #[test]
    fn detect_audio_format_float32() {
        assert_eq!(detect_audio_format(0x0003, 32), AudioFormat::Float32);
    }

    #[test]
    fn detect_audio_format_ms_adpcm() {
        assert_eq!(detect_audio_format(0x0002, 4), AudioFormat::MsAdpcm);
    }

    #[test]
    fn detect_audio_format_ima_adpcm() {
        assert_eq!(detect_audio_format(0x0011, 4), AudioFormat::ImaAdpcm);
    }

    #[test]
    fn detect_audio_format_xma() {
        assert_eq!(detect_audio_format(0x0165, 16), AudioFormat::Xma);
    }

    #[test]
    fn detect_audio_format_unknown_falls_back_to_pcm16() {
        assert_eq!(detect_audio_format(0xFFFF, 16), AudioFormat::Pcm16);
    }

    // ── MS ADPCM decoder tests ──────────────────────────────────────────

    /// Build a synthetic mono MS ADPCM block with known values for testing.
    fn build_ms_adpcm_mono_block(
        predictor: u16,
        delta: u16,
        sample1: i16,
        sample2: i16,
        nibbles: &[u8],
    ) -> Vec<u8> {
        let mut block = Vec::new();
        block.extend_from_slice(&predictor.to_le_bytes());
        block.extend_from_slice(&delta.to_le_bytes());
        block.extend_from_slice(&sample1.to_le_bytes());
        block.extend_from_slice(&sample2.to_le_bytes());
        // Pack nibbles: each byte holds two nibbles (low nibble first)
        for pair in nibbles.chunks(2) {
            let low = pair[0] & 0x0F;
            let high = if pair.len() > 1 { pair[1] & 0x0F } else { 0 };
            block.push(low | (high << 4));
        }
        block
    }

    #[test]
    fn decode_ms_adpcm_mono_basic() {
        // Use predictor 0 (256, 0) — predicts from sample[n-2] only.
        // Initial delta = 64, samples = [100, 200].
        // Nibbles: all zeros (no delta adjustment, pure prediction).
        let block = build_ms_adpcm_mono_block(0, 64, 100, 200, &[0, 0, 0, 0]);
        let result = decode_ms_adpcm(&block, block.len() as u16, 1, 6).unwrap();

        // First two samples should be exact: 100, 200
        assert_eq!(result[0], 100);
        assert_eq!(result[1], 200);

        // Subsequent samples: predicted = (256 * sample[n-2] + 0 * sample[n-1]) / 256 = sample[n-2]
        // With nibble=0 (signed=0), sample stays predicted
        // So: sample[2] = 100, sample[3] = 200, sample[4] = 100, sample[5] = 200
        assert_eq!(result[2], 100);
        assert_eq!(result[3], 200);
        assert_eq!(result[4], 100);
        assert_eq!(result[5], 200);
    }

    #[test]
    fn decode_ms_adpcm_mono_positive_delta() {
        // Use predictor 0 (256, 0). Initial samples = [0, 0].
        // Nibble = 7 (signed = +7). delta = 64 initially.
        // sample[2] = predicted(0) + 64*7 = 448.
        // delta updates: adapt[7] = 614, delta = 614*64/256 = 153 (approx)
        // sample[3] = predicted(0) + 153*7 = 1071
        let block = build_ms_adpcm_mono_block(0, 64, 0, 0, &[0x77, 0x77]);
        let result = decode_ms_adpcm(&block, block.len() as u16, 1, 6).unwrap();

        assert_eq!(result[0], 0);
        assert_eq!(result[1], 0);
        // nibble[0] = 7 -> signed = 7, delta=64 -> 64*7=448
        assert_eq!(result[2], 448);
        // nibble[1] = 7, delta updated: adapt[7]=614, (614*64)/256=153.5 -> 153
        // 153*7=1071
        assert_eq!(result[3], 1071);
    }

    #[test]
    fn decode_ms_adpcm_stereo_basic() {
        // Stereo: two headers, then interleaved nibbles.
        let mut stereo_data = Vec::new();

        // Ch1 header: predictor=0, delta=32, sample1=100, sample2=200
        stereo_data.extend_from_slice(&0u16.to_le_bytes());
        stereo_data.extend_from_slice(&32u16.to_le_bytes());
        stereo_data.extend_from_slice(&100i16.to_le_bytes());
        stereo_data.extend_from_slice(&200i16.to_le_bytes());

        // Ch2 header: predictor=0, delta=32, sample1=-100, sample2=-200
        stereo_data.extend_from_slice(&0u16.to_le_bytes());
        stereo_data.extend_from_slice(&32u16.to_le_bytes());
        stereo_data.extend_from_slice(&(-100i16).to_le_bytes());
        stereo_data.extend_from_slice(&(-200i16).to_le_bytes());

        // Nibbles (stereo interleaved): ch1_nibble, ch2_nibble, ...
        // Pack: byte0 = nibble0(ch1) | nibble1(ch2)<<4, byte1 = nibble2(ch1) | nibble3(ch2)<<4
        stereo_data.push(0x00); // ch1=0, ch2=0
        stereo_data.push(0x00); // ch1=0, ch2=0

        let result = decode_ms_adpcm(&stereo_data, stereo_data.len() as u16, 2, 6).unwrap();

        // Every block must produce exactly `samples_per_block` frames per
        // channel (the stereo decoder used to be short by ~half).
        assert_eq!(result.len(), 2 * 6);

        // Interleaved: [ch1_100, ch2_-100, ch1_200, ch2_-200, ch1_pred...]
        assert_eq!(result[0], 100);
        assert_eq!(result[1], -100);
        assert_eq!(result[2], 200);
        assert_eq!(result[3], -200);

        // With nibble=0, ch1 predicts from ch1 history, ch2 from ch2 history
        // ch1: predictor 0 -> sample[n] = sample[n-2] -> 100
        // ch2: predictor 0 -> sample[n] = sample[n-2] -> -100
        assert_eq!(result[4], 100);
        assert_eq!(result[5], -100);
    }

    #[test]
    fn decode_ms_adpcm_stereo_full_block_length() {
        // Stereo block with enough nibble data for the full samples_per_block.
        let mut stereo_data = Vec::new();
        for _ in 0..2 {
            stereo_data.extend_from_slice(&0u16.to_le_bytes()); // predictor
            stereo_data.extend_from_slice(&32u16.to_le_bytes()); // delta
            stereo_data.extend_from_slice(&100i16.to_le_bytes()); // sample1
            stereo_data.extend_from_slice(&200i16.to_le_bytes()); // sample2
        }
        // 4 data bytes -> 4 nibbles per channel = exactly `remaining` (4)
        // samples per channel with samples_per_block = 6.
        stereo_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let result = decode_ms_adpcm(&stereo_data, stereo_data.len() as u16, 2, 6).unwrap();
        assert_eq!(result.len(), 2 * 6);
        // Frame-major interleaving: every pair is (ch1, ch2). Both channels
        // share the same history, and predictor 0 (256, 0) predicts
        // sample[n-2], so the sequence alternates 100, 200, 100, 200, ...
        for frame in 0..6 {
            let expected = if frame % 2 == 0 { 100 } else { 200 };
            assert_eq!(result[frame * 2], expected);
            assert_eq!(result[frame * 2 + 1], expected);
        }
    }

    #[test]
    fn decode_ms_adpcm_invalid_predictor_returns_error() {
        // Predictor index 7 is out of range (0-6)
        let block = vec![7u8, 0, 64, 0, 100, 0, 200, 0, 0x00];
        let _ = block;
        // Actually build properly
        let block = build_ms_adpcm_mono_block(7, 64, 100, 200, &[0]);
        let result = decode_ms_adpcm(&block, block.len() as u16, 1, 4);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn decode_ms_adpcm_truncated_block_returns_error() {
        // Block smaller than header
        let block = vec![0u8, 0]; // Only 2 bytes, header requires 8
        let result = decode_ms_adpcm(&block, 8, 1, 4);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn decode_ms_adpcm_empty_data_returns_ok_with_empty_output() {
        let result = decode_ms_adpcm(&[], 8, 1, 4).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn decode_ms_adpcm_unsupported_channels() {
        let result = decode_ms_adpcm(&[0; 24], 24, 3, 6);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // ── IMA ADPCM decoder tests ─────────────────────────────────────────

    /// Build a mono IMA ADPCM block: [predictor(2B)][step_index(1B)][reserved(1B)][nibbles...]
    fn build_ima_adpcm_mono_block(predictor: i16, step_index: u8, nibbles: &[u8]) -> Vec<u8> {
        let mut block = Vec::new();
        block.extend_from_slice(&predictor.to_le_bytes());
        block.push(step_index);
        block.push(0); // reserved
        // Pack nibbles: low nibble first
        for pair in nibbles.chunks(2) {
            let low = pair[0] & 0x0F;
            let high = if pair.len() > 1 { pair[1] & 0x0F } else { 0 };
            block.push(low | (high << 4));
        }
        block
    }

    #[test]
    fn decode_ima_adpcm_mono_basic() {
        // Predictor=0, step_index=0, nibbles all zero
        // step = step_table[0] = 7
        // delta = 7>>3 = 0 (integer division)
        // Nibble 0: no bits set, delta = 0
        // Sample stays at 0
        // step_index += index_table[0] = -1, clamped to 0
        let block = build_ima_adpcm_mono_block(0, 0, &[0, 0, 0, 0]);
        let result = decode_ima_adpcm(&block, 1, block.len() as u16).unwrap();

        // Initial sample = 0, then all zeros
        assert_eq!(result[0], 0);
        for &s in &result {
            assert_eq!(s, 0);
        }
    }

    #[test]
    fn decode_ima_adpcm_mono_positive_delta() {
        // Predictor=0, step_index=0
        // nibble = 0x7 (binary 0111): sign=0 (positive), magnitude=7
        // step = 7
        // delta = (7>>3) + (7>>2)*(mag&1) + (7>>1)*(mag&2) + 7*(mag&4)
        //       = 0 + 1*1 + 3*1 + 7*1
        //       = 0 + 1 + 3 + 7 = 11
        // sample = 0 + 11 = 11
        // step_index += index_table[7] = 8, clamped to 8
        let mut block = build_ima_adpcm_mono_block(0, 0, &[0x77]);
        // Let me use nibble=7 (low nibble = 7)
        // byte = 0x07 -> low nibble=7, high nibble=0
        block[4] = 0x07; // Just one nibble=7 in the first byte
        let result = decode_ima_adpcm(&block, 1, block.len() as u16).unwrap();

        // Initial sample = 0
        assert_eq!(result[0], 0);
        // First decoded nibble = 7
        // step = 7, delta = 7>>3 + 7>>2 + 7>>1 + 7 = 0 + 1 + 3 + 7 = 11
        // sample = 0 + 11 = 11
        assert_eq!(result[1], 11);

        // Second nibble (high nibble of byte = 0)
        // step = step_table[8] = 16 (since index went from 0+8=8)
        // delta = 16>>3 = 2
        // sample = 11 + 2 = 13
        // Actually wait, step_index after nibble 7: index_table[7] = 8, so step_index = 0+8 = 8
        // step_table[8] = 16
        // nibble=0 -> delta = 16>>3 = 2
        // sample = 11+2 = 13
        assert_eq!(result[2], 13);
    }

    #[test]
    fn decode_ima_adpcm_mono_negative_nibble() {
        // Predictor=1000, step_index=0
        // nibble = 0x8 (binary 1000): sign=1 (negative), magnitude=0
        // step = 7
        // delta = 7>>3 = 0 (for magnitude=0)
        // With sign bit: delta = -0 = 0
        // sample = 1000 + 0 = 1000
        // step_index += index_table[8] = -1 -> -1 -> clamped to 0
        let mut block = build_ima_adpcm_mono_block(1000, 0, &[0x00]);
        block[4] = 0x08; // low nibble = 8
        let result = decode_ima_adpcm(&block, 1, block.len() as u16).unwrap();

        assert_eq!(result[0], 1000);
        // nibble=8: sign=1, magnitude=0 -> delta = -(7>>3) = 0
        assert_eq!(result[1], 1000);
    }

    #[test]
    fn decode_ima_adpcm_stereo_basic() {
        // Stereo IMA: [ch1_header(4)][ch1_nibbles...][ch2_header(4)][ch2_nibbles...]
        let mut stereo_block = Vec::new();

        // Ch1: predictor=0, step_index=0
        stereo_block.extend_from_slice(&0i16.to_le_bytes());
        stereo_block.push(0);
        stereo_block.push(0);
        stereo_block.push(0x00); // nibbles: 0
        // Pad to block_size/2
        while stereo_block.len() < 8 {
            stereo_block.push(0);
        }

        // Ch2: predictor=0, step_index=0
        stereo_block.extend_from_slice(&0i16.to_le_bytes());
        stereo_block.push(0);
        stereo_block.push(0);
        stereo_block.push(0x00);
        while stereo_block.len() < 16 {
            stereo_block.push(0);
        }

        let block_size = stereo_block.len() as u16;
        let result = decode_ima_adpcm(&stereo_block, 2, block_size).unwrap();

        // Interleaved: [ch1_0, ch2_0, ch1_0, ch2_0, ...]
        // Each channel has 4 header bytes + 4 nibble bytes = 8 bytes per channel
        // 4 nibble bytes × 2 nibbles/byte = 8 decoded + 1 initial = 9 samples/ch
        // 9 × 2 channels = 18 interleaved samples
        assert_eq!(result.len(), 18);
        assert_eq!(result[0], 0); // ch1 initial
        assert_eq!(result[1], 0); // ch2 initial
    }

    #[test]
    fn decode_ima_adpcm_empty_data() {
        let result = decode_ima_adpcm(&[], 1, 4).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn decode_ima_adpcm_unsupported_channels() {
        let result = decode_ima_adpcm(&[0; 8], 3, 4);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // ── XMA decoder tests ───────────────────────────────────────────────

    #[test]
    fn decode_xma_empty_data_returns_error() {
        let result = decode_xma(&[], 2);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn decode_xma_unsupported_channels() {
        let result = decode_xma(&[0; 16], 3);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn decode_xma_silent_frame() {
        // A frame with quant_scale=0 produces silence.
        // Frame header: num_subframes=1, quant_scale=0
        let mut frame = Vec::new();
        // Header bytes (little-endian u32): (1 << 24) | (0 << 16) = 0x01000000
        frame.extend_from_slice(&0x01000000u32.to_le_bytes());
        // Need at least one subframe's worth of data even if silent
        frame.extend_from_slice(&[0u8; 32]); // padding

        let result = decode_xma(&frame, 1).unwrap();
        // Should produce output (XMA_FRAME_SAMPLES samples from silent frame)
        assert!(!result.is_empty());
        // All samples should be 0
        for &s in &result {
            assert_eq!(s, 0);
        }
    }

    #[test]
    fn decode_xma_invalid_frame_header_terminates() {
        // Frame with num_subframes=0 should cause termination
        let frame = vec![0u8; 8]; // header all zeros + padding
        let result = decode_xma(&frame, 1);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn decode_xma_big_endian_detection() {
        // Xbox 360 big-endian format: the first 4 bytes swapped.
        // Little-endian: [0x01, 0x00, 0x00, 0x00] = 0x01000000
        // Big-endian byte-swapped: [0x00, 0x00, 0x00, 0x01]
        let mut frame = vec![0x00u8, 0x00, 0x00, 0x01]; // big-endian: 0x01000000
        // Need some data after header
        frame.extend_from_slice(&[0u8; 64]);

        let result = decode_xma(&frame, 1);
        // Should succeed after byte-swap
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let samples = result.unwrap();
        assert!(!samples.is_empty());
    }

    #[test]
    fn decode_xma_stereo_produces_interleaved_output() {
        // Mono frame data but requesting 2 channels - should still produce output
        let mut frame = Vec::new();
        frame.extend_from_slice(&0x01000000u32.to_le_bytes()); // 1 subframe, quant=0 (silent)
        frame.extend_from_slice(&[0u8; 64]);

        let result = decode_xma(&frame, 2).unwrap();
        assert!(!result.is_empty());
        // Should be interleaved stereo
        assert!(result.len() >= 2);
    }

    #[test]
    fn decode_xma_stereo_output_is_frame_major_interleaved() {
        // Two subframes: channel 0 gets all-zero coefficients (pure silence),
        // channel 1 gets a constant non-zero coefficient, so the decoded
        // output must alternate (zero, non-zero) per frame.
        let mut frame = Vec::new();
        frame.extend_from_slice(&0x02020000u32.to_le_bytes()); // 2 subframes, quant=2
        frame.extend_from_slice(&[0u8; 256]); // subframe 0: all-zero coeffs
        frame.extend_from_slice(&[0x02u8; 256]); // subframe 1: sign-extended -1 coeffs

        let result = decode_xma(&frame, 2).unwrap();
        assert!(!result.is_empty());
        // Even positions (channel 0) are exactly zero; odd positions
        // (channel 1) carry energy.
        for (i, &s) in result.iter().enumerate() {
            if i % 2 == 0 {
                assert_eq!(s, 0);
            }
        }
        assert!(
            result.iter().skip(1).step_by(2).any(|&s| s != 0),
            "channel 1 should contain decoded energy"
        );
    }

    #[test]
    fn convert_and_resample_partial_frame_does_not_panic() {
        // An odd sample count that is not a multiple of the channel count
        // (e.g. a DirectSound write of an odd number of samples) must not
        // panic; the trailing partial frame is dropped.
        let samples = vec![0.5f32, -0.5, 0.25]; // 1.5 frames of stereo
        let result = convert_and_resample(&samples, 2, 48000, 2, 48000);
        assert_eq!(result.len(), 2);
        assert!((result[0] - 0.5).abs() < 0.001);
        assert!((result[1] - (-0.5)).abs() < 0.001);
    }

    #[test]
    fn convert_and_resample_zero_rates_do_not_panic() {
        let samples = vec![0.5f32, -0.5, 0.25, -0.25];
        // source_rate == 0 used to panic on division by zero
        assert!(convert_and_resample(&samples, 2, 0, 2, 48000).is_empty());
        // dest_rate == 0
        assert!(convert_and_resample(&samples, 2, 48000, 2, 0).is_empty());
    }

    // ── convert_game_audio_to_float tests ───────────────────────────────

    #[test]
    fn convert_game_audio_pcm16_to_float() {
        let pcm: Vec<i16> = vec![0, i16::MAX, i16::MIN, 1000];
        let data: Vec<u8> = pcm.iter().flat_map(|s| s.to_le_bytes()).collect();

        let result =
            convert_game_audio_to_float(&data, AudioFormat::Pcm16, 1, 48000, 0, 0).unwrap();
        assert_eq!(result.len(), 4);
        assert!((result[0]).abs() < 0.001);
        assert!((result[1] - 1.0).abs() < 0.001);
        assert!((result[2] - (-1.0)).abs() < 0.001);
        assert!((result[3] - (1000.0 / i16::MAX as f32)).abs() < 0.001);
    }

    #[test]
    fn convert_game_audio_pcm24_to_float() {
        // 24-bit PCM: sample = 0x7FFFFF (positive max)
        let data = vec![0xFF, 0xFF, 0x7F]; // 24-bit LE
        let result =
            convert_game_audio_to_float(&data, AudioFormat::Pcm24, 1, 48000, 0, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert!((result[0] - 1.0).abs() < 0.001);

        // 24-bit PCM: sample = 0 (silence)
        let data = vec![0x00, 0x00, 0x00];
        let result =
            convert_game_audio_to_float(&data, AudioFormat::Pcm24, 1, 48000, 0, 0).unwrap();
        assert!((result[0]).abs() < 0.001);

        // 24-bit PCM: sample = -0x800000 (negative max)
        let data = vec![0x00, 0x00, 0x80];
        let result =
            convert_game_audio_to_float(&data, AudioFormat::Pcm24, 1, 48000, 0, 0).unwrap();
        assert!((result[0] - (-1.0)).abs() < 0.001);
    }

    #[test]
    fn convert_game_audio_pcm32_to_float() {
        let data = i32::MAX.to_le_bytes().to_vec();
        let result =
            convert_game_audio_to_float(&data, AudioFormat::Pcm32, 1, 48000, 0, 0).unwrap();
        assert!((result[0] - 1.0).abs() < 0.001);

        let data = i32::MIN.to_le_bytes().to_vec();
        let result =
            convert_game_audio_to_float(&data, AudioFormat::Pcm32, 1, 48000, 0, 0).unwrap();
        assert!((result[0] - (-1.0)).abs() < 0.001);
    }

    #[test]
    fn convert_game_audio_float32_to_float() {
        let data = 0.5f32.to_le_bytes().to_vec();
        let result =
            convert_game_audio_to_float(&data, AudioFormat::Float32, 1, 48000, 0, 0).unwrap();
        assert!((result[0] - 0.5).abs() < 0.001);
    }

    #[test]
    fn convert_game_audio_ms_adpcm_roundtrip() {
        // Encode: build a simple mono MS ADPCM block, decode via the convenience function
        let block = build_ms_adpcm_mono_block(0, 64, 100, 200, &[0, 0, 0, 0]);
        let result = convert_game_audio_to_float(
            &block,
            AudioFormat::MsAdpcm,
            1,
            22050,
            block.len() as u16,
            6,
        )
        .unwrap();
        assert!(!result.is_empty());
        // First two samples should be 100/32767 and 200/32767 in float
        assert!((result[0] - (100.0 / i16::MAX as f32)).abs() < 0.001);
        assert!((result[1] - (200.0 / i16::MAX as f32)).abs() < 0.001);
    }

    #[test]
    fn convert_game_audio_ima_adpcm_roundtrip() {
        let block = build_ima_adpcm_mono_block(0, 0, &[0, 0, 0, 0]);
        let result = convert_game_audio_to_float(
            &block,
            AudioFormat::ImaAdpcm,
            1,
            22050,
            block.len() as u16,
            0,
        )
        .unwrap();
        assert!(!result.is_empty());
        // All zeros
        for &s in &result {
            assert!((s).abs() < 0.001);
        }
    }

    #[test]
    fn convert_game_audio_xma_roundtrip() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&0x01000000u32.to_le_bytes()); // silent frame
        frame.extend_from_slice(&[0u8; 64]);

        let result = convert_game_audio_to_float(&frame, AudioFormat::Xma, 1, 48000, 0, 0).unwrap();
        assert!(!result.is_empty());
        // Silent frame should produce zeros
        for &s in &result {
            assert!((s).abs() < 0.001);
        }
    }

    #[test]
    fn convert_game_audio_ima_adpcm_positive_nibble_float() {
        let mut block = build_ima_adpcm_mono_block(0, 0, &[0x00]);
        block[4] = 0x07; // nibble = 7
        let result = convert_game_audio_to_float(
            &block,
            AudioFormat::ImaAdpcm,
            1,
            22050,
            block.len() as u16,
            0,
        )
        .unwrap();
        assert!(!result.is_empty());
        // First sample = 0 (initial), second = 11 (decoded)
        // In float: 11/32767 ≈ 0.000336
        assert!((result[0]).abs() < 0.001);
        assert!(result[1] > 0.0);
    }

    // ── IMDCT helper tests ──────────────────────────────────────────────

    #[test]
    fn imdct_zero_input_returns_zero_output() {
        let coeffs = vec![0.0f32; 128]; // half_n = 128 for N=256
        let result = imdct(&coeffs);
        assert_eq!(result.len(), 256);
        for &s in &result {
            assert!((s).abs() < 0.001);
        }
    }

    #[test]
    fn imdct_dc_component() {
        // DC coefficient: only first coeff non-zero
        let mut coeffs = vec![0.0f32; 128];
        coeffs[0] = 1.0;
        let result = imdct(&coeffs);
        assert_eq!(result.len(), 256);
        // Should be non-zero (non-trivial transform)
        let has_energy = result.iter().any(|&s| s.abs() > 0.001);
        assert!(has_energy);
    }

    #[test]
    fn imdct_sine_window_shape() {
        let mut coeffs = vec![0.0f32; 128];
        coeffs[0] = 1.0;
        let result = imdct(&coeffs);
        // Sine window should make edges approach zero
        assert!((result[0]).abs() < 0.1);
        assert!((result[255]).abs() < 0.1);
    }

    // ── AudioFormat enum tests ──────────────────────────────────────────

    #[test]
    fn audio_format_debug_and_clone() {
        let fmt = AudioFormat::MsAdpcm;
        let _debug = format!("{fmt:?}");
        let _clone = fmt;
        assert_eq!(fmt, AudioFormat::MsAdpcm);
    }

    #[test]
    fn audio_format_copy_semantics() {
        let a = AudioFormat::ImaAdpcm;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    // ── XAPO effect tests ────────────────────────────────────────────────

    fn make_reverb_clsid() -> [u8; 16] {
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]
    }

    fn make_lowpass_clsid() -> [u8; 16] {
        [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]
    }

    fn make_highpass_clsid() -> [u8; 16] {
        [
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03,
        ]
    }

    fn make_echo_clsid() -> [u8; 16] {
        [
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04,
        ]
    }

    fn make_compressor_clsid() -> [u8; 16] {
        [
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x05,
        ]
    }

    fn make_normalize_clsid() -> [u8; 16] {
        [
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x06,
        ]
    }

    fn make_equalizer_clsid() -> [u8; 16] {
        [
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x07,
        ]
    }

    #[test]
    fn xapo_reverb_processes_and_resets() {
        let mut reverb = XapoReverb::new(0.5, 48000, 2);
        let reg = reverb.registration();
        // friendly_name should contain "Reverb" via the wide-char encoding
        assert!(reg.friendly_name[0] != 0);
        assert_eq!(reg.flags, XAPO_FLAG_INPLACE);
        assert_eq!(reverb.channels(), 2);
        assert_eq!(reverb.sample_rate(), 48000);

        let input = vec![1.0f32, -1.0, 0.5, -0.5];
        let mut output = vec![0.0f32; 4];
        let _result = reverb.process(&input, &mut output);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        // After reverb processing, output should differ from input
        let changed = input
            .iter()
            .zip(output.iter())
            .any(|(a, b)| (a - b).abs() > 0.001);
        assert!(changed);

        reverb.reset();
        // After reset, processing silence should produce silence
        let silence = vec![0.0f32; 4];
        let mut out2 = vec![1.0f32; 4];
        let _result = reverb.process(&silence, &mut out2);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        for &s in &out2 {
            assert!((s).abs() < 0.001);
        }
    }

    #[test]
    fn xapo_lowpass_attenuates_high_frequencies() {
        let mut lp = XapoLowPass::new(0.2, 1, 48000);
        let reg = lp.registration();
        assert!(reg.friendly_name[0] != 0);

        // Alternating signal (high frequency)
        let input = vec![1.0f32, -1.0, 1.0, -1.0, 1.0, -1.0, 1.0, -1.0];
        let mut output = vec![0.0f32; 8];
        let _result = lp.process(&input, &mut output);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let max_out = output.iter().map(|s| s.abs()).fold(0.0f32, f32::max);
        assert!(max_out < 1.0);
    }

    #[test]
    fn xapo_highpass_blocks_dc() {
        let mut hp = XapoHighPass::new(0.3, 1, 48000);
        let reg = hp.registration();
        assert!(reg.friendly_name[0] != 0);

        // DC signal (constant)
        let input = vec![0.5f32; 16];
        let mut output = vec![0.0f32; 16];
        let _result = hp.process(&input, &mut output);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        // DC should be attenuated toward zero
        let steady_state: f32 = output.iter().skip(8).sum();
        assert!(steady_state.abs() < 1.0);
    }

    #[test]
    fn xapo_echo_produces_delayed_output() {
        let mut echo = XapoEcho::new(10.0, 0.5, 1.0, 1, 100);
        let reg = echo.registration();
        assert!(reg.friendly_name[0] != 0);

        // 10ms delay at 100Hz = 1 frame delay
        // Input: impulse at frame 0
        let input = vec![1.0f32, 0.0, 0.0, 0.0, 0.0];
        let mut output = vec![0.0f32; 5];
        let _result = echo.process(&input, &mut output);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        // With the read-before-write delay line and 1 frame delay,
        // the impulse appears at output[1] (delayed by 1 frame).
        assert!((output[0] - 0.0).abs() < 0.001);
        // Frame 1: delayed impulse (buffer contained 1.0 from frame 0)
        assert!((output[1] - 1.0).abs() < 0.001);
        // Frame 2: first feedback tap (1.0 * 0.5 = 0.5)
        assert!((output[2] - 0.5).abs() < 0.001);
        // Frame 3: second feedback tap (0.5 * 0.5 = 0.25)
        assert!((output[3] - 0.25).abs() < 0.001);
    }

    #[test]
    fn xapo_compressor_reduces_loud_signals() {
        let mut comp = XapoCompressor::new(-6.0, 4.0, 1.0, 10.0, 1, 48000);
        let reg = comp.registration();
        assert!(reg.friendly_name[0] != 0);

        // Loud signal above threshold
        let input = vec![0.8f32; 480]; // 10ms at 48kHz
        let mut output = vec![0.0f32; 480];
        let _result = comp.process(&input, &mut output);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        // Output should be quieter than input
        let avg_out: f32 = output.iter().sum::<f32>() / 480.0;
        assert!(avg_out < 0.8);
    }

    #[test]
    fn xapo_normalize_scales_to_target() {
        let mut norm = XapoNormalize::new(0.5, 1, 48000);
        let reg = norm.registration();
        assert!(reg.friendly_name[0] != 0);

        let input = vec![0.25f32, -0.25, 0.1, -0.1];
        let mut output = vec![0.0f32; 4];
        let _result = norm.process(&input, &mut output);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        // Peak should be scaled toward 0.5
        let max_out = output.iter().map(|s| s.abs()).fold(0.0f32, f32::max);
        assert!((max_out - 0.5).abs() < 0.001);
    }

    #[test]
    fn xapo_manager_register_create_process_destroy() {
        let mut mgr = XapoManager::new();
        mgr.register_builtins();

        assert!(mgr.is_registered(&make_reverb_clsid()));
        assert!(mgr.is_registered(&make_lowpass_clsid()));
        assert!(mgr.is_registered(&make_highpass_clsid()));
        assert!(mgr.is_registered(&make_echo_clsid()));
        assert!(mgr.is_registered(&make_compressor_clsid()));
        assert!(mgr.is_registered(&make_normalize_clsid()));
        assert!(mgr.is_registered(&make_equalizer_clsid()));
        assert_eq!(mgr.registered_count(), 7);

        // Create a reverb instance
        let handle = mgr
            .create_instance(&make_reverb_clsid())
            .expect("reverb should be registered");
        assert!(handle > 0);

        // Process through the instance
        let input = vec![1.0f32, -1.0, 0.5, -0.5];
        let mut output = vec![0.0f32; 4];
        let processed = mgr.process_instance(handle, &input, &mut output);
        assert!(processed);
        let changed = input
            .iter()
            .zip(output.iter())
            .any(|(a, b)| (a - b).abs() > 0.001);
        assert!(changed);

        // Reset
        assert!(mgr.reset_instance(handle));

        // Registration properties for instance
        let props = mgr.instance_registration(handle);
        assert!(props.is_some());

        // Destroy
        assert!(mgr.destroy_instance(handle));
        assert_eq!(mgr.instance_count(), 0);

        // Unknown CLSID should fail
        let unknown_clsid = [0xFF; 16];
        assert!(mgr.create_instance(&unknown_clsid).is_none());
    }

    #[test]
    fn xapo_manager_process_unknown_id_returns_false() {
        let mut mgr = XapoManager::new();
        let mut output = vec![0.0f32; 4];
        assert!(!mgr.process_instance(999, &[1.0; 4], &mut output));
        assert!(!mgr.destroy_instance(999));
        assert!(!mgr.reset_instance(999));
    }

    #[test]
    fn xapo_guid_constants_defined() {
        // Verify the GUID constants exist and have the expected byte counts.
        assert_eq!(CLSID_XAPO.len(), 16);
        assert_eq!(IID_IXAPO.len(), 16);
        assert_eq!(IID_IXAPOParameters.len(), 16);

        // Verify CLSID_XAPO matches the expected string {5EC3B1C3-5E4B-4f4e-B0E0-7B7D1E7B9E7C}
        // Data1 = 0x5EC3B1C3 → LE bytes: [0xC3, 0xB1, 0xC3, 0x5E]
        assert_eq!(CLSID_XAPO[0], 0xC3);
        assert_eq!(CLSID_XAPO[1], 0xB1);
        assert_eq!(CLSID_XAPO[2], 0xC3);
        assert_eq!(CLSID_XAPO[3], 0x5E);
        // Data2 = 0x5E4B → LE bytes: [0x4B, 0x5E]
        assert_eq!(CLSID_XAPO[4], 0x4B);
        assert_eq!(CLSID_XAPO[5], 0x5E);
        // Data3 = 0x4f4e → LE bytes: [0x4E, 0x4F]
        assert_eq!(CLSID_XAPO[6], 0x4E);
        assert_eq!(CLSID_XAPO[7], 0x4F);
    }

    #[test]
    fn xapo_flags_have_correct_values() {
        assert_eq!(XAPO_FLAG_INPLACE, 1);
        assert_eq!(XAPO_FLAG_BUFFERCOUNT_MUST_EQUAL, 4);
        assert_eq!(XAPO_BUFFER_SILENT, 1);
        assert_eq!(XAPO_BUFFER_VALID, 2);
    }

    #[test]
    fn xapo_registration_properties_new_creates_valid_struct() {
        let clsid = make_reverb_clsid();
        let reg = XAPO_REGISTRATION_PROPERTIES::new(clsid, "Test Effect", XAPO_FLAG_INPLACE);
        assert_eq!(reg.clsid, clsid);
        assert_eq!(reg.major_version, 1);
        assert_eq!(reg.minor_version, 0);
        assert_eq!(reg.flags, XAPO_FLAG_INPLACE);
        assert_eq!(reg.min_input_buffer_count, 1);
        assert_eq!(reg.max_input_buffer_count, 1);
        assert_eq!(reg.min_output_buffer_count, 1);
        assert_eq!(reg.max_output_buffer_count, 1);
        // friendly_name should contain 'T' at index 0
        assert_eq!(reg.friendly_name[0], 'T' as u16);
        assert_eq!(reg.friendly_name[1], 'e' as u16);
        assert_eq!(reg.friendly_name[2], 's' as u16);
        assert_eq!(reg.friendly_name[3], 't' as u16);
        // Null terminator after "Test Effect"
        assert_eq!(reg.friendly_name[11], 0);
        // copyright_info should contain "Casa1 XAPO Effect"
        assert_eq!(reg.copyright_info[0], 'C' as u16);
    }

    #[test]
    fn xapo_xapo_buffer_layout() {
        let data: [f32; 4] = [0.0, 0.5, -0.5, 1.0];
        let xb = XAPO_BUFFER {
            buffer: &data as *const f32,
            flags: XAPO_BUFFER_VALID,
            valid_frame_count: 2,
        };
        assert_eq!(xb.flags, XAPO_BUFFER_VALID);
        assert_eq!(xb.valid_frame_count, 2);
        // Verify we can read through the raw pointer
        // SAFETY: the buffer is a live local array; the pointer stays valid for
        // the duration of this test.
        unsafe {
            assert!((*xb.buffer.add(1) - 0.5).abs() < 0.001);
        }
    }
}
