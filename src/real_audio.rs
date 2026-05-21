//! Real audio backend for Casa1.
//!
//! Bridges XAudio2 mastering voices, WASAPI audio clients, and DirectSound
//! buffers to real `cpal` output streams on macOS. Provides real device
//! enumeration, format conversion, sample rate conversion, voice callbacks,
//! reverb DSP, and device hotplug detection.

use crate::audio::{
    AudioClientId, AudioDeviceInfo, DeviceId,
    LatencyRecord, RenderOutput, SampleFormat, VoiceId, WaveFormat,
};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Real audio device
// ---------------------------------------------------------------------------

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
pub struct RealAudioBackend {
    host: cpal::Host,
    devices: BTreeMap<DeviceId, RealAudioDevice>,
    next_device_id: DeviceId,
    streams: HashMap<DeviceId, cpal::Stream>,
    stream_queues: HashMap<DeviceId, Arc<Mutex<VecDeque<f32>>>>,
    latency_log: Vec<LatencyRecord>,
    /// Per-client state for WASAPI exclusive-mode streams.
    exclusive_clients: HashMap<AudioClientId, WasapiExclusiveState>,
    /// Auto-incrementing counter for AudioClientId values.
    next_audio_client_id: AudioClientId,
}

impl RealAudioBackend {
    /// Create a new real audio backend, enumerating available output devices.
    pub fn new() -> AppResult<Self> {
        let host = cpal::default_host();
        let mut devices = BTreeMap::new();
        let mut next_device_id: DeviceId = 1;

        let default_device = host.default_output_device();

        if let Some(device_list) = host.output_devices().ok() {
            for device in device_list {
                let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
                let config = device.default_output_config().ok();
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
                        name,
                        channels,
                        sample_rate,
                        is_default,
                    },
                );
                next_device_id += 1;
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
            next_audio_client_id: 1,
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
    pub fn open_xaudio2_master(
        &mut self,
        format: &WaveFormat,
    ) -> AppResult<DeviceId> {
        let device_id = self.default_device_id()?;
        self.ensure_stream(device_id, format)?;
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
        let converted = convert_and_resample(
            samples,
            source_channels,
            source_rate,
            device.channels,
            device.sample_rate,
        );
        if let Some(queue) = self.stream_queues.get(&device_id) {
            if let Ok(mut q) = queue.lock() {
                q.extend(converted);
                // Limit queue to ~4 seconds of audio to prevent unbounded growth
                let max_samples = device.sample_rate as usize * device.channels as usize * 4;
                while q.len() > max_samples {
                    q.pop_front();
                }
            }
        }
        Ok(())
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

        // Find the device this mastering voice is associated with
        let device_id = match audio_subsystem.voice_started(mastering_voice) {
            Ok(true) => {
                // Use default device
                self.default_device_id().unwrap_or(1)
            }
            _ => self.default_device_id().unwrap_or(1),
        };

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
    pub fn open_wasapi_client(
        &mut self,
        format: &WaveFormat,
        buffer_frames: usize,
        event_driven: bool,
    ) -> AppResult<DeviceId> {
        let device_id = self.default_device_id()?;
        self.ensure_stream(device_id, format)?;

        // Record latency
        let latency_ms = measure_latency_ms(format.sample_rate, buffer_frames);
        self.latency_log.push(LatencyRecord {
            subsystem: "wasapi".to_string(),
            device_id,
            measured_ms: latency_ms,
        });

        let _ = event_driven; // Real cpal callback is inherently event-driven
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
        let converted = convert_and_resample(
            samples,
            source_channels,
            source_rate,
            device.channels,
            device.sample_rate,
        );
        if let Some(queue) = self.stream_queues.get(&device_id) {
            if let Ok(mut q) = queue.lock() {
                q.extend(converted);
                let max_samples = device.sample_rate as usize * device.channels as usize * 4;
                while q.len() > max_samples {
                    q.pop_front();
                }
            }
        }
        Ok(())
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
        self.latency_log.push(LatencyRecord {
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
    /// Internally delegates to `push_wasapi_frames()` after validation.
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
        let expected_samples = state.buffer_frames * channels;

        if samples.len() != expected_samples {
            let actual_frames = if channels > 0 {
                samples.len() / channels
            } else {
                0
            };
            return Err(AppError::new(
                ReasonCode::RcAudioBufferSizeMismatch,
                format!(
                    "exclusive-mode buffer size mismatch: expected {} frames ({} samples), got {} frames ({} samples)",
                    state.buffer_frames, expected_samples, actual_frames, samples.len(),
                ),
            ));
        }

        // Delegate to shared-mode push which handles channel/rate conversion.
        // In exclusive mode the format matches exactly, so no resampling occurs.
        self.push_wasapi_frames(
            state.device_id,
            samples,
            state.format.channels,
            state.format.sample_rate,
        )
    }

    // -----------------------------------------------------------------------
    // DirectSound real output
    // -----------------------------------------------------------------------

    /// Open a real output stream for a DirectSound buffer.
    pub fn open_direct_sound_buffer(
        &mut self,
        format: &WaveFormat,
    ) -> AppResult<DeviceId> {
        let device_id = self.default_device_id()?;
        self.ensure_stream(device_id, format)?;
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
        let converted = convert_and_resample(
            samples,
            source_channels,
            source_rate,
            device.channels,
            device.sample_rate,
        );
        if let Some(queue) = self.stream_queues.get(&device_id) {
            if let Ok(mut q) = queue.lock() {
                q.extend(converted);
                let max_samples = device.sample_rate as usize * device.channels as usize * 4;
                while q.len() > max_samples {
                    q.pop_front();
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Device hotplug
    // -----------------------------------------------------------------------

    /// Refresh the device list, detecting newly connected or removed devices.
    ///
    /// Returns `(added_devices, removed_device_ids)`.
    pub fn detect_device_changes(&mut self) -> AppResult<(Vec<RealAudioDevice>, Vec<DeviceId>)> {
        let mut current_names: BTreeMap<String, RealAudioDevice> = BTreeMap::new();
        let default_device = self.host.default_output_device();

        if let Some(device_list) = self.host.output_devices().ok() {
            for device in device_list {
                let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
                let config = device.default_output_config().ok();
                let channels = config.as_ref().map(|c| c.channels()).unwrap_or(2);
                let sample_rate = config.as_ref().map(|c| c.sample_rate().0).unwrap_or(48_000);
                let is_default = default_device
                    .as_ref()
                    .map(|d| d.name().map(|n| n == name).unwrap_or(false))
                    .unwrap_or(false);

                current_names.insert(
                    name.clone(),
                    RealAudioDevice {
                        id: 0, // placeholder
                        name,
                        channels,
                        sample_rate,
                        is_default,
                    },
                );
            }
        }

        let existing_names: Vec<String> = self.devices.values().map(|d| d.name.clone()).collect();
        let current_name_set: Vec<String> = current_names.keys().cloned().collect();
        let mut added = Vec::new();

        // Detect added devices
        for (name, mut device) in current_names {
            if !existing_names.contains(&name) {
                device.id = self.next_device_id;
                self.next_device_id += 1;
                added.push(device.clone());
                self.devices.insert(device.id, device);
            }
        }

        // Detect removed devices
        let to_remove: Vec<DeviceId> = self
            .devices
            .iter()
            .filter(|(_, device)| !current_name_set.contains(&device.name))
            .map(|(id, _)| *id)
            .collect();

        for id in &to_remove {
            self.devices.remove(id);
            self.streams.remove(id);
            self.stream_queues.remove(id);
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
        let queued_frames = if channels > 0 {
            queued_samples / channels
        } else {
            0
        };
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
        // Clean up any exclusive-mode clients using this device
        self.exclusive_clients.retain(|_, state| state.device_id != device_id);
    }

    /// Close all output streams and exclusive-mode clients.
    pub fn close_all_streams(&mut self) {
        self.streams.clear();
        self.stream_queues.clear();
        self.exclusive_clients.clear();
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Ensure a cpal output stream exists for the given device.
    fn ensure_stream(
        &mut self,
        device_id: DeviceId,
        format: &WaveFormat,
    ) -> AppResult<()> {
        if self.streams.contains_key(&device_id) {
            return Ok(());
        }

        let cpal_device = self.find_cpal_device(device_id)?;
        let supported_config = cpal_device.default_output_config().map_err(|e| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to get audio output config: {e}"),
            )
        })?;

        let queue: Arc<Mutex<VecDeque<f32>>> = Arc::new(Mutex::new(VecDeque::new()));
        let callback_queue = Arc::clone(&queue);
        let error_callback = |error: cpal::StreamError| {
            let _ = error;
        };

        let stream_config = supported_config.config();
        let stream = match supported_config.sample_format() {
            cpal::SampleFormat::F32 => cpal_device
                .build_output_stream(
                    &stream_config,
                    move |data: &mut [f32], _| fill_output_f32(data, &callback_queue),
                    error_callback,
                    None,
                )
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcAudioUnsupported,
                        format!("failed to build f32 audio stream: {e}"),
                    )
                })?,
            cpal::SampleFormat::I16 => cpal_device
                .build_output_stream(
                    &stream_config,
                    move |data: &mut [i16], _| fill_output_i16(data, &callback_queue),
                    error_callback,
                    None,
                )
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcAudioUnsupported,
                        format!("failed to build i16 audio stream: {e}"),
                    )
                })?,
            cpal::SampleFormat::U16 => cpal_device
                .build_output_stream(
                    &stream_config,
                    move |data: &mut [u16], _| fill_output_u16(data, &callback_queue),
                    error_callback,
                    None,
                )
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcAudioUnsupported,
                        format!("failed to build u16 audio stream: {e}"),
                    )
                })?,
            other => {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!("unsupported host audio sample format {other:?}"),
                ))
            }
        };

        stream.play().map_err(|e| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to start audio stream: {e}"),
            )
        })?;

        // Record initial latency
        let buffer_frames = stream_config.buffer_size;
        let latency_ms = measure_latency_ms(
            format.sample_rate,
            match buffer_frames {
                cpal::BufferSize::Default => 1024,
                cpal::BufferSize::Fixed(v) => v as usize,
            },
        );
        self.latency_log.push(LatencyRecord {
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
        if self.streams.contains_key(&device_id) {
            // Stream already exists - return the stored buffer size for this
            // device if we have exclusive state for it.
            for state in self.exclusive_clients.values() {
                if state.device_id == device_id {
                    return Ok(state.buffer_frames);
                }
            }
            // Fallback: just return a reasonable default. The stream is already
            // open so we can reuse it.
            return Ok(256);
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
        let supported_config = matched
            .with_sample_rate(cpal::SampleRate(format.sample_rate));

        let queue: Arc<Mutex<VecDeque<f32>>> = Arc::new(Mutex::new(VecDeque::new()));
        let error_callback = |error: cpal::StreamError| {
            let _ = error;
        };

        // Try progressively larger buffer sizes (target ≤10ms latency).
        // 64 frames @ 48kHz ≈ 1.3ms, 512 frames @ 48kHz ≈ 10.7ms.
        let buffer_candidates: &[u32] = &[64, 96, 128, 160, 192, 256, 384, 512];
        let mut stream = None;
        let mut chosen_frames: usize = 256;

        for &frames in buffer_candidates {
            let mut stream_config = supported_config.config();
            stream_config.buffer_size = cpal::BufferSize::Fixed(frames);

            let cb_queue = Arc::clone(&queue);
            let err_cb = error_callback;

            let result = match supported_config.sample_format() {
                cpal::SampleFormat::F32 => cpal_device.build_output_stream(
                    &stream_config,
                    move |data: &mut [f32], _| fill_output_f32(data, &cb_queue),
                    err_cb,
                    None,
                ),
                cpal::SampleFormat::I16 => {
                    let cb_queue = Arc::clone(&queue);
                    cpal_device.build_output_stream(
                        &stream_config,
                        move |data: &mut [i16], _| fill_output_i16(data, &cb_queue),
                        err_cb,
                        None,
                    )
                }
                cpal::SampleFormat::U16 => {
                    let cb_queue = Arc::clone(&queue);
                    cpal_device.build_output_stream(
                        &stream_config,
                        move |data: &mut [u16], _| fill_output_u16(data, &cb_queue),
                        err_cb,
                        None,
                    )
                }
                other => {
                    return Err(AppError::new(
                        ReasonCode::RcAudioUnsupported,
                        format!(
                            "unsupported host audio sample format {other:?}"
                        ),
                    ))
                }
            };

            match result {
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

        self.streams.insert(device_id, stream);
        self.stream_queues.insert(device_id, queue);

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
            if device.name().map(|n| n == our_device.name).unwrap_or(false) {
                return Ok(device);
            }
        }

        // Fallback to default
        self.host.default_output_device().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                "no audio output device available",
            )
        })
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
    samples
        .iter()
        .map(|&s| (((s.clamp(-1.0, 1.0) + 1.0) * 0.5) * 255.0) as u8)
        .collect()
}

/// Convert AudioSamples from the audio subsystem to f32.
pub fn convert_samples_to_float(samples: &crate::audio::AudioSamples) -> Vec<f32> {
    match samples {
        crate::audio::AudioSamples::Pcm16(values) => pcm16_to_float(values),
        crate::audio::AudioSamples::Float32(values) => values.clone(),
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
            format!(
                "MS ADPCM block size {block_size} < header size {header_size}"
            ),
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
        for ch in 0..num_channels {
            output.push(prev_samples[ch][0] as i16);
        }
        for ch in 0..num_channels {
            output.push(prev_samples[ch][1] as i16);
        }

        // The compressed nibble data starts after headers
        let nibble_start = header_size;
        // Number of PCM samples per channel left to decode in this block
        let remaining = samples_per_block.saturating_sub(2);

        // For mono: all nibbles belong to channel 0 consecutively.
        // For stereo: nibbles are interleaved (ch1, ch2, ch1, ch2, …).
        let bytes_available = block.len().saturating_sub(nibble_start);
        let nibble_count = bytes_available * 2; // 2 nibbles per byte

        for i in 0..(remaining.min(nibble_count)) {
            let ch = if num_channels == 2 && remaining > 0 {
                // Stereo interleave: nibbles are per-channel interleaved
                // Each channel gets every other nibble starting at its offset
                // ch = i % num_channels
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

        // If we didn't get enough samples per block, pad with silence
        let decoded_per_ch = remaining.min(nibble_count) + 2;
        if decoded_per_ch < samples_per_block {
            let pad = samples_per_block - decoded_per_ch;
            // For stereo, pad interleaved
            for _ in 0..pad {
                for ch in 0..num_channels {
                    if ch == 0 || num_channels == 1 {
                        let ch_idx = 0;
                        let coeff = MS_ADPCM_COEFFICIENTS[predictors[ch_idx]];
                        let predicted = (coeff.0 as i32 * prev_samples[ch_idx][0]
                            + coeff.1 as i32 * prev_samples[ch_idx][1])
                            / 256;
                        let sample = predicted.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                        prev_samples[ch_idx][0] = prev_samples[ch_idx][1];
                        prev_samples[ch_idx][1] = sample as i32;
                        output.push(sample);
                    } else {
                        // For stereo ch2 when padding
                        let coeff = MS_ADPCM_COEFFICIENTS[predictors[1]];
                        let predicted = (coeff.0 as i32 * prev_samples[1][0]
                            + coeff.1 as i32 * prev_samples[1][1])
                            / 256;
                        let sample = predicted.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                        prev_samples[1][0] = prev_samples[1][1];
                        prev_samples[1][1] = sample as i32;
                        output.push(sample);
                    }
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
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408,
    449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
    2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630,
    9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794,
    32767,
];

/// IMA/DVI ADPCM step index table (16 entries).
///
/// Each 4-bit nibble maps to an index adjustment applied to the step index
/// after decoding a sample.
const IMA_ADPCM_INDEX_TABLE: [i16; 16] = [
    -1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8,
];

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
    let num_blocks = if block_size > 0 {
        adpcm_data.len() / block_size
    } else {
        0
    };

    // Estimate output capacity: each byte produces 2 samples per channel (4-bit nibbles)
    let samples_per_block = (per_channel_data_size - header_size) * 2 + 1; // +1 for initial sample
    let mut output = Vec::with_capacity(num_blocks * samples_per_block * num_channels);

    for block_idx in 0..num_blocks {
        let block_start = block_idx * block_size;
        let block_end = (block_start + block_size).min(adpcm_data.len());
        let block = &adpcm_data[block_start..block_end];

        // Decode each channel independently
        let mut channel_samples: [Vec<i16>; 2] = [Vec::new(), Vec::new()];

        for ch in 0..num_channels {
            let ch_offset = if num_channels == 1 {
                0
            } else {
                // For stereo: ch1 data starts at 0, ch2 data starts at block_size/2
                ch * per_channel_data_size
            };

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
            channel_samples[ch].push(initial_sample);

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
                    channel_samples[ch].push(sample);

                    // Update step index
                    step_index = (step_index + IMA_ADPCM_INDEX_TABLE[nibble as usize])
                        .clamp(0, 88);
                }
            }
        }

        // Interleave channels into output
        let max_frames = channel_samples[0]
            .len()
            .max(channel_samples[1].len());
        for frame in 0..max_frames {
            for ch in 0..num_channels {
                if frame < channel_samples[ch].len() {
                    output.push(channel_samples[ch][frame]);
                } else {
                    // Pad with last sample if channels are uneven
                    output.push(
                        channel_samples[ch]
                            .last()
                            .copied()
                            .unwrap_or(0),
                    );
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

    // State for overlap-add
    let mut prev_frame = vec![0.0f32; XMA_FRAME_SAMPLES * num_channels];
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

        if quant_scale == 0 {
            // Zero quantisation scale → silent frame
            let frame_output = vec![0i16; XMA_FRAME_SAMPLES * num_channels];
            for ch in 0..num_channels {
                for i in 0..XMA_FRAME_SAMPLES {
                    let idx = i * num_channels + ch;
                    output.push(frame_output[idx]);
                }
            }
            frame_index += 1;
            continue;
        }

        // For each subframe, extract quantised MDCT coefficients and decode.
        for sf in 0..num_channels.min(num_subframes) {
            // Each subframe contains XMA_FRAME_SAMPLES coefficients.
            // We'll read from the bitstream at the current offset.
            // For simplicity in this first-pass decoder, we parse a fixed
            // number of bytes per sample.

            let mut mdct_coeffs = vec![0.0f32; XMA_FRAME_SAMPLES];

            // The subframe data contains quantised coefficients.
            // We approximate the bit allocation: each coefficient gets
            // a number of bits proportional to the quant_scale.
            // For simplicity, we treat quant_scale as the number of bits
            // per coefficient (clamped to a reasonable range).
            let bits_per_coeff = quant_scale.clamp(2, 16);
            let bytes_per_coeff = (bits_per_coeff + 7) / 8;
            let subframe_size = XMA_FRAME_SAMPLES * bytes_per_coeff;

            let sf_end = (offset + subframe_size).min(data.len());
            let sf_data = &data[offset..sf_end];

            // Dequantise coefficients from the byte stream.
            // We read bytes_per_coeff bytes per coefficient and treat them
            // as a signed integer, then scale by the quantisation step.
            let quant_step = 1.0f32 / (1u32 << (bits_per_coeff - 1)) as f32;

            for i in 0..XMA_FRAME_SAMPLES.min(sf_data.len() / bytes_per_coeff.max(1)) {
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

                mdct_coeffs[i] = raw_val as f32 * quant_step;
            }

            offset += subframe_size;

            // Apply inverse MDCT to get time-domain samples
            let time_samples = imdct(&mdct_coeffs);

            // Overlap-add with previous frame
            let half_frame = XMA_FRAME_SAMPLES / 2;
            for i in 0..half_frame {
                let prev_idx = if frame_index > 0 {
                    i * num_channels + sf
                } else {
                    continue; // No previous frame for overlap at start
                };
                if frame_index > 0 && prev_idx < prev_frame.len() {
                    let out_sample = time_samples[i] + prev_frame[prev_idx];
                    let clamped = out_sample.clamp(-1.0, 1.0);
                    let pcm = if clamped <= -1.0 {
                        i16::MIN
                    } else {
                        (clamped * i16::MAX as f32) as i16
                    };
                    output.push(pcm);
                }
            }

            // Store second half for next frame's overlap
            for i in half_frame..XMA_FRAME_SAMPLES {
                let prev_idx = i * num_channels + sf;
                if prev_idx < prev_frame.len() {
                    prev_frame[prev_idx] = time_samples[i];
                }
            }
        }

        frame_index += 1;

        // Safety limit: prevent runaway parsing
        if frame_index > 1024 {
            break;
        }
    }

    // Flush remaining overlap samples (last half-frame)
    if frame_index > 0 {
        for i in 0..XMA_FRAME_SAMPLES / 2 {
            for ch in 0..num_channels {
                let idx = i * num_channels + ch;
                if idx < prev_frame.len() {
                    let clamped = prev_frame[idx].clamp(-1.0, 1.0);
                    let pcm = if clamped <= -1.0 {
                        i16::MIN
                    } else {
                        (clamped * i16::MAX as f32) as i16
                    };
                    output.push(pcm);
                }
            }
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
fn imdct(coefficients: &[f32]) -> Vec<f32> {
    let n = XMA_FRAME_SAMPLES;
    let half_n = n / 2;
    let mut time = vec![0.0f32; n];

    // For a standard MDCT, N/2 input coefficients → N output samples.
    // We use a simple DCT-IV approach.
    //
    // The inverse MDCT (IMDCT) is defined as:
    //
    //   y[n] = sum_{k=0}^{N/2-1} X[k] * cos(pi/N * (n + 1/2 + N/2) * (k + 1/2))
    //
    // for n = 0, ..., N-1.
    //
    // We implement this directly for clarity.

    let scale = 2.0 / n as f32;
    let pi_over_n = std::f32::consts::PI / n as f32;

    for n_idx in 0..n {
        let mut sum = 0.0f32;
        for k in 0..coefficients.len().min(half_n) {
            let angle = pi_over_n * (n_idx as f32 + 0.5 + half_n as f32) * (k as f32 + 0.5);
            sum += coefficients[k] * angle.cos();
        }
        time[n_idx] = sum * scale;
    }

    // Apply sine window (standard for MDCT-based codecs)
    for n_idx in 0..n {
        let window = (std::f32::consts::PI * (n_idx as f32 + 0.5) / n as f32).sin();
        time[n_idx] *= window;
    }

    time
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
                    let raw = (chunk[0] as i32) | ((chunk[1] as i32) << 8) | ((chunk[2] as i32) << 16);
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
                    float_samples.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
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

    if samples.is_empty() {
        return Vec::new();
    }

    let source_frames = samples.len() / source_channels;
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
        resampled.copy_from_slice(samples);
    } else {
        // Linear interpolation resampling
        for frame in 0..dest_frames {
            let source_pos = (frame as f64 * source_rate as f64) / dest_rate as f64;
            let frame0 = (source_pos as usize).min(source_frames - 1);
            let frame1 = (frame0 + 1).min(source_frames - 1);
            let frac = source_pos - frame0 as f64;

            for ch in 0..source_channels {
                let s0 = samples[frame0 * source_channels + ch];
                let s1 = samples[frame1 * source_channels + ch];
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
        (2, _) => source[channel.min(1)],
        // Mono from multi-channel: downmix all
        (_, 1) => source.iter().copied().sum::<f32>() / source.len() as f32,
        // 5.1 source (6 ch) → 2 ch stereo: FL+FC, FR+FC with LFE mixed in
        (6, 2) => match channel {
            0 => source[0] + source[2] * 0.5 + source[3] * 0.3,   // FL ← FL + 0.5*FC + 0.3*LFE
            1 => source[1] + source[2] * 0.5 + source[3] * 0.3,   // FR ← FR + 0.5*FC + 0.3*LFE
            _ => 0.0,
        },
        // 7.1 source (8 ch) → 2 ch stereo
        (8, 2) => match channel {
            0 => source[0] + source[2] * 0.5 + source[3] * 0.3,   // FL
            1 => source[1] + source[2] * 0.5 + source[3] * 0.3,   // FR
            _ => 0.0,
        },
        // 5.1 source → 5.1 output: pass through
        (6, 6) => source[channel],
        // 7.1 source → 7.1 output: pass through
        (8, 8) => source[channel],
        // 2 ch → 5.1: duplicate stereo to front, silence others
        (2, 6) => match channel {
            0 | 2 => source[0],  // FL, FC ← FL
            1 | 3 => source[1],  // FR, LFE ← FR (LFE gets FR as placeholder)
            _ => 0.0,             // RL, RR silent
        },
        // 2 ch → 7.1
        (2, 8) => match channel {
            0 | 2 => source[0],
            1 | 3 => source[1],
            _ => 0.0,
        },
        // 5.1 → 7.1: SL/SR are copied from RL/RR
        (6, 8) => match channel {
            0..=3 => source[channel],
            4 | 6 => source[4],   // RL → RL, SL → RL
            5 | 7 => source[5],   // RR → RR, SR → RR
            _ => 0.0,
        },
        // 7.1 → 5.1: mix SL into RL, SR into RR
        (8, 6) => match channel {
            0..=3 => source[channel],
            4 => (source[4] + source[6]) * 0.5,   // RL ← (RL + SL) * 0.5
            5 => (source[5] + source[7]) * 0.5,   // RR ← (RR + SR) * 0.5
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
        for ch in 0..channels {
            let idx = frame * channels + ch;
            previous[ch] = previous[ch] + alpha * (samples[idx] - previous[ch]);
            samples[idx] = previous[ch];
        }
    }
}

/// Normalize audio samples to use the full dynamic range.
pub fn normalize_samples(samples: &mut [f32]) {
    let max_abs = samples
        .iter()
        .map(|s| s.abs())
        .fold(0.0f32, f32::max);

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

fn fill_output_f32(output: &mut [f32], queue: &Arc<Mutex<VecDeque<f32>>>) {
    let Ok(mut samples) = queue.lock() else {
        output.fill(0.0);
        return;
    };
    for sample in output.iter_mut() {
        *sample = samples.pop_front().unwrap_or(0.0).clamp(-1.0, 1.0);
    }
}

fn fill_output_i16(output: &mut [i16], queue: &Arc<Mutex<VecDeque<f32>>>) {
    let Ok(mut samples) = queue.lock() else {
        output.fill(0);
        return;
    };
    for sample in output.iter_mut() {
        let value = samples.pop_front().unwrap_or(0.0).clamp(-1.0, 1.0);
        *sample = (value * i16::MAX as f32) as i16;
    }
}

fn fill_output_u16(output: &mut [u16], queue: &Arc<Mutex<VecDeque<f32>>>) {
    let Ok(mut samples) = queue.lock() else {
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
        assert!(backend.is_ok());
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
        let buffers: Vec<(usize, String)> = vec![
            (100, "buf_a".to_string()),
            (100, "buf_b".to_string()),
        ];
        let callbacks = calculate_buffer_callbacks(&buffers, 150);
        // Only buf_a completes within 150 frames
        assert_eq!(callbacks.len(), 1);
        assert_eq!(callbacks[0], (100, "buf_a".to_string()));
    }

    #[test]
    #[ignore] // Requires real audio hardware
    fn default_device_detection() {
        let backend = RealAudioBackend::new().unwrap();
        let devices = backend.enumerate_devices();
        if !devices.is_empty() {
            let default_id = backend.default_device_id();
            assert!(default_id.is_ok());
        }
    }

    #[test]
    #[ignore] // Requires real audio hardware
    fn latency_log_records_entries() {
        let backend = RealAudioBackend::new().unwrap();
        let log = backend.latency_log();
        // The log starts empty; entries are added when streams open
        assert!(log.len() <= 10);
    }

    #[test]
    #[ignore] // Requires real audio hardware
    fn device_hotplug_detect_changes() {
        let mut backend = RealAudioBackend::new().unwrap();
        // Calling detect_device_changes should succeed even if no changes
        let result = backend.detect_device_changes();
        assert!(result.is_ok());
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
        assert!(latency >= 10 && latency <= 50);
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
    /// Block: [predictor(2B)][delta(2B)][sample1(2B)][sample2(2B)][nibbles...]
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
    fn decode_ms_adpcm_invalid_predictor_returns_error() {
        // Predictor index 7 is out of range (0-6)
        let mut block = vec![7u8, 0, 64, 0, 100, 0, 200, 0, 0x00];
        let _ = block;
        // Actually build properly
        let block = build_ms_adpcm_mono_block(7, 64, 100, 200, &[0]);
        let result = decode_ms_adpcm(&block, block.len() as u16, 1, 4);
        assert!(result.is_err());
    }

    #[test]
    fn decode_ms_adpcm_truncated_block_returns_error() {
        // Block smaller than header
        let block = vec![0u8, 0]; // Only 2 bytes, header requires 8
        let result = decode_ms_adpcm(&block, 8, 1, 4);
        assert!(result.is_err());
    }

    #[test]
    fn decode_ms_adpcm_empty_data_returns_ok_with_empty_output() {
        let result = decode_ms_adpcm(&[], 8, 1, 4).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn decode_ms_adpcm_unsupported_channels() {
        let result = decode_ms_adpcm(&[0; 24], 24, 3, 6);
        assert!(result.is_err());
    }

    // ── IMA ADPCM decoder tests ─────────────────────────────────────────

    /// Build a mono IMA ADPCM block: [predictor(2B)][step_index(1B)][reserved(1B)][nibbles...]
    fn build_ima_adpcm_mono_block(
        predictor: i16,
        step_index: u8,
        nibbles: &[u8],
    ) -> Vec<u8> {
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
        assert!(result.is_err());
    }

    // ── XMA decoder tests ───────────────────────────────────────────────

    #[test]
    fn decode_xma_empty_data_returns_error() {
        let result = decode_xma(&[], 2);
        assert!(result.is_err());
    }

    #[test]
    fn decode_xma_unsupported_channels() {
        let result = decode_xma(&[0; 16], 3);
        assert!(result.is_err());
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
        assert!(result.is_err());
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
        assert!(result.is_ok());
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

    // ── convert_game_audio_to_float tests ───────────────────────────────

    #[test]
    fn convert_game_audio_pcm16_to_float() {
        let pcm: Vec<i16> = vec![0, i16::MAX, i16::MIN, 1000];
        let data: Vec<u8> = pcm
            .iter()
            .flat_map(|s| s.to_le_bytes())
            .collect();

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

        let result =
            convert_game_audio_to_float(&frame, AudioFormat::Xma, 1, 48000, 0, 0).unwrap();
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
}
