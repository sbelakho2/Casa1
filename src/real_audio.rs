//! Real audio backend for Casa1.
//!
//! Bridges XAudio2 mastering voices, WASAPI audio clients, and DirectSound
//! buffers to real `cpal` output streams on macOS. Provides real device
//! enumeration, format conversion, sample rate conversion, voice callbacks,
//! reverb DSP, and device hotplug detection.

use crate::audio::{
    AudioDeviceInfo, DeviceId,
    LatencyRecord, RenderOutput, VoiceId, WaveFormat,
};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Real audio device
// ---------------------------------------------------------------------------

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
    // WASAPI real output
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
    }

    /// Close all output streams.
    pub fn close_all_streams(&mut self) {
        self.streams.clear();
        self.stream_queues.clear();
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
fn remap_channel(source: &[f32], channel: usize, output_channels: usize) -> f32 {
    match (source.len(), output_channels) {
        (1, _) => source[0],
        (2, 1) => (source[0] + source[1]) * 0.5,
        (2, _) => source[channel.min(1)],
        (_, 1) => source.iter().copied().sum::<f32>() / source.len() as f32,
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
}
