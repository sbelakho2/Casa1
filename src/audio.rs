use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::process::{Command as HostCommand, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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
}

#[derive(Debug, Clone)]
enum VoiceKind {
    Mastering { device_id: DeviceId },
    Submix { destination: VoiceId, reverb_mix: f32 },
    Source {
        destination: VoiceId,
        queue: VecDeque<QueuedBuffer>,
        played_frames: u64,
    },
}

#[derive(Debug, Clone)]
struct VoiceRecord {
    format: WaveFormat,
    started: bool,
    volume: f32,
    channel_volumes: Vec<f32>,
    output_matrix: Vec<f32>,
    kind: VoiceKind,
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

#[derive(Debug, Clone)]
struct DirectSoundRecord {
    device_id: DeviceId,
}

#[derive(Debug, Clone)]
struct DirectSoundBufferRecord {
    device_id: DeviceId,
    format: WaveFormat,
    samples: Vec<f32>,
    cursor: usize,
    playing: bool,
}

#[derive(Debug, Clone)]
pub struct AudioSubsystem {
    next_id: u64,
    devices: BTreeMap<DeviceId, AudioDeviceRecord>,
    default_device: DeviceId,
    voices: BTreeMap<VoiceId, VoiceRecord>,
    audio_clients: BTreeMap<AudioClientId, AudioClientRecord>,
    direct_sound: BTreeMap<DirectSoundId, DirectSoundRecord>,
    direct_sound_buffers: BTreeMap<DirectSoundBufferId, DirectSoundBufferRecord>,
    notifications: Vec<String>,
    latency_log: Vec<LatencyRecord>,
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
            notifications: Vec::new(),
            latency_log: Vec::new(),
        }
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
        self.notifications.push(format!("device_added:{id}:{name}"));
        id
    }

    pub fn remove_device(&mut self, device: DeviceId) -> AppResult<()> {
        let record = self.device_mut(device)?;
        record.plugged = false;
        record.info.is_default = false;
        self.notifications.push(format!("device_removed:{device}"));
        if self.default_device == device {
            let replacement = self
                .devices
                .values()
                .find(|candidate| candidate.plugged)
                .map(|candidate| candidate.info.id)
                .ok_or_else(|| AppError::new(ReasonCode::RcAudioUnsupported, "no audio devices remain"))?;
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
        self.notifications.push(format!("default_changed:{old_default}->{device}"));

        let active_mastering = self
            .voices
            .iter()
            .filter_map(|(voice_id, voice)| match voice.kind {
                VoiceKind::Mastering { .. } if voice.started => Some(*voice_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        if !active_mastering.is_empty() {
            self.notifications.push(format!("playback_stop:{old_default}"));
            for voice_id in active_mastering {
                if let VoiceKind::Mastering { device_id } = &mut self.voice_mut(voice_id)?.kind {
                    *device_id = device;
                }
            }
            self.notifications.push(format!("playback_recover:{device}"));
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
            },
        );
        Ok(id)
    }

    pub fn create_submix_voice(&mut self, format: WaveFormat, destination: VoiceId) -> AppResult<VoiceId> {
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
            },
        );
        Ok(id)
    }

    pub fn create_source_voice(&mut self, format: WaveFormat, destination: VoiceId) -> AppResult<VoiceId> {
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
            },
        );
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
        let (source_format, destination) = {
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
            (voice_record.format.clone(), destination)
        };
        let destination_rate = self.voice(destination)?.format.sample_rate;
        let samples = convert_samples(buffer.samples);
        let resampled = resample_interleaved(
            &samples,
            source_format.channels as usize,
            source_format.sample_rate,
            destination_rate,
        );
        let frame_count = resampled.len() / source_format.channels as usize;
        let record = self.voice_mut(voice)?;
        match &mut record.kind {
            VoiceKind::Source { queue, .. } => queue.push_back(QueuedBuffer {
                tag: buffer.tag,
                samples: resampled,
                frames: frame_count,
                cursor: 0,
            }),
            _ => unreachable!(),
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
        self.voices.remove(&voice).map(|_| ()).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, format!("unknown voice {voice}"))
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
                VoiceKind::Submix { destination, .. } | VoiceKind::Source { destination, .. } => Some(destination),
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

    pub fn render_xaudio2(&mut self, mastering: VoiceId, frames: usize) -> AppResult<RenderOutput> {
        if !matches!(self.voice(mastering)?.kind, VoiceKind::Mastering { .. }) {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "render_xaudio2 requires a mastering voice",
            ));
        }
        let mut voice_callbacks = Vec::new();
        let mut underflow_frames = 0;
        let samples = self.render_voice_mix(mastering, frames, &mut voice_callbacks, &mut underflow_frames)?;
        let device_id = match self.voice(mastering)?.kind {
            VoiceKind::Mastering { device_id } => device_id,
            _ => unreachable!(),
        };
        let latency_ms = measure_latency_ms(self.voice(mastering)?.format.sample_rate, frames);
        self.latency_log.push(LatencyRecord {
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
            .map_err(|error| AppError::from_io(ReasonCode::RcIo, "failed to launch afplay for rendered audio", &error))?;
        let _ = fs::remove_file(&temp_path);
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

    pub fn drain_audio_client(&mut self, client: AudioClientId, frames: usize) -> AppResult<RenderOutput> {
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
        self.latency_log.push(LatencyRecord {
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

    pub fn create_direct_sound8(&mut self, device: DeviceId) -> AppResult<DirectSoundId> {
        self.device(device)?;
        let id = self.alloc_id();
        self.direct_sound.insert(id, DirectSoundRecord { device_id: device });
        Ok(id)
    }

    pub fn create_direct_sound_buffer(
        &mut self,
        direct_sound: DirectSoundId,
        format: WaveFormat,
    ) -> AppResult<DirectSoundBufferId> {
        self.validate_format(&format)?;
        let device_id = self
            .direct_sound
            .get(&direct_sound)
            .ok_or_else(|| AppError::new(ReasonCode::RcAudioUnsupported, "unknown DirectSound object"))?
            .device_id;
        let id = self.alloc_id();
        self.direct_sound_buffers.insert(
            id,
            DirectSoundBufferRecord {
                cursor: 0,
                device_id,
                format,
                playing: false,
                samples: Vec::new(),
            },
        );
        Ok(id)
    }

    pub fn write_direct_sound_buffer(&mut self, buffer: DirectSoundBufferId, samples: &[f32]) -> AppResult<()> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        let channels = record.format.channels as usize;
        if !samples.len().is_multiple_of(channels) {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "DirectSound writes must align to channel count",
            ));
        }
        record.samples = samples.to_vec();
        record.cursor = 0;
        Ok(())
    }

    pub fn play_direct_sound_buffer(&mut self, buffer: DirectSoundBufferId) -> AppResult<()> {
        self.direct_sound_buffer_mut(buffer)?.playing = true;
        Ok(())
    }

    pub fn stop_direct_sound_buffer(&mut self, buffer: DirectSoundBufferId) -> AppResult<()> {
        self.direct_sound_buffer_mut(buffer)?.playing = false;
        Ok(())
    }

    pub fn mix_direct_sound_buffer(&mut self, buffer: DirectSoundBufferId, frames: usize) -> AppResult<RenderOutput> {
        let record = self.direct_sound_buffer_mut(buffer)?;
        let channels = record.format.channels as usize;
        let mut samples = Vec::with_capacity(frames * channels);
        for _ in 0..frames {
            for channel in 0..channels {
                let index = record.cursor * channels + channel;
                let sample = if record.playing && index < record.samples.len() {
                    record.samples[index]
                } else {
                    0.0
                };
                samples.push(sample);
            }
            if record.playing {
                record.cursor += 1;
            }
        }
        let latency_ms = measure_latency_ms(record.format.sample_rate, frames);
        let device_id = record.device_id;
        self.latency_log.push(LatencyRecord {
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
        let (format, started, volume, channel_volumes, kind_snapshot) = {
            let record = self.voice(voice)?;
            (
                record.format.clone(),
                record.started,
                record.volume,
                record.channel_volumes.clone(),
                record.kind.clone(),
            )
        };
        let channels = format.channels as usize;
        if !started {
            return Ok(vec![0.0; frames * channels]);
        }
        match kind_snapshot {
            VoiceKind::Mastering { .. } => {
                let child_ids = self.child_voice_ids(voice);
                let mut mix = vec![0.0; frames * channels];
                for child in child_ids {
                    let child_mix = self.render_voice_mix(child, frames, callbacks, underflow_frames)?;
                    let projected = self.project_to_parent(child, &child_mix, channels)?;
                    mix_in_place(&mut mix, &projected);
                }
                apply_levels(&mut mix, channels, volume, &channel_volumes);
                Ok(mix)
            }
            VoiceKind::Submix { reverb_mix, .. } => {
                let child_ids = self.child_voice_ids(voice);
                let mut mix = vec![0.0; frames * channels];
                for child in child_ids {
                    let child_mix = self.render_voice_mix(child, frames, callbacks, underflow_frames)?;
                    let projected = self.project_to_parent(child, &child_mix, channels)?;
                    mix_in_place(&mut mix, &projected);
                }
                if reverb_mix > 0.0 {
                    apply_reverb(&mut mix, channels, reverb_mix);
                }
                apply_levels(&mut mix, channels, volume, &channel_volumes);
                Ok(mix)
            }
            VoiceKind::Source { .. } => {
                let mut mix = self.consume_source_frames(voice, frames, callbacks, underflow_frames)?;
                apply_levels(&mut mix, channels, volume, &channel_volumes);
                Ok(mix)
            }
        }
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
                        queue.pop_front();
                    }
                    let Some(buffer) = queue.front_mut() else {
                        *underflow_frames += 1;
                        continue;
                    };
                    let sample_offset = buffer.cursor * channels;
                    let frame_samples = &buffer.samples[sample_offset..sample_offset + channels];
                    let write_offset = frame_index * channels;
                    mix[write_offset..write_offset + channels].copy_from_slice(frame_samples);
                    buffer.cursor += 1;
                    if buffer.cursor == buffer.frames {
                        callbacks.push(VoiceCallbackEvent {
                            voice,
                            event: "OnBufferEnd".to_string(),
                            tag: buffer.tag.clone(),
                            sample_offset: *played_frames + frame_index as u64 + 1,
                        });
                    }
                }
                *played_frames += frames as u64;
            }
            _ => unreachable!(),
        }
        Ok(mix)
    }

    fn child_voice_ids(&self, parent: VoiceId) -> Vec<VoiceId> {
        self.voices
            .iter()
            .filter_map(|(voice_id, voice)| match voice.kind {
                VoiceKind::Submix { destination, .. } | VoiceKind::Source { destination, .. }
                    if destination == parent =>
                {
                    Some(*voice_id)
                }
                _ => None,
            })
            .collect()
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
        let sample_rate_supported = matches!(format.sample_rate, 44_100 | 48_000 | 24_000);
        let channels_supported = matches!(format.channels, 1 | 2);
        if !sample_rate_supported || !channels_supported {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                "unsupported audio format requested",
            ));
        }
        match format.sample_format {
            SampleFormat::Pcm16 | SampleFormat::Float32 => Ok(()),
        }
    }

    fn device(&self, device: DeviceId) -> AppResult<&AudioDeviceRecord> {
        self.devices.get(&device).filter(|device| device.plugged).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, format!("unknown audio device {device}"))
        })
    }

    fn device_mut(&mut self, device: DeviceId) -> AppResult<&mut AudioDeviceRecord> {
        self.devices.get_mut(&device).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, format!("unknown audio device {device}"))
        })
    }

    fn voice(&self, voice: VoiceId) -> AppResult<&VoiceRecord> {
        self.voices.get(&voice).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, format!("unknown voice {voice}"))
        })
    }

    fn voice_mut(&mut self, voice: VoiceId) -> AppResult<&mut VoiceRecord> {
        self.voices.get_mut(&voice).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, format!("unknown voice {voice}"))
        })
    }

    fn audio_client(&self, client: AudioClientId) -> AppResult<&AudioClientRecord> {
        self.audio_clients.get(&client).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, format!("unknown audio client {client}"))
        })
    }

    fn audio_client_mut(&mut self, client: AudioClientId) -> AppResult<&mut AudioClientRecord> {
        self.audio_clients.get_mut(&client).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, format!("unknown audio client {client}"))
        })
    }

    fn direct_sound_buffer_mut(&mut self, buffer: DirectSoundBufferId) -> AppResult<&mut DirectSoundBufferRecord> {
        self.direct_sound_buffers.get_mut(&buffer).ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, format!("unknown DirectSound buffer {buffer}"))
        })
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
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
    let destination_frames = ((source_frames as u64 * destination_rate as u64) / source_rate as u64) as usize;
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

fn default_output_matrix(source_channels: usize, destination_channels: usize) -> Vec<f32> {
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
    for frame in 0..samples.len() / channels {
        for channel in 0..channels {
            let index = frame * channels + channel;
            samples[index] += previous[channel] * wet;
            previous[channel] = samples[index];
        }
    }
}

fn mix_in_place(destination: &mut [f32], source: &[f32]) {
    for (dst, src) in destination.iter_mut().zip(source.iter()) {
        *dst += *src;
    }
}

fn measure_latency_ms(sample_rate: u32, buffered_frames: usize) -> u32 {
    ((((buffered_frames as f32 / sample_rate as f32) * 1000.0).round() as u32) + 10).min(50)
}