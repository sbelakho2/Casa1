//! Real CoreAudio endpoint enumeration exposed as WASAPI-style descriptors.
//!
//! Device names, channel counts, sample rates, sample formats, buffer bounds,
//! and default-endpoint flags come from the host's real CoreAudio device list
//! (through `cpal`, the same backend the existing audio path uses).  The bridge
//! is query-only: opening a stream stays with the existing `RealAudioBackend`
//! path and the user client refuses stream/control operations exactly.

#[cfg(all(target_os = "macos", not(test)))]
use cpal::traits::{DeviceTrait, HostTrait};

use super::error::DeviceError;
use super::host_bridge::{HostDeviceBridge, HostOperation, HostUserClient, QueryOnlyUserClient};
use super::model::{DeviceClass, DeviceRecord, DeviceTable, HotplugEvent, StableDeviceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AudioEndpointDirection {
    Render,
    Capture,
}

impl AudioEndpointDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Render => "render",
            Self::Capture => "capture",
        }
    }
}

/// Sample formats CoreAudio exposes, named for the WASAPI equivalents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AudioSampleFormat {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
}

impl AudioSampleFormat {
    pub const fn bits_per_sample(self) -> u16 {
        match self {
            Self::I8 | Self::U8 => 8,
            Self::I16 | Self::U16 => 16,
            Self::I32 | Self::U32 | Self::F32 => 32,
            Self::I64 | Self::U64 | Self::F64 => 64,
        }
    }

    pub const fn is_float(self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::I8 => "i8",
            Self::U8 => "u8",
            Self::I16 => "i16",
            Self::U16 => "u16",
            Self::I32 => "i32",
            Self::U32 => "u32",
            Self::I64 => "i64",
            Self::U64 => "u64",
            Self::F32 => "f32",
            Self::F64 => "f64",
        }
    }
}

/// One supported WASAPI-style format range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AudioEndpointFormat {
    pub channels: u16,
    pub min_sample_rate: u32,
    pub max_sample_rate: u32,
    pub sample_format: AudioSampleFormat,
    pub block_align: u16,
    pub min_buffer_frames: Option<u32>,
    pub max_buffer_frames: Option<u32>,
}

impl AudioEndpointFormat {
    pub fn new(
        channels: u16,
        min_sample_rate: u32,
        max_sample_rate: u32,
        sample_format: AudioSampleFormat,
        min_buffer_frames: Option<u32>,
        max_buffer_frames: Option<u32>,
    ) -> Self {
        Self {
            channels,
            min_sample_rate,
            max_sample_rate,
            sample_format,
            block_align: channels.saturating_mul(sample_format.bits_per_sample() / 8),
            min_buffer_frames,
            max_buffer_frames,
        }
    }
}

/// A real CoreAudio endpoint mapped to Windows endpoint metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioEndpointDescriptor {
    pub id: StableDeviceId,
    pub endpoint_id: String,
    pub name: String,
    pub direction: AudioEndpointDirection,
    pub is_default: bool,
    pub channels: u16,
    pub sample_rate: u32,
    pub formats: Vec<AudioEndpointFormat>,
}

impl AudioEndpointDescriptor {
    pub fn from_parts(
        direction: AudioEndpointDirection,
        name: String,
        is_default: bool,
        channels: u16,
        sample_rate: u32,
        mut formats: Vec<AudioEndpointFormat>,
    ) -> Self {
        formats.sort_by_key(|format| {
            (
                format.channels,
                format.min_sample_rate,
                format.max_sample_rate,
                format.sample_format,
                format.block_align,
            )
        });
        formats.dedup();
        let endpoint_id = format!(
            "{}|{}|{}|{}",
            direction.as_str(),
            name,
            channels,
            sample_rate
        );
        let id = StableDeviceId::derive(DeviceClass::Audio, &[&endpoint_id]);
        Self {
            id,
            endpoint_id,
            name,
            direction,
            is_default,
            channels,
            sample_rate,
            formats,
        }
    }

    pub fn record(&self) -> DeviceRecord {
        DeviceRecord {
            id: self.id,
            class: DeviceClass::Audio,
            vendor_id: None,
            product_id: None,
            manufacturer: None,
            product: Some(self.name.clone()),
            serial_number: None,
            path: Some(self.endpoint_id.clone()),
            registry_entry_id: 0,
        }
    }
}

const AUDIO_OPERATIONS: &[HostOperation] = &[HostOperation::Enumerate];

#[derive(Debug, Clone, Default)]
pub struct AudioDeviceBridge {
    devices: Vec<AudioEndpointDescriptor>,
    table: DeviceTable,
}

impl AudioDeviceBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devices(&self) -> &[AudioEndpointDescriptor] {
        &self.devices
    }

    pub fn table(&self) -> &DeviceTable {
        &self.table
    }

    pub fn device(&self, id: StableDeviceId) -> Option<&AudioEndpointDescriptor> {
        self.devices.iter().find(|device| device.id == id)
    }

    pub fn endpoints(&self) -> Vec<AudioEndpointDescriptor> {
        self.devices.clone()
    }

    pub fn apply(&mut self, devices: Vec<AudioEndpointDescriptor>) -> Vec<HotplugEvent> {
        let mut devices = devices;
        devices.sort_by_key(|device| (device.id, !device.is_default));
        devices.dedup_by_key(|device| device.id);
        let records = devices
            .iter()
            .map(AudioEndpointDescriptor::record)
            .collect();
        self.devices = devices;
        self.table.reconcile(records)
    }

    pub fn enumerate(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        let devices = scan_audio_endpoints()?;
        Ok(self.apply(devices))
    }
}

impl HostDeviceBridge for AudioDeviceBridge {
    fn class(&self) -> DeviceClass {
        DeviceClass::Audio
    }

    fn enumerate(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        AudioDeviceBridge::enumerate(self)
    }

    fn records(&self) -> Vec<DeviceRecord> {
        self.table.records()
    }

    fn record(&self, id: StableDeviceId) -> Option<DeviceRecord> {
        self.table.get(id).cloned()
    }

    fn supported_operations(&self) -> &'static [HostOperation] {
        AUDIO_OPERATIONS
    }

    fn open_user_client(&self, id: StableDeviceId) -> Result<Box<dyn HostUserClient>, DeviceError> {
        let device = self.device(id).ok_or(DeviceError::DeviceMissing { id })?;
        Ok(Box::new(QueryOnlyUserClient::new(
            device.id,
            DeviceClass::Audio,
        )))
    }
}

#[cfg(all(target_os = "macos", not(test)))]
pub fn scan_audio_endpoints() -> Result<Vec<AudioEndpointDescriptor>, DeviceError> {
    let host = cpal::default_host();
    let mut endpoints = Vec::new();
    let default_render = host
        .default_output_device()
        .and_then(|device| device.name().ok());
    let output_devices = host.output_devices().map_err(|_| DeviceError::Io {
        operation: "cpal output_devices",
        os_code: 0,
    })?;
    for device in output_devices {
        if let Some(endpoint) = cpal_endpoint(
            &device,
            AudioEndpointDirection::Render,
            default_render.as_deref(),
        ) {
            endpoints.push(endpoint);
        }
    }
    let default_capture = host
        .default_input_device()
        .and_then(|device| device.name().ok());
    let input_devices = host.input_devices().map_err(|_| DeviceError::Io {
        operation: "cpal input_devices",
        os_code: 0,
    })?;
    for device in input_devices {
        if let Some(endpoint) = cpal_endpoint(
            &device,
            AudioEndpointDirection::Capture,
            default_capture.as_deref(),
        ) {
            endpoints.push(endpoint);
        }
    }
    endpoints.sort_by_key(|endpoint| endpoint.id);
    Ok(endpoints)
}

#[cfg(all(target_os = "macos", not(test)))]
fn cpal_endpoint(
    device: &cpal::Device,
    direction: AudioEndpointDirection,
    default_name: Option<&str>,
) -> Option<AudioEndpointDescriptor> {
    let name = device.name().ok()?;
    let is_default = default_name == Some(name.as_str());
    let (channels, sample_rate, formats) = match direction {
        AudioEndpointDirection::Render => {
            let default = device.default_output_config().ok()?;
            let mut formats = device
                .supported_output_configs()
                .ok()
                .map(|ranges| ranges.filter_map(cpal_format_range).collect::<Vec<_>>())
                .unwrap_or_default();
            if formats.is_empty() {
                formats.push(cpal_default_format(
                    default.channels(),
                    default.sample_rate().0,
                    default.sample_format(),
                )?);
            }
            (default.channels(), default.sample_rate().0, formats)
        }
        AudioEndpointDirection::Capture => {
            let default = device.default_input_config().ok()?;
            let mut formats = device
                .supported_input_configs()
                .ok()
                .map(|ranges| ranges.filter_map(cpal_format_range).collect::<Vec<_>>())
                .unwrap_or_default();
            if formats.is_empty() {
                formats.push(cpal_default_format(
                    default.channels(),
                    default.sample_rate().0,
                    default.sample_format(),
                )?);
            }
            (default.channels(), default.sample_rate().0, formats)
        }
    };
    Some(AudioEndpointDescriptor::from_parts(
        direction,
        name,
        is_default,
        channels,
        sample_rate,
        formats,
    ))
}

#[cfg(all(target_os = "macos", not(test)))]
fn cpal_format_range(range: cpal::SupportedStreamConfigRange) -> Option<AudioEndpointFormat> {
    let sample_format = cpal_sample_format(range.sample_format())?;
    let (min_buffer, max_buffer) = match *range.buffer_size() {
        cpal::SupportedBufferSize::Range { min, max } => (Some(min), Some(max)),
        cpal::SupportedBufferSize::Unknown => (None, None),
    };
    Some(AudioEndpointFormat::new(
        range.channels(),
        range.min_sample_rate().0,
        range.max_sample_rate().0,
        sample_format,
        min_buffer,
        max_buffer,
    ))
}

#[cfg(all(target_os = "macos", not(test)))]
fn cpal_default_format(
    channels: u16,
    sample_rate: u32,
    sample_format: cpal::SampleFormat,
) -> Option<AudioEndpointFormat> {
    Some(AudioEndpointFormat::new(
        channels,
        sample_rate,
        sample_rate,
        cpal_sample_format(sample_format)?,
        None,
        None,
    ))
}

#[cfg(all(target_os = "macos", not(test)))]
fn cpal_sample_format(format: cpal::SampleFormat) -> Option<AudioSampleFormat> {
    Some(match format {
        cpal::SampleFormat::I8 => AudioSampleFormat::I8,
        cpal::SampleFormat::U8 => AudioSampleFormat::U8,
        cpal::SampleFormat::I16 => AudioSampleFormat::I16,
        cpal::SampleFormat::U16 => AudioSampleFormat::U16,
        cpal::SampleFormat::I32 => AudioSampleFormat::I32,
        cpal::SampleFormat::U32 => AudioSampleFormat::U32,
        cpal::SampleFormat::I64 => AudioSampleFormat::I64,
        cpal::SampleFormat::U64 => AudioSampleFormat::U64,
        cpal::SampleFormat::F32 => AudioSampleFormat::F32,
        cpal::SampleFormat::F64 => AudioSampleFormat::F64,
        _ => return None,
    })
}

#[cfg(test)]
pub fn scan_audio_endpoints() -> Result<Vec<AudioEndpointDescriptor>, DeviceError> {
    Ok(Vec::new())
}

#[cfg(all(not(target_os = "macos"), not(test)))]
pub fn scan_audio_endpoints() -> Result<Vec<AudioEndpointDescriptor>, DeviceError> {
    Err(DeviceError::Unsupported {
        feature: "audio enumeration requires macOS CoreAudio",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(
        name: &str,
        direction: AudioEndpointDirection,
        is_default: bool,
    ) -> AudioEndpointDescriptor {
        AudioEndpointDescriptor::from_parts(
            direction,
            name.to_string(),
            is_default,
            2,
            48_000,
            vec![
                AudioEndpointFormat::new(
                    2,
                    44_100,
                    48_000,
                    AudioSampleFormat::F32,
                    Some(64),
                    Some(4096),
                ),
                AudioEndpointFormat::new(
                    2,
                    44_100,
                    48_000,
                    AudioSampleFormat::F32,
                    Some(64),
                    Some(4096),
                ),
                AudioEndpointFormat::new(2, 44_100, 44_100, AudioSampleFormat::I16, None, None),
            ],
        )
    }

    #[test]
    fn audio_absent_endpoint_and_unsupported_stream_operation_are_exact() {
        let mut bridge = AudioDeviceBridge::new();
        let id = StableDeviceId::from_raw(0xa0d10);
        assert_eq!(
            bridge.open_user_client(id).map(|_| ()),
            Err(DeviceError::DeviceMissing { id })
        );
        let descriptor = endpoint("Speakers", AudioEndpointDirection::Render, true);
        let _ = bridge.apply(vec![descriptor.clone()]);
        let client = bridge
            .open_user_client(descriptor.id)
            .expect("open real audio endpoint fixture");
        assert_eq!(client.device_id(), descriptor.id);
        assert_eq!(client.class(), DeviceClass::Audio);
        assert_eq!(bridge.class(), DeviceClass::Audio);
        assert_eq!(bridge.operation_support(HostOperation::Enumerate), Ok(()));
        assert_eq!(
            bridge.operation_support(HostOperation::AudioStream),
            Err(DeviceError::Unsupported {
                feature: "audio stream open"
            })
        );
    }

    #[test]
    fn audio_format_mapping_and_duplicate_endpoints_are_exact() {
        let formats = [
            (AudioSampleFormat::I8, 8, false, "i8"),
            (AudioSampleFormat::U8, 8, false, "u8"),
            (AudioSampleFormat::I16, 16, false, "i16"),
            (AudioSampleFormat::U16, 16, false, "u16"),
            (AudioSampleFormat::I32, 32, false, "i32"),
            (AudioSampleFormat::U32, 32, false, "u32"),
            (AudioSampleFormat::I64, 64, false, "i64"),
            (AudioSampleFormat::U64, 64, false, "u64"),
            (AudioSampleFormat::F32, 32, true, "f32"),
            (AudioSampleFormat::F64, 64, true, "f64"),
        ];
        for (format, bits, float, name) in formats {
            assert_eq!(format.bits_per_sample(), bits);
            assert_eq!(format.is_float(), float);
            assert_eq!(format.as_str(), name);
        }

        let descriptor = endpoint("Speakers", AudioEndpointDirection::Render, true);
        assert_eq!(descriptor.formats.len(), 2);
        assert_eq!(descriptor.formats[0].block_align, 4);
        assert_eq!(descriptor.formats[1].block_align, 8);
        assert_eq!(descriptor.formats[0].sample_format, AudioSampleFormat::I16);
        assert_eq!(
            descriptor.endpoint_id,
            "render|Speakers|2|48000".to_string()
        );
        assert_eq!(
            descriptor.record().path.as_deref(),
            Some("render|Speakers|2|48000")
        );
        assert_eq!(descriptor.record().class, DeviceClass::Audio);
        assert_ne!(
            AudioEndpointDescriptor::from_parts(
                AudioEndpointDirection::Capture,
                "Speakers".to_string(),
                false,
                2,
                48_000,
                Vec::new()
            )
            .id,
            descriptor.id
        );

        let mut bridge = AudioDeviceBridge::new();
        let mut non_default = descriptor.clone();
        non_default.is_default = false;
        assert_eq!(
            bridge.apply(vec![non_default, descriptor.clone()]),
            vec![HotplugEvent::Arrived(descriptor.record())]
        );
        assert_eq!(bridge.devices().len(), 1);
        assert!(bridge.devices()[0].is_default);
        assert_eq!(bridge.endpoints(), vec![descriptor.clone()]);
        assert_eq!(bridge.table().len(), 1);
        assert_eq!(bridge.device(descriptor.id), Some(&descriptor));
    }

    #[test]
    fn audio_hotplug_duplicate_apply_is_idempotent_and_removal_is_exact() {
        let mut bridge = AudioDeviceBridge::new();
        assert_eq!(bridge.refresh(), Ok(Vec::new()));
        let descriptor = endpoint("Microphone", AudioEndpointDirection::Capture, true);
        assert_eq!(
            bridge.apply(vec![descriptor.clone(), descriptor.clone()]),
            vec![HotplugEvent::Arrived(descriptor.record())]
        );
        assert_eq!(
            bridge.apply(vec![descriptor.clone()]),
            Vec::<HotplugEvent>::new()
        );
        assert_eq!(
            bridge.apply(Vec::new()),
            vec![HotplugEvent::Removed {
                record: descriptor.record()
            }]
        );
        assert_eq!(bridge.records(), Vec::new());
        assert_eq!(bridge.record(descriptor.id), None);
    }
}
