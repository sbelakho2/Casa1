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
    /// Whether CoreAudio hog mode backs this exclusive client (and, when not,
    /// why the client-side contract is in force).
    pub hog_mode: HogModeOutcome,
}

/// A real audio output device discovered via `cpal`.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Real period/latency values of the device backing a WASAPI audio client,
/// in `REFERENCE_TIME` (100 ns) units.
///
/// The values come from the cpal device's own output configuration (its
/// supported buffer-size range when the host exposes one); a sample-rate
/// derived default (10 ms default / 3 ms minimum) is used only when the
/// device cannot be queried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevicePeriodInfo {
    /// Device sample rate the periods are measured at.
    pub sample_rate: u32,
    /// Default device period.
    pub default_period_hns: u64,
    /// Minimum device period.
    pub minimum_period_hns: u64,
    /// Stream latency of a buffer-sized period on this device.
    pub stream_latency_hns: u64,
}

// ---------------------------------------------------------------------------
// System-wide loopback capture (CoreAudio process taps / ScreenCaptureKit)
// ---------------------------------------------------------------------------

/// Seconds of real system-output history retained for loopback clients.
pub const SYSTEM_LOOPBACK_HISTORY_SECONDS: u32 = 4;

/// Which real system-output capture backend the host can provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemLoopbackBackend {
    /// CoreAudio process tap (`AudioHardwareCreateProcessTap` +
    /// `CATapDescription`, macOS 14.2+).
    CoreAudioProcessTap,
    /// ScreenCaptureKit audio capture (`SCStream.capturesAudio`).
    ScreenCaptureKit,
    /// No host system-output capture API is available.
    Unavailable,
}

/// A pinned reason a system-loopback capture could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemLoopbackFailure {
    /// No host backend is available (non-macOS, old macOS, or forced off).
    Unavailable,
    /// The tap description object could not be created.
    ObjectUnavailable,
    /// `AudioHardwareCreateProcessTap` failed with this `OSStatus`.
    TapCreation(i32),
    /// `AudioHardwareCreateAggregateDevice` failed with this `OSStatus`.
    AggregateCreation(i32),
    /// `AudioDeviceStart` failed with this `OSStatus`.
    StreamStart(i32),
    /// The tap's stream format is not the backed 32-bit float shape.
    FormatUnavailable,
}

/// Pure capability classification (testable without touching the host).
pub fn classify_system_loopback_probe(
    process_tap_available: bool,
    screen_capture_kit_available: bool,
    forced_off: bool,
) -> SystemLoopbackBackend {
    if forced_off {
        SystemLoopbackBackend::Unavailable
    } else if process_tap_available {
        SystemLoopbackBackend::CoreAudioProcessTap
    } else if screen_capture_kit_available {
        SystemLoopbackBackend::ScreenCaptureKit
    } else {
        SystemLoopbackBackend::Unavailable
    }
}

/// Map a failure at `stage` (with its `OSStatus`) to a pinned reason.
pub fn classify_system_loopback_failure(
    stage: SystemLoopbackFailure,
    status: i32,
) -> SystemLoopbackFailure {
    match stage {
        SystemLoopbackFailure::TapCreation(_) => SystemLoopbackFailure::TapCreation(status),
        SystemLoopbackFailure::AggregateCreation(_) => {
            SystemLoopbackFailure::AggregateCreation(status)
        }
        SystemLoopbackFailure::StreamStart(_) => SystemLoopbackFailure::StreamStart(status),
        other => other,
    }
}

/// Probe the host for a real system-output capture backend.
///
/// `CASA1_SYSTEM_LOOPBACK=off` (or `0`) forces the internal render-history
/// fallback; unset (or `auto`) probes the host.
pub fn system_loopback_capability() -> SystemLoopbackBackend {
    #[cfg(test)]
    {
        // Tests never touch the developer's real system audio unless a test
        // explicitly overrides this.  The real probe is still available
        // through `probe_system_loopback_capability_for_test`.
        test_system_loopback_capability_override().unwrap_or(SystemLoopbackBackend::Unavailable)
    }
    #[cfg(not(test))]
    {
        probe_system_loopback_capability()
    }
}

/// The real host probe (bypasses the test override).
pub(crate) fn probe_system_loopback_capability() -> SystemLoopbackBackend {
    let forced_off = std::env::var("CASA1_SYSTEM_LOOPBACK")
        .map(|value| {
            let value = value.trim();
            value.eq_ignore_ascii_case("off") || value == "0"
        })
        .unwrap_or(false);
    classify_system_loopback_probe(
        process_tap_available(),
        screen_capture_kit_available(),
        forced_off,
    )
}

/// Real host probe for capability-gated tests.
#[cfg(test)]
pub(crate) fn probe_system_loopback_capability_for_test() -> SystemLoopbackBackend {
    probe_system_loopback_capability()
}

#[cfg(target_os = "macos")]
fn process_tap_available() -> bool {
    platform::process_tap_symbols_available()
}

#[cfg(not(target_os = "macos"))]
fn process_tap_available() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn screen_capture_kit_available() -> bool {
    platform::screen_capture_kit_available()
}

#[cfg(not(target_os = "macos"))]
fn screen_capture_kit_available() -> bool {
    false
}

/// The real captured samples and counters shared with the host callback.
///
/// The callback runs on the host audio thread, so ingestion never blocks it:
/// a contended lock drops that callback's frames instead of stalling audio.
#[derive(Debug)]
struct SystemLoopbackSink {
    /// The generation this sink belongs to (the session's generation).
    generation: u64,
    /// The generation currently allowed to publish frames.  Teardown bumps
    /// this before stopping the host stream, so late callbacks from a stale
    /// tap/stream are dropped instead of leaking into a replacement session.
    live_generation: u64,
    channels: u16,
    sample_rate: u32,
    samples: VecDeque<f32>,
    frames_delivered: u64,
    dropped_frames: u64,
}

impl SystemLoopbackSink {
    fn new(generation: u64, channels: u16, sample_rate: u32) -> Self {
        Self {
            generation,
            live_generation: generation,
            channels: channels.max(1),
            sample_rate: sample_rate.max(1),
            samples: VecDeque::new(),
            frames_delivered: 0,
            dropped_frames: 0,
        }
    }

    fn max_samples(&self) -> usize {
        (self.sample_rate.max(1) as usize)
            .saturating_mul(self.channels.max(1) as usize)
            .saturating_mul(SYSTEM_LOOPBACK_HISTORY_SECONDS as usize)
    }

    fn live(&self, generation: u64) -> bool {
        generation == self.live_generation && generation == self.generation
    }

    /// Invalidate `generation` and discard its buffered frames.
    fn stop(&mut self, generation: u64) {
        if self.generation == generation {
            self.live_generation = generation.wrapping_add(1);
            self.samples.clear();
        }
    }

    /// Append interleaved f32 system frames for `generation`.
    ///
    /// Returns `true` when the frames were accepted.  A stale generation (an
    /// old tap callback racing teardown) is rejected without touching the
    /// buffer.  If the callback's real format differs from the negotiated tap
    /// format, the session adopts the callback's format and restarts its
    /// history (the real stream renegotiated, so old frames are not
    /// compatible).
    fn ingest(
        &mut self,
        generation: u64,
        channels: u16,
        sample_rate: u32,
        interleaved: &[f32],
    ) -> bool {
        if !self.live(generation) {
            return false;
        }
        let channels = channels.max(1);
        let sample_rate = sample_rate.max(1);
        if channels != self.channels || sample_rate != self.sample_rate {
            self.channels = channels;
            self.sample_rate = sample_rate;
            self.samples.clear();
        }
        if interleaved.is_empty() {
            return true;
        }
        let max_samples = self.max_samples();
        let drop = self
            .samples
            .len()
            .saturating_add(interleaved.len())
            .saturating_sub(max_samples);
        let drop = drop.min(self.samples.len());
        for _ in 0..drop {
            self.samples.pop_front();
        }
        self.dropped_frames = self
            .dropped_frames
            .saturating_add((drop / self.channels.max(1) as usize) as u64);
        let room = max_samples.saturating_sub(self.samples.len());
        let take = interleaved.len().min(room);
        if take < interleaved.len() {
            self.dropped_frames = self.dropped_frames.saturating_add(
                ((interleaved.len() - take) / self.channels.max(1) as usize) as u64,
            );
        }
        self.samples.extend(
            interleaved[interleaved.len().saturating_sub(take)..]
                .iter()
                .copied(),
        );
        self.frames_delivered = self
            .frames_delivered
            .saturating_add((take / self.channels.max(1) as usize) as u64);
        true
    }
}

/// One live system-loopback capture session.
struct SystemLoopbackSession {
    backend: SystemLoopbackBackend,
    generation: u64,
    shared: Arc<Mutex<SystemLoopbackSink>>,
    /// Host teardown; dropped exactly once by [`RealAudioBackend::stop_system_loopback`].
    stop: Option<Box<dyn FnOnce() + Send>>,
}

impl SystemLoopbackSession {
    fn stop(&mut self) {
        {
            let mut sink = self
                .shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            sink.stop(self.generation);
        }
        if let Some(stop) = self.stop.take() {
            stop();
        }
        // Host teardown synchronizes its callback; clear once more so a
        // callback that passed the generation check before teardown cannot
        // leave frames behind.
        let mut sink = self
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sink.samples.clear();
    }
}

/// Observable system-loopback state (tests / diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemLoopbackSnapshot {
    pub capability: SystemLoopbackBackend,
    pub running: bool,
    pub backend: Option<SystemLoopbackBackend>,
    pub generation: u64,
    pub channels: u16,
    pub sample_rate: u32,
    pub buffered_frames: u64,
    pub frames_delivered: u64,
    pub dropped_frames: u64,
}

#[cfg(test)]
static TEST_SYSTEM_LOOPBACK_CAPABILITY: Mutex<Option<SystemLoopbackBackend>> = Mutex::new(None);

/// Serializes every test that drives the process-global system-loopback seam
/// (the capability override, the fault injector and the live test session).
#[cfg(test)]
static TEST_NEXT_EXCLUSIVE_STREAM_OPEN: Mutex<Option<Result<usize, i32>>> = Mutex::new(None);

/// Force the next exclusive-mode stream open to succeed with `frames` or fail
/// with `status` (test seam: the real open needs a live output device).
#[cfg(test)]
pub(crate) fn force_next_exclusive_stream_open(result: Option<Result<usize, i32>>) {
    *TEST_NEXT_EXCLUSIVE_STREAM_OPEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = result;
}

#[cfg(test)]
static SYSTEM_LOOPBACK_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn lock_system_loopback_tests() -> std::sync::MutexGuard<'static, ()> {
    SYSTEM_LOOPBACK_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Force the probed system-loopback capability for a test (serialized by the
/// caller against other loopback tests).
#[cfg(test)]
pub(crate) fn set_test_system_loopback_capability(backend: Option<SystemLoopbackBackend>) {
    *TEST_SYSTEM_LOOPBACK_CAPABILITY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = backend;
}

#[cfg(test)]
fn test_system_loopback_capability_override() -> Option<SystemLoopbackBackend> {
    *TEST_SYSTEM_LOOPBACK_CAPABILITY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
static TEST_NEXT_SYSTEM_LOOPBACK_FAILURE: Mutex<Option<SystemLoopbackFailure>> = Mutex::new(None);

/// Force the next [`RealAudioBackend::start_system_loopback`] to fail with
/// `reason` (test seam used by the loopback fallback tests).
#[cfg(test)]
pub(crate) fn force_next_system_loopback_failure(reason: Option<SystemLoopbackFailure>) {
    *TEST_NEXT_SYSTEM_LOOPBACK_FAILURE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = reason;
}

#[cfg(test)]
fn take_forced_system_loopback_failure() -> Option<SystemLoopbackFailure> {
    TEST_NEXT_SYSTEM_LOOPBACK_FAILURE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
}

// ---------------------------------------------------------------------------
// CoreAudio hog mode (true hardware-exclusive access)
// ---------------------------------------------------------------------------

/// The real outcome of a CoreAudio hog-mode request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HogModeOutcome {
    /// This process now owns hog mode on the device.
    Acquired,
    /// This process already owned hog mode on the device.
    AlreadyHeld,
    /// Another process owns hog mode; the client-side contract is used.
    Denied { owner_pid: i32 },
    /// The host/device cannot provide hog mode; the client-side contract is
    /// used.
    Unavailable,
}

impl HogModeOutcome {
    /// Whether the device is genuinely hogged by this process.
    pub fn is_exclusive(self) -> bool {
        matches!(self, HogModeOutcome::Acquired | HogModeOutcome::AlreadyHeld)
    }
}

/// The host operations an exclusive-mode open needs for true hog mode.
///
/// Split behind a trait so the acquisition/denial/rate-failure transitions are
/// adversarially testable without grabbing the developer's real output device.
pub(crate) trait HogModeDriver {
    fn hog_owner(&mut self) -> Result<i32, i32>;
    fn set_hog(&mut self) -> Result<i32, i32>;
    fn release_hog(&mut self) -> Result<(), i32>;
    fn set_nominal_sample_rate(&mut self, sample_rate: f64) -> Result<(), i32>;
    fn set_buffer_frame_size(&mut self, frames: u32) -> Result<(), i32>;
}

/// Acquire hog mode and pin the device's nominal sample rate to the exact
/// exclusive-mode rate.
///
/// If the rate cannot be pinned, hog mode is released again and the caller
/// falls back to the client-side exclusive contract (the host cannot provide
/// true exclusive mode at that rate).
pub(crate) fn acquire_exclusive_hog_with(
    driver: &mut dyn HogModeDriver,
    our_pid: i32,
    sample_rate: u32,
) -> HogModeOutcome {
    fn after_set(owner: i32, our_pid: i32) -> HogModeOutcome {
        if owner == our_pid {
            HogModeOutcome::Acquired
        } else if owner == -1 {
            // The host refused the set and left the device free: hog mode is
            // genuinely unavailable, not denied by another owner.
            HogModeOutcome::Unavailable
        } else {
            HogModeOutcome::Denied { owner_pid: owner }
        }
    }
    let outcome = match driver.hog_owner() {
        Ok(owner) if owner == our_pid => HogModeOutcome::AlreadyHeld,
        Ok(_) => match driver.set_hog() {
            Ok(owner) => after_set(owner, our_pid),
            Err(_) => match driver.hog_owner() {
                Ok(owner) => after_set(owner, our_pid),
                Err(_) => HogModeOutcome::Unavailable,
            },
        },
        Err(_) => HogModeOutcome::Unavailable,
    };
    if outcome.is_exclusive()
        && driver
            .set_nominal_sample_rate(sample_rate.max(1) as f64)
            .is_err()
    {
        let _ = driver.release_hog();
        return HogModeOutcome::Unavailable;
    }
    outcome
}

// ---------------------------------------------------------------------------
// Real audio backend
// ---------------------------------------------------------------------------

/// Why the device-interface path of an audio-interface activation could not
/// be resolved to a real device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioActivationDeviceFailure {
    /// The real output-device list is genuinely empty (or the backend has no
    /// default render device). Maps to `AUDCLNT_E_DEVICE_INVALIDATED`.
    NoDevices,
    /// The supplied device-interface path names a device this runtime cannot
    /// map onto the real (cpal) device list — e.g. a capture-endpoint
    /// interface id (`DEVINTERFACE_AUDIO_CAPTURE`) or an endpoint instance
    /// path for a non-default device. Also maps to the device error.
    UnknownDevicePath,
}

/// `DEVINTERFACE_AUDIO_RENDER` (`{e6327cad-dcec-4949-ae8a-991e976a79d2}`) —
/// the device-interface id that names the **default render** device.
pub const DEVINTERFACE_AUDIO_RENDER: &str = "{e6327cad-dcec-4949-ae8a-991e976a79d2}";
/// `DEVINTERFACE_AUDIO_CAPTURE` (`{2eef81be-33fa-4800-9670-1cd474972c3f}`) —
/// the device-interface id that names the default capture device. Capture
/// activations resolve this id (or a capture endpoint instance path) to the
/// real default input device enumerated from the host.
pub const DEVINTERFACE_AUDIO_CAPTURE: &str = "{2eef81be-33fa-4800-9670-1cd474972c3f}";

/// Whether an `ActivateAudioInterfaceAsync` device-interface path asks for a
/// **capture** endpoint.
///
/// Windows names capture endpoints with the
/// `DEVINTERFACE_AUDIO_CAPTURE` interface id or a capture endpoint instance
/// path. Capture endpoint instance paths carry the `{0.0.1.00000000}.{...}`
/// endpoint id (render endpoints use the `{0.0.0....}` form) and usually
/// embed the capture interface id as well.
pub fn audio_activation_path_is_capture(device_interface_path: Option<&str>) -> bool {
    let Some(path) = device_interface_path else {
        return false;
    };
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    let capture_guid = DEVINTERFACE_AUDIO_CAPTURE
        .trim_start_matches('{')
        .trim_end_matches('}');
    lower.contains(capture_guid) || lower.contains("{0.0.1.") || lower.contains("#0.0.1.")
}

/// Resolve a capture-side `ActivateAudioInterfaceAsync` device-interface path
/// against the real input-device snapshot (pure, deterministic — tests
/// exercise it with synthetic lists).
///
/// The `DEVINTERFACE_AUDIO_CAPTURE` interface id and capture endpoint instance
/// paths resolve to the default real input device. A non-capture path is
/// `UnknownDevicePath`; an empty list (or a list without a default input
/// device) is `NoDevices`.
pub fn resolve_audio_capture_activation_device(
    input_devices: &[RealAudioDevice],
    device_interface_path: Option<&str>,
) -> Result<RealAudioDevice, AudioActivationDeviceFailure> {
    if !audio_activation_path_is_capture(device_interface_path) {
        return Err(AudioActivationDeviceFailure::UnknownDevicePath);
    }
    let Some(default) = input_devices.iter().find(|device| device.is_default) else {
        return Err(AudioActivationDeviceFailure::NoDevices);
    };
    Ok(default.clone())
}

/// Resolve an `ActivateAudioInterfaceAsync` device-interface path against a
/// real-device snapshot (pure, deterministic — tests exercise it with
/// synthetic lists).
///
/// Windows semantics used here:
/// - `None` / empty path → the default render device.
/// - The `DEVINTERFACE_AUDIO_RENDER` interface id (the documented way to ask
///   for the default render device by GUID string) → the default render
///   device.
/// - `DEVINTERFACE_AUDIO_CAPTURE` or any other endpoint instance path → the
///   endpoint does not exist on this runtime's real device list.
pub fn resolve_audio_activation_device(
    devices: &[RealAudioDevice],
    device_interface_path: Option<&str>,
) -> Result<RealAudioDevice, AudioActivationDeviceFailure> {
    let path = device_interface_path.map(str::trim).unwrap_or("");
    let normalized = path
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or(path);
    let asks_default = path.is_empty()
        || normalized.eq_ignore_ascii_case(
            DEVINTERFACE_AUDIO_RENDER
                .trim_start_matches('{')
                .trim_end_matches('}'),
        );
    let asks_capture = normalized.eq_ignore_ascii_case(
        DEVINTERFACE_AUDIO_CAPTURE
            .trim_start_matches('{')
            .trim_end_matches('}'),
    );
    let Some(default) = devices.iter().find(|device| device.is_default) else {
        // No default render endpoint (the list may be empty, or every real
        // device lacks the default flag).
        return Err(AudioActivationDeviceFailure::NoDevices);
    };
    if asks_default {
        return Ok(default.clone());
    }
    if asks_capture {
        // The capture interface id never resolves on the render activation
        // surface.
        return Err(AudioActivationDeviceFailure::UnknownDevicePath);
    }
    Err(AudioActivationDeviceFailure::UnknownDevicePath)
}

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
    /// The live real system-output capture (process tap / ScreenCaptureKit).
    system_loopback: Option<SystemLoopbackSession>,
    /// Generation counter for system-loopback sessions (stale callbacks are
    /// rejected by generation).
    next_system_loopback_generation: u64,
    /// Devices on which this process currently owns CoreAudio hog mode.
    hog_devices: HashMap<DeviceId, i32>,
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
            system_loopback: None,
            next_system_loopback_generation: 1,
            hog_devices: HashMap::new(),
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

    /// Snapshot the enumerated real output devices (id, name, channels,
    /// sample rate, default flag) for audio-interface activation.
    pub fn activation_device_snapshot(&self) -> Vec<RealAudioDevice> {
        self.devices.values().cloned().collect()
    }

    /// Resolve the `ActivateAudioInterfaceAsync` device-interface path
    /// against the real device list of this backend.
    ///
    /// Capture paths (the `DEVINTERFACE_AUDIO_CAPTURE` interface id and
    /// capture endpoint instance paths) resolve against the real host input
    /// devices; render paths use [`resolve_audio_activation_device`].
    pub fn resolve_activation_device(
        &self,
        device_interface_path: Option<&str>,
    ) -> Result<RealAudioDevice, AudioActivationDeviceFailure> {
        if audio_activation_path_is_capture(device_interface_path) {
            let inputs = self.capture_device_snapshot();
            return resolve_audio_capture_activation_device(&inputs, device_interface_path);
        }
        let devices = self.activation_device_snapshot();
        resolve_audio_activation_device(&devices, device_interface_path)
    }

    /// Snapshot the real host input devices (default input device included)
    /// for capture-side activation.
    ///
    /// Each entry carries the real device name, channel count and sample rate
    /// from the host's default input configuration. The default input device
    /// is the one capture activations bind to; ids continue the output-device
    /// id space so a capture record can never collide with a render record.
    pub fn capture_device_snapshot(&self) -> Vec<RealAudioDevice> {
        let default_input_name = self
            .host
            .default_input_device()
            .and_then(|device| device.name().ok());
        let mut inputs = Vec::new();
        let Ok(devices) = self.host.input_devices() else {
            return inputs;
        };
        for (index, device) in devices.enumerate() {
            let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
            let Ok(config) = device.default_input_config() else {
                eprintln!(
                    "[RealAudio] capture_device_snapshot: no input config for '{name}'; skipping"
                );
                continue;
            };
            let channels = config.channels();
            let sample_rate = config.sample_rate().0;
            let is_default = default_input_name
                .as_ref()
                .map(|default_name| default_name == &name)
                .unwrap_or(false);
            inputs.push(RealAudioDevice {
                id: self.next_device_id + index as DeviceId,
                key: format!("{name}|{channels}|{sample_rate}|capture"),
                name,
                channels,
                sample_rate,
                is_default,
            });
        }
        inputs
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
    /// On macOS the default output device is additionally put into CoreAudio
    /// hog mode (`kAudioDevicePropertyHogMode`) and pinned to the exact
    /// nominal sample rate and fixed buffer frame size.  When another process
    /// owns hog mode (or the host/device cannot provide it), the real outcome
    /// is recorded in [`WasapiExclusiveState::hog_mode`] and the documented
    /// client-side exclusive contract is enforced unchanged.
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

        // True hardware exclusivity where the host supports it: hog mode plus
        // the exact nominal rate before the fixed-buffer stream is built.
        // Denial is not an error: the client-side contract stays in force.
        let hog_mode = self.acquire_hog_mode(device_id, format.sample_rate);

        // Create an exclusive-mode cpal stream (exact sample rate, no resampling)
        let buffer_frames = match self.ensure_stream_exclusive(device_id, &format) {
            Ok(frames) => frames,
            Err(error) => {
                self.release_hog_if_unused(device_id);
                return Err(error);
            }
        };
        self.pin_exclusive_buffer_frames(device_id, buffer_frames.min(u32::MAX as usize) as u32);

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
                hog_mode,
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
            self.release_hog(*id);
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

    /// The most recent latency the backend recorded for a device.
    pub fn last_latency_ms(&self, device_id: DeviceId) -> Option<u32> {
        self.latency_log
            .iter()
            .rev()
            .find(|record| record.device_id == device_id)
            .map(|record| record.measured_ms)
    }

    /// The real period/latency values of a device, in `REFERENCE_TIME` units.
    ///
    /// Queries the cpal device's default output configuration and uses its
    /// supported buffer-size range when the host exposes one (CoreAudio
    /// reports a range; WASAPI reports a range too).  When the device cannot
    /// be queried (headless host / stale snapshot) the values are derived
    /// from the device's own sample rate: a 10 ms default period and a 3 ms
    /// minimum, which is the documented Windows shared-mode fallback.
    pub fn device_period_info(&self, device: &RealAudioDevice) -> DevicePeriodInfo {
        let sample_rate = device.sample_rate.max(1);
        let fallback = |rate: u32| DevicePeriodInfo {
            sample_rate: rate,
            default_period_hns: hns_from_frames(rate as u64 / 100, rate),
            minimum_period_hns: hns_from_frames(rate as u64 * 3 / 1000, rate),
            stream_latency_hns: hns_from_frames(rate as u64 / 100, rate),
        };
        let Some(backend_device) = self
            .devices
            .values()
            .find(|candidate| candidate.key == device.key)
        else {
            return fallback(sample_rate);
        };
        let Ok(cpal_device) = self.find_cpal_device(backend_device.id) else {
            return fallback(sample_rate);
        };
        let Ok(config) = cpal_device.default_output_config() else {
            return fallback(sample_rate);
        };
        let rate = config.sample_rate().0.max(1);
        let default_frames = match config.config().buffer_size {
            cpal::BufferSize::Fixed(frames) => frames.max(1),
            cpal::BufferSize::Default => (rate / 100).max(1),
        };
        let minimum_frames = match config.buffer_size() {
            cpal::SupportedBufferSize::Range { min, .. } => (*min).max(1),
            cpal::SupportedBufferSize::Unknown => default_frames,
        };
        DevicePeriodInfo {
            sample_rate: rate,
            default_period_hns: hns_from_frames(default_frames as u64, rate),
            minimum_period_hns: hns_from_frames(minimum_frames as u64, rate),
            stream_latency_hns: hns_from_frames(default_frames as u64, rate),
        }
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
        self.release_hog(device_id);
    }

    /// Close all output streams and exclusive-mode clients.
    pub fn close_all_streams(&mut self) {
        self.streams.clear();
        self.stream_queues.clear();
        self.exclusive_clients.clear();
        self.exclusive_streams.clear();
        let devices: Vec<DeviceId> = self.hog_devices.keys().copied().collect();
        for device_id in devices {
            self.release_hog(device_id);
        }
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

        // Generic runtime event (no behavior change): the FIRST successful
        // real audio device initialization — a cpal output stream was built
        // AND started on a real device.  Never emitted for stubs or failed
        // opens (both error out above).  The Steam workload observer derives
        // the audio-initialized milestone from it.
        crate::runtime_events::emit_global(
            &crate::runtime_events::RuntimeEvent::AudioDeviceOpened {
                device: self.device_info(device_id)?.name.clone(),
                api: "RealAudioBackend::ensure_stream (cpal)".to_string(),
            },
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
        #[cfg(test)]
        if let Some(result) = TEST_NEXT_EXCLUSIVE_STREAM_OPEN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return result.map_err(|status| {
                AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!("forced exclusive stream open failure ({status})"),
                )
            });
        }
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

        // Generic runtime event (no behavior change): the FIRST successful
        // real audio initialization in exclusive mode — a cpal exclusive
        // stream was built AND started on a real device.  Never emitted for
        // stubs or failed opens (both error out above).
        crate::runtime_events::emit_global(
            &crate::runtime_events::RuntimeEvent::AudioDeviceOpened {
                device: self.device_info(device_id)?.name.clone(),
                api: "RealAudioBackend::ensure_stream_exclusive (cpal)".to_string(),
            },
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

    // -----------------------------------------------------------------------
    // Real system-output loopback capture
    // -----------------------------------------------------------------------

    /// Which real system-output capture backend the host offers.
    pub fn system_loopback_capability(&self) -> SystemLoopbackBackend {
        system_loopback_capability()
    }

    /// Start real system-output capture (beyond this runtime's render
    /// history) and return the backend actually used.
    ///
    /// The capture is independent of any runtime render stream: it taps the
    /// system output mix, so audio produced by other processes is captured
    /// too.  Idempotent while a session is live.
    pub fn start_system_loopback(
        &mut self,
    ) -> Result<SystemLoopbackBackend, SystemLoopbackFailure> {
        if let Some(session) = self.system_loopback.as_ref() {
            return Ok(session.backend);
        }
        #[cfg(test)]
        if let Some(reason) = take_forced_system_loopback_failure() {
            return Err(reason);
        }
        let backend = system_loopback_capability();
        if backend == SystemLoopbackBackend::Unavailable {
            return Err(SystemLoopbackFailure::Unavailable);
        }
        let generation = self.next_system_loopback_generation.max(1);
        self.next_system_loopback_generation = generation.wrapping_add(1).max(1);
        let shared = Arc::new(Mutex::new(SystemLoopbackSink::new(generation, 2, 48_000)));
        let session = match backend {
            #[cfg(target_os = "macos")]
            SystemLoopbackBackend::CoreAudioProcessTap => {
                platform::start_process_tap(Arc::clone(&shared), generation)?
            }
            #[cfg(target_os = "macos")]
            SystemLoopbackBackend::ScreenCaptureKit => {
                platform::start_screen_capture_kit(Arc::clone(&shared), generation)?
            }
            _ => return Err(SystemLoopbackFailure::Unavailable),
        };
        self.system_loopback = Some(session);
        Ok(backend)
    }

    /// Stop real system-output capture and invalidate any in-flight callback.
    ///
    /// Safe to call at any point (including while the host stream is still
    /// delivering frames): the generation is bumped before teardown and the
    /// host stop synchronizes the callback, so no stale frame is ever handed
    /// to a later capture client.
    pub fn stop_system_loopback(&mut self) {
        if let Some(mut session) = self.system_loopback.take() {
            session.stop();
        }
    }

    /// Whether real system-output capture is currently running.
    pub fn system_loopback_running(&self) -> bool {
        self.system_loopback.is_some()
    }

    /// The real capture format `(channels, sample_rate)` of the live system
    /// loopback, when running.
    pub fn system_loopback_format(&self) -> Option<(u16, u32)> {
        let session = self.system_loopback.as_ref()?;
        let sink = session
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Some((sink.channels, sink.sample_rate))
    }

    /// Frames currently buffered by the real system-output capture.
    pub fn system_loopback_available_frames(&self) -> u32 {
        let Some(session) = self.system_loopback.as_ref() else {
            return 0;
        };
        let sink = session
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (sink.samples.len() / sink.channels.max(1) as usize).min(u32::MAX as usize) as u32
    }

    /// Drain the real captured system frames (interleaved f32 in the capture
    /// format reported by [`Self::system_loopback_format`]).
    pub fn read_system_loopback_data(&mut self) -> Vec<f32> {
        let Some(session) = self.system_loopback.as_ref() else {
            return Vec::new();
        };
        let mut sink = session
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sink.samples.drain(..).collect()
    }

    /// Observable system-loopback state.
    pub fn system_loopback_status(&self) -> SystemLoopbackSnapshot {
        let capability = system_loopback_capability();
        let Some(session) = self.system_loopback.as_ref() else {
            return SystemLoopbackSnapshot {
                capability,
                running: false,
                backend: None,
                generation: 0,
                channels: 0,
                sample_rate: 0,
                buffered_frames: 0,
                frames_delivered: 0,
                dropped_frames: 0,
            };
        };
        let sink = session
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        SystemLoopbackSnapshot {
            capability,
            running: true,
            backend: Some(session.backend),
            generation: session.generation,
            channels: sink.channels,
            sample_rate: sink.sample_rate,
            buffered_frames: (sink.samples.len() / sink.channels.max(1) as usize) as u64,
            frames_delivered: sink.frames_delivered,
            dropped_frames: sink.dropped_frames,
        }
    }

    /// Install a deterministic in-process system-loopback session (test seam:
    /// exercises the real loopback delivery path without TCC/hardware).
    #[cfg(test)]
    pub(crate) fn install_test_system_loopback(&mut self, channels: u16, sample_rate: u32) -> u64 {
        self.stop_system_loopback();
        let generation = self.next_system_loopback_generation.max(1);
        self.next_system_loopback_generation = generation.wrapping_add(1).max(1);
        let shared = Arc::new(Mutex::new(SystemLoopbackSink::new(
            generation,
            channels,
            sample_rate,
        )));
        self.system_loopback = Some(SystemLoopbackSession {
            backend: SystemLoopbackBackend::CoreAudioProcessTap,
            generation,
            shared,
            stop: Some(Box::new(|| {})),
        });
        generation
    }

    /// Publish interleaved frames through the live test/system sink.
    #[cfg(test)]
    pub(crate) fn push_test_system_loopback_frames(
        &mut self,
        generation: u64,
        channels: u16,
        sample_rate: u32,
        interleaved: &[f32],
    ) -> bool {
        let Some(session) = self.system_loopback.as_ref() else {
            return false;
        };
        let mut sink = session
            .shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sink.ingest(generation, channels, sample_rate, interleaved)
    }

    // -----------------------------------------------------------------------
    // CoreAudio hog mode (true exclusive access)
    // -----------------------------------------------------------------------

    /// Acquire hog mode for an exclusive-mode open on the default output
    /// device, pinning the exact client sample rate.  Non-default devices (and
    /// non-macOS hosts) report `Unavailable` and keep the client-side
    /// exclusive contract.
    fn acquire_hog_mode(&mut self, device_id: DeviceId, sample_rate: u32) -> HogModeOutcome {
        let is_default = self
            .devices
            .get(&device_id)
            .map(|device| device.is_default)
            .unwrap_or(false);
        if !is_default {
            return HogModeOutcome::Unavailable;
        }
        #[cfg(target_os = "macos")]
        {
            let our_pid = std::process::id() as i32;
            let Some(mut driver) = platform::CoreAudioHogDriver::open_default_output() else {
                return HogModeOutcome::Unavailable;
            };
            let outcome = acquire_exclusive_hog_with(&mut driver, our_pid, sample_rate);
            if outcome.is_exclusive() {
                self.hog_devices.insert(device_id, our_pid);
            }
            outcome
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = sample_rate;
            HogModeOutcome::Unavailable
        }
    }

    /// Pin the device buffer frame size to the exact fixed exclusive buffer.
    fn pin_exclusive_buffer_frames(&self, device_id: DeviceId, frames: u32) {
        if !self.hog_devices.contains_key(&device_id) {
            return;
        }
        #[cfg(target_os = "macos")]
        if let Some(mut driver) = platform::CoreAudioHogDriver::open_default_output()
            && let Err(status) = driver.set_buffer_frame_size(frames.max(1))
        {
            eprintln!("[RealAudio] exclusive buffer-size pin failed: OSStatus {status}");
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (device_id, frames);
    }

    /// Release hog mode for `device_id` if no other exclusive client uses it.
    fn release_hog_if_unused(&mut self, device_id: DeviceId) {
        let in_use = self
            .exclusive_clients
            .values()
            .any(|state| state.device_id == device_id);
        if in_use {
            return;
        }
        self.release_hog(device_id);
    }

    fn release_hog(&mut self, device_id: DeviceId) {
        if self.hog_devices.remove(&device_id).is_none() {
            return;
        }
        #[cfg(target_os = "macos")]
        if let Some(mut driver) = platform::CoreAudioHogDriver::open_default_output()
            && let Err(status) = driver.release_hog()
        {
            eprintln!("[RealAudio] hog-mode release failed: OSStatus {status}");
        }
        #[cfg(not(target_os = "macos"))]
        let _ = device_id;
    }

    /// Whether this process currently owns CoreAudio hog mode on `device_id`.
    pub fn hog_mode_held(&self, device_id: DeviceId) -> bool {
        self.hog_devices.contains_key(&device_id)
    }

    /// The real hog-mode outcome recorded for an exclusive-mode client.
    pub fn exclusive_client_hog_mode(&self, client: AudioClientId) -> Option<HogModeOutcome> {
        self.exclusive_clients
            .get(&client)
            .map(|state| state.hog_mode)
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
pub fn max_capture_samples(rate: u32, channels: u16) -> usize {
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
        .as_chunks::<3>()
        .0
        .iter()
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
        .as_chunks::<4>()
        .0
        .iter()
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
            data.as_chunks::<4>()
                .0
                .iter()
                .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect()
        }
        0x0001 => match bits_per_sample {
            8 => u8_to_float(data),
            16 => {
                let i16_samples: Vec<i16> = data
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                pcm16_to_float(&i16_samples)
            }
            24 => pcm24_to_float(data),
            32 => {
                let i32_samples: Vec<i32> = data
                    .as_chunks::<4>()
                    .0
                    .iter()
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
#[allow(dead_code)] // IMDCT reference implementation for future codec support
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
#[allow(dead_code)] // echo delay state retained for future XAPO echo tuning
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

/// Convert a frame count to `REFERENCE_TIME` (100 ns units) at `rate`.
fn hns_from_frames(frames: u64, rate: u32) -> u64 {
    if rate == 0 {
        return 0;
    }
    (frames.saturating_mul(10_000_000) / rate as u64).max(1)
}

// ---------------------------------------------------------------------------
// macOS host capture: CoreAudio process taps + ScreenCaptureKit
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFRelease, CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::{CFString, CFStringRef};
    use objc::declare::ClassDecl;
    use objc::runtime::{Class, Object, Sel};
    use objc::{msg_send, sel, sel_impl};
    use std::ffi::c_void;
    use std::os::raw::c_char;
    use std::ptr;
    use std::sync::mpsc;
    use std::sync::{OnceLock, atomic::Ordering};
    use std::time::Duration;

    const SCOPE_GLOBAL: u32 = 0x676c_6f62; // 'glob'
    const SYSTEM_OBJECT: u32 = 1;
    const HW_DEFAULT_OUTPUT_DEVICE: u32 = 0x644f_7574; // 'dOut'
    const HW_TRANSLATE_PID_TO_PROCESS_OBJECT: u32 = 0x6964_3270; // 'id2p'
    const DEVICE_HOG_MODE: u32 = 0x6f69_6e6b; // 'oink'
    const DEVICE_NOMINAL_SAMPLE_RATE: u32 = 0x6e73_7274; // 'nsrt'
    const DEVICE_BUFFER_FRAME_SIZE: u32 = 0x6673_697a; // 'fsiz'
    const TAP_FORMAT: u32 = 0x7466_6d74; // 'tfmt'
    const TAP_UID: u32 = 0x7475_6964; // 'tuid'
    const FORMAT_LINEAR_PCM: u32 = 0x6c70_636d; // 'lpcm'
    const FORMAT_FLAG_IS_FLOAT: u32 = 1 << 0;
    const AGGREGATE_DEVICE_UID_KEY: &str = "uid";
    const AGGREGATE_DEVICE_PRIVATE_KEY: &str = "private";
    const AGGREGATE_DEVICE_TAP_LIST_KEY: &str = "taps";
    const SUB_TAP_UID_KEY: &str = "uid";

    #[repr(C)]
    struct AudioObjectPropertyAddress {
        selector: u32,
        scope: u32,
        element: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct AudioStreamBasicDescription {
        sample_rate: f64,
        format_id: u32,
        format_flags: u32,
        bytes_per_packet: u32,
        frames_per_packet: u32,
        bytes_per_frame: u32,
        channels_per_frame: u32,
        bits_per_channel: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct AudioBuffer {
        number_channels: u32,
        data_byte_size: u32,
        data: *mut c_void,
    }

    #[repr(C)]
    struct AudioBufferList {
        number_buffers: u32,
        buffers: [AudioBuffer; 1],
    }

    type OsStatus = i32;
    type AudioObjectId = u32;
    type AudioDeviceIoProcId = *mut c_void;

    type GetPropertyDataFn = unsafe extern "C" fn(
        AudioObjectId,
        *const AudioObjectPropertyAddress,
        u32,
        *const c_void,
        *mut u32,
        *mut c_void,
    ) -> OsStatus;
    type SetPropertyDataFn = unsafe extern "C" fn(
        AudioObjectId,
        *const AudioObjectPropertyAddress,
        u32,
        *const c_void,
        u32,
        *const c_void,
    ) -> OsStatus;
    type CreateAggregateFn = unsafe extern "C" fn(*const c_void, *mut AudioObjectId) -> OsStatus;
    type DestroyAggregateFn = unsafe extern "C" fn(AudioObjectId) -> OsStatus;
    type CreateIoProcWithBlockFn = unsafe extern "C" fn(
        *mut AudioDeviceIoProcId,
        AudioObjectId,
        *mut c_void,
        *const c_void,
    ) -> OsStatus;
    type DestroyIoProcFn = unsafe extern "C" fn(AudioObjectId, AudioDeviceIoProcId) -> OsStatus;
    type StartDeviceFn = unsafe extern "C" fn(AudioObjectId, AudioDeviceIoProcId) -> OsStatus;
    type CreateProcessTapFn = unsafe extern "C" fn(*mut Object, *mut AudioObjectId) -> OsStatus;
    type DestroyProcessTapFn = unsafe extern "C" fn(AudioObjectId) -> OsStatus;

    struct CoreAudioApi {
        get_property_data: GetPropertyDataFn,
        set_property_data: SetPropertyDataFn,
        create_aggregate: CreateAggregateFn,
        destroy_aggregate: DestroyAggregateFn,
        create_ioproc: CreateIoProcWithBlockFn,
        destroy_ioproc: DestroyIoProcFn,
        device_start: StartDeviceFn,
        device_stop: StartDeviceFn,
        create_process_tap: Option<CreateProcessTapFn>,
        destroy_process_tap: Option<DestroyProcessTapFn>,
    }

    fn coreaudio_handle() -> Option<*mut c_void> {
        static HANDLE: OnceLock<usize> = OnceLock::new();
        let handle = *HANDLE.get_or_init(|| unsafe {
            libc::dlopen(
                c"/System/Library/Frameworks/CoreAudio.framework/CoreAudio".as_ptr(),
                libc::RTLD_LAZY | libc::RTLD_LOCAL,
            ) as usize
        });
        (handle != 0).then_some(handle as *mut c_void)
    }

    fn symbol(handle: *mut c_void, name: &[u8]) -> Option<*mut c_void> {
        let symbol = unsafe { libc::dlsym(handle, name.as_ptr() as *const c_char) };
        (!symbol.is_null()).then_some(symbol)
    }

    #[cfg(test)]
    static TEST_CORE_AUDIO_API: Mutex<Option<&'static CoreAudioApi>> = Mutex::new(None);

    fn coreaudio_api() -> Option<&'static CoreAudioApi> {
        #[cfg(test)]
        if let Some(api) = *TEST_CORE_AUDIO_API
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            return Some(api);
        }
        static API: OnceLock<Option<CoreAudioApi>> = OnceLock::new();
        API.get_or_init(|| {
            let handle = coreaudio_handle()?;
            unsafe {
                let get_property_data: GetPropertyDataFn =
                    std::mem::transmute(symbol(handle, b"AudioObjectGetPropertyData\0")?);
                let set_property_data: SetPropertyDataFn =
                    std::mem::transmute(symbol(handle, b"AudioObjectSetPropertyData\0")?);
                let create_aggregate: CreateAggregateFn =
                    std::mem::transmute(symbol(handle, b"AudioHardwareCreateAggregateDevice\0")?);
                let destroy_aggregate: DestroyAggregateFn =
                    std::mem::transmute(symbol(handle, b"AudioHardwareDestroyAggregateDevice\0")?);
                let create_ioproc: CreateIoProcWithBlockFn =
                    std::mem::transmute(symbol(handle, b"AudioDeviceCreateIOProcIDWithBlock\0")?);
                let destroy_ioproc: DestroyIoProcFn =
                    std::mem::transmute(symbol(handle, b"AudioDeviceDestroyIOProcID\0")?);
                let device_start: StartDeviceFn =
                    std::mem::transmute(symbol(handle, b"AudioDeviceStart\0")?);
                let device_stop: StartDeviceFn =
                    std::mem::transmute(symbol(handle, b"AudioDeviceStop\0")?);
                let create_process_tap: Option<CreateProcessTapFn> =
                    symbol(handle, b"AudioHardwareCreateProcessTap\0")
                        .map(|symbol| std::mem::transmute(symbol));
                let destroy_process_tap: Option<DestroyProcessTapFn> =
                    symbol(handle, b"AudioHardwareDestroyProcessTap\0")
                        .map(|symbol| std::mem::transmute(symbol));
                Some(CoreAudioApi {
                    get_property_data,
                    set_property_data,
                    create_aggregate,
                    destroy_aggregate,
                    create_ioproc,
                    destroy_ioproc,
                    device_start,
                    device_stop,
                    create_process_tap,
                    destroy_process_tap,
                })
            }
        })
        .as_ref()
    }

    pub(super) fn process_tap_symbols_available() -> bool {
        coreaudio_api().is_some_and(|api| {
            api.create_process_tap.is_some() && api.destroy_process_tap.is_some()
        })
    }

    pub(super) fn screen_capture_kit_available() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| unsafe {
            let handle = libc::dlopen(
                c"/System/Library/Frameworks/ScreenCaptureKit.framework/ScreenCaptureKit".as_ptr(),
                libc::RTLD_LAZY | libc::RTLD_LOCAL,
            );
            !handle.is_null() && Class::get("SCStream").is_some()
        })
    }

    fn property_address(selector: u32) -> AudioObjectPropertyAddress {
        AudioObjectPropertyAddress {
            selector,
            scope: SCOPE_GLOBAL,
            element: 0,
        }
    }

    unsafe fn get_property<T>(
        api: &CoreAudioApi,
        object: AudioObjectId,
        selector: u32,
    ) -> Result<T, OsStatus> {
        let address = property_address(selector);
        let mut value: T = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<T>() as u32;
        let status = unsafe {
            (api.get_property_data)(
                object,
                &address,
                0,
                ptr::null(),
                &mut size,
                &mut value as *mut T as *mut c_void,
            )
        };
        if status == 0 && size as usize >= std::mem::size_of::<T>() {
            Ok(value)
        } else {
            Err(status)
        }
    }

    unsafe fn set_property<T>(
        api: &CoreAudioApi,
        object: AudioObjectId,
        selector: u32,
        value: &mut T,
    ) -> OsStatus {
        let address = property_address(selector);
        unsafe {
            (api.set_property_data)(
                object,
                &address,
                0,
                ptr::null(),
                std::mem::size_of::<T>() as u32,
                value as *mut T as *mut c_void,
            )
        }
    }

    unsafe fn translate_pid(api: &CoreAudioApi, pid: i32) -> Option<AudioObjectId> {
        let address = property_address(HW_TRANSLATE_PID_TO_PROCESS_OBJECT);
        let mut object: AudioObjectId = 0;
        let mut size = std::mem::size_of::<AudioObjectId>() as u32;
        let mut pid = pid;
        let status = unsafe {
            (api.get_property_data)(
                SYSTEM_OBJECT,
                &address,
                std::mem::size_of::<i32>() as u32,
                &mut pid as *mut i32 as *const c_void,
                &mut size,
                &mut object as *mut AudioObjectId as *mut c_void,
            )
        };
        (status == 0 && object != 0).then_some(object)
    }

    unsafe fn query_tap_format(api: &CoreAudioApi, tap: AudioObjectId) -> Option<(u16, u32)> {
        let format: AudioStreamBasicDescription =
            unsafe { get_property(api, tap, TAP_FORMAT) }.ok()?;
        let is_float = format.format_flags & FORMAT_FLAG_IS_FLOAT != 0;
        if format.format_id != FORMAT_LINEAR_PCM
            || !is_float
            || format.bits_per_channel != 32
            || format.channels_per_frame == 0
            || format.sample_rate <= 0.0
        {
            return None;
        }
        Some((
            format.channels_per_frame.min(u16::MAX as u32) as u16,
            format.sample_rate.round() as u32,
        ))
    }

    unsafe fn query_tap_uid(api: &CoreAudioApi, tap: AudioObjectId) -> Option<CFString> {
        let address = property_address(TAP_UID);
        let mut value: CFStringRef = ptr::null();
        let mut size = std::mem::size_of::<CFStringRef>() as u32;
        let status = unsafe {
            (api.get_property_data)(
                tap,
                &address,
                0,
                ptr::null(),
                &mut size,
                &mut value as *mut CFStringRef as *mut c_void,
            )
        };
        (status == 0 && !value.is_null()).then(|| unsafe { CFString::wrap_under_get_rule(value) })
    }

    unsafe fn exclude_own_process(processes: *mut Object, own_process: AudioObjectId) {
        if own_process == 0 {
            return;
        }
        let Some(number_class) = Class::get("NSNumber") else {
            return; // coverage: unreachable — Foundation always provides NSNumber
        };
        let number: *mut Object =
            unsafe { msg_send![number_class, numberWithUnsignedInt: own_process] };
        if number.is_null() {
            return; // coverage: unreachable — numberWithUnsignedInt: never returns nil
        }
        let _: () = unsafe { msg_send![processes, addObject: number] };
    }

    unsafe fn create_tap_description(own_process: AudioObjectId) -> Option<*mut Object> {
        let class = Class::get("CATapDescription")?;
        let alloc: *mut Object = unsafe { msg_send![class, alloc] };
        if alloc.is_null() {
            return None; // coverage: unreachable — NSObject's alloc always returns an instance
        }
        let array_class = Class::get("NSMutableArray")?;
        let processes: *mut Object = unsafe { msg_send![array_class, array] };
        unsafe { exclude_own_process(processes, own_process) };
        let description: *mut Object =
            unsafe { msg_send![alloc, initStereoGlobalTapButExcludeProcesses: processes] };
        if description.is_null() {
            return None; // coverage: unreachable — CATapDescription's designated init is total
        }
        let _: () = unsafe { msg_send![description, setPrivate: 1i8] };
        // CATapDescription always implements setMuteBehavior: (macOS 12+;
        // process taps themselves need 14.2+), so this is unconditional.
        let _: () = unsafe { msg_send![description, setMuteBehavior: 0i64] };
        Some(description)
    }

    fn aggregate_composition(tap_uid: &CFString) -> CFDictionary<CFString, CFType> {
        let tap_entry = CFDictionary::<CFString, CFType>::from_CFType_pairs(&[(
            CFString::new(SUB_TAP_UID_KEY),
            tap_uid.as_CFType(),
        )]);
        let tap_list = CFArray::<CFType>::from_CFTypes(&[tap_entry.as_CFType()]);
        static AGGREGATE_SERIAL: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let serial = AGGREGATE_SERIAL.fetch_add(1, Ordering::Relaxed);
        let aggregate_uid = CFString::new(&format!(
            "Casa1-System-Loopback-{}-{serial}",
            std::process::id()
        ));
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::new(AGGREGATE_DEVICE_UID_KEY),
                aggregate_uid.as_CFType(),
            ),
            (
                CFString::new(AGGREGATE_DEVICE_PRIVATE_KEY),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                CFString::new(AGGREGATE_DEVICE_TAP_LIST_KEY),
                tap_list.as_CFType(),
            ),
        ])
    }

    /// Interleave one host `AudioBufferList` of 32-bit floats.
    ///
    /// Returns the interleaved samples and the actual channel count.  A
    /// single buffer is interleaved; multiple buffers are one channel each
    /// (the CoreAudio non-interleaved layout).
    unsafe fn audio_buffer_list_to_interleaved(list: *const AudioBufferList) -> (Vec<f32>, u16) {
        if list.is_null() {
            return (Vec::new(), 0);
        }
        let number_buffers = unsafe { (*list).number_buffers as usize };
        if number_buffers == 0 || number_buffers > 64 {
            return (Vec::new(), 0);
        }
        let buffers = unsafe { ptr::addr_of!((*list).buffers) as *const AudioBuffer };
        let first = unsafe { &*buffers };
        if first.data.is_null() || first.number_channels == 0 {
            return (Vec::new(), 0);
        }
        if number_buffers == 1 {
            let channels = first.number_channels as usize;
            let frames = first.data_byte_size as usize / (4 * channels);
            if frames == 0 {
                return (Vec::new(), 0);
            }
            let samples =
                unsafe { std::slice::from_raw_parts(first.data as *const f32, frames * channels) };
            return (samples.to_vec(), channels.min(u16::MAX as usize) as u16);
        }
        let frames = (0..number_buffers)
            .map(|index| {
                let buffer = unsafe { &*buffers.add(index) };
                if buffer.data.is_null() {
                    0
                } else {
                    buffer.data_byte_size as usize / 4
                }
            })
            .min()
            .unwrap_or(0);
        if frames == 0 {
            return (Vec::new(), 0);
        }
        let channels = number_buffers.min(u16::MAX as usize) as u16;
        let mut output = vec![0.0f32; frames * number_buffers];
        for (channel, index) in (0..number_buffers).enumerate() {
            let buffer = unsafe { &*buffers.add(index) };
            if buffer.data.is_null() {
                // coverage: unreachable — frames is the minimum over every
                // buffer, so a null buffer already forced frames == 0 above.
                continue; // coverage: unreachable — see the frames == 0 return above
            }
            let samples = unsafe { std::slice::from_raw_parts(buffer.data as *const f32, frames) };
            for (frame, sample) in samples.iter().enumerate() {
                output[frame * number_buffers + channel] = *sample;
            }
        }
        (output, channels)
    }

    pub(super) fn start_process_tap(
        shared: Arc<Mutex<SystemLoopbackSink>>,
        generation: u64,
    ) -> Result<SystemLoopbackSession, SystemLoopbackFailure> {
        let api = coreaudio_api().ok_or(SystemLoopbackFailure::Unavailable)?;
        let create_tap = api
            .create_process_tap
            .ok_or(SystemLoopbackFailure::Unavailable)?;
        let destroy_tap = api
            .destroy_process_tap
            .ok_or(SystemLoopbackFailure::Unavailable)?;
        let own_process = unsafe { translate_pid(api, std::process::id() as i32) }.unwrap_or(0);
        let description =
            objc::rc::autoreleasepool(|| unsafe { create_tap_description(own_process) })
                .ok_or(SystemLoopbackFailure::ObjectUnavailable)?;
        let mut tap: AudioObjectId = 0;
        let status = unsafe { create_tap(description, &mut tap) };
        unsafe {
            let _: () = msg_send![description, release];
        }
        if status != 0 || tap == 0 {
            return Err(SystemLoopbackFailure::TapCreation(status));
        }

        let Some((channels, sample_rate)) = (unsafe { query_tap_format(api, tap) }) else {
            unsafe {
                let _ = destroy_tap(tap);
            }
            return Err(SystemLoopbackFailure::FormatUnavailable);
        };
        let Some(tap_uid) = (unsafe { query_tap_uid(api, tap) }) else {
            unsafe {
                let _ = destroy_tap(tap);
            }
            return Err(SystemLoopbackFailure::ObjectUnavailable);
        };
        let composition = aggregate_composition(&tap_uid);
        let mut aggregate: AudioObjectId = 0;
        let status = unsafe {
            (api.create_aggregate)(
                composition.as_concrete_TypeRef() as *const c_void,
                &mut aggregate,
            )
        };
        if status != 0 || aggregate == 0 {
            unsafe {
                let _ = destroy_tap(tap);
            }
            return Err(SystemLoopbackFailure::AggregateCreation(status));
        }

        let sink = Arc::clone(&shared);
        let block = block::ConcreteBlock::new(
            move |_now: *const c_void,
                  input: *const AudioBufferList,
                  _input_time: *const c_void,
                  _output: *mut AudioBufferList,
                  _output_time: *const c_void| {
                let (samples, actual_channels) = unsafe { audio_buffer_list_to_interleaved(input) };
                if samples.is_empty() {
                    return;
                }
                if let Ok(mut sink) = sink.try_lock() {
                    let _ = sink.ingest(generation, actual_channels, sample_rate, &samples);
                }
            },
        );
        let block = block.copy();
        let mut ioproc: AudioDeviceIoProcId = ptr::null_mut();
        let block_ptr = &*block as *const _ as *const c_void;
        let status =
            unsafe { (api.create_ioproc)(&mut ioproc, aggregate, ptr::null_mut(), block_ptr) };
        if status != 0 || ioproc.is_null() {
            unsafe {
                let _ = (api.destroy_aggregate)(aggregate);
                let _ = destroy_tap(tap);
            }
            return Err(SystemLoopbackFailure::StreamStart(status));
        }
        let status = unsafe { (api.device_start)(aggregate, ioproc) };
        if status != 0 {
            unsafe {
                let _ = (api.destroy_ioproc)(aggregate, ioproc);
                let _ = (api.destroy_aggregate)(aggregate);
                let _ = destroy_tap(tap);
            }
            return Err(SystemLoopbackFailure::StreamStart(status));
        }

        {
            let mut sink = shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            sink.channels = channels;
            sink.sample_rate = sample_rate;
        }
        let ioproc = ioproc as usize;
        let stop = Box::new(move || unsafe {
            let ioproc = ioproc as AudioDeviceIoProcId;
            let _ = (api.device_stop)(aggregate, ioproc);
            let _ = (api.destroy_ioproc)(aggregate, ioproc);
            let _ = (api.destroy_aggregate)(aggregate);
            let _ = destroy_tap(tap);
        });
        Ok(SystemLoopbackSession {
            backend: SystemLoopbackBackend::CoreAudioProcessTap,
            generation,
            shared,
            stop: Some(stop),
        })
    }

    pub(super) fn start_screen_capture_kit(
        shared: Arc<Mutex<SystemLoopbackSink>>,
        generation: u64,
    ) -> Result<SystemLoopbackSession, SystemLoopbackFailure> {
        sck::start(shared, generation)
    }

    /// CoreAudio hog-mode driver for the default output device.
    pub(crate) struct CoreAudioHogDriver {
        api: &'static CoreAudioApi,
        device: AudioObjectId,
        pid: i32,
    }

    impl CoreAudioHogDriver {
        pub(crate) fn open_default_output() -> Option<Self> {
            let api = coreaudio_api()?;
            let device: AudioObjectId =
                unsafe { get_property(api, SYSTEM_OBJECT, HW_DEFAULT_OUTPUT_DEVICE) }.ok()?;
            (device != 0).then_some(Self {
                api,
                device,
                pid: std::process::id() as i32,
            })
        }
    }

    impl HogModeDriver for CoreAudioHogDriver {
        fn hog_owner(&mut self) -> Result<i32, i32> {
            unsafe { get_property(self.api, self.device, DEVICE_HOG_MODE) }
        }

        fn set_hog(&mut self) -> Result<i32, i32> {
            let mut owner = self.pid;
            let status =
                unsafe { set_property(self.api, self.device, DEVICE_HOG_MODE, &mut owner) };
            if status != 0 { Err(status) } else { Ok(owner) }
        }

        fn release_hog(&mut self) -> Result<(), i32> {
            let owner = self.hog_owner()?;
            if owner != self.pid {
                return Ok(());
            }
            let mut value = self.pid;
            let status =
                unsafe { set_property(self.api, self.device, DEVICE_HOG_MODE, &mut value) };
            if status == 0 { Ok(()) } else { Err(status) }
        }

        fn set_nominal_sample_rate(&mut self, sample_rate: f64) -> Result<(), i32> {
            let mut value = sample_rate;
            let status = unsafe {
                set_property(
                    self.api,
                    self.device,
                    DEVICE_NOMINAL_SAMPLE_RATE,
                    &mut value,
                )
            };
            if status == 0 { Ok(()) } else { Err(status) }
        }

        fn set_buffer_frame_size(&mut self, frames: u32) -> Result<(), i32> {
            let mut value = frames;
            let status = unsafe {
                set_property(self.api, self.device, DEVICE_BUFFER_FRAME_SIZE, &mut value)
            };
            if status == 0 { Ok(()) } else { Err(status) }
        }
    }

    /// ScreenCaptureKit audio capture (`SCStream.capturesAudio`).
    #[cfg(not(test))]
    mod sck {
        use super::*;

        const OUTPUT_TYPE_AUDIO: i64 = 1;
        const CONTENT_TIMEOUT: Duration = Duration::from_secs(4);
        const START_TIMEOUT: Duration = Duration::from_secs(4);
        const STOP_TIMEOUT: Duration = Duration::from_secs(2);
        const FLAG_AUDIO_BUFFER_LIST_ASSURE_16_BYTE_ALIGNMENT: u32 = 1 << 0;

        struct SckContext {
            shared: Arc<Mutex<SystemLoopbackSink>>,
            generation: u64,
            sample_rate: u32,
        }

        type SampleBufferAudioBufferListFn = unsafe extern "C" fn(
            *mut c_void,
            *mut usize,
            *mut AudioBufferList,
            usize,
            *const c_void,
            *const c_void,
            u32,
            *mut *mut c_void,
        ) -> OsStatus;

        fn sample_buffer_api() -> Option<SampleBufferAudioBufferListFn> {
            static API: OnceLock<usize> = OnceLock::new();
            let pointer = *API.get_or_init(|| unsafe {
                let handle = libc::dlopen(
                    c"/System/Library/Frameworks/CoreMedia.framework/CoreMedia".as_ptr(),
                    libc::RTLD_LAZY | libc::RTLD_LOCAL,
                );
                if handle.is_null() {
                    return 0;
                }
                symbol(
                    handle,
                    b"CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer\0",
                )
                .map(|symbol| symbol as usize)
                .unwrap_or(0)
            });
            (pointer != 0).then(|| unsafe {
                std::mem::transmute::<usize, SampleBufferAudioBufferListFn>(pointer)
            })
        }

        unsafe fn empty_array() -> Option<*mut Object> {
            let class = Class::get("NSArray")?;
            let array: *mut Object = unsafe { msg_send![class, array] };
            (!array.is_null()).then_some(array)
        }

        unsafe fn shareable_content() -> Option<*mut Object> {
            let class = Class::get("SCShareableContent")?;
            let (sender, receiver) = mpsc::channel::<(usize, usize)>();
            let block =
                block::ConcreteBlock::new(move |content: *mut Object, error: *mut Object| {
                    let _ = sender.send((content as usize, error as usize));
                });
            let block = block.copy();
            let block_ptr = &*block as *const _ as *const c_void;
            let _: () =
                unsafe { msg_send![class, getShareableContentWithCompletionHandler: block_ptr] };
            match receiver.recv_timeout(CONTENT_TIMEOUT) {
                Ok((content, error)) if content != 0 && error == 0 => {
                    let retained: *mut Object =
                        unsafe { msg_send![content as *mut Object, retain] };
                    (!retained.is_null()).then_some(retained)
                }
                _ => None,
            }
        }

        unsafe fn first_display(content: *mut Object) -> Option<*mut Object> {
            let displays: *mut Object = unsafe { msg_send![content, displays] };
            if displays.is_null() {
                return None;
            }
            let count: usize = unsafe { msg_send![displays, count] };
            if count == 0 {
                return None;
            }
            let display: *mut Object = unsafe { msg_send![displays, objectAtIndex: 0] };
            (!display.is_null()).then_some(display)
        }

        unsafe fn create_filter(display: *mut Object) -> Option<*mut Object> {
            let class = Class::get("SCContentFilter")?;
            let excluded = unsafe { empty_array() }?;
            let alloc: *mut Object = unsafe { msg_send![class, alloc] };
            if alloc.is_null() {
                return None;
            }
            let filter: *mut Object =
                unsafe { msg_send![alloc, initWithDisplay: display excludingWindows: excluded] };
            (!filter.is_null()).then_some(filter)
        }

        unsafe fn create_configuration(sample_rate: u32, channels: u16) -> Option<*mut Object> {
            let class = Class::get("SCStreamConfiguration")?;
            let config: *mut Object = unsafe { msg_send![class, new] };
            if config.is_null() {
                return None;
            }
            let _: () = unsafe { msg_send![config, setCapturesAudio: 1i8] };
            let _: () = unsafe { msg_send![config, setExcludesCurrentProcessAudio: 1i8] };
            let _: () = unsafe { msg_send![config, setSampleRate: sample_rate.max(1) as i64] };
            let _: () = unsafe { msg_send![config, setChannelCount: channels.max(1) as i64] };
            let _: () = unsafe { msg_send![config, setWidth: 2usize] };
            let _: () = unsafe { msg_send![config, setHeight: 2usize] };
            Some(config)
        }

        extern "C" fn did_output(
            this: &mut Object,
            _cmd: Sel,
            _stream: *mut Object,
            sample_buffer: *mut c_void,
            output_type: i64,
        ) {
            if output_type != OUTPUT_TYPE_AUDIO || sample_buffer.is_null() {
                return;
            }
            let context_pointer = unsafe { *this.get_ivar::<usize>("casa_context") };
            if context_pointer == 0 {
                return;
            }
            let context = unsafe { &*(context_pointer as *const SckContext) };
            let (samples, channels) = unsafe { sample_buffer_to_interleaved(sample_buffer) };
            if samples.is_empty() {
                return;
            }
            if let Ok(mut sink) = context.shared.try_lock() {
                let _ = sink.ingest(context.generation, channels, context.sample_rate, &samples);
            }
        }

        extern "C" fn dealloc(this: &mut Object, _cmd: Sel) {
            unsafe {
                let pointer = *this.get_ivar::<usize>("casa_context");
                if pointer != 0 {
                    drop(Box::from_raw(pointer as *mut SckContext));
                    this.set_ivar("casa_context", 0usize);
                }
                let _: () = msg_send![super(this, class!(NSObject)), dealloc];
            }
        }

        fn output_class() -> Option<&'static Class> {
            static CLASS: OnceLock<usize> = OnceLock::new();
            let pointer = *CLASS.get_or_init(|| {
                let Some(superclass) = Class::get("NSObject") else {
                    return 0;
                };
                let Some(mut declaration) = ClassDecl::new("Casa1SCStreamOutput", superclass)
                else {
                    return 0;
                };
                declaration.add_ivar::<usize>("casa_context");
                unsafe {
                    declaration.add_method(
                        sel!(stream:didOutputSampleBuffer:ofType:),
                        did_output
                            as extern "C" fn(&mut Object, Sel, *mut Object, *mut c_void, i64),
                    );
                    declaration
                        .add_method(sel!(dealloc), dealloc as extern "C" fn(&mut Object, Sel));
                }
                declaration.register() as *const Class as usize
            });
            (pointer != 0).then(|| unsafe { &*(pointer as *const Class) })
        }

        unsafe fn sample_buffer_to_interleaved(sample_buffer: *mut c_void) -> (Vec<f32>, u16) {
            let Some(get_buffers) = sample_buffer_api() else {
                return (Vec::new(), 0);
            };
            let mut needed = 0usize;
            let _status = unsafe {
                get_buffers(
                    sample_buffer,
                    &mut needed,
                    ptr::null_mut(),
                    0,
                    ptr::null(),
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                )
            };
            if needed == 0 {
                return (Vec::new(), 0);
            }
            let words = needed.div_ceil(std::mem::size_of::<u128>());
            let mut storage = vec![0u128; words];
            let list = storage.as_mut_ptr() as *mut AudioBufferList;
            let mut block_buffer: *mut c_void = ptr::null_mut();
            let status = unsafe {
                get_buffers(
                    sample_buffer,
                    &mut needed,
                    list,
                    words * std::mem::size_of::<u128>(),
                    ptr::null(),
                    ptr::null(),
                    FLAG_AUDIO_BUFFER_LIST_ASSURE_16_BYTE_ALIGNMENT,
                    &mut block_buffer,
                )
            };
            if status != 0 {
                return (Vec::new(), 0);
            }
            let result = unsafe { audio_buffer_list_to_interleaved(list) };
            if !block_buffer.is_null() {
                unsafe {
                    CFRelease(block_buffer);
                }
            }
            result
        }

        pub(super) fn start(
            shared: Arc<Mutex<SystemLoopbackSink>>,
            generation: u64,
        ) -> Result<SystemLoopbackSession, SystemLoopbackFailure> {
            unsafe {
                let content = shareable_content().ok_or(SystemLoopbackFailure::Unavailable)?;
                let display =
                    first_display(content).ok_or(SystemLoopbackFailure::ObjectUnavailable)?;
                let filter =
                    create_filter(display).ok_or(SystemLoopbackFailure::ObjectUnavailable)?;
                let channels = 2u16;
                let sample_rate = 48_000u32;
                let configuration = create_configuration(sample_rate, channels)
                    .ok_or(SystemLoopbackFailure::ObjectUnavailable)?;
                let stream_class =
                    Class::get("SCStream").ok_or(SystemLoopbackFailure::Unavailable)?;
                let alloc: *mut Object = msg_send![stream_class, alloc];
                let stream: *mut Object = msg_send![alloc, initWithFilter: filter configuration: configuration delegate: ptr::null::<Object>()];
                let _: () = msg_send![filter, release];
                let _: () = msg_send![configuration, release];
                if stream.is_null() {
                    let _: () = msg_send![content, release];
                    return Err(SystemLoopbackFailure::ObjectUnavailable);
                }

                let Some(output_class) = output_class() else {
                    let _: () = msg_send![stream, release];
                    let _: () = msg_send![content, release];
                    return Err(SystemLoopbackFailure::Unavailable);
                };
                let output: *mut Object = msg_send![output_class, alloc];
                let context = Box::into_raw(Box::new(SckContext {
                    shared: Arc::clone(&shared),
                    generation,
                    sample_rate,
                }));
                (&mut *output).set_ivar("casa_context", context as usize);
                let output: *mut Object = msg_send![output, init];
                let mut error: *mut Object = ptr::null_mut();
                let added: bool = msg_send![stream, addStreamOutput: output type: OUTPUT_TYPE_AUDIO sampleHandlerQueue: ptr::null::<c_void>() error: &mut error];
                if !added {
                    let _: () = msg_send![output, release];
                    let _: () = msg_send![stream, release];
                    let _: () = msg_send![content, release];
                    return Err(SystemLoopbackFailure::StreamStart(-1));
                }

                let (sender, receiver) = mpsc::channel::<usize>();
                let block = block::ConcreteBlock::new(move |error: *mut Object| {
                    let _ = sender.send(error as usize);
                });
                let block = block.copy();
                let block_ptr = &*block as *const _ as *const c_void;
                let _: () = msg_send![stream, startCaptureWithCompletionHandler: block_ptr];
                match receiver.recv_timeout(START_TIMEOUT) {
                    Ok(0) => {}
                    _ => {
                        let _: () = msg_send![stream, removeStreamOutput: output type: OUTPUT_TYPE_AUDIO error: ptr::null_mut::<*mut Object>()];
                        let _: () = msg_send![output, release];
                        let _: () = msg_send![stream, release];
                        let _: () = msg_send![content, release];
                        return Err(SystemLoopbackFailure::StreamStart(-1));
                    }
                }

                let stream_address = stream as usize;
                let output_address = output as usize;
                let content_address = content as usize;
                let stop = Box::new(move || {
                    let stream = stream_address as *mut Object;
                    let output = output_address as *mut Object;
                    let content = content_address as *mut Object;
                    let (sender, receiver) = mpsc::channel::<usize>();
                    let block = block::ConcreteBlock::new(move |error: *mut Object| {
                        let _ = sender.send(error as usize);
                    });
                    let block = block.copy();
                    let block_ptr = &*block as *const _ as *const c_void;
                    let _: () = msg_send![stream, stopCaptureWithCompletionHandler: block_ptr];
                    let _ = receiver.recv_timeout(STOP_TIMEOUT);
                    let _: () = msg_send![stream, removeStreamOutput: output type: OUTPUT_TYPE_AUDIO error: ptr::null_mut::<*mut Object>()];
                    let _: () = msg_send![output, release];
                    let _: () = msg_send![stream, release];
                    let _: () = msg_send![content, release];
                });
                Ok(SystemLoopbackSession {
                    backend: SystemLoopbackBackend::ScreenCaptureKit,
                    generation,
                    shared,
                    stop: Some(stop),
                })
            }
        }
    }

    /// Deterministic fake CoreAudio host used by the adversarial system
    /// loopback/hog tests.  It implements the same function-pointer API as the
    /// real framework, including invoking the installed IOProc block with a
    /// synthetic AudioBufferList, so the entire capture pipeline runs without
    /// TCC or touching the developer's audio devices.
    #[cfg(test)]
    pub(crate) mod fake {
        use super::*;
        use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32};

        static TAP_STATUS: AtomicI32 = AtomicI32::new(0);
        static AGGREGATE_STATUS: AtomicI32 = AtomicI32::new(0);
        static IOPROC_STATUS: AtomicI32 = AtomicI32::new(0);
        static START_STATUS: AtomicI32 = AtomicI32::new(0);
        static FORMAT_VALID: AtomicBool = AtomicBool::new(true);
        static HOG_OWNER: AtomicI32 = AtomicI32::new(-1);
        static SET_HOG_STATUS: AtomicI32 = AtomicI32::new(0);
        static SET_RATE_STATUS: AtomicI32 = AtomicI32::new(0);
        static SET_BUFFER_STATUS: AtomicI32 = AtomicI32::new(0);
        static DEFAULT_DEVICE: AtomicU32 = AtomicU32::new(3);
        static FAIL_SELECTOR: AtomicU32 = AtomicU32::new(0);
        static NULL_TAP_UID: AtomicBool = AtomicBool::new(false);
        static SAMPLES: Mutex<Vec<f32>> = Mutex::new(Vec::new());
        static SAMPLE_CHANNELS: AtomicU32 = AtomicU32::new(2);
        static DESTROYED_TAP: AtomicU32 = AtomicU32::new(0);
        static DESTROYED_AGGREGATE: AtomicU32 = AtomicU32::new(0);
        static DESTROYED_IOPROC: AtomicU32 = AtomicU32::new(0);
        static FAKE_UID: OnceLock<usize> = OnceLock::new();

        fn lock<T>(mutex: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
            mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        unsafe fn write_out<T: Copy>(out: *mut c_void, size: *mut u32, value: T) {
            if !size.is_null() {
                unsafe {
                    *size = std::mem::size_of::<T>() as u32;
                }
            }
            if !out.is_null() {
                unsafe {
                    *(out as *mut T) = value;
                }
            }
        }

        fn fake_uid() -> CFStringRef {
            let pointer = *FAKE_UID.get_or_init(|| {
                let uid = CFString::new("Casa1-Fake-Tap");
                let pointer = uid.as_concrete_TypeRef() as usize;
                std::mem::forget(uid);
                pointer
            });
            pointer as CFStringRef
        }

        unsafe extern "C" fn fake_get(
            object: AudioObjectId,
            address: *const AudioObjectPropertyAddress,
            _qualifier_size: u32,
            _qualifier: *const c_void,
            size: *mut u32,
            out: *mut c_void,
        ) -> OsStatus {
            if address.is_null() {
                return -50;
            }
            let selector = unsafe { (*address).selector };
            if FAIL_SELECTOR.load(Ordering::SeqCst) == selector {
                return -4;
            }
            match selector {
                HW_DEFAULT_OUTPUT_DEVICE => {
                    unsafe { write_out(out, size, DEFAULT_DEVICE.load(Ordering::SeqCst)) };
                    0
                }
                HW_TRANSLATE_PID_TO_PROCESS_OBJECT => {
                    unsafe { write_out(out, size, 5u32) };
                    0
                }
                TAP_FORMAT if object == 7 => {
                    let valid = FORMAT_VALID.load(Ordering::SeqCst);
                    let format = AudioStreamBasicDescription {
                        sample_rate: 48_000.0,
                        format_id: if valid { FORMAT_LINEAR_PCM } else { 0 },
                        format_flags: if valid { FORMAT_FLAG_IS_FLOAT } else { 0 },
                        bytes_per_packet: 8,
                        frames_per_packet: 1,
                        bytes_per_frame: 8,
                        channels_per_frame: if valid { 2 } else { 0 },
                        bits_per_channel: 32,
                        reserved: 0,
                    };
                    unsafe { write_out(out, size, format) };
                    0
                }
                TAP_UID if object == 7 => {
                    let uid = if NULL_TAP_UID.load(Ordering::SeqCst) {
                        ptr::null()
                    } else {
                        fake_uid()
                    };
                    unsafe { write_out(out, size, uid) };
                    0
                }
                DEVICE_HOG_MODE if object == 3 => {
                    unsafe { write_out(out, size, HOG_OWNER.load(Ordering::SeqCst)) };
                    0
                }
                DEVICE_NOMINAL_SAMPLE_RATE if object == 3 => {
                    unsafe { write_out(out, size, 48_000.0f64) };
                    0
                }
                DEVICE_BUFFER_FRAME_SIZE if object == 3 => {
                    unsafe { write_out(out, size, 128u32) };
                    0
                }
                _ => -4,
            }
        }

        unsafe extern "C" fn fake_set(
            object: AudioObjectId,
            address: *const AudioObjectPropertyAddress,
            _qualifier_size: u32,
            _qualifier: *const c_void,
            _size: u32,
            data: *const c_void,
        ) -> OsStatus {
            if address.is_null() || data.is_null() {
                return -50;
            }
            let selector = unsafe { (*address).selector };
            match selector {
                DEVICE_HOG_MODE if object == 3 => {
                    let status = SET_HOG_STATUS.load(Ordering::SeqCst);
                    if status == 0 {
                        let requested = unsafe { *(data as *const i32) };
                        let owner = HOG_OWNER.load(Ordering::SeqCst);
                        // CoreAudio treats setting hog mode to the current
                        // owner as a release, and to a free device as an
                        // acquire.
                        HOG_OWNER.store(
                            if owner == requested { -1 } else { requested },
                            Ordering::SeqCst,
                        );
                    }
                    status
                }
                DEVICE_NOMINAL_SAMPLE_RATE if object == 3 => SET_RATE_STATUS.load(Ordering::SeqCst),
                DEVICE_BUFFER_FRAME_SIZE if object == 3 => SET_BUFFER_STATUS.load(Ordering::SeqCst),
                _ => -4,
            }
        }

        unsafe extern "C" fn fake_create_tap(
            _description: *mut Object,
            tap: *mut AudioObjectId,
        ) -> OsStatus {
            let status = TAP_STATUS.load(Ordering::SeqCst);
            if status == 0 && !tap.is_null() {
                unsafe {
                    *tap = 7;
                }
            }
            status
        }

        unsafe extern "C" fn fake_destroy_tap(_tap: AudioObjectId) -> OsStatus {
            DESTROYED_TAP.fetch_add(1, Ordering::SeqCst);
            0
        }

        unsafe extern "C" fn fake_create_aggregate(
            _composition: *const c_void,
            aggregate: *mut AudioObjectId,
        ) -> OsStatus {
            let status = AGGREGATE_STATUS.load(Ordering::SeqCst);
            if status == 0 && !aggregate.is_null() {
                unsafe {
                    *aggregate = 8;
                }
            }
            status
        }

        unsafe extern "C" fn fake_destroy_aggregate(_aggregate: AudioObjectId) -> OsStatus {
            DESTROYED_AGGREGATE.fetch_add(1, Ordering::SeqCst);
            0
        }

        type IoArgs = (
            *const c_void,
            *const AudioBufferList,
            *const c_void,
            *mut AudioBufferList,
            *const c_void,
        );

        unsafe extern "C" fn fake_create_ioproc(
            ioproc: *mut AudioDeviceIoProcId,
            _device: AudioObjectId,
            _queue: *mut c_void,
            block: *const c_void,
        ) -> OsStatus {
            let status = IOPROC_STATUS.load(Ordering::SeqCst);
            if status != 0 {
                return status;
            }
            if ioproc.is_null() || block.is_null() {
                return -50;
            }
            unsafe {
                *ioproc = 0x1 as AudioDeviceIoProcId;
            }
            let samples = lock(&SAMPLES).clone();
            if samples.is_empty() {
                let block = unsafe { &*(block as *const block::Block<IoArgs, ()>) };
                unsafe {
                    block.call((
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null(),
                    ));
                }
            } else {
                let channels = SAMPLE_CHANNELS.load(Ordering::SeqCst).max(1);
                let mut data = samples;
                let buffer = AudioBuffer {
                    number_channels: channels,
                    data_byte_size: (data.len() * std::mem::size_of::<f32>()) as u32,
                    data: data.as_mut_ptr() as *mut c_void,
                };
                let list = AudioBufferList {
                    number_buffers: 1,
                    buffers: [buffer],
                };
                let block = unsafe { &*(block as *const block::Block<IoArgs, ()>) };
                unsafe {
                    block.call((
                        ptr::null(),
                        &list,
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null(),
                    ));
                }
            }
            0
        }

        unsafe extern "C" fn fake_destroy_ioproc(
            _device: AudioObjectId,
            _ioproc: AudioDeviceIoProcId,
        ) -> OsStatus {
            DESTROYED_IOPROC.fetch_add(1, Ordering::SeqCst);
            0
        }

        unsafe extern "C" fn fake_start(
            _device: AudioObjectId,
            _ioproc: AudioDeviceIoProcId,
        ) -> OsStatus {
            START_STATUS.load(Ordering::SeqCst)
        }

        unsafe extern "C" fn fake_stop(
            _device: AudioObjectId,
            _ioproc: AudioDeviceIoProcId,
        ) -> OsStatus {
            0
        }

        pub(crate) fn install() {
            TAP_STATUS.store(0, Ordering::SeqCst);
            AGGREGATE_STATUS.store(0, Ordering::SeqCst);
            IOPROC_STATUS.store(0, Ordering::SeqCst);
            START_STATUS.store(0, Ordering::SeqCst);
            FORMAT_VALID.store(true, Ordering::SeqCst);
            HOG_OWNER.store(-1, Ordering::SeqCst);
            SET_HOG_STATUS.store(0, Ordering::SeqCst);
            SET_RATE_STATUS.store(0, Ordering::SeqCst);
            SET_BUFFER_STATUS.store(0, Ordering::SeqCst);
            DEFAULT_DEVICE.store(3, Ordering::SeqCst);
            FAIL_SELECTOR.store(0, Ordering::SeqCst);
            NULL_TAP_UID.store(false, Ordering::SeqCst);
            SAMPLE_CHANNELS.store(2, Ordering::SeqCst);
            DESTROYED_TAP.store(0, Ordering::SeqCst);
            DESTROYED_AGGREGATE.store(0, Ordering::SeqCst);
            DESTROYED_IOPROC.store(0, Ordering::SeqCst);
            lock(&SAMPLES).clear();
            let api = CoreAudioApi {
                get_property_data: fake_get,
                set_property_data: fake_set,
                create_aggregate: fake_create_aggregate,
                destroy_aggregate: fake_destroy_aggregate,
                create_ioproc: fake_create_ioproc,
                destroy_ioproc: fake_destroy_ioproc,
                device_start: fake_start,
                device_stop: fake_stop,
                create_process_tap: Some(fake_create_tap),
                destroy_process_tap: Some(fake_destroy_tap),
            };
            *TEST_CORE_AUDIO_API
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::leak(Box::new(api)));
        }

        pub(crate) fn clear() {
            *TEST_CORE_AUDIO_API
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }

        pub(crate) fn set_tap_status(status: i32) {
            TAP_STATUS.store(status, Ordering::SeqCst);
        }

        pub(crate) fn set_aggregate_status(status: i32) {
            AGGREGATE_STATUS.store(status, Ordering::SeqCst);
        }

        pub(crate) fn set_ioproc_status(status: i32) {
            IOPROC_STATUS.store(status, Ordering::SeqCst);
        }

        pub(crate) fn set_start_status(status: i32) {
            START_STATUS.store(status, Ordering::SeqCst);
        }

        pub(crate) fn set_format_valid(valid: bool) {
            FORMAT_VALID.store(valid, Ordering::SeqCst);
        }

        pub(crate) fn set_samples(samples: Vec<f32>, channels: u16) {
            SAMPLE_CHANNELS.store(channels.max(1) as u32, Ordering::SeqCst);
            *lock(&SAMPLES) = samples;
        }

        pub(crate) fn set_hog(
            owner: i32,
            set_hog_status: i32,
            set_rate_status: i32,
            set_buffer_status: i32,
        ) {
            HOG_OWNER.store(owner, Ordering::SeqCst);
            SET_HOG_STATUS.store(set_hog_status, Ordering::SeqCst);
            SET_RATE_STATUS.store(set_rate_status, Ordering::SeqCst);
            SET_BUFFER_STATUS.store(set_buffer_status, Ordering::SeqCst);
        }

        pub(crate) fn hog_owner() -> i32 {
            HOG_OWNER.load(Ordering::SeqCst)
        }

        pub(crate) fn set_default_device(device: u32) {
            DEFAULT_DEVICE.store(device, Ordering::SeqCst);
        }

        pub(crate) fn null_tap_uid() {
            NULL_TAP_UID.store(true, Ordering::SeqCst);
        }

        pub(crate) fn fail_hog_mode_query() {
            FAIL_SELECTOR.store(DEVICE_HOG_MODE, Ordering::SeqCst);
        }

        pub(crate) fn destroy_counts() -> (u32, u32, u32) {
            (
                DESTROYED_TAP.load(Ordering::SeqCst),
                DESTROYED_AGGREGATE.load(Ordering::SeqCst),
                DESTROYED_IOPROC.load(Ordering::SeqCst),
            )
        }

        #[test]
        fn system_loopback_tap_exclusion_invalid_zero_process_is_a_noop() {
            unsafe {
                // own_process == 0 means "could not translate our PID"; the
                // helper must return before touching the process array.
                assert_eq!(exclude_own_process(ptr::null_mut(), 0), ());
            }
        }

        #[test]
        fn system_loopback_buffer_list_edge_shapes_are_pinned() {
            unsafe {
                assert_eq!(
                    audio_buffer_list_to_interleaved(ptr::null()),
                    (Vec::new(), 0)
                );
                let mut zero = AudioBufferList {
                    number_buffers: 0,
                    buffers: [AudioBuffer {
                        number_channels: 2,
                        data_byte_size: 8,
                        data: ptr::null_mut(),
                    }],
                };
                assert_eq!(
                    audio_buffer_list_to_interleaved(&zero as *const _),
                    (Vec::new(), 0)
                );
                let mut missing = AudioBufferList {
                    number_buffers: 1,
                    buffers: [AudioBuffer {
                        number_channels: 2,
                        data_byte_size: 8,
                        data: ptr::null_mut(),
                    }],
                };
                assert_eq!(
                    audio_buffer_list_to_interleaved(&missing as *const _),
                    (Vec::new(), 0)
                );
                let mut dummy = [0.0f32; 2];
                let empty_frames = AudioBufferList {
                    number_buffers: 1,
                    buffers: [AudioBuffer {
                        number_channels: 2,
                        data_byte_size: 0,
                        data: dummy.as_mut_ptr() as *mut c_void,
                    }],
                };
                assert_eq!(
                    audio_buffer_list_to_interleaved(&empty_frames as *const _),
                    (Vec::new(), 0)
                );
                let _ = &mut zero;
                let _ = &mut missing;

                let mut left = [0.1f32, 0.2];
                let mut right = [0.3f32, 0.4];
                let mut storage = vec![0u64; 8];
                let list = storage.as_mut_ptr() as *mut AudioBufferList;
                (*list).number_buffers = 2;
                let buffers = ptr::addr_of_mut!((*list).buffers) as *mut AudioBuffer;
                *buffers = AudioBuffer {
                    number_channels: 1,
                    data_byte_size: 8,
                    data: left.as_mut_ptr() as *mut c_void,
                };
                *buffers.add(1) = AudioBuffer {
                    number_channels: 1,
                    data_byte_size: 8,
                    data: right.as_mut_ptr() as *mut c_void,
                };
                assert_eq!(
                    audio_buffer_list_to_interleaved(list),
                    (vec![0.1, 0.3, 0.2, 0.4], 2)
                );
                *buffers.add(1) = AudioBuffer {
                    number_channels: 1,
                    data_byte_size: 8,
                    data: ptr::null_mut(),
                };
                // A null channel buffer makes the minimum frame count zero,
                // so the whole callback is rejected rather than half-read.
                assert_eq!(audio_buffer_list_to_interleaved(list), (Vec::new(), 0));
                *buffers = AudioBuffer {
                    number_channels: 1,
                    data_byte_size: 8,
                    data: ptr::null_mut(),
                };
                assert_eq!(audio_buffer_list_to_interleaved(list), (Vec::new(), 0));
            }
        }
    }

    #[cfg(test)]
    mod sck {
        use super::*;

        /// The production ScreenCaptureKit path is compiled out of the test
        /// binary (it needs Screen Recording TCC and a live display); the tap
        /// pipeline is exercised against the fake CoreAudio host instead.
        pub(super) fn start(
            _shared: Arc<Mutex<SystemLoopbackSink>>,
            _generation: u64,
        ) -> Result<SystemLoopbackSession, SystemLoopbackFailure> {
            Err(SystemLoopbackFailure::Unavailable)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_audio_backend_creates() {
        // Capability gate: audio services/hardware may be absent (headless
        // CI, VMs without a CoreAudio/WASAPI device). The backend itself
        // always constructs, so probe the device list instead.
        let backend = match RealAudioBackend::new() {
            Ok(backend) => backend,
            Err(error) => {
                eprintln!(
                    "skipping real_audio_backend_creates: no audio services available ({error})"
                );
                return;
            }
        };
        let devices = backend.enumerate_devices();
        if devices.is_empty() {
            eprintln!("skipping real_audio_backend_creates: no audio output devices present");
            return;
        }
        assert!(devices.iter().any(|d| d.is_default || !d.name.is_empty()));
    }

    #[test]
    fn default_device_detection() {
        // Capability gate: requires at least one real audio output device.
        let backend = match RealAudioBackend::new() {
            Ok(backend) => backend,
            Err(error) => {
                eprintln!("skipping default_device_detection: no audio services ({error})");
                return;
            }
        };
        if backend.enumerate_devices().is_empty() {
            eprintln!("skipping default_device_detection: no audio output devices present");
            return;
        }
        let default_id = backend.default_device_id();
        assert!(default_id.is_ok(), "expected Ok, got {default_id:?}");
    }

    #[test]
    fn latency_log_records_entries() {
        // Capability gate: the backend must initialize (audio services).
        let backend = match RealAudioBackend::new() {
            Ok(backend) => backend,
            Err(error) => {
                eprintln!("skipping latency_log_records_entries: no audio services ({error})");
                return;
            }
        };
        let log = backend.latency_log();
        // The log starts empty; entries are added when streams open
        assert!(log.len() <= 10);
    }

    #[test]
    fn device_hotplug_detect_changes() {
        // Capability gate: requires a live audio host to re-enumerate
        // (works with zero devices too, but a host is needed).
        let mut backend = match RealAudioBackend::new() {
            Ok(backend) => backend,
            Err(error) => {
                eprintln!("skipping device_hotplug_detect_changes: no audio services ({error})");
                return;
            }
        };
        // Calling detect_device_changes should succeed even if no changes
        let result = backend.detect_device_changes();
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    // ── Audio format detection tests ───────────────────────────────────

    // ── MS ADPCM decoder tests ──────────────────────────────────────────

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
    fn decode_ms_adpcm_unsupported_channels() {
        let result = decode_ms_adpcm(&[0; 24], 24, 3, 6);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // ── IMA ADPCM decoder tests ─────────────────────────────────────────

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

    // ── AudioFormat enum tests ──────────────────────────────────────────

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
    fn xapo_manager_process_unknown_id_returns_false() {
        let mut mgr = XapoManager::new();
        let mut output = vec![0.0f32; 4];
        assert!(!mgr.process_instance(999, &[1.0; 4], &mut output));
        assert!(!mgr.destroy_instance(999));
        assert!(!mgr.reset_instance(999));
    }

    // ── Audio-interface activation resolution tests ─────────────────────

    fn sample_device(id: u64, name: &str, is_default: bool) -> RealAudioDevice {
        RealAudioDevice {
            id,
            key: format!("{name}|2|48000"),
            name: name.to_string(),
            channels: 2,
            sample_rate: 48_000,
            is_default,
        }
    }

    #[test]
    fn activation_resolution_empty_list_is_no_devices() {
        assert_eq!(
            resolve_audio_activation_device(&[], None),
            Err(AudioActivationDeviceFailure::NoDevices)
        );
        assert_eq!(
            resolve_audio_activation_device(&[], Some("")),
            Err(AudioActivationDeviceFailure::NoDevices)
        );
        assert_eq!(
            resolve_audio_activation_device(&[], Some(DEVINTERFACE_AUDIO_RENDER)),
            Err(AudioActivationDeviceFailure::NoDevices)
        );
    }

    #[test]
    fn activation_resolution_capture_guid_and_unknown_paths_are_unknown_devices() {
        let devices = vec![sample_device(2, "Built-in Speakers", true)];
        assert_eq!(
            resolve_audio_activation_device(&devices, Some(DEVINTERFACE_AUDIO_CAPTURE)),
            Err(AudioActivationDeviceFailure::UnknownDevicePath)
        );
        assert_eq!(
            resolve_audio_activation_device(
                &devices,
                Some(
                    r"\?\SWD#MMDEVAPI#{0.0.0.00000000}.{guid}#{e6327cad-dcec-4949-ae8a-991e976a79d2}"
                ),
            ),
            Err(AudioActivationDeviceFailure::UnknownDevicePath)
        );
    }

    #[test]
    fn activation_resolution_list_without_default_is_no_devices() {
        // A device list with entries but no default render endpoint cannot
        // serve a default-device activation.
        let devices = vec![sample_device(1, "HDMI Output", false)];
        assert_eq!(
            resolve_audio_activation_device(&devices, None),
            Err(AudioActivationDeviceFailure::NoDevices)
        );
    }

    #[test]
    fn backend_activation_resolution_matches_pure_resolver() {
        // Capability gate: needs the real audio host to enumerate.
        let backend = match RealAudioBackend::new() {
            Ok(backend) => backend,
            Err(error) => {
                eprintln!("skipping backend_activation_resolution: no audio services ({error})");
                return;
            }
        };
        let snapshot = backend.activation_device_snapshot();
        if snapshot.is_empty() {
            assert_eq!(
                backend.resolve_activation_device(None),
                Err(AudioActivationDeviceFailure::NoDevices)
            );
            return;
        }
        let resolved = backend
            .resolve_activation_device(None)
            .expect("default device resolves when the list is non-empty");
        assert!(resolved.is_default);
        assert!(!resolved.name.is_empty());
        // The snapshot used for resolution is the same real device list.
        assert!(snapshot.iter().any(|device| device.id == resolved.id));
    }

    #[test]
    fn device_period_info_falls_back_to_the_device_sample_rate() {
        let backend = match RealAudioBackend::new() {
            Ok(backend) => backend,
            Err(error) => {
                eprintln!("skipping device_period_info fallback: no audio services ({error})");
                return;
            }
        };
        // A device key that cannot match a live enumeration uses the
        // sample-rate derived fallback: 10 ms default, 3 ms minimum.
        let device = RealAudioDevice {
            id: 999_999,
            key: "Casa1 Nonexistent Device|2|48000".to_string(),
            name: "Casa1 Nonexistent Device".to_string(),
            channels: 2,
            sample_rate: 48_000,
            is_default: false,
        };
        let info = backend.device_period_info(&device);
        assert_eq!(info.sample_rate, 48_000);
        assert_eq!(info.default_period_hns, 100_000);
        assert_eq!(info.minimum_period_hns, 30_000);
        assert!(info.minimum_period_hns <= info.default_period_hns);
        // Half the rate: the periods scale with the real device sample rate.
        let device_8k = RealAudioDevice {
            sample_rate: 8_000,
            ..device
        };
        let info_8k = backend.device_period_info(&device_8k);
        assert_eq!(info_8k.default_period_hns, 100_000);
        assert_eq!(info_8k.minimum_period_hns, 30_000);
    }

    #[test]
    fn device_period_info_uses_the_live_device_when_present() {
        let backend = match RealAudioBackend::new() {
            Ok(backend) => backend,
            Err(error) => {
                eprintln!("skipping device_period_info live: no audio services ({error})");
                return;
            }
        };
        let Some(live) = backend
            .activation_device_snapshot()
            .into_iter()
            .find(|device| device.is_default)
        else {
            eprintln!("skipping device_period_info live: no default audio device");
            return;
        };
        let info = backend.device_period_info(&live);
        assert!(info.sample_rate > 0);
        assert!(info.default_period_hns > 0);
        assert!(info.minimum_period_hns > 0);
        assert!(info.minimum_period_hns <= info.default_period_hns);
        assert_eq!(info.stream_latency_hns, info.default_period_hns);
    }

    #[test]
    fn last_latency_ms_reports_the_backend_record_for_a_device() {
        let backend = match RealAudioBackend::new() {
            Ok(backend) => backend,
            Err(error) => {
                eprintln!("skipping last_latency_ms: no audio services ({error})");
                return;
            }
        };
        // An unknown device has no latency record.
        assert_eq!(backend.last_latency_ms(999_999), None);
    }

    // ── System-output loopback (tap / ScreenCaptureKit) ─────────────────

    /// Serializes fake-host tests and restores the real probe on drop.
    struct FakeHostGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl FakeHostGuard {
        fn new() -> Self {
            let lock = lock_system_loopback_tests();
            platform::fake::install();
            set_test_system_loopback_capability(Some(SystemLoopbackBackend::CoreAudioProcessTap));
            Self { _lock: lock }
        }
    }

    impl Drop for FakeHostGuard {
        fn drop(&mut self) {
            set_test_system_loopback_capability(None);
            platform::fake::clear();
        }
    }

    fn fake_device(backend: &mut RealAudioBackend, id: DeviceId, is_default: bool) {
        backend.devices.insert(
            id,
            RealAudioDevice {
                id,
                key: format!("fake-device-{id}"),
                name: format!("Fake Device {id}"),
                channels: 2,
                sample_rate: 48_000,
                is_default,
            },
        );
    }

    fn exclusive_test_format() -> WaveFormat {
        WaveFormat {
            channels: 2,
            sample_rate: 48_000,
            sample_format: SampleFormat::Float32,
        }
    }

    #[test]
    fn system_loopback_process_tap_pipeline_captures_and_tears_down() {
        let _host = FakeHostGuard::new();
        platform::fake::set_samples(vec![0.25, 0.75, 0.5, 0.5], 2);
        let mut backend = RealAudioBackend::new().expect("backend");
        assert_eq!(
            backend.start_system_loopback(),
            Ok(SystemLoopbackBackend::CoreAudioProcessTap)
        );
        assert_eq!(backend.system_loopback_format(), Some((2, 48_000)));
        assert_eq!(backend.system_loopback_available_frames(), 2);
        assert_eq!(
            backend.read_system_loopback_data(),
            vec![0.25, 0.75, 0.5, 0.5]
        );
        let status = backend.system_loopback_status();
        assert_eq!(status.frames_delivered, 2);
        assert_eq!(status.buffered_frames, 0);
        backend.stop_system_loopback();
        assert!(!backend.system_loopback_running());
        assert_eq!(
            platform::fake::destroy_counts(),
            (1, 1, 1),
            "tap, aggregate and IOProc are all released exactly once"
        );
    }

    #[test]
    fn system_loopback_tap_creation_failure_is_pinned() {
        let _host = FakeHostGuard::new();
        platform::fake::set_tap_status(-50);
        let mut backend = RealAudioBackend::new().expect("backend");
        assert_eq!(
            backend.start_system_loopback(),
            Err(SystemLoopbackFailure::TapCreation(-50))
        );
        assert!(!backend.system_loopback_running());
        assert_eq!(platform::fake::destroy_counts(), (0, 0, 0));
    }

    #[test]
    fn system_loopback_aggregate_creation_failure_is_pinned() {
        let _host = FakeHostGuard::new();
        platform::fake::set_aggregate_status(-4);
        let mut backend = RealAudioBackend::new().expect("backend");
        assert_eq!(
            backend.start_system_loopback(),
            Err(SystemLoopbackFailure::AggregateCreation(-4))
        );
        assert_eq!(
            platform::fake::destroy_counts(),
            (1, 0, 0),
            "a failed aggregate creation still destroys the tap"
        );
    }

    #[test]
    fn system_loopback_stream_start_failure_is_pinned() {
        let _host = FakeHostGuard::new();
        platform::fake::set_start_status(-1);
        let mut backend = RealAudioBackend::new().expect("backend");
        assert_eq!(
            backend.start_system_loopback(),
            Err(SystemLoopbackFailure::StreamStart(-1))
        );
        assert_eq!(
            platform::fake::destroy_counts(),
            (1, 1, 1),
            "a failed device start unwinds the IOProc, aggregate and tap"
        );
    }

    #[test]
    fn system_loopback_tap_format_unavailable_is_pinned() {
        let _host = FakeHostGuard::new();
        platform::fake::set_format_valid(false);
        let mut backend = RealAudioBackend::new().expect("backend");
        assert_eq!(
            backend.start_system_loopback(),
            Err(SystemLoopbackFailure::FormatUnavailable)
        );
        assert_eq!(platform::fake::destroy_counts(), (1, 0, 0));
    }

    #[test]
    fn system_loopback_ioproc_failure_unwinds_aggregate_and_tap() {
        let _host = FakeHostGuard::new();
        platform::fake::set_ioproc_status(-1);
        let mut backend = RealAudioBackend::new().expect("backend");
        assert_eq!(
            backend.start_system_loopback(),
            Err(SystemLoopbackFailure::StreamStart(-1))
        );
        assert_eq!(platform::fake::destroy_counts(), (1, 1, 0));
    }

    #[test]
    fn system_loopback_empty_callback_is_dropped_without_frames() {
        let _host = FakeHostGuard::new();
        let mut backend = RealAudioBackend::new().expect("backend");
        assert_eq!(
            backend.start_system_loopback(),
            Ok(SystemLoopbackBackend::CoreAudioProcessTap)
        );
        assert_eq!(backend.system_loopback_available_frames(), 0);
        assert_eq!(backend.system_loopback_status().frames_delivered, 0);
        backend.stop_system_loopback();
        assert_eq!(platform::fake::destroy_counts(), (1, 1, 1));
    }

    #[test]
    fn system_loopback_null_tap_uid_is_a_failure() {
        let _host = FakeHostGuard::new();
        platform::fake::null_tap_uid();
        let mut backend = RealAudioBackend::new().expect("backend");
        assert_eq!(
            backend.start_system_loopback(),
            Err(SystemLoopbackFailure::ObjectUnavailable)
        );
        assert_eq!(platform::fake::destroy_counts(), (1, 0, 0));
    }

    #[test]
    fn system_loopback_sck_fallback_is_unavailable() {
        let shared = Arc::new(Mutex::new(SystemLoopbackSink::new(1, 2, 48_000)));
        assert_eq!(
            platform::start_screen_capture_kit(shared, 1).err(),
            Some(SystemLoopbackFailure::Unavailable)
        );
    }

    #[test]
    fn exclusive_mode_hog_acquire_and_release_are_pinned() {
        let _host = FakeHostGuard::new();
        platform::fake::set_hog(-1, 0, 0, 0);
        let mut backend = RealAudioBackend::new().expect("backend");
        fake_device(&mut backend, 11, true);
        force_next_exclusive_stream_open(Some(Ok(128)));
        let client = backend
            .open_wasapi_client_exclusive(11, exclusive_test_format())
            .expect("fake exclusive open");
        assert_eq!(
            backend.exclusive_client_hog_mode(client),
            Some(HogModeOutcome::Acquired)
        );
        assert!(backend.hog_mode_held(11));
        assert_eq!(
            platform::fake::hog_owner(),
            std::process::id() as i32,
            "hog mode is owned by this process"
        );
        backend.close_stream(11);
        assert!(!backend.hog_mode_held(11));
        assert_eq!(platform::fake::hog_owner(), -1, "hog mode is released");
        assert_eq!(backend.exclusive_client_hog_mode(client), None);
    }

    #[test]
    fn exclusive_mode_hog_denial_keeps_the_client_contract() {
        let _host = FakeHostGuard::new();
        platform::fake::set_hog(1_234, -50, 0, 0);
        let mut backend = RealAudioBackend::new().expect("backend");
        fake_device(&mut backend, 12, true);
        force_next_exclusive_stream_open(Some(Ok(64)));
        let client = backend
            .open_wasapi_client_exclusive(12, exclusive_test_format())
            .expect("client-side exclusive open still succeeds");
        assert_eq!(
            backend.exclusive_client_hog_mode(client),
            Some(HogModeOutcome::Denied { owner_pid: 1_234 })
        );
        assert!(!backend.hog_mode_held(12));
        assert_eq!(
            backend
                .exclusive_clients
                .get(&client)
                .expect("exclusive state")
                .buffer_frames,
            64
        );
        backend.hog_devices.insert(12, std::process::id() as i32);
        backend.close_all_streams();
        assert!(!backend.hog_mode_held(12));
    }

    #[test]
    fn exclusive_mode_hog_rate_failure_releases_and_falls_back() {
        let _host = FakeHostGuard::new();
        platform::fake::set_hog(-1, 0, -50, 0);
        let mut backend = RealAudioBackend::new().expect("backend");
        fake_device(&mut backend, 13, true);
        force_next_exclusive_stream_open(Some(Ok(64)));
        let client = backend
            .open_wasapi_client_exclusive(13, exclusive_test_format())
            .expect("client-side exclusive open still succeeds");
        assert_eq!(
            backend.exclusive_client_hog_mode(client),
            Some(HogModeOutcome::Unavailable)
        );
        assert!(!backend.hog_mode_held(13));
        assert_eq!(
            platform::fake::hog_owner(),
            -1,
            "the failed rate pin released hog mode"
        );
        backend.close_stream(13);
    }

    #[test]
    fn exclusive_mode_stream_open_failure_releases_hog() {
        let _host = FakeHostGuard::new();
        platform::fake::set_hog(-1, 0, 0, 0);
        let mut backend = RealAudioBackend::new().expect("backend");
        fake_device(&mut backend, 14, true);
        force_next_exclusive_stream_open(Some(Err(-50)));
        let error = backend
            .open_wasapi_client_exclusive(14, exclusive_test_format())
            .expect_err("forced exclusive stream failure");
        assert_eq!(error.code, ReasonCode::RcAudioUnsupported);
        assert!(!backend.hog_mode_held(14));
        assert_eq!(
            platform::fake::hog_owner(),
            -1,
            "a failed stream open releases the already-acquired hog"
        );
    }

    #[test]
    fn exclusive_mode_non_default_device_reports_hog_unavailable() {
        let _host = FakeHostGuard::new();
        platform::fake::set_hog(-1, 0, 0, 0);
        let mut backend = RealAudioBackend::new().expect("backend");
        fake_device(&mut backend, 18, false);
        force_next_exclusive_stream_open(Some(Ok(64)));
        let client = backend
            .open_wasapi_client_exclusive(18, exclusive_test_format())
            .expect("client-side exclusive open");
        assert_eq!(
            backend.exclusive_client_hog_mode(client),
            Some(HogModeOutcome::Unavailable),
            "hog mode is only attempted on the default output device"
        );
        assert!(!backend.hog_mode_held(18));
        backend.close_stream(18);
    }

    #[test]
    fn exclusive_mode_missing_default_output_reports_hog_unavailable() {
        let _host = FakeHostGuard::new();
        platform::fake::set_hog(-1, 0, 0, 0);
        platform::fake::set_default_device(0);
        let mut backend = RealAudioBackend::new().expect("backend");
        fake_device(&mut backend, 19, true);
        force_next_exclusive_stream_open(Some(Ok(64)));
        let client = backend
            .open_wasapi_client_exclusive(19, exclusive_test_format())
            .expect("client-side exclusive open");
        assert_eq!(
            backend.exclusive_client_hog_mode(client),
            Some(HogModeOutcome::Unavailable),
            "a host with no default output cannot provide hog mode"
        );
        assert!(!backend.hog_mode_held(19));
        backend.close_stream(19);
    }

    #[test]
    fn exclusive_mode_second_client_failure_keeps_the_first_hog() {
        let _host = FakeHostGuard::new();
        platform::fake::set_hog(-1, 0, 0, 0);
        let mut backend = RealAudioBackend::new().expect("backend");
        fake_device(&mut backend, 20, true);
        force_next_exclusive_stream_open(Some(Ok(128)));
        let first = backend
            .open_wasapi_client_exclusive(20, exclusive_test_format())
            .expect("first exclusive client");
        assert!(backend.hog_mode_held(20));
        force_next_exclusive_stream_open(Some(Err(-50)));
        backend
            .open_wasapi_client_exclusive(20, exclusive_test_format())
            .expect_err("second exclusive open fails");
        assert_eq!(
            backend.hog_mode_held(20),
            true,
            "a failed second client must not release the first client's hog"
        );
        assert_eq!(backend.exclusive_client_hog_mode(first).is_some(), true);
        backend.close_stream(20);
        assert!(!backend.hog_mode_held(20));
    }

    #[test]
    fn exclusive_mode_hog_release_failure_is_reported_but_drops_the_lease() {
        let _host = FakeHostGuard::new();
        platform::fake::set_hog(-1, 0, 0, 0);
        let mut backend = RealAudioBackend::new().expect("backend");
        fake_device(&mut backend, 21, true);
        force_next_exclusive_stream_open(Some(Ok(64)));
        backend
            .open_wasapi_client_exclusive(21, exclusive_test_format())
            .expect("exclusive open");
        let our_pid = std::process::id() as i32;
        platform::fake::set_hog(our_pid, -50, 0, 0);
        backend.close_stream(21);
        assert!(
            !backend.hog_mode_held(21),
            "the emulator lease is dropped even when the host release fails"
        );
        assert_eq!(platform::fake::hog_owner(), our_pid);
        platform::fake::set_hog(-1, 0, 0, 0);
    }

    #[test]
    fn hog_mode_property_query_failure_is_reported() {
        let _host = FakeHostGuard::new();
        platform::fake::fail_hog_mode_query();
        let mut driver =
            platform::CoreAudioHogDriver::open_default_output().expect("fake default device");
        assert_eq!(driver.hog_owner(), Err(-4));
        assert_eq!(
            acquire_exclusive_hog_with(&mut driver, std::process::id() as i32, 48_000),
            HogModeOutcome::Unavailable
        );
    }

    #[test]
    fn device_hotplug_stale_removal_releases_hog() {
        let _host = FakeHostGuard::new();
        let mut backend = RealAudioBackend::new().expect("backend");
        let stale = 999_999;
        fake_device(&mut backend, stale, false);
        backend.hog_devices.insert(stale, std::process::id() as i32);
        if backend.detect_device_changes().is_err() {
            return;
        }
        assert_eq!(
            backend.hog_mode_held(stale),
            false,
            "a device removed by hotplug loses its hog lease"
        );
    }

    #[test]
    fn exclusive_mode_buffer_pin_failure_is_reported_but_keeps_hog() {
        let _host = FakeHostGuard::new();
        platform::fake::set_hog(-1, 0, 0, -50);
        let mut backend = RealAudioBackend::new().expect("backend");
        fake_device(&mut backend, 15, true);
        force_next_exclusive_stream_open(Some(Ok(64)));
        let client = backend
            .open_wasapi_client_exclusive(15, exclusive_test_format())
            .expect("fake exclusive open");
        assert_eq!(
            backend.exclusive_client_hog_mode(client),
            Some(HogModeOutcome::Acquired)
        );
        assert!(
            backend.hog_mode_held(15),
            "a buffer-size pin failure does not drop the hog lease"
        );
        backend.close_stream(15);
    }

    #[test]
    fn system_loopback_probe_fallback_classification_is_pinned() {
        assert_eq!(
            classify_system_loopback_probe(true, true, false),
            SystemLoopbackBackend::CoreAudioProcessTap
        );
        assert_eq!(
            classify_system_loopback_probe(false, true, false),
            SystemLoopbackBackend::ScreenCaptureKit
        );
        assert_eq!(
            classify_system_loopback_probe(false, false, false),
            SystemLoopbackBackend::Unavailable
        );
        assert_eq!(
            classify_system_loopback_probe(true, true, true),
            SystemLoopbackBackend::Unavailable,
            "CASA1_SYSTEM_LOOPBACK=off always forces the fallback"
        );
        let _lock = lock_system_loopback_tests();
        platform::fake::clear();
        let real = probe_system_loopback_capability_for_test();
        assert!(
            matches!(
                real,
                SystemLoopbackBackend::CoreAudioProcessTap
                    | SystemLoopbackBackend::ScreenCaptureKit
                    | SystemLoopbackBackend::Unavailable
            ),
            "the real probe loads the host frameworks without panicking"
        );
    }

    #[test]
    fn system_loopback_failure_stage_mapping_is_pinned() {
        assert_eq!(
            classify_system_loopback_failure(SystemLoopbackFailure::TapCreation(0), -50),
            SystemLoopbackFailure::TapCreation(-50)
        );
        assert_eq!(
            classify_system_loopback_failure(SystemLoopbackFailure::AggregateCreation(0), -4),
            SystemLoopbackFailure::AggregateCreation(-4)
        );
        assert_eq!(
            classify_system_loopback_failure(SystemLoopbackFailure::StreamStart(0), -1),
            SystemLoopbackFailure::StreamStart(-1)
        );
        assert_eq!(
            classify_system_loopback_failure(SystemLoopbackFailure::FormatUnavailable, -1),
            SystemLoopbackFailure::FormatUnavailable
        );
    }

    #[test]
    fn system_loopback_stale_generation_is_rejected_after_test_session_teardown() {
        let mut backend = RealAudioBackend::new().expect("backend");
        let generation = backend.install_test_system_loopback(2, 8_000);
        assert!(backend.system_loopback_running());
        assert_eq!(backend.system_loopback_format(), Some((2, 8_000)));
        assert!(backend.push_test_system_loopback_frames(generation, 2, 8_000, &[0.25; 8]));
        assert_eq!(backend.system_loopback_available_frames(), 4);
        let status = backend.system_loopback_status();
        assert!(status.running);
        assert_eq!(status.generation, generation);
        assert_eq!(
            status.backend,
            Some(SystemLoopbackBackend::CoreAudioProcessTap)
        );
        assert_eq!(status.channels, 2);
        assert_eq!(status.sample_rate, 8_000);
        assert_eq!(status.buffered_frames, 4);
        assert_eq!(status.frames_delivered, 4);
        assert_eq!(status.dropped_frames, 0);

        backend.stop_system_loopback();
        assert!(!backend.system_loopback_running());
        assert!(
            !backend.push_test_system_loopback_frames(generation, 2, 8_000, &[0.5; 8]),
            "a callback from the torn-down session must be rejected"
        );
        assert_eq!(backend.system_loopback_available_frames(), 0);
        assert_eq!(backend.read_system_loopback_data(), Vec::<f32>::new());
        let status = backend.system_loopback_status();
        assert!(!status.running);
        assert_eq!(status.backend, None);
        assert_eq!(status.generation, 0);
    }

    #[test]
    fn system_loopback_sink_history_boundary_drops_oldest_frames() {
        let mut sink = SystemLoopbackSink::new(3, 1, 1_000);
        assert_eq!(sink.max_samples(), 4_000);
        assert!(
            sink.ingest(3, 1, 1_000, &[]),
            "an empty callback is accepted without touching history"
        );
        let input: Vec<f32> = (0..5_000).map(|value| value as f32).collect();
        assert!(sink.ingest(3, 1, 1_000, &input[..3_000]));
        assert!(sink.ingest(3, 1, 1_000, &input[3_000..]));
        assert_eq!(sink.samples.len(), 4_000);
        assert_eq!(sink.samples.front().copied(), Some(1_000.0));
        assert_eq!(sink.samples.back().copied(), Some(4_999.0));
        assert_eq!(sink.dropped_frames, 1_000);
        // A callback larger than the whole history exercises the
        // after-drop truncation path as well as the oldest-frame eviction.
        assert!(sink.ingest(3, 1, 1_000, &input));
        assert_eq!(sink.samples.len(), 4_000);
        assert_eq!(sink.samples.front().copied(), Some(1_000.0));
        assert_eq!(sink.samples.back().copied(), Some(4_999.0));
        assert_eq!(sink.dropped_frames, 6_000);
        assert!(
            !sink.ingest(2, 1, 1_000, &[1.0]),
            "an old generation cannot grow the replacement history"
        );
    }

    #[test]
    fn system_loopback_sink_format_change_discards_incompatible_history() {
        let mut sink = SystemLoopbackSink::new(4, 2, 48_000);
        assert!(sink.ingest(4, 2, 48_000, &[0.1; 4]));
        assert_eq!(sink.samples.len(), 4);
        assert!(sink.ingest(4, 2, 44_100, &[0.2; 2]));
        assert_eq!(sink.sample_rate, 44_100);
        assert_eq!(sink.samples, VecDeque::from(vec![0.2, 0.2]));
        sink.stop(4);
        assert!(sink.samples.is_empty());
        assert!(!sink.ingest(4, 2, 44_100, &[0.3; 2]));
    }

    #[test]
    fn system_loopback_capability_unavailable_never_starts() {
        let _lock = lock_system_loopback_tests();
        set_test_system_loopback_capability(Some(SystemLoopbackBackend::Unavailable));
        let mut backend = RealAudioBackend::new().expect("backend");
        assert_eq!(
            backend.system_loopback_capability(),
            SystemLoopbackBackend::Unavailable
        );
        assert_eq!(
            backend.start_system_loopback(),
            Err(SystemLoopbackFailure::Unavailable)
        );
        assert!(!backend.system_loopback_running());
        set_test_system_loopback_capability(None);
    }

    #[test]
    fn system_loopback_duplicate_start_is_idempotent() {
        let _lock = lock_system_loopback_tests();
        set_test_system_loopback_capability(Some(SystemLoopbackBackend::CoreAudioProcessTap));
        let mut backend = RealAudioBackend::new().expect("backend");
        let generation = backend.install_test_system_loopback(2, 48_000);
        assert_eq!(
            backend.start_system_loopback(),
            Ok(SystemLoopbackBackend::CoreAudioProcessTap)
        );
        assert_eq!(
            backend.start_system_loopback(),
            Ok(SystemLoopbackBackend::CoreAudioProcessTap),
            "a second Start reuses the live session"
        );
        assert_eq!(backend.system_loopback_status().generation, generation);
        backend.stop_system_loopback();
        set_test_system_loopback_capability(None);
    }

    #[test]
    fn system_loopback_real_start_or_creation_failure_is_reported() {
        if std::env::var("CASA1_TEST_REAL_SYSTEM_LOOPBACK").as_deref() != Ok("1") {
            eprintln!(
                "skipping system_loopback_real_start_or_creation_failure_is_reported: set CASA1_TEST_REAL_SYSTEM_LOOPBACK=1"
            );
            return;
        }
        let mut backend = RealAudioBackend::new().expect("backend");
        let capability = probe_system_loopback_capability_for_test();
        match backend.start_system_loopback() {
            Ok(used) => {
                assert_eq!(used, capability, "the probed backend is the one used");
                assert!(backend.system_loopback_running());
                backend.stop_system_loopback();
                assert!(!backend.system_loopback_running());
            }
            Err(failure) => {
                assert_ne!(
                    failure,
                    SystemLoopbackFailure::Unavailable,
                    "a probed backend fails for a real creation reason"
                );
                assert!(!backend.system_loopback_running());
            }
        }
    }

    // ── CoreAudio hog mode ───────────────────────────────────────────────

    #[derive(Default)]
    struct FakeHogDriver {
        owner: i32,
        owner_error: Option<i32>,
        set_result: Option<i32>,
        set_calls: u32,
        release_called: bool,
        rate_result: Option<i32>,
        rates: Vec<f64>,
    }

    impl HogModeDriver for FakeHogDriver {
        fn hog_owner(&mut self) -> Result<i32, i32> {
            match self.owner_error {
                Some(status) => Err(status),
                None => Ok(self.owner),
            }
        }

        fn set_hog(&mut self) -> Result<i32, i32> {
            self.set_calls += 1;
            match self.set_result {
                Some(owner) => {
                    self.owner = owner;
                    Ok(owner)
                }
                None => Err(-50),
            }
        }

        fn release_hog(&mut self) -> Result<(), i32> {
            self.release_called = true;
            if self.owner != -1 {
                self.owner = -1;
            }
            Ok(())
        }

        fn set_nominal_sample_rate(&mut self, sample_rate: f64) -> Result<(), i32> {
            self.rates.push(sample_rate);
            match self.rate_result {
                Some(status) => Err(status),
                None => Ok(()),
            }
        }

        fn set_buffer_frame_size(&mut self, _frames: u32) -> Result<(), i32> {
            Ok(())
        }
    }

    #[test]
    fn hog_mode_deny_and_unavailable_pin_the_client_contract() {
        let mut denied = FakeHogDriver {
            owner: 1_234,
            set_result: Some(1_234),
            ..FakeHogDriver::default()
        };
        let outcome = acquire_exclusive_hog_with(&mut denied, 42, 48_000);
        assert_eq!(outcome, HogModeOutcome::Denied { owner_pid: 1_234 });
        assert!(!outcome.is_exclusive());
        assert_eq!(denied.set_calls, 1);

        let mut unavailable = FakeHogDriver {
            owner: -1,
            set_result: None,
            ..FakeHogDriver::default()
        };
        assert_eq!(
            acquire_exclusive_hog_with(&mut unavailable, 42, 48_000),
            HogModeOutcome::Unavailable,
            "a refused set with a still-free device is unavailable, not denied"
        );
        assert!(!unavailable.release_called);
    }

    #[test]
    fn hog_mode_owner_query_failure_is_reported_as_unavailable() {
        let mut driver = FakeHogDriver {
            owner_error: Some(-4),
            ..FakeHogDriver::default()
        };
        assert_eq!(
            acquire_exclusive_hog_with(&mut driver, 42, 48_000),
            HogModeOutcome::Unavailable
        );
        assert_eq!(driver.set_calls, 0, "no hog set on an unqueryable device");
    }

    struct SecondQueryFailsDriver {
        calls: u32,
    }

    impl HogModeDriver for SecondQueryFailsDriver {
        fn hog_owner(&mut self) -> Result<i32, i32> {
            self.calls += 1;
            if self.calls == 1 { Ok(-1) } else { Err(-4) }
        }

        fn set_hog(&mut self) -> Result<i32, i32> {
            Err(-50)
        }

        fn release_hog(&mut self) -> Result<(), i32> {
            Ok(())
        }

        fn set_nominal_sample_rate(&mut self, _sample_rate: f64) -> Result<(), i32> {
            Ok(())
        }

        fn set_buffer_frame_size(&mut self, _frames: u32) -> Result<(), i32> {
            Ok(())
        }
    }

    #[test]
    fn hog_mode_set_failure_then_query_failure_is_unavailable() {
        let mut driver = SecondQueryFailsDriver { calls: 0 };
        assert_eq!(
            acquire_exclusive_hog_with(&mut driver, 42, 48_000),
            HogModeOutcome::Unavailable
        );
        assert_eq!(
            driver.calls, 2,
            "the owner is re-queried after a failed set"
        );
    }

    #[test]
    fn hog_mode_rate_pin_failure_releases_and_falls_back() {
        let mut driver = FakeHogDriver {
            owner: -1,
            set_result: Some(42),
            rate_result: Some(-50),
            ..FakeHogDriver::default()
        };
        let outcome = acquire_exclusive_hog_with(&mut driver, 42, 44_100);
        assert_eq!(outcome, HogModeOutcome::Unavailable);
        assert!(
            driver.release_called,
            "a failed exact-rate pin releases hog"
        );
        assert_eq!(driver.rates, vec![44_100.0]);
        assert_eq!(driver.owner, -1);
    }

    #[test]
    fn hog_mode_already_held_reacquire_is_rejected_and_pins_the_rate() {
        let mut driver = FakeHogDriver {
            owner: 42,
            set_result: Some(0),
            ..FakeHogDriver::default()
        };
        let outcome = acquire_exclusive_hog_with(&mut driver, 42, 96_000);
        assert_eq!(outcome, HogModeOutcome::AlreadyHeld);
        assert!(outcome.is_exclusive());
        assert_eq!(driver.set_calls, 0, "hog is not re-taken");
        assert_eq!(driver.rates, vec![96_000.0]);
    }
}
