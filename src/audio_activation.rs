//! Real audio-interface activation (`ActivateAudioInterfaceAsync`).
//!
//! Guest-facing activation model for the `mmdevapi.dll`
//! `ActivateAudioInterfaceAsync` export, backed by the REAL device stack in
//! [`crate::real_audio`]:
//!
//! - The requested COM interface id (`riid`) selects what is activated.
//!   Every supported audio-client family riid (`IAudioClient`,
//!   `IAudioClient2`, `IAudioClient3`) activates the same deepest real object
//!   the stack can back: a guest audio-endpoint object bound to the real
//!   device with the real device's data (id, name, channels, sample rate,
//!   default flag) as enumerated from the host. Unsupported riids fail the
//!   activation with `E_NOINTERFACE`.
//! - The activated endpoint carries a real `IAudioClient` method vtable (the
//!   host thunks declared in this module): `Initialize` parses and validates
//!   the guest `WAVEFORMATEX`/`WAVEFORMATEXTENSIBLE` and stores the real
//!   initialized format and buffer geometry; `Start`/`Stop`/`Reset` drive a
//!   real playback clock that drains the committed frames at the initialized
//!   sample rate, so `GetCurrentPadding` is real client-side buffer
//!   accounting; `GetService(IID_IAudioRenderClient)` produces a real guest
//!   render-client object whose `GetBuffer`/`ReleaseBuffer` hand out and
//!   reclaim a real guest-visible buffer whose released frames flow into the
//!   real cpal output stream (see the "IAudioClient / IAudioRenderClient"
//!   section below).
//! - Activation is asynchronous: the dispatch records a pending completion
//!   (handler + result) here, and the runtime's servicing points (block
//!   dispatch safepoint, message-loop idle drain) invoke the handler in guest
//!   context — the handler is never called inline inside the activation call.
//! - Every activation outcome carries a real HRESULT: `S_OK` with the
//!   activated endpoint object, `AUDCLNT_E_DEVICE_INVALIDATED` when the real
//!   device list is genuinely empty or the requested endpoint does not exist,
//!   `E_NOINTERFACE` for an unsupported riid. Invalid arguments
//!   (`E_INVALIDARG`) fail synchronously and never invoke the handler.
//!
//! The store is keyed by the runtime's guest pid ([`crate::runtime::process`]
//! pid namespace — one value per live runtime), so parallel runtimes in the
//! test suite never observe each other's pending activations or endpoint
//! records.

use crate::audio::{SampleFormat, WaveFormat};
use crate::real_audio::{RealAudioBackend, RealAudioDevice};
use crate::runtime::HostThunk;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Activation HRESULTs
// ---------------------------------------------------------------------------

/// `S_OK`.
pub const ACTIVATION_S_OK: u32 = 0;
/// `E_INVALIDARG` — a required argument is null/invalid; returned
/// synchronously and the completion handler is never invoked.
pub const ACTIVATION_E_INVALIDARG: u32 = 0x8007_0057;
/// `E_NOINTERFACE` — the requested riid is not backed by this runtime.
pub const ACTIVATION_E_NOINTERFACE: u32 = 0x8000_4002;
/// `AUDCLNT_E_DEVICE_INVALIDATED` `AUDCLNT_ERR(0x004)` — the real device list
/// is genuinely empty (or the requested device endpoint does not exist on
/// this host).
pub const AUDCLNT_E_DEVICE_INVALIDATED: u32 = 0x8889_0004;

// ---------------------------------------------------------------------------
// WASAPI IAudioClient HRESULTs, flags and formats (audioclient.h)
// ---------------------------------------------------------------------------

/// `S_OK`.
pub const AUDCLNT_S_OK: u32 = 0;
/// `S_FALSE` — a shared-mode format supported through the audio engine's
/// conversion (channel remap / resample), not bit-exact.
pub const AUDCLNT_S_FALSE: u32 = 1;
/// `E_POINTER` — a required pointer argument is null.
pub const AUDCLNT_E_POINTER: u32 = 0x8000_4003;
/// `E_INVALIDARG` — an argument value is invalid.
pub const AUDCLNT_E_INVALIDARG: u32 = 0x8007_0057;
/// `AUDCLNT_E_NOT_INITIALIZED` `AUDCLNT_ERR(0x001)`.
pub const AUDCLNT_E_NOT_INITIALIZED: u32 = 0x8889_0001;
/// `AUDCLNT_E_ALREADY_INITIALIZED` `AUDCLNT_ERR(0x002)`.
pub const AUDCLNT_E_ALREADY_INITIALIZED: u32 = 0x8889_0002;
/// `AUDCLNT_E_WRONG_ENDPOINT_TYPE` `AUDCLNT_ERR(0x003)`.
pub const AUDCLNT_E_WRONG_ENDPOINT_TYPE: u32 = 0x8889_0003;
/// `AUDCLNT_E_NOT_STOPPED` `AUDCLNT_ERR(0x005)`.
pub const AUDCLNT_E_NOT_STOPPED: u32 = 0x8889_0005;
/// `AUDCLNT_E_BUFFER_TOO_LARGE` `AUDCLNT_ERR(0x006)`.
pub const AUDCLNT_E_BUFFER_TOO_LARGE: u32 = 0x8889_0006;
/// `AUDCLNT_E_OUT_OF_ORDER` `AUDCLNT_ERR(0x007)`.
pub const AUDCLNT_E_OUT_OF_ORDER: u32 = 0x8889_0007;
/// `AUDCLNT_E_UNSUPPORTED_FORMAT` `AUDCLNT_ERR(0x008)`.
pub const AUDCLNT_E_UNSUPPORTED_FORMAT: u32 = 0x8889_0008;
/// `AUDCLNT_E_INVALID_SIZE` `AUDCLNT_ERR(0x009)`.
pub const AUDCLNT_E_INVALID_SIZE: u32 = 0x8889_0009;
/// `AUDCLNT_E_BUFFER_OPERATION_PENDING` `AUDCLNT_ERR(0x00B)`.
pub const AUDCLNT_E_BUFFER_OPERATION_PENDING: u32 = 0x8889_000B;
/// The documented "stream is not started" error (`AUDCLNT_ERR(0x00D)`; the
/// MSDN `IAudioRenderClient::GetBuffer`/`ReleaseBuffer` contract).
pub const AUDCLNT_E_NOT_STARTED: u32 = 0x8889_000D;
/// `AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED` `AUDCLNT_ERR(0x011)`.
pub const AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED: u32 = 0x8889_0011;
/// `AUDCLNT_E_EVENTHANDLE_NOT_SET` `AUDCLNT_ERR(0x014)`.
pub const AUDCLNT_E_EVENTHANDLE_NOT_SET: u32 = 0x8889_0014;
/// `AUDCLNT_E_BUFFER_SIZE_ERROR` `AUDCLNT_ERR(0x016)`.
pub const AUDCLNT_E_BUFFER_SIZE_ERROR: u32 = 0x8889_0016;
/// `AUDCLNT_E_INVALID_DEVICE_PERIOD` `AUDCLNT_ERR(0x020)`.
pub const AUDCLNT_E_INVALID_DEVICE_PERIOD: u32 = 0x8889_0020;
/// `AUDCLNT_E_INVALID_STREAM_FLAG` `AUDCLNT_ERR(0x021)`.
pub const AUDCLNT_E_INVALID_STREAM_FLAG: u32 = 0x8889_0021;

/// `AUDCLNT_SHAREMODE_SHARED`.
pub const AUDCLNT_SHAREMODE_SHARED: u32 = 0;
/// `AUDCLNT_SHAREMODE_EXCLUSIVE`.
pub const AUDCLNT_SHAREMODE_EXCLUSIVE: u32 = 1;

/// `AUDCLNT_STREAMFLAGS_CROSSPROCESS`.
pub const AUDCLNT_STREAMFLAGS_CROSSPROCESS: u32 = 0x0001_0000;
/// `AUDCLNT_STREAMFLAGS_LOOPBACK` (capture only; rejected on render).
pub const AUDCLNT_STREAMFLAGS_LOOPBACK: u32 = 0x0002_0000;
/// `AUDCLNT_STREAMFLAGS_EVENTCALLBACK` — the client is driven by the event
/// handle set with `SetEventHandle`.
pub const AUDCLNT_STREAMFLAGS_EVENTCALLBACK: u32 = 0x0004_0000;
/// `AUDCLNT_STREAMFLAGS_NOPERSIST`.
pub const AUDCLNT_STREAMFLAGS_NOPERSIST: u32 = 0x0008_0000;
/// `AUDCLNT_STREAMFLAGS_RATEADJUST`.
pub const AUDCLNT_STREAMFLAGS_RATEADJUST: u32 = 0x0010_0000;
/// `AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY`.
pub const AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY: u32 = 0x0800_0000;
/// `AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM`.
pub const AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM: u32 = 0x8000_0000;

/// `AUDCLNT_BUFFERFLAGS_SILENT` — the released frames are silence.
pub const AUDCLNT_BUFFERFLAGS_SILENT: u32 = 0x1;
/// `AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY`.
pub const AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY: u32 = 0x2;
/// `AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR`.
pub const AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR: u32 = 0x4;

/// `WAVE_FORMAT_PCM`.
pub const WAVE_FORMAT_PCM: u16 = 0x0001;
/// `WAVE_FORMAT_IEEE_FLOAT`.
pub const WAVE_FORMAT_IEEE_FLOAT: u16 = 0x0003;
/// `WAVE_FORMAT_EXTENSIBLE`.
pub const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;

/// `KSDATAFORMAT_SUBTYPE_PCM` `{00000001-0000-0010-8000-00aa00389b71}`.
pub const KSDATAFORMAT_SUBTYPE_PCM: [u8; 16] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];
/// `KSDATAFORMAT_SUBTYPE_IEEE_FLOAT` `{00000003-0000-0010-8000-00aa00389b71}`.
pub const KSDATAFORMAT_SUBTYPE_IEEE_FLOAT: [u8; 16] = [
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// `IID_IAudioRenderClient` `{f294acfc-3146-4483-a7bf-addca7c260e2}`.
pub const IID_IAUDIO_RENDER_CLIENT: [u8; 16] = [
    0xfc, 0xac, 0x94, 0xf2, 0x46, 0x31, 0x83, 0x44, 0xa7, 0xbf, 0xad, 0xdc, 0xa7, 0xc2, 0x60, 0xe2,
];

// ---------------------------------------------------------------------------
// Requested-interface (riid) table
// ---------------------------------------------------------------------------

/// `IID_IAudioClient` `{1cb9ad4c-dbfa-4c32-b178-c2f568a703b2}`.
pub const IID_IAUDIO_CLIENT: [u8; 16] = [
    0x4c, 0xad, 0xb9, 0x1c, 0xfa, 0xdb, 0x32, 0x4c, 0xb1, 0x78, 0xc2, 0xf5, 0x68, 0xa7, 0x03, 0xb2,
];
/// `IID_IAudioClient2` `{726778cd-f60a-4eda-82de-e47610cd78aa}`.
pub const IID_IAUDIO_CLIENT_2: [u8; 16] = [
    0xcd, 0x78, 0x67, 0x72, 0x0a, 0xf6, 0xda, 0x4e, 0x82, 0xde, 0xe4, 0x76, 0x10, 0xcd, 0x78, 0xaa,
];
/// `IID_IAudioClient3` `{7ed4ee07-8e67-4cd4-8c1a-2b7a5987ad42}`.
pub const IID_IAUDIO_CLIENT_3: [u8; 16] = [
    0x07, 0xee, 0xd4, 0x7e, 0x67, 0x8e, 0xd4, 0x4c, 0x8c, 0x1a, 0x2b, 0x7a, 0x59, 0x87, 0xad, 0x42,
];
/// `IID_IUnknown` `{00000000-0000-0000-c000-000000000046}`.
pub const IID_IUNKNOWN: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// True when the activation can back the requested interface id.
///
/// The audio-client family (`IAudioClient`/`IAudioClient2`/`IAudioClient3`,
/// all render-path WASAPI client interfaces) and `IUnknown` activate the real
/// audio-endpoint object. Everything else (`IAudioEndpointVolume`,
/// `IAudioCaptureClient`, non-audio riids, ...) is `E_NOINTERFACE`: the
/// runtime has no backing model for those surfaces yet.
pub fn is_supported_activation_riid(riid: &[u8; 16]) -> bool {
    *riid == IID_IAUDIO_CLIENT
        || *riid == IID_IAUDIO_CLIENT_2
        || *riid == IID_IAUDIO_CLIENT_3
        || *riid == IID_IUNKNOWN
}

/// Short human-readable name of a supported activation riid (for traces).
pub fn activation_riid_name(riid: &[u8; 16]) -> String {
    if *riid == IID_IAUDIO_CLIENT {
        "IAudioClient".to_string()
    } else if *riid == IID_IAUDIO_CLIENT_2 {
        "IAudioClient2".to_string()
    } else if *riid == IID_IAUDIO_CLIENT_3 {
        "IAudioClient3".to_string()
    } else if *riid == IID_IUNKNOWN {
        "IUnknown".to_string()
    } else {
        let bytes: Vec<String> = riid.iter().map(|byte| format!("{byte:02x}")).collect();
        bytes.join("")
    }
}

// ---------------------------------------------------------------------------
// Pending activation completions (per runtime, keyed by guest pid)
// ---------------------------------------------------------------------------

/// One queued activation completion: the runtime invokes the completion
/// handler's method asynchronously with the real activation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingActivationCompletion {
    /// The guest completion-handler COM object (`this` of the invocation).
    pub handler_object: u64,
    /// The handler method entry point, resolved from its vtable slot 3
    /// (the `ActivateCompleted` slot) when the activation was requested.
    pub handler_method: u64,
    /// The real activation result: `ACTIVATION_S_OK`,
    /// `ACTIVATION_E_NOINTERFACE`, or `AUDCLNT_E_DEVICE_INVALIDATED`.
    pub result_hr: u32,
    /// The activated guest audio-endpoint object (0 when the activation
    /// failed). Never a null/empty vtable object.
    pub interface_object: u64,
}

static PENDING_COMPLETIONS: LazyLock<Mutex<HashMap<u32, VecDeque<PendingActivationCompletion>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn pending_locks() -> MutexGuard<'static, HashMap<u32, VecDeque<PendingActivationCompletion>>> {
    PENDING_COMPLETIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Queue one activation completion for the runtime with guest pid `pid`.
///
/// FIFO per runtime: completions are delivered in activation order.
pub(crate) fn push_activation_completion(pid: u32, completion: PendingActivationCompletion) {
    pending_locks()
        .entry(pid)
        .or_default()
        .push_back(completion);
}

/// Pop the oldest pending activation completion for `pid`, if any.
pub(crate) fn pop_activation_completion(pid: u32) -> Option<PendingActivationCompletion> {
    let mut pending = pending_locks();
    let queue = pending.get_mut(&pid)?;
    let completion = queue.pop_front();
    if queue.is_empty() {
        pending.remove(&pid);
    }
    completion
}

/// Number of completions still queued for `pid` (test observability helper).
#[cfg(test)]
pub(crate) fn pending_activation_completions(pid: u32) -> usize {
    pending_locks().get(&pid).map(VecDeque::len).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Activated audio-endpoint records (per runtime, keyed by guest pid)
// ---------------------------------------------------------------------------

/// The real device data bound to one activated guest audio-endpoint object.
#[derive(Debug, Clone)]
pub struct AudioEndpointRecord {
    /// The real device snapshot the endpoint was activated on.
    pub device: RealAudioDevice,
    /// The riid the guest requested (which audio-client interface the
    /// endpoint object was produced for).
    pub requested_riid: [u8; 16],
}

static ENDPOINT_RECORDS: LazyLock<Mutex<HashMap<u32, BTreeMap<u64, AudioEndpointRecord>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn endpoint_locks() -> MutexGuard<'static, HashMap<u32, BTreeMap<u64, AudioEndpointRecord>>> {
    ENDPOINT_RECORDS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Bind a real device snapshot to a guest endpoint object of runtime `pid`.
///
/// The record is the guest-observable real data of the activation: device id,
/// name, channels, sample rate and default flag — as queried from the actual
/// host device list at activation time.
pub(crate) fn store_endpoint_record(pid: u32, object: u64, record: AudioEndpointRecord) {
    endpoint_locks()
        .entry(pid)
        .or_default()
        .insert(object, record);
}

/// The real device data bound to a guest endpoint object, when known.
#[allow(dead_code)] // read by the audio-activation tests and endpoint tooling
pub(crate) fn endpoint_record(pid: u32, object: u64) -> Option<AudioEndpointRecord> {
    endpoint_locks()
        .get(&pid)
        .and_then(|records| records.get(&object))
        .cloned()
}

// ---------------------------------------------------------------------------
// IAudioClient / IAudioRenderClient — real WASAPI method surface
// ---------------------------------------------------------------------------
//
// The activated endpoint object carries a real IAudioClient method vtable
// whose slots dispatch into the host thunks declared here.  The per-endpoint
// state is keyed by the runtime's guest pid so parallel runtimes never share
// client state, and every value it exposes is derived from real device data
// or real guest input — never a canned constant:
//
// - `Initialize` parses and validates the guest WAVEFORMATEX /
//   WAVEFORMATEXTENSIBLE (channel count, sample rate, bit depth, block
//   alignment and the extensible sub-format) against the bound device and
//   stores the real initialized format plus the real buffer geometry.
// - `Start` starts a real playback clock: frames committed through
//   `IAudioRenderClient::ReleaseBuffer` are drained at the initialized sample
//   rate from `Instant::now()`, so `GetCurrentPadding` is real client-side
//   buffer accounting and the paced queue's drained byte count is observable.
// - `GetStreamLatency` / `GetDevicePeriod` report the values the real cpal
//   backend produces for the bound device, and `GetMixFormat` writes the real
//   mix format (device sample rate/channels, 32-bit float extensible).
// - `GetService(IID_IAudioRenderClient)` produces a real guest object whose
//   `GetBuffer`/`ReleaseBuffer` hand out and reclaim the real guest-visible
//   render buffer; released frames are decoded and pushed into the real cpal
//   output stream the backend opened for the device, so a guest writing
//   frames reaches the host output (the paced queue remains the observable
//   client-side accounting even when no real output device is available).

/// The parsed, validated form of a guest `WAVEFORMATEX` /
/// `WAVEFORMATEXTENSIBLE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioClientFormat {
    /// The original `wFormatTag` (may be `WAVE_FORMAT_EXTENSIBLE`).
    pub container_tag: u16,
    /// The effective sample format tag (`WAVE_FORMAT_PCM` or
    /// `WAVE_FORMAT_IEEE_FLOAT`; extensible sub-formats resolve to these).
    pub wave_format_tag: u16,
    /// Channel count.
    pub channels: u16,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// `nAvgBytesPerSec` from the guest structure.
    pub avg_bytes_per_sec: u32,
    /// `nBlockAlign` from the guest structure (bytes per frame).
    pub block_align: u16,
    /// Container bit depth (`wBitsPerSample`).
    pub bits_per_sample: u16,
    /// `wValidBitsPerSample` (equals `bits_per_sample` for plain
    /// `WAVEFORMATEX`).
    pub valid_bits_per_sample: u16,
    /// `dwChannelMask` (a standard speaker mask when the guest left it 0).
    pub channel_mask: u32,
}

impl AudioClientFormat {
    /// Bytes per single-channel sample (container size).
    pub fn bytes_per_sample(&self) -> u16 {
        if self.channels == 0 {
            return 0;
        }
        self.block_align / self.channels
    }

    /// Whether the effective format is IEEE float.
    pub fn is_float(&self) -> bool {
        self.wave_format_tag == WAVE_FORMAT_IEEE_FLOAT
    }
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// The standard speaker mask for a channel count (0 when non-standard).
pub fn channel_mask_for_channels(channels: u16) -> u32 {
    match channels {
        1 => 0x4,   // SPEAKER_FRONT_CENTER
        2 => 0x3,   // FRONT_LEFT | FRONT_RIGHT
        3 => 0x7,   // + FRONT_CENTER
        4 => 0x33,  // QUAD
        5 => 0x37,  // 4.0 + FRONT_CENTER
        6 => 0x3F,  // 5.1
        7 => 0x13F, // 6.1
        8 => 0x63F, // 7.1
        _ => 0,
    }
}

/// Parse and validate a guest `WAVEFORMATEX` / `WAVEFORMATEXTENSIBLE`.
///
/// Structural errors and unsupported formats both surface as
/// [`AUDCLNT_E_UNSUPPORTED_FORMAT`] (the error `IAudioClient::Initialize`
/// returns for a format the engine cannot accept).
pub fn parse_wave_format(bytes: &[u8]) -> Result<AudioClientFormat, u32> {
    if bytes.len() < 18 {
        return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
    }
    let container_tag = le_u16(bytes, 0);
    let channels = le_u16(bytes, 2);
    let sample_rate = le_u32(bytes, 4);
    let avg_bytes_per_sec = le_u32(bytes, 8);
    let block_align = le_u16(bytes, 12);
    let bits_per_sample = le_u16(bytes, 14);
    let cb_size = le_u16(bytes, 16);

    let mut effective_tag = container_tag;
    let mut valid_bits_per_sample = bits_per_sample;
    let mut channel_mask = 0_u32;
    if container_tag == WAVE_FORMAT_EXTENSIBLE {
        if cb_size < 22 || bytes.len() < 40 {
            return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
        }
        valid_bits_per_sample = le_u16(bytes, 18);
        channel_mask = le_u32(bytes, 20);
        let sub_format: [u8; 16] = bytes[24..40]
            .try_into()
            .map_err(|_| AUDCLNT_E_UNSUPPORTED_FORMAT)?;
        if sub_format == KSDATAFORMAT_SUBTYPE_PCM {
            effective_tag = WAVE_FORMAT_PCM;
        } else if sub_format == KSDATAFORMAT_SUBTYPE_IEEE_FLOAT {
            effective_tag = WAVE_FORMAT_IEEE_FLOAT;
        } else {
            // Any other sub-format (including compressed sub-types) is not
            // backed by the real render stack.
            return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
        }
    } else if effective_tag != WAVE_FORMAT_PCM && effective_tag != WAVE_FORMAT_IEEE_FLOAT {
        return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
    }

    if channels == 0 || channels > 64 {
        return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
    }
    if !(1_000..=768_000).contains(&sample_rate) {
        return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
    }
    match effective_tag {
        WAVE_FORMAT_PCM => {
            if !matches!(bits_per_sample, 8 | 16 | 24 | 32) {
                return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
            }
        }
        WAVE_FORMAT_IEEE_FLOAT => {
            if bits_per_sample != 32 {
                return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
            }
        }
        _ => return Err(AUDCLNT_E_UNSUPPORTED_FORMAT),
    }
    if valid_bits_per_sample == 0 {
        valid_bits_per_sample = bits_per_sample;
    }
    if valid_bits_per_sample > bits_per_sample {
        return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
    }
    let bytes_per_sample = ((bits_per_sample as u32) + 7) / 8;
    let expected_align = (channels as u32) * bytes_per_sample;
    if block_align == 0 || block_align as u32 != expected_align {
        return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
    }
    let expected_avg = (sample_rate as u64) * (block_align as u64);
    if avg_bytes_per_sec != 0 && avg_bytes_per_sec as u64 != expected_avg {
        return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
    }
    if channel_mask == 0 {
        channel_mask = channel_mask_for_channels(channels);
    }
    Ok(AudioClientFormat {
        container_tag,
        wave_format_tag: effective_tag,
        channels,
        sample_rate,
        avg_bytes_per_sec,
        block_align,
        bits_per_sample,
        valid_bits_per_sample,
        channel_mask,
    })
}

/// Serialize a real `WAVEFORMATEXTENSIBLE` (40 bytes) for `format`.
pub fn wave_format_bytes(format: &AudioClientFormat) -> Vec<u8> {
    let block_align = (format.channels as u32) * (((format.bits_per_sample as u32) + 7) / 8);
    let avg_bytes_per_sec = (format.sample_rate as u64)
        .saturating_mul(block_align as u64)
        .min(u32::MAX as u64) as u32;
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&WAVE_FORMAT_EXTENSIBLE.to_le_bytes());
    bytes.extend_from_slice(&format.channels.to_le_bytes());
    bytes.extend_from_slice(&format.sample_rate.to_le_bytes());
    bytes.extend_from_slice(&avg_bytes_per_sec.to_le_bytes());
    bytes.extend_from_slice(&(block_align as u16).to_le_bytes());
    bytes.extend_from_slice(&format.bits_per_sample.to_le_bytes());
    bytes.extend_from_slice(&22_u16.to_le_bytes());
    bytes.extend_from_slice(&format.valid_bits_per_sample.to_le_bytes());
    let mask = if format.channel_mask == 0 {
        channel_mask_for_channels(format.channels)
    } else {
        format.channel_mask
    };
    bytes.extend_from_slice(&mask.to_le_bytes());
    let sub_format = if format.is_float() {
        KSDATAFORMAT_SUBTYPE_IEEE_FLOAT
    } else {
        KSDATAFORMAT_SUBTYPE_PCM
    };
    bytes.extend_from_slice(&sub_format);
    bytes
}

/// The real mix format of a bound cpal device: the device's own channel
/// count and sample rate as a 32-bit float `WAVEFORMATEXTENSIBLE` (the
/// shared-mode engine format this runtime feeds).
pub fn mix_format_for_device(device: &RealAudioDevice) -> AudioClientFormat {
    let channels = device.channels.max(1);
    let sample_rate = device.sample_rate.max(1);
    AudioClientFormat {
        container_tag: WAVE_FORMAT_EXTENSIBLE,
        wave_format_tag: WAVE_FORMAT_IEEE_FLOAT,
        channels,
        sample_rate,
        avg_bytes_per_sec: sample_rate
            .saturating_mul(channels as u32)
            .saturating_mul(4),
        block_align: channels.saturating_mul(4),
        bits_per_sample: 32,
        valid_bits_per_sample: 32,
        channel_mask: channel_mask_for_channels(channels),
    }
}

/// Whether `format` is supported for `share_mode` on the real `device`.
///
/// `S_OK` = bit-exact, `S_FALSE` = supported through the audio engine's real
/// conversion path (the backend remaps channels and resamples),
/// `AUDCLNT_E_UNSUPPORTED_FORMAT` = not backed.
pub fn audio_format_support(
    device: &RealAudioDevice,
    format: &AudioClientFormat,
    share_mode: u32,
) -> u32 {
    let exact = format.channels == device.channels
        && format.sample_rate == device.sample_rate
        && format.wave_format_tag == WAVE_FORMAT_IEEE_FLOAT
        && format.bits_per_sample == 32;
    if exact {
        return AUDCLNT_S_OK;
    }
    if share_mode == AUDCLNT_SHAREMODE_EXCLUSIVE {
        // Exclusive mode runs at the device format; a different rate or
        // channel count cannot be produced without conversion, which
        // exclusive mode forbids.
        return AUDCLNT_E_UNSUPPORTED_FORMAT;
    }
    // Shared mode: the backend's real conversion path handles PCM/float
    // channel remaps and resampling.
    AUDCLNT_S_FALSE
}

/// The IAudioClient vtable method sequence: IUnknown preamble, the twelve
/// IAudioClient methods (slots 3..=14), and the IAudioClient2/3 extension
/// methods (slots 15..=20) so an endpoint activated for `IAudioClient2` /
/// `IAudioClient3` carries their full real surface too.
pub(crate) fn audio_client_methods() -> Vec<HostThunk> {
    vec![
        HostThunk::AudioClientQueryInterface,                   // [0]
        HostThunk::GuestObjectAddRef,                           // [1]
        HostThunk::GuestObjectRelease,                          // [2]
        HostThunk::AudioClientInitialize,                       // [3]
        HostThunk::AudioClientGetBufferSize,                    // [4]
        HostThunk::AudioClientGetStreamLatency,                 // [5]
        HostThunk::AudioClientGetCurrentPadding,                // [6]
        HostThunk::AudioClientIsFormatSupported,                // [7]
        HostThunk::AudioClientGetMixFormat,                     // [8]
        HostThunk::AudioClientGetDevicePeriod,                  // [9]
        HostThunk::AudioClientStart,                            // [10]
        HostThunk::AudioClientStop,                             // [11]
        HostThunk::AudioClientReset,                            // [12]
        HostThunk::AudioClientSetEventHandle,                   // [13]
        HostThunk::AudioClientGetService,                       // [14]
        HostThunk::AudioClientIsOffloadCapable,                 // [15] IAudioClient2
        HostThunk::AudioClientSetClientProperties,              // [16] IAudioClient2
        HostThunk::AudioClientGetBufferSizeLimits,              // [17] IAudioClient2
        HostThunk::AudioClientGetSharedModeEnginePeriod,        // [18] IAudioClient3
        HostThunk::AudioClientGetCurrentSharedModeEnginePeriod, // [19]
        HostThunk::AudioClientInitializeSharedAudioStream,      // [20] IAudioClient3
    ]
}

/// The IAudioRenderClient vtable method sequence: IUnknown preamble plus
/// `GetBuffer` and `ReleaseBuffer`.
pub(crate) fn audio_render_client_methods() -> Vec<HostThunk> {
    vec![
        HostThunk::AudioRenderClientQueryInterface, // [0]
        HostThunk::GuestObjectAddRef,               // [1]
        HostThunk::GuestObjectRelease,              // [2]
        HostThunk::AudioRenderClientGetBuffer,      // [3]
        HostThunk::AudioRenderClientReleaseBuffer,  // [4]
    ]
}

/// Default device period when the real backend cannot be queried: 10 ms in
/// `REFERENCE_TIME` units (100 ns).
pub const DEFAULT_DEVICE_PERIOD_HNS: u64 = 100_000;
/// Minimum device period fallback: 3 ms in `REFERENCE_TIME` units.
pub const MINIMUM_DEVICE_PERIOD_HNS: u64 = 30_000;

/// Convert a frame count to `REFERENCE_TIME` (100 ns units) at `rate`.
fn frames_to_hns(frames: u64, rate: u32) -> u64 {
    if rate == 0 {
        return 0;
    }
    frames.saturating_mul(10_000_000) / rate as u64
}

/// Convert `REFERENCE_TIME` (100 ns units) to frames at `rate`.
fn hns_to_frames(hns: u64, rate: u32) -> u64 {
    (hns as u128 * rate as u128 / 10_000_000) as u64
}

/// One bound audio client: the real device, the parsed initialized format,
/// the real guest render buffer and the real playback clock.
#[derive(Debug, Clone)]
pub struct AudioClientState {
    /// The real device snapshot the endpoint was activated on.
    pub device: RealAudioDevice,
    /// The riid the guest requested at activation.
    pub requested_riid: [u8; 16],
    /// Whether `Initialize` has succeeded.
    pub initialized: bool,
    /// `AUDCLNT_SHAREMODE_SHARED` / `EXCLUSIVE`.
    pub share_mode: u32,
    /// The `Initialize` stream flags.
    pub stream_flags: u32,
    /// `AUDCLNT_STREAMFLAGS_EVENTCALLBACK` was requested.
    pub event_driven: bool,
    /// The real initialized format.
    pub format: Option<AudioClientFormat>,
    /// The real client buffer size in frames.
    pub buffer_frames: u32,
    /// Guest address of the real render buffer.
    pub buffer_address: u64,
    /// Byte length of the real render buffer.
    pub buffer_bytes: u64,
    /// Frames handed out by `GetBuffer` and not yet released (0 when none).
    pub buffer_outstanding_frames: u32,
    /// Frames committed through `ReleaseBuffer`.
    pub submitted_frames: u64,
    /// Frames drained before the current run span.
    pub drained_frames_carry: u64,
    /// When the current run span started (None while stopped).
    pub run_started: Option<Instant>,
    /// Whether the client is running.
    pub running: bool,
    /// The real guest event handle set by `SetEventHandle`.
    pub event_handle: u64,
    /// Whether the ready event is currently signaled (dedup for auto-reset
    /// events).
    pub event_ready_signaled: bool,
    /// Real default device period in `REFERENCE_TIME` units.
    pub default_period_hns: u64,
    /// Real minimum device period in `REFERENCE_TIME` units.
    pub minimum_period_hns: u64,
    /// Real stream latency in `REFERENCE_TIME` units.
    pub stream_latency_hns: u64,
    /// The real cpal device id the output stream was opened on.
    pub real_device_id: Option<crate::audio::DeviceId>,
    /// The cached IAudioRenderClient guest object (0 when none yet).
    pub render_service_object: u64,
    /// The `IAudioClient2::SetClientProperties` stream category.
    pub client_category: u32,
    /// The `IAudioClient2::SetClientProperties` offload request.
    pub client_offload_requested: bool,
}

impl AudioClientState {
    /// Frames the real playback clock has drained at `now`.
    fn drained_frames(&self, now: Instant) -> u64 {
        let mut drained = self.drained_frames_carry;
        if let Some(started) = self.run_started {
            let rate = self
                .format
                .as_ref()
                .map(|format| format.sample_rate)
                .unwrap_or(self.device.sample_rate)
                .max(1);
            let elapsed = now.saturating_duration_since(started);
            let frames = (elapsed.as_nanos() * rate as u128 / 1_000_000_000) as u64;
            drained = drained.saturating_add(frames);
        }
        drained.min(self.submitted_frames)
    }

    /// The real client-side padding (committed but not yet drained frames).
    fn padding_frames(&self, now: Instant) -> u32 {
        self.submitted_frames
            .saturating_sub(self.drained_frames(now)) as u32
    }
}

/// The real plan produced by [`plan_initialize`] before the guest buffer is
/// allocated.
#[derive(Debug, Clone, Copy)]
pub struct AudioInitializePlan {
    /// Real buffer size in frames.
    pub buffer_frames: u32,
    /// Bytes per frame.
    pub block_align: u16,
    /// Whether the stream is event-driven.
    pub event_driven: bool,
    /// Share mode.
    pub share_mode: u32,
    /// Stream flags.
    pub stream_flags: u32,
    /// Requested buffer duration in `REFERENCE_TIME` units.
    pub duration_hns: u64,
    /// Requested periodicity in `REFERENCE_TIME` units.
    pub periodicity_hns: u64,
}

#[derive(Default)]
struct AudioClientRegistry {
    clients: HashMap<u32, BTreeMap<u64, AudioClientState>>,
    render_clients: HashMap<u32, BTreeMap<u64, u64>>,
}

static AUDIO_CLIENTS: LazyLock<Mutex<AudioClientRegistry>> =
    LazyLock::new(|| Mutex::new(AudioClientRegistry::default()));

fn audio_clients() -> MutexGuard<'static, AudioClientRegistry> {
    AUDIO_CLIENTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

static AUDIO_CLIENT_REAL_BACKEND: LazyLock<Mutex<Option<RealAudioBackend>>> =
    LazyLock::new(|| Mutex::new(None));

fn audio_client_backend() -> MutexGuard<'static, Option<RealAudioBackend>> {
    AUDIO_CLIENT_REAL_BACKEND
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn ensure_audio_client_backend(
    guard: &mut Option<RealAudioBackend>,
) -> Option<&mut RealAudioBackend> {
    if guard.is_none() {
        match RealAudioBackend::new() {
            Ok(backend) => *guard = Some(backend),
            Err(error) => {
                eprintln!("[RealAudio] audio-client backend init failed: {error}");
                return None;
            }
        }
    }
    guard.as_mut()
}

/// Attach a real audio-client state to a freshly activated endpoint object.
///
/// Idempotent: a pre-existing state for the object is left untouched.
pub(crate) fn register_audio_client(
    pid: u32,
    object: u64,
    device: RealAudioDevice,
    requested_riid: [u8; 16],
) {
    let (default_period_hns, minimum_period_hns) = {
        let mut backend = audio_client_backend();
        ensure_audio_client_backend(&mut backend)
            .map(|backend| {
                let info = backend.device_period_info(&device);
                (info.default_period_hns, info.minimum_period_hns)
            })
            .unwrap_or((DEFAULT_DEVICE_PERIOD_HNS, MINIMUM_DEVICE_PERIOD_HNS))
    };
    let mut registry = audio_clients();
    registry
        .clients
        .entry(pid)
        .or_default()
        .entry(object)
        .or_insert_with(|| AudioClientState {
            device,
            requested_riid,
            initialized: false,
            share_mode: AUDCLNT_SHAREMODE_SHARED,
            stream_flags: 0,
            event_driven: false,
            format: None,
            buffer_frames: 0,
            buffer_address: 0,
            buffer_bytes: 0,
            buffer_outstanding_frames: 0,
            submitted_frames: 0,
            drained_frames_carry: 0,
            run_started: None,
            running: false,
            event_handle: 0,
            event_ready_signaled: false,
            default_period_hns,
            minimum_period_hns,
            stream_latency_hns: default_period_hns,
            real_device_id: None,
            render_service_object: 0,
            client_category: 0,
            client_offload_requested: false,
        });
}

/// Drop every audio-client/render-client state bound to `object` (called when
/// the runtime releases the guest object).  When the released endpoint was
/// the last audio client using a real stream, the backend stream is closed.
pub(crate) fn release_audio_object(pid: u32, object: u64) {
    let (removed, close_device) = {
        let mut registry = audio_clients();
        let removed = registry
            .clients
            .get_mut(&pid)
            .and_then(|clients| clients.remove(&object));
        if removed.is_some() {
            // Cached render-client service objects lose their binding too.
            if let Some(render_clients) = registry.render_clients.get_mut(&pid) {
                render_clients.retain(|_, endpoint| *endpoint != object);
            }
        } else if let Some(render_clients) = registry.render_clients.get_mut(&pid) {
            render_clients.remove(&object);
        }
        let close_device = removed
            .as_ref()
            .and_then(|state| state.real_device_id)
            .filter(|device_id| {
                !registry
                    .clients
                    .values()
                    .flat_map(|clients| clients.values())
                    .any(|state| state.real_device_id == Some(*device_id))
            });
        if registry
            .render_clients
            .get(&pid)
            .is_some_and(|render_clients| render_clients.is_empty())
        {
            registry.render_clients.remove(&pid);
        }
        if registry
            .clients
            .get(&pid)
            .is_some_and(|clients| clients.is_empty())
        {
            registry.clients.remove(&pid);
        }
        (removed, close_device)
    };
    let _ = removed;
    if let Some(device_id) = close_device {
        let mut guard = audio_client_backend();
        if let Some(backend) = guard.as_mut() {
            backend.close_stream(device_id);
        }
    }
}

/// Whether `object` is a bound audio client of `pid`.
pub(crate) fn has_audio_client(pid: u32, object: u64) -> bool {
    audio_clients()
        .clients
        .get(&pid)
        .is_some_and(|clients| clients.contains_key(&object))
}

/// The real device bound to an endpoint object (tests / tooling).
pub(crate) fn device_of(pid: u32, object: u64) -> Option<RealAudioDevice> {
    audio_clients()
        .clients
        .get(&pid)
        .and_then(|clients| clients.get(&object))
        .map(|state| state.device.clone())
}

/// Observable snapshot of one bound audio client (tests).
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct AudioClientTestSnapshot {
    pub initialized: bool,
    pub running: bool,
    pub buffer_frames: u32,
    pub buffer_address: u64,
    pub submitted_frames: u64,
    pub drained_frames_carry: u64,
    pub event_handle: u64,
    pub real_device_id: Option<crate::audio::DeviceId>,
}

#[cfg(test)]
pub(crate) fn test_client_snapshot(pid: u32, object: u64) -> Option<AudioClientTestSnapshot> {
    audio_clients()
        .clients
        .get(&pid)
        .and_then(|clients| clients.get(&object))
        .map(|state| AudioClientTestSnapshot {
            initialized: state.initialized,
            running: state.running,
            buffer_frames: state.buffer_frames,
            buffer_address: state.buffer_address,
            submitted_frames: state.submitted_frames,
            drained_frames_carry: state.drained_frames_carry,
            event_handle: state.event_handle,
            real_device_id: state.real_device_id,
        })
}

/// Plan an `Initialize` call: validate the state, share mode, stream flags,
/// requested duration/periodicity and the guest format against the real
/// device, and compute the real buffer geometry.
pub(crate) fn plan_initialize(
    pid: u32,
    object: u64,
    share_mode: u32,
    stream_flags: u32,
    duration_hns: i64,
    periodicity_hns: i64,
    format: &AudioClientFormat,
) -> Result<AudioInitializePlan, u32> {
    if duration_hns < 0 || periodicity_hns < 0 {
        return Err(AUDCLNT_E_INVALIDARG);
    }
    if share_mode > AUDCLNT_SHAREMODE_EXCLUSIVE {
        return Err(AUDCLNT_E_INVALIDARG);
    }
    if stream_flags & AUDCLNT_STREAMFLAGS_LOOPBACK != 0 {
        // Loopback is a capture mode; this endpoint is a render client.
        return Err(AUDCLNT_E_INVALID_STREAM_FLAG);
    }
    let mut registry = audio_clients();
    let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&object))
    else {
        return Err(AUDCLNT_E_DEVICE_INVALIDATED);
    };
    if state.initialized {
        return Err(AUDCLNT_E_ALREADY_INITIALIZED);
    }
    let duration_hns = duration_hns as u64;
    let periodicity_hns = periodicity_hns as u64;
    if share_mode == AUDCLNT_SHAREMODE_EXCLUSIVE {
        if duration_hns == 0 {
            return Err(AUDCLNT_E_INVALIDARG);
        }
    } else if periodicity_hns != 0 {
        // Shared mode does not take a periodicity.
        return Err(AUDCLNT_E_INVALIDARG);
    }
    let support = audio_format_support(&state.device, format, share_mode);
    if support != AUDCLNT_S_OK && support != AUDCLNT_S_FALSE {
        return Err(support);
    }
    let rate = format.sample_rate.max(1);
    let requested_frames = if duration_hns == 0 {
        hns_to_frames(state.default_period_hns, rate).max(1)
    } else {
        hns_to_frames(duration_hns, rate).max(1)
    };
    // The real engine caps a client buffer at two seconds of audio.
    let max_frames = (rate as u64).saturating_mul(2).max(1);
    let buffer_frames = requested_frames.min(max_frames).max(1) as u32;
    Ok(AudioInitializePlan {
        buffer_frames,
        block_align: format.block_align.max(1),
        event_driven: stream_flags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK != 0,
        share_mode,
        stream_flags,
        duration_hns,
        periodicity_hns,
    })
}

/// Store a successful `Initialize` and open the real output stream for the
/// bound device (best effort: headless hosts keep the real paced queue).
pub(crate) fn commit_initialize(
    pid: u32,
    object: u64,
    plan: &AudioInitializePlan,
    format: &AudioClientFormat,
    buffer_address: u64,
    buffer_bytes: u64,
) -> u32 {
    let mut registry = audio_clients();
    let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&object))
    else {
        return AUDCLNT_E_DEVICE_INVALIDATED;
    };
    state.initialized = true;
    state.share_mode = plan.share_mode;
    state.stream_flags = plan.stream_flags;
    state.event_driven = plan.event_driven;
    state.format = Some(format.clone());
    state.buffer_frames = plan.buffer_frames;
    state.buffer_address = buffer_address;
    state.buffer_bytes = buffer_bytes;
    state.buffer_outstanding_frames = 0;
    state.submitted_frames = 0;
    state.drained_frames_carry = 0;
    state.run_started = None;
    state.running = false;
    state.event_ready_signaled = false;
    let device_rate = state.device.sample_rate.max(1);
    state.stream_latency_hns = frames_to_hns(plan.buffer_frames as u64, device_rate).max(1);
    if let Some((device_id, latency_ms)) =
        open_real_render_stream(&state.device, format, plan.buffer_frames, plan.event_driven)
    {
        state.real_device_id = Some(device_id);
        if let Some(latency_ms) = latency_ms {
            state.stream_latency_hns = (latency_ms as u64).saturating_mul(10_000).max(1);
        }
    }
    AUDCLNT_S_OK
}

/// Open the real cpal output stream for the bound device (shared-mode path).
fn open_real_render_stream(
    device: &RealAudioDevice,
    format: &AudioClientFormat,
    buffer_frames: u32,
    event_driven: bool,
) -> Option<(crate::audio::DeviceId, Option<u32>)> {
    let wave_format = WaveFormat {
        channels: format.channels,
        sample_rate: format.sample_rate,
        sample_format: if format.is_float() {
            SampleFormat::Float32
        } else {
            SampleFormat::Pcm16
        },
    };
    let mut guard = audio_client_backend();
    let backend = ensure_audio_client_backend(&mut guard)?;
    let device_id = backend
        .activation_device_snapshot()
        .into_iter()
        .find(|candidate| candidate.key == device.key)?
        .id;
    backend
        .open_wasapi_client(&wave_format, buffer_frames as usize, event_driven)
        .ok()?;
    let latency_ms = backend.last_latency_ms(device_id);
    Some((device_id, latency_ms))
}

/// Push decoded render frames into the real cpal output stream of
/// `device_id` (a no-op when the stream was never opened).
pub(crate) fn push_real_render_samples(
    device_id: crate::audio::DeviceId,
    samples: &[f32],
    channels: u16,
    sample_rate: u32,
) {
    let mut guard = audio_client_backend();
    if let Some(backend) = guard.as_mut()
        && let Err(error) = backend.push_wasapi_frames(device_id, samples, channels, sample_rate)
    {
        eprintln!("[RealAudio] audio-client render push failed: {error}");
    }
}

fn with_client_state<T>(
    pid: u32,
    object: u64,
    message: &str,
    body: impl FnOnce(&mut AudioClientState) -> Result<T, u32>,
) -> Result<T, u32> {
    let mut registry = audio_clients();
    let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&object))
    else {
        eprintln!("[RealAudio] {message}: unbound audio client {object:#x}");
        return Err(AUDCLNT_E_DEVICE_INVALIDATED);
    };
    body(state)
}

/// `GetBufferSize` — the real client buffer size in frames.
pub(crate) fn get_buffer_size(pid: u32, object: u64) -> Result<u32, u32> {
    with_client_state(pid, object, "GetBufferSize", |state| {
        if !state.initialized {
            return Err(AUDCLNT_E_NOT_INITIALIZED);
        }
        Ok(state.buffer_frames)
    })
}

/// `GetStreamLatency` — the real stream latency in `REFERENCE_TIME` units.
pub(crate) fn get_stream_latency(pid: u32, object: u64) -> Result<u64, u32> {
    with_client_state(pid, object, "GetStreamLatency", |state| {
        if !state.initialized {
            return Err(AUDCLNT_E_NOT_INITIALIZED);
        }
        Ok(state.stream_latency_hns)
    })
}

/// `GetDevicePeriod` — `(default, minimum)` real device period in
/// `REFERENCE_TIME` units.
pub(crate) fn get_device_period(pid: u32, object: u64) -> Result<(u64, u64), u32> {
    with_client_state(pid, object, "GetDevicePeriod", |state| {
        if !state.initialized {
            return Err(AUDCLNT_E_NOT_INITIALIZED);
        }
        Ok((state.default_period_hns, state.minimum_period_hns))
    })
}

/// `IAudioClient2::SetClientProperties(pProperties)` — store the real client
/// properties.  The host has no offload engine, so an offload request is
/// recorded (and answered honestly by `IsOffloadCapable`).
pub(crate) fn set_client_properties(
    pid: u32,
    object: u64,
    category: u32,
    offload_requested: bool,
) -> u32 {
    let result = with_client_state(pid, object, "SetClientProperties", |state| {
        state.client_category = category;
        state.client_offload_requested = offload_requested;
        Ok(AUDCLNT_S_OK)
    });
    match result {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `IAudioClient2::GetBufferSizeLimits` — the real buffer-duration limits of
/// the bound device: its minimum period up to the engine's two-second
/// maximum, in `REFERENCE_TIME` units.
pub(crate) fn get_buffer_size_limits(
    pid: u32,
    object: u64,
    format: &AudioClientFormat,
) -> Result<(u64, u64), u32> {
    with_client_state(pid, object, "GetBufferSizeLimits", |state| {
        let support = audio_format_support(&state.device, format, AUDCLNT_SHAREMODE_SHARED);
        if support != AUDCLNT_S_OK && support != AUDCLNT_S_FALSE {
            return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
        }
        Ok((state.minimum_period_hns.max(1), 20_000_000))
    })
}

/// `IAudioClient3::GetSharedModeEnginePeriod` — the real shared-mode engine
/// periods in frames at the requested format's rate:
/// `(default, fundamental, minimum, maximum)`.
pub(crate) fn get_shared_mode_engine_period(
    pid: u32,
    object: u64,
    format: &AudioClientFormat,
) -> Result<(u32, u32, u32, u32), u32> {
    with_client_state(pid, object, "GetSharedModeEnginePeriod", |state| {
        let support = audio_format_support(&state.device, format, AUDCLNT_SHAREMODE_SHARED);
        if support != AUDCLNT_S_OK && support != AUDCLNT_S_FALSE {
            return Err(AUDCLNT_E_UNSUPPORTED_FORMAT);
        }
        let rate = format.sample_rate.max(1);
        let default_frames = hns_to_frames(state.default_period_hns, rate).max(1);
        let minimum_frames = hns_to_frames(state.minimum_period_hns, rate)
            .max(1)
            .min(default_frames);
        let maximum_frames = hns_to_frames(20_000_000, rate).max(default_frames);
        Ok((
            default_frames as u32,
            minimum_frames as u32,
            minimum_frames as u32,
            maximum_frames as u32,
        ))
    })
}

/// `IAudioClient3::GetCurrentSharedModeEnginePeriod` — the device's real mix
/// format plus the current engine period in frames.
pub(crate) fn current_shared_mode_engine_period(
    pid: u32,
    object: u64,
) -> Result<(AudioClientFormat, u32), u32> {
    with_client_state(pid, object, "GetCurrentSharedModeEnginePeriod", |state| {
        let mix = mix_format_for_device(&state.device);
        let frames = hns_to_frames(state.default_period_hns, mix.sample_rate).max(1);
        Ok((mix, frames as u32))
    })
}

/// `IAudioClient3::InitializeSharedAudioStream` — build the real shared-mode
/// plan for the requested period in frames.
pub(crate) fn plan_initialize_shared_audio_stream(
    pid: u32,
    object: u64,
    stream_flags: u32,
    period_frames: u32,
    format: &AudioClientFormat,
) -> Result<AudioInitializePlan, u32> {
    if period_frames == 0 {
        return Err(AUDCLNT_E_INVALIDARG);
    }
    let duration_hns = frames_to_hns(period_frames as u64, format.sample_rate.max(1));
    plan_initialize(
        pid,
        object,
        AUDCLNT_SHAREMODE_SHARED,
        stream_flags,
        duration_hns as i64,
        0,
        format,
    )
}

/// `GetCurrentPadding` — the real client-side padding (frames committed but
/// not yet drained by the playback clock).
pub(crate) fn get_current_padding(pid: u32, object: u64) -> Result<u32, u32> {
    with_client_state(pid, object, "GetCurrentPadding", |state| {
        if !state.initialized {
            return Err(AUDCLNT_E_NOT_INITIALIZED);
        }
        Ok(state.padding_frames(Instant::now()))
    })
}

/// `Start` — start the real playback clock.
pub(crate) fn start(pid: u32, object: u64) -> u32 {
    let result = with_client_state(pid, object, "Start", |state| {
        if !state.initialized {
            return Err(AUDCLNT_E_NOT_INITIALIZED);
        }
        if state.event_driven && state.event_handle == 0 {
            return Err(AUDCLNT_E_EVENTHANDLE_NOT_SET);
        }
        if state.running {
            // Windows: starting an already-running stream returns S_FALSE.
            return Ok(AUDCLNT_S_FALSE);
        }
        state.running = true;
        state.run_started = Some(Instant::now());
        state.event_ready_signaled = false;
        Ok(AUDCLNT_S_OK)
    });
    match result {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `Stop` — freeze the playback clock (remaining padding stays buffered).
pub(crate) fn stop(pid: u32, object: u64) -> u32 {
    let result = with_client_state(pid, object, "Stop", |state| {
        if !state.initialized {
            return Err(AUDCLNT_E_NOT_INITIALIZED);
        }
        if !state.running {
            return Ok(AUDCLNT_S_FALSE);
        }
        let now = Instant::now();
        state.drained_frames_carry = state.drained_frames(now);
        state.run_started = None;
        state.running = false;
        state.event_ready_signaled = false;
        Ok(AUDCLNT_S_OK)
    });
    match result {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `Reset` — discard the buffered frames (only valid while stopped).
pub(crate) fn reset(pid: u32, object: u64) -> u32 {
    let result = with_client_state(pid, object, "Reset", |state| {
        if !state.initialized {
            return Err(AUDCLNT_E_NOT_INITIALIZED);
        }
        if state.running {
            return Err(AUDCLNT_E_NOT_STOPPED);
        }
        state.submitted_frames = 0;
        state.drained_frames_carry = 0;
        state.run_started = None;
        state.buffer_outstanding_frames = 0;
        state.event_ready_signaled = false;
        Ok(AUDCLNT_S_OK)
    });
    match result {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `SetEventHandle` — store the real guest event handle the runtime signals
/// when the render buffer is ready.
pub(crate) fn set_event_handle(pid: u32, object: u64, handle: u64) -> u32 {
    let result = with_client_state(pid, object, "SetEventHandle", |state| {
        if !state.initialized {
            return Err(AUDCLNT_E_NOT_INITIALIZED);
        }
        if handle == 0 {
            return Err(AUDCLNT_E_INVALIDARG);
        }
        if !state.event_driven {
            return Err(AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED);
        }
        state.event_handle = handle;
        state.event_ready_signaled = false;
        Ok(AUDCLNT_S_OK)
    });
    match result {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// The event handle to signal right now, if the buffer is ready and the ready
/// signal has not already been raised.  Transition-based so auto-reset events
/// are not consumed before the guest observes them.
pub(crate) fn take_ready_event(pid: u32, endpoint: u64) -> Option<u64> {
    let mut registry = audio_clients();
    let state = registry.clients.get_mut(&pid)?.get_mut(&endpoint)?;
    if !state.running || state.event_handle == 0 {
        return None;
    }
    let padding = state.padding_frames(Instant::now());
    if padding < state.buffer_frames {
        if state.event_ready_signaled {
            return None;
        }
        state.event_ready_signaled = true;
        return Some(state.event_handle);
    }
    state.event_ready_signaled = false;
    None
}

/// Every ready event of `pid` that should be raised now (the servicing-point
/// tick: a running client whose buffer has free space raises its event so a
/// blocked event-driven guest wakes).
pub(crate) fn take_ready_events(pid: u32) -> Vec<u64> {
    let mut registry = audio_clients();
    let Some(clients) = registry.clients.get_mut(&pid) else {
        return Vec::new();
    };
    let now = Instant::now();
    let mut handles = Vec::new();
    for state in clients.values_mut() {
        if !state.running || state.event_handle == 0 {
            continue;
        }
        if state.padding_frames(now) < state.buffer_frames {
            if !state.event_ready_signaled {
                state.event_ready_signaled = true;
                handles.push(state.event_handle);
            }
        } else {
            state.event_ready_signaled = false;
        }
    }
    handles
}

/// Bind an `IAudioRenderClient` service object to its endpoint.
pub(crate) fn bind_render_service(pid: u32, endpoint: u64, service_object: u64) {
    let mut registry = audio_clients();
    if let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&endpoint))
    {
        state.render_service_object = service_object;
    }
    registry
        .render_clients
        .entry(pid)
        .or_default()
        .insert(service_object, endpoint);
}

/// The cached `IAudioRenderClient` object of an endpoint, if any.
pub(crate) fn render_service_for(pid: u32, endpoint: u64) -> Option<u64> {
    audio_clients()
        .clients
        .get(&pid)
        .and_then(|clients| clients.get(&endpoint))
        .map(|state| state.render_service_object)
        .filter(|object| *object != 0)
}

/// The endpoint a render-client service object belongs to.
fn render_client_endpoint(registry: &AudioClientRegistry, pid: u32, service: u64) -> Option<u64> {
    registry
        .render_clients
        .get(&pid)
        .and_then(|clients| clients.get(&service))
        .copied()
}

/// `IAudioRenderClient::GetBuffer` — hand out the real guest render buffer.
pub(crate) fn render_get_buffer(
    pid: u32,
    service_object: u64,
    frames_requested: u32,
) -> Result<(u64, u32), u32> {
    let mut registry = audio_clients();
    let endpoint = render_client_endpoint(&registry, pid, service_object)
        .ok_or(AUDCLNT_E_DEVICE_INVALIDATED)?;
    let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&endpoint))
    else {
        return Err(AUDCLNT_E_DEVICE_INVALIDATED);
    };
    if !state.initialized {
        return Err(AUDCLNT_E_NOT_INITIALIZED);
    }
    if !state.running {
        return Err(AUDCLNT_E_NOT_STARTED);
    }
    if state.buffer_outstanding_frames != 0 {
        return Err(AUDCLNT_E_OUT_OF_ORDER);
    }
    if frames_requested == 0 {
        return Err(AUDCLNT_E_INVALIDARG);
    }
    let padding = state.padding_frames(Instant::now());
    let available = state.buffer_frames.saturating_sub(padding);
    if frames_requested > available {
        return Err(AUDCLNT_E_BUFFER_TOO_LARGE);
    }
    state.buffer_outstanding_frames = frames_requested;
    Ok((state.buffer_address, frames_requested))
}

/// The real route information `ReleaseBuffer` needs to decode and play the
/// released frames.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderRelease {
    /// The endpoint the release belongs to.
    pub endpoint: u64,
    /// Guest address of the released buffer.
    pub buffer_address: u64,
    /// Frames released.
    pub frames: u32,
    /// Bytes per frame of the initialized format.
    pub block_align: u16,
    /// Effective sample format tag.
    pub wave_format_tag: u16,
    /// Container bit depth.
    pub bits_per_sample: u16,
    /// Client channel count.
    pub channels: u16,
    /// Client sample rate.
    pub sample_rate: u32,
    /// `AUDCLNT_BUFFERFLAGS_SILENT` was set.
    pub silent: bool,
    /// The real cpal device id (when a real stream was opened).
    pub real_device_id: Option<crate::audio::DeviceId>,
}

/// `IAudioRenderClient::ReleaseBuffer` — reclaim the buffer and commit the
/// written frames into the real playback clock.
pub(crate) fn render_release_buffer(
    pid: u32,
    service_object: u64,
    frames_written: u32,
    flags: u32,
) -> Result<RenderRelease, u32> {
    let mut registry = audio_clients();
    let endpoint = render_client_endpoint(&registry, pid, service_object)
        .ok_or(AUDCLNT_E_DEVICE_INVALIDATED)?;
    let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&endpoint))
    else {
        return Err(AUDCLNT_E_DEVICE_INVALIDATED);
    };
    if !state.initialized {
        return Err(AUDCLNT_E_NOT_INITIALIZED);
    }
    if !state.running {
        return Err(AUDCLNT_E_NOT_STARTED);
    }
    if state.buffer_outstanding_frames == 0 {
        return Err(AUDCLNT_E_OUT_OF_ORDER);
    }
    if frames_written == 0 || frames_written > state.buffer_outstanding_frames {
        return Err(AUDCLNT_E_INVALIDARG);
    }
    let format = state
        .format
        .as_ref()
        .cloned()
        .ok_or(AUDCLNT_E_NOT_INITIALIZED)?;
    state.buffer_outstanding_frames = 0;
    state.submitted_frames = state.submitted_frames.saturating_add(frames_written as u64);
    Ok(RenderRelease {
        endpoint,
        buffer_address: state.buffer_address,
        frames: frames_written,
        block_align: format.block_align,
        wave_format_tag: format.wave_format_tag,
        bits_per_sample: format.bits_per_sample,
        channels: format.channels,
        sample_rate: format.sample_rate,
        silent: flags & AUDCLNT_BUFFERFLAGS_SILENT != 0,
        real_device_id: state.real_device_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_riids_cover_audio_client_family() {
        assert!(is_supported_activation_riid(&IID_IAUDIO_CLIENT));
        assert!(is_supported_activation_riid(&IID_IAUDIO_CLIENT_2));
        assert!(is_supported_activation_riid(&IID_IAUDIO_CLIENT_3));
        assert!(is_supported_activation_riid(&IID_IUNKNOWN));
    }

    #[test]
    fn unsupported_riids_rejected() {
        let unknown = [0xaa; 16];
        assert!(!is_supported_activation_riid(&unknown));
        let zeroes = [0u8; 16];
        assert!(!is_supported_activation_riid(&zeroes));
    }

    #[test]
    fn riid_names_are_human_readable() {
        assert_eq!(activation_riid_name(&IID_IAUDIO_CLIENT), "IAudioClient");
        assert_eq!(activation_riid_name(&IID_IAUDIO_CLIENT_2), "IAudioClient2");
        assert_eq!(activation_riid_name(&IID_IAUDIO_CLIENT_3), "IAudioClient3");
        assert_eq!(activation_riid_name(&IID_IUNKNOWN), "IUnknown");
        assert_eq!(
            activation_riid_name(&[0x12; 16]),
            "12121212121212121212121212121212"
        );
    }

    #[test]
    fn pending_completions_are_fifo_and_pid_scoped() {
        let first = PendingActivationCompletion {
            handler_object: 0x10,
            handler_method: 0x20,
            result_hr: ACTIVATION_S_OK,
            interface_object: 0x30,
        };
        let second = PendingActivationCompletion {
            handler_object: 0x40,
            handler_method: 0x50,
            result_hr: AUDCLNT_E_DEVICE_INVALIDATED,
            interface_object: 0,
        };
        let pid_a = 0x7a11;
        let pid_b = 0x7a22;
        assert_eq!(pending_activation_completions(pid_a), 0);

        push_activation_completion(pid_a, first);
        push_activation_completion(pid_a, second);
        push_activation_completion(pid_b, second);

        assert_eq!(pending_activation_completions(pid_a), 2);
        assert_eq!(pending_activation_completions(pid_b), 1);
        // FIFO order within one runtime.
        assert_eq!(pop_activation_completion(pid_a), Some(first));
        assert_eq!(pop_activation_completion(pid_a), Some(second));
        assert_eq!(pop_activation_completion(pid_a), None);
        // The other runtime's queue is untouched.
        assert_eq!(pending_activation_completions(pid_b), 1);
        assert_eq!(pop_activation_completion(pid_b), Some(second));
        assert_eq!(pop_activation_completion(pid_b), None);
    }

    #[test]
    fn endpoint_records_round_trip_per_pid() {
        let pid = 0x7b11;
        let device = RealAudioDevice {
            id: 3,
            key: "MacBook Pro Speakers|2|48000".to_string(),
            name: "MacBook Pro Speakers".to_string(),
            channels: 2,
            sample_rate: 48_000,
            is_default: true,
        };
        assert!(endpoint_record(pid, 0x9_000).is_none());
        store_endpoint_record(
            pid,
            0x9_000,
            AudioEndpointRecord {
                device: device.clone(),
                requested_riid: IID_IAUDIO_CLIENT,
            },
        );
        let record = endpoint_record(pid, 0x9_000).expect("record stored");
        assert_eq!(record.device, device);
        assert_eq!(record.requested_riid, IID_IAUDIO_CLIENT);
        // A different runtime never sees the record.
        assert!(endpoint_record(0x7b22, 0x9_000).is_none());
    }

    // -----------------------------------------------------------------------
    // IAudioClient / IAudioRenderClient — real format, clock and buffer model
    // -----------------------------------------------------------------------

    fn test_device() -> RealAudioDevice {
        RealAudioDevice {
            id: 1,
            key: "Test Device|2|48000".to_string(),
            name: "Test Device".to_string(),
            channels: 2,
            sample_rate: 48_000,
            is_default: true,
        }
    }

    fn test_format(tag: u16, channels: u16, rate: u32, bits: u16) -> AudioClientFormat {
        AudioClientFormat {
            container_tag: tag,
            wave_format_tag: tag,
            channels,
            sample_rate: rate,
            avg_bytes_per_sec: rate * channels as u32 * ((bits as u32 + 7) / 8),
            block_align: channels * ((bits + 7) / 8),
            bits_per_sample: bits,
            valid_bits_per_sample: bits,
            channel_mask: channel_mask_for_channels(channels),
        }
    }

    fn pcm16_stereo_48k_bytes() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(18);
        bytes.extend_from_slice(&WAVE_FORMAT_PCM.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&48_000_u32.to_le_bytes());
        bytes.extend_from_slice(&(48_000_u32 * 4).to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&16_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes
    }

    #[test]
    fn wave_format_parsing_accepts_real_pcm_shape() {
        let parsed = parse_wave_format(&pcm16_stereo_48k_bytes()).expect("valid PCM16 stereo");
        assert_eq!(parsed.wave_format_tag, WAVE_FORMAT_PCM);
        assert_eq!(parsed.channels, 2);
        assert_eq!(parsed.sample_rate, 48_000);
        assert_eq!(parsed.bits_per_sample, 16);
        assert_eq!(parsed.block_align, 4);
        assert_eq!(parsed.bytes_per_sample(), 2);
        assert!(!parsed.is_float());
    }

    #[test]
    fn wave_format_parsing_rejects_unsupported_shapes() {
        // Short structure.
        assert_eq!(
            parse_wave_format(&[0_u8; 10]),
            Err(AUDCLNT_E_UNSUPPORTED_FORMAT)
        );
        // Compressed/unbacked format tag (ADPCM = 0x0002).
        let mut adpcm = pcm16_stereo_48k_bytes();
        adpcm[0] = 0x02;
        assert_eq!(parse_wave_format(&adpcm), Err(AUDCLNT_E_UNSUPPORTED_FORMAT));
        // Zero channels.
        let mut zero_channels = pcm16_stereo_48k_bytes();
        zero_channels[2] = 0;
        zero_channels[3] = 0;
        assert_eq!(
            parse_wave_format(&zero_channels),
            Err(AUDCLNT_E_UNSUPPORTED_FORMAT)
        );
        // Invalid bit depth for PCM (7 bits).
        let mut seven_bits = pcm16_stereo_48k_bytes();
        seven_bits[14] = 7;
        assert_eq!(
            parse_wave_format(&seven_bits),
            Err(AUDCLNT_E_UNSUPPORTED_FORMAT)
        );
        // Block alignment inconsistent with channels/bits.
        let mut bad_align = pcm16_stereo_48k_bytes();
        bad_align[12] = 9;
        assert_eq!(
            parse_wave_format(&bad_align),
            Err(AUDCLNT_E_UNSUPPORTED_FORMAT)
        );
        // Extensible with an unknown sub-format GUID.
        let mut extensible = Vec::new();
        extensible.extend_from_slice(&WAVE_FORMAT_EXTENSIBLE.to_le_bytes());
        extensible.extend_from_slice(&2_u16.to_le_bytes());
        extensible.extend_from_slice(&48_000_u32.to_le_bytes());
        extensible.extend_from_slice(&(48_000_u32 * 4).to_le_bytes());
        extensible.extend_from_slice(&4_u16.to_le_bytes());
        extensible.extend_from_slice(&32_u16.to_le_bytes());
        extensible.extend_from_slice(&22_u16.to_le_bytes());
        extensible.extend_from_slice(&32_u16.to_le_bytes());
        extensible.extend_from_slice(&0x3_u32.to_le_bytes());
        extensible.extend_from_slice(&[0xAA; 16]);
        assert_eq!(
            parse_wave_format(&extensible),
            Err(AUDCLNT_E_UNSUPPORTED_FORMAT)
        );
    }

    #[test]
    fn wave_format_extensible_round_trips_through_serialization() {
        let device = test_device();
        let mix = mix_format_for_device(&device);
        assert_eq!(mix.channels, device.channels);
        assert_eq!(mix.sample_rate, device.sample_rate);
        assert_eq!(mix.bits_per_sample, 32);
        assert!(mix.is_float());
        let bytes = wave_format_bytes(&mix);
        assert_eq!(bytes.len(), 40);
        let parsed = parse_wave_format(&bytes).expect("serialized format parses");
        assert_eq!(parsed.wave_format_tag, WAVE_FORMAT_IEEE_FLOAT);
        assert_eq!(parsed.channels, device.channels);
        assert_eq!(parsed.sample_rate, device.sample_rate);
        assert_eq!(parsed.bits_per_sample, 32);
        assert_eq!(parsed.valid_bits_per_sample, 32);
        // A PCM16 guest format also round-trips as a supported conversion
        // shape.
        let pcm = parse_wave_format(&pcm16_stereo_48k_bytes()).expect("pcm parses");
        let pcm_bytes = wave_format_bytes(&pcm);
        let reparsed = parse_wave_format(&pcm_bytes).expect("pcm serialized parses");
        assert_eq!(reparsed.wave_format_tag, WAVE_FORMAT_PCM);
    }

    #[test]
    fn format_support_distinguishes_exact_convertible_and_unsupported() {
        let device = test_device();
        let mix = mix_format_for_device(&device);
        assert_eq!(
            audio_format_support(&device, &mix, AUDCLNT_SHAREMODE_SHARED),
            AUDCLNT_S_OK
        );
        let pcm16 = test_format(WAVE_FORMAT_PCM, 2, 48_000, 16);
        assert_eq!(
            audio_format_support(&device, &pcm16, AUDCLNT_SHAREMODE_SHARED),
            AUDCLNT_S_FALSE,
            "the backend's real conversion path supports PCM16"
        );
        let other_rate = test_format(WAVE_FORMAT_PCM, 2, 44_100, 16);
        assert_eq!(
            audio_format_support(&device, &other_rate, AUDCLNT_SHAREMODE_SHARED),
            AUDCLNT_S_FALSE,
            "shared mode resamples"
        );
        assert_eq!(
            audio_format_support(&device, &other_rate, AUDCLNT_SHAREMODE_EXCLUSIVE),
            AUDCLNT_E_UNSUPPORTED_FORMAT,
            "exclusive mode cannot leave the device rate"
        );
    }

    #[test]
    fn audio_client_clock_drains_submitted_frames_at_device_rate() {
        let pid = 0x7c01;
        let object = 0x9_101;
        let device = test_device();
        register_audio_client(pid, object, device.clone(), IID_IAUDIO_CLIENT);
        let format = test_format(WAVE_FORMAT_PCM, 2, 48_000, 16);
        let plan = plan_initialize(
            pid,
            object,
            AUDCLNT_SHAREMODE_SHARED,
            0,
            100_000,
            0,
            &format,
        )
        .expect("initialize plan");
        assert_eq!(plan.buffer_frames, 480);
        assert_eq!(
            commit_initialize(pid, object, &plan, &format, 0x2_000, 1920),
            AUDCLNT_S_OK
        );
        assert_eq!(start(pid, object), AUDCLNT_S_OK);
        assert_eq!(start(pid, object), AUDCLNT_S_FALSE, "already running");

        // Submit 480 frames (10 ms at 48 kHz) and backdate the clock span so
        // 5 ms have drained: 240 frames remain padded.
        {
            let mut registry = audio_clients();
            let state = registry
                .clients
                .get_mut(&pid)
                .and_then(|clients| clients.get_mut(&object))
                .expect("state");
            state.submitted_frames = 480;
            state.run_started = Some(Instant::now() - std::time::Duration::from_millis(5));
        }
        let padding = get_current_padding(pid, object).expect("padding");
        assert!(
            (200..=280).contains(&padding),
            "5 ms of 10 ms drains about half the buffer, got {padding}"
        );

        // Backdate past the whole buffer: the clock drains to zero.
        {
            let mut registry = audio_clients();
            let state = registry
                .clients
                .get_mut(&pid)
                .and_then(|clients| clients.get_mut(&object))
                .expect("state");
            state.run_started = Some(Instant::now() - std::time::Duration::from_millis(50));
        }
        assert_eq!(get_current_padding(pid, object), Ok(0));

        // Stop freezes the clock: padding set while stopped never advances.
        assert_eq!(stop(pid, object), AUDCLNT_S_OK);
        {
            let mut registry = audio_clients();
            let state = registry
                .clients
                .get_mut(&pid)
                .and_then(|clients| clients.get_mut(&object))
                .expect("state");
            state.submitted_frames = 480;
            state.drained_frames_carry = 240;
        }
        assert_eq!(get_current_padding(pid, object), Ok(240));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(
            get_current_padding(pid, object),
            Ok(240),
            "a stopped client's padding never advances"
        );
        assert_eq!(reset(pid, object), AUDCLNT_S_OK);
        assert_eq!(get_current_padding(pid, object), Ok(0));
        release_audio_object(pid, object);
    }

    #[test]
    fn render_buffer_round_trips_real_accounting() {
        let pid = 0x7c02;
        let object = 0x9_102;
        let service = 0x9_202;
        let device = test_device();
        register_audio_client(pid, object, device.clone(), IID_IAUDIO_CLIENT);
        let format = test_format(WAVE_FORMAT_PCM, 2, 8_000, 16);
        let plan = plan_initialize(
            pid,
            object,
            AUDCLNT_SHAREMODE_SHARED,
            0,
            500_000,
            0,
            &format,
        )
        .expect("initialize plan");
        assert_eq!(plan.buffer_frames, 400);
        assert_eq!(
            commit_initialize(pid, object, &plan, &format, 0x3_000, 1600),
            AUDCLNT_S_OK
        );
        bind_render_service(pid, object, service);
        assert_eq!(start(pid, object), AUDCLNT_S_OK);

        // GetBuffer hands out the real bound buffer address.
        let (address, frames) = render_get_buffer(pid, service, 400).expect("get buffer");
        assert_eq!(address, 0x3_000);
        assert_eq!(frames, 400);
        // Re-issuing before ReleaseBuffer is out of order.
        assert_eq!(
            render_get_buffer(pid, service, 100),
            Err(AUDCLNT_E_OUT_OF_ORDER)
        );
        let release = render_release_buffer(pid, service, 400, 0).expect("release buffer");
        assert_eq!(release.endpoint, object);
        assert_eq!(release.frames, 400);
        assert_eq!(release.buffer_address, 0x3_000);
        let snapshot = test_client_snapshot(pid, object).expect("snapshot");
        assert_eq!(snapshot.submitted_frames, 400);
        // At 8 kHz the 400 committed frames drain over 50 ms; immediately
        // after the release nearly the whole buffer is still padded.
        let padding = get_current_padding(pid, object).expect("padding");
        assert!(padding >= 380, "padding right after release: {padding}");
        // Releasing without a pending GetBuffer is out of order.
        assert_eq!(
            render_release_buffer(pid, service, 1, 0),
            Err(AUDCLNT_E_OUT_OF_ORDER)
        );
        // Let the real clock drain the committed frames, then round-trip a
        // second buffer (released as silence).
        for _ in 0..200 {
            if get_current_padding(pid, object) == Ok(0) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(get_current_padding(pid, object), Ok(0));
        render_get_buffer(pid, service, 400).expect("get buffer again");
        render_release_buffer(pid, service, 400, AUDCLNT_BUFFERFLAGS_SILENT)
            .expect("silent release");
        assert_eq!(
            test_client_snapshot(pid, object)
                .expect("snapshot")
                .submitted_frames,
            800
        );
        assert_eq!(stop(pid, object), AUDCLNT_S_OK);
        assert_eq!(
            render_get_buffer(pid, service, 100),
            Err(AUDCLNT_E_NOT_STARTED)
        );
        release_audio_object(pid, object);
        release_audio_object(pid, service);
    }

    #[test]
    fn event_handle_is_stored_and_ready_signal_is_transition_based() {
        let pid = 0x7c03;
        let object = 0x9_103;
        let device = test_device();
        register_audio_client(pid, object, device.clone(), IID_IAUDIO_CLIENT);
        let format = test_format(WAVE_FORMAT_PCM, 2, 48_000, 16);
        let plan = plan_initialize(
            pid,
            object,
            AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
            100_000,
            0,
            &format,
        )
        .expect("initialize plan");
        assert!(plan.event_driven);
        assert_eq!(
            commit_initialize(pid, object, &plan, &format, 0x4_000, 1920),
            AUDCLNT_S_OK
        );
        assert_eq!(set_event_handle(pid, object, 0xABC), AUDCLNT_S_OK);
        assert_eq!(start(pid, object), AUDCLNT_S_OK);
        assert_eq!(take_ready_event(pid, object), Some(0xABC));
        assert_eq!(
            take_ready_event(pid, object),
            None,
            "the ready signal is raised once per ready transition"
        );
        // The servicing-point tick raises the same event once the transition
        // flag is clear, and never crosses runtime boundaries.
        {
            let mut registry = audio_clients();
            let state = registry
                .clients
                .get_mut(&pid)
                .and_then(|clients| clients.get_mut(&object))
                .expect("state");
            state.event_ready_signaled = false;
        }
        assert_eq!(take_ready_events(pid), vec![0xABC]);
        assert!(take_ready_events(pid).is_empty());
        assert!(take_ready_events(0x7c99).is_empty());
        release_audio_object(pid, object);
    }

    #[test]
    fn event_handle_rejected_without_event_callback_flag() {
        let pid = 0x7c04;
        let object = 0x9_104;
        register_audio_client(pid, object, test_device(), IID_IAUDIO_CLIENT);
        let format = test_format(WAVE_FORMAT_PCM, 2, 48_000, 16);
        let plan = plan_initialize(
            pid,
            object,
            AUDCLNT_SHAREMODE_SHARED,
            0,
            100_000,
            0,
            &format,
        )
        .expect("initialize plan");
        commit_initialize(pid, object, &plan, &format, 0x5_000, 1920);
        assert_eq!(
            set_event_handle(pid, object, 0xABC),
            AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED
        );
        release_audio_object(pid, object);
    }

    #[test]
    fn extension_period_queries_derive_from_device_state() {
        let pid = 0x7c05;
        let object = 0x9_105;
        register_audio_client(pid, object, test_device(), IID_IAUDIO_CLIENT_3);
        let format = test_format(WAVE_FORMAT_PCM, 2, 48_000, 16);
        let (default_frames, fundamental_frames, minimum_frames, maximum_frames) =
            get_shared_mode_engine_period(pid, object, &format).expect("engine periods");
        assert!(default_frames > 0);
        assert_eq!(fundamental_frames, minimum_frames);
        assert!(minimum_frames <= default_frames);
        assert!(maximum_frames >= default_frames);
        let (minimum_hns, maximum_hns) =
            get_buffer_size_limits(pid, object, &format).expect("buffer limits");
        assert!(minimum_hns > 0);
        assert_eq!(maximum_hns, 20_000_000);
        let (mix, current_frames) =
            current_shared_mode_engine_period(pid, object).expect("current period");
        assert_eq!(mix.channels, 2);
        assert_eq!(mix.sample_rate, 48_000);
        assert!(mix.is_float());
        assert_eq!(current_frames, default_frames);
        assert_eq!(set_client_properties(pid, object, 3, false), AUDCLNT_S_OK);
        let plan = plan_initialize_shared_audio_stream(pid, object, 0, 240, &format)
            .expect("shared stream plan");
        assert_eq!(plan.buffer_frames, 240);
        release_audio_object(pid, object);
    }
}
