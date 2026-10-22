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
//! - The activation operation out-parameter receives a real guest
//!   `IActivateAudioInterfaceAsyncOperation` object
//!   (`QueryInterface`/`AddRef`/`Release`/`GetActivateResult`).  The
//!   completion handler receives that operation object (the Windows
//!   `IActivateAudioInterfaceCompletionHandler::ActivateCompleted` contract),
//!   and `GetActivateResult` returns the real activation HRESULT plus the
//!   activated interface (after AddRef).  Before the completion is delivered
//!   `GetActivateResult` returns `E_ILLEGAL_METHOD_CALL`; a second call after
//!   a successful read is rejected the same way.
//! - `Initialize` with `AUDCLNT_STREAMFLAGS_LOOPBACK` on a RENDER endpoint
//!   turns the client into a loopback capture client: `GetService(
//!   IID_IAudioCaptureClient)` then hands out the render stream's recently
//!   played frames (the same f32 frames released through the real render
//!   client, converted to the capture format) from a per-device history.
//!   With no render stream active the capture clock paces real silent
//!   packets flagged `AUDCLNT_BUFFERFLAGS_SILENT`.  Loopback requested on a
//!   genuine capture endpoint is `AUDCLNT_E_WRONG_ENDPOINT_TYPE`; loopback +
//!   exclusive mode is `AUDCLNT_E_INVALID_STREAM_FLAG` (loopback is a
//!   shared-mode path).  Capture endpoints from the
//!   `DEVINTERFACE_AUDIO_CAPTURE` activation path are real input endpoints
//!   (`AudioDirection::Capture`).
//! - Exclusive mode is enforced client-side with the real device values:
//!   the buffer duration is mandatory, at least the device minimum period
//!   (cpal's supported buffer-size minimum) and at most the engine's
//!   two-second maximum; a nonzero periodicity must also be at least the
//!   minimum and no larger than the buffer; and the format must be the exact
//!   device format (channel count, sample rate, 32-bit float), because
//!   exclusive mode forbids the shared-mode conversion path.  The cpal host
//!   path additionally opens a private fixed-buffer stream at that exact
//!   format.  What the host cannot provide is documented honestly: cpal does
//!   not expose a portable "hardware exclusive" flag (on backends without
//!   WASAPI exclusive support the stream is a private shared stream), the
//!   negotiated hardware period may be coarser than the requested
//!   `hnsPeriodicity`, and offload/bitstream exclusivity is not backed.
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

/// `E_ILLEGAL_METHOD_CALL` — `IActivateAudioInterfaceAsyncOperation::
/// GetActivateResult` before the activation completed, and on every call
/// after the completed result has been read once.
pub const E_ILLEGAL_METHOD_CALL: u32 = 0x8000_000E;
/// `E_PENDING` — the generic pending HRESULT retained for callers that probe
/// with it; the operation surface reports `E_ILLEGAL_METHOD_CALL`, which is
/// the documented `GetActivateResult` result before completion.
pub const E_PENDING: u32 = 0x8000_000A;

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

/// `AUDCLNT_S_BUFFER_EMPTY` `AUDCLNT_SUCCESS(0x001)` — no captured packet is
/// available to read.
pub const AUDCLNT_S_BUFFER_EMPTY: u32 = 0x0889_0001;
/// `AUDCLNT_S_THREAD_ALREADY_REGISTERED` `AUDCLNT_SUCCESS(0x002)` — the
/// session notification object is already registered.
pub const AUDCLNT_S_THREAD_ALREADY_REGISTERED: u32 = 0x0889_0002;

/// `AUDCLNT_STREAMSTATE_STRMFLGS_STOPPED` — `IAudioClock::GetState`.
pub const AUDCLNT_STREAMSTATE_STOPPED: u32 = 0x1;
/// `AUDCLNT_STREAMSTATE_STRMFLGS_RUNNING` — `IAudioClock::GetState`.
pub const AUDCLNT_STREAMSTATE_RUNNING: u32 = 0x2;
/// `AUDCLNT_STREAMSTATE_STRMFLGS_PAUSED` — `IAudioClock::GetState`.
pub const AUDCLNT_STREAMSTATE_PAUSED: u32 = 0x4;
/// `AUDCLNT_STREAMSTATE_STRMFLGS_ERROR` — `IAudioClock::GetState`.
pub const AUDCLNT_STREAMSTATE_ERROR: u32 = 0x8;

/// `AudioSessionStateInactive`.
pub const AUDIO_SESSION_STATE_INACTIVE: u32 = 0;
/// `AudioSessionStateActive`.
pub const AUDIO_SESSION_STATE_ACTIVE: u32 = 1;
/// `AudioSessionStateExpired`.
pub const AUDIO_SESSION_STATE_EXPIRED: u32 = 2;

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

/// `IID_IAudioCaptureClient` `{c8adbd64-e71e-48a0-a4de-185c395cd317}`.
pub const IID_IAUDIO_CAPTURE_CLIENT: [u8; 16] = [
    0x64, 0xbd, 0xad, 0xc8, 0x1e, 0xe7, 0xa0, 0x48, 0xa4, 0xde, 0x18, 0x5c, 0x39, 0x5c, 0xd3, 0x17,
];
/// `IID_IAudioClock` `{cd63314f-3fba-4a1b-812c-ef96358728e7}`.
pub const IID_IAUDIO_CLOCK: [u8; 16] = [
    0x4f, 0x31, 0x63, 0xcd, 0xba, 0x3f, 0x1b, 0x4a, 0x81, 0x2c, 0xef, 0x96, 0x35, 0x87, 0x28, 0xe7,
];
/// `IID_ISimpleAudioVolume` `{87ce5498-68d6-44e5-9215-6da47ef883d8}`.
pub const IID_ISIMPLE_AUDIO_VOLUME: [u8; 16] = [
    0x98, 0x54, 0xce, 0x87, 0xd6, 0x68, 0xe5, 0x44, 0x92, 0x15, 0x6d, 0xa4, 0x7e, 0xf8, 0x83, 0xd8,
];
/// `IID_IAudioStreamVolume` `{93014887-242d-4068-8a15-cf5e93b90fe3}`.
pub const IID_IAUDIO_STREAM_VOLUME: [u8; 16] = [
    0x87, 0x48, 0x01, 0x93, 0x2d, 0x24, 0x68, 0x40, 0x8a, 0x15, 0xcf, 0x5e, 0x93, 0xb9, 0x0f, 0xe3,
];
/// `IID_IAudioSessionControl` `{f4b1a599-7266-4319-a8ca-e70acb11e8cd}`.
pub const IID_IAUDIO_SESSION_CONTROL: [u8; 16] = [
    0x99, 0xa5, 0xb1, 0xf4, 0x66, 0x72, 0x19, 0x43, 0xa8, 0xca, 0xe7, 0x0a, 0xcb, 0x11, 0xe8, 0xcd,
];
/// `IID_IAudioSessionControl2` `{bfb7ff88-7239-4fc9-8fa2-07c950be9c6d}`.
pub const IID_IAUDIO_SESSION_CONTROL_2: [u8; 16] = [
    0x88, 0xff, 0xb7, 0xbf, 0x39, 0x72, 0xc9, 0x4f, 0x8f, 0xa2, 0x07, 0xc9, 0x50, 0xbe, 0x9c, 0x6d,
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
/// `IID_IActivateAudioInterfaceAsyncOperation`
/// `{72a22d78-cde4-431d-b8cc-843a71199b6d}`.
pub const IID_IACTIVATE_AUDIO_INTERFACE_ASYNC_OPERATION: [u8; 16] = [
    0x78, 0x2d, 0xa2, 0x72, 0xe4, 0xcd, 0x1d, 0x43, 0xb8, 0xcc, 0x84, 0x3a, 0x71, 0x19, 0x9b, 0x6d,
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
    } else if *riid == IID_IAUDIO_RENDER_CLIENT {
        "IAudioRenderClient".to_string()
    } else if *riid == IID_IAUDIO_CAPTURE_CLIENT {
        "IAudioCaptureClient".to_string()
    } else if *riid == IID_IAUDIO_CLOCK {
        "IAudioClock".to_string()
    } else if *riid == IID_ISIMPLE_AUDIO_VOLUME {
        "ISimpleAudioVolume".to_string()
    } else if *riid == IID_IAUDIO_STREAM_VOLUME {
        "IAudioStreamVolume".to_string()
    } else if *riid == IID_IAUDIO_SESSION_CONTROL {
        "IAudioSessionControl".to_string()
    } else if *riid == IID_IAUDIO_SESSION_CONTROL_2 {
        "IAudioSessionControl2".to_string()
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
///
/// The matching activation-operation object is completed here (before the
/// runtime invokes the handler) and becomes the completion's interface
/// argument, so the handler receives the Windows
/// `IActivateAudioInterfaceAsyncOperation` object rather than the activated
/// interface.
pub(crate) fn pop_activation_completion(pid: u32) -> Option<PendingActivationCompletion> {
    let mut completion = {
        let mut pending = pending_locks();
        let queue = pending.get_mut(&pid)?;
        let completion = queue.pop_front();
        if queue.is_empty() {
            pending.remove(&pid);
        }
        completion
    }?;
    if let Some(operation) = pop_pending_operation(pid) {
        complete_activation_operation(
            pid,
            operation,
            completion.result_hr,
            completion.interface_object,
        );
        completion.interface_object = operation;
    }
    Some(completion)
}

/// Number of completions still queued for `pid` (test observability helper).
#[cfg(test)]
pub(crate) fn pending_activation_completions(pid: u32) -> usize {
    pending_locks().get(&pid).map(VecDeque::len).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// IActivateAudioInterfaceAsyncOperation — real guest operation objects
// ---------------------------------------------------------------------------
//
// One operation object is allocated per async activation (including failed
// activations: Windows always completes an operation, with the activation
// HRESULT inside).  The operation starts incomplete; the runtime's completion
// drain completes it through `pop_activation_completion` immediately before
// invoking the handler, so `GetActivateResult` inside `ActivateCompleted`
// observes the real result.
//
// Lifecycle: the guest holds one reference on the operation object.  The
// operation state is dropped when the last guest reference is released; a
// pending operation is also dropped if its activation never completes.

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActivationOperationState {
    /// The real activation HRESULT (S_OK, E_NOINTERFACE,
    /// AUDCLNT_E_DEVICE_INVALIDATED, ...).
    result_hr: u32,
    /// The activated interface object (0 for a failed activation).
    interface_object: u64,
    /// Whether the activation reached completion.
    completed: bool,
    /// Whether `GetActivateResult` already returned the completed result.
    result_taken: bool,
}

static ACTIVATION_OPERATIONS: LazyLock<
    Mutex<HashMap<u32, BTreeMap<u64, ActivationOperationState>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

static PENDING_OPERATIONS: LazyLock<Mutex<HashMap<u32, VecDeque<u64>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn operation_locks() -> MutexGuard<'static, HashMap<u32, BTreeMap<u64, ActivationOperationState>>> {
    ACTIVATION_OPERATIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn pending_operation_locks() -> MutexGuard<'static, HashMap<u32, VecDeque<u64>>> {
    PENDING_OPERATIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Register a freshly allocated operation object and its pending activation.
///
/// The operation is queued in activation order; the matching completion
/// (pushed by the activation dispatch) completes it when the runtime drain
/// delivers the handler.
pub(crate) fn register_activation_operation(pid: u32, operation: u64, interface_object: u64) {
    operation_locks().entry(pid).or_default().insert(
        operation,
        ActivationOperationState {
            result_hr: ACTIVATION_S_OK,
            interface_object,
            completed: false,
            result_taken: false,
        },
    );
    pending_operation_locks()
        .entry(pid)
        .or_default()
        .push_back(operation);
}

fn pop_pending_operation(pid: u32) -> Option<u64> {
    let mut pending = pending_operation_locks();
    let queue = pending.get_mut(&pid)?;
    let operation = queue.pop_front();
    if queue.is_empty() {
        pending.remove(&pid);
    }
    operation
}

/// Mark an operation as completed with the real activation outcome.
pub(crate) fn complete_activation_operation(
    pid: u32,
    operation: u64,
    result_hr: u32,
    interface_object: u64,
) {
    if let Some(state) = operation_locks()
        .get_mut(&pid)
        .and_then(|operations| operations.get_mut(&operation))
    {
        state.result_hr = result_hr;
        state.interface_object = interface_object;
        state.completed = true;
    }
}

/// `IActivateAudioInterfaceAsyncOperation::GetActivateResult`.
///
/// Returns `(activation_hr, activated_interface)` once, after completion.
/// Before completion, and on every call after the first completed read, the
/// documented `E_ILLEGAL_METHOD_CALL` is returned.
pub(crate) fn operation_get_activate_result(pid: u32, operation: u64) -> Result<(u32, u64), u32> {
    let mut operations = operation_locks();
    let Some(state) = operations
        .get_mut(&pid)
        .and_then(|operations| operations.get_mut(&operation))
    else {
        return Err(E_ILLEGAL_METHOD_CALL);
    };
    if !state.completed || state.result_taken {
        return Err(E_ILLEGAL_METHOD_CALL);
    }
    state.result_taken = true;
    Ok((state.result_hr, state.interface_object))
}

/// Whether an operation object supports the requested riid in
/// `QueryInterface`.
pub(crate) fn activation_operation_supports_riid(riid: &[u8; 16]) -> bool {
    *riid == IID_IUNKNOWN || *riid == IID_IACTIVATE_AUDIO_INTERFACE_ASYNC_OPERATION
}

/// Whether `operation` is a live activation-operation object of `pid`.
pub(crate) fn is_activation_operation(pid: u32, operation: u64) -> bool {
    operation_locks()
        .get(&pid)
        .is_some_and(|operations| operations.contains_key(&operation))
}

/// The activated interface a (possibly pending) operation carries (test and
/// tooling observability; completion updates it in place).
#[allow(dead_code)] // read by the audio-activation tests and endpoint tooling
pub(crate) fn activation_operation_interface(pid: u32, operation: u64) -> Option<u64> {
    operation_locks()
        .get(&pid)
        .and_then(|operations| operations.get(&operation))
        .map(|state| state.interface_object)
}

/// Drop the operation state of `operation` (called when the guest object's
/// last reference is released).
pub(crate) fn release_activation_operation(pid: u32, operation: u64) {
    let removed = operation_locks()
        .get_mut(&pid)
        .and_then(|operations| operations.remove(&operation))
        .is_some();
    if removed {
        let mut pending = pending_operation_locks();
        if let Some(queue) = pending.get_mut(&pid) {
            queue.retain(|candidate| *candidate != operation);
            if queue.is_empty() {
                pending.remove(&pid);
            }
        }
    }
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
// Loopback capture — the render stream's played frames, duplicated
// ---------------------------------------------------------------------------
//
// Loopback capture is activated on a RENDER endpoint with
// `AUDCLNT_STREAMFLAGS_LOOPBACK`.  The frames a render client releases are
// appended to a per-runtime/per-device ring (the same f32 samples that are
// pushed into the real cpal output), and a loopback capture client reads them
// back with its own absolute cursor, converted to the capture client's
// channel count and sample rate.  No render stream active means no source
// frames: the capture packet is paced by the capture clock and reported with
// `AUDCLNT_BUFFERFLAGS_SILENT`, which is the real WASAPI loopback behaviour
// for a silent render side.

/// Two seconds of loopback history per device (the engine's maximum buffer).
const LOOPBACK_HISTORY_SECONDS: u32 = 2;

#[derive(Debug, Clone)]
struct LoopbackRing {
    /// Interleaved f32 samples in the renderer's format.
    samples: VecDeque<f32>,
    /// Renderer channel count.
    channels: u16,
    /// Renderer sample rate.
    sample_rate: u32,
    /// Absolute frame index of `samples.front()`.
    base_frame: u64,
}

impl LoopbackRing {
    fn end_frame(&self) -> u64 {
        let channels = self.channels.max(1) as u64;
        self.base_frame + self.samples.len() as u64 / channels
    }
}

static LOOPBACK_RINGS: LazyLock<Mutex<HashMap<(u32, String), LoopbackRing>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Running render streams per runtime/device, used to distinguish "render
/// side is silent because it is not running" from "render side is running but
/// has not produced a packet yet".
static ACTIVE_RENDER_STREAMS: LazyLock<Mutex<HashMap<(u32, String), usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn loopback_ring_locks() -> MutexGuard<'static, HashMap<(u32, String), LoopbackRing>> {
    LOOPBACK_RINGS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn active_render_locks() -> MutexGuard<'static, HashMap<(u32, String), usize>> {
    ACTIVE_RENDER_STREAMS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn mark_render_stream_started(pid: u32, key: &str) {
    *active_render_locks()
        .entry((pid, key.to_string()))
        .or_insert(0) += 1;
}

fn mark_render_stream_stopped(pid: u32, key: &str) {
    let mut active = active_render_locks();
    if let Some(count) = active.get_mut(&(pid, key.to_string())) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            active.remove(&(pid, key.to_string()));
        }
    }
}

/// Whether a render stream on the loopback endpoint's device is running.
fn render_stream_active(pid: u32, key: &str) -> bool {
    active_render_locks()
        .get(&(pid, key.to_string()))
        .copied()
        .unwrap_or(0)
        > 0
}

/// Append released render frames to the device's loopback history.
fn loopback_push_frames(pid: u32, key: &str, samples: &[f32], channels: u16, sample_rate: u32) {
    let channels = channels.max(1);
    let sample_rate = sample_rate.max(1);
    let mut rings = loopback_ring_locks();
    let ring = rings
        .entry((pid, key.to_string()))
        .or_insert_with(|| LoopbackRing {
            samples: VecDeque::new(),
            channels,
            sample_rate,
            base_frame: 0,
        });
    if ring.channels != channels || ring.sample_rate != sample_rate {
        // The renderer changed format: keep the absolute timeline continuous
        // and start the new format with an empty history.
        ring.base_frame = ring.end_frame();
        ring.samples.clear();
        ring.channels = channels;
        ring.sample_rate = sample_rate;
    }
    ring.samples.extend(samples.iter().copied());
    let max_frames = (sample_rate as u64)
        .saturating_mul(LOOPBACK_HISTORY_SECONDS as u64)
        .max(1);
    while ring.end_frame().saturating_sub(ring.base_frame) > max_frames {
        let drop_samples = channels as usize;
        if ring.samples.len() < drop_samples {
            ring.samples.clear();
            break;
        }
        for _ in 0..drop_samples {
            ring.samples.pop_front();
        }
        ring.base_frame += 1;
    }
}

/// The loopback history of a device: `(base_frame, end_frame, channels,
/// sample_rate)`.
fn loopback_ring_info(pid: u32, key: &str) -> Option<(u64, u64, u16, u32)> {
    let rings = loopback_ring_locks();
    let ring = rings.get(&(pid, key.to_string()))?;
    Some((
        ring.base_frame,
        ring.end_frame(),
        ring.channels,
        ring.sample_rate,
    ))
}

/// Frames a loopback capture client can read right now, in its own format.
fn loopback_available_frames(
    pid: u32,
    key: &str,
    cursor: u64,
    capture_rate: u32,
    capture_channels: u16,
) -> u32 {
    let _ = capture_channels;
    let Some((base, end, _, source_rate)) = loopback_ring_info(pid, key) else {
        return 0;
    };
    let cursor = cursor.max(base).min(end);
    let available = end - cursor;
    let target = available.saturating_mul(capture_rate.max(1) as u64) / source_rate.max(1) as u64;
    target.min(u32::MAX as u64) as u32
}

/// Read loopback frames into the capture client's format.
///
/// Returns the interleaved samples (zero-filled when the history is shorter
/// than the requested packet) and the number of output frames that carried
/// real source samples.
fn loopback_take_frames(
    pid: u32,
    key: &str,
    cursor: &mut u64,
    capture_channels: u16,
    capture_rate: u32,
    frames: u32,
) -> (Vec<f32>, u32) {
    let capture_channels = capture_channels.max(1) as usize;
    let capture_rate = capture_rate.max(1);
    let mut output = vec![0.0f32; frames as usize * capture_channels];
    let mut rings = loopback_ring_locks();
    let Some(ring) = rings.get_mut(&(pid, key.to_string())) else {
        // No render history at all: the silent clock packet does not advance
        // the cursor, so frames rendered later are still captured.
        return (output, 0);
    };
    if *cursor < ring.base_frame {
        *cursor = ring.base_frame;
    }
    let available = ring.end_frame().saturating_sub(*cursor);
    let source_channels = ring.channels.max(1) as usize;
    let source_rate = ring.sample_rate.max(1) as u64;
    let ratio = source_rate as f64 / capture_rate as f64;
    let mut real_frames = 0_u32;
    for frame in 0..frames as u64 {
        let position = *cursor as f64 + frame as f64 * ratio;
        let source_frame = position.floor() as u64;
        if source_frame >= ring.end_frame() {
            break;
        }
        let offset = (source_frame - ring.base_frame) as usize * source_channels;
        if offset + source_channels > ring.samples.len() {
            break;
        }
        let source: Vec<f32> = ring
            .samples
            .iter()
            .skip(offset)
            .take(source_channels)
            .copied()
            .collect();
        let frame_start = frame as usize * capture_channels;
        match (capture_channels, source_channels) {
            (dst, src) if dst == src => {
                output[frame_start..frame_start + dst].copy_from_slice(&source);
            }
            (1, src) => {
                let sum: f32 = source.iter().take(src).sum();
                output[frame_start] = sum / src as f32;
            }
            (dst, 1) => {
                for channel in 0..dst {
                    output[frame_start + channel] = source[0];
                }
            }
            (dst, src) => {
                for channel in 0..dst {
                    output[frame_start + channel] = source.get(channel).copied().unwrap_or(0.0);
                }
                let _ = src;
            }
        }
        real_frames += 1;
    }
    // Advance only past source frames that actually contributed to this
    // packet; a silent clock-paced packet leaves the cursor at the render
    // position so a later render packet is not skipped.
    if real_frames > 0 {
        let consumed = (real_frames as f64 * ratio).ceil().max(1.0) as u64;
        *cursor = cursor.saturating_add(consumed.min(available));
    }
    (output, real_frames)
}

/// The initial capture cursor: the first frame still retained in the render
/// history (so a loopback client reads the recently played frames).
fn loopback_start_cursor(pid: u32, key: &str) -> u64 {
    loopback_ring_info(pid, key)
        .map(|(base, _, _, _)| base)
        .unwrap_or(0)
}

/// Discard the buffered loopback history for one capture client (Reset): the
/// next packet starts at the current render position.
fn loopback_reset_cursor(pid: u32, key: &str) -> u64 {
    loopback_ring_info(pid, key)
        .map(|(_, end, _, _)| end)
        .unwrap_or(0)
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

/// The `IActivateAudioInterfaceAsyncOperation` vtable method sequence:
/// IUnknown preamble plus `GetActivateResult` at slot 3.
pub(crate) fn audio_activation_operation_methods() -> Vec<HostThunk> {
    vec![
        HostThunk::AudioActivationOperationQueryInterface, // [0]
        HostThunk::GuestObjectAddRef,                      // [1]
        HostThunk::GuestObjectRelease,                     // [2]
        HostThunk::AudioActivationOperationGetActivateResult, // [3]
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

/// The stream direction of a bound audio client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AudioDirection {
    /// A render (playback) client: released frames flow into the real output.
    Render,
    /// A capture (recording) client: `GetBuffer` hands out real captured
    /// frames.
    Capture,
}

/// Which real service object a bound guest service object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AudioServiceKind {
    /// `IAudioRenderClient` (render endpoints only).
    RenderClient,
    /// `IAudioClock`.
    Clock,
    /// `ISimpleAudioVolume`.
    SimpleVolume,
    /// `IAudioStreamVolume`.
    StreamVolume,
    /// `IAudioSessionControl` / `IAudioSessionControl2`.
    SessionControl,
    /// `IAudioCaptureClient` (capture endpoints only).
    CaptureClient,
}

impl AudioServiceKind {
    /// Whether this service kind is valid for the endpoint direction.
    pub fn supports_direction(self, direction: AudioDirection) -> bool {
        match self {
            AudioServiceKind::RenderClient => direction == AudioDirection::Render,
            AudioServiceKind::CaptureClient => direction == AudioDirection::Capture,
            _ => true,
        }
    }
}

/// The IAudioClock vtable method sequence: IUnknown preamble,
/// `GetFrequency`, `GetPosition`, `GetState`.
pub(crate) fn audio_clock_methods() -> Vec<HostThunk> {
    vec![
        HostThunk::AudioServiceQueryInterface, // [0]
        HostThunk::GuestObjectAddRef,          // [1]
        HostThunk::GuestObjectRelease,         // [2]
        HostThunk::AudioClockGetFrequency,     // [3]
        HostThunk::AudioClockGetPosition,      // [4]
        HostThunk::AudioClockGetState,         // [5]
    ]
}

/// The ISimpleAudioVolume vtable method sequence: IUnknown preamble,
/// `SetMasterVolume`, `GetMasterVolume`, `SetMute`, `GetMute`.
pub(crate) fn simple_audio_volume_methods() -> Vec<HostThunk> {
    vec![
        HostThunk::AudioServiceQueryInterface,       // [0]
        HostThunk::GuestObjectAddRef,                // [1]
        HostThunk::GuestObjectRelease,               // [2]
        HostThunk::AudioSimpleVolumeSetMasterVolume, // [3]
        HostThunk::AudioSimpleVolumeGetMasterVolume, // [4]
        HostThunk::AudioSimpleVolumeSetMute,         // [5]
        HostThunk::AudioSimpleVolumeGetMute,         // [6]
    ]
}

/// The IAudioStreamVolume vtable method sequence: IUnknown preamble,
/// `GetChannelCount`, `SetChannelVolume`, `GetChannelVolume`,
/// `SetAllVolumes`, `GetAllVolumes`.
pub(crate) fn audio_stream_volume_methods() -> Vec<HostThunk> {
    vec![
        HostThunk::AudioServiceQueryInterface,        // [0]
        HostThunk::GuestObjectAddRef,                 // [1]
        HostThunk::GuestObjectRelease,                // [2]
        HostThunk::AudioStreamVolumeGetChannelCount,  // [3]
        HostThunk::AudioStreamVolumeSetChannelVolume, // [4]
        HostThunk::AudioStreamVolumeGetChannelVolume, // [5]
        HostThunk::AudioStreamVolumeSetAllVolumes,    // [6]
        HostThunk::AudioStreamVolumeGetAllVolumes,    // [7]
    ]
}

/// The IAudioSessionControl2 vtable method sequence: the IAudioSessionControl
/// surface plus the IAudioSessionControl2 extension methods.  Activating
/// `IAudioSessionControl` returns this same object; its first eleven slots are
/// layout-compatible with `IAudioSessionControl`.
pub(crate) fn audio_session_control_methods() -> Vec<HostThunk> {
    vec![
        HostThunk::AudioServiceQueryInterface,                // [0]
        HostThunk::GuestObjectAddRef,                         // [1]
        HostThunk::GuestObjectRelease,                        // [2]
        HostThunk::AudioSessionControlGetState,               // [3]
        HostThunk::AudioSessionControlSetDisplayName,         // [4]
        HostThunk::AudioSessionControlGetDisplayName,         // [5]
        HostThunk::AudioSessionControlSetIconPath,            // [6]
        HostThunk::AudioSessionControlGetIconPath,            // [7]
        HostThunk::AudioSessionControlSetGroupingParam,       // [8]
        HostThunk::AudioSessionControlGetGroupingParam,       // [9]
        HostThunk::AudioSessionControlRegisterNotification,   // [10]
        HostThunk::AudioSessionControlUnregisterNotification, // [11]
        HostThunk::AudioSessionControl2GetSessionIdentifier,  // [12]
        HostThunk::AudioSessionControl2GetSessionInstanceIdentifier, // [13]
        HostThunk::AudioSessionControl2GetProcessId,          // [14]
        HostThunk::AudioSessionControl2IsSystemSoundsSession, // [15]
        HostThunk::AudioSessionControl2SetDuckingPreference,  // [16]
    ]
}

/// The IAudioCaptureClient vtable method sequence: IUnknown preamble,
/// `GetBuffer`, `ReleaseBuffer`, `GetNextPacketSize`.
pub(crate) fn audio_capture_client_methods() -> Vec<HostThunk> {
    vec![
        HostThunk::AudioServiceQueryInterface,          // [0]
        HostThunk::GuestObjectAddRef,                   // [1]
        HostThunk::GuestObjectRelease,                  // [2]
        HostThunk::AudioCaptureClientGetBuffer,         // [3]
        HostThunk::AudioCaptureClientReleaseBuffer,     // [4]
        HostThunk::AudioCaptureClientGetNextPacketSize, // [5]
    ]
}

/// The vtable method sequence of one service kind.
pub(crate) fn audio_service_methods(kind: AudioServiceKind) -> Vec<HostThunk> {
    match kind {
        AudioServiceKind::RenderClient => audio_render_client_methods(),
        AudioServiceKind::Clock => audio_clock_methods(),
        AudioServiceKind::SimpleVolume => simple_audio_volume_methods(),
        AudioServiceKind::StreamVolume => audio_stream_volume_methods(),
        AudioServiceKind::SessionControl => audio_session_control_methods(),
        AudioServiceKind::CaptureClient => audio_capture_client_methods(),
    }
}

/// The IID of a service kind's primary interface (used by `GetService` and
/// `QueryInterface`).
pub(crate) fn audio_service_iid(kind: AudioServiceKind) -> [u8; 16] {
    match kind {
        AudioServiceKind::RenderClient => IID_IAUDIO_RENDER_CLIENT,
        AudioServiceKind::Clock => IID_IAUDIO_CLOCK,
        AudioServiceKind::SimpleVolume => IID_ISIMPLE_AUDIO_VOLUME,
        AudioServiceKind::StreamVolume => IID_IAUDIO_STREAM_VOLUME,
        AudioServiceKind::SessionControl => IID_IAUDIO_SESSION_CONTROL,
        AudioServiceKind::CaptureClient => IID_IAUDIO_CAPTURE_CLIENT,
    }
}

/// Resolve a requested service IID to its real service kind (`GetService`).
pub(crate) fn audio_service_kind_for_riid(riid: &[u8; 16]) -> Option<AudioServiceKind> {
    if *riid == IID_IAUDIO_RENDER_CLIENT {
        Some(AudioServiceKind::RenderClient)
    } else if *riid == IID_IAUDIO_CLOCK {
        Some(AudioServiceKind::Clock)
    } else if *riid == IID_ISIMPLE_AUDIO_VOLUME {
        Some(AudioServiceKind::SimpleVolume)
    } else if *riid == IID_IAUDIO_STREAM_VOLUME {
        Some(AudioServiceKind::StreamVolume)
    } else if *riid == IID_IAUDIO_SESSION_CONTROL || *riid == IID_IAUDIO_SESSION_CONTROL_2 {
        Some(AudioServiceKind::SessionControl)
    } else if *riid == IID_IAUDIO_CAPTURE_CLIENT {
        Some(AudioServiceKind::CaptureClient)
    } else {
        None
    }
}

/// Whether a service object of `kind` supports `riid` in its
/// `QueryInterface`.
pub(crate) fn audio_service_supports_riid(kind: AudioServiceKind, riid: &[u8; 16]) -> bool {
    if *riid == IID_IUNKNOWN {
        return true;
    }
    match kind {
        AudioServiceKind::SessionControl => {
            *riid == IID_IAUDIO_SESSION_CONTROL || *riid == IID_IAUDIO_SESSION_CONTROL_2
        }
        other => *riid == audio_service_iid(other),
    }
}

/// Human-readable service name for traces.
pub(crate) fn audio_service_name(kind: AudioServiceKind) -> &'static str {
    match kind {
        AudioServiceKind::RenderClient => "IAudioRenderClient",
        AudioServiceKind::Clock => "IAudioClock",
        AudioServiceKind::SimpleVolume => "ISimpleAudioVolume",
        AudioServiceKind::StreamVolume => "IAudioStreamVolume",
        AudioServiceKind::SessionControl => "IAudioSessionControl",
        AudioServiceKind::CaptureClient => "IAudioCaptureClient",
    }
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
/// the real guest buffer and the real stream clock.  Render clients drain
/// committed frames through the playback clock; capture clients produce
/// frames through the capture clock (real input callback when the host input
/// opened, the paced capture queue otherwise).
#[derive(Debug, Clone)]
pub struct AudioClientState {
    /// The real device snapshot the endpoint was activated on.
    pub device: RealAudioDevice,
    /// The direction the endpoint was activated for.  A render endpoint that
    /// Initialize switched to loopback reports `Capture` here.
    pub direction: AudioDirection,
    /// Whether this client is a loopback capture on a render endpoint.
    pub loopback: bool,
    /// The riid the guest requested at activation.
    pub requested_riid: [u8; 16],
    /// Per-session serial backing the session identifiers.
    pub session_serial: u64,
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
    /// Guest address of the real render/capture buffer.
    pub buffer_address: u64,
    /// Byte length of the real guest buffer.
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
    /// The real exclusive-mode audio client id the exclusive stream opened
    /// with (None when exclusive mode fell back to the client-side contract
    /// or the stream is shared).
    pub exclusive_client_id: Option<crate::audio::AudioClientId>,
    /// The cached IAudioRenderClient guest object (0 when none yet).
    pub render_service_object: u64,
    /// The cached IAudioClock guest object (0 when none yet).
    pub clock_service_object: u64,
    /// The cached ISimpleAudioVolume guest object (0 when none yet).
    pub simple_volume_service_object: u64,
    /// The cached IAudioStreamVolume guest object (0 when none yet).
    pub stream_volume_service_object: u64,
    /// The cached IAudioSessionControl/IAudioSessionControl2 guest object
    /// (0 when none yet).
    pub session_service_object: u64,
    /// The cached IAudioCaptureClient guest object (0 when none yet).
    pub capture_service_object: u64,
    /// The `IAudioClient2::SetClientProperties` stream category.
    pub client_category: u32,
    /// The `IAudioClient2::SetClientProperties` offload request.
    pub client_offload_requested: bool,
    // ── Session (ISimpleAudioVolume / IAudioStreamVolume / session) state ──
    /// Session master volume (0.0..=1.0), applied to pushed output samples.
    pub session_volume: f32,
    /// Session mute; when set the endpoint's output gain is zero.
    pub session_muted: bool,
    /// Per-channel stream volumes (empty = every channel at 1.0).
    pub channel_volumes: Vec<f32>,
    /// Session display name (`SetDisplayName`); None is the device default.
    pub session_display_name: Option<String>,
    /// Session icon path (`SetIconPath`); None means no icon path set.
    pub session_icon_path: Option<String>,
    /// Session grouping parameter (`SetGroupingParam`).
    pub session_grouping_param: [u8; 16],
    /// The registered `IAudioSessionEvents` notification object (0 = none).
    pub session_notification_object: u64,
    /// `IAudioSessionControl2::SetDuckingPreference` opt-out flag.
    pub session_ducking_opt_out: bool,
    // ── Capture state ──────────────────────────────────────────────────────
    /// Frames produced by the capture clock before the current run span.
    pub capture_frames_carry: u64,
    /// Frames released to the guest through `ReleaseBuffer`.
    pub capture_consumed_frames: u64,
    /// Frames of the outstanding capture packet (0 when none is handed out).
    pub capture_outstanding_frames: u32,
    /// Capture packet device position at `GetBuffer` time.
    pub capture_packet_position: u64,
    /// Capture packet QPC position (100 ns since the client epoch).
    pub capture_packet_qpc: u64,
    /// Real captured samples delivered by the input callback (f32,
    /// interleaved) waiting to be handed out.
    pub capture_queue: VecDeque<f32>,
    /// Absolute render-frame cursor of a loopback capture client.
    pub loopback_cursor: u64,
    /// Whether the real cpal input stream opened for this client.
    pub capture_input_active: bool,
    /// Client epoch used for `IAudioClock::GetPosition`'s QPC value.
    pub clock_epoch: Instant,
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

    /// Frames the real capture clock has produced at `now`.
    fn capture_arrived_frames(&self, now: Instant) -> u64 {
        let mut arrived = self.capture_frames_carry;
        if let Some(started) = self.run_started {
            let rate = self
                .format
                .as_ref()
                .map(|format| format.sample_rate)
                .unwrap_or(self.device.sample_rate)
                .max(1);
            let elapsed = now.saturating_duration_since(started);
            let frames = (elapsed.as_nanos() * rate as u128 / 1_000_000_000) as u64;
            arrived = arrived.saturating_add(frames);
        }
        arrived
    }

    /// The frames of the next capture packet, capped at the client buffer
    /// size (the engine's packet size).
    ///
    /// Loopback clients are queue-driven: the packet size is the render
    /// history available to this client.  While a render stream is running an
    /// empty history means "wait for the render side"; with no render stream
    /// active the packet is paced by the capture clock and will be delivered
    /// as silence (`AUDCLNT_BUFFERFLAGS_SILENT`).
    fn capture_next_packet_frames(&self, pid: u32, now: Instant) -> u32 {
        if self.loopback {
            let rate = self
                .format
                .as_ref()
                .map(|format| format.sample_rate)
                .unwrap_or(self.device.sample_rate);
            let channels = self
                .format
                .as_ref()
                .map(|format| format.channels)
                .unwrap_or(self.device.channels);
            let loopback = loopback_available_frames(
                pid,
                &self.device.key,
                self.loopback_cursor,
                rate,
                channels,
            );
            if loopback > 0 {
                return loopback.min(self.buffer_frames.max(1));
            }
            if render_stream_active(pid, &self.device.key) {
                return 0;
            }
        }
        let available = self
            .capture_arrived_frames(now)
            .saturating_sub(self.capture_consumed_frames);
        available.min(self.buffer_frames.max(1) as u64) as u32
    }

    /// The stream frequency (`IAudioClock::GetFrequency`).
    fn clock_frequency(&self) -> u32 {
        self.format
            .as_ref()
            .map(|format| format.sample_rate)
            .unwrap_or(self.device.sample_rate)
            .max(1)
    }

    /// The played/captured frame position and the QPC position at `now`.
    fn clock_position(&self, now: Instant) -> (u64, u64) {
        let position = match self.direction {
            AudioDirection::Render => self.drained_frames(now),
            AudioDirection::Capture => self.capture_arrived_frames(now),
        };
        let qpc = now
            .saturating_duration_since(self.clock_epoch)
            .as_nanos()
            .checked_div(100)
            .unwrap_or(0)
            .min(u64::MAX as u128) as u64;
        (position, qpc)
    }

    /// The session state (`AudioSessionStateActive` while the stream runs).
    fn session_state(&self) -> u32 {
        if self.running {
            AUDIO_SESSION_STATE_ACTIVE
        } else {
            AUDIO_SESSION_STATE_INACTIVE
        }
    }

    /// The per-channel output gains of the session volume/mute state and the
    /// per-channel stream volumes (one gain per client channel).
    pub fn output_gains(&self) -> Vec<f32> {
        let channels = self
            .format
            .as_ref()
            .map(|format| format.channels)
            .unwrap_or(self.device.channels)
            .max(1) as usize;
        let master = if self.session_muted {
            0.0
        } else {
            self.session_volume.clamp(0.0, 1.0)
        };
        (0..channels)
            .map(|channel| master * self.channel_volumes.get(channel).copied().unwrap_or(1.0))
            .collect()
    }

    /// Apply the session gains to interleaved `samples` in place.
    pub fn apply_output_gain(&self, samples: &mut [f32]) {
        let gains = self.output_gains();
        if gains.is_empty() {
            return;
        }
        for (index, sample) in samples.iter_mut().enumerate() {
            *sample *= gains[index % gains.len()];
        }
    }
}

/// Apply per-channel output gains to interleaved samples (the real
/// `ISimpleAudioVolume` + `IAudioStreamVolume` gain, applied where released
/// frames enter the host output).
pub fn apply_output_gains(samples: &mut [f32], gains: &[f32]) {
    if gains.is_empty() {
        return;
    }
    for (index, sample) in samples.iter_mut().enumerate() {
        *sample *= gains[index % gains.len()];
    }
}

/// The real plan produced by [`plan_initialize`] before the guest buffer is
/// allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// `AUDCLNT_STREAMFLAGS_LOOPBACK`: capture the render side of a render
    /// endpoint.
    pub loopback: bool,
    /// Requested buffer duration in `REFERENCE_TIME` units.
    pub duration_hns: u64,
    /// Requested periodicity in `REFERENCE_TIME` units.
    pub periodicity_hns: u64,
}

#[derive(Default)]
struct AudioClientRegistry {
    clients: HashMap<u32, BTreeMap<u64, AudioClientState>>,
    /// Every real service object handed out by `GetService`: object →
    /// (endpoint, service kind).
    services: HashMap<u32, BTreeMap<u64, (u64, AudioServiceKind)>>,
}

/// Per-session serial counter (the non-zero identity component of the
/// session identifier strings).
static NEXT_SESSION_SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

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

/// Attach a real render audio-client state to a freshly activated endpoint
/// object.
///
/// Idempotent: a pre-existing state for the object is left untouched.  The
/// activation path uses [`register_audio_client_direction`] because capture
/// endpoints must be bound with `AudioDirection::Capture`; this render-only
/// helper remains for tests and render-side tooling.
#[allow(dead_code)] // render-path helper retained for tests/tooling
pub(crate) fn register_audio_client(
    pid: u32,
    object: u64,
    device: RealAudioDevice,
    requested_riid: [u8; 16],
) {
    register_audio_client_direction(pid, object, device, requested_riid, AudioDirection::Render);
}

/// Attach a real audio-client state for `direction` to an endpoint object.
///
/// Idempotent: a pre-existing state for the object is left untouched.
pub(crate) fn register_audio_client_direction(
    pid: u32,
    object: u64,
    device: RealAudioDevice,
    requested_riid: [u8; 16],
    direction: AudioDirection,
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
            direction,
            loopback: false,
            requested_riid,
            session_serial: NEXT_SESSION_SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
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
            exclusive_client_id: None,
            render_service_object: 0,
            clock_service_object: 0,
            simple_volume_service_object: 0,
            stream_volume_service_object: 0,
            session_service_object: 0,
            capture_service_object: 0,
            client_category: 0,
            client_offload_requested: false,
            session_volume: 1.0,
            session_muted: false,
            channel_volumes: Vec::new(),
            session_display_name: None,
            session_icon_path: None,
            session_grouping_param: [0_u8; 16],
            session_notification_object: 0,
            session_ducking_opt_out: false,
            capture_frames_carry: 0,
            capture_consumed_frames: 0,
            capture_outstanding_frames: 0,
            capture_packet_position: 0,
            capture_packet_qpc: 0,
            capture_queue: VecDeque::new(),
            loopback_cursor: 0,
            capture_input_active: false,
            clock_epoch: Instant::now(),
        });
}

/// Drop every audio-client/service state bound to `object` (called when the
/// runtime releases the guest object).  When the released endpoint was the
/// last audio client using a real stream, the backend stream is closed.
pub(crate) fn release_audio_object(pid: u32, object: u64) {
    let (removed, close_device, stop_capture) = {
        let mut registry = audio_clients();
        let removed = registry
            .clients
            .get_mut(&pid)
            .and_then(|clients| clients.remove(&object));
        if removed.is_some() {
            // Cached service objects of the endpoint lose their binding too.
            if let Some(services) = registry.services.get_mut(&pid) {
                services.retain(|_, (endpoint, _)| *endpoint != object);
            }
        } else if let Some(services) = registry.services.get_mut(&pid) {
            services.remove(&object);
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
        let stop_capture = removed
            .as_ref()
            .is_some_and(|state| state.capture_input_active)
            && !registry
                .clients
                .values()
                .flat_map(|clients| clients.values())
                .any(|state| state.capture_input_active);
        if registry
            .services
            .get(&pid)
            .is_some_and(|services| services.is_empty())
        {
            registry.services.remove(&pid);
        }
        if registry
            .clients
            .get(&pid)
            .is_some_and(|clients| clients.is_empty())
        {
            registry.clients.remove(&pid);
        }
        (removed, close_device, stop_capture)
    };
    if let Some(state) = removed.as_ref()
        && state.running
        && state.direction == AudioDirection::Render
        && !state.loopback
    {
        mark_render_stream_stopped(pid, &state.device.key);
    }
    release_activation_operation(pid, object);
    if let Some(device_id) = close_device {
        let mut guard = audio_client_backend();
        if let Some(backend) = guard.as_mut() {
            backend.close_stream(device_id);
        }
    }
    if stop_capture {
        let mut guard = audio_client_backend();
        if let Some(backend) = guard.as_mut() {
            backend.stop_input_stream();
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

/// The current stream direction of an endpoint (a loopback render endpoint
/// reports `Capture` after its loopback `Initialize`).
pub(crate) fn client_direction(pid: u32, object: u64) -> Option<AudioDirection> {
    audio_clients()
        .clients
        .get(&pid)
        .and_then(|clients| clients.get(&object))
        .map(|state| state.direction)
}

/// Whether a service kind is valid for an endpoint's direction.
pub(crate) fn service_supported_for_direction(
    direction: AudioDirection,
    kind: AudioServiceKind,
) -> bool {
    kind.supports_direction(direction)
}

/// Whether an activated device came from a capture interface path (the real
/// input-device snapshot marks those keys with a `|capture` suffix).
pub(crate) fn device_is_capture(device: &RealAudioDevice) -> bool {
    device.key.ends_with("|capture")
}

/// Observable snapshot of one bound audio client (tests).
#[cfg(test)]
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct AudioClientTestSnapshot {
    pub initialized: bool,
    pub running: bool,
    pub direction: AudioDirection,
    pub share_mode: u32,
    pub buffer_frames: u32,
    pub buffer_address: u64,
    pub submitted_frames: u64,
    pub drained_frames_carry: u64,
    pub event_handle: u64,
    pub real_device_id: Option<crate::audio::DeviceId>,
    pub exclusive_client_id: Option<crate::audio::AudioClientId>,
    pub session_volume: f32,
    pub session_muted: bool,
    pub channel_volumes: Vec<f32>,
    pub session_display_name: Option<String>,
    pub session_notification_object: u64,
    pub capture_consumed_frames: u64,
    pub capture_frames_carry: u64,
    pub capture_outstanding_frames: u32,
    pub capture_input_active: bool,
    pub loopback: bool,
    pub loopback_cursor: u64,
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
            direction: state.direction,
            share_mode: state.share_mode,
            buffer_frames: state.buffer_frames,
            buffer_address: state.buffer_address,
            submitted_frames: state.submitted_frames,
            drained_frames_carry: state.drained_frames_carry,
            event_handle: state.event_handle,
            real_device_id: state.real_device_id,
            exclusive_client_id: state.exclusive_client_id,
            session_volume: state.session_volume,
            session_muted: state.session_muted,
            channel_volumes: state.channel_volumes.clone(),
            session_display_name: state.session_display_name.clone(),
            session_notification_object: state.session_notification_object,
            capture_consumed_frames: state.capture_consumed_frames,
            capture_frames_carry: state.capture_frames_carry,
            capture_outstanding_frames: state.capture_outstanding_frames,
            capture_input_active: state.capture_input_active,
            loopback: state.loopback,
            loopback_cursor: state.loopback_cursor,
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
    let loopback = stream_flags & AUDCLNT_STREAMFLAGS_LOOPBACK != 0;
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
    if loopback {
        // Loopback is a capture mode on a RENDER endpoint.  Requesting it on
        // a true capture endpoint is the documented wrong-endpoint error; the
        // exclusive engine has no loopback path (loopback is shared-mode).
        if state.direction == AudioDirection::Capture {
            return Err(AUDCLNT_E_WRONG_ENDPOINT_TYPE);
        }
        if share_mode == AUDCLNT_SHAREMODE_EXCLUSIVE {
            return Err(AUDCLNT_E_INVALID_STREAM_FLAG);
        }
    }
    let duration_hns = duration_hns as u64;
    let periodicity_hns = periodicity_hns as u64;
    let rate = format.sample_rate.max(1);
    // The real engine caps a client buffer at two seconds of audio.
    let max_frames = (rate as u64).saturating_mul(2).max(1);
    if share_mode == AUDCLNT_SHAREMODE_EXCLUSIVE {
        // Exclusive-mode constraints enforced client-side (the cpal exclusive
        // stream is opened only for an exact device-format match, see
        // `audio_format_support`):
        // - the buffer duration is mandatory and must be at least the real
        //   device minimum period (cpal's supported buffer-size minimum),
        // - a nonzero periodicity must also be at least that minimum and can
        //   never exceed the buffer itself,
        // - the engine's two-second maximum buffer applies.
        if duration_hns == 0 {
            return Err(AUDCLNT_E_INVALIDARG);
        }
        let minimum_period = state.minimum_period_hns.max(1);
        if duration_hns < minimum_period {
            return Err(AUDCLNT_E_BUFFER_SIZE_ERROR);
        }
        if hns_to_frames(duration_hns, rate) > max_frames {
            return Err(AUDCLNT_E_BUFFER_TOO_LARGE);
        }
        if periodicity_hns != 0 {
            if periodicity_hns < minimum_period || periodicity_hns > duration_hns {
                return Err(AUDCLNT_E_INVALID_DEVICE_PERIOD);
            }
        }
    } else if periodicity_hns != 0 {
        // Shared mode does not take a periodicity.
        return Err(AUDCLNT_E_INVALIDARG);
    }
    let support = audio_format_support(&state.device, format, share_mode);
    if support != AUDCLNT_S_OK && support != AUDCLNT_S_FALSE {
        return Err(support);
    }
    let requested_frames = if duration_hns == 0 {
        hns_to_frames(state.default_period_hns, rate).max(1)
    } else {
        hns_to_frames(duration_hns, rate).max(1)
    };
    let buffer_frames = requested_frames.min(max_frames).max(1) as u32;
    Ok(AudioInitializePlan {
        buffer_frames,
        block_align: format.block_align.max(1),
        event_driven: stream_flags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK != 0,
        share_mode,
        stream_flags,
        loopback,
        duration_hns,
        periodicity_hns,
    })
}

/// Store a successful `Initialize` and open the real host stream for the
/// bound device and direction (best effort: headless hosts keep the real
/// paced queue).
///
/// Render clients open the real shared or exclusive output stream the share
/// mode selects; capture clients start the real host input stream (the paced
/// capture queue backs hosts where the input cannot open).
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
    state.loopback = plan.loopback;
    if plan.loopback {
        // A loopback stream captures the render endpoint's played frames.
        state.direction = AudioDirection::Capture;
    }
    state.format = Some(format.clone());
    state.channel_volumes = vec![1.0; format.channels.max(1) as usize];
    state.buffer_frames = plan.buffer_frames;
    state.buffer_address = buffer_address;
    state.buffer_bytes = buffer_bytes;
    state.buffer_outstanding_frames = 0;
    state.submitted_frames = 0;
    state.drained_frames_carry = 0;
    state.capture_frames_carry = 0;
    state.capture_consumed_frames = 0;
    state.capture_outstanding_frames = 0;
    state.capture_packet_position = 0;
    state.capture_packet_qpc = 0;
    state.capture_queue.clear();
    state.capture_input_active = false;
    state.loopback_cursor = if plan.loopback {
        loopback_start_cursor(pid, &state.device.key)
    } else {
        0
    };
    state.run_started = None;
    state.running = false;
    state.event_ready_signaled = false;
    state.exclusive_client_id = None;
    state.clock_epoch = Instant::now();
    let device_rate = state.device.sample_rate.max(1);
    state.stream_latency_hns = frames_to_hns(plan.buffer_frames as u64, device_rate).max(1);
    match state.direction {
        AudioDirection::Render => {
            if plan.share_mode == AUDCLNT_SHAREMODE_EXCLUSIVE {
                if let Some((device_id, client_id, latency_ms)) =
                    open_real_exclusive_render_stream(&state.device, format)
                {
                    state.real_device_id = Some(device_id);
                    state.exclusive_client_id = Some(client_id);
                    if let Some(latency_ms) = latency_ms {
                        state.stream_latency_hns =
                            (latency_ms as u64).saturating_mul(10_000).max(1);
                    }
                }
            } else if let Some((device_id, latency_ms)) = open_real_render_stream(
                &state.device,
                format,
                plan.buffer_frames,
                plan.event_driven,
            ) {
                state.real_device_id = Some(device_id);
                if let Some(latency_ms) = latency_ms {
                    state.stream_latency_hns = (latency_ms as u64).saturating_mul(10_000).max(1);
                }
            }
        }
        AudioDirection::Capture => {
            if plan.loopback {
                // Loopback does not open the host microphone: its source is
                // the real render history of the bound render device.
                state.capture_input_active = false;
            } else {
                state.capture_input_active = open_real_capture_stream(format);
            }
        }
    }
    AUDCLNT_S_OK
}

/// The real `WaveFormat` of an initialized client format.
fn client_wave_format(format: &AudioClientFormat) -> WaveFormat {
    WaveFormat {
        channels: format.channels,
        sample_rate: format.sample_rate,
        sample_format: if format.is_float() {
            SampleFormat::Float32
        } else {
            SampleFormat::Pcm16
        },
    }
}

/// The real backend device id matching a bound device snapshot.
fn real_backend_device_id(
    backend: &RealAudioBackend,
    device: &RealAudioDevice,
) -> Option<crate::audio::DeviceId> {
    backend
        .activation_device_snapshot()
        .into_iter()
        .find(|candidate| candidate.key == device.key)
        .map(|candidate| candidate.id)
}

/// Open the real cpal output stream for the bound device (shared-mode path).
fn open_real_render_stream(
    device: &RealAudioDevice,
    format: &AudioClientFormat,
    buffer_frames: u32,
    event_driven: bool,
) -> Option<(crate::audio::DeviceId, Option<u32>)> {
    let wave_format = client_wave_format(format);
    let mut guard = audio_client_backend();
    let backend = ensure_audio_client_backend(&mut guard)?;
    let device_id = real_backend_device_id(backend, device)?;
    backend
        .open_wasapi_client(&wave_format, buffer_frames as usize, event_driven)
        .ok()?;
    let latency_ms = backend.last_latency_ms(device_id);
    Some((device_id, latency_ms))
}

/// Open the real exclusive-mode cpal output stream for the bound device
/// (the real `open_wasapi_client_exclusive` path: exact client format, no
/// resampling, smallest hardware buffer).
fn open_real_exclusive_render_stream(
    device: &RealAudioDevice,
    format: &AudioClientFormat,
) -> Option<(
    crate::audio::DeviceId,
    crate::audio::AudioClientId,
    Option<u32>,
)> {
    let wave_format = client_wave_format(format);
    let mut guard = audio_client_backend();
    let backend = ensure_audio_client_backend(&mut guard)?;
    let device_id = real_backend_device_id(backend, device)?;
    let client_id = backend
        .open_wasapi_client_exclusive(device_id, wave_format)
        .ok()?;
    let latency_ms = backend.last_latency_ms(device_id);
    Some((device_id, client_id, latency_ms))
}

/// Start the real host input stream for a capture client (best effort).
fn open_real_capture_stream(format: &AudioClientFormat) -> bool {
    let mut guard = audio_client_backend();
    let Some(backend) = ensure_audio_client_backend(&mut guard) else {
        return false;
    };
    match backend.start_input_stream(format.sample_rate, format.channels) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("[RealAudio] capture input stream unavailable: {error}");
            false
        }
    }
}

/// Push render frames into the real cpal output stream of `device_id` (a
/// no-op when the stream was never opened).
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

/// Record released render frames in the loopback history of the endpoint's
/// device.  This is independent of whether the host output stream opened:
/// the frames are the client-side render queue either way, and a loopback
/// capture client on the same device reads these exact samples back.
pub(crate) fn push_loopback_render_samples(
    pid: u32,
    device_key: &str,
    samples: &[f32],
    channels: u16,
    sample_rate: u32,
) {
    loopback_push_frames(pid, device_key, samples, channels, sample_rate);
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

/// `GetCurrentPadding` — the real client-side padding: frames committed but
/// not yet drained by the playback clock on render streams; frames available
/// to read on capture streams.
pub(crate) fn get_current_padding(pid: u32, object: u64) -> Result<u32, u32> {
    with_client_state(pid, object, "GetCurrentPadding", |state| {
        if !state.initialized {
            return Err(AUDCLNT_E_NOT_INITIALIZED);
        }
        let now = Instant::now();
        Ok(match state.direction {
            AudioDirection::Render => state.padding_frames(now),
            AudioDirection::Capture => state.capture_next_packet_frames(pid, now),
        })
    })
}

/// `Start` — start the real stream clock.
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
        if state.direction == AudioDirection::Render && !state.loopback {
            mark_render_stream_started(pid, &state.device.key);
        }
        notify_session_state(pid, state);
        Ok(AUDCLNT_S_OK)
    });
    match result {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `Stop` — freeze the stream clock (remaining padding stays buffered;
/// captured frames already produced stay readable).
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
        state.capture_frames_carry = state.capture_arrived_frames(now);
        if state.direction == AudioDirection::Render && !state.loopback {
            mark_render_stream_stopped(pid, &state.device.key);
        }
        state.run_started = None;
        state.running = false;
        state.event_ready_signaled = false;
        notify_session_state(pid, state);
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
        state.capture_frames_carry = 0;
        state.capture_consumed_frames = 0;
        state.capture_outstanding_frames = 0;
        state.capture_packet_position = 0;
        state.capture_packet_qpc = 0;
        state.capture_queue.clear();
        if state.loopback {
            // Reset discards the loopback packets buffered for this client;
            // the render history shared with other clients is untouched.
            state.loopback_cursor = loopback_reset_cursor(pid, &state.device.key);
        }
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

/// The event handle to signal right now, if the stream is ready and the ready
/// signal has not already been raised.  Transition-based so auto-reset events
/// are not consumed before the guest observes them.
///
/// Render streams are ready when the buffer has free space; capture streams
/// are ready when a packet is available to read.
pub(crate) fn take_ready_event(pid: u32, endpoint: u64) -> Option<u64> {
    let mut registry = audio_clients();
    let state = registry.clients.get_mut(&pid)?.get_mut(&endpoint)?;
    if !state.running || state.event_handle == 0 {
        return None;
    }
    let now = Instant::now();
    let ready = match state.direction {
        AudioDirection::Render => state.padding_frames(now) < state.buffer_frames,
        AudioDirection::Capture => state.capture_next_packet_frames(pid, now) > 0,
    };
    if ready {
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
/// tick: a running client whose buffer is ready raises its event so a
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
        let ready = match state.direction {
            AudioDirection::Render => state.padding_frames(now) < state.buffer_frames,
            AudioDirection::Capture => state.capture_next_packet_frames(pid, now) > 0,
        };
        if ready {
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

/// Bind a real service object to its endpoint and service kind.
pub(crate) fn bind_service(pid: u32, endpoint: u64, service_object: u64, kind: AudioServiceKind) {
    let mut registry = audio_clients();
    if let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&endpoint))
    {
        match kind {
            AudioServiceKind::RenderClient => state.render_service_object = service_object,
            AudioServiceKind::Clock => state.clock_service_object = service_object,
            AudioServiceKind::SimpleVolume => state.simple_volume_service_object = service_object,
            AudioServiceKind::StreamVolume => state.stream_volume_service_object = service_object,
            AudioServiceKind::SessionControl => state.session_service_object = service_object,
            AudioServiceKind::CaptureClient => state.capture_service_object = service_object,
        }
    }
    registry
        .services
        .entry(pid)
        .or_default()
        .insert(service_object, (endpoint, kind));
}

/// Bind an `IAudioRenderClient` service object to its endpoint (test helper;
/// production code binds through [`bind_service`]).
#[cfg(test)]
pub(crate) fn bind_render_service(pid: u32, endpoint: u64, service_object: u64) {
    bind_service(
        pid,
        endpoint,
        service_object,
        AudioServiceKind::RenderClient,
    );
}

/// The cached service object of an endpoint for `kind`, if any.
pub(crate) fn service_for(pid: u32, endpoint: u64, kind: AudioServiceKind) -> Option<u64> {
    audio_clients()
        .clients
        .get(&pid)
        .and_then(|clients| clients.get(&endpoint))
        .map(|state| match kind {
            AudioServiceKind::RenderClient => state.render_service_object,
            AudioServiceKind::Clock => state.clock_service_object,
            AudioServiceKind::SimpleVolume => state.simple_volume_service_object,
            AudioServiceKind::StreamVolume => state.stream_volume_service_object,
            AudioServiceKind::SessionControl => state.session_service_object,
            AudioServiceKind::CaptureClient => state.capture_service_object,
        })
        .filter(|object| *object != 0)
}

/// The service kind of a bound service object (for generic `QueryInterface`).
pub(crate) fn service_kind(pid: u32, service: u64) -> Option<AudioServiceKind> {
    audio_clients()
        .services
        .get(&pid)
        .and_then(|services| services.get(&service))
        .map(|(_, kind)| *kind)
}

/// The endpoint a service object of `kind` belongs to.
fn service_endpoint(
    registry: &AudioClientRegistry,
    pid: u32,
    service: u64,
    kind: AudioServiceKind,
) -> Option<u64> {
    registry
        .services
        .get(&pid)
        .and_then(|services| services.get(&service))
        .filter(|(_, bound_kind)| *bound_kind == kind)
        .map(|(endpoint, _)| *endpoint)
}

/// Run `body` against the audio-client state behind a bound service object.
fn with_service_state<T>(
    pid: u32,
    service: u64,
    kind: AudioServiceKind,
    message: &str,
    body: impl FnOnce(&mut AudioClientState) -> Result<T, u32>,
) -> Result<T, u32> {
    let mut registry = audio_clients();
    let endpoint =
        service_endpoint(&registry, pid, service, kind).ok_or(AUDCLNT_E_DEVICE_INVALIDATED)?;
    let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&endpoint))
    else {
        eprintln!("[RealAudio] {message}: service {service:#x} has no endpoint state");
        return Err(AUDCLNT_E_DEVICE_INVALIDATED);
    };
    body(state)
}

// ---------------------------------------------------------------------------
// Session notifications — the real IAudioSessionEvents callbacks
// ---------------------------------------------------------------------------

/// One `IAudioSessionEvents` callback raised by a real session-state change.
#[derive(Debug, Clone, PartialEq)]
pub enum AudioSessionNotificationKind {
    /// `OnStateChanged` — the session became active/inactive.
    StateChanged { state: u32 },
    /// `OnDisplayNameChanged` (the new display name is a real guest string).
    DisplayNameChanged { name: String, event_context: u64 },
    /// `OnIconPathChanged`.
    IconPathChanged { path: String, event_context: u64 },
    /// `OnSimpleVolumeChanged`.
    SimpleVolumeChanged {
        volume: f32,
        muted: bool,
        event_context: u64,
    },
    /// `OnChannelVolumeChanged`.
    ChannelVolumeChanged {
        volumes: Vec<f32>,
        changed_channel: u32,
        event_context: u64,
    },
    /// `OnGroupingParamChanged`.
    GroupingParamChanged { param: [u8; 16], event_context: u64 },
}

/// One queued session notification: the registered notification object plus
/// the callback data (the vtable slot is derived from the kind).
#[derive(Debug, Clone, PartialEq)]
pub struct AudioSessionNotification {
    /// The registered `IAudioSessionEvents` object.
    pub object: u64,
    /// The callback data.
    pub kind: AudioSessionNotificationKind,
}

/// A fully resolved session callback: object, method entry point and
/// arguments, ready to invoke from the runtime servicing point.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingAudioNotification {
    /// The notification object.
    pub object: u64,
    /// The resolved method entry point.
    pub method: u64,
    /// The invocation arguments (the object `this` is passed separately).
    pub args: Vec<u64>,
}

static SESSION_NOTIFICATION_OUTBOX: LazyLock<
    Mutex<HashMap<u32, VecDeque<AudioSessionNotification>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

static PENDING_AUDIO_NOTIFICATIONS: LazyLock<
    Mutex<HashMap<u32, VecDeque<PendingAudioNotification>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn session_notification_locks()
-> MutexGuard<'static, HashMap<u32, VecDeque<AudioSessionNotification>>> {
    SESSION_NOTIFICATION_OUTBOX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn pending_notification_locks()
-> MutexGuard<'static, HashMap<u32, VecDeque<PendingAudioNotification>>> {
    PENDING_AUDIO_NOTIFICATIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn queue_session_notification(pid: u32, notification: AudioSessionNotification) {
    session_notification_locks()
        .entry(pid)
        .or_default()
        .push_back(notification);
}

/// Notify the registered session object of a simple-volume change.
fn notify_simple_volume(pid: u32, state: &AudioClientState, event_context: u64) {
    if state.session_notification_object == 0 {
        return;
    }
    queue_session_notification(
        pid,
        AudioSessionNotification {
            object: state.session_notification_object,
            kind: AudioSessionNotificationKind::SimpleVolumeChanged {
                volume: state.session_volume,
                muted: state.session_muted,
                event_context,
            },
        },
    );
}

/// Notify the registered session object of a channel-volume change.
fn notify_channel_volume(
    pid: u32,
    state: &AudioClientState,
    changed_channel: u32,
    event_context: u64,
) {
    if state.session_notification_object == 0 {
        return;
    }
    queue_session_notification(
        pid,
        AudioSessionNotification {
            object: state.session_notification_object,
            kind: AudioSessionNotificationKind::ChannelVolumeChanged {
                volumes: state.channel_volumes.clone(),
                changed_channel,
                event_context,
            },
        },
    );
}

/// Notify the registered session object of a state change.
fn notify_session_state(pid: u32, state: &AudioClientState) {
    if state.session_notification_object == 0 {
        return;
    }
    queue_session_notification(
        pid,
        AudioSessionNotification {
            object: state.session_notification_object,
            kind: AudioSessionNotificationKind::StateChanged {
                state: state.session_state(),
            },
        },
    );
}

/// Drain the pending session-notification descriptors of `pid` (the runtime
/// resolves the vtable method and queues the invocation).
pub(crate) fn take_session_notifications(pid: u32) -> Vec<AudioSessionNotification> {
    let mut outbox = session_notification_locks();
    let Some(queue) = outbox.get_mut(&pid) else {
        return Vec::new();
    };
    let notifications = queue.drain(..).collect();
    outbox.remove(&pid);
    notifications
}

/// Queue a fully resolved session callback for the runtime servicing point.
pub(crate) fn push_audio_notification(pid: u32, notification: PendingAudioNotification) {
    pending_notification_locks()
        .entry(pid)
        .or_default()
        .push_back(notification);
}

/// Pop the oldest resolved session callback of `pid`.
pub(crate) fn pop_audio_notification(pid: u32) -> Option<PendingAudioNotification> {
    let mut pending = pending_notification_locks();
    let queue = pending.get_mut(&pid)?;
    let notification = queue.pop_front();
    if queue.is_empty() {
        pending.remove(&pid);
    }
    notification
}

// ---------------------------------------------------------------------------
// IAudioClock — real stream clock
// ---------------------------------------------------------------------------

/// `IAudioClock::GetFrequency` — the initialized stream frequency.
pub(crate) fn clock_frequency(pid: u32, service: u64) -> Result<u32, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::Clock,
        "GetFrequency",
        |state| {
            if !state.initialized {
                return Err(AUDCLNT_E_NOT_INITIALIZED);
            }
            Ok(state.clock_frequency())
        },
    )
}

/// `IAudioClock::GetPosition` — `(frame_position, qpc_position)` in the
/// clock's own units (frames and 100 ns), driven by the same clock that backs
/// `GetCurrentPadding`.
pub(crate) fn clock_position(pid: u32, service: u64) -> Result<(u64, u64), u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::Clock,
        "GetPosition",
        |state| {
            if !state.initialized {
                return Err(AUDCLNT_E_NOT_INITIALIZED);
            }
            Ok(state.clock_position(Instant::now()))
        },
    )
}

/// `IAudioClock::GetState` — the real stream state.
pub(crate) fn clock_state(pid: u32, service: u64) -> Result<u32, u32> {
    with_service_state(pid, service, AudioServiceKind::Clock, "GetState", |state| {
        if !state.initialized {
            return Err(AUDCLNT_E_NOT_INITIALIZED);
        }
        Ok(if state.running {
            AUDCLNT_STREAMSTATE_RUNNING
        } else {
            AUDCLNT_STREAMSTATE_STOPPED
        })
    })
}

// ---------------------------------------------------------------------------
// ISimpleAudioVolume — real session master volume and mute
// ---------------------------------------------------------------------------

/// `ISimpleAudioVolume::SetMasterVolume(level, eventContext)`.
pub(crate) fn set_master_volume(pid: u32, service: u64, level: f32, event_context: u64) -> u32 {
    if !level.is_finite() || !(0.0..=1.0).contains(&level) {
        return AUDCLNT_E_INVALIDARG;
    }
    match with_service_state(
        pid,
        service,
        AudioServiceKind::SimpleVolume,
        "SetMasterVolume",
        |state| {
            state.session_volume = level;
            notify_simple_volume(pid, state, event_context);
            Ok(AUDCLNT_S_OK)
        },
    ) {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `ISimpleAudioVolume::GetMasterVolume(pfLevel)`.
pub(crate) fn get_master_volume(pid: u32, service: u64) -> Result<f32, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::SimpleVolume,
        "GetMasterVolume",
        |state| Ok(state.session_volume),
    )
}

/// `ISimpleAudioVolume::SetMute(bMute, eventContext)`.
pub(crate) fn set_mute(pid: u32, service: u64, muted: bool, event_context: u64) -> u32 {
    match with_service_state(
        pid,
        service,
        AudioServiceKind::SimpleVolume,
        "SetMute",
        |state| {
            state.session_muted = muted;
            notify_simple_volume(pid, state, event_context);
            Ok(AUDCLNT_S_OK)
        },
    ) {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `ISimpleAudioVolume::GetMute(pbMute)`.
pub(crate) fn get_mute(pid: u32, service: u64) -> Result<bool, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::SimpleVolume,
        "GetMute",
        |state| Ok(state.session_muted),
    )
}

// ---------------------------------------------------------------------------
// IAudioStreamVolume — real per-channel stream volumes
// ---------------------------------------------------------------------------

/// The initialized channel count of the endpoint behind a service object.
fn service_channel_count(state: &AudioClientState) -> Result<u32, u32> {
    if !state.initialized {
        return Err(AUDCLNT_E_NOT_INITIALIZED);
    }
    Ok(state
        .format
        .as_ref()
        .map(|format| format.channels)
        .unwrap_or(state.device.channels)
        .max(1) as u32)
}

/// `IAudioStreamVolume::GetChannelCount(pu32Count)`.
pub(crate) fn stream_volume_channel_count(pid: u32, service: u64) -> Result<u32, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::StreamVolume,
        "GetChannelCount",
        |state| service_channel_count(state),
    )
}

/// `IAudioStreamVolume::SetChannelVolume(dwIndex, fLevel, EventContext)`.
pub(crate) fn set_channel_volume(
    pid: u32,
    service: u64,
    index: u32,
    level: f32,
    event_context: u64,
) -> u32 {
    if !level.is_finite() || !(0.0..=1.0).contains(&level) {
        return AUDCLNT_E_INVALIDARG;
    }
    match with_service_state(
        pid,
        service,
        AudioServiceKind::StreamVolume,
        "SetChannelVolume",
        |state| {
            let channels = service_channel_count(state)?;
            if index >= channels {
                return Err(AUDCLNT_E_INVALIDARG);
            }
            if state.channel_volumes.len() < channels as usize {
                state.channel_volumes.resize(channels as usize, 1.0);
            }
            state.channel_volumes[index as usize] = level;
            notify_channel_volume(pid, state, index, event_context);
            Ok(AUDCLNT_S_OK)
        },
    ) {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `IAudioStreamVolume::GetChannelVolume(dwIndex, pfLevel)`.
pub(crate) fn get_channel_volume(pid: u32, service: u64, index: u32) -> Result<f32, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::StreamVolume,
        "GetChannelVolume",
        |state| {
            let channels = service_channel_count(state)?;
            if index >= channels {
                return Err(AUDCLNT_E_INVALIDARG);
            }
            Ok(state
                .channel_volumes
                .get(index as usize)
                .copied()
                .unwrap_or(1.0))
        },
    )
}

/// `IAudioStreamVolume::SetAllVolumes(dwCount, pfVolumes, EventContext)`.
pub(crate) fn set_all_volumes(
    pid: u32,
    service: u64,
    volumes: Vec<f32>,
    event_context: u64,
) -> u32 {
    if volumes
        .iter()
        .any(|level| !level.is_finite() || !(0.0..=1.0).contains(level))
    {
        return AUDCLNT_E_INVALIDARG;
    }
    match with_service_state(
        pid,
        service,
        AudioServiceKind::StreamVolume,
        "SetAllVolumes",
        |state| {
            let channels = service_channel_count(state)? as usize;
            if volumes.len() != channels {
                return Err(AUDCLNT_E_INVALIDARG);
            }
            state.channel_volumes = volumes;
            notify_channel_volume(pid, state, u32::MAX, event_context);
            Ok(AUDCLNT_S_OK)
        },
    ) {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `IAudioStreamVolume::GetAllVolumes(dwCount, pfVolumes)`.
pub(crate) fn get_all_volumes(pid: u32, service: u64) -> Result<Vec<f32>, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::StreamVolume,
        "GetAllVolumes",
        |state| {
            let channels = service_channel_count(state)? as usize;
            let mut volumes = state.channel_volumes.clone();
            volumes.resize(channels, 1.0);
            Ok(volumes)
        },
    )
}

// ---------------------------------------------------------------------------
// IAudioSessionControl / IAudioSessionControl2 — real session state
// ---------------------------------------------------------------------------

/// `IAudioSessionControl::GetState(pRetVal)`.
pub(crate) fn session_state(pid: u32, service: u64) -> Result<u32, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "GetState",
        |state| Ok(state.session_state()),
    )
}

/// `IAudioSessionControl::SetDisplayName(Value, EventContext)`.
pub(crate) fn set_display_name(
    pid: u32,
    service: u64,
    name: Option<String>,
    event_context: u64,
) -> u32 {
    match with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "SetDisplayName",
        |state| {
            state.session_display_name = name.clone();
            if state.session_notification_object != 0 {
                let effective = name.clone().unwrap_or_else(|| state.device.name.clone());
                let notification = AudioSessionNotification {
                    object: state.session_notification_object,
                    kind: AudioSessionNotificationKind::DisplayNameChanged {
                        name: effective,
                        event_context,
                    },
                };
                queue_session_notification(pid, notification);
            }
            Ok(AUDCLNT_S_OK)
        },
    ) {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `IAudioSessionControl::GetDisplayName(pRetVal)` — the stored name, or the
/// device's real name when the guest left the default.
pub(crate) fn get_display_name(pid: u32, service: u64) -> Result<String, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "GetDisplayName",
        |state| {
            Ok(state
                .session_display_name
                .clone()
                .unwrap_or_else(|| state.device.name.clone()))
        },
    )
}

/// `IAudioSessionControl::SetIconPath(Value, EventContext)`.
pub(crate) fn set_icon_path(
    pid: u32,
    service: u64,
    path: Option<String>,
    event_context: u64,
) -> u32 {
    match with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "SetIconPath",
        |state| {
            state.session_icon_path = path.clone();
            if let Some(path) = path
                && state.session_notification_object != 0
            {
                queue_session_notification(
                    pid,
                    AudioSessionNotification {
                        object: state.session_notification_object,
                        kind: AudioSessionNotificationKind::IconPathChanged {
                            path,
                            event_context,
                        },
                    },
                );
            }
            Ok(AUDCLNT_S_OK)
        },
    ) {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `IAudioSessionControl::GetIconPath(pRetVal)`.
pub(crate) fn get_icon_path(pid: u32, service: u64) -> Result<Option<String>, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "GetIconPath",
        |state| Ok(state.session_icon_path.clone()),
    )
}

/// `IAudioSessionControl::SetGroupingParam(Override, EventContext)`.
pub(crate) fn set_grouping_param(
    pid: u32,
    service: u64,
    param: Option<[u8; 16]>,
    event_context: u64,
) -> u32 {
    match with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "SetGroupingParam",
        |state| {
            state.session_grouping_param = param.unwrap_or([0_u8; 16]);
            if state.session_notification_object != 0 {
                queue_session_notification(
                    pid,
                    AudioSessionNotification {
                        object: state.session_notification_object,
                        kind: AudioSessionNotificationKind::GroupingParamChanged {
                            param: state.session_grouping_param,
                            event_context,
                        },
                    },
                );
            }
            Ok(AUDCLNT_S_OK)
        },
    ) {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `IAudioSessionControl::GetGroupingParam(pRetVal)`.
pub(crate) fn get_grouping_param(pid: u32, service: u64) -> Result<[u8; 16], u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "GetGroupingParam",
        |state| Ok(state.session_grouping_param),
    )
}

/// `IAudioSessionControl::RegisterAudioSessionNotification(NewNotifications)`.
pub(crate) fn register_session_notification(pid: u32, service: u64, object: u64) -> u32 {
    if object == 0 {
        return AUDCLNT_E_INVALIDARG;
    }
    match with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "RegisterAudioSessionNotification",
        |state| {
            if state.session_notification_object == object {
                return Ok(AUDCLNT_S_THREAD_ALREADY_REGISTERED);
            }
            state.session_notification_object = object;
            Ok(AUDCLNT_S_OK)
        },
    ) {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `IAudioSessionControl::UnregisterAudioSessionNotification(PrevNotifications)`.
pub(crate) fn unregister_session_notification(pid: u32, service: u64, object: u64) -> u32 {
    match with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "UnregisterAudioSessionNotification",
        |state| {
            if object == 0 || state.session_notification_object == object {
                state.session_notification_object = 0;
            }
            Ok(AUDCLNT_S_OK)
        },
    ) {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

/// `IAudioSessionControl2::GetSessionIdentifier(pRetVal)`.
pub(crate) fn session_identifier(pid: u32, service: u64) -> Result<String, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "GetSessionIdentifier",
        |state| Ok(format!("{}.{}", state.device.key, state.session_serial)),
    )
}

/// `IAudioSessionControl2::GetSessionInstanceIdentifier(pRetVal)`.
pub(crate) fn session_instance_identifier(pid: u32, service: u64) -> Result<String, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "GetSessionInstanceIdentifier",
        |state| {
            Ok(format!(
                "{}.{}.instance",
                state.device.key, state.session_serial
            ))
        },
    )
}

/// `IAudioSessionControl2::GetProcessId(pRetVal)` — the guest process that
/// owns the runtime.
pub(crate) fn session_process_id(pid: u32, service: u64) -> Result<u32, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "GetProcessId",
        |state| {
            let _ = state;
            Ok(pid)
        },
    )
}

/// `IAudioSessionControl2::IsSystemSoundsSession()` — app sessions are not
/// the system-sounds session.
pub(crate) fn is_system_sounds_session(pid: u32, service: u64) -> Result<bool, u32> {
    with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "IsSystemSoundsSession",
        |state| {
            let _ = state;
            Ok(false)
        },
    )
}

/// `IAudioSessionControl2::SetDuckingPreference(optOut)`.
pub(crate) fn set_ducking_preference(pid: u32, service: u64, opt_out: bool) -> u32 {
    match with_service_state(
        pid,
        service,
        AudioServiceKind::SessionControl,
        "SetDuckingPreference",
        |state| {
            state.session_ducking_opt_out = opt_out;
            Ok(AUDCLNT_S_OK)
        },
    ) {
        Ok(hr) => hr,
        Err(hr) => hr,
    }
}

// ---------------------------------------------------------------------------
// IAudioRenderClient / IAudioCaptureClient — real buffer hand-out
// ---------------------------------------------------------------------------

/// `IAudioRenderClient::GetBuffer` — hand out the real guest render buffer.
pub(crate) fn render_get_buffer(
    pid: u32,
    service_object: u64,
    frames_requested: u32,
) -> Result<(u64, u32), u32> {
    let mut registry = audio_clients();
    let endpoint = service_endpoint(
        &registry,
        pid,
        service_object,
        AudioServiceKind::RenderClient,
    )
    .ok_or(AUDCLNT_E_DEVICE_INVALIDATED)?;
    let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&endpoint))
    else {
        return Err(AUDCLNT_E_DEVICE_INVALIDATED);
    };
    if state.direction != AudioDirection::Render {
        return Err(AUDCLNT_E_WRONG_ENDPOINT_TYPE);
    }
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
    /// The real exclusive-mode client id (when an exclusive stream opened).
    pub exclusive_client_id: Option<crate::audio::AudioClientId>,
    /// The per-channel session/stream gains applied where released frames
    /// enter the host output.
    pub channel_gains: Vec<f32>,
}

/// `IAudioRenderClient::ReleaseBuffer` — reclaim the buffer, commit the
/// written frames into the real playback clock and report the real session
/// gains to apply before the frames reach the host output.
pub(crate) fn render_release_buffer(
    pid: u32,
    service_object: u64,
    frames_written: u32,
    flags: u32,
) -> Result<RenderRelease, u32> {
    let mut registry = audio_clients();
    let endpoint = service_endpoint(
        &registry,
        pid,
        service_object,
        AudioServiceKind::RenderClient,
    )
    .ok_or(AUDCLNT_E_DEVICE_INVALIDATED)?;
    let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&endpoint))
    else {
        return Err(AUDCLNT_E_DEVICE_INVALIDATED);
    };
    if state.direction != AudioDirection::Render {
        return Err(AUDCLNT_E_WRONG_ENDPOINT_TYPE);
    }
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
        exclusive_client_id: state.exclusive_client_id,
        channel_gains: state.output_gains(),
    })
}

/// One real capture packet handed to the guest through
/// `IAudioCaptureClient::GetBuffer`.
#[derive(Debug, Clone, PartialEq)]
pub struct CapturePacket {
    /// The endpoint the packet belongs to.
    pub endpoint: u64,
    /// Guest address of the packet data.
    pub buffer_address: u64,
    /// Frames in the packet.
    pub frames: u32,
    /// Client channel count.
    pub channels: u16,
    /// Effective sample format tag.
    pub wave_format_tag: u16,
    /// Container bit depth.
    pub bits_per_sample: u16,
    /// Block alignment in bytes.
    pub block_align: u16,
    /// `AUDCLNT_BUFFERFLAGS_*` for the packet.
    pub flags: u32,
    /// Device position of the packet's first frame.
    pub device_position: u64,
    /// QPC position of the packet (100 ns units).
    pub qpc_position: u64,
    /// The interleaved f32 samples of the packet (real captured frames when
    /// the input delivered them, silence otherwise).
    pub samples: Vec<f32>,
}

impl CapturePacket {
    /// Serialize the packet samples in the client's initialized format (the
    /// bytes `IAudioCaptureClient::GetBuffer` hands to the guest).
    pub fn sample_bytes(&self) -> Vec<u8> {
        match self.wave_format_tag {
            WAVE_FORMAT_IEEE_FLOAT => {
                let mut bytes = Vec::with_capacity(self.samples.len() * 4);
                for sample in &self.samples {
                    bytes.extend_from_slice(&sample.to_le_bytes());
                }
                bytes
            }
            WAVE_FORMAT_PCM => match self.bits_per_sample {
                8 => self
                    .samples
                    .iter()
                    .map(|sample| ((sample.clamp(-1.0, 1.0) * 127.0).round() as i32 + 128) as u8)
                    .collect(),
                16 => {
                    let mut bytes = Vec::with_capacity(self.samples.len() * 2);
                    for sample in &self.samples {
                        let value = (sample.clamp(-1.0, 1.0) * i16::MAX as f32).round() as i16;
                        bytes.extend_from_slice(&value.to_le_bytes());
                    }
                    bytes
                }
                24 => {
                    let mut bytes = Vec::with_capacity(self.samples.len() * 3);
                    for sample in &self.samples {
                        let value = (sample.clamp(-1.0, 1.0) * 8_388_607.0).round() as i32;
                        let encoded = value.to_le_bytes();
                        bytes.extend_from_slice(&encoded[..3]);
                    }
                    bytes
                }
                32 => {
                    let mut bytes = Vec::with_capacity(self.samples.len() * 4);
                    for sample in &self.samples {
                        let value = (sample.clamp(-1.0, 1.0) * i32::MAX as f32).round() as i32;
                        bytes.extend_from_slice(&value.to_le_bytes());
                    }
                    bytes
                }
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }
}

/// `IAudioCaptureClient::GetBuffer` — fill and hand out the next real
/// captured packet.
pub(crate) fn capture_get_buffer(pid: u32, service_object: u64) -> Result<CapturePacket, u32> {
    let mut registry = audio_clients();
    let endpoint = service_endpoint(
        &registry,
        pid,
        service_object,
        AudioServiceKind::CaptureClient,
    )
    .ok_or(AUDCLNT_E_DEVICE_INVALIDATED)?;
    let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&endpoint))
    else {
        return Err(AUDCLNT_E_DEVICE_INVALIDATED);
    };
    if state.direction != AudioDirection::Capture {
        return Err(AUDCLNT_E_WRONG_ENDPOINT_TYPE);
    }
    if !state.initialized {
        return Err(AUDCLNT_E_NOT_INITIALIZED);
    }
    if !state.running {
        return Err(AUDCLNT_E_NOT_STARTED);
    }
    if state.capture_outstanding_frames != 0 {
        return Err(AUDCLNT_E_OUT_OF_ORDER);
    }
    // Pull whatever the real input callback delivered since the last packet.
    if state.capture_input_active && !state.loopback {
        let mut backend_guard = audio_client_backend();
        if let Some(backend) = backend_guard.as_mut() {
            let captured = backend.read_capture_data();
            if !captured.is_empty() {
                state.capture_queue.extend(captured);
                let cap = crate::real_audio::max_capture_samples(
                    state.clock_frequency(),
                    state
                        .format
                        .as_ref()
                        .map(|format| format.channels)
                        .unwrap_or(state.device.channels),
                );
                while state.capture_queue.len() > cap {
                    state.capture_queue.pop_front();
                }
            }
        }
    }
    let now = Instant::now();
    let frames = state.capture_next_packet_frames(pid, now);
    if frames == 0 {
        return Err(AUDCLNT_S_BUFFER_EMPTY);
    }
    let format = state
        .format
        .as_ref()
        .cloned()
        .ok_or(AUDCLNT_E_NOT_INITIALIZED)?;
    let channels = format.channels.max(1) as usize;
    let sample_count = frames as usize * channels;
    let (samples, real_frames) = if state.loopback {
        let mut cursor = state.loopback_cursor;
        let (samples, real_frames) = loopback_take_frames(
            pid,
            &state.device.key,
            &mut cursor,
            format.channels,
            format.sample_rate,
            frames,
        );
        state.loopback_cursor = cursor;
        (samples, real_frames as usize)
    } else {
        let mut samples = Vec::with_capacity(sample_count);
        let mut real_frames = 0_usize;
        while samples.len() < sample_count {
            match state.capture_queue.pop_front() {
                Some(sample) => {
                    if samples.len() % channels == 0 {
                        real_frames += 1;
                    }
                    samples.push(sample);
                }
                None => samples.push(0.0),
            }
        }
        (samples, real_frames)
    };
    let silent = real_frames == 0;
    state.capture_outstanding_frames = frames;
    state.capture_packet_position = state.capture_consumed_frames;
    let (_, qpc_position) = state.clock_position(now);
    state.capture_packet_qpc = qpc_position;
    Ok(CapturePacket {
        endpoint,
        buffer_address: state.buffer_address,
        frames,
        channels: format.channels,
        wave_format_tag: format.wave_format_tag,
        bits_per_sample: format.bits_per_sample,
        block_align: format.block_align,
        flags: if silent {
            AUDCLNT_BUFFERFLAGS_SILENT
        } else {
            0
        },
        device_position: state.capture_packet_position,
        qpc_position,
        samples,
    })
}

/// The real capture route information `ReleaseBuffer` needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureRelease {
    /// The endpoint the release belongs to.
    pub endpoint: u64,
    /// Frames released to the guest.
    pub frames: u32,
}

/// `IAudioCaptureClient::ReleaseBuffer` — consume the outstanding packet.
pub(crate) fn capture_release_buffer(
    pid: u32,
    service_object: u64,
    frames_released: u32,
    _flags: u32,
) -> Result<CaptureRelease, u32> {
    let mut registry = audio_clients();
    let endpoint = service_endpoint(
        &registry,
        pid,
        service_object,
        AudioServiceKind::CaptureClient,
    )
    .ok_or(AUDCLNT_E_DEVICE_INVALIDATED)?;
    let Some(state) = registry
        .clients
        .get_mut(&pid)
        .and_then(|clients| clients.get_mut(&endpoint))
    else {
        return Err(AUDCLNT_E_DEVICE_INVALIDATED);
    };
    if state.direction != AudioDirection::Capture {
        return Err(AUDCLNT_E_WRONG_ENDPOINT_TYPE);
    }
    if !state.initialized {
        return Err(AUDCLNT_E_NOT_INITIALIZED);
    }
    if !state.running {
        return Err(AUDCLNT_E_NOT_STARTED);
    }
    if state.capture_outstanding_frames == 0 {
        return Err(AUDCLNT_E_OUT_OF_ORDER);
    }
    if frames_released == 0 || frames_released > state.capture_outstanding_frames {
        return Err(AUDCLNT_E_INVALIDARG);
    }
    state.capture_outstanding_frames = 0;
    state.capture_consumed_frames = state
        .capture_consumed_frames
        .saturating_add(frames_released as u64);
    Ok(CaptureRelease {
        endpoint,
        frames: frames_released,
    })
}

/// `IAudioCaptureClient::GetNextPacketSize` — frames in the next packet (0
/// when none is available).
pub(crate) fn capture_next_packet_size(pid: u32, service_object: u64) -> Result<u32, u32> {
    with_service_state(
        pid,
        service_object,
        AudioServiceKind::CaptureClient,
        "GetNextPacketSize",
        |state| {
            if state.direction != AudioDirection::Capture {
                return Err(AUDCLNT_E_WRONG_ENDPOINT_TYPE);
            }
            if !state.initialized {
                return Err(AUDCLNT_E_NOT_INITIALIZED);
            }
            if state.capture_outstanding_frames != 0 {
                return Err(AUDCLNT_E_OUT_OF_ORDER);
            }
            if !state.running {
                return Ok(0);
            }
            Ok(state.capture_next_packet_frames(pid, Instant::now()))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_riids_rejected() {
        let unknown = [0xaa; 16];
        assert!(!is_supported_activation_riid(&unknown));
        let zeroes = [0u8; 16];
        assert!(!is_supported_activation_riid(&zeroes));
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

    // -----------------------------------------------------------------------
    // IActivateAudioInterfaceAsyncOperation — completion, error and lifetime
    // -----------------------------------------------------------------------

    #[test]
    fn activation_operation_reports_result_once_after_completion() {
        let pid = 0x7d01;
        let operation = 0x9_501;
        register_activation_operation(pid, operation, 0x9_601);
        assert_eq!(
            activation_operation_interface(pid, operation),
            Some(0x9_601)
        );
        assert_eq!(
            operation_get_activate_result(pid, operation),
            Err(E_ILLEGAL_METHOD_CALL),
            "no result before the activation completes"
        );
        complete_activation_operation(pid, operation, ACTIVATION_S_OK, 0x9_601);
        assert_eq!(
            operation_get_activate_result(pid, operation),
            Ok((ACTIVATION_S_OK, 0x9_601))
        );
        assert_eq!(
            operation_get_activate_result(pid, operation),
            Err(E_ILLEGAL_METHOD_CALL),
            "the completed result is returned exactly once"
        );
        release_activation_operation(pid, operation);
        assert_eq!(activation_operation_interface(pid, operation), None);
        assert_eq!(
            operation_get_activate_result(pid, operation),
            Err(E_ILLEGAL_METHOD_CALL)
        );
    }

    #[test]
    fn activation_operation_failure_result_is_still_a_completion() {
        let pid = 0x7d02;
        let operation = 0x9_502;
        register_activation_operation(pid, operation, 0);
        complete_activation_operation(pid, operation, ACTIVATION_E_NOINTERFACE, 0);
        assert_eq!(
            operation_get_activate_result(pid, operation),
            Ok((ACTIVATION_E_NOINTERFACE, 0)),
            "GetActivateResult succeeds and carries the activation HRESULT"
        );
        assert_eq!(
            operation_get_activate_result(pid, operation),
            Err(E_ILLEGAL_METHOD_CALL)
        );
        release_activation_operation(pid, operation);
    }

    #[test]
    fn activation_operation_query_interface_ids() {
        assert!(activation_operation_supports_riid(&IID_IUNKNOWN));
        assert!(activation_operation_supports_riid(
            &IID_IACTIVATE_AUDIO_INTERFACE_ASYNC_OPERATION
        ));
        assert!(!activation_operation_supports_riid(&IID_IAUDIO_CLIENT));
        assert!(!activation_operation_supports_riid(&[0xAA; 16]));
    }

    // -----------------------------------------------------------------------
    // Loopback capture — real render frames read back
    // -----------------------------------------------------------------------

    fn loopback_capture_service(
        pid: u32,
        object: u64,
        service: u64,
        device: &RealAudioDevice,
        stream_flags: u32,
    ) -> AudioClientFormat {
        let format = test_format(WAVE_FORMAT_PCM, 2, 8_000, 16);
        register_audio_client(pid, object, device.clone(), IID_IAUDIO_CLIENT);
        let plan = plan_initialize(
            pid,
            object,
            AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_LOOPBACK | stream_flags,
            100_000,
            0,
            &format,
        )
        .expect("loopback initialize plan");
        assert!(plan.loopback);
        assert_eq!(
            commit_initialize(pid, object, &plan, &format, 0x6_000, 3200),
            AUDCLNT_S_OK
        );
        bind_service(pid, object, service, AudioServiceKind::CaptureClient);
        format
    }

    #[test]
    fn loopback_capture_reads_back_the_render_stream_frames() {
        let pid = 0x7d10;
        let object = 0x9_510;
        let service = 0x9_610;
        let device = test_device();
        let format = loopback_capture_service(
            pid,
            object,
            service,
            &device,
            AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
        );
        let snapshot = test_client_snapshot(pid, object).expect("snapshot");
        assert_eq!(snapshot.direction, AudioDirection::Capture);
        assert!(snapshot.loopback);
        assert!(
            !snapshot.capture_input_active,
            "loopback never opens the mic"
        );

        // A render client released 80 real frames into the device's history.
        let mut rendered = Vec::new();
        for frame in 0..80_u32 {
            let sample = frame as f32 / 1000.0;
            rendered.push(sample);
            rendered.push(-sample);
        }
        push_loopback_render_samples(
            pid,
            &device.key,
            &rendered,
            format.channels,
            format.sample_rate,
        );

        // Loopback is event-driven: a packet is already available at Start.
        assert_eq!(set_event_handle(pid, object, 0xE1), AUDCLNT_S_OK);
        assert_eq!(start(pid, object), AUDCLNT_S_OK);
        assert_eq!(take_ready_event(pid, object), Some(0xE1));
        assert_eq!(capture_next_packet_size(pid, service), Ok(80));

        let packet = capture_get_buffer(pid, service).expect("loopback packet");
        assert_eq!(packet.frames, 80);
        assert_eq!(packet.flags, 0, "real render frames are not silent");
        assert_eq!(
            packet.samples, rendered,
            "the capture client reads the render stream's frames back"
        );
        capture_release_buffer(pid, service, 80, 0).expect("release loopback packet");
        assert_eq!(capture_next_packet_size(pid, service), Ok(0));
        stop(pid, object);
        reset(pid, object);
        release_audio_object(pid, object);
        release_audio_object(pid, service);
    }

    #[test]
    fn loopback_is_rejected_on_a_capture_endpoint() {
        let pid = 0x7d12;
        let object = 0x9_512;
        let mut device = test_device();
        device.key = "Test Microphone|2|48000|capture".to_string();
        device.name = "Test Microphone".to_string();
        register_audio_client_direction(
            pid,
            object,
            device,
            IID_IAUDIO_CLIENT,
            AudioDirection::Capture,
        );
        let format = test_format(WAVE_FORMAT_PCM, 2, 48_000, 16);
        assert_eq!(
            plan_initialize(
                pid,
                object,
                AUDCLNT_SHAREMODE_SHARED,
                AUDCLNT_STREAMFLAGS_LOOPBACK,
                100_000,
                0,
                &format,
            ),
            Err(AUDCLNT_E_WRONG_ENDPOINT_TYPE),
            "loopback on a true capture endpoint is the wrong endpoint type"
        );
        release_audio_object(pid, object);
    }

    #[test]
    fn loopback_is_rejected_for_exclusive_mode() {
        let pid = 0x7d13;
        let object = 0x9_513;
        let device = test_device();
        register_audio_client(pid, object, device, IID_IAUDIO_CLIENT);
        let mix = mix_format_for_device(&test_device());
        assert_eq!(
            plan_initialize(
                pid,
                object,
                AUDCLNT_SHAREMODE_EXCLUSIVE,
                AUDCLNT_STREAMFLAGS_LOOPBACK,
                100_000,
                0,
                &mix,
            ),
            Err(AUDCLNT_E_INVALID_STREAM_FLAG),
            "loopback is a shared-mode capture path"
        );
        release_audio_object(pid, object);
    }

    // -----------------------------------------------------------------------
    // Exclusive mode — client-side buffer/period/format constraints
    // -----------------------------------------------------------------------

    #[test]
    fn exclusive_mode_enforces_buffer_and_period_constraints() {
        let pid = 0x7d20;
        let object = 0x9_520;
        let device = test_device();
        register_audio_client(pid, object, device.clone(), IID_IAUDIO_CLIENT);
        let mix = mix_format_for_device(&device);
        // The synthetic device uses the documented 10 ms / 3 ms fallback.
        let plan = plan_initialize(
            pid,
            object,
            AUDCLNT_SHAREMODE_EXCLUSIVE,
            0,
            100_000,
            0,
            &mix,
        )
        .expect("exclusive plan at 10 ms");
        assert_eq!(plan.buffer_frames, 480);
        assert_eq!(
            plan_initialize(pid, object, AUDCLNT_SHAREMODE_EXCLUSIVE, 0, 10_000, 0, &mix,),
            Err(AUDCLNT_E_BUFFER_SIZE_ERROR),
            "below the real minimum device period"
        );
        assert_eq!(
            plan_initialize(
                pid,
                object,
                AUDCLNT_SHAREMODE_EXCLUSIVE,
                0,
                100_000,
                10_000,
                &mix,
            ),
            Err(AUDCLNT_E_INVALID_DEVICE_PERIOD),
            "periodicity below the minimum period"
        );
        assert_eq!(
            plan_initialize(
                pid,
                object,
                AUDCLNT_SHAREMODE_EXCLUSIVE,
                0,
                100_000,
                200_000,
                &mix,
            ),
            Err(AUDCLNT_E_INVALID_DEVICE_PERIOD),
            "periodicity larger than the buffer"
        );
        assert_eq!(
            plan_initialize(
                pid,
                object,
                AUDCLNT_SHAREMODE_EXCLUSIVE,
                0,
                30_000_000,
                0,
                &mix,
            ),
            Err(AUDCLNT_E_BUFFER_TOO_LARGE),
            "the engine caps buffers at two seconds"
        );
        let pcm = test_format(WAVE_FORMAT_PCM, 2, 48_000, 16);
        assert_eq!(
            plan_initialize(
                pid,
                object,
                AUDCLNT_SHAREMODE_EXCLUSIVE,
                0,
                100_000,
                0,
                &pcm,
            ),
            Err(AUDCLNT_E_UNSUPPORTED_FORMAT),
            "exclusive mode requires the exact device format"
        );
        release_audio_object(pid, object);
    }
}
