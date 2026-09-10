//! Real audio-interface activation (`ActivateAudioInterfaceAsync`).
//!
//! Guest-facing activation model for the `mmdevapi.dll`
//! `ActivateAudioInterfaceAsync` export, backed by the REAL device stack in
//! [`crate::real_audio`]:
//!
//! - The requested COM interface id (`riid`) selects what is activated.
//!   The runtime has no guest `IAudioClient` vtable model (its guest audio
//!   surfaces are XAudio2/DirectSound/WinMM), so every supported audio-client
//!   family riid activates the same deepest real object the stack can back:
//!   a guest audio-endpoint object bound to the real device with the real
//!   device's data (id, name, channels, sample rate, default flag) as
//!   enumerated from the host. Unsupported riids fail the activation with
//!   `E_NOINTERFACE`.
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

use crate::real_audio::RealAudioDevice;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{LazyLock, Mutex, MutexGuard};

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
/// `AUDCLNT_E_DEVICE_INVALIDATED` — the real device list is genuinely empty
/// (or the requested device endpoint does not exist on this host).
pub const AUDCLNT_E_DEVICE_INVALIDATED: u32 = 0x8889_0006;

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

/// Number of completions still queued for `pid`.
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
}
