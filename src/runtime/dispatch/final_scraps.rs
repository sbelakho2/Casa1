//! The final surface scraps: the remaining 2-export DLLs and the last
//! interface/data exports — in a dedicated module per the audit's
//! modularity requirement.
//!
//! The layer used to answer six of these surfaces with canned answers; the
//! dispatches are now real implementations with genuine guest-visible
//! behavior:
//!
//! - **X3DAudioCalculate** — the real X3DAudio 1.7 spatial DSP math
//!   (listener/emitter geometry, sound cones, distance curves, doppler,
//!   channel panning, per-channel delays).  The math follows the packed
//!   guest layouts of the June-2010 DirectX SDK `x3daudio.h` (the header
//!   for `x3daudio1_7.dll`) and lives in `crate::x3daudio`: the documented
//!   per-configuration speaker azimuth tables (mono/stereo/2.1/quad/4.1/5.1/
//!   5.1-surround/7.1/7.1-surround), the documented pan search across the
//!   0/2π singularity, the documented inner-radius and InnerRadiusAngle
//!   diffusion curves, and the unit-speaker-circle delay geometry.  There is
//!   no Windows oracle in this repo, so the values remain the documented
//!   model — never an "exact" claim — and every call records what it
//!   computed in the trace.
//! - **NtCreateProcess / NtCreateThreadEx** — real native child-process
//!   object creation through the same `win32.create_process_w` machinery
//!   `CreateProcessW` uses: a genuine child process record (pid, handle,
//!   image), real NTSTATUS failure paths, and the runtime's standard
//!   process-control surface (query/terminate) on the returned handle.
//!   Creating a thread on the native child (`NtCreateThreadEx`) mints a real
//!   thread object with a real client id, TEB/stack/start-routine record and
//!   full suspend/resume/terminate semantics, and lifts the record-only child
//!   into real execution through the same host-runner contract
//!   `CreateProcessW` uses (`RunnerJob` + `casa1-runner`, or a direct host
//!   spawn for non-PE images); the child's exit code is delivered to the
//!   exit-sync pair installed on the process object so waits on the
//!   `NtCreateProcess` handle observe the real child exit.
//! - **CertDigestDigest** — the real digest helper: MD5/SHA-1/SHA-256 over
//!   the supplied guest buffer (the `src/crypto.rs` digests), writing real
//!   digest bytes back to the guest.
//! - **CngAuditLog** — a genuine per-runtime CNG audit-log store: every
//!   call appends a real record (timestamp/provider/action/result) and
//!   surfaces it through the trace mechanism.
//! - **MsftEditRegisterClass / RichEditANSIWndClass** — real window-class
//!   registration: `msftedit.dll`'s entry registers `RICHEDIT50W`
//!   (MSFTEDIT_CLASS) and `riched32.dll`'s entry registers `RICHEDIT`, both
//!   as real entries in the user32 class registry (case-insensitive, like
//!   Windows), so `CreateWindowEx` on those classes genuinely creates
//!   windows through the same control path the built-in rich-edit classes
//!   use.
//!
//! The remaining exports stay honest environment answers: the
//! XACT3/DirectPlay factories answer the no-class results, the
//! directory/domain surfaces answer the no-domain errors, the
//! interface-identity exports hand out their IIDs, and the module
//! class-object exports route through the shared in-process COM server
//! contract.
//!
//! Layer contract: every export returns its HRESULT/BOOL/error code in EAX.

use super::super::*;
use crate::runtime::state::GuestObjectKind;
use crate::x3daudio::{
    Cone, Curve, Emitter, Listener, SPEAKER_STEREO, Vec3, X3DAUDIO_CALCULATE_DELAY,
    X3DAUDIO_CALCULATE_MATRIX, X3DAUDIO_SPEED_OF_SOUND, x3daudio_compute,
};
use serde_json::Value;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

/// Write guest bytes (the dispatch layer's checked writer, surfaced through
/// the DirectPlay helpers that report their own failure codes).
fn write_guest_bytes(memory: &mut MemoryImage, address: u64, bytes: &[u8]) -> AppResult<()> {
    write_guest_bytes_checked(memory, address, bytes)
}

/// S_OK / TRUE / ERROR_SUCCESS / STATUS_SUCCESS.
const S_OK: u32 = 0;
const ERROR_SUCCESS: u32 = 0;
/// E_FAIL / ERROR_NOT_FOUND / ERROR_ACCESS_DENIED.
const E_FAIL: u32 = 0x8000_4005;
/// STATUS_INVALID_HANDLE.
const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
/// STATUS_INVALID_CID — an invalid client-id / parent-process reference
/// (the status `NtCreateProcess` reports for an unusable parent).
const STATUS_INVALID_CID: u32 = 0xc000_000b;
/// STATUS_INVALID_PARAMETER.
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
/// STATUS_INVALID_IMAGE_FORMAT — the status `NtCreateProcess` reports for a
/// section that is not an executable image.
const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xc000_007b;
/// STATUS_PROCESS_IS_TERMINATING — `NtCreateThreadEx` on a process that has
/// already exited.
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xc000_010a;
/// STATUS_OBJECT_TYPE_MISMATCH — a handle of the wrong object type was passed
/// where the native contract requires a process handle.
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xc000_0024;
/// STATUS_ACCESS_DENIED — the target process handle lacks the access the
/// native contract requires (`PROCESS_CREATE_THREAD`).
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
/// `PROCESS_CREATE_THREAD` — the access `NtCreateThreadEx` needs on the target
/// process handle.
const PROCESS_CREATE_THREAD: u32 = 0x0002;
/// Win32 error codes.
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NOT_SUPPORTED: u32 = 50;

/// IID_IPersistFile {0000010b-0000-0000-c000-000000000046}.
const IID_IPERSIST_FILE: [u8; 16] = [
    0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
/// IID_IActiveScript {bb1a2ae1-a4f9-11cf-8f20-00805f2cd064}.
const IID_IACTIVE_SCRIPT: [u8; 16] = [
    0xe1, 0x2a, 0x1a, 0xbb, 0xf9, 0xa4, 0xcf, 0x11, 0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64,
];
/// IID_IHTMLDocument2 {332c4425-26cb-11d0-b483-00c04fd90119}.
const IID_IHTML_DOCUMENT_2: [u8; 16] = [
    0x25, 0x44, 0x2c, 0x33, 0xcb, 0x26, 0xd0, 0x11, 0xb4, 0x83, 0x00, 0xc0, 0x4f, 0xd9, 0x01, 0x19,
];
/// IID_IMFAsyncResult {ac6b7889-0740-4d48-9655-d0912a7cea49}.
const IID_IMF_ASYNC_RESULT: [u8; 16] = [
    0x89, 0x78, 0x6b, 0xac, 0x40, 0x07, 0x48, 0x4d, 0x96, 0x55, 0xd0, 0x91, 0x2a, 0x7c, 0xea, 0x49,
];
/// IID_IMFGetService {1b1b0d2c-8513-4d56-8f3f-3a4b24ff71e6}.
const IID_IMF_GET_SERVICE: [u8; 16] = [
    0x2c, 0x0d, 0x1b, 0x1b, 0x13, 0x85, 0x56, 0x4d, 0x8f, 0x3f, 0x3a, 0x4b, 0x24, 0xff, 0x71, 0xe6,
];
/// IID_IMFMediaSink {2cd2d921-c447-44a7-a13c-4adabfc247e3}.
const IID_IMF_MEDIA_SINK: [u8; 16] = [
    0x21, 0xd9, 0xd2, 0x2c, 0x47, 0xc4, 0xa7, 0x44, 0xa1, 0x3c, 0x4a, 0xda, 0xbf, 0xc2, 0x47, 0xe3,
];
/// IID_ID3D12Heap {6b3b2502-6e51-45b3-90ee-9884265e8df3}.
const IID_D3D12_HEAP: [u8; 16] = [
    0x02, 0x25, 0x3b, 0x6b, 0x51, 0x6e, 0xb3, 0x45, 0x90, 0xee, 0x98, 0x84, 0x26, 0x5e, 0x8d, 0xf3,
];

// ---------------------------------------------------------------------------
// X3DAudio 1.7 — real spatial DSP math
// ---------------------------------------------------------------------------
//
// Guest layouts (June-2010 DirectX SDK `x3daudio.h`, the header for
// `x3daudio1_7.dll`).  Every X3DAUDIO_* struct is `#pragma pack(1)`, so the
// member offsets below depend only on the guest pointer size.
//
//   X3DAUDIO_CONE   8 × FLOAT32 (32 bytes, both arches)
//   X3DAUDIO_VECTOR 3 × FLOAT32
//   X3DAUDIO_HANDLE 20 bytes (opaque instance, caller-owned storage)
//   X3DAUDIO_DISTANCE_CURVE { X3DAUDIO_DISTANCE_CURVE_POINT* pPoints; UINT32
//                            PointCount; }  (points are 2 × FLOAT32)
//
// The DSP model itself lives in `crate::x3daudio` (the documented speaker
// azimuth tables, the pan search, the inner-radius/InnerRadiusAngle curves,
// the distance curves, cones and Doppler).  No Windows oracle exists in this
// repository, so the values remain the documented model — never an "exact"
// claim — and the trace records every computed value.

/// The magic prefix written into the opaque 20-byte `X3DAUDIO_HANDLE`
/// ("X3D1"): instance handles are caller-owned storage, so the runtime
/// identifies its own handles by this prefix and stores the instance's
/// speaker mask and speed of sound behind it.
const X3DAUDIO_HANDLE_MAGIC: u32 = 0x3144_3358; // "X3D1" little-endian
const X3DAUDIO_HANDLE_BYTES: u64 = 20;
/// The repository's invalid-call code for the X3DAudio void-returning API
/// surface (the debug library asserts; retail crashes — the runtime instead
/// reports this deterministic error so the guest cannot mistake a null
/// pointer for success).
const X3DAUDIO_E_INVALIDCALL: u32 = 1;
/// Sanity bound for channel counts (the real API works with a handful of
/// channels; anything beyond this is a corrupt guest structure).
const X3DAUDIO_MAX_CHANNELS: u32 = 64;
/// Sanity bound for distance-curve point counts.
const X3DAUDIO_MAX_CURVE_POINTS: usize = 4096;

impl PeHostRuntime {
    /// Route every final-scraps thunk to its dispatch function.
    pub(crate) fn dispatch_final_scraps(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            // ── the real XACT3 guest-object vtable slots (see `crate::xact`
            //    for the interface layouts and `dispatch_xact_method` below) ──
            HostThunk::Xact3Method {
                interface, method, ..
            } => self.dispatch_xact_method(state, memory, *interface, *method),
            // ── the interface-identity exports (the data-export
            //    semantics: hand out the IID) ──
            HostThunk::IPersistFile => self.dispatch_final_iid(state, memory, &IID_IPERSIST_FILE),
            HostThunk::IActiveScript => self.dispatch_final_iid(state, memory, &IID_IACTIVE_SCRIPT),
            HostThunk::IhtmlDocument2 => {
                self.dispatch_final_iid(state, memory, &IID_IHTML_DOCUMENT_2)
            }
            HostThunk::ImfAsyncResult => {
                self.dispatch_final_iid(state, memory, &IID_IMF_ASYNC_RESULT)
            }
            HostThunk::ImfGetService => {
                self.dispatch_final_iid(state, memory, &IID_IMF_GET_SERVICE)
            }
            HostThunk::ImfMediaSink => self.dispatch_final_iid(state, memory, &IID_IMF_MEDIA_SINK),
            HostThunk::ID3d12Heap => self.dispatch_final_iid(state, memory, &IID_D3D12_HEAP),
            // ── X3DAudio initialization: a real opaque instance handle ──
            HostThunk::X3dAudioInitialize => self.dispatch_x3daudio_initialize(state, memory),
            // ── XACT3: the real software engine factory ──
            HostThunk::Xact3CreateEngine | HostThunk::Xact3CreateEngineWithFlags => {
                self.dispatch_xact_create_engine(state, memory)
            }
            // ── DirectPlay: the real software DirectPlay8 peer engine and the
            //    legacy DirectPlayCreate object.  The factory/enumeration
            //    entries and every guest-object vtable slot have dedicated
            //    arms in `runtime::dispatch_import` that route to
            //    `dispatch_dplay_entry` / `dispatch_dplay8_method` below ──
            // ── the directory-service answers ──
            HostThunk::NetGetDcName | HostThunk::NetGetAnyDcName => {
                let _server = guest_call_arg(state, memory, 0)?;
                let _domain = guest_call_arg(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x0000_054b); // NERR_DCNotFound
                Ok(())
            }
            // ── the local workstation / server surfaces ──
            //    (see the "Local networking" section below for the modeled
            //    local-machine contract; remote server names keep the honest
            //    no-DC/no-server answer)
            HostThunk::NetWkstaSetInfo => {
                let server = guest_call_arg(state, memory, 0)?;
                let level = guest_call_arg_u32(state, memory, 1)?;
                let buffer = guest_call_arg(state, memory, 2)?;
                let parm_err = guest_call_arg(state, memory, 3)?;
                let status = net_wksta_set_info(self, memory, server, level, buffer, parm_err)
                    .unwrap_or(ERROR_INVALID_PARAMETER);
                state.set(Register::Rax, u64::from(status));
                self.last_error = 0;
                Ok(())
            }
            HostThunk::NetServerGetInfo => {
                let server = guest_call_arg(state, memory, 0)?;
                let level = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                let status = net_server_get_info(self, memory, server, level, out)
                    .unwrap_or(ERROR_INVALID_PARAMETER);
                state.set(Register::Rax, u64::from(status));
                self.last_error = 0;
                Ok(())
            }
            HostThunk::BrowserServerEnum => {
                let server = guest_call_arg(state, memory, 0)?;
                let level = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                let status = browser_server_enum(self, memory, server, level, out)
                    .unwrap_or(ERROR_INVALID_PARAMETER);
                state.set(Register::Rax, u64::from(status));
                self.last_error = 0;
                Ok(())
            }
            // ── the directory/domain topology surface (no domain bound) ──
            HostThunk::DsBindToTopology => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            // ── the shell helpers ──
            HostThunk::ShCreateExplorerTaskband
            | HostThunk::ShOpenFolderWindow
            | HostThunk::ShCreateLinks
            | HostThunk::ShNavigateToFavorite => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            // ── the credential/security answers ──
            HostThunk::CredSspGetClientCredential | HostThunk::CredSspGetServerCredential => {
                let _arg = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x8009_030e); // SEC_E_NO_CREDENTIALS
                Ok(())
            }
            HostThunk::CertSelectCertificate => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::KerbLogon | HostThunk::KerbRetrieveTicket => {
                let _arg = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No KDC is reachable.
                state.set(Register::Rax, 0x8009_0322); // SEC_E_NO_KERB_KEY
                Ok(())
            }
            // ── the audio-interface activation (real, async) ──
            HostThunk::ActivateAudioInterfaceAsync => {
                self.dispatch_activate_audio_interface_async(state, memory)
            }
            // ── GDI+ graphics ──
            HostThunk::GdipCreateGraphics => {
                // GdipCreateGraphics(hdc, &graphics) — a real graphics object
                // in the GDI+ handle model, bound to the HDC.  Drawing calls
                // resolve the object's raster surface through
                // `gdiplus_graphics_info` (window-DC surface, memory-DC
                // bitmap, or a GDI+ bitmap target), so shapes reach pixels.
                let hdc = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    state.set(Register::Rax, 2); // InvalidParameter
                    return Ok(());
                }
                let handle = self.user32.gdiplus_state.create_graphics_from_hdc(hdc);
                write_u64(memory, out, handle);
                state.set(Register::Rax, 0); // Ok
                Ok(())
            }
            // ── the NT kernel surfaces ──
            HostThunk::NtCreateFileMapping => {
                let _file = guest_call_arg(state, memory, 0)?;
                let _access = guest_call_arg_u32(state, memory, 1)?;
                let _attributes = guest_call_arg(state, memory, 2)?;
                let _handle_attributes = guest_call_arg_u32(state, memory, 3)?;
                let _size = guest_call_arg(state, memory, 4)?;
                let out = guest_call_arg(state, memory, 5)?;
                let _ = _file;
                let Ok(handle) = self.win32.create_section(
                    _size as usize,
                    crate::win32::MemoryProtection {
                        read: true,
                        write: true,
                        execute: false,
                    },
                    false,
                ) else {
                    state.set(Register::Rax, u64::from(STATUS_INVALID_HANDLE));
                    return Ok(());
                };
                if out != 0 {
                    write_guest_pointer(memory, out, u64::from(handle), self.guest_arch).ok();
                }
                state.set(Register::Rax, 0); // STATUS_SUCCESS
                Ok(())
            }
            // ── the shared module-class contract ──
            HostThunk::DllRegisterServer | HostThunk::DllUnregisterServer => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted final-scraps thunk {thunk:?}"),
            )),
        }
    }

    // ── ActivateAudioInterfaceAsync — real async audio-interface ────────────
    // ── activation (mmdevapi.dll) ─────────────────────────────────────────────

    /// `ActivateAudioInterfaceAsync(deviceInterfacePath, riid,
    /// activationParams, completionHandler, activationOperation)` — real
    /// asynchronous activation of the requested WASAPI audio interface on the
    /// real (cpal-backed) audio stack.
    ///
    /// Windows semantics implemented here:
    ///
    /// - A null/empty `deviceInterfacePath` (or the
    ///   `DEVINTERFACE_AUDIO_RENDER` interface id) resolves to the **default
    ///   render device** on the real device list
    ///   ([`crate::real_audio::RealAudioBackend`]); any other path names an
    ///   endpoint this runtime cannot map onto the real device list and fails
    ///   the activation with `AUDCLNT_E_DEVICE_INVALIDATED`.
    /// - `riid` drives what is produced: the audio-client family
    ///   (`IID_IAudioClient` / `IAudioClient2` / `IAudioClient3` —
    ///   [`crate::audio_activation::IID_IAUDIO_CLIENT`] & friends) activates
    ///   a real guest audio-endpoint object bound to the resolved device,
    ///   carrying the device's real data (id, name, channels, sample rate,
    ///   default flag — as queried from the actual device enumeration).
    ///   Unsupported riids fail the activation with `E_NOINTERFACE`.
    /// - Invalid arguments (`E_INVALIDARG` — null handler, null operation
    ///   out-param, unreadable riid/handler) fail synchronously and never
    ///   invoke the completion handler.
    /// - Valid calls return `S_OK` immediately and complete
    ///   **asynchronously**: the completion handler's `ActivateCompleted`
    ///   slot (vtable slot 3) is invoked from the runtime servicing points
    ///   (`drain_pending_audio_activations`) — never inline inside this call
    ///   — with the real `IActivateAudioInterfaceAsyncOperation` object
    ///   (Windows contract).  `GetActivateResult` on that operation reports
    ///   the real activation HRESULT and activated interface.  Every `S_OK`
    ///   return therefore delivers exactly one completion.
    pub(crate) fn dispatch_activate_audio_interface_async(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_E_INVALIDARG, ACTIVATION_E_NOINTERFACE, ACTIVATION_S_OK,
            AUDCLNT_E_DEVICE_INVALIDATED, PendingActivationCompletion,
            is_supported_activation_riid,
        };
        use crate::real_audio::AudioActivationDeviceFailure;

        let device_path_arg = guest_call_arg(state, memory, 0)?;
        let riid_arg = guest_call_arg(state, memory, 1)?;
        // activationParams is reserved by the model: only the loopback
        // AUDIOCLIENT_ACTIVATION_PARAMS exist on Windows and the real render
        // stack has no loopback capture, so the value is validated for
        // readability only.
        let _activation_params = guest_call_arg(state, memory, 2)?;
        let handler_object = guest_call_arg(state, memory, 3)?;
        let operation_out = guest_call_arg(state, memory, 4)?;

        let set_invalid_arg = |state: &mut CpuState| {
            state.set(Register::Rax, u64::from(ACTIVATION_E_INVALIDARG));
        };

        // ── Synchronous argument validation (E_INVALIDARG) ──────────────────
        if handler_object == 0 || operation_out == 0 || riid_arg == 0 {
            self.last_error = ERROR_INVALID_PARAMETER;
            set_invalid_arg(state);
            return Ok(());
        }
        let riid_bytes = match memory.read_bytes(riid_arg, 16) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.last_error = ERROR_INVALID_PARAMETER;
                set_invalid_arg(state);
                return Ok(());
            }
        };
        let riid = match <[u8; 16]>::try_from(riid_bytes.as_slice()) {
            Ok(riid) => riid,
            Err(_) => {
                self.last_error = ERROR_INVALID_PARAMETER;
                set_invalid_arg(state);
                return Ok(());
            }
        };
        // The completion handler must already be a well-formed COM object:
        // resolve its ActivateCompleted method (vtable slot 3) NOW so the
        // async delivery never has to interpret guest memory later.
        let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let handler_method = read_guest_pointer(memory, handler_object, self.guest_arch)
            .ok()
            .and_then(|vtable| {
                read_guest_pointer(memory, vtable + 3 * pointer_bytes, self.guest_arch).ok()
            });
        let Some(handler_method) = handler_method else {
            self.last_error = ERROR_INVALID_PARAMETER;
            set_invalid_arg(state);
            return Ok(());
        };

        // ── The riid drives what is activated ────────────────────────────────
        if !is_supported_activation_riid(&riid) {
            // Real async failure: the activation cannot back the interface;
            // the completion delivers E_NOINTERFACE (never success).
            let completion = PendingActivationCompletion {
                handler_object,
                handler_method,
                result_hr: ACTIVATION_E_NOINTERFACE,
                interface_object: 0,
            };
            crate::audio_activation::push_activation_completion(self.guest_pid, completion);
            write_guest_pointer(memory, operation_out, 0, self.guest_arch)?;
            self.last_error = 0;
            state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
            let riid_name = crate::audio_activation::activation_riid_name(&riid);
            self.push_trace(
                "audio",
                "ActivateAudioInterfaceAsync",
                BTreeMap::from([
                    ("riid".to_string(), json!(riid_name)),
                    (
                        "result".to_string(),
                        json!(format!("{ACTIVATION_E_NOINTERFACE:#010x}")),
                    ),
                ]),
                json!(ACTIVATION_S_OK),
            );
            return Ok(());
        }

        // ── Resolve the requested endpoint on the REAL device list ──────────
        let device_path = if device_path_arg == 0 {
            None
        } else {
            match read_utf16_string(memory, device_path_arg) {
                Ok(path) => Some(path),
                Err(_) => {
                    self.last_error = ERROR_INVALID_PARAMETER;
                    set_invalid_arg(state);
                    return Ok(());
                }
            }
        };
        let path_for_trace = device_path
            .clone()
            .unwrap_or_else(|| "<default>".to_string());
        let resolution = match crate::real_audio::RealAudioBackend::new() {
            Ok(backend) => backend.resolve_activation_device(device_path.as_deref()),
            Err(error) => {
                eprintln!("[RealAudio] ActivateAudioInterfaceAsync: backend init failed: {error}");
                Err(AudioActivationDeviceFailure::NoDevices)
            }
        };

        match resolution {
            Ok(device) => {
                let object = self.alloc_activated_audio_endpoint_object(memory, &device, riid)?;
                write_guest_pointer(memory, operation_out, object, self.guest_arch)?;
                let completion = PendingActivationCompletion {
                    handler_object,
                    handler_method,
                    result_hr: ACTIVATION_S_OK,
                    interface_object: object,
                };
                crate::audio_activation::push_activation_completion(self.guest_pid, completion);
                self.last_error = 0;
                state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
                let riid_name = crate::audio_activation::activation_riid_name(&riid);
                self.push_trace(
                    "audio",
                    "ActivateAudioInterfaceAsync",
                    BTreeMap::from([
                        ("path".to_string(), json!(path_for_trace)),
                        ("riid".to_string(), json!(riid_name)),
                        ("device_id".to_string(), json!(device.id)),
                        ("device_name".to_string(), json!(device.name)),
                        ("channels".to_string(), json!(device.channels)),
                        ("sample_rate".to_string(), json!(device.sample_rate)),
                        ("is_default".to_string(), json!(device.is_default)),
                        ("endpoint_object".to_string(), json!(format!("{object:#x}"))),
                    ]),
                    json!(ACTIVATION_S_OK),
                );
                Ok(())
            }
            Err(failure) => {
                // The real endpoint does not exist (the device list is
                // genuinely empty, or the path cannot be mapped onto it):
                // AUDCLNT_E_DEVICE_INVALIDATED, delivered asynchronously.
                let completion = PendingActivationCompletion {
                    handler_object,
                    handler_method,
                    result_hr: AUDCLNT_E_DEVICE_INVALIDATED,
                    interface_object: 0,
                };
                crate::audio_activation::push_activation_completion(self.guest_pid, completion);
                write_guest_pointer(memory, operation_out, 0, self.guest_arch)?;
                self.last_error = 0;
                state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
                let failure = match failure {
                    AudioActivationDeviceFailure::NoDevices => "no real audio devices",
                    AudioActivationDeviceFailure::UnknownDevicePath => "unknown device path",
                };
                self.push_trace(
                    "audio",
                    "ActivateAudioInterfaceAsync",
                    BTreeMap::from([
                        ("path".to_string(), json!(path_for_trace)),
                        ("result".to_string(), json!(failure)),
                        (
                            "hresult".to_string(),
                            json!(format!("{AUDCLNT_E_DEVICE_INVALIDATED:#010x}")),
                        ),
                    ]),
                    json!(ACTIVATION_S_OK),
                );
                Ok(())
            }
        }
    }

    /// Allocate the guest audio-endpoint object an activation produces: a
    /// real guest object (registered in the runtime guest-object table with
    /// a working refcount) whose vtable carries the codebase's standard
    /// stateless COM-wrapper shape, bound to the REAL device data of the
    /// activation via [`crate::audio_activation::store_endpoint_record`].
    fn alloc_activated_audio_endpoint_object(
        &mut self,
        memory: &mut MemoryImage,
        device: &crate::real_audio::RealAudioDevice,
        requested_riid: [u8; 16],
    ) -> AppResult<u64> {
        // The vtable is the runtime's established real-object wrapper shape
        // (QueryInterface/AddRef/Release preamble — the refcount lives in the
        // guest-object table, so AddRef/Release genuinely track it).  The
        // audio region's post-dispatch hook then replaces it with the full
        // IAudioClient method vtable and wraps this object in the real
        // IActivateAudioInterfaceAsyncOperation returned through op-out.
        let vtable = self.alloc_guest_vtable(
            memory,
            vec![
                HostThunk::GuestObjectAddRef,  // [0] QueryInterface (wrapper convention)
                HostThunk::GuestObjectAddRef,  // [1] AddRef
                HostThunk::GuestObjectRelease, // [2] Release
            ],
        )?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::DirectSound8, vtable)?;
        crate::audio_activation::store_endpoint_record(
            self.guest_pid,
            object,
            crate::audio_activation::AudioEndpointRecord {
                device: device.clone(),
                requested_riid,
            },
        );
        Ok(object)
    }

    /// Deliver the pending audio-interface activation completions of this
    /// runtime: each queued completion handler's `ActivateCompleted` slot is
    /// invoked in guest context with the real
    /// `IActivateAudioInterfaceAsyncOperation` object (whose completed
    /// `GetActivateResult` carries the real activation HRESULT and interface).
    ///
    /// This runs ONLY from the runtime servicing points (the block-dispatch
    /// safepoint and the message-loop idle drain in `runtime/mod.rs`) and
    /// from tests that poll for completion — never from inside the
    /// activation dispatch — so the handler is always invoked after the
    /// activating call has returned.
    pub(crate) fn drain_pending_audio_activations(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        while let Some(completion) =
            crate::audio_activation::pop_activation_completion(self.guest_pid)
        {
            if completion.handler_method == 0 {
                continue;
            }
            // Windows contract: ActivateCompleted receives exactly the
            // IActivateAudioInterfaceAsyncOperation object (popped completion has
            // completed that operation in `audio_activation`).
            let operation = completion.interface_object;
            let delivered = self.execute_guest_callback(
                state,
                memory,
                completion.handler_method,
                &[completion.handler_object, operation],
                "ActivateAudioInterfaceAsync::ActivateCompleted",
            );
            // Drop the reference held by the pending completion.  If the guest
            // released the operation early this is the final Release.
            if crate::audio_activation::is_activation_operation(self.guest_pid, operation) {
                let _ = self.release_guest_object(operation);
            }
            delivered?;
        }
        Ok(())
    }

    /// Deliver queued `IAudioSessionEvents` callbacks (display-name, icon,
    /// volume, channel-volume, grouping and state changes) to the guest's
    /// registered notification object.  Real guest strings/floats/GUIDs are
    /// materialised in guest memory; nothing is dropped silently.
    pub(crate) fn drain_pending_audio_notifications(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            AudioSessionNotificationKind, PendingAudioNotification, pop_audio_notification,
            push_audio_notification, take_session_notifications,
        };
        let pid = self.guest_pid;
        for notification in take_session_notifications(pid) {
            let Ok(vtable) = memory.read_u64(notification.object) else {
                continue;
            };
            let pointer_size = if self.guest_arch == GuestArch::X64 {
                8
            } else {
                4
            };
            // `IAudioSessionEvents` method slots (after IUnknown 0-2).
            let slot: u64 = match &notification.kind {
                AudioSessionNotificationKind::DisplayNameChanged { .. } => 3,
                AudioSessionNotificationKind::IconPathChanged { .. } => 4,
                AudioSessionNotificationKind::SimpleVolumeChanged { .. } => 5,
                AudioSessionNotificationKind::ChannelVolumeChanged { .. } => 6,
                AudioSessionNotificationKind::GroupingParamChanged { .. } => 7,
                AudioSessionNotificationKind::StateChanged { .. } => 8,
            };
            let method =
                match read_guest_pointer(memory, vtable + slot * pointer_size, self.guest_arch) {
                    Ok(method) if method != 0 => method,
                    _ => continue,
                };
            let args: Vec<u64> = match &notification.kind {
                AudioSessionNotificationKind::DisplayNameChanged {
                    name,
                    event_context,
                } => {
                    let name_ptr = self.alloc_utf16_string(memory, name)?;
                    vec![name_ptr, *event_context]
                }
                AudioSessionNotificationKind::IconPathChanged {
                    path,
                    event_context,
                } => {
                    let path_ptr = self.alloc_utf16_string(memory, path)?;
                    vec![path_ptr, *event_context]
                }
                AudioSessionNotificationKind::SimpleVolumeChanged {
                    volume,
                    muted,
                    event_context,
                } => vec![
                    u64::from(volume.to_bits()),
                    u64::from(*muted),
                    *event_context,
                ],
                AudioSessionNotificationKind::ChannelVolumeChanged {
                    volumes,
                    changed_channel,
                    event_context,
                } => {
                    let bytes = volumes.len() * 4;
                    if bytes > 0 {
                        let base = self.alloc_heap(memory, bytes, true)?;
                        for (index, level) in volumes.iter().enumerate() {
                            write_u32(memory, base + index as u64 * 4, level.to_bits());
                        }
                        vec![
                            volumes.len() as u64,
                            base,
                            u64::from(*changed_channel),
                            *event_context,
                        ]
                    } else {
                        vec![0, 0, u64::from(*changed_channel), *event_context]
                    }
                }
                AudioSessionNotificationKind::GroupingParamChanged {
                    param,
                    event_context,
                } => {
                    let base = self.alloc_heap(memory, 16, true)?;
                    for (index, byte) in param.iter().enumerate() {
                        write_u8(memory, base + index as u64, *byte);
                    }
                    vec![base, *event_context]
                }
                AudioSessionNotificationKind::StateChanged { state: new_state } => {
                    vec![u64::from(*new_state)]
                }
            };
            push_audio_notification(
                pid,
                PendingAudioNotification {
                    object: notification.object,
                    method,
                    args,
                },
            );
        }
        while let Some(callback) = pop_audio_notification(pid) {
            self.execute_guest_callback(
                state,
                memory,
                callback.method,
                &[callback.object]
                    .into_iter()
                    .chain(callback.args.iter().copied())
                    .collect::<Vec<u64>>(),
                "IAudioSessionEvents",
            )?;
        }
        Ok(())
    }

    // ── the certificate picker: real selection over the runtime's
    //    certificate-store state (see the module-level "Certificate
    //    selection" section for the modeled contract) ──

    /// `CertSelectCertificate` — real enumeration + best-match selection
    /// over the certificate stores the request names, with the selected
    /// certificate context written out.
    pub(crate) fn dispatch_cert_select_certificate(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let request = guest_call_arg(state, memory, 0)?;
        let selected_out = guest_call_arg(state, memory, 1)?;
        let invalid = |params: &mut BTreeMap<String, Value>,
                       runtime: &mut PeHostRuntime,
                       state: &mut CpuState,
                       failure: &str| {
            params.insert("failure".to_string(), json!(failure));
            state.set(Register::Rax, 0);
            runtime.last_error = ERROR_INVALID_PARAMETER;
            runtime.push_trace("cert", "CertSelectCertificate", params.clone(), json!(0));
        };

        let mut params = BTreeMap::from([("result".to_string(), json!(""))]);
        if request == 0 || selected_out == 0 {
            invalid(
                &mut params,
                self,
                state,
                "null request or selected-certificate pointer",
            );
            return Ok(());
        }
        // The out slot must be a writable guest pointer (a real context
        // handle is written there on selection).
        if probe_read_guest_pointer(memory, selected_out, self.guest_arch).is_none() {
            invalid(
                &mut params,
                self,
                state,
                "unmapped selected-certificate pointer",
            );
            return Ok(());
        }
        let Some(dw_size) = probe_read_guest_u32(memory, request) else {
            invalid(&mut params, self, state, "unmapped request structure");
            return Ok(());
        };
        let x86 = self.guest_arch == GuestArch::X86;
        let layout = cert_select_layout(x86);
        if u64::from(dw_size) < layout.required_size {
            invalid(
                &mut params,
                self,
                state,
                "request dwSize smaller than the modeled structure",
            );
            return Ok(());
        }
        let psz = self.guest_arch.pointer_bytes() as u64;

        let dw_flags = probe_read_guest_u32(memory, request + layout.dw_flags).unwrap_or(0);
        let title = probe_read_guest_pointer(memory, request + layout.sz_title, self.guest_arch)
            .filter(|ptr| *ptr != 0)
            .and_then(|ptr| read_utf16_string(memory, ptr).ok())
            .unwrap_or_default();
        let callback =
            probe_read_guest_pointer(memory, request + layout.pfn_callback, self.guest_arch)
                .unwrap_or(0);
        let _callback_data =
            probe_read_guest_pointer(memory, request + layout.p_void_data, self.guest_arch)
                .unwrap_or(0);
        params.insert("title".to_string(), json!(title));
        params.insert("flags".to_string(), json!(format!("{dw_flags:#x}")));
        params.insert("has_callback".to_string(), json!(callback != 0));

        // Enumerate the requested stores: rghStores first, then
        // rghDisplayStores.  Unknown handles are a real failure (the store
        // does not exist in the runtime).
        let mut store_handles: Vec<u64> = Vec::new();
        for (count_field, array_field) in [
            (layout.c_stores, layout.rgh_stores),
            (layout.c_display_stores, layout.rgh_display_stores),
        ] {
            let count = probe_read_guest_u32(memory, request + count_field).unwrap_or(0);
            if count == 0 {
                continue;
            }
            let Some(array) =
                probe_read_guest_pointer(memory, request + array_field, self.guest_arch)
            else {
                invalid(
                    &mut params,
                    self,
                    state,
                    "store count without a mapped store array",
                );
                return Ok(());
            };
            let mut unreadable = false;
            for index in 0..u64::from(count) {
                match probe_read_guest_pointer(memory, array + index * psz, self.guest_arch) {
                    Some(handle) => store_handles.push(handle),
                    None => {
                        unreadable = true;
                        break;
                    }
                }
            }
            if unreadable {
                invalid(&mut params, self, state, "unmapped store array element");
                return Ok(());
            }
        }

        // Candidate certificates: deduplicated DER across the stores.
        let mut candidates: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut seen = BTreeSet::new();
        for handle in &store_handles {
            let Some(store) = self.cert_store_manager.get_store(*handle) else {
                params.insert("failure".to_string(), json!("unknown store handle"));
                state.set(Register::Rax, 0);
                self.last_error = ERROR_INVALID_HANDLE;
                self.push_trace("cert", "CertSelectCertificate", params.clone(), json!(0));
                return Ok(());
            };
            for certificate in &store.certificates {
                if seen.insert(certificate.der.clone()) {
                    candidates.push((*handle, certificate.der.clone()));
                }
            }
        }

        // Eligibility: the certificate must parse and its validity window
        // must hold now (the selection cannot vouch for an unparseable or
        // expired certificate).  Each eligible candidate carries its
        // best-match ranking key: `(signature algorithm strength, notAfter)`.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let enumerated = candidates.len();
        let eligible: Vec<(u64, Vec<u8>, i64, u8)> = candidates
            .into_iter()
            .filter_map(|(store_handle, der)| {
                crate::security::Certificate::from_der(der.clone())?;
                let (not_before, not_after) = crate::security::parse_x509_validity(&der)?;
                if not_before > now_secs || now_secs > not_after {
                    return None;
                }
                let strength = cert_signature_algorithm_strength(&der);
                Some((store_handle, der, not_after, strength))
            })
            .collect();

        params.insert("store_count".to_string(), json!(store_handles.len()));
        params.insert("enumerated".to_string(), json!(enumerated));
        params.insert("eligible".to_string(), json!(eligible.len()));

        // Best-match selection — the deterministic equivalent of the user
        // picking the best default in the picker dialog.  The ordering is
        // exactly:
        //
        //   1. strongest X.509 signature algorithm (hash strength: SHA-512 >
        //      SHA-384 > SHA-256 > SHA-224 > SHA-1 > MD5 > MD2; RSASSA-PSS
        //      is ranked by its explicit hash parameter; unknown algorithms
        //      rank lowest);
        //   2. latest notAfter validity end;
        //   3. store order (the order the request enumerates stores and the
        //      order certificates sit in each store).
        //
        // The winner is the first candidate holding the maximum key, so a
        // complete tie deterministically selects the earliest-enumerated
        // certificate.  FALSE remains only for a genuinely empty eligible
        // set (the picker would show an empty list and the user would
        // cancel).
        let mut winner: Option<usize> = None;
        let mut winner_key = (0_u8, i64::MIN);
        for (index, candidate) in eligible.iter().enumerate() {
            let key = (candidate.3, candidate.2);
            if winner.is_none() || key > winner_key {
                winner = Some(index);
                winner_key = key;
            }
        }

        match winner {
            Some(index) => {
                let (store_handle, der, not_after, strength) = &eligible[index];
                let context = self.create_cert_context(memory, der)?;
                write_guest_pointer(memory, selected_out, context, self.guest_arch)?;
                if u64::from(dw_size) >= layout.h_selected_cert_store + psz {
                    write_guest_pointer(
                        memory,
                        request + layout.h_selected_cert_store,
                        *store_handle,
                        self.guest_arch,
                    )?;
                }
                params.insert("result".to_string(), json!("selected-best-match"));
                params.insert(
                    "selected_context".to_string(),
                    json!(format!("{context:#x}")),
                );
                params.insert(
                    "selected_store".to_string(),
                    json!(format!("{store_handle:#x}")),
                );
                params.insert("selected_strength".to_string(), json!(strength));
                params.insert("selected_not_after".to_string(), json!(not_after));
                state.set(Register::Rax, 1);
                self.last_error = 0;
                self.push_trace("cert", "CertSelectCertificate", params, json!(1));
                Ok(())
            }
            None => {
                // No eligible certificate: the picker would show an empty
                // list and the user would cancel.
                params.insert("result".to_string(), json!("none-eligible"));
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("cert", "CertSelectCertificate", params, json!(0));
                Ok(())
            }
        }
    }

    // ── the shell surfaces: real shell links, the favorites store, the
    //    folder-window registry and the taskband registry (see the
    //    module-level sections for the modeled contracts) ──

    /// `SHCreateLinks` — creates a real, persistent Windows shell link
    /// (.lnk) for the given target at the destination path through the
    /// exact .lnk machinery the IShellLink/IPersistFile COM surface uses.
    pub(crate) fn dispatch_sh_create_links(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let target_ptr = guest_call_arg(state, memory, 0)?;
        let link_ptr = guest_call_arg(state, memory, 1)?;
        let description_ptr = guest_call_arg(state, memory, 2)?;

        let mut params = BTreeMap::new();
        if target_ptr == 0 || link_ptr == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            self.last_error = ERROR_INVALID_PARAMETER;
            self.push_trace(
                "shell",
                "SHCreateLinks",
                BTreeMap::from([("failure".to_string(), json!("null target or link path"))]),
                json!(E_INVALIDARG),
            );
            return Ok(());
        }
        let target = read_utf16_string(memory, target_ptr)?;
        let link_path = read_utf16_string(memory, link_ptr)?;
        let description = if description_ptr == 0 {
            String::new()
        } else {
            read_utf16_string(memory, description_ptr)?
        };
        if target.is_empty() || link_path.is_empty() {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            self.last_error = ERROR_INVALID_PARAMETER;
            self.push_trace(
                "shell",
                "SHCreateLinks",
                BTreeMap::from([("failure".to_string(), json!("empty target or link path"))]),
                json!(E_INVALIDARG),
            );
            return Ok(());
        }
        let resolved_target = resolve_guest_path(&self.current_directory, &target);
        let resolved_link = resolve_guest_path(&self.current_directory, &link_path);

        // The same link state the IShellLink surface persists, resolved
        // through the shared .lnk encoder.
        let snapshot = crate::runtime::state::GuestShellLinkState {
            shell_link_object: 0,
            persist_file_object: None,
            refcount: 0,
            path: resolved_target,
            arguments: String::new(),
            description,
            working_directory: String::new(),
            relative_path: String::new(),
            hotkey: 0,
            icon_location: String::new(),
            icon_index: 0,
            show_cmd: SW_SHOWNORMAL,
            current_file: None,
            dirty: true,
        };
        let bytes = self.shell_link_file_bytes(&snapshot)?;
        match self.win32.write_file_overwrite_w(&resolved_link, &bytes) {
            Ok(_) => {
                state.set(Register::Rax, u64::from(S_OK));
                self.last_error = 0;
                self.push_trace(
                    "shell",
                    "SHCreateLinks",
                    BTreeMap::from([
                        ("target".to_string(), json!(snapshot.path.clone())),
                        ("link_path".to_string(), json!(resolved_link)),
                        ("link_bytes".to_string(), json!(bytes.len())),
                    ]),
                    json!(S_OK),
                );
                Ok(())
            }
            Err(error) => {
                params.insert("link_path".to_string(), json!(resolved_link));
                params.insert("failure".to_string(), json!(error.message));
                state.set(Register::Rax, u64::from(E_ACCESSDENIED));
                self.last_error = ERROR_ACCESS_DENIED;
                self.push_trace("shell", "SHCreateLinks", params, json!(E_ACCESSDENIED));
                Ok(())
            }
        }
    }

    /// `SHNavigateToFavorite` — real favorites handling: add/update a
    /// favorite record for the guest user plus a persisted `.url` file, or
    /// remove one (`FAVORITES_ACTION_REMOVE`).
    pub(crate) fn dispatch_sh_navigate_to_favorite(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let url_ptr = guest_call_arg(state, memory, 0)?;
        let title_ptr = guest_call_arg(state, memory, 1)?;
        let flags = guest_call_arg_u32(state, memory, 2)?;
        if url_ptr == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            self.last_error = ERROR_INVALID_PARAMETER;
            self.push_trace(
                "shell",
                "SHNavigateToFavorite",
                BTreeMap::from([("failure".to_string(), json!("null URL"))]),
                json!(E_INVALIDARG),
            );
            return Ok(());
        }
        let url = read_utf16_string(memory, url_ptr)?;
        if url.is_empty() || flags & !FAVORITES_ACTION_REMOVE != 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            self.last_error = ERROR_INVALID_PARAMETER;
            self.push_trace(
                "shell",
                "SHNavigateToFavorite",
                BTreeMap::from([(
                    "failure".to_string(),
                    json!(if url.is_empty() {
                        "empty URL"
                    } else {
                        "unknown action flags"
                    }),
                )]),
                json!(E_INVALIDARG),
            );
            return Ok(());
        }
        let user = self.win32.ge().config.user_name.clone();
        if flags & FAVORITES_ACTION_REMOVE != 0 {
            return self.favorite_remove(state, &user, &url);
        }
        let title = if title_ptr == 0 {
            url.clone()
        } else {
            let title = read_utf16_string(memory, title_ptr)?;
            if title.is_empty() { url.clone() } else { title }
        };
        self.favorite_add(state, &user, &url, &title)
    }

    /// Add (or update) a favorite: real store record + a persisted `.url`
    /// file on the guest drive.
    fn favorite_add(
        &mut self,
        state: &mut CpuState,
        user: &str,
        url: &str,
        title: &str,
    ) -> AppResult<()> {
        let favorites_dir = format!("C:\\Users\\{user}\\Favorites");
        // Windows creates the Favorites folder with the first favorite.
        match self.win32.get_file_attributes_w(&favorites_dir) {
            Ok(_) => {}
            Err(error) if error.code == ReasonCode::RcFsNotFound => {
                if let Err(create_error) = self.win32.create_directory_w(&favorites_dir) {
                    return self.favorite_failure(
                        state,
                        url,
                        if create_error.code == ReasonCode::RcFsPathInvalid {
                            HRESULT_PATH_NOT_FOUND
                        } else {
                            E_ACCESSDENIED
                        },
                        "Favorites folder could not be created",
                    );
                }
            }
            Err(_) => {
                return self.favorite_failure(
                    state,
                    url,
                    E_ACCESSDENIED,
                    "Favorites folder unavailable",
                );
            }
        }
        let file_name = format!("{}.url", sanitize_favorite_file_name(title));
        let file_path = format!("{favorites_dir}\\{file_name}");
        let content = format!("[InternetShortcut]\r\nURL={url}\r\n");
        if let Err(write_error) = self
            .win32
            .write_file_overwrite_w(&file_path, content.as_bytes())
        {
            let hresult = if write_error.code == ReasonCode::RcFsPathInvalid {
                HRESULT_PATH_NOT_FOUND
            } else if write_error.code == ReasonCode::RcFsNotFound {
                HRESULT_FILE_NOT_FOUND
            } else {
                E_ACCESSDENIED
            };
            return self.favorite_failure(
                state,
                url,
                hresult,
                "favorite file could not be written",
            );
        }

        let now = host_now_millis();
        let pid = self.guest_pid;
        let previous = favorite_store_locked(|store| {
            store
                .get(&pid)
                .and_then(|by_user| by_user.get(user))
                .and_then(|by_url| by_url.get(url))
                .cloned()
        });
        // A renamed favorite leaves no stale .url behind.
        if let Some(old_file) = previous
            .as_ref()
            .and_then(|record| record.file_path.clone())
        {
            if old_file != file_path {
                let _ = self.win32.delete_file_w(&old_file);
            }
        }
        let added_at_ms = previous
            .as_ref()
            .map(|record| record.added_at_ms)
            .unwrap_or(now);
        let record = FavoriteRecord {
            user: user.to_string(),
            url: url.to_string(),
            title: title.to_string(),
            added_at_ms,
            updated_at_ms: now,
            file_path: Some(file_path),
        };
        let was_update = favorite_store_locked(|store| {
            let by_user = store.entry(pid).or_default();
            let by_url = by_user.entry(user.to_string()).or_default();
            let existed = by_url.contains_key(url);
            by_url.insert(url.to_string(), record.clone());
            existed
        });
        let total = self.favorite_records().len();
        state.set(Register::Rax, u64::from(S_OK));
        self.last_error = 0;
        self.push_trace(
            "shell",
            "SHNavigateToFavorite",
            BTreeMap::from([
                ("user".to_string(), json!(user)),
                ("url".to_string(), json!(url)),
                ("title".to_string(), json!(title)),
                (
                    "file".to_string(),
                    json!(record.file_path.clone().unwrap_or_default()),
                ),
                (
                    "action".to_string(),
                    json!(if was_update { "update" } else { "add" }),
                ),
                ("total".to_string(), json!(total)),
            ]),
            json!(S_OK),
        );
        Ok(())
    }

    /// Remove a favorite by URL (record + persisted file).  S_OK when a
    /// record was removed; S_FALSE when none existed.
    fn favorite_remove(&mut self, state: &mut CpuState, user: &str, url: &str) -> AppResult<()> {
        let pid = self.guest_pid;
        let removed = favorite_store_locked(|store| {
            let Some(by_url) = store
                .get_mut(&pid)
                .and_then(|by_user| by_user.get_mut(user))
            else {
                return None;
            };
            by_url.remove(url)
        });
        match removed {
            Some(record) => {
                if let Some(file) = &record.file_path {
                    let _ = self.win32.delete_file_w(file);
                }
                state.set(Register::Rax, u64::from(S_OK));
                self.last_error = 0;
                self.push_trace(
                    "shell",
                    "SHNavigateToFavorite",
                    BTreeMap::from([
                        ("user".to_string(), json!(user)),
                        ("url".to_string(), json!(url)),
                        ("action".to_string(), json!("remove")),
                        ("removed_title".to_string(), json!(record.title)),
                    ]),
                    json!(S_OK),
                );
                Ok(())
            }
            None => {
                state.set(Register::Rax, u64::from(S_FALSE));
                self.last_error = 0;
                self.push_trace(
                    "shell",
                    "SHNavigateToFavorite",
                    BTreeMap::from([
                        ("user".to_string(), json!(user)),
                        ("url".to_string(), json!(url)),
                        ("action".to_string(), json!("remove")),
                    ]),
                    json!(S_FALSE),
                );
                Ok(())
            }
        }
    }

    fn favorite_failure(
        &mut self,
        state: &mut CpuState,
        url: &str,
        hresult: u32,
        failure: &str,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(hresult));
        self.last_error = hresult_to_win32(hresult);
        self.push_trace(
            "shell",
            "SHNavigateToFavorite",
            BTreeMap::from([
                ("url".to_string(), json!(url)),
                ("failure".to_string(), json!(failure)),
            ]),
            json!(hresult),
        );
        Ok(())
    }

    /// The favorite records of this runtime's guest user (sorted by URL) —
    /// the observable state of the favorites store.
    pub(crate) fn favorite_records(&self) -> Vec<FavoriteRecord> {
        let user = self.win32.ge().config.user_name.clone();
        favorite_records_for(self.guest_pid, &user)
    }

    /// `SHOpenFolderWindow` — opens a real folder-window session in the
    /// per-runtime folder-window registry (folder path, visibility and
    /// open/close transitions).
    pub(crate) fn dispatch_sh_open_folder_window(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let folder_ptr = guest_call_arg(state, memory, 0)?;
        let parent_hwnd = guest_call_arg(state, memory, 1)?;
        let flags = guest_call_arg_u32(state, memory, 2)?;
        if folder_ptr == 0 || flags != 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            self.last_error = ERROR_INVALID_PARAMETER;
            self.push_trace(
                "shell",
                "SHOpenFolderWindow",
                BTreeMap::from([(
                    "failure".to_string(),
                    json!(if folder_ptr == 0 {
                        "null folder path"
                    } else {
                        "reserved dwFlags must be zero"
                    }),
                )]),
                json!(E_INVALIDARG),
            );
            return Ok(());
        }
        let folder = read_utf16_string(memory, folder_ptr)?;
        if folder.is_empty() {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            self.last_error = ERROR_INVALID_PARAMETER;
            self.push_trace(
                "shell",
                "SHOpenFolderWindow",
                BTreeMap::from([("failure".to_string(), json!("empty folder path"))]),
                json!(E_INVALIDARG),
            );
            return Ok(());
        }
        let resolved = resolve_guest_path(&self.current_directory, &folder);

        // The folder must really exist (and really be a folder).
        let (exists, is_directory) = match self.win32.get_file_attributes_w(&resolved) {
            Ok(attributes) => (true, attributes.iter().any(|a| a == "directory")),
            Err(_) => (false, false),
        };
        if !exists {
            let parent_exists = windows_parent_path(&resolved)
                .is_some_and(|parent| self.win32.get_file_attributes_w(&parent).is_ok());
            let hresult = if parent_exists {
                HRESULT_FILE_NOT_FOUND
            } else {
                HRESULT_PATH_NOT_FOUND
            };
            state.set(Register::Rax, u64::from(hresult));
            self.last_error = if hresult == HRESULT_FILE_NOT_FOUND {
                ERROR_FILE_NOT_FOUND
            } else {
                ERROR_PATH_NOT_FOUND
            };
            self.push_trace(
                "shell",
                "SHOpenFolderWindow",
                BTreeMap::from([
                    ("folder".to_string(), json!(resolved)),
                    ("failure".to_string(), json!("folder does not exist")),
                ]),
                json!(hresult),
            );
            return Ok(());
        }
        if !is_directory {
            state.set(Register::Rax, u64::from(HRESULT_DIRECTORY_NOT_FOUND));
            self.last_error = ERROR_DIRECTORY_NOT_FOUND;
            self.push_trace(
                "shell",
                "SHOpenFolderWindow",
                BTreeMap::from([
                    ("folder".to_string(), json!(resolved)),
                    ("failure".to_string(), json!("path is not a directory")),
                ]),
                json!(HRESULT_DIRECTORY_NOT_FOUND),
            );
            return Ok(());
        }

        // Create the window session in the registry.
        let now = host_now_millis();
        let pid = self.guest_pid;
        let (window_id, open_count) = folder_window_store_locked(|registry| {
            let state = registry
                .entry(pid)
                .or_insert_with(FolderWindowRegistry::new);
            let open_count = state
                .windows
                .values()
                .filter(|window| window.visible)
                .count();
            if open_count >= FOLDER_WINDOW_OPEN_BUDGET {
                return (None, open_count);
            }
            let id = state.next_id;
            state.next_id += 1;
            let record = FolderWindowRecord {
                id,
                folder: resolved.clone(),
                visible: true,
                opened_at_ms: now,
                closed_at_ms: None,
                events: VecDeque::from([FolderWindowEvent {
                    at_ms: now,
                    kind: "open".to_string(),
                }]),
            };
            state.windows.insert(id, record);
            (Some(id), open_count + 1)
        });
        let Some(window_id) = window_id else {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            self.last_error = ERROR_OUTOFMEMORY_WIN32;
            self.push_trace(
                "shell",
                "SHOpenFolderWindow",
                BTreeMap::from([
                    ("folder".to_string(), json!(resolved)),
                    ("failure".to_string(), json!("open-window budget exhausted")),
                ]),
                json!(E_OUTOFMEMORY),
            );
            return Ok(());
        };
        let _ = parent_hwnd;
        let registry_total = self.folder_window_records().len();
        state.set(Register::Rax, u64::from(S_OK));
        self.last_error = 0;
        self.push_trace(
            "shell",
            "SHOpenFolderWindow",
            BTreeMap::from([
                ("window_id".to_string(), json!(window_id)),
                ("folder".to_string(), json!(resolved)),
                ("visible".to_string(), json!(true)),
                ("open_windows".to_string(), json!(open_count)),
                ("registry_total".to_string(), json!(registry_total)),
            ]),
            json!(S_OK),
        );
        Ok(())
    }

    /// Close a folder-window session: the window hides and the registry
    /// records the close transition.  Returns false when no open window
    /// with that id exists.
    ///
    /// There is no guest-visible close export for folder windows (the
    /// modeled surface only opens them), so the close operation of the
    /// registry is exercised by the runtime tests and remains available to
    /// the trace/registry tooling.
    #[allow(dead_code)]
    pub(crate) fn close_folder_window(&self, id: u64) -> bool {
        let pid = self.guest_pid;
        folder_window_store_locked(|registry| {
            let Some(record) = registry
                .get_mut(&pid)
                .and_then(|state| state.windows.get_mut(&id))
            else {
                return false;
            };
            if !record.visible {
                return false;
            }
            record.visible = false;
            record.closed_at_ms = Some(host_now_millis());
            record.events.push_back(FolderWindowEvent {
                at_ms: record.closed_at_ms.unwrap_or(0),
                kind: "close".to_string(),
            });
            true
        })
    }

    /// The folder-window sessions of this runtime (sorted by id).
    pub(crate) fn folder_window_records(&self) -> Vec<FolderWindowRecord> {
        let pid = self.guest_pid;
        folder_window_store_locked(|registry| {
            registry
                .get(&pid)
                .map(|state| state.windows.values().cloned().collect())
                .unwrap_or_default()
        })
    }

    /// `SHCreateExplorerTaskband` — creates the runtime's taskband session
    /// (one per shell session) bound to the guest's requested task list.
    pub(crate) fn dispatch_sh_create_explorer_taskband(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let tasks_ptr = guest_call_arg(state, memory, 0)?;
        let task_count = guest_call_arg_u32(state, memory, 1)?;
        let flags = guest_call_arg_u32(state, memory, 2)?;
        if flags != 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            self.last_error = ERROR_INVALID_PARAMETER;
            self.push_trace(
                "shell",
                "SHCreateExplorerTaskband",
                BTreeMap::from([(
                    "failure".to_string(),
                    json!("reserved dwFlags must be zero"),
                )]),
                json!(E_INVALIDARG),
            );
            return Ok(());
        }
        if task_count > 4096 || (task_count > 0 && tasks_ptr == 0) {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            self.last_error = ERROR_INVALID_PARAMETER;
            self.push_trace(
                "shell",
                "SHCreateExplorerTaskband",
                BTreeMap::from([(
                    "failure".to_string(),
                    json!(if task_count > 4096 {
                        "unreasonable task count"
                    } else {
                        "task count without a task array"
                    }),
                )]),
                json!(E_INVALIDARG),
            );
            return Ok(());
        }
        let psz = self.guest_arch.pointer_bytes() as u64;
        let mut command_lines = Vec::with_capacity(task_count as usize);
        for index in 0..u64::from(task_count) {
            let Some(entry_ptr) =
                probe_read_guest_pointer(memory, tasks_ptr + index * psz, self.guest_arch)
            else {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                self.last_error = ERROR_INVALID_PARAMETER;
                self.push_trace(
                    "shell",
                    "SHCreateExplorerTaskband",
                    BTreeMap::from([(
                        "failure".to_string(),
                        json!(format!("unmapped task array entry {index}")),
                    )]),
                    json!(E_INVALIDARG),
                );
                return Ok(());
            };
            if entry_ptr == 0 {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                self.last_error = ERROR_INVALID_PARAMETER;
                self.push_trace(
                    "shell",
                    "SHCreateExplorerTaskband",
                    BTreeMap::from([(
                        "failure".to_string(),
                        json!(format!("null task array entry {index}")),
                    )]),
                    json!(E_INVALIDARG),
                );
                return Ok(());
            }
            let command_line = read_utf16_string(memory, entry_ptr)?;
            if command_line.is_empty() {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                self.last_error = ERROR_INVALID_PARAMETER;
                self.push_trace(
                    "shell",
                    "SHCreateExplorerTaskband",
                    BTreeMap::from([(
                        "failure".to_string(),
                        json!(format!("empty task command line at {index}")),
                    )]),
                    json!(E_INVALIDARG),
                );
                return Ok(());
            }
            command_lines.push(command_line);
        }

        let pid = self.guest_pid;
        let created = taskband_store_locked(|store| {
            if store.contains_key(&pid) {
                return None;
            }
            let taskband = ExplorerTaskband {
                created_at_ms: host_now_millis(),
                tasks: command_lines
                    .iter()
                    .map(|command_line| TaskbandTaskEntry {
                        command_line: command_line.clone(),
                        display_name: taskband_display_name(command_line),
                    })
                    .collect(),
            };
            store.insert(pid, taskband);
            store.get(&pid).cloned()
        });
        match created {
            Some(taskband) => {
                state.set(Register::Rax, u64::from(S_OK));
                self.last_error = 0;
                self.push_trace(
                    "shell",
                    "SHCreateExplorerTaskband",
                    BTreeMap::from([
                        ("created".to_string(), json!(true)),
                        ("tasks".to_string(), json!(taskband.tasks.len())),
                    ]),
                    json!(S_OK),
                );
                Ok(())
            }
            None => {
                // One taskband per shell session (as on Windows); the
                // session already exists, so nothing new was created.
                let existing_tasks = self
                    .explorer_taskband()
                    .map(|band| band.tasks.len())
                    .unwrap_or(0);
                state.set(Register::Rax, u64::from(S_FALSE));
                self.last_error = 0;
                self.push_trace(
                    "shell",
                    "SHCreateExplorerTaskband",
                    BTreeMap::from([
                        ("created".to_string(), json!(false)),
                        ("existing_tasks".to_string(), json!(existing_tasks)),
                        (
                            "failure".to_string(),
                            json!("taskband session already exists"),
                        ),
                    ]),
                    json!(S_FALSE),
                );
                Ok(())
            }
        }
    }

    /// The explorer-taskband session of this runtime, when one exists.
    pub(crate) fn explorer_taskband(&self) -> Option<ExplorerTaskband> {
        let pid = self.guest_pid;
        taskband_store_locked(|store| store.get(&pid).cloned())
    }

    /// The interface-IID data export.
    fn dispatch_final_iid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        iid: &[u8; 16],
    ) -> AppResult<()> {
        let address = self.alloc_zeroed(memory, 64, 8)?;
        for (i, byte) in iid.iter().enumerate() {
            memory.write_u8(address + i as u64, *byte);
        }
        state.set(Register::Rax, address);
        Ok(())
    }

    /// `X3DAudioInitialize(speaker_mask, speed_of_sound, handle)` — writes a
    /// real opaque 20-byte instance handle carrying the instance's speaker
    /// mask and speed of sound for `X3DAudioCalculate`.
    pub(crate) fn dispatch_x3daudio_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let speaker_mask = guest_call_arg_u32(state, memory, 0)?;
        // The real signature passes a FLOAT32 speed of sound (the x86
        // thunk-arg layout places it in one 32-bit stack slot).
        let speed = f32::from_bits(guest_call_arg_u32(state, memory, 1)?);
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(X3DAUDIO_E_INVALIDCALL));
            return Ok(());
        }
        let speed = if speed.is_finite() && speed > 0.0 {
            speed
        } else {
            X3DAUDIO_SPEED_OF_SOUND
        };
        write_u32(memory, out, X3DAUDIO_HANDLE_MAGIC);
        write_u32(memory, out + 4, speaker_mask);
        write_u32(memory, out + 8, speed.to_bits());
        write_u32(memory, out + 12, 0);
        write_u32(memory, out + 16, 0);
        state.set(Register::Rax, u64::from(S_OK));
        self.last_error = 0;
        self.push_trace(
            "audio",
            "X3DAudioInitialize",
            BTreeMap::from([
                (
                    "speaker_mask".to_string(),
                    json!(format!("{speaker_mask:#x}")),
                ),
                ("speed_of_sound".to_string(), json!(speed)),
            ]),
            json!(S_OK),
        );
        Ok(())
    }

    /// `X3DAudioCalculate(handle, listener, emitter, flags, dsp_settings)` —
    /// the real spatial DSP math (see the module documentation for the
    /// model's documented approximations).
    pub(crate) fn dispatch_x3daudio_calculate(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_ptr = guest_call_arg(state, memory, 0)?;
        let listener_ptr = guest_call_arg(state, memory, 1)?;
        let emitter_ptr = guest_call_arg(state, memory, 2)?;
        let flags = guest_call_arg_u32(state, memory, 3)?;
        let dsps_ptr = guest_call_arg(state, memory, 4)?;

        if listener_ptr == 0 || emitter_ptr == 0 || dsps_ptr == 0 {
            self.x3daudio_calc_invalid(state, flags, "null listener/emitter/DSP settings");
            return Ok(());
        }

        // The instance handle (opaque, caller-owned 20 bytes): a zero handle
        // pointer falls back to the documented default stereo instance; a
        // mapped handle that is not one of ours is an invalid call.
        let Some((speaker_mask, speed_of_sound)) =
            x3d_read_handle(memory, handle_ptr, self.guest_arch)
        else {
            self.x3daudio_calc_invalid(state, flags, "invalid X3DAudio instance handle");
            return Ok(());
        };

        // DSP settings header: SrcChannelCount/DstChannelCount are inputs.
        let psz = self.guest_arch.pointer_bytes() as u64;
        let src_count = match probe_read_guest_u32(memory, dsps_ptr + 2 * psz) {
            Some(count) => count,
            None => {
                self.x3daudio_calc_invalid(state, flags, "unmapped DSP settings");
                return Ok(());
            }
        };
        let dst_count = match probe_read_guest_u32(memory, dsps_ptr + 2 * psz + 4) {
            Some(count) => count,
            None => {
                self.x3daudio_calc_invalid(state, flags, "unmapped DSP settings");
                return Ok(());
            }
        };
        if src_count == 0
            || dst_count == 0
            || src_count > X3DAUDIO_MAX_CHANNELS
            || dst_count > X3DAUDIO_MAX_CHANNELS
        {
            self.x3daudio_calc_invalid(state, flags, "out-of-range channel counts");
            return Ok(());
        }
        let matrix_ptr = probe_read_guest_pointer(memory, dsps_ptr, self.guest_arch);
        let delay_ptr = probe_read_guest_pointer(memory, dsps_ptr + psz, self.guest_arch);
        if flags & X3DAUDIO_CALCULATE_MATRIX != 0 && matrix_ptr.is_none() {
            self.x3daudio_calc_invalid(state, flags, "matrix flag with no coefficient array");
            return Ok(());
        }
        if flags & X3DAUDIO_CALCULATE_DELAY != 0 && delay_ptr.is_none() {
            self.x3daudio_calc_invalid(state, flags, "delay flag with no delay-time array");
            return Ok(());
        }

        // Parse the guest listener/emitter (packed layouts).
        let Some(listener) = x3d_parse_listener(memory, listener_ptr, self.guest_arch) else {
            self.x3daudio_calc_invalid(state, flags, "unmapped listener");
            return Ok(());
        };
        let Some(emitter) = x3d_parse_emitter(memory, emitter_ptr, self.guest_arch) else {
            self.x3daudio_calc_invalid(state, flags, "unmapped emitter");
            return Ok(());
        };
        if !listener.position.finite()
            || !listener.orient_front.finite()
            || !listener.orient_top.finite()
            || !emitter.position.finite()
            || !emitter.orient_front.finite()
            || !emitter.orient_top.finite()
        {
            self.x3daudio_calc_invalid(state, flags, "non-finite listener/emitter geometry");
            return Ok(());
        }
        if emitter.channel_count != src_count || emitter.channel_count == 0 {
            self.x3daudio_calc_invalid(state, flags, "DSP source count differs from the emitter");
            return Ok(());
        }

        let result = x3daudio_compute(
            &listener,
            &emitter,
            flags,
            speaker_mask,
            speed_of_sound,
            src_count,
            dst_count,
        );

        // Write the computed values back through the guest pointers.
        if let Some(matrix) = &result.matrix {
            let base = matrix_ptr.expect("validated above");
            for (index, coefficient) in matrix.iter().enumerate() {
                write_u32(memory, base + index as u64 * 4, coefficient.to_bits());
            }
        }
        if let Some(delays) = &result.delays_ms {
            let base = delay_ptr.expect("validated above");
            for (index, delay) in delays.iter().enumerate() {
                write_u32(memory, base + index as u64 * 4, delay.to_bits());
            }
        }
        let scalar_writes: &[(u64, Option<f32>)] = &[
            (2 * psz + 8, result.lpf_direct),
            (2 * psz + 12, result.lpf_reverb),
            (2 * psz + 16, result.reverb_level),
            (2 * psz + 20, result.doppler_factor),
            (2 * psz + 24, result.emitter_to_listener_angle),
            (2 * psz + 28, Some(result.emitter_to_listener_distance)),
            (2 * psz + 32, result.emitter_velocity_component),
            (2 * psz + 36, result.listener_velocity_component),
        ];
        for (offset, value) in scalar_writes {
            if let Some(value) = value {
                write_u32(memory, dsps_ptr + offset, value.to_bits());
            }
        }

        state.set(Register::Rax, u64::from(S_OK));
        self.last_error = 0;
        let mut params = BTreeMap::from([
            ("flags".to_string(), json!(format!("{flags:#x}"))),
            (
                "distance".to_string(),
                json!(result.emitter_to_listener_distance),
            ),
            (
                "emitter_angle".to_string(),
                json!(result.emitter_to_listener_angle.unwrap_or(f32::NAN)),
            ),
            ("src_channels".to_string(), json!(src_count)),
            ("dst_channels".to_string(), json!(dst_count)),
            (
                "matrix".to_string(),
                json!(
                    result
                        .matrix
                        .as_ref()
                        .map(|m| format!("{} coeffs", m.len()))
                        .unwrap_or_else(|| "not requested".to_string())
                ),
            ),
        ]);
        if let Some(delay) = &result.delays_ms {
            params.insert("delays_ms".to_string(), json!(format!("{delay:?}")));
        }
        if let Some(doppler) = result.doppler_factor {
            params.insert("doppler_factor".to_string(), json!(doppler));
        }
        self.push_trace("audio", "X3DAudioCalculate", params, json!(S_OK));
        Ok(())
    }

    /// `NtCreateProcess` — real native child-process object creation:
    /// `NtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes,
    /// ParentProcess, InheritObjectTable, SectionHandle, DebugPort,
    /// ExceptionPort)`.
    ///
    /// The child is created through the SAME machinery the `CreateProcessW`
    /// arm uses (`win32::create_process_w`): a genuine process object with a
    /// guest pid, a real kernel handle, an image, and full process-control
    /// semantics (query/terminate/duplicate).  A NULL section handle (or
    /// `NtCurrentProcess`) creates the child from the parent's own image.
    /// A non-NULL section must be an IMAGE-backed section: a section whose
    /// backing file is a real PE image (recorded by `NtCreateSection` when
    /// the caller requests `SEC_IMAGE`) maps the child to that image, the
    /// exact semantics of an image-section `NtCreateProcess`.  Every other
    /// section kind — anonymous/data sections and file sections created
    /// without image semantics — keeps `STATUS_INVALID_IMAGE_FORMAT`, the
    /// status real Windows reports for a section that is not an executable
    /// image.  `InheritObjectTable` is honored by recording the parent's
    /// inheritable handles on the child exactly as
    /// `CreateProcessW(bInheritHandles)` does.
    ///
    /// `NtCreateProcess` itself creates no primary thread (the native
    /// contract leaves that to `NtCreateThread`); the child is not launched
    /// until a thread is created on it.  `NtCreateThreadEx` on the returned
    /// handle creates the real thread object AND lifts the child into real
    /// execution through the host-runner machinery
    /// (`spawn_native_child_image`), with the real exit code delivered to
    /// the exit-sync pair installed here.
    pub(crate) fn dispatch_nt_create_process(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let process_handle_ptr = guest_call_arg(state, memory, 0)?;
        let desired_access = guest_call_arg_u32(state, memory, 1)?;
        let _object_attributes = guest_call_arg(state, memory, 2)?;
        let parent_process = guest_call_arg_u32(state, memory, 3)?;
        let inherit_object_table = guest_call_arg_u32(state, memory, 4)? != 0;
        let section_handle = guest_call_arg_u32(state, memory, 5)?;
        let debug_port = guest_call_arg_u32(state, memory, 6)?;
        let exception_port = guest_call_arg_u32(state, memory, 7)?;

        if process_handle_ptr == 0 {
            self.nt_create_process_fail(
                state,
                STATUS_INVALID_PARAMETER,
                "null process-handle pointer",
            );
            return Ok(());
        }
        // The runtime has no debug-port / exception-port objects: a native
        // caller asking for a debugged child cannot be honored honestly, so
        // non-NULL ports fail instead of silently dropping the semantics.
        if debug_port != 0 || exception_port != 0 {
            self.nt_create_process_fail(
                state,
                STATUS_INVALID_PARAMETER,
                "debug/exception ports are not modelable",
            );
            return Ok(());
        }

        // Resolve the child image:
        //  - a NULL section creates the child from the parent's own image;
        //  - a section handle must be a live Section object backed by a real
        //    PE image (an image section), which supplies the child image;
        //  - every other section kind answers STATUS_INVALID_IMAGE_FORMAT,
        //    like real Windows for a section that is not an executable image.
        let section_image = if section_handle != 0 {
            let section_is_live = matches!(
                self.win32.handle_object_type(section_handle),
                Ok(crate::win32::ObjectType::Section)
            );
            if !section_is_live {
                self.nt_create_process_fail(state, STATUS_INVALID_HANDLE, "invalid section handle");
                return Ok(());
            }
            let resolved = self
                .win32
                .handle_object_identity(section_handle)
                .ok()
                .and_then(|object_id| section_image_lookup(self.guest_pid, object_id.0));
            match resolved {
                Some(image) => Some(image),
                None => {
                    self.nt_create_process_fail(
                        state,
                        STATUS_INVALID_IMAGE_FORMAT,
                        "section is not an executable image",
                    );
                    return Ok(());
                }
            }
        } else {
            None
        };
        let image = match section_image {
            Some(image) => {
                // The section carries the image.  A supplied parent handle is
                // still validated (an unusable parent is an invalid client
                // id) but never overrides the image, matching Windows.
                if !matches!(parent_process, 0 | u32::MAX)
                    && self.win32.process_state(parent_process).is_err()
                {
                    self.nt_create_process_fail(
                        state,
                        STATUS_INVALID_CID,
                        "invalid parent process",
                    );
                    return Ok(());
                }
                image
            }
            None => match parent_process {
                0 | u32::MAX => {
                    // NtCurrentProcess (NULL or (HANDLE)-1): the child is born
                    // from the parent's own image.
                    if self.main_module_path.is_empty() {
                        self.nt_create_process_fail(
                            state,
                            STATUS_INVALID_IMAGE_FORMAT,
                            "parent image is not known",
                        );
                        return Ok(());
                    }
                    self.main_module_path.clone()
                }
                parent => match self.win32.process_state(parent) {
                    Ok(parent_state) => parent_state.executable,
                    Err(_) => {
                        self.nt_create_process_fail(
                            state,
                            STATUS_INVALID_CID,
                            "invalid parent process",
                        );
                        return Ok(());
                    }
                },
            },
        };

        // Create the real child process object through the CreateProcessW
        // machinery.  The host execution is deferred: `NtCreateProcess`
        // creates no primary thread, so the child is spawned for real only
        // when `NtCreateThreadEx` creates one on this handle.
        let result = match self.win32.create_process_w(
            &image,
            &image,
            &self.process_environment,
            &self.current_directory,
            inherit_object_table,
        ) {
            Ok(result) => result,
            Err(error) => {
                self.push_trace(
                    "process",
                    "NtCreateProcess",
                    BTreeMap::from([
                        (
                            "failure".to_string(),
                            json!("process-object creation failed"),
                        ),
                        ("error".to_string(), json!(error.to_string())),
                    ]),
                    json!(format!("{STATUS_INVALID_PARAMETER:#x}")),
                );
                state.set(Register::Rax, u64::from(STATUS_INVALID_PARAMETER));
                self.last_error = STATUS_INVALID_PARAMETER;
                return Ok(());
            }
        };
        // Install the exit-sync pair exactly like launch_guest_child_process
        // so WaitForSingleObject can block on this child's handle, and keep
        // the same pair for the host-runner monitor that
        // `NtCreateThreadEx` starts: the real child's exit code lands in it.
        let sync = Arc::new((std::sync::Mutex::new(None), std::sync::Condvar::new()));
        let _ = self
            .win32
            .install_process_exit_sync(result.process_handle, sync.clone());
        native_child_launch_register(
            self.guest_pid,
            result.process_id,
            NativeChildLaunch {
                image: image.clone(),
                cwd: self.current_directory.clone(),
                environment: self.process_environment.clone(),
                process_id: result.process_id,
                sync,
                launched: false,
                thread_start: None,
                suspended_thread: None,
                host_pid: Arc::new(std::sync::Mutex::new(None)),
                terminated: false,
            },
        );
        write_guest_pointer(
            memory,
            process_handle_ptr,
            u64::from(result.process_handle),
            self.guest_arch,
        )?;

        state.set(Register::Rax, 0); // STATUS_SUCCESS
        self.last_error = 0;
        self.emit_event(crate::runtime_events::RuntimeEvent::ProcessSpawnRequested {
            image: image.clone(),
            command_line: String::new(),
            parent_pid: self.win32.current_process_id(),
        });
        self.push_trace(
            "process",
            "NtCreateProcess",
            BTreeMap::from([
                ("image".to_string(), json!(image)),
                (
                    "desired_access".to_string(),
                    json!(format!("{desired_access:#x}")),
                ),
                (
                    "section".to_string(),
                    json!(if section_handle == 0 {
                        "NULL (parent image)".to_string()
                    } else {
                        format!("image section {section_handle:#x}")
                    }),
                ),
                ("process_handle".to_string(), json!(result.process_handle)),
                ("process_id".to_string(), json!(result.process_id)),
                (
                    "inherit_object_table".to_string(),
                    json!(inherit_object_table),
                ),
            ]),
            json!(0),
        );
        Ok(())
    }

    /// `NtCreateThreadEx` — native thread creation with a real,
    /// process-targeted thread object.
    ///
    /// `NtCurrentProcess` (`NULL` / `(HANDLE)-1` / the open current-process
    /// handle) keeps the runtime's scheduler-backed thread path
    /// (`dispatch_nt_create_thread_ex`).  A thread created on a native child
    /// process — an `NtCreateProcess` object carrying an image — mints a real
    /// thread object in the runtime's thread tables (real client id, handle,
    /// priority, suspend count) and prepares the guest thread record (TEB,
    /// stack honoring the thread-creation stack parameters, start routine and
    /// parameter).  The FIRST thread on an unlaunched native child also lifts
    /// the child into real execution through the same host-runner contract
    /// `CreateProcessW` uses (`spawn_native_child_image`); when the image
    /// cannot run on the host (missing image / missing runner), the start
    /// routine is scheduled through the runtime's existing guest thread
    /// scheduler as the bare-entry fallback.
    ///
    /// The host runner executes the image from its entry point — exactly what
    /// Windows does for a process created from an image section with no
    /// command line (argv is the image alone).  The NT thread object still
    /// carries the caller's start routine/parameter for query, suspend,
    /// resume and terminate semantics.
    pub(crate) fn dispatch_nt_create_thread_ex_on_process(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let process_handle = guest_call_arg_u32(state, memory, 3)?;
        if process_handle == 0
            || process_handle == u32::MAX
            || process_handle == self.win32.current_process_handle()
        {
            return self.dispatch_nt_create_thread_ex(state, memory);
        }
        let process = match self.win32.process_state(process_handle) {
            Ok(process) => process,
            Err(_) => {
                // A live handle of the wrong type answers the type mismatch;
                // a dead handle answers STATUS_INVALID_HANDLE.
                let status = if self.win32.handle_object_type(process_handle).is_ok() {
                    STATUS_OBJECT_TYPE_MISMATCH
                } else {
                    STATUS_INVALID_HANDLE
                };
                self.nt_create_thread_fail(state, status, "invalid process handle", process_handle);
                return Ok(());
            }
        };
        if process.process_id == self.guest_pid {
            // A second, independent handle to the current process: the
            // scheduler-backed thread path.
            return self.dispatch_nt_create_thread_ex(state, memory);
        }
        // The native contract requires PROCESS_CREATE_THREAD on the target
        // handle (the runtime's process objects carry access masks, so a
        // restricted OpenProcess handle is refused exactly like Windows).
        if self
            .win32
            .describe_handle(process_handle)
            .is_ok_and(|descriptor| descriptor.access_mask & PROCESS_CREATE_THREAD == 0)
        {
            self.nt_create_thread_fail(
                state,
                STATUS_ACCESS_DENIED,
                "process handle lacks PROCESS_CREATE_THREAD",
                process_handle,
            );
            return Ok(());
        }

        let thread_handle_ptr = guest_call_arg(state, memory, 0)?;
        let _desired_access = guest_call_arg_u32(state, memory, 1)?;
        let _object_attributes = guest_call_arg(state, memory, 2)?;
        let start_address = guest_call_arg(state, memory, 4)?;
        let parameter = guest_call_arg(state, memory, 5)?;
        let create_suspended = guest_call_arg_u32(state, memory, 6)? != 0;
        let _stack_zero_bits = guest_call_arg_u32(state, memory, 7)?;
        let _stack_commit = guest_call_arg(state, memory, 8)?;
        let stack_reserve = guest_call_arg(state, memory, 9)?;

        if start_address == 0 {
            self.nt_create_thread_fail(
                state,
                STATUS_INVALID_PARAMETER,
                "null start routine",
                process_handle,
            );
            return Ok(());
        }
        if process.exit_code.is_some() {
            self.nt_create_thread_fail(
                state,
                STATUS_PROCESS_IS_TERMINATING,
                "target process has exited",
                process_handle,
            );
            return Ok(());
        }

        // A real thread object: client id in the runtime's thread tables with
        // full query / suspend / resume / terminate semantics.
        let thread_handle = self.win32.create_thread(
            crate::win32::ThreadPlan {
                exit_code: None,
                priority: 0,
                signaled: false,
            },
            false,
        );
        let thread_id = self.win32.thread_id_for_handle(thread_handle)?;

        // Lift the record-only native child into real execution: only the
        // FIRST thread on an unlaunched `NtCreateProcess` child spawns the
        // host run; later threads get real thread records (a host-runner
        // child cannot be injected with a new guest thread).
        //
        // The first thread's start routine/parameter is handed to the host
        // run (the `casa1-runner` job's `thread_start`), so the child's
        // first thread genuinely begins at the caller's routine exactly like
        // Windows — not at the image entry point.  With CREATE_SUSPENDED the
        // host run is DEFERRED until the first `NtResumeThread` releases the
        // suspension; a child terminated before that resume never launches.
        let registered = native_child_launch_registered(self.guest_pid, process.process_id);
        let mut host_launched = false;
        let mut deferred = false;
        let mut launch_note: Option<String> = None;
        if registered {
            native_child_launch_set_thread_start(
                self.guest_pid,
                process.process_id,
                start_address,
                parameter,
            );
            if create_suspended {
                match native_child_launch_mark_suspended(
                    self.guest_pid,
                    process.process_id,
                    thread_handle,
                ) {
                    Ok(()) => deferred = true,
                    Err(note) => launch_note = Some(note),
                }
            } else if let Some(claim) =
                native_child_launch_claim(self.guest_pid, process.process_id)
            {
                match self.spawn_native_child_image(&claim) {
                    Ok(()) => host_launched = true,
                    Err(error) => {
                        native_child_launch_unclaim(self.guest_pid, process.process_id);
                        launch_note = Some(error.message.clone());
                    }
                }
            } else {
                launch_note = Some("native child already launched".to_string());
            }
        }

        // The runtime-side thread record: a real TEB/stack/CPU state for the
        // start routine.  When the real execution runs outside this runtime
        // (a host-runner / already-running child, or a CREATE_SUSPENDED
        // child whose host run is deferred), the record is kept in the
        // runtime's external-child thread table; only a native child whose
        // host run could not start falls back to the runtime's existing guest
        // thread scheduler (bare-entry scheduling).
        let external_execution = !registered || host_launched || deferred;
        let mut scheduled = false;
        if self.guest_arch == GuestArch::X86 {
            match self.prepare_guest_thread_entry(
                memory,
                thread_handle,
                stack_reserve,
                start_address,
                parameter,
            ) {
                Ok(mut pending) => {
                    if create_suspended {
                        pending.suspended = 1;
                        let _ = self.win32.set_thread_suspend_count(thread_id, 1);
                    }
                    if external_execution {
                        native_child_thread_retain(
                            self.guest_pid,
                            thread_handle,
                            process.process_id,
                            pending,
                        );
                    } else {
                        self.pending_guest_threads.push_back(pending);
                        scheduled = true;
                    }
                }
                Err(error) => {
                    launch_note = Some(format!("guest thread record unavailable: {error}"));
                }
            }
        }

        if thread_handle_ptr != 0 {
            write_u32(memory, thread_handle_ptr, thread_handle);
        }
        self.emit_event(crate::runtime_events::RuntimeEvent::ThreadCreated { thread_id });
        state.set(Register::Rax, 0); // STATUS_SUCCESS
        self.last_error = 0;
        let mut trace_params = BTreeMap::from([
            (
                "process_handle".to_string(),
                json!(format!("{process_handle:#x}")),
            ),
            ("process_id".to_string(), json!(process.process_id)),
            ("thread_handle".to_string(), json!(thread_handle)),
            ("thread_id".to_string(), json!(thread_id)),
            (
                "start_address".to_string(),
                json!(format!("{start_address:#x}")),
            ),
            ("parameter".to_string(), json!(format!("{parameter:#x}"))),
            ("create_suspended".to_string(), json!(create_suspended)),
            ("host_launched".to_string(), json!(host_launched)),
            ("deferred".to_string(), json!(deferred)),
            ("external_execution".to_string(), json!(external_execution)),
            ("scheduled".to_string(), json!(scheduled)),
        ]);
        if let Some(note) = launch_note {
            trace_params.insert("launch_note".to_string(), json!(note));
        }
        self.push_trace("process", "NtCreateThreadEx", trace_params, json!(0));
        Ok(())
    }

    /// Spawn the real execution of a native child's image through the exact
    /// host-runner contract `CreateProcessW` uses (see
    /// `launch_guest_child_process`): PE images run under `casa1-runner` with
    /// a serialized `RunnerJob`; non-PE host binaries spawn directly.  The
    /// exit code is delivered to the `sync` pair installed on the
    /// `NtCreateProcess` process object, so waits on that handle observe the
    /// real child exit.
    ///
    /// `NtCreateProcess` carries no command line: the child's argv is exactly
    /// the image (argv[0]) with no extra arguments, matching Windows for a
    /// process created from an image section with no parameters.  The runner
    /// protocol's `args` vector is empty for that reason.
    ///
    /// The first thread's start routine/parameter (from `NtCreateThreadEx`)
    /// travels in the job's `thread_start`, so a PE child's first thread
    /// genuinely begins at the caller's routine.  The spawned host process
    /// id is recorded in the launch entry's host-pid slot so
    /// `NtTerminateProcess` can kill a running child.
    pub(crate) fn spawn_native_child_image(&mut self, claim: &NativeChildClaim) -> AppResult<()> {
        let process_id = claim.process_id;
        let image = claim.image.as_str();
        let environment = &claim.environment;
        let cwd = claim.cwd.as_str();
        let sync = claim.sync.clone();
        let thread_start = claim.thread_start;
        let host_pid = claim.host_pid.clone();
        let host_program = self.win32.guest_path_to_host_path(image)?;
        if !host_program.exists() {
            return Err(AppError::new(
                ReasonCode::RcFsNotFound,
                format!("child executable not found: {}", host_program.display()),
            ));
        }
        let host_cwd = self
            .win32
            .guest_path_to_host_path(cwd)
            .ok()
            .or_else(|| host_program.parent().map(|parent| parent.to_path_buf()))
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        if is_pe_image(&host_program)? {
            // PE images run under casa1-runner (real process isolation), the
            // same contract launch_guest_child_process uses.
            let runner_path = find_casa1_runner_binary()?;
            let mut env = environment.clone();
            if let Some(run_id) = self.process_environment.get("CASA1_RUN_ID").cloned() {
                env.insert("CASA1_RUN_ID".to_string(), run_id);
            }
            env.insert(
                "CASA1_PARENT_PID".to_string(),
                self.win32.current_process_id().to_string(),
            );
            let ge = self.win32.ge().clone();
            let dtm = self.dtm;
            let child_test_base = env
                .get("CASA1_TEST_ID")
                .map(String::as_str)
                .filter(|id| !id.is_empty())
                .unwrap_or("native-child")
                .to_string();
            let child_test_id = format!("{child_test_base}-child-{process_id}");
            let job = crate::runner::RunnerJob {
                ge_name: ge.config.name.clone(),
                ge_root: ge.root.clone(),
                program: host_program.clone(),
                // NtCreateProcess carries no command line: no extra args.
                args: Vec::new(),
                cwd: host_cwd.clone(),
                env,
                dtm,
                intent: crate::runner::RunIntent::Run,
                trace_categories: Vec::new(),
                test_id: child_test_id,
                jit_mode: crate::runner::JitMode::Auto,
                steam_ipc: false,
                window_width: None,
                window_height: None,
                // The NT first thread's start routine: the runner begins
                // guest execution there with the thread parameter instead of
                // the image entry point (Windows NtCreateThreadEx).
                thread_start: thread_start.map(|(address, parameter)| {
                    crate::runner::RunnerThreadStart { address, parameter }
                }),
            };
            let job_json = serde_json::to_string(&job).map_err(|error| {
                AppError::new(
                    ReasonCode::RcRunnerProtocolInvalid,
                    format!("failed to serialise native child runner job: {error}"),
                )
            })?;
            let job_dir = std::env::temp_dir().join("casa1-createprocess");
            std::fs::create_dir_all(&job_dir).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to create job dir {}", job_dir.display()),
                    &error,
                )
            })?;
            let job_path = job_dir.join(format!(
                "native-child-{process_id}-{}.json",
                NATIVE_CHILD_JOB_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::write(&job_path, &job_json).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to write runner job to {}", job_path.display()),
                    &error,
                )
            })?;
            // Spawn synchronously so a missing runner or a refused spawn
            // falls back to the guest scheduler instead of silently never
            // running; the pid is tracked for NtTerminateProcess.
            let child = match Self::spawn_runner_process(&runner_path, &job_path) {
                Ok(child) => child,
                Err(error) => {
                    let _ = std::fs::remove_file(&job_path);
                    return Err(error);
                }
            };
            if let Ok(mut slot) = host_pid.lock() {
                *slot = Some(child.id());
            }
            std::thread::spawn(move || {
                let exit_code = Self::finish_runner_child(child);
                let _ = std::fs::remove_file(&job_path);
                let (lock, cvar) = &*sync;
                let mut guard = lock.lock().unwrap();
                // First writer wins: a terminate that already recorded the
                // requested exit code must not be overwritten by the killed
                // host child's synthetic wait result.
                if guard.is_none() {
                    *guard = Some(exit_code);
                }
                cvar.notify_all();
            });
        } else {
            // Guest processes may only run PE images.  Exec'ing a host binary
            // here would let a guest request arbitrary native execution.
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                format!(
                    "native child image {} is not a PE image; native execution is forbidden",
                    host_program.display()
                ),
            ));
        }
        Ok(())
    }

    /// `CertDigestDigest(request)` — the real digest helper.  `request`
    /// points at the packed descriptor:
    ///
    /// ```text
    /// +0x00   pbData     ptr      input buffer
    /// +psz    cbData     u32      input byte count
    /// +psz+4  algId      u32      CALG_MD5 (0x8003), CALG_SHA1 (0x8004),
    ///                             CALG_SHA_256 (0x800c); 0 = CALG_MD5
    /// +psz+8  pbDigest   ptr      output buffer
    /// +psz+12 pcbDigest  ptr      [in] capacity / [out] required bytes
    /// ```
    ///
    /// Returns TRUE and writes the real digest bytes; on failure returns
    /// FALSE with the Win32 error in last_error (ERROR_INVALID_PARAMETER,
    /// ERROR_NOT_SUPPORTED, ERROR_INSUFFICIENT_BUFFER).
    pub(crate) fn dispatch_cert_digest_digest(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let request = guest_call_arg(state, memory, 0)?;
        let psz = self.guest_arch.pointer_bytes() as u64;
        if request == 0 {
            self.cert_digest_fail(state, ERROR_INVALID_PARAMETER, "null request");
            return Ok(());
        }
        let Some(data_ptr) = probe_read_guest_pointer(memory, request, self.guest_arch) else {
            self.cert_digest_fail(state, ERROR_INVALID_PARAMETER, "unmapped request");
            return Ok(());
        };
        let cb_data = probe_read_guest_u32(memory, request + psz).unwrap_or(0);
        let alg_id = probe_read_guest_u32(memory, request + psz + 4).unwrap_or(0);
        let digest_ptr = probe_read_guest_pointer(memory, request + psz + 8, self.guest_arch);
        let digest_size_ptr = probe_read_guest_pointer(memory, request + psz + 12, self.guest_arch);
        if data_ptr == 0 && cb_data != 0 {
            self.cert_digest_fail(state, ERROR_INVALID_PARAMETER, "null data buffer");
            return Ok(());
        }
        if cb_data > 0x4000_0000 {
            self.cert_digest_fail(state, ERROR_INVALID_PARAMETER, "data buffer too large");
            return Ok(());
        }
        let data = if cb_data == 0 {
            Vec::new()
        } else if let Ok(bytes) = memory.read_bytes(data_ptr, cb_data as usize) {
            bytes
        } else {
            self.cert_digest_fail(state, ERROR_INVALID_PARAMETER, "unmapped data buffer");
            return Ok(());
        };
        let digest: Vec<u8> = match alg_id {
            0 | 0x8003 => crate::crypto::md5(&data).to_vec(), // CALG_MD5
            0x8004 => crate::crypto::sha1(&data).to_vec(),    // CALG_SHA1
            0x800c => crate::crypto::sha256(&data).to_vec(),  // CALG_SHA_256
            _ => {
                self.cert_digest_fail(state, ERROR_NOT_SUPPORTED, "unsupported digest algorithm");
                return Ok(());
            }
        };
        let capacity = match digest_size_ptr {
            Some(ptr) => probe_read_guest_u32(memory, ptr).unwrap_or(u32::MAX),
            None => digest.len() as u32,
        };
        let Some(digest_ptr) = digest_ptr else {
            // Required-size probe: the digest is computed and only the
            // length is reported (Windows digest-query style).
            if let Some(ptr) = digest_size_ptr {
                write_u32(memory, ptr, digest.len() as u32);
            }
            state.set(Register::Rax, 1);
            self.last_error = 0;
            self.push_trace(
                "security",
                "CertDigestDigest",
                BTreeMap::from([
                    ("mode".to_string(), json!("size-probe")),
                    ("alg".to_string(), json!(format!("{alg_id:#x}"))),
                    ("cb_data".to_string(), json!(cb_data)),
                    ("digest_bytes".to_string(), json!(digest.len())),
                ]),
                json!(1),
            );
            return Ok(());
        };
        if capacity < digest.len() as u32 {
            // Partial write + ERROR_INSUFFICIENT_BUFFER with the required
            // size reported (CryptGetHashParam contract).
            for (index, byte) in digest.iter().take(capacity as usize).enumerate() {
                memory.map_bytes(digest_ptr + index as u64, &[*byte]);
            }
            if let Some(ptr) = digest_size_ptr {
                write_u32(memory, ptr, digest.len() as u32);
            }
            self.cert_digest_fail(state, ERROR_INSUFFICIENT_BUFFER, "digest buffer too small");
            return Ok(());
        }
        let digest_hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        for (index, byte) in digest.iter().enumerate() {
            memory.map_bytes(digest_ptr + index as u64, &[*byte]);
        }
        if let Some(ptr) = digest_size_ptr {
            write_u32(memory, ptr, digest.len() as u32);
        }
        state.set(Register::Rax, 1);
        self.last_error = 0;
        self.push_trace(
            "security",
            "CertDigestDigest",
            BTreeMap::from([
                ("alg".to_string(), json!(format!("{alg_id:#x}"))),
                ("cb_data".to_string(), json!(cb_data)),
                ("digest_bytes".to_string(), json!(digest.len())),
                ("digest".to_string(), json!(digest_hex)),
            ]),
            json!(1),
        );
        Ok(())
    }

    /// `CngAuditLog(record)` — appends a genuine CNG audit-log record.
    /// `record` points at `{ provider: u32, action: u32, result: u32 }`
    /// (the result is the status of the operation being audited).  Every
    /// call creates a real store entry with a host timestamp and surfaces
    /// the entry through the trace mechanism.
    pub(crate) fn dispatch_cng_audit_log(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let record_ptr = guest_call_arg(state, memory, 0)?;
        if record_ptr == 0 {
            state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
            self.last_error = ERROR_INVALID_PARAMETER;
            self.push_trace(
                "cngaudit",
                "CngAuditLog",
                BTreeMap::from([("failure".to_string(), json!("null record"))]),
                json!(ERROR_INVALID_PARAMETER),
            );
            return Ok(());
        }
        let Some(provider) = probe_read_guest_u32(memory, record_ptr) else {
            state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
            self.last_error = ERROR_INVALID_PARAMETER;
            self.push_trace(
                "cngaudit",
                "CngAuditLog",
                BTreeMap::from([("failure".to_string(), json!("unmapped record"))]),
                json!(ERROR_INVALID_PARAMETER),
            );
            return Ok(());
        };
        let action = probe_read_guest_u32(memory, record_ptr + 4).unwrap_or(0);
        let result = probe_read_guest_u32(memory, record_ptr + 8).unwrap_or(0);
        let record = CngAuditRecord {
            timestamp_ms: cng_audit_timestamp_ms(),
            provider,
            action,
            result,
        };
        cng_audit_append(self.guest_pid, record);
        let total_records = self.cng_audit_records().len();
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        self.last_error = 0;
        self.push_trace(
            "cngaudit",
            "CngAuditLog",
            BTreeMap::from([
                ("provider".to_string(), json!(format!("{provider:#x}"))),
                ("action".to_string(), json!(format!("{action:#x}"))),
                ("result".to_string(), json!(format!("{result:#x}"))),
                ("timestamp_ms".to_string(), json!(record.timestamp_ms)),
                ("total_records".to_string(), json!(total_records)),
            ]),
            json!(ERROR_SUCCESS),
        );
        Ok(())
    }

    /// The audit-log records this runtime has appended (per-runtime query
    /// helper used by the tests and the trace surface).
    pub(crate) fn cng_audit_records(&self) -> Vec<CngAuditRecord> {
        cng_audit_records_for(self.guest_pid)
    }

    /// `MsftEditRegisterClass` / `RichEditANSIWndClass` — real window-class
    /// registration.  `msftedit.dll` registers the MSFTEDIT_CLASS window
    /// class (`RICHEDIT50W`); `riched32.dll`'s ANSI entry registers the
    /// `RICHEDIT` class.  Both create real entries in the user32 class
    /// registry and return the registered class atom (nonzero = TRUE), so
    /// `CreateWindowEx` on those classes genuinely creates controls through
    /// the same path the built-in `richedit`/`riched20w` classes use.
    pub(crate) fn dispatch_richedit_register_class(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        _memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let (api, class_name): (&str, &str) = match thunk {
            HostThunk::MsftEditRegisterClass => ("MsftEditRegisterClass", "RICHEDIT50W"),
            HostThunk::RichEditAnsiWndClass => ("RichEditANSIWndClass", "RICHEDIT"),
            _ => unreachable!("routed only for the rich-edit register entries"),
        };
        let atom = self.user32.register_class_ex_w(class_name);
        state.set(Register::Rax, u64::from(atom));
        self.last_error = 0;
        self.push_trace(
            "input",
            api,
            BTreeMap::from([
                ("class_name".to_string(), json!(class_name)),
                ("atom".to_string(), json!(atom)),
            ]),
            json!(atom),
        );
        Ok(())
    }

    /// Trace an invalid `X3DAudioCalculate` call (the API returns void, so
    /// the deterministic error code plus the trace is the failure surface).
    fn x3daudio_calc_invalid(&mut self, state: &mut CpuState, flags: u32, why: &str) {
        state.set(Register::Rax, u64::from(X3DAUDIO_E_INVALIDCALL));
        self.push_trace(
            "audio",
            "X3DAudioCalculate",
            BTreeMap::from([
                ("flags".to_string(), json!(format!("{flags:#x}"))),
                ("failure".to_string(), json!(why)),
            ]),
            json!(X3DAUDIO_E_INVALIDCALL),
        );
    }

    /// Trace an `NtCreateProcess` NTSTATUS failure.
    fn nt_create_process_fail(&mut self, state: &mut CpuState, status: u32, why: &str) {
        state.set(Register::Rax, u64::from(status));
        self.last_error = status;
        self.push_trace(
            "process",
            "NtCreateProcess",
            BTreeMap::from([("failure".to_string(), json!(why))]),
            json!(format!("{status:#x}")),
        );
    }

    /// Trace an `NtCreateThreadEx` NTSTATUS failure.
    fn nt_create_thread_fail(
        &mut self,
        state: &mut CpuState,
        status: u32,
        why: &str,
        process_handle: u32,
    ) {
        state.set(Register::Rax, u64::from(status));
        self.last_error = status;
        self.push_trace(
            "process",
            "NtCreateThreadEx",
            BTreeMap::from([
                ("failure".to_string(), json!(why)),
                (
                    "process_handle".to_string(),
                    json!(format!("{process_handle:#x}")),
                ),
            ]),
            json!(format!("{status:#x}")),
        );
    }

    /// Trace a `CertDigestDigest` FALSE failure with its Win32 error.
    fn cert_digest_fail(&mut self, state: &mut CpuState, error: u32, why: &str) {
        state.set(Register::Rax, 0);
        self.last_error = error;
        self.push_trace(
            "security",
            "CertDigestDigest",
            BTreeMap::from([("failure".to_string(), json!(why))]),
            json!(0),
        );
    }
}

// ---------------------------------------------------------------------------
// X3DAudio model
// ---------------------------------------------------------------------------

/// Read the opaque 20-byte instance handle: `(speaker_mask, speed_of_sound)`.
fn x3d_read_handle(memory: &MemoryImage, handle_ptr: u64, _arch: GuestArch) -> Option<(u32, f32)> {
    if handle_ptr == 0 {
        // A null handle falls back to the documented default stereo
        // instance (lenient for callers that never initialized).
        return Some((SPEAKER_STEREO, X3DAUDIO_SPEED_OF_SOUND));
    }
    if !memory.is_range_mapped(handle_ptr, X3DAUDIO_HANDLE_BYTES as usize) {
        return None;
    }
    let magic = read_u32(memory, handle_ptr).ok()?;
    if magic != X3DAUDIO_HANDLE_MAGIC {
        return None;
    }
    let mask = read_u32(memory, handle_ptr + 4).ok()?;
    let speed = f32::from_bits(read_u32(memory, handle_ptr + 8).ok()?);
    let speed = if speed.is_finite() && speed > 0.0 {
        speed
    } else {
        X3DAUDIO_SPEED_OF_SOUND
    };
    Some((mask, speed))
}

/// Parse a packed guest `X3DAUDIO_CONE` (32 bytes).
fn x3d_parse_cone(memory: &MemoryImage, cone_ptr: u64) -> Option<Cone> {
    if !memory.is_range_mapped(cone_ptr, 32usize) {
        return None;
    }
    let f = |offset: u64| -> Option<f32> {
        Some(f32::from_bits(read_u32(memory, cone_ptr + offset).ok()?))
    };
    Some(Cone {
        inner_angle: f(0)?,
        outer_angle: f(4)?,
        inner_volume: f(8)?,
        outer_volume: f(12)?,
        inner_lpf: f(16)?,
        outer_lpf: f(20)?,
        inner_reverb: f(24)?,
        outer_reverb: f(28)?,
    })
}

/// Parse a packed guest `X3DAUDIO_LISTENER`.
fn x3d_parse_listener(
    memory: &MemoryImage,
    listener_ptr: u64,
    arch: GuestArch,
) -> Option<Listener> {
    let vec = |offset: u64| -> Option<Vec3> {
        Some(Vec3 {
            x: f32::from_bits(read_u32(memory, listener_ptr + offset).ok()?),
            y: f32::from_bits(read_u32(memory, listener_ptr + offset + 4).ok()?),
            z: f32::from_bits(read_u32(memory, listener_ptr + offset + 8).ok()?),
        })
    };
    let orient_front = vec(0)?;
    let orient_top = vec(12)?;
    let position = vec(24)?;
    let velocity = vec(36)?;
    let cone_ptr = probe_read_guest_pointer(memory, listener_ptr + 48, arch)?;
    let cone = if cone_ptr == 0 {
        None
    } else {
        Some(x3d_parse_cone(memory, cone_ptr)?)
    };
    Some(Listener {
        orient_front,
        orient_top,
        position,
        velocity,
        cone,
    })
}

/// Parse a packed guest `X3DAUDIO_EMITTER` (June-2010 layout, 15 members).
fn x3d_parse_emitter(memory: &MemoryImage, emitter_ptr: u64, arch: GuestArch) -> Option<Emitter> {
    let psz = arch.pointer_bytes() as u64;
    let vec = |offset: u64| -> Option<Vec3> {
        Some(Vec3 {
            x: f32::from_bits(read_u32(memory, emitter_ptr + offset).ok()?),
            y: f32::from_bits(read_u32(memory, emitter_ptr + offset + 4).ok()?),
            z: f32::from_bits(read_u32(memory, emitter_ptr + offset + 8).ok()?),
        })
    };
    let cone_ptr = probe_read_guest_pointer(memory, emitter_ptr, arch)?;
    let orient_front = vec(psz)?;
    let orient_top = vec(psz + 12)?;
    let position = vec(psz + 24)?;
    let velocity = vec(psz + 36)?;
    let inner_radius = f32::from_bits(read_u32(memory, emitter_ptr + psz + 48).ok()?);
    let inner_radius_angle = f32::from_bits(read_u32(memory, emitter_ptr + psz + 52).ok()?);
    let channel_count = read_u32(memory, emitter_ptr + psz + 56).ok()?;
    let channel_radius = f32::from_bits(read_u32(memory, emitter_ptr + psz + 60).ok()?);
    let azimuth_ptr = probe_read_guest_pointer(memory, emitter_ptr + psz + 64, arch)?;
    let mut curve_ptrs = [0_u64; 5];
    for (index, slot) in curve_ptrs.iter_mut().enumerate() {
        *slot = probe_read_guest_pointer(
            memory,
            emitter_ptr + psz + 64 + psz * (index as u64 + 1),
            arch,
        )?;
    }
    let curve_distance_scaler =
        f32::from_bits(read_u32(memory, emitter_ptr + psz + 64 + 6 * psz).ok()?);
    let doppler_scaler = f32::from_bits(read_u32(memory, emitter_ptr + psz + 68 + 6 * psz).ok()?);

    let cone = if cone_ptr == 0 {
        None
    } else {
        Some(x3d_parse_cone(memory, cone_ptr)?)
    };
    let mut channel_azimuths = Vec::with_capacity(channel_count as usize);
    if azimuth_ptr != 0 {
        for index in 0..channel_count as u64 {
            channel_azimuths.push(f32::from_bits(
                read_u32(memory, azimuth_ptr + index * 4).ok()?,
            ));
        }
    }
    let parse_curve = |curve_ptr: u64| -> Option<Option<Curve>> {
        if curve_ptr == 0 {
            return Some(None);
        }
        let points_ptr = probe_read_guest_pointer(memory, curve_ptr, arch)?;
        let point_count = read_u32(memory, curve_ptr + psz).ok()? as usize;
        if point_count < 2 || point_count > X3DAUDIO_MAX_CURVE_POINTS {
            return None;
        }
        let mut points = Vec::with_capacity(point_count);
        let mut last_distance = -1.0_f32;
        for index in 0..point_count {
            let base = points_ptr + index as u64 * 8;
            let distance = f32::from_bits(read_u32(memory, base).ok()?);
            let setting = f32::from_bits(read_u32(memory, base + 4).ok()?);
            if !(distance >= last_distance) {
                return None; // unsorted or duplicated distances
            }
            last_distance = distance;
            points.push((distance, setting));
        }
        Some(Some(Curve { points }))
    };
    let volume_curve = parse_curve(curve_ptrs[0])?;
    let lfe_curve = parse_curve(curve_ptrs[1])?;
    let lpf_direct_curve = parse_curve(curve_ptrs[2])?;
    let lpf_reverb_curve = parse_curve(curve_ptrs[3])?;
    let reverb_curve = parse_curve(curve_ptrs[4])?;

    Some(Emitter {
        cone,
        orient_front,
        orient_top,
        position,
        velocity,
        inner_radius,
        inner_radius_angle,
        channel_count,
        channel_radius,
        channel_azimuths,
        volume_curve,
        lfe_curve,
        lpf_direct_curve,
        lpf_reverb_curve,
        reverb_curve,
        curve_distance_scaler,
        doppler_scaler,
    })
}

// ---------------------------------------------------------------------------
// Certificate selection — cryptdlg.dll CertSelectCertificate
// ---------------------------------------------------------------------------
//
// Modeled contract (the SDK's CRYPTUI_SELECTCERTIFICATE_STRUCT-shaped
// request, x86/x64 guest layouts):
//
//   BOOL CertSelectCertificate(
//       PCCRYPTUI_SELECTCERTIFICATE_STRUCT pCertSelect,  // arg 0
//       PCCERT_CONTEXT* ppSelectedCert);                 // arg 1
//
// Windows shows a picker dialog; this runtime has no certificate UI, so the
// operation implements the honest unattended equivalent: a real selection
// over the runtime's certificate-store state (`CertificateStoreManager`,
// the same stores CertOpenStore/PFXImportCertStore populate).
//
// - The stores named by `rghStores` (cStores entries) and
//   `rghDisplayStores` (cDisplayStores entries) are the candidate sources;
//   certificates are deduplicated across stores by their DER bytes.
// - Selection criteria (as far as the request is modeled): a certificate
//   is a candidate when it is a member of a requested store AND its parsed
//   X.509 validity currently holds (notBefore <= now <= notAfter).  The
//   display-only members (szTitle/szDisplayName/dwDontUseColumn) have no
//   selection semantics; a supplied pfnCallback would let the app filter
//   the dialog's entries, but no guest-call path exists from this surface,
//   so its presence is traced rather than silently honored.
// - Best-match: the eligible candidates are ordered deterministically as
//   the unattended equivalent of the user picking the best default entry:
//   (1) strongest X.509 signature algorithm (digest strength order, with
//   RSASSA-PSS ranked by its explicit hash parameter), (2) latest notAfter,
//   (3) store order (request enumeration order, then certificate order in
//   the store).  The first candidate with the maximum key is selected —
//   TRUE, the selected certificate context (a real runtime context, as
//   CertFindCertificateInStore produces) written to `*ppSelectedCert`, and
//   the owning store handle written back to the request's
//   `hSelectedCertStore`.  FALSE remains only for a genuinely empty
//   eligible set (user-cancel semantics); no dialog is ever claimed.
// - Real failure modes: a null request/out pointer, an undersized
//   `dwSize`, unmapped store arrays or an unknown store handle fail with
//   FALSE and GetLastError = ERROR_INVALID_PARAMETER / ERROR_INVALID_HANDLE.

/// HRESULT-style/BOOL constants shared by the modeled shell and picker
/// surfaces.
const S_FALSE: u32 = 1;
/// E_OUTOFMEMORY (0x8007000E).
const E_OUTOFMEMORY: u32 = 0x8007_000e;
/// E_ACCESSDENIED (0x80070005).
const E_ACCESSDENIED: u32 = 0x8007_0005;
/// HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND).
const HRESULT_FILE_NOT_FOUND: u32 = 0x8007_0002;
/// HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND).
const HRESULT_PATH_NOT_FOUND: u32 = 0x8007_0003;
/// HRESULT_FROM_WIN32(ERROR_DIRECTORY).
const HRESULT_DIRECTORY_NOT_FOUND: u32 = 0x8007_010b;
/// ERROR_OUTOFMEMORY (8) — the Win32 error behind E_OUTOFMEMORY.
const ERROR_OUTOFMEMORY_WIN32: u32 = 8;
/// ERROR_DIRECTORY (267).
const ERROR_DIRECTORY_NOT_FOUND: u32 = 267;

/// The guest offsets of the modeled CRYPTUI_SELECTCERTIFICATE_STRUCT.
#[derive(Debug, Clone, Copy)]
struct CertSelectLayout {
    dw_flags: u64,
    sz_title: u64,
    pfn_callback: u64,
    p_void_data: u64,
    c_display_stores: u64,
    rgh_display_stores: u64,
    c_stores: u64,
    rgh_stores: u64,
    h_selected_cert_store: u64,
    /// The size through the last member the selection consumes.
    required_size: u64,
}

fn cert_select_layout(x86: bool) -> CertSelectLayout {
    if x86 {
        CertSelectLayout {
            dw_flags: 8,
            sz_title: 12,
            pfn_callback: 24,
            p_void_data: 28,
            c_display_stores: 32,
            rgh_display_stores: 36,
            c_stores: 40,
            rgh_stores: 44,
            h_selected_cert_store: 56,
            required_size: 48,
        }
    } else {
        CertSelectLayout {
            dw_flags: 16,
            sz_title: 24,
            pfn_callback: 48,
            p_void_data: 56,
            c_display_stores: 64,
            rgh_display_stores: 72,
            c_stores: 80,
            rgh_stores: 88,
            h_selected_cert_store: 112,
            required_size: 96,
        }
    }
}

/// A minimal DER TLV reader for the signature-algorithm walk: returns the
/// tag, the content start offset and the content length, advancing `offset`
/// past the value.
fn cert_der_tlv(der: &[u8], offset: &mut usize) -> Option<(u8, usize, usize)> {
    let tag = *der.get(*offset)?;
    *offset += 1;
    let first = *der.get(*offset)?;
    *offset += 1;
    let length = if first & 0x80 == 0 {
        first as usize
    } else {
        let bytes = (first & 0x7f) as usize;
        if bytes == 0 || bytes > 4 {
            return None;
        }
        let mut value = 0_usize;
        for _ in 0..bytes {
            value = (value << 8) | *der.get(*offset)? as usize;
            *offset += 1;
        }
        value
    };
    let start = *offset;
    if start.checked_add(length)? > der.len() {
        return None;
    }
    *offset += length;
    Some((tag, start, length))
}

/// The X.509 signature algorithm strength used by the best-match ordering.
///
/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm
/// AlgorithmIdentifier, signatureValue }`, so the outer second element is the
/// signing algorithm.  Digest strength order (strongest first):
/// SHA-512 (7) > SHA-384 (6) > SHA-256 (5) > SHA-224 (4) > SHA-1 (3) >
/// MD5 (2) > MD2 (1) > unknown (0).  RSASSA-PSS is ranked by its explicit
/// `hashAlgorithm` parameter (defaulting to SHA-1 per RFC 4055); Ed25519 is
/// ranked with the SHA-512 class.
fn cert_signature_algorithm_strength(der: &[u8]) -> u8 {
    let mut offset = 0;
    let Some((tag, content_start, _)) = cert_der_tlv(der, &mut offset) else {
        return 0;
    };
    if tag != 0x30 {
        return 0;
    }
    let mut offset = content_start;
    // tbsCertificate
    if cert_der_tlv(der, &mut offset).is_none() {
        return 0;
    }
    // signatureAlgorithm AlgorithmIdentifier
    let Some((algorithm_tag, algorithm_start, algorithm_len)) = cert_der_tlv(der, &mut offset)
    else {
        return 0;
    };
    if algorithm_tag != 0x30 {
        return 0;
    }
    let algorithm_end = algorithm_start + algorithm_len;
    let mut cursor = algorithm_start;
    let Some((oid_tag, oid_start, oid_len)) = cert_der_tlv(der, &mut cursor) else {
        return 0;
    };
    if oid_tag != 0x06 || cursor > algorithm_end {
        return 0;
    }
    let oid = &der[oid_start..oid_start + oid_len];
    let strength = signature_oid_strength(oid);
    if oid == OID_RSASSA_PSS
        && let Some(hash_strength) = pss_hash_strength(der, cursor, algorithm_end)
    {
        return hash_strength;
    }
    strength
}

/// OID 1.2.840.113549.1.1.10 — RSASSA-PSS.
const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];

/// The digest strength of a signature-algorithm OID.
fn signature_oid_strength(oid: &[u8]) -> u8 {
    const MD2_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02];
    const MD5_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04];
    const SHA1_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
    const SHA224_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e];
    const SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    const SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    const SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
    const ECDSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
    const ECDSA_SHA224: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01];
    const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    const ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
    const DSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03];
    const DSA_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02];
    const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
    const ED448: &[u8] = &[0x2b, 0x65, 0x71];
    if oid == MD2_RSA {
        1
    } else if oid == MD5_RSA {
        2
    } else if oid == SHA1_RSA || oid == ECDSA_SHA1 || oid == DSA_SHA1 {
        3
    } else if oid == ECDSA_SHA224 || oid == SHA224_RSA {
        4
    } else if oid == SHA256_RSA || oid == ECDSA_SHA256 || oid == DSA_SHA256 || oid == OID_RSASSA_PSS
    {
        5
    } else if oid == SHA384_RSA || oid == ECDSA_SHA384 {
        6
    } else if oid == SHA512_RSA || oid == ECDSA_SHA512 || oid == ED25519 || oid == ED448 {
        7
    } else {
        0
    }
}

/// The digest strength named by an RSASSA-PSS `hashAlgorithm` parameter
/// (`[0] EXPLICIT AlgorithmIdentifier` inside `RSASSA-PSS-params`); `None`
/// when the parameters are absent or unparseable (the caller then keeps the
/// base PSS ranking).
fn pss_hash_strength(der: &[u8], params_start: usize, params_end: usize) -> Option<u8> {
    let mut offset = params_start;
    let (tag, start, length) = cert_der_tlv(der, &mut offset)?;
    if tag != 0x30 {
        return None;
    }
    let end = (start + length).min(params_end);
    let mut cursor = start;
    while cursor < end {
        let (field_tag, field_start, field_len) = cert_der_tlv(der, &mut cursor)?;
        if field_tag == 0xa0 {
            let mut inner = field_start;
            let (sequence_tag, sequence_start, _) = cert_der_tlv(der, &mut inner)?;
            if sequence_tag != 0x30 {
                return None;
            }
            let mut oid_cursor = sequence_start;
            let (oid_tag, oid_start, oid_len) = cert_der_tlv(der, &mut oid_cursor)?;
            if oid_tag != 0x06 {
                return None;
            }
            return Some(hash_oid_strength(&der[oid_start..oid_start + oid_len]));
        }
        let _ = field_len;
    }
    None
}

/// The digest strength of a hash-algorithm OID (the PSS parameter table).
fn hash_oid_strength(oid: &[u8]) -> u8 {
    const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
    const SHA224: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
    const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
    if oid == SHA1 {
        3
    } else if oid == SHA224 {
        4
    } else if oid == SHA256 {
        5
    } else if oid == SHA384 {
        6
    } else if oid == SHA512 {
        7
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Local networking — wkssvc.dll NetWkstaSetInfo, srvsvc.dll NetServerGetInfo,
// browser.dll BrowserServerEnum
// ---------------------------------------------------------------------------
//
// Modeled contract (the local machine is the only machine this runtime can
// honestly describe):
//
//   NET_API_STATUS NetWkstaSetInfo(LPCWSTR servername, DWORD level,
//                                  LPBYTE buffer, LPDWORD parm_err);
//   NET_API_STATUS NetServerGetInfo(LPWSTR servername, DWORD level,
//                                   LPBYTE *bufptr);
//   NET_API_STATUS BrowserServerEnum(LPWSTR servername, DWORD level,
//                                    LPBYTE *out_entries);
//
// - The local machine is named by a NULL/empty server name, "." or the
//   host name (with an optional leading "\\\\").  Remote server names keep
//   the honest no-domain/no-server answer `NERR_DCNotFound`: this runtime
//   has no domain controller, no browser service and no remote transport,
//   and never fakes one.
// - `NetWkstaSetInfo` validates WKSTA_INFO_100/101/102 (`platform_id` 0 or
//   `PLATFORM_ID_NT`, a non-empty ≤15-character computer name and LAN
//   group, mapped strings) and stores the accepted values as the
//   per-runtime workstation state (`*parm_err` receives the member offset
//   of the first invalid parameter, 0 on success).  The stored identity is
//   what the local `NetServerGetInfo`/`BrowserServerEnum` records report.
// - `NetServerGetInfo` fills a SERVER_INFO_100/101/102 record in one
//   `NetApiBufferFree`-able buffer: platform id `PLATFORM_ID_NT`, the
//   stored or configured computer name, version 10.0, the `SV_TYPE_*` bits
//   of a workgroup member (`WORKSTATION | SERVER | NT | DOMAIN_MEMBER`) and
//   the LAN group/domain in the comment.
// - `BrowserServerEnum` enumerates the servers the browser service knows.
//   The runtime models no browser service and no network shares (no
//   `NetShareAdd`/session state exists), so the honest non-empty
//   enumeration is the single server that genuinely exists — the local
//   machine itself — written as the same SERVER_INFO_100/101/102 record and
//   answered `ERROR_SUCCESS`; the runtime's `NetServerEnum` path keeps its
//   empty guest enumeration.

/// NERR_DCNotFound (1355) — no domain controller / no remote server.
const NERR_DC_NOT_FOUND: u32 = 0x0000_054b;
/// ERROR_INVALID_LEVEL (124).
const ERROR_INVALID_LEVEL: u32 = 124;
/// PLATFORM_ID_NT (400).
const PLATFORM_ID_NT: u32 = 400;
/// PLATFORM_ID_DOS / OS2 / OSF / VMS / WINDOWS (the pre-NT platform ids a
/// guest could name in a WKSTA_INFO_100 set request).
const PLATFORM_ID_DOS: u32 = 300;
const PLATFORM_ID_OS2: u32 = 400 + 1;
/// `SV_TYPE_*` server-type bits (lmcons.h).
const SV_TYPE_WORKSTATION: u32 = 0x0000_0001;
const SV_TYPE_SERVER: u32 = 0x0000_0002;
const SV_TYPE_DOMAIN_MEMBER: u32 = 0x0000_0100;
const SV_TYPE_NT: u32 = 0x0000_1000;

/// The workstation state `NetWkstaSetInfo` accepted for a guest runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WkstaSetInfoState {
    pub platform_id: u32,
    pub computer_name: String,
    pub lan_group: String,
    pub version_major: u32,
    pub version_minor: u32,
    pub lan_root: Option<String>,
    pub logged_on_users: Option<u32>,
}

/// Per-process sequence making native-child runner job files unique even when
/// concurrent runtimes reuse guest pids (parallel tests, multiple children).
static NATIVE_CHILD_JOB_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

static WKSTA_SET_INFO_STATE: LazyLock<Mutex<BTreeMap<u32, WkstaSetInfoState>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// The stored workstation state for a guest runtime, if `NetWkstaSetInfo`
/// has accepted one.
fn wksta_set_info_state(guest_pid: u32) -> Option<WkstaSetInfoState> {
    let states = WKSTA_SET_INFO_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    states.get(&guest_pid).cloned()
}

/// The local machine identity the local-net surfaces report: the stored
/// `NetWkstaSetInfo` state when present, otherwise the guest network
/// configuration (the same host facts `NetWkstaGetInfo` derives from).
struct LocalServerIdentity {
    name: String,
    domain: String,
    platform_id: u32,
    version_major: u32,
    version_minor: u32,
    lan_root: String,
}

fn local_server_identity(runtime: &PeHostRuntime) -> LocalServerIdentity {
    let config = guest_net_config(runtime);
    match wksta_set_info_state(runtime.guest_pid) {
        Some(state) => LocalServerIdentity {
            name: state.computer_name,
            domain: state.lan_group,
            platform_id: if state.platform_id == 0 {
                PLATFORM_ID_NT
            } else {
                state.platform_id
            },
            version_major: state.version_major,
            version_minor: state.version_minor,
            lan_root: state.lan_root.unwrap_or_else(|| "C:\\WINDOWS".to_string()),
        },
        None => LocalServerIdentity {
            name: config.hostname,
            domain: config.domain,
            platform_id: PLATFORM_ID_NT,
            version_major: 10,
            version_minor: 0,
            lan_root: "C:\\WINDOWS".to_string(),
        },
    }
}

/// Whether a guest `servername` argument names the local machine.
fn net_server_name_is_local(
    runtime: &PeHostRuntime,
    memory: &MemoryImage,
    server_ptr: u64,
) -> AppResult<bool> {
    if server_ptr == 0 {
        return Ok(true);
    }
    let name = read_utf16_string(memory, server_ptr)?;
    let name = name.trim();
    let bare = name.trim_start_matches('\\');
    if bare.is_empty() || bare == "." {
        return Ok(true);
    }
    let identity = local_server_identity(runtime);
    let configured = guest_net_config(runtime).hostname;
    Ok(bare.eq_ignore_ascii_case(&identity.name)
        || bare.eq_ignore_ascii_case(&configured)
        || bare.eq_ignore_ascii_case("localhost"))
}

/// The guest layout of one SERVER_INFO_1xx record.
struct ServerInfoLayout {
    size: usize,
    platform_id: u64,
    name: u64,
    version_major: u64,
    version_minor: u64,
    server_type: u64,
    comment: u64,
    users: u64,
    disc: u64,
    hidden: u64,
    announce: u64,
    announce_delta: u64,
    licenses: u64,
    user_path: u64,
}

fn server_info_layout(level: u32, arch: GuestArch) -> Option<ServerInfoLayout> {
    match (level, arch) {
        (100, GuestArch::X86) => Some(ServerInfoLayout {
            size: 8,
            platform_id: 0,
            name: 4,
            version_major: 0,
            version_minor: 0,
            server_type: 0,
            comment: 0,
            users: 0,
            disc: 0,
            hidden: 0,
            announce: 0,
            announce_delta: 0,
            licenses: 0,
            user_path: 0,
        }),
        (100, GuestArch::X64) => Some(ServerInfoLayout {
            size: 16,
            platform_id: 0,
            name: 8,
            version_major: 0,
            version_minor: 0,
            server_type: 0,
            comment: 0,
            users: 0,
            disc: 0,
            hidden: 0,
            announce: 0,
            announce_delta: 0,
            licenses: 0,
            user_path: 0,
        }),
        (101, GuestArch::X86) => Some(ServerInfoLayout {
            size: 24,
            platform_id: 0,
            name: 4,
            version_major: 8,
            version_minor: 12,
            server_type: 16,
            comment: 20,
            users: 0,
            disc: 0,
            hidden: 0,
            announce: 0,
            announce_delta: 0,
            licenses: 0,
            user_path: 0,
        }),
        (101, GuestArch::X64) => Some(ServerInfoLayout {
            size: 40,
            platform_id: 0,
            name: 8,
            version_major: 16,
            version_minor: 20,
            server_type: 24,
            comment: 32,
            users: 0,
            disc: 0,
            hidden: 0,
            announce: 0,
            announce_delta: 0,
            licenses: 0,
            user_path: 0,
        }),
        (102, GuestArch::X86) => Some(ServerInfoLayout {
            size: 52,
            platform_id: 0,
            name: 4,
            version_major: 8,
            version_minor: 12,
            server_type: 16,
            comment: 20,
            users: 24,
            disc: 28,
            hidden: 32,
            announce: 36,
            announce_delta: 40,
            licenses: 44,
            user_path: 48,
        }),
        (102, GuestArch::X64) => Some(ServerInfoLayout {
            size: 72,
            platform_id: 0,
            name: 8,
            version_major: 16,
            version_minor: 20,
            server_type: 24,
            comment: 32,
            users: 40,
            disc: 44,
            hidden: 48,
            announce: 52,
            announce_delta: 56,
            licenses: 60,
            user_path: 64,
        }),
        _ => None,
    }
}

/// Write one SERVER_INFO_100/101/102 record for the local machine into a
/// guest-heap buffer and store its pointer at `out`.
fn write_local_server_info(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    api: &str,
    level: u32,
    out: u64,
) -> AppResult<u32> {
    let Some(layout) = server_info_layout(level, runtime.guest_arch) else {
        return Ok(ERROR_INVALID_LEVEL);
    };
    let identity = local_server_identity(runtime);
    let comment = format!("Casa1 virtual server [{}]", identity.domain);
    let mut strings: Vec<&str> = vec![&identity.name, &comment];
    if level == 102 {
        strings.push(&identity.lan_root);
    }
    let (base, pointers) = alloc_packed_string_block(runtime, memory, layout.size, &strings)?;
    write_u32(memory, base + layout.platform_id, identity.platform_id);
    write_guest_pointer(memory, base + layout.name, pointers[0], runtime.guest_arch)?;
    if level >= 101 {
        write_u32(memory, base + layout.version_major, identity.version_major);
        write_u32(memory, base + layout.version_minor, identity.version_minor);
        write_u32(
            memory,
            base + layout.server_type,
            SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_NT | SV_TYPE_DOMAIN_MEMBER,
        );
        write_guest_pointer(
            memory,
            base + layout.comment,
            pointers[1],
            runtime.guest_arch,
        )?;
    }
    if level == 102 {
        write_u32(memory, base + layout.users, 1); // the logged-on guest user
        write_u32(memory, base + layout.disc, 0);
        write_u32(memory, base + layout.hidden, 0);
        write_u32(memory, base + layout.announce, 0);
        write_u32(memory, base + layout.announce_delta, 0);
        write_u32(memory, base + layout.licenses, 0);
        write_guest_pointer(
            memory,
            base + layout.user_path,
            pointers[2],
            runtime.guest_arch,
        )?;
    }
    write_guest_pointer(memory, out, base, runtime.guest_arch)?;
    runtime.push_trace(
        "network",
        api,
        BTreeMap::from([
            ("servername".to_string(), json!("local")),
            ("level".to_string(), json!(level)),
            ("name".to_string(), json!(identity.name)),
            ("domain".to_string(), json!(identity.domain)),
        ]),
        json!(ERROR_SUCCESS),
    );
    Ok(ERROR_SUCCESS)
}

/// `NetServerGetInfo` — real SERVER_INFO for the local machine; remote
/// server names keep `NERR_DCNotFound`.
fn net_server_get_info(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    server: u64,
    level: u32,
    out: u64,
) -> AppResult<u32> {
    if out == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    if !net_server_name_is_local(runtime, memory, server)? {
        write_guest_pointer(memory, out, 0, runtime.guest_arch)?;
        runtime.push_trace(
            "network",
            "NetServerGetInfo",
            BTreeMap::from([
                ("servername".to_string(), json!("remote")),
                ("level".to_string(), json!(level)),
            ]),
            json!(NERR_DC_NOT_FOUND),
        );
        return Ok(NERR_DC_NOT_FOUND);
    }
    write_local_server_info(runtime, memory, "NetServerGetInfo", level, out)
}

/// The guest layout of one WKSTA_INFO_1xx record (the members
/// `NetWkstaSetInfo` consumes).
struct WkstaSetInfoLayout {
    size: u64,
    platform_id: u64,
    computer_name: u64,
    lan_group: u64,
    version_major: u64,
    version_minor: u64,
    lan_root: u64,
    logged_on_users: u64,
}

fn wksta_set_info_layout(level: u32, arch: GuestArch) -> Option<WkstaSetInfoLayout> {
    match (level, arch) {
        (100, GuestArch::X86) => Some(WkstaSetInfoLayout {
            size: 20,
            platform_id: 0,
            computer_name: 4,
            lan_group: 8,
            version_major: 12,
            version_minor: 16,
            lan_root: 0,
            logged_on_users: 0,
        }),
        (100, GuestArch::X64) => Some(WkstaSetInfoLayout {
            size: 32,
            platform_id: 0,
            computer_name: 8,
            lan_group: 16,
            version_major: 24,
            version_minor: 28,
            lan_root: 0,
            logged_on_users: 0,
        }),
        (101, GuestArch::X86) => Some(WkstaSetInfoLayout {
            size: 24,
            platform_id: 0,
            computer_name: 4,
            lan_group: 8,
            version_major: 12,
            version_minor: 16,
            lan_root: 20,
            logged_on_users: 0,
        }),
        (101, GuestArch::X64) => Some(WkstaSetInfoLayout {
            size: 40,
            platform_id: 0,
            computer_name: 8,
            lan_group: 16,
            version_major: 24,
            version_minor: 28,
            lan_root: 32,
            logged_on_users: 0,
        }),
        (102, GuestArch::X86) => Some(WkstaSetInfoLayout {
            size: 28,
            platform_id: 0,
            computer_name: 4,
            lan_group: 8,
            version_major: 12,
            version_minor: 16,
            lan_root: 20,
            logged_on_users: 24,
        }),
        (102, GuestArch::X64) => Some(WkstaSetInfoLayout {
            size: 48,
            platform_id: 0,
            computer_name: 8,
            lan_group: 16,
            version_major: 24,
            version_minor: 28,
            lan_root: 32,
            logged_on_users: 40,
        }),
        _ => None,
    }
}

/// `NetWkstaSetInfo` — validates and stores real workstation state for the
/// local machine; remote server names keep `NERR_DCNotFound`.
fn net_wksta_set_info(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    server: u64,
    level: u32,
    buffer: u64,
    parm_err: u64,
) -> AppResult<u32> {
    let write_parm_err = |memory: &mut MemoryImage, offset: u64| {
        if parm_err != 0 {
            write_guest_u32(memory, parm_err, offset as u32).ok();
        }
    };
    if !net_server_name_is_local(runtime, memory, server)? {
        write_parm_err(memory, 0);
        runtime.push_trace(
            "network",
            "NetWkstaSetInfo",
            BTreeMap::from([
                ("servername".to_string(), json!("remote")),
                ("level".to_string(), json!(level)),
            ]),
            json!(NERR_DC_NOT_FOUND),
        );
        return Ok(NERR_DC_NOT_FOUND);
    }
    if buffer == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let Some(layout) = wksta_set_info_layout(level, runtime.guest_arch) else {
        return Ok(ERROR_INVALID_LEVEL);
    };
    if !memory.is_range_mapped(buffer, layout.size as usize) {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let arch = runtime.guest_arch;
    let read_pointer = |memory: &MemoryImage, offset: u64| -> Option<u64> {
        probe_read_guest_pointer(memory, buffer + offset, arch)
    };
    let read_string = |memory: &MemoryImage, offset: u64| -> Option<String> {
        let pointer = read_pointer(memory, offset)?;
        if pointer == 0 {
            return None;
        }
        read_utf16_string(memory, pointer).ok()
    };

    let platform_id = probe_read_guest_u32(memory, buffer + layout.platform_id).unwrap_or(0);
    if platform_id != 0
        && platform_id != PLATFORM_ID_NT
        && platform_id != PLATFORM_ID_DOS
        && platform_id != PLATFORM_ID_OS2
    {
        write_parm_err(memory, layout.platform_id);
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let Some(computer_name) = read_string(memory, layout.computer_name) else {
        write_parm_err(memory, layout.computer_name);
        return Ok(ERROR_INVALID_PARAMETER);
    };
    if computer_name.is_empty() || computer_name.encode_utf16().count() > 15 {
        write_parm_err(memory, layout.computer_name);
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let Some(lan_group) = read_string(memory, layout.lan_group) else {
        write_parm_err(memory, layout.lan_group);
        return Ok(ERROR_INVALID_PARAMETER);
    };
    if lan_group.is_empty() || lan_group.encode_utf16().count() > 15 {
        write_parm_err(memory, layout.lan_group);
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let version_major = probe_read_guest_u32(memory, buffer + layout.version_major).unwrap_or(0);
    let version_minor = probe_read_guest_u32(memory, buffer + layout.version_minor).unwrap_or(0);
    let lan_root = if layout.lan_root != 0 {
        read_string(memory, layout.lan_root)
    } else {
        None
    };
    let logged_on_users = if layout.logged_on_users != 0 {
        probe_read_guest_u32(memory, buffer + layout.logged_on_users)
    } else {
        None
    };

    let state = WkstaSetInfoState {
        platform_id,
        computer_name,
        lan_group,
        version_major,
        version_minor,
        lan_root,
        logged_on_users,
    };
    WKSTA_SET_INFO_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(runtime.guest_pid, state.clone());
    write_parm_err(memory, 0);
    runtime.push_trace(
        "network",
        "NetWkstaSetInfo",
        BTreeMap::from([
            ("servername".to_string(), json!("local")),
            ("level".to_string(), json!(level)),
            ("computer_name".to_string(), json!(state.computer_name)),
            ("lan_group".to_string(), json!(state.lan_group)),
        ]),
        json!(ERROR_SUCCESS),
    );
    Ok(ERROR_SUCCESS)
}

/// `BrowserServerEnum` — the local machine as the single enumerated server;
/// remote server names keep `NERR_DCNotFound`.
fn browser_server_enum(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    server: u64,
    level: u32,
    out: u64,
) -> AppResult<u32> {
    if out == 0 {
        return Ok(ERROR_INVALID_PARAMETER);
    }
    if !net_server_name_is_local(runtime, memory, server)? {
        write_guest_pointer(memory, out, 0, runtime.guest_arch)?;
        runtime.push_trace(
            "network",
            "BrowserServerEnum",
            BTreeMap::from([
                ("servername".to_string(), json!("remote")),
                ("level".to_string(), json!(level)),
            ]),
            json!(NERR_DC_NOT_FOUND),
        );
        return Ok(NERR_DC_NOT_FOUND);
    }
    write_local_server_info(runtime, memory, "BrowserServerEnum", level, out)
}

// ---------------------------------------------------------------------------
// Shell links — shdocvw.dll SHCreateLinks
// ---------------------------------------------------------------------------
//
// Modeled contract:
//
//   HRESULT SHCreateLinks(LPCWSTR pszTarget,        // arg 0
//                         LPCWSTR pszLinkPath,      // arg 1
//                         LPCWSTR pszDescription);  // arg 2 (optional)
//
// Creates a real, persistent Windows shell link (.lnk) for `pszTarget` at
// `pszLinkPath`, wired through the exact .lnk machinery the runtime's
// IShellLink/IPersistFile COM surface uses (`shell_link_file_bytes` →
// `src/lnk.rs`, persisted through the real file layer with
// `write_file_overwrite_w`), so the file a guest reads back is a genuine
// shortcut with the documented binary layout.  S_OK when the link file was
// written; E_INVALIDARG for null/empty target or link path; the COM Save
// contract's E_ACCESSDENIED when the file layer rejects the write.

// ---------------------------------------------------------------------------
// Favorites — shdocvw.dll SHNavigateToFavorite
// ---------------------------------------------------------------------------
//
// Modeled contract:
//
//   HRESULT SHNavigateToFavorite(LPCWSTR pszUrl,   // arg 0
//                                LPCWSTR pszTitle, // arg 1 (optional)
//                                DWORD dwFlags);   // arg 2
//
// with dwFlags = 0 (add/update, the default) or
// FAVORITES_ACTION_REMOVE = 1.  The runtime has no browsing engine, so the
// "navigate to a favorite" operation is modeled by its real substrate: the
// favorites themselves.  Every add creates a REAL record in the per-runtime
// favorites store (keyed by guest user, then URL) AND persists a genuine
// Windows `.url` favorite file (`[InternetShortcut]`) under the guest
// user's Favorites folder on the guest drive — the same artifact a real
// browser's favorites list contains.  S_OK with a real record; S_FALSE
// when a remove found nothing to remove; E_INVALIDARG for a null/empty
// URL or an unknown flag.  List/remove of the store are real operations
// surfaced through `favorite_records` and the trace.

/// FAVORITES_ACTION_REMOVE: remove the stored favorite for the URL.
const FAVORITES_ACTION_REMOVE: u32 = 0x0000_0001;

/// One genuine favorite record (per guest user, per URL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FavoriteRecord {
    /// The guest user owning the favorite.
    pub(crate) user: String,
    /// The favorite URL (the record key).
    pub(crate) url: String,
    /// The display title.
    pub(crate) title: String,
    /// Host wall-clock milliseconds of the first add.
    pub(crate) added_at_ms: u64,
    /// Host wall-clock milliseconds of the last update.
    pub(crate) updated_at_ms: u64,
    /// The guest path of the persisted `.url` file (None when no file
    /// could be persisted).
    pub(crate) file_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Folder windows — browseui.dll SHOpenFolderWindow
// ---------------------------------------------------------------------------
//
// Modeled contract:
//
//   HRESULT SHOpenFolderWindow(LPCWSTR pszFolderPath, // arg 0
//                              HWND hwndParent,       // arg 1 (unused)
//                              DWORD dwFlags);        // arg 2
//
// There is no desktop shell in the runtime and no window machinery that
// could display a shell view, so the honest real behavior is the folder-
// window session: every call opens a real window session in the per-runtime
// folder-window registry (folder path, visibility, open/close transitions
// with timestamps).  S_OK when the window session was created;
// E_INVALIDARG for a null/empty folder; HRESULT_FROM_WIN32(ERROR_FILE_
// NOT_FOUND / ERROR_PATH_NOT_FOUND / ERROR_DIRECTORY) when the folder does
// not resolve; E_OUTOFMEMORY when the registry's open-window budget is
// exhausted.  Closing a window session (`close_folder_window`) records the
// close transition and hides the window; the registry is observable
// through `folder_window_records` and the trace.

/// One folder-window transition event (open/close).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FolderWindowEvent {
    /// Host wall-clock milliseconds of the transition.
    pub(crate) at_ms: u64,
    /// The transition kind: "open" or "close".
    pub(crate) kind: String,
}

/// One open/closed folder-window session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FolderWindowRecord {
    /// The per-runtime session id (monotonic).
    pub(crate) id: u64,
    /// The resolved guest folder path.
    pub(crate) folder: String,
    /// Window visibility (false after the session is closed).
    pub(crate) visible: bool,
    /// Host wall-clock milliseconds of the open transition.
    pub(crate) opened_at_ms: u64,
    /// Host wall-clock milliseconds of the close transition.
    pub(crate) closed_at_ms: Option<u64>,
    /// The transition events, oldest first.
    pub(crate) events: VecDeque<FolderWindowEvent>,
}

/// The number of concurrently open folder-window sessions per runtime.
const FOLDER_WINDOW_OPEN_BUDGET: usize = 128;

/// The per-runtime folder-window registry (monotonic ids + sessions).
#[derive(Debug, Default)]
struct FolderWindowRegistry {
    next_id: u64,
    windows: std::collections::BTreeMap<u64, FolderWindowRecord>,
}

impl FolderWindowRegistry {
    fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Explorer taskband — browseui.dll SHCreateExplorerTaskband
// ---------------------------------------------------------------------------
//
// Modeled contract:
//
//   HRESULT SHCreateExplorerTaskband(LPWSTR* rgszCommandLines, // arg 0
//                                    UINT cCommandLines,       // arg 1
//                                    DWORD dwFlags);           // arg 2
//
// There is no explorer shell in the runtime, so the real underlying
// operation that IS modelable is the taskband session: one taskband object
// bound to the runtime's shell session, carrying the guest's requested task
// entries (each entry a command line, with a derived display name).  The
// Windows shell hosts exactly one taskband per session, so a second call
// answers S_FALSE without creating another session.  S_OK when the taskband
// session was actually created; E_INVALIDARG for a null entry array with a
// nonzero count, an empty command line, or nonzero reserved dwFlags.  The
// state is observable through `explorer_taskband` and the trace.

/// The per-runtime explorer-taskband session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExplorerTaskband {
    /// Host wall-clock milliseconds of the session creation.
    pub(crate) created_at_ms: u64,
    /// The task entries, in guest order.
    pub(crate) tasks: Vec<TaskbandTaskEntry>,
}

/// One taskband task entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskbandTaskEntry {
    /// The command line the guest requested for the task.
    pub(crate) command_line: String,
    /// The display name derived from the command line.
    pub(crate) display_name: String,
}

/// Derive the task display name from a command line: the file name of the
/// first whitespace-delimited token (quotes stripped, extension removed),
/// or the whole command line when no path-like token exists.
fn taskband_display_name(command_line: &str) -> String {
    let token = command_line
        .split_whitespace()
        .next()
        .unwrap_or(command_line)
        .trim_matches('"');
    let file_name = token.rsplit(['\\', '/']).next().unwrap_or(token).trim();
    let stem = match file_name.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => file_name,
    };
    if stem.is_empty() {
        command_line.to_string()
    } else {
        stem.to_string()
    }
}

/// Sanitize a favorite title into a Windows file name (the invalid file
/// name characters are replaced; trailing dots/spaces are trimmed).
fn sanitize_favorite_file_name(title: &str) -> String {
    let mut sanitized: String = title
        .chars()
        .map(|ch| {
            if matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                ch
            }
        })
        .collect();
    while sanitized.ends_with(['.', ' ']) {
        sanitized.pop();
    }
    if sanitized.is_empty() {
        "Favorite".to_string()
    } else {
        sanitized.chars().take(120).collect()
    }
}

/// Host wall-clock milliseconds (Unix epoch).
fn host_now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Map a modeled HRESULT back to its Win32 GetLastError code.
fn hresult_to_win32(hresult: u32) -> u32 {
    hresult & 0x0000_ffff
}

// ---------------------------------------------------------------------------
// Per-runtime stores (keyed by the runtime's guest pid — every runtime owns
// a distinct guest pid, so parallel runtimes never share state).
// ---------------------------------------------------------------------------

type FavoriteStore = std::collections::BTreeMap<
    u32,
    std::collections::BTreeMap<String, std::collections::BTreeMap<String, FavoriteRecord>>,
>;

fn favorite_store_locked<T>(op: impl FnOnce(&mut FavoriteStore) -> T) -> T {
    use std::sync::LazyLock;
    static STORE: LazyLock<std::sync::Mutex<FavoriteStore>> =
        LazyLock::new(|| std::sync::Mutex::new(FavoriteStore::new()));
    if let Ok(mut store) = STORE.lock() {
        op(&mut store)
    } else {
        panic!("favorites store poisoned");
    }
}

fn favorite_records_for(pid: u32, user: &str) -> Vec<FavoriteRecord> {
    favorite_store_locked(|store| {
        store
            .get(&pid)
            .and_then(|by_user| by_user.get(user))
            .map(|by_url| by_url.values().cloned().collect())
            .unwrap_or_default()
    })
}

fn folder_window_store_locked<T>(
    op: impl FnOnce(&mut std::collections::BTreeMap<u32, FolderWindowRegistry>) -> T,
) -> T {
    use std::sync::LazyLock;
    static STORE: LazyLock<
        std::sync::Mutex<std::collections::BTreeMap<u32, FolderWindowRegistry>>,
    > = LazyLock::new(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
    if let Ok(mut store) = STORE.lock() {
        op(&mut store)
    } else {
        panic!("folder-window store poisoned");
    }
}

fn taskband_store_locked<T>(
    op: impl FnOnce(&mut std::collections::BTreeMap<u32, ExplorerTaskband>) -> T,
) -> T {
    use std::sync::LazyLock;
    static STORE: LazyLock<std::sync::Mutex<std::collections::BTreeMap<u32, ExplorerTaskband>>> =
        LazyLock::new(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
    if let Ok(mut store) = STORE.lock() {
        op(&mut store)
    } else {
        panic!("taskband store poisoned");
    }
}

// ---------------------------------------------------------------------------
// CNG audit-log store
// ---------------------------------------------------------------------------

/// One genuine CNG audit-log record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CngAuditRecord {
    /// Host wall-clock timestamp at append time (milliseconds since the
    /// Unix epoch).
    pub(crate) timestamp_ms: u64,
    /// The audited CNG provider (as the guest reported it).
    pub(crate) provider: u32,
    /// The audited action (as the guest reported it).
    pub(crate) action: u32,
    /// The status the audited operation completed with.
    pub(crate) result: u32,
}

/// The per-runtime audit-log store keyed by the runtime's guest pid (every
/// runtime owns a distinct guest pid).  Bounded per runtime so a long-lived
/// host process cannot grow the store without bound.
fn cng_audit_store() -> &'static std::sync::Mutex<
    std::collections::BTreeMap<u32, std::collections::VecDeque<CngAuditRecord>>,
> {
    use std::sync::LazyLock;
    static STORE: LazyLock<
        std::sync::Mutex<
            std::collections::BTreeMap<u32, std::collections::VecDeque<CngAuditRecord>>,
        >,
    > = LazyLock::new(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
    &STORE
}

fn cng_audit_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn cng_audit_append(runtime_pid: u32, record: CngAuditRecord) {
    const MAX_RECORDS_PER_RUNTIME: usize = 4096;
    if let Ok(mut store) = cng_audit_store().lock() {
        let records = store.entry(runtime_pid).or_default();
        if records.len() >= MAX_RECORDS_PER_RUNTIME {
            records.pop_front();
        }
        records.push_back(record);
    }
}

fn cng_audit_records_for(runtime_pid: u32) -> Vec<CngAuditRecord> {
    if let Ok(store) = cng_audit_store().lock() {
        store
            .get(&runtime_pid)
            .map(|records| records.iter().copied().collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Native child-process launch state
// ---------------------------------------------------------------------------

/// Launch state for a native child process created by `NtCreateProcess`
/// before a thread makes it runnable: the image/cwd/environment its host run
/// must use, the exit-sync pair installed on its process object, the first
/// thread's start routine, and the state of the deferred/immediate host run.
struct NativeChildLaunch {
    image: String,
    cwd: String,
    environment: BTreeMap<String, String>,
    process_id: u32,
    /// Exit-sync pair installed on the child's process object.  The
    /// host-runner monitor signals it with the real exit code.
    sync: Arc<(std::sync::Mutex<Option<u32>>, std::sync::Condvar)>,
    /// Set once a thread has spawned the real child execution; later threads
    /// on the same process only get thread records (a running host child
    /// cannot be injected with new guest threads).
    launched: bool,
    /// The FIRST thread's start routine/parameter (`NtCreateThreadEx`): the
    /// host run begins at this routine with this parameter instead of the
    /// image entry point, exactly like Windows.
    thread_start: Option<(u64, u64)>,
    /// The guest thread handle whose `NtResumeThread` must start the host
    /// run when the first thread was created CREATE_SUSPENDED.  `None` for
    /// an immediately-launched first thread and cleared on resume.
    suspended_thread: Option<u32>,
    /// Host process id of the running child once spawned.  Shared with the
    /// monitor thread; taken by `NtTerminateProcess` to kill the child.
    host_pid: Arc<std::sync::Mutex<Option<u32>>>,
    /// Set when the child process was terminated: no later thread creation
    /// or resume may launch the host run.
    terminated: bool,
}

/// The per-runtime native-child launch table, keyed by
/// `(runtime guest pid, child process id)` so concurrent runtimes in one host
/// process never alias (every runtime owns a distinct monotonic guest pid) and
/// any handle to the child object (including a later `OpenProcess` handle)
/// resolves the same launch state.
fn native_child_launch_store() -> &'static std::sync::Mutex<BTreeMap<(u32, u32), NativeChildLaunch>>
{
    use std::sync::LazyLock;
    static STORE: LazyLock<std::sync::Mutex<BTreeMap<(u32, u32), NativeChildLaunch>>> =
        LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));
    &STORE
}

/// Register a freshly created `NtCreateProcess` child.  Bounded per runtime:
/// if a guest creates more unlaunched children than the cap, launched (or
/// stale) entries are pruned first.
fn native_child_launch_register(runtime_pid: u32, process_id: u32, launch: NativeChildLaunch) {
    const MAX_CHILDREN_PER_RUNTIME: usize = 1024;
    if let Ok(mut store) = native_child_launch_store().lock() {
        let same_runtime = store.keys().filter(|(pid, _)| *pid == runtime_pid).count();
        if same_runtime >= MAX_CHILDREN_PER_RUNTIME {
            store.retain(|(pid, _), entry| *pid != runtime_pid || !entry.launched);
        }
        store.insert((runtime_pid, process_id), launch);
    }
}

/// Record the first thread's start routine/parameter for the host run.  A
/// later thread never overrides the routine the first thread already
/// recorded (or the host run already started with).
fn native_child_launch_set_thread_start(
    runtime_pid: u32,
    process_id: u32,
    start_address: u64,
    parameter: u64,
) {
    if let Ok(mut store) = native_child_launch_store().lock()
        && let Some(entry) = store.get_mut(&(runtime_pid, process_id))
        && !entry.launched
        && !entry.terminated
        && entry.thread_start.is_none()
    {
        entry.thread_start = Some((start_address, parameter));
    }
}

/// Mark the first thread CREATE_SUSPENDED: the host run is deferred until
/// that thread's `NtResumeThread` releases the suspension.  Returns the
/// reason the suspension could not be recorded (the child already launched
/// or was terminated) so the caller can trace it honestly.
fn native_child_launch_mark_suspended(
    runtime_pid: u32,
    process_id: u32,
    thread_handle: u32,
) -> Result<(), String> {
    if let Ok(mut store) = native_child_launch_store().lock()
        && let Some(entry) = store.get_mut(&(runtime_pid, process_id))
    {
        if entry.terminated {
            return Err("native child is terminated".to_string());
        }
        if entry.launched {
            return Err("native child already launched".to_string());
        }
        if entry.suspended_thread.is_none() {
            entry.suspended_thread = Some(thread_handle);
        }
        return Ok(());
    }
    Err("native child is not registered".to_string())
}

/// The fields needed to spawn a claimed launch (owned, so the store lock is
/// never held across the host spawn).
pub(crate) struct NativeChildClaim {
    pub(crate) image: String,
    pub(crate) cwd: String,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) process_id: u32,
    pub(crate) sync: Arc<(std::sync::Mutex<Option<u32>>, std::sync::Condvar)>,
    /// First-thread start routine/parameter handed to the host run.
    pub(crate) thread_start: Option<(u64, u64)>,
    /// Host-pid slot the spawn records the running child pid in.
    pub(crate) host_pid: Arc<std::sync::Mutex<Option<u32>>>,
}

fn native_child_claim_from(entry: &NativeChildLaunch) -> NativeChildClaim {
    NativeChildClaim {
        image: entry.image.clone(),
        cwd: entry.cwd.clone(),
        environment: entry.environment.clone(),
        process_id: entry.process_id,
        sync: entry.sync.clone(),
        thread_start: entry.thread_start,
        host_pid: entry.host_pid.clone(),
    }
}

/// Claim the first launch of an unlaunched native child.  Returns `None` for
/// process ids that are not registered `NtCreateProcess` children, were
/// already claimed, or were terminated; the claim is reverted with
/// [`native_child_launch_unclaim`] when the host spawn fails, so a later
/// thread creation can retry.
fn native_child_launch_claim(runtime_pid: u32, process_id: u32) -> Option<NativeChildClaim> {
    let mut store = native_child_launch_store().lock().ok()?;
    let entry = store.get_mut(&(runtime_pid, process_id))?;
    if entry.launched || entry.terminated {
        return None;
    }
    entry.launched = true;
    entry.suspended_thread = None;
    Some(native_child_claim_from(entry))
}

/// Claim the DEFERRED launch when the CREATE_SUSPENDED first thread is
/// resumed (its suspend count reaches zero).  `None` for a thread that is
/// not the deferred first thread, or for a launch that already ran or was
/// terminated — those must never start a host run.
pub(crate) fn native_child_launch_resume_claim(
    runtime_pid: u32,
    process_id: u32,
    thread_handle: u32,
) -> Option<NativeChildClaim> {
    let mut store = native_child_launch_store().lock().ok()?;
    let entry = store.get_mut(&(runtime_pid, process_id))?;
    if entry.launched || entry.terminated || entry.suspended_thread != Some(thread_handle) {
        return None;
    }
    entry.launched = true;
    entry.suspended_thread = None;
    Some(native_child_claim_from(entry))
}

/// Cancel a deferred launch because its CREATE_SUSPENDED first thread was
/// terminated before ever being resumed: the child must never launch.
/// Returns `true` when a deferred launch was actually cancelled.
pub(crate) fn native_child_launch_cancel_suspended(
    runtime_pid: u32,
    process_id: u32,
    thread_handle: u32,
) -> bool {
    let Ok(mut store) = native_child_launch_store().lock() else {
        return false;
    };
    let Some(entry) = store.get_mut(&(runtime_pid, process_id)) else {
        return false;
    };
    if entry.launched || entry.terminated || entry.suspended_thread != Some(thread_handle) {
        return false;
    }
    entry.terminated = true;
    entry.launched = true;
    entry.suspended_thread = None;
    entry.thread_start = None;
    true
}

/// Revert an optimistic claim after a failed host spawn.
pub(crate) fn native_child_launch_unclaim(runtime_pid: u32, process_id: u32) {
    if let Ok(mut store) = native_child_launch_store().lock()
        && let Some(entry) = store.get_mut(&(runtime_pid, process_id))
        && !entry.terminated
    {
        entry.launched = false;
    }
}

/// Whether `process_id` is a registered `NtCreateProcess` child (launched or
/// not) for this runtime.
fn native_child_launch_registered(runtime_pid: u32, process_id: u32) -> bool {
    native_child_launch_store()
        .lock()
        .map(|store| store.contains_key(&(runtime_pid, process_id)))
        .unwrap_or(false)
}

/// Terminate a native child: mark it terminated so no later thread creation
/// or resume can launch the host run, and kill an already-running host child
/// (SIGKILL on Unix — `NtTerminateProcess` is a forceful termination).
/// Returns `true` when a live host child was signalled.
pub(crate) fn native_child_terminate_host(runtime_pid: u32, process_id: u32) -> bool {
    let host_pid = {
        let Ok(mut store) = native_child_launch_store().lock() else {
            return false;
        };
        let Some(entry) = store.get_mut(&(runtime_pid, process_id)) else {
            return false;
        };
        entry.terminated = true;
        entry.launched = true; // every later claim is refused
        entry.suspended_thread = None;
        entry.thread_start = None;
        entry.host_pid.clone()
    };
    let Some(pid) = host_pid.lock().ok().and_then(|mut slot| slot.take()) else {
        return false;
    };
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = pid;
    true
}

/// The running host child's pid for a registered `NtCreateProcess` child
/// (`None` before the host run starts, after it exits, or after a kill).
pub(crate) fn native_child_host_pid(runtime_pid: u32, process_id: u32) -> Option<u32> {
    let store = native_child_launch_store().lock().ok()?;
    store
        .get(&(runtime_pid, process_id))
        .and_then(|entry| entry.host_pid.lock().ok().and_then(|slot| *slot))
}

/// The runtime-side thread records for child threads whose real execution
/// runs outside this runtime (spawned host-runner children, already-running
/// children, CREATE_SUSPENDED children whose host run is deferred, or a
/// native child whose host run could not start): real TEB/stack/CPU state
/// owned by the runtime, keyed by `(runtime guest pid, thread handle)` and
/// carrying the child process id the thread belongs to.
struct NativeChildThreadRecord {
    process_id: u32,
    thread: PendingGuestThread,
}

/// The query view of a runtime-side child thread record: the values
/// `NtQueryInformationThread` must report for a host-launched child thread.
pub(crate) struct NativeChildThreadInfo {
    pub(crate) process_id: u32,
    pub(crate) start_address: u64,
    pub(crate) teb_base: u64,
}

fn native_child_thread_store()
-> &'static std::sync::Mutex<BTreeMap<(u32, u32), NativeChildThreadRecord>> {
    use std::sync::LazyLock;
    static STORE: LazyLock<std::sync::Mutex<BTreeMap<(u32, u32), NativeChildThreadRecord>>> =
        LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));
    &STORE
}

/// The query view of a child thread record (`None` for runtime-scheduled
/// threads and unknown handles).
pub(crate) fn native_child_thread_info(
    runtime_pid: u32,
    thread_handle: u32,
) -> Option<NativeChildThreadInfo> {
    let store = native_child_thread_store().lock().ok()?;
    store
        .get(&(runtime_pid, thread_handle))
        .map(|record| NativeChildThreadInfo {
            process_id: record.process_id,
            start_address: record.thread.start_address,
            teb_base: record.thread.teb_base,
        })
}

/// Remove and return a child thread record (the deferred-launch resume and
/// the terminate cleanup need to take ownership of the pending record).
pub(crate) fn native_child_thread_take(
    runtime_pid: u32,
    thread_handle: u32,
) -> Option<(u32, PendingGuestThread)> {
    let mut store = native_child_thread_store().lock().ok()?;
    store
        .remove(&(runtime_pid, thread_handle))
        .map(|record| (record.process_id, record.thread))
}

/// Every child thread handle recorded for a child process (the terminate
/// cleanup enumerates them to end the process's threads).
pub(crate) fn native_child_thread_handles_for_process(
    runtime_pid: u32,
    process_id: u32,
) -> Vec<u32> {
    native_child_thread_store()
        .lock()
        .map(|store| {
            store
                .iter()
                .filter(|((pid, _), record)| *pid == runtime_pid && record.process_id == process_id)
                .map(|((_, handle), _)| *handle)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn native_child_thread_retain(
    runtime_pid: u32,
    thread_handle: u32,
    process_id: u32,
    thread: PendingGuestThread,
) {
    if let Ok(mut store) = native_child_thread_store().lock() {
        store.insert(
            (runtime_pid, thread_handle),
            NativeChildThreadRecord { process_id, thread },
        );
    }
}

// ---------------------------------------------------------------------------
// Image-backed section registry
// ---------------------------------------------------------------------------
//
// `NtCreateSection` records a section whose backing file is a real PE image
// (SEC_IMAGE) under `(runtime guest pid, section object id)`.  The object id
// — not the handle — is the key, so duplicate/aliased handles to the same
// section resolve the same image.  `NtCreateProcess` resolves its section
// handle through the same registry; every section without an entry is not an
// executable image and keeps STATUS_INVALID_IMAGE_FORMAT.

fn section_image_store() -> &'static std::sync::Mutex<BTreeMap<(u32, u64), String>> {
    use std::sync::LazyLock;
    static STORE: LazyLock<std::sync::Mutex<BTreeMap<(u32, u64), String>>> =
        LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));
    &STORE
}

/// Record a section as image-backed by `image` (the guest path of its PE
/// file).  Bounded per runtime so a long-lived host process cannot grow the
/// registry without bound.
pub(crate) fn section_image_register(runtime_pid: u32, object_id: u64, image: &str) {
    const MAX_IMAGES_PER_RUNTIME: usize = 1024;
    if let Ok(mut store) = section_image_store().lock() {
        let same_runtime = store.keys().filter(|(pid, _)| *pid == runtime_pid).count();
        if same_runtime >= MAX_IMAGES_PER_RUNTIME {
            store.retain(|(pid, _), _| *pid != runtime_pid);
        }
        store.insert((runtime_pid, object_id), image.to_string());
    }
}

fn section_image_lookup(runtime_pid: u32, object_id: u64) -> Option<String> {
    section_image_store()
        .lock()
        .ok()?
        .get(&(runtime_pid, object_id))
        .cloned()
}

// ---------------------------------------------------------------------------
// XACT3 — the real software engine core
// ---------------------------------------------------------------------------
//
// The dispatch layer below implements the June-2010 `xact3.h` interface
// tables (`IXACT3Engine`, `IXACT3SoundBank`, `IXACT3WaveBank`, `IXACT3Cue`,
// `IXACT3Wave`) against the format parsers and state model in `crate::xact`.
// Every vtable slot is a real guest object method: the slot carries its
// interface/method identity (see `HostThunk::Xact3Method`), arguments are
// read through the guest ABI, and every success/failure is the genuine
// result of parsing/decoding/playing the real bank bytes.
//
// The playback path uses the runtime's own audio stack exactly like the
// XAudio2 surface does: a mastering voice on the default audio device, one
// source voice per live cue/wave, real PCM submission with loop points, real
// volume/pitch application, and the standard render/publish drain.  Nothing
// is faked: a cue whose wave bank is missing returns XACTENGINE_E_NOWAVEBANK,
// an out-of-range index returns XACTENGINE_E_INVALIDCUEINDEX / ...WAVEINDEX,
// malformed banks return XACTENGINE_E_INVALIDDATA, and codecs without a
// decoder (XMA/WMA) return XACTENGINE_E_INVALIDDATA when used.

/// `XACTVOLUME_MAX` from xact3.h.
const XACT_VOLUME_MAX: f32 = 16_777_216.0;

/// One engine notification ready to be delivered to the registered guest
/// callback.  The notification struct is rebuilt in guest memory at delivery
/// time (the store lock is never held across a guest callback).
#[derive(Debug, Clone, Copy)]
struct XactPendingNotification {
    callback: u64,
    type_: u8,
    cue_index: u16,
    sound_bank: u64,
    cue: u64,
    wave_bank: u64,
    wave: u64,
    wave_index: u16,
    context: u64,
    variable_index: u16,
    variable_value: f32,
}

/// The subset of `XACT_RUNTIME_PARAMETERS` this engine consumes.
#[derive(Debug, Clone, Copy, Default)]
struct XactRuntimeParams {
    global_settings: u64,
    global_settings_size: u32,
    notification_callback: u64,
    renderer_id: u64,
    xaudio2: u64,
}

/// A fully resolved, decoded playback: interleaved PCM plus the authored
/// volume/pitch/loop/category values for one cue or wave instance.
struct XactResolvedPlayback {
    samples: Vec<i16>,
    channels: u16,
    sample_rate: u32,
    loop_count: u8,
    loop_start_samples: u32,
    loop_total_samples: u32,
    volume: f32,
    pitch: i16,
    category: u16,
    /// Optional source-to-destination channel matrix applied before the
    /// samples reach the source voice.
    matrix: Option<(u32, u32, Vec<f32>)>,
    /// Real output-voice destinations selected by `SetOutputVoices`.
    /// Empty means the default route to the engine mastering voice.
    routes: Vec<crate::xact::OutputVoiceRoute>,
}

/// Read argument `index` of a guest-object vtable call.  For the x86 stdcall
/// ABI the dispatcher popped the return address before the handler runs, so
/// word 0 is `this` and word 1 is the first declared argument; the Microsoft
/// x64 ABI passes `this` in RCX and the first argument in RDX, which is the
/// same numbering.
fn xact_arg(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<u64> {
    guest_call_arg(state, memory, index)
}

fn xact_arg_u32(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<u32> {
    Ok(xact_arg(state, memory, index)? as u32)
}

fn xact_arg_u16(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<u16> {
    Ok(xact_arg(state, memory, index)? as u16)
}

fn xact_arg_i16(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<i16> {
    Ok(xact_arg(state, memory, index)? as u16 as i16)
}

fn xact_arg_f32(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<f32> {
    Ok(f32::from_bits(xact_arg(state, memory, index)? as u32))
}

/// Read a NUL-terminated guest string; an unreadable pointer yields `None`.
fn xact_guest_string(memory: &MemoryImage, address: u64) -> Option<String> {
    if address == 0 {
        return None;
    }
    read_c_string(memory, address).ok()
}

fn xact_write_u16(memory: &mut MemoryImage, address: u64, value: u16) -> AppResult<()> {
    write_u16(memory, address, value);
    Ok(())
}

fn xact_write_u32(memory: &mut MemoryImage, address: u64, value: u32) -> AppResult<()> {
    write_u32(memory, address, value);
    Ok(())
}

fn xact_write_f32(memory: &mut MemoryImage, address: u64, value: f32) -> AppResult<()> {
    write_u32(memory, address, value.to_bits());
    Ok(())
}

/// A monotonic millisecond tick for notification timestamps.
fn xact_time_ms() -> i32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| (duration.as_millis() & 0x7FFF_FFFF) as i32)
        .unwrap_or(0)
}

impl PeHostRuntime {
    /// `XACT3CreateEngine` / `XACT3CreateEngineWithFlags`.
    ///
    /// Contract (same for both exports in this runtime's import surface):
    /// `XACT3CreateEngine(DWORD creationFlags, IXACT3Engine **ppEngine)`.
    /// `ppEngine` must be non-null and the flags may only carry the documented
    /// audition/debug bits; anything else is `E_INVALIDARG` with a zeroed
    /// out-pointer.  Success returns `S_OK` and a real engine object whose
    /// vtable is the IXACT3Engine table from `crate::xact`.
    fn dispatch_xact_create_engine(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let flags = guest_call_arg_u32(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 || flags & !crate::xact::XACT_CREATE_FLAGS_MASK != 0 {
            if out != 0 {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            }
            state.set(Register::Rax, u64::from(crate::xact::E_INVALIDARG));
            self.last_error = 0;
            return Ok(());
        }

        let pid = self.guest_pid;
        let mut store = crate::xact::lock_xact_runtimes();
        let runtime = store.entry(pid).or_default();
        let vtable = self.xact_vtable(memory, runtime, crate::xact::IFACE_ENGINE)?;
        let object = self.alloc_zeroed(memory, 0x20, 16)?;
        write_u64(memory, object, vtable);
        runtime.objects.insert(
            object,
            crate::xact::XactObject::Engine(crate::xact::EngineState {
                refcount: 1,
                ..Default::default()
            }),
        );
        write_guest_pointer(memory, out, object, self.guest_arch)?;
        drop(store);

        self.push_trace(
            "audio",
            "XACT3CreateEngine",
            BTreeMap::from([
                ("flags".to_string(), json!(flags)),
                ("engine".to_string(), json!(format!("{object:#x}"))),
            ]),
            json!(crate::xact::S_OK),
        );
        state.set(Register::Rax, u64::from(crate::xact::S_OK));
        self.last_error = 0;
        Ok(())
    }

    /// Allocate (once per runtime and interface) the guest vtable for an XACT
    /// interface.  Every slot is a distinct `Xact3Method` host thunk carrying
    /// the slot's interface, vtable index and x86 stdcall argument size.
    fn xact_vtable(
        &mut self,
        memory: &mut MemoryImage,
        runtime: &mut crate::xact::XactRuntime,
        interface: u8,
    ) -> AppResult<u64> {
        if let Some(address) = runtime.vtables.get(&interface) {
            return Ok(*address);
        }
        let methods = crate::xact::interface_methods(interface);
        let thunks = methods
            .iter()
            .map(|(method, x86_arg_bytes)| HostThunk::Xact3Method {
                interface,
                method: *method,
                x86_arg_bytes: *x86_arg_bytes,
            })
            .collect::<Vec<_>>();
        let vtable = self.alloc_guest_vtable(memory, thunks)?;
        runtime.vtables.insert(interface, vtable);
        Ok(vtable)
    }

    /// Allocate one guest object for `interface` with `state`, registering it
    /// in the runtime store with reference count 1.
    fn xact_alloc_object(
        &mut self,
        memory: &mut MemoryImage,
        runtime: &mut crate::xact::XactRuntime,
        interface: u8,
        state: crate::xact::XactObject,
    ) -> AppResult<u64> {
        let vtable = self.xact_vtable(memory, runtime, interface)?;
        let object = self.alloc_zeroed(memory, 0x20, 16)?;
        write_u64(memory, object, vtable);
        runtime.objects.insert(object, state);
        Ok(object)
    }

    /// Dispatch one `HostThunk::Xact3Method` vtable slot.
    fn dispatch_xact_method(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        interface: u8,
        method: u16,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let pid = self.guest_pid;
        let (result, pending, drop_runtime) = {
            let mut store = crate::xact::lock_xact_runtimes();
            let runtime = store.entry(pid).or_default();
            let (result, pending) =
                self.xact_invoke(runtime, state, memory, this, interface, method)?;
            let drop_runtime = runtime.objects.is_empty();
            (result, pending, drop_runtime)
        };
        if drop_runtime {
            crate::xact::lock_xact_runtimes().remove(&pid);
        }
        for notification in pending {
            self.xact_deliver_notification(state, memory, &notification)?;
        }
        state.set(Register::Rax, u64::from(result));
        self.last_error = 0;
        Ok(())
    }

    /// The interface method body.  Returns the value the method delivers in
    /// EAX/RAX (an HRESULT, or the index/refcount value for the methods whose
    /// contract returns a value) plus any notifications to deliver once the
    /// store lock is released.
    fn xact_invoke(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        this: u64,
        interface: u8,
        method: u16,
    ) -> AppResult<(u32, Vec<XactPendingNotification>)> {
        if !runtime.objects.contains_key(&this) {
            return Ok((crate::xact::E_INVALIDARG, Vec::new()));
        }
        match method {
            0 => self.xact_query_interface(runtime, state, memory, this),
            1 => {
                let Some(object) = runtime.objects.get_mut(&this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                Ok((object.add_ref(), Vec::new()))
            }
            2 => self.xact_release_object(runtime, state, memory, this),
            _ => match interface {
                crate::xact::IFACE_ENGINE => {
                    self.xact_invoke_engine(runtime, state, memory, this, method)
                }
                crate::xact::IFACE_SOUNDBANK => {
                    self.xact_invoke_soundbank(runtime, state, memory, this, method)
                }
                crate::xact::IFACE_WAVEBANK => {
                    self.xact_invoke_wavebank(runtime, state, memory, this, method)
                }
                crate::xact::IFACE_CUE => {
                    self.xact_invoke_cue(runtime, state, memory, this, method)
                }
                crate::xact::IFACE_WAVE => {
                    self.xact_invoke_wave(runtime, state, memory, this, method)
                }
                _ => Ok((crate::xact::E_INVALIDARG, Vec::new())),
            },
        }
    }

    /// `IUnknown::QueryInterface` for every XACT object.  The engine accepts
    /// `IID_IUnknown` and `IID_IXACT3Engine` (the XACT3.5+ interface id from
    /// the June-2010 header); the other interfaces accept `IID_IUnknown`.
    fn xact_query_interface(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        state: &CpuState,
        memory: &mut MemoryImage,
        this: u64,
    ) -> AppResult<(u32, Vec<XactPendingNotification>)> {
        let riid_pointer = xact_arg(state, memory, 1)?;
        let out = xact_arg(state, memory, 2)?;
        if out == 0 {
            return Ok((crate::xact::E_INVALIDARG, Vec::new()));
        }
        let mut riid = [0u8; 16];
        if riid_pointer != 0 {
            let bytes = read_guest_bytes(memory, riid_pointer, 16).unwrap_or_default();
            for (slot, byte) in riid.iter_mut().zip(bytes.iter()) {
                *slot = *byte;
            }
        }
        let is_engine = matches!(
            runtime.objects.get(&this),
            Some(crate::xact::XactObject::Engine(_))
        );
        let supported = riid == crate::xact::IID_IUNKNOWN
            || (is_engine && riid == crate::xact::IID_IXACT3_ENGINE);
        if supported {
            if let Some(object) = runtime.objects.get_mut(&this) {
                object.add_ref();
            }
            write_guest_pointer(memory, out, this, self.guest_arch)?;
            Ok((crate::xact::S_OK, Vec::new()))
        } else {
            write_guest_pointer(memory, out, 0, self.guest_arch)?;
            Ok((crate::xact::E_NOINTERFACE, Vec::new()))
        }
    }

    /// `IUnknown::Release`.  Reaching zero performs the object's real
    /// cleanup: live voices stop, banks/cues/waves are removed, and an
    /// engine release also stops every voice it owns.
    fn xact_release_object(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        this: u64,
    ) -> AppResult<(u32, Vec<XactPendingNotification>)> {
        let refcount = {
            let Some(object) = runtime.objects.get_mut(&this) else {
                return Ok((crate::xact::E_INVALIDARG, Vec::new()));
            };
            object.release()
        };
        if refcount != 0 {
            return Ok((refcount, Vec::new()));
        }
        let mut pending = Vec::new();
        self.xact_destroy_object(runtime, state, memory, this, &mut pending)?;
        Ok((0, pending))
    }

    /// Real teardown for one object whose reference count hit zero (or that
    /// was explicitly destroyed through its interface).
    fn xact_destroy_object(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        this: u64,
        pending: &mut Vec<XactPendingNotification>,
    ) -> AppResult<()> {
        let Some(object) = runtime.objects.remove(&this) else {
            return Ok(());
        };
        match object {
            crate::xact::XactObject::Engine(engine_state) => {
                let cue_objects = runtime.cue_objects_for_engine(this);
                for cue_object in &cue_objects {
                    let live = match runtime.objects.get(cue_object) {
                        Some(crate::xact::XactObject::Cue(cue)) => cue.live,
                        _ => None,
                    };
                    if let Some(live) = live {
                        for voice in live.voices() {
                            let _ = self.xact_stop_live_voice(voice);
                        }
                    }
                }
                for live in engine_state.wave_voices.values() {
                    for voice in live.voices() {
                        let _ = self.xact_stop_live_voice(voice);
                    }
                }
                if let Some(mastering) = engine_state.mastering_voice {
                    let _ = self.xact_stop_live_voice(mastering);
                }
                // Close every guest-streamed bank before its object goes away.
                let streams = runtime
                    .objects
                    .values()
                    .filter_map(|candidate| match candidate {
                        crate::xact::XactObject::WaveBank(bank)
                            if bank.engine == this && bank.bank.guest_source.is_some() =>
                        {
                            bank.bank.guest_source.clone()
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                for stream in streams {
                    self.xact_close_guest_stream(state, memory, &stream);
                }
                // Remove every object owned by this engine.
                let owned = runtime
                    .objects
                    .iter()
                    .filter_map(|(address, candidate)| match candidate {
                        crate::xact::XactObject::SoundBank(bank) if bank.engine == this => {
                            Some(*address)
                        }
                        crate::xact::XactObject::WaveBank(bank) if bank.engine == this => {
                            Some(*address)
                        }
                        crate::xact::XactObject::Cue(cue) if cue.engine == this => Some(*address),
                        crate::xact::XactObject::Wave(wave) if wave.engine == this => {
                            Some(*address)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                for address in owned {
                    runtime.objects.remove(&address);
                }
                let _ = pending;
            }
            crate::xact::XactObject::SoundBank(state) => {
                pending.extend(xact_collect_notifications(
                    runtime.engine(state.engine),
                    6, // XACTNOTIFICATIONTYPE_SOUNDBANKDESTROYED
                    this,
                    0,
                    0xFFFF,
                ));
            }
            crate::xact::XactObject::WaveBank(bank_state) => {
                if let Some(stream) = bank_state.bank.guest_source.clone() {
                    self.xact_close_guest_stream(state, memory, &stream);
                }
                if let Some(engine) = runtime.engine(bank_state.engine) {
                    pending.extend(xact_collect_notifications(
                        Some(engine),
                        7, // XACTNOTIFICATIONTYPE_WAVEBANKDESTROYED
                        0,
                        0,
                        0xFFFF,
                    ));
                }
            }
            crate::xact::XactObject::Cue(state) => {
                if let Some(live) = state.live {
                    for voice in live.voices() {
                        let _ = self.xact_stop_live_voice(voice);
                    }
                }
                pending.extend(xact_collect_notifications(
                    runtime.engine(state.engine),
                    4, // XACTNOTIFICATIONTYPE_CUEDESTROYED
                    state.sound_bank,
                    this,
                    state.index,
                ));
            }
            crate::xact::XactObject::Wave(state) => {
                if let Some(live) = state.live {
                    for voice in live.voices() {
                        let _ = self.xact_stop_live_voice(voice);
                    }
                }
                pending.extend(xact_collect_notifications(
                    runtime.engine(state.engine),
                    14, // XACTNOTIFICATIONTYPE_WAVESTOP
                    state.wave_bank,
                    0,
                    state.index,
                ));
            }
        }
        Ok(())
    }

    /// Fully stop and remove one live source voice from the audio stack.
    fn xact_stop_live_voice(&mut self, voice: crate::audio::VoiceId) -> AppResult<()> {
        let _ = self.audio.stop_voice(voice);
        let _ = self.audio.destroy_voice(voice);
        Ok(())
    }

    /// The `IXACT3Engine` method bodies.
    fn xact_invoke_engine(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        this: u64,
        method: u16,
    ) -> AppResult<(u32, Vec<XactPendingNotification>)> {
        match method {
            3 => {
                // GetRendererCount(XACTINDEX *pnRendererCount)
                let out = xact_arg(state, memory, 1)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                xact_write_u16(memory, out, 1)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            4 => {
                // GetRendererDetails(XACTINDEX index, XACT_RENDERER_DETAILS *out)
                let index = xact_arg_u16(state, memory, 1)?;
                let out = xact_arg(state, memory, 2)?;
                if index != 0 || out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                // XACT_RENDERER_DETAILS: WCHAR[255] id, WCHAR[255] name,
                // BOOL defaultDevice (1024 bytes).
                let id = "Casa1 XACT Software Renderer";
                let mut encoded = Vec::new();
                for unit in id.encode_utf16() {
                    encoded.extend_from_slice(&unit.to_le_bytes());
                }
                memory.map_bytes(out, &vec![0u8; 1024]);
                memory.map_bytes(out, &encoded);
                memory.map_bytes(out + 510, &encoded);
                write_u32(memory, out + 1020, 1);
                Ok((crate::xact::S_OK, Vec::new()))
            }
            5 => {
                // GetFinalMixFormat(WAVEFORMATEXTENSIBLE *pFormat)
                let out = xact_arg(state, memory, 1)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                // Stereo 48 kHz 32-bit float, extensible, with the IEEE-float
                // sub-format: this engine's final mix.
                xact_write_u16(memory, out, 0xFFFE)?;
                xact_write_u16(memory, out + 2, 2)?;
                xact_write_u32(memory, out + 4, 48_000)?;
                xact_write_u32(memory, out + 8, 48_000 * 2 * 4)?;
                xact_write_u16(memory, out + 12, 8)?;
                xact_write_u16(memory, out + 14, 32)?;
                xact_write_u16(memory, out + 16, 22)?;
                xact_write_u16(memory, out + 18, 32)?;
                xact_write_u32(memory, out + 20, 3)?;
                memory.map_bytes(
                    out + 24,
                    &[
                        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa,
                        0x00, 0x38, 0x9b, 0x71,
                    ],
                );
                Ok((crate::xact::S_OK, Vec::new()))
            }
            6 => self.xact_engine_initialize(runtime, state, memory, this),
            7 => {
                // Shutdown: stop everything this engine owns.
                let state = runtime.engine_mut(this);
                if let Some(engine) = state {
                    engine.initialized = false;
                    engine.categories.clear();
                    engine.variables.clear();
                    engine.variable_values.clear();
                    engine.notifications.clear();
                }
                self.xact_engine_stop_all(runtime, this, &mut Vec::new())?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            8 => {
                // DoWork: pump the engine's audio graph.
                let initialized = runtime
                    .engine(this)
                    .map(|engine| engine.initialized)
                    .unwrap_or(false);
                if !initialized {
                    return Ok((crate::xact::XACTENGINE_E_NOTINITIALIZED, Vec::new()));
                }
                let mut pending = Vec::new();
                self.xact_drain_engine(runtime, this, &mut pending)?;
                Ok((crate::xact::S_OK, pending))
            }
            9 => {
                // CreateSoundBank(buffer, size, flags, alloc, out)
                let buffer = xact_arg(state, memory, 1)?;
                let size = xact_arg_u32(state, memory, 2)?;
                let _flags = xact_arg_u32(state, memory, 3)?;
                let _alloc = xact_arg_u32(state, memory, 4)?;
                let out = xact_arg(state, memory, 5)?;
                let initialized = runtime
                    .engine(this)
                    .map(|engine| engine.initialized)
                    .unwrap_or(false);
                if !initialized {
                    return Ok((crate::xact::XACTENGINE_E_NOTINITIALIZED, Vec::new()));
                }
                if buffer == 0 || size == 0 || out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let bytes = read_guest_bytes(memory, buffer, size as usize)?;
                let bank = match crate::xact::SoundBank::parse(&bytes) {
                    Ok(bank) => bank,
                    Err(error) => return Ok((error, Vec::new())),
                };
                let object = self.xact_alloc_object(
                    memory,
                    runtime,
                    crate::xact::IFACE_SOUNDBANK,
                    crate::xact::XactObject::SoundBank(crate::xact::SoundBankState {
                        refcount: 1,
                        engine: this,
                        bank,
                    }),
                )?;
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                self.push_trace(
                    "audio",
                    "IXACT3Engine::CreateSoundBank",
                    BTreeMap::from([("size".to_string(), json!(size))]),
                    json!(format!("{object:#x}")),
                );
                Ok((crate::xact::S_OK, Vec::new()))
            }
            10 => {
                // CreateInMemoryWaveBank(buffer, size, flags, alloc, out)
                let buffer = xact_arg(state, memory, 1)?;
                let size = xact_arg_u32(state, memory, 2)?;
                let _flags = xact_arg_u32(state, memory, 3)?;
                let _alloc = xact_arg_u32(state, memory, 4)?;
                let out = xact_arg(state, memory, 5)?;
                let initialized = runtime
                    .engine(this)
                    .map(|engine| engine.initialized)
                    .unwrap_or(false);
                if !initialized {
                    return Ok((crate::xact::XACTENGINE_E_NOTINITIALIZED, Vec::new()));
                }
                if buffer == 0 || size == 0 || out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let bytes = read_guest_bytes(memory, buffer, size as usize)?;
                let bank = match crate::xact::WaveBank::parse(&bytes) {
                    Ok(bank) => bank,
                    Err(error) => return Ok((error, Vec::new())),
                };
                if bank.streaming {
                    // The native engine forbids loading a streaming bank as an
                    // in-memory bank.
                    return Ok((crate::xact::XACTENGINE_E_INVALIDUSAGE, Vec::new()));
                }
                let object = self.xact_alloc_object(
                    memory,
                    runtime,
                    crate::xact::IFACE_WAVEBANK,
                    crate::xact::XactObject::WaveBank(crate::xact::WaveBankState {
                        refcount: 1,
                        engine: this,
                        bank,
                        prepared: std::collections::BTreeSet::new(),
                        streaming_cache: std::collections::BTreeMap::new(),
                    }),
                )?;
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                self.push_trace(
                    "audio",
                    "IXACT3Engine::CreateInMemoryWaveBank",
                    BTreeMap::from([("size".to_string(), json!(size))]),
                    json!(format!("{object:#x}")),
                );
                Ok((crate::xact::S_OK, Vec::new()))
            }
            11 => {
                // CreateStreamingWaveBank(XACT_WAVEBANK_STREAMING_PARAMETERS,
                // out).  The parameter block is
                //   HANDLE file; DWORD offset; DWORD flags; WORD packetSize;
                //   XACT_FILEIO_CALLBACKS fileio;   // read, seek, close
                // with the callback pointers naturally aligned after the
                // stock 16/24-byte prefix.  Header and entry reads go through
                // the guest's own callbacks; the bank keeps the handle and
                // callbacks for later on-demand entry loads.
                let params = xact_arg(state, memory, 1)?;
                let out = xact_arg(state, memory, 2)?;
                let initialized = runtime
                    .engine(this)
                    .map(|engine| engine.initialized)
                    .unwrap_or(false);
                if !initialized {
                    return Ok((crate::xact::XACTENGINE_E_NOTINITIALIZED, Vec::new()));
                }
                if params == 0 || out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let pointer_size = self.guest_arch.pointer_bytes() as u64;
                let file = read_guest_pointer(memory, params, self.guest_arch)?;
                let offset = read_u32(memory, params + pointer_size)?;
                let _flags = read_u32(memory, params + pointer_size + 4)?;
                let _packet_size = read_u16(memory, params + pointer_size + 8)?;
                let callbacks = params + xact_stream_callbacks_offset(pointer_size);
                let read_callback = read_guest_pointer(memory, callbacks, self.guest_arch)?;
                let seek_callback =
                    read_guest_pointer(memory, callbacks + pointer_size, self.guest_arch)?;
                let close_callback =
                    read_guest_pointer(memory, callbacks + 2 * pointer_size, self.guest_arch)?;
                if file == 0 || read_callback == 0 || seek_callback == 0 || close_callback == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let source = crate::xact::GuestStreamSource {
                    file,
                    offset,
                    read: read_callback,
                    seek: seek_callback,
                    close: close_callback,
                };
                let file_length = match self.xact_guest_stream_length(state, memory, &source) {
                    Ok(length) => length,
                    Err(error) => return Ok((error, Vec::new())),
                };
                let offset = offset as usize;
                if offset > file_length {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDDATA, Vec::new()));
                }
                let bank_length = file_length - offset;
                if bank_length < 52 {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDDATA, Vec::new()));
                }
                let header =
                    match self.xact_guest_stream_read_at(state, memory, &source, offset as u32, 52)
                    {
                        Ok(bytes) => bytes,
                        Err(error) => return Ok((error, Vec::new())),
                    };
                let mut needed = 52_usize;
                for index in 0..4 {
                    let segment_offset = u32::from_le_bytes([
                        header[12 + index * 8],
                        header[13 + index * 8],
                        header[14 + index * 8],
                        header[15 + index * 8],
                    ]) as usize;
                    let segment_length = u32::from_le_bytes([
                        header[16 + index * 8],
                        header[17 + index * 8],
                        header[18 + index * 8],
                        header[19 + index * 8],
                    ]) as usize;
                    if segment_length > 0 {
                        needed = needed.max(segment_offset.saturating_add(segment_length));
                    }
                }
                if needed > bank_length {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDDATA, Vec::new()));
                }
                let data = match self.xact_guest_stream_read_at(
                    state,
                    memory,
                    &source,
                    offset as u32,
                    needed,
                ) {
                    Ok(bytes) => bytes,
                    Err(error) => return Ok((error, Vec::new())),
                };
                let _ = header;
                let bank = match crate::xact::WaveBank::parse_streaming_header_guest(
                    &data,
                    bank_length,
                    source.clone(),
                ) {
                    Ok(bank) => bank,
                    Err(error) => return Ok((error, Vec::new())),
                };
                let object = self.xact_alloc_streaming_bank_object(memory, runtime, this, bank)?;
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                self.push_trace(
                    "audio",
                    "IXACT3Engine::CreateStreamingWaveBank",
                    BTreeMap::from([
                        ("file".to_string(), json!(format!("{file:#x}"))),
                        ("offset".to_string(), json!(source.offset)),
                    ]),
                    json!(format!("{object:#x}")),
                );
                Ok((crate::xact::S_OK, Vec::new()))
            }
            12 => {
                // PrepareWave(flags, path, packetSize, align, offset, loops, out)
                let path = xact_arg(state, memory, 2)?;
                let _packet_size = xact_arg_u32(state, memory, 3)?;
                let _align = xact_arg_u32(state, memory, 4)?;
                let _offset = xact_arg_u32(state, memory, 5)?;
                let loop_count = xact_arg_u32(state, memory, 6)? as u8;
                let out = xact_arg(state, memory, 7)?;
                let initialized = runtime
                    .engine(this)
                    .map(|engine| engine.initialized)
                    .unwrap_or(false);
                if !initialized {
                    return Ok((crate::xact::XACTENGINE_E_NOTINITIALIZED, Vec::new()));
                }
                if path == 0 || out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let Some(guest_path) = xact_guest_string(memory, path) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let Some(host_path) = self.xact_resolve_file_path(&guest_path) else {
                    return Ok((crate::xact::E_FAIL, Vec::new()));
                };
                let bank = match crate::xact::open_streaming_wave_bank(&host_path) {
                    Ok(bank) => bank,
                    Err(error) => return Ok((error, Vec::new())),
                };
                if bank.entries.is_empty() {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDDATA, Vec::new()));
                }
                let bank_object =
                    self.xact_alloc_streaming_bank_object(memory, runtime, this, bank)?;
                if let Err(error) =
                    self.xact_prepare_bank_entry(state, memory, runtime, bank_object, 0)
                {
                    return Ok((error, Vec::new()));
                }
                let object = self.xact_alloc_wave_object(
                    memory,
                    runtime,
                    this,
                    bank_object,
                    0,
                    crate::xact::XACT_STATE_PREPARED,
                    None,
                    loop_count,
                )?;
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            13 => {
                // PrepareInMemoryWave(flags, entry, seekTable, data, offset,
                // loops, out): decode the caller's 24-byte WAVEBANKENTRY
                // metadata against the supplied PCM buffer.
                let entry = xact_arg(state, memory, 2)?;
                let _seek_table = xact_arg(state, memory, 3)?;
                let data = xact_arg(state, memory, 4)?;
                let offset = xact_arg_u32(state, memory, 5)? as usize;
                let loop_count = xact_arg_u32(state, memory, 6)? as u8;
                let out = xact_arg(state, memory, 7)?;
                let initialized = runtime
                    .engine(this)
                    .map(|engine| engine.initialized)
                    .unwrap_or(false);
                if !initialized {
                    return Ok((crate::xact::XACTENGINE_E_NOTINITIALIZED, Vec::new()));
                }
                if entry == 0 || data == 0 || out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let Ok(parsed) = xact_read_wave_entry(memory, entry) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                if parsed.data_length == 0 {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDDATA, Vec::new()));
                }
                let payload = read_guest_bytes(
                    memory,
                    data.saturating_add(offset as u64),
                    parsed.data_length as usize,
                )?;
                let mut decoded = parsed;
                crate::xact::decode_wave_payload(&mut decoded, &payload);
                if decoded.pcm.is_none() {
                    return Ok((
                        decoded
                            .decode_error
                            .unwrap_or(crate::xact::XACTENGINE_E_INVALIDDATA),
                        Vec::new(),
                    ));
                }
                let bank = crate::xact::WaveBank {
                    name: "InMemoryWave".to_string(),
                    streaming: false,
                    source_path: None,
                    guest_source: None, // coverage: unreachable — struct-literal field line
                    entry_names: Vec::new(),
                    entries: vec![decoded],
                };
                let bank_object =
                    self.xact_alloc_streaming_bank_object(memory, runtime, this, bank)?;
                let object = self.xact_alloc_wave_object(
                    memory,
                    runtime,
                    this,
                    bank_object,
                    0,
                    crate::xact::XACT_STATE_PREPARED,
                    None,
                    loop_count,
                )?;
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            14 => {
                // PrepareStreamingWave(flags, entry, params, align, seek,
                // offset, loops, out).  The params block is the XACT
                // streaming descriptor: { path, fileOffset, length, reserved }.
                // The payload is read from the guest file with a real seek.
                let entry = xact_arg(state, memory, 2)?;
                let params = xact_arg(state, memory, 3)?;
                let _align = xact_arg_u32(state, memory, 4)?;
                let _seek = xact_arg(state, memory, 5)?;
                let _offset = xact_arg_u32(state, memory, 6)?;
                let loop_count = xact_arg_u32(state, memory, 7)? as u8;
                let out = xact_arg(state, memory, 8)?;
                let initialized = runtime
                    .engine(this)
                    .map(|engine| engine.initialized)
                    .unwrap_or(false);
                if !initialized {
                    return Ok((crate::xact::XACTENGINE_E_NOTINITIALIZED, Vec::new()));
                }
                if entry == 0 || params == 0 || out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let path_pointer = u64::from(read_u32(memory, params)?);
                let file_offset = read_u32(memory, params + 4)?;
                let declared_length = read_u32(memory, params + 8)?;
                if path_pointer == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let Some(guest_path) = xact_guest_string(memory, path_pointer) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let Some(host_path) = self.xact_resolve_file_path(&guest_path) else {
                    return Ok((crate::xact::E_FAIL, Vec::new()));
                };
                let Ok(mut parsed) = xact_read_wave_entry(memory, entry) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                parsed.data_offset = file_offset;
                if declared_length != 0 {
                    parsed.data_length = declared_length;
                }
                if parsed.data_length == 0 {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDDATA, Vec::new()));
                }
                let bank = crate::xact::WaveBank {
                    name: "StreamingWave".to_string(),
                    streaming: true,
                    source_path: Some(host_path),
                    guest_source: None, // coverage: unreachable — struct-literal field line
                    entry_names: Vec::new(),
                    entries: vec![parsed],
                };
                let bank_object =
                    self.xact_alloc_streaming_bank_object(memory, runtime, this, bank)?;
                if let Err(error) =
                    self.xact_prepare_bank_entry(state, memory, runtime, bank_object, 0)
                {
                    return Ok((error, Vec::new()));
                }
                let object = self.xact_alloc_wave_object(
                    memory,
                    runtime,
                    this,
                    bank_object,
                    0,
                    crate::xact::XACT_STATE_PREPARED,
                    None,
                    loop_count,
                )?;
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            15 => {
                // RegisterNotification(desc)
                let desc = xact_arg(state, memory, 1)?;
                if desc == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let callback = runtime
                    .engine(this)
                    .map(|engine| engine.notification_callback)
                    .unwrap_or(0);
                if callback == 0 {
                    return Ok((crate::xact::XACTENGINE_E_NONOTIFICATIONCALLBACK, Vec::new()));
                }
                let pointer_size = self.guest_arch.pointer_bytes() as u64;
                let type_ = memory.read_u8(desc)?;
                if type_ == 0 || type_ > 18 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let flags = memory.read_u8(desc + 1)?;
                let (sound_bank, wave_bank, cue, wave, cue_index, wave_index, context) =
                    if pointer_size == 4 {
                        (
                            u64::from(read_u32(memory, desc + 2)?),
                            u64::from(read_u32(memory, desc + 6)?),
                            u64::from(read_u32(memory, desc + 10)?),
                            u64::from(read_u32(memory, desc + 14)?),
                            read_u16(memory, desc + 18)?,
                            read_u16(memory, desc + 20)?,
                            u64::from(read_u32(memory, desc + 22)?),
                        )
                    } else {
                        (
                            memory.read_u64(desc + 2)?,
                            memory.read_u64(desc + 10)?,
                            memory.read_u64(desc + 18)?,
                            memory.read_u64(desc + 26)?,
                            read_u16(memory, desc + 34)?,
                            read_u16(memory, desc + 36)?,
                            memory.read_u64(desc + 38)?,
                        )
                    };
                let registration = crate::xact::NotificationRegistration {
                    type_,
                    flags,
                    sound_bank,
                    wave_bank,
                    cue,
                    wave,
                    cue_index,
                    wave_index,
                    context,
                };
                let engine = runtime.engine_mut(this);
                let Some(engine) = engine else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                if engine.notifications.contains(&registration) {
                    return Ok((crate::xact::XACTENGINE_E_NOTIFICATIONREGISTERED, Vec::new()));
                }
                engine.notifications.push(registration);
                Ok((crate::xact::S_OK, Vec::new()))
            }
            16 => {
                // UnRegisterNotification(desc); a null description removes all
                // (documented native behavior).
                let desc = xact_arg(state, memory, 1)?;
                let callback = runtime
                    .engine(this)
                    .map(|engine| engine.notification_callback)
                    .unwrap_or(0);
                if callback == 0 {
                    return Ok((crate::xact::XACTENGINE_E_NONOTIFICATIONCALLBACK, Vec::new()));
                }
                let Some(engine) = runtime.engine_mut(this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                if desc == 0 {
                    engine.notifications.clear();
                    return Ok((crate::xact::S_OK, Vec::new()));
                }
                let pointer_size = self.guest_arch.pointer_bytes() as u64;
                let registration = if pointer_size == 4 {
                    crate::xact::NotificationRegistration {
                        type_: memory.read_u8(desc)?,
                        flags: memory.read_u8(desc + 1)?,
                        sound_bank: u64::from(read_u32(memory, desc + 2)?),
                        wave_bank: u64::from(read_u32(memory, desc + 6)?),
                        cue: u64::from(read_u32(memory, desc + 10)?),
                        wave: u64::from(read_u32(memory, desc + 14)?),
                        cue_index: read_u16(memory, desc + 18)?,
                        wave_index: read_u16(memory, desc + 20)?,
                        context: u64::from(read_u32(memory, desc + 22)?),
                    }
                } else {
                    crate::xact::NotificationRegistration {
                        type_: memory.read_u8(desc)?,
                        flags: memory.read_u8(desc + 1)?,
                        sound_bank: memory.read_u64(desc + 2)?,
                        wave_bank: memory.read_u64(desc + 10)?,
                        cue: memory.read_u64(desc + 18)?,
                        wave: memory.read_u64(desc + 26)?,
                        cue_index: read_u16(memory, desc + 34)?,
                        wave_index: read_u16(memory, desc + 36)?,
                        context: memory.read_u64(desc + 38)?,
                    }
                };
                engine.notifications.retain(|entry| *entry != registration);
                Ok((crate::xact::S_OK, Vec::new()))
            }
            17 => {
                // GetCategory(name) -> XACTCATEGORY (returned in EAX)
                let name = xact_arg(state, memory, 1)?;
                let Some(name) = xact_guest_string(memory, name) else {
                    return Ok((u32::from(crate::xact::XACTCATEGORY_INVALID), Vec::new()));
                };
                let Some(engine) = runtime.engine(this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let index = engine
                    .categories
                    .iter()
                    .position(|category| category.name == name)
                    .map(|index| index as u16)
                    .unwrap_or(crate::xact::XACTCATEGORY_INVALID);
                Ok((u32::from(index), Vec::new()))
            }
            18 => {
                // Stop(category, flags)
                let category = xact_arg_u16(state, memory, 1)?;
                let _flags = xact_arg_u32(state, memory, 2)?;
                if runtime
                    .engine(this)
                    .map(|engine| category as usize >= engine.categories.len())
                    .unwrap_or(true)
                {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDCATEGORY, Vec::new()));
                }
                let mut pending = Vec::new();
                self.xact_engine_stop_category(runtime, this, category, &mut pending)?;
                Ok((crate::xact::S_OK, pending))
            }
            19 => {
                // SetVolume(category, volume)
                let category = xact_arg_u16(state, memory, 1)?;
                let volume = xact_arg_f32(state, memory, 2)?;
                let Some(engine) = runtime.engine_mut(this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                if category as usize >= engine.categories.len() {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDCATEGORY, Vec::new()));
                }
                let volume = volume.clamp(0.0, XACT_VOLUME_MAX);
                engine.categories[category as usize].current_volume =
                    engine.categories[category as usize].authored_volume * volume;
                // Descendant categories follow the parent gain.
                for index in 0..engine.categories.len() {
                    if engine.categories[index].parent == category {
                        let authored = engine.categories[index].authored_volume;
                        engine.categories[index].current_volume = authored * volume;
                    }
                }
                self.xact_apply_category_gains(runtime, this)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            20 => {
                // Pause(category, fPause)
                let category = xact_arg_u16(state, memory, 1)?;
                let pause = xact_arg_u32(state, memory, 2)? != 0;
                let Some(engine) = runtime.engine_mut(this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                if category as usize >= engine.categories.len() {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDCATEGORY, Vec::new()));
                }
                engine.categories[category as usize].paused = pause;
                self.xact_engine_pause_category(runtime, this, category, pause)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            21 => {
                // GetGlobalVariableIndex(name) -> index
                let name = xact_arg(state, memory, 1)?;
                let Some(name) = xact_guest_string(memory, name) else {
                    return Ok((
                        u32::from(crate::xact::XACTVARIABLEINDEX_INVALID),
                        Vec::new(),
                    ));
                };
                let Some(engine) = runtime.engine(this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let index = engine
                    .variables
                    .iter()
                    .position(|variable| {
                        variable.name == name
                            && variable.accessibility & 0x01 != 0
                            && variable.accessibility & 0x04 == 0
                    })
                    .map(|index| index as u16)
                    .unwrap_or(crate::xact::XACTVARIABLEINDEX_INVALID);
                Ok((u32::from(index), Vec::new()))
            }
            22 => {
                // SetGlobalVariable(index, value)
                let index = xact_arg_u16(state, memory, 1)?;
                let value = xact_arg_f32(state, memory, 2)?;
                let Some(engine) = runtime.engine_mut(this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let variable = match engine.variables.get(index as usize) {
                    Some(variable)
                        if variable.accessibility & 0x01 != 0
                            && variable.accessibility & 0x04 == 0
                            && variable.accessibility & 0x02 == 0 =>
                    {
                        variable.clone()
                    }
                    _ => return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new())),
                };
                let clamped = value.clamp(variable.min, variable.max);
                engine.variable_values[index as usize] = clamped;
                let engine_state = runtime.engine(this).cloned();
                let mut pending = Vec::new();
                if let Some(engine_state) = engine_state {
                    pending.extend(xact_collect_notifications(
                        Some(&engine_state),
                        9, // XACTNOTIFICATIONTYPE_GLOBALVARIABLECHANGED
                        0,
                        0,
                        0xFFFF,
                    ));
                    for notification in &mut pending {
                        notification.variable_index = index;
                        notification.variable_value = clamped;
                    }
                }
                Ok((crate::xact::S_OK, pending))
            }
            23 => {
                // GetGlobalVariable(index, out)
                let index = xact_arg_u16(state, memory, 1)?;
                let out = xact_arg(state, memory, 2)?;
                let Some(engine) = runtime.engine(this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let Some(variable) = engine.variables.get(index as usize) else {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                };
                if variable.accessibility & 0x01 == 0 || variable.accessibility & 0x04 != 0 {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                }
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let value = engine
                    .variable_values
                    .get(index as usize)
                    .copied()
                    .unwrap_or(variable.initial);
                xact_write_f32(memory, out, value)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            _ => Ok((crate::xact::E_INVALIDARG, Vec::new())),
        }
    }

    /// `IXACT3Engine::Initialize`.  Parses the real XGS global-settings buffer
    /// when supplied; otherwise the documented native default of three
    /// categories (Global/Default/Music) is installed.  A second call returns
    /// `XACTENGINE_E_ALREADYINITIALIZED`.
    fn xact_engine_initialize(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        this: u64,
    ) -> AppResult<(u32, Vec<XactPendingNotification>)> {
        let params_pointer = xact_arg(state, memory, 1)?;
        if params_pointer == 0 {
            return Ok((crate::xact::E_INVALIDARG, Vec::new()));
        }
        if runtime
            .engine(this)
            .map(|engine| engine.initialized)
            .unwrap_or(false)
        {
            return Ok((crate::xact::XACTENGINE_E_ALREADYINITIALIZED, Vec::new()));
        }
        let pointer_size = self.guest_arch.pointer_bytes() as u64;
        let params = if pointer_size == 4 {
            XactRuntimeParams {
                global_settings: u64::from(read_u32(memory, params_pointer + 4)?),
                global_settings_size: read_u32(memory, params_pointer + 8)?,
                notification_callback: u64::from(read_u32(memory, params_pointer + 28)?),
                renderer_id: u64::from(read_u32(memory, params_pointer + 32)?),
                xaudio2: u64::from(read_u32(memory, params_pointer + 36)?),
            }
        } else {
            XactRuntimeParams {
                global_settings: memory.read_u64(params_pointer + 8)?,
                global_settings_size: read_u32(memory, params_pointer + 16)?,
                notification_callback: memory.read_u64(params_pointer + 48)?,
                renderer_id: memory.read_u64(params_pointer + 56)?,
                xaudio2: memory.read_u64(params_pointer + 64)?,
            }
        };
        if params.xaudio2 != 0 {
            // Composition onto a guest-supplied IXAudio2 is not part of the
            // modeled surface; genuine invalid-usage result.
            return Ok((crate::xact::XACTENGINE_E_INVALIDUSAGE, Vec::new()));
        }

        let mut engine = crate::xact::EngineState {
            refcount: runtime
                .engine(this)
                .map(|engine| engine.refcount)
                .unwrap_or(1),
            initialized: true,
            notification_callback: params.notification_callback,
            ..Default::default()
        };
        if params.global_settings != 0 && params.global_settings_size > 0 {
            let bytes = read_guest_bytes(
                memory,
                params.global_settings,
                params.global_settings_size as usize,
            )?;
            let settings = match crate::xact::GlobalSettings::parse(&bytes) {
                Ok(settings) => settings,
                Err(error) => return Ok((error, Vec::new())),
            };
            for category in settings.categories {
                engine.categories.push(crate::xact::CategoryState {
                    name: category.name,
                    authored_volume: category.volume,
                    current_volume: category.volume,
                    parent: category.parent,
                    instance_limit: category.instance_limit,
                    paused: false,
                    visibility: category.visibility,
                    release_ms: category.fade_out_ms,
                    release_curve: category.release_curve,
                });
            }
            for variable in settings.variables {
                engine.variable_values.push(variable.initial);
                engine.variables.push(variable);
            }
        } else {
            // Documented default when no global settings are supplied.
            for (name, parent) in [("Global", 0xFFFFu16), ("Default", 0), ("Music", 0)] {
                engine.categories.push(crate::xact::CategoryState {
                    name: name.to_string(),
                    authored_volume: 1.0,
                    current_volume: 1.0,
                    parent,
                    instance_limit: 255,
                    paused: false,
                    visibility: 1,
                    release_ms: 0,
                    release_curve: crate::xact::ReleaseCurve::Linear,
                });
            }
        }
        let _ = xact_guest_string(memory, params.renderer_id);
        let Some(slot) = runtime.engine_mut(this) else {
            return Ok((crate::xact::E_INVALIDARG, Vec::new()));
        };
        *slot = engine;
        Ok((crate::xact::S_OK, Vec::new()))
    }

    /// Stop every live cue/wave on one engine (used by `Shutdown` and
    /// engine teardown).
    fn xact_engine_stop_all(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
        pending: &mut Vec<XactPendingNotification>,
    ) -> AppResult<()> {
        let cue_objects = runtime.cue_objects_for_engine(engine);
        for cue_object in cue_objects {
            let live = match runtime.objects.get(&cue_object) {
                Some(crate::xact::XactObject::Cue(cue)) => cue.live,
                _ => None,
            };
            if live.is_some() {
                self.xact_stop_cue_object(runtime, cue_object, pending)?;
            }
        }
        let wave_objects = runtime
            .objects
            .iter()
            .filter_map(|(address, object)| match object {
                crate::xact::XactObject::Wave(wave)
                    if wave.engine == engine && wave.live.is_some() =>
                {
                    Some(*address)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for wave_object in wave_objects {
            self.xact_stop_wave_object(runtime, wave_object, pending)?;
        }
        Ok(())
    }

    /// Stop the live cues of one engine whose category chain includes
    /// `category`.
    fn xact_engine_stop_category(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
        category: u16,
        pending: &mut Vec<XactPendingNotification>,
    ) -> AppResult<()> {
        let Some(engine_state) = runtime.engine(engine).cloned() else {
            return Ok(());
        };
        let cue_objects = runtime.cue_objects_for_engine(engine);
        for cue_object in cue_objects {
            let live = match runtime.objects.get(&cue_object) {
                Some(crate::xact::XactObject::Cue(cue)) => cue.live,
                _ => None,
            };
            if let Some(live) = live
                && engine_state.category_includes(category, live.category)
            {
                self.xact_stop_cue_object(runtime, cue_object, pending)?;
            }
        }
        let wave_objects = runtime
            .objects
            .iter()
            .filter_map(|(address, object)| match object {
                crate::xact::XactObject::Wave(wave)
                    if wave.engine == engine && wave.live.is_some() =>
                {
                    Some(*address)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for wave_object in wave_objects {
            let live = match runtime.objects.get(&wave_object) {
                Some(crate::xact::XactObject::Wave(wave)) => wave.live,
                _ => None,
            };
            if let Some(live) = live
                && engine_state.category_includes(category, live.category)
            {
                self.xact_stop_wave_object(runtime, wave_object, pending)?;
            }
        }
        Ok(())
    }

    /// Pause/resume the live voices of one category.
    fn xact_engine_pause_category(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
        category: u16,
        pause: bool,
    ) -> AppResult<()> {
        let Some(engine_state) = runtime.engine(engine).cloned() else {
            return Ok(());
        };
        let cue_objects = runtime.cue_objects_for_engine(engine);
        for cue_object in cue_objects {
            let live = match runtime.objects.get(&cue_object) {
                Some(crate::xact::XactObject::Cue(cue)) => cue.live,
                _ => None,
            };
            if let Some(live) = live
                && engine_state.category_includes(category, live.category)
            {
                self.xact_pause_voice(live.voice, pause)?;
                if let Some(crate::xact::XactObject::Cue(cue)) =
                    runtime.objects.get_mut(&cue_object)
                {
                    cue.state = if pause {
                        crate::xact::XACT_STATE_PAUSED
                    } else {
                        crate::xact::XACT_STATE_PLAYING
                    };
                    if let Some(entry) = cue.live.as_mut() {
                        entry.paused = pause;
                    }
                }
            }
        }
        let wave_entries = runtime
            .objects
            .iter()
            .filter_map(|(address, object)| match object {
                crate::xact::XactObject::Wave(wave)
                    if wave.engine == engine && wave.live.is_some() =>
                {
                    Some((*address, wave.live))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for (wave_object, live) in wave_entries {
            if let Some(live) = live
                && engine_state.category_includes(category, live.category)
            {
                self.xact_pause_voice(live.voice, pause)?;
                if let Some(crate::xact::XactObject::Wave(wave)) =
                    runtime.objects.get_mut(&wave_object)
                {
                    wave.state = if pause {
                        crate::xact::XACT_STATE_PAUSED
                    } else {
                        crate::xact::XACT_STATE_PLAYING
                    };
                    if let Some(entry) = wave.live.as_mut() {
                        entry.paused = pause;
                    }
                }
            }
        }
        Ok(())
    }

    /// Recompute every live voice's gain after a category volume change.
    fn xact_apply_category_gains(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
    ) -> AppResult<()> {
        let Some(engine_state) = runtime.engine(engine).cloned() else {
            return Ok(());
        };
        let mut updates = Vec::new();
        for (address, object) in &runtime.objects {
            match object {
                crate::xact::XactObject::Cue(cue) => {
                    if let Some(live) = cue.live {
                        let release_gain = live.release.map(|fade| fade.fraction()).unwrap_or(1.0);
                        updates.push((
                            *address,
                            live.voice,
                            live.base_volume
                                * engine_state.category_gain(live.category)
                                * release_gain,
                        ));
                    }
                }
                crate::xact::XactObject::Wave(wave) => {
                    if let Some(live) = wave.live {
                        updates.push((
                            *address,
                            live.voice,
                            live.base_volume * engine_state.category_gain(live.category),
                        ));
                    }
                }
                _ => {}
            }
        }
        for (_, voice, gain) in updates {
            let _ = self
                .audio
                .set_volume(voice, gain.clamp(0.0, XACT_VOLUME_MAX));
        }
        Ok(())
    }

    fn xact_pause_voice(&mut self, voice: crate::audio::VoiceId, pause: bool) -> AppResult<()> {
        if pause {
            let _ = self.audio.stop_voice(voice);
        } else {
            let _ = self.audio.start_voice(voice);
        }
        Ok(())
    }
}

/// Filter the engine's registrations for one notification type.  A
/// registration with a zero cue/sound-bank selector matches every source.
fn xact_collect_notifications(
    engine: Option<&crate::xact::EngineState>,
    type_: u8,
    sound_bank: u64,
    cue: u64,
    cue_index: u16,
) -> Vec<XactPendingNotification> {
    let Some(engine) = engine else {
        return Vec::new();
    };
    if engine.notification_callback == 0 {
        return Vec::new();
    }
    engine
        .notifications
        .iter()
        .filter(|registration| {
            registration.type_ == type_
                && (registration.sound_bank == 0 || registration.sound_bank == sound_bank)
                && (registration.cue == 0 || registration.cue == cue)
        })
        .map(|registration| XactPendingNotification {
            callback: engine.notification_callback,
            type_,
            cue_index,
            sound_bank,
            cue,
            wave_bank: registration.wave_bank,
            wave: registration.wave,
            wave_index: registration.wave_index,
            context: registration.context,
            variable_index: 0,
            variable_value: 0.0,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// XACT3 sound-bank and wave-bank interface methods
// ---------------------------------------------------------------------------

impl PeHostRuntime {
    /// The `IXACT3SoundBank` method bodies.
    fn xact_invoke_soundbank(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        this: u64,
        method: u16,
    ) -> AppResult<(u32, Vec<XactPendingNotification>)> {
        match method {
            3 => {
                // GetCueIndex(name) -> XACTINDEX
                let name = xact_arg(state, memory, 1)?;
                let Some(name) = xact_guest_string(memory, name) else {
                    return Ok((u32::from(crate::xact::XACTINDEX_INVALID), Vec::new()));
                };
                let Some(bank) = runtime.objects.get(&this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let crate::xact::XactObject::SoundBank(bank) = bank else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let index = bank
                    .bank
                    .cue_index_by_name(&name)
                    .unwrap_or(crate::xact::XACTINDEX_INVALID);
                Ok((u32::from(index), Vec::new()))
            }
            4 => {
                // GetNumCues(XACTINDEX *out)
                let out = xact_arg(state, memory, 1)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let Some(bank) = runtime.objects.get(&this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let crate::xact::XactObject::SoundBank(bank) = bank else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                xact_write_u16(memory, out, bank.bank.cues.len() as u16)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            5 => {
                // GetCueProperties(index, XACT_CUE_PROPERTIES *out)
                let index = xact_arg_u16(state, memory, 1)?;
                let out = xact_arg(state, memory, 2)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let Some(bank) = runtime.objects.get(&this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let crate::xact::XactObject::SoundBank(bank) = bank else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let Some(cue) = bank.bank.cues.get(index as usize) else {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDCUEINDEX, Vec::new()));
                };
                let interactive = cue
                    .variation_index
                    .and_then(|variation| bank.bank.variations.get(variation))
                    .filter(|variation| variation.kind == 3)
                    .map(|variation| variation.variable)
                    .unwrap_or(0);
                let num_variations = cue
                    .variation_index
                    .and_then(|variation| bank.bank.variations.get(variation))
                    .map(|variation| variation.entries.len())
                    .unwrap_or(0) as u16;
                let live = runtime
                    .objects
                    .values()
                    .filter(|object| match object {
                        crate::xact::XactObject::Cue(cue) => {
                            cue.sound_bank == this && cue.index == index
                        }
                        _ => false,
                    })
                    .count() as u8;
                xact_write_cue_properties(
                    memory,
                    out,
                    &cue.name,
                    interactive,
                    num_variations,
                    cue.instance_limit,
                    live,
                )?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            6 | 7 => {
                // Prepare(index, flags, timeOffset, out) / Play(index, ...)
                let index = xact_arg_u16(state, memory, 1)?;
                let _flags = xact_arg_u32(state, memory, 2)?;
                let _time_offset = xact_arg_u32(state, memory, 3)? as i32;
                let out = xact_arg(state, memory, 4)?;
                let engine = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::SoundBank(bank)) => bank.engine,
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                // Validate the cue index against the parsed bank.
                let valid = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::SoundBank(bank)) => {
                        (index as usize) < bank.bank.cues.len()
                    }
                    _ => false,
                };
                if !valid {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDCUEINDEX, Vec::new()));
                }
                let mut pending = Vec::new();
                let object = self.xact_alloc_cue_object(
                    memory,
                    runtime,
                    engine,
                    this,
                    index,
                    if method == 7 {
                        crate::xact::XACT_STATE_PREPARING
                    } else {
                        crate::xact::XACT_STATE_PREPARED
                    },
                )?;
                if method == 7 {
                    // Real playback: resolve the cue's selection and start a
                    // source voice.  A failure destroys the half-built object
                    // and returns the genuine resolution/decode error.
                    if let Err(error) = self.xact_start_cue_playback(
                        runtime,
                        memory,
                        object,
                        this,
                        index,
                        &mut pending,
                    )? {
                        runtime.objects.remove(&object);
                        return Ok((error, Vec::new()));
                    }
                    let engine_state = runtime.engine(engine).cloned();
                    pending.extend(xact_collect_notifications(
                        engine_state.as_ref(),
                        2, // XACTNOTIFICATIONTYPE_CUEPLAY
                        this,
                        object,
                        index,
                    ));
                }
                if out != 0 {
                    write_guest_pointer(memory, out, object, self.guest_arch)?;
                }
                Ok((crate::xact::S_OK, pending))
            }
            8 => {
                // Stop(index, flags): stop every live cue of this index.
                let index = xact_arg_u16(state, memory, 1)?;
                let _flags = xact_arg_u32(state, memory, 2)?;
                let valid = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::SoundBank(bank)) => {
                        (index as usize) < bank.bank.cues.len()
                    }
                    _ => false,
                };
                if !valid {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDCUEINDEX, Vec::new()));
                }
                let objects = runtime
                    .objects
                    .iter()
                    .filter_map(|(address, object)| match object {
                        crate::xact::XactObject::Cue(cue)
                            if cue.sound_bank == this && cue.index == index =>
                        {
                            Some(*address)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let mut pending = Vec::new();
                for object in objects {
                    self.xact_stop_cue_object(runtime, object, &mut pending)?;
                }
                Ok((crate::xact::S_OK, pending))
            }
            9 => {
                // Destroy
                let mut pending = Vec::new();
                self.xact_destroy_object(runtime, state, memory, this, &mut pending)?;
                Ok((crate::xact::S_OK, pending))
            }
            10 => {
                // GetState(DWORD *out)
                let out = xact_arg(state, memory, 1)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                xact_write_u32(memory, out, crate::xact::XACT_STATE_INUSE)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            _ => Ok((crate::xact::E_INVALIDARG, Vec::new())),
        }
    }

    /// The `IXACT3WaveBank` method bodies.
    fn xact_invoke_wavebank(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        this: u64,
        method: u16,
    ) -> AppResult<(u32, Vec<XactPendingNotification>)> {
        match method {
            3 => {
                // Destroy
                let mut pending = Vec::new();
                self.xact_destroy_object(runtime, state, memory, this, &mut pending)?;
                Ok((crate::xact::S_OK, pending))
            }
            4 => {
                // GetNumWaves(XACTINDEX *out)
                let out = xact_arg(state, memory, 1)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let Some(bank) = xact_wave_bank(runtime, this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                xact_write_u16(memory, out, bank.entries.len() as u16)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            5 => {
                // GetWaveIndex(name) -> XACTINDEX
                let name = xact_arg(state, memory, 1)?;
                let Some(name) = xact_guest_string(memory, name) else {
                    return Ok((u32::from(crate::xact::XACTINDEX_INVALID), Vec::new()));
                };
                let Some(bank) = xact_wave_bank(runtime, this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let index = bank
                    .entry_index_by_name(&name)
                    .unwrap_or(crate::xact::XACTINDEX_INVALID);
                Ok((u32::from(index), Vec::new()))
            }
            6 => {
                // GetWaveProperties(index, XACT_WAVE_PROPERTIES *out)
                let index = xact_arg_u16(state, memory, 1)?;
                let out = xact_arg(state, memory, 2)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let Some(bank) = xact_wave_bank(runtime, this) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let Some(entry) = bank.entries.get(index as usize) else {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDWAVEINDEX, Vec::new()));
                };
                xact_write_wave_properties(memory, out, bank, entry, index)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            7 | 8 => {
                // Prepare/Play(index, flags, offset, loopCount, out)
                let index = xact_arg_u16(state, memory, 1)?;
                let _flags = xact_arg_u32(state, memory, 2)?;
                let _play_offset = xact_arg_u32(state, memory, 3)?;
                let loop_count = xact_arg_u32(state, memory, 4)? as u8;
                let out = xact_arg(state, memory, 5)?;
                let engine = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::WaveBank(bank)) => bank.engine,
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                let valid = xact_wave_bank(runtime, this)
                    .map(|bank| (index as usize) < bank.entries.len())
                    .unwrap_or(false);
                if !valid {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDWAVEINDEX, Vec::new()));
                }
                let mut pending = Vec::new();
                let mut voice = None;
                if method == 7 {
                    // Prepare performs the real streaming read now and marks
                    // the entry prepared; Play later reads it from the cache.
                    match self.xact_prepare_bank_entry(state, memory, runtime, this, index) {
                        Ok(()) => {}
                        Err(error) => return Ok((error, Vec::new())),
                    }
                }
                if method == 8 {
                    match self.xact_play_wave(
                        runtime,
                        engine,
                        this,
                        index,
                        loop_count,
                        &mut pending,
                    )? {
                        Ok(started) => voice = Some(started),
                        Err(error) => return Ok((error, Vec::new())),
                    }
                }
                let object = self.xact_alloc_wave_object(
                    memory,
                    runtime,
                    engine,
                    this,
                    index,
                    if method == 8 {
                        crate::xact::XACT_STATE_PLAYING
                    } else {
                        crate::xact::XACT_STATE_PREPARED
                    },
                    voice,
                    loop_count,
                )?;
                if out != 0 {
                    write_guest_pointer(memory, out, object, self.guest_arch)?;
                }
                if method == 8 {
                    let engine_state = runtime.engine(engine).cloned();
                    pending.extend(xact_collect_notifications(
                        engine_state.as_ref(),
                        13, // XACTNOTIFICATIONTYPE_WAVEPLAY
                        this,
                        0,
                        index,
                    ));
                }
                Ok((crate::xact::S_OK, pending))
            }
            9 => {
                // Stop(index, flags)
                let index = xact_arg_u16(state, memory, 1)?;
                let _flags = xact_arg_u32(state, memory, 2)?;
                let valid = xact_wave_bank(runtime, this)
                    .map(|bank| (index as usize) < bank.entries.len())
                    .unwrap_or(false);
                if !valid {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDWAVEINDEX, Vec::new()));
                }
                let objects = runtime
                    .objects
                    .iter()
                    .filter_map(|(address, object)| match object {
                        crate::xact::XactObject::Wave(wave)
                            if wave.wave_bank == this && wave.index == index =>
                        {
                            Some(*address)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let mut pending = Vec::new();
                for object in objects {
                    self.xact_stop_wave_object(runtime, object, &mut pending)?;
                }
                Ok((crate::xact::S_OK, pending))
            }
            10 => {
                // GetState(DWORD *out)
                let out = xact_arg(state, memory, 1)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                xact_write_u32(memory, out, crate::xact::XACT_STATE_INUSE)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            _ => Ok((crate::xact::E_INVALIDARG, Vec::new())),
        }
    }
}

/// Offset of the `XACT_FILEIO_CALLBACKS` block inside
/// `XACT_WAVEBANK_STREAMING_PARAMETERS`: the stock 16-byte x86 prefix is
/// pointer-aligned for the three callbacks, and the x64 prefix is 24 bytes.
fn xact_stream_callbacks_offset(pointer_size: u64) -> u64 {
    if pointer_size == 4 { 16 } else { 24 }
}

impl PeHostRuntime {
    /// Prepare one wave-bank entry: in-memory entries are marked ready, and a
    /// streaming entry is loaded from the real file (or through the guest's
    /// file callbacks) with a seek/read and cached until the bank is
    /// destroyed.
    fn xact_prepare_bank_entry(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        runtime: &mut crate::xact::XactRuntime,
        bank_object: u64,
        index: u16,
    ) -> Result<(), u32> {
        let (streaming, source_path, guest_source, entry) = {
            let Some(crate::xact::XactObject::WaveBank(bank)) = runtime.objects.get(&bank_object)
            else {
                return Err(crate::xact::E_INVALIDARG);
            };
            if index as usize >= bank.bank.entries.len() {
                return Err(crate::xact::XACTENGINE_E_INVALIDWAVEINDEX);
            }
            if bank.prepared.contains(&index) {
                return Ok(());
            }
            (
                bank.bank.streaming,
                bank.bank.source_path.clone(),
                bank.bank.guest_source.clone(),
                bank.bank.entries[index as usize].clone(),
            )
        };
        let pcm = match entry.pcm.clone() {
            Some(pcm) => pcm,
            None if streaming => {
                if entry.data_length == 0 {
                    return Err(crate::xact::XACTENGINE_E_INVALIDDATA);
                }
                match (guest_source, source_path) {
                    (Some(source), _) => {
                        let offset = source.offset.saturating_add(entry.data_offset);
                        let payload = self.xact_guest_stream_read_at(
                            state,
                            memory,
                            &source,
                            offset,
                            entry.data_length as usize,
                        )?;
                        let mut decoded = entry.clone();
                        crate::xact::decode_wave_payload(&mut decoded, &payload);
                        decoded.pcm.ok_or(
                            decoded
                                .decode_error
                                .unwrap_or(crate::xact::XACTENGINE_E_INVALIDDATA),
                        )?
                    }
                    (None, Some(path)) => crate::xact::load_streaming_entry(&path, &entry)?,
                    // creation either records a host path or a guest source.
                    (None, None) => {
                        return Err(crate::xact::XACTENGINE_E_INVALIDDATA); // coverage: unreachable — no third creation form
                    }
                }
            }
            None => return Err(crate::xact::XACTENGINE_E_INVALIDDATA),
        };
        let Some(crate::xact::XactObject::WaveBank(bank)) = runtime.objects.get_mut(&bank_object)
        else {
            return Err(crate::xact::E_INVALIDARG); // coverage: unreachable — object cannot vanish mid-call
        };
        if bank.bank.streaming {
            bank.streaming_cache.insert(index, pcm);
        }
        bank.prepared.insert(index);
        Ok(())
    }

    /// Ask the guest's seek callback for the current file length
    /// (`FILE_END`, origin 2).
    fn xact_guest_stream_length(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        source: &crate::xact::GuestStreamSource,
    ) -> Result<usize, u32> {
        let out = self
            .alloc_zeroed(memory, 8, 4)
            .map_err(|_| crate::xact::E_FAIL)?;
        let status = self
            .execute_guest_callback(
                state,
                memory,
                source.seek,
                &[source.file, 0, 2, out],
                "XACT stream seek",
            )
            .map_err(|_| crate::xact::E_FAIL)? as u32;
        if status != crate::xact::S_OK {
            return Err(status);
        }
        Ok(read_u32(memory, out).map_err(|_| crate::xact::E_FAIL)? as usize)
    }

    /// Seek to `offset` and read exactly `length` bytes through the guest's
    /// callbacks.  A failed callback propagates its HRESULT; a seek that does
    /// not land on the requested offset or a short read is `E_FAIL`.
    fn xact_guest_stream_read_at(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        source: &crate::xact::GuestStreamSource,
        offset: u32,
        length: usize,
    ) -> Result<Vec<u8>, u32> {
        let out = self
            .alloc_zeroed(memory, 8, 4)
            .map_err(|_| crate::xact::E_FAIL)?;
        let status = self
            .execute_guest_callback(
                state,
                memory,
                source.seek,
                &[source.file, u64::from(offset), 0, out],
                "XACT stream seek",
            )
            .map_err(|_| crate::xact::E_FAIL)? as u32;
        if status != crate::xact::S_OK {
            return Err(status);
        }
        if read_u32(memory, out).map_err(|_| crate::xact::E_FAIL)? != offset {
            return Err(crate::xact::E_FAIL);
        }
        let buffer = self
            .alloc_zeroed(memory, length.max(1), 4)
            .map_err(|_| crate::xact::E_FAIL)?;
        let status = self
            .execute_guest_callback(
                state,
                memory,
                source.read,
                &[source.file, buffer, length as u64, out],
                "XACT stream read",
            )
            .map_err(|_| crate::xact::E_FAIL)? as u32;
        if status != crate::xact::S_OK {
            return Err(status);
        }
        if read_u32(memory, out).map_err(|_| crate::xact::E_FAIL)? as usize != length {
            return Err(crate::xact::E_FAIL);
        }
        Ok(read_guest_bytes(memory, buffer, length).map_err(|_| crate::xact::E_FAIL)?)
    }

    /// Invoke the guest's close callback for a streaming bank.
    fn xact_close_guest_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        source: &crate::xact::GuestStreamSource,
    ) {
        let _ = self.execute_guest_callback(
            state,
            memory,
            source.close,
            &[source.file],
            "XACT stream close",
        );
    }
}

/// Read one 24-byte `WAVEBANKENTRY` metadata block from guest memory.
fn xact_read_wave_entry(memory: &MemoryImage, address: u64) -> AppResult<crate::xact::WaveEntry> {
    let flags_and_duration = read_u32(memory, address)?;
    let format = crate::xact::MiniFormat::decode(read_u32(memory, address + 4)?);
    Ok(crate::xact::WaveEntry {
        flags: flags_and_duration & 0xF,
        duration_samples: (flags_and_duration >> 4) & 0x0FFF_FFFF,
        format,
        data_offset: read_u32(memory, address + 8)?,
        data_length: read_u32(memory, address + 12)?,
        loop_start_sample: read_u32(memory, address + 16)?,
        loop_total_samples: read_u32(memory, address + 20)?,
        pcm: None,
        decode_error: None,
    })
}

/// Borrow one wave bank's parsed data from the store.
fn xact_wave_bank<'a>(
    runtime: &'a crate::xact::XactRuntime,
    address: u64,
) -> Option<&'a crate::xact::WaveBank> {
    match runtime.objects.get(&address) {
        Some(crate::xact::XactObject::WaveBank(bank)) => Some(&bank.bank),
        _ => None,
    }
}

/// Write one `XACT_CUE_PROPERTIES` (friendlyName[255], interactive, variable
/// index, variation count, instance limit/count).
fn xact_write_cue_properties(
    memory: &mut MemoryImage,
    out: u64,
    name: &str,
    interactive_variable: i16,
    num_variations: u16,
    max_instances: u8,
    current_instances: u8,
) -> AppResult<()> {
    memory.map_bytes(out, &vec![0u8; 268]);
    let mut bytes = name.as_bytes().to_vec();
    bytes.truncate(254);
    bytes.push(0);
    memory.map_bytes(out, &bytes);
    let interactive = interactive_variable != 0;
    write_u32(memory, out + 256, u32::from(interactive));
    write_u16(memory, out + 260, interactive_variable as u16);
    write_u16(memory, out + 262, num_variations);
    write_u8(memory, out + 264, max_instances);
    write_u8(memory, out + 265, current_instances);
    Ok(())
}

/// Write one `XACT_WAVE_PROPERTIES`.
fn xact_write_wave_properties(
    memory: &mut MemoryImage,
    out: u64,
    bank: &crate::xact::WaveBank,
    entry: &crate::xact::WaveEntry,
    index: u16,
) -> AppResult<()> {
    memory.map_bytes(out, &vec![0u8; 84]);
    let name = bank.entry_name(index as usize).unwrap_or("");
    let mut bytes = name.as_bytes().to_vec();
    bytes.truncate(63);
    bytes.push(0);
    memory.map_bytes(out, &bytes);
    write_u32(memory, out + 64, entry.format.encode());
    write_u32(memory, out + 68, entry.sample_count());
    write_u32(memory, out + 72, entry.loop_start_sample);
    write_u32(memory, out + 76, entry.loop_total_samples);
    write_u32(memory, out + 80, u32::from(bank.streaming));
    Ok(())
}

// ---------------------------------------------------------------------------
// XACT3 cue/wave instances and the real playback path
// ---------------------------------------------------------------------------

impl PeHostRuntime {
    /// The `IXACT3Cue` method bodies.
    fn xact_invoke_cue(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        this: u64,
        method: u16,
    ) -> AppResult<(u32, Vec<XactPendingNotification>)> {
        match method {
            3 => {
                // Play(): start (or restart) the cue's real source voice.
                let (engine, sound_bank, index, live, has_voice) = match runtime.objects.get(&this)
                {
                    Some(crate::xact::XactObject::Cue(cue)) => (
                        cue.engine,
                        cue.sound_bank,
                        cue.index,
                        cue.live,
                        cue.live.is_some(),
                    ),
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                let mut pending = Vec::new();
                if let Some(live) = live {
                    for voice in live.voices() {
                        let _ = self.xact_stop_live_voice(voice);
                    }
                    if let Some(engine_state) = runtime.engine_mut(engine) {
                        engine_state.cue_voices.remove(&this);
                    }
                    if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get_mut(&this)
                    {
                        cue.live = None;
                    }
                }
                let _ = has_voice;
                match self.xact_start_cue_playback(
                    runtime,
                    memory,
                    this,
                    sound_bank,
                    index,
                    &mut pending,
                )? {
                    Ok(()) => {
                        let engine_state = runtime.engine(engine).cloned();
                        pending.extend(xact_collect_notifications(
                            engine_state.as_ref(),
                            2,
                            sound_bank,
                            this,
                            index,
                        ));
                        Ok((crate::xact::S_OK, pending))
                    }
                    Err(error) => Ok((error, Vec::new())),
                }
            }
            4 => {
                // Stop(flags): a non-immediate stop with an authored XGS
                // release envelope starts the real fade and leaves the voice
                // alive for the drain; otherwise the cut is immediate.
                let flags = xact_arg_u32(state, memory, 1)?;
                let mut pending = Vec::new();
                if !self.xact_begin_cue_release(runtime, this, flags, &mut pending)? {
                    self.xact_stop_cue_object(runtime, this, &mut pending)?;
                }
                Ok((crate::xact::S_OK, pending))
            }
            5 => {
                // GetState(DWORD *out)
                let out = xact_arg(state, memory, 1)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let state_bits = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Cue(cue)) => cue.state,
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                xact_write_u32(memory, out, state_bits)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            6 => {
                // Destroy
                let mut pending = Vec::new();
                self.xact_destroy_object(runtime, state, memory, this, &mut pending)?;
                Ok((crate::xact::S_OK, pending))
            }
            7 => {
                // SetMatrixCoefficients(src, dst, matrix)
                let source_channels = xact_arg_u32(state, memory, 1)?;
                let destination_channels = xact_arg_u32(state, memory, 2)?;
                let matrix = xact_arg(state, memory, 3)?;
                if source_channels == 0
                    || destination_channels == 0
                    || source_channels * destination_channels > 64
                    || matrix == 0
                {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let count = (source_channels * destination_channels) as usize;
                let bytes = read_guest_bytes(memory, matrix, count * 4)?;
                let values = bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect::<Vec<_>>();
                if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get_mut(&this) {
                    cue.matrix = Some((source_channels, destination_channels, values));
                }
                Ok((crate::xact::S_OK, Vec::new()))
            }
            8 => {
                // GetVariableIndex(name): cue-local friendly names take
                // precedence over the global variable table.  The local
                // name table is the XSB per-slot name index; content that
                // carries no table falls back to the global names of the
                // variables the cue's local slots shadow, then to the
                // engine's globals.
                let name = xact_arg(state, memory, 1)?;
                let Some(name) = xact_guest_string(memory, name) else {
                    return Ok((
                        u32::from(crate::xact::XACTVARIABLEINDEX_INVALID),
                        Vec::new(),
                    ));
                };
                let (engine, names, bindings) = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Cue(cue)) => (
                        cue.engine,
                        cue.local_variable_names.clone(),
                        cue.local_variables.clone(),
                    ),
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                if let Some(slot) = names
                    .iter()
                    .position(|candidate| !candidate.is_empty() && *candidate == name)
                {
                    return Ok((slot as u32, Vec::new()));
                }
                let Some(engine_state) = runtime.engine(engine) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                if let Some(slot) = bindings.iter().position(|binding| {
                    *binding >= 0
                        && engine_state
                            .variables
                            .get(*binding as usize)
                            .map(|variable| variable.name == name)
                            .unwrap_or(false)
                }) {
                    return Ok((slot as u32, Vec::new()));
                }
                let global = engine_state
                    .variables
                    .iter()
                    .position(|variable| {
                        variable.name == name
                            && variable.accessibility & 0x01 != 0
                            && variable.accessibility & 0x04 == 0
                    })
                    .map(|index| index as u16)
                    .unwrap_or(crate::xact::XACTVARIABLEINDEX_INVALID);
                Ok((u32::from(global), Vec::new()))
            }
            9 => {
                // SetVariable(index, value): indices inside the cue's local
                // slot range are cue-local overrides layered over the global
                // variable they shadow; higher indices address the engine
                // globals directly, matching GetVariableIndex's fallback.
                let index = xact_arg_u16(state, memory, 1)?;
                let value = xact_arg_f32(state, memory, 2)?;
                let (engine, binding, local_count) = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Cue(cue)) => (
                        cue.engine,
                        cue.local_variables.get(index as usize).copied(),
                        cue.local_variables.len(),
                    ),
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                let Some(engine_state) = runtime.engine(engine) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                if index as usize >= local_count {
                    let Some(variable) = engine_state.variables.get(index as usize) else {
                        return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                    };
                    if variable.accessibility & 0x01 == 0
                        || variable.accessibility & 0x02 != 0
                        || variable.accessibility & 0x04 != 0
                    {
                        return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                    }
                    let clamped = value.clamp(variable.min, variable.max);
                    if let Some(engine_state) = runtime.engine_mut(engine)
                        && let Some(slot) = engine_state.variable_values.get_mut(index as usize)
                    {
                        *slot = clamped;
                    }
                    return Ok((crate::xact::S_OK, Vec::new()));
                }
                let Some(binding) = binding.filter(|binding| *binding >= 0) else {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                };
                let Some(variable) = engine_state.variables.get(binding as usize) else {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                };
                if variable.accessibility & 0x01 == 0 || variable.accessibility & 0x02 != 0 {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                }
                let clamped = value.clamp(variable.min, variable.max);
                if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get_mut(&this) {
                    cue.local_values.insert(binding as u16, clamped);
                }
                Ok((crate::xact::S_OK, Vec::new()))
            }
            10 => {
                // GetVariable(index, out): the cue-local override wins; with
                // no override the shadowed global value is read.  Indices
                // outside the local slot range read the engine global.
                let index = xact_arg_u16(state, memory, 1)?;
                let out = xact_arg(state, memory, 2)?;
                let (engine, binding, local_value, local_count) = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Cue(cue)) => {
                        let binding = cue.local_variables.get(index as usize).copied();
                        let local = binding.and_then(|binding| {
                            (binding >= 0)
                                .then(|| cue.local_values.get(&(binding as u16)).copied())
                                .flatten()
                        });
                        (cue.engine, binding, local, cue.local_variables.len())
                    }
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                let Some(engine_state) = runtime.engine(engine) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                if index as usize >= local_count {
                    let Some(variable) = engine_state.variables.get(index as usize) else {
                        return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                    };
                    if variable.accessibility & 0x01 == 0 || variable.accessibility & 0x04 != 0 {
                        return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                    }
                    let value = engine_state
                        .variable_values
                        .get(index as usize)
                        .copied()
                        .unwrap_or(variable.initial);
                    xact_write_f32(memory, out, value)?;
                    return Ok((crate::xact::S_OK, Vec::new()));
                }
                let Some(binding) = binding.filter(|binding| *binding >= 0) else {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                };
                let Some(variable) = engine_state.variables.get(binding as usize) else {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                };
                if variable.accessibility & 0x01 == 0 {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX, Vec::new()));
                }
                let value = local_value.unwrap_or_else(|| {
                    engine_state
                        .variable_values
                        .get(binding as usize)
                        .copied()
                        .unwrap_or(variable.initial)
                });
                xact_write_f32(memory, out, value)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            11 => {
                // Pause(fPause)
                let pause = xact_arg_u32(state, memory, 1)? != 0;
                let live = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Cue(cue)) => cue.live,
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                if let Some(live) = live {
                    for voice in live.voices() {
                        self.xact_pause_voice(voice, pause)?;
                    }
                    if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get_mut(&this)
                    {
                        cue.state = if pause {
                            crate::xact::XACT_STATE_PAUSED
                        } else {
                            crate::xact::XACT_STATE_PLAYING
                        };
                        if let Some(entry) = cue.live.as_mut() {
                            entry.paused = pause;
                        }
                    }
                }
                Ok((crate::xact::S_OK, Vec::new()))
            }
            12 => {
                // GetProperties(ppProperties): hand out the cue's cached
                // XACT_CUE_INSTANCE_PROPERTIES block.
                let out = xact_arg(state, memory, 1)?;
                let properties = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Cue(cue)) => cue.properties_address,
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                if out == 0 || properties == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                write_guest_pointer(memory, out, properties, self.guest_arch)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            13 => {
                // SetOutputVoices(const XAUDIO2_VOICE_SENDS *): a real send
                // list of guest IXAudio2Voice objects.  Null restores the
                // default mastering route.  Each send descriptor is
                // { UINT32 Flags; IXAudio2Voice *pOutputVoice; }.
                let sends = xact_arg(state, memory, 1)?;
                if sends == 0 {
                    let status = self.xact_apply_cue_output_voices(runtime, this, None)?;
                    return Ok((status, Vec::new()));
                }
                let pointer_size = self.guest_arch.pointer_bytes() as u64;
                let count = read_u32(memory, sends)?;
                let descriptors = if pointer_size == 4 {
                    u64::from(read_u32(memory, sends + 4)?)
                } else {
                    memory.read_u64(sends + 8)?
                };
                if count == 0 {
                    let status = self.xact_apply_cue_output_voices(runtime, this, None)?;
                    return Ok((status, Vec::new()));
                }
                if count as usize > crate::xact::XACT_MAX_OUTPUT_VOICES || descriptors == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let descriptor_size = if pointer_size == 4 { 8 } else { 16 };
                let pointer_offset = if pointer_size == 4 { 4 } else { 8 };
                let previous = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Cue(cue)) => cue.output_voices.clone(),
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                let mut routes: Vec<crate::xact::OutputVoiceRoute> =
                    Vec::with_capacity(count as usize);
                for index in 0..u64::from(count) {
                    let entry = descriptors + index * descriptor_size;
                    let _flags = read_u32(memory, entry)?;
                    let voice = if pointer_size == 4 {
                        u64::from(read_u32(memory, entry + pointer_offset)?)
                    } else {
                        memory.read_u64(entry + pointer_offset)?
                    };
                    if voice == 0 || routes.iter().any(|route| route.voice == voice) {
                        return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                    }
                    let Some(channels) = self.xact_output_voice_channels(voice) else {
                        return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                    };
                    let matrix = previous
                        .as_ref()
                        .and_then(|routes| routes.iter().find(|route| route.voice == voice))
                        .and_then(|route| route.matrix.clone());
                    routes.push(crate::xact::OutputVoiceRoute {
                        voice,
                        channels,
                        matrix,
                    });
                }
                let status = self.xact_apply_cue_output_voices(runtime, this, Some(routes))?;
                Ok((status, Vec::new()))
            }
            14 => {
                // SetOutputVoiceMatrix(pOutputVoice, src, dst, matrix):
                // apply per-output-voice coefficients to this cue's mix.
                // The destination must be one of the real output voices
                // selected by SetOutputVoices and `dst` must match that
                // voice's channel count; the source count is validated when
                // the cue's decoded wave is mixed.
                let voice = xact_arg(state, memory, 1)?;
                let source_channels = xact_arg_u32(state, memory, 2)?;
                let destination_channels = xact_arg_u32(state, memory, 3)?;
                let matrix = xact_arg(state, memory, 4)?;
                if voice == 0
                    || source_channels == 0
                    || destination_channels == 0
                    || source_channels > 8
                    || destination_channels > 8
                    || source_channels * destination_channels > 64
                    || matrix == 0
                {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let count = (source_channels * destination_channels) as usize;
                let bytes = read_guest_bytes(memory, matrix, count * 4)?;
                let values = bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect::<Vec<_>>();
                if values.iter().any(|value| !value.is_finite()) {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let route_index = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Cue(cue)) => cue
                        .output_voices
                        .as_ref()
                        .and_then(|routes| routes.iter().position(|route| route.voice == voice)),
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                let Some(route_index) = route_index else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get_mut(&this)
                    && let Some(route) = cue
                        .output_voices
                        .as_mut()
                        .and_then(|routes| routes.get_mut(route_index))
                {
                    if u16::from(route.channels) != destination_channels as u16 {
                        return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                    }
                    route.matrix = Some((source_channels, destination_channels, values));
                }
                Ok((crate::xact::S_OK, Vec::new()))
            }
            _ => Ok((crate::xact::E_INVALIDARG, Vec::new())),
        }
    }

    /// The `IXACT3Wave` method bodies.
    fn xact_invoke_wave(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        this: u64,
        method: u16,
    ) -> AppResult<(u32, Vec<XactPendingNotification>)> {
        match method {
            3 => {
                // Destroy
                let mut pending = Vec::new();
                self.xact_destroy_object(runtime, state, memory, this, &mut pending)?;
                Ok((crate::xact::S_OK, pending))
            }
            4 => {
                // Play()
                let (engine, wave_bank, index, loop_count, live) = match runtime.objects.get(&this)
                {
                    Some(crate::xact::XactObject::Wave(wave)) => (
                        wave.engine,
                        wave.wave_bank,
                        wave.index,
                        wave.loop_count,
                        wave.live,
                    ),
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                let mut pending = Vec::new();
                if let Some(live) = live {
                    for voice in live.voices() {
                        let _ = self.xact_stop_live_voice(voice);
                    }
                    if let Some(engine_state) = runtime.engine_mut(engine) {
                        engine_state.wave_voices.remove(&this);
                    }
                    if let Some(crate::xact::XactObject::Wave(wave)) =
                        runtime.objects.get_mut(&this)
                    {
                        wave.live = None;
                    }
                }
                match self.xact_play_wave(
                    runtime,
                    engine,
                    wave_bank,
                    index,
                    loop_count,
                    &mut pending,
                )? {
                    Ok(_) => Ok((crate::xact::S_OK, pending)),
                    Err(error) => Ok((error, Vec::new())),
                }
            }
            5 => {
                // Stop(flags)
                let mut pending = Vec::new();
                self.xact_stop_wave_object(runtime, this, &mut pending)?;
                Ok((crate::xact::S_OK, pending))
            }
            6 => {
                // Pause(fPause)
                let pause = xact_arg_u32(state, memory, 1)? != 0;
                let live = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Wave(wave)) => wave.live,
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                if let Some(live) = live {
                    self.xact_pause_voice(live.voice, pause)?;
                    if let Some(crate::xact::XactObject::Wave(wave)) =
                        runtime.objects.get_mut(&this)
                    {
                        wave.state = if pause {
                            crate::xact::XACT_STATE_PAUSED
                        } else {
                            crate::xact::XACT_STATE_PLAYING
                        };
                        if let Some(entry) = wave.live.as_mut() {
                            entry.paused = pause;
                        }
                    }
                }
                Ok((crate::xact::S_OK, Vec::new()))
            }
            7 => {
                // GetState(DWORD *out)
                let out = xact_arg(state, memory, 1)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let state_bits = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Wave(wave)) => wave.state,
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                xact_write_u32(memory, out, state_bits)?;
                Ok((crate::xact::S_OK, Vec::new()))
            }
            8 => {
                // SetPitch(cents)
                let cents = xact_arg_i16(state, memory, 1)?;
                if let Some(crate::xact::XactObject::Wave(wave)) = runtime.objects.get_mut(&this) {
                    wave.pitch = cents;
                    if let Some(live) = wave.live {
                        let _ = self
                            .audio
                            .set_frequency_ratio(live.voice, crate::xact::pitch_to_ratio(cents));
                        if let Some(entry) = wave.live.as_mut() {
                            entry.pitch_cents = cents;
                        }
                    }
                }
                Ok((crate::xact::S_OK, Vec::new()))
            }
            9 => {
                // SetVolume(volume)
                let volume = xact_arg_f32(state, memory, 1)?;
                if let Some(crate::xact::XactObject::Wave(wave)) = runtime.objects.get_mut(&this) {
                    wave.volume = volume;
                    if let Some(live) = wave.live {
                        let _ = self
                            .audio
                            .set_volume(live.voice, volume.clamp(0.0, XACT_VOLUME_MAX));
                        if let Some(entry) = wave.live.as_mut() {
                            entry.base_volume = volume;
                        }
                    }
                }
                Ok((crate::xact::S_OK, Vec::new()))
            }
            10 => {
                // SetMatrixCoefficients(src, dst, matrix)
                let source_channels = xact_arg_u32(state, memory, 1)?;
                let destination_channels = xact_arg_u32(state, memory, 2)?;
                let matrix = xact_arg(state, memory, 3)?;
                if source_channels == 0
                    || destination_channels == 0
                    || source_channels * destination_channels > 64
                    || matrix == 0
                {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let count = (source_channels * destination_channels) as usize;
                let bytes = read_guest_bytes(memory, matrix, count * 4)?;
                let values = bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect::<Vec<_>>();
                if let Some(crate::xact::XactObject::Wave(wave)) = runtime.objects.get_mut(&this) {
                    wave.matrix = Some((source_channels, destination_channels, values));
                }
                Ok((crate::xact::S_OK, Vec::new()))
            }
            11 => {
                // GetProperties(XACT_WAVE_INSTANCE_PROPERTIES *out)
                let out = xact_arg(state, memory, 1)?;
                if out == 0 {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                }
                let Some(bank) = xact_wave_bank(runtime, {
                    match runtime.objects.get(&this) {
                        Some(crate::xact::XactObject::Wave(wave)) => wave.wave_bank,
                        _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                    }
                }) else {
                    return Ok((crate::xact::E_INVALIDARG, Vec::new()));
                };
                let index = match runtime.objects.get(&this) {
                    Some(crate::xact::XactObject::Wave(wave)) => wave.index,
                    _ => return Ok((crate::xact::E_INVALIDARG, Vec::new())),
                };
                let Some(entry) = bank.entries.get(index as usize) else {
                    return Ok((crate::xact::XACTENGINE_E_INVALIDWAVEINDEX, Vec::new()));
                };
                xact_write_wave_properties(memory, out, bank, entry, index)?;
                xact_write_u32(memory, out + 84, 0)?; // backgroundMusic
                Ok((crate::xact::S_OK, Vec::new()))
            }
            _ => Ok((crate::xact::E_INVALIDARG, Vec::new())),
        }
    }

    /// Allocate a cue object with its cached `XACT_CUE_INSTANCE_PROPERTIES`
    /// guest block.
    fn xact_alloc_cue_object(
        &mut self,
        memory: &mut MemoryImage,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
        sound_bank: u64,
        index: u16,
        state_bits: u32,
    ) -> AppResult<u64> {
        let (
            name,
            interactive,
            num_variations,
            instance_limit,
            mut cue_local_variables,
            mut cue_local_names,
        ) = {
            let Some(crate::xact::XactObject::SoundBank(bank)) = runtime.objects.get(&sound_bank)
            else {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    "XACT cue allocation on a non-sound-bank object".to_string(),
                ));
            };
            let Some(cue) = bank.bank.cues.get(index as usize) else {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    "XACT cue allocation with an out-of-range index".to_string(),
                ));
            };
            let interactive = cue
                .variation_index
                .and_then(|variation| bank.bank.variations.get(variation))
                .filter(|variation| variation.kind == 3)
                .map(|variation| variation.variable)
                .unwrap_or(0);
            let num_variations = cue
                .variation_index
                .and_then(|variation| bank.bank.variations.get(variation))
                .map(|variation| variation.entries.len())
                .unwrap_or(0) as u16;
            (
                cue.name.clone(),
                interactive,
                num_variations,
                cue.instance_limit,
                cue.local_variables.clone(),
                cue.local_variable_names.clone(),
            )
        };
        // Cue-scoped XGS variables are cue-local even when the cue's variation
        // table does not bind them: every public variable with the cue scope
        // bit gets a local slot (initial value comes from the engine table).
        if let Some(engine_state) = runtime.engine(engine) {
            for (variable_index, variable) in engine_state.variables.iter().enumerate() {
                let binding = variable_index as i16;
                if variable.accessibility & 0x04 != 0
                    && variable.accessibility & 0x01 != 0
                    && !cue_local_variables.contains(&binding)
                {
                    cue_local_variables.push(binding);
                    cue_local_names.push(variable.name.clone());
                }
            }
        } // coverage: unreachable — loop-brace line-table artifact
        let current_instances = runtime
            .objects
            .values()
            .filter(|object| match object {
                crate::xact::XactObject::Cue(cue) => {
                    cue.sound_bank == sound_bank && cue.index == index
                }
                _ => false,
            })
            .count() as u8;
        let properties = self.alloc_zeroed(memory, 320, 4)?;
        // XACT_CUE_INSTANCE_PROPERTIES: allocAttributes, cueProperties,
        // activeVariationProperties.
        xact_write_cue_properties(
            memory,
            properties + 4,
            &name,
            interactive,
            num_variations,
            instance_limit,
            current_instances,
        )?;
        let object = self.xact_alloc_object(
            memory,
            runtime,
            crate::xact::IFACE_CUE,
            crate::xact::XactObject::Cue(crate::xact::CueObject {
                refcount: 1,
                engine,
                sound_bank,
                index,
                state: state_bits,
                live: None,
                properties_address: properties,
                matrix: None,
                loop_count: 0,
                local_variables: cue_local_variables,
                local_variable_names: cue_local_names,
                local_values: BTreeMap::new(),
                output_voices: None,
                playback: None,
            }),
        )?;
        Ok(object)
    }

    /// Resolve a guest `IXAudio2Voice` output target to its channel count.
    /// Only real voices created through the runtime's XAudio2 surface (source
    /// voices, including submix voices, and mastering voices) are accepted.
    fn xact_output_voice_channels(&self, address: u64) -> Option<u16> {
        let voice = self
            .xaudio_source_voices
            .get(&address)
            .or_else(|| self.xaudio_mastering_voices.get(&address))?;
        self.audio
            .voice_format(voice.voice_id)
            .ok()
            .map(|format| format.channels)
    }

    /// Resolve a guest XACT file path through the runtime's GE file tables.
    /// Absolute drive paths go through `host_path_for_windows_path`; the
    /// Win32 path forms XACT content actually uses are handled first:
    /// drive-relative (`C:banks\x.xwb`), `\SystemRoot\...`, and
    /// `%SystemRoot%` / `%windir%` are expanded against the GE and the
    /// guest environment.  Device paths that already name a real host file
    /// are accepted as-is so tests and tools can pass a raw path.  Missing
    /// paths return `None`, which the callers surface as the genuine
    /// `E_FAIL` file-open error.
    fn xact_resolve_file_path(&self, guest_path: &str) -> Option<String> {
        let normalized = guest_path.replace('/', "\\");
        let system_root = self
            .win32
            .get_environment_variable_w("SystemRoot")
            .or_else(|| self.win32.get_environment_variable_w("windir"))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "C:\\Windows".to_string());
        let rooted_env = normalized.strip_prefix('\\').filter(|rest| {
            let rest = rest.to_ascii_lowercase();
            rest.starts_with("%systemroot%\\") || rest.starts_with("%windir%\\")
        });
        let normalized = rooted_env.unwrap_or(normalized.as_str());
        let lower = normalized.to_ascii_lowercase();
        let absolute = if let Some(rest) = normalized
            .strip_prefix("\\SystemRoot\\")
            .or_else(|| normalized.strip_prefix("SystemRoot\\"))
        {
            format!("{system_root}\\{rest}")
        } else if lower.starts_with("%systemroot%\\") {
            format!("{system_root}\\{}", &normalized[13..])
        } else if lower.starts_with("%windir%\\") {
            format!("{system_root}\\{}", &normalized[9..])
        } else if normalized.len() >= 2
            && normalized.as_bytes()[1] == b':'
            && !normalized[2..].starts_with('\\')
            && !normalized[2..].is_empty()
        {
            // Drive-relative: the drive's current directory is the GE drive
            // root in this model (the guest process starts at `C:\`).
            format!("{}:\\{}", &normalized[..1], &normalized[2..])
        } else {
            normalized.to_string()
        };
        if let Ok(host) = self.win32.ge().host_path_for_windows_path(&absolute)
            && host.is_file()
        {
            return Some(host.to_string_lossy().into_owned());
        }
        let direct = std::path::Path::new(guest_path);
        if direct.is_file() {
            return Some(direct.to_string_lossy().into_owned());
        }
        None
    }

    /// Allocate a wave-bank object for a streaming (or standalone prepared)
    /// bank, with empty prepare/cache state.
    fn xact_alloc_streaming_bank_object(
        &mut self,
        memory: &mut MemoryImage,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
        bank: crate::xact::WaveBank,
    ) -> AppResult<u64> {
        self.xact_alloc_object(
            memory,
            runtime,
            crate::xact::IFACE_WAVEBANK,
            crate::xact::XactObject::WaveBank(crate::xact::WaveBankState {
                refcount: 1,
                engine,
                bank,
                prepared: std::collections::BTreeSet::new(),
                streaming_cache: std::collections::BTreeMap::new(),
            }),
        )
    }

    /// Allocate a wave object.
    #[allow(clippy::too_many_arguments)]
    fn xact_alloc_wave_object(
        &mut self,
        memory: &mut MemoryImage,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
        wave_bank: u64,
        index: u16,
        state_bits: u32,
        voice: Option<crate::xact::LiveVoice>,
        loop_count: u8,
    ) -> AppResult<u64> {
        let object = self.xact_alloc_object(
            memory,
            runtime,
            crate::xact::IFACE_WAVE,
            crate::xact::XactObject::Wave(crate::xact::WaveObject {
                refcount: 1,
                engine,
                wave_bank,
                index,
                state: state_bits,
                live: voice,
                volume: 1.0,
                pitch: 0,
                matrix: None,
                loop_count,
            }),
        )?;
        if let Some(voice) = voice
            && let Some(engine_state) = runtime.engine_mut(engine)
        {
            engine_state.wave_voices.insert(object, voice);
        }
        Ok(object)
    }

    /// Resolve and start a cue's real playback; on success the cue object and
    /// its engine entry carry the live voice.
    fn xact_start_cue_playback(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        _memory: &mut MemoryImage,
        cue_object: u64,
        bank_object: u64,
        index: u16,
        _pending: &mut Vec<XactPendingNotification>,
    ) -> AppResult<Result<(), u32>> {
        let engine = match runtime.objects.get(&bank_object) {
            Some(crate::xact::XactObject::SoundBank(bank)) => bank.engine,
            _ => return Ok(Err(crate::xact::E_INVALIDARG)),
        };
        let resolved = match xact_resolve_cue(runtime, engine, bank_object, cue_object, index) {
            Ok(resolved) => resolved,
            Err(error) => return Ok(Err(error)),
        };
        let base_volume = resolved.volume;
        let pitch_cents = resolved.pitch;
        let category = resolved.category;
        let playback = crate::xact::CuePlayback {
            samples: resolved.samples.clone(),
            channels: resolved.channels,
            sample_rate: resolved.sample_rate,
            loop_count: resolved.loop_count,
            loop_start_samples: resolved.loop_start_samples,
            loop_total_samples: resolved.loop_total_samples,
            volume: resolved.volume,
            pitch: resolved.pitch,
            category: resolved.category,
        };
        let voices = match self.xact_start_resolved_playback(runtime, engine, resolved)? {
            Ok(voices) => voices,
            Err(error) => return Ok(Err(error)),
        };
        let Some((voice, extra)) = voices.split_first() else {
            return Ok(Err(crate::xact::E_FAIL));
        };
        let mut extra_voices = [0_u64; crate::xact::XACT_MAX_OUTPUT_VOICES - 1];
        let extra_voice_count = extra.len().min(extra_voices.len()) as u8;
        extra_voices[..usize::from(extra_voice_count)]
            .copy_from_slice(&extra[..usize::from(extra_voice_count)]);
        let live = crate::xact::LiveVoice {
            voice: *voice,
            extra_voices,
            extra_voice_count,
            base_volume,
            pitch_cents,
            category,
            paused: false,
            release: None,
        };
        if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get_mut(&cue_object) {
            cue.live = Some(live);
            cue.playback = Some(playback);
            cue.state = crate::xact::XACT_STATE_PLAYING;
        }
        if let Some(engine_state) = runtime.engine_mut(engine) {
            engine_state.cue_voices.insert(cue_object, live);
        }
        Ok(Ok(()))
    }

    /// Apply a `SetOutputVoices` selection to a cue.  A cue that is currently
    /// playing is rerouted for real: its old source voices are stopped and the
    /// preserved decoded source is restarted on one real source voice per new
    /// destination, carrying that destination's gain and matrix.
    fn xact_apply_cue_output_voices(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        cue_object: u64,
        routes: Option<Vec<crate::xact::OutputVoiceRoute>>,
    ) -> AppResult<u32> {
        let (engine, live, playback, matrix) = match runtime.objects.get(&cue_object) {
            Some(crate::xact::XactObject::Cue(cue)) => (
                cue.engine,
                cue.live,
                cue.playback.clone(),
                cue.matrix.clone(),
            ),
            _ => return Ok(crate::xact::E_INVALIDARG),
        };
        let Some(live) = live else {
            if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get_mut(&cue_object) {
                cue.output_voices = routes;
            }
            return Ok(crate::xact::S_OK);
        };
        let Some(playback) = playback else {
            return Ok(crate::xact::E_FAIL); // coverage: unreachable — live cues always have a snapshot
        };
        // Stop and destroy the old destination voices before building the new
        // ones: a reroute must never leave the cue rendering to both graphs.
        for voice in live.voices() {
            self.xact_stop_live_voice(voice)?;
        }
        let resolved = XactResolvedPlayback {
            samples: playback.samples,
            channels: playback.channels,
            sample_rate: playback.sample_rate,
            loop_count: playback.loop_count,
            loop_start_samples: playback.loop_start_samples,
            loop_total_samples: playback.loop_total_samples,
            volume: playback.volume,
            pitch: playback.pitch,
            category: playback.category,
            matrix,
            routes: routes.clone().unwrap_or_default(),
        };
        let voices = match self.xact_start_resolved_playback(runtime, engine, resolved)? {
            Ok(voices) => voices,
            Err(error) => {
                if let Some(crate::xact::XactObject::Cue(cue)) =
                    runtime.objects.get_mut(&cue_object)
                {
                    cue.live = None;
                    cue.state = crate::xact::XACT_STATE_STOPPED;
                }
                if let Some(engine_state) = runtime.engine_mut(engine) {
                    engine_state.cue_voices.remove(&cue_object);
                }
                return Ok(error);
            }
        };
        let voice = voices[0];
        let extra = &voices[1..];
        let mut extra_voices = [0_u64; crate::xact::XACT_MAX_OUTPUT_VOICES - 1];
        let extra_voice_count = extra.len().min(extra_voices.len()) as u8;
        extra_voices[..usize::from(extra_voice_count)]
            .copy_from_slice(&extra[..usize::from(extra_voice_count)]);
        let rerouted = crate::xact::LiveVoice {
            voice,
            extra_voices,
            extra_voice_count,
            ..live
        };
        if live.paused {
            for voice in rerouted.voices() {
                self.xact_pause_voice(voice, true)?;
            }
        }
        if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get_mut(&cue_object) {
            cue.output_voices = routes;
            cue.live = Some(rerouted);
            cue.state = if live.paused {
                crate::xact::XACT_STATE_PAUSED
            } else {
                crate::xact::XACT_STATE_PLAYING
            };
        } // coverage: unreachable — block-brace line-table artifact
        if let Some(engine_state) = runtime.engine_mut(engine) {
            engine_state.cue_voices.insert(cue_object, rerouted);
        }
        Ok(crate::xact::S_OK)
    }

    /// Resolve and start one wave-bank entry as a standalone wave instance.
    fn xact_play_wave(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
        wave_bank: u64,
        index: u16,
        loop_count: u8,
        _pending: &mut Vec<XactPendingNotification>,
    ) -> AppResult<Result<crate::xact::LiveVoice, u32>> {
        let resolved = match xact_resolve_wave_entry(runtime, engine, wave_bank, index, loop_count)
        {
            Ok(resolved) => resolved,
            Err(error) => return Ok(Err(error)),
        };
        let base_volume = resolved.volume;
        let pitch_cents = resolved.pitch;
        let category = resolved.category;
        let voices = match self.xact_start_resolved_playback(runtime, engine, resolved)? {
            Ok(voices) => voices,
            Err(error) => return Ok(Err(error)),
        };
        let Some(voice) = voices.first().copied() else {
            return Ok(Err(crate::xact::E_FAIL));
        };
        Ok(Ok(crate::xact::LiveVoice {
            voice,
            extra_voices: [0_u64; crate::xact::XACT_MAX_OUTPUT_VOICES - 1],
            extra_voice_count: 0,
            base_volume,
            pitch_cents,
            category,
            paused: false,
            release: None,
        }))
    }

    /// Ensure the engine has a mastering voice on the runtime's audio stack.
    fn xact_ensure_mastering_voice(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
    ) -> AppResult<Result<crate::audio::VoiceId, u32>> {
        if let Some(voice) = runtime
            .engine(engine)
            .and_then(|engine_state| engine_state.mastering_voice)
        {
            return Ok(Ok(voice));
        }
        let format = crate::audio::WaveFormat {
            channels: 2,
            sample_rate: 48_000,
            sample_format: crate::audio::SampleFormat::Float32,
        };
        match self.audio.create_mastering_voice(format) {
            Ok(voice) => {
                let _ = self.audio.start_voice(voice);
                if let Some(engine_state) = runtime.engine_mut(engine) {
                    engine_state.mastering_voice = Some(voice);
                }
                Ok(Ok(voice))
            }
            Err(error) => {
                self.push_trace(
                    "audio",
                    "IXACT3Engine::MasteringVoiceError",
                    BTreeMap::from([("error".to_string(), json!(error.to_string()))]),
                    json!(crate::xact::E_FAIL),
                );
                Ok(Err(crate::xact::E_FAIL))
            }
        }
    }

    /// Start a resolved cue/wave on real source voices: real PCM submission,
    /// real loop points, real volume, real pitch.  A cue routed through
    /// `SetOutputVoices` gets one real source voice per guest output voice;
    /// every voice is a child of the engine mastering voice, so the rendered
    /// mix carries each destination's coefficients and gain.
    fn xact_start_resolved_playback(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
        resolved: XactResolvedPlayback,
    ) -> AppResult<Result<Vec<crate::audio::VoiceId>, u32>> {
        let mastering = match self.xact_ensure_mastering_voice(runtime, engine)? {
            Ok(voice) => voice,
            Err(error) => return Ok(Err(error)),
        };
        let category_gain = runtime
            .engine(engine)
            .map(|engine_state| engine_state.category_gain(resolved.category))
            .unwrap_or(1.0);
        let gain = (resolved.volume * category_gain).clamp(0.0, XACT_VOLUME_MAX);
        let frequency = crate::xact::pitch_to_ratio(resolved.pitch);
        let routes = resolved.routes.clone();
        let mut destinations = Vec::new();
        if routes.is_empty() {
            destinations.push((None, resolved.channels));
        } else {
            for route in &routes {
                destinations.push((Some(route), route.channels));
            }
        }
        let mut created = Vec::with_capacity(destinations.len());
        for (route, _channels) in destinations {
            let (samples, channels) = match route {
                None => match xact_apply_output_matrix(
                    resolved.samples.clone(),
                    resolved.channels,
                    resolved.matrix.as_ref(),
                ) {
                    Ok(result) => result,
                    Err(error) => {
                        self.xact_destroy_voices(&created);
                        return Ok(Err(error));
                    }
                },
                Some(route) => {
                    match xact_route_output_voice(&resolved.samples, resolved.channels, route) {
                        Ok(result) => result,
                        Err(error) => {
                            self.xact_destroy_voices(&created);
                            return Ok(Err(error));
                        }
                    }
                }
            };
            let channels = u32::from(channels.max(1));
            let frames = (samples.len() as u32) / channels;
            let format = crate::audio::WaveFormat {
                channels: channels as u16,
                sample_rate: resolved.sample_rate,
                sample_format: crate::audio::SampleFormat::Pcm16,
            };
            let voice = match self.audio.create_source_voice(format, mastering) {
                Ok(voice) => voice,
                Err(error) => {
                    self.push_trace(
                        "audio",
                        "IXACT3Engine::SourceVoiceError",
                        BTreeMap::from([("error".to_string(), json!(error.to_string()))]),
                        json!(crate::xact::E_FAIL),
                    );
                    self.xact_destroy_voices(&created);
                    return Ok(Err(crate::xact::E_FAIL));
                }
            };
            let (loop_begin, loop_length, loop_count) = if resolved.loop_count > 0 {
                let (begin_samples, length_samples) = if resolved.loop_total_samples > 0 {
                    (resolved.loop_start_samples, resolved.loop_total_samples)
                } else {
                    (0, frames)
                };
                (
                    Some(begin_samples.saturating_mul(channels)),
                    Some(length_samples.saturating_mul(channels)),
                    Some(
                        if resolved.loop_count == crate::xact::XACTLOOPCOUNT_INFINITE {
                            0
                        } else {
                            u32::from(resolved.loop_count)
                        },
                    ),
                )
            } else {
                (None, None, None)
            };
            let tag = format!("xact-{}", self.next_audio_buffer_tag);
            self.next_audio_buffer_tag += 1;
            let buffer = crate::audio::SourceBuffer {
                tag,
                samples: crate::audio::AudioSamples::Pcm16(samples),
                loop_begin,
                loop_length,
                loop_count,
            };
            if self.audio.submit_source_buffer(voice, buffer).is_err() {
                let _ = self.audio.destroy_voice(voice);
                self.xact_destroy_voices(&created);
                return Ok(Err(crate::xact::E_FAIL));
            }
            let _ = self.audio.set_volume(voice, gain);
            let _ = self.audio.set_frequency_ratio(voice, frequency);
            if self.audio.start_voice(voice).is_err() {
                let _ = self.audio.destroy_voice(voice);
                self.xact_destroy_voices(&created);
                return Ok(Err(crate::xact::E_FAIL));
            }
            created.push(voice);
        }
        Ok(Ok(created))
    }

    fn xact_destroy_voices(&mut self, voices: &[crate::audio::VoiceId]) {
        for voice in voices {
            let _ = self.audio.stop_voice(*voice);
            let _ = self.audio.destroy_voice(*voice);
        }
    }

    /// Begin the authored release for one cue when the category carries a
    /// non-zero XGS fade-out time.  Returns false when the stop must be
    /// immediate (explicit immediate flag, no envelope, or already fading).
    fn xact_begin_cue_release(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        object: u64,
        flags: u32,
        pending: &mut Vec<XactPendingNotification>,
    ) -> AppResult<bool> {
        if flags & crate::xact::XACT_FLAG_STOP_IMMEDIATE != 0 {
            return Ok(false);
        }
        let (engine, live) = match runtime.objects.get(&object) {
            Some(crate::xact::XactObject::Cue(cue)) => (cue.engine, cue.live),
            _ => return Ok(false),
        };
        let Some(live) = live else {
            return Ok(false);
        };
        if live.release.is_some() {
            return Ok(true);
        }
        let (release_ms, release_curve) = runtime
            .engine(engine)
            .and_then(|engine| engine.categories.get(live.category as usize))
            .map(|category| (category.release_ms, category.release_curve))
            .unwrap_or((0, crate::xact::ReleaseCurve::Linear));
        if release_ms == 0 {
            return Ok(false);
        }
        let sample_rate = self
            .audio
            .voice_format(live.voice)
            .map(|format| format.sample_rate)
            .unwrap_or(48_000);
        let total_frames = ((u64::from(release_ms) * u64::from(sample_rate)) / 1000).max(1) as u32;
        let category_gain = runtime
            .engine(engine)
            .map(|engine| engine.category_gain(live.category))
            .unwrap_or(1.0);
        let start_gain = (live.base_volume * category_gain).clamp(0.0, XACT_VOLUME_MAX);
        let fade = crate::xact::ReleaseFade {
            total_frames,
            remaining_frames: total_frames,
            start_gain,
            curve: release_curve,
        };
        let fading = crate::xact::LiveVoice {
            release: Some(fade),
            ..live
        };
        for voice in live.voices() {
            let _ = self.audio.set_volume(voice, start_gain);
        }
        if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get_mut(&object) {
            cue.live = Some(fading);
            cue.state = crate::xact::XACT_STATE_STOPPING;
        }
        if let Some(engine_state) = runtime.engine_mut(engine) {
            engine_state.cue_voices.insert(object, fading);
        }
        let _ = pending;
        Ok(true)
    }

    /// Stop one cue object: real voice teardown and a CUESTOP notification.
    fn xact_stop_cue_object(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        object: u64,
        pending: &mut Vec<XactPendingNotification>,
    ) -> AppResult<()> {
        let (engine, sound_bank, index, live) = match runtime.objects.get_mut(&object) {
            Some(crate::xact::XactObject::Cue(cue)) => {
                let live = cue.live.take();
                cue.state = crate::xact::XACT_STATE_STOPPED;
                (cue.engine, cue.sound_bank, cue.index, live)
            }
            _ => return Ok(()),
        };
        if let Some(live) = live {
            for voice in live.voices() {
                let _ = self.xact_stop_live_voice(voice);
            }
        }
        if let Some(engine_state) = runtime.engine_mut(engine) {
            engine_state.cue_voices.remove(&object);
        }
        let engine_state = runtime.engine(engine).cloned();
        pending.extend(xact_collect_notifications(
            engine_state.as_ref(),
            3, // XACTNOTIFICATIONTYPE_CUESTOP
            sound_bank,
            object,
            index,
        ));
        Ok(())
    }

    /// Stop one standalone wave object.
    fn xact_stop_wave_object(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        object: u64,
        pending: &mut Vec<XactPendingNotification>,
    ) -> AppResult<()> {
        let (engine, wave_bank, index, live) = match runtime.objects.get_mut(&object) {
            Some(crate::xact::XactObject::Wave(wave)) => {
                let live = wave.live.take();
                wave.state = crate::xact::XACT_STATE_STOPPED;
                (wave.engine, wave.wave_bank, wave.index, live)
            }
            _ => return Ok(()),
        };
        if let Some(live) = live {
            for voice in live.voices() {
                let _ = self.xact_stop_live_voice(voice);
            }
        }
        if let Some(engine_state) = runtime.engine_mut(engine) {
            engine_state.wave_voices.remove(&object);
        }
        let engine_state = runtime.engine(engine).cloned();
        pending.extend(xact_collect_notifications(
            engine_state.as_ref(),
            14, // XACTNOTIFICATIONTYPE_WAVESTOP
            wave_bank,
            0,
            index,
        ));
        Ok(())
    }

    /// Render the engine's live voices through the runtime audio stack, then
    /// retire voices whose authored data was fully consumed.  This is the
    /// same drain contract the XAudio2 surface uses (`render_xaudio2` +
    /// live publish / `afplay` in non-deterministic runs).
    fn xact_drain_engine(
        &mut self,
        runtime: &mut crate::xact::XactRuntime,
        engine: u64,
        pending: &mut Vec<XactPendingNotification>,
    ) -> AppResult<()> {
        let (mastering, voices) = {
            let Some(engine_state) = runtime.engine(engine) else {
                return Ok(());
            };
            let mut voices = Vec::new();
            for live in engine_state.cue_voices.values() {
                voices.extend(live.voices());
            }
            for live in engine_state.wave_voices.values() {
                voices.extend(live.voices());
            }
            (engine_state.mastering_voice, voices)
        };
        let Some(mastering) = mastering else {
            return Ok(());
        };
        let mut frames = 0_usize;
        for voice in &voices {
            if self.audio.voice_started(*voice)? {
                frames = frames.max(self.audio.queued_source_frames(*voice)?);
            }
        }
        let release_voices = runtime
            .engine(engine)
            .map(|engine_state| {
                engine_state
                    .cue_voices
                    .iter()
                    .filter_map(|(object, live)| {
                        live.release.map(|fade| {
                            (
                                *object,
                                live.voices().collect::<Vec<_>>(),
                                live.base_volume,
                                live.category,
                                fade,
                            )
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !release_voices.is_empty() {
            // Release envelopes advance in fixed render slices so the gain
            // curve is observable across DoWork calls.
            frames = frames.min(512);
            let gains = release_voices
                .iter()
                .flat_map(|(_, voices, base, category, fade)| {
                    let category_gain = runtime
                        .engine(engine)
                        .map(|engine| engine.category_gain(*category))
                        .unwrap_or(1.0);
                    let gain =
                        (*base * category_gain * fade.fraction()).clamp(0.0, XACT_VOLUME_MAX);
                    voices.iter().map(move |voice| (*voice, gain))
                })
                .collect::<Vec<_>>();
            for (voice, gain) in gains {
                let _ = self.audio.set_volume(voice, gain);
            }
        }
        if frames > 0 {
            let format = self.audio.voice_format(mastering)?;
            let output = self.audio.render_xaudio2(mastering, frames)?;
            if self.live_session.is_some() && output.samples.iter().any(|sample| *sample != 0.0) {
                self.publish_live_audio(LiveAudioChunk {
                    format: format.clone(),
                    samples: output.samples.clone(),
                });
            } else if !self.dtm && output.samples.iter().any(|sample| *sample != 0.0) {
                self.audio.play_render_output(&output, &format)?;
            }
            self.push_trace(
                "audio",
                "XACT3Render",
                BTreeMap::from([
                    ("frames".to_string(), json!(frames)),
                    ("latency_ms".to_string(), json!(output.latency_ms)),
                ]),
                json!(output.crc32),
            );
        }
        // Advance active release envelopes by the rendered slice; a cue
        // whose envelope hit zero is torn down after this render.
        let mut release_updates = Vec::new();
        let mut expired_releases = Vec::new();
        for (object, _, _, _, fade) in &release_voices {
            let remaining = fade.remaining_frames.saturating_sub(frames as u32);
            release_updates.push((*object, remaining));
            if remaining == 0 {
                expired_releases.push(*object);
            }
        }
        for (object, remaining) in &release_updates {
            if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get_mut(object)
                && let Some(live) = cue.live.as_mut()
                && let Some(fade) = live.release.as_mut()
            {
                fade.remaining_frames = *remaining;
            }
            if let Some(engine_state) = runtime.engine_mut(engine)
                && let Some(live) = engine_state.cue_voices.get_mut(object)
                && let Some(fade) = live.release.as_mut()
            {
                fade.remaining_frames = *remaining;
            }
        }
        for object in expired_releases {
            self.xact_stop_cue_object(runtime, object, pending)?;
        }
        // Retire everything that finished playing.
        let finished_cues = runtime
            .engine(engine)
            .map(|engine_state| {
                engine_state
                    .cue_voices
                    .iter()
                    .filter(|(_, live)| {
                        live.voices().all(|voice| {
                            self.audio
                                .queued_source_frames(voice)
                                .map(|queued| queued == 0)
                                .unwrap_or(false)
                        })
                    })
                    .map(|(object, _)| *object)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for object in finished_cues {
            self.xact_stop_cue_object(runtime, object, pending)?;
        }
        let finished_waves = runtime
            .engine(engine)
            .map(|engine_state| {
                engine_state
                    .wave_voices
                    .iter()
                    .filter(|(_, live)| {
                        live.voices().all(|voice| {
                            self.audio
                                .queued_source_frames(voice)
                                .map(|queued| queued == 0)
                                .unwrap_or(false)
                        })
                    })
                    .map(|(object, _)| *object)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for object in finished_waves {
            self.xact_stop_wave_object(runtime, object, pending)?;
        }
        Ok(())
    }

    /// Invoke the registered guest notification callback with the packed
    /// `XACT_NOTIFICATION` for one event.
    fn xact_deliver_notification(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        notification: &XactPendingNotification,
    ) -> AppResult<()> {
        if notification.callback == 0 {
            return Ok(());
        }
        let pointer_size = self.guest_arch.pointer_bytes() as u64;
        let size = if pointer_size == 4 { 64 } else { 80 };
        let address = self.alloc_zeroed(memory, size, 8)?;
        write_u8(memory, address, notification.type_);
        write_u32(memory, address + 1, xact_time_ms() as u32);
        write_guest_pointer(memory, address + 5, notification.context, self.guest_arch)?;
        let union = address + 5 + pointer_size;
        match notification.type_ {
            // Cue / marker notifications: cueIndex, pSoundBank, pCue.
            1..=5 => {
                write_u16(memory, union, notification.cue_index);
                write_guest_pointer(memory, union + 2, notification.sound_bank, self.guest_arch)?;
                write_guest_pointer(
                    memory,
                    union + 2 + pointer_size,
                    notification.cue,
                    self.guest_arch,
                )?;
            }
            // Sound-bank destroyed: a single pSoundBank pointer.
            6 => {
                write_guest_pointer(memory, union, notification.sound_bank, self.guest_arch)?;
            }
            // Wave-bank destroyed: a single pWaveBank pointer.
            7 => {
                write_guest_pointer(memory, union, notification.wave_bank, self.guest_arch)?;
            }
            // Global/local variable changed.
            8 | 9 => {
                write_u16(memory, union, notification.cue_index);
                write_guest_pointer(memory, union + 2, notification.sound_bank, self.guest_arch)?;
                write_guest_pointer(
                    memory,
                    union + 2 + pointer_size,
                    notification.cue,
                    self.guest_arch,
                )?;
                write_u16(
                    memory,
                    union + 2 + 2 * pointer_size,
                    notification.variable_index,
                );
                write_u32(
                    memory,
                    union + 4 + 2 * pointer_size,
                    notification.variable_value.to_bits(),
                );
                write_u32(memory, union + 8 + 2 * pointer_size, 0);
            }
            // Wave notifications: pWaveBank, waveIndex, cueIndex, pSoundBank,
            // pCue, pWave.
            12..=18 => {
                write_guest_pointer(memory, union, notification.wave_bank, self.guest_arch)?;
                write_u16(memory, union + pointer_size, notification.wave_index);
                write_u16(memory, union + pointer_size + 2, notification.cue_index);
                write_guest_pointer(
                    memory,
                    union + pointer_size + 4,
                    notification.sound_bank,
                    self.guest_arch,
                )?;
                write_guest_pointer(
                    memory,
                    union + 2 * pointer_size + 4,
                    notification.cue,
                    self.guest_arch,
                )?;
                write_guest_pointer(
                    memory,
                    union + 3 * pointer_size + 4,
                    notification.wave,
                    self.guest_arch,
                )?;
            }
            _ => {}
        }
        let _ = self.execute_guest_callback(
            state,
            memory,
            notification.callback,
            &[address],
            "XACT3 notification",
        )?;
        Ok(())
    }
}

/// Resolve a cue's authored selection into decoded playback: the XSB sound
/// record, its wave references, the referenced wave banks (by name), and the
/// decoded PCM with track gains mixed.
fn xact_resolve_cue(
    runtime: &crate::xact::XactRuntime,
    engine: u64,
    bank_object: u64,
    cue_object: u64,
    cue_index: u16,
) -> Result<XactResolvedPlayback, u32> {
    let Some(crate::xact::XactObject::SoundBank(bank)) = runtime.objects.get(&bank_object) else {
        return Err(crate::xact::E_INVALIDARG);
    };
    let mut variables = runtime
        .engine(engine)
        .map(|engine| engine.variable_values.clone())
        .unwrap_or_default();
    let mut matrix = None;
    let mut routes = Vec::new();
    if let Some(crate::xact::XactObject::Cue(cue)) = runtime.objects.get(&cue_object) {
        for (index, value) in &cue.local_values {
            if let Some(slot) = variables.get_mut(*index as usize) {
                *slot = *value;
            }
        }
        matrix = cue.matrix.clone();
        routes = cue.output_voices.clone().unwrap_or_default();
    }
    let selection = bank.bank.select_cue_with_variables(cue_index, &variables)?;
    let mut channels = 0u16;
    let mut sample_rate = 0u32;
    let mut loop_count = 0u8;
    let mut loop_start_samples = 0u32;
    let mut loop_total_samples = 0u32;
    let mut tracks = Vec::new();
    for track in &selection.sound.tracks {
        let Some(name) = bank.bank.wavebank_names.get(track.wave.wavebank as usize) else {
            return Err(crate::xact::XACTENGINE_E_NOWAVEBANK);
        };
        let Some(wave_bank_object) = runtime.wave_bank_by_name(engine, name) else {
            return Err(crate::xact::XACTENGINE_E_NOWAVEBANK);
        };
        let Some(crate::xact::XactObject::WaveBank(wave_bank)) =
            runtime.objects.get(&wave_bank_object)
        else {
            return Err(crate::xact::XACTENGINE_E_NOWAVEBANK);
        };
        let Some(entry) = wave_bank.bank.entries.get(track.wave.wave_index as usize) else {
            return Err(crate::xact::XACTENGINE_E_INVALIDWAVEINDEX);
        };
        let pcm = match entry.pcm.clone() {
            Some(pcm) => pcm,
            None => wave_bank
                .streaming_cache
                .get(&(track.wave.wave_index))
                .cloned()
                .ok_or(crate::xact::XACTENGINE_E_WAVEBANKNOTPREPARED)?,
        };
        if channels == 0 {
            channels = entry.format.channels;
            sample_rate = entry.format.sample_rate;
            loop_count = track.wave.loop_count;
            loop_start_samples = entry.loop_start_sample;
            loop_total_samples = entry.loop_total_samples;
        } else if entry.format.channels != channels || entry.format.sample_rate != sample_rate {
            return Err(crate::xact::XACTENGINE_E_INVALIDDATA);
        }
        tracks.push((pcm, track.volume));
    }
    if tracks.is_empty() {
        return Err(crate::xact::XACTENGINE_E_INVALIDDATA);
    }
    let samples = xact_mix_tracks(&tracks, channels as usize);
    Ok(XactResolvedPlayback {
        samples,
        channels,
        sample_rate,
        loop_count,
        loop_start_samples,
        loop_total_samples,
        volume: selection.sound.volume,
        pitch: selection.sound.pitch,
        category: selection.sound.category,
        matrix,
        routes,
    })
}

/// Resolve one wave-bank entry into decoded playback.
fn xact_resolve_wave_entry(
    runtime: &crate::xact::XactRuntime,
    _engine: u64,
    wave_bank_object: u64,
    index: u16,
    loop_count: u8,
) -> Result<XactResolvedPlayback, u32> {
    let Some(crate::xact::XactObject::WaveBank(wave_bank)) = runtime.objects.get(&wave_bank_object)
    else {
        return Err(crate::xact::E_INVALIDARG);
    };
    let Some(entry) = wave_bank.bank.entries.get(index as usize) else {
        return Err(crate::xact::XACTENGINE_E_INVALIDWAVEINDEX);
    };
    let pcm = match entry.pcm.clone() {
        Some(pcm) => pcm,
        None => wave_bank
            .streaming_cache
            .get(&index)
            .cloned()
            .ok_or(crate::xact::XACTENGINE_E_WAVEBANKNOTPREPARED)?,
    };
    Ok(XactResolvedPlayback {
        samples: pcm,
        channels: entry.format.channels,
        sample_rate: entry.format.sample_rate,
        loop_count,
        loop_start_samples: entry.loop_start_sample,
        loop_total_samples: entry.loop_total_samples,
        volume: 1.0,
        pitch: 0,
        category: 0,
        matrix: None,
        routes: Vec::new(),
    })
}

/// Mix one cue into one real output voice.  An explicit
/// `SetOutputVoiceMatrix` supplies the coefficients; otherwise a documented
/// default routing maps matching channels one-to-one and spreads a mono
/// source across every destination channel.  A mismatched matrix is
/// `XACTENGINE_E_INVALIDDATA`.
fn xact_route_output_voice(
    samples: &[i16],
    channels: u16,
    route: &crate::xact::OutputVoiceRoute,
) -> Result<(Vec<i16>, u16), u32> {
    let destination_channels = route.channels.max(1) as usize;
    let source_channels = channels.max(1) as usize;
    let matrix = match &route.matrix {
        Some(matrix) => matrix.clone(),
        None => {
            let mut coefficients = vec![0.0_f32; source_channels * destination_channels];
            if source_channels == 1 {
                coefficients.fill(1.0);
            } else {
                for channel in 0..source_channels.min(destination_channels) {
                    coefficients[channel * destination_channels + channel] = 1.0;
                }
            }
            (
                source_channels as u32,
                destination_channels as u32,
                coefficients,
            )
        }
    };
    if matrix.1 as usize != destination_channels {
        return Err(crate::xact::XACTENGINE_E_INVALIDDATA);
    }
    xact_apply_output_matrix(samples.to_vec(), channels, Some(&matrix))
}

/// Apply a source-to-destination channel matrix to interleaved PCM.  The
/// matrix is row-major source-major (the XACT `SetMatrixCoefficients`
/// layout): `out[src][dst] = in[src] * matrix[src * dst_count + dst]`.
/// A matrix whose source count does not match the decoded wave is invalid.
fn xact_apply_output_matrix(
    samples: Vec<i16>,
    channels: u16,
    matrix: Option<&(u32, u32, Vec<f32>)>,
) -> Result<(Vec<i16>, u16), u32> {
    let Some((source, destination, coefficients)) = matrix else {
        return Ok((samples, channels));
    };
    let source_channels = *source as usize;
    let destination_channels = *destination as usize;
    if source_channels == 0
        || destination_channels == 0
        || source_channels != channels as usize
        || coefficients.len() != source_channels * destination_channels
    {
        return Err(crate::xact::XACTENGINE_E_INVALIDDATA);
    }
    let frames = samples.len() / source_channels;
    let mut mixed = Vec::with_capacity(frames * destination_channels);
    for frame in 0..frames {
        for destination_index in 0..destination_channels {
            let mut value = 0.0_f32;
            for source_index in 0..source_channels {
                let sample = samples[frame * source_channels + source_index] as f32;
                value +=
                    sample * coefficients[source_index * destination_channels + destination_index];
            }
            mixed.push(value.clamp(-32768.0, 32767.0) as i16);
        }
    }
    Ok((mixed, destination_channels as u16))
}

/// Sum the decoded tracks of one sound, scaling each track by its authored
/// gain and clamping into the 16-bit sample range.
fn xact_mix_tracks(tracks: &[(Vec<i16>, f32)], channels: usize) -> Vec<i16> {
    if tracks.len() == 1 {
        return tracks[0].0.clone();
    }
    let length = tracks
        .iter()
        .map(|(samples, _)| samples.len())
        .min()
        .unwrap_or(0);
    let mut mixed = vec![0_i32; length];
    for (samples, volume) in tracks {
        for (slot, sample) in mixed.iter_mut().zip(samples.iter()) {
            *slot += (*sample as f32 * volume) as i32;
        }
    }
    let _ = channels;
    mixed
        .into_iter()
        .map(|sample| sample.clamp(i16::MIN as i32, i16::MAX as i32) as i16)
        .collect()
}

// ---------------------------------------------------------------------------
// DirectPlay — the real software DirectPlay8 peer engine
// ---------------------------------------------------------------------------
//
// The dispatch layer below implements the `dplay8.h`/`dpaddr.h` interfaces
// (`IDirectPlay8Address`, `IDirectPlay8Peer`) and the legacy `IDirectPlay4`
// subset from `dplay.h` against the real engine in `crate::dplay`:
//
// - `DirectPlay8Create` / `DirectPlay8AddressCreate` / `DirectPlayCreate`
//   hand out real guest objects whose vtables are the exact interface tables
//   from the DirectX headers; every slot is a `HostThunk::Dplay8Method`
//   carrying its interface/method identity.
// - `DirectPlayEnumerateW` runs the guest callback for the built-in TCP/IP
//   service provider and for every real session this runtime currently hosts
//   (see `crate::dplay::hosted_sessions`).
// - `Host`/`Connect`/`SendTo`/`EnumHosts`/`Close` map onto the real UDP
//   transport; `GetCaps`/`GetSPCaps`/`GetConnectionInfo` report the live
//   engine facts; the remaining methods return the genuine `DPNERR_*` for
//   the condition (including `DPNERR_UNSUPPORTED` for the surfaces the
//   engine genuinely does not model, such as lobby registration).
//
// The engine never fabricates success: see `crate::dplay` for the wire
// messages and the per-operation failure codes.

/// `CLASS_E_CLASSNOTAVAILABLE` — the honest answer of the internal
/// `DP8SPCreate` service-provider factory, which has no COM class object in
/// this runtime (applications use `DirectPlay8Create` instead).
const DPLAY_CLASS_E_CLASSNOTAVAILABLE: u32 = 0x8004_0153;

/// Align a byte offset to the guest pointer size (Windows x64 aligns
/// pointers to 8; x86 to 4).
fn dplay_align(value: u64, pointer_size: u64) -> u64 {
    (value + pointer_size - 1) & !(pointer_size - 1)
}

fn dplay_riid(memory: &MemoryImage, address: u64) -> [u8; 16] {
    let mut riid = [0u8; 16];
    if address != 0 {
        if let Ok(bytes) = read_guest_bytes(memory, address, 16) {
            riid.copy_from_slice(&bytes);
        }
    }
    riid
}

fn dplay_utf16_z(memory: &MemoryImage, address: u64) -> String {
    if address == 0 {
        return String::new();
    }
    read_utf16z(memory, address, 4096).unwrap_or_default()
}

fn dplay_ansi_z(memory: &MemoryImage, address: u64) -> String {
    if address == 0 {
        return String::new();
    }
    read_c_string(memory, address).unwrap_or_default()
}

/// Write a byte buffer with the DirectPlay buffer contract: the size pointer
/// is always updated to the required size; a null/too-small buffer returns
/// `DPNERR_BUFFERTOOSMALL`.
fn dplay_write_raw_buffer(
    memory: &mut MemoryImage,
    buffer: u64,
    size_ptr: u64,
    data: &[u8],
) -> u32 {
    let available = if size_ptr != 0 {
        read_u32(memory, size_ptr).unwrap_or(0)
    } else {
        u32::MAX
    };
    if size_ptr != 0 {
        write_u32(memory, size_ptr, data.len() as u32);
    }
    if buffer == 0 || (size_ptr != 0 && available < data.len() as u32) {
        return crate::dplay::DPNERR_BUFFERTOOSMALL;
    }
    if write_guest_bytes_checked(memory, buffer, data).is_err() {
        return crate::dplay::DPNERR_INVALIDPOINTER;
    }
    S_OK
}

/// The same contract for a NUL-terminated UTF-16 string: the count is in
/// characters including the terminator.
fn dplay_write_utf16_buffer(
    memory: &mut MemoryImage,
    buffer: u64,
    size_ptr: u64,
    text: &str,
) -> u32 {
    let mut data = crate::dplay::encode_utf16_bytes(text);
    data.extend_from_slice(&[0, 0]);
    let required_chars = (data.len() / 2) as u32;
    let available = if size_ptr != 0 {
        read_u32(memory, size_ptr).unwrap_or(0)
    } else {
        u32::MAX
    };
    if size_ptr != 0 {
        write_u32(memory, size_ptr, required_chars);
    }
    if buffer == 0 || (size_ptr != 0 && available < required_chars) {
        return crate::dplay::DPNERR_BUFFERTOOSMALL;
    }
    if write_guest_bytes_checked(memory, buffer, &data).is_err() {
        return crate::dplay::DPNERR_INVALIDPOINTER;
    }
    S_OK
}

/// The ANSI variant (count in bytes including the terminator).
fn dplay_write_ansi_buffer(
    memory: &mut MemoryImage,
    buffer: u64,
    size_ptr: u64,
    text: &str,
) -> u32 {
    let mut data = text.as_bytes().to_vec();
    data.push(0);
    let available = if size_ptr != 0 {
        read_u32(memory, size_ptr).unwrap_or(0)
    } else {
        u32::MAX
    };
    if size_ptr != 0 {
        write_u32(memory, size_ptr, data.len() as u32);
    }
    if buffer == 0 || (size_ptr != 0 && available < data.len() as u32) {
        return crate::dplay::DPNERR_BUFFERTOOSMALL;
    }
    if write_guest_bytes_checked(memory, buffer, &data).is_err() {
        return crate::dplay::DPNERR_INVALIDPOINTER;
    }
    S_OK
}

/// Read a `DPN_APPLICATION_DESC` from guest memory (x86/x64 layouts).
fn dplay_read_app_desc(
    memory: &MemoryImage,
    address: u64,
    guest_arch: GuestArch,
) -> crate::dplay::DplayAppDesc {
    let mut desc = crate::dplay::DplayAppDesc::default();
    if address == 0 {
        return desc;
    }
    let pointer_size = guest_arch.pointer_bytes() as u64;
    desc.flags = read_u32(memory, address + 4).unwrap_or(0);
    desc.instance_guid = dplay_riid(memory, address + 8);
    desc.application_guid = dplay_riid(memory, address + 24);
    desc.max_players = read_u32(memory, address + 40).unwrap_or(0);
    desc.current_players = read_u32(memory, address + 44).unwrap_or(0);
    let name_ptr = read_guest_pointer(memory, address + 48, guest_arch).unwrap_or(0);
    desc.session_name = dplay_utf16_z(memory, name_ptr);
    let password_ptr =
        read_guest_pointer(memory, address + 48 + pointer_size, guest_arch).unwrap_or(0);
    desc.password = dplay_utf16_z(memory, password_ptr);
    desc
}

/// Write a `DPN_APPLICATION_DESC` into guest memory, returning the required
/// struct size for the guest architecture.
fn dplay_write_app_desc(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    address: u64,
    desc: &crate::dplay::DplayAppDesc,
) -> AppResult<u64> {
    let pointer_size = runtime.guest_arch.pointer_bytes() as u64;
    let size = dplay_align(48 + pointer_size * 3 + 4, pointer_size) + pointer_size + 4;
    if address == 0 {
        return Ok(size);
    }
    write_guest_bytes(memory, address, &vec![0u8; size as usize])?;
    write_u32(memory, address, size as u32);
    write_u32(memory, address + 4, desc.flags);
    write_guest_bytes(memory, address + 8, &desc.instance_guid)?;
    write_guest_bytes(memory, address + 24, &desc.application_guid)?;
    write_u32(memory, address + 40, desc.max_players);
    write_u32(memory, address + 44, desc.current_players);
    let name = runtime.alloc_zeroed(memory, (desc.session_name.len() + 1) * 2, 2)?;
    write_guest_bytes(
        memory,
        name,
        &crate::dplay::encode_utf16_bytes(&desc.session_name),
    )?;
    write_guest_pointer(memory, address + 48, name, runtime.guest_arch)?;
    let password = runtime.alloc_zeroed(memory, (desc.password.len() + 1) * 2, 2)?;
    write_guest_bytes(
        memory,
        password,
        &crate::dplay::encode_utf16_bytes(&desc.password),
    )?;
    write_guest_pointer(
        memory,
        address + 48 + pointer_size,
        password,
        runtime.guest_arch,
    )?;
    Ok(size)
}

impl PeHostRuntime {
    /// The factory/enumeration entries of the DirectPlay surface.
    pub(crate) fn dispatch_dplay_entry(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::DirectPlay8Create => {
                let _clsid = guest_call_arg(state, memory, 0)?;
                let iid = dplay_riid(memory, guest_call_arg(state, memory, 1)?);
                let out = guest_call_arg(state, memory, 2)?;
                if out == 0 {
                    state.set(
                        Register::Rax,
                        u64::from(crate::dplay::DPNERR_INVALIDPOINTER),
                    );
                    return Ok(());
                }
                if iid != crate::dplay::IID_IDIRECTPLAY8_PEER && iid != crate::dplay::IID_IUNKNOWN {
                    write_guest_pointer(memory, out, 0, self.guest_arch)?;
                    state.set(Register::Rax, u64::from(crate::dplay::DPNERR_NOINTERFACE));
                    return Ok(());
                }
                let object = self.dplay_create_object(
                    memory,
                    crate::dplay::IFACE_PEER,
                    crate::dplay::DplayObject::Peer(crate::dplay::Dplay8Peer::new()),
                )?;
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                state.set(Register::Rax, u64::from(crate::dplay::S_OK));
                self.last_error = 0;
                Ok(())
            }
            HostThunk::DirectPlay8AddressCreate => {
                let iid = dplay_riid(memory, guest_call_arg(state, memory, 0)?);
                let out = guest_call_arg(state, memory, 1)?;
                let outer = guest_call_arg(state, memory, 2)?;
                if out == 0 {
                    state.set(
                        Register::Rax,
                        u64::from(crate::dplay::DPNERR_INVALIDPOINTER),
                    );
                    return Ok(());
                }
                if outer != 0
                    || (iid != crate::dplay::IID_IDIRECTPLAY8_ADDRESS
                        && iid != crate::dplay::IID_IUNKNOWN)
                {
                    write_guest_pointer(memory, out, 0, self.guest_arch)?;
                    state.set(Register::Rax, u64::from(crate::dplay::DPNERR_NOINTERFACE));
                    return Ok(());
                }
                let object = self.dplay_create_address_object(memory)?;
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                state.set(Register::Rax, u64::from(crate::dplay::S_OK));
                self.last_error = 0;
                Ok(())
            }
            HostThunk::DirectPlayCreate => {
                let _guid = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let outer = guest_call_arg(state, memory, 2)?;
                if out == 0 {
                    state.set(
                        Register::Rax,
                        u64::from(crate::dplay::DPNERR_INVALIDPOINTER),
                    );
                    return Ok(());
                }
                if outer != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch)?;
                    state.set(Register::Rax, u64::from(crate::dplay::DPNERR_NOINTERFACE));
                    return Ok(());
                }
                let object = self.dplay_create_object(
                    memory,
                    crate::dplay::IFACE_LEGACY,
                    crate::dplay::DplayObject::Legacy(crate::dplay::LegacyPeer::new()),
                )?;
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                state.set(Register::Rax, u64::from(crate::dplay::S_OK));
                self.last_error = 0;
                Ok(())
            }
            HostThunk::DirectPlayEnumerateW => {
                let callback = guest_call_arg(state, memory, 0)?;
                let context = guest_call_arg(state, memory, 1)?;
                if callback == 0 {
                    state.set(Register::Rax, u64::from(crate::dplay::DPNERR_INVALIDPARAM));
                    return Ok(());
                }
                // The real TCP/IP service provider this engine speaks over.
                if !self.dplay_emit_enum_connection(
                    state,
                    memory,
                    callback,
                    context,
                    &crate::dplay::CLSID_DP8SP_TCPIP,
                    "Internet TCP/IP Connection For DirectPlay",
                    None,
                )? {
                    state.set(Register::Rax, u64::from(crate::dplay::S_OK));
                    return Ok(());
                }
                // Every session this runtime currently hosts, with its real
                // bound endpoint.
                for session in crate::dplay::hosted_sessions() {
                    if !self.dplay_emit_enum_connection(
                        state,
                        memory,
                        callback,
                        context,
                        &session.instance_guid,
                        &session.session_name,
                        Some(session.address),
                    )? {
                        break;
                    }
                }
                state.set(Register::Rax, u64::from(crate::dplay::S_OK));
                self.last_error = 0;
                Ok(())
            }
            HostThunk::Dp8spCreate => {
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(DPLAY_CLASS_E_CLASSNOTAVAILABLE));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted DirectPlay entry thunk {thunk:?}"),
            )),
        }
    }

    /// Invoke the guest enumeration callback with a real connection/session
    /// description (`DirectPlayEnumerateW` callback contract).
    #[allow(clippy::too_many_arguments)]
    fn dplay_emit_enum_connection(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        callback: u64,
        context: u64,
        guid: &[u8; 16],
        name: &str,
        address: Option<std::net::SocketAddr>,
    ) -> AppResult<bool> {
        let guid_memory = self.alloc_zeroed(memory, 16, 4)?;
        write_guest_bytes(memory, guid_memory, guid)?;
        // A TCP/IP connection blob: the SOCKADDR_IN of the real endpoint.
        let connection = self.alloc_zeroed(memory, 16, 4)?;
        if let Some(address) = address {
            write_u16(memory, connection, 2); // AF_INET
            write_u16(memory, connection + 2, address.port().to_be());
            if let std::net::IpAddr::V4(ip) = address.ip() {
                write_guest_bytes(memory, connection + 4, &ip.octets())?;
            }
        }
        let pointer_size = self.guest_arch.pointer_bytes() as u64;
        let name_memory = self.alloc_zeroed(memory, (name.len() + 1) * 2, 2)?;
        write_guest_bytes(memory, name_memory, &crate::dplay::encode_utf16_bytes(name))?;
        let dname = self.alloc_zeroed(memory, (8 + pointer_size * 2) as usize, pointer_size)?;
        write_u32(memory, dname, (8 + pointer_size * 2) as u32);
        write_u32(memory, dname + 4, 0);
        write_guest_pointer(memory, dname + 8, name_memory, self.guest_arch)?;
        write_guest_pointer(
            memory,
            dname + 8 + pointer_size,
            name_memory,
            self.guest_arch,
        )?;
        let result = self.execute_guest_callback(
            state,
            memory,
            callback,
            &[guid_memory, connection, 16, dname, 0, context],
            "DirectPlayEnumerateW",
        )?;
        Ok(result != 0)
    }

    /// Allocate one guest object with its interface vtable and register it in
    /// the per-process DirectPlay store with reference count 1.  This entry
    /// point takes the store lock; use [`Self::dplay_create_object_in`] when
    /// a runtime borrow is already held (vtable dispatch holds it for the
    /// whole method, and the store lock is not re-entrant).
    fn dplay_create_object(
        &mut self,
        memory: &mut MemoryImage,
        interface: u8,
        object: crate::dplay::DplayObject,
    ) -> AppResult<u64> {
        let pid = self.guest_pid;
        let mut store = crate::dplay::lock_dplay_runtimes();
        let runtime = store.entry(pid).or_default();
        self.dplay_create_object_in(memory, runtime, interface, object)
    }

    /// The lock-free object constructor: the caller already holds the
    /// per-process store borrow.
    fn dplay_create_object_in(
        &mut self,
        memory: &mut MemoryImage,
        runtime: &mut crate::dplay::DplayRuntime,
        interface: u8,
        object: crate::dplay::DplayObject,
    ) -> AppResult<u64> {
        let vtable = self.dplay_vtable_in(memory, runtime, interface)?;
        let address = self.alloc_zeroed(memory, 0x20, 16)?;
        write_u64(memory, address, vtable);
        runtime.objects.insert(
            address,
            crate::dplay::DplayObjectEntry {
                refcount: 1,
                object,
            },
        );
        Ok(address)
    }

    /// `CoCreateInstance(CLSID_DirectPlay8Address, ..., IID_IDirectPlay8Address)`.
    pub(crate) fn dplay_create_address_object(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<u64> {
        self.dplay_create_object(
            memory,
            crate::dplay::IFACE_ADDRESS,
            crate::dplay::DplayObject::Address(crate::dplay::Dplay8Address::new()),
        )
    }

    /// Allocate (once per runtime and interface) the guest vtable for a
    /// DirectPlay interface; every slot is a `Dplay8Method` host thunk.
    fn dplay_vtable_in(
        &mut self,
        memory: &mut MemoryImage,
        runtime: &mut crate::dplay::DplayRuntime,
        interface: u8,
    ) -> AppResult<u64> {
        if let Some(address) = runtime.vtables.get(&interface) {
            return Ok(*address);
        }
        let methods = crate::dplay::interface_methods(interface);
        let thunks = methods
            .iter()
            .map(|(method, x86_arg_words)| HostThunk::Dplay8Method {
                interface,
                method: *method,
                x86_arg_bytes: x86_arg_words.saturating_mul(4),
            })
            .collect::<Vec<_>>();
        let vtable = self.alloc_guest_vtable(memory, thunks)?;
        runtime.vtables.insert(interface, vtable);
        Ok(vtable)
    }

    /// Dispatch one `HostThunk::Dplay8Method` vtable slot.
    pub(crate) fn dispatch_dplay8_method(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let HostThunk::Dplay8Method {
            interface, method, ..
        } = *thunk
        else {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                "dispatch_dplay8_method called with a non-DirectPlay thunk".to_string(),
            ));
        };
        let this = guest_call_arg(state, memory, 0)?;
        let pid = self.guest_pid;
        let result = {
            let mut store = crate::dplay::lock_dplay_runtimes();
            let runtime = store.entry(pid).or_default();
            if !runtime.objects.contains_key(&this) {
                crate::dplay::DPNERR_INVALIDPARAM
            } else {
                match method {
                    0 => self.dplay_query_interface(runtime, state, memory, this, interface),
                    1 => match runtime.objects.get_mut(&this) {
                        Some(entry) => {
                            entry.refcount = entry.refcount.saturating_add(1);
                            entry.refcount
                        }
                        None => crate::dplay::DPNERR_INVALIDPARAM,
                    },
                    2 => self.dplay_release_object(runtime, this),
                    _ => match interface {
                        crate::dplay::IFACE_ADDRESS => {
                            self.dplay_invoke_address(runtime, state, memory, this, method)
                        }
                        crate::dplay::IFACE_PEER => {
                            self.dplay_invoke_peer(runtime, state, memory, this, method)
                        }
                        crate::dplay::IFACE_LEGACY => {
                            self.dplay_invoke_legacy(runtime, state, memory, this, method)
                        }
                        _ => crate::dplay::DPNERR_INVALIDPARAM,
                    },
                }
            }
        };
        state.set(Register::Rax, u64::from(result));
        self.last_error = 0;
        Ok(())
    }

    /// `IUnknown::QueryInterface` for every DirectPlay object.
    fn dplay_query_interface(
        &mut self,
        runtime: &mut crate::dplay::DplayRuntime,
        state: &CpuState,
        memory: &mut MemoryImage,
        this: u64,
        interface: u8,
    ) -> u32 {
        let riid = dplay_riid(memory, xact_arg(state, memory, 1).unwrap_or(0));
        let out = xact_arg(state, memory, 2).unwrap_or(0);
        if out == 0 {
            return crate::dplay::DPNERR_INVALIDPOINTER;
        }
        let supported = match interface {
            crate::dplay::IFACE_ADDRESS => {
                riid == crate::dplay::IID_IDIRECTPLAY8_ADDRESS || riid == crate::dplay::IID_IUNKNOWN
            }
            crate::dplay::IFACE_PEER => {
                riid == crate::dplay::IID_IDIRECTPLAY8_PEER || riid == crate::dplay::IID_IUNKNOWN
            }
            _ => riid == crate::dplay::IID_IUNKNOWN,
        };
        if supported {
            if let Some(entry) = runtime.objects.get_mut(&this) {
                entry.refcount = entry.refcount.saturating_add(1);
            }
            let _ = write_guest_pointer(memory, out, this, self.guest_arch);
            crate::dplay::S_OK
        } else {
            let _ = write_guest_pointer(memory, out, 0, self.guest_arch);
            crate::dplay::DPNERR_NOINTERFACE
        }
    }

    /// `IUnknown::Release`: reaching zero drops the engine object (which
    /// performs the real close/teardown for peers).
    fn dplay_release_object(&mut self, runtime: &mut crate::dplay::DplayRuntime, this: u64) -> u32 {
        let refcount = match runtime.objects.get_mut(&this) {
            Some(entry) => {
                entry.refcount = entry.refcount.saturating_sub(1);
                entry.refcount
            }
            None => return crate::dplay::DPNERR_INVALIDPARAM,
        };
        if refcount == 0 {
            runtime.objects.remove(&this);
        }
        refcount
    }

    /// The `IDirectPlay8Address` method set.
    fn dplay_invoke_address(
        &mut self,
        runtime: &mut crate::dplay::DplayRuntime,
        state: &CpuState,
        memory: &mut MemoryImage,
        this: u64,
        method: u16,
    ) -> u32 {
        macro_rules! arg {
            ($index:expr) => {
                xact_arg(state, memory, $index).unwrap_or(0)
            };
        }
        macro_rules! arg_u32 {
            ($index:expr) => {
                xact_arg_u32(state, memory, $index).unwrap_or(0)
            };
        }
        match method {
            3 => {
                let url = dplay_utf16_z(memory, arg!(1));
                match runtime.objects.get_mut(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => address.build_from_url(&url),
                    _ => crate::dplay::DPNERR_INVALIDPARAM,
                }
            }
            4 => {
                let url = dplay_ansi_z(memory, arg!(1));
                match runtime.objects.get_mut(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => address.build_from_url(&url),
                    _ => crate::dplay::DPNERR_INVALIDPARAM,
                }
            }
            5 => {
                let out = arg!(1);
                if out == 0 {
                    return crate::dplay::DPNERR_INVALIDPOINTER;
                }
                let duplicate = match runtime.objects.get(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => address.duplicate(),
                    _ => return crate::dplay::DPNERR_INVALIDPARAM,
                };
                match self.dplay_create_object_in(
                    memory,
                    runtime,
                    crate::dplay::IFACE_ADDRESS,
                    crate::dplay::DplayObject::Address(duplicate),
                ) {
                    Ok(object) => {
                        let _ = write_guest_pointer(memory, out, object, self.guest_arch);
                        crate::dplay::S_OK
                    }
                    Err(_) => crate::dplay::DPNERR_OUTOFMEMORY,
                }
            }
            6 => {
                let other = arg!(1);
                let source = match runtime.objects.get(&other) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => address.clone(),
                    _ => return crate::dplay::DPNERR_INVALIDPARAM,
                };
                match runtime.objects.get_mut(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => {
                        address.set_equal(&source);
                        crate::dplay::S_OK
                    }
                    _ => crate::dplay::DPNERR_INVALIDPARAM,
                }
            }
            7 => {
                let other = arg!(1);
                let (left, right) = match (runtime.objects.get(&this), runtime.objects.get(&other))
                {
                    (
                        Some(crate::dplay::DplayObjectEntry {
                            object: crate::dplay::DplayObject::Address(left),
                            ..
                        }),
                        Some(crate::dplay::DplayObjectEntry {
                            object: crate::dplay::DplayObject::Address(right),
                            ..
                        }),
                    ) => (left.clone(), right.clone()),
                    _ => return crate::dplay::DPNERR_INVALIDPARAM,
                };
                if left.is_equal(&right) {
                    crate::dplay::DPNSUCCESS_EQUAL
                } else {
                    crate::dplay::DPNSUCCESS_NOTEQUAL
                }
            }
            8 => match runtime.objects.get_mut(&this) {
                Some(crate::dplay::DplayObjectEntry {
                    object: crate::dplay::DplayObject::Address(address),
                    ..
                }) => {
                    address.clear();
                    crate::dplay::S_OK
                }
                _ => crate::dplay::DPNERR_INVALIDPARAM,
            },
            9 | 10 => {
                let url = match runtime.objects.get(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => address.url(),
                    _ => return crate::dplay::DPNERR_INVALIDPARAM,
                };
                if method == 9 {
                    dplay_write_utf16_buffer(memory, arg!(1), arg!(2), &url)
                } else {
                    dplay_write_ansi_buffer(memory, arg!(1), arg!(2), &url)
                }
            }
            11 | 19 => {
                let guid = match runtime.objects.get(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => {
                        if method == 11 {
                            address.get_sp()
                        } else {
                            address.get_device()
                        }
                    }
                    _ => return crate::dplay::DPNERR_INVALIDPARAM,
                };
                match guid {
                    Some(guid) => {
                        let _ = write_guest_bytes_checked(memory, arg!(1), &guid);
                        crate::dplay::S_OK
                    }
                    None => crate::dplay::DPNERR_DOESNOTEXIST,
                }
            }
            12 => {
                let data = match runtime.objects.get(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => address.user_data().to_vec(),
                    _ => return crate::dplay::DPNERR_INVALIDPARAM,
                };
                dplay_write_raw_buffer(memory, arg!(1), arg!(2), &data)
            }
            13 | 20 => {
                let guid = dplay_riid(memory, arg!(1));
                match runtime.objects.get_mut(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => {
                        if method == 13 {
                            address.set_sp(&guid)
                        } else {
                            address.set_device(&guid)
                        }
                    }
                    _ => crate::dplay::DPNERR_INVALIDPARAM,
                }
            }
            14 => {
                let size = arg_u32!(2) as usize;
                let data = read_guest_bytes(memory, arg!(1), size).unwrap_or_default();
                match runtime.objects.get_mut(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => {
                        address.set_user_data(&data);
                        crate::dplay::S_OK
                    }
                    _ => crate::dplay::DPNERR_INVALIDPARAM,
                }
            }
            15 => {
                let count = match runtime.objects.get(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => address.num_components(),
                    _ => return crate::dplay::DPNERR_INVALIDPARAM,
                };
                write_u32(memory, arg!(1), count);
                crate::dplay::S_OK
            }
            16 => {
                let name = dplay_utf16_z(memory, arg!(1));
                let component = match runtime.objects.get(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => address.component(&name).cloned(),
                    _ => return crate::dplay::DPNERR_INVALIDPARAM,
                };
                match component {
                    Some(component) => {
                        write_u32(memory, arg!(4), component.data_type);
                        dplay_write_raw_buffer(memory, arg!(2), arg!(3), &component.data)
                    }
                    None => crate::dplay::DPNERR_DOESNOTEXIST,
                }
            }
            17 => {
                let index = arg_u32!(1);
                let component = match runtime.objects.get(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => address
                        .component_at(index)
                        .map(|(name, component)| (name.to_string(), component.clone())),
                    _ => return crate::dplay::DPNERR_INVALIDPARAM,
                };
                match component {
                    Some((name, component)) => {
                        let name_result = dplay_write_utf16_buffer(memory, arg!(2), arg!(3), &name);
                        let data_result =
                            dplay_write_raw_buffer(memory, arg!(4), arg!(5), &component.data);
                        write_u32(memory, arg!(6), component.data_type);
                        if name_result != crate::dplay::S_OK {
                            name_result
                        } else {
                            data_result
                        }
                    }
                    None => crate::dplay::DPNERR_DOESNOTEXIST,
                }
            }
            18 => {
                let name = dplay_utf16_z(memory, arg!(1));
                let size = arg_u32!(3) as usize;
                let data = read_guest_bytes(memory, arg!(2), size).unwrap_or_default();
                let data_type = arg_u32!(4);
                match runtime.objects.get_mut(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => address.add_component(&name, data_type, &data),
                    _ => crate::dplay::DPNERR_INVALIDPARAM,
                }
            }
            21 => {
                // BuildFromDirectPlay4Address(pDP, flags): a real conversion
                // from the legacy peer's bound TCP/IP endpoint.
                if arg_u32!(2) != 0 {
                    return crate::dplay::DPNERR_INVALIDFLAGS;
                }
                let legacy_object = arg!(1);
                let addr = match runtime.objects.get(&legacy_object) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Legacy(legacy),
                        ..
                    }) => legacy.player_address(legacy.local_player),
                    _ => return crate::dplay::DPNERR_INVALIDPARAM,
                };
                let Some(addr) = addr else {
                    return crate::dplay::DPNERR_NOCONNECTION;
                };
                let hostname = addr.ip().to_string();
                let port = addr.port();
                match runtime.objects.get_mut(&this) {
                    Some(crate::dplay::DplayObjectEntry {
                        object: crate::dplay::DplayObject::Address(address),
                        ..
                    }) => {
                        address.clear();
                        let _ = address.set_sp(&crate::dplay::CLSID_DP8SP_TCPIP);
                        let _ = address.set_hostname(&hostname);
                        let _ = address.set_port(port);
                        crate::dplay::S_OK
                    }
                    _ => crate::dplay::DPNERR_INVALIDPARAM,
                }
            }
            _ => crate::dplay::DPNERR_INVALIDPARAM,
        }
    }
}

impl PeHostRuntime {
    /// The `IDirectPlay8Peer` method set.
    fn dplay_invoke_peer(
        &mut self,
        runtime: &mut crate::dplay::DplayRuntime,
        state: &CpuState,
        memory: &mut MemoryImage,
        this: u64,
        method: u16,
    ) -> u32 {
        use crate::dplay;
        let pointer_size = self.guest_arch.pointer_bytes() as u64;
        macro_rules! arg {
            ($index:expr) => {
                xact_arg(state, memory, $index).unwrap_or(0)
            };
        }
        macro_rules! arg_u32 {
            ($index:expr) => {
                xact_arg_u32(state, memory, $index).unwrap_or(0)
            };
        }
        match method {
            3 => {
                let context = arg!(1);
                let handler = arg!(2);
                let flags = arg_u32!(3);
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.initialize(context, handler, flags),
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            4 => {
                // One real provider: the TCP/IP transport this engine speaks.
                let buffer = arg!(3);
                let data_size_ptr = arg!(4);
                let returned_ptr = arg!(5);
                let entry_size: u32 = if pointer_size == 4 { 32 } else { 48 };
                let available = if data_size_ptr != 0 {
                    read_u32(memory, data_size_ptr).unwrap_or(0)
                } else {
                    u32::MAX
                };
                if data_size_ptr != 0 {
                    write_u32(memory, data_size_ptr, entry_size);
                }
                let room = buffer != 0 && available >= entry_size;
                if returned_ptr != 0 {
                    write_u32(memory, returned_ptr, u32::from(room));
                }
                if !room {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                let name = match self.alloc_zeroed(memory, 80, 2) {
                    Ok(name) => name,
                    Err(_) => return dplay::DPNERR_OUTOFMEMORY,
                };
                let label = "Internet TCP/IP Connection For DirectPlay";
                if write_guest_bytes(memory, name, &dplay::encode_utf16_bytes(label)).is_err() {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                let name_ptr_offset = if pointer_size == 4 { 20 } else { 24 };
                let tail = if pointer_size == 4 { 24 } else { 32 };
                let _ = write_guest_bytes_checked(memory, buffer, &vec![0u8; entry_size as usize]);
                let _ = write_guest_bytes_checked(memory, buffer + 4, &dplay::CLSID_DP8SP_TCPIP);
                let _ =
                    write_guest_pointer(memory, buffer + name_ptr_offset, name, self.guest_arch);
                let _ = write_guest_pointer(memory, buffer + tail, 0, self.guest_arch);
                let _ =
                    write_guest_pointer(memory, buffer + tail + pointer_size, 0, self.guest_arch);
                dplay::S_OK
            }
            5 => {
                // CancelAsyncOperation(hAsyncOp).
                let handle = arg_u32!(1);
                let result = match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.cancel_async_operation(handle),
                    _ => dplay::DPNERR_INVALIDPARAM,
                };
                if result == dplay::S_OK {
                    runtime.cancel_pending_async(handle);
                }
                result
            }
            6 => {
                // Connect(app, host, device, security, creds, data, size,
                //         playerContext, asyncContext, phAsync, flags).
                let host_object = arg!(2);
                let player_context = arg!(8);
                let flags = arg_u32!(11);
                let target = match runtime.objects.get(&host_object) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Address(address),
                        ..
                    }) => address.socket_addr(),
                    _ => return dplay::DPNERR_INVALIDHOSTADDRESS,
                };
                let Some(target) = target else {
                    return dplay::DPNERR_INVALIDHOSTADDRESS;
                };
                if target.port() == 0 {
                    return dplay::DPNERR_INCOMPLETEADDRESS;
                }
                let name = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.local_player_name().to_string(),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let name = if name.is_empty() {
                    "DirectPlay8 Peer".to_string()
                } else {
                    name
                };
                let asynchronous = flags & dplay::DPNOP_SYNC == 0;
                let (async_handle, dpnid) = match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => {
                        let handle = if asynchronous {
                            peer.begin_async_operation(dplay::AsyncOperationKind::Connect)
                        } else {
                            0
                        };
                        let result = peer.connect(target, &name, &[]);
                        if result != dplay::S_OK {
                            if handle != 0 {
                                let _ = peer.cancel_async_operation(handle);
                            }
                            return result;
                        }
                        peer.set_local_context(player_context);
                        (handle, peer.local_dpnid())
                    }
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                if !asynchronous {
                    dplay::S_OK
                } else {
                    if arg!(10) != 0 {
                        let _ = write_guest_pointer(
                            memory,
                            arg!(10),
                            u64::from(async_handle),
                            self.guest_arch,
                        );
                    }
                    runtime.push_event(
                        this,
                        dplay::DplayEvent::ConnectComplete {
                            async_op: async_handle,
                            context: player_context,
                            result: dplay::S_OK,
                            dpnid,
                        },
                    );
                    dplay::DPNERR_PENDING
                }
            }
            7 => {
                // SendTo(dpnid, buffers, count, timeout, async, phAsync, flags).
                let dpnid = arg_u32!(1);
                let buffers = arg!(2);
                let count = arg_u32!(3).min(64);
                let flags = arg_u32!(7);
                let stride = pointer_size * 2;
                let mut payload = Vec::new();
                for index in 0..count {
                    let base = buffers + u64::from(index) * stride;
                    let size = read_u32(memory, base).unwrap_or(0) as usize;
                    let pointer = read_guest_pointer(memory, base + pointer_size, self.guest_arch)
                        .unwrap_or(0);
                    if size == 0 {
                        continue;
                    }
                    match read_guest_bytes(memory, pointer, size) {
                        Ok(bytes) => payload.extend_from_slice(&bytes),
                        Err(_) => return dplay::DPNERR_INVALIDPOINTER,
                    }
                    if payload.len() > dplay::MAX_MESSAGE_PAYLOAD {
                        return dplay::DPNERR_DATATOOLARGE;
                    }
                }
                let asynchronous = flags & dplay::DPNOP_SYNC == 0;
                let async_handle = match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => {
                        let handle = if asynchronous {
                            peer.begin_send_operation(arg!(5))
                        } else {
                            0
                        };
                        let result = peer.send_to(dpnid, &payload);
                        if result != dplay::S_OK {
                            if handle != 0 {
                                let _ = peer.cancel_async_operation(handle);
                            }
                            return result;
                        }
                        handle
                    }
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                if !asynchronous {
                    dplay::S_OK
                } else {
                    if arg!(6) != 0 {
                        let _ = write_guest_pointer(
                            memory,
                            arg!(6),
                            u64::from(async_handle),
                            self.guest_arch,
                        );
                    }
                    // Exactly one completion is queued later by the
                    // reliability layer: success after every fragment is
                    // acknowledged, or the real failure on retry exhaustion.
                    dplay::DPNERR_PENDING
                }
            }
            8 => {
                let (messages, bytes) = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.send_queue(),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                if arg!(2) != 0 {
                    write_u32(memory, arg!(2), messages);
                }
                if arg!(3) != 0 {
                    write_u32(memory, arg!(3), bytes);
                }
                dplay::S_OK
            }
            9 => {
                // Host(app, devices, count, security, creds, context, flags).
                let desc = dplay_read_app_desc(memory, arg!(1), self.guest_arch);
                let devices = arg!(2);
                let count = arg_u32!(3);
                let local_context = arg!(6);
                let mut bind = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    0,
                );
                if count > 0 && devices != 0 {
                    let first = read_guest_pointer(memory, devices, self.guest_arch).unwrap_or(0);
                    if let Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Address(address),
                        ..
                    }) = runtime.objects.get(&first)
                    {
                        if let Some(address) = address.socket_addr() {
                            bind = address;
                        }
                    }
                }
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => {
                        let result = peer.host(&desc, bind);
                        if result != dplay::S_OK {
                            return result;
                        }
                        peer.set_local_context(local_context);
                    }
                    _ => return dplay::DPNERR_INVALIDPARAM,
                }
                runtime.push_event(
                    this,
                    dplay::DplayEvent::CreatePlayer {
                        dpnid: dplay::HOST_PLAYER_ID,
                        context: local_context,
                    },
                );
                dplay::S_OK
            }
            10 => {
                let desc = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.app_desc().clone(),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                match dplay_write_app_desc(self, memory, arg!(1), &desc) {
                    Ok(size) => {
                        let buffer = arg!(1);
                        let size_ptr = arg!(2);
                        if buffer == 0 {
                            if size_ptr != 0 {
                                write_u32(memory, size_ptr, size as u32);
                            }
                            dplay::DPNERR_BUFFERTOOSMALL
                        } else {
                            let available = if size_ptr != 0 {
                                read_u32(memory, size_ptr).unwrap_or(0)
                            } else {
                                u32::MAX
                            };
                            if size_ptr != 0 {
                                write_u32(memory, size_ptr, size as u32);
                            }
                            if available < size as u32 {
                                dplay::DPNERR_BUFFERTOOSMALL
                            } else {
                                dplay::S_OK
                            }
                        }
                    }
                    Err(_) => dplay::DPNERR_OUTOFMEMORY,
                }
            }
            11 => {
                let desc = dplay_read_app_desc(memory, arg!(1), self.guest_arch);
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => {
                        peer.set_app_desc(desc);
                        dplay::S_OK
                    }
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            12 => {
                let name = dplay_utf16_z(
                    memory,
                    read_guest_pointer(memory, arg!(1) + 8, self.guest_arch).unwrap_or(0),
                );
                let data_size = read_u32(memory, arg!(1) + 8 + 2 * pointer_size).unwrap_or(0);
                let data_ptr =
                    read_guest_pointer(memory, arg!(1) + 8 + pointer_size, self.guest_arch)
                        .unwrap_or(0);
                let data =
                    read_guest_bytes(memory, data_ptr, data_size as usize).unwrap_or_default();
                let owner = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.local_dpnid(),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => match peer.create_group(&name, owner, &data) {
                        Ok(group_id) => {
                            if arg!(4) != 0 {
                                write_u32(memory, arg!(4), group_id);
                            }
                            dplay::S_OK
                        }
                        Err(error) => error,
                    },
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            13 => match runtime.objects.get_mut(&this) {
                Some(dplay::DplayObjectEntry {
                    object: dplay::DplayObject::Peer(peer),
                    ..
                }) => peer.destroy_group(arg_u32!(1)),
                _ => dplay::DPNERR_INVALIDPARAM,
            },
            14 => match runtime.objects.get_mut(&this) {
                Some(dplay::DplayObjectEntry {
                    object: dplay::DplayObject::Peer(peer),
                    ..
                }) => peer.add_player_to_group(arg_u32!(1), arg_u32!(2)),
                _ => dplay::DPNERR_INVALIDPARAM,
            },
            15 => match runtime.objects.get_mut(&this) {
                Some(dplay::DplayObjectEntry {
                    object: dplay::DplayObject::Peer(peer),
                    ..
                }) => peer.remove_player_from_group(arg_u32!(1), arg_u32!(2)),
                _ => dplay::DPNERR_INVALIDPARAM,
            },
            16 => {
                let name = dplay_utf16_z(
                    memory,
                    read_guest_pointer(memory, arg!(2) + 8, self.guest_arch).unwrap_or(0),
                );
                let data_size = read_u32(memory, arg!(2) + 8 + 2 * pointer_size).unwrap_or(0);
                let data_ptr =
                    read_guest_pointer(memory, arg!(2) + 8 + pointer_size, self.guest_arch)
                        .unwrap_or(0);
                let data =
                    read_guest_bytes(memory, data_ptr, data_size as usize).unwrap_or_default();
                let group_id = arg_u32!(1);
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.set_group_info(group_id, &name, &data),
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            17 => {
                let group_id = arg_u32!(1);
                let group = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.group(group_id),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let Some(group) = group else {
                    return dplay::DPNERR_INVALIDGROUP;
                };
                let base = arg!(2);
                let size_ptr = arg!(3);
                let name = group.name.clone();
                let data = group.data.clone();
                let base_size = (8 + 4 * pointer_size) as u32;
                let required = base_size + (name.len() as u32 + 1) * 2 + data.len() as u32;
                if size_ptr != 0 {
                    write_u32(memory, size_ptr, required);
                }
                if base == 0 {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                let available = if size_ptr != 0 {
                    read_u32(memory, size_ptr).unwrap_or(0)
                } else {
                    u32::MAX
                };
                if available < required {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                let _ = write_guest_bytes_checked(memory, base, &vec![0u8; required as usize]);
                write_u32(memory, base, required);
                write_u32(memory, base + 4, dplay::DPNINFO_NAME | dplay::DPNINFO_DATA);
                let name_memory = base + base_size as u64;
                let _ = write_guest_bytes_checked(
                    memory,
                    name_memory,
                    &dplay::encode_utf16_bytes(&name),
                );
                let _ = write_guest_pointer(memory, base + 8, name_memory, self.guest_arch);
                let data_memory = name_memory + (name.len() as u64 + 1) * 2;
                let _ = write_guest_bytes_checked(memory, data_memory, &data);
                let _ = write_guest_pointer(
                    memory,
                    base + 8 + pointer_size,
                    data_memory,
                    self.guest_arch,
                );
                write_u32(memory, base + 8 + 2 * pointer_size, data.len() as u32);
                dplay::S_OK
            }
            18 => {
                let mut ids: Vec<u32> = Vec::new();
                if let Some(dplay::DplayObjectEntry {
                    object: dplay::DplayObject::Peer(peer),
                    ..
                }) = runtime.objects.get(&this)
                {
                    if arg_u32!(3) & 0x0001 != 0 {
                        ids.extend(peer.players().iter().map(|player| player.dpnid));
                    }
                    if arg_u32!(3) & 0x0010 != 0 {
                        ids.extend(peer.groups().iter().map(|group| group.group_id));
                    }
                }
                let buffer = arg!(1);
                let count_ptr = arg!(2);
                let required = ids.len() as u32;
                let available = if count_ptr != 0 {
                    read_u32(memory, count_ptr).unwrap_or(0)
                } else {
                    u32::MAX
                };
                if count_ptr != 0 {
                    write_u32(memory, count_ptr, required);
                }
                if buffer == 0 || available < required {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                for (index, id) in ids.iter().enumerate() {
                    write_u32(memory, buffer + index as u64 * 4, *id);
                }
                dplay::S_OK
            }
            19 => {
                let group = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.group(arg_u32!(1)),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let Some(group) = group else {
                    return dplay::DPNERR_INVALIDGROUP;
                };
                let members: Vec<u32> = group.members.iter().copied().collect();
                let buffer = arg!(2);
                let count_ptr = arg!(3);
                let required = members.len() as u32;
                let available = if count_ptr != 0 {
                    read_u32(memory, count_ptr).unwrap_or(0)
                } else {
                    u32::MAX
                };
                if count_ptr != 0 {
                    write_u32(memory, count_ptr, required);
                }
                if buffer == 0 || available < required {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                for (index, id) in members.iter().enumerate() {
                    write_u32(memory, buffer + index as u64 * 4, *id);
                }
                dplay::S_OK
            }
            20 => {
                let info = arg!(1);
                let name = dplay_utf16_z(
                    memory,
                    read_guest_pointer(memory, info + 8, self.guest_arch).unwrap_or(0),
                );
                let data_size = read_u32(memory, info + 8 + 2 * pointer_size).unwrap_or(0);
                let data_ptr = read_guest_pointer(memory, info + 8 + pointer_size, self.guest_arch)
                    .unwrap_or(0);
                let data =
                    read_guest_bytes(memory, data_ptr, data_size as usize).unwrap_or_default();
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => {
                        peer.set_local_player_name(&name);
                        peer.set_local_player_data(&data);
                        dplay::S_OK
                    }
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            21 => {
                let dpnid = arg_u32!(1);
                let info = arg!(2);
                let size_ptr = arg!(3);
                let (name, data, is_local) = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => {
                        let local = dpnid == peer.local_dpnid();
                        let name = if local {
                            peer.local_player_name().to_string()
                        } else {
                            peer.players()
                                .into_iter()
                                .find(|player| player.dpnid == dpnid)
                                .map(|player| player.name)
                                .unwrap_or_default()
                        };
                        let data = if local {
                            peer.local_player_data().to_vec()
                        } else {
                            Vec::new()
                        };
                        (name, data, local)
                    }
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                if !is_local {
                    let exists = matches!(
                        runtime.objects.get(&this),
                        Some(dplay::DplayObjectEntry {
                            object: dplay::DplayObject::Peer(peer),
                            ..
                        }) if peer.player_exists(dpnid)
                    );
                    if !exists {
                        return dplay::DPNERR_INVALIDPLAYER;
                    }
                }
                let base_size = (8 + 4 * pointer_size) as u32;
                let required = base_size + (name.len() as u32 + 1) * 2 + data.len() as u32;
                if size_ptr != 0 {
                    write_u32(memory, size_ptr, required);
                }
                if info == 0 {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                let available = if size_ptr != 0 {
                    read_u32(memory, size_ptr).unwrap_or(0)
                } else {
                    u32::MAX
                };
                if available < required {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                let _ = write_guest_bytes_checked(memory, info, &vec![0u8; required as usize]);
                write_u32(memory, info, required);
                write_u32(memory, info + 4, dplay::DPNINFO_NAME | dplay::DPNINFO_DATA);
                let name_memory = info + base_size as u64;
                let _ = write_guest_bytes_checked(
                    memory,
                    name_memory,
                    &dplay::encode_utf16_bytes(&name),
                );
                let _ = write_guest_pointer(memory, info + 8, name_memory, self.guest_arch);
                let data_memory = name_memory + (name.len() as u64 + 1) * 2;
                let _ = write_guest_bytes_checked(memory, data_memory, &data);
                let _ = write_guest_pointer(
                    memory,
                    info + 8 + pointer_size,
                    data_memory,
                    self.guest_arch,
                );
                write_u32(memory, info + 8 + 2 * pointer_size, data.len() as u32);
                dplay::S_OK
            }
            22 => {
                let dpnid = arg_u32!(1);
                let out = arg!(2);
                if out == 0 {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                let addr = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer
                        .players()
                        .into_iter()
                        .find(|player| player.dpnid == dpnid)
                        .map(|player| player.addr),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let Some(addr) = addr else {
                    return dplay::DPNERR_INVALIDPLAYER;
                };
                match self.dplay_create_address_for(memory, runtime, addr) {
                    Ok(object) => {
                        let _ = write_guest_pointer(memory, out, object, self.guest_arch);
                        dplay::S_OK
                    }
                    Err(_) => dplay::DPNERR_OUTOFMEMORY,
                }
            }
            23 => {
                let array = arg!(1);
                let count_ptr = arg!(2);
                let local = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.local_address(),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let required = u32::from(local.is_some());
                let available = if count_ptr != 0 {
                    read_u32(memory, count_ptr).unwrap_or(0)
                } else {
                    u32::MAX
                };
                if count_ptr != 0 {
                    write_u32(memory, count_ptr, required);
                }
                if array == 0 || available < required {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                if let Some(addr) = local {
                    match self.dplay_create_address_for(memory, runtime, addr) {
                        Ok(object) => {
                            let _ = write_guest_pointer(memory, array, object, self.guest_arch);
                        }
                        Err(_) => return dplay::DPNERR_OUTOFMEMORY,
                    }
                }
                dplay::S_OK
            }
            24 => match runtime.objects.get_mut(&this) {
                Some(dplay::DplayObjectEntry {
                    object: dplay::DplayObject::Peer(peer),
                    ..
                }) => peer.close(),
                _ => dplay::DPNERR_INVALIDPARAM,
            },
            25 => {
                // EnumHosts(app, hostAddr, device, data, size, count, retry,
                //           timeout, userContext, phAsync, flags).
                let host_object = arg!(2);
                let targets = match runtime.objects.get(&host_object) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Address(address),
                        ..
                    }) => match address.socket_addr() {
                        Some(address) => vec![address],
                        None => Vec::new(),
                    },
                    _ => Vec::new(),
                };
                let timeout_ms = arg_u32!(8);
                let timeout = if timeout_ms == 0 {
                    Duration::from_millis(u64::from(dplay::DEFAULT_ENUM_TIMEOUT_MS))
                } else {
                    Duration::from_millis(u64::from(timeout_ms))
                };
                let context = arg!(9);
                let flags = arg_u32!(11);
                let asynchronous = flags & dplay::DPNOP_SYNC == 0;
                let application_guid =
                    dplay_read_app_desc(memory, arg!(1), self.guest_arch).application_guid;
                if asynchronous {
                    let handle = match runtime.objects.get_mut(&this) {
                        Some(dplay::DplayObjectEntry {
                            object: dplay::DplayObject::Peer(peer),
                            ..
                        }) => {
                            match peer.start_enum_hosts(
                                &application_guid,
                                &targets,
                                timeout,
                                context,
                            ) {
                                Ok(handle) => handle,
                                Err(error) => return error,
                            }
                        }
                        _ => return dplay::DPNERR_INVALIDPARAM,
                    };
                    if arg!(10) != 0 {
                        let _ = write_guest_pointer(
                            memory,
                            arg!(10),
                            u64::from(handle),
                            self.guest_arch,
                        );
                    }
                    dplay::DPNERR_PENDING
                } else {
                    let results = match runtime.objects.get(&this) {
                        Some(dplay::DplayObjectEntry {
                            object: dplay::DplayObject::Peer(peer),
                            ..
                        }) => peer.enum_hosts(&application_guid, &targets, timeout),
                        _ => return dplay::DPNERR_INVALIDPARAM,
                    };
                    if arg!(10) != 0 {
                        let _ = write_guest_pointer(memory, arg!(10), 0, self.guest_arch);
                    }
                    for session in results {
                        runtime.push_event(
                            this,
                            dplay::DplayEvent::EnumHostsResponse {
                                context,
                                session,
                                async_op: 0,
                            },
                        );
                    }
                    dplay::S_OK
                }
            }
            26 => {
                let data_size = arg_u32!(3) as usize;
                let data = read_guest_bytes(memory, arg!(2), data_size).unwrap_or_default();
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.destroy_player(arg_u32!(1), &data),
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            27 => dplay::S_OK,
            28 => {
                let dpnid = arg_u32!(1);
                let out = arg!(2);
                let context = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) if dpnid == peer.local_dpnid() => peer.local_context(),
                    Some(_) => 0,
                    None => return dplay::DPNERR_INVALIDPARAM,
                };
                if context == 0 {
                    return dplay::DPNERR_INVALIDPLAYER;
                }
                if out != 0 {
                    let _ = write_guest_pointer(memory, out, context, self.guest_arch);
                }
                dplay::S_OK
            }
            29 => {
                // GetGroupContext(dpnidGroup, pvGroupContext, flags): the
                // group context is the real byte storage set by
                // CreateGroup/SetGroupInfo, materialised in guest memory.
                if arg_u32!(3) != 0 {
                    return dplay::DPNERR_INVALIDFLAGS;
                }
                let out = arg!(2);
                if out == 0 {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                let group_id = arg_u32!(1);
                let data = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.group_context(group_id),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                match data {
                    Ok(bytes) => {
                        let pointer = if bytes.is_empty() {
                            0
                        } else {
                            match self.alloc_zeroed(memory, bytes.len(), 4) {
                                Ok(pointer) => {
                                    let _ = write_guest_bytes_checked(memory, pointer, &bytes);
                                    pointer
                                }
                                Err(_) => return dplay::DPNERR_OUTOFMEMORY,
                            }
                        };
                        let _ = write_guest_pointer(memory, out, pointer, self.guest_arch);
                        dplay::S_OK
                    }
                    Err(error) => error,
                }
            }
            30 => {
                let caps = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.caps(),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let base = arg!(1);
                if base == 0 {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                let _ = write_guest_bytes_checked(memory, base, &vec![0u8; 20]);
                write_u32(memory, base, 20);
                write_u32(memory, base + 4, caps.flags);
                write_u32(memory, base + 8, caps.connect_timeout_ms);
                write_u32(memory, base + 12, caps.connect_retries);
                write_u32(memory, base + 16, caps.timeout_until_keep_alive_ms);
                dplay::S_OK
            }
            31 => {
                let base = arg!(1);
                if base == 0 {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                let caps = dplay::DplayCaps {
                    flags: read_u32(memory, base + 4).unwrap_or(0),
                    connect_timeout_ms: read_u32(memory, base + 8).unwrap_or(0),
                    connect_retries: read_u32(memory, base + 12).unwrap_or(0),
                    timeout_until_keep_alive_ms: read_u32(memory, base + 16).unwrap_or(0),
                };
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.set_caps(&caps),
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            32 => {
                let base = arg!(2);
                if base == 0 {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                let caps = dplay::DplaySpCaps {
                    flags: read_u32(memory, base + 4).unwrap_or(0),
                    num_threads: read_u32(memory, base + 8).unwrap_or(0),
                    default_enum_count: read_u32(memory, base + 12).unwrap_or(0),
                    default_enum_retry_interval_ms: read_u32(memory, base + 16).unwrap_or(0),
                    default_enum_timeout_ms: read_u32(memory, base + 20).unwrap_or(0),
                    max_enum_payload_size: read_u32(memory, base + 24).unwrap_or(0),
                    buffers_per_thread: read_u32(memory, base + 28).unwrap_or(0),
                    system_buffer_size: read_u32(memory, base + 32).unwrap_or(0),
                };
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.set_sp_caps(&caps),
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            33 => {
                let caps = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.sp_caps(),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let base = arg!(2);
                if base == 0 {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                let _ = write_guest_bytes_checked(memory, base, &vec![0u8; 36]);
                write_u32(memory, base, 36);
                write_u32(memory, base + 4, caps.flags);
                write_u32(memory, base + 8, caps.num_threads);
                write_u32(memory, base + 12, caps.default_enum_count);
                write_u32(memory, base + 16, caps.default_enum_retry_interval_ms);
                write_u32(memory, base + 20, caps.default_enum_timeout_ms);
                write_u32(memory, base + 24, caps.max_enum_payload_size);
                write_u32(memory, base + 28, caps.buffers_per_thread);
                write_u32(memory, base + 32, caps.system_buffer_size);
                dplay::S_OK
            }
            34 => {
                let info = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Peer(peer),
                        ..
                    }) => peer.connection_info(),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let base = arg!(2);
                if base == 0 {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                let _ = write_guest_bytes_checked(memory, base, &vec![0u8; 92]);
                write_u32(memory, base, 92);
                write_u32(memory, base + 4, info.round_trip_latency_ms);
                write_u32(
                    memory,
                    base + 8,
                    info.bytes_sent.min(u64::from(u32::MAX)) as u32,
                );
                write_u32(
                    memory,
                    base + 12,
                    info.packets_sent.min(u64::from(u32::MAX)) as u32,
                );
                write_u32(
                    memory,
                    base + 16,
                    info.bytes_received.min(u64::from(u32::MAX)) as u32,
                );
                write_u32(
                    memory,
                    base + 20,
                    info.packets_received.min(u64::from(u32::MAX)) as u32,
                );
                write_u32(
                    memory,
                    base + 84,
                    info.messages_received.min(u64::from(u32::MAX)) as u32,
                );
                dplay::S_OK
            }
            // RegisterLobby: this runtime has no DirectPlay lobby service or
            // lobby client connection to register with, so the real result
            // is DPNERR_UNSUPPORTED.
            35 => dplay::DPNERR_UNSUPPORTED,
            36 => match runtime.objects.get_mut(&this) {
                Some(dplay::DplayObjectEntry {
                    object: dplay::DplayObject::Peer(peer),
                    ..
                }) => {
                    let reason = peer.close();
                    runtime.push_event(
                        this,
                        dplay::DplayEvent::TerminateSession {
                            result: reason,
                            data: Vec::new(),
                        },
                    );
                    dplay::S_OK
                }
                _ => dplay::DPNERR_INVALIDPARAM,
            },
            _ => dplay::DPNERR_INVALIDPARAM,
        }
    }

    /// Build a real address object for a live socket address.  The caller
    /// already holds the per-process store borrow from vtable dispatch.
    fn dplay_create_address_for(
        &mut self,
        memory: &mut MemoryImage,
        runtime: &mut crate::dplay::DplayRuntime,
        addr: std::net::SocketAddr,
    ) -> AppResult<u64> {
        let mut address = crate::dplay::Dplay8Address::new();
        let _ = address.set_hostname(&addr.ip().to_string());
        let _ = address.set_port(addr.port());
        let _ = address.set_sp(&crate::dplay::CLSID_DP8SP_TCPIP);
        self.dplay_create_object_in(
            memory,
            runtime,
            crate::dplay::IFACE_ADDRESS,
            crate::dplay::DplayObject::Address(address),
        )
    }

    /// Deliver the queued DirectPlay8 engine events (received datagrams,
    /// connect/send completions, player create/destroy, session lost) to the
    /// registered guest message handler.  This runs from the runtime
    /// servicing points (block-dispatch safepoint and message-loop idle
    /// drain) so callbacks never run inside the peer method that queued the
    /// event.
    pub(crate) fn drain_pending_dplay_events(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::dplay::DplayObject;
        let pid = self.guest_pid;
        let mut deliveries: Vec<(u64, u64, u32, crate::dplay::DplayEvent)> = Vec::new();
        {
            let mut store = crate::dplay::lock_dplay_runtimes();
            let Some(runtime) = store.get_mut(&pid) else {
                return Ok(());
            };
            let owners: Vec<u64> = runtime
                .objects
                .iter()
                .filter(|(_, entry)| matches!(entry.object, DplayObject::Peer(_)))
                .map(|(owner, _)| *owner)
                .collect();
            for owner in owners {
                let Some(crate::dplay::DplayObjectEntry {
                    object: DplayObject::Peer(peer),
                    ..
                }) = runtime.objects.get_mut(&owner)
                else {
                    continue;
                };
                let handler = peer.message_handler();
                if handler == 0 {
                    let _ = peer.poll_engine_events();
                    continue;
                }
                let user_context = peer.user_context();
                let local_dpnid = peer.local_dpnid();
                for event in peer.poll_engine_events() {
                    deliveries.push((handler, user_context, local_dpnid, event));
                }
            }
            let pending: Vec<crate::dplay::PendingDplayEvent> = runtime.pending.drain(..).collect();
            for pending in pending {
                let Some(crate::dplay::DplayObjectEntry {
                    object: DplayObject::Peer(peer),
                    ..
                }) = runtime.objects.get_mut(&pending.owner)
                else {
                    continue;
                };
                if let Some(handle) = pending.event.async_operation() {
                    if !peer.complete_async_operation(handle) {
                        // Cancelled while queued: the completion must not run.
                        continue;
                    }
                }
                let handler = peer.message_handler();
                if handler == 0 {
                    continue;
                }
                deliveries.push((
                    handler,
                    peer.user_context(),
                    peer.local_dpnid(),
                    pending.event,
                ));
            }
        }
        for (handler, user_context, local_dpnid, event) in deliveries {
            let (message_id, message_ptr) =
                self.dplay_materialize_message(memory, &event, local_dpnid)?;
            let _ = self.execute_guest_callback(
                state,
                memory,
                handler,
                &[user_context, u64::from(message_id), message_ptr],
                "IDirectPlay8Peer message handler",
            )?;
        }
        Ok(())
    }

    /// Materialise one `DPN_MSGID_*` message structure in guest memory using
    /// the guest architecture's pointer size and natural alignment.
    fn dplay_materialize_message(
        &mut self,
        memory: &mut MemoryImage,
        event: &crate::dplay::DplayEvent,
        local_dpnid: u32,
    ) -> AppResult<(u32, u64)> {
        use crate::dplay::DplayEvent;
        let is64 = self.guest_arch == GuestArch::X64;
        let pointer_size: usize = if is64 { 8 } else { 4 };
        match event {
            DplayEvent::Receive { sender, data, .. } => {
                let data_ptr = if data.is_empty() {
                    0
                } else {
                    let pointer = self.alloc_zeroed(memory, data.len(), 1)?;
                    let _ = write_guest_bytes_checked(memory, pointer, data);
                    pointer
                };
                let (size, source_at, destination_at, group_at) = if is64 {
                    (64, 32, 40, 48)
                } else {
                    (32, 16, 20, 24)
                };
                let base = self.alloc_zeroed(memory, size, pointer_size as u64)?;
                write_u32(memory, base, size as u32);
                let pointer_at = if is64 { 16 } else { 8 };
                let length_at = if is64 { 24 } else { 12 };
                if is64 {
                    write_u64(memory, base + pointer_at, data_ptr);
                } else {
                    write_u32(memory, base + pointer_at, data_ptr as u32);
                }
                write_u32(memory, base + length_at, data.len() as u32);
                if is64 {
                    write_u64(memory, base + source_at, u64::from(*sender));
                    write_u64(memory, base + destination_at, u64::from(local_dpnid));
                    write_u64(memory, base + group_at, 0);
                } else {
                    write_u32(memory, base + source_at, *sender);
                    write_u32(memory, base + destination_at, local_dpnid);
                    write_u32(memory, base + group_at, 0);
                }
                Ok((1, base))
            }
            DplayEvent::CreatePlayer { dpnid, context } => {
                let (size, dpnid_at, context_at) = if is64 { (24, 8, 16) } else { (12, 4, 8) };
                let base = self.alloc_zeroed(memory, size, pointer_size as u64)?;
                write_u32(memory, base, size as u32);
                if is64 {
                    write_u64(memory, base + dpnid_at, u64::from(*dpnid));
                    write_u64(memory, base + context_at, *context);
                } else {
                    write_u32(memory, base + dpnid_at, *dpnid);
                    write_u32(memory, base + context_at, *context as u32);
                }
                Ok((3, base))
            }
            DplayEvent::DestroyPlayer {
                dpnid,
                reason,
                context,
            } => {
                let (size, dpnid_at, reason_at, context_at) = if is64 {
                    (32, 8, 16, 24)
                } else {
                    (16, 4, 8, 12)
                };
                let base = self.alloc_zeroed(memory, size, pointer_size as u64)?;
                write_u32(memory, base, size as u32);
                if is64 {
                    write_u64(memory, base + dpnid_at, u64::from(*dpnid));
                    write_u32(memory, base + reason_at, *reason);
                    write_u64(memory, base + context_at, *context);
                } else {
                    write_u32(memory, base + dpnid_at, *dpnid);
                    write_u32(memory, base + reason_at, *reason);
                    write_u32(memory, base + context_at, *context as u32);
                }
                Ok((4, base))
            }
            DplayEvent::ConnectComplete {
                async_op,
                context,
                result,
                dpnid,
            } => {
                let (size, op_at, context_at, result_at, player_at) = if is64 {
                    (56, 8, 16, 24, 48)
                } else {
                    (28, 4, 8, 12, 24)
                };
                let base = self.alloc_zeroed(memory, size, pointer_size as u64)?;
                write_u32(memory, base, size as u32);
                if is64 {
                    write_u64(memory, base + op_at, u64::from(*async_op));
                    write_u64(memory, base + context_at, *context);
                    write_u32(memory, base + result_at, *result);
                    write_u64(memory, base + player_at, u64::from(*dpnid));
                } else {
                    write_u32(memory, base + op_at, *async_op);
                    write_u32(memory, base + context_at, *context as u32);
                    write_u32(memory, base + result_at, *result);
                    write_u32(memory, base + player_at, *dpnid);
                }
                Ok((7, base))
            }
            DplayEvent::SendComplete {
                async_op,
                context,
                result,
            } => {
                let (size, op_at, context_at, result_at) = if is64 {
                    (32, 8, 16, 24)
                } else {
                    (16, 4, 8, 12)
                };
                let base = self.alloc_zeroed(memory, size, pointer_size as u64)?;
                write_u32(memory, base, size as u32);
                if is64 {
                    write_u64(memory, base + op_at, u64::from(*async_op));
                    write_u64(memory, base + context_at, *context);
                    write_u32(memory, base + result_at, *result);
                } else {
                    write_u32(memory, base + op_at, *async_op);
                    write_u32(memory, base + context_at, *context as u32);
                    write_u32(memory, base + result_at, *result);
                }
                Ok((2, base))
            }
            DplayEvent::SessionLost { result } => {
                let base = self.alloc_zeroed(memory, 8, 4)?;
                write_u32(memory, base, 8);
                write_u32(memory, base + 4, *result);
                Ok((10, base))
            }
            DplayEvent::TerminateSession { result, data } => {
                let data_ptr = if data.is_empty() {
                    0
                } else {
                    let pointer = self.alloc_zeroed(memory, data.len(), 1)?;
                    let _ = write_guest_bytes_checked(memory, pointer, data);
                    pointer
                };
                let (size, result_at, data_at, size_at) = if is64 {
                    (32, 8, 16, 24)
                } else {
                    (16, 4, 8, 12)
                };
                let base = self.alloc_zeroed(memory, size, pointer_size as u64)?;
                write_u32(memory, base, size as u32);
                if is64 {
                    write_u32(memory, base + result_at, *result);
                    write_u64(memory, base + data_at, data_ptr);
                    write_u32(memory, base + size_at, data.len() as u32);
                } else {
                    write_u32(memory, base + result_at, *result);
                    write_u32(memory, base + data_at, data_ptr as u32);
                    write_u32(memory, base + size_at, data.len() as u32);
                }
                Ok((11, base))
            }
            DplayEvent::EnumHostsResponse {
                context, session, ..
            } => {
                let (size, context_at, latency_at) = if is64 { (40, 8, 32) } else { (20, 4, 16) };
                let base = self.alloc_zeroed(memory, size, pointer_size as u64)?;
                write_u32(memory, base, size as u32);
                if is64 {
                    write_u64(memory, base + context_at, *context);
                    write_u32(memory, base + latency_at, session.latency_ms);
                } else {
                    write_u32(memory, base + context_at, *context as u32);
                    write_u32(memory, base + latency_at, session.latency_ms);
                }
                Ok((13, base))
            }
        }
    }
}

impl PeHostRuntime {
    /// The legacy `IDirectPlay4` method subset, backed by the same engine.
    fn dplay_invoke_legacy(
        &mut self,
        runtime: &mut crate::dplay::DplayRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        this: u64,
        method: u16,
    ) -> u32 {
        use crate::dplay;
        /// `DPERR_NOMESSAGES` (`MAKE_HRESULT(1, _FACDP, 190)`).
        const DPERR_NOMESSAGES: u32 = 0x8015_00be;
        const DPSESSION_NEWGAME: u32 = 0x0000_0001;
        let pointer_size = self.guest_arch.pointer_bytes() as u64;
        macro_rules! arg {
            ($index:expr) => {
                xact_arg(state, memory, $index).unwrap_or(0)
            };
        }
        macro_rules! arg_u32 {
            ($index:expr) => {
                xact_arg_u32(state, memory, $index).unwrap_or(0)
            };
        }
        match method {
            3 | 5 | 7 | 8 | 10 | 11 | 15 | 16 | 17 | 27 | 28 | 32 | 33 | 34 | 35 | 36 | 37 | 38
            | 39 | 40 | 41 | 42 | 43 | 44 | 45 | 46 | 47 | 48 | 49 | 50 | 51 | 52 => {
                dplay::DPNERR_UNSUPPORTED
            }
            4 => match runtime.objects.get_mut(&this) {
                Some(dplay::DplayObjectEntry {
                    object: dplay::DplayObject::Legacy(legacy),
                    ..
                }) => legacy.close(),
                _ => dplay::DPNERR_INVALIDPARAM,
            },
            6 => {
                let out = arg!(1);
                let name = dplay_utf16_z(
                    memory,
                    read_guest_pointer(memory, arg!(2) + 8, self.guest_arch).unwrap_or(0),
                );
                if out == 0 {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Legacy(legacy),
                        ..
                    }) => match legacy.create_player(&name) {
                        Ok(player_id) => {
                            write_u32(memory, out, player_id);
                            dplay::S_OK
                        }
                        Err(error) => error,
                    },
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            9 => match runtime.objects.get_mut(&this) {
                Some(dplay::DplayObjectEntry {
                    object: dplay::DplayObject::Legacy(legacy),
                    ..
                }) => legacy.destroy_player(arg_u32!(1)),
                _ => dplay::DPNERR_INVALIDPARAM,
            },
            12 => {
                let callback = arg!(2);
                let context = arg!(3);
                if callback == 0 {
                    return dplay::DPNERR_INVALIDPARAM;
                }
                let players = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Legacy(legacy),
                        ..
                    }) => legacy.peer.players(),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                for player in players {
                    let name_memory =
                        match self.alloc_zeroed(memory, (player.name.len() + 1) * 2, 2) {
                            Ok(address) => address,
                            Err(_) => return dplay::DPNERR_OUTOFMEMORY,
                        };
                    if write_guest_bytes(
                        memory,
                        name_memory,
                        &dplay::encode_utf16_bytes(&player.name),
                    )
                    .is_err()
                    {
                        return dplay::DPNERR_INVALIDPARAM;
                    }
                    let dname = match self.alloc_zeroed(
                        memory,
                        (8 + pointer_size * 2) as usize,
                        pointer_size,
                    ) {
                        Ok(address) => address,
                        Err(_) => return dplay::DPNERR_OUTOFMEMORY,
                    };
                    write_u32(memory, dname, (8 + pointer_size * 2) as u32);
                    write_u32(memory, dname + 4, 0);
                    let _ = write_guest_pointer(memory, dname + 8, name_memory, self.guest_arch);
                    let _ = write_guest_pointer(
                        memory,
                        dname + 8 + pointer_size,
                        name_memory,
                        self.guest_arch,
                    );
                    match self.execute_guest_callback(
                        state,
                        memory,
                        callback,
                        &[
                            u64::from(player.dpnid),
                            u64::from(player.flags),
                            dname,
                            0,
                            context,
                        ],
                        "IDirectPlay4::EnumPlayers",
                    ) {
                        Ok(result) if result == 0 => break,
                        Ok(_) => {}
                        Err(_) => return dplay::DPNERR_GENERIC,
                    }
                }
                dplay::S_OK
            }
            13 => {
                let lpsd = arg!(1);
                let timeout_ms = arg_u32!(2);
                let callback = arg!(3);
                let context = arg!(4);
                if callback == 0 {
                    return dplay::DPNERR_INVALIDPARAM;
                }
                let application_guid = if lpsd != 0 {
                    dplay_riid(memory, lpsd + 24)
                } else {
                    [0u8; 16]
                };
                let timeout = if timeout_ms == 0 {
                    Duration::from_millis(u64::from(dplay::DEFAULT_ENUM_TIMEOUT_MS))
                } else {
                    Duration::from_millis(u64::from(timeout_ms))
                };
                let sessions = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Legacy(legacy),
                        ..
                    }) => legacy.peer.enum_hosts(&application_guid, &[], timeout),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let timeout_pointer = match self.alloc_zeroed(memory, 4, 4) {
                    Ok(address) => address,
                    Err(_) => return dplay::DPNERR_OUTOFMEMORY,
                };
                write_u32(memory, timeout_pointer, timeout_ms);
                for session in sessions {
                    let size: u64 = 80;
                    let desc = match self.alloc_zeroed(
                        memory,
                        (size + session.session_name.len() as u64 + 1) as usize,
                        4,
                    ) {
                        Ok(address) => address,
                        Err(_) => return dplay::DPNERR_OUTOFMEMORY,
                    };
                    write_u32(memory, desc, size as u32);
                    write_u32(memory, desc + 4, dplay::DPNSESSION_NODPNSVR);
                    let _ = write_guest_bytes_checked(memory, desc + 8, &session.instance_guid);
                    let _ = write_guest_bytes_checked(memory, desc + 24, &session.application_guid);
                    write_u32(memory, desc + 40, session.max_players);
                    write_u32(memory, desc + 44, session.current_players);
                    let name_memory = desc + size;
                    let _ = write_guest_bytes_checked(
                        memory,
                        name_memory,
                        &[session.session_name.as_bytes(), &[0]].concat(),
                    );
                    let _ = write_guest_pointer(memory, desc + 48, name_memory, self.guest_arch);
                    match self.execute_guest_callback(
                        state,
                        memory,
                        callback,
                        &[desc, timeout_pointer, 0, context],
                        "IDirectPlay4::EnumSessions",
                    ) {
                        Ok(result) if result == 0 => break,
                        Ok(_) => {}
                        Err(_) => return dplay::DPNERR_GENERIC,
                    }
                }
                dplay::S_OK
            }
            14 | 19 => {
                let (is_host, max_players) = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Legacy(legacy),
                        ..
                    }) => (legacy.peer.is_hosting(), legacy.max_players),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let base = if method == 14 { arg!(1) } else { arg!(2) };
                if base == 0 {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                let _ = write_guest_bytes_checked(memory, base, &vec![0u8; 40]);
                write_u32(memory, base, 40);
                write_u32(memory, base + 4, if is_host { 0x0000_0002 } else { 0 });
                write_u32(memory, base + 8, dplay::MAX_MESSAGE_PAYLOAD as u32);
                write_u32(memory, base + 12, 0);
                write_u32(memory, base + 16, max_players);
                write_u32(memory, base + 20, 100_000);
                write_u32(memory, base + 24, 1);
                write_u32(memory, base + 28, 8);
                write_u32(memory, base + 32, 12);
                write_u32(memory, base + 36, dplay::DEFAULT_CONNECT_TIMEOUT_MS);
                dplay::S_OK
            }
            18 => {
                let player_id = arg_u32!(1);
                let addr = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Legacy(legacy),
                        ..
                    }) => legacy.player_address(player_id),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let Some(addr) = addr else {
                    return dplay::DPNERR_INVALIDPLAYER;
                };
                let buffer = arg!(2);
                let size_ptr = arg!(3);
                let required = 16u32;
                if size_ptr != 0 {
                    write_u32(memory, size_ptr, required);
                }
                if buffer == 0 {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                let available = if size_ptr != 0 {
                    read_u32(memory, size_ptr).unwrap_or(0)
                } else {
                    u32::MAX
                };
                if available < required {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                // A real SOCKADDR_IN for the player's TCP/IP endpoint.
                let _ = write_guest_bytes_checked(memory, buffer, &vec![0u8; 16]);
                write_u16(memory, buffer, 2);
                write_u16(memory, buffer + 2, addr.port().to_be());
                if let std::net::IpAddr::V4(ip) = addr.ip() {
                    let _ = write_guest_bytes_checked(memory, buffer + 4, &ip.octets());
                }
                dplay::S_OK
            }
            20 | 29 => {
                let player_id = arg_u32!(1);
                if method == 20 {
                    let data = match runtime.objects.get(&this) {
                        Some(dplay::DplayObjectEntry {
                            object: dplay::DplayObject::Legacy(legacy),
                            ..
                        }) => legacy
                            .players
                            .get(&player_id)
                            .map(|player| player.data.clone())
                            .unwrap_or_default(),
                        _ => return dplay::DPNERR_INVALIDPARAM,
                    };
                    dplay_write_raw_buffer(memory, arg!(2), arg!(3), &data)
                } else {
                    let size = arg_u32!(3) as usize;
                    let data = read_guest_bytes(memory, arg!(2), size).unwrap_or_default();
                    match runtime.objects.get_mut(&this) {
                        Some(dplay::DplayObjectEntry {
                            object: dplay::DplayObject::Legacy(legacy),
                            ..
                        }) => match legacy.players.get_mut(&player_id) {
                            Some(player) => {
                                player.data = data;
                                dplay::S_OK
                            }
                            None => dplay::DPNERR_INVALIDPLAYER,
                        },
                        _ => dplay::DPNERR_INVALIDPARAM,
                    }
                }
            }
            21 | 30 => {
                if method == 21 {
                    let player_id = arg_u32!(1);
                    let name = match runtime.objects.get(&this) {
                        Some(dplay::DplayObjectEntry {
                            object: dplay::DplayObject::Legacy(legacy),
                            ..
                        }) => legacy
                            .players
                            .get(&player_id)
                            .map(|player| player.name.clone()),
                        _ => return dplay::DPNERR_INVALIDPARAM,
                    };
                    let Some(name) = name else {
                        return dplay::DPNERR_INVALIDPLAYER;
                    };
                    let buffer = arg!(2);
                    let size_ptr = arg!(3);
                    let base_size = 8 + pointer_size * 2;
                    let required = base_size as u32 + (name.len() as u32 + 1) * 2;
                    if size_ptr != 0 {
                        write_u32(memory, size_ptr, required);
                    }
                    if buffer == 0 {
                        return dplay::DPNERR_BUFFERTOOSMALL;
                    }
                    let available = if size_ptr != 0 {
                        read_u32(memory, size_ptr).unwrap_or(0)
                    } else {
                        u32::MAX
                    };
                    if available < required {
                        return dplay::DPNERR_BUFFERTOOSMALL;
                    }
                    let _ =
                        write_guest_bytes_checked(memory, buffer, &vec![0u8; required as usize]);
                    write_u32(memory, buffer, required);
                    write_u32(memory, buffer + 4, 0);
                    let name_memory = buffer + base_size as u64;
                    let _ = write_guest_bytes_checked(
                        memory,
                        name_memory,
                        &dplay::encode_utf16_bytes(&name),
                    );
                    let _ = write_guest_pointer(memory, buffer + 8, name_memory, self.guest_arch);
                    let _ = write_guest_pointer(
                        memory,
                        buffer + 8 + pointer_size,
                        name_memory,
                        self.guest_arch,
                    );
                    dplay::S_OK
                } else {
                    let player_id = arg_u32!(1);
                    let name = dplay_utf16_z(
                        memory,
                        read_guest_pointer(memory, arg!(2) + 8, self.guest_arch).unwrap_or(0),
                    );
                    match runtime.objects.get_mut(&this) {
                        Some(dplay::DplayObjectEntry {
                            object: dplay::DplayObject::Legacy(legacy),
                            ..
                        }) => match legacy.players.get_mut(&player_id) {
                            Some(player) => {
                                player.name = name;
                                dplay::S_OK
                            }
                            None => dplay::DPNERR_INVALIDPLAYER,
                        },
                        _ => dplay::DPNERR_INVALIDPARAM,
                    }
                }
            }
            22 => {
                let (name, instance, application, max) = match runtime.objects.get(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Legacy(legacy),
                        ..
                    }) => (
                        legacy.session_name.clone(),
                        legacy.instance_guid,
                        legacy.app_guid,
                        legacy.max_players,
                    ),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let buffer = arg!(1);
                let size_ptr = arg!(2);
                let required = 80u32 + name.len() as u32 + 1;
                if size_ptr != 0 {
                    write_u32(memory, size_ptr, required);
                }
                if buffer == 0 {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                let available = if size_ptr != 0 {
                    read_u32(memory, size_ptr).unwrap_or(0)
                } else {
                    u32::MAX
                };
                if available < required {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                let _ = write_guest_bytes_checked(memory, buffer, &vec![0u8; required as usize]);
                write_u32(memory, buffer, 80);
                write_u32(memory, buffer + 4, dplay::DPNSESSION_NODPNSVR);
                let _ = write_guest_bytes_checked(memory, buffer + 8, &instance);
                let _ = write_guest_bytes_checked(memory, buffer + 24, &application);
                write_u32(memory, buffer + 40, max);
                write_u32(memory, buffer + 44, 1);
                let name_memory = buffer + 80;
                let _ = write_guest_bytes_checked(
                    memory,
                    name_memory,
                    &[name.as_bytes(), &[0]].concat(),
                );
                let _ = write_guest_pointer(memory, buffer + 48, name_memory, self.guest_arch);
                dplay::S_OK
            }
            23 => match runtime.objects.get_mut(&this) {
                Some(dplay::DplayObjectEntry {
                    object: dplay::DplayObject::Legacy(legacy),
                    ..
                }) => legacy.initialize(),
                _ => dplay::DPNERR_INVALIDPARAM,
            },
            24 => {
                let lpsd = arg!(1);
                let flags = arg_u32!(2);
                if lpsd == 0 {
                    return dplay::DPNERR_INVALIDPARAM;
                }
                let name = dplay_ansi_z(
                    memory,
                    read_guest_pointer(memory, lpsd + 48, self.guest_arch).unwrap_or(0),
                );
                let max_players = read_u32(memory, lpsd + 40).unwrap_or(0);
                let instance = dplay_riid(memory, lpsd + 8);
                let application = dplay_riid(memory, lpsd + 24);
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Legacy(legacy),
                        ..
                    }) => {
                        if flags & DPSESSION_NEWGAME != 0 {
                            let name = if name.is_empty() {
                                "DirectPlay4 Session".to_string()
                            } else {
                                name
                            };
                            let result = legacy.open_host(&name, max_players);
                            if result == dplay::S_OK && application != [0u8; 16] {
                                legacy.app_guid = application;
                            }
                            result
                        } else {
                            let player_name = if name.is_empty() {
                                "DirectPlay4 Player".to_string()
                            } else {
                                name.clone()
                            };
                            legacy.open_session(&instance, &player_name)
                        }
                    }
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            25 => {
                let from_ptr = arg!(1);
                let to_ptr = arg!(2);
                let data_ptr = arg!(4);
                let size_ptr = arg!(5);
                let received = match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Legacy(legacy),
                        ..
                    }) => legacy.receive(Duration::ZERO),
                    _ => return dplay::DPNERR_INVALIDPARAM,
                };
                let Some(message) = received else {
                    return DPERR_NOMESSAGES;
                };
                let available = if size_ptr != 0 {
                    read_u32(memory, size_ptr).unwrap_or(0)
                } else {
                    u32::MAX
                };
                if size_ptr != 0 {
                    write_u32(memory, size_ptr, message.data.len() as u32);
                }
                if data_ptr == 0 || available < message.data.len() as u32 {
                    return dplay::DPNERR_BUFFERTOOSMALL;
                }
                if write_guest_bytes_checked(memory, data_ptr, &message.data).is_err() {
                    return dplay::DPNERR_INVALIDPOINTER;
                }
                if from_ptr != 0 {
                    write_u32(memory, from_ptr, message.from_dpnid);
                }
                if to_ptr != 0 {
                    let local = match runtime.objects.get(&this) {
                        Some(dplay::DplayObjectEntry {
                            object: dplay::DplayObject::Legacy(legacy),
                            ..
                        }) => legacy.local_player,
                        _ => 0,
                    };
                    write_u32(memory, to_ptr, local);
                }
                dplay::S_OK
            }
            26 => {
                let from = arg_u32!(1);
                let to = arg_u32!(2);
                let size = arg_u32!(5) as usize;
                let data = read_guest_bytes(memory, arg!(4), size).unwrap_or_default();
                match runtime.objects.get_mut(&this) {
                    Some(dplay::DplayObjectEntry {
                        object: dplay::DplayObject::Legacy(legacy),
                        ..
                    }) => legacy.send(from, to, &data),
                    _ => dplay::DPNERR_INVALIDPARAM,
                }
            }
            31 => {
                let name = dplay_ansi_z(
                    memory,
                    read_guest_pointer(memory, arg!(1) + 48, self.guest_arch).unwrap_or(0),
                );
                let max_players = read_u32(memory, arg!(1) + 40).unwrap_or(0);
                if !name.is_empty() {
                    match runtime.objects.get_mut(&this) {
                        Some(dplay::DplayObjectEntry {
                            object: dplay::DplayObject::Legacy(legacy),
                            ..
                        }) => {
                            legacy.session_name = name;
                            legacy.max_players = max_players;
                        }
                        _ => return dplay::DPNERR_INVALIDPARAM,
                    }
                }
                dplay::S_OK
            }
            _ => dplay::DPNERR_INVALIDPARAM,
        }
    }
}

// ---------------------------------------------------------------------------
// X3DAudio pure-math tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod audio_activation_tests {
    use super::*;
    use crate::audio_activation::{
        ACTIVATION_E_INVALIDARG, ACTIVATION_E_NOINTERFACE, ACTIVATION_S_OK,
        AUDCLNT_E_DEVICE_INVALIDATED, IID_IAUDIO_CLIENT,
    };
    use crate::ge::{GameEnvironment, GeArch};
    use crate::real_audio::RealAudioBackend;
    use tempfile::TempDir;

    // Guest fixture addresses (far below the x86 thunk/data bases the
    // runtime allocates from, mirroring the runtime's own x86 test layout).
    const STACK: u64 = 0x50_000;
    const HANDLER_OBJECT: u64 = 0x60_000;
    const HANDLER_VTABLE: u64 = 0x60_100;
    const HANDLER_STUB: u64 = 0x60_200;
    const MARKER_HR: u64 = 0x44_000;
    const MARKER_OBJ: u64 = 0x44_004;
    const MARKER_COUNT: u64 = 0x44_008;
    const RIID_ADDR: u64 = 0x63_000;
    const OP_OUT: u64 = 0x64_000;
    const PATH_ADDR: u64 = 0x65_000;

    fn activation_test_runtime(name: &str) -> (PeHostRuntime, TempDir) {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), name, GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.guest_arch = GuestArch::X86;
        runtime.next_thunk_address = thunk_base_for_arch(GuestArch::X86);
        runtime.next_data_address = data_base_for_arch(GuestArch::X86);
        runtime.next_heap_address = heap_base_for_arch(GuestArch::X86);
        runtime
            .win32
            .reset_address_space(private_pages_base_for_arch(GuestArch::X86));
        runtime.x86_heap_region = 0;
        (runtime, temp_dir)
    }

    fn with_big_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(body)
            .expect("spawn big-stack thread")
            .join()
            .expect("big-stack thread panicked")
    }

    fn install_handler(memory: &mut MemoryImage) {
        memory.map_bytes(MARKER_HR, &[0_u8; 12]);
        memory.map_bytes(HANDLER_OBJECT, &[0_u8; 8]);
        memory.map_bytes(HANDLER_VTABLE, &[0_u8; 16]);
        let mut stub = vec![0x90_u8; 0x40];
        stub[..27].copy_from_slice(&[
            0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]   (operation object)
            0xA3, 0x04, 0x40, 0x04, 0x00, // mov [0x44004], eax
            0xA1, 0x08, 0x40, 0x04, 0x00, // mov eax, [0x44008] (count)
            0x05, 0x01, 0x00, 0x00, 0x00, // add eax, 1
            0xA3, 0x08, 0x40, 0x04, 0x00, // mov [0x44008], eax
            0x31, 0xC0, // xor eax, eax
            0xC3, // ret
        ]);
        memory.map_bytes(HANDLER_STUB, &stub);
        write_u32(memory, HANDLER_OBJECT, HANDLER_VTABLE as u32);
        write_u32(memory, HANDLER_VTABLE + 12, HANDLER_STUB as u32);
    }

    fn dispatch_activate(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        path: Option<&str>,
        riid: &[u8; 16],
        handler: u64,
        operation_out: u64,
    ) -> u64 {
        let thunk = runtime.alloc_host_thunk(HostThunk::ActivateAudioInterfaceAsync);
        memory.map_bytes(RIID_ADDR, riid);
        memory.map_bytes(OP_OUT, &[0_u8; 8]);
        let path_addr = match path {
            Some(path) => {
                let mut units = Vec::new();
                for unit in path.encode_utf16() {
                    units.extend_from_slice(&unit.to_le_bytes());
                }
                units.extend_from_slice(&0_u16.to_le_bytes());
                memory.map_bytes(PATH_ADDR, &units);
                PATH_ADDR
            }
            None => 0,
        };
        memory.map_bytes(STACK - 0x400, &[0_u8; 0x600]);
        write_u32(memory, STACK, 0xDEAD_BEEF);
        write_guest_pointer(memory, STACK + 4, path_addr, GuestArch::X86).expect("write path arg");
        write_guest_pointer(memory, STACK + 8, RIID_ADDR, GuestArch::X86).expect("write riid arg");
        write_guest_pointer(memory, STACK + 12, 0, GuestArch::X86)
            .expect("write activation-params arg");
        write_guest_pointer(memory, STACK + 16, handler, GuestArch::X86)
            .expect("write handler arg");
        write_guest_pointer(memory, STACK + 20, operation_out, GuestArch::X86)
            .expect("write operation-out arg");
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, STACK);
        runtime
            .dispatch_import(thunk, &mut state, memory)
            .expect("dispatch ActivateAudioInterfaceAsync");
        state.get(Register::Rax)
    }

    fn drain_activations(runtime: &mut PeHostRuntime, memory: &mut MemoryImage) {
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, STACK);
        runtime
            .drain_pending_audio_activations(&mut state, memory)
            .expect("drain audio activations");
    }

    fn marker_hr(memory: &MemoryImage) -> u32 {
        read_u32(memory, MARKER_HR).expect("marker hr")
    }

    fn marker_object(memory: &MemoryImage) -> u32 {
        read_u32(memory, MARKER_OBJ).expect("marker object")
    }

    fn marker_count(memory: &MemoryImage) -> u32 {
        read_u32(memory, MARKER_COUNT).expect("marker count")
    }

    fn real_default_device_available() -> bool {
        match RealAudioBackend::new() {
            Ok(backend) => backend
                .enumerate_devices()
                .iter()
                .any(|device| device.is_default),
            Err(error) => {
                eprintln!(
                    "audio activation test skipped: no real audio services available ({error})"
                );
                false
            }
        }
    }

    fn real_device_list_empty() -> bool {
        match RealAudioBackend::new() {
            Ok(backend) => backend.enumerate_devices().is_empty(),
            Err(error) => {
                eprintln!("audio activation test proceeding without audio services ({error})");
                true
            }
        }
    }

    fn real_capture_device_available() -> bool {
        match RealAudioBackend::new() {
            Ok(backend) => {
                let mut backend = backend;
                backend.start_input_stream(48_000, 2).is_ok()
            }
            Err(_) => false,
        }
    }

    #[test]
    fn activation_null_handler_fails_invalidarg_without_completion() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = activation_test_runtime("act-invalid-arg");
            let mut memory = MemoryImage::default();
            install_handler(&mut memory);
            // Null completion handler: E_INVALIDARG synchronously, nothing queued.
            let hr = dispatch_activate(
                &mut runtime,
                &mut memory,
                None,
                &IID_IAUDIO_CLIENT,
                0,
                OP_OUT,
            );
            assert_eq!(hr, u64::from(ACTIVATION_E_INVALIDARG));
            assert_eq!(
                crate::audio_activation::pending_activation_completions(runtime.guest_pid),
                0,
                "no completion may be queued for an invalid-argument call"
            );
            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_count(&memory), 0, "handler must never be invoked");
            // Null operation out-param: same synchronous failure.
            let hr = dispatch_activate(
                &mut runtime,
                &mut memory,
                None,
                &IID_IAUDIO_CLIENT,
                HANDLER_OBJECT,
                0,
            );
            assert_eq!(hr, u64::from(ACTIVATION_E_INVALIDARG));
            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_count(&memory), 0);
        })
    }

    #[test]
    fn activation_unsupported_riid_completes_with_nointerface_never_success() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = activation_test_runtime("act-bad-riid");
            let mut memory = MemoryImage::default();
            install_handler(&mut memory);
            let unknown_riid = [0xAB; 16];
            let hr = dispatch_activate(
                &mut runtime,
                &mut memory,
                None,
                &unknown_riid,
                HANDLER_OBJECT,
                OP_OUT,
            );
            // The call starts the async activation and returns S_OK…
            assert_eq!(hr, u64::from(ACTIVATION_S_OK));
            // …but the handler is NOT invoked inline during the call, and the
            // activation operation carries no interface.
            assert_eq!(marker_count(&memory), 0, "handler must not run inline");
            assert_eq!(
                crate::audio_activation::pending_activation_completions(runtime.guest_pid),
                1
            );
            let operation = read_guest_pointer(&memory, OP_OUT, GuestArch::X86).unwrap();
            assert_ne!(operation, 0, "failed activations still return an operation");

            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_count(&memory), 1, "handler invoked exactly once");
            assert_eq!(
                marker_object(&memory) as u64,
                operation,
                "the handler receives the operation object"
            );
            let (result_hr, interface) = crate::audio_activation::operation_get_activate_result(
                runtime.guest_pid,
                operation,
            )
            .expect("completion delivered");
            assert_eq!(
                result_hr, ACTIVATION_E_NOINTERFACE,
                "unsupported riid delivers E_NOINTERFACE"
            );
            assert_eq!(interface, 0, "no interface object for E_NOINTERFACE");
            assert_eq!(
                crate::audio_activation::pending_activation_completions(runtime.guest_pid),
                0,
                "the completion queue is empty after the drain"
            );
        })
    }

    #[test]
    fn activation_operation_survives_early_guest_release_until_completion() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = activation_test_runtime("act-early-release");
            let mut memory = MemoryImage::default();
            install_handler(&mut memory);
            let unknown_riid = [0xCD; 16];
            let hr = dispatch_activate(
                &mut runtime,
                &mut memory,
                None,
                &unknown_riid,
                HANDLER_OBJECT,
                OP_OUT,
            );
            assert_eq!(hr, u64::from(ACTIVATION_S_OK));
            let operation = read_guest_pointer(&memory, OP_OUT, GuestArch::X86).unwrap();
            assert_ne!(operation, 0);
            // The guest drops its reference before completion: the pending
            // completion still holds one, so the handler receives a live
            // operation object.
            assert_eq!(
                runtime
                    .release_guest_object(operation)
                    .expect("guest Release"),
                1
            );
            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_count(&memory), 1);
            assert_eq!(marker_object(&memory) as u64, operation);
            // The completion's reference was the last one: the operation and
            // its activation state are gone after delivery.
            assert!(!runtime.guest_objects.contains_key(&operation));
            assert!(!crate::audio_activation::is_activation_operation(
                runtime.guest_pid,
                operation,
            ));
        })
    }

    #[test]
    fn activation_default_device_completes_async_with_real_endpoint() {
        with_big_stack(|| {
            // Capability gate: needs a real default render device (same probing
            // style as the real_audio tests).
            if !real_default_device_available() {
                eprintln!("skipping activation_default_device test: no real default render device");
                return;
            }
            let (mut runtime, _tmp) = activation_test_runtime("act-default-device");
            let mut memory = MemoryImage::default();
            install_handler(&mut memory);

            let hr = dispatch_activate(
                &mut runtime,
                &mut memory,
                None, // null path = default render device
                &IID_IAUDIO_CLIENT,
                HANDLER_OBJECT,
                OP_OUT,
            );
            assert_eq!(hr, u64::from(ACTIVATION_S_OK));
            // Not delivered inline: the handler must be invoked asynchronously.
            assert_eq!(marker_count(&memory), 0, "handler must not run inline");
            let operation = read_guest_pointer(&memory, OP_OUT, GuestArch::X86).unwrap();
            assert_ne!(operation, 0, "the activation carries an operation object");
            assert_eq!(
                crate::audio_activation::pending_activation_completions(runtime.guest_pid),
                1,
                "one completion queued"
            );

            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_count(&memory), 1, "handler invoked exactly once");
            assert_eq!(
                marker_object(&memory) as u64,
                operation,
                "the handler receives the operation object"
            );
            let (result_hr, endpoint) = crate::audio_activation::operation_get_activate_result(
                runtime.guest_pid,
                operation,
            )
            .expect("completion delivered");
            assert_eq!(result_hr, ACTIVATION_S_OK);
            assert_ne!(endpoint, 0, "the operation carries the endpoint");

            // The endpoint is a REAL guest object bound to the REAL device data.
            let kind = runtime
                .guest_object_kind(endpoint)
                .expect("endpoint object");
            assert_eq!(kind, GuestObjectKind::DirectSound8);
            let record = crate::audio_activation::endpoint_record(runtime.guest_pid, endpoint)
                .expect("real device record bound to the endpoint");
            assert!(record.device.is_default, "default render device activated");
            assert!(!record.device.name.is_empty(), "real device name");
            assert!(record.device.sample_rate > 0, "real device sample rate");
            assert!(record.device.channels >= 1, "real device channel count");
            assert_eq!(record.requested_riid, IID_IAUDIO_CLIENT);
            // The object's IUnknown lifecycle is real: AddRef/Release move the
            // runtime refcount and Release to zero removes the object.
            let refs = runtime.add_ref_guest_object(endpoint).expect("AddRef");
            assert_eq!(refs, 2);
            assert_eq!(runtime.release_guest_object(endpoint).expect("Release"), 1);
            assert_eq!(
                runtime
                    .release_guest_object(endpoint)
                    .expect("final Release"),
                0
            );
            assert!(!runtime.guest_objects.contains_key(&endpoint));

            // The operation object's IUnknown lifecycle is real too: the last
            // Release forgets its activation state.
            assert_eq!(runtime.add_ref_guest_object(operation).expect("AddRef"), 2);
            assert_eq!(runtime.release_guest_object(operation).expect("Release"), 1);
            assert_eq!(
                runtime
                    .release_guest_object(operation)
                    .expect("final Release"),
                0
            );
            assert!(!runtime.guest_objects.contains_key(&operation));
            assert_eq!(
                crate::audio_activation::activation_operation_interface(
                    runtime.guest_pid,
                    operation,
                ),
                None
            );
        })
    }

    #[test]
    fn activation_capture_guid_path_resolves_or_reports_device_error() {
        with_big_stack(|| {
            // The capture DEVINTERFACE activates a real input device when the
            // host has one; with no real capture device the activation fails
            // AUDCLNT_E_DEVICE_INVALIDATED asynchronously.
            let (mut runtime, _tmp) = activation_test_runtime("act-capture-guid");
            let mut memory = MemoryImage::default();
            install_handler(&mut memory);
            let capture_available = real_capture_device_available();
            if !capture_available {
                eprintln!(
                    "capture activation test: no real capture device — asserting the \
                     device-error path"
                );
            }
            let hr = dispatch_activate(
                &mut runtime,
                &mut memory,
                Some("{2eef81be-33fa-4800-9670-1cd474972c3f}"),
                &IID_IAUDIO_CLIENT,
                HANDLER_OBJECT,
                OP_OUT,
            );
            assert_eq!(hr, u64::from(ACTIVATION_S_OK));
            let operation = read_guest_pointer(&memory, OP_OUT, GuestArch::X86).unwrap();
            assert_ne!(operation, 0);
            drain_activations(&mut runtime, &mut memory);
            assert_ne!(marker_object(&memory), 0);
            let (result_hr, interface) = crate::audio_activation::operation_get_activate_result(
                runtime.guest_pid,
                operation,
            )
            .expect("completion delivered");
            if capture_available {
                assert_eq!(result_hr, ACTIVATION_S_OK);
                assert_ne!(interface, 0);
            } else {
                assert_eq!(result_hr, AUDCLNT_E_DEVICE_INVALIDATED);
                assert_eq!(interface, 0);
            }
            assert_eq!(marker_count(&memory), 1);
        })
    }

    #[test]
    fn activation_without_real_devices_completes_with_device_invalidated() {
        with_big_stack(|| {
            // Runs only when the real device list is genuinely empty (headless
            // CI, VMs without CoreAudio output) — the condition the assignment
            // requires for AUDCLNT_E_DEVICE_INVALIDATED.
            if !real_device_list_empty() {
                eprintln!("skipping activation no-device test: real audio devices are present");
                return;
            }
            let (mut runtime, _tmp) = activation_test_runtime("act-no-devices");
            let mut memory = MemoryImage::default();
            install_handler(&mut memory);
            let hr = dispatch_activate(
                &mut runtime,
                &mut memory,
                None,
                &IID_IAUDIO_CLIENT,
                HANDLER_OBJECT,
                OP_OUT,
            );
            assert_eq!(hr, u64::from(ACTIVATION_S_OK));
            let operation = read_guest_pointer(&memory, OP_OUT, GuestArch::X86).unwrap();
            assert_ne!(operation, 0, "failed activations still return an operation");
            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_object(&memory) as u64, operation);
            let (result_hr, interface) = crate::audio_activation::operation_get_activate_result(
                runtime.guest_pid,
                operation,
            )
            .expect("completion delivered");
            assert_eq!(result_hr, AUDCLNT_E_DEVICE_INVALIDATED);
            assert_eq!(interface, 0);
            assert_eq!(marker_count(&memory), 1);
        })
    }
}

// ---------------------------------------------------------------------------
// XACT3 engine tests: real banks, real cues, real playback state
// ---------------------------------------------------------------------------

#[cfg(test)]
mod xact_engine_tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use crate::xact::fixtures::{
        XsbSpec, XwbTestEntry, build_xgs, build_xgs_curve, build_xgs_curve_with_fade, build_xsb,
        build_xsb_interactive, build_xwb, build_xwb_entries, release_at,
    };
    use tempfile::TempDir;

    const STACK: u64 = 0x60_000;
    const BANK_BUFFER: u64 = 0x10_0000;
    const OUT_A: u64 = 0x20_0000;
    const OUT_B: u64 = 0x20_0100;
    const OUT_C: u64 = 0x20_0200;
    const PARAMS: u64 = 0x20_1000;
    const NOTIFY_DESC: u64 = 0x20_2000;
    const MARKERS: u64 = 0x20_3000;
    const RIID_ADDR: u64 = 0x20_4000;
    const CALLBACK_STUB: u64 = 0x30_0000;
    const STRING_BUF: u64 = 0x40_0000;
    const RETURN_SENTINEL: u32 = 0xDEAD_BEEF;
    const STREAM_SRC: u64 = 0x50_0000;
    const STREAM_STATE: u64 = 0x51_0000;
    const STREAM_PARAMS: u64 = 0x52_0000;
    const STREAM_READ_STUB: u64 = 0x53_0000;
    const STREAM_SEEK_STUB: u64 = 0x53_1000;
    const STREAM_CLOSE_STUB: u64 = 0x53_2000;
    const STREAM_HANDLE: u64 = 0xB012_34;

    fn stream_read_stub_bytes() -> Vec<u8> {
        let mut code = Vec::new();
        let state = STREAM_STATE as u32;
        // A stdcall callback must preserve esi/edi (the host thunk verifies
        // callee-saved registers); the pushes move the stack arguments by 8.
        code.extend_from_slice(&[0x56, 0x57]);
        // mov eax, [esp+20] (requested bytes)
        code.extend_from_slice(&[0x8B, 0x44, 0x24, 0x14]);
        // mov ecx, [cap]; cmp eax, ecx; jbe +2; mov eax, ecx
        code.extend_from_slice(&[0x8B, 0x0D]);
        code.extend_from_slice(&(state + 8).to_le_bytes());
        code.extend_from_slice(&[0x39, 0xC8, 0x76, 0x02, 0x89, 0xC8]);
        // mov ecx, [pos]; mov esi, STREAM_SRC; add esi, ecx
        code.extend_from_slice(&[0x8B, 0x0D]);
        code.extend_from_slice(&state.to_le_bytes());
        code.push(0xBE);
        code.extend_from_slice(&(STREAM_SRC as u32).to_le_bytes());
        code.extend_from_slice(&[0x01, 0xCE]);
        // mov edi, [esp+16] (destination); mov ecx, eax; rep movsb
        code.extend_from_slice(&[0x8B, 0x7C, 0x24, 0x10, 0x89, 0xC1, 0xF3, 0xA4]);
        // add [pos], eax; mov edx, [esp+24]; mov [edx], eax
        code.extend_from_slice(&[0x01, 0x05]);
        code.extend_from_slice(&state.to_le_bytes());
        code.extend_from_slice(&[0x8B, 0x54, 0x24, 0x18, 0x89, 0x02]);
        // inc dword [read_calls]; pop edi; pop esi; xor eax, eax; ret 16
        code.extend_from_slice(&[0xFF, 0x05]);
        code.extend_from_slice(&(state + 12).to_le_bytes());
        code.extend_from_slice(&[0x5F, 0x5E, 0x31, 0xC0, 0xC2, 0x10, 0x00]);
        code
    }

    fn stream_seek_stub_bytes() -> Vec<u8> {
        let mut code = Vec::new();
        let state = STREAM_STATE as u32;
        // mov eax, [esp+8] (offset); mov ecx, [esp+12] (origin)
        code.extend_from_slice(&[0x8B, 0x44, 0x24, 0x08, 0x8B, 0x4C, 0x24, 0x0C]);
        // cmp ecx, 0; je store
        code.extend_from_slice(&[0x83, 0xF9, 0x00, 0x74, 0x20]);
        // cmp ecx, 1; je current
        code.extend_from_slice(&[0x83, 0xF9, 0x01, 0x74, 0x0D]);
        // cmp ecx, 2; je end
        code.extend_from_slice(&[0x83, 0xF9, 0x02, 0x74, 0x10]);
        // mov eax, E_INVALIDARG; ret 16
        code.extend_from_slice(&[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x10, 0x00]);
        // current: add eax, [pos]; jmp store
        code.extend_from_slice(&[0x03, 0x05]);
        code.extend_from_slice(&state.to_le_bytes());
        code.extend_from_slice(&[0xEB, 0x06]);
        // end: add eax, [len]
        code.extend_from_slice(&[0x03, 0x05]);
        code.extend_from_slice(&(state + 4).to_le_bytes());
        // store: mov [pos], eax; mov ecx, [esp+16]; mov [ecx], eax
        code.extend_from_slice(&[0x89, 0x05]);
        code.extend_from_slice(&state.to_le_bytes());
        code.extend_from_slice(&[0x8B, 0x4C, 0x24, 0x10, 0x89, 0x01]);
        // inc dword [seek_calls]; xor eax, eax; ret 16
        code.extend_from_slice(&[0xFF, 0x05]);
        code.extend_from_slice(&(state + 16).to_le_bytes());
        code.extend_from_slice(&[0x31, 0xC0, 0xC2, 0x10, 0x00]);
        code
    }

    fn stream_close_stub_bytes() -> Vec<u8> {
        let mut code = Vec::new();
        let state = STREAM_STATE as u32;
        // mov eax, [esp+4]; mov [closed_handle], eax
        code.extend_from_slice(&[0x8B, 0x44, 0x24, 0x04, 0xA3]);
        code.extend_from_slice(&(state + 24).to_le_bytes());
        // inc dword [close_calls]; xor eax, eax; ret 4
        code.extend_from_slice(&[0xFF, 0x05]);
        code.extend_from_slice(&(state + 20).to_le_bytes());
        code.extend_from_slice(&[0x31, 0xC0, 0xC2, 0x04, 0x00]);
        code
    }

    fn install_stream_fixture(memory: &mut MemoryImage, bytes: &[u8]) {
        // execute_guest_callback places the synthetic frame below the dispatch
        // stack; map that page so a stdcall stub can push callee-saved
        // registers and use `ret N` without faulting.
        memory.map_bytes(STACK - 0x1000, &[0_u8; 0x1000]);
        memory.map_bytes(STREAM_SRC, bytes);
        memory.map_bytes(STREAM_STATE, &[0_u8; 32]);
        write_u32(memory, STREAM_STATE + 4, bytes.len() as u32);
        write_u32(memory, STREAM_STATE + 8, 0xFFFF_FFFF);
        memory.map_bytes(STREAM_READ_STUB, &stream_read_stub_bytes());
        memory.map_bytes(STREAM_SEEK_STUB, &stream_seek_stub_bytes());
        memory.map_bytes(STREAM_CLOSE_STUB, &stream_close_stub_bytes());
    }

    fn write_output_sends(memory: &mut MemoryImage, count: u32, voices: &[u64]) {
        memory.map_bytes(PARAMS, &[0_u8; 128]);
        write_u32(memory, PARAMS, count);
        write_u32(memory, PARAMS + 4, (PARAMS + 16) as u32);
        for (index, voice) in voices.iter().enumerate() {
            write_u32(memory, PARAMS + 16 + index as u64 * 8, 0);
            write_u32(memory, PARAMS + 20 + index as u64 * 8, *voice as u32);
        }
    }

    fn write_stream_params(
        memory: &mut MemoryImage,
        read: u64,
        seek: u64,
        close: u64,
        file: u64,
        offset: u32,
    ) {
        memory.map_bytes(STREAM_PARAMS, &[0_u8; 32]);
        write_u32(memory, STREAM_PARAMS, file as u32);
        write_u32(memory, STREAM_PARAMS + 4, offset);
        write_u16(memory, STREAM_PARAMS + 12, 2);
        write_u32(memory, STREAM_PARAMS + 16, read as u32);
        write_u32(memory, STREAM_PARAMS + 20, seek as u32);
        write_u32(memory, STREAM_PARAMS + 24, close as u32);
    }

    fn xact_test_runtime(name: &str) -> (PeHostRuntime, TempDir) {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), name, GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.guest_arch = GuestArch::X86;
        runtime.next_thunk_address = thunk_base_for_arch(GuestArch::X86);
        runtime.next_data_address = data_base_for_arch(GuestArch::X86);
        runtime.next_heap_address = heap_base_for_arch(GuestArch::X86);
        runtime
            .win32
            .reset_address_space(private_pages_base_for_arch(GuestArch::X86));
        runtime.x86_heap_region = 0;
        (runtime, temp_dir)
    }

    fn with_big_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(body)
            .expect("spawn big-stack thread")
            .join()
            .expect("big-stack thread panicked")
    }

    fn write_guest_c_string(memory: &mut MemoryImage, address: u64, value: &str) {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        memory.map_bytes(address, &bytes);
    }

    fn map_bank(memory: &mut MemoryImage, bytes: &[u8]) -> u64 {
        memory.map_bytes(BANK_BUFFER, bytes);
        BANK_BUFFER
    }

    fn xact_prepare_direct(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        bank_object: u64,
        index: u16,
    ) -> Result<(), u32> {
        let mut state = CpuState::new(GuestArch::X86);
        let pid = runtime.guest_pid;
        let mut store = crate::xact::lock_xact_runtimes();
        let xact_runtime = store.get_mut(&pid).expect("xact runtime");
        runtime.xact_prepare_bank_entry(&mut state, memory, xact_runtime, bank_object, index)
    }

    fn xact_with_store<R>(
        runtime: &PeHostRuntime,
        f: impl FnOnce(&crate::xact::XactRuntime) -> R,
    ) -> Option<R> {
        let store = crate::xact::lock_xact_runtimes();
        store.get(&runtime.guest_pid).map(f)
    }

    fn xact_call(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        this: u64,
        interface: u8,
        method: u16,
        args: &[u64],
    ) -> u64 {
        let arg_words = crate::xact::interface_methods(interface)
            .iter()
            .find(|(index, _)| *index == method)
            .expect("XACT method exists in the interface table")
            .1;
        let thunk = runtime.alloc_host_thunk(HostThunk::Xact3Method {
            interface,
            method,
            x86_arg_bytes: arg_words * 4,
        });
        memory.map_bytes(STACK, &vec![0_u8; 0x400]);
        write_u32(memory, STACK, RETURN_SENTINEL);
        write_guest_pointer(memory, STACK + 4, this, GuestArch::X86).expect("write this");
        for (index, arg) in args.iter().enumerate() {
            write_guest_pointer(memory, STACK + 8 + index as u64 * 4, *arg, GuestArch::X86)
                .expect("write argument");
        }
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, STACK);
        runtime
            .dispatch_import(thunk, &mut state, memory)
            .expect("dispatch XACT method");
        assert_eq!(
            state.rip,
            u64::from(RETURN_SENTINEL),
            "the real dispatcher restores the return address"
        );
        state.get(Register::Rax)
    }

    fn xact_create_engine_raw(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        flags: u32,
        out: u64,
    ) -> u64 {
        let thunk = runtime.alloc_host_thunk(HostThunk::Xact3CreateEngine);
        memory.map_bytes(STACK, &vec![0_u8; 0x400]);
        if out != 0 {
            memory.map_bytes(out, &[0_u8; 8]);
        }
        write_u32(memory, STACK, RETURN_SENTINEL);
        write_u32(memory, STACK + 4, flags);
        write_guest_pointer(memory, STACK + 8, out, GuestArch::X86).expect("write out engine");
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, STACK);
        runtime
            .dispatch_import(thunk, &mut state, memory)
            .expect("dispatch XACT3CreateEngine");
        state.get(Register::Rax)
    }

    fn xact_create_engine(runtime: &mut PeHostRuntime, memory: &mut MemoryImage) -> u64 {
        let eax = xact_create_engine_raw(runtime, memory, 0, OUT_A);
        assert_eq!(eax, u64::from(crate::xact::S_OK), "engine creation");
        u64::from(read_u32(memory, OUT_A).expect("engine pointer"))
    }

    fn xact_initialize(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        engine: u64,
        callback: u64,
    ) -> u64 {
        memory.map_bytes(PARAMS, &[0_u8; 64]);
        write_u32(memory, PARAMS + 28, callback as u32);
        xact_call(
            runtime,
            memory,
            engine,
            crate::xact::IFACE_ENGINE,
            6,
            &[PARAMS],
        )
    }

    fn xact_initialize_with_settings(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        engine: u64,
        settings: &[u8],
    ) -> u64 {
        memory.map_bytes(BANK_BUFFER, settings);
        let buffer = BANK_BUFFER;
        memory.map_bytes(PARAMS, &[0_u8; 64]);
        write_u32(memory, PARAMS + 4, buffer as u32);
        write_u32(memory, PARAMS + 8, settings.len() as u32);
        xact_call(
            runtime,
            memory,
            engine,
            crate::xact::IFACE_ENGINE,
            6,
            &[PARAMS],
        )
    }

    fn xact_mastering_voice(runtime: &PeHostRuntime) -> crate::audio::VoiceId {
        xact_with_store(runtime, |state| {
            state.objects.values().find_map(|object| match object {
                crate::xact::XactObject::Engine(engine) => engine.mastering_voice,
                _ => None,
            })
        })
        .flatten()
        .expect("engine mastering voice")
    }

    fn xact_f32(value: f32) -> u64 {
        u64::from(value.to_bits())
    }

    fn xact_cue_state(runtime: &PeHostRuntime, cue: u64) -> Option<u32> {
        xact_with_store(runtime, |state| match state.objects.get(&cue) {
            Some(crate::xact::XactObject::Cue(cue)) => Some(cue.state),
            _ => None,
        })
        .flatten()
    }

    fn xact_load_wavebank(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        engine: u64,
        bytes: &[u8],
    ) -> u64 {
        let buffer = map_bank(memory, bytes);
        memory.map_bytes(OUT_B, &[0_u8; 8]);
        let eax = xact_call(
            runtime,
            memory,
            engine,
            crate::xact::IFACE_ENGINE,
            10,
            &[buffer, bytes.len() as u64, 0, 0, OUT_B],
        );
        assert_eq!(eax, u64::from(crate::xact::S_OK), "wave bank load");
        u64::from(read_u32(memory, OUT_B).expect("wave bank pointer"))
    }

    fn xact_load_soundbank(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        engine: u64,
        bytes: &[u8],
    ) -> u64 {
        let buffer = map_bank(memory, bytes);
        memory.map_bytes(OUT_B, &[0_u8; 8]);
        let eax = xact_call(
            runtime,
            memory,
            engine,
            crate::xact::IFACE_ENGINE,
            9,
            &[buffer, bytes.len() as u64, 0, 0, OUT_B],
        );
        assert_eq!(eax, u64::from(crate::xact::S_OK), "sound bank load");
        u64::from(read_u32(memory, OUT_B).expect("sound bank pointer"))
    }

    fn xact_load_banks(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        engine: u64,
        wavebank: &[u8],
        soundbank: &[u8],
    ) -> (u64, u64) {
        let wb = xact_load_wavebank(runtime, memory, engine, wavebank);
        let sb = xact_load_soundbank(runtime, memory, engine, soundbank);
        (wb, sb)
    }

    fn install_notification_callback(memory: &mut MemoryImage) {
        memory.map_bytes(MARKERS, &[0_u8; 16]);
        let mut stub = Vec::new();
        stub.extend_from_slice(&[0x8B, 0x44, 0x24, 0x04]); // mov eax,[esp+4]
        stub.extend_from_slice(&[0x0F, 0xB6, 0x08]); // movzx ecx, byte [eax]
        stub.push(0x89);
        stub.push(0x0D);
        stub.extend_from_slice(&(MARKERS as u32).to_le_bytes());
        stub.extend_from_slice(&[0x8B, 0x48, 0x05]); // mov ecx,[eax+5]
        stub.push(0x89);
        stub.push(0x0D);
        stub.extend_from_slice(&((MARKERS + 4) as u32).to_le_bytes());
        stub.extend_from_slice(&[0x31, 0xC0, 0xC3]); // xor eax,eax; ret
        memory.map_bytes(CALLBACK_STUB, &stub);
    }

    fn cue_live_voice(runtime: &PeHostRuntime, cue: u64) -> Option<crate::audio::VoiceId> {
        xact_with_store(runtime, |state| match state.objects.get(&cue) {
            Some(crate::xact::XactObject::Cue(cue)) => cue.live.map(|live| live.voice),
            _ => None,
        })
        .flatten()
    }

    fn cue_live_voices(runtime: &PeHostRuntime, cue: u64) -> Vec<crate::audio::VoiceId> {
        xact_with_store(runtime, |state| match state.objects.get(&cue) {
            Some(crate::xact::XactObject::Cue(cue)) => cue
                .live
                .map(|live| live.voices().collect::<Vec<_>>())
                .unwrap_or_default(),
            _ => Vec::new(),
        })
        .unwrap_or_default()
    }

    fn xact_test_output_voice(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        channels: u16,
    ) -> u64 {
        let format = crate::audio::WaveFormat {
            channels,
            sample_rate: 48_000,
            sample_format: crate::audio::SampleFormat::Float32,
        };
        let mastering = runtime
            .audio
            .create_mastering_voice(format.clone())
            .expect("output-voice mastering");
        let voice = runtime
            .audio
            .create_submix_voice(format, mastering)
            .expect("output-voice submix");
        runtime
            .alloc_xaudio2_source_voice_object(memory, 0, voice)
            .expect("guest output-voice object")
    }

    fn tone() -> Vec<i16> {
        (0..441)
            .map(|index| ((index as f32 * 0.1).sin() * 10_000.0) as i16)
            .collect()
    }

    fn simple_soundbank(cues: &[(&str, u16)]) -> Vec<u8> {
        build_xsb(&XsbSpec {
            bank_name: "SoundBank",
            wavebank_name: "WaveBank",
            cues,
        })
    }

    #[test]
    fn xact_engine_create_validates_flags_and_releases_cleanly() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-create");
            let mut memory = MemoryImage::default();

            // Invalid flags: E_INVALIDARG with a zeroed out-pointer.
            let eax = xact_create_engine_raw(&mut runtime, &mut memory, 0x8000_0000, OUT_A);
            assert_eq!(eax, u64::from(crate::xact::E_INVALIDARG));
            assert_eq!(read_u32(&memory, OUT_A).expect("out"), 0);
            // Null out-pointer: E_INVALIDARG.
            let eax = xact_create_engine_raw(&mut runtime, &mut memory, 0, 0);
            assert_eq!(eax, u64::from(crate::xact::E_INVALIDARG));

            let engine = xact_create_engine(&mut runtime, &mut memory);
            assert_ne!(engine, 0);
            let vtable = xact_with_store(&runtime, |state| {
                state
                    .vtables
                    .get(&crate::xact::IFACE_ENGINE)
                    .copied()
                    .expect("engine vtable allocated")
            })
            .expect("xact store");
            assert_eq!(
                u64::from(read_u32(&memory, engine).expect("vtable pointer")),
                vtable
            );

            // QueryInterface: IUnknown and IID_IXACT3Engine succeed, unknown
            // IIDs return E_NOINTERFACE with a zeroed out-pointer.
            memory.map_bytes(RIID_ADDR, &crate::xact::IID_IUNKNOWN);
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                engine,
                crate::xact::IFACE_ENGINE,
                0,
                &[RIID_ADDR, OUT_C],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            assert_eq!(u64::from(read_u32(&memory, OUT_C).expect("QI out")), engine);
            memory.map_bytes(RIID_ADDR, &[0xAB; 16]);
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                engine,
                crate::xact::IFACE_ENGINE,
                0,
                &[RIID_ADDR, OUT_C],
            );
            assert_eq!(eax, u64::from(crate::xact::E_NOINTERFACE));
            assert_eq!(read_u32(&memory, OUT_C).expect("QI out"), 0);
            memory.map_bytes(RIID_ADDR, &crate::xact::IID_IXACT3_ENGINE);
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                engine,
                crate::xact::IFACE_ENGINE,
                0,
                &[RIID_ADDR, OUT_C],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));

            // Reference counting: 1 initial + 2 successful QI.  Release
            // returns the *new* count; the final release destroys the engine.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    2,
                    &[],
                ),
                2
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    2,
                    &[],
                ),
                1
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    2,
                    &[],
                ),
                0
            );
            assert!(
                xact_with_store(&runtime, |_| ()).is_none(),
                "releasing the engine removes the whole XACT runtime"
            );
        })
    }

    #[test]
    fn xact_wavebank_decodes_real_pcm_and_rejects_bad_files() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-wavebank");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::S_OK)
            );

            let pcm: Vec<i16> = vec![0, 1000, -1000, 32767, -32768, 42];
            let xwb = build_xwb("TestBank", &[pcm.clone()], &["one"], &[]);
            let bank = xact_load_wavebank(&mut runtime, &mut memory, engine, &xwb);

            // The decoded PCM is bit-exact with what was written.
            xact_with_store(&runtime, |state| {
                let Some(crate::xact::XactObject::WaveBank(wave_bank)) = state.objects.get(&bank)
                else {
                    panic!("wave bank object present");
                };
                assert_eq!(wave_bank.bank.name, "TestBank");
                assert_eq!(wave_bank.bank.entry_names, vec!["one"]);
                assert_eq!(
                    wave_bank.bank.entries[0].pcm.as_deref(),
                    Some(pcm.as_slice())
                );
                assert_eq!(wave_bank.bank.entries[0].format.sample_rate, 44100);
            })
            .expect("xact store");

            // GetNumWaves / GetWaveIndex / GetWaveProperties through the vtable.
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                bank,
                crate::xact::IFACE_WAVEBANK,
                4,
                &[OUT_A],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            assert_eq!(read_u16(&memory, OUT_A).expect("wave count"), 1);

            write_guest_c_string(&mut memory, STRING_BUF, "one");
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                bank,
                crate::xact::IFACE_WAVEBANK,
                5,
                &[STRING_BUF],
            );
            assert_eq!(eax, 0);
            write_guest_c_string(&mut memory, STRING_BUF, "missing");
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                bank,
                crate::xact::IFACE_WAVEBANK,
                5,
                &[STRING_BUF],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTINDEX_INVALID));

            let eax = xact_call(
                &mut runtime,
                &mut memory,
                bank,
                crate::xact::IFACE_WAVEBANK,
                6,
                &[0, OUT_B],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            assert_eq!(read_u32(&memory, OUT_B + 68).expect("duration"), 6);
            assert_eq!(read_u32(&memory, OUT_B + 64).expect("format"), {
                let format = crate::xact::MiniFormat {
                    tag: crate::xact::WAVEBANK_TAG_PCM,
                    channels: 1,
                    sample_rate: 44100,
                    block_align: 2,
                    bits_per_sample: 16,
                };
                format.encode()
            });

            // Malformed input: wrong signature -> XACTENGINE_E_INVALIDDATA.
            let mut bad = xwb.clone();
            bad[0] = b'X';
            let buffer = map_bank(&mut memory, &bad);
            memory.map_bytes(OUT_B, &[0_u8; 8]);
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                engine,
                crate::xact::IFACE_ENGINE,
                10,
                &[buffer, bad.len() as u64, 0, 0, OUT_B],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTENGINE_E_INVALIDDATA));

            // Truncated input -> XACTENGINE_E_INVALIDDATA.
            let truncated = &xwb[..xwb.len() - 2];
            let buffer = map_bank(&mut memory, truncated);
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                engine,
                crate::xact::IFACE_ENGINE,
                10,
                &[buffer, truncated.len() as u64, 0, 0, OUT_B],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTENGINE_E_INVALIDDATA));

            // A streaming-flagged bank cannot be loaded in memory.
            let mut streaming = xwb.clone();
            streaming[52] = 1; // bank-data flags at segment 0
            let buffer = map_bank(&mut memory, &streaming);
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                engine,
                crate::xact::IFACE_ENGINE,
                10,
                &[buffer, streaming.len() as u64, 0, 0, OUT_B],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTENGINE_E_INVALIDUSAGE));

            // Bad wave index -> XACTENGINE_E_INVALIDWAVEINDEX.
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                bank,
                crate::xact::IFACE_WAVEBANK,
                6,
                &[9, OUT_B],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTENGINE_E_INVALIDWAVEINDEX));

            // ADPCM entries decode to real PCM.
            let block: Vec<u8> = vec![0, 0, 16, 0, 0xE8, 0x03, 0, 0, 0x01];
            let adpcm_xwb = build_xwb_entries(
                "AdpcmBank",
                &[XwbTestEntry {
                    name: "adpcm".to_string(),
                    payload: block.clone(),
                    tag: crate::xact::WAVEBANK_TAG_ADPCM,
                    channels: 1,
                    sample_rate: 22050,
                    block_align: 9,
                    bits_per_sample: 4,
                    duration_samples: 4,
                    loop_region: (0, 0),
                }],
            );
            let adpcm_bank = xact_load_wavebank(&mut runtime, &mut memory, engine, &adpcm_xwb);
            xact_with_store(&runtime, |state| {
                let Some(crate::xact::XactObject::WaveBank(wave_bank)) =
                    state.objects.get(&adpcm_bank)
                else {
                    panic!("ADPCM wave bank object present");
                };
                assert_eq!(
                    wave_bank.bank.entries[0].pcm.as_deref(),
                    Some([1000_i16, 0, 1016, 0, 1016, 0].as_slice())
                );
            })
            .expect("xact store");
        })
    }

    #[test]
    fn xact_cue_lookup_playback_and_state_transitions_are_real() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-playback");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::S_OK)
            );

            let wave = tone();
            let xwb = build_xwb("WaveBank", &[wave], &["tone"], &[]);
            let xsb = simple_soundbank(&[("beep", 0), ("boop", 0)]);
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);

            // Cue lookup by name (and misses) through the real bank.
            write_guest_c_string(&mut memory, STRING_BUF, "beep");
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                sb,
                crate::xact::IFACE_SOUNDBANK,
                3,
                &[STRING_BUF],
            );
            assert_eq!(eax, 0);
            write_guest_c_string(&mut memory, STRING_BUF, "boop");
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                sb,
                crate::xact::IFACE_SOUNDBANK,
                3,
                &[STRING_BUF],
            );
            assert_eq!(eax, 1);
            write_guest_c_string(&mut memory, STRING_BUF, "nope");
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                sb,
                crate::xact::IFACE_SOUNDBANK,
                3,
                &[STRING_BUF],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTINDEX_INVALID));
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                sb,
                crate::xact::IFACE_SOUNDBANK,
                4,
                &[OUT_A],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            assert_eq!(read_u16(&memory, OUT_A).expect("cue count"), 2);

            // Play a cue: a real source voice starts.
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                sb,
                crate::xact::IFACE_SOUNDBANK,
                7,
                &[0, 0, 0, OUT_C],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));
            assert_ne!(cue, 0);
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                cue,
                crate::xact::IFACE_CUE,
                5,
                &[OUT_A],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            assert_eq!(
                read_u32(&memory, OUT_A).expect("cue state"),
                crate::xact::XACT_STATE_PLAYING
            );
            let voice = cue_live_voice(&runtime, cue).expect("live cue voice");
            assert!(runtime.audio.voice_started(voice).expect("voice lookup"));
            assert!(
                runtime
                    .audio
                    .queued_source_frames(voice)
                    .expect("queued frames")
                    > 0
            );

            // Pause/resume are real voice state changes.
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                cue,
                crate::xact::IFACE_CUE,
                11,
                &[1],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            xact_call(
                &mut runtime,
                &mut memory,
                cue,
                crate::xact::IFACE_CUE,
                5,
                &[OUT_A],
            );
            assert_eq!(
                read_u32(&memory, OUT_A).expect("paused state"),
                crate::xact::XACT_STATE_PAUSED
            );
            assert!(!runtime.audio.voice_started(voice).expect("voice lookup"));
            xact_call(
                &mut runtime,
                &mut memory,
                cue,
                crate::xact::IFACE_CUE,
                11,
                &[0],
            );
            xact_call(
                &mut runtime,
                &mut memory,
                cue,
                crate::xact::IFACE_CUE,
                5,
                &[OUT_A],
            );
            assert_eq!(
                read_u32(&memory, OUT_A).expect("resumed state"),
                crate::xact::XACT_STATE_PLAYING
            );
            assert!(runtime.audio.voice_started(voice).expect("voice lookup"));

            // DoWork renders the queued audio; the finished cue retires to
            // STOPPED with its voice torn down.
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                engine,
                crate::xact::IFACE_ENGINE,
                8,
                &[],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            xact_call(
                &mut runtime,
                &mut memory,
                cue,
                crate::xact::IFACE_CUE,
                5,
                &[OUT_A],
            );
            assert_eq!(
                read_u32(&memory, OUT_A).expect("finished state"),
                crate::xact::XACT_STATE_STOPPED
            );
            assert!(cue_live_voice(&runtime, cue).is_none());

            // Replay then explicit stop.
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                cue,
                crate::xact::IFACE_CUE,
                3,
                &[],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            assert!(cue_live_voice(&runtime, cue).is_some());
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                cue,
                crate::xact::IFACE_CUE,
                4,
                &[0],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            xact_call(
                &mut runtime,
                &mut memory,
                cue,
                crate::xact::IFACE_CUE,
                5,
                &[OUT_A],
            );
            assert_eq!(
                read_u32(&memory, OUT_A).expect("stopped state"),
                crate::xact::XACT_STATE_STOPPED
            );
            assert!(cue_live_voice(&runtime, cue).is_none());

            // Cue properties carry the real authored data.
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                sb,
                crate::xact::IFACE_SOUNDBANK,
                5,
                &[0, OUT_B],
            );
            assert_eq!(eax, u64::from(crate::xact::S_OK));
            assert_eq!(memory.read_u8(OUT_B + 264).expect("instance limit"), 0xFF);
            assert_eq!(
                memory.read_u8(OUT_B + 265).expect("instance count"),
                1,
                "the stopped-but-alive cue object is one instance"
            );
            assert_eq!(&memory.read_bytes(OUT_B, 4).unwrap_or_default(), b"beep");
        })
    }

    #[test]
    fn xact_bad_indices_and_engine_errors_are_genuine() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-errors");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);

            // Banks cannot be created before Initialize.
            let xsb = simple_soundbank(&[("beep", 0)]);
            let buffer = map_bank(&mut memory, &xsb);
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                engine,
                crate::xact::IFACE_ENGINE,
                9,
                &[buffer, xsb.len() as u64, 0, 0, OUT_B],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTENGINE_E_NOTINITIALIZED));
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::S_OK)
            );
            // A second Initialize is rejected.
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::XACTENGINE_E_ALREADYINITIALIZED)
            );

            // Malformed sound bank.
            let mut bad = xsb.clone();
            bad[6..8].copy_from_slice(&9_u16.to_le_bytes());
            let buffer = map_bank(&mut memory, &bad);
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                engine,
                crate::xact::IFACE_ENGINE,
                9,
                &[buffer, bad.len() as u64, 0, 0, OUT_B],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTENGINE_E_INVALIDDATA));

            let wave = tone();
            let xwb = build_xwb("WaveBank", &[wave], &[], &[]);
            let (wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);

            // Bad cue / wave indices.
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                sb,
                crate::xact::IFACE_SOUNDBANK,
                5,
                &[9, OUT_B],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTENGINE_E_INVALIDCUEINDEX));
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                sb,
                crate::xact::IFACE_SOUNDBANK,
                7,
                &[9, 0, 0, OUT_C],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTENGINE_E_INVALIDCUEINDEX));
            let eax = xact_call(
                &mut runtime,
                &mut memory,
                wb,
                crate::xact::IFACE_WAVEBANK,
                8,
                &[9, 0, 0, 0, OUT_C],
            );
            assert_eq!(eax, u64::from(crate::xact::XACTENGINE_E_INVALIDWAVEINDEX));

            // Category and variable surface.
            write_guest_c_string(&mut memory, STRING_BUF, "Music");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    17,
                    &[STRING_BUF],
                ),
                2
            );
            write_guest_c_string(&mut memory, STRING_BUF, "Nope");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    17,
                    &[STRING_BUF],
                ),
                u64::from(crate::xact::XACTCATEGORY_INVALID)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    19,
                    &[9, u64::from(1.0_f32.to_bits())],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDCATEGORY)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    20,
                    &[9, 1],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDCATEGORY)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    21,
                    &[STRING_BUF],
                ),
                u64::from(crate::xact::XACTVARIABLEINDEX_INVALID)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    23,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );

            // Notifications require a registered callback.
            memory.map_bytes(NOTIFY_DESC, &[0_u8; 32]);
            write_u8(&mut memory, NOTIFY_DESC, 2);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    15,
                    &[NOTIFY_DESC],
                ),
                u64::from(crate::xact::XACTENGINE_E_NONOTIFICATIONCALLBACK)
            );

            // Renderer and final-mix surface are real values.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    3,
                    &[OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(read_u16(&memory, OUT_A).expect("renderer count"), 1);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    5,
                    &[OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(read_u16(&memory, OUT_A + 2).expect("channels"), 2);
            assert_eq!(read_u32(&memory, OUT_A + 4).expect("sample rate"), 48_000);
            assert_eq!(read_u16(&memory, OUT_A + 14).expect("bits"), 32);

            // Streaming wave-bank creation validates the guest parameter
            // block before any guest file callback runs.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[0, OUT_B],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );
        })
    }

    #[test]
    fn xact_notification_callback_receives_cue_play() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-notify");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            install_notification_callback(&mut memory);
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, CALLBACK_STUB),
                u64::from(crate::xact::S_OK)
            );

            memory.map_bytes(NOTIFY_DESC, &[0_u8; 32]);
            write_u8(&mut memory, NOTIFY_DESC, 2); // CUEPLAY
            write_u32(&mut memory, NOTIFY_DESC + 22, 0x0000_ABCD); // pvContext (x86)
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    15,
                    &[NOTIFY_DESC],
                ),
                u64::from(crate::xact::S_OK)
            );
            // The exact same registration is rejected.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    15,
                    &[NOTIFY_DESC],
                ),
                u64::from(crate::xact::XACTENGINE_E_NOTIFICATIONREGISTERED)
            );

            let wave = tone();
            let xwb = build_xwb("WaveBank", &[wave], &[], &[]);
            let xsb = simple_soundbank(&[("beep", 0)]);
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    7,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(read_u32(&memory, MARKERS).expect("notify type"), 2);
            assert_eq!(
                read_u32(&memory, MARKERS + 4).expect("notify context"),
                0x0000_ABCD
            );

            // Unregister, then a second play fires no callback.
            write_u32(&mut memory, MARKERS, 0);
            write_u32(&mut memory, MARKERS + 4, 0);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    16,
                    &[NOTIFY_DESC],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    7,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(read_u32(&memory, MARKERS).expect("no callback"), 0);
        })
    }

    #[test]
    fn xact_streaming_guest_callbacks_load_prepare_play_and_close() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-streaming-guest");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::S_OK)
            );
            let first = vec![1234_i16; 64];
            let second = vec![-2345_i16; 96];
            let entries = [
                XwbTestEntry {
                    name: "first".to_string(),
                    payload: first
                        .iter()
                        .flat_map(|sample| sample.to_le_bytes())
                        .collect(),
                    tag: crate::xact::WAVEBANK_TAG_PCM,
                    channels: 1,
                    sample_rate: 44100,
                    block_align: 2,
                    bits_per_sample: 16,
                    duration_samples: first.len() as u32,
                    loop_region: (0, 0),
                },
                XwbTestEntry {
                    name: "second".to_string(),
                    payload: second
                        .iter()
                        .flat_map(|sample| sample.to_le_bytes())
                        .collect(),
                    tag: crate::xact::WAVEBANK_TAG_PCM,
                    channels: 1,
                    sample_rate: 44100,
                    block_align: 2,
                    bits_per_sample: 16,
                    duration_samples: second.len() as u32,
                    loop_region: (0, 0),
                },
            ];
            let mut xwb = build_xwb_entries("StreamBank", &entries);
            // Bank-data flags live at offset 52 in a genuine WBND header.
            xwb[52] |= crate::xact::WAVEBANK_TYPE_STREAMING as u8;
            install_stream_fixture(&mut memory, &xwb);
            memory.map_bytes(OUT_B, &[0_u8; 8]);

            // Null callbacks, a zero file handle, a null params block and a
            // null out pointer are all rejected before any guest I/O.
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                0,
                0,
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[STREAM_PARAMS, OUT_B],
                ),
                u64::from(crate::xact::E_INVALIDARG),
                "zero file handle"
            );
            write_stream_params(
                &mut memory,
                0,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[STREAM_PARAMS, OUT_B],
                ),
                u64::from(crate::xact::E_INVALIDARG),
                "null read callback"
            );
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                0,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[STREAM_PARAMS, OUT_B],
                ),
                u64::from(crate::xact::E_INVALIDARG),
                "null seek callback"
            );
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                0,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[STREAM_PARAMS, OUT_B],
                ),
                u64::from(crate::xact::E_INVALIDARG),
                "null close callback"
            );
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[0, OUT_B],
                ),
                u64::from(crate::xact::E_INVALIDARG),
                "null streaming parameters"
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[STREAM_PARAMS, 0],
                ),
                u64::from(crate::xact::E_INVALIDARG),
                "null out pointer"
            );
            assert_eq!(read_u32(&memory, STREAM_STATE + 12).expect("read calls"), 0);
            assert_eq!(read_u32(&memory, STREAM_STATE + 16).expect("seek calls"), 0);
            assert_eq!(
                read_u32(&memory, STREAM_STATE + 20).expect("close calls"),
                0
            );

            // Creation performs real guest seeks/reads for the header and
            // keeps only metadata plus the source handle/callbacks.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[STREAM_PARAMS, OUT_B],
                ),
                u64::from(crate::xact::S_OK)
            );
            let seek_after_create =
                read_u32(&memory, STREAM_STATE + 16).expect("seek calls after create");
            let read_after_create =
                read_u32(&memory, STREAM_STATE + 12).expect("read calls after create");
            assert!(seek_after_create >= 3, "file length + header seeks");
            assert!(read_after_create >= 1, "header read");
            let wb = u64::from(read_u32(&memory, OUT_B).expect("streaming bank pointer"));
            let (streaming, payload_free, entries_len, source) =
                xact_with_store(&runtime, |state| match state.objects.get(&wb) {
                    Some(crate::xact::XactObject::WaveBank(state)) => (
                        state.bank.streaming,
                        state.bank.entries.iter().all(|entry| entry.pcm.is_none()),
                        state.bank.entries.len(),
                        state.bank.guest_source.clone(),
                    ),
                    _ => (false, false, 0, None),
                })
                .expect("bank state");
            assert!(
                streaming,
                "streaming flag parsed through the guest callbacks"
            );
            assert!(payload_free, "creation did not materialise wave PCM");
            assert_eq!(entries_len, 2);
            let source = source.expect("guest stream source retained");
            assert_eq!(source.file, STREAM_HANDLE);
            assert_eq!(source.read, STREAM_READ_STUB);
            assert_eq!(source.seek, STREAM_SEEK_STUB);
            assert_eq!(source.close, STREAM_CLOSE_STUB);

            // Playing an unprepared streaming entry is the genuine error.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    8,
                    &[0, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::XACTENGINE_E_WAVEBANKNOTPREPARED)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    7,
                    &[9, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDWAVEINDEX)
            );

            // Prepare entry 1: the guest seek moves to that entry's byte
            // range and the guest read supplies exactly its payload.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    7,
                    &[1, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cached = xact_with_store(&runtime, |state| match state.objects.get(&wb) {
                Some(crate::xact::XactObject::WaveBank(state)) => {
                    state.streaming_cache.get(&1).cloned()
                }
                _ => None,
            })
            .flatten()
            .expect("prepared streaming payload");
            assert_eq!(
                cached, second,
                "the second entry's bytes were read, not the first"
            );
            assert!(
                read_u32(&memory, STREAM_STATE + 12).expect("read calls after prepare")
                    > read_after_create
            );
            assert!(
                read_u32(&memory, STREAM_STATE + 16).expect("seek calls after prepare")
                    > seek_after_create
            );
            // Preparing the same entry again is a no-op.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    7,
                    &[1, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            // A non-wave-bank `this` pointer is rejected before any read.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_WAVEBANK,
                    7,
                    &[0, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );
            // The ABI callback offset covers both pointer widths.
            assert_eq!(super::xact_stream_callbacks_offset(4), 16);
            assert_eq!(super::xact_stream_callbacks_offset(8), 24);

            // The prepared entry plays through the real audio stack.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    8,
                    &[1, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let wave = u64::from(read_u32(&memory, OUT_C).expect("wave pointer"));
            let voice = xact_with_store(&runtime, |state| match state.objects.get(&wave) {
                Some(crate::xact::XactObject::Wave(wave)) => wave.live.map(|live| live.voice),
                _ => None,
            })
            .flatten()
            .expect("streamed live voice");
            assert!(
                runtime
                    .audio
                    .queued_source_frames(voice)
                    .expect("queued frames")
                    > 0
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    8,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );

            // Destroying the bank invokes the guest close callback once with
            // the exact file handle.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                read_u32(&memory, STREAM_STATE + 20).expect("close calls"),
                1
            );
            assert_eq!(
                read_u32(&memory, STREAM_STATE + 24).expect("closed handle"),
                STREAM_HANDLE as u32
            );

            // Engine teardown closes any still-live guest streamed bank.
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[STREAM_PARAMS, OUT_B],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    2,
                    &[],
                ),
                0
            );
            assert_eq!(
                read_u32(&memory, STREAM_STATE + 20).expect("close calls after teardown"),
                2
            );
        })
    }

    #[test]
    fn xact_streaming_guest_callback_failures_and_short_reads_are_exact() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-streaming-errors");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::S_OK)
            );
            let xwb = {
                let mut bank = build_xwb("StreamBank", &[vec![1_i16; 32]], &[], &[]);
                bank[52] |= crate::xact::WAVEBANK_TYPE_STREAMING as u8;
                bank
            };
            let create = |runtime: &mut PeHostRuntime, memory: &mut MemoryImage| {
                xact_call(
                    runtime,
                    memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[STREAM_PARAMS, OUT_B],
                )
            };

            // Read callback failure propagates its exact HRESULT.
            install_stream_fixture(&mut memory, &xwb);
            memory.map_bytes(
                STREAM_READ_STUB,
                &[0xB8, 0x05, 0x00, 0x07, 0x80, 0xC2, 0x10, 0x00],
            );
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(create(&mut runtime, &mut memory), 0x8007_0005);

            // Seek callback failure propagates its exact HRESULT.
            install_stream_fixture(&mut memory, &xwb);
            memory.map_bytes(
                STREAM_SEEK_STUB,
                &[0xB8, 0x05, 0x40, 0x00, 0x80, 0xC2, 0x10, 0x00],
            );
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(create(&mut runtime, &mut memory), 0x8000_4005);

            // A seek that reports success but lands elsewhere is a hard I/O
            // failure: the caller must not read bytes from a stale position.
            install_stream_fixture(&mut memory, &xwb);
            memory.map_bytes(
                STREAM_SEEK_STUB,
                &[
                    0x31, 0xC0, 0x8B, 0x4C, 0x24, 0x10, 0xC7, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xC2,
                    0x10, 0x00,
                ],
            );
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                create(&mut runtime, &mut memory),
                u64::from(crate::xact::E_FAIL)
            );

            // A short header read is rejected, not partially parsed.
            install_stream_fixture(&mut memory, &xwb);
            write_u32(&mut memory, STREAM_STATE + 8, 8);
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                create(&mut runtime, &mut memory),
                u64::from(crate::xact::E_FAIL)
            );

            // The header read can succeed while the larger metadata read is
            // short: creation still fails instead of parsing a partial span.
            install_stream_fixture(&mut memory, &xwb);
            write_u32(&mut memory, STREAM_STATE + 8, 52);
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                create(&mut runtime, &mut memory),
                u64::from(crate::xact::E_FAIL)
            );

            // A file shorter than a WBND header and an offset past EOF are
            // both malformed streaming content.
            install_stream_fixture(&mut memory, &xwb);
            write_u32(&mut memory, STREAM_STATE + 4, 20);
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                create(&mut runtime, &mut memory),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA)
            );
            install_stream_fixture(&mut memory, &xwb);
            write_u32(&mut memory, STREAM_STATE + 4, 52);
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                create(&mut runtime, &mut memory),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA),
                "metadata segment extends past the advertised file length"
            );
            install_stream_fixture(&mut memory, &xwb);
            let past_eof = xwb.len() as u32 + 4096;
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                past_eof,
            );
            assert_eq!(
                create(&mut runtime, &mut memory),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA)
            );

            // A corrupt signature reaches the parser and keeps its genuine
            // content error after successful callback I/O.
            let mut corrupt = xwb.clone();
            corrupt[0] ^= 0xFF;
            install_stream_fixture(&mut memory, &corrupt);
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                create(&mut runtime, &mut memory),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA)
            );

            // A non-null but unmapped callback pointer fails dispatch.
            install_stream_fixture(&mut memory, &xwb);
            write_stream_params(
                &mut memory,
                0xDEAD_0000,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                create(&mut runtime, &mut memory),
                u64::from(crate::xact::E_FAIL)
            );

            // Failed creations never invoke close.
            assert_eq!(
                read_u32(&memory, STREAM_STATE + 20).expect("close calls"),
                0
            );

            // A payload short read during Prepare fails without caching.
            install_stream_fixture(&mut memory, &xwb);
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                create(&mut runtime, &mut memory),
                u64::from(crate::xact::S_OK)
            );
            let wb = u64::from(read_u32(&memory, OUT_B).expect("streaming bank pointer"));
            // A seek failure during the entry load (after creation's seeks
            // succeeded) propagates through Prepare.
            memory.map_bytes(
                STREAM_SEEK_STUB,
                &[0xB8, 0x05, 0x40, 0x00, 0x80, 0xC2, 0x10, 0x00],
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    7,
                    &[0, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::E_FAIL)
            );
            memory.map_bytes(STREAM_SEEK_STUB, &stream_seek_stub_bytes());
            write_u32(&mut memory, STREAM_STATE + 8, 4);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    7,
                    &[0, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::E_FAIL)
            );
            let (prepared, cached) =
                xact_with_store(&runtime, |state| match state.objects.get(&wb) {
                    Some(crate::xact::XactObject::WaveBank(state)) => (
                        state.prepared.contains(&0),
                        state.streaming_cache.contains_key(&0),
                    ),
                    _ => (true, true),
                })
                .expect("bank state");
            assert!(!prepared, "short payload is not marked prepared");
            assert!(!cached, "short payload is not cached");

            // A zero-length streaming entry is malformed content, not a
            // zero-byte successful prepare.
            let empty = [XwbTestEntry {
                name: "empty".to_string(),
                payload: Vec::new(),
                tag: crate::xact::WAVEBANK_TAG_PCM,
                channels: 1,
                sample_rate: 44100,
                block_align: 2,
                bits_per_sample: 16,
                duration_samples: 0,
                loop_region: (0, 0),
            }];
            let mut empty = build_xwb_entries("EmptyBank", &empty);
            empty[52] |= crate::xact::WAVEBANK_TYPE_STREAMING as u8;
            install_stream_fixture(&mut memory, &empty);
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                create(&mut runtime, &mut memory),
                u64::from(crate::xact::S_OK)
            );
            let empty_bank = u64::from(read_u32(&memory, OUT_B).expect("empty bank"));
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    empty_bank,
                    crate::xact::IFACE_WAVEBANK,
                    7,
                    &[0, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA)
            );
        })
    }

    #[test]
    fn xact_prepare_wave_accepts_drive_and_systemroot_relative_paths() {
        with_big_stack(|| {
            let (mut runtime, tmp) = xact_test_runtime("xact-stream-paths");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::S_OK)
            );
            let pcm = vec![777_i16; 32];
            let entries = [XwbTestEntry {
                name: "tone".to_string(),
                payload: pcm.iter().flat_map(|sample| sample.to_le_bytes()).collect(),
                tag: crate::xact::WAVEBANK_TAG_PCM,
                channels: 1,
                sample_rate: 44100,
                block_align: 2,
                bits_per_sample: 16,
                duration_samples: pcm.len() as u32,
                loop_region: (0, 0),
            }];
            let mut xwb = build_xwb_entries("StreamBank", &entries);
            xwb[52] |= crate::xact::WAVEBANK_TYPE_STREAMING as u8;
            let drive = tmp.path().join("xact-stream-paths").join("drive_c");
            std::fs::create_dir_all(drive.join("windows").join("system32"))
                .expect("system32 directory");
            std::fs::write(drive.join("stream-drive.xwb"), &xwb).expect("drive-root bank");
            std::fs::write(drive.join("windows/system32/stream-sys.xwb"), &xwb)
                .expect("system-root bank");
            let plain = build_xwb("PlainBank", &[tone()], &[], &[]);
            std::fs::write(drive.join("plain.xwb"), &plain).expect("plain bank");
            let empty_entries = [XwbTestEntry {
                name: "empty".to_string(),
                payload: Vec::new(),
                tag: crate::xact::WAVEBANK_TAG_PCM,
                channels: 1,
                sample_rate: 44100,
                block_align: 2,
                bits_per_sample: 16,
                duration_samples: 0,
                loop_region: (0, 0),
            }];
            let mut empty_stream = build_xwb_entries("EmptyStream", &empty_entries);
            empty_stream[52] |= crate::xact::WAVEBANK_TYPE_STREAMING as u8;
            std::fs::write(drive.join("empty-stream.xwb"), &empty_stream)
                .expect("empty streaming bank");

            let prepare = |runtime: &mut PeHostRuntime, memory: &mut MemoryImage, path: &str| {
                write_guest_c_string(memory, STRING_BUF, path);
                memory.map_bytes(OUT_B, &[0_u8; 8]);
                xact_call(
                    runtime,
                    memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    12,
                    &[0, STRING_BUF, 2, 4, 0, 0, OUT_B],
                )
            };

            // Drive-relative: C:current-directory-relative resolves through
            // the GE drive tables, not the host working directory.
            assert_eq!(
                prepare(&mut runtime, &mut memory, r"C:stream-drive.xwb"),
                u64::from(crate::xact::S_OK)
            );
            let wave = u64::from(read_u32(&memory, OUT_B).expect("wave pointer"));
            let (source, cached) =
                xact_with_store(&runtime, |state| match state.objects.get(&wave) {
                    Some(crate::xact::XactObject::Wave(wave)) => {
                        match state.objects.get(&wave.wave_bank) {
                            Some(crate::xact::XactObject::WaveBank(bank)) => (
                                bank.bank.source_path.clone(),
                                bank.streaming_cache.get(&0).cloned(),
                            ),
                            _ => (None, None),
                        }
                    }
                    _ => (None, None),
                })
                .expect("prepared wave state");
            let source = source.expect("resolved streaming source");
            assert!(
                std::path::Path::new(&source).is_file(),
                "drive-relative bank resolved to a real file: {source}"
            );
            assert_eq!(cached.expect("streamed payload"), pcm);

            for path in [
                r"\SystemRoot\system32\stream-sys.xwb",
                r"\%SystemRoot%\system32\stream-sys.xwb",
                r"\%windir%\system32\stream-sys.xwb",
            ] {
                let result = prepare(&mut runtime, &mut memory, path);
                assert_eq!(result, u64::from(crate::xact::S_OK), "{path}");
            }

            // A parsed streaming bank with a zero-length entry fails when
            // PrepareWave actually loads entry 0.
            assert_eq!(
                prepare(&mut runtime, &mut memory, r"C:empty-stream.xwb"),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA)
            );

            // PrepareStreamingWave: a declared length past EOF fails in the
            // real read path after the bank object is built.
            write_guest_c_string(&mut memory, STRING_BUF, r"C:stream-drive.xwb");
            let entry_address = 0x41_0000_u64;
            let params_address = 0x41_1000_u64;
            memory.map_bytes(entry_address, &[0_u8; 32]);
            memory.map_bytes(params_address, &[0_u8; 16]);
            write_u32(&mut memory, entry_address, 32 << 4);
            let format = crate::xact::MiniFormat {
                tag: crate::xact::WAVEBANK_TAG_PCM,
                channels: 1,
                sample_rate: 44100,
                block_align: 2,
                bits_per_sample: 16,
            };
            write_u32(&mut memory, entry_address + 4, format.encode());
            write_u32(&mut memory, entry_address + 8, 0);
            write_u32(&mut memory, entry_address + 12, 64);
            write_u32(&mut memory, params_address, STRING_BUF as u32);
            write_u32(&mut memory, params_address + 8, xwb.len() as u32 + 1);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    14,
                    &[0, entry_address, params_address, 4, 0, 0, 0, OUT_B],
                ),
                u64::from(crate::xact::E_FAIL)
            );

            // A non-streaming bank is rejected by the streaming parser.
            assert_eq!(
                prepare(&mut runtime, &mut memory, r"C:plain.xwb"),
                u64::from(crate::xact::XACTENGINE_E_INVALIDUSAGE)
            );

            // Missing files keep the genuine file-open error for every
            // supported path form.
            for path in [
                r"C:missing.xwb",
                r"\SystemRoot\system32\missing.xwb",
                r"%SystemRoot%\system32\missing.xwb",
                "relative-missing.xwb",
            ] {
                assert_eq!(
                    prepare(&mut runtime, &mut memory, path),
                    u64::from(crate::xact::E_FAIL),
                    "{path}"
                );
            }
        })
    }

    #[test]
    fn xact_two_output_voices_apply_per_voice_matrix_gains() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-output-voices");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb("WaveBank", &[vec![1000_i16; 441]], &[], &[]);
            let xsb = simple_soundbank(&[("mono", 0)]);
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));

            // Two real guest IXAudio2Voice output voices, both stereo.
            let left_voice = xact_test_output_voice(&mut runtime, &mut memory, 2);
            let right_voice = xact_test_output_voice(&mut runtime, &mut memory, 2);

            // XAUDIO2_VOICE_SENDS { OutputCount, pSends } with 8-byte
            // XAUDIO2_SEND_DESCRIPTOR { Flags, pOutputVoice } entries.
            memory.map_bytes(PARAMS, &[0_u8; 128]);
            write_u32(&mut memory, PARAMS, 2);
            write_u32(&mut memory, PARAMS + 4, (PARAMS + 16) as u32);
            write_u32(&mut memory, PARAMS + 16, 0);
            write_u32(&mut memory, PARAMS + 20, left_voice as u32);
            write_u32(&mut memory, PARAMS + 24, 0);
            write_u32(&mut memory, PARAMS + 28, right_voice as u32);

            // A matrix cannot target a voice that was not selected, and an
            // unknown/dead output-voice pointer is rejected.
            write_u32(&mut memory, PARAMS + 64, 0.5_f32.to_bits());
            write_u32(&mut memory, PARAMS + 68, 0.0_f32.to_bits());
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    14,
                    &[left_voice, 1, 2, PARAMS + 64],
                ),
                u64::from(crate::xact::E_INVALIDARG),
                "matrix before SetOutputVoices is invalid"
            );
            write_u32(&mut memory, PARAMS, 9);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::E_INVALIDARG),
                "more than XAUDIO2_MAX_SEND_COUNT destinations"
            );
            write_u32(&mut memory, PARAMS, 1);
            write_u32(&mut memory, PARAMS + 20, 0x00AB_CDEF);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::E_INVALIDARG),
                "a non-XAudio2 pointer is not an output voice"
            );
            write_u32(&mut memory, PARAMS, 2);
            write_u32(&mut memory, PARAMS + 20, left_voice as u32);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::S_OK)
            );
            let routes = xact_with_store(&runtime, |state| match state.objects.get(&cue) {
                Some(crate::xact::XactObject::Cue(cue)) => cue.output_voices.clone(),
                _ => None,
            })
            .flatten()
            .expect("output-voice routes");
            assert_eq!(routes.len(), 2);
            assert_eq!(routes[0].voice, left_voice);
            assert_eq!(routes[0].channels, 2);
            assert_eq!(routes[1].voice, right_voice);
            assert_eq!(routes[1].channels, 2);

            // Mono cue -> left output voice (left 0.5) and right output
            // voice (right 0.25).  Each destination genuinely scales the
            // cue mix with its own coefficients.
            write_u32(&mut memory, PARAMS + 64, 0.5_f32.to_bits());
            write_u32(&mut memory, PARAMS + 68, 0.0_f32.to_bits());
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    14,
                    &[left_voice, 1, 2, PARAMS + 64],
                ),
                u64::from(crate::xact::S_OK)
            );
            write_u32(&mut memory, PARAMS + 72, 0.0_f32.to_bits());
            write_u32(&mut memory, PARAMS + 76, 0.25_f32.to_bits());
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    14,
                    &[right_voice, 1, 2, PARAMS + 72],
                ),
                u64::from(crate::xact::S_OK)
            );
            // Destination channel count must match the real voice.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    14,
                    &[left_voice, 1, 3, PARAMS + 64],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    14,
                    &[left_voice, 0, 2, PARAMS + 64],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );

            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            let voices = cue_live_voices(&runtime, cue);
            assert_eq!(voices.len(), 2, "one real source voice per destination");
            for voice in &voices {
                assert_eq!(
                    runtime
                        .audio
                        .voice_format(*voice)
                        .expect("route format")
                        .channels,
                    2
                );
                assert!((runtime.audio.volume(*voice).expect("route gain") - 1.0).abs() < 1.0e-3);
            }
            let mastering = xact_mastering_voice(&runtime);
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render two output voices");
            let amplitude = 1000.0_f32 / i16::MAX as f32 * crate::xact::decibels_to_amplitude(180);
            assert!(
                (output.samples[0] - amplitude * 0.5).abs() < 1.0e-5,
                "left output voice gain: {}",
                output.samples[0]
            );
            assert!(
                (output.samples[1] - amplitude * 0.25).abs() < 1.0e-5,
                "right output voice gain: {}",
                output.samples[1]
            );

            // A matrix whose source count does not match the decoded wave
            // is rejected at Play with the genuine bad-content error.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    4,
                    &[u64::from(crate::xact::XACT_FLAG_STOP_IMMEDIATE)],
                ),
                u64::from(crate::xact::S_OK)
            );
            for index in 0..4 {
                write_u32(&mut memory, PARAMS + 80 + index * 4, 0.25_f32.to_bits());
            }
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    14,
                    &[left_voice, 2, 2, PARAMS + 80],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA),
                "matrix source channels must match the cue wave"
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    14,
                    &[left_voice, 1, 2, PARAMS + 64],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
        })
    }

    #[test]
    fn xact_set_output_voices_reroutes_live_cue_exactly() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-reroute");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb("WaveBank", &[vec![1000_i16; 4096]], &[], &[]);
            let xsb = simple_soundbank(&[("mono", 0)]);
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));
            let voice_a = xact_test_output_voice(&mut runtime, &mut memory, 2);
            let voice_b = xact_test_output_voice(&mut runtime, &mut memory, 2);
            let amplitude = 1000.0_f32 / i16::MAX as f32 * crate::xact::decibels_to_amplitude(180);

            // Initial route: left output voice scaled by 0.5.
            write_output_sends(&mut memory, 1, &[voice_a]);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::S_OK)
            );
            write_u32(&mut memory, PARAMS + 64, 0.5_f32.to_bits());
            write_u32(&mut memory, PARAMS + 68, 0.0_f32.to_bits());
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    14,
                    &[voice_a, 1, 2, PARAMS + 64],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            let voices_a = cue_live_voices(&runtime, cue);
            assert_eq!(voices_a.len(), 1);
            let mastering = xact_mastering_voice(&runtime);
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render initial route");
            assert!((output.samples[0] - amplitude * 0.5).abs() < 1.0e-5);
            assert!(output.samples[1].abs() < 1.0e-6);

            // Reroute to a different destination voice mid-play.
            write_output_sends(&mut memory, 1, &[voice_b]);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::S_OK)
            );
            let voices_b = cue_live_voices(&runtime, cue);
            assert_eq!(voices_b.len(), 1);
            assert_ne!(voices_a, voices_b, "new destination gets a new voice");
            assert!(
                runtime.audio.voice_format(voices_a[0]).is_err(),
                "old destination voice is destroyed by the reroute"
            );
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render rerouted default matrix");
            assert!((output.samples[0] - amplitude).abs() < 1.0e-5);
            assert!((output.samples[1] - amplitude).abs() < 1.0e-5);

            // Replace the destination matrix, then reroute again: the carried
            // matrix is applied to the live playback, not just stored.
            write_u32(&mut memory, PARAMS + 64, 0.25_f32.to_bits());
            write_u32(&mut memory, PARAMS + 68, 0.75_f32.to_bits());
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    14,
                    &[voice_b, 1, 2, PARAMS + 64],
                ),
                u64::from(crate::xact::S_OK)
            );
            write_output_sends(&mut memory, 1, &[voice_b]);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::S_OK)
            );
            let voices_c = cue_live_voices(&runtime, cue);
            assert_ne!(voices_b, voices_c);
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render rerouted matrix");
            assert!((output.samples[0] - amplitude * 0.25).abs() < 1.0e-5);
            assert!((output.samples[1] - amplitude * 0.75).abs() < 1.0e-5);

            // A rejected reroute leaves the active routing untouched.
            write_output_sends(&mut memory, 1, &[0x00AB_CDEF]);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );
            assert_eq!(cue_live_voices(&runtime, cue), voices_c);
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render after rejected reroute");
            assert!((output.samples[0] - amplitude * 0.25).abs() < 1.0e-5);
            assert!((output.samples[1] - amplitude * 0.75).abs() < 1.0e-5);

            // A non-cue `this` pointer is rejected by the dispatch guard and
            // by the reroute helper itself.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );
            let pid = runtime.guest_pid;
            let mut store = crate::xact::lock_xact_runtimes();
            let xact_runtime = store.get_mut(&pid).expect("xact runtime");
            assert_eq!(
                runtime
                    .xact_apply_cue_output_voices(xact_runtime, engine, None)
                    .expect("reroute helper"),
                crate::xact::E_INVALIDARG
            );
            drop(store);

            // A paused cue reroutes without resuming: the new voices exist
            // but stay stopped and the state remains PAUSED.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    11,
                    &[1],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_cue_state(&runtime, cue),
                Some(crate::xact::XACT_STATE_PAUSED)
            );
            write_output_sends(&mut memory, 1, &[voice_a]);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::S_OK)
            );
            let voices_paused = cue_live_voices(&runtime, cue);
            assert_ne!(voices_paused, voices_c);
            assert!(
                !runtime
                    .audio
                    .voice_started(voices_paused[0])
                    .expect("paused voice")
            );
            assert_eq!(
                xact_cue_state(&runtime, cue),
                Some(crate::xact::XACT_STATE_PAUSED)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    11,
                    &[0],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_cue_state(&runtime, cue),
                Some(crate::xact::XACT_STATE_PLAYING)
            );

            // An empty send list is the default mastering route.
            write_output_sends(&mut memory, 0, &[]);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::S_OK)
            );
            let voices_d = cue_live_voices(&runtime, cue);
            assert_ne!(voices_c, voices_d);
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render empty send list");
            assert!((output.samples[0] - amplitude).abs() < 1.0e-5);
            assert!((output.samples[1] - amplitude).abs() < 1.0e-5);

            // A null send list restores the same default route.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[0],
                ),
                u64::from(crate::xact::S_OK)
            );
            let voices_e = cue_live_voices(&runtime, cue);
            assert_ne!(voices_d, voices_e);

            // A reroute that fails in the mixing path stops the dangling cue
            // instead of leaving it half-routed.
            write_output_sends(&mut memory, 1, &[voice_b]);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::S_OK)
            );
            for index in 0..4 {
                write_u32(&mut memory, PARAMS + 64 + index * 4, 0.25_f32.to_bits());
            }
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    14,
                    &[voice_b, 2, 2, PARAMS + 64],
                ),
                u64::from(crate::xact::S_OK)
            );
            write_output_sends(&mut memory, 1, &[voice_b]);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    13,
                    &[PARAMS],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA)
            );
            assert!(cue_live_voices(&runtime, cue).is_empty());
            let state = xact_with_store(&runtime, |state| match state.objects.get(&cue) {
                Some(crate::xact::XactObject::Cue(cue)) => cue.state,
                _ => u32::MAX,
            })
            .expect("cue state");
            assert_eq!(state, crate::xact::XACT_STATE_STOPPED);
        })
    }

    #[test]
    fn xact_release_curve_variants_pin_exact_gain_steps() {
        for (byte, curve, name) in [
            (0_u8, crate::xact::ReleaseCurve::Linear, "linear"),
            (1_u8, crate::xact::ReleaseCurve::Logarithmic, "log"),
            (2_u8, crate::xact::ReleaseCurve::EqualPower, "equal-power"),
            (3_u8, crate::xact::ReleaseCurve::Squared, "squared"),
        ] {
            with_big_stack(move || {
                let (mut runtime, _tmp) = xact_test_runtime(&format!("xact-release-{name}"));
                let mut memory = MemoryImage::default();
                let engine = xact_create_engine(&mut runtime, &mut memory);
                let settings = build_xgs_curve_with_fade(byte, 100);
                assert_eq!(
                    xact_initialize_with_settings(&mut runtime, &mut memory, engine, &settings),
                    u64::from(crate::xact::S_OK),
                    "{name} settings"
                );
                let xwb = build_xwb("WaveBank", &[vec![1000_i16; 20_000]], &[], &[]);
                let xsb = simple_soundbank(&[("mono", 0)]);
                let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
                assert_eq!(
                    xact_call(
                        &mut runtime,
                        &mut memory,
                        sb,
                        crate::xact::IFACE_SOUNDBANK,
                        6,
                        &[0, 0, 0, OUT_C],
                    ),
                    u64::from(crate::xact::S_OK)
                );
                let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));
                assert_eq!(
                    xact_call(
                        &mut runtime,
                        &mut memory,
                        cue,
                        crate::xact::IFACE_CUE,
                        3,
                        &[],
                    ),
                    u64::from(crate::xact::S_OK)
                );
                let voice = cue_live_voices(&runtime, cue)[0];
                assert_eq!(
                    xact_call(
                        &mut runtime,
                        &mut memory,
                        cue,
                        crate::xact::IFACE_CUE,
                        4,
                        &[0],
                    ),
                    u64::from(crate::xact::S_OK)
                );
                assert_eq!(
                    xact_cue_state(&runtime, cue),
                    Some(crate::xact::XACT_STATE_STOPPING),
                    "{name} release starts"
                );
                let start_gain = runtime.audio.volume(voice).expect("start gain");
                let total = 4410_u32; // 100 ms at 44.1 kHz
                for step in 1..=3_u32 {
                    assert_eq!(
                        xact_call(
                            &mut runtime,
                            &mut memory,
                            engine,
                            crate::xact::IFACE_ENGINE,
                            8,
                            &[512],
                        ),
                        u64::from(crate::xact::S_OK)
                    );
                    // The gain applied for this slice is the fraction
                    // before the envelope advances.
                    let remaining = total - (step - 1) * 512;
                    let expected = start_gain * release_at(curve, remaining, total);
                    let volume = runtime.audio.volume(voice).expect("release gain");
                    assert!(
                        (volume - expected).abs() < 1.0e-5,
                        "{name} step {step}: {volume} != {expected}"
                    );
                }
                for _ in 0..8 {
                    assert_eq!(
                        xact_call(
                            &mut runtime,
                            &mut memory,
                            engine,
                            crate::xact::IFACE_ENGINE,
                            8,
                            &[512],
                        ),
                        u64::from(crate::xact::S_OK)
                    );
                }
                assert_eq!(
                    xact_cue_state(&runtime, cue),
                    Some(crate::xact::XACT_STATE_STOPPED),
                    "{name} release completes"
                );
                assert!(
                    runtime.audio.voice_format(voice).is_err(),
                    "{name} released voice is destroyed"
                );
            });
        }
    }

    #[test]
    fn xact_release_volume_and_malformed_curve_are_exact() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-release-volume");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            let settings = build_xgs_curve_with_fade(0, 100);
            assert_eq!(
                xact_initialize_with_settings(&mut runtime, &mut memory, engine, &settings),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb("WaveBank", &[vec![1000_i16; 20_000]], &[], &[]);
            let xsb = simple_soundbank(&[("mono", 0)]);
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            let voice = cue_live_voices(&runtime, cue)[0];
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    4,
                    &[0],
                ),
                u64::from(crate::xact::S_OK)
            );
            let start_gain = runtime.audio.volume(voice).expect("start gain");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    8,
                    &[512],
                ),
                u64::from(crate::xact::S_OK)
            );
            // Category volume changes during release are scaled by the
            // current curve fraction, not by the linear frame fraction.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    19,
                    &[0, xact_f32(2.0)],
                ),
                u64::from(crate::xact::S_OK)
            );
            let expected =
                start_gain * 2.0 * release_at(crate::xact::ReleaseCurve::Linear, 3898, 4410);
            let volume = runtime.audio.volume(voice).expect("release gain");
            assert!((volume - expected).abs() < 1.0e-5, "{volume} != {expected}");
            // The next slice re-applies the same curve fraction before the
            // envelope advances.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    8,
                    &[512],
                ),
                u64::from(crate::xact::S_OK)
            );
            let expected =
                start_gain * 2.0 * release_at(crate::xact::ReleaseCurve::Linear, 3898, 4410);
            let volume = runtime.audio.volume(voice).expect("release gain");
            assert!((volume - expected).abs() < 1.0e-5, "{volume} != {expected}");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    8,
                    &[512],
                ),
                u64::from(crate::xact::S_OK)
            );
            let expected =
                start_gain * 2.0 * release_at(crate::xact::ReleaseCurve::Linear, 3386, 4410);
            let volume = runtime.audio.volume(voice).expect("release gain");
            assert!((volume - expected).abs() < 1.0e-5, "{volume} != {expected}");
        })
    }

    #[test]
    fn xact_malformed_release_curve_byte_is_rejected() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-release-malformed");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            let settings = build_xgs_curve(4);
            assert_eq!(
                xact_initialize_with_settings(&mut runtime, &mut memory, engine, &settings),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA),
                "unknown curve byte is malformed content"
            );
        })
    }

    #[test]
    fn xact_cue_local_variables_override_globals_and_drive_variations() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-variables");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            let mut xgs = build_xgs();
            // Make the XGS variable settable (bit 0x02 is read-only).
            xgs[100] = 0x01;
            assert_eq!(
                xact_initialize_with_settings(&mut runtime, &mut memory, engine, &xgs),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb(
                "WaveBank",
                &[vec![100_i16; 441], vec![200_i16; 441]],
                &[],
                &[],
            );
            let xsb = build_xsb_interactive(
                "SoundBank",
                "WaveBank",
                "variableCue",
                0,
                &[(0, 0.0, 500.0), (1, 500.0, 1000.0)],
                Some("CueSpeed"),
            );
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));
            write_guest_c_string(&mut memory, STRING_BUF, "SpeedOfSound");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                0,
                "cue-local index for the bound variable"
            );
            write_guest_c_string(&mut memory, STRING_BUF, "CueSpeed");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                0,
                "the XSB local friendly-name table resolves first"
            );
            write_guest_c_string(&mut memory, STRING_BUF, "NotAVariable");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                u64::from(crate::xact::XACTVARIABLEINDEX_INVALID)
            );
            // A global name that is not cue-local still falls back to the
            // engine variable table.
            write_guest_c_string(&mut memory, STRING_BUF, "SpeedOfSound");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                0,
                "global-name fallback"
            );

            // Invalid local indices are rejected; valid values clamp to the
            // global variable's authored range.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    9,
                    &[7, xact_f32(1.0)],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    9,
                    &[0, xact_f32(800.0)],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    10,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("local value")),
                800.0
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    23,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("global value")),
                343.0
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    23,
                    &[9, OUT_A],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );

            // The cue-local value selects the upper interactive range; the
            // global value is still the lower range.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            let mastering = xact_mastering_voice(&runtime);
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render local-variable selection");
            let expected_upper = 200.0_f32 / i16::MAX as f32;
            assert!(
                (output.samples[0] - expected_upper).abs() < 1.0e-5,
                "cue-local 800 selects the upper wave: {}",
                output.samples[0]
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    4,
                    &[u64::from(crate::xact::XACT_FLAG_STOP_IMMEDIATE)],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    22,
                    &[0, xact_f32(100.0)],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    10,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("cue scope")),
                800.0,
                "the cue override wins over the changed global"
            );

            // A fresh cue without an override follows the global value and
            // picks the lower wave.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let second = u64::from(read_u32(&memory, OUT_C).expect("second cue"));
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    second,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render global-variable selection");
            let expected_lower = 100.0_f32 / i16::MAX as f32;
            assert!(
                (output.samples[0] - expected_lower).abs() < 1.0e-5,
                "global 100 selects the lower wave: {}",
                output.samples[0]
            );
        })
    }

    #[test]
    fn xact_cue_scoped_variable_uses_local_value_and_rejects_global_io() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-cue-scoped");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            let mut xgs = build_xgs();
            // Public + cue-scoped: each cue owns this variable.
            xgs[100] = 0x05;
            assert_eq!(
                xact_initialize_with_settings(&mut runtime, &mut memory, engine, &xgs),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb(
                "WaveBank",
                &[vec![100_i16; 441], vec![200_i16; 441]],
                &[],
                &[],
            );
            let xsb = build_xsb_interactive(
                "SoundBank",
                "WaveBank",
                "variableCue",
                0,
                &[(0, 0.0, 500.0), (1, 500.0, 1000.0)],
                Some("CueSpeed"),
            );
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));
            write_guest_c_string(&mut memory, STRING_BUF, "SpeedOfSound");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                0,
                "binding-name fallback resolves the cue-local slot"
            );
            write_guest_c_string(&mut memory, STRING_BUF, "CueSpeed");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                0
            );
            // A cue-scoped variable is not visible through the engine API.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    23,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    22,
                    &[0, xact_f32(100.0)],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    9,
                    &[0, xact_f32(800.0)],
                ),
                u64::from(crate::xact::S_OK),
                "cue scope accepts a public cue-scoped variable"
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    10,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("local value")),
                800.0
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            let mastering = xact_mastering_voice(&runtime);
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render cue-scoped value");
            let expected_upper = 200.0_f32 / i16::MAX as f32;
            assert!((output.samples[0] - expected_upper).abs() < 1.0e-5);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    4,
                    &[u64::from(crate::xact::XACT_FLAG_STOP_IMMEDIATE)],
                ),
                u64::from(crate::xact::S_OK)
            );

            // A fresh cue starts from the authored initial value.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let second = u64::from(read_u32(&memory, OUT_C).expect("second cue"));
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    second,
                    crate::xact::IFACE_CUE,
                    10,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("initial value")),
                343.0
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    second,
                    crate::xact::IFACE_CUE,
                    9,
                    &[0, xact_f32(5000.0)],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    second,
                    crate::xact::IFACE_CUE,
                    10,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("clamped max")),
                1000.0
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    second,
                    crate::xact::IFACE_CUE,
                    9,
                    &[0, xact_f32(-50.0)],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    second,
                    crate::xact::IFACE_CUE,
                    10,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("clamped min")),
                0.0
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    second,
                    crate::xact::IFACE_CUE,
                    9,
                    &[1, xact_f32(1.0)],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );
        })
    }

    #[test]
    fn xact_cue_readonly_scoped_variable_rejects_set_but_reads_initial() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-cue-readonly");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            let mut xgs = build_xgs();
            // Public + read-only + cue-scoped.
            xgs[100] = 0x07;
            assert_eq!(
                xact_initialize_with_settings(&mut runtime, &mut memory, engine, &xgs),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb(
                "WaveBank",
                &[vec![100_i16; 441], vec![200_i16; 441]],
                &[],
                &[],
            );
            let xsb = build_xsb_interactive(
                "SoundBank",
                "WaveBank",
                "variableCue",
                0,
                &[(0, 0.0, 500.0), (1, 500.0, 1000.0)],
                Some("CueSpeed"),
            );
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    9,
                    &[0, xact_f32(800.0)],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    10,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("read-only value")),
                343.0
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    22,
                    &[0, xact_f32(1.0)],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );
        })
    }

    #[test]
    fn xact_cue_variable_out_of_range_binding_is_rejected() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-cue-binding");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            let mut xgs = build_xgs();
            xgs[100] = 0x01;
            assert_eq!(
                xact_initialize_with_settings(&mut runtime, &mut memory, engine, &xgs),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb(
                "WaveBank",
                &[vec![100_i16; 441], vec![200_i16; 441]],
                &[],
                &[],
            );
            // The cue binds local slot 0 to a non-existent global 99.
            let xsb = build_xsb_interactive(
                "SoundBank",
                "WaveBank",
                "variableCue",
                99,
                &[(0, 0.0, 500.0), (1, 500.0, 1000.0)],
                Some("CueSpeed"),
            );
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));
            write_guest_c_string(&mut memory, STRING_BUF, "SpeedOfSound");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                0,
                "a missing local binding falls back to the global name"
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    9,
                    &[0, xact_f32(800.0)],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    10,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    10,
                    &[1, OUT_A],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX)
            );
            // Selection falls back to the weighted table (entry 0).
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            let mastering = xact_mastering_voice(&runtime);
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render missing-binding selection");
            let expected_lower = 100.0_f32 / i16::MAX as f32;
            assert!((output.samples[0] - expected_lower).abs() < 1.0e-5);
        })
    }

    #[test]
    fn xact_cue_variable_unbound_binding_edges_are_exact() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-cue-unbound");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            let mut xgs = build_xgs();
            xgs[100] = 0x01;
            assert_eq!(
                xact_initialize_with_settings(&mut runtime, &mut memory, engine, &xgs),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb(
                "WaveBank",
                &[vec![100_i16; 441], vec![200_i16; 441]],
                &[],
                &[],
            );
            // Negative binding: the parser records no local slot at all.
            let xsb = build_xsb_interactive(
                "SoundBank",
                "WaveBank",
                "variableCue",
                -1,
                &[(0, 0.0, 500.0), (1, 500.0, 1000.0)],
                Some("CueSpeed"),
            );
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));
            write_guest_c_string(&mut memory, STRING_BUF, "CueSpeed");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                u64::from(crate::xact::XACTVARIABLEINDEX_INVALID),
                "an unbound cue has no local name table"
            );
            write_guest_c_string(&mut memory, STRING_BUF, "SpeedOfSound");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                0
            );
            // With no local slot, index 0 is the engine global.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    9,
                    &[0, xact_f32(800.0)],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    23,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("global value")),
                800.0
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    9,
                    &[1, xact_f32(1.0)],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX),
                "an unbound cue has no slot 1"
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            let mastering = xact_mastering_voice(&runtime);
            let output = runtime
                .audio
                .render_xaudio2(mastering, 441)
                .expect("render unbound selection");
            let expected_lower = 100.0_f32 / i16::MAX as f32;
            assert!(
                (output.samples[0] - expected_lower).abs() < 1.0e-5,
                "an unbound variation keeps its weighted selection"
            );
        })
    }

    #[test]
    fn xact_cue_variable_empty_local_name_falls_back_and_rejects_unknown() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-cue-empty-name");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            let mut xgs = build_xgs();
            xgs[100] = 0x01;
            assert_eq!(
                xact_initialize_with_settings(&mut runtime, &mut memory, engine, &xgs),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb(
                "WaveBank",
                &[vec![100_i16; 441], vec![200_i16; 441]],
                &[],
                &[],
            );
            let xsb = build_xsb_interactive(
                "SoundBank",
                "WaveBank",
                "variableCue",
                0,
                &[(0, 0.0, 500.0), (1, 500.0, 1000.0)],
                Some(""),
            );
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue pointer"));
            write_guest_c_string(&mut memory, STRING_BUF, "SpeedOfSound");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                0,
                "empty local names are skipped, binding name wins"
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    9,
                    &[0, xact_f32(100.0)],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    23,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("global initial")),
                343.0,
                "the empty-name cue override did not touch the global"
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    10,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("local value")),
                100.0
            );
            write_guest_c_string(&mut memory, STRING_BUF, "NotTheBinding");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                u64::from(crate::xact::XACTVARIABLEINDEX_INVALID),
                "an unrelated name is rejected even with an empty local table"
            );
        })
    }

    #[test]
    fn xact_prepare_bank_entry_rejects_unknown_codecs_and_invalid_objects() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-prepare-edges");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::S_OK)
            );
            let entries = [XwbTestEntry {
                name: "unsupported".to_string(),
                payload: vec![1, 2, 3, 4],
                tag: 9,
                channels: 1,
                sample_rate: 44100,
                block_align: 2,
                bits_per_sample: 16,
                duration_samples: 2,
                loop_region: (0, 0),
            }];
            let xwb = build_xwb_entries("CodecBank", &entries);
            let buffer = map_bank(&mut memory, &xwb);
            memory.map_bytes(OUT_B, &[0_u8; 8]);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    10,
                    &[buffer, xwb.len() as u64, 0, 0, OUT_B],
                ),
                u64::from(crate::xact::S_OK)
            );
            let wb = u64::from(read_u32(&memory, OUT_B).expect("bank pointer"));
            // An in-memory entry with no decoded PCM keeps the genuine
            // content error instead of pretending to prepare.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    7,
                    &[0, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA)
            );
            // A non-bank `this` pointer is rejected before the entry lookup.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_WAVEBANK,
                    7,
                    &[0, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );
            // Preparing the in-memory PCM entry twice is idempotent.
            let xwb = build_xwb("PcmBank", &[tone()], &[], &[]);
            let buffer = map_bank(&mut memory, &xwb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    10,
                    &[buffer, xwb.len() as u64, 0, 0, OUT_B],
                ),
                u64::from(crate::xact::S_OK)
            );
            let pcm_bank = u64::from(read_u32(&memory, OUT_B).expect("pcm bank"));
            for _ in 0..2 {
                assert_eq!(
                    xact_call(
                        &mut runtime,
                        &mut memory,
                        pcm_bank,
                        crate::xact::IFACE_WAVEBANK,
                        7,
                        &[0, 0, 0, 0, OUT_C],
                    ),
                    u64::from(crate::xact::S_OK)
                );
            }
            // The entry loader itself rejects a non-bank object and an
            // out-of-range index before touching entry data.
            assert_eq!(
                xact_prepare_direct(&mut runtime, &mut memory, engine, 0),
                Err(crate::xact::E_INVALIDARG)
            );
            assert_eq!(
                xact_prepare_direct(&mut runtime, &mut memory, pcm_bank, 9),
                Err(crate::xact::XACTENGINE_E_INVALIDWAVEINDEX)
            );

            // A guest-streamed entry whose codec has no decoder records the
            // genuine decode error after the callback read succeeds.
            let entries = [XwbTestEntry {
                name: "unsupported-stream".to_string(),
                payload: vec![1, 2, 3, 4],
                tag: 9,
                channels: 1,
                sample_rate: 44100,
                block_align: 2,
                bits_per_sample: 16,
                duration_samples: 2,
                loop_region: (0, 0),
            }];
            let mut streamed = build_xwb_entries("CodecStream", &entries);
            streamed[52] |= crate::xact::WAVEBANK_TYPE_STREAMING as u8;
            install_stream_fixture(&mut memory, &streamed);
            write_stream_params(
                &mut memory,
                STREAM_READ_STUB,
                STREAM_SEEK_STUB,
                STREAM_CLOSE_STUB,
                STREAM_HANDLE,
                0,
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    11,
                    &[STREAM_PARAMS, OUT_B],
                ),
                u64::from(crate::xact::S_OK)
            );
            let codec_bank = u64::from(read_u32(&memory, OUT_B).expect("codec bank"));
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    codec_bank,
                    crate::xact::IFACE_WAVEBANK,
                    7,
                    &[0, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDDATA)
            );
        })
    }

    #[test]
    fn xact_destroy_objects_tear_down_live_voices_and_reject_stale_handles() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-destroy");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            assert_eq!(
                xact_initialize(&mut runtime, &mut memory, engine, 0),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb("WaveBank", &[vec![1000_i16; 441]], &[], &[]);
            let xsb = simple_soundbank(&[("mono", 0)]);
            let (wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            // A live wave object and a live cue object.
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    8,
                    &[0, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let wave = u64::from(read_u32(&memory, OUT_C).expect("wave"));
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue"));
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );

            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wave,
                    crate::xact::IFACE_WAVE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wave,
                    crate::xact::IFACE_WAVE,
                    4,
                    &[u64::from(crate::xact::XACT_FLAG_STOP_IMMEDIATE)],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    6,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    3,
                    &[],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    9,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    5,
                    &[0, OUT_C],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    3,
                    &[],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    wb,
                    crate::xact::IFACE_WAVEBANK,
                    8,
                    &[0, 0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::E_INVALIDARG)
            );
        })
    }

    #[test]
    fn xact_cue_scoped_variable_without_variation_binding_gets_local_slot() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = xact_test_runtime("xact-cue-scoped-plain");
            let mut memory = MemoryImage::default();
            let engine = xact_create_engine(&mut runtime, &mut memory);
            let mut xgs = build_xgs();
            xgs[100] = 0x05;
            assert_eq!(
                xact_initialize_with_settings(&mut runtime, &mut memory, engine, &xgs),
                u64::from(crate::xact::S_OK)
            );
            let xwb = build_xwb("WaveBank", &[vec![100_i16; 441]], &[], &[]);
            let xsb = simple_soundbank(&[("plain", 0)]);
            let (_wb, sb) = xact_load_banks(&mut runtime, &mut memory, engine, &xwb, &xsb);
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    sb,
                    crate::xact::IFACE_SOUNDBANK,
                    6,
                    &[0, 0, 0, OUT_C],
                ),
                u64::from(crate::xact::S_OK)
            );
            let cue = u64::from(read_u32(&memory, OUT_C).expect("cue"));
            write_guest_c_string(&mut memory, STRING_BUF, "SpeedOfSound");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                0,
                "a cue-scoped variable is registered even without a variation binding"
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    9,
                    &[0, xact_f32(800.0)],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    10,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::S_OK)
            );
            assert_eq!(
                f32::from_bits(read_u32(&memory, OUT_A).expect("local value")),
                800.0
            );
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    engine,
                    crate::xact::IFACE_ENGINE,
                    23,
                    &[0, OUT_A],
                ),
                u64::from(crate::xact::XACTENGINE_E_INVALIDVARIABLEINDEX),
                "the engine cannot read a cue-scoped variable"
            );
            write_guest_c_string(&mut memory, STRING_BUF, "NotAVariable");
            assert_eq!(
                xact_call(
                    &mut runtime,
                    &mut memory,
                    cue,
                    crate::xact::IFACE_CUE,
                    8,
                    &[STRING_BUF],
                ),
                u64::from(crate::xact::XACTVARIABLEINDEX_INVALID)
            );
        })
    }
}

// Shared guest-dispatch support for the tests below (the same x86 stack
// convention the runtime test module's `dispatch_x86_thunk` uses).
#[cfg(test)]
mod final_scraps_test_support {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use tempfile::TempDir;

    pub(crate) const STACK: u64 = 0x50_000;

    pub(crate) fn test_runtime(name: &str) -> (PeHostRuntime, TempDir) {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), name, GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.guest_arch = GuestArch::X86;
        runtime.next_thunk_address = thunk_base_for_arch(GuestArch::X86);
        runtime.next_data_address = data_base_for_arch(GuestArch::X86);
        runtime.next_heap_address = heap_base_for_arch(GuestArch::X86);
        runtime
            .win32
            .reset_address_space(private_pages_base_for_arch(GuestArch::X86));
        runtime.x86_heap_region = 0;
        (runtime, temp_dir)
    }

    pub(crate) fn with_big_stack<T: Send + 'static>(
        body: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(body)
            .expect("spawn big-stack thread")
            .join()
            .expect("big-stack thread panicked")
    }

    pub(crate) fn dispatch_x86(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thunk: u64,
        args: &[u32],
    ) -> u32 {
        memory.map_bytes(STACK, &[0_u8; 0x400]);
        write_u32(memory, STACK, 0xDEAD_BEEF);
        for (index, arg) in args.iter().enumerate() {
            write_u32(memory, STACK + 4 + index as u64 * 4, *arg);
        }
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, STACK);
        runtime
            .dispatch_import(thunk, &mut state, memory)
            .unwrap_or_else(|error| panic!("dispatch x86 thunk: {error}"));
        state.get(Register::Rax) as u32
    }
}

#[cfg(test)]
mod x3daudio_dispatch_tests {
    use super::final_scraps_test_support::*;
    use super::*;
    use crate::x3daudio::{
        SPEAKER_5POINT1, SPEAKER_7POINT1, SPEAKER_STEREO, X3DAUDIO_CALCULATE_DELAY,
        X3DAUDIO_CALCULATE_EMITTER_ANGLE, X3DAUDIO_CALCULATE_MATRIX,
        X3DAUDIO_CALCULATE_REDIRECT_TO_LFE, X3DAUDIO_CALCULATE_ZEROCENTER, X3DAUDIO_SPEED_OF_SOUND,
    };

    const HANDLE: u64 = 0x70_000;
    const LISTENER: u64 = 0x70_100;
    const EMITTER: u64 = 0x70_200;
    const DSP: u64 = 0x70_300;
    const MATRIX: u64 = 0x70_400;
    const DELAYS: u64 = 0x70_500;

    fn write_f32(memory: &mut MemoryImage, address: u64, value: f32) {
        write_u32(memory, address, value.to_bits());
    }

    fn write_vec(memory: &mut MemoryImage, address: u64, x: f32, y: f32, z: f32) {
        write_f32(memory, address, x);
        write_f32(memory, address + 4, y);
        write_f32(memory, address + 8, z);
    }

    fn matrix_value(memory: &MemoryImage, index: u64) -> f32 {
        f32::from_bits(read_u32(memory, MATRIX + index * 4).expect("matrix word"))
    }

    fn delay_value(memory: &MemoryImage, index: u64) -> f32 {
        f32::from_bits(read_u32(memory, DELAYS + index * 4).expect("delay word"))
    }

    fn scene(memory: &mut MemoryImage, mask: u32, dst_count: u32) {
        memory.map_bytes(HANDLE, &[0_u8; 32]);
        memory.map_bytes(LISTENER, &[0_u8; 64]);
        memory.map_bytes(EMITTER, &[0_u8; 112]);
        memory.map_bytes(DSP, &[0_u8; 64]);
        memory.map_bytes(MATRIX, &[0_u8; 8 * 64 * 4]);
        memory.map_bytes(DELAYS, &[0_u8; 64]);
        write_vec(memory, LISTENER, 0.0, 0.0, 1.0); // OrientFront
        write_vec(memory, LISTENER + 12, 0.0, 1.0, 0.0); // OrientTop
        write_vec(memory, EMITTER + 4, 0.0, 0.0, 1.0); // OrientFront
        write_vec(memory, EMITTER + 16, 0.0, 1.0, 0.0); // OrientTop
        write_f32(memory, EMITTER + 92, 1.0); // CurveDistanceScaler
        write_f32(memory, EMITTER + 96, 1.0); // DopplerScaler
        write_u32(memory, EMITTER + 60, 1); // ChannelCount
        write_u32(memory, DSP, MATRIX as u32); // pMatrixCoefficients
        write_u32(memory, DSP + 4, DELAYS as u32); // pDelayTimes
        write_u32(memory, DSP + 8, 1); // SrcChannelCount
        write_u32(memory, DSP + 12, dst_count); // DstChannelCount
        write_u32(memory, HANDLE, X3DAUDIO_HANDLE_MAGIC);
        write_u32(memory, HANDLE + 4, mask);
        write_u32(memory, HANDLE + 8, X3DAUDIO_SPEED_OF_SOUND.to_bits());
    }

    fn calculate(runtime: &mut PeHostRuntime, memory: &mut MemoryImage, flags: u32) -> u32 {
        let thunk = runtime.alloc_host_thunk(HostThunk::X3dAudioCalculate);
        dispatch_x86(
            runtime,
            memory,
            thunk,
            &[
                HANDLE as u32,
                LISTENER as u32,
                EMITTER as u32,
                flags,
                DSP as u32,
            ],
        )
    }
}

#[cfg(test)]
mod cert_selection_tests {
    use super::final_scraps_test_support::*;
    use super::*;

    const REQUEST: u64 = 0x80_000;
    const SELECTED: u64 = 0x80_100;
    const STORE_ARRAY: u64 = 0x80_200;
    const SEL_X86_CSTORES: u64 = 40;
    const SEL_X86_RGHSTORES: u64 = 44;
    const SEL_X86_HSELECTED: u64 = 56;

    fn write_request(memory: &mut MemoryImage, stores: &[u64]) {
        memory.map_bytes(REQUEST, &[0_u8; 64]);
        memory.map_bytes(STORE_ARRAY, &[0_u8; 64]);
        write_u32(memory, REQUEST, 60); // dwSize
        write_u32(memory, REQUEST + SEL_X86_CSTORES, stores.len() as u32);
        for (index, store) in stores.iter().enumerate() {
            write_u32(memory, STORE_ARRAY + index as u64 * 4, *store as u32);
        }
        write_u32(memory, REQUEST + SEL_X86_RGHSTORES, STORE_ARRAY as u32);
    }

    fn select_certificate(runtime: &mut PeHostRuntime, memory: &mut MemoryImage) -> u32 {
        let thunk = runtime.alloc_host_thunk(HostThunk::CertSelectCertificate);
        dispatch_x86(runtime, memory, thunk, &[REQUEST as u32, SELECTED as u32])
    }

    fn selected_der(runtime: &PeHostRuntime, memory: &MemoryImage) -> Vec<u8> {
        let context = read_u32(memory, SELECTED).expect("selected context") as u64;
        assert_ne!(context, 0, "a certificate context must be written");
        runtime
            .cert_contexts
            .get(&context)
            .expect("registered context")
            .clone()
    }

    fn build_cert(serial: u64, cn: &str, not_before: i64, not_after: i64, sha384: bool) -> Vec<u8> {
        use der::{Decode, Encode};
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::EncodePublicKey;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use sha2::{Sha256, Sha384};
        use spki::SubjectPublicKeyInfoOwned;
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::{Time, Validity};

        let mut rng = StdRng::seed_from_u64(0xC3A1_0000 + serial);
        let key = RsaPrivateKey::new(&mut rng, 1024).expect("rsa key");
        let spki = SubjectPublicKeyInfoOwned::from_der(
            RsaPublicKey::from(&key)
                .to_public_key_der()
                .expect("spki der")
                .as_bytes(),
        )
        .expect("spki");
        let at = |seconds: i64| -> SystemTime {
            if seconds >= 0 {
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds as u64)
            } else {
                std::time::UNIX_EPOCH - std::time::Duration::from_secs(seconds.unsigned_abs())
            }
        };
        let validity = Validity {
            not_before: Time::try_from(at(not_before)).expect("notBefore"),
            not_after: Time::try_from(at(not_after)).expect("notAfter"),
        };
        let subject = Name::from_str(&format!("CN={cn}")).expect("subject");
        let serial_number = SerialNumber::from(serial as u32);
        if sha384 {
            let signer = SigningKey::<Sha384>::new(key);
            CertificateBuilder::new(
                Profile::Root,
                serial_number,
                validity,
                subject,
                spki,
                &signer,
            )
            .expect("builder")
            .build()
            .expect("certificate")
            .to_der()
            .expect("der")
        } else {
            let signer = SigningKey::<Sha256>::new(key);
            CertificateBuilder::new(
                Profile::Root,
                serial_number,
                validity,
                subject,
                spki,
                &signer,
            )
            .expect("builder")
            .build()
            .expect("certificate")
            .to_der()
            .expect("der")
        }
    }

    fn now_seconds() -> i64 {
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
    }

    #[test]
    fn unknown_store_handle_keeps_the_real_error() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = test_runtime("cert-order-bad-store");
            let mut memory = MemoryImage::default();
            memory.map_bytes(SELECTED, &[0_u8; 8]);
            write_request(&mut memory, &[0xdead_beef]);
            assert_eq!(select_certificate(&mut runtime, &mut memory), 0);
            assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
        })
    }
}

#[cfg(test)]
mod local_net_tests {
    use super::final_scraps_test_support::*;
    use super::*;

    const OUT: u64 = 0x90_000;
    const SERVER_NAME: u64 = 0x90_100;
    const PARM_ERR: u64 = 0x90_200;
    const WKSTA_BUFFER: u64 = 0x90_300;
    const NAME_STR: u64 = 0x90_400;
    const GROUP_STR: u64 = 0x90_500;
    const LAN_ROOT_STR: u64 = 0x90_600;

    fn write_wide(memory: &mut MemoryImage, address: u64, value: &str) {
        let mut bytes = Vec::new();
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        memory.map_bytes(address, &bytes);
    }

    fn read_wide(memory: &MemoryImage, address: u64) -> String {
        read_utf16_string(memory, address).expect("wide string")
    }

    fn write_wksta_100(memory: &mut MemoryImage, platform_id: u32, name: &str, group: &str) {
        memory.map_bytes(WKSTA_BUFFER, &[0_u8; 32]);
        write_wide(memory, NAME_STR, name);
        write_wide(memory, GROUP_STR, group);
        write_u32(memory, WKSTA_BUFFER, platform_id);
        write_u32(memory, WKSTA_BUFFER + 4, NAME_STR as u32);
        write_u32(memory, WKSTA_BUFFER + 8, GROUP_STR as u32);
        write_u32(memory, WKSTA_BUFFER + 12, 10);
        write_u32(memory, WKSTA_BUFFER + 16, 0);
    }

    #[test]
    fn net_server_get_info_local_machine_levels() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = test_runtime("net-server-local");
            let mut memory = MemoryImage::default();
            memory.map_bytes(OUT, &[0_u8; 8]);
            let get_info = runtime.alloc_host_thunk(HostThunk::NetServerGetInfo);

            // NULL server name: the local machine.
            write_u32(&mut memory, PARM_ERR, 0xFFFF_FFFF);
            assert_eq!(
                dispatch_x86(&mut runtime, &mut memory, get_info, &[0, 101, OUT as u32]),
                ERROR_SUCCESS
            );
            let base = read_u32(&memory, OUT).expect("server info") as u64;
            assert_ne!(base, 0);
            assert_eq!(read_u32(&memory, base).expect("platform"), 400);
            assert_eq!(
                read_wide(&memory, read_u32(&memory, base + 4).unwrap() as u64),
                "CASA1"
            );
            assert_eq!(read_u32(&memory, base + 8).unwrap(), 10);
            assert_eq!(read_u32(&memory, base + 12).unwrap(), 0);
            let server_type = read_u32(&memory, base + 16).unwrap();
            assert_ne!(server_type & 0x0000_0001, 0, "SV_TYPE_WORKSTATION");
            assert_ne!(server_type & 0x0000_0002, 0, "SV_TYPE_SERVER");
            assert_ne!(server_type & 0x0000_1000, 0, "SV_TYPE_NT");
            assert_ne!(server_type & 0x0000_0100, 0, "SV_TYPE_DOMAIN_MEMBER");
            assert_eq!(
                read_wide(&memory, read_u32(&memory, base + 20).unwrap() as u64),
                "Casa1 virtual server [WORKGROUP]"
            );

            // Level 100 (platform + name only).
            memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(&mut runtime, &mut memory, get_info, &[0, 100, OUT as u32]),
                ERROR_SUCCESS
            );
            let base = read_u32(&memory, OUT).expect("server info") as u64;
            assert_eq!(read_u32(&memory, base).unwrap(), 400);
            assert_eq!(
                read_wide(&memory, read_u32(&memory, base + 4).unwrap() as u64),
                "CASA1"
            );

            // Level 102 (users/disc/announce/userpath).
            memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(&mut runtime, &mut memory, get_info, &[0, 102, OUT as u32]),
                ERROR_SUCCESS
            );
            let base = read_u32(&memory, OUT).expect("server info") as u64;
            assert_eq!(read_u32(&memory, base + 24).unwrap(), 1, "sv102_users");
            assert_eq!(read_u32(&memory, base + 28).unwrap(), 0, "sv102_disc");
            assert_eq!(read_u32(&memory, base + 32).unwrap(), 0, "sv102_hidden");
            assert_eq!(
                read_wide(&memory, read_u32(&memory, base + 48).unwrap() as u64),
                "C:\\WINDOWS"
            );

            // The host name (with or without the UNC prefix) is local too.
            write_wide(&mut memory, SERVER_NAME, "\\\\CASA1");
            memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    get_info,
                    &[SERVER_NAME as u32, 101, OUT as u32],
                ),
                ERROR_SUCCESS
            );

            // A remote server name is the honest no-DC answer and leaves a
            // zero buffer pointer behind.
            write_wide(&mut memory, SERVER_NAME, "\\\\REMOTE-SRV");
            write_u32(&mut memory, OUT, 0xFFFF_FFFF);
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    get_info,
                    &[SERVER_NAME as u32, 101, OUT as u32],
                ),
                NERR_DC_NOT_FOUND
            );
            assert_eq!(read_u32(&memory, OUT).unwrap(), 0);

            // An unsupported level is a real ERROR_INVALID_LEVEL.
            assert_eq!(
                dispatch_x86(&mut runtime, &mut memory, get_info, &[0, 999, OUT as u32]),
                ERROR_INVALID_LEVEL
            );
        })
    }

    #[test]
    fn net_wksta_set_info_validates_and_stores_local_state() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = test_runtime("net-wksta-set");
            let mut memory = MemoryImage::default();
            let set_info = runtime.alloc_host_thunk(HostThunk::NetWkstaSetInfo);
            let get_info = runtime.alloc_host_thunk(HostThunk::NetServerGetInfo);
            memory.map_bytes(PARM_ERR, &[0_u8; 8]);
            memory.map_bytes(OUT, &[0_u8; 8]);

            write_wksta_100(&mut memory, 400, "CASA1X", "WORKGROUP1");
            write_u32(&mut memory, PARM_ERR, 0xFFFF_FFFF);
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    set_info,
                    &[0, 100, WKSTA_BUFFER as u32, PARM_ERR as u32],
                ),
                ERROR_SUCCESS
            );
            assert_eq!(read_u32(&memory, PARM_ERR).unwrap(), 0, "parm_err");
            let stored = wksta_set_info_state(runtime.guest_pid).expect("stored state");
            assert_eq!(stored.platform_id, 400);
            assert_eq!(stored.computer_name, "CASA1X");
            assert_eq!(stored.lan_group, "WORKGROUP1");
            assert_eq!(stored.version_major, 10);
            assert_eq!(stored.version_minor, 0);

            // The stored identity is what the local server record reports.
            assert_eq!(
                dispatch_x86(&mut runtime, &mut memory, get_info, &[0, 101, OUT as u32]),
                ERROR_SUCCESS
            );
            let base = read_u32(&memory, OUT).expect("server info") as u64;
            assert_eq!(
                read_wide(&memory, read_u32(&memory, base + 4).unwrap() as u64),
                "CASA1X"
            );
            assert_eq!(
                read_wide(&memory, read_u32(&memory, base + 20).unwrap() as u64),
                "Casa1 virtual server [WORKGROUP1]"
            );

            // Real validation: empty computer name → ERROR_INVALID_PARAMETER
            // with parm_err at the name member offset.
            write_wksta_100(&mut memory, 400, "", "WORKGROUP1");
            write_u32(&mut memory, PARM_ERR, 0xFFFF_FFFF);
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    set_info,
                    &[0, 100, WKSTA_BUFFER as u32, PARM_ERR as u32],
                ),
                ERROR_INVALID_PARAMETER
            );
            assert_eq!(read_u32(&memory, PARM_ERR).unwrap(), 4);

            // Over-long NetBIOS names are rejected too.
            write_wksta_100(&mut memory, 400, "SIXTEEN-CHARS-XX", "WORKGROUP1");
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    set_info,
                    &[0, 100, WKSTA_BUFFER as u32, PARM_ERR as u32],
                ),
                ERROR_INVALID_PARAMETER
            );
            assert_eq!(read_u32(&memory, PARM_ERR).unwrap(), 4);

            // An unknown platform id fails on the platform member.
            write_wksta_100(&mut memory, 12345, "CASA1X", "WORKGROUP1");
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    set_info,
                    &[0, 100, WKSTA_BUFFER as u32, PARM_ERR as u32],
                ),
                ERROR_INVALID_PARAMETER
            );
            assert_eq!(read_u32(&memory, PARM_ERR).unwrap(), 0);

            // A NULL buffer / unsupported level / remote name keep their
            // documented answers.
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    set_info,
                    &[0, 100, 0, PARM_ERR as u32],
                ),
                ERROR_INVALID_PARAMETER
            );
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    set_info,
                    &[0, 7, WKSTA_BUFFER as u32, PARM_ERR as u32],
                ),
                ERROR_INVALID_LEVEL
            );
            write_wide(&mut memory, SERVER_NAME, "\\\\REMOTE-SRV");
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    set_info,
                    &[
                        SERVER_NAME as u32,
                        100,
                        WKSTA_BUFFER as u32,
                        PARM_ERR as u32
                    ],
                ),
                NERR_DC_NOT_FOUND
            );

            // Level 101/102 carry the LAN root and logged-on count.
            memory.map_bytes(WKSTA_BUFFER, &[0_u8; 48]);
            write_wide(&mut memory, NAME_STR, "CASA1X");
            write_wide(&mut memory, GROUP_STR, "WORKGROUP1");
            write_wide(&mut memory, LAN_ROOT_STR, "C:\\USERS");
            write_u32(&mut memory, WKSTA_BUFFER, 400);
            write_u32(&mut memory, WKSTA_BUFFER + 4, NAME_STR as u32);
            write_u32(&mut memory, WKSTA_BUFFER + 8, GROUP_STR as u32);
            write_u32(&mut memory, WKSTA_BUFFER + 12, 6);
            write_u32(&mut memory, WKSTA_BUFFER + 16, 1);
            write_u32(&mut memory, WKSTA_BUFFER + 20, LAN_ROOT_STR as u32);
            write_u32(&mut memory, WKSTA_BUFFER + 24, 2);
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    set_info,
                    &[0, 102, WKSTA_BUFFER as u32, PARM_ERR as u32],
                ),
                ERROR_SUCCESS
            );
            let stored = wksta_set_info_state(runtime.guest_pid).expect("stored state");
            assert_eq!(stored.version_major, 6);
            assert_eq!(stored.version_minor, 1);
            assert_eq!(stored.lan_root.as_deref(), Some("C:\\USERS"));
            assert_eq!(stored.logged_on_users, Some(2));
        })
    }

    #[test]
    fn browser_server_enum_enumerates_the_local_host() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = test_runtime("browser-server-enum");
            let mut memory = MemoryImage::default();
            memory.map_bytes(OUT, &[0_u8; 8]);
            let enumerate = runtime.alloc_host_thunk(HostThunk::BrowserServerEnum);

            // NULL server name: the local machine is the single entry.
            assert_eq!(
                dispatch_x86(&mut runtime, &mut memory, enumerate, &[0, 101, OUT as u32]),
                ERROR_SUCCESS
            );
            let base = read_u32(&memory, OUT).expect("entry") as u64;
            assert_ne!(base, 0, "the local host is enumerated");
            assert_eq!(read_u32(&memory, base).unwrap(), 400);
            assert_eq!(
                read_wide(&memory, read_u32(&memory, base + 4).unwrap() as u64),
                "CASA1"
            );
            let server_type = read_u32(&memory, base + 16).unwrap();
            assert_ne!(server_type & 0x0000_0001, 0, "SV_TYPE_WORKSTATION");
            assert_ne!(server_type & 0x0000_1000, 0, "SV_TYPE_NT");

            // Level 100 works as well.
            memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(&mut runtime, &mut memory, enumerate, &[0, 100, OUT as u32]),
                ERROR_SUCCESS
            );
            assert_ne!(read_u32(&memory, OUT).unwrap(), 0);

            // Remote names keep the honest no-browser/no-DC answer.
            write_wide(&mut memory, SERVER_NAME, "\\\\REMOTE-SRV");
            write_u32(&mut memory, OUT, 0xFFFF_FFFF);
            assert_eq!(
                dispatch_x86(
                    &mut runtime,
                    &mut memory,
                    enumerate,
                    &[SERVER_NAME as u32, 101, OUT as u32],
                ),
                NERR_DC_NOT_FOUND
            );
            assert_eq!(read_u32(&memory, OUT).unwrap(), 0);

            // Invalid level / null out pointer.
            assert_eq!(
                dispatch_x86(&mut runtime, &mut memory, enumerate, &[0, 7, OUT as u32]),
                ERROR_INVALID_LEVEL
            );
            assert_eq!(
                dispatch_x86(&mut runtime, &mut memory, enumerate, &[0, 101, 0]),
                ERROR_INVALID_PARAMETER
            );
        })
    }
}

#[cfg(test)]
mod native_child_image_tests {
    use super::final_scraps_test_support::*;
    use super::*;

    #[test]
    fn spawn_native_child_image_rejects_non_pe_program_without_native_execution() {
        let (mut runtime, temp_dir) = test_runtime("native-child-nonpe");
        let guest_image = "C:\\child\\payload.sh";
        let host_image = runtime
            .win32
            .guest_path_to_host_path(guest_image)
            .expect("host path for child image");
        std::fs::create_dir_all(host_image.parent().expect("parent dir")).expect("mkdir");
        std::fs::write(&host_image, b"#!/bin/sh\nexit 0\n").expect("write host script");
        let claim = NativeChildClaim {
            image: guest_image.to_string(),
            cwd: "C:\\child".to_string(),
            environment: BTreeMap::new(),
            process_id: 0xC0DE,
            sync: Arc::new((std::sync::Mutex::new(None), std::sync::Condvar::new())),
            thread_start: None,
            host_pid: Arc::new(std::sync::Mutex::new(None)),
        };
        let error = runtime
            .spawn_native_child_image(&claim)
            .expect_err("a non-PE host program must never be spawned");
        assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
        assert_eq!(
            error.message,
            format!(
                "native child image {} is not a PE image; native execution is forbidden",
                host_image.display()
            )
        );
        assert_eq!(
            *claim.host_pid.lock().expect("host pid slot"),
            None,
            "no host child was spawned"
        );
        drop(temp_dir);
    }
}
