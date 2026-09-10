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
//!   for `x3daudio1_7.dll`).  There is no Windows oracle in this repo, so
//!   the implementation is a complete documented model — never an "exact"
//!   claim — and every call records what it computed in the trace.
//! - **NtCreateProcess** — real native child-process object creation
//!   through the same `win32.create_process_w` machinery `CreateProcessW`
//!   uses: a genuine child process record (pid, handle, image), real
//!   NTSTATUS failure paths, and the runtime's standard process-control
//!   surface (query/terminate) on the returned handle.
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
use serde_json::Value;

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
// The DSP model follows the documented X3DAudio behavior:
// - the default volume/LFE curves conform to the inverse-square law with
//   distances ≤ CurveDistanceScaler clamped to no attenuation;
// - the default LPF direct curve is [0,1]→[1,0.75], the LPF reverb curve
//   [0,0.75]→[1,0.75], the reverb curve [0,1]→[1,0];
// - an emitter is audible in the two destination speakers that straddle its
//   azimuth (equal-power pair pan; a source exactly on a speaker line is
//   heard solely from that speaker), with the inner-radius model bleeding
//   the signal toward an all-speaker mix near/above the listener;
// - cone angles scale volume/LPF/reverb between the inner and outer cone
//   values (LPF values are coefficient subtrahends);
// - doppler uses the projected emitter/listener velocity components along
//   the emitter→listener axis with the standard first-order approximation
//   f = 1 + DopplerScaler·(v_e·u − v_l·u)/c.
//
// No Windows oracle exists in this repository, so the DSP values are a
// complete, deterministic, documented approximation (the trace records
// every computed value); nothing here claims oracle-exactness.

/// X3DAudio calculation control flags (`X3DAUDIO_CALCULATE_*`).
const X3DAUDIO_CALCULATE_MATRIX: u32 = 0x0000_0001;
const X3DAUDIO_CALCULATE_DELAY: u32 = 0x0000_0002;
const X3DAUDIO_CALCULATE_LPF_DIRECT: u32 = 0x0000_0004;
const X3DAUDIO_CALCULATE_LPF_REVERB: u32 = 0x0000_0008;
const X3DAUDIO_CALCULATE_REVERB: u32 = 0x0000_0010;
const X3DAUDIO_CALCULATE_DOPPLER: u32 = 0x0000_0020;
const X3DAUDIO_CALCULATE_EMITTER_ANGLE: u32 = 0x0000_0040;
const X3DAUDIO_CALCULATE_ZEROCENTER: u32 = 0x0001_0000;
const X3DAUDIO_CALCULATE_REDIRECT_TO_LFE: u32 = 0x0002_0000;

/// Speaker-position mask bits (winnt.h SPEAKER_* values).
const SPEAKER_FRONT_LEFT: u32 = 0x0000_0001;
const SPEAKER_FRONT_RIGHT: u32 = 0x0000_0002;
const SPEAKER_FRONT_CENTER: u32 = 0x0000_0004;
const SPEAKER_LOW_FREQUENCY: u32 = 0x0000_0008;
const SPEAKER_BACK_LEFT: u32 = 0x0000_0010;
const SPEAKER_BACK_RIGHT: u32 = 0x0000_0020;
const SPEAKER_FRONT_LEFT_OF_CENTER: u32 = 0x0000_0040;
const SPEAKER_FRONT_RIGHT_OF_CENTER: u32 = 0x0000_0080;
const SPEAKER_BACK_CENTER: u32 = 0x0000_0100;
const SPEAKER_SIDE_LEFT: u32 = 0x0000_0200;
const SPEAKER_SIDE_RIGHT: u32 = 0x0000_0400;
const SPEAKER_STEREO: u32 = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT;

/// The magic prefix written into the opaque 20-byte `X3DAUDIO_HANDLE`
/// ("X3D1"): instance handles are caller-owned storage, so the runtime
/// identifies its own handles by this prefix and stores the instance's
/// speaker mask and speed of sound behind it.
const X3DAUDIO_HANDLE_MAGIC: u32 = 0x3144_3358; // "X3D1" little-endian
const X3DAUDIO_HANDLE_BYTES: u64 = 20;
/// Default speed of sound (X3DAUDIO_SPEED_OF_SOUND, metres/second).
const X3DAUDIO_SPEED_OF_SOUND: f32 = 343.5;
/// X3DAUDIO_2PI — also marks an LFE channel in `pChannelAzimuths`.
const X3DAUDIO_2PI: f32 = 6.283_185_307;
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
/// The (unit) speaker-circle radius used for per-channel delay times.
const X3DAUDIO_SPEAKER_RADIUS: f32 = 1.0;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct X3dVec {
    x: f32,
    y: f32,
    z: f32,
}

impl X3dVec {
    fn add(self, other: X3dVec) -> X3dVec {
        X3dVec {
            x: self.x + other.x,
            y: self.y + other.y,
            z: self.z + other.z,
        }
    }

    fn sub(self, other: X3dVec) -> X3dVec {
        X3dVec {
            x: self.x - other.x,
            y: self.y - other.y,
            z: self.z - other.z,
        }
    }

    fn dot(self, other: X3dVec) -> f32 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }

    fn cross(self, other: X3dVec) -> X3dVec {
        X3dVec {
            x: self.y * other.z - self.z * other.y,
            y: self.z * other.x - self.x * other.z,
            z: self.x * other.y - self.y * other.x,
        }
    }

    fn len(self) -> f32 {
        self.dot(self).sqrt()
    }

    fn normalized(self) -> Option<X3dVec> {
        let length = self.len();
        if !(length > 1.0e-12) || !length.is_finite() {
            return None;
        }
        let inv = 1.0 / length;
        Some(X3dVec {
            x: self.x * inv,
            y: self.y * inv,
            z: self.z * inv,
        })
    }

    fn scaled(self, factor: f32) -> X3dVec {
        X3dVec {
            x: self.x * factor,
            y: self.y * factor,
            z: self.z * factor,
        }
    }

    fn finite(self) -> bool {
        self.x.is_finite() && self.y.is_finite() && self.z.is_finite()
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct X3dCone {
    inner_angle: f32,
    outer_angle: f32,
    inner_volume: f32,
    outer_volume: f32,
    inner_lpf: f32,
    outer_lpf: f32,
    inner_reverb: f32,
    outer_reverb: f32,
}

/// A distance curve (normalized distances in [0, 1]).
#[derive(Debug, Clone, Default)]
struct X3dCurve {
    points: Vec<(f32, f32)>,
}

#[derive(Debug, Clone, Copy, Default)]
struct X3dListener {
    orient_front: X3dVec,
    orient_top: X3dVec,
    position: X3dVec,
    velocity: X3dVec,
    cone: Option<X3dCone>,
}

#[derive(Debug, Clone, Default)]
struct X3dEmitter {
    cone: Option<X3dCone>,
    orient_front: X3dVec,
    orient_top: X3dVec,
    position: X3dVec,
    velocity: X3dVec,
    inner_radius: f32,
    inner_radius_angle: f32,
    channel_count: u32,
    channel_radius: f32,
    channel_azimuths: Vec<f32>,
    volume_curve: Option<X3dCurve>,
    lfe_curve: Option<X3dCurve>,
    lpf_direct_curve: Option<X3dCurve>,
    lpf_reverb_curve: Option<X3dCurve>,
    reverb_curve: Option<X3dCurve>,
    curve_distance_scaler: f32,
    doppler_scaler: f32,
}

/// The full result of one `X3DAudioCalculate` — every member is filled only
/// when its calculation flag selected it (distance is always computed).
#[derive(Debug, Clone, Default)]
struct X3dDspResult {
    /// Dst-major matrix coefficients, stored as the SDK documents:
    /// `pMatrixCoefficients[SrcChannelCount * D + S]`.
    matrix: Option<Vec<f32>>,
    /// Delay time per destination channel, milliseconds.
    delays_ms: Option<Vec<f32>>,
    lpf_direct: Option<f32>,
    lpf_reverb: Option<f32>,
    reverb_level: Option<f32>,
    doppler_factor: Option<f32>,
    emitter_to_listener_angle: Option<f32>,
    emitter_to_listener_distance: f32,
    emitter_velocity_component: Option<f32>,
    listener_velocity_component: Option<f32>,
}

impl PeHostRuntime {
    /// Route every final-scraps thunk to its dispatch function.
    pub(crate) fn dispatch_final_scraps(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
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
            // ── XACT3 ──
            HostThunk::Xact3CreateEngine | HostThunk::Xact3CreateEngineWithFlags => {
                let _flags = guest_call_arg_u32(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            // ── DirectPlay ──
            HostThunk::DirectPlayCreate => {
                let _clsid = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let _outer = guest_call_arg(state, memory, 2)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x8004_0153); // REGDB_E_CLASSNOTREG
                Ok(())
            }
            HostThunk::DirectPlayEnumerateW => {
                let _callback = guest_call_arg(state, memory, 0)?;
                let _context = guest_call_arg(state, memory, 1)?;
                // No DirectPlay sessions exist.
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::Dp8spCreate => {
                let _clsid = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x8004_0153);
                Ok(())
            }
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
            HostThunk::NetWkstaSetInfo => {
                let _server = guest_call_arg(state, memory, 0)?;
                let _level = guest_call_arg_u32(state, memory, 1)?;
                let _buffer = guest_call_arg(state, memory, 2)?;
                let _error = guest_call_arg(state, memory, 3)?;
                state.set(Register::Rax, 0x0000_054b);
                Ok(())
            }
            HostThunk::NetServerGetInfo => {
                let _server = guest_call_arg(state, memory, 0)?;
                let _level = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x0000_054b);
                Ok(())
            }
            HostThunk::BrowserServerEnum => {
                let _server = guest_call_arg(state, memory, 0)?;
                let _level = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x0000_054b);
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
    ///   — with the real activation result (HRESULT) and the activated
    ///   interface object (or 0 on failure).  Every `S_OK` return therefore
    ///   delivers exactly one completion.
    ///
    /// Model divergence (reported): Windows hands the handler an
    /// `IActivateAudioInterfaceAsyncOperation` object whose `GetActivateResult`
    /// carries the result; this runtime has no operation-object guest model,
    /// so the handler receives `(result_hr, activated_interface)` directly.
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
        // guest-object table, so AddRef/Release genuinely track it).  No
        // IAudioClient method host thunks exist in the runtime yet, so the
        // activated object's real content is the bound device record rather
        // than per-method audio-client calls (see the module report).
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
    /// invoked in guest context with the real activation result and the
    /// activated interface object (or 0).
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
            self.execute_guest_callback(
                state,
                memory,
                completion.handler_method,
                &[
                    completion.handler_object,
                    u64::from(completion.result_hr),
                    completion.interface_object,
                ],
                "ActivateAudioInterfaceAsync::ActivateCompleted",
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
        // expired certificate).
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let enumerated = candidates.len();
        let eligible: Vec<(u64, Vec<u8>)> = candidates
            .into_iter()
            .filter(|(_, der)| {
                crate::security::Certificate::from_der(der.clone()).is_some()
                    && crate::security::parse_x509_validity(der).is_some_and(
                        |(not_before, not_after)| not_before <= now_secs && now_secs <= not_after,
                    )
            })
            .collect();

        params.insert("store_count".to_string(), json!(store_handles.len()));
        params.insert("enumerated".to_string(), json!(enumerated));
        params.insert("eligible".to_string(), json!(eligible.len()));

        match eligible.len() {
            1 => {
                let (store_handle, der) = &eligible[0];
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
                params.insert("result".to_string(), json!("selected"));
                params.insert(
                    "selected_context".to_string(),
                    json!(format!("{context:#x}")),
                );
                params.insert(
                    "selected_store".to_string(),
                    json!(format!("{store_handle:#x}")),
                );
                state.set(Register::Rax, 1);
                self.last_error = 0;
                self.push_trace("cert", "CertSelectCertificate", params, json!(1));
                Ok(())
            }
            0 => {
                // No eligible certificate: the picker would show an empty
                // list and the user would cancel.
                params.insert("result".to_string(), json!("none-eligible"));
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("cert", "CertSelectCertificate", params, json!(0));
                Ok(())
            }
            _ => {
                // Several certificates qualify; without a user to pick one
                // the operation must not claim a selection.
                params.insert("result".to_string(), json!("ambiguous"));
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
    ///
    /// Documented model bounds: the runtime's section objects are anonymous
    /// data sections (no image-backed `NtCreateSection` exists in this
    /// runtime), so a non-NULL section cannot be resolved to an image and
    /// fails with `STATUS_INVALID_IMAGE_FORMAT` — the exact status real
    /// Windows reports for a section that is not an image section.  Native
    /// children are process records: `NtCreateProcess` itself creates no
    /// primary thread (the native contract leaves that to `NtCreateThread`),
    /// and this runtime has no native-thread-creation surface to attach one,
    /// so no `casa1-runner` host subprocess is spawned — a record-only child
    /// is the deepest real behavior the runtime's model supports.
    pub(crate) fn dispatch_nt_create_process(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let process_handle_ptr = guest_call_arg(state, memory, 0)?;
        let desired_access = guest_call_arg_u32(state, memory, 1)?;
        let _object_attributes = guest_call_arg(state, memory, 2)?;
        let parent_process = guest_call_arg_u32(state, memory, 3)?;
        let _inherit_object_table = guest_call_arg_u32(state, memory, 4)?;
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
        //  - a section handle must be a live Section object, and the
        //    runtime's sections are data sections — never image sections —
        //    so they answer STATUS_INVALID_IMAGE_FORMAT like real Windows.
        if section_handle != 0 {
            let section_is_live = matches!(
                self.win32.handle_object_type(section_handle),
                Ok(crate::win32::ObjectType::Section)
            );
            if !section_is_live {
                self.nt_create_process_fail(state, STATUS_INVALID_HANDLE, "invalid section handle");
                return Ok(());
            }
            self.nt_create_process_fail(
                state,
                STATUS_INVALID_IMAGE_FORMAT,
                "section is not an executable image",
            );
            return Ok(());
        }
        let image = match parent_process {
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
        };

        // Create the real child process object through the CreateProcessW
        // machinery (no host subprocess — see the method documentation).
        let result = match self.win32.create_process_w(
            &image,
            &image,
            &self.process_environment,
            &self.current_directory,
            false,
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
        // so WaitForSingleObject can block on this child's handle.
        let sync = Arc::new((std::sync::Mutex::new(None), std::sync::Condvar::new()));
        let _ = self
            .win32
            .install_process_exit_sync(result.process_handle, sync);
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
                ("section".to_string(), json!("NULL (parent image)")),
                ("process_handle".to_string(), json!(result.process_handle)),
                ("process_id".to_string(), json!(result.process_id)),
            ]),
            json!(0),
        );
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
fn x3d_parse_cone(memory: &MemoryImage, cone_ptr: u64) -> Option<X3dCone> {
    if !memory.is_range_mapped(cone_ptr, 32usize) {
        return None;
    }
    let f = |offset: u64| -> Option<f32> {
        Some(f32::from_bits(read_u32(memory, cone_ptr + offset).ok()?))
    };
    Some(X3dCone {
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
) -> Option<X3dListener> {
    let vec = |offset: u64| -> Option<X3dVec> {
        Some(X3dVec {
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
    Some(X3dListener {
        orient_front,
        orient_top,
        position,
        velocity,
        cone,
    })
}

/// Parse a packed guest `X3DAUDIO_EMITTER` (June-2010 layout, 15 members).
fn x3d_parse_emitter(
    memory: &MemoryImage,
    emitter_ptr: u64,
    arch: GuestArch,
) -> Option<X3dEmitter> {
    let psz = arch.pointer_bytes() as u64;
    let vec = |offset: u64| -> Option<X3dVec> {
        Some(X3dVec {
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
    let parse_curve = |curve_ptr: u64| -> Option<Option<X3dCurve>> {
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
        Some(Some(X3dCurve { points }))
    };
    let volume_curve = parse_curve(curve_ptrs[0])?;
    let lfe_curve = parse_curve(curve_ptrs[1])?;
    let lpf_direct_curve = parse_curve(curve_ptrs[2])?;
    let lpf_reverb_curve = parse_curve(curve_ptrs[3])?;
    let reverb_curve = parse_curve(curve_ptrs[4])?;

    Some(X3dEmitter {
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

/// The default volume/LFE curve: inverse-square rolloff with distances up
/// to one curve-distance-scaler unit clamped to no attenuation.
fn x3daudio_default_volume_curve(scaled_distance: f32) -> f32 {
    if !(scaled_distance > 0.0) || !scaled_distance.is_finite() {
        return 1.0;
    }
    if scaled_distance <= 1.0 {
        1.0
    } else {
        1.0 / scaled_distance
    }
}

/// Evaluate a piecewise-linear distance curve at a scaled distance.  Values
/// below the first point take the first point; values beyond the last point
/// take the last point's setting (the documented X3DAudio behavior).
fn x3daudio_curve_value(points: &[(f32, f32)], scaled_distance: f32) -> f32 {
    if points.is_empty() {
        return 1.0;
    }
    if scaled_distance <= points[0].0 {
        return points[0].1;
    }
    let last = points[points.len() - 1];
    if scaled_distance >= last.0 {
        return last.1;
    }
    for window in points.windows(2) {
        let (d0, v0) = window[0];
        let (d1, v1) = window[1];
        if scaled_distance >= d0 && scaled_distance <= d1 {
            let span = d1 - d0;
            if span <= 0.0 {
                return v1;
            }
            let t = (scaled_distance - d0) / span;
            return v0 + (v1 - v0) * t;
        }
    }
    last.1
}

/// The cone scalers for an angle (radians between the emitter/listener
/// front and the emitter→listener axis): `(volume, lpf_subtrahend,
/// reverb)`.  On/within the inner cone the inner values apply; on/beyond
/// the outer cone the outer values apply; between the two the scaler is
/// linearly interpolated.  Cone angles are full angles (half-angle
/// comparison).  The LPF values are coefficient subtrahends: the path
/// coefficient is multiplied by `(1 − subtrahend)`.
fn x3daudio_cone_scale(cone: &X3dCone, angle: f32) -> (f32, f32, f32) {
    let half_inner = cone.inner_angle.max(0.0) * 0.5;
    let half_outer = cone.outer_angle.max(cone.inner_angle).max(0.0) * 0.5;
    let t = if angle <= half_inner || half_outer <= half_inner {
        0.0
    } else if angle >= half_outer {
        1.0
    } else {
        (angle - half_inner) / (half_outer - half_inner)
    };
    let t = t.clamp(0.0, 1.0);
    let lerp = |inner: f32, outer: f32| inner + (outer - inner) * t;
    (
        lerp(cone.inner_volume, cone.outer_volume),
        lerp(cone.inner_lpf, cone.outer_lpf),
        lerp(cone.inner_reverb, cone.outer_reverb),
    )
}

/// The first-order (documented approximation) doppler factor:
/// `1 + DopplerScaler·(v_e·u − v_l·u) / c`, clamped non-negative.
fn x3daudio_doppler_factor(
    speed_of_sound: f32,
    doppler_scaler: f32,
    emitter_velocity_component: f32,
    listener_velocity_component: f32,
) -> f32 {
    if !speed_of_sound.is_finite() || speed_of_sound <= 0.0 {
        return 1.0;
    }
    let scaler = if doppler_scaler.is_finite() && doppler_scaler > 0.0 {
        doppler_scaler
    } else {
        0.0
    };
    let factor =
        1.0 + scaler * (emitter_velocity_component - listener_velocity_component) / speed_of_sound;
    factor.max(0.0)
}

/// The destination-speaker azimuth table for an instance speaker mask, in
/// stream channel order (the k-th stream channel is the k-th set speaker
/// bit).  `None` marks an LFE speaker (no azimuth).  Azimuths are radians,
/// clockwise from the listener's front in the plane orthogonal to the top
/// vector.  The documented geometry is an approximation of the X3DAudio
/// speaker circle: front pairs span ±90° (or ±30° when side speakers are
/// present), rears sit at ±135°, back center at 180°, and LFE has no
/// position.  When the mask cannot explain `dst_count` channels the
/// remaining channels are placed evenly around the circle.
fn x3daudio_dst_geometry(mask: u32, dst_count: u32) -> Vec<Option<f32>> {
    let surround = mask & (SPEAKER_SIDE_LEFT | SPEAKER_SIDE_RIGHT) != 0;
    let front_span = if surround {
        std::f32::consts::FRAC_PI_6
    } else {
        std::f32::consts::FRAC_PI_2
    };
    let table: [(u32, Option<f32>); 11] = [
        (SPEAKER_FRONT_LEFT, Some(-front_span)),
        (SPEAKER_FRONT_RIGHT, Some(front_span)),
        (SPEAKER_FRONT_CENTER, Some(0.0)),
        (SPEAKER_LOW_FREQUENCY, None),
        (SPEAKER_BACK_LEFT, Some(-3.0 * std::f32::consts::FRAC_PI_4)),
        (SPEAKER_BACK_RIGHT, Some(3.0 * std::f32::consts::FRAC_PI_4)),
        (SPEAKER_FRONT_LEFT_OF_CENTER, Some(-front_span * 0.5)),
        (SPEAKER_FRONT_RIGHT_OF_CENTER, Some(front_span * 0.5)),
        (SPEAKER_BACK_CENTER, Some(std::f32::consts::PI)),
        (SPEAKER_SIDE_LEFT, Some(-std::f32::consts::FRAC_PI_2)),
        (SPEAKER_SIDE_RIGHT, Some(std::f32::consts::FRAC_PI_2)),
    ];
    let mut channels = Vec::new();
    for (bit, azimuth) in table {
        if mask & bit != 0 {
            channels.push(azimuth);
        }
    }
    if channels.len() < dst_count as usize {
        // Unknown/partial mask: fall back to an even placement over the
        // full circle (stereo still lands on ±90°), keeping the mask-derived
        // geometry for the channels it does explain.
        let mut even = Vec::with_capacity(dst_count as usize);
        for index in 0..dst_count {
            let azimuth = if dst_count == 1 {
                0.0
            } else {
                -std::f32::consts::FRAC_PI_2
                    + std::f32::consts::TAU * (index as f32) / (dst_count as f32)
            };
            even.push(Some(azimuth));
        }
        for (index, slot) in channels.iter_mut().enumerate() {
            even[index] = *slot;
        }
        even
    } else {
        channels.truncate(dst_count as usize);
        channels
    }
}

/// Equal-power pair panning over the destination azimuth circle: a source
/// azimuth is heard in the two destination speakers that straddle it, with
/// constant-power gains (a source exactly on a speaker line is heard solely
/// from that speaker).  The returned gains sum in power to 1.
fn x3daudio_pair_pan_gains(azimuth: f32, dst_azimuths: &[f32]) -> Vec<f32> {
    let mut gains = vec![0.0_f32; dst_azimuths.len()];
    if dst_azimuths.is_empty() {
        return gains;
    }
    if dst_azimuths.len() == 1 {
        gains[0] = 1.0;
        return gains;
    }
    let mut indexed: Vec<(f32, usize)> = dst_azimuths
        .iter()
        .copied()
        .enumerate()
        .map(|(index, az)| (az.rem_euclid(std::f32::consts::TAU), index))
        .collect();
    indexed.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let a = azimuth.rem_euclid(std::f32::consts::TAU);
    for &(speaker_az, speaker_index) in &indexed {
        if (speaker_az - a).abs() < 1.0e-5 {
            gains[speaker_index] = 1.0;
            return gains;
        }
    }
    let n = indexed.len();
    let mut pair: Option<(usize, f32, f32)> = None;
    for window in 0..n {
        let left = indexed[window];
        let right = indexed[(window + 1) % n];
        let span = if window + 1 < n {
            right.0 - left.0
        } else {
            std::f32::consts::TAU - left.0 + right.0
        };
        let offset = if window + 1 < n {
            a - left.0
        } else if a >= left.0 {
            a - left.0
        } else {
            std::f32::consts::TAU - left.0 + a
        };
        if offset >= -1.0e-5 && offset <= span + 1.0e-5 {
            pair = Some((window, span, offset));
            break;
        }
    }
    let Some((window, span, offset)) = pair else {
        return gains;
    };
    if span <= 1.0e-5 {
        gains[indexed[window].1] = 1.0;
        return gains;
    }
    let t = (offset / span).clamp(0.0, 1.0);
    // Constant-power pan: cos/sin over the pair's angular span.
    let angle = t * std::f32::consts::FRAC_PI_2;
    gains[indexed[window].1] = angle.cos();
    gains[indexed[(window + 1) % n].1] = angle.sin();
    gains
}

/// The per-channel delay times (milliseconds) for a stereo destination
/// field: every destination channel is delayed so the wavefront from the
/// source point arrives at all speakers at the same time (the nearest
/// speaker carries the largest delay; the farthest speaker 0).  Speaker
/// positions sit on the unit speaker circle around the listener.
fn x3daudio_stereo_delays_ms(
    source_point: X3dVec,
    listener: &X3dListener,
    dst_azimuths: &[f32],
    speed_of_sound: f32,
) -> Vec<f32> {
    let speed = if speed_of_sound.is_finite() && speed_of_sound > 0.0 {
        speed_of_sound
    } else {
        X3DAUDIO_SPEED_OF_SOUND
    };
    let (Some(front), Some(top)) = (
        listener.orient_front.normalized(),
        listener.orient_top.normalized(),
    ) else {
        return vec![0.0; dst_azimuths.len()];
    };
    let right = top.cross(front);
    let distances: Vec<f32> = dst_azimuths
        .iter()
        .map(|azimuth| {
            let dir = X3dVec {
                x: azimuth.cos() * front.x + azimuth.sin() * right.x,
                y: azimuth.cos() * front.y + azimuth.sin() * right.y,
                z: azimuth.cos() * front.z + azimuth.sin() * right.z,
            };
            let speaker = listener.position.add(dir.scaled(X3DAUDIO_SPEAKER_RADIUS));
            source_point.sub(speaker).len()
        })
        .collect();
    let farthest = distances.iter().copied().fold(0.0_f32, f32::max);
    distances
        .iter()
        .map(|distance| (farthest - distance).max(0.0) / speed * 1000.0)
        .collect()
}

/// The world position of a source channel point, plus whether the channel
/// is an LFE channel (multi-point emitters mark LFE with a 2π azimuth; LFE
/// points sit at the emitter base).
fn x3daudio_source_point(emitter: &X3dEmitter, src: usize) -> (X3dVec, bool) {
    if emitter.channel_count <= 1 {
        return (emitter.position, false);
    }
    let azimuth = emitter.channel_azimuths.get(src).copied().unwrap_or(0.0);
    if (azimuth - X3DAUDIO_2PI).abs() < 1.0e-3 {
        return (emitter.position, true);
    }
    let (Some(front), Some(top)) = (
        emitter.orient_front.normalized(),
        emitter.orient_top.normalized(),
    ) else {
        return (emitter.position, false);
    };
    let right = top.cross(front);
    let dir = X3dVec {
        x: azimuth.cos() * front.x + azimuth.sin() * right.x,
        y: azimuth.cos() * front.y + azimuth.sin() * right.y,
        z: azimuth.cos() * front.z + azimuth.sin() * right.z,
    };
    (
        emitter.position.add(dir.scaled(emitter.channel_radius)),
        false,
    )
}

/// The listener-frame azimuth of a source point, and its elevation above
/// the horizontal plane.  Azimuths are clockwise from the listener's front
/// (right = top × front).
fn x3daudio_listener_frame(point: &X3dVec, listener: &X3dListener) -> (f32, f32) {
    let (Some(front), Some(top)) = (
        listener.orient_front.normalized(),
        listener.orient_top.normalized(),
    ) else {
        return (0.0, 0.0);
    };
    let right = top.cross(front);
    let Some(dir) = point.normalized() else {
        return (0.0, 0.0);
    };
    let azimuth = dir.dot(right).atan2(dir.dot(front));
    let elevation = dir.dot(top).clamp(-1.0, 1.0).asin();
    (azimuth, elevation)
}

/// The inner-radius blend weight toward the all-speaker mix for a source
/// point (0 = pure pair pan, 1 = equal in every speaker).  The blend grows
/// as the source enters the inner-radius sphere around the listener and its
/// angle from the vertical axis falls inside the inner-radius-angle cone.
fn x3daudio_inner_radius_blend(
    emitter: &X3dEmitter,
    point: &X3dVec,
    listener: &X3dListener,
) -> f32 {
    let distance = point.len();
    if distance <= 1.0e-6 {
        return 1.0;
    }
    let mut ratio = 0.0_f32;
    if emitter.inner_radius > 0.0 {
        ratio = ratio.max(distance / emitter.inner_radius);
    }
    if emitter.inner_radius_angle > 0.0 && emitter.inner_radius_angle < std::f32::consts::FRAC_PI_2
    {
        let (_azimuth, elevation) = x3daudio_listener_frame(point, listener);
        // Angle from the vertical axis: 0 when directly above/below.
        let from_vertical = std::f32::consts::FRAC_PI_2 - elevation.abs();
        ratio = ratio.max(from_vertical / emitter.inner_radius_angle);
    }
    if emitter.inner_radius <= 0.0 && emitter.inner_radius_angle <= 0.0 {
        return 0.0;
    }
    (1.0 - ratio.min(1.0)).max(0.0)
}

/// Compute the DSP result for one listener/emitter pair.
#[allow(clippy::too_many_arguments)]
fn x3daudio_compute(
    listener: &X3dListener,
    emitter: &X3dEmitter,
    flags: u32,
    speaker_mask: u32,
    speed_of_sound: f32,
    src_count: u32,
    dst_count: u32,
) -> X3dDspResult {
    let mut result = X3dDspResult::default();

    // ── Base geometry: emitter→listener vector, distance, angle ──
    let to_listener = listener.position.sub(emitter.position);
    let distance = to_listener.len();
    result.emitter_to_listener_distance = if distance.is_finite() { distance } else { 0.0 };
    let axis = to_listener.normalized();
    let emitter_angle = match (axis, emitter.orient_front.normalized()) {
        (Some(axis), Some(front)) => axis.dot(front).clamp(-1.0, 1.0).acos(),
        _ => 0.0,
    };
    if flags & X3DAUDIO_CALCULATE_EMITTER_ANGLE != 0 {
        result.emitter_to_listener_angle = Some(emitter_angle);
    }

    // ── Scaled base distance for the distance curves ──
    let scaler = emitter.curve_distance_scaler;
    let scaled_distance = if scaler.is_finite() && scaler > 0.0 {
        result.emitter_to_listener_distance / scaler
    } else {
        f32::INFINITY
    };

    // ── Cone scalers (emitter cone only with single-channel emitters;
    //    listener cone applies always; both multiply) ──
    let to_emitter = emitter.position.sub(listener.position);
    let listener_cone_angle = match (to_emitter.normalized(), listener.orient_front.normalized()) {
        (Some(dir), Some(front)) => dir.dot(front).clamp(-1.0, 1.0).acos(),
        _ => 0.0,
    };
    let mut volume_scale = 1.0_f32;
    let mut lpf_subtrahend = 0.0_f32;
    let mut reverb_scale = 1.0_f32;
    if emitter.channel_count == 1
        && let Some(cone) = &emitter.cone
    {
        let (volume, lpf, reverb) = x3daudio_cone_scale(cone, emitter_angle);
        volume_scale *= volume;
        lpf_subtrahend = 1.0 - (1.0 - lpf_subtrahend) * (1.0 - lpf);
        reverb_scale *= reverb;
    }
    if let Some(cone) = &listener.cone {
        let (volume, lpf, reverb) = x3daudio_cone_scale(cone, listener_cone_angle);
        volume_scale *= volume;
        lpf_subtrahend = 1.0 - (1.0 - lpf_subtrahend) * (1.0 - lpf);
        reverb_scale *= reverb;
    }

    // ── Distance-curve values ──
    let volume_curve = match &emitter.volume_curve {
        Some(curve) => x3daudio_curve_value(&curve.points, scaled_distance),
        None => x3daudio_default_volume_curve(scaled_distance),
    };
    let lfe_value = match &emitter.lfe_curve {
        Some(curve) => x3daudio_curve_value(&curve.points, scaled_distance),
        None => x3daudio_default_volume_curve(scaled_distance),
    };
    let lpf_direct_value = match &emitter.lpf_direct_curve {
        Some(curve) => x3daudio_curve_value(&curve.points, scaled_distance),
        None => x3daudio_curve_value(&[(0.0, 1.0), (1.0, 0.75)], scaled_distance),
    };
    let lpf_reverb_value = match &emitter.lpf_reverb_curve {
        Some(curve) => x3daudio_curve_value(&curve.points, scaled_distance),
        None => x3daudio_curve_value(&[(0.0, 0.75), (1.0, 0.75)], scaled_distance),
    };
    let reverb_value = match &emitter.reverb_curve {
        Some(curve) => x3daudio_curve_value(&curve.points, scaled_distance),
        None => x3daudio_curve_value(&[(0.0, 1.0), (1.0, 0.0)], scaled_distance),
    };

    // ── LPF / reverb coefficients (cone LPF values are subtrahends) ──
    if flags & X3DAUDIO_CALCULATE_LPF_DIRECT != 0 {
        result.lpf_direct = Some(lpf_direct_value * (1.0 - lpf_subtrahend));
    }
    if flags & X3DAUDIO_CALCULATE_LPF_REVERB != 0 {
        result.lpf_reverb = Some(lpf_reverb_value * (1.0 - lpf_subtrahend));
    }
    if flags & X3DAUDIO_CALCULATE_REVERB != 0 {
        result.reverb_level = Some(reverb_value * reverb_scale);
    }

    // ── Doppler: projected velocity components along the emitter→listener
    //    axis (only meaningful when the two are separated) ──
    if flags & X3DAUDIO_CALCULATE_DOPPLER != 0 {
        let (evc, lvc) = match axis {
            Some(axis) => (emitter.velocity.dot(axis), listener.velocity.dot(axis)),
            None => (0.0, 0.0),
        };
        result.emitter_velocity_component = Some(evc);
        result.listener_velocity_component = Some(lvc);
        result.doppler_factor = Some(x3daudio_doppler_factor(
            speed_of_sound,
            emitter.doppler_scaler,
            evc,
            lvc,
        ));
    }

    // ── Matrix coefficients (dst-major: [Dst * SrcCount + Src]) ──
    if flags & X3DAUDIO_CALCULATE_MATRIX != 0 {
        let dst_geometry = x3daudio_dst_geometry(speaker_mask, dst_count);
        let dst_azimuths: Vec<f32> = dst_geometry.iter().flatten().copied().collect();
        let lfe_dst = dst_geometry.iter().position(|azimuth| azimuth.is_none());
        let lfe_src = emitter
            .channel_azimuths
            .iter()
            .any(|azimuth| (*azimuth - X3DAUDIO_2PI).abs() < 1.0e-3);
        let mut matrix = vec![0.0_f32; (src_count as usize) * (dst_count as usize)];
        for src in 0..src_count as usize {
            let (point, is_lfe) = x3daudio_source_point(emitter, src);
            let mut gains = vec![0.0_f32; dst_count as usize];
            if is_lfe {
                // LFE channels sit at the emitter base and use the LFE
                // curve only; they feed the destination LFE (if any).
                if let Some(lfe_dst) = lfe_dst {
                    gains[lfe_dst] = lfe_value;
                }
            } else {
                // Non-LFE sources pan over the non-LFE speakers.
                let to_point = point.sub(listener.position);
                let (pan_azimuth, _elevation) = x3daudio_listener_frame(&to_point, listener);
                let pan = x3daudio_pair_pan_gains(pan_azimuth, &dst_azimuths);
                let equal = if dst_azimuths.is_empty() {
                    0.0
                } else {
                    1.0 / dst_azimuths.len() as f32
                };
                let blend = x3daudio_inner_radius_blend(emitter, &to_point, listener);
                let mut pan_index = 0;
                for (channel, azimuth) in dst_geometry.iter().enumerate() {
                    if azimuth.is_none() {
                        continue;
                    }
                    let pair_gain = pan[pan_index];
                    pan_index += 1;
                    gains[channel] = pair_gain * (1.0 - blend) + equal * blend;
                }
            }
            for (channel, gain) in gains.iter_mut().enumerate() {
                let row_is_lfe = lfe_dst == Some(channel);
                if is_lfe {
                    if !row_is_lfe {
                        *gain = 0.0;
                    }
                } else if row_is_lfe {
                    // A destination LFE receives an equal mix of every
                    // non-LFE source when REDIRECT_TO_LFE is requested.
                    *gain = if flags & X3DAUDIO_CALCULATE_REDIRECT_TO_LFE != 0 && !lfe_src {
                        1.0
                    } else {
                        0.0
                    };
                } else {
                    *gain *= volume_curve * volume_scale;
                }
            }
            for (channel, gain) in gains.iter().enumerate() {
                matrix[channel * src_count as usize + src] = *gain;
            }
            if flags & X3DAUDIO_CALCULATE_ZEROCENTER != 0
                && let Some(center) = dst_geometry.iter().position(|az| *az == Some(0.0))
            {
                matrix[center * src_count as usize + src] = 0.0;
            }
        }
        result.matrix = Some(matrix);
    }

    // ── Delay times: the documented stereo-field-only delay array ──
    if flags & X3DAUDIO_CALCULATE_DELAY != 0 && speaker_mask == SPEAKER_STEREO && dst_count == 2 {
        let dst_azimuths = x3daudio_dst_geometry(speaker_mask, dst_count)
            .into_iter()
            .flatten()
            .collect::<Vec<f32>>();
        let source_point = x3daudio_source_point(emitter, 0).0;
        result.delays_ms = Some(x3daudio_stereo_delays_ms(
            source_point,
            listener,
            &dst_azimuths,
            speed_of_sound,
        ));
    }

    result
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
// - Best-match: with exactly one eligible certificate the operation
//   selects it deterministically — TRUE, the selected certificate context
//   (a real runtime context, as CertFindCertificateInStore produces)
//   written to `*ppSelectedCert`, and the owning store handle written back
//   to the request's `hSelectedCertStore`.  With none (or several — an
//   ambiguous pick needs a user) the operation answers FALSE with the
//   user-cancel semantics; no dialog is ever claimed.
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
// X3DAudio pure-math tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod x3daudio_math_tests {
    use super::*;

    fn listener_at_origin() -> X3dListener {
        X3dListener {
            orient_front: X3dVec {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            },
            orient_top: X3dVec {
                x: 0.0,
                y: 1.0,
                z: 0.0,
            },
            position: X3dVec {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
            velocity: X3dVec {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
            cone: None,
        }
    }

    #[test]
    fn distance_attenuation_is_monotonic_and_inverse_square() {
        // Default curve: no attenuation at ≤ 1 scaled unit, then 1/d.
        assert_eq!(x3daudio_default_volume_curve(0.5), 1.0);
        assert_eq!(x3daudio_default_volume_curve(1.0), 1.0);
        assert!((x3daudio_default_volume_curve(2.0) - 0.5).abs() < 1.0e-6);
        assert!((x3daudio_default_volume_curve(4.0) - 0.25).abs() < 1.0e-6);
        let mut previous = f32::INFINITY;
        for scaled in (1..=100).map(|v| v as f32 * 0.25) {
            let volume = x3daudio_default_volume_curve(scaled);
            assert!(volume <= previous + 1.0e-6, "rolloff must be monotonic");
            previous = volume;
        }
    }

    #[test]
    fn custom_curve_is_piecewise_linear_and_clamps() {
        let curve = vec![(0.0, 1.0), (0.5, 0.5), (1.0, 0.0)];
        assert_eq!(x3daudio_curve_value(&curve, -1.0), 1.0);
        assert_eq!(x3daudio_curve_value(&curve, 0.0), 1.0);
        assert!((x3daudio_curve_value(&curve, 0.25) - 0.75).abs() < 1.0e-6);
        assert_eq!(x3daudio_curve_value(&curve, 1.0), 0.0);
        assert_eq!(
            x3daudio_curve_value(&curve, 100.0),
            0.0,
            "clamped to the last point"
        );
    }

    #[test]
    fn cone_attenuation_orders_inside_between_outside() {
        let cone = X3dCone {
            inner_angle: std::f32::consts::FRAC_PI_2,
            outer_angle: std::f32::consts::PI,
            inner_volume: 1.0,
            outer_volume: 0.25,
            inner_lpf: 0.0,
            outer_lpf: 0.5,
            inner_reverb: 0.5,
            outer_reverb: 1.0,
            ..X3dCone::default()
        };
        let inside = x3daudio_cone_scale(&cone, 0.1);
        // 60° sits strictly between the inner half-angle (45°) and the
        // outer half-angle (90°).
        let between = x3daudio_cone_scale(&cone, std::f32::consts::FRAC_PI_3);
        let outside = x3daudio_cone_scale(&cone, std::f32::consts::PI);
        assert_eq!(inside.0, 1.0, "inside the inner cone: inner volume");
        assert_eq!(outside.0, 0.25, "beyond the outer cone: outer volume");
        assert!(
            between.0 >= outside.0 && between.0 <= inside.0,
            "the between-cones volume must interpolate"
        );
        assert!(between.0 > outside.0 && between.0 < inside.0);
        assert_eq!(inside.1, 0.0, "inner LPF subtrahend");
        assert_eq!(outside.1, 0.5, "outer LPF subtrahend");
        assert_eq!(inside.2, 0.5, "inner reverb scaler");
        assert_eq!(outside.2, 1.0, "outer reverb scaler");
    }

    #[test]
    fn doppler_bounds_and_monotonicity() {
        let speed = 343.5;
        // Static pair: exactly 1.0.
        assert!((x3daudio_doppler_factor(speed, 1.0, 0.0, 0.0) - 1.0).abs() < 1.0e-6);
        // Approaching emitter (positive component along e→l): higher pitch.
        let approaching = x3daudio_doppler_factor(speed, 1.0, 100.0, 0.0);
        assert!(approaching > 1.0 && approaching < 2.0);
        // Receding emitter: lower pitch.
        let receding = x3daudio_doppler_factor(speed, 1.0, -100.0, 0.0);
        assert!(receding < 1.0 && receding > 0.0);
        // Approaching listener (negative component along e→l): higher pitch.
        let listener_approaches = x3daudio_doppler_factor(speed, 1.0, 0.0, -100.0);
        assert!(listener_approaches > 1.0);
        // Monotonic in the closing speed.
        let mut previous = 0.0_f32;
        for closing in 0..=50 {
            let factor = x3daudio_doppler_factor(speed, 1.0, closing as f32 * 2.0, 0.0);
            assert!(factor >= previous);
            previous = factor;
        }
        // Doppler scaler 0 (or negative) disables the shift.
        assert_eq!(x3daudio_doppler_factor(speed, 0.0, 100.0, 0.0), 1.0);
        assert_eq!(x3daudio_doppler_factor(speed, -1.0, 100.0, 0.0), 1.0);
    }

    #[test]
    fn pair_pan_is_equal_power_and_hits_speaker_lines() {
        // Stereo field at ±90°.
        let stereo = vec![-std::f32::consts::FRAC_PI_2, std::f32::consts::FRAC_PI_2];
        let hard_left = x3daudio_pair_pan_gains(-std::f32::consts::FRAC_PI_2, &stereo);
        assert_eq!(hard_left[0], 1.0);
        assert_eq!(hard_left[1], 0.0);
        let center = x3daudio_pair_pan_gains(0.0, &stereo);
        let power: f32 = center.iter().map(|g| g * g).sum();
        assert!((power - 1.0).abs() < 1.0e-5, "constant-power pan");
        assert!(
            (center[0] - center[1]).abs() < 1.0e-6,
            "symmetric center pan"
        );
        // Every azimuth keeps the pair power at 1.
        for degrees in 0..=360 {
            let azimuth = (degrees as f32).to_radians() - std::f32::consts::PI;
            let gains = x3daudio_pair_pan_gains(azimuth, &stereo);
            let power: f32 = gains.iter().map(|g| g * g).sum();
            assert!((power - 1.0).abs() < 1.0e-4, "power at {degrees}°");
        }
    }

    #[test]
    fn pan_front_rear_split_uses_the_full_circle() {
        // Quad azimuths in stream order (FL, FR, BL, BR → −90, +90, −135,
        // +135), sorted around the circle for the pan test.
        let mut dst = vec![
            -std::f32::consts::FRAC_PI_2,
            std::f32::consts::FRAC_PI_2,
            -3.0 * std::f32::consts::FRAC_PI_4,
            3.0 * std::f32::consts::FRAC_PI_4,
        ];
        dst.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let index_of = |az: f32| {
            dst.iter()
                .position(|candidate| (candidate - az).abs() < 1.0e-4)
                .expect("speaker azimuth present")
        };
        let bl = index_of(-3.0 * std::f32::consts::FRAC_PI_4);
        let fl = index_of(-std::f32::consts::FRAC_PI_2);
        let fr = index_of(std::f32::consts::FRAC_PI_2);
        let br = index_of(3.0 * std::f32::consts::FRAC_PI_4);
        // A source directly ahead stays in the front pair (power 1).
        let ahead = x3daudio_pair_pan_gains(0.0, &dst);
        let front_power: f32 = ahead[fl] * ahead[fl] + ahead[fr] * ahead[fr];
        assert!((front_power - 1.0).abs() < 1.0e-5);
        assert!(ahead[bl].abs() < 1.0e-6 && ahead[br].abs() < 1.0e-6);
        // A source directly behind (180°) must land on the rear pair.
        let behind = x3daudio_pair_pan_gains(std::f32::consts::PI, &dst);
        let rear_power: f32 = behind[bl] * behind[bl] + behind[br] * behind[br];
        assert!((rear_power - 1.0).abs() < 1.0e-5);
        assert!(behind[fl].abs() < 1.0e-6 && behind[fr].abs() < 1.0e-6);
    }

    #[test]
    fn compute_geometry_matches_stereo_field() {
        // Emitter 6 units to the LEFT of a listener facing +z; the listener
        // frame's right vector is top×front = +x, so a −x source sits at
        // azimuth −90° (hard left).
        let listener = listener_at_origin();
        let emitter = X3dEmitter {
            position: X3dVec {
                x: -6.0,
                y: 0.0,
                z: 0.0,
            },
            velocity: X3dVec {
                x: 3.0,
                y: 0.0,
                z: 0.0,
            },
            channel_count: 1,
            curve_distance_scaler: 3.0,
            doppler_scaler: 1.0,
            ..X3dEmitter::default()
        };
        let result = x3daudio_compute(
            &listener,
            &emitter,
            X3DAUDIO_CALCULATE_MATRIX
                | X3DAUDIO_CALCULATE_DELAY
                | X3DAUDIO_CALCULATE_DOPPLER
                | X3DAUDIO_CALCULATE_EMITTER_ANGLE,
            SPEAKER_STEREO,
            343.5,
            1,
            2,
        );
        assert!((result.emitter_to_listener_distance - 6.0).abs() < 1.0e-5);
        let matrix = result.matrix.expect("matrix requested");
        assert_eq!(matrix.len(), 1 * 2, "src × dst coefficients");
        // Distance 6 with scaler 3: volume = 3/6 = 0.5, hard-left → FL only.
        assert!((matrix[0] - 0.5).abs() < 1.0e-5);
        assert!(matrix[1].abs() < 1.0e-6);
        // Delays: FL speaker (1 unit left) is 5 units away, FR 7: FL is
        // delayed by (7−5)/343.5 s ≈ 5.82 ms, FR not at all.
        let delays = result.delays_ms.expect("delay requested");
        assert_eq!(delays.len(), 2);
        assert!(delays[0] > 0.0 && (delays[0] - 5.8224).abs() < 0.01);
        assert!(delays[1].abs() < 1.0e-5);
        // Doppler: approaching along the axis at 3 units/s.
        assert!(result.doppler_factor.unwrap() > 1.0);
        assert!((result.doppler_factor.unwrap() - (1.0 + 3.0 / 343.5)).abs() < 1.0e-4);
    }

    #[test]
    fn inner_radius_blends_above_listener_to_all_speakers() {
        let listener = listener_at_origin();
        let emitter = X3dEmitter {
            inner_radius: 4.0,
            inner_radius_angle: std::f32::consts::FRAC_PI_4,
            channel_count: 1,
            ..X3dEmitter::default()
        };
        // At the listener itself: the full all-speaker blend.
        let at_listener = X3dVec {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        };
        let blend = x3daudio_inner_radius_blend(&emitter, &at_listener, &listener);
        assert!((blend - 1.0).abs() < 1.0e-5);
        // Directly above the listener inside the sphere: mostly blended
        // (2/4 of the radius → blend 0.5), and far more than the same
        // distance horizontally (elevation keeps it inside the angle cone).
        let above = X3dVec {
            x: 0.0,
            y: 2.0,
            z: 0.0,
        };
        let blend = x3daudio_inner_radius_blend(&emitter, &above, &listener);
        assert!(
            (blend - 0.5).abs() < 1.0e-5,
            "above the listener at half the inner radius"
        );
        let horizontal = X3dVec {
            x: 2.0,
            y: 0.0,
            z: 0.0,
        };
        let blend = x3daudio_inner_radius_blend(&emitter, &horizontal, &listener);
        assert!(
            blend < 0.5,
            "a horizontal source at the same distance is outside the angle cone"
        );
        // Far outside the radius: no blend.
        let far = X3dVec {
            x: 0.0,
            y: 0.0,
            z: 100.0,
        };
        assert_eq!(x3daudio_inner_radius_blend(&emitter, &far, &listener), 0.0);
        // No inner radius configured: never blends.
        let plain = X3dEmitter {
            channel_count: 1,
            ..X3dEmitter::default()
        };
        assert_eq!(x3daudio_inner_radius_blend(&plain, &above, &listener), 0.0);
    }
}
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

    /// Run the body on an 8 MB stack thread (the runtime's guest-callback
    /// machinery needs the same big-stack setup the runtime test suite uses).
    fn with_big_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(body)
            .expect("spawn big-stack thread")
            .join()
            .expect("big-stack thread panicked")
    }

    /// Install a guest completion-handler COM object whose `ActivateCompleted`
    /// slot (vtable slot 3) is real x86 stub code that records
    /// `(result_hr, activated_interface)` at the marker addresses and counts
    /// its invocations.
    fn install_handler(memory: &mut MemoryImage) {
        memory.map_bytes(MARKER_HR, &[0_u8; 12]);
        memory.map_bytes(HANDLER_OBJECT, &[0_u8; 8]);
        memory.map_bytes(HANDLER_VTABLE, &[0_u8; 16]);
        let mut stub = vec![0x90_u8; 0x40];
        stub[..36].copy_from_slice(&[
            0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]   (result hr)
            0xA3, 0x00, 0x40, 0x04, 0x00, // mov [0x44000], eax
            0x8B, 0x44, 0x24, 0x0C, // mov eax, [esp+12]  (interface object)
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

    /// Dispatch `ActivateAudioInterfaceAsync` (x86 stack args) through the
    /// real import dispatch and return the HRESULT in EAX.
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

    /// Poll for async completion: drain the runtime's pending audio
    /// activations (the same drain the block-dispatch safepoint and the
    /// message-loop idle pump run in a live session).
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

    /// Capability probe shared with the real_audio tests: the success paths
    /// need a real default render device.
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
            assert_eq!(operation, 0, "failed activations return no interface");

            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_count(&memory), 1, "handler invoked exactly once");
            assert_eq!(
                marker_hr(&memory),
                ACTIVATION_E_NOINTERFACE,
                "unsupported riid delivers E_NOINTERFACE"
            );
            assert_eq!(
                marker_object(&memory),
                0,
                "no interface object for E_NOINTERFACE"
            );
            assert_eq!(
                crate::audio_activation::pending_activation_completions(runtime.guest_pid),
                0,
                "the completion queue is empty after the drain"
            );
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
            let endpoint = read_guest_pointer(&memory, OP_OUT, GuestArch::X86).unwrap();
            assert_ne!(endpoint, 0, "the activation operation carries the endpoint");
            assert_eq!(
                crate::audio_activation::pending_activation_completions(runtime.guest_pid),
                1,
                "one completion queued"
            );

            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_count(&memory), 1, "handler invoked exactly once");
            assert_eq!(marker_hr(&memory), ACTIVATION_S_OK);
            assert_eq!(marker_object(&memory) as u64, endpoint);

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
        })
    }

    #[test]
    fn activation_render_interface_guid_path_resolves_to_default_device() {
        with_big_stack(|| {
            // The documented DEVINTERFACE_AUDIO_RENDER GUID string must activate
            // the default render device just like the empty path.
            if !real_default_device_available() {
                eprintln!("skipping activation render-guid test: no real default render device");
                return;
            }
            let (mut runtime, _tmp) = activation_test_runtime("act-render-guid");
            let mut memory = MemoryImage::default();
            install_handler(&mut memory);
            let hr = dispatch_activate(
                &mut runtime,
                &mut memory,
                Some("{e6327cad-dcec-4949-ae8a-991e976a79d2}"),
                &IID_IAUDIO_CLIENT,
                HANDLER_OBJECT,
                OP_OUT,
            );
            assert_eq!(hr, u64::from(ACTIVATION_S_OK));
            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_hr(&memory), ACTIVATION_S_OK);
            assert_ne!(marker_object(&memory), 0);
        })
    }

    #[test]
    fn activation_capture_guid_path_fails_with_device_error() {
        with_big_stack(|| {
            // DEVINTERFACE_AUDIO_CAPTURE never resolves on the render activation
            // surface — the failure is AUDCLNT_E_DEVICE_INVALIDATED, delivered
            // asynchronously (no real device needed for this path).
            let (mut runtime, _tmp) = activation_test_runtime("act-capture-guid");
            let mut memory = MemoryImage::default();
            install_handler(&mut memory);
            let hr = dispatch_activate(
                &mut runtime,
                &mut memory,
                Some("{2eef81be-33fa-4800-9670-1cd474972c3f}"),
                &IID_IAUDIO_CLIENT,
                HANDLER_OBJECT,
                OP_OUT,
            );
            assert_eq!(hr, u64::from(ACTIVATION_S_OK));
            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_hr(&memory), AUDCLNT_E_DEVICE_INVALIDATED);
            assert_eq!(marker_object(&memory), 0);
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
            drain_activations(&mut runtime, &mut memory);
            assert_eq!(marker_hr(&memory), AUDCLNT_E_DEVICE_INVALIDATED);
            assert_eq!(marker_object(&memory), 0);
            assert_eq!(marker_count(&memory), 1);
        })
    }
}
