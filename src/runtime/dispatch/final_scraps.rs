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
            // ── the audio-session activation ──
            HostThunk::ActivateAudioInterfaceAsync => {
                let _device = guest_call_arg(state, memory, 0)?;
                let _iid = guest_call_arg(state, memory, 1)?;
                let _activation = guest_call_arg(state, memory, 2)?;
                let _callback = guest_call_arg(state, memory, 3)?;
                let out = guest_call_arg(state, memory, 4)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                let _ = _device;
                state.set(Register::Rax, 0x8889_0006); // AUDCLNT_E_DEVICE_INVALIDATED
                Ok(())
            }
            // ── GDI+ graphics ──
            HostThunk::GdipCreateGraphics => {
                let _hdc = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let _ = _hdc;
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let graphics = self
                    .alloc_guest_object(memory, GuestObjectKind::GdiPlusGraphics, vtable)
                    .unwrap_or(0);
                if graphics == 0 || out == 0 {
                    state.set(Register::Rax, 3); // OutOfMemory
                    return Ok(());
                }
                write_guest_pointer(memory, out, graphics, self.guest_arch).ok();
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
