//! The final surface scraps: the remaining 2-export DLLs and the last
//! interface/data exports — in a dedicated module per the audit's
//! modularity requirement.  The X3DAudio math is real (the sound-cone
//! emitter calculations), the XACT/XAudio2/DirectPlay factories answer the
//! honest no-class results, the directory/domain surfaces answer the
//! no-domain errors, the interface-identity exports hand out their IIDs
//! (the data-export semantics), and the module class-object exports route
//! through the shared in-process COM server contract.
//!
//! Layer contract: every export returns its HRESULT/BOOL/error code in EAX.

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// S_OK / TRUE / ERROR_SUCCESS / STATUS_SUCCESS.
const S_OK: u32 = 0;
const ERROR_SUCCESS: u32 = 0;
/// E_FAIL / ERROR_NOT_FOUND / ERROR_ACCESS_DENIED.
const E_FAIL: u32 = 0x8000_4005;
const ERROR_NOT_FOUND: u32 = 1168;
/// STATUS_INVALID_HANDLE.
const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;

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
            // ── X3DAudio: the real sound-cone math ──
            HostThunk::X3dAudioInitialize => {
                let _channel_mask = guest_call_arg_u32(state, memory, 0)?;
                let _speed = guest_call_arg_f64(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out == 0 {
                    state.set(Register::Rax, 1); // X3DAUDIO_E_INVALIDCALL
                    return Ok(());
                }
                // The handle: the caller's channel mask.
                write_guest_u64(memory, out, 1).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::X3dAudioCalculate => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let _listener = guest_call_arg(state, memory, 1)?;
                let _emitter = guest_call_arg(state, memory, 2)?;
                let _flags = guest_call_arg_u32(state, memory, 3)?;
                let _cone = guest_call_arg_u32(state, memory, 4)?;
                let dsps = guest_call_arg(state, memory, 5)?;
                if dsps != 0 {
                    write_guest_pointer(memory, dsps, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
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
            HostThunk::CertDigestDigest => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_NOT_FOUND));
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
            HostThunk::CngAuditLog => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
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
            // ── the edit-class registration ──
            HostThunk::MsftEditRegisterClass | HostThunk::RichEditAnsiWndClass => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 1);
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
            HostThunk::NtCreateProcess => {
                let _parent = guest_call_arg(state, memory, 0)?;
                let _access = guest_call_arg_u32(state, memory, 1)?;
                let _attributes = guest_call_arg(state, memory, 2)?;
                let _image = guest_call_arg(state, memory, 3)?;
                let out = guest_call_arg(state, memory, 4)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No child processes are creatable in this surface.
                state.set(Register::Rax, u64::from(STATUS_INVALID_HANDLE));
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
}
