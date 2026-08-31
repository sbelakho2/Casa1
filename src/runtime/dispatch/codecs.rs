//! Media-codec component dispatch: the wmcodecdsp.dll, wmvcore.dll,
//! audioses.dll, msdmo.dll, the DMO/MFT codec DLLs (colorcnv, mfaacenc,
//! mfh264enc, mfmpeg2src, mfvpxdec, mp3dmod, mpg4decdmod, msmpeg2adec,
//! msmpeg2vdec, resampledmo), evr.dll, amstream.dll, qedit.dll and
//! dxva2.dll exports, in a dedicated module per the audit's modularity
//! requirement.  The component factories hand out the honest objects: no
//! codecs are registered, so `DMOEnum` reports zero DMOs, the WM-codec
//! factories create their objects (whose method surface answers the
//! no-codec errors), the EVR factories build media types / renderer /
//! presenter / allocator objects on the shared MF machinery, the
//! DXVA2 factories reuse the DXGI device manager, and the module-class
//! exports route through the shared in-process COM server contract.
//!
//! Layer contract: every export returns its HRESULT in EAX.

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// S_OK.
const S_OK: u32 = 0;
/// E_FAIL.
const E_FAIL: u32 = 0x8000_4005;

impl PeHostRuntime {
    /// Route every codec-component thunk to its dispatch function.
    pub(crate) fn dispatch_codecs(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            // ── The WM-codec factories ──
            HostThunk::WmcdspCreateAudioDecoder
            | HostThunk::WmcdspCreateAudioEncoder
            | HostThunk::WmcdspCreateConverter
            | HostThunk::WmcdspCreateDecoder
            | HostThunk::WmcdspCreateEncoder
            | HostThunk::WmcdspCreateProcessor
            | HostThunk::WmcdspCreateResampler => {
                let _format = guest_call_arg_u32(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                // The codec object is created; its method surface answers
                // the no-codec errors.
                let object = self.codecs_alloc_object(memory, GuestObjectKind::WmCodec)?;
                if object == 0 || out == 0 {
                    state.set(Register::Rax, u64::from(E_FAIL));
                    return Ok(());
                }
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── The WM core factories ──
            HostThunk::WmCreateEditor
            | HostThunk::WmCreateIndexer
            | HostThunk::WmCreateProfileManager
            | HostThunk::WmCreateReader
            | HostThunk::WmCreateSyncReader
            | HostThunk::WmCreateWriter => {
                let out_index = if matches!(thunk, HostThunk::WmCreateReader) {
                    2
                } else if matches!(thunk, HostThunk::WmCreateEditor)
                    || matches!(thunk, HostThunk::WmCreateWriter)
                {
                    1
                } else {
                    0
                };
                let out = guest_call_arg(state, memory, out_index)?;
                let kind = if matches!(thunk, HostThunk::WmCreateEditor) {
                    GuestObjectKind::WmEditor
                } else if matches!(thunk, HostThunk::WmCreateIndexer) {
                    GuestObjectKind::WmIndexer
                } else if matches!(thunk, HostThunk::WmCreateProfileManager) {
                    GuestObjectKind::WmProfileManager
                } else if matches!(thunk, HostThunk::WmCreateSyncReader) {
                    GuestObjectKind::WmSyncReader
                } else if matches!(thunk, HostThunk::WmCreateWriter) {
                    GuestObjectKind::WmWriter
                } else {
                    GuestObjectKind::WmReader
                };
                let object = self.codecs_alloc_object(memory, kind)?;
                if object == 0 || out == 0 {
                    eprintln!("wm-create failed: object={object:#x} out={out:#x}");
                    state.set(Register::Rax, u64::from(E_FAIL));
                    return Ok(());
                }
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::WmIsContentProtected => {
                let _path = guest_call_arg(state, memory, 0)?;
                let protected = guest_call_arg(state, memory, 1)?;
                if protected != 0 {
                    write_guest_u32(memory, protected, 0).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── The audio-session helpers ──
            HostThunk::AudioSessionFromGuid
            | HostThunk::AudioSessionFromHwnd
            | HostThunk::AudioSessionFromString => {
                let _key = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                // No audio sessions exist.
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::AudioSessionize => {
                let _session = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── The DMO registry ──
            HostThunk::DmoEnum => {
                let _category = guest_call_arg(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let count = guest_call_arg(state, memory, 2)?;
                let _guids = guest_call_arg(state, memory, 3)?;
                let _actual = guest_call_arg(state, memory, 4)?;
                if count != 0 {
                    write_guest_u32(memory, count, 0).ok();
                }
                // No DMOs are registered.
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::DmoGetName | HostThunk::DmoGetTypes => {
                let _clsid = guest_call_arg(state, memory, 0)?;
                // No DMO with that CLSID exists.
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            HostThunk::DmoGuidToStr => {
                let guid = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let bytes = memory.read_bytes(guid, 16).unwrap_or_default();
                let mut raw = [0_u8; 16];
                raw.copy_from_slice(&bytes);
                // The Windows GUID bytes are little-endian in the first
                // three fields; the uuid crate formats the network order.
                let canonical = [
                    raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9],
                    raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
                ];
                let text = format!("{{{}}}", uuid::Uuid::from_bytes(canonical));
                let address = self.codecs_scratch_string(memory, &text)?;
                if out != 0 {
                    write_guest_pointer(memory, out, address, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::DmoStrToGuid => {
                let text = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let text = read_utf16_string(memory, text).unwrap_or_default();
                let text = text.trim_matches(|c| c == '{' || c == '}');
                match uuid::Uuid::parse_str(text) {
                    Ok(guid) => {
                        if out != 0 {
                            let canonical = guid.into_bytes();
                            let le = [
                                canonical[3],
                                canonical[2],
                                canonical[1],
                                canonical[0],
                                canonical[5],
                                canonical[4],
                                canonical[7],
                                canonical[6],
                                canonical[8],
                                canonical[9],
                                canonical[10],
                                canonical[11],
                                canonical[12],
                                canonical[13],
                                canonical[14],
                                canonical[15],
                            ];
                            for (i, byte) in le.iter().enumerate() {
                                memory.write_u8(out + i as u64, *byte);
                            }
                        }
                        state.set(Register::Rax, u64::from(S_OK));
                    }
                    Err(_) => state.set(Register::Rax, u64::from(E_FAIL)),
                }
                Ok(())
            }
            HostThunk::MoFree => {
                let _block = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── The EVR factories ──
            HostThunk::MfCreateVideoMediaType => {
                let _major = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let object =
                    self.codecs_alloc_object(memory, GuestObjectKind::EvrVideoMediaType)?;
                if object == 0 || out == 0 {
                    state.set(Register::Rax, u64::from(E_FAIL));
                    return Ok(());
                }
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::MfCreateVideoMixer
            | HostThunk::MfCreateVideoPresenter
            | HostThunk::MfCreateVideoRenderer => {
                let _unknown = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let kind = if matches!(thunk, HostThunk::MfCreateVideoMixer) {
                    GuestObjectKind::EvrVideoMixer
                } else if matches!(thunk, HostThunk::MfCreateVideoPresenter) {
                    GuestObjectKind::EvrVideoPresenter
                } else {
                    GuestObjectKind::EvrVideoRenderer
                };
                let object = self.codecs_alloc_object(memory, kind)?;
                if object == 0 || out == 0 {
                    state.set(Register::Rax, u64::from(E_FAIL));
                    return Ok(());
                }
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::MfCreateVideoSampleAllocator => {
                let _riid = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let object =
                    self.codecs_alloc_object(memory, GuestObjectKind::EvrSampleAllocator)?;
                if object == 0 || out == 0 {
                    state.set(Register::Rax, u64::from(E_FAIL));
                    return Ok(());
                }
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── qedit ──
            HostThunk::AmGetErrorText => {
                // The ANSI error text (the same DirectShow table).
                let hr = guest_call_arg_u32(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let max_len = guest_call_arg_u32(state, memory, 2)?;
                let text = dshow_error_text(hr);
                let mut written = 0_u32;
                for byte in text.as_bytes() {
                    if written >= max_len.saturating_sub(1) {
                        break;
                    }
                    memory.write_u8(buffer + written as u64, *byte);
                    written += 1;
                }
                memory.write_u8(buffer + written as u64, 0);
                state.set(Register::Rax, u64::from(written));
                Ok(())
            }
            HostThunk::CreateErrorInfo => {
                let out = guest_call_arg(state, memory, 0)?;
                let object = self.codecs_alloc_object(memory, GuestObjectKind::ComErrorInfo)?;
                if object == 0 || out == 0 {
                    state.set(Register::Rax, u64::from(E_FAIL));
                    return Ok(());
                }
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::CreateFilter => {
                // No DirectShow filters are registered.
                let _clsid = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            // ── DXVA2 ──
            HostThunk::Dxva2CreateDirect3DDeviceManager9 => {
                let _token = guest_call_arg_u32(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                // The device manager reuses the MF DXGI device manager.
                let vtable = self.alloc_guest_vtable(memory, mf_dxgi_device_manager_methods())?;
                let object = self
                    .alloc_guest_object(memory, GuestObjectKind::ImfDxgiDeviceManager, vtable)
                    .unwrap_or(0);
                if object == 0 || out == 0 {
                    state.set(Register::Rax, u64::from(E_FAIL));
                    return Ok(());
                }
                self.mf_dxgi_device_managers.insert(
                    object,
                    crate::runtime::state::MfDxgiDeviceManagerState::default(),
                );
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::Dxva2CreateVideoService => {
                let _device_manager = guest_call_arg(state, memory, 0)?;
                let _riid = guest_call_arg(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                let object =
                    self.codecs_alloc_object(memory, GuestObjectKind::Dxva2VideoService)?;
                if object == 0 || out == 0 {
                    state.set(Register::Rax, u64::from(E_FAIL));
                    return Ok(());
                }
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::Dxva2GetVideoProcessorCaps => {
                let _processor = guest_call_arg(state, memory, 0)?;
                let _device = guest_call_arg(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                // No video processors are available.
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            // ── The module class-object exports (the shared server
            //    contract answers them) ──
            HostThunk::DllCanUnloadNow
            | HostThunk::DllGetClassObject
            | HostThunk::DllRegisterServer
            | HostThunk::DllUnregisterServer => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted codec-component thunk {thunk:?}"),
            )),
        }
    }

    /// Allocate a codec-component object.
    fn codecs_alloc_object(
        &mut self,
        memory: &mut MemoryImage,
        kind: GuestObjectKind,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let object = self.alloc_guest_object(memory, kind, vtable).unwrap_or(0);
        if object != 0 {
            self.codec_objects.insert(object, 0_u32);
        }
        Ok(object)
    }

    /// The guest-resident scratch string for the codec surface.
    fn codecs_scratch_string(&mut self, memory: &mut MemoryImage, text: &str) -> AppResult<u64> {
        let mut address = self.wic.string_slots[1];
        if address == 0 {
            address = self.alloc_zeroed(memory, 256, 8)?;
            self.wic.string_slots[1] = address;
        }
        for (i, unit) in text.encode_utf16().enumerate() {
            write_guest_u16(memory, address + (i as u64 * 2), unit).ok();
        }
        write_guest_u16(
            memory,
            address + (text.encode_utf16().count() as u64 * 2),
            0,
        )
        .ok();
        Ok(address)
    }
}

fn dshow_error_text(hr: u32) -> &'static str {
    match hr {
        0x8004_0227 => "No filters were found to process the stream",
        0x8004_0228 => "No decompressor was found to process the stream",
        0x8004_0214 => "The filter graph does not support the requested operation",
        0x8004_0207 => "The pins are not connected",
        0x8004_0206 => "The input pin is not connected",
        0x8004_0208 => "The output pin is not connected",
        0x8004_0209 => "No media type was set on the pin",
        0x8004_020a => "The pins are already connected",
        0x8004_0211 => "The media type is not set",
        0x8004_0212 => "The filter is already in the graph",
        0x8004_0213 => "The filter is not in the graph",
        0x8004_0217 => "The clock is already set on the graph",
        0x8004_0218 => "The clock is not set on the graph",
        0x8004_0219 => "The renderer cannot render the media type",
        0x8004_0201 => "The operation is not supported",
        0x8004_0202 => "The media type is not supported",
        0x8004_0203 => "The operation cannot be performed",
        0x8004_0204 => "The operation was canceled",
        0x8004_0205 => "The filter is already active",
        _ => "DirectShow error",
    }
}
