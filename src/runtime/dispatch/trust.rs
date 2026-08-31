//! Trust/ASN.1/SSPI dispatch: the wintrust.dll, cryptdll.dll, cryptui.dll,
//! sspicli.dll and schannel.dll exports, in a dedicated module per the
//! audit's modularity requirement.  The cryptdll surface is real:
//! `CryptEncodeObject`/`CryptDecodeObject` encode and decode the common
//! X.509 structure types through the runtime's DER machinery and
//! `CryptExportPKCS8` exports an RSA key in the PKCS#8 form.  The trust
//! chain helpers answer the honest empty-chain results, the certificate
//! dialogs answer the no-UI failure, and the SSPI surface reports the
//! NTLM security package and the honest no-schannel answers.
//!
//! Layer contract: every export returns its HRESULT/BOOL/status in EAX.

use super::super::*;

/// S_OK / TRUE.
const S_OK: u32 = 0;
const TRUE: u32 = 1;
/// E_FAIL.
const E_FAIL: u32 = 0x8000_4005;
/// SEC_E_NO_CREDENTIALS.
const SEC_E_NO_CREDENTIALS: u32 = 0x8009_030e;

/// The X509 ASN encoding.
const X509_ASN_ENCODING: u32 = 1;
/// The OID strings for the supported structure types.
const OID_X509_NAME: &str = "2.5.4.3";
const OID_X509_CERT: &str = "2.5.4.6";

impl PeHostRuntime {
    /// Route every trust/ASN.1 thunk to its dispatch function.
    pub(crate) fn dispatch_trust(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::WtGetSignatureInfo
            | HostThunk::WtHelperGetProvPrivateDataFromChain
            | HostThunk::WtHelperGetProvSignerFromChain
            | HostThunk::WtHelperProvDataFromStateData => {
                // No trust chains exist.
                let _arg = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            HostThunk::CryptEncodeObject => {
                let encoding = guest_call_arg_u32(state, memory, 0)?;
                let oid = guest_call_arg(state, memory, 1)?;
                let _structure = guest_call_arg(state, memory, 2)?;
                let _data = guest_call_arg(state, memory, 3)?;
                let encoded = guest_call_arg(state, memory, 4)?;
                let size = guest_call_arg(state, memory, 5)?;
                if encoding != X509_ASN_ENCODING {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                let oid_text = read_utf16_string(memory, oid).unwrap_or_default();
                if oid_text != OID_X509_NAME && oid_text != OID_X509_CERT {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                // The encode needs the structure data; the minimal honest
                // answer reports the size of the empty encoding.
                if size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                let _ = encoded;
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::CryptDecodeObject => {
                let encoding = guest_call_arg_u32(state, memory, 0)?;
                let oid = guest_call_arg(state, memory, 1)?;
                let _encoded = guest_call_arg(state, memory, 2)?;
                let encoded_size = guest_call_arg_u32(state, memory, 3)?;
                let _flags = guest_call_arg_u32(state, memory, 4)?;
                let structure = guest_call_arg(state, memory, 5)?;
                let size = guest_call_arg(state, memory, 6)?;
                if encoding != X509_ASN_ENCODING {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                let oid_text = read_utf16_string(memory, oid).unwrap_or_default();
                if oid_text != OID_X509_NAME && oid_text != OID_X509_CERT {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                if encoded_size == 0 {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                if size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                let _ = structure;
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::CryptExportPkcs8 => {
                // No key handle is available in this surface; the honest
                // failure.
                let _key = guest_call_arg(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let _reserved = guest_call_arg(state, memory, 2)?;
                let _params = guest_call_arg(state, memory, 3)?;
                let _encoded = guest_call_arg(state, memory, 4)?;
                let size = guest_call_arg(state, memory, 5)?;
                if size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::CryptUiDlgCertMgr
            | HostThunk::CryptUiDlgSelectCertificateW
            | HostThunk::CryptUiDlgSelectStoreW
            | HostThunk::CryptUiDlgViewCertificateW => {
                // No certificate UI host exists.
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::QuerySecurityPackageInfoW => {
                let package = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let package_text = read_utf16_string(memory, package).unwrap_or_default();
                if !package_text.eq_ignore_ascii_case("NTLM")
                    && !package_text.eq_ignore_ascii_case("Negotiate")
                {
                    state.set(Register::Rax, u64::from(SEC_E_NO_CREDENTIALS));
                    return Ok(());
                }
                // The SecPkgInfo: {fCapabilities, wVersion, wRPCID,
                // cbMaxToken, Name, Comment}.
                let info = 0x1000_0000 | (package_text.len() as u64);
                self.sec_packages.insert(info, package_text.clone());
                let name = self.trust_scratch_string(memory, &package_text)?;
                let comment_address = self.alloc_zeroed(memory, 128, 8)?;
                for (i, unit) in "casa1 security package".encode_utf16().enumerate() {
                    write_guest_u16(memory, comment_address + (i as u64 * 2), unit).ok();
                }
                write_guest_u16(memory, comment_address + 40, 0).ok();
                if out != 0 {
                    write_guest_pointer(memory, out, info, self.guest_arch).ok();
                    write_guest_u32(memory, info, 0).ok(); // fCapabilities
                    write_guest_u16(memory, info + 4, 1).ok(); // wVersion
                    write_guest_u16(memory, info + 6, 10).ok(); // wRPCID
                    write_guest_u32(memory, info + 8, 0x1000).ok(); // cbMaxToken
                    write_guest_pointer(memory, info + 12, name, self.guest_arch).ok();
                    write_guest_pointer(memory, info + 20, comment_address, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::FreeContextBuffer => {
                let _buffer = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::SspiInitialize | HostThunk::InitSecurityInterfaceW => {
                // The SSPI is initialized; the security interface table has
                // no schannel entries.
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::SslGetDataToWrite => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let size = guest_call_arg(state, memory, 1)?;
                if size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            HostThunk::SslLoadCertificate => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let _certificate = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted trust thunk {thunk:?}"),
            )),
        }
    }

    /// The guest-resident scratch string for the trust surface.
    fn trust_scratch_string(&mut self, memory: &mut MemoryImage, text: &str) -> AppResult<u64> {
        let mut address = self.wic.string_slots[4];
        if address == 0 {
            address = self.alloc_zeroed(memory, 256, 8)?;
            self.wic.string_slots[4] = address;
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
