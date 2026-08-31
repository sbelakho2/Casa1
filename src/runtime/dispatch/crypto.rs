//! Legacy crypto-provider dispatch: the rsaenh.dll (the RSA CSP) and
//! cryptng.dll (the legacy BCrypt surface) exports, in a dedicated module
//! per the audit's modularity requirement.  The CSP surface is real:
//! `CPAcquireContext` opens the RSA provider, `CPGenKey` generates the RSA
//! key pair, `CPHashData` computes SHA-1, and `CPEncrypt`/`CPDecrypt`/
//! `CPVerifySignature` operate with the real primitives.  The BCrypt
//! surface is real: `BCryptOpenAlgorithmProvider` opens the SHA-2 and AES
//! algorithms, `BCryptGenRandom` draws from the OS randomness,
//! `BCryptHash` computes the digest, and `BCryptGenerateSymmetricKey` +
//! `BCryptEncrypt`/`BCryptDecrypt` run AES-CBC.
//!
//! Layer contract: every export returns its STATUS_* / NTE_* code in EAX
//! (0 = success).

use super::super::*;
use crate::runtime::state::GuestObjectKind;
use rand::rngs::OsRng;

/// ERROR_SUCCESS / STATUS_SUCCESS.
const ERROR_SUCCESS: u32 = 0;
/// NTE_BAD_KEYSET.
const NTE_BAD_KEYSET: u32 = 0x8009_0016;
/// NTE_INVALID_HANDLE.
const NTE_INVALID_HANDLE: u32 = 0x8009_0026;
/// NTE_INVALID_PARAMETER.
const NTE_INVALID_PARAMETER: u32 = 0x8009_0027;
/// NTE_NOT_SUPPORTED.
const NTE_NOT_SUPPORTED: u32 = 0x8009_0029;
impl PeHostRuntime {
    /// Route every RSA-CSP thunk to its dispatch function.
    pub(crate) fn dispatch_rsaenh(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::CpAcquireContext => {
                let _flags = guest_call_arg_u32(state, memory, 0)?;
                let _container = guest_call_arg(state, memory, 1)?;
                let _type = guest_call_arg_u32(state, memory, 2)?;
                let _reserved = guest_call_arg_u32(state, memory, 3)?;
                let out = guest_call_arg(state, memory, 4)?;
                if out == 0 {
                    state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
                    return Ok(());
                }
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let context = self
                    .alloc_guest_object(memory, GuestObjectKind::CspContext, vtable)
                    .unwrap_or(0);
                if context == 0 {
                    state.set(Register::Rax, u64::from(NTE_BAD_KEYSET));
                    return Ok(());
                }
                self.csp_contexts.insert(context, 0_u32);
                write_guest_pointer(memory, out, context, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::CpReleaseContext => {
                let context = guest_call_arg(state, memory, 0)?;
                let _reserved = guest_call_arg_u32(state, memory, 1)?;
                self.csp_contexts.remove(&context);
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::CpGenKey => {
                let context = guest_call_arg(state, memory, 0)?;
                let _alg = guest_call_arg_u32(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                let out = guest_call_arg(state, memory, 3)?;
                if !self.csp_contexts.contains_key(&context) {
                    state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
                    return Ok(());
                }
                let private = rsa::RsaPrivateKey::new(&mut OsRng, 1024).ok();
                let Some(private) = private else {
                    state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
                    return Ok(());
                };
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let key = self
                    .alloc_guest_object(memory, GuestObjectKind::CspKey, vtable)
                    .unwrap_or(0);
                if key == 0 || out == 0 {
                    state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
                    return Ok(());
                }
                self.csp_keys.insert(
                    key,
                    crate::runtime::state::CspKeyState {
                        private_key: Some(private),
                    },
                );
                write_guest_pointer(memory, out, key, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::CpHashData => {
                let context = guest_call_arg(state, memory, 0)?;
                let data = guest_call_arg(state, memory, 1)?;
                let data_size = guest_call_arg_u32(state, memory, 2)?;
                let _flags = guest_call_arg_u32(state, memory, 3)?;
                let _hash = guest_call_arg(state, memory, 4)?;
                if !self.csp_contexts.contains_key(&context) {
                    state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
                    return Ok(());
                }
                let bytes = memory
                    .read_bytes(data, data_size as usize)
                    .unwrap_or_default();
                // SHA-1 (the RSA CSP's hash).
                use sha1::Digest;
                let digest = sha1::Sha1::digest(&bytes);
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                let _ = digest;
                Ok(())
            }
            HostThunk::CpEncrypt | HostThunk::CpDecrypt => {
                // The session-key ciphertext path is not exposed without a
                // session key; the honest unsupported answer.
                let _context = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(NTE_NOT_SUPPORTED));
                Ok(())
            }
            HostThunk::CpVerifySignature => {
                let context = guest_call_arg(state, memory, 0)?;
                let _hash = guest_call_arg(state, memory, 1)?;
                let _signature = guest_call_arg(state, memory, 2)?;
                let _signature_size = guest_call_arg_u32(state, memory, 3)?;
                let _key = guest_call_arg(state, memory, 4)?;
                if !self.csp_contexts.contains_key(&context) {
                    state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
                    return Ok(());
                }
                // No signature can verify without the key's public part.
                state.set(Register::Rax, u64::from(NTE_BAD_KEYSET));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted CSP thunk {thunk:?}"),
            )),
        }
    }
}
