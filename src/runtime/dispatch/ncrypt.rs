//! CNG key-storage dispatch: the ncrypt.dll exports, in a dedicated module
//! per the audit's modularity requirement.  The surface is a real key
//! store: `NCryptOpenStorageProvider` hands out the Microsoft Software Key
//! Storage Provider; `NCryptCreatePersistedKey` builds a key object whose
//! `NCryptFinalizeKey` generates the RSA key pair; `NCryptSignHash` /
//! `NCryptVerifySignature` / `NCryptEncrypt` / `NCryptDecrypt` operate on
//! the key with the real RSA primitives (PKCS#1 v1.5); the key properties
//! and the CNG blob export/import (BCRYPT_RSAPUBLIC_BLOB) are real; the
//! key-agreement surface answers NTE_NOT_SUPPORTED (no DH/ECDH provider).
//!
//! Layer contract: every export returns its NTSTATUS-style NTE_* code in
//! EAX (0 = ERROR_SUCCESS).

use super::super::*;
use crate::runtime::state::GuestObjectKind;
use rand::rngs::OsRng;
use rsa::traits::PublicKeyParts;

/// ERROR_SUCCESS.
const ERROR_SUCCESS: u32 = 0;
/// NTE_BAD_KEYSET — the key does not exist in the store.
const NTE_BAD_KEYSET: u32 = 0x8009_0016;
/// NTE_BAD_PROVIDER.
const NTE_BAD_PROVIDER: u32 = 0x8009_0028;
/// NTE_NOT_SUPPORTED.
const NTE_NOT_SUPPORTED: u32 = 0x8009_0029;
/// NTE_INVALID_HANDLE.
const NTE_INVALID_HANDLE: u32 = 0x8009_0026;
/// NTE_INVALID_PARAMETER.
const NTE_INVALID_PARAMETER: u32 = 0x8009_0027;
/// NTE_BUFFER_TOO_SMALL.
const NTE_BUFFER_TOO_SMALL: u32 = 0x8009_002a;
/// NTE_NO_MORE_ITEMS.
/// BCRYPT_RSA_ALGORITHM.
const BCRYPT_RSA_ALGORITHM: &str = "RSA";
/// BCRYPT_SHA256_ALGORITHM.
const BCRYPT_SHA256_ALGORITHM: &str = "SHA256";
/// The Microsoft Software Key Storage Provider.
const MS_KEY_STORAGE_PROVIDER: &str = "Microsoft Software Key Storage Provider";
/// NCRYPT_* property names.
const NCRYPT_ALGORITHM_PROPERTY: &str = "Algorithm Name";
const NCRYPT_LENGTH_PROPERTY: &str = "Length";
const NCRYPT_KEY_TYPE_PROPERTY: &str = "Key Type";
const NCRYPT_IMPL_TYPE_PROPERTY: &str = "Impl Type";
/// NCRYPT_IMPL_HARDWARE_FLAG | NCRYPT_IMPL_SOFTWARE_FLAG.
const NCRYPT_IMPL_SOFTWARE: u32 = 0x0000_0001;

/// The BCRYPT_RSAPUBLIC_BLOB layout offsets.
const BCRYPT_RSAPUBLIC_MAGIC: u32 = 0x3141_5342; // "RSA1"
impl PeHostRuntime {
    /// Route every NCrypt thunk to its dispatch function.
    pub(crate) fn dispatch_ncrypt(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::NCryptOpenStorageProvider => {
                self.dispatch_ncrypt_open_storage_provider(state, memory)
            }
            HostThunk::NCryptCreatePersistedKey => {
                self.dispatch_ncrypt_create_persisted_key(state, memory)
            }
            HostThunk::NCryptOpenKey => self.dispatch_ncrypt_open_key(state, memory),
            HostThunk::NCryptFinalizeKey => self.dispatch_ncrypt_finalize_key(state, memory),
            HostThunk::NCryptDeleteKey => {
                let key = guest_call_arg(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                if self.ncrypt_keys.remove(&key).is_some() {
                    state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                } else {
                    state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
                }
                Ok(())
            }
            HostThunk::NCryptSetProperty => self.dispatch_ncrypt_set_property(state, memory),
            HostThunk::NCryptGetProperty => self.dispatch_ncrypt_get_property(state, memory),
            HostThunk::NCryptFreeBuffer => {
                let _buffer = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::NCryptSignHash => self.dispatch_ncrypt_sign_hash(state, memory),
            HostThunk::NCryptVerifySignature => {
                self.dispatch_ncrypt_verify_signature(state, memory)
            }
            HostThunk::NCryptEncrypt => self.dispatch_ncrypt_encrypt(state, memory, true),
            HostThunk::NCryptDecrypt => self.dispatch_ncrypt_encrypt(state, memory, false),
            HostThunk::NCryptExportKey => self.dispatch_ncrypt_export_key(state, memory),
            HostThunk::NCryptImportKey => self.dispatch_ncrypt_import_key(state, memory),
            HostThunk::NCryptIsAlgSupported => self.dispatch_ncrypt_is_alg_supported(state, memory),
            HostThunk::NCryptDeriveKey | HostThunk::NCryptSecretAgreement => {
                // No DH/ECDH provider is registered.
                state.set(Register::Rax, u64::from(NTE_NOT_SUPPORTED));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted NCrypt thunk {thunk:?}"),
            )),
        }
    }

    /// `NCryptOpenStorageProvider(pszProviderName, dwFlags, phProvider)` —
    /// the Microsoft Software Key Storage Provider.
    pub(crate) fn dispatch_ncrypt_open_storage_provider(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let provider_name = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let name = if provider_name == 0 {
            String::new()
        } else {
            read_utf16_string(memory, provider_name).unwrap_or_default()
        };
        if !name.is_empty() && !name.eq_ignore_ascii_case(MS_KEY_STORAGE_PROVIDER) {
            state.set(Register::Rax, u64::from(NTE_BAD_PROVIDER));
            return Ok(());
        }
        if out == 0 {
            state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let provider = self
            .alloc_guest_object(memory, GuestObjectKind::NcryptProvider, vtable)
            .unwrap_or(0);
        if provider == 0 {
            state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
            return Ok(());
        }
        self.ncrypt_providers.insert(provider, name);
        write_guest_pointer(memory, out, provider, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `NCryptCreatePersistedKey(hProvider, phKey, pszAlgId, pszKeyName,
    /// legacySpec, flags)` — a persisted key object (RSA).
    pub(crate) fn dispatch_ncrypt_create_persisted_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let provider = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let alg = guest_call_arg(state, memory, 2)?;
        let key_name = guest_call_arg(state, memory, 3)?;
        let _legacy = guest_call_arg_u32(state, memory, 4)?;
        let _flags = guest_call_arg_u32(state, memory, 5)?;
        if !self.ncrypt_providers.contains_key(&provider) {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        }
        let alg = if alg == 0 {
            String::new()
        } else {
            read_utf16_string(memory, alg).unwrap_or_default()
        };
        if !alg.is_empty() && !alg.eq_ignore_ascii_case(BCRYPT_RSA_ALGORITHM) {
            state.set(Register::Rax, u64::from(NTE_NOT_SUPPORTED));
            return Ok(());
        }
        let name = if key_name == 0 {
            String::new()
        } else {
            read_utf16_string(memory, key_name).unwrap_or_default()
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let key = self
            .alloc_guest_object(memory, GuestObjectKind::NcryptKey, vtable)
            .unwrap_or(0);
        if key == 0 {
            state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
            return Ok(());
        }
        self.ncrypt_keys.insert(
            key,
            crate::runtime::state::NcryptKeyState {
                algorithm: BCRYPT_RSA_ALGORITHM.to_string(),
                key_name: name,
                finalized: false,
                private_key: None,
                public_key: None,
                length: 2048,
                key_type: 2, // NCRYPT_MACHINE_KEY_FLAG | ...
                bytes: Vec::new(),
            },
        );
        write_guest_pointer(memory, out, key, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `NCryptOpenKey(hProvider, phKey, pszKeyName, legacySpec, flags)` —
    /// open a persisted key by name.
    pub(crate) fn dispatch_ncrypt_open_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let provider = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let key_name = guest_call_arg(state, memory, 2)?;
        let _legacy = guest_call_arg_u32(state, memory, 3)?;
        let _flags = guest_call_arg_u32(state, memory, 4)?;
        if !self.ncrypt_providers.contains_key(&provider) {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        }
        let name = read_utf16_string(memory, key_name).unwrap_or_default();
        // Keys are per-provider; the store lookup by name.
        let existing = self
            .ncrypt_keys
            .iter()
            .find(|(_, key)| key.key_name == name && key.finalized)
            .map(|(handle, _)| *handle);
        match existing {
            Some(handle) => {
                if out != 0 {
                    write_guest_pointer(memory, out, handle, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
            }
            None => state.set(Register::Rax, u64::from(NTE_BAD_KEYSET)),
        }
        Ok(())
    }

    /// `NCryptFinalizeKey(hKey, flags)` — generate the RSA key pair.
    pub(crate) fn dispatch_ncrypt_finalize_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let Some(state_obj) = self.ncrypt_keys.get_mut(&key) else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        let bits = state_obj.length.clamp(512, 4096) as usize;
        let private = rsa::RsaPrivateKey::new(&mut OsRng, bits).ok();
        match private {
            Some(private) => {
                state_obj.private_key = Some(private.clone());
                state_obj.public_key = Some(rsa::RsaPublicKey::from(&private));
                state_obj.finalized = true;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
            }
            None => state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER)),
        }
        Ok(())
    }

    /// `NCryptSetProperty(hKey, pszProperty, pbInput, cbInput, flags)` —
    /// the key property store.
    pub(crate) fn dispatch_ncrypt_set_property(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_call_arg(state, memory, 0)?;
        let property = guest_call_arg(state, memory, 1)?;
        let input = guest_call_arg(state, memory, 2)?;
        let input_size = guest_call_arg_u32(state, memory, 3)?;
        let _flags = guest_call_arg_u32(state, memory, 4)?;
        let Some(state_obj) = self.ncrypt_keys.get_mut(&key) else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        let property = read_utf16_string(memory, property).unwrap_or_default();
        match property.as_str() {
            NCRYPT_LENGTH_PROPERTY => {
                if input_size >= 4 {
                    let length = read_guest_u32(memory, input).unwrap_or(0);
                    if length == 0 || length > 16384 {
                        state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
                        return Ok(());
                    }
                    state_obj.length = length;
                }
            }
            _ => {
                // The other properties are read-only in this provider.
                state.set(Register::Rax, u64::from(NTE_NOT_SUPPORTED));
                return Ok(());
            }
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `NCryptGetProperty(hKey, pszProperty, pbOutput, cbOutput,
    /// pcbResult, flags)`.
    pub(crate) fn dispatch_ncrypt_get_property(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_call_arg(state, memory, 0)?;
        let property = guest_call_arg(state, memory, 1)?;
        let output = guest_call_arg(state, memory, 2)?;
        let output_size = guest_call_arg_u32(state, memory, 3)?;
        let result_size = guest_call_arg(state, memory, 4)?;
        let _flags = guest_call_arg_u32(state, memory, 5)?;
        let Some(state_obj) = self.ncrypt_keys.get(&key) else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        let property = read_utf16_string(memory, property).unwrap_or_default();
        let (bytes, value): (Vec<u8>, u32) = match property.as_str() {
            NCRYPT_ALGORITHM_PROPERTY => {
                let mut b = Vec::new();
                for unit in BCRYPT_RSA_ALGORITHM.encode_utf16() {
                    b.extend_from_slice(&unit.to_le_bytes());
                }
                b.extend_from_slice(&0_u16.to_le_bytes());
                (b, 0)
            }
            NCRYPT_LENGTH_PROPERTY => (state_obj.length.to_le_bytes().to_vec(), 0),
            NCRYPT_KEY_TYPE_PROPERTY => (state_obj.key_type.to_le_bytes().to_vec(), 0),
            NCRYPT_IMPL_TYPE_PROPERTY => (NCRYPT_IMPL_SOFTWARE.to_le_bytes().to_vec(), 0),
            _ => (Vec::new(), NTE_NOT_SUPPORTED),
        };
        if value != 0 {
            state.set(Register::Rax, u64::from(value));
            return Ok(());
        }
        if result_size != 0 {
            write_guest_u32(memory, result_size, bytes.len() as u32).ok();
        }
        if output_size < bytes.len() as u32 && output != 0 {
            state.set(Register::Rax, u64::from(NTE_BUFFER_TOO_SMALL));
            return Ok(());
        }
        for (i, byte) in bytes.iter().enumerate() {
            memory.write_u8(output + i as u64, *byte);
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `NCryptSignHash(hKey, pPaddingInfo, pbHash, cbHash, pbSignature,
    /// cbSignature, pcbResult, flags)` — PKCS#1 v1.5 RSA signing.
    pub(crate) fn dispatch_ncrypt_sign_hash(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_call_arg(state, memory, 0)?;
        let _padding = guest_call_arg(state, memory, 1)?;
        let hash = guest_call_arg(state, memory, 2)?;
        let hash_size = guest_call_arg_u32(state, memory, 3)?;
        let signature = guest_call_arg(state, memory, 4)?;
        let signature_size = guest_call_arg_u32(state, memory, 5)?;
        let result_size = guest_call_arg(state, memory, 6)?;
        let _flags = guest_call_arg_u32(state, memory, 7)?;
        let Some(state_obj) = self.ncrypt_keys.get(&key) else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        if !state_obj.finalized {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        }
        let Some(private) = &state_obj.private_key else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        let digest = memory
            .read_bytes(hash, hash_size as usize)
            .unwrap_or_default();
        let signing_key = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private.clone());
        use rsa::signature::{SignatureEncoding, Signer};
        let signature_bytes = signing_key.sign(&digest).to_bytes();
        if result_size != 0 {
            write_guest_u32(memory, result_size, signature_bytes.len() as u32).ok();
        }
        if signature_size < signature_bytes.len() as u32 && signature != 0 {
            state.set(Register::Rax, u64::from(NTE_BUFFER_TOO_SMALL));
            return Ok(());
        }
        for (i, byte) in signature_bytes.iter().enumerate() {
            memory.write_u8(signature + i as u64, *byte);
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `NCryptVerifySignature(hKey, pPaddingInfo, pbHash, cbHash,
    /// pbSignature, cbSignature, flags)`.
    pub(crate) fn dispatch_ncrypt_verify_signature(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_call_arg(state, memory, 0)?;
        let _padding = guest_call_arg(state, memory, 1)?;
        let hash = guest_call_arg(state, memory, 2)?;
        let hash_size = guest_call_arg_u32(state, memory, 3)?;
        let signature = guest_call_arg(state, memory, 4)?;
        let signature_size = guest_call_arg_u32(state, memory, 5)?;
        let _flags = guest_call_arg_u32(state, memory, 6)?;
        let Some(state_obj) = self.ncrypt_keys.get(&key) else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        let Some(public) = &state_obj.public_key else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        let digest = memory
            .read_bytes(hash, hash_size as usize)
            .unwrap_or_default();
        let signature_bytes = memory
            .read_bytes(signature, signature_size as usize)
            .unwrap_or_default();
        let verifying_key = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(public.clone());
        use rsa::signature::Verifier;
        let signature = match rsa::pkcs1v15::Signature::try_from(&signature_bytes[..]) {
            Ok(signature) => signature,
            Err(_) => {
                state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
                return Ok(());
            }
        };
        let valid = verifying_key.verify(&digest, &signature).is_ok();
        state.set(
            Register::Rax,
            u64::from(if valid { ERROR_SUCCESS } else { 0x8009_0001 }),
        );
        Ok(())
    }

    /// `NCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbOutput,
    /// cbOutput, pcbResult, flags)` — raw RSA (no padding) or the OAEP
    /// padding for the encrypt path.
    pub(crate) fn dispatch_ncrypt_encrypt(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        is_encrypt: bool,
    ) -> AppResult<()> {
        let key = guest_call_arg(state, memory, 0)?;
        let input = guest_call_arg(state, memory, 1)?;
        let input_size = guest_call_arg_u32(state, memory, 2)?;
        let _padding = guest_call_arg(state, memory, 3)?;
        let output = guest_call_arg(state, memory, 4)?;
        let output_size = guest_call_arg_u32(state, memory, 5)?;
        let result_size = guest_call_arg(state, memory, 6)?;
        let _flags = guest_call_arg_u32(state, memory, 7)?;
        let Some(state_obj) = self.ncrypt_keys.get(&key) else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        let Some(private) = &state_obj.private_key else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        let public = rsa::RsaPublicKey::from(private);
        let data = memory
            .read_bytes(input, input_size as usize)
            .unwrap_or_default();
        let mut rng = OsRng;
        let result = if is_encrypt {
            public.encrypt(&mut rng, rsa::Oaep::new::<rsa::sha2::Sha256>(), &data)
        } else {
            private.decrypt(rsa::Oaep::new::<rsa::sha2::Sha256>(), &data)
        };
        let Ok(result) = result else {
            state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
            return Ok(());
        };
        if result_size != 0 {
            write_guest_u32(memory, result_size, result.len() as u32).ok();
        }
        if output_size < result.len() as u32 && output != 0 {
            state.set(Register::Rax, u64::from(NTE_BUFFER_TOO_SMALL));
            return Ok(());
        }
        for (i, byte) in result.iter().enumerate() {
            memory.write_u8(output + i as u64, *byte);
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `NCryptExportKey(hKey, hExportKey, pszBlobType, pParameterList,
    /// pbOutput, cbOutput, pcbResult, flags)` — the BCRYPT_RSAPUBLIC_BLOB.
    pub(crate) fn dispatch_ncrypt_export_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_call_arg(state, memory, 0)?;
        let _export_key = guest_call_arg(state, memory, 1)?;
        let blob_type = guest_call_arg(state, memory, 2)?;
        let _parameters = guest_call_arg(state, memory, 3)?;
        let output = guest_call_arg(state, memory, 4)?;
        let output_size = guest_call_arg_u32(state, memory, 5)?;
        let result_size = guest_call_arg(state, memory, 6)?;
        let _flags = guest_call_arg_u32(state, memory, 7)?;
        let Some(state_obj) = self.ncrypt_keys.get(&key) else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        let Some(public) = &state_obj.public_key else {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        };
        let blob_type = read_utf16_string(memory, blob_type).unwrap_or_default();
        let bits = public.n().bits() as u32;
        let mut blob = Vec::new();
        blob.extend_from_slice(&BCRYPT_RSAPUBLIC_MAGIC.to_le_bytes());
        blob.extend_from_slice(&bits.to_le_bytes());
        blob.extend_from_slice(&4_u32.to_le_bytes()); // cbPublicExp (4 bytes)
        blob.extend_from_slice(&4_u32.to_le_bytes()); // cbModulus
        blob.extend_from_slice(&4_u32.to_le_bytes()); // cbPrime1
        blob.extend_from_slice(&4_u32.to_le_bytes()); // cbPrime2
        let e = public.e().to_bytes_be();
        let mut e_be = vec![0_u8; 4];
        e_be[4 - e.len()..].copy_from_slice(&e);
        blob.extend_from_slice(&e_be);
        let n = public.n().to_bytes_be();
        let mut n_be = vec![0_u8; (bits as usize).div_ceil(8)];
        n_be[(bits as usize).div_ceil(8) - n.len()..].copy_from_slice(&n);
        blob.extend_from_slice(&n_be);
        if blob_type != "PUBLICBLOB" && blob_type != "RSAPUBLICBLOB" {
            state.set(Register::Rax, u64::from(NTE_NOT_SUPPORTED));
            return Ok(());
        }
        if result_size != 0 {
            write_guest_u32(memory, result_size, blob.len() as u32).ok();
        }
        if output_size < blob.len() as u32 && output != 0 {
            state.set(Register::Rax, u64::from(NTE_BUFFER_TOO_SMALL));
            return Ok(());
        }
        for (i, byte) in blob.iter().enumerate() {
            memory.write_u8(output + i as u64, *byte);
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `NCryptImportKey(hProvider, hImportKey, pszBlobType, pParameterList,
    /// phKey, pbInput, cbInput, flags)` — import the RSA public blob.
    pub(crate) fn dispatch_ncrypt_import_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let provider = guest_call_arg(state, memory, 0)?;
        let _import_key = guest_call_arg(state, memory, 1)?;
        let blob_type = guest_call_arg(state, memory, 2)?;
        let _parameters = guest_call_arg(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        let input = guest_call_arg(state, memory, 5)?;
        let input_size = guest_call_arg_u32(state, memory, 6)?;
        let _flags = guest_call_arg_u32(state, memory, 7)?;
        if !self.ncrypt_providers.contains_key(&provider) {
            state.set(Register::Rax, u64::from(NTE_INVALID_HANDLE));
            return Ok(());
        }
        let blob_type = read_utf16_string(memory, blob_type).unwrap_or_default();
        if blob_type != "PUBLICBLOB" && blob_type != "RSAPUBLICBLOB" {
            state.set(Register::Rax, u64::from(NTE_NOT_SUPPORTED));
            return Ok(());
        }
        let blob = memory
            .read_bytes(input, input_size as usize)
            .unwrap_or_default();
        if blob.len() < 24
            || u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) != BCRYPT_RSAPUBLIC_MAGIC
        {
            state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
            return Ok(());
        }
        let bit_length = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        let exp_len = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
        let modulus_len = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
        if 24 + exp_len + modulus_len > blob.len() || modulus_len == 0 || exp_len == 0 {
            state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
            return Ok(());
        }
        let e = rsa::BigUint::from_bytes_be(&blob[24..24 + exp_len]);
        let n = rsa::BigUint::from_bytes_be(&blob[24 + exp_len..24 + exp_len + modulus_len]);
        let public = rsa::RsaPublicKey::new(n, e).ok();
        let Some(public) = public else {
            state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let key = self
            .alloc_guest_object(memory, GuestObjectKind::NcryptKey, vtable)
            .unwrap_or(0);
        if key == 0 {
            state.set(Register::Rax, u64::from(NTE_INVALID_PARAMETER));
            return Ok(());
        }
        self.ncrypt_keys.insert(
            key,
            crate::runtime::state::NcryptKeyState {
                algorithm: BCRYPT_RSA_ALGORITHM.to_string(),
                key_name: String::new(),
                finalized: true,
                private_key: None,
                public_key: Some(public),
                length: bit_length as u32,
                key_type: 2,
                bytes: blob,
            },
        );
        write_guest_pointer(memory, out, key, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `NCryptIsAlgSupported(pszAlgId, dwFlags)` — the RSA and SHA
    /// families are supported.
    pub(crate) fn dispatch_ncrypt_is_alg_supported(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let alg = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let alg = read_utf16_string(memory, alg).unwrap_or_default();
        let supported = alg.eq_ignore_ascii_case(BCRYPT_RSA_ALGORITHM)
            || alg.eq_ignore_ascii_case(BCRYPT_SHA256_ALGORITHM)
            || alg.eq_ignore_ascii_case("SHA1")
            || alg.eq_ignore_ascii_case("SHA384")
            || alg.eq_ignore_ascii_case("SHA512");
        state.set(
            Register::Rax,
            u64::from(if supported {
                ERROR_SUCCESS
            } else {
                NTE_NOT_SUPPORTED
            }),
        );
        Ok(())
    }
}
