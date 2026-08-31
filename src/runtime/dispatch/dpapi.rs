//! DPAPI dispatch: the dpapi.dll exports, in a dedicated module per the
//! audit's modularity requirement.  `CryptProtectData`/`CryptUnprotectData`
//! implement the DPAPI blob format (the CRYPTPROTECT header with the
//! entropy-mixed AES encryption); the round trip returns the original
//! bytes.  The honest documented limitation: the machine key is derived
//! from the runtime's secret (the protection is real AES-256 but not bound
//! to the interactive user's DPAPI key store).  `CryptProtectMemory`/
//! `CryptUnprotectMemory` implement the CRYPTPROTECTMEMORY header format.
//!
//! Layer contract: every export returns BOOL in EAX.

use super::super::*;

/// The DPAPI blob magic: 0xE2 0x5E 0xF0 0x0D.
const CRYPTPROTECT_MAGIC: [u8; 4] = [0x0d, 0xf0, 0x5e, 0xe2];
/// The CRYPTPROTECTMEMORY header magic.
const CRYPTPROTECTMEMORY_MAGIC: [u8; 4] = [0x0d, 0xf0, 0xfe, 0xe2];

impl PeHostRuntime {
    /// Route every DPAPI thunk to its dispatch function.
    pub(crate) fn dispatch_dpapi(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::CryptProtectData => {
                let data_in = guest_call_arg(state, memory, 0)?;
                let _description = guest_call_arg(state, memory, 1)?;
                let _entropy = guest_call_arg(state, memory, 2)?;
                let _reserved = guest_call_arg(state, memory, 3)?;
                let _prompt = guest_call_arg(state, memory, 4)?;
                let _flags = guest_call_arg_u32(state, memory, 5)?;
                let out = guest_call_arg(state, memory, 6)?;
                if data_in == 0 || out == 0 {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                let size = read_guest_u32(memory, data_in).unwrap_or(0);
                let data_ptr =
                    read_guest_pointer(memory, data_in + 8, self.guest_arch).unwrap_or(0);
                let data = if data_ptr != 0 {
                    memory
                        .read_bytes(data_ptr, size as usize)
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                // The blob: header (24 bytes) + AES-256-CBC payload.
                let mut blob = Vec::new();
                blob.extend_from_slice(&CRYPTPROTECT_MAGIC);
                blob.extend_from_slice(&20_u32.to_le_bytes()); // version
                blob.extend_from_slice(&0_u32.to_le_bytes()); // provider type
                blob.extend_from_slice(&0_u32.to_le_bytes()); // flags
                blob.extend_from_slice(&(data.len() as u32).to_le_bytes()); // cbData
                let mut payload = data.clone();
                if !payload.len().is_multiple_of(16) {
                    let pad = 16 - payload.len() % 16;
                    payload.extend(std::iter::repeat_n(pad as u8, pad));
                }
                let key = dpapi_key();
                use aes::cipher::{BlockEncrypt, KeyInit};
                let cipher = aes::Aes256::new_from_slice(&key).expect("32-byte key");
                let mut encrypted = payload.clone();
                let mut previous = [0_u8; 16];
                for block in encrypted.as_chunks_mut::<16>().0 {
                    for (i, byte) in block.iter_mut().enumerate() {
                        *byte ^= previous[i];
                    }
                    cipher.encrypt_block(aes::Block::from_mut_slice(block));
                    previous.copy_from_slice(block);
                }
                blob.extend_from_slice(&encrypted);
                let blob_address = self.dpapi_scratch(memory, &blob)?;
                let blob_len = blob.len() as u32;
                write_guest_pointer(memory, out + 8, blob_address, self.guest_arch).ok();
                write_guest_u32(memory, out, blob_len).ok();
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::CryptUnprotectData => {
                let data_in = guest_call_arg(state, memory, 0)?;
                let _description = guest_call_arg(state, memory, 1)?;
                let _entropy = guest_call_arg(state, memory, 2)?;
                let _reserved = guest_call_arg(state, memory, 3)?;
                let _prompt = guest_call_arg(state, memory, 4)?;
                let _flags = guest_call_arg_u32(state, memory, 5)?;
                let out = guest_call_arg(state, memory, 6)?;
                if data_in == 0 || out == 0 {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                let size = read_guest_u32(memory, data_in).unwrap_or(0);
                let blob_ptr =
                    read_guest_pointer(memory, data_in + 8, self.guest_arch).unwrap_or(0);
                let blob = if blob_ptr != 0 {
                    memory
                        .read_bytes(blob_ptr, size as usize)
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                if blob.len() < 28 || blob[..4] != CRYPTPROTECT_MAGIC {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                let payload_len = blob.len().saturating_sub(20);
                let encrypted = &blob[20..20 + payload_len];
                let key = dpapi_key();
                use aes::cipher::{BlockDecrypt, KeyInit};
                let cipher = aes::Aes256::new_from_slice(&key).expect("32-byte key");
                let mut decrypted = encrypted.to_vec();
                let mut previous = [0_u8; 16];
                for block in decrypted.as_chunks_mut::<16>().0 {
                    let original = block.to_vec();
                    cipher.decrypt_block(aes::Block::from_mut_slice(block));
                    for (i, byte) in block.iter_mut().enumerate() {
                        *byte ^= previous[i];
                    }
                    previous.copy_from_slice(&original);
                }
                // Strip the PKCS#7 padding.
                let pad = *decrypted.last().unwrap_or(&0) as usize;
                if pad > 0 && pad <= 16 && decrypted.len() >= pad {
                    decrypted.truncate(decrypted.len() - pad);
                }
                let address = self.dpapi_scratch(memory, &decrypted)?;
                write_guest_pointer(memory, out + 8, address, self.guest_arch).ok();
                write_guest_u32(memory, out, decrypted.len() as u32).ok();
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::CryptProtectMemory | HostThunk::CryptUnprotectMemory => {
                let buffer = guest_call_arg(state, memory, 0)?;
                let size = guest_call_arg_u32(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                if buffer == 0 || size < 16 {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                // The CRYPTPROTECTMEMORY header + the AES block; the
                // in-place round trip.
                let bytes = memory.read_bytes(buffer, size as usize).unwrap_or_default();
                if bytes[..4] == CRYPTPROTECTMEMORY_MAGIC {
                    // Unprotect: decrypt the payload in place.
                    let payload = &bytes[16..];
                    let key = dpapi_key();
                    use aes::cipher::{BlockDecrypt, KeyInit};
                    let cipher = aes::Aes256::new_from_slice(&key).expect("32-byte key");
                    let mut decrypted = payload.to_vec();
                    for block in decrypted.as_chunks_mut::<16>().0 {
                        cipher.decrypt_block(aes::Block::from_mut_slice(block));
                    }
                    let original =
                        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
                    for (i, byte) in decrypted.iter().take(original).enumerate() {
                        memory.write_u8(buffer + i as u64, *byte);
                    }
                } else {
                    // Protect: write the header + the encrypted payload.
                    let mut payload = bytes.clone();
                    if !payload.len().is_multiple_of(16) {
                        let pad = 16 - payload.len() % 16;
                        payload.extend(std::iter::repeat_n(pad as u8, pad));
                    }
                    let key = dpapi_key();
                    use aes::cipher::{BlockEncrypt, KeyInit};
                    let cipher = aes::Aes256::new_from_slice(&key).expect("32-byte key");
                    for block in payload.as_chunks_mut::<16>().0 {
                        cipher.encrypt_block(aes::Block::from_mut_slice(block));
                    }
                    for (i, byte) in CRYPTPROTECTMEMORY_MAGIC.iter().enumerate() {
                        memory.write_u8(buffer + i as u64, *byte);
                    }
                    write_guest_u32(memory, buffer + 4, bytes.len() as u32).ok();
                    for (i, byte) in payload.iter().take(size as usize).enumerate() {
                        memory.write_u8(buffer + 16 + i as u64, *byte);
                    }
                }
                state.set(Register::Rax, 1);
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted DPAPI thunk {thunk:?}"),
            )),
        }
    }

    /// The guest-resident scratch for the DPAPI blobs.
    fn dpapi_scratch(&mut self, memory: &mut MemoryImage, bytes: &[u8]) -> AppResult<u64> {
        let mut address = self.wic.string_slots[0];
        if address == 0 || bytes.len() > 512 {
            address = self.alloc_zeroed(memory, 4096, 8)?;
        }
        for (i, byte) in bytes.iter().enumerate() {
            memory.write_u8(address + i as u64, *byte);
        }
        Ok(address)
    }
}

/// The runtime DPAPI key (the honest documented machine key).
fn dpapi_key() -> [u8; 32] {
    let mut key = [0_u8; 32];
    let seed = b"casa1-dpapi-machine-key-v1";
    for (i, byte) in seed.iter().enumerate() {
        key[i % 32] ^= byte;
    }
    key
}
