//! Runtime state types for the software TPM: hierarchies, primary/public
//! areas, transient objects, NV indices, and authorization sessions.

use std::collections::BTreeMap;

use p256::SecretKey;
use rsa::RsaPrivateKey;

use super::constants::{
    NV_INDEX_BASE, NV_INDEX_LAST, TPM_ALG_ECC, TPM_ALG_NULL, TPM_ALG_RSA, TPM_RC_TYPE,
    TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM,
};
use super::crypto::{hash, hash_len};
use super::persist::{NvPersisted, PersistedState};
use super::wire::{Reader, Writer};

// ---------------------------------------------------------------------------
// Hierarchies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hierarchy {
    Owner,
    Endorsement,
    Lockout,
    Platform,
}

impl Hierarchy {
    pub fn from_handle(handle: u32) -> Option<Self> {
        match handle {
            TPM_RH_OWNER => Some(Self::Owner),
            TPM_RH_ENDORSEMENT => Some(Self::Endorsement),
            TPM_RH_LOCKOUT => Some(Self::Lockout),
            TPM_RH_PLATFORM => Some(Self::Platform),
            _ => None,
        }
    }

    pub fn handle(self) -> u32 {
        match self {
            Self::Owner => TPM_RH_OWNER,
            Self::Endorsement => TPM_RH_ENDORSEMENT,
            Self::Lockout => TPM_RH_LOCKOUT,
            Self::Platform => TPM_RH_PLATFORM,
        }
    }

    pub fn seed(self, state: &PersistedState) -> [u8; 32] {
        match self {
            Self::Owner => state.owner_seed,
            Self::Endorsement => state.endorsement_seed,
            Self::Lockout => state.lockout_seed,
            Self::Platform => state.platform_seed,
        }
    }

    pub fn auth<'a>(self, state: &'a PersistedState) -> &'a [u8] {
        match self {
            Self::Owner => &state.owner_auth,
            Self::Endorsement => &state.endorsement_auth,
            Self::Lockout => &state.lockout_auth,
            Self::Platform => &state.platform_auth,
        }
    }

    pub fn auth_mut<'a>(self, state: &'a mut PersistedState) -> &'a mut Vec<u8> {
        match self {
            Self::Owner => &mut state.owner_auth,
            Self::Endorsement => &mut state.endorsement_auth,
            Self::Lockout => &mut state.lockout_auth,
            Self::Platform => &mut state.platform_auth,
        }
    }
}

// ---------------------------------------------------------------------------
// Public areas
// ---------------------------------------------------------------------------

/// Parsed `TPMT_PUBLIC` with the bytes needed to re-marshal a generated
/// public area and compute its TPM name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicArea {
    pub object_type: u16,
    pub name_alg: u16,
    pub object_attributes: u32,
    pub scheme: u16,
    pub scheme_hash: u16,
    pub key_bits: u16,
    pub exponent: u32,
    pub curve: u16,
    /// Bytes before the `unique` field (the template prefix).
    pub prefix: Vec<u8>,
    /// Encoded `unique` field, including `TPM2B` length prefixes.
    pub unique: Vec<u8>,
    /// Full marshaled `TPMT_PUBLIC`.
    pub raw: Vec<u8>,
    pub rsa_modulus: Vec<u8>,
    pub ecc_x: Vec<u8>,
    pub ecc_y: Vec<u8>,
}

impl PublicArea {
    /// Parse a marshaled `TPMT_PUBLIC` and validate the type-specific fields.
    pub fn parse(raw: &[u8]) -> Result<Self, u32> {
        let mut reader = Reader::new(raw);
        let object_type = reader.u16()?;
        let name_alg = reader.u16()?;
        if hash_len(name_alg).is_none() {
            return Err(super::constants::TPM_RC_HASH);
        }
        let object_attributes = reader.u32()?;
        let _auth_policy = reader.tpm2b(64)?;
        let (
            scheme,
            scheme_hash,
            key_bits,
            exponent,
            curve,
            unique_offset,
            rsa_modulus,
            ecc_x,
            ecc_y,
        ) = match object_type {
            TPM_ALG_RSA => {
                let symmetric = reader.u16()?;
                if symmetric != TPM_ALG_NULL {
                    let _key_bits = reader.u16()?;
                    let _mode = reader.u16()?;
                }
                let scheme = reader.u16()?;
                let scheme_hash = if scheme != TPM_ALG_NULL {
                    reader.u16()?
                } else {
                    0
                };
                let key_bits = reader.u16()?;
                let exponent = reader.u32()?;
                let unique_offset = reader.position();
                let modulus = reader.tpm2b(512)?.to_vec();
                (
                    scheme,
                    scheme_hash,
                    key_bits,
                    exponent,
                    0,
                    unique_offset,
                    modulus,
                    Vec::new(),
                    Vec::new(),
                )
            }
            TPM_ALG_ECC => {
                let symmetric = reader.u16()?;
                if symmetric != TPM_ALG_NULL {
                    let _key_bits = reader.u16()?;
                    let _mode = reader.u16()?;
                }
                let scheme = reader.u16()?;
                let scheme_hash = if scheme != TPM_ALG_NULL {
                    reader.u16()?
                } else {
                    0
                };
                let curve = reader.u16()?;
                let kdf = reader.u16()?;
                if kdf != TPM_ALG_NULL {
                    let _kdf_hash = reader.u16()?;
                }
                let unique_offset = reader.position();
                let x = reader.tpm2b(64)?.to_vec();
                let y = reader.tpm2b(64)?.to_vec();
                (
                    scheme,
                    scheme_hash,
                    256,
                    0,
                    curve,
                    unique_offset,
                    Vec::new(),
                    x,
                    y,
                )
            }
            _ => return Err(TPM_RC_TYPE),
        };
        reader.finish()?;
        Ok(Self {
            object_type,
            name_alg,
            object_attributes,
            scheme,
            scheme_hash,
            key_bits,
            exponent,
            curve,
            prefix: raw[..unique_offset].to_vec(),
            unique: raw[unique_offset..].to_vec(),
            raw: raw.to_vec(),
            rsa_modulus,
            ecc_x,
            ecc_y,
        })
    }

    /// Clone the template and replace its `unique` field.
    pub fn with_unique(&self, unique: Vec<u8>, modulus: Vec<u8>, x: Vec<u8>, y: Vec<u8>) -> Self {
        let mut raw = self.prefix.clone();
        raw.extend_from_slice(&unique);
        Self {
            unique,
            raw,
            rsa_modulus: modulus,
            ecc_x: x,
            ecc_y: y,
            ..self.clone()
        }
    }

    pub fn name(&self) -> Vec<u8> {
        let mut name = self.name_alg.to_be_bytes().to_vec();
        if let Some(digest) = hash(self.name_alg, &self.raw) {
            name.extend_from_slice(&digest);
        }
        name
    }

    pub fn is_signing_key(&self) -> bool {
        self.object_attributes & super::constants::TPMA_OBJECT_SIGN != 0
    }
}

// ---------------------------------------------------------------------------
// Transient objects
// ---------------------------------------------------------------------------

pub enum KeyMaterial {
    Rsa(RsaPrivateKey),
    Ecc(SecretKey),
}

pub struct Object {
    pub public: PublicArea,
    pub name: Vec<u8>,
    pub auth: Vec<u8>,
    pub key: KeyMaterial,
    pub child_seed: [u8; 32],
}

// ---------------------------------------------------------------------------
// NV indices
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvIndex {
    pub index: u32,
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub data_size: u16,
    pub auth: Vec<u8>,
    pub data: Vec<u8>,
    pub written: bool,
    pub write_locked: bool,
    pub read_locked: bool,
    pub public_raw: Vec<u8>,
}

impl NvIndex {
    pub fn from_public(
        index: u32,
        name_alg: u16,
        attributes: u32,
        auth_policy: Vec<u8>,
        data_size: u16,
        auth: Vec<u8>,
        public_raw: Vec<u8>,
    ) -> Self {
        Self {
            index,
            name_alg,
            attributes,
            auth_policy,
            data_size,
            auth,
            data: Vec::new(),
            written: false,
            write_locked: false,
            read_locked: false,
            public_raw,
        }
    }

    pub fn name(&self) -> Vec<u8> {
        let mut name = self.name_alg.to_be_bytes().to_vec();
        if let Some(digest) = hash(self.name_alg, &self.public_raw) {
            name.extend_from_slice(&digest);
        }
        name
    }

    pub fn to_persisted(&self) -> NvPersisted {
        NvPersisted {
            index: self.index,
            name_alg: self.name_alg,
            attributes: self.attributes,
            auth_policy: self.auth_policy.clone(),
            data_size: self.data_size,
            auth: self.auth.clone(),
            data: self.data.clone(),
            written: self.written,
            write_locked: self.write_locked,
            read_locked: self.read_locked,
        }
    }

    pub fn from_persisted(entry: NvPersisted) -> Self {
        let mut writer = Writer::new();
        writer.u32(entry.index);
        writer.u16(entry.name_alg);
        writer.u32(entry.attributes);
        writer.tpm2b(&entry.auth_policy);
        writer.u16(entry.data_size);
        let public_raw = writer.into_vec();
        Self {
            index: entry.index,
            name_alg: entry.name_alg,
            attributes: entry.attributes,
            auth_policy: entry.auth_policy,
            data_size: entry.data_size,
            auth: entry.auth,
            data: entry.data,
            written: entry.written,
            write_locked: entry.write_locked,
            read_locked: entry.read_locked,
            public_raw,
        }
    }

    pub fn nv_public(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.tpm2b(&self.public_raw);
        writer.into_vec()
    }

    pub fn is_valid_index(index: u32) -> bool {
        (NV_INDEX_BASE..=NV_INDEX_LAST).contains(&index)
    }
}

// ---------------------------------------------------------------------------
// Authorization sessions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCommand {
    pub handle: u32,
    pub nonce: Vec<u8>,
    pub attributes: u8,
    pub hmac: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub handle: u32,
    pub nonce_tpm: [u8; 32],
    pub session_key: [u8; 32],
    pub auth_hash: u16,
    pub bound_entity: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionMaterial {
    pub handle: u32,
    pub nonce_tpm: [u8; 32],
    pub session_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseSession {
    pub handle: u32,
    pub nonce_tpm: [u8; 32],
    pub session_key: [u8; 32],
    pub nonce_caller: Vec<u8>,
    pub attributes: u8,
}

/// Authorization handle kind for an incoming command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTarget {
    Hierarchy(Hierarchy),
    Object(u32),
    Nv(u32),
    Pcr(u32),
}

impl AuthTarget {
    pub fn expected_auth<'a>(
        self,
        state: &'a PersistedState,
        objects: &'a BTreeMap<u32, Object>,
    ) -> &'a [u8] {
        match self {
            Self::Hierarchy(hierarchy) => hierarchy.auth(state),
            Self::Object(handle) => objects
                .get(&handle)
                .map(|object| object.auth.as_slice())
                .unwrap_or(&[]),
            Self::Nv(index) => state
                .nv
                .iter()
                .find(|entry| entry.index == index)
                .map(|entry| entry.auth.as_slice())
                .unwrap_or(&[]),
            Self::Pcr(_) => &[],
        }
    }
}

/// Parse the `TPMS_NV_PUBLIC` payload of a `TPM2B_NV_PUBLIC`.
pub fn parse_nv_public(raw: &[u8]) -> Result<(u32, u16, u32, Vec<u8>, u16), u32> {
    let mut reader = Reader::new(raw);
    let index = reader.u32()?;
    let name_alg = reader.u16()?;
    let attributes = reader.u32()?;
    let auth_policy = reader.tpm2b(64)?.to_vec();
    let data_size = reader.u16()?;
    reader.finish()?;
    Ok((index, name_alg, attributes, auth_policy, data_size))
}
