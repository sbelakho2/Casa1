//! Atomic persistence for per-game-environment TPM state.
//!
//! The state file is deliberately self-describing and checksummed:
//!
//! ```text
//! "CASA1TPM" | version:u32 | payload_len:u64 | JSON payload | SHA-256 digest
//! ```
//!
//! A missing file starts a fresh TPM; a corrupt file is rejected with a
//! specific [`Corruption`] and is never overwritten or reset.  Saving writes a
//! sibling temporary file, fsyncs it, and renames it over the target so a
//! crash cannot leave a half-written state file.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::constants::{
    MAX_DIGEST_SIZE, MAX_NV_INDICES, MAX_NV_SIZE, PCR_COUNT, TPM_ALG_SHA1, TPM_ALG_SHA256,
    TPM_ALG_SHA384, TPM_ALG_SHA512, is_nv_index,
};
use super::crypto::Drbg;

const MAGIC: &[u8; 8] = b"CASA1TPM";
const FORMAT_VERSION: u32 = 1;
const HEADER_LEN: usize = 8 + 4 + 8;
const DIGEST_LEN: usize = 32;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Persisted NV index state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NvPersisted {
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
}

/// All state that survives an orderly shutdown or a process restart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedState {
    pub format: u32,
    pub owner_seed: [u8; 32],
    pub endorsement_seed: [u8; 32],
    pub platform_seed: [u8; 32],
    pub lockout_seed: [u8; 32],
    pub session_seed: [u8; 32],
    pub owner_auth: Vec<u8>,
    pub endorsement_auth: Vec<u8>,
    pub lockout_auth: Vec<u8>,
    pub platform_auth: Vec<u8>,
    pub pcrs: Vec<[u8; 32]>,
    pub pcr_update_counter: u32,
    pub nv: Vec<NvPersisted>,
    pub drbg: Drbg,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
}

impl PersistedState {
    /// Build a fresh state from 32 bytes of host entropy.
    pub fn fresh(entropy: [u8; 32]) -> Self {
        use super::crypto::derive_seed;
        Self {
            format: FORMAT_VERSION,
            owner_seed: derive_seed(&entropy, b"casa1-tpm-seed-owner-v1"),
            endorsement_seed: derive_seed(&entropy, b"casa1-tpm-seed-endorsement-v1"),
            platform_seed: derive_seed(&entropy, b"casa1-tpm-seed-platform-v1"),
            lockout_seed: derive_seed(&entropy, b"casa1-tpm-seed-lockout-v1"),
            session_seed: derive_seed(&entropy, b"casa1-tpm-seed-session-v1"),
            owner_auth: Vec::new(),
            endorsement_auth: Vec::new(),
            lockout_auth: Vec::new(),
            platform_auth: Vec::new(),
            pcrs: vec![[0u8; 32]; PCR_COUNT],
            pcr_update_counter: 0,
            nv: Vec::new(),
            drbg: Drbg::from_seed(derive_seed(&entropy, b"casa1-tpm-seed-drbg-v1")),
            clock: 0,
            reset_count: 1,
            restart_count: 1,
        }
    }

    pub fn validate(&self) -> Result<(), Corruption> {
        if self.format != FORMAT_VERSION {
            return Err(Corruption::StateVersion(self.format));
        }
        if self.pcrs.len() != PCR_COUNT {
            return Err(Corruption::InvalidPcrCount(self.pcrs.len()));
        }
        for (name, auth) in [
            ("owner", &self.owner_auth),
            ("endorsement", &self.endorsement_auth),
            ("lockout", &self.lockout_auth),
            ("platform", &self.platform_auth),
        ] {
            let _ = name;
            if auth.len() > MAX_DIGEST_SIZE {
                return Err(Corruption::InvalidAuth(auth.len()));
            }
        }
        if self.nv.len() > MAX_NV_INDICES {
            return Err(Corruption::InvalidNvCount(self.nv.len()));
        }
        let mut seen = Vec::with_capacity(self.nv.len());
        for entry in &self.nv {
            if !is_nv_index(entry.index) || seen.contains(&entry.index) {
                return Err(Corruption::InvalidNvIndex(entry.index));
            }
            seen.push(entry.index);
            if entry.data_size == 0 || entry.data_size as usize > MAX_NV_SIZE {
                return Err(Corruption::InvalidNvSize(entry.data_size));
            }
            if entry.data.len() > entry.data_size as usize {
                return Err(Corruption::InvalidNvData {
                    data: entry.data.len(),
                    size: entry.data_size,
                });
            }
            if entry.auth.len() > MAX_DIGEST_SIZE {
                return Err(Corruption::InvalidAuth(entry.auth.len()));
            }
            if !matches!(
                entry.name_alg,
                TPM_ALG_SHA1 | TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA512
            ) {
                return Err(Corruption::InvalidNameAlg(entry.name_alg));
            }
        }
        Ok(())
    }
}

/// A precise reason a state file was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corruption {
    ShortHeader,
    BadMagic,
    UnsupportedVersion(u32),
    LengthMismatch { declared: u64, actual: u64 },
    ChecksumMismatch,
    Payload,
    StateVersion(u32),
    InvalidPcrCount(usize),
    InvalidNvCount(usize),
    InvalidNvIndex(u32),
    InvalidNvSize(u16),
    InvalidNvData { data: usize, size: u16 },
    InvalidAuth(usize),
    InvalidNameAlg(u16),
}

impl std::fmt::Display for Corruption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Persistence failure.  I/O errors and corrupt files are distinguished so a
/// caller (TBS) can map the former to `TBS_E_IOERROR` and never silently resets
/// a corrupt environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistError {
    Io(std::io::ErrorKind),
    Corrupt(Corruption),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "tpm state I/O error: {kind:?}"),
            Self::Corrupt(corruption) => write!(f, "tpm state corrupt: {corruption}"),
        }
    }
}

impl std::error::Error for PersistError {}

fn checksum(version: u32, payload_len: u64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MAGIC);
    hasher.update(version.to_be_bytes());
    hasher.update(payload_len.to_be_bytes());
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Serialize a state into the on-disk envelope.
pub fn encode(state: &PersistedState) -> Result<Vec<u8>, PersistError> {
    let payload =
        serde_json::to_vec(state).map_err(|_| PersistError::Corrupt(Corruption::Payload))?;
    let payload_len = payload.len() as u64;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + DIGEST_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&checksum(FORMAT_VERSION, payload_len, &payload));
    Ok(out)
}

/// Decode the on-disk envelope, rejecting every malformed variant precisely.
pub fn decode(bytes: &[u8]) -> Result<PersistedState, PersistError> {
    if bytes.len() < HEADER_LEN + DIGEST_LEN {
        return Err(PersistError::Corrupt(Corruption::ShortHeader));
    }
    if &bytes[..8] != MAGIC {
        return Err(PersistError::Corrupt(Corruption::BadMagic));
    }
    let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if version != FORMAT_VERSION {
        return Err(PersistError::Corrupt(Corruption::UnsupportedVersion(
            version,
        )));
    }
    let declared = u64::from_be_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ]);
    let actual = (bytes.len() - HEADER_LEN - DIGEST_LEN) as u64;
    if declared != actual {
        return Err(PersistError::Corrupt(Corruption::LengthMismatch {
            declared,
            actual,
        }));
    }
    let payload = &bytes[HEADER_LEN..HEADER_LEN + actual as usize];
    let stored = &bytes[HEADER_LEN + actual as usize..];
    if !super::crypto::ct_eq(&checksum(version, declared, payload), stored) {
        return Err(PersistError::Corrupt(Corruption::ChecksumMismatch));
    }
    let state: PersistedState =
        serde_json::from_slice(payload).map_err(|_| PersistError::Corrupt(Corruption::Payload))?;
    state.validate().map_err(PersistError::Corrupt)?;
    Ok(state)
}

/// Read a state file; `Ok(None)` means the file does not exist yet.
pub fn load(path: &Path) -> Result<Option<PersistedState>, PersistError> {
    match fs::read(path) {
        Ok(bytes) => decode(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(PersistError::Io(error.kind())),
    }
}

/// Atomically persist `state` at `path`.
pub fn save(path: &Path, state: &PersistedState) -> Result<(), PersistError> {
    let bytes = encode(state)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&parent).map_err(|error| PersistError::Io(error.kind()))?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_string());
    let temp = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = File::create(&temp).map_err(|error| PersistError::Io(error.kind()))?;
        file.write_all(&bytes)
            .map_err(|error| PersistError::Io(error.kind()))?;
        file.sync_all()
            .map_err(|error| PersistError::Io(error.kind()))?;
        drop(file);
        fs::rename(&temp, path).map_err(|error| PersistError::Io(error.kind()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Return the standard relative state path inside a game-environment root.
pub fn environment_state_path(root: &Path) -> PathBuf {
    root.join("tpm2").join("state.bin")
}
