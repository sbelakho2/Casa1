//! Persistent AOT profile store.
//!
//! A profile records which guest addresses a previous run actually reached:
//! hot blocks, direct call targets, indirect-call targets and function
//! entries.  The next launch seeds the whole-image precompile walk with those
//! addresses so code reached indirectly (and therefore invisible to the static
//! walk) is translated before guest entry.
//!
//! Every file is bound to an exact `(image hash, translator version, CPU
//! profile)` key and carries a checksum.  A record that does not match the
//! key, is truncated, has trailing bytes, or fails the checksum is rejected
//! with a stable error — stale code is never executed.
//!
//! Writes are atomic: bytes go to a sibling temporary file, are fsynced, and
//! are renamed over the destination.  A reader therefore sees either the old
//! complete profile or the new complete profile, never a partial write.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Profile file format version.
pub const AOT_PROFILE_FORMAT_VERSION: u32 = 1;
/// File name inside the image/translator/CPU-keyed cache directory.
pub const AOT_PROFILE_FILE_NAME: &str = "profile.bin";

const MAGIC: &[u8; 8] = b"C1PROF\0\0";
const HEADER_FIXED: usize = 8 + 4 + 4 + 8 + 2 + 4;
const RECORD_SIZE: usize = 1 + 8 + 8;
const CHECKSUM_SIZE: usize = 8;
const MAX_IMAGE_HASH_LEN: usize = 255;

/// Identity of one persistent AOT/profile store.  All three components are
/// part of the cache key; a mismatch rejects the file instead of loading it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileKey {
    pub image_hash: String,
    pub translator: u32,
    pub cpu_profile: u64,
}

impl ProfileKey {
    pub fn new(image_hash: impl Into<String>, translator: u32, cpu_profile: u64) -> Self {
        Self {
            image_hash: image_hash.into(),
            translator,
            cpu_profile,
        }
    }
}

/// Stable rejection reasons.  Messages are asserted verbatim by tests and are
/// reported by the precompile-only summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    Io(String),
    BadMagic,
    UnsupportedFormat { found: u32, expected: u32 },
    ChecksumMismatch { found: u64, expected: u64 },
    Truncated(&'static str),
    TrailingBytes,
    ImageHashMismatch { found: String, expected: String },
    TranslatorMismatch { found: u32, expected: u32 },
    CpuProfileMismatch { found: u64, expected: u64 },
    InvalidImageHash(String),
    UnknownTargetKind(u8),
    TooManyRecords(u64),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(f, "profile I/O error: {message}"),
            Self::BadMagic => write!(f, "profile bad magic"),
            Self::UnsupportedFormat { found, expected } => write!(
                f,
                "profile format mismatch: found {found}, expected {expected}"
            ),
            Self::ChecksumMismatch { found, expected } => write!(
                f,
                "profile checksum mismatch: found {found:016x}, expected {expected:016x}"
            ),
            Self::Truncated(what) => write!(f, "profile truncated: {what}"),
            Self::TrailingBytes => write!(f, "profile trailing bytes"),
            Self::ImageHashMismatch { found, expected } => write!(
                f,
                "profile image hash mismatch: found {found}, expected {expected}"
            ),
            Self::TranslatorMismatch { found, expected } => write!(
                f,
                "profile translator version mismatch: found {found}, expected {expected}"
            ),
            Self::CpuProfileMismatch { found, expected } => write!(
                f,
                "profile CPU profile mismatch: found {found:016x}, expected {expected:016x}"
            ),
            Self::InvalidImageHash(hash) => write!(f, "profile invalid image hash: {hash}"),
            Self::UnknownTargetKind(kind) => write!(f, "profile unknown target kind {kind}"),
            Self::TooManyRecords(count) => write!(f, "profile record count too large: {count}"),
        }
    }
}

impl std::error::Error for ProfileError {}

impl From<ProfileError> for AppError {
    fn from(error: ProfileError) -> Self {
        AppError::new(ReasonCode::RcJitCompilationError, error.to_string())
    }
}

impl From<std::io::Error> for ProfileError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// The four persisted target classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileTargetKind {
    HotBlock = 0,
    DirectCall = 1,
    IndirectCall = 2,
    FunctionEntry = 3,
}

impl ProfileTargetKind {
    const ALL: [Self; 4] = [
        Self::HotBlock,
        Self::DirectCall,
        Self::IndirectCall,
        Self::FunctionEntry,
    ];

    fn code(self) -> u8 {
        self as u8
    }

    fn from_code(code: u8) -> Result<Self, ProfileError> {
        match code {
            0 => Ok(Self::HotBlock),
            1 => Ok(Self::DirectCall),
            2 => Ok(Self::IndirectCall),
            3 => Ok(Self::FunctionEntry),
            other => Err(ProfileError::UnknownTargetKind(other)),
        }
    }
}

/// Address -> hit count for every target class.  Maps are ordered so the
/// on-disk encoding is deterministic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileTargets {
    pub hot_blocks: BTreeMap<u64, u64>,
    pub direct_calls: BTreeMap<u64, u64>,
    pub indirect_calls: BTreeMap<u64, u64>,
    pub function_entries: BTreeMap<u64, u64>,
}

impl ProfileTargets {
    pub fn is_empty(&self) -> bool {
        self.hot_blocks.is_empty()
            && self.direct_calls.is_empty()
            && self.indirect_calls.is_empty()
            && self.function_entries.is_empty()
    }

    pub fn get(&self, kind: ProfileTargetKind, address: u64) -> Option<u64> {
        self.map(kind).get(&address).copied()
    }

    pub fn contains(&self, address: u64) -> bool {
        ProfileTargetKind::ALL
            .iter()
            .any(|kind| self.map(*kind).contains_key(&address))
    }

    /// Union of every recorded address: the seeds for the next launch's
    /// precompile walk.
    pub fn seed_addresses(&self) -> Vec<u64> {
        let mut seeds = std::collections::BTreeSet::new();
        for kind in ProfileTargetKind::ALL {
            seeds.extend(self.map(kind).keys().copied());
        }
        seeds.into_iter().collect()
    }

    /// Number of distinct addresses across all target classes.
    pub fn address_count(&self) -> u64 {
        self.seed_addresses().len() as u64
    }

    /// Record one observation.  Repeated observations accumulate hits.
    pub fn record(&mut self, kind: ProfileTargetKind, address: u64, hits: u64) {
        let slot = self.map_mut(kind).entry(address).or_insert(0);
        *slot = slot.saturating_add(hits);
    }

    /// Merge another profile into this one, accumulating hits.
    pub fn merge(&mut self, other: &Self) {
        for kind in ProfileTargetKind::ALL {
            for (address, hits) in other.map(kind) {
                self.record(kind, *address, *hits);
            }
        }
    }

    /// Drop every recorded target whose address lies in `[start, end)`.
    /// Used by self-modifying-code invalidation so stale addresses can never
    /// seed a later precompile.
    pub fn clear_range(&mut self, start: u64, end: u64) {
        for kind in ProfileTargetKind::ALL {
            self.map_mut(kind)
                .retain(|address, _| *address < start || *address >= end);
        }
    }

    pub fn clear_address(&mut self, address: u64) {
        self.clear_range(address, address.saturating_add(1));
    }

    fn map(&self, kind: ProfileTargetKind) -> &BTreeMap<u64, u64> {
        match kind {
            ProfileTargetKind::HotBlock => &self.hot_blocks,
            ProfileTargetKind::DirectCall => &self.direct_calls,
            ProfileTargetKind::IndirectCall => &self.indirect_calls,
            ProfileTargetKind::FunctionEntry => &self.function_entries,
        }
    }

    fn map_mut(&mut self, kind: ProfileTargetKind) -> &mut BTreeMap<u64, u64> {
        match kind {
            ProfileTargetKind::HotBlock => &mut self.hot_blocks,
            ProfileTargetKind::DirectCall => &mut self.direct_calls,
            ProfileTargetKind::IndirectCall => &mut self.indirect_calls,
            ProfileTargetKind::FunctionEntry => &mut self.function_entries,
        }
    }

    fn record_count(&self) -> usize {
        ProfileTargetKind::ALL
            .iter()
            .map(|kind| self.map(*kind).len())
            .sum()
    }

    /// Deterministic, checksummed encoding bound to `key`.
    pub fn encode(&self, key: &ProfileKey) -> Result<Vec<u8>, ProfileError> {
        validate_image_hash(&key.image_hash)?;
        let count = u64::try_from(self.record_count())
            .map_err(|_| ProfileError::TooManyRecords(u64::MAX))?;
        let mut out = Vec::with_capacity(
            HEADER_FIXED + key.image_hash.len() + self.record_count() * RECORD_SIZE + CHECKSUM_SIZE,
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&AOT_PROFILE_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&key.translator.to_le_bytes());
        out.extend_from_slice(&key.cpu_profile.to_le_bytes());
        out.extend_from_slice(&(key.image_hash.len() as u16).to_le_bytes());
        out.extend_from_slice(key.image_hash.as_bytes());
        out.extend_from_slice(&(count as u32).to_le_bytes());
        for kind in ProfileTargetKind::ALL {
            for (address, hits) in self.map(kind) {
                out.push(kind.code());
                out.extend_from_slice(&address.to_le_bytes());
                out.extend_from_slice(&hits.to_le_bytes());
            }
        }
        let checksum = profile_fnv1a(&out);
        out.extend_from_slice(&checksum.to_le_bytes());
        Ok(out)
    }

    /// Validate a record against `expected` and decode it.
    pub fn decode(bytes: &[u8], expected: &ProfileKey) -> Result<Self, ProfileError> {
        if bytes.len() < HEADER_FIXED + CHECKSUM_SIZE {
            return Err(ProfileError::Truncated("header"));
        }
        if &bytes[..8] != MAGIC {
            return Err(ProfileError::BadMagic);
        }
        let payload_end = bytes.len() - CHECKSUM_SIZE;
        let stored = u64::from_le_bytes(
            bytes[payload_end..]
                .try_into()
                .map_err(|_| ProfileError::Truncated("checksum"))?,
        );
        let actual = profile_fnv1a(&bytes[..payload_end]);
        if actual != stored {
            return Err(ProfileError::ChecksumMismatch {
                found: actual,
                expected: stored,
            });
        }
        let mut cursor = 8;
        let format = read_u32(bytes, &mut cursor, payload_end)?;
        if format != AOT_PROFILE_FORMAT_VERSION {
            return Err(ProfileError::UnsupportedFormat {
                found: format,
                expected: AOT_PROFILE_FORMAT_VERSION,
            });
        }
        let translator = read_u32(bytes, &mut cursor, payload_end)?;
        let cpu_profile = read_u64(bytes, &mut cursor, payload_end)?;
        let hash_len = read_u16(bytes, &mut cursor, payload_end)? as usize;
        if hash_len == 0 || hash_len > MAX_IMAGE_HASH_LEN {
            return Err(ProfileError::Truncated("image hash"));
        }
        let hash_end = cursor
            .checked_add(hash_len)
            .ok_or(ProfileError::Truncated("image hash"))?;
        if hash_end > payload_end {
            return Err(ProfileError::Truncated("image hash"));
        }
        let image_hash = std::str::from_utf8(&bytes[cursor..hash_end])
            .map_err(|_| ProfileError::InvalidImageHash("non-UTF-8".to_string()))?
            .to_string();
        cursor = hash_end;
        let count = read_u32(bytes, &mut cursor, payload_end)? as usize;
        let records_end = cursor
            .checked_add(count.saturating_mul(RECORD_SIZE))
            .ok_or(ProfileError::TooManyRecords(count as u64))?;
        if records_end > payload_end {
            return Err(ProfileError::Truncated("records"));
        }
        let mut targets = ProfileTargets::default();
        for _ in 0..count {
            let kind = ProfileTargetKind::from_code(read_u8(bytes, &mut cursor, payload_end)?)?;
            let address = read_u64(bytes, &mut cursor, payload_end)?;
            let hits = read_u64(bytes, &mut cursor, payload_end)?;
            let slot = targets.map_mut(kind).entry(address).or_insert(0);
            *slot = slot.saturating_add(hits);
        }
        if cursor != payload_end {
            return Err(ProfileError::TrailingBytes);
        }
        if image_hash != expected.image_hash {
            return Err(ProfileError::ImageHashMismatch {
                found: image_hash,
                expected: expected.image_hash.clone(),
            });
        }
        if translator != expected.translator {
            return Err(ProfileError::TranslatorMismatch {
                found: translator,
                expected: expected.translator,
            });
        }
        if cpu_profile != expected.cpu_profile {
            return Err(ProfileError::CpuProfileMismatch {
                found: cpu_profile,
                expected: expected.cpu_profile,
            });
        }
        Ok(targets)
    }
}

fn read_u8(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<u8, ProfileError> {
    if *cursor >= end {
        return Err(ProfileError::Truncated("record"));
    }
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<u16, ProfileError> {
    let range = cursor
        .checked_add(2)
        .filter(|value| *value <= end)
        .ok_or(ProfileError::Truncated("u16"))?;
    let value = u16::from_le_bytes(
        bytes[*cursor..range]
            .try_into()
            .map_err(|_| ProfileError::Truncated("u16"))?,
    );
    *cursor = range;
    Ok(value)
}

fn read_u32(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<u32, ProfileError> {
    let range = cursor
        .checked_add(4)
        .filter(|value| *value <= end)
        .ok_or(ProfileError::Truncated("u32"))?;
    let value = u32::from_le_bytes(
        bytes[*cursor..range]
            .try_into()
            .map_err(|_| ProfileError::Truncated("u32"))?,
    );
    *cursor = range;
    Ok(value)
}

fn read_u64(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<u64, ProfileError> {
    let range = cursor
        .checked_add(8)
        .filter(|value| *value <= end)
        .ok_or(ProfileError::Truncated("u64"))?;
    let value = u64::from_le_bytes(
        bytes[*cursor..range]
            .try_into()
            .map_err(|_| ProfileError::Truncated("u64"))?,
    );
    *cursor = range;
    Ok(value)
}

pub(crate) fn profile_fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn validate_image_hash(image_hash: &str) -> Result<(), ProfileError> {
    if image_hash.is_empty()
        || image_hash.len() > MAX_IMAGE_HASH_LEN
        || image_hash
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(ProfileError::InvalidImageHash(image_hash.to_string()));
    }
    Ok(())
}

fn safe_component(image_hash: &str) -> String {
    image_hash
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

/// `cache_root/aot/<image-hash>-t<translator>-c<cpu-profile>/`.
pub fn profile_directory(cache_root: &Path, key: &ProfileKey) -> PathBuf {
    cache_root.join("aot").join(format!(
        "{}-t{}-c{:016x}",
        safe_component(&key.image_hash),
        key.translator,
        key.cpu_profile
    ))
}

/// Full path of the profile record for `key`.
pub fn profile_file_path(cache_root: &Path, key: &ProfileKey) -> PathBuf {
    profile_directory(cache_root, key).join(AOT_PROFILE_FILE_NAME)
}

/// Read a profile for `expected`.  A missing file is `Ok(None)`; every other
/// failure is returned verbatim so callers can report the exact reason.
pub fn load_profile_file(
    path: &Path,
    expected: &ProfileKey,
) -> Result<Option<ProfileTargets>, ProfileError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ProfileError::Io(error.to_string())),
    };
    ProfileTargets::decode(&bytes, expected).map(Some)
}

/// Persist `targets` atomically.  The temporary file is created beside the
/// destination so the final `rename` stays on one filesystem.
pub fn store_profile_file(
    path: &Path,
    key: &ProfileKey,
    targets: &ProfileTargets,
) -> Result<(), ProfileError> {
    let bytes = targets.encode(key)?;
    write_atomic(path, &bytes)
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ProfileError> {
    write_atomic_impl(path, bytes, None)
}

fn write_atomic_impl(
    path: &Path,
    bytes: &[u8],
    fail_after: Option<usize>,
) -> Result<(), ProfileError> {
    use std::io::Write;
    let directory = path
        .parent()
        .ok_or_else(|| ProfileError::Io("profile path has no parent".to_string()))?;
    std::fs::create_dir_all(directory)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(AOT_PROFILE_FILE_NAME);
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".{file_name}.tmp-{}-{sequence}",
        std::process::id()
    ));
    let result = (|| -> Result<(), ProfileError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        match fail_after {
            Some(limit) => {
                let written = limit.min(bytes.len());
                file.write_all(&bytes[..written])?;
                file.sync_all()?;
                return Err(ProfileError::Io("injected partial write".to_string()));
            }
            None => file.write_all(bytes)?,
        }
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Machine-readable AOT pipeline counters reported with a run and by the
/// install-time precompile mode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AotRunSummary {
    /// Distinct profile target addresses loaded and merged into this run.
    pub persisted_targets_loaded: u64,
    /// Blocks discovered and handed to the compiler before guest entry.
    pub blocks_precompiled: u64,
    /// Blocks translated before entry and served from the persistent cache.
    pub aot_hits: u64,
    /// Blocks translated before entry that had no usable cached record.
    pub aot_misses: u64,
    /// Cache/profile records rejected for integrity or key mismatches.
    pub aot_rejected: u64,
    /// Profile targets written after the run (or discovered by precompile-only).
    pub profile_targets_persisted: u64,
    /// Exact rejection reason when the stored profile was discarded.
    pub profile_error: Option<String>,
}

/// Machine-readable result of an install-time `--precompile-only` run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AotPrecompileReport {
    pub image_hash: String,
    pub cache_dir: String,
    pub profile_path: String,
    /// Profile targets loaded from a previous run and used as seeds.
    pub persisted_targets_loaded: u64,
    /// Persisted seed addresses that were precompiled.
    pub seeded_compiled: u64,
    /// Total blocks discovered and handed to the compiler.
    pub blocks_precompiled: u64,
    /// Blocks served from the persistent cache during this pass.
    pub aot_hits: u64,
    /// Blocks compiled because no usable cached record existed.
    pub aot_misses: u64,
    /// Cache/profile records rejected for integrity or key mismatches.
    pub aot_rejected: u64,
}

/// Test-only injection point for the partial-write/atomic-rename test.
#[cfg(test)]
pub(crate) fn write_atomic_failing_for_test(
    path: &Path,
    bytes: &[u8],
    fail_after: usize,
) -> Result<(), ProfileError> {
    write_atomic_impl(path, bytes, Some(fail_after))
}
