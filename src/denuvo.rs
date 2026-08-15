// ---------------------------------------------------------------------------
// Enhanced Denuvo Anti-Tamper Emulation (Gap 10.2)
// ---------------------------------------------------------------------------
//
// Denuvo Anti-Tamper is a DRM system that encrypts code sections of a game's
// executable and decrypts them at runtime using hardware-bound license tokens.
// This module provides enhanced emulation that handles:
//
//   1. Denuvo trigger detection and handling (code triggers that verify license)
//   2. License validation bypass with trigger state tracking
//   3. Anti-debugging countermeasures (IsDebuggerPresent, NtQueryInformationProcess)
//   4. Anti-tamper verification (integrity-checked code section hashes)
//   5. Code section decryption with multiple encryption schemes
//
// This module builds on the base DenuvoEmulator in src/security.rs but adds
// the enhanced features needed for Gap 10.2.
// ---------------------------------------------------------------------------

use crate::cpu::MemoryImage;
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::security::{AntiDebugState, CodeSection, DenuvoConfig, DenuvoEmulator, DenuvoVersion};
use aes::cipher::{BlockDecryptMut, KeyIvInit};
#[cfg(test)]
use aes::cipher::BlockEncryptMut;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Denuvo trigger system
// ---------------------------------------------------------------------------

/// The type of a Denuvo trigger point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerType {
    /// License verification trigger — checks that a valid license token exists.
    LicenseCheck,
    /// Code decryption trigger — decrypts a code section on first access.
    CodeDecrypt,
    /// Integrity verification trigger — checks code section hashes.
    IntegrityCheck,
    /// Anti-debug trigger — performs timing-based debugger detection.
    AntiDebug,
    /// Hardware binding trigger — verifies hardware ID matches license.
    HardwareBind,
    /// Unknown trigger type.
    Unknown(u32),
}

/// State of a single Denuvo trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerState {
    /// RVA of the trigger point in the PE image.
    pub rva: u64,
    /// Type of the trigger.
    pub trigger_type: TriggerType,
    /// Whether this trigger has been fired (activated).
    pub fired: bool,
    /// Number of times this trigger has been hit.
    pub hit_count: u64,
    /// Associated code section index (if applicable).
    pub section_index: Option<usize>,
    /// Timestamp of last activation.
    pub last_fired_time: u64,
}

// ---------------------------------------------------------------------------
// Anti-tamper hash cache
// ---------------------------------------------------------------------------

/// Cached hash for an integrity-checked code region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperHashEntry {
    /// RVA of the code region.
    pub rva: u64,
    /// Size of the region.
    pub size: u32,
    /// Expected hash (original, untampered).
    pub expected_hash: [u8; 32],
    /// Whether this region has been verified at least once.
    pub verified: bool,
    /// Number of times verified.
    pub verify_count: u64,
}

// ---------------------------------------------------------------------------
// Anti-debugging timing
// ---------------------------------------------------------------------------

/// Expected timing values for anti-debug checks.
///
/// When a debugger is attached, timing-based checks can detect the overhead
/// of single-stepping.  We return consistent, realistic timing values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDebugTiming {
    /// Expected rdtsc delta between two checkpoints (no debugger).
    pub rdtsc_delta: u64,
    /// Expected QueryPerformanceCounter delta.
    pub qpc_delta: u64,
    /// Expected GetTickCount delta.
    pub tick_delta: u32,
    /// Number of timing checks performed.
    pub check_count: u64,
}

impl AntiDebugTiming {
    /// Creates default timing values that indicate no debugger is present.
    pub fn new() -> Self {
        Self {
            rdtsc_delta: 1500, // ~1500 cycles for a short code sequence
            qpc_delta: 500,    // ~500 ns
            tick_delta: 0,     // GetTickCount has ~15ms resolution
            check_count: 0,
        }
    }
}

impl Default for AntiDebugTiming {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Enhanced Denuvo Emulator
// ---------------------------------------------------------------------------

/// Enhanced Denuvo anti-tamper emulator with full trigger system support.
///
/// This wraps the base [`DenuvoEmulator`] and adds:
/// - Trigger detection and state tracking
/// - License validation bypass with trigger handling
/// - Anti-debugging countermeasures
/// - Anti-tamper hash verification
/// - Multiple encryption scheme support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedDenuvoEmulator {
    /// The base Denuvo emulator.
    pub base: DenuvoEmulator,
    /// Trigger states keyed by RVA.
    pub triggers: BTreeMap<u64, TriggerState>,
    /// Anti-tamper hash cache.
    pub tamper_hashes: BTreeMap<u64, TamperHashEntry>,
    /// Anti-debug timing values.
    pub anti_debug_timing: AntiDebugTiming,
    /// Anti-debug state.
    pub anti_debug: AntiDebugState,
    /// Whether the enhanced emulator has been initialized.
    pub initialized: bool,
    /// Number of triggers that have been successfully handled.
    pub triggers_handled: u64,
    /// Number of triggers that failed (should be 0 in normal operation).
    pub triggers_failed: u64,
    /// Session ID for this emulator instance (deterministic).
    pub session_id: u64,
    /// Base address where the PE image is loaded in guest memory. Trigger
    /// keys, tamper-hash keys, and the public API are all RVA-based; the
    /// base is added only at the memory-access boundary.
    #[serde(default)]
    pub image_base: u64,
}

// ---------------------------------------------------------------------------
// Section containment lookup
// ---------------------------------------------------------------------------

/// Precomputed index for finding the code section containing an RVA in
/// O(log S) instead of scanning all sections per query.
struct SectionIndexLookup<'a> {
    /// (section rva, section index) pairs sorted by rva.
    by_rva: Vec<(u64, usize)>,
    sections: &'a [CodeSection],
}

impl<'a> SectionIndexLookup<'a> {
    fn new(sections: &'a [CodeSection]) -> Self {
        let mut by_rva: Vec<(u64, usize)> = sections
            .iter()
            .enumerate()
            .map(|(idx, s)| (s.rva, idx))
            .collect();
        by_rva.sort_unstable_by_key(|&(rva, _)| rva);
        Self { by_rva, sections }
    }

    /// Returns the index of the section containing `rva`, if any.
    fn find(&self, rva: u64) -> Option<usize> {
        let pos = self.by_rva.partition_point(|&(start, _)| start <= rva);
        if pos == 0 {
            return None;
        }
        let (start, idx) = self.by_rva[pos - 1];
        let section = &self.sections[idx];
        if rva < start.saturating_add(section.size as u64) {
            Some(idx)
        } else {
            None
        }
    }
}

impl EnhancedDenuvoEmulator {
    /// Creates a new enhanced Denuvo emulator with the given configuration.
    pub fn new(config: DenuvoConfig) -> Self {
        let session_id = generate_session_id();
        Self {
            base: DenuvoEmulator::new(config),
            triggers: BTreeMap::new(),
            tamper_hashes: BTreeMap::new(),
            anti_debug_timing: AntiDebugTiming::new(),
            anti_debug: AntiDebugState::new(),
            initialized: false,
            triggers_handled: 0,
            triggers_failed: 0,
            session_id,
            image_base: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /// Initializes the enhanced emulator.
    ///
    /// This calls the base emulator's initialize method and then scans the
    /// PE image for Denuvo trigger patterns, setting up trigger states and
    /// tamper hash entries.
    pub fn initialize(&mut self, memory: &mut MemoryImage, base: u64) -> AppResult<()> {
        // Initialize the base emulator
        self.base.initialize(memory, base)?;
        self.image_base = base;

        // Set up triggers from the config's trigger points
        for &rva in &self.base.config.trigger_points {
            self.triggers.insert(
                rva,
                TriggerState {
                    rva,
                    trigger_type: TriggerType::CodeDecrypt,
                    fired: false,
                    hit_count: 0,
                    section_index: None,
                    last_fired_time: 0,
                },
            );
        }

        // Set up tamper hash entries from code sections
        for section in &self.base.config.code_sections {
            self.tamper_hashes.insert(
                section.rva,
                TamperHashEntry {
                    rva: section.rva,
                    size: section.size,
                    expected_hash: section.original_hash,
                    verified: false,
                    verify_count: 0,
                },
            );
        }

        // Associate triggers with the code section that contains them,
        // via a sorted interval lookup instead of an O(triggers × sections)
        // scan.
        let section_lookup = SectionIndexLookup::new(&self.base.config.code_sections);
        for trigger in self.triggers.values_mut() {
            if trigger.section_index.is_none() {
                trigger.section_index = section_lookup.find(trigger.rva);
            }
        }

        // Auto-detect additional triggers from the PE image
        self.detect_triggers(memory, base)?;

        self.initialized = true;
        Ok(())
    }

    /// Scans the PE image for Denuvo trigger patterns.
    ///
    /// Denuvo inserts trigger points at specific code patterns.  We look for
    /// common patterns like:
    /// - Call instructions to known Denuvo thunks
    /// - Indirect jumps through Denuvo's dispatch table
    /// - Specific byte sequences used as trigger markers
    ///
    /// Detected triggers are keyed by RVA (the same key space as
    /// [`TriggerState::rva`] and the public trigger API); the image base is
    /// added only when addressing guest memory.
    fn detect_triggers(&mut self, memory: &MemoryImage, base: u64) -> AppResult<()> {
        // Precompute absolute section ranges for O(log S) containment checks
        // instead of re-scanning every section per CALL instruction.
        let mut section_ranges: Vec<(u64, u64, usize)> =
            Vec::with_capacity(self.base.config.code_sections.len());
        for (idx, section) in self.base.config.code_sections.iter().enumerate() {
            let Some(start) = base.checked_add(section.rva) else {
                continue;
            };
            section_ranges.push((start, start.saturating_add(section.size as u64), idx));
        }
        section_ranges.sort_unstable_by_key(|&(start, _, _)| start);

        // Scan each code section for trigger patterns
        for (idx, section) in self.base.config.code_sections.iter().enumerate() {
            let Some(abs_addr) = base.checked_add(section.rva) else {
                continue;
            };
            let Ok(data) = memory.read_bytes(abs_addr, section.size as usize) else {
                continue;
            };

            // Scan for CALL rel32 instructions (E8 xx xx xx xx) that target
            // addresses outside the current section — these are potential triggers
            let mut offset = 0;
            while offset + 5 <= data.len() {
                if data[offset] == 0xE8 {
                    // CALL rel32
                    let rel32 = i32::from_le_bytes([
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                        data[offset + 4],
                    ]);
                    let target = abs_addr
                        .wrapping_add(offset as u64 + 5)
                        .wrapping_add(rel32 as u64);

                    // Check if target is outside all known code sections
                    let pos = section_ranges.partition_point(|&(start, _, _)| start <= target);
                    let in_section = pos > 0 && target < section_ranges[pos - 1].1;

                    if !in_section {
                        let trigger_rva = section.rva.saturating_add(offset as u64);
                        self.triggers.entry(trigger_rva).or_insert(TriggerState {
                            rva: trigger_rva,
                            trigger_type: TriggerType::CodeDecrypt,
                            fired: false,
                            hit_count: 0,
                            section_index: Some(idx),
                            last_fired_time: 0,
                        });
                    }
                }
                offset += 1;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Trigger handling
    // -----------------------------------------------------------------------

    /// Handles a Denuvo trigger at the given RVA.
    ///
    /// When the guest code hits a Denuvo trigger point, this method:
    /// 1. Identifies the trigger type
    /// 2. Performs the required action (decrypt, verify, etc.)
    /// 3. Updates the trigger state
    /// 4. Returns whether the trigger was successfully handled
    ///
    /// `rva` is a relative virtual address (the same key space used by
    /// [`add_trigger`](Self::add_trigger) and [`trigger_rvas`](Self::trigger_rvas));
    /// the image base is added at the guest-memory boundary.
    pub fn handle_trigger(&mut self, memory: &mut MemoryImage, rva: u64) -> AppResult<bool> {
        let trigger = match self.triggers.get_mut(&rva) {
            Some(t) => t,
            None => return Ok(false),
        };

        trigger.hit_count += 1;
        trigger.last_fired_time = current_timestamp();

        let trigger_type = trigger.trigger_type.clone();
        let section_index = trigger.section_index;

        let result = match trigger_type {
            TriggerType::LicenseCheck => self.handle_license_trigger(),
            TriggerType::CodeDecrypt => self.handle_decrypt_trigger(memory, section_index),
            TriggerType::IntegrityCheck => self.handle_integrity_trigger(memory, section_index),
            TriggerType::AntiDebug => {
                self.handle_anti_debug_trigger();
                Ok(())
            }
            TriggerType::HardwareBind => self.handle_hardware_bind_trigger(),
            TriggerType::Unknown(_) => self.handle_decrypt_trigger(memory, section_index),
        };
        if let Err(error) = result {
            self.triggers_failed += 1;
            return Err(error);
        }

        // Mark trigger as fired
        if let Some(t) = self.triggers.get_mut(&rva) {
            t.fired = true;
        }
        self.triggers_handled += 1;
        Ok(true)
    }

    /// Handles a license verification trigger.
    fn handle_license_trigger(&mut self) -> AppResult<()> {
        if self.base.state.license_token.is_none() {
            let _token = self.base.generate_license_token();
        }
        if !self.base.license_verified {
            let token = self.base.state.license_token.clone().unwrap_or_default();
            self.base.verify_license_token(&token);
        }
        Ok(())
    }

    /// Handles a code decryption trigger.
    fn handle_decrypt_trigger(
        &mut self,
        memory: &mut MemoryImage,
        section_index: Option<usize>,
    ) -> AppResult<()> {
        match section_index {
            Some(idx) => {
                if idx >= self.base.config.code_sections.len() {
                    return Err(AppError::new(
                        ReasonCode::RcDrmSectionNotFound,
                        format!("decrypt trigger section index {idx} out of bounds"),
                    ));
                }
                if self.base.config.code_sections[idx].encrypted {
                    self.base.decrypt_code_section(memory, idx)?;
                }
            }
            None => {
                // Decrypt all encrypted sections
                let count = self.base.config.code_sections.len();
                for idx in 0..count {
                    if self.base.config.code_sections[idx].encrypted {
                        self.base.decrypt_code_section(memory, idx)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Handles an integrity verification trigger.
    fn handle_integrity_trigger(
        &mut self,
        memory: &mut MemoryImage,
        section_index: Option<usize>,
    ) -> AppResult<()> {
        match section_index {
            Some(idx) => {
                // `section_index` is user-controlled via `add_trigger`, so it
                // must be bounds-checked before dispatch.
                if idx >= self.base.config.code_sections.len() {
                    return Err(AppError::new(
                        ReasonCode::RcDrmSectionNotFound,
                        format!("integrity trigger section index {idx} out of bounds"),
                    ));
                }
                self.base.verify_integrity(memory, idx)?;
            }
            None => {
                let count = self.base.config.code_sections.len();
                for idx in 0..count {
                    self.base.verify_integrity(memory, idx)?;
                }
            }
        }
        Ok(())
    }

    /// Handles an anti-debug trigger.
    fn handle_anti_debug_trigger(&mut self) {
        self.anti_debug_timing.check_count += 1;
        // Anti-debug state already returns "no debugger" for all checks
    }

    /// Handles a hardware binding trigger.
    fn handle_hardware_bind_trigger(&mut self) -> AppResult<()> {
        // Ensure hardware ID is set
        if self.base.state.hardware_id == [0u8; 16] {
            self.base.state.hardware_id = DenuvoEmulator::generate_hardware_id();
        }
        // Generate license token if not present
        if self.base.state.license_token.is_none() {
            let _token = self.base.generate_license_token();
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Anti-debugging API
    // -----------------------------------------------------------------------

    /// Returns `false` to indicate no debugger is present.
    pub fn is_debugger_present(&self) -> bool {
        self.anti_debug.is_debugger_present()
    }

    /// Returns `false` to indicate no remote debugger is present.
    pub fn check_remote_debugger_present(&self) -> bool {
        self.anti_debug.check_remote_debugger_present()
    }

    /// Handles `NtQueryInformationProcess` anti-debug checks.
    ///
    /// Returns a u64 value indicating no debugger is present for the given
    /// information class.  Also handles `ProcessProtectionInformation` (class 0x3D).
    pub fn nt_query_information_process(&self, info_class: u32) -> u64 {
        match info_class {
            // ProcessDebugPort (7)
            7 => 0,
            // ProcessDebugObjectHandle (30)
            30 => 0,
            // ProcessDebugFlags (31)
            31 => 1, // 1 = no debugger
            // ProcessProtectionInformation (0x3D = 61)
            61 => {
                // Return PS_PROTECTION with no protection
                // Level = 0, Type = 0, Signer = 0
                0u64
            }
            _ => 0,
        }
    }

    /// Returns expected timing values for timing-based anti-debug checks.
    pub fn get_timing_values(&self) -> &AntiDebugTiming {
        &self.anti_debug_timing
    }

    /// Returns a fake RDTSC value that indicates no debugger overhead.
    pub fn get_rdtsc_value(&self) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static RDTSC_COUNTER: AtomicU64 = AtomicU64::new(1_000_000);
        RDTSC_COUNTER.fetch_add(self.anti_debug_timing.rdtsc_delta, Ordering::Relaxed)
    }

    // -----------------------------------------------------------------------
    // Anti-tamper verification
    // -----------------------------------------------------------------------

    /// Verifies the integrity of a code section and returns the expected hash.
    ///
    /// If the code has been modified, this still returns the *expected* hash
    /// (the original hash from initialization), so the anti-tamper check
    /// appears to pass.
    pub fn verify_tamper_hash(&mut self, memory: &MemoryImage, rva: u64) -> AppResult<[u8; 32]> {
        let entry = self.tamper_hashes.get(&rva).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDrmSectionNotFound,
                format!("no tamper hash entry for RVA {rva:#x}"),
            )
        })?;

        let expected_hash = entry.expected_hash;
        let _size = entry.size;

        // Drop the immutable borrow before mutating
        let rva_owned = rva;
        if let Some(entry) = self.tamper_hashes.get_mut(&rva_owned) {
            entry.verified = true;
            entry.verify_count += 1;
        }

        // Also run the base emulator's integrity check
        if let Some(section_idx) = self.find_section_index(rva_owned)
            && let Err(error) = self.base.verify_integrity(memory, section_idx)
        {
            eprintln!(
                "[Denuvo] verify_tamper_hash: base integrity check failed for section {}: {}",
                section_idx, error
            );
        }

        Ok(expected_hash)
    }

    /// Verifies all tamper hash entries and returns expected hashes.
    pub fn verify_all_tamper_hashes(
        &mut self,
        memory: &MemoryImage,
    ) -> AppResult<Vec<(u64, [u8; 32])>> {
        let rvas: Vec<u64> = self.tamper_hashes.keys().copied().collect();
        let mut results = Vec::with_capacity(rvas.len());
        for rva in rvas {
            let hash = self.verify_tamper_hash(memory, rva)?;
            results.push((rva, hash));
        }
        Ok(results)
    }

    /// Returns the expected hash for a code section at the given RVA.
    ///
    /// This is used when the anti-tamper system queries for the expected
    /// hash value — we always return the original (untampered) hash.
    pub fn get_expected_hash(&self, rva: u64) -> Option<[u8; 32]> {
        self.tamper_hashes
            .get(&rva)
            .map(|e| e.expected_hash)
            .or_else(|| {
                // Fall back to code sections
                self.base
                    .config
                    .code_sections
                    .iter()
                    .find(|s| s.rva == rva)
                    .map(|s| s.original_hash)
            })
    }

    /// Updates the expected hash for a code region (e.g. after re-encryption).
    pub fn update_tamper_hash(&mut self, rva: u64, new_hash: [u8; 32]) -> AppResult<()> {
        let entry = self.tamper_hashes.get_mut(&rva).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDrmSectionNotFound,
                format!("no tamper hash entry for RVA {rva:#x}"),
            )
        })?;
        entry.expected_hash = new_hash;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Code section decryption
    // -----------------------------------------------------------------------

    /// Decrypts a code section using the appropriate scheme based on Denuvo version.
    ///
    /// - V4/V5: Simple XOR with derived key
    /// - V6: XOR + AES-128 key wrapping
    /// - V7: XOR + AES-256 + hardware-bound key
    pub fn decrypt_section_enhanced(
        &mut self,
        memory: &mut MemoryImage,
        section_index: usize,
    ) -> AppResult<()> {
        let section = self
            .base
            .config
            .code_sections
            .get(section_index)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcDrmSectionNotFound,
                    format!("denuvo code section index {section_index} out of bounds"),
                )
            })?;

        if !section.encrypted {
            return Ok(());
        }

        match self.base.config.version {
            DenuvoVersion::V4 | DenuvoVersion::V5 => {
                // Base emulator handles XOR decryption
                self.base.decrypt_code_section(memory, section_index)?;
            }
            DenuvoVersion::V6 => {
                // V6: XOR + AES-128 key wrapping
                self.decrypt_v6_section(memory, section_index)?;
            }
            DenuvoVersion::V7 => {
                // V7: XOR + AES-256 + hardware-bound key
                self.decrypt_v7_section(memory, section_index)?;
            }
        }
        Ok(())
    }

    /// Decrypts a V6 code section using AES-128-CBC with key material derived from
    /// hardware ID, section hash, and session ID.
    fn decrypt_v6_section(
        &mut self,
        memory: &mut MemoryImage,
        section_index: usize,
    ) -> AppResult<()> {
        let section = self
            .base
            .config
            .code_sections
            .get(section_index)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcDrmSectionNotFound,
                    format!("denuvo code section index {section_index} out of bounds"),
                )
            })?;

        // Derive combined key material from hardware ID + section hash + session ID
        let mut key_material = Vec::with_capacity(48);
        key_material.extend_from_slice(&self.base.state.hardware_id);
        key_material.extend_from_slice(&section.original_hash);
        key_material.extend_from_slice(&self.session_id.to_le_bytes());
        // Include the "AES unwrap" context to match the original two-pass derivation
        key_material.extend_from_slice(b"v6-aes-unwrap");
        let derived = sha256_hash(&key_material);

        // First 16 bytes of SHA-256 → AES-128 key, last 16 bytes → IV
        let aes_key: [u8; 16] = {
            let mut k = [0u8; 16];
            k.copy_from_slice(&derived[..16]);
            k
        };
        let iv: [u8; 16] = {
            let mut i = [0u8; 16];
            i.copy_from_slice(&derived[16..]);
            i
        };

        let abs_addr = self.image_base.checked_add(section.rva).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "denuvo section address overflows",
            )
        })?;
        let mut data = section.decrypted.clone();

        // AES-128-CBC decrypt with PKCS7 padding
        type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
        let decryptor = Aes128CbcDec::new(&aes_key.into(), &iv.into());
        let pt = decryptor
            .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut data)
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcDrmDecryptFailed,
                    "AES-128-CBC decryption failed for Denuvo V6 section",
                )
                .with_hint(e.to_string())
            })?;
        let decrypted_len = pt.len();

        memory.map_bytes(abs_addr, &pt[..decrypted_len]);
        self.base.config.code_sections[section_index].encrypted = false;
        if self.base.config.code_sections.iter().all(|s| !s.encrypted) {
            self.base.state.code_sections_decrypted = true;
        }
        Ok(())
    }

    /// Decrypts a V7 code section using AES-256-CBC with key material derived from
    /// hardware ID, section hash, session ID, and per-section nonce.
    fn decrypt_v7_section(
        &mut self,
        memory: &mut MemoryImage,
        section_index: usize,
    ) -> AppResult<()> {
        let section = self
            .base
            .config
            .code_sections
            .get(section_index)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcDrmSectionNotFound,
                    format!("denuvo code section index {section_index} out of bounds"),
                )
            })?;

        // Derive key from hardware ID + section hash + session ID + per-section nonce
        let mut key_material = Vec::with_capacity(64);
        key_material.extend_from_slice(&self.base.state.hardware_id);
        key_material.extend_from_slice(&section.original_hash);
        key_material.extend_from_slice(&self.session_id.to_le_bytes());
        key_material.extend_from_slice(&(section_index as u64).to_le_bytes());
        let derived_key = sha256_hash(&key_material);

        // Derive IV from the same material with a context tag
        let mut iv_material = Vec::with_capacity(64);
        iv_material.extend_from_slice(&derived_key);
        iv_material.extend_from_slice(b"v7-aes256-iv");
        let iv_hash = sha256_hash(&iv_material);
        let iv: [u8; 16] = {
            let mut i = [0u8; 16];
            i.copy_from_slice(&iv_hash[..16]);
            i
        };

        // Use full 32-byte SHA-256 as AES-256 key
        let aes_key: [u8; 32] = {
            let mut k = [0u8; 32];
            k.copy_from_slice(&derived_key);
            k
        };

        let abs_addr = self.image_base.checked_add(section.rva).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDrmDecryptFailed,
                "denuvo section address overflows",
            )
        })?;
        let mut data = section.decrypted.clone();

        // AES-256-CBC decrypt with PKCS7 padding
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        let decryptor = Aes256CbcDec::new(&aes_key.into(), &iv.into());
        let pt = decryptor
            .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut data)
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcDrmDecryptFailed,
                    "AES-256-CBC decryption failed for Denuvo V7 section",
                )
                .with_hint(e.to_string())
            })?;
        let decrypted_len = pt.len();

        memory.map_bytes(abs_addr, &pt[..decrypted_len]);
        self.base.config.code_sections[section_index].encrypted = false;
        if self.base.config.code_sections.iter().all(|s| !s.encrypted) {
            self.base.state.code_sections_decrypted = true;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Utility methods
    // -----------------------------------------------------------------------

    /// Finds the section index containing the given RVA.
    fn find_section_index(&self, rva: u64) -> Option<usize> {
        SectionIndexLookup::new(&self.base.config.code_sections).find(rva)
    }

    /// Returns the number of unfired triggers.
    pub fn unfired_trigger_count(&self) -> usize {
        self.triggers.values().filter(|t| !t.fired).count()
    }

    /// Returns all trigger RVAs.
    pub fn trigger_rvas(&self) -> Vec<u64> {
        self.triggers.keys().copied().collect()
    }

    /// Returns the trigger state for a given RVA.
    pub fn get_trigger_state(&self, rva: u64) -> Option<&TriggerState> {
        self.triggers.get(&rva)
    }

    /// Adds a manual trigger at the given RVA.
    pub fn add_trigger(
        &mut self,
        rva: u64,
        trigger_type: TriggerType,
        section_index: Option<usize>,
    ) {
        self.triggers.insert(
            rva,
            TriggerState {
                rva,
                trigger_type,
                fired: false,
                hit_count: 0,
                section_index,
                last_fired_time: 0,
            },
        );
    }

    /// Resets all trigger states (e.g. for a new game session).
    pub fn reset_triggers(&mut self) {
        for trigger in self.triggers.values_mut() {
            trigger.fired = false;
            trigger.hit_count = 0;
            trigger.last_fired_time = 0;
        }
        self.triggers_handled = 0;
        self.triggers_failed = 0;
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Computes a SHA-256 hash.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Generates a deterministic session ID.
fn generate_session_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);
    let id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mix with a hash of the current time for uniqueness
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    id.wrapping_add(time)
}

/// Returns the current timestamp in milliseconds.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::CodeSection;

    fn make_config() -> DenuvoConfig {
        DenuvoConfig {
            version: DenuvoVersion::V6,
            enabled: true,
            integrity_check_interval_ms: 5000,
            code_sections: Vec::new(),
            trigger_points: vec![0x5000, 0x6000],
        }
    }

    fn make_config_with_sections() -> DenuvoConfig {
        let code1 = vec![0x90u8; 64];
        let code2 = vec![0xB8u8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        let hash1 = sha256_hash(&code1);
        let hash2 = sha256_hash(&code2);
        DenuvoConfig {
            version: DenuvoVersion::V6,
            enabled: true,
            integrity_check_interval_ms: 5000,
            code_sections: vec![
                CodeSection {
                    rva: 0x1000,
                    size: 64,
                    original_hash: hash1,
                    decrypted: code1,
                    encrypted: true,
                },
                CodeSection {
                    rva: 0x2000,
                    size: 6,
                    original_hash: hash2,
                    decrypted: code2,
                    encrypted: true,
                },
            ],
            trigger_points: vec![0x5000, 0x6000],
        }
    }

    #[test]
    fn enhanced_denuvo_initialization() {
        let config = make_config();
        let emulator = EnhancedDenuvoEmulator::new(config);
        assert!(!emulator.initialized);
        assert!(emulator.triggers.is_empty());
        assert!(emulator.tamper_hashes.is_empty());
        assert!(!emulator.anti_debug.is_debugger_present());
        assert!(!emulator.anti_debug.check_remote_debugger_present());
        assert_eq!(emulator.triggers_handled, 0);
        assert_eq!(emulator.triggers_failed, 0);
    }

    #[test]
    fn enhanced_denuvo_initialize_with_sections() {
        let config = make_config_with_sections();
        let mut emulator = EnhancedDenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();

        // Map code sections
        memory.map_bytes(0x1000, &[0x90u8; 64]);
        memory.map_bytes(0x2000, &[0xB8u8, 0x01, 0x00, 0x00, 0x00, 0xC3]);

        emulator.initialize(&mut memory, 0).unwrap();
        assert!(emulator.initialized);

        // Triggers should be set up from trigger_points
        assert!(emulator.triggers.contains_key(&0x5000));
        assert!(emulator.triggers.contains_key(&0x6000));

        // Tamper hashes should be set up from code sections
        assert!(emulator.tamper_hashes.contains_key(&0x1000));
        assert!(emulator.tamper_hashes.contains_key(&0x2000));
    }

    #[test]
    fn enhanced_denuvo_trigger_handling() {
        let config = make_config_with_sections();
        let mut emulator = EnhancedDenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();

        let code1 = vec![0x90u8; 64];
        let code2 = vec![0xB8u8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        memory.map_bytes(0x1000, &code1);
        memory.map_bytes(0x2000, &code2);

        emulator.initialize(&mut memory, 0).unwrap();

        // After initialize(), section data is plaintext read from memory.
        // Encrypt it with the same key derivation decrypt_code_section will use.
        for idx in 0..emulator.base.config.code_sections.len() {
            let section = &emulator.base.config.code_sections[idx];
            if !section.encrypted {
                continue;
            }
            let plaintext = section.decrypted.clone();

            // Derive key: SHA-256(hardware_id + original_hash)
            let mut key_material = Vec::with_capacity(48);
            key_material.extend_from_slice(&emulator.base.state.hardware_id);
            key_material.extend_from_slice(&section.original_hash);
            let derived = {
                let mut hasher = Sha256::new();
                hasher.update(&key_material);
                hasher.finalize()
            };
            let aes_key: [u8; 16] = {
                let mut k = [0u8; 16];
                k.copy_from_slice(&derived[..16]);
                k
            };
            let iv: [u8; 16] = {
                let mut i = [0u8; 16];
                i.copy_from_slice(&derived[16..]);
                i
            };

            // PKCS7-pad and AES-128-CBC encrypt
            let block_size = 16usize;
            let pad_len = block_size - (plaintext.len() % block_size);
            let mut padded = plaintext.clone();
            padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
            type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
            let enc = Aes128CbcEnc::new(&aes_key.into(), &iv.into());
            let ct = enc
                .encrypt_padded_mut::<cipher::block_padding::Pkcs7>(
                    &mut padded,
                    plaintext.len(),
                )
                .unwrap();
            emulator.base.config.code_sections[idx].decrypted = ct.to_vec();
        }

        // Handle a decrypt trigger
        let handled = emulator.handle_trigger(&mut memory, 0x5000).unwrap();
        assert!(handled);
        assert_eq!(emulator.triggers_handled, 1);

        let state = emulator.get_trigger_state(0x5000).unwrap();
        assert!(state.fired);
        assert_eq!(state.hit_count, 1);
    }

    #[test]
    fn enhanced_denuvo_unknown_trigger() {
        let config = make_config();
        let mut emulator = EnhancedDenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        emulator.initialize(&mut memory, 0).unwrap();

        // Unknown RVA should not be handled
        let handled = emulator.handle_trigger(&mut memory, 0x9999).unwrap();
        assert!(!handled);
        assert_eq!(emulator.triggers_handled, 0);
    }

    #[test]
    fn enhanced_denuvo_anti_debug() {
        let config = make_config();
        let emulator = EnhancedDenuvoEmulator::new(config);

        assert!(!emulator.is_debugger_present());
        assert!(!emulator.check_remote_debugger_present());

        // NtQueryInformationProcess checks
        assert_eq!(emulator.nt_query_information_process(7), 0); // DebugPort
        assert_eq!(emulator.nt_query_information_process(30), 0); // DebugObjectHandle
        assert_eq!(emulator.nt_query_information_process(31), 1); // DebugFlags
        assert_eq!(emulator.nt_query_information_process(61), 0); // ProtectionInformation
        assert_eq!(emulator.nt_query_information_process(99), 0); // Unknown
    }

    #[test]
    fn enhanced_denuvo_rdtsc() {
        let config = make_config();
        let emulator = EnhancedDenuvoEmulator::new(config);

        let tsc1 = emulator.get_rdtsc_value();
        let tsc2 = emulator.get_rdtsc_value();
        assert!(tsc2 > tsc1);
        // Delta should be approximately rdtsc_delta
        let delta = tsc2 - tsc1;
        assert!((1000..=10000).contains(&delta), "delta was {delta}");
    }

    #[test]
    fn enhanced_denuvo_tamper_hash() {
        let config = make_config_with_sections();
        let mut emulator = EnhancedDenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();

        memory.map_bytes(0x1000, &[0x90u8; 64]);
        memory.map_bytes(0x2000, &[0xB8u8, 0x01, 0x00, 0x00, 0x00, 0xC3]);

        emulator.initialize(&mut memory, 0).unwrap();

        // Verify tamper hash for section at 0x1000
        let hash = emulator.verify_tamper_hash(&memory, 0x1000).unwrap();
        assert_eq!(hash.len(), 32);

        // The expected hash should be the original hash
        let entry = emulator.tamper_hashes.get(&0x1000).unwrap();
        assert!(entry.verified);
        assert_eq!(entry.verify_count, 1);
    }

    #[test]
    fn enhanced_denuvo_tamper_hash_not_found() {
        let config = make_config();
        let mut emulator = EnhancedDenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        emulator.initialize(&mut memory, 0).unwrap();

        let result = emulator.verify_tamper_hash(&memory, 0xDEAD);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn enhanced_denuvo_v6_decrypt() {
        let code = vec![0x90u8; 64];
        let config = DenuvoConfig {
            version: DenuvoVersion::V6,
            enabled: true,
            integrity_check_interval_ms: 5000,
            code_sections: vec![CodeSection {
                rva: 0x1000,
                size: 64,
                original_hash: [0u8; 32],
                decrypted: Vec::new(),
                encrypted: true,
            }],
            trigger_points: Vec::new(),
        };
        let mut emulator = EnhancedDenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, &code);
        emulator.initialize(&mut memory, 0).unwrap();

        // After initialize(), section.decrypted = plaintext (read from memory),
        // original_hash = SHA-256(plaintext), hardware_id and session_id are set.
        //
        // decrypt_v6_section derives key as:
        //   SHA-256(hardware_id + original_hash + session_id + "v6-aes-unwrap")
        let section = &emulator.base.config.code_sections[0];
        let mut key_material = Vec::with_capacity(48);
        key_material.extend_from_slice(&emulator.base.state.hardware_id);
        key_material.extend_from_slice(&section.original_hash);
        key_material.extend_from_slice(&emulator.session_id.to_le_bytes());
        key_material.extend_from_slice(b"v6-aes-unwrap");
        let derived = {
            let mut hasher = Sha256::new();
            hasher.update(&key_material);
            hasher.finalize()
        };
        let aes_key: [u8; 16] = {
            let mut k = [0u8; 16];
            k.copy_from_slice(&derived[..16]);
            k
        };
        let iv: [u8; 16] = {
            let mut i = [0u8; 16];
            i.copy_from_slice(&derived[16..]);
            i
        };

        // PKCS7-pad and AES-128-CBC encrypt the plaintext
        let block_size = 16usize;
        let pad_len = block_size - (code.len() % block_size);
        let mut padded = code.clone();
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        let enc = Aes128CbcEnc::new(&aes_key.into(), &iv.into());
        let ct = enc
            .encrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut padded, code.len())
            .unwrap();
        let ciphertext = ct.to_vec();

        // Replace section.decrypted with the ciphertext
        emulator.base.config.code_sections[0].decrypted = ciphertext;

        emulator.decrypt_section_enhanced(&mut memory, 0).unwrap();
        assert!(!emulator.base.config.code_sections[0].encrypted);
        assert!(emulator.base.state.code_sections_decrypted);
        let decrypted_data = memory.read_bytes(0x1000, code.len()).unwrap();
        assert_eq!(decrypted_data, code);
    }

    #[test]
    fn enhanced_denuvo_v7_decrypt() {
        let code = vec![0xCCu8; 128];
        let config = DenuvoConfig {
            version: DenuvoVersion::V7,
            enabled: true,
            integrity_check_interval_ms: 5000,
            code_sections: vec![CodeSection {
                rva: 0x3000,
                size: 128,
                original_hash: [0u8; 32],
                decrypted: Vec::new(),
                encrypted: true,
            }],
            trigger_points: Vec::new(),
        };
        let mut emulator = EnhancedDenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x3000, &code);
        emulator.initialize(&mut memory, 0).unwrap();

        // After initialize(), section.decrypted = plaintext (read from memory),
        // original_hash = SHA-256(plaintext), hardware_id and session_id are set.
        //
        // decrypt_v7_section derives key as:
        //   derived_key = SHA-256(hardware_id + original_hash + session_id + section_index)
        //   iv = SHA-256(derived_key + "v7-aes256-iv")[..16]
        //   aes_key = derived_key (32 bytes for AES-256)
        let section = &emulator.base.config.code_sections[0];
        let mut key_material = Vec::with_capacity(64);
        key_material.extend_from_slice(&emulator.base.state.hardware_id);
        key_material.extend_from_slice(&section.original_hash);
        key_material.extend_from_slice(&emulator.session_id.to_le_bytes());
        key_material.extend_from_slice(&0u64.to_le_bytes()); // section_index = 0
        let derived_key = {
            let mut hasher = Sha256::new();
            hasher.update(&key_material);
            hasher.finalize()
        };
        let mut iv_material = Vec::with_capacity(64);
        iv_material.extend_from_slice(&derived_key);
        iv_material.extend_from_slice(b"v7-aes256-iv");
        let iv_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&iv_material);
            hasher.finalize()
        };
        let aes_key: [u8; 32] = {
            let mut k = [0u8; 32];
            k.copy_from_slice(&derived_key);
            k
        };
        let iv: [u8; 16] = {
            let mut i = [0u8; 16];
            i.copy_from_slice(&iv_hash[..16]);
            i
        };

        // AES-256-CBC encrypt with PKCS7 padding
        let block_size = 16usize;
        let pad_len = block_size - (code.len() % block_size);
        let mut padded = code.clone();
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        let enc = Aes256CbcEnc::new(&aes_key.into(), &iv.into());
        let ct = enc
            .encrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut padded, code.len())
            .unwrap();
        let ciphertext = ct.to_vec();

        // Replace section.decrypted with the ciphertext
        emulator.base.config.code_sections[0].decrypted = ciphertext;

        emulator.decrypt_section_enhanced(&mut memory, 0).unwrap();
        assert!(!emulator.base.config.code_sections[0].encrypted);
        assert!(emulator.base.state.code_sections_decrypted);
        let decrypted_data = memory.read_bytes(0x3000, code.len()).unwrap();
        assert_eq!(decrypted_data, code);
    }

    #[test]
    fn enhanced_denuvo_add_trigger() {
        let config = make_config();
        let mut emulator = EnhancedDenuvoEmulator::new(config);

        emulator.add_trigger(0x7000, TriggerType::LicenseCheck, None);
        assert!(emulator.triggers.contains_key(&0x7000));
        assert_eq!(emulator.unfired_trigger_count(), 1);
    }

    #[test]
    fn enhanced_denuvo_reset_triggers() {
        let config = make_config();
        let mut emulator = EnhancedDenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        emulator.initialize(&mut memory, 0).unwrap();

        // Add a trigger and fire it
        emulator.add_trigger(0x7000, TriggerType::AntiDebug, None);
        let _ = emulator.handle_trigger(&mut memory, 0x7000);

        assert_eq!(emulator.triggers_handled, 1);

        emulator.reset_triggers();
        assert_eq!(emulator.triggers_handled, 0);
        let state = emulator.get_trigger_state(0x7000).unwrap();
        assert!(!state.fired);
        assert_eq!(state.hit_count, 0);
    }

    #[test]
    fn enhanced_denuvo_license_trigger() {
        let config = make_config();
        let mut emulator = EnhancedDenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        emulator.initialize(&mut memory, 0).unwrap();

        emulator.add_trigger(0x8000, TriggerType::LicenseCheck, None);
        let handled = emulator.handle_trigger(&mut memory, 0x8000).unwrap();
        assert!(handled);

        // License should now be verified
        assert!(emulator.base.license_verified);
        assert!(emulator.base.state.license_token.is_some());
    }

    #[test]
    fn enhanced_denuvo_hardware_bind_trigger() {
        let config = make_config();
        let mut emulator = EnhancedDenuvoEmulator::new(config);
        let mut memory = MemoryImage::default();
        emulator.initialize(&mut memory, 0).unwrap();

        emulator.add_trigger(0x9000, TriggerType::HardwareBind, None);
        let handled = emulator.handle_trigger(&mut memory, 0x9000).unwrap();
        assert!(handled);

        // Hardware ID should be set
        assert_ne!(emulator.base.state.hardware_id, [0u8; 16]);
    }

    #[test]
    fn enhanced_denuvo_timing_values() {
        let timing = AntiDebugTiming::new();
        assert!(timing.rdtsc_delta > 0);
        assert!(timing.qpc_delta > 0);
        assert_eq!(timing.check_count, 0);
    }
}
