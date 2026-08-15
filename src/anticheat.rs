// ---------------------------------------------------------------------------
// Anti-Cheat Driver Shim (Gap 10.1)
// ---------------------------------------------------------------------------
//
// When a Windows game uses a kernel-level anti-cheat driver (EAC, BattlEye,
// Riot Vanguard, etc.), macOS cannot load those drivers.  This module provides
// an `AntiCheatDriverShim` that intercepts driver-level anti-cheat calls and
// returns deterministic but realistic-looking responses so the game can
// continue running under the Casa1 emulation layer.
//
// Architecture:
//   AntiCheatDriverShim
//     ├── known driver detection (name → provider mapping)
//     ├── process information reporter (PID, parent PID, image path)
//     ├── module list reporter  (loaded DLLs with correct paths)
//     ├── integrity check handler (hash verification of loaded modules)
//     └── hardware information provider (CPUID, disk serial, MAC address)
// ---------------------------------------------------------------------------

use crate::cpu::MemoryImage;
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Known anti-cheat driver definitions
// ---------------------------------------------------------------------------

/// Anti-cheat provider identified from a driver name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AntiCheatProvider {
    /// Easy Anti-Cheat (Epic Online Services / Kamu).
    EasyAntiCheat,
    /// BattlEye anti-cheat.
    BattlEye,
    /// Riot Vanguard (League of Legends, Valorant).
    RiotVanguard,
    /// Xigncode / XHunter (Wellbia).
    Xigncode,
    /// FACEIT anti-cheat.
    Faceit,
    /// HoYoverse (miHoYo) anti-cheat (Genshin Impact, Honkai).
    Hoyoverse,
    /// nProtect GameGuard (INCA Internet).
    NProtect,
    /// EQU8 anti-cheat.
    Equ8,
    /// Unknown / unrecognized anti-cheat provider.
    Unknown,
}

/// A single known anti-cheat driver mapping.
struct DriverRule {
    /// Lowercase filename needle (e.g. "easyanticheat.sys").
    needle: &'static str,
    /// Provider this needle maps to.
    provider: AntiCheatProvider,
    /// Human-readable label for logging.
    label: &'static str,
}

/// Table of known anti-cheat driver names.
const DRIVER_RULES: &[DriverRule] = &[
    DriverRule {
        needle: "easyanticheat.sys",
        provider: AntiCheatProvider::EasyAntiCheat,
        label: "Easy Anti-Cheat kernel driver",
    },
    DriverRule {
        needle: "easyanticheat_eos.sys",
        provider: AntiCheatProvider::EasyAntiCheat,
        label: "Easy Anti-Cheat EOS kernel driver",
    },
    DriverRule {
        needle: "eac.sys",
        provider: AntiCheatProvider::EasyAntiCheat,
        label: "Easy Anti-Cheat kernel driver",
    },
    DriverRule {
        needle: "bedaisy.sys",
        provider: AntiCheatProvider::BattlEye,
        label: "BattlEye kernel driver",
    },
    DriverRule {
        needle: "beservice.exe",
        provider: AntiCheatProvider::BattlEye,
        label: "BattlEye service helper",
    },
    DriverRule {
        needle: "battleye.sys",
        provider: AntiCheatProvider::BattlEye,
        label: "BattlEye kernel driver",
    },
    DriverRule {
        needle: "vgk.sys",
        provider: AntiCheatProvider::RiotVanguard,
        label: "Riot Vanguard kernel driver",
    },
    DriverRule {
        needle: "vgc.exe",
        provider: AntiCheatProvider::RiotVanguard,
        label: "Riot Vanguard service helper",
    },
    DriverRule {
        needle: "xhunter1.sys",
        provider: AntiCheatProvider::Xigncode,
        label: "Xigncode/XHunter kernel driver",
    },
    DriverRule {
        needle: "xigncode.sys",
        provider: AntiCheatProvider::Xigncode,
        label: "Xigncode kernel driver",
    },
    DriverRule {
        needle: "faceit.sys",
        provider: AntiCheatProvider::Faceit,
        label: "FACEIT kernel driver",
    },
    DriverRule {
        needle: "faceitclient.exe",
        provider: AntiCheatProvider::Faceit,
        label: "FACEIT client",
    },
    DriverRule {
        needle: "mhyprot2.sys",
        provider: AntiCheatProvider::Hoyoverse,
        label: "HoYoverse kernel driver",
    },
    DriverRule {
        needle: "mhyprot3.sys",
        provider: AntiCheatProvider::Hoyoverse,
        label: "HoYoverse kernel driver v3",
    },
    DriverRule {
        needle: "nprotect",
        provider: AntiCheatProvider::NProtect,
        label: "nProtect/GameGuard component",
    },
    DriverRule {
        needle: "gameguard",
        provider: AntiCheatProvider::NProtect,
        label: "GameGuard component",
    },
    DriverRule {
        needle: "gg_client.sys",
        provider: AntiCheatProvider::NProtect,
        label: "GameGuard client driver",
    },
    DriverRule {
        needle: "equ8.sys",
        provider: AntiCheatProvider::Equ8,
        label: "EQU8 kernel driver",
    },
    DriverRule {
        needle: "easyanticheat",
        provider: AntiCheatProvider::EasyAntiCheat,
        label: "Easy Anti-Cheat component",
    },
];

// ---------------------------------------------------------------------------
// Process / module information types
// ---------------------------------------------------------------------------

/// Information about a single loaded module (DLL) in the guest process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Base address where the module is loaded.
    pub base_address: u64,
    /// Size of the module image in bytes.
    pub image_size: u32,
    /// Full Windows-style path to the module (e.g. "C:\Windows\System32\ntdll.dll").
    pub image_path: String,
    /// Module base name (e.g. "ntdll.dll").
    pub base_name: String,
    /// SHA-256 hash of the module's code sections (for integrity checks).
    pub code_hash: [u8; 32],
}

/// Information about the guest process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub parent_pid: u32,
    /// Full Windows-style image path.
    pub image_path: String,
    /// Process creation timestamp (Unix millis).
    pub creation_time: u64,
    /// Session ID.
    pub session_id: u32,
}

/// Hardware identifiers reported to anti-cheat drivers.
///
/// These values are deterministic (derived from a seed) so that repeated
/// queries return consistent data, but realistic-looking enough to pass
/// anti-cheat validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    /// CPU vendor string (12 bytes, e.g. "GenuineIntel").
    pub cpu_vendor: [u8; 12],
    /// CPUID leaf 1 EAX (family/model/stepping).
    pub cpuid_eax: u32,
    /// CPUID leaf 1 EBX.
    pub cpuid_ebx: u32,
    /// CPUID leaf 1 ECX.
    pub cpuid_ecx: u32,
    /// CPUID leaf 1 EDX.
    pub cpuid_edx: u32,
    /// CPU brand string (up to 48 bytes).
    pub cpu_brand: String,
    /// Disk serial number (deterministic, 20 ASCII digits).
    pub disk_serial: String,
    /// MAC address (6 bytes).
    pub mac_address: [u8; 6],
    /// BIOS UUID (16 bytes).
    pub bios_uuid: [u8; 16],
    /// Motherboard serial (deterministic, 32 ASCII chars).
    pub motherboard_serial: String,
    /// Total physical memory in MB.
    pub total_memory_mb: u32,
    /// Number of logical processors.
    pub num_processors: u32,
}

// ---------------------------------------------------------------------------
// Shim state
// ---------------------------------------------------------------------------

/// State of a loaded anti-cheat driver shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShimState {
    /// Shim has not been loaded.
    NotLoaded,
    /// Shim is loaded and operational.
    Active,
    /// Shim has been unloaded.
    Unloaded,
}

/// Result of an integrity check performed by the shim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheckResponse {
    /// Whether the integrity check passed.
    pub passed: bool,
    /// Hash of the checked region.
    pub computed_hash: [u8; 32],
    /// Size of the checked region.
    pub region_size: u32,
    /// Timestamp of the check.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// AntiCheatDriverShim
// ---------------------------------------------------------------------------

/// Global monotonic counter for generating deterministic timestamps.
static SHIM_TICK: AtomicU64 = AtomicU64::new(0);

/// The anti-cheat driver shim.
///
/// Intercepts driver-level anti-cheat calls and returns deterministic but
/// realistic-looking responses.  Each instance tracks the loaded state,
/// the detected provider, and cached hardware/process information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCheatDriverShim {
    /// Which anti-cheat provider this shim is handling.
    pub provider: AntiCheatProvider,
    /// Current shim state.
    pub state: ShimState,
    /// The driver filename that triggered this shim.
    pub driver_name: String,
    /// Process information for the guest process.
    pub process_info: ProcessInfo,
    /// List of loaded modules in the guest process.
    pub modules: Vec<ModuleInfo>,
    /// Hardware information (consistent across queries).
    pub hardware_info: HardwareInfo,
    /// Number of integrity checks performed.
    pub integrity_check_count: u64,
    /// Number of process info queries.
    pub process_query_count: u64,
    /// Number of module list queries.
    pub module_query_count: u64,
    /// Number of hardware info queries.
    pub hardware_query_count: u64,
    /// Whether the shim has been initialized with hardware seed.
    initialized: bool,
}

impl AntiCheatDriverShim {
    /// Creates a new `AntiCheatDriverShim` for the given driver name.
    ///
    /// The driver name is matched against the known anti-cheat driver table
    /// to determine the provider.  Process and hardware information are
    /// initialized with deterministic defaults.
    pub fn new(driver_name: &str, pid: u32, parent_pid: u32, image_path: &str) -> Self {
        let provider = Self::detect_provider(driver_name);
        let process_info = ProcessInfo {
            pid,
            parent_pid,
            image_path: image_path.to_string(),
            creation_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            session_id: 1,
        };
        let hardware_info = Self::generate_hardware_info(pid);

        Self {
            provider,
            state: ShimState::NotLoaded,
            driver_name: driver_name.to_string(),
            process_info,
            modules: Vec::new(),
            hardware_info,
            integrity_check_count: 0,
            process_query_count: 0,
            module_query_count: 0,
            hardware_query_count: 0,
            initialized: true,
        }
    }

    // -----------------------------------------------------------------------
    // Driver detection
    // -----------------------------------------------------------------------

    /// Detects the anti-cheat provider from a driver filename.
    pub fn detect_provider(driver_name: &str) -> AntiCheatProvider {
        let normalized = driver_name.to_ascii_lowercase().replace('\\', "/");
        for rule in DRIVER_RULES {
            if normalized.contains(rule.needle) {
                return rule.provider;
            }
        }
        AntiCheatProvider::Unknown
    }

    /// Detects whether the given driver name matches any known anti-cheat driver.
    pub fn is_known_driver(driver_name: &str) -> bool {
        let normalized = driver_name.to_ascii_lowercase().replace('\\', "/");
        DRIVER_RULES.iter().any(|r| normalized.contains(r.needle))
    }

    /// Returns a human-readable label for the given driver name.
    pub fn driver_label(driver_name: &str) -> Option<&'static str> {
        let normalized = driver_name.to_ascii_lowercase().replace('\\', "/");
        for rule in DRIVER_RULES {
            if normalized.contains(rule.needle) {
                return Some(rule.label);
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Shim lifecycle
    // -----------------------------------------------------------------------

    /// Loads the shim, transitioning from `NotLoaded` to `Active`.
    ///
    /// Populates the module list with standard Windows modules that anti-cheat
    /// drivers expect to see loaded.
    pub fn load(&mut self) -> AppResult<()> {
        if self.state == ShimState::Active {
            return Err(AppError::new(
                ReasonCode::RcAnticheatDriverDetected,
                "anti-cheat shim already loaded",
            ));
        }
        self.populate_default_modules();
        self.state = ShimState::Active;
        Ok(())
    }

    /// Unloads the shim.
    pub fn unload(&mut self) {
        self.state = ShimState::Unloaded;
    }

    // -----------------------------------------------------------------------
    // Process information queries
    // -----------------------------------------------------------------------

    /// Returns process information for the guest process.
    ///
    /// Anti-cheat drivers query process information to verify the game is
    /// running in an expected context.  We return deterministic data derived
    /// from the actual emulated environment.
    pub fn query_process_info(&mut self) -> ProcessInfo {
        self.process_query_count += 1;
        self.process_info.clone()
    }

    /// Updates the process information (e.g. when the image path changes).
    pub fn update_process_info(&mut self, pid: u32, parent_pid: u32, image_path: &str) {
        self.process_info.pid = pid;
        self.process_info.parent_pid = parent_pid;
        self.process_info.image_path = image_path.to_string();
    }

    // -----------------------------------------------------------------------
    // Module list queries
    // -----------------------------------------------------------------------

    /// Returns the list of loaded modules.
    ///
    /// Anti-cheat drivers enumerate loaded DLLs to detect injected cheats.
    /// We return a realistic list of standard Windows modules.
    pub fn query_module_list(&mut self) -> Vec<ModuleInfo> {
        self.module_query_count += 1;
        self.modules.clone()
    }

    /// Adds a module to the tracked module list.
    pub fn add_module(
        &mut self,
        base_address: u64,
        image_size: u32,
        image_path: &str,
        code_hash: [u8; 32],
    ) {
        let base_name = image_path
            .rsplit(|c| c == '\\' || c == '/')
            .next()
            .unwrap_or(image_path)
            .to_string();
        self.modules.push(ModuleInfo {
            base_address,
            image_size,
            image_path: image_path.to_string(),
            base_name,
            code_hash,
        });
    }

    /// Adds a module from guest memory by computing its hash.
    pub fn add_module_from_memory(
        &mut self,
        memory: &MemoryImage,
        base_address: u64,
        image_size: u32,
        image_path: &str,
    ) -> AppResult<()> {
        let data = memory.read_bytes(base_address, image_size as usize)?;
        let hash = sha256_hash(&data);
        self.add_module(base_address, image_size, image_path, hash);
        Ok(())
    }

    /// Removes a module from the tracked list by base address.
    pub fn remove_module(&mut self, base_address: u64) -> bool {
        let before = self.modules.len();
        self.modules.retain(|m| m.base_address != base_address);
        self.modules.len() < before
    }

    // -----------------------------------------------------------------------
    // Integrity checks
    // -----------------------------------------------------------------------

    /// Performs an integrity check on a memory region.
    ///
    /// Anti-cheat drivers verify that code sections have not been modified.
    /// We compute the actual hash and compare against the expected hash
    /// stored in the module list.  If no expected hash is available, we
    /// generate one from the current memory contents and store it.
    pub fn check_integrity(
        &mut self,
        memory: &MemoryImage,
        base_address: u64,
        size: u32,
    ) -> AppResult<IntegrityCheckResponse> {
        self.integrity_check_count += 1;
        let data = memory.read_bytes(base_address, size as usize)?;
        let computed_hash = sha256_hash(&data);

        // Look up the module that contains this region
        let expected_hash = self
            .modules
            .iter()
            .find(|m| {
                base_address >= m.base_address
                    && base_address < m.base_address + m.image_size as u64
            })
            .map(|m| m.code_hash);

        let passed = match expected_hash {
            Some(expected) => computed_hash == expected,
            None => {
                // No expected hash — first check for this region; record it
                let base_name = format!("region_{base_address:X}");
                self.add_module(base_address, size, &base_name, computed_hash);
                true
            }
        };

        let timestamp = SHIM_TICK.fetch_add(1, Ordering::Relaxed);

        Ok(IntegrityCheckResponse {
            passed,
            computed_hash,
            region_size: size,
            timestamp,
        })
    }

    /// Performs an integrity check on a specific module by index.
    pub fn check_module_integrity(
        &mut self,
        memory: &MemoryImage,
        module_index: usize,
    ) -> AppResult<IntegrityCheckResponse> {
        let module = self.modules.get(module_index).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDrmSectionNotFound,
                format!("module index {module_index} out of bounds"),
            )
        })?;
        self.check_integrity(memory, module.base_address, module.image_size)
    }

    /// Performs integrity checks on all tracked modules.
    pub fn check_all_modules(
        &mut self,
        memory: &MemoryImage,
    ) -> AppResult<Vec<IntegrityCheckResponse>> {
        let count = self.modules.len();
        let mut results = Vec::with_capacity(count);
        for idx in 0..count {
            results.push(self.check_module_integrity(memory, idx)?);
        }
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Hardware information queries
    // -----------------------------------------------------------------------

    /// Returns hardware information for the guest environment.
    ///
    /// Anti-cheat drivers collect hardware identifiers for machine binding.
    /// We return deterministic values derived from the process ID so they
    /// are consistent across queries but unique per game instance.
    pub fn query_hardware_info(&mut self) -> HardwareInfo {
        self.hardware_query_count += 1;
        self.hardware_info.clone()
    }

    /// Generates deterministic hardware information from a seed (PID).
    fn generate_hardware_info(seed: u32) -> HardwareInfo {
        // Derive all hardware identifiers from a single seed using SHA-256
        let seed_bytes = seed.to_le_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"casa1-hw-seed");
        hasher.update(&seed_bytes);
        hasher.update(b"casa1-hw-salt-1");
        let hash1: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(b"casa1-hw-seed");
        hasher.update(&seed_bytes);
        hasher.update(b"casa1-hw-salt-2");
        let hash2: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(b"casa1-hw-seed");
        hasher.update(&seed_bytes);
        hasher.update(b"casa1-hw-salt-3");
        let hash3: [u8; 32] = hasher.finalize().into();

        // CPU vendor: "GenuineIntel" (12 bytes)
        let mut cpu_vendor = [0u8; 12];
        cpu_vendor.copy_from_slice(b"GenuineIntel");

        // CPUID leaf 1: realistic-looking values for Intel Core i7
        let cpuid_eax = 0x0009_06EA; // Comet Lake
        let cpuid_ebx = 0x0002_0800 | ((seed & 0xFF) as u32); // brand index + APIC ID
        let cpuid_ecx = 0x7FFA_FBBF; // feature flags
        let cpuid_edx = 0xBFEB_FBFF; // feature flags

        // CPU brand string
        let cpu_brand = "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz".to_string();

        // Disk serial: 20 ASCII digits derived from hash
        let disk_serial = derive_ascii_digits(&hash1, 20);

        // MAC address: use a locally-administered address (second bit of first byte = 1)
        let mut mac_address = [0u8; 6];
        mac_address.copy_from_slice(&hash2[..6]);
        mac_address[0] = (mac_address[0] & 0xFC) | 0x02; // locally administered, unicast

        // BIOS UUID: 16 bytes from hash
        let mut bios_uuid = [0u8; 16];
        bios_uuid.copy_from_slice(&hash3[..16]);
        // Set version 4 variant bits
        bios_uuid[6] = (bios_uuid[6] & 0x0F) | 0x40;
        bios_uuid[8] = (bios_uuid[8] & 0x3F) | 0x80;

        // Motherboard serial: 32 ASCII chars from hash
        let motherboard_serial = derive_ascii_hex(&hash1, &hash2);

        // Total memory: 16 GB (realistic for gaming)
        let total_memory_mb = 16 * 1024;

        // Number of processors: 8 logical cores
        let num_processors = 8;

        HardwareInfo {
            cpu_vendor,
            cpuid_eax,
            cpuid_ebx,
            cpuid_ecx,
            cpuid_edx,
            cpu_brand,
            disk_serial,
            mac_address,
            bios_uuid,
            motherboard_serial,
            total_memory_mb,
            num_processors,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Populates the module list with standard Windows modules that anti-cheat
    /// drivers expect to see loaded in any Windows process.
    fn populate_default_modules(&mut self) {
        let default_modules = [
            (
                0x7FFE_0000u64,
                0x0010_0000u32,
                r"C:\Windows\System32\ntdll.dll",
            ),
            (
                0x7FFD_0000u64,
                0x0010_0000u32,
                r"C:\Windows\System32\kernel32.dll",
            ),
            (
                0x7FFC_0000u64,
                0x0008_0000u32,
                r"C:\Windows\System32\KernelBase.dll",
            ),
            (
                0x7FFB_0000u64,
                0x0004_0000u32,
                r"C:\Windows\System32\user32.dll",
            ),
            (
                0x7FFA_0000u64,
                0x0004_0000u32,
                r"C:\Windows\System32\gdi32.dll",
            ),
            (
                0x7FF9_0000u64,
                0x0004_0000u32,
                r"C:\Windows\System32\advapi32.dll",
            ),
            (
                0x7FF8_0000u64,
                0x0002_0000u32,
                r"C:\Windows\System32\ws2_32.dll",
            ),
            (
                0x7FF7_0000u64,
                0x0002_0000u32,
                r"C:\Windows\System32\msvcrt.dll",
            ),
            (
                0x7FF6_0000u64,
                0x0002_0000u32,
                r"C:\Windows\System32\ole32.dll",
            ),
            (
                0x7FF5_0000u64,
                0x0001_0000u32,
                r"C:\Windows\System32\shell32.dll",
            ),
            (
                0x7FF4_0000u64,
                0x0001_0000u32,
                r"C:\Windows\System32\shlwapi.dll",
            ),
            (
                0x7FF3_0000u64,
                0x0001_0000u32,
                r"C:\Windows\System32\version.dll",
            ),
            (
                0x7FF2_0000u64,
                0x0001_0000u32,
                r"C:\Windows\System32\crypt32.dll",
            ),
            (
                0x7FF1_0000u64,
                0x0001_0000u32,
                r"C:\Windows\System32\wintrust.dll",
            ),
            (
                0x7FF0_0000u64,
                0x0001_0000u32,
                r"C:\Windows\System32\secur32.dll",
            ),
            (
                0x7FEF_0000u64,
                0x0001_0000u32,
                r"C:\Windows\System32\iphlpapi.dll",
            ),
            (
                0x7FEE_0000u64,
                0x0001_0000u32,
                r"C:\Windows\System32\psapi.dll",
            ),
            (
                0x7FED_0000u64,
                0x0001_0000u32,
                r"C:\Windows\System32\dbghelp.dll",
            ),
        ];

        for (base, size, path) in &default_modules {
            // Generate a deterministic hash for each module based on its path
            let hash = sha256_hash(path.as_bytes());
            self.add_module(*base, *size, path, hash);
        }
    }
}

// ---------------------------------------------------------------------------
// Anti-Cheat Shim Registry
// ---------------------------------------------------------------------------

/// A registry of active anti-cheat driver shims, keyed by driver name.
///
/// This allows multiple anti-cheat drivers to be tracked simultaneously
/// (e.g. a game might use both EAC and BattlEye).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCheatShimRegistry {
    /// Active shims keyed by lowercase driver name.
    shims: BTreeMap<String, AntiCheatDriverShim>,
    /// Default PID for the guest process.
    default_pid: u32,
    /// Default parent PID.
    default_parent_pid: u32,
    /// Default image path.
    default_image_path: String,
}

impl AntiCheatShimRegistry {
    /// Creates a new empty registry.
    pub fn new(pid: u32, parent_pid: u32, image_path: &str) -> Self {
        Self {
            shims: BTreeMap::new(),
            default_pid: pid,
            default_parent_pid: parent_pid,
            default_image_path: image_path.to_string(),
        }
    }

    /// Attempts to load a shim for the given driver name.
    ///
    /// If the driver name matches a known anti-cheat driver, a shim is
    /// created, loaded, and registered.  Returns `Ok(true)` if a shim was
    /// loaded, `Ok(false)` if the driver is not a known anti-cheat driver.
    pub fn try_load_driver(&mut self, driver_name: &str) -> AppResult<bool> {
        if !AntiCheatDriverShim::is_known_driver(driver_name) {
            return Ok(false);
        }
        let key = driver_name.to_ascii_lowercase();
        if self.shims.contains_key(&key) {
            return Ok(true); // Already loaded
        }
        let mut shim = AntiCheatDriverShim::new(
            driver_name,
            self.default_pid,
            self.default_parent_pid,
            &self.default_image_path,
        );
        shim.load()?;
        self.shims.insert(key, shim);
        Ok(true)
    }

    /// Unloads a shim by driver name.
    pub fn unload_driver(&mut self, driver_name: &str) -> bool {
        let key = driver_name.to_ascii_lowercase();
        if let Some(shim) = self.shims.get_mut(&key) {
            shim.unload();
            true
        } else {
            false
        }
    }

    /// Returns a reference to the shim for the given driver, if loaded.
    pub fn get_shim(&self, driver_name: &str) -> Option<&AntiCheatDriverShim> {
        self.shims.get(&driver_name.to_ascii_lowercase())
    }

    /// Returns a mutable reference to the shim for the given driver.
    pub fn get_shim_mut(&mut self, driver_name: &str) -> Option<&mut AntiCheatDriverShim> {
        self.shims.get_mut(&driver_name.to_ascii_lowercase())
    }

    /// Returns all active shims.
    pub fn active_shims(&self) -> Vec<&AntiCheatDriverShim> {
        self.shims
            .values()
            .filter(|s| s.state == ShimState::Active)
            .collect()
    }

    /// Returns the number of loaded shims.
    pub fn count(&self) -> usize {
        self.shims.len()
    }

    /// Checks if any anti-cheat driver is loaded.
    pub fn has_active_shim(&self) -> bool {
        self.shims.values().any(|s| s.state == ShimState::Active)
    }
}

impl Default for AntiCheatShimRegistry {
    fn default() -> Self {
        Self::new(0, 0, "")
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Computes a SHA-256 hash of the given data.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Derives a string of ASCII digit characters from a hash.
fn derive_ascii_digits(hash: &[u8], len: usize) -> String {
    let mut result = String::with_capacity(len);
    for i in 0..len {
        let byte = hash[i % hash.len()];
        result.push((b'0' + (byte % 10)) as char);
    }
    result
}

/// Derives a 32-character hex string from two hashes.
fn derive_ascii_hex(hash1: &[u8; 32], hash2: &[u8; 32]) -> String {
    let mut result = String::with_capacity(32);
    for i in 0..16 {
        result.push_str(&format!("{:02x}", hash1[i]));
    }
    for i in 0..16 {
        result.push_str(&format!("{:02x}", hash2[i]));
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_eac_provider() {
        assert_eq!(
            AntiCheatDriverShim::detect_provider("easyanticheat.sys"),
            AntiCheatProvider::EasyAntiCheat
        );
        assert_eq!(
            AntiCheatDriverShim::detect_provider("EasyAntiCatch_EOS.sys"),
            AntiCheatProvider::Unknown // typo — no match
        );
        assert_eq!(
            AntiCheatDriverShim::detect_provider("EasyAntiCheat_EOS.sys"),
            AntiCheatProvider::EasyAntiCheat
        );
    }

    #[test]
    fn detect_battleye_provider() {
        assert_eq!(
            AntiCheatDriverShim::detect_provider("bedaisy.sys"),
            AntiCheatProvider::BattlEye
        );
        assert_eq!(
            AntiCheatDriverShim::detect_provider("BattlEye.sys"),
            AntiCheatProvider::BattlEye
        );
    }

    #[test]
    fn detect_vanguard_provider() {
        assert_eq!(
            AntiCheatDriverShim::detect_provider("vgk.sys"),
            AntiCheatProvider::RiotVanguard
        );
    }

    #[test]
    fn detect_unknown_provider() {
        assert_eq!(
            AntiCheatDriverShim::detect_provider("some_random_driver.sys"),
            AntiCheatProvider::Unknown
        );
    }

    #[test]
    fn is_known_driver_check() {
        assert!(AntiCheatDriverShim::is_known_driver("easyanticheat.sys"));
        assert!(AntiCheatDriverShim::is_known_driver("bedaisy.sys"));
        assert!(AntiCheatDriverShim::is_known_driver("vgk.sys"));
        assert!(!AntiCheatDriverShim::is_known_driver("ntoskrnl.exe"));
    }

    #[test]
    fn driver_label_lookup() {
        assert_eq!(
            AntiCheatDriverShim::driver_label("easyanticheat.sys"),
            Some("Easy Anti-Cheat kernel driver")
        );
        assert_eq!(AntiCheatDriverShim::driver_label("unknown.sys"), None);
    }

    #[test]
    fn shim_load_unload() {
        let mut shim =
            AntiCheatDriverShim::new("easyanticheat.sys", 1234, 100, r"C:\Game\game.exe");
        assert_eq!(shim.state, ShimState::NotLoaded);
        assert!(shim.modules.is_empty());

        shim.load().unwrap();
        assert_eq!(shim.state, ShimState::Active);
        assert!(!shim.modules.is_empty()); // default modules populated

        // Loading again should fail
        let _result = shim.load();
        assert!(_result.is_err(), "expected Err, got {_result:?}");

        shim.unload();
        assert_eq!(shim.state, ShimState::Unloaded);
    }

    #[test]
    fn shim_process_info() {
        let mut shim =
            AntiCheatDriverShim::new("bedaisy.sys", 5000, 2000, r"C:\Games\pubg\TslGame.exe");
        shim.load().unwrap();

        let info = shim.query_process_info();
        assert_eq!(info.pid, 5000);
        assert_eq!(info.parent_pid, 2000);
        assert_eq!(info.image_path, r"C:\Games\pubg\TslGame.exe");
        assert_eq!(shim.process_query_count, 1);

        shim.update_process_info(5001, 2001, r"C:\Games\pubg\TslGame_BE.exe");
        let info = shim.query_process_info();
        assert_eq!(info.pid, 5001);
        assert_eq!(info.parent_pid, 2001);
    }

    #[test]
    fn shim_module_list() {
        let mut shim =
            AntiCheatDriverShim::new("easyanticheat.sys", 1000, 500, r"C:\Game\game.exe");
        shim.load().unwrap();

        assert_eq!(shim.module_query_count, 0);

        let modules = shim.query_module_list();
        assert!(!modules.is_empty());
        assert_eq!(shim.module_query_count, 1);

        // Check that ntdll.dll is in the default modules
        let ntdll = modules.iter().find(|m| m.base_name == "ntdll.dll");
        assert!(ntdll.is_some());
        assert_eq!(ntdll.unwrap().image_path, r"C:\Windows\System32\ntdll.dll");
    }

    #[test]
    fn shim_add_remove_module() {
        let mut shim = AntiCheatDriverShim::new(
            "vgk.sys",
            3000,
            1000,
            r"C:\Riot Games\VALORANT\valorant.exe",
        );
        shim.load().unwrap();

        let initial_count = shim.modules.len();
        let hash = sha256_hash(b"test module data");
        shim.add_module(0x8000_0000, 0x10000, r"C:\Game\cheat.dll", hash);
        assert_eq!(shim.modules.len(), initial_count + 1);

        let found = shim.modules.iter().find(|m| m.base_name == "cheat.dll");
        assert!(found.is_some());

        assert!(shim.remove_module(0x8000_0000));
        assert_eq!(shim.modules.len(), initial_count);
        assert!(!shim.remove_module(0x8000_0000)); // already removed
    }

    #[test]
    fn shim_hardware_info() {
        let mut shim = AntiCheatDriverShim::new(
            "mhyprot2.sys",
            4000,
            1000,
            r"C:\Genshin Impact\GenshinImpact.exe",
        );
        shim.load().unwrap();

        let hw = shim.query_hardware_info();
        assert_eq!(shim.hardware_query_count, 1);

        // CPU vendor should be "GenuineIntel"
        assert_eq!(&hw.cpu_vendor, b"GenuineIntel");

        // MAC address should have locally-administered bit set
        assert_eq!(hw.mac_address[0] & 0x02, 0x02);

        // Disk serial should be 20 ASCII digits
        assert_eq!(hw.disk_serial.len(), 20);
        assert!(hw.disk_serial.chars().all(|c| c.is_ascii_digit()));

        // Motherboard serial should be 64 hex chars (32 bytes from two hashes)
        assert_eq!(hw.motherboard_serial.len(), 64);

        // Memory should be 16 GB
        assert_eq!(hw.total_memory_mb, 16 * 1024);

        // Processors should be 8
        assert_eq!(hw.num_processors, 8);

        // CPU brand should be set
        assert!(hw.cpu_brand.contains("Intel"));

        // BIOS UUID should have version 4 bits set
        assert_eq!(hw.bios_uuid[6] & 0xF0, 0x40);
        assert_eq!(hw.bios_uuid[8] & 0xC0, 0x80);
    }

    #[test]
    fn shim_hardware_info_consistency() {
        let mut shim1 = AntiCheatDriverShim::new("eac.sys", 100, 1, r"C:\game.exe");
        let mut shim2 = AntiCheatDriverShim::new("eac.sys", 100, 1, r"C:\game.exe");
        shim1.load().unwrap();
        shim2.load().unwrap();

        // Same PID should produce same hardware info
        let hw1 = shim1.query_hardware_info().clone();
        let hw2 = shim2.query_hardware_info().clone();
        assert_eq!(hw1.disk_serial, hw2.disk_serial);
        assert_eq!(hw1.mac_address, hw2.mac_address);
        assert_eq!(hw1.bios_uuid, hw2.bios_uuid);

        // Different PID should produce different hardware info
        let mut shim3 = AntiCheatDriverShim::new("eac.sys", 200, 1, r"C:\game.exe");
        shim3.load().unwrap();
        let hw3 = shim3.query_hardware_info().clone();
        assert_ne!(hw1.disk_serial, hw3.disk_serial);
        assert_ne!(hw1.mac_address, hw3.mac_address);
    }

    #[test]
    fn shim_integrity_check() {
        let mut shim =
            AntiCheatDriverShim::new("easyanticheat.sys", 1000, 500, r"C:\Game\game.exe");
        shim.load().unwrap();

        // Use an address not covered by any default module (beyond 0x800E_0000)
        let test_base: u64 = 0x1_0000_0000;
        let mut memory = MemoryImage::default();
        let code = vec![0x90, 0x90, 0xC3, 0x90];
        memory.map_bytes(test_base, &code);

        let result = shim.check_integrity(&memory, test_base, 4).unwrap();
        // First check should pass (hash is recorded)
        assert!(result.passed);
        assert_eq!(result.region_size, 4);
        assert_eq!(shim.integrity_check_count, 1);

        // Second check with same data should also pass
        let result = shim.check_integrity(&memory, test_base, 4).unwrap();
        assert!(result.passed);

        // Modify the memory and check again — should fail
        memory.map_bytes(test_base, &[0xCC, 0x90, 0xC3, 0x90]);
        let result = shim.check_integrity(&memory, test_base, 4).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn shim_registry() {
        let mut registry = AntiCheatShimRegistry::new(5000, 1000, r"C:\Game\game.exe");

        assert!(!registry.has_active_shim());
        assert_eq!(registry.count(), 0);

        // Load EAC
        let loaded = registry.try_load_driver("easyanticheat.sys").unwrap();
        assert!(loaded);
        assert_eq!(registry.count(), 1);
        assert!(registry.has_active_shim());

        // Loading same driver again should succeed but not add a new entry
        let loaded = registry.try_load_driver("EasyAntiCheat.sys").unwrap();
        assert!(loaded);
        assert_eq!(registry.count(), 1);

        // Unknown driver should not load
        let loaded = registry.try_load_driver("ntoskrnl.exe").unwrap();
        assert!(!loaded);
        assert_eq!(registry.count(), 1);

        // Load BattlEye
        let loaded = registry.try_load_driver("bedaisy.sys").unwrap();
        assert!(loaded);
        assert_eq!(registry.count(), 2);

        // Get shim
        let shim = registry.get_shim("easyanticheat.sys").unwrap();
        assert_eq!(shim.provider, AntiCheatProvider::EasyAntiCheat);

        // Unload
        assert!(registry.unload_driver("easyanticheat.sys"));
        assert!(registry.get_shim("easyanticheat.sys").is_some()); // still exists but unloaded
    }
}
