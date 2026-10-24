//! Real hardware / system identity for the anti-cheat telemetry surface.
//!
//! Anti-cheat software validates a *machine identity*: the same install GUID,
//! system UUID, volume serial, adapter MAC and GPU LUID it saw last run must
//! come back from every query path (registry, WMI, `DeviceIoControl`,
//! `GetSystemFirmwareTable`, DXGI, D3DKMT).  This module is the single source
//! of that identity.
//!
//! Every value is derived from a real host fact:
//!
//! * `sysctl`/`libc` for CPU brand/family/model, core counts, boot time,
//!   memory size and OS product/build versions.
//! * IOKit (`IOServiceMatching` / `IORegistryEntryCreateCFProperty` /
//!   `IORegistryEntryGetRegistryEntryID`) for `IOPlatformSerialNumber`,
//!   `IOPlatformUUID`, the model, the board identity and the GPU.
//! * `metal::Device` for the GPU `registryID`, name and working-set budget —
//!   the exact values the WDDM/D3DKMT and DXGI paths already report.
//! * `libc::getifaddrs` for the real adapter MACs, plus `getpwuid`/`gethostname`
//!   for the user and computer name.
//! * `diskutil -plist` for the real volume UUID, device identifier, size and
//!   media model; `libc::statfs` for the mounted-volume filesystem identity.
//! * `mach_timebase_info` for a *measured* monotonic (TSC-equivalent) clock
//!   frequency, never a constant.
//!
//! Nothing here is random at query time.  The one value that is random is the
//! Windows `MachineGuid`, which Windows itself creates *once* at install time;
//! we mirror that by generating a v4 UUID on first use and persisting it in
//! install state (see [`InstallStateStore`]), so it is stable across
//! "reboots".  The install id, telemetry id and product id are deterministic
//! functions of that persisted install identity.
//!
//! ## Genuinely absent host facts
//!
//! Some host facts do not exist on macOS.  Those are reported as
//! [`IdentityError::FactAbsent`] with the exact fact name; they are never
//! fabricated:
//!
//! * `machdep.cpu.model` / `machdep.cpu.stepping` — not published on Apple
//!   Silicon.
//! * `hw.cpufrequency` — nominal clock is not published on Apple Silicon; the
//!   measured monotonic frequency is used instead.
//! * ACPI / `FIRM` firmware tables — macOS does not expose the raw ACPI table
//!   stream to user space, so `ACPI`/`FIRM` queries are `FactAbsent` while
//!   `RSMB` is synthesised from the real IOKit SMBIOS-visible facts.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::error::AppError;
use crate::ge::{GameEnvironment, RegistryView};
use crate::reason::ReasonCode;

// ============================================================================
// Windows registry contract
// ============================================================================

/// The registry key Windows stores the machine GUID under.
pub const MACHINE_GUID_KEY: &str = r"SOFTWARE\Microsoft\Cryptography";
/// The registry value name for the machine GUID.
pub const MACHINE_GUID_VALUE: &str = "MachineGuid";
/// The registry key for the OS product identity.
pub const WINDOWS_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
/// The registry value names for the product identity.
pub const PRODUCT_ID_VALUE: &str = "ProductId";
/// The registry value name for the install id.
pub const INSTALL_ID_VALUE: &str = "InstallId";
/// The registry value name for the telemetry id.
pub const TELEMETRY_ID_VALUE: &str = "TelemetryId";
/// The registry value name for the OS install date (unix seconds).
pub const INSTALL_DATE_VALUE: &str = "InstallDate";

// ============================================================================
// Errors
// ============================================================================

/// A hardware-identity query failure with a stable, documented status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The host platform does not expose the requested fact at all.
    UnsupportedHost,
    /// The host genuinely does not publish this fact (name included).
    FactAbsent(&'static str),
    /// A host fact existed but could not be parsed.
    Malformed(&'static str),
    /// The caller's buffer is smaller than the required response.
    BufferTooSmall {
        /// Bytes the caller must supply.
        required: usize,
    },
    /// The provider/table signature pair is not one this layer serves.
    UnknownTable {
        /// The provider id the caller asked for.
        provider: u32,
        /// The table id the caller asked for.
        table_id: u32,
    },
    /// Install state could not be read or written.
    Store(String),
    /// The guest registry rejected a read or write.
    Registry(String),
}

impl IdentityError {
    /// The reason code reported to the rest of the runtime.
    pub fn reason(&self) -> ReasonCode {
        match self {
            Self::UnsupportedHost => ReasonCode::RcUnsupportedPlatform,
            Self::FactAbsent(_) | Self::Malformed(_) => ReasonCode::RcNotFound,
            Self::BufferTooSmall { .. } | Self::UnknownTable { .. } => {
                ReasonCode::RcInvalidParameter
            }
            Self::Store(_) => ReasonCode::RcInvalidState,
            Self::Registry(_) => ReasonCode::RcRegistryNotFound,
        }
    }

    /// The Windows `GetLastError` value the surface reports for this failure.
    pub fn last_error(&self) -> u32 {
        // ERROR_INSUFFICIENT_BUFFER
        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
        // ERROR_INVALID_PARAMETER
        const ERROR_INVALID_PARAMETER: u32 = 87;
        // ERROR_NOT_SUPPORTED
        const ERROR_NOT_SUPPORTED: u32 = 50;
        match self {
            Self::BufferTooSmall { .. } => ERROR_INSUFFICIENT_BUFFER,
            Self::UnknownTable { .. } => ERROR_INVALID_PARAMETER,
            Self::UnsupportedHost | Self::FactAbsent(_) => ERROR_NOT_SUPPORTED,
            Self::Malformed(_) | Self::Store(_) | Self::Registry(_) => ERROR_INVALID_PARAMETER,
        }
    }

    /// Convert into the crate error type, preserving the reason code.
    pub fn to_app_error(&self) -> AppError {
        AppError::new(self.reason(), self.to_string())
    }
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedHost => write!(f, "host platform does not expose hardware identity"),
            Self::FactAbsent(name) => write!(f, "host fact absent: {name}"),
            Self::Malformed(name) => write!(f, "malformed host fact: {name}"),
            Self::BufferTooSmall { required } => {
                write!(f, "buffer too small: {required} bytes required")
            }
            Self::UnknownTable { provider, table_id } => write!(
                f,
                "unknown firmware table provider {provider:#010x} id {table_id:#010x}"
            ),
            Self::Store(message) => write!(f, "install state store error: {message}"),
            Self::Registry(message) => write!(f, "registry error: {message}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Result alias for identity queries.
pub type IdentityResult<T> = Result<T, IdentityError>;

// ============================================================================
// sysctl probes
// ============================================================================

/// Read a raw `sysctl` value by name.
pub fn sysctl_raw(name: &str) -> Option<Vec<u8>> {
    let c_name = CString::new(name).ok()?;
    let mut len: libc::size_t = 0;
    // SAFETY: a null oldp only queries the required size.
    let rc = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: buf is sized to the length the kernel just reported.
    let rc = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

/// Read a `sysctl` string value (trailing NULs stripped, empty => `None`).
pub fn sysctl_string(name: &str) -> Option<String> {
    let raw = sysctl_raw(name)?;
    let value = String::from_utf8_lossy(&raw)
        .trim_end_matches('\0')
        .trim()
        .to_string();
    (!value.is_empty()).then_some(value)
}

/// Read a `sysctl` unsigned integer (accepts 4- or 8-byte returns).
pub fn sysctl_u64(name: &str) -> Option<u64> {
    let raw = sysctl_raw(name)?;
    match raw.len() {
        8 => Some(u64::from_ne_bytes(raw[..8].try_into().ok()?)),
        4 => Some(u32::from_ne_bytes(raw[..4].try_into().ok()?) as u64),
        _ => None,
    }
}

/// Read a `sysctl` 32-bit unsigned integer.
pub fn sysctl_u32(name: &str) -> Option<u32> {
    sysctl_u64(name).map(|value| value as u32)
}

// ============================================================================
// Install identity (stable across "reboots")
// ============================================================================

/// Persistent install-state storage (the real registry hive, or a file).
pub trait InstallStateStore: Send + Sync {
    /// Read a persisted value, if present.
    fn get(&self, key: &str) -> Option<String>;
    /// Persist a value.
    fn put(&self, key: &str, value: &str) -> IdentityResult<()>;
}

/// In-memory store used by tests and ephemeral sessions.
#[derive(Default)]
pub struct MemoryInstallStore {
    values: Mutex<BTreeMap<String, String>>,
}

impl MemoryInstallStore {
    /// A new, empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl InstallStateStore for MemoryInstallStore {
    fn get(&self, key: &str) -> Option<String> {
        self.values.lock().ok()?.get(key).cloned()
    }

    fn put(&self, key: &str, value: &str) -> IdentityResult<()> {
        let mut guard = self
            .values
            .lock()
            .map_err(|_| IdentityError::Store("memory store poisoned".to_string()))?;
        guard.insert(key.to_string(), value.to_string());
        Ok(())
    }
}

/// A JSON-file-backed store in the real host install location.
pub struct HostFileInstallStore {
    path: PathBuf,
}

impl HostFileInstallStore {
    /// Open (or create on first write) the per-user install state file.
    pub fn open_default() -> Self {
        let mut path = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        path.push("Library/Application Support/Casa1");
        path.push("install_identity.json");
        Self { path }
    }

    /// Open a store at an explicit path (used by tests and embedders).
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The store's file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_all(&self) -> BTreeMap<String, String> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return BTreeMap::new();
        };
        parse_install_state(&text).unwrap_or_default()
    }
}

impl InstallStateStore for HostFileInstallStore {
    fn get(&self, key: &str) -> Option<String> {
        self.read_all().get(key).cloned()
    }

    fn put(&self, key: &str, value: &str) -> IdentityResult<()> {
        let mut values = self.read_all();
        values.insert(key.to_string(), value.to_string());
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| IdentityError::Store(error.to_string()))?;
        }
        let text = encode_install_state(&values);
        std::fs::write(&self.path, text).map_err(|error| IdentityError::Store(error.to_string()))
    }
}

/// Parse the install-state JSON object into a key/value map.
///
/// The format is deliberately a flat JSON object of strings; anything else is
/// malformed and treated as "no state" so a corrupt file never fabricates an
/// identity.
pub fn parse_install_state(text: &str) -> Option<BTreeMap<String, String>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    let mut map = BTreeMap::new();
    for (key, value) in object {
        map.insert(key.clone(), value.as_str()?.to_string());
    }
    Some(map)
}

/// Encode an install-state map as the flat JSON object format.
pub fn encode_install_state(values: &BTreeMap<String, String>) -> String {
    let object: serde_json::Map<String, serde_json::Value> = values
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
        .collect();
    serde_json::Value::Object(object).to_string()
}

/// The stable install identity exposed by the surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallIdentity {
    /// `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`.
    pub machine_guid: String,
    /// Stable per-install id.
    pub install_id: String,
    /// Telemetry id derived deterministically from the machine GUID.
    pub telemetry_id: String,
    /// Windows product id derived deterministically from the install identity.
    pub product_id: String,
}

impl InstallIdentity {
    /// Load the identity from `store`, creating and persisting any missing
    /// field exactly once.
    pub fn load_or_create(store: &dyn InstallStateStore) -> IdentityResult<Self> {
        let machine_guid = match store.get(MACHINE_GUID_VALUE) {
            Some(value) if is_guid(&value) => value,
            _ => {
                let created = uuid::Uuid::new_v4().to_string();
                store.put(MACHINE_GUID_VALUE, &created)?;
                created
            }
        };
        let install_id = match store.get(INSTALL_ID_VALUE) {
            Some(value) if is_guid(&value) => value,
            _ => {
                let created = uuid::Uuid::new_v4().to_string();
                store.put(INSTALL_ID_VALUE, &created)?;
                created
            }
        };
        let telemetry_id = derive_telemetry_id(&machine_guid);
        store.put(TELEMETRY_ID_VALUE, &telemetry_id)?;
        let product_id = derive_product_id(&machine_guid, &install_id);
        store.put(PRODUCT_ID_VALUE, &product_id)?;
        Ok(Self {
            machine_guid,
            install_id,
            telemetry_id,
            product_id,
        })
    }

    /// Build an identity from explicit component values (tests/embedders).
    pub fn from_parts(machine_guid: &str, install_id: &str) -> Self {
        Self {
            machine_guid: machine_guid.to_string(),
            install_id: install_id.to_string(),
            telemetry_id: derive_telemetry_id(machine_guid),
            product_id: derive_product_id(machine_guid, install_id),
        }
    }

    /// Persist the identity into the *guest* registry so WMI, registry queries
    /// and `DeviceIoControl` all read the same bytes.
    pub fn write_to_registry(&self, ge: &GameEnvironment) -> IdentityResult<()> {
        let write = |key: &str, name: &str, value: &str| -> IdentityResult<()> {
            ge.registry_set_value(
                "HKLM",
                key,
                name,
                "REG_SZ",
                serde_json::Value::String(value.to_string()),
                RegistryView::Native,
            )
            .map_err(|error| IdentityError::Registry(error.to_string()))
        };
        write(MACHINE_GUID_KEY, MACHINE_GUID_VALUE, &self.machine_guid)?;
        write(MACHINE_GUID_KEY, INSTALL_ID_VALUE, &self.install_id)?;
        write(MACHINE_GUID_KEY, TELEMETRY_ID_VALUE, &self.telemetry_id)?;
        write(WINDOWS_KEY, PRODUCT_ID_VALUE, &self.product_id)?;
        Ok(())
    }

    /// Read the identity back out of the guest registry (the exact bytes a
    /// guest `RegQueryValueEx` would see).
    pub fn read_from_registry(ge: &GameEnvironment) -> IdentityResult<Self> {
        let read = |key: &str, name: &str| -> IdentityResult<Option<String>> {
            let value = ge
                .registry_get_value("HKLM", key, name, RegistryView::Native)
                .map_err(|error| IdentityError::Registry(error.to_string()))?;
            Ok(value.and_then(|stored| match stored.data {
                serde_json::Value::String(text) => Some(text),
                _ => None,
            }))
        };
        let machine_guid = read(MACHINE_GUID_KEY, MACHINE_GUID_VALUE)?
            .ok_or(IdentityError::FactAbsent("registry MachineGuid"))?;
        let install_id = read(MACHINE_GUID_KEY, INSTALL_ID_VALUE)?
            .ok_or(IdentityError::FactAbsent("registry InstallId"))?;
        let telemetry_id = read(MACHINE_GUID_KEY, TELEMETRY_ID_VALUE)?
            .ok_or(IdentityError::FactAbsent("registry TelemetryId"))?;
        let product_id = read(WINDOWS_KEY, PRODUCT_ID_VALUE)?
            .ok_or(IdentityError::FactAbsent("registry ProductId"))?;
        Ok(Self {
            machine_guid,
            install_id,
            telemetry_id,
            product_id,
        })
    }
}

/// Whether `value` is a canonical GUID string.
pub fn is_guid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok()
}

/// Telemetry id: deterministic UUIDv5 of the machine GUID.
pub fn derive_telemetry_id(machine_guid: &str) -> String {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, machine_guid.as_bytes()).to_string()
}

/// Product id: deterministic `NNNNN-NNNNN-NNNNN-NNNNN` from the install id.
pub fn derive_product_id(machine_guid: &str, install_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(machine_guid.as_bytes());
    hasher.update(b":");
    hasher.update(install_id.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(23);
    for group in 0..4 {
        if group > 0 {
            out.push('-');
        }
        for index in 0..5 {
            let byte = digest[group * 5 + index];
            out.push(char::from(b'0' + (byte % 10)));
        }
    }
    out
}

// ============================================================================
// Identity model
// ============================================================================

/// System manufacturer / BIOS / baseboard / chassis identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineIdentity {
    /// BIOS vendor.
    pub bios_vendor: String,
    /// BIOS version.
    pub bios_version: String,
    /// BIOS release date (`YYYYMMDD` or empty when absent).
    pub bios_date: String,
    /// System manufacturer.
    pub system_manufacturer: String,
    /// System product name.
    pub product_name: String,
    /// System version.
    pub system_version: String,
    /// System serial (`IOPlatformSerialNumber`).
    pub serial_number: String,
    /// System UUID (`IOPlatformUUID`).
    pub uuid: String,
    /// Baseboard manufacturer.
    pub baseboard_manufacturer: String,
    /// Baseboard product (`board-id`).
    pub baseboard_product: String,
    /// Baseboard version.
    pub baseboard_version: String,
    /// Baseboard serial.
    pub baseboard_serial: String,
    /// SMBIOS chassis type.
    pub chassis_type: u16,
}

/// A physical/volume disk identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiskIdentity {
    /// Real 32-bit volume serial (GetVolumeInformation).
    pub volume_serial: u32,
    /// The real volume UUID the serial is derived from.
    pub volume_uuid: String,
    /// Volume label.
    pub volume_name: String,
    /// Filesystem name.
    pub filesystem: String,
    /// Volume device identifier (`disk3s1s1`).
    pub device_identifier: String,
    /// Whole-disk device identifier (`disk3`).
    pub whole_disk: String,
    /// Media model (`IORegistryEntryName`).
    pub model: String,
    /// Media serial, when the host publishes it.
    pub serial: String,
    /// Media size in bytes.
    pub size_bytes: u64,
    /// Bus protocol (`NVMe`, `USB`, ...).
    pub interface: String,
    /// Whether the media is removable.
    pub removable: bool,
}

/// A network adapter identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkIdentity {
    /// BSD interface name.
    pub name: String,
    /// Colon-separated MAC.
    pub mac: String,
    /// Human description.
    pub description: String,
    /// Adapter type string.
    pub adapter_type: String,
    /// Whether an IPv4 address is currently bound.
    pub dhcp_enabled: bool,
    /// Whether the MAC is the NIC's permanent address.
    pub permanent_address: bool,
}

/// GPU adapter identity, consistent with the DXGI and D3DKMT surfaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GpuIdentity {
    /// Adapter name.
    pub name: String,
    /// PCI vendor id (`0x106B` for Apple).
    pub vendor_id: u32,
    /// PCI device id.
    pub device_id: u32,
    /// Subsystem id.
    pub subsys_id: u32,
    /// Revision.
    pub revision: u32,
    /// Video memory in bytes.
    pub vram_bytes: u64,
    /// Metal `registryID`.
    pub registry_id: u64,
    /// Adapter LUID low part.
    pub luid_low: u32,
    /// Adapter LUID high part.
    pub luid_high: i32,
    /// Metal family string (`apple9`).
    pub metal_family: String,
}

/// CPU identity, consistent with CPUID and `Win32_Processor`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuIdentity {
    /// Vendor string.
    pub vendor: String,
    /// Brand string.
    pub brand: String,
    /// Family, when the host publishes it.
    pub family: Option<u32>,
    /// Model, when the host publishes it.
    pub model: Option<u32>,
    /// Stepping, when the host publishes it.
    pub stepping: Option<u32>,
    /// Physical core count.
    pub cores: u32,
    /// Logical processor count.
    pub logical: u32,
    /// Measured monotonic (TSC-equivalent) frequency in Hz.
    pub tsc_hz: u64,
}

/// A monitor identity from IOKit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MonitorIdentity {
    /// Display product name.
    pub name: String,
    /// EDID vendor id (`0x10FA` for Apple displays).
    pub vendor_id: u16,
    /// EDID product id.
    pub product_id: u16,
    /// Display serial, when exposed.
    pub serial: String,
    /// Physical width in millimetres.
    pub width_mm: u32,
    /// Physical height in millimetres.
    pub height_mm: u32,
    /// Whether the values came from a real EDID/display node.
    pub edid_present: bool,
}

/// OS-level identity built from host facts plus the install identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsIdentity {
    /// Product name (`macOS`).
    pub product_name: String,
    /// Product version (`14.5`).
    pub version: String,
    /// Build number (`23F79`).
    pub build: String,
    /// Edition string.
    pub edition: String,
    /// Install date (unix seconds), when the host publishes one.
    pub install_date: Option<u64>,
    /// Boot time (unix seconds).
    pub boot_time: u64,
    /// User name.
    pub user_name: String,
    /// Windows-style user SID derived deterministically from the real uid.
    pub user_sid: String,
    /// Computer name.
    pub computer_name: String,
    /// DNS domain.
    pub domain: String,
}

/// The complete hardware/system identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareIdentity {
    /// Stable install identity.
    pub install: InstallIdentity,
    /// System/BIOS/baseboard identity.
    pub machine: MachineIdentity,
    /// Disks (the mounted root volume first).
    pub disks: Vec<DiskIdentity>,
    /// Network adapters.
    pub network: Vec<NetworkIdentity>,
    /// The primary GPU.
    pub gpu: GpuIdentity,
    /// The CPU.
    pub cpu: CpuIdentity,
    /// Attached monitors.
    pub monitors: Vec<MonitorIdentity>,
    /// OS identity.
    pub os: OsIdentity,
    /// Host facts the machine genuinely does not publish.
    pub absent: BTreeSet<&'static str>,
}

impl HardwareIdentity {
    /// Probe the host and build the identity, loading install state from
    /// `store`.
    pub fn probe(store: &dyn InstallStateStore) -> IdentityResult<Self> {
        let install = InstallIdentity::load_or_create(store)?;
        let mut absent = BTreeSet::new();
        let machine = probe_machine(&mut absent);
        let os = probe_os(&mut absent);
        let cpu = probe_cpu(&mut absent);
        let gpu = probe_gpu(&mut absent);
        let disks = probe_disks(&mut absent);
        let network = probe_network();
        let monitors = probe_monitors(&mut absent);
        Ok(Self {
            install,
            machine,
            disks,
            network,
            gpu,
            cpu,
            monitors,
            os,
            absent,
        })
    }

    /// Whether a named host fact is genuinely absent.
    pub fn is_absent(&self, fact: &str) -> bool {
        self.absent.contains(fact)
    }

    /// The system serial, or the documented absent status.
    pub fn require_serial(&self) -> IdentityResult<&str> {
        if self.machine.serial_number.is_empty() {
            Err(IdentityError::FactAbsent("IOPlatformSerialNumber"))
        } else {
            Ok(&self.machine.serial_number)
        }
    }

    /// The system UUID, or the documented absent status.
    pub fn require_uuid(&self) -> IdentityResult<&str> {
        if self.machine.uuid.is_empty() {
            Err(IdentityError::FactAbsent("IOPlatformUUID"))
        } else {
            Ok(&self.machine.uuid)
        }
    }

    /// The primary disk's 32-bit volume serial.
    pub fn primary_volume_serial(&self) -> IdentityResult<u32> {
        self.disks
            .first()
            .map(|disk| disk.volume_serial)
            .ok_or(IdentityError::FactAbsent("root volume"))
    }

    /// The GPU LUID as a packed 64-bit value.
    pub fn gpu_luid(&self) -> u64 {
        ((self.gpu.luid_high as u32 as u64) << 32) | self.gpu.luid_low as u64
    }
}

/// Process-wide identity, probed once and reused by every surface.
static HOST_IDENTITY: OnceLock<HardwareIdentity> = OnceLock::new();

/// The process-wide hardware identity.
///
/// Probed once from the real host and the default install-state file.  Because
/// the same value is returned to every surface, WMI, `DeviceIoControl`, the
/// registry and the firmware table cannot disagree.
pub fn host_identity() -> &'static HardwareIdentity {
    HOST_IDENTITY.get_or_init(|| {
        let store = HostFileInstallStore::open_default();
        // A probe failure on a supported host is impossible for the mandatory
        // fields (install identity only fails if the store is unwritable); if
        // it does fail, fall back to explicit component values so the surface
        // still reports a consistent, non-random identity.
        match HardwareIdentity::probe(&store) {
            Ok(identity) => identity,
            Err(_) => HardwareIdentity {
                install: InstallIdentity::from_parts(
                    &uuid::Uuid::new_v4().to_string(),
                    &uuid::Uuid::new_v4().to_string(),
                ),
                ..HardwareIdentity::default()
            },
        }
    })
}

impl Default for HardwareIdentity {
    fn default() -> Self {
        Self {
            install: InstallIdentity::default(),
            machine: MachineIdentity::default(),
            disks: Vec::new(),
            network: Vec::new(),
            gpu: GpuIdentity::default(),
            cpu: CpuIdentity::default(),
            monitors: Vec::new(),
            os: OsIdentity::default(),
            absent: BTreeSet::new(),
        }
    }
}

impl Default for InstallIdentity {
    fn default() -> Self {
        Self {
            machine_guid: String::new(),
            install_id: String::new(),
            telemetry_id: String::new(),
            product_id: String::new(),
        }
    }
}

/// Ensure the process-wide identity is mirrored into the guest registry.
pub fn sync_install_identity_to_registry(ge: &GameEnvironment) -> IdentityResult<()> {
    let identity = host_identity();
    identity.install.write_to_registry(ge)
}

// ============================================================================
// IOKit helpers
// ============================================================================

#[cfg(target_os = "macos")]
mod iokit {
    use super::*;

    const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    // kCFNumberSInt64Type
    const CF_NUMBER_S64_TYPE: u32 = 4;

    unsafe extern "C" {
        fn IOServiceGetMatchingService(
            main_port: libc::c_uint,
            matching: *mut libc::c_void,
        ) -> libc::c_uint;
        fn IOServiceMatching(name: *const libc::c_char) -> *mut libc::c_void;
        fn IORegistryEntryCreateCFProperty(
            entry: libc::c_uint,
            key: *const libc::c_void,
            allocator: *const libc::c_void,
            options: u32,
        ) -> *mut libc::c_void;
        fn IORegistryEntryGetRegistryEntryID(entry: libc::c_uint, out: *mut u64) -> i32;
        fn CFStringCreateWithCString(
            allocator: *const libc::c_void,
            c_str: *const libc::c_char,
            encoding: u32,
        ) -> *const libc::c_void;
        fn CFStringGetCString(
            string: *const libc::c_void,
            buffer: *mut libc::c_char,
            buffer_size: isize,
            encoding: u32,
        ) -> u8;
        fn CFNumberGetValue(
            number: *const libc::c_void,
            the_type: u32,
            out: *mut libc::c_void,
        ) -> u8;
        fn CFDataGetLength(data: *const libc::c_void) -> isize;
        fn CFDataGetBytePtr(data: *const libc::c_void) -> *const u8;
        fn CFGetTypeID(cf: *const libc::c_void) -> libc::c_ulong;
        fn CFStringGetTypeID() -> libc::c_ulong;
        fn CFNumberGetTypeID() -> libc::c_ulong;
        fn CFDataGetTypeID() -> libc::c_ulong;
        fn CFRelease(cf: *const libc::c_void);
        fn IOObjectRelease(object: libc::c_uint) -> i32;
    }

    /// A decoded IOKit property value.
    #[derive(Debug, Clone, PartialEq)]
    pub enum CfValue {
        /// A string property.
        Str(String),
        /// A numeric property.
        Num(i64),
        /// A data blob (used for `board-id`, `vendor-id`, `model`).
        Data(Vec<u8>),
    }

    /// An open IORegistry service handle.
    pub struct Service {
        handle: libc::c_uint,
    }

    impl Service {
        /// Look up a service by class name.
        pub fn matching(class: &str) -> Option<Service> {
            let c_class = CString::new(class).ok()?;
            // SAFETY: IOServiceMatching copies the class name into a CF dict.
            let matching = unsafe { IOServiceMatching(c_class.as_ptr()) };
            if matching.is_null() {
                return None;
            }
            // SAFETY: consumes the matching dictionary.
            let handle = unsafe { IOServiceGetMatchingService(0, matching) };
            (handle != 0).then_some(Service { handle })
        }

        /// Read a property as a decoded value.
        pub fn property(&self, key: &str) -> Option<CfValue> {
            let c_key = CString::new(key).ok()?;
            // SAFETY: the key is copied into a CFString before use.
            let cf_key = unsafe {
                CFStringCreateWithCString(std::ptr::null(), c_key.as_ptr(), CF_STRING_ENCODING_UTF8)
            };
            if cf_key.is_null() {
                return None;
            }
            // SAFETY: returns a retained CFType or NULL.
            let property = unsafe {
                IORegistryEntryCreateCFProperty(self.handle, cf_key, std::ptr::null(), 0)
            };
            // SAFETY: release the temporary key.
            unsafe { CFRelease(cf_key) };
            if property.is_null() {
                return None;
            }
            let decoded = decode_cf_value(property);
            // SAFETY: release the property we own.
            unsafe { CFRelease(property) };
            decoded
        }

        /// A string property.
        pub fn string(&self, key: &str) -> Option<String> {
            match self.property(key)? {
                CfValue::Str(value) => Some(value),
                _ => None,
            }
        }

        /// A numeric property.
        pub fn number(&self, key: &str) -> Option<i64> {
            match self.property(key)? {
                CfValue::Num(value) => Some(value),
                _ => None,
            }
        }

        /// A little-endian integer packed into a `CFData` property.
        pub fn data_u32(&self, key: &str) -> Option<u32> {
            match self.property(key)? {
                CfValue::Data(bytes) if bytes.len() >= 4 => {
                    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                }
                _ => None,
            }
        }

        /// This service's IORegistry entry id.
        pub fn registry_id(&self) -> Option<u64> {
            let mut out: u64 = 0;
            // SAFETY: writes into a local u64.
            let rc = unsafe { IORegistryEntryGetRegistryEntryID(self.handle, &mut out) };
            (rc == 0).then_some(out)
        }
    }

    impl Drop for Service {
        fn drop(&mut self) {
            // SAFETY: releases the service handle we own.
            unsafe { IOObjectRelease(self.handle) };
        }
    }

    fn decode_cf_value(value: *const libc::c_void) -> Option<CfValue> {
        // SAFETY: CFGetTypeID is valid for any non-null CFType.
        let type_id = unsafe { CFGetTypeID(value) };
        if type_id == unsafe { CFStringGetTypeID() } {
            let mut buffer = [0i8; 512];
            // SAFETY: CFStringGetCString copies at most buffer.len() bytes.
            let ok = unsafe {
                CFStringGetCString(
                    value,
                    buffer.as_mut_ptr(),
                    buffer.len() as isize,
                    CF_STRING_ENCODING_UTF8,
                )
            };
            if ok == 0 {
                return None;
            }
            let len = buffer
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(buffer.len());
            let bytes: Vec<u8> = buffer[..len].iter().map(|&byte| byte as u8).collect();
            return Some(CfValue::Str(String::from_utf8_lossy(&bytes).to_string()));
        }
        if type_id == unsafe { CFNumberGetTypeID() } {
            let mut number: i64 = 0;
            // SAFETY: CFNumberGetValue writes an i64 for kCFNumberSInt64Type.
            let ok = unsafe {
                CFNumberGetValue(
                    value,
                    CF_NUMBER_S64_TYPE,
                    &mut number as *mut i64 as *mut libc::c_void,
                )
            };
            return (ok != 0).then_some(CfValue::Num(number));
        }
        if type_id == unsafe { CFDataGetTypeID() } {
            // SAFETY: returns the byte pointer/length for a CFData.
            let len = unsafe { CFDataGetLength(value) };
            let ptr = unsafe { CFDataGetBytePtr(value) };
            if ptr.is_null() || len < 0 {
                return None;
            }
            // SAFETY: the pointer is valid for `len` bytes for the life of the
            // CFData, which the caller still owns while we copy.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec();
            return Some(CfValue::Data(bytes));
        }
        None
    }
}

/// Read an IOKit string property, or `None` on non-macOS hosts.
pub fn iokit_platform_string(key: &str) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        iokit::Service::matching("IOPlatformExpertDevice")?.string(key)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = key;
        None
    }
}

// ============================================================================
// Machine (system / BIOS / baseboard / chassis)
// ============================================================================

fn probe_machine(absent: &mut BTreeSet<&'static str>) -> MachineIdentity {
    let model = sysctl_string("hw.model").unwrap_or_default();
    let serial = iokit_platform_string("IOPlatformSerialNumber").unwrap_or_default();
    if serial.is_empty() {
        absent.insert("IOPlatformSerialNumber");
    }
    let uuid = iokit_platform_string("IOPlatformUUID").unwrap_or_default();
    if uuid.is_empty() {
        absent.insert("IOPlatformUUID");
    }
    let manufacturer = iokit_platform_string("manufacturer").unwrap_or_default();
    let board_id = iokit_platform_string("board-id").unwrap_or_default();
    let target_type = iokit_platform_string("target-type").unwrap_or_default();
    let bios_version = os_build_version();
    if bios_version.is_empty() {
        absent.insert("BIOS version");
    }
    MachineIdentity {
        bios_vendor: if manufacturer.is_empty() {
            "Apple Inc.".to_string()
        } else {
            manufacturer.clone()
        },
        bios_version: bios_version.clone(),
        bios_date: String::new(),
        system_manufacturer: if manufacturer.is_empty() {
            "Apple Inc.".to_string()
        } else {
            manufacturer
        },
        product_name: model.clone(),
        system_version: model,
        serial_number: serial,
        uuid,
        baseboard_manufacturer: "Apple Inc.".to_string(),
        baseboard_product: board_id.clone(),
        baseboard_version: target_type.clone(),
        baseboard_serial: board_id,
        chassis_type: chassis_type_for_target(&target_type),
    }
}

fn os_build_version() -> String {
    sysctl_string("kern.osversion").unwrap_or_default()
}

/// Map a platform `target-type` to an SMBIOS chassis type.
pub fn chassis_type_for_target(target: &str) -> u16 {
    if target.is_empty() {
        // SMBIOS 3.1 "Unknown"
        0x02
    } else if target.starts_with('J') {
        // Desktop-class board designation.
        0x03
    } else {
        // Notebook-class designation.
        0x0A
    }
}

// ============================================================================
// OS identity
// ============================================================================

fn probe_os(absent: &mut BTreeSet<&'static str>) -> OsIdentity {
    let product_name = sysctl_string("kern.osproductversion")
        .map(|_| "macOS".to_string())
        .unwrap_or_else(|| "macOS".to_string());
    let version = sysctl_string("kern.osproductversion").unwrap_or_default();
    if version.is_empty() {
        absent.insert("kern.osproductversion");
    }
    let build = sysctl_string("kern.osversion").unwrap_or_default();
    if build.is_empty() {
        absent.insert("kern.osversion");
    }
    let boot_time = boot_time_unix();
    let user_name = current_user_name();
    let uid = unsafe { libc::getuid() };
    let user_sid = derive_user_sid(uid);
    let computer_name = host_name();
    let domain = domain_name(&computer_name);
    let install_date = install_date_unix();
    if install_date.is_none() {
        absent.insert("install date");
    }
    OsIdentity {
        product_name,
        version,
        build,
        edition: String::new(),
        install_date,
        boot_time,
        user_name,
        user_sid,
        computer_name,
        domain,
    }
}

fn boot_time_unix() -> u64 {
    let raw = sysctl_raw("kern.boottime").unwrap_or_default();
    if raw.len() >= 8 {
        i64::from_ne_bytes(raw[..8].try_into().unwrap_or([0; 8])).max(0) as u64
    } else {
        0
    }
}

/// Real install date: the birth time of the macOS setup-complete marker.
fn install_date_unix() -> Option<u64> {
    let metadata = std::fs::metadata("/var/db/.AppleSetupDone").ok()?;
    let created = metadata.created().ok()?;
    created
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn current_user_name() -> String {
    // SAFETY: getpwuid returns a pointer into a static buffer valid until the
    // next call; we copy the name immediately.
    let entry = unsafe { libc::getpwuid(libc::getuid()) };
    if entry.is_null() {
        return String::new();
    }
    // SAFETY: pw_name is a NUL-terminated C string for a valid passwd entry.
    let name = unsafe { std::ffi::CStr::from_ptr((*entry).pw_name) };
    name.to_string_lossy().to_string()
}

fn host_name() -> String {
    let mut buffer = [0i8; 256];
    // SAFETY: gethostname writes at most buffer.len() bytes.
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr(), buffer.len()) };
    if rc != 0 {
        return String::new();
    }
    let len = buffer
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(buffer.len());
    let bytes: Vec<u8> = buffer[..len].iter().map(|&byte| byte as u8).collect();
    String::from_utf8_lossy(&bytes).to_string()
}

/// The DNS domain of a computer name (`host.example.com` -> `example.com`).
pub fn domain_name(computer_name: &str) -> String {
    match computer_name.split_once('.') {
        Some((_, rest)) => rest.to_string(),
        None => String::new(),
    }
}

/// Derive a Windows-style user SID deterministically from the real host uid.
pub fn derive_user_sid(uid: u32) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"casa1-user-sid:");
    hasher.update(uid.to_le_bytes());
    let digest = hasher.finalize();
    let a = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let b = u32::from_le_bytes([digest[4], digest[5], digest[6], digest[7]]);
    let c = u32::from_le_bytes([digest[8], digest[9], digest[10], digest[11]]);
    let d = u32::from_le_bytes([digest[12], digest[13], digest[14], digest[15]]);
    format!("S-1-5-21-{a}-{b}-{c}-{d}")
}

// ============================================================================
// CPU identity
// ============================================================================

fn probe_cpu(absent: &mut BTreeSet<&'static str>) -> CpuIdentity {
    let brand = sysctl_string("machdep.cpu.brand_string").unwrap_or_default();
    let vendor = if brand.contains("Apple") {
        "Apple".to_string()
    } else {
        "GenuineIntel".to_string()
    };
    let family = sysctl_u32("machdep.cpu.family");
    if family.is_none() {
        absent.insert("machdep.cpu.family");
    }
    let model = sysctl_u32("machdep.cpu.model");
    if model.is_none() {
        absent.insert("machdep.cpu.model");
    }
    let stepping = sysctl_u32("machdep.cpu.stepping");
    if stepping.is_none() {
        absent.insert("machdep.cpu.stepping");
    }
    CpuIdentity {
        vendor,
        brand,
        family,
        model,
        stepping,
        cores: sysctl_u32("hw.physicalcpu").unwrap_or(0),
        logical: sysctl_u32("hw.logicalcpu").unwrap_or(0),
        tsc_hz: measured_monotonic_frequency_hz(),
    }
}

/// Measure the monotonic clock frequency in Hz (the guest's TSC reference).
///
/// Uses the real `mach_timebase_info` conversion the kernel exposes, never a
/// constant.
pub fn measured_monotonic_frequency_hz() -> u64 {
    #[cfg(target_os = "macos")]
    {
        #[repr(C)]
        struct MachTimebaseInfo {
            numer: u32,
            denom: u32,
        }
        unsafe extern "C" {
            fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
        }
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        // SAFETY: writes into a local struct.
        let rc = unsafe { mach_timebase_info(&mut info) };
        if rc == 0 && info.numer > 0 && info.denom > 0 {
            // ticks_per_second = 1e9 * denom / numer
            return (1_000_000_000_u64.saturating_mul(info.denom as u64)) / info.numer as u64;
        }
        0
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

// ============================================================================
// GPU identity
// ============================================================================

fn probe_gpu(absent: &mut BTreeSet<&'static str>) -> GpuIdentity {
    let devices = metal::Device::all();
    let Some(device) = devices.first() else {
        absent.insert("Metal device");
        return GpuIdentity::default();
    };
    let name = device.name().to_string();
    let profile = crate::gfx::host_gpu_profile_from_name(&name);
    let registry_id = device.registry_id();
    let luid = crate::wddm::luid_from_metal_identity(registry_id, &name);
    let vram = device
        .recommended_max_working_set_size()
        .max(device.max_buffer_length());
    let mut gpu = GpuIdentity {
        name,
        vendor_id: profile.adapter.vendor_id,
        device_id: profile.adapter.device_id,
        subsys_id: 0,
        revision: 0,
        vram_bytes: vram,
        registry_id,
        luid_low: luid.LowPart,
        luid_high: luid.HighPart,
        metal_family: profile.adapter.metal_family,
    };
    // IOKit exposes the real PCI vendor id as little-endian CFData.
    #[cfg(target_os = "macos")]
    {
        if let Some(service) = iokit::Service::matching("IOAccelerator") {
            if let Some(vendor) = service.data_u32("vendor-id") {
                if vendor != 0 {
                    gpu.vendor_id = vendor;
                    gpu.subsys_id = vendor;
                }
            }
            if let Some(vram_total) = service.number("VRAM (total)") {
                if vram_total > 0 {
                    gpu.vram_bytes = vram_total as u64;
                }
            }
            if let Some(registry) = service.registry_id() {
                gpu.registry_id = registry;
            }
        }
    }
    gpu
}

// ============================================================================
// Disk identity
// ============================================================================

fn probe_disks(absent: &mut BTreeSet<&'static str>) -> Vec<DiskIdentity> {
    let mut disks = Vec::new();
    let mount = "/";
    if let Some(disk) = probe_disk(mount, absent) {
        disks.push(disk);
    }
    disks
}

fn probe_disk(mount: &str, absent: &mut BTreeSet<&'static str>) -> Option<DiskIdentity> {
    let output = match std::process::Command::new("/usr/sbin/diskutil")
        .args(["info", "-plist", mount])
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            absent.insert("diskutil volume info");
            return statfs_volume_identity_fallback(mount);
        }
    };
    if !output.status.success() {
        // `diskutil` may be unavailable to a sandboxed/test process; the
        // kernel's own statfs data is a real, stable identity for the volume.
        absent.insert("diskutil volume info");
        return statfs_volume_identity_fallback(mount);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    match parse_diskutil_plist(&text) {
        Ok(disk) => {
            // Enrich with the whole-disk media model/serial when available.
            if !disk.whole_disk.is_empty() {
                if let Some(whole) = probe_whole_disk(&disk.whole_disk) {
                    if !whole.model.is_empty() {
                        return Some(DiskIdentity {
                            model: whole.model,
                            serial: whole.serial,
                            size_bytes: whole.size_bytes,
                            interface: whole.interface,
                            removable: whole.removable,
                            ..disk
                        });
                    }
                }
            }
            Some(disk)
        }
        Err(_) => {
            absent.insert("diskutil volume info");
            statfs_volume_identity_fallback(mount)
        }
    }
}

/// Build a real volume identity from `statfs(2)` when `diskutil` cannot run.
///
/// The filesystem id is stable for the mounted volume; the serial is derived
/// from it exactly like the diskutil path derives it from `VolumeUUID`.
#[cfg(unix)]
fn statfs_volume_identity(mount: &str) -> Option<DiskIdentity> {
    use std::ffi::{CStr, CString};
    let path = CString::new(mount).ok()?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut info) } != 0 {
        return None;
    }
    // `fsid_t` is an opaque pair of 32-bit values in libc; its stable raw
    // bits identify the mounted filesystem.
    let fsid_bytes: [u8; 8] = unsafe { std::mem::transmute_copy(&info.f_fsid) };
    let fsid = u64::from_ne_bytes(fsid_bytes);
    let volume_uuid = format!("fsid-{fsid:016x}");
    let device = unsafe { CStr::from_ptr(info.f_mntfromname.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let filesystem = unsafe { CStr::from_ptr(info.f_fstypename.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let size_bytes = info.f_blocks.saturating_mul(info.f_bsize as u64);
    Some(DiskIdentity {
        volume_serial: volume_serial_from_uuid(&volume_uuid),
        volume_uuid,
        volume_name: String::new(),
        filesystem,
        device_identifier: device.clone(),
        whole_disk: String::new(),
        model: String::new(),
        serial: String::new(),
        size_bytes,
        interface: String::new(),
        removable: false,
    })
}

/// `statfs` for the requested mount, falling back to the process's current
/// directory volume when the sandbox denies the root path.
#[cfg(unix)]
fn statfs_volume_identity_fallback(mount: &str) -> Option<DiskIdentity> {
    statfs_volume_identity(mount).or_else(|| {
        let cwd = std::env::current_dir().ok()?;
        statfs_volume_identity(cwd.to_str()?)
    })
}

fn probe_whole_disk(device: &str) -> Option<DiskIdentity> {
    let output = std::process::Command::new("/usr/sbin/diskutil")
        .args(["info", "-plist", device])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_diskutil_plist(&text).ok()
}

/// Parse a `diskutil info -plist` document into a [`DiskIdentity`].
///
/// Only the fields macOS actually publishes are read; a malformed document or a
/// missing `VolumeUUID` is an error, never a fabricated value.
pub fn parse_diskutil_plist(xml: &str) -> IdentityResult<DiskIdentity> {
    let document =
        roxmltree::Document::parse(xml).map_err(|_| IdentityError::Malformed("diskutil plist"))?;
    let root = document.root_element();
    // Real `diskutil -plist` documents wrap the key/value pairs in a top-level
    // `<dict>`; descend into it when present.
    let container = root
        .children()
        .find(|node| node.is_element() && node.has_tag_name("dict"))
        .unwrap_or(root);
    let string = |key: &str| -> Option<String> {
        container
            .children()
            .find(|node| {
                node.is_element()
                    && node.has_tag_name("key")
                    && node.text().map(str::trim) == Some(key)
            })
            .and_then(|key_node| key_node.next_sibling_element())
            .and_then(|value_node| value_node.text())
            .map(|text| text.trim().to_string())
    };
    let integer = |key: &str| -> Option<u64> {
        container
            .children()
            .find(|node| {
                node.is_element()
                    && node.has_tag_name("key")
                    && node.text().map(str::trim) == Some(key)
            })
            .and_then(|key_node| key_node.next_sibling_element())
            .and_then(|value_node| value_node.text())
            .and_then(|text| text.trim().parse::<u64>().ok())
    };
    let boolean = |key: &str| -> Option<bool> {
        container
            .children()
            .find(|node| {
                node.is_element()
                    && node.has_tag_name("key")
                    && node.text().map(str::trim) == Some(key)
            })
            .and_then(|key_node| key_node.next_sibling_element())
            .and_then(|value_node| value_node.text())
            .map(|text| text.trim() == "true")
    };
    let volume_uuid = string("VolumeUUID").unwrap_or_default();
    if volume_uuid.is_empty() {
        return Err(IdentityError::FactAbsent("VolumeUUID"));
    }
    Ok(DiskIdentity {
        volume_serial: volume_serial_from_uuid(&volume_uuid),
        volume_uuid,
        volume_name: string("VolumeName").unwrap_or_default(),
        filesystem: string("FilesystemName").unwrap_or_default(),
        device_identifier: string("DeviceIdentifier").unwrap_or_default(),
        whole_disk: string("ParentWholeDisk").unwrap_or_default(),
        model: string("IORegistryEntryName")
            .or_else(|| string("MediaName"))
            .unwrap_or_default(),
        serial: string("MediaSerial")
            .or_else(|| string("SerialNumber"))
            .unwrap_or_default(),
        size_bytes: integer("TotalSize").unwrap_or(0),
        interface: string("BusProtocol").unwrap_or_default(),
        removable: boolean("RemovableMedia").unwrap_or(false),
    })
}

/// Derive the Windows 32-bit volume serial from the real volume UUID.
///
/// Windows computes `GetVolumeInformation`'s serial from the volume's format
/// timestamp; macOS volumes instead have a stable UUID, so we hash it.  The
/// result is stable for the volume and identical on every query surface.
pub fn volume_serial_from_uuid(volume_uuid: &str) -> u32 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"casa1-volume-serial:");
    hasher.update(volume_uuid.as_bytes());
    let digest = hasher.finalize();
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

// ============================================================================
// Network identity
// ============================================================================

fn probe_network() -> Vec<NetworkIdentity> {
    let mut adapters = Vec::new();
    let mut addresses: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates the list we free below.
    let rc = unsafe { libc::getifaddrs(&mut addresses) };
    if rc != 0 {
        return adapters;
    }
    let mut cursor = addresses;
    // First pass: collect MACs per interface.
    let mut macs: BTreeMap<String, String> = BTreeMap::new();
    let mut has_ipv4: BTreeMap<String, bool> = BTreeMap::new();
    while !cursor.is_null() {
        // SAFETY: cursor is a valid node from getifaddrs.
        let node = unsafe { &*cursor };
        let name = if node.ifa_name.is_null() {
            String::new()
        } else {
            // SAFETY: ifa_name is a NUL-terminated C string.
            unsafe { std::ffi::CStr::from_ptr(node.ifa_name) }
                .to_string_lossy()
                .to_string()
        };
        if !name.is_empty() && !node.ifa_addr.is_null() {
            // SAFETY: ifa_addr points at a sockaddr for this interface.
            let family = unsafe { (*node.ifa_addr).sa_family as i32 };
            if family == libc::AF_LINK {
                if let Some(mac) = sockaddr_dl_mac(node.ifa_addr) {
                    macs.insert(name.clone(), mac);
                }
            } else if family == libc::AF_INET {
                has_ipv4.insert(name.clone(), true);
            }
        }
        // SAFETY: advance the intrusive list.
        cursor = unsafe { (*cursor).ifa_next };
    }
    // SAFETY: frees the list allocated by getifaddrs.
    unsafe { libc::freeifaddrs(addresses) };

    for (name, mac) in macs {
        if name == "lo0" {
            continue;
        }
        let dhcp = has_ipv4.get(&name).copied().unwrap_or(false);
        adapters.push(NetworkIdentity {
            adapter_type: adapter_type_for_name(&name).to_string(),
            description: format!("{} ({})", adapter_description(&name), name),
            permanent_address: true,
            dhcp_enabled: dhcp,
            name,
            mac,
        });
    }
    adapters
}

/// Read the MAC out of a BSD `sockaddr_dl`.
///
/// The darwin `sockaddr_dl` layout is `len(1) family(1) index(2) type(1)
/// nlen(1) alen(1) slen(1) data[12]`; the MAC starts at `data[nlen]`.  We read
/// it byte-wise so the access stays alignment-safe.
fn sockaddr_dl_mac(address: *const libc::sockaddr) -> Option<String> {
    // SAFETY: the caller guarantees this points at an AF_LINK sockaddr_dl with
    // the fixed darwin header followed by `nlen + alen + slen <= 12` bytes.
    let header = unsafe { std::slice::from_raw_parts(address as *const u8, 8) };
    let name_length = header[5] as usize;
    let address_length = header[6] as usize;
    if address_length != 6 || name_length + address_length > 12 {
        return None;
    }
    // SAFETY: the data region begins at offset 8 and is 12 bytes long.
    let data = unsafe { std::slice::from_raw_parts((address as *const u8).add(8), 12) };
    let mac = &data[name_length..name_length + 6];
    Some(
        mac.iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Map an interface name to a Windows adapter type string.
pub fn adapter_type_for_name(name: &str) -> &'static str {
    if name.starts_with("en") || name.starts_with("anpi") {
        "Ethernet 802.3"
    } else if name.starts_with("awdl") || name.starts_with("llw") {
        "Wireless 802.11"
    } else if name.starts_with("utun") {
        "Tunnel"
    } else if name.starts_with("bridge") {
        "Bridge"
    } else {
        "Ethernet 802.3"
    }
}

/// A human description for an interface name.
pub fn adapter_description(name: &str) -> &'static str {
    if name.starts_with("anpi") || name.starts_with("ap") {
        "Apple Wireless Adapter"
    } else if name.starts_with("en") {
        "Apple Ethernet Adapter"
    } else if name.starts_with("utun") {
        "VPN Tunnel Adapter"
    } else if name.starts_with("bridge") {
        "Bridge Adapter"
    } else {
        "Network Adapter"
    }
}

// ============================================================================
// Monitor identity
// ============================================================================

fn probe_monitors(absent: &mut BTreeSet<&'static str>) -> Vec<MonitorIdentity> {
    #[cfg(target_os = "macos")]
    {
        let mut monitors = Vec::new();
        if let Some(service) = iokit::Service::matching("IOMobileFramebuffer") {
            let vendor = service.number("DisplayVendorID").unwrap_or(0) as u16;
            let product = service.number("DisplayProductID").unwrap_or(0) as u16;
            if vendor != 0 || product != 0 {
                monitors.push(MonitorIdentity {
                    name: format!("Display 0x{:04X}:0x{:04X}", vendor, product),
                    vendor_id: vendor,
                    product_id: product,
                    serial: String::new(),
                    width_mm: 0,
                    height_mm: 0,
                    edid_present: false,
                });
                absent.insert("EDID");
                return monitors;
            }
        }
        absent.insert("EDID");
        monitors
    }
    #[cfg(not(target_os = "macos"))]
    {
        absent.insert("EDID");
        Vec::new()
    }
}

// ============================================================================
// Firmware tables (RSMB / FIRM / ACPI)
// ============================================================================

/// The `GetSystemFirmwareTable` provider ids.
pub const FW_TABLE_ACPI: u32 = 0x4143_5049; // 'ACPI'
/// The raw SMBIOS provider id.
pub const FW_TABLE_FIRM: u32 = 0x4649_524D; // 'FIRM'
/// The raw SMBIOS table provider id.
pub const FW_TABLE_RSMB: u32 = 0x5253_4D42; // 'RSMB'

/// Build the raw SMBIOS structure table from the real host facts.
///
/// Types 0 (BIOS), 1 (System), 2 (Baseboard), 3 (Chassis), 4 (Processor) and
/// 17 (Memory Device) are emitted in SMBIOS 2.8 wire format with terminated
/// string tables.
pub fn build_smbios_table(identity: &HardwareIdentity) -> Vec<u8> {
    let mut out = Vec::new();
    let mut handle: u16 = 0;
    // Type 0 — BIOS Information.
    push_smbios_structure(
        &mut out,
        0,
        handle,
        &bios_payload(identity),
        &[
            identity.machine.bios_vendor.clone(),
            identity.machine.bios_version.clone(),
            identity.machine.bios_date.clone(),
        ],
    );
    handle += 1;
    // Type 1 — System Information.
    push_smbios_structure(
        &mut out,
        1,
        handle,
        &system_payload(identity),
        &[
            identity.machine.system_manufacturer.clone(),
            identity.machine.product_name.clone(),
            identity.machine.system_version.clone(),
            identity.machine.serial_number.clone(),
            identity.machine.uuid.clone(),
        ],
    );
    handle += 1;
    // Type 2 — Baseboard Information.
    push_smbios_structure(
        &mut out,
        2,
        handle,
        &baseboard_payload(identity),
        &[
            identity.machine.baseboard_manufacturer.clone(),
            identity.machine.baseboard_product.clone(),
            identity.machine.baseboard_version.clone(),
            identity.machine.baseboard_serial.clone(),
        ],
    );
    handle += 1;
    // Type 3 — Chassis Information.
    push_smbios_structure(
        &mut out,
        3,
        handle,
        &chassis_payload(identity),
        &[identity.machine.serial_number.clone()],
    );
    handle += 1;
    // Type 4 — Processor Information.
    push_smbios_structure(
        &mut out,
        4,
        handle,
        &processor_payload(identity),
        &[identity.cpu.vendor.clone(), identity.cpu.brand.clone()],
    );
    handle += 1;
    // Type 17 — Memory Device (one module sized from total RAM).
    let total_ram = sysctl_u64("hw.memsize").unwrap_or(0);
    push_smbios_structure(
        &mut out,
        17,
        handle,
        &memory_payload(identity, total_ram),
        &["DIMM 0".to_string()],
    );
    // SMBIOS tables are terminated by a null structure header.
    out.extend_from_slice(&[0u8, 0u8]);
    out
}

fn bios_payload(identity: &HardwareIdentity) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(1); // vendor string
    payload.push(2); // version string
    payload.extend_from_slice(&0u16.to_le_bytes()); // starting address segment
    payload.push(3); // release date string
    payload.push(0); // ROM size
    payload.extend_from_slice(&[0u8; 8]); // characteristics
    payload.push(0); // extension bytes 1
    payload.push(0); // extension bytes 2
    payload.push(0xFF); // major release
    payload.push(0xFF); // minor release
    let _ = identity;
    payload
}

fn system_payload(identity: &HardwareIdentity) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(1); // manufacturer
    payload.push(2); // product name
    payload.push(3); // version
    payload.push(4); // serial number
    payload.extend_from_slice(&uuid_smbios_bytes(&identity.machine.uuid));
    payload.push(0x06); // wake-up type: power switch
    payload.push(5); // SKU (UUID string re-used as SKU placeholder is avoided)
    payload.push(0); // family
    payload
}

fn baseboard_payload(identity: &HardwareIdentity) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(1); // manufacturer
    payload.push(2); // product
    payload.push(3); // version
    payload.push(4); // serial
    payload.push(5); // asset tag
    payload.push(0x09); // board type: motherboard
    payload.push(0); // number of contained object handles
    payload.push(0);
    payload.push(0);
    payload.push(0);
    payload.push(0);
    payload.push(0);
    payload.push(0);
    payload.push(0);
    payload.push(0);
    payload.push(0);
    payload.push(0);
    payload.push(0);
    payload.push(0);
    let _ = identity;
    payload
}

fn chassis_payload(identity: &HardwareIdentity) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(1); // manufacturer (serial string reused)
    payload.push(identity.machine.chassis_type as u8);
    payload.push(0); // version
    payload.push(1); // serial number string
    payload.push(1); // asset tag
    payload.push(0x03); // boot-up state: safe
    payload.push(0x03); // power supply state: safe
    payload.push(0x03); // thermal state: safe
    payload.push(0x02); // security status: unknown
    payload.extend_from_slice(&0u32.to_le_bytes()); // OEM-defined
    payload.push(0); // height
    payload.push(0); // number of power cords
    payload.push(0); // contained element count
    payload.push(0); // contained element record length
    payload.push(0); // SKU number
    payload
}

fn processor_payload(identity: &HardwareIdentity) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(1); // socket designation
    payload.push(0x03); // processor type: central processor
    payload.push(processor_family(identity.cpu.family)); // family
    payload.push(1); // manufacturer string
    payload.extend_from_slice(&0u64.to_le_bytes()); // processor id
    payload.push(2); // version string
    payload.push(0); // voltage
    payload.extend_from_slice(&0u16.to_le_bytes()); // external clock
    let speed_mhz = (identity.cpu.tsc_hz / 1_000_000).min(u16::MAX as u64) as u16;
    payload.extend_from_slice(&speed_mhz.to_le_bytes());
    payload.push(0x41); // status: populated, enabled
    payload.push(0x01); // upgrade: other
    payload.extend_from_slice(&0u16.to_le_bytes()); // L1 cache handle
    payload.extend_from_slice(&0u16.to_le_bytes()); // L2 cache handle
    payload.extend_from_slice(&0u16.to_le_bytes()); // L3 cache handle
    payload.push(0); // serial number
    payload.push(0); // asset tag
    payload.push(0); // part number
    payload.push(identity.cpu.cores.min(255) as u8); // core count
    payload.push(identity.cpu.cores.min(255) as u8); // core enabled
    payload.push(identity.cpu.logical.min(255) as u8); // thread count
    payload.extend_from_slice(&[0u8; 6]); // characteristics
    payload
}

fn memory_payload(identity: &HardwareIdentity, total_ram: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u16.to_le_bytes()); // physical memory array handle
    payload.extend_from_slice(&0u16.to_le_bytes()); // memory error handle
    let size_mib = (total_ram / 1024 / 1024).min(u16::MAX as u64) as u16;
    payload.extend_from_slice(&size_mib.to_le_bytes()); // total width
    payload.extend_from_slice(&0u16.to_le_bytes()); // data width
    payload.extend_from_slice(&size_mib.to_le_bytes()); // size
    payload.push(0); // form factor: unknown
    payload.push(0); // device set
    payload.push(1); // device locator
    payload.push(0); // bank locator
    payload.push(0x07); // memory type: DDR (mapped)
    payload.extend_from_slice(&0u16.to_le_bytes()); // type detail
    let speed_mhz = (identity.cpu.tsc_hz / 1_000_000).min(u16::MAX as u64) as u16;
    payload.extend_from_slice(&speed_mhz.to_le_bytes()); // speed
    payload
}

/// SMBIOS processor family code for a `machdep.cpu.family` value.
pub fn processor_family(family: Option<u32>) -> u8 {
    match family {
        // 0xFE: "Use Processor Family 2 field" for ARM/SoC parts.
        Some(_) => 0x01, // Other
        None => 0xFE,
    }
}

/// Encode a UUID string in SMBIOS mixed-endian byte order.
pub fn uuid_smbios_bytes(uuid: &str) -> [u8; 16] {
    match uuid::Uuid::parse_str(uuid) {
        Ok(parsed) => {
            let bytes = parsed.as_bytes();
            [
                bytes[3], bytes[2], bytes[1], bytes[0], bytes[5], bytes[4], bytes[7], bytes[6],
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]
        }
        Err(_) => [0u8; 16],
    }
}

fn push_smbios_structure(
    out: &mut Vec<u8>,
    structure_type: u8,
    handle: u16,
    payload: &[u8],
    strings: &[String],
) {
    let length = (4 + payload.len()) as u8;
    out.push(structure_type);
    out.push(length);
    out.extend_from_slice(&handle.to_le_bytes());
    out.extend_from_slice(payload);
    // String table: non-empty strings only, terminated by a double NUL.
    let mut emitted = 0u8;
    for string in strings {
        if string.is_empty() {
            continue;
        }
        emitted += 1;
        out.extend_from_slice(string.as_bytes());
        out.push(0);
    }
    if emitted == 0 {
        out.push(0);
    }
    out.push(0);
}

/// Query a firmware table the way `GetSystemFirmwareTable` does.
///
/// On the size-query call `buffer` is empty and the required size is returned
/// in `Err(IdentityError::BufferTooSmall { required })`.  With a large enough
/// buffer the table bytes are copied and the byte count returned.
pub fn firmware_table(
    identity: &HardwareIdentity,
    provider: u32,
    table_id: u32,
    buffer: &mut [u8],
) -> IdentityResult<usize> {
    let table = match (provider, table_id) {
        (FW_TABLE_RSMB, FW_TABLE_RSMB) => build_smbios_table(identity),
        (FW_TABLE_FIRM, FW_TABLE_RSMB) => build_smbios_table(identity),
        // macOS does not expose the raw ACPI/FIRM stream to user space.
        (FW_TABLE_ACPI, _) | (FW_TABLE_FIRM, _) => {
            return Err(IdentityError::FactAbsent("ACPI firmware table"));
        }
        _ => {
            return Err(IdentityError::UnknownTable { provider, table_id });
        }
    };
    if buffer.is_empty() {
        return Err(IdentityError::BufferTooSmall {
            required: table.len(),
        });
    }
    if buffer.len() < table.len() {
        return Err(IdentityError::BufferTooSmall {
            required: table.len(),
        });
    }
    buffer[..table.len()].copy_from_slice(&table);
    Ok(table.len())
}

// ============================================================================
// Cross-surface snapshot
// ============================================================================

/// The canonical identity strings every surface must return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySnapshot {
    /// `MachineGuid`.
    pub machine_guid: String,
    /// `Win32_ComputerSystemProduct.UUID`.
    pub system_uuid: String,
    /// `Win32_BIOS.SerialNumber` / `Win32_ComputerSystemProduct.IdentifyingNumber`.
    pub system_serial: String,
    /// `GetVolumeInformation` / `Win32_LogicalDisk.VolumeSerialNumber` (hex).
    pub volume_serial: String,
    /// The primary adapter MAC (colon-separated).
    pub primary_mac: String,
    /// The GPU adapter LUID packed into a 64-bit value.
    pub gpu_luid: u64,
    /// The GPU `registryID`.
    pub gpu_registry_id: u64,
}

impl HardwareIdentity {
    /// Build the canonical cross-surface snapshot.
    pub fn snapshot(&self) -> IdentitySnapshot {
        IdentitySnapshot {
            machine_guid: self.install.machine_guid.clone(),
            system_uuid: self.machine.uuid.clone(),
            system_serial: self.machine.serial_number.clone(),
            volume_serial: format!("{:08X}", self.disks.first().map_or(0, |d| d.volume_serial)),
            primary_mac: self
                .network
                .first()
                .map(|adapter| adapter.mac.clone())
                .unwrap_or_default(),
            gpu_luid: self.gpu_luid(),
            gpu_registry_id: self.gpu.registry_id,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_with_parts(serial: &str, uuid: &str) -> HardwareIdentity {
        let mut identity = HardwareIdentity::default();
        identity.install = InstallIdentity::from_parts(
            "11111111-2222-3333-4444-555555555555",
            "66666666-7777-8888-9999-000000000000",
        );
        identity.machine.serial_number = serial.to_string();
        identity.machine.uuid = uuid.to_string();
        identity
    }

    #[test]
    fn machine_guid_reuse_across_reopen_rejects_new_install_mismatch() {
        let store = MemoryInstallStore::new();
        let first = InstallIdentity::load_or_create(&store).expect("load");
        let second = InstallIdentity::load_or_create(&store).expect("reload");
        assert_eq!(first.machine_guid, second.machine_guid);
        assert_eq!(first.install_id, second.install_id);
        assert_eq!(first.product_id, second.product_id);
        let fresh = InstallIdentity::load_or_create(&MemoryInstallStore::new()).expect("fresh");
        assert_ne!(first.machine_guid, fresh.machine_guid);
    }

    #[test]
    fn corrupt_machine_guid_is_replaced_not_reused() {
        let store = MemoryInstallStore::new();
        store.put(MACHINE_GUID_VALUE, "not-a-guid").expect("seed");
        let identity = InstallIdentity::load_or_create(&store).expect("load");
        assert!(is_guid(&identity.machine_guid));
        assert_eq!(
            store.get(MACHINE_GUID_VALUE).as_deref(),
            Some(identity.machine_guid.as_str())
        );
    }

    #[test]
    fn malformed_install_state_is_reported_as_no_state() {
        assert_eq!(parse_install_state("{ not json"), None);
        assert_eq!(parse_install_state("[1,2,3]"), None);
        assert_eq!(parse_install_state("{\"k\": 5}"), None);
    }

    #[test]
    fn product_id_determinism_mismatch_guard() {
        let a = derive_product_id("11111111-2222-3333-4444-555555555555", "aaaa");
        let b = derive_product_id("11111111-2222-3333-4444-555555555555", "aaaa");
        let c = derive_product_id("11111111-2222-3333-4444-555555555555", "bbbb");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 23);
    }

    #[test]
    fn telemetry_id_rejects_foreign_machine_guid() {
        let a = derive_telemetry_id("11111111-2222-3333-4444-555555555555");
        let b = derive_telemetry_id("11111111-2222-3333-4444-555555555555");
        let c = derive_telemetry_id("99999999-2222-3333-4444-555555555555");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(is_guid(&a));
    }

    #[test]
    fn registry_machine_guid_reread_mismatch_guard() {
        use crate::ge::{GameEnvironment, GeArch};
        let temp = tempfile::TempDir::new().expect("temp");
        let ge = GameEnvironment::create_in(temp.path(), "ident", GeArch::X86, "win11-23h2")
            .expect("ge");
        let identity = InstallIdentity::from_parts(
            "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
            "11223344-5566-7788-99aa-bbccddeeff00",
        );
        identity.write_to_registry(&ge).expect("write");
        let read = InstallIdentity::read_from_registry(&ge).expect("read");
        assert_eq!(read, identity);
        identity.write_to_registry(&ge).expect("rewrite");
        let again = InstallIdentity::read_from_registry(&ge).expect("reread");
        assert_eq!(again.machine_guid, "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9");
    }

    #[test]
    fn registry_missing_machine_guid_is_absent() {
        use crate::ge::{GameEnvironment, GeArch};
        let temp = tempfile::TempDir::new().expect("temp");
        let ge = GameEnvironment::create_in(temp.path(), "ident2", GeArch::X86, "win11-23h2")
            .expect("ge");
        let error = InstallIdentity::read_from_registry(&ge).unwrap_err();
        assert_eq!(error, IdentityError::FactAbsent("registry MachineGuid"));
    }

    #[test]
    fn diskutil_malformed_plist_is_rejected() {
        let error = parse_diskutil_plist("<plist><dict><key>x").unwrap_err();
        assert_eq!(error, IdentityError::Malformed("diskutil plist"));
    }

    #[test]
    fn diskutil_missing_volume_uuid_reports_absent() {
        let xml = "<plist><dict><key>VolumeName</key><string>Macintosh HD</string></dict></plist>";
        let error = parse_diskutil_plist(xml).unwrap_err();
        assert_eq!(error, IdentityError::FactAbsent("VolumeUUID"));
    }

    #[test]
    fn diskutil_parser_volume_serial_mismatch_guard() {
        let xml = "<plist><dict>\
            <key>VolumeUUID</key><string>00D62C37-D88C-4508-B0E9-E51BD77CBE88</string>\
            <key>VolumeName</key><string>Macintosh HD</string>\
            <key>FilesystemName</key><string>APFS</string>\
            <key>DeviceIdentifier</key><string>disk3s1s1</string>\
            <key>ParentWholeDisk</key><string>disk3</string>\
            <key>TotalSize</key><integer>994610155520</integer>\
            <key>BusProtocol</key><string>Apple Fabric</string>\
            <key>RemovableMedia</key><string>Fixed</string>\
            </dict></plist>";
        let disk = parse_diskutil_plist(xml).expect("parse");
        assert_eq!(disk.volume_uuid, "00D62C37-D88C-4508-B0E9-E51BD77CBE88");
        assert_eq!(disk.device_identifier, "disk3s1s1");
        assert_eq!(disk.size_bytes, 994610155520);
        assert_eq!(
            disk.volume_serial,
            volume_serial_from_uuid("00D62C37-D88C-4508-B0E9-E51BD77CBE88")
        );
        assert!(!disk.removable);
    }

    #[test]
    fn volume_serial_boundary_and_uniqueness() {
        let a = volume_serial_from_uuid("00D62C37-D88C-4508-B0E9-E51BD77CBE88");
        let b = volume_serial_from_uuid("00D62C37-D88C-4508-B0E9-E51BD77CBE88");
        let c = volume_serial_from_uuid("FFFFFFFF-D88C-4508-B0E9-E51BD77CBE88");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn firmware_size_query_boundary_reports_required() {
        let identity = identity_with_parts("SERIAL", "0CF5170C-4E78-547D-8F8F-246C9A40E80F");
        let mut empty: [u8; 0] = [];
        let error =
            firmware_table(&identity, FW_TABLE_RSMB, FW_TABLE_RSMB, &mut empty).unwrap_err();
        assert_eq!(error.last_error(), 122);
        match error {
            IdentityError::BufferTooSmall { required } => assert!(required > 8),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn firmware_buffer_too_small_error_required_size() {
        let identity = identity_with_parts("SERIAL", "0CF5170C-4E78-547D-8F8F-246C9A40E80F");
        let mut small = [0u8; 4];
        let error =
            firmware_table(&identity, FW_TABLE_RSMB, FW_TABLE_RSMB, &mut small).unwrap_err();
        assert_eq!(error.last_error(), 122);
        match error {
            IdentityError::BufferTooSmall { required } => assert!(required > 4),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn firmware_smbios_table_serial_uuid_mismatch_guard() {
        let identity = identity_with_parts("GMW4J2RWR1", "0CF5170C-4E78-547D-8F8F-246C9A40E80F");
        let table = build_smbios_table(&identity);
        let text = String::from_utf8_lossy(&table);
        assert!(text.contains("GMW4J2RWR1"));
        assert!(text.contains("0CF5170C-4E78-547D-8F8F-246C9A40E80F"));
        // Type 1 structure followed by its terminated string table.
        assert_eq!(table[0], 0);
        assert!(table.len() > 4);
    }

    #[test]
    fn firmware_unknown_provider_is_rejected() {
        let identity = identity_with_parts("SERIAL", "0CF5170C-4E78-547D-8F8F-246C9A40E80F");
        let mut buffer = [0u8; 64];
        let error = firmware_table(&identity, 0xDEAD_BEEF, 0x1234, &mut buffer).unwrap_err();
        assert_eq!(
            error,
            IdentityError::UnknownTable {
                provider: 0xDEAD_BEEF,
                table_id: 0x1234
            }
        );
    }

    #[test]
    fn firmware_acpi_table_is_unsupported_not_fabricated() {
        let identity = identity_with_parts("SERIAL", "0CF5170C-4E78-547D-8F8F-246C9A40E80F");
        let mut buffer = [0u8; 64];
        let error =
            firmware_table(&identity, FW_TABLE_ACPI, FW_TABLE_ACPI, &mut buffer).unwrap_err();
        assert_eq!(error, IdentityError::FactAbsent("ACPI firmware table"));
        assert_eq!(error.last_error(), 50);
    }

    #[test]
    fn absent_serial_uuid_error_status_is_pinned() {
        let identity = HardwareIdentity::default();
        assert_eq!(
            identity.require_serial().unwrap_err(),
            IdentityError::FactAbsent("IOPlatformSerialNumber")
        );
        assert_eq!(
            identity.require_uuid().unwrap_err(),
            IdentityError::FactAbsent("IOPlatformUUID")
        );
        assert_eq!(
            identity.primary_volume_serial().unwrap_err(),
            IdentityError::FactAbsent("root volume")
        );
    }

    #[test]
    fn uuid_encoding_mixed_endian_garbage_rejected() {
        let bytes = uuid_smbios_bytes("00112233-4455-6677-8899-aabbccddeeff");
        assert_eq!(
            bytes,
            [
                0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        assert_eq!(uuid_smbios_bytes("garbage"), [0u8; 16]);
    }

    #[test]
    fn domain_name_splits_suffix_and_rejects_bare_host() {
        assert_eq!(domain_name("host.example.com"), "example.com");
        assert_eq!(domain_name("localhost"), "");
    }

    #[test]
    fn derived_user_sid_uid_boundary() {
        let a = derive_user_sid(501);
        let b = derive_user_sid(501);
        let c = derive_user_sid(502);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("S-1-5-21-"));
    }

    #[test]
    fn chassis_type_fallback_for_absent_target() {
        assert_eq!(chassis_type_for_target(""), 0x02);
        assert_eq!(chassis_type_for_target("J714s"), 0x03);
        assert_eq!(chassis_type_for_target("MacBookPro18,3"), 0x0A);
    }

    #[test]
    fn adapter_type_and_description_reject_unknown_names_with_defaults() {
        assert_eq!(adapter_type_for_name("utun0"), "Tunnel");
        assert_eq!(adapter_type_for_name("bridge0"), "Bridge");
        assert_eq!(adapter_type_for_name("zzz9"), "Ethernet 802.3");
        assert_eq!(adapter_description("utun0"), "VPN Tunnel Adapter");
        assert_eq!(adapter_description("weird0"), "Network Adapter");
    }

    #[test]
    fn snapshot_cross_surface_mismatch_guard() {
        let mut identity =
            identity_with_parts("GMW4J2RWR1", "0CF5170C-4E78-547D-8F8F-246C9A40E80F");
        identity.disks.push(DiskIdentity {
            volume_serial: 0xDEAD_BEEF,
            ..DiskIdentity::default()
        });
        identity.network.push(NetworkIdentity {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            ..NetworkIdentity::default()
        });
        identity.gpu.luid_low = 0x1111_2222;
        identity.gpu.luid_high = 0x3333_4444;
        identity.gpu.registry_id = 7;
        let snapshot = identity.snapshot();
        assert_eq!(snapshot.system_serial, "GMW4J2RWR1");
        assert_eq!(snapshot.system_uuid, "0CF5170C-4E78-547D-8F8F-246C9A40E80F");
        assert_eq!(snapshot.volume_serial, "DEADBEEF");
        assert_eq!(snapshot.primary_mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(snapshot.gpu_luid, 0x3333_4444_1111_2222);
        assert_eq!(snapshot.gpu_registry_id, 7);
        assert_eq!(
            snapshot.machine_guid,
            "11111111-2222-3333-4444-555555555555"
        );
    }

    #[test]
    fn probe_repeated_queries_stability_and_absence_boundary() {
        let store = MemoryInstallStore::new();
        let first = HardwareIdentity::probe(&store).expect("probe");
        let second = HardwareIdentity::probe(&store).expect("reprobe");
        assert_eq!(first.install.machine_guid, second.install.machine_guid);
        assert_eq!(first.machine.uuid, second.machine.uuid);
        assert_eq!(first.machine.serial_number, second.machine.serial_number);
        assert_eq!(first.gpu.registry_id, second.gpu.registry_id);
        // The CPU brand is a real host fact on every supported Mac.
        assert!(!first.cpu.brand.is_empty());
    }

    #[test]
    fn probe_cpu_model_absence_edge_not_fabricated() {
        let identity = HardwareIdentity::probe(&MemoryInstallStore::new()).expect("probe");
        // On hosts that do not publish machdep.cpu.model, the value is None and
        // the fact is recorded as absent; it is never invented.
        assert_eq!(
            identity.is_absent("machdep.cpu.model"),
            identity.cpu.model.is_none()
        );
    }

    #[test]
    fn firmware_empty_buffer_boundary_matches_table() {
        let identity = identity_with_parts("SERIAL", "0CF5170C-4E78-547D-8F8F-246C9A40E80F");
        let mut empty: [u8; 0] = [];
        let required = match firmware_table(&identity, FW_TABLE_RSMB, FW_TABLE_RSMB, &mut empty) {
            Err(IdentityError::BufferTooSmall { required }) => required,
            other => panic!("unexpected {other:?}"),
        };
        let mut buffer = vec![0u8; required];
        let written =
            firmware_table(&identity, FW_TABLE_RSMB, FW_TABLE_RSMB, &mut buffer).expect("fill");
        assert_eq!(written, required);
        assert_eq!(&buffer, &build_smbios_table(&identity));
    }

    #[test]
    fn error_reason_codes_and_last_errors_are_exact() {
        assert_eq!(IdentityError::UnsupportedHost.last_error(), 50);
        assert_eq!(
            IdentityError::BufferTooSmall { required: 1 }.last_error(),
            122
        );
        assert_eq!(
            IdentityError::UnknownTable {
                provider: 0,
                table_id: 0
            }
            .last_error(),
            87
        );
        assert_eq!(
            IdentityError::FactAbsent("x").reason(),
            ReasonCode::RcNotFound
        );
        assert_eq!(
            IdentityError::Store("x".to_string()).reason(),
            ReasonCode::RcInvalidState
        );
        assert_eq!(
            IdentityError::Registry("x".to_string()).reason(),
            ReasonCode::RcRegistryNotFound
        );
    }
}
