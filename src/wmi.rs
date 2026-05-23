// wmi.rs — WMI (Windows Management Instrumentation) infrastructure
//
// Implements COM interfaces for WMI: IWbemLocator, IWbemServices,
// IWbemClassObject, IEnumWbemClassObject, and a WQL query parser.
//
// All WMI classes return macOS-equivalent values using system calls
// (sysctl, sw_vers, hostname, etc.).

use std::collections::HashMap;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;

// ============================================================================
// macOS System Info Query Helpers
// ============================================================================

/// Run a sysctl command and return the result as a trimmed string.
fn sysctl_value(name: &str) -> Option<String> {
    Command::new("/usr/sbin/sysctl")
        .arg("-n")
        .arg(name)
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            } else {
                None
            }
        })
}

/// Run a sysctl command and parse the result as u64.
fn sysctl_u64(name: &str) -> Option<u64> {
    sysctl_value(name).and_then(|s| s.parse::<u64>().ok())
}

/// Run a sysctl command and parse the result as u32.
fn sysctl_u32(name: &str) -> Option<u32> {
    sysctl_value(name).and_then(|s| s.parse::<u32>().ok())
}

/// Get total physical RAM in bytes.
fn total_physical_memory() -> u64 {
    sysctl_u64("hw.memsize").unwrap_or(8 * 1024 * 1024 * 1024) // default 8 GB
}

/// Get available RAM in bytes (approximate using vm_page_free_count).
fn available_physical_memory() -> u64 {
    // vm_page_free_count * page_size
    let page_size = sysctl_u64("hw.pagesize").unwrap_or(16384);
    let free_pages = sysctl_u64("vm.page_free_count").unwrap_or(0);
    let result = free_pages.saturating_mul(page_size);
    if result > 0 {
        result
    } else {
        // Fallback: report ~25% of total as free
        total_physical_memory() / 4
    }
}

/// Get physical CPU core count.
fn physical_cpu_count() -> u32 {
    sysctl_u32("hw.physicalcpu").unwrap_or(4)
}

/// Get logical CPU core count.
fn logical_cpu_count() -> u32 {
    sysctl_u32("hw.logicalcpu").unwrap_or(8)
}

/// Get hostname.
fn host_name() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "localhost".to_string())
}

/// Get macOS version string (e.g., "14.5").
fn os_version() -> String {
    Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "14.0".to_string())
}

/// Get macOS build number (e.g., "23F79").
fn os_build_number() -> String {
    Command::new("/usr/bin/sw_vers")
        .arg("-buildVersion")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "0".to_string())
}

/// Get current user name.
fn user_name() -> String {
    std::env::var("USER").unwrap_or_else(|_| "user".to_string())
}

/// Generate a macOS marketing name from version string.
fn os_marketing_name(version: &str) -> String {
    let major: u32 = version.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(14);
    match major {
        15 => "macOS Sequoia",
        14 => "macOS Sonoma",
        13 => "macOS Ventura",
        12 => "macOS Monterey",
        11 => "macOS Big Sur",
        10 => "macOS Catalina",
        _  => "macOS",
    }.to_string()
}

/// Get system boot time as DMTF datetime string.
fn boot_time_dmtf() -> String {
    // Use sysctl kern.boottime to get boot timestamp
    let boottime_str = sysctl_value("kern.boottime").unwrap_or_default();
    // Parse "{ sec = 123456, usec = 789 }" format
    let sec = boottime_str
        .split(|c: char| c == ',' || c == ' ' || c == '=')
        .filter_map(|s| {
            let s = s.trim();
            if s.starts_with(|c: char| c.is_ascii_digit()) {
                s.parse::<u64>().ok()
            } else {
                None
            }
        })
        .next()
        .unwrap_or_else(|| {
            // Fallback: current time minus 1 hour
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
            now.as_secs().saturating_sub(3600)
        });

    // Convert to DMTF datetime: YYYYMMDDHHMMSS.******±UUU
    let secs = sec as i64;
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Approximate date from days since epoch (1970-01-01)
    let mut year = 1970i64;
    let mut remaining_days = days;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u32;
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        month += 1;
    }
    let day = (remaining_days + 1) as u32;

    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}.000000+000",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

/// Get current time as DMTF datetime.
fn now_dmtf() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let total_secs = now.as_secs() as i64;
    let days = total_secs / 86400;
    let time_secs = total_secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    let mut year = 1970i64;
    let mut remaining = days;
    loop {
        let diy = if is_leap_year(year) { 366 } else { 365 };
        if remaining < diy { break; }
        remaining -= diy;
        year += 1;
    }
    let md = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u32;
    for &d in &md {
        if remaining < d { break; }
        remaining -= d;
        month += 1;
    }
    let day = (remaining + 1) as u32;

    // Timezone offset: UTC+0 for simplicity
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}.000000+000",
        year, month, day, hours, minutes, seconds
    )
}

/// Get current screen dimensions via macOS system_profiler or defaults.
fn screen_resolution() -> (u32, u32) {
    // Try using system_profiler for display info
    let output = Command::new("/usr/sbin/system_profiler")
        .args(["SPDisplaysDataType"])
        .output()
        .ok();
    if let Some(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(res) = trimmed.strip_prefix("Resolution: ") {
                let parts: Vec<&str> = res.split(" x ").collect();
                if parts.len() == 2 {
                    let w = parts[0].trim().parse::<u32>().unwrap_or(1920);
                    let h = parts[1].trim().parse::<u32>().unwrap_or(1080);
                    return (w, h);
                }
            }
        }
    }
    // Default to Retina-like resolution
    (1920, 1080)
}

// ============================================================================
// WMI Property Types
// ============================================================================

#[derive(Clone, Debug)]
pub enum WmiPropertyValue {
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Bool(bool),
    String(String),
    Float(f64),
    DateTime(String), // DMTF format
    Array(Vec<WmiPropertyValue>),
    Object(Box<WmiObject>),
    Null,
}

impl Default for WmiPropertyValue {
    fn default() -> Self {
        WmiPropertyValue::Null
    }
}

/// A WMI object instance with property bag.
#[derive(Clone, Debug, Default)]
pub struct WmiObject {
    pub class_name: String,
    pub properties: HashMap<String, WmiPropertyValue>,
    pub keys: Vec<String>,
}

impl WmiObject {
    pub fn new(class_name: &str) -> Self {
        Self {
            class_name: class_name.to_string(),
            properties: HashMap::new(),
            keys: Vec::new(),
        }
    }

    pub fn set<K: Into<String>, V: Into<WmiPropertyValue>>(&mut self, key: K, value: V) -> &mut Self {
        self.properties.insert(key.into(), value.into());
        self
    }

    pub fn get(&self, key: &str) -> Option<&WmiPropertyValue> {
        self.properties.get(key)
    }

    pub fn get_string(&self, key: &str) -> Option<String> {
        match self.properties.get(key)? {
            WmiPropertyValue::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    pub fn get_u32(&self, key: &str) -> Option<u32> {
        match self.properties.get(key)? {
            WmiPropertyValue::Uint32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        match self.properties.get(key)? {
            WmiPropertyValue::Uint64(v) => Some(*v),
            _ => None,
        }
    }
}

impl From<String> for WmiPropertyValue {
    fn from(s: String) -> Self { WmiPropertyValue::String(s) }
}

impl From<&str> for WmiPropertyValue {
    fn from(s: &str) -> Self { WmiPropertyValue::String(s.to_string()) }
}

impl From<u32> for WmiPropertyValue {
    fn from(v: u32) -> Self { WmiPropertyValue::Uint32(v) }
}

impl From<u64> for WmiPropertyValue {
    fn from(v: u64) -> Self { WmiPropertyValue::Uint64(v) }
}

impl From<i32> for WmiPropertyValue {
    fn from(v: i32) -> Self { WmiPropertyValue::Int32(v) }
}

impl From<bool> for WmiPropertyValue {
    fn from(v: bool) -> Self { WmiPropertyValue::Bool(v) }
}

impl From<u16> for WmiPropertyValue {
    fn from(v: u16) -> Self { WmiPropertyValue::Uint16(v) }
}

// ============================================================================
// WMI Class Provider Trait
// ============================================================================

/// WMI class provider — handles WQL queries for a specific class.
pub trait WmiClassProvider: Send + Sync {
    fn class_name(&self) -> &'static str;
    fn get_object(&self, key: &str, value: &str) -> Option<WmiObject>;
    fn exec_query(&self, _wql: &str) -> AppResult<Vec<WmiObject>> {
        self.enum_objects()
    }
    fn enum_objects(&self) -> AppResult<Vec<WmiObject>>;
}

// ============================================================================
// Win32_ComputerSystem Provider
// ============================================================================

pub struct Win32ComputerSystemProvider;

impl Win32ComputerSystemProvider {
    fn build_object(&self) -> WmiObject {
        let hostname = host_name();
        let total_ram = total_physical_memory();
        let logical = logical_cpu_count();
        let username = user_name();
        let domain = "".to_string();

        WmiObject::new("Win32_ComputerSystem")
            .set("Name", hostname.clone())
            .set("Manufacturer", "Apple Inc.")
            .set("Model", sysctl_value("hw.model").unwrap_or_else(|| "Mac".to_string()))
            .set("TotalPhysicalMemory", total_ram)
            .set("NumberOfProcessors", logical)
            .set("Domain", domain)
            .set("PrimaryOwnerName", username)
            .set("SystemType", "ARM64")
            .clone()
    }
}

impl WmiClassProvider for Win32ComputerSystemProvider {
    fn class_name(&self) -> &'static str {
        "Win32_ComputerSystem"
    }

    fn get_object(&self, _key: &str, value: &str) -> Option<WmiObject> {
        let obj = self.build_object();
        if obj.get_string("Name").as_deref() == Some(value) {
            Some(obj)
        } else {
            None
        }
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        Ok(vec![self.build_object()])
    }
}

// ============================================================================
// Win32_Processor Provider
// ============================================================================

pub struct Win32ProcessorProvider;

impl Win32ProcessorProvider {
    fn build_object(&self) -> WmiObject {
        let physical = physical_cpu_count();
        let logical = logical_cpu_count();
        let freq = sysctl_u32("hw.cpufrequency").unwrap_or(3200);

        WmiObject::new("Win32_Processor")
            .set("Name", "Apple Silicon")
            .set("NumberOfCores", physical)
            .set("NumberOfLogicalProcessors", logical)
            .set("MaxClockSpeed", freq)
            .set("Architecture", 9u16) // 9 = x64
            .set("ProcessorId", "ARM64")
            .set("Manufacturer", "Apple")
            .set("Description", "Apple Silicon Processor")
            .clone()
    }
}

impl WmiClassProvider for Win32ProcessorProvider {
    fn class_name(&self) -> &'static str {
        "Win32_Processor"
    }

    fn get_object(&self, _key: &str, _value: &str) -> Option<WmiObject> {
        Some(self.build_object())
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        Ok((0..physical_cpu_count()).map(|_| self.build_object()).collect())
    }
}

// ============================================================================
// Win32_OperatingSystem Provider
// ============================================================================

pub struct Win32OperatingSystemProvider;

impl Win32OperatingSystemProvider {
    fn build_object(&self) -> WmiObject {
        let version = os_version();
        let build = os_build_number();
        let marketing = os_marketing_name(&version);
        let total_ram_kb = total_physical_memory() / 1024;
        let avail_ram_kb = available_physical_memory() / 1024;
        let hostname = host_name();

        WmiObject::new("Win32_OperatingSystem")
            .set("Caption", format!("{} {}", marketing, version))
            .set("Version", version)
            .set("BuildNumber", build.clone())
            .set("BuildType", "Release")
            .set("OSArchitecture", "ARM64")
            .set("TotalVisibleMemorySize", total_ram_kb as u64)
            .set("FreePhysicalMemory", avail_ram_kb as u64)
            .set("FreeVirtualMemory", avail_ram_kb as u64)
            .set("TotalVirtualMemorySize", (total_ram_kb + 2_097_152) as u64) // ~2 GB page file
            .set("LastBootUpTime", WmiPropertyValue::DateTime(boot_time_dmtf()))
            .set("CSName", hostname)
            .set("RegisteredUser", user_name())
            .set("SerialNumber", "00000-00000-00000-00000")
            .set("Organization", "")
            .set("CountryCode", "1")
            .set("CurrentTimeZone", -420i32) // UTC-7 in minutes
            .set("NumberOfUsers", 1u32)
            .set("NumberOfProcesses", 512u32)
            .set("ServicePackMajorVersion", 0u16)
            .set("ServicePackMinorVersion", 0u16)
            .set("SuiteMask", 0x0100u16) // VER_SUITE_SINGLEUSERTS
            .set("ProductType", 1u32) // VER_NT_WORKSTATION
            .clone()
    }
}

impl WmiClassProvider for Win32OperatingSystemProvider {
    fn class_name(&self) -> &'static str {
        "Win32_OperatingSystem"
    }

    fn get_object(&self, _key: &str, value: &str) -> Option<WmiObject> {
        let obj = self.build_object();
        if obj.get_string("CSName").as_deref() == Some(value) {
            Some(obj)
        } else {
            None
        }
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        Ok(vec![self.build_object()])
    }
}

// ============================================================================
// Win32_VideoController Provider
// ============================================================================

pub struct Win32VideoControllerProvider;

impl Win32VideoControllerProvider {
    fn build_object(&self) -> WmiObject {
        let (width, height) = screen_resolution();

        // Try to get GPU info from system_profiler
        let gpu_name = Self::get_gpu_name();
        let vram_bytes = Self::get_vram_bytes();

        WmiObject::new("Win32_VideoController")
            .set("Name", gpu_name.clone())
            .set("AdapterRAM", vram_bytes)
            .set("DriverVersion", "1.0")
            .set("VideoProcessor", "Apple Graphics")
            .set("VideoArchitecture", 1u16) // VGA
            .set("VideoMemoryType", 2u16)  // VRAM
            .set("CurrentHorizontalResolution", width)
            .set("CurrentVerticalResolution", height)
            .set("CurrentRefreshRate", 60u32)
            .set("MaxRefreshRate", 120u32)
            .set("MinRefreshRate", 30u32)
            .set("Status", "OK")
            .set("Description", gpu_name)
            .clone()
    }

    fn get_gpu_name() -> String {
        let output = Command::new("/usr/sbin/system_profiler")
            .args(["SPDisplaysDataType"])
            .output()
            .ok();
        if let Some(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(name) = trimmed.strip_prefix("Chipset Model: ") {
                    return name.trim().to_string();
                }
            }
        }
        "Apple GPU".to_string()
    }

    fn get_vram_bytes() -> u64 {
        let output = Command::new("/usr/sbin/system_profiler")
            .args(["SPDisplaysDataType"])
            .output()
            .ok();
        if let Some(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(vram) = trimmed.strip_prefix("VRAM (Total): ") {
                    // e.g., "VRAM (Total): 10 GB" or "VRAM (Total): 1536 MB"
                    let vram = vram.trim();
                    if let Some(gb) = vram.strip_suffix(" GB") {
                        if let Ok(n) = gb.trim().parse::<u64>() {
                            return n * 1024 * 1024 * 1024;
                        }
                    }
                    if let Some(mb) = vram.strip_suffix(" MB") {
                        if let Ok(n) = mb.trim().parse::<u64>() {
                            return n * 1024 * 1024;
                        }
                    }
                }
            }
        }
        // Default: 2 GB
        2 * 1024 * 1024 * 1024
    }
}

impl WmiClassProvider for Win32VideoControllerProvider {
    fn class_name(&self) -> &'static str {
        "Win32_VideoController"
    }

    fn get_object(&self, _key: &str, _value: &str) -> Option<WmiObject> {
        Some(self.build_object())
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        Ok(vec![self.build_object()])
    }
}

// ============================================================================
// Win32_DiskDrive Provider
// ============================================================================

pub struct Win32DiskDriveProvider;

impl Win32DiskDriveProvider {
    fn build_object(&self) -> WmiObject {
        // Try to get disk info from system_profiler or diskutil
        let (model, size_bytes, interface, partitions) = Self::get_disk_info();

        WmiObject::new("Win32_DiskDrive")
            .set("Model", model)
            .set("Size", size_bytes)
            .set("InterfaceType", interface)
            .set("MediaType", "Fixed hard disk media")
            .set("Partitions", partitions)
            .set("Caption", "APPLE SSD")
            .set("Status", "OK")
            .set("BytesPerSector", 512u32)
            .set("SectorsPerTrack", 63u32)
            .set("TotalHeads", 255u32)
            .set("TotalCylinders", 16383u32)
            .set("TracksPerCylinder", 255u32)
            .clone()
    }

    fn get_disk_info() -> (String, u64, String, u32) {
        // Try using diskutil
        let output = Command::new("/usr/sbin/diskutil")
            .args(["info", "/"])
            .output()
            .ok();
        if let Some(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut model = "APPLE SSD".to_string();
            let mut size: u64 = 256 * 1024 * 1024 * 1024; // 256 GB default
            let mut partitions = 2u32;

            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(m) = trimmed.strip_prefix("Device / Media Name:") {
                    model = format!("APPLE SSD {}", m.trim());
                }
                if let Some(s) = trimmed.strip_prefix("Disk Size:") {
                    // Parse "256.0 GB (256000000000 Bytes)" or similar
                    let s = s.trim();
                    if let Some(bytes_str) = s.split('(').nth(1) {
                        if let Some(bytes) = bytes_str.split_whitespace().next() {
                            if let Ok(b) = bytes.replace(',', "").parse::<u64>() {
                                size = b;
                            }
                        }
                    }
                }
                if trimmed.contains("Partition") || trimmed.contains("Synthetic") {
                    // Count partitions roughly
                }
            }

            return (model, size, "NVMe".to_string(), partitions);
        }

        // Fallback using sysctl
        let size = sysctl_u64("hw.disk0.size").unwrap_or(256 * 1024 * 1024 * 1024);
        ("APPLE SSD".to_string(), size, "NVMe".to_string(), 2)
    }
}

impl WmiClassProvider for Win32DiskDriveProvider {
    fn class_name(&self) -> &'static str {
        "Win32_DiskDrive"
    }

    fn get_object(&self, _key: &str, _value: &str) -> Option<WmiObject> {
        Some(self.build_object())
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        Ok(vec![self.build_object()])
    }
}

// ============================================================================
// Win32_NetworkAdapter Provider
// ============================================================================

pub struct Win32NetworkAdapterProvider;

impl Win32NetworkAdapterProvider {
    fn build_objects(&self) -> Vec<WmiObject> {
        let mut objects = Vec::new();

        // Loopback adapter
        objects.push(
            WmiObject::new("Win32_NetworkAdapter")
                .set("Name", "Loopback Adapter")
                .set("MACAddress", "00:00:00:00:00:00")
                .set("IPEnabled", false)
                .set("NetConnectionStatus", 0u32) // Disconnected
                .set("AdapterType", "Loopback")
                .set("Description", "Software Loopback Interface")
                .set("Speed", 1000000000u64) // 1 Gbps
                .set("Manufacturer", "Microsoft")
                .set("NetEnabled", false)
                .set("Index", 0u32)
                .clone()
        );

        // Try to get active network interfaces
        let output = Command::new("/sbin/ifconfig")
            .output()
            .ok();
        if let Some(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut current_iface: Option<String> = None;
            let mut current_mac: Option<String> = None;
            let mut current_ips: Vec<String> = Vec::new();
            let mut is_up = false;

            for line in text.lines() {
                if line.is_empty() {
                    if let Some(name) = current_iface.take() {
                        if name != "lo0" && !name.starts_with("gif") && !name.starts_with("stf")
                            && !name.starts_with("awdl") && !name.starts_with("llw")
                        {
                            let ip_enabled = !current_ips.is_empty();
                            objects.push(
                                WmiObject::new("Win32_NetworkAdapter")
                                    .set("Name", name.clone())
                                    .set("MACAddress", current_mac.clone().unwrap_or_else(|| "00:00:00:00:00:00".to_string()))
                                    .set("IPEnabled", ip_enabled)
                                    .set("IPAddress", WmiPropertyValue::Array(
                                        current_ips.iter().map(|ip| WmiPropertyValue::String(ip.clone())).collect()
                                    ))
                                    .set("NetConnectionStatus", if ip_enabled { 2u32 } else { 0u32 }) // 2=connected
                                    .set("AdapterType", "Ethernet 802.3")
                                    .set("Description", name)
                                    .set("Speed", 1000000000u64)
                                    .set("Manufacturer", "Apple")
                                    .set("NetEnabled", is_up)
                                    .set("Index", objects.len() as u32)
                                    .clone()
                            );
                        }
                    }
                    current_ips.clear();
                    current_mac = None;
                    is_up = false;
                    continue;
                }

                let trimmed = line.trim();
                if !trimmed.starts_with('\t') && !trimmed.starts_with(' ') {
                    // Interface name line
                    let name = trimmed.split(':').next().unwrap_or("").to_string();
                    current_iface = Some(name);
                    is_up = trimmed.contains("UP");
                } else if trimmed.starts_with("ether ") {
                    let mac = trimmed.trim_start_matches("ether ").trim().to_string();
                    current_mac = Some(mac);
                } else if trimmed.starts_with("inet ") {
                    let ip = trimmed.trim_start_matches("inet ").split_whitespace().next().unwrap_or("").to_string();
                    if !ip.is_empty() {
                        current_ips.push(ip);
                    }
                }
            }
        }

        objects
    }
}

impl WmiClassProvider for Win32NetworkAdapterProvider {
    fn class_name(&self) -> &'static str {
        "Win32_NetworkAdapter"
    }

    fn get_object(&self, key: &str, value: &str) -> Option<WmiObject> {
        for obj in self.build_objects() {
            match key {
                "Name" => {
                    if obj.get_string("Name").as_deref() == Some(value) {
                        return Some(obj);
                    }
                }
                "MACAddress" => {
                    if obj.get_string("MACAddress").as_deref() == Some(value) {
                        return Some(obj);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        Ok(self.build_objects())
    }
}

// ============================================================================
// Win32_BIOS Provider
// ============================================================================

pub struct Win32BiosProvider;

impl Win32BiosProvider {
    fn build_object(&self) -> WmiObject {
        // Try to get boot ROM version
        let boot_args = sysctl_value("kern.bootargs").unwrap_or_default();
        let version = if boot_args.is_empty() {
            "APPLE  - 1.0".to_string()
        } else {
            format!("APPLE Boot ROM - {}", boot_args)
        };

        WmiObject::new("Win32_BIOS")
            .set("Name", "Apple Boot ROM")
            .set("Version", version)
            .set("Manufacturer", "Apple Inc.")
            .set("ReleaseDate", WmiPropertyValue::DateTime("20230101000000.000000+000".to_string()))
            .set("Status", "OK")
            .set("SerialNumber", "000000000000")
            .set("SMBIOSBIOSVersion", "1.0")
            .set("PrimaryBIOS", true)
            .clone()
    }
}

impl WmiClassProvider for Win32BiosProvider {
    fn class_name(&self) -> &'static str {
        "Win32_BIOS"
    }

    fn get_object(&self, _key: &str, _value: &str) -> Option<WmiObject> {
        Some(self.build_object())
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        Ok(vec![self.build_object()])
    }
}

// ============================================================================
// Win32_LogicalDisk Provider
// ============================================================================

pub struct Win32LogicalDiskProvider;

impl Win32LogicalDiskProvider {
    fn build_object(&self) -> WmiObject {
        let (total_bytes, free_bytes, volume_name) = Self::get_disk_space();

        WmiObject::new("Win32_LogicalDisk")
            .set("DeviceID", "C:")
            .set("DriveType", 3u32) // DRIVE_FIXED
            .set("Size", total_bytes)
            .set("FreeSpace", free_bytes)
            .set("VolumeName", volume_name)
            .set("VolumeSerialNumber", "00000000")
            .set("FileSystem", "APFS")
            .set("Compressed", false)
            .set("SupportsDiskQuotas", false)
            .set("SupportsFileBasedCompression", false)
            .set("MaximumComponentLength", 255u32)
            .set("MediaType", 12u32) // Fixed hard disk
            .clone()
    }

    fn get_disk_space() -> (u64, u64, String) {
        // Try using diskutil
        let output = Command::new("/usr/sbin/diskutil")
            .args(["info", "/"])
            .output()
            .ok();
        if let Some(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut total: u64 = 512 * 1024 * 1024 * 1024; // 512 GB default
            let mut free: u64 = 256 * 1024 * 1024 * 1024; // 256 GB default
            let mut name = "Macintosh HD".to_string();

            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(s) = trimmed.strip_prefix("Disk Size:") {
                    let s = s.trim();
                    if let Some(bytes_str) = s.split('(').nth(1) {
                        if let Some(bytes) = bytes_str.split_whitespace().next() {
                            if let Ok(b) = bytes.replace(',', "").parse::<u64>() {
                                total = b;
                            }
                        }
                    }
                }
                if let Some(s) = trimmed.strip_prefix("Volume Free Space:") {
                    let s = s.trim();
                    if let Some(bytes_str) = s.split('(').nth(1) {
                        if let Some(bytes) = bytes_str.split_whitespace().next() {
                            if let Ok(b) = bytes.replace(',', "").parse::<u64>() {
                                free = b;
                            }
                        }
                    }
                }
                if let Some(n) = trimmed.strip_prefix("Volume Name:") {
                    name = n.trim().to_string();
                }
            }
            return (total, free, name);
        }

        // Fallback using statfs or defaults
        (512 * 1024 * 1024 * 1024, 256 * 1024 * 1024 * 1024, "Macintosh HD".to_string())
    }
}

impl WmiClassProvider for Win32LogicalDiskProvider {
    fn class_name(&self) -> &'static str {
        "Win32_LogicalDisk"
    }

    fn get_object(&self, key: &str, value: &str) -> Option<WmiObject> {
        let obj = self.build_object();
        match key {
            "DeviceID" | "VolumeName" => {
                if obj.get_string(key).as_deref() == Some(value) {
                    Some(obj)
                } else {
                    None
                }
            }
            _ => Some(obj),
        }
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        Ok(vec![self.build_object()])
    }
}

// ============================================================================
// Win32_TimeZone Provider
// ============================================================================

pub struct Win32TimeZoneProvider;

impl Win32TimeZoneProvider {
    fn build_object(&self) -> WmiObject {
        let tz_name = sysctl_value("kern.timezone.name").unwrap_or_else(|| "UTC".to_string());

        WmiObject::new("Win32_TimeZone")
            .set("Caption", format!("(UTC+00:00) {}", tz_name))
            .set("StandardName", tz_name.clone())
            .set("DaylightName", format!("{} (Daylight)", tz_name))
            .set("Bias", 0i32)
            .set("DaylightBias", -60i32)
            .set("StandardBias", 0i32)
            .set("DaylightYear", 0u32)
            .set("StandardYear", 0u32)
            .clone()
    }
}

impl WmiClassProvider for Win32TimeZoneProvider {
    fn class_name(&self) -> &'static str {
        "Win32_TimeZone"
    }

    fn get_object(&self, _key: &str, _value: &str) -> Option<WmiObject> {
        Some(self.build_object())
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        Ok(vec![self.build_object()])
    }
}

// ============================================================================
// Win32_ComputerSystemProduct Provider
// ============================================================================

pub struct Win32ComputerSystemProductProvider;

impl Win32ComputerSystemProductProvider {
    fn build_object(&self) -> WmiObject {
        WmiObject::new("Win32_ComputerSystemProduct")
            .set("Name", "Mac")
            .set("IdentifyingNumber", "00000000000000000")
            .set("SKUNumber", "")
            .set("Vendor", "Apple Inc.")
            .set("Version", sysctl_value("hw.model").unwrap_or_else(|| "Mac".to_string()))
            .set("UUID", "00000000-0000-0000-0000-000000000000")
            .clone()
    }
}

impl WmiClassProvider for Win32ComputerSystemProductProvider {
    fn class_name(&self) -> &'static str {
        "Win32_ComputerSystemProduct"
    }

    fn get_object(&self, _key: &str, _value: &str) -> Option<WmiObject> {
        Some(self.build_object())
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        Ok(vec![self.build_object()])
    }
}

// ============================================================================
// WQL Query Parser
// ============================================================================

#[derive(Debug, Clone)]
pub struct WqlQuery {
    pub select_columns: Option<Vec<String>>, // None = SELECT *
    pub from_class: String,
    pub where_clause: Option<WqlWhereClause>,
}

#[derive(Debug, Clone)]
pub enum WqlWhereClause {
    Simple { property: String, op: WqlOp, value: String },
    And(Vec<WqlWhereClause>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum WqlOp {
    Eq, Neq, Lt, Le, Gt, Ge, Like,
}

impl WqlOp {
    fn from_str(s: &str) -> Option<WqlOp> {
        match s.to_uppercase().as_str() {
            "=" => Some(WqlOp::Eq),
            "!=" | "<>" => Some(WqlOp::Neq),
            "<" => Some(WqlOp::Lt),
            "<=" => Some(WqlOp::Le),
            ">" => Some(WqlOp::Gt),
            ">=" => Some(WqlOp::Ge),
            "LIKE" => Some(WqlOp::Like),
            _ => None,
        }
    }
}

/// Parse a WQL query string.
///
/// Supports:
/// - `SELECT * FROM Win32_Class`
/// - `SELECT col1, col2 FROM Win32_Class`
/// - `SELECT * FROM Win32_Class WHERE prop = 'value'`
/// - `SELECT * FROM Win32_Class WHERE prop LIKE '%pattern%'`
/// - `SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3`
pub fn parse_wql(query: &str) -> AppResult<WqlQuery> {
    let trimmed = query.trim();

    // Must start with SELECT (case-insensitive)
    let upper = trimmed.to_uppercase();
    if !upper.starts_with("SELECT") {
        return Err(AppError::new(
            ReasonCode::RcWmiParseError,
            format!("WQL query must start with SELECT: {}", query),
        ));
    }

    let after_select = trimmed[6..].trim();

    // Find FROM position
    let from_idx = after_select.to_uppercase().find("FROM").ok_or_else(|| {
        AppError::new(
            ReasonCode::RcWmiParseError,
            format!("WQL query missing FROM clause: {}", query),
        )
    })?;

    let columns_str = after_select[..from_idx].trim();
    let after_from = after_select[from_idx + 4..].trim();

    // Parse select columns
    let select_columns = if columns_str == "*" {
        None
    } else {
        Some(
            columns_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        )
    };

    // Find WHERE position
    let where_idx = after_from.to_uppercase().find("WHERE");
    let class_name = if let Some(idx) = where_idx {
        after_from[..idx].trim().to_string()
    } else {
        after_from.to_string()
    };

    if class_name.is_empty() {
        return Err(AppError::new(
            ReasonCode::RcWmiParseError,
            format!("WQL query missing class name: {}", query),
        ));
    }

    // Parse WHERE clause
    let where_clause = if let Some(idx) = where_idx {
        let where_str = after_from[idx + 5..].trim();
        Some(parse_where_clause(where_str)?)
    } else {
        None
    };

    Ok(WqlQuery {
        select_columns,
        from_class: class_name,
        where_clause,
    })
}

fn parse_where_clause(s: &str) -> AppResult<WqlWhereClause> {
    let trimmed = s.trim();

    // Check for AND
    let and_parts: Vec<&str> = split_by_and(trimmed);
    if and_parts.len() > 1 {
        let clauses: AppResult<Vec<WqlWhereClause>> = and_parts
            .into_iter()
            .map(parse_simple_condition)
            .collect();
        return Ok(WqlWhereClause::And(clauses?));
    }

    parse_simple_condition(trimmed)
}

fn split_by_and(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth: usize = 0;
    let mut start = 0;
    let upper = s.to_uppercase();
    let chars: Vec<char> = s.chars().collect();

    for (i, _) in chars.iter().enumerate() {
        if chars[i] == '(' { depth += 1; }
        if chars[i] == ')' { depth = depth.saturating_sub(1); }
        if depth == 0 && i + 3 < s.len() && &upper[i..i+3] == "AND" {
            // Make sure it's a word boundary
            let prev_is_boundary = i == 0 || chars[i-1] == ' ';
            let next_is_boundary = i + 3 >= s.len() || chars[i+3] == ' ';
            if prev_is_boundary && next_is_boundary {
                parts.push(s[start..i].trim());
                start = i + 3;
            }
        }
    }
    if start < s.len() {
        parts.push(s[start..].trim());
    }
    parts
}

fn parse_simple_condition(s: &str) -> AppResult<WqlWhereClause> {
    let trimmed = s.trim();

    // Try LIKE first (longest operator)
    let like_idx = trimmed.to_uppercase().find("LIKE");
    if let Some(idx) = like_idx {
        let before = trimmed[..idx].trim();
        let after = trimmed[idx + 4..].trim();
        if !before.is_empty() && !after.is_empty() {
            return Ok(WqlWhereClause::Simple {
                property: before.to_string(),
                op: WqlOp::Like,
                value: unquote(after),
            });
        }
    }

    // Try multi-char operators: !=, <>, <=, >=
    let operators = ["!=", "<>", "<=", ">="];
    for op_str in &operators {
        if let Some(idx) = trimmed.find(op_str) {
            let before = trimmed[..idx].trim();
            let after = trimmed[idx + op_str.len()..].trim();
            if !before.is_empty() && !after.is_empty() {
                if let Some(op) = WqlOp::from_str(op_str) {
                    if is_simple_property(before) {
                        return Ok(WqlWhereClause::Simple {
                            property: before.to_string(),
                            op,
                            value: unquote(after),
                        });
                    }
                }
            }
        }
    }

    // Try single-char operators: =, <, >
    let operators = ["=", "<", ">"];
    for op_str in &operators {
        if let Some(idx) = trimmed.find(op_str) {
            let before = trimmed[..idx].trim();
            let after = trimmed[idx + op_str.len()..].trim();
            if !before.is_empty() && !after.is_empty() {
                if let Some(op) = WqlOp::from_str(op_str) {
                    if is_simple_property(before) {
                        return Ok(WqlWhereClause::Simple {
                            property: before.to_string(),
                            op,
                            value: unquote(after),
                        });
                    }
                }
            }
        }
    }

    Err(AppError::new(
        ReasonCode::RcWmiParseError,
        format!("Cannot parse WHERE clause: {}", s),
    ))
}

fn is_simple_property(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn unquote(s: &str) -> String {
    let trimmed = s.trim();
    if (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with('"') && trimmed.ends_with('"'))
    {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

/// Evaluate a WHERE condition against a WmiObject.
pub fn evaluate_condition(obj: &WmiObject, clause: &WqlWhereClause) -> bool {
    match clause {
        WqlWhereClause::Simple { property, op, value } => {
            let prop_value = match obj.properties.get(property) {
                Some(v) => v,
                None => return false,
            };

            match op {
                WqlOp::Eq => values_equal(prop_value, value),
                WqlOp::Neq => !values_equal(prop_value, value),
                WqlOp::Like => values_like(prop_value, value),
                WqlOp::Gt => values_compare(prop_value, value) == std::cmp::Ordering::Greater,
                WqlOp::Ge => values_compare(prop_value, value) != std::cmp::Ordering::Less,
                WqlOp::Lt => values_compare(prop_value, value) == std::cmp::Ordering::Less,
                WqlOp::Le => values_compare(prop_value, value) != std::cmp::Ordering::Greater,
            }
        }
        WqlWhereClause::And(clauses) => {
            clauses.iter().all(|c| evaluate_condition(obj, c))
        }
    }
}

fn values_equal(prop: &WmiPropertyValue, value: &str) -> bool {
    match prop {
        WmiPropertyValue::String(s) => s.eq_ignore_ascii_case(value),
        WmiPropertyValue::Uint32(v) => value.parse::<u32>().map(|n| *v == n).unwrap_or(false),
        WmiPropertyValue::Uint64(v) => value.parse::<u64>().map(|n| *v == n).unwrap_or(false),
        WmiPropertyValue::Int32(v) => value.parse::<i32>().map(|n| *v == n).unwrap_or(false),
        WmiPropertyValue::Bool(v) => {
            value.eq_ignore_ascii_case("true") && *v
                || value.eq_ignore_ascii_case("false") && !*v
                || value.parse::<u32>().map(|n| (*v && n != 0) || (!*v && n == 0)).unwrap_or(false)
        }
        WmiPropertyValue::Uint16(v) => value.parse::<u16>().map(|n| *v == n).unwrap_or(false),
        _ => false,
    }
}

fn values_like(prop: &WmiPropertyValue, pattern: &str) -> bool {
    let prop_str = match prop {
        WmiPropertyValue::String(s) => s,
        WmiPropertyValue::Uint32(v) => return pattern.parse::<u32>().map(|p| *v == p).unwrap_or(false),
        _ => return false,
    };

    // Simple wildcard matching: % matches any sequence, _ matches single char
    let regex_pattern = pattern
        .replace('%', ".*")
        .replace('_', ".");

    if let Ok(re) = regex::Regex::new(&format!("^(?i){}$", regex_pattern)) {
        re.is_match(prop_str)
    } else {
        prop_str.eq_ignore_ascii_case(pattern.trim_matches('%'))
    }
}

fn values_compare(prop: &WmiPropertyValue, value: &str) -> std::cmp::Ordering {
    match prop {
        WmiPropertyValue::Uint32(v) => value.parse::<u32>().map(|n| (*v).cmp(&n)).unwrap_or(std::cmp::Ordering::Equal),
        WmiPropertyValue::Uint64(v) => value.parse::<u64>().map(|n| (*v).cmp(&n)).unwrap_or(std::cmp::Ordering::Equal),
        WmiPropertyValue::Int32(v) => value.parse::<i32>().map(|n| (*v).cmp(&n)).unwrap_or(std::cmp::Ordering::Equal),
        WmiPropertyValue::Uint16(v) => value.parse::<u16>().map(|n| (*v).cmp(&n)).unwrap_or(std::cmp::Ordering::Equal),
        WmiPropertyValue::String(s) => s.to_lowercase().cmp(&value.to_lowercase()),
        _ => std::cmp::Ordering::Equal,
    }
}

// ============================================================================
// WMI Service — orchestrates providers
// ============================================================================

/// Default WMI service with all standard providers registered.
pub fn create_default_wmi_service() -> WbemServices {
    let mut service = WbemServices::new();
    service.register(Box::new(Win32ComputerSystemProvider));
    service.register(Box::new(Win32ProcessorProvider));
    service.register(Box::new(Win32OperatingSystemProvider));
    service.register(Box::new(Win32VideoControllerProvider));
    service.register(Box::new(Win32DiskDriveProvider));
    service.register(Box::new(Win32NetworkAdapterProvider));
    service.register(Box::new(Win32BiosProvider));
    service.register(Box::new(Win32LogicalDiskProvider));
    service.register(Box::new(Win32TimeZoneProvider));
    service.register(Box::new(Win32ComputerSystemProductProvider));
    service
}

// ============================================================================
// IWbemLocator COM Interface
// ============================================================================

#[derive(Debug)]
pub struct WbemLocator {
    service: WbemServices,
}

impl WbemLocator {
    pub fn new() -> Self {
        Self {
            service: create_default_wmi_service(),
        }
    }

    /// ConnectServer — creates a WMI connection to the specified namespace.
    ///
    /// Standard namespace: `root\cimv2`
    pub fn connect_server(
        &self,
        server: Option<&str>,
        _user: Option<&str>,
        _password: Option<&str>,
        _locale: Option<&str>,
        _flags: u32,
        _authority: Option<&str>,
        namespace: Option<&str>,
    ) -> AppResult<WbemServices> {
        let namespace = namespace.unwrap_or("root\\cimv2");
        let server = server.unwrap_or("localhost");

        // We accept all connections and return our service
        eprintln!(
            "WbemLocator::ConnectServer(server={server:?}, namespace={namespace:?})"
        );

        Ok(self.service.clone())
    }
}

impl Default for WbemLocator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IWbemServices COM Interface
// ============================================================================

pub struct WbemServices {
    providers: HashMap<String, Box<dyn WmiClassProvider>>,
}

impl std::fmt::Debug for WbemServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WbemServices")
            .field("providers", &self.providers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Clone for WbemServices {
    fn clone(&self) -> Self {
        // WmiClassProvider is not cloneable; create a new empty services
        WbemServices {
            providers: HashMap::new(),
        }
    }
}

impl WbemServices {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn register(&mut self, provider: Box<dyn WmiClassProvider>) {
        let name = provider.class_name().to_string();
        self.providers.insert(name, provider);
    }

    /// Get a provider by class name.
    pub fn get_provider(&self, class_name: &str) -> Option<&dyn WmiClassProvider> {
        self.providers.get(class_name).map(|p| p.as_ref())
    }

    /// ExecQuery — execute a WQL query and return results.
    pub fn exec_query(&self, _query_format: &str, query: &str, _flags: u32) -> AppResult<Vec<WmiObject>> {
        eprintln!("WbemServices::ExecQuery(query={query:?})");

        let parsed = parse_wql(query)?;
        let provider = self.get_provider(&parsed.from_class).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWmiClassNotFound,
                format!("WMI class not found: {}", parsed.from_class),
            )
        })?;

        let objects = provider.exec_query(query)?;

        // Apply WHERE filter
        let filtered = if let Some(ref where_clause) = parsed.where_clause {
            objects.into_iter().filter(|obj| evaluate_condition(obj, where_clause)).collect()
        } else {
            objects
        };

        // Apply column projection
        let projected = if let Some(ref columns) = parsed.select_columns {
            filtered.into_iter().map(|obj| {
                let mut projected_obj = WmiObject::new(&obj.class_name);
                projected_obj.keys = obj.keys.clone();
                for col in columns {
                    if let Some(val) = obj.properties.get(col) {
                        projected_obj.properties.insert(col.clone(), val.clone());
                    }
                }
                projected_obj
            }).collect()
        } else {
            filtered
        };

        Ok(projected)
    }

    /// CreateInstanceEnum — enumerate all instances of a class.
    pub fn create_instance_enum(&self, class_name: &str, _flags: u32) -> AppResult<Vec<WmiObject>> {
        eprintln!("WbemServices::CreateInstanceEnum(class={class_name:?})");

        let provider = self.get_provider(class_name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWmiClassNotFound,
                format!("WMI class not found: {class_name}"),
            )
        })?;

        provider.enum_objects()
    }

    /// GetObject — retrieve a specific object by path.
    pub fn get_object(&self, object_path: &str, _flags: u32) -> AppResult<WmiObject> {
        eprintln!("WbemServices::GetObject(path={object_path:?})");

        // Parse object path: "Win32_ComputerSystem.Name='hostname'"
        let (class_name, key, value) = parse_object_path(object_path)?;

        let provider = self.get_provider(&class_name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWmiClassNotFound,
                format!("WMI class not found: {class_name}"),
            )
        })?;

        provider.get_object(&key, &value).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWmiObjectNotFound,
                format!("WMI object not found: {object_path}"),
            )
        })
    }
}

impl Default for WbemServices {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a WMI object path like "Win32_ComputerSystem.Name='hostname'"
fn parse_object_path(path: &str) -> AppResult<(String, String, String)> {
    let trimmed = path.trim();

    // Find the '.' separator between class name and key
    let dot_idx = trimmed.find('.').ok_or_else(|| {
        AppError::new(
            ReasonCode::RcWmiParseError,
            format!("Invalid object path (no '.' separator): {path}"),
        )
    })?;

    let class_name = trimmed[..dot_idx].trim().to_string();
    let key_part = trimmed[dot_idx + 1..].trim();

    let eq_idx = key_part.find('=').ok_or_else(|| {
        AppError::new(
            ReasonCode::RcWmiParseError,
            format!("Invalid object path (no '=' in key part): {path}"),
        )
    })?;

    let key = key_part[..eq_idx].trim().to_string();
    let value = unquote(&key_part[eq_idx + 1..]);

    Ok((class_name, key, value))
}

// ============================================================================
// IWbemClassObject COM Interface wrapper
// ============================================================================

#[derive(Debug, Clone)]
pub struct WbemClassObject {
    pub object: WmiObject,
}

impl WbemClassObject {
    pub fn new(object: WmiObject) -> Self {
        Self { object }
    }

    /// Get a property value. Returns (value_variant, type, flavor).
    pub fn get(&self, property_name: &str) -> Option<&WmiPropertyValue> {
        self.object.properties.get(property_name)
    }

    /// Set a property value.
    pub fn put(&mut self, property_name: &str, value: WmiPropertyValue) {
        self.object.properties.insert(property_name.to_string(), value);
    }

    /// Get all property names.
    pub fn get_names(&self) -> Vec<String> {
        self.object.properties.keys().cloned().collect()
    }

    /// Get the object as MOF-like text.
    pub fn get_object_text(&self) -> String {
        let mut text = format!("Instance of {}\n{{\n", self.object.class_name);
        let mut keys: Vec<&String> = self.object.properties.keys().collect();
        keys.sort();
        for key in keys {
            let val = &self.object.properties[key];
            text.push_str(&format!("    {} = {};\n", key, property_to_string(val)));
        }
        text.push('}');
        text
    }
}

fn property_to_string(val: &WmiPropertyValue) -> String {
    match val {
        WmiPropertyValue::String(s) => format!("\"{}\"", s),
        WmiPropertyValue::Uint32(v) => v.to_string(),
        WmiPropertyValue::Uint64(v) => v.to_string(),
        WmiPropertyValue::Int32(v) => v.to_string(),
        WmiPropertyValue::Uint16(v) => v.to_string(),
        WmiPropertyValue::Int16(v) => v.to_string(),
        WmiPropertyValue::Int64(v) => v.to_string(),
        WmiPropertyValue::Bool(v) => v.to_string(),
        WmiPropertyValue::Float(v) => v.to_string(),
        WmiPropertyValue::DateTime(s) => format!("\"{}\"", s),
        WmiPropertyValue::Null => "NULL".to_string(),
        WmiPropertyValue::Array(arr) => {
            let items: Vec<String> = arr.iter().map(property_to_string).collect();
            format!("{{ {} }}", items.join(", "))
        }
        WmiPropertyValue::Object(obj) => {
            format!("<Object: {}>", obj.class_name)
        }
    }
}

// ============================================================================
// IEnumWbemClassObject COM Interface
// ============================================================================

#[derive(Debug, Clone)]
pub struct EnumWbemObjects {
    objects: Vec<WbemClassObject>,
    position: usize,
}

impl EnumWbemObjects {
    pub fn new(objects: Vec<WbemClassObject>) -> Self {
        Self { objects, position: 0 }
    }

    pub fn from_wmi_objects(objects: Vec<WmiObject>) -> Self {
        Self {
            objects: objects.into_iter().map(WbemClassObject::new).collect(),
            position: 0,
        }
    }

    /// Return the next N objects.
    pub fn next(&mut self, count: u32) -> Vec<WbemClassObject> {
        let remaining = self.objects.len().saturating_sub(self.position);
        let take = (count as usize).min(remaining);
        let result: Vec<_> = self.objects[self.position..self.position + take].to_vec();
        self.position += take;
        result
    }

    /// Reset the enumeration to the beginning.
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Skip N objects. Returns the number actually skipped.
    pub fn skip(&mut self, count: u32) -> u32 {
        let remaining = self.objects.len().saturating_sub(self.position);
        let skip = (count as usize).min(remaining);
        self.position += skip;
        skip as u32
    }

    /// Clone the enumeration (preserving current position for both).
    pub fn clone_enum(&self) -> Self {
        Self {
            objects: self.objects.clone(),
            position: self.position,
        }
    }

    /// Total number of objects.
    pub fn count(&self) -> usize {
        self.objects.len()
    }

    /// Number of objects remaining.
    pub fn remaining(&self) -> usize {
        self.objects.len().saturating_sub(self.position)
    }
}

// ============================================================================
// Convenience — WMI COM interface as guest vtable thunks
// ============================================================================

/// The vtable layout for IWbemLocator:
/// [0] QueryInterface, [1] AddRef, [2] Release,
/// [3] ConnectServer
pub const WBEM_LOCATOR_VTABLE_COUNT: usize = 4;

/// The vtable layout for IWbemServices:
/// [0] QueryInterface, [1] AddRef, [2] Release,
/// [3] OpenNamespace, [4] CancelAsyncCall, [5] QueryObjectSink,
/// [6] GetObject, [7] PutInstance, [8] DeleteInstance,
/// [9] CreateInstanceEnum, [10] ExecQuery, [11] ExecNotificationQuery,
/// [12] ExecMethod
pub const WBEM_SERVICES_VTABLE_COUNT: usize = 13;

/// The vtable layout for IWbemClassObject:
/// [0] QueryInterface, [1] AddRef, [2] Release,
/// [3] GetFunction, [4] Get, [5] Put, [6] Delete, [7] GetNames,
/// [8] SetFieldValue, [9] BeginMethodEnum, [10] EndMethodEnum,
/// [11] NextMethod, [12] GetMethod, [13] GetMethodOrigin,
/// [14] GetMethodQualifierSet, [15] GetMethodParameterQualifierSet,
/// [16] GetPropertyQualifierSet, [17] Clone, [18] GetObjectText,
/// [19] SpawnDerivedClass, [20] SpawnInstance,
/// [21] CompareTo, [22] GetPropertyOrigin, [23] InheritsFrom,
/// [24] GetClassName, [25] IsMethod
pub const WBEM_CLASS_OBJECT_VTABLE_COUNT: usize = 26;

/// The vtable layout for IEnumWbemClassObject:
/// [0] QueryInterface, [1] AddRef, [2] Release,
/// [3] Next, [4] Skip, [5] Reset, [6] Clone,
/// [7] GetCount
pub const ENUM_WBEM_CLASS_OBJECT_VTABLE_COUNT: usize = 8;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wql_parse_simple() {
        let query = parse_wql("SELECT * FROM Win32_ComputerSystem").unwrap();
        assert!(query.select_columns.is_none());
        assert_eq!(query.from_class, "Win32_ComputerSystem");
        assert!(query.where_clause.is_none());
    }

    #[test]
    fn test_wql_parse_where() {
        let query = parse_wql("SELECT * FROM Win32_Processor WHERE Name = 'Apple Silicon'").unwrap();
        assert!(query.select_columns.is_none());
        assert_eq!(query.from_class, "Win32_Processor");
        assert!(query.where_clause.is_some());
        if let Some(WqlWhereClause::Simple { ref property, ref op, ref value }) = query.where_clause {
            assert_eq!(property, "Name");
            assert_eq!(*op, WqlOp::Eq);
            assert_eq!(value, "Apple Silicon");
        } else {
            panic!("Expected Simple where clause");
        }
    }

    #[test]
    fn test_wql_parse_select_columns() {
        let query = parse_wql("SELECT Name, Manufacturer FROM Win32_ComputerSystem").unwrap();
        assert_eq!(query.select_columns, Some(vec!["Name".to_string(), "Manufacturer".to_string()]));
        assert_eq!(query.from_class, "Win32_ComputerSystem");
        assert!(query.where_clause.is_none());
    }

    #[test]
    fn test_wql_parse_where_with_number() {
        let query = parse_wql("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3").unwrap();
        assert_eq!(query.from_class, "Win32_LogicalDisk");
        if let Some(WqlWhereClause::Simple { ref property, ref op, ref value }) = query.where_clause {
            assert_eq!(property, "DriveType");
            assert_eq!(*op, WqlOp::Eq);
            assert_eq!(value, "3");
        } else {
            panic!("Expected Simple where clause");
        }
    }

    #[test]
    fn test_wql_parse_like() {
        let query = parse_wql("SELECT * FROM Win32_ComputerSystem WHERE Name LIKE '%host%'").unwrap();
        assert_eq!(query.from_class, "Win32_ComputerSystem");
        if let Some(WqlWhereClause::Simple { ref property, ref op, ref value }) = query.where_clause {
            assert_eq!(property, "Name");
            assert_eq!(*op, WqlOp::Like);
            assert_eq!(value, "%host%");
        } else {
            panic!("Expected Simple where clause");
        }
    }

    #[test]
    fn test_wql_parse_and() {
        let query = parse_wql("SELECT * FROM Win32_Processor WHERE Name = 'Apple Silicon' AND Architecture = 9").unwrap();
        if let Some(WqlWhereClause::And(ref clauses)) = query.where_clause {
            assert_eq!(clauses.len(), 2);
        } else {
            panic!("Expected And where clause");
        }
    }

    #[test]
    fn test_win32_computersystem_properties() {
        let provider = Win32ComputerSystemProvider;
        let objects = provider.enum_objects().unwrap();
        assert_eq!(objects.len(), 1);
        let obj = &objects[0];
        assert_eq!(obj.class_name, "Win32_ComputerSystem");
        assert!(obj.get_string("Name").is_some());
        assert_eq!(obj.get_string("Manufacturer").as_deref(), Some("Apple Inc."));
        assert!(obj.get_u64("TotalPhysicalMemory").unwrap() > 0);
        assert!(obj.get_u32("NumberOfProcessors").unwrap() > 0);
        assert!(obj.get_string("PrimaryOwnerName").is_some());
    }

    #[test]
    fn test_win32_processor_properties() {
        let provider = Win32ProcessorProvider;
        let objects = provider.enum_objects().unwrap();
        assert!(!objects.is_empty());
        let obj = &objects[0];
        assert_eq!(obj.class_name, "Win32_Processor");
        assert_eq!(obj.get_string("Name").as_deref(), Some("Apple Silicon"));
        assert!(obj.get_u32("NumberOfCores").unwrap() > 0);
        assert!(obj.get_u32("NumberOfLogicalProcessors").unwrap() > 0);
        assert!(obj.get_u32("MaxClockSpeed").unwrap() > 0);
        assert_eq!(obj.get_u16("Architecture"), Some(9));
    }

    #[test]
    fn test_win32_operatingsystem_properties() {
        let provider = Win32OperatingSystemProvider;
        let objects = provider.enum_objects().unwrap();
        assert_eq!(objects.len(), 1);
        let obj = &objects[0];
        assert_eq!(obj.class_name, "Win32_OperatingSystem");
        assert!(obj.get_string("Caption").unwrap().contains("macOS"));
        assert!(obj.get_string("BuildNumber").is_some());
        assert_eq!(obj.get_string("OSArchitecture").as_deref(), Some("ARM64"));
        assert!(obj.get_u64("TotalVisibleMemorySize").unwrap() > 0);
        assert!(obj.get_u64("FreePhysicalMemory").unwrap() > 0);
    }

    #[test]
    fn test_win32_videocontroller_properties() {
        let provider = Win32VideoControllerProvider;
        let objects = provider.enum_objects().unwrap();
        assert_eq!(objects.len(), 1);
        let obj = &objects[0];
        assert!(obj.get_string("Name").is_some());
        assert!(obj.get_u64("AdapterRAM").unwrap() > 0);
        assert!(obj.get_u32("CurrentHorizontalResolution").unwrap() > 0);
        assert!(obj.get_u32("CurrentVerticalResolution").unwrap() > 0);
    }

    #[test]
    fn test_win32_diskdrive_properties() {
        let provider = Win32DiskDriveProvider;
        let objects = provider.enum_objects().unwrap();
        assert_eq!(objects.len(), 1);
        let obj = &objects[0];
        assert!(obj.get_string("Model").is_some());
        assert_eq!(obj.get_string("MediaType").as_deref(), Some("Fixed hard disk media"));
        assert!(obj.get_u64("Size").unwrap() > 0);
    }

    #[test]
    fn test_win32_bios_properties() {
        let provider = Win32BiosProvider;
        let objects = provider.enum_objects().unwrap();
        assert_eq!(objects.len(), 1);
        let obj = &objects[0];
        assert_eq!(obj.get_string("Manufacturer").as_deref(), Some("Apple Inc."));
        assert!(obj.get_string("Version").is_some());
    }

    #[test]
    fn test_win32_logicaldisk_properties() {
        let provider = Win32LogicalDiskProvider;
        let objects = provider.enum_objects().unwrap();
        assert_eq!(objects.len(), 1);
        let obj = &objects[0];
        assert_eq!(obj.get_string("DeviceID").as_deref(), Some("C:"));
        assert_eq!(obj.get_u32("DriveType"), Some(3));
        assert!(obj.get_u64("Size").unwrap() > 0);
    }

    #[test]
    fn test_win32_networkadapter_properties() {
        let provider = Win32NetworkAdapterProvider;
        let objects = provider.enum_objects().unwrap();
        assert!(!objects.is_empty());
        // At least a loopback adapter
        assert!(objects.iter().any(|o| o.get_string("Name").as_deref() == Some("Loopback Adapter")));
    }

    #[test]
    fn test_wbem_locator_connect() {
        let locator = WbemLocator::new();
        let service = locator.connect_server(None, None, None, None, 0, None, Some("root\\cimv2")).unwrap();
        // Verify the service works
        let objects = service.exec_query("WQL", "SELECT * FROM Win32_ComputerSystem", 0).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].class_name, "Win32_ComputerSystem");
    }

    #[test]
    fn test_wbem_services_query() {
        let service = create_default_wmi_service();
        let objects = service.exec_query("WQL", "SELECT * FROM Win32_Processor", 0).unwrap();
        assert!(!objects.is_empty());
        assert_eq!(objects[0].class_name, "Win32_Processor");
    }

    #[test]
    fn test_wbem_services_query_with_where() {
        let service = create_default_wmi_service();
        let objects = service.exec_query("WQL", "SELECT * FROM Win32_Processor WHERE Name = 'Apple Silicon'", 0).unwrap();
        assert!(!objects.is_empty());
    }

    #[test]
    fn test_wbem_services_query_select_columns() {
        let service = create_default_wmi_service();
        let objects = service.exec_query("WQL", "SELECT Name, Manufacturer FROM Win32_ComputerSystem", 0).unwrap();
        assert_eq!(objects.len(), 1);
        let obj = &objects[0];
        assert!(obj.get_string("Name").is_some());
        assert!(obj.get_string("Manufacturer").is_some());
        // TotalPhysicalMemory should not be in projected result
        assert!(obj.get_u64("TotalPhysicalMemory").is_none());
    }

    #[test]
    fn test_wbem_class_object_get() {
        let service = create_default_wmi_service();
        let objects = service.exec_query("WQL", "SELECT * FROM Win32_ComputerSystem", 0).unwrap();
        assert_eq!(objects.len(), 1);
        let class_obj = WbemClassObject::new(objects[0].clone());
        assert!(class_obj.get("Name").is_some());
        assert!(class_obj.get("Manufacturer").is_some());
        assert!(class_obj.get("TotalPhysicalMemory").is_some());
    }

    #[test]
    fn test_wbem_class_object_put() {
        let obj = WmiObject::new("Win32_Test");
        let mut class_obj = WbemClassObject::new(obj);
        class_obj.put("TestProperty", WmiPropertyValue::String("test_value".to_string()));
        assert_eq!(
            class_obj.get("TestProperty").map(|v| match v {
                WmiPropertyValue::String(s) => s.as_str(),
                _ => "",
            }),
            Some("test_value")
        );
    }

    #[test]
    fn test_wbem_class_object_get_names() {
        let service = create_default_wmi_service();
        let objects = service.exec_query("WQL", "SELECT * FROM Win32_ComputerSystem", 0).unwrap();
        let class_obj = WbemClassObject::new(objects[0].clone());
        let names = class_obj.get_names();
        assert!(names.contains(&"Name".to_string()));
        assert!(names.contains(&"Manufacturer".to_string()));
    }

    #[test]
    fn test_wbem_enum_next() {
        let service = create_default_wmi_service();
        let objects = service.exec_query("WQL", "SELECT * FROM Win32_Processor", 0).unwrap();
        let mut enum_objs = EnumWbemObjects::from_wmi_objects(objects);
        let count = enum_objs.count();
        assert!(count > 0);

        // Get first item
        let first_batch = enum_objs.next(1);
        assert_eq!(first_batch.len(), 1);

        // Reset and get all
        enum_objs.reset();
        let all = enum_objs.next(count as u32);
        assert_eq!(all.len(), count);

        // Skip
        enum_objs.reset();
        let skipped = enum_objs.skip(1);
        assert_eq!(skipped, 1);
        assert_eq!(enum_objs.remaining(), count.saturating_sub(1));
    }

    #[test]
    fn test_wbem_enum_clone() {
        let service = create_default_wmi_service();
        let objects = service.exec_query("WQL", "SELECT * FROM Win32_Processor", 0).unwrap();
        let enum_objs = EnumWbemObjects::from_wmi_objects(objects);
        let cloned = enum_objs.clone_enum();
        assert_eq!(cloned.count(), enum_objs.count());
    }

    #[test]
    fn test_create_instance_enum() {
        let service = create_default_wmi_service();
        let objects = service.create_instance_enum("Win32_OperatingSystem", 0).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].class_name, "Win32_OperatingSystem");
    }

    #[test]
    fn test_get_object_by_path() {
        let service = create_default_wmi_service();
        let hostname = host_name();
        let path = format!("Win32_ComputerSystem.Name='{hostname}'");
        let obj = service.get_object(&path, 0).unwrap();
        assert_eq!(obj.class_name, "Win32_ComputerSystem");
    }

    #[test]
    fn test_object_text() {
        let obj = WmiObject::new("Win32_Test")
            .set("Name", "test")
            .set("Value", 42u32)
            .clone();
        let class_obj = WbemClassObject::new(obj);
        let text = class_obj.get_object_text();
        assert!(text.contains("Instance of Win32_Test"));
        assert!(text.contains("Name = \"test\""));
        assert!(text.contains("Value = 42"));
    }

    #[test]
    fn test_parse_object_path() {
        let (class, key, value) = parse_object_path("Win32_ComputerSystem.Name='MyPC'").unwrap();
        assert_eq!(class, "Win32_ComputerSystem");
        assert_eq!(key, "Name");
        assert_eq!(value, "MyPC");
    }

    #[test]
    fn test_wql_parse_error() {
        let result = parse_wql("NOT A WQL QUERY");
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_condition() {
        let mut obj = WmiObject::new("Win32_Test");
        obj.set("Name", "TestMachine");
        obj.set("Value", 42u32);

        // Test Eq
        let clause = WqlWhereClause::Simple {
            property: "Name".to_string(),
            op: WqlOp::Eq,
            value: "TestMachine".to_string(),
        };
        assert!(evaluate_condition(&obj, &clause));

        // Test Neq
        let clause = WqlWhereClause::Simple {
            property: "Name".to_string(),
            op: WqlOp::Neq,
            value: "Other".to_string(),
        };
        assert!(evaluate_condition(&obj, &clause));

        // Test numeric comparison
        let clause = WqlWhereClause::Simple {
            property: "Value".to_string(),
            op: WqlOp::Gt,
            value: "10".to_string(),
        };
        assert!(evaluate_condition(&obj, &clause));

        let clause = WqlWhereClause::Simple {
            property: "Value".to_string(),
            op: WqlOp::Lt,
            value: "100".to_string(),
        };
        assert!(evaluate_condition(&obj, &clause));
    }

    #[test]
    fn test_sysctl_helpers() {
        // Test that sysctl functions work on macOS
        let mem = total_physical_memory();
        assert!(mem > 0, "Total physical memory should be > 0");

        let phys = physical_cpu_count();
        assert!(phys > 0, "Physical CPU count should be > 0");

        let log = logical_cpu_count();
        assert!(log > 0, "Logical CPU count should be > 0");
        assert!(log >= phys, "Logical cores >= physical cores");

        let host = host_name();
        assert!(!host.is_empty(), "Hostname should not be empty");

        let user = user_name();
        assert!(!user.is_empty(), "Username should not be empty");

        let os_ver = os_version();
        assert!(!os_ver.is_empty(), "OS version should not be empty");

        let build = os_build_number();
        assert!(!build.is_empty(), "Build number should not be empty");
    }

    /// Helper to get u16 from WmiPropertyValue
    trait WmiObjectExt {
        fn get_u16(&self, key: &str) -> Option<u16>;
    }

    impl WmiObjectExt for WmiObject {
        fn get_u16(&self, key: &str) -> Option<u16> {
            match self.properties.get(key)? {
                WmiPropertyValue::Uint16(v) => Some(*v),
                _ => None,
            }
        }
    }
}
