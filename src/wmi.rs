// wmi.rs — WMI (Windows Management Instrumentation) infrastructure
//
// Implements COM interfaces for WMI: IWbemLocator, IWbemServices,
// IWbemClassObject, IEnumWbemClassObject, and a WQL query parser.
//
// All WMI classes return macOS-equivalent values using system calls
// (sysctl, sw_vers, hostname, etc.).

use crate::error::{AppError, AppResult};
use crate::hardware_identity::{HardwareIdentity, host_identity};
use crate::reason::ReasonCode;
use std::collections::HashMap;
use std::ffi::CString;
use std::time::{SystemTime, UNIX_EPOCH};

/// The process-wide hardware identity every WMI class is sourced from, so WMI
/// can never disagree with the registry, the device IOCTLs, the firmware table
/// or DXGI/D3DKMT.
fn identity() -> &'static HardwareIdentity {
    host_identity()
}

/// A WMI DMTF datetime string from unix seconds (UTC).
fn unix_to_dmtf(seconds: u64) -> WmiPropertyValue {
    WmiPropertyValue::DateTime(format_dmtf(seconds as i64))
}

fn format_dmtf(total_secs: i64) -> String {
    let total_secs = total_secs.max(0);
    let days = total_secs / 86400;
    let time_secs = total_secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;
    let mut year = 1970i64;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u32;
    for days_in_month in month_days {
        if remaining < days_in_month {
            break;
        }
        remaining -= days_in_month;
        month += 1;
    }
    let day = (remaining + 1) as u32;
    format!("{year:04}{month:02}{day:02}{hours:02}{minutes:02}{seconds:02}.000000+000")
}

// ============================================================================
// macOS System Info Query Helpers
// ============================================================================

/// Call sysctlbyname and return the raw bytes.
///
/// Uses the direct `libc::sysctlbyname` C API instead of spawning a
/// `/usr/sbin/sysctl` subprocess.
///
/// # Safety
///
/// Calls libc::sysctlbyname which is safe for any well-formed C string
/// name; the kernel validates the MIB name internally.
fn sysctl_raw(name: &str) -> Option<Vec<u8>> {
    let c_name = CString::new(name).ok()?;
    let mut len: libc::size_t = 0;

    // First call with null oldp to query the required buffer size.
    // SAFETY: sysctlbyname with null oldp never writes, only queries size.
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
    // SAFETY: sysctlbyname writes at most `len` bytes into `buf`, which
    // we have pre-sized to that length.
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

/// Run a sysctl query and return the result as a trimmed string.
///
/// Uses the direct `libc::sysctlbyname` C API instead of spawning a
/// `/usr/sbin/sysctl` subprocess.
fn sysctl_value(name: &str) -> Option<String> {
    let raw = sysctl_raw(name)?;
    let s = String::from_utf8_lossy(&raw)
        .trim_end_matches('\0')
        .to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Run a sysctl query and parse the result as u64.
///
/// Handles both 8-byte (u64) and 4-byte (u32 promoted) returns.
fn sysctl_u64(name: &str) -> Option<u64> {
    let raw = sysctl_raw(name)?;
    match raw.len() {
        8 => {
            // SAFETY: checked length == 8 above
            Some(u64::from_ne_bytes(raw[..8].try_into().ok()?))
        }
        4 => {
            // SAFETY: checked length >= 4 above
            Some(u32::from_ne_bytes(raw[..4].try_into().ok()?) as u64)
        }
        _ => None,
    }
}

/// Run a sysctl query and parse the result as u32.
fn sysctl_u32(name: &str) -> Option<u32> {
    let raw = sysctl_raw(name)?;
    if raw.len() >= 4 {
        // SAFETY: checked length >= 4 above
        Some(u32::from_ne_bytes(raw[..4].try_into().ok()?))
    } else {
        None
    }
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

/// Generate a macOS marketing name from version string.
fn os_marketing_name(version: &str) -> String {
    let major: u32 = version
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(14);
    match major {
        15 => "macOS Sequoia",
        14 => "macOS Sonoma",
        13 => "macOS Ventura",
        12 => "macOS Monterey",
        11 => "macOS Big Sur",
        10 => "macOS Catalina",
        _ => "macOS",
    }
    .to_string()
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

/// Get current time as DMTF datetime.
#[allow(dead_code)] // WMI timestamp formatting helper; not yet referenced
fn now_dmtf() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
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
        if remaining < diy {
            break;
        }
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
        if remaining < d {
            break;
        }
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

/// Get current screen dimensions via CoreGraphics API.
///
/// Uses `CGMainDisplayID` / `CGDisplayPixelsWide` / `CGDisplayPixelsHigh`
/// from the CoreGraphics framework instead of spawning `system_profiler`.
fn screen_resolution() -> (u32, u32) {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn CGMainDisplayID() -> u32;
            fn CGDisplayPixelsWide(display: u32) -> usize;
            fn CGDisplayPixelsHigh(display: u32) -> usize;
        }
        // SAFETY: CoreGraphics display functions are safe to call on macOS;
        // they query the window server for the main display dimensions.
        let display = unsafe { CGMainDisplayID() };
        let width = unsafe { CGDisplayPixelsWide(display) };
        let height = unsafe { CGDisplayPixelsHigh(display) };
        if width > 0 && height > 0 {
            return (width as u32, height as u32);
        }
    }
    // Default to Retina-like resolution
    (1920, 1080)
}

// ============================================================================
// WMI Property Types
// ============================================================================

#[derive(Clone, Debug, Default)]
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
    #[default]
    Null,
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

    pub fn set<K: Into<String>, V: Into<WmiPropertyValue>>(
        &mut self,
        key: K,
        value: V,
    ) -> &mut Self {
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
    fn from(s: String) -> Self {
        WmiPropertyValue::String(s)
    }
}

impl From<&str> for WmiPropertyValue {
    fn from(s: &str) -> Self {
        WmiPropertyValue::String(s.to_string())
    }
}

impl From<u32> for WmiPropertyValue {
    fn from(v: u32) -> Self {
        WmiPropertyValue::Uint32(v)
    }
}

impl From<u64> for WmiPropertyValue {
    fn from(v: u64) -> Self {
        WmiPropertyValue::Uint64(v)
    }
}

impl From<i32> for WmiPropertyValue {
    fn from(v: i32) -> Self {
        WmiPropertyValue::Int32(v)
    }
}

impl From<bool> for WmiPropertyValue {
    fn from(v: bool) -> Self {
        WmiPropertyValue::Bool(v)
    }
}

impl From<u16> for WmiPropertyValue {
    fn from(v: u16) -> Self {
        WmiPropertyValue::Uint16(v)
    }
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
    /// Clone this provider into a new boxed trait object so that
    /// `WbemServices` can be duplicated (e.g. by `IWbemLocator::ConnectServer`)
    /// without losing any registered class providers.
    fn clone_box(&self) -> Box<dyn WmiClassProvider>;
}

// ============================================================================
// Win32_ComputerSystem Provider
// ============================================================================

#[derive(Clone)]
pub struct Win32ComputerSystemProvider;

impl Win32ComputerSystemProvider {
    fn build_object(&self) -> WmiObject {
        let identity = identity();
        let total_ram = total_physical_memory();
        let logical = identity.cpu.logical;

        WmiObject::new("Win32_ComputerSystem")
            .set("Name", identity.os.computer_name.clone())
            .set("Manufacturer", identity.machine.system_manufacturer.clone())
            .set("Model", identity.machine.product_name.clone())
            .set("TotalPhysicalMemory", total_ram)
            .set("NumberOfProcessors", logical)
            .set("Domain", identity.os.domain.clone())
            .set("PrimaryOwnerName", identity.os.user_name.clone())
            .set("SystemType", "ARM64")
            .set("UserName", identity.os.user_name.clone())
            .clone()
    }
}

impl WmiClassProvider for Win32ComputerSystemProvider {
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }

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

#[derive(Clone)]
pub struct Win32ProcessorProvider;

impl Win32ProcessorProvider {
    fn build_object(&self) -> WmiObject {
        let identity = identity();
        let physical = identity.cpu.cores;
        let logical = identity.cpu.logical;
        // MaxClockSpeed is in MHz: the measured monotonic (TSC) frequency.
        let freq = (identity.cpu.tsc_hz / 1_000_000).min(u32::MAX as u64) as u32;

        WmiObject::new("Win32_Processor")
            .set("Name", identity.cpu.brand.clone())
            .set("NumberOfCores", physical)
            .set("NumberOfLogicalProcessors", logical)
            .set("MaxClockSpeed", freq)
            .set("Architecture", 9u16) // 9 = x64
            .set(
                "Family",
                identity.cpu.family.map_or(2u16, |value| value as u16),
            )
            .set(
                "Stepping",
                identity.cpu.stepping.map_or(0u16, |value| value as u16),
            )
            .set("ProcessorId", format!("{:016X}", identity.gpu_luid()))
            .set("Manufacturer", identity.cpu.vendor.clone())
            .set("Description", identity.cpu.brand.clone())
            .clone()
    }
}

impl WmiClassProvider for Win32ProcessorProvider {
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }
    fn class_name(&self) -> &'static str {
        "Win32_Processor"
    }

    fn get_object(&self, _key: &str, _value: &str) -> Option<WmiObject> {
        Some(self.build_object())
    }

    fn enum_objects(&self) -> AppResult<Vec<WmiObject>> {
        // Build the object once and clone it per entry — one instance per
        // physical processor, without re-running the sysctls per core.
        let obj = self.build_object();
        Ok((0..physical_cpu_count()).map(|_| obj.clone()).collect())
    }
}

// ============================================================================
// Win32_OperatingSystem Provider
// ============================================================================

#[derive(Clone)]
pub struct Win32OperatingSystemProvider;

impl Win32OperatingSystemProvider {
    fn build_object(&self) -> WmiObject {
        let identity = identity();
        let version = identity.os.version.clone();
        let build = identity.os.build.clone();
        let marketing = os_marketing_name(&version);
        let total_ram_kb = total_physical_memory() / 1024;
        let avail_ram_kb = available_physical_memory() / 1024;

        let mut object = WmiObject::new("Win32_OperatingSystem")
            .set("Caption", format!("{} {version}", marketing))
            .set("Version", version)
            .set("BuildNumber", build)
            .set("BuildType", "Release")
            .set("OSArchitecture", "ARM64")
            .set("TotalVisibleMemorySize", total_ram_kb)
            .set("FreePhysicalMemory", avail_ram_kb)
            .set("FreeVirtualMemory", avail_ram_kb)
            .set("TotalVirtualMemorySize", total_ram_kb + 2_097_152) // ~2 GB page file
            .set("LastBootUpTime", unix_to_dmtf(identity.os.boot_time))
            .set("CSName", identity.os.computer_name.clone())
            .set("RegisteredUser", identity.os.user_name.clone())
            .set("SerialNumber", identity.install.product_id.clone())
            .set("Organization", "")
            .set("CountryCode", "1")
            .set("CurrentTimeZone", 0i32)
            .set("NumberOfUsers", 1u32)
            .set("NumberOfProcesses", 512u32)
            .set("ServicePackMajorVersion", 0u16)
            .set("ServicePackMinorVersion", 0u16)
            .set("SuiteMask", 0x0100u16) // VER_SUITE_SINGLEUSERTS
            .set("ProductType", 1u32) // VER_NT_WORKSTATION
            .clone();
        if let Some(install_date) = identity.os.install_date {
            object.set("InstallDate", unix_to_dmtf(install_date));
        }
        object
    }
}

impl WmiClassProvider for Win32OperatingSystemProvider {
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }
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

#[derive(Clone)]
pub struct Win32VideoControllerProvider;

impl Win32VideoControllerProvider {
    fn build_object(&self) -> WmiObject {
        let (width, height) = screen_resolution();
        let identity = identity();

        // The GPU identity is sourced from the same Metal/IOKit probe the DXGI
        // and D3DKMT surfaces use, so the name/VRAM/vendor always agree.
        let gpu_name = if identity.gpu.name.is_empty() {
            Self::get_gpu_name()
        } else {
            identity.gpu.name.clone()
        };
        let vram_bytes = if identity.gpu.vram_bytes == 0 {
            Self::get_vram_bytes()
        } else {
            identity.gpu.vram_bytes
        };

        WmiObject::new("Win32_VideoController")
            .set("Name", gpu_name.clone())
            .set("AdapterRAM", vram_bytes)
            .set(
                "PNPDeviceID",
                format!("Metal\\{:016X}", identity.gpu.registry_id),
            )
            .set(
                "AdapterCompatibility",
                identity.machine.system_manufacturer.clone(),
            )
            .set("DriverVersion", "1.0")
            .set("VideoProcessor", "Apple Graphics")
            .set("VideoArchitecture", 1u16) // VGA
            .set("VideoMemoryType", 2u16) // VRAM
            .set("CurrentHorizontalResolution", width)
            .set("CurrentVerticalResolution", height)
            .set("CurrentRefreshRate", 60u32)
            .set("MaxRefreshRate", 120u32)
            .set("MinRefreshRate", 30u32)
            .set("Status", "OK")
            .set("Description", gpu_name)
            .clone()
    }

    /// Get GPU model name via IOKit IOAccelerator registry.
    fn get_gpu_name() -> String {
        // Use IOKit to query the IOAccelerator (GPU) name from the IORegistry.
        #[cfg(target_os = "macos")]
        {
            let name = Self::iokit_gpu_name();
            if !name.is_empty() {
                return name;
            }
        }
        // Fallback: use hw.model to infer GPU family
        if let Some(model) = sysctl_value("hw.model")
            .filter(|m| m.contains("Pro") || m.contains("Max") || m.contains("Ultra"))
        {
            return format!("Apple {} GPU", model);
        }
        "Apple GPU".to_string()
    }

    /// Query IOKit IOAccelerator for the GPU name.
    #[cfg(target_os = "macos")]
    fn iokit_gpu_name() -> String {
        unsafe extern "C" {
            fn IOServiceGetMatchingService(
                mainPort: libc::c_uint,
                matching: *mut libc::c_void,
            ) -> libc::c_uint;
            fn IOServiceMatching(name: *const libc::c_char) -> *mut libc::c_void;
            fn CFStringCreateWithCString(
                allocator: *const libc::c_void,
                cStr: *const libc::c_char,
                encoding: u32,
            ) -> *const libc::c_void;
            fn IORegistryEntryCreateCFProperty(
                entry: libc::c_uint,
                key: *const libc::c_void,
                allocator: *const libc::c_void,
                options: u32,
            ) -> *mut libc::c_void;
            fn CFStringGetCString(
                theString: *const libc::c_void,
                buffer: *mut libc::c_char,
                bufferSize: isize,
                encoding: u32,
            ) -> u8;
            fn CFRelease(cf: *const libc::c_void);
            fn IOObjectRelease(object: libc::c_uint) -> i32;
        }
        const CF_STRING_ENCODING_UTF8: u32 = 0x08000100;

        // SAFETY: IOKit functions are safe to call on macOS; they query the IORegistry.
        let matching = unsafe { IOServiceMatching(c"IOAccelerator".as_ptr()) };
        if matching.is_null() {
            return String::new();
        }
        // SAFETY: IOServiceGetMatchingService consumes the matching dictionary.
        let service = unsafe { IOServiceGetMatchingService(0, matching) };
        if service == 0 {
            return String::new();
        }

        // Create a CFString key for "Model" — IORegistryEntryCreateCFProperty
        // requires the key to be a CFStringRef, not a raw C string.
        let model_cfstr = unsafe {
            CFStringCreateWithCString(std::ptr::null(), c"Model".as_ptr(), CF_STRING_ENCODING_UTF8)
        };
        if model_cfstr.is_null() {
            // Release the IO service before returning.
            unsafe { IOObjectRelease(service) };
            return String::new();
        }

        // SAFETY: IORegistryEntryCreateCFProperty returns a CFString or NULL.
        // Use null() for allocator: CoreFoundation accepts NULL as "use default allocator".
        let cf_prop =
            unsafe { IORegistryEntryCreateCFProperty(service, model_cfstr, std::ptr::null(), 0) };
        // SAFETY: Release the IO service object and the CFString key.
        unsafe { IOObjectRelease(service) };
        unsafe { CFRelease(model_cfstr) };

        if cf_prop.is_null() {
            return String::new();
        }

        let mut buf = [0i8; 256];
        // SAFETY: CFStringGetCString copies the string content into buf.
        let success = unsafe {
            CFStringGetCString(
                cf_prop,
                buf.as_mut_ptr(),
                buf.len() as isize,
                CF_STRING_ENCODING_UTF8,
            )
        };
        // SAFETY: Release the CFString.
        unsafe { CFRelease(cf_prop) };

        if success != 0 {
            let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            let name =
                String::from_utf8_lossy(&buf[..len].iter().map(|&c| c as u8).collect::<Vec<_>>())
                    .to_string();
            if !name.is_empty() {
                return name;
            }
        }
        String::new()
    }

    /// Get VRAM size in bytes via IOKit IOAccelerator registry.
    fn get_vram_bytes() -> u64 {
        #[cfg(target_os = "macos")]
        {
            let vram = Self::iokit_vram_bytes();
            if vram > 0 {
                return vram;
            }
        }
        // Default: 2 GB
        2 * 1024 * 1024 * 1024
    }

    /// Query IOKit IOAccelerator for VRAM size.
    #[cfg(target_os = "macos")]
    fn iokit_vram_bytes() -> u64 {
        unsafe extern "C" {
            fn IOServiceGetMatchingService(
                mainPort: libc::c_uint,
                matching: *mut libc::c_void,
            ) -> libc::c_uint;
            fn IOServiceMatching(name: *const libc::c_char) -> *mut libc::c_void;
            fn CFStringCreateWithCString(
                allocator: *const libc::c_void,
                cStr: *const libc::c_char,
                encoding: u32,
            ) -> *const libc::c_void;
            fn IORegistryEntryCreateCFProperty(
                entry: libc::c_uint,
                key: *const libc::c_void,
                allocator: *const libc::c_void,
                options: u32,
            ) -> *mut libc::c_void;
            fn CFNumberGetValue(
                number: *const libc::c_void,
                theType: u32,
                valuePtr: *mut libc::c_void,
            ) -> u8;
            fn CFRelease(cf: *const libc::c_void);
            fn IOObjectRelease(object: libc::c_uint) -> i32;
        }
        const CF_STRING_ENCODING_UTF8: u32 = 0x08000100;
        const KCF_NUMBER_S64_TYPE: u32 = 4; // kCFNumberSInt64Type

        // SAFETY: IOKit functions are safe to call on macOS.
        let matching = unsafe { IOServiceMatching(c"IOAccelerator".as_ptr()) };
        if matching.is_null() {
            return 0;
        }
        // SAFETY: IOServiceGetMatchingService consumes the matching dictionary.
        let service = unsafe { IOServiceGetMatchingService(0, matching) };
        if service == 0 {
            return 0;
        }

        // Create a CFString key for "VRAM (total)" — IORegistryEntryCreateCFProperty
        // requires the key to be a CFStringRef, not a raw C string.
        let vram_cfstr = unsafe {
            CFStringCreateWithCString(
                std::ptr::null(),
                c"VRAM (total)".as_ptr(),
                CF_STRING_ENCODING_UTF8,
            )
        };
        if vram_cfstr.is_null() {
            // Release the IO service before returning.
            unsafe { IOObjectRelease(service) };
            return 0;
        }

        // SAFETY: IORegistryEntryCreateCFProperty returns a CFNumber or NULL.
        // Use null() for allocator: CoreFoundation accepts NULL as "use default allocator".
        let cf_num =
            unsafe { IORegistryEntryCreateCFProperty(service, vram_cfstr, std::ptr::null(), 0) };
        // SAFETY: Release the IO service object and the CFString key.
        unsafe { IOObjectRelease(service) };
        unsafe { CFRelease(vram_cfstr) };

        if cf_num.is_null() {
            return 0;
        }

        let mut vram_val: i64 = 0;
        // SAFETY: CFNumberGetValue writes the numeric value into vram_val.
        let success = unsafe {
            CFNumberGetValue(
                cf_num,
                KCF_NUMBER_S64_TYPE,
                &mut vram_val as *mut _ as *mut libc::c_void,
            )
        };
        // SAFETY: Release the CFNumber.
        unsafe { CFRelease(cf_num) };

        if success != 0 && vram_val > 0 {
            return vram_val as u64;
        }
        0
    }
}

impl WmiClassProvider for Win32VideoControllerProvider {
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }
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

#[derive(Clone)]
pub struct Win32DiskDriveProvider;

impl Win32DiskDriveProvider {
    fn build_object(&self) -> WmiObject {
        let identity = identity();
        let (fallback_model, fallback_size, fallback_interface, partitions) = Self::get_disk_info();
        let disk = identity.disks.first();
        let model = disk
            .map(|disk| disk.model.clone())
            .filter(|model| !model.is_empty())
            .unwrap_or(fallback_model);
        let size_bytes = disk
            .map(|disk| disk.size_bytes)
            .filter(|size| *size > 0)
            .unwrap_or(fallback_size);
        let interface = disk
            .map(|disk| disk.interface.clone())
            .filter(|interface| !interface.is_empty())
            .unwrap_or(fallback_interface);

        let mut object = WmiObject::new("Win32_DiskDrive")
            .set("Model", model.clone())
            .set("Size", size_bytes)
            .set("InterfaceType", interface)
            .set("MediaType", "Fixed hard disk media")
            .set("Partitions", partitions)
            .set("Caption", model)
            .set("Status", "OK")
            .set("BytesPerSector", 512u32)
            .set("SectorsPerTrack", 63u32)
            .set("TotalHeads", 255u32)
            .set("TotalCylinders", 16383u32)
            .set("TracksPerCylinder", 255u32)
            .clone();
        if let Some(disk) = disk {
            object.set("SerialNumber", disk.serial.clone());
            object.set("DeviceID", disk.whole_disk.clone());
        }
        object
    }

    /// Get disk info using `libc::statfs()` and `std::fs` metadata.
    ///
    /// Replaces the old shell-out to `/usr/sbin/diskutil`.
    fn get_disk_info() -> (String, u64, String, u32) {
        // Use statfs to get filesystem statistics for the root volume.
        let root_path = match std::ffi::CString::new("/") {
            Ok(p) => p,
            Err(_) => {
                return (
                    "APPLE SSD".to_string(),
                    256 * 1024 * 1024 * 1024,
                    "NVMe".to_string(),
                    2,
                );
            }
        };
        // SAFETY: statfs writes filesystem metadata into the provided struct.
        // The path "/" is always valid on macOS; zeroed statfs is a safe initial state.
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(root_path.as_ptr(), &mut stat) };
        if rc == 0 {
            // f_blocks * f_bsize = total size in bytes
            let total_bytes = stat.f_blocks as u64 * stat.f_bsize as u64;
            // Get filesystem type name from f_fstypename
            // SAFETY: f_fstypename is a null-terminated C string written by statfs.
            let fstype = unsafe { std::ffi::CStr::from_ptr(stat.f_fstypename.as_ptr()) }
                .to_string_lossy()
                .to_string();
            let interface = if fstype.contains("apfs") || fstype.contains("hfs") {
                "NVMe".to_string()
            } else {
                "SCSI".to_string()
            };
            return ("APPLE SSD".to_string(), total_bytes, interface, 2u32);
        }

        // Fallback: default values
        (
            "APPLE SSD".to_string(),
            256 * 1024 * 1024 * 1024,
            "NVMe".to_string(),
            2,
        )
    }
}

impl WmiClassProvider for Win32DiskDriveProvider {
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }
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

#[derive(Clone)]
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
                .set("PermanentAddress", "00:00:00:00:00:00")
                .set("DHCPEnabled", false)
                .clone(),
        );

        // The guest network surfaces (GetAdaptersAddresses / GetAdaptersInfo /
        // GetIfTable) all report the guest adapter model; WMI reports the same
        // model so anti-cheat cannot observe a MAC that disagrees between
        // iphlpapi and WMI.
        let config = crate::network::guest_network_config(&identity().os.user_name);
        for adapter in &config.adapters {
            if adapter.if_type == 24 {
                continue; // software loopback: already reported above
            }
            let mac = adapter
                .mac
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(":");
            objects.push(
                WmiObject::new("Win32_NetworkAdapter")
                    .set("Name", adapter.description.clone())
                    .set("NetConnectionID", adapter.friendly_name.clone())
                    .set("MACAddress", mac.clone())
                    .set("PermanentAddress", mac)
                    .set("IPEnabled", adapter.dhcp_enabled)
                    .set(
                        "NetConnectionStatus",
                        if adapter.dhcp_enabled { 2u32 } else { 0u32 },
                    )
                    .set("AdapterType", guest_if_type_name(adapter.if_type))
                    .set("Description", adapter.description.clone())
                    .set("Speed", adapter.speed)
                    .set("Manufacturer", "Apple")
                    .set("NetEnabled", true)
                    .set("DHCPEnabled", adapter.dhcp_enabled)
                    .set("Index", adapter.index)
                    .clone(),
            );
        }

        objects
    }
}

/// Map a guest `IF_TYPE` to a Windows adapter-type string.
fn guest_if_type_name(if_type: u32) -> &'static str {
    match if_type {
        6 => "Ethernet 802.3",
        71 => "Wireless 802.11",
        24 => "Loopback",
        _ => "Ethernet 802.3",
    }
}

impl WmiClassProvider for Win32NetworkAdapterProvider {
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }
    fn class_name(&self) -> &'static str {
        "Win32_NetworkAdapter"
    }

    fn get_object(&self, key: &str, value: &str) -> Option<WmiObject> {
        for obj in self.build_objects() {
            if matches!(key, "Name" | "MACAddress") && obj.get_string(key).as_deref() == Some(value)
            {
                return Some(obj);
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

#[derive(Clone)]
pub struct Win32BiosProvider;

impl Win32BiosProvider {
    fn build_object(&self) -> WmiObject {
        let identity = identity();
        let machine = &identity.machine;
        // The BIOS image version tracks the installed firmware/build.
        let version = if machine.bios_version.is_empty() {
            machine.product_name.clone()
        } else {
            machine.bios_version.clone()
        };
        let mut object = WmiObject::new("Win32_BIOS")
            .set("Name", machine.bios_vendor.clone())
            .set("Version", version.clone())
            .set("Manufacturer", machine.bios_vendor.clone())
            .set("Status", "OK")
            .set("SerialNumber", machine.serial_number.clone())
            .set("SMBIOSBIOSVersion", version)
            .set("PrimaryBIOS", true)
            .clone();
        if !machine.bios_date.is_empty() {
            object.set(
                "ReleaseDate",
                WmiPropertyValue::DateTime(format!("{}.000000+000", machine.bios_date)),
            );
        }
        object
    }
}

impl WmiClassProvider for Win32BiosProvider {
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }
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

#[derive(Clone)]
pub struct Win32LogicalDiskProvider;

impl Win32LogicalDiskProvider {
    fn build_object(&self) -> WmiObject {
        let (total_bytes, free_bytes, volume_name) = Self::get_disk_space();
        let identity = identity();
        let disk = identity.disks.first();
        let volume_serial = disk
            .map(|disk| format!("{:08X}", disk.volume_serial))
            .unwrap_or_else(|| "00000000".to_string());
        let filesystem = disk
            .map(|disk| disk.filesystem.clone())
            .filter(|filesystem| !filesystem.is_empty())
            .unwrap_or_else(|| "APFS".to_string());
        let label = disk
            .map(|disk| disk.volume_name.clone())
            .filter(|label| !label.is_empty())
            .unwrap_or(volume_name);

        WmiObject::new("Win32_LogicalDisk")
            .set("DeviceID", "C:")
            .set("DriveType", 3u32) // DRIVE_FIXED
            .set("Size", total_bytes)
            .set("FreeSpace", free_bytes)
            .set("VolumeName", label)
            .set("VolumeSerialNumber", volume_serial)
            .set("FileSystem", filesystem)
            .set("Compressed", false)
            .set("SupportsDiskQuotas", false)
            .set("SupportsFileBasedCompression", false)
            .set("MaximumComponentLength", 255u32)
            .set("MediaType", 12u32) // Fixed hard disk
            .clone()
    }

    /// Get disk space info using `libc::statfs()`.
    ///
    /// Replaces the old shell-out to `/usr/sbin/diskutil`.
    fn get_disk_space() -> (u64, u64, String) {
        let root_path = match std::ffi::CString::new("/") {
            Ok(p) => p,
            Err(_) => {
                return (
                    512 * 1024 * 1024 * 1024,
                    256 * 1024 * 1024 * 1024,
                    "Macintosh HD".to_string(),
                );
            }
        };
        // SAFETY: statfs writes filesystem metadata into the provided struct.
        // The path "/" is always valid on macOS; zeroed statfs is safe.
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(root_path.as_ptr(), &mut stat) };
        if rc == 0 {
            let total = stat.f_blocks as u64 * stat.f_bsize as u64;
            let free = stat.f_bfree as u64 * stat.f_bsize as u64;
            // SAFETY: f_mntonname and f_fstypename are null-terminated C strings.
            let _fstype = unsafe { std::ffi::CStr::from_ptr(stat.f_fstypename.as_ptr()) }
                .to_string_lossy()
                .to_string();
            return (total, free, "Macintosh HD".to_string());
        }

        // Fallback: use std::fs
        if let Ok(_meta) = std::fs::metadata("/") {
            // We can't get accurate free space from std::fs metadata, so use defaults
        }
        (
            512 * 1024 * 1024 * 1024,
            256 * 1024 * 1024 * 1024,
            "Macintosh HD".to_string(),
        )
    }
}

impl WmiClassProvider for Win32LogicalDiskProvider {
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }
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

#[derive(Clone)]
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
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }
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

#[derive(Clone)]
pub struct Win32ComputerSystemProductProvider;

impl Win32ComputerSystemProductProvider {
    fn build_object(&self) -> WmiObject {
        let machine = &identity().machine;
        WmiObject::new("Win32_ComputerSystemProduct")
            .set("Name", machine.product_name.clone())
            .set("IdentifyingNumber", machine.serial_number.clone())
            .set("SKUNumber", machine.baseboard_product.clone())
            .set("Vendor", machine.system_manufacturer.clone())
            .set("Version", machine.system_version.clone())
            .set("UUID", machine.uuid.clone())
            .clone()
    }
}

impl WmiClassProvider for Win32ComputerSystemProductProvider {
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }
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
// Win32_BaseBoard Provider
// ============================================================================

#[derive(Clone)]
pub struct Win32BaseBoardProvider;

impl Win32BaseBoardProvider {
    fn build_object(&self) -> WmiObject {
        let machine = &identity().machine;
        WmiObject::new("Win32_BaseBoard")
            .set("Manufacturer", machine.baseboard_manufacturer.clone())
            .set("Product", machine.baseboard_product.clone())
            .set("Version", machine.baseboard_version.clone())
            .set("SerialNumber", machine.baseboard_serial.clone())
            .set("Tag", "Base Board".to_string())
            .set("HostingBoard", true)
            .set("PoweredOn", true)
            .clone()
    }
}

impl WmiClassProvider for Win32BaseBoardProvider {
    fn clone_box(&self) -> Box<dyn WmiClassProvider> {
        Box::new(self.clone())
    }
    fn class_name(&self) -> &'static str {
        "Win32_BaseBoard"
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
    Simple {
        property: String,
        op: WqlOp,
        value: String,
    },
    And(Vec<WqlWhereClause>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum WqlOp {
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
    Like,
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
    if !trimmed
        .get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("SELECT"))
    {
        return Err(AppError::new(
            ReasonCode::RcWmiParseError,
            format!("WQL query must start with SELECT: {}", query),
        ));
    }

    let after_select = trimmed[6..].trim();

    // Find FROM position (byte-accurate; safe to slice `after_select`)
    let from_idx = find_ci(after_select, "FROM").ok_or_else(|| {
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
    let where_idx = find_ci(after_from, "WHERE");
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
        let clauses: AppResult<Vec<WqlWhereClause>> =
            and_parts.into_iter().map(parse_simple_condition).collect();
        return Ok(WqlWhereClause::And(clauses?));
    }

    parse_simple_condition(trimmed)
}

/// Find the byte index of a case-insensitive ASCII keyword in `s`.
///
/// Scans the raw bytes so the returned index is a char boundary of `s`
/// whenever the keyword is ASCII (multi-byte UTF-8 bytes are never ASCII,
/// so they can neither match nor be matched across).
fn find_ci(s: &str, keyword: &str) -> Option<usize> {
    let k = keyword.as_bytes();
    if k.is_empty() {
        return None;
    }
    s.as_bytes()
        .windows(k.len())
        .position(|w| w.eq_ignore_ascii_case(k))
}

fn split_by_and(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth: usize = 0;
    let mut start = 0;
    let bytes = s.as_bytes();

    let mut i = 0;
    while i + 3 <= bytes.len() {
        // `i` is always a char boundary: it starts at 0 and advances by
        // whole characters below.
        let ch = match s[i..].chars().next() {
            Some(c) => c,
            None => break,
        };
        if ch == '(' {
            depth += 1;
        }
        if ch == ')' {
            depth = depth.saturating_sub(1);
        }
        if depth == 0 && bytes[i..i + 3].eq_ignore_ascii_case(b"AND") {
            // Make sure it's a word boundary. The matched bytes are ASCII
            // "AND", so i and i + 3 are both char boundaries.
            let prev_is_boundary = i == 0 || bytes[i - 1].is_ascii_whitespace();
            let next_is_boundary = i + 3 >= bytes.len() || bytes[i + 3].is_ascii_whitespace();
            if prev_is_boundary && next_is_boundary {
                parts.push(s[start..i].trim());
                start = i + 3;
            }
        }
        i += ch.len_utf8();
    }
    if start < s.len() {
        parts.push(s[start..].trim());
    }
    parts
}

/// Try to parse `s` as `<property> <op> <value>` for a specific operator.
///
/// Only matches when the operator is a standalone token bounded by
/// whitespace and the property is a simple identifier, so quoted values
/// containing operator words (e.g. `Name = 'LIKE'`) fall through.
fn parse_operator_condition(s: &str, op_str: &str) -> Option<(String, WqlOp, String)> {
    let idx = s.find(op_str)?;
    let before = s[..idx].trim();
    let after = s[idx + op_str.len()..].trim();
    if before.is_empty() || after.is_empty() || !is_simple_property(before) {
        return None;
    }
    let op = WqlOp::from_str(op_str)?;
    Some((before.to_string(), op, unquote(after)))
}

fn parse_simple_condition(s: &str) -> AppResult<WqlWhereClause> {
    let trimmed = s.trim();

    // Try LIKE first (longest operator). Only treat it as an operator when
    // it is a standalone word and the property is a simple identifier, so a
    // value containing the literal word "LIKE" is not misparsed.
    if let Some(idx) = find_ci(trimmed, "LIKE") {
        let prev_is_boundary = idx == 0 || trimmed[..idx].ends_with(char::is_whitespace);
        let next_is_boundary =
            idx + 4 >= trimmed.len() || trimmed[idx + 4..].starts_with(char::is_whitespace);
        if prev_is_boundary && next_is_boundary {
            let before = trimmed[..idx].trim();
            let after = trimmed[idx + 4..].trim();
            if !before.is_empty() && !after.is_empty() && is_simple_property(before) {
                return Ok(WqlWhereClause::Simple {
                    property: before.to_string(),
                    op: WqlOp::Like,
                    value: unquote(after),
                });
            }
        }
    }

    // Try multi-char operators: !=, <>, <=, >=
    for op_str in ["!=", "<>", "<=", ">="] {
        if let Some((property, op, value)) = parse_operator_condition(trimmed, op_str) {
            return Ok(WqlWhereClause::Simple {
                property,
                op,
                value,
            });
        }
    }

    // Try single-char operators: =, <, >
    for op_str in ["=", "<", ">"] {
        if let Some((property, op, value)) = parse_operator_condition(trimmed, op_str) {
            return Ok(WqlWhereClause::Simple {
                property,
                op,
                value,
            });
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
    if trimmed.len() >= 2
        && ((trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || (trimmed.starts_with('"') && trimmed.ends_with('"')))
    {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

/// Evaluate a WHERE condition against a WmiObject.
pub fn evaluate_condition(obj: &WmiObject, clause: &WqlWhereClause) -> bool {
    match clause {
        WqlWhereClause::Simple {
            property,
            op,
            value,
        } => {
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
        WqlWhereClause::And(clauses) => clauses.iter().all(|c| evaluate_condition(obj, c)),
    }
}

fn values_equal(prop: &WmiPropertyValue, value: &str) -> bool {
    match prop {
        WmiPropertyValue::String(s) => s.eq_ignore_ascii_case(value), // case-insensitive comparison
        WmiPropertyValue::Uint32(v) => value.parse::<u32>().map(|n| *v == n).unwrap_or(false),
        WmiPropertyValue::Uint64(v) => value.parse::<u64>().map(|n| *v == n).unwrap_or(false),
        WmiPropertyValue::Int32(v) => value.parse::<i32>().map(|n| *v == n).unwrap_or(false),
        WmiPropertyValue::Bool(v) => {
            value.eq_ignore_ascii_case("true") && *v // case-insensitive comparison
                || value.eq_ignore_ascii_case("false") && !*v // case-insensitive comparison
                || value.parse::<u32>().map(|n| (*v && n != 0) || (!*v && n == 0)).unwrap_or(false)
        }
        WmiPropertyValue::Uint16(v) => value.parse::<u16>().map(|n| *v == n).unwrap_or(false),
        _ => false,
    }
}

fn values_like(prop: &WmiPropertyValue, pattern: &str) -> bool {
    let prop_str = match prop {
        WmiPropertyValue::String(s) => s,
        WmiPropertyValue::Uint32(v) => {
            return pattern.parse::<u32>().map(|p| *v == p).unwrap_or(false);
        }
        _ => return false,
    };

    // Simple wildcard matching: % matches any sequence, _ matches single char.
    // Escape regex metacharacters first so guest-supplied patterns cannot
    // change the match semantics.
    let regex_pattern = regex::escape(pattern).replace('%', ".*").replace('_', ".");

    if let Ok(re) = regex::Regex::new(&format!("^(?i){}$", regex_pattern)) {
        re.is_match(prop_str)
    } else {
        prop_str.eq_ignore_ascii_case(pattern.trim_matches('%')) // case-insensitive comparison
    }
}

fn values_compare(prop: &WmiPropertyValue, value: &str) -> std::cmp::Ordering {
    match prop {
        WmiPropertyValue::Uint32(v) => value
            .parse::<u32>()
            .map(|n| (*v).cmp(&n))
            .unwrap_or(std::cmp::Ordering::Equal),
        WmiPropertyValue::Uint64(v) => value
            .parse::<u64>()
            .map(|n| (*v).cmp(&n))
            .unwrap_or(std::cmp::Ordering::Equal),
        WmiPropertyValue::Int32(v) => value
            .parse::<i32>()
            .map(|n| (*v).cmp(&n))
            .unwrap_or(std::cmp::Ordering::Equal),
        WmiPropertyValue::Uint16(v) => value
            .parse::<u16>()
            .map(|n| (*v).cmp(&n))
            .unwrap_or(std::cmp::Ordering::Equal),
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
    service.register(Box::new(Win32BaseBoardProvider));
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
    // The argument list mirrors the IWbemLocator::ConnectServer COM vtable
    // signature; the extra parameters are accepted for compatibility.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_server(
        &self,
        server: Option<&str>,
        user: Option<&str>,
        password: Option<&str>,
        _locale: Option<&str>,
        _flags: u32,
        _authority: Option<&str>,
        namespace: Option<&str>,
    ) -> AppResult<WbemServices> {
        let namespace = namespace.unwrap_or("root\\cimv2");
        let server = server.unwrap_or("localhost");

        // Log all parameters so authentication context is not silently discarded
        let user_str = user.unwrap_or("<none>");
        let pass_str = if password.is_some() {
            "<supplied>"
        } else {
            "<none>"
        };
        eprintln!(
            "WbemLocator::ConnectServer(server={server:?}, namespace={namespace:?}, user={user_str:?}, password={pass_str})"
        );

        // Note: WMI authentication (user/password) is not enforced on macOS;
        // the connection is accepted unconditionally.

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
        // Deep-clone every registered provider so the duplicated services
        // expose the same class set (IWbemLocator::ConnectServer semantics).
        let providers = self
            .providers
            .iter()
            .map(|(name, provider)| (name.clone(), provider.clone_box()))
            .collect();
        WbemServices { providers }
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
    pub fn exec_query(
        &self,
        _query_format: &str,
        query: &str,
        _flags: u32,
    ) -> AppResult<Vec<WmiObject>> {
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
            objects
                .into_iter()
                .filter(|obj| evaluate_condition(obj, where_clause))
                .collect()
        } else {
            objects
        };

        // Apply column projection
        let projected = if let Some(ref columns) = parsed.select_columns {
            filtered
                .into_iter()
                .map(|obj| {
                    let mut projected_obj = WmiObject::new(&obj.class_name);
                    projected_obj.keys = obj.keys.clone();
                    for col in columns {
                        if let Some(val) = obj.properties.get(col) {
                            projected_obj.properties.insert(col.clone(), val.clone());
                        }
                    }
                    projected_obj
                })
                .collect()
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
        self.object
            .properties
            .insert(property_name.to_string(), value);
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
        Self {
            objects,
            position: 0,
        }
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
    fn test_wql_like_regex_metachars() {
        // Regression: LIKE patterns with regex metacharacters must match
        // literally, not as regular expressions.
        let mut obj = WmiObject::new("Win32_Test");
        obj.set("Name", "a+b");
        let clause = WqlWhereClause::Simple {
            property: "Name".to_string(),
            op: WqlOp::Like,
            value: "a+b".to_string(),
        };
        assert!(evaluate_condition(&obj, &clause));
        let mut obj2 = WmiObject::new("Win32_Test");
        obj2.set("Name", "aXb");
        let clause2 = WqlWhereClause::Simple {
            property: "Name".to_string(),
            op: WqlOp::Like,
            value: "a+b".to_string(),
        };
        assert!(!evaluate_condition(&obj2, &clause2));
    }

    #[test]
    fn test_win32_processor_properties() {
        let provider = Win32ProcessorProvider;
        let objects = provider.enum_objects().unwrap();
        assert!(!objects.is_empty());
        let obj = &objects[0];
        assert_eq!(obj.class_name, "Win32_Processor");
        assert_eq!(
            obj.get_string("Name").as_deref(),
            Some(crate::hardware_identity::host_identity().cpu.brand.as_str())
        );
        assert!(obj.get_u32("NumberOfCores").unwrap() > 0);
        assert!(obj.get_u32("NumberOfLogicalProcessors").unwrap() > 0);
        assert!(obj.get_u32("MaxClockSpeed").unwrap() > 0);
        assert_eq!(obj.get_u16("Architecture"), Some(9));
    }

    #[test]
    fn test_win32_networkadapter_properties() {
        let provider = Win32NetworkAdapterProvider;
        let objects = provider.enum_objects().unwrap();
        assert!(!objects.is_empty());
        // At least a loopback adapter
        assert!(
            objects
                .iter()
                .any(|o| o.get_string("Name").as_deref() == Some("Loopback Adapter"))
        );
    }

    #[test]
    fn test_wbem_services_query() {
        let service = create_default_wmi_service();
        let objects = service
            .exec_query("WQL", "SELECT * FROM Win32_Processor", 0)
            .unwrap();
        assert!(!objects.is_empty());
        assert_eq!(objects[0].class_name, "Win32_Processor");
    }

    #[test]
    fn test_wbem_services_query_with_where() {
        let service = create_default_wmi_service();
        let brand = crate::hardware_identity::host_identity().cpu.brand.clone();
        let query = format!("SELECT * FROM Win32_Processor WHERE Name = '{brand}'");
        let objects = service.exec_query("WQL", &query, 0).unwrap();
        assert!(!objects.is_empty());
    }

    #[test]
    fn test_wql_parse_error() {
        let result = parse_wql("NOT A WQL QUERY");
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn test_sysctl_helpers() {
        // Test that the remaining sysctl helpers work on macOS.
        let mem = total_physical_memory();
        assert!(mem > 0, "Total physical memory should be > 0");

        let phys = physical_cpu_count();
        assert!(phys > 0, "Physical CPU count should be > 0");

        let model = sysctl_value("hw.model");
        assert!(model.is_some(), "hw.model should not be empty");
    }

    #[test]
    fn win32_bios_serial_mismatch_guard() {
        let identity = crate::hardware_identity::host_identity();
        let bios = Win32BiosProvider.build_object();
        assert_eq!(
            bios.get_string("SerialNumber").as_deref(),
            Some(identity.machine.serial_number.as_str())
        );
        assert_eq!(
            bios.get_string("Version").as_deref(),
            Some(identity.machine.bios_version.as_str())
        );
    }

    #[test]
    fn win32_computer_system_product_uuid_mismatch_guard() {
        let identity = crate::hardware_identity::host_identity();
        let product = Win32ComputerSystemProductProvider.build_object();
        assert_eq!(
            product.get_string("UUID").as_deref(),
            Some(identity.machine.uuid.as_str())
        );
        assert_eq!(
            product.get_string("IdentifyingNumber").as_deref(),
            Some(identity.machine.serial_number.as_str())
        );
    }

    #[test]
    fn win32_baseboard_serial_mismatch_guard() {
        let identity = crate::hardware_identity::host_identity();
        let board = Win32BaseBoardProvider.build_object();
        assert_eq!(
            board.get_string("SerialNumber").as_deref(),
            Some(identity.machine.baseboard_serial.as_str())
        );
        let service = create_default_wmi_service();
        let objects = service
            .exec_query("WQL", "SELECT * FROM Win32_BaseBoard", 0)
            .unwrap();
        assert_eq!(objects.len(), 1);
    }

    #[test]
    fn win32_logicaldisk_volume_serial_mismatch_guard() {
        let identity = crate::hardware_identity::host_identity();
        let expected = identity
            .disks
            .first()
            .map(|disk| format!("{:08X}", disk.volume_serial))
            .unwrap_or_else(|| "00000000".to_string());
        let disk = Win32LogicalDiskProvider.build_object();
        assert_eq!(
            disk.get_string("VolumeSerialNumber").as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn win32_networkadapter_mac_mismatch_guard() {
        // WMI and the iphlpapi guest model must report the same adapters.
        let config = crate::network::guest_network_config(
            &crate::hardware_identity::host_identity().os.user_name,
        );
        let adapters = Win32NetworkAdapterProvider.build_objects();
        let primary = config
            .adapters
            .iter()
            .find(|adapter| adapter.if_type != 24)
            .expect("ethernet adapter");
        let expected = primary
            .mac
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let found = adapters
            .iter()
            .any(|adapter| adapter.get_string("MACAddress").as_deref() == Some(expected.as_str()));
        assert_eq!(found, true);
    }

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
