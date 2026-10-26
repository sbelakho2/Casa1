//! Real IOKit HID enumeration and device handles.
//!
//! Enumeration uses `IOHIDManager` with a match-all dictionary and reads the
//! device's own `IOHIDDevice` properties (`IOHIDDeviceGetProperty`).  Open uses
//! `IOHIDDeviceOpen`, registers an input-report callback with a preallocated
//! buffer, and schedules the device on the current run loop.  No devices are
//! fabricated when the host reports none.

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::error::DeviceError;
use super::model::{
    DeviceClass, DeviceRecord, DeviceTable, HotplugEvent, OpenState, StableDeviceId,
};

#[cfg(all(target_os = "macos", not(test)))]
use super::ffi;

/// A HID usage/page pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidUsagePair {
    pub usage_page: u16,
    pub usage: u16,
}

/// An enumerated HID device and its real report descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HidDeviceInfo {
    pub id: StableDeviceId,
    pub registry_entry_id: u64,
    pub vendor_id: u16,
    pub product_id: u16,
    pub usage_page: u16,
    pub usage: u16,
    pub usage_pairs: Vec<HidUsagePair>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub transport: Option<String>,
    pub location_id: Option<u32>,
    pub report_descriptor: Vec<u8>,
    pub max_input_report_size: usize,
    pub max_output_report_size: usize,
    pub max_feature_report_size: usize,
}

impl HidDeviceInfo {
    pub fn record(&self) -> DeviceRecord {
        DeviceRecord {
            id: self.id,
            class: DeviceClass::Hid,
            vendor_id: Some(self.vendor_id),
            product_id: Some(self.product_id),
            manufacturer: self.manufacturer.clone(),
            product: self.product.clone(),
            serial_number: self.serial_number.clone(),
            path: Some(format!("IOHIDDevice:{:016x}", self.registry_entry_id)),
            registry_entry_id: self.registry_entry_id,
        }
    }

    pub fn is_game_controller(&self) -> bool {
        self.usage_pairs
            .iter()
            .any(|pair| pair.usage_page == 0x01 && matches!(pair.usage, 0x04 | 0x05 | 0x08))
    }
}

/// A complete input report delivered by the IOKit callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HidInputReport {
    pub report_id: u32,
    pub data: Vec<u8>,
}

/// HID bridge table keyed by stable IDs.
type OpenRegistry = Arc<Mutex<BTreeSet<StableDeviceId>>>;

#[derive(Debug, Clone, Default)]
pub struct HidBridge {
    devices: Vec<HidDeviceInfo>,
    table: DeviceTable,
    open_registry: OpenRegistry,
}

impl HidBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devices(&self) -> &[HidDeviceInfo] {
        &self.devices
    }

    pub fn table(&self) -> &DeviceTable {
        &self.table
    }

    pub fn device(&self, id: StableDeviceId) -> Option<&HidDeviceInfo> {
        self.devices.iter().find(|device| device.id == id)
    }

    pub fn apply(&mut self, devices: Vec<HidDeviceInfo>) -> Vec<HotplugEvent> {
        let mut devices = devices;
        devices.sort_by_key(|device| device.id);
        let records = devices.iter().map(HidDeviceInfo::record).collect();
        self.devices = devices;
        self.table.reconcile(records)
    }

    pub fn enumerate(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        let devices = scan_hid_devices()?;
        Ok(self.apply(devices))
    }

    pub fn open(&self, id: StableDeviceId) -> Result<HidDevice, DeviceError> {
        let info = self
            .device(id)
            .ok_or(DeviceError::DeviceMissing { id })?
            .clone();
        self.open_info(&info)
    }

    pub fn open_checked(
        &self,
        id: StableDeviceId,
        vendor_id: u16,
        product_id: u16,
    ) -> Result<HidDevice, DeviceError> {
        let info = self
            .device(id)
            .ok_or(DeviceError::DeviceMissing { id })?
            .clone();
        ensure_vendor(&info, vendor_id, product_id)?;
        self.open_info(&info)
    }

    fn open_info(&self, info: &HidDeviceInfo) -> Result<HidDevice, DeviceError> {
        match self.open_registry.lock() {
            Ok(mut open) => {
                if !open.insert(info.id) {
                    return Err(DeviceError::AlreadyOpen { id: info.id });
                }
            }
            Err(_) => {
                return Err(DeviceError::Io {
                    operation: "hid open registry",
                    os_code: 0,
                });
            }
        }
        match open_hid_device(info, Arc::clone(&self.open_registry)) {
            Ok(device) => Ok(device),
            Err(error) => {
                if let Ok(mut open) = self.open_registry.lock() {
                    open.remove(&info.id);
                }
                Err(error)
            }
        }
    }
}

fn ensure_vendor(info: &HidDeviceInfo, vendor_id: u16, product_id: u16) -> Result<(), DeviceError> {
    if info.vendor_id == vendor_id && info.product_id == product_id {
        return Ok(());
    }
    Err(DeviceError::VendorMismatch {
        id: info.id,
        expected_vendor: vendor_id,
        expected_product: product_id,
        actual_vendor: info.vendor_id,
        actual_product: info.product_id,
    })
}

fn validate_report_length(length: usize, maximum: usize) -> Result<(), DeviceError> {
    if length == 0 || length > maximum {
        return Err(DeviceError::InvalidReportLength {
            expected: maximum,
            actual: length,
        });
    }
    Ok(())
}

#[cfg(all(target_os = "macos", not(test)))]
struct HidCallbackContext {
    queue: Arc<Mutex<VecDeque<HidInputReport>>>,
    last_result: Arc<Mutex<Option<i32>>>,
}

#[cfg(all(target_os = "macos", not(test)))]
unsafe extern "C" fn input_report_callback(
    context: *mut std::ffi::c_void,
    result: i32,
    _sender: *mut std::ffi::c_void,
    _report_type: u32,
    report_id: u32,
    report: *mut u8,
    report_length: isize,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: context points to the Box<HidCallbackContext> owned by the
    // handle and remains alive until the device is unscheduled.
    let context = unsafe { &*(context as *const HidCallbackContext) };
    if result != 0 {
        if let Ok(mut last) = context.last_result.lock() {
            *last = Some(result);
        }
        return;
    }
    if report.is_null() || report_length <= 0 {
        return;
    }
    // SAFETY: IOKit guarantees report is valid for report_length bytes for the
    // duration of the callback.
    let bytes = unsafe { std::slice::from_raw_parts(report, report_length as usize) }.to_vec();
    if let Ok(mut queue) = context.queue.lock() {
        if queue.len() >= 128 {
            queue.pop_front();
        }
        queue.push_back(HidInputReport {
            report_id,
            data: bytes,
        });
    }
}

/// An open HID device.  Dropping it unschedules and closes the real device.
pub struct HidDevice {
    #[cfg(all(target_os = "macos", not(test)))]
    manager: Option<ffi::HidManager>,
    #[cfg(all(target_os = "macos", not(test)))]
    device: *const std::ffi::c_void,
    #[cfg(all(target_os = "macos", not(test)))]
    input_buffer: Box<[u8]>,
    #[cfg(all(target_os = "macos", not(test)))]
    callback_context: Option<Box<HidCallbackContext>>,
    #[cfg(all(target_os = "macos", not(test)))]
    scheduled: bool,
    queue: Arc<Mutex<VecDeque<HidInputReport>>>,
    #[allow(dead_code)] // read by the IOKit report path, cfg'd out under test
    last_result: Arc<Mutex<Option<i32>>>,
    max_output_report_size: usize,
    max_feature_report_size: usize,
    open_registry: Option<OpenRegistry>,
    state: OpenState,
}

impl HidDevice {
    pub fn id(&self) -> StableDeviceId {
        self.state
            .id()
            .unwrap_or_else(|| StableDeviceId::from_raw(0))
    }

    pub fn is_open(&self) -> bool {
        self.state.is_open()
    }

    pub fn close(&mut self) -> Result<(), DeviceError> {
        let id = self.state.end()?;
        #[cfg(all(target_os = "macos", not(test)))]
        {
            self.close_platform(id)?;
        }
        #[cfg(not(all(target_os = "macos", not(test))))]
        {
            self.release_open_registry(id);
        }
        Ok(())
    }

    pub fn drain_reports(&mut self) -> Vec<HidInputReport> {
        if let Ok(mut queue) = self.queue.lock() {
            return queue.drain(..).collect();
        }
        Vec::new()
    }

    pub fn pump_events(&mut self, timeout: Duration) -> usize {
        #[cfg(all(target_os = "macos", not(test)))]
        {
            if !self.state.is_open() || timeout.is_zero() {
                return 0;
            }
            let _ = ffi::run_loop_for(timeout.as_secs_f64());
            if let Ok(queue) = self.queue.lock() {
                return queue.len();
            }
        }
        let _ = timeout;
        0
    }

    pub fn read_report(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<HidInputReport>, DeviceError> {
        let Some(id) = self.state.id() else {
            return Err(DeviceError::NotOpen {
                id: self.state.last_id(),
            });
        };
        #[cfg(all(target_os = "macos", not(test)))]
        {
            if let Ok(mut queue) = self.queue.lock()
                && let Some(report) = queue.pop_front()
            {
                return Ok(Some(report));
            }
            let _ = ffi::run_loop_for(timeout.as_secs_f64());
            if let Ok(mut last) = self.last_result.lock()
                && let Some(result) = last.take()
                && result != 0
            {
                return Err(map_kr_device("IOHIDDeviceInputReport", result, id));
            }
            if let Ok(mut queue) = self.queue.lock() {
                return Ok(queue.pop_front());
            }
        }
        let _ = (timeout, id);
        if let Ok(mut queue) = self.queue.lock() {
            return Ok(queue.pop_front());
        }
        Ok(None)
    }

    pub fn get_input_report(
        &mut self,
        report_id: u32,
        buffer: &mut [u8],
    ) -> Result<usize, DeviceError> {
        let Some(id) = self.state.id() else {
            return Err(DeviceError::NotOpen {
                id: self.state.last_id(),
            });
        };
        if buffer.is_empty() {
            return Err(DeviceError::InvalidReportLength {
                expected: 1,
                actual: 0,
            });
        }
        #[cfg(all(target_os = "macos", not(test)))]
        {
            let (kr, length) = ffi::hid_get_report(
                self.device,
                ffi::KIO_HID_REPORT_TYPE_INPUT,
                report_id,
                buffer,
            );
            if kr != 0 {
                return Err(map_kr_device("IOHIDDeviceGetReport", kr, id));
            }
            return Ok(length);
        }
        #[cfg(not(all(target_os = "macos", not(test))))]
        {
            let _ = (id, report_id, buffer);
            Err(DeviceError::Unsupported {
                feature: "HID input reports",
            })
        }
    }

    pub fn send_output_report(&mut self, report_id: u32, report: &[u8]) -> Result<(), DeviceError> {
        self.send_report(ReportKind::Output, report_id, report)
    }

    pub fn send_feature_report(
        &mut self,
        report_id: u32,
        report: &[u8],
    ) -> Result<(), DeviceError> {
        self.send_report(ReportKind::Feature, report_id, report)
    }

    fn send_report(
        &mut self,
        kind: ReportKind,
        report_id: u32,
        report: &[u8],
    ) -> Result<(), DeviceError> {
        let Some(id) = self.state.id() else {
            return Err(DeviceError::NotOpen {
                id: self.state.last_id(),
            });
        };
        #[cfg(all(target_os = "macos", not(test)))]
        {
            let maximum = match kind {
                ReportKind::Output => self.max_output_report_size,
                ReportKind::Feature => self.max_feature_report_size,
            };
            if maximum == 0 {
                return Err(DeviceError::Unsupported {
                    feature: "HID report type",
                });
            }
            validate_report_length(report.len(), maximum)?;
            let report_type = match kind {
                ReportKind::Output => ffi::KIO_HID_REPORT_TYPE_OUTPUT,
                ReportKind::Feature => ffi::KIO_HID_REPORT_TYPE_FEATURE,
            };
            let kr = ffi::hid_set_report(self.device, report_type, report_id, report);
            if kr != 0 {
                return Err(map_kr_device("IOHIDDeviceSetReport", kr, id));
            }
            return Ok(());
        }
        #[cfg(not(all(target_os = "macos", not(test))))]
        {
            let maximum = match kind {
                ReportKind::Output => self.max_output_report_size,
                ReportKind::Feature => self.max_feature_report_size,
            };
            if maximum == 0 {
                return Err(DeviceError::Unsupported {
                    feature: "HID report type",
                });
            }
            validate_report_length(report.len(), maximum)?;
            let _ = (id, report_id, report);
            Err(DeviceError::Unsupported {
                feature: "HID reports",
            })
        }
    }

    #[cfg(not(all(target_os = "macos", not(test))))]
    fn release_open_registry(&mut self, id: StableDeviceId) {
        if let Some(registry) = self.open_registry.take()
            && let Ok(mut open) = registry.lock()
        {
            open.remove(&id);
        }
    }
}

impl Drop for HidDevice {
    fn drop(&mut self) {
        #[cfg(all(target_os = "macos", not(test)))]
        {
            if let Some(id) = self.state.id() {
                let _ = self.close_platform(id);
            }
        }
        #[cfg(not(all(target_os = "macos", not(test))))]
        {
            if let Some(id) = self.state.id() {
                self.release_open_registry(id);
            }
        }
        let _ = self.state.end();
    }
}

#[derive(Debug, Clone, Copy)]
enum ReportKind {
    Output,
    Feature,
}

#[cfg(all(target_os = "macos", not(test)))]
impl HidDevice {
    fn close_platform(&mut self, id: StableDeviceId) -> Result<(), DeviceError> {
        if self.scheduled {
            ffi::hid_unschedule(self.device);
            self.scheduled = false;
        }
        self.input_buffer.fill(0);
        self.callback_context = None;
        let kr = if self.device.is_null() {
            0
        } else {
            ffi::hid_device_close(self.device)
        };
        if !self.device.is_null() {
            ffi::cf_release(self.device);
            self.device = std::ptr::null();
        }
        self.manager = None;
        if let Some(registry) = self.open_registry.take()
            && let Ok(mut open) = registry.lock()
        {
            open.remove(&id);
        }
        if kr != 0 {
            return Err(map_kr_device("IOHIDDeviceClose", kr, id));
        }
        Ok(())
    }
}

#[cfg(all(target_os = "macos", not(test)))]
pub fn scan_hid_devices() -> Result<Vec<HidDeviceInfo>, DeviceError> {
    let manager = ffi::HidManager::new().ok_or(DeviceError::Unsupported {
        feature: "IOHIDManager",
    })?;
    manager.set_match_all();
    let kr = manager.open();
    if kr != 0 {
        return Err(map_kr("IOHIDManagerOpen", kr));
    }
    let Some(set) = manager.copy_devices() else {
        return Ok(Vec::new());
    };
    let mut devices: Vec<HidDeviceInfo> = set
        .values()
        .iter()
        .filter_map(|device| snapshot(*device))
        .collect();
    devices.sort_by_key(|device| device.id);
    Ok(devices)
}

#[cfg(all(target_os = "macos", not(test)))]
fn snapshot(device: *const std::ffi::c_void) -> Option<HidDeviceInfo> {
    let vendor_id = u16::try_from(hid_number(device, "VendorID").unwrap_or(0)).ok()?;
    let product_id = u16::try_from(hid_number(device, "ProductID").unwrap_or(0)).ok()?;
    let usage_page =
        u16::try_from(hid_number(device, "PrimaryUsagePage").unwrap_or(0)).unwrap_or(0);
    let usage = u16::try_from(hid_number(device, "PrimaryUsage").unwrap_or(0)).unwrap_or(0);
    let registry_entry_id = ffi::registry_entry_id(ffi::hid_device_service(device)).unwrap_or(0);
    let serial_number = hid_string(device, "SerialNumber");
    let location_id = hid_number(device, "LocationID")
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0);
    let id = stable_hid_id(
        vendor_id,
        product_id,
        serial_number.as_deref(),
        location_id,
        registry_entry_id,
    );
    Some(HidDeviceInfo {
        id,
        registry_entry_id,
        vendor_id,
        product_id,
        usage_page,
        usage,
        usage_pairs: if usage_page != 0 || usage != 0 {
            vec![HidUsagePair { usage_page, usage }]
        } else {
            Vec::new()
        },
        manufacturer: hid_string(device, "Manufacturer"),
        product: hid_string(device, "Product"),
        serial_number,
        transport: hid_string(device, "Transport"),
        location_id,
        report_descriptor: hid_data(device, "ReportDescriptor").unwrap_or_default(),
        max_input_report_size: hid_number(device, "MaxInputReportSize")
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value > 0)
            .unwrap_or(64),
        max_output_report_size: hid_number(device, "MaxOutputReportSize")
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
        max_feature_report_size: hid_number(device, "MaxFeatureReportSize")
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
    })
}

#[cfg(all(target_os = "macos", not(test)))]
fn stable_hid_id(
    vendor_id: u16,
    product_id: u16,
    serial: Option<&str>,
    location: Option<u32>,
    registry_entry_id: u64,
) -> StableDeviceId {
    let vendor = format!("{vendor_id:04x}");
    let product = format!("{product_id:04x}");
    let location = location.map(|value| format!("{value:08x}"));
    let registry = registry_entry_id.to_string();
    let mut parts = vec![vendor.as_str(), product.as_str()];
    if let Some(serial) = serial.filter(|value| !value.is_empty()) {
        parts.push(serial);
    }
    if let Some(location) = location.as_deref() {
        parts.push(location);
    }
    if parts.len() == 2 {
        parts.push(registry.as_str());
    }
    StableDeviceId::derive(DeviceClass::Hid, &parts)
}

#[cfg(all(target_os = "macos", not(test)))]
fn hid_number(device: *const std::ffi::c_void, key: &str) -> Option<i64> {
    match ffi::hid_property(device, key)? {
        ffi::CfValue::Number(value) => Some(value),
        _ => None,
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn hid_string(device: *const std::ffi::c_void, key: &str) -> Option<String> {
    match ffi::hid_property(device, key)? {
        ffi::CfValue::String(value) => Some(value),
        _ => None,
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn hid_data(device: *const std::ffi::c_void, key: &str) -> Option<Vec<u8>> {
    match ffi::hid_property(device, key)? {
        ffi::CfValue::Data(value) => Some(value),
        _ => None,
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn open_hid_device(
    info: &HidDeviceInfo,
    open_registry: OpenRegistry,
) -> Result<HidDevice, DeviceError> {
    let manager = ffi::HidManager::new().ok_or(DeviceError::Unsupported {
        feature: "IOHIDManager",
    })?;
    manager.set_match_all();
    let kr = manager.open();
    if kr != 0 {
        return Err(map_kr("IOHIDManagerOpen", kr));
    }
    let set = manager
        .copy_devices()
        .ok_or(DeviceError::DeviceMissing { id: info.id })?;
    let mut selected = None;
    for device in set.values() {
        if snapshot(*device).map(|candidate| candidate.id) == Some(info.id) {
            selected = Some(ffi::HidManager::retain(*device));
            break;
        }
    }
    let device = selected.ok_or(DeviceError::DeviceMissing { id: info.id })?;

    let kr = ffi::hid_device_open(device);
    if kr != 0 {
        ffi::cf_release(device);
        return Err(map_kr_device("IOHIDDeviceOpen", kr, info.id));
    }

    let queue = Arc::new(Mutex::new(VecDeque::new()));
    let last_result = Arc::new(Mutex::new(None));
    let callback_context = Box::new(HidCallbackContext {
        queue: Arc::clone(&queue),
        last_result: Arc::clone(&last_result),
    });
    let mut input_buffer = vec![0_u8; info.max_input_report_size.max(1)].into_boxed_slice();
    let context_ptr = &*callback_context as *const HidCallbackContext as *mut std::ffi::c_void;
    ffi::hid_register_input_report(
        device,
        input_buffer.as_mut_ptr(),
        input_buffer.len(),
        input_report_callback,
        context_ptr,
    );
    ffi::hid_schedule(device);

    let mut state = OpenState::default();
    state.begin(info.id)?;
    Ok(HidDevice {
        manager: Some(manager),
        device,
        input_buffer,
        callback_context: Some(callback_context),
        scheduled: true,
        queue,
        last_result,
        max_output_report_size: info.max_output_report_size,
        max_feature_report_size: info.max_feature_report_size,
        open_registry: Some(open_registry),
        state,
    })
}

#[cfg(all(target_os = "macos", not(test)))]
fn map_kr(operation: &'static str, kr: i32) -> DeviceError {
    match kr {
        ffi::KIORETURN_NOT_PRIVILEGED
        | ffi::KIORETURN_NOT_PERMITTED
        | ffi::KIORETURN_EXCLUSIVE_ACCESS
        | ffi::KIORETURN_BUSY => DeviceError::PermissionDenied { operation },
        ffi::KIORETURN_UNSUPPORTED => DeviceError::Unsupported {
            feature: "IOHIDManager",
        },
        ffi::KIORETURN_TIMEOUT => DeviceError::Timeout { timeout_ms: 0 },
        _ => DeviceError::Io {
            operation,
            os_code: kr,
        },
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn map_kr_device(operation: &'static str, kr: i32, id: StableDeviceId) -> DeviceError {
    match kr {
        ffi::KIORETURN_NOT_PRIVILEGED | ffi::KIORETURN_NOT_PERMITTED => {
            DeviceError::PermissionDenied { operation }
        }
        ffi::KIORETURN_NO_DEVICE
        | ffi::KIORETURN_OFFLINE
        | ffi::KIORETURN_NOT_ATTACHED
        | ffi::KIORETURN_NOT_OPEN => DeviceError::Unplugged { id },
        ffi::KIORETURN_UNSUPPORTED => DeviceError::Unsupported {
            feature: "HID report",
        },
        ffi::KIORETURN_BAD_ARGUMENT => DeviceError::InvalidReportLength {
            expected: 0,
            actual: 0,
        },
        ffi::KIORETURN_EXCLUSIVE_ACCESS | ffi::KIORETURN_BUSY => DeviceError::Busy {
            path: format!("hid:{id}"),
        },
        ffi::KIORETURN_TIMEOUT => DeviceError::Timeout { timeout_ms: 0 },
        _ => DeviceError::Io {
            operation,
            os_code: kr,
        },
    }
}

#[cfg(test)]
pub fn scan_hid_devices() -> Result<Vec<HidDeviceInfo>, DeviceError> {
    Ok(Vec::new())
}

#[cfg(all(not(target_os = "macos"), not(test)))]
pub fn scan_hid_devices() -> Result<Vec<HidDeviceInfo>, DeviceError> {
    Err(DeviceError::Unsupported {
        feature: "HID enumeration requires macOS IOKit",
    })
}

#[cfg(test)]
fn open_hid_device(
    info: &HidDeviceInfo,
    open_registry: OpenRegistry,
) -> Result<HidDevice, DeviceError> {
    if info.product.as_deref() == Some("__open_fails__") {
        return Err(DeviceError::Unsupported {
            feature: "injected open failure",
        });
    }
    let mut state = OpenState::default();
    state.begin(info.id)?;
    Ok(HidDevice {
        queue: Arc::new(Mutex::new(VecDeque::new())),
        last_result: Arc::new(Mutex::new(None)),
        max_output_report_size: info.max_output_report_size,
        max_feature_report_size: info.max_feature_report_size,
        open_registry: Some(open_registry),
        state,
    })
}

#[cfg(all(not(target_os = "macos"), not(test)))]
fn open_hid_device(
    _info: &HidDeviceInfo,
    _open_registry: OpenRegistry,
) -> Result<HidDevice, DeviceError> {
    Err(DeviceError::Unsupported {
        feature: "HID device access requires macOS IOKit",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> HidDeviceInfo {
        HidDeviceInfo {
            id: StableDeviceId::from_raw(0x55),
            registry_entry_id: 0x55,
            vendor_id: 0x045e,
            product_id: 0x028e,
            usage_page: 1,
            usage: 5,
            usage_pairs: vec![HidUsagePair {
                usage_page: 1,
                usage: 5,
            }],
            manufacturer: None,
            product: Some("Controller".to_string()),
            serial_number: None,
            transport: None,
            location_id: None,
            report_descriptor: Vec::new(),
            max_input_report_size: 64,
            max_output_report_size: 8,
            max_feature_report_size: 0,
        }
    }

    #[test]
    fn hid_double_open_and_double_close_are_exact_errors() {
        let id = StableDeviceId::from_raw(7);
        let mut state = OpenState::default();
        assert_eq!(state.begin(id), Ok(()));
        assert_eq!(state.begin(id), Err(DeviceError::AlreadyOpen { id }));
        assert_eq!(state.end(), Ok(id));
        assert_eq!(state.end(), Err(DeviceError::AlreadyClosed { id }));
    }

    #[test]
    fn hid_vendor_mismatch_handle_is_rejected_exactly() {
        let info = info();
        assert_eq!(
            ensure_vendor(&info, 0x054c, 0x0ce6),
            Err(DeviceError::VendorMismatch {
                id: info.id,
                expected_vendor: 0x054c,
                expected_product: 0x0ce6,
                actual_vendor: 0x045e,
                actual_product: 0x028e,
            })
        );
    }

    #[test]
    fn hid_invalid_report_lengths_are_rejected_exactly() {
        assert_eq!(
            validate_report_length(9, 8),
            Err(DeviceError::InvalidReportLength {
                expected: 8,
                actual: 9
            })
        );
        assert_eq!(
            validate_report_length(0, 8),
            Err(DeviceError::InvalidReportLength {
                expected: 8,
                actual: 0
            })
        );
    }

    #[test]
    fn hid_real_device_permission_denied_or_double_open_is_exact() {
        let mut bridge = HidBridge::new();
        match bridge.enumerate() {
            Ok(_) => {}
            Err(DeviceError::PermissionDenied { operation }) => {
                assert_eq!(operation, "IOHIDManagerOpen");
                return;
            }
            Err(DeviceError::Unsupported { feature }) => {
                assert_eq!(feature, "HID enumeration requires macOS IOKit");
                return;
            }
            Err(error) => panic!("unexpected HID enumeration error: {error:?}"),
        }
        let Some(info) = bridge.devices().first().cloned() else {
            return;
        };
        match bridge.open(info.id) {
            Ok(mut device) => {
                assert_eq!(
                    bridge.open(info.id).map(|_| ()),
                    Err(DeviceError::AlreadyOpen { id: info.id })
                );
                assert_eq!(device.close(), Ok(()));
                assert_eq!(
                    device.close(),
                    Err(DeviceError::AlreadyClosed { id: info.id })
                );
            }
            Err(DeviceError::PermissionDenied { operation }) => {
                assert!(matches!(operation, "IOHIDDeviceOpen" | "IOHIDManagerOpen"));
            }
            Err(DeviceError::DeviceMissing { id }) => assert_eq!(id, info.id),
            Err(DeviceError::Unplugged { id }) => assert_eq!(id, info.id),
            Err(DeviceError::Unsupported { feature }) => {
                assert_eq!(feature, "HID report");
            }
            Err(DeviceError::Busy { path }) => {
                assert_eq!(path, format!("hid:{}", info.id));
            }
            Err(error) => panic!("unexpected HID open error: {error:?}"),
        }
    }

    #[test]
    fn hid_report_handle_lifecycle_edges_and_usage_detection_are_exact() {
        let info = info();
        assert!(info.is_game_controller());
        let mut non_controller = info.clone();
        non_controller.usage_pairs = vec![HidUsagePair {
            usage_page: 0x01,
            usage: 0x80,
        }];
        assert!(!non_controller.is_game_controller());
        non_controller.usage_pairs.clear();
        assert!(!non_controller.is_game_controller());
        assert_eq!(
            info.record().path.as_deref(),
            Some("IOHIDDevice:0000000000000055")
        );

        let mut bridge = HidBridge::new();
        assert_eq!(bridge.devices().len(), 0);
        assert_eq!(bridge.table().len(), 0);
        assert_eq!(
            bridge.open(info.id).map(|_| ()),
            Err(DeviceError::DeviceMissing { id: info.id })
        );
        assert_eq!(
            bridge
                .open_checked(info.id, info.vendor_id, info.product_id)
                .map(|_| ()),
            Err(DeviceError::DeviceMissing { id: info.id })
        );
        assert_eq!(
            bridge.apply(vec![info.clone()]),
            vec![HotplugEvent::Arrived(info.record())]
        );
        assert_eq!(bridge.devices().len(), 1);
        assert_eq!(bridge.table().len(), 1);
        assert_eq!(bridge.device(info.id), Some(&info));
        assert_eq!(
            bridge.open_checked(info.id, 0x054c, 0x0ce6).map(|_| ()),
            Err(DeviceError::VendorMismatch {
                id: info.id,
                expected_vendor: 0x054c,
                expected_product: 0x0ce6,
                actual_vendor: 0x045e,
                actual_product: 0x028e,
            })
        );

        let mut device = bridge
            .open_checked(info.id, info.vendor_id, info.product_id)
            .expect("open checked fixture");
        assert_eq!(
            bridge.open(info.id).map(|_| ()),
            Err(DeviceError::AlreadyOpen { id: info.id })
        );
        assert_eq!(device.id(), info.id);
        assert!(device.is_open());
        assert_eq!(device.read_report(Duration::ZERO), Ok(None));
        assert_eq!(device.pump_events(Duration::ZERO), 0);
        assert_eq!(device.drain_reports(), Vec::new());
        device.queue.lock().unwrap().push_back(HidInputReport {
            report_id: 2,
            data: vec![1, 2, 3],
        });
        assert_eq!(
            device.read_report(Duration::ZERO),
            Ok(Some(HidInputReport {
                report_id: 2,
                data: vec![1, 2, 3]
            }))
        );
        assert_eq!(
            device.get_input_report(1, &mut []).unwrap_err(),
            DeviceError::InvalidReportLength {
                expected: 1,
                actual: 0
            }
        );
        let mut input = [0u8; 4];
        assert_eq!(
            device.get_input_report(1, &mut input),
            Err(DeviceError::Unsupported {
                feature: "HID input reports"
            })
        );
        assert_eq!(
            device.send_output_report(0, &[]),
            Err(DeviceError::InvalidReportLength {
                expected: 8,
                actual: 0
            })
        );
        assert_eq!(
            device.send_output_report(0, &[0u8; 9]),
            Err(DeviceError::InvalidReportLength {
                expected: 8,
                actual: 9
            })
        );
        assert_eq!(
            device.send_output_report(0, &[0u8; 8]),
            Err(DeviceError::Unsupported {
                feature: "HID reports"
            })
        );
        assert_eq!(
            device.send_feature_report(0, &[]),
            Err(DeviceError::Unsupported {
                feature: "HID report type"
            })
        );
        assert_eq!(device.close(), Ok(()));
        assert!(!device.is_open());
        assert_eq!(device.id().as_u64(), 0);
        assert_eq!(
            device.close(),
            Err(DeviceError::AlreadyClosed { id: info.id })
        );
        assert_eq!(
            device.read_report(Duration::ZERO),
            Err(DeviceError::NotOpen { id: info.id })
        );
        assert_eq!(
            device.get_input_report(1, &mut input),
            Err(DeviceError::NotOpen { id: info.id })
        );
        assert_eq!(
            device.send_output_report(0, &[0u8; 8]),
            Err(DeviceError::NotOpen { id: info.id })
        );

        let mut feature_info = info.clone();
        feature_info.max_feature_report_size = 8;
        assert_eq!(
            bridge.apply(vec![feature_info.clone()]),
            Vec::<HotplugEvent>::new()
        );
        let mut feature = bridge.open(info.id).expect("reopen after close");
        assert_eq!(
            feature.send_feature_report(0, &[0u8; 9]),
            Err(DeviceError::InvalidReportLength {
                expected: 8,
                actual: 9
            })
        );
        assert_eq!(
            feature.send_feature_report(0, &[0u8; 8]),
            Err(DeviceError::Unsupported {
                feature: "HID reports"
            })
        );
        drop(feature);
        assert!(bridge.open(info.id).is_ok());
    }

    #[test]
    fn hid_open_failure_and_poisoned_registry_edges_are_exact() {
        let mut failing = info();
        failing.product = Some("__open_fails__".to_string());
        let mut bridge = HidBridge::new();
        let _ = bridge.apply(vec![failing.clone()]);
        assert_eq!(
            bridge.open(failing.id).map(|_| ()),
            Err(DeviceError::Unsupported {
                feature: "injected open failure"
            })
        );
        assert!(!bridge.open_registry.lock().unwrap().contains(&failing.id));
        let mut recovered = failing.clone();
        recovered.product = Some("Controller".to_string());
        let _ = bridge.apply(vec![recovered.clone()]);
        assert!(bridge.open(recovered.id).is_ok());

        let mut poisoned = HidBridge::new();
        let info = info();
        let _ = poisoned.apply(vec![info.clone()]);
        let registry = Arc::clone(&poisoned.open_registry);
        let _ = std::thread::spawn(move || {
            let _guard = registry.lock().unwrap();
            panic!("poison registry");
        })
        .join();
        assert_eq!(
            poisoned.open(info.id).map(|_| ()),
            Err(DeviceError::Io {
                operation: "hid open registry",
                os_code: 0
            })
        );

        let mut queue_poison = HidBridge::new();
        let _ = queue_poison.apply(vec![info.clone()]);
        let mut device = queue_poison.open(info.id).expect("open before poisoning");
        let queue = Arc::clone(&device.queue);
        let _ = std::thread::spawn(move || {
            let _guard = queue.lock().unwrap();
            panic!("poison queue");
        })
        .join();
        assert_eq!(device.drain_reports(), Vec::new());
        assert_eq!(device.read_report(Duration::ZERO), Ok(None));
        let registry = Arc::clone(device.open_registry.as_ref().expect("registry"));
        let _ = std::thread::spawn(move || {
            let _guard = registry.lock().unwrap();
            panic!("poison device registry");
        })
        .join();
        drop(device);
    }

    #[test]
    fn hid_stale_handle_after_unplug_is_missing_exactly() {
        let info = info();
        let mut bridge = HidBridge::new();
        assert_eq!(
            bridge.apply(vec![info.clone()]),
            vec![HotplugEvent::Arrived(info.record())]
        );
        assert_eq!(
            bridge.apply(Vec::new()),
            vec![HotplugEvent::Removed {
                record: info.record()
            }]
        );
        assert_eq!(
            bridge.open(info.id).map(|_| ()),
            Err(DeviceError::DeviceMissing { id: info.id })
        );
    }

    #[test]
    fn hid_missing_handle_open_is_exact_and_not_permission() {
        let id = StableDeviceId::from_raw(0xdead_beef);
        let bridge = HidBridge::new();
        assert_eq!(
            bridge.open(id).map(|_| ()),
            Err(DeviceError::DeviceMissing { id })
        );
    }
}
