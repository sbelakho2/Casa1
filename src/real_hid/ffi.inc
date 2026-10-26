//! Minimal IOKit/CoreFoundation bindings for the physical-device bridge.
//!
//! Only the documented, stable C APIs are bound here.  Every function that
//! returns a CoreFoundation object is wrapped so its retain count is released;
//! borrowed values from `IOHIDDeviceGetProperty` and `CFSetGetValues` are
//! decoded without releasing.

use std::ffi::{CString, c_char, c_void};
use std::ptr;

pub const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
pub const CF_NUMBER_SINT64_TYPE: u32 = 4;
pub const KCF_ALLOCATOR_DEFAULT: *const c_void = ptr::null();
pub const KCF_PROPERTY_LIST_IMMUTABLE: u32 = 0;
pub const IO_MASTER_PORT_DEFAULT: u32 = 0;
pub const IOSERVICE_PLANE: &str = "IOService";

pub const KIO_HID_REPORT_TYPE_INPUT: u32 = 0;
pub const KIO_HID_REPORT_TYPE_OUTPUT: u32 = 1;
pub const KIO_HID_REPORT_TYPE_FEATURE: u32 = 2;
pub const KIO_HID_OPTIONS_NONE: u32 = 0;

pub const KIORETURN_NO_DEVICE: i32 = 0xe000_02c0_u32 as i32;
pub const KIORETURN_NOT_PRIVILEGED: i32 = 0xe000_02c1_u32 as i32;
pub const KIORETURN_BAD_ARGUMENT: i32 = 0xe000_02c2_u32 as i32;
pub const KIORETURN_EXCLUSIVE_ACCESS: i32 = 0xe000_02c5_u32 as i32;
pub const KIORETURN_UNSUPPORTED: i32 = 0xe000_02c7_u32 as i32;
pub const KIORETURN_NOT_OPEN: i32 = 0xe000_02cd_u32 as i32;
pub const KIORETURN_BUSY: i32 = 0xe000_02d5_u32 as i32;
pub const KIORETURN_TIMEOUT: i32 = 0xe000_02d6_u32 as i32;
pub const KIORETURN_OFFLINE: i32 = 0xe000_02d7_u32 as i32;
pub const KIORETURN_NOT_ATTACHED: i32 = 0xe000_02d9_u32 as i32;
pub const KIORETURN_NOT_PERMITTED: i32 = 0xe000_02e2_u32 as i32;

pub type CfTypeRef = *const c_void;

pub type IOHIDReportCallback = unsafe extern "C" fn(
    context: *mut c_void,
    result: i32,
    sender: *mut c_void,
    report_type: u32,
    report_id: u32,
    report: *mut u8,
    report_length: isize,
);

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(
        allocator: *const c_void,
        c_str: *const c_char,
        encoding: u32,
    ) -> *const c_void;
    fn CFStringGetCString(
        string: *const c_void,
        buffer: *mut c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> u8;
    fn CFNumberGetValue(number: *const c_void, the_type: u32, value_ptr: *mut c_void) -> u8;
    fn CFDataGetLength(data: *const c_void) -> isize;
    fn CFDataGetBytePtr(data: *const c_void) -> *const u8;
    fn CFArrayGetCount(array: *const c_void) -> isize;
    fn CFArrayGetValueAtIndex(array: *const c_void, index: isize) -> *const c_void;
    fn CFSetGetCount(set: *const c_void) -> isize;
    fn CFSetGetValues(set: *const c_void, values: *mut *const c_void);
    fn CFGetTypeID(value: *const c_void) -> libc::c_ulong;
    fn CFStringGetTypeID() -> libc::c_ulong;
    fn CFNumberGetTypeID() -> libc::c_ulong;
    fn CFDataGetTypeID() -> libc::c_ulong;
    fn CFBooleanGetTypeID() -> libc::c_ulong;
    fn CFBooleanGetValue(boolean: *const c_void) -> u8;
    fn CFArrayGetTypeID() -> libc::c_ulong;
    fn CFRetain(value: *const c_void);
    fn CFRelease(value: *const c_void);
    fn CFRunLoopGetCurrent() -> *mut c_void;
    fn CFRunLoopRunInMode(
        mode: *const c_void,
        seconds: f64,
        return_after_source_handled: u8,
    ) -> i32;
    static kCFRunLoopDefaultMode: *const c_void;
}

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceMatching(name: *const c_char) -> *mut c_void;
    fn IOServiceGetMatchingServices(
        main_port: u32,
        matching: *const c_void,
        existing: *mut u32,
    ) -> i32;
    fn IOIteratorNext(iterator: u32) -> u32;
    fn IOObjectRelease(object: u32) -> i32;
    fn IORegistryEntryCreateCFProperty(
        entry: u32,
        key: *const c_void,
        allocator: *const c_void,
        options: u32,
    ) -> *mut c_void;
    fn IORegistryEntryGetRegistryEntryID(entry: u32, out: *mut u64) -> i32;
    fn IORegistryEntryGetChildIterator(entry: u32, plane: *const c_char, iterator: *mut u32)
    -> i32;
    fn IOObjectGetClass(object: u32, class_name: *mut c_char) -> i32;

    fn IOHIDManagerCreate(allocator: *const c_void, options: u32) -> *mut c_void;
    fn IOHIDManagerSetDeviceMatching(manager: *mut c_void, matching: *const c_void);
    fn IOHIDManagerOpen(manager: *mut c_void, options: u32) -> i32;
    fn IOHIDManagerClose(manager: *mut c_void, options: u32) -> i32;
    fn IOHIDManagerCopyDevices(manager: *mut c_void) -> *mut c_void;
    fn IOHIDDeviceGetProperty(device: *const c_void, key: *const c_void) -> *const c_void;
    fn IOHIDDeviceGetService(device: *const c_void) -> u32;
    fn IOHIDDeviceOpen(device: *const c_void, options: u32) -> i32;
    fn IOHIDDeviceClose(device: *const c_void, options: u32) -> i32;
    fn IOHIDDeviceScheduleWithRunLoop(
        device: *const c_void,
        run_loop: *mut c_void,
        mode: *const c_void,
    );
    fn IOHIDDeviceUnscheduleFromRunLoop(
        device: *const c_void,
        run_loop: *mut c_void,
        mode: *const c_void,
    );
    fn IOHIDDeviceRegisterInputReportCallback(
        device: *const c_void,
        report: *mut u8,
        report_length: isize,
        callback: Option<IOHIDReportCallback>,
        context: *mut c_void,
    );
    fn IOHIDDeviceGetReport(
        device: *const c_void,
        report_type: u32,
        report_id: u32,
        report: *mut u8,
        report_length: *mut isize,
    ) -> i32;
    fn IOHIDDeviceSetReport(
        device: *const c_void,
        report_type: u32,
        report_id: u32,
        report: *const u8,
        report_length: isize,
    ) -> i32;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfValue {
    String(String),
    Number(i64),
    Bool(bool),
    Data(Vec<u8>),
    Array(Vec<CfValue>),
    Other,
}

pub struct CfOwned(CfTypeRef);

impl Drop for CfOwned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: every CfOwned is a retained CoreFoundation value.
            unsafe { CFRelease(self.0) };
        }
    }
}

impl CfOwned {
    pub fn value(&self) -> CfValue {
        // SAFETY: self.0 is a live CoreFoundation value for this borrow.
        unsafe { decode(self.0) }
    }
}

pub struct IoService(u32);

impl IoService {
    pub fn property(&self, key: &str) -> Option<CfOwned> {
        property(self.0, key)
    }

    pub fn string(&self, key: &str) -> Option<String> {
        match self.property(key)?.value() {
            CfValue::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn number(&self, key: &str) -> Option<i64> {
        match self.property(key)?.value() {
            CfValue::Number(value) => Some(value),
            _ => None,
        }
    }

    pub fn data(&self, key: &str) -> Option<Vec<u8>> {
        match self.property(key)?.value() {
            CfValue::Data(value) => Some(value),
            _ => None,
        }
    }

    pub fn registry_entry_id(&self) -> Option<u64> {
        let mut id = 0_u64;
        // SAFETY: out points to a valid u64.
        let kr = unsafe { IORegistryEntryGetRegistryEntryID(self.0, &mut id) };
        (kr == 0).then_some(id)
    }

    pub fn class_name(&self) -> Option<String> {
        let mut buffer = [0_i8; 128];
        // SAFETY: IOObjectGetClass writes at most io_name_t (128 bytes).
        let kr = unsafe { IOObjectGetClass(self.0, buffer.as_mut_ptr()) };
        if kr != 0 {
            return None;
        }
        let len = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        Some(
            buffer[..len]
                .iter()
                .map(|byte| *byte as u8)
                .map(char::from)
                .collect(),
        )
    }

    pub fn children(&self) -> Vec<IoService> {
        let mut iterator = 0_u32;
        let Ok(plane) = CString::new(IOSERVICE_PLANE) else {
            return Vec::new();
        };
        // SAFETY: plane is NUL-terminated; iterator is initialized on success.
        let kr = unsafe { IORegistryEntryGetChildIterator(self.0, plane.as_ptr(), &mut iterator) };
        if kr != 0 || iterator == 0 {
            return Vec::new();
        }
        let mut children = Vec::new();
        loop {
            // SAFETY: iterator is a live io_iterator_t.
            let child = unsafe { IOIteratorNext(iterator) };
            if child == 0 {
                break;
            }
            children.push(IoService(child));
        }
        // SAFETY: release the iterator; children hold their own references.
        unsafe { IOObjectRelease(iterator) };
        children
    }
}

impl Drop for IoService {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: IoService owns its io_object_t reference.
            unsafe { IOObjectRelease(self.0) };
        }
    }
}

pub struct HidManager(*mut c_void);

impl HidManager {
    pub fn new() -> Option<Self> {
        // SAFETY: kCFAllocatorDefault is NULL and options are documented.
        let manager = unsafe { IOHIDManagerCreate(KCF_ALLOCATOR_DEFAULT, KIO_HID_OPTIONS_NONE) };
        (!manager.is_null()).then_some(Self(manager))
    }

    pub fn set_match_all(&self) {
        // SAFETY: a NULL matching dictionary matches every HID device.
        unsafe { IOHIDManagerSetDeviceMatching(self.0, ptr::null()) };
    }

    pub fn open(&self) -> i32 {
        // SAFETY: self.0 is a live IOHIDManagerRef.
        unsafe { IOHIDManagerOpen(self.0, KIO_HID_OPTIONS_NONE) }
    }

    pub fn copy_devices(&self) -> Option<HidDeviceSet> {
        // SAFETY: self.0 is a live IOHIDManagerRef; the returned CFSet is owned.
        let set = unsafe { IOHIDManagerCopyDevices(self.0) };
        if set.is_null() {
            return None;
        }
        let owned = CfOwned(set);
        // SAFETY: set is a live CFSetRef.
        let count = unsafe { CFSetGetCount(set) };
        if count <= 0 {
            return Some(HidDeviceSet {
                _set: owned,
                values: Vec::new(),
            });
        }
        let mut values = vec![ptr::null(); count as usize];
        // SAFETY: values has room for `count` borrowed CFTypeRef values.
        unsafe { CFSetGetValues(set, values.as_mut_ptr()) };
        Some(HidDeviceSet {
            _set: owned,
            values,
        })
    }

    pub fn retain(device: *const c_void) -> *const c_void {
        // SAFETY: device is a live IOHIDDeviceRef from a manager copy.
        unsafe { CFRetain(device) };
        device
    }
}

pub struct HidDeviceSet {
    _set: CfOwned,
    values: Vec<*const c_void>,
}

impl HidDeviceSet {
    pub fn values(&self) -> &[*const c_void] {
        &self.values
    }
}

impl Drop for HidManager {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: close is safe on an open or closed manager; the manager
            // object itself is retained and must be released.
            unsafe {
                IOHIDManagerClose(self.0, KIO_HID_OPTIONS_NONE);
                CFRelease(self.0);
            }
        }
    }
}

pub fn matching_services(class: &str) -> Vec<IoService> {
    let Ok(c_class) = CString::new(class) else {
        return Vec::new();
    };
    // SAFETY: IOServiceMatching copies the class name.
    let matching = unsafe { IOServiceMatching(c_class.as_ptr()) };
    if matching.is_null() {
        return Vec::new();
    }
    // SAFETY: IOServiceGetMatchingServices consumes the matching dictionary.
    let mut iterator = 0_u32;
    let kr =
        unsafe { IOServiceGetMatchingServices(IO_MASTER_PORT_DEFAULT, matching, &mut iterator) };
    if kr != 0 || iterator == 0 {
        return Vec::new();
    }
    let mut services = Vec::new();
    loop {
        // SAFETY: iterator is a live io_iterator_t.
        let service = unsafe { IOIteratorNext(iterator) };
        if service == 0 {
            break;
        }
        services.push(IoService(service));
    }
    // SAFETY: release the iterator.
    unsafe { IOObjectRelease(iterator) };
    services
}

pub fn property(entry: u32, key: &str) -> Option<CfOwned> {
    let Ok(c_key) = CString::new(key) else {
        return None;
    };
    // SAFETY: key is a NUL-terminated C string; the function returns a retained value.
    let cf_key = unsafe {
        CFStringCreateWithCString(
            KCF_ALLOCATOR_DEFAULT,
            c_key.as_ptr(),
            CF_STRING_ENCODING_UTF8,
        )
    };
    if cf_key.is_null() {
        return None;
    }
    // SAFETY: cf_key is a valid CFStringRef; returns a retained property.
    let value = unsafe {
        IORegistryEntryCreateCFProperty(
            entry,
            cf_key,
            KCF_ALLOCATOR_DEFAULT,
            KCF_PROPERTY_LIST_IMMUTABLE,
        )
    };
    // SAFETY: release the temporary key.
    unsafe { CFRelease(cf_key) };
    (!value.is_null()).then(|| CfOwned(value))
}

pub fn hid_property(device: *const c_void, key: &str) -> Option<CfValue> {
    let Ok(c_key) = CString::new(key) else {
        return None;
    };
    // SAFETY: key is a NUL-terminated C string.
    let cf_key = unsafe {
        CFStringCreateWithCString(
            KCF_ALLOCATOR_DEFAULT,
            c_key.as_ptr(),
            CF_STRING_ENCODING_UTF8,
        )
    };
    if cf_key.is_null() {
        return None;
    }
    // SAFETY: returns a borrowed CFTypeRef valid for the device's lifetime.
    let value = unsafe { IOHIDDeviceGetProperty(device, cf_key) };
    // SAFETY: release the temporary key.
    unsafe { CFRelease(cf_key) };
    if value.is_null() {
        return None;
    }
    // SAFETY: value is a live borrowed CoreFoundation value.
    Some(unsafe { decode(value) })
}

pub fn registry_entry_id(entry: u32) -> Option<u64> {
    let mut id = 0_u64;
    // SAFETY: out points to a valid u64.
    let kr = unsafe { IORegistryEntryGetRegistryEntryID(entry, &mut id) };
    (kr == 0).then_some(id)
}

pub fn hid_device_service(device: *const c_void) -> u32 {
    // SAFETY: device is a live IOHIDDeviceRef; the service is borrowed.
    unsafe { IOHIDDeviceGetService(device) }
}

pub fn hid_device_open(device: *const c_void) -> i32 {
    // SAFETY: device is a live IOHIDDeviceRef.
    unsafe { IOHIDDeviceOpen(device, KIO_HID_OPTIONS_NONE) }
}

pub fn hid_device_close(device: *const c_void) -> i32 {
    // SAFETY: device is a live IOHIDDeviceRef.
    unsafe { IOHIDDeviceClose(device, KIO_HID_OPTIONS_NONE) }
}

pub fn hid_schedule(device: *const c_void) {
    // SAFETY: the current run loop and default mode are process-global.
    unsafe {
        IOHIDDeviceScheduleWithRunLoop(device, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    }
}

pub fn hid_unschedule(device: *const c_void) {
    // SAFETY: the current run loop and default mode are process-global.
    unsafe {
        IOHIDDeviceUnscheduleFromRunLoop(device, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    }
}

pub fn hid_register_input_report(
    device: *const c_void,
    buffer: *mut u8,
    length: usize,
    callback: IOHIDReportCallback,
    context: *mut c_void,
) {
    // SAFETY: buffer/context outlive the registration (owned by the handle).
    unsafe {
        IOHIDDeviceRegisterInputReportCallback(
            device,
            buffer,
            length as isize,
            Some(callback),
            context,
        );
    }
}

pub fn hid_get_report(
    device: *const c_void,
    report_type: u32,
    report_id: u32,
    buffer: &mut [u8],
) -> (i32, usize) {
    let mut length = buffer.len() as isize;
    // SAFETY: buffer is valid for `length` bytes.
    let kr = unsafe {
        IOHIDDeviceGetReport(
            device,
            report_type,
            report_id,
            buffer.as_mut_ptr(),
            &mut length,
        )
    };
    (kr, usize::try_from(length).unwrap_or(0))
}

pub fn hid_set_report(
    device: *const c_void,
    report_type: u32,
    report_id: u32,
    buffer: &[u8],
) -> i32 {
    // SAFETY: buffer is valid for buffer.len() bytes.
    unsafe {
        IOHIDDeviceSetReport(
            device,
            report_type,
            report_id,
            buffer.as_ptr(),
            buffer.len() as isize,
        )
    }
}

pub fn run_loop_for(seconds: f64) -> i32 {
    // SAFETY: the current run loop and default mode are process-global.
    unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, seconds, 1) }
}

pub fn cf_release(value: *const c_void) {
    if !value.is_null() {
        // SAFETY: caller transfers one retained reference.
        unsafe { CFRelease(value) };
    }
}

unsafe fn decode(value: *const c_void) -> CfValue {
    if value.is_null() {
        return CfValue::Other;
    }
    // SAFETY: type IDs are immutable process-global constants.
    let type_id = unsafe { CFGetTypeID(value) };
    if type_id == unsafe { CFStringGetTypeID() } {
        let mut buffer = [0_i8; 4096];
        // SAFETY: buffer has room for 4096 bytes; encoding is UTF-8.
        let ok = unsafe {
            CFStringGetCString(
                value,
                buffer.as_mut_ptr(),
                buffer.len() as isize,
                CF_STRING_ENCODING_UTF8,
            )
        };
        if ok == 0 {
            return CfValue::Other;
        }
        let len = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        let bytes: Vec<u8> = buffer[..len].iter().map(|byte| *byte as u8).collect();
        return CfValue::String(String::from_utf8_lossy(&bytes).into_owned());
    }
    if type_id == unsafe { CFNumberGetTypeID() } {
        let mut number = 0_i64;
        // SAFETY: CFNumberGetValue writes an i64 for kCFNumberSInt64Type.
        let ok = unsafe {
            CFNumberGetValue(
                value,
                CF_NUMBER_SINT64_TYPE,
                &mut number as *mut i64 as *mut c_void,
            )
        };
        return if ok == 0 {
            CfValue::Other
        } else {
            CfValue::Number(number)
        };
    }
    if type_id == unsafe { CFDataGetTypeID() } {
        // SAFETY: the byte pointer is valid for the data length during decode.
        let len = unsafe { CFDataGetLength(value) };
        let ptr = unsafe { CFDataGetBytePtr(value) };
        if ptr.is_null() || len < 0 {
            return CfValue::Other;
        }
        // SAFETY: ptr is valid for len bytes for the lifetime of the borrowed value.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec();
        return CfValue::Data(bytes);
    }
    if type_id == unsafe { CFBooleanGetTypeID() } {
        // SAFETY: value is a CFBooleanRef.
        return CfValue::Bool(unsafe { CFBooleanGetValue(value) } != 0);
    }
    if type_id == unsafe { CFArrayGetTypeID() } {
        // SAFETY: value is a CFArrayRef.
        let count = unsafe { CFArrayGetCount(value) };
        let mut items = Vec::new();
        for index in 0..count.max(0) {
            // SAFETY: index is within the array; the element is borrowed.
            let item = unsafe { CFArrayGetValueAtIndex(value, index) };
            // SAFETY: item is a live borrowed value.
            items.push(unsafe { decode(item) });
        }
        return CfValue::Array(items);
    }
    CfValue::Other
}
