//! PCI-specific IOKit/CoreFoundation bindings.
//!
//! The base HID/serial/USB bridge keeps its own include file.  PCI needs two
//! extra capabilities the base bindings deliberately do not expose: dictionary
//! decoding (`IODeviceMemory` is an array of dictionaries) and a checked
//! service match that preserves the IOKit return code.  The platform calls are
//! compiled only for the real host build; the pure dictionary decoding used by
//! the bridge is unit-tested.

use std::ffi::{CString, c_char, c_void};
use std::ptr;

pub const KIORETURN_BAD_ARGUMENT: i32 = 0xe000_02c2_u32 as i32;
pub const KIORETURN_UNSUPPORTED: i32 = 0xe000_02c7_u32 as i32;
pub const KIORETURN_NOT_PRIVILEGED: i32 = 0xe000_02c1_u32 as i32;
pub const KIORETURN_NOT_PERMITTED: i32 = 0xe000_02e2_u32 as i32;

/// A decoded CoreFoundation value from an IORegistry property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PciCfValue {
    String(String),
    Number(i64),
    Bool(bool),
    Data(Vec<u8>),
    Array(Vec<PciCfValue>),
    Dictionary(Vec<(String, PciCfValue)>),
    Other,
}

/// Read a numeric field from a decoded dictionary.
pub fn dictionary_number(fields: &[(String, PciCfValue)], key: &str) -> Option<u64> {
    fields.iter().find_map(|(name, value)| {
        if name == key {
            match value {
                PciCfValue::Number(number) => u64::try_from(*number).ok(),
                _ => None,
            }
        } else {
            None
        }
    })
}

/// Decode `IODeviceMemory`-style `(address, length)` dictionaries.
pub fn dictionary_ranges(value: &PciCfValue) -> Option<Vec<(u64, u64)>> {
    let PciCfValue::Array(entries) = value else {
        return None;
    };
    let mut ranges = Vec::new();
    for entry in entries {
        let PciCfValue::Dictionary(fields) = entry else {
            continue;
        };
        let address = dictionary_number(fields, "address");
        let length = dictionary_number(fields, "length");
        if let (Some(address), Some(length)) = (address, length) {
            ranges.push((address, length));
        }
    }
    Some(ranges)
}

/// Flatten `IOServiceDEXTEntitlements` into its real entitlement strings.
pub fn entitlement_strings(value: &PciCfValue) -> Option<Vec<String>> {
    let PciCfValue::Array(groups) = value else {
        return None;
    };
    let mut entitlements = Vec::new();
    for group in groups {
        match group {
            PciCfValue::Array(items) => {
                for item in items {
                    if let PciCfValue::String(text) = item {
                        entitlements.push(text.clone());
                    }
                }
            }
            PciCfValue::String(text) => entitlements.push(text.clone()),
            _ => {}
        }
    }
    Some(entitlements)
}

#[cfg(all(target_os = "macos", not(test)))]
mod platform {
    use super::*;

    const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const CF_NUMBER_SINT64_TYPE: u32 = 4;
    const KCF_ALLOCATOR_DEFAULT: *const c_void = ptr::null();
    const KCF_PROPERTY_LIST_IMMUTABLE: u32 = 0;
    const IO_MASTER_PORT_DEFAULT: u32 = 0;

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
        fn CFDictionaryGetCount(dictionary: *const c_void) -> isize;
        fn CFDictionaryGetKeysAndValues(
            dictionary: *const c_void,
            keys: *mut *const c_void,
            values: *mut *const c_void,
        );
        fn CFGetTypeID(value: *const c_void) -> libc::c_ulong;
        fn CFStringGetTypeID() -> libc::c_ulong;
        fn CFNumberGetTypeID() -> libc::c_ulong;
        fn CFDataGetTypeID() -> libc::c_ulong;
        fn CFBooleanGetTypeID() -> libc::c_ulong;
        fn CFBooleanGetValue(boolean: *const c_void) -> u8;
        fn CFArrayGetTypeID() -> libc::c_ulong;
        fn CFDictionaryGetTypeID() -> libc::c_ulong;
        fn CFRelease(value: *const c_void);
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
    }

    struct OwnedValue(*const c_void);

    impl Drop for OwnedValue {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: every OwnedValue holds a retained property.
                unsafe { CFRelease(self.0) };
            }
        }
    }

    impl OwnedValue {
        fn value(&self) -> PciCfValue {
            // SAFETY: self.0 is a live CoreFoundation value for this borrow.
            unsafe { decode(self.0) }
        }
    }

    pub struct PciService(u32);

    impl PciService {
        fn property(&self, key: &str) -> Option<OwnedValue> {
            let c_key = CString::new(key).ok()?;
            // SAFETY: c_key is NUL-terminated.
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
            // SAFETY: cf_key is a valid CFStringRef; the result is retained.
            let value = unsafe {
                IORegistryEntryCreateCFProperty(
                    self.0,
                    cf_key,
                    KCF_ALLOCATOR_DEFAULT,
                    KCF_PROPERTY_LIST_IMMUTABLE,
                )
            };
            // SAFETY: release the temporary key.
            unsafe { CFRelease(cf_key) };
            (!value.is_null()).then(|| OwnedValue(value))
        }

        pub fn value(&self, key: &str) -> Option<PciCfValue> {
            self.property(key).map(|value| value.value())
        }

        pub fn data(&self, key: &str) -> Option<Vec<u8>> {
            match self.value(key)? {
                PciCfValue::Data(bytes) => Some(bytes),
                _ => None,
            }
        }

        pub fn string(&self, key: &str) -> Option<String> {
            match self.value(key)? {
                PciCfValue::String(text) => Some(text),
                _ => None,
            }
        }

        pub fn registry_entry_id(&self) -> Option<u64> {
            let mut id = 0_u64;
            // SAFETY: out points to a valid u64.
            let kr = unsafe { IORegistryEntryGetRegistryEntryID(self.0, &mut id) };
            (kr == 0).then_some(id)
        }
    }

    impl Drop for PciService {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: PciService owns its io_object_t reference.
                unsafe { IOObjectRelease(self.0) };
            }
        }
    }

    pub fn matching_services_checked(class: &str) -> Result<Vec<PciService>, i32> {
        let c_class = CString::new(class).map_err(|_| KIORETURN_BAD_ARGUMENT)?;
        // SAFETY: IOServiceMatching copies the class name.
        let matching = unsafe { IOServiceMatching(c_class.as_ptr()) };
        if matching.is_null() {
            return Err(KIORETURN_UNSUPPORTED);
        }
        // SAFETY: IOServiceGetMatchingServices consumes the matching dictionary.
        let mut iterator = 0_u32;
        let kr = unsafe {
            IOServiceGetMatchingServices(IO_MASTER_PORT_DEFAULT, matching, &mut iterator)
        };
        if kr != 0 {
            return Err(kr);
        }
        if iterator == 0 {
            return Ok(Vec::new());
        }
        let mut services = Vec::new();
        loop {
            // SAFETY: iterator is a live io_iterator_t.
            let service = unsafe { IOIteratorNext(iterator) };
            if service == 0 {
                break;
            }
            services.push(PciService(service));
        }
        // SAFETY: release the iterator.
        unsafe { IOObjectRelease(iterator) };
        Ok(services)
    }

    unsafe fn decode(value: *const c_void) -> PciCfValue {
        if value.is_null() {
            return PciCfValue::Other;
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
                return PciCfValue::Other;
            }
            let len = buffer
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(buffer.len());
            let bytes: Vec<u8> = buffer[..len].iter().map(|byte| *byte as u8).collect();
            return PciCfValue::String(String::from_utf8_lossy(&bytes).into_owned());
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
                PciCfValue::Other
            } else {
                PciCfValue::Number(number)
            };
        }
        if type_id == unsafe { CFDataGetTypeID() } {
            // SAFETY: the byte pointer is valid for the data length during decode.
            let len = unsafe { CFDataGetLength(value) };
            let ptr = unsafe { CFDataGetBytePtr(value) };
            if ptr.is_null() || len < 0 {
                return PciCfValue::Other;
            }
            // SAFETY: ptr is valid for len bytes for the borrowed value's lifetime.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec();
            return PciCfValue::Data(bytes);
        }
        if type_id == unsafe { CFBooleanGetTypeID() } {
            // SAFETY: value is a CFBooleanRef.
            return PciCfValue::Bool(unsafe { CFBooleanGetValue(value) } != 0);
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
            return PciCfValue::Array(items);
        }
        if type_id == unsafe { CFDictionaryGetTypeID() } {
            // SAFETY: value is a CFDictionaryRef.
            let count = unsafe { CFDictionaryGetCount(value) };
            if count <= 0 {
                return PciCfValue::Dictionary(Vec::new());
            }
            let mut keys = vec![ptr::null(); count as usize];
            let mut values = vec![ptr::null(); count as usize];
            // SAFETY: both buffers have room for `count` borrowed values.
            unsafe { CFDictionaryGetKeysAndValues(value, keys.as_mut_ptr(), values.as_mut_ptr()) };
            let mut fields = Vec::new();
            for (key, value) in keys.iter().zip(values.iter()) {
                // SAFETY: keys and values are live borrowed CoreFoundation values.
                let PciCfValue::String(key) = (unsafe { decode(*key) }) else {
                    continue;
                };
                // SAFETY: value is a live borrowed CoreFoundation value.
                fields.push((key, unsafe { decode(*value) }));
            }
            return PciCfValue::Dictionary(fields);
        }
        PciCfValue::Other
    }
}

#[cfg(all(target_os = "macos", not(test)))]
pub use platform::{PciService, matching_services_checked};

#[cfg(test)]
mod tests {
    use super::*;

    fn dictionary(address: u64, length: u64) -> PciCfValue {
        PciCfValue::Dictionary(vec![
            ("address".to_string(), PciCfValue::Number(address as i64)),
            ("length".to_string(), PciCfValue::Number(length as i64)),
        ])
    }

    #[test]
    fn malformed_dictionary_values_are_rejected_without_synthesizing_ranges() {
        assert_eq!(dictionary_ranges(&PciCfValue::Dictionary(Vec::new())), None);
        assert_eq!(
            dictionary_ranges(&PciCfValue::Array(vec![
                PciCfValue::String("not-a-dictionary".to_string()),
                PciCfValue::Dictionary(vec![
                    ("address".to_string(), PciCfValue::String("bad".to_string())),
                    ("length".to_string(), PciCfValue::Number(0x100)),
                ]),
                PciCfValue::Dictionary(vec![("address".to_string(), PciCfValue::Number(0x1000)),]),
                dictionary(0x2000, 0x40),
            ])),
            Some(vec![(0x2000, 0x40)])
        );
        assert_eq!(
            dictionary_number(
                &[("address".to_string(), PciCfValue::String("bad".to_string()))],
                "address"
            ),
            None
        );
        assert_eq!(
            dictionary_number(
                &[("address".to_string(), PciCfValue::Number(-1))],
                "address"
            ),
            None
        );
        assert_eq!(
            dictionary_number(&dictionary(7, 8).into_entries(), "length"),
            Some(8)
        );
        assert_eq!(
            entitlement_strings(&PciCfValue::Array(vec![
                PciCfValue::Array(vec![
                    PciCfValue::String("a".to_string()),
                    PciCfValue::Number(1),
                ]),
                PciCfValue::String("b".to_string()),
                PciCfValue::Bool(false),
            ])),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(entitlement_strings(&PciCfValue::Other), None);
    }

    trait IntoEntries {
        fn into_entries(self) -> Vec<(String, PciCfValue)>;
    }

    impl IntoEntries for PciCfValue {
        fn into_entries(self) -> Vec<(String, PciCfValue)> {
            match self {
                PciCfValue::Dictionary(entries) => entries,
                _ => Vec::new(),
            }
        }
    }
}
