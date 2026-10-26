//! Process-wide dispatch registry for guest handles backed by real serial and
//! USB devices.
//!
//! The runtime's Win32 handle table intentionally owns kernel objects only.
//! Serial devices are host terminal descriptors with termios state, and USB
//! dispatch needs the stable host identity, so both are stored here and
//! referenced by tagged handle values that can never collide with the normal
//! 4-byte-granularity Win32 table.

use super::{DeviceError, SerialConfig, SerialDevice, StableDeviceId};
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

/// First tagged dispatch handle.  Handles from here upward are only minted by
/// this registry; the Win32 handle table starts at 4 and is not expected to
/// reach this range.
pub const FIRST_DISPATCH_HANDLE: u64 = 0x7A11_0000;

/// Maximum serial transfer accepted by ReadFile/WriteFile.  Larger requests
/// fail with ERROR_INVALID_PARAMETER before reaching the backend.
pub const MAX_SERIAL_TRANSFER: usize = 1 << 20;

/// COMMTIMEOUTS as stored for GetCommTimeouts/SetCommTimeouts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommTimeouts {
    pub read_interval_timeout: u32,
    pub read_total_timeout_multiplier: u32,
    pub read_total_timeout_constant: u32,
    pub write_total_timeout_multiplier: u32,
    pub write_total_timeout_constant: u32,
}

impl CommTimeouts {
    pub fn read_timeout(&self) -> Duration {
        Duration::from_millis(u64::from(self.read_total_timeout_constant))
    }

    pub fn write_timeout(&self) -> Duration {
        Duration::from_millis(u64::from(self.write_total_timeout_constant))
    }
}

struct SerialEntry {
    device: SerialDevice,
    timeouts: CommTimeouts,
}

struct UsbEntry {
    device_id: StableDeviceId,
    path: String,
}

#[derive(Default)]
struct Registry {
    next_handle: u64,
    serial: BTreeMap<u64, SerialEntry>,
    usb: BTreeMap<u64, UsbEntry>,
    serial_aliases: BTreeMap<u64, u64>,
    usb_aliases: BTreeMap<u64, u64>,
    serial_refs: BTreeMap<u64, usize>,
    usb_refs: BTreeMap<u64, usize>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}

fn lock() -> MutexGuard<'static, Registry> {
    registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn next_handle(registry: &mut Registry) -> u64 {
    let handle = if registry.next_handle == 0 {
        FIRST_DISPATCH_HANDLE
    } else {
        registry.next_handle
    };
    registry.next_handle = handle + 1;
    handle
}

/// Register an opened serial device.  A second open of the same host port is
/// rejected as busy, matching Windows' exclusive COM-port semantics.
pub fn register_serial(device: SerialDevice) -> Result<u64, DeviceError> {
    let path = device.path().to_string();
    let mut registry = lock();
    if registry
        .serial
        .values()
        .any(|entry| entry.device.path() == path)
    {
        return Err(DeviceError::Busy { path });
    }
    let handle = next_handle(&mut registry);
    registry.serial.insert(
        handle,
        SerialEntry {
            device,
            timeouts: CommTimeouts::default(),
        },
    );
    registry.serial_refs.insert(handle, 1);
    Ok(handle)
}

pub fn register_usb(device_id: StableDeviceId, path: String) -> u64 {
    let mut registry = lock();
    let handle = next_handle(&mut registry);
    registry.usb.insert(handle, UsbEntry { device_id, path });
    registry.usb_refs.insert(handle, 1);
    handle
}

fn canonical_serial(registry: &Registry, handle: u64) -> Option<u64> {
    let canonical = *registry.serial_aliases.get(&handle).unwrap_or(&handle);
    registry
        .serial
        .contains_key(&canonical)
        .then_some(canonical)
}

fn canonical_usb(registry: &Registry, handle: u64) -> Option<u64> {
    let canonical = *registry.usb_aliases.get(&handle).unwrap_or(&handle);
    registry.usb.contains_key(&canonical).then_some(canonical)
}

/// Duplicate a tagged serial handle.  The alias resolves to the same device
/// and keeps it open until every duplicate is closed.
pub fn duplicate_serial(handle: u64) -> Result<u64, DeviceError> {
    let mut registry = lock();
    let canonical = canonical_serial(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    let alias = next_handle(&mut registry);
    registry.serial_aliases.insert(alias, canonical);
    *registry.serial_refs.entry(canonical).or_insert(1) += 1;
    Ok(alias)
}

pub fn duplicate_usb(handle: u64) -> Result<u64, DeviceError> {
    let mut registry = lock();
    let canonical = canonical_usb(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    let alias = next_handle(&mut registry);
    registry.usb_aliases.insert(alias, canonical);
    *registry.usb_refs.entry(canonical).or_insert(1) += 1;
    Ok(alias)
}

pub fn is_serial(handle: u64) -> bool {
    canonical_serial(&lock(), handle).is_some()
}

pub fn is_usb(handle: u64) -> bool {
    canonical_usb(&lock(), handle).is_some()
}

pub fn serial_handle_count() -> usize {
    lock().serial.len()
}

pub fn usb_handle_count() -> usize {
    lock().usb.len()
}

pub fn serial_config(handle: u64) -> Result<SerialConfig, DeviceError> {
    let registry = lock();
    let canonical = canonical_serial(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    registry
        .serial
        .get(&canonical)
        .map(|entry| entry.device.config())
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })
}

pub fn serial_configure(handle: u64, config: SerialConfig) -> Result<(), DeviceError> {
    let mut registry = lock();
    let canonical = canonical_serial(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    let entry = registry
        .serial
        .get_mut(&canonical)
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })?;
    entry.device.configure(config)
}

pub fn serial_read(
    handle: u64,
    buffer: &mut [u8],
    timeout: Duration,
) -> Result<usize, DeviceError> {
    let mut registry = lock();
    let canonical = canonical_serial(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    let entry = registry
        .serial
        .get_mut(&canonical)
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })?;
    entry.device.read(buffer, timeout)
}

pub fn serial_write(handle: u64, buffer: &[u8], timeout: Duration) -> Result<usize, DeviceError> {
    let mut registry = lock();
    let canonical = canonical_serial(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    let entry = registry
        .serial
        .get_mut(&canonical)
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })?;
    entry.device.write(buffer, timeout)
}

pub fn serial_flush(handle: u64) -> Result<(), DeviceError> {
    let mut registry = lock();
    let canonical = canonical_serial(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    let entry = registry
        .serial
        .get_mut(&canonical)
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })?;
    entry.device.flush()
}

pub fn serial_escape(handle: u64, function: u32) -> Result<(), DeviceError> {
    let mut registry = lock();
    let canonical = canonical_serial(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    let entry = registry
        .serial
        .get_mut(&canonical)
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })?;
    entry.device.escape(function)
}

pub fn serial_clear_error(handle: u64) -> Result<(), DeviceError> {
    if canonical_serial(&lock(), handle).is_some() {
        Ok(())
    } else {
        Err(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })
    }
}

pub fn serial_timeouts(handle: u64) -> Result<CommTimeouts, DeviceError> {
    let registry = lock();
    let canonical = canonical_serial(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    registry
        .serial
        .get(&canonical)
        .map(|entry| entry.timeouts)
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })
}

pub fn set_serial_timeouts(handle: u64, timeouts: CommTimeouts) -> Result<(), DeviceError> {
    let mut registry = lock();
    let canonical = canonical_serial(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    let entry = registry
        .serial
        .get_mut(&canonical)
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })?;
    entry.timeouts = timeouts;
    Ok(())
}

/// Remove one reference to a serial handle.  The device closes when the last
/// reference (original or duplicate) is closed.
pub fn close_serial(handle: u64) -> Result<(), DeviceError> {
    let mut registry = lock();
    let canonical = canonical_serial(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    if handle != canonical {
        registry.serial_aliases.remove(&handle);
    }
    let remaining = {
        let refs = registry.serial_refs.entry(canonical).or_insert(1);
        *refs = refs.saturating_sub(1);
        *refs
    };
    if remaining > 0 {
        return Ok(());
    }
    registry.serial_refs.remove(&canonical);
    registry
        .serial_aliases
        .retain(|_, target| *target != canonical);
    let mut entry = registry
        .serial
        .remove(&canonical)
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })?;
    entry.device.close()
}

pub fn close_usb(handle: u64) -> bool {
    let mut registry = lock();
    let Some(canonical) = canonical_usb(&registry, handle) else {
        return false;
    };
    if handle != canonical {
        registry.usb_aliases.remove(&handle);
    }
    let remaining = {
        let refs = registry.usb_refs.entry(canonical).or_insert(1);
        *refs = refs.saturating_sub(1);
        *refs
    };
    if remaining > 0 {
        return true;
    }
    registry.usb_refs.remove(&canonical);
    registry
        .usb_aliases
        .retain(|_, target| *target != canonical);
    registry.usb.remove(&canonical).is_some()
}

pub fn usb_device_id(handle: u64) -> Result<StableDeviceId, DeviceError> {
    let registry = lock();
    let canonical = canonical_usb(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    registry
        .usb
        .get(&canonical)
        .map(|entry| entry.device_id)
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })
}

pub fn usb_path(handle: u64) -> Result<String, DeviceError> {
    let registry = lock();
    let canonical = canonical_usb(&registry, handle).ok_or(DeviceError::NotOpen {
        id: StableDeviceId::from_raw(handle),
    })?;
    registry
        .usb
        .get(&canonical)
        .map(|entry| entry.path.clone())
        .ok_or(DeviceError::NotOpen {
            id: StableDeviceId::from_raw(handle),
        })
}

#[cfg(test)]
pub fn reset_for_tests() {
    let mut registry = lock();
    registry.serial.clear();
    registry.usb.clear();
    registry.serial_aliases.clear();
    registry.usb_aliases.clear();
    registry.serial_refs.clear();
    registry.usb_refs.clear();
    registry.next_handle = 0;
}

#[cfg(test)]
mod duplicate_tests {
    use super::*;

    #[test]
    fn duplicated_serial_and_usb_handles_share_lifetime_until_last_close() {
        reset_for_tests();
        let port = "/dev/casa1-test-serial";
        let serial = register_serial(SerialDevice::test_device(port)).expect("serial");
        let serial_copy = duplicate_serial(serial).expect("duplicate serial");
        assert_ne!(serial_copy, serial);
        assert!(is_serial(serial));
        assert!(is_serial(serial_copy));
        close_serial(serial_copy).expect("close duplicate");
        assert!(is_serial(serial), "the original keeps the device open");
        assert_eq!(
            serial_config(serial).expect("config").baud_rate,
            SerialConfig::default().baud_rate
        );
        close_serial(serial).expect("close original");
        assert!(!is_serial(serial));
        assert!(!is_serial(serial_copy));
        assert_eq!(
            duplicate_serial(serial),
            Err(DeviceError::NotOpen {
                id: StableDeviceId::from_raw(serial)
            })
        );

        let device_id = StableDeviceId::from_raw(0xCA5A_0002);
        let usb = register_usb(device_id, "usb-test".to_string());
        let usb_copy = duplicate_usb(usb).expect("duplicate usb");
        assert_ne!(usb_copy, usb);
        assert_eq!(usb_device_id(usb_copy), Ok(device_id));
        assert!(close_usb(usb_copy));
        assert!(is_usb(usb));
        assert!(close_usb(usb));
        assert!(!is_usb(usb));
        assert!(!is_usb(usb_copy));
        assert_eq!(
            duplicate_usb(usb),
            Err(DeviceError::NotOpen {
                id: StableDeviceId::from_raw(usb)
            })
        );
    }
}
