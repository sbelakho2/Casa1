//! Real PCI device enumeration and a DriverKit-equivalent PCI user client.
//!
//! Enumeration uses `IOServiceMatching("IOPCIDevice")` and reads the device's
//! own IORegistry properties (`vendor-id`, `device-id`, `class-code`,
//! `revision-id`, `subsystem-*`, `IODeviceMemory`).  Configuration-space reads
//! are served only for the fields the host actually publishes through the
//! registry; every other byte needs the DriverKit PCI transport entitlement and
//! is reported as an exact permission error.  No device or BAR is synthesized.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use super::error::DeviceError;
use super::host_bridge::{HostDeviceBridge, HostOperation, HostUserClient};
use super::model::{DeviceClass, DeviceRecord, DeviceTable, HotplugEvent, StableDeviceId};

#[cfg(all(target_os = "macos", not(test)))]
use super::ffi_ext;

/// Size of the standard PCI configuration space.
pub const PCI_CONFIG_SPACE_SIZE: usize = 256;

/// Offset of the vendor id in PCI configuration space.
pub const PCI_VENDOR_ID_OFFSET: u16 = 0x00;
/// Offset of the device id in PCI configuration space.
pub const PCI_DEVICE_ID_OFFSET: u16 = 0x02;
/// Offset of the revision id in PCI configuration space.
pub const PCI_REVISION_ID_OFFSET: u16 = 0x08;
/// Offset of the class code (prog-if, subclass, class) in configuration space.
pub const PCI_CLASS_CODE_OFFSET: u16 = 0x09;
/// Offset of the subsystem vendor id in configuration space.
pub const PCI_SUBSYSTEM_VENDOR_OFFSET: u16 = 0x2c;
/// Offset of the subsystem id in configuration space.
pub const PCI_SUBSYSTEM_ID_OFFSET: u16 = 0x2e;

/// User-client request: map one BAR.
pub const PCI_CONTROL_MAP_BAR: u32 = 0x0000_0001;
/// User-client request: read one BAR.
pub const PCI_CONTROL_READ_BAR: u32 = 0x0000_0002;

/// Length of the BAR request payload: index (1) + offset (8) + length (8).
const BAR_REQUEST_LEN: usize = 17;

/// One I/O or memory BAR reported by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PciBar {
    /// BAR index as published by the host.
    pub index: u8,
    /// Base address in host physical address space.
    pub address: u64,
    /// Window length in bytes.
    pub size: u64,
}

/// One real `IOPCIDevice` and the identity the host exposes for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciDeviceInfo {
    pub id: StableDeviceId,
    pub registry_entry_id: u64,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u32,
    pub revision_id: u8,
    pub subsystem_vendor_id: Option<u16>,
    pub subsystem_id: Option<u16>,
    pub bus: Option<u8>,
    pub device: Option<u8>,
    pub function: Option<u8>,
    pub bars: Vec<PciBar>,
    pub driverkit_entitlements: Vec<String>,
}

impl PciDeviceInfo {
    pub fn record(&self) -> DeviceRecord {
        DeviceRecord {
            id: self.id,
            class: DeviceClass::Pci,
            vendor_id: Some(self.vendor_id),
            product_id: Some(self.device_id),
            manufacturer: None,
            product: match (self.bus, self.device, self.function) {
                (Some(bus), Some(device), Some(function)) => {
                    Some(format!("PCI {bus:02x}:{device:02x}.{function}"))
                }
                _ => None,
            },
            serial_number: None,
            path: Some(format!("IOPCIDevice:{:016x}", self.registry_entry_id)),
            registry_entry_id: self.registry_entry_id,
        }
    }

    pub fn bar(&self, index: u8) -> Option<&PciBar> {
        self.bars.iter().find(|bar| bar.index == index)
    }

    /// Read a byte range from the PCI configuration header fields the host
    /// publishes through the registry.
    ///
    /// Unpublished bytes require the DriverKit PCI transport entitlement, so
    /// they fail with an exact permission error instead of fabricated zeroes.
    pub fn config_read(&self, offset: u16, length: usize) -> Result<Vec<u8>, DeviceError> {
        if length == 0 {
            return Err(DeviceError::InvalidArgument {
                field: "length",
                reason: "must be non-zero",
            });
        }
        let end = usize::from(offset)
            .checked_add(length)
            .ok_or(DeviceError::InvalidArgument {
                field: "config_offset",
                reason: "range overflows address space",
            })?;
        if end > PCI_CONFIG_SPACE_SIZE {
            return Err(DeviceError::InvalidArgument {
                field: "config_offset",
                reason: "outside 256-byte config space",
            });
        }
        let mut bytes = Vec::with_capacity(length);
        for position in usize::from(offset)..end {
            let byte = self
                .config_byte(position as u16)
                .ok_or(DeviceError::PermissionDenied {
                    operation: "IOPCIDevice config space",
                })?;
            bytes.push(byte);
        }
        Ok(bytes)
    }

    fn config_byte(&self, offset: u16) -> Option<u8> {
        match offset {
            PCI_VENDOR_ID_OFFSET => Some((self.vendor_id & 0x00ff) as u8),
            0x01 => Some((self.vendor_id >> 8) as u8),
            PCI_DEVICE_ID_OFFSET => Some((self.device_id & 0x00ff) as u8),
            0x03 => Some((self.device_id >> 8) as u8),
            PCI_REVISION_ID_OFFSET => Some(self.revision_id),
            PCI_CLASS_CODE_OFFSET => Some((self.class_code & 0x0000_00ff) as u8),
            0x0a => Some(((self.class_code >> 8) & 0xff) as u8),
            0x0b => Some(((self.class_code >> 16) & 0xff) as u8),
            PCI_SUBSYSTEM_VENDOR_OFFSET => {
                self.subsystem_vendor_id.map(|value| (value & 0x00ff) as u8)
            }
            0x2d => self.subsystem_vendor_id.map(|value| (value >> 8) as u8),
            PCI_SUBSYSTEM_ID_OFFSET => self.subsystem_id.map(|value| (value & 0x00ff) as u8),
            0x2f => self.subsystem_id.map(|value| (value >> 8) as u8),
            _ => None,
        }
    }
}

/// Build BAR records from `(address, length)` ranges published by the host.
///
/// Zero-length entries are not BARs and are skipped rather than exposed as a
/// zero-sized window.
pub fn bars_from_ranges(ranges: &[(u64, u64)]) -> Vec<PciBar> {
    let mut bars = Vec::new();
    for (address, size) in ranges {
        if *size == 0 {
            continue;
        }
        bars.push(PciBar {
            index: bars.len() as u8,
            address: *address,
            size: *size,
        });
    }
    bars
}

/// Parse IOKit's `pcidebug` (`bus:device:function`, optionally followed by a
/// range hint such as `(1:128)`).
pub fn parse_pcidebug(value: &str) -> Option<(u8, u8, u8)> {
    let head = value.split('(').next()?;
    let mut parts = head.split(':');
    let bus = parts.next()?.parse().ok()?;
    let device = parts.next()?.parse().ok()?;
    let function = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((bus, device, function))
}

/// Derive the stable id for a PCI device from host-reported identity.
pub fn stable_pci_id(
    vendor_id: u16,
    device_id: u16,
    pcidebug: Option<&str>,
    registry_entry_id: u64,
) -> StableDeviceId {
    let vendor = format!("{vendor_id:04x}");
    let device = format!("{device_id:04x}");
    let registry = registry_entry_id.to_string();
    let mut parts = vec![vendor.as_str(), device.as_str()];
    if let Some(debug) = pcidebug.filter(|value| !value.is_empty()) {
        parts.push(debug);
    }
    if parts.len() == 2 {
        parts.push(registry.as_str());
    }
    StableDeviceId::derive(DeviceClass::Pci, &parts)
}

/// A PCI user client.  Reads use the live device set so an unplugged handle
/// fails with [`DeviceError::Unplugged`] instead of returning stale bytes.
pub struct PciUserClient {
    info: PciDeviceInfo,
    live: Arc<Mutex<BTreeSet<StableDeviceId>>>,
}

impl PciUserClient {
    fn ensure_live(&self) -> Result<(), DeviceError> {
        let live = self.live.lock().map_err(|_| DeviceError::Io {
            operation: "pci live registry",
            os_code: 0,
        })?;
        if live.contains(&self.info.id) {
            Ok(())
        } else {
            Err(DeviceError::Unplugged { id: self.info.id })
        }
    }
}

impl HostUserClient for PciUserClient {
    fn device_id(&self) -> StableDeviceId {
        self.info.id
    }

    fn class(&self) -> DeviceClass {
        DeviceClass::Pci
    }

    fn read(&mut self, offset: u16, length: usize) -> Result<Vec<u8>, DeviceError> {
        self.ensure_live()?;
        self.info.config_read(offset, length)
    }

    fn control(&mut self, request: u32, payload: &[u8]) -> Result<Vec<u8>, DeviceError> {
        self.ensure_live()?;
        let (index, offset, length) = parse_bar_request(payload)?;
        validate_bar_request(&self.info.bars, index, offset, length)?;
        match request {
            PCI_CONTROL_MAP_BAR => Err(DeviceError::Unsupported {
                feature: "pci BAR mapping requires DriverKit PCI transport entitlement",
            }),
            PCI_CONTROL_READ_BAR => Err(DeviceError::Unsupported {
                feature: "pci BAR read requires DriverKit PCI transport entitlement",
            }),
            _ => Err(DeviceError::InvalidArgument {
                field: "request",
                reason: "unknown PCI user-client request",
            }),
        }
    }
}

fn parse_bar_request(payload: &[u8]) -> Result<(u8, u64, usize), DeviceError> {
    if payload.len() != BAR_REQUEST_LEN {
        return Err(DeviceError::InvalidArgument {
            field: "bar_request",
            reason: "expected 17 bytes",
        });
    }
    let index = payload[0];
    let mut offset_bytes = [0_u8; 8];
    offset_bytes.copy_from_slice(&payload[1..9]);
    let mut length_bytes = [0_u8; 8];
    length_bytes.copy_from_slice(&payload[9..17]);
    Ok((
        index,
        u64::from_le_bytes(offset_bytes),
        u64::from_le_bytes(length_bytes) as usize,
    ))
}

fn validate_bar_request(
    bars: &[PciBar],
    index: u8,
    offset: u64,
    length: usize,
) -> Result<(), DeviceError> {
    if length == 0 {
        return Err(DeviceError::InvalidArgument {
            field: "length",
            reason: "must be non-zero",
        });
    }
    let bar = bars
        .iter()
        .find(|bar| bar.index == index)
        .ok_or(DeviceError::InvalidArgument {
            field: "bar_index",
            reason: "no such BAR",
        })?;
    let end = offset
        .checked_add(length as u64)
        .ok_or(DeviceError::InvalidArgument {
            field: "bar_offset",
            reason: "range overflows address space",
        })?;
    if end > bar.size {
        return Err(DeviceError::InvalidArgument {
            field: "bar_offset",
            reason: "range exceeds BAR size",
        });
    }
    Ok(())
}

const PCI_OPERATIONS: &[HostOperation] = &[
    HostOperation::Enumerate,
    HostOperation::Open,
    HostOperation::ConfigSpaceRead,
];

/// PCI bridge table keyed by stable ids.
#[derive(Debug, Clone, Default)]
pub struct PciBridge {
    devices: Vec<PciDeviceInfo>,
    table: DeviceTable,
    live: Arc<Mutex<BTreeSet<StableDeviceId>>>,
}

impl PciBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devices(&self) -> &[PciDeviceInfo] {
        &self.devices
    }

    pub fn table(&self) -> &DeviceTable {
        &self.table
    }

    pub fn device(&self, id: StableDeviceId) -> Option<&PciDeviceInfo> {
        self.devices.iter().find(|device| device.id == id)
    }

    pub fn apply(&mut self, devices: Vec<PciDeviceInfo>) -> Vec<HotplugEvent> {
        let mut devices = devices;
        devices.sort_by_key(|device| device.id);
        devices.dedup_by_key(|device| device.id);
        let records = devices.iter().map(PciDeviceInfo::record).collect();
        self.devices = devices;
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        live.clear();
        live.extend(self.devices.iter().map(|device| device.id));
        drop(live);
        self.table.reconcile(records)
    }

    pub fn enumerate(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        let devices = scan_pci_devices()?;
        Ok(self.apply(devices))
    }
}

impl HostDeviceBridge for PciBridge {
    fn class(&self) -> DeviceClass {
        DeviceClass::Pci
    }

    fn enumerate(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        PciBridge::enumerate(self)
    }

    fn records(&self) -> Vec<DeviceRecord> {
        self.table.records()
    }

    fn record(&self, id: StableDeviceId) -> Option<DeviceRecord> {
        self.table.get(id).cloned()
    }

    fn supported_operations(&self) -> &'static [HostOperation] {
        PCI_OPERATIONS
    }

    fn open_user_client(&self, id: StableDeviceId) -> Result<Box<dyn HostUserClient>, DeviceError> {
        let info = self
            .device(id)
            .ok_or(DeviceError::DeviceMissing { id })?
            .clone();
        Ok(Box::new(PciUserClient {
            info,
            live: Arc::clone(&self.live),
        }))
    }
}

#[cfg(all(target_os = "macos", not(test)))]
pub fn scan_pci_devices() -> Result<Vec<PciDeviceInfo>, DeviceError> {
    let services = ffi_ext::matching_services_checked("IOPCIDevice").map_err(|kr| match kr {
        ffi_ext::KIORETURN_NOT_PRIVILEGED | ffi_ext::KIORETURN_NOT_PERMITTED => {
            DeviceError::PermissionDenied {
                operation: "IOServiceGetMatchingServices(IOPCIDevice)",
            }
        }
        ffi_ext::KIORETURN_UNSUPPORTED => DeviceError::Unsupported {
            feature: "IOPCIDevice enumeration",
        },
        other => DeviceError::Io {
            operation: "IOServiceGetMatchingServices(IOPCIDevice)",
            os_code: other,
        },
    })?;
    let mut devices = Vec::new();
    let mut seen = BTreeSet::new();
    for service in services {
        let Some(registry_entry_id) = service.registry_entry_id() else {
            continue;
        };
        if !seen.insert(registry_entry_id) {
            continue;
        }
        if let Some(device) = pci_snapshot(&service, registry_entry_id) {
            devices.push(device);
        }
    }
    devices.sort_by_key(|device| device.id);
    Ok(devices)
}

#[cfg(all(target_os = "macos", not(test)))]
fn pci_snapshot(service: &ffi_ext::PciService, registry_entry_id: u64) -> Option<PciDeviceInfo> {
    let vendor_id = le_u32_data(service, "vendor-id")? as u16;
    let device_id = le_u32_data(service, "device-id")? as u16;
    let class_code = le_u32_data(service, "class-code").unwrap_or(0);
    let revision_id = le_u32_data(service, "revision-id").unwrap_or(0) as u8;
    let subsystem_vendor_id = le_u32_data(service, "subsystem-vendor-id").map(|value| value as u16);
    let subsystem_id = le_u32_data(service, "subsystem-id").map(|value| value as u16);
    let pcidebug = service.string("pcidebug");
    let (bus, device, function) = pcidebug
        .as_deref()
        .and_then(parse_pcidebug)
        .map_or((None, None, None), |(bus, device, function)| {
            (Some(bus), Some(device), Some(function))
        });
    let bars = service
        .value("IODeviceMemory")
        .and_then(|value| ffi_ext::dictionary_ranges(&value))
        .map(|ranges| bars_from_ranges(&ranges))
        .unwrap_or_default();
    let driverkit_entitlements = service
        .value("IOServiceDEXTEntitlements")
        .and_then(|value| ffi_ext::entitlement_strings(&value))
        .unwrap_or_default();
    Some(PciDeviceInfo {
        id: stable_pci_id(vendor_id, device_id, pcidebug.as_deref(), registry_entry_id),
        registry_entry_id,
        vendor_id,
        device_id,
        class_code,
        revision_id,
        subsystem_vendor_id,
        subsystem_id,
        bus,
        device,
        function,
        bars,
        driverkit_entitlements,
    })
}

#[cfg(all(target_os = "macos", not(test)))]
fn le_u32_data(service: &ffi_ext::PciService, key: &str) -> Option<u32> {
    let bytes = service.data(key)?;
    (bytes.len() >= 4).then(|| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
pub fn scan_pci_devices() -> Result<Vec<PciDeviceInfo>, DeviceError> {
    Ok(Vec::new())
}

#[cfg(all(not(target_os = "macos"), not(test)))]
pub fn scan_pci_devices() -> Result<Vec<PciDeviceInfo>, DeviceError> {
    Err(DeviceError::Unsupported {
        feature: "PCI enumeration requires macOS IOKit",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn info() -> PciDeviceInfo {
        PciDeviceInfo {
            id: StableDeviceId::from_raw(0x900),
            registry_entry_id: 0x900,
            vendor_id: 0x106b,
            device_id: 0x1901,
            class_code: 0x000d_2000,
            revision_id: 0x02,
            subsystem_vendor_id: Some(0x106b),
            subsystem_id: Some(0x1901),
            bus: Some(2),
            device: Some(0),
            function: Some(0),
            bars: bars_from_ranges(&[(0x1_0000_0000, 0x1_0000), (0x2_0000_0000, 0x20_0000)]),
            driverkit_entitlements: vec!["com.apple.developer.driverkit.transport.pci".to_string()],
        }
    }

    fn bar_request(index: u8, offset: u64, length: u64) -> Vec<u8> {
        let mut payload = vec![index];
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(&length.to_le_bytes());
        payload
    }

    #[test]
    fn pci_absent_device_and_stale_handle_report_exact_errors() {
        let mut bridge = PciBridge::new();
        let id = StableDeviceId::from_raw(0x900);
        assert_eq!(
            bridge.open_user_client(id).map(|_| ()),
            Err(DeviceError::DeviceMissing { id })
        );

        let mut events = bridge.apply(vec![info()]);
        assert_eq!(events.len(), 1);
        events.clear();
        let mut client = bridge.open_user_client(id).expect("open real PCI fixture");
        assert_eq!(client.device_id(), id);
        assert_eq!(client.class(), DeviceClass::Pci);
        assert_eq!(
            client.read(PCI_VENDOR_ID_OFFSET, 4),
            Ok(vec![0x6b, 0x10, 0x01, 0x19])
        );

        let removed = bridge.apply(Vec::new());
        assert_eq!(
            removed,
            vec![HotplugEvent::Removed {
                record: info().record()
            }]
        );
        assert_eq!(
            client.read(PCI_VENDOR_ID_OFFSET, 2),
            Err(DeviceError::Unplugged { id })
        );
        assert_eq!(
            client.control(PCI_CONTROL_MAP_BAR, &bar_request(0, 0, 1)),
            Err(DeviceError::Unplugged { id })
        );
    }

    #[test]
    fn pci_config_space_malformed_and_permission_denied_are_exact() {
        let device = info();
        assert_eq!(
            device.config_read(0, 0),
            Err(DeviceError::InvalidArgument {
                field: "length",
                reason: "must be non-zero"
            })
        );
        assert_eq!(
            device.config_read(1, usize::MAX),
            Err(DeviceError::InvalidArgument {
                field: "config_offset",
                reason: "range overflows address space"
            })
        );
        assert_eq!(
            device.config_read(0xff, 2),
            Err(DeviceError::InvalidArgument {
                field: "config_offset",
                reason: "outside 256-byte config space"
            })
        );
        assert_eq!(
            device.config_read(0x0c, 1),
            Err(DeviceError::PermissionDenied {
                operation: "IOPCIDevice config space"
            })
        );
        assert_eq!(
            device.config_read(PCI_REVISION_ID_OFFSET, 4),
            Ok(vec![0x02, 0x00, 0x20, 0x0d])
        );
        assert_eq!(
            device.config_read(PCI_SUBSYSTEM_VENDOR_OFFSET, 4),
            Ok(vec![0x6b, 0x10, 0x01, 0x19])
        );

        let mut no_subsystem = info();
        no_subsystem.subsystem_vendor_id = None;
        no_subsystem.subsystem_id = None;
        assert_eq!(
            no_subsystem.config_read(PCI_SUBSYSTEM_VENDOR_OFFSET, 2),
            Err(DeviceError::PermissionDenied {
                operation: "IOPCIDevice config space"
            })
        );
    }

    #[test]
    fn pci_bar_request_malformed_and_entitlement_limited_are_exact() {
        let mut bridge = PciBridge::new();
        let id = info().id;
        let _ = bridge.apply(vec![info()]);
        let mut client = bridge.open_user_client(id).expect("open PCI fixture");

        assert_eq!(
            client.control(PCI_CONTROL_MAP_BAR, &[0]),
            Err(DeviceError::InvalidArgument {
                field: "bar_request",
                reason: "expected 17 bytes"
            })
        );
        assert_eq!(
            client.control(PCI_CONTROL_MAP_BAR, &bar_request(9, 0, 1)),
            Err(DeviceError::InvalidArgument {
                field: "bar_index",
                reason: "no such BAR"
            })
        );
        assert_eq!(
            client.control(PCI_CONTROL_MAP_BAR, &bar_request(0, 0, 0)),
            Err(DeviceError::InvalidArgument {
                field: "length",
                reason: "must be non-zero"
            })
        );
        assert_eq!(
            client.control(PCI_CONTROL_MAP_BAR, &bar_request(0, u64::MAX, 2)),
            Err(DeviceError::InvalidArgument {
                field: "bar_offset",
                reason: "range overflows address space"
            })
        );
        assert_eq!(
            client.control(PCI_CONTROL_MAP_BAR, &bar_request(0, 0x1_0000, 1)),
            Err(DeviceError::InvalidArgument {
                field: "bar_offset",
                reason: "range exceeds BAR size"
            })
        );
        assert_eq!(
            client.control(PCI_CONTROL_MAP_BAR, &bar_request(0, 0, 4)),
            Err(DeviceError::Unsupported {
                feature: "pci BAR mapping requires DriverKit PCI transport entitlement"
            })
        );
        assert_eq!(
            client.control(PCI_CONTROL_READ_BAR, &bar_request(0, 0, 4)),
            Err(DeviceError::Unsupported {
                feature: "pci BAR read requires DriverKit PCI transport entitlement"
            })
        );
        assert_eq!(
            client.control(0xdead, &bar_request(0, 0, 4)),
            Err(DeviceError::InvalidArgument {
                field: "request",
                reason: "unknown PCI user-client request"
            })
        );
    }

    #[test]
    fn pci_duplicate_ids_and_hotplug_refresh_are_idempotent() {
        let mut bridge = PciBridge::new();
        assert_eq!(bridge.refresh(), Ok(Vec::new()));
        let device = info();
        assert_eq!(
            bridge.apply(vec![device.clone(), device.clone()]),
            vec![HotplugEvent::Arrived(device.record())]
        );
        assert_eq!(bridge.devices().len(), 1);
        assert_eq!(bridge.table().len(), 1);
        assert_eq!(bridge.device(device.id), Some(&device));
        assert_eq!(HostDeviceBridge::records(&bridge), vec![device.record()]);
        assert_eq!(
            HostDeviceBridge::record(&bridge, device.id),
            Some(device.record())
        );
        assert_eq!(bridge.class(), DeviceClass::Pci);
        assert_eq!(
            bridge.apply(vec![device.clone()]),
            Vec::<HotplugEvent>::new()
        );
        assert_eq!(bridge.operation_support(HostOperation::Enumerate), Ok(()));
        assert_eq!(bridge.operation_support(HostOperation::Open), Ok(()));
        assert_eq!(
            bridge.operation_support(HostOperation::ConfigSpaceRead),
            Ok(())
        );
        assert_eq!(
            bridge.operation_support(HostOperation::ConfigSpaceWrite),
            Err(DeviceError::Unsupported {
                feature: "pci config space write"
            })
        );
        assert_eq!(
            bridge.operation_support(HostOperation::BarMapping),
            Err(DeviceError::Unsupported {
                feature: "pci BAR mapping"
            })
        );
    }

    #[test]
    fn pci_identity_parsing_and_bar_ranges_reject_malformed_input() {
        assert_eq!(parse_pcidebug("2:0:1"), Some((2, 0, 1)));
        assert_eq!(parse_pcidebug("0:0:0(1:128)"), Some((0, 0, 0)));
        assert_eq!(parse_pcidebug("2:0"), None);
        assert_eq!(parse_pcidebug("x:0:0"), None);
        assert_eq!(parse_pcidebug("2:0:0:1"), None);

        let with_debug = stable_pci_id(0x106b, 0x1901, Some("2:0:0"), 1);
        assert_eq!(with_debug, stable_pci_id(0x106b, 0x1901, Some("2:0:0"), 99));
        assert_ne!(with_debug, stable_pci_id(0x106b, 0x1901, Some("2:0:1"), 1));
        let without_debug = stable_pci_id(0x106b, 0x1901, None, 7);
        assert_eq!(without_debug, stable_pci_id(0x106b, 0x1901, None, 7));
        assert_ne!(without_debug, stable_pci_id(0x106b, 0x1901, None, 8));

        assert_eq!(
            bars_from_ranges(&[(0x1000, 0x100), (0x2000, 0), (0x3000, 0x20)]),
            vec![
                PciBar {
                    index: 0,
                    address: 0x1000,
                    size: 0x100
                },
                PciBar {
                    index: 1,
                    address: 0x3000,
                    size: 0x20
                }
            ]
        );
        assert_eq!(bars_from_ranges(&[(0, 0)]), Vec::new());
        let device = info();
        assert_eq!(device.bar(0).map(|bar| bar.size), Some(0x1_0000));
        assert_eq!(device.bar(2), None);
        assert_eq!(
            device.record().path.as_deref(),
            Some("IOPCIDevice:0000000000000900")
        );
        assert_eq!(device.record().product.as_deref(), Some("PCI 02:00.0"));
        let mut no_location = info();
        no_location.bus = None;
        no_location.device = None;
        no_location.function = None;
        assert_eq!(no_location.record().product, None);
    }

    #[test]
    fn pci_poisoned_live_registry_is_an_exact_io_error() {
        let mut bridge = PciBridge::new();
        let id = info().id;
        let _ = bridge.apply(vec![info()]);
        let live = Arc::clone(&bridge.live);
        let mut client = bridge.open_user_client(id).expect("open PCI fixture");
        let _ = std::thread::spawn(move || {
            let _guard = live.lock().unwrap();
            panic!("poison pci live registry");
        })
        .join();
        assert_eq!(
            client.read(PCI_VENDOR_ID_OFFSET, 1),
            Err(DeviceError::Io {
                operation: "pci live registry",
                os_code: 0
            })
        );
    }
}
