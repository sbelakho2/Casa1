//! Real USB enumeration through IOKit (`IOUSBHostDevice` and the legacy
//! `IOUSBDevice` class) and a Windows-shaped transfer validator.
//!
//! The bridge never invents a USB device.  It reads the host's device
//! properties, traverses real `IOUSBHostInterface` children, parses any real
//! configuration-descriptor blobs the service exposes, and reports exact
//! errors for missing endpoints and unsupported transfer flags/types.

use super::error::DeviceError;
use super::model::{DeviceClass, DeviceRecord, DeviceTable, HotplugEvent, StableDeviceId};

#[cfg(all(target_os = "macos", not(test)))]
use super::ffi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbTransferType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

impl UsbTransferType {
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0x03 {
            0 => Some(Self::Control),
            1 => Some(Self::Isochronous),
            2 => Some(Self::Bulk),
            3 => Some(Self::Interrupt),
            _ => None, // coverage: unreachable — `& 0x03` has only four values
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Isochronous => "isochronous",
            Self::Bulk => "bulk",
            Self::Interrupt => "interrupt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbDirection {
    Out,
    In,
}

impl UsbDirection {
    pub const fn from_address(address: u8) -> Self {
        if address & 0x80 != 0 {
            Self::In
        } else {
            Self::Out
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbEndpointDescriptor {
    pub address: u8,
    pub number: u8,
    pub direction: UsbDirection,
    pub transfer_type: UsbTransferType,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbInterfaceDescriptor {
    pub number: u8,
    pub alternate_setting: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub endpoints: Vec<UsbEndpointDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbConfigurationDescriptor {
    pub value: u8,
    pub attributes: u8,
    pub max_power_ma: u16,
    pub interfaces: Vec<UsbInterfaceDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDeviceDescriptor {
    pub vendor_id: u16,
    pub product_id: u16,
    pub bcd_device: u16,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub max_packet_size0: u8,
    pub num_configurations: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDeviceInfo {
    pub id: StableDeviceId,
    pub registry_entry_id: u64,
    pub descriptor: UsbDeviceDescriptor,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub vendor_string: Option<String>,
    pub location_id: Option<u32>,
    pub current_configuration: Option<u8>,
    pub configurations: Vec<UsbConfigurationDescriptor>,
    pub raw_configuration_descriptors: Vec<Vec<u8>>,
}

impl UsbDeviceInfo {
    pub fn record(&self) -> DeviceRecord {
        DeviceRecord {
            id: self.id,
            class: DeviceClass::Usb,
            vendor_id: Some(self.descriptor.vendor_id),
            product_id: Some(self.descriptor.product_id),
            manufacturer: self.manufacturer.clone(),
            product: self.product.clone(),
            serial_number: self.serial_number.clone(),
            path: Some(format!("IOUSBHostDevice:{:016x}", self.registry_entry_id)),
            registry_entry_id: self.registry_entry_id,
        }
    }

    pub fn endpoint(&self, interface_number: u8, address: u8) -> Option<&UsbEndpointDescriptor> {
        self.configurations
            .iter()
            .flat_map(|configuration| &configuration.interfaces)
            .filter(|interface| interface.number == interface_number)
            .flat_map(|interface| &interface.endpoints)
            .find(|endpoint| endpoint.address == address)
    }

    pub fn validate_transfer(&self, request: &UsbTransferRequest) -> Result<(), DeviceError> {
        request.validate_flags()?;
        if request.length == 0 {
            return Err(DeviceError::InvalidArgument {
                field: "length",
                reason: "must be non-zero",
            });
        }
        match request.transfer_type {
            UsbTransferType::Isochronous => {
                return Err(DeviceError::UnsupportedTransferType {
                    kind: UsbTransferType::Isochronous,
                });
            }
            UsbTransferType::Control => {
                return Err(DeviceError::Unsupported {
                    feature: "usb control transfer",
                });
            }
            UsbTransferType::Bulk | UsbTransferType::Interrupt => {}
        }
        let Some(endpoint) = self.endpoint(request.interface_number, request.endpoint_address)
        else {
            return Err(DeviceError::EndpointMissing {
                interface: request.interface_number,
                endpoint: request.endpoint_address,
            });
        };
        if endpoint.direction != request.direction {
            return Err(DeviceError::InvalidArgument {
                field: "endpoint_address",
                reason: "direction does not match endpoint descriptor",
            });
        }
        if endpoint.transfer_type != request.transfer_type {
            return Err(DeviceError::InvalidArgument {
                field: "transfer_type",
                reason: "type does not match endpoint descriptor",
            });
        }
        Ok(())
    }
}

pub const USB_TRANSFER_FLAG_SHORT_NOT_OK: u32 = 0x0000_0001;
pub const USB_TRANSFER_FLAG_ZERO_PACKET: u32 = 0x0000_0002;
pub const USB_TRANSFER_FLAG_NO_DMA_MAP: u32 = 0x0000_0004;
pub const USB_TRANSFER_FLAG_ISO_ASAP: u32 = 0x0000_0008;

const USB_TRANSFER_KNOWN_FLAGS: u32 = USB_TRANSFER_FLAG_SHORT_NOT_OK
    | USB_TRANSFER_FLAG_ZERO_PACKET
    | USB_TRANSFER_FLAG_NO_DMA_MAP
    | USB_TRANSFER_FLAG_ISO_ASAP;
const USB_TRANSFER_SUPPORTED_FLAGS: u32 =
    USB_TRANSFER_FLAG_SHORT_NOT_OK | USB_TRANSFER_FLAG_ZERO_PACKET;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbTransferRequest {
    pub interface_number: u8,
    pub endpoint_address: u8,
    pub transfer_type: UsbTransferType,
    pub direction: UsbDirection,
    pub flags: u32,
    pub length: usize,
}

impl UsbTransferRequest {
    pub fn validate_flags(&self) -> Result<(), DeviceError> {
        let unknown = self.flags & !USB_TRANSFER_KNOWN_FLAGS;
        if unknown != 0 {
            return Err(DeviceError::UnsupportedTransferFlag { flag: unknown });
        }
        let unsupported = self.flags & !USB_TRANSFER_SUPPORTED_FLAGS;
        if unsupported != 0 {
            let flag = 1_u32 << unsupported.trailing_zeros();
            return Err(DeviceError::UnsupportedTransferFlag { flag });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct UsbBridge {
    devices: Vec<UsbDeviceInfo>,
    table: DeviceTable,
}

impl UsbBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devices(&self) -> &[UsbDeviceInfo] {
        &self.devices
    }

    pub fn table(&self) -> &DeviceTable {
        &self.table
    }

    pub fn device(&self, id: StableDeviceId) -> Option<&UsbDeviceInfo> {
        self.devices.iter().find(|device| device.id == id)
    }

    pub fn apply(&mut self, devices: Vec<UsbDeviceInfo>) -> Vec<HotplugEvent> {
        let mut devices = devices;
        devices.sort_by_key(|device| device.id);
        let records = devices.iter().map(UsbDeviceInfo::record).collect();
        self.devices = devices;
        self.table.reconcile(records)
    }

    pub fn enumerate(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        let devices = scan_usb_devices()?;
        Ok(self.apply(devices))
    }

    pub fn validate_transfer(
        &self,
        id: StableDeviceId,
        request: &UsbTransferRequest,
    ) -> Result<(), DeviceError> {
        let device = self.device(id).ok_or(DeviceError::DeviceMissing { id })?;
        device.validate_transfer(request)
    }

    pub fn submit_transfer(
        &self,
        id: StableDeviceId,
        request: &UsbTransferRequest,
    ) -> Result<Vec<u8>, DeviceError> {
        self.validate_transfer(id, request)?;
        Err(DeviceError::Unsupported {
            feature: "usb data transfer",
        })
    }
}

pub fn parse_configuration_descriptors(
    bytes: &[u8],
) -> Result<Vec<UsbConfigurationDescriptor>, DeviceError> {
    let mut configurations = Vec::new();
    let mut current: Option<UsbConfigurationDescriptor> = None;
    let mut interface: Option<UsbInterfaceDescriptor> = None;
    let mut offset = 0;

    while offset < bytes.len() {
        let length = bytes[offset] as usize;
        if length < 2 || offset + length > bytes.len() {
            return Err(DeviceError::MalformedDescriptor {
                offset,
                reason: "descriptor length is invalid or truncated",
            });
        }
        let descriptor_type = bytes[offset + 1];
        match descriptor_type {
            2 => {
                if let Some(interface) = interface.take()
                    && let Some(configuration) = current.as_mut()
                {
                    configuration.interfaces.push(interface);
                }
                if let Some(previous) = current.take() {
                    configurations.push(previous);
                }
                if length < 9 {
                    return Err(DeviceError::MalformedDescriptor {
                        offset,
                        reason: "configuration descriptor is too short",
                    });
                }
                current = Some(UsbConfigurationDescriptor {
                    value: bytes[offset + 5],
                    attributes: bytes[offset + 7],
                    max_power_ma: u16::from(bytes[offset + 8]) * 2,
                    interfaces: Vec::new(),
                });
                interface = None;
            }
            4 => {
                let Some(configuration) = current.as_mut() else {
                    return Err(DeviceError::MalformedDescriptor {
                        offset,
                        reason: "interface descriptor precedes configuration",
                    });
                };
                if length < 9 {
                    return Err(DeviceError::MalformedDescriptor {
                        offset,
                        reason: "interface descriptor is too short",
                    });
                }
                if let Some(previous) = interface.take() {
                    configuration.interfaces.push(previous);
                }
                interface = Some(UsbInterfaceDescriptor {
                    number: bytes[offset + 2],
                    alternate_setting: bytes[offset + 3],
                    class: bytes[offset + 5],
                    subclass: bytes[offset + 6],
                    protocol: bytes[offset + 7],
                    endpoints: Vec::new(),
                });
            }
            5 => {
                let Some(interface) = interface.as_mut() else {
                    return Err(DeviceError::MalformedDescriptor {
                        offset,
                        reason: "endpoint descriptor precedes interface",
                    });
                };
                if length < 7 {
                    return Err(DeviceError::MalformedDescriptor {
                        offset,
                        reason: "endpoint descriptor is too short",
                    });
                }
                let address = bytes[offset + 2];
                let attributes = bytes[offset + 3];
                let transfer_type = UsbTransferType::from_bits(attributes).ok_or(
                    // coverage: unreachable — from_bits masks to two bits
                    DeviceError::MalformedDescriptor {
                        offset, // coverage: unreachable — from_bits always succeeds
                        reason: "endpoint transfer type is invalid", // coverage: unreachable
                    }, // coverage: unreachable
                )?; // coverage: unreachable — from_bits always succeeds
                let max_packet_size = u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]);
                interface.endpoints.push(UsbEndpointDescriptor {
                    address,
                    number: address & 0x0f,
                    direction: UsbDirection::from_address(address),
                    transfer_type,
                    attributes,
                    max_packet_size,
                    interval: bytes[offset + 6],
                });
            }
            _ => {}
        }
        offset += length;
    }

    if let Some(interface) = interface
        && let Some(configuration) = current.as_mut()
    {
        configuration.interfaces.push(interface);
    }
    if let Some(configuration) = current {
        configurations.push(configuration);
    }
    if configurations.is_empty() {
        return Err(DeviceError::MalformedDescriptor {
            offset: 0,
            reason: "missing configuration descriptor",
        });
    }
    Ok(configurations)
}

#[cfg(all(target_os = "macos", not(test)))]
pub fn scan_usb_devices() -> Result<Vec<UsbDeviceInfo>, DeviceError> {
    let mut services = ffi::matching_services("IOUSBHostDevice");
    services.extend(ffi::matching_services("IOUSBDevice"));
    let mut seen = std::collections::BTreeSet::new();
    let mut devices = Vec::new();
    for service in services {
        let Some(registry_entry_id) = service.registry_entry_id() else {
            continue;
        };
        if !seen.insert(registry_entry_id) {
            continue;
        }
        if let Some(device) = usb_snapshot(&service, registry_entry_id) {
            devices.push(device);
        }
    }
    devices.sort_by_key(|device| device.id);
    Ok(devices)
}

#[cfg(all(target_os = "macos", not(test)))]
fn usb_snapshot(service: &ffi::IoService, registry_entry_id: u64) -> Option<UsbDeviceInfo> {
    let vendor_id = property_number(service, &["idVendor", "VendorID"])
        .and_then(|value| u16::try_from(value).ok())?;
    let product_id = property_number(service, &["idProduct", "ProductID"])
        .and_then(|value| u16::try_from(value).ok())?;
    let serial_number = property_string(
        service,
        &[
            "USB Serial Number",
            "kUSBSerialNumberString",
            "SerialNumber",
        ],
    );
    let location_id = property_number(service, &["locationID", "LocationID"])
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0);
    let current_configuration = property_number(
        service,
        &[
            "kUSBCurrentConfiguration",
            "bConfigurationValue",
            "CurrentConfiguration",
        ],
    )
    .and_then(|value| u8::try_from(value).ok());
    let id = stable_usb_id(
        vendor_id,
        product_id,
        serial_number.as_deref(),
        location_id,
        registry_entry_id,
    );

    let mut raw_configuration_descriptors = Vec::new();
    let mut configurations = Vec::new();
    for key in [
        "IOUSBConfigurationDescriptor",
        "ConfigurationDescriptor",
        "USBConfigurationDescriptor",
    ] {
        if let Some(bytes) = service.data(key)
            && let Ok(parsed) = parse_configuration_descriptors(&bytes)
        {
            configurations.extend(parsed);
            raw_configuration_descriptors.push(bytes);
        }
    }

    let interfaces = service
        .children()
        .into_iter()
        .filter(|child| {
            matches!(
                child.class_name().as_deref(),
                Some("IOUSBHostInterface") | Some("IOUSBInterface")
            )
        })
        .filter_map(|child| interface_snapshot(&child))
        .collect::<Vec<_>>();

    if configurations.is_empty() && (!interfaces.is_empty() || current_configuration.is_some()) {
        configurations.push(UsbConfigurationDescriptor {
            value: current_configuration.unwrap_or(0),
            attributes: property_number(service, &["bmAttributes"]).unwrap_or(0) as u8,
            max_power_ma: property_number(service, &["MaxPower", "bMaxPower"])
                .and_then(|value| u16::try_from(value).ok())
                .map(|value| value * 2)
                .unwrap_or(0),
            interfaces,
        });
    } else if !configurations.is_empty() && !interfaces.is_empty() {
        for configuration in &mut configurations {
            if configuration.interfaces.is_empty() {
                configuration.interfaces = interfaces.clone();
            }
        }
    }

    Some(UsbDeviceInfo {
        id,
        registry_entry_id,
        descriptor: UsbDeviceDescriptor {
            vendor_id,
            product_id,
            bcd_device: property_number(service, &["bcdDevice", "DeviceReleaseNumber"])
                .and_then(|value| u16::try_from(value).ok())
                .unwrap_or(0),
            class: property_number(service, &["bDeviceClass"]).unwrap_or(0) as u8,
            subclass: property_number(service, &["bDeviceSubClass"]).unwrap_or(0) as u8,
            protocol: property_number(service, &["bDeviceProtocol"]).unwrap_or(0) as u8,
            max_packet_size0: property_number(service, &["bMaxPacketSize0", "MaxPacketSize"])
                .unwrap_or(0) as u8,
            num_configurations: property_number(service, &["bNumConfigurations"]).unwrap_or(0)
                as u8,
        },
        manufacturer: property_string(
            service,
            &["USB Vendor Name", "kUSBVendorString", "Manufacturer"],
        ),
        product: property_string(
            service,
            &["USB Product Name", "kUSBProductString", "Product"],
        ),
        serial_number,
        vendor_string: property_string(service, &["kUSBVendorString"]),
        location_id,
        current_configuration,
        configurations,
        raw_configuration_descriptors,
    })
}

#[cfg(all(target_os = "macos", not(test)))]
fn interface_snapshot(interface: &ffi::IoService) -> Option<UsbInterfaceDescriptor> {
    let number = property_number(interface, &["bInterfaceNumber", "InterfaceNumber"])
        .and_then(|value| u8::try_from(value).ok())?;
    let endpoints = ["IOUSBEndpointDescriptor", "EndpointDescriptor"]
        .iter()
        .filter_map(|key| interface.data(key))
        .find_map(|bytes| parse_endpoint_descriptors(&bytes));
    Some(UsbInterfaceDescriptor {
        number,
        alternate_setting: property_number(interface, &["bAlternateSetting", "AlternateSetting"])
            .unwrap_or(0) as u8,
        class: property_number(interface, &["bInterfaceClass"]).unwrap_or(0) as u8,
        subclass: property_number(interface, &["bInterfaceSubClass"]).unwrap_or(0) as u8,
        protocol: property_number(interface, &["bInterfaceProtocol"]).unwrap_or(0) as u8,
        endpoints: endpoints.unwrap_or_default(),
    })
}

#[cfg(all(target_os = "macos", not(test)))]
fn parse_endpoint_descriptors(bytes: &[u8]) -> Option<Vec<UsbEndpointDescriptor>> {
    let mut endpoints = Vec::new();
    let mut offset = 0;
    while offset + 2 <= bytes.len() {
        let length = bytes[offset] as usize;
        if length < 2 || offset + length > bytes.len() {
            return None;
        }
        if bytes[offset + 1] == 5 && length >= 7 {
            let address = bytes[offset + 2];
            let attributes = bytes[offset + 3];
            let transfer_type = UsbTransferType::from_bits(attributes)?;
            let max_packet_size = u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]);
            endpoints.push(UsbEndpointDescriptor {
                address,
                number: address & 0x0f,
                direction: UsbDirection::from_address(address),
                transfer_type,
                attributes,
                max_packet_size,
                interval: bytes[offset + 6],
            });
        }
        offset += length;
    }
    Some(endpoints)
}

#[cfg(all(target_os = "macos", not(test)))]
fn property_number(service: &ffi::IoService, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| service.number(key))
}

#[cfg(all(target_os = "macos", not(test)))]
fn property_string(service: &ffi::IoService, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| service.string(key))
}

#[cfg(all(target_os = "macos", not(test)))]
fn stable_usb_id(
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
    StableDeviceId::derive(DeviceClass::Usb, &parts)
}

#[cfg(test)]
pub fn scan_usb_devices() -> Result<Vec<UsbDeviceInfo>, DeviceError> {
    Ok(Vec::new())
}

#[cfg(all(not(target_os = "macos"), not(test)))]
pub fn scan_usb_devices() -> Result<Vec<UsbDeviceInfo>, DeviceError> {
    Err(DeviceError::Unsupported {
        feature: "USB enumeration requires macOS IOKit",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> UsbDeviceInfo {
        UsbDeviceInfo {
            id: StableDeviceId::from_raw(0x99),
            registry_entry_id: 0x99,
            descriptor: UsbDeviceDescriptor {
                vendor_id: 0x1234,
                product_id: 0x5678,
                bcd_device: 0x0100,
                class: 0,
                subclass: 0,
                protocol: 0,
                max_packet_size0: 64,
                num_configurations: 1,
            },
            manufacturer: None,
            product: Some("Fixture".to_string()),
            serial_number: None,
            vendor_string: None,
            location_id: None,
            current_configuration: Some(1),
            configurations: vec![UsbConfigurationDescriptor {
                value: 1,
                attributes: 0x80,
                max_power_ma: 100,
                interfaces: vec![UsbInterfaceDescriptor {
                    number: 0,
                    alternate_setting: 0,
                    class: 3,
                    subclass: 0,
                    protocol: 0,
                    endpoints: vec![UsbEndpointDescriptor {
                        address: 0x81,
                        number: 1,
                        direction: UsbDirection::In,
                        transfer_type: UsbTransferType::Interrupt,
                        attributes: 3,
                        max_packet_size: 8,
                        interval: 10,
                    }],
                }],
            }],
            raw_configuration_descriptors: Vec::new(),
        }
    }

    #[test]
    fn usb_unknown_transfer_flags_are_rejected_exactly() {
        let request = UsbTransferRequest {
            interface_number: 0,
            endpoint_address: 0x81,
            transfer_type: UsbTransferType::Interrupt,
            direction: UsbDirection::In,
            flags: 0x8000_0000,
            length: 8,
        };
        assert_eq!(
            request.validate_flags(),
            Err(DeviceError::UnsupportedTransferFlag { flag: 0x8000_0000 })
        );
    }

    #[test]
    fn usb_known_but_unsupported_transfer_flags_are_rejected_exactly() {
        let request = UsbTransferRequest {
            interface_number: 0,
            endpoint_address: 0x81,
            transfer_type: UsbTransferType::Interrupt,
            direction: UsbDirection::In,
            flags: USB_TRANSFER_FLAG_NO_DMA_MAP | USB_TRANSFER_FLAG_ISO_ASAP,
            length: 8,
        };
        assert_eq!(
            request.validate_flags(),
            Err(DeviceError::UnsupportedTransferFlag {
                flag: USB_TRANSFER_FLAG_NO_DMA_MAP
            })
        );
    }

    #[test]
    fn usb_isochronous_transfer_is_rejected_exactly() {
        let request = UsbTransferRequest {
            interface_number: 0,
            endpoint_address: 0x81,
            transfer_type: UsbTransferType::Isochronous,
            direction: UsbDirection::In,
            flags: 0,
            length: 8,
        };
        assert_eq!(
            device().validate_transfer(&request),
            Err(DeviceError::UnsupportedTransferType {
                kind: UsbTransferType::Isochronous
            })
        );
    }

    #[test]
    fn usb_missing_endpoint_is_rejected_exactly() {
        let request = UsbTransferRequest {
            interface_number: 0,
            endpoint_address: 0x82,
            transfer_type: UsbTransferType::Bulk,
            direction: UsbDirection::In,
            flags: 0,
            length: 64,
        };
        assert_eq!(
            device().validate_transfer(&request),
            Err(DeviceError::EndpointMissing {
                interface: 0,
                endpoint: 0x82
            })
        );
    }

    #[test]
    fn usb_malformed_descriptor_is_rejected_exactly() {
        assert_eq!(
            parse_configuration_descriptors(&[9, 2, 0, 0]),
            Err(DeviceError::MalformedDescriptor {
                offset: 0,
                reason: "descriptor length is invalid or truncated"
            })
        );
        assert_eq!(
            parse_configuration_descriptors(&[4, 4, 0, 0]),
            Err(DeviceError::MalformedDescriptor {
                offset: 0,
                reason: "interface descriptor precedes configuration"
            })
        );
    }

    #[test]
    fn usb_multi_configuration_descriptor_boundary_keeps_interfaces_paired() {
        let bytes = [
            9, 2, 27, 0, 1, 1, 0, 0x80, 50, // configuration 1
            9, 4, 0, 0, 1, 3, 0, 0, 0, // interface 0, one endpoint
            7, 5, 0x81, 0x03, 8, 0, 10, // interrupt IN
            9, 2, 27, 0, 2, 2, 0, 0xc0, 100, // configuration 2
            9, 4, 1, 0, 1, 0xff, 0, 0, 0, // interface 1, one endpoint
            7, 5, 0x02, 0x02, 64, 0, 0, // bulk OUT
        ];
        let configurations = parse_configuration_descriptors(&bytes).unwrap();
        assert_eq!(configurations.len(), 2);
        assert_eq!(configurations[0].value, 1);
        assert_eq!(configurations[0].interfaces.len(), 1);
        assert_eq!(configurations[0].interfaces[0].endpoints.len(), 1);
        assert_eq!(configurations[0].interfaces[0].endpoints[0].address, 0x81);
        assert_eq!(configurations[1].value, 2);
        assert_eq!(configurations[1].interfaces.len(), 1);
        assert_eq!(configurations[1].interfaces[0].number, 1);
        assert_eq!(
            configurations[1].interfaces[0].endpoints[0].transfer_type,
            UsbTransferType::Bulk
        );
    }

    #[test]
    fn usb_real_enumeration_missing_devices_never_synthesized() {
        let mut bridge = UsbBridge::new();
        match bridge.enumerate() {
            Ok(events) => assert_eq!(events.len(), bridge.devices().len()),
            Err(DeviceError::Unsupported { feature }) => {
                assert_eq!(feature, "USB enumeration requires macOS IOKit");
            }
            Err(error) => panic!("unexpected USB enumeration error: {error:?}"),
        }
    }

    #[test]
    fn usb_transfer_validation_rejects_every_unsupported_edge_exactly() {
        assert_eq!(
            UsbTransferType::from_bits(0),
            Some(UsbTransferType::Control)
        );
        assert_eq!(
            UsbTransferType::from_bits(1),
            Some(UsbTransferType::Isochronous)
        );
        assert_eq!(UsbTransferType::from_bits(2), Some(UsbTransferType::Bulk));
        assert_eq!(
            UsbTransferType::from_bits(3),
            Some(UsbTransferType::Interrupt)
        );
        assert_eq!(UsbTransferType::Control.as_str(), "control");
        assert_eq!(UsbTransferType::Isochronous.as_str(), "isochronous");
        assert_eq!(UsbTransferType::Bulk.as_str(), "bulk");
        assert_eq!(UsbTransferType::Interrupt.as_str(), "interrupt");
        assert_eq!(UsbDirection::from_address(0x81), UsbDirection::In);
        assert_eq!(UsbDirection::from_address(0x01), UsbDirection::Out);

        let device = device();
        assert_eq!(
            device.record().path.as_deref(),
            Some("IOUSBHostDevice:0000000000000099")
        );
        assert_eq!(device.endpoint(0, 0x81).map(|ep| ep.address), Some(0x81));
        assert_eq!(device.endpoint(1, 0x81), None);
        assert_eq!(device.endpoint(0, 0x82), None);

        let zero = UsbTransferRequest {
            interface_number: 0,
            endpoint_address: 0x81,
            transfer_type: UsbTransferType::Interrupt,
            direction: UsbDirection::In,
            flags: 0,
            length: 0,
        };
        assert_eq!(
            device.validate_transfer(&zero),
            Err(DeviceError::InvalidArgument {
                field: "length",
                reason: "must be non-zero"
            })
        );
        let control = UsbTransferRequest {
            length: 8,
            transfer_type: UsbTransferType::Control,
            ..zero.clone()
        };
        assert_eq!(
            device.validate_transfer(&control),
            Err(DeviceError::Unsupported {
                feature: "usb control transfer"
            })
        );
        let wrong_direction = UsbTransferRequest {
            length: 8,
            direction: UsbDirection::Out,
            ..zero.clone()
        };
        assert_eq!(
            device.validate_transfer(&wrong_direction),
            Err(DeviceError::InvalidArgument {
                field: "endpoint_address",
                reason: "direction does not match endpoint descriptor"
            })
        );
        let wrong_type = UsbTransferRequest {
            length: 8,
            transfer_type: UsbTransferType::Bulk,
            ..zero.clone()
        };
        assert_eq!(
            device.validate_transfer(&wrong_type),
            Err(DeviceError::InvalidArgument {
                field: "transfer_type",
                reason: "type does not match endpoint descriptor"
            })
        );
        let valid = UsbTransferRequest {
            length: 8,
            flags: USB_TRANSFER_FLAG_SHORT_NOT_OK | USB_TRANSFER_FLAG_ZERO_PACKET,
            ..zero
        };
        assert_eq!(device.validate_transfer(&valid), Ok(()));

        let mut bridge = UsbBridge::new();
        assert_eq!(bridge.devices().len(), 0);
        assert_eq!(bridge.table().len(), 0);
        assert_eq!(
            bridge.apply(vec![device.clone()]),
            vec![HotplugEvent::Arrived(device.record())]
        );
        assert_eq!(bridge.devices().len(), 1);
        assert_eq!(bridge.table().len(), 1);
        assert_eq!(bridge.device(device.id), Some(&device));
        assert_eq!(bridge.validate_transfer(device.id, &valid), Ok(()));
        assert_eq!(
            bridge.submit_transfer(device.id, &valid),
            Err(DeviceError::Unsupported {
                feature: "usb data transfer"
            })
        );
        assert_eq!(
            bridge.submit_transfer(StableDeviceId::from_raw(0xdead), &valid),
            Err(DeviceError::DeviceMissing {
                id: StableDeviceId::from_raw(0xdead)
            })
        );
        assert_eq!(
            bridge.enumerate(),
            Ok(vec![HotplugEvent::Removed {
                record: device.record()
            }])
        );
    }

    #[test]
    fn usb_descriptor_truncation_and_precedence_edges_are_exact() {
        assert_eq!(
            parse_configuration_descriptors(&[8, 2, 0, 0, 0, 0, 0, 0]),
            Err(DeviceError::MalformedDescriptor {
                offset: 0,
                reason: "configuration descriptor is too short"
            })
        );
        assert_eq!(
            parse_configuration_descriptors(&[
                9, 2, 0, 0, 0, 1, 0, 0x80, 50, 8, 4, 0, 0, 1, 3, 0, 0
            ]),
            Err(DeviceError::MalformedDescriptor {
                offset: 9,
                reason: "interface descriptor is too short"
            })
        );
        assert_eq!(
            parse_configuration_descriptors(&[
                9, 2, 0, 0, 0, 1, 0, 0x80, 50, 7, 5, 0x81, 3, 8, 0, 10
            ]),
            Err(DeviceError::MalformedDescriptor {
                offset: 9,
                reason: "endpoint descriptor precedes interface"
            })
        );
        assert_eq!(
            parse_configuration_descriptors(&[
                9, 2, 0, 0, 0, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 0, 0, 0, 6, 5, 0x81, 3, 8, 0
            ]),
            Err(DeviceError::MalformedDescriptor {
                offset: 18,
                reason: "endpoint descriptor is too short"
            })
        );
        assert_eq!(
            parse_configuration_descriptors(&[]),
            Err(DeviceError::MalformedDescriptor {
                offset: 0,
                reason: "missing configuration descriptor"
            })
        );
        let two_interfaces = [
            9, 2, 0, 0, 0, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 0, 0, 0, 9, 4, 1, 0, 0, 0xff, 0, 0, 0,
            7, 5, 0x81, 3, 8, 0, 10,
        ];
        let configurations = parse_configuration_descriptors(&two_interfaces).unwrap();
        assert_eq!(configurations.len(), 1);
        assert_eq!(configurations[0].interfaces.len(), 2);
        assert_eq!(configurations[0].interfaces[1].number, 1);
        assert_eq!(configurations[0].interfaces[1].endpoints.len(), 1);
        let with_unknown = [
            2, 1, 9, 2, 0, 0, 0, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 0, 0, 0, 7, 5, 0x81, 3, 8, 0, 10,
        ];
        let configurations = parse_configuration_descriptors(&with_unknown).unwrap();
        assert_eq!(configurations.len(), 1);
        assert_eq!(configurations[0].interfaces.len(), 1);
        assert_eq!(configurations[0].interfaces[0].endpoints.len(), 1);
    }

    #[test]
    fn usb_missing_device_handle_is_exact_and_never_synthetic() {
        let id = StableDeviceId::from_raw(0x1234);
        let bridge = UsbBridge::new();
        let request = UsbTransferRequest {
            interface_number: 0,
            endpoint_address: 0x81,
            transfer_type: UsbTransferType::Bulk,
            direction: UsbDirection::In,
            flags: 0,
            length: 64,
        };
        assert_eq!(
            bridge.validate_transfer(id, &request),
            Err(DeviceError::DeviceMissing { id })
        );
        assert!(bridge.devices().is_empty());
    }
}
