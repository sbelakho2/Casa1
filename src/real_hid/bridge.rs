//! Windows-shaped aggregate over the real HID, USB, and serial bridges.
//!
//! The dispatch layer gets stable handles, a raw-input table for HID devices, a
//! COM-port table for serial devices, and exact hotplug deltas.  Nothing is
//! added to any table unless a real host scan reported it.

use super::audio_device_bridge::{
    AudioDeviceBridge, AudioEndpointDescriptor, scan_audio_endpoints,
};
use super::error::DeviceError;
use super::hid::{HidBridge, HidDevice};
use super::model::{DeviceClass, DeviceRecord, HotplugEvent, StableDeviceId};
use super::net_bridge::{NetworkBridge, WindowsAdapterEntry, scan_network_adapters};
use super::pci_bridge::{PciBridge, PciDeviceInfo, scan_pci_devices};
use super::serial::{SerialBridge, SerialConfig, SerialDevice};
use super::usb::{UsbBridge, UsbDeviceInfo, UsbTransferRequest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawInputDeviceEntry {
    pub handle: u64,
    pub device_id: StableDeviceId,
    pub usage_page: u16,
    pub usage: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialPortEntry {
    pub handle: u64,
    pub device_id: StableDeviceId,
    pub com_port: String,
    pub callout_path: String,
    pub dialin_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDeviceEntry {
    pub handle: u64,
    pub device_id: StableDeviceId,
    pub vendor_id: u16,
    pub product_id: u16,
    pub configurations: usize,
    pub interfaces: usize,
    pub endpoints: usize,
}

#[derive(Debug, Clone, Default)]
pub struct PhysicalDeviceBridge {
    hid: HidBridge,
    usb: UsbBridge,
    serial: SerialBridge,
    pci: PciBridge,
    network: NetworkBridge,
    audio: AudioDeviceBridge,
}

impl PhysicalDeviceBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn hid(&self) -> &HidBridge {
        &self.hid
    }

    pub fn hid_mut(&mut self) -> &mut HidBridge {
        &mut self.hid
    }

    pub fn usb(&self) -> &UsbBridge {
        &self.usb
    }

    pub fn usb_mut(&mut self) -> &mut UsbBridge {
        &mut self.usb
    }

    pub fn serial(&self) -> &SerialBridge {
        &self.serial
    }

    pub fn serial_mut(&mut self) -> &mut SerialBridge {
        &mut self.serial
    }

    pub fn pci(&self) -> &PciBridge {
        &self.pci
    }

    pub fn pci_mut(&mut self) -> &mut PciBridge {
        &mut self.pci
    }

    pub fn network(&self) -> &NetworkBridge {
        &self.network
    }

    pub fn network_mut(&mut self) -> &mut NetworkBridge {
        &mut self.network
    }

    pub fn audio(&self) -> &AudioDeviceBridge {
        &self.audio
    }

    pub fn audio_mut(&mut self) -> &mut AudioDeviceBridge {
        &mut self.audio
    }

    /// Scans every bus before mutating any table, so a failed bus cannot
    /// produce a partial "unplug" of another bus's devices.
    pub fn refresh(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        let hid = super::hid::scan_hid_devices()?;
        let usb = super::usb::scan_usb_devices()?;
        let serial = super::serial::scan_serial_devices()?;
        let pci = scan_pci_devices()?;
        let network = scan_network_adapters()?;
        let audio = scan_audio_endpoints()?;
        let mut events = self.hid.apply(hid);
        events.extend(self.usb.apply(usb));
        events.extend(self.serial.apply(serial));
        events.extend(self.pci.apply(pci));
        events.extend(self.network.apply(network));
        events.extend(self.audio.apply(audio));
        events.sort_by(|left, right| {
            left.device()
                .id
                .cmp(&right.device().id)
                .then_with(|| left.device().class.cmp(&right.device().class))
        });
        Ok(events)
    }

    pub fn devices(&self) -> Vec<DeviceRecord> {
        let mut records = Vec::new();
        records.extend(self.hid.table().iter().cloned());
        records.extend(self.usb.table().iter().cloned());
        records.extend(self.serial.table().iter().cloned());
        records.extend(self.pci.table().iter().cloned());
        records.extend(self.network.table().iter().cloned());
        records.extend(self.audio.table().iter().cloned());
        records.sort_by(|left, right| {
            left.class
                .cmp(&right.class)
                .then_with(|| left.id.cmp(&right.id))
        });
        records
    }

    pub fn device(&self, id: StableDeviceId) -> Option<DeviceRecord> {
        self.hid
            .table()
            .get(id)
            .or_else(|| self.usb.table().get(id))
            .or_else(|| self.serial.table().get(id))
            .or_else(|| self.pci.table().get(id))
            .or_else(|| self.network.table().get(id))
            .or_else(|| self.audio.table().get(id))
            .cloned()
    }

    pub fn device_count(&self) -> usize {
        self.hid.devices().len()
            + self.usb.devices().len()
            + self.serial.devices().len()
            + self.pci.devices().len()
            + self.network.devices().len()
            + self.audio.devices().len()
    }

    /// Real PCI devices with the identity and BAR sizes the host publishes.
    pub fn pci_devices(&self) -> Vec<PciDeviceInfo> {
        self.pci.devices().to_vec()
    }

    /// Real host adapters mapped to Windows-adapter-style metadata.
    pub fn network_adapters(&self) -> Vec<WindowsAdapterEntry> {
        self.network.adapters()
    }

    /// Real CoreAudio endpoints mapped to WASAPI-style descriptors.
    pub fn audio_endpoints(&self) -> Vec<AudioEndpointDescriptor> {
        self.audio.endpoints()
    }

    pub fn raw_input_table(&self) -> Vec<RawInputDeviceEntry> {
        self.hid
            .devices()
            .iter()
            .map(|device| RawInputDeviceEntry {
                handle: device.id.as_u64(),
                device_id: device.id,
                usage_page: device.usage_page,
                usage: device.usage,
                vendor_id: device.vendor_id,
                product_id: device.product_id,
                name: device.product.clone().unwrap_or_else(|| {
                    format!("HID {:04x}:{:04x}", device.vendor_id, device.product_id)
                }),
            })
            .collect()
    }

    pub fn serial_ports(&self) -> Vec<SerialPortEntry> {
        let mut devices: Vec<_> = self.serial.devices().iter().collect();
        devices.sort_by(|left, right| left.callout_path.cmp(&right.callout_path));
        devices
            .into_iter()
            .enumerate()
            .map(|(index, device)| SerialPortEntry {
                handle: device.id.as_u64(),
                device_id: device.id,
                com_port: format!("COM{}", index + 1),
                callout_path: device.callout_path.clone(),
                dialin_path: device.dialin_path.clone(),
            })
            .collect()
    }

    pub fn usb_devices(&self) -> Vec<UsbDeviceEntry> {
        self.usb
            .devices()
            .iter()
            .map(|device| {
                let endpoints = device
                    .configurations
                    .iter()
                    .flat_map(|configuration| &configuration.interfaces)
                    .map(|interface| interface.endpoints.len())
                    .sum();
                let interfaces = device
                    .configurations
                    .iter()
                    .map(|configuration| configuration.interfaces.len())
                    .sum();
                UsbDeviceEntry {
                    handle: device.id.as_u64(),
                    device_id: device.id,
                    vendor_id: device.descriptor.vendor_id,
                    product_id: device.descriptor.product_id,
                    configurations: device.configurations.len(),
                    interfaces,
                    endpoints,
                }
            })
            .collect()
    }

    pub fn open_hid(
        &self,
        id: StableDeviceId,
        vendor_id: u16,
        product_id: u16,
    ) -> Result<HidDevice, DeviceError> {
        self.hid.open_checked(id, vendor_id, product_id)
    }

    pub fn open_serial(
        &self,
        id: StableDeviceId,
        config: SerialConfig,
    ) -> Result<SerialDevice, DeviceError> {
        self.serial.open(id, config)
    }

    pub fn validate_usb_transfer(
        &self,
        id: StableDeviceId,
        request: &UsbTransferRequest,
    ) -> Result<(), DeviceError> {
        self.usb.validate_transfer(id, request)
    }

    pub fn usb_device(&self, id: StableDeviceId) -> Option<&UsbDeviceInfo> {
        self.usb.device(id)
    }

    pub fn class_of(&self, id: StableDeviceId) -> Option<DeviceClass> {
        self.device(id).map(|record| record.class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::real_hid::usb::{
        UsbConfigurationDescriptor, UsbDeviceDescriptor, UsbDirection, UsbEndpointDescriptor,
        UsbInterfaceDescriptor, UsbTransferType,
    };

    fn hid_info() -> crate::real_hid::hid::HidDeviceInfo {
        crate::real_hid::hid::HidDeviceInfo {
            id: StableDeviceId::from_raw(0x101),
            registry_entry_id: 0x101,
            vendor_id: 0x045e,
            product_id: 0x028e,
            usage_page: 1,
            usage: 5,
            usage_pairs: vec![crate::real_hid::hid::HidUsagePair {
                usage_page: 1,
                usage: 5,
            }],
            manufacturer: Some("Microsoft".to_string()),
            product: Some("Controller".to_string()),
            serial_number: Some("serial".to_string()),
            transport: Some("USB".to_string()),
            location_id: Some(1),
            report_descriptor: vec![5, 1, 9, 5],
            max_input_report_size: 64,
            max_output_report_size: 8,
            max_feature_report_size: 8,
        }
    }

    fn serial_info(id: u64, path: &str) -> crate::real_hid::serial::SerialDeviceInfo {
        crate::real_hid::serial::SerialDeviceInfo {
            id: StableDeviceId::from_raw(id),
            registry_entry_id: id,
            callout_path: path.to_string(),
            dialin_path: Some(path.replace("/dev/cu.", "/dev/tty.")),
            tty_device: Some(format!("tty{id:08x}")),
            base_name: Some(format!("base{id:08x}")),
            client_type: Some("IOSerialBSDClientType".to_string()),
        }
    }

    fn usb_info() -> UsbDeviceInfo {
        UsbDeviceInfo {
            id: StableDeviceId::from_raw(0x202),
            registry_entry_id: 0x202,
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
            manufacturer: Some("Fixture".to_string()),
            product: Some("USB Fixture".to_string()),
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
    fn aggregate_bridge_tables_and_dispatch_accessors_are_exact() {
        let mut bridge = PhysicalDeviceBridge::new();
        assert!(bridge.hid().devices().is_empty());
        assert!(bridge.usb().devices().is_empty());
        assert!(bridge.serial().devices().is_empty());
        assert!(bridge.hid_mut().devices().is_empty());
        assert!(bridge.usb_mut().devices().is_empty());
        assert!(bridge.serial_mut().devices().is_empty());
        assert!(bridge.pci().devices().is_empty());
        assert!(bridge.network().devices().is_empty());
        assert!(bridge.audio().devices().is_empty());
        assert!(bridge.pci_mut().devices().is_empty());
        assert!(bridge.network_mut().devices().is_empty());
        assert!(bridge.audio_mut().devices().is_empty());

        let hid = hid_info();
        let usb = usb_info();
        let serial_a = serial_info(0x303, "/dev/cu.zzz");
        let serial_b = serial_info(0x302, "/dev/cu.aaa");
        bridge.hid.apply(vec![hid.clone()]);
        bridge.usb.apply(vec![usb.clone()]);
        bridge
            .serial
            .apply(vec![serial_a.clone(), serial_b.clone()]);
        assert_eq!(bridge.device_count(), 4);

        let records = bridge.devices();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].class, DeviceClass::Hid);
        assert_eq!(records[1].class, DeviceClass::Usb);
        assert_eq!(records[2].class, DeviceClass::Serial);
        assert_eq!(records[2].id, serial_b.id);
        assert_eq!(records[3].id, serial_a.id);

        assert_eq!(bridge.device(hid.id), Some(hid.record()));
        assert_eq!(bridge.device(usb.id), Some(usb.record()));
        assert_eq!(bridge.device(serial_a.id), Some(serial_a.record()));
        assert_eq!(bridge.device(StableDeviceId::from_raw(0)), None);
        assert_eq!(bridge.class_of(hid.id), Some(DeviceClass::Hid));
        assert_eq!(bridge.class_of(usb.id), Some(DeviceClass::Usb));
        assert_eq!(bridge.class_of(serial_a.id), Some(DeviceClass::Serial));
        assert_eq!(bridge.class_of(StableDeviceId::from_raw(0)), None);

        let raw = bridge.raw_input_table();
        assert_eq!(
            raw,
            vec![RawInputDeviceEntry {
                handle: hid.id.as_u64(),
                device_id: hid.id,
                usage_page: 1,
                usage: 5,
                vendor_id: 0x045e,
                product_id: 0x028e,
                name: "Controller".to_string(),
            }]
        );
        let mut unnamed = hid.clone();
        unnamed.id = StableDeviceId::from_raw(0x102);
        unnamed.product = None;
        bridge.hid.apply(vec![hid.clone(), unnamed.clone()]);
        assert_eq!(
            bridge.raw_input_table()[1].name,
            format!("HID {:04x}:{:04x}", 0x045e, 0x028e)
        );

        let ports = bridge.serial_ports();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].com_port, "COM1");
        assert_eq!(ports[0].device_id, serial_b.id);
        assert_eq!(ports[0].callout_path, "/dev/cu.aaa");
        assert_eq!(ports[0].dialin_path.as_deref(), Some("/dev/tty.aaa"));
        assert_eq!(ports[1].com_port, "COM2");
        assert_eq!(ports[1].device_id, serial_a.id);

        let usb_entries = bridge.usb_devices();
        assert_eq!(
            usb_entries,
            vec![UsbDeviceEntry {
                handle: usb.id.as_u64(),
                device_id: usb.id,
                vendor_id: 0x1234,
                product_id: 0x5678,
                configurations: 1,
                interfaces: 1,
                endpoints: 1,
            }]
        );

        assert!(
            bridge
                .open_hid(hid.id, hid.vendor_id, hid.product_id)
                .is_ok()
        );
        assert_eq!(
            bridge.open_hid(hid.id, 0x054c, 0x0ce6).map(|_| ()),
            Err(DeviceError::VendorMismatch {
                id: hid.id,
                expected_vendor: 0x054c,
                expected_product: 0x0ce6,
                actual_vendor: 0x045e,
                actual_product: 0x028e,
            })
        );
        assert_eq!(
            bridge
                .open_hid(StableDeviceId::from_raw(0), 0, 0)
                .map(|_| ()),
            Err(DeviceError::DeviceMissing {
                id: StableDeviceId::from_raw(0)
            })
        );
        assert!(
            bridge
                .open_serial(serial_a.id, SerialConfig::default())
                .is_ok()
        );
        assert_eq!(
            bridge
                .open_serial(StableDeviceId::from_raw(0), SerialConfig::default())
                .map(|_| ()),
            Err(DeviceError::DeviceMissing {
                id: StableDeviceId::from_raw(0)
            })
        );

        let request = UsbTransferRequest {
            interface_number: 0,
            endpoint_address: 0x81,
            transfer_type: UsbTransferType::Interrupt,
            direction: UsbDirection::In,
            flags: 0,
            length: 8,
        };
        assert_eq!(bridge.validate_usb_transfer(usb.id, &request), Ok(()));
        assert_eq!(
            bridge.validate_usb_transfer(StableDeviceId::from_raw(0), &request),
            Err(DeviceError::DeviceMissing {
                id: StableDeviceId::from_raw(0)
            })
        );
        assert_eq!(bridge.usb_device(usb.id), Some(&usb));
        assert_eq!(bridge.usb_device(StableDeviceId::from_raw(0)), None);

        let events = bridge.refresh().expect("empty host scans");
        assert_eq!(events.len(), 5);
        assert_eq!(bridge.device_count(), 0);
        assert_eq!(bridge.devices(), Vec::new());
        assert_eq!(bridge.raw_input_table(), Vec::new());
        assert_eq!(bridge.serial_ports(), Vec::new());
        assert_eq!(bridge.usb_devices(), Vec::new());
        assert_eq!(bridge.pci_devices(), Vec::new());
        assert_eq!(bridge.network_adapters(), Vec::new());
        assert_eq!(bridge.audio_endpoints(), Vec::new());
    }

    #[test]
    fn empty_bridge_tables_are_missing_devices_not_synthetic() {
        let bridge = PhysicalDeviceBridge::new();
        assert_eq!(bridge.device_count(), 0);
        assert_eq!(bridge.raw_input_table(), Vec::<RawInputDeviceEntry>::new());
        assert_eq!(bridge.serial_ports(), Vec::<SerialPortEntry>::new());
        assert_eq!(bridge.usb_devices(), Vec::<UsbDeviceEntry>::new());
        assert_eq!(bridge.devices(), Vec::<DeviceRecord>::new());
    }
}
