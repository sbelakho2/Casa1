//! In-process IOKit user-client transport.
//!
//! Enumeration reuses the real [`PhysicalDeviceBridge`] scans (HID, USB,
//! serial, PCI, network, audio), so it works with no entitlement.  A channel
//! opens the host object for the duration of one operation: HID devices are
//! opened/scheduled and closed around the report call, serial ports are
//! opened/configured and closed, and PCI config space is read from the live
//! device record.  Operations the host genuinely cannot grant an
//! unentitled user client (PCI BAR mapping/config writes, USB bulk transfers,
//! network link control) are reported as
//! [`ProxyError::EntitlementRequired`] even before the transport is entered.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::device_proxy::{
    CancelToken, CapabilityDescriptor, DeviceChannel, DeviceClass, DeviceFamily, DeviceRecord,
    DeviceTransport, HotplugEvent, ProxyError, ProxyOperation, StableDeviceId, remaining,
    resolve_deadline,
};
use crate::real_hid::bridge::PhysicalDeviceBridge;
use crate::real_hid::serial::SerialConfig;

/// `IOCTL_HID_READ_REPORT`: read one buffered input report.
pub const IOCTL_HID_READ_REPORT: u32 = 0x000B_0001;
/// `IOCTL_HID_WRITE_REPORT`: send one output report.
pub const IOCTL_HID_WRITE_REPORT: u32 = 0x000B_0002;
/// `IOCTL_HID_SET_FEATURE`: send one feature report.
pub const IOCTL_HID_SET_FEATURE: u32 = 0x000B_0003;

/// DriverKit capability descriptor for one Windows-facing device class.
pub fn capability_for_class(class: DeviceClass) -> CapabilityDescriptor {
    match class {
        DeviceClass::Hid => CapabilityDescriptor::new(
            DeviceFamily::Hid,
            false,
            vec![
                ProxyOperation::Enumerate,
                ProxyOperation::Open,
                ProxyOperation::Close,
                ProxyOperation::Read,
                ProxyOperation::Write,
                ProxyOperation::Ioctl,
                ProxyOperation::Hotplug,
                ProxyOperation::Descriptor,
            ],
            Vec::new(),
        ),
        DeviceClass::Serial => CapabilityDescriptor::new(
            DeviceFamily::Serial,
            false,
            vec![
                ProxyOperation::Enumerate,
                ProxyOperation::Open,
                ProxyOperation::Close,
                ProxyOperation::Read,
                ProxyOperation::Write,
                ProxyOperation::Ioctl,
                ProxyOperation::Hotplug,
                ProxyOperation::Descriptor,
            ],
            Vec::new(),
        ),
        DeviceClass::Usb => CapabilityDescriptor::new(
            DeviceFamily::Usb,
            true,
            vec![
                ProxyOperation::Enumerate,
                ProxyOperation::Open,
                ProxyOperation::Close,
                ProxyOperation::Hotplug,
                ProxyOperation::Descriptor,
            ],
            vec![ProxyOperation::Read, ProxyOperation::Write],
        ),
        DeviceClass::Pci => CapabilityDescriptor::new(
            DeviceFamily::Pci,
            true,
            vec![
                ProxyOperation::Enumerate,
                ProxyOperation::Open,
                ProxyOperation::Close,
                ProxyOperation::Read,
                ProxyOperation::Hotplug,
                ProxyOperation::Descriptor,
            ],
            vec![ProxyOperation::Write, ProxyOperation::Ioctl],
        ),
        DeviceClass::Network => CapabilityDescriptor::new(
            DeviceFamily::Network,
            true,
            vec![
                ProxyOperation::Enumerate,
                ProxyOperation::Open,
                ProxyOperation::Close,
                ProxyOperation::Hotplug,
                ProxyOperation::Descriptor,
            ],
            vec![ProxyOperation::Write, ProxyOperation::Ioctl],
        ),
        DeviceClass::Audio => CapabilityDescriptor::new(
            DeviceFamily::Audio,
            false,
            vec![
                ProxyOperation::Enumerate,
                ProxyOperation::Open,
                ProxyOperation::Close,
                ProxyOperation::Hotplug,
                ProxyOperation::Descriptor,
            ],
            Vec::new(),
        ),
    }
}

/// The IOKit user-client transport.
pub struct IokitTransport {
    bridge: Arc<Mutex<PhysicalDeviceBridge>>,
}

impl IokitTransport {
    /// An empty transport; enumeration performs the real host scans.
    pub fn new() -> Self {
        Self {
            bridge: Arc::new(Mutex::new(PhysicalDeviceBridge::new())),
        }
    }

    fn lock(&self) -> MutexGuard<'_, PhysicalDeviceBridge> {
        self.bridge
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for IokitTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceTransport for IokitTransport {
    fn enumerate(&mut self) -> Result<Vec<DeviceRecord>, ProxyError> {
        let mut bridge = self.lock();
        bridge.refresh().map_err(ProxyError::from_device_error)?;
        Ok(bridge.devices())
    }

    fn hotplug(&mut self) -> Result<Vec<HotplugEvent>, ProxyError> {
        self.lock().refresh().map_err(ProxyError::from_device_error)
    }

    fn descriptor(&self, id: StableDeviceId) -> Option<CapabilityDescriptor> {
        self.lock()
            .device(id)
            .map(|record| capability_for_class(record.class))
    }

    fn open(
        &mut self,
        id: StableDeviceId,
        _deadline: Option<Instant>,
    ) -> Result<Box<dyn DeviceChannel>, ProxyError> {
        let bridge = self.lock();
        let record = bridge.device(id).ok_or(ProxyError::DeviceMissing { id })?;
        let descriptor = capability_for_class(record.class);
        descriptor.require(ProxyOperation::Open)?;
        let kind = match record.class {
            DeviceClass::Hid => IokitKind::Hid,
            DeviceClass::Serial => IokitKind::Serial,
            DeviceClass::Pci => IokitKind::Pci,
            DeviceClass::Usb | DeviceClass::Network | DeviceClass::Audio => IokitKind::QueryOnly,
        };
        Ok(Box::new(IokitChannel {
            bridge: Arc::clone(&self.bridge),
            id,
            kind,
            descriptor,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IokitKind {
    Hid,
    Serial,
    Pci,
    QueryOnly,
}

struct IokitChannel {
    bridge: Arc<Mutex<PhysicalDeviceBridge>>,
    id: StableDeviceId,
    kind: IokitKind,
    descriptor: CapabilityDescriptor,
}

impl IokitChannel {
    fn lock(&self) -> MutexGuard<'_, PhysicalDeviceBridge> {
        self.bridge
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn map_error(
        &self,
        operation: ProxyOperation,
        error: crate::real_hid::DeviceError,
    ) -> ProxyError {
        match error {
            crate::real_hid::DeviceError::Unsupported { .. } => ProxyError::Unsupported {
                family: self.descriptor.family,
                operation,
            },
            other => ProxyError::from_device_error(other),
        }
    }

    fn timeout(&self, deadline: Option<Instant>) -> Result<Duration, ProxyError> {
        let deadline = resolve_deadline(deadline);
        remaining(deadline).ok_or(ProxyError::Timeout { timeout_ms: 0 })
    }
}

impl DeviceChannel for IokitChannel {
    fn descriptor(&self) -> CapabilityDescriptor {
        self.descriptor.clone()
    }

    fn read(
        &mut self,
        buffer: &mut [u8],
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<usize, ProxyError> {
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }
        let timeout = self.timeout(deadline)?;
        match self.kind {
            IokitKind::Hid => {
                let bridge = self.lock();
                let mut device = bridge
                    .hid()
                    .open(self.id)
                    .map_err(|error| self.map_error(ProxyOperation::Read, error))?;
                device.pump_events(timeout);
                if cancel.is_cancelled() {
                    return Err(ProxyError::Cancelled);
                }
                let report = device
                    .read_report(Duration::ZERO)
                    .map_err(|error| self.map_error(ProxyOperation::Read, error))?;
                let Some(report) = report else {
                    return Err(ProxyError::Timeout {
                        timeout_ms: timeout.as_millis() as u64,
                    });
                };
                let count = buffer.len().min(report.data.len());
                buffer[..count].copy_from_slice(&report.data[..count]);
                Ok(count)
            }
            IokitKind::Serial => {
                let bridge = self.lock();
                let mut device = bridge
                    .serial()
                    .open(self.id, SerialConfig::default())
                    .map_err(|error| self.map_error(ProxyOperation::Read, error))?;
                device
                    .read(buffer, timeout)
                    .map_err(|error| self.map_error(ProxyOperation::Read, error))
            }
            IokitKind::Pci => {
                let bridge = self.lock();
                let info = bridge
                    .pci()
                    .device(self.id)
                    .ok_or(ProxyError::DeviceMissing { id: self.id })?;
                let bytes = info
                    .config_read(0, buffer.len())
                    .map_err(|error| self.map_error(ProxyOperation::Read, error))?;
                let count = buffer.len().min(bytes.len());
                buffer[..count].copy_from_slice(&bytes[..count]);
                Ok(count)
            }
            IokitKind::QueryOnly => Err(ProxyError::Unsupported {
                family: self.descriptor.family,
                operation: ProxyOperation::Read,
            }),
        }
    }

    fn write(
        &mut self,
        data: &[u8],
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<usize, ProxyError> {
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }
        let timeout = self.timeout(deadline)?;
        match self.kind {
            IokitKind::Hid => {
                let bridge = self.lock();
                let mut device = bridge
                    .hid()
                    .open(self.id)
                    .map_err(|error| self.map_error(ProxyOperation::Write, error))?;
                device
                    .send_output_report(0, data)
                    .map_err(|error| self.map_error(ProxyOperation::Write, error))?;
                Ok(data.len())
            }
            IokitKind::Serial => {
                let bridge = self.lock();
                let mut device = bridge
                    .serial()
                    .open(self.id, SerialConfig::default())
                    .map_err(|error| self.map_error(ProxyOperation::Write, error))?;
                device
                    .write(data, timeout)
                    .map_err(|error| self.map_error(ProxyOperation::Write, error))
            }
            IokitKind::Pci | IokitKind::QueryOnly => Err(ProxyError::Unsupported {
                family: self.descriptor.family,
                operation: ProxyOperation::Write,
            }),
        }
    }

    fn ioctl(
        &mut self,
        code: u32,
        input: &[u8],
        output_len: usize,
        _deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<Vec<u8>, ProxyError> {
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }
        match self.kind {
            IokitKind::Hid => {
                let bridge = self.lock();
                let mut device = bridge
                    .hid()
                    .open(self.id)
                    .map_err(|error| self.map_error(ProxyOperation::Ioctl, error))?;
                match code {
                    IOCTL_HID_READ_REPORT => {
                        let mut buffer = vec![0_u8; output_len.max(1)];
                        let count = device
                            .get_input_report(0, &mut buffer)
                            .map_err(|error| self.map_error(ProxyOperation::Ioctl, error))?;
                        buffer.truncate(count.min(output_len));
                        Ok(buffer)
                    }
                    IOCTL_HID_WRITE_REPORT => {
                        device
                            .send_output_report(0, input)
                            .map_err(|error| self.map_error(ProxyOperation::Ioctl, error))?;
                        Ok(Vec::new())
                    }
                    IOCTL_HID_SET_FEATURE => {
                        device
                            .send_feature_report(0, input)
                            .map_err(|error| self.map_error(ProxyOperation::Ioctl, error))?;
                        Ok(Vec::new())
                    }
                    _ => Err(ProxyError::UnsupportedIoctl { code }),
                }
            }
            IokitKind::Serial => Err(ProxyError::UnsupportedIoctl { code }),
            IokitKind::Pci | IokitKind::QueryOnly => Err(ProxyError::Unsupported {
                family: self.descriptor.family,
                operation: ProxyOperation::Ioctl,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entitlement_gated_families_report_privilege_not_held() {
        let usb = capability_for_class(DeviceClass::Usb);
        assert!(usb.entitlement_required);
        assert_eq!(
            usb.require(ProxyOperation::Read),
            Err(ProxyError::EntitlementRequired {
                family: DeviceFamily::Usb,
                operation: ProxyOperation::Read,
            })
        );
        assert!(usb.require(ProxyOperation::Open).is_ok());
        let pci = capability_for_class(DeviceClass::Pci);
        assert_eq!(
            pci.require(ProxyOperation::Ioctl),
            Err(ProxyError::EntitlementRequired {
                family: DeviceFamily::Pci,
                operation: ProxyOperation::Ioctl,
            })
        );
        assert!(pci.require(ProxyOperation::Read).is_ok());
        let network = capability_for_class(DeviceClass::Network);
        assert_eq!(
            network.require(ProxyOperation::Write),
            Err(ProxyError::EntitlementRequired {
                family: DeviceFamily::Network,
                operation: ProxyOperation::Write,
            })
        );
    }

    #[test]
    fn unentitled_families_expose_real_operations_and_audio_is_unsupported() {
        for class in [DeviceClass::Hid, DeviceClass::Serial] {
            let descriptor = capability_for_class(class);
            assert!(!descriptor.entitlement_required);
            for operation in [
                ProxyOperation::Enumerate,
                ProxyOperation::Open,
                ProxyOperation::Read,
                ProxyOperation::Write,
                ProxyOperation::Ioctl,
                ProxyOperation::Hotplug,
                ProxyOperation::Descriptor,
            ] {
                assert!(
                    descriptor.require(operation).is_ok(),
                    "{} must expose {operation:?}",
                    class.as_str()
                );
            }
        }
        let audio = capability_for_class(DeviceClass::Audio);
        assert_eq!(
            audio.require(ProxyOperation::Read),
            Err(ProxyError::Unsupported {
                family: DeviceFamily::Audio,
                operation: ProxyOperation::Read,
            })
        );
        assert_eq!(
            audio.require(ProxyOperation::Read).unwrap_err().ntstatus(),
            crate::casak::status::STATUS_NOT_SUPPORTED
        );
    }
}
