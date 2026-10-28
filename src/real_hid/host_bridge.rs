//! DriverKit-style host-device abstraction shared by the physical bridges.
//!
//! Every bridge exposes the same lifecycle: enumerate real host devices into a
//! stable-ID table, report exact hotplug deltas, and hand out a user client for
//! operations the host actually permits.  Operations that need a DriverKit
//! entitlement are reported as [`DeviceError::Unsupported`] rather than being
//! emulated.

use super::error::DeviceError;
use super::model::{DeviceClass, DeviceRecord, HotplugEvent, StableDeviceId};

/// An operation a host bridge can be asked to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostOperation {
    /// Enumerate attached host devices.
    Enumerate,
    /// Open a user client for one device.
    Open,
    /// Read PCI configuration space.
    ConfigSpaceRead,
    /// Write PCI configuration space.
    ConfigSpaceWrite,
    /// Map or read a PCI BAR.
    BarMapping,
    /// Submit a device data transfer.
    DataTransfer,
    /// Open an audio stream on an endpoint.
    AudioStream,
    /// Change link state (up/down, media selection).
    LinkControl,
}

impl HostOperation {
    /// Stable feature name used by the unsupported-operation error.
    pub const fn feature(self) -> &'static str {
        match self {
            Self::Enumerate => "host enumeration",
            Self::Open => "host user client",
            Self::ConfigSpaceRead => "pci config space read",
            Self::ConfigSpaceWrite => "pci config space write",
            Self::BarMapping => "pci BAR mapping",
            Self::DataTransfer => "device data transfer",
            Self::AudioStream => "audio stream open",
            Self::LinkControl => "network link control",
        }
    }
}

/// A DriverKit-equivalent user client.
///
/// The default methods refuse the operation with an exact unsupported error;
/// a bridge overrides only the operations the real host permits.  This is the
/// abstraction that keeps entitlement-limited surfaces honest instead of
/// returning fabricated success.
pub trait HostUserClient {
    /// Stable identity of the device backing this client.
    fn device_id(&self) -> StableDeviceId;

    /// Windows-facing class of the device backing this client.
    fn class(&self) -> DeviceClass;

    /// Read from the device's register or configuration window.
    fn read(&mut self, offset: u16, length: usize) -> Result<Vec<u8>, DeviceError> {
        let _ = (offset, length);
        Err(DeviceError::Unsupported {
            feature: "host user client read",
        })
    }

    /// Write to the device's register or configuration window.
    fn write(&mut self, offset: u16, data: &[u8]) -> Result<(), DeviceError> {
        let _ = (offset, data);
        Err(DeviceError::Unsupported {
            feature: "host user client write",
        })
    }

    /// Invoke a bridge-specific control request.
    fn control(&mut self, request: u32, payload: &[u8]) -> Result<Vec<u8>, DeviceError> {
        let _ = (request, payload);
        Err(DeviceError::Unsupported {
            feature: "host user client control",
        })
    }
}

/// A host-device bridge: stable-ID enumeration, hotplug refresh, and user
/// clients.
pub trait HostDeviceBridge {
    /// Windows-facing device class this bridge reports.
    fn class(&self) -> DeviceClass;

    /// Scan the real host and reconcile the bridge's table.
    fn enumerate(&mut self) -> Result<Vec<HotplugEvent>, DeviceError>;

    /// Snapshot every device currently in the bridge table.
    fn records(&self) -> Vec<DeviceRecord>;

    /// Look up one device record by stable ID.
    fn record(&self, id: StableDeviceId) -> Option<DeviceRecord>;

    /// Operations this bridge's host transport actually supports.
    fn supported_operations(&self) -> &'static [HostOperation];

    /// Open a user client for `id`, or return the exact missing-device error.
    fn open_user_client(&self, id: StableDeviceId) -> Result<Box<dyn HostUserClient>, DeviceError>;

    /// Refresh hotplug state.  The default is a plain re-enumeration; bridges
    /// with a cheaper delta path override it.
    fn refresh(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        self.enumerate()
    }

    /// Require one operation, returning the exact unsupported error when the
    /// host transport cannot provide it.
    fn operation_support(&self, operation: HostOperation) -> Result<(), DeviceError> {
        if self.supported_operations().contains(&operation) {
            Ok(())
        } else {
            Err(DeviceError::Unsupported {
                feature: operation.feature(),
            })
        }
    }
}

/// A user client for query-only bridges (network adapters, audio endpoints).
///
/// It identifies the real device but refuses register/control access that the
/// host bridge does not provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryOnlyUserClient {
    id: StableDeviceId,
    class: DeviceClass,
}

impl QueryOnlyUserClient {
    pub const fn new(id: StableDeviceId, class: DeviceClass) -> Self {
        Self { id, class }
    }
}

impl HostUserClient for QueryOnlyUserClient {
    fn device_id(&self) -> StableDeviceId {
        self.id
    }

    fn class(&self) -> DeviceClass {
        self.class
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_operations_have_exact_features_and_user_client_defaults() {
        let id = StableDeviceId::from_raw(0x5eed);
        let mut client = QueryOnlyUserClient::new(id, DeviceClass::Network);
        assert_eq!(client.device_id(), id);
        assert_eq!(client.class(), DeviceClass::Network);
        assert_eq!(
            client.read(0, 1),
            Err(DeviceError::Unsupported {
                feature: "host user client read"
            })
        );
        assert_eq!(
            client.write(0, &[1]),
            Err(DeviceError::Unsupported {
                feature: "host user client write"
            })
        );
        assert_eq!(
            client.control(7, &[]),
            Err(DeviceError::Unsupported {
                feature: "host user client control"
            })
        );

        let operations = [
            (HostOperation::Enumerate, "host enumeration"),
            (HostOperation::Open, "host user client"),
            (HostOperation::ConfigSpaceRead, "pci config space read"),
            (HostOperation::ConfigSpaceWrite, "pci config space write"),
            (HostOperation::BarMapping, "pci BAR mapping"),
            (HostOperation::DataTransfer, "device data transfer"),
            (HostOperation::AudioStream, "audio stream open"),
            (HostOperation::LinkControl, "network link control"),
        ];
        for (operation, feature) in operations {
            assert_eq!(operation.feature(), feature);
        }
    }
}
