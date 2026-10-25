//! Plug-and-play and power state machine.
//!
//! Devices form a real parent/child tree.  A device must be started before it
//! can enter a device power state, removal is refused while children remain,
//! and a device whose host backing is unavailable never reports a synthetic
//! start or D0 success.

use std::collections::{BTreeMap, BTreeSet};

use crate::casak::status::{
    STATUS_DELETE_PENDING, STATUS_DEVICE_HARDWARE_ERROR, STATUS_DEVICE_NOT_READY,
    STATUS_INVALID_DEVICE_STATE, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_POWER_STATE_INVALID,
};

/// `IRP_MN_SET_POWER`.
pub const IRP_MN_SET_POWER: u8 = 0x02;

/// Monotonic device-node identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceNodeId(pub u64);

/// Device power state (`WdfPowerDeviceD0`..`D3` values are 1..=4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PowerState {
    D0,
    D1,
    D2,
    D3,
}

impl PowerState {
    /// Converts the guest-visible `WdfPowerDevice*` value.
    pub fn from_raw(value: u32) -> Result<Self, i32> {
        match value {
            1 => Ok(Self::D0),
            2 => Ok(Self::D1),
            3 => Ok(Self::D2),
            4 => Ok(Self::D3),
            _ => Err(STATUS_POWER_STATE_INVALID),
        }
    }

    pub const fn raw(self) -> u32 {
        match self {
            Self::D0 => 1,
            Self::D1 => 2,
            Self::D2 => 3,
            Self::D3 => 4,
        }
    }
}

/// Lifecycle state of a device node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Created,
    Started,
    Stopped,
    Removed,
}

/// A device-tree node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNode {
    pub id: DeviceNodeId,
    pub name: String,
    pub parent: Option<DeviceNodeId>,
    pub state: DeviceState,
    pub power: PowerState,
    pub host_present: bool,
    pub children: BTreeSet<DeviceNodeId>,
}

/// The PnP/power manager.
#[derive(Debug)]
pub struct PnpManager {
    nodes: BTreeMap<DeviceNodeId, DeviceNode>,
    names: BTreeMap<String, DeviceNodeId>,
    next_id: u64,
}

impl PnpManager {
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            names: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Adds a device node.  Names are unique case-insensitively and a parent
    /// must exist and not be removed.
    pub fn add_device(
        &mut self,
        name: &str,
        parent: Option<DeviceNodeId>,
        host_present: bool,
    ) -> Result<DeviceNodeId, i32> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.contains('\0') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let key = trimmed.to_ascii_lowercase();
        if self.names.contains_key(&key) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        if let Some(parent_id) = parent {
            let record = self.nodes.get(&parent_id).ok_or(STATUS_INVALID_HANDLE)?;
            if record.state == DeviceState::Removed {
                return Err(STATUS_DELETE_PENDING);
            }
        }
        let id = DeviceNodeId(self.next_id);
        self.next_id += 1;
        self.nodes.insert(
            id,
            DeviceNode {
                id,
                name: trimmed.to_string(),
                parent,
                state: DeviceState::Created,
                power: PowerState::D3,
                host_present,
                children: BTreeSet::new(),
            },
        );
        self.names.insert(key, id);
        if let Some(parent_id) = parent {
            if let Some(record) = self.nodes.get_mut(&parent_id) {
                record.children.insert(id);
            }
        }
        Ok(id)
    }

    /// Starts a device.  A host-unavailable device fails with
    /// `STATUS_DEVICE_HARDWARE_ERROR`; there is no synthetic success.
    pub fn start_device(&mut self, id: DeviceNodeId) -> Result<PowerState, i32> {
        let record = self.nodes.get(&id).ok_or(STATUS_INVALID_HANDLE)?;
        match record.state {
            DeviceState::Removed => Err(STATUS_DELETE_PENDING),
            DeviceState::Started => Err(STATUS_INVALID_DEVICE_STATE),
            DeviceState::Created | DeviceState::Stopped => {
                if !record.host_present {
                    return Err(STATUS_DEVICE_HARDWARE_ERROR);
                }
                if let Some(record) = self.nodes.get_mut(&id) {
                    record.state = DeviceState::Started;
                    record.power = PowerState::D0;
                }
                Ok(PowerState::D0)
            }
        }
    }

    /// Stops a started device.
    pub fn stop_device(&mut self, id: DeviceNodeId) -> Result<PowerState, i32> {
        let record = self.nodes.get(&id).ok_or(STATUS_INVALID_HANDLE)?;
        match record.state {
            DeviceState::Removed => Err(STATUS_DELETE_PENDING),
            DeviceState::Started => {
                if let Some(record) = self.nodes.get_mut(&id) {
                    record.state = DeviceState::Stopped;
                    record.power = PowerState::D3;
                }
                Ok(PowerState::D3)
            }
            DeviceState::Created | DeviceState::Stopped => Err(STATUS_INVALID_DEVICE_STATE),
        }
    }

    /// Moves a started device to `power`.  Repeating the current state and
    /// powering up a device that is not started are both invalid.
    pub fn set_power(&mut self, id: DeviceNodeId, power: PowerState) -> Result<PowerState, i32> {
        let record = self.nodes.get(&id).ok_or(STATUS_INVALID_HANDLE)?;
        match record.state {
            DeviceState::Removed => Err(STATUS_DELETE_PENDING),
            DeviceState::Created | DeviceState::Stopped => {
                if power == PowerState::D0 {
                    Err(STATUS_DEVICE_NOT_READY)
                } else {
                    Err(STATUS_INVALID_DEVICE_STATE)
                }
            }
            DeviceState::Started => {
                if !record.host_present {
                    return Err(STATUS_DEVICE_HARDWARE_ERROR);
                }
                if record.power == power {
                    return Err(STATUS_INVALID_DEVICE_STATE);
                }
                if let Some(record) = self.nodes.get_mut(&id) {
                    record.power = power;
                }
                Ok(power)
            }
        }
    }

    /// Dispatches `IRP_MJ_POWER`/`IRP_MN_SET_POWER` with `raw_power`.
    pub fn power_irp(
        &mut self,
        id: DeviceNodeId,
        minor: u8,
        raw_power: u32,
    ) -> Result<PowerState, i32> {
        if !self.nodes.contains_key(&id) {
            return Err(STATUS_INVALID_HANDLE);
        }
        if self
            .nodes
            .get(&id)
            .is_some_and(|record| record.state == DeviceState::Removed)
        {
            return Err(STATUS_DELETE_PENDING);
        }
        if minor != IRP_MN_SET_POWER {
            return Err(STATUS_NOT_SUPPORTED);
        }
        self.set_power(id, PowerState::from_raw(raw_power)?)
    }

    /// Removes a device.  A device with live children is busy.
    pub fn remove_device(&mut self, id: DeviceNodeId) -> Result<(), i32> {
        let record = self.nodes.get(&id).ok_or(STATUS_INVALID_HANDLE)?;
        if record.state == DeviceState::Removed {
            return Err(STATUS_DELETE_PENDING);
        }
        if !record.children.is_empty() {
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
        let (parent, name) = (record.parent, record.name.to_ascii_lowercase());
        if let Some(parent_id) = parent {
            if let Some(record) = self.nodes.get_mut(&parent_id) {
                record.children.remove(&id);
            }
        }
        self.names.remove(&name);
        if let Some(record) = self.nodes.get_mut(&id) {
            record.state = DeviceState::Removed;
            record.power = PowerState::D3;
        }
        Ok(())
    }

    /// Delivers `IRP_MN_REMOVE_DEVICE`.
    pub fn remove_irp(&mut self, id: DeviceNodeId) -> Result<(), i32> {
        self.remove_device(id)
    }

    pub fn query(&self, id: DeviceNodeId) -> Result<&DeviceNode, i32> {
        self.nodes.get(&id).ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn find(&self, name: &str) -> Result<DeviceNodeId, i32> {
        self.names
            .get(&name.trim().to_ascii_lowercase())
            .copied()
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    pub fn children(&self, id: DeviceNodeId) -> Result<Vec<DeviceNodeId>, i32> {
        Ok(self.query(id)?.children.iter().copied().collect())
    }

    pub fn device_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn child_count(&self, id: DeviceNodeId) -> Result<usize, i32> {
        Ok(self.query(id)?.children.len())
    }
}

impl Default for PnpManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_device_rejects_invalid_names_duplicates_and_missing_parents() {
        assert_eq!(PnpManager::default().device_count(), 0);
        let mut manager = PnpManager::new();
        assert_eq!(
            manager.add_device("", None, true),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.add_device("bad\0", None, true),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.add_device("child", Some(DeviceNodeId(404)), true),
            Err(STATUS_INVALID_HANDLE)
        );
        let root = manager.add_device("Root", None, true).unwrap();
        assert_eq!(
            manager.add_device("root", None, true),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        let child = manager.add_device("Child", Some(root), true).unwrap();
        assert_eq!(manager.find(" child ").unwrap(), child);
        assert_eq!(manager.find("missing"), Err(STATUS_OBJECT_NAME_NOT_FOUND));
        assert_eq!(manager.children(root).unwrap(), vec![child]);
        assert_eq!(manager.child_count(root).unwrap(), 1);
        assert_eq!(manager.device_count(), 2);
        assert_eq!(manager.query(child).unwrap().state, DeviceState::Created);
        assert_eq!(manager.query(child).unwrap().power, PowerState::D3);
        assert_eq!(manager.query(DeviceNodeId(404)), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            manager.children(DeviceNodeId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.child_count(DeviceNodeId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn start_stop_and_remove_state_machine_rejects_invalid_transitions() {
        let mut manager = PnpManager::new();
        let root = manager.add_device("Root", None, true).unwrap();
        let child = manager.add_device("Child", Some(root), true).unwrap();
        assert_eq!(
            manager.remove_device(root),
            Err(STATUS_INVALID_DEVICE_STATE)
        );
        assert_eq!(manager.start_device(child).unwrap(), PowerState::D0);
        assert_eq!(
            manager.start_device(child),
            Err(STATUS_INVALID_DEVICE_STATE)
        );
        assert_eq!(manager.stop_device(child).unwrap(), PowerState::D3);
        assert_eq!(manager.stop_device(child), Err(STATUS_INVALID_DEVICE_STATE));
        assert_eq!(manager.start_device(child).unwrap(), PowerState::D0);
        assert_eq!(manager.remove_device(child), Ok(()));
        assert_eq!(manager.remove_device(child), Err(STATUS_DELETE_PENDING));
        assert_eq!(manager.remove_irp(child), Err(STATUS_DELETE_PENDING));
        assert_eq!(manager.start_device(child), Err(STATUS_DELETE_PENDING));
        assert_eq!(manager.stop_device(child), Err(STATUS_DELETE_PENDING));
        assert_eq!(
            manager.set_power(child, PowerState::D1),
            Err(STATUS_DELETE_PENDING)
        );
        assert_eq!(
            manager.power_irp(child, IRP_MN_SET_POWER, 1),
            Err(STATUS_DELETE_PENDING)
        );
        assert_eq!(
            manager.add_device("Late", Some(child), true),
            Err(STATUS_DELETE_PENDING)
        );
        assert_eq!(manager.query(child).unwrap().state, DeviceState::Removed);
        assert_eq!(manager.query(child).unwrap().power, PowerState::D3);
        assert_eq!(manager.remove_device(root), Ok(()));
        assert_eq!(manager.start_device(root), Err(STATUS_DELETE_PENDING));
        assert_eq!(manager.stop_device(root), Err(STATUS_DELETE_PENDING));
        assert_eq!(
            manager.start_device(DeviceNodeId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.stop_device(DeviceNodeId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.set_power(DeviceNodeId(404), PowerState::D0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.remove_device(DeviceNodeId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn host_unavailable_devices_never_report_synthetic_success() {
        let mut manager = PnpManager::new();
        let absent = manager.add_device("Absent", None, false).unwrap();
        assert_eq!(
            manager.start_device(absent),
            Err(STATUS_DEVICE_HARDWARE_ERROR)
        );
        assert_eq!(
            manager.power_irp(absent, IRP_MN_SET_POWER, 1),
            Err(STATUS_DEVICE_NOT_READY)
        );
        let started = manager.add_device("Present", None, true).unwrap();
        manager.start_device(started).unwrap();
        manager.nodes.get_mut(&started).unwrap().host_present = false;
        assert_eq!(
            manager.set_power(started, PowerState::D1),
            Err(STATUS_DEVICE_HARDWARE_ERROR)
        );
    }

    #[test]
    fn power_irp_rejects_unsupported_minors_states_and_values() {
        let mut manager = PnpManager::new();
        let device = manager.add_device("Device", None, true).unwrap();
        assert_eq!(
            manager.power_irp(DeviceNodeId(404), IRP_MN_SET_POWER, 1),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.power_irp(device, 0x01, 1),
            Err(STATUS_NOT_SUPPORTED)
        );
        assert_eq!(
            manager.power_irp(device, IRP_MN_SET_POWER, 9),
            Err(STATUS_POWER_STATE_INVALID)
        );
        assert_eq!(
            manager.set_power(device, PowerState::D0),
            Err(STATUS_DEVICE_NOT_READY)
        );
        assert_eq!(
            manager.set_power(device, PowerState::D1),
            Err(STATUS_INVALID_DEVICE_STATE)
        );
        manager.start_device(device).unwrap();
        assert_eq!(
            manager.set_power(device, PowerState::D0),
            Err(STATUS_INVALID_DEVICE_STATE)
        );
        assert_eq!(
            manager
                .power_irp(device, IRP_MN_SET_POWER, PowerState::D1.raw())
                .unwrap(),
            PowerState::D1
        );
        assert_eq!(
            manager
                .power_irp(device, IRP_MN_SET_POWER, PowerState::D3.raw())
                .unwrap(),
            PowerState::D3
        );
        assert_eq!(
            manager.set_power(device, PowerState::D0).unwrap(),
            PowerState::D0
        );
        assert_eq!(PowerState::from_raw(1).unwrap(), PowerState::D0);
        assert_eq!(PowerState::from_raw(2).unwrap(), PowerState::D1);
        assert_eq!(PowerState::from_raw(3).unwrap(), PowerState::D2);
        assert_eq!(PowerState::from_raw(4).unwrap(), PowerState::D3);
        assert_eq!(PowerState::from_raw(0), Err(STATUS_POWER_STATE_INVALID));
        assert_eq!(PowerState::D0.raw(), 1);
        assert_eq!(PowerState::D1.raw(), 2);
        assert_eq!(PowerState::D2.raw(), 3);
        assert_eq!(PowerState::D3.raw(), 4);
    }
}
