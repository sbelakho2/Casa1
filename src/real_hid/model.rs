//! Shared physical-device model: stable IDs, device records, hotplug events,
//! and the reconcile table used by every bridge.  Records only ever describe
//! devices reported by the host; an empty scan produces an empty table.

use std::collections::BTreeMap;

/// The Windows-facing device class of a host device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceClass {
    Hid,
    Usb,
    Serial,
    Pci,
    Network,
    Audio,
}

impl DeviceClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hid => "hid",
            Self::Usb => "usb",
            Self::Serial => "serial",
            Self::Pci => "pci",
            Self::Network => "network",
            Self::Audio => "audio",
        }
    }
}

/// A stable device identifier suitable for a Windows handle table.
///
/// The value is derived from host-reported identity (serial, location, path,
/// registry entry) and never from an enumeration index, so unplugging one
/// device cannot rename a surviving device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableDeviceId(u64);

impl StableDeviceId {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub fn derive(class: DeviceClass, parts: &[&str]) -> Self {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in class.as_str().bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        for part in parts {
            hash ^= 0xff;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            for byte in part.as_bytes() {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        Self(if hash == 0 { 1 } else { hash })
    }
}

impl std::fmt::Display for StableDeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// A host device in the dispatch table.  `path` is the native resource
/// (callout device, IORegistry path, or location) used to reopen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub id: StableDeviceId,
    pub class: DeviceClass,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub path: Option<String>,
    pub registry_entry_id: u64,
}

impl DeviceRecord {
    pub fn display_name(&self) -> String {
        if let Some(product) = self.product.as_deref().filter(|name| !name.is_empty()) {
            return product.to_string();
        }
        match (self.vendor_id, self.product_id) {
            (Some(vendor), Some(product)) => {
                format!("{:04x}:{:04x}", vendor, product)
            }
            _ => format!("{} {}", self.class.as_str(), self.id),
        }
    }
}

/// A hotplug notification produced by [`DeviceTable::reconcile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotplugEvent {
    Arrived(DeviceRecord),
    Removed { record: DeviceRecord },
}

impl HotplugEvent {
    pub fn device(&self) -> &DeviceRecord {
        match self {
            Self::Arrived(record) => record,
            Self::Removed { record } => record,
        }
    }
}

/// The reconcile table behind a physical bridge.
#[derive(Debug, Default)]
pub(crate) struct OpenState {
    id: Option<StableDeviceId>,
    last_id: Option<StableDeviceId>,
}

impl OpenState {
    pub(crate) fn begin(&mut self, id: StableDeviceId) -> Result<(), super::error::DeviceError> {
        if let Some(open) = self.id {
            return Err(super::error::DeviceError::AlreadyOpen { id: open });
        }
        self.id = Some(id);
        self.last_id = Some(id);
        Ok(())
    }

    pub(crate) fn end(&mut self) -> Result<StableDeviceId, super::error::DeviceError> {
        match self.id.take() {
            Some(id) => {
                self.last_id = Some(id);
                Ok(id)
            }
            None => Err(super::error::DeviceError::AlreadyClosed {
                id: self.last_id.unwrap_or_else(|| StableDeviceId::from_raw(0)),
            }),
        }
    }

    pub(crate) fn is_open(&self) -> bool {
        self.id.is_some()
    }

    pub(crate) fn id(&self) -> Option<StableDeviceId> {
        self.id
    }

    pub(crate) fn last_id(&self) -> StableDeviceId {
        self.last_id
            .or(self.id)
            .unwrap_or_else(|| StableDeviceId::from_raw(0))
    }
}

#[derive(Debug, Clone, Default)]
pub struct DeviceTable {
    records: BTreeMap<StableDeviceId, DeviceRecord>,
    initialized: bool,
}

impl DeviceTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, id: StableDeviceId) -> Option<&DeviceRecord> {
        self.records.get(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &DeviceRecord> {
        self.records.values()
    }

    pub fn records(&self) -> Vec<DeviceRecord> {
        self.records.values().cloned().collect()
    }

    /// Replaces the table with a real host scan and returns exact hotplug
    /// deltas.  The first scan reports arrivals only; an empty scan on an
    /// already-initialized table reports removals and never synthesizes a
    /// placeholder device.
    pub fn reconcile(&mut self, incoming: Vec<DeviceRecord>) -> Vec<HotplugEvent> {
        let mut next = BTreeMap::new();
        for record in incoming {
            next.entry(record.id).or_insert(record);
        }

        let mut events = Vec::new();
        if !self.initialized {
            for record in next.values() {
                events.push(HotplugEvent::Arrived(record.clone()));
            }
            self.initialized = true;
        } else {
            for (id, record) in &next {
                if !self.records.contains_key(id) {
                    events.push(HotplugEvent::Arrived(record.clone()));
                }
            }
            for (id, record) in &self.records {
                if !next.contains_key(id) {
                    events.push(HotplugEvent::Removed {
                        record: record.clone(),
                    });
                }
            }
        }

        self.records = next;
        events
    }

    pub fn clear(&mut self) {
        self.records.clear();
        self.initialized = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: u64, product: &str) -> DeviceRecord {
        DeviceRecord {
            id: StableDeviceId::from_raw(id),
            class: DeviceClass::Hid,
            vendor_id: Some(0x045e),
            product_id: Some(0x028e),
            manufacturer: Some("Microsoft".to_string()),
            product: Some(product.to_string()),
            serial_number: None,
            path: Some("/dev/example".to_string()),
            registry_entry_id: id,
        }
    }

    #[test]
    fn unplug_race_reconcile_removes_once_and_never_synthesizes_devices() {
        let device = record(0x11, "Controller");
        let mut table = DeviceTable::new();

        assert_eq!(
            table.reconcile(vec![device.clone()]),
            vec![HotplugEvent::Arrived(device.clone())]
        );
        assert_eq!(
            table.reconcile(Vec::new()),
            vec![HotplugEvent::Removed {
                record: device.clone()
            }]
        );
        assert_eq!(table.reconcile(Vec::new()), Vec::<HotplugEvent>::new());
        assert!(table.is_empty());
    }

    #[test]
    fn duplicate_unplug_scan_reports_a_single_removal() {
        let device = record(0x22, "Controller");
        let mut table = DeviceTable::new();
        let _ = table.reconcile(vec![device.clone()]);
        assert_eq!(
            table.reconcile(vec![device.clone()]),
            Vec::<HotplugEvent>::new()
        );
        assert_eq!(
            table.reconcile(Vec::new()),
            vec![HotplugEvent::Removed { record: device }]
        );
    }

    #[test]
    fn model_stable_ids_and_table_clear_edges_are_exact() {
        assert_eq!(DeviceClass::Hid.as_str(), "hid");
        assert_eq!(DeviceClass::Usb.as_str(), "usb");
        assert_eq!(DeviceClass::Serial.as_str(), "serial");
        assert_eq!(DeviceClass::Pci.as_str(), "pci");
        assert_eq!(DeviceClass::Network.as_str(), "network");
        assert_eq!(DeviceClass::Audio.as_str(), "audio");

        let id = StableDeviceId::derive(DeviceClass::Hid, &["045e", "028e"]);
        assert_eq!(id.as_u64(), 0x7817_8703_29fa_74f7);
        assert_eq!(id.to_string(), "7817870329fa74f7");

        let named = record(0x31, "Controller");
        assert_eq!(named.display_name(), "Controller");
        let numeric = record(0x32, "");
        assert_eq!(numeric.display_name(), "045e:028e");
        let mut anonymous = record(0x33, "");
        anonymous.product = None;
        anonymous.vendor_id = None;
        anonymous.product_id = None;
        assert_eq!(
            anonymous.display_name(),
            format!("hid {anonymous_id}", anonymous_id = anonymous.id)
        );

        let arrived = HotplugEvent::Arrived(named.clone());
        let removed = HotplugEvent::Removed {
            record: named.clone(),
        };
        assert_eq!(arrived.device(), &named);
        assert_eq!(removed.device(), &named);

        let open_id = StableDeviceId::from_raw(0x77);
        let mut open = OpenState::default();
        assert!(!open.is_open());
        assert_eq!(open.id(), None);
        assert_eq!(open.last_id().as_u64(), 0);
        assert_eq!(open.begin(open_id), Ok(()));
        assert!(open.is_open());
        assert_eq!(open.id(), Some(open_id));
        assert_eq!(open.last_id(), open_id);
        assert_eq!(open.end(), Ok(open_id));
        assert_eq!(open.last_id(), open_id);
        assert_eq!(
            open.end(),
            Err(crate::real_hid::error::DeviceError::AlreadyClosed { id: open_id })
        );

        let mut table = DeviceTable::new();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert_eq!(table.get(open_id), None);
        assert_eq!(table.iter().count(), 0);
        assert_eq!(table.records(), Vec::new());
        assert_eq!(
            table.reconcile(vec![named.clone(), named.clone()]),
            vec![HotplugEvent::Arrived(named.clone())]
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(named.id), Some(&named));
        assert_eq!(table.iter().count(), 1);
        assert_eq!(table.records(), vec![named.clone()]);
        assert_eq!(
            table.reconcile(vec![named.clone()]),
            Vec::<HotplugEvent>::new()
        );
        let other = record(0x44, "Other");
        assert_eq!(
            table.reconcile(vec![other.clone()]),
            vec![
                HotplugEvent::Arrived(other.clone()),
                HotplugEvent::Removed {
                    record: named.clone()
                }
            ]
        );
        table.clear();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert_eq!(table.records(), Vec::new());
        assert_eq!(
            table.reconcile(vec![named.clone()]),
            vec![HotplugEvent::Arrived(named)]
        );
    }
}
