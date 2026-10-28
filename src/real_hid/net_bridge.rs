//! Real host network-interface enumeration.
//!
//! Interfaces come from `getifaddrs`; MAC addresses, MTU, speed, interface
//! type, addresses, and link state are the host's own values.  The bridge never
//! invents an adapter: an empty host list produces an empty table.  Adapters
//! are exposed with Windows-adapter-style metadata but only query operations
//! are supported (link control needs a privileged host path).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::error::DeviceError;
use super::host_bridge::{HostDeviceBridge, HostOperation, HostUserClient, QueryOnlyUserClient};
use super::model::{DeviceClass, DeviceRecord, DeviceTable, HotplugEvent, StableDeviceId};

/// One real host interface after all `getifaddrs` nodes were merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAdapterInfo {
    pub id: StableDeviceId,
    pub bsd_name: String,
    pub if_index: u32,
    pub mac: Option<[u8; 6]>,
    pub if_type: u32,
    pub mtu: u32,
    pub speed: u64,
    pub flags: u32,
    /// `IfOperStatusUp` (1) or `IfOperStatusDown` (2).
    pub oper_status: u32,
    /// Windows `MediaConnectState`: connected (1) or disconnected (2).
    pub media_connect_state: u32,
    pub ipv4: Vec<(Ipv4Addr, u8)>,
    pub ipv6: Vec<Ipv6Addr>,
}

impl NetworkAdapterInfo {
    pub fn record(&self) -> DeviceRecord {
        DeviceRecord {
            id: self.id,
            class: DeviceClass::Network,
            vendor_id: None,
            product_id: None,
            manufacturer: None,
            product: Some(self.bsd_name.clone()),
            serial_number: self.mac.map(|mac| format_mac(&mac)),
            path: Some(self.bsd_name.clone()),
            registry_entry_id: u64::from(self.if_index),
        }
    }

    /// Windows-adapter-style view of the real interface.
    pub fn windows_entry(&self) -> WindowsAdapterEntry {
        WindowsAdapterEntry {
            handle: self.id.as_u64(),
            device_id: self.id,
            if_index: self.if_index,
            adapter_name: self.bsd_name.clone(),
            friendly_name: self.bsd_name.clone(),
            description: self.bsd_name.clone(),
            mac: self.mac,
            if_type: self.if_type,
            mtu: self.mtu,
            speed: self.speed,
            oper_status: self.oper_status,
            media_connect_state: self.media_connect_state,
            ipv4: self.ipv4.clone(),
            ipv6: self.ipv6.clone(),
        }
    }
}

/// One raw `getifaddrs` observation before nodes are merged by interface name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawInterfaceRecord {
    pub name: String,
    pub if_index: u32,
    pub if_type: u32,
    pub mtu: u32,
    pub speed: u64,
    pub flags: u32,
    pub mac: Option<[u8; 6]>,
    pub ipv4: Vec<(Ipv4Addr, u8)>,
    pub ipv6: Vec<Ipv6Addr>,
}

impl RawInterfaceRecord {
    fn merge(&mut self, other: RawInterfaceRecord) {
        self.flags |= other.flags;
        if self.if_index == 0 {
            self.if_index = other.if_index;
        }
        if self.if_type == 0 {
            self.if_type = other.if_type;
        }
        if self.mtu == 0 {
            self.mtu = other.mtu;
        }
        if self.speed == 0 {
            self.speed = other.speed;
        }
        if self.mac.is_none() {
            self.mac = other.mac;
        }
        self.ipv4.extend(other.ipv4);
        self.ipv4.sort_unstable();
        self.ipv4.dedup();
        self.ipv6.extend(other.ipv6);
        self.ipv6.sort_unstable();
        self.ipv6.dedup();
    }
}

/// Merge raw observations into one adapter per real interface name.
pub fn build_adapters(records: Vec<RawInterfaceRecord>) -> Vec<NetworkAdapterInfo> {
    let mut merged: BTreeMap<String, RawInterfaceRecord> = BTreeMap::new();
    for record in records {
        if record.name.is_empty() {
            continue;
        }
        match merged.get_mut(&record.name) {
            Some(existing) => existing.merge(record),
            None => {
                merged.insert(record.name.clone(), record);
            }
        }
    }
    let mut adapters: Vec<NetworkAdapterInfo> = merged
        .into_values()
        .map(NetworkAdapterInfo::from_raw)
        .collect();
    adapters.sort_by_key(|adapter| adapter.id);
    adapters
}

impl NetworkAdapterInfo {
    fn from_raw(raw: RawInterfaceRecord) -> Self {
        let mac_key = match raw.mac {
            Some(mac) => format_mac(&mac),
            None => raw.if_index.to_string(),
        };
        let id = StableDeviceId::derive(DeviceClass::Network, &[&raw.name, &mac_key]);
        let up = link_is_up(raw.flags);
        Self {
            id,
            bsd_name: raw.name,
            if_index: raw.if_index,
            mac: raw.mac,
            if_type: raw.if_type,
            mtu: raw.mtu,
            speed: raw.speed,
            flags: raw.flags,
            oper_status: if up { 1 } else { 2 },
            media_connect_state: if up { 1 } else { 2 },
            ipv4: raw.ipv4,
            ipv6: raw.ipv6,
        }
    }
}

/// Windows `IP_ADAPTER_ADDRESSES`-style metadata for a real interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsAdapterEntry {
    pub handle: u64,
    pub device_id: StableDeviceId,
    pub if_index: u32,
    pub adapter_name: String,
    pub friendly_name: String,
    pub description: String,
    pub mac: Option<[u8; 6]>,
    pub if_type: u32,
    pub mtu: u32,
    pub speed: u64,
    pub oper_status: u32,
    pub media_connect_state: u32,
    pub ipv4: Vec<(Ipv4Addr, u8)>,
    pub ipv6: Vec<Ipv6Addr>,
}

fn link_is_up(flags: u32) -> bool {
    let up = flags & (libc::IFF_UP as u32) != 0;
    let running = flags & (libc::IFF_RUNNING as u32) != 0;
    up && running
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

const NETWORK_OPERATIONS: &[HostOperation] = &[HostOperation::Enumerate];

#[derive(Debug, Clone, Default)]
pub struct NetworkBridge {
    devices: Vec<NetworkAdapterInfo>,
    table: DeviceTable,
}

impl NetworkBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devices(&self) -> &[NetworkAdapterInfo] {
        &self.devices
    }

    pub fn table(&self) -> &DeviceTable {
        &self.table
    }

    pub fn device(&self, id: StableDeviceId) -> Option<&NetworkAdapterInfo> {
        self.devices.iter().find(|device| device.id == id)
    }

    pub fn adapters(&self) -> Vec<WindowsAdapterEntry> {
        self.devices
            .iter()
            .map(NetworkAdapterInfo::windows_entry)
            .collect()
    }

    pub fn apply(&mut self, devices: Vec<NetworkAdapterInfo>) -> Vec<HotplugEvent> {
        let mut devices = devices;
        devices.sort_by_key(|device| device.id);
        devices.dedup_by_key(|device| device.id);
        let records = devices.iter().map(NetworkAdapterInfo::record).collect();
        self.devices = devices;
        self.table.reconcile(records)
    }

    pub fn enumerate(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        let devices = scan_network_adapters()?;
        Ok(self.apply(devices))
    }
}

impl HostDeviceBridge for NetworkBridge {
    fn class(&self) -> DeviceClass {
        DeviceClass::Network
    }

    fn enumerate(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        NetworkBridge::enumerate(self)
    }

    fn records(&self) -> Vec<DeviceRecord> {
        self.table.records()
    }

    fn record(&self, id: StableDeviceId) -> Option<DeviceRecord> {
        self.table.get(id).cloned()
    }

    fn supported_operations(&self) -> &'static [HostOperation] {
        NETWORK_OPERATIONS
    }

    fn open_user_client(&self, id: StableDeviceId) -> Result<Box<dyn HostUserClient>, DeviceError> {
        let device = self.device(id).ok_or(DeviceError::DeviceMissing { id })?;
        Ok(Box::new(QueryOnlyUserClient::new(
            device.id,
            DeviceClass::Network,
        )))
    }
}

#[cfg(all(target_os = "macos", not(test)))]
pub fn scan_network_adapters() -> Result<Vec<NetworkAdapterInfo>, DeviceError> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates the list freed below.
    let rc = unsafe { libc::getifaddrs(&mut list) };
    if rc != 0 {
        return Err(DeviceError::Io {
            operation: "getifaddrs",
            os_code: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    let mut records = Vec::new();
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: cursor is a valid node from getifaddrs.
        let node = unsafe { &*cursor };
        if !node.ifa_name.is_null() {
            // SAFETY: ifa_name is a NUL-terminated C string.
            let name = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) }
                .to_string_lossy()
                .into_owned();
            if !name.is_empty() {
                let mut record = RawInterfaceRecord {
                    name,
                    flags: node.ifa_flags,
                    ..RawInterfaceRecord::default()
                };
                if !node.ifa_data.is_null() {
                    // SAFETY: ifa_data points at the interface's if_data.
                    let data = unsafe { &*(node.ifa_data as *const libc::if_data) };
                    record.if_type = u32::from(data.ifi_type);
                    record.mtu = data.ifi_mtu;
                    record.speed = u64::from(data.ifi_baudrate);
                }
                if !node.ifa_addr.is_null() {
                    collect_address(node, &mut record);
                }
                records.push(record);
            }
        }
        // SAFETY: advance the intrusive list.
        cursor = unsafe { (*cursor).ifa_next };
    }
    // SAFETY: frees the list allocated by getifaddrs.
    unsafe { libc::freeifaddrs(list) };
    Ok(build_adapters(records))
}

#[cfg(all(target_os = "macos", not(test)))]
fn collect_address(node: &libc::ifaddrs, record: &mut RawInterfaceRecord) {
    // SAFETY: ifa_addr is non-null and points at the node's sockaddr.
    let family = unsafe { (*node.ifa_addr).sa_family as i32 };
    match family {
        libc::AF_LINK => {
            // SAFETY: AF_LINK addresses are sockaddr_dl.
            let link = unsafe { &*(node.ifa_addr as *const libc::sockaddr_dl) };
            record.if_index = u32::from(link.sdl_index);
            record.if_type = u32::from(link.sdl_type);
            let name_len = usize::from(link.sdl_nlen);
            let address_len = usize::from(link.sdl_alen);
            if address_len == 6 && name_len + address_len <= link.sdl_data.len() {
                let mut mac = [0_u8; 6];
                for (index, byte) in link.sdl_data[name_len..name_len + address_len]
                    .iter()
                    .enumerate()
                {
                    mac[index] = *byte as u8;
                }
                record.mac = Some(mac);
            }
        }
        libc::AF_INET => {
            // SAFETY: AF_INET addresses are sockaddr_in.
            let address = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in) };
            record.ipv4.push((
                Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)),
                ipv4_prefix(node.ifa_netmask),
            ));
        }
        libc::AF_INET6 => {
            // SAFETY: AF_INET6 addresses are sockaddr_in6.
            let address = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in6) };
            record.ipv6.push(Ipv6Addr::from(address.sin6_addr.s6_addr));
        }
        _ => {}
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn ipv4_prefix(mask: *const libc::sockaddr) -> u8 {
    if mask.is_null() {
        return 0;
    }
    // SAFETY: IPv4 netmasks are sockaddr_in.
    let mask = unsafe { &*(mask as *const libc::sockaddr_in) };
    u32::from_be(mask.sin_addr.s_addr).count_ones() as u8
}

#[cfg(test)]
pub fn scan_network_adapters() -> Result<Vec<NetworkAdapterInfo>, DeviceError> {
    Ok(Vec::new())
}

#[cfg(all(not(target_os = "macos"), not(test)))]
pub fn scan_network_adapters() -> Result<Vec<NetworkAdapterInfo>, DeviceError> {
    Err(DeviceError::Unsupported {
        feature: "network enumeration requires macOS getifaddrs",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(name: &str, mac: Option<[u8; 6]>, flags: u32) -> RawInterfaceRecord {
        RawInterfaceRecord {
            name: name.to_string(),
            if_index: 7,
            if_type: 6,
            mtu: 1500,
            speed: 1_000_000_000,
            flags,
            mac,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        }
    }

    #[test]
    fn network_absent_adapter_and_unsupported_operation_are_exact() {
        let mut bridge = NetworkBridge::new();
        let id = StableDeviceId::from_raw(0xabc);
        assert_eq!(
            bridge.open_user_client(id).map(|_| ()),
            Err(DeviceError::DeviceMissing { id })
        );
        let adapter = NetworkAdapterInfo::from_raw(raw(
            "en0",
            Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
            (libc::IFF_UP | libc::IFF_RUNNING) as u32,
        ));
        let _ = bridge.apply(vec![adapter.clone()]);
        let client = bridge
            .open_user_client(adapter.id)
            .expect("open real adapter fixture");
        assert_eq!(client.device_id(), adapter.id);
        assert_eq!(client.class(), DeviceClass::Network);
        assert_eq!(bridge.class(), DeviceClass::Network);
        assert_eq!(bridge.operation_support(HostOperation::Enumerate), Ok(()));
        assert_eq!(
            bridge.operation_support(HostOperation::LinkControl),
            Err(DeviceError::Unsupported {
                feature: "network link control"
            })
        );
        assert_eq!(
            bridge.operation_support(HostOperation::DataTransfer),
            Err(DeviceError::Unsupported {
                feature: "device data transfer"
            })
        );
    }

    #[test]
    fn network_link_state_and_duplicate_records_are_exact() {
        let mut first = raw(
            "en0",
            Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
            libc::IFF_UP as u32,
        );
        first.ipv4.push((Ipv4Addr::new(10, 0, 2, 15), 24));
        let mut second = raw("en0", None, (libc::IFF_UP | libc::IFF_RUNNING) as u32);
        second.ipv4.push((Ipv4Addr::new(10, 0, 2, 15), 24));
        second.ipv6.push("fd00::2".parse().expect("static IPv6"));
        let adapters = build_adapters(vec![first, second, raw("en0", None, 0)]);
        assert_eq!(adapters.len(), 1);
        let adapter = &adapters[0];
        assert_eq!(adapter.bsd_name, "en0");
        assert_eq!(adapter.mac, Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
        assert_eq!(adapter.ipv4, vec![(Ipv4Addr::new(10, 0, 2, 15), 24)]);
        assert_eq!(adapter.ipv6.len(), 1);
        assert_eq!(adapter.oper_status, 1);
        assert_eq!(adapter.media_connect_state, 1);
        assert_eq!(adapter.if_index, 7);
        assert_eq!(adapter.if_type, 6);
        assert_eq!(adapter.mtu, 1500);
        assert_eq!(adapter.speed, 1_000_000_000);
        assert_eq!(
            adapter.record().serial_number.as_deref(),
            Some("00:1a:2b:3c:4d:5e")
        );

        let empty = RawInterfaceRecord {
            name: "en1".to_string(),
            ..RawInterfaceRecord::default()
        };
        let filled = raw(
            "en1",
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            libc::IFF_UP as u32,
        );
        let merged = build_adapters(vec![empty, filled]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].if_index, 7);
        assert_eq!(merged[0].if_type, 6);
        assert_eq!(merged[0].mtu, 1500);
        assert_eq!(merged[0].speed, 1_000_000_000);
        assert_eq!(merged[0].mac, Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));

        let down = build_adapters(vec![raw("en9", None, 0)]);
        assert_eq!(down[0].oper_status, 2);
        assert_eq!(down[0].media_connect_state, 2);
        assert_eq!(build_adapters(Vec::new()), Vec::new());
        assert_eq!(build_adapters(vec![raw("", None, 0)]), Vec::new());
    }

    #[test]
    fn network_hotplug_duplicate_apply_is_idempotent_and_ids_are_stable() {
        let mut bridge = NetworkBridge::new();
        assert_eq!(bridge.refresh(), Ok(Vec::new()));
        let adapter = NetworkAdapterInfo::from_raw(raw(
            "en0",
            Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
            (libc::IFF_UP | libc::IFF_RUNNING) as u32,
        ));
        assert_eq!(
            bridge.apply(vec![adapter.clone(), adapter.clone()]),
            vec![HotplugEvent::Arrived(adapter.record())]
        );
        assert_eq!(bridge.devices().len(), 1);
        assert_eq!(bridge.table().len(), 1);
        assert_eq!(bridge.device(adapter.id), Some(&adapter));
        assert_eq!(bridge.adapters(), vec![adapter.windows_entry()]);
        assert_eq!(
            bridge.apply(vec![adapter.clone()]),
            Vec::<HotplugEvent>::new()
        );
        assert_eq!(
            bridge.apply(Vec::new()),
            vec![HotplugEvent::Removed {
                record: adapter.record()
            }]
        );
        assert_eq!(bridge.records(), Vec::new());
        assert_eq!(bridge.record(adapter.id), None);
    }
}
