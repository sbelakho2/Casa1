//! Loopback/virtual host transport for CasaK device-tree PDOs.
//!
//! The transport is a real in-process device model: writes are queued and
//! read back byte-for-byte, IOCTL codes have registered responses, and an
//! unplug (immediate or armed for the next in-flight read) fails exactly like
//! a removed USB device.  It is the backing implementation that keeps a PnP
//! device object from being a no-op when the island dispatches an IRP.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::device_proxy::{
    CancelToken, CapabilityDescriptor, DeviceChannel, DeviceFamily, DeviceRecord, DeviceTransport,
    HotplugEvent, ProxyError, ProxyOperation, StableDeviceId, resolve_deadline, validate_transfer,
};

/// A loopback device description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackDeviceRecord {
    /// Stable device id.
    pub id: StableDeviceId,
    /// Human-readable name.
    pub name: String,
    /// DriverKit family.
    pub family: DeviceFamily,
    /// Largest number of buffered bytes the device accepts.
    pub capacity: usize,
    /// Whether the device is currently unplugged.
    pub unplugged: bool,
}

struct LoopbackDevice {
    id: StableDeviceId,
    name: String,
    family: DeviceFamily,
    capacity: usize,
    read_queue: VecDeque<u8>,
    written: Vec<u8>,
    ioctls: BTreeMap<u32, Vec<u8>>,
    unplugged: bool,
    unplug_on_next_read: bool,
    read_stall: Option<Duration>,
}

#[derive(Default)]
struct LoopbackState {
    devices: BTreeMap<StableDeviceId, LoopbackDevice>,
    device_keys: BTreeMap<u64, StableDeviceId>,
    last_live: BTreeSet<StableDeviceId>,
    next_id: u64,
}

/// A shareable loopback bus.
///
/// Clones share the device table, so a proxy can own one transport clone while
/// the driver island adds/removes/unplugs devices through another.
#[derive(Clone, Default)]
pub struct LoopbackBus {
    state: Arc<Mutex<LoopbackState>>,
}

impl LoopbackBus {
    /// An empty loopback bus.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, LoopbackState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Adds a device with a deterministic id derived from `name`.
    pub fn add_device(&self, name: &str, family: DeviceFamily) -> StableDeviceId {
        let mut state = self.lock();
        state.next_id += 1;
        let id = StableDeviceId::derive(
            family.device_class(),
            &[name, &format!("loopback-{}", state.next_id)],
        );
        state.devices.insert(
            id,
            LoopbackDevice {
                id,
                name: name.to_string(),
                family,
                capacity: crate::device_proxy::MAX_TRANSFER_BYTES,
                read_queue: VecDeque::new(),
                written: Vec::new(),
                ioctls: BTreeMap::new(),
                unplugged: false,
                unplug_on_next_read: false,
                read_stall: None,
            },
        );
        id
    }

    /// Adds a device with an explicit stable id (used by the PnP device tree).
    pub fn add_named_device(&self, id: StableDeviceId, name: &str, family: DeviceFamily) -> bool {
        let mut state = self.lock();
        if state.devices.contains_key(&id) {
            return false;
        }
        state.devices.insert(
            id,
            LoopbackDevice {
                id,
                name: name.to_string(),
                family,
                capacity: crate::device_proxy::MAX_TRANSFER_BYTES,
                read_queue: VecDeque::new(),
                written: Vec::new(),
                ioctls: BTreeMap::new(),
                unplugged: false,
                unplug_on_next_read: false,
                read_stall: None,
            },
        );
        true
    }

    /// Binds a CasaK device-object key to a loopback device id.
    pub fn bind_device_key(&self, id: StableDeviceId, device: u64) {
        self.lock().device_keys.insert(device, id);
    }

    /// The loopback device id bound to a CasaK device-object key.
    pub fn device_id_for(&self, device: u64) -> Option<StableDeviceId> {
        self.lock().device_keys.get(&device).copied()
    }

    /// Registers the response for one IOCTL code.
    pub fn register_ioctl(&self, id: StableDeviceId, code: u32, response: Vec<u8>) -> bool {
        let mut state = self.lock();
        match state.devices.get_mut(&id) {
            Some(device) => {
                device.ioctls.insert(code, response);
                true
            }
            None => false,
        }
    }

    /// Changes the device write capacity.
    pub fn set_capacity(&self, id: StableDeviceId, capacity: usize) -> bool {
        let mut state = self.lock();
        match state.devices.get_mut(&id) {
            Some(device) => {
                device.capacity = capacity;
                true
            }
            None => false,
        }
    }

    /// Removes a device from the bus.
    pub fn remove_device(&self, id: StableDeviceId) -> bool {
        let mut state = self.lock();
        state.device_keys.retain(|_, value| *value != id);
        state.devices.remove(&id).is_some()
    }

    /// Unplugs a device.  Enumerations stop reporting it and reads fail with
    /// [`ProxyError::Unplugged`].
    pub fn unplug(&self, id: StableDeviceId) -> bool {
        let mut state = self.lock();
        match state.devices.get_mut(&id) {
            Some(device) => {
                device.unplugged = true;
                true
            }
            None => false,
        }
    }

    /// Arms an unplug that becomes visible to the next read while it is in
    /// flight.
    pub fn unplug_on_next_read(&self, id: StableDeviceId) -> bool {
        let mut state = self.lock();
        match state.devices.get_mut(&id) {
            Some(device) => {
                device.unplug_on_next_read = true;
                true
            }
            None => false,
        }
    }

    /// Sets a per-read stall used to exercise timeout and cancellation.
    pub fn set_read_stall(&self, id: StableDeviceId, stall: Option<Duration>) -> bool {
        let mut state = self.lock();
        match state.devices.get_mut(&id) {
            Some(device) => {
                device.read_stall = stall;
                true
            }
            None => false,
        }
    }

    /// Records for every attached device.
    pub fn devices(&self) -> Vec<LoopbackDeviceRecord> {
        self.lock()
            .devices
            .values()
            .map(|device| LoopbackDeviceRecord {
                id: device.id,
                name: device.name.clone(),
                family: device.family,
                capacity: device.capacity,
                unplugged: device.unplugged,
            })
            .collect()
    }

    /// Bytes written to a device (transport evidence).
    pub fn written(&self, id: StableDeviceId) -> Option<Vec<u8>> {
        self.lock()
            .devices
            .get(&id)
            .map(|device| device.written.clone())
    }
}

fn record(device: &LoopbackDevice) -> DeviceRecord {
    DeviceRecord {
        id: device.id,
        class: device.family.device_class(),
        vendor_id: None,
        product_id: None,
        manufacturer: Some("CasaK".to_string()),
        product: Some(device.name.clone()),
        serial_number: None,
        path: Some(format!("loopback:{}", device.name)),
        registry_entry_id: device.id.as_u64(),
    }
}

fn capability(family: DeviceFamily) -> CapabilityDescriptor {
    CapabilityDescriptor::new(
        family,
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
    )
}

/// The loopback transport.
pub struct LoopbackTransport {
    bus: LoopbackBus,
}

impl LoopbackTransport {
    /// A transport over `bus`.
    pub fn new(bus: LoopbackBus) -> Self {
        Self { bus }
    }
}

impl DeviceTransport for LoopbackTransport {
    fn enumerate(&mut self) -> Result<Vec<DeviceRecord>, ProxyError> {
        let state = self.bus.lock();
        Ok(state
            .devices
            .values()
            .filter(|device| !device.unplugged)
            .map(record)
            .collect())
    }

    fn hotplug(&mut self) -> Result<Vec<HotplugEvent>, ProxyError> {
        let mut state = self.bus.lock();
        let live: BTreeSet<StableDeviceId> = state
            .devices
            .values()
            .filter(|device| !device.unplugged)
            .map(|device| device.id)
            .collect();
        let mut events = Vec::new();
        for id in live.difference(&state.last_live) {
            if let Some(device) = state.devices.get(id) {
                events.push(HotplugEvent::Arrived(record(device)));
            }
        }
        for id in state.last_live.difference(&live) {
            if let Some(device) = state.devices.get(id) {
                events.push(HotplugEvent::Removed {
                    record: record(device),
                });
            }
        }
        state.last_live = live;
        Ok(events)
    }

    fn descriptor(&self, id: StableDeviceId) -> Option<CapabilityDescriptor> {
        let state = self.bus.lock();
        state
            .devices
            .get(&id)
            .map(|device| capability(device.family))
    }

    fn open(
        &mut self,
        id: StableDeviceId,
        _deadline: Option<Instant>,
    ) -> Result<Box<dyn DeviceChannel>, ProxyError> {
        let state = self.bus.lock();
        let device = state
            .devices
            .get(&id)
            .ok_or(ProxyError::DeviceMissing { id })?;
        if device.unplugged {
            return Err(ProxyError::Unplugged { id });
        }
        Ok(Box::new(LoopbackChannel {
            bus: self.bus.clone(),
            id,
            descriptor: capability(device.family),
        }))
    }
}

struct LoopbackChannel {
    bus: LoopbackBus,
    id: StableDeviceId,
    descriptor: CapabilityDescriptor,
}

fn timeout_ms(deadline: Instant) -> u64 {
    deadline
        .checked_duration_since(Instant::now())
        .map(|remaining| remaining.as_millis() as u64)
        .unwrap_or(0)
}

impl DeviceChannel for LoopbackChannel {
    fn descriptor(&self) -> CapabilityDescriptor {
        self.descriptor.clone()
    }

    fn read(
        &mut self,
        buffer: &mut [u8],
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<usize, ProxyError> {
        validate_transfer(buffer.len())?;
        let deadline = resolve_deadline(deadline);
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }
        if deadline <= Instant::now() {
            return Err(ProxyError::Timeout { timeout_ms: 0 });
        }
        let stall = {
            let mut state = self.bus.lock();
            let device = state
                .devices
                .get_mut(&self.id)
                .ok_or(ProxyError::DeviceMissing { id: self.id })?;
            if device.unplugged {
                return Err(ProxyError::Unplugged { id: self.id });
            }
            if device.unplug_on_next_read {
                device.unplug_on_next_read = false;
                device.unplugged = true;
                return Err(ProxyError::Unplugged { id: self.id });
            }
            device.read_stall
        };
        if let Some(stall) = stall {
            match deadline.checked_duration_since(Instant::now()) {
                Some(remaining) if remaining > stall => std::thread::sleep(stall),
                _ => {
                    return Err(ProxyError::Timeout {
                        timeout_ms: timeout_ms(deadline),
                    });
                }
            }
            if cancel.is_cancelled() {
                return Err(ProxyError::Cancelled);
            }
        }
        let mut state = self.bus.lock();
        let device = state
            .devices
            .get_mut(&self.id)
            .ok_or(ProxyError::DeviceMissing { id: self.id })?;
        if device.unplugged {
            return Err(ProxyError::Unplugged { id: self.id });
        }
        if device.read_queue.is_empty() {
            return Err(ProxyError::Timeout {
                timeout_ms: timeout_ms(deadline),
            });
        }
        let count = buffer.len().min(device.read_queue.len());
        for slot in buffer.iter_mut().take(count) {
            *slot = device
                .read_queue
                .pop_front()
                .expect("read queue length was checked");
        }
        Ok(count)
    }

    fn write(
        &mut self,
        data: &[u8],
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<usize, ProxyError> {
        validate_transfer(data.len())?;
        let deadline = resolve_deadline(deadline);
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }
        if deadline <= Instant::now() {
            return Err(ProxyError::Timeout {
                timeout_ms: timeout_ms(deadline),
            });
        }
        let mut state = self.bus.lock();
        let device = state
            .devices
            .get_mut(&self.id)
            .ok_or(ProxyError::DeviceMissing { id: self.id })?;
        if device.unplugged || device.unplug_on_next_read {
            device.unplugged = true;
            return Err(ProxyError::Unplugged { id: self.id });
        }
        if device.read_queue.len() + data.len() > device.capacity {
            return Err(ProxyError::InvalidParameter {
                field: "loopback device capacity",
            });
        }
        device.read_queue.extend(data.iter().copied());
        device.written.extend_from_slice(data);
        Ok(data.len())
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
        let state = self.bus.lock();
        let device = state
            .devices
            .get(&self.id)
            .ok_or(ProxyError::DeviceMissing { id: self.id })?;
        if device.unplugged {
            return Err(ProxyError::Unplugged { id: self.id });
        }
        let response = device
            .ioctls
            .get(&code)
            .ok_or(ProxyError::UnsupportedIoctl { code })?;
        let _ = input;
        if output_len < response.len() {
            return Err(ProxyError::InvalidParameter {
                field: "ioctl output length",
            });
        }
        Ok(response.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_write_read_is_byte_exact_and_hotplug_is_delta_only() {
        let bus = LoopbackBus::new();
        let id = bus.add_device("CasaLoop", DeviceFamily::Virtual);
        let mut transport = LoopbackTransport::new(bus.clone());
        assert!(matches!(
            transport.hotplug().expect("first hotplug").as_slice(),
            [HotplugEvent::Arrived(_)]
        ));
        assert!(transport.hotplug().expect("steady hotplug").is_empty());
        let channel = transport.open(id, None).expect("open");
        let mut channel = channel;
        let payload = [0x00, 0x11, 0x22, 0xFF];
        assert_eq!(
            channel
                .write(&payload, None, &CancelToken::new())
                .expect("write"),
            payload.len()
        );
        let mut buffer = [0_u8; 4];
        assert_eq!(
            channel
                .read(&mut buffer, None, &CancelToken::new())
                .expect("read"),
            payload.len()
        );
        assert_eq!(buffer, payload);
    }

    #[test]
    fn loopback_capacity_overflow_and_missing_ioctl_are_exact() {
        let bus = LoopbackBus::new();
        let id = bus.add_device("CasaSmall", DeviceFamily::Virtual);
        assert!(bus.set_capacity(id, 2));
        let mut transport = LoopbackTransport::new(bus);
        let mut channel = transport.open(id, None).expect("open");
        assert_eq!(
            channel.write(&[1, 2, 3], None, &CancelToken::new()),
            Err(ProxyError::InvalidParameter {
                field: "loopback device capacity",
            })
        );
        assert_eq!(
            channel.ioctl(0xDEAD, &[], 4, None, &CancelToken::new()),
            Err(ProxyError::UnsupportedIoctl { code: 0xDEAD })
        );
    }

    #[test]
    fn loopback_unplug_and_stall_fail_with_documented_statuses() {
        let bus = LoopbackBus::new();
        let id = bus.add_device("CasaUnplug", DeviceFamily::Virtual);
        let mut transport = LoopbackTransport::new(bus.clone());
        let mut channel = transport.open(id, None).expect("open");
        assert!(bus.unplug_on_next_read(id));
        assert_eq!(
            channel.read(&mut [0_u8; 1], None, &CancelToken::new()),
            Err(ProxyError::Unplugged { id })
        );
        let second = bus.add_device("CasaStall", DeviceFamily::Virtual);
        assert!(bus.set_read_stall(second, Some(Duration::from_millis(50))));
        let mut second_channel = transport.open(second, None).expect("open second");
        assert_eq!(
            second_channel.read(&mut [0_u8; 1], Some(Instant::now()), &CancelToken::new()),
            Err(ProxyError::Timeout { timeout_ms: 0 })
        );
    }
}
