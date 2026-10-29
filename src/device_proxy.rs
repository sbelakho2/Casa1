//! Windows-device semantics over real host-device transports.
//!
//! A [`HostDeviceProxy`] is the single abstraction the driver island uses for
//! host-backed device objects.  It maps the Windows device model
//! (`IRP_MJ_CREATE`/`READ`/`WRITE`/`DEVICE_CONTROL`, hotplug and descriptors)
//! onto a [`DeviceTransport`], and it keeps the exact NTSTATUS for every
//! failure path.  Two transports ship with this module:
//!
//! - [`crate::devicekit::iokit::IokitTransport`] — the in-process IOKit
//!   user-client transport over the HID/USB/serial/PCI/network/audio bridges.
//!   Enumeration needs no entitlement.  Operations that genuinely require a
//!   signed DriverKit dext report [`ProxyError::EntitlementRequired`]
//!   (`STATUS_PRIVILEGE_NOT_HELD`) instead of fabricating success.
//! - [`crate::devicekit::loopback::LoopbackTransport`] — the virtual transport
//!   backing CasaK device-tree PDOs.  A Windows driver's IRP reaches a real,
//!   byte-exact in-process implementation rather than a no-op.
//!
//! Nothing here silently succeeds: an invalid handle, a missing device, an
//! unplug, a cancelled or timed-out transfer, a mismatched IOCTL code and an
//! entitlement-gated operation all return their documented NTSTATUS.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::casak::io::STATUS_INVALID_BUFFER_SIZE;
use crate::casak::status::{
    STATUS_ACCESS_DENIED, STATUS_CANCELLED, STATUS_DEVICE_BUSY, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_PRIVILEGE_NOT_HELD, STATUS_SUCCESS, STATUS_TIMEOUT,
};
pub use crate::real_hid::{DeviceClass, DeviceRecord, HotplugEvent, StableDeviceId};

use crate::devicekit::loopback::{LoopbackBus, LoopbackTransport};

/// The device is no longer attached (`STATUS_DEVICE_NOT_CONNECTED`).
pub const STATUS_DEVICE_NOT_CONNECTED: i32 = 0xC000_009Fu32 as i32;
/// An I/O request failed inside the host transport (`STATUS_IO_DEVICE_ERROR`).
pub const STATUS_IO_DEVICE_ERROR: i32 = 0xC000_0185u32 as i32;

/// Largest single transfer the proxy accepts.  Anything larger is rejected
/// with `STATUS_INVALID_BUFFER_SIZE` before a transport is touched.
pub const MAX_TRANSFER_BYTES: usize = 1024 * 1024;
/// Deadline applied when a caller does not supply one.
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(2);
/// Deadline used by driver-island IRP dispatch.
pub const IRP_TIMEOUT: Duration = Duration::from_millis(250);

/// The Windows-facing operation a proxy call represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProxyOperation {
    Enumerate,
    Open,
    Close,
    Read,
    Write,
    Ioctl,
    Hotplug,
    Descriptor,
}

impl ProxyOperation {
    /// Stable name used by error messages and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enumerate => "enumerate",
            Self::Open => "open",
            Self::Close => "close",
            Self::Read => "read",
            Self::Write => "write",
            Self::Ioctl => "ioctl",
            Self::Hotplug => "hotplug",
            Self::Descriptor => "descriptor",
        }
    }
}

/// DeviceKit-shaped family of a host device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceFamily {
    Usb,
    Hid,
    Serial,
    Network,
    Audio,
    Pci,
    Virtual,
}

impl DeviceFamily {
    /// Stable family name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Hid => "hid",
            Self::Serial => "serial",
            Self::Network => "network",
            Self::Audio => "audio",
            Self::Pci => "pci",
            Self::Virtual => "virtual",
        }
    }

    /// The Windows-facing class used for stable host device ids.
    pub const fn device_class(self) -> DeviceClass {
        match self {
            Self::Usb => DeviceClass::Usb,
            Self::Hid => DeviceClass::Hid,
            Self::Serial => DeviceClass::Serial,
            Self::Network => DeviceClass::Network,
            Self::Audio => DeviceClass::Audio,
            Self::Pci => DeviceClass::Pci,
            Self::Virtual => DeviceClass::Hid,
        }
    }

    /// Maps an NT `FILE_DEVICE_*` type to the host family a PDO is backed by.
    pub const fn from_nt_device_type(device_type: u32) -> Self {
        match device_type {
            0x0B | 0x0F | 0x1A | 0x33 => Self::Hid,
            0x1B => Self::Serial,
            0x12 | 0x13 | 0x17 | 0x28 => Self::Network,
            0x1D | 0x25 | 0x26 => Self::Audio,
            0x34 => Self::Usb,
            0x03 | 0x2A | 0x32 => Self::Pci,
            _ => Self::Virtual,
        }
    }
}

/// DriverKit-shaped capability description of one host device.
///
/// `entitlement_required` is the family-level fact; `dext_required` lists the
/// operations that additionally need a signed DriverKit extension.  The
/// two-level shape keeps enumeration available on a machine where every
/// data-path operation is entitlement-gated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDescriptor {
    /// DriverKit family of the device.
    pub family: DeviceFamily,
    /// Whether this family needs a DriverKit entitlement at all.
    pub entitlement_required: bool,
    /// Operations this transport really implements without an entitlement.
    pub supported: Vec<ProxyOperation>,
    /// Operations that need a signed dext (`STATUS_PRIVILEGE_NOT_HELD`).
    pub dext_required: Vec<ProxyOperation>,
}

impl CapabilityDescriptor {
    /// Builds a descriptor from its parts.
    pub fn new(
        family: DeviceFamily,
        entitlement_required: bool,
        supported: Vec<ProxyOperation>,
        dext_required: Vec<ProxyOperation>,
    ) -> Self {
        Self {
            family,
            entitlement_required,
            supported,
            dext_required,
        }
    }

    /// Verifies one operation, returning the exact failure when the transport
    /// cannot provide it.
    pub fn require(&self, operation: ProxyOperation) -> Result<(), ProxyError> {
        if self.entitlement_required && self.dext_required.contains(&operation) {
            return Err(ProxyError::EntitlementRequired {
                family: self.family,
                operation,
            });
        }
        if self.supported.contains(&operation) {
            Ok(())
        } else {
            Err(ProxyError::Unsupported {
                family: self.family,
                operation,
            })
        }
    }
}

/// Cooperative cancellation shared with an in-flight transport operation.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A fresh, uncancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation; a transport checks this before and after any
    /// blocking step.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// An exact proxy failure with a stable NTSTATUS and Win32 mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// The proxy handle was never minted or was already closed.
    InvalidHandle,
    /// The host device disappeared from the bus.
    DeviceMissing { id: StableDeviceId },
    /// The device was unplugged after the channel was opened.
    Unplugged { id: StableDeviceId },
    /// The operation needs a signed DriverKit extension.
    EntitlementRequired {
        family: DeviceFamily,
        operation: ProxyOperation,
    },
    /// The transport does not implement the operation at all.
    Unsupported {
        family: DeviceFamily,
        operation: ProxyOperation,
    },
    /// A zero-length transfer has no device meaning.
    ZeroLength,
    /// The transfer exceeds [`MAX_TRANSFER_BYTES`].
    Oversized { requested: usize, maximum: usize },
    /// An invalid argument on a specific field.
    InvalidParameter { field: &'static str },
    /// The wait deadline elapsed.
    Timeout { timeout_ms: u64 },
    /// The request was cancelled.
    Cancelled,
    /// The IOCTL code is not implemented by the backing device.
    UnsupportedIoctl { code: u32 },
    /// The host denied access.
    AccessDenied,
    /// The transport is busy with an exclusive channel.
    Busy,
    /// The backing device is not open.
    NotOpen { id: StableDeviceId },
    /// A host call failed.
    Io {
        operation: &'static str,
        os_code: i32,
    },
}

impl ProxyError {
    /// Exact NTSTATUS returned through the IRP path.
    pub const fn ntstatus(&self) -> i32 {
        match self {
            Self::InvalidHandle | Self::NotOpen { .. } => STATUS_INVALID_HANDLE,
            Self::DeviceMissing { .. } => STATUS_OBJECT_NAME_NOT_FOUND,
            Self::Unplugged { .. } => STATUS_DEVICE_NOT_CONNECTED,
            Self::EntitlementRequired { .. } => STATUS_PRIVILEGE_NOT_HELD,
            Self::Unsupported { .. } => STATUS_NOT_SUPPORTED,
            Self::ZeroLength | Self::InvalidParameter { .. } => STATUS_INVALID_PARAMETER,
            Self::Oversized { .. } => STATUS_INVALID_BUFFER_SIZE,
            Self::Timeout { .. } => STATUS_TIMEOUT,
            Self::Cancelled => STATUS_CANCELLED,
            Self::UnsupportedIoctl { .. } => STATUS_INVALID_DEVICE_REQUEST,
            Self::AccessDenied => STATUS_ACCESS_DENIED,
            Self::Busy => STATUS_DEVICE_BUSY,
            Self::Io { .. } => STATUS_IO_DEVICE_ERROR,
        }
    }

    /// Exact Win32 `GetLastError`/HRESULT low word for the failure.
    pub const fn windows_error(&self) -> u32 {
        match self {
            Self::InvalidHandle | Self::NotOpen { .. } => 6,
            Self::DeviceMissing { .. } => 2,
            Self::Unplugged { .. } => 1167,
            Self::EntitlementRequired { .. } => 1314,
            Self::Unsupported { .. } => 50,
            Self::ZeroLength | Self::InvalidParameter { .. } => 87,
            Self::Oversized { .. } => 122,
            Self::Timeout { .. } => 1460,
            Self::Cancelled => 995,
            Self::UnsupportedIoctl { .. } => 1,
            Self::AccessDenied => 5,
            Self::Busy => 32,
            Self::Io { .. } => 1117,
        }
    }

    /// Maps a bridge-level [`crate::real_hid::DeviceError`] onto the proxy.
    pub fn from_device_error(error: crate::real_hid::DeviceError) -> Self {
        use crate::real_hid::DeviceError;
        match error {
            DeviceError::PermissionDenied { .. } => Self::AccessDenied,
            DeviceError::DeviceMissing { id } => Self::DeviceMissing { id },
            DeviceError::Unplugged { id } => Self::Unplugged { id },
            DeviceError::Unsupported { .. }
            | DeviceError::UnsupportedTransferFlag { .. }
            | DeviceError::UnsupportedTransferType { .. } => Self::Unsupported {
                family: DeviceFamily::Virtual,
                operation: ProxyOperation::Ioctl,
            },
            DeviceError::Busy { .. } | DeviceError::AlreadyOpen { .. } => Self::Busy,
            DeviceError::NotOpen { id } => Self::NotOpen { id },
            DeviceError::AlreadyClosed { .. } => Self::Busy,
            DeviceError::Timeout { timeout_ms } => Self::Timeout { timeout_ms },
            DeviceError::Io { operation, os_code } => Self::Io {
                operation: leak_operation(operation),
                os_code,
            },
            DeviceError::InvalidArgument { field, .. } => Self::InvalidParameter { field },
            DeviceError::InvalidReportLength { .. }
            | DeviceError::VendorMismatch { .. }
            | DeviceError::EndpointMissing { .. }
            | DeviceError::MalformedDescriptor { .. } => Self::InvalidParameter {
                field: "device request",
            },
        }
    }
}

fn leak_operation(operation: &str) -> &'static str {
    match operation {
        "read" => "read",
        "write" => "write",
        "poll" => "poll",
        "close" => "close",
        "open" => "open",
        _ => "device io",
    }
}

/// A transport-level open channel.
///
/// Transports implement the Windows-facing byte and IOCTL semantics; the
/// proxy adds handle validation, transfer bounds, entitlement policy and
/// status mapping.
pub trait DeviceChannel: Send {
    /// Capability descriptor of the open device.
    fn descriptor(&self) -> CapabilityDescriptor;

    /// Reads into `buffer`, honouring `deadline` and `cancel`.
    fn read(
        &mut self,
        buffer: &mut [u8],
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<usize, ProxyError>;

    /// Writes `data`, honouring `deadline` and `cancel`.
    fn write(
        &mut self,
        data: &[u8],
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<usize, ProxyError>;

    /// Invokes `code` with `input`, returning at most `output_len` bytes.
    fn ioctl(
        &mut self,
        code: u32,
        input: &[u8],
        output_len: usize,
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<Vec<u8>, ProxyError>;

    /// Closes the channel.  The default is a no-op for channels whose device
    /// lifetime is the channel lifetime.
    fn close(&mut self) -> Result<(), ProxyError> {
        Ok(())
    }
}

/// A host-device transport.
///
/// Enumeration and hotplug must work without any entitlement.  `open` returns
/// the exact failure when the device is gone or the host denies access.
pub trait DeviceTransport: Send {
    /// Enumerates every device the transport can currently see.
    fn enumerate(&mut self) -> Result<Vec<DeviceRecord>, ProxyError>;

    /// Returns hotplug deltas since the previous call.
    fn hotplug(&mut self) -> Result<Vec<HotplugEvent>, ProxyError>;

    /// Capability descriptor for one enumerated device.
    fn descriptor(&self, id: StableDeviceId) -> Option<CapabilityDescriptor>;

    /// Opens a channel for `id`.
    fn open(
        &mut self,
        id: StableDeviceId,
        deadline: Option<Instant>,
    ) -> Result<Box<dyn DeviceChannel>, ProxyError>;
}

/// A real, opaque host device handle minted by [`HostDeviceProxy::open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProxyHandle(u64);

impl ProxyHandle {
    /// Raw handle value (never zero for a live handle).
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Reconstructs a handle value used by a caller that persisted it.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
}

struct ChannelEntry {
    device: StableDeviceId,
    channel: Box<dyn DeviceChannel>,
}

/// The Windows-device proxy over one or more transports.
pub struct HostDeviceProxy {
    transports: Vec<Box<dyn DeviceTransport>>,
    channels: BTreeMap<ProxyHandle, ChannelEntry>,
    next_handle: u64,
}

impl HostDeviceProxy {
    /// An empty proxy with no transports.
    pub fn new() -> Self {
        Self {
            transports: Vec::new(),
            channels: BTreeMap::new(),
            next_handle: 1,
        }
    }

    /// A proxy over one transport.
    pub fn with_transport(transport: Box<dyn DeviceTransport>) -> Self {
        let mut proxy = Self::new();
        proxy.transports.push(transport);
        proxy
    }

    /// Adds a transport.  Enumeration and hotplug merge every transport.
    pub fn register_transport(&mut self, transport: Box<dyn DeviceTransport>) {
        self.transports.push(transport);
    }

    /// Enumerates the real host devices across every transport.
    pub fn enumerate(&mut self) -> Result<Vec<DeviceRecord>, ProxyError> {
        let mut records = Vec::new();
        for transport in &mut self.transports {
            records.extend(transport.enumerate()?);
        }
        records.sort_by(|left, right| {
            left.class
                .cmp(&right.class)
                .then_with(|| left.id.cmp(&right.id))
        });
        records.dedup_by_key(|record| record.id);
        Ok(records)
    }

    /// Hotplug deltas across every transport.
    pub fn hotplug(&mut self) -> Result<Vec<HotplugEvent>, ProxyError> {
        let mut events = Vec::new();
        for transport in &mut self.transports {
            events.extend(transport.hotplug()?);
        }
        events.sort_by_key(|event| event.device().id);
        events.dedup_by(|left, right| left.device().id == right.device().id);
        Ok(events)
    }

    /// Capability descriptor for an enumerated device.
    pub fn descriptor(&self, id: StableDeviceId) -> Option<CapabilityDescriptor> {
        self.transports
            .iter()
            .find_map(|transport| transport.descriptor(id))
    }

    /// Opens a real host device and mints a proxy handle.
    pub fn open(
        &mut self,
        id: StableDeviceId,
        deadline: Option<Instant>,
    ) -> Result<ProxyHandle, ProxyError> {
        let descriptor = self
            .descriptor(id)
            .ok_or(ProxyError::DeviceMissing { id })?;
        descriptor.require(ProxyOperation::Open)?;
        let transport = self
            .transports
            .iter_mut()
            .find(|transport| transport.descriptor(id).is_some())
            .ok_or(ProxyError::DeviceMissing { id })?;
        let channel = transport.open(id, deadline)?;
        let handle = ProxyHandle(self.next_handle);
        self.next_handle += 1;
        self.channels.insert(
            handle,
            ChannelEntry {
                device: id,
                channel,
            },
        );
        Ok(handle)
    }

    /// Closes a proxy handle.  A second close is `STATUS_INVALID_HANDLE`.
    pub fn close(&mut self, handle: ProxyHandle) -> Result<(), ProxyError> {
        let mut entry = self
            .channels
            .remove(&handle)
            .ok_or(ProxyError::InvalidHandle)?;
        entry.channel.close()
    }

    /// Number of live channels (test and diagnostics surface).
    pub fn open_channel_count(&self) -> usize {
        self.channels.len()
    }

    /// True when `handle` is live.
    pub fn is_open(&self, handle: ProxyHandle) -> bool {
        self.channels.contains_key(&handle)
    }

    /// Device behind a live handle.
    pub fn device(&self, handle: ProxyHandle) -> Result<StableDeviceId, ProxyError> {
        self.channels
            .get(&handle)
            .map(|entry| entry.device)
            .ok_or(ProxyError::InvalidHandle)
    }

    /// Capability descriptor behind a live handle.
    pub fn descriptor_for(&self, handle: ProxyHandle) -> Result<CapabilityDescriptor, ProxyError> {
        self.channels
            .get(&handle)
            .map(|entry| entry.channel.descriptor())
            .ok_or(ProxyError::InvalidHandle)
    }

    /// Reads from a live handle.
    pub fn read(
        &mut self,
        handle: ProxyHandle,
        buffer: &mut [u8],
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<usize, ProxyError> {
        validate_transfer(buffer.len())?;
        let entry = self
            .channels
            .get_mut(&handle)
            .ok_or(ProxyError::InvalidHandle)?;
        entry.channel.descriptor().require(ProxyOperation::Read)?;
        entry.channel.read(buffer, deadline, cancel)
    }

    /// Writes to a live handle.
    pub fn write(
        &mut self,
        handle: ProxyHandle,
        data: &[u8],
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<usize, ProxyError> {
        validate_transfer(data.len())?;
        let entry = self
            .channels
            .get_mut(&handle)
            .ok_or(ProxyError::InvalidHandle)?;
        entry.channel.descriptor().require(ProxyOperation::Write)?;
        entry.channel.write(data, deadline, cancel)
    }

    /// Issues a Windows-device IOCTL to a live handle.
    pub fn ioctl(
        &mut self,
        handle: ProxyHandle,
        code: u32,
        input: &[u8],
        output_len: usize,
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> Result<Vec<u8>, ProxyError> {
        if output_len > MAX_TRANSFER_BYTES {
            return Err(ProxyError::Oversized {
                requested: output_len,
                maximum: MAX_TRANSFER_BYTES,
            });
        }
        if input.len() > MAX_TRANSFER_BYTES {
            return Err(ProxyError::Oversized {
                requested: input.len(),
                maximum: MAX_TRANSFER_BYTES,
            });
        }
        let entry = self
            .channels
            .get_mut(&handle)
            .ok_or(ProxyError::InvalidHandle)?;
        entry.channel.descriptor().require(ProxyOperation::Ioctl)?;
        let output = entry
            .channel
            .ioctl(code, input, output_len, deadline, cancel)?;
        if output.len() > output_len {
            return Err(ProxyError::InvalidParameter {
                field: "ioctl output length",
            });
        }
        Ok(output)
    }
}

impl Default for HostDeviceProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Rejects a transfer that no device can complete.
pub fn validate_transfer(len: usize) -> Result<(), ProxyError> {
    if len == 0 {
        return Err(ProxyError::ZeroLength);
    }
    if len > MAX_TRANSFER_BYTES {
        return Err(ProxyError::Oversized {
            requested: len,
            maximum: MAX_TRANSFER_BYTES,
        });
    }
    Ok(())
}

/// Resolves a caller deadline, falling back to [`DEFAULT_IO_TIMEOUT`].
pub fn resolve_deadline(deadline: Option<Instant>) -> Instant {
    deadline.unwrap_or_else(|| Instant::now() + DEFAULT_IO_TIMEOUT)
}

/// Remaining time before `deadline`, or `None` when it already elapsed.
pub fn remaining(deadline: Instant) -> Option<Duration> {
    let now = Instant::now();
    (deadline > now).then(|| deadline - now)
}

/// A device object backed by the loopback transport.
struct IslandProxyState {
    bus: LoopbackBus,
    proxy: HostDeviceProxy,
    handles: BTreeMap<u64, ProxyHandle>,
}

fn islands() -> &'static Mutex<BTreeMap<usize, IslandProxyState>> {
    static ISLANDS: OnceLock<Mutex<BTreeMap<usize, IslandProxyState>>> = OnceLock::new();
    ISLANDS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn lock_islands() -> std::sync::MutexGuard<'static, BTreeMap<usize, IslandProxyState>> {
    islands()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn with_island<R>(island: usize, register: impl FnOnce(&mut IslandProxyState) -> R) -> Option<R> {
    let mut registry = lock_islands();
    let state = registry.get_mut(&island)?;
    Some(register(state))
}

/// Attaches a loopback-backed proxy to a CasaK PnP device object.
///
/// The proxy handle is minted immediately, so the device object reported to
/// the driver already has a live host implementation behind it.
pub fn attach_device(
    island: usize,
    device: u64,
    name: &str,
    family: DeviceFamily,
    live_devices: &[u64],
) -> Result<ProxyHandle, ProxyError> {
    let mut registry = lock_islands();
    let state = registry.entry(island).or_insert_with(|| {
        let bus = LoopbackBus::new();
        let proxy = HostDeviceProxy::with_transport(Box::new(LoopbackTransport::new(bus.clone())));
        IslandProxyState {
            bus,
            proxy,
            handles: BTreeMap::new(),
        }
    });
    // The island key is the island-state address.  When an island is dropped
    // and a later island reuses that address, its proxy must not inherit the
    // previous generation's devices: prune everything the live island does
    // not own before attaching.
    let stale: Vec<u64> = state
        .handles
        .keys()
        .filter(|key| !live_devices.contains(key))
        .copied()
        .collect();
    for key in stale {
        if let Some(handle) = state.handles.remove(&key) {
            let _ = state.proxy.close(handle);
        }
        if let Some(id) = state.bus.device_id_for(key) {
            let _ = state.bus.remove_device(id);
        }
    }
    if let Some(handle) = state.handles.get(&device).copied() {
        return Ok(handle);
    }
    let id = StableDeviceId::derive(
        family.device_class(),
        &[name, &format!("casa-device-{device}")],
    );
    state.bus.add_named_device(id, name, family);
    state.bus.bind_device_key(id, device);
    let handle = state.proxy.open(id, None)?;
    state.handles.insert(device, handle);
    Ok(handle)
}

/// Closes and forgets the proxy of a deleted CasaK device object.
pub fn detach_device(island: usize, device: u64) -> Option<ProxyHandle> {
    let mut registry = lock_islands();
    let state = registry.get_mut(&island)?;
    let handle = state.handles.remove(&device);
    if let Some(handle) = handle {
        let _ = state.proxy.close(handle);
    }
    if let Some(id) = state.bus.device_id_for(device) {
        let _ = state.bus.remove_device(id);
    }
    if state.handles.is_empty() {
        registry.remove(&island);
    }
    handle
}

/// Whether `device` has a live proxy in `island`.
pub fn is_attached(island: usize, device: u64) -> bool {
    with_island(island, |state| state.handles.contains_key(&device)).unwrap_or(false)
}

/// Opens (or reopens) a CasaK device.  Idempotent while already open.
pub fn open_device(
    island: usize,
    device: u64,
    deadline: Option<Instant>,
) -> Result<ProxyHandle, ProxyError> {
    with_island(island, |state| {
        if let Some(handle) = state.handles.get(&device).copied()
            && state.proxy.is_open(handle)
        {
            return Ok(handle);
        }
        let id = state
            .bus
            .device_id_for(device)
            .ok_or(ProxyError::DeviceMissing {
                id: StableDeviceId::from_raw(device),
            })?;
        let handle = state.proxy.open(id, deadline)?;
        state.handles.insert(device, handle);
        Ok(handle)
    })
    .unwrap_or(Err(ProxyError::InvalidHandle))
}

/// Closes a CasaK device's proxy channel (a second close is an invalid
/// handle, matching the Windows close path).
pub fn close_device(island: usize, device: u64) -> Result<(), ProxyError> {
    with_island(island, |state| {
        let handle = state
            .handles
            .remove(&device)
            .ok_or(ProxyError::InvalidHandle)?;
        state.proxy.close(handle)
    })
    .unwrap_or(Err(ProxyError::InvalidHandle))
}

/// Capability descriptor of an attached CasaK device.
pub fn device_descriptor(island: usize, device: u64) -> Result<CapabilityDescriptor, ProxyError> {
    with_island(island, |state| {
        let handle = state
            .handles
            .get(&device)
            .copied()
            .ok_or(ProxyError::InvalidHandle)?;
        state.proxy.descriptor_for(handle)
    })
    .unwrap_or(Err(ProxyError::InvalidHandle))
}

/// Reads from an attached CasaK device through its proxy.
pub fn read_device(
    island: usize,
    device: u64,
    buffer: &mut [u8],
    deadline: Option<Instant>,
    cancel: &CancelToken,
) -> Result<usize, ProxyError> {
    with_island(island, |state| {
        let handle = state
            .handles
            .get(&device)
            .copied()
            .ok_or(ProxyError::InvalidHandle)?;
        state.proxy.read(handle, buffer, deadline, cancel)
    })
    .unwrap_or(Err(ProxyError::InvalidHandle))
}

/// Writes to an attached CasaK device through its proxy.
pub fn write_device(
    island: usize,
    device: u64,
    data: &[u8],
    deadline: Option<Instant>,
    cancel: &CancelToken,
) -> Result<usize, ProxyError> {
    with_island(island, |state| {
        let handle = state
            .handles
            .get(&device)
            .copied()
            .ok_or(ProxyError::InvalidHandle)?;
        state.proxy.write(handle, data, deadline, cancel)
    })
    .unwrap_or(Err(ProxyError::InvalidHandle))
}

/// IOCTLs an attached CasaK device through its proxy.
pub fn ioctl_device(
    island: usize,
    device: u64,
    code: u32,
    input: &[u8],
    output_len: usize,
    deadline: Option<Instant>,
    cancel: &CancelToken,
) -> Result<Vec<u8>, ProxyError> {
    with_island(island, |state| {
        let handle = state
            .handles
            .get(&device)
            .copied()
            .ok_or(ProxyError::InvalidHandle)?;
        state
            .proxy
            .ioctl(handle, code, input, output_len, deadline, cancel)
    })
    .unwrap_or(Err(ProxyError::InvalidHandle))
}

/// Enumerates the loopback devices of an island (used by descriptor and
/// hotplug surfaces).
pub fn enumerate_island(island: usize) -> Result<Vec<DeviceRecord>, ProxyError> {
    with_island(island, |state| state.proxy.enumerate()).unwrap_or_else(|| Ok(Vec::new()))
}

/// Hotplug deltas of an island's loopback devices.
pub fn hotplug_island(island: usize) -> Result<Vec<HotplugEvent>, ProxyError> {
    with_island(island, |state| state.proxy.hotplug()).unwrap_or_else(|| Ok(Vec::new()))
}

/// Simulates a host unplug of an attached device, exercising the in-flight
/// failure path from tests (never used by production code).
#[cfg(test)]
pub(crate) fn test_unplug(island: usize, device: u64) -> bool {
    with_island(island, |state| {
        let Some(handle) = state.handles.get(&device).copied() else {
            return false;
        };
        let Ok(id) = state.proxy.device(handle) else {
            return false;
        };
        state.bus.unplug(id)
    })
    .unwrap_or(false)
}

/// Arms a deterministic unplug on the next read of an attached device.
#[cfg(test)]
pub(crate) fn test_unplug_on_next_read(island: usize, device: u64) -> bool {
    with_island(island, |state| {
        let Some(handle) = state.handles.get(&device).copied() else {
            return false;
        };
        let Ok(id) = state.proxy.device(handle) else {
            return false;
        };
        state.bus.unplug_on_next_read(id)
    })
    .unwrap_or(false)
}

/// The success status shared with the IRP layer.
pub const PROXY_SUCCESS: i32 = STATUS_SUCCESS;

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_proxy() -> (HostDeviceProxy, StableDeviceId) {
        let bus = LoopbackBus::new();
        let id = bus.add_device("CasaLoop", DeviceFamily::Virtual);
        let proxy = HostDeviceProxy::with_transport(Box::new(LoopbackTransport::new(bus)));
        (proxy, id)
    }

    #[test]
    fn invalid_proxy_handle_reports_exact_status() {
        let (mut proxy, id) = loopback_proxy();
        let cancel = CancelToken::new();
        assert_eq!(
            proxy.read(ProxyHandle::from_raw(999), &mut [0_u8; 4], None, &cancel),
            Err(ProxyError::InvalidHandle)
        );
        assert_eq!(ProxyError::InvalidHandle.ntstatus(), STATUS_INVALID_HANDLE);
        let handle = proxy.open(id, None).expect("open");
        assert_eq!(proxy.close(handle), Ok(()));
        assert_eq!(
            proxy.close(handle),
            Err(ProxyError::InvalidHandle),
            "double close is an invalid handle"
        );
    }

    fn only_id(proxy: &mut HostDeviceProxy) -> StableDeviceId {
        proxy.enumerate().expect("enumerate")[0].id
    }

    #[test]
    fn zero_and_oversized_transfers_are_rejected_with_exact_status() {
        let (mut proxy, _) = loopback_proxy();
        let id = only_id(&mut proxy);
        let handle = proxy.open(id, None).expect("open");
        let cancel = CancelToken::new();
        assert_eq!(
            proxy.write(handle, &[], None, &cancel),
            Err(ProxyError::ZeroLength)
        );
        assert_eq!(
            proxy.read(handle, &mut [], None, &cancel),
            Err(ProxyError::ZeroLength)
        );
        assert_eq!(ProxyError::ZeroLength.ntstatus(), STATUS_INVALID_PARAMETER);
        let oversized = vec![0_u8; MAX_TRANSFER_BYTES + 1];
        assert_eq!(
            proxy.write(handle, &oversized, None, &cancel),
            Err(ProxyError::Oversized {
                requested: MAX_TRANSFER_BYTES + 1,
                maximum: MAX_TRANSFER_BYTES,
            })
        );
        assert_eq!(
            ProxyError::Oversized {
                requested: 1,
                maximum: 0,
            }
            .ntstatus(),
            STATUS_INVALID_BUFFER_SIZE
        );
        assert_eq!(
            proxy.ioctl(handle, 1, &[], MAX_TRANSFER_BYTES + 1, None, &cancel),
            Err(ProxyError::Oversized {
                requested: MAX_TRANSFER_BYTES + 1,
                maximum: MAX_TRANSFER_BYTES,
            })
        );
    }

    #[test]
    fn cancellation_and_timeout_are_exact() {
        let (mut proxy, _) = loopback_proxy();
        let id = only_id(&mut proxy);
        let handle = proxy.open(id, None).expect("open");
        let cancelled = CancelToken::new();
        cancelled.cancel();
        assert_eq!(
            proxy.read(handle, &mut [0_u8; 4], None, &cancelled),
            Err(ProxyError::Cancelled)
        );
        assert_eq!(ProxyError::Cancelled.ntstatus(), STATUS_CANCELLED);
        let expired = Instant::now() - Duration::from_millis(1);
        assert_eq!(
            proxy.read(handle, &mut [0_u8; 4], Some(expired), &CancelToken::new()),
            Err(ProxyError::Timeout { timeout_ms: 0 })
        );
        assert_eq!(
            ProxyError::Timeout { timeout_ms: 0 }.ntstatus(),
            STATUS_TIMEOUT
        );
    }

    #[test]
    fn unplug_during_in_flight_read_reports_device_not_connected() {
        let bus = LoopbackBus::new();
        let id = bus.add_device("CasaHot", DeviceFamily::Virtual);
        let mut proxy =
            HostDeviceProxy::with_transport(Box::new(LoopbackTransport::new(bus.clone())));
        let handle = proxy.open(id, None).expect("open");
        assert!(matches!(
            proxy.hotplug().expect("seed hotplug").as_slice(),
            [HotplugEvent::Arrived(_)]
        ));
        assert!(bus.unplug_on_next_read(id));
        assert_eq!(
            proxy.read(handle, &mut [0_u8; 4], None, &CancelToken::new()),
            Err(ProxyError::Unplugged { id })
        );
        assert_eq!(
            ProxyError::Unplugged { id }.ntstatus(),
            STATUS_DEVICE_NOT_CONNECTED
        );
        assert!(proxy.enumerate().expect("enumerate").is_empty());
        assert!(matches!(
            proxy.hotplug().expect("hotplug").as_slice(),
            [HotplugEvent::Removed { .. }]
        ));
    }

    #[test]
    fn ioctl_code_mismatch_is_invalid_device_request() {
        let (mut proxy, _) = loopback_proxy();
        let id = only_id(&mut proxy);
        let handle = proxy.open(id, None).expect("open");
        assert_eq!(
            proxy.ioctl(handle, 0x0022_0004, b"PING", 8, None, &CancelToken::new()),
            Err(ProxyError::UnsupportedIoctl { code: 0x0022_0004 })
        );
        assert_eq!(
            ProxyError::UnsupportedIoctl { code: 1 }.ntstatus(),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(ProxyError::UnsupportedIoctl { code: 1 }.windows_error(), 1);
    }

    #[test]
    fn entitlement_and_unsupported_operations_fail_exactly() {
        let descriptor = CapabilityDescriptor::new(
            DeviceFamily::Pci,
            true,
            vec![ProxyOperation::Open, ProxyOperation::Read],
            vec![ProxyOperation::Ioctl],
        );
        assert_eq!(
            descriptor.require(ProxyOperation::Ioctl),
            Err(ProxyError::EntitlementRequired {
                family: DeviceFamily::Pci,
                operation: ProxyOperation::Ioctl,
            })
        );
        assert_eq!(
            ProxyError::EntitlementRequired {
                family: DeviceFamily::Pci,
                operation: ProxyOperation::Ioctl,
            }
            .ntstatus(),
            STATUS_PRIVILEGE_NOT_HELD
        );
        assert_eq!(
            ProxyError::EntitlementRequired {
                family: DeviceFamily::Pci,
                operation: ProxyOperation::Ioctl,
            }
            .windows_error(),
            1314
        );
        assert_eq!(
            descriptor.require(ProxyOperation::Write),
            Err(ProxyError::Unsupported {
                family: DeviceFamily::Pci,
                operation: ProxyOperation::Write,
            })
        );
        assert_eq!(
            ProxyError::Unsupported {
                family: DeviceFamily::Pci,
                operation: ProxyOperation::Write,
            }
            .ntstatus(),
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(
            ProxyError::Unsupported {
                family: DeviceFamily::Pci,
                operation: ProxyOperation::Write,
            }
            .windows_error(),
            50
        );
        // Enumeration stays available even on an entitlement-gated family.
        assert!(descriptor.require(ProxyOperation::Open).is_ok());
        assert!(descriptor.require(ProxyOperation::Read).is_ok());
    }

    #[test]
    fn loopback_round_trip_is_byte_exact() {
        let bus = LoopbackBus::new();
        let id = bus.add_device("CasaExact", DeviceFamily::Virtual);
        bus.register_ioctl(id, 0x0022_0004, b"KMDF".to_vec());
        let mut proxy = HostDeviceProxy::with_transport(Box::new(LoopbackTransport::new(bus)));
        let handle = proxy.open(id, None).expect("open");
        let payload = [0x00, 0xFF, 0x10, 0x7F, 0x80, 0x01];
        assert_eq!(
            proxy.write(handle, &payload, None, &CancelToken::new()),
            Ok(payload.len())
        );
        let mut readback = [0_u8; 6];
        assert_eq!(
            proxy.read(handle, &mut readback, None, &CancelToken::new()),
            Ok(6)
        );
        assert_eq!(readback, payload);
        assert_eq!(
            proxy.ioctl(handle, 0x0022_0004, b"PING", 8, None, &CancelToken::new()),
            Ok(b"KMDF".to_vec())
        );
    }

    #[test]
    fn island_attach_open_read_write_and_detach() {
        let island = 0xC0FF_EE00usize;
        let device = 7u64;
        let handle = attach_device(
            island,
            device,
            "CasaChildA",
            DeviceFamily::Serial,
            &[device],
        )
        .expect("attach");
        assert!(is_attached(island, device));
        assert_eq!(open_device(island, device, None).expect("open"), handle);
        assert_eq!(
            write_device(island, device, &[9, 8, 7], None, &CancelToken::new()),
            Ok(3)
        );
        let mut buffer = [0_u8; 3];
        assert_eq!(
            read_device(island, device, &mut buffer, None, &CancelToken::new()),
            Ok(3)
        );
        assert_eq!(buffer, [9, 8, 7]);
        assert_eq!(
            device_descriptor(island, device)
                .expect("descriptor")
                .family,
            DeviceFamily::Serial
        );
        assert_eq!(close_device(island, device), Ok(()));
        assert_eq!(close_device(island, device), Err(ProxyError::InvalidHandle));
        assert_eq!(detach_device(island, device), None);
        assert!(!is_attached(island, device));
        assert_eq!(
            read_device(island, device, &mut buffer, None, &CancelToken::new()),
            Err(ProxyError::InvalidHandle)
        );
    }

    #[test]
    fn cancellation_during_in_flight_read_is_exact() {
        let bus = LoopbackBus::new();
        let id = bus.add_device("CasaCancel", DeviceFamily::Virtual);
        assert!(bus.set_read_stall(id, Some(Duration::from_millis(100))));
        let mut proxy = HostDeviceProxy::with_transport(Box::new(LoopbackTransport::new(bus)));
        let handle = proxy.open(id, None).expect("open");
        let token = CancelToken::new();
        let worker_token = token.clone();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0_u8; 4];
            proxy.read(handle, &mut buffer, None, &worker_token)
        });
        std::thread::sleep(Duration::from_millis(10));
        token.cancel();
        assert_eq!(worker.join().expect("reader"), Err(ProxyError::Cancelled));
    }

    #[test]
    fn host_unplug_during_in_flight_read_is_exact() {
        let bus = LoopbackBus::new();
        let id = bus.add_device("CasaYank", DeviceFamily::Virtual);
        assert!(bus.set_read_stall(id, Some(Duration::from_millis(100))));
        let mut proxy =
            HostDeviceProxy::with_transport(Box::new(LoopbackTransport::new(bus.clone())));
        let handle = proxy.open(id, None).expect("open");
        let worker = std::thread::spawn(move || {
            let mut buffer = [0_u8; 4];
            proxy.read(handle, &mut buffer, None, &CancelToken::new())
        });
        std::thread::sleep(Duration::from_millis(10));
        assert!(bus.unplug(id));
        assert_eq!(
            worker.join().expect("reader"),
            Err(ProxyError::Unplugged { id })
        );
    }

    #[test]
    fn island_proxy_generation_prunes_stale_devices_on_address_reuse() {
        let island = 0xC0FF_EE02usize;
        let first =
            attach_device(island, 1, "CasaOld", DeviceFamily::Virtual, &[1]).expect("first");
        let second =
            attach_device(island, 2, "CasaNew", DeviceFamily::Virtual, &[2]).expect("second");
        assert_ne!(first, second);
        assert!(!is_attached(island, 1));
        assert!(is_attached(island, 2));
        assert_eq!(
            read_device(island, 1, &mut [0_u8; 1], None, &CancelToken::new()),
            Err(ProxyError::InvalidHandle)
        );
        detach_device(island, 2);
    }

    #[test]
    fn island_unplug_during_in_flight_read_is_exact() {
        let island = 0xC0FF_EE01usize;
        let device = 11u64;
        attach_device(
            island,
            device,
            "CasaChildB",
            DeviceFamily::Virtual,
            &[device],
        )
        .expect("attach");
        assert!(test_unplug_on_next_read(island, device));
        assert_eq!(
            read_device(island, device, &mut [0_u8; 4], None, &CancelToken::new()),
            Err(ProxyError::Unplugged {
                id: StableDeviceId::derive(
                    DeviceFamily::Virtual.device_class(),
                    &["CasaChildB", &format!("casa-device-{device}")],
                ),
            })
        );
        assert!(test_unplug(island, device));
        detach_device(island, device);
    }
}
