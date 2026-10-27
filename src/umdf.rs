//! User-Mode Driver Framework (UMDF) host process model.
//!
//! UMDF drivers do not execute in the kernel.  A reflector loads the driver
//! into a dedicated user-mode host process, the driver exposes COM-style
//! entry/factory/device callbacks, and the host forwards I/O messages over an
//! in-process message loop.  This module implements that model directly:
//!
//! - a bounded [`DriverHost`] object with an explicit lifetime state machine
//! - COM-style [`DriverEntry`], [`DriverFactory`], [`DeviceCallbacks`] and
//!   [`FileCallbacks`] contracts plus an interface reflection registry
//! - a FIFO host message loop with real completions
//! - a reusable host object pool and per-host crash isolation
//! - exact NTSTATUS/HRESULT errors for invalid state, invalid objects and
//!   host features that UMDF cannot provide in this runtime
//!
//! The model deliberately does not panic on a misbehaving driver: a callback
//! error or panic crashes only the owning host.  Other hosts keep running, and
//! every subsequent request to the crashed host fails with the exact
//! `STATUS_PROCESS_IS_TERMINATING` HRESULT.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::casak::status::{
    STATUS_CANCELLED, STATUS_DEVICE_NOT_READY, STATUS_INVALID_DEVICE_STATE, STATUS_INVALID_HANDLE,
    STATUS_OBJECT_TYPE_MISMATCH, STATUS_PROCESS_IS_TERMINATING, STATUS_SUCCESS,
};

/// NTSTATUS as used by the UMDF host model.
pub type NtStatus = i32;
/// COM HRESULT as used by the reflector-facing callbacks.
pub type HResult = i32;

pub const S_OK: HResult = 0;
pub const E_NOTIMPL: HResult = 0x8000_4001u32 as HResult;
pub const E_NOINTERFACE: HResult = 0x8000_4002u32 as HResult;
pub const E_POINTER: HResult = 0x8000_4003u32 as HResult;
pub const E_FAIL: HResult = 0x8000_4005u32 as HResult;
pub const E_UNEXPECTED: HResult = 0x8000_FFFFu32 as HResult;
pub const E_OUTOFMEMORY: HResult = 0x8007_000Eu32 as HResult;
pub const E_INVALIDARG: HResult = 0x8007_0057u32 as HResult;
pub const E_ACCESSDENIED: HResult = 0x8007_0005u32 as HResult;

/// `IRP_MN_SURPRISE_REMOVAL`.
pub const PNP_MINOR_SURPRISE_REMOVAL: u8 = 0x17;

/// Exact error contract for the UMDF host model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UmdfError {
    /// A parameter or interface identifier was malformed.
    InvalidArgument,
    /// The requested COM interface is not reflected by this host.
    NoInterface,
    /// The host process cannot provide the requested UMDF feature.
    NotSupported,
    /// The host/device/object is in the wrong lifetime state.
    InvalidState,
    /// No object exists for the supplied handle.
    InvalidHandle,
    /// The handle exists but denotes a different object type.
    WrongObjectType,
    /// Creating a device or message failed for lack of host resources.
    OutOfMemory,
    /// The host object pool has no free slot.
    PoolExhausted,
    /// The host message ring is full.
    MessageQueueFull,
    /// The host process has already crashed.
    HostCrashed,
    /// The host process is stopping or already stopped.
    HostStopped,
    /// The device was surprised-removed or removed.
    DeviceRemoved,
}

impl UmdfError {
    /// COM HRESULT returned through the reflector boundary.
    pub const fn hresult(self) -> HResult {
        match self {
            Self::InvalidArgument => E_INVALIDARG,
            Self::NoInterface => E_NOINTERFACE,
            Self::NotSupported => E_NOTIMPL,
            Self::InvalidState | Self::HostStopped => STATUS_INVALID_DEVICE_STATE,
            Self::InvalidHandle => STATUS_INVALID_HANDLE,
            Self::WrongObjectType => STATUS_OBJECT_TYPE_MISMATCH,
            Self::OutOfMemory | Self::PoolExhausted | Self::MessageQueueFull => E_OUTOFMEMORY,
            Self::HostCrashed => STATUS_PROCESS_IS_TERMINATING,
            Self::DeviceRemoved => STATUS_DEVICE_NOT_READY,
        }
    }

    /// NTSTATUS returned to a kernel-mode caller of the same operation.
    pub const fn ntstatus(self) -> NtStatus {
        match self {
            Self::InvalidArgument => crate::casak::status::STATUS_INVALID_PARAMETER,
            Self::NoInterface | Self::NotSupported => crate::casak::status::STATUS_NOT_SUPPORTED,
            Self::InvalidState | Self::HostStopped => STATUS_INVALID_DEVICE_STATE,
            Self::InvalidHandle => STATUS_INVALID_HANDLE,
            Self::WrongObjectType => STATUS_OBJECT_TYPE_MISMATCH,
            Self::OutOfMemory | Self::PoolExhausted | Self::MessageQueueFull => {
                crate::casak::status::STATUS_INSUFFICIENT_RESOURCES
            }
            Self::HostCrashed => STATUS_PROCESS_IS_TERMINATING,
            Self::DeviceRemoved => STATUS_DEVICE_NOT_READY,
        }
    }
}

impl std::fmt::Display for UmdfError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?} (0x{:08X})", self.hresult() as u32)
    }
}

impl std::error::Error for UmdfError {}

/// A COM interface identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Iid(pub u128);

pub const IID_IUNKNOWN: Iid = Iid(0x0000_0000_0000_0000_C000_0000_0000_0046);
pub const IID_IDRIVER_ENTRY: Iid = Iid(0x0000_0000_0000_0000_C000_0000_0000_4701);
pub const IID_IDRIVER_FACTORY: Iid = Iid(0x0000_0000_0000_0000_C000_0000_0000_4702);
pub const IID_IDEVICE_CALLBACK: Iid = Iid(0x0000_0000_0000_0000_C000_0000_0000_4703);
pub const IID_IFILE_CALLBACK: Iid = Iid(0x0000_0000_0000_0000_C000_0000_0000_4704);

/// One reflected COM interface: its IID and method names, in vtable order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectedInterface {
    pub iid: Iid,
    pub methods: &'static [&'static str],
}

impl ReflectedInterface {
    pub const fn new(iid: Iid, methods: &'static [&'static str]) -> Self {
        Self { iid, methods }
    }
}

/// Interface reflection registry and proxy allocation pool.
#[derive(Debug, Default)]
pub struct ReflectionPool {
    interfaces: BTreeMap<Iid, ReflectedInterface>,
    proxies: u64,
}

impl ReflectionPool {
    /// Registry pre-populated with the four UMDF host interfaces.
    pub fn with_umdf_interfaces() -> Self {
        let mut pool = Self::default();
        for interface in [
            ReflectedInterface::new(IID_IUNKNOWN, &["QueryInterface", "AddRef", "Release"]),
            ReflectedInterface::new(
                IID_IDRIVER_ENTRY,
                &[
                    "QueryInterface",
                    "AddRef",
                    "Release",
                    "OnInitialize",
                    "OnDeinitialize",
                ],
            ),
            ReflectedInterface::new(
                IID_IDRIVER_FACTORY,
                &["QueryInterface", "AddRef", "Release", "CreateInstance"],
            ),
            ReflectedInterface::new(
                IID_IDEVICE_CALLBACK,
                &[
                    "QueryInterface",
                    "AddRef",
                    "Release",
                    "OnCreate",
                    "OnClose",
                    "OnCleanup",
                    "OnIoControl",
                    "OnRead",
                    "OnWrite",
                    "OnPnp",
                    "OnPower",
                    "OnSurpriseRemoval",
                ],
            ),
            ReflectedInterface::new(
                IID_IFILE_CALLBACK,
                &[
                    "QueryInterface",
                    "AddRef",
                    "Release",
                    "OnFileCreate",
                    "OnFileClose",
                    "OnFileCleanup",
                ],
            ),
        ] {
            // Static well-known interfaces are unique.
            let _ = pool.register(interface);
        }
        pool
    }

    /// Register a reflected interface.  Duplicate IIDs are rejected exactly
    /// like a reflector re-registering the same proxy class.
    pub fn register(&mut self, interface: ReflectedInterface) -> Result<(), UmdfError> {
        if self.interfaces.contains_key(&interface.iid) {
            return Err(UmdfError::InvalidState);
        }
        self.interfaces.insert(interface.iid, interface);
        Ok(())
    }

    /// Resolve an interface.  Unsupported interfaces fail with `E_NOINTERFACE`.
    pub fn query(&self, iid: Iid) -> Result<&ReflectedInterface, UmdfError> {
        self.interfaces.get(&iid).ok_or(UmdfError::NoInterface)
    }

    /// Allocate a reflected proxy for a supported interface.
    pub fn proxy(&mut self, iid: Iid) -> Result<Iid, UmdfError> {
        self.query(iid)?;
        self.proxies += 1;
        Ok(iid)
    }

    pub fn proxy_count(&self) -> u64 {
        self.proxies
    }

    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }
}

/// A reusable host-object pool slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PoolSlot(pub u32);

/// Bounded host object pool.  Released slots are reused before the pool grows.
#[derive(Debug)]
pub struct HostObjectPool {
    capacity: usize,
    next: u32,
    free: Vec<u32>,
    in_use: BTreeSet<u32>,
    allocations: u64,
}

impl HostObjectPool {
    pub fn new(capacity: usize) -> Result<Self, UmdfError> {
        if capacity == 0 {
            return Err(UmdfError::InvalidArgument);
        }
        Ok(Self {
            capacity,
            next: 0,
            free: Vec::new(),
            in_use: BTreeSet::new(),
            allocations: 0,
        })
    }

    pub fn allocate(&mut self) -> Result<PoolSlot, UmdfError> {
        let slot = if let Some(slot) = self.free.pop() {
            slot
        } else if (self.next as usize) < self.capacity {
            let slot = self.next;
            self.next += 1;
            slot
        } else {
            return Err(UmdfError::PoolExhausted);
        };
        self.in_use.insert(slot);
        self.allocations += 1;
        Ok(PoolSlot(slot))
    }

    pub fn release(&mut self, slot: PoolSlot) -> Result<(), UmdfError> {
        if !self.in_use.remove(&slot.0) {
            return Err(UmdfError::InvalidHandle);
        }
        self.free.push(slot.0);
        Ok(())
    }

    pub fn in_use(&self) -> usize {
        self.in_use.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn allocations(&self) -> u64 {
        self.allocations
    }
}

/// Stable host process identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostId(pub u32);

/// The user-mode process that owns a driver host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostProcess {
    pub host: HostId,
    pub process_id: u32,
}

/// Host lifetime state.  A crashed host never transitions back to running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLifetime {
    Created,
    Running,
    Stopping,
    Stopped,
    Crashed,
}

/// Why a host was isolated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrashReason {
    CallbackError(UmdfError),
    CallbackPanic,
    InitializationFailure(UmdfError),
}

/// Context handed to the driver entry/factory callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostContext {
    pub host: HostId,
    pub process_id: u32,
    pub generation: u64,
}

/// Stable device identifier inside one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub u64);

/// Device creation parameters passed to `IDriverFactory::CreateInstance`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCreateContext {
    pub instance_id: String,
    pub hardware_ids: Vec<String>,
}

/// `IDriverEntry` callback contract.
pub trait DriverEntry {
    fn on_initialize(&mut self, context: HostContext) -> Result<(), UmdfError>;
    fn on_deinitialize(&mut self, context: HostContext);
}

/// `IDriverFactory` callback contract.
pub trait DriverFactory {
    fn create_instance(
        &mut self,
        device: DeviceId,
        context: &DeviceCreateContext,
    ) -> Result<DeviceInstance, UmdfError>;
}

/// One user-mode device instance created by a driver factory.
pub struct DeviceInstance {
    pub callbacks: Box<dyn DeviceCallbacks>,
    pub file_callbacks: Option<Box<dyn FileCallbacks>>,
}

/// Per-device callback contract.
pub trait DeviceCallbacks {
    fn on_create(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }

    fn on_close(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }

    fn on_cleanup(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }

    fn on_io_control(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }

    fn on_read(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }

    fn on_write(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }

    fn on_pnp(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }

    fn on_power(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }

    fn on_surprise_removal(&mut self) -> Result<(), UmdfError> {
        Ok(())
    }
}

/// Per-file-object callback contract.
pub trait FileCallbacks {
    fn on_file_create(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }

    fn on_file_close(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }

    fn on_file_cleanup(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
        Ok(STATUS_SUCCESS)
    }
}

/// One message delivered to a host device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMessageKind {
    Create {
        desired_access: u32,
    },
    Cleanup,
    Close,
    IoControl {
        code: u32,
        input: Vec<u8>,
        output_capacity: usize,
    },
    Read {
        length: usize,
    },
    Write {
        data: Vec<u8>,
    },
    Pnp {
        minor: u8,
    },
    Power {
        state: u32,
    },
}

/// One queued host message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMessage {
    pub id: u64,
    pub device: DeviceId,
    pub kind: HostMessageKind,
}

/// Result of dispatching one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageCompletion {
    pub message: u64,
    pub device: DeviceId,
    pub status: NtStatus,
    pub information: usize,
}

/// Observable host lifecycle events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEvent {
    Initialized,
    DeviceAdded(DeviceId),
    MessageQueued(u64),
    MessageCompleted(MessageCompletion),
    DeviceSurprised(DeviceId),
    DeviceRemoved(DeviceId),
    PendingMessagesCancelled(DeviceId, usize),
    UnsupportedFeature(&'static str),
    HostCrashed(CrashReason),
    DriverDeinitialized,
}

/// Device lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Running,
    SurpriseRemoved,
    Removed,
}

struct RegisteredDriver {
    entry: Box<dyn DriverEntry>,
    factory: Box<dyn DriverFactory>,
}

struct Device {
    callbacks: Box<dyn DeviceCallbacks>,
    file_callbacks: Option<Box<dyn FileCallbacks>>,
    state: DeviceState,
    pool_slot: PoolSlot,
}

/// Host configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostConfig {
    pub max_devices: usize,
    pub max_messages: usize,
    pub pool_capacity: usize,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            max_devices: 16,
            max_messages: 64,
            pool_capacity: 64,
        }
    }
}

/// A live UMDF driver host process.
pub struct DriverHost {
    process: HostProcess,
    context: HostContext,
    lifetime: HostLifetime,
    driver: Option<RegisteredDriver>,
    devices: BTreeMap<DeviceId, Device>,
    messages: VecDeque<HostMessage>,
    completions: VecDeque<MessageCompletion>,
    events: VecDeque<HostEvent>,
    reflection: ReflectionPool,
    pool: HostObjectPool,
    config: HostConfig,
    next_device: u64,
    next_message: u64,
    crash: Option<CrashReason>,
    deinitialized: bool,
}

impl DriverHost {
    /// Create a host process object.  The host is not yet initialized.
    pub fn new(host: HostId, process_id: u32, config: HostConfig) -> Result<Self, UmdfError> {
        if process_id == 0 {
            return Err(UmdfError::InvalidArgument);
        }
        if config.max_devices == 0 || config.max_messages == 0 {
            return Err(UmdfError::InvalidArgument);
        }
        let pool = HostObjectPool::new(config.pool_capacity)?;
        Ok(Self {
            process: HostProcess { host, process_id },
            context: HostContext {
                host,
                process_id,
                generation: 1,
            },
            lifetime: HostLifetime::Created,
            driver: None,
            devices: BTreeMap::new(),
            messages: VecDeque::new(),
            completions: VecDeque::new(),
            events: VecDeque::new(),
            reflection: ReflectionPool::with_umdf_interfaces(),
            pool,
            config,
            next_device: 1,
            next_message: 1,
            crash: None,
            deinitialized: false,
        })
    }

    pub fn process(&self) -> HostProcess {
        self.process
    }

    pub fn context(&self) -> HostContext {
        self.context
    }

    pub fn lifetime(&self) -> HostLifetime {
        self.lifetime
    }

    pub fn crash_reason(&self) -> Option<&CrashReason> {
        self.crash.as_ref()
    }

    pub fn device_count(&self) -> usize {
        self.devices
            .values()
            .filter(|device| device.state == DeviceState::Running)
            .count()
    }

    pub fn queued_messages(&self) -> usize {
        self.messages.len()
    }

    pub fn pending_completions(&self) -> usize {
        self.completions.len()
    }

    pub fn events(&self) -> impl Iterator<Item = &HostEvent> + '_ {
        self.events.iter()
    }

    pub fn driver_deinitialized(&self) -> bool {
        self.deinitialized
    }

    pub fn reflection(&self) -> &ReflectionPool {
        &self.reflection
    }

    pub fn pool(&self) -> &HostObjectPool {
        &self.pool
    }

    pub fn device_state(&self, device: DeviceId) -> Result<DeviceState, UmdfError> {
        self.devices
            .get(&device)
            .map(|device| device.state)
            .ok_or(UmdfError::InvalidHandle)
    }

    /// Register a reflected interface on this host.
    pub fn register_interface(&mut self, interface: ReflectedInterface) -> Result<(), UmdfError> {
        if self.lifetime != HostLifetime::Created {
            return Err(UmdfError::InvalidState);
        }
        self.reflection.register(interface)
    }

    /// Resolve a COM interface.  Unknown IIDs return `E_NOINTERFACE`.
    pub fn query_interface(&self, iid: Iid) -> Result<&ReflectedInterface, UmdfError> {
        self.reflection.query(iid)
    }

    /// Register the driver entry/factory pair.  Exactly one registration is
    /// accepted, and only before initialization.
    pub fn register_driver(
        &mut self,
        entry: Box<dyn DriverEntry>,
        factory: Box<dyn DriverFactory>,
    ) -> Result<(), UmdfError> {
        if self.lifetime != HostLifetime::Created {
            return Err(UmdfError::InvalidState);
        }
        if self.driver.is_some() {
            return Err(UmdfError::InvalidState);
        }
        self.reflection.query(IID_IDRIVER_ENTRY)?;
        self.reflection.query(IID_IDRIVER_FACTORY)?;
        self.driver = Some(RegisteredDriver { entry, factory });
        Ok(())
    }

    /// Initialize the driver entry object and move the host to running.
    pub fn initialize(&mut self) -> Result<(), UmdfError> {
        if self.lifetime != HostLifetime::Created {
            return Err(UmdfError::InvalidState);
        }
        let Some(driver) = self.driver.as_mut() else {
            return Err(UmdfError::InvalidState);
        };
        let context = self.context;
        let result = catch_unwind(AssertUnwindSafe(|| driver.entry.on_initialize(context)));
        match result {
            Ok(Ok(())) => {
                self.lifetime = HostLifetime::Running;
                self.events.push_back(HostEvent::Initialized);
                Ok(())
            }
            Ok(Err(error)) => {
                self.record_crash(CrashReason::InitializationFailure(error));
                Err(error)
            }
            Err(_) => {
                self.record_crash(CrashReason::CallbackPanic);
                Err(UmdfError::HostCrashed)
            }
        }
    }

    /// Ask the driver factory for a device and add it to the host.
    pub fn add_device(
        &mut self,
        instance_id: impl Into<String>,
        hardware_ids: Vec<String>,
    ) -> Result<DeviceId, UmdfError> {
        self.require_running()?;
        if self.device_count() >= self.config.max_devices {
            return Err(UmdfError::OutOfMemory);
        }
        let device_id = DeviceId(self.next_device);
        let create = DeviceCreateContext {
            instance_id: instance_id.into(),
            hardware_ids,
        };
        let Some(driver) = self.driver.as_mut() else {
            return Err(UmdfError::InvalidState);
        };
        let created = catch_unwind(AssertUnwindSafe(|| {
            driver.factory.create_instance(device_id, &create)
        }));
        let instance = match created {
            Ok(Ok(instance)) => instance,
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                self.record_crash(CrashReason::CallbackPanic);
                return Err(UmdfError::HostCrashed);
            }
        };
        let slot = self.pool.allocate()?;
        self.next_device += 1;
        self.devices.insert(
            device_id,
            Device {
                callbacks: instance.callbacks,
                file_callbacks: instance.file_callbacks,
                state: DeviceState::Running,
                pool_slot: slot,
            },
        );
        self.events.push_back(HostEvent::DeviceAdded(device_id));
        Ok(device_id)
    }

    /// Remove a device.  Surprise removal records the state transition without
    /// the clean shutdown contract; both variants cancel queued messages.
    pub fn remove_device(&mut self, device: DeviceId, surprise: bool) -> Result<(), UmdfError> {
        self.require_running()?;
        let Some(record) = self.devices.get(&device) else {
            return Err(UmdfError::InvalidHandle);
        };
        match record.state {
            DeviceState::Removed => return Err(UmdfError::InvalidState),
            DeviceState::SurpriseRemoved if !surprise => return Err(UmdfError::InvalidState),
            _ => {}
        }
        if surprise {
            let surprise_result = {
                let record = self
                    .devices
                    .get_mut(&device)
                    .expect("device was checked above");
                catch_unwind(AssertUnwindSafe(|| record.callbacks.on_surprise_removal()))
            };
            match surprise_result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    self.record_crash(CrashReason::CallbackError(error));
                    return Err(UmdfError::HostCrashed);
                }
                Err(_) => {
                    self.record_crash(CrashReason::CallbackPanic);
                    return Err(UmdfError::HostCrashed);
                }
            }
        }
        let cancelled = self.cancel_device_messages(device);
        let record = self
            .devices
            .get_mut(&device)
            .expect("device was checked above");
        record.state = if surprise {
            DeviceState::SurpriseRemoved
        } else {
            DeviceState::Removed
        };
        let slot = record.pool_slot;
        self.pool.release(slot)?;
        self.events.push_back(if surprise {
            HostEvent::DeviceSurprised(device)
        } else {
            HostEvent::DeviceRemoved(device)
        });
        if cancelled > 0 {
            self.events
                .push_back(HostEvent::PendingMessagesCancelled(device, cancelled));
        }
        Ok(())
    }

    /// Queue one I/O message for a running device.
    pub fn submit_message(
        &mut self,
        device: DeviceId,
        kind: HostMessageKind,
    ) -> Result<u64, UmdfError> {
        self.require_running()?;
        let Some(record) = self.devices.get(&device) else {
            return Err(UmdfError::InvalidHandle);
        };
        if record.state != DeviceState::Running {
            return Err(UmdfError::DeviceRemoved);
        }
        if self.messages.len() >= self.config.max_messages {
            return Err(UmdfError::MessageQueueFull);
        }
        let id = self.next_message;
        self.next_message += 1;
        self.messages.push_back(HostMessage { id, device, kind });
        self.events.push_back(HostEvent::MessageQueued(id));
        Ok(id)
    }

    /// Dispatch up to `budget` queued messages in FIFO order.
    pub fn pump(&mut self, budget: usize) -> Result<Vec<MessageCompletion>, UmdfError> {
        self.require_running()?;
        let mut completed = Vec::new();
        for _ in 0..budget {
            let Some(message) = self.messages.pop_front() else {
                break;
            };
            let completion = self.dispatch_message(message)?;
            self.completions.push_back(completion);
            self.events
                .push_back(HostEvent::MessageCompleted(completion));
            completed.push(completion);
        }
        Ok(completed)
    }

    /// Drain completions accumulated by `pump`.
    pub fn take_completions(&mut self) -> Vec<MessageCompletion> {
        self.completions.drain(..).collect()
    }

    /// Deinitialize the driver and stop the host.  A crashed host cannot be
    /// reinitialized or cleanly shut down.
    pub fn shutdown(&mut self) -> Result<(), UmdfError> {
        match self.lifetime {
            HostLifetime::Crashed => return Err(UmdfError::HostCrashed),
            HostLifetime::Stopped | HostLifetime::Stopping => {
                return Err(UmdfError::HostStopped);
            }
            HostLifetime::Created => return Err(UmdfError::InvalidState),
            HostLifetime::Running => {}
        }
        self.lifetime = HostLifetime::Stopping;
        self.messages.clear();
        for device in self.devices.values_mut() {
            if device.state == DeviceState::Running {
                device.state = DeviceState::Removed;
                let _ = self.pool.release(device.pool_slot);
            }
        }
        self.devices.clear();
        if let Some(driver) = self.driver.as_mut() {
            let context = self.context;
            let result = catch_unwind(AssertUnwindSafe(|| driver.entry.on_deinitialize(context)));
            if result.is_ok() {
                self.deinitialized = true;
            } else {
                self.record_crash(CrashReason::CallbackPanic);
                return Err(UmdfError::HostCrashed);
            }
        }
        self.lifetime = HostLifetime::Stopped;
        self.events.push_back(HostEvent::DriverDeinitialized);
        Ok(())
    }

    /// Report a host feature that the current UMDF host cannot provide.  The
    /// exact HRESULT is `E_NOTIMPL`; the event remains observable.
    pub fn unsupported_feature(&mut self, feature: &'static str) -> Result<(), UmdfError> {
        self.events
            .push_back(HostEvent::UnsupportedFeature(feature));
        Err(UmdfError::NotSupported)
    }

    /// Crash only this host, leaving every other host untouched.
    pub fn crash(&mut self, reason: CrashReason) -> Result<(), UmdfError> {
        if self.lifetime == HostLifetime::Crashed {
            return Err(UmdfError::HostCrashed);
        }
        self.record_crash(reason);
        Err(UmdfError::HostCrashed)
    }

    fn require_running(&self) -> Result<(), UmdfError> {
        match self.lifetime {
            HostLifetime::Running => Ok(()),
            HostLifetime::Crashed => Err(UmdfError::HostCrashed),
            HostLifetime::Stopped | HostLifetime::Stopping => Err(UmdfError::HostStopped),
            HostLifetime::Created => Err(UmdfError::InvalidState),
        }
    }

    fn dispatch_message(&mut self, message: HostMessage) -> Result<MessageCompletion, UmdfError> {
        let Some(device) = self.devices.get_mut(&message.device) else {
            return Err(UmdfError::InvalidHandle);
        };
        if device.state != DeviceState::Running {
            return Err(UmdfError::DeviceRemoved);
        }
        let result = catch_unwind(AssertUnwindSafe(|| dispatch_device(device, &message)));
        match result {
            Ok(Ok(status)) => Ok(MessageCompletion {
                message: message.id,
                device: message.device,
                status,
                information: information_for(&message.kind),
            }),
            Ok(Err(error)) => {
                self.record_crash(CrashReason::CallbackError(error));
                Err(UmdfError::HostCrashed)
            }
            Err(_) => {
                self.record_crash(CrashReason::CallbackPanic);
                Err(UmdfError::HostCrashed)
            }
        }
    }

    fn cancel_device_messages(&mut self, device: DeviceId) -> usize {
        let mut cancelled = 0;
        let mut retained = VecDeque::with_capacity(self.messages.len());
        while let Some(message) = self.messages.pop_front() {
            if message.device == device {
                cancelled += 1;
                self.completions.push_back(MessageCompletion {
                    message: message.id,
                    device,
                    status: STATUS_CANCELLED,
                    information: 0,
                });
            } else {
                retained.push_back(message);
            }
        }
        self.messages = retained;
        cancelled
    }

    fn record_crash(&mut self, reason: CrashReason) {
        self.lifetime = HostLifetime::Crashed;
        self.crash = Some(reason.clone());
        self.messages.clear();
        self.events.push_back(HostEvent::HostCrashed(reason));
    }
}

fn information_for(kind: &HostMessageKind) -> usize {
    match kind {
        HostMessageKind::IoControl {
            output_capacity, ..
        } => *output_capacity,
        HostMessageKind::Read { length } => *length,
        HostMessageKind::Write { data } => data.len(),
        _ => 0,
    }
}

fn dispatch_device(device: &mut Device, message: &HostMessage) -> Result<NtStatus, UmdfError> {
    match &message.kind {
        HostMessageKind::Create { .. } => match device.file_callbacks.as_mut() {
            Some(file) => file.on_file_create(message),
            None => device.callbacks.on_create(message),
        },
        HostMessageKind::Cleanup => match device.file_callbacks.as_mut() {
            Some(file) => file.on_file_cleanup(message),
            None => device.callbacks.on_cleanup(message),
        },
        HostMessageKind::Close => match device.file_callbacks.as_mut() {
            Some(file) => file.on_file_close(message),
            None => device.callbacks.on_close(message),
        },
        HostMessageKind::IoControl { .. } => device.callbacks.on_io_control(message),
        HostMessageKind::Read { .. } => device.callbacks.on_read(message),
        HostMessageKind::Write { .. } => device.callbacks.on_write(message),
        HostMessageKind::Pnp { minor } => {
            if *minor == PNP_MINOR_SURPRISE_REMOVAL {
                device.callbacks.on_surprise_removal()?;
            }
            device.callbacks.on_pnp(message)
        }
        HostMessageKind::Power { .. } => device.callbacks.on_power(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopEntry {
        initialize_result: Result<(), UmdfError>,
        deinitialized: u32,
    }

    impl DriverEntry for NoopEntry {
        fn on_initialize(&mut self, _context: HostContext) -> Result<(), UmdfError> {
            self.initialize_result
        }

        fn on_deinitialize(&mut self, _context: HostContext) {
            self.deinitialized += 1;
        }
    }

    struct NoopFactory {
        fail: bool,
    }

    impl DriverFactory for NoopFactory {
        fn create_instance(
            &mut self,
            _device: DeviceId,
            _context: &DeviceCreateContext,
        ) -> Result<DeviceInstance, UmdfError> {
            if self.fail {
                return Err(UmdfError::OutOfMemory);
            }
            Ok(DeviceInstance {
                callbacks: Box::new(NoopDevice),
                file_callbacks: None,
            })
        }
    }

    #[derive(Default)]
    struct NoopDevice;

    impl DeviceCallbacks for NoopDevice {}

    struct CrashingDevice {
        panic: bool,
    }

    impl DeviceCallbacks for CrashingDevice {
        fn on_io_control(&mut self, _message: &HostMessage) -> Result<NtStatus, UmdfError> {
            if self.panic {
                panic!("umdf test callback panic");
            }
            Err(UmdfError::NotSupported)
        }
    }

    fn host(process_id: u32, pool_capacity: usize) -> DriverHost {
        DriverHost::new(
            HostId(process_id),
            process_id,
            HostConfig {
                max_devices: 2,
                max_messages: 2,
                pool_capacity,
            },
        )
        .expect("host")
    }

    fn initialized_host(process_id: u32) -> DriverHost {
        let mut host = host(process_id, 4);
        host.register_driver(
            Box::new(NoopEntry {
                initialize_result: Ok(()),
                deinitialized: 0,
            }),
            Box::new(NoopFactory { fail: false }),
        )
        .expect("register driver");
        host.initialize().expect("initialize");
        host
    }

    #[test]
    fn double_initialize_and_shutdown_reject_with_exact_invalid_state() {
        let mut host = initialized_host(41);
        assert_eq!(
            host.initialize().expect_err("double initialize"),
            UmdfError::InvalidState
        );
        assert_eq!(
            host.initialize().expect_err("double initialize").hresult(),
            STATUS_INVALID_DEVICE_STATE
        );
        host.shutdown().expect("shutdown");
        assert_eq!(
            host.shutdown().expect_err("double shutdown"),
            UmdfError::HostStopped
        );
        assert_eq!(host.lifetime(), HostLifetime::Stopped);
    }

    #[test]
    fn unsupported_umdf_interface_returns_exact_e_nointerface() {
        let mut host = initialized_host(42);
        assert_eq!(
            host.query_interface(Iid(0xDEAD_BEEF_0000_0000_0000_0000_0000_0001))
                .expect_err("unknown interface"),
            UmdfError::NoInterface
        );
        assert_eq!(UmdfError::NoInterface.hresult(), E_NOINTERFACE);
        assert_eq!(
            host.unsupported_feature("host-reflector-kernel-mode")
                .expect_err("unsupported feature"),
            UmdfError::NotSupported
        );
        assert_eq!(E_NOTIMPL, 0x8000_4001u32 as HResult);
    }

    #[test]
    fn host_crash_isolation_rejects_messages_without_affecting_other_hosts() {
        let mut crashed = initialized_host(51);
        let device = crashed
            .add_device("root\\crash", Vec::new())
            .expect("add device");
        // Replace the no-op device with one whose IOCTL callback fails.
        crashed.devices.get_mut(&device).expect("device").callbacks =
            Box::new(CrashingDevice { panic: false });
        crashed
            .submit_message(
                device,
                HostMessageKind::IoControl {
                    code: 1,
                    input: Vec::new(),
                    output_capacity: 0,
                },
            )
            .expect("queue ioctl");
        assert_eq!(
            crashed.pump(1).expect_err("callback failure crashes host"),
            UmdfError::HostCrashed
        );
        assert_eq!(crashed.lifetime(), HostLifetime::Crashed);
        assert_eq!(
            crashed
                .submit_message(device, HostMessageKind::Cleanup)
                .expect_err("crashed host rejects work"),
            UmdfError::HostCrashed
        );
        assert_eq!(
            UmdfError::HostCrashed.hresult(),
            STATUS_PROCESS_IS_TERMINATING
        );

        let mut healthy = initialized_host(52);
        let healthy_device = healthy
            .add_device("root\\healthy", Vec::new())
            .expect("healthy device");
        healthy
            .submit_message(healthy_device, HostMessageKind::Cleanup)
            .expect("healthy queue");
        assert_eq!(healthy.pump(1).expect("healthy pump").len(), 1);
        assert_eq!(healthy.lifetime(), HostLifetime::Running);
    }

    #[test]
    fn host_callback_panic_is_isolated_to_the_owning_host() {
        let mut host = initialized_host(61);
        let device = host
            .add_device("root\\panic", Vec::new())
            .expect("add device");
        host.devices.get_mut(&device).expect("device").callbacks =
            Box::new(CrashingDevice { panic: true });
        host.submit_message(
            device,
            HostMessageKind::IoControl {
                code: 2,
                input: Vec::new(),
                output_capacity: 0,
            },
        )
        .expect("queue ioctl");
        assert_eq!(
            host.pump(1).expect_err("panic crashes host"),
            UmdfError::HostCrashed
        );
        assert_eq!(host.crash_reason(), Some(&CrashReason::CallbackPanic));
    }

    #[test]
    fn object_pool_exhaustion_and_stale_release_are_exact() {
        let mut pool = HostObjectPool::new(1).expect("pool");
        let slot = pool.allocate().expect("slot");
        assert_eq!(
            pool.allocate().expect_err("pool exhausted"),
            UmdfError::PoolExhausted
        );
        assert_eq!(UmdfError::PoolExhausted.hresult(), E_OUTOFMEMORY);
        pool.release(slot).expect("release");
        assert_eq!(
            pool.release(slot).expect_err("stale release"),
            UmdfError::InvalidHandle
        );
        let reused = pool.allocate().expect("reuse");
        assert_eq!(reused, slot);
        pool.release(reused).expect("release reused");
        assert_eq!(UmdfError::InvalidHandle.hresult(), STATUS_INVALID_HANDLE);
        assert_eq!(
            HostObjectPool::new(0).expect_err("zero capacity"),
            UmdfError::InvalidArgument
        );
    }

    #[test]
    fn surprise_removal_cancels_queued_messages_and_rejects_late_submits() {
        let mut host = initialized_host(71);
        let device = host
            .add_device("root\\surprise", Vec::new())
            .expect("add device");
        host.submit_message(device, HostMessageKind::Cleanup)
            .expect("queue cleanup");
        host.submit_message(device, HostMessageKind::Close)
            .expect("queue close");
        host.remove_device(device, true).expect("surprise remove");
        assert_eq!(host.device_state(device), Ok(DeviceState::SurpriseRemoved));
        let completions = host.take_completions();
        assert_eq!(completions.len(), 2);
        assert_eq!(completions[0].status, STATUS_CANCELLED);
        assert_eq!(completions[1].status, STATUS_CANCELLED);
        assert_eq!(
            host.submit_message(device, HostMessageKind::Cleanup)
                .expect_err("late submit"),
            UmdfError::DeviceRemoved
        );
        assert_eq!(UmdfError::DeviceRemoved.hresult(), STATUS_DEVICE_NOT_READY);
        assert_eq!(
            host.remove_device(device, false)
                .expect_err("double remove"),
            UmdfError::InvalidState
        );
    }

    #[test]
    fn message_queue_and_device_limits_reject_with_exact_errors() {
        let mut host = initialized_host(81);
        let first = host.add_device("root\\a", Vec::new()).expect("first");
        let _second = host.add_device("root\\b", Vec::new()).expect("second");
        assert_eq!(
            host.add_device("root\\c", Vec::new())
                .expect_err("device limit"),
            UmdfError::OutOfMemory
        );
        host.submit_message(first, HostMessageKind::Cleanup)
            .expect("first message");
        host.submit_message(first, HostMessageKind::Close)
            .expect("second message");
        assert_eq!(
            host.submit_message(first, HostMessageKind::Cleanup)
                .expect_err("queue limit"),
            UmdfError::MessageQueueFull
        );
        assert_eq!(UmdfError::MessageQueueFull.hresult(), E_OUTOFMEMORY);
    }

    #[test]
    fn reflection_registry_rejects_duplicate_iid_and_unknown_proxy() {
        let mut pool = ReflectionPool::with_umdf_interfaces();
        let duplicate = ReflectedInterface::new(IID_IDRIVER_ENTRY, &["QueryInterface"]);
        assert_eq!(
            pool.register(duplicate).expect_err("duplicate iid"),
            UmdfError::InvalidState
        );
        assert_eq!(
            pool.proxy(Iid(1)).expect_err("unknown proxy"),
            UmdfError::NoInterface
        );
        assert_eq!(pool.proxy_count(), 0);
        assert_eq!(pool.len(), 5);
    }
}
