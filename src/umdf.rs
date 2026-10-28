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
use std::time::{Duration, Instant};

use crate::casak::status::{
    STATUS_CANCELLED, STATUS_DEVICE_BUSY, STATUS_DEVICE_NOT_READY, STATUS_INVALID_DEVICE_STATE,
    STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH, STATUS_PROCESS_IS_TERMINATING,
    STATUS_SUCCESS,
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
/// `HRESULT_FROM_WIN32(ERROR_BUSY)` (170 = `0xAA`): the spinlock is held.
pub const HRESULT_FROM_WIN32_ERROR_BUSY: HResult = 0x8007_00AAu32 as HResult;

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
    /// The requested resource (spinlock) is held by another vCPU.
    Busy,
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
            Self::Busy => HRESULT_FROM_WIN32_ERROR_BUSY,
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
            Self::Busy => STATUS_DEVICE_BUSY,
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

/// A wall-clock timer entry in the host's timer pump.
///
/// Due times are absolute `Instant` deadlines.  A timer whose deadline is in
/// the past when pumped fires immediately and reports the exact lateness
/// (`now - deadline`).  Cancelling a timer that is concurrently due returns
/// `false` (the timer already fired or fired racing the cancel).
#[derive(Debug, Clone)]
pub struct HostTimer {
    pub id: u64,
    deadline: Instant,
    period: Option<Duration>,
    armed: bool,
    fired: u64,
    last_lateness: Duration,
}

/// One fired-timer record produced by a pump pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerFired {
    pub id: u64,
    pub lateness: Duration,
}

/// Real wall-clock timer pump for one UMDF host.
///
/// Timers are monotonic-`Instant` based: zero-due timers fire on the next
/// pump, positive-due timers fire only when the pump clock reaches their
/// deadline, and overdue timers report exact lateness.  The pump is the only
/// context in which a timer callback runs, mirroring the UMDF host thread
/// that owns timer DPCs.
#[derive(Debug, Default)]
pub struct TimerPump {
    next_id: u64,
    timers: BTreeMap<u64, HostTimer>,
    total_fires: u64,
}

impl TimerPump {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm a timer to fire at `deadline`; periodic timers re-arm with their
    /// period after each fire (catching up overdue periods one fire at a
    /// time).
    pub fn start(&mut self, deadline: Instant, period: Option<Duration>) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.timers.insert(
            id,
            HostTimer {
                id,
                deadline,
                period,
                armed: true,
                fired: 0,
                last_lateness: Duration::ZERO,
            },
        );
        id
    }

    /// Cancel a timer.  Returns `true` when the timer was still armed (the
    /// cancel won the race); `false` when it had already fired or was never
    /// armed (the fire won the race).
    pub fn cancel(&mut self, id: u64) -> Result<bool, UmdfError> {
        let timer = self.timers.get_mut(&id).ok_or(UmdfError::InvalidHandle)?;
        let was_armed = timer.armed;
        timer.armed = false;
        Ok(was_armed)
    }

    /// Fire every armed timer whose deadline is `<= now`, in deadline order.
    /// Overdue timers report exact lateness (`now - deadline`).
    pub fn pump(&mut self, now: Instant) -> Vec<TimerFired> {
        let due = self
            .timers
            .values()
            .filter(|timer| timer.armed && timer.deadline <= now)
            .map(|timer| (timer.id, timer.deadline, timer.period))
            .collect::<Vec<_>>();
        let mut fired = Vec::new();
        for (id, deadline, period) in due {
            // The `due` snapshot was taken from this map in the same pass
            // and nothing cancels timers between the snapshot and here.
            let timer = self.timers.get_mut(&id).expect("timer from snapshot");
            let lateness = now.saturating_duration_since(deadline);
            timer.fired += 1;
            timer.last_lateness = lateness;
            self.total_fires += 1;
            match period {
                Some(period) if !period.is_zero() => {
                    timer.deadline += period;
                    // Overdue periodic timers stay armed; the next pump fires
                    // them again and reports the further lateness.
                }
                _ => timer.armed = false,
            }
            fired.push(TimerFired { id, lateness });
        }
        fired
    }

    pub fn is_armed(&self, id: u64) -> bool {
        self.timers.get(&id).is_some_and(|timer| timer.armed)
    }

    pub fn fire_count(&self, id: u64) -> u64 {
        self.timers.get(&id).map_or(0, |timer| timer.fired)
    }

    pub fn last_lateness(&self, id: u64) -> Option<Duration> {
        self.timers
            .get(&id)
            .filter(|timer| timer.fired > 0)
            .map(|timer| timer.last_lateness)
    }

    pub fn total_fires(&self) -> u64 {
        self.total_fires
    }

    pub fn len(&self) -> usize {
        self.timers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.timers.is_empty()
    }
}

/// One registered asynchronous work item (KMDF `WDFWORKITEM` analogue).
struct WorkItemState {
    group: Option<u64>,
    queued: bool,
    runs: u64,
}

/// Asynchronous work-item queue with serialization ordering guarantees.
///
/// The queue drains in strict FIFO order, so work within a serialization
/// group always executes in enqueue order (the KMDF automatic-serialization
/// ordering guarantee).  Enqueuing an item that is already queued fails with
/// `InvalidState` exactly like `WdfWorkItemEnqueue` on an outstanding item,
/// which also makes same-group re-enqueue from inside a callback observable
/// as a rejected transition instead of silent reordering.
#[derive(Default)]
pub struct WorkQueue {
    next_id: u64,
    items: BTreeMap<u64, WorkItemState>,
    queue: VecDeque<u64>,
    executed: VecDeque<u64>,
    executed_count: u64,
    max_depth: usize,
}

impl WorkQueue {
    pub fn new(max_depth: usize) -> Result<Self, UmdfError> {
        if max_depth == 0 {
            return Err(UmdfError::InvalidArgument);
        }
        Ok(Self {
            max_depth,
            ..Self::default()
        })
    }

    /// Register a work item; `group` is its serialization group.
    pub fn create_item(&mut self, group: Option<u64>) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.items.insert(
            id,
            WorkItemState {
                group,
                queued: false,
                runs: 0,
            },
        );
        id
    }

    /// Enqueue a registered item.  Rejected when the item is already queued
    /// (`InvalidState`) or the queue is at capacity (`MessageQueueFull`).
    pub fn enqueue(&mut self, item: u64) -> Result<(), UmdfError> {
        let state = self.items.get_mut(&item).ok_or(UmdfError::InvalidHandle)?;
        if state.queued {
            return Err(UmdfError::InvalidState);
        }
        if self.queue.len() >= self.max_depth {
            return Err(UmdfError::MessageQueueFull);
        }
        state.queued = true;
        self.queue.push_back(item);
        Ok(())
    }

    /// Execute the next queued item in FIFO order; returns its id, or `None`
    /// when the queue is empty.
    pub fn run_one(&mut self) -> Option<u64> {
        let item = self.queue.pop_front()?;
        let state = self
            .items
            .get_mut(&item)
            .expect("queued item is registered");
        state.queued = false;
        state.runs += 1;
        self.executed.push_back(item);
        self.executed_count += 1;
        Some(item)
    }

    /// Drain up to `budget` items; returns the executed ids in execution
    /// order.
    pub fn drain(&mut self, budget: usize) -> Vec<u64> {
        let mut done = Vec::new();
        for _ in 0..budget {
            match self.run_one() {
                Some(id) => done.push(id),
                None => break,
            }
        }
        done
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    pub fn is_queued(&self, item: u64) -> bool {
        self.items.get(&item).is_some_and(|state| state.queued)
    }

    /// The serialization group a work item belongs to.
    pub fn group(&self, item: u64) -> Option<Option<u64>> {
        self.items.get(&item).map(|state| state.group)
    }

    pub fn runs(&self, item: u64) -> u64 {
        self.items.get(&item).map_or(0, |state| state.runs)
    }

    pub fn executed(&self) -> impl Iterator<Item = u64> + '_ {
        self.executed.iter().copied()
    }

    pub fn executed_count(&self) -> u64 {
        self.executed_count
    }
}

/// A multi-vCPU spinlock under the island's cooperative threading model.
///
/// The host has a fixed set of vCPUs; a spinlock is owned by exactly one
/// vCPU at a time.  Acquiring a held lock from a different vCPU fails with
/// `Busy` (`STATUS_DEVICE_BUSY` / `HRESULT_FROM_WIN32(ERROR_BUSY)`) instead
/// of blocking forever — the cooperative model has no preemptive waiter to
/// make progress, so contention is reported exactly.  Releasing from a
/// non-owner is rejected, and recursive acquire from the owner is rejected
/// (KMDF spinlocks are not recursive; the real framework deadlocks, we fail
/// closed with the exact error).
#[derive(Debug, Clone)]
pub struct MultiVcpuSpinLock {
    vcpus: u32,
    owner: Option<u32>,
    contentions: u64,
    acquisitions: u64,
}

impl MultiVcpuSpinLock {
    pub fn new(vcpus: u32) -> Result<Self, UmdfError> {
        if vcpus == 0 {
            return Err(UmdfError::InvalidArgument);
        }
        Ok(Self {
            vcpus,
            owner: None,
            contentions: 0,
            acquisitions: 0,
        })
    }

    fn check_vcpu(&self, vcpu: u32) -> Result<(), UmdfError> {
        if vcpu >= self.vcpus {
            return Err(UmdfError::InvalidArgument);
        }
        Ok(())
    }

    /// Try to acquire the lock for `vcpu`.
    pub fn acquire(&mut self, vcpu: u32) -> Result<(), UmdfError> {
        self.check_vcpu(vcpu)?;
        match self.owner {
            None => {
                self.owner = Some(vcpu);
                self.acquisitions += 1;
                Ok(())
            }
            Some(owner) if owner == vcpu => Err(UmdfError::InvalidState),
            Some(_) => {
                self.contentions += 1;
                Err(UmdfError::Busy)
            }
        }
    }

    /// Release the lock; only the owning vCPU may release it.
    pub fn release(&mut self, vcpu: u32) -> Result<(), UmdfError> {
        self.check_vcpu(vcpu)?;
        if self.owner != Some(vcpu) {
            return Err(UmdfError::InvalidState);
        }
        self.owner = None;
        Ok(())
    }

    pub fn owner(&self) -> Option<u32> {
        self.owner
    }

    pub fn contentions(&self) -> u64 {
        self.contentions
    }

    pub fn acquisitions(&self) -> u64 {
        self.acquisitions
    }
}

/// Why a host was restarted by the watchdog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartRecord {
    pub host: HostId,
    pub previous_process_id: u32,
    pub new_process_id: u32,
    pub generation: u64,
    /// Exact NTSTATUS the crashed host reported before the restart.
    pub crash_status: NtStatus,
}

/// Process-lifecycle watchdog over a set of UMDF hosts.
///
/// A crashed host is restarted with a fresh process id and a bumped
/// generation; the exact crash status (`STATUS_PROCESS_IS_TERMINATING`) is
/// preserved in the restart record.  Every other host's state — devices,
/// messages, queue — is untouched by another host's crash or restart.
pub struct HostSupervisor {
    hosts: BTreeMap<HostId, DriverHost>,
    restarts: Vec<RestartRecord>,
    next_generation: BTreeMap<HostId, u64>,
    next_process_id: u32,
    max_restarts_per_host: usize,
}

impl HostSupervisor {
    pub fn new(max_restarts_per_host: usize) -> Result<Self, UmdfError> {
        if max_restarts_per_host == 0 {
            return Err(UmdfError::InvalidArgument);
        }
        Ok(Self {
            hosts: BTreeMap::new(),
            restarts: Vec::new(),
            next_generation: BTreeMap::new(),
            next_process_id: 1,
            max_restarts_per_host,
        })
    }

    /// Insert a host under its id; duplicate ids are rejected.
    pub fn add_host(&mut self, host: DriverHost) -> Result<(), UmdfError> {
        let id = host.process().host;
        if self.hosts.contains_key(&id) {
            return Err(UmdfError::InvalidState);
        }
        self.hosts.insert(id, host);
        Ok(())
    }

    pub fn host(&self, id: HostId) -> Option<&DriverHost> {
        self.hosts.get(&id)
    }

    pub fn host_mut(&mut self, id: HostId) -> Option<&mut DriverHost> {
        self.hosts.get_mut(&id)
    }

    pub fn restarts(&self) -> &[RestartRecord] {
        &self.restarts
    }

    /// Restart every crashed host: the crashed host object is replaced by a
    /// fresh `Created` host with a new process id and generation+1, and the
    /// exact crash status is recorded.  Hosts that have already used their
    /// restart budget stay crashed.  Returns the restart records produced by
    /// this pass.
    pub fn poll(&mut self) -> Vec<RestartRecord> {
        let crashed = self
            .hosts
            .iter()
            .filter_map(|(id, host)| (host.lifetime() == HostLifetime::Crashed).then_some(*id))
            .collect::<Vec<_>>();
        let mut produced = Vec::new();
        for id in crashed {
            let prior_restarts = self
                .restarts
                .iter()
                .filter(|record| record.host == id)
                .count();
            if prior_restarts >= self.max_restarts_per_host {
                continue;
            }
            let old = self
                .hosts
                .remove(&id)
                .expect("crashed id came from the map");
            let crash_status = old
                .crash_reason()
                .map_or(STATUS_PROCESS_IS_TERMINATING, |reason| match reason {
                    CrashReason::CallbackError(error) => error.ntstatus(),
                    CrashReason::CallbackPanic | CrashReason::InitializationFailure(_) => {
                        STATUS_PROCESS_IS_TERMINATING
                    }
                });
            let generation = {
                let entry = self.next_generation.entry(id).or_insert(1);
                *entry += 1;
                *entry
            };
            let new_process_id = self.next_process_id;
            self.next_process_id += 1;
            let mut fresh = DriverHost::new(id, new_process_id, HostConfig::default())
                .expect("supervisor restart uses a valid default config");
            fresh.context.generation = generation;
            fresh
                .events
                .push_back(HostEvent::HostRestarted(id, generation));
            self.hosts.insert(id, fresh);
            let record = RestartRecord {
                host: id,
                previous_process_id: old.process().process_id,
                new_process_id,
                generation,
                crash_status,
            };
            self.restarts.push(record.clone());
            produced.push(record);
        }
        produced
    }

    /// True when the host has exhausted its restart budget and remains
    /// crashed permanently.
    pub fn permanently_crashed(&self, id: HostId) -> bool {
        let Some(host) = self.hosts.get(&id) else {
            return false;
        };
        if host.lifetime() != HostLifetime::Crashed {
            return false;
        }
        self.restarts
            .iter()
            .filter(|record| record.host == id)
            .count()
            >= self.max_restarts_per_host
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
    /// A wall-clock timer fired; carries the exact lateness (`now - due`).
    TimerFired(u64, Duration),
    /// A queued work item finished executing (FIFO order observable).
    WorkExecuted(u64),
    /// The supervisor restarted a crashed host with a new generation.
    HostRestarted(HostId, u64),
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
    timers: TimerPump,
    work: WorkQueue,
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
            timers: TimerPump::new(),
            work: WorkQueue::new(64).expect("fixed work-queue depth is non-zero"),
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

    /// Arm a host timer on the wall-clock pump.  Only a running host may arm
    /// timers.
    pub fn start_timer(
        &mut self,
        deadline: Instant,
        period: Option<Duration>,
    ) -> Result<u64, UmdfError> {
        self.require_running()?;
        Ok(self.timers.start(deadline, period))
    }

    /// Cancel a host timer; `false` means the timer already fired (the fire
    /// won the race against the cancel).
    pub fn cancel_timer(&mut self, id: u64) -> Result<bool, UmdfError> {
        self.require_running()?;
        self.timers.cancel(id)
    }

    /// Fire every timer due at `now` on this host, recording
    /// [`HostEvent::TimerFired`] with the exact lateness for each.
    pub fn pump_timers(&mut self, now: Instant) -> Result<Vec<TimerFired>, UmdfError> {
        self.require_running()?;
        let fired = self.timers.pump(now);
        for record in &fired {
            self.events
                .push_back(HostEvent::TimerFired(record.id, record.lateness));
        }
        Ok(fired)
    }

    /// Register a host work item; `group` is the serialization group
    /// (KMDF automatic-serialization analogue).
    pub fn create_work_item(&mut self, group: Option<u64>) -> Result<u64, UmdfError> {
        self.require_running()?;
        Ok(self.work.create_item(group))
    }

    /// Enqueue a registered work item; re-enqueue while queued is rejected
    /// exactly like `WdfWorkItemEnqueue` on an outstanding item.
    pub fn enqueue_work(&mut self, item: u64) -> Result<(), UmdfError> {
        self.require_running()?;
        self.work.enqueue(item)
    }

    /// Drain up to `budget` runnable work items, recording
    /// [`HostEvent::WorkExecuted`] in execution order.
    pub fn drain_work(&mut self, budget: usize) -> Result<Vec<u64>, UmdfError> {
        self.require_running()?;
        let executed = self.work.drain(budget);
        for id in &executed {
            self.events.push_back(HostEvent::WorkExecuted(*id));
        }
        Ok(executed)
    }

    /// The host's wall-clock timer pump (inspection).
    pub fn timers(&self) -> &TimerPump {
        &self.timers
    }

    /// The host's asynchronous work queue (inspection).
    pub fn work_queue(&self) -> &WorkQueue {
        &self.work
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

    #[test]
    fn timer_pump_zero_due_fires_immediately_and_overdue_reports_exact_lateness() {
        let mut pump = TimerPump::new();
        let start = Instant::now();
        let base = start + Duration::from_millis(100);
        let zero = pump.start(base, None);
        let late = pump.start(base + Duration::from_millis(10), None);
        // Before either deadline: nothing fires.
        assert_eq!(pump.pump(start), Vec::new());
        // Zero-due fires on the pump at its deadline with zero lateness.
        assert_eq!(
            pump.pump(base),
            vec![TimerFired {
                id: zero,
                lateness: Duration::ZERO
            }]
        );
        assert!(!pump.is_armed(zero));
        // Overdue timer reports the exact lateness (now - deadline).
        let now = base + Duration::from_millis(25);
        assert_eq!(
            pump.pump(now),
            vec![TimerFired {
                id: late,
                lateness: Duration::from_millis(15)
            }]
        );
        assert_eq!(
            pump.last_lateness(late),
            Some(Duration::from_millis(15)),
            "overdue lateness is exact"
        );
        assert_eq!(pump.total_fires(), 2);
        assert!(
            !pump.is_empty(),
            "fired timers stay registered for inspection"
        );
        assert_eq!(pump.len(), 2, "both timers remain in the pump");
        assert_eq!(
            pump.cancel(zero).expect("cancel fired timer"),
            false,
            "cancelling an already-fired timer loses the race"
        );
        assert_eq!(
            pump.cancel(99).expect_err("unknown timer"),
            UmdfError::InvalidHandle
        );
        assert_eq!(
            UmdfError::InvalidHandle.hresult(),
            STATUS_INVALID_HANDLE,
            "timer handle errors keep the exact NTSTATUS"
        );
    }

    #[test]
    fn timer_cancel_races_due_timer_and_periodic_overdue_rearms() {
        let mut pump = TimerPump::new();
        let base = Instant::now();
        let armed = pump.start(base + Duration::from_millis(5), None);
        let raced = pump.start(base + Duration::from_millis(5), None);
        // Cancel wins the race for one timer before the deadline.
        assert_eq!(
            pump.cancel(armed).expect("cancel armed"),
            true,
            "cancel before the deadline wins"
        );
        assert_eq!(
            pump.pump(base + Duration::from_millis(5)),
            vec![TimerFired {
                id: raced,
                lateness: Duration::ZERO
            }]
        );
        // Cancel after the fire loses the race.
        assert_eq!(
            pump.cancel(raced).expect("cancel after fire"),
            false,
            "cancel after the fire loses"
        );

        // Periodic timer re-arms and keeps firing with growing lateness when
        // the pump falls behind.
        let periodic = pump.start(
            base + Duration::from_millis(10),
            Some(Duration::from_millis(10)),
        );
        let first = pump.pump(base + Duration::from_millis(12));
        assert_eq!(
            first,
            vec![TimerFired {
                id: periodic,
                lateness: Duration::from_millis(2)
            }]
        );
        assert!(pump.is_armed(periodic), "periodic timer re-arms");
        let second = pump.pump(base + Duration::from_millis(31));
        assert_eq!(
            second,
            vec![TimerFired {
                id: periodic,
                lateness: Duration::from_millis(11)
            }],
            "overdue periodic fire reports lateness past the re-armed deadline"
        );
        assert_eq!(pump.fire_count(periodic), 2);
    }

    #[test]
    fn work_queue_serialization_preserves_group_order_and_rejects_overfill() {
        let mut queue = WorkQueue::new(3).expect("queue");
        assert_eq!(
            WorkQueue::new(0).err(),
            Some(UmdfError::InvalidArgument),
            "zero depth is rejected exactly"
        );
        let a1 = queue.create_item(Some(1));
        let b1 = queue.create_item(Some(2));
        let a2 = queue.create_item(Some(1));
        assert_eq!(queue.group(a1), Some(Some(1)));
        assert_eq!(queue.group(b1), Some(Some(2)));
        assert_eq!(queue.group(999), None, "unknown item has no group");
        queue.enqueue(a1).expect("a1");
        queue.enqueue(b1).expect("b1");
        queue.enqueue(a2).expect("a2");
        assert_eq!(
            queue.enqueue(a1),
            Err(UmdfError::InvalidState),
            "re-enqueue while queued is rejected exactly like KMDF"
        );
        assert_eq!(
            UmdfError::InvalidState.ntstatus(),
            STATUS_INVALID_DEVICE_STATE,
            "double enqueue keeps the exact NTSTATUS"
        );
        let unregistered = queue.create_item(None) + 100;
        assert_eq!(
            queue.enqueue(unregistered),
            Err(UmdfError::InvalidHandle),
            "unknown work item is rejected"
        );
        assert_eq!(
            queue.run_one(),
            Some(a1),
            "FIFO executes the oldest queued item"
        );
        assert!(!queue.is_queued(a1));
        queue.enqueue(a1).expect("re-enqueue after run is allowed");
        let overflow = queue.create_item(None);
        assert_eq!(
            queue.enqueue(overflow),
            Err(UmdfError::MessageQueueFull),
            "queue overfill is rejected exactly"
        );
        assert_eq!(
            UmdfError::MessageQueueFull.hresult(),
            E_OUTOFMEMORY,
            "overfill maps to E_OUTOFMEMORY"
        );
        let rest = queue.drain(8);
        assert_eq!(
            rest,
            vec![b1, a2, a1],
            "FIFO overall; original group-1 order a1 before a2 preserved"
        );
        assert_eq!(queue.pending(), 0);
        assert_eq!(queue.runs(a1), 2, "a1 ran once, then its re-enqueue ran");
        assert_eq!(queue.runs(b1), 1);
        assert_eq!(queue.executed_count(), 4);
        assert_eq!(queue.executed().collect::<Vec<_>>(), vec![a1, b1, a2, a1]);
        assert_eq!(queue.run_one(), None, "empty drain returns None");
        assert_eq!(
            queue.group(overflow),
            Some(None),
            "ungrouped item reports no serialization group"
        );
    }

    #[test]
    fn work_queue_double_enqueue_race_is_invalid_state() {
        let mut queue = WorkQueue::new(8).expect("queue");
        let item = queue.create_item(Some(7));
        assert!(!queue.is_queued(item));
        queue.enqueue(item).expect("first enqueue");
        assert!(queue.is_queued(item));
        assert_eq!(
            queue.enqueue(item),
            Err(UmdfError::InvalidState),
            "double enqueue is a rejected transition"
        );
        assert_eq!(queue.drain(1), vec![item]);
        assert!(!queue.is_queued(item), "item leaves the queue when run");
        assert_eq!(queue.runs(item), 1);
        queue.enqueue(item).expect("re-enqueue after run");
        assert_eq!(queue.drain(1), vec![item]);
        assert_eq!(queue.runs(item), 2);
        assert_eq!(
            queue.run_one(),
            None,
            "drained queue reports no runnable work"
        );
    }

    #[test]
    fn multi_vcpu_spinlock_contention_is_busy_and_releases_reject_non_owner() {
        let mut lock = MultiVcpuSpinLock::new(2).expect("lock");
        assert_eq!(
            MultiVcpuSpinLock::new(0).expect_err("zero vcpus"),
            UmdfError::InvalidArgument
        );
        lock.acquire(0).expect("vcpu0 acquires");
        assert_eq!(lock.owner(), Some(0));
        assert_eq!(
            lock.acquire(1).expect_err("contention"),
            UmdfError::Busy,
            "contention from another vCPU is Busy, not a hang"
        );
        assert_eq!(lock.contentions(), 1);
        assert_eq!(
            UmdfError::Busy.hresult(),
            HRESULT_FROM_WIN32_ERROR_BUSY,
            "Busy maps to HRESULT_FROM_WIN32(ERROR_BUSY)"
        );
        assert_eq!(
            UmdfError::Busy.ntstatus(),
            STATUS_DEVICE_BUSY,
            "Busy maps to STATUS_DEVICE_BUSY"
        );
        assert_eq!(
            lock.acquire(0).expect_err("recursive acquire"),
            UmdfError::InvalidState,
            "owner recursion is rejected (real KMDF deadlocks)"
        );
        assert_eq!(
            lock.release(1).expect_err("non-owner release"),
            UmdfError::InvalidState
        );
        lock.release(0).expect("owner releases");
        assert_eq!(lock.owner(), None);
        lock.acquire(1).expect("vcpu1 acquires after release");
        assert_eq!(lock.acquisitions(), 2);
        assert_eq!(
            lock.acquire(9).expect_err("out-of-range vcpu"),
            UmdfError::InvalidArgument
        );
        assert_eq!(
            lock.release(9).expect_err("out-of-range release"),
            UmdfError::InvalidArgument
        );
    }

    #[test]
    fn watchdog_restarts_crashed_host_with_exact_status_and_preserves_others() {
        let mut supervisor = HostSupervisor::new(2).expect("supervisor");
        assert_eq!(
            HostSupervisor::new(0).err(),
            Some(UmdfError::InvalidArgument),
            "zero restart budget is rejected exactly"
        );
        let mut crashed = initialized_host(91);
        let device = crashed
            .add_device("root\\watchdog", Vec::new())
            .expect("device");
        crashed
            .submit_message(device, HostMessageKind::Cleanup)
            .expect("queue");
        crashed
            .crash(CrashReason::CallbackError(UmdfError::NotSupported))
            .expect_err("crash");
        let mut healthy = initialized_host(92);
        let healthy_device = healthy
            .add_device("root\\healthy-watch", Vec::new())
            .expect("healthy device");
        healthy
            .submit_message(healthy_device, HostMessageKind::Cleanup)
            .expect("healthy queue");
        supervisor.add_host(crashed).expect("add crashed");
        supervisor.add_host(healthy).expect("add healthy");
        assert_eq!(
            supervisor
                .add_host(initialized_host(91))
                .expect_err("duplicate host id"),
            UmdfError::InvalidState
        );

        let first = supervisor.poll();
        assert_eq!(first.len(), 1, "only the crashed host restarts");
        assert_eq!(first[0].host, HostId(91));
        assert_eq!(
            first[0].crash_status,
            UmdfError::NotSupported.ntstatus(),
            "restart records the exact crash NTSTATUS"
        );
        assert_eq!(first[0].generation, 2);
        assert_ne!(first[0].new_process_id, first[0].previous_process_id);
        let restarted = supervisor.host(HostId(91)).expect("restarted host");
        assert_eq!(restarted.lifetime(), HostLifetime::Created);
        assert_eq!(restarted.context().generation, 2);
        // The healthy host is untouched: device and queued message intact.
        let healthy = supervisor.host(HostId(92)).expect("healthy host");
        assert_eq!(healthy.lifetime(), HostLifetime::Running);
        assert_eq!(healthy.device_count(), 1);
        assert_eq!(healthy.queued_messages(), 1);

        // Second crash consumes the budget; the third poll leaves it crashed.
        let again = supervisor.host_mut(HostId(91)).expect("host");
        again
            .register_driver(
                Box::new(NoopEntry {
                    initialize_result: Ok(()),
                    deinitialized: 0,
                }),
                Box::new(NoopFactory { fail: false }),
            )
            .expect("re-register");
        again.initialize().expect("re-initialize");
        again.crash(CrashReason::CallbackPanic).expect_err("crash");
        let second = supervisor.poll();
        assert_eq!(second.len(), 1);
        assert_eq!(
            second[0].crash_status, STATUS_PROCESS_IS_TERMINATING,
            "panic crash restarts with STATUS_PROCESS_IS_TERMINATING"
        );
        let again = supervisor.host_mut(HostId(91)).expect("host");
        again.crash(CrashReason::CallbackPanic).expect_err("crash");
        let third = supervisor.poll();
        assert!(
            third.is_empty(),
            "restart budget exhausted: host stays crashed"
        );
        assert!(supervisor.permanently_crashed(HostId(91)));
        assert!(!supervisor.permanently_crashed(HostId(92)));
        assert!(
            !supervisor.permanently_crashed(HostId(777)),
            "an unknown host id is never permanently crashed"
        );
        assert_eq!(supervisor.restarts().len(), 2);
        let healthy = supervisor.host(HostId(92)).expect("healthy host");
        assert_eq!(healthy.lifetime(), HostLifetime::Running);
    }

    #[test]
    fn host_timer_and_work_facilities_reject_stopped_and_crashed_hosts() {
        let mut host = initialized_host(101);
        let now = Instant::now();
        let timer = host
            .start_timer(now, None)
            .expect("arm timer on running host");
        assert_eq!(
            host.pump_timers(now).expect("pump"),
            vec![TimerFired {
                id: timer,
                lateness: Duration::ZERO
            }]
        );
        assert_eq!(host.timers().total_fires(), 1, "timers() inspects the pump");
        // Cancelling a still-armed timer wins the race.
        let armed = host
            .start_timer(now + Duration::from_secs(60), None)
            .expect("arm armed timer");
        assert_eq!(
            host.cancel_timer(armed).expect("cancel armed"),
            true,
            "cancelling an armed timer wins"
        );
        assert!(host.events().any(|event| matches!(
            event,
            HostEvent::TimerFired(id, Duration::ZERO) if *id == timer
        )));
        let work = host.create_work_item(Some(3)).expect("register work item");
        host.enqueue_work(work).expect("enqueue work");
        assert_eq!(host.drain_work(4).expect("drain"), vec![work]);
        assert_eq!(host.work_queue().runs(work), 1);
        assert!(
            host.events()
                .any(|event| *event == HostEvent::WorkExecuted(work))
        );

        host.shutdown().expect("shutdown");
        assert_eq!(
            host.start_timer(now, None).expect_err("timer after stop"),
            UmdfError::HostStopped
        );
        assert_eq!(
            host.cancel_timer(timer).expect_err("cancel after stop"),
            UmdfError::HostStopped
        );
        assert_eq!(
            host.pump_timers(now).expect_err("pump after stop"),
            UmdfError::HostStopped
        );
        assert_eq!(
            host.create_work_item(None)
                .expect_err("work item after stop"),
            UmdfError::HostStopped
        );
        assert_eq!(
            host.enqueue_work(work).expect_err("work after stop"),
            UmdfError::HostStopped
        );
        assert_eq!(
            host.drain_work(1).expect_err("drain after stop"),
            UmdfError::HostStopped
        );
        assert_eq!(
            UmdfError::HostStopped.ntstatus(),
            STATUS_INVALID_DEVICE_STATE,
            "stopped-host errors keep the exact NTSTATUS"
        );
    }
}
