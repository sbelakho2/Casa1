//! CasaK kernel I/O manager built on the NT object manager.
//!
//! This module implements the Kernel-mode I/O subset the CasaK executive
//! needs, with real state and no guest execution:
//!
//! - [`IoManager`] creates [`DriverObject`]/[`DeviceObject`] pairs whose names
//!   are registered in the object manager namespace (`\Driver\...` and
//!   `\Device\...`), maintains the driver device chain, and destroys devices
//!   through real object reference counts shared with open handles
//! - device stacks: attach/detach ordering, top-of-stack and next-lower walk
//!   helpers, per-device [`DeviceFlags`], and bounded [`DeviceExtension`]
//!   payload bytes
//! - IRPs: a real parameter block with a backing buffer, length and alignment
//!   validation, an IO_STACK_LOCATION array ordered from the bottom of the
//!   stack to the top, a FIFO pending queue per device, synchronous
//!   completion, cross-thread cancellation, and completion routines invoked
//!   from the lower stack location to the upper one with real STATUS
//!   propagation (including `STATUS_MORE_PROCESSING_REQUIRED`)
//! - I/O completion ports: bound object handles with completion keys, a real
//!   packet FIFO, blocking dequeue with timeout (std condvar), close that
//!   wakes waiters, exactly-once delivery and posted/delivered/dropped
//!   counters
//!
//! Every queue is a real FIFO, every buffer is a real heap allocation, and the
//! shared IRP core and completion ports are safe to drive from another thread.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::casak::object::{
    DevicePayload, DriverPayload, Handle, IoCompletionPayload, NtStatus, ObjectId, ObjectManager,
    ObjectPayload, ObjectType, STATUS_INVALID_ADDRESS, STATUS_INVALID_HANDLE, STATUS_NOT_FOUND,
    STATUS_SUCCESS,
};

/// A required argument was malformed (for example a non-power-of-two
/// alignment).
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as NtStatus;
/// The request is not valid for the target device or object state.
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = 0xC000_0010u32 as NtStatus;
/// A logical request length exceeds the backing buffer.
pub const STATUS_INVALID_BUFFER_SIZE: NtStatus = 0x8000_0006u32 as NtStatus;
/// A user buffer address does not satisfy the requested alignment.
pub const STATUS_DATATYPE_MISALIGNMENT: NtStatus = 0x8000_0002u32 as NtStatus;
/// The device is already part of a device stack.
pub const STATUS_DEVICE_ALREADY_ATTACHED: NtStatus = 0xC000_0100u32 as NtStatus;
/// The device is marked for deletion.
pub const STATUS_DELETE_PENDING: NtStatus = 0xC000_0056u32 as NtStatus;
/// The IRP has been queued but not yet completed.
pub const STATUS_PENDING: NtStatus = 0x0000_0103;
/// A blocking dequeue elapsed without a packet.
pub const STATUS_TIMEOUT: NtStatus = 0x0000_0102;
/// The IRP was cancelled before completion.
pub const STATUS_CANCELLED: NtStatus = 0xC000_0120u32 as NtStatus;
/// A completion routine stalled the completion walk.
pub const STATUS_MORE_PROCESSING_REQUIRED: NtStatus = 0xC000_0016u32 as NtStatus;
/// A generic failure for repeated completion attempts.
pub const STATUS_UNSUCCESSFUL: NtStatus = 0xC000_0001u32 as NtStatus;

/// Monotonic identifier of an IRP owned by the I/O manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IrpId(pub u64);

/// The major function code of an IRP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IrpMajorFunction {
    Create,
    Close,
    Read,
    Write,
    QueryInformation,
    SetInformation,
    FileSystemControl,
    DeviceControl,
    Power,
    Cleanup,
    Shutdown,
    Pnp,
}

impl IrpMajorFunction {
    /// Every major function, in declaration order.
    pub const ALL: [IrpMajorFunction; 12] = [
        IrpMajorFunction::Create,
        IrpMajorFunction::Close,
        IrpMajorFunction::Read,
        IrpMajorFunction::Write,
        IrpMajorFunction::QueryInformation,
        IrpMajorFunction::SetInformation,
        IrpMajorFunction::FileSystemControl,
        IrpMajorFunction::DeviceControl,
        IrpMajorFunction::Power,
        IrpMajorFunction::Cleanup,
        IrpMajorFunction::Shutdown,
        IrpMajorFunction::Pnp,
    ];

    /// The NT `IRP_MJ_*` code for this major function.
    pub const fn code(self) -> u8 {
        match self {
            IrpMajorFunction::Create => 0x00,
            IrpMajorFunction::Close => 0x02,
            IrpMajorFunction::Read => 0x03,
            IrpMajorFunction::Write => 0x04,
            IrpMajorFunction::QueryInformation => 0x05,
            IrpMajorFunction::SetInformation => 0x06,
            IrpMajorFunction::FileSystemControl => 0x0D,
            IrpMajorFunction::DeviceControl => 0x0E,
            IrpMajorFunction::Shutdown => 0x10,
            IrpMajorFunction::Cleanup => 0x12,
            IrpMajorFunction::Power => 0x16,
            IrpMajorFunction::Pnp => 0x1B,
        }
    }

    /// Stable name of this major function.
    pub const fn name(self) -> &'static str {
        match self {
            IrpMajorFunction::Create => "IRP_MJ_CREATE",
            IrpMajorFunction::Close => "IRP_MJ_CLOSE",
            IrpMajorFunction::Read => "IRP_MJ_READ",
            IrpMajorFunction::Write => "IRP_MJ_WRITE",
            IrpMajorFunction::QueryInformation => "IRP_MJ_QUERY_INFORMATION",
            IrpMajorFunction::SetInformation => "IRP_MJ_SET_INFORMATION",
            IrpMajorFunction::FileSystemControl => "IRP_MJ_FILE_SYSTEM_CONTROL",
            IrpMajorFunction::DeviceControl => "IRP_MJ_DEVICE_CONTROL",
            IrpMajorFunction::Power => "IRP_MJ_POWER",
            IrpMajorFunction::Cleanup => "IRP_MJ_CLEANUP",
            IrpMajorFunction::Shutdown => "IRP_MJ_SHUTDOWN",
            IrpMajorFunction::Pnp => "IRP_MJ_PNP",
        }
    }
}

impl std::fmt::Display for IrpMajorFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// `IRP_MN_START_DEVICE`.
pub const IRP_MN_START_DEVICE: u8 = 0x00;
/// `IRP_MN_STOP_DEVICE`.
pub const IRP_MN_STOP_DEVICE: u8 = 0x01;
/// `IRP_MN_REMOVE_DEVICE`.
pub const IRP_MN_REMOVE_DEVICE: u8 = 0x02;
/// `IRP_MN_QUERY_CAPABILITIES`.
pub const IRP_MN_QUERY_CAPABILITIES: u8 = 0x09;

/// Per-device `DO_*` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceFlags(u32);

impl DeviceFlags {
    /// No flags.
    pub const NONE: DeviceFlags = DeviceFlags(0);
    /// `DO_BUFFERED_IO`: I/O uses a system buffer.
    pub const BUFFERED_IO: DeviceFlags = DeviceFlags(0x0000_0004);
    /// `DO_EXCLUSIVE`: only one opener at a time.
    pub const EXCLUSIVE: DeviceFlags = DeviceFlags(0x0000_0008);
    /// `DO_DIRECT_IO`: I/O uses MDLs.
    pub const DIRECT_IO: DeviceFlags = DeviceFlags(0x0000_0010);
    /// `DO_DEVICE_INITIALIZING`: the device is still being initialized.
    pub const DEVICE_INITIALIZING: DeviceFlags = DeviceFlags(0x0000_0080);
    /// `DO_POWER_PAGABLE`: power IRPs are delivered at PASSIVE_LEVEL.
    pub const POWER_PAGABLE: DeviceFlags = DeviceFlags(0x0000_0200);
    /// `DO_POWER_INRUSH`: the device needs inrush current.
    pub const POWER_INRUSH: DeviceFlags = DeviceFlags(0x0000_0400);

    /// Raw flag bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` when every bit of `flag` is set.
    pub const fn contains(self, flag: DeviceFlags) -> bool {
        self.0 & flag.0 == flag.0
    }

    /// Returns `true` when no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Sets every bit of `flag`.
    pub fn insert(&mut self, flag: DeviceFlags) {
        self.0 |= flag.0;
    }

    /// Clears every bit of `flag`.
    pub fn remove(&mut self, flag: DeviceFlags) {
        self.0 &= !flag.0;
    }
}

impl std::ops::BitOr for DeviceFlags {
    type Output = DeviceFlags;

    fn bitor(self, rhs: DeviceFlags) -> DeviceFlags {
        DeviceFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for DeviceFlags {
    fn bitor_assign(&mut self, rhs: DeviceFlags) {
        self.0 |= rhs.0;
    }
}

/// A bounded device (or driver) extension payload of real bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceExtension {
    bytes: Vec<u8>,
}

impl DeviceExtension {
    /// An empty extension.
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// An extension backed by `bytes`.
    pub fn with_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// The raw extension bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// The extension size in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when the extension holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Replaces the extension payload.
    pub fn set_bytes(&mut self, bytes: impl Into<Vec<u8>>) {
        self.bytes = bytes.into();
    }

    /// Reads `length` bytes at `offset`. Out-of-range reads fail with
    /// [`STATUS_INVALID_ADDRESS`] against the real backing bytes.
    pub fn read(&self, offset: usize, length: usize) -> Result<&[u8], NtStatus> {
        let end = offset.checked_add(length).ok_or(STATUS_INVALID_ADDRESS)?;
        self.bytes.get(offset..end).ok_or(STATUS_INVALID_ADDRESS)
    }

    /// Writes `data` at `offset`. Out-of-range writes fail with
    /// [`STATUS_INVALID_ADDRESS`] against the real backing bytes.
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), NtStatus> {
        let end = offset
            .checked_add(data.len())
            .ok_or(STATUS_INVALID_ADDRESS)?;
        let target = self
            .bytes
            .get_mut(offset..end)
            .ok_or(STATUS_INVALID_ADDRESS)?;
        target.copy_from_slice(data);
        Ok(())
    }
}

/// The real parameter block of an IRP: major/minor codes plus a backing
/// system buffer, a logical length, and the user address/alignment used for
/// validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrpParameterBlock {
    /// Major function code.
    pub major: IrpMajorFunction,
    /// Minor function code.
    pub minor: u8,
    /// Real backing bytes for the request.
    pub system_buffer: Vec<u8>,
    /// Logical request length; must not exceed `system_buffer.len()`.
    pub length: usize,
    /// User buffer address checked for alignment (zero means "none").
    pub user_address: usize,
    /// Required alignment of `user_address` (zero means "none").
    pub required_alignment: usize,
}

impl IrpParameterBlock {
    /// Builds a parameter block with a zeroed real buffer of `length` bytes.
    pub fn new(major: IrpMajorFunction, minor: u8, length: usize) -> Self {
        Self {
            major,
            minor,
            system_buffer: vec![0u8; length],
            length,
            user_address: 0,
            required_alignment: 0,
        }
    }

    /// Replaces the backing buffer without changing the logical length.
    pub fn with_buffer(mut self, bytes: Vec<u8>) -> Self {
        self.system_buffer = bytes;
        self
    }

    /// Sets the logical length without changing the backing buffer.
    pub fn with_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    /// Sets the user address and its required alignment.
    pub fn with_user_address(mut self, address: usize, alignment: usize) -> Self {
        self.user_address = address;
        self.required_alignment = alignment;
        self
    }

    /// The real backing bytes.
    pub fn buffer(&self) -> &[u8] {
        &self.system_buffer
    }

    /// The real backing bytes, mutably.
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.system_buffer
    }

    /// Validates the argument block. A non-power-of-two alignment is
    /// [`STATUS_INVALID_PARAMETER`], an over-long request is
    /// [`STATUS_INVALID_BUFFER_SIZE`], and a misaligned user address is
    /// [`STATUS_DATATYPE_MISALIGNMENT`].
    pub fn validate(&self) -> Result<(), NtStatus> {
        if self.required_alignment != 0 && !self.required_alignment.is_power_of_two() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.length > self.system_buffer.len() {
            return Err(STATUS_INVALID_BUFFER_SIZE);
        }
        if self.user_address != 0
            && self.required_alignment > 1
            && self.user_address % self.required_alignment != 0
        {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        Ok(())
    }

    /// Bounds-checked read from the real backing buffer.
    pub fn read(&self, offset: usize, length: usize) -> Result<&[u8], NtStatus> {
        let end = offset.checked_add(length).ok_or(STATUS_INVALID_PARAMETER)?;
        if end > self.length {
            return Err(STATUS_INVALID_BUFFER_SIZE);
        }
        self.system_buffer
            .get(offset..end)
            .ok_or(STATUS_INVALID_PARAMETER)
    }

    /// Bounds-checked write into the real backing buffer.
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), NtStatus> {
        let end = offset
            .checked_add(data.len())
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if end > self.length {
            return Err(STATUS_INVALID_BUFFER_SIZE);
        }
        let target = self
            .system_buffer
            .get_mut(offset..end)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        target.copy_from_slice(data);
        Ok(())
    }
}

/// Per-stack-location parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackParameters {
    /// No parameters.
    None,
    /// Read/Write: logical length and byte offset.
    ReadWrite { length: usize, byte_offset: u64 },
    /// Device control: control code and buffer shapes.
    DeviceControl {
        io_control_code: u32,
        input_length: usize,
        output_length: usize,
        output_offset: usize,
    },
    /// Create: desired access and options.
    Create { desired_access: u32, options: u32 },
    /// Close: no parameters.
    Close,
}

/// The status a completion routine receives when the IRP completes back up
/// the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrpCompletion {
    /// The IRP being completed.
    pub irp: IrpId,
    /// The device whose stack location is completing.
    pub device: ObjectId,
    /// The running STATUS at this location.
    pub status: NtStatus,
    /// The information value of the IRP.
    pub information: usize,
}

/// A completion routine. Returning [`STATUS_MORE_PROCESSING_REQUIRED`] stops
/// the completion walk until the IRP is completed again.
pub type CompletionRoutine = Box<dyn FnMut(&IrpCompletion) -> NtStatus + Send>;

/// A read-only view of one IO_STACK_LOCATION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackLocationView {
    /// The device this location belongs to.
    pub device: ObjectId,
    /// Major function code.
    pub major: IrpMajorFunction,
    /// Minor function code.
    pub minor: u8,
    /// Location parameters.
    pub parameters: StackParameters,
    /// Whether a completion routine is installed.
    pub has_completion_routine: bool,
}

struct IoStackLocation {
    device: ObjectId,
    major: IrpMajorFunction,
    minor: u8,
    parameters: StackParameters,
    completion: Option<CompletionRoutine>,
}

impl IoStackLocation {
    fn view(&self) -> StackLocationView {
        StackLocationView {
            device: self.device,
            major: self.major,
            minor: self.minor,
            parameters: self.parameters.clone(),
            has_completion_routine: self.completion.is_some(),
        }
    }
}

struct Irp {
    parameters: IrpParameterBlock,
    stack: Vec<IoStackLocation>,
    status: NtStatus,
    information: usize,
    pending: bool,
    pending_device: Option<ObjectId>,
    cancelled: bool,
    completed: bool,
}

/// Shared IRP lifecycle state: every IRP plus one FIFO pending queue per
/// device. Clone an [`IrpCore`] to complete or cancel IRPs from another
/// thread; the inner mutex makes exactly-once completion real.
#[derive(Clone)]
pub struct IrpCore {
    state: Arc<Mutex<IrpState>>,
}

struct IrpState {
    irps: HashMap<IrpId, Irp>,
    queues: HashMap<ObjectId, VecDeque<IrpId>>,
    next_irp: u64,
    completed: u64,
    cancelled: u64,
}

impl IrpCore {
    /// Creates an empty core. IRP identifiers start at one.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(IrpState {
                irps: HashMap::new(),
                queues: HashMap::new(),
                next_irp: 1,
                completed: 0,
                cancelled: 0,
            })),
        }
    }

    fn insert(&self, parameters: IrpParameterBlock, stack: Vec<IoStackLocation>) -> IrpId {
        let mut state = self.state.lock().unwrap();
        let id = IrpId(state.next_irp);
        state.next_irp += 1;
        state.irps.insert(
            id,
            Irp {
                parameters,
                stack,
                status: STATUS_PENDING,
                information: 0,
                pending: false,
                pending_device: None,
                cancelled: false,
                completed: false,
            },
        );
        id
    }

    fn with_irp<T>(&self, irp: IrpId, read: impl FnOnce(&Irp) -> T) -> Result<T, NtStatus> {
        let state = self.state.lock().unwrap();
        let entry = state.irps.get(&irp).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(read(entry))
    }

    /// Number of live IRPs (completed IRPs are retained for inspection).
    pub fn len(&self) -> usize {
        self.state.lock().unwrap().irps.len()
    }

    /// Returns `true` when no IRP has ever been allocated.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of IRPs that reached a final status.
    pub fn completed_count(&self) -> u64 {
        self.state.lock().unwrap().completed
    }

    /// Number of IRPs completed because they were cancelled.
    pub fn cancelled_count(&self) -> u64 {
        self.state.lock().unwrap().cancelled
    }

    /// Number of IRPs currently sitting in a device pending queue.
    pub fn pending_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .queues
            .values()
            .map(VecDeque::len)
            .sum()
    }

    /// Returns `true` when `irp` exists in the core.
    pub fn contains(&self, irp: IrpId) -> bool {
        self.state.lock().unwrap().irps.contains_key(&irp)
    }

    /// Current status of an IRP.
    pub fn status(&self, irp: IrpId) -> Result<NtStatus, NtStatus> {
        self.with_irp(irp, |entry| entry.status)
    }

    /// Current information value of an IRP.
    pub fn information(&self, irp: IrpId) -> Result<usize, NtStatus> {
        self.with_irp(irp, |entry| entry.information)
    }

    /// A copy of the IRP parameter block.
    pub fn parameters(&self, irp: IrpId) -> Result<IrpParameterBlock, NtStatus> {
        self.with_irp(irp, |entry| entry.parameters.clone())
    }

    /// A view of every IO_STACK_LOCATION, ordered from the bottom of the
    /// device stack (index zero) to the top.
    pub fn stack_view(&self, irp: IrpId) -> Result<Vec<StackLocationView>, NtStatus> {
        self.with_irp(irp, |entry| {
            entry.stack.iter().map(IoStackLocation::view).collect()
        })
    }

    /// Whether the IRP is queued and waiting for completion.
    pub fn is_pending(&self, irp: IrpId) -> Result<bool, NtStatus> {
        self.with_irp(irp, |entry| entry.pending)
    }

    /// Whether the IRP reached a final status.
    pub fn is_completed(&self, irp: IrpId) -> Result<bool, NtStatus> {
        self.with_irp(irp, |entry| entry.completed)
    }

    /// Whether the IRP was completed by cancellation.
    pub fn is_cancelled(&self, irp: IrpId) -> Result<bool, NtStatus> {
        self.with_irp(irp, |entry| entry.cancelled)
    }

    /// The device whose pending queue currently holds the IRP.
    pub fn pending_device(&self, irp: IrpId) -> Result<Option<ObjectId>, NtStatus> {
        self.with_irp(irp, |entry| entry.pending_device)
    }

    /// The FIFO of pending IRPs for a device.
    pub fn pending_irps(&self, device: ObjectId) -> Vec<IrpId> {
        self.state
            .lock()
            .unwrap()
            .queues
            .get(&device)
            .map(|queue| queue.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Queues an IRP on a device FIFO and marks it pending.
    pub fn queue(&self, device: ObjectId, irp: IrpId) -> Result<(), NtStatus> {
        let mut state = self.state.lock().unwrap();
        {
            let entry = state.irps.get(&irp).ok_or(STATUS_INVALID_HANDLE)?;
            if entry.completed {
                return Err(STATUS_UNSUCCESSFUL);
            }
            if entry.pending {
                return Err(STATUS_INVALID_DEVICE_REQUEST);
            }
            if !entry.stack.iter().any(|location| location.device == device) {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }
        state.queues.entry(device).or_default().push_back(irp);
        let entry = state.irps.get_mut(&irp).ok_or(STATUS_INVALID_HANDLE)?;
        entry.pending = true;
        entry.pending_device = Some(device);
        entry.status = STATUS_PENDING;
        Ok(())
    }

    /// Completes an IRP. Removes it from its device queue, seeds the status
    /// and information, then invokes completion routines from the lowest
    /// stack location to the highest. Repeated completion fails with
    /// [`STATUS_UNSUCCESSFUL`].
    pub fn complete(
        &self,
        irp: IrpId,
        status: NtStatus,
        information: usize,
    ) -> Result<NtStatus, NtStatus> {
        let mut state = self.state.lock().unwrap();
        let queued_device = {
            let entry = state.irps.get_mut(&irp).ok_or(STATUS_INVALID_HANDLE)?;
            if entry.completed {
                return Err(STATUS_UNSUCCESSFUL);
            }
            let device = entry.pending_device.take();
            entry.pending = false;
            entry.status = status;
            entry.information = information;
            entry.cancelled = false;
            device
        };
        if let Some(device) = queued_device {
            if let Some(queue) = state.queues.get_mut(&device) {
                queue.retain(|queued| *queued != irp);
            }
        }
        match run_completion(&mut state, irp) {
            Some(final_status) => {
                state.completed += 1;
                Ok(final_status)
            }
            None => Ok(STATUS_MORE_PROCESSING_REQUIRED),
        }
    }

    /// Cancels an IRP: removes it from the device FIFO and completes it
    /// exactly once with a `STATUS_CANCELLED` seed. Cancelling a completed
    /// IRP fails with [`STATUS_UNSUCCESSFUL`].
    pub fn cancel(&self, irp: IrpId) -> Result<NtStatus, NtStatus> {
        let mut state = self.state.lock().unwrap();
        let queued_device = {
            let entry = state.irps.get_mut(&irp).ok_or(STATUS_INVALID_HANDLE)?;
            if entry.completed {
                return Err(STATUS_UNSUCCESSFUL);
            }
            let device = entry.pending_device.take();
            entry.pending = false;
            entry.cancelled = true;
            entry.status = STATUS_CANCELLED;
            device
        };
        if let Some(device) = queued_device {
            if let Some(queue) = state.queues.get_mut(&device) {
                queue.retain(|queued| *queued != irp);
            }
        }
        let final_status = match run_completion(&mut state, irp) {
            Some(status) => status,
            None => {
                if let Some(entry) = state.irps.get_mut(&irp) {
                    entry.cancelled = true;
                    entry.status = STATUS_CANCELLED;
                    entry.pending = false;
                    entry.pending_device = None;
                    entry.completed = true;
                }
                STATUS_CANCELLED
            }
        };
        state.cancelled += 1;
        state.completed += 1;
        Ok(final_status)
    }

    /// Installs a per-location completion routine.
    pub fn set_completion_routine(
        &self,
        irp: IrpId,
        device: ObjectId,
        routine: CompletionRoutine,
    ) -> Result<(), NtStatus> {
        let mut state = self.state.lock().unwrap();
        let entry = state.irps.get_mut(&irp).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.completed {
            return Err(STATUS_UNSUCCESSFUL);
        }
        let location = entry
            .stack
            .iter_mut()
            .find(|location| location.device == device)
            .ok_or(STATUS_NOT_FOUND)?;
        location.completion = Some(routine);
        Ok(())
    }

    /// Replaces the parameters of one stack location.
    pub fn set_stack_parameters(
        &self,
        irp: IrpId,
        device: ObjectId,
        parameters: StackParameters,
    ) -> Result<(), NtStatus> {
        let mut state = self.state.lock().unwrap();
        let entry = state.irps.get_mut(&irp).ok_or(STATUS_INVALID_HANDLE)?;
        let location = entry
            .stack
            .iter_mut()
            .find(|location| location.device == device)
            .ok_or(STATUS_NOT_FOUND)?;
        location.parameters = parameters;
        Ok(())
    }

    /// Cancels every queued IRP for a device, in FIFO order, returning the
    /// cancelled identifiers. Used by device deletion.
    pub fn cancel_pending_for_device(&self, device: ObjectId) -> Vec<IrpId> {
        let pending: Vec<IrpId> = {
            let mut state = self.state.lock().unwrap();
            state
                .queues
                .remove(&device)
                .map(|queue| queue.into_iter().collect())
                .unwrap_or_default()
        };
        for irp in &pending {
            let _ = self.cancel(*irp);
        }
        pending
    }
}

impl Default for IrpCore {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs the completion walk in stack order (bottom to top). Returns the final
/// status when the IRP completed, or `None` when a routine returned
/// [`STATUS_MORE_PROCESSING_REQUIRED`].
fn run_completion(state: &mut IrpState, irp: IrpId) -> Option<NtStatus> {
    let entry = state.irps.get_mut(&irp)?;
    let information = entry.information;
    let mut status = entry.status;
    let mut stalled = false;
    for location in entry.stack.iter_mut() {
        if let Some(mut routine) = location.completion.take() {
            let completion = IrpCompletion {
                irp,
                device: location.device,
                status,
                information,
            };
            let next = routine(&completion);
            location.completion = Some(routine);
            status = next;
            if next == STATUS_MORE_PROCESSING_REQUIRED {
                stalled = true;
                break;
            }
        }
    }
    entry.status = status;
    if stalled {
        entry.completed = false;
        entry.pending = true;
        entry.pending_device = None;
        None
    } else {
        entry.completed = true;
        entry.pending = false;
        entry.pending_device = None;
        Some(status)
    }
}

/// A loaded driver object with its device chain and extension payload.
pub struct DriverObject {
    /// Object manager identifier.
    pub id: ObjectId,
    /// Driver name as registered under `\Driver`.
    pub name: String,
    /// Driver extension payload.
    pub extension: DeviceExtension,
    first_device: Option<ObjectId>,
    device_count: usize,
}

impl DriverObject {
    /// The most recently created device (the head of the chain).
    pub fn first_device(&self) -> Option<ObjectId> {
        self.first_device
    }

    /// Number of devices in the driver chain.
    pub fn device_count(&self) -> usize {
        self.device_count
    }
}

/// A device object with its stack links and extension payload.
pub struct DeviceObject {
    /// Object manager identifier.
    pub id: ObjectId,
    /// Device name as registered under `\Device` (if named).
    pub name: Option<String>,
    /// Owning driver object.
    pub driver: Option<ObjectId>,
    /// Device extension payload.
    pub extension: DeviceExtension,
    /// `DO_*` device flags.
    pub flags: DeviceFlags,
    /// Whether `IoDeleteDevice` marked this device deleted.
    pub deleted: bool,
    attached_device: Option<ObjectId>,
    lower_device: Option<ObjectId>,
    next_device: Option<ObjectId>,
}

impl DeviceObject {
    /// The device directly above this one in a stack.
    pub fn attached_device(&self) -> Option<ObjectId> {
        self.attached_device
    }

    /// The device directly below this one in a stack.
    pub fn lower_device(&self) -> Option<ObjectId> {
        self.lower_device
    }
}

/// Result of a synchronous IRP completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynchronousIoResult {
    /// The IRP that was allocated and completed.
    pub irp: IrpId,
    /// Final status after completion routines ran.
    pub status: NtStatus,
    /// Information value, the logical length on success and zero on failure.
    pub information: usize,
}

/// A packet delivered through an I/O completion port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionPacket {
    /// Completion key of the bound object.
    pub key: usize,
    /// Completion status.
    pub status: NtStatus,
    /// Information value (for example bytes transferred).
    pub information: usize,
    /// Optional packet payload bytes.
    pub bytes: Vec<u8>,
}

impl CompletionPacket {
    /// Builds a packet with no payload bytes.
    pub fn new(key: usize, status: NtStatus, information: usize) -> Self {
        Self {
            key,
            status,
            information,
            bytes: Vec::new(),
        }
    }

    /// Attaches payload bytes to the packet.
    pub fn with_bytes(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.bytes = bytes.into();
        self
    }
}

struct PortState {
    packets: VecDeque<CompletionPacket>,
    closed: bool,
}

struct PortInner {
    state: Mutex<PortState>,
    wake: Condvar,
    queue_depth: u32,
    posted: AtomicU64,
    delivered: AtomicU64,
    dropped: AtomicU64,
}

impl PortInner {
    fn new(queue_depth: u32) -> Self {
        Self {
            state: Mutex::new(PortState {
                packets: VecDeque::new(),
                closed: false,
            }),
            wake: Condvar::new(),
            queue_depth,
            posted: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }
}

/// A cloneable handle to an I/O completion port. Clones share the same packet
/// FIFO, counters and waiter wakeups, so a clone can block in
/// [`CompletionPort::dequeue`] while another thread posts or closes.
#[derive(Clone)]
pub struct CompletionPort {
    id: ObjectId,
    inner: Arc<PortInner>,
}

impl CompletionPort {
    /// The object manager identifier of the underlying IoCompletion object.
    pub fn id(&self) -> ObjectId {
        self.id
    }

    /// The advertised queue depth of the port.
    pub fn queue_depth(&self) -> u32 {
        self.inner.queue_depth
    }

    /// Enqueues a packet, waking one waiter. Posting to a closed port fails
    /// with [`STATUS_INVALID_HANDLE`].
    pub fn post(&self, packet: CompletionPacket) -> Result<(), NtStatus> {
        let mut state = self.inner.state.lock().unwrap();
        if state.closed {
            return Err(STATUS_INVALID_HANDLE);
        }
        state.packets.push_back(packet);
        self.inner.posted.fetch_add(1, Ordering::SeqCst);
        drop(state);
        self.inner.wake.notify_one();
        Ok(())
    }

    /// Dequeues a packet without blocking; returns `None` when empty.
    pub fn try_dequeue(&self) -> Option<CompletionPacket> {
        let mut state = self.inner.state.lock().unwrap();
        let packet = state.packets.pop_front();
        if packet.is_some() {
            self.inner.delivered.fetch_add(1, Ordering::SeqCst);
        }
        packet
    }

    /// Dequeues a packet, blocking at most `timeout`. Returns
    /// [`STATUS_TIMEOUT`] when no packet arrives in time and
    /// [`STATUS_CANCELLED`] when the port was closed.
    pub fn dequeue(&self, timeout: Duration) -> Result<CompletionPacket, NtStatus> {
        let deadline = Instant::now() + timeout;
        let mut state = self.inner.state.lock().unwrap();
        loop {
            if let Some(packet) = state.packets.pop_front() {
                self.inner.delivered.fetch_add(1, Ordering::SeqCst);
                return Ok(packet);
            }
            if state.closed {
                return Err(STATUS_CANCELLED);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(STATUS_TIMEOUT);
            }
            let (next_state, _) = self.inner.wake.wait_timeout(state, deadline - now).unwrap();
            state = next_state;
        }
    }

    /// Closes the port: queued packets are dropped and every waiter is woken.
    /// Returns how many queued packets were dropped. Closing twice drops
    /// nothing the second time.
    pub fn close(&self) -> u64 {
        let mut state = self.inner.state.lock().unwrap();
        if state.closed {
            return 0;
        }
        state.closed = true;
        let dropped = state.packets.len() as u64;
        state.packets.clear();
        self.inner.dropped.fetch_add(dropped, Ordering::SeqCst);
        drop(state);
        self.inner.wake.notify_all();
        dropped
    }

    /// Packets posted through the port.
    pub fn posted_count(&self) -> u64 {
        self.inner.posted.load(Ordering::SeqCst)
    }

    /// Packets delivered exactly once through dequeue.
    pub fn delivered_count(&self) -> u64 {
        self.inner.delivered.load(Ordering::SeqCst)
    }

    /// Packets dropped by closing the port.
    pub fn dropped_count(&self) -> u64 {
        self.inner.dropped.load(Ordering::SeqCst)
    }

    /// Packets currently waiting in the FIFO.
    pub fn pending_count(&self) -> usize {
        self.inner.state.lock().unwrap().packets.len()
    }

    /// Whether the port has been closed.
    pub fn is_closed(&self) -> bool {
        self.inner.state.lock().unwrap().closed
    }
}

impl std::fmt::Debug for CompletionPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionPort")
            .field("id", &self.id)
            .field("queue_depth", &self.queue_depth())
            .field("posted", &self.posted_count())
            .field("delivered", &self.delivered_count())
            .field("dropped", &self.dropped_count())
            .field("pending", &self.pending_count())
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// The kernel I/O manager: driver/device objects, device stacks, IRPs and
/// I/O completion ports on top of one object manager.
pub struct IoManager {
    objects: ObjectManager,
    drivers: HashMap<ObjectId, DriverObject>,
    devices: HashMap<ObjectId, DeviceObject>,
    irps: IrpCore,
    ports: HashMap<ObjectId, CompletionPort>,
    bindings: HashMap<(u32, Handle), (ObjectId, usize)>,
}

impl IoManager {
    /// Creates an empty I/O manager with its own object manager.
    pub fn new() -> Self {
        Self {
            objects: ObjectManager::new(),
            drivers: HashMap::new(),
            devices: HashMap::new(),
            irps: IrpCore::new(),
            ports: HashMap::new(),
            bindings: HashMap::new(),
        }
    }

    /// The underlying object manager.
    pub fn objects(&self) -> &ObjectManager {
        &self.objects
    }

    /// The underlying object manager, mutably (handles, namespace queries).
    pub fn objects_mut(&mut self) -> &mut ObjectManager {
        &mut self.objects
    }

    /// The shareable IRP core. Clones can complete or cancel IRPs from
    /// another thread.
    pub fn irp_core(&self) -> IrpCore {
        self.irps.clone()
    }

    /// Number of registered drivers.
    pub fn driver_count(&self) -> usize {
        self.drivers.len()
    }

    /// Number of registered devices, including deleted ones with live
    /// references.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Creates a driver object named `\Driver\<name>` with a real object
    /// manager namespace entry.
    pub fn create_driver(
        &mut self,
        name: &str,
        extension: DeviceExtension,
    ) -> Result<ObjectId, NtStatus> {
        let path = format!("\\Driver\\{name}");
        let payload = ObjectPayload::Driver(DriverPayload::new(name));
        let id = self
            .objects
            .create_object(ObjectType::Driver, payload, Some(&path))?;
        self.drivers.insert(
            id,
            DriverObject {
                id,
                name: name.to_string(),
                extension,
                first_device: None,
                device_count: 0,
            },
        );
        Ok(id)
    }

    /// Looks up a driver object.
    pub fn driver(&self, driver: ObjectId) -> Result<&DriverObject, NtStatus> {
        self.drivers.get(&driver).ok_or(STATUS_INVALID_HANDLE)
    }

    /// The driver device chain, most recently created first (NT head
    /// insertion order).
    pub fn driver_devices(&self, driver: ObjectId) -> Result<Vec<ObjectId>, NtStatus> {
        let entry = self.drivers.get(&driver).ok_or(STATUS_INVALID_HANDLE)?;
        let mut devices = Vec::new();
        let mut cursor = entry.first_device;
        while let Some(device) = cursor {
            devices.push(device);
            cursor = self
                .devices
                .get(&device)
                .and_then(|entry| entry.next_device);
        }
        Ok(devices)
    }

    /// Number of devices attached to a driver.
    pub fn driver_device_count(&self, driver: ObjectId) -> Result<usize, NtStatus> {
        Ok(self.driver(driver)?.device_count())
    }

    /// Creates a device object for `driver`. Named devices are registered as
    /// `\Device\<name>`; unnamed devices only live in the driver chain.
    pub fn create_device(
        &mut self,
        driver: ObjectId,
        name: Option<&str>,
        extension: DeviceExtension,
        flags: DeviceFlags,
    ) -> Result<ObjectId, NtStatus> {
        if !self.drivers.contains_key(&driver) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let path = name.map(|name| format!("\\Device\\{name}"));
        let payload = ObjectPayload::Device(DevicePayload::new(name.unwrap_or("")));
        let id = self
            .objects
            .create_object(ObjectType::Device, payload, path.as_deref())?;
        let next_device = self
            .drivers
            .get(&driver)
            .and_then(|entry| entry.first_device);
        if let Some(entry) = self.drivers.get_mut(&driver) {
            entry.first_device = Some(id);
            entry.device_count += 1;
        }
        self.devices.insert(
            id,
            DeviceObject {
                id,
                name: name.map(str::to_string),
                driver: Some(driver),
                extension,
                flags,
                deleted: false,
                attached_device: None,
                lower_device: None,
                next_device,
            },
        );
        Ok(id)
    }

    /// Looks up a device object, including deleted devices whose last
    /// reference is still open.
    pub fn device(&self, device: ObjectId) -> Result<&DeviceObject, NtStatus> {
        self.devices.get(&device).ok_or(STATUS_INVALID_HANDLE)
    }

    /// The driver owning this device.
    pub fn device_driver(&self, device: ObjectId) -> Result<Option<ObjectId>, NtStatus> {
        Ok(self.device(device)?.driver)
    }

    /// The current `DO_*` flags of a device.
    pub fn device_flags(&self, device: ObjectId) -> Result<DeviceFlags, NtStatus> {
        Ok(self.device(device)?.flags)
    }

    /// Replaces the `DO_*` flags of a device.
    pub fn set_device_flags(
        &mut self,
        device: ObjectId,
        flags: DeviceFlags,
    ) -> Result<(), NtStatus> {
        self.devices
            .get_mut(&device)
            .ok_or(STATUS_INVALID_HANDLE)?
            .flags = flags;
        Ok(())
    }

    /// The device extension payload.
    pub fn device_extension(&self, device: ObjectId) -> Result<&DeviceExtension, NtStatus> {
        Ok(&self.device(device)?.extension)
    }

    /// Replaces the device extension payload.
    pub fn set_device_extension(
        &mut self,
        device: ObjectId,
        extension: DeviceExtension,
    ) -> Result<(), NtStatus> {
        self.devices
            .get_mut(&device)
            .ok_or(STATUS_INVALID_HANDLE)?
            .extension = extension;
        Ok(())
    }

    /// Attaches `device` directly above the top of `target`'s stack and
    /// returns the previous top device. A device already in a stack fails
    /// with [`STATUS_DEVICE_ALREADY_ATTACHED`].
    pub fn attach_device(
        &mut self,
        device: ObjectId,
        target: ObjectId,
    ) -> Result<ObjectId, NtStatus> {
        if device == target {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let top = self.top_of_stack(target)?;
        match self.devices.get(&target) {
            Some(entry) if entry.deleted => return Err(STATUS_DELETE_PENDING),
            Some(_) => {}
            None => return Err(STATUS_INVALID_HANDLE),
        }
        match self.devices.get(&device) {
            Some(entry) if entry.deleted => return Err(STATUS_DELETE_PENDING),
            Some(entry) => {
                if entry.attached_device.is_some() || entry.lower_device.is_some() {
                    return Err(STATUS_DEVICE_ALREADY_ATTACHED);
                }
            }
            None => return Err(STATUS_INVALID_HANDLE),
        }
        if let Some(entry) = self.devices.get_mut(&device) {
            entry.lower_device = Some(top);
        }
        if let Some(entry) = self.devices.get_mut(&top) {
            entry.attached_device = Some(device);
        }
        Ok(top)
    }

    /// Detaches the device directly above `target` (NT `IoDetachDevice`) and
    /// returns it. Fails with [`STATUS_INVALID_DEVICE_REQUEST`] when nothing
    /// is attached above `target`.
    pub fn detach_device(&mut self, target: ObjectId) -> Result<ObjectId, NtStatus> {
        let detached = self
            .devices
            .get(&target)
            .ok_or(STATUS_INVALID_HANDLE)?
            .attached_device
            .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
        if let Some(entry) = self.devices.get_mut(&detached) {
            entry.lower_device = None;
        }
        if let Some(entry) = self.devices.get_mut(&target) {
            entry.attached_device = None;
        }
        Ok(detached)
    }

    /// Walks `attached_device` links to the top of the stack containing
    /// `device`.
    pub fn top_of_stack(&self, device: ObjectId) -> Result<ObjectId, NtStatus> {
        let mut current = device;
        loop {
            let entry = self.devices.get(&current).ok_or(STATUS_INVALID_HANDLE)?;
            match entry.attached_device {
                Some(upper) => {
                    current = upper;
                    if current == device {
                        return Err(STATUS_INVALID_DEVICE_REQUEST);
                    }
                }
                None => return Ok(current),
            }
        }
    }

    /// Walks `lower_device` links to the bottom of the stack containing
    /// `device`.
    pub fn bottom_of_stack(&self, device: ObjectId) -> Result<ObjectId, NtStatus> {
        let mut current = device;
        loop {
            let entry = self.devices.get(&current).ok_or(STATUS_INVALID_HANDLE)?;
            match entry.lower_device {
                Some(lower) => {
                    current = lower;
                    if current == device {
                        return Err(STATUS_INVALID_DEVICE_REQUEST);
                    }
                }
                None => return Ok(current),
            }
        }
    }

    /// The next lower device (the one this device is attached to).
    pub fn next_lower_device(&self, device: ObjectId) -> Result<Option<ObjectId>, NtStatus> {
        Ok(self.device(device)?.lower_device)
    }

    /// The next device attached above this one.
    pub fn next_attached_device(&self, device: ObjectId) -> Result<Option<ObjectId>, NtStatus> {
        Ok(self.device(device)?.attached_device)
    }

    /// The stack locations for an IRP sent to `target`, ordered from the
    /// bottom of the stack (index zero) to `target`.
    pub fn stack_devices(&self, device: ObjectId) -> Result<Vec<ObjectId>, NtStatus> {
        let mut chain = vec![device];
        let mut current = device;
        loop {
            let lower = self.device(current)?.lower_device;
            match lower {
                Some(lower_device) => {
                    chain.push(lower_device);
                    current = lower_device;
                    if chain.len() > self.devices.len() {
                        return Err(STATUS_INVALID_DEVICE_REQUEST);
                    }
                }
                None => break,
            }
        }
        chain.reverse();
        Ok(chain)
    }

    /// Removes `device` from any stack it is part of, reconnecting the
    /// devices around it.
    fn unlink_from_stack(&mut self, device: ObjectId) {
        let (upper, lower) = match self.devices.get(&device) {
            Some(entry) => (entry.attached_device, entry.lower_device),
            None => return,
        };
        if let Some(upper_device) = upper {
            if let Some(entry) = self.devices.get_mut(&upper_device) {
                entry.lower_device = lower;
            }
        }
        if let Some(lower_device) = lower {
            if let Some(entry) = self.devices.get_mut(&lower_device) {
                entry.attached_device = upper;
            }
        }
        if let Some(entry) = self.devices.get_mut(&device) {
            entry.attached_device = None;
            entry.lower_device = None;
        }
    }

    /// Deletes a device: detaches it from its stack, unlinks it from the
    /// driver chain, cancels its pending IRPs, marks it deleted and drops the
    /// creator reference. The object is destroyed when the last open handle
    /// closes.
    pub fn delete_device(&mut self, device: ObjectId) -> Result<(), NtStatus> {
        let (driver, next_device) = {
            let entry = self.devices.get(&device).ok_or(STATUS_INVALID_HANDLE)?;
            if entry.deleted {
                return Err(STATUS_DELETE_PENDING);
            }
            (entry.driver, entry.next_device)
        };
        self.unlink_from_stack(device);
        if let Some(driver_id) = driver {
            if let Some(entry) = self.drivers.get_mut(&driver_id) {
                if entry.first_device == Some(device) {
                    entry.first_device = next_device;
                } else {
                    let mut cursor = entry.first_device;
                    while let Some(current) = cursor {
                        let next = self
                            .devices
                            .get(&current)
                            .and_then(|device| device.next_device);
                        if next == Some(device) {
                            if let Some(previous) = self.devices.get_mut(&current) {
                                previous.next_device = next_device;
                            }
                            break;
                        }
                        cursor = next;
                    }
                }
                entry.device_count = entry.device_count.saturating_sub(1);
            }
        }
        if let Some(entry) = self.devices.get_mut(&device) {
            entry.deleted = true;
            entry.next_device = None;
        }
        self.irps.cancel_pending_for_device(device);
        self.objects.release_object(device)?;
        Ok(())
    }

    /// Allocates an IRP for `target`: the stack location array covers the
    /// devices from the bottom of `target`'s stack up to `target`, ordered
    /// bottom-first. Read/Write locations receive the logical length.
    pub fn allocate_irp(
        &self,
        target: ObjectId,
        parameters: IrpParameterBlock,
    ) -> Result<IrpId, NtStatus> {
        match self.devices.get(&target) {
            Some(entry) if entry.deleted => return Err(STATUS_DELETE_PENDING),
            Some(_) => {}
            None => return Err(STATUS_INVALID_HANDLE),
        }
        let chain = self.stack_devices(target)?;
        let major = parameters.major;
        let minor = parameters.minor;
        let length = parameters.length;
        let stack = chain
            .into_iter()
            .map(|device| IoStackLocation {
                device,
                major,
                minor,
                parameters: match major {
                    IrpMajorFunction::Read | IrpMajorFunction::Write => {
                        StackParameters::ReadWrite {
                            length,
                            byte_offset: 0,
                        }
                    }
                    IrpMajorFunction::DeviceControl => StackParameters::DeviceControl {
                        io_control_code: 0,
                        input_length: length,
                        output_length: 0,
                        output_offset: 0,
                    },
                    IrpMajorFunction::Create => StackParameters::Create {
                        desired_access: 0,
                        options: 0,
                    },
                    IrpMajorFunction::Close => StackParameters::Close,
                    _ => StackParameters::None,
                },
                completion: None,
            })
            .collect();
        Ok(self.irps.insert(parameters, stack))
    }

    /// Queues an IRP on the device FIFO.
    pub fn queue_irp(&self, device: ObjectId, irp: IrpId) -> Result<(), NtStatus> {
        match self.devices.get(&device) {
            Some(entry) if entry.deleted => return Err(STATUS_DELETE_PENDING),
            Some(_) => {}
            None => return Err(STATUS_INVALID_HANDLE),
        }
        self.irps.queue(device, irp)
    }

    /// The FIFO of pending IRPs for a device.
    pub fn pending_irps(&self, device: ObjectId) -> Result<Vec<IrpId>, NtStatus> {
        if !self.devices.contains_key(&device) {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(self.irps.pending_irps(device))
    }

    /// Completes an IRP, running completion routines bottom-to-top.
    pub fn complete_irp(
        &self,
        irp: IrpId,
        status: NtStatus,
        information: usize,
    ) -> Result<NtStatus, NtStatus> {
        self.irps.complete(irp, status, information)
    }

    /// Cancels a pending IRP exactly once with `STATUS_CANCELLED`.
    pub fn cancel_irp(&self, irp: IrpId) -> Result<NtStatus, NtStatus> {
        self.irps.cancel(irp)
    }

    /// Installs a completion routine on the stack location of `device`.
    pub fn set_completion_routine(
        &self,
        irp: IrpId,
        device: ObjectId,
        routine: CompletionRoutine,
    ) -> Result<(), NtStatus> {
        self.irps.set_completion_routine(irp, device, routine)
    }

    /// Replaces the parameters of one stack location.
    pub fn set_stack_parameters(
        &self,
        irp: IrpId,
        device: ObjectId,
        parameters: StackParameters,
    ) -> Result<(), NtStatus> {
        self.irps.set_stack_parameters(irp, device, parameters)
    }

    /// Validates the parameter block and completes the IRP synchronously.
    /// An invalid device fails the call; an invalid parameter block completes
    /// the IRP with that status.
    pub fn send_synchronous(
        &self,
        device: ObjectId,
        parameters: IrpParameterBlock,
    ) -> Result<SynchronousIoResult, NtStatus> {
        let irp = self.allocate_irp(device, parameters)?;
        let (status, information) = {
            let entry = self.irps.parameters(irp)?;
            match entry.validate() {
                Ok(()) => (STATUS_SUCCESS, entry.length),
                Err(error) => (error, 0),
            }
        };
        let final_status = self.irps.complete(irp, status, information)?;
        Ok(SynchronousIoResult {
            irp,
            status: final_status,
            information,
        })
    }

    /// Current status of an IRP.
    pub fn irp_status(&self, irp: IrpId) -> Result<NtStatus, NtStatus> {
        self.irps.status(irp)
    }

    /// Current information value of an IRP.
    pub fn irp_information(&self, irp: IrpId) -> Result<usize, NtStatus> {
        self.irps.information(irp)
    }

    /// A copy of the IRP parameter block.
    pub fn irp_parameters(&self, irp: IrpId) -> Result<IrpParameterBlock, NtStatus> {
        self.irps.parameters(irp)
    }

    /// Views of the IRP stack locations, bottom of the stack first.
    pub fn irp_stack(&self, irp: IrpId) -> Result<Vec<StackLocationView>, NtStatus> {
        self.irps.stack_view(irp)
    }

    /// Device identifiers of the IRP stack locations, bottom first.
    pub fn irp_stack_devices(&self, irp: IrpId) -> Result<Vec<ObjectId>, NtStatus> {
        Ok(self
            .irps
            .stack_view(irp)?
            .into_iter()
            .map(|location| location.device)
            .collect())
    }

    /// Whether the IRP is queued and waiting.
    pub fn irp_is_pending(&self, irp: IrpId) -> Result<bool, NtStatus> {
        self.irps.is_pending(irp)
    }

    /// Whether the IRP reached a final status.
    pub fn irp_is_completed(&self, irp: IrpId) -> Result<bool, NtStatus> {
        self.irps.is_completed(irp)
    }

    /// Whether the IRP was completed by cancellation.
    pub fn irp_is_cancelled(&self, irp: IrpId) -> Result<bool, NtStatus> {
        self.irps.is_cancelled(irp)
    }

    /// The device whose queue currently holds the IRP.
    pub fn irp_pending_device(&self, irp: IrpId) -> Result<Option<ObjectId>, NtStatus> {
        self.irps.pending_device(irp)
    }

    /// Number of allocated IRPs.
    pub fn irp_count(&self) -> usize {
        self.irps.len()
    }

    /// Number of IRPs that reached a final status.
    pub fn completed_irp_count(&self) -> u64 {
        self.irps.completed_count()
    }

    /// Number of IRPs completed by cancellation.
    pub fn cancelled_irp_count(&self) -> u64 {
        self.irps.cancelled_count()
    }

    /// Number of IRPs currently queued on device FIFOs.
    pub fn pending_irp_count(&self) -> usize {
        self.irps.pending_count()
    }

    /// Creates an IoCompletion object (optionally named in the object
    /// namespace) and returns a cloneable port handle.
    pub fn create_completion_port(
        &mut self,
        name: Option<&str>,
        queue_depth: u32,
    ) -> Result<CompletionPort, NtStatus> {
        let payload = ObjectPayload::IoCompletion(IoCompletionPayload::new(queue_depth));
        let id = self
            .objects
            .create_object(ObjectType::IoCompletion, payload, name)?;
        let port = CompletionPort {
            id,
            inner: Arc::new(PortInner::new(queue_depth)),
        };
        self.ports.insert(id, port.clone());
        Ok(port)
    }

    /// Looks up a live completion port.
    pub fn completion_port(&self, port: ObjectId) -> Result<CompletionPort, NtStatus> {
        self.ports.get(&port).cloned().ok_or(STATUS_INVALID_HANDLE)
    }

    /// Number of live completion ports.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Binds an object handle to a completion port with a completion key.
    /// The handle is validated against the object manager.
    pub fn bind_completion_port(
        &mut self,
        port: ObjectId,
        process: u32,
        handle: Handle,
        key: usize,
    ) -> Result<(), NtStatus> {
        let entry = self.ports.get(&port).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.is_closed() {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.objects.lookup_handle(process, handle)?;
        self.bindings.insert((process, handle), (port, key));
        Ok(())
    }

    /// Removes an object handle binding, returning the port and key it had.
    pub fn unbind_completion_port(
        &mut self,
        process: u32,
        handle: Handle,
    ) -> Option<(ObjectId, usize)> {
        self.bindings.remove(&(process, handle))
    }

    /// The completion key bound to an object handle.
    pub fn bound_completion_key(&self, process: u32, handle: Handle) -> Option<usize> {
        self.bindings.get(&(process, handle)).map(|entry| entry.1)
    }

    /// The completion port bound to an object handle.
    pub fn bound_port(&self, process: u32, handle: Handle) -> Option<ObjectId> {
        self.bindings.get(&(process, handle)).map(|entry| entry.0)
    }

    /// Every object handle bound to a port, sorted by process then handle.
    pub fn port_bindings(&self, port: ObjectId) -> Vec<(u32, Handle, usize)> {
        let mut bindings: Vec<(u32, Handle, usize)> = self
            .bindings
            .iter()
            .filter(|(_, entry)| entry.0 == port)
            .map(|((process, handle), entry)| (*process, *handle, entry.1))
            .collect();
        bindings.sort_by_key(|(process, handle, _)| (*process, *handle));
        bindings
    }

    /// Posts a packet to a port.
    pub fn post_to_port(&self, port: ObjectId, packet: CompletionPacket) -> Result<(), NtStatus> {
        self.ports
            .get(&port)
            .ok_or(STATUS_INVALID_HANDLE)?
            .post(packet)
    }

    /// Closes a port: wakes waiters, drops queued packets, removes its
    /// bindings and releases the creator reference on the IoCompletion
    /// object. Returns how many packets were dropped.
    pub fn close_completion_port(&mut self, port: ObjectId) -> Result<u64, NtStatus> {
        let entry = self.ports.remove(&port).ok_or(STATUS_INVALID_HANDLE)?;
        let dropped = entry.close();
        self.bindings
            .retain(|_, (bound_port, _)| *bound_port != port);
        let _ = self.objects.release_object(port);
        Ok(dropped)
    }
}

impl Default for IoManager {
    fn default() -> Self {
        Self::new()
    }
}

// __IO_RS_CONTINUE__

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casak::object::STATUS_OBJECT_NAME_COLLISION;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Arc, Mutex};

    fn new_driver(manager: &mut IoManager, name: &str) -> ObjectId {
        manager
            .create_driver(name, DeviceExtension::new())
            .expect("create driver")
    }

    fn new_device(manager: &mut IoManager, driver: ObjectId, name: &str) -> ObjectId {
        manager
            .create_device(
                driver,
                Some(name),
                DeviceExtension::new(),
                DeviceFlags::default(),
            )
            .expect("create device")
    }

    #[test]
    fn driver_and_device_objects_register_names_and_chains() {
        let mut manager = IoManager::new();
        let driver = new_driver(&mut manager, "CasaTest");
        assert_eq!(manager.driver_count(), 1);
        assert_eq!(manager.driver(driver).unwrap().name, "CasaTest");
        assert_eq!(
            manager
                .objects()
                .query_object(driver)
                .unwrap()
                .name
                .as_deref(),
            Some("\\Driver\\CasaTest")
        );

        let first = new_device(&mut manager, driver, "First");
        let second = new_device(&mut manager, driver, "Second");
        assert_eq!(manager.device_count(), 2);
        assert_eq!(manager.driver_device_count(driver).unwrap(), 2);
        // NT head insertion: the most recently created device comes first.
        assert_eq!(manager.driver_devices(driver).unwrap(), vec![second, first]);
        assert_eq!(manager.device_driver(second).unwrap(), Some(driver));
        assert_eq!(
            manager
                .objects()
                .query_object(first)
                .unwrap()
                .name
                .as_deref(),
            Some("\\Device\\First")
        );
        assert_eq!(
            manager.objects().query_object(first).unwrap().type_name(),
            "Device"
        );
        let unnamed = manager
            .create_device(driver, None, DeviceExtension::new(), DeviceFlags::default())
            .unwrap();
        assert!(
            manager
                .objects()
                .query_object(unnamed)
                .unwrap()
                .name
                .is_none()
        );
        assert_eq!(manager.driver_device_count(driver).unwrap(), 3);
    }

    #[test]
    fn duplicate_names_and_invalid_handles_are_rejected() {
        let mut manager = IoManager::new();
        let driver = new_driver(&mut manager, "DupDrv");
        assert_eq!(
            manager.create_driver("DupDrv", DeviceExtension::new()),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        new_device(&mut manager, driver, "Dev");
        assert_eq!(
            manager.create_device(
                driver,
                Some("Dev"),
                DeviceExtension::new(),
                DeviceFlags::default()
            ),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            manager.create_device(
                ObjectId(9999),
                Some("Orphan"),
                DeviceExtension::new(),
                DeviceFlags::default()
            ),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.allocate_irp(
                ObjectId(9999),
                IrpParameterBlock::new(IrpMajorFunction::Read, 0, 4)
            ),
            Err(STATUS_INVALID_HANDLE)
        );
        let device = manager.driver_devices(driver).unwrap()[0];
        assert_eq!(
            manager.attach_device(device, device),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.attach_device(ObjectId(9999), device),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.device(ObjectId(9999)).err(),
            Some(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn device_stack_attach_detach_walks_and_rejects_cycles() {
        let mut manager = IoManager::new();
        let driver = new_driver(&mut manager, "StackDrv");
        let lower = new_device(&mut manager, driver, "Lower");
        let middle = new_device(&mut manager, driver, "Middle");
        let upper = new_device(&mut manager, driver, "Upper");

        assert_eq!(manager.attach_device(middle, lower).unwrap(), lower);
        assert_eq!(manager.attach_device(upper, middle).unwrap(), middle);
        assert_eq!(manager.top_of_stack(lower).unwrap(), upper);
        assert_eq!(manager.bottom_of_stack(upper).unwrap(), lower);
        assert_eq!(manager.next_lower_device(upper).unwrap(), Some(middle));
        assert_eq!(manager.next_attached_device(lower).unwrap(), Some(middle));
        assert_eq!(
            manager.stack_devices(upper).unwrap(),
            vec![lower, middle, upper]
        );

        assert_eq!(
            manager.attach_device(upper, lower),
            Err(STATUS_DEVICE_ALREADY_ATTACHED)
        );
        assert_eq!(manager.detach_device(middle).unwrap(), upper);
        assert_eq!(manager.top_of_stack(middle).unwrap(), middle);
        assert_eq!(manager.next_attached_device(middle).unwrap(), None);
        assert_eq!(
            manager.detach_device(middle),
            Err(STATUS_INVALID_DEVICE_REQUEST)
        );
    }

    #[test]
    fn irp_queue_completion_routines_run_bottom_to_top_once() {
        let mut manager = IoManager::new();
        let driver = new_driver(&mut manager, "IrpDrv");
        let lower = new_device(&mut manager, driver, "Lower");
        let upper = new_device(&mut manager, driver, "Upper");
        manager.attach_device(upper, lower).unwrap();
        let core = manager.irp_core();

        let parameters = IrpParameterBlock::new(IrpMajorFunction::Read, 0, 32);
        assert_eq!(parameters.validate(), Ok(()));
        let irp = manager.allocate_irp(upper, parameters).unwrap();
        assert_eq!(core.status(irp).unwrap(), STATUS_PENDING);

        let order = Arc::new(Mutex::new(Vec::new()));
        for view in core.stack_view(irp).unwrap() {
            let order = Arc::clone(&order);
            core.set_completion_routine(
                irp,
                view.device,
                Box::new(move |completion| {
                    order.lock().unwrap().push(completion.device);
                    STATUS_SUCCESS
                }),
            )
            .unwrap();
        }

        core.queue(upper, irp).unwrap();
        assert!(core.is_pending(irp).unwrap());
        assert_eq!(core.pending_irps(upper), vec![irp]);
        assert_eq!(core.pending_count(), 1);

        assert_eq!(
            core.complete(irp, STATUS_SUCCESS, 32).unwrap(),
            STATUS_SUCCESS
        );
        assert!(core.is_completed(irp).unwrap());
        assert_eq!(core.information(irp).unwrap(), 32);
        assert_eq!(core.status(irp).unwrap(), STATUS_SUCCESS);
        assert_eq!(*order.lock().unwrap(), vec![lower, upper]);
        assert_eq!(core.pending_count(), 0);
        assert_eq!(core.completed_count(), 1);
        assert_eq!(
            core.complete(irp, STATUS_SUCCESS, 32),
            Err(STATUS_UNSUCCESSFUL)
        );
    }

    #[test]
    fn irp_queue_rejects_double_queue_completed_and_foreign_devices() {
        let mut manager = IoManager::new();
        let driver = new_driver(&mut manager, "QueueDrv");
        let device = new_device(&mut manager, driver, "Target");
        let other = new_device(&mut manager, driver, "Other");
        let core = manager.irp_core();

        let irp = manager
            .allocate_irp(device, IrpParameterBlock::new(IrpMajorFunction::Read, 0, 4))
            .unwrap();
        // A device not on the IRP's stack cannot queue it.
        assert_eq!(core.queue(other, irp), Err(STATUS_INVALID_PARAMETER));
        core.queue(device, irp).unwrap();
        // Double queueing is rejected while it is pending.
        assert_eq!(core.queue(device, irp), Err(STATUS_INVALID_DEVICE_REQUEST));
        // Completion routines may only be attached to stack devices, and not
        // after completion.
        assert_eq!(
            core.set_completion_routine(irp, other, Box::new(|_| STATUS_SUCCESS)),
            Err(STATUS_NOT_FOUND)
        );
        core.complete(irp, STATUS_SUCCESS, 4).unwrap();
        assert_eq!(core.queue(device, irp), Err(STATUS_UNSUCCESSFUL));
        assert_eq!(
            core.set_completion_routine(irp, device, Box::new(|_| STATUS_SUCCESS)),
            Err(STATUS_UNSUCCESSFUL)
        );
        // Unknown IRPs fail cleanly.
        assert_eq!(core.queue(device, IrpId(999)), Err(STATUS_INVALID_HANDLE));
        assert_eq!(core.cancel(IrpId(999)), Err(STATUS_INVALID_HANDLE));

        // An allocated but never-queued IRP can still be completed (NT allows
        // completing an IRP the driver never queued) and only once.
        let direct = manager
            .allocate_irp(
                device,
                IrpParameterBlock::new(IrpMajorFunction::Close, 0, 2),
            )
            .unwrap();
        assert_eq!(core.complete(direct, STATUS_SUCCESS, 2), Ok(STATUS_SUCCESS));
        assert_eq!(
            core.complete(direct, STATUS_SUCCESS, 2),
            Err(STATUS_UNSUCCESSFUL)
        );
    }

    #[test]
    fn irp_cancel_is_exactly_once_and_works_cross_thread() {
        let mut manager = IoManager::new();
        let driver = new_driver(&mut manager, "CancelDrv");
        let device = new_device(&mut manager, driver, "Target");
        let core = manager.irp_core();

        let irp = manager
            .allocate_irp(
                device,
                IrpParameterBlock::new(IrpMajorFunction::Write, 0, 8),
            )
            .unwrap();
        core.queue(device, irp).unwrap();
        assert!(core.is_pending(irp).unwrap());

        let thread_core = core.clone();
        let canceller = std::thread::spawn(move || thread_core.cancel(irp));
        assert_eq!(canceller.join().unwrap(), Ok(STATUS_CANCELLED));
        assert!(core.is_cancelled(irp).unwrap());
        assert_eq!(core.status(irp).unwrap(), STATUS_CANCELLED);
        assert!(!core.is_pending(irp).unwrap());
        assert_eq!(core.cancelled_count(), 1);
        assert_eq!(core.completed_count(), 1);
        assert!(core.pending_irps(device).is_empty());
        assert_eq!(core.cancel(irp), Err(STATUS_UNSUCCESSFUL));

        // A never-queued IRP is cancellable exactly once and reported as such.
        let direct = manager
            .allocate_irp(
                device,
                IrpParameterBlock::new(IrpMajorFunction::Cleanup, 0, 1),
            )
            .unwrap();
        assert_eq!(core.cancel(direct), Ok(STATUS_CANCELLED));
        assert!(core.is_cancelled(direct).unwrap());
        assert_eq!(core.cancel(direct), Err(STATUS_UNSUCCESSFUL));
    }

    #[test]
    fn more_processing_required_stalls_then_resumes_exactly_once() {
        let mut manager = IoManager::new();
        let driver = new_driver(&mut manager, "StallDrv");
        let lower = new_device(&mut manager, driver, "Lower");
        let upper = new_device(&mut manager, driver, "Upper");
        manager.attach_device(upper, lower).unwrap();
        let core = manager.irp_core();
        let irp = manager
            .allocate_irp(
                upper,
                IrpParameterBlock::new(IrpMajorFunction::DeviceControl, 0, 8),
            )
            .unwrap();

        let lower_calls = Arc::new(AtomicUsize::new(0));
        let upper_calls = Arc::new(AtomicUsize::new(0));
        let upper_status = Arc::new(Mutex::new(None));
        {
            let lower_calls = Arc::clone(&lower_calls);
            core.set_completion_routine(
                irp,
                lower,
                Box::new(move |_| {
                    lower_calls.fetch_add(1, AtomicOrdering::SeqCst);
                    if lower_calls.load(AtomicOrdering::SeqCst) == 1 {
                        STATUS_MORE_PROCESSING_REQUIRED
                    } else {
                        STATUS_SUCCESS
                    }
                }),
            )
            .unwrap();
        }
        {
            let upper_calls = Arc::clone(&upper_calls);
            let upper_status = Arc::clone(&upper_status);
            core.set_completion_routine(
                irp,
                upper,
                Box::new(move |completion| {
                    upper_calls.fetch_add(1, AtomicOrdering::SeqCst);
                    *upper_status.lock().unwrap() = Some(completion.status);
                    STATUS_SUCCESS
                }),
            )
            .unwrap();
        }

        // The first pass stalls at the lower routine.
        assert_eq!(
            core.complete(irp, STATUS_SUCCESS, 8).unwrap(),
            STATUS_MORE_PROCESSING_REQUIRED
        );
        assert!(core.is_pending(irp).unwrap());
        assert!(!core.is_completed(irp).unwrap());
        assert_eq!(lower_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(upper_calls.load(AtomicOrdering::SeqCst), 0);
        // A stalled IRP is marked pending but no longer sits in the device
        // queue (it is the completer's responsibility until re-completed).
        assert!(core.pending_irps(upper).is_empty());
        assert_eq!(core.pending_device(irp).unwrap(), None);

        // The second pass re-enters the stalled routine and continues upward.
        assert_eq!(
            core.complete(irp, STATUS_SUCCESS, 8).unwrap(),
            STATUS_SUCCESS
        );
        assert!(core.is_completed(irp).unwrap());
        assert_eq!(lower_calls.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(upper_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(*upper_status.lock().unwrap(), Some(STATUS_SUCCESS));
        assert_eq!(core.pending_count(), 0);
        assert_eq!(
            core.complete(irp, STATUS_SUCCESS, 8),
            Err(STATUS_UNSUCCESSFUL)
        );
    }

    #[test]
    fn device_deletion_cancels_pending_irps_and_unlinks_the_stack() {
        let mut manager = IoManager::new();
        let driver = new_driver(&mut manager, "DeleteDrv");
        let lower = new_device(&mut manager, driver, "Lower");
        let upper = new_device(&mut manager, driver, "Upper");
        manager.attach_device(upper, lower).unwrap();
        let core = manager.irp_core();
        let irp = manager
            .allocate_irp(upper, IrpParameterBlock::new(IrpMajorFunction::Read, 0, 16))
            .unwrap();
        core.queue(upper, irp).unwrap();
        assert_eq!(core.pending_count(), 1);

        manager.delete_device(upper).unwrap();
        assert!(core.is_cancelled(irp).unwrap());
        assert!(core.is_completed(irp).unwrap());
        assert_eq!(core.pending_count(), 0);
        assert_eq!(manager.driver_device_count(driver).unwrap(), 1);
        assert_eq!(manager.top_of_stack(lower).unwrap(), lower);
        assert_eq!(
            manager.allocate_irp(upper, IrpParameterBlock::new(IrpMajorFunction::Read, 0, 1)),
            Err(STATUS_DELETE_PENDING)
        );
        assert_eq!(manager.delete_device(upper), Err(STATUS_DELETE_PENDING));
        assert_eq!(
            manager.attach_device(upper, lower),
            Err(STATUS_DELETE_PENDING)
        );
    }

    #[test]
    fn completion_port_binds_posts_dequeues_and_closes() {
        let mut manager = IoManager::new();
        let driver = new_driver(&mut manager, "PortDrv");
        let device = new_device(&mut manager, driver, "PortTarget");
        let port = manager
            .create_completion_port(Some("\\Device\\Port"), 8)
            .unwrap();
        assert_eq!(manager.port_count(), 1);
        assert_eq!(port.queue_depth(), 8);

        let handle = manager
            .objects_mut()
            .grant_handle(7, device, 1, false)
            .expect("grant handle");
        // An invalid handle cannot be bound.
        assert_eq!(
            manager.bind_completion_port(port.id(), 7, Handle(0), 1),
            Err(STATUS_INVALID_HANDLE)
        );
        manager
            .bind_completion_port(port.id(), 7, handle, 0x44)
            .unwrap();
        assert_eq!(manager.bound_completion_key(7, handle), Some(0x44));
        assert_eq!(manager.bound_port(7, handle), Some(port.id()));
        assert_eq!(manager.port_bindings(port.id()), vec![(7, handle, 0x44)]);
        assert_eq!(
            manager.unbind_completion_port(7, handle),
            Some((port.id(), 0x44))
        );
        assert_eq!(manager.unbind_completion_port(7, handle), None);
        assert_eq!(manager.bound_completion_key(7, handle), None);

        manager
            .post_to_port(
                port.id(),
                CompletionPacket::new(0x44, STATUS_SUCCESS, 12).with_bytes([1_u8, 2, 3]),
            )
            .unwrap();
        let packet = port.try_dequeue().expect("packet");
        assert_eq!(
            (packet.key, packet.status, packet.information),
            (0x44, STATUS_SUCCESS, 12)
        );
        assert_eq!(packet.bytes, vec![1, 2, 3]);
        assert_eq!(port.posted_count(), 1);
        assert_eq!(port.delivered_count(), 1);
        assert_eq!(port.dequeue(Duration::ZERO), Err(STATUS_TIMEOUT));

        manager
            .post_to_port(port.id(), CompletionPacket::new(0x44, STATUS_SUCCESS, 1))
            .unwrap();
        assert_eq!(manager.close_completion_port(port.id()).unwrap(), 1);
        assert!(port.is_closed());
        assert_eq!(port.dropped_count(), 1);
        assert_eq!(
            port.post(CompletionPacket::new(0x44, STATUS_SUCCESS, 1)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(port.dequeue(Duration::ZERO), Err(STATUS_CANCELLED));
        assert_eq!(
            manager.close_completion_port(port.id()),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.port_count(), 0);
        // Double close through the handle is a clean no-op.
        assert_eq!(port.close(), 0);
    }

    #[test]
    fn completion_port_blocking_dequeue_wakes_on_post_and_on_close() {
        let mut manager = IoManager::new();
        let port = manager.create_completion_port(None, 1).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = port.clone();
        let thread = std::thread::spawn(move || {
            sender.send(waiter.dequeue(Duration::from_secs(2))).unwrap();
        });
        std::thread::sleep(Duration::from_millis(20));
        port.post(CompletionPacket::new(9, STATUS_SUCCESS, 3))
            .unwrap();
        let packet = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("dequeue delivered")
            .expect("packet");
        assert_eq!(packet.key, 9);
        thread.join().unwrap();
        assert_eq!(port.delivered_count(), 1);

        // A waiter blocked when the port closes is released with CANCELLED.
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = port.clone();
        let thread = std::thread::spawn(move || {
            sender.send(waiter.dequeue(Duration::from_secs(2))).unwrap();
        });
        std::thread::sleep(Duration::from_millis(20));
        port.close();
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("close wake"),
            Err(STATUS_CANCELLED)
        );
        thread.join().unwrap();
    }

    #[test]
    fn parameter_block_validation_rejects_bad_requests() {
        assert_eq!(
            IrpParameterBlock::new(IrpMajorFunction::Read, 0, 4)
                .with_length(8)
                .validate(),
            Err(STATUS_INVALID_BUFFER_SIZE)
        );
        assert_eq!(
            IrpParameterBlock::new(IrpMajorFunction::Read, 0, 4)
                .with_user_address(0x1001, 3)
                .validate(),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            IrpParameterBlock::new(IrpMajorFunction::Read, 0, 4)
                .with_user_address(0x1001, 4)
                .validate(),
            Err(STATUS_DATATYPE_MISALIGNMENT)
        );
        assert_eq!(
            IrpParameterBlock::new(IrpMajorFunction::Read, 0, 4)
                .with_user_address(0x1000, 4)
                .validate(),
            Ok(())
        );
        // The zero-length edge is valid; a zero buffer with a length is not.
        assert_eq!(
            IrpParameterBlock::new(IrpMajorFunction::Read, 0, 0).validate(),
            Ok(())
        );
        assert_eq!(
            IrpParameterBlock::new(IrpMajorFunction::Read, 0, 0)
                .with_length(1)
                .validate(),
            Err(STATUS_INVALID_BUFFER_SIZE)
        );
    }
}
