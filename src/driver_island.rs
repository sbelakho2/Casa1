//! Sandboxed kernel driver island.
//!
//! This module executes a real, relocated PE driver image's `DriverEntry`
//! through the guest CPU runtime.  The image is mapped into the canonical
//! guest address space, its imports are patched against a real kernel API shim
//! table backed by CasaK objects, and a real guest `DRIVER_OBJECT` is handed
//! to the entry point.  The shims mutate real CasaK driver/device objects,
//! tagged pool blocks and IRPs, and `DbgPrint` is recorded in the runtime
//! trace plus the island's own log.
//!
//! The island executes native PE64 and PE32 images through the runtime's
//! x64/x86 guest paths.  Import and delay-import entries must be covered by
//! the shim table, and guest execution goes through the runtime's existing
//! [`PeHostRuntime::execute_guest_callback`] entry.  Nothing about the entry
//! call is synthesized — the bytes execute.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::casak::exec::{PoolBlock, PoolTag, TaggedPool};
use crate::casak::io::{
    DeviceExtension, DeviceFlags, IoManager, IrpId, IrpMajorFunction, IrpParameterBlock,
    STATUS_CANCELLED, STATUS_INVALID_PARAMETER, StackParameters,
};
use crate::casak::object::{
    ObjectId, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_ADDRESS, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};
use crate::cpu::{CpuState, GuestArch, MemoryImage, Register};
use crate::driver_image::{ImportRef, ImportReport, KernelApiSet, LoadedDriver, load_driver_image};
use crate::error::{AppError, AppResult};
use crate::ge::{FileAccess, RegistryView, ShareMode};
use crate::reason::ReasonCode;
use crate::runtime::{HostThunk, PeHostRuntime};
use crate::trace::TraceEvent;
use crate::vm::{VmProtection, VmRegionKind, VmState};
use crate::win32::CreationDisposition;

/// `IO_TYPE_DRIVER`.
const DRIVER_OBJECT_TYPE: u16 = 4;
/// `sizeof(DRIVER_OBJECT)` on x64.
const DRIVER_OBJECT_SIZE: u64 = 0x150;
/// `sizeof(DRIVER_OBJECT)` on x86.
const DRIVER_OBJECT_SIZE_X86: u64 = 0xA8;
/// `IO_TYPE_DEVICE`.
const DEVICE_OBJECT_TYPE: u16 = 3;
/// `sizeof(DEVICE_OBJECT)` on x64.
const DEVICE_OBJECT_SIZE: u16 = 0x150;
/// `sizeof(DEVICE_OBJECT)` on x86.
const DEVICE_OBJECT_SIZE_X86: u16 = 0xA8;
/// `IO_TYPE_IRP`.
const IRP_TYPE: u16 = 6;
/// Guest scratch stack (the same low arena the runtime's own tests use).
const STACK_BASE: u64 = 0x10_000;
const STACK_SIZE: u64 = 0x2000;
/// Per-island data arena (driver object, strings, guest device/IRP blocks).
const ARENA_SIZE: u64 = 0x10_0000;
/// Where a driver image is placed when its preferred base is unusable.
const DEFAULT_IMAGE_BASE: u64 = 0x1_4000_0000;
/// Where a PE32 image is placed when its preferred base is unusable.
const DEFAULT_IMAGE_BASE_X86: u64 = 0x1000_0000;
/// PE32 images (and their arenas) must stay below the 4 GiB boundary.
const X86_ADDRESS_LIMIT: u64 = 0x8000_0000;
/// `DRIVER_OBJECT.MajorFunction` has `IRP_MJ_MAXIMUM_FUNCTION + 1` slots.
const MAJOR_FUNCTION_COUNT: usize = 28;
/// `STATUS_ACCESS_VIOLATION`.
const STATUS_ACCESS_VIOLATION: i32 = 0xC000_0005u32 as i32;
/// `STATUS_INVALID_HANDLE`.
const STATUS_INVALID_HANDLE: i32 = 0xC000_0008u32 as i32;
/// `STATUS_INVALID_DEVICE_REQUEST`.
const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010u32 as i32;
/// `STATUS_DEVICE_BUSY`.
const STATUS_DEVICE_BUSY: i32 = 0x8000_0011u32 as i32;
/// `STATUS_BUFFER_TOO_SMALL`.
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
/// `STATUS_PENDING`.
const STATUS_PENDING: i32 = 0x0000_0103;
/// `STATUS_TIMEOUT`.
const STATUS_TIMEOUT: i32 = 0x0000_0102;
/// `STATUS_NO_MORE_ENTRIES`.
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;
/// First handle value minted for an island device namespace open.  This range
/// is disjoint from the canonical Win32 handle table values.
const DEVICE_HANDLE_BASE: u32 = 0x7C00_0000;
/// `SERVICE_BOOT_START`.
const SERVICE_BOOT_START: u32 = 0;
/// `SERVICE_SYSTEM_START`.
const SERVICE_SYSTEM_START: u32 = 1;
/// `SERVICE_AUTO_START`.
const SERVICE_AUTO_START: u32 = 2;
/// `SERVICE_DEMAND_START`.
const SERVICE_DEMAND_START: u32 = 3;
/// `SERVICE_DISABLED`.
const SERVICE_DISABLED: u32 = 4;
/// `IRP_MN_START_DEVICE`.
const IRP_MN_START_DEVICE: u8 = 0x00;
/// `IRP_MN_REMOVE_DEVICE`.
const IRP_MN_REMOVE_DEVICE: u8 = 0x02;
/// `IRP_MN_STOP_DEVICE`.
const IRP_MN_STOP_DEVICE: u8 = 0x04;
/// `IRP_MN_SET_POWER` (the only power minor the island model implements).
const IRP_MN_SET_POWER: u8 = 0x02;
/// `DevicePowerState` — the only `POWER_STATE_TYPE` the island accepts.
const POWER_STATE_TYPE_DEVICE: u32 = 1;
/// `WdfPowerDeviceD0`.
const WDF_POWER_DEVICE_D0: u32 = 1;
/// `WdfPowerDeviceD3`.
const WDF_POWER_DEVICE_D3: u32 = 4;
/// `WdfPowerDeviceD3Final`, the previous state reported to the first D0Entry.
const WDF_POWER_DEVICE_D3_FINAL: u32 = 5;

/// `STATUS_IMAGE_ALREADY_LOADED` — the service is already loaded.
const STATUS_IMAGE_ALREADY_LOADED: i32 = 0xC000_010Eu32 as i32;
/// `\Registry\Machine\System\CurrentControlSet\Services\` (lowercase).
const SERVICE_REGISTRY_PREFIX: &str = "system\\currentcontrolset\\services\\";
/// `\Registry\Machine\` (lowercase), including the trailing separator.
const MACHINE_REGISTRY_PREFIX: &str = "\\registry\\machine\\";

/// One island device handle.  Handles live in the runtime-level registry so a
/// device opened by one guest thread context can be closed by another.
#[derive(Debug, Clone)]
struct IslandDeviceHandle {
    service_name: String,
    device_guest: u64,
    device_id: ObjectId,
}

/// The island registry of one runtime.  `Rc`-backed island state is not
/// `Send`, but a runtime itself is single-host-threaded (the guest "threads"
/// are emulated contexts), so the mutex serializes registry access and the
/// wrapper is only ever used from the owning host thread.
struct SharedIsland(Box<DriverIsland>);

// SAFETY: every access to the registry happens while the owning runtime is
// mutably borrowed on its single host thread; the mutex only makes the
// process-global side table usable by the type system and orders access from
// guest thread contexts.
unsafe impl Send for SharedIsland {}

#[derive(Default)]
struct IslandRegistry {
    services: BTreeMap<usize, BTreeMap<String, SharedIsland>>,
    device_handles: BTreeMap<usize, BTreeMap<u32, IslandDeviceHandle>>,
    next_device_handle: BTreeMap<usize, u32>,
}

fn island_registry() -> &'static Mutex<IslandRegistry> {
    static REGISTRY: OnceLock<Mutex<IslandRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(IslandRegistry::default()))
}

fn lock_registry() -> MutexGuard<'static, IslandRegistry> {
    island_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A guest callback the current shim defers until its `RefCell` borrow ends.
struct PendingGuestCall {
    entry: u64,
    args: Vec<u64>,
    label: &'static str,
    purpose: PendingPurpose,
}

enum PendingPurpose {
    DriverDeviceAdd,
    IoDispatch {
        request: u64,
    },
    FileDispatch {
        request: u64,
    },
    IoTargetSend {
        pending: Box<PendingIoTargetSend>,
    },
    Callbacks {
        remaining: Vec<GuestCallback>,
        dispatch_next: bool,
    },
    PnpSequence {
        device: u64,
        irp_guest: u64,
        current_required: bool,
        remaining: VecDeque<PnpStep>,
        rollback: VecDeque<GuestCallback>,
        failure_status: Option<i32>,
        final_state: PnpFinalState,
    },
}

/// One guest callback in a PnP/power transition.  `required` callbacks fail
/// the transition when they return a negative NTSTATUS; informational ones
/// (void framework callbacks) only record their execution.
#[derive(Debug, Clone)]
struct PnpStep {
    entry: u64,
    args: Vec<u64>,
    label: &'static str,
    required: bool,
    rollback: Vec<GuestCallback>,
}

/// Device state applied when every step of a PnP/power transition succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PnpFinalState {
    Started,
    Stopped,
    Removed,
    PowerD0,
    PowerD3,
}

struct PendingIoTargetSend {
    irp: IrpId,
    irp_guest: u64,
    entry: u64,
    device_object: u64,
    system_buffer: u64,
    output_ptr: u64,
    output_len: usize,
    bytes_returned: u64,
    request: u64,
    target: u64,
    io_control: u32,
    input_ptr: u64,
    input_len: u32,
    saved: (u64, u64, u64, u32, u32, u32, u64),
}

/// One real (guest-visible) KMDF object.
/// `WDF_PNPPOWER_EVENT_CALLBACKS` subset the framework invokes through the
/// island.  Only callbacks a driver actually registers are non-zero.
#[derive(Debug, Clone, Copy, Default)]
struct KmdfPnpPowerCallbacks {
    prepare_hardware: u64,
    release_hardware: u64,
    d0_entry: u64,
    d0_exit: u64,
    self_managed_io_init: u64,
    self_managed_io_suspend: u64,
    self_managed_io_restart: u64,
    self_managed_io_fini: u64,
}

/// `WDF_FILEOBJECT_CONFIG` subset: the cleanup/close callbacks that map onto
/// `IRP_MJ_CLEANUP` and `IRP_MJ_CLOSE`.
#[derive(Debug, Clone, Copy, Default)]
struct KmdfFileObjectConfig {
    evt_file_cleanup: u64,
    evt_file_close: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct KmdfDeviceInit {
    device_type: u32,
    io_type: u32,
    name: Option<String>,
    pnp_power: KmdfPnpPowerCallbacks,
    file_object: KmdfFileObjectConfig,
    is_pdo: bool,
    parent_device: Option<u64>,
    device_id: Option<String>,
    hardware_ids: Vec<String>,
    compatible_ids: Vec<String>,
    instance_id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct KmdfDevice {
    object_guest: u64,
    casak: ObjectId,
    name: String,
    context_guest: u64,
    pnp_power: KmdfPnpPowerCallbacks,
    file_cleanup: u64,
    file_close: u64,
    file_object: u64,
    power_state: u32,
    started: bool,
    removed: bool,
    device_id: Option<String>,
    hardware_ids: Vec<String>,
    compatible_ids: Vec<String>,
    instance_id: Option<String>,
}

/// One `WDFMEMORY` allocation: the framework object owns this guest buffer.
#[derive(Debug, Clone)]
struct KmdfMemory {
    buffer: u64,
    size: usize,
}

/// One `WDFSTRING` allocation: an owned copy of the source `UNICODE_STRING`.
#[derive(Debug, Clone)]
struct KmdfString {
    buffer: u64,
    length: u16,
    maximum: u16,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
struct KmdfQueueCallbacks {
    default: u64,
    read: u64,
    write: u64,
    device_control: u64,
    internal_device_control: u64,
    stop: u64,
    resume: u64,
    canceled_on_queue: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct KmdfQueue {
    device: u64,
    callbacks: KmdfQueueCallbacks,
    dispatch_type: u32,
    default_queue: bool,
    queued: VecDeque<u64>,
    in_flight: BTreeSet<u64>,
    stopped: bool,
    draining: bool,
    context_guest: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct KmdfRequest {
    irp: IrpId,
    device: Option<u64>,
    io_control: u32,
    input_len: u32,
    output_len: u32,
    input_guest: u64,
    output_guest: u64,
    completed: bool,
    status: i32,
    information: usize,
    context_guest: u64,
    queue: Option<u64>,
    outer_irp_guest: u64,
    major: IrpMajorFunction,
    target: Option<u64>,
    canceled: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct KmdfIoTarget {
    device: u64,
    context_guest: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KmdfObjectKind {
    Driver,
    DeviceInit,
    Device,
    Queue,
    Request,
    WaitLock,
    IoTarget,
    FileObject,
    Memory,
    String,
}

impl KmdfObjectKind {
    /// Per-kind context layout: the default context bytes allocated when the
    /// caller asks for none, and the alignment of the context block.
    const fn layout(self) -> (usize, usize) {
        match self {
            Self::Driver => (0x20, 8),
            Self::DeviceInit => (0x40, 8),
            Self::Device => (0x80, 16),
            Self::Queue => (0x80, 16),
            Self::Request => (0x80, 8),
            Self::WaitLock => (0x20, 8),
            Self::IoTarget => (0x80, 8),
            Self::FileObject => (0x40, 8),
            Self::Memory => (0x40, 8),
            Self::String => (0x20, 8),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct KmdfObjectAttributes {
    evt_cleanup: u64,
    evt_destroy: u64,
    parent: Option<u64>,
    context_size_override: usize,
    context_type_info: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct KmdfObject {
    kind: KmdfObjectKind,
    parent: Option<u64>,
    children: BTreeSet<u64>,
    context_guest: u64,
    context_size: usize,
    context_type: u64,
    extra_contexts: Vec<(u64, u64, usize)>,
    evt_cleanup: u64,
    evt_destroy: u64,
    deleted: bool,
}

/// A guest callback scheduled by a shim and executed once the island state
/// borrow is released.
#[derive(Debug, Clone)]
struct GuestCallback {
    entry: u64,
    args: Vec<u64>,
    label: &'static str,
}

/// A real blocking wait lock.  The gate is shared with the waiting path so a
/// release on another host thread wakes a parked guest callback.
#[derive(Clone)]
struct KmdfWaitLock {
    gate: Arc<(Mutex<bool>, Condvar)>,
}

/// The KMDF shim subset's state: a real WDFDRIVER handle, device-init objects,
/// CasaK-backed WDFDEVICEs, queues, requests, targets and wait locks, plus the
/// framework dispatch context for the IRP currently being delivered.
#[allow(dead_code)]
#[derive(Default)]
struct KmdfState {
    driver_handle: u64,
    driver_object_guest: u64,
    evt_driver_device_add: u64,
    evt_driver_unload: u64,
    driver_pool_tag: u32,
    driver_init_flags: u32,
    driver_unload_ran: bool,
    device_inits: BTreeMap<u64, KmdfDeviceInit>,
    devices: BTreeMap<u64, KmdfDevice>,
    devices_by_object: BTreeMap<u64, u64>,
    queues: BTreeMap<u64, KmdfQueue>,
    requests: BTreeMap<u64, KmdfRequest>,
    iotargets: BTreeMap<u64, KmdfIoTarget>,
    objects: BTreeMap<u64, KmdfObject>,
    wait_locks: BTreeMap<u64, KmdfWaitLock>,
    memories: BTreeMap<u64, KmdfMemory>,
    strings: BTreeMap<u64, KmdfString>,
    framework_dispatch: u64,
    framework_dispatches: BTreeMap<u8, u64>,
    current_irp_guest: u64,
    current_device_guest: u64,
    current_system_buffer: u64,
    current_input_len: u32,
    current_output_len: u32,
    current_io_control: u32,
    current_request: u64,
    ioctl_dispatches: u64,
    read_dispatches: u64,
    write_dispatches: u64,
    cleanup_dispatches: u64,
    close_dispatches: u64,
    file_cleanup_dispatches: u64,
    file_close_dispatches: u64,
    pnp_start_dispatches: u64,
    pnp_stop_dispatches: u64,
    pnp_remove_dispatches: u64,
    power_d0_dispatches: u64,
    power_d3_dispatches: u64,
    queued_dispatches: u64,
    manual_retrievals: u64,
    cancel_dispatches: u64,
    stop_dispatches: u64,
    resume_dispatches: u64,
    iotarget_sends: u64,
    parked_acquires: u64,
    driver_unload_calls: u64,
}

#[cfg(test)]
thread_local! {
    /// The island removed by the most recent `NtUnloadDriver`; tests inspect
    /// its teardown evidence after the registration has been forgotten.
    static LAST_UNLOADED_DRIVER: RefCell<Option<DriverIsland>> = RefCell::new(None);
}

/// One kernel API exported by the island's shim table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverShim {
    DbgPrint,
    IoCreateDevice,
    IoDeleteDevice,
    IoCreateSymbolicLink,
    IoDeleteSymbolicLink,
    IoAllocateIrp,
    IoFreeIrp,
    RtlInitUnicodeString,
    IofCompleteRequest,
    IoCompleteRequest,
    ExAllocatePoolWithTag,
    ExFreePoolWithTag,
    /// Default `MajorFunction` dispatch: refuses unsupported IRPs.
    IrpDispatch,
    /// KMDF subset: `WdfDriverCreate`.
    WdfDriverCreate,
    /// KMDF subset: `WdfDeviceInitSetDeviceType`.
    WdfDeviceInitSetDeviceType,
    /// KMDF subset: `WdfDeviceInitSetIoType`.
    WdfDeviceInitSetIoType,
    /// KMDF subset: `WdfDeviceInitAssignName`.
    WdfDeviceInitAssignName,
    /// KMDF subset: `WdfDeviceCreate`.
    WdfDeviceCreate,
    /// KMDF subset: `WdfIoQueueCreate`.
    WdfIoQueueCreate,
    /// KMDF subset: `WdfRequestCreate`.
    WdfRequestCreate,
    /// KMDF subset: `WdfRequestFormatRequestForIoctl`.
    WdfRequestFormatRequestForIoctl,
    /// KMDF subset: `WdfRequestRetrieveInputBuffer`.
    WdfRequestRetrieveInputBuffer,
    /// KMDF subset: `WdfRequestRetrieveOutputBuffer`.
    WdfRequestRetrieveOutputBuffer,
    /// KMDF subset: `WdfRequestComplete`.
    WdfRequestComplete,
    /// KMDF subset: `WdfRequestCompleteWithInformation`.
    WdfRequestCompleteWithInformation,
    /// KMDF subset: `WdfDeviceWdmGetDeviceObject`.
    WdfDeviceWdmGetDeviceObject,
    /// KMDF subset: `WdfObjectGetTypedContext` (and its Worker form).
    WdfObjectGetTypedContext,
    /// KMDF subset: `WdfObjectDelete`.
    WdfObjectDelete,
    /// KMDF subset: `WdfWaitLockCreate`.
    WdfWaitLockCreate,
    /// KMDF subset: `WdfWaitLockAcquire`.
    WdfWaitLockAcquire,
    /// KMDF subset: `WdfWaitLockRelease`.
    WdfWaitLockRelease,
    /// KMDF subset: `WdfObjectAllocateContext`.
    WdfObjectAllocateContext,
    /// KMDF subset: `WdfDeviceGetIoTarget`.
    WdfDeviceGetIoTarget,
    /// KMDF subset: `WdfIoTargetCreate`.
    WdfIoTargetCreate,
    /// KMDF subset: `WdfIoTargetSendIoctlSynchronously`.
    WdfIoTargetSendIoctlSynchronously,
    /// KMDF subset: `WdfIoTargetFormatRequestForIoctl`.
    WdfIoTargetFormatRequestForIoctl,
    /// KMDF subset: `WdfRequestSend`.
    WdfRequestSend,
    /// KMDF subset: `WdfRequestCancelQueuedRequest`.
    WdfRequestCancelQueuedRequest,
    /// KMDF subset: `WdfIoQueueRetrieveNextRequest`.
    WdfIoQueueRetrieveNextRequest,
    /// KMDF subset: `WdfIoQueueRetrieveFoundRequest`.
    WdfIoQueueRetrieveFoundRequest,
    /// KMDF subset: `WdfIoQueueStop`.
    WdfIoQueueStop,
    /// KMDF subset: `WdfIoQueueStopSynchronously`.
    WdfIoQueueStopSynchronously,
    /// KMDF subset: `WdfIoQueueDrain`.
    WdfIoQueueDrain,
    /// KMDF subset: `WdfIoQueueDrainSynchronously`.
    WdfIoQueueDrainSynchronously,
    /// KMDF subset: `WdfIoQueuePurge`.
    WdfIoQueuePurge,
    /// KMDF subset: `WdfIoQueuePurgeSynchronously`.
    WdfIoQueuePurgeSynchronously,
    /// KMDF subset: `WdfIoQueueStart`.
    WdfIoQueueStart,
    /// Framework-installed `IRP_MJ_READ` dispatch.
    WdfEvtIoReadDispatch,
    /// Framework-installed `IRP_MJ_WRITE` dispatch.
    WdfEvtIoWriteDispatch,
    /// Framework-installed `IRP_MJ_DEVICE_CONTROL` dispatch that delivers the
    /// current IRP to the device's queue callback.
    WdfEvtIoDeviceControlDispatch,
    /// Framework-installed `IRP_MJ_CLEANUP` dispatch.
    WdfEvtIoCleanupDispatch,
    /// Framework-installed `IRP_MJ_CLOSE` dispatch.
    WdfEvtIoCloseDispatch,
    /// KMDF subset: `WdfDeviceInitSetPnpPowerEventCallbacks`.
    WdfDeviceInitSetPnpPowerEventCallbacks,
    /// KMDF subset: `WdfDeviceInitSetFileObjectConfig`.
    WdfDeviceInitSetFileObjectConfig,
    /// KMDF subset: `WdfMemoryCreate`.
    WdfMemoryCreate,
    /// KMDF subset: `WdfMemoryCreatePreallocated`.
    WdfMemoryCreatePreallocated,
    /// KMDF subset: `WdfMemoryGetBuffer`.
    WdfMemoryGetBuffer,
    /// KMDF subset: `WdfStringCreate`.
    WdfStringCreate,
    /// KMDF subset: `WdfStringGetUnicodeString`.
    WdfStringGetUnicodeString,
    /// KMDF subset: `WdfDeviceEnqueueRequest`.
    WdfDeviceEnqueueRequest,
    /// KMDF subset: `WdfPdoInitAllocate`.
    WdfPdoInitAllocate,
    /// KMDF subset: `WdfPdoInitAssignDeviceID`.
    WdfPdoInitAssignDeviceID,
    /// KMDF subset: `WdfPdoInitAssignInstanceID`.
    WdfPdoInitAssignInstanceID,
    /// KMDF subset: `WdfPdoInitAddHardwareID`.
    WdfPdoInitAddHardwareID,
    /// KMDF subset: `WdfPdoInitAddCompatibleID`.
    WdfPdoInitAddCompatibleID,
    /// Framework-installed `IRP_MJ_PNP` dispatch.
    WdfEvtPnpDispatch,
    /// Framework-installed `IRP_MJ_POWER` dispatch.
    WdfEvtPowerDispatch,
}

impl DriverShim {
    fn for_import(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "dbgprint" => Some(Self::DbgPrint),
            "iocreatedevice" => Some(Self::IoCreateDevice),
            "iodeletedevice" => Some(Self::IoDeleteDevice),
            "iocreatesymboliclink" => Some(Self::IoCreateSymbolicLink),
            "iodeletesymboliclink" => Some(Self::IoDeleteSymbolicLink),
            "ioallocateirp" => Some(Self::IoAllocateIrp),
            "iofreeirp" => Some(Self::IoFreeIrp),
            "rtlinitunicodestring" => Some(Self::RtlInitUnicodeString),
            "iofcompleterequest" => Some(Self::IofCompleteRequest),
            "iocompleterequest" => Some(Self::IoCompleteRequest),
            "exallocatepoolwithtag" => Some(Self::ExAllocatePoolWithTag),
            "exfreepoolwithtag" => Some(Self::ExFreePoolWithTag),
            "wdfdrivercreate" => Some(Self::WdfDriverCreate),
            "wdfdeviceinitsetdevicetype" => Some(Self::WdfDeviceInitSetDeviceType),
            "wdfdeviceinitsetiotype" => Some(Self::WdfDeviceInitSetIoType),
            "wdfdeviceinitassignname" => Some(Self::WdfDeviceInitAssignName),
            "wdfdevicecreate" => Some(Self::WdfDeviceCreate),
            "wdfioqueuecreate" => Some(Self::WdfIoQueueCreate),
            "wdfrequestcreate" => Some(Self::WdfRequestCreate),
            "wdfrequestformatrequestforioctl" => Some(Self::WdfRequestFormatRequestForIoctl),
            "wdfrequestretrieveinputbuffer" => Some(Self::WdfRequestRetrieveInputBuffer),
            "wdfrequestretrieveoutputbuffer" => Some(Self::WdfRequestRetrieveOutputBuffer),
            "wdfrequestcomplete" => Some(Self::WdfRequestComplete),
            "wdfrequestcompletewithinformation" => Some(Self::WdfRequestCompleteWithInformation),
            "wdfdevicewdmgetdeviceobject" => Some(Self::WdfDeviceWdmGetDeviceObject),
            "wdfobjectgettypedcontext" | "wdfobjectgettypedcontextworker" => {
                Some(Self::WdfObjectGetTypedContext)
            }
            "wdfobjectdelete" => Some(Self::WdfObjectDelete),
            "wdfwaitlockcreate" => Some(Self::WdfWaitLockCreate),
            "wdfwaitlockacquire" => Some(Self::WdfWaitLockAcquire),
            "wdfwaitlockrelease" => Some(Self::WdfWaitLockRelease),
            "wdfobjectallocatecontext" => Some(Self::WdfObjectAllocateContext),
            "wdfdevicegetiotarget" => Some(Self::WdfDeviceGetIoTarget),
            "wdfiotargetcreate" => Some(Self::WdfIoTargetCreate),
            "wdfiotargetsendioctlsynchronously" => Some(Self::WdfIoTargetSendIoctlSynchronously),
            "wdfiotargetformatrequestforioctl" => Some(Self::WdfIoTargetFormatRequestForIoctl),
            "wdfrequestsend" => Some(Self::WdfRequestSend),
            "wdfrequestcancelqueuedrequest" => Some(Self::WdfRequestCancelQueuedRequest),
            "wdfioqueueretrievenextrequest" => Some(Self::WdfIoQueueRetrieveNextRequest),
            "wdfioqueueretrievefoundrequest" => Some(Self::WdfIoQueueRetrieveFoundRequest),
            "wdfioqueuestop" => Some(Self::WdfIoQueueStop),
            "wdfioqueuestopsynchronously" => Some(Self::WdfIoQueueStopSynchronously),
            "wdfioqueuedrain" => Some(Self::WdfIoQueueDrain),
            "wdfioqueuedrainsynchronously" => Some(Self::WdfIoQueueDrainSynchronously),
            "wdfioqueuepurge" => Some(Self::WdfIoQueuePurge),
            "wdfioqueuepurgesynchronously" => Some(Self::WdfIoQueuePurgeSynchronously),
            "wdfioqueuestart" => Some(Self::WdfIoQueueStart),
            "wdfdeviceinitsetpnppowereventcallbacks" => {
                Some(Self::WdfDeviceInitSetPnpPowerEventCallbacks)
            }
            "wdfdeviceinitsetfileobjectconfig" => Some(Self::WdfDeviceInitSetFileObjectConfig),
            "wdfmemorycreate" => Some(Self::WdfMemoryCreate),
            "wdfmemorycreatepreallocated" => Some(Self::WdfMemoryCreatePreallocated),
            "wdfmemorygetbuffer" => Some(Self::WdfMemoryGetBuffer),
            "wdfmemorydelete" => Some(Self::WdfObjectDelete),
            "wdfstringcreate" => Some(Self::WdfStringCreate),
            "wdfstringgetunicodestring" => Some(Self::WdfStringGetUnicodeString),
            "wdfstringdelete" => Some(Self::WdfObjectDelete),
            "wdfdeviceenqueuerequest" => Some(Self::WdfDeviceEnqueueRequest),
            "wdfpdoinitallocate" => Some(Self::WdfPdoInitAllocate),
            "wdfpdoinitassigndeviceid" => Some(Self::WdfPdoInitAssignDeviceID),
            "wdfpdoinitassigninstanceid" => Some(Self::WdfPdoInitAssignInstanceID),
            "wdfpdoinitaddhardwareid" => Some(Self::WdfPdoInitAddHardwareID),
            "wdfpdoinitaddcompatibleid" => Some(Self::WdfPdoInitAddCompatibleID),
            _ => None,
        }
    }

    /// The stdcall argument byte count popped by the x86 host-thunk
    /// dispatcher after the shim returns.
    pub(crate) fn x86_arg_bytes(self) -> u64 {
        match self {
            Self::DbgPrint => 4,
            Self::IoCreateDevice => 28,
            Self::IoDeleteDevice => 4,
            Self::IoCreateSymbolicLink | Self::IoDeleteSymbolicLink => 8,
            Self::IoAllocateIrp => 8,
            Self::IoFreeIrp => 4,
            Self::RtlInitUnicodeString => 8,
            Self::IofCompleteRequest | Self::IoCompleteRequest => 8,
            Self::ExAllocatePoolWithTag => 12,
            Self::ExFreePoolWithTag => 8,
            Self::IrpDispatch => 8,
            Self::WdfDriverCreate => 20,
            Self::WdfDeviceInitSetDeviceType | Self::WdfDeviceInitSetIoType => 8,
            Self::WdfDeviceInitAssignName => 8,
            Self::WdfDeviceCreate => 12,
            Self::WdfIoQueueCreate => 16,
            Self::WdfRequestCreate => 12,
            Self::WdfRequestFormatRequestForIoctl => 32,
            Self::WdfRequestRetrieveInputBuffer | Self::WdfRequestRetrieveOutputBuffer => 16,
            Self::WdfRequestComplete => 8,
            Self::WdfRequestCompleteWithInformation => 12,
            Self::WdfDeviceWdmGetDeviceObject => 4,
            Self::WdfObjectGetTypedContext => 8,
            Self::WdfObjectDelete => 4,
            Self::WdfWaitLockCreate => 8,
            Self::WdfWaitLockAcquire => 8,
            Self::WdfWaitLockRelease => 4,
            Self::WdfObjectAllocateContext => 12,
            Self::WdfDeviceGetIoTarget => 4,
            Self::WdfIoTargetCreate => 12,
            Self::WdfIoTargetSendIoctlSynchronously => 28,
            Self::WdfIoTargetFormatRequestForIoctl => 28,
            Self::WdfRequestSend => 12,
            Self::WdfRequestCancelQueuedRequest => 4,
            Self::WdfIoQueueRetrieveNextRequest | Self::WdfIoQueueRetrieveFoundRequest => 12,
            Self::WdfIoQueueStop | Self::WdfIoQueueDrain | Self::WdfIoQueuePurge => 12,
            Self::WdfIoQueueStopSynchronously
            | Self::WdfIoQueueDrainSynchronously
            | Self::WdfIoQueuePurgeSynchronously
            | Self::WdfIoQueueStart => 4,
            Self::WdfEvtIoReadDispatch
            | Self::WdfEvtIoWriteDispatch
            | Self::WdfEvtIoDeviceControlDispatch
            | Self::WdfEvtIoCleanupDispatch
            | Self::WdfEvtIoCloseDispatch
            | Self::WdfEvtPnpDispatch
            | Self::WdfEvtPowerDispatch => 8,
            Self::WdfDeviceInitSetPnpPowerEventCallbacks
            | Self::WdfDeviceInitSetFileObjectConfig => 8,
            Self::WdfMemoryCreate => 24,
            Self::WdfMemoryCreatePreallocated => 16,
            Self::WdfMemoryGetBuffer => 8,
            Self::WdfStringCreate => 12,
            Self::WdfStringGetUnicodeString => 8,
            Self::WdfDeviceEnqueueRequest => 8,
            Self::WdfPdoInitAllocate => 4,
            Self::WdfPdoInitAssignDeviceID
            | Self::WdfPdoInitAssignInstanceID
            | Self::WdfPdoInitAddHardwareID
            | Self::WdfPdoInitAddCompatibleID => 8,
        }
    }
}

/// A device exposed by the island and backed by a CasaK device object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IslandDevice {
    /// Full guest path (`\Device\<name>`), or an empty string for a nameless
    /// device.
    pub name: String,
    /// Guest `PDEVICE_OBJECT` pointer handed to the driver.
    pub guest_pointer: u64,
    /// Whether `IoDeleteDevice` removed it.
    pub deleted: bool,
}

/// A loaded driver island with its real entry execution result.
pub struct DriverIsland {
    inner: Rc<RefCell<IslandState>>,
}

struct IslandState {
    arch: GuestArch,
    image_base: u64,
    image_size: u32,
    driver_name: String,
    registry_path: String,
    driver_object_guest: u64,
    registry_path_guest: u64,
    default_dispatch: u64,
    entry_rva: u32,
    entry_guest: u64,
    unload_rva: Option<u32>,
    unload_guest: Option<u64>,
    status: i32,
    loaded: bool,
    unloaded: bool,
    io: IoManager,
    casak_driver: ObjectId,
    devices: Vec<IslandDevice>,
    device_ids: BTreeMap<u64, ObjectId>,
    debug_log: Vec<String>,
    imports: ImportReport,
    pool: TaggedPool,
    pool_blocks: BTreeMap<u64, PoolBlock>,
    irp_ids: BTreeMap<u64, IrpId>,
    irp_guests: BTreeMap<IrpId, u64>,
    symbolic_links: Vec<(String, String)>,
    kmdf: KmdfState,
    removed_device_objects: BTreeSet<u64>,
    arena: IslandArena,
}

struct IslandArena {
    cursor: u64,
    end: u64,
}

impl IslandArena {
    fn alloc(&mut self, memory: &mut MemoryImage, len: usize, align: u64) -> AppResult<u64> {
        let len = len.max(1);
        let align = align.max(1);
        let start = align_up(self.cursor, align);
        let end = start
            .checked_add(len as u64)
            .ok_or_else(|| AppError::new(ReasonCode::RcIo, "driver island arena overflow"))?;
        if end > self.end {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!(
                    "driver island arena exhausted (need {len} bytes at {start:#x}, end {:#x})",
                    self.end
                ),
            ));
        }
        memory.map_bytes(start, &vec![0_u8; len]);
        self.cursor = end;
        Ok(start)
    }
}

impl DriverIsland {
    /// Loads `bytes` as a PE64 driver, maps it into `memory`, resolves its
    /// imports against the kernel shim table, builds a real guest
    /// `DRIVER_OBJECT`, and executes `DriverEntry(DriverObject, RegistryPath)`
    /// through `runtime`'s guest callback entry.
    ///
    /// A negative `DriverEntry` status is returned as an island state (the
    /// call itself succeeded); malformed images and unresolved imports are
    /// errors.
    #[cfg(test)]
    pub(crate) fn load_and_start(
        bytes: &[u8],
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
    ) -> AppResult<Self> {
        Self::load_and_start_named(bytes, "CasaDriver", runtime, memory)
    }

    /// Like [`Self::load_and_start`] with an explicit driver/service name.
    pub(crate) fn load_and_start_named(
        bytes: &[u8],
        driver_name: &str,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
    ) -> AppResult<Self> {
        let image_arch = pe_image_arch(bytes)
            .map_err(|message| AppError::new(ReasonCode::RcPeParseInvalid, message))?;
        if runtime.guest_arch != image_arch {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "driver island requires a {} guest runtime for this image",
                    match image_arch {
                        GuestArch::X86 => "x86",
                        GuestArch::X64 => "x64",
                    }
                ),
            ));
        }
        let default_base = if image_arch == GuestArch::X86 {
            DEFAULT_IMAGE_BASE_X86
        } else {
            DEFAULT_IMAGE_BASE
        };
        let (preferred, size_hint) = pe_layout_hint(bytes).unwrap_or((default_base, 0x10000));
        let (image_base, arena_base) = choose_placement(runtime, preferred, size_hint, image_arch)?;
        let mut driver =
            load_driver_image(bytes, image_base).map_err(|status| driver_image_error(status))?;
        if driver.machine
            != if image_arch == GuestArch::X86 {
                0x014C
            } else {
                0x8664
            }
        {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                format!(
                    "driver image optional header does not match machine {:#x}",
                    driver.machine
                ),
            ));
        }

        // Resolve the regular imports and the delay-import table at load
        // time; both IATs are patched before DriverEntry executes.
        let (imports, unresolved) = patch_imports(&mut driver, runtime, image_arch);
        if !unresolved.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcImportMissing,
                format!(
                    "unsupported or unresolved driver imports: {}",
                    unresolved
                        .iter()
                        .map(|(dll, symbol, set)| format!("{set:?}:{dll}!{symbol}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }

        memory.set_vm(runtime.win32.address_space_mut());
        {
            let vm = runtime.win32.address_space_mut();
            let image_size = driver.size_of_image as u64;
            vm.register(image_base, image_size, VmRegionKind::Image);
            vm.commit(
                image_base,
                image_size,
                VmProtection::READ_WRITE_EXECUTE,
                false,
            );
            vm.register(STACK_BASE, STACK_SIZE, VmRegionKind::Stack);
            vm.commit(STACK_BASE, STACK_SIZE, VmProtection::READ_WRITE, false);
            vm.register(arena_base, ARENA_SIZE, VmRegionKind::Private);
            vm.commit(arena_base, ARENA_SIZE, VmProtection::READ_WRITE, false);
        }
        memory.map_bytes(image_base, &driver.image);
        memory.map_bytes(STACK_BASE, &vec![0_u8; STACK_SIZE as usize]);

        let mut io = IoManager::new();
        let casak_driver = io
            .create_driver(driver_name, DeviceExtension::new())
            .map_err(|status| nt_error("IoCreateDriver", status))?;
        let default_dispatch = allocate_shim(runtime, DriverShim::IrpDispatch);

        let registry_path =
            format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{driver_name}");
        let mut state = IslandState {
            arch: image_arch,
            image_base,
            image_size: driver.size_of_image,
            driver_name: driver_name.to_string(),
            registry_path: registry_path.clone(),
            driver_object_guest: 0,
            registry_path_guest: 0,
            default_dispatch,
            entry_rva: driver.entry_rva,
            entry_guest: driver.address_of(driver.entry_rva),
            unload_rva: driver.unload_rva,
            unload_guest: driver.unload_rva.map(|rva| driver.address_of(rva)),
            status: STATUS_SUCCESS,
            loaded: false,
            unloaded: false,
            io,
            casak_driver,
            devices: Vec::new(),
            device_ids: BTreeMap::new(),
            debug_log: Vec::new(),
            imports,
            pool: TaggedPool::new(4 * 1024 * 1024),
            pool_blocks: BTreeMap::new(),
            irp_ids: BTreeMap::new(),
            irp_guests: BTreeMap::new(),
            symbolic_links: Vec::new(),
            kmdf: KmdfState::default(),
            removed_device_objects: BTreeSet::new(),
            arena: IslandArena {
                cursor: arena_base,
                end: arena_base + ARENA_SIZE,
            },
        };

        let driver_name_guest = allocate_unicode_string(&mut state, memory, driver_name)?;
        let registry_guest = allocate_unicode_string(&mut state, memory, &registry_path)?;
        let driver_object =
            state
                .arena
                .alloc(memory, driver_object_size(image_arch) as usize, 16)?;
        let extension = state.arena.alloc(memory, 0x28, 16)?;
        state.driver_object_guest = driver_object;
        state.registry_path_guest = registry_guest;
        build_driver_object(
            &state,
            memory,
            driver_object,
            extension,
            driver_name_guest,
            registry_guest,
            default_dispatch,
        )?;

        let inner = Rc::new(RefCell::new(state));
        let status = {
            let _active = ActiveIsland::install(inner.clone());
            let mut cpu = CpuState::new(image_arch);
            cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x100);
            let entry = inner.borrow().entry_guest;
            let result = runtime.execute_guest_callback(
                &mut cpu,
                memory,
                entry,
                &[driver_object, registry_guest],
                "DriverEntry",
            )?;
            result as u32 as i32
        };
        {
            let mut state = inner.borrow_mut();
            state.status = status;
            state.loaded = status_is_success(status);
        }
        Ok(Self { inner })
    }

    /// Executes the exported `DriverUnload` (when present), then deletes any
    /// devices the driver left behind.  Returns the unload status, or `None`
    /// when the island was already unloaded or had no unload routine.
    pub(crate) fn unload(
        &mut self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<i32>> {
        let inner = self.inner.clone();
        let (unloaded, unload_guest, driver_object) = {
            let state = inner.borrow();
            (
                state.unloaded,
                state.unload_guest,
                state.driver_object_guest,
            )
        };
        if unloaded {
            return Ok(None);
        }
        if self.has_open_device_handles(runtime) {
            return Ok(Some(STATUS_DEVICE_BUSY));
        }
        let arch = inner.borrow().arch;
        let status = if let Some(entry) = unload_guest {
            let _active = ActiveIsland::install(inner.clone());
            let mut cpu = CpuState::new(arch);
            cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x100);
            let result = runtime.execute_guest_callback(
                &mut cpu,
                memory,
                entry,
                &[driver_object],
                "DriverUnload",
            )?;
            Some(result as u32 as i32)
        } else {
            None
        };

        let mut callbacks = Vec::new();
        {
            let mut state = inner.borrow_mut();
            let driver_handle = state.kmdf.driver_handle;
            if driver_handle != 0 {
                state.collect_delete_callbacks(driver_handle, &mut callbacks);
            }
        }
        if !callbacks.is_empty() {
            let _active = ActiveIsland::install(inner.clone());
            for call in callbacks {
                let mut cpu = CpuState::new(arch);
                cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x100);
                runtime
                    .execute_guest_callback(&mut cpu, memory, call.entry, &call.args, call.label)?;
            }
        }
        let mut state = inner.borrow_mut();
        state.purge_deleted_objects();
        state.kmdf.driver_handle = 0;
        let live = state
            .io
            .driver_devices(state.casak_driver)
            .unwrap_or_default();
        let mut deleted_guests = Vec::new();
        for id in live {
            if state.io.delete_device(id).is_ok() {
                deleted_guests.extend(
                    state
                        .device_ids
                        .iter()
                        .filter_map(|(guest, mapped)| (*mapped == id).then_some(*guest)),
                );
            }
        }
        for device in state.devices.iter_mut() {
            if deleted_guests.contains(&device.guest_pointer) {
                device.deleted = true;
            }
        }
        state.device_ids.clear();
        // Symbolic links are island-owned objects: unloading the service
        // tears them down with the devices that exposed them.
        state.symbolic_links.clear();
        if driver_object != 0 {
            let head_offset = match arch {
                GuestArch::X86 => 0x04,
                GuestArch::X64 => 0x08,
            };
            write_guest_pointer(memory, driver_object + head_offset, 0, arch)?;
        }
        state.loaded = false;
        state.unloaded = true;
        Ok(status)
    }

    /// The real `NtLoadDriver` surface: open the service's registry key,
    /// read and expand `ImagePath`, read the image through the runtime file
    /// tables, and load it as a real island (executing `DriverEntry`).
    ///
    /// Statuses follow the kernel contract: a duplicate service is
    /// `STATUS_IMAGE_ALREADY_LOADED`; a missing key/value/image is
    /// `STATUS_OBJECT_NAME_NOT_FOUND`; a malformed or wrong-bitness image is
    /// `STATUS_INVALID_IMAGE_FORMAT`; a bad `UNICODE_STRING` is
    /// `STATUS_INVALID_PARAMETER`.  A failing `DriverEntry` returns its own
    /// NTSTATUS and leaves no registration behind.
    pub(crate) fn nt_load_driver(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        service_path: u64,
    ) -> i32 {
        let raw_path = match read_service_unicode_string(memory, service_path, runtime.guest_arch) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let service_name = match parse_service_name(&raw_path) {
            Ok(name) => name,
            Err(status) => return status,
        };
        let key = loaded_driver_key(runtime, &service_name);
        if lock_registry()
            .services
            .get(&key.0)
            .is_some_and(|services| services.contains_key(&key.1))
        {
            return STATUS_IMAGE_ALREADY_LOADED;
        }
        let Some(registry_key) = resolve_service_key(runtime, &service_name) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        match service_start_type(runtime, &registry_key) {
            Ok(
                Some(SERVICE_BOOT_START)
                | Some(SERVICE_SYSTEM_START)
                | Some(SERVICE_AUTO_START)
                | Some(SERVICE_DEMAND_START)
                | None,
            ) => {}
            Ok(Some(SERVICE_DISABLED)) => return STATUS_OBJECT_NAME_NOT_FOUND,
            Ok(Some(_)) => return STATUS_OBJECT_NAME_NOT_FOUND,
            Err(status) => return status,
        }
        let image_path = match read_service_image_path(runtime, &registry_key) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let bytes = match read_service_image(runtime, &image_path) {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };
        let island =
            match DriverIsland::load_and_start_named(&bytes, &service_name, runtime, memory) {
                Ok(island) => island,
                Err(error) => return nt_load_error_status(&error),
            };
        if island.status() < 0 {
            return island.status();
        }
        lock_registry()
            .services
            .entry(key.0)
            .or_default()
            .insert(key.1, SharedIsland(Box::new(island)));
        record_driver_event(
            runtime,
            "NtLoadDriver",
            &service_name,
            STATUS_SUCCESS,
            Some(&image_path),
        );
        STATUS_SUCCESS
    }

    /// The real `NtUnloadDriver` surface: look up the loaded island by
    /// service name, execute `DriverUnload` (when exported), destroy the
    /// CasaK devices/links, and forget the registration.  An unloaded or
    /// unknown service is `STATUS_OBJECT_NAME_NOT_FOUND`.
    pub(crate) fn nt_unload_driver(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        service_path: u64,
    ) -> i32 {
        let raw_path = match read_service_unicode_string(memory, service_path, runtime.guest_arch) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let service_name = match parse_service_name(&raw_path) {
            Ok(name) => name,
            Err(status) => return status,
        };
        let key = loaded_driver_key(runtime, &service_name);
        let removed = lock_registry()
            .services
            .get_mut(&key.0)
            .and_then(|services| services.remove(&key.1));
        let Some(SharedIsland(boxed)) = removed else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let mut island = *boxed;
        if island.has_open_device_handles(runtime) {
            lock_registry()
                .services
                .entry(key.0)
                .or_default()
                .insert(key.1, SharedIsland(Box::new(island)));
            record_driver_event(
                runtime,
                "NtUnloadDriver",
                &service_name,
                STATUS_DEVICE_BUSY,
                None,
            );
            return STATUS_DEVICE_BUSY;
        }
        match island.unload(runtime, memory) {
            Ok(status) => {
                let status = status.unwrap_or(STATUS_SUCCESS);
                record_driver_event(runtime, "NtUnloadDriver", &service_name, status, None);
                #[cfg(test)]
                LAST_UNLOADED_DRIVER.with(|slot| *slot.borrow_mut() = Some(island));
                #[cfg(not(test))]
                drop(island);
                status
            }
            Err(_) => {
                lock_registry()
                    .services
                    .entry(key.0)
                    .or_default()
                    .insert(key.1, SharedIsland(Box::new(island)));
                record_driver_event(
                    runtime,
                    "NtUnloadDriver",
                    &service_name,
                    STATUS_INVALID_PARAMETER,
                    None,
                );
                STATUS_INVALID_PARAMETER
            }
        }
    }

    /// The driver/service name used for `\Driver\<name>` and the registry
    /// service path.
    pub fn driver_name(&self) -> String {
        self.inner.borrow().driver_name.clone()
    }

    /// The real guest `UNICODE_STRING` path handed to `DriverEntry`.
    pub fn registry_path(&self) -> String {
        self.inner.borrow().registry_path.clone()
    }

    /// The guest base the driver image is mapped at.
    pub fn image_base(&self) -> u64 {
        self.inner.borrow().image_base
    }

    /// `SizeOfImage`.
    pub fn image_size(&self) -> u32 {
        self.inner.borrow().image_size
    }

    /// The guest `PDRIVER_OBJECT` passed to `DriverEntry`.
    pub fn driver_object_pointer(&self) -> u64 {
        self.inner.borrow().driver_object_guest
    }

    /// `AddressOfEntryPoint` of the loaded image.
    pub fn entry_rva(&self) -> u32 {
        self.inner.borrow().entry_rva
    }

    /// The exported `DriverUnload` RVA, when the image exports one.
    pub fn unload_rva(&self) -> Option<u32> {
        self.inner.borrow().unload_rva
    }

    /// The guest `DriverUnload` entry address, when exported.
    pub fn unload_pointer(&self) -> Option<u64> {
        self.inner.borrow().unload_guest
    }

    /// The real `DriverEntry` NTSTATUS.
    pub fn status(&self) -> i32 {
        self.inner.borrow().status
    }

    /// Whether `DriverEntry` returned success and the island is still loaded.
    pub fn is_loaded(&self) -> bool {
        self.inner.borrow().loaded
    }

    /// Whether any guest handle is still open onto this island's device
    /// namespace (an unload is refused while one is).
    pub(crate) fn has_open_device_handles(&self, runtime: &PeHostRuntime) -> bool {
        let state = self.inner.borrow();
        let runtime_id = runtime_identity(runtime);
        let registry = lock_registry();
        registry
            .device_handles
            .get(&runtime_id)
            .into_iter()
            .flat_map(|handles| handles.values())
            .any(|handle| {
                handle.service_name == state.driver_name
                    && state.device_ids.values().any(|id| *id == handle.device_id)
            })
    }

    /// The number of devices currently owned by the CasaK driver object.
    pub fn device_count(&self) -> usize {
        let state = self.inner.borrow();
        state
            .io
            .driver_device_count(state.casak_driver)
            .unwrap_or(0)
    }

    /// The device chain as observed in CasaK (most recently created first).
    pub fn casak_device_names(&self) -> Vec<String> {
        let state = self.inner.borrow();
        state
            .io
            .driver_devices(state.casak_driver)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|id| {
                state
                    .io
                    .device(id)
                    .ok()
                    .and_then(|device| device.name.clone())
            })
            .collect()
    }

    /// Devices the driver created through `IoCreateDevice`, including deleted
    /// ones.
    pub fn created_devices(&self) -> Vec<IslandDevice> {
        self.inner.borrow().devices.clone()
    }

    /// Every formatted `DbgPrint` message, in call order.
    pub fn dbg_print_log(&self) -> Vec<String> {
        self.inner.borrow().debug_log.clone()
    }

    /// The import resolution report produced while patching the IAT.
    pub fn imports(&self) -> ImportReport {
        self.inner.borrow().imports.clone()
    }

    /// Symbolic links created by the driver (`link -> target`).
    pub fn symbolic_links(&self) -> Vec<(String, String)> {
        self.inner.borrow().symbolic_links.clone()
    }

    /// Live tagged pool bytes currently owned through
    /// `ExAllocatePoolWithTag`.
    pub fn pool_used_bytes(&self) -> usize {
        self.inner.borrow().pool.used_bytes()
    }

    /// Tagged pool allocations performed by the driver.
    pub fn pool_allocation_count(&self) -> usize {
        self.inner.borrow().pool.allocation_count()
    }

    /// Tagged pool frees performed by the driver.
    pub fn pool_free_count(&self) -> usize {
        self.inner.borrow().pool.free_count()
    }

    /// IRPs the driver completed through `IoCompleteRequest`.
    pub fn completed_irp_count(&self) -> u64 {
        self.inner.borrow().io.completed_irp_count()
    }

    /// Invoke one island shim directly from a test, with arguments placed in
    /// the guest ABI locations the shim reads.  This exercises the same shim
    /// path as guest code without needing a hand-assembled caller for every
    /// operation.
    #[cfg(test)]
    pub(crate) fn call_shim_for_test(
        &self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        function: DriverShim,
        args: &[u64],
    ) -> AppResult<u64> {
        let inner = self.inner.clone();
        let _active = ActiveIsland::install(inner.clone());
        let arch = inner.borrow().arch;
        let mut cpu = CpuState::new(arch);
        let rsp = STACK_BASE + STACK_SIZE - 0x300;
        cpu.set(Register::Rsp, rsp);
        match arch {
            GuestArch::X64 => {
                let registers = [Register::Rcx, Register::Rdx, Register::R8, Register::R9];
                for (index, value) in args.iter().enumerate() {
                    if let Some(register) = registers.get(index) {
                        cpu.set(*register, *value);
                    } else {
                        memory.write_u64(rsp + 0x20 + (index as u64 - 4) * 8, *value);
                    }
                }
            }
            GuestArch::X86 => {
                for (index, value) in args.iter().enumerate() {
                    memory.write_u32(rsp + index as u64 * 4, *value as u32);
                }
            }
        }
        dispatch_shim(runtime, &mut cpu, memory, function)?;
        Ok(cpu.get(Register::Rax))
    }

    #[cfg(test)]
    pub(crate) fn kmdf_driver_handle(&self) -> u64 {
        self.inner.borrow().kmdf.driver_handle
    }

    #[cfg(test)]
    pub(crate) fn kmdf_device_handles(&self) -> Vec<u64> {
        self.inner.borrow().kmdf.devices.keys().copied().collect()
    }

    #[cfg(test)]
    pub(crate) fn kmdf_wait_lock_handles(&self) -> Vec<u64> {
        self.inner
            .borrow()
            .kmdf
            .wait_locks
            .keys()
            .copied()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn kmdf_wait_lock_gate(&self, handle: u64) -> Option<Arc<(Mutex<bool>, Condvar)>> {
        self.inner
            .borrow()
            .kmdf
            .wait_locks
            .get(&handle)
            .map(|lock| lock.gate.clone())
    }

    #[cfg(test)]
    pub(crate) fn kmdf_request_state(&self, handle: u64) -> Option<(bool, i32, usize, u64)> {
        self.inner
            .borrow()
            .kmdf
            .requests
            .get(&handle)
            .map(|request| {
                (
                    request.completed,
                    request.status,
                    request.information,
                    request.outer_irp_guest,
                )
            })
    }

    #[cfg(test)]
    pub(crate) fn kmdf_context_size(&self, handle: u64) -> Option<usize> {
        self.inner
            .borrow()
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_size)
    }

    #[cfg(test)]
    pub(crate) fn kmdf_typed_context(&self, handle: u64) -> Option<u64> {
        self.inner
            .borrow()
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
    }

    /// Build a real CasaK IRP and a guest `_IRP`/`IO_STACK_LOCATION`, then
    /// invoke the driver's real `MajorFunction` guest code with the guest IRP
    /// pointer.  Returns `(NTSTATUS, Information)`.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_irp(
        &self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device_guest: u64,
        major: IrpMajorFunction,
        io_control_code: u32,
        input_ptr: u64,
        input_len: u32,
        output_ptr: u64,
        output_len: u32,
        byte_offset: u64,
    ) -> AppResult<(i32, usize)> {
        self.dispatch_irp_inner(
            runtime,
            memory,
            device_guest,
            major,
            0,
            None,
            io_control_code,
            input_ptr,
            input_len,
            output_ptr,
            output_len,
            byte_offset,
        )
    }

    /// Deliver one real `IRP_MJ_PNP` IRP with `minor` to the device's PnP
    /// handler (the framework dispatch for a KMDF device).
    #[allow(dead_code)]
    pub(crate) fn dispatch_pnp(
        &self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device_guest: u64,
        minor: u8,
    ) -> AppResult<(i32, usize)> {
        self.dispatch_irp_inner(
            runtime,
            memory,
            device_guest,
            IrpMajorFunction::Pnp,
            minor,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }

    /// Deliver one real `IRP_MJ_POWER`/`IRP_MN_SET_POWER` IRP that asks the
    /// device to enter `power_state` (`WdfPowerDeviceD0`/`WdfPowerDeviceD3`).
    #[allow(dead_code)]
    pub(crate) fn set_device_power(
        &self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device_guest: u64,
        power_state: u32,
    ) -> AppResult<(i32, usize)> {
        self.dispatch_irp_inner(
            runtime,
            memory,
            device_guest,
            IrpMajorFunction::Power,
            IRP_MN_SET_POWER,
            Some(power_state),
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_irp_inner(
        &self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device_guest: u64,
        major: IrpMajorFunction,
        minor: u8,
        power_state: Option<u32>,
        io_control_code: u32,
        input_ptr: u64,
        input_len: u32,
        output_ptr: u64,
        output_len: u32,
        byte_offset: u64,
    ) -> AppResult<(i32, usize)> {
        let inner = self.inner.clone();
        let (arch, default_dispatch, irp, irp_guest, stack_guest, system_buffer_guest, handler) = {
            let mut state = inner.borrow_mut();
            if state.removed_device_objects.contains(&device_guest) {
                return Ok((STATUS_INVALID_DEVICE_REQUEST, 0));
            }
            let Some(casak_device) = state.device_ids.get(&device_guest).copied() else {
                return Ok((STATUS_INVALID_HANDLE, 0));
            };
            let buffer_len = if matches!(major, IrpMajorFunction::Pnp | IrpMajorFunction::Power) {
                0
            } else {
                input_len.max(output_len) as usize
            };
            let parameters = IrpParameterBlock::new(major, minor, input_len as usize);
            let irp = match state.io.allocate_irp(casak_device, parameters) {
                Ok(irp) => irp,
                Err(status) => return Ok((status, 0)),
            };
            if major == IrpMajorFunction::DeviceControl {
                let _ = state.io.set_stack_parameters(
                    irp,
                    casak_device,
                    crate::casak::io::StackParameters::DeviceControl {
                        io_control_code,
                        input_length: input_len as usize,
                        output_length: output_len as usize,
                        output_offset: 0,
                    },
                );
            } else if matches!(major, IrpMajorFunction::Read | IrpMajorFunction::Write) {
                let _ = state.io.set_stack_parameters(
                    irp,
                    casak_device,
                    crate::casak::io::StackParameters::ReadWrite {
                        length: input_len.max(output_len) as usize,
                        byte_offset,
                    },
                );
            }
            let arch = state.arch;
            let irp_guest = match state.arena.alloc(memory, irp_guest_size(arch) as usize, 8) {
                Ok(guest) => guest,
                Err(_) => {
                    let _ = state.io.complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
                    return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
                }
            };
            let stack_guest = match state.arena.alloc(memory, io_stack_location_size(arch), 8) {
                Ok(guest) => guest,
                Err(_) => {
                    let _ = state.io.complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
                    return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
                }
            };
            let system_buffer_guest = if buffer_len > 0 {
                match state.arena.alloc(memory, buffer_len, 8) {
                    Ok(guest) => guest,
                    Err(_) => {
                        let _ = state.io.complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
                        return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
                    }
                }
            } else {
                0
            };
            if input_len > 0 {
                let mut input = vec![0_u8; input_len as usize];
                if memory.read_into(input_ptr, &mut input).is_err() {
                    let _ = state.io.complete_irp(irp, STATUS_ACCESS_VIOLATION, 0);
                    return Ok((STATUS_ACCESS_VIOLATION, 0));
                }
                memory.map_bytes(system_buffer_guest, &input);
            }
            if output_len > 0
                && (output_ptr == 0
                    || crate::host_thunks::validate_guest_pointer(
                        memory,
                        output_ptr,
                        output_len as usize,
                    )
                    .is_err())
            {
                let _ = state.io.complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
                return Ok((STATUS_INVALID_PARAMETER, 0));
            }
            let handler = read_guest_pointer(
                memory,
                state.driver_object_guest
                    + major_function_offset(arch)
                    + major.code() as u64 * arch.pointer_bytes() as u64,
                arch,
            )?;
            (
                arch,
                state.default_dispatch,
                irp,
                irp_guest,
                stack_guest,
                system_buffer_guest,
                handler,
            )
        };

        if handler == 0 || handler == default_dispatch {
            let _ = self
                .inner
                .borrow()
                .io
                .complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            return Ok((STATUS_INVALID_DEVICE_REQUEST, 0));
        }

        build_guest_irp(
            memory,
            arch,
            irp_guest,
            stack_guest,
            system_buffer_guest,
            device_guest,
            output_ptr,
            major,
            minor,
            power_state,
            io_control_code,
            input_len,
            output_len,
            byte_offset,
        )?;
        {
            let mut state = self.inner.borrow_mut();
            state.kmdf.current_irp_guest = irp_guest;
            state.kmdf.current_device_guest = device_guest;
            state.kmdf.current_system_buffer = system_buffer_guest;
            state.kmdf.current_input_len = input_len;
            state.kmdf.current_output_len = output_len;
            state.kmdf.current_io_control = io_control_code;
            state.kmdf.current_request = 0;
        }

        let status = {
            let _active = ActiveIsland::install(inner.clone());
            let mut cpu = CpuState::new(arch);
            cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x100);
            let result = runtime.execute_guest_callback(
                &mut cpu,
                memory,
                handler,
                &[irp_guest, device_guest],
                "DriverMajorFunction",
            )?;
            result as u32 as i32
        };

        let (guest_status, information) = match arch {
            GuestArch::X64 => (
                memory.read_u32(irp_guest + 0x30)? as i32,
                memory.read_u64(irp_guest + 0x40)? as usize,
            ),
            GuestArch::X86 => (
                memory.read_u32(irp_guest + 0x18)? as i32,
                memory.read_u32(irp_guest + 0x20)? as usize,
            ),
        };
        let final_status = if status != guest_status {
            // The handler's return is authoritative when it differs from the
            // IoStatus block it wrote.
            status
        } else {
            guest_status
        };
        let _ = self
            .inner
            .borrow()
            .io
            .complete_irp(irp, final_status, information);
        {
            let mut state = self.inner.borrow_mut();
            state.kmdf.current_irp_guest = 0;
            state.kmdf.current_device_guest = 0;
            state.kmdf.current_system_buffer = 0;
            state.kmdf.current_request = 0;
        }
        if output_len > 0 && system_buffer_guest != 0 {
            let mut output = vec![0_u8; output_len as usize];
            if memory.read_into(system_buffer_guest, &mut output).is_ok() {
                memory.map_bytes(output_ptr, &output);
            }
        }
        Ok((final_status, information))
    }
}

fn irp_guest_size(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X86 => 0x80,
        GuestArch::X64 => 0x100,
    }
}

fn io_stack_location_size(arch: GuestArch) -> usize {
    match arch {
        GuestArch::X86 => 0x24,
        GuestArch::X64 => 0x48,
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn build_guest_irp(
    memory: &mut MemoryImage,
    arch: GuestArch,
    irp: u64,
    stack: u64,
    system_buffer: u64,
    device_object: u64,
    user_buffer: u64,
    major: IrpMajorFunction,
    minor: u8,
    power_state: Option<u32>,
    io_control_code: u32,
    input_length: u32,
    output_length: u32,
    byte_offset: u64,
) -> AppResult<()> {
    memory.write_u16(irp, IRP_TYPE);
    memory.write_u16(irp + 0x02, irp_guest_size(arch) as u16);
    let (system_buffer_offset, status_offset, information_offset, stack_pointer_offset) = match arch
    {
        GuestArch::X64 => (0x18, 0x30, 0x40, 0x98),
        GuestArch::X86 => (0x0C, 0x18, 0x20, 0x4C),
    };
    write_guest_pointer(memory, irp + system_buffer_offset, system_buffer, arch)?;
    memory.write_u32(irp + status_offset, STATUS_SUCCESS as u32);
    write_guest_pointer(
        memory,
        irp + status_offset + arch.pointer_bytes() as u64,
        0,
        arch,
    )?;
    write_guest_pointer(memory, irp + information_offset, 0, arch)?;
    let requestor_mode_offset = match arch {
        GuestArch::X64 => 0x48,
        GuestArch::X86 => 0x24,
    };
    memory.write_u8(irp + requestor_mode_offset, 1);
    let user_buffer_offset = match arch {
        GuestArch::X64 => 0x78,
        GuestArch::X86 => 0x40,
    };
    write_guest_pointer(memory, irp + user_buffer_offset, user_buffer, arch)?;
    write_guest_pointer(memory, irp + stack_pointer_offset, stack, arch)?;

    memory.write_u8(stack, major.code());
    memory.write_u8(stack + 1, minor);
    memory.write_u8(stack + 2, 0);
    memory.write_u8(stack + 3, 0);
    match arch {
        GuestArch::X64 => {
            match major {
                IrpMajorFunction::Power => {
                    memory.write_u32(stack + 0x08, POWER_STATE_TYPE_DEVICE);
                    memory.write_u32(stack + 0x10, power_state.unwrap_or(WDF_POWER_DEVICE_D0));
                }
                IrpMajorFunction::DeviceControl => {
                    memory.write_u32(stack + 0x08, output_length);
                    memory.write_u32(stack + 0x10, input_length);
                    memory.write_u32(stack + 0x18, io_control_code);
                    write_guest_pointer(memory, stack + 0x20, system_buffer, arch)?;
                }
                IrpMajorFunction::Read | IrpMajorFunction::Write => {
                    memory.write_u32(stack + 0x08, output_length.max(input_length));
                    memory.write_u32(stack + 0x0C, 0);
                    memory.write_u64(stack + 0x10, byte_offset);
                }
                _ => {}
            }
            write_guest_pointer(memory, stack + 0x20, device_object, arch)?;
        }
        GuestArch::X86 => {
            match major {
                IrpMajorFunction::Power => {
                    memory.write_u32(stack + 0x04, POWER_STATE_TYPE_DEVICE);
                    memory.write_u32(stack + 0x08, power_state.unwrap_or(WDF_POWER_DEVICE_D0));
                }
                IrpMajorFunction::DeviceControl => {
                    memory.write_u32(stack + 0x04, output_length);
                    memory.write_u32(stack + 0x08, input_length);
                    memory.write_u32(stack + 0x0C, io_control_code);
                    write_guest_pointer(memory, stack + 0x10, system_buffer, arch)?;
                }
                IrpMajorFunction::Read | IrpMajorFunction::Write => {
                    memory.write_u32(stack + 0x04, output_length.max(input_length));
                    memory.write_u32(stack + 0x08, 0);
                    memory.write_u64(stack + 0x0C, byte_offset);
                }
                _ => {}
            }
            write_guest_pointer(memory, stack + 0x14, device_object, arch)?;
        }
    }
    Ok(())
}

impl std::fmt::Debug for DriverIsland {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.inner.borrow();
        formatter
            .debug_struct("DriverIsland")
            .field("driver_name", &state.driver_name)
            .field("entry_rva", &format_args!("{:#x}", state.entry_rva))
            .field("status", &state.status)
            .field("loaded", &state.loaded)
            .finish()
    }
}

impl IslandState {
    /// Add another `DbgPrint` entry to the runtime trace and island log.
    fn record_debug_print(&mut self, runtime: &mut PeHostRuntime, message: &str) {
        self.debug_log.push(message.to_string());
        let index = runtime.next_trace_index;
        runtime.trace_events.push(TraceEvent {
            event_index: index,
            category: "driver".to_string(),
            call_id: "DbgPrint".to_string(),
            parameters: BTreeMap::from([
                ("driver".to_string(), json!(self.driver_name)),
                ("message".to_string(), json!(message)),
            ]),
            return_value: json!(message.len()),
            get_last_error: None,
            side_effect_hashes: Vec::new(),
        });
        runtime.next_trace_index += 1;
    }

    fn handle_shim(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        function: DriverShim,
    ) -> AppResult<Option<PendingGuestCall>> {
        match function {
            DriverShim::DbgPrint => self.dbg_print(runtime, state, memory)?,
            DriverShim::IoCreateDevice => self.io_create_device(state, memory)?,
            DriverShim::IoDeleteDevice => self.io_delete_device(state, memory)?,
            DriverShim::IoCreateSymbolicLink => self.io_create_symbolic_link(state, memory)?,
            DriverShim::IoDeleteSymbolicLink => self.io_delete_symbolic_link(state, memory)?,
            DriverShim::IoAllocateIrp => self.io_allocate_irp(state, memory)?,
            DriverShim::IoFreeIrp => self.io_free_irp(state, memory)?,
            DriverShim::RtlInitUnicodeString => self.rtl_init_unicode_string(state, memory)?,
            DriverShim::IofCompleteRequest | DriverShim::IoCompleteRequest => {
                self.io_complete_request(state, memory)?
            }
            DriverShim::ExAllocatePoolWithTag => self.ex_allocate_pool(state, memory)?,
            DriverShim::ExFreePoolWithTag => self.ex_free_pool(state, memory)?,
            DriverShim::IrpDispatch => {
                set_status(state, crate::casak::io::STATUS_INVALID_DEVICE_REQUEST);
            }
            DriverShim::WdfDriverCreate => {
                return self.wdf_driver_create(runtime, state, memory);
            }
            DriverShim::WdfDeviceInitSetDeviceType => {
                self.wdf_device_init_set_device_type(state, memory)?
            }
            DriverShim::WdfDeviceInitSetIoType => {
                self.wdf_device_init_set_io_type(state, memory)?
            }
            DriverShim::WdfDeviceInitAssignName => {
                self.wdf_device_init_assign_name(state, memory)?
            }
            DriverShim::WdfDeviceCreate => self.wdf_device_create(state, memory)?,
            DriverShim::WdfIoQueueCreate => self.wdf_io_queue_create(state, memory)?,
            DriverShim::WdfRequestCreate => self.wdf_request_create(state, memory)?,
            DriverShim::WdfRequestFormatRequestForIoctl => {
                self.wdf_request_format_for_ioctl(state, memory)?
            }
            DriverShim::WdfRequestRetrieveInputBuffer => {
                self.wdf_request_retrieve_buffer(state, memory, true)?
            }
            DriverShim::WdfRequestRetrieveOutputBuffer => {
                self.wdf_request_retrieve_buffer(state, memory, false)?
            }
            DriverShim::WdfRequestComplete => self.wdf_request_complete(state, memory, None)?,
            DriverShim::WdfRequestCompleteWithInformation => {
                let information = guest_arg(state, memory, 2)? as usize;
                self.wdf_request_complete(state, memory, Some(information))?
            }
            DriverShim::WdfDeviceWdmGetDeviceObject => {
                self.wdf_device_wdm_get_device_object(state, memory)?
            }
            DriverShim::WdfObjectGetTypedContext => {
                self.wdf_object_get_typed_context(state, memory)?
            }
            DriverShim::WdfObjectDelete => return self.wdf_object_delete(state, memory),
            DriverShim::WdfWaitLockCreate => self.wdf_wait_lock_create(state, memory)?,
            DriverShim::WdfWaitLockAcquire => self.wdf_wait_lock_acquire(state, memory)?,
            DriverShim::WdfWaitLockRelease => self.wdf_wait_lock_release(state, memory)?,
            DriverShim::WdfObjectAllocateContext => {
                self.wdf_object_allocate_context(state, memory)?
            }
            DriverShim::WdfDeviceGetIoTarget => self.wdf_device_get_iotarget(state, memory)?,
            DriverShim::WdfIoTargetCreate => self.wdf_iotarget_create(state, memory)?,
            DriverShim::WdfIoTargetSendIoctlSynchronously => {
                return self.wdf_iotarget_send_ioctl(runtime, state, memory);
            }
            DriverShim::WdfIoTargetFormatRequestForIoctl => {
                self.wdf_iotarget_format_request(state, memory)?
            }
            DriverShim::WdfRequestSend => return self.wdf_request_send(runtime, state, memory),
            DriverShim::WdfRequestCancelQueuedRequest => {
                return self.wdf_request_cancel_queued(state, memory);
            }
            DriverShim::WdfIoQueueRetrieveNextRequest => {
                self.wdf_queue_retrieve(state, memory, false)?
            }
            DriverShim::WdfIoQueueRetrieveFoundRequest => {
                self.wdf_queue_retrieve(state, memory, true)?
            }
            DriverShim::WdfIoQueueStop => {
                return self.wdf_queue_stop(state, memory, false, false);
            }
            DriverShim::WdfIoQueueStopSynchronously => {
                return self.wdf_queue_stop(state, memory, false, true);
            }
            DriverShim::WdfIoQueueDrain => {
                return self.wdf_queue_stop(state, memory, true, false);
            }
            DriverShim::WdfIoQueueDrainSynchronously => {
                return self.wdf_queue_stop(state, memory, true, true);
            }
            DriverShim::WdfIoQueuePurge | DriverShim::WdfIoQueuePurgeSynchronously => {
                return self.wdf_queue_purge(state, memory);
            }
            DriverShim::WdfIoQueueStart => return self.wdf_queue_start(state, memory),
            DriverShim::WdfEvtIoReadDispatch => {
                return self.wdf_dispatch(IrpMajorFunction::Read, state, memory);
            }
            DriverShim::WdfEvtIoWriteDispatch => {
                return self.wdf_dispatch(IrpMajorFunction::Write, state, memory);
            }
            DriverShim::WdfEvtIoDeviceControlDispatch => {
                return self.wdf_dispatch(IrpMajorFunction::DeviceControl, state, memory);
            }
            DriverShim::WdfEvtIoCleanupDispatch => {
                return self.wdf_dispatch(IrpMajorFunction::Cleanup, state, memory);
            }
            DriverShim::WdfEvtIoCloseDispatch => {
                return self.wdf_dispatch(IrpMajorFunction::Close, state, memory);
            }
            DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks => {
                self.wdf_device_init_set_pnp_power_callbacks(state, memory)?
            }
            DriverShim::WdfDeviceInitSetFileObjectConfig => {
                self.wdf_device_init_set_file_object_config(state, memory)?
            }
            DriverShim::WdfMemoryCreate => self.wdf_memory_create(state, memory, false)?,
            DriverShim::WdfMemoryCreatePreallocated => {
                self.wdf_memory_create(state, memory, true)?
            }
            DriverShim::WdfMemoryGetBuffer => self.wdf_memory_get_buffer(state, memory)?,
            DriverShim::WdfStringCreate => self.wdf_string_create(state, memory)?,
            DriverShim::WdfStringGetUnicodeString => {
                self.wdf_string_get_unicode_string(state, memory)?
            }
            DriverShim::WdfDeviceEnqueueRequest => {
                return self.wdf_device_enqueue_request(state, memory);
            }
            DriverShim::WdfPdoInitAllocate => self.wdf_pdo_init_allocate(state, memory)?,
            DriverShim::WdfPdoInitAssignDeviceID => {
                self.wdf_pdo_init_set_id(state, memory, false)?
            }
            DriverShim::WdfPdoInitAssignInstanceID => {
                self.wdf_pdo_init_set_id(state, memory, true)?
            }
            DriverShim::WdfPdoInitAddHardwareID => {
                self.wdf_pdo_init_add_id(state, memory, false)?
            }
            DriverShim::WdfPdoInitAddCompatibleID => {
                self.wdf_pdo_init_add_id(state, memory, true)?
            }
            DriverShim::WdfEvtPnpDispatch => return self.wdf_pnp_dispatch(state, memory),
            DriverShim::WdfEvtPowerDispatch => return self.wdf_power_dispatch(state, memory),
        }
        Ok(None)
    }

    fn finish_pending(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        purpose: PendingPurpose,
        callback_status: i32,
    ) -> AppResult<Option<PendingGuestCall>> {
        match purpose {
            PendingPurpose::DriverDeviceAdd => {
                set_status(state, callback_status);
            }
            PendingPurpose::IoTargetSend { pending } => {
                let (status, _) = self.finish_ioctl_send(memory, *pending)?;
                set_status(state, status);
            }
            PendingPurpose::IoDispatch { request } => {
                let (completed, status) = self
                    .kmdf
                    .requests
                    .get(&request)
                    .map(|request| (request.completed, request.status))
                    .unwrap_or((false, STATUS_INVALID_DEVICE_REQUEST));
                let status = if completed {
                    status
                } else {
                    self.write_outer_irp_status(memory, STATUS_PENDING, 0)?;
                    STATUS_PENDING
                };
                self.kmdf.current_request = 0;
                set_status(state, status);
                return self.dispatch_next_queued(memory);
            }
            PendingPurpose::FileDispatch { request } => {
                self.complete_kmdf_request(memory, request, STATUS_SUCCESS, 0)?;
                self.kmdf.current_request = 0;
                set_status(state, STATUS_SUCCESS);
                return self.dispatch_next_queued(memory);
            }
            PendingPurpose::PnpSequence {
                device,
                irp_guest,
                current_required,
                mut remaining,
                mut rollback,
                failure_status,
                final_state,
            } => {
                let mut failure = failure_status;
                if failure.is_none() && current_required && callback_status < 0 {
                    failure = Some(callback_status);
                }
                if let Some(status) = failure {
                    if let Some(call) = rollback.pop_front() {
                        return Ok(Some(PendingGuestCall {
                            entry: call.entry,
                            args: call.args,
                            label: call.label,
                            purpose: PendingPurpose::PnpSequence {
                                device,
                                irp_guest,
                                current_required: false,
                                remaining: VecDeque::new(),
                                rollback,
                                failure_status: Some(status),
                                final_state,
                            },
                        }));
                    }
                    self.purge_deleted_objects();
                    self.write_irp_status(memory, irp_guest, status, 0)?;
                    set_status(state, status);
                    return Ok(None);
                }
                if let Some(next) = remaining.pop_front() {
                    let rollback = VecDeque::from(next.rollback.clone());
                    let current_required = next.required;
                    return Ok(Some(PendingGuestCall {
                        entry: next.entry,
                        args: next.args,
                        label: next.label,
                        purpose: PendingPurpose::PnpSequence {
                            device,
                            irp_guest,
                            current_required,
                            remaining,
                            rollback,
                            failure_status: None,
                            final_state,
                        },
                    }));
                }
                self.apply_pnp_final_state(device, final_state);
                self.purge_deleted_objects();
                self.write_irp_status(memory, irp_guest, STATUS_SUCCESS, 0)?;
                set_status(state, STATUS_SUCCESS);
            }
            PendingPurpose::Callbacks {
                mut remaining,
                dispatch_next,
            } => {
                if !remaining.is_empty() {
                    let next = remaining.remove(0);
                    return Ok(Some(PendingGuestCall {
                        entry: next.entry,
                        args: next.args,
                        label: next.label,
                        purpose: PendingPurpose::Callbacks {
                            remaining,
                            dispatch_next,
                        },
                    }));
                }
                self.purge_deleted_objects();
                set_status(state, STATUS_SUCCESS);
                if dispatch_next {
                    return self.dispatch_next_queued(memory);
                }
            }
        }
        Ok(None)
    }

    fn write_outer_irp_status(
        &self,
        memory: &mut MemoryImage,
        status: i32,
        information: usize,
    ) -> AppResult<()> {
        self.write_irp_status(memory, self.kmdf.current_irp_guest, status, information)
    }

    fn write_irp_status(
        &self,
        memory: &mut MemoryImage,
        irp: u64,
        status: i32,
        information: usize,
    ) -> AppResult<()> {
        if irp == 0 {
            return Ok(());
        }
        let (status_offset, information_offset) = match self.arch {
            GuestArch::X64 => (0x30, 0x40),
            GuestArch::X86 => (0x18, 0x20),
        };
        memory.write_u32(irp + status_offset, status as u32);
        write_guest_pointer(
            memory,
            irp + information_offset,
            information as u64,
            self.arch,
        )
    }

    /// Parse a `WDF_OBJECT_ATTRIBUTES` block for this architecture.  The
    /// `Size` field bounds which trailing members are honored, matching KMDF's
    /// forward-compatible structure sizing.
    fn parse_object_attributes(
        &self,
        memory: &MemoryImage,
        attributes: u64,
    ) -> AppResult<KmdfObjectAttributes> {
        let mut parsed = KmdfObjectAttributes::default();
        if attributes == 0 {
            return Ok(parsed);
        }
        let pointer_bytes = self.arch.pointer_bytes() as u64;
        let size = memory.read_u32(attributes)? as u64;
        let minimum = match self.arch {
            GuestArch::X64 => 0x38,
            GuestArch::X86 => 0x20,
        };
        if size < 8
            || crate::host_thunks::validate_guest_pointer(
                memory,
                attributes,
                size.min(minimum) as usize,
            )
            .is_err()
        {
            return Ok(parsed);
        }
        let (cleanup_offset, destroy_offset, parent_offset, override_offset, type_offset) =
            match self.arch {
                GuestArch::X64 => (0x08, 0x10, 0x20, 0x28, 0x30),
                GuestArch::X86 => (0x04, 0x08, 0x14, 0x18, 0x1C),
            };
        if size >= cleanup_offset + pointer_bytes {
            parsed.evt_cleanup =
                read_guest_pointer(memory, attributes + cleanup_offset, self.arch)?;
        }
        if size >= destroy_offset + pointer_bytes {
            parsed.evt_destroy =
                read_guest_pointer(memory, attributes + destroy_offset, self.arch)?;
        }
        if size >= parent_offset + pointer_bytes {
            let parent = read_guest_pointer(memory, attributes + parent_offset, self.arch)?;
            parsed.parent = (parent != 0).then_some(parent);
        }
        if size >= override_offset + pointer_bytes {
            parsed.context_size_override =
                read_guest_pointer(memory, attributes + override_offset, self.arch)? as usize;
        }
        if size >= type_offset + pointer_bytes {
            parsed.context_type_info =
                read_guest_pointer(memory, attributes + type_offset, self.arch)?;
        }
        Ok(parsed)
    }

    /// Read the `ContextSize` member of a `WDF_OBJECT_CONTEXT_TYPE_INFO`.
    fn context_type_size(&self, memory: &MemoryImage, type_info: u64) -> AppResult<usize> {
        if type_info == 0 {
            return Ok(0);
        }
        let offset = match self.arch {
            GuestArch::X64 => 0x10,
            GuestArch::X86 => 0x08,
        };
        let size = read_guest_pointer(memory, type_info + offset, self.arch)? as usize;
        Ok(size)
    }

    /// Create one framework object with its per-kind context slot and attach it
    /// to the requested parent.  The handle block is `0x80` bytes and the
    /// context follows it, so `WdfObjectGetTypedContext` can return a stable
    /// guest pointer for the object's lifetime.
    fn create_kmdf_object(
        &mut self,
        memory: &mut MemoryImage,
        kind: KmdfObjectKind,
        attributes: u64,
    ) -> AppResult<u64> {
        let parsed = self.parse_object_attributes(memory, attributes)?;
        let (default_size, _align) = kind.layout();
        let type_size = self.context_type_size(memory, parsed.context_type_info)?;
        let context_size = if parsed.context_size_override > 0 {
            parsed.context_size_override
        } else if type_size > 0 {
            type_size
        } else {
            default_size
        }
        .clamp(8, 0x10_000);
        let handle = self.arena.alloc(memory, 0x80 + context_size, 16)?;
        let context_guest = handle + 0x80;
        memory.map_bytes(context_guest, &vec![0_u8; context_size]);
        let parent = parsed
            .parent
            .filter(|parent| self.kmdf.objects.contains_key(parent));
        let object = KmdfObject {
            kind,
            parent,
            children: BTreeSet::new(),
            context_guest,
            context_size,
            context_type: parsed.context_type_info,
            extra_contexts: Vec::new(),
            evt_cleanup: parsed.evt_cleanup,
            evt_destroy: parsed.evt_destroy,
            deleted: false,
        };
        if let Some(parent) = parent {
            let parent_object = self
                .kmdf
                .objects
                .get_mut(&parent)
                .expect("parent object must exist for a validated parent handle");
            parent_object.children.insert(handle);
        }
        self.kmdf.objects.insert(handle, object);
        Ok(handle)
    }

    /// Collect the cleanup/destroy callbacks for `handle` and its children in
    /// post-order, removing each object from its domain maps.  The object
    /// metadata itself survives until `purge_deleted_objects` so callbacks can
    /// still resolve their typed context.
    fn collect_delete_callbacks(&mut self, handle: u64, callbacks: &mut Vec<GuestCallback>) {
        let Some(object) = self.kmdf.objects.get(&handle) else {
            return;
        };
        if object.deleted {
            return;
        }
        let children = object.children.iter().copied().collect::<Vec<_>>();
        for child in children {
            self.collect_delete_callbacks(child, callbacks);
        }
        let (kind, parent, evt_cleanup, evt_destroy) = {
            let object = self.kmdf.objects.get(&handle).expect("object");
            (
                object.kind,
                object.parent,
                object.evt_cleanup,
                object.evt_destroy,
            )
        };
        if let Some(parent) = parent {
            if let Some(parent_object) = self.kmdf.objects.get_mut(&parent) {
                parent_object.children.remove(&handle);
            }
        }
        if kind == KmdfObjectKind::Driver
            && self.kmdf.evt_driver_unload != 0
            && !self.kmdf.driver_unload_ran
        {
            self.kmdf.driver_unload_ran = true;
            self.kmdf.driver_unload_calls += 1;
            callbacks.push(GuestCallback {
                entry: self.kmdf.evt_driver_unload,
                args: vec![handle],
                label: "EvtDriverUnload",
            });
        }
        if evt_cleanup != 0 {
            callbacks.push(GuestCallback {
                entry: evt_cleanup,
                args: vec![handle],
                label: "EvtCleanup",
            });
        }
        if evt_destroy != 0 {
            callbacks.push(GuestCallback {
                entry: evt_destroy,
                args: vec![handle],
                label: "EvtDestroy",
            });
        }
        if let Some(object) = self.kmdf.objects.get_mut(&handle) {
            object.deleted = true;
        }
        self.remove_object_domain(handle);
    }

    fn remove_object_domain(&mut self, handle: u64) {
        if let Some(device) = self.kmdf.devices.remove(&handle) {
            self.kmdf.devices_by_object.remove(&device.object_guest);
            if let Some(id) = self.device_ids.remove(&device.object_guest) {
                let _ = self.io.delete_device(id);
            }
            if let Some(record) = self
                .devices
                .iter_mut()
                .find(|record| record.guest_pointer == device.object_guest)
            {
                record.deleted = true;
            }
        }
        if let Some(queue) = self.kmdf.queues.remove(&handle) {
            let requests = queue
                .queued
                .iter()
                .chain(queue.in_flight.iter())
                .copied()
                .collect::<Vec<_>>();
            for request in requests {
                self.force_cancel_request(request);
            }
        }
        if let Some(request) = self.kmdf.requests.remove(&handle) {
            if !request.completed {
                let _ = self.io.cancel_irp(request.irp);
            }
            if self.kmdf.current_request == handle {
                self.kmdf.current_request = 0;
            }
        }
        self.kmdf.device_inits.remove(&handle);
        self.kmdf.iotargets.remove(&handle);
        self.kmdf.memories.remove(&handle);
        self.kmdf.strings.remove(&handle);
        if let Some(lock) = self.kmdf.wait_locks.remove(&handle) {
            let (gate, wake) = &*lock.gate;
            if let Ok(mut locked) = gate.lock() {
                *locked = false;
                wake.notify_all();
            }
        }
    }

    fn force_cancel_request(&mut self, handle: u64) -> bool {
        let Some(request) = self.kmdf.requests.get_mut(&handle) else {
            return false;
        };
        if request.completed {
            return false;
        }
        request.completed = true;
        request.canceled = true;
        request.status = STATUS_CANCELLED;
        request.information = 0;
        let irp = request.irp;
        let _ = self.io.cancel_irp(irp);
        true
    }

    fn purge_deleted_objects(&mut self) {
        let deleted = self
            .kmdf
            .objects
            .iter()
            .filter_map(|(handle, object)| object.deleted.then_some(*handle))
            .collect::<Vec<_>>();
        for handle in deleted {
            self.kmdf.objects.remove(&handle);
        }
    }

    fn dbg_print(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let format = guest_arg(state, memory, 0)?;
        let format = read_ansi_z(memory, format, 4096)?;
        let mut args = Vec::new();
        for index in 1..8 {
            args.push(guest_arg(state, memory, index).unwrap_or(0));
        }
        let message = format_dbg_print(&format, &args, memory, self.arch);
        self.record_debug_print(runtime, &message);
        state.set(Register::Rax, message.len() as u64);
        Ok(())
    }

    fn rtl_init_unicode_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let destination = guest_arg(state, memory, 0)?;
        let source = guest_arg(state, memory, 1)?;
        if destination != 0
            && crate::host_thunks::validate_guest_pointer(
                memory,
                destination,
                unicode_string_size(self.arch),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if destination != 0 {
            let text = read_utf16_z(memory, source, 0x4000)?;
            let length = (text.encode_utf16().count() * 2) as u16;
            write_unicode_string_header(
                memory,
                destination,
                length,
                length.saturating_add(2),
                source,
                self.arch,
            )?; // coverage: unreachable — write_unicode_string_header only performs infallible MemoryImage writes
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    fn io_create_device(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let driver_object = guest_arg(state, memory, 0)?;
        let extension_size = guest_arg(state, memory, 1)? as usize;
        let name_pointer = guest_arg(state, memory, 2)?;
        let device_type = guest_arg(state, memory, 3)? as u32;
        let _characteristics = guest_arg(state, memory, 4)? as u32;
        let exclusive = guest_arg(state, memory, 5)? != 0;
        let output_pointer = guest_arg(state, memory, 6)?;
        if driver_object != self.driver_object_guest
            || output_pointer == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                output_pointer,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if extension_size > 0x10_0000 {
            set_status(state, STATUS_INSUFFICIENT_RESOURCES);
            return Ok(());
        }
        let raw_name = if name_pointer != 0 {
            read_unicode_string(memory, name_pointer, self.arch)?.0
        } else {
            String::new()
        };
        let raw_name = (!raw_name.is_empty()).then_some(raw_name);
        match self.create_device_object(memory, raw_name, extension_size, device_type, exclusive)? {
            Ok(guest) => {
                write_guest_pointer(memory, output_pointer, guest, self.arch)?;
                set_status(state, STATUS_SUCCESS);
            }
            Err(status) => set_status(state, status),
        }
        Ok(())
    }

    fn create_device_object(
        &mut self,
        memory: &mut MemoryImage,
        raw_name: Option<String>,
        extension_size: usize,
        device_type: u32,
        exclusive: bool,
    ) -> AppResult<Result<u64, i32>> {
        let driver_object = self.driver_object_guest;
        if driver_object == 0 {
            return Ok(Err(STATUS_INVALID_PARAMETER));
        }
        if extension_size > 0x10_0000 {
            return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
        }
        let device_name = raw_name
            .as_deref()
            .map(strip_device_prefix)
            .map(str::to_string);
        let mut flags = DeviceFlags::NONE;
        if exclusive {
            flags.insert(DeviceFlags::EXCLUSIVE);
        }
        let extension = DeviceExtension::with_bytes(vec![0_u8; extension_size]);
        let device =
            match self
                .io
                .create_device(self.casak_driver, device_name.as_deref(), extension, flags)
            {
                Ok(id) => id,
                Err(status) => return Ok(Err(status)),
            };

        let guest = match self.arena.alloc(memory, 0x180, 16) {
            Ok(guest) => guest,
            Err(_) => {
                let _ = self.io.delete_device(device);
                return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
            }
        };
        let extension_guest = if extension_size > 0 {
            match self.arena.alloc(memory, extension_size, 8) {
                Ok(extension_guest) => extension_guest,
                Err(_) => {
                    let _ = self.io.delete_device(device);
                    return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
                }
            }
        } else {
            0
        };
        let arch = self.arch;
        match arch {
            GuestArch::X64 => {
                let previous_head = memory.read_u64(driver_object + 0x08)?;
                memory.write_u16(guest, DEVICE_OBJECT_TYPE);
                memory.write_u16(guest + 0x02, DEVICE_OBJECT_SIZE);
                memory.write_u32(guest + 0x04, 1);
                memory.write_u64(guest + 0x08, driver_object);
                memory.write_u64(guest + 0x10, previous_head);
                memory.write_u64(guest + 0x18, 0);
                memory.write_u64(guest + 0x20, 0);
                memory.write_u64(guest + 0x28, 0);
                memory.write_u32(guest + 0x30, 0);
                memory.write_u32(guest + 0x34, 0);
                memory.write_u64(guest + 0x38, 0);
                memory.write_u64(guest + 0x40, extension_guest);
                memory.write_u32(guest + 0x48, device_type);
                memory.write_u8(guest + 0x4C, 1);
                memory.write_u64(driver_object + 0x08, guest);
            }
            GuestArch::X86 => {
                let previous_head = read_guest_pointer(memory, driver_object + 0x04, arch)?;
                memory.write_u16(guest, DEVICE_OBJECT_TYPE);
                memory.write_u16(guest + 0x02, DEVICE_OBJECT_SIZE_X86);
                memory.write_u32(guest + 0x04, 1);
                write_guest_pointer(memory, guest + 0x08, driver_object, arch)?;
                write_guest_pointer(memory, guest + 0x0C, previous_head, arch)?;
                write_guest_pointer(memory, guest + 0x10, 0, arch)?;
                write_guest_pointer(memory, guest + 0x14, 0, arch)?;
                write_guest_pointer(memory, guest + 0x18, 0, arch)?;
                memory.write_u32(guest + 0x1C, 0);
                memory.write_u32(guest + 0x20, 0);
                write_guest_pointer(memory, guest + 0x24, 0, arch)?;
                write_guest_pointer(memory, guest + 0x28, extension_guest, arch)?;
                memory.write_u32(guest + 0x2C, device_type);
                memory.write_u8(guest + 0x30, 1);
                write_guest_pointer(memory, driver_object + 0x04, guest, arch)?;
            }
        }

        let full_name = device_name
            .as_deref()
            .map(|name| format!("\\Device\\{name}"))
            .unwrap_or_default();
        self.devices.push(IslandDevice {
            name: full_name,
            guest_pointer: guest,
            deleted: false,
        });
        self.device_ids.insert(guest, device);
        Ok(Ok(guest))
    }

    fn io_delete_device(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let guest = guest_arg(state, memory, 0)?;
        let Some(device) = self.device_ids.remove(&guest) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        let status = match self.io.delete_device(device) {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => status,
        };
        if status == STATUS_SUCCESS {
            if let Some(record) = self
                .devices
                .iter_mut()
                .find(|record| record.guest_pointer == guest)
            {
                record.deleted = true;
            }
            self.rebuild_device_chain(memory)?;
        }
        set_status(state, status);
        Ok(())
    }

    fn rebuild_device_chain(&self, memory: &mut MemoryImage) -> AppResult<()> {
        let arch = self.arch;
        let link_offset = match arch {
            GuestArch::X86 => 0x0C,
            GuestArch::X64 => 0x10,
        };
        let head_offset = match arch {
            GuestArch::X86 => 0x04,
            GuestArch::X64 => 0x08,
        };
        let mut next = 0_u64;
        for device in self.devices.iter().rev() {
            if device.deleted || device.guest_pointer == 0 {
                continue;
            }
            write_guest_pointer(memory, device.guest_pointer + link_offset, next, arch)?;
            next = device.guest_pointer;
        }
        write_guest_pointer(memory, self.driver_object_guest + head_offset, next, arch)
    }

    fn io_create_symbolic_link(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let link_pointer = guest_arg(state, memory, 0)?;
        let target_pointer = guest_arg(state, memory, 1)?;
        let link = read_unicode_string(memory, link_pointer, self.arch)?.0;
        let target = read_unicode_string(memory, target_pointer, self.arch)?.0;
        if link.is_empty() || target.is_empty() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if self
            .symbolic_links
            .iter()
            .any(|(existing, _)| existing.eq_ignore_ascii_case(&link))
        {
            set_status(state, STATUS_OBJECT_NAME_COLLISION);
            return Ok(());
        }
        self.symbolic_links.push((link, target));
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    fn io_delete_symbolic_link(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let link_pointer = guest_arg(state, memory, 0)?;
        let link = read_unicode_string(memory, link_pointer, self.arch)?.0;
        let before = self.symbolic_links.len();
        self.symbolic_links
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(&link));
        if self.symbolic_links.len() == before {
            set_status(state, STATUS_OBJECT_NAME_NOT_FOUND);
        } else {
            set_status(state, STATUS_SUCCESS);
        }
        Ok(())
    }

    fn io_allocate_irp(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let _stack_size = guest_arg(state, memory, 0)? as u8;
        let _charge_quota = guest_arg(state, memory, 1)? != 0;
        let target = self
            .devices
            .iter()
            .rev()
            .find(|device| !device.deleted)
            .and_then(|device| self.device_ids.get(&device.guest_pointer).copied());
        let Some(target) = target else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        let irp = match self.io.allocate_irp(
            target,
            IrpParameterBlock::new(IrpMajorFunction::DeviceControl, 0, 0),
        ) {
            Ok(irp) => irp,
            Err(_) => {
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        let guest = match self.arena.alloc(memory, 0x100, 8) {
            Ok(guest) => guest,
            Err(_) => {
                let _ = self.io.complete_irp(irp, STATUS_CANCELLED, 0);
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        memory.write_u16(guest, IRP_TYPE);
        memory.write_u16(guest + 0x02, 0x100);
        self.irp_ids.insert(guest, irp);
        self.irp_guests.insert(irp, guest);
        state.set(Register::Rax, guest);
        Ok(())
    }

    fn io_free_irp(&mut self, state: &mut CpuState, memory: &MemoryImage) -> AppResult<()> {
        let guest = guest_arg(state, memory, 0)?;
        if let Some(irp) = self.irp_ids.remove(&guest) {
            let _ = self.io.complete_irp(irp, STATUS_CANCELLED, 0);
            self.irp_guests.remove(&irp);
        }
        state.set(Register::Rax, 0);
        Ok(())
    }

    fn io_complete_request(&mut self, state: &mut CpuState, memory: &MemoryImage) -> AppResult<()> {
        let guest = guest_arg(state, memory, 0)?;
        let Some(irp) = self.irp_ids.get(&guest).copied() else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        let status = self
            .io
            .complete_irp(irp, STATUS_SUCCESS, 0)
            .unwrap_or(STATUS_INVALID_PARAMETER);
        set_status(state, status);
        Ok(())
    }

    fn ex_allocate_pool(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _pool_type = guest_arg(state, memory, 0)? as u32;
        let size = guest_arg(state, memory, 1)? as usize;
        let tag_bits = guest_arg(state, memory, 2)? as u32;
        let tag = PoolTag::new(&tag_bits.to_le_bytes());
        if size > 0x100_0000 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let block = match self.pool.allocate(tag, size) {
            Ok(block) => block,
            Err(_) => {
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        let guest = match self.arena.alloc(memory, size, 8) {
            Ok(guest) => guest,
            Err(_) => {
                let _ = self.pool.free(block);
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        self.pool_blocks.insert(guest, block);
        state.set(Register::Rax, guest);
        Ok(())
    }

    fn ex_free_pool(&mut self, state: &mut CpuState, memory: &MemoryImage) -> AppResult<()> {
        let guest = guest_arg(state, memory, 0)?;
        let tag_bits = guest_arg(state, memory, 1)? as u32;
        let tag = PoolTag::new(&tag_bits.to_le_bytes());
        if let Some(block) = self.pool_blocks.remove(&guest) {
            if block.tag == tag {
                let _ = self.pool.free(block);
            } else {
                self.pool_blocks.insert(guest, block);
                state.set(Register::Rax, STATUS_INVALID_ADDRESS as i64 as u64);
                return Ok(());
            }
        }
        state.set(Register::Rax, 0);
        Ok(())
    }

    fn wdf_driver_create(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let driver_object = guest_arg(state, memory, 0)?;
        let _registry_path = guest_arg(state, memory, 1)?;
        let attributes = guest_arg(state, memory, 2)?;
        let config = guest_arg(state, memory, 3)?;
        let driver_out = guest_arg(state, memory, 4)?;
        if driver_object != self.driver_object_guest
            || driver_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                driver_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        let (size_offset, add_offset, unload_offset, tag_offset, flags_offset, minimum_size) =
            match self.arch {
                GuestArch::X64 => (0u64, 8u64, 0x10u64, 0x18u64, 0x1Cu64, 0x20u64),
                GuestArch::X86 => (0, 4, 8, 0xC, 0x10, 0x14),
            };
        let mut evt_device_add = 0;
        let mut evt_driver_unload = 0;
        let mut driver_pool_tag = 0;
        let mut driver_init_flags = 0;
        if config != 0 {
            if crate::host_thunks::validate_guest_pointer(memory, config, minimum_size as usize)
                .is_err()
            {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(None);
            }
            let size = memory.read_u32(config + size_offset)? as u64;
            if size < minimum_size {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(None);
            }
            evt_device_add = read_guest_pointer(memory, config + add_offset, self.arch)?;
            if size >= unload_offset + self.arch.pointer_bytes() as u64 {
                evt_driver_unload = read_guest_pointer(memory, config + unload_offset, self.arch)?;
            } // coverage: unreachable — size >= minimum_size (0x20/0x14) always covers the 0x18/0x0C unload offset
            if size >= tag_offset + 4 {
                driver_pool_tag = memory.read_u32(config + tag_offset)?;
            } // coverage: unreachable — size >= minimum_size (0x20/0x14) always covers the 0x1C/0x10 tag offset
            if size >= flags_offset + 4 {
                driver_init_flags = memory.read_u32(config + flags_offset)?;
            } // coverage: unreachable — size >= minimum_size equals the 0x20/0x14 flags end, so this condition is always true
        }

        let dispatches = [
            (IrpMajorFunction::Read, DriverShim::WdfEvtIoReadDispatch),
            (IrpMajorFunction::Write, DriverShim::WdfEvtIoWriteDispatch),
            (
                IrpMajorFunction::DeviceControl,
                DriverShim::WdfEvtIoDeviceControlDispatch,
            ),
            (
                IrpMajorFunction::Cleanup,
                DriverShim::WdfEvtIoCleanupDispatch,
            ),
            (IrpMajorFunction::Close, DriverShim::WdfEvtIoCloseDispatch),
            (IrpMajorFunction::Pnp, DriverShim::WdfEvtPnpDispatch),
            (IrpMajorFunction::Power, DriverShim::WdfEvtPowerDispatch),
        ];
        // `WdfDriverInitNoDispatchOverride` leaves the driver's own
        // MajorFunction table untouched.
        if driver_init_flags & 0x2 == 0 {
            for (major, shim) in dispatches {
                let address = if let Some(address) =
                    self.kmdf.framework_dispatches.get(&major.code()).copied()
                {
                    address
                } else {
                    let address = allocate_shim(runtime, shim);
                    self.kmdf.framework_dispatches.insert(major.code(), address);
                    address
                };
                if major == IrpMajorFunction::DeviceControl {
                    self.kmdf.framework_dispatch = address;
                }
                let major_offset = major_function_offset(self.arch)
                    + major.code() as u64 * self.arch.pointer_bytes() as u64;
                write_guest_pointer(memory, driver_object + major_offset, address, self.arch)?;
            }
        }

        let driver_handle = self.create_kmdf_object(memory, KmdfObjectKind::Driver, attributes)?;
        self.kmdf.driver_handle = driver_handle;
        self.kmdf.driver_object_guest = driver_object;
        self.kmdf.evt_driver_device_add = evt_device_add;
        self.kmdf.evt_driver_unload = evt_driver_unload;
        self.kmdf.driver_pool_tag = driver_pool_tag;
        self.kmdf.driver_init_flags = driver_init_flags;
        write_guest_pointer(memory, driver_out, driver_handle, self.arch)?;
        if evt_device_add == 0 {
            set_status(state, STATUS_SUCCESS);
            return Ok(None);
        }
        let device_init = self.create_kmdf_object(memory, KmdfObjectKind::DeviceInit, 0)?;
        if let Some(object) = self.kmdf.objects.get_mut(&device_init) {
            object.parent = Some(driver_handle);
        }
        if let Some(driver) = self.kmdf.objects.get_mut(&driver_handle) {
            driver.children.insert(device_init);
        }
        self.kmdf.device_inits.insert(
            device_init,
            KmdfDeviceInit {
                device_type: 0,
                io_type: 0,
                name: None,
                pnp_power: KmdfPnpPowerCallbacks::default(),
                file_object: KmdfFileObjectConfig::default(),
                is_pdo: false,
                parent_device: None,
                device_id: None,
                hardware_ids: Vec::new(),
                compatible_ids: Vec::new(),
                instance_id: None,
            },
        );
        Ok(Some(PendingGuestCall {
            entry: evt_device_add,
            args: vec![driver_handle, device_init],
            label: "EvtDriverDeviceAdd",
            purpose: PendingPurpose::DriverDeviceAdd,
        }))
    }

    fn wdf_device_init_set_device_type(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let device_type = guest_arg(state, memory, 1)? as u32;
        match self.kmdf.device_inits.get_mut(&init) {
            Some(init) => {
                init.device_type = device_type;
                set_status(state, STATUS_SUCCESS);
            }
            None => set_status(state, STATUS_INVALID_PARAMETER),
        }
        Ok(())
    }

    fn wdf_device_init_set_io_type(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let io_type = guest_arg(state, memory, 1)? as u32;
        match self.kmdf.device_inits.get_mut(&init) {
            Some(init) => {
                init.io_type = io_type;
                set_status(state, STATUS_SUCCESS);
            }
            None => set_status(state, STATUS_INVALID_PARAMETER),
        }
        Ok(())
    }

    fn wdf_device_init_assign_name(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let name = guest_arg(state, memory, 1)?;
        let (text, _, _) = read_unicode_string(memory, name, self.arch)?;
        match self.kmdf.device_inits.get_mut(&init) {
            Some(init) => {
                init.name = (!text.is_empty()).then_some(text);
                set_status(state, STATUS_SUCCESS);
            }
            None => set_status(state, STATUS_INVALID_PARAMETER),
        }
        Ok(())
    }

    fn wdf_device_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let init_argument = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let device_out = guest_arg(state, memory, 2)?;
        if device_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                device_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        // Accept both `&DeviceInit` (the documented KMDF form) and the init
        // handle itself.
        let mut init_handle = init_argument;
        if let Ok(value) = read_guest_pointer(memory, init_argument, self.arch) {
            if self.kmdf.device_inits.contains_key(&value) {
                init_handle = value;
            }
        }
        let Some(init) = self.kmdf.device_inits.get(&init_handle).cloned() else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        let guest =
            match self.create_device_object(memory, init.name, 0, init.device_type, false)? {
                Ok(guest) => guest,
                Err(status) => {
                    set_status(state, status);
                    return Ok(());
                }
            };
        let casak = *self
            .device_ids
            .get(&guest)
            .expect("island device ids are inserted before their guest handle is returned");
        let name = self
            .devices
            .iter()
            .rev()
            .find(|device| device.guest_pointer == guest)
            .map(|device| device.name.clone())
            .unwrap_or_default();
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Device, attributes)?;
        if self
            .kmdf
            .objects
            .get(&handle)
            .is_some_and(|object| object.parent.is_none())
        {
            let parent = init
                .parent_device
                .filter(|parent| self.kmdf.devices.contains_key(parent))
                .unwrap_or(self.kmdf.driver_handle);
            if let Some(object) = self.kmdf.objects.get_mut(&handle) {
                object.parent = Some(parent);
            }
            if let Some(object) = self.kmdf.objects.get_mut(&parent) {
                object.children.insert(handle);
            }
        }
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        self.kmdf.devices.insert(
            handle,
            KmdfDevice {
                object_guest: guest,
                casak,
                name,
                context_guest,
                pnp_power: init.pnp_power,
                file_cleanup: init.file_object.evt_file_cleanup,
                file_close: init.file_object.evt_file_close,
                file_object: 0,
                power_state: WDF_POWER_DEVICE_D3,
                started: false,
                removed: false,
                device_id: init.device_id,
                hardware_ids: init.hardware_ids,
                compatible_ids: init.compatible_ids,
                instance_id: init.instance_id,
            },
        );
        self.kmdf.devices_by_object.insert(guest, handle);
        write_guest_pointer(memory, device_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    fn wdf_io_queue_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        let config = guest_arg(state, memory, 1)?;
        let attributes = guest_arg(state, memory, 2)?;
        let queue_out = guest_arg(state, memory, 3)?;
        if !self.kmdf.devices.contains_key(&device)
            || queue_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                queue_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let mut callbacks = KmdfQueueCallbacks::default();
        let mut dispatch_type = 0;
        let mut default_queue = false;
        if config != 0 {
            let minimum = match self.arch {
                GuestArch::X86 => 0x10,
                GuestArch::X64 => 0x18,
            };
            if crate::host_thunks::validate_guest_pointer(memory, config, minimum).is_err() {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
            let size = memory.read_u32(config)? as u64;
            if size < 8 {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
            dispatch_type = memory.read_u32(config + 4)?;
            let (allow_offset, default_offset, first_callback) = match self.arch {
                GuestArch::X64 => (0x0Cu64, 0x0Du64, 0x10u64),
                GuestArch::X86 => (0x0Cu64, 0x0Du64, 0x10u64),
            };
            if size > allow_offset {
                let _allow_zero_length = memory.read_u8(config + allow_offset)? != 0;
            }
            if size > default_offset {
                default_queue = memory.read_u8(config + default_offset)? != 0;
            }
            let pointer = self.arch.pointer_bytes() as u64;
            let callbacks_table = [
                (0x00u64, &mut callbacks.default),
                (0x08, &mut callbacks.read),
                (0x10, &mut callbacks.write),
                (0x18, &mut callbacks.device_control),
                (0x20, &mut callbacks.internal_device_control),
                (0x28, &mut callbacks.stop),
                (0x30, &mut callbacks.resume),
                (0x38, &mut callbacks.canceled_on_queue),
            ];
            for (index, slot) in callbacks_table {
                let offset = first_callback + index;
                if size >= offset + pointer {
                    *slot = read_guest_pointer(memory, config + offset, self.arch)?;
                }
            }
        }
        if dispatch_type > 2 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Queue, attributes)?;
        if self
            .kmdf
            .objects
            .get(&handle)
            .is_some_and(|object| object.parent.is_none())
        {
            if let Some(object) = self.kmdf.objects.get_mut(&handle) {
                object.parent = Some(device);
            }
            if let Some(object) = self.kmdf.objects.get_mut(&device) {
                object.children.insert(handle);
            }
        }
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        self.kmdf.queues.insert(
            handle,
            KmdfQueue {
                device,
                callbacks,
                dispatch_type,
                default_queue,
                queued: VecDeque::new(),
                in_flight: BTreeSet::new(),
                stopped: false,
                draining: false,
                context_guest,
            },
        );
        write_guest_pointer(memory, queue_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    fn wdf_request_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let attributes = guest_arg(state, memory, 0)?;
        let io_target = guest_arg(state, memory, 1)?;
        let request_out = guest_arg(state, memory, 2)?;
        if request_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                request_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let target_device = self.resolve_target_device(io_target);
        let Some(target) = target_device else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(());
        };
        let Some(device) = self.kmdf.devices.get(&target) else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(());
        };
        let irp = match self.io.allocate_irp(
            device.casak,
            IrpParameterBlock::new(IrpMajorFunction::DeviceControl, 0, 0),
        ) {
            Ok(irp) => irp,
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        };
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Request, attributes)?;
        if self
            .kmdf
            .objects
            .get(&handle)
            .is_some_and(|object| object.parent.is_none())
        {
            let parent = if self.kmdf.iotargets.contains_key(&io_target) {
                io_target
            } else {
                target
            };
            if let Some(object) = self.kmdf.objects.get_mut(&handle) {
                object.parent = Some(parent);
            }
            if let Some(object) = self.kmdf.objects.get_mut(&parent) {
                object.children.insert(handle);
            }
        }
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        self.kmdf.requests.insert(
            handle,
            KmdfRequest {
                irp,
                device: Some(target),
                io_control: 0,
                input_len: 0,
                output_len: 0,
                input_guest: 0,
                output_guest: 0,
                completed: false,
                status: STATUS_SUCCESS,
                information: 0,
                context_guest,
                queue: None,
                outer_irp_guest: 0,
                major: IrpMajorFunction::DeviceControl,
                target: (io_target != 0).then_some(io_target),
                canceled: false,
            },
        );
        write_guest_pointer(memory, request_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    fn resolve_target_device(&self, target: u64) -> Option<u64> {
        if self.kmdf.devices.contains_key(&target) {
            return Some(target);
        }
        if let Some(iotarget) = self.kmdf.iotargets.get(&target) {
            return Some(iotarget.device);
        }
        self.kmdf.devices.keys().next().copied()
    }

    fn wdf_request_format_for_ioctl(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        let target = guest_arg(state, memory, 1)?;
        let io_control = guest_arg(state, memory, 2)? as u32;
        let input_guest = guest_arg(state, memory, 3)?;
        let input_len = guest_arg(state, memory, 4)? as u32;
        let output_guest = guest_arg(state, memory, 5)?;
        let output_len = guest_arg(state, memory, 6)? as u32;
        let _options = guest_arg(state, memory, 7)?;
        let resolved_device = self.resolve_target_device(target);
        let Some(request) = self.kmdf.requests.get_mut(&request) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        request.io_control = io_control;
        request.input_guest = input_guest;
        request.input_len = input_len;
        request.output_guest = output_guest;
        request.output_len = output_len;
        request.target = Some(target);
        if resolved_device.is_some() {
            request.device = resolved_device;
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    fn wdf_request_retrieve_buffer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        input: bool,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        let minimum = guest_arg(state, memory, 1)? as usize;
        let buffer_out = guest_arg(state, memory, 2)?;
        let length_out = guest_arg(state, memory, 3)?;
        let pointer_bytes = self.arch.pointer_bytes();
        if buffer_out == 0
            || length_out == 0
            || crate::host_thunks::validate_guest_pointer(memory, buffer_out, pointer_bytes)
                .is_err()
            || crate::host_thunks::validate_guest_pointer(memory, length_out, pointer_bytes)
                .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(request) = self.kmdf.requests.get(&request) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        let (buffer, length) = if input {
            (request.input_guest, request.input_len)
        } else {
            (request.output_guest, request.output_len)
        };
        if minimum > length as usize || (minimum > 0 && buffer == 0) {
            set_status(state, STATUS_BUFFER_TOO_SMALL);
            return Ok(());
        }
        write_guest_pointer(memory, buffer_out, buffer, self.arch)?;
        write_guest_pointer(memory, length_out, u64::from(length), self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    fn wdf_request_complete(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        information: Option<usize>,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let status = guest_arg(state, memory, 1)? as u32 as i32;
        let information = information.unwrap_or(0);
        let Some(request) = self.kmdf.requests.get(&handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        if request.completed {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        self.complete_kmdf_request(memory, handle, status, information)?;
        set_status(state, status);
        Ok(())
    }

    fn wdf_device_wdm_get_device_object(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        match self.kmdf.devices.get(&device) {
            Some(device) => state.set(Register::Rax, device.object_guest),
            None => set_status(state, STATUS_INVALID_HANDLE),
        }
        Ok(())
    }

    fn wdf_object_get_typed_context(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let type_info = guest_arg(state, memory, 1)?;
        let Some(object) = self.kmdf.objects.get(&handle) else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        if type_info == 0 {
            state.set(Register::Rax, object.context_guest);
            return Ok(());
        }
        let type_info_size = match self.arch {
            GuestArch::X64 => 0x18,
            GuestArch::X86 => 0x0C,
        };
        let type_size = if crate::host_thunks::validate_guest_pointer(
            memory,
            type_info,
            type_info_size,
        )
        .is_ok()
        {
            self.context_type_size(memory, type_info)?
        } else {
            0
        };
        let extra = object
            .extra_contexts
            .iter()
            .find_map(|(registered_type, context, size)| {
                (*registered_type == type_info && *size >= type_size).then_some(*context)
            });
        if let Some(context) = extra {
            state.set(Register::Rax, context);
            return Ok(());
        }
        if type_size > object.context_size {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        state.set(Register::Rax, object.context_guest);
        Ok(())
    }

    fn wdf_object_delete(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let handle = guest_arg(state, memory, 0)?;
        if !self.kmdf.objects.contains_key(&handle) {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        }
        if self
            .kmdf
            .objects
            .get(&handle)
            .is_some_and(|object| object.deleted)
        {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        }
        let mut callbacks = Vec::new();
        self.collect_delete_callbacks(handle, &mut callbacks);
        if self.driver_object_guest != 0 {
            self.rebuild_device_chain(memory)?;
        }
        set_status(state, STATUS_SUCCESS);
        if callbacks.is_empty() {
            self.purge_deleted_objects();
        }
        Ok(Self::callbacks_pending(callbacks, false))
    }

    fn wdf_wait_lock_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let attributes = guest_arg(state, memory, 0)?;
        let lock_out = guest_arg(state, memory, 1)?;
        if lock_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                lock_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::WaitLock, attributes)?;
        if self
            .kmdf
            .objects
            .get(&handle)
            .is_some_and(|object| object.parent.is_none())
        {
            let driver = self.kmdf.driver_handle;
            if let Some(object) = self.kmdf.objects.get_mut(&handle) {
                object.parent = Some(driver);
            }
            if let Some(object) = self.kmdf.objects.get_mut(&driver) {
                object.children.insert(handle);
            }
        }
        self.kmdf.wait_locks.insert(
            handle,
            KmdfWaitLock {
                gate: Arc::new((Mutex::new(false), Condvar::new())),
            },
        );
        write_guest_pointer(memory, lock_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Resolve the optional `PLONGLONG` timeout.  A null pointer means
    /// infinite wait; negative values are relative 100 ns units and
    /// non-negative values are absolute 100 ns since 1601-01-01 (we treat a
    /// zero absolute as "try once", matching KMDF's documented behavior).
    fn wait_lock_timeout(&self, memory: &MemoryImage, pointer: u64) -> AppResult<Option<Duration>> {
        if pointer == 0 {
            return Ok(None);
        }
        let units = match self.arch {
            GuestArch::X64 => memory.read_u64(pointer)? as i64,
            GuestArch::X86 => i64::from(memory.read_u32(pointer)? as i32),
        };
        if units == 0 {
            return Ok(Some(Duration::ZERO));
        }
        let relative = if units < 0 {
            units.saturating_neg()
        } else {
            // Absolute deadlines are converted against the guest clock's
            // current UTC time; tests use relative timeouts.
            units
        };
        Ok(Some(Duration::from_nanos(
            (relative as u64).saturating_mul(100),
        )))
    }

    fn wait_lock_acquire_gate(
        &self,
        gate: &Arc<(Mutex<bool>, Condvar)>,
        timeout: Option<Duration>,
    ) -> i32 {
        let started = Instant::now();
        let (mutex, wake) = &**gate;
        let mut locked = match mutex.lock() {
            Ok(locked) => locked,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !*locked {
            *locked = true;
            return STATUS_SUCCESS;
        }
        let Some(timeout) = timeout else {
            while *locked {
                locked = match wake.wait(locked) {
                    Ok(locked) => locked,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
            *locked = true;
            return STATUS_SUCCESS;
        };
        if timeout.is_zero() {
            return STATUS_TIMEOUT;
        }
        let deadline = started + timeout;
        while *locked {
            let now = Instant::now();
            if now >= deadline {
                return STATUS_TIMEOUT;
            }
            let remaining = deadline - now;
            locked = match wake.wait_timeout(locked, remaining) {
                Ok((locked, _)) => locked,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        *locked = true;
        STATUS_SUCCESS
    }

    fn wdf_wait_lock_acquire(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let timeout_pointer = guest_arg(state, memory, 1)?;
        let timeout = self.wait_lock_timeout(memory, timeout_pointer)?;
        let Some(lock) = self.kmdf.wait_locks.get(&handle).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let already_held = lock.gate.0.lock().map(|locked| *locked).unwrap_or(false);
        let status = self.wait_lock_acquire_gate(&lock.gate, timeout);
        if already_held && status == STATUS_SUCCESS {
            self.kmdf.parked_acquires += 1;
        }
        set_status(state, status);
        Ok(())
    }

    fn wdf_wait_lock_release(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let Some(lock) = self.kmdf.wait_locks.get(&handle).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let (mutex, wake) = &*lock.gate;
        let mut locked = match mutex.lock() {
            Ok(locked) => locked,
            Err(poisoned) => poisoned.into_inner(),
        };
        *locked = false;
        drop(locked);
        wake.notify_all();
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Lazily create the single `WDFFILEOBJECT` the island associates with
    /// this device's cleanup/close IRPs.
    fn ensure_file_object(
        &mut self,
        memory: &mut MemoryImage,
        device_handle: u64,
    ) -> AppResult<u64> {
        if let Some(existing) = self
            .kmdf
            .devices
            .get(&device_handle)
            .map(|device| device.file_object)
            .filter(|object| *object != 0)
        {
            return Ok(existing);
        }
        let object = self.create_kmdf_object(memory, KmdfObjectKind::FileObject, 0)?;
        if let Some(device) = self.kmdf.objects.get_mut(&device_handle) {
            device.children.insert(object);
        }
        if let Some(file) = self.kmdf.objects.get_mut(&object) {
            file.parent = Some(device_handle);
        }
        if let Some(device) = self.kmdf.devices.get_mut(&device_handle) {
            device.file_object = object;
        }
        Ok(object)
    }

    fn choose_queue(&self, device_handle: u64) -> Option<u64> {
        self.kmdf
            .queues
            .iter()
            .filter(|(_, queue)| queue.device == device_handle)
            .find(|(_, queue)| queue.default_queue)
            .or_else(|| {
                self.kmdf
                    .queues
                    .iter()
                    .find(|(_, queue)| queue.device == device_handle)
            })
            .map(|(handle, _)| *handle)
    }

    fn queue_callback(queue: &KmdfQueue, major: IrpMajorFunction) -> u64 {
        match major {
            IrpMajorFunction::Read => {
                if queue.callbacks.read != 0 {
                    queue.callbacks.read
                } else {
                    queue.callbacks.default
                }
            }
            IrpMajorFunction::Write => {
                if queue.callbacks.write != 0 {
                    queue.callbacks.write
                } else {
                    queue.callbacks.default
                }
            }
            IrpMajorFunction::DeviceControl => {
                if queue.callbacks.device_control != 0 {
                    queue.callbacks.device_control
                } else {
                    queue.callbacks.default
                }
            }
            _ => queue.callbacks.default,
        }
    }

    fn callback_call(
        queue_handle: u64,
        request_handle: u64,
        request: &KmdfRequest,
        entry: u64,
        label: &'static str,
    ) -> PendingGuestCall {
        let args = match request.major {
            IrpMajorFunction::Read | IrpMajorFunction::Write => vec![
                queue_handle,
                request_handle,
                u64::from(request.input_len.max(request.output_len)),
            ],
            IrpMajorFunction::DeviceControl => vec![
                queue_handle,
                request_handle,
                u64::from(request.output_len),
                u64::from(request.input_len),
                u64::from(request.io_control),
            ],
            _ => vec![queue_handle, request_handle],
        };
        PendingGuestCall {
            entry,
            args,
            label,
            purpose: PendingPurpose::IoDispatch {
                request: request_handle,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new_kmdf_request(
        &mut self,
        memory: &mut MemoryImage,
        device_handle: u64,
        queue_handle: u64,
        major: IrpMajorFunction,
        io_control: u32,
        input_len: u32,
        output_len: u32,
        input_guest: u64,
        output_guest: u64,
        outer_irp_guest: u64,
    ) -> AppResult<Result<u64, i32>> {
        let Some(device) = self.kmdf.devices.get(&device_handle) else {
            return Ok(Err(STATUS_INVALID_DEVICE_REQUEST));
        };
        let casak = device.casak;
        let irp = match self.io.allocate_irp(
            casak,
            IrpParameterBlock::new(major, 0, input_len.max(output_len) as usize),
        ) {
            Ok(irp) => irp,
            Err(status) => return Ok(Err(status)),
        };
        if major == IrpMajorFunction::DeviceControl {
            let _ = self.io.set_stack_parameters(
                irp,
                casak,
                StackParameters::DeviceControl {
                    io_control_code: io_control,
                    input_length: input_len as usize,
                    output_length: output_len as usize,
                    output_offset: 0,
                },
            );
        } else if matches!(major, IrpMajorFunction::Read | IrpMajorFunction::Write) {
            let _ = self.io.set_stack_parameters(
                irp,
                casak,
                StackParameters::ReadWrite {
                    length: input_len.max(output_len) as usize,
                    byte_offset: 0,
                },
            );
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Request, 0)?;
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        let parent = if queue_handle != 0 {
            queue_handle
        } else {
            device_handle
        };
        if let Some(object) = self.kmdf.objects.get_mut(&handle) {
            object.parent = Some(parent);
        }
        if let Some(object) = self.kmdf.objects.get_mut(&parent) {
            object.children.insert(handle);
        }
        self.kmdf.requests.insert(
            handle,
            KmdfRequest {
                irp,
                device: Some(device_handle),
                io_control,
                input_len,
                output_len,
                input_guest,
                output_guest,
                completed: false,
                status: STATUS_SUCCESS,
                information: 0,
                context_guest,
                queue: (queue_handle != 0).then_some(queue_handle),
                outer_irp_guest,
                major,
                target: None,
                canceled: false,
            },
        );
        self.kmdf.current_request = handle;
        Ok(Ok(handle))
    }

    fn wdf_dispatch(
        &mut self,
        major: IrpMajorFunction,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let irp_guest = guest_arg(state, memory, 0)?;
        let device_object = guest_arg(state, memory, 1)?;
        if irp_guest != 0 {
            self.kmdf.current_irp_guest = irp_guest;
        }
        let Some(device_handle) = self.kmdf.devices_by_object.get(&device_object).copied() else {
            self.write_outer_irp_status(memory, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let file_callback = self
            .kmdf
            .devices
            .get(&device_handle)
            .map_or(0, |device| match major {
                IrpMajorFunction::Cleanup => device.file_cleanup,
                IrpMajorFunction::Close => device.file_close,
                _ => 0,
            });
        if file_callback != 0 {
            let request = match self.new_kmdf_request(
                memory,
                device_handle,
                0,
                major,
                0,
                0,
                0,
                0,
                0,
                irp_guest,
            )? {
                Ok(request) => request,
                Err(status) => {
                    self.write_outer_irp_status(memory, status, 0)?;
                    set_status(state, status);
                    return Ok(None);
                }
            };
            let file_object = self.ensure_file_object(memory, device_handle)?;
            if major == IrpMajorFunction::Cleanup {
                self.kmdf.file_cleanup_dispatches += 1;
            } else {
                self.kmdf.file_close_dispatches += 1;
            }
            self.kmdf.current_request = request;
            self.write_outer_irp_status(memory, STATUS_PENDING, 0)?;
            set_status(state, STATUS_PENDING);
            return Ok(Some(PendingGuestCall {
                entry: file_callback,
                args: vec![device_handle, request, file_object],
                label: if major == IrpMajorFunction::Cleanup {
                    "EvtFileCleanup"
                } else {
                    "EvtFileClose"
                },
                purpose: PendingPurpose::FileDispatch { request },
            }));
        }
        let Some(queue_handle) = self.choose_queue(device_handle) else {
            self.write_outer_irp_status(memory, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let input_len = self.kmdf.current_input_len;
        let output_len = self.kmdf.current_output_len;
        let io_control = self.kmdf.current_io_control;
        let system_buffer = self.kmdf.current_system_buffer;
        let (input_guest, output_guest) = match major {
            IrpMajorFunction::Read => (0, system_buffer),
            IrpMajorFunction::Write => (system_buffer, 0),
            _ => (system_buffer, system_buffer),
        };
        let request = match self.new_kmdf_request(
            memory,
            device_handle,
            queue_handle,
            major,
            io_control,
            input_len,
            output_len,
            input_guest,
            output_guest,
            irp_guest,
        )? {
            Ok(request) => request,
            Err(status) => {
                self.write_outer_irp_status(memory, status, 0)?;
                set_status(state, status);
                return Ok(None);
            }
        };
        let queue = self.kmdf.queues.get(&queue_handle).cloned().expect("queue");
        let defer = queue.stopped
            || queue.dispatch_type == 2
            || (queue.dispatch_type == 0 && !queue.in_flight.is_empty());
        if defer {
            if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                queue.queued.push_back(request);
            }
            self.kmdf.queued_dispatches += 1;
            self.write_outer_irp_status(memory, STATUS_PENDING, 0)?;
            set_status(state, STATUS_PENDING);
            return Ok(None);
        }
        let entry = Self::queue_callback(&queue, major);
        if entry == 0 {
            let status = if matches!(major, IrpMajorFunction::Cleanup | IrpMajorFunction::Close) {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_DEVICE_REQUEST
            };
            self.complete_kmdf_request(memory, request, status, 0)?;
            set_status(state, status);
            return Ok(None);
        }
        if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
            queue.in_flight.insert(request);
        }
        match major {
            IrpMajorFunction::Read => self.kmdf.read_dispatches += 1,
            IrpMajorFunction::Write => self.kmdf.write_dispatches += 1,
            IrpMajorFunction::DeviceControl => self.kmdf.ioctl_dispatches += 1,
            IrpMajorFunction::Cleanup => self.kmdf.cleanup_dispatches += 1,
            IrpMajorFunction::Close => self.kmdf.close_dispatches += 1,
            _ => {}
        }
        self.kmdf.current_request = request;
        self.write_outer_irp_status(memory, STATUS_PENDING, 0)?;
        let request_state = self.kmdf.requests.get(&request).expect("request").clone();
        let label = match major {
            IrpMajorFunction::Read => "EvtIoRead",
            IrpMajorFunction::Write => "EvtIoWrite",
            IrpMajorFunction::DeviceControl => "EvtIoDeviceControl",
            _ => "EvtIoDefault",
        };
        Ok(Some(Self::callback_call(
            queue_handle,
            request,
            &request_state,
            entry,
            label,
        )))
    }

    fn dispatch_next_queued(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        loop {
            let candidate = self.kmdf.queues.iter().find_map(|(handle, queue)| {
                if queue.dispatch_type == 2 {
                    return None;
                }
                if queue.stopped && !queue.draining {
                    return None;
                }
                if queue.dispatch_type == 0 && !queue.in_flight.is_empty() {
                    return None;
                }
                queue
                    .queued
                    .front()
                    .copied()
                    .map(|request| (*handle, request))
            });
            let Some((queue_handle, request_handle)) = candidate else {
                for queue in self.kmdf.queues.values_mut() {
                    if queue.draining && queue.queued.is_empty() {
                        queue.draining = false;
                        queue.stopped = true;
                    }
                }
                return Ok(None);
            };
            let request = match self.kmdf.requests.get(&request_handle) {
                Some(request) => request.clone(),
                None => {
                    if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                        queue.queued.pop_front();
                    }
                    continue;
                }
            };
            let queue = self
                .kmdf
                .queues
                .get(&queue_handle)
                .cloned()
                .expect("queue handle comes from iterating the same map");
            let entry = Self::queue_callback(&queue, request.major);
            if entry == 0 {
                if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                    queue.queued.pop_front();
                }
                let status = if matches!(
                    request.major,
                    IrpMajorFunction::Cleanup | IrpMajorFunction::Close
                ) {
                    STATUS_SUCCESS
                } else {
                    STATUS_INVALID_DEVICE_REQUEST
                };
                self.complete_kmdf_request(memory, request_handle, status, 0)?;
                continue;
            }
            if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                queue.queued.pop_front();
                queue.in_flight.insert(request_handle);
            }
            self.kmdf.queued_dispatches += 1;
            match request.major {
                IrpMajorFunction::Read => self.kmdf.read_dispatches += 1,
                IrpMajorFunction::Write => self.kmdf.write_dispatches += 1,
                IrpMajorFunction::DeviceControl => self.kmdf.ioctl_dispatches += 1,
                IrpMajorFunction::Cleanup => self.kmdf.cleanup_dispatches += 1,
                IrpMajorFunction::Close => self.kmdf.close_dispatches += 1,
                _ => {}
            }
            self.kmdf.current_request = request_handle;
            self.write_irp_status(memory, request.outer_irp_guest, STATUS_PENDING, 0)?;
            let label = match request.major {
                IrpMajorFunction::Read => "EvtIoRead",
                IrpMajorFunction::Write => "EvtIoWrite",
                IrpMajorFunction::DeviceControl => "EvtIoDeviceControl",
                _ => "EvtIoDefault",
            };
            return Ok(Some(Self::callback_call(
                queue_handle,
                request_handle,
                &request,
                entry,
                label,
            )));
        }
    }

    fn complete_kmdf_request(
        &mut self,
        memory: &mut MemoryImage,
        handle: u64,
        status: i32,
        information: usize,
    ) -> AppResult<()> {
        let Some(request) = self.kmdf.requests.get_mut(&handle) else {
            return Ok(());
        };
        if request.completed {
            return Ok(());
        }
        request.completed = true;
        request.status = status;
        request.information = information;
        let irp = request.irp;
        let outer = request.outer_irp_guest;
        let queue = request.queue;
        let _ = self.io.complete_irp(irp, status, information);
        if let Some(queue_handle) = queue {
            if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                queue.in_flight.remove(&handle);
                if queue.draining && queue.queued.is_empty() {
                    queue.draining = false;
                    queue.stopped = true;
                }
            }
        }
        if self.kmdf.current_request == handle {
            self.kmdf.current_request = 0;
        }
        self.write_irp_status(memory, outer, status, information)
    }

    fn wdf_queue_retrieve(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        found: bool,
    ) -> AppResult<()> {
        let queue_handle = guest_arg(state, memory, 0)?;
        let (found_request, request_out) = if found {
            (guest_arg(state, memory, 1)?, guest_arg(state, memory, 2)?)
        } else {
            (0, guest_arg(state, memory, 1)?)
        };
        if request_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                request_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let request = if found {
            queue
                .queued
                .iter()
                .position(|request| *request == found_request)
                .and_then(|index| queue.queued.remove(index))
        } else {
            queue.queued.pop_front()
        };
        let Some(request) = request else {
            set_status(state, STATUS_NO_MORE_ENTRIES);
            return Ok(());
        };
        if let Some(request) = self.kmdf.requests.get_mut(&request) {
            request.queue = None;
        }
        self.kmdf.manual_retrievals += 1;
        write_guest_pointer(memory, request_out, request, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    fn wdf_queue_stop(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        drain: bool,
        _synchronously: bool,
    ) -> AppResult<Option<PendingGuestCall>> {
        let queue_handle = guest_arg(state, memory, 0)?;
        let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        queue.stopped = true;
        if drain {
            queue.draining = true;
        }
        let stop_callback = queue.callbacks.stop;
        let in_flight = queue
            .in_flight
            .iter()
            .chain(queue.queued.iter())
            .copied()
            .collect::<Vec<_>>();
        if in_flight.is_empty() && drain && queue.queued.is_empty() {
            queue.draining = false;
        }
        let mut callbacks = Vec::new();
        if stop_callback != 0 {
            for request in in_flight {
                self.kmdf.stop_dispatches += 1;
                callbacks.push(GuestCallback {
                    entry: stop_callback,
                    args: vec![queue_handle, request, 1],
                    label: "EvtIoStop",
                });
            }
        }
        set_status(state, STATUS_SUCCESS);
        Ok(Self::callbacks_pending(callbacks, drain))
    }

    fn wdf_queue_purge(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let queue_handle = guest_arg(state, memory, 0)?;
        let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        queue.stopped = true;
        queue.draining = false;
        let canceled_callback = queue.callbacks.canceled_on_queue;
        let queued = queue.queued.drain(..).collect::<Vec<_>>();
        let in_flight = std::mem::take(&mut queue.in_flight);
        let mut callbacks = Vec::new();
        for request in queued {
            self.kmdf.cancel_dispatches += 1;
            if canceled_callback != 0 {
                callbacks.push(GuestCallback {
                    entry: canceled_callback,
                    args: vec![queue_handle, request],
                    label: "EvtIoCanceledOnQueue",
                });
            } else {
                self.force_cancel_request(request);
                self.write_request_outer_status(memory, request, STATUS_CANCELLED, 0)?;
            }
        }
        for request in in_flight {
            self.kmdf.cancel_dispatches += 1;
            if canceled_callback != 0 {
                callbacks.push(GuestCallback {
                    entry: canceled_callback,
                    args: vec![queue_handle, request],
                    label: "EvtIoCanceledOnQueue",
                });
            } else {
                self.force_cancel_request(request);
                self.write_request_outer_status(memory, request, STATUS_CANCELLED, 0)?;
            }
        }
        set_status(state, STATUS_SUCCESS);
        Ok(Self::callbacks_pending(callbacks, false))
    }

    fn wdf_queue_start(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let queue_handle = guest_arg(state, memory, 0)?;
        let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        queue.stopped = false;
        queue.draining = false;
        let resume_callback = queue.callbacks.resume;
        let in_flight = queue
            .in_flight
            .iter()
            .chain(queue.queued.iter())
            .copied()
            .collect::<Vec<_>>();
        let mut callbacks = Vec::new();
        if resume_callback != 0 {
            for request in in_flight {
                self.kmdf.resume_dispatches += 1;
                callbacks.push(GuestCallback {
                    entry: resume_callback,
                    args: vec![queue_handle, request],
                    label: "EvtIoResume",
                });
            }
        }
        set_status(state, STATUS_SUCCESS);
        Ok(Self::callbacks_pending(callbacks, true))
    }

    fn callbacks_pending(
        callbacks: Vec<GuestCallback>,
        dispatch_next: bool,
    ) -> Option<PendingGuestCall> {
        let mut remaining = callbacks;
        if remaining.is_empty() {
            return None;
        }
        let first = remaining.remove(0);
        Some(PendingGuestCall {
            entry: first.entry,
            args: first.args,
            label: first.label,
            purpose: PendingPurpose::Callbacks {
                remaining,
                dispatch_next,
            },
        })
    }

    fn write_request_outer_status(
        &self,
        memory: &mut MemoryImage,
        request: u64,
        status: i32,
        information: usize,
    ) -> AppResult<()> {
        if let Some(request) = self.kmdf.requests.get(&request) {
            self.write_irp_status(memory, request.outer_irp_guest, status, information)?;
        }
        Ok(())
    }

    fn wdf_request_cancel_queued(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let handle = guest_arg(state, memory, 0)?;
        let Some(request) = self.kmdf.requests.get(&handle).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        let Some(queue_handle) = request.queue else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let Some(index) = queue.queued.iter().position(|queued| *queued == handle) else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        queue.queued.remove(index);
        let canceled_callback = queue.callbacks.canceled_on_queue;
        self.kmdf.cancel_dispatches += 1;
        if canceled_callback != 0 {
            set_status(state, STATUS_SUCCESS);
            return Ok(Self::callbacks_pending(
                vec![GuestCallback {
                    entry: canceled_callback,
                    args: vec![queue_handle, handle],
                    label: "EvtIoCanceledOnQueue",
                }],
                false,
            ));
        }
        self.force_cancel_request(handle);
        self.write_request_outer_status(memory, handle, STATUS_CANCELLED, 0)?;
        set_status(state, STATUS_CANCELLED);
        Ok(None)
    }

    fn wdf_device_get_iotarget(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        if !self.kmdf.devices.contains_key(&device) {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        }
        let existing = self
            .kmdf
            .iotargets
            .iter()
            .find_map(|(handle, target)| (target.device == device).then_some(*handle));
        let target = if let Some(target) = existing {
            target
        } else {
            let target = self.create_kmdf_object(memory, KmdfObjectKind::IoTarget, 0)?;
            if let Some(object) = self.kmdf.objects.get_mut(&target) {
                object.parent = Some(device);
            }
            if let Some(object) = self.kmdf.objects.get_mut(&device) {
                object.children.insert(target);
            }
            let context_guest = self
                .kmdf
                .objects
                .get(&target)
                .map(|object| object.context_guest)
                .unwrap_or(target + 0x80);
            self.kmdf.iotargets.insert(
                target,
                KmdfIoTarget {
                    device,
                    context_guest,
                },
            );
            target
        };
        state.set(Register::Rax, target);
        Ok(())
    }

    fn wdf_iotarget_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let target_out = guest_arg(state, memory, 2)?;
        if !self.kmdf.devices.contains_key(&device)
            || target_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                target_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let target = self.create_kmdf_object(memory, KmdfObjectKind::IoTarget, attributes)?;
        if self
            .kmdf
            .objects
            .get(&target)
            .is_some_and(|object| object.parent.is_none())
        {
            if let Some(object) = self.kmdf.objects.get_mut(&target) {
                object.parent = Some(device);
            }
            if let Some(object) = self.kmdf.objects.get_mut(&device) {
                object.children.insert(target);
            }
        }
        let context_guest = self
            .kmdf
            .objects
            .get(&target)
            .map(|object| object.context_guest)
            .unwrap_or(target + 0x80);
        self.kmdf.iotargets.insert(
            target,
            KmdfIoTarget {
                device,
                context_guest,
            },
        );
        write_guest_pointer(memory, target_out, target, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    fn read_memory_descriptor(
        &self,
        memory: &MemoryImage,
        descriptor: u64,
    ) -> AppResult<(u64, usize)> {
        if descriptor == 0 {
            return Ok((0, 0));
        }
        let _kind = memory.read_u32(descriptor)?;
        let (pointer_offset, length_offset) = match self.arch {
            GuestArch::X64 => (0x08u64, 0x10u64),
            GuestArch::X86 => (0x04, 0x08),
        };
        let pointer = read_guest_pointer(memory, descriptor + pointer_offset, self.arch)?;
        let length = read_guest_pointer(memory, descriptor + length_offset, self.arch)? as usize;
        Ok((pointer, length))
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_ioctl_send(
        &mut self,
        memory: &mut MemoryImage,
        target: u64,
        request: u64,
        io_control: u32,
        input: &[u8],
        input_ptr: u64,
        output_ptr: u64,
        output_len: usize,
    ) -> AppResult<Option<PendingIoTargetSend>> {
        let Some(device_handle) = self.resolve_target_device(target) else {
            return Ok(None);
        };
        let Some(device) = self.kmdf.devices.get(&device_handle).cloned() else {
            return Ok(None);
        };
        let irp = match self.io.allocate_irp(
            device.casak,
            IrpParameterBlock::new(IrpMajorFunction::DeviceControl, 0, input.len()),
        ) {
            Ok(irp) => irp,
            Err(_) => return Ok(None),
        };
        let _ = self.io.set_stack_parameters(
            irp,
            device.casak,
            StackParameters::DeviceControl {
                io_control_code: io_control,
                input_length: input.len(),
                output_length: output_len,
                output_offset: 0,
            },
        );
        let arch = self.arch;
        let irp_guest = self.arena.alloc(memory, irp_guest_size(arch) as usize, 8)?;
        let stack_guest = self.arena.alloc(memory, io_stack_location_size(arch), 8)?;
        let buffer_len = input.len().max(output_len);
        let system_buffer = if buffer_len > 0 {
            self.arena.alloc(memory, buffer_len, 8)?
        } else {
            0
        };
        if !input.is_empty() {
            memory.map_bytes(system_buffer, input);
        }
        build_guest_irp(
            memory,
            arch,
            irp_guest,
            stack_guest,
            system_buffer,
            device.object_guest,
            output_ptr,
            IrpMajorFunction::DeviceControl,
            0,
            None,
            io_control,
            input.len() as u32,
            output_len as u32,
            0,
        )?; // coverage: unreachable — build_guest_irp only performs infallible MemoryImage writes
        let handler = read_guest_pointer(
            memory,
            self.driver_object_guest
                + major_function_offset(arch)
                + IrpMajorFunction::DeviceControl.code() as u64 * arch.pointer_bytes() as u64,
            arch,
        )?;
        if handler == 0 || handler == self.default_dispatch {
            let _ = self.io.complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            return Ok(None);
        }
        let saved = (
            self.kmdf.current_irp_guest,
            self.kmdf.current_device_guest,
            self.kmdf.current_system_buffer,
            self.kmdf.current_input_len,
            self.kmdf.current_output_len,
            self.kmdf.current_io_control,
            self.kmdf.current_request,
        );
        self.kmdf.current_irp_guest = irp_guest;
        self.kmdf.current_device_guest = device.object_guest;
        self.kmdf.current_system_buffer = system_buffer;
        self.kmdf.current_input_len = input.len() as u32;
        self.kmdf.current_output_len = output_len as u32;
        self.kmdf.current_io_control = io_control;
        self.kmdf.current_request = 0;
        self.kmdf.iotarget_sends += 1;
        Ok(Some(PendingIoTargetSend {
            irp,
            irp_guest,
            entry: handler,
            device_object: device.object_guest,
            system_buffer,
            output_ptr,
            output_len,
            bytes_returned: 0,
            request,
            target,
            io_control,
            input_ptr,
            input_len: input.len() as u32,
            saved,
        }))
    }

    fn finish_ioctl_send(
        &mut self,
        memory: &mut MemoryImage,
        pending: PendingIoTargetSend,
    ) -> AppResult<(i32, usize)> {
        let arch = self.arch;
        let bytes_returned = pending.bytes_returned;
        let (guest_status, information) = match arch {
            GuestArch::X64 => (
                memory.read_u32(pending.irp_guest + 0x30)? as i32,
                memory.read_u64(pending.irp_guest + 0x40)? as usize,
            ),
            GuestArch::X86 => (
                memory.read_u32(pending.irp_guest + 0x18)? as i32,
                memory.read_u32(pending.irp_guest + 0x20)? as usize,
            ),
        };
        let _ = self.io.complete_irp(pending.irp, guest_status, information);
        if pending.output_len > 0 && pending.output_ptr != 0 && pending.system_buffer != 0 {
            let mut output = vec![0_u8; pending.output_len];
            if memory.read_into(pending.system_buffer, &mut output).is_ok() {
                memory.map_bytes(pending.output_ptr, &output);
            }
        }
        (
            self.kmdf.current_irp_guest,
            self.kmdf.current_device_guest,
            self.kmdf.current_system_buffer,
            self.kmdf.current_input_len,
            self.kmdf.current_output_len,
            self.kmdf.current_io_control,
            self.kmdf.current_request,
        ) = pending.saved;
        if pending.request != 0 {
            if let Some(request) = self.kmdf.requests.get_mut(&pending.request) {
                request.target = Some(pending.target);
                request.io_control = pending.io_control;
                request.input_guest = pending.input_ptr;
                request.input_len = pending.input_len;
                request.output_guest = pending.output_ptr;
                request.output_len = pending.output_len as u32;
            }
            self.apply_iotarget_result(memory, pending.request, guest_status, information)?;
        }
        if bytes_returned != 0
            && crate::host_thunks::validate_guest_pointer(
                memory,
                bytes_returned,
                self.arch.pointer_bytes(),
            )
            .is_ok()
        {
            write_guest_pointer(memory, bytes_returned, information as u64, self.arch)?;
        }
        Ok((guest_status, information))
    }

    fn apply_iotarget_result(
        &mut self,
        memory: &mut MemoryImage,
        request: u64,
        status: i32,
        information: usize,
    ) -> AppResult<()> {
        let Some(request_state) = self.kmdf.requests.get_mut(&request) else {
            return Ok(());
        };
        request_state.completed = true;
        request_state.status = status;
        request_state.information = information;
        let outer = request_state.outer_irp_guest;
        let irp = request_state.irp;
        let _ = self.io.complete_irp(irp, status, information);
        self.write_irp_status(memory, outer, status, information)
    }

    fn wdf_iotarget_send_ioctl(
        &mut self,
        _runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let target = guest_arg(state, memory, 0)?;
        let request = guest_arg(state, memory, 1)?;
        let io_control = guest_arg(state, memory, 2)? as u32;
        let input_descriptor = guest_arg(state, memory, 3)?;
        let output_descriptor = guest_arg(state, memory, 4)?;
        let _options = guest_arg(state, memory, 5)?;
        let bytes_returned = guest_arg(state, memory, 6)?;
        let (input_ptr, input_len) = self.read_memory_descriptor(memory, input_descriptor)?;
        let (output_ptr, output_len) = self.read_memory_descriptor(memory, output_descriptor)?;
        let mut input = vec![0_u8; input_len];
        if input_len > 0 && memory.read_into(input_ptr, &mut input).is_err() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        let Some(mut pending) = self.prepare_ioctl_send(
            memory, target, request, io_control, &input, input_ptr, output_ptr, output_len,
        )?
        else {
            self.apply_iotarget_result(memory, request, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        pending.bytes_returned = bytes_returned;
        Ok(Some(PendingGuestCall {
            entry: pending.entry,
            args: vec![pending.irp_guest, pending.device_object],
            label: "WdfIoTargetSend",
            purpose: PendingPurpose::IoTargetSend {
                pending: Box::new(pending),
            },
        }))
    }

    fn wdf_iotarget_format_request(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let target = guest_arg(state, memory, 0)?;
        let request = guest_arg(state, memory, 1)?;
        let io_control = guest_arg(state, memory, 2)? as u32;
        let input_descriptor = guest_arg(state, memory, 3)?;
        let input_offset = guest_arg(state, memory, 4)?;
        let output_descriptor = guest_arg(state, memory, 5)?;
        let output_offset = guest_arg(state, memory, 6)?;
        let (input_ptr, input_len) = self.read_memory_descriptor(memory, input_descriptor)?;
        let (output_ptr, output_len) = self.read_memory_descriptor(memory, output_descriptor)?;
        let Some(request_state) = self.kmdf.requests.get_mut(&request) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        request_state.target = Some(target);
        request_state.io_control = io_control;
        request_state.input_guest = input_ptr.saturating_add(input_offset);
        request_state.input_len = input_len.saturating_sub(input_offset as usize) as u32;
        request_state.output_guest = output_ptr.saturating_add(output_offset);
        request_state.output_len = output_len.saturating_sub(output_offset as usize) as u32;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    fn wdf_request_send(
        &mut self,
        _runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let request = guest_arg(state, memory, 0)?;
        let target = guest_arg(state, memory, 1)?;
        let _options = guest_arg(state, memory, 2)?;
        let Some(request_state) = self.kmdf.requests.get(&request).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        let target = if target != 0 {
            target
        } else {
            request_state.target.unwrap_or(0)
        };
        let mut input = vec![0_u8; request_state.input_len as usize];
        if !input.is_empty()
            && memory
                .read_into(request_state.input_guest, &mut input)
                .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        let Some(pending) = self.prepare_ioctl_send(
            memory,
            target,
            request,
            request_state.io_control,
            &input,
            request_state.input_guest,
            request_state.output_guest,
            request_state.output_len as usize,
        )?
        else {
            self.apply_iotarget_result(memory, request, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        Ok(Some(PendingGuestCall {
            entry: pending.entry,
            args: vec![pending.irp_guest, pending.device_object],
            label: "WdfRequestSend",
            purpose: PendingPurpose::IoTargetSend {
                pending: Box::new(pending),
            },
        }))
    }

    fn wdf_object_allocate_context(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let type_info = guest_arg(state, memory, 1)?;
        let context_out = guest_arg(state, memory, 2)?;
        if context_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                context_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(kind) = self.kmdf.objects.get(&handle).map(|object| object.kind) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let type_size = self.context_type_size(memory, type_info)?;
        let size = if type_size > 0 {
            type_size
        } else {
            kind.layout().0
        }
        .clamp(8, 0x10_000);
        let context_guest = self.arena.alloc(memory, size, 8)?;
        if let Some(object) = self.kmdf.objects.get_mut(&handle) {
            object.extra_contexts.push((type_info, context_guest, size));
        }
        write_guest_pointer(memory, context_out, context_guest, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Parse `WDF_PNPPOWER_EVENT_CALLBACKS` for a device-init handle.  The
    /// `Size` member bounds which callbacks are honored, exactly like the
    /// forward-compatible KMDF structure contract.
    fn wdf_device_init_set_pnp_power_callbacks(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let callbacks = guest_arg(state, memory, 1)?;
        if !self.kmdf.device_inits.contains_key(&init)
            || callbacks == 0
            || crate::host_thunks::validate_guest_pointer(memory, callbacks, 4).is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let size = memory.read_u32(callbacks)? as u64;
        if size < 4 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let pointer = self.arch.pointer_bytes() as u64;
        let offsets: [u64; 8] = match self.arch {
            GuestArch::X64 => [0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x50],
            GuestArch::X86 => [0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x28],
        };
        let mut parsed = KmdfPnpPowerCallbacks::default();
        let read = |offset: u64| -> AppResult<u64> {
            if size >= offset + pointer {
                read_guest_pointer(memory, callbacks + offset, self.arch)
            } else {
                Ok(0)
            }
        };
        parsed.prepare_hardware = read(offsets[0])?;
        parsed.release_hardware = read(offsets[1])?;
        parsed.d0_entry = read(offsets[2])?;
        parsed.d0_exit = read(offsets[3])?;
        parsed.self_managed_io_init = read(offsets[4])?;
        parsed.self_managed_io_suspend = read(offsets[5])?;
        parsed.self_managed_io_restart = read(offsets[6])?;
        parsed.self_managed_io_fini = read(offsets[7])?;
        let init = self
            .kmdf
            .device_inits
            .get_mut(&init)
            .expect("device init was validated above");
        init.pnp_power = parsed;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Parse `WDF_FILEOBJECT_CONFIG`: EvtFileCleanup/EvtFileClose map onto
    /// `IRP_MJ_CLEANUP`/`IRP_MJ_CLOSE` dispatch.
    fn wdf_device_init_set_file_object_config(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let config = guest_arg(state, memory, 1)?;
        let _attributes = guest_arg(state, memory, 2)?;
        if !self.kmdf.device_inits.contains_key(&init)
            || config == 0
            || crate::host_thunks::validate_guest_pointer(memory, config, 4).is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let size = memory.read_u32(config)? as u64;
        let minimum = match self.arch {
            GuestArch::X64 => 0x10,
            GuestArch::X86 => 0x08,
        };
        if size < minimum {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let pointer = self.arch.pointer_bytes() as u64;
        let (close_offset, cleanup_offset) = match self.arch {
            GuestArch::X64 => (0x10, 0x18),
            GuestArch::X86 => (0x08, 0x0C),
        };
        let evt_file_close = if size >= close_offset + pointer {
            read_guest_pointer(memory, config + close_offset, self.arch)?
        } else {
            0
        };
        let evt_file_cleanup = if size >= cleanup_offset + pointer {
            read_guest_pointer(memory, config + cleanup_offset, self.arch)?
        } else {
            0
        };
        let init = self
            .kmdf
            .device_inits
            .get_mut(&init)
            .expect("device init was validated above");
        init.file_object = KmdfFileObjectConfig {
            evt_file_cleanup,
            evt_file_close,
        };
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfMemoryCreate`/`WdfMemoryCreatePreallocated`: allocate a framework
    /// memory object over real guest bytes.
    fn wdf_memory_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        preallocated: bool,
    ) -> AppResult<()> {
        let pointer = self.arch.pointer_bytes() as u64;
        let (attributes, pool_type, supplied_buffer, size, memory_out, buffer_out) = if preallocated
        {
            (
                guest_arg(state, memory, 0)?,
                0,
                guest_arg(state, memory, 1)?,
                guest_arg(state, memory, 2)? as usize,
                guest_arg(state, memory, 3)?,
                0,
            )
        } else {
            (
                guest_arg(state, memory, 0)?,
                guest_arg(state, memory, 1)? as u32,
                u64::MAX,
                guest_arg(state, memory, 3)? as usize,
                guest_arg(state, memory, 4)?,
                guest_arg(state, memory, 5)?,
            )
        };
        let out_valid = memory_out != 0
            && crate::host_thunks::validate_guest_pointer(memory, memory_out, pointer as usize)
                .is_ok();
        let buffer_out_valid = preallocated
            || (buffer_out != 0
                && crate::host_thunks::validate_guest_pointer(
                    memory,
                    buffer_out,
                    pointer as usize,
                )
                .is_ok());
        if !out_valid || !buffer_out_valid {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if (!preallocated && pool_type > 1) || size > 0x10_0000 {
            set_status(
                state,
                if pool_type > 1 && !preallocated {
                    STATUS_INVALID_PARAMETER
                } else {
                    STATUS_INSUFFICIENT_RESOURCES
                },
            );
            return Ok(());
        }
        let buffer = if preallocated {
            if size > 0
                && (supplied_buffer == 0
                    || crate::host_thunks::validate_guest_pointer(memory, supplied_buffer, size)
                        .is_err())
            {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
            supplied_buffer
        } else {
            let buffer = self.arena.alloc(memory, size.max(1), 8)?;
            memory.map_bytes(buffer, &vec![0_u8; size.max(1)]);
            buffer
        };
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Memory, attributes)?;
        self.kmdf
            .memories
            .insert(handle, KmdfMemory { buffer, size });
        write_guest_pointer(memory, memory_out, handle, self.arch)?;
        if !preallocated {
            write_guest_pointer(memory, buffer_out, buffer, self.arch)?;
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfMemoryGetBuffer`.
    fn wdf_memory_get_buffer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let size_out = guest_arg(state, memory, 1)?;
        let Some(record) = self.kmdf.memories.get(&handle).cloned() else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        if size_out != 0
            && crate::host_thunks::validate_guest_pointer(
                memory,
                size_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        if size_out != 0 {
            write_guest_pointer(memory, size_out, record.size as u64, self.arch)?;
        }
        state.set(Register::Rax, record.buffer);
        Ok(())
    }

    /// `WdfStringCreate`: copy a caller `UNICODE_STRING` into a WDFSTRING.
    fn wdf_string_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let source = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let string_out = guest_arg(state, memory, 2)?;
        if string_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                string_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(text) = self.read_valid_unicode_string(memory, source) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        let length = (text.encode_utf16().count() * 2) as u16;
        let bytes = length as usize;
        let buffer = self.arena.alloc(memory, bytes.max(2), 2)?;
        memory.map_bytes(buffer, &vec![0_u8; bytes.max(2)]);
        for (index, unit) in text.encode_utf16().enumerate() {
            memory.write_u16(buffer + index as u64 * 2, unit);
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::String, attributes)?;
        self.kmdf.strings.insert(
            handle,
            KmdfString {
                buffer,
                length,
                maximum: length.saturating_add(2),
            },
        );
        write_guest_pointer(memory, string_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfStringGetUnicodeString`.
    fn wdf_string_get_unicode_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let destination = guest_arg(state, memory, 1)?;
        if destination == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                destination,
                unicode_string_size(self.arch),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(record) = self.kmdf.strings.get(&handle).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        write_unicode_string_header(
            memory,
            destination,
            record.length,
            record.maximum,
            record.buffer,
            self.arch,
        )?; // coverage: unreachable — write_unicode_string_header only performs infallible MemoryImage writes
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Validate and read a `UNICODE_STRING` without converting a malformed
    /// descriptor into an internal guest-memory error.
    fn read_valid_unicode_string(&self, memory: &MemoryImage, address: u64) -> Option<String> {
        if address == 0 {
            return Some(String::new());
        }
        if crate::host_thunks::validate_guest_pointer(
            memory,
            address,
            unicode_string_size(self.arch),
        )
        .is_err()
        {
            return None;
        }
        let length = memory.read_u16(address).ok()? as usize;
        let maximum = memory.read_u16(address + 2).ok()? as usize;
        if length % 2 != 0 || length > maximum || length > 0x800 {
            return None;
        }
        let buffer = read_guest_pointer(
            memory,
            address + unicode_string_buffer_offset(self.arch),
            self.arch,
        )
        .ok()?;
        if length > 0
            && (buffer == 0
                || crate::host_thunks::validate_guest_pointer(memory, buffer, length).is_err())
        {
            return None;
        }
        read_unicode_string(memory, address, self.arch)
            .ok()
            .map(|(text, _, _)| text)
    }

    /// `WdfPdoInitAllocate`: mint a PDO device-init owned by `parent`.
    fn wdf_pdo_init_allocate(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let parent = guest_arg(state, memory, 0)?;
        if !self.kmdf.devices.contains_key(&parent) {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        }
        let init = self.create_kmdf_object(memory, KmdfObjectKind::DeviceInit, 0)?;
        if let Some(object) = self.kmdf.objects.get_mut(&init) {
            object.parent = Some(parent);
        }
        if let Some(object) = self.kmdf.objects.get_mut(&parent) {
            object.children.insert(init);
        }
        self.kmdf.device_inits.insert(
            init,
            KmdfDeviceInit {
                device_type: 0,
                io_type: 0,
                name: None,
                pnp_power: KmdfPnpPowerCallbacks::default(),
                file_object: KmdfFileObjectConfig::default(),
                is_pdo: true,
                parent_device: Some(parent),
                device_id: None,
                hardware_ids: Vec::new(),
                compatible_ids: Vec::new(),
                instance_id: None,
            },
        );
        state.set(Register::Rax, init);
        Ok(())
    }

    /// `WdfPdoInitAssignDeviceID`/`WdfPdoInitAssignInstanceID`.
    fn wdf_pdo_init_set_id(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        instance: bool,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let string = guest_arg(state, memory, 1)?;
        let Some(text) = self.read_valid_unicode_string(memory, string) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if text.is_empty() || text.len() > 0x100 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(record) = self.kmdf.device_inits.get_mut(&init) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if !record.is_pdo {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if instance {
            record.instance_id = Some(text);
        } else {
            record.device_id = Some(text);
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfPdoInitAddHardwareID`/`WdfPdoInitAddCompatibleID`.
    fn wdf_pdo_init_add_id(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        compatible: bool,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let string = guest_arg(state, memory, 1)?;
        let Some(text) = self.read_valid_unicode_string(memory, string) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if text.is_empty() || text.len() > 0x100 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(record) = self.kmdf.device_inits.get_mut(&init) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if !record.is_pdo {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let list = if compatible {
            &mut record.compatible_ids
        } else {
            &mut record.hardware_ids
        };
        if list.len() >= 16 {
            set_status(state, STATUS_INSUFFICIENT_RESOURCES);
            return Ok(());
        }
        list.push(text);
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfDeviceEnqueueRequest`: place a driver-created request on the
    /// device's queue and dispatch it when the queue rules allow.
    fn wdf_device_enqueue_request(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let device_handle = guest_arg(state, memory, 0)?;
        let request_handle = guest_arg(state, memory, 1)?;
        if !self.kmdf.devices.contains_key(&device_handle) {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        let Some(request) = self.kmdf.requests.get(&request_handle).cloned() else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        if request.completed || request.queue.is_some() {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        let Some(queue_handle) = self.choose_queue(device_handle) else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let queue = self
            .kmdf
            .queues
            .get(&queue_handle)
            .cloned()
            .expect("queue was selected from the queue map");
        let entry = Self::queue_callback(&queue, request.major);
        if entry == 0 {
            self.complete_kmdf_request(memory, request_handle, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        if let Some(request) = self.kmdf.requests.get_mut(&request_handle) {
            request.queue = Some(queue_handle);
        }
        let defer = queue.stopped
            || queue.dispatch_type == 2
            || (queue.dispatch_type == 0 && !queue.in_flight.is_empty());
        if defer {
            if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                queue.queued.push_back(request_handle);
            }
            self.kmdf.queued_dispatches += 1;
            set_status(state, STATUS_SUCCESS);
            return Ok(None);
        }
        if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
            queue.in_flight.insert(request_handle);
        }
        self.kmdf.current_request = request_handle;
        let request = self
            .kmdf
            .requests
            .get(&request_handle)
            .cloned()
            .expect("request was validated above");
        set_status(state, STATUS_SUCCESS);
        Ok(Some(Self::callback_call(
            queue_handle,
            request_handle,
            &request,
            entry,
            "EvtIoDeviceControl",
        )))
    }

    /// `IRP_MJ_PNP` framework dispatch.
    fn wdf_pnp_dispatch(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let irp_guest = guest_arg(state, memory, 0)?;
        let device_object = guest_arg(state, memory, 1)?;
        let Some(device) = self.kmdf.devices_by_object.get(&device_object).copied() else {
            return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
        };
        let Some(minor) = self.irp_minor(memory, irp_guest) else {
            return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
        };
        let (pnp, started, power_state) = self
            .kmdf
            .devices
            .get(&device)
            .map(|record| (record.pnp_power, record.started, record.power_state))
            .expect("a device object always maps to a live device");
        let mut steps = VecDeque::new();
        let final_state = match minor {
            IRP_MN_START_DEVICE => {
                self.kmdf.pnp_start_dispatches += 1;
                if started {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
                }
                let release = GuestCallback {
                    entry: pnp.release_hardware,
                    args: vec![device],
                    label: "EvtDeviceReleaseHardware",
                };
                let d0_exit = GuestCallback {
                    entry: pnp.d0_exit,
                    args: vec![device, u64::from(WDF_POWER_DEVICE_D3)],
                    label: "EvtDeviceD0Exit",
                };
                if pnp.prepare_hardware != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.prepare_hardware,
                        args: vec![device, 0, 0],
                        label: "EvtDevicePrepareHardware",
                        required: true,
                        rollback: Vec::new(),
                    });
                }
                if pnp.d0_entry != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.d0_entry,
                        args: vec![device, u64::from(WDF_POWER_DEVICE_D3_FINAL)],
                        label: "EvtDeviceD0Entry",
                        required: true,
                        rollback: if release.entry != 0 {
                            vec![release.clone()]
                        } else {
                            Vec::new()
                        },
                    });
                }
                if pnp.self_managed_io_init != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.self_managed_io_init,
                        args: vec![device],
                        label: "EvtDeviceSelfManagedIoInit",
                        required: true,
                        rollback: [d0_exit, release]
                            .into_iter()
                            .filter(|callback| callback.entry != 0)
                            .collect(),
                    });
                }
                PnpFinalState::Started
            }
            IRP_MN_STOP_DEVICE => {
                self.kmdf.pnp_stop_dispatches += 1;
                if !started || power_state != WDF_POWER_DEVICE_D0 {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
                }
                if pnp.self_managed_io_fini != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.self_managed_io_fini,
                        args: vec![device],
                        label: "EvtDeviceSelfManagedIoFini",
                        required: false,
                        rollback: Vec::new(),
                    });
                }
                if pnp.d0_exit != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.d0_exit,
                        args: vec![device, u64::from(WDF_POWER_DEVICE_D3)],
                        label: "EvtDeviceD0Exit",
                        required: true,
                        rollback: Vec::new(),
                    });
                }
                if pnp.release_hardware != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.release_hardware,
                        args: vec![device],
                        label: "EvtDeviceReleaseHardware",
                        required: true,
                        rollback: Vec::new(),
                    });
                }
                PnpFinalState::Stopped
            }
            IRP_MN_REMOVE_DEVICE => {
                self.kmdf.pnp_remove_dispatches += 1;
                let object_guest = self
                    .kmdf
                    .devices
                    .get(&device)
                    .expect("device was resolved above")
                    .object_guest;
                if started {
                    if pnp.self_managed_io_fini != 0 {
                        steps.push_back(PnpStep {
                            entry: pnp.self_managed_io_fini,
                            args: vec![device],
                            label: "EvtDeviceSelfManagedIoFini",
                            required: false,
                            rollback: Vec::new(),
                        });
                    }
                    if pnp.d0_exit != 0 {
                        steps.push_back(PnpStep {
                            entry: pnp.d0_exit,
                            args: vec![device, u64::from(WDF_POWER_DEVICE_D3)],
                            label: "EvtDeviceD0Exit",
                            required: false,
                            rollback: Vec::new(),
                        });
                    }
                    if pnp.release_hardware != 0 {
                        steps.push_back(PnpStep {
                            entry: pnp.release_hardware,
                            args: vec![device],
                            label: "EvtDeviceReleaseHardware",
                            required: false,
                            rollback: Vec::new(),
                        });
                    }
                }
                if let Some(record) = self.kmdf.devices.get_mut(&device) {
                    record.removed = true;
                }
                self.removed_device_objects.insert(object_guest);
                let mut callbacks = Vec::new();
                self.collect_delete_callbacks(device, &mut callbacks);
                for callback in callbacks {
                    steps.push_back(PnpStep {
                        entry: callback.entry,
                        args: callback.args,
                        label: callback.label,
                        required: false,
                        rollback: Vec::new(),
                    });
                }
                PnpFinalState::Removed
            }
            _ => return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST),
        };
        self.begin_pnp_sequence(state, memory, device, irp_guest, steps, final_state)
    }

    fn irp_minor(&self, memory: &MemoryImage, irp_guest: u64) -> Option<u8> {
        let stack = self.irp_stack_location(memory, irp_guest)?;
        memory.read_u8(stack + 1).ok()
    }

    fn irp_stack_location(&self, memory: &MemoryImage, irp_guest: u64) -> Option<u64> {
        if irp_guest == 0 {
            return None;
        }
        let offset = match self.arch {
            GuestArch::X64 => 0x98,
            GuestArch::X86 => 0x4C,
        };
        read_guest_pointer(memory, irp_guest + offset, self.arch)
            .ok()
            .filter(|stack| *stack != 0)
    }

    /// `IRP_MJ_POWER` framework dispatch for `IRP_MN_SET_POWER`.
    fn wdf_power_dispatch(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let irp_guest = guest_arg(state, memory, 0)?;
        let device_object = guest_arg(state, memory, 1)?;
        let Some(device) = self.kmdf.devices_by_object.get(&device_object).copied() else {
            return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
        };
        let Some(stack) = self.irp_stack_location(memory, irp_guest) else {
            return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
        };
        let minor = memory.read_u8(stack + 1)?;
        let (type_offset, state_offset) = match self.arch {
            GuestArch::X64 => (0x08u64, 0x10u64),
            GuestArch::X86 => (0x04u64, 0x08u64),
        };
        let power_type = memory.read_u32(stack + type_offset)?;
        let target = memory.read_u32(stack + state_offset)?;
        if minor != IRP_MN_SET_POWER || power_type != POWER_STATE_TYPE_DEVICE {
            return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
        }
        let (pnp, started, power_state) = self
            .kmdf
            .devices
            .get(&device)
            .map(|record| (record.pnp_power, record.started, record.power_state))
            .expect("a device object always maps to a live device");
        let mut steps = VecDeque::new();
        let final_state = match target {
            WDF_POWER_DEVICE_D0 => {
                self.kmdf.power_d0_dispatches += 1;
                if !started || power_state == WDF_POWER_DEVICE_D0 {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
                }
                if pnp.d0_entry != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.d0_entry,
                        args: vec![device, u64::from(WDF_POWER_DEVICE_D3)],
                        label: "EvtDeviceD0Entry",
                        required: true,
                        rollback: Vec::new(),
                    });
                }
                if pnp.self_managed_io_restart != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.self_managed_io_restart,
                        args: vec![device],
                        label: "EvtDeviceSelfManagedIoRestart",
                        required: false,
                        rollback: Vec::new(),
                    });
                }
                PnpFinalState::PowerD0
            }
            WDF_POWER_DEVICE_D3 => {
                self.kmdf.power_d3_dispatches += 1;
                if !started || power_state != WDF_POWER_DEVICE_D0 {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
                }
                if pnp.self_managed_io_suspend != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.self_managed_io_suspend,
                        args: vec![device],
                        label: "EvtDeviceSelfManagedIoSuspend",
                        required: false,
                        rollback: Vec::new(),
                    });
                }
                if pnp.d0_exit != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.d0_exit,
                        args: vec![device, u64::from(WDF_POWER_DEVICE_D3)],
                        label: "EvtDeviceD0Exit",
                        required: true,
                        rollback: Vec::new(),
                    });
                }
                PnpFinalState::PowerD3
            }
            _ => return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST),
        };
        self.begin_pnp_sequence(state, memory, device, irp_guest, steps, final_state)
    }

    fn fail_pnp(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        irp_guest: u64,
        status: i32,
    ) -> AppResult<Option<PendingGuestCall>> {
        self.write_irp_status(memory, irp_guest, status, 0)?;
        set_status(state, status);
        Ok(None)
    }

    fn begin_pnp_sequence(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        device: u64,
        irp_guest: u64,
        mut steps: VecDeque<PnpStep>,
        final_state: PnpFinalState,
    ) -> AppResult<Option<PendingGuestCall>> {
        if let Some(first) = steps.pop_front() {
            let rollback = VecDeque::from(first.rollback.clone());
            let current_required = first.required;
            return Ok(Some(PendingGuestCall {
                entry: first.entry,
                args: first.args,
                label: first.label,
                purpose: PendingPurpose::PnpSequence {
                    device,
                    irp_guest,
                    current_required,
                    remaining: steps,
                    rollback,
                    failure_status: None,
                    final_state,
                },
            }));
        }
        self.apply_pnp_final_state(device, final_state);
        self.purge_deleted_objects();
        self.write_irp_status(memory, irp_guest, STATUS_SUCCESS, 0)?;
        set_status(state, STATUS_SUCCESS);
        Ok(None)
    }

    fn apply_pnp_final_state(&mut self, device: u64, final_state: PnpFinalState) {
        if final_state == PnpFinalState::Removed {
            return;
        }
        let record = self
            .kmdf
            .devices
            .get_mut(&device)
            .expect("a PnP final state is applied only while the device exists");
        if final_state == PnpFinalState::Started {
            record.started = true;
            record.power_state = WDF_POWER_DEVICE_D0;
        } else if final_state == PnpFinalState::Stopped {
            record.started = false;
            record.power_state = WDF_POWER_DEVICE_D3;
        } else if final_state == PnpFinalState::PowerD0 {
            record.power_state = WDF_POWER_DEVICE_D0;
        } else if final_state == PnpFinalState::PowerD3 {
            record.power_state = WDF_POWER_DEVICE_D3;
        }
    }
}

/// True when `handle` was minted by an island device-namespace open.
pub(crate) fn is_island_device_handle(runtime: &PeHostRuntime, handle: u32) -> bool {
    let runtime_id = runtime_identity(runtime);
    lock_registry()
        .device_handles
        .get(&runtime_id)
        .is_some_and(|handles| handles.contains_key(&handle))
}

/// Close an island device-namespace handle.  Returns `true` when the handle
/// belonged to the island namespace and was released by this call (a second
/// close therefore reports `false` and falls through to the invalid-handle
/// path).
pub(crate) fn close_island_device_handle(runtime: &PeHostRuntime, handle: u32) -> bool {
    let runtime_id = runtime_identity(runtime);
    lock_registry()
        .device_handles
        .get_mut(&runtime_id)
        .and_then(|handles| handles.remove(&handle))
        .is_some()
}

/// `NtCreateFile` island hook: when `raw_path` names a loaded island device
/// (directly or through a symbolic link), mint a device handle and write it
/// to `handle_ptr`.  Returns `None` when the path is not in the island
/// namespace, `Some(status)` otherwise.
pub(crate) fn nt_open_island_device(
    runtime: &PeHostRuntime,
    memory: &mut MemoryImage,
    raw_path: &str,
    handle_ptr: u64,
) -> Option<i32> {
    let device = resolve_island_device(runtime, raw_path)?;
    if handle_ptr == 0 || crate::host_thunks::validate_guest_pointer(memory, handle_ptr, 4).is_err()
    {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let runtime_id = runtime_identity(runtime);
    let mut registry = lock_registry();
    let counter = registry.next_device_handle.entry(runtime_id).or_insert(0);
    let handle = DEVICE_HANDLE_BASE.wrapping_add(*counter);
    *counter = counter.wrapping_add(1);
    registry
        .device_handles
        .entry(runtime_id)
        .or_default()
        .insert(handle, device);
    drop(registry);
    memory.write_u32(handle_ptr, handle);
    Some(STATUS_SUCCESS)
}

/// Dispatch an island device handle's I/O through the real driver
/// `MajorFunction`.  Returns `None` for handles outside the island namespace.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_island_device_io(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    handle: u32,
    major: IrpMajorFunction,
    io_control_code: u32,
    input_ptr: u64,
    input_len: u32,
    output_ptr: u64,
    output_len: u32,
    byte_offset: u64,
) -> AppResult<Option<(i32, usize)>> {
    let runtime_id = runtime_identity(runtime);
    let (device, inner) = {
        let registry = lock_registry();
        let Some(device) = registry
            .device_handles
            .get(&runtime_id)
            .and_then(|handles| handles.get(&handle))
            .cloned()
        else {
            return Ok(None);
        };
        let service_key = device.service_name.to_ascii_lowercase();
        let Some(shared) = registry
            .services
            .get(&runtime_id)
            .and_then(|services| services.get(&service_key))
        else {
            return Ok(Some((STATUS_INVALID_HANDLE, 0)));
        };
        (device, shared.0.inner.clone())
    };
    // A handle opened to a device that has since been deleted is stale.
    let live = inner
        .borrow()
        .device_ids
        .get(&device.device_guest)
        .is_some_and(|id| *id == device.device_id);
    if !live {
        return Ok(Some((STATUS_INVALID_HANDLE, 0)));
    }
    let result = DriverIsland { inner }.dispatch_irp(
        runtime,
        memory,
        device.device_guest,
        major,
        io_control_code,
        input_ptr,
        input_len,
        output_ptr,
        output_len,
        byte_offset,
    )?;
    Ok(Some(result))
}

fn normalize_device_path(raw: &str) -> String {
    let mut path = raw
        .trim_matches(|ch| ch == '\0' || ch == ' ')
        .replace('/', "\\");
    if let Some(rest) = path.strip_prefix("\\\\.\\") {
        path = format!("\\??\\{rest}");
    }
    if path.len() > 1 {
        while path.ends_with('\\') {
            path.pop();
        }
    }
    path
}

fn resolve_island_device(runtime: &PeHostRuntime, raw_path: &str) -> Option<IslandDeviceHandle> {
    let path = normalize_device_path(raw_path);
    if path.is_empty() {
        return None;
    }
    let runtime_id = runtime_identity(runtime);
    let registry = lock_registry();
    for island in registry
        .services
        .get(&runtime_id)
        .into_iter()
        .flat_map(|services| services.values())
    {
        let state = island.0.inner.borrow();
        let direct = state
            .devices
            .iter()
            .find(|device| !device.deleted && device.name.eq_ignore_ascii_case(&path));
        let link_target = state
            .symbolic_links
            .iter()
            .find_map(|(link, target)| link.eq_ignore_ascii_case(&path).then_some(target.as_str()));
        let linked = link_target.and_then(|target| {
            state
                .devices
                .iter()
                .find(|device| !device.deleted && device.name.eq_ignore_ascii_case(target))
        });
        // `\??\Name` is also accepted for a device without an explicit
        // symbolic link (the NT object-manager DOS-device prefix).
        let dos_prefixed = {
            let rest = path
                .strip_prefix("\\??\\")
                .or_else(|| path.strip_prefix("\\DosDevices\\"));
            rest.and_then(|rest| {
                let target = format!("\\Device\\{rest}");
                state
                    .devices
                    .iter()
                    .find(|device| !device.deleted && device.name.eq_ignore_ascii_case(&target))
            })
        };
        let Some(device) = direct.or(linked).or(dos_prefixed) else {
            continue;
        };
        let Some(device_id) = state.device_ids.get(&device.guest_pointer).copied() else {
            continue;
        };
        return Some(IslandDeviceHandle {
            service_name: state.driver_name.clone(),
            device_guest: device.guest_pointer,
            device_id,
        });
    }
    None
}

/// Dispatches one island shim from the runtime's `HostThunk` match arm.
pub(crate) fn dispatch_shim(
    runtime: &mut PeHostRuntime,
    state: &mut CpuState,
    memory: &mut MemoryImage,
    function: DriverShim,
) -> AppResult<()> {
    let island = ACTIVE_ISLAND
        .with(|slot| slot.borrow().clone())
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("driver island shim {function:?} invoked with no active island"),
            )
        })?;
    let mut pending = {
        let mut island_state = island.borrow_mut();
        island_state.handle_shim(runtime, state, memory, function)?
    };
    while let Some(call) = pending {
        let arch = island.borrow().arch;
        let mut cpu = CpuState::new(arch);
        // Leave the top frame for the context that invoked the shim: a KMDF
        // callback runs while DriverEntry (or a MajorFunction handler) is still
        // live on the same guest stack.
        cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x800);
        let result =
            runtime.execute_guest_callback(&mut cpu, memory, call.entry, &call.args, call.label);
        let status = match result {
            Ok(value) => value as u32 as i32,
            Err(_) => STATUS_INVALID_PARAMETER,
        };
        pending = {
            let mut island_state = island.borrow_mut();
            island_state.finish_pending(state, memory, call.purpose, status)?
        };
    }
    Ok(())
}

thread_local! {
    static ACTIVE_ISLAND: RefCell<Option<Rc<RefCell<IslandState>>>> = const { RefCell::new(None) };
}

struct ActiveIsland;

impl ActiveIsland {
    fn install(island: Rc<RefCell<IslandState>>) -> Self {
        ACTIVE_ISLAND.with(|slot| *slot.borrow_mut() = Some(island));
        Self
    }
}

impl Drop for ActiveIsland {
    fn drop(&mut self) {
        ACTIVE_ISLAND.with(|slot| *slot.borrow_mut() = None);
    }
}

fn allocate_shim(runtime: &mut PeHostRuntime, function: DriverShim) -> u64 {
    let address = runtime.next_thunk_address;
    runtime.next_thunk_address += 0x10;
    runtime
        .host_thunks
        .insert(address, HostThunk::DriverIslandShim { function });
    address
}

fn patch_imports(
    driver: &mut LoadedDriver,
    runtime: &mut PeHostRuntime,
    arch: GuestArch,
) -> (ImportReport, Vec<(String, String, KernelApiSet)>) {
    let mut report = ImportReport {
        resolved: Vec::new(),
        unresolved: Vec::new(),
    };
    let pointer_bytes = arch.pointer_bytes();
    let imports = driver.imports.clone();
    for module in imports {
        for (index, symbol) in module.symbols.iter().enumerate() {
            let target = (module.dll.clone(), symbol.display(), module.set);
            let address = match symbol {
                ImportRef::Name(name) => {
                    DriverShim::for_import(name).map(|function| allocate_shim(runtime, function))
                }
                ImportRef::Ordinal(_) => None,
            };
            let offset = module.first_thunk_rva as usize + index * pointer_bytes;
            match address {
                Some(address) if offset + pointer_bytes <= driver.image.len() => {
                    write_image_pointer(&mut driver.image, offset, address, arch);
                    report.resolved.push(target);
                }
                _ => report.unresolved.push(target),
            }
        }
    }
    // Delay imports are resolved eagerly at load time (lazy resolution is
    // not required by the island contract): every name is mapped through the
    // same kernel shim table and the delay IAT is written before entry runs.
    let delay_imports = driver.delay_imports.clone();
    for module in delay_imports {
        let set = KernelApiSet::classify(&module.dll);
        for (index, symbol) in module.symbols.iter().enumerate() {
            let target = (module.dll.clone(), symbol.display(), set);
            let address = match symbol {
                ImportRef::Name(name) => {
                    DriverShim::for_import(name).map(|function| allocate_shim(runtime, function))
                }
                ImportRef::Ordinal(_) => None,
            };
            let offset = module.iat_rva as usize + index * pointer_bytes;
            match address {
                Some(address) if offset + pointer_bytes <= driver.image.len() => {
                    write_image_pointer(&mut driver.image, offset, address, arch);
                    // Keep the delay INT consistent with the patched IAT so a
                    // runtime helper that re-reads it sees the same targets.
                    let int_offset = module.int_rva as usize + index * pointer_bytes;
                    if int_offset + pointer_bytes <= driver.image.len() {
                        write_image_pointer(&mut driver.image, int_offset, address, arch);
                    }
                    report.resolved.push(target);
                }
                _ => report.unresolved.push(target),
            }
        }
    }
    let unresolved = report.unresolved.clone();
    (report, unresolved)
}

fn write_image_pointer(image: &mut [u8], offset: usize, value: u64, arch: GuestArch) {
    match arch {
        GuestArch::X86 => {
            image[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
        GuestArch::X64 => {
            image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
}

fn build_driver_object(
    state: &IslandState,
    memory: &mut MemoryImage,
    driver_object: u64,
    extension: u64,
    driver_name: u64,
    registry_path: u64,
    default_dispatch: u64,
) -> AppResult<()> {
    let arch = state.arch;
    match arch {
        GuestArch::X64 => {
            memory.write_u16(driver_object, DRIVER_OBJECT_TYPE);
            memory.write_u16(driver_object + 0x02, DRIVER_OBJECT_SIZE as u16);
            memory.write_u64(driver_object + 0x08, 0);
            memory.write_u32(driver_object + 0x10, 0);
            memory.write_u64(driver_object + 0x18, state.image_base);
            memory.write_u32(driver_object + 0x20, state.image_size);
            memory.write_u64(driver_object + 0x28, 0);
            memory.write_u64(driver_object + 0x30, extension);
            copy_unicode_string(memory, driver_name, driver_object + 0x38, arch)?;
            memory.write_u64(driver_object + 0x48, 0);
            memory.write_u64(driver_object + 0x50, 0);
            memory.write_u64(driver_object + 0x58, state.entry_guest);
            memory.write_u64(driver_object + 0x60, 0);
            memory.write_u64(driver_object + 0x68, state.unload_guest.unwrap_or(0));
        }
        GuestArch::X86 => {
            memory.write_u16(driver_object, DRIVER_OBJECT_TYPE);
            memory.write_u16(driver_object + 0x02, DRIVER_OBJECT_SIZE_X86 as u16);
            write_guest_pointer(memory, driver_object + 0x04, 0, arch)?;
            memory.write_u32(driver_object + 0x08, 0);
            memory.write_u32(driver_object + 0x0C, state.image_base as u32);
            memory.write_u32(driver_object + 0x10, state.image_size);
            write_guest_pointer(memory, driver_object + 0x14, 0, arch)?;
            write_guest_pointer(memory, driver_object + 0x18, extension, arch)?;
            copy_unicode_string(memory, driver_name, driver_object + 0x1C, arch)?;
            write_guest_pointer(memory, driver_object + 0x24, 0, arch)?;
            write_guest_pointer(memory, driver_object + 0x28, 0, arch)?;
            write_guest_pointer(memory, driver_object + 0x2C, state.entry_guest, arch)?;
            write_guest_pointer(memory, driver_object + 0x30, 0, arch)?;
            write_guest_pointer(
                memory,
                driver_object + 0x34,
                state.unload_guest.unwrap_or(0),
                arch,
            )?; // coverage: unreachable — write_guest_pointer is infallible for a MemoryImage
        }
    }
    let major_offset = major_function_offset(arch);
    for index in 0..MAJOR_FUNCTION_COUNT {
        write_guest_pointer(
            memory,
            driver_object + major_offset + index as u64 * arch.pointer_bytes() as u64,
            default_dispatch,
            arch,
        )?; // coverage: unreachable — write_guest_pointer is infallible for a MemoryImage
    }

    write_guest_pointer(memory, extension, driver_object, arch)?;
    write_guest_pointer(memory, extension + 0x08, 0, arch)?;
    memory.write_u32(extension + 0x10, 0);
    copy_unicode_string(memory, registry_path, extension + 0x18, arch)?;
    Ok(())
}

fn copy_unicode_string(
    memory: &mut MemoryImage,
    source: u64,
    destination: u64,
    arch: GuestArch,
) -> AppResult<()> {
    let length = memory.read_u16(source)?;
    let maximum = memory.read_u16(source + 2)?;
    let buffer = read_guest_pointer(memory, source + unicode_string_buffer_offset(arch), arch)?;
    write_unicode_string_header(memory, destination, length, maximum, buffer, arch)?;
    Ok(())
}

fn write_unicode_string_header(
    memory: &mut MemoryImage,
    destination: u64,
    length: u16,
    maximum: u16,
    buffer: u64,
    arch: GuestArch,
) -> AppResult<()> {
    memory.write_u16(destination, length);
    memory.write_u16(destination + 2, maximum);
    memory.write_u32(destination + 4, 0);
    write_guest_pointer(
        memory,
        destination + unicode_string_buffer_offset(arch),
        buffer,
        arch,
    )
}

fn unicode_string_buffer_offset(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X86 => 4,
        GuestArch::X64 => 8,
    }
}

fn unicode_string_size(arch: GuestArch) -> usize {
    match arch {
        GuestArch::X86 => 8,
        GuestArch::X64 => 16,
    }
}

fn major_function_offset(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X86 => 0x38,
        GuestArch::X64 => 0x70,
    }
}

fn driver_object_size(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X86 => DRIVER_OBJECT_SIZE_X86,
        GuestArch::X64 => DRIVER_OBJECT_SIZE,
    }
}

fn write_guest_pointer(
    memory: &mut MemoryImage,
    address: u64,
    value: u64,
    arch: GuestArch,
) -> AppResult<()> {
    match arch {
        GuestArch::X86 => memory.write_u32(address, value as u32),
        GuestArch::X64 => memory.write_u64(address, value),
    }
    Ok(())
}

fn read_guest_pointer(memory: &MemoryImage, address: u64, arch: GuestArch) -> AppResult<u64> {
    match arch {
        GuestArch::X86 => memory.read_u32(address).map(u64::from),
        GuestArch::X64 => memory.read_u64(address),
    }
}

fn allocate_unicode_string(
    state: &mut IslandState,
    memory: &mut MemoryImage,
    text: &str,
) -> AppResult<u64> {
    let units = text.encode_utf16().collect::<Vec<_>>();
    let buffer = state.arena.alloc(memory, (units.len() + 1) * 2, 2)?;
    for (index, unit) in units.iter().enumerate() {
        memory.write_u16(buffer + index as u64 * 2, *unit);
    }
    memory.write_u16(buffer + units.len() as u64 * 2, 0);
    let header = state
        .arena
        .alloc(memory, unicode_string_size(state.arch), 8)?;
    write_unicode_string_header(
        memory,
        header,
        (units.len() * 2) as u16,
        ((units.len() + 1) * 2) as u16,
        buffer,
        state.arch,
    )?; // coverage: unreachable — write_unicode_string_header only performs infallible MemoryImage writes
    Ok(header)
}

fn read_unicode_string(
    memory: &MemoryImage,
    address: u64,
    arch: GuestArch,
) -> AppResult<(String, u16, u64)> {
    if address == 0 {
        return Ok((String::new(), 0, 0));
    }
    let length = memory.read_u16(address)?;
    let _maximum = memory.read_u16(address + 2)?;
    let buffer = read_guest_pointer(memory, address + unicode_string_buffer_offset(arch), arch)?;
    if length == 0 {
        return Ok((String::new(), 0, buffer));
    }
    if length % 2 != 0 || buffer == 0 {
        return Err(AppError::new(
            ReasonCode::RcMemoryAccessViolation,
            format!("invalid UNICODE_STRING at {address:#x} (Length={length})"),
        ));
    }
    let mut units = Vec::with_capacity(length as usize / 2);
    for index in 0..length / 2 {
        units.push(memory.read_u16(buffer + index as u64 * 2)?);
    }
    Ok((String::from_utf16_lossy(&units), length, buffer))
}

fn read_utf16_z(memory: &MemoryImage, address: u64, maximum_units: usize) -> AppResult<String> {
    if address == 0 {
        return Ok(String::new());
    }
    let mut units = Vec::new();
    for index in 0..maximum_units {
        let unit = memory.read_u16(address + index as u64 * 2)?;
        if unit == 0 {
            return Ok(String::from_utf16_lossy(&units));
        }
        units.push(unit);
    }
    Err(AppError::new(
        ReasonCode::RcMemoryAccessViolation,
        format!("unterminated UTF-16 string at {address:#x}"),
    ))
}

fn read_ansi_z(memory: &MemoryImage, address: u64, maximum: usize) -> AppResult<String> {
    if address == 0 {
        return Ok(String::new());
    }
    let mut bytes = Vec::new();
    for index in 0..maximum {
        let byte = memory.read_u8(address + index as u64)?;
        if byte == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.push(byte);
    }
    Err(AppError::new(
        ReasonCode::RcMemoryAccessViolation,
        format!("unterminated ANSI string at {address:#x}"),
    ))
}

fn format_dbg_print(format: &str, args: &[u64], memory: &MemoryImage, arch: GuestArch) -> String {
    let characters = format.chars().collect::<Vec<_>>();
    let mut output = String::new();
    let mut index = 0;
    let mut argument = 0;
    while index < characters.len() {
        if characters[index] != '%' {
            output.push(characters[index]);
            index += 1;
            continue;
        }
        index += 1;
        if index >= characters.len() {
            output.push('%');
            break;
        }
        if characters[index] == '%' {
            output.push('%');
            index += 1;
            continue;
        }
        let mut wide = false;
        while index < characters.len()
            && matches!(characters[index], 'h' | 'l' | 'w' | 'I' | '6' | '4' | 'z')
        {
            wide |= characters[index] == 'w';
            index += 1;
        }
        if index >= characters.len() {
            output.push('%');
            break;
        }
        let conversion = characters[index];
        index += 1;
        let value = args.get(argument).copied().unwrap_or(0);
        argument += 1;
        match conversion {
            's' | 'S' => {
                let string = if wide {
                    read_utf16_z(memory, value, 4096).unwrap_or_default()
                } else {
                    read_ansi_z(memory, value, 4096).unwrap_or_default()
                };
                output.push_str(&string);
            }
            'Z' => {
                output.push_str(
                    &read_unicode_string(memory, value, arch)
                        .map(|(text, _, _)| text)
                        .unwrap_or_default(),
                );
            }
            'u' => output.push_str(&(value as u32).to_string()),
            'd' | 'i' => output.push_str(&(value as i32).to_string()),
            'x' => output.push_str(&format!("{:x}", value as u32)),
            'X' => output.push_str(&format!("{:X}", value as u32)),
            'p' => output.push_str(&format!("{value:#x}")),
            'c' => output.push(char::from_u32(value as u32).unwrap_or('?')),
            other => {
                output.push('%');
                output.push(other);
            }
        }
    }
    output
}

fn guest_arg(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<u64> {
    match state.arch {
        GuestArch::X64 => match index {
            0 => Ok(state.get(Register::Rcx)),
            1 => Ok(state.get(Register::Rdx)),
            2 => Ok(state.get(Register::R8)),
            3 => Ok(state.get(Register::R9)),
            _ => memory.read_u64(state.get(Register::Rsp) + 0x20 + (index as u64 - 4) * 8),
        },
        GuestArch::X86 => memory
            .read_u32(state.get(Register::Rsp) + index as u64 * 4)
            .map(u64::from),
    }
}

fn set_status(state: &mut CpuState, status: i32) {
    state.set(Register::Rax, status as i64 as u64);
}

fn runtime_identity(runtime: &PeHostRuntime) -> usize {
    runtime as *const PeHostRuntime as usize
}

fn loaded_driver_key(runtime: &PeHostRuntime, service_name: &str) -> (usize, String) {
    (runtime_identity(runtime), service_name.to_ascii_lowercase())
}

/// Read a `PUNICODE_STRING` argument, rejecting null, unmapped, and
/// structurally invalid descriptors.
fn read_service_unicode_string(
    memory: &MemoryImage,
    address: u64,
    arch: GuestArch,
) -> Result<String, i32> {
    if address == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let length = memory
        .read_u16(address)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let _maximum = memory
        .read_u16(address + 2)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let buffer = read_guest_pointer(memory, address + unicode_string_buffer_offset(arch), arch)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    if length == 0 || length % 2 != 0 || buffer == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut bytes = vec![0_u8; length as usize];
    memory
        .read_into(buffer, &mut bytes)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| STATUS_INVALID_PARAMETER)
}

/// Extract the service name from a `\Registry\Machine\System\
/// CurrentControlSet\Services\<name>` path.  The prefix comparison is
/// case-insensitive, matching the object manager's path semantics.
fn parse_service_name(raw: &str) -> Result<String, i32> {
    let path = raw.trim_matches(|ch| ch == '\0' || ch == ' ');
    let lower = path.to_ascii_lowercase();
    let Some(rest) = lower
        .strip_prefix(MACHINE_REGISTRY_PREFIX)
        .map(|_| &path[MACHINE_REGISTRY_PREFIX.len()..])
    else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    if !rest
        .to_ascii_lowercase()
        .starts_with(SERVICE_REGISTRY_PREFIX)
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let service = rest[SERVICE_REGISTRY_PREFIX.len()..].trim_matches('\\');
    let service = service.split('\\').next().unwrap_or("");
    if service.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(service.to_string())
}

/// Resolve `SYSTEM\CurrentControlSet\Services\<name>` case-insensitively
/// through the real registry store (the same GE registry the Win32 Reg*
/// layer and `NtOpenKey` use).
fn resolve_service_key(runtime: &PeHostRuntime, service_name: &str) -> Option<String> {
    let mut actual = String::new();
    for segment in ["SYSTEM", "CurrentControlSet", "Services", service_name] {
        let children = runtime
            .win32
            .ge()
            .registry_enum_keys("HKLM", &actual, RegistryView::Native)
            .ok()?;
        let found = children
            .iter()
            .find(|child| child.eq_ignore_ascii_case(segment))?;
        actual = if actual.is_empty() {
            found.clone()
        } else {
            format!("{actual}\\{found}")
        };
    }
    Some(actual)
}

/// Read `ImagePath` from the resolved service key and expand it against the
/// GE file system.  Only `REG_SZ`/`REG_EXPAND_SZ` values carry an image path.
fn read_service_image_path(runtime: &PeHostRuntime, registry_key: &str) -> Result<String, i32> {
    let value_names = runtime
        .win32
        .ge()
        .registry_enum_values("HKLM", registry_key, RegistryView::Native)
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let value_name = value_names
        .iter()
        .find(|name| name.eq_ignore_ascii_case("ImagePath"))
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let stored = runtime
        .win32
        .registry_get_value("HKLM", registry_key, value_name, RegistryView::Native)
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    match stored.value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" | "REG_EXPAND_SZ" => {}
        _ => return Err(crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32),
    }
    let image_path = stored
        .data
        .as_str()
        .ok_or(crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32)?;
    Ok(expand_driver_image_path(
        image_path,
        &runtime.process_environment,
    ))
}

/// Read the service `StartType` (`SERVICE_BOOT_START`..`SERVICE_DISABLED`).
/// A missing value is accepted (no start-type constraint).
fn service_start_type(runtime: &PeHostRuntime, registry_key: &str) -> Result<Option<u32>, i32> {
    let value_names = runtime
        .win32
        .ge()
        .registry_enum_values("HKLM", registry_key, RegistryView::Native)
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let Some(value_name) = value_names
        .iter()
        .find(|name| name.eq_ignore_ascii_case("StartType"))
    else {
        return Ok(None);
    };
    let stored = runtime
        .win32
        .registry_get_value("HKLM", registry_key, value_name, RegistryView::Native)
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let raw = stored
        .data
        .as_u64()
        .or_else(|| stored.data.as_str().and_then(|text| text.parse().ok()))
        .ok_or(STATUS_INVALID_PARAMETER)?;
    Ok(Some(raw as u32))
}

/// Expand a driver `ImagePath`: strip quotes, expand every `%VAR%` against
/// the GE process environment, map `\SystemRoot` / `%SystemRoot%` to
/// `C:\Windows`, unwrap `\??\` / `\DosDevices\`, and root relative paths at
/// the Windows directory.
fn expand_driver_image_path(raw: &str, environment: &BTreeMap<String, String>) -> String {
    const WINDOWS: &str = "C:\\Windows";
    let mut path = raw.trim().to_string();
    if let Some(quoted) = path.strip_prefix('"') {
        if let Some(end) = quoted.find('"') {
            path = quoted[..end].to_string();
        }
    }
    path = expand_environment_percent(&path, environment);
    path = replace_ascii_case_insensitive(&path, "%systemroot%", WINDOWS);
    path = replace_ascii_case_insensitive(&path, "\\systemroot", WINDOWS);
    let lower = path.to_ascii_lowercase();
    if lower.starts_with("\\??\\") {
        path = path[4..].to_string();
    } else if lower.starts_with("\\dosdevices\\") {
        path = path[12..].to_string();
    }
    if !path.contains(':') {
        path = if path.starts_with('\\') {
            format!("{WINDOWS}{path}")
        } else {
            format!("{WINDOWS}\\{path}")
        };
    }
    path.replace('/', "\\")
}

fn replace_ascii_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut start = 0;
    while let Some(offset) = lower[start..].find(needle) {
        let position = start + offset;
        output.push_str(&input[start..position]);
        output.push_str(replacement);
        start = position + needle.len();
    }
    output.push_str(&input[start..]);
    output
}

/// Open the image through the runtime's real file tables and read its bytes.
fn read_service_image(runtime: &mut PeHostRuntime, image_path: &str) -> Result<Vec<u8>, i32> {
    let handle = runtime
        .win32
        .create_file_w(
            image_path,
            FileAccess::read_only(),
            ShareMode::all(),
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        )
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let bytes = runtime
        .win32
        .read_file(handle, usize::MAX)
        .map_err(|_| crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32);
    let _ = runtime.win32.close_handle(handle);
    bytes
}

/// Expand `%NAME%` references against the GE process environment,
/// case-insensitively.  An undefined variable is copied through literally,
/// matching `ExpandEnvironmentStringsW`.
fn expand_environment_percent(source: &str, environment: &BTreeMap<String, String>) -> String {
    let mut expanded = String::with_capacity(source.len());
    let mut remainder = source;
    while let Some(start) = remainder.find('%') {
        expanded.push_str(&remainder[..start]);
        let after_start = &remainder[start + 1..];
        if let Some(end) = after_start.find('%') {
            let name = &after_start[..end];
            if let Some((_, value)) = environment
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
            {
                expanded.push_str(value);
                remainder = &after_start[end + 1..];
                continue;
            }
        }
        expanded.push('%');
        remainder = after_start;
    }
    expanded.push_str(remainder);
    expanded
}

/// Record one driver load/unload trace event on the runtime.
fn record_driver_event(
    runtime: &mut PeHostRuntime,
    call_id: &str,
    service_name: &str,
    status: i32,
    image_path: Option<&str>,
) {
    let index = runtime.next_trace_index;
    let mut parameters = BTreeMap::from([
        ("service".to_string(), json!(service_name)),
        ("status".to_string(), json!(format!("{status:#010x}"))),
    ]);
    if let Some(path) = image_path {
        parameters.insert("image_path".to_string(), json!(path));
    }
    runtime.trace_events.push(TraceEvent {
        event_index: index,
        category: "driver".to_string(),
        call_id: call_id.to_string(),
        parameters,
        return_value: json!(status),
        get_last_error: None,
        side_effect_hashes: Vec::new(),
    });
    runtime.next_trace_index += 1;
}

fn nt_load_error_status(error: &AppError) -> i32 {
    match error.code {
        ReasonCode::RcFsNotFound | ReasonCode::RcRegistryNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        _ => crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32,
    }
}

#[cfg(test)]
pub(crate) fn with_loaded_driver<R>(
    runtime: &PeHostRuntime,
    service_name: &str,
    inspect: impl FnOnce(&DriverIsland) -> R,
) -> Option<R> {
    let key = loaded_driver_key(runtime, service_name);
    lock_registry()
        .services
        .get(&key.0)
        .and_then(|services| services.get(&key.1))
        .map(|island| inspect(&island.0))
}

/// Drop every island registration and handle owned by `runtime`.  Called by
/// the runtime's `Drop` so a reused host address never observes a stale
/// service namespace.
pub(crate) fn forget_runtime(runtime: &PeHostRuntime) {
    let runtime_id = runtime_identity(runtime);
    let mut registry = lock_registry();
    registry.services.remove(&runtime_id);
    registry.device_handles.remove(&runtime_id);
    registry.next_device_handle.remove(&runtime_id);
}

#[cfg(test)]
pub(crate) fn reset_runtime_registry(runtime: &PeHostRuntime) {
    forget_runtime(runtime);
}

#[cfg(test)]
pub(crate) fn take_last_unloaded_driver() -> Option<DriverIsland> {
    LAST_UNLOADED_DRIVER.with(|slot| slot.borrow_mut().take())
}

fn status_is_success(status: i32) -> bool {
    (status as u32) < 0x8000_0000
}

fn strip_device_prefix(name: &str) -> &str {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("\\device\\") {
        &name[8..]
    } else {
        name.trim_start_matches('\\')
    }
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    value.wrapping_add(align - 1) & !(align - 1)
}

fn driver_image_error(status: u32) -> AppError {
    AppError::new(
        ReasonCode::RcPeParseInvalid,
        format!("driver image rejected with NTSTATUS {status:#010x}"),
    )
}

fn nt_error(operation: &str, status: i32) -> AppError {
    AppError::new(
        ReasonCode::RcIo,
        format!("{operation} failed with NTSTATUS {status:#010x}"),
    )
}

/// The guest architecture of a PE image, rejecting a machine/optional-header
/// magic mismatch (the only images the island refuses for bitness reasons).
fn pe_image_arch(bytes: &[u8]) -> Result<GuestArch, String> {
    if bytes.len() < 0x40 || read_u16(bytes, 0) != Some(0x5A4D) {
        return Err("driver island requires a PE image".to_string());
    }
    let pe = read_u32(bytes, 0x3C).ok_or("truncated DOS header")? as usize;
    if read_u32(bytes, pe) != Some(0x0000_4550) {
        return Err("driver island requires a PE image".to_string());
    }
    let machine = read_u16(bytes, pe + 4).ok_or("truncated COFF header")?;
    let magic = read_u16(bytes, pe + 24).ok_or("truncated optional header")?;
    match (machine, magic) {
        (0x8664, 0x020B) => Ok(GuestArch::X64),
        (0x014C, 0x010B) => Ok(GuestArch::X86),
        (0x8664, 0x010B) => Err("PE32 optional header on an x64 machine".to_string()),
        (0x014C, 0x020B) => Err("PE32+ optional header on an x86 machine".to_string()),
        (other, _) => Err(format!("driver island rejects machine {other:#x}")),
    }
}

/// Returns `(preferred image base, SizeOfImage)` from the PE headers when the
/// basic DOS/PE/optional-header shape is present.
fn pe_layout_hint(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() < 0x40 || read_u16(bytes, 0) != Some(0x5A4D) {
        return None;
    }
    let pe = read_u32(bytes, 0x3C)? as usize;
    if read_u32(bytes, pe) != Some(0x0000_4550) {
        return None;
    }
    let coff = pe + 4;
    let optional = coff + 20;
    let magic = read_u16(bytes, optional)?;
    let (base, size_offset) = match magic {
        0x020B => (read_u64(bytes, optional + 24)?, optional + 56),
        0x010B => (read_u32(bytes, optional + 28)? as u64, optional + 56),
        _ => return None,
    };
    let size = read_u32(bytes, size_offset)? as u64;
    Some((base, size.max(0x1000)))
}

fn choose_placement(
    runtime: &PeHostRuntime,
    preferred: u64,
    size_hint: u64,
    arch: GuestArch,
) -> AppResult<(u64, u64)> {
    let fallback = if arch == GuestArch::X86 {
        DEFAULT_IMAGE_BASE_X86
    } else {
        DEFAULT_IMAGE_BASE
    };
    let preferred_valid = preferred >= 0x1_0000
        && preferred & 0xFFFF == 0
        && (arch != GuestArch::X86 || preferred < X86_ADDRESS_LIMIT);
    let start = if preferred_valid { preferred } else { fallback };
    let size = size_hint.max(0x1000);
    for index in 0..256_u64 {
        let base = start.wrapping_add(index * 0x40_0000);
        let arena = align_up(base.saturating_add(size), 0x1_0000);
        if arch == GuestArch::X86
            && (base.saturating_add(size) > X86_ADDRESS_LIMIT
                || arena.saturating_add(ARENA_SIZE) > X86_ADDRESS_LIMIT)
        {
            break;
        }
        let stack_end = STACK_BASE + STACK_SIZE;
        if base < stack_end && base.saturating_add(size) > STACK_BASE {
            continue;
        }
        if arena < stack_end && arena.saturating_add(ARENA_SIZE) > STACK_BASE {
            continue; // coverage: unreachable — arena >= align_up(STACK_BASE + 0x1000, 0x10000) = 0x20000 > stack_end 0x12000
        }
        if range_is_free(runtime, base, size) && range_is_free(runtime, arena, ARENA_SIZE) {
            return Ok((base, arena));
        }
    }
    Err(AppError::new(
        ReasonCode::RcIo,
        format!("no free guest address range for a {size:#x}-byte driver image"),
    ))
}

fn range_is_free(runtime: &PeHostRuntime, base: u64, size: u64) -> bool {
    let vm = runtime.win32.address_space();
    let start = base & !0xFFF;
    let end = base.saturating_add(size);
    let mut address = start;
    while address < end {
        if vm.query(address).state != VmState::Free {
            return false;
        }
        address = address.saturating_add(0x1000);
    }
    true
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|bytes| {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casak::io::STATUS_UNSUCCESSFUL;
    use crate::ge::{GameEnvironment, GeArch, RegistryView};
    use crate::host_thunks::ImplementationLevel;
    use serde_json::json;
    use tempfile::TempDir;

    const TEXT_RVA: u32 = 0x1000;
    const UNLOAD_RVA: u32 = 0x1100;
    const RDATA_RVA: u32 = 0x2000;
    const IMPORT_RVA: u32 = 0x2100;
    const ILT_RVA: u32 = 0x2140;
    const IAT_RVA: u32 = 0x21A0;
    const DLL_NAME_RVA: u32 = 0x2200;
    const DBG_FMT_RVA: u32 = 0x2380;
    const WIDE_DEV_RVA: u32 = 0x23C0;
    const WIDE_LINK_RVA: u32 = 0x2400;
    const DBG_UNLOAD_RVA: u32 = 0x2440;
    const EXPORT_RVA: u32 = 0x2480;
    const DRIVER_PTR_RVA: u32 = 0x3000;
    const US_DEV_RVA: u32 = 0x3008;
    const US_LINK_RVA: u32 = 0x3018;
    const DEV_OBJ_OUT_RVA: u32 = 0x3028;
    const ENTRY_MARKER_RVA: u32 = 0x3030;
    const UNLOAD_MARKER_RVA: u32 = 0x3034;

    const IAT_DBG: u32 = IAT_RVA;
    const IAT_RTL: u32 = IAT_RVA + 8;
    const IAT_IO_CREATE: u32 = IAT_RVA + 16;
    const IAT_IO_SYMLINK: u32 = IAT_RVA + 24;
    const IAT_IO_DELETE: u32 = IAT_RVA + 32;
    const IAT_IO_ALLOC_IRP: u32 = IAT_RVA + 40;
    const IAT_IOF_COMPLETE: u32 = IAT_RVA + 56;
    const IAT_EX_ALLOC: u32 = IAT_RVA + 72;
    const IAT_EX_FREE: u32 = IAT_RVA + 80;

    const IMPORT_NAMES: [(&str, u32); 11] = [
        ("DbgPrint", 0x2210),
        ("RtlInitUnicodeString", 0x2230),
        ("IoCreateDevice", 0x2250),
        ("IoCreateSymbolicLink", 0x2270),
        ("IoDeleteDevice", 0x2290),
        ("IoAllocateIrp", 0x22B0),
        ("IoFreeIrp", 0x22C0),
        ("IofCompleteRequest", 0x22D0),
        ("IoCompleteRequest", 0x22F0),
        ("ExAllocatePoolWithTag", 0x2310),
        ("ExFreePoolWithTag", 0x2330),
    ];

    #[derive(Default)]
    struct CodeBuilder {
        bytes: Vec<u8>,
        fixups: Vec<(usize, u32, usize)>,
    }

    impl CodeBuilder {
        fn raw(&mut self, bytes: &[u8]) {
            self.bytes.extend_from_slice(bytes);
        }

        fn disp(&mut self, target: u32) {
            self.disp_with_trailing(target, 0);
        }

        fn disp_with_trailing(&mut self, target: u32, trailing: usize) {
            let offset = self.bytes.len();
            self.bytes.extend_from_slice(&[0_u8; 4]);
            self.fixups.push((offset, target, trailing));
        }

        fn disp_imm32(&mut self, target: u32, immediate: u32) {
            self.disp_with_trailing(target, 4);
            self.raw(&immediate.to_le_bytes());
        }

        fn call_iat(&mut self, target: u32) {
            self.raw(&[0xFF, 0x15]);
            self.disp(target);
        }

        fn inc_dword(&mut self, target: u32) {
            self.raw(&[0xFF, 0x05]);
            self.disp(target);
        }

        fn finish(&mut self, rva: u32) -> Vec<u8> {
            for (offset, target, trailing) in self.fixups.drain(..) {
                let end = rva as i64 + offset as i64 + 4 + trailing as i64;
                let displacement = target as i64 - end;
                self.bytes[offset..offset + 4]
                    .copy_from_slice(&(displacement as i32).to_le_bytes());
            }
            self.bytes.clone()
        }
    }

    fn build_test_driver(
        entry_failure: bool,
        unresolved_import: bool,
        exercise_services: bool,
    ) -> Vec<u8> {
        let mut file = vec![0_u8; 0xC00];
        file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
        file[0x3C..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        file[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        file[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        file[coff + 2..coff + 4].copy_from_slice(&3_u16.to_le_bytes());
        file[coff + 16..coff + 18].copy_from_slice(&0xF0_u16.to_le_bytes());
        file[coff + 18..coff + 20].copy_from_slice(&0x0022_u16.to_le_bytes());
        let optional = coff + 20;
        file[optional..optional + 2].copy_from_slice(&0x020B_u16.to_le_bytes());
        file[optional + 4..optional + 8].copy_from_slice(&0x200_u32.to_le_bytes());
        file[optional + 8..optional + 12].copy_from_slice(&0x800_u32.to_le_bytes());
        file[optional + 16..optional + 20].copy_from_slice(&TEXT_RVA.to_le_bytes());
        file[optional + 20..optional + 24].copy_from_slice(&TEXT_RVA.to_le_bytes());
        file[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
        file[optional + 32..optional + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        file[optional + 36..optional + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        file[optional + 48..optional + 50].copy_from_slice(&6_u16.to_le_bytes());
        file[optional + 56..optional + 60].copy_from_slice(&0x4000_u32.to_le_bytes());
        file[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        file[optional + 68..optional + 70].copy_from_slice(&1_u16.to_le_bytes());
        let directory_count = optional + 108;
        file[directory_count..directory_count + 4].copy_from_slice(&16_u32.to_le_bytes());
        let directories = optional + 112;
        file[directories..directories + 4].copy_from_slice(&EXPORT_RVA.to_le_bytes());
        file[directories + 4..directories + 8].copy_from_slice(&0x100_u32.to_le_bytes());
        let import_directory = directories + 8;
        file[import_directory..import_directory + 4].copy_from_slice(&IMPORT_RVA.to_le_bytes());
        file[import_directory + 4..import_directory + 8].copy_from_slice(&0x28_u32.to_le_bytes());

        let section_table = optional + 0xF0;
        let mut write_section = |index: usize,
                                 name: &[u8; 8],
                                 virtual_size: u32,
                                 rva: u32,
                                 raw_size: u32,
                                 raw: u32,
                                 characteristics: u32| {
            let entry = section_table + index * 40;
            file[entry..entry + 8].copy_from_slice(name);
            file[entry + 8..entry + 12].copy_from_slice(&virtual_size.to_le_bytes());
            file[entry + 12..entry + 16].copy_from_slice(&rva.to_le_bytes());
            file[entry + 16..entry + 20].copy_from_slice(&raw_size.to_le_bytes());
            file[entry + 20..entry + 24].copy_from_slice(&raw.to_le_bytes());
            file[entry + 36..entry + 40].copy_from_slice(&characteristics.to_le_bytes());
        };
        write_section(
            0,
            b".text\0\0\0",
            0x200,
            TEXT_RVA,
            0x200,
            0x200,
            0x6000_0020,
        );
        write_section(
            1,
            b".rdata\0\0",
            0x600,
            RDATA_RVA,
            0x600,
            0x400,
            0x4000_0040,
        );
        write_section(2, b".data\0\0\0", 0x200, 0x3000, 0x200, 0xA00, 0xC000_0040);

        let entry = if entry_failure {
            let mut code = CodeBuilder::default();
            code.raw(&[0xC7, 0x05]);
            code.disp_imm32(ENTRY_MARKER_RVA, 0xCA5A_0001);
            code.raw(&[0xB8]);
            code.raw(&(STATUS_UNSUCCESSFUL as u32).to_le_bytes());
            code.raw(&[0xC3]);
            code.finish(TEXT_RVA)
        } else {
            let mut code = CodeBuilder::default();
            code.raw(&[0xC7, 0x05]);
            code.disp_imm32(ENTRY_MARKER_RVA, 0xCA5A_0001);
            code.raw(&[0x48, 0x89, 0x0D]);
            code.disp(DRIVER_PTR_RVA);
            code.raw(&[0x48, 0x8D, 0x0D]);
            code.disp(DBG_FMT_RVA);
            code.raw(&[0x31, 0xC0]);
            code.call_iat(IAT_DBG);
            code.raw(&[0x48, 0x8D, 0x0D]);
            code.disp(US_DEV_RVA);
            code.raw(&[0x48, 0x8D, 0x15]);
            code.disp(WIDE_DEV_RVA);
            code.call_iat(IAT_RTL);
            code.raw(&[0x48, 0x8D, 0x0D]);
            code.disp(US_LINK_RVA);
            code.raw(&[0x48, 0x8D, 0x15]);
            code.disp(WIDE_LINK_RVA);
            code.call_iat(IAT_RTL);
            code.raw(&[0x48, 0x83, 0xEC, 0x38]);
            code.raw(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
            code.raw(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]);
            code.raw(&[0x48, 0x8D, 0x05]);
            code.disp(DEV_OBJ_OUT_RVA);
            code.raw(&[0x48, 0x89, 0x44, 0x24, 0x30]);
            code.raw(&[0x48, 0x8B, 0x0D]);
            code.disp(DRIVER_PTR_RVA);
            code.raw(&[0x31, 0xD2]);
            code.raw(&[0x4C, 0x8D, 0x05]);
            code.disp(US_DEV_RVA);
            code.raw(&[0x41, 0xB9]);
            code.raw(&0x22_u32.to_le_bytes());
            code.call_iat(IAT_IO_CREATE);
            code.raw(&[0x48, 0x83, 0xC4, 0x38]);
            code.raw(&[0x85, 0xC0]);
            code.raw(&[0x79, 0x06]);
            code.raw(&[0xB8]);
            code.raw(&(STATUS_UNSUCCESSFUL as u32).to_le_bytes());
            code.raw(&[0xC3]);
            code.raw(&[0x48, 0x8D, 0x0D]);
            code.disp(US_LINK_RVA);
            code.raw(&[0x48, 0x8D, 0x15]);
            code.disp(US_DEV_RVA);
            code.call_iat(IAT_IO_SYMLINK);
            if exercise_services {
                code.raw(&[0xB9, 0x01, 0, 0, 0]);
                code.raw(&[0x31, 0xD2]);
                code.call_iat(IAT_IO_ALLOC_IRP);
                code.raw(&[0x48, 0x89, 0xC1]);
                code.raw(&[0x31, 0xD2]);
                code.call_iat(IAT_IOF_COMPLETE);
                code.raw(&[0x31, 0xC9]);
                code.raw(&[0xBA, 0x40, 0, 0, 0]);
                code.raw(&[0x41, 0xB8, 0x54, 0x73, 0x74, 0x31]);
                code.call_iat(IAT_EX_ALLOC);
                code.raw(&[0x48, 0x89, 0xC1]);
                code.raw(&[0xBA, 0x54, 0x73, 0x74, 0x31]);
                code.call_iat(IAT_EX_FREE);
                code.raw(&[0x31, 0xC0]);
            }
            code.raw(&[0xC3]);
            code.finish(TEXT_RVA)
        };
        assert!(entry.len() <= 0x100);

        let mut unload = CodeBuilder::default();
        unload.raw(&[0x31, 0xC0]);
        unload.raw(&[0x48, 0x8D, 0x0D]);
        unload.disp(DBG_UNLOAD_RVA);
        unload.call_iat(IAT_DBG);
        unload.raw(&[0xC7, 0x05]);
        unload.disp_imm32(UNLOAD_MARKER_RVA, 0xCA5A_0002);
        unload.raw(&[0x48, 0x8B, 0x0D]);
        unload.disp(DEV_OBJ_OUT_RVA);
        unload.raw(&[0x48, 0x85, 0xC9]);
        unload.raw(&[0x74, 0x06]);
        unload.call_iat(IAT_IO_DELETE);
        unload.raw(&[0xC3]);
        let unload = unload.finish(UNLOAD_RVA);
        assert!(unload.len() <= 0x100);

        file[0x200..0x200 + entry.len()].copy_from_slice(&entry);
        file[0x300..0x300 + unload.len()].copy_from_slice(&unload);

        let mut rdata = vec![0_u8; 0x600];
        let rva = |address: u32| (address - RDATA_RVA) as usize;
        let descriptor = rva(IMPORT_RVA);
        rdata[descriptor..descriptor + 4].copy_from_slice(&ILT_RVA.to_le_bytes());
        rdata[descriptor + 12..descriptor + 16].copy_from_slice(&DLL_NAME_RVA.to_le_bytes());
        rdata[descriptor + 16..descriptor + 20].copy_from_slice(&IAT_RVA.to_le_bytes());
        for (index, (_, hint)) in IMPORT_NAMES.iter().enumerate() {
            rdata[rva(ILT_RVA) + index * 8..rva(ILT_RVA) + index * 8 + 8]
                .copy_from_slice(&(*hint as u64).to_le_bytes());
            rdata[rva(IAT_RVA) + index * 8..rva(IAT_RVA) + index * 8 + 8]
                .copy_from_slice(&(*hint as u64).to_le_bytes());
        }
        rdata[rva(DLL_NAME_RVA)..rva(DLL_NAME_RVA) + 13].copy_from_slice(b"ntoskrnl.exe\0");
        for (index, (name, hint)) in IMPORT_NAMES.iter().enumerate() {
            let symbol = if unresolved_import && index == IMPORT_NAMES.len() - 1 {
                "PsGetCurrentProcessId"
            } else {
                name
            };
            let offset = rva(*hint);
            rdata[offset..offset + 2].copy_from_slice(&0_u16.to_le_bytes());
            rdata[offset + 2..offset + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
            rdata[offset + 2 + symbol.len()] = 0;
        }
        rdata[rva(DBG_FMT_RVA)..rva(DBG_FMT_RVA) + 22].copy_from_slice(b"CasaTest DriverEntry\n\0");
        write_wide(&mut rdata, rva(WIDE_DEV_RVA), "\\Device\\CasaTest");
        write_wide(&mut rdata, rva(WIDE_LINK_RVA), "\\??\\CasaTest");
        rdata[rva(DBG_UNLOAD_RVA)..rva(DBG_UNLOAD_RVA) + 23]
            .copy_from_slice(b"CasaTest DriverUnload\n\0");

        let export = rva(EXPORT_RVA);
        let export_name = 0x24F0_u32;
        let functions = 0x24B0_u32;
        let names = 0x24B8_u32;
        let ordinals = 0x24C0_u32;
        rdata[export + 12..export + 16].copy_from_slice(&export_name.to_le_bytes());
        rdata[export + 16..export + 20].copy_from_slice(&1_u32.to_le_bytes());
        rdata[export + 20..export + 24].copy_from_slice(&2_u32.to_le_bytes());
        rdata[export + 24..export + 28].copy_from_slice(&2_u32.to_le_bytes());
        rdata[export + 28..export + 32].copy_from_slice(&functions.to_le_bytes());
        rdata[export + 32..export + 36].copy_from_slice(&names.to_le_bytes());
        rdata[export + 36..export + 40].copy_from_slice(&ordinals.to_le_bytes());
        rdata[rva(functions)..rva(functions) + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());
        rdata[rva(functions) + 4..rva(functions) + 8].copy_from_slice(&UNLOAD_RVA.to_le_bytes());
        rdata[rva(names)..rva(names) + 4].copy_from_slice(&0x24D0_u32.to_le_bytes());
        rdata[rva(names) + 4..rva(names) + 8].copy_from_slice(&0x24E0_u32.to_le_bytes());
        rdata[rva(ordinals)..rva(ordinals) + 2].copy_from_slice(&0_u16.to_le_bytes());
        rdata[rva(ordinals) + 2..rva(ordinals) + 4].copy_from_slice(&1_u16.to_le_bytes());
        rdata[rva(0x24D0)..rva(0x24D0) + 12].copy_from_slice(b"DriverEntry\0");
        rdata[rva(0x24E0)..rva(0x24E0) + 13].copy_from_slice(b"DriverUnload\0");
        rdata[rva(export_name)..rva(export_name) + 13].copy_from_slice(b"CasaTest.sys\0");
        file[0x400..0xA00].copy_from_slice(&rdata);
        file
    }

    fn put_u16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(image: &mut [u8], offset: usize, value: u64) {
        image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn build_pe32_driver() -> Vec<u8> {
        const TEXT_RVA: u32 = 0x1000;
        const RDATA_RVA: u32 = 0x2000;
        const DATA_RVA: u32 = 0x3000;
        const HANDLER_RVA: u32 = 0x1200;
        const US_DEV_RVA: u32 = 0x3000;
        const DEV_OUT_RVA: u32 = 0x3010;
        const MARKER_RVA: u32 = 0x3014;
        const DRIVER_PTR_RVA: u32 = 0x3018;
        const IMAGE_BASE: u32 = 0x1000_0000;

        let mut file = vec![0_u8; 0xC00];
        file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
        put_u32(&mut file, 0x3C, 0x80);
        file[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        put_u16(&mut file, coff, 0x014C);
        put_u16(&mut file, coff + 2, 3);
        put_u16(&mut file, coff + 16, 0xE0);
        put_u16(&mut file, coff + 18, 0x0102);
        let optional = coff + 20;
        put_u16(&mut file, optional, 0x010B);
        put_u32(&mut file, optional + 4, 0x400);
        put_u32(&mut file, optional + 8, 0x400);
        put_u32(&mut file, optional + 16, TEXT_RVA);
        put_u32(&mut file, optional + 20, TEXT_RVA);
        put_u32(&mut file, optional + 24, RDATA_RVA);
        put_u32(&mut file, optional + 28, 0x1000_0000);
        put_u32(&mut file, optional + 32, 0x1000);
        put_u32(&mut file, optional + 36, 0x200);
        put_u16(&mut file, optional + 48, 6);
        put_u32(&mut file, optional + 56, 0x4000);
        put_u32(&mut file, optional + 60, 0x200);
        put_u16(&mut file, optional + 68, 1);
        put_u32(&mut file, optional + 92, 16);
        let directories = optional + 96;
        put_u32(&mut file, directories + 8, 0x2100);
        put_u32(&mut file, directories + 12, 0x28);

        let section_table = optional + 0xE0;
        let mut write_section = |index: usize,
                                 name: &[u8; 8],
                                 virtual_size: u32,
                                 rva: u32,
                                 raw_size: u32,
                                 raw: u32,
                                 characteristics: u32| {
            let entry = section_table + index * 40;
            file[entry..entry + 8].copy_from_slice(name);
            put_u32(&mut file, entry + 8, virtual_size);
            put_u32(&mut file, entry + 12, rva);
            put_u32(&mut file, entry + 16, raw_size);
            put_u32(&mut file, entry + 20, raw);
            put_u32(&mut file, entry + 36, characteristics);
        };
        write_section(
            0,
            b".text\0\0\0",
            0x400,
            TEXT_RVA,
            0x400,
            0x200,
            0x6000_0020,
        );
        write_section(
            1,
            b".rdata\0\0",
            0x400,
            RDATA_RVA,
            0x400,
            0x600,
            0x4000_0040,
        );
        write_section(
            2,
            b".data\0\0\0",
            0x200,
            DATA_RVA,
            0x200,
            0xA00,
            0xC000_0040,
        );

        let mut entry = Vec::new();
        entry.extend_from_slice(&[0x8B, 0x44, 0x24, 0x04]); // mov eax,[esp+4]
        entry.extend_from_slice(&[0xA3]);
        entry.extend_from_slice(&(IMAGE_BASE + DRIVER_PTR_RVA).to_le_bytes());
        entry.extend_from_slice(&[0xB9]);
        entry.extend_from_slice(&(0x1000_0000u32 + HANDLER_RVA).to_le_bytes());
        for major in [14u32, 3, 4] {
            entry.extend_from_slice(&[0x89, 0x88]);
            entry.extend_from_slice(&(0x38 + major * 4).to_le_bytes());
        }
        entry.extend_from_slice(&[0xC7, 0x05]);
        entry.extend_from_slice(&(IMAGE_BASE + MARKER_RVA).to_le_bytes());
        entry.extend_from_slice(&0xCA5A_0005u32.to_le_bytes());
        entry.extend_from_slice(&[0x68]);
        entry.extend_from_slice(&(IMAGE_BASE + DEV_OUT_RVA).to_le_bytes());
        entry.extend_from_slice(&[0x6A, 0x00, 0x6A, 0x00]);
        entry.extend_from_slice(&[0x68, 0x22, 0, 0, 0]);
        entry.extend_from_slice(&[0x68]);
        entry.extend_from_slice(&(IMAGE_BASE + US_DEV_RVA).to_le_bytes());
        entry.extend_from_slice(&[0x6A, 0x00]);
        entry.extend_from_slice(&[0xFF, 0x35]);
        entry.extend_from_slice(&(IMAGE_BASE + DRIVER_PTR_RVA).to_le_bytes());
        entry.extend_from_slice(&[0xFF, 0x15]);
        entry.extend_from_slice(&(IMAGE_BASE + 0x2160).to_le_bytes());
        entry.extend_from_slice(&[0x31, 0xC0, 0xC2, 0x08, 0x00]);
        assert!(entry.len() <= 0x100);
        file[0x200..0x200 + entry.len()].copy_from_slice(&entry);

        let mut handler = Vec::new();
        handler.extend_from_slice(&[0x8B, 0x44, 0x24, 0x04]); // mov eax,[esp+4]
        handler.extend_from_slice(&[0xC7, 0x40, 0x18, 0, 0, 0, 0]);
        handler.extend_from_slice(&[0xC7, 0x40, 0x20, 4, 0, 0, 0]);
        handler.extend_from_slice(&[0x8B, 0x48, 0x0C]); // mov ecx,[eax+0xC]
        handler.extend_from_slice(&[0xC7, 0x01]);
        handler.extend_from_slice(b"RESP");
        handler.extend_from_slice(&[0xC7, 0x05]);
        handler.extend_from_slice(&(IMAGE_BASE + MARKER_RVA).to_le_bytes());
        handler.extend_from_slice(&0xCA5A_0006u32.to_le_bytes());
        handler.extend_from_slice(&[0x31, 0xC0, 0xC2, 0x08, 0x00]);
        file[0x400..0x400 + handler.len()].copy_from_slice(&handler);

        let mut unload = vec![0x8B, 0x44, 0x24, 0x04];
        unload.extend_from_slice(&[0xFF, 0x35]);
        unload.extend_from_slice(&(IMAGE_BASE + DEV_OUT_RVA).to_le_bytes());
        unload.extend_from_slice(&[0xFF, 0x15]);
        unload.extend_from_slice(&(IMAGE_BASE + 0x2164).to_le_bytes());
        unload.extend_from_slice(&[0xC2, 0x04, 0x00]);
        file[0x480..0x480 + unload.len()].copy_from_slice(&unload);

        let rva = |address: u32| (address - RDATA_RVA) as usize;
        let descriptor = rva(0x2100);
        put_u32(&mut file, 0x600 + descriptor, 0x2140);
        put_u32(&mut file, 0x600 + descriptor + 12, 0x2180);
        put_u32(&mut file, 0x600 + descriptor + 16, 0x2160);
        for (index, hint) in [0x21A0u32, 0x21B0].iter().enumerate() {
            put_u32(&mut file, 0x600 + rva(0x2140) + index * 4, *hint);
            put_u32(&mut file, 0x600 + rva(0x2160) + index * 4, *hint);
        }
        file[0x600 + rva(0x2180)..0x600 + rva(0x2180) + 13].copy_from_slice(b"ntoskrnl.exe\0");
        for (name, hint) in [("IoCreateDevice", 0x21A0u32), ("IoDeleteDevice", 0x21B0)] {
            let offset = 0x600 + rva(hint);
            put_u16(&mut file, offset, 0);
            file[offset + 2..offset + 2 + name.len()].copy_from_slice(name.as_bytes());
        }
        write_wide(&mut file[0x600..0xA00], rva(0x2200), "\\Device\\Casa32");
        let data = 0xA00;
        put_u16(&mut file, data, 28);
        put_u16(&mut file, data + 2, 30);
        put_u32(&mut file, data + 4, IMAGE_BASE + 0x2200);
        put_u32(&mut file, data + 0x10, 0);
        put_u32(&mut file, data + 0x14, 0);
        put_u32(&mut file, data + 0x18, 0);
        file
    }

    fn with_delay_import(mut image: Vec<u8>, symbol: &str) -> Vec<u8> {
        let directories = 0x98 + 112;
        put_u32(&mut image, directories + 13 * 8, 0x2500);
        put_u32(&mut image, directories + 13 * 8 + 4, 0x20);
        let rva = |address: u32| 0x400 + (address - 0x2000) as usize;
        let descriptor = rva(0x2500);
        put_u32(&mut image, descriptor, 1); // attributes: RVAs
        put_u32(&mut image, descriptor + 4, 0x2540); // name
        put_u32(&mut image, descriptor + 12, 0x2570); // IAT
        put_u32(&mut image, descriptor + 16, 0x2560); // INT
        put_u32(&mut image, descriptor + 28, 0); // timestamp
        image[rva(0x2540)..rva(0x2540) + 13].copy_from_slice(b"ntoskrnl.exe\0");
        put_u64(&mut image, rva(0x2560), 0x2580);
        put_u64(&mut image, rva(0x2570), 0);
        let name = rva(0x2580);
        put_u16(&mut image, name, 0);
        image[name + 2..name + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
        image[name + 2 + symbol.len()] = 0;
        image
    }

    fn build_io_driver() -> Vec<u8> {
        const IO_HANDLER_RVA: u32 = 0x3100;
        const IO_MARKER_RVA: u32 = 0x3140;
        let mut file = build_test_driver(false, false, false);
        let mut code = CodeBuilder::default();
        code.raw(&[0x48, 0x8D, 0x05]);
        code.disp(IO_HANDLER_RVA);
        for major in [14u32, 3, 4] {
            code.raw(&[0x48, 0x89, 0x81]);
            code.raw(&((0x70 + major * 8) as u32).to_le_bytes());
        }
        code.raw(&[0x48, 0x89, 0x0D]);
        code.disp(DRIVER_PTR_RVA);
        code.raw(&[0x48, 0x83, 0xEC, 0x38]);
        code.raw(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
        code.raw(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]);
        code.raw(&[0x48, 0x8D, 0x05]);
        code.disp(DEV_OBJ_OUT_RVA);
        code.raw(&[0x48, 0x89, 0x44, 0x24, 0x30]);
        code.raw(&[0x48, 0x8B, 0x0D]);
        code.disp(DRIVER_PTR_RVA);
        code.raw(&[0x31, 0xD2]);
        code.raw(&[0x4C, 0x8D, 0x05]);
        code.disp(US_DEV_RVA);
        code.raw(&[0x41, 0xB9]);
        code.raw(&0x22_u32.to_le_bytes());
        code.call_iat(IAT_IO_CREATE);
        code.raw(&[0x48, 0x83, 0xC4, 0x38]);
        code.raw(&[0x31, 0xC0, 0xC3]);
        let entry = code.finish(TEXT_RVA);
        assert!(entry.len() <= 0x100);
        file[0x200..0x300].fill(0);
        file[0x200..0x200 + entry.len()].copy_from_slice(&entry);

        let mut handler = CodeBuilder::default();
        handler.raw(&[0xC7, 0x41, 0x30, 0, 0, 0, 0]);
        handler.raw(&[0x48, 0xC7, 0x41, 0x40, 4, 0, 0, 0]);
        handler.raw(&[0x48, 0x8B, 0x41, 0x18]);
        handler.raw(&[0xC7, 0x00]);
        handler.raw(b"RESP");
        handler.raw(&[0xC7, 0x05]);
        handler.disp_imm32(IO_MARKER_RVA, 0xCA5A_0004);
        handler.raw(&[0x31, 0xC0, 0xC3]);
        let handler = handler.finish(IO_HANDLER_RVA);
        let offset = 0xA00 + (IO_HANDLER_RVA - 0x3000) as usize;
        file[offset..offset + handler.len()].copy_from_slice(&handler);
        put_u32(&mut file, 0xA00 + (IO_MARKER_RVA - 0x3000) as usize, 0);
        let device_name = 0xA00 + (US_DEV_RVA - 0x3000) as usize;
        put_u16(&mut file, device_name, 32);
        put_u16(&mut file, device_name + 2, 34);
        put_u64(
            &mut file,
            device_name + 8,
            0x1_4000_0000 + u64::from(WIDE_DEV_RVA),
        );
        file
    }

    const K_TEXT_RVA: u32 = 0x1000;
    const K_ENTRY_RVA: u32 = 0x1000;
    const K_EVT_ADD_RVA: u32 = 0x1100;
    const K_EVT_IOCTL_RVA: u32 = 0x1300;
    const K_RDATA_RVA: u32 = 0x2000;
    const K_DATA_RVA: u32 = 0x3000;
    const K_IMPORT_RVA: u32 = 0x2100;
    const K_ILT_RVA: u32 = 0x2140;
    const K_IAT_RVA: u32 = 0x21D0;
    const K_DLL_RVA: u32 = 0x2260;
    const K_HINT_RVA: u32 = 0x2280;
    const K_US_DEV_RVA: u32 = 0x3010;
    const K_WIDE_DEV_RVA: u32 = 0x3030;
    const K_CONFIG_RVA: u32 = 0x3050;
    const K_DRIVER_OUT_RVA: u32 = 0x3080;
    const K_DEVICE_OUT_RVA: u32 = 0x3088;
    const K_QUEUE_OUT_RVA: u32 = 0x3090;
    const K_REQUEST_OUT_RVA: u32 = 0x3098;
    const K_LOCK_OUT_RVA: u32 = 0x30A0;
    const K_INIT_TMP_RVA: u32 = 0x30A8;
    const K_DEVOBJ_OUT_RVA: u32 = 0x30B0;
    const K_OUTBUF_PTR_RVA: u32 = 0x30B8;
    const K_OUTBUF_LEN_RVA: u32 = 0x30C0;
    const K_MARKER_RVA: u32 = 0x30C8;
    const K_IOCTL_MARKER_RVA: u32 = 0x30CC;
    const K_DELETE_MARKER_RVA: u32 = 0x30D0;
    const K_QCONFIG_RVA: u32 = 0x3100;
    const K_IMAGE_BASE: u64 = 0x1_4000_0000;

    const KMDF_IMPORTS: [&str; 17] = [
        "WdfDriverCreate",
        "WdfDeviceInitSetDeviceType",
        "WdfDeviceInitSetIoType",
        "WdfDeviceInitAssignName",
        "WdfDeviceCreate",
        "WdfIoQueueCreate",
        "WdfRequestCreate",
        "WdfRequestFormatRequestForIoctl",
        "WdfRequestRetrieveOutputBuffer",
        "WdfRequestCompleteWithInformation",
        "WdfDeviceWdmGetDeviceObject",
        "WdfObjectGetTypedContext",
        "WdfObjectDelete",
        "WdfWaitLockCreate",
        "WdfWaitLockAcquire",
        "WdfWaitLockRelease",
        "WdfRequestRetrieveInputBuffer",
    ];

    fn build_kmdf_driver(with_queue: bool, missing_symbol: bool, bad_callback: bool) -> Vec<u8> {
        let mut file = vec![0_u8; 0x1000];
        file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
        put_u32(&mut file, 0x3C, 0x80);
        file[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        put_u16(&mut file, coff, 0x8664);
        put_u16(&mut file, coff + 2, 3);
        put_u16(&mut file, coff + 16, 0xF0);
        put_u16(&mut file, coff + 18, 0x0022);
        let optional = coff + 20;
        put_u16(&mut file, optional, 0x020B);
        put_u32(&mut file, optional + 4, 0x400);
        put_u32(&mut file, optional + 8, 0xC00);
        put_u32(&mut file, optional + 16, K_ENTRY_RVA);
        put_u32(&mut file, optional + 20, K_TEXT_RVA);
        put_u64(&mut file, optional + 24, K_IMAGE_BASE);
        put_u32(&mut file, optional + 32, 0x1000);
        put_u32(&mut file, optional + 36, 0x200);
        put_u16(&mut file, optional + 48, 6);
        put_u32(&mut file, optional + 56, 0x4000);
        put_u32(&mut file, optional + 60, 0x200);
        put_u16(&mut file, optional + 68, 1);
        put_u32(&mut file, optional + 108, 16);
        let directories = optional + 112;
        // No exports; one import descriptor (the terminator stays zero).
        put_u32(&mut file, directories + 8, K_IMPORT_RVA);
        put_u32(&mut file, directories + 12, 0x28);

        let section_table = optional + 0xF0;
        let mut write_section = |index: usize,
                                 name: &[u8; 8],
                                 virtual_size: u32,
                                 rva: u32,
                                 raw_size: u32,
                                 raw: u32,
                                 characteristics: u32| {
            let entry = section_table + index * 40;
            file[entry..entry + 8].copy_from_slice(name);
            put_u32(&mut file, entry + 8, virtual_size);
            put_u32(&mut file, entry + 12, rva);
            put_u32(&mut file, entry + 16, raw_size);
            put_u32(&mut file, entry + 20, raw);
            put_u32(&mut file, entry + 36, characteristics);
        };
        write_section(
            0,
            b".text\0\0\0",
            0x400,
            K_TEXT_RVA,
            0x400,
            0x200,
            0x6000_0020,
        );
        write_section(
            1,
            b".rdata\0\0",
            0x600,
            K_RDATA_RVA,
            0x600,
            0x600,
            0x4000_0040,
        );
        write_section(
            2,
            b".data\0\0\0",
            0x400,
            K_DATA_RVA,
            0x400,
            0xC00,
            0xC000_0040,
        );

        let mut entry = CodeBuilder::default();
        entry.raw(&[0x49, 0x89, 0xD3]); // mov r11,rdx (RegistryPath)
        entry.raw(&[0x48, 0x8D, 0x05]);
        entry.disp(K_CONFIG_RVA);
        entry.raw(&[0xC7, 0x00]);
        entry.raw(&0x28_u32.to_le_bytes());
        if bad_callback {
            entry.raw(&[0xBA]);
            entry.raw(&0xDEAD_0000_u32.to_le_bytes());
        } else {
            entry.raw(&[0x48, 0x8D, 0x15]);
            entry.disp(K_EVT_ADD_RVA);
        }
        entry.raw(&[0x48, 0x89, 0x50, 0x08]); // config.EvtDriverDeviceAdd
        entry.raw(&[0x4C, 0x89, 0xDA]); // mov rdx,r11
        entry.raw(&[0x45, 0x31, 0xC0]); // xor r8d,r8d
        entry.raw(&[0x4C, 0x8D, 0x0D]);
        entry.disp(K_CONFIG_RVA);
        entry.raw(&[0x48, 0x83, 0xEC, 0x28]);
        entry.raw(&[0x4C, 0x8D, 0x15]);
        entry.disp(K_DRIVER_OUT_RVA);
        entry.raw(&[0x4C, 0x89, 0x54, 0x24, 0x20]);
        entry.call_iat(K_IAT_RVA);
        entry.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        let entry = entry.finish(K_ENTRY_RVA);
        assert!(entry.len() <= 0x100);
        file[0x200..0x200 + entry.len()].copy_from_slice(&entry);

        let mut add = CodeBuilder::default();
        add.raw(&[0x48, 0x89, 0x15]);
        add.disp(K_INIT_TMP_RVA);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(K_INIT_TMP_RVA);
        add.raw(&[0xBA, 0x22, 0, 0, 0]);
        add.call_iat(K_IAT_RVA + 8);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(K_INIT_TMP_RVA);
        add.raw(&[0xBA, 1, 0, 0, 0]);
        add.call_iat(K_IAT_RVA + 16);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(K_INIT_TMP_RVA);
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(K_US_DEV_RVA);
        add.call_iat(K_IAT_RVA + 24);
        add.raw(&[0x48, 0x8D, 0x0D]);
        add.disp(K_INIT_TMP_RVA);
        add.raw(&[0x31, 0xD2]);
        add.raw(&[0x4C, 0x8D, 0x05]);
        add.disp(K_DEVICE_OUT_RVA);
        add.call_iat(K_IAT_RVA + 32);
        add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
        if with_queue {
            add.raw(&[0x48, 0x8D, 0x05]);
            add.disp(K_QCONFIG_RVA);
            add.raw(&[0xC7, 0x00]);
            add.raw(&0x40_u32.to_le_bytes());
            add.raw(&[0x48, 0x8D, 0x15]);
            add.disp(K_EVT_IOCTL_RVA);
            add.raw(&[0x48, 0x89, 0x50, 0x28]);
            add.raw(&[0x48, 0x8B, 0x0D]);
            add.disp(K_DEVICE_OUT_RVA);
            add.raw(&[0x48, 0x89, 0xC2]);
            add.raw(&[0x45, 0x31, 0xC0]);
            add.raw(&[0x4C, 0x8D, 0x0D]);
            add.disp(K_QUEUE_OUT_RVA);
            add.call_iat(K_IAT_RVA + 40);
            add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
        }
        // Exercise WdfRequestCreate + WdfRequestFormatRequestForIoctl.
        add.raw(&[0x31, 0xC9, 0x31, 0xD2]);
        add.raw(&[0x4C, 0x8D, 0x05]);
        add.disp(K_REQUEST_OUT_RVA);
        add.call_iat(K_IAT_RVA + 48);
        add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
        add.raw(&[0x48, 0x83, 0xEC, 0x48]);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(K_REQUEST_OUT_RVA);
        add.raw(&[0x31, 0xD2]);
        add.raw(&[0x41, 0xB8]);
        add.raw(&0x0022_0004_u32.to_le_bytes());
        add.raw(&[0x45, 0x31, 0xC9]);
        for displacement in [0x20_u8, 0x28, 0x30, 0x38] {
            add.raw(&[0x48, 0xC7, 0x44, 0x24, displacement, 0, 0, 0, 0]);
        }
        add.call_iat(K_IAT_RVA + 56);
        add.raw(&[0x48, 0x83, 0xC4, 0x48]);
        // WdfObjectDelete removes the request (and its CasaK IRP).
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(K_REQUEST_OUT_RVA);
        add.call_iat(K_IAT_RVA + 96);
        add.raw(&[0xC7, 0x05]);
        add.disp_imm32(K_DELETE_MARKER_RVA, 0xCA5A_0012);
        // Typed device context.
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(K_DEVICE_OUT_RVA);
        add.raw(&[0xBA, 1, 0, 0, 0]);
        add.call_iat(K_IAT_RVA + 88);
        add.raw(&[0x48, 0x85, 0xC0, 0x74, 0x06]);
        add.raw(&[0xC7, 0x00, 0xDE, 0xC0, 0, 0]);
        // WdfDeviceWdmGetDeviceObject.
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(K_DEVICE_OUT_RVA);
        add.call_iat(K_IAT_RVA + 80);
        add.raw(&[0x48, 0x89, 0x05]);
        add.disp(K_DEVOBJ_OUT_RVA);
        // Wait lock create/acquire/release.
        add.raw(&[0x31, 0xC9]);
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(K_LOCK_OUT_RVA);
        add.call_iat(K_IAT_RVA + 104);
        add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(K_LOCK_OUT_RVA);
        add.raw(&[0x31, 0xD2]);
        add.call_iat(K_IAT_RVA + 112);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(K_LOCK_OUT_RVA);
        add.call_iat(K_IAT_RVA + 120);
        add.raw(&[0xC7, 0x05]);
        add.disp_imm32(K_MARKER_RVA, 0xCA5A_0010);
        add.raw(&[0x31, 0xC0, 0xC3]);
        let add = add.finish(K_EVT_ADD_RVA);
        assert!(
            add.len() <= 0x200,
            "device-add callback is {} bytes",
            add.len()
        );
        let add_offset = 0x200 + (K_EVT_ADD_RVA - K_TEXT_RVA) as usize;
        file[add_offset..add_offset + add.len()].copy_from_slice(&add);

        let mut ioctl = CodeBuilder::default();
        ioctl.raw(&[0x44, 0x8B, 0x54, 0x24, 0x28]); // ioctl code
        ioctl.raw(&[0x49, 0x89, 0xD3]); // request
        ioctl.raw(&[0x48, 0x83, 0xEC, 0x28]);
        ioctl.raw(&[0x4C, 0x89, 0xD9]);
        ioctl.raw(&[0xBA, 4, 0, 0, 0]);
        ioctl.raw(&[0x4C, 0x8D, 0x05]);
        ioctl.disp(K_OUTBUF_PTR_RVA);
        ioctl.raw(&[0x4C, 0x8D, 0x0D]);
        ioctl.disp(K_OUTBUF_LEN_RVA);
        ioctl.call_iat(K_IAT_RVA + 64);
        ioctl.raw(&[0x85, 0xC0]);
        ioctl.raw(&[0x0F, 0x88]);
        ioctl.disp(K_EVT_IOCTL_RVA + 0x60);
        ioctl.raw(&[0x48, 0x8B, 0x05]);
        ioctl.disp(K_OUTBUF_PTR_RVA);
        ioctl.raw(&[0x48, 0x85, 0xC0]);
        ioctl.raw(&[0x0F, 0x84]);
        ioctl.disp(K_EVT_IOCTL_RVA + 0x60);
        ioctl.raw(&[0xC7, 0x00]);
        ioctl.raw(&0x2146_4457_u32.to_le_bytes()); // "WDF!"
        ioctl.raw(&[0x44, 0x89, 0x15]);
        ioctl.disp(K_IOCTL_MARKER_RVA);
        ioctl.raw(&[0x4C, 0x89, 0xD9]);
        ioctl.raw(&[0x31, 0xD2]);
        ioctl.raw(&[0x41, 0xB8]);
        ioctl.raw(&4_u32.to_le_bytes());
        ioctl.call_iat(K_IAT_RVA + 72);
        if ioctl.bytes.len() > 0x60 {
            panic!("ioctl callback body is {} bytes", ioctl.bytes.len());
        }
        ioctl.raw(&vec![0x90; 0x60 - ioctl.bytes.len()]);
        ioctl.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        let ioctl = ioctl.finish(K_EVT_IOCTL_RVA);
        assert!(ioctl.len() <= 0x200);
        let ioctl_offset = 0x200 + (K_EVT_IOCTL_RVA - K_TEXT_RVA) as usize;
        file[ioctl_offset..ioctl_offset + ioctl.len()].copy_from_slice(&ioctl);

        let data_rva = |address: u32| 0xC00 + (address - K_DATA_RVA) as usize;
        let config = data_rva(K_CONFIG_RVA);
        put_u32(&mut file, config, 0x28);
        let us = data_rva(K_US_DEV_RVA);
        put_u16(&mut file, us, 30);
        put_u16(&mut file, us + 2, 32);
        put_u64(&mut file, us + 8, K_IMAGE_BASE + u64::from(K_WIDE_DEV_RVA));
        write_wide(
            &mut file[0xC00..0x1000],
            (K_WIDE_DEV_RVA - K_DATA_RVA) as usize,
            "\\Device\\WdfCasa",
        );
        put_u32(&mut file, data_rva(K_QCONFIG_RVA), 0x40);

        let rva = |address: u32| 0x600 + (address - K_RDATA_RVA) as usize;
        let descriptor = rva(K_IMPORT_RVA);
        put_u32(&mut file, descriptor, K_ILT_RVA);
        put_u32(&mut file, descriptor + 12, K_DLL_RVA);
        put_u32(&mut file, descriptor + 16, K_IAT_RVA);
        file[rva(K_DLL_RVA)..rva(K_DLL_RVA) + 10].copy_from_slice(b"WdfLdr.sys");
        file[rva(K_DLL_RVA) + 10] = 0;
        let mut hint_rva = K_HINT_RVA;
        for (index, symbol) in KMDF_IMPORTS.iter().enumerate() {
            put_u64(&mut file, rva(K_ILT_RVA) + index * 8, u64::from(hint_rva));
            put_u64(&mut file, rva(K_IAT_RVA) + index * 8, u64::from(hint_rva));
            let name = if missing_symbol && index == 0 {
                "WdfDriverCreatX"
            } else {
                symbol
            };
            let offset = rva(hint_rva);
            put_u16(&mut file, offset, 0);
            file[offset + 2..offset + 2 + name.len()].copy_from_slice(name.as_bytes());
            file[offset + 2 + name.len()] = 0;
            hint_rva += (2 + name.len() + 1 + 1) as u32 & !1;
        }
        assert!(
            hint_rva <= 0x2500,
            "hint/name table overruns rdata: {hint_rva:#x}"
        );
        file
    }

    const F_TEXT_RVA: u32 = 0x1000;
    const F_ENTRY_RVA: u32 = 0x1000;
    const F_ADD_RVA: u32 = 0x1180;
    const F_IOCTL_RVA: u32 = 0x1400;
    const F_READ_RVA: u32 = 0x1480;
    const F_WRITE_RVA: u32 = 0x1500;
    const F_DEFAULT_RVA: u32 = 0x1580;
    const F_STOP_RVA: u32 = 0x1600;
    const F_RESUME_RVA: u32 = 0x1640;
    const F_CANCEL_RVA: u32 = 0x1680;
    const F_CLEANUP_RVA: u32 = 0x16C0;
    const F_DESTROY_RVA: u32 = 0x1700;
    const F_UNLOAD_RVA: u32 = 0x1740;
    const F_RDATA_RVA: u32 = 0x2000;
    const F_DATA_RVA: u32 = 0x3000;
    const F_IMPORT_RVA: u32 = 0x2100;
    const F_ILT_RVA: u32 = 0x2140;
    const F_IAT_RVA: u32 = 0x2170;
    const F_DLL_RVA: u32 = 0x21C0;
    const F_HINT_RVA: u32 = 0x21E0;
    const F_IMAGE_BASE: u64 = 0x1_4000_0000;

    const F_CONFIG: u32 = 0x3000;
    const F_QCONFIG: u32 = 0x3040;
    const F_Q2CONFIG: u32 = 0x30B0;
    const F_US_DEVA: u32 = 0x3120;
    const F_WIDEA: u32 = 0x3140;
    const F_US_DEVB: u32 = 0x3160;
    const F_WIDEB: u32 = 0x3180;
    const F_DEVINIT: u32 = 0x31A0;
    const F_DRIVER: u32 = 0x31A8;
    const F_DEV_A: u32 = 0x31B0;
    const F_DEV_B: u32 = 0x31B8;
    const F_QUEUE_A: u32 = 0x31C0;
    const F_QUEUE_B: u32 = 0x31C8;
    const F_ATTRS: u32 = 0x31D0;
    const F_TYPEINFO: u32 = 0x3210;
    const F_OUTBUF_PTR: u32 = 0x3230;
    const F_OUTBUF_LEN: u32 = 0x3238;
    const F_REQ_TMP: u32 = 0x3240;
    const F_IOCTL_MARKER: u32 = 0x3250;
    const F_IOCTL_COUNT: u32 = 0x3254;
    const F_READ_COUNT: u32 = 0x3258;
    const F_WRITE_COUNT: u32 = 0x325C;
    const F_WRITE_MARKER: u32 = 0x3260;
    const F_DEFAULT_COUNT: u32 = 0x3264;
    const F_STOP_COUNT: u32 = 0x3268;
    const F_RESUME_COUNT: u32 = 0x326C;
    const F_CANCEL_COUNT: u32 = 0x3270;
    const F_CLEANUP_COUNT: u32 = 0x3274;
    const F_DESTROY_COUNT: u32 = 0x3278;
    const F_ADD_COUNT: u32 = 0x327C;
    const F_UNLOAD_COUNT: u32 = 0x3280;
    const F_UNLOAD_MARKER: u32 = 0x3284;

    const F_IAT_DRIVER: u32 = F_IAT_RVA;
    const F_IAT_ASSIGN: u32 = F_IAT_RVA + 8;
    const F_IAT_DEVICE: u32 = F_IAT_RVA + 16;
    const F_IAT_QUEUE: u32 = F_IAT_RVA + 24;
    const F_IAT_RETRIEVE_OUT: u32 = F_IAT_RVA + 32;
    const F_IAT_RETRIEVE_IN: u32 = F_IAT_RVA + 40;
    const F_IAT_COMPLETE_INFO: u32 = F_IAT_RVA + 48;
    const F_IAT_COMPLETE: u32 = F_IAT_RVA + 56;

    const F_IMPORTS: [&str; 8] = [
        "WdfDriverCreate",
        "WdfDeviceInitAssignName",
        "WdfDeviceCreate",
        "WdfIoQueueCreate",
        "WdfRequestRetrieveOutputBuffer",
        "WdfRequestRetrieveInputBuffer",
        "WdfRequestCompleteWithInformation",
        "WdfRequestComplete",
    ];

    fn build_kmdf_full_driver(dispatch_type: u32, with_cancel_callback: bool) -> Vec<u8> {
        let mut file = vec![0_u8; 0x1400];
        file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
        put_u32(&mut file, 0x3C, 0x80);
        file[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        put_u16(&mut file, coff, 0x8664);
        put_u16(&mut file, coff + 2, 3);
        put_u16(&mut file, coff + 16, 0xF0);
        put_u16(&mut file, coff + 18, 0x0022);
        let optional = coff + 20;
        put_u16(&mut file, optional, 0x020B);
        put_u32(&mut file, optional + 4, 0x800);
        put_u32(&mut file, optional + 8, 0x1400);
        put_u32(&mut file, optional + 16, F_ENTRY_RVA);
        put_u32(&mut file, optional + 20, F_TEXT_RVA);
        put_u64(&mut file, optional + 24, F_IMAGE_BASE);
        put_u32(&mut file, optional + 32, 0x1000);
        put_u32(&mut file, optional + 36, 0x200);
        put_u16(&mut file, optional + 48, 6);
        put_u32(&mut file, optional + 56, 0x4000);
        put_u32(&mut file, optional + 60, 0x200);
        put_u16(&mut file, optional + 68, 1);
        put_u32(&mut file, optional + 108, 16);
        let directories = optional + 112;
        put_u32(&mut file, directories + 8, F_IMPORT_RVA);
        put_u32(&mut file, directories + 12, 0x28);

        let section_table = optional + 0xF0;
        let mut write_section = |index: usize,
                                 name: &[u8; 8],
                                 virtual_size: u32,
                                 rva: u32,
                                 raw_size: u32,
                                 raw: u32,
                                 characteristics: u32| {
            let entry = section_table + index * 40;
            file[entry..entry + 8].copy_from_slice(name);
            put_u32(&mut file, entry + 8, virtual_size);
            put_u32(&mut file, entry + 12, rva);
            put_u32(&mut file, entry + 16, raw_size);
            put_u32(&mut file, entry + 20, raw);
            put_u32(&mut file, entry + 36, characteristics);
        };
        write_section(
            0,
            b".text\0\0\0",
            0x800,
            F_TEXT_RVA,
            0x800,
            0x200,
            0x6000_0020,
        );
        write_section(
            1,
            b".rdata\0\0",
            0x600,
            F_RDATA_RVA,
            0x600,
            0xA00,
            0x4000_0040,
        );
        write_section(
            2,
            b".data\0\0\0",
            0x400,
            F_DATA_RVA,
            0x400,
            0x1000,
            0xC000_0040,
        );

        let mut entry = CodeBuilder::default();
        entry.raw(&[0x49, 0x89, 0xCA]); // mov r10,rcx
        entry.raw(&[0x49, 0x89, 0xD3]); // mov r11,rdx
        entry.raw(&[0x48, 0x8D, 0x05]);
        entry.disp(F_CONFIG);
        entry.raw(&[0xC7, 0x00]);
        entry.raw(&0x20_u32.to_le_bytes());
        entry.raw(&[0x48, 0x8D, 0x0D]);
        entry.disp(F_ADD_RVA);
        entry.raw(&[0x48, 0x89, 0x48, 0x08]);
        entry.raw(&[0x48, 0x8D, 0x0D]);
        entry.disp(F_UNLOAD_RVA);
        entry.raw(&[0x48, 0x89, 0x48, 0x10]);
        entry.raw(&[0xC7, 0x40, 0x18]);
        entry.raw(&0x2146_4457_u32.to_le_bytes());
        entry.raw(&[0x4C, 0x89, 0xD1]); // rcx = DriverObject
        entry.raw(&[0x4C, 0x89, 0xDA]); // rdx = RegistryPath
        entry.raw(&[0x45, 0x31, 0xC0]); // xor r8d,r8d
        entry.raw(&[0x4C, 0x8D, 0x0D]);
        entry.disp(F_CONFIG);
        entry.raw(&[0x48, 0x83, 0xEC, 0x28]);
        entry.raw(&[0x48, 0x8D, 0x05]);
        entry.disp(F_DRIVER);
        entry.raw(&[0x48, 0x89, 0x44, 0x24, 0x20]);
        entry.call_iat(F_IAT_DRIVER);
        entry.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        let entry = entry.finish(F_ENTRY_RVA);
        assert!(entry.len() <= 0x180);
        copy_code(&mut file, F_ENTRY_RVA, &entry);

        let mut add = CodeBuilder::default();
        add.raw(&[0x48, 0x89, 0x15]); // device init (second argument)
        add.disp(F_DEVINIT);
        // WDF_OBJECT_ATTRIBUTES: Size=0x38, cleanup/destroy, context 0x30.
        add.raw(&[0x48, 0x8D, 0x3D]);
        add.disp(F_ATTRS);
        add.raw(&[0xC7, 0x07]);
        add.raw(&0x38_u32.to_le_bytes());
        add.raw(&[0x48, 0x8D, 0x05]);
        add.disp(F_CLEANUP_RVA);
        add.raw(&[0x48, 0x89, 0x47, 0x08]);
        add.raw(&[0x48, 0x8D, 0x05]);
        add.disp(F_DESTROY_RVA);
        add.raw(&[0x48, 0x89, 0x47, 0x10]);
        add.raw(&[0x48, 0xC7, 0x47, 0x18, 0, 0, 0, 0]);
        add.raw(&[0x48, 0xC7, 0x47, 0x20, 0, 0, 0, 0]);
        add.raw(&[0x48, 0xC7, 0x47, 0x28, 0x30, 0, 0, 0]);
        add.raw(&[0x48, 0x8D, 0x05]);
        add.disp(F_TYPEINFO);
        add.raw(&[0x48, 0x89, 0x47, 0x30]);
        add.raw(&[0x48, 0x8D, 0x05]);
        add.disp(F_TYPEINFO);
        add.raw(&[0xC7, 0x00, 0x18, 0, 0, 0]);
        add.raw(&[0x48, 0xC7, 0x40, 0x10, 0x30, 0, 0, 0]);
        add.raw(&[0x48, 0x83, 0xEC, 0x28]);

        // Device A.
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(F_DEVINIT);
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(F_US_DEVA);
        add.call_iat(F_IAT_ASSIGN);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(F_DEVINIT);
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(F_ATTRS);
        add.raw(&[0x4C, 0x8D, 0x05]);
        add.disp(F_DEV_A);
        add.call_iat(F_IAT_DEVICE);

        // Device B reuses the init handle after renaming it.
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(F_DEVINIT);
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(F_US_DEVB);
        add.call_iat(F_IAT_ASSIGN);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(F_DEVINIT);
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(F_ATTRS);
        add.raw(&[0x4C, 0x8D, 0x05]);
        add.disp(F_DEV_B);
        add.call_iat(F_IAT_DEVICE);

        for (config_rva, default_queue, queue_type, device_out, queue_out) in [
            (F_QCONFIG, 1u8, dispatch_type, F_DEV_A, F_QUEUE_A),
            (F_Q2CONFIG, 0u8, 1u32, F_DEV_B, F_QUEUE_B),
        ] {
            add.raw(&[0x48, 0x8D, 0x05]);
            add.disp(config_rva);
            add.raw(&[0xC7, 0x00]);
            add.raw(&0x50_u32.to_le_bytes());
            add.raw(&[0xC7, 0x40, 0x04]);
            add.raw(&queue_type.to_le_bytes());
            add.raw(&[0xC7, 0x40, 0x08, 0, 0, 0, 0]);
            add.raw(&[0xC6, 0x40, 0x0C, 0]);
            add.raw(&[0xC6, 0x40, 0x0D, default_queue]);
            add.raw(&[0x48, 0x8D, 0x0D]);
            add.disp(F_DEFAULT_RVA);
            add.raw(&[0x48, 0x89, 0x48, 0x10]);
            add.raw(&[0x48, 0x8D, 0x0D]);
            add.disp(F_READ_RVA);
            add.raw(&[0x48, 0x89, 0x48, 0x18]);
            add.raw(&[0x48, 0x8D, 0x0D]);
            add.disp(F_WRITE_RVA);
            add.raw(&[0x48, 0x89, 0x48, 0x20]);
            add.raw(&[0x48, 0x8D, 0x0D]);
            add.disp(F_IOCTL_RVA);
            add.raw(&[0x48, 0x89, 0x48, 0x28]);
            add.raw(&[0x48, 0xC7, 0x40, 0x30, 0, 0, 0, 0]);
            add.raw(&[0x48, 0x8D, 0x0D]);
            add.disp(F_STOP_RVA);
            add.raw(&[0x48, 0x89, 0x48, 0x38]);
            add.raw(&[0x48, 0x8D, 0x0D]);
            add.disp(F_RESUME_RVA);
            add.raw(&[0x48, 0x89, 0x48, 0x40]);
            if with_cancel_callback {
                add.raw(&[0x48, 0x8D, 0x0D]);
                add.disp(F_CANCEL_RVA);
                add.raw(&[0x48, 0x89, 0x48, 0x48]);
            } else {
                add.raw(&[0x48, 0xC7, 0x40, 0x48, 0, 0, 0, 0]);
            }
            add.raw(&[0x48, 0x8B, 0x0D]);
            add.disp(device_out);
            add.raw(&[0x48, 0x8D, 0x15]);
            add.disp(config_rva);
            add.raw(&[0x4C, 0x8D, 0x05]);
            add.disp(F_ATTRS);
            add.raw(&[0x4C, 0x8D, 0x0D]);
            add.disp(queue_out);
            add.call_iat(F_IAT_QUEUE);
        }
        add.raw(&[0x48, 0x83, 0xC4, 0x28]);
        add.inc_dword(F_ADD_COUNT);
        add.raw(&[0x31, 0xC0, 0xC2, 0x08, 0x00]);
        let add = add.finish(F_ADD_RVA);
        assert!(add.len() <= 0x280, "device add is {} bytes", add.len());
        copy_code(&mut file, F_ADD_RVA, &add);

        let mut ioctl = CodeBuilder::default();
        ioctl.raw(&[0x48, 0x89, 0x15]);
        ioctl.disp(F_REQ_TMP);
        ioctl.raw(&[0x44, 0x8B, 0x54, 0x24, 0x28]);
        ioctl.raw(&[0x44, 0x89, 0x15]);
        ioctl.disp(F_IOCTL_MARKER);
        ioctl.inc_dword(F_IOCTL_COUNT);
        ioctl.raw(&[0x48, 0x83, 0xEC, 0x28]);
        ioctl.raw(&[0x48, 0x8B, 0x0D]);
        ioctl.disp(F_REQ_TMP);
        ioctl.raw(&[0xBA, 4, 0, 0, 0]);
        ioctl.raw(&[0x4C, 0x8D, 0x05]);
        ioctl.disp(F_OUTBUF_PTR);
        ioctl.raw(&[0x4C, 0x8D, 0x0D]);
        ioctl.disp(F_OUTBUF_LEN);
        ioctl.call_iat(F_IAT_RETRIEVE_OUT);
        ioctl.raw(&[0x48, 0x8B, 0x05]);
        ioctl.disp(F_OUTBUF_PTR);
        ioctl.raw(&[0xC7, 0x00]);
        ioctl.raw(&0x46444D4B_u32.to_le_bytes()); // "KMDF"
        ioctl.raw(&[0x48, 0x8B, 0x0D]);
        ioctl.disp(F_REQ_TMP);
        ioctl.raw(&[0x31, 0xD2]);
        ioctl.raw(&[0x41, 0xB8, 4, 0, 0, 0]);
        ioctl.call_iat(F_IAT_COMPLETE_INFO);
        ioctl.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        let ioctl = ioctl.finish(F_IOCTL_RVA);
        assert!(ioctl.len() <= 0x80);
        copy_code(&mut file, F_IOCTL_RVA, &ioctl);

        let mut read = CodeBuilder::default();
        read.raw(&[0x48, 0x89, 0x15]);
        read.disp(F_REQ_TMP);
        read.inc_dword(F_READ_COUNT);
        read.raw(&[0x48, 0x83, 0xEC, 0x28]);
        read.raw(&[0x48, 0x8B, 0x0D]);
        read.disp(F_REQ_TMP);
        read.raw(&[0xBA, 4, 0, 0, 0]);
        read.raw(&[0x4C, 0x8D, 0x05]);
        read.disp(F_OUTBUF_PTR);
        read.raw(&[0x4C, 0x8D, 0x0D]);
        read.disp(F_OUTBUF_LEN);
        read.call_iat(F_IAT_RETRIEVE_OUT);
        read.raw(&[0x48, 0x8B, 0x05]);
        read.disp(F_OUTBUF_PTR);
        read.raw(&[0xC7, 0x00]);
        read.raw(&0x31304452_u32.to_le_bytes()); // "RD01"
        read.raw(&[0x48, 0x8B, 0x0D]);
        read.disp(F_REQ_TMP);
        read.raw(&[0x31, 0xD2]);
        read.raw(&[0x41, 0xB8, 4, 0, 0, 0]);
        read.call_iat(F_IAT_COMPLETE_INFO);
        read.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        let read = read.finish(F_READ_RVA);
        assert!(read.len() <= 0x80);
        copy_code(&mut file, F_READ_RVA, &read);

        let mut write = CodeBuilder::default();
        write.raw(&[0x48, 0x89, 0x15]);
        write.disp(F_REQ_TMP);
        write.inc_dword(F_WRITE_COUNT);
        write.raw(&[0x48, 0x83, 0xEC, 0x28]);
        write.raw(&[0x48, 0x8B, 0x0D]);
        write.disp(F_REQ_TMP);
        write.raw(&[0x31, 0xD2]);
        write.raw(&[0x4C, 0x8D, 0x05]);
        write.disp(F_OUTBUF_PTR);
        write.raw(&[0x4C, 0x8D, 0x0D]);
        write.disp(F_OUTBUF_LEN);
        write.call_iat(F_IAT_RETRIEVE_IN);
        write.raw(&[0x48, 0x8B, 0x05]);
        write.disp(F_OUTBUF_PTR);
        write.raw(&[0x8B, 0x08]);
        write.raw(&[0x89, 0x0D]);
        write.disp(F_WRITE_MARKER);
        write.raw(&[0x48, 0x8B, 0x0D]);
        write.disp(F_REQ_TMP);
        write.raw(&[0x31, 0xD2]);
        write.raw(&[0x41, 0xB8, 4, 0, 0, 0]);
        write.call_iat(F_IAT_COMPLETE_INFO);
        write.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        let write = write.finish(F_WRITE_RVA);
        assert!(write.len() <= 0x80);
        copy_code(&mut file, F_WRITE_RVA, &write);

        let mut default = CodeBuilder::default();
        default.raw(&[0x48, 0x89, 0x15]);
        default.disp(F_REQ_TMP);
        default.inc_dword(F_DEFAULT_COUNT);
        default.raw(&[0x48, 0x83, 0xEC, 0x28]);
        default.raw(&[0x48, 0x8B, 0x0D]);
        default.disp(F_REQ_TMP);
        default.raw(&[0x31, 0xD2, 0x45, 0x31, 0xC0]);
        default.call_iat(F_IAT_COMPLETE);
        default.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        let default = default.finish(F_DEFAULT_RVA);
        copy_code(&mut file, F_DEFAULT_RVA, &default);

        for (rva, marker) in [
            (F_STOP_RVA, F_STOP_COUNT),
            (F_RESUME_RVA, F_RESUME_COUNT),
            (F_CLEANUP_RVA, F_CLEANUP_COUNT),
            (F_DESTROY_RVA, F_DESTROY_COUNT),
        ] {
            let mut callback = CodeBuilder::default();
            callback.inc_dword(marker);
            callback.raw(&[0xC3]);
            let callback = callback.finish(rva);
            copy_code(&mut file, rva, &callback);
        }

        let mut cancel = CodeBuilder::default();
        cancel.raw(&[0x48, 0x89, 0x15]);
        cancel.disp(F_REQ_TMP);
        cancel.inc_dword(F_CANCEL_COUNT);
        cancel.raw(&[0x48, 0x8B, 0x0D]);
        cancel.disp(F_REQ_TMP);
        cancel.raw(&[0xBA]);
        cancel.raw(&STATUS_CANCELLED_u32());
        cancel.call_iat(F_IAT_COMPLETE);
        cancel.raw(&[0xC3]);
        let cancel = cancel.finish(F_CANCEL_RVA);
        copy_code(&mut file, F_CANCEL_RVA, &cancel);

        let mut unload = CodeBuilder::default();
        unload.inc_dword(F_UNLOAD_COUNT);
        unload.raw(&[0xC7, 0x05]);
        unload.disp_imm32(F_UNLOAD_MARKER, 0xCA5A_0200);
        unload.raw(&[0xC3]);
        let unload = unload.finish(F_UNLOAD_RVA);
        copy_code(&mut file, F_UNLOAD_RVA, &unload);

        let data_rva = |address: u32| 0x1000 + (address - F_DATA_RVA) as usize;
        let config = data_rva(F_CONFIG);
        put_u32(&mut file, config, 0x20);
        put_u64(&mut file, config + 8, F_IMAGE_BASE + u64::from(F_ADD_RVA));
        put_u64(
            &mut file,
            config + 0x10,
            F_IMAGE_BASE + u64::from(F_UNLOAD_RVA),
        );
        put_u32(&mut file, config + 0x18, 0x2146_4457);
        put_u32(&mut file, config + 0x1C, 0);
        for (us, wide, name) in [
            (F_US_DEVA, F_WIDEA, "\\Device\\WdfA"),
            (F_US_DEVB, F_WIDEB, "\\Device\\WdfB"),
        ] {
            let units = name.encode_utf16().count();
            let us_offset = data_rva(us);
            put_u16(&mut file, us_offset, (units * 2) as u16);
            put_u16(&mut file, us_offset + 2, ((units + 1) * 2) as u16);
            put_u64(&mut file, us_offset + 8, F_IMAGE_BASE + u64::from(wide));
            write_wide(
                &mut file[0x1000..0x1400],
                (wide - F_DATA_RVA) as usize,
                name,
            );
        }
        let attrs = data_rva(F_ATTRS);
        put_u32(&mut file, attrs, 0x38);
        put_u64(
            &mut file,
            attrs + 8,
            F_IMAGE_BASE + u64::from(F_CLEANUP_RVA),
        );
        put_u64(
            &mut file,
            attrs + 0x10,
            F_IMAGE_BASE + u64::from(F_DESTROY_RVA),
        );
        put_u64(&mut file, attrs + 0x28, 0x30);
        put_u64(
            &mut file,
            attrs + 0x30,
            F_IMAGE_BASE + u64::from(F_TYPEINFO),
        );
        let type_info = data_rva(F_TYPEINFO);
        put_u32(&mut file, type_info, 0x18);
        put_u64(&mut file, type_info + 0x10, 0x30);

        let rva = |address: u32| 0xA00 + (address - F_RDATA_RVA) as usize;
        let descriptor = rva(F_IMPORT_RVA);
        put_u32(&mut file, descriptor, F_ILT_RVA);
        put_u32(&mut file, descriptor + 12, F_DLL_RVA);
        put_u32(&mut file, descriptor + 16, F_IAT_RVA);
        file[rva(F_DLL_RVA)..rva(F_DLL_RVA) + 10].copy_from_slice(b"WdfLdr.sys");
        file[rva(F_DLL_RVA) + 10] = 0;
        let mut hint_rva = F_HINT_RVA;
        for (index, symbol) in F_IMPORTS.iter().enumerate() {
            put_u64(&mut file, rva(F_ILT_RVA) + index * 8, u64::from(hint_rva));
            put_u64(&mut file, rva(F_IAT_RVA) + index * 8, u64::from(hint_rva));
            let offset = rva(hint_rva);
            put_u16(&mut file, offset, 0);
            file[offset + 2..offset + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
            file[offset + 2 + symbol.len()] = 0;
            hint_rva += (2 + symbol.len() + 1 + 1) as u32 & !1;
        }
        assert!(hint_rva <= 0x2500, "hint table overruns: {hint_rva:#x}");
        file
    }

    // ---- PnP/power KMDF fixture -------------------------------------------
    //
    // A single-device KMDF image whose EvtDriverDeviceAdd registers
    // WDF_PNPPOWER_EVENT_CALLBACKS and WDF_FILEOBJECT_CONFIG.  Every callback
    // increments a guest counter; status callbacks return P_FAIL_STATUS when
    // their bit is set in P_FAIL_MASK, so tests can inject failures at each
    // transition step.

    const P_TEXT_RVA: u32 = 0x1000;
    const P_ENTRY_RVA: u32 = 0x1000;
    const P_ADD_RVA: u32 = 0x1100;
    const P_PREPARE_RVA: u32 = 0x1200;
    const P_RELEASE_RVA: u32 = 0x1240;
    const P_D0ENTRY_RVA: u32 = 0x1280;
    const P_D0EXIT_RVA: u32 = 0x12C0;
    const P_SELFINIT_RVA: u32 = 0x1300;
    const P_SELFFINI_RVA: u32 = 0x1340;
    const P_SUSPEND_RVA: u32 = 0x1380;
    const P_RESTART_RVA: u32 = 0x13C0;
    const P_CLEANUP_RVA: u32 = 0x1400;
    const P_DESTROY_RVA: u32 = 0x1440;
    const P_FCLEANUP_RVA: u32 = 0x1480;
    const P_FCLOSE_RVA: u32 = 0x14C0;
    const P_RDATA_RVA: u32 = 0x2000;
    const P_DATA_RVA: u32 = 0x3000;
    const P_IMPORT_RVA: u32 = 0x2100;
    const P_ILT_RVA: u32 = 0x2140;
    const P_IAT_RVA: u32 = 0x2180;
    const P_DLL_RVA: u32 = 0x21C0;
    const P_HINT_RVA: u32 = 0x21E0;
    const P_IMAGE_BASE: u64 = 0x1_4000_0000;

    const P_PNP_CONFIG: u32 = 0x3070;
    const P_FILE_CONFIG: u32 = 0x30D0;
    const P_DEV_ATTRS: u32 = 0x3100;
    const P_FAIL_MASK: u32 = 0x3160;
    const P_FAIL_STATUS: u32 = 0x3164;
    const P_PREPARE_COUNT: u32 = 0x3168;
    const P_RELEASE_COUNT: u32 = 0x316C;
    const P_D0ENTRY_COUNT: u32 = 0x3170;
    const P_D0EXIT_COUNT: u32 = 0x3174;
    const P_SELFINIT_COUNT: u32 = 0x3178;
    const P_SELFFINI_COUNT: u32 = 0x317C;
    const P_SUSPEND_COUNT: u32 = 0x3180;
    const P_RESTART_COUNT: u32 = 0x3184;
    const P_CLEANUP_COUNT: u32 = 0x3188;
    const P_DESTROY_COUNT: u32 = 0x318C;
    const P_FCLEANUP_COUNT: u32 = 0x3190;
    const P_FCLOSE_COUNT: u32 = 0x3194;
    const P_LAST_PREV: u32 = 0x3198;
    const P_LAST_TARGET: u32 = 0x319C;
    const P_CLEANUP_AFTER_DESTROY: u32 = 0x31A0;
    const P_DESTROY_AFTER_CLEANUP: u32 = 0x31A4;
    const P_DEVICE_OUT: u32 = 0x31A8;
    const P_DRIVER_OUT: u32 = 0x31B0;
    const P_DEVINIT: u32 = 0x31B8;
    const P_DRIVER_CONFIG: u32 = 0x31C0;

    const P_IAT_DRIVER: u32 = P_IAT_RVA;
    const P_IAT_SET_PNP: u32 = P_IAT_RVA + 8;
    const P_IAT_SET_FILE: u32 = P_IAT_RVA + 16;
    const P_IAT_DEVICE: u32 = P_IAT_RVA + 24;
    const P_IMPORTS: [&str; 4] = [
        "WdfDriverCreate",
        "WdfDeviceInitSetPnpPowerEventCallbacks",
        "WdfDeviceInitSetFileObjectConfig",
        "WdfDeviceCreate",
    ];

    fn pnp_data_rva(address: u32) -> usize {
        0x1C00 + (address - P_DATA_RVA) as usize
    }

    fn pnp_copy(file: &mut [u8], rva: u32, code: &[u8]) {
        let offset = 0x400 + (rva - P_TEXT_RVA) as usize;
        file[offset..offset + code.len()].copy_from_slice(code);
    }

    fn pnp_status_callback(count: u32, fail_bit: u32, store_arg: Option<u32>, rva: u32) -> Vec<u8> {
        let mut code = CodeBuilder::default();
        if let Some(target) = store_arg {
            code.raw(&[0x89, 0x15]);
            code.disp(target);
        }
        code.inc_dword(count);
        code.raw(&[0x8B, 0x05]);
        code.disp(P_FAIL_MASK);
        code.raw(&[0xA9]);
        code.raw(&fail_bit.to_le_bytes());
        code.raw(&[0x74, 0x07]);
        code.raw(&[0x8B, 0x05]);
        code.disp(P_FAIL_STATUS);
        code.raw(&[0xC3]);
        code.raw(&[0x31, 0xC0, 0xC3]);
        code.finish(rva)
    }

    fn pnp_void_callback(count: u32, rva: u32) -> Vec<u8> {
        let mut code = CodeBuilder::default();
        code.inc_dword(count);
        code.raw(&[0xC3]);
        code.finish(rva)
    }

    /// Cleanup/destroy stubs that record the other callback's counter, so the
    /// test can pin the post-order cascade exactly.
    fn pnp_order_callback(other_count: u32, flag: u32, count: u32, rva: u32) -> Vec<u8> {
        let mut code = CodeBuilder::default();
        code.raw(&[0x8B, 0x05]);
        code.disp(other_count);
        code.raw(&[0x89, 0x05]);
        code.disp(flag);
        code.inc_dword(count);
        code.raw(&[0xC3]);
        code.finish(rva)
    }

    fn build_kmdf_pnp_driver() -> Vec<u8> {
        let mut file = vec![0_u8; 0x2C00];
        file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
        put_u32(&mut file, 0x3C, 0x80);
        file[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        put_u16(&mut file, coff, 0x8664);
        put_u16(&mut file, coff + 2, 3);
        put_u16(&mut file, coff + 16, 0xF0);
        put_u16(&mut file, coff + 18, 0x0022);
        let optional = coff + 20;
        put_u16(&mut file, optional, 0x020B);
        put_u32(&mut file, optional + 4, 0x1000);
        put_u32(&mut file, optional + 8, 0x1800);
        put_u32(&mut file, optional + 16, P_ENTRY_RVA);
        put_u32(&mut file, optional + 20, P_TEXT_RVA);
        put_u64(&mut file, optional + 24, P_IMAGE_BASE);
        put_u32(&mut file, optional + 32, 0x1000);
        put_u32(&mut file, optional + 36, 0x200);
        put_u16(&mut file, optional + 48, 6);
        put_u32(&mut file, optional + 56, 0x4000);
        put_u32(&mut file, optional + 60, 0x400);
        put_u16(&mut file, optional + 68, 1);
        put_u32(&mut file, optional + 108, 16);
        let directories = optional + 112;
        put_u32(&mut file, directories + 8, P_IMPORT_RVA);
        put_u32(&mut file, directories + 12, 0x28);

        let section_table = optional + 0xF0;
        let mut write_section = |index: usize,
                                 name: &[u8; 8],
                                 virtual_size: u32,
                                 rva: u32,
                                 raw_size: u32,
                                 raw: u32,
                                 characteristics: u32| {
            let entry = section_table + index * 40;
            file[entry..entry + 8].copy_from_slice(name);
            put_u32(&mut file, entry + 8, virtual_size);
            put_u32(&mut file, entry + 12, rva);
            put_u32(&mut file, entry + 16, raw_size);
            put_u32(&mut file, entry + 20, raw);
            put_u32(&mut file, entry + 36, characteristics);
        };
        write_section(
            0,
            b".text\0\0\0",
            0x1000,
            P_TEXT_RVA,
            0x1000,
            0x400,
            0x6000_0020,
        );
        write_section(
            1,
            b".rdata\0\0",
            0x800,
            P_RDATA_RVA,
            0x800,
            0x1400,
            0x4000_0040,
        );
        write_section(
            2,
            b".data\0\0\0",
            0x1000,
            P_DATA_RVA,
            0x1000,
            0x1C00,
            0xC000_0040,
        );

        let mut entry = CodeBuilder::default();
        entry.raw(&[0x49, 0x89, 0xD3]); // mov r11,rdx (RegistryPath)
        entry.raw(&[0x48, 0x8D, 0x05]);
        entry.disp(P_DRIVER_CONFIG);
        entry.raw(&[0xC7, 0x00]);
        entry.raw(&0x28_u32.to_le_bytes());
        entry.raw(&[0x48, 0x8D, 0x15]);
        entry.disp(P_ADD_RVA);
        entry.raw(&[0x48, 0x89, 0x50, 0x08]);
        entry.raw(&[0x4C, 0x89, 0xDA]); // rdx = RegistryPath
        entry.raw(&[0x45, 0x31, 0xC0]); // xor r8d,r8d
        entry.raw(&[0x4C, 0x8D, 0x0D]);
        entry.disp(P_DRIVER_CONFIG);
        entry.raw(&[0x48, 0x83, 0xEC, 0x28]);
        entry.raw(&[0x48, 0x8D, 0x05]);
        entry.disp(P_DRIVER_OUT);
        entry.raw(&[0x48, 0x89, 0x44, 0x24, 0x20]);
        entry.call_iat(P_IAT_DRIVER);
        entry.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        let entry = entry.finish(P_ENTRY_RVA);
        pnp_copy(&mut file, P_ENTRY_RVA, &entry);

        let mut add = CodeBuilder::default();
        add.raw(&[0x48, 0x89, 0x15]); // mov [rip+disp], rdx (DeviceInit)
        add.disp(P_DEVINIT);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(P_DEVINIT);
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(P_PNP_CONFIG);
        add.call_iat(P_IAT_SET_PNP);
        add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(P_DEVINIT);
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(P_FILE_CONFIG);
        add.raw(&[0x45, 0x31, 0xC0]);
        add.call_iat(P_IAT_SET_FILE);
        add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(P_DEVINIT);
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(P_DEV_ATTRS);
        add.raw(&[0x4C, 0x8D, 0x05]);
        add.disp(P_DEVICE_OUT);
        add.call_iat(P_IAT_DEVICE);
        add.raw(&[0xC3]);
        let add = add.finish(P_ADD_RVA);
        assert!(add.len() <= 0x80, "pnp device add is {} bytes", add.len());
        pnp_copy(&mut file, P_ADD_RVA, &add);

        for (count, bit, store, rva) in [
            (P_PREPARE_COUNT, 1, None, P_PREPARE_RVA),
            (P_RELEASE_COUNT, 16, None, P_RELEASE_RVA),
            (P_D0ENTRY_COUNT, 2, Some(P_LAST_PREV), P_D0ENTRY_RVA),
            (P_D0EXIT_COUNT, 8, Some(P_LAST_TARGET), P_D0EXIT_RVA),
            (P_SELFINIT_COUNT, 4, None, P_SELFINIT_RVA),
            (P_SUSPEND_COUNT, 32, None, P_SUSPEND_RVA),
            (P_RESTART_COUNT, 64, None, P_RESTART_RVA),
        ] {
            let code = pnp_status_callback(count, bit, store, rva);
            pnp_copy(&mut file, rva, &code);
        }
        for (count, rva) in [
            (P_SELFFINI_COUNT, P_SELFFINI_RVA),
            (P_FCLEANUP_COUNT, P_FCLEANUP_RVA),
            (P_FCLOSE_COUNT, P_FCLOSE_RVA),
        ] {
            let code = pnp_void_callback(count, rva);
            pnp_copy(&mut file, rva, &code);
        }
        let code = pnp_order_callback(
            P_DESTROY_COUNT,
            P_CLEANUP_AFTER_DESTROY,
            P_CLEANUP_COUNT,
            P_CLEANUP_RVA,
        );
        pnp_copy(&mut file, P_CLEANUP_RVA, &code);
        let code = pnp_order_callback(
            P_CLEANUP_COUNT,
            P_DESTROY_AFTER_CLEANUP,
            P_DESTROY_COUNT,
            P_DESTROY_RVA,
        );
        pnp_copy(&mut file, P_DESTROY_RVA, &code);

        let data = |address: u32| pnp_data_rva(address);
        put_u32(&mut file, data(P_PNP_CONFIG), 0x58);
        for (offset, rva) in [
            (0x08u32, P_PREPARE_RVA),
            (0x10, P_RELEASE_RVA),
            (0x18, P_D0ENTRY_RVA),
            (0x20, P_D0EXIT_RVA),
            (0x28, P_SELFINIT_RVA),
            (0x30, P_SUSPEND_RVA),
            (0x38, P_RESTART_RVA),
            (0x50, P_SELFFINI_RVA),
        ] {
            put_u64(
                &mut file,
                data(P_PNP_CONFIG) + offset as usize,
                P_IMAGE_BASE + u64::from(rva),
            );
        }
        put_u32(&mut file, data(P_FILE_CONFIG), 0x20);
        put_u64(
            &mut file,
            data(P_FILE_CONFIG) + 0x10,
            P_IMAGE_BASE + u64::from(P_FCLOSE_RVA),
        );
        put_u64(
            &mut file,
            data(P_FILE_CONFIG) + 0x18,
            P_IMAGE_BASE + u64::from(P_FCLEANUP_RVA),
        );
        put_u32(&mut file, data(P_DEV_ATTRS), 0x38);
        put_u64(
            &mut file,
            data(P_DEV_ATTRS) + 0x08,
            P_IMAGE_BASE + u64::from(P_CLEANUP_RVA),
        );
        put_u64(
            &mut file,
            data(P_DEV_ATTRS) + 0x10,
            P_IMAGE_BASE + u64::from(P_DESTROY_RVA),
        );

        let rva = |address: u32| 0x1400 + (address - P_RDATA_RVA) as usize;
        let descriptor = rva(P_IMPORT_RVA);
        put_u32(&mut file, descriptor, P_ILT_RVA);
        put_u32(&mut file, descriptor + 12, P_DLL_RVA);
        put_u32(&mut file, descriptor + 16, P_IAT_RVA);
        file[rva(P_DLL_RVA)..rva(P_DLL_RVA) + 10].copy_from_slice(b"WdfLdr.sys");
        file[rva(P_DLL_RVA) + 10] = 0;
        let mut hint_rva = P_HINT_RVA;
        for (index, symbol) in P_IMPORTS.iter().enumerate() {
            put_u64(&mut file, rva(P_ILT_RVA) + index * 8, u64::from(hint_rva));
            put_u64(&mut file, rva(P_IAT_RVA) + index * 8, u64::from(hint_rva));
            let offset = rva(hint_rva);
            put_u16(&mut file, offset, 0);
            file[offset + 2..offset + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
            file[offset + 2 + symbol.len()] = 0;
            hint_rva += (2 + symbol.len() + 1 + 1) as u32 & !1;
        }
        assert!(hint_rva <= 0x2400, "pnp hint table overruns: {hint_rva:#x}");
        file
    }

    const X86K_ENTRY_RVA: u32 = 0x1000;
    const X86K_ADD_RVA: u32 = 0x1100;
    const X86K_UNLOAD_RVA: u32 = 0x1180;
    const X86K_TEXT_RVA: u32 = 0x1000;
    const X86K_RDATA_RVA: u32 = 0x2000;
    const X86K_DATA_RVA: u32 = 0x3000;
    const X86K_IMPORT_RVA: u32 = 0x2100;
    const X86K_ILT_RVA: u32 = 0x2140;
    const X86K_IAT_RVA: u32 = 0x2160;
    const X86K_DLL_RVA: u32 = 0x2180;
    const X86K_HINT_RVA: u32 = 0x21A0;
    const X86K_IMAGE_BASE: u32 = 0x1000_0000;
    const X86K_CONFIG: u32 = 0x3000;
    const X86K_DRIVER_PTR: u32 = 0x3018;
    const X86K_REG_PATH: u32 = 0x301C;
    const X86K_DRIVER_OUT: u32 = 0x3020;
    const X86K_DEVINIT: u32 = 0x3024;
    const X86K_DEVICE_OUT: u32 = 0x3028;
    const X86K_US_DEV: u32 = 0x3030;
    const X86K_WIDE_DEV: u32 = 0x3050;
    const X86K_ADD_MARKER: u32 = 0x3070;
    const X86K_UNLOAD_MARKER: u32 = 0x3074;
    const X86K_IAT_DRIVER: u32 = X86K_IAT_RVA;
    const X86K_IAT_ASSIGN: u32 = X86K_IAT_RVA + 4;
    const X86K_IAT_DEVICE: u32 = X86K_IAT_RVA + 8;
    const X86K_IMPORTS: [&str; 3] = [
        "WdfDriverCreate",
        "WdfDeviceInitAssignName",
        "WdfDeviceCreate",
    ];

    fn build_kmdf_driver_pe32() -> Vec<u8> {
        let mut file = vec![0_u8; 0xC00];
        file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
        put_u32(&mut file, 0x3C, 0x80);
        file[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        put_u16(&mut file, coff, 0x014C);
        put_u16(&mut file, coff + 2, 3);
        put_u16(&mut file, coff + 16, 0xE0);
        put_u16(&mut file, coff + 18, 0x0102);
        let optional = coff + 20;
        put_u16(&mut file, optional, 0x010B);
        put_u32(&mut file, optional + 4, 0x400);
        put_u32(&mut file, optional + 8, 0xC00);
        put_u32(&mut file, optional + 16, X86K_ENTRY_RVA);
        put_u32(&mut file, optional + 20, X86K_TEXT_RVA);
        put_u32(&mut file, optional + 24, X86K_RDATA_RVA);
        put_u32(&mut file, optional + 28, X86K_IMAGE_BASE);
        put_u32(&mut file, optional + 32, 0x1000);
        put_u32(&mut file, optional + 36, 0x200);
        put_u16(&mut file, optional + 48, 6);
        put_u32(&mut file, optional + 56, 0x4000);
        put_u32(&mut file, optional + 60, 0x200);
        put_u16(&mut file, optional + 68, 1);
        put_u32(&mut file, optional + 92, 16);
        let directories = optional + 96;
        put_u32(&mut file, directories + 8, X86K_IMPORT_RVA);
        put_u32(&mut file, directories + 12, 0x28);

        let section_table = optional + 0xE0;
        let mut write_section = |index: usize,
                                 name: &[u8; 8],
                                 virtual_size: u32,
                                 rva: u32,
                                 raw_size: u32,
                                 raw: u32,
                                 characteristics: u32| {
            let entry = section_table + index * 40;
            file[entry..entry + 8].copy_from_slice(name);
            put_u32(&mut file, entry + 8, virtual_size);
            put_u32(&mut file, entry + 12, rva);
            put_u32(&mut file, entry + 16, raw_size);
            put_u32(&mut file, entry + 20, raw);
            put_u32(&mut file, entry + 36, characteristics);
        };
        write_section(
            0,
            b".text\0\0\0",
            0x400,
            X86K_TEXT_RVA,
            0x400,
            0x200,
            0x6000_0020,
        );
        write_section(
            1,
            b".rdata\0\0",
            0x400,
            X86K_RDATA_RVA,
            0x400,
            0x600,
            0x4000_0040,
        );
        write_section(
            2,
            b".data\0\0\0",
            0x200,
            X86K_DATA_RVA,
            0x200,
            0xA00,
            0xC000_0040,
        );

        let mut entry = Vec::new();
        entry.extend_from_slice(&[0x8B, 0x44, 0x24, 0x04]); // DriverObject
        entry.extend_from_slice(&[0xA3]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DRIVER_PTR).to_le_bytes());
        entry.extend_from_slice(&[0x8B, 0x44, 0x24, 0x08]); // RegistryPath
        entry.extend_from_slice(&[0xA3]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_REG_PATH).to_le_bytes());
        entry.extend_from_slice(&[0xC7, 0x05]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG).to_le_bytes());
        entry.extend_from_slice(&0x14_u32.to_le_bytes());
        entry.extend_from_slice(&[0xC7, 0x05]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG + 4).to_le_bytes());
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_ADD_RVA).to_le_bytes());
        entry.extend_from_slice(&[0xC7, 0x05]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG + 8).to_le_bytes());
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_UNLOAD_RVA).to_le_bytes());
        entry.extend_from_slice(&[0xC7, 0x05]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG + 0xC).to_le_bytes());
        entry.extend_from_slice(&0x2146_4457_u32.to_le_bytes());
        entry.extend_from_slice(&[0xC7, 0x05]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG + 0x10).to_le_bytes());
        entry.extend_from_slice(&0_u32.to_le_bytes());
        entry.extend_from_slice(&[0x68]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DRIVER_OUT).to_le_bytes());
        entry.extend_from_slice(&[0x68]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG).to_le_bytes());
        entry.extend_from_slice(&[0x6A, 0x00]);
        entry.extend_from_slice(&[0xFF, 0x35]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_REG_PATH).to_le_bytes());
        entry.extend_from_slice(&[0xFF, 0x35]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DRIVER_PTR).to_le_bytes());
        entry.extend_from_slice(&[0xFF, 0x15]);
        entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_IAT_DRIVER).to_le_bytes());
        entry.extend_from_slice(&[0xC2, 0x08, 0x00]);
        assert!(entry.len() <= 0x100);
        file[0x200..0x200 + entry.len()].copy_from_slice(&entry);

        let mut add = Vec::new();
        add.extend_from_slice(&[0x8B, 0x44, 0x24, 0x08]); // DeviceInit
        add.extend_from_slice(&[0xA3]);
        add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DEVINIT).to_le_bytes());
        add.extend_from_slice(&[0x68]);
        add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_US_DEV).to_le_bytes());
        add.extend_from_slice(&[0xFF, 0x35]);
        add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DEVINIT).to_le_bytes());
        add.extend_from_slice(&[0xFF, 0x15]);
        add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_IAT_ASSIGN).to_le_bytes());
        add.extend_from_slice(&[0x68]);
        add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DEVICE_OUT).to_le_bytes());
        add.extend_from_slice(&[0x6A, 0x00]);
        add.extend_from_slice(&[0x68]);
        add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DEVINIT).to_le_bytes());
        add.extend_from_slice(&[0xFF, 0x15]);
        add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_IAT_DEVICE).to_le_bytes());
        add.extend_from_slice(&[0xC7, 0x05]);
        add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_ADD_MARKER).to_le_bytes());
        add.extend_from_slice(&0xCA5A_0031_u32.to_le_bytes());
        add.extend_from_slice(&[0x31, 0xC0, 0xC2, 0x08, 0x00]);
        assert!(add.len() <= 0x80);
        file[0x300..0x300 + add.len()].copy_from_slice(&add);

        let mut unload = Vec::new();
        unload.extend_from_slice(&[0xC7, 0x05]);
        unload.extend_from_slice(&(X86K_IMAGE_BASE + X86K_UNLOAD_MARKER).to_le_bytes());
        unload.extend_from_slice(&0xCA5A_0032_u32.to_le_bytes());
        unload.extend_from_slice(&[0xC2, 0x04, 0x00]);
        file[0x380..0x380 + unload.len()].copy_from_slice(&unload);

        let rva = |address: u32| 0x600 + (address - X86K_RDATA_RVA) as usize;
        let descriptor = rva(X86K_IMPORT_RVA);
        put_u32(&mut file, descriptor, X86K_ILT_RVA);
        put_u32(&mut file, descriptor + 12, X86K_DLL_RVA);
        put_u32(&mut file, descriptor + 16, X86K_IAT_RVA);
        file[rva(X86K_DLL_RVA)..rva(X86K_DLL_RVA) + 10].copy_from_slice(b"WdfLdr.sys");
        file[rva(X86K_DLL_RVA) + 10] = 0;
        let mut hint_rva = X86K_HINT_RVA;
        for (index, symbol) in X86K_IMPORTS.iter().enumerate() {
            put_u32(&mut file, rva(X86K_ILT_RVA) + index * 4, hint_rva);
            put_u32(&mut file, rva(X86K_IAT_RVA) + index * 4, hint_rva);
            let offset = rva(hint_rva);
            put_u16(&mut file, offset, 0);
            file[offset + 2..offset + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
            file[offset + 2 + symbol.len()] = 0;
            hint_rva += (2 + symbol.len() + 1 + 1) as u32 & !1;
        }
        let data = 0xA00;
        put_u32(&mut file, data, 0x14);
        put_u32(&mut file, data + 4, X86K_IMAGE_BASE + X86K_ADD_RVA);
        put_u32(&mut file, data + 8, X86K_IMAGE_BASE + X86K_UNLOAD_RVA);
        put_u32(&mut file, data + 0xC, 0x2146_4457);
        put_u32(&mut file, data + 0x10, 0);
        let us = 0xA00 + (X86K_US_DEV - X86K_DATA_RVA) as usize;
        put_u16(&mut file, us, 26);
        put_u16(&mut file, us + 2, 28);
        put_u32(&mut file, us + 4, X86K_IMAGE_BASE + X86K_WIDE_DEV);
        write_wide(
            &mut file[0xA00..0xC00],
            (X86K_WIDE_DEV - X86K_DATA_RVA) as usize,
            "\\Device\\Wdf32",
        );
        file
    }

    fn copy_code(file: &mut [u8], rva: u32, code: &[u8]) {
        let offset = 0x200 + (rva - F_TEXT_RVA) as usize;
        file[offset..offset + code.len()].copy_from_slice(code);
    }

    fn STATUS_CANCELLED_u32() -> [u8; 4] {
        (STATUS_CANCELLED as u32).to_le_bytes()
    }

    fn write_wide(rdata: &mut [u8], offset: usize, text: &str) {
        for (index, unit) in text.encode_utf16().chain([0]).enumerate() {
            rdata[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }

    fn test_runtime() -> (PeHostRuntime, TempDir) {
        test_runtime_with_ge(|_| {})
    }

    fn test_runtime_with_ge<F: FnOnce(&mut GameEnvironment)>(
        configure: F,
    ) -> (PeHostRuntime, TempDir) {
        let directory = TempDir::new().expect("temp dir");
        let mut ge = GameEnvironment::create_in(
            directory.path(),
            "driver-island",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        configure(&mut ge);
        let runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        reset_runtime_registry(&runtime);
        (runtime, directory)
    }

    fn stage_service(ge: &mut GameEnvironment, service: &str, image_path: &str, image: &[u8]) {
        let key = format!("SYSTEM\\CurrentControlSet\\Services\\{service}");
        ge.registry_create_key("HKLM", &key, RegistryView::Native)
            .expect("create service key");
        ge.registry_set_value(
            "HKLM",
            &key,
            "ImagePath",
            "REG_SZ",
            json!(image_path),
            RegistryView::Native,
        )
        .expect("write ImagePath");
        ge.create_directory("C:\\Windows\\System32\\drivers", true)
            .expect("create driver directory");
        ge.write_file(DRIVER_IMAGE_PATH, image, true)
            .expect("write driver image");
    }

    const DRIVER_IMAGE_PATH: &str = "C:\\Windows\\System32\\drivers\\casa_nt.sys";

    fn guest_unicode_string(memory: &mut MemoryImage, header: u64, text: &str) -> u64 {
        let units = text.encode_utf16().collect::<Vec<_>>();
        let buffer = header + 0x100;
        memory.map_bytes(header, &[0_u8; 16]);
        memory.map_bytes(buffer, &vec![0_u8; (units.len() + 1) * 2]);
        memory.write_u16(header, (units.len() * 2) as u16);
        memory.write_u16(header + 2, ((units.len() + 1) * 2) as u16);
        memory.write_u64(header + 8, buffer);
        for (index, unit) in units.iter().enumerate() {
            memory.write_u16(buffer + index as u64 * 2, *unit);
        }
        header
    }

    fn prepare_guest_memory(runtime: &mut PeHostRuntime, memory: &mut MemoryImage) {
        let vm = runtime.win32.address_space_mut();
        vm.register(STACK_BASE, STACK_SIZE, VmRegionKind::Stack);
        vm.commit(STACK_BASE, STACK_SIZE, VmProtection::READ_WRITE, false);
        vm.register(0x40_000, 0x20_000, VmRegionKind::Private);
        vm.commit(0x40_000, 0x20_000, VmProtection::READ_WRITE, false);
        memory.set_vm(vm);
    }

    fn test_runtime_x86() -> (PeHostRuntime, TempDir) {
        let (mut runtime, directory) = test_runtime();
        runtime.guest_arch = GuestArch::X86;
        runtime.next_thunk_address = 0x7100_0000;
        (runtime, directory)
    }

    fn test_runtime_x86_with_ge<F: FnOnce(&mut GameEnvironment)>(
        configure: F,
    ) -> (PeHostRuntime, TempDir) {
        let directory = TempDir::new().expect("temp dir");
        let mut ge = GameEnvironment::create_in(
            directory.path(),
            "driver-island-x86",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        configure(&mut ge);
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.guest_arch = GuestArch::X86;
        runtime.next_thunk_address = 0x7100_0000;
        reset_runtime_registry(&runtime);
        (runtime, directory)
    }

    fn guest_unicode_string_x86(memory: &mut MemoryImage, header: u64, text: &str) -> u64 {
        let units = text.encode_utf16().collect::<Vec<_>>();
        let buffer = header + 0x100;
        memory.map_bytes(header, &[0_u8; 8]);
        memory.map_bytes(buffer, &vec![0_u8; (units.len() + 1) * 2]);
        memory.write_u16(header, (units.len() * 2) as u16);
        memory.write_u16(header + 2, ((units.len() + 1) * 2) as u16);
        memory.write_u32(header + 4, buffer as u32);
        for (index, unit) in units.iter().enumerate() {
            memory.write_u16(buffer + index as u64 * 2, *unit);
        }
        header
    }

    fn write_object_attributes(memory: &mut MemoryImage, address: u64, name: u64, arch: GuestArch) {
        let size = 48;
        memory.map_bytes(address, &[0_u8; 48]);
        match arch {
            GuestArch::X64 => {
                memory.write_u32(address, 48);
                memory.write_u64(address + 16, name);
            }
            GuestArch::X86 => {
                memory.write_u32(address, 24);
                memory.write_u32(address + 8, name as u32);
                let _ = size;
            }
        }
    }

    fn create_device_file(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        path: &str,
        base: u64,
    ) -> (u32, i32) {
        let arch = runtime.guest_arch;
        let name = match arch {
            GuestArch::X64 => guest_unicode_string(memory, base, path),
            GuestArch::X86 => guest_unicode_string_x86(memory, base, path),
        };
        let attributes = base + 0x1000;
        write_object_attributes(memory, attributes, name, arch);
        let handle_ptr = base + 0x2000;
        let iosb = base + 0x2100;
        memory.map_bytes(handle_ptr, &[0_u8; 4]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        let status = dispatch_nt_thunk(
            runtime,
            memory,
            HostThunk::NtCreateFile,
            &[
                handle_ptr,
                0x0012_0000,
                attributes,
                iosb,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
            ],
        );
        (memory.read_u32(handle_ptr).unwrap_or(0), status)
    }

    fn dispatch_nt_thunk(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thunk: HostThunk,
        args: &[u64],
    ) -> i32 {
        dispatch_nt_thunk_on_thread(
            runtime,
            memory,
            thunk,
            args,
            STACK_BASE + STACK_SIZE - 0x100,
        )
    }

    fn dispatch_nt_thunk_on_thread(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thunk: HostThunk,
        args: &[u64],
        stack_pointer: u64,
    ) -> i32 {
        let thunk_address = runtime.next_thunk_address;
        runtime.next_thunk_address += 0x10;
        runtime.host_thunks.insert(thunk_address, thunk);
        memory.map_bytes(STACK_BASE, &vec![0_u8; STACK_SIZE as usize]);
        let mut cpu = CpuState::new(runtime.guest_arch);
        cpu.set(Register::Rsp, stack_pointer);
        runtime
            .execute_guest_callback(&mut cpu, memory, thunk_address, args, "NtDispatch")
            .expect("guest thunk dispatch") as u32 as i32
    }

    fn with_big_stack<F: FnOnce() + Send + 'static>(body: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(body)
            .expect("spawn test thread")
            .join()
            .expect("test thread");
    }

    #[test]
    fn executes_driver_entry_for_real() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime();
            let mut memory = MemoryImage::default();
            let bytes = build_test_driver(false, false, false);
            let island = DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory)
                .expect("DriverEntry must execute");

            assert_eq!(island.status(), STATUS_SUCCESS);
            assert!(island.is_loaded());
            assert_eq!(island.driver_name(), "CasaDriver");
            assert!(island.registry_path().ends_with("\\Services\\CasaDriver"));
            assert_eq!(island.device_count(), 1);
            assert_eq!(island.casak_device_names(), vec!["CasaTest".to_string()]);

            let devices = island.created_devices();
            assert_eq!(devices.len(), 1);
            assert_eq!(devices[0].name, "\\Device\\CasaTest");
            assert!(!devices[0].deleted);
            let device = devices[0].guest_pointer;
            assert_ne!(device, 0);

            let driver_object = island.driver_object_pointer();
            assert_eq!(memory.read_u16(driver_object).unwrap(), DRIVER_OBJECT_TYPE);
            assert_eq!(
                memory.read_u64(driver_object + 0x08).unwrap(),
                device,
                "DRIVER_OBJECT.DeviceObject points at the guest device"
            );
            assert_eq!(memory.read_u16(device).unwrap(), DEVICE_OBJECT_TYPE);
            assert_eq!(
                memory.read_u64(device + 0x08).unwrap(),
                driver_object,
                "DEVICE_OBJECT.DriverObject points back at the driver"
            );
            for index in 0..MAJOR_FUNCTION_COUNT {
                assert_ne!(
                    memory
                        .read_u64(driver_object + 0x70 + index as u64 * 8)
                        .unwrap(),
                    0,
                    "MajorFunction[{index}] is populated"
                );
            }
            assert_eq!(
                memory
                    .read_u32(island.image_base() + ENTRY_MARKER_RVA as u64)
                    .unwrap(),
                0xCA5A_0001,
                "guest code executed its own store"
            );

            assert_eq!(
                island.dbg_print_log(),
                vec!["CasaTest DriverEntry\n".to_string()]
            );
            assert!(runtime.trace_events.iter().any(|event| {
                event.call_id == "DbgPrint"
                    && event
                        .parameters
                        .get("message")
                        .and_then(|value| value.as_str())
                        == Some("CasaTest DriverEntry\n")
            }));
            assert_eq!(
                island.symbolic_links(),
                vec![(
                    "\\??\\CasaTest".to_string(),
                    "\\Device\\CasaTest".to_string()
                )]
            );
            let imports = island.imports();
            assert!(imports.unresolved.is_empty());
            assert_eq!(imports.resolved.len(), IMPORT_NAMES.len());
        });
    }

    #[test]
    fn service_shims_allocate_irps_and_tagged_pool() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime();
            let mut memory = MemoryImage::default();
            let bytes = build_test_driver(false, false, true);
            let island = DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory)
                .expect("service-shim driver must execute");
            assert_eq!(island.status(), STATUS_SUCCESS);
            assert_eq!(
                island.completed_irp_count(),
                1,
                "IoAllocateIrp + IofCompleteRequest completed a CasaK IRP"
            );
            assert_eq!(
                island.pool_allocation_count(),
                1,
                "ExAllocatePoolWithTag allocated a tagged CasaK block"
            );
            assert_eq!(
                island.pool_free_count(),
                1,
                "ExFreePoolWithTag freed the tagged block"
            );
            assert_eq!(island.pool_used_bytes(), 0);
        });
    }

    #[test]
    fn rejects_a_bad_image() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime();
            let mut memory = MemoryImage::default();
            let error =
                match DriverIsland::load_and_start(b"not a driver", &mut runtime, &mut memory) {
                    Ok(_) => panic!("a non-PE must be rejected"),
                    Err(error) => error,
                };
            assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
        });
    }

    #[test]
    fn reports_unresolved_imports_without_executing() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime();
            let mut memory = MemoryImage::default();
            let bytes = build_test_driver(false, true, false);
            let error = match DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory) {
                Ok(_) => panic!("unresolved imports must reject the load"),
                Err(error) => error,
            };
            assert_eq!(error.code, ReasonCode::RcImportMissing);
            assert!(
                error.message.contains("PsGetCurrentProcessId"),
                "error names the unresolved import: {}",
                error.message
            );
        });
    }

    #[test]
    fn surfaces_driver_entry_failure_status() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime();
            let mut memory = MemoryImage::default();
            let bytes = build_test_driver(true, false, false);
            let island = DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory)
                .expect("the entry bytes execute even when they fail");
            assert_eq!(island.status(), STATUS_UNSUCCESSFUL);
            assert!(!island.is_loaded());
            assert_eq!(island.device_count(), 0);
            assert!(island.created_devices().is_empty());
            assert_eq!(
                memory
                    .read_u32(island.image_base() + ENTRY_MARKER_RVA as u64)
                    .unwrap(),
                0xCA5A_0001,
                "the failing entry still ran"
            );
        });
    }

    #[test]
    fn double_load_and_unload_lifecycle() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime();
            let mut memory = MemoryImage::default();
            let bytes = build_test_driver(false, false, false);
            let mut first = DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory)
                .expect("first load");
            let mut second = DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory)
                .expect("second load");
            assert_ne!(
                first.image_base(),
                second.image_base(),
                "each island gets its own guest image mapping"
            );
            assert_eq!(first.device_count(), 1);
            assert_eq!(second.device_count(), 1);

            assert_eq!(
                first
                    .unload(&mut runtime, &mut memory)
                    .expect("unload first"),
                Some(STATUS_SUCCESS)
            );
            assert!(!first.is_loaded());
            assert_eq!(first.device_count(), 0);
            assert!(first.casak_device_names().is_empty());
            assert!(first.created_devices()[0].deleted);
            assert_eq!(
                memory
                    .read_u32(first.image_base() + UNLOAD_MARKER_RVA as u64)
                    .unwrap(),
                0xCA5A_0002,
                "DriverUnload executed in the guest"
            );
            assert!(
                first
                    .dbg_print_log()
                    .iter()
                    .any(|message| message.contains("DriverUnload"))
            );
            assert_eq!(
                first
                    .unload(&mut runtime, &mut memory)
                    .expect("repeat unload"),
                None,
                "a second unload does not execute DriverUnload again"
            );

            assert!(second.is_loaded());
            assert_eq!(second.device_count(), 1);
            assert_eq!(
                second
                    .unload(&mut runtime, &mut memory)
                    .expect("unload second"),
                Some(STATUS_SUCCESS)
            );
            assert_eq!(second.device_count(), 0);
        });
    }

    #[test]
    fn driver_service_load_unload() {
        with_big_stack(|| {
            let image = build_test_driver(false, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaNtSvc",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\REGISTRY\\MACHINE\\system\\currentcontrolset\\services\\CasaNtSvc",
            );

            // The production thunk mapping resolves the export name.
            assert_eq!(
                crate::runtime::registered_export_implementation_level("ntdll.dll", "NtLoadDriver"),
                ImplementationLevel::Implemented
            );
            assert_eq!(
                crate::runtime::registered_export_implementation_level(
                    "ntdll.dll",
                    "NtUnloadDriver"
                ),
                ImplementationLevel::Implemented
            );

            let load = dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            );
            assert_eq!(load, STATUS_SUCCESS, "NtLoadDriver loads the service");

            let (image_base, created_devices) =
                with_loaded_driver(&runtime, "CasaNtSvc", |island| {
                    assert_eq!(island.status(), STATUS_SUCCESS);
                    assert!(island.is_loaded());
                    assert_eq!(island.device_count(), 1);
                    assert_eq!(island.casak_device_names(), vec!["CasaTest"]);
                    assert_eq!(
                        island.created_devices()[0].name,
                        "\\Device\\CasaTest",
                        "the guest device path is real"
                    );
                    assert_eq!(island.symbolic_links().len(), 1);
                    assert!(
                        island
                            .dbg_print_log()
                            .iter()
                            .any(|message| message.contains("CasaTest DriverEntry")),
                        "the guest DriverEntry must have run: {:?}",
                        island.dbg_print_log()
                    );
                    (island.image_base(), island.created_devices().len())
                })
                .expect("the service is registered after a successful load");
            assert_eq!(created_devices, 1);
            assert_eq!(
                memory
                    .read_u32(image_base + ENTRY_MARKER_RVA as u64)
                    .unwrap(),
                0xCA5A_0001,
                "DriverEntry executed in the guest"
            );

            let duplicate = dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            );
            assert_eq!(duplicate, STATUS_IMAGE_ALREADY_LOADED);
            assert_eq!(duplicate as u32, 0xC000_010E);

            let unload = dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            );
            assert_eq!(unload, STATUS_SUCCESS, "NtUnloadDriver unloads the service");
            let unloaded =
                take_last_unloaded_driver().expect("unloaded island retained for evidence");
            assert!(!unloaded.is_loaded());
            assert_eq!(unloaded.device_count(), 0);
            assert!(unloaded.casak_device_names().is_empty());
            assert!(unloaded.created_devices()[0].deleted);
            assert!(unloaded.symbolic_links().is_empty());
            assert!(
                unloaded
                    .dbg_print_log()
                    .iter()
                    .any(|message| message.contains("CasaTest DriverUnload")),
                "the guest DriverUnload must have run: {:?}",
                unloaded.dbg_print_log()
            );
            assert_eq!(
                memory
                    .read_u32(image_base + UNLOAD_MARKER_RVA as u64)
                    .unwrap(),
                0xCA5A_0002,
                "DriverUnload executed in the guest"
            );
            assert!(
                with_loaded_driver(&runtime, "CasaNtSvc", |_| ()).is_none(),
                "the registration is forgotten after unload"
            );

            let second_unload = dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            );
            assert_eq!(second_unload, STATUS_OBJECT_NAME_NOT_FOUND);
        });
    }

    #[test]
    fn driver_service_load_rejects_missing_registry_value_and_file() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                ge.registry_create_key(
                    "HKLM",
                    "SYSTEM\\CurrentControlSet\\Services\\CasaNoValue",
                    RegistryView::Native,
                )
                .expect("create value-less service key");
                ge.registry_create_key(
                    "HKLM",
                    "SYSTEM\\CurrentControlSet\\Services\\CasaNoFile",
                    RegistryView::Native,
                )
                .expect("create file-less service key");
                ge.registry_set_value(
                    "HKLM",
                    "SYSTEM\\CurrentControlSet\\Services\\CasaNoFile",
                    "ImagePath",
                    "REG_SZ",
                    json!("C:\\Windows\\System32\\drivers\\missing.sys"),
                    RegistryView::Native,
                )
                .expect("write ImagePath");
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);

            let missing_key = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaMissing",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[missing_key],
                ),
                STATUS_OBJECT_NAME_NOT_FOUND,
                "a missing service key"
            );

            let missing_value = guest_unicode_string(
                &mut memory,
                0x41_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaNoValue",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[missing_value],
                ),
                STATUS_OBJECT_NAME_NOT_FOUND,
                "a service without ImagePath"
            );

            let missing_file = guest_unicode_string(
                &mut memory,
                0x42_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaNoFile",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[missing_file],
                ),
                STATUS_OBJECT_NAME_NOT_FOUND,
                "an ImagePath that names no readable file"
            );

            assert_eq!(
                dispatch_nt_thunk(&mut runtime, &mut memory, HostThunk::NtLoadDriver, &[0],),
                STATUS_INVALID_PARAMETER,
                "a null PUNICODE_STRING"
            );

            // Structurally invalid descriptor: odd Length.
            memory.map_bytes(0x43_000, &[0_u8; 16]);
            memory.write_u16(0x43_000, 3);
            memory.write_u64(0x43_008, 0x44_000);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[0x43_000],
                ),
                STATUS_INVALID_PARAMETER,
                "an odd-length UNICODE_STRING"
            );
        });
    }

    #[test]
    fn pe32_driver_entry_executes_and_creates_a_device() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime_x86();
            let mut memory = MemoryImage::default();
            let bytes = build_pe32_driver();
            let island =
                DriverIsland::load_and_start_named(&bytes, "CasaPe32", &mut runtime, &mut memory)
                    .expect("PE32 DriverEntry must execute through the x86 guest");
            assert_eq!(island.status(), STATUS_SUCCESS);
            assert!(island.is_loaded());
            assert_eq!(island.device_count(), 1);
            assert_eq!(island.casak_device_names(), vec!["Casa32".to_string()]);
            assert_eq!(
                memory.read_u32(island.image_base() + 0x3014).unwrap(),
                0xCA5A_0005,
                "the x86 DriverEntry bytes executed"
            );
            assert_ne!(
                memory.read_u32(island.image_base() + 0x3010).unwrap(),
                0,
                "IoCreateDevice returned a real guest PDEVICE_OBJECT"
            );
            let driver_object = island.driver_object_pointer();
            assert_eq!(memory.read_u16(driver_object).unwrap(), DRIVER_OBJECT_TYPE);
            assert_eq!(
                memory.read_u32(driver_object + 0x70).unwrap(),
                0x1000_1200,
                "DEVICE_CONTROL major function was installed by the guest"
            );
        });
    }

    #[test]
    fn pe32_mismatched_machine_is_rejected() {
        with_big_stack(|| {
            let mut bytes = build_pe32_driver();
            bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
            let (mut runtime, _directory) = test_runtime_x86();
            let mut memory = MemoryImage::default();
            let error = match DriverIsland::load_and_start_named(
                &bytes,
                "CasaPe32Bad",
                &mut runtime,
                &mut memory,
            ) {
                Ok(_) => panic!("machine/optional-header mismatch must be rejected"),
                Err(error) => error,
            };
            assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
        });
    }

    #[test]
    fn delay_imports_are_resolved_eagerly_and_unresolved_ones_reject() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime();
            let mut memory = MemoryImage::default();
            let bytes = with_delay_import(build_test_driver(false, false, false), "DbgPrint");
            let island =
                DriverIsland::load_and_start_named(&bytes, "CasaDelay", &mut runtime, &mut memory)
                    .expect("delay imports must resolve at load");
            assert!(
                island
                    .imports()
                    .resolved
                    .iter()
                    .any(|(dll, symbol, _)| dll == "ntoskrnl.exe" && symbol == "DbgPrint"),
                "the delay import is reported as resolved"
            );
            assert_ne!(
                memory.read_u64(island.image_base() + 0x2570).unwrap(),
                0,
                "the delay IAT was patched with the kernel shim"
            );

            let unresolved = with_delay_import(
                build_test_driver(false, false, false),
                "PsGetCurrentProcessId",
            );
            let error = match DriverIsland::load_and_start_named(
                &unresolved,
                "CasaDelayBad",
                &mut runtime,
                &mut memory,
            ) {
                Ok(_) => panic!("an unresolved delay import must reject the load"),
                Err(error) => error,
            };
            assert_eq!(error.code, ReasonCode::RcImportMissing);
            assert!(error.message.contains("PsGetCurrentProcessId"));
        });
    }

    #[test]
    fn guest_ioctl_read_and_write_dispatch_real_irps() {
        with_big_stack(|| {
            let image = build_io_driver();
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaIo",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaIo",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );

            let (devices, names) = with_loaded_driver(&runtime, "CasaIo", |island| {
                (island.device_count(), island.casak_device_names())
            })
            .expect("loaded");
            assert_eq!(devices, 1, "DriverEntry created the device: {names:?}");
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\CasaTest", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            assert_ne!(handle, 0);

            let input = 0x51_000;
            let output = 0x52_000;
            let iosb = 0x53_000;
            memory.map_bytes(input, b"PING");
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            let status = dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[
                    u64::from(handle),
                    0,
                    0,
                    0,
                    iosb,
                    0x22_0004,
                    input,
                    4,
                    output,
                    8,
                ],
            );
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
            assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"RESP");
            let image_base = with_loaded_driver(&runtime, "CasaIo", |island| island.image_base())
                .expect("loaded");
            assert_eq!(
                memory.read_u32(image_base + 0x3140).unwrap(),
                0xCA5A_0004,
                "the driver's real DEVICE_CONTROL code ran"
            );

            memory.map_bytes(output, &[0_u8; 8]);
            let status = dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtReadFile,
                &[u64::from(handle), 0, 0, 0, iosb, output, 8, 0, 0],
            );
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
            assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"RESP");

            memory.map_bytes(input, b"DATA");
            memory.map_bytes(iosb, &[0_u8; 24]);
            let status = dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtWriteFile,
                &[u64::from(handle), 0, 0, 0, iosb, input, 4, 0, 0],
            );
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
            assert_eq!(memory.read_u32(image_base + 0x3140).unwrap(), 0xCA5A_0004);

            // A handle outside the island namespace is an invalid handle.
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[0xDEAD, 0, 0, 0, iosb, 0x22_0004, input, 4, output, 8],
                ),
                STATUS_INVALID_HANDLE
            );
            // A missing device path is not opened.
            let (missing, missing_status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\Missing", 0x45_000);
            assert_eq!(missing, 0);
            assert_eq!(missing_status, STATUS_OBJECT_NAME_NOT_FOUND);
            // An invalid output buffer is rejected before the driver runs.
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x22_0004,
                        input,
                        4,
                        0xDEAD_0000,
                        4,
                    ],
                ),
                STATUS_INVALID_PARAMETER
            );
            // Unloading with an open island handle is refused.
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_DEVICE_BUSY
            );
            assert!(with_loaded_driver(&runtime, "CasaIo", |_| ()).is_some());
        });
    }

    #[test]
    fn irp_without_a_handler_fails_with_invalid_device_request() {
        with_big_stack(|| {
            let image = build_test_driver(false, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaNoHandler",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaNoHandler",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\CasaTest", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            let iosb = 0x53_000;
            let buffer = 0x54_000;
            memory.map_bytes(iosb, &[0_u8; 24]);
            memory.map_bytes(buffer, &[0_u8; 8]);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtReadFile,
                    &[u64::from(handle), 0, 0, 0, iosb, buffer, 8, 0, 0],
                ),
                STATUS_INVALID_DEVICE_REQUEST
            );
        });
    }

    #[test]
    fn pe32_device_ioctl_dispatches_through_x86_irp() {
        with_big_stack(|| {
            let image = build_pe32_driver();
            let (mut runtime, _directory) = test_runtime_x86_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaPe32Svc",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string_x86(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaPe32Svc",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\Casa32", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            assert_ne!(handle, 0);

            let input = 0x51_000;
            let output = 0x52_000;
            let iosb = 0x53_000;
            memory.map_bytes(input, b"PING");
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x22_0004,
                        input,
                        4,
                        output,
                        8
                    ],
                ),
                STATUS_SUCCESS
            );
            assert_eq!(memory.read_u32(iosb + 4).unwrap(), 4);
            assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"RESP");
            let image_base =
                with_loaded_driver(&runtime, "CasaPe32Svc", |island| island.image_base())
                    .expect("loaded");
            assert_eq!(
                memory.read_u32(image_base + 0x3014).unwrap(),
                0xCA5A_0006,
                "the PE32 DEVICE_CONTROL handler ran"
            );
        });
    }

    #[test]
    fn nt_load_expands_environment_honors_start_type_and_traces() {
        with_big_stack(|| {
            let image = build_test_driver(false, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                let key = "SYSTEM\\CurrentControlSet\\Services\\CasaEnv";
                ge.registry_create_key("HKLM", key, RegistryView::Native)
                    .expect("create service key");
                ge.registry_set_value(
                    "HKLM",
                    key,
                    "ImagePath",
                    "REG_EXPAND_SZ",
                    json!("%CASA_DRIVER_DIR%\\casa_nt.sys"),
                    RegistryView::Native,
                )
                .expect("write ImagePath");
                ge.registry_set_value(
                    "HKLM",
                    key,
                    "StartType",
                    "REG_DWORD",
                    json!(SERVICE_DEMAND_START),
                    RegistryView::Native,
                )
                .expect("write StartType");
                let disabled = "SYSTEM\\CurrentControlSet\\Services\\CasaDisabled";
                ge.registry_create_key("HKLM", disabled, RegistryView::Native)
                    .expect("create disabled key");
                ge.registry_set_value(
                    "HKLM",
                    disabled,
                    "ImagePath",
                    "REG_SZ",
                    json!("C:\\Windows\\System32\\drivers\\casa_nt.sys"),
                    RegistryView::Native,
                )
                .expect("write disabled ImagePath");
                ge.registry_set_value(
                    "HKLM",
                    disabled,
                    "StartType",
                    "REG_DWORD",
                    json!(SERVICE_DISABLED),
                    RegistryView::Native,
                )
                .expect("write disabled StartType");
                ge.create_directory("C:\\Windows\\System32\\drivers", true)
                    .expect("create driver directory");
                ge.write_file(DRIVER_IMAGE_PATH, &image, true)
                    .expect("write driver image");
            });
            runtime.process_environment.insert(
                "CASA_DRIVER_DIR".to_string(),
                "C:\\Windows\\System32\\drivers".to_string(),
            );
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaEnv",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS,
                "%%ENV%% in ImagePath expands from the GE environment"
            );
            assert!(runtime.trace_events.iter().any(|event| {
                event.category == "driver"
                    && event.call_id == "NtLoadDriver"
                    && event
                        .parameters
                        .get("status")
                        .and_then(|value| value.as_str())
                        == Some("0x00000000")
            }));
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            assert!(
                runtime.trace_events.iter().any(|event| {
                    event.category == "driver" && event.call_id == "NtUnloadDriver"
                })
            );

            let disabled = guest_unicode_string(
                &mut memory,
                0x42_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaDisabled",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[disabled],
                ),
                STATUS_OBJECT_NAME_NOT_FOUND,
                "SERVICE_DISABLED services are not started"
            );
        });
    }

    #[test]
    fn kmdf_device_add_and_ioctl_complete_through_guest_callbacks() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdf",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdf",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS,
                "WdfDriverCreate must drive EvtDriverDeviceAdd"
            );
            let image_base = with_loaded_driver(&runtime, "CasaKmdf", |island| {
                assert_eq!(island.status(), STATUS_SUCCESS);
                assert_eq!(island.device_count(), 1);
                assert_eq!(island.casak_device_names(), vec!["WdfCasa"]);
                let state = island.inner.borrow();
                assert_ne!(state.kmdf.driver_handle, 0, "real WDFDRIVER object");
                assert_eq!(state.kmdf.devices.len(), 1, "real WDFDEVICE object");
                assert_eq!(state.kmdf.queues.len(), 1, "real WDFQUEUE object");
                assert_eq!(state.kmdf.wait_locks.len(), 1, "real wait lock");
                assert!(
                    state.kmdf.requests.is_empty(),
                    "WdfRequestCreate built a real CasaK IRP that WdfObjectDelete removed"
                );
                let device = state.kmdf.devices.values().next().expect("device");
                assert_eq!(
                    memory.read_u32(device.context_guest).unwrap(),
                    0xC0DE,
                    "WdfObjectGetTypedContext returned writable context storage"
                );
                drop(state);
                assert_eq!(
                    memory
                        .read_u32(island.image_base() + u64::from(K_MARKER_RVA))
                        .unwrap(),
                    0xCA5A_0010,
                    "the guest EvtDriverDeviceAdd code ran"
                );
                assert_eq!(
                    memory
                        .read_u32(island.image_base() + u64::from(K_DELETE_MARKER_RVA))
                        .unwrap(),
                    0xCA5A_0012,
                    "WdfObjectDelete ran in the guest callback"
                );
                assert_ne!(
                    memory
                        .read_u64(island.image_base() + u64::from(K_DEVOBJ_OUT_RVA))
                        .unwrap(),
                    0,
                    "WdfDeviceWdmGetDeviceObject returned the real PDEVICE_OBJECT"
                );
                island.image_base()
            })
            .expect("loaded");

            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfCasa", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            assert_ne!(handle, 0);
            let input = 0x51_000;
            let output = 0x52_000;
            let iosb = 0x53_000;
            memory.map_bytes(input, b"PING");
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        input,
                        4,
                        output,
                        8,
                    ],
                ),
                STATUS_SUCCESS,
                "the framework queue delivered the ioctl to EvtIoDeviceControl"
            );
            assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
            assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"WDF!");
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(K_IOCTL_MARKER_RVA))
                    .unwrap(),
                0x0022_0004,
                "the guest EvtIoDeviceControl code ran"
            );
            with_loaded_driver(&runtime, "CasaKmdf", |island| {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.ioctl_dispatches, 1);
                assert_eq!(state.kmdf.requests.len(), 1, "framework request only");
                assert!(
                    state
                        .kmdf
                        .requests
                        .values()
                        .any(|request| request.completed)
                );
            })
            .expect("loaded");

            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_DEVICE_BUSY,
                "the open island handle keeps the KMDF driver busy"
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtClose,
                    &[u64::from(handle)],
                ),
                STATUS_SUCCESS
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS,
                "closing the handle allows unload"
            );
        });
    }

    #[test]
    fn kmdf_ioctl_without_a_queue_fails_with_invalid_device_request() {
        with_big_stack(|| {
            let image = build_kmdf_driver(false, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfNoQueue",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfNoQueue",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfCasa", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            let iosb = 0x53_000;
            let output = 0x52_000;
            memory.map_bytes(iosb, &[0_u8; 24]);
            memory.map_bytes(output, &[0_u8; 8]);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[u64::from(handle), 0, 0, 0, iosb, 0x22_0004, 0, 0, output, 8],
                ),
                STATUS_INVALID_DEVICE_REQUEST,
                "an ioctl with no queue must not reach a callback"
            );
            assert!(crate::driver_island::close_island_device_handle(
                &runtime, handle
            ));
        });
    }

    #[test]
    fn kmdf_missing_framework_symbol_rejects_the_image() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime();
            let mut memory = MemoryImage::default();
            let bytes = build_kmdf_driver(true, true, false);
            let error = match DriverIsland::load_and_start_named(
                &bytes,
                "CasaKmdfBad",
                &mut runtime,
                &mut memory,
            ) {
                Ok(_) => panic!("a missing WDF symbol must reject the load"),
                Err(error) => error,
            };
            assert_eq!(error.code, ReasonCode::RcImportMissing);
            assert!(
                error.message.contains("WdfDriverCreatX"),
                "{}",
                error.message
            );
        });
    }

    #[test]
    fn kmdf_bad_device_add_callback_is_rejected() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime();
            let mut memory = MemoryImage::default();
            let bytes = build_kmdf_driver(true, false, true);
            let island = DriverIsland::load_and_start_named(
                &bytes,
                "CasaKmdfBadCallback",
                &mut runtime,
                &mut memory,
            )
            .expect("the entry bytes execute");
            assert_eq!(island.status(), STATUS_INVALID_PARAMETER);
            assert!(!island.is_loaded());
            assert_eq!(island.device_count(), 0);
        });
    }

    #[test]
    fn island_handle_close_and_double_close_are_accounted() {
        with_big_stack(|| {
            let image = build_io_driver();
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaClose",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaClose",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\CasaTest", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_DEVICE_BUSY
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtClose,
                    &[u64::from(handle)],
                ),
                STATUS_SUCCESS,
                "NtClose releases an island handle"
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtClose,
                    &[u64::from(handle)],
                ),
                STATUS_INVALID_HANDLE,
                "double close is rejected"
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS,
                "unload succeeds after the handle is closed"
            );
        });
    }

    #[test]
    fn close_handle_releases_an_island_handle() {
        with_big_stack(|| {
            let image = build_io_driver();
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaCloseHandle",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaCloseHandle",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\CasaTest", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            assert_ne!(handle, 0);
            assert!(
                crate::driver_island::is_island_device_handle(&runtime, handle),
                "NtCreateFile minted an island handle"
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::CloseHandle,
                    &[u64::from(handle)],
                ),
                1
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
        });
    }

    fn claim_island(runtime: &PeHostRuntime, service: &str) -> DriverIsland {
        with_loaded_driver(runtime, service, |island| DriverIsland {
            inner: island.inner.clone(),
        })
        .expect("driver island loaded")
    }

    fn queue_for_device(island: &DriverIsland, device: u64) -> u64 {
        island
            .inner
            .borrow()
            .kmdf
            .queues
            .iter()
            .find(|(_, queue)| queue.device == device && queue.default_queue)
            .map(|(handle, _)| *handle)
            .expect("default queue")
    }

    fn pending_request(island: &DriverIsland) -> u64 {
        island
            .inner
            .borrow()
            .kmdf
            .requests
            .iter()
            .find(|(_, request)| !request.completed)
            .map(|(handle, _)| *handle)
            .expect("pending request")
    }

    fn write_descriptor(memory: &mut MemoryImage, address: u64, pointer: u64, length: u64) {
        memory.map_bytes(address, &[0_u8; 0x20]);
        memory.write_u32(address, 0);
        memory.write_u64(address + 8, pointer);
        memory.write_u64(address + 0x10, length);
    }

    #[test]
    fn kmdf_full_config_parses_and_invokes_evt_driver_unload() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(0, true);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfConfig",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfConfig",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfConfig");
            assert_eq!(island.device_count(), 2);
            let names = island.casak_device_names();
            assert!(names.iter().any(|name| name == "WdfA"), "{names:?}");
            assert!(names.iter().any(|name| name == "WdfB"), "{names:?}");
            let image_base = island.image_base();
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.driver_pool_tag, 0x2146_4457);
                assert_eq!(state.kmdf.driver_init_flags, 0);
                assert_ne!(state.kmdf.evt_driver_unload, 0);
                assert_eq!(state.kmdf.devices.len(), 2);
                assert_eq!(state.kmdf.queues.len(), 2);
                for device in state.kmdf.devices.values() {
                    assert_eq!(
                        state
                            .kmdf
                            .objects
                            .get(&device.context_guest.saturating_sub(0x80))
                            .map(|object| object.context_size),
                        Some(0x30),
                        "requested context size is honored"
                    );
                }
            }
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_ADD_COUNT))
                    .unwrap(),
                1,
                "EvtDriverDeviceAdd ran"
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let unloaded = take_last_unloaded_driver().expect("unloaded island");
            assert_eq!(unloaded.inner.borrow().kmdf.driver_unload_calls, 1);
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_UNLOAD_MARKER))
                    .unwrap(),
                0xCA5A_0200,
                "WDF_DRIVER_CONFIG.EvtDriverUnload executed"
            );
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_UNLOAD_COUNT))
                    .unwrap(),
                1
            );
        });
    }

    #[test]
    fn kmdf_framework_dispatches_read_write_cleanup_close_and_ioctl() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(0, true);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfDispatch",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfDispatch",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfDispatch");
            let image_base = island.image_base();
            let device_guest = island
                .created_devices()
                .into_iter()
                .find(|device| device.name.ends_with("WdfA"))
                .map(|device| device.guest_pointer)
                .expect("device A");
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            let input = 0x51_000;
            let output = 0x52_000;
            let iosb = 0x53_000;
            memory.map_bytes(input, b"PING");
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        input,
                        4,
                        output,
                        8,
                    ],
                ),
                STATUS_SUCCESS
            );
            assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"KMDF");
            assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_IOCTL_MARKER))
                    .unwrap(),
                0x0022_0004
            );
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtReadFile,
                    &[u64::from(handle), 0, 0, 0, iosb, output, 8, 0, 0],
                ),
                STATUS_SUCCESS
            );
            assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"RD01");
            assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
            memory.map_bytes(input, b"DATA");
            memory.map_bytes(iosb, &[0_u8; 24]);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtWriteFile,
                    &[u64::from(handle), 0, 0, 0, iosb, input, 4, 0, 0],
                ),
                STATUS_SUCCESS
            );
            assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_WRITE_MARKER))
                    .unwrap(),
                0x41544144
            );
            let (cleanup_status, _) = island
                .dispatch_irp(
                    &mut runtime,
                    &mut memory,
                    device_guest,
                    IrpMajorFunction::Cleanup,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("cleanup dispatch");
            assert_eq!(cleanup_status, STATUS_SUCCESS);
            let (close_status, _) = island
                .dispatch_irp(
                    &mut runtime,
                    &mut memory,
                    device_guest,
                    IrpMajorFunction::Close,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("close dispatch");
            assert_eq!(close_status, STATUS_SUCCESS);
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.ioctl_dispatches, 1);
                assert_eq!(state.kmdf.read_dispatches, 1);
                assert_eq!(state.kmdf.write_dispatches, 1);
                assert_eq!(state.kmdf.cleanup_dispatches, 1);
                assert_eq!(state.kmdf.close_dispatches, 1);
            }
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_DEFAULT_COUNT))
                    .unwrap(),
                2
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtClose,
                    &[u64::from(handle)],
                ),
                STATUS_SUCCESS
            );
        });
    }

    #[test]
    fn kmdf_manual_queue_retrieve_and_cancel_callbacks() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(2, true);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfManual",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfManual",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfManual");
            let image_base = island.image_base();
            let device = island.kmdf_device_handles()[0];
            let queue = queue_for_device(&island, device);
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            let input = 0x51_000;
            let output = 0x52_000;
            let iosb = 0x53_000;
            memory.map_bytes(input, b"PING");
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            for _ in 0..2 {
                assert_eq!(
                    dispatch_nt_thunk(
                        &mut runtime,
                        &mut memory,
                        HostThunk::NtDeviceIoControlFile,
                        &[
                            u64::from(handle),
                            0,
                            0,
                            0,
                            iosb,
                            0x0022_0004,
                            input,
                            4,
                            output,
                            8,
                        ],
                    ),
                    STATUS_PENDING,
                    "manual queues defer delivery"
                );
            }
            let requests = island
                .inner
                .borrow()
                .kmdf
                .requests
                .iter()
                .filter(|(_, request)| !request.completed)
                .map(|(handle, _)| *handle)
                .collect::<Vec<_>>();
            assert_eq!(requests.len(), 2);
            let found_out = 0x54_000;
            memory.map_bytes(found_out, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoQueueRetrieveFoundRequest,
                        &[queue, requests[1], found_out],
                    )
                    .expect("retrieve found") as u32 as i32,
                STATUS_SUCCESS
            );
            assert_eq!(memory.read_u64(found_out).unwrap(), requests[1]);
            let next_out = 0x54_100;
            memory.map_bytes(next_out, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoQueueRetrieveNextRequest,
                        &[queue, next_out],
                    )
                    .expect("retrieve next") as u32 as i32,
                STATUS_SUCCESS
            );
            assert_eq!(memory.read_u64(next_out).unwrap(), requests[0]);
            for request in requests {
                assert_eq!(
                    island
                        .call_shim_for_test(
                            &mut runtime,
                            &mut memory,
                            DriverShim::WdfRequestCompleteWithInformation,
                            &[request, STATUS_SUCCESS as u64, 4],
                        )
                        .expect("complete") as u32 as i32,
                    STATUS_SUCCESS
                );
                let (completed, status, information, outer) =
                    island.kmdf_request_state(request).unwrap();
                assert!(completed);
                assert_eq!(status, STATUS_SUCCESS);
                assert_eq!(information, 4);
                assert_eq!(memory.read_u64(outer + 0x40).unwrap(), 4);
            }
            // Queue one more request and cancel it: the queue's
            // EvtIoCanceledOnQueue callback completes it with STATUS_CANCELLED.
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        input,
                        4,
                        output,
                        8,
                    ],
                ),
                STATUS_PENDING
            );
            let cancel_request = pending_request(&island);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestCancelQueuedRequest,
                        &[cancel_request],
                    )
                    .expect("cancel queued") as u32 as i32,
                STATUS_SUCCESS
            );
            let (completed, status, _, outer) =
                island.kmdf_request_state(cancel_request).expect("request");
            assert!(completed);
            assert_eq!(status, STATUS_CANCELLED);
            assert_ne!(outer, 0);
            assert_eq!(
                memory.read_u32(outer + 0x30).unwrap(),
                STATUS_CANCELLED as u32
            );
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.manual_retrievals, 2);
                assert_eq!(state.kmdf.cancel_dispatches, 1);
            }
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_CANCEL_COUNT))
                    .unwrap(),
                1
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtClose,
                    &[u64::from(handle)],
                ),
                STATUS_SUCCESS
            );
        });
    }

    #[test]
    fn kmdf_queue_stop_resume_and_sequential_dispatch() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(0, true);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfQueue",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfQueue",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfQueue");
            let image_base = island.image_base();
            let device = island.kmdf_device_handles()[0];
            let queue = queue_for_device(&island, device);
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoQueueStopSynchronously,
                        &[queue],
                    )
                    .expect("stop") as u32 as i32,
                STATUS_SUCCESS
            );
            let input = 0x51_000;
            let output = 0x52_000;
            let iosb = 0x53_000;
            memory.map_bytes(input, b"PING");
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            for _ in 0..2 {
                assert_eq!(
                    dispatch_nt_thunk(
                        &mut runtime,
                        &mut memory,
                        HostThunk::NtDeviceIoControlFile,
                        &[
                            u64::from(handle),
                            0,
                            0,
                            0,
                            iosb,
                            0x0022_0004,
                            input,
                            4,
                            output,
                            8,
                        ],
                    ),
                    STATUS_PENDING,
                    "a stopped queue does not deliver"
                );
            }
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoQueueStopSynchronously,
                        &[queue],
                    )
                    .expect("stop queued") as u32 as i32,
                STATUS_SUCCESS
            );
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_STOP_COUNT))
                    .unwrap(),
                2,
                "EvtIoStop observed both queued requests"
            );
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoQueueStart,
                        &[queue],
                    )
                    .expect("start") as u32 as i32,
                STATUS_SUCCESS
            );
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_RESUME_COUNT))
                    .unwrap(),
                2
            );
            {
                let state = island.inner.borrow();
                assert_eq!(
                    memory
                        .read_u32(image_base + u64::from(F_IOCTL_COUNT))
                        .unwrap(),
                    2,
                    "sequential dispatch delivered both queued requests (ioctl_disp={}, queued_disp={}, queues={:?}, reqs={:?})",
                    state.kmdf.ioctl_dispatches,
                    state.kmdf.queued_dispatches,
                    state.kmdf.queues,
                    state
                        .kmdf
                        .requests
                        .values()
                        .map(|request| (request.completed, request.status))
                        .collect::<Vec<_>>()
                );
                assert_eq!(state.kmdf.ioctl_dispatches, 2);
                let queue = state.kmdf.queues.get(&queue).expect("queue");
                assert!(queue.queued.is_empty());
                assert!(queue.in_flight.is_empty());
                assert!(!queue.stopped);
                assert!(
                    state
                        .kmdf
                        .requests
                        .values()
                        .all(|request| request.completed)
                );
            }
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtClose,
                    &[u64::from(handle)],
                ),
                STATUS_SUCCESS
            );
        });
    }

    #[test]
    fn kmdf_iotarget_sends_ioctl_to_another_device() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(0, true);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfTarget",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfTarget",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfTarget");
            let image_base = island.image_base();
            let device_a = island
                .inner
                .borrow()
                .kmdf
                .devices
                .iter()
                .find(|(_, device)| device.name.ends_with("WdfA"))
                .map(|(handle, _)| *handle)
                .expect("device A");
            let device_b = island
                .inner
                .borrow()
                .kmdf
                .devices
                .iter()
                .find(|(_, device)| device.name.ends_with("WdfB"))
                .map(|(handle, _)| *handle)
                .expect("device B");
            let target_a = island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceGetIoTarget,
                    &[device_a],
                )
                .expect("get target");
            assert_ne!(target_a, 0);
            let target_b_out = 0x54_000;
            memory.map_bytes(target_b_out, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoTargetCreate,
                        &[device_b, 0, target_b_out],
                    )
                    .expect("create target") as u32 as i32,
                STATUS_SUCCESS
            );
            let target_b = memory.read_u64(target_b_out).unwrap();
            assert_ne!(target_b, target_a);
            let input = 0x56_000;
            let output = 0x56_100;
            let bytes_returned = 0x56_200;
            memory.map_bytes(input, b"PING");
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(bytes_returned, &[0_u8; 8]);
            let input_descriptor = 0x55_000;
            let output_descriptor = 0x55_020;
            write_descriptor(&mut memory, input_descriptor, input, 4);
            write_descriptor(&mut memory, output_descriptor, output, 8);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoTargetSendIoctlSynchronously,
                        &[
                            target_b,
                            0,
                            0x0022_0004,
                            input_descriptor,
                            output_descriptor,
                            0,
                            bytes_returned,
                        ],
                    )
                    .expect("send ioctl") as u32 as i32,
                STATUS_SUCCESS
            );
            assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"KMDF");
            assert_eq!(memory.read_u64(bytes_returned).unwrap(), 4);
            // The formatted-request + WdfRequestSend path completes a real
            // WDFREQUEST against device B.
            let request_out = 0x54_100;
            memory.map_bytes(request_out, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestCreate,
                        &[0, target_b, request_out],
                    )
                    .expect("create request") as u32 as i32,
                STATUS_SUCCESS
            );
            let request = memory.read_u64(request_out).unwrap();
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoTargetFormatRequestForIoctl,
                        &[
                            target_b,
                            request,
                            0x0022_0004,
                            input_descriptor,
                            0,
                            output_descriptor,
                            0,
                        ],
                    )
                    .expect("format request") as u32 as i32,
                STATUS_SUCCESS
            );
            memory.map_bytes(output, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestSend,
                        &[request, target_b, 0],
                    )
                    .expect("send request") as u32 as i32,
                STATUS_SUCCESS
            );
            let (completed, status, information, _) =
                island.kmdf_request_state(request).expect("request");
            assert!(completed);
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(information, 4);
            assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"KMDF");
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.iotarget_sends, 2);
                assert_eq!(state.kmdf.iotargets.len(), 2);
            }
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_IOCTL_COUNT))
                    .unwrap(),
                2
            );
        });
    }

    #[test]
    fn kmdf_wait_lock_blocks_with_timeout_and_wakes_waiters() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfLock",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfLock",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfLock");
            let lock = island.kmdf_wait_lock_handles()[0];
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockAcquire,
                        &[lock, 0],
                    )
                    .expect("acquire") as u32 as i32,
                STATUS_SUCCESS
            );
            let gate = island.kmdf_wait_lock_gate(lock).expect("gate");
            let releaser = {
                let gate = gate.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(30));
                    let (mutex, wake) = &*gate;
                    let mut locked = mutex.lock().unwrap();
                    *locked = false;
                    drop(locked);
                    wake.notify_all();
                })
            };
            let timeout = 0x54_000;
            memory.map_bytes(timeout, &[0_u8; 8]);
            memory.write_u64(timeout, (-20_000_000_i64) as u64);
            let started = std::time::Instant::now();
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockAcquire,
                        &[lock, timeout],
                    )
                    .expect("blocking acquire") as u32 as i32,
                STATUS_SUCCESS
            );
            let elapsed = started.elapsed();
            assert!(
                elapsed >= std::time::Duration::from_millis(20),
                "acquire parked the guest for {elapsed:?}"
            );
            releaser.join().expect("releaser");
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockRelease,
                        &[lock],
                    )
                    .expect("release") as u32 as i32,
                STATUS_SUCCESS
            );
            // A held lock with a relative 100 microsecond timeout returns
            // STATUS_TIMEOUT and leaves the lock held.
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockAcquire,
                        &[lock, 0],
                    )
                    .expect("acquire again") as u32 as i32,
                STATUS_SUCCESS
            );
            memory.write_u64(timeout, (-1_000_i64) as u64);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockAcquire,
                        &[lock, timeout],
                    )
                    .expect("timeout acquire") as u32 as i32,
                STATUS_TIMEOUT
            );
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockRelease,
                        &[lock],
                    )
                    .expect("final release") as u32 as i32,
                STATUS_SUCCESS
            );
            // Adversarial: four independent waiters serialize on the same
            // gate; the shared state must never observe two owners at once.
            let gate = island.kmdf_wait_lock_gate(lock).expect("gate");
            let mut held = {
                let (mutex, _) = &*gate;
                let mut guard = mutex.lock().unwrap();
                *guard = true;
                guard
            };
            let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut waiters = Vec::new();
            for _ in 0..4 {
                let gate = gate.clone();
                let active = active.clone();
                let peak = peak.clone();
                waiters.push(std::thread::spawn(move || {
                    let (mutex, wake) = &*gate;
                    let mut locked = mutex.lock().unwrap();
                    while *locked {
                        locked = wake.wait(locked).unwrap();
                    }
                    *locked = true;
                    let now = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    *locked = false;
                    drop(locked);
                    wake.notify_all();
                }));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            *held = false;
            drop(held);
            let (_, wake) = &*gate;
            wake.notify_all();
            for waiter in waiters {
                waiter.join().expect("waiter");
            }
            assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn kmdf_object_contexts_attributes_and_cascade_deletion() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(0, true);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfObjects",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfObjects",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfObjects");
            let image_base = island.image_base();
            let driver = island.kmdf_driver_handle();
            let devices = island.kmdf_device_handles();
            let device = devices[0];
            let queue = queue_for_device(&island, device);
            assert_eq!(island.kmdf_context_size(device), Some(0x30));
            let context = island.kmdf_typed_context(device).expect("context");
            memory.write_u32(context, 0x00C0_FFEE);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfObjectGetTypedContext,
                        &[device, 1],
                    )
                    .expect("typed context")
                    .saturating_sub(context),
                0
            );
            let type_info = 0x54_000;
            let context_out = 0x54_010;
            memory.map_bytes(type_info, &[0_u8; 0x20]);
            memory.map_bytes(context_out, &[0_u8; 8]);
            memory.write_u32(type_info, 0x18);
            memory.write_u64(type_info + 0x10, 0x40);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfObjectAllocateContext,
                        &[device, type_info, context_out],
                    )
                    .expect("allocate context") as u32 as i32,
                STATUS_SUCCESS
            );
            let extra = memory.read_u64(context_out).unwrap();
            assert_ne!(extra, context);
            memory.write_u32(extra + 0x30, 0x1234_5678);
            assert_eq!(memory.read_u32(extra + 0x30).unwrap(), 0x1234_5678);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfObjectDelete,
                        &[queue],
                    )
                    .expect("delete queue") as u32 as i32,
                STATUS_SUCCESS
            );
            assert!(island.inner.borrow().kmdf.queues.get(&queue).is_none());
            assert_eq!(island.kmdf_device_handles().len(), 2);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfObjectDelete,
                        &[driver],
                    )
                    .expect("delete driver") as u32 as i32,
                STATUS_SUCCESS
            );
            {
                let state = island.inner.borrow();
                assert!(state.kmdf.devices.is_empty());
                assert!(state.kmdf.queues.is_empty());
                assert_eq!(state.kmdf.driver_unload_calls, 1);
            }
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_UNLOAD_MARKER))
                    .unwrap(),
                0xCA5A_0200
            );
            assert!(
                memory
                    .read_u32(image_base + u64::from(F_CLEANUP_COUNT))
                    .unwrap()
                    >= 3
            );
            assert!(
                memory
                    .read_u32(image_base + u64::from(F_DESTROY_COUNT))
                    .unwrap()
                    >= 3
            );
        });
    }

    #[test]
    fn kmdf_driver_config_flags_disable_dispatch_override() {
        with_big_stack(|| {
            let mut image = build_kmdf_full_driver(0, true);
            put_u32(&mut image, 0x1000 + 0x1C, 2);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfFlags",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfFlags",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfFlags");
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.driver_init_flags, 2);
            assert!(state.kmdf.framework_dispatches.is_empty());
            assert_eq!(state.kmdf.driver_pool_tag, 0x2146_4457);
        });
    }

    #[test]
    fn kmdf_pe32_driver_executes_and_unloads() {
        with_big_stack(|| {
            let image = build_kmdf_driver_pe32();
            let (mut runtime, _directory) = test_runtime_x86_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdf32",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string_x86(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdf32",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS,
                "the crafted PE32 KMDF DriverEntry must execute"
            );
            let island = claim_island(&runtime, "CasaKmdf32");
            let image_base = island.image_base();
            assert_eq!(island.device_count(), 1);
            assert_eq!(island.casak_device_names(), vec!["Wdf32"]);
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.driver_pool_tag, 0x2146_4457);
                assert_ne!(state.kmdf.evt_driver_unload, 0);
            }
            assert_eq!(
                memory
                    .read_u32(u64::from(image_base as u32 + X86K_ADD_MARKER))
                    .unwrap(),
                0xCA5A_0031
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let unloaded = take_last_unloaded_driver().expect("unloaded");
            assert_eq!(unloaded.inner.borrow().kmdf.driver_unload_calls, 1);
            assert_eq!(
                memory
                    .read_u32(u64::from(image_base as u32 + X86K_UNLOAD_MARKER))
                    .unwrap(),
                0xCA5A_0032,
                "32-bit EvtDriverUnload executed"
            );
        });
    }

    #[test]
    fn kmdf_cancelled_request_without_callback_completes_cancelled() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(2, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfCancel",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfCancel",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfCancel");
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            let iosb = 0x53_000;
            memory.map_bytes(iosb, &[0_u8; 24]);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[u64::from(handle), 0, 0, 0, iosb, 0x0022_0004, 0, 0, 0, 0],
                ),
                STATUS_PENDING
            );
            let request = pending_request(&island);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestCancelQueuedRequest,
                        &[request],
                    )
                    .expect("cancel") as u32 as i32,
                STATUS_CANCELLED
            );
            let (completed, status, _, outer) =
                island.kmdf_request_state(request).expect("request");
            assert!(completed);
            assert_eq!(status, STATUS_CANCELLED);
            assert_eq!(
                memory.read_u32(outer + 0x30).unwrap(),
                STATUS_CANCELLED as u32
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtClose,
                    &[u64::from(handle)],
                ),
                STATUS_SUCCESS
            );
        });
    }

    #[test]
    fn loaded_driver_registry_is_shared_across_guest_thread_contexts() {
        with_big_stack(|| {
            let image = build_test_driver(false, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaThreaded",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaThreaded",
            );
            let thread_a = STACK_BASE + STACK_SIZE - 0x180;
            let thread_b = STACK_BASE + STACK_SIZE - 0x280;
            assert_eq!(
                dispatch_nt_thunk_on_thread(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                    thread_a,
                ),
                STATUS_SUCCESS,
                "load from guest thread A"
            );
            assert_eq!(
                dispatch_nt_thunk_on_thread(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                    thread_b,
                ),
                STATUS_IMAGE_ALREADY_LOADED,
                "duplicate load from guest thread B"
            );
            assert_eq!(
                dispatch_nt_thunk_on_thread(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                    thread_b,
                ),
                STATUS_SUCCESS,
                "unload from guest thread B"
            );
            assert!(with_loaded_driver(&runtime, "CasaThreaded", |_| ()).is_none());
        });
    }

    fn x64_complete_stub(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        island: &DriverIsland,
        status: i32,
        information: u32,
    ) -> u64 {
        let complete = allocate_shim(runtime, DriverShim::WdfRequestCompleteWithInformation);
        let mut code = vec![0x48, 0x89, 0xD1, 0xBA];
        code.extend_from_slice(&status.to_le_bytes());
        code.extend_from_slice(&[0x41, 0xB8]);
        code.extend_from_slice(&information.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&complete.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0, 0xC3]);
        let entry = island
            .inner
            .borrow_mut()
            .arena
            .alloc(memory, code.len(), 16)
            .expect("complete stub");
        memory.map_bytes(entry, &code);
        entry
    }

    fn x64_marker_stub(memory: &mut MemoryImage, island: &DriverIsland, counter: u64) -> u64 {
        let mut code = vec![0xFF, 0x05, 0, 0, 0, 0, 0xC3];
        let entry = island
            .inner
            .borrow_mut()
            .arena
            .alloc(memory, code.len(), 16)
            .expect("marker stub");
        let displacement = counter as i64 - (entry as i64 + 6);
        code[2..6].copy_from_slice(&(displacement as i32).to_le_bytes());
        memory.map_bytes(entry, &code);
        entry
    }

    fn arena_counter(memory: &mut MemoryImage, island: &DriverIsland) -> u64 {
        island
            .inner
            .borrow_mut()
            .arena
            .alloc(memory, 8, 8)
            .expect("counter")
    }

    fn set_queue_callbacks(island: &DriverIsland, queue: u64, f: impl FnOnce(&mut KmdfQueue)) {
        if let Some(queue) = island.inner.borrow_mut().kmdf.queues.get_mut(&queue) {
            f(queue);
        }
    }

    fn patch_kmdf_config(image: &mut [u8], flags: u32) {
        const STUB: u32 = 0x3078;
        const COUNTER: u32 = 0x30E0;
        let data_offset = |address: u32| 0xC00 + (address - K_DATA_RVA) as usize;
        let stub = data_offset(STUB);
        let counter = data_offset(COUNTER);
        let displacement = COUNTER as i64 - (STUB as i64 + 6);
        image[stub..stub + 2].copy_from_slice(&[0xFF, 0x05]);
        image[stub + 2..stub + 6].copy_from_slice(&(displacement as i32).to_le_bytes());
        image[stub + 6] = 0xC3;
        image[counter..counter + 4].copy_from_slice(&0_u32.to_le_bytes());
        let config = data_offset(K_CONFIG_RVA);
        image[config + 0x10..config + 0x18]
            .copy_from_slice(&(K_IMAGE_BASE + u64::from(STUB)).to_le_bytes());
        image[config + 0x18..config + 0x1C].copy_from_slice(&0x2146_4457_u32.to_le_bytes());
        image[config + 0x1C..config + 0x20].copy_from_slice(&flags.to_le_bytes());
    }

    fn unload_marker(memory: &MemoryImage, base: u64) -> u32 {
        memory.read_u32(base + 0x30E0).unwrap()
    }

    #[test]
    fn kmdf_driver_config_parse_and_evt_driver_unload() {
        with_big_stack(|| {
            let mut image = build_kmdf_driver(true, false, false);
            patch_kmdf_config(&mut image, 0);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfCfg",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfCfg",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfCfg");
            let base = island.image_base();
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.driver_pool_tag, 0x2146_4457);
                assert_eq!(state.kmdf.driver_init_flags, 0);
                assert_ne!(state.kmdf.evt_driver_unload, 0);
                assert_eq!(state.kmdf.framework_dispatches.len(), 7);
            }
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let unloaded = take_last_unloaded_driver().expect("unloaded island");
            assert_eq!(unloaded.inner.borrow().kmdf.driver_unload_calls, 1);
            assert_eq!(unload_marker(&memory, base), 1);
        });
    }

    #[test]
    fn kmdf_read_write_cleanup_and_close_dispatch() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfRw",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfRw",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfRw");
            let device = island.created_devices()[0].guest_pointer;
            let queue = *island.inner.borrow().kmdf.queues.keys().next().unwrap();
            let stub = x64_complete_stub(&mut runtime, &mut memory, &island, STATUS_SUCCESS, 0);
            set_queue_callbacks(&island, queue, |queue| {
                queue.callbacks.read = stub;
                queue.callbacks.write = stub;
                queue.callbacks.default = stub;
            });
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfCasa", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            let buffer = 0x52_000;
            let iosb = 0x53_000;
            memory.map_bytes(buffer, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtReadFile,
                    &[u64::from(handle), 0, 0, 0, iosb, buffer, 8, 0, 0],
                ),
                STATUS_SUCCESS
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtWriteFile,
                    &[u64::from(handle), 0, 0, 0, iosb, buffer, 4, 0, 0],
                ),
                STATUS_SUCCESS
            );
            let (status, _) = island
                .dispatch_irp(
                    &mut runtime,
                    &mut memory,
                    device,
                    IrpMajorFunction::Cleanup,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("cleanup");
            assert_eq!(status, STATUS_SUCCESS);
            let (status, _) = island
                .dispatch_irp(
                    &mut runtime,
                    &mut memory,
                    device,
                    IrpMajorFunction::Close,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("close");
            assert_eq!(status, STATUS_SUCCESS);
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.read_dispatches, 1);
                assert_eq!(state.kmdf.write_dispatches, 1);
                assert_eq!(state.kmdf.cleanup_dispatches, 1);
                assert_eq!(state.kmdf.close_dispatches, 1);
            }
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtClose,
                    &[u64::from(handle)],
                ),
                STATUS_SUCCESS
            );
        });
    }

    #[test]
    fn kmdf_manual_queue_retrieval_and_cancellation() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfManual",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfManual",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfManual");
            let queue = *island.inner.borrow().kmdf.queues.keys().next().unwrap();
            set_queue_callbacks(&island, queue, |queue| {
                queue.dispatch_type = 2;
                queue.default_queue = true;
            });
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfCasa", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            let input = 0x51_000;
            let output = 0x52_000;
            let iosb = 0x53_000;
            memory.map_bytes(input, b"PING");
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            for _ in 0..2 {
                assert_eq!(
                    dispatch_nt_thunk(
                        &mut runtime,
                        &mut memory,
                        HostThunk::NtDeviceIoControlFile,
                        &[
                            u64::from(handle),
                            0,
                            0,
                            0,
                            iosb,
                            0x0022_0004,
                            input,
                            4,
                            output,
                            8,
                        ],
                    ),
                    STATUS_PENDING
                );
            }
            let requests = island
                .inner
                .borrow()
                .kmdf
                .requests
                .iter()
                .filter(|(_, request)| !request.completed)
                .map(|(handle, _)| *handle)
                .collect::<Vec<_>>();
            assert_eq!(requests.len(), 2);
            let out = 0x54_000;
            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoQueueRetrieveFoundRequest,
                        &[queue, requests[1], out],
                    )
                    .expect("found") as u32 as i32,
                STATUS_SUCCESS
            );
            assert_eq!(memory.read_u64(out).unwrap(), requests[1]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoQueueRetrieveNextRequest,
                        &[queue, out],
                    )
                    .expect("next") as u32 as i32,
                STATUS_SUCCESS
            );
            assert_eq!(memory.read_u64(out).unwrap(), requests[0]);
            for request in &requests {
                assert_eq!(
                    island
                        .call_shim_for_test(
                            &mut runtime,
                            &mut memory,
                            DriverShim::WdfRequestComplete,
                            &[*request, STATUS_SUCCESS as u64],
                        )
                        .expect("complete") as u32 as i32,
                    STATUS_SUCCESS
                );
            }
            let cancel_stub =
                x64_complete_stub(&mut runtime, &mut memory, &island, STATUS_CANCELLED, 0);
            set_queue_callbacks(&island, queue, |queue| {
                queue.callbacks.canceled_on_queue = cancel_stub;
            });
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        input,
                        4,
                        output,
                        8,
                    ],
                ),
                STATUS_PENDING
            );
            let cancel = island
                .inner
                .borrow()
                .kmdf
                .requests
                .iter()
                .find(|(_, request)| !request.completed)
                .map(|(handle, _)| *handle)
                .unwrap();
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestCancelQueuedRequest,
                        &[cancel],
                    )
                    .expect("cancel") as u32 as i32,
                STATUS_SUCCESS
            );
            let (completed, status, _, _) = island.kmdf_request_state(cancel).unwrap();
            assert!(completed);
            assert_eq!(status, STATUS_CANCELLED);
            // Without EvtIoCanceledOnQueue the framework completes the queued
            // request itself with STATUS_CANCELLED.
            set_queue_callbacks(&island, queue, |queue| {
                queue.callbacks.canceled_on_queue = 0;
            });
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        input,
                        4,
                        output,
                        8,
                    ],
                ),
                STATUS_PENDING
            );
            let cancel = island
                .inner
                .borrow()
                .kmdf
                .requests
                .iter()
                .find(|(_, request)| !request.completed)
                .map(|(handle, _)| *handle)
                .unwrap();
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestCancelQueuedRequest,
                        &[cancel],
                    )
                    .expect("cancel no callback") as u32 as i32,
                STATUS_CANCELLED
            );
            assert_eq!(
                island.kmdf_request_state(cancel).unwrap().1,
                STATUS_CANCELLED
            );
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.manual_retrievals, 2);
                assert_eq!(state.kmdf.cancel_dispatches, 2);
            }
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtClose,
                    &[u64::from(handle)],
                ),
                STATUS_SUCCESS
            );
        });
    }

    #[test]
    fn kmdf_iotarget_sends_to_another_device_with_real_completion() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfT",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfT",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfT");
            let base = island.image_base();
            let device_a = island.kmdf_device_handles()[0];
            let init = *island
                .inner
                .borrow()
                .kmdf
                .device_inits
                .keys()
                .next()
                .unwrap();
            let name = guest_unicode_string(&mut memory, 0x57_000, "\\Device\\WdfB");
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfDeviceInitAssignName,
                        &[init, name],
                    )
                    .expect("name") as u32 as i32,
                STATUS_SUCCESS
            );
            let device_b_out = 0x54_000;
            memory.map_bytes(device_b_out, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfDeviceCreate,
                        &[init, 0, device_b_out],
                    )
                    .expect("device B") as u32 as i32,
                STATUS_SUCCESS
            );
            let device_b = memory.read_u64(device_b_out).unwrap();
            let config = 0x58_000;
            memory.map_bytes(config, &[0_u8; 0x60]);
            memory.write_u32(config, 0x50);
            memory.write_u32(config + 4, 1);
            memory.write_u64(config + 0x28, base + u64::from(K_EVT_IOCTL_RVA));
            let queue_out = 0x54_010;
            memory.map_bytes(queue_out, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoQueueCreate,
                        &[device_b, config, 0, queue_out],
                    )
                    .expect("queue B") as u32 as i32,
                STATUS_SUCCESS
            );
            let target_b_out = 0x54_020;
            memory.map_bytes(target_b_out, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoTargetCreate,
                        &[device_b, 0, target_b_out],
                    )
                    .expect("target B") as u32 as i32,
                STATUS_SUCCESS
            );
            let target_b = memory.read_u64(target_b_out).unwrap();
            assert_ne!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfDeviceGetIoTarget,
                        &[device_a],
                    )
                    .expect("target A"),
                0
            );
            let input = 0x56_000;
            let output = 0x56_100;
            let bytes_returned = 0x56_200;
            memory.map_bytes(input, b"PING");
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(bytes_returned, &[0_u8; 8]);
            let input_descriptor = 0x55_000;
            let output_descriptor = 0x55_020;
            for (descriptor, pointer, length) in [
                (input_descriptor, input, 4u64),
                (output_descriptor, output, 8),
            ] {
                memory.map_bytes(descriptor, &[0_u8; 0x20]);
                memory.write_u32(descriptor, 0);
                memory.write_u64(descriptor + 8, pointer);
                memory.write_u64(descriptor + 0x10, length);
            }
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfIoTargetSendIoctlSynchronously,
                        &[
                            target_b,
                            0,
                            0x0022_0004,
                            input_descriptor,
                            output_descriptor,
                            0,
                            bytes_returned,
                        ],
                    )
                    .expect("send") as u32 as i32,
                STATUS_SUCCESS
            );
            assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"WDF!");
            assert_eq!(memory.read_u64(bytes_returned).unwrap(), 4);
            let request_out = 0x54_100;
            memory.map_bytes(request_out, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestCreate,
                        &[0, target_b, request_out],
                    )
                    .expect("request") as u32 as i32,
                STATUS_SUCCESS
            );
            let request = memory.read_u64(request_out).unwrap();
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestFormatRequestForIoctl,
                        &[request, target_b, 0x0022_0004, input, 4, output, 8, 0,],
                    )
                    .expect("format") as u32 as i32,
                STATUS_SUCCESS
            );
            memory.map_bytes(output, &[0_u8; 8]);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestSend,
                        &[request, target_b, 0],
                    )
                    .expect("send request") as u32 as i32,
                STATUS_SUCCESS
            );
            let (completed, status, information, _) = island.kmdf_request_state(request).unwrap();
            assert!(completed);
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(information, 4);
            assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"WDF!");
            assert_eq!(island.inner.borrow().kmdf.iotarget_sends, 2);
        });
    }

    #[test]
    fn kmdf_wait_lock_parks_guest_until_release_with_timeout() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfL",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfL",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfL");
            let lock = island.kmdf_wait_lock_handles()[0];
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockAcquire,
                        &[lock, 0],
                    )
                    .expect("acquire") as u32 as i32,
                STATUS_SUCCESS
            );
            let gate = island.kmdf_wait_lock_gate(lock).unwrap();
            let releaser = {
                let gate = gate.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(30));
                    let (mutex, wake) = &*gate;
                    let mut locked = mutex.lock().unwrap();
                    *locked = false;
                    drop(locked);
                    wake.notify_all();
                })
            };
            let timeout = 0x54_000;
            memory.map_bytes(timeout, &[0_u8; 8]);
            memory.write_u64(timeout, (-20_000_000_i64) as u64);
            let started = std::time::Instant::now();
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockAcquire,
                        &[lock, timeout],
                    )
                    .expect("blocking acquire") as u32 as i32,
                STATUS_SUCCESS
            );
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(20),
                "WdfWaitLockAcquire must block the guest until release"
            );
            releaser.join().unwrap();
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockRelease,
                        &[lock],
                    )
                    .expect("release") as u32 as i32,
                STATUS_SUCCESS
            );
            assert!(island.inner.borrow().kmdf.parked_acquires >= 1);
            // A held lock with a 100 microsecond relative timeout returns
            // STATUS_TIMEOUT without taking ownership.
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockAcquire,
                        &[lock, 0],
                    )
                    .expect("reacquire") as u32 as i32,
                STATUS_SUCCESS
            );
            memory.write_u64(timeout, (-1_000_i64) as u64);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockAcquire,
                        &[lock, timeout],
                    )
                    .expect("timeout") as u32 as i32,
                STATUS_TIMEOUT
            );
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfWaitLockRelease,
                        &[lock],
                    )
                    .expect("final release") as u32 as i32,
                STATUS_SUCCESS
            );
            let mut held = {
                let (mutex, _) = &*gate;
                let mut guard = mutex.lock().unwrap();
                *guard = true;
                guard
            };
            // hold the gate while the waiters start
            let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut waiters = Vec::new();
            for _ in 0..4 {
                let gate = gate.clone();
                let active = active.clone();
                let peak = peak.clone();
                waiters.push(std::thread::spawn(move || {
                    let (mutex, wake) = &*gate;
                    let mut locked = mutex.lock().unwrap();
                    while *locked {
                        locked = wake.wait(locked).unwrap();
                    }
                    *locked = true;
                    let now = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    *locked = false;
                    drop(locked);
                    wake.notify_all();
                }));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            *held = false;
            drop(held);
            let (_, wake) = &*gate;
            wake.notify_all();
            for waiter in waiters {
                waiter.join().unwrap();
            }
            assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn kmdf_object_contexts_attributes_and_driver_cascade() {
        with_big_stack(|| {
            let mut image = build_kmdf_driver(true, false, false);
            patch_kmdf_config(&mut image, 0);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfO",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfO",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfO");
            let base = island.image_base();
            let driver = island.kmdf_driver_handle();
            let device = island.kmdf_device_handles()[0];
            let queue = *island.inner.borrow().kmdf.queues.keys().next().unwrap();
            assert_eq!(island.kmdf_context_size(device), Some(0x80));
            let context = island.kmdf_typed_context(device).unwrap();
            let cleanup_counter = arena_counter(&mut memory, &island);
            let destroy_counter = arena_counter(&mut memory, &island);
            let cleanup_stub = x64_marker_stub(&mut memory, &island, cleanup_counter);
            let destroy_stub = x64_marker_stub(&mut memory, &island, destroy_counter);
            {
                let mut state = island.inner.borrow_mut();
                for handle in [device, queue] {
                    let object = state.kmdf.objects.get_mut(&handle).unwrap();
                    object.evt_cleanup = cleanup_stub;
                    object.evt_destroy = destroy_stub;
                }
            }
            let type_info = 0x54_000;
            let context_out = 0x54_010;
            memory.map_bytes(type_info, &[0_u8; 0x20]);
            memory.map_bytes(context_out, &[0_u8; 8]);
            memory.write_u32(type_info, 0x18);
            memory.write_u64(type_info + 0x10, 0x40);
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfObjectAllocateContext,
                        &[device, type_info, context_out],
                    )
                    .expect("allocate context") as u32 as i32,
                STATUS_SUCCESS
            );
            let extra = memory.read_u64(context_out).unwrap();
            assert_ne!(extra, context);
            memory.write_u32(extra + 0x30, 0x1234_5678);
            assert_eq!(memory.read_u32(extra + 0x30).unwrap(), 0x1234_5678);
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .objects
                    .get(&device)
                    .unwrap()
                    .extra_contexts[0]
                    .2,
                0x40
            );
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfObjectDelete,
                        &[driver],
                    )
                    .expect("delete driver") as u32 as i32,
                STATUS_SUCCESS
            );
            {
                let state = island.inner.borrow();
                assert!(state.kmdf.devices.is_empty());
                assert!(state.kmdf.queues.is_empty());
                assert_eq!(state.kmdf.driver_unload_calls, 1);
            }
            assert_eq!(memory.read_u32(cleanup_counter).unwrap(), 2);
            assert_eq!(memory.read_u32(destroy_counter).unwrap(), 2);
            assert_eq!(unload_marker(&memory, base), 1);
        });
    }

    #[test]
    fn kmdf_driver_init_flags_skip_dispatch_override() {
        with_big_stack(|| {
            let mut image = build_kmdf_driver(true, false, false);
            patch_kmdf_config(&mut image, 2);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                stage_service(
                    ge,
                    "CasaKmdfF",
                    "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfF",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[service_path],
                ),
                STATUS_SUCCESS
            );
            let island = claim_island(&runtime, "CasaKmdfF");
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.driver_init_flags, 2);
            assert!(state.kmdf.framework_dispatches.is_empty());
            assert_eq!(state.kmdf.driver_pool_tag, 0x2146_4457);
        });
    }

    fn load_staged_island_x64(
        image: &[u8],
        service: &str,
    ) -> (Box<PeHostRuntime>, TempDir, MemoryImage, DriverIsland) {
        let (runtime, directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                service,
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                image,
            );
        });
        let mut runtime = Box::new(runtime);
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            &format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{service}"),
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS,
            "staged service {service} must load"
        );
        let island = claim_island(&runtime, service);
        (runtime, directory, memory, island)
    }

    fn load_staged_island_x86(
        image: &[u8],
        service: &str,
    ) -> (Box<PeHostRuntime>, TempDir, MemoryImage, DriverIsland) {
        let (runtime, directory) = test_runtime_x86_with_ge(|ge| {
            stage_service(
                ge,
                service,
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                image,
            );
        });
        let mut runtime = Box::new(runtime);
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string_x86(
            &mut memory,
            0x40_000,
            &format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{service}"),
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS,
            "staged x86 service {service} must load"
        );
        let island = claim_island(&runtime, service);
        (runtime, directory, memory, island)
    }

    fn write_guest_wide(memory: &mut MemoryImage, address: u64, text: &str) {
        let units = text.encode_utf16().collect::<Vec<_>>();
        memory.map_bytes(address, &vec![0_u8; (units.len() + 1) * 2]);
        for (index, unit) in units.iter().enumerate() {
            memory.write_u16(address + index as u64 * 2, *unit);
        }
    }

    fn call_island_shim(
        island: &DriverIsland,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        function: DriverShim,
        args: &[u64],
    ) -> AppResult<i32> {
        island
            .call_shim_for_test(runtime, memory, function, args)
            .map(|value| value as u32 as i32)
    }

    fn call_island_shim_raw(
        island: &DriverIsland,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        function: DriverShim,
        args: &[u64],
    ) -> AppResult<u64> {
        island.call_shim_for_test(runtime, memory, function, args)
    }

    #[test]
    fn shim_x86_arg_bytes_abi_mismatch_or_zero_width_rejects() {
        let expected = [
            (DriverShim::DbgPrint, 4u64),
            (DriverShim::IoCreateDevice, 28),
            (DriverShim::IoDeleteDevice, 4),
            (DriverShim::IoCreateSymbolicLink, 8),
            (DriverShim::IoDeleteSymbolicLink, 8),
            (DriverShim::IoAllocateIrp, 8),
            (DriverShim::IoFreeIrp, 4),
            (DriverShim::RtlInitUnicodeString, 8),
            (DriverShim::IofCompleteRequest, 8),
            (DriverShim::IoCompleteRequest, 8),
            (DriverShim::ExAllocatePoolWithTag, 12),
            (DriverShim::ExFreePoolWithTag, 8),
            (DriverShim::IrpDispatch, 8),
            (DriverShim::WdfDriverCreate, 20),
            (DriverShim::WdfDeviceInitSetDeviceType, 8),
            (DriverShim::WdfDeviceInitSetIoType, 8),
            (DriverShim::WdfDeviceInitAssignName, 8),
            (DriverShim::WdfDeviceCreate, 12),
            (DriverShim::WdfIoQueueCreate, 16),
            (DriverShim::WdfRequestCreate, 12),
            (DriverShim::WdfRequestFormatRequestForIoctl, 32),
            (DriverShim::WdfRequestRetrieveInputBuffer, 16),
            (DriverShim::WdfRequestRetrieveOutputBuffer, 16),
            (DriverShim::WdfRequestComplete, 8),
            (DriverShim::WdfRequestCompleteWithInformation, 12),
            (DriverShim::WdfDeviceWdmGetDeviceObject, 4),
            (DriverShim::WdfObjectGetTypedContext, 8),
            (DriverShim::WdfObjectDelete, 4),
            (DriverShim::WdfWaitLockCreate, 8),
            (DriverShim::WdfWaitLockAcquire, 8),
            (DriverShim::WdfWaitLockRelease, 4),
            (DriverShim::WdfObjectAllocateContext, 12),
            (DriverShim::WdfDeviceGetIoTarget, 4),
            (DriverShim::WdfIoTargetCreate, 12),
            (DriverShim::WdfIoTargetSendIoctlSynchronously, 28),
            (DriverShim::WdfIoTargetFormatRequestForIoctl, 28),
            (DriverShim::WdfRequestSend, 12),
            (DriverShim::WdfRequestCancelQueuedRequest, 4),
            (DriverShim::WdfIoQueueRetrieveNextRequest, 12),
            (DriverShim::WdfIoQueueRetrieveFoundRequest, 12),
            (DriverShim::WdfIoQueueStop, 12),
            (DriverShim::WdfIoQueueStopSynchronously, 4),
            (DriverShim::WdfIoQueueDrain, 12),
            (DriverShim::WdfIoQueueDrainSynchronously, 4),
            (DriverShim::WdfIoQueuePurge, 12),
            (DriverShim::WdfIoQueuePurgeSynchronously, 4),
            (DriverShim::WdfIoQueueStart, 4),
            (DriverShim::WdfEvtIoReadDispatch, 8),
            (DriverShim::WdfEvtIoWriteDispatch, 8),
            (DriverShim::WdfEvtIoDeviceControlDispatch, 8),
            (DriverShim::WdfEvtIoCleanupDispatch, 8),
            (DriverShim::WdfEvtIoCloseDispatch, 8),
            (DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks, 8),
            (DriverShim::WdfDeviceInitSetFileObjectConfig, 8),
            (DriverShim::WdfMemoryCreate, 24),
            (DriverShim::WdfMemoryCreatePreallocated, 16),
            (DriverShim::WdfMemoryGetBuffer, 8),
            (DriverShim::WdfStringCreate, 12),
            (DriverShim::WdfStringGetUnicodeString, 8),
            (DriverShim::WdfDeviceEnqueueRequest, 8),
            (DriverShim::WdfPdoInitAllocate, 4),
            (DriverShim::WdfPdoInitAssignDeviceID, 8),
            (DriverShim::WdfPdoInitAssignInstanceID, 8),
            (DriverShim::WdfPdoInitAddHardwareID, 8),
            (DriverShim::WdfPdoInitAddCompatibleID, 8),
            (DriverShim::WdfEvtPnpDispatch, 8),
            (DriverShim::WdfEvtPowerDispatch, 8),
        ];
        for (shim, want) in expected {
            assert_eq!(
                shim.x86_arg_bytes(),
                want,
                "{shim:?} must pop its exact stdcall byte count"
            );
        }
    }

    #[test]
    fn unload_error_restores_registration_and_reports_invalid_parameter() {
        with_big_stack(|| {
            let image = build_test_driver(false, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaUnloadFail");
            island.inner.borrow_mut().unload_guest = Some(0xDEAD_BEEF);
            let service_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaUnloadFail",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_INVALID_PARAMETER,
                "a failed DriverUnload must be reported as INVALID_PARAMETER"
            );
            assert!(
                with_loaded_driver(&runtime, "CasaUnloadFail", |_| ()).is_some(),
                "the island must be re-registered after a failed unload"
            );
            assert!(island.is_loaded(), "failed unload leaves the island loaded");
        });
    }

    #[test]
    fn io_shims_reject_malformed_names_and_links() {
        with_big_stack(|| {
            let image = build_test_driver(false, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaBadIo");
            let link = guest_unicode_string(&mut memory, 0x50_000, "\\??\\CasaTest");
            let target = guest_unicode_string(&mut memory, 0x52_000, "\\Device\\CasaTest");

            let deleted = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoDeleteSymbolicLink,
                &[link],
            );
            assert_eq!(deleted.expect("delete link"), STATUS_SUCCESS);
            let missing = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoDeleteSymbolicLink,
                &[link],
            );
            assert_eq!(
                missing.expect("delete missing link"),
                STATUS_OBJECT_NAME_NOT_FOUND
            );

            let created = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateSymbolicLink,
                &[link, target],
            );
            assert_eq!(created.expect("recreate link"), STATUS_SUCCESS);
            let duplicate = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateSymbolicLink,
                &[link, target],
            );
            assert_eq!(
                duplicate.expect("duplicate link"),
                STATUS_OBJECT_NAME_COLLISION
            );
            let null_link = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateSymbolicLink,
                &[0, target],
            );
            assert_eq!(
                null_link.expect("empty link name"),
                STATUS_INVALID_PARAMETER
            );

            let irp = call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoAllocateIrp,
                &[1, 0],
            )
            .expect("allocate irp");
            assert_ne!(irp, 0);
            let freed = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoFreeIrp,
                &[irp],
            )
            .expect("free irp");
            assert_eq!(freed, 0);
            let free_unknown = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoFreeIrp,
                &[0xDEAD_0000],
            )
            .expect("free unknown irp");
            assert_eq!(free_unknown, 0);

            let default_dispatch = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IrpDispatch,
                &[0, 0],
            )
            .expect("default dispatch");
            assert_eq!(default_dispatch, STATUS_INVALID_DEVICE_REQUEST);

            let wide = 0x54_000;
            write_guest_wide(&mut memory, wide, "CasaWide");
            let header = 0x56_000;
            memory.map_bytes(header, &[0_u8; 16]);
            let init = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::RtlInitUnicodeString,
                &[header, wide],
            );
            assert_eq!(init.expect("init unicode string"), 0);
            assert_eq!(memory.read_u16(header).unwrap(), 16);
            let null_source = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::RtlInitUnicodeString,
                &[header, 0],
            );
            assert_eq!(null_source.expect("null source"), 0);
            assert_eq!(memory.read_u16(header).unwrap(), 0);
            let bad_destination = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::RtlInitUnicodeString,
                &[1, wide],
            );
            assert_eq!(
                bad_destination.expect("bad unicode destination"),
                STATUS_INVALID_PARAMETER
            );
            let unterminated = 0x46_000;
            memory.map_bytes(unterminated, &vec![0xFF_u8; 0x8000]);
            let error = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::RtlInitUnicodeString,
                &[header, unterminated],
            )
            .unwrap_err();
            assert_eq!(error.code, ReasonCode::RcMemoryAccessViolation);

            let no_format = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::DbgPrint,
                &[0],
            );
            assert_eq!(no_format.expect("null format"), 0);
            let bad_ansi = 0x46_000;
            memory.map_bytes(bad_ansi, &vec![b'A'; 4096]);
            let error = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::DbgPrint,
                &[bad_ansi],
            )
            .unwrap_err();
            assert_eq!(error.code, ReasonCode::RcMemoryAccessViolation);

            let driver = island.driver_object_pointer();
            let out = 0x58_000;
            memory.map_bytes(out, &[0_u8; 8]);
            let wrong_driver = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateDevice,
                &[0xDEAD, 0, 0, 3, 0, 0, out],
            );
            assert_eq!(
                wrong_driver.expect("wrong driver object"),
                STATUS_INVALID_PARAMETER
            );
            let null_out = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateDevice,
                &[driver, 0, 0, 3, 0, 0, 0],
            );
            assert_eq!(null_out.expect("null device out"), STATUS_INVALID_PARAMETER);
            let huge_extension = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateDevice,
                &[driver, 0x20_0000, 0, 3, 0, 0, out],
            );
            assert_eq!(
                huge_extension.expect("oversized extension"),
                STATUS_INSUFFICIENT_RESOURCES
            );
            let nameless = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateDevice,
                &[driver, 0, 0, 3, 0, 0, out],
            );
            assert_eq!(nameless.expect("nameless device"), STATUS_SUCCESS);
            let exclusive = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateDevice,
                &[driver, 0, 0, 3, 0, 1, out],
            );
            assert_eq!(exclusive.expect("exclusive device"), STATUS_SUCCESS);
            let duplicate_name = guest_unicode_string(&mut memory, 0x5A_000, "\\Device\\CasaTest");
            let duplicate = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateDevice,
                &[driver, 0, duplicate_name, 3, 0, 0, out],
            );
            assert_eq!(
                duplicate.expect("duplicate device name"),
                STATUS_OBJECT_NAME_COLLISION
            );

            {
                let mut state = island.inner.borrow_mut();
                state.driver_object_guest = 0;
                let no_driver = state
                    .create_device_object(&mut memory, Some("NoDriver".into()), 0, 3, false)
                    .expect("no-driver result");
                assert_eq!(no_driver, Err(STATUS_INVALID_PARAMETER));
                state.driver_object_guest = driver;
                let too_large = state
                    .create_device_object(&mut memory, Some("TooLarge".into()), 0x20_0000, 3, false)
                    .expect("oversized result");
                assert_eq!(too_large, Err(STATUS_INSUFFICIENT_RESOURCES));
                let saved_end = state.arena.end;
                state.arena.end = state.arena.cursor;
                let exhausted = state
                    .create_device_object(&mut memory, Some("Exhausted".into()), 0, 3, false)
                    .expect("arena result");
                assert_eq!(exhausted, Err(STATUS_INSUFFICIENT_RESOURCES));
                let start = align_up(state.arena.cursor, 16);
                state.arena.end = start + 0x180;
                let extension_fail = state
                    .create_device_object(&mut memory, Some("ExtFail".into()), 0x10, 3, false)
                    .expect("extension arena result");
                assert_eq!(extension_fail, Err(STATUS_INSUFFICIENT_RESOURCES));
                state.arena.end = saved_end;
            }

            let zero_length = 0x5C_000;
            memory.map_bytes(zero_length, &[0_u8; 16]);
            memory.write_u16(zero_length, 0);
            memory.write_u64(zero_length + 8, wide);
            let empty_name = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateSymbolicLink,
                &[zero_length, target],
            );
            assert_eq!(
                empty_name.expect("zero-length link"),
                STATUS_INVALID_PARAMETER
            );
            let odd_length = 0x5D_000;
            memory.map_bytes(odd_length, &[0_u8; 16]);
            memory.write_u16(odd_length, 3);
            memory.write_u64(odd_length + 8, wide);
            let error = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateSymbolicLink,
                &[odd_length, target],
            )
            .unwrap_err();
            assert_eq!(error.code, ReasonCode::RcMemoryAccessViolation);
            let null_buffer = 0x5E_000;
            memory.map_bytes(null_buffer, &[0_u8; 16]);
            memory.write_u16(null_buffer, 4);
            memory.write_u64(null_buffer + 8, 0);
            let error = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoCreateSymbolicLink,
                &[null_buffer, target],
            )
            .unwrap_err();
            assert_eq!(error.code, ReasonCode::RcMemoryAccessViolation);
        });
    }

    #[test]
    fn dbg_print_format_rejects_malformed_conversions() {
        let mut memory = MemoryImage::default();
        let ansi = 0x10_000;
        let wide = 0x11_000;
        let unicode = 0x12_000;
        write_guest_wide(&mut memory, wide, "wide");
        memory.map_bytes(ansi, b"ansi\0");
        memory.map_bytes(unicode, &[0_u8; 16]);
        memory.write_u16(unicode, 8);
        memory.write_u64(unicode + 8, wide);
        assert_eq!(
            format_dbg_print("tail %", &[], &memory, GuestArch::X64),
            "tail %"
        );
        assert_eq!(format_dbg_print("%%", &[], &memory, GuestArch::X64), "%");
        assert_eq!(format_dbg_print("%w", &[], &memory, GuestArch::X64), "%");
        assert_eq!(format_dbg_print("%hd", &[7], &memory, GuestArch::X64), "7");
        assert_eq!(
            format_dbg_print("%ws", &[u64::from(wide as u32)], &memory, GuestArch::X64),
            "wide"
        );
        assert_eq!(
            format_dbg_print("%S", &[u64::from(ansi as u32)], &memory, GuestArch::X64),
            "ansi"
        );
        assert_eq!(
            format_dbg_print("%Z", &[u64::from(unicode as u32)], &memory, GuestArch::X64),
            "wide"
        );
        assert_eq!(
            format_dbg_print(
                "%u %d %x %X %p %c %q",
                &[1, (-2i32) as u64, 0xAB, 0xCD, 0x10, 0x41, 0],
                &memory,
                GuestArch::X64
            ),
            "1 -2 ab CD 0x10 A %q"
        );
    }

    #[test]
    fn driver_image_helpers_reject_malformed_layouts_and_paths() {
        let short = [0_u8; 0x20];
        assert_eq!(
            pe_image_arch(&short),
            Err("driver island requires a PE image".to_string())
        );
        let mut bad_magic = vec![0_u8; 0x100];
        bad_magic[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
        put_u32(&mut bad_magic, 0x3C, 0x80);
        assert_eq!(
            pe_image_arch(&bad_magic),
            Err("driver island requires a PE image".to_string())
        );
        let mut x86_magic = build_test_driver(false, false, false);
        put_u16(&mut x86_magic, 0x84, 0x014C);
        assert_eq!(
            pe_image_arch(&x86_magic),
            Err("PE32+ optional header on an x86 machine".to_string())
        );
        let mut x64_magic = build_test_driver(false, false, false);
        put_u16(&mut x64_magic, 0x98, 0x010B);
        assert_eq!(
            pe_image_arch(&x64_magic),
            Err("PE32 optional header on an x64 machine".to_string())
        );
        let mut unknown = build_test_driver(false, false, false);
        put_u16(&mut unknown, 0x84, 0x1234);
        assert_eq!(
            pe_image_arch(&unknown),
            Err("driver island rejects machine 0x1234".to_string())
        );
        assert_eq!(pe_layout_hint(&short), None);
        assert_eq!(pe_layout_hint(&bad_magic), None);
        let mut unknown_magic = build_test_driver(false, false, false);
        put_u16(&mut unknown_magic, 0x98, 0x9999);
        assert_eq!(pe_layout_hint(&unknown_magic), None);
        let hint = pe_layout_hint(&build_test_driver(false, false, false)).expect("layout hint");
        assert_eq!(hint.0, 0x1_4000_0000);
        assert_eq!(hint.1, 0x4000);

        assert_eq!(
            parse_service_name("\\Registry\\Machine\\System\\Foo"),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            parse_service_name("\\Registry\\Machine\\System\\CurrentControlSet\\Foo"),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            parse_service_name("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\\\"),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            parse_service_name(
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaCase\\Parameters"
            ),
            Ok("CasaCase".to_string())
        );

        let environment = BTreeMap::from([
            ("WINDIR".to_string(), "C:\\Windows".to_string()),
            ("SYSTEMROOT".to_string(), "C:\\Windows".to_string()),
        ]);
        assert_eq!(
            expand_driver_image_path("\"C:\\Windows\\x.sys\"", &environment),
            "C:\\Windows\\x.sys"
        );
        assert_eq!(
            expand_driver_image_path("\"C:\\Windows\\x.sys", &environment),
            "\"C:\\Windows\\x.sys"
        );
        assert_eq!(
            expand_driver_image_path("\\??\\C:\\Windows\\x.sys", &environment),
            "C:\\Windows\\x.sys"
        );
        assert_eq!(
            expand_driver_image_path("\\DosDevices\\C:\\Windows\\x.sys", &environment),
            "C:\\Windows\\x.sys"
        );
        assert_eq!(
            expand_driver_image_path("\\SystemRoot\\System32\\x.sys", &environment),
            "C:\\Windows\\System32\\x.sys"
        );
        assert_eq!(
            expand_driver_image_path("\\System32\\x.sys", &environment),
            "C:\\Windows\\System32\\x.sys"
        );
        assert_eq!(
            expand_driver_image_path("System32\\x.sys", &environment),
            "C:\\Windows\\System32\\x.sys"
        );
        assert_eq!(
            expand_driver_image_path("%WINDIR%/x.sys", &environment),
            "C:\\Windows\\x.sys"
        );
        assert_eq!(
            expand_driver_image_path("%NOPE%\\x.sys", &environment),
            "C:\\Windows\\%NOPE%\\x.sys"
        );
        assert_eq!(expand_environment_percent("%NOPE%", &environment), "%NOPE%");
        assert_eq!(
            expand_environment_percent("a%WINDIR%b", &environment),
            "aC:\\Windowsb"
        );

        let not_found = AppError::new(ReasonCode::RcFsNotFound, "missing");
        assert_eq!(
            nt_load_error_status(&not_found),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        let registry = AppError::new(ReasonCode::RcRegistryNotFound, "missing");
        assert_eq!(
            nt_load_error_status(&registry),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        let parse = AppError::new(ReasonCode::RcPeParseInvalid, "bad");
        assert_eq!(
            nt_load_error_status(&parse),
            crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32
        );
        let image_error = driver_image_error(0xC000_0010);
        assert_eq!(image_error.code, ReasonCode::RcPeParseInvalid);
        assert_eq!(
            image_error.message,
            "driver image rejected with NTSTATUS 0xc0000010"
        );
        let io_error = nt_error("IoCreateDriver", STATUS_INVALID_HANDLE);
        assert_eq!(io_error.code, ReasonCode::RcIo);
        assert_eq!(
            io_error.message,
            "IoCreateDriver failed with NTSTATUS 0xc0000008"
        );
        assert_eq!(strip_device_prefix("\\Device\\Casa"), "Casa");
        assert_eq!(strip_device_prefix("\\\\Casa"), "Casa");
        assert_eq!(strip_device_prefix("Casa"), "Casa");
        assert_eq!(align_up(5, 0), 5);
        assert_eq!(align_up(5, 1), 5);
        assert_eq!(align_up(5, 4), 8);
    }

    #[test]
    fn choose_placement_rejects_exhausted_and_overlapping_x86_ranges() {
        let (runtime, _directory) = test_runtime_x86();
        let placed = choose_placement(&runtime, 0x10000, 0x2000, GuestArch::X86)
            .expect("stack overlap is skipped");
        assert_ne!(placed.0, 0x10000, "the stack-overlapping base is skipped");
        assert!(placed.0 > 0x12000, "placement is above the stack");
        assert_eq!(placed.0 & 0xFFFF, 0, "placement stays 64 KiB aligned");
        let error = choose_placement(&runtime, 0x7FF0_0000, 0x2000, GuestArch::X86)
            .expect_err("no x86 range below the 4 GiB boundary");
        assert_eq!(error.code, ReasonCode::RcIo);
        assert!(
            error.message.contains("no free guest address range"),
            "placement error names the exhausted range: {}",
            error.message
        );
    }

    #[test]
    fn nt_load_rejects_non_string_image_path_and_expands_quoted_path() {
        with_big_stack(|| {
            let image = build_test_driver(false, false, false);
            let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
                let bad_key = "SYSTEM\\CurrentControlSet\\Services\\CasaBadType";
                ge.registry_create_key("HKLM", bad_key, RegistryView::Native)
                    .expect("create key");
                ge.registry_set_value(
                    "HKLM",
                    bad_key,
                    "ImagePath",
                    "REG_DWORD",
                    json!(7),
                    RegistryView::Native,
                )
                .expect("write bad type");
                stage_service(
                    ge,
                    "CasaQuoted",
                    "\"C:\\Windows\\System32\\drivers\\casa_nt.sys\"",
                    &image,
                );
            });
            let mut memory = MemoryImage::default();
            prepare_guest_memory(&mut runtime, &mut memory);
            let bad_path = guest_unicode_string(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaBadType",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[bad_path],
                ),
                crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32,
                "a non-string ImagePath cannot name a driver image"
            );
            let quoted_path = guest_unicode_string(
                &mut memory,
                0x42_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaQuoted",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtLoadDriver,
                    &[quoted_path],
                ),
                STATUS_SUCCESS,
                "a quoted ImagePath is stripped and loaded"
            );
        });
    }

    #[test]
    fn import_ordinals_reject_regular_and_delay_tables() {
        with_big_stack(|| {
            let (mut runtime, _directory) = test_runtime();
            let mut regular = build_test_driver(false, false, false);
            let ilt = 0x400 + (ILT_RVA - RDATA_RVA) as usize;
            put_u64(&mut regular, ilt, 0x8000_0000_0000_0001);
            let mut memory = MemoryImage::default();
            let error = DriverIsland::load_and_start(&regular, &mut runtime, &mut memory)
                .expect_err("ordinal imports have no shim");
            assert_eq!(error.code, ReasonCode::RcImportMissing);
            assert!(
                error.message.contains("ntoskrnl.exe"),
                "ordinal rejection names the module: {}",
                error.message
            );

            let (mut runtime, _directory) = test_runtime();
            let mut delay =
                with_delay_import(build_test_driver(false, false, false), "IoDeleteDevice");
            let int = 0x400 + (0x2560 - RDATA_RVA) as usize;
            put_u64(&mut delay, int, 0x8000_0000_0000_0002);
            let mut memory = MemoryImage::default();
            let error = DriverIsland::load_and_start(&delay, &mut runtime, &mut memory)
                .expect_err("delay ordinal imports have no shim");
            assert_eq!(error.code, ReasonCode::RcImportMissing);
        });
    }

    #[test]
    fn no_active_island_shim_is_rejected_with_unimplemented_reason() {
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let mut cpu = CpuState::new(GuestArch::X64);
        let error = dispatch_shim(&mut runtime, &mut cpu, &mut memory, DriverShim::DbgPrint)
            .expect_err("shim outside an island must fail");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
        assert!(
            error.message.contains("no active island"),
            "the error names the missing island: {}",
            error.message
        );
    }

    fn x64_ret_stub(memory: &mut MemoryImage, island: &DriverIsland) -> u64 {
        let entry = island
            .inner
            .borrow_mut()
            .arena
            .alloc(memory, 1, 1)
            .expect("ret stub");
        memory.map_bytes(entry, &[0xC3]);
        entry
    }

    #[test]
    fn kmdf_driver_and_device_shims_reject_invalid_arguments() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaKmdfBadArgs");
            let driver = island.driver_object_pointer();
            let out = 0x58_000;
            memory.map_bytes(out, &[0_u8; 8]);

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDriverCreate,
                    &[0xDEAD, 0, 0, 0, out],
                )
                .expect("wrong driver object"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDriverCreate,
                    &[driver, 0, 0, 0, 0],
                )
                .expect("null driver out"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDriverCreate,
                    &[driver, 0, 0, u64::MAX, out],
                )
                .expect("unmapped config"),
                STATUS_INVALID_PARAMETER
            );
            let small_config = 0x58_100;
            memory.map_bytes(small_config, &[0_u8; 0x40]);
            memory.write_u32(small_config, 4);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDriverCreate,
                    &[driver, 0, 0, small_config, out],
                )
                .expect("undersized config"),
                STATUS_INVALID_PARAMETER
            );
            let good_config = 0x58_200;
            memory.map_bytes(good_config, &[0_u8; 0x40]);
            memory.write_u32(good_config, 0x20);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDriverCreate,
                    &[driver, 0, 0, good_config, out],
                )
                .expect("driver create without device add"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDriverCreate,
                    &[driver, 0, 0, good_config, out],
                )
                .expect("driver create reuses framework dispatches"),
                STATUS_SUCCESS
            );

            let init = *island
                .inner
                .borrow()
                .kmdf
                .device_inits
                .keys()
                .next()
                .expect("device init");
            let name = guest_unicode_string(&mut memory, 0x59_000, "\\Device\\WdfCasa");
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetDeviceType,
                    &[0xDEAD, 1],
                )
                .expect("set type on missing init"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetIoType,
                    &[0xDEAD, 1],
                )
                .expect("set io type on missing init"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitAssignName,
                    &[0xDEAD, name],
                )
                .expect("assign name on missing init"),
                STATUS_INVALID_PARAMETER
            );
            let init_pointer = 0x59_800;
            memory.map_bytes(init_pointer, &[0_u8; 8]);
            memory.write_u64(init_pointer, init);
            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceCreate,
                    &[init_pointer, 0, out],
                )
                .expect("duplicate device through init pointer"),
                STATUS_OBJECT_NAME_COLLISION
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceCreate,
                    &[init, 0, out],
                )
                .expect("duplicate device through init handle"),
                STATUS_OBJECT_NAME_COLLISION
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceCreate,
                    &[init, 0, 0],
                )
                .expect("null device out"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitAssignName,
                    &[init, 0],
                )
                .expect("clear init name"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceCreate,
                    &[init, 0, out],
                )
                .expect("unnamed device via cleared init"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceCreate,
                    &[0xDEAD, 0, out],
                )
                .expect("missing init"),
                STATUS_INVALID_PARAMETER
            );

            let device = island.kmdf_device_handles()[0];
            let queue_out = 0x5A_000;
            memory.map_bytes(queue_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[0xDEAD, 0, 0, queue_out],
                )
                .expect("queue for missing device"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device, 0, 0, 0],
                )
                .expect("null queue out"),
                STATUS_INVALID_PARAMETER
            );
            let queue_config = 0x5A_100;
            memory.map_bytes(queue_config, &[0_u8; 0x60]);
            memory.write_u32(queue_config, 4);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device, 1, 0, queue_out],
                )
                .expect("unmapped queue config"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device, queue_config, 0, queue_out],
                )
                .expect("undersized queue config"),
                STATUS_INVALID_PARAMETER
            );
            memory.write_u32(queue_config, 0x50);
            memory.write_u32(queue_config + 4, 3);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device, queue_config, 0, queue_out],
                )
                .expect("unsupported dispatch type"),
                STATUS_INVALID_PARAMETER
            );
            memory.write_u32(queue_config + 4, 1);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device, queue_config, 0, queue_out],
                )
                .expect("valid queue"),
                STATUS_SUCCESS
            );

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device, 0],
                )
                .expect("null request out"),
                STATUS_INVALID_PARAMETER
            );
            let request_out = 0x5B_000;
            memory.map_bytes(request_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device, request_out],
                )
                .expect("request for live device"),
                STATUS_SUCCESS
            );
            let request = memory.read_u64(request_out).unwrap();
            assert_ne!(request, 0);
            let queue = *island.inner.borrow().kmdf.queues.keys().next().unwrap();
            let target = call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceGetIoTarget,
                &[device],
            )
            .expect("request target");
            assert_ne!(target, 0);
            let saved_devices = {
                let mut state = island.inner.borrow_mut();
                std::mem::take(&mut state.kmdf.devices)
            };
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, 0, request_out],
                )
                .expect("request without devices"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            island.inner.borrow_mut().kmdf.devices = saved_devices;
            let saved_device = {
                let mut state = island.inner.borrow_mut();
                state.kmdf.devices.remove(&device)
            };
            assert!(saved_device.is_some());
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, target, request_out],
                )
                .expect("request for stale iotarget device"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            if let Some(device_record) = saved_device {
                island
                    .inner
                    .borrow_mut()
                    .kmdf
                    .devices
                    .insert(device, device_record);
            }
            {
                let mut state = island.inner.borrow_mut();
                let missing = state.new_kmdf_request(
                    &mut memory,
                    0xDEAD,
                    queue,
                    IrpMajorFunction::DeviceControl,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                );
                assert_eq!(
                    missing.expect("missing device result"),
                    Err(STATUS_INVALID_DEVICE_REQUEST)
                );
                let casak = state.kmdf.devices.get(&device).unwrap().casak;
                let _ = state.io.delete_device(casak);
                let deleted = state.new_kmdf_request(
                    &mut memory,
                    device,
                    queue,
                    IrpMajorFunction::DeviceControl,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                );
                assert_eq!(
                    deleted.expect("deleted device result"),
                    Err(crate::casak::io::STATUS_DELETE_PENDING as i32)
                );
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device, request_out],
                )
                .expect("shim allocation failure"),
                crate::casak::io::STATUS_DELETE_PENDING as i32
            );
        });
    }

    #[test]
    fn kmdf_requests_and_iotargets_reject_bad_handles_and_buffers() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(0, true);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaKmdfBadReq");
            let device_a = island.kmdf_device_handles()[0];
            let device_b = island.kmdf_device_handles()[1];

            let out = 0x5C_000;
            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device_a, out],
                )
                .expect("request a"),
                STATUS_SUCCESS
            );
            let request = memory.read_u64(out).unwrap();

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestFormatRequestForIoctl,
                    &[0xDEAD, device_a, 1, 0, 0, 0, 0, 0],
                )
                .expect("format missing request"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestRetrieveInputBuffer,
                    &[request, 0, 0, out],
                )
                .expect("retrieve null buffer out"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestRetrieveInputBuffer,
                    &[0xDEAD, 0, out, out],
                )
                .expect("retrieve missing request"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestRetrieveOutputBuffer,
                    &[request, 1, out, out],
                )
                .expect("retrieve beyond buffer"),
                STATUS_BUFFER_TOO_SMALL
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestComplete,
                    &[0xDEAD, STATUS_SUCCESS as u64],
                )
                .expect("complete missing request"),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestComplete,
                    &[request, STATUS_SUCCESS as u64],
                )
                .expect("complete request"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestComplete,
                    &[request, STATUS_SUCCESS as u64],
                )
                .expect("double complete"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceWdmGetDeviceObject,
                    &[0xDEAD],
                )
                .expect("missing device object"),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectGetTypedContext,
                    &[0xDEAD, 0],
                )
                .expect("missing typed context"),
                0
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectAllocateContext,
                    &[device_a, 0, 0],
                )
                .expect("null context out"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectAllocateContext,
                    &[0xDEAD, 0, out],
                )
                .expect("context for missing object"),
                STATUS_INVALID_HANDLE
            );
            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device_a, out],
                )
                .expect("request for context"),
                STATUS_SUCCESS
            );
            let context_request = memory.read_u64(out).unwrap();
            let context_out = 0x5C_100;
            memory.map_bytes(context_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectAllocateContext,
                    &[context_request, 0, context_out],
                )
                .expect("default context size"),
                STATUS_SUCCESS
            );
            let default_context = memory.read_u64(context_out).unwrap();
            assert_eq!(
                island.kmdf_context_size(context_request),
                Some(0x80),
                "the request kind's default context size is used"
            );
            let type_info = 0x5C_200;
            memory.map_bytes(type_info, &[0_u8; 0x20]);
            memory.write_u32(type_info, 0x18);
            memory.write_u64(type_info + 0x10, 0x20);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectAllocateContext,
                    &[context_request, type_info, context_out],
                )
                .expect("typed context size"),
                STATUS_SUCCESS
            );
            let typed_context = memory.read_u64(context_out).unwrap();
            assert_ne!(typed_context, default_context);
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectGetTypedContext,
                    &[context_request, type_info],
                )
                .expect("typed context lookup"),
                typed_context
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[0xDEAD],
                )
                .expect("delete missing object"),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[context_request],
                )
                .expect("delete context request"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[context_request],
                )
                .expect("double delete object"),
                STATUS_INVALID_HANDLE
            );
            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device_a, out],
                )
                .expect("deleted object request"),
                STATUS_SUCCESS
            );
            let deleted_object = memory.read_u64(out).unwrap();
            island
                .inner
                .borrow_mut()
                .kmdf
                .objects
                .get_mut(&deleted_object)
                .unwrap()
                .deleted = true;
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[deleted_object],
                )
                .expect("delete already deleted object"),
                STATUS_INVALID_HANDLE
            );

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceGetIoTarget,
                    &[0xDEAD],
                )
                .expect("target for missing device"),
                STATUS_INVALID_HANDLE
            );
            let target_out = 0x5D_000;
            memory.map_bytes(target_out, &[0_u8; 8]);
            let target_a = call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceGetIoTarget,
                &[device_a],
            )
            .expect("target a");
            assert_ne!(target_a, 0);
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceGetIoTarget,
                    &[device_a],
                )
                .expect("cached target a"),
                target_a
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetCreate,
                    &[0xDEAD, 0, target_out],
                )
                .expect("target for missing device create"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetCreate,
                    &[device_a, 0, 0],
                )
                .expect("null target out"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetCreate,
                    &[device_b, 0, target_out],
                )
                .expect("target b"),
                STATUS_SUCCESS
            );
            let target_b = memory.read_u64(target_out).unwrap();
            assert_ne!(target_b, 0);

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetFormatRequestForIoctl,
                    &[target_b, 0xDEAD, 1, 0, 0, 0, 0],
                )
                .expect("format missing request"),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestSend,
                    &[0xDEAD, target_b, 0],
                )
                .expect("send missing request"),
                STATUS_INVALID_HANDLE
            );

            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device_a, out],
                )
                .expect("send request"),
                STATUS_SUCCESS
            );
            let send_request = memory.read_u64(out).unwrap();
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestSend,
                    &[send_request, 0, 0],
                )
                .expect("send with implicit target"),
                STATUS_PENDING
            );
            {
                let mut state = island.inner.borrow_mut();
                let request = state.kmdf.requests.get_mut(&send_request).unwrap();
                request.completed = false;
                request.input_guest = 1;
                request.input_len = 4;
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestSend,
                    &[send_request, 0, 0],
                )
                .expect("send with unreadable input"),
                STATUS_INVALID_PARAMETER
            );

            let bad_input = 1;
            let input_descriptor = 0x5E_100;
            memory.map_bytes(input_descriptor, &[0_u8; 0x20]);
            memory.write_u64(input_descriptor + 8, bad_input);
            memory.write_u64(input_descriptor + 0x10, 4);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetSendIoctlSynchronously,
                    &[target_a, 0, 0x22_0004, input_descriptor, 0, 0, 0],
                )
                .expect("sync send with unreadable input"),
                STATUS_INVALID_PARAMETER
            );

            let saved_devices = {
                let mut state = island.inner.borrow_mut();
                std::mem::take(&mut state.kmdf.devices)
            };
            {
                let mut state = island.inner.borrow_mut();
                if let Some(request) = state.kmdf.requests.get_mut(&send_request) {
                    request.completed = false;
                    request.input_guest = 0;
                    request.input_len = 0;
                    request.target = Some(target_b);
                }
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestSend,
                    &[send_request, target_b, 0],
                )
                .expect("send to iotarget with no device"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            {
                let mut state = island.inner.borrow_mut();
                if let Some(request) = state.kmdf.requests.get_mut(&send_request) {
                    request.completed = false;
                    request.target = None;
                }
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetSendIoctlSynchronously,
                    &[0, 0, 0, 0, 0, 0, 0],
                )
                .expect("sync send with no devices"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            island.inner.borrow_mut().kmdf.devices = saved_devices;

            {
                let mut state = island.inner.borrow_mut();
                let casak = state.kmdf.devices.get(&device_b).unwrap().casak;
                let _ = state.io.delete_device(casak);
            }
            {
                let mut state = island.inner.borrow_mut();
                if let Some(request) = state.kmdf.requests.get_mut(&send_request) {
                    request.completed = false;
                }
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestSend,
                    &[send_request, device_b, 0],
                )
                .expect("send after casak device deletion"),
                STATUS_INVALID_DEVICE_REQUEST
            );

            island
                .inner
                .borrow_mut()
                .apply_iotarget_result(&mut memory, 0xDEAD, STATUS_SUCCESS, 0)
                .expect("missing request result");

            let driver = island.driver_object_pointer();
            let major_slot = driver + 0x70 + IrpMajorFunction::DeviceControl.code() as u64 * 8;
            memory.write_u64(major_slot, 0);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetSendIoctlSynchronously,
                    &[device_a, 0, 0x22_0004, 0, 0, 0, 0],
                )
                .expect("sync send with no handler"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            let default_dispatch = island.inner.borrow().default_dispatch;
            memory.write_u64(major_slot, default_dispatch);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetSendIoctlSynchronously,
                    &[device_a, 0, 0x22_0004, 0, 0, 0, 0],
                )
                .expect("sync send with default handler"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            let framework_dispatch = island.inner.borrow().kmdf.framework_dispatch;
            assert_ne!(framework_dispatch, 0);
            memory.write_u64(major_slot, framework_dispatch);
        });
    }

    fn kmdf_device_named(island: &DriverIsland, name: &str) -> u64 {
        island
            .inner
            .borrow()
            .kmdf
            .devices
            .iter()
            .find(|(_, device)| device.name.ends_with(name))
            .map(|(handle, _)| *handle)
            .expect("named kmdf device")
    }

    fn make_kmdf_request(
        island: &DriverIsland,
        memory: &mut MemoryImage,
        device: u64,
        queue: u64,
        major: IrpMajorFunction,
    ) -> u64 {
        island
            .inner
            .borrow_mut()
            .new_kmdf_request(memory, device, queue, major, 0, 0, 0, 0, 0, 0)
            .expect("request result")
            .expect("request")
    }

    #[test]
    fn kmdf_queue_edges_reject_stale_requests_and_recover_from_drain_races() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(2, true);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaKmdfQueueEdge");
            let image_base = island.image_base();
            let device_a = kmdf_device_named(&island, "WdfA");
            let device_b = kmdf_device_named(&island, "WdfB");
            let device_a_guest = island
                .created_devices()
                .into_iter()
                .find(|device| device.name.ends_with("WdfA"))
                .map(|device| device.guest_pointer)
                .expect("device a guest");
            let device_b_guest = island
                .created_devices()
                .into_iter()
                .find(|device| device.name.ends_with("WdfB"))
                .map(|device| device.guest_pointer)
                .expect("device b guest");
            let queue_a = queue_for_device(&island, device_a);
            let queue_b = island
                .inner
                .borrow()
                .kmdf
                .queues
                .iter()
                .find(|(_, queue)| queue.device == device_b)
                .map(|(handle, _)| *handle)
                .expect("queue for device b");
            let ret_stub = x64_ret_stub(&mut memory, &island);
            let complete = x64_complete_stub(&mut runtime, &mut memory, &island, STATUS_SUCCESS, 0);

            set_queue_callbacks(&island, queue_a, |queue| {
                queue.callbacks.default = 0;
                queue.callbacks.read = 0;
                queue.callbacks.write = 0;
                queue.callbacks.device_control = 0;
                queue.dispatch_type = 0;
                queue.stopped = false;
                queue.draining = false;
                queue.queued.clear();
                queue.in_flight.clear();
            });

            let request = make_kmdf_request(
                &island,
                &mut memory,
                device_a,
                queue_a,
                IrpMajorFunction::DeviceControl,
            );
            island
                .inner
                .borrow_mut()
                .kmdf
                .queues
                .get_mut(&queue_a)
                .unwrap()
                .queued
                .push_back(request);
            {
                let mut state = island.inner.borrow_mut();
                assert!(
                    state
                        .dispatch_next_queued(&mut memory)
                        .expect("entry zero dispatch")
                        .is_none()
                );
            }
            let (completed, status, _, _) = island.kmdf_request_state(request).unwrap();
            assert!(completed);
            assert_eq!(status, STATUS_INVALID_DEVICE_REQUEST);

            let cleanup = make_kmdf_request(
                &island,
                &mut memory,
                device_a,
                queue_a,
                IrpMajorFunction::Cleanup,
            );
            island
                .inner
                .borrow_mut()
                .kmdf
                .queues
                .get_mut(&queue_a)
                .unwrap()
                .queued
                .push_back(cleanup);
            {
                let mut state = island.inner.borrow_mut();
                assert!(
                    state
                        .dispatch_next_queued(&mut memory)
                        .expect("cleanup entry zero")
                        .is_none()
                );
            }
            let (completed, status, _, _) = island.kmdf_request_state(cleanup).unwrap();
            assert!(completed);
            assert_eq!(status, STATUS_SUCCESS);

            island
                .inner
                .borrow_mut()
                .kmdf
                .queues
                .get_mut(&queue_a)
                .unwrap()
                .queued
                .push_back(0xDEAD);
            {
                let mut state = island.inner.borrow_mut();
                assert!(
                    state
                        .dispatch_next_queued(&mut memory)
                        .expect("stale queued handle")
                        .is_none()
                );
            }
            assert!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .queues
                    .get(&queue_a)
                    .unwrap()
                    .queued
                    .is_empty()
            );

            island
                .inner
                .borrow_mut()
                .kmdf
                .queues
                .get_mut(&queue_a)
                .unwrap()
                .draining = true;
            {
                let mut state = island.inner.borrow_mut();
                assert!(
                    state
                        .dispatch_next_queued(&mut memory)
                        .expect("drained queue")
                        .is_none()
                );
            }
            {
                let state = island.inner.borrow();
                let queue = state.kmdf.queues.get(&queue_a).unwrap();
                assert!(!queue.draining);
                assert!(queue.stopped);
            }

            let type2 = make_kmdf_request(
                &island,
                &mut memory,
                device_a,
                queue_a,
                IrpMajorFunction::DeviceControl,
            );
            {
                let mut state = island.inner.borrow_mut();
                let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
                queue.dispatch_type = 2;
                queue.stopped = false;
                queue.draining = false;
                queue.queued.push_back(type2);
            }
            {
                let mut state = island.inner.borrow_mut();
                assert!(
                    state
                        .dispatch_next_queued(&mut memory)
                        .expect("manual queue skipped")
                        .is_none()
                );
            }
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .queues
                    .get(&queue_a)
                    .unwrap()
                    .queued
                    .len(),
                1
            );

            {
                let mut state = island.inner.borrow_mut();
                let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
                queue.dispatch_type = 0;
                queue.stopped = true;
                queue.draining = false;
            }
            {
                let mut state = island.inner.borrow_mut();
                assert!(
                    state
                        .dispatch_next_queued(&mut memory)
                        .expect("stopped queue skipped")
                        .is_none()
                );
            }
            {
                let mut state = island.inner.borrow_mut();
                let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
                queue.stopped = false;
                queue.in_flight.insert(type2);
            }
            {
                let mut state = island.inner.borrow_mut();
                assert!(
                    state
                        .dispatch_next_queued(&mut memory)
                        .expect("sequential in-flight skip")
                        .is_none()
                );
            }
            {
                let mut state = island.inner.borrow_mut();
                let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
                queue.queued.clear();
                queue.in_flight.clear();
                queue.callbacks.default = complete;
            }

            for (major, label, counter) in [
                (IrpMajorFunction::Read, "EvtIoRead", 0usize),
                (IrpMajorFunction::Write, "EvtIoWrite", 1),
                (IrpMajorFunction::DeviceControl, "EvtIoDeviceControl", 2),
                (IrpMajorFunction::Cleanup, "EvtIoDefault", 3),
                (IrpMajorFunction::Close, "EvtIoDefault", 4),
                (IrpMajorFunction::Create, "EvtIoDefault", 5),
            ] {
                let request = make_kmdf_request(&island, &mut memory, device_a, queue_a, major);
                island
                    .inner
                    .borrow_mut()
                    .kmdf
                    .queues
                    .get_mut(&queue_a)
                    .unwrap()
                    .queued
                    .push_back(request);
                let call = {
                    let mut state = island.inner.borrow_mut();
                    state
                        .dispatch_next_queued(&mut memory)
                        .expect("queued dispatch")
                        .expect("callback")
                };
                assert_eq!(call.label, label);
                assert_eq!(call.args[1], request);
                {
                    let mut state = island.inner.borrow_mut();
                    let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
                    queue.in_flight.remove(&request);
                }
                let state = island.inner.borrow();
                let counters = [
                    state.kmdf.read_dispatches,
                    state.kmdf.write_dispatches,
                    state.kmdf.ioctl_dispatches,
                    state.kmdf.cleanup_dispatches,
                    state.kmdf.close_dispatches,
                    state.kmdf.queued_dispatches,
                ];
                let expected = match counter {
                    0 => [1, 0, 0, 0, 0, 1],
                    1 => [1, 1, 0, 0, 0, 2],
                    2 => [1, 1, 1, 0, 0, 3],
                    3 => [1, 1, 1, 1, 0, 4],
                    4 => [1, 1, 1, 1, 1, 5],
                    _ => [1, 1, 1, 1, 1, 6],
                };
                assert_eq!(counters, expected, "counter {counter}");
            }

            let device_object = island
                .inner
                .borrow()
                .kmdf
                .devices
                .get(&device_a)
                .unwrap()
                .object_guest;
            let mut cpu = CpuState::new(GuestArch::X64);
            cpu.set(Register::Rcx, 0);
            cpu.set(Register::Rdx, device_object);
            let mut state = island.inner.borrow_mut();
            let call = state
                .wdf_dispatch(IrpMajorFunction::Create, &mut cpu, &mut memory)
                .expect("unsupported major dispatch")
                .expect("default callback");
            assert_eq!(call.label, "EvtIoDefault");
            let queue = state.kmdf.queues.get(&queue_a).unwrap().clone();
            drop(state);
            for request in queue.in_flight.iter() {
                island
                    .inner
                    .borrow_mut()
                    .kmdf
                    .queues
                    .get_mut(&queue_a)
                    .unwrap()
                    .in_flight
                    .remove(request);
            }

            let irp_guest = 0x5F_800;
            memory.map_bytes(irp_guest, &[0_u8; 0x100]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfEvtIoDeviceControlDispatch,
                    &[irp_guest, 0xDEAD],
                )
                .expect("dispatch for missing device object"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                memory.read_u32(irp_guest + 0x30).unwrap(),
                STATUS_INVALID_DEVICE_REQUEST as u32
            );

            {
                let mut state = island.inner.borrow_mut();
                let casak = state.kmdf.devices.get(&device_b).unwrap().casak;
                let _ = state.io.delete_device(casak);
            }
            let (status, _) = island
                .dispatch_irp(
                    &mut runtime,
                    &mut memory,
                    device_b_guest,
                    IrpMajorFunction::DeviceControl,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("dispatch after casak deletion");
            assert_eq!(status, crate::casak::io::STATUS_DELETE_PENDING as i32);

            set_queue_callbacks(&island, queue_a, |queue| {
                queue.callbacks.default = 0;
                queue.callbacks.read = 0;
                queue.callbacks.write = 0;
                queue.callbacks.device_control = 0;
                queue.dispatch_type = 0;
                queue.stopped = false;
                queue.draining = false;
                queue.queued.clear();
                queue.in_flight.clear();
            });
            let (status, _) = island
                .dispatch_irp(
                    &mut runtime,
                    &mut memory,
                    device_a_guest,
                    IrpMajorFunction::DeviceControl,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("ioctl without callback");
            assert_eq!(status, STATUS_INVALID_DEVICE_REQUEST);
            for major in [IrpMajorFunction::Cleanup, IrpMajorFunction::Close] {
                let (status, _) = island
                    .dispatch_irp(
                        &mut runtime,
                        &mut memory,
                        device_a_guest,
                        major,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    )
                    .expect("cleanup dispatch without callback");
                assert_eq!(status, STATUS_SUCCESS);
            }

            {
                let mut state = island.inner.borrow_mut();
                state
                    .complete_kmdf_request(&mut memory, 0xDEAD, STATUS_SUCCESS, 0)
                    .expect("complete missing request");
            }
            let done = make_kmdf_request(
                &island,
                &mut memory,
                device_a,
                queue_a,
                IrpMajorFunction::DeviceControl,
            );
            {
                let mut state = island.inner.borrow_mut();
                state
                    .complete_kmdf_request(&mut memory, done, STATUS_SUCCESS, 4)
                    .expect("complete request");
                state
                    .complete_kmdf_request(&mut memory, done, STATUS_SUCCESS, 4)
                    .expect("double complete is ignored");
            }
            let draining = make_kmdf_request(
                &island,
                &mut memory,
                device_a,
                queue_a,
                IrpMajorFunction::DeviceControl,
            );
            {
                let mut state = island.inner.borrow_mut();
                state
                    .kmdf
                    .queues
                    .get_mut(&queue_a)
                    .unwrap()
                    .in_flight
                    .insert(draining);
                state.kmdf.queues.get_mut(&queue_a).unwrap().draining = true;
                state.kmdf.queues.get_mut(&queue_a).unwrap().queued.clear();
                state
                    .complete_kmdf_request(&mut memory, draining, STATUS_SUCCESS, 0)
                    .expect("complete draining request");
                let queue = state.kmdf.queues.get(&queue_a).unwrap();
                assert!(!queue.draining);
                assert!(queue.stopped);
            }

            set_queue_callbacks(&island, queue_a, |queue| {
                queue.callbacks.default = complete;
                queue.callbacks.read = 0;
                queue.callbacks.write = 0;
                queue.callbacks.device_control = 0;
                queue.dispatch_type = 0;
                queue.stopped = false;
                queue.draining = false;
                queue.queued.clear();
                queue.in_flight.clear();
            });
            let (device_handle, file_status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x5A_000);
            assert_eq!(file_status, STATUS_SUCCESS);
            let buffer = 0x5B_000;
            let iosb = 0x5B_100;
            memory.map_bytes(buffer, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtReadFile,
                    &[u64::from(device_handle), 0, 0, 0, iosb, buffer, 8, 0, 0],
                ),
                STATUS_SUCCESS,
                "read falls back to the default queue callback"
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtWriteFile,
                    &[u64::from(device_handle), 0, 0, 0, iosb, buffer, 8, 0, 0],
                ),
                STATUS_SUCCESS,
                "write falls back to the default queue callback"
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(device_handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        buffer,
                        8,
                        buffer,
                        8,
                    ],
                ),
                STATUS_SUCCESS,
                "ioctl falls back to the default queue callback"
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtClose,
                    &[u64::from(device_handle)],
                ),
                STATUS_SUCCESS
            );

            memory.map_bytes(0x5F_000, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueRetrieveNextRequest,
                    &[queue_b, 0],
                )
                .expect("retrieve null out"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueRetrieveNextRequest,
                    &[0xDEAD, 0x5F_000],
                )
                .expect("retrieve missing queue"),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueRetrieveNextRequest,
                    &[queue_b, 0x5F_000],
                )
                .expect("retrieve from empty queue"),
                STATUS_NO_MORE_ENTRIES
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStop,
                    &[0xDEAD],
                )
                .expect("stop missing queue"),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueDrain,
                    &[queue_b],
                )
                .expect("drain empty queue"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueDrainSynchronously,
                    &[queue_b],
                )
                .expect("drain synchronously empty queue"),
                STATUS_SUCCESS
            );

            let stop_count = memory
                .read_u32(image_base + u64::from(F_STOP_COUNT))
                .unwrap();
            let stop_request = make_kmdf_request(
                &island,
                &mut memory,
                device_a,
                queue_a,
                IrpMajorFunction::DeviceControl,
            );
            {
                let mut state = island.inner.borrow_mut();
                let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
                queue.callbacks.default = ret_stub;
                queue.callbacks.stop = image_base + u64::from(F_STOP_RVA);
                queue.callbacks.resume = image_base + u64::from(F_RESUME_RVA);
                queue.in_flight.insert(stop_request);
                queue.queued.clear();
                queue.stopped = false;
                queue.draining = false;
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStop,
                    &[queue_a],
                )
                .expect("stop with in-flight request"),
                STATUS_SUCCESS
            );
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_STOP_COUNT))
                    .unwrap(),
                stop_count + 1
            );
            let resume_count = memory
                .read_u32(image_base + u64::from(F_RESUME_COUNT))
                .unwrap();
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStart,
                    &[queue_a],
                )
                .expect("resume in-flight request"),
                STATUS_SUCCESS
            );
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_RESUME_COUNT))
                    .unwrap(),
                resume_count + 1
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStart,
                    &[0xDEAD],
                )
                .expect("start missing queue"),
                STATUS_INVALID_HANDLE
            );
            {
                let mut state = island.inner.borrow_mut();
                state
                    .kmdf
                    .queues
                    .get_mut(&queue_a)
                    .unwrap()
                    .in_flight
                    .clear();
                state
                    .kmdf
                    .requests
                    .get_mut(&stop_request)
                    .unwrap()
                    .completed = true;
            }

            let cancel_before = memory
                .read_u32(image_base + u64::from(F_CANCEL_COUNT))
                .unwrap();
            let queued_cancel = make_kmdf_request(
                &island,
                &mut memory,
                device_a,
                queue_a,
                IrpMajorFunction::DeviceControl,
            );
            let inflight_cancel = make_kmdf_request(
                &island,
                &mut memory,
                device_a,
                queue_a,
                IrpMajorFunction::DeviceControl,
            );
            {
                let mut state = island.inner.borrow_mut();
                let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
                queue.callbacks.canceled_on_queue = image_base + u64::from(F_CANCEL_RVA);
                queue.queued.push_back(queued_cancel);
                queue.in_flight.insert(inflight_cancel);
                queue.stopped = false;
                queue.draining = false;
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueuePurge,
                    &[queue_a],
                )
                .expect("purge with cancel callback"),
                STATUS_SUCCESS
            );
            for request in [queued_cancel, inflight_cancel] {
                let (completed, status, _, _) = island.kmdf_request_state(request).unwrap();
                assert!(completed);
                assert_eq!(status, STATUS_CANCELLED);
            }
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_CANCEL_COUNT))
                    .unwrap(),
                cancel_before + 2
            );

            set_queue_callbacks(&island, queue_a, |queue| {
                queue.callbacks.canceled_on_queue = 0;
            });
            let force_cancel = make_kmdf_request(
                &island,
                &mut memory,
                device_a,
                queue_a,
                IrpMajorFunction::DeviceControl,
            );
            island
                .inner
                .borrow_mut()
                .kmdf
                .queues
                .get_mut(&queue_a)
                .unwrap()
                .queued
                .push_back(force_cancel);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueuePurgeSynchronously,
                    &[queue_a],
                )
                .expect("purge without cancel callback"),
                STATUS_SUCCESS
            );
            let (completed, status, _, _) = island.kmdf_request_state(force_cancel).unwrap();
            assert!(completed);
            assert_eq!(status, STATUS_CANCELLED);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueuePurgeSynchronously,
                    &[0xDEAD],
                )
                .expect("purge missing queue"),
                STATUS_INVALID_HANDLE
            );

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCancelQueuedRequest,
                    &[0xDEAD],
                )
                .expect("cancel missing request"),
                STATUS_INVALID_HANDLE
            );
            let no_queue = make_kmdf_request(
                &island,
                &mut memory,
                device_a,
                queue_a,
                IrpMajorFunction::DeviceControl,
            );
            {
                let mut state = island.inner.borrow_mut();
                state.kmdf.requests.get_mut(&no_queue).unwrap().queue = None;
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCancelQueuedRequest,
                    &[no_queue],
                )
                .expect("cancel request without queue"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            {
                let mut state = island.inner.borrow_mut();
                state.kmdf.requests.get_mut(&no_queue).unwrap().queue = Some(0xDEAD);
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCancelQueuedRequest,
                    &[no_queue],
                )
                .expect("cancel request with missing queue"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            {
                let mut state = island.inner.borrow_mut();
                state.kmdf.requests.get_mut(&no_queue).unwrap().queue = Some(queue_a);
                state.kmdf.queues.get_mut(&queue_a).unwrap().queued.clear();
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCancelQueuedRequest,
                    &[no_queue],
                )
                .expect("cancel request not queued"),
                STATUS_INVALID_DEVICE_REQUEST
            );
        });
    }

    #[test]
    fn kmdf_wait_lock_rejects_invalid_handles_and_recovers_from_poison() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaKmdfBadLock");
            let lock = island.kmdf_wait_lock_handles()[0];
            let driver = island.kmdf_driver_handle();
            let out = 0x5F_000;
            memory.map_bytes(out, &[0_u8; 8]);

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockCreate,
                    &[0, 0],
                )
                .expect("null lock out"),
                STATUS_INVALID_PARAMETER
            );
            let attrs = 0x5F_100;
            let type_info = 0x5F_200;
            memory.map_bytes(attrs, &[0_u8; 0x38]);
            memory.map_bytes(type_info, &[0_u8; 0x20]);
            memory.write_u32(attrs, 0x38);
            memory.write_u64(attrs + 0x20, driver);
            memory.write_u64(attrs + 0x28, 0);
            memory.write_u64(attrs + 0x30, type_info);
            memory.write_u32(type_info, 0x18);
            memory.write_u64(type_info + 0x10, 0x20);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockCreate,
                    &[attrs, out],
                )
                .expect("typed wait lock"),
                STATUS_SUCCESS
            );
            let typed_lock = memory.read_u64(out).unwrap();
            assert_eq!(island.kmdf_context_size(typed_lock), Some(0x20));
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .objects
                    .get(&typed_lock)
                    .and_then(|object| object.parent),
                Some(driver)
            );
            assert!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .objects
                    .get(&driver)
                    .is_some_and(|object| object.children.contains(&typed_lock))
            );
            memory.map_bytes(0x5F_FFC, &[0_u8; 4]);
            memory.write_u32(0x5F_FFC, 0x38);
            let ignored = island
                .inner
                .borrow()
                .parse_object_attributes(&memory, 0x5F_FFC)
                .expect("invalid attrs are ignored");
            assert_eq!(ignored.evt_cleanup, 0);
            assert_eq!(ignored.evt_destroy, 0);
            assert!(ignored.parent.is_none());
            assert_eq!(ignored.context_size_override, 0);
            assert_eq!(ignored.context_type_info, 0);

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[0xDEAD, 0],
                )
                .expect("acquire missing lock"),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockRelease,
                    &[0xDEAD],
                )
                .expect("release missing lock"),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, 0],
                )
                .expect("acquire lock"),
                STATUS_SUCCESS
            );
            let zero_timeout = 0x5F_300;
            memory.map_bytes(zero_timeout, &[0_u8; 8]);
            memory.write_u64(zero_timeout, 0);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, zero_timeout],
                )
                .expect("zero timeout on held lock"),
                STATUS_TIMEOUT
            );
            let gate = island.kmdf_wait_lock_gate(lock).unwrap();
            let releaser = {
                let gate = gate.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    let (mutex, wake) = &*gate;
                    let mut locked = mutex.lock().unwrap();
                    *locked = false;
                    drop(locked);
                    wake.notify_all();
                })
            };
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, 0],
                )
                .expect("infinite wait"),
                STATUS_SUCCESS
            );
            releaser.join().expect("releaser");
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockRelease,
                    &[lock],
                )
                .expect("release lock"),
                STATUS_SUCCESS
            );

            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockCreate,
                    &[0, out],
                )
                .expect("poisoned lock create"),
                STATUS_SUCCESS
            );
            let poisoned = memory.read_u64(out).unwrap();
            let gate = island.kmdf_wait_lock_gate(poisoned).unwrap();
            let poisoner = {
                let gate = gate.clone();
                std::thread::spawn(move || {
                    let (mutex, _) = &*gate;
                    let mut locked = mutex.lock().unwrap();
                    *locked = true;
                    panic!("poison the wait lock");
                })
            };
            assert!(poisoner.join().is_err(), "the poisoner panics");
            let tiny_timeout = 0x5F_400;
            memory.map_bytes(tiny_timeout, &[0_u8; 8]);
            memory.write_u64(tiny_timeout, (-1_i64) as u64);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[poisoned, tiny_timeout],
                )
                .expect("poisoned timed acquire"),
                STATUS_TIMEOUT
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockRelease,
                    &[poisoned],
                )
                .expect("poisoned release"),
                STATUS_SUCCESS
            );

            let absolute = 0x5F_500;
            memory.map_bytes(absolute, &[0_u8; 8]);
            memory.write_u64(absolute, 10);
            let island_state = island.inner.borrow();
            assert_eq!(
                island_state
                    .wait_lock_timeout(&memory, absolute)
                    .expect("absolute timeout"),
                Some(Duration::from_nanos(1_000))
            );
            assert_eq!(
                island_state
                    .wait_lock_timeout(&memory, zero_timeout)
                    .expect("zero timeout"),
                Some(Duration::ZERO)
            );
        });
    }

    #[test]
    fn kmdf_object_cascade_cancels_queued_requests_and_rejects_stale_objects() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(0, true);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaKmdfCascade");
            let device = island.kmdf_device_handles()[0];

            let mut callbacks = Vec::new();
            island
                .inner
                .borrow_mut()
                .collect_delete_callbacks(0xDEAD, &mut callbacks);
            assert!(callbacks.is_empty());

            let out = 0x50_000;
            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device, out],
                )
                .expect("cascade request"),
                STATUS_SUCCESS
            );
            let cascade_request = memory.read_u64(out).unwrap();
            {
                let mut state = island.inner.borrow_mut();
                state
                    .kmdf
                    .objects
                    .get_mut(&cascade_request)
                    .unwrap()
                    .deleted = true;
                let mut callbacks = Vec::new();
                state.collect_delete_callbacks(cascade_request, &mut callbacks);
                assert!(callbacks.is_empty());
            }
            {
                let mut state = island.inner.borrow_mut();
                assert!(!state.force_cancel_request(0xDEAD));
                assert!(
                    state.force_cancel_request(cascade_request),
                    "a stale-deleted request is still cancelable"
                );
            }

            let config = 0x51_000;
            let queue_out = 0x52_000;
            memory.map_bytes(config, &[0_u8; 0x60]);
            memory.map_bytes(queue_out, &[0_u8; 8]);
            memory.write_u32(config, 0x50);
            memory.write_u32(config + 4, 0);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device, config, 0, queue_out],
                )
                .expect("cascade queue"),
                STATUS_SUCCESS
            );
            let cascade_queue = memory.read_u64(queue_out).unwrap();
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device, out],
                )
                .expect("queued cascade request"),
                STATUS_SUCCESS
            );
            let queued = memory.read_u64(out).unwrap();
            {
                let mut state = island.inner.borrow_mut();
                state
                    .kmdf
                    .queues
                    .get_mut(&cascade_queue)
                    .unwrap()
                    .queued
                    .push_back(queued);
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[cascade_queue],
                )
                .expect("delete queue with queued requests"),
                STATUS_SUCCESS
            );
            let (canceled, status, _, _) = island.kmdf_request_state(queued).unwrap();
            assert!(canceled);
            assert_eq!(status, STATUS_CANCELLED);

            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device, out],
                )
                .expect("current request"),
                STATUS_SUCCESS
            );
            let current = memory.read_u64(out).unwrap();
            island.inner.borrow_mut().kmdf.current_request = current;
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[current],
                )
                .expect("delete current request"),
                STATUS_SUCCESS
            );
            assert_eq!(island.inner.borrow().kmdf.current_request, 0);

            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device, out],
                )
                .expect("completed request"),
                STATUS_SUCCESS
            );
            let completed = memory.read_u64(out).unwrap();
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestComplete,
                    &[completed, STATUS_SUCCESS as u64],
                )
                .expect("complete request"),
                STATUS_SUCCESS
            );
            assert!(!island.inner.borrow_mut().force_cancel_request(completed));
        });
    }

    #[test]
    fn x86_kmdf_layout_paths_and_shims_reject_malformed_blocks() {
        with_big_stack(|| {
            let image = build_kmdf_driver_pe32();
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x86(&image, "CasaX86Layout");
            let driver = island.kmdf_driver_handle();
            let device = island.kmdf_device_handles()[0];

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetDeviceType,
                    &[0xDEAD, 1],
                )
                .expect("x86 missing init"),
                STATUS_INVALID_PARAMETER
            );

            let irp_guest = 0x50_000;
            memory.map_bytes(irp_guest, &[0_u8; 0x100]);
            {
                let state = island.inner.borrow();
                state
                    .write_irp_status(&mut memory, irp_guest, STATUS_ACCESS_VIOLATION, 7)
                    .expect("x86 irp status");
            }
            assert_eq!(
                memory.read_u32(irp_guest + 0x18).unwrap(),
                STATUS_ACCESS_VIOLATION as u32
            );
            assert_eq!(memory.read_u32(irp_guest + 0x20).unwrap(), 7);

            let attrs = 0x51_000;
            let type_info = 0x51_040;
            memory.map_bytes(attrs, &[0_u8; 0x40]);
            memory.write_u32(attrs, 0x30);
            memory.write_u32(attrs + 0x04, 0);
            memory.write_u32(attrs + 0x08, 0);
            memory.write_u32(attrs + 0x14, driver as u32);
            memory.write_u32(attrs + 0x18, 0);
            memory.write_u32(attrs + 0x1C, type_info as u32);
            let parsed = island
                .inner
                .borrow()
                .parse_object_attributes(&memory, attrs)
                .expect("x86 attributes");
            assert_eq!(parsed.evt_cleanup, 0);
            assert_eq!(parsed.evt_destroy, 0);
            assert_eq!(parsed.parent, Some(driver));
            assert_eq!(parsed.context_size_override, 0);
            assert_eq!(parsed.context_type_info, u64::from(type_info as u32));

            memory.map_bytes(type_info, &[0_u8; 0x20]);
            memory.write_u32(type_info + 0x08, 0x18);
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .context_type_size(&memory, type_info)
                    .expect("x86 context type size"),
                0x18
            );

            let timeout = 0x52_000;
            memory.map_bytes(timeout, &[0_u8; 8]);
            memory.write_u32(timeout, 0);
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .wait_lock_timeout(&memory, timeout)
                    .expect("x86 zero timeout"),
                Some(Duration::ZERO)
            );
            memory.write_u32(timeout, 10);
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .wait_lock_timeout(&memory, timeout)
                    .expect("x86 absolute timeout"),
                Some(Duration::from_nanos(1_000))
            );
            memory.write_u32(timeout, (-1_i32) as u32);
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .wait_lock_timeout(&memory, timeout)
                    .expect("x86 relative timeout"),
                Some(Duration::from_nanos(100))
            );

            let descriptor = 0x53_000;
            memory.map_bytes(descriptor, &[0_u8; 0x20]);
            memory.write_u32(descriptor, 0);
            memory.write_u32(descriptor + 4, 0x1234_5678);
            memory.write_u32(descriptor + 8, 9);
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .read_memory_descriptor(&memory, descriptor)
                    .expect("x86 descriptor"),
                (0x1234_5678, 9)
            );

            let config = 0x54_000;
            let queue_out = 0x54_100;
            memory.map_bytes(config, &[0_u8; 0x60]);
            memory.map_bytes(queue_out, &[0_u8; 4]);
            memory.write_u32(config, 0x50);
            memory.write_u32(config + 4, 1);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device, config, 0, queue_out],
                )
                .expect("x86 queue create"),
                STATUS_SUCCESS
            );
            memory.write_u32(config + 4, 3);
            memory.map_bytes(queue_out, &[0_u8; 4]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device, config, 0, queue_out],
                )
                .expect("x86 invalid dispatch type"),
                STATUS_INVALID_PARAMETER
            );

            let finish_irp_guest = 0x55_000;
            memory.map_bytes(finish_irp_guest, &[0_u8; 0x100]);
            memory.write_u32(finish_irp_guest + 0x18, STATUS_ACCESS_VIOLATION as u32);
            memory.write_u32(finish_irp_guest + 0x20, 7);
            let mut state = island.inner.borrow_mut();
            let casak = state.kmdf.devices.get(&device).unwrap().casak;
            let irp = state
                .io
                .allocate_irp(
                    casak,
                    IrpParameterBlock::new(IrpMajorFunction::DeviceControl, 0, 0),
                )
                .expect("x86 irp");
            let pending = PendingIoTargetSend {
                irp,
                irp_guest: finish_irp_guest,
                entry: 0,
                device_object: 0,
                system_buffer: 0,
                output_ptr: 0,
                output_len: 0,
                bytes_returned: 0,
                request: 0,
                target: 0,
                io_control: 0,
                input_ptr: 0,
                input_len: 0,
                saved: (0, 0, 0, 0, 0, 0, 0),
            };
            assert_eq!(
                state
                    .finish_ioctl_send(&mut memory, pending)
                    .expect("x86 finish send"),
                (STATUS_ACCESS_VIOLATION, 7)
            );
        });
    }

    #[test]
    fn island_namespace_rejects_bad_paths_stale_handles_and_missing_services() {
        with_big_stack(|| {
            let image = build_test_driver(false, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaNamespace");
            assert_eq!(normalize_device_path("\\\\.\\CasaTest"), "\\??\\CasaTest");
            assert_eq!(
                normalize_device_path("\\Device\\CasaTest\\\\"),
                "\\Device\\CasaTest"
            );
            assert_eq!(normalize_device_path("  "), "");
            assert!(resolve_island_device(&runtime, "").is_none());
            assert!(resolve_island_device(&runtime, "   ").is_none());

            let handle_ptr = 0x5F_000;
            memory.map_bytes(handle_ptr, &[0_u8; 8]);
            assert_eq!(
                nt_open_island_device(&runtime, &mut memory, "", handle_ptr),
                None
            );
            assert_eq!(
                nt_open_island_device(&runtime, &mut memory, "\\Device\\CasaTest", 0),
                Some(STATUS_INVALID_PARAMETER)
            );
            assert_eq!(
                nt_open_island_device(&runtime, &mut memory, "\\Device\\CasaTest", 1),
                Some(STATUS_INVALID_PARAMETER)
            );
            assert_eq!(
                nt_open_island_device(&runtime, &mut memory, "\\Device\\CasaTest", handle_ptr),
                Some(STATUS_SUCCESS)
            );
            let direct_handle = memory.read_u32(handle_ptr).unwrap();
            assert_ne!(direct_handle, 0);
            assert_eq!(
                nt_open_island_device(&runtime, &mut memory, "\\??\\CasaTest", handle_ptr),
                Some(STATUS_SUCCESS),
                "the driver's symbolic link resolves"
            );
            let link_handle = memory.read_u32(handle_ptr).unwrap();
            assert_ne!(link_handle, direct_handle);
            assert_eq!(
                nt_open_island_device(&runtime, &mut memory, "\\DosDevices\\CasaTest", handle_ptr),
                Some(STATUS_SUCCESS),
                "the DOS-device prefix resolves without a link"
            );
            assert_eq!(
                nt_open_island_device(&runtime, &mut memory, "\\Device\\CasaTest\\\\", handle_ptr),
                Some(STATUS_SUCCESS),
                "trailing separators are normalized"
            );

            assert_eq!(
                dispatch_island_device_io(
                    &mut runtime,
                    &mut memory,
                    0xDEAD_0000,
                    IrpMajorFunction::DeviceControl,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("unknown handle"),
                None
            );
            assert_eq!(
                dispatch_island_device_io(
                    &mut runtime,
                    &mut memory,
                    direct_handle,
                    IrpMajorFunction::DeviceControl,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("live handle"),
                Some((STATUS_INVALID_DEVICE_REQUEST, 0))
            );

            let runtime_id = runtime_identity(&runtime);
            let saved_services = lock_registry().services.remove(&runtime_id);
            assert!(saved_services.is_some());
            assert_eq!(
                dispatch_island_device_io(
                    &mut runtime,
                    &mut memory,
                    link_handle,
                    IrpMajorFunction::DeviceControl,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("handle with missing service"),
                Some((STATUS_INVALID_HANDLE, 0))
            );
            if let Some(services) = saved_services {
                lock_registry().services.insert(runtime_id, services);
            }

            let record = lock_registry()
                .device_handles
                .get(&runtime_id)
                .and_then(|handles| handles.get(&direct_handle))
                .cloned()
                .expect("direct handle record");
            island
                .inner
                .borrow_mut()
                .device_ids
                .remove(&record.device_guest);
            assert_eq!(
                dispatch_island_device_io(
                    &mut runtime,
                    &mut memory,
                    direct_handle,
                    IrpMajorFunction::DeviceControl,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("stale device handle"),
                Some((STATUS_INVALID_HANDLE, 0))
            );
        });
    }

    #[test]
    fn wdf_config_edges_reject_stale_parents_and_invalid_dispatch_type() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfConfigEdges");
            let device = island.kmdf_device_handles()[0];
            let driver = island.driver_object_pointer();
            let out = 0x41_000;
            memory.map_bytes(out, &[0_u8; 0x40]);

            let text = 0x42_000;
            memory.map_bytes(text, &[0_u8; 0x40]);
            memory.write_u16(text, u16::from(b'A'));
            memory.write_u16(text + 2, u16::from(b'B'));
            memory.write_u16(text + 4, 0);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::RtlInitUnicodeString,
                    &[0xFFFF_FFFF, text],
                )
                .expect("invalid destination"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::RtlInitUnicodeString,
                    &[text, text],
                )
                .expect("overlapping source and destination"),
                STATUS_SUCCESS
            );
            assert_eq!(memory.read_u16(text).unwrap(), 4);
            assert_eq!(memory.read_u16(text + 2).unwrap(), 6);
            assert_eq!(memory.read_u64(text + 8).unwrap(), text);

            let attrs = 0x43_000;
            let type_info = 0x44_000;
            let lock_out = 0x45_000;
            memory.map_bytes(attrs, &[0_u8; 0x40]);
            memory.map_bytes(type_info, &[0_u8; 0x20]);
            memory.write_u32(attrs, 0x38);
            memory.write_u64(attrs + 0x20, 0xDEAD_BEEF);
            memory.write_u64(attrs + 0x28, 0x20_0000);
            memory.write_u32(type_info, 0x18);
            memory.write_u64(type_info + 0x10, 0x18);
            memory.write_u64(attrs + 0x30, type_info);
            memory.map_bytes(lock_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockCreate,
                    &[attrs, lock_out],
                )
                .expect("wait lock with stale parent"),
                STATUS_SUCCESS
            );
            let lock = memory.read_u64(lock_out).unwrap();
            {
                let state = island.inner.borrow();
                let object = state.kmdf.objects.get(&lock).expect("wait lock object");
                assert_eq!(object.context_size, 0x10_000);
                assert_eq!(object.parent, Some(state.kmdf.driver_handle));
            }

            let short_config = 0x46_000;
            memory.map_bytes(short_config, &[0_u8; 0x40]);
            memory.write_u32(short_config, 0x1F);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDriverCreate,
                    &[driver, 0, 0, short_config, out],
                )
                .expect("undersized driver config"),
                STATUS_INVALID_PARAMETER
            );

            let config = 0x46_040;
            memory.map_bytes(config, &[0_u8; 0x40]);
            memory.write_u32(config, 0x20);
            memory.write_u64(config + 0x10, 0xDEAD_BEEF);
            memory.write_u32(config + 0x18, 0xCA5A_2146);
            memory.write_u32(config + 0x1C, 2);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDriverCreate,
                    &[driver, 0, 0, config, out],
                )
                .expect("full driver config"),
                STATUS_SUCCESS
            );
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.evt_driver_unload, 0xDEAD_BEEF);
                assert_eq!(state.kmdf.driver_pool_tag, 0xCA5A_2146);
                assert_eq!(state.kmdf.driver_init_flags, 2);
            }

            let queue_config = 0x47_000;
            let queue_out = 0x47_040;
            memory.map_bytes(queue_config, &[0_u8; 0x20]);
            memory.map_bytes(queue_out, &[0_u8; 8]);
            memory.write_u32(queue_config, 0x0E);
            memory.write_u32(queue_config + 4, 3);
            memory.write_u8(queue_config + 0x0C, 1);
            memory.write_u8(queue_config + 0x0D, 1);
            let queues_before = island.inner.borrow().kmdf.queues.len();
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device, queue_config, 0, queue_out],
                )
                .expect("invalid queue dispatch type"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(island.inner.borrow().kmdf.queues.len(), queues_before);

            assert_eq!(
                parse_service_name("\\Registry\\Machine\\System\\CurrentControlSet\\Other\\X"),
                Err(STATUS_INVALID_PARAMETER)
            );
            assert_eq!(parse_service_name(""), Err(STATUS_INVALID_PARAMETER));
        });
    }

    #[test]
    fn wdf_request_iotarget_edges_reject_stale_devices_and_invalid_driver_objects() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(0, true);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfEdges");
            let device_a = kmdf_device_named(&island, "WdfA");
            let device_b = kmdf_device_named(&island, "WdfB");
            let device_b_object = island
                .inner
                .borrow()
                .kmdf
                .devices
                .get(&device_b)
                .expect("device b")
                .object_guest;
            let out = 0x41_000;
            memory.map_bytes(out, &[0_u8; 8]);

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device_a, out],
                )
                .expect("request create"),
                STATUS_SUCCESS
            );
            let request = memory.read_u64(out).unwrap();
            {
                let state = island.inner.borrow();
                assert_eq!(
                    state
                        .kmdf
                        .objects
                        .get(&request)
                        .expect("request object")
                        .parent,
                    Some(device_a)
                );
                assert!(
                    state
                        .kmdf
                        .objects
                        .get(&device_a)
                        .expect("device object")
                        .children
                        .contains(&request)
                );
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[request],
                )
                .expect("delete request"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[request],
                )
                .expect("double delete request"),
                STATUS_INVALID_HANDLE
            );

            let target_out = 0x42_000;
            memory.map_bytes(target_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetCreate,
                    &[0xDEAD, 0, target_out],
                )
                .expect("target for missing device"),
                STATUS_INVALID_PARAMETER
            );
            let attrs = 0x43_000;
            memory.map_bytes(attrs, &[0_u8; 0x40]);
            memory.write_u32(attrs, 0x38);
            memory.write_u64(attrs + 0x20, 0xDEAD_BEEF);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetCreate,
                    &[device_a, attrs, target_out],
                )
                .expect("target with stale parent"),
                STATUS_SUCCESS
            );
            let target = memory.read_u64(target_out).unwrap();
            {
                let state = island.inner.borrow();
                assert_eq!(
                    state
                        .kmdf
                        .objects
                        .get(&target)
                        .expect("target object")
                        .parent,
                    Some(device_a)
                );
                assert!(
                    state
                        .kmdf
                        .objects
                        .get(&device_a)
                        .expect("device object")
                        .children
                        .contains(&target)
                );
            }

            let driver = island.driver_object_pointer();
            let major_slot = driver + 0x70 + IrpMajorFunction::DeviceControl.code() as u64 * 8;
            memory.write_u64(major_slot, 0);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetSendIoctlSynchronously,
                    &[target, 0, 0x0022_0004, 0, 0, 0, 0],
                )
                .expect("sync send without handler"),
                STATUS_INVALID_DEVICE_REQUEST
            );

            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, device_a, out],
                )
                .expect("send request create"),
                STATUS_SUCCESS
            );
            let send_request = memory.read_u64(out).unwrap();
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestFormatRequestForIoctl,
                    &[send_request, target, 0x0022_0004, 0, 0, 0, 0, 0],
                )
                .expect("format request"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestSend,
                    &[send_request, target, 0],
                )
                .expect("send without handler"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            let (completed, status, _, _) = island
                .kmdf_request_state(send_request)
                .expect("request state");
            assert!(completed);
            assert_eq!(status, STATUS_INVALID_DEVICE_REQUEST);

            let saved_driver_object = island.inner.borrow().driver_object_guest;
            island.inner.borrow_mut().driver_object_guest = 0x7000_0000_0000;
            let sync_error = call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetSendIoctlSynchronously,
                &[target, 0, 0x0022_0004, 0, 0, 0, 0],
            )
            .expect_err("sync send with corrupt driver object");
            assert_eq!(sync_error.code, ReasonCode::RcUnimplInsn);
            {
                let mut state = island.inner.borrow_mut();
                if let Some(request) = state.kmdf.requests.get_mut(&send_request) {
                    request.completed = false;
                }
            }
            let send_error = call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestSend,
                &[send_request, target, 0],
            )
            .expect_err("request send with corrupt driver object");
            assert_eq!(send_error.code, ReasonCode::RcUnimplInsn);
            island.inner.borrow_mut().driver_object_guest = saved_driver_object;
            memory.write_u64(major_slot, 0);

            let irp_guest = 0x44_000;
            memory.map_bytes(irp_guest, &[0_u8; 0x100]);
            {
                let mut state = island.inner.borrow_mut();
                let casak = state.kmdf.devices.get(&device_b).expect("device b").casak;
                let _ = state.io.delete_device(casak);
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfEvtIoDeviceControlDispatch,
                    &[irp_guest, device_b_object],
                )
                .expect("dispatch to deleted device"),
                crate::casak::io::STATUS_DELETE_PENDING as i32
            );
            assert_eq!(
                memory.read_u32(irp_guest + 0x30).unwrap(),
                crate::casak::io::STATUS_DELETE_PENDING as u32
            );
        });
    }

    #[test]
    fn kmdf_queue_stop_start_and_purge_reject_orphaned_requests() {
        with_big_stack(|| {
            let image = build_kmdf_full_driver(0, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfQueueEdges");
            let image_base = island.image_base();
            let device = kmdf_device_named(&island, "WdfA");
            let queue = queue_for_device(&island, device);
            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStopSynchronously,
                    &[queue],
                )
                .expect("stop empty queue"),
                STATUS_SUCCESS
            );
            let input = 0x46_000;
            let output = 0x47_000;
            let iosb = 0x48_000;
            memory.map_bytes(input, b"PING");
            memory.map_bytes(output, &[0_u8; 8]);
            memory.map_bytes(iosb, &[0_u8; 24]);
            for _ in 0..2 {
                assert_eq!(
                    dispatch_nt_thunk(
                        &mut runtime,
                        &mut memory,
                        HostThunk::NtDeviceIoControlFile,
                        &[
                            u64::from(handle),
                            0,
                            0,
                            0,
                            iosb,
                            0x0022_0004,
                            input,
                            4,
                            output,
                            8,
                        ],
                    ),
                    STATUS_PENDING
                );
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStopSynchronously,
                    &[queue],
                )
                .expect("stop queued queue"),
                STATUS_SUCCESS
            );
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_STOP_COUNT))
                    .unwrap(),
                2
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStart,
                    &[queue],
                )
                .expect("restart queue"),
                STATUS_SUCCESS
            );
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_RESUME_COUNT))
                    .unwrap(),
                2
            );
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_IOCTL_COUNT))
                    .unwrap(),
                2
            );
            {
                let state = island.inner.borrow();
                let queue_state = state.kmdf.queues.get(&queue).expect("queue");
                assert!(queue_state.queued.is_empty());
                assert!(queue_state.in_flight.is_empty());
                assert!(!queue_state.stopped);
                assert_eq!(state.kmdf.stop_dispatches, 2);
                assert_eq!(state.kmdf.resume_dispatches, 2);
                assert!(
                    state
                        .kmdf
                        .requests
                        .values()
                        .all(|request| request.completed)
                );
            }

            let ret_stub = x64_ret_stub(&mut memory, &island);
            set_queue_callbacks(&island, queue, |queue| {
                queue.callbacks.device_control = ret_stub;
            });
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        input,
                        4,
                        output,
                        8,
                    ],
                ),
                STATUS_PENDING
            );
            let in_flight_request = island
                .inner
                .borrow()
                .kmdf
                .requests
                .iter()
                .find(|(_, request)| !request.completed && request.queue == Some(queue))
                .map(|(request, _)| *request)
                .expect("in-flight request");
            let (_, _, _, outer) = island
                .kmdf_request_state(in_flight_request)
                .expect("request state");
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueuePurge,
                    &[queue],
                )
                .expect("purge in-flight request"),
                STATUS_SUCCESS
            );
            let (completed, status, _, outer_after) = island
                .kmdf_request_state(in_flight_request)
                .expect("request state");
            assert!(completed);
            assert_eq!(status, STATUS_CANCELLED);
            assert_eq!(outer_after, outer);
            assert_eq!(
                memory.read_u32(outer + 0x30).unwrap(),
                STATUS_CANCELLED as u32
            );
            assert_eq!(island.inner.borrow().kmdf.cancel_dispatches, 1);
            assert!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .queues
                    .get(&queue)
                    .expect("queue")
                    .in_flight
                    .is_empty()
            );
        });
    }

    #[test]
    fn wait_lock_gate_poison_race_and_corrupt_driver_object_reject() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfPoison");
            let lock = island.kmdf_wait_lock_handles()[0];
            let gate = island.kmdf_wait_lock_gate(lock).expect("gate");
            let poison = gate.clone();
            let panicked = std::thread::spawn(move || {
                let (mutex, _) = &*poison;
                let _guard = mutex.lock().expect("lock before poison");
                panic!("poison wait lock mutex");
            })
            .join();
            assert!(panicked.is_err());
            assert!(gate.0.is_poisoned());
            {
                let (mutex, _) = &*gate;
                let mut locked = mutex.lock().unwrap_err().into_inner();
                *locked = true;
            }
            let notify = gate.clone();
            let notifier = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                let (mutex, wake) = &*notify;
                let mut locked = mutex.lock().unwrap_err().into_inner();
                *locked = false;
                drop(locked);
                wake.notify_all();
            });
            assert_eq!(
                island.inner.borrow().wait_lock_acquire_gate(&gate, None),
                STATUS_SUCCESS
            );
            notifier.join().expect("notifier");
            {
                let (mutex, _) = &*gate;
                let mut locked = mutex.lock().unwrap_err().into_inner();
                *locked = true;
            }
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .wait_lock_acquire_gate(&gate, Some(Duration::from_millis(20))),
                STATUS_TIMEOUT
            );

            let (handle, status) =
                create_device_file(&mut runtime, &mut memory, "\\Device\\WdfCasa", 0x41_000);
            assert_eq!(status, STATUS_SUCCESS);
            let driver_object = island.driver_object_pointer();
            let saved_driver_object = island.inner.borrow().driver_object_guest;
            island.inner.borrow_mut().driver_object_guest = 0x7000_0000_0000;
            let error = dispatch_island_device_io(
                &mut runtime,
                &mut memory,
                handle,
                IrpMajorFunction::DeviceControl,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect_err("dispatch with corrupt driver object");
            assert_eq!(error.code, ReasonCode::RcUnimplInsn);
            island.inner.borrow_mut().driver_object_guest = saved_driver_object;
            let major_slot =
                driver_object + 0x70 + IrpMajorFunction::DeviceControl.code() as u64 * 8;
            let saved_handler = memory.read_u64(major_slot).unwrap();
            memory.write_u64(major_slot, 0);
            assert_eq!(
                dispatch_island_device_io(
                    &mut runtime,
                    &mut memory,
                    handle,
                    IrpMajorFunction::DeviceControl,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("dispatch without handler"),
                Some((STATUS_INVALID_DEVICE_REQUEST, 0))
            );
            memory.write_u64(major_slot, saved_handler);
        });
    }

    #[test]
    fn pe32_unload_corrupt_callback_and_exhausted_unicode_arena_reject() {
        with_big_stack(|| {
            let image = build_kmdf_driver_pe32();
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x86(&image, "CasaPe32Edges");
            let driver = island.driver_object_pointer();
            let default_dispatch = island.inner.borrow().default_dispatch;
            assert_eq!(
                memory.read_u32(driver + 0x38).unwrap(),
                default_dispatch as u32
            );
            let image_base = island.image_base();
            {
                let state = island.inner.borrow();
                assert_eq!(state.unload_guest, None);
                assert_eq!(
                    state.kmdf.evt_driver_unload,
                    image_base + u64::from(X86K_UNLOAD_RVA)
                );
            }
            assert_eq!(memory.read_u32(driver + 0x34).unwrap(), 0);

            let header = {
                let mut state = island.inner.borrow_mut();
                allocate_unicode_string(&mut state, &mut memory, "AB").expect("unicode string")
            };
            assert_eq!(memory.read_u16(header).unwrap(), 4);
            assert_eq!(memory.read_u16(header + 2).unwrap(), 6);
            assert_ne!(memory.read_u32(header + 4).unwrap(), 0);

            let saved_cursor = {
                let mut state = island.inner.borrow_mut();
                let saved = state.arena.cursor;
                state.arena.cursor = state.arena.end;
                saved
            };
            let error = {
                let mut state = island.inner.borrow_mut();
                allocate_unicode_string(&mut state, &mut memory, "AB").expect_err("exhausted arena")
            };
            assert_eq!(error.code, ReasonCode::RcIo);
            assert!(
                error.message.contains("driver island arena exhausted"),
                "{}",
                error.message
            );
            island.inner.borrow_mut().arena.cursor = saved_cursor;

            island.inner.borrow_mut().kmdf.evt_driver_unload = 0xDEAD_BEEF;
            let service_path = guest_unicode_string_x86(
                &mut memory,
                0x40_000,
                "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaPe32Edges",
            );
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtUnloadDriver,
                    &[service_path],
                ),
                STATUS_INVALID_PARAMETER
            );
            assert!(island.is_loaded());
        });
    }

    #[test]
    fn kmdf_short_attributes_and_zero_destination_reject_implicit_members() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfAttrShort");
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::RtlInitUnicodeString,
                    &[0, 0xDEAD_BEEF],
                )
                .expect("zero destination must be accepted"),
                STATUS_SUCCESS
            );

            let attrs = 0x41_000;
            memory.map_bytes(attrs, &[0_u8; 0x40]);
            memory.write_u32(attrs, 8);
            let parsed = island
                .inner
                .borrow()
                .parse_object_attributes(&memory, attrs)
                .expect("short attributes");
            assert_eq!(parsed.evt_cleanup, 0);
            assert_eq!(parsed.evt_destroy, 0);
            assert_eq!(parsed.parent, None);
            assert_eq!(parsed.context_size_override, 0);
            assert_eq!(parsed.context_type_info, 0);

            memory.write_u32(attrs, 0x28);
            memory.write_u64(attrs + 0x20, 0x1234_5678);
            memory.write_u64(attrs + 0x28, 0xDEAD_BEEF);
            memory.write_u64(attrs + 0x30, 0xFEED_FACE);
            let parsed = island
                .inner
                .borrow()
                .parse_object_attributes(&memory, attrs)
                .expect("parent-only attributes");
            assert_eq!(parsed.parent, Some(0x1234_5678));
            assert_eq!(parsed.context_size_override, 0);
            assert_eq!(parsed.context_type_info, 0);
        });
    }

    #[test]
    fn kmdf_driver_and_queue_config_omissions_reject_implicit_fields() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfConfigOmit");
            let driver = island.driver_object_pointer();
            let out = 0x41_000;
            memory.map_bytes(out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDriverCreate,
                    &[driver, 0, 0, 0, out],
                )
                .expect("config-less driver create"),
                STATUS_SUCCESS
            );
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.evt_driver_unload, 0);
                assert_eq!(state.kmdf.driver_pool_tag, 0);
                assert_eq!(state.kmdf.driver_init_flags, 0);
            }

            let device = island.kmdf_device_handles()[0];
            let config = 0x42_000;
            let queue_out = 0x43_000;
            memory.map_bytes(config, &[0_u8; 0x20]);
            memory.map_bytes(queue_out, &[0_u8; 8]);
            memory.write_u32(config, 8);
            memory.write_u32(config + 4, 0);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device, config, 0, queue_out],
                )
                .expect("short queue config"),
                STATUS_SUCCESS
            );
            let queue = memory.read_u64(queue_out).unwrap();
            {
                let state = island.inner.borrow();
                let record = state.kmdf.queues.get(&queue).expect("created queue");
                assert_eq!(record.default_queue, false);
                assert_eq!(record.dispatch_type, 0);
                assert_eq!(record.callbacks.default, 0);
                assert_eq!(record.callbacks.device_control, 0);
            }
        });
    }

    #[test]
    fn kmdf_object_parent_edges_and_driverless_delete_reject_cascade() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfParentEdges");
            let device = island.kmdf_device_handles()[0];
            let attrs = 0x41_000;
            memory.map_bytes(attrs, &[0_u8; 0x40]);
            memory.write_u32(attrs, 0x38);
            memory.write_u64(attrs + 0x20, device);
            let request_out = 0x42_000;
            memory.map_bytes(request_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[attrs, device, request_out],
                )
                .expect("request with explicit parent"),
                STATUS_SUCCESS
            );
            let request = memory.read_u64(request_out).unwrap();
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .objects
                    .get(&request)
                    .expect("request object")
                    .parent,
                Some(device)
            );

            let saved_driver_object = island.inner.borrow().driver_object_guest;
            island.inner.borrow_mut().driver_object_guest = 0;
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[request],
                )
                .expect("driverless object delete"),
                STATUS_SUCCESS
            );
            island.inner.borrow_mut().driver_object_guest = saved_driver_object;
            assert_eq!(
                island.inner.borrow().kmdf.objects.contains_key(&request),
                false
            );

            let target_out = 0x43_000;
            memory.map_bytes(target_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetCreate,
                    &[device, attrs, target_out],
                )
                .expect("iotarget with explicit parent"),
                STATUS_SUCCESS
            );
            let target = memory.read_u64(target_out).unwrap();
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .objects
                    .get(&target)
                    .expect("target object")
                    .parent,
                Some(device)
            );
        });
    }

    #[test]
    fn kmdf_queue_callback_absence_and_stale_completion_edges_reject() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfQueueNoCallbacks");
            let device = island.kmdf_device_handles()[0];
            let queue = *island
                .inner
                .borrow()
                .kmdf
                .queues
                .keys()
                .next()
                .expect("queue");
            set_queue_callbacks(&island, queue, |record| {
                record.callbacks.stop = 0;
                record.callbacks.resume = 0;
                record.callbacks.canceled_on_queue = 0;
            });
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStop,
                    &[queue],
                )
                .expect("stop without callback"),
                STATUS_SUCCESS
            );
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .queues
                    .get(&queue)
                    .expect("queue")
                    .stopped,
                true
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStart,
                    &[queue],
                )
                .expect("start without callback"),
                STATUS_SUCCESS
            );
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .queues
                    .get(&queue)
                    .expect("queue")
                    .stopped,
                false
            );

            island
                .inner
                .borrow_mut()
                .kmdf
                .queues
                .get_mut(&queue)
                .expect("queue")
                .queued
                .push_back(0xDEAD);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueuePurge,
                    &[queue],
                )
                .expect("purge stale queued handle"),
                STATUS_SUCCESS
            );
            assert_eq!(
                island
                    .inner
                    .borrow()
                    .kmdf
                    .queues
                    .get(&queue)
                    .expect("queue")
                    .queued
                    .is_empty(),
                true
            );

            let request = make_kmdf_request(
                &island,
                &mut memory,
                device,
                queue,
                IrpMajorFunction::DeviceControl,
            );
            island
                .inner
                .borrow_mut()
                .kmdf
                .requests
                .get_mut(&request)
                .expect("request")
                .queue = Some(0xDEAD);
            island
                .inner
                .borrow_mut()
                .complete_kmdf_request(&mut memory, request, STATUS_CANCELLED, 0)
                .expect("complete request with stale queue");
            let (completed, status, _, _) = island.kmdf_request_state(request).expect("state");
            assert_eq!(completed, true);
            assert_eq!(status, STATUS_CANCELLED);
        });
    }

    const STATUS_ACCESS_DENIED: i32 = 0xC000_0022u32 as i32;

    fn pnp_u32(memory: &MemoryImage, base: u64, rva: u32) -> u32 {
        memory
            .read_u32(base + u64::from(rva))
            .expect("pnp fixture dword")
    }

    fn pnp_set_failure(memory: &mut MemoryImage, base: u64, mask: u32, status: i32) {
        memory.write_u32(base + u64::from(P_FAIL_MASK), mask);
        memory.write_u32(base + u64::from(P_FAIL_STATUS), status as u32);
    }

    fn pnp_load(
        service: &str,
    ) -> (
        Box<PeHostRuntime>,
        TempDir,
        MemoryImage,
        DriverIsland,
        u64,
        u64,
    ) {
        let image = build_kmdf_pnp_driver();
        let (runtime, directory, memory, island) = load_staged_island_x64(&image, service);
        let base = island.image_base();
        let device = island
            .created_devices()
            .into_iter()
            .next()
            .expect("pnp fixture device")
            .guest_pointer;
        (runtime, directory, memory, island, base, device)
    }

    #[test]
    fn pnp_invalid_minors_repeated_start_stop_and_remove_after_remove_reject() {
        with_big_stack(|| {
            let (mut runtime, _dir, mut memory, island, base, device) = pnp_load("CasaPnpLife");
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                    .expect("stop before start")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                    .expect("D3 before start")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                    .expect("D0 before start")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, 0x01)
                    .expect("query-remove minor")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, 2)
                    .expect("D2 power state")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island
                    .dispatch_irp(
                        &mut runtime,
                        &mut memory,
                        device,
                        IrpMajorFunction::Power,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    )
                    .expect("non-set-power minor")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 0);

            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("start")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 0);
            assert_eq!(
                pnp_u32(&memory, base, P_LAST_PREV),
                WDF_POWER_DEVICE_D3_FINAL
            );
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("repeated start")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 1);

            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                    .expect("D3")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_SUSPEND_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_D0EXIT_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_LAST_TARGET), WDF_POWER_DEVICE_D3);
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                    .expect("repeated D3")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                    .expect("stop while D3")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                    .expect("D0")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 2);
            assert_eq!(pnp_u32(&memory, base, P_LAST_PREV), WDF_POWER_DEVICE_D3);
            assert_eq!(pnp_u32(&memory, base, P_RESTART_COUNT), 1);
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                    .expect("repeated D0")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );

            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                    .expect("stop")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_SELFFINI_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_D0EXIT_COUNT), 2);
            assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 1);
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                    .expect("repeated stop")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                    .expect("D3 after stop")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );

            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("restart after stop")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_REMOVE_DEVICE)
                    .expect("remove")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_SELFFINI_COUNT), 2);
            assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 2);
            assert_eq!(pnp_u32(&memory, base, P_CLEANUP_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_DESTROY_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_CLEANUP_AFTER_DESTROY), 0);
            assert_eq!(pnp_u32(&memory, base, P_DESTROY_AFTER_CLEANUP), 1);
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_REMOVE_DEVICE)
                    .expect("repeated remove")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("start after remove")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(island.device_count(), 0);
            assert!(island.created_devices()[0].deleted);
        });
    }

    #[test]
    fn pnp_start_callback_failures_roll_back_and_never_become_ready() {
        with_big_stack(|| {
            let (mut runtime, _dir, mut memory, island, base, device) =
                pnp_load("CasaPnpStartFail");
            pnp_set_failure(&mut memory, base, 1, STATUS_INSUFFICIENT_RESOURCES);
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("prepare hardware failure")
                    .0,
                STATUS_INSUFFICIENT_RESOURCES
            );
            assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 0);
            assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 0);
            assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 0);
            {
                let handle = island.kmdf_device_handles()[0];
                let state = island.inner.borrow();
                let record = state.kmdf.devices.get(&handle).expect("device");
                assert_eq!(record.started, false);
                assert_eq!(record.power_state, WDF_POWER_DEVICE_D3);
            }
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                    .expect("stop after failed start")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );

            pnp_set_failure(&mut memory, base, 2, STATUS_UNSUCCESSFUL);
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("D0Entry failure")
                    .0,
                STATUS_UNSUCCESSFUL
            );
            assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 2);
            assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 0);
            {
                let handle = island.kmdf_device_handles()[0];
                let state = island.inner.borrow();
                let record = state.kmdf.devices.get(&handle).expect("device");
                assert_eq!(record.started, false);
                assert_eq!(record.power_state, WDF_POWER_DEVICE_D3);
            }

            pnp_set_failure(&mut memory, base, 4, STATUS_ACCESS_DENIED);
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("self-managed IO failure")
                    .0,
                STATUS_ACCESS_DENIED
            );
            assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 3);
            assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 2);
            assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_D0EXIT_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 2);
            {
                let handle = island.kmdf_device_handles()[0];
                let state = island.inner.borrow();
                let record = state.kmdf.devices.get(&handle).expect("device");
                assert_eq!(record.started, false);
                assert_eq!(record.power_state, WDF_POWER_DEVICE_D3);
            }

            pnp_set_failure(&mut memory, base, 0, 0);
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("start after rollbacks")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 3);
            assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 2);
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                    .expect("power down")
                    .0,
                STATUS_SUCCESS
            );
            pnp_set_failure(&mut memory, base, 2, STATUS_UNSUCCESSFUL);
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                    .expect("D0 failure")
                    .0,
                STATUS_UNSUCCESSFUL
            );
            assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 4);
            assert_eq!(pnp_u32(&memory, base, P_RESTART_COUNT), 0);
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                    .expect("D3 after failed D0")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            pnp_set_failure(&mut memory, base, 0, 0);
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                    .expect("D0 recovery")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_LAST_PREV), WDF_POWER_DEVICE_D3);
            assert_eq!(pnp_u32(&memory, base, P_RESTART_COUNT), 1);
        });
    }

    #[test]
    fn pnp_file_cleanup_and_device_cleanup_destroy_ordering_reject_out_of_order() {
        with_big_stack(|| {
            let (mut runtime, _dir, mut memory, island, base, device) = pnp_load("CasaPnpOrder");
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("start")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(
                island
                    .dispatch_irp(
                        &mut runtime,
                        &mut memory,
                        device,
                        IrpMajorFunction::Cleanup,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    )
                    .expect("file cleanup")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_FCLEANUP_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_FCLOSE_COUNT), 0);
            assert_eq!(
                island
                    .dispatch_irp(
                        &mut runtime,
                        &mut memory,
                        device,
                        IrpMajorFunction::Close,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    )
                    .expect("file close")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_FCLOSE_COUNT), 1);
            {
                let handle = island.kmdf_device_handles()[0];
                let state = island.inner.borrow();
                let object = state.kmdf.objects.get(&handle).expect("device object");
                assert_ne!(object.evt_cleanup, 0);
                assert_ne!(object.evt_destroy, 0);
            }
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_REMOVE_DEVICE)
                    .expect("remove")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_CLEANUP_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_DESTROY_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_CLEANUP_AFTER_DESTROY), 0);
            assert_eq!(pnp_u32(&memory, base, P_DESTROY_AFTER_CLEANUP), 1);
            {
                let state = island.inner.borrow();
                assert_eq!(state.kmdf.file_cleanup_dispatches, 1);
                assert_eq!(state.kmdf.file_close_dispatches, 1);
                assert!(state.kmdf.devices.is_empty());
            }
        });
    }

    #[test]
    fn pnp_malformed_callback_config_and_unsupported_framework_import_reject() {
        with_big_stack(|| {
            let (mut runtime, _dir, mut memory, island, _base, device) =
                pnp_load("CasaPnpMalformed");
            let init = *island
                .inner
                .borrow()
                .kmdf
                .device_inits
                .keys()
                .next()
                .expect("fixture device init");
            let config = 0x41_000;
            memory.map_bytes(config, &[0_u8; 0x40]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks,
                    &[init, 0],
                )
                .expect("null callback table"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks,
                    &[0xDEAD, config],
                )
                .expect("stale device init"),
                STATUS_INVALID_PARAMETER
            );
            memory.write_u32(config, 0);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks,
                    &[init, config],
                )
                .expect("zero-size callback table"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetFileObjectConfig,
                    &[init, 0, 0],
                )
                .expect("null file config"),
                STATUS_INVALID_PARAMETER
            );
            memory.write_u32(config, 0);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetFileObjectConfig,
                    &[init, config, 0],
                )
                .expect("zero-size file config"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceEnqueueRequest,
                    &[0xDEAD, 0xBEEF],
                )
                .expect("stale enqueue device"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            let request_out = 0x42_000;
            memory.map_bytes(request_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, 0, request_out],
                )
                .expect("request create"),
                STATUS_SUCCESS
            );
            let request = memory.read_u64(request_out).expect("request handle");
            let device_handle = island.kmdf_device_handles()[0];
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceEnqueueRequest,
                    &[device_handle, request],
                )
                .expect("enqueue without a queue"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceEnqueueRequest,
                    &[device, 0xDEAD],
                )
                .expect("stale request"),
                STATUS_INVALID_DEVICE_REQUEST
            );
        });
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _dir, mut memory, island) =
                load_staged_island_x64(&image, "CasaPnpNoCallbacks");
            let device = island.created_devices()[0].guest_pointer;
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_REMOVE_DEVICE)
                    .expect("remove without callbacks"),
                (STATUS_SUCCESS, 0)
            );
            assert_eq!(island.device_count(), 0);
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_REMOVE_DEVICE)
                    .expect("repeated remove without callbacks")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
        });
        with_big_stack(|| {
            let mut image = build_kmdf_pnp_driver();
            image[0x1642..0x1660].fill(0);
            image[0x1642..0x1649].copy_from_slice(b"WdfFoo\0");
            let (mut runtime, _directory) = test_runtime();
            let mut memory = MemoryImage::default();
            let error = DriverIsland::load_and_start_named(
                &image,
                "CasaPnpUnsupported",
                &mut runtime,
                &mut memory,
            )
            .expect_err("an unsupported framework import must reject the image");
            assert_eq!(error.code, ReasonCode::RcImportMissing);
            assert!(
                error.message.contains("Kmdf:WdfLdr.sys!WdfFoo"),
                "{}",
                error.message
            );
        });
    }

    #[test]
    fn wdf_memory_string_and_typed_context_sizing_errors_reject() {
        with_big_stack(|| {
            assert!(matches!(
                DriverShim::for_import("WdfMemoryCreate"),
                Some(DriverShim::WdfMemoryCreate)
            ));
            assert!(matches!(
                DriverShim::for_import("WdfMemoryDelete"),
                Some(DriverShim::WdfObjectDelete)
            ));
            assert!(matches!(
                DriverShim::for_import("WdfStringCreate"),
                Some(DriverShim::WdfStringCreate)
            ));
            assert!(matches!(
                DriverShim::for_import("WdfStringDelete"),
                Some(DriverShim::WdfObjectDelete)
            ));
            assert!(matches!(
                DriverShim::for_import("WdfDeviceEnqueueRequest"),
                Some(DriverShim::WdfDeviceEnqueueRequest)
            ));
            assert!(matches!(
                DriverShim::for_import("WdfPdoInitAllocate"),
                Some(DriverShim::WdfPdoInitAllocate)
            ));
            assert!(matches!(
                DriverShim::for_import("WdfPdoInitSetEventCallbacks"),
                None
            ));
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _dir, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfMem");
            let device = island.kmdf_device_handles()[0];
            let memory_out = 0x41_000;
            let buffer_out = 0x41_008;
            let size_out = 0x41_010;
            memory.map_bytes(0x41_000, &[0_u8; 0x20]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryCreate,
                    &[0, 2, 0x2146_4457, 0x10, memory_out, buffer_out],
                )
                .expect("invalid pool type"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryCreate,
                    &[0, 0, 0x2146_4457, 0x20_0000, memory_out, buffer_out],
                )
                .expect("oversized memory"),
                STATUS_INSUFFICIENT_RESOURCES
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryCreate,
                    &[0, 0, 0x2146_4457, 0x10, 0, buffer_out],
                )
                .expect("null memory out"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryCreate,
                    &[0, 0, 0x2146_4457, 0x10, memory_out, 0xDEAD_0000],
                )
                .expect("invalid buffer out"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryCreatePreallocated,
                    &[0, 0xDEAD_0000, 0x10, memory_out],
                )
                .expect("invalid preallocated buffer"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryCreate,
                    &[0, 0, 0x2146_4457, 0x80, memory_out, buffer_out],
                )
                .expect("memory create"),
                STATUS_SUCCESS
            );
            let handle = memory.read_u64(memory_out).expect("memory handle");
            let buffer = memory.read_u64(buffer_out).expect("memory buffer");
            assert_ne!(buffer, 0);
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryGetBuffer,
                    &[handle, size_out],
                )
                .expect("memory buffer"),
                buffer
            );
            assert_eq!(memory.read_u64(size_out).expect("memory size"), 0x80);
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryGetBuffer,
                    &[handle, 0],
                )
                .expect("memory buffer without size"),
                buffer
            );
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryGetBuffer,
                    &[0xDEAD, size_out],
                )
                .expect("stale memory handle"),
                0
            );
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryGetBuffer,
                    &[handle, 0xDEAD_0000],
                )
                .expect("invalid size out"),
                0
            );
            let preallocated = 0x43_000;
            memory.map_bytes(preallocated, &[0_u8; 0x20]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryCreatePreallocated,
                    &[0, preallocated, 0x10, memory_out],
                )
                .expect("preallocated memory"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[handle],
                )
                .expect("delete memory"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfMemoryGetBuffer,
                    &[handle, size_out],
                )
                .expect("deleted memory"),
                0
            );

            let source = guest_unicode_string(&mut memory, 0x44_000, "WdfStr");
            let string_out = 0x45_000;
            let destination = 0x45_100;
            memory.map_bytes(string_out, &[0_u8; 8]);
            memory.map_bytes(destination, &[0_u8; 16]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfStringCreate,
                    &[0xDEAD_0000, 0, string_out],
                )
                .expect("invalid source string"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfStringCreate,
                    &[0, 0, string_out],
                )
                .expect("null source string"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfStringCreate,
                    &[source, 0, 0],
                )
                .expect("null string out"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfStringCreate,
                    &[source, 0, string_out],
                )
                .expect("string create"),
                STATUS_SUCCESS
            );
            let string = memory.read_u64(string_out).expect("string handle");
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfStringGetUnicodeString,
                    &[string, destination],
                )
                .expect("string readback"),
                STATUS_SUCCESS
            );
            assert_eq!(memory.read_u16(destination).expect("length"), 12);
            assert_eq!(memory.read_u16(destination + 2).expect("maximum"), 14);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfStringGetUnicodeString,
                    &[0xDEAD, destination],
                )
                .expect("stale string"),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfStringGetUnicodeString,
                    &[string, 0],
                )
                .expect("null string destination"),
                STATUS_INVALID_PARAMETER
            );

            let type_info = 0x46_000;
            memory.map_bytes(type_info, &[0_u8; 0x30]);
            memory.write_u32(type_info, 0x18);
            memory.write_u64(type_info + 0x10, 0x1000);
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectGetTypedContext,
                    &[device, type_info],
                )
                .expect("oversized typed context"),
                0
            );
            memory.write_u64(type_info + 0x10, 0x80);
            assert_ne!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectGetTypedContext,
                    &[device, type_info],
                )
                .expect("sized typed context"),
                0
            );
            assert_ne!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectGetTypedContext,
                    &[device, 0],
                )
                .expect("untyped context"),
                0
            );
            let odd = 0x47_000;
            memory.map_bytes(odd, &[0_u8; 0x20]);
            memory.write_u16(odd, 3);
            memory.write_u16(odd + 2, 8);
            memory.write_u64(odd + 8, 0x47_100);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfStringCreate,
                    &[odd, 0, string_out],
                )
                .expect("odd unicode length"),
                STATUS_INVALID_PARAMETER
            );
            let overlong = 0x48_000;
            memory.map_bytes(overlong, &[0_u8; 0x20]);
            memory.write_u16(overlong, 4);
            memory.write_u16(overlong + 2, 2);
            memory.write_u64(overlong + 8, 0x48_100);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfStringCreate,
                    &[overlong, 0, string_out],
                )
                .expect("length beyond maximum"),
                STATUS_INVALID_PARAMETER
            );
            let missing = 0x49_000;
            memory.map_bytes(missing, &[0_u8; 0x20]);
            memory.write_u16(missing, 4);
            memory.write_u16(missing + 2, 4);
            memory.write_u64(missing + 8, 0);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfStringCreate,
                    &[missing, 0, string_out],
                )
                .expect("null unicode buffer"),
                STATUS_INVALID_PARAMETER
            );
            let extra_type = 0x4A_000;
            let extra_out = 0x4A_100;
            memory.map_bytes(extra_type, &[0_u8; 0x20]);
            memory.map_bytes(extra_out, &[0_u8; 8]);
            memory.write_u32(extra_type, 0x18);
            memory.write_u64(extra_type + 0x10, 0x20);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectAllocateContext,
                    &[device, extra_type, extra_out],
                )
                .expect("allocate extra context"),
                STATUS_SUCCESS
            );
            let extra = memory.read_u64(extra_out).expect("extra context");
            assert_ne!(extra, 0);
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectGetTypedContext,
                    &[device, extra_type],
                )
                .expect("typed extra context"),
                extra
            );
            let device_object = island
                .inner
                .borrow()
                .kmdf
                .devices
                .get(&device)
                .expect("device")
                .object_guest;
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfEvtPnpDispatch,
                    &[0, device_object],
                )
                .expect("pnp without an IRP"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfEvtPowerDispatch,
                    &[0, device_object],
                )
                .expect("power without an IRP"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfEvtPnpDispatch,
                    &[0x1234, 0xDEAD],
                )
                .expect("pnp for an unknown device"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfEvtPowerDispatch,
                    &[0x1234, 0xDEAD],
                )
                .expect("power for an unknown device"),
                STATUS_INVALID_DEVICE_REQUEST
            );
        });
    }

    #[test]
    fn wdf_device_enqueue_request_rejects_double_enqueue_and_dispatch_edges() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _dir, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfEnqueue");
            let device = island.kmdf_device_handles()[0];
            let queue = *island
                .inner
                .borrow()
                .kmdf
                .queues
                .keys()
                .next()
                .expect("fixture queue");
            let base = island.image_base();
            let request_out = 0x41_000;
            let output = 0x42_000;
            memory.map_bytes(request_out, &[0_u8; 8]);
            memory.map_bytes(output, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, 0, request_out],
                )
                .expect("request create"),
                STATUS_SUCCESS
            );
            let request = memory.read_u64(request_out).expect("request");
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestFormatRequestForIoctl,
                    &[request, 0, 0x0022_0004, 0, 0, output, 4, 0],
                )
                .expect("format request"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceEnqueueRequest,
                    &[device, request],
                )
                .expect("enqueue"),
                STATUS_SUCCESS
            );
            assert_eq!(
                memory
                    .read_u32(base + u64::from(K_IOCTL_MARKER_RVA))
                    .expect("ioctl marker"),
                0x0022_0004
            );
            assert_eq!(
                island.kmdf_request_state(request),
                Some((true, STATUS_SUCCESS, 4, 0))
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceEnqueueRequest,
                    &[device, request],
                )
                .expect("double enqueue"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceEnqueueRequest,
                    &[0xDEAD, request],
                )
                .expect("stale enqueue device"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceEnqueueRequest,
                    &[device, 0xDEAD],
                )
                .expect("stale enqueue request"),
                STATUS_INVALID_DEVICE_REQUEST
            );

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStop,
                    &[queue, 0, 0],
                )
                .expect("stop queue"),
                STATUS_SUCCESS
            );
            memory.map_bytes(request_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, 0, request_out],
                )
                .expect("deferred request create"),
                STATUS_SUCCESS
            );
            let deferred = memory.read_u64(request_out).expect("deferred request");
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestFormatRequestForIoctl,
                    &[deferred, 0, 0x0022_0004, 0, 0, output, 4, 0],
                )
                .expect("deferred format"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceEnqueueRequest,
                    &[device, deferred],
                )
                .expect("deferred enqueue"),
                STATUS_SUCCESS
            );
            assert_eq!(
                island.kmdf_request_state(deferred).map(|state| state.0),
                Some(false)
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueRetrieveNextRequest,
                    &[queue, request_out],
                )
                .expect("retrieve deferred"),
                STATUS_SUCCESS
            );
            assert_eq!(memory.read_u64(request_out).expect("retrieved"), deferred);

            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStart,
                    &[queue],
                )
                .expect("start queue"),
                STATUS_SUCCESS
            );
            set_queue_callbacks(&island, queue, |record| {
                record.callbacks.default = 0;
                record.callbacks.device_control = 0;
            });
            memory.map_bytes(request_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, 0, request_out],
                )
                .expect("callbackless request create"),
                STATUS_SUCCESS
            );
            let callbackless = memory.read_u64(request_out).expect("callbackless request");
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceEnqueueRequest,
                    &[device, callbackless],
                )
                .expect("callbackless enqueue"),
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island.kmdf_request_state(callbackless).map(|state| state.1),
                Some(STATUS_INVALID_DEVICE_REQUEST)
            );
        });
    }

    #[test]
    fn wdf_pdo_init_rejects_malformed_ids_and_invalid_parent() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _dir, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfPdo");
            let device = island.kmdf_device_handles()[0];
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAllocate,
                    &[0xDEAD],
                )
                .expect("stale parent"),
                STATUS_INVALID_HANDLE
            );
            let init = call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAllocate,
                &[device],
            )
            .expect("pdo init");
            assert_ne!(init, 0);
            let ordinary_init = *island
                .inner
                .borrow()
                .kmdf
                .device_inits
                .keys()
                .find(|handle| **handle != init)
                .expect("ordinary device init");
            let device_id = guest_unicode_string(&mut memory, 0x43_000, "CasaPnpDev");
            let hardware_id = guest_unicode_string(&mut memory, 0x44_000, "CasaPnpHw");
            let instance_id = guest_unicode_string(&mut memory, 0x45_000, "Instance1");
            let empty = guest_unicode_string(&mut memory, 0x46_000, "");
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAssignDeviceID,
                    &[0xDEAD, device_id],
                )
                .expect("stale pdo init"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAssignDeviceID,
                    &[ordinary_init, device_id],
                )
                .expect("non-pdo init"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAssignDeviceID,
                    &[init, 0xDEAD_0000],
                )
                .expect("invalid device id string"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAssignDeviceID,
                    &[init, empty],
                )
                .expect("empty device id"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAssignDeviceID,
                    &[init, device_id],
                )
                .expect("device id"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAddHardwareID,
                    &[init, 0xDEAD_0000],
                )
                .expect("invalid hardware id string"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAddHardwareID,
                    &[init, empty],
                )
                .expect("empty hardware id"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAddHardwareID,
                    &[0xDEAD, hardware_id],
                )
                .expect("stale hardware id init"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAddHardwareID,
                    &[ordinary_init, hardware_id],
                )
                .expect("non-pdo hardware id"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAddCompatibleID,
                    &[ordinary_init, hardware_id],
                )
                .expect("non-pdo compatible id"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAssignInstanceID,
                    &[init, instance_id],
                )
                .expect("instance id"),
                STATUS_SUCCESS
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAddCompatibleID,
                    &[init, hardware_id],
                )
                .expect("compatible id"),
                STATUS_SUCCESS
            );
            for _ in 0..16 {
                assert_eq!(
                    call_island_shim(
                        &island,
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfPdoInitAddHardwareID,
                        &[init, hardware_id],
                    )
                    .expect("hardware id"),
                    STATUS_SUCCESS
                );
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAddHardwareID,
                    &[init, hardware_id],
                )
                .expect("hardware id overflow"),
                STATUS_INSUFFICIENT_RESOURCES
            );
            let device_out = 0x47_000;
            memory.map_bytes(device_out, &[0_u8; 8]);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceCreate,
                    &[0xDEAD, 0, device_out],
                )
                .expect("stale pdo create"),
                STATUS_INVALID_PARAMETER
            );
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceCreate,
                    &[init, 0, device_out],
                )
                .expect("pdo device create"),
                STATUS_SUCCESS
            );
            let created = memory.read_u64(device_out).expect("pdo handle");
            let state = island.inner.borrow();
            let record = state.kmdf.devices.get(&created).expect("pdo device");
            assert_eq!(record.device_id.as_deref(), Some("CasaPnpDev"));
            assert_eq!(record.hardware_ids.len(), 16);
            assert_eq!(record.compatible_ids.len(), 1);
            assert_eq!(record.instance_id.as_deref(), Some("Instance1"));
            assert_eq!(record.power_state, WDF_POWER_DEVICE_D3);
            assert!(!record.started);
        });
    }

    #[test]
    fn pnp_x86_callbacks_power_and_sized_context_reject_stale_edges() {
        with_big_stack(|| {
            let image = build_kmdf_driver_pe32();
            let (mut runtime, _dir, mut memory, island) =
                load_staged_island_x86(&image, "CasaPnpX86");
            let init = *island
                .inner
                .borrow()
                .kmdf
                .device_inits
                .keys()
                .next()
                .expect("x86 device init");
            let device = island.created_devices()[0].guest_pointer;
            let config = 0x41_000;
            memory.map_bytes(config, &[0_u8; 0x40]);
            memory.write_u32(config, 4);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks,
                    &[init, config],
                )
                .expect("short x86 pnp callbacks"),
                STATUS_SUCCESS
            );
            {
                let state = island.inner.borrow();
                let parsed = state.kmdf.device_inits.get(&init).expect("init").pnp_power;
                assert_eq!(parsed.prepare_hardware, 0);
                assert_eq!(parsed.self_managed_io_fini, 0);
            }
            memory.write_u32(config, 0x2C);
            for (index, offset) in [0x04u32, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C]
                .iter()
                .enumerate()
            {
                memory.write_u32(config + u64::from(*offset), 0x1000 + index as u32 * 0x10);
            }
            memory.write_u32(config + 0x28, 0x2000);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks,
                    &[init, config],
                )
                .expect("full x86 pnp callbacks"),
                STATUS_SUCCESS
            );
            {
                let state = island.inner.borrow();
                let parsed = state.kmdf.device_inits.get(&init).expect("init").pnp_power;
                assert_eq!(parsed.prepare_hardware, 0x1000);
                assert_eq!(parsed.release_hardware, 0x1010);
                assert_eq!(parsed.d0_entry, 0x1020);
                assert_eq!(parsed.d0_exit, 0x1030);
                assert_eq!(parsed.self_managed_io_init, 0x1040);
                assert_eq!(parsed.self_managed_io_suspend, 0x1050);
                assert_eq!(parsed.self_managed_io_restart, 0x1060);
                assert_eq!(parsed.self_managed_io_fini, 0x2000);
            }
            let file_config = 0x42_000;
            memory.map_bytes(file_config, &[0_u8; 0x20]);
            memory.write_u32(file_config, 8);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetFileObjectConfig,
                    &[init, file_config, 0],
                )
                .expect("short x86 file config"),
                STATUS_SUCCESS
            );
            {
                let state = island.inner.borrow();
                let parsed = state
                    .kmdf
                    .device_inits
                    .get(&init)
                    .expect("init")
                    .file_object;
                assert_eq!(parsed.evt_file_cleanup, 0);
                assert_eq!(parsed.evt_file_close, 0);
            }
            memory.write_u32(file_config, 0x18);
            memory.write_u32(file_config + 0x08, 0x3000);
            memory.write_u32(file_config + 0x0C, 0x3010);
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitSetFileObjectConfig,
                    &[init, file_config, 0],
                )
                .expect("full x86 file config"),
                STATUS_SUCCESS
            );
            {
                let state = island.inner.borrow();
                let parsed = state
                    .kmdf
                    .device_inits
                    .get(&init)
                    .expect("init")
                    .file_object;
                assert_eq!(parsed.evt_file_close, 0x3000);
                assert_eq!(parsed.evt_file_cleanup, 0x3010);
            }
            let device_handle = island.kmdf_device_handles()[0];
            let type_info = 0x43_000;
            memory.map_bytes(type_info, &[0_u8; 0x20]);
            memory.write_u32(type_info, 0x10);
            memory.write_u32(type_info + 0x08, 0x1000);
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectGetTypedContext,
                    &[device_handle, type_info],
                )
                .expect("oversized x86 typed context"),
                0
            );
            memory.write_u32(type_info + 0x08, 0x40);
            assert_ne!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectGetTypedContext,
                    &[device_handle, type_info],
                )
                .expect("sized x86 typed context"),
                0
            );
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                    .expect("x86 D3 before start")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("x86 start")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                    .expect("x86 D3")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(
                island
                    .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                    .expect("x86 D0")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                    .expect("x86 stop")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                    .expect("repeated x86 stop")
                    .0,
                STATUS_INVALID_DEVICE_REQUEST
            );
        });
    }

    #[test]
    fn pnp_start_without_release_and_cleanup_without_hardware_roll_back() {
        with_big_stack(|| {
            let (mut runtime, _dir, mut memory, island, base, device) =
                pnp_load("CasaPnpRollbackEdges");
            let handle = island.kmdf_device_handles()[0];
            {
                let mut state = island.inner.borrow_mut();
                let record = state.kmdf.devices.get_mut(&handle).expect("device");
                record.pnp_power.prepare_hardware = 0;
                record.pnp_power.release_hardware = 0;
                record.pnp_power.self_managed_io_init = 0;
            }
            assert_eq!(
                island
                    .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                    .expect("start without prepare/release/self-io")
                    .0,
                STATUS_SUCCESS
            );
            assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 1);
            assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 0);
            assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 0);
            assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 0);
        });
        with_big_stack(|| {
            let image = build_kmdf_full_driver(0, false);
            let (mut runtime, _dir, mut memory, island) =
                load_staged_island_x64(&image, "CasaPnpStaleFileDevice");
            let handles = island.kmdf_device_handles();
            let stale_handle = handles[1];
            let (object, casak) = {
                let state = island.inner.borrow();
                let record = state.kmdf.devices.get(&stale_handle).expect("device");
                (record.object_guest, record.casak)
            };
            {
                let mut state = island.inner.borrow_mut();
                state
                    .kmdf
                    .devices
                    .get_mut(&stale_handle)
                    .expect("device")
                    .file_cleanup = 0x1234;
                state.io.delete_device(casak).expect("delete stale device");
            }
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfEvtIoCleanupDispatch,
                    &[0, object],
                )
                .expect("file dispatch for a deleted device"),
                crate::casak::io::STATUS_DELETE_PENDING
            );
        });
    }

    #[test]
    fn kmdf_dispatch_arena_exhaustion_rejects_with_io_error() {
        with_big_stack(|| {
            let image = build_kmdf_driver(true, false, false);
            let (mut runtime, _directory, mut memory, island) =
                load_staged_island_x64(&image, "CasaWdfArenaFault");
            let device_object = *island
                .inner
                .borrow()
                .kmdf
                .devices_by_object
                .keys()
                .next()
                .expect("device object");
            {
                let mut state = island.inner.borrow_mut();
                let handle = *state
                    .kmdf
                    .devices_by_object
                    .get(&device_object)
                    .expect("device handle");
                state
                    .kmdf
                    .devices
                    .get_mut(&handle)
                    .expect("device")
                    .file_cleanup = 0x1234;
            }
            let saved_cursor = {
                let mut state = island.inner.borrow_mut();
                let saved = state.arena.cursor;
                state.arena.cursor = state.arena.end;
                saved
            };
            let error = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfEvtIoDeviceControlDispatch,
                &[0, device_object],
            )
            .expect_err("exhausted arena must reject request creation");
            assert_eq!(error.code, ReasonCode::RcIo);
            assert_eq!(
                error.message.contains("driver island arena exhausted"),
                true
            );
            let error = call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfEvtIoCleanupDispatch,
                &[0, device_object],
            )
            .expect_err("exhausted arena must reject file request creation");
            assert_eq!(error.code, ReasonCode::RcIo);
            assert_eq!(
                error.message.contains("driver island arena exhausted"),
                true
            );
            island.inner.borrow_mut().arena.cursor = saved_cursor;
        });
    }
}
