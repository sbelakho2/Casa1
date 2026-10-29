//! KMDF object model.

use super::*;

pub(crate) struct PendingIoTargetSend {
    pub(crate) irp: IrpId,
    pub(crate) irp_guest: u64,
    pub(crate) entry: u64,
    pub(crate) device_object: u64,
    pub(crate) system_buffer: u64,
    pub(crate) output_ptr: u64,
    pub(crate) output_len: usize,
    pub(crate) bytes_returned: u64,
    pub(crate) request: u64,
    pub(crate) target: u64,
    pub(crate) io_control: u32,
    pub(crate) input_ptr: u64,
    pub(crate) input_len: u32,
    pub(crate) saved: (u64, u64, u64, u32, u32, u32, u64),
}

/// One real (guest-visible) KMDF object.
/// `WDF_PNPPOWER_EVENT_CALLBACKS` subset the framework invokes through the
/// island.  Only callbacks a driver actually registers are non-zero.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct KmdfPnpPowerCallbacks {
    pub(crate) prepare_hardware: u64,
    pub(crate) release_hardware: u64,
    pub(crate) d0_entry: u64,
    pub(crate) d0_exit: u64,
    pub(crate) self_managed_io_init: u64,
    pub(crate) self_managed_io_suspend: u64,
    pub(crate) self_managed_io_restart: u64,
    pub(crate) self_managed_io_fini: u64,
    pub(crate) surprise_removal: u64,
}

/// `WDF_FILEOBJECT_CONFIG` subset: the cleanup/close callbacks that map onto
/// `IRP_MJ_CLEANUP` and `IRP_MJ_CLOSE`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct KmdfFileObjectConfig {
    pub(crate) evt_file_cleanup: u64,
    pub(crate) evt_file_close: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfDeviceInit {
    pub(crate) device_type: u32,
    pub(crate) io_type: u32,
    pub(crate) name: Option<String>,
    pub(crate) pnp_power: KmdfPnpPowerCallbacks,
    pub(crate) file_object: KmdfFileObjectConfig,
    pub(crate) is_pdo: bool,
    pub(crate) power_policy_owner: bool,
    pub(crate) parent_device: Option<u64>,
    pub(crate) device_id: Option<String>,
    pub(crate) hardware_ids: Vec<String>,
    pub(crate) compatible_ids: Vec<String>,
    pub(crate) instance_id: Option<String>,
    /// Set for inits from `WdfControlDeviceInitAllocate`: the resulting
    /// device is a non-PnP control device finalized by
    /// `WdfControlFinishInitializing`.
    pub(crate) is_control: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfDevice {
    pub(crate) object_guest: u64,
    pub(crate) casak: ObjectId,
    pub(crate) name: String,
    pub(crate) context_guest: u64,
    pub(crate) pnp_power: KmdfPnpPowerCallbacks,
    pub(crate) file_cleanup: u64,
    pub(crate) file_close: u64,
    pub(crate) file_object: u64,
    pub(crate) power_state: u32,
    pub(crate) started: bool,
    pub(crate) removed: bool,
    pub(crate) surprised: bool,
    pub(crate) idle: bool,
    pub(crate) idle_refs: u32,
    pub(crate) device_id: Option<String>,
    pub(crate) hardware_ids: Vec<String>,
    pub(crate) compatible_ids: Vec<String>,
    pub(crate) instance_id: Option<String>,
    /// Control (non-PnP) device from `WdfControlDeviceInitAllocate`.
    pub(crate) is_control: bool,
    /// `WdfControlFinishInitializing` completed for this control device.
    pub(crate) control_finished: bool,
}

/// One `WDFMEMORY` allocation: the framework object owns this guest buffer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KmdfMemory {
    pub(crate) buffer: u64,
    pub(crate) size: usize,
    /// Set for `WdfMemoryCreatePreallocated` objects: only these may be
    /// rebound by `WdfMemoryAssign`.
    pub(crate) preallocated: bool,
}

/// One `WDFSTRING` allocation: an owned copy of the source `UNICODE_STRING`.
#[derive(Debug, Clone)]
pub(crate) struct KmdfString {
    pub(crate) buffer: u64,
    pub(crate) length: u16,
    pub(crate) maximum: u16,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub(crate) struct KmdfQueueCallbacks {
    pub(crate) default: u64,
    pub(crate) read: u64,
    pub(crate) write: u64,
    pub(crate) device_control: u64,
    pub(crate) internal_device_control: u64,
    pub(crate) stop: u64,
    pub(crate) resume: u64,
    pub(crate) canceled_on_queue: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfQueue {
    pub(crate) device: u64,
    pub(crate) callbacks: KmdfQueueCallbacks,
    pub(crate) dispatch_type: u32,
    pub(crate) default_queue: bool,
    pub(crate) queued: VecDeque<u64>,
    pub(crate) in_flight: BTreeSet<u64>,
    pub(crate) stopped: bool,
    pub(crate) draining: bool,
    pub(crate) power_managed: bool,
    pub(crate) context_guest: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfRequest {
    pub(crate) irp: IrpId,
    pub(crate) device: Option<u64>,
    pub(crate) io_control: u32,
    pub(crate) input_len: u32,
    pub(crate) output_len: u32,
    pub(crate) input_guest: u64,
    pub(crate) output_guest: u64,
    pub(crate) completed: bool,
    pub(crate) status: i32,
    pub(crate) information: usize,
    pub(crate) context_guest: u64,
    pub(crate) queue: Option<u64>,
    pub(crate) outer_irp_guest: u64,
    pub(crate) major: IrpMajorFunction,
    pub(crate) target: Option<u64>,
    pub(crate) canceled: bool,
    pub(crate) cancelable: bool,
    pub(crate) cancel_callback: u64,
    pub(crate) impersonating: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfIoTarget {
    pub(crate) device: u64,
    pub(crate) context_guest: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KmdfObjectKind {
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
    SpinLock,
    Timer,
    WorkItem,
    Collection,
    LookasideList,
    Interrupt,
    DmaEnabler,
    DmaTransaction,
    UsbTarget,
    UsbPipe,
    ChildList,
    ChildIterator,
    CmResourceList,
}

impl KmdfObjectKind {
    /// Per-kind context layout: the default context bytes allocated when the
    /// caller asks for none, and the alignment of the context block.
    pub(crate) const fn layout(self) -> (usize, usize) {
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
            Self::SpinLock => (0x20, 8),
            Self::Timer => (0x40, 8),
            Self::WorkItem => (0x40, 8),
            Self::Collection => (0x20, 8),
            Self::LookasideList => (0x20, 8),
            Self::Interrupt => (0x40, 8),
            Self::DmaEnabler => (0x40, 8),
            Self::DmaTransaction => (0x40, 8),
            Self::UsbTarget => (0x40, 8),
            Self::UsbPipe => (0x20, 8),
            Self::ChildList => (0x40, 8),
            Self::ChildIterator => (0x20, 8),
            Self::CmResourceList => (0x20, 8),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct KmdfObjectAttributes {
    pub(crate) evt_cleanup: u64,
    pub(crate) evt_destroy: u64,
    pub(crate) parent: Option<u64>,
    pub(crate) context_size_override: usize,
    pub(crate) context_type_info: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfObject {
    pub(crate) kind: KmdfObjectKind,
    pub(crate) parent: Option<u64>,
    pub(crate) children: BTreeSet<u64>,
    pub(crate) context_guest: u64,
    pub(crate) context_size: usize,
    pub(crate) context_type: u64,
    pub(crate) extra_contexts: Vec<(u64, u64, usize)>,
    pub(crate) evt_cleanup: u64,
    pub(crate) evt_destroy: u64,
    pub(crate) deleted: bool,
    /// Outstanding `WdfObjectReference` count.  An object with references is
    /// not destroyed by `WdfObjectDelete` until the last reference is
    /// released; the delete then completes with its cleanup/destroy
    /// callbacks and parent-child cascade.
    pub(crate) references: u32,
    /// `WdfObjectDelete` was called while references were outstanding; the
    /// object dies when the count reaches zero.
    pub(crate) delete_pending: bool,
}

/// A guest callback scheduled by a shim and executed once the island state
/// borrow is released.
#[derive(Debug, Clone)]
pub(crate) struct GuestCallback {
    pub(crate) entry: u64,
    pub(crate) args: Vec<u64>,
    pub(crate) label: &'static str,
}

/// A real blocking wait lock.  The gate is shared with the waiting path so a
/// release on another host thread wakes a parked guest callback.
#[derive(Clone)]
pub(crate) struct KmdfWaitLock {
    pub(crate) gate: Arc<(Mutex<bool>, Condvar)>,
}

/// One `WDFSPINLOCK`.  Acquiring raises IRQL to `DISPATCH_LEVEL`; releasing
/// restores the IRQL that was current before the acquire.
#[derive(Debug, Clone)]
pub(crate) struct KmdfSpinLock {
    pub(crate) held: bool,
    pub(crate) raised_from: u8,
}

/// `WDF_TIMER_CONFIG` subset: callback.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct KmdfTimerConfig {
    pub(crate) evt_timer: u64,
}

/// One `WDFTIMER`.  Zero-due timers fire their real guest callback at start;
/// longer deadlines are recorded and remain observable/ stoppable.
#[derive(Debug, Clone)]
pub(crate) struct KmdfTimer {
    pub(crate) config: KmdfTimerConfig,
    pub(crate) running: bool,
    pub(crate) fired: u64,
    pub(crate) context_guest: u64,
}

/// `WDF_WORKITEM_CONFIG` subset.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct KmdfWorkItemConfig {
    pub(crate) evt_work_item: u64,
}

/// One `WDFWORKITEM`.
#[derive(Debug, Clone)]
pub(crate) struct KmdfWorkItem {
    pub(crate) config: KmdfWorkItemConfig,
    pub(crate) queued: bool,
    pub(crate) completed: u64,
    pub(crate) context_guest: u64,
}

/// One `WDFCOLLECTION`: an ordered set of guest object handles.  Duplicates
/// are rejected and removal of a non-member is an error, matching the KMDF
/// collection contract.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfCollection {
    pub(crate) items: Vec<u64>,
    pub(crate) max_size: usize,
}

/// One `WDFLOOKASIDE`: fixed-size block cache with real reuse-by-pointer
/// accounting over guest buffers allocated from the island arena.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfLookaside {
    pub(crate) block_size: usize,
    pub(crate) max_depth: usize,
    /// Freed blocks available for reuse, most recent first.
    pub(crate) free: Vec<u64>,
    pub(crate) in_use: usize,
    pub(crate) hits: u64,
    pub(crate) misses: u64,
}

/// A memory object allocated from a lookaside list; deletion returns the
/// block to the owning lookaside.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct KmdfLookasideBlock {
    pub(crate) lookaside: u64,
    pub(crate) block: u64,
}

/// `WDF_INTERRUPT_CONFIG` subset.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct KmdfInterruptConfig {
    pub(crate) evt_isr: u64,
    pub(crate) evt_dpc: u64,
}

/// One `WDFINTERRUPT`: connected to the island's virtual interrupt
/// controller; the ISR runs at device IRQL and may queue the DPC.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfInterrupt {
    pub(crate) config: KmdfInterruptConfig,
    pub(crate) device: u64,
    /// Virtual controller id (`InterruptManager`).
    pub(crate) controller: u64,
    pub(crate) context_guest: u64,
    pub(crate) connected: bool,
    pub(crate) disabled: u32,
    pub(crate) dpc_queued: u64,
}

/// DMA profiles honored by the mini-DMA channel model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KmdfDmaProfile {
    /// `WdfDmaProfileShort`: transfers limited to 64 KB single-segment.
    Short,
    /// `WdfDmaProfileLong`: single physically-contiguous segment up to the
    /// enabler's `MaximumLength`.
    Long,
    /// `WdfDmaProfileScatterGather`: multi-segment transfers.
    ScatterGather,
}

/// `WDF_DMA_ENABLER_CONFIG` subset.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct KmdfDmaEnablerConfig {
    pub(crate) profile: KmdfDmaProfile,
    pub(crate) maximum_length: u64,
}

/// One `WDFDMAENABLER`: the mini-DMA channel contract (profile, maximum
/// transfer length, segment accounting).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfDmaEnabler {
    pub(crate) config: KmdfDmaEnablerConfig,
    pub(crate) device: u64,
    pub(crate) active_transactions: u32,
    pub(crate) completed_transactions: u64,
    pub(crate) transferred_bytes: u64,
}

/// One `WDFDMATRANSACTION` in the mini-DMA channel model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KmdfDmaPhase {
    /// Created but not initialized; `Execute` fails.
    Created,
    /// Initialized with a length; ready to execute.
    Initialized,
    /// Executed; transfer counts are available.
    Executed,
    /// Released back to the enabler; must be re-initialized.
    Released,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct KmdfDmaTransaction {
    pub(crate) enabler: u64,
    pub(crate) phase: KmdfDmaPhase,
    pub(crate) direction: u32,
    pub(crate) length: u64,
    pub(crate) transferred: u64,
    pub(crate) segments: u64,
}

/// One USB endpoint parsed from a real configuration descriptor.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct KmdfUsbEndpoint {
    /// Endpoint address including the direction bit (`0x80` = IN).
    pub(crate) address: u8,
    pub(crate) attributes: u8,
    pub(crate) max_packet: u16,
    pub(crate) interval: u8,
}

/// `WDF_USB_DEVICE_CREATE_CONFIG` subset plus the parsed endpoint table.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfUsbTarget {
    pub(crate) device: u64,
    pub(crate) usb_version: u16,
    pub(crate) vendor_id: u16,
    pub(crate) product_id: u16,
    pub(crate) endpoints: Vec<KmdfUsbEndpoint>,
    /// Per-pipe stall state (a stalled pipe rejects transfers until
    /// reset), keyed by endpoint index.
    pub(crate) stalled: BTreeSet<u32>,
    pub(crate) aborted: BTreeSet<u32>,
    /// Device-side staged data per endpoint index: writes append here,
    /// reads consume from here (the island's loopback device model).
    pub(crate) staged: BTreeMap<u32, Vec<u8>>,
    pub(crate) transfers: u64,
    pub(crate) transferred_bytes: u64,
}

/// One `WDFPIPE`: a configured pipe over one endpoint of a USB target.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct KmdfUsbPipe {
    pub(crate) target: u64,
    pub(crate) endpoint_index: u32,
    pub(crate) in_endpoint: bool,
    pub(crate) bulk: bool,
    pub(crate) max_packet: u16,
}

/// One open `WDFKEY`: a path in the GE-backed registry store.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfRegistryKey {
    pub(crate) path: String,
    pub(crate) access: u32,
}

/// One `WDFCHILDLIST`: the bus driver's dynamic child descriptions plus the
/// PnP arrival/removal accounting.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct KmdfChildList {
    pub(crate) device: u64,
    pub(crate) evt_enumerate_children: u64,
    pub(crate) descriptions: Vec<u64>,
    pub(crate) arrivals: u64,
    pub(crate) removals: u64,
}

/// One `WDFCHILDITERATOR`: a live position over a child list.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct KmdfChildIterator {
    pub(crate) list: u64,
    pub(crate) position: usize,
}

/// One `WDFCMRESLIST`: a guest-visible `CM_PARTIAL_RESOURCE_LIST` with
/// `descriptors` partial resource descriptors.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct KmdfCmResourceList {
    pub(crate) guest: u64,
    pub(crate) descriptors: usize,
}

/// The KMDF shim subset's state: a real WDFDRIVER handle, device-init objects,
/// CasaK-backed WDFDEVICEs, queues, requests, targets and wait locks, plus the
/// framework dispatch context for the IRP currently being delivered.
#[allow(dead_code)]
#[derive(Default)]
pub(crate) struct KmdfState {
    pub(crate) driver_handle: u64,
    pub(crate) driver_object_guest: u64,
    pub(crate) evt_driver_device_add: u64,
    pub(crate) evt_driver_unload: u64,
    pub(crate) driver_pool_tag: u32,
    pub(crate) driver_init_flags: u32,
    pub(crate) driver_unload_ran: bool,
    pub(crate) device_inits: BTreeMap<u64, KmdfDeviceInit>,
    pub(crate) devices: BTreeMap<u64, KmdfDevice>,
    pub(crate) devices_by_object: BTreeMap<u64, u64>,
    pub(crate) queues: BTreeMap<u64, KmdfQueue>,
    pub(crate) requests: BTreeMap<u64, KmdfRequest>,
    pub(crate) iotargets: BTreeMap<u64, KmdfIoTarget>,
    pub(crate) objects: BTreeMap<u64, KmdfObject>,
    pub(crate) wait_locks: BTreeMap<u64, KmdfWaitLock>,
    pub(crate) memories: BTreeMap<u64, KmdfMemory>,
    pub(crate) strings: BTreeMap<u64, KmdfString>,
    pub(crate) spinlocks: BTreeMap<u64, KmdfSpinLock>,
    pub(crate) timers: BTreeMap<u64, KmdfTimer>,
    pub(crate) work_items: BTreeMap<u64, KmdfWorkItem>,
    pub(crate) collections: BTreeMap<u64, KmdfCollection>,
    pub(crate) lookasides: BTreeMap<u64, KmdfLookaside>,
    pub(crate) lookaside_blocks: BTreeMap<u64, KmdfLookasideBlock>,
    pub(crate) interrupts: BTreeMap<u64, KmdfInterrupt>,
    /// Guest-held interrupt locks (`WdfInterruptAcquireLock`).
    pub(crate) interrupt_locks: BTreeMap<u64, bool>,
    pub(crate) next_interrupt_vector: u32,
    pub(crate) dma_enablers: BTreeMap<u64, KmdfDmaEnabler>,
    pub(crate) dma_transactions: BTreeMap<u64, KmdfDmaTransaction>,
    pub(crate) usb_targets: BTreeMap<u64, KmdfUsbTarget>,
    pub(crate) usb_pipes: BTreeMap<u64, KmdfUsbPipe>,
    /// Open `WDFKEY` handles (not WDFOBJECTs; closed with `WdfRegistryClose`).
    pub(crate) registry_keys: BTreeMap<u64, KmdfRegistryKey>,
    pub(crate) next_registry_key: u64,
    pub(crate) child_lists: BTreeMap<u64, KmdfChildList>,
    pub(crate) child_iterators: BTreeMap<u64, KmdfChildIterator>,
    /// Identification description -> child PDO handle for arrived children.
    pub(crate) child_devices: BTreeMap<u64, u64>,
    pub(crate) cm_resource_lists: BTreeMap<u64, KmdfCmResourceList>,
    pub(crate) framework_dispatch: u64,
    pub(crate) framework_dispatches: BTreeMap<u8, u64>,
    pub(crate) current_irp_guest: u64,
    pub(crate) current_device_guest: u64,
    pub(crate) current_system_buffer: u64,
    pub(crate) current_input_len: u32,
    pub(crate) current_output_len: u32,
    pub(crate) current_io_control: u32,
    pub(crate) current_request: u64,
    pub(crate) ioctl_dispatches: u64,
    pub(crate) read_dispatches: u64,
    pub(crate) write_dispatches: u64,
    pub(crate) cleanup_dispatches: u64,
    pub(crate) close_dispatches: u64,
    pub(crate) file_cleanup_dispatches: u64,
    pub(crate) file_close_dispatches: u64,
    pub(crate) pnp_start_dispatches: u64,
    pub(crate) pnp_stop_dispatches: u64,
    pub(crate) pnp_remove_dispatches: u64,
    pub(crate) power_d0_dispatches: u64,
    pub(crate) power_d3_dispatches: u64,
    pub(crate) queued_dispatches: u64,
    pub(crate) manual_retrievals: u64,
    pub(crate) cancel_dispatches: u64,
    pub(crate) stop_dispatches: u64,
    pub(crate) resume_dispatches: u64,
    pub(crate) iotarget_sends: u64,
    pub(crate) parked_acquires: u64,
    pub(crate) driver_unload_calls: u64,
    pub(crate) timer_fires: u64,
    pub(crate) work_item_runs: u64,
    pub(crate) power_managed_defers: u64,
    pub(crate) surprise_removals: u64,
    pub(crate) irp_forwards: u64,
    pub(crate) collection_adds: u64,
    pub(crate) collection_removes: u64,
    pub(crate) lookaside_allocations: u64,
    pub(crate) interrupt_isrs: u64,
    pub(crate) interrupt_dpcs: u64,
    pub(crate) dma_executions: u64,
    pub(crate) usb_transfers: u64,
    pub(crate) registry_value_writes: u64,
    pub(crate) child_arrivals: u64,
    pub(crate) child_removals: u64,
    pub(crate) request_impersonations: u64,
    pub(crate) parent_queue_forwards: u64,
    pub(crate) object_references: u64,
    pub(crate) control_devices_finished: u64,
    pub(crate) symbolic_links_created: u64,
}
