//! Island bookkeeping state, handles, pending-call records and arena.

use super::*;

/// One island device handle.  Handles live in the runtime-level registry so a
/// device opened by one guest thread context can be closed by another.
#[derive(Debug, Clone)]
pub(crate) struct IslandDeviceHandle {
    pub(crate) service_name: String,
    pub(crate) device_guest: u64,
    pub(crate) device_id: ObjectId,
}

/// The crate-visible view of the live island namespace: the loaded driver
/// islands, every live device they created and every symbolic link they
/// installed.  Directory-object enumeration is built from this view, so it
/// always matches the real loaded/removed driver state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IslandNamespace {
    /// Loaded driver/service names (`\Driver\<name>` entries).
    pub(crate) drivers: Vec<String>,
    /// Live device object paths (`\Device\<name>`).
    pub(crate) devices: Vec<String>,
    /// Live device object path to the driver that created it, used to
    /// enumerate the real objects under `\Driver\<name>`.
    pub(crate) device_drivers: Vec<(String, String)>,
    /// Live symbolic links as `(link, target)` pairs.
    pub(crate) symbolic_links: Vec<(String, String)>,
}

/// A real directory-object handle minted by `NtOpenDirectoryObject`.
#[derive(Debug, Clone)]
pub(crate) struct IslandDirectoryHandle {
    /// Canonical directory path (`\Device`, `\Driver`, `\GLOBAL??`, `\??`).
    pub(crate) path: String,
}

/// The island registry of one runtime.  `Rc`-backed island state is not
/// `Send`, but a runtime itself is single-host-threaded (the guest "threads"
/// are emulated contexts), so the mutex serializes registry access and the
/// wrapper is only ever used from the owning host thread.
pub(crate) struct SharedIsland(pub(crate) Box<DriverIsland>);

// SAFETY: every access to the registry happens while the owning runtime is
// mutably borrowed on its single host thread; the mutex only makes the
// process-global side table usable by the type system and orders access from
// guest thread contexts.
unsafe impl Send for SharedIsland {}

#[derive(Default)]
pub(crate) struct IslandRegistry {
    pub(crate) services: BTreeMap<usize, BTreeMap<String, SharedIsland>>,
    pub(crate) device_handles: BTreeMap<usize, BTreeMap<u32, IslandDeviceHandle>>,
    pub(crate) next_device_handle: BTreeMap<usize, u32>,
    pub(crate) directory_handles: BTreeMap<usize, BTreeMap<u32, IslandDirectoryHandle>>,
    pub(crate) next_directory_handle: BTreeMap<usize, u32>,
}

pub(crate) fn island_registry() -> &'static Mutex<IslandRegistry> {
    static REGISTRY: OnceLock<Mutex<IslandRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(IslandRegistry::default()))
}

pub(crate) fn lock_registry() -> MutexGuard<'static, IslandRegistry> {
    island_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A guest callback the current shim defers until its `RefCell` borrow ends.
pub(crate) struct PendingGuestCall {
    pub(crate) entry: u64,
    pub(crate) args: Vec<u64>,
    pub(crate) label: &'static str,
    pub(crate) purpose: PendingPurpose,
}

pub(crate) enum PendingPurpose {
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
    /// Deferred procedure calls drained after IRQL drops below dispatch level.
    Dpcs {
        remaining: VecDeque<GuestCallback>,
        restore_irql: u8,
        final_result: u64,
    },
    /// A WDFWORKITEM callback; the item leaves the queued state once the real
    /// guest callback returns.
    WorkItem {
        handle: u64,
    },
    /// `EvtChildListEnumerateChildren`: the guest callback filled a temporary
    /// `WDFCOLLECTION` of identification descriptions; the framework diffs
    /// it against the child list when the call returns and applies the PnP
    /// arrival/removal accounting.
    ChildListScan {
        list: u64,
        collection: u64,
    },
    /// `WdfInterruptSynchronize`: the guest callback ran with the interrupt
    /// synchronized; the call returns TRUE (the callback's BOOLEAN result
    /// is not surfaced by the framework).
    InterruptSync,
}

pub(crate) struct IslandState {
    pub(crate) arch: GuestArch,
    pub(crate) image_base: u64,
    pub(crate) image_size: u32,
    pub(crate) driver_name: String,
    pub(crate) registry_path: String,
    pub(crate) driver_object_guest: u64,
    pub(crate) registry_path_guest: u64,
    pub(crate) default_dispatch: u64,
    pub(crate) entry_rva: u32,
    pub(crate) entry_guest: u64,
    pub(crate) unload_rva: Option<u32>,
    pub(crate) unload_guest: Option<u64>,
    pub(crate) status: i32,
    pub(crate) loaded: bool,
    pub(crate) unloaded: bool,
    pub(crate) io: IoManager,
    pub(crate) casak_driver: ObjectId,
    pub(crate) devices: Vec<IslandDevice>,
    pub(crate) device_ids: BTreeMap<u64, ObjectId>,
    pub(crate) debug_log: Vec<String>,
    pub(crate) imports: ImportReport,
    pub(crate) pool: TaggedPool,
    pub(crate) pool_blocks: BTreeMap<u64, PoolBlock>,
    pub(crate) irp_ids: BTreeMap<u64, IrpId>,
    pub(crate) irp_guests: BTreeMap<IrpId, u64>,
    pub(crate) symbolic_links: Vec<(String, String)>,
    pub(crate) kmdf: KmdfState,
    pub(crate) kernel: KernelState,
    pub(crate) process: ProcessManager,
    pub(crate) current_process: ProcessId,
    pub(crate) current_thread: ThreadId,
    pub(crate) diagnostics: DiagnosticsManager,
    pub(crate) alpc: AlpcManager,
    pub(crate) alpc_handles: BTreeMap<u64, AlpcPort>,
    pub(crate) next_alpc_handle: u64,
    pub(crate) executive: Executive,
    pub(crate) system_threads: SystemThreadManager,
    pub(crate) interrupts: InterruptManager,
    pub(crate) thread_cpus: BTreeMap<ThreadId, CpuState>,
    pub(crate) thread_quantum: Duration,
    pub(crate) slice_deadline: Option<Instant>,
    pub(crate) current_system_thread: Option<ThreadId>,
    pub(crate) pending_interrupts: VecDeque<u32>,
    pub(crate) notification_waits: u64,
    pub(crate) removed_device_objects: BTreeSet<u64>,
    pub(crate) arena: IslandArena,
}

pub(crate) struct IslandArena {
    pub(crate) cursor: u64,
    pub(crate) end: u64,
}

impl IslandArena {
    pub(crate) fn alloc(
        &mut self,
        memory: &mut MemoryImage,
        len: usize,
        align: u64,
    ) -> AppResult<u64> {
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

/// One acquired spin lock: the IRQL the acquire raised to and the IRQL the
/// release must restore.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SpinLockState {
    pub(crate) raised_from: u8,
}

/// One real `KDPC`.  The routine is guest code and runs only when IRQL drops
/// below `DISPATCH_LEVEL`, exactly like the kernel's software interrupt.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DpcState {
    pub(crate) routine: u64,
    pub(crate) context: u64,
    pub(crate) arg1: u64,
    pub(crate) arg2: u64,
    pub(crate) queued: bool,
}

/// One real `KEVENT`.  `gate` is shared with the (bounded) waiting path so a
/// concurrent signal can release a parked wait.
#[derive(Debug, Clone)]
pub(crate) struct KernelEvent {
    pub(crate) event_type: u32,
    pub(crate) signaled: bool,
    pub(crate) gate: Arc<(Mutex<bool>, Condvar)>,
}

/// One locked memory descriptor list.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MdlState {
    pub(crate) virtual_address: u64,
    pub(crate) byte_count: u64,
    pub(crate) write_access: bool,
    pub(crate) locked: bool,
}

/// One kernel lookaside list, backed by the real [`crate::casak::exec::LookasideList`]
/// and a stable guest buffer per cached host block.
pub(crate) struct IslandLookaside {
    pub(crate) list: crate::casak::exec::LookasideList,
    pub(crate) entry_size: usize,
    pub(crate) guest_by_ptr: BTreeMap<usize, u64>,
    pub(crate) block_by_guest: BTreeMap<u64, crate::casak::exec::LookasideBlock>,
}

/// The island's kernel personality state that is not owned by CasaK: current
/// IRQL, spin locks, DPCs, dispatcher events, MDLs, lookaside lists and real
/// registry key handles.
#[derive(Default)]
pub(crate) struct KernelState {
    pub(crate) irql: u8,
    pub(crate) spinlocks: BTreeMap<u64, SpinLockState>,
    pub(crate) dpcs: BTreeMap<u64, DpcState>,
    pub(crate) pending_dpcs: VecDeque<u64>,
    pub(crate) events: BTreeMap<u64, KernelEvent>,
    pub(crate) mdls: BTreeMap<u64, MdlState>,
    pub(crate) lookasides: BTreeMap<u64, IslandLookaside>,
    pub(crate) registry_keys: BTreeMap<u64, String>,
    pub(crate) next_key_handle: u64,
}

#[cfg(test)]
thread_local! {
    /// The island removed by the most recent `NtUnloadDriver`; tests inspect
    /// its teardown evidence after the registration has been forgotten.
    pub(crate) static LAST_UNLOADED_DRIVER: RefCell<Option<DriverIsland>> = RefCell::new(None);
}

thread_local! {
    pub(crate) static ACTIVE_ISLAND: RefCell<Option<Rc<RefCell<IslandState>>>> = const { RefCell::new(None) };
}
