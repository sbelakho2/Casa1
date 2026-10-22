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
use std::collections::BTreeMap;
use std::rc::Rc;

use serde_json::json;

use crate::casak::exec::{PoolBlock, PoolTag, TaggedPool};
use crate::casak::io::{
    DeviceExtension, DeviceFlags, IoManager, IrpId, IrpMajorFunction, IrpParameterBlock,
    STATUS_CANCELLED, STATUS_INVALID_PARAMETER,
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

/// `STATUS_IMAGE_ALREADY_LOADED` — the service is already loaded.
const STATUS_IMAGE_ALREADY_LOADED: i32 = 0xC000_010Eu32 as i32;
/// `\Registry\Machine\System\CurrentControlSet\Services\` (lowercase).
const SERVICE_REGISTRY_PREFIX: &str = "system\\currentcontrolset\\services\\";
/// `\Registry\Machine\` (lowercase), including the trailing separator.
const MACHINE_REGISTRY_PREFIX: &str = "\\registry\\machine\\";

thread_local! {
    /// Drivers loaded through `NtLoadDriver`, keyed by (runtime identity,
    /// lowercased service name).  Guest execution is single-threaded, so the
    /// registration is per-thread; the runtime identity keeps two runtimes in
    /// one thread from sharing a service namespace.
    static LOADED_DRIVER_SERVICES: RefCell<BTreeMap<(usize, String), DriverIsland>> =
        RefCell::new(BTreeMap::new());
    /// Handles opened onto an island device namespace path, keyed by
    /// (runtime identity, handle value).  These handles are owned by the
    /// island namespace, not the Win32 file table.
    static DEVICE_HANDLES: RefCell<BTreeMap<(usize, u32), IslandDeviceHandle>> =
        RefCell::new(BTreeMap::new());
    /// Next synthetic handle value per runtime.
    static NEXT_DEVICE_HANDLE: RefCell<BTreeMap<usize, u32>> = RefCell::new(BTreeMap::new());
}

#[derive(Debug, Clone)]
struct IslandDeviceHandle {
    service_name: String,
    device_guest: u64,
    device_id: ObjectId,
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
                    "unresolved driver imports: {}",
                    unresolved
                        .iter()
                        .map(|(dll, symbol, _)| format!("{dll}!{symbol}"))
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
        if self.has_open_device_handles() {
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

        let mut state = inner.borrow_mut();
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
        if LOADED_DRIVER_SERVICES.with(|map| map.borrow().contains_key(&key)) {
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
        LOADED_DRIVER_SERVICES.with(|map| {
            map.borrow_mut().insert(key, island);
        });
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
        let Some(mut island) = LOADED_DRIVER_SERVICES.with(|map| map.borrow_mut().remove(&key))
        else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if island.has_open_device_handles() {
            LOADED_DRIVER_SERVICES.with(|map| {
                map.borrow_mut().insert(key, island);
            });
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
                LOADED_DRIVER_SERVICES.with(|map| {
                    map.borrow_mut().insert(key, island);
                });
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
    pub fn has_open_device_handles(&self) -> bool {
        let state = self.inner.borrow();
        DEVICE_HANDLES.with(|handles| {
            handles.borrow().values().any(|handle| {
                handle.service_name == state.driver_name
                    && state.device_ids.values().any(|id| *id == handle.device_id)
            })
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

    /// Build a real CasaK IRP and a guest `_IRP`/`IO_STACK_LOCATION`, then
    /// invoke the driver's real `MajorFunction` guest code with the guest IRP
    /// pointer.  Returns `(NTSTATUS, Information)`.
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
        let inner = self.inner.clone();
        let (arch, default_dispatch, irp, irp_guest, stack_guest, system_buffer_guest, handler) = {
            let mut state = inner.borrow_mut();
            let Some(casak_device) = state.device_ids.get(&device_guest).copied() else {
                return Ok((STATUS_INVALID_HANDLE, 0));
            };
            let buffer_len = input_len.max(output_len) as usize;
            let parameters = IrpParameterBlock::new(major, 0, input_len as usize);
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
            io_control_code,
            input_len,
            output_len,
            byte_offset,
        )?;

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
fn build_guest_irp(
    memory: &mut MemoryImage,
    arch: GuestArch,
    irp: u64,
    stack: u64,
    system_buffer: u64,
    device_object: u64,
    user_buffer: u64,
    major: IrpMajorFunction,
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
    memory.write_u8(stack + 1, 0);
    memory.write_u8(stack + 2, 0);
    memory.write_u8(stack + 3, 0);
    match arch {
        GuestArch::X64 => {
            match major {
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
    ) -> AppResult<()> {
        match function {
            DriverShim::DbgPrint => self.dbg_print(runtime, state, memory),
            DriverShim::IoCreateDevice => self.io_create_device(state, memory),
            DriverShim::IoDeleteDevice => self.io_delete_device(state, memory),
            DriverShim::IoCreateSymbolicLink => self.io_create_symbolic_link(state, memory),
            DriverShim::IoDeleteSymbolicLink => self.io_delete_symbolic_link(state, memory),
            DriverShim::IoAllocateIrp => self.io_allocate_irp(state, memory),
            DriverShim::IoFreeIrp => self.io_free_irp(state, memory),
            DriverShim::RtlInitUnicodeString => self.rtl_init_unicode_string(state, memory),
            DriverShim::IofCompleteRequest | DriverShim::IoCompleteRequest => {
                self.io_complete_request(state, memory)
            }
            DriverShim::ExAllocatePoolWithTag => self.ex_allocate_pool(state, memory),
            DriverShim::ExFreePoolWithTag => self.ex_free_pool(state, memory),
            DriverShim::IrpDispatch => {
                set_status(state, crate::casak::io::STATUS_INVALID_DEVICE_REQUEST);
                Ok(())
            }
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
            )?;
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
        let device_name = if raw_name.is_empty() {
            None
        } else {
            Some(strip_device_prefix(&raw_name).to_string())
        };
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
                Err(status) => {
                    set_status(state, status);
                    return Ok(());
                }
            };

        let guest = match self.arena.alloc(memory, 0x180, 16) {
            Ok(guest) => guest,
            Err(_) => {
                let _ = self.io.delete_device(device);
                set_status(state, STATUS_INSUFFICIENT_RESOURCES);
                return Ok(());
            }
        };
        let extension_guest = if extension_size > 0 {
            match self.arena.alloc(memory, extension_size, 8) {
                Ok(extension_guest) => extension_guest,
                Err(_) => {
                    let _ = self.io.delete_device(device);
                    set_status(state, STATUS_INSUFFICIENT_RESOURCES);
                    return Ok(());
                }
            }
        } else {
            0
        };
        let arch = self.arch;
        match arch {
            GuestArch::X64 => {
                let previous_head = memory.read_u64(self.driver_object_guest + 0x08)?;
                memory.write_u16(guest, DEVICE_OBJECT_TYPE);
                memory.write_u16(guest + 0x02, DEVICE_OBJECT_SIZE);
                memory.write_u32(guest + 0x04, 1);
                memory.write_u64(guest + 0x08, self.driver_object_guest);
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
                memory.write_u64(self.driver_object_guest + 0x08, guest);
                write_guest_pointer(memory, output_pointer, guest, arch)?;
            }
            GuestArch::X86 => {
                let previous_head =
                    read_guest_pointer(memory, self.driver_object_guest + 0x04, arch)?;
                memory.write_u16(guest, DEVICE_OBJECT_TYPE);
                memory.write_u16(guest + 0x02, DEVICE_OBJECT_SIZE_X86);
                memory.write_u32(guest + 0x04, 1);
                write_guest_pointer(memory, guest + 0x08, self.driver_object_guest, arch)?;
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
                write_guest_pointer(memory, self.driver_object_guest + 0x04, guest, arch)?;
                write_guest_pointer(memory, output_pointer, guest, arch)?;
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
        set_status(state, STATUS_SUCCESS);
        Ok(())
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
}

/// True when `handle` was minted by an island device-namespace open.
pub(crate) fn is_island_device_handle(runtime: &PeHostRuntime, handle: u32) -> bool {
    DEVICE_HANDLES.with(|handles| {
        handles
            .borrow()
            .contains_key(&(runtime_identity(runtime), handle))
    })
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
    let handle = NEXT_DEVICE_HANDLE.with(|next| {
        let mut next = next.borrow_mut();
        let counter = next.entry(runtime_id).or_insert(0);
        let handle = DEVICE_HANDLE_BASE.wrapping_add(*counter);
        *counter = counter.wrapping_add(1);
        handle
    });
    DEVICE_HANDLES.with(|handles| {
        handles.borrow_mut().insert((runtime_id, handle), device);
    });
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
    let Some(device) =
        DEVICE_HANDLES.with(|handles| handles.borrow().get(&(runtime_id, handle)).cloned())
    else {
        return Ok(None);
    };
    let key = loaded_driver_key(runtime, &device.service_name);
    let island = LOADED_DRIVER_SERVICES
        .with(|map| map.borrow().get(&key).map(|island| island.inner.clone()));
    let Some(inner) = island else {
        return Ok(Some((STATUS_INVALID_HANDLE, 0)));
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
    LOADED_DRIVER_SERVICES.with(|map| {
        for ((identity, _), island) in map.borrow().iter() {
            if *identity != runtime_id {
                continue;
            }
            let state = island.inner.borrow();
            let direct = state
                .devices
                .iter()
                .find(|device| !device.deleted && device.name.eq_ignore_ascii_case(&path));
            let link_target = state.symbolic_links.iter().find_map(|(link, target)| {
                link.eq_ignore_ascii_case(&path).then_some(target.as_str())
            });
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
    })
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
    let mut island = island.borrow_mut();
    island.handle_shim(runtime, state, memory, function)
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
            )?;
        }
    }
    let major_offset = major_function_offset(arch);
    for index in 0..MAJOR_FUNCTION_COUNT {
        write_guest_pointer(
            memory,
            driver_object + major_offset + index as u64 * arch.pointer_bytes() as u64,
            default_dispatch,
            arch,
        )?;
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
    )?;
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
    LOADED_DRIVER_SERVICES.with(|map| map.borrow().get(&key).map(inspect))
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
        if base < 0x1_0000 {
            continue;
        }
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
            continue;
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

    /// (hint/name entry RVA, symbol name) in import-table order.
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

    /// A native PE32 driver: `IoCreateDevice` through a 4-byte IAT with a
    /// stdcall shim, plus real DEVICE_CONTROL/READ/WRITE major functions.
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

    /// Add one delay-import descriptor (attributes = RVA) to an x64 driver.
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

    /// A PE64 driver whose DEVICE_CONTROL/READ/WRITE major functions write a
    /// real response and complete with STATUS_SUCCESS.
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

    /// Allocate a host thunk exactly like `alloc_host_thunk` and drive it
    /// through the real guest callback dispatcher on an x64 guest state.
    /// Attach the canonical VM and commit the scratch stack plus the
    /// UNICODE_STRING/argument scratch pages so guest accesses validate even
    /// before (and after) an island attaches its own mappings.
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
        let thunk_address = runtime.next_thunk_address;
        runtime.next_thunk_address += 0x10;
        runtime.host_thunks.insert(thunk_address, thunk);
        memory.map_bytes(STACK_BASE, &vec![0_u8; STACK_SIZE as usize]);
        let mut cpu = CpuState::new(runtime.guest_arch);
        cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x100);
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
}
