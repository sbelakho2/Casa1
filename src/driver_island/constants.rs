//! Island constants (status codes, IRP codes, object sizes).

/// `IO_TYPE_DRIVER`.
pub(crate) const DRIVER_OBJECT_TYPE: u16 = 4;

/// `sizeof(DRIVER_OBJECT)` on x64.
pub(crate) const DRIVER_OBJECT_SIZE: u64 = 0x150;

/// `sizeof(DRIVER_OBJECT)` on x86.
pub(crate) const DRIVER_OBJECT_SIZE_X86: u64 = 0xA8;

/// `IO_TYPE_DEVICE`.
pub(crate) const DEVICE_OBJECT_TYPE: u16 = 3;

/// `sizeof(DEVICE_OBJECT)` on x64.
pub(crate) const DEVICE_OBJECT_SIZE: u16 = 0x150;

/// `sizeof(DEVICE_OBJECT)` on x86.
pub(crate) const DEVICE_OBJECT_SIZE_X86: u16 = 0xA8;

/// `IO_TYPE_IRP`.
pub(crate) const IRP_TYPE: u16 = 6;

/// Guest scratch stack (the same low arena the runtime's own tests use).
pub(crate) const STACK_BASE: u64 = 0x10_000;

pub(crate) const STACK_SIZE: u64 = 0x2000;

/// Per-island data arena (driver object, strings, guest device/IRP blocks).
pub(crate) const ARENA_SIZE: u64 = 0x10_0000;

/// Where a driver image is placed when its preferred base is unusable.
pub(crate) const DEFAULT_IMAGE_BASE: u64 = 0x1_4000_0000;

/// Where a PE32 image is placed when its preferred base is unusable.
pub(crate) const DEFAULT_IMAGE_BASE_X86: u64 = 0x1000_0000;

/// PE32 images (and their arenas) must stay below the 4 GiB boundary.
pub(crate) const X86_ADDRESS_LIMIT: u64 = 0x8000_0000;

/// `DRIVER_OBJECT.MajorFunction` has `IRP_MJ_MAXIMUM_FUNCTION + 1` slots.
pub(crate) const MAJOR_FUNCTION_COUNT: usize = 28;

/// `STATUS_ACCESS_VIOLATION`.
pub(crate) const STATUS_ACCESS_VIOLATION: i32 = 0xC000_0005u32 as i32;

/// `STATUS_INVALID_HANDLE`.
pub(crate) const STATUS_INVALID_HANDLE: i32 = 0xC000_0008u32 as i32;

/// `STATUS_INVALID_DEVICE_REQUEST`.
pub(crate) const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010u32 as i32;

/// `STATUS_DEVICE_BUSY`.
pub(crate) const STATUS_DEVICE_BUSY: i32 = 0x8000_0011u32 as i32;

/// `STATUS_BUFFER_TOO_SMALL`.
pub(crate) const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;

/// `STATUS_PENDING`.
pub(crate) const STATUS_PENDING: i32 = 0x0000_0103;

/// `STATUS_TIMEOUT`.
pub(crate) const STATUS_TIMEOUT: i32 = 0x0000_0102;

/// `STATUS_NO_MORE_ENTRIES`.
pub(crate) const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;

/// First handle value minted for an island device namespace open.  This range
/// is disjoint from the canonical Win32 handle table values.
pub(crate) const DEVICE_HANDLE_BASE: u32 = 0x7C00_0000;

/// First handle value minted for an island directory-object open.  This range
/// is disjoint from both the Win32 handle table and the island device range.
pub(crate) const DIRECTORY_HANDLE_BASE: u32 = 0x7D00_0000;

/// `SERVICE_BOOT_START`.
pub(crate) const SERVICE_BOOT_START: u32 = 0;

/// `SERVICE_SYSTEM_START`.
pub(crate) const SERVICE_SYSTEM_START: u32 = 1;

/// `SERVICE_AUTO_START`.
pub(crate) const SERVICE_AUTO_START: u32 = 2;

/// `SERVICE_DEMAND_START`.
pub(crate) const SERVICE_DEMAND_START: u32 = 3;

/// `SERVICE_DISABLED`.
pub(crate) const SERVICE_DISABLED: u32 = 4;

/// `IRP_MN_START_DEVICE`.
pub(crate) const IRP_MN_START_DEVICE: u8 = 0x00;

/// `IRP_MN_REMOVE_DEVICE`.
pub(crate) const IRP_MN_REMOVE_DEVICE: u8 = 0x02;

/// `IRP_MN_STOP_DEVICE`.
pub(crate) const IRP_MN_STOP_DEVICE: u8 = 0x04;

/// `IRP_MN_SURPRISE_REMOVAL`.
pub(crate) const IRP_MN_SURPRISE_REMOVAL: u8 = 0x17;

/// `IRP_MN_SET_POWER` (the only power minor the island model implements).
pub(crate) const IRP_MN_SET_POWER: u8 = 0x02;

/// `DevicePowerState` — the only `POWER_STATE_TYPE` the island accepts.
pub(crate) const POWER_STATE_TYPE_DEVICE: u32 = 1;

/// `WdfPowerDeviceD0`.
pub(crate) const WDF_POWER_DEVICE_D0: u32 = 1;

/// `WdfPowerDeviceD3`.
pub(crate) const WDF_POWER_DEVICE_D3: u32 = 4;

/// `WdfPowerDeviceD3Final`, the previous state reported to the first D0Entry.
pub(crate) const WDF_POWER_DEVICE_D3_FINAL: u32 = 5;

/// `STATUS_IMAGE_ALREADY_LOADED` — the service is already loaded.
pub(crate) const STATUS_IMAGE_ALREADY_LOADED: i32 = 0xC000_010Eu32 as i32;

/// `STATUS_ACCESS_DENIED`.
pub(crate) const STATUS_ACCESS_DENIED: i32 = 0xC000_0022u32 as i32;

/// `STATUS_NOT_SUPPORTED` — the operation is recognised but has no island
/// implementation.
pub(crate) const STATUS_NOT_SUPPORTED: i32 = 0xC000_00BBu32 as i32;

/// `STATUS_INVALID_DEVICE_STATE` — an object is in the wrong state for the
/// requested transition (double acquire, release of an unheld lock).
pub(crate) const STATUS_INVALID_DEVICE_STATE: i32 = 0xC000_0184u32 as i32;

/// `STATUS_UNSUCCESSFUL` — a guest slice failed before publishing a status.
#[allow(dead_code)]
pub(crate) const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;

/// `STATUS_NOT_FOUND` — no object matches the synthetic request.
#[allow(dead_code)]
pub(crate) const STATUS_NOT_FOUND: i32 = 0xC000_0225u32 as i32;

/// Maximum scheduler slices in one pump call; hosts call again to continue.
pub(crate) const MAX_THREAD_SLICES: usize = 64;

/// `STATUS_BUFFER_OVERFLOW` — the query succeeded but the caller buffer was
/// too small; the required length is still reported.
pub(crate) const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;

/// `STATUS_OBJECT_PATH_INVALID` — a registry path is not under
/// `\Registry\Machine`.
pub(crate) const STATUS_OBJECT_PATH_INVALID: i32 = 0xC000_0039u32 as i32;

/// `DISPATCH_LEVEL`.
pub(crate) const DISPATCH_LEVEL: u8 = 2;

/// `HIGH_LEVEL`.
pub(crate) const HIGH_LEVEL: u8 = 15;

/// `NonPagedPool`.
pub(crate) const NON_PAGED_POOL: u32 = 0;

/// `PagedPool`.
pub(crate) const PAGED_POOL: u32 = 1;

/// `NotificationEvent`.
pub(crate) const NOTIFICATION_EVENT: u32 = 0;

/// `SynchronizationEvent`.
pub(crate) const SYNCHRONIZATION_EVENT: u32 = 1;

/// `KernelMode` for `MmProbeAndLockPages`.
pub(crate) const KERNEL_MODE: u8 = 0;

/// `UserMode` for `MmProbeAndLockPages`.
pub(crate) const USER_MODE: u8 = 1;

/// `IoReadAccess`.
pub(crate) const IO_READ_ACCESS: u32 = 0;

/// `IoWriteAccess`.
pub(crate) const IO_WRITE_ACCESS: u32 = 1;

/// `IoModifyAccess`.
pub(crate) const IO_MODIFY_ACCESS: u32 = 2;

/// `KeyValuePartialInformation`.
pub(crate) const KEY_VALUE_PARTIAL_INFORMATION: u32 = 2;

/// `KeyValueFullInformation`.
pub(crate) const KEY_VALUE_FULL_INFORMATION: u32 = 1;

/// Base of the island's real registry key handle namespace.
pub(crate) const KEY_HANDLE_BASE: u64 = 0x7E00_0000;

/// Number of guest 100ns ticks per millisecond.
pub(crate) const TICKS_PER_MILLISECOND: i128 = 10_000;

/// Longest host sleep a blocking dispatcher wait may park for.  The island has
/// no guest scheduler, so a longer deadline cannot make progress anyway; the
/// wait still consumes its real deadline up to this bound.
pub(crate) const MAX_DISPATCHER_WAIT_MS: u128 = 1_000;

/// `\Registry\Machine\System\CurrentControlSet\Services\` (lowercase).
pub(crate) const SERVICE_REGISTRY_PREFIX: &str = "system\\currentcontrolset\\services\\";

/// `\Registry\Machine\` (lowercase), including the trailing separator.
pub(crate) const MACHINE_REGISTRY_PREFIX: &str = "\\registry\\machine\\";
