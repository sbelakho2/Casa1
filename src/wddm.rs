//! Synthetic WDDM kernel-mode-thunk (D3DKMT) personality over the Metal path.
//!
//! This module is the kernel-facing half of the synthetic WDDM driver: guest
//! KMT calls resolve to an adapter/device/allocation/synchronization/swapchain
//! object model whose identities come from the real host GPU and whose waits
//! are scheduled on real Metal shared events (`MTLSharedEvent`). Present calls
//! run through the existing [`crate::gfx::GraphicsBackend`] surface, which uses
//! a CAMetalLayer drawable when a window is attached and the real offscreen
//! swapchain surface otherwise.
//!
//! Every entry point validates the guest-supplied handle/identity and returns
//! the canonical NTSTATUS equivalent (`STATUS_INVALID_HANDLE`,
//! `STATUS_INVALID_PARAMETER`, or the `STATUS_GRAPHICS_*` family) instead of
//! silently succeeding on stale or fabricated objects.

use crate::gfx::{self, DxgiFormat, GraphicsBackend, SwapchainDesc};
use metal::foreign_types::ForeignType;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

// ── NTSTATUS values returned by the KMT surface ─────────────────────────────

/// STATUS_SUCCESS.
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
/// STATUS_TIMEOUT (the wait deadline elapsed before the fence value).
pub const STATUS_TIMEOUT: u32 = 0x0000_0102;
/// STATUS_INVALID_HANDLE.
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
/// STATUS_INVALID_PARAMETER.
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// STATUS_ACCESS_DENIED.
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
/// STATUS_OBJECT_NAME_COLLISION (duplicate allocation identity).
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
/// STATUS_NOT_SUPPORTED (a documented but unmodelled query class).
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER.
pub const STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER: u32 = 0xC01E_0002;
/// STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE (the submitted command buffer failed).
pub const STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE: u32 = 0xC01E_0200;
/// STATUS_GRAPHICS_PRESENT_INVALID_WINDOW (unknown or destroyed swapchain).
pub const STATUS_GRAPHICS_PRESENT_INVALID_WINDOW: u32 = 0xC01E_000F;
/// STATUS_GRAPHICS_NO_VIDEO_MEMORY (resident bytes exceed the segment budget).
pub const STATUS_GRAPHICS_NO_VIDEO_MEMORY: u32 = 0xC01E_0100;
/// STATUS_GRAPHICS_ALLOCATION_BUSY (an in-use object blocks the operation).
pub const STATUS_GRAPHICS_ALLOCATION_BUSY: u32 = 0xC01E_0102;
/// STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE.
pub const STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE: u32 = 0xC01E_0114;
/// STATUS_GRAPHICS_INVALID_PIXELFORMAT.
pub const STATUS_GRAPHICS_INVALID_PIXELFORMAT: u32 = 0xC01E_033D;

/// A KMT failure: the guest-visible NTSTATUS plus a stable diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WddmError {
    status: u32,
    detail: &'static str,
}

impl WddmError {
    /// Construct an error for an exact NTSTATUS value.
    pub const fn new(status: u32, detail: &'static str) -> Self {
        Self { status, detail }
    }

    /// The exact NTSTATUS the KMT entry point returns.
    pub const fn status(self) -> u32 {
        self.status
    }

    /// Stable diagnostic text (never guest-visible).
    pub const fn detail(self) -> &'static str {
        self.detail
    }
}

/// Result returned by every KMT entry point.
pub type WddmResult<T> = Result<T, WddmError>;

const fn failed<T>(status: u32, detail: &'static str) -> WddmResult<T> {
    Err(WddmError::new(status, detail))
}

// ── Identities and handles ──────────────────────────────────────────────────

/// A Windows LUID, derived from the real Metal device registry id and name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Luid {
    /// Low 32 bits.
    pub LowPart: u32,
    /// High 32 bits (signed in the Windows ABI).
    pub HighPart: i32,
}

impl Luid {
    /// Pack the LUID into a single 64-bit value (high part first).
    pub const fn to_u64(self) -> u64 {
        ((self.HighPart as u32 as u64) << 32) | self.LowPart as u64
    }
}

/// Derive a stable LUID from the real Metal registry id and device name.
///
/// The hash binds the guest-visible adapter identity to the host GPU so two
/// processes enumerate the same LUID for the same physical device.
pub fn luid_from_metal_identity(registry_id: u64, device_name: &str) -> Luid {
    let mut hasher = Sha256::new();
    hasher.update(registry_id.to_le_bytes());
    hasher.update(device_name.as_bytes());
    let digest = hasher.finalize();
    Luid {
        LowPart: u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]),
        HighPart: i32::from_le_bytes([digest[4], digest[5], digest[6], digest[7]]),
    }
}

macro_rules! kmt_handle {
    ($name:ident) => {
        /// Opaque KMT handle (unique inside its object namespace).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u32);
    };
}

kmt_handle!(AdapterHandle);
kmt_handle!(DeviceHandle);
kmt_handle!(AllocationHandle);
kmt_handle!(ContextHandle);
kmt_handle!(KeyedMutexHandle);
kmt_handle!(SyncObjectHandle);
kmt_handle!(SwapChainHandle);

/// Maximum number of entries in a KMT handle array (allocation/render/sync).
pub const MAX_KMT_ARRAY: usize = 256;
/// Highest context/allocation scheduling priority accepted by the driver.
pub const MAX_SCHEDULING_PRIORITY: u32 = 31;
/// The single render node exposed by the Metal personality.
pub const RENDER_NODE_ORDINAL: u32 = 0;
/// Number of GPU nodes exposed by the Metal personality.
pub const RENDER_NODE_COUNT: u32 = 1;
/// Upper bound on bytes a single `D3DKMTRender` blit touches (test/GPU sanity).
const MAX_RENDER_BYTES: u64 = 1 << 20;

/// Documented `D3DKMT_QUERYSTATISTICS_TYPE` values.
pub const D3DKMT_QUERYSTATISTICS_ADAPTER: u32 = 0;
/// `D3DKMT_QUERYSTATISTICS_NODE`.
pub const D3DKMT_QUERYSTATISTICS_NODE: u32 = 5;
/// `D3DKMT_QUERYSTATISTICS_ADAPTER2`.
pub const D3DKMT_QUERYSTATISTICS_ADAPTER2: u32 = 11;

/// A WDDM allocation segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegmentId(pub u32);

/// Local (VRAM-backed) segment.
pub const SEGMENT_LOCAL: SegmentId = SegmentId(0);
/// Non-local (system-memory) segment.
pub const SEGMENT_NON_LOCAL: SegmentId = SegmentId(1);

/// A segment as reported by `D3DKMTQueryAdapterInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentInfo {
    /// Segment identity.
    pub id: SegmentId,
    /// Real budget for this segment in bytes.
    pub budget: u64,
    /// Bytes currently resident in this segment.
    pub used: u64,
}

/// Adapter identity as reported by `D3DKMTEnumAdapters`/`D3DKMTQueryAdapterInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WddmAdapterInfo {
    /// Backend adapter id.
    pub adapter_id: u64,
    /// LUID used to open the adapter.
    pub luid: Luid,
    /// Real Metal `registryID`.
    pub registry_id: u64,
    /// PCI vendor id from the existing GPU identity.
    pub vendor_id: u32,
    /// PCI device id from the existing GPU identity.
    pub device_id: u32,
    /// Metal device name from the existing GPU identity.
    pub name: String,
    /// Metal family from the existing GPU identity.
    pub metal_family: String,
    /// Adapter-wide budget (Metal recommended working set).
    pub budget: u64,
    /// Per-segment budgets and usage.
    pub segments: Vec<SegmentInfo>,
}

/// Device object state as reported by the KMT surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Whether the object can be opened through another handle.
    pub shareable: bool,
    /// Owning process identity recorded at creation.
    pub owner_process: u64,
}

/// Allocation state as reported by the KMT surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationInfo {
    /// Exact allocation size in bytes.
    pub size: u64,
    /// Owning process identity recorded at creation.
    pub owner_process: u64,
    /// Whether the allocation can be shared across device handles.
    pub shareable: bool,
    /// Segment the allocation belongs to.
    pub segment: SegmentId,
    /// Current `MakeResident` reference count.
    pub residency: u32,
}

/// Swapchain state as reported by `D3DKMTQuerySwapChainInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapChainInfo {
    /// Surface width.
    pub width: u32,
    /// Surface height.
    pub height: u32,
    /// Backbuffer count.
    pub buffer_count: u32,
    /// Presents routed through the GPU backend.
    pub present_count: u64,
    /// Refresh (vblank) count advanced by presents.
    pub refresh_count: u64,
    /// Current flip index over the backbuffers.
    pub flip_index: u32,
}

/// `D3DKMTPresent` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WddmPresentResult {
    /// Total presents on this swapchain.
    pub present_count: u64,
    /// Total refresh intervals consumed.
    pub refresh_count: u64,
    /// Backbuffer index presented next.
    pub flip_index: u32,
    /// Frame index reported by the GPU backend.
    pub displayed_frame_index: u64,
    /// Real elapsed nanoseconds reported by the GPU backend.
    pub frame_time_ns: u64,
    /// Whether the backend accepted the tearing request.
    pub tearing_allowed: bool,
}

/// `D3DKMTQueryStatistics` counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WddmStatistics {
    /// Presents routed through the GPU backend.
    pub present_count: u64,
    /// Refresh intervals consumed by those presents.
    pub refresh_count: u64,
    /// Flip operations.
    pub flip_count: u64,
    /// Live allocations.
    pub allocation_count: u64,
    /// Sum of all allocation sizes.
    pub allocated_bytes: u64,
    /// Allocations with a non-zero residency count.
    pub resident_count: u64,
    /// Sum of resident allocation sizes.
    pub resident_bytes: u64,
    /// Successful synchronization signals.
    pub signal_count: u64,
    /// Wait calls that reached a real synchronization object.
    pub wait_count: u64,
    /// Waits that returned `STATUS_TIMEOUT`.
    pub timeout_count: u64,
    /// Last real frame interval reported by the GPU backend.
    pub last_frame_time_ns: u64,
    /// Last frame index reported by the GPU backend.
    pub last_displayed_frame_index: u64,
    /// Render submissions that completed on the GPU.
    pub render_count: u64,
    /// Bytes filled by completed render submissions.
    pub render_bytes: u64,
    /// Live context objects.
    pub context_count: u64,
    /// Keyed-mutex acquisitions that took ownership.
    pub keyed_mutex_acquire_count: u64,
    /// Keyed-mutex acquisitions that returned `STATUS_TIMEOUT`.
    pub keyed_mutex_timeout_count: u64,
}

/// One entry of a `D3DKMTCreateAllocation` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationDesc {
    /// Exact allocation size in bytes.
    pub size: u64,
    /// Segment the allocation belongs to.
    pub segment: SegmentId,
}

/// `D3DKMTCreateAllocation` request for one or more allocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateAllocationsRequest {
    /// Device that owns the allocations.
    pub device: DeviceHandle,
    /// Per-allocation sizes and segments.
    pub allocations: Vec<AllocationDesc>,
    /// Base guest allocation identity; entry `n` gets `resource_id_base + n`.
    pub resource_id_base: u64,
    /// Whether the allocations may be shared.
    pub shareable: bool,
    /// Owning process identity.
    pub owner_process: u64,
}

/// `D3DKMTCreateContext` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateContextRequest {
    /// Device that owns the context.
    pub device: DeviceHandle,
    /// Render node ordinal (the Metal personality exposes node 0).
    pub node_ordinal: u32,
    /// Scheduling priority in `0..=MAX_SCHEDULING_PRIORITY`.
    pub priority: u32,
}

/// Live context state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextInfo {
    /// Driver-generated context identity.
    pub context_id: u64,
    /// Render node ordinal.
    pub node_ordinal: u32,
    /// Stored scheduling priority.
    pub priority: u32,
    /// Completed render submissions through this context.
    pub submit_count: u64,
}

/// `D3DKMTRender` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderRequest {
    /// Device owning the context and allocations.
    pub device: DeviceHandle,
    /// Context the command buffer is submitted on.
    pub context: ContextHandle,
    /// Allocation handles referenced by the command buffer.
    pub allocations: Vec<AllocationHandle>,
    /// Fill byte applied by the real Metal blit.
    pub fill_value: u8,
    /// Optional fence (shared event, completion value).
    pub fence: Option<(SyncObjectHandle, u64)>,
}

/// `D3DKMTRender` completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderResult {
    /// Context that submitted the work.
    pub context_id: u64,
    /// Bytes actually filled on the GPU.
    pub bytes_filled: u64,
    /// Fence value signalled after GPU completion.
    pub fence_value: u64,
    /// Effective scheduling priority (max of context and allocation priorities).
    pub effective_priority: u32,
}

/// A display mode reported by `D3DKMTGetDisplayModeList`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DisplayModeInfo {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Refresh rate numerator.
    pub refresh_numerator: u32,
    /// Refresh rate denominator.
    pub refresh_denominator: u32,
}

/// `D3DKMT_QUERYSTATISTICS_NODE` counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WddmNodeStatistics {
    /// Render node ordinal.
    pub node_ordinal: u32,
    /// Live contexts on this node.
    pub context_count: u64,
    /// Completed render submissions.
    pub render_count: u64,
    /// Bytes filled by completed submissions.
    pub render_bytes: u64,
    /// Highest effective priority scheduled.
    pub last_effective_priority: u32,
    /// Live allocations on the node's adapter.
    pub allocation_count: u64,
    /// Sum of live allocation sizes.
    pub allocated_bytes: u64,
}

/// `D3DKMTCreateDevice` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateDeviceRequest {
    /// Open adapter handle.
    pub adapter: AdapterHandle,
    /// Whether other `OpenDevice` handles may reference the object.
    pub shareable: bool,
    /// Owning process identity.
    pub owner_process: u64,
}

/// `D3DKMTCreateAllocation` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateAllocationRequest {
    /// Device that owns the allocation.
    pub device: DeviceHandle,
    /// Exact allocation size in bytes.
    pub size: u64,
    /// Segment the allocation belongs to.
    pub segment: SegmentId,
    /// Guest allocation identity (must be unique per device object).
    pub resource_id: u64,
    /// Whether the allocation may be shared.
    pub shareable: bool,
    /// Owning process identity.
    pub owner_process: u64,
}

/// `D3DKMTCreateSwapChain` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateSwapChainRequest {
    /// Device that owns the swapchain.
    pub device: DeviceHandle,
    /// Surface width in pixels.
    pub width: u32,
    /// Surface height in pixels.
    pub height: u32,
    /// Backbuffer format.
    pub format: DxgiFormat,
    /// Backbuffer count (must be at least 2).
    pub buffer_count: u32,
}

/// `D3DKMTPresent` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentRequest {
    /// Swapchain to present.
    pub swapchain: SwapChainHandle,
    /// Vertical-blank interval (`0` = immediate, `1..=4` = vblank multiples).
    pub sync_interval: u32,
    /// Whether tearing is allowed when the interval is zero.
    pub allow_tearing: bool,
}

// ── Backing records ─────────────────────────────────────────────────────────

struct SegmentRecord {
    budget: u64,
    used: u64,
}

struct AdapterRecord {
    info: WddmAdapterInfo,
    device: metal::Device,
    segments: Vec<SegmentRecord>,
    device_objects: BTreeSet<u64>,
    private_driver_formats: BTreeMap<u32, u32>,
}

struct DeviceObjectRecord {
    adapter_id: u64,
    shareable: bool,
    owner_process: u64,
    allocations: BTreeSet<AllocationHandle>,
    contexts: BTreeSet<ContextHandle>,
    sync_objects: BTreeSet<SyncObjectHandle>,
    keyed_mutexes: BTreeSet<KeyedMutexHandle>,
    swapchains: BTreeSet<SwapChainHandle>,
}

struct AllocationObject {
    adapter_id: u64,
    size: u64,
    segment: SegmentId,
    resource_id: u64,
    shareable: bool,
    owner_process: u64,
    residency: u32,
    priority: u32,
    keyed_mutex: Option<Arc<(Mutex<KeyedMutexState>, Condvar)>>,
}

struct AllocationRef {
    object: u64,
    device_object: u64,
}

struct ContextRecord {
    device_object: u64,
    adapter_id: u64,
    node_ordinal: u32,
    priority: u32,
    context_id: u64,
    submit_count: u64,
    submit_bytes: u64,
}

struct KeyedMutexState {
    key: u64,
    owner_process: Option<u64>,
    depth: u32,
    wake_count: u64,
}

struct KeyedMutexRecord {
    object: u64,
    device_object: u64,
    state: Arc<(Mutex<KeyedMutexState>, Condvar)>,
}

struct SyncObjectRecord {
    device_object: u64,
    event: metal::SharedEvent,
    value: Arc<Mutex<u64>>,
}

struct SwapChainRecord {
    gfx_swapchain: gfx::SwapchainId,
    device_object: u64,
    width: u32,
    height: u32,
    buffer_count: u32,
    present_count: u64,
    refresh_count: u64,
    flip_index: u32,
}

#[derive(Default)]
struct StatisticsRecord {
    present_count: u64,
    refresh_count: u64,
    flip_count: u64,
    signal_count: u64,
    wait_count: u64,
    timeout_count: u64,
    last_frame_time_ns: u64,
    last_displayed_frame_index: u64,
    last_effective_priority: u32,
    render_count: u64,
    render_bytes: u64,
    keyed_mutex_acquire_count: u64,
    keyed_mutex_timeout_count: u64,
}

struct WddmState {
    adapters: BTreeMap<u64, AdapterRecord>,
    adapter_handles: BTreeMap<AdapterHandle, u64>,
    devices: BTreeMap<DeviceHandle, u64>,
    device_objects: BTreeMap<u64, DeviceObjectRecord>,
    allocation_objects: BTreeMap<u64, AllocationObject>,
    allocations: BTreeMap<AllocationHandle, AllocationRef>,
    allocation_keys: BTreeMap<(u64, u64), u64>,
    contexts: BTreeMap<ContextHandle, ContextRecord>,
    keyed_mutexes: BTreeMap<KeyedMutexHandle, KeyedMutexRecord>,
    sync_objects: BTreeMap<SyncObjectHandle, SyncObjectRecord>,
    swapchains: BTreeMap<SwapChainHandle, SwapChainRecord>,
    statistics: StatisticsRecord,
    next_adapter: u64,
    next_object: u64,
    next_allocation: u64,
    next_context: u64,
    next_handle: u32,
}

impl WddmState {
    fn new() -> Self {
        Self {
            adapters: BTreeMap::new(),
            adapter_handles: BTreeMap::new(),
            devices: BTreeMap::new(),
            device_objects: BTreeMap::new(),
            allocation_objects: BTreeMap::new(),
            allocations: BTreeMap::new(),
            allocation_keys: BTreeMap::new(),
            contexts: BTreeMap::new(),
            keyed_mutexes: BTreeMap::new(),
            sync_objects: BTreeMap::new(),
            swapchains: BTreeMap::new(),
            statistics: StatisticsRecord::default(),
            next_adapter: 0,
            next_object: 0,
            next_allocation: 0,
            next_context: 1,
            next_handle: 1,
        }
    }

    fn alloc_handle(&mut self) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 1;
        handle
    }
}

/// The synthetic WDDM driver personality.
///
/// The subsystem owns the adapter object table, the GPU present backend, and
/// the real host fences. It is `Send + Sync`: signal/wait races run against the
/// same Metal shared events the GPU path would signal.
pub struct WddmSubsystem {
    state: Mutex<WddmState>,
    backend: Mutex<GraphicsBackend>,
}

impl WddmSubsystem {
    /// Enumerate the host Metal devices and build the synthetic adapter table.
    pub fn new() -> Self {
        Self::with_metal_devices(metal::Device::all())
    }

    /// Build a subsystem for an explicit Metal device set.
    ///
    /// An empty set models a host with no GPU: enumeration is empty and every
    /// open/create call fails with `STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER`.
    pub fn with_metal_devices(devices: Vec<metal::Device>) -> Self {
        let mut state = WddmState::new();
        for device in devices {
            let profile = gfx::host_gpu_profile_from_name(device.name());
            let registry_id = device.registry_id();
            let budget = device
                .recommended_max_working_set_size()
                .max(device.max_buffer_length())
                .max(1);
            let adapter_id = state.next_adapter;
            state.next_adapter += 1;
            state.adapters.insert(
                adapter_id,
                AdapterRecord {
                    info: WddmAdapterInfo {
                        adapter_id,
                        luid: luid_from_metal_identity(registry_id, device.name()),
                        registry_id,
                        vendor_id: profile.adapter.vendor_id,
                        device_id: profile.adapter.device_id,
                        name: profile.adapter.name,
                        metal_family: profile.adapter.metal_family,
                        budget,
                        segments: Vec::new(),
                    },
                    device,
                    segments: vec![
                        SegmentRecord { budget, used: 0 },
                        SegmentRecord {
                            budget: budget / 2,
                            used: 0,
                        },
                    ],
                    device_objects: BTreeSet::new(),
                    private_driver_formats: BTreeMap::new(),
                },
            );
        }
        Self {
            state: Mutex::new(state),
            backend: Mutex::new(GraphicsBackend::new()),
        }
    }

    fn state(&self) -> MutexGuard<'_, WddmState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn backend(&self) -> MutexGuard<'_, GraphicsBackend> {
        self.backend
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `D3DKMTEnumAdapters`: the real host GPU set.
    pub fn d3dkmt_enum_adapters(&self) -> Vec<WddmAdapterInfo> {
        let state = self.state();
        state
            .adapters
            .values()
            .map(|adapter| adapter_snapshot(adapter))
            .collect()
    }

    /// `D3DKMTQueryAdapterInfo`: snapshot an open adapter.
    pub fn d3dkmt_query_adapter_info(&self, adapter: AdapterHandle) -> WddmResult<WddmAdapterInfo> {
        let state = self.state();
        let adapter_id = require_adapter(&state, adapter)?;
        let record = state
            .adapters
            .get(&adapter_id)
            .ok_or_else(|| WddmError::new(STATUS_INVALID_HANDLE, "adapter vanished"))?;
        Ok(adapter_snapshot(record))
    }

    /// `D3DKMTOpenAdapterFromLuid`.
    pub fn d3dkmt_open_adapter_from_luid(&self, luid: Luid) -> WddmResult<AdapterHandle> {
        let mut state = self.state();
        let adapter_id = state
            .adapters
            .iter()
            .find_map(|(id, adapter)| (adapter.info.luid == luid).then_some(*id))
            .ok_or_else(|| {
                WddmError::new(
                    STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER,
                    "no adapter has this LUID",
                )
            })?;
        let handle = AdapterHandle(state.alloc_handle());
        state.adapter_handles.insert(handle, adapter_id);
        Ok(handle)
    }

    /// `D3DKMTOpenAdapterFromGdiDisplayName`.
    ///
    /// Accepts the canonical GDI names (`\\.\DISPLAY1`), a bare `DISPLAYn`,
    /// or the adapter's reported name.  Unknown names fail with
    /// `STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER`; an empty name is an invalid
    /// parameter.
    pub fn d3dkmt_open_adapter_from_display_name(&self, name: &str) -> WddmResult<AdapterHandle> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return failed(STATUS_INVALID_PARAMETER, "empty GDI display name");
        }
        let display_index = trimmed
            .to_ascii_uppercase()
            .rsplit_once("DISPLAY")
            .and_then(|(_, suffix)| suffix.parse::<usize>().ok())
            .filter(|index| *index >= 1);
        let mut state = self.state();
        let adapter_id = if let Some(index) = display_index {
            state.adapters.keys().nth(index - 1).copied()
        } else {
            state.adapters.iter().find_map(|(id, adapter)| {
                adapter
                    .info
                    .name
                    .eq_ignore_ascii_case(trimmed)
                    .then_some(*id)
            })
        }
        .ok_or_else(|| {
            WddmError::new(
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER,
                "no adapter answers to this display name",
            )
        })?;
        let handle = AdapterHandle(state.alloc_handle());
        state.adapter_handles.insert(handle, adapter_id);
        Ok(handle)
    }

    /// `D3DKMTOpenAdapterFromDeviceName`.
    ///
    /// Matches the reported device name, a `metal#<registry-id>` synthetic
    /// device interface, or a `DISPLAYn` name.  The registry id binds the
    /// identity to the real Metal device.
    pub fn d3dkmt_open_adapter_from_device_name(&self, name: &str) -> WddmResult<AdapterHandle> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return failed(STATUS_INVALID_PARAMETER, "empty device name");
        }
        if let Some(rest) = trimmed
            .to_ascii_lowercase()
            .strip_prefix("metal#")
            .map(str::to_string)
        {
            let registry_id = u64::from_str_radix(rest.trim_start_matches("0x"), 16)
                .map_err(|_| WddmError::new(STATUS_INVALID_PARAMETER, "malformed device name"))?;
            let mut state = self.state();
            let adapter_id = state
                .adapters
                .iter()
                .find_map(|(id, adapter)| (adapter.info.registry_id == registry_id).then_some(*id))
                .ok_or_else(|| {
                    WddmError::new(
                        STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER,
                        "no adapter has this registry id",
                    )
                })?;
            let handle = AdapterHandle(state.alloc_handle());
            state.adapter_handles.insert(handle, adapter_id);
            return Ok(handle);
        }
        if trimmed.to_ascii_uppercase().contains("DISPLAY") {
            return self.d3dkmt_open_adapter_from_display_name(trimmed);
        }
        let mut state = self.state();
        let adapter_id = state
            .adapters
            .iter()
            .find_map(|(id, adapter)| {
                adapter
                    .info
                    .name
                    .to_ascii_lowercase()
                    .contains(&trimmed.to_ascii_lowercase())
                    .then_some(*id)
            })
            .ok_or_else(|| {
                WddmError::new(
                    STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER,
                    "no adapter answers to this device name",
                )
            })?;
        let handle = AdapterHandle(state.alloc_handle());
        state.adapter_handles.insert(handle, adapter_id);
        Ok(handle)
    }

    /// `D3DKMTGetDisplayModeList`: the backend's real output modes, deduped.
    pub fn d3dkmt_display_modes(&self, adapter: AdapterHandle) -> WddmResult<Vec<DisplayModeInfo>> {
        {
            let state = self.state();
            require_adapter(&state, adapter)?;
        }
        let mut modes = BTreeSet::new();
        for output in self.backend().outputs() {
            for mode in &output.modes {
                modes.insert(DisplayModeInfo {
                    width: mode.width,
                    height: mode.height,
                    refresh_numerator: mode.refresh_numerator,
                    refresh_denominator: mode.refresh_denominator,
                });
            }
        }
        Ok(modes.into_iter().collect())
    }

    /// `D3DKMTSetDisplayPrivateDriverFormat`: persist the format per VidPn source.
    pub fn d3dkmt_set_display_private_driver_format(
        &self,
        adapter: AdapterHandle,
        vidpn_source_id: u32,
        attribute: u32,
    ) -> WddmResult<()> {
        let mut state = self.state();
        let adapter_id = require_adapter(&state, adapter)?;
        let source_count = self.backend().outputs().len() as u32;
        if vidpn_source_id >= source_count {
            return failed(
                STATUS_INVALID_PARAMETER,
                "VidPn source does not exist on this adapter",
            );
        }
        state
            .adapters
            .get_mut(&adapter_id)
            .expect("adapter validated above")
            .private_driver_formats
            .insert(vidpn_source_id, attribute);
        Ok(())
    }

    /// Stored `SetDisplayPrivateDriverFormat` state for a VidPn source.
    pub fn display_private_driver_format(
        &self,
        adapter: AdapterHandle,
        vidpn_source_id: u32,
    ) -> WddmResult<u32> {
        let state = self.state();
        let adapter_id = require_adapter(&state, adapter)?;
        state
            .adapters
            .get(&adapter_id)
            .expect("adapter validated above")
            .private_driver_formats
            .get(&vidpn_source_id)
            .copied()
            .ok_or_else(|| {
                WddmError::new(
                    STATUS_INVALID_PARAMETER,
                    "no private driver format for this VidPn source",
                )
            })
    }

    /// `D3DKMTCloseAdapter`.
    pub fn d3dkmt_close_adapter(&self, adapter: AdapterHandle) -> WddmResult<()> {
        let mut state = self.state();
        let adapter_id = require_adapter(&state, adapter)?;
        let has_devices = state
            .adapters
            .get(&adapter_id)
            .is_some_and(|record| !record.device_objects.is_empty());
        if has_devices {
            return failed(
                STATUS_GRAPHICS_ALLOCATION_BUSY,
                "adapter still has live device objects",
            );
        }
        state.adapter_handles.remove(&adapter);
        Ok(())
    }

    /// `D3DKMTCreateDevice`.
    pub fn d3dkmt_create_device(&self, request: CreateDeviceRequest) -> WddmResult<DeviceHandle> {
        let mut state = self.state();
        let adapter_id = require_adapter(&state, request.adapter)?;
        let object_id = state.next_object;
        state.next_object += 1;
        let handle = DeviceHandle(state.alloc_handle());
        state.devices.insert(handle, object_id);
        state.device_objects.insert(
            object_id,
            DeviceObjectRecord {
                adapter_id,
                shareable: request.shareable,
                owner_process: request.owner_process,
                allocations: BTreeSet::new(),
                contexts: BTreeSet::new(),
                sync_objects: BTreeSet::new(),
                keyed_mutexes: BTreeSet::new(),
                swapchains: BTreeSet::new(),
            },
        );
        state
            .adapters
            .get_mut(&adapter_id)
            .expect("adapter validated above")
            .device_objects
            .insert(object_id);
        Ok(handle)
    }

    /// Device object state, including the recorded owner and shareable flag.
    pub fn device_info(&self, device: DeviceHandle) -> WddmResult<DeviceInfo> {
        let state = self.state();
        let object_id = require_device(&state, device)?;
        let record = state
            .device_objects
            .get(&object_id)
            .expect("device object present for live handle");
        Ok(DeviceInfo {
            shareable: record.shareable,
            owner_process: record.owner_process,
        })
    }

    /// `D3DKMTOpenDevice`: open a second handle to a shareable device object.
    pub fn d3dkmt_open_device(&self, device: DeviceHandle) -> WddmResult<DeviceHandle> {
        let mut state = self.state();
        let object_id = require_device(&state, device)?;
        let shareable = state
            .device_objects
            .get(&object_id)
            .is_some_and(|record| record.shareable);
        if !shareable {
            return failed(
                STATUS_ACCESS_DENIED,
                "device object was not created shareable",
            );
        }
        let handle = DeviceHandle(state.alloc_handle());
        state.devices.insert(handle, object_id);
        Ok(handle)
    }

    /// `D3DKMTDestroyDevice`: destroys the object when the last handle closes.
    pub fn d3dkmt_destroy_device(&self, device: DeviceHandle) -> WddmResult<()> {
        let mut state = self.state();
        let object_id = state
            .devices
            .remove(&device)
            .ok_or_else(|| WddmError::new(STATUS_INVALID_HANDLE, "unknown device handle"))?;
        if state.devices.values().any(|id| *id == object_id) {
            return Ok(());
        }
        let object = state
            .device_objects
            .remove(&object_id)
            .expect("live device object is always present");
        for allocation in object.allocations {
            let _ = remove_allocation_handle(&mut state, allocation);
        }
        for context in object.contexts {
            state.contexts.remove(&context);
        }
        for keyed_mutex in object.keyed_mutexes {
            state.keyed_mutexes.remove(&keyed_mutex);
        }
        for sync_object in object.sync_objects {
            state.sync_objects.remove(&sync_object);
        }
        for swapchain in object.swapchains {
            if let Some(record) = state.swapchains.remove(&swapchain) {
                let _ = self.backend().destroy_swapchain(record.gfx_swapchain);
            }
        }
        if let Some(adapter) = state.adapters.get_mut(&object.adapter_id) {
            adapter.device_objects.remove(&object_id);
        }
        Ok(())
    }

    /// `D3DKMTCreateAllocation`.
    pub fn d3dkmt_create_allocation(
        &self,
        request: CreateAllocationRequest,
    ) -> WddmResult<AllocationHandle> {
        let handles = self.d3dkmt_create_allocations(CreateAllocationsRequest {
            device: request.device,
            allocations: vec![AllocationDesc {
                size: request.size,
                segment: request.segment,
            }],
            resource_id_base: request.resource_id,
            shareable: request.shareable,
            owner_process: request.owner_process,
        })?;
        handles
            .into_iter()
            .next()
            .ok_or_else(|| WddmError::new(STATUS_INVALID_PARAMETER, "empty allocation request"))
    }

    /// `D3DKMTCreateAllocation` with an allocation array.
    ///
    /// The whole request is validated before any object is created, so a
    /// duplicate identity, zero size, or unknown segment creates nothing.
    pub fn d3dkmt_create_allocations(
        &self,
        request: CreateAllocationsRequest,
    ) -> WddmResult<Vec<AllocationHandle>> {
        let mut state = self.state();
        let object_id = require_device(&state, request.device)?;
        let adapter_id = state
            .device_objects
            .get(&object_id)
            .expect("device object present for live handle")
            .adapter_id;
        if request.allocations.is_empty() || request.allocations.len() > MAX_KMT_ARRAY {
            return failed(
                STATUS_INVALID_PARAMETER,
                "allocation array size is outside 1..=MAX_KMT_ARRAY",
            );
        }
        let segment_count = state
            .adapters
            .get(&adapter_id)
            .expect("adapter present for live device")
            .segments
            .len() as u32;
        let mut seen = BTreeSet::new();
        for (index, allocation) in request.allocations.iter().enumerate() {
            if allocation.size == 0 {
                return failed(STATUS_INVALID_PARAMETER, "allocation size must be non-zero");
            }
            if allocation.segment.0 >= segment_count {
                return failed(
                    STATUS_INVALID_PARAMETER,
                    "allocation segment does not exist",
                );
            }
            let resource_id = request
                .resource_id_base
                .checked_add(index as u64)
                .ok_or_else(|| {
                    WddmError::new(STATUS_INVALID_PARAMETER, "resource identity overflow")
                })?;
            if state
                .allocation_keys
                .contains_key(&(object_id, resource_id))
                || !seen.insert(resource_id)
            {
                return failed(
                    STATUS_OBJECT_NAME_COLLISION,
                    "allocation identity already exists on this device",
                );
            }
        }
        let mut handles = Vec::with_capacity(request.allocations.len());
        for (index, allocation) in request.allocations.iter().enumerate() {
            let resource_id = request.resource_id_base + index as u64;
            let allocation_id = state.next_allocation;
            state.next_allocation += 1;
            let handle = AllocationHandle(state.alloc_handle());
            state.allocation_objects.insert(
                allocation_id,
                AllocationObject {
                    adapter_id,
                    size: allocation.size,
                    segment: allocation.segment,
                    resource_id,
                    shareable: request.shareable,
                    owner_process: request.owner_process,
                    residency: 0,
                    priority: 0,
                    keyed_mutex: None,
                },
            );
            state.allocations.insert(
                handle,
                AllocationRef {
                    object: allocation_id,
                    device_object: object_id,
                },
            );
            state
                .allocation_keys
                .insert((object_id, resource_id), allocation_id);
            state
                .device_objects
                .get_mut(&object_id)
                .expect("device object present for live handle")
                .allocations
                .insert(handle);
            handles.push(handle);
        }
        Ok(handles)
    }

    /// `D3DKMTDestroyAllocation`.
    pub fn d3dkmt_destroy_allocation(&self, allocation: AllocationHandle) -> WddmResult<()> {
        let mut state = self.state();
        remove_allocation_handle(&mut state, allocation)
            .map(|_| ())
            .ok_or_else(|| {
                WddmError::new(
                    STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE,
                    "unknown allocation handle",
                )
            })
    }

    /// Allocation state, including the recorded owner, priority and residency.
    pub fn allocation_info(&self, allocation: AllocationHandle) -> WddmResult<AllocationInfo> {
        let state = self.state();
        let object = allocation_object(&state, allocation)?;
        Ok(AllocationInfo {
            size: object.size,
            owner_process: object.owner_process,
            shareable: object.shareable,
            segment: object.segment,
            residency: object.residency,
        })
    }

    /// Current allocation scheduling priority (`D3DKMTSetAllocationPriority`).
    pub fn allocation_priority(&self, allocation: AllocationHandle) -> WddmResult<u32> {
        Ok(allocation_object(&self.state(), allocation)?.priority)
    }

    /// `D3DKMTSetAllocationPriority`: stored and consumed by `Render`.
    pub fn d3dkmt_set_allocation_priority(
        &self,
        device: DeviceHandle,
        allocations: &[AllocationHandle],
        priority: u32,
    ) -> WddmResult<()> {
        if priority > MAX_SCHEDULING_PRIORITY {
            return failed(
                STATUS_INVALID_PARAMETER,
                "allocation priority is outside 0..=MAX_SCHEDULING_PRIORITY",
            );
        }
        if allocations.is_empty() || allocations.len() > MAX_KMT_ARRAY {
            return failed(
                STATUS_INVALID_PARAMETER,
                "allocation array size is outside 1..=MAX_KMT_ARRAY",
            );
        }
        let mut state = self.state();
        let object_id = require_device(&state, device)?;
        for allocation in allocations {
            let reference = state.allocations.get(allocation).ok_or_else(|| {
                WddmError::new(
                    STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE,
                    "unknown allocation handle",
                )
            })?;
            if reference.device_object != object_id {
                return failed(
                    STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE,
                    "allocation is not opened on this device",
                );
            }
        }
        for allocation in allocations {
            let object = state
                .allocations
                .get(allocation)
                .expect("validated above")
                .object;
            state
                .allocation_objects
                .get_mut(&object)
                .expect("allocation object present for live handle")
                .priority = priority;
        }
        Ok(())
    }

    /// `D3DKMTQueryAllocationResidency`.
    pub fn d3dkmt_query_allocation_residency(
        &self,
        allocation: AllocationHandle,
    ) -> WddmResult<u32> {
        Ok(self.allocation_info(allocation)?.residency)
    }

    /// `D3DKMTMakeResident`: charge the allocation to its segment exactly once.
    pub fn d3dkmt_make_resident(
        &self,
        allocation: AllocationHandle,
        owner_process: u64,
    ) -> WddmResult<u32> {
        let mut state = self.state();
        let object_id = allocation_object_id(&state, allocation)?;
        let (adapter_id, segment_id, size, first_residency, owner) = {
            let object = state
                .allocation_objects
                .get(&object_id)
                .expect("allocation object present for live handle");
            (
                object.adapter_id,
                object.segment,
                object.size,
                object.residency == 0,
                object.owner_process,
            )
        };
        if owner != owner_process {
            return failed(STATUS_ACCESS_DENIED, "residency owner mismatch");
        }
        if first_residency {
            let segment = state
                .adapters
                .get_mut(&adapter_id)
                .and_then(|adapter| adapter.segments.get_mut(segment_id.0 as usize))
                .expect("segment validated at allocation creation");
            let within_budget = segment
                .used
                .checked_add(size)
                .is_some_and(|next| next <= segment.budget);
            if !within_budget {
                return failed(
                    STATUS_GRAPHICS_NO_VIDEO_MEMORY,
                    "resident bytes exceed the segment budget",
                );
            }
            segment.used += size;
        }
        let object = state
            .allocation_objects
            .get_mut(&object_id)
            .expect("allocation object present for live handle");
        object.residency += 1;
        Ok(object.residency)
    }

    /// `D3DKMTEvict`: release one residency reference.
    pub fn d3dkmt_evict(
        &self,
        allocation: AllocationHandle,
        owner_process: u64,
    ) -> WddmResult<u32> {
        let mut state = self.state();
        let object_id = allocation_object_id(&state, allocation)?;
        let (adapter_id, segment_id, size, residency, owner) = {
            let object = state
                .allocation_objects
                .get(&object_id)
                .expect("allocation object present for live handle");
            (
                object.adapter_id,
                object.segment,
                object.size,
                object.residency,
                object.owner_process,
            )
        };
        if owner != owner_process {
            return failed(STATUS_ACCESS_DENIED, "residency owner mismatch");
        }
        if residency == 0 {
            return failed(
                STATUS_GRAPHICS_ALLOCATION_BUSY,
                "allocation is already fully evicted",
            );
        }
        let residency = {
            let object = state
                .allocation_objects
                .get_mut(&object_id)
                .expect("allocation object present for live handle");
            object.residency -= 1;
            object.residency
        };
        if residency == 0 {
            let segment = state
                .adapters
                .get_mut(&adapter_id)
                .and_then(|adapter| adapter.segments.get_mut(segment_id.0 as usize))
                .expect("segment validated at allocation creation");
            segment.used = segment.used.saturating_sub(size);
        }
        Ok(residency)
    }

    /// `D3DKMTCreateSynchronizationObject`: a real `MTLSharedEvent` fence.
    pub fn d3dkmt_create_synchronization_object(
        &self,
        device: DeviceHandle,
        initial_value: u64,
    ) -> WddmResult<SyncObjectHandle> {
        let mut state = self.state();
        let object_id = require_device(&state, device)?;
        let adapter_id = state
            .device_objects
            .get(&object_id)
            .expect("device object present for live handle")
            .adapter_id;
        let event = state
            .adapters
            .get(&adapter_id)
            .expect("adapter present for live device")
            .device
            .new_shared_event();
        event.set_signaled_value(initial_value);
        let handle = SyncObjectHandle(state.alloc_handle());
        state.sync_objects.insert(
            handle,
            SyncObjectRecord {
                device_object: object_id,
                event,
                value: Arc::new(Mutex::new(initial_value)),
            },
        );
        state
            .device_objects
            .get_mut(&object_id)
            .expect("device object present for live handle")
            .sync_objects
            .insert(handle);
        Ok(handle)
    }

    /// `D3DKMTSignalSynchronizationObject`: monotonic host-fence signal.
    pub fn d3dkmt_signal_synchronization_object(
        &self,
        sync_object: SyncObjectHandle,
        value: u64,
    ) -> WddmResult<()> {
        let mut state = self.state();
        let (event, gate) = {
            let record = state.sync_objects.get(&sync_object).ok_or_else(|| {
                WddmError::new(STATUS_INVALID_HANDLE, "unknown synchronization object")
            })?;
            (record.event.clone(), Arc::clone(&record.value))
        };
        let mut current = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if value <= *current {
            return failed(
                STATUS_INVALID_PARAMETER,
                "fence signal values must increase",
            );
        }
        *current = value;
        event.set_signaled_value(value);
        drop(current);
        state.statistics.signal_count += 1;
        Ok(())
    }

    /// `D3DKMTWaitForSynchronizationObject` with host-fence timeout semantics.
    ///
    /// `timeout_ns == 0` performs a non-blocking check, a finite value waits
    /// up to that wall-clock deadline, and `u64::MAX` waits indefinitely. The
    /// wait itself blocks on the real Metal shared event, so signalled GPU
    /// work wakes the waiter without polling.
    pub fn d3dkmt_wait_for_synchronization_object(
        &self,
        sync_object: SyncObjectHandle,
        value: u64,
        timeout_ns: u64,
    ) -> WddmResult<()> {
        let event = {
            let mut state = self.state();
            let event = state
                .sync_objects
                .get(&sync_object)
                .ok_or_else(|| {
                    WddmError::new(STATUS_INVALID_HANDLE, "unknown synchronization object")
                })?
                .event
                .clone();
            state.statistics.wait_count += 1;
            event
        };
        if event.signaled_value() >= value {
            return Ok(());
        }
        if timeout_ns == 0 {
            self.state().statistics.timeout_count += 1;
            return failed(STATUS_TIMEOUT, "fence value not reached at zero timeout");
        }
        let timeout_ms = if timeout_ns == u64::MAX {
            u64::MAX
        } else {
            timeout_ns.saturating_add(999_999) / 1_000_000
        };
        if wait_for_shared_event(&event, value, timeout_ms) && event.signaled_value() >= value {
            return Ok(());
        }
        self.state().statistics.timeout_count += 1;
        failed(STATUS_TIMEOUT, "fence value not reached before deadline")
    }

    /// `D3DKMTSignalSynchronizationObject2`: broadcast one value to an array.
    pub fn d3dkmt_signal_synchronization_objects(
        &self,
        device: DeviceHandle,
        objects: &[SyncObjectHandle],
        contexts: &[ContextHandle],
        value: u64,
    ) -> WddmResult<()> {
        if objects.is_empty() || objects.len() > MAX_KMT_ARRAY {
            return failed(
                STATUS_INVALID_PARAMETER,
                "synchronization object array is outside 1..=MAX_KMT_ARRAY",
            );
        }
        if contexts.len() > MAX_KMT_ARRAY {
            return failed(
                STATUS_INVALID_PARAMETER,
                "broadcast context array is larger than MAX_KMT_ARRAY",
            );
        }
        let mut state = self.state();
        let object_id = require_device(&state, device)?;
        for context in contexts {
            let record = state.contexts.get(context).ok_or_else(|| {
                WddmError::new(STATUS_INVALID_HANDLE, "unknown broadcast context")
            })?;
            if record.device_object != object_id {
                return failed(
                    STATUS_INVALID_HANDLE,
                    "broadcast context belongs to another device",
                );
            }
        }
        let mut events = Vec::with_capacity(objects.len());
        for object in objects {
            let record = state.sync_objects.get(object).ok_or_else(|| {
                WddmError::new(STATUS_INVALID_HANDLE, "unknown synchronization object")
            })?;
            if record.device_object != object_id {
                return failed(
                    STATUS_INVALID_HANDLE,
                    "synchronization object belongs to another device",
                );
            }
            let current = record
                .value
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if value <= *current {
                return failed(
                    STATUS_INVALID_PARAMETER,
                    "fence signal values must increase",
                );
            }
            events.push((record.event.clone(), Arc::clone(&record.value)));
        }
        for (event, gate) in events {
            let mut current = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            *current = value;
            event.set_signaled_value(value);
        }
        state.statistics.signal_count += objects.len() as u64;
        Ok(())
    }

    /// `D3DKMTWaitForSynchronizationObject2`: wait for every fence in an array.
    pub fn d3dkmt_wait_for_synchronization_objects(
        &self,
        device: DeviceHandle,
        objects: &[SyncObjectHandle],
        values: &[u64],
        timeout_ns: u64,
    ) -> WddmResult<()> {
        if objects.is_empty() || objects.len() > MAX_KMT_ARRAY || objects.len() != values.len() {
            return failed(
                STATUS_INVALID_PARAMETER,
                "synchronization array/value size mismatch",
            );
        }
        let events = {
            let mut state = self.state();
            let object_id = require_device(&state, device)?;
            let mut events = Vec::with_capacity(objects.len());
            for object in objects {
                let record = state.sync_objects.get(object).ok_or_else(|| {
                    WddmError::new(STATUS_INVALID_HANDLE, "unknown synchronization object")
                })?;
                if record.device_object != object_id {
                    return failed(
                        STATUS_INVALID_HANDLE,
                        "synchronization object belongs to another device",
                    );
                }
                events.push(record.event.clone());
            }
            state.statistics.wait_count += objects.len() as u64;
            events
        };
        let deadline =
            (timeout_ns != u64::MAX).then(|| Instant::now() + Duration::from_nanos(timeout_ns));
        for (event, value) in events.iter().zip(values) {
            if event.signaled_value() >= *value {
                continue;
            }
            let timeout_ms = match deadline {
                None => u64::MAX,
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        self.state().statistics.timeout_count += 1;
                        return failed(STATUS_TIMEOUT, "fence array wait expired");
                    }
                    (remaining.as_nanos() as u64).saturating_add(999_999) / 1_000_000
                }
            };
            if !wait_for_shared_event(event, *value, timeout_ms) || event.signaled_value() < *value
            {
                self.state().statistics.timeout_count += 1;
                return failed(STATUS_TIMEOUT, "fence array value not reached");
            }
        }
        Ok(())
    }

    /// `D3DKMTDestroySynchronizationObject`.
    pub fn d3dkmt_destroy_synchronization_object(
        &self,
        device: DeviceHandle,
        sync_object: SyncObjectHandle,
    ) -> WddmResult<()> {
        let mut state = self.state();
        let object_id = require_device(&state, device)?;
        let record = state.sync_objects.get(&sync_object).ok_or_else(|| {
            WddmError::new(STATUS_INVALID_HANDLE, "unknown synchronization object")
        })?;
        if record.device_object != object_id {
            return failed(
                STATUS_INVALID_HANDLE,
                "synchronization object belongs to another device",
            );
        }
        state.sync_objects.remove(&sync_object);
        if let Some(device) = state.device_objects.get_mut(&object_id) {
            device.sync_objects.remove(&sync_object);
        }
        Ok(())
    }

    /// `D3DKMTOpenResource`: open a second device-scoped handle to a shared
    /// allocation object owned by this adapter.
    pub fn d3dkmt_open_resource(
        &self,
        device: DeviceHandle,
        resource: AllocationHandle,
    ) -> WddmResult<AllocationHandle> {
        let mut state = self.state();
        let object_id = require_device(&state, device)?;
        let adapter_id = state
            .device_objects
            .get(&object_id)
            .expect("device object present for live handle")
            .adapter_id;
        let shared = allocation_object_id(&state, resource)?;
        let (resource_adapter, shareable, resource_id) = {
            let object = state
                .allocation_objects
                .get(&shared)
                .expect("allocation object present for live handle");
            (object.adapter_id, object.shareable, object.resource_id)
        };
        if !shareable {
            return failed(STATUS_ACCESS_DENIED, "allocation was not created shareable");
        }
        if resource_adapter != adapter_id {
            return failed(
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER,
                "shared allocation belongs to another adapter",
            );
        }
        if state.allocations.iter().any(|(_, reference)| {
            reference.object == shared && reference.device_object == object_id
        }) || state
            .allocation_keys
            .contains_key(&(object_id, resource_id))
        {
            return failed(
                STATUS_OBJECT_NAME_COLLISION,
                "shared resource is already open on this device",
            );
        }
        let handle = AllocationHandle(state.alloc_handle());
        state.allocations.insert(
            handle,
            AllocationRef {
                object: shared,
                device_object: object_id,
            },
        );
        state
            .allocation_keys
            .insert((object_id, resource_id), shared);
        state
            .device_objects
            .get_mut(&object_id)
            .expect("device object present for live handle")
            .allocations
            .insert(handle);
        Ok(handle)
    }

    /// `D3DKMTOpenResource2` (the private-data payload is validated by the
    /// thunk and does not alter the shared identity).
    pub fn d3dkmt_open_resource2(
        &self,
        device: DeviceHandle,
        resource: AllocationHandle,
    ) -> WddmResult<AllocationHandle> {
        self.d3dkmt_open_resource(device, resource)
    }

    /// `D3DKMTOpenKeyedMutex`: keyed mutex state shared by every open handle.
    #[rustfmt::skip]
    pub fn d3dkmt_open_keyed_mutex(
        &self,
        device: DeviceHandle,
        resource: AllocationHandle,
        key: u64,
    ) -> WddmResult<KeyedMutexHandle> {
        let mut state = self.state();
        let object_id = require_device(&state, device)?;
        let adapter_id = state
            .device_objects
            .get(&object_id)
            .expect("device object present for live handle")
            .adapter_id;
        let shared = allocation_object_id(&state, resource)?;
        let reference = state
            .allocations
            .get(&resource)
            .expect("allocation reference present for live handle");
        if reference.device_object != object_id {
            return failed(
                STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE,
                "allocation is not opened on this device",
            );
        }
        let (resource_adapter, shareable, existing) = {
            let object = state
                .allocation_objects
                .get(&shared)
                .expect("allocation object present for live handle");
            (
                object.adapter_id,
                object.shareable,
                object.keyed_mutex.clone(),
            )
        };
        if !shareable {
            return failed(
                STATUS_ACCESS_DENIED,
                "keyed mutex requires a shareable allocation",
            );
        }
        if resource_adapter != adapter_id {
            return failed( // coverage: unreachable — cross-adapter allocation is device-scoped
                STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER,
                "keyed mutex allocation belongs to another adapter",
            );
        }
        let already_open = state.keyed_mutexes.iter().any(|(handle, record)| {
            record.object == shared
                && state
                    .device_objects
                    .get(&object_id)
                    .is_some_and(|device| device.keyed_mutexes.contains(handle))
        });
        if already_open {
            return failed(
                STATUS_OBJECT_NAME_COLLISION,
                "keyed mutex is already open on this device",
            );
        }
        let state_arc = if let Some(existing) = existing {
            let (guard, _) = &*existing;
            let guard = guard
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if guard.key != key {
                return failed(STATUS_ACCESS_DENIED, "keyed mutex key mismatch");
            }
            drop(guard);
            existing
        } else {
            if key == 0 {
                return failed(STATUS_INVALID_PARAMETER, "keyed mutex key is zero");
            }
            let state_arc = Arc::new((
                Mutex::new(KeyedMutexState {
                    key,
                    owner_process: None,
                    depth: 0,
                    wake_count: 0,
                }),
                Condvar::new(),
            ));
            state
                .allocation_objects
                .get_mut(&shared)
                .expect("allocation object present for live handle")
                .keyed_mutex = Some(Arc::clone(&state_arc));
            state_arc
        };
        let handle = KeyedMutexHandle(state.alloc_handle());
        state.keyed_mutexes.insert(
            handle,
            KeyedMutexRecord {
                object: shared,
                device_object: object_id,
                state: state_arc,
            },
        );
        state
            .device_objects
            .get_mut(&object_id)
            .expect("device object present for live handle")
            .keyed_mutexes
            .insert(handle);
        Ok(handle)
    }

    /// `D3DKMTOpenKeyedMutex2`.
    pub fn d3dkmt_open_keyed_mutex2(
        &self,
        device: DeviceHandle,
        resource: AllocationHandle,
        key: u64,
    ) -> WddmResult<KeyedMutexHandle> {
        self.d3dkmt_open_keyed_mutex(device, resource, key)
    }

    /// `D3DKMTAcquireKeyedMutex`: blocking acquire with an exact timeout.
    pub fn d3dkmt_acquire_keyed_mutex(
        &self,
        keyed_mutex: KeyedMutexHandle,
        key: u64,
        timeout_ns: u64,
        owner_process: u64,
    ) -> WddmResult<()> {
        let state_arc = {
            let state = self.state();
            let record = state.keyed_mutexes.get(&keyed_mutex).ok_or_else(|| {
                WddmError::new(STATUS_INVALID_HANDLE, "unknown keyed mutex handle")
            })?;
            Arc::clone(&record.state)
        };
        let (lock, condvar) = &*state_arc;
        let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.key != key {
            return failed(STATUS_ACCESS_DENIED, "keyed mutex key mismatch");
        }
        if guard.owner_process == Some(owner_process) {
            guard.depth += 1;
            drop(guard);
            self.state().statistics.keyed_mutex_acquire_count += 1;
            return Ok(());
        }
        let deadline =
            (timeout_ns != u64::MAX).then(|| Instant::now() + Duration::from_nanos(timeout_ns));
        while guard.owner_process.is_some() {
            let remaining = match deadline {
                None => Duration::from_secs(86_400),
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        drop(guard);
                        self.state().statistics.keyed_mutex_timeout_count += 1;
                        return failed(STATUS_TIMEOUT, "keyed mutex acquisition timed out");
                    }
                    remaining
                }
            };
            let (next, timed_out) = condvar
                .wait_timeout(guard, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard = next;
            if timed_out.timed_out() && guard.owner_process.is_some() {
                drop(guard);
                self.state().statistics.keyed_mutex_timeout_count += 1;
                return failed(STATUS_TIMEOUT, "keyed mutex acquisition timed out");
            }
        }
        guard.owner_process = Some(owner_process);
        guard.depth = 1;
        drop(guard);
        self.state().statistics.keyed_mutex_acquire_count += 1;
        Ok(())
    }

    /// `D3DKMTReleaseKeyedMutex`: release one acquisition; wake exactly once.
    pub fn d3dkmt_release_keyed_mutex(
        &self,
        keyed_mutex: KeyedMutexHandle,
        key: u64,
        owner_process: u64,
    ) -> WddmResult<()> {
        let state_arc = {
            let state = self.state();
            state
                .keyed_mutexes
                .get(&keyed_mutex)
                .map(|record| Arc::clone(&record.state))
                .ok_or_else(|| {
                    WddmError::new(STATUS_INVALID_HANDLE, "unknown keyed mutex handle")
                })?
        };
        let (lock, condvar) = &*state_arc;
        let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.key != key {
            return failed(STATUS_ACCESS_DENIED, "keyed mutex key mismatch");
        }
        if guard.owner_process != Some(owner_process) || guard.depth == 0 {
            return failed(
                STATUS_ACCESS_DENIED,
                "keyed mutex is not held by this owner",
            );
        }
        guard.depth -= 1;
        if guard.depth == 0 {
            guard.owner_process = None;
            guard.wake_count += 1;
            drop(guard);
            condvar.notify_one();
            return Ok(());
        }
        Ok(())
    }

    /// Close one keyed-mutex handle (the underlying allocation keeps the state).
    pub fn d3dkmt_destroy_keyed_mutex(&self, keyed_mutex: KeyedMutexHandle) -> WddmResult<()> {
        let mut state = self.state();
        let record = state
            .keyed_mutexes
            .remove(&keyed_mutex)
            .ok_or_else(|| WddmError::new(STATUS_INVALID_HANDLE, "unknown keyed mutex"))?;
        if let Some(device) = state.device_objects.get_mut(&record.device_object) {
            device.keyed_mutexes.remove(&keyed_mutex);
        }
        Ok(())
    }

    /// Number of release wakeups observed by a keyed mutex (exactly-once test).
    pub fn keyed_mutex_wake_count(&self, keyed_mutex: KeyedMutexHandle) -> WddmResult<u64> {
        let state = self.state();
        let record = state
            .keyed_mutexes
            .get(&keyed_mutex)
            .ok_or_else(|| WddmError::new(STATUS_INVALID_HANDLE, "unknown keyed mutex"))?;
        let (lock, _) = &*record.state;
        let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(guard.wake_count)
    }

    /// `D3DKMTCreateContext`: a real context object on render node 0.
    pub fn d3dkmt_create_context(
        &self,
        request: CreateContextRequest,
    ) -> WddmResult<ContextHandle> {
        if request.node_ordinal >= RENDER_NODE_COUNT {
            return failed(
                STATUS_INVALID_PARAMETER,
                "context node ordinal does not exist",
            );
        }
        if request.priority > MAX_SCHEDULING_PRIORITY {
            return failed(
                STATUS_INVALID_PARAMETER,
                "context priority is outside 0..=MAX_SCHEDULING_PRIORITY",
            );
        }
        let mut state = self.state();
        let object_id = require_device(&state, request.device)?;
        let adapter_id = state
            .device_objects
            .get(&object_id)
            .expect("device object present for live handle")
            .adapter_id;
        let context_id = state.next_context;
        state.next_context += 1;
        let handle = ContextHandle(state.alloc_handle());
        state.contexts.insert(
            handle,
            ContextRecord {
                device_object: object_id,
                adapter_id,
                node_ordinal: request.node_ordinal,
                priority: request.priority,
                context_id,
                submit_count: 0,
                submit_bytes: 0,
            },
        );
        state
            .device_objects
            .get_mut(&object_id)
            .expect("device object present for live handle")
            .contexts
            .insert(handle);
        Ok(handle)
    }

    /// Live context state.
    pub fn context_info(&self, context: ContextHandle) -> WddmResult<ContextInfo> {
        let state = self.state();
        let record = state
            .contexts
            .get(&context)
            .ok_or_else(|| WddmError::new(STATUS_INVALID_HANDLE, "unknown context handle"))?;
        Ok(ContextInfo {
            context_id: record.context_id,
            node_ordinal: record.node_ordinal,
            priority: record.priority,
            submit_count: record.submit_count,
        })
    }

    /// `D3DKMTDestroyContext`.
    pub fn d3dkmt_destroy_context(&self, context: ContextHandle) -> WddmResult<()> {
        let mut state = self.state();
        let record = state
            .contexts
            .remove(&context)
            .ok_or_else(|| WddmError::new(STATUS_INVALID_HANDLE, "unknown context handle"))?;
        if let Some(device) = state.device_objects.get_mut(&record.device_object) {
            device.contexts.remove(&context);
        }
        Ok(())
    }

    /// `D3DKMTDestroyContext` scoped to the device that owns the context.
    pub fn d3dkmt_destroy_context_on(
        &self,
        device: DeviceHandle,
        context: ContextHandle,
    ) -> WddmResult<()> {
        let mut state = self.state();
        let object_id = require_device(&state, device)?;
        let record = state
            .contexts
            .get(&context)
            .ok_or_else(|| WddmError::new(STATUS_INVALID_HANDLE, "unknown context handle"))?;
        if record.device_object != object_id {
            return failed(STATUS_INVALID_HANDLE, "context belongs to another device");
        }
        let record = state
            .contexts
            .remove(&context)
            .expect("context validated above");
        if let Some(device) = state.device_objects.get_mut(&record.device_object) {
            device.contexts.remove(&context);
        }
        Ok(())
    }

    /// `D3DKMTRender`: validate a context/allocation list, submit a real Metal
    /// blit fill, wait for GPU completion, and signal the completion fence.
    pub fn d3dkmt_render(&self, request: RenderRequest) -> WddmResult<RenderResult> {
        let (device, context_id, effective_priority, bytes, fence, fence_completion) = {
            let state = self.state();
            let object_id = require_device(&state, request.device)?;
            let context = state
                .contexts
                .get(&request.context)
                .ok_or_else(|| WddmError::new(STATUS_INVALID_HANDLE, "unknown render context"))?;
            if context.device_object != object_id {
                return failed(
                    STATUS_INVALID_HANDLE,
                    "render context belongs to another device",
                );
            }
            if request.allocations.is_empty() || request.allocations.len() > MAX_KMT_ARRAY {
                return failed(
                    STATUS_INVALID_PARAMETER,
                    "render allocation array is outside 1..=MAX_KMT_ARRAY",
                );
            }
            let mut bytes = 0_u64;
            let mut effective_priority = context.priority;
            for allocation in &request.allocations {
                let reference = state.allocations.get(allocation).ok_or_else(|| {
                    WddmError::new(
                        STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE,
                        "render allocation list references an unknown handle",
                    )
                })?;
                if reference.device_object != object_id {
                    return failed(
                        STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE,
                        "render allocation is not opened on this device",
                    );
                }
                let object = state
                    .allocation_objects
                    .get(&reference.object)
                    .expect("allocation object present for live handle");
                bytes = bytes.saturating_add(object.size);
                effective_priority = effective_priority.max(object.priority);
            }
            let fence = match request.fence {
                None => None,
                Some((sync_object, value)) => {
                    let record = state.sync_objects.get(&sync_object).ok_or_else(|| {
                        WddmError::new(STATUS_INVALID_HANDLE, "unknown render fence")
                    })?;
                    if record.device_object != object_id {
                        return failed(
                            STATUS_INVALID_HANDLE,
                            "render fence belongs to another device",
                        );
                    }
                    let current = record
                        .value
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if value <= *current {
                        return failed(
                            STATUS_INVALID_PARAMETER,
                            "render fence value must increase",
                        );
                    }
                    Some((
                        sync_object,
                        value,
                        record.event.clone(),
                        Arc::clone(&record.value),
                    ))
                }
            };
            let device = state
                .adapters
                .get(&context.adapter_id)
                .expect("adapter present for live device")
                .device
                .clone();
            let fence_completion = fence.as_ref().map_or(0, |(_, value, _, _)| *value);
            (
                device,
                context.context_id,
                effective_priority,
                bytes.min(MAX_RENDER_BYTES),
                fence,
                fence_completion,
            )
        };
        submit_gpu_fill(&device, bytes, request.fill_value)?;
        let mut state = self.state();
        if let Some((_sync_object, value, event, gate)) = fence {
            let mut current = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if value <= *current {
                return failed(
                    STATUS_INVALID_PARAMETER,
                    "render fence value was overtaken during submission",
                );
            }
            *current = value;
            event.set_signaled_value(value);
            state.statistics.signal_count += 1;
        }
        if let Some(context) = state.contexts.get_mut(&request.context) {
            context.submit_count += 1;
            context.submit_bytes += bytes;
        }
        state.statistics.render_count += 1;
        state.statistics.render_bytes += bytes;
        state.statistics.last_effective_priority = effective_priority;
        Ok(RenderResult {
            context_id,
            bytes_filled: bytes,
            fence_value: fence_completion,
            effective_priority,
        })
    }

    /// `D3DKMTQueryStatistics` for the documented ADAPTER/ADAPTER2/NODE types.
    pub fn d3dkmt_query_statistics_for(
        &self,
        adapter: AdapterHandle,
        query_type: u32,
        node_ordinal: u32,
    ) -> WddmResult<WddmStatistics> {
        if query_type == D3DKMT_QUERYSTATISTICS_NODE {
            let node = self.d3dkmt_query_node_statistics(adapter, node_ordinal)?;
            return Ok(WddmStatistics {
                allocation_count: node.allocation_count,
                allocated_bytes: node.allocated_bytes,
                render_count: node.render_count,
                render_bytes: node.render_bytes,
                context_count: node.context_count,
                ..WddmStatistics::default()
            });
        }
        if query_type != D3DKMT_QUERYSTATISTICS_ADAPTER
            && query_type != D3DKMT_QUERYSTATISTICS_ADAPTER2
        {
            if query_type > 19 {
                return failed(
                    STATUS_INVALID_PARAMETER,
                    "query statistics type is not a documented D3DKMT type",
                );
            }
            return failed(
                STATUS_NOT_SUPPORTED,
                "query statistics type is not modelled by the Metal personality",
            );
        }
        let state = self.state();
        let adapter_id = require_adapter(&state, adapter)?;
        Ok(statistics_for_adapter(&state, adapter_id))
    }

    /// `D3DKMT_QUERYSTATISTICS_NODE` counters for render node 0.
    pub fn d3dkmt_query_node_statistics(
        &self,
        adapter: AdapterHandle,
        node_ordinal: u32,
    ) -> WddmResult<WddmNodeStatistics> {
        if node_ordinal >= RENDER_NODE_COUNT {
            return failed(
                STATUS_INVALID_PARAMETER,
                "statistics node ordinal does not exist",
            );
        }
        let state = self.state();
        let adapter_id = require_adapter(&state, adapter)?;
        let context_count = state
            .contexts
            .values()
            .filter(|context| {
                context.adapter_id == adapter_id && context.node_ordinal == node_ordinal
            })
            .count() as u64;
        let (render_count, render_bytes) = state
            .contexts
            .values()
            .filter(|context| {
                context.adapter_id == adapter_id && context.node_ordinal == node_ordinal
            })
            .fold((0_u64, 0_u64), |(count, bytes), context| {
                (count + context.submit_count, bytes + context.submit_bytes)
            });
        let node = WddmNodeStatistics {
            node_ordinal,
            context_count,
            render_count,
            render_bytes,
            last_effective_priority: state.statistics.last_effective_priority,
            allocation_count: state
                .allocation_objects
                .values()
                .filter(|object| object.adapter_id == adapter_id)
                .count() as u64,
            allocated_bytes: state
                .allocation_objects
                .values()
                .filter(|object| object.adapter_id == adapter_id)
                .map(|object| object.size)
                .sum(),
        };
        Ok(node)
    }

    /// `D3DKMTCreateSwapChain`: allocate the backend offscreen/present surface.
    pub fn d3dkmt_create_swapchain(
        &self,
        request: CreateSwapChainRequest,
    ) -> WddmResult<SwapChainHandle> {
        let mut state = self.state();
        let object_id = require_device(&state, request.device)?;
        if request.width == 0 || request.height == 0 {
            return failed(
                STATUS_INVALID_PARAMETER,
                "swapchain dimensions must be non-zero",
            );
        }
        if request.format == DxgiFormat::Unknown {
            return failed(
                STATUS_GRAPHICS_INVALID_PIXELFORMAT,
                "unknown swapchain pixel format",
            );
        }
        let gfx_swapchain = self
            .backend()
            .create_swapchain(SwapchainDesc {
                width: request.width,
                height: request.height,
                format: request.format,
                buffer_count: request.buffer_count,
            })
            .map_err(|_| {
                WddmError::new(
                    STATUS_INVALID_PARAMETER,
                    "GPU backend rejected the swapchain",
                )
            })?;
        let handle = SwapChainHandle(state.alloc_handle());
        state.swapchains.insert(
            handle,
            SwapChainRecord {
                gfx_swapchain,
                device_object: object_id,
                width: request.width,
                height: request.height,
                buffer_count: request.buffer_count,
                present_count: 0,
                refresh_count: 0,
                flip_index: 0,
            },
        );
        state
            .device_objects
            .get_mut(&object_id)
            .expect("device object present for live handle")
            .swapchains
            .insert(handle);
        Ok(handle)
    }

    /// `D3DKMTPresent`: route the flip through the existing GPU present path.
    pub fn d3dkmt_present(&self, request: PresentRequest) -> WddmResult<WddmPresentResult> {
        let mut state = self.state();
        let gfx_swapchain = state
            .swapchains
            .get(&request.swapchain)
            .ok_or_else(|| {
                WddmError::new(
                    STATUS_GRAPHICS_PRESENT_INVALID_WINDOW,
                    "unknown or closed swapchain",
                )
            })?
            .gfx_swapchain;
        let presented = self
            .backend()
            .present(gfx_swapchain, request.sync_interval, request.allow_tearing)
            .map_err(|_| {
                WddmError::new(STATUS_INVALID_PARAMETER, "GPU backend rejected the present")
            })?;
        let record = state
            .swapchains
            .get_mut(&request.swapchain)
            .expect("swapchain cannot be destroyed while the state lock is held");
        let refresh_advance = u64::from(request.sync_interval.max(1));
        record.present_count += 1;
        record.refresh_count += refresh_advance;
        record.flip_index = (record.flip_index + 1) % record.buffer_count;
        let result = WddmPresentResult {
            present_count: record.present_count,
            refresh_count: record.refresh_count,
            flip_index: record.flip_index,
            displayed_frame_index: presented.displayed_frame_index,
            frame_time_ns: presented.frame_time_ns,
            tearing_allowed: presented.tearing_allowed,
        };
        state.statistics.present_count += 1;
        state.statistics.refresh_count += refresh_advance;
        state.statistics.flip_count += 1;
        state.statistics.last_frame_time_ns = presented.frame_time_ns;
        state.statistics.last_displayed_frame_index = presented.displayed_frame_index;
        Ok(result)
    }

    /// Swapchain state reported to the guest.
    pub fn d3dkmt_query_swapchain_info(
        &self,
        swapchain: SwapChainHandle,
    ) -> WddmResult<SwapChainInfo> {
        let state = self.state();
        let record = state.swapchains.get(&swapchain).ok_or_else(|| {
            WddmError::new(
                STATUS_GRAPHICS_PRESENT_INVALID_WINDOW,
                "unknown or closed swapchain",
            )
        })?;
        Ok(SwapChainInfo {
            width: record.width,
            height: record.height,
            buffer_count: record.buffer_count,
            present_count: record.present_count,
            refresh_count: record.refresh_count,
            flip_index: record.flip_index,
        })
    }

    /// `D3DKMTDestroySwapChain`.
    pub fn d3dkmt_destroy_swapchain(&self, swapchain: SwapChainHandle) -> WddmResult<()> {
        let mut state = self.state();
        let record = state
            .swapchains
            .remove(&swapchain)
            .ok_or_else(|| WddmError::new(STATUS_INVALID_HANDLE, "unknown swapchain handle"))?;
        if let Some(device) = state.device_objects.get_mut(&record.device_object) {
            device.swapchains.remove(&swapchain);
        }
        let _ = self.backend().destroy_swapchain(record.gfx_swapchain);
        Ok(())
    }

    /// `D3DKMTQueryStatistics`: live object/memory counts plus backend counters.
    pub fn d3dkmt_query_statistics(&self) -> WddmStatistics {
        let state = self.state();
        WddmStatistics {
            present_count: state.statistics.present_count,
            refresh_count: state.statistics.refresh_count,
            flip_count: state.statistics.flip_count,
            allocation_count: state.allocation_objects.len() as u64,
            allocated_bytes: state
                .allocation_objects
                .values()
                .map(|object| object.size)
                .sum(),
            resident_count: state
                .allocation_objects
                .values()
                .filter(|object| object.residency > 0)
                .count() as u64,
            resident_bytes: state
                .allocation_objects
                .values()
                .filter(|object| object.residency > 0)
                .map(|object| object.size)
                .sum(),
            signal_count: state.statistics.signal_count,
            wait_count: state.statistics.wait_count,
            timeout_count: state.statistics.timeout_count,
            last_frame_time_ns: state.statistics.last_frame_time_ns,
            last_displayed_frame_index: state.statistics.last_displayed_frame_index,
            render_count: state.statistics.render_count,
            render_bytes: state.statistics.render_bytes,
            context_count: state.contexts.len() as u64,
            keyed_mutex_acquire_count: state.statistics.keyed_mutex_acquire_count,
            keyed_mutex_timeout_count: state.statistics.keyed_mutex_timeout_count,
        }
    }
}

fn statistics_for_adapter(state: &WddmState, adapter_id: u64) -> WddmStatistics {
    let allocation_objects = state
        .allocation_objects
        .values()
        .filter(|object| object.adapter_id == adapter_id);
    WddmStatistics {
        present_count: state.statistics.present_count,
        refresh_count: state.statistics.refresh_count,
        flip_count: state.statistics.flip_count,
        allocation_count: allocation_objects.clone().count() as u64,
        allocated_bytes: allocation_objects.clone().map(|object| object.size).sum(),
        resident_count: allocation_objects
            .clone()
            .filter(|object| object.residency > 0)
            .count() as u64,
        resident_bytes: allocation_objects
            .filter(|object| object.residency > 0)
            .map(|object| object.size)
            .sum(),
        signal_count: state.statistics.signal_count,
        wait_count: state.statistics.wait_count,
        timeout_count: state.statistics.timeout_count,
        last_frame_time_ns: state.statistics.last_frame_time_ns,
        last_displayed_frame_index: state.statistics.last_displayed_frame_index,
        render_count: state.statistics.render_count,
        render_bytes: state.statistics.render_bytes,
        context_count: state
            .contexts
            .values()
            .filter(|context| context.adapter_id == adapter_id)
            .count() as u64,
        keyed_mutex_acquire_count: state.statistics.keyed_mutex_acquire_count,
        keyed_mutex_timeout_count: state.statistics.keyed_mutex_timeout_count,
    }
}

fn adapter_snapshot(record: &AdapterRecord) -> WddmAdapterInfo {
    let mut info = record.info.clone();
    info.segments = record
        .segments
        .iter()
        .enumerate()
        .map(|(index, segment)| SegmentInfo {
            id: SegmentId(index as u32),
            budget: segment.budget,
            used: segment.used,
        })
        .collect();
    info
}

fn require_adapter(state: &WddmState, handle: AdapterHandle) -> WddmResult<u64> {
    state.adapter_handles.get(&handle).copied().ok_or_else(|| {
        WddmError::new(
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER,
            "unknown adapter handle",
        )
    })
}

fn require_device(state: &WddmState, handle: DeviceHandle) -> WddmResult<u64> {
    state
        .devices
        .get(&handle)
        .copied()
        .ok_or_else(|| WddmError::new(STATUS_INVALID_HANDLE, "unknown device handle"))
}

fn allocation_object_id(state: &WddmState, allocation: AllocationHandle) -> WddmResult<u64> {
    state
        .allocations
        .get(&allocation)
        .map(|reference| reference.object)
        .ok_or_else(|| {
            WddmError::new(
                STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE,
                "unknown allocation handle",
            )
        })
}

#[rustfmt::skip]
fn allocation_object(
    state: &WddmState,
    allocation: AllocationHandle,
) -> WddmResult<&AllocationObject> {
    let object = allocation_object_id(state, allocation)?;
    state.allocation_objects.get(&object).ok_or_else(|| {
        WddmError::new( // coverage: unreachable — live handles imply live objects
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE,
            "allocation object is not live",
        )
    }) // coverage: unreachable — no public entry point can drop an allocation object while its handle remains
}

fn remove_allocation_handle(
    state: &mut WddmState,
    allocation: AllocationHandle,
) -> Option<AllocationRef> {
    let reference = state.allocations.remove(&allocation)?;
    if let Some(device) = state.device_objects.get_mut(&reference.device_object) {
        device.allocations.remove(&allocation);
    }
    let live: BTreeSet<(u64, u64)> = state
        .allocations
        .values()
        .map(|live| (live.device_object, live.object))
        .collect();
    state
        .allocation_keys
        .retain(|(device_object, _), object| live.contains(&(*device_object, *object)));
    if live.iter().any(|(_, object)| *object == reference.object) {
        return Some(reference);
    }
    let object = state.allocation_objects.remove(&reference.object)?;
    let doomed: Vec<KeyedMutexHandle> = state
        .keyed_mutexes
        .iter()
        .filter(|(_, record)| record.object == reference.object)
        .map(|(handle, _)| *handle)
        .collect();
    for handle in doomed {
        state.keyed_mutexes.remove(&handle);
        for device in state.device_objects.values_mut() {
            device.keyed_mutexes.remove(&handle);
        }
    }
    if object.residency > 0 {
        if let Some(segment) = state
            .adapters
            .get_mut(&object.adapter_id)
            .and_then(|adapter| adapter.segments.get_mut(object.segment.0 as usize))
        {
            segment.used = segment.used.saturating_sub(object.size);
        }
    }
    Some(reference)
}

fn submit_gpu_fill(device: &metal::Device, bytes: u64, fill_value: u8) -> WddmResult<()> {
    let length = (bytes.max(4) + 3) & !3;
    let queue = device.new_command_queue();
    let buffer = device.new_buffer(length, metal::MTLResourceOptions::StorageModeShared);
    let command_buffer = queue.new_command_buffer();
    {
        let encoder = command_buffer.new_blit_command_encoder();
        encoder.fill_buffer(&buffer, metal::NSRange::new(0, length), fill_value);
        encoder.end_encoding();
    }
    command_buffer.commit();
    command_buffer.wait_until_completed();
    completion_status(command_buffer.status())
}

fn completion_status(status: metal::MTLCommandBufferStatus) -> WddmResult<()> {
    if status == metal::MTLCommandBufferStatus::Completed {
        Ok(())
    } else {
        failed(
            STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE,
            "Metal blit command buffer did not complete",
        )
    }
}

fn wait_for_shared_event(event: &metal::SharedEvent, value: u64, timeout_ms: u64) -> bool {
    let object = event.as_ptr() as *mut objc::runtime::Object;
    // SAFETY: `event` is a live MTLSharedEvent; `waitUntilSignaledValue:` is
    // the documented thread-safe blocking wait for a shareable event.
    let signaled: objc::runtime::BOOL =
        unsafe { msg_send![object, waitUntilSignaledValue: value timeoutMS: timeout_ms] };
    signaled == objc::runtime::YES
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    fn subsystem() -> Arc<WddmSubsystem> {
        let subsystem = WddmSubsystem::new();
        assert!(
            !subsystem.d3dkmt_enum_adapters().is_empty(),
            "a real Metal device is required for the WDDM facade"
        );
        Arc::new(subsystem)
    }

    fn open_adapter(subsystem: &WddmSubsystem) -> AdapterHandle {
        let info = subsystem
            .d3dkmt_enum_adapters()
            .into_iter()
            .next()
            .expect("enumerated adapter");
        subsystem
            .d3dkmt_open_adapter_from_luid(info.luid)
            .expect("open adapter")
    }

    fn create_device(
        subsystem: &WddmSubsystem,
        adapter: AdapterHandle,
        shareable: bool,
    ) -> DeviceHandle {
        subsystem
            .d3dkmt_create_device(CreateDeviceRequest {
                adapter,
                shareable,
                owner_process: 7,
            })
            .expect("create device")
    }

    fn create_allocation(
        subsystem: &WddmSubsystem,
        device: DeviceHandle,
        size: u64,
        segment: SegmentId,
        resource_id: u64,
    ) -> AllocationHandle {
        subsystem
            .d3dkmt_create_allocation(CreateAllocationRequest {
                device,
                size,
                segment,
                resource_id,
                shareable: true,
                owner_process: 7,
            })
            .expect("create allocation")
    }

    fn create_sync(
        subsystem: &WddmSubsystem,
        device: DeviceHandle,
        initial_value: u64,
    ) -> SyncObjectHandle {
        subsystem
            .d3dkmt_create_synchronization_object(device, initial_value)
            .expect("create synchronization object")
    }

    fn create_context(
        subsystem: &WddmSubsystem,
        device: DeviceHandle,
        priority: u32,
    ) -> ContextHandle {
        subsystem
            .d3dkmt_create_context(CreateContextRequest {
                device,
                node_ordinal: RENDER_NODE_ORDINAL,
                priority,
            })
            .expect("create context")
    }

    fn create_swapchain(
        subsystem: &WddmSubsystem,
        device: DeviceHandle,
        width: u32,
        height: u32,
        buffer_count: u32,
    ) -> SwapChainHandle {
        subsystem
            .d3dkmt_create_swapchain(CreateSwapChainRequest {
                device,
                width,
                height,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count,
            })
            .expect("create swapchain")
    }

    #[test]
    fn invalid_luid_and_adapter_handles_are_rejected_with_graphics_status() {
        let empty = WddmSubsystem::with_metal_devices(Vec::new());
        assert_eq!(empty.d3dkmt_enum_adapters(), Vec::new());
        let missing_luid = Luid {
            LowPart: 0xDEAD_BEEF,
            HighPart: 0x0BAD_F00D_u32 as i32,
        };
        let missing = empty
            .d3dkmt_open_adapter_from_luid(missing_luid)
            .unwrap_err();
        assert_eq!(missing.status(), STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER);
        assert_eq!(missing.detail(), "no adapter has this LUID");

        let subsystem = subsystem();
        let info = subsystem
            .d3dkmt_enum_adapters()
            .into_iter()
            .next()
            .expect("enumerated adapter");
        assert_eq!(
            info.luid,
            luid_from_metal_identity(info.registry_id, &info.name)
        );
        assert_eq!(
            info.luid.to_u64() >> 32,
            u64::from(info.luid.HighPart as u32)
        );
        assert_eq!(info.segments.len(), 2);

        let adapter = subsystem
            .d3dkmt_open_adapter_from_luid(info.luid)
            .expect("open adapter");
        let queried = subsystem
            .d3dkmt_query_adapter_info(adapter)
            .expect("query adapter");
        assert_eq!(queried.luid, info.luid);
        assert_eq!(queried.registry_id, info.registry_id);
        assert_eq!(queried.segments.len(), 2);
        assert_eq!(
            subsystem
                .d3dkmt_query_adapter_info(AdapterHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
        assert_eq!(
            subsystem
                .d3dkmt_close_adapter(AdapterHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
        assert_eq!(subsystem.d3dkmt_close_adapter(adapter), Ok(()));
        assert_eq!(
            subsystem
                .d3dkmt_close_adapter(adapter)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_device(CreateDeviceRequest {
                    adapter,
                    shareable: false,
                    owner_process: 7,
                })
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
    }

    #[test]
    fn device_open_duplicate_destroy_and_lifetime_boundaries_are_exact() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        assert_eq!(
            subsystem
                .d3dkmt_create_device(CreateDeviceRequest {
                    adapter: AdapterHandle(0xDEAD),
                    shareable: true,
                    owner_process: 7,
                })
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );

        let private = create_device(&subsystem, adapter, false);
        assert_eq!(
            subsystem.device_info(private).expect("device info"),
            DeviceInfo {
                shareable: false,
                owner_process: 7,
            }
        );
        assert_eq!(
            subsystem
                .device_info(DeviceHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem.d3dkmt_open_device(private).unwrap_err().status(),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_device(DeviceHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );

        let first = create_device(&subsystem, adapter, true);
        let second = subsystem
            .d3dkmt_open_device(first)
            .expect("shareable device opens");
        let allocation = create_allocation(&subsystem, first, 128, SEGMENT_LOCAL, 1);
        let sync = create_sync(&subsystem, first, 0);
        let swapchain = create_swapchain(&subsystem, first, 4, 4, 2);
        assert_eq!(
            subsystem
                .d3dkmt_close_adapter(adapter)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_ALLOCATION_BUSY
        );

        assert_eq!(subsystem.d3dkmt_destroy_device(first), Ok(()));
        assert_eq!(
            subsystem
                .allocation_info(allocation)
                .expect("second handle keeps the object alive")
                .size,
            128
        );
        assert_eq!(subsystem.d3dkmt_destroy_device(second), Ok(()));
        assert_eq!(
            subsystem
                .d3dkmt_destroy_device(second)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem.allocation_info(allocation).unwrap_err().status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_object(sync, 1)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_query_swapchain_info(swapchain)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_PRESENT_INVALID_WINDOW
        );
        assert_eq!(subsystem.d3dkmt_destroy_device(private), Ok(()));
        assert_eq!(subsystem.d3dkmt_close_adapter(adapter), Ok(()));
    }

    #[test]
    fn duplicate_allocation_and_invalid_allocation_handles_are_rejected() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);

        assert_eq!(
            subsystem
                .d3dkmt_create_allocation(CreateAllocationRequest {
                    device: DeviceHandle(0xFFFF_FFFF),
                    size: 1,
                    segment: SEGMENT_LOCAL,
                    resource_id: 1,
                    shareable: false,
                    owner_process: 7,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_allocation(CreateAllocationRequest {
                    device,
                    size: 0,
                    segment: SEGMENT_LOCAL,
                    resource_id: 1,
                    shareable: false,
                    owner_process: 7,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_allocation(CreateAllocationRequest {
                    device,
                    size: 1,
                    segment: SegmentId(9),
                    resource_id: 1,
                    shareable: false,
                    owner_process: 7,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );

        let allocation = create_allocation(&subsystem, device, 4096, SEGMENT_LOCAL, 42);
        assert_eq!(
            subsystem
                .d3dkmt_create_allocation(CreateAllocationRequest {
                    device,
                    size: 1,
                    segment: SEGMENT_NON_LOCAL,
                    resource_id: 42,
                    shareable: false,
                    owner_process: 8,
                })
                .unwrap_err()
                .status(),
            STATUS_OBJECT_NAME_COLLISION
        );

        let info = subsystem
            .allocation_info(allocation)
            .expect("allocation info");
        assert_eq!(info.size, 4096);
        assert_eq!(info.owner_process, 7);
        assert_eq!(info.shareable, true);
        assert_eq!(info.segment, SEGMENT_LOCAL);
        assert_eq!(
            subsystem.d3dkmt_query_allocation_residency(allocation),
            Ok(0)
        );
        assert_eq!(
            subsystem
                .allocation_info(AllocationHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_query_allocation_residency(AllocationHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_make_resident(AllocationHandle(0xFFFF_FFFF), 7)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_evict(AllocationHandle(0xFFFF_FFFF), 7)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_make_resident(allocation, 8)
                .unwrap_err()
                .status(),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            subsystem.d3dkmt_evict(allocation, 8).unwrap_err().status(),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(subsystem.d3dkmt_destroy_allocation(allocation), Ok(()));
        assert_eq!(
            subsystem
                .d3dkmt_destroy_allocation(allocation)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem.allocation_info(allocation).unwrap_err().status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
    }

    #[test]
    fn residency_accounting_over_budget_and_evict_boundaries_are_exact() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let budget = subsystem
            .d3dkmt_query_adapter_info(adapter)
            .expect("adapter info")
            .segments[0]
            .budget;

        let allocation = create_allocation(&subsystem, device, 4096, SEGMENT_LOCAL, 1);
        assert_eq!(subsystem.d3dkmt_make_resident(allocation, 7), Ok(1));
        assert_eq!(subsystem.d3dkmt_make_resident(allocation, 7), Ok(2));
        assert_eq!(
            subsystem
                .d3dkmt_query_adapter_info(adapter)
                .expect("adapter info")
                .segments[0]
                .used,
            4096
        );

        let over_budget = create_allocation(
            &subsystem,
            device,
            budget.saturating_add(1),
            SEGMENT_LOCAL,
            2,
        );
        assert_eq!(
            subsystem
                .d3dkmt_make_resident(over_budget, 7)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_NO_VIDEO_MEMORY
        );

        assert_eq!(subsystem.d3dkmt_evict(allocation, 7), Ok(1));
        assert_eq!(
            subsystem
                .d3dkmt_query_adapter_info(adapter)
                .expect("adapter info")
                .segments[0]
                .used,
            4096
        );
        assert_eq!(subsystem.d3dkmt_evict(allocation, 7), Ok(0));
        assert_eq!(
            subsystem
                .d3dkmt_query_adapter_info(adapter)
                .expect("adapter info")
                .segments[0]
                .used,
            0
        );
        assert_eq!(
            subsystem.d3dkmt_evict(allocation, 7).unwrap_err().status(),
            STATUS_GRAPHICS_ALLOCATION_BUSY
        );

        assert_eq!(subsystem.d3dkmt_make_resident(allocation, 7), Ok(1));
        assert_eq!(subsystem.d3dkmt_destroy_allocation(allocation), Ok(()));
        assert_eq!(
            subsystem
                .d3dkmt_query_adapter_info(adapter)
                .expect("adapter info")
                .segments[0]
                .used,
            0
        );

        let non_local = create_allocation(&subsystem, device, 1, SEGMENT_NON_LOCAL, 3);
        assert_eq!(subsystem.d3dkmt_make_resident(non_local, 7), Ok(1));
        assert_eq!(
            subsystem
                .d3dkmt_query_adapter_info(adapter)
                .expect("adapter info")
                .segments[1]
                .used,
            1
        );
        assert_eq!(subsystem.d3dkmt_destroy_allocation(non_local), Ok(()));

        let idle = create_allocation(&subsystem, device, 8, SEGMENT_LOCAL, 4);
        assert_eq!(subsystem.d3dkmt_destroy_allocation(idle), Ok(()));

        let statistics = subsystem.d3dkmt_query_statistics();
        assert_eq!(statistics.allocation_count, 1);
        assert_eq!(statistics.allocated_bytes, budget.saturating_add(1));
        assert_eq!(statistics.resident_count, 0);
        assert_eq!(statistics.resident_bytes, 0);
    }

    #[test]
    fn synchronization_invalid_handles_timeouts_and_backwards_signals_are_rejected() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        assert_eq!(
            subsystem
                .d3dkmt_create_synchronization_object(DeviceHandle(0xFFFF_FFFF), 0)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );

        let sync = create_sync(&subsystem, device, 2);
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_object(SyncObjectHandle(0xFFFF_FFFF), 1)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_wait_for_synchronization_object(SyncObjectHandle(0xFFFF_FFFF), 1, 0)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem.d3dkmt_wait_for_synchronization_object(sync, 2, 0),
            Ok(())
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_object(sync, 1)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_object(sync, 2)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem.d3dkmt_signal_synchronization_object(sync, 3),
            Ok(())
        );
        assert_eq!(
            subsystem
                .d3dkmt_wait_for_synchronization_object(sync, 4, 0)
                .unwrap_err()
                .status(),
            STATUS_TIMEOUT
        );
        let started = Instant::now();
        assert_eq!(
            subsystem
                .d3dkmt_wait_for_synchronization_object(sync, 4, 2_000_000)
                .unwrap_err()
                .status(),
            STATUS_TIMEOUT
        );
        assert!(started.elapsed() >= Duration::from_millis(1));
        assert_eq!(
            subsystem.d3dkmt_signal_synchronization_object(sync, 5),
            Ok(())
        );
        assert_eq!(
            subsystem.d3dkmt_wait_for_synchronization_object(sync, 5, u64::MAX),
            Ok(())
        );

        let statistics = subsystem.d3dkmt_query_statistics();
        assert_eq!(statistics.signal_count, 2);
        assert_eq!(statistics.wait_count, 4);
        assert_eq!(statistics.timeout_count, 2);
    }

    #[test]
    fn concurrent_signal_wait_races_wake_each_waiter_exactly_once() {
        const WAITERS: usize = 6;
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let sync = create_sync(&subsystem, device, 0);
        let barrier = Arc::new(Barrier::new(WAITERS + 1));
        let wakes = Arc::new(AtomicUsize::new(0));
        let mut waiters = Vec::new();
        for _ in 0..WAITERS {
            let subsystem = Arc::clone(&subsystem);
            let barrier = Arc::clone(&barrier);
            let wakes = Arc::clone(&wakes);
            waiters.push(thread::spawn(move || {
                barrier.wait();
                let result = subsystem.d3dkmt_wait_for_synchronization_object(sync, 1, u64::MAX);
                if result.is_ok() {
                    wakes.fetch_add(1, Ordering::SeqCst);
                }
                result.map_err(|error| error.status())
            }));
        }
        barrier.wait();
        thread::sleep(Duration::from_millis(10));
        assert_eq!(
            subsystem.d3dkmt_signal_synchronization_object(sync, 1),
            Ok(())
        );
        for waiter in waiters {
            assert_eq!(waiter.join().expect("waiter thread"), Ok(()));
        }
        assert_eq!(wakes.load(Ordering::SeqCst), WAITERS);
        let statistics = subsystem.d3dkmt_query_statistics();
        assert_eq!(statistics.wait_count, WAITERS as u64);
        assert_eq!(statistics.timeout_count, 0);
    }

    #[test]
    fn concurrent_wait_timeouts_are_per_waiter_and_exact() {
        const WAITERS: usize = 4;
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let sync = create_sync(&subsystem, device, 0);
        let barrier = Arc::new(Barrier::new(WAITERS + 1));
        let mut waiters = Vec::new();
        for _ in 0..WAITERS {
            let subsystem = Arc::clone(&subsystem);
            let barrier = Arc::clone(&barrier);
            waiters.push(thread::spawn(move || {
                barrier.wait();
                subsystem.d3dkmt_wait_for_synchronization_object(sync, 9, 2_000_000)
            }));
        }
        barrier.wait();
        for waiter in waiters {
            let error = waiter.join().expect("waiter thread").unwrap_err();
            assert_eq!(error.status(), STATUS_TIMEOUT);
        }
        let statistics = subsystem.d3dkmt_query_statistics();
        assert_eq!(statistics.wait_count, WAITERS as u64);
        assert_eq!(statistics.timeout_count, WAITERS as u64);
    }

    #[test]
    fn present_on_invalid_and_closed_swapchains_is_rejected() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        assert_eq!(
            subsystem
                .d3dkmt_create_swapchain(CreateSwapChainRequest {
                    device: DeviceHandle(0xFFFF_FFFF),
                    width: 8,
                    height: 8,
                    format: DxgiFormat::B8G8R8A8Unorm,
                    buffer_count: 2,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_swapchain(CreateSwapChainRequest {
                    device,
                    width: 0,
                    height: 8,
                    format: DxgiFormat::B8G8R8A8Unorm,
                    buffer_count: 2,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_swapchain(CreateSwapChainRequest {
                    device,
                    width: 8,
                    height: 8,
                    format: DxgiFormat::B8G8R8A8Unorm,
                    buffer_count: 1,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_swapchain(CreateSwapChainRequest {
                    device,
                    width: 8,
                    height: 8,
                    format: DxgiFormat::Unknown,
                    buffer_count: 2,
                })
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_PIXELFORMAT
        );

        let swapchain = create_swapchain(&subsystem, device, 8, 8, 3);
        assert_eq!(
            subsystem
                .d3dkmt_query_swapchain_info(SwapChainHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_PRESENT_INVALID_WINDOW
        );
        assert_eq!(
            subsystem
                .d3dkmt_present(PresentRequest {
                    swapchain: SwapChainHandle(0xFFFF_FFFF),
                    sync_interval: 0,
                    allow_tearing: false,
                })
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_PRESENT_INVALID_WINDOW
        );
        assert_eq!(
            subsystem
                .d3dkmt_present(PresentRequest {
                    swapchain,
                    sync_interval: 5,
                    allow_tearing: false,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );

        let first = subsystem
            .d3dkmt_present(PresentRequest {
                swapchain,
                sync_interval: 0,
                allow_tearing: true,
            })
            .expect("first present");
        assert_eq!(first.present_count, 1);
        assert_eq!(first.refresh_count, 1);
        assert_eq!(first.flip_index, 1);
        assert_eq!(first.displayed_frame_index, 1);
        assert_eq!(first.tearing_allowed, true);
        let second = subsystem
            .d3dkmt_present(PresentRequest {
                swapchain,
                sync_interval: 2,
                allow_tearing: false,
            })
            .expect("second present");
        assert_eq!(second.present_count, 2);
        assert_eq!(second.refresh_count, 3);
        assert_eq!(second.flip_index, 2);
        assert_eq!(second.displayed_frame_index, 2);
        assert_eq!(second.tearing_allowed, false);
        let info = subsystem
            .d3dkmt_query_swapchain_info(swapchain)
            .expect("swapchain info");
        assert_eq!(info.present_count, 2);
        assert_eq!(info.refresh_count, 3);
        assert_eq!(info.flip_index, 2);

        assert_eq!(subsystem.d3dkmt_destroy_swapchain(swapchain), Ok(()));
        assert_eq!(
            subsystem
                .d3dkmt_present(PresentRequest {
                    swapchain,
                    sync_interval: 0,
                    allow_tearing: false,
                })
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_PRESENT_INVALID_WINDOW
        );
        assert_eq!(
            subsystem
                .d3dkmt_destroy_swapchain(swapchain)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn statistics_track_gpu_and_memory_counters_across_destroy_boundaries() {
        let empty = WddmSubsystem::with_metal_devices(Vec::new());
        assert_eq!(empty.d3dkmt_query_statistics(), WddmStatistics::default());
        assert_eq!(
            empty
                .d3dkmt_make_resident(AllocationHandle(1), 0)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );

        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let allocation = create_allocation(&subsystem, device, 4096, SEGMENT_LOCAL, 1);
        assert_eq!(subsystem.d3dkmt_make_resident(allocation, 7), Ok(1));
        let sync = create_sync(&subsystem, device, 0);
        assert_eq!(
            subsystem.d3dkmt_signal_synchronization_object(sync, 1),
            Ok(())
        );
        assert_eq!(
            subsystem.d3dkmt_wait_for_synchronization_object(sync, 1, 0),
            Ok(())
        );
        let swapchain = create_swapchain(&subsystem, device, 8, 8, 2);
        subsystem
            .d3dkmt_present(PresentRequest {
                swapchain,
                sync_interval: 1,
                allow_tearing: false,
            })
            .expect("first present");
        subsystem
            .d3dkmt_present(PresentRequest {
                swapchain,
                sync_interval: 1,
                allow_tearing: false,
            })
            .expect("second present");

        let statistics = subsystem.d3dkmt_query_statistics();
        assert_eq!(statistics.present_count, 2);
        assert_eq!(statistics.refresh_count, 2);
        assert_eq!(statistics.flip_count, 2);
        assert_eq!(statistics.allocation_count, 1);
        assert_eq!(statistics.allocated_bytes, 4096);
        assert_eq!(statistics.resident_count, 1);
        assert_eq!(statistics.resident_bytes, 4096);
        assert_eq!(statistics.signal_count, 1);
        assert_eq!(statistics.wait_count, 1);
        assert_eq!(statistics.timeout_count, 0);
        assert_eq!(statistics.last_displayed_frame_index, 2);
        assert_ne!(statistics.last_frame_time_ns, 0);

        assert_eq!(subsystem.d3dkmt_destroy_allocation(allocation), Ok(()));
        let after = subsystem.d3dkmt_query_statistics();
        assert_eq!(after.allocation_count, 0);
        assert_eq!(after.allocated_bytes, 0);
        assert_eq!(after.resident_count, 0);
        assert_eq!(after.resident_bytes, 0);
    }

    #[test]
    fn allocation_arrays_reject_invalid_bounds_segments_and_duplicate_identities() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let request = |allocations: Vec<AllocationDesc>, base: u64| CreateAllocationsRequest {
            device,
            allocations,
            resource_id_base: base,
            shareable: true,
            owner_process: 7,
        };
        assert_eq!(
            subsystem
                .d3dkmt_create_allocations(request(Vec::new(), 0))
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_allocations(request(
                    vec![
                        AllocationDesc {
                            size: 1,
                            segment: SEGMENT_LOCAL,
                        };
                        MAX_KMT_ARRAY + 1
                    ],
                    0
                ))
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_allocations(request(
                    vec![
                        AllocationDesc {
                            size: 0,
                            segment: SEGMENT_LOCAL,
                        },
                        AllocationDesc {
                            size: 1,
                            segment: SEGMENT_LOCAL,
                        },
                    ],
                    1
                ))
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_allocations(request(
                    vec![AllocationDesc {
                        size: 1,
                        segment: SegmentId(9),
                    }],
                    1
                ))
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_allocations(request(
                    vec![
                        AllocationDesc {
                            size: 1,
                            segment: SEGMENT_LOCAL,
                        };
                        2
                    ],
                    u64::MAX
                ))
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(subsystem.d3dkmt_query_statistics().allocation_count, 0);

        let existing = create_allocation(&subsystem, device, 16, SEGMENT_LOCAL, 10);
        assert_eq!(
            subsystem
                .d3dkmt_create_allocations(request(
                    vec![
                        AllocationDesc {
                            size: 1,
                            segment: SEGMENT_LOCAL,
                        };
                        2
                    ],
                    10
                ))
                .unwrap_err()
                .status(),
            STATUS_OBJECT_NAME_COLLISION
        );
        let handles = subsystem
            .d3dkmt_create_allocations(request(
                vec![
                    AllocationDesc {
                        size: 32,
                        segment: SEGMENT_LOCAL,
                    },
                    AllocationDesc {
                        size: 64,
                        segment: SEGMENT_NON_LOCAL,
                    },
                ],
                20,
            ))
            .expect("allocation array");
        assert_eq!(handles.len(), 2);
        assert_eq!(
            subsystem
                .allocation_info(handles[0])
                .expect("first allocation")
                .size,
            32
        );
        assert_eq!(
            subsystem
                .allocation_info(handles[1])
                .expect("second allocation")
                .segment,
            SEGMENT_NON_LOCAL
        );
        assert_eq!(subsystem.d3dkmt_query_statistics().allocation_count, 3);
        for handle in handles {
            assert_eq!(subsystem.d3dkmt_destroy_allocation(handle), Ok(()));
        }
        assert_eq!(subsystem.d3dkmt_destroy_allocation(existing), Ok(()));
        assert_eq!(subsystem.d3dkmt_query_statistics().allocation_count, 0);
    }

    #[test]
    fn context_and_render_reject_stale_handles_invalid_lists_and_priority_bounds() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let other_device = create_device(&subsystem, adapter, false);
        let invalid = CreateContextRequest {
            device,
            node_ordinal: 1,
            priority: 0,
        };
        assert_eq!(
            subsystem
                .d3dkmt_create_context(invalid)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_context(CreateContextRequest {
                    device,
                    node_ordinal: 0,
                    priority: MAX_SCHEDULING_PRIORITY + 1,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_create_context(CreateContextRequest {
                    device: DeviceHandle(0xFFFF_FFFF),
                    node_ordinal: 0,
                    priority: 0,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        let context = create_context(&subsystem, device, MAX_SCHEDULING_PRIORITY);
        let info = subsystem.context_info(context).expect("context info");
        assert_eq!(info.node_ordinal, RENDER_NODE_ORDINAL);
        assert_eq!(info.priority, MAX_SCHEDULING_PRIORITY);
        assert_eq!(info.submit_count, 0);
        assert_eq!(
            subsystem
                .context_info(ContextHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_destroy_context_on(other_device, context)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_destroy_context_on(DeviceHandle(0xFFFF_FFFF), context)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        let allocation = create_allocation(&subsystem, device, 4096, SEGMENT_LOCAL, 1);
        let foreign = create_allocation(&subsystem, other_device, 4096, SEGMENT_LOCAL, 1);

        assert_eq!(
            subsystem
                .d3dkmt_render(RenderRequest {
                    device,
                    context,
                    allocations: Vec::new(),
                    fill_value: 0,
                    fence: None,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_render(RenderRequest {
                    device,
                    context: ContextHandle(0xFFFF_FFFF),
                    allocations: vec![allocation],
                    fill_value: 0,
                    fence: None,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        let foreign_context = create_context(&subsystem, other_device, 0);
        assert_eq!(
            subsystem
                .d3dkmt_render(RenderRequest {
                    device,
                    context: foreign_context,
                    allocations: vec![allocation],
                    fill_value: 0,
                    fence: None,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_render(RenderRequest {
                    device,
                    context,
                    allocations: vec![AllocationHandle(0xFFFF_FFFF)],
                    fill_value: 0,
                    fence: None,
                })
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_render(RenderRequest {
                    device,
                    context,
                    allocations: vec![foreign],
                    fill_value: 0,
                    fence: None,
                })
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_render(RenderRequest {
                    device,
                    context,
                    allocations: vec![allocation; MAX_KMT_ARRAY + 1],
                    fill_value: 0,
                    fence: None,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_render(RenderRequest {
                    device,
                    context,
                    allocations: vec![allocation],
                    fill_value: 0,
                    fence: Some((SyncObjectHandle(0xFFFF_FFFF), 1)),
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        let sync = create_sync(&subsystem, device, 5);
        assert_eq!(
            subsystem
                .d3dkmt_render(RenderRequest {
                    device,
                    context,
                    allocations: vec![allocation],
                    fill_value: 0,
                    fence: Some((sync, 5)),
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        let foreign_sync = create_sync(&subsystem, other_device, 0);
        assert_eq!(
            subsystem
                .d3dkmt_render(RenderRequest {
                    device,
                    context,
                    allocations: vec![allocation],
                    fill_value: 0,
                    fence: Some((foreign_sync, 1)),
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_set_allocation_priority(device, &[allocation], MAX_SCHEDULING_PRIORITY)
                .expect("max priority"),
            ()
        );
        let rendered = subsystem
            .d3dkmt_render(RenderRequest {
                device,
                context,
                allocations: vec![allocation],
                fill_value: 0x41,
                fence: Some((sync, 6)),
            })
            .expect("render submission");
        assert_eq!(rendered.bytes_filled, 4096);
        assert_eq!(rendered.effective_priority, MAX_SCHEDULING_PRIORITY);
        assert_eq!(rendered.fence_value, 6);
        assert_eq!(
            subsystem.d3dkmt_wait_for_synchronization_object(sync, 6, 0),
            Ok(())
        );
        assert_eq!(
            subsystem
                .context_info(context)
                .expect("context info")
                .submit_count,
            1
        );
        assert_eq!(subsystem.d3dkmt_query_statistics().render_count, 1);
        assert_eq!(subsystem.d3dkmt_query_statistics().render_bytes, 4096);
        assert_eq!(subsystem.d3dkmt_destroy_context(context), Ok(()));
        assert_eq!(
            subsystem
                .d3dkmt_destroy_context(context)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_render(RenderRequest {
                    device,
                    context,
                    allocations: vec![allocation],
                    fill_value: 0,
                    fence: None,
                })
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn allocation_priority_boundaries_and_cross_device_lists_are_rejected() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let other = create_device(&subsystem, adapter, false);
        let allocation = create_allocation(&subsystem, device, 8, SEGMENT_LOCAL, 1);
        let foreign = create_allocation(&subsystem, other, 8, SEGMENT_LOCAL, 1);
        assert_eq!(
            subsystem
                .d3dkmt_set_allocation_priority(device, &[allocation], 0)
                .expect("minimum priority"),
            ()
        );
        assert_eq!(subsystem.allocation_priority(allocation), Ok(0));
        assert_eq!(
            subsystem
                .d3dkmt_set_allocation_priority(device, &[allocation], MAX_SCHEDULING_PRIORITY,)
                .expect("maximum priority"),
            ()
        );
        assert_eq!(
            subsystem.allocation_priority(allocation),
            Ok(MAX_SCHEDULING_PRIORITY)
        );
        assert_eq!(
            subsystem
                .d3dkmt_set_allocation_priority(device, &[allocation], MAX_SCHEDULING_PRIORITY + 1,)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_set_allocation_priority(device, &[], 1)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_set_allocation_priority(device, &[foreign], 1)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_set_allocation_priority(device, &[AllocationHandle(0xFFFF_FFFF)], 1,)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem
                .allocation_priority(AllocationHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
    }

    #[test]
    fn shared_resource_open_rejects_collisions_cross_adapter_and_private_data_errors() {
        let devices = metal::Device::all();
        assert!(!devices.is_empty(), "a real Metal device is required");
        let physical = devices[0].clone();
        let subsystem = WddmSubsystem::with_metal_devices(vec![physical.clone(), physical]);
        let info: Vec<_> = subsystem.d3dkmt_enum_adapters();
        assert_eq!(info.len(), 2);
        let first = subsystem
            .d3dkmt_open_adapter_from_luid(info[0].luid)
            .expect("first adapter");
        let second = subsystem
            .d3dkmt_open_adapter_from_display_name("DISPLAY2")
            .expect("second adapter");
        let device = create_device(&subsystem, first, false);
        let same_adapter = create_device(&subsystem, first, false);
        let other_adapter = create_device(&subsystem, second, false);

        let private = subsystem
            .d3dkmt_create_allocation(CreateAllocationRequest {
                device,
                size: 16,
                segment: SEGMENT_LOCAL,
                resource_id: 1,
                shareable: false,
                owner_process: 7,
            })
            .expect("private allocation");
        assert_eq!(
            subsystem
                .d3dkmt_open_resource(same_adapter, private)
                .unwrap_err()
                .status(),
            STATUS_ACCESS_DENIED
        );
        let shared = create_allocation(&subsystem, device, 32, SEGMENT_LOCAL, 2);
        assert_eq!(
            subsystem
                .d3dkmt_open_resource(device, shared)
                .unwrap_err()
                .status(),
            STATUS_OBJECT_NAME_COLLISION
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_resource(other_adapter, shared)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_resource(DeviceHandle(0xFFFF_FFFF), shared)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_resource(same_adapter, AllocationHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        let opened = subsystem
            .d3dkmt_open_resource(same_adapter, shared)
            .expect("open shared resource");
        assert_eq!(
            subsystem.allocation_info(opened).expect("opened info").size,
            32
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_resource(same_adapter, shared)
                .unwrap_err()
                .status(),
            STATUS_OBJECT_NAME_COLLISION
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_resource2(device, opened)
                .unwrap_err()
                .status(),
            STATUS_OBJECT_NAME_COLLISION
        );
        assert_eq!(subsystem.d3dkmt_destroy_allocation(shared), Ok(()));
        assert_eq!(
            subsystem
                .allocation_info(opened)
                .expect("alias keeps object")
                .size,
            32
        );
        assert_eq!(subsystem.d3dkmt_destroy_allocation(opened), Ok(()));
        assert_eq!(
            subsystem
                .allocation_info(private)
                .expect("private allocation survives")
                .size,
            16
        );
    }

    #[test]
    fn keyed_mutex_timeout_release_errors_and_exactly_once_wake_are_exact() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let allocation = create_allocation(&subsystem, device, 64, SEGMENT_LOCAL, 1);
        let private = subsystem
            .d3dkmt_create_allocation(CreateAllocationRequest {
                device,
                size: 8,
                segment: SEGMENT_LOCAL,
                resource_id: 2,
                shareable: false,
                owner_process: 7,
            })
            .expect("private allocation");
        assert_eq!(
            subsystem
                .d3dkmt_open_keyed_mutex(device, private, 0x55)
                .unwrap_err()
                .status(),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_keyed_mutex(device, allocation, 0)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        let mutex = subsystem
            .d3dkmt_open_keyed_mutex(device, allocation, 0x1234)
            .expect("open keyed mutex");
        assert_eq!(
            subsystem
                .d3dkmt_open_keyed_mutex(device, allocation, 0x1234)
                .unwrap_err()
                .status(),
            STATUS_OBJECT_NAME_COLLISION
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_keyed_mutex2(device, allocation, 0x9999)
                .unwrap_err()
                .status(),
            STATUS_OBJECT_NAME_COLLISION
        );
        let other_device = create_device(&subsystem, adapter, false);
        let alias = subsystem
            .d3dkmt_open_resource(other_device, allocation)
            .expect("open resource on second device");
        assert_eq!(
            subsystem
                .d3dkmt_open_keyed_mutex(other_device, alias, 0x9999)
                .unwrap_err()
                .status(),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(mutex, 0x9999, 0, 7)
                .unwrap_err()
                .status(),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(KeyedMutexHandle(0xFFFF_FFFF), 0x1234, 0, 7)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(mutex, 0x1234, 0, 7)
                .expect("first acquire"),
            ()
        );
        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(mutex, 0x1234, 0, 7)
                .expect("recursive acquire"),
            ()
        );
        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(mutex, 0x1234, 0, 8)
                .unwrap_err()
                .status(),
            STATUS_TIMEOUT
        );
        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(mutex, 0x1234, 1_000_000, 8)
                .unwrap_err()
                .status(),
            STATUS_TIMEOUT
        );
        assert_eq!(
            subsystem
                .d3dkmt_release_keyed_mutex(mutex, 0x9999, 7)
                .unwrap_err()
                .status(),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            subsystem
                .d3dkmt_release_keyed_mutex(mutex, 0x1234, 8)
                .unwrap_err()
                .status(),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            subsystem.d3dkmt_release_keyed_mutex(mutex, 0x1234, 7),
            Ok(())
        );
        assert_eq!(
            subsystem.d3dkmt_release_keyed_mutex(mutex, 0x1234, 7),
            Ok(())
        );
        assert_eq!(
            subsystem
                .d3dkmt_release_keyed_mutex(mutex, 0x1234, 7)
                .unwrap_err()
                .status(),
            STATUS_ACCESS_DENIED
        );

        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(mutex, 0x1234, 0, 7)
                .expect("acquire before wake"),
            ()
        );
        let waiter = {
            let subsystem = Arc::clone(&subsystem);
            thread::spawn(move || {
                subsystem.d3dkmt_acquire_keyed_mutex(mutex, 0x1234, 5_000_000_000, 8)
            })
        };
        thread::sleep(Duration::from_millis(20));
        let wakes_before = subsystem
            .keyed_mutex_wake_count(mutex)
            .expect("wake count before release");
        assert_eq!(
            subsystem.d3dkmt_release_keyed_mutex(mutex, 0x1234, 7),
            Ok(())
        );
        assert_eq!(waiter.join().expect("keyed mutex waiter"), Ok(()));
        assert_eq!(
            subsystem.keyed_mutex_wake_count(mutex),
            Ok(wakes_before + 1)
        );
        assert_eq!(
            subsystem
                .d3dkmt_release_keyed_mutex(mutex, 0x1234, 8)
                .expect("waiter release"),
            ()
        );
        assert_eq!(
            subsystem
                .keyed_mutex_wake_count(KeyedMutexHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(subsystem.d3dkmt_destroy_keyed_mutex(mutex), Ok(()));
        assert_eq!(
            subsystem
                .d3dkmt_destroy_keyed_mutex(mutex)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_release_keyed_mutex(mutex, 0x1234, 8)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn synchronization_object_arrays_reject_bad_handles_and_timeout_atomically() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let other = create_device(&subsystem, adapter, false);
        let first = create_sync(&subsystem, device, 0);
        let second = create_sync(&subsystem, device, 0);
        let foreign = create_sync(&subsystem, other, 0);
        let context = create_context(&subsystem, device, 1);
        let foreign_context = create_context(&subsystem, other, 1);
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_objects(device, &[], &[], 1)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_objects(device, &[first; MAX_KMT_ARRAY + 1], &[], 1,)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_objects(
                    device,
                    &[SyncObjectHandle(0xFFFF_FFFF)],
                    &[],
                    1,
                )
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_objects(device, &[foreign], &[], 1)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_objects(
                    device,
                    &[first],
                    &[ContextHandle(0xFFFF_FFFF)],
                    1,
                )
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_objects(device, &[first], &[foreign_context], 1,)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_objects(
                    device,
                    &[first],
                    &[context; MAX_KMT_ARRAY + 1],
                    1,
                )
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem.d3dkmt_signal_synchronization_objects(device, &[first], &[], 1),
            Ok(())
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_objects(device, &[first], &[], 1)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem.d3dkmt_signal_synchronization_objects(
                device,
                &[first, second],
                &[context],
                2,
            ),
            Ok(())
        );
        assert_eq!(
            subsystem
                .d3dkmt_wait_for_synchronization_objects(device, &[first, second], &[2, 2], 0,),
            Ok(())
        );
        assert_eq!(
            subsystem
                .d3dkmt_wait_for_synchronization_objects(device, &[first], &[], 0)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_wait_for_synchronization_objects(
                    device,
                    &[SyncObjectHandle(0xFFFF_FFFF)],
                    &[1],
                    0,
                )
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_wait_for_synchronization_objects(device, &[foreign], &[1], 0)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_wait_for_synchronization_objects(device, &[first], &[9], 1_000_000)
                .unwrap_err()
                .status(),
            STATUS_TIMEOUT
        );
        assert_eq!(
            subsystem
                .d3dkmt_wait_for_synchronization_objects(device, &[first], &[9], 0)
                .unwrap_err()
                .status(),
            STATUS_TIMEOUT
        );
        assert_eq!(
            subsystem.d3dkmt_destroy_synchronization_object(device, first),
            Ok(())
        );
        assert_eq!(
            subsystem
                .d3dkmt_destroy_synchronization_object(device, first)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_signal_synchronization_object(first, 3)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_destroy_synchronization_object(device, foreign)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_destroy_synchronization_object(DeviceHandle(0xFFFF_FFFF), second)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn adapter_names_modes_and_private_format_reject_unknown_targets() {
        let subsystem = subsystem();
        let snapshot = subsystem
            .d3dkmt_enum_adapters()
            .into_iter()
            .next()
            .expect("enumerated adapter");
        assert_eq!(
            subsystem
                .d3dkmt_open_adapter_from_display_name("")
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_adapter_from_device_name("   ")
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_adapter_from_display_name("\\\\.\\DISPLAY9")
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_adapter_from_device_name("metal#zz")
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_adapter_from_device_name("metal#ffffffffffffffff")
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
        assert_eq!(
            subsystem
                .d3dkmt_open_adapter_from_device_name("not a gpu")
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
        let display = subsystem
            .d3dkmt_open_adapter_from_display_name("\\\\.\\DISPLAY1")
            .expect("GDI display adapter");
        let by_name = subsystem
            .d3dkmt_open_adapter_from_device_name(&snapshot.name)
            .expect("device-name adapter");
        let by_registry = subsystem
            .d3dkmt_open_adapter_from_device_name(&format!("metal#{:x}", snapshot.registry_id))
            .expect("registry-id adapter");
        assert_eq!(
            subsystem
                .d3dkmt_query_adapter_info(display)
                .expect("display adapter info")
                .luid,
            snapshot.luid
        );
        assert_eq!(
            subsystem
                .d3dkmt_query_adapter_info(by_name)
                .expect("named adapter info")
                .luid,
            snapshot.luid
        );
        assert_eq!(
            subsystem
                .d3dkmt_query_adapter_info(by_registry)
                .expect("registry adapter info")
                .luid,
            snapshot.luid
        );
        let modes = subsystem
            .d3dkmt_display_modes(display)
            .expect("display modes");
        assert!(!modes.is_empty(), "backend reports real modes");
        let mut expected = BTreeSet::new();
        for output in subsystem.backend().outputs() {
            for mode in &output.modes {
                expected.insert(DisplayModeInfo {
                    width: mode.width,
                    height: mode.height,
                    refresh_numerator: mode.refresh_numerator,
                    refresh_denominator: mode.refresh_denominator,
                });
            }
        }
        assert_eq!(modes, expected.into_iter().collect::<Vec<_>>());
        assert_eq!(
            subsystem
                .d3dkmt_set_display_private_driver_format(display, 0, 7)
                .expect("set private format"),
            ()
        );
        assert_eq!(subsystem.display_private_driver_format(display, 0), Ok(7));
        assert_eq!(
            subsystem
                .d3dkmt_set_display_private_driver_format(display, u32::MAX, 7)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .display_private_driver_format(display, u32::MAX)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_display_modes(AdapterHandle(0xFFFF_FFFF))
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
        assert_eq!(subsystem.d3dkmt_close_adapter(display), Ok(()));
        assert_eq!(
            subsystem
                .d3dkmt_display_modes(display)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
        assert_eq!(
            subsystem
                .d3dkmt_set_display_private_driver_format(display, 0, 1)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
    }

    #[test]
    fn device_destroy_reaps_contexts_keyed_mutexes_and_shared_handles() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let survivor_device = create_device(&subsystem, adapter, false);
        let allocation = create_allocation(&subsystem, device, 16, SEGMENT_LOCAL, 1);
        let context = create_context(&subsystem, device, 1);
        let mutex = subsystem
            .d3dkmt_open_keyed_mutex(device, allocation, 0x22)
            .expect("keyed mutex");
        let survivor = subsystem
            .d3dkmt_open_resource(survivor_device, allocation)
            .expect("shared alias");
        assert_eq!(subsystem.d3dkmt_destroy_context_on(device, context), Ok(()));
        let reaped_context = create_context(&subsystem, device, 2);
        assert_eq!(subsystem.d3dkmt_destroy_device(device), Ok(()));
        assert_eq!(
            subsystem.context_info(reaped_context).unwrap_err().status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(mutex, 0x22, 0, 7)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem.allocation_info(allocation).unwrap_err().status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        assert_eq!(
            subsystem
                .allocation_info(survivor)
                .expect("shared alias survives")
                .size,
            16
        );
        assert_eq!(subsystem.d3dkmt_query_statistics().context_count, 0);
        assert_eq!(subsystem.d3dkmt_destroy_device(survivor_device), Ok(()));
    }

    #[test]
    fn typed_statistics_reject_unknown_unsupported_types_and_node_bounds() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        assert_eq!(
            subsystem
                .d3dkmt_query_statistics_for(adapter, 1, 0)
                .unwrap_err()
                .status(),
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(
            subsystem
                .d3dkmt_query_statistics_for(adapter, 99, 0)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_query_statistics_for(adapter, D3DKMT_QUERYSTATISTICS_NODE, 1)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            subsystem
                .d3dkmt_query_statistics_for(
                    AdapterHandle(0xFFFF_FFFF),
                    D3DKMT_QUERYSTATISTICS_ADAPTER,
                    0,
                )
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER
        );
        assert_eq!(
            subsystem
                .d3dkmt_query_node_statistics(adapter, 1)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
        let device = create_device(&subsystem, adapter, false);
        let allocation = create_allocation(&subsystem, device, 128, SEGMENT_LOCAL, 1);
        let context = create_context(&subsystem, device, 3);
        subsystem
            .d3dkmt_render(RenderRequest {
                device,
                context,
                allocations: vec![allocation],
                fill_value: 0,
                fence: None,
            })
            .expect("render for statistics");
        let adapter_stats = subsystem
            .d3dkmt_query_statistics_for(adapter, D3DKMT_QUERYSTATISTICS_ADAPTER, 0)
            .expect("adapter statistics");
        assert_eq!(adapter_stats.allocation_count, 1);
        assert_eq!(adapter_stats.allocated_bytes, 128);
        assert_eq!(adapter_stats.context_count, 1);
        assert_eq!(adapter_stats.render_count, 1);
        assert_eq!(adapter_stats.render_bytes, 128);
        let adapter2 = subsystem
            .d3dkmt_query_statistics_for(adapter, D3DKMT_QUERYSTATISTICS_ADAPTER2, 0)
            .expect("adapter2 statistics");
        assert_eq!(adapter2, adapter_stats);
        let node = subsystem
            .d3dkmt_query_node_statistics(adapter, RENDER_NODE_ORDINAL)
            .expect("node statistics");
        assert_eq!(node.node_ordinal, RENDER_NODE_ORDINAL);
        assert_eq!(node.context_count, 1);
        assert_eq!(node.render_count, 1);
        assert_eq!(node.render_bytes, 128);
        assert_eq!(node.allocation_count, 1);
        assert_eq!(node.allocated_bytes, 128);
        assert_eq!(node.last_effective_priority, 3);
        assert_eq!(
            subsystem
                .d3dkmt_query_node_statistics(adapter, RENDER_NODE_COUNT)
                .unwrap_err()
                .status(),
            STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn wddm_adapter_name_edges_reject_unknown_and_non_display_names() {
        let subsystem = subsystem();
        let snapshot = subsystem
            .d3dkmt_enum_adapters()
            .into_iter()
            .next()
            .expect("enumerated adapter");
        let by_display_name = subsystem
            .d3dkmt_open_adapter_from_display_name(&snapshot.name)
            .expect("display-name lookup of the reported adapter name");
        assert_eq!(
            subsystem
                .d3dkmt_query_adapter_info(by_display_name)
                .expect("opened adapter info")
                .luid,
            snapshot.luid
        );
        let unknown = subsystem
            .d3dkmt_open_adapter_from_display_name("not a display target")
            .unwrap_err();
        assert_eq!(unknown.status(), STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER);
        assert_eq!(unknown.detail(), "no adapter answers to this display name");
        let delegated = subsystem
            .d3dkmt_open_adapter_from_device_name("DISPLAY0")
            .unwrap_err();
        assert_eq!(delegated.status(), STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER);
        assert_eq!(
            delegated.detail(),
            "no adapter answers to this display name"
        );
    }

    #[test]
    fn wddm_sync_array_wait_timeout_and_infinite_race_are_exact() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let sync = create_sync(&subsystem, device, 0);
        let waiter = {
            let subsystem = Arc::clone(&subsystem);
            thread::spawn(move || {
                subsystem.d3dkmt_wait_for_synchronization_objects(device, &[sync], &[1], u64::MAX)
            })
        };
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            subsystem.d3dkmt_signal_synchronization_object(sync, 1),
            Ok(())
        );
        assert_eq!(waiter.join().expect("array waiter thread"), Ok(()));
        let error = subsystem
            .d3dkmt_wait_for_synchronization_objects(device, &[sync], &[2], 20_000_000)
            .unwrap_err();
        assert_eq!(error.status(), STATUS_TIMEOUT);
        assert_eq!(error.detail(), "fence array value not reached");
        let statistics = subsystem.d3dkmt_query_statistics();
        assert_eq!(statistics.wait_count, 2);
        assert_eq!(statistics.timeout_count, 1);
    }

    #[test]
    fn wddm_keyed_mutex_shared_reopen_and_destroy_reap_invalidates_handles() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let other_device = create_device(&subsystem, adapter, false);
        let allocation = create_allocation(&subsystem, device, 64, SEGMENT_LOCAL, 1);
        assert_eq!(
            subsystem
                .d3dkmt_open_keyed_mutex(other_device, allocation, 0x1234)
                .unwrap_err()
                .status(),
            STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE
        );
        let alias = subsystem
            .d3dkmt_open_resource(other_device, allocation)
            .expect("alias allocation handle");
        let mutex = subsystem
            .d3dkmt_open_keyed_mutex(device, allocation, 0x1234)
            .expect("open keyed mutex");
        assert_eq!(
            subsystem
                .d3dkmt_open_keyed_mutex(other_device, alias, 0x2222)
                .unwrap_err()
                .status(),
            STATUS_ACCESS_DENIED
        );
        let shared = subsystem
            .d3dkmt_open_keyed_mutex(other_device, alias, 0x1234)
            .expect("reopen shared keyed mutex on the second device");
        assert_ne!(mutex, shared);
        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(mutex, 0x1234, 0, 7)
                .expect("acquire through the first handle"),
            ()
        );
        assert_eq!(
            subsystem
                .d3dkmt_release_keyed_mutex(shared, 0x1234, 7)
                .expect("release through the shared handle"),
            ()
        );
        assert_eq!(subsystem.d3dkmt_destroy_allocation(alias), Ok(()));
        assert_eq!(subsystem.d3dkmt_destroy_allocation(allocation), Ok(()));
        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(mutex, 0x1234, 0, 7)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            subsystem
                .keyed_mutex_wake_count(shared)
                .unwrap_err()
                .status(),
            STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn wddm_keyed_mutex_infinite_wait_race_acquires_after_release() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let allocation = create_allocation(&subsystem, device, 64, SEGMENT_LOCAL, 1);
        let mutex = subsystem
            .d3dkmt_open_keyed_mutex(device, allocation, 0x4321)
            .expect("open keyed mutex");
        assert_eq!(
            subsystem
                .d3dkmt_acquire_keyed_mutex(mutex, 0x4321, 0, 7)
                .expect("owner acquire"),
            ()
        );
        let waiter = {
            let subsystem = Arc::clone(&subsystem);
            thread::spawn(move || subsystem.d3dkmt_acquire_keyed_mutex(mutex, 0x4321, u64::MAX, 8))
        };
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            subsystem.d3dkmt_release_keyed_mutex(mutex, 0x4321, 7),
            Ok(())
        );
        assert_eq!(waiter.join().expect("keyed mutex waiter"), Ok(()));
        assert_eq!(
            subsystem.d3dkmt_release_keyed_mutex(mutex, 0x4321, 8),
            Ok(())
        );
        let statistics = subsystem.d3dkmt_query_statistics();
        assert_eq!(statistics.keyed_mutex_acquire_count, 2);
        assert_eq!(statistics.keyed_mutex_timeout_count, 0);
    }

    #[test]
    fn wddm_concurrent_render_fence_overtake_race_is_rejected_exactly() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let allocation = create_allocation(&subsystem, device, MAX_RENDER_BYTES, SEGMENT_LOCAL, 1);
        let context = create_context(&subsystem, device, 1);
        let fence = create_sync(&subsystem, device, 0);
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let subsystem = Arc::clone(&subsystem);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                subsystem.d3dkmt_render(RenderRequest {
                    device,
                    context,
                    allocations: vec![allocation],
                    fill_value: 0xA5,
                    fence: Some((fence, 7)),
                })
            }));
        }
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("render worker"))
            .collect::<Vec<_>>();
        let successes = results.iter().filter(|result| result.is_ok()).count();
        let errors = results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .collect::<Vec<_>>();
        assert_eq!(successes, 1);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].status(), STATUS_INVALID_PARAMETER);
        assert_eq!(
            errors[0].detail(),
            "render fence value was overtaken during submission"
        );
    }

    #[test]
    fn wddm_statistics_node_error_and_valid_node_arm_are_exact() {
        let subsystem = subsystem();
        let adapter = open_adapter(&subsystem);
        let device = create_device(&subsystem, adapter, false);
        let allocation = create_allocation(&subsystem, device, 256, SEGMENT_LOCAL, 1);
        let context = create_context(&subsystem, device, 5);
        subsystem
            .d3dkmt_render(RenderRequest {
                device,
                context,
                allocations: vec![allocation],
                fill_value: 0x33,
                fence: None,
            })
            .expect("render for node statistics");
        let error = subsystem
            .d3dkmt_query_statistics_for(adapter, D3DKMT_QUERYSTATISTICS_NODE, RENDER_NODE_COUNT)
            .unwrap_err();
        assert_eq!(error.status(), STATUS_INVALID_PARAMETER);
        assert_eq!(error.detail(), "statistics node ordinal does not exist");
        let node = subsystem
            .d3dkmt_query_statistics_for(adapter, D3DKMT_QUERYSTATISTICS_NODE, RENDER_NODE_ORDINAL)
            .expect("valid node statistics");
        assert_eq!(node.allocation_count, 1);
        assert_eq!(node.allocated_bytes, 256);
        assert_eq!(node.render_count, 1);
        assert_eq!(node.render_bytes, 256);
        assert_eq!(node.context_count, 1);
    }

    #[test]
    fn wddm_render_submit_failure_returns_gpu_exception_status() {
        assert_eq!(
            completion_status(metal::MTLCommandBufferStatus::Error),
            Err(WddmError::new(
                STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE,
                "Metal blit command buffer did not complete",
            ))
        );
    }
}
