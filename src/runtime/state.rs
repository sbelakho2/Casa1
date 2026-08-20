//! Runtime state: PeHostRuntime definition, its fields, the guest-object/device
//! tracking structs, and the per-thread/TLS/TEB-adjacent state.
use super::*;
#[derive(Debug, Clone, Default)]
pub(crate) struct CrtGlobals {
    pub(crate) argc_ptr: u64,
    pub(crate) argv_ptr_ptr: u64,
    pub(crate) environ_ptr_ptr: u64,
    pub(crate) commode_ptr: u64,
    pub(crate) fmode_ptr: u64,
    pub(crate) iob_streams: [u64; 3],
}

/// Host-side state behind a guest `FILE*` (the FILE block is a zeroed 0x80-byte
/// guest allocation that mirrors the UCRT `_iobuf` footprint; the fd lives at
/// offset 0x10 so guests reading `_file` directly observe it).
#[derive(Debug, Clone)]
#[allow(dead_code)] // CRT file state flag retained for future CRT paths
pub(crate) struct CrtFileState {
    /// Win32 handle backing the stream (for files opened via the CRT).
    pub(crate) handle: u32,
    /// Normalised guest path ("" for `_fdopen`-created streams).
    pub(crate) path: String,
    pub(crate) readable: bool,
    pub(crate) writable: bool,
    /// `a`/`a+` mode: writes are always positioned at EOF.
    pub(crate) append: bool,
    pub(crate) update: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestObjectKind {
    XAudio2Engine,
    XAudio2MasteringVoice,
    XAudio2SourceVoice,
    DxgiFactory,
    DxgiAdapter,
    D3d11Device,
    D3d11DeviceContext,
    D3d11DeferredContext,
    DxgiSwapChain,
    D3d12Device,
    D3d12CommandQueue,
    D3d12CommandAllocator,
    D3d12DescriptorHeap,
    D3d12GraphicsCommandList,
    D3d12Fence,
    D3d12Resource,
    D3d11Buffer,
    D3d11Texture2D,
    D3d11View,
    D3d11InputLayout,
    D3d11Shader,
    D3d11BlendState,
    D3d11RasterizerState,
    D3d11DepthStencilState,
    D3d11SamplerState,
    D3d11Query,
    ShellLinkInterface,
    DirectInput8,
    DirectInput8Device,
    /// A COM-created DirectSound8 object (IDirectSound8).
    DirectSound8,
    /// A COM-created FileOpenDialog/FileSaveDialog object.
    FileDialog,
    SteamVRHmd,
    SteamVRCompositor,
    SteamVRChaperone,
    SteamVRController,
    SteamVRInput,
    SteamVRRenderModels,
    /// A COM class factory (IClassFactory).
    ComClassFactory,
    /// A COM dispatch object (IDispatch).
    #[allow(dead_code)] // guest object kind tags (state-model completeness)
    ComDispatch,
    /// A XAPO audio effect object (IXAPO).
    XapoEffect,
    // ── WMI COM Objects ───────────────────────────────────────────────────────
    /// IWbemLocator COM object.
    WbemLocator,
    /// IWbemServices COM object.
    WbemServices,
    /// IWbemClassObject COM object.
    WbemClassObject,
    /// IEnumWbemClassObject COM object.
    EnumWbemObjects,
    // ── WebView2 COM Objects ─────────────────────────────────────────────────
    /// ICoreWebView2Environment COM object.
    WebView2Environment,
    /// ICoreWebView2Controller COM object.
    WebView2Controller,
    /// ICoreWebView2 COM object.
    WebView2WebView,
    /// ICoreWebView2Settings COM object.
    WebView2Settings,
    /// ICoreWebView2WebResourceResponse COM object.
    WebView2WebResourceResponse,
    // ── D3D9 Objects (Phase 1.5) ─────────────────────────────────────────────
    /// IDirect3D9 factory COM object.
    D3d9Factory,
    /// IDirect3DDevice9 COM object.
    D3d9Device,
    /// IDirect3DVertexBuffer9 COM object.
    D3d9VertexBuffer,
    /// IDirect3DIndexBuffer9 COM object.
    D3d9IndexBuffer,
    /// IDirect3DTexture9 COM object.
    D3d9Texture,
    /// IDirect3DQuery9 COM object.
    #[allow(dead_code)] // guest object kind tags (state-model completeness)
    D3d9Query,
    /// IDirect3DSwapChain9 COM object.
    #[allow(dead_code)] // guest object kind tags (state-model completeness)
    D3d9SwapChain,
    // ── Phase L: COM/Shell Completion ───────────────────────────────────
    /// IShellFolder COM object (created via CLSID_ShellFolder).
    ShellFolder,
    /// IShellItem COM object (created via SHCreateItemFromParsingName etc.)
    ShellItem,
    /// IContextMenu COM object.
    ContextMenu,
    /// IPropertyStore COM object.
    PropertyStore,
    /// IXMLDOMDocument COM object.
    XmlDomDocument,
    /// IMoniker COM object (URL moniker).
    UrlMoniker,
    /// IEnumIDList COM object (enumerator created by IShellFolder::EnumObjects).
    EnumIdList,
    // ── D3D9 Surface & Shader Objects ──────────────────────────────────────
    /// IDirect3DSurface9 COM object.
    D3d9Surface,
    /// IDirect3DVertexDeclaration9 COM object.
    D3d9VertexDeclaration,
    /// IDirect3DVertexShader9 COM object.
    D3d9VertexShader,
    /// IDirect3DPixelShader9 COM object.
    D3d9PixelShader,
    // ── D2D1 Objects (Phase 3.6) ─────────────────────────────────────────
    /// ID2D1Brush COM object.
    D2d1Brush,
    /// ID2D1StrokeStyle COM object.
    D2d1StrokeStyle,
    /// ID2D1DrawingStateBlock COM object.
    D2d1DrawingStateBlock,
    /// ID2D1Bitmap COM object.
    D2d1Bitmap,
    /// ID2D1RenderTarget COM object.
    D2d1RenderTarget,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestObjectMeta {
    pub(crate) kind: GuestObjectKind,
    pub(crate) refcount: u32,
}

/// State for a live IEnumIDList enumerator created by IShellFolder::EnumObjects.
///
/// Tracks the enumerated PIDL list and current position so that
/// `Next` / `Skip` / `Reset` operate correctly.
#[derive(Debug, Clone)]
pub(crate) struct EnumIdListState {
    /// PIDLs for each item (guest pointers to UTF-16 path strings).
    pub(crate) pidls: Vec<u64>,
    /// Current position in the enumeration (index into `pidls`).
    pub(crate) current: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellLinkInterfaceKind {
    ShellLinkW,
    PersistFile,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestShellLinkInterface {
    pub(crate) state_id: u64,
    #[allow(dead_code)]
    pub(crate) kind: ShellLinkInterfaceKind,
}

#[derive(Debug, Clone)]
pub(crate) struct GuestShellLinkState {
    pub(crate) shell_link_object: u64,
    pub(crate) persist_file_object: Option<u64>,
    pub(crate) refcount: u32,
    pub(crate) path: String,
    pub(crate) arguments: String,
    pub(crate) description: String,
    pub(crate) working_directory: String,
    pub(crate) hotkey: u16,
    pub(crate) icon_location: String,
    pub(crate) icon_index: i32,
    pub(crate) show_cmd: i32,
    pub(crate) current_file: Option<String>,
    pub(crate) dirty: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct GuestXAudio2Engine {
    pub(crate) mastering_voice: Option<u64>,
    pub(crate) source_voices: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestXAudio2Voice {
    pub(crate) engine_object: u64,
    pub(crate) voice_id: VoiceId,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestDxgiFactory;

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestDxgiAdapter {
    pub(crate) factory_object: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d12Device;

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d12CommandQueue {
    pub(crate) device_object: u64,
    pub(crate) queue_id: D3d12CommandQueueId,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d12CommandAllocator {
    pub(crate) device_object: u64,
    pub(crate) allocator_id: D3d12CommandAllocatorId,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d12DescriptorHeap {
    pub(crate) device_object: u64,
    pub(crate) heap_id: D3d12DescriptorHeapId,
    pub(crate) ty: DescriptorHeapType,
    pub(crate) cpu_handle_start: u64,
    pub(crate) descriptor_count: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct GuestD3d12CommandList {
    pub(crate) device_object: u64,
    pub(crate) allocator_object: u64,
    pub(crate) command_list_id: Option<D3d12CommandListId>,
    pub(crate) closed_stream: Option<ImmutableCommandStream>,
    pub(crate) render_pass_active: bool,
    /// True if this command list is a D3D12 bundle
    /// (D3D12_COMMAND_LIST_TYPE_BUNDLE). Bundles are pre-recorded sequences
    /// that can be replayed via ExecuteBundle on a parent direct command list.
    pub(crate) is_bundle: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d12Fence {
    pub(crate) device_object: u64,
    pub(crate) fence_id: D3d12FenceId,
}

#[derive(Debug, Clone)]
pub(crate) struct GuestD3d12SwapChain {
    pub(crate) device_object: u64,
    pub(crate) swapchain_id: D3d12SwapchainId,
    pub(crate) backbuffer_objects: BTreeMap<u32, u64>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d12Resource {
    pub(crate) device_object: u64,
    pub(crate) resource_id: D3d12ResourceId,
    pub(crate) format: DxgiFormat,
    pub(crate) swapchain_backbuffer: bool,
}

pub(crate) struct GuestD3d11Device {
    pub(crate) device: D3d11Device,
    pub(crate) context_object: u64,
    pub(crate) swapchain_object: Option<u64>,
    pub(crate) backbuffer_objects: BTreeMap<u32, u64>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d11Context {
    pub(crate) device_object: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct GuestD3d11DeferredContext {
    pub(crate) device_object: u64,
    pub(crate) deferred_context: crate::d3d11::DeferredContext,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestDxgiSwapChain {
    pub(crate) device_object: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d11Texture2D {
    pub(crate) device_object: u64,
    pub(crate) resource_id: D3d11ResourceId,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d11Buffer {
    pub(crate) device_object: u64,
    pub(crate) resource_id: D3d11ResourceId,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d11View {
    pub(crate) device_object: u64,
    pub(crate) view_id: D3d11ViewId,
    pub(crate) kind: ViewKind,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d11InputLayout {
    pub(crate) device_object: u64,
    pub(crate) layout_id: InputLayoutId,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d11Shader {
    pub(crate) device_object: u64,
    pub(crate) shader_id: u64,
    pub(crate) stage: D3d11ShaderStage,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d11BlendState {
    pub(crate) device_object: u64,
    pub(crate) state_id: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d11RasterizerState {
    pub(crate) device_object: u64,
    pub(crate) state_id: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d11DepthStencilState {
    pub(crate) device_object: u64,
    pub(crate) state_id: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestD3d11SamplerState {
    pub(crate) device_object: u64,
    pub(crate) state_id: u64,
}

/// Tracks state for a real (on-disk) DLL loaded via `load_real_dll`.
#[allow(dead_code)] // real-DLL state retained for future native-DLL loading
pub(crate) struct RealDllState {
    /// Host path to the on-disk DLL file.
    pub(crate) path: PathBuf,
    /// Normalised DLL name (e.g. "mydll.dll").
    pub(crate) dll_name: String,
    /// Map of export name → thunk address in guest space.
    pub(crate) exports: HashMap<String, u64>,
    /// PE entry point RVA (non-zero if the DLL has a DllMain).
    pub(crate) entry_point: Option<u32>,
    /// Image base from the PE optional header (for relocation).
    pub(crate) image_base: u64,
    /// Reference count (incremented on each LoadLibrary, decremented on FreeLibrary).
    pub(crate) refcount: u32,
    /// Guest module handle (the address allocated in guest space).
    pub(crate) handle: u64,
    /// Optional native macOS dylib loaded via `libloading` (if a native shim exists).
    pub(crate) native_library: Option<libloading::Library>,
}

/// Tracks metadata for a loaded DLL (both synthetic and real PE).
/// Used for HMODULE-based lookup and DllMain notification dispatch.
#[derive(Debug, Clone)]
#[allow(dead_code)] // module-table fields retained for future GetModule* APIs
pub(crate) struct DllInfo {
    /// Module handle (HMODULE) — the base address in guest space.
    pub handle: u64,
    /// Size of the module image in bytes.
    pub image_size: u64,
    /// PE entry point RVA (0 if synthetic/no entry point).
    pub entry_point_rva: u32,
    /// Reference/load count (incremented on LoadLibrary, decremented on FreeLibrary).
    pub load_count: u32,
    /// Normalised module name (e.g. "kernel32.dll").
    pub module_name: String,
    /// Host path to the on-disk DLL (empty for synthetic modules).
    pub host_path: String,
    /// TLS callback addresses as RVAs (relative to original image base).
    /// Empty vec for modules without TLS callbacks.
    pub tls_callbacks: Vec<u64>,
}

#[allow(dead_code)] // runtime state retained for future import paths
pub(crate) struct PeHostRuntime {
    pub(crate) audio: AudioSubsystem,
    pub(crate) win32: Win32Subsystem,
    pub(crate) user32: User32Subsystem,
    /// Generic runtime-event observers (workloads like the Steam milestone
    /// observer).  Empty by default — the runtime works perfectly with no
    /// observer attached.  The same list is shared (via clone) with the
    /// win32/user32 subsystems and registered as the process-wide current
    /// list so the global CEF bridge / real-audio backend can publish.
    pub(crate) observers: crate::runtime_events::ObserverList,
    pub(crate) guest_arch: GuestArch,
    pub(crate) live_session: Option<LivePeSession>,
    pub(crate) live_keyboard_device: Option<String>,
    pub(crate) live_mouse_device: Option<String>,
    pub(crate) pending_keyboard_replay: Vec<KeyboardReplayEvent>,
    pub(crate) keyboard_replay_device: Option<String>,
    pub(crate) keyboard_replay_injected: bool,
    pub(crate) host_thunks: U64Map<HostThunk>,
    /// Maps guest thunk addresses → fast-thunk indices for JIT direct calls.
    pub(crate) thunk_to_fast_index: U64Map<usize>,
    pub(crate) guest_objects: BTreeMap<u64, GuestObjectMeta>,
    pub(crate) shell_link_interfaces: BTreeMap<u64, GuestShellLinkInterface>,
    pub(crate) shell_link_states: BTreeMap<u64, GuestShellLinkState>,
    pub(crate) xaudio_engines: BTreeMap<u64, GuestXAudio2Engine>,
    pub(crate) xaudio_mastering_voices: BTreeMap<u64, GuestXAudio2Voice>,
    pub(crate) xaudio_source_voices: BTreeMap<u64, GuestXAudio2Voice>,
    /// DirectInput8 instance objects created via DirectInput8Create
    pub(crate) directinput8_objects: BTreeMap<u64, ()>,
    /// DirectInput8 device objects — device_object -> guid
    pub(crate) directinput8_device_objects: BTreeMap<u64, String>,
    /// Per-device force-feedback state for DirectInputDevice8.
    pub(crate) directinput8_ff_state: BTreeMap<u64, crate::real_win32::DirectInputDevice8>,
    pub(crate) d3d12_runtime: D3d12Runtime,
    pub(crate) d3d12_guest_root_signature: Option<D3d12RootSignatureId>,
    pub(crate) d3d12_guest_pipeline_state: Option<D3d12PipelineStateId>,
    pub(crate) dxgi_factories: BTreeMap<u64, GuestDxgiFactory>,
    pub(crate) dxgi_adapters: BTreeMap<u64, GuestDxgiAdapter>,
    pub(crate) d3d12_devices: BTreeMap<u64, GuestD3d12Device>,
    pub(crate) d3d12_command_queues: BTreeMap<u64, GuestD3d12CommandQueue>,
    pub(crate) d3d12_command_allocators: BTreeMap<u64, GuestD3d12CommandAllocator>,
    pub(crate) d3d12_descriptor_heaps: BTreeMap<u64, GuestD3d12DescriptorHeap>,
    pub(crate) d3d12_command_lists: BTreeMap<u64, GuestD3d12CommandList>,
    pub(crate) d3d12_fences: BTreeMap<u64, GuestD3d12Fence>,
    pub(crate) d3d12_swapchains: BTreeMap<u64, GuestD3d12SwapChain>,
    pub(crate) d3d12_resources: BTreeMap<u64, GuestD3d12Resource>,
    pub(crate) d3d11_devices: BTreeMap<u64, GuestD3d11Device>,
    pub(crate) d3d11_contexts: BTreeMap<u64, GuestD3d11Context>,
    pub(crate) d3d11_deferred_contexts: BTreeMap<u64, GuestD3d11DeferredContext>,
    pub(crate) d3d11_swapchains: BTreeMap<u64, GuestDxgiSwapChain>,
    pub(crate) d3d11_buffers: BTreeMap<u64, GuestD3d11Buffer>,
    pub(crate) d3d11_textures: BTreeMap<u64, GuestD3d11Texture2D>,
    pub(crate) d3d11_views: BTreeMap<u64, GuestD3d11View>,
    pub(crate) d3d11_input_layouts: BTreeMap<u64, GuestD3d11InputLayout>,
    pub(crate) d3d11_shaders: BTreeMap<u64, GuestD3d11Shader>,
    pub(crate) d3d11_blend_states: BTreeMap<u64, GuestD3d11BlendState>,
    pub(crate) d3d11_rasterizer_states: BTreeMap<u64, GuestD3d11RasterizerState>,
    pub(crate) d3d11_depth_stencil_states: BTreeMap<u64, GuestD3d11DepthStencilState>,
    pub(crate) d3d11_sampler_states: BTreeMap<u64, GuestD3d11SamplerState>,
    /// Tracks D3D11 Map operations: resource_object → (guest_ptr, data_size)
    /// Used by Unmap to find the guest data pointer and read back CPU modifications.
    pub(crate) d3d11_mapped_resources: U64Map<(u64, usize)>,
    pub(crate) instruction_cache: U64Map<CachedInstructionEntry>,
    pub(crate) instruction_cache_lru: VecDeque<(u64, u64)>,
    pub(crate) instruction_cache_generation: u64,
    pub(crate) basic_block_cache: U64Map<CachedBlockEntry>,
    pub(crate) basic_block_cache_lru: VecDeque<(u64, u64)>,
    pub(crate) basic_block_cache_generation: u64,
    pub(crate) allowed_trace_categories: Option<BTreeSet<String>>,
    pub(crate) trace_events: Vec<TraceEvent>,
    pub(crate) gfx_frames: Vec<GfxFrame>,
    pub(crate) next_trace_index: u64,
    pub(crate) next_thunk_address: u64,
    pub(crate) next_data_address: u64,
    pub(crate) next_device_context_handle: u64,
    pub(crate) next_gdi_object_handle: u64,
    pub(crate) next_descriptor_handle: u64,
    pub(crate) next_heap_address: u64,
    /// Tracks which x86 heap region is currently active (0 = primary at
    /// X86_CRT_HEAP_BASE, 1 = secondary at X86_CRT_HEAP_BASE_2, etc.).
    /// Incremented when the bump pointer exceeds the 32-bit address space.
    pub(crate) x86_heap_region: u32,
    pub(crate) heap_allocations: BTreeMap<u64, usize>,
    /// Test-only failure injection: when set, the next heap allocation
    /// (malloc/calloc/realloc and the CRT FILE-block allocation) fails with
    /// ENOMEM and NULL instead of succeeding.  Cleared on consumption.
    pub(crate) crt_alloc_fail_next: bool,
    pub(crate) critical_sections: BTreeMap<u64, usize>,
    pub(crate) condition_variables: BTreeMap<u64, GuestConditionVariable>,
    pub(crate) srw_locks: BTreeMap<u64, Arc<GuestSRWLock>>,
    pub(crate) apc_queues: BTreeMap<u64, GuestApcQueue>,
    pub(crate) timer_queue: GuestTimerQueue,
    /// Shared work queue for timer expirations (filled by background threads,
    /// drained by `drain_timer_work_queue`).
    pub(crate) timer_work_sink: Arc<Mutex<VecDeque<(u64, u64)>>>,
    /// Next handle value for `CreateTimerQueueTimer`.
    pub(crate) next_timer_queue_handle: u64,
    /// Active wait registrations (handle → (object_handle, callback, context)).
    pub(crate) wait_registrations: BTreeMap<u64, (u32, u64, u64)>,
    /// Next handle value for `RegisterWaitForSingleObject`.
    pub(crate) next_wait_handle: u64,
    // ── BCrypt / CNG Crypto State ────────────────────────────────────────────
    pub(crate) bcrypt_ctx: BCryptContext,
    /// Maps provider handle → algorithm ID string (e.g. "SHA256", "AES")
    pub(crate) bcrypt_providers: BTreeMap<u64, String>,
    /// Maps hash handle → BCryptHash state
    pub(crate) bcrypt_hashes: BTreeMap<u64, crate::real_win32::BCryptHash>,
    /// Maps key handle → BCryptKey state
    pub(crate) bcrypt_keys: BTreeMap<u64, crate::real_win32::BCryptKey>,
    /// Maps secret handle → BCryptSecret (result of secret agreement)
    pub(crate) bcrypt_secrets: BTreeMap<u64, crate::real_win32::BCryptSecret>,
    pub(crate) next_bcrypt_provider_id: u64,
    pub(crate) next_bcrypt_hash_id: u64,
    pub(crate) next_bcrypt_key_id: u64,
    pub(crate) next_bcrypt_secret_id: u64,
    /// Manages certificate stores for crypt32.dll operations.
    pub(crate) cert_store_manager: crate::security::CertificateStoreManager,
    /// Maps store handle -> store name for synthetic cert stores opened via CertOpenStore.
    pub(crate) cert_store_names: BTreeMap<u64, String>,
    /// Maps cert context handle → raw DER bytes for certificates created via CertCreateCertificateContext.
    pub(crate) cert_contexts: BTreeMap<u64, Vec<u8>>,
    /// Tracks certificate enumeration position per store (store_handle → next_index).
    pub(crate) cert_enum_cursors: BTreeMap<u64, usize>,
    /// Phase L3: Maps window handle (hwnd) → IDropTarget pointer for drag-and-drop.
    pub(crate) drop_targets: BTreeMap<u64, u64>,
    /// Next available drop target tracking ID.
    pub(crate) next_drop_target_id: u64,
    pub(crate) signal_handlers: BTreeMap<i32, u64>,
    pub(crate) tls_slots: BTreeMap<u32, u64>,
    pub(crate) fls_slots: BTreeMap<u32, u64>,
    /// DllMain calls queued during LoadLibrary that must be executed after
    /// the current host thunk returns to the main execution loop.
    /// Each entry is (image_base, entry_point_rva, reason).
    pub(crate) pending_dll_main_calls: VecDeque<(u64, u32, u32)>,
    /// FLS callbacks collected during fiber deletion; the runtime should
    /// invoke these in guest context after the current thunk returns.
    pub(crate) pending_fiber_fls_callbacks: Vec<u64>,
    pub(crate) pending_guest_threads: VecDeque<PendingGuestThread>,
    pub(crate) active_pumped_guest_thread: Option<u32>,
    pub(crate) yield_pumped_guest_thread: bool,
    /// Wait descriptor attached by a pumped thread's blocking-wait thunk;
    /// the pump moves it onto the requeued thread record.
    pub(crate) pump_yield_with_wait: Option<GuestWait>,
    /// True while the MAIN loop's thread is parked in the scheduler wait
    /// queue; the main loop then runs pump-driven until the run ends.
    pub(crate) main_thread_parked: bool,
    /// Wait descriptor handed off by a wait thunk; the dispatch epilogue
    /// (after stack fixup + return-address restore) parks the thread with it.
    pub(crate) parked_wait: Option<GuestWait>,
    pub(crate) yield_pumped_guest_thread_wake_tick: Option<u64>,
    /// Set by `ExitThread`/`_endthreadex`/`_endthread`/`TerminateThread` while
    /// a pumped thread is active: the pump consumes it and ends the thread
    /// immediately instead of resuming guest code.
    pub(crate) pumped_thread_exit_requested: Option<u32>,
    /// Whether the pump fires DLL_THREAD_DETACH for an explicit exit
    /// (`ExitThread`/`_endthreadex` fire it; `TerminateThread` does not).
    pub(crate) pumped_thread_exit_with_detach: bool,
    /// Process-exit request recorded by `ExitProcess`/`TerminateProcess`(self)/
    /// `exit`/`_exit`/`abort` before they return.  When a pumped thread
    /// requests process exit, the pump abandons all pending threads and
    /// propagates the code to the main loop (which breaks on `Some(code)`).
    pub(crate) process_exit_requested: Option<u32>,
    /// Exit code recorded when an explicit thread-exit API (`ExitThread`/
    /// `_endthreadex`/`_endthread`/`TerminateThread` on self) runs on the
    /// MAIN thread (no pumped thread active).  Windows only ends the process
    /// when its LAST thread exits, so this ends the main thread's execution
    /// while the run keeps pumping pending guest threads; the run ends with
    /// this code once no pending threads remain (or a process-exit API runs).
    pub(crate) main_thread_exit_code: Option<u32>,
    pub(crate) tls_vector_ptr: u64,
    pub(crate) init_once_pending: BTreeSet<u64>,
    pub(crate) init_once_completed: BTreeMap<u64, u64>,
    pub(crate) atexit_handlers: Vec<u64>,
    pub(crate) next_gdi_handle: u64,
    pub(crate) module_handles: BTreeMap<String, u64>,
    pub(crate) module_names_by_handle: BTreeMap<u64, String>,
    pub(crate) module_paths_by_handle: BTreeMap<u64, String>,
    pub(crate) synthetic_module_handles: BTreeSet<u64>,
    pub(crate) materialized_synthetic_modules: BTreeSet<u64>,
    /// Real (on-disk) DLLs that have been loaded via `load_real_dll`.
    /// Keyed by normalised DLL name (lowercase, e.g. "mydll.dll").
    pub(crate) loaded_real_dlls: HashMap<String, RealDllState>,
    /// Cache for forwarded export resolutions.
    /// Key is the forwarder string (e.g. "KERNEL32.CreateFileW"),
    /// value is the resolved address or None if unresolvable.
    pub(crate) forwarder_export_cache: BTreeMap<String, Option<u64>>,
    /// HMODULE → DllInfo tracking table for all loaded DLLs.
    /// Populated for synthetic modules (via get_or_create_module_handle),
    /// real PE DLLs (via load_real_dll), and the main module.
    pub(crate) dll_info_table: HashMap<u64, DllInfo>,
    /// Registered initialization callbacks for synthetic/managed DLLs.
    /// Called with (module_handle, DLL_PROCESS_ATTACH) when a synthetic
    /// module is first created.
    pub(crate) synthetic_dll_init_callbacks: Vec<Box<dyn FnMut(u64, u32)>>,
    pub(crate) network: NetworkStack,
    /// WinHTTP/WinINet stack for HTTP/TLS operations
    pub(crate) winhttp: WinHttpStack,
    pub(crate) device_contexts: BTreeMap<u64, Option<u32>>,
    pub(crate) dialog_procs: BTreeMap<u32, u64>,
    pub(crate) window_surfaces: BTreeMap<u32, WindowSurface>,
    pub(crate) dc_selected_objects: BTreeMap<u64, u64>,
    /// HBITMAP → backing pixel buffer (for DIB sections / compatible bitmaps).
    /// Populated by `CreateDIBSection` / `CreateCompatibleBitmap`, read by
    /// `BitBlt` / `StretchBlt` when the source is a memory DC.
    pub(crate) gdi_bitmaps: BTreeMap<u64, MemoryBitmap>,
    pub(crate) dc_background_modes: BTreeMap<u64, i32>,
    pub(crate) dc_text_colors: BTreeMap<u64, u32>,
    pub(crate) dc_bk_colors: BTreeMap<u64, u32>,
    pub(crate) gdi_objects: BTreeMap<u64, String>,
    pub(crate) gdi_brushes: BTreeMap<u64, u32>,
    pub(crate) gdi_pens: BTreeMap<u64, u32>,
    pub(crate) gdi_fonts: BTreeMap<u64, GdiFont>,
    // --- Menu subsystem (Phase I2) ---
    pub(crate) menus: BTreeMap<u32, Menu>,
    pub(crate) next_menu_handle: u32,
    pub(crate) window_menus: BTreeMap<u32, u32>,
    pub(crate) progress_bar_states: BTreeMap<u32, ProgressBarState>,
    /// Scrollbar state per window per bar type (0=horizontal, 1=vertical)
    pub(crate) scroll_info: BTreeMap<(u32, u8), ScrollBarInfo>,
    /// Common control state per window handle
    pub(crate) common_control_state: BTreeMap<u32, CommonControlState>,
    /// ImageList handles → metadata
    pub(crate) image_lists: BTreeMap<u32, ImageListInfo>,
    /// Next ImageList handle
    pub(crate) next_image_list_handle: u32,
    /// Whether comctl32 has been initialized
    pub(crate) common_controls_initialized: bool,
    /// Bitmask of ICC_* flags from InitCommonControlsEx
    pub(crate) common_controls_flags: u32,
    /// Animation settings (from SystemParametersInfoW SPI_GETANIMATION/SETANIMATION)
    pub(crate) animation_settings: u32,
    pub(crate) error_mode: u32,
    pub(crate) last_error: u32,
    pub(crate) invalid_parameter_handler: u64,
    // ── Patch 6b: CRT errno / doserrno model ────────────────────────────────
    /// TLS vector slot holding the per-thread errno int pointer. 0 = not yet
    /// allocated (slot 0 is permanently occupied by the static TLS block, so
    /// 0 is a safe "unallocated" sentinel).
    pub(crate) crt_errno_slot: u32,
    /// TLS vector slot holding the per-thread doserrno int pointer (0 = none).
    pub(crate) crt_doserrno_slot: u32,
    /// Host-side mirror of the current thread's errno (used by `_get_errno`
    /// and as the x64 fallback when no guest TLS vector exists).
    pub(crate) crt_errno_value: i32,
    /// Host-side mirror of the current thread's doserrno.
    pub(crate) crt_doserrno_value: i32,
    /// Stable guest int storage for errno on x64 (no TLS vector) — lazily
    /// allocated on first use.
    pub(crate) crt_errno_storage: u64,
    /// Stable guest int storage for doserrno on x64 — lazily allocated.
    pub(crate) crt_doserrno_storage: u64,
    /// Guest pointer to the static buffer used by strerror/_strerror.
    pub(crate) crt_strerror_buf: u64,
    /// MSVC LCG PRNG state for rand/srand.
    pub(crate) crt_rand_state: u32,
    /// Host instant for `clock()` (elapsed milliseconds since runtime start).
    pub(crate) crt_start_instant: std::time::Instant,
    /// Guest `FILE*` block address → host stream state.
    pub(crate) crt_files: BTreeMap<u64, CrtFileState>,
    /// Monotonic index used to allocate guest FILE blocks.
    pub(crate) crt_next_file_index: u64,
    pub(crate) unhandled_exception_filter: u64,
    pub(crate) main_module_security_cookie_address: Option<u64>,
    pub(crate) process_pointer_cookie: u64,
    pub(crate) mapped_image_base: u64,
    pub(crate) mapped_image_size: u64,
    pub(crate) teb_base: u64,
    pub(crate) peb_base: u64,
    pub(crate) main_module_name: String,
    pub(crate) main_module_path: String,
    pub(crate) main_module_exports: Vec<ExportSymbol>,
    pub(crate) globals: CrtGlobals,
    /// Guest pointer to the "C" locale string (for setlocale).
    pub(crate) locale_string: u64,
    pub(crate) command_line: String,
    pub(crate) command_line_ansi_ptr: u64,
    pub(crate) command_line_wide_ptr: u64,
    pub(crate) process_parameters_ptr: u64,
    pub(crate) configured_narrow_argv_mode: Option<u32>,
    pub(crate) process_environment: BTreeMap<String, String>,
    pub(crate) current_directory: String,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    // --- Steam.exe crash-point instrumentation ---
    // The fields below track state specific to Steam.exe's x86 startup sequence.
    // They are only active when the guest binary is Steam.exe running under X86.
    // Each field is guarded by `guest_arch == GuestArch::X86` checks so that
    // non-Steam executables incur zero overhead.
    /// Rolling window of the most recent basic-block summaries that touch the
    /// `0x401389..=0x4013fc` helper region (the record-iteration loop).
    pub(crate) steam_401389_recent_blocks: VecDeque<String>,
    /// First block summary where ESI crossed the 0x1000 threshold during the
    /// record scan — helps identify the point where the index goes out of bounds.
    pub(crate) steam_401389_first_over_0x1000: Option<String>,
    /// Expected ESI value after the callee at `0x401434` returns to `0x4013a8`.
    /// Used to detect callee-saved register corruption across the call.
    pub(crate) steam_401389_expected_esi_after_401434: Option<u32>,
    /// Rolling window of recent main-module block RVAs (for context in errors).
    pub(crate) recent_main_block_rvas: VecDeque<u32>,
    /// Count of recent blocks at `0xcc400` (ConVar creation start) — non-zero
    /// indicates the ConVar registration phase is active.
    pub(crate) recent_main_cc400_count: usize,
    /// Rolling window of blocks in the `0x13d197..=0x13f78d` final-assert window.
    pub(crate) steam_final_assert_recent_blocks: VecDeque<String>,
    /// History of global-variable writes observed in the final-assert window.
    pub(crate) steam_final_assert_global_history: VecDeque<String>,
    /// Rolling window of blocks in the `0x16ddf0..=0x16e120` pre-report window.
    pub(crate) steam_pre_report_blocks: VecDeque<String>,
    /// Address of the stack slot where ESI is saved in the `0x401389` frame.
    /// Used to detect if `0x401434` overwrites the saved ESI slot.
    pub(crate) steam_401389_saved_esi_slot_addr: Option<u64>,
    /// `this` pointer for the ConVar object whose `memcpy` is being tracked.
    pub(crate) steam_convar_memcpy_watch_this: Option<u64>,
    /// Rolling window of blocks touching the `0x165af0` helper range.
    pub(crate) steam_565af0_recent_blocks: VecDeque<String>,
    /// Expected EDI value while inside the `0x4dea00` call chain.
    pub(crate) steam_4dea00_expected_edi: Option<u64>,
    /// Expected EDI value for the install-dir setup block.
    pub(crate) steam_install_dir_expected_edi: Option<u64>,
    /// Rolling window of blocks in the status-writer sub-range of the final-assert window.
    pub(crate) steam_final_status_writer_blocks: VecDeque<String>,
    /// Rolling window of blocks in the critical-section sub-range of the final-assert window.
    pub(crate) steam_final_lock_blocks: VecDeque<String>,
    /// Number of hash-insert probes emitted so far (capped at 16).
    pub(crate) steam_4ae970_probe_count: usize,
    /// Number of owner-allocator probes emitted so far (capped at 16).
    pub(crate) steam_owner_allocator_probe_count: usize,
    /// Counter of API calls dispatched since execution started (for Steam tracing).
    pub(crate) steam_api_call_count: u64,
    /// Max API calls to trace under `steam_api_trace` before throttling.
    pub(crate) steam_api_trace_max: u64,
    /// Whether we've already reported the first exit from the mapped image.
    pub(crate) steam_reported_image_exit: bool,
    pub(crate) next_frame_index: u32,
    pub(crate) next_audio_buffer_tag: u64,
    /// Set only when a real guest swapchain present has produced a frame
    /// (D3D9 device present, D3D9 swapchain present, D3D11 present, D3D12
    /// present).  Never set from the GDI preview path, builtin window
    /// painting, or any synthetic path.
    pub(crate) first_real_guest_frame_seen: bool,
    /// Most recent frame extracted from REAL guest GDI pixels (a guest-driven
    /// `BitBlt`/`StretchBlt` into a window surface, or a real memory-DC
    /// conversion).  Never assigned synthetic chrome/theme composition.
    pub(crate) last_real_gdi_frame: Option<LiveFrame>,
    /// Count of real guest swapchain presents (incremented only at the four
    /// real present sites: D3D9 device present, D3D9 swapchain present,
    /// D3D11 present, D3D12 present).  GDI window pixels do not increment it.
    pub(crate) real_guest_frames: u64,
    /// Timestamp of the last GDI window preview publish — used for rate-limiting
    /// `publish_live_window_preview_if_needed()` to at most 1 frame per 33 ms
    /// (~30 FPS) so that GDI previews never flood the live frame channel.
    pub(crate) last_gdi_preview_publish: std::time::Instant,
    pub(crate) delivering_guest_exception: bool,
    /// Set when an unhandled guest exception (RaiseException with no
    /// handler, or an unhandled fault) terminates the process: the finalizer
    /// reports ExecutionTermination::GuestException with this code.
    pub(crate) unhandled_guest_exception: Option<u32>,
    pub(crate) dtm: bool,
    /// Telemetry collector for unsupported imports, vtable methods,
    /// shader-model requests, and unimplemented CPU instructions.
    pub(crate) telemetry: TelemetryCollector,
    /// When enabled (via `CASA1_STEAM_TRACE` env var), Steam.exe-specific
    /// diagnostic probes in the main execution loop are active.  These probes
    /// track cookie-slot values, ESI-clobber detection, final-assert window
    /// blocks, record-table iteration, ConVar creation, hash-table inserts,
    /// owner-allocator steps, and many other Steam-only state-machine checks.
    /// Disabled by default — only enable when debugging Steam.exe startup
    /// failures.
    pub(crate) enable_steam_tracing: bool,
    pub(crate) jit_runtime: Option<crate::jit::JitRuntime>,
    /// JIT policy requested by the caller (RunnerJob protocol; Auto keeps
    /// the historical dormant behavior).
    pub(crate) jit_mode: crate::runner::JitMode,
    /// Tiered compilation manager that tracks execution counts and promotes
    /// hot blocks to higher optimization tiers.
    pub(crate) tiered_compiler: crate::jit::TieredCompiler,
    /// XInput controller manager (Phase 5.2.1).
    pub(crate) xinput_manager: crate::real_win32::XInputManager,
    /// Steam Input API state (Phase 5.2.4).
    pub(crate) steam_input: crate::steam_input::SteamInput,
    /// SteamVR / OpenVR state (Phase 5.3.1).
    pub(crate) steam_vr: crate::steamvr::SteamVR,
    // -- COM/OLE Automation tracking (Phase P0.1) --
    /// CLSID string per class factory guest object address.
    pub(crate) com_factory_clsids: HashMap<u64, String>,
    /// Registration token -> CLSID string for CoRegisterClassObject/CoRevokeClassObject.
    pub(crate) com_registration_tokens: HashMap<u32, String>,
    /// Next registration token value.
    pub(crate) com_next_token: u32,
    /// Native COM apartment state for DllGetClassObject resolution and
    /// class-factory registration.  Lazily initialised on first COM call.
    pub(crate) com_apartment: Option<crate::real_win32::ComApartmentState>,
    /// Maps file handles to ADS stream info (base_windows_path, stream_name).
    /// Populated by CreateFileW when an NTFS Alternate Data Stream path is detected.
    pub(crate) ads_handles: HashMap<u32, (String, String)>,
    /// XAPO audio effect manager for IXAPO COM object dispatch.
    pub(crate) xapo_manager: crate::real_audio::XapoManager,
    /// Guest XAPO effect objects: maps guest object address -> effect instance ID.
    pub(crate) xapo_effect_instances: HashMap<u64, u64>,
    // ── WMI State ──────────────────────────────────────────────────────────────
    /// WbemServices instances: maps guest object address -> WbemServices.
    pub(crate) wmi_services: HashMap<u64, crate::wmi::WbemServices>,
    /// WbemClassObject instances: maps guest object address -> WbemClassObject.
    pub(crate) wmi_class_objects: HashMap<u64, crate::wmi::WbemClassObject>,
    /// EnumWbemObjects instances: maps guest object address -> EnumWbemObjects.
    pub(crate) wmi_enums: HashMap<u64, crate::wmi::EnumWbemObjects>,
    // ── Direct2D / DirectWrite State ──────────────────────────────────────────
    /// D2D factory instances.
    pub(crate) d2d_factory: Option<crate::d2d::D2DFactory>,
    /// DWrite factory instances.
    pub(crate) dwrite_factory: Option<crate::dwrite::DWriteFactory>,
    /// D2D brush objects: maps guest object address -> brush.
    pub(crate) d2d_brushes: HashMap<u64, crate::d2d::D2DBrush>,
    /// D2D bitmap objects: maps guest object address -> bitmap.
    pub(crate) d2d_bitmaps: HashMap<u64, crate::d2d::D2DBitmap>,
    /// DWrite text format objects: maps guest object address -> format.
    pub(crate) dwrite_formats: HashMap<u64, crate::dwrite::DWriteTextFormat>,
    /// DWrite text layout objects: maps guest object address -> layout.
    pub(crate) dwrite_layouts: HashMap<u64, crate::dwrite::DWriteTextLayout>,
    // ── Print Subsystem ────────────────────────────────────────────────────────
    /// Print spooler state (winspool.drv)
    pub(crate) print_subsystem: crate::print::PrintSubsystem,
    // ── WebView2 Runtime ───────────────────────────────────────────────────────
    /// WebView2 COM interface state (wraps WKWebView via cef_bridge).
    pub(crate) webview2_runtime: crate::webview2::WebView2Runtime,
    // ── SEH / VEH Exception Handling ──────────────────────────────────────────
    /// Structured Exception Handling and Vectored Exception Handling subsystem.
    /// Manages .pdata exception tables, VEH handler chains, and SEH dispatch.
    pub(crate) seh: crate::seh::SehSubsystem,
    // ── D3D9 Basic Rendering (Phase 1.5) ──────────────────────────────────────
    /// Direct3D9 compatibility shim (lazily initialised).
    pub(crate) d3d9_shim: Option<crate::d3d11::Direct3D9Shim>,
    /// Guest IDirect3DDevice9 objects → shim device state.
    pub(crate) d3d9_devices: HashMap<u64, crate::d3d11::Direct3D9Device>,
    /// Guest IDirect3DVertexBuffer9 objects → shim vertex buffer.
    pub(crate) d3d9_vertex_buffers: HashMap<u64, crate::d3d11::VertexBuffer9>,
    /// Guest IDirect3DIndexBuffer9 objects → shim index buffer.
    pub(crate) d3d9_index_buffers: HashMap<u64, crate::d3d11::IndexBuffer9>,
    /// Guest IDirect3DTexture9 objects → shim texture.
    pub(crate) d3d9_textures: HashMap<u64, crate::d3d11::D3d9Texture>,
    /// Guest IDirect3DQuery9 objects (stub).
    pub(crate) d3d9_queries: HashMap<u64, ()>,
    /// Guest IDirect3DSwapChain9 objects → device association.
    pub(crate) d3d9_swapchains: HashMap<u64, u64>,
    /// Guest IDirect3D9 factory objects.
    pub(crate) d3d9_factories: HashSet<u64>,
    // ── Steam API (Phase B3) ────────────────────────────────────────────────
    /// Whether SteamAPI_Init() has been called successfully.
    pub(crate) steam_api_initialized: bool,
    /// Registered Steam callbacks: maps callback ID → callback function pointer.
    /// Used by SteamAPI_RegisterCallback / SteamAPI_RunCallbacks.
    pub(crate) steam_callbacks: BTreeMap<u32, u64>,
    /// Registered Steam call results: maps call result ID → callback function pointer.
    /// Used by SteamAPI_RegisterCallResult / SteamAPI_UnregisterCallResult.
    pub(crate) steam_call_results: BTreeMap<u64, u64>,
    /// Interface pointer counter for SteamInternal_CreateInterface.
    /// Incremented for each unique interface version string.
    pub(crate) steam_interface_pointers: BTreeMap<String, u64>,
    /// Next virtual address for Steam interface allocation.
    pub(crate) next_steam_interface_address: u64,
    // ── Phase M4: SxS Activation Context state ──────────────────────────────
    /// Activation context handle → ActivationContext
    pub(crate) activation_contexts: BTreeMap<u64, crate::pe::ActivationContext>,
    /// Stack of active activation context cookies (for DeactivateActCtx)
    pub(crate) activation_context_stack: Vec<u64>,
    /// Next activation context handle value
    pub(crate) next_activation_context_handle: u64,
    /// Whether comctl32 version 6 (Common Controls v6) is active via manifest
    pub(crate) comctl32_v6_active: bool,
    /// Whether `.local` file-based DLL redirection is active.
    /// When true, the application directory is searched first for all DLL loads
    /// (Windows "local redirection" / activation context isolation).
    pub(crate) local_redirect_active: bool,
    /// Phase L — maps ShellItem guest object addresses to their associated
    /// path string (used by ShellFolderBindToObject -> SHCreateItemFromParsingName).
    pub(crate) shell_item_paths: HashMap<u64, String>,
    /// Phase L1 — maps ShellFolder (IShellFolder) guest object addresses / PIDLs
    /// to their associated directory path (used by ShellFolderEnumObjects).
    pub(crate) shell_folder_paths: HashMap<u64, String>,
    /// Phase L1 — maps IEnumIDList enumerator guest object addresses to their
    /// enumeration state (PIDL list + current position).
    pub(crate) enum_id_lists: HashMap<u64, EnumIdListState>,
    /// Phase L4 — maps IContextMenu guest object addresses to the list of
    /// filesystem paths they represent (used by InvokeCommand to open files).
    pub(crate) context_menu_paths: HashMap<u64, Vec<String>>,
    // ── DXGI Factory State (Phase 5.5 #2) ──────────────────────────────
    /// Tracked window association for IDXGIFactory::MakeWindowAssociation.
    /// Stores (hwnd, flags).
    pub(crate) dxgi_window_assoc: Option<(u64, u32)>,
    /// Per-object private data for IDXGIFactory::SetPrivateData.
    /// Outer key = object pointer, inner key = GUID-as-u128, value = data bytes.
    pub(crate) dxgi_private_data: HashMap<u64, HashMap<u128, Vec<u8>>>,
    // ── DWrite Font Collection Loaders ─────────────────────────────────
    /// Registered font collection loader handles for IDWriteFactory.
    /// Tracked so Register/UnregisterFontCollectionLoader are consistent.
    pub(crate) dwrite_font_collection_loaders: HashSet<u64>,
    // ── Drag & Drop ────────────────────────────────────────────────────
    /// Tracked dropped files per HDROP handle for DragQueryFileW.
    /// Maps HDROP handle → list of file paths.
    pub(crate) drag_drop_files: HashMap<u64, Vec<String>>,
    // ── Property Store ─────────────────────────────────────────────────
    /// Per-property-store key-value tracking for IPropertyStore::SetValue.
    /// Outer key = this pointer, inner key = PROPERTYKEY encoding (fmtid:u128 | pid:u32).
    pub(crate) property_store_data: HashMap<u64, Vec<(u128, u32, Vec<u8>)>>,
    // ── D3D9 Private Data ──────────────────────────────────────────────
    /// Per-object private data for D3D9 IDirect3DResource9::SetPrivateData etc.
    pub(crate) d3d9_private_data: HashMap<(u64, u128), Vec<u8>>,
    // ── DXGI Event Registration ────────────────────────────────────────
    /// Cookie counter for DXGI event registrations (stereo/occlusion status).
    pub(crate) next_dxgi_cookie: u64,
    /// Cookie-to-event-handle mapping for stereo status.
    pub(crate) dxgi_stereo_events: HashMap<u64, u64>,
    /// Cookie-to-event-handle mapping for occlusion status.
    pub(crate) dxgi_occlusion_events: HashMap<u64, u64>,
    // ── CEF Cross-Origin Whitelist ────────────────────────────────────
    /// Tracked cross-origin whitelist entries for CefAdd/Remove/ClearCrossOriginWhitelist.
    pub(crate) cef_cross_origin_whitelist: HashSet<String>,
    // ── DWM Per-Window State ──────────────────────────────────────────
    /// Per-hwnd blur-behind state for DwmEnableBlurBehindWindow.
    /// Stores (fEnable, blur_region, transition_on_maximized).
    pub(crate) dwm_blur_states: HashMap<u32, (bool, u32, bool)>,
    /// Per-hwnd extended frame margins for DwmExtendFrameIntoClientArea.
    /// Stores (cxLeftWidth, cxRightWidth, cyTopHeight, cyBottomHeight).
    pub(crate) dwm_margins: HashMap<u32, (u32, u32, u32, u32)>,
}

#[derive(Debug)]
pub(crate) struct CachedInstruction {
    pub(crate) bytes: Vec<u8>,
    pub(crate) decoded: DecodedInstruction,
}

#[derive(Debug)]
pub(crate) struct CachedInstructionEntry {
    pub(crate) cached: Arc<CachedInstruction>,
    pub(crate) generation: u64,
}

#[derive(Debug)]
pub(crate) struct CachedBlock {
    pub(crate) bytes: Vec<u8>,
    pub(crate) translated: TranslatedBlock,
    pub(crate) start_rip: u64,
    pub(crate) end_rip: u64,
}

#[derive(Debug)]
pub(crate) struct CachedBlockEntry {
    pub(crate) cached: Arc<CachedBlock>,
    pub(crate) generation: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct WindowSurface {
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) bytes: Vec<u8>,
    /// Pixel provenance: `true` ONLY after a real guest-driven SRCCOPY blit
    /// copied real source pixels into this surface.  Host-invented content
    /// (builtin control chrome, theme fills, blank placeholders) leaves this
    /// `false` so synthetic pixels can never reach the live channel, be
    /// cached as a real GDI frame, or propagate through later blits.
    pub(crate) real_pixels: bool,
}

/// A GDI bitmap backing a memory DC (created via `CreateDIBSection` or
/// `CreateCompatibleBitmap`).  `guest_pixel_ptr` is the guest-visible address
/// of the pixel data (returned to the guest via `ppvBits` for DIB sections);
/// we mirror the bytes host-side so `BitBlt`/`StretchBlt` can read them
/// without round-tripping through guest memory on every pixel.
#[derive(Debug, Clone)]
pub(crate) struct MemoryBitmap {
    pub(crate) width: usize,
    pub(crate) height: usize,
    /// Bytes-per-pixel (1, 2, 3, or 4).  Modern apps almost always use 4
    /// (BGRA).  We store pixels in their native layout and convert on blit.
    pub(crate) bpp: usize,
    /// Host-side mirror of the pixel data, in the bitmap's native layout
    /// (bottom-up for DIB sections, as Windows stores them).
    pub(crate) bytes: Vec<u8>,
    /// Guest address of the pixel data, so we can refresh the mirror from
    /// guest memory before a blit (the guest writes pixels directly into a
    /// DIB section's buffer).
    pub(crate) guest_pixel_ptr: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GdiFont {
    pub(crate) height: i32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProgressBarState {
    pub(crate) min: i32,
    pub(crate) max: i32,
    pub(crate) pos: i32,
    pub(crate) step: i32,
}

impl PeHostRuntime {
    pub(crate) fn new(
        ge: GameEnvironment,
        dtm: bool,
        pending_keyboard_replay: Vec<KeyboardReplayEvent>,
        live_session: Option<LivePeSession>,
        allowed_trace_categories: Option<BTreeSet<String>>,
    ) -> Self {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let keyboard_replay_device = if pending_keyboard_replay.is_empty() {
            None
        } else {
            Some(user32.register_keyboard_device(&KeyboardDevice {
                vendor_id: 0xca51,
                product_id: 0x0001,
                serial: "pe-runtime-replay".to_string(),
            }))
        };
        let live_keyboard_device = if live_session.is_some() {
            Some(user32.register_keyboard_device(&KeyboardDevice {
                vendor_id: 0xca51,
                product_id: 0x0002,
                serial: "pe-runtime-live".to_string(),
            }))
        } else {
            None
        };
        let live_mouse_device = if live_session.is_some() {
            Some(user32.register_mouse_device(&MouseDevice {
                vendor_id: 0xca51,
                product_id: 0x0003,
                serial: "pe-runtime-live".to_string(),
            }))
        } else {
            None
        };
        let observers = crate::runtime_events::new_observer_list();
        // The initial guest process: a fresh guest pid from the ONE guest
        // pid namespace, the standalone diagnostic context ("macwin"
        // provenance — the host pid is never the guest identity), and the
        // runtime's historical address-space cursor so anonymous
        // reservations land where they always have.  The address space is
        // THE canonical VirtualMemory the interpreter/JIT/win32 share.
        let guest_process = crate::runtime::process::GuestProcess::new(
            crate::runtime::process::allocate_guest_pid(),
            None,
            crate::runtime::process::InitialProcessContext::macwin_default(),
            super::private_pages_base_for_arch(GuestArch::X64),
        );
        let mut runtime = Self {
            audio: AudioSubsystem::new(),
            win32: Win32Subsystem::new_with_guest_process(
                ge,
                dtm,
                live_session.is_some(),
                guest_process,
            ),
            user32,
            observers: observers.clone(),
            guest_arch: GuestArch::X64,
            live_session,
            live_keyboard_device,
            live_mouse_device,
            pending_keyboard_replay,
            keyboard_replay_device,
            keyboard_replay_injected: false,
            host_thunks: U64Map::default(),
            thunk_to_fast_index: U64Map::default(),
            guest_objects: BTreeMap::new(),
            shell_link_interfaces: BTreeMap::new(),
            shell_link_states: BTreeMap::new(),
            xaudio_engines: BTreeMap::new(),
            xaudio_mastering_voices: BTreeMap::new(),
            xaudio_source_voices: BTreeMap::new(),
            directinput8_objects: BTreeMap::new(),
            directinput8_device_objects: BTreeMap::new(),
            directinput8_ff_state: BTreeMap::new(),
            d3d12_runtime: D3d12Runtime::new(),
            d3d12_guest_root_signature: None,
            d3d12_guest_pipeline_state: None,
            dxgi_factories: BTreeMap::new(),
            dxgi_adapters: BTreeMap::new(),
            d3d12_devices: BTreeMap::new(),
            d3d12_command_queues: BTreeMap::new(),
            d3d12_command_allocators: BTreeMap::new(),
            d3d12_descriptor_heaps: BTreeMap::new(),
            d3d12_command_lists: BTreeMap::new(),
            d3d12_fences: BTreeMap::new(),
            d3d12_swapchains: BTreeMap::new(),
            d3d12_resources: BTreeMap::new(),
            d3d11_devices: BTreeMap::new(),
            d3d11_contexts: BTreeMap::new(),
            d3d11_deferred_contexts: BTreeMap::new(),
            d3d11_swapchains: BTreeMap::new(),
            d3d11_buffers: BTreeMap::new(),
            d3d11_textures: BTreeMap::new(),
            d3d11_views: BTreeMap::new(),
            d3d11_input_layouts: BTreeMap::new(),
            d3d11_shaders: BTreeMap::new(),
            d3d11_blend_states: BTreeMap::new(),
            d3d11_rasterizer_states: BTreeMap::new(),
            d3d11_depth_stencil_states: BTreeMap::new(),
            d3d11_sampler_states: BTreeMap::new(),
            d3d11_mapped_resources: U64Map::default(),
            instruction_cache: U64Map::default(),
            instruction_cache_lru: VecDeque::new(),
            instruction_cache_generation: 0,
            basic_block_cache: U64Map::default(),
            basic_block_cache_lru: VecDeque::new(),
            basic_block_cache_generation: 0,
            allowed_trace_categories,
            trace_events: Vec::new(),
            gfx_frames: Vec::new(),
            next_trace_index: 2,
            next_thunk_address: THUNK_BASE,
            next_data_address: CRT_DATA_BASE,
            next_device_context_handle: 0x9000,
            next_gdi_object_handle: 0xa000,
            next_descriptor_handle: DESCRIPTOR_HANDLE_BASE,
            next_heap_address: CRT_HEAP_BASE,
            x86_heap_region: 0,
            heap_allocations: BTreeMap::new(),
            crt_alloc_fail_next: false,
            critical_sections: BTreeMap::new(),
            condition_variables: BTreeMap::new(),
            srw_locks: BTreeMap::new(),
            apc_queues: BTreeMap::new(),
            timer_queue: GuestTimerQueue::new(),
            timer_work_sink: Arc::new(Mutex::new(VecDeque::new())),
            next_timer_queue_handle: 0xE0000001,
            wait_registrations: BTreeMap::new(),
            next_wait_handle: 0xE0001001,
            // ── BCrypt / CNG Crypto State ────────────────────────────────────
            bcrypt_ctx: BCryptContext::new(),
            bcrypt_providers: BTreeMap::new(),
            bcrypt_hashes: BTreeMap::new(),
            bcrypt_keys: BTreeMap::new(),
            bcrypt_secrets: BTreeMap::new(),
            next_bcrypt_provider_id: 0xB0000001,
            next_bcrypt_hash_id: 0xB1000001,
            next_bcrypt_key_id: 0xB2000001,
            next_bcrypt_secret_id: 0xB3000001,
            cert_store_manager: crate::security::CertificateStoreManager::new(),
            cert_store_names: BTreeMap::new(),
            cert_contexts: BTreeMap::new(),
            cert_enum_cursors: BTreeMap::new(),
            drop_targets: BTreeMap::new(),
            next_drop_target_id: 0xDD010000,
            signal_handlers: BTreeMap::new(),
            tls_slots: BTreeMap::new(),
            fls_slots: BTreeMap::new(),
            pending_dll_main_calls: VecDeque::new(),
            pending_fiber_fls_callbacks: Vec::new(),
            pending_guest_threads: VecDeque::new(),
            active_pumped_guest_thread: None,
            yield_pumped_guest_thread: false,
            pump_yield_with_wait: None,
            main_thread_parked: false,
            parked_wait: None,
            yield_pumped_guest_thread_wake_tick: None,
            pumped_thread_exit_requested: None,
            pumped_thread_exit_with_detach: true,
            process_exit_requested: None,
            main_thread_exit_code: None,
            tls_vector_ptr: 0,
            init_once_pending: BTreeSet::new(),
            init_once_completed: BTreeMap::new(),
            atexit_handlers: Vec::new(),
            next_gdi_handle: 0xDD000000, // GDI handle space starts at a high address
            module_handles: BTreeMap::new(),
            module_names_by_handle: BTreeMap::new(),
            module_paths_by_handle: BTreeMap::new(),
            synthetic_module_handles: BTreeSet::new(),
            materialized_synthetic_modules: BTreeSet::new(),
            loaded_real_dlls: HashMap::new(),
            forwarder_export_cache: BTreeMap::new(),
            dll_info_table: HashMap::new(),
            synthetic_dll_init_callbacks: Vec::new(),
            network: NetworkStack::new(),
            winhttp: WinHttpStack::new(),
            device_contexts: BTreeMap::new(),
            dialog_procs: BTreeMap::new(),
            window_surfaces: BTreeMap::new(),
            dc_selected_objects: BTreeMap::new(),
            gdi_bitmaps: BTreeMap::new(),
            dc_background_modes: BTreeMap::new(),
            dc_text_colors: BTreeMap::new(),
            dc_bk_colors: BTreeMap::new(),
            gdi_objects: BTreeMap::new(),
            gdi_brushes: BTreeMap::new(),
            gdi_pens: BTreeMap::new(),
            gdi_fonts: BTreeMap::new(),
            menus: BTreeMap::new(),
            next_menu_handle: 0x1000,
            window_menus: BTreeMap::new(),
            progress_bar_states: BTreeMap::new(),
            scroll_info: BTreeMap::new(),
            common_control_state: BTreeMap::new(),
            image_lists: BTreeMap::new(),
            next_image_list_handle: 0x2000,
            common_controls_initialized: false,
            common_controls_flags: 0,
            animation_settings: 0,
            error_mode: 0,
            last_error: 0,
            invalid_parameter_handler: 0,
            crt_errno_slot: 0,
            crt_doserrno_slot: 0,
            crt_errno_value: 0,
            crt_doserrno_value: 0,
            crt_errno_storage: 0,
            crt_doserrno_storage: 0,
            crt_strerror_buf: 0,
            crt_rand_state: 1,
            crt_start_instant: std::time::Instant::now(),
            crt_files: BTreeMap::new(),
            crt_next_file_index: 1,
            unhandled_exception_filter: 0,
            main_module_security_cookie_address: None,
            process_pointer_cookie: 0,
            mapped_image_base: 0,
            mapped_image_size: 0,
            teb_base: 0,
            peb_base: 0,
            main_module_name: String::new(),
            main_module_path: String::new(),
            main_module_exports: Vec::new(),
            globals: CrtGlobals::default(),
            locale_string: 0,
            command_line: String::new(),
            command_line_ansi_ptr: 0,
            command_line_wide_ptr: 0,
            process_parameters_ptr: 0,
            configured_narrow_argv_mode: None,
            process_environment: BTreeMap::new(),
            current_directory: "C:\\".to_string(),
            stdout: String::new(),
            stderr: String::new(),
            steam_401389_recent_blocks: VecDeque::new(),
            steam_401389_first_over_0x1000: None,
            steam_401389_expected_esi_after_401434: None,
            steam_565af0_recent_blocks: VecDeque::new(),
            recent_main_block_rvas: VecDeque::new(),
            recent_main_cc400_count: 0,
            steam_final_assert_recent_blocks: VecDeque::new(),
            steam_final_assert_global_history: VecDeque::new(),
            steam_pre_report_blocks: VecDeque::new(),
            steam_401389_saved_esi_slot_addr: None,
            steam_convar_memcpy_watch_this: None,
            steam_final_status_writer_blocks: VecDeque::new(),
            steam_final_lock_blocks: VecDeque::new(),
            steam_4dea00_expected_edi: None,
            steam_install_dir_expected_edi: None,
            steam_4ae970_probe_count: 0,
            steam_owner_allocator_probe_count: 0,
            steam_api_call_count: 0,
            steam_api_trace_max: 10000,
            steam_reported_image_exit: false,
            next_frame_index: 0,
            next_audio_buffer_tag: 1,
            first_real_guest_frame_seen: false,
            last_real_gdi_frame: None,
            real_guest_frames: 0,
            last_gdi_preview_publish: std::time::Instant::now(),
            delivering_guest_exception: false,
            unhandled_guest_exception: None,
            dtm,
            telemetry: TelemetryCollector::new(),
            // Steam diagnostic tracing is opt-in via env var.
            // Only enable when debugging Steam.exe startup failures.
            enable_steam_tracing: std::env::var("CASA1_STEAM_TRACE").is_ok(),
            jit_runtime: None,
            jit_mode: crate::runner::JitMode::Auto,
            tiered_compiler: crate::jit::TieredCompiler::with_thresholds(u32::MAX, u32::MAX),
            xinput_manager: crate::real_win32::XInputManager::new(),
            steam_input: crate::steam_input::SteamInput::new(),
            steam_vr: crate::steamvr::SteamVR::new(),
            com_factory_clsids: HashMap::new(),
            com_registration_tokens: HashMap::new(),
            com_next_token: 1,
            com_apartment: None,
            ads_handles: HashMap::new(),
            xapo_manager: {
                let mut mgr = crate::real_audio::XapoManager::new();
                mgr.register_builtins();
                mgr
            },
            xapo_effect_instances: HashMap::new(),
            // ── WMI State ──────────────────────────────────────────────────────
            wmi_services: HashMap::new(),
            wmi_class_objects: HashMap::new(),
            wmi_enums: HashMap::new(),
            // ── Direct2D / DirectWrite State ──────────────────────────────────────
            d2d_factory: None,
            dwrite_factory: None,
            d2d_brushes: HashMap::new(),
            d2d_bitmaps: HashMap::new(),
            dwrite_formats: HashMap::new(),
            dwrite_layouts: HashMap::new(),
            // ── Print Subsystem ─────────────────────────────────────────────────
            print_subsystem: crate::print::PrintSubsystem::new(),
            // ── WebView2 Runtime ───────────────────────────────────────────────
            webview2_runtime: crate::webview2::WebView2Runtime::new(),
            // ── SEH / VEH Exception Handling ───────────────────────────────────
            seh: crate::seh::SehSubsystem::new(),
            // ── D3D9 Basic Rendering (Phase 1.5) ───────────────────────────────
            d3d9_shim: None,
            d3d9_devices: HashMap::new(),
            d3d9_vertex_buffers: HashMap::new(),
            d3d9_index_buffers: HashMap::new(),
            d3d9_textures: HashMap::new(),
            d3d9_queries: HashMap::new(),
            d3d9_swapchains: HashMap::new(),
            d3d9_factories: HashSet::new(),
            // ── Steam API (Phase B3) ────────────────────────────────────────────────
            steam_api_initialized: false,
            steam_callbacks: BTreeMap::new(),
            steam_call_results: BTreeMap::new(),
            steam_interface_pointers: BTreeMap::new(),
            next_steam_interface_address: 0x7f0000000000,
            // ── Phase M4: SxS Activation Context state ──────────────────────
            activation_contexts: BTreeMap::new(),
            activation_context_stack: Vec::new(),
            next_activation_context_handle: 0xE0000001,
            comctl32_v6_active: false,
            local_redirect_active: false,
            shell_item_paths: HashMap::new(),
            // ── Phase L1: Shell folder paths / EnumIDList state ───────────────
            shell_folder_paths: HashMap::new(),
            enum_id_lists: HashMap::new(),
            // ── Phase L4: Context menu paths ─────────────────────────────────
            context_menu_paths: HashMap::new(),
            // ── Phase 1 sub-agent fields ──────────────────────────────────────
            dxgi_window_assoc: None,
            dxgi_private_data: HashMap::new(),
            dwrite_font_collection_loaders: HashSet::new(),
            drag_drop_files: HashMap::new(),
            property_store_data: HashMap::new(),
            d3d9_private_data: HashMap::new(),
            next_dxgi_cookie: 1,
            dxgi_stereo_events: HashMap::new(),
            dxgi_occlusion_events: HashMap::new(),
            cef_cross_origin_whitelist: HashSet::new(),
            dwm_blur_states: HashMap::new(),
            dwm_margins: HashMap::new(),
        };
        // Wire the runtime's observer list into the subsystems that emit
        // events outside the runtime's own dispatch (the Win32 file layer
        // and the user32 window layer hold a clone of the shared list; the
        // global CEF bridge and the real-audio backend publish through the
        // process-wide current-observer registry for the runtime's lifetime).
        runtime.win32.event_observers = Some(observers.clone());
        runtime.user32.event_observers = Some(observers.clone());
        crate::cef_bridge::set_event_observers(Some(observers.clone()));
        crate::runtime_events::register_current_observers(observers);
        runtime
    }
}
impl PeHostRuntime {
    pub(crate) fn write_guest_unicode_string(
        &self,
        memory: &mut MemoryImage,
        address: u64,
        value_ptr: u64,
        value: &str,
    ) -> AppResult<()> {
        let byte_len = value.encode_utf16().count().checked_mul(2).ok_or_else(|| {
            AppError::new(ReasonCode::RcUnimplInsn, "unicode string length overflow")
        })?;
        let byte_len = u16::try_from(byte_len).map_err(|_| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unicode string is too large for a guest UNICODE_STRING: {value:?}"),
            )
        })?;
        let maximum_length = byte_len.checked_add(2).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unicode string maximum length overflow for {value:?}"),
            )
        })?;
        memory.map_bytes(address, &byte_len.to_le_bytes());
        memory.map_bytes(address + 2, &maximum_length.to_le_bytes());
        match self.guest_arch {
            GuestArch::X86 => write_guest_pointer(memory, address + 4, value_ptr, self.guest_arch)?,
            GuestArch::X64 => {
                memory.map_bytes(address + 4, &[0; 4]);
                write_guest_pointer(memory, address + 8, value_ptr, self.guest_arch)?;
            }
        }
        Ok(())
    }

    pub(crate) fn sync_process_parameters(
        &mut self,
        memory: &mut MemoryImage,
        image_path: &str,
    ) -> AppResult<()> {
        if self.guest_arch != GuestArch::X86 || self.peb_base == 0 {
            return Ok(());
        }

        let command_line = self.command_line.clone();
        if self.command_line_wide_ptr == 0 {
            self.command_line_wide_ptr = self.alloc_utf16_string(memory, &command_line)?;
        }

        let current_directory = self.current_directory.clone();
        let process_environment = self.process_environment.clone();
        let dll_path = "C:\\Windows\\System32";
        let current_directory_ptr = self.alloc_utf16_string(memory, &current_directory)?;
        let dll_path_ptr = self.alloc_utf16_string(memory, dll_path)?;
        let image_path_ptr = self.alloc_utf16_string(memory, image_path)?;
        let environment_ptr = self.alloc_utf16_environment_block(memory, &process_environment)?;
        let process_parameters_ptr = self.alloc_zeroed(memory, 0x80, 16)?;

        write_u32(memory, process_parameters_ptr, 0x80);
        write_u32(memory, process_parameters_ptr + 4, 0x80);
        write_u32(
            memory,
            process_parameters_ptr + 8,
            RTL_USER_PROCESS_PARAMETERS_NORMALIZED,
        );
        write_guest_pointer(
            memory,
            process_parameters_ptr + 0x18,
            u64::from(STD_INPUT_HANDLE),
            self.guest_arch,
        )?;
        write_guest_pointer(
            memory,
            process_parameters_ptr + 0x1c,
            u64::from(STD_OUTPUT_HANDLE),
            self.guest_arch,
        )?;
        write_guest_pointer(
            memory,
            process_parameters_ptr + 0x20,
            u64::from(STD_ERROR_HANDLE),
            self.guest_arch,
        )?;
        self.write_guest_unicode_string(
            memory,
            process_parameters_ptr + 0x24,
            current_directory_ptr,
            &current_directory,
        )?;
        self.write_guest_unicode_string(
            memory,
            process_parameters_ptr + 0x30,
            dll_path_ptr,
            dll_path,
        )?;
        self.write_guest_unicode_string(
            memory,
            process_parameters_ptr + 0x38,
            image_path_ptr,
            image_path,
        )?;
        self.write_guest_unicode_string(
            memory,
            process_parameters_ptr + 0x40,
            self.command_line_wide_ptr,
            &command_line,
        )?;
        write_guest_pointer(
            memory,
            process_parameters_ptr + 0x48,
            environment_ptr,
            self.guest_arch,
        )?;
        write_guest_pointer(
            memory,
            self.peb_base + 0x10,
            process_parameters_ptr,
            self.guest_arch,
        )?;
        self.process_parameters_ptr = process_parameters_ptr;
        Ok(())
    }
}
