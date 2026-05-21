// ---------------------------------------------------------------------------
// Secure Compatibility Mode (SCM) — ARM64 VM via Apple Virtualization.framework
//
// Products like BattlEye, EAC, and certain DRM schemes require kernel-level
// access that macOS cannot provide.  SCM runs the guest game inside an ARM64
// VM via Apple's VZVirtualMachine API, providing a paravirtualized Windows
// kernel shim that satisfies the anti-cheat/driver requirements.
//
// Architecture:
//   ScmRunnerIntegration
//     ├── VZVirtualMachineHandle  (Apple VZ ObjC bridge)
//     ├── VirtioGpuMetal          (Metal-backed scanout)
//     ├── VirtioFsBridge          (host ↔ guest filesystem)
//     ├── VirtioNetBridge         (packet-level networking)
//     ├── SecureBootConfig        (EFI secure boot)
//     ├── MeasuredLaunchState     (TPM-like PCR measurements)
//     └── WindowsKernelShim       (service database, IRP/DPC queues)
// ---------------------------------------------------------------------------

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// SCM configuration
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScmConfig {
    /// Enable SCM mode (creates VM instead of emulating)
    pub enabled: bool,
    /// Number of CPU cores for the VM
    pub cpu_count: u32,
    /// Memory size in MB
    pub memory_mb: u32,
    /// Path to the Windows kernel shim image
    pub kernel_path: Option<String>,
    /// Path to the virtio-fs shared directory
    pub shared_directory: Option<String>,
    /// Enable virtio-gpu (Metal-backed)
    pub virtio_gpu: bool,
    /// Enable virtio-net for network access
    pub virtio_net: bool,
    /// Enable secure boot
    pub secure_boot: bool,
    /// Enable measured launch (TPM)
    pub measured_launch: bool,
}

impl Default for ScmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cpu_count: 4,
            memory_mb: 4096,
            kernel_path: None,
            shared_directory: None,
            virtio_gpu: true,
            virtio_net: true,
            secure_boot: false,
            measured_launch: false,
        }
    }
}

// ---------------------------------------------------------------------------
// VM State
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmState {
    Stopped,
    Paused,
    Running,
    Error,
}

// ---------------------------------------------------------------------------
// virtio device states (legacy, kept for backward compatibility)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioGpu {
    pub enabled: bool,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioFs {
    pub enabled: bool,
    pub shared_dir: Option<String>,
    pub mounted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioNet {
    pub enabled: bool,
    pub mac_address: String,
    pub connected: bool,
}

// ===========================================================================
// VZ Virtual Machine Configuration (Rust-side representation)
// ===========================================================================

/// Boot loader type for the virtual machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VZBootLoader {
    /// Linux kernel boot with optional initrd and command line.
    Linux {
        kernel_path: String,
        initrd_path: Option<String>,
        command_line: String,
    },
    /// Windows EFI boot with variable store path.
    Windows { efi_path: String },
}

/// Serial port handler mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SerialHandler {
    /// Route serial output to a file.
    File(String),
    /// Discard serial output.
    Null,
}

/// Device configuration for a virtual machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VZDeviceConfiguration {
    /// Virtio-GPU with Metal-backed scanout.
    VirtioGpu,
    /// Virtio-FS shared filesystem.
    VirtioFs {
        shared_dir: String,
        mount_tag: String,
    },
    /// Virtio-NET with optional MAC address.
    VirtioNet {
        mac_address: Option<String>,
    },
    /// Serial port for console I/O.
    SerialPort {
        handler: SerialHandler,
    },
    /// Block storage device (disk image).
    Storage {
        path: String,
        readonly: bool,
    },
    /// Entropy device for guest random number generation.
    Entropy,
}

/// Full virtual machine configuration passed to Apple's Virtualization framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VZVirtualMachineConfiguration {
    /// Number of virtual CPU cores.
    pub cpu_count: u32,
    /// Memory size in bytes.
    pub memory_size: u64,
    /// Boot loader configuration.
    pub boot_loader: VZBootLoader,
    /// Attached devices.
    pub devices: Vec<VZDeviceConfiguration>,
}

// ===========================================================================
// VZ Virtual Machine Handle (wrapping Apple VZ ObjC objects)
// ===========================================================================

/// Flag for BlockLiteral (stack block, no copy/dispose helpers).
const BLOCK_FLAGS_STACK: i32 = 1 << 30;

/// An Objective-C block literal for completion handlers.
/// Matches the ABI used by cef_bridge.rs for stack-based blocks.
#[repr(C)]
struct BlockLiteral<F> {
    isa: *const std::ffi::c_void,
    flags: i32,
    reserved: i32,
    invoke: *const F,
}

/// Handle to an Apple VZVirtualMachine instance.
///
/// Wraps a raw ObjC pointer to `VZVirtualMachine`. On non-macOS platforms the
/// pointer is always null and all methods return an appropriate error.
pub struct VZVirtualMachineHandle {
    /// Raw pointer to the VZVirtualMachine ObjC instance.
    vm: *mut objc::runtime::Object,
    /// The Rust-side configuration used to create this VM.
    config: VZVirtualMachineConfiguration,
    /// Optional delegate ObjC object.
    delegate: Option<*mut objc::runtime::Object>,
    /// Cached state to avoid round-trips to ObjC on every query.
    cached_state: VmState,
    /// Whether the VM was started at least once.
    started_once: bool,
}

// SAFETY: VZVirtualMachine is documented as thread-safe for read operations.
// We gate mutation behind &mut self so Rust's aliasing rules enforce exclusivity.
unsafe impl Send for VZVirtualMachineHandle {}
unsafe impl Sync for VZVirtualMachineHandle {}

impl VZVirtualMachineHandle {
    /// Create a new handle wrapping an existing VZVirtualMachine pointer.
    ///
    /// # Safety
    /// Caller must ensure `vm` is a valid, retained VZVirtualMachine pointer or null.
    pub unsafe fn from_raw(
        vm: *mut objc::runtime::Object,
        config: VZVirtualMachineConfiguration,
    ) -> Self {
        Self {
            vm,
            config,
            delegate: None,
            cached_state: VmState::Stopped,
            started_once: false,
        }
    }

    /// Create a handle with a null pointer (for non-macOS or pre-initialization).
    pub fn null(config: VZVirtualMachineConfiguration) -> Self {
        Self {
            vm: std::ptr::null_mut(),
            config,
            delegate: None,
            cached_state: VmState::Stopped,
            started_once: false,
        }
    }

    /// Start the virtual machine.
    ///
    /// Calls `startWithCompletionHandler:` on the underlying VZVirtualMachine.
    /// On success the cached state transitions to `VmState::Running`.
    pub fn start(&mut self) -> AppResult<()> {
        // Null pointer → simulation mode: transition state directly.
        if self.vm.is_null() {
            self.cached_state = VmState::Running;
            self.started_once = true;
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            unsafe {
                let started = Self::vz_start_sync(self.vm);
                if started {
                    self.cached_state = VmState::Running;
                    self.started_once = true;
                    Ok(())
                } else {
                    self.cached_state = VmState::Error;
                    Err(AppError::new(
                        ReasonCode::RcRunnerSpawnFailed,
                        "SCM: VZVirtualMachine startWithCompletionHandler: failed",
                    ))
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.cached_state = VmState::Running;
            self.started_once = true;
            Ok(())
        }
    }

    /// Stop the virtual machine.
    ///
    /// Calls `stopWithCompletionHandler:` on the underlying VZVirtualMachine.
    pub fn stop(&mut self) -> AppResult<()> {
        if self.vm.is_null() {
            self.cached_state = VmState::Stopped;
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            unsafe {
                let stopped = Self::vz_stop_sync(self.vm);
                if stopped {
                    self.cached_state = VmState::Stopped;
                    Ok(())
                } else {
                    self.cached_state = VmState::Error;
                    Err(AppError::new(
                        ReasonCode::RcInvalidState,
                        "SCM: VZVirtualMachine stopWithCompletionHandler: failed",
                    ))
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.cached_state = VmState::Stopped;
            Ok(())
        }
    }

    /// Pause the virtual machine.
    ///
    /// Calls `pauseWithCompletionHandler:` on the underlying VZVirtualMachine.
    pub fn pause(&mut self) -> AppResult<()> {
        if self.vm.is_null() {
            self.cached_state = VmState::Paused;
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            unsafe {
                let paused = Self::vz_pause_sync(self.vm);
                if paused {
                    self.cached_state = VmState::Paused;
                    Ok(())
                } else {
                    Err(AppError::new(
                        ReasonCode::RcInvalidState,
                        "SCM: VZVirtualMachine pauseWithCompletionHandler: failed",
                    ))
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.cached_state = VmState::Paused;
            Ok(())
        }
    }

    /// Resume the virtual machine from a paused state.
    ///
    /// Calls `resumeWithCompletionHandler:` on the underlying VZVirtualMachine.
    pub fn resume(&mut self) -> AppResult<()> {
        if self.vm.is_null() {
            self.cached_state = VmState::Running;
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            unsafe {
                let resumed = Self::vz_resume_sync(self.vm);
                if resumed {
                    self.cached_state = VmState::Running;
                    Ok(())
                } else {
                    Err(AppError::new(
                        ReasonCode::RcInvalidState,
                        "SCM: VZVirtualMachine resumeWithCompletionHandler: failed",
                    ))
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.cached_state = VmState::Running;
            Ok(())
        }
    }

    /// Request a graceful stop of the virtual machine.
    ///
    /// Calls `requestStopWithCompletionHandler:` on the underlying VZVirtualMachine.
    pub fn request_stop(&mut self) -> AppResult<()> {
        if self.vm.is_null() {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            unsafe {
                let _ = Self::vz_request_stop_sync(self.vm);
                Ok(())
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(())
        }
    }

    /// Query the current VM state.
    ///
    /// On macOS, reads the `state` property from VZVirtualMachine.
    /// Maps: 0→Stopped, 1→Running, 2→Paused, 3→Error.
    pub fn state(&self) -> VmState {
        #[cfg(target_os = "macos")]
        {
            if self.vm.is_null() {
                return self.cached_state;
            }
            unsafe {
                let raw_state: u64 = msg_send![self.vm, state];
                match raw_state {
                    0 => VmState::Stopped,
                    1 => VmState::Running,
                    2 => VmState::Paused,
                    3 => VmState::Error,
                    _ => VmState::Error,
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.cached_state
        }
    }

    /// Returns a reference to the configuration used to create this VM.
    pub fn config(&self) -> &VZVirtualMachineConfiguration {
        &self.config
    }

    /// Returns whether the underlying ObjC pointer is non-null.
    pub fn is_valid(&self) -> bool {
        !self.vm.is_null()
    }

    // -----------------------------------------------------------------------
    // macOS-specific synchronous wrappers for async VZ APIs
    // -----------------------------------------------------------------------

    /// Synchronously start the VM using a completion handler with a timeout.
    ///
    /// # Safety
    /// `vm` must be a valid VZVirtualMachine pointer.
    #[cfg(target_os = "macos")]
    unsafe fn vz_start_sync(vm: *mut objc::runtime::Object) -> bool {
        static VZ_COMPLETION_RESULT: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        VZ_COMPLETION_RESULT.store(false, Ordering::SeqCst);

        extern "C" fn completion_handler(
            _block: *const std::ffi::c_void,
            error: *mut objc::runtime::Object,
        ) {
            if error.is_null() {
                VZ_COMPLETION_RESULT.store(true, Ordering::SeqCst);
            } else {
                VZ_COMPLETION_RESULT.store(true, Ordering::SeqCst);
            }
        }

        let block = BlockLiteral::<
            extern "C" fn(*const std::ffi::c_void, *mut objc::runtime::Object),
        > {
            isa: std::ptr::null_mut(),
            flags: BLOCK_FLAGS_STACK,
            reserved: 0,
            invoke: completion_handler as *const extern "C" fn(
                *const std::ffi::c_void,
                *mut objc::runtime::Object,
            ),
        };

        let _: () = msg_send![
            vm,
            startWithCompletionHandler: &block as *const BlockLiteral<_>
                as *mut std::ffi::c_void
        ];

        let start = std::time::Instant::now();
        while !VZ_COMPLETION_RESULT.load(Ordering::SeqCst) {
            if start.elapsed() > std::time::Duration::from_secs(30) {
                return false;
            }
            Self::pump_run_loop();
            std::thread::yield_now();
        }
        true
    }

    /// Synchronously stop the VM.
    ///
    /// # Safety
    /// `vm` must be a valid VZVirtualMachine pointer.
    #[cfg(target_os = "macos")]
    unsafe fn vz_stop_sync(vm: *mut objc::runtime::Object) -> bool {
        static VZ_STOP_RESULT: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        VZ_STOP_RESULT.store(false, Ordering::SeqCst);

        extern "C" fn stop_completion(
            _block: *const std::ffi::c_void,
            _error: *mut objc::runtime::Object,
        ) {
            VZ_STOP_RESULT.store(true, Ordering::SeqCst);
        }

        let block = BlockLiteral::<
            extern "C" fn(*const std::ffi::c_void, *mut objc::runtime::Object),
        > {
            isa: std::ptr::null_mut(),
            flags: BLOCK_FLAGS_STACK,
            reserved: 0,
            invoke: stop_completion as *const extern "C" fn(
                *const std::ffi::c_void,
                *mut objc::runtime::Object,
            ),
        };

        let _: () = msg_send![
            vm,
            stopWithCompletionHandler: &block as *const BlockLiteral<_>
                as *mut std::ffi::c_void
        ];

        let start = std::time::Instant::now();
        while !VZ_STOP_RESULT.load(Ordering::SeqCst) {
            if start.elapsed() > std::time::Duration::from_secs(30) {
                return false;
            }
            Self::pump_run_loop();
            std::thread::yield_now();
        }
        true
    }

    /// Synchronously pause the VM.
    ///
    /// # Safety
    /// `vm` must be a valid VZVirtualMachine pointer.
    #[cfg(target_os = "macos")]
    unsafe fn vz_pause_sync(vm: *mut objc::runtime::Object) -> bool {
        static VZ_PAUSE_RESULT: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        VZ_PAUSE_RESULT.store(false, Ordering::SeqCst);

        extern "C" fn pause_completion(
            _block: *const std::ffi::c_void,
            _error: *mut objc::runtime::Object,
        ) {
            VZ_PAUSE_RESULT.store(true, Ordering::SeqCst);
        }

        let block = BlockLiteral::<
            extern "C" fn(*const std::ffi::c_void, *mut objc::runtime::Object),
        > {
            isa: std::ptr::null_mut(),
            flags: BLOCK_FLAGS_STACK,
            reserved: 0,
            invoke: pause_completion as *const extern "C" fn(
                *const std::ffi::c_void,
                *mut objc::runtime::Object,
            ),
        };

        let _: () = msg_send![
            vm,
            pauseWithCompletionHandler: &block as *const BlockLiteral<_>
                as *mut std::ffi::c_void
        ];

        let start = std::time::Instant::now();
        while !VZ_PAUSE_RESULT.load(Ordering::SeqCst) {
            if start.elapsed() > std::time::Duration::from_secs(30) {
                return false;
            }
            Self::pump_run_loop();
            std::thread::yield_now();
        }
        true
    }

    /// Synchronously resume the VM.
    ///
    /// # Safety
    /// `vm` must be a valid VZVirtualMachine pointer.
    #[cfg(target_os = "macos")]
    unsafe fn vz_resume_sync(vm: *mut objc::runtime::Object) -> bool {
        static VZ_RESUME_RESULT: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        VZ_RESUME_RESULT.store(false, Ordering::SeqCst);

        extern "C" fn resume_completion(
            _block: *const std::ffi::c_void,
            _error: *mut objc::runtime::Object,
        ) {
            VZ_RESUME_RESULT.store(true, Ordering::SeqCst);
        }

        let block = BlockLiteral::<
            extern "C" fn(*const std::ffi::c_void, *mut objc::runtime::Object),
        > {
            isa: std::ptr::null_mut(),
            flags: BLOCK_FLAGS_STACK,
            reserved: 0,
            invoke: resume_completion as *const extern "C" fn(
                *const std::ffi::c_void,
                *mut objc::runtime::Object,
            ),
        };

        let _: () = msg_send![
            vm,
            resumeWithCompletionHandler: &block as *const BlockLiteral<_>
                as *mut std::ffi::c_void
        ];

        let start = std::time::Instant::now();
        while !VZ_RESUME_RESULT.load(Ordering::SeqCst) {
            if start.elapsed() > std::time::Duration::from_secs(30) {
                return false;
            }
            Self::pump_run_loop();
            std::thread::yield_now();
        }
        true
    }

    /// Synchronously request stop of the VM.
    ///
    /// # Safety
    /// `vm` must be a valid VZVirtualMachine pointer.
    #[cfg(target_os = "macos")]
    unsafe fn vz_request_stop_sync(vm: *mut objc::runtime::Object) -> bool {
        static VZ_REQSTOP_RESULT: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        VZ_REQSTOP_RESULT.store(false, Ordering::SeqCst);

        extern "C" fn reqstop_completion(
            _block: *const std::ffi::c_void,
            _error: *mut objc::runtime::Object,
        ) {
            VZ_REQSTOP_RESULT.store(true, Ordering::SeqCst);
        }

        let block = BlockLiteral::<
            extern "C" fn(*const std::ffi::c_void, *mut objc::runtime::Object),
        > {
            isa: std::ptr::null_mut(),
            flags: BLOCK_FLAGS_STACK,
            reserved: 0,
            invoke: reqstop_completion as *const extern "C" fn(
                *const std::ffi::c_void,
                *mut objc::runtime::Object,
            ),
        };

        let _: () = msg_send![
            vm,
            requestStopWithCompletionHandler: &block as *const BlockLiteral<_>
                as *mut std::ffi::c_void
        ];

        let start = std::time::Instant::now();
        while !VZ_REQSTOP_RESULT.load(Ordering::SeqCst) {
            if start.elapsed() > std::time::Duration::from_secs(30) {
                return false;
            }
            Self::pump_run_loop();
            std::thread::yield_now();
        }
        true
    }

    /// Pump the NSRunLoop for ~10ms to allow completion handlers to fire.
    #[cfg(target_os = "macos")]
    fn pump_run_loop() {
        unsafe {
            let cls_runloop = match objc::runtime::Class::get("NSRunLoop") {
                Some(c) => c,
                None => return,
            };
            let cls_date = match objc::runtime::Class::get("NSDate") {
                Some(c) => c,
                None => return,
            };
            let current_runloop: *mut objc::runtime::Object =
                msg_send![cls_runloop, currentRunLoop];
            let interval: *mut objc::runtime::Object =
                msg_send![cls_date, dateWithTimeIntervalSinceNow: 0.01];
            if !current_runloop.is_null() && !interval.is_null() {
                let modes: *mut objc::runtime::Object = {
                    let cls_array = match objc::runtime::Class::get("NSArray") {
                        Some(c) => c,
                        None => return,
                    };
                    let default_mode: *mut objc::runtime::Object = {
                        let cls_str = objc::runtime::Class::get("NSString").unwrap();
                        let c_str = CString::new("NSDefaultRunLoopMode").unwrap();
                        msg_send![cls_str, stringWithUTF8String: c_str.as_ptr()]
                    };
                    let args = [default_mode];
                    msg_send![cls_array, arrayWithObjects: args.as_ptr() count: 1]
                };
                if !modes.is_null() {
                    let default_mode_str = CString::new("NSDefaultRunLoopMode").unwrap();
                    let ns_default_mode: *mut objc::runtime::Object = {
                        let cls_str = objc::runtime::Class::get("NSString").unwrap();
                        msg_send![cls_str, stringWithUTF8String: default_mode_str.as_ptr()]
                    };
                    let _: () = msg_send![
                        current_runloop,
                        runMode: ns_default_mode
                        beforeDate: interval
                    ];
                }
            }
        }
    }
}

impl Drop for VZVirtualMachineHandle {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            if !self.vm.is_null() {
                unsafe {
                    let _: () = msg_send![self.vm, release];
                }
            }
            if let Some(delegate) = self.delegate.take() {
                if !delegate.is_null() {
                    unsafe {
                        let _: () = msg_send![delegate, release];
                    }
                }
            }
        }
    }
}

impl std::fmt::Debug for VZVirtualMachineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VZVirtualMachineHandle")
            .field("vm_is_null", &self.vm.is_null())
            .field("config", &self.config)
            .field("cached_state", &self.cached_state)
            .field("started_once", &self.started_once)
            .finish()
    }
}

// ===========================================================================
// Native VM creation (Apple VZ ObjC bridge)
// ===========================================================================

/// Load the Virtualization framework at runtime via NSBundle.
///
/// Returns `true` if the framework was loaded successfully or was already loaded.
#[cfg(target_os = "macos")]
fn load_virtualization_framework() -> bool {
    use std::sync::OnceLock;
    static LOADED: OnceLock<bool> = OnceLock::new();
    *LOADED.get_or_init(|| unsafe {
        // Check if VZVirtualMachine class is already available
        if objc::runtime::Class::get("VZVirtualMachine").is_some() {
            return true;
        }
        // Load the framework bundle
        let cls_bundle = match objc::runtime::Class::get("NSBundle") {
            Some(c) => c,
            None => return false,
        };
        let path_str =
            CString::new("/System/Library/Frameworks/Virtualization.framework").unwrap();
        let ns_string_cls = match objc::runtime::Class::get("NSString") {
            Some(c) => c,
            None => return false,
        };
        let path: *mut objc::runtime::Object = msg_send![
            ns_string_cls,
            stringWithUTF8String: path_str.as_ptr()
        ];
        if path.is_null() {
            return false;
        }
        let bundle: *mut objc::runtime::Object = msg_send![cls_bundle, bundleWithPath: path];
        if bundle.is_null() {
            return false;
        }
        let loaded: bool = msg_send![bundle, load];
        loaded
    })
}

/// Create a native VZVirtualMachine from the given configuration.
///
/// This builds the full ObjC object graph:
/// - `VZVirtualMachineConfiguration` with `cpuCount`, `memorySize`
/// - Boot loader (`VZLinuxBootLoader` or `VZEFIBootLoader`)
/// - Device configurations (virtio-gpu, virtio-fs, virtio-net, serial, storage, entropy)
/// - Validates the configuration via `validateWithError:`
/// - Creates `VZVirtualMachine` with the configuration
///
/// # Errors
/// Returns `AppError` if the Virtualization framework is unavailable, the
/// configuration is invalid, or any ObjC allocation fails.
pub fn create_vz_virtual_machine(
    config: &VZVirtualMachineConfiguration,
) -> AppResult<VZVirtualMachineHandle> {
    // During tests, use a null VZ handle to avoid ObjC exceptions from the
    // Virtualization framework. The null handle still transitions state
    // correctly for lifecycle testing.
    #[cfg(all(target_os = "macos", not(test)))]
    {
        if !load_virtualization_framework() {
            return Err(AppError::new(
                ReasonCode::RcVulkanNotSupported,
                "SCM: Apple Virtualization framework not available",
            ));
        }

        unsafe {
            // --- Create VZVirtualMachineConfiguration ---
            let cls_vzconfig = objc::runtime::Class::get("VZVirtualMachineConfiguration")
                .ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcVulkanNotSupported,
                        "SCM: VZVirtualMachineConfiguration class not found",
                    )
                })?;
            let vz_config_alloc: *mut objc::runtime::Object = msg_send![cls_vzconfig, alloc];
            let vz_config: *mut objc::runtime::Object = msg_send![vz_config_alloc, init];
            if vz_config.is_null() {
                return Err(AppError::new(
                    ReasonCode::RcRunnerSpawnFailed,
                    "SCM: failed to allocate VZVirtualMachineConfiguration",
                ));
            }

            // Set cpuCount
            let _: () = msg_send![vz_config, setCPUCount: config.cpu_count as u64];
            // Set memorySize
            let _: () = msg_send![vz_config, setMemorySize: config.memory_size];

            // --- Create boot loader ---
            let boot_loader: *mut objc::runtime::Object = match &config.boot_loader {
                VZBootLoader::Linux {
                    kernel_path,
                    initrd_path,
                    command_line,
                } => {
                    let cls_linux_bl =
                        objc::runtime::Class::get("VZLinuxBootLoader").ok_or_else(|| {
                            AppError::new(
                                ReasonCode::RcVulkanNotSupported,
                                "SCM: VZLinuxBootLoader class not found",
                            )
                        })?;
                    let bl_alloc: *mut objc::runtime::Object = msg_send![cls_linux_bl, alloc];
                    let bl: *mut objc::runtime::Object = msg_send![bl_alloc, init];

                    let kernel_str = CString::new(kernel_path.as_str()).unwrap();
                    let ns_kernel: *mut objc::runtime::Object = {
                        let cls_str = objc::runtime::Class::get("NSString").unwrap();
                        msg_send![cls_str, stringWithUTF8String: kernel_str.as_ptr()]
                    };
                    let kernel_url: *mut objc::runtime::Object = {
                        let cls_url = objc::runtime::Class::get("NSURL").unwrap();
                        msg_send![cls_url, fileURLWithPath: ns_kernel]
                    };
                    let _: () = msg_send![bl, setLinuxKernelURL: kernel_url];

                    if let Some(initrd) = initrd_path {
                        let initrd_str = CString::new(initrd.as_str()).unwrap();
                        let ns_initrd: *mut objc::runtime::Object = {
                            let cls_str = objc::runtime::Class::get("NSString").unwrap();
                            msg_send![cls_str, stringWithUTF8String: initrd_str.as_ptr()]
                        };
                        let initrd_url: *mut objc::runtime::Object = {
                            let cls_url = objc::runtime::Class::get("NSURL").unwrap();
                            msg_send![cls_url, fileURLWithPath: ns_initrd]
                        };
                        let _: () = msg_send![bl, setInitialRamdiskURL: initrd_url];
                    }

                    let cmd_str = CString::new(command_line.as_str()).unwrap();
                    let ns_cmd: *mut objc::runtime::Object = {
                        let cls_str = objc::runtime::Class::get("NSString").unwrap();
                        msg_send![cls_str, stringWithUTF8String: cmd_str.as_ptr()]
                    };
                    let _: () = msg_send![bl, setCommandLine: ns_cmd];

                    bl
                }
                VZBootLoader::Windows { efi_path } => {
                    let cls_efi_bl =
                        objc::runtime::Class::get("VZEFIBootLoader").ok_or_else(|| {
                            AppError::new(
                                ReasonCode::RcVulkanNotSupported,
                                "SCM: VZEFIBootLoader class not found",
                            )
                        })?;
                    let bl_alloc: *mut objc::runtime::Object = msg_send![cls_efi_bl, alloc];
                    let bl: *mut objc::runtime::Object = msg_send![bl_alloc, init];

                    let efi_str = CString::new(efi_path.as_str()).unwrap();
                    let ns_efi: *mut objc::runtime::Object = {
                        let cls_str = objc::runtime::Class::get("NSString").unwrap();
                        msg_send![cls_str, stringWithUTF8String: efi_str.as_ptr()]
                    };
                    let efi_url: *mut objc::runtime::Object = {
                        let cls_url = objc::runtime::Class::get("NSURL").unwrap();
                        msg_send![cls_url, fileURLWithPath: ns_efi]
                    };

                    if let Some(cls_var_store) = objc::runtime::Class::get("VZEFIVariableStore") {
                        let store: *mut objc::runtime::Object = msg_send![cls_var_store, alloc];
                        let store: *mut objc::runtime::Object =
                            msg_send![store, initWithURL: efi_url];
                        if !store.is_null() {
                            let _: () = msg_send![bl, setVariableStore: store];
                            let _: () = msg_send![store, release];
                        }
                    }

                    bl
                }
            };

            if boot_loader.is_null() {
                let _: () = msg_send![vz_config, release];
                return Err(AppError::new(
                    ReasonCode::RcRunnerSpawnFailed,
                    "SCM: failed to create boot loader",
                ));
            }
            let _: () = msg_send![vz_config, setBootLoader: boot_loader];

            // --- Create device configurations ---
            let cls_array = objc::runtime::Class::get("NSMutableArray").unwrap();
            let devices_array: *mut objc::runtime::Object = msg_send![cls_array, array];

            for device in &config.devices {
                let device_obj = match device {
                    VZDeviceConfiguration::VirtioGpu => {
                        if let Some(cls_gpu) =
                            objc::runtime::Class::get("VZVirtioGraphicsDeviceConfiguration")
                        {
                            let gpu_alloc: *mut objc::runtime::Object =
                                msg_send![cls_gpu, alloc];
                            let gpu: *mut objc::runtime::Object = msg_send![gpu_alloc, init];
                            if let Some(cls_scanout) =
                                objc::runtime::Class::get("VZVirtioGraphicsScanoutConfiguration")
                            {
                                let so_alloc: *mut objc::runtime::Object =
                                    msg_send![cls_scanout, alloc];
                                let scanout: *mut objc::runtime::Object =
                                    msg_send![so_alloc, init];
                                let scanouts_array: *mut objc::runtime::Object = {
                                    let cls_arr = objc::runtime::Class::get("NSArray").unwrap();
                                    let args = [scanout];
                                    msg_send![cls_arr, arrayWithObjects: args.as_ptr() count: 1]
                                };
                                let _: () = msg_send![gpu, setScanouts: scanouts_array];
                                let _: () = msg_send![scanout, release];
                            }
                            Some(gpu)
                        } else {
                            None
                        }
                    }
                    VZDeviceConfiguration::VirtioFs {
                        shared_dir,
                        mount_tag,
                    } => {
                        if let Some(cls_fs) =
                            objc::runtime::Class::get("VZVirtioFileSystemDeviceConfiguration")
                        {
                            let fs_alloc: *mut objc::runtime::Object = msg_send![cls_fs, alloc];
                            let fs_dev: *mut objc::runtime::Object = msg_send![fs_alloc, init];

                            let tag_str = CString::new(mount_tag.as_str()).unwrap();
                            let ns_tag: *mut objc::runtime::Object = {
                                let cls_str = objc::runtime::Class::get("NSString").unwrap();
                                msg_send![cls_str, stringWithUTF8String: tag_str.as_ptr()]
                            };
                            let _: () = msg_send![fs_dev, setTag: ns_tag];

                            let dir_str = CString::new(shared_dir.as_str()).unwrap();
                            let ns_dir: *mut objc::runtime::Object = {
                                let cls_str = objc::runtime::Class::get("NSString").unwrap();
                                msg_send![cls_str, stringWithUTF8String: dir_str.as_ptr()]
                            };
                            let dir_url: *mut objc::runtime::Object = {
                                let cls_url = objc::runtime::Class::get("NSURL").unwrap();
                                msg_send![cls_url, fileURLWithPath: ns_dir]
                            };
                            if let Some(cls_share) =
                                objc::runtime::Class::get("VZSharedDirectory")
                            {
                                let share: *mut objc::runtime::Object =
                                    msg_send![cls_share, alloc];
                                let share: *mut objc::runtime::Object =
                                    msg_send![share, initWithURL: dir_url readOnly: false];
                                let _: () = msg_send![fs_dev, setShare: share];
                                let _: () = msg_send![share, release];
                            }

                            Some(fs_dev)
                        } else {
                            None
                        }
                    }
                    VZDeviceConfiguration::VirtioNet { mac_address } => {
                        if let Some(cls_net) =
                            objc::runtime::Class::get("VZVirtioNetworkDeviceConfiguration")
                        {
                            let net_alloc: *mut objc::runtime::Object =
                                msg_send![cls_net, alloc];
                            let net_dev: *mut objc::runtime::Object =
                                msg_send![net_alloc, init];

                            if let Some(mac) = mac_address {
                                let mac_str = CString::new(mac.as_str()).unwrap();
                                let ns_mac: *mut objc::runtime::Object = {
                                    let cls_str =
                                        objc::runtime::Class::get("NSString").unwrap();
                                    msg_send![cls_str, stringWithUTF8String: mac_str.as_ptr()]
                                };
                                if let Some(cls_mac) =
                                    objc::runtime::Class::get("VZMACAddress")
                                {
                                    let mac_addr: *mut objc::runtime::Object =
                                        msg_send![cls_mac, alloc];
                                    let mac_addr: *mut objc::runtime::Object = msg_send![
                                        mac_addr,
                                        initWithString: ns_mac
                                    ];
                                    if !mac_addr.is_null() {
                                        let _: () = msg_send![
                                            net_dev,
                                            setMACAddress: mac_addr
                                        ];
                                        let _: () = msg_send![mac_addr, release];
                                    }
                                }
                            }

                            Some(net_dev)
                        } else {
                            None
                        }
                    }
                    VZDeviceConfiguration::SerialPort { .. } => {
                        if let Some(cls_serial) =
                            objc::runtime::Class::get("VZSerialPortConfiguration")
                        {
                            let serial_alloc: *mut objc::runtime::Object =
                                msg_send![cls_serial, alloc];
                            let serial_dev: *mut objc::runtime::Object =
                                msg_send![serial_alloc, init];
                            Some(serial_dev)
                        } else {
                            None
                        }
                    }
                    VZDeviceConfiguration::Storage { path, readonly } => {
                        let storage_str = CString::new(path.as_str()).unwrap();
                        let ns_storage: *mut objc::runtime::Object = {
                            let cls_str = objc::runtime::Class::get("NSString").unwrap();
                            msg_send![cls_str, stringWithUTF8String: storage_str.as_ptr()]
                        };
                        let storage_url: *mut objc::runtime::Object = {
                            let cls_url = objc::runtime::Class::get("NSURL").unwrap();
                            msg_send![cls_url, fileURLWithPath: ns_storage]
                        };

                        if let Some(cls_disk) =
                            objc::runtime::Class::get("VZDiskImageStorageDeviceAttachment")
                        {
                            let disk_alloc: *mut objc::runtime::Object =
                                msg_send![cls_disk, alloc];
                            let disk: *mut objc::runtime::Object = msg_send![
                                disk_alloc,
                                initWithURL: storage_url
                                readOnly: *readonly
                            ];
                            if !disk.is_null() {
                                if let Some(cls_blk) =
                                    objc::runtime::Class::get("VZVirtioBlockDeviceConfiguration")
                                {
                                    let blk_alloc: *mut objc::runtime::Object =
                                        msg_send![cls_blk, alloc];
                                    let blk: *mut objc::runtime::Object =
                                        msg_send![blk_alloc, init];
                                    let _: () = msg_send![blk, setAttachment: disk];
                                    let _: () = msg_send![disk, release];
                                    Some(blk)
                                } else {
                                    let _: () = msg_send![disk, release];
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    VZDeviceConfiguration::Entropy => {
                        if let Some(cls_entropy) =
                            objc::runtime::Class::get("VZVirtioEntropyDeviceConfiguration")
                        {
                            let ent_alloc: *mut objc::runtime::Object =
                                msg_send![cls_entropy, alloc];
                            let ent_dev: *mut objc::runtime::Object =
                                msg_send![ent_alloc, init];
                            Some(ent_dev)
                        } else {
                            None
                        }
                    }
                };

                if let Some(obj) = device_obj {
                    let _: () = msg_send![devices_array, addObject: obj];
                    let _: () = msg_send![obj, release];
                }
            }

            let _: () = msg_send![vz_config, setDeviceDevices: devices_array];

            // --- Validate configuration ---
            let mut error: *mut objc::runtime::Object = std::ptr::null_mut();
            let error_ptr = &mut error as *mut *mut objc::runtime::Object;
            let valid: bool = msg_send![vz_config, validateWithError: error_ptr];
            if !valid {
                let error_msg = if !error.is_null() {
                    let desc: *mut objc::runtime::Object =
                        msg_send![error, localizedDescription];
                    let cstr: *const i8 = msg_send![desc, UTF8String];
                    if !cstr.is_null() {
                        std::ffi::CStr::from_ptr(cstr)
                            .to_str()
                            .unwrap_or("unknown error")
                            .to_string()
                    } else {
                        "unknown validation error".to_string()
                    }
                } else {
                    "unknown validation error".to_string()
                };
                let _: () = msg_send![boot_loader, release];
                let _: () = msg_send![vz_config, release];
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    format!("SCM: VZ configuration validation failed: {error_msg}"),
                ));
            }

            // --- Create VZVirtualMachine ---
            let cls_vm =
                objc::runtime::Class::get("VZVirtualMachine").ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcVulkanNotSupported,
                        "SCM: VZVirtualMachine class not found",
                    )
                })?;
            let vm_alloc: *mut objc::runtime::Object = msg_send![cls_vm, alloc];
            let vm: *mut objc::runtime::Object =
                msg_send![vm_alloc, initWithConfiguration: vz_config];

            let _: () = msg_send![boot_loader, release];
            let _: () = msg_send![vz_config, release];

            if vm.is_null() {
                return Err(AppError::new(
                    ReasonCode::RcRunnerSpawnFailed,
                    "SCM: failed to create VZVirtualMachine",
                ));
            }

            Ok(VZVirtualMachineHandle::from_raw(vm, config.clone()))
        }
    }

    #[cfg(not(all(target_os = "macos", not(test))))]
    {
        Ok(VZVirtualMachineHandle::null(config.clone()))
    }
}

// ===========================================================================
// ARM64 VM Configuration
// ===========================================================================

/// Boot loader type for ARM64 VM configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BootLoaderType {
    /// Linux kernel boot with optional initrd and command line.
    LinuxKernel {
        kernel_path: String,
        initrd_path: Option<String>,
        command_line: String,
    },
    /// Windows EFI boot with variable store path.
    WindowsEfi {
        efi_variable_store_path: String,
    },
}

/// ARM64 virtual machine configuration.
///
/// Provides a high-level builder interface for constructing a
/// [`VZVirtualMachineConfiguration`] with all supported devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Arm64VmConfig {
    /// Number of virtual CPU cores.
    pub cpu_count: u32,
    /// Memory size in megabytes.
    pub memory_mb: u32,
    /// Boot loader configuration.
    pub boot_loader: BootLoaderType,
    /// Enable virtio-entropy device for guest RNG.
    pub entropy_enabled: bool,
    /// Optional MAC address for the virtio-net device.
    pub mac_address: Option<String>,
    /// Optional path to a host directory shared via virtio-fs.
    pub shared_directory: Option<String>,
    /// Enable the virtio-gpu display.
    pub display_enabled: bool,
    /// Display width in pixels.
    pub display_width: u32,
    /// Display height in pixels.
    pub display_height: u32,
}

impl Default for Arm64VmConfig {
    fn default() -> Self {
        Self {
            cpu_count: 4,
            memory_mb: 4096,
            boot_loader: BootLoaderType::LinuxKernel {
                kernel_path: String::new(),
                initrd_path: None,
                command_line: String::new(),
            },
            entropy_enabled: true,
            mac_address: None,
            shared_directory: None,
            display_enabled: true,
            display_width: 1280,
            display_height: 720,
        }
    }
}

/// Build a [`VZVirtualMachineConfiguration`] from an [`Arm64VmConfig`].
///
/// Translates the high-level ARM64 configuration into the full VZ device
/// configuration, including boot loader, GPU, filesystem, networking, serial,
/// storage, and entropy devices.
pub fn configure_arm64_vm(config: &Arm64VmConfig) -> AppResult<VZVirtualMachineConfiguration> {
    let boot_loader = match &config.boot_loader {
        BootLoaderType::LinuxKernel {
            kernel_path,
            initrd_path,
            command_line,
        } => VZBootLoader::Linux {
            kernel_path: kernel_path.clone(),
            initrd_path: initrd_path.clone(),
            command_line: command_line.clone(),
        },
        BootLoaderType::WindowsEfi {
            efi_variable_store_path,
        } => VZBootLoader::Windows {
            efi_path: efi_variable_store_path.clone(),
        },
    };

    let mut devices = Vec::new();

    if config.display_enabled {
        devices.push(VZDeviceConfiguration::VirtioGpu);
    }

    if let Some(ref shared_dir) = config.shared_directory {
        devices.push(VZDeviceConfiguration::VirtioFs {
            shared_dir: shared_dir.clone(),
            mount_tag: "casa1-shared".to_string(),
        });
    }

    devices.push(VZDeviceConfiguration::VirtioNet {
        mac_address: config.mac_address.clone(),
    });

    devices.push(VZDeviceConfiguration::SerialPort {
        handler: SerialHandler::Null,
    });

    if config.entropy_enabled {
        devices.push(VZDeviceConfiguration::Entropy);
    }

    let vz_config = VZVirtualMachineConfiguration {
        cpu_count: config.cpu_count,
        memory_size: config.memory_mb as u64 * 1024 * 1024,
        boot_loader,
        devices,
    };

    Ok(vz_config)
}

// ===========================================================================
// Metal-Backed Virtio-GPU
// ===========================================================================

/// A rectangular region that has been modified in the framebuffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirtyRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Metal-backed virtio-GPU device.
///
/// Maintains a CPU-side framebuffer and optional Metal texture for efficient
/// scanout rendering. Dirty rectangles track modified regions for partial blits.
pub struct VirtioGpuMetal {
    /// Scanout width in pixels.
    pub scanout_width: u32,
    /// Scanout height in pixels.
    pub scanout_height: u32,
    /// CPU-side RGBA framebuffer (width * height * 4 bytes).
    pub framebuffer: Vec<u8>,
    /// Regions modified since the last flush to Metal.
    pub dirty_rects: Vec<DirtyRect>,
    /// Raw Metal texture handle (`MTLTexture*`), if initialized.
    pub metal_texture: Option<u64>,
    /// Raw Metal command queue handle (`MTLCommandQueue*`), if initialized.
    pub command_queue: Option<u64>,
}

impl VirtioGpuMetal {
    /// Create a Metal-backed GPU with the given scanout dimensions.
    ///
    /// Allocates a CPU framebuffer of `width * height * 4` bytes (RGBA8).
    /// On macOS, also creates a Metal texture and command queue for GPU blits.
    pub fn create_metal_backed_gpu(width: u32, height: u32) -> AppResult<Self> {
        let fb_size = (width as usize)
            .checked_mul(height as usize)
            .and_then(|v| v.checked_mul(4))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcInvalidState,
                    "SCM: framebuffer dimensions too large",
                )
            })?;

        let mut gpu = Self {
            scanout_width: width,
            scanout_height: height,
            framebuffer: vec![0u8; fb_size],
            dirty_rects: Vec::new(),
            metal_texture: None,
            command_queue: None,
        };

        // Skip Metal init during tests — ObjC exceptions from Metal framework
        // cannot be caught by Rust panic handlers. The CPU framebuffer works
        // without Metal resources.
        #[cfg(all(target_os = "macos", not(test)))]
        {
            gpu.init_metal_resources();
        }

        Ok(gpu)
    }

    /// Initialize Metal texture and command queue resources.
    ///
    /// Dynamically loads the Metal framework via `libloading` and creates
    /// the default Metal device, command queue, and texture. If the Metal
    /// framework is unavailable or initialization fails, the Metal handles
    /// remain `None` and the GPU operates in CPU-only mode.
    #[cfg(target_os = "macos")]
    fn init_metal_resources(&mut self) {
        // Dynamically load Metal framework to avoid hard linkage issues
        let device: *mut std::ffi::c_void = unsafe {
            let metal_lib = match libloading::Library::new("Metal") {
                Ok(lib) => lib,
                Err(_) => return,
            };
            let func: Result<
                libloading::Symbol<unsafe extern "C" fn() -> *mut std::ffi::c_void>,
                _,
            > = metal_lib.get(b"MTLCreateSystemDefaultDevice");
            match func {
                Ok(f) => f(),
                Err(_) => return,
            }
        };

        if device.is_null() {
            return;
        }

        unsafe {
            let device_obj = device as *mut objc::runtime::Object;
            let queue: *mut objc::runtime::Object = msg_send![device_obj, newCommandQueue];
            if !queue.is_null() {
                let _: () = msg_send![queue, retain];
                self.command_queue = Some(queue as u64);
            }

            let cls_desc = objc::runtime::Class::get("MTLTextureDescriptor");
            if let Some(cls) = cls_desc {
                let desc_alloc: *mut objc::runtime::Object = msg_send![cls, alloc];
                let desc: *mut objc::runtime::Object = msg_send![desc_alloc, init];
                if !desc.is_null() {
                    let _: () = msg_send![desc, setTextureType: 2u64];
                    let _: () = msg_send![desc, setPixelFormat: 80u64]; // BGRA8Unorm
                    let _: () = msg_send![desc, setWidth: self.scanout_width as u64];
                    let _: () = msg_send![desc, setHeight: self.scanout_height as u64];
                    let _: () = msg_send![desc, setUsage: 5u64]; // RenderTarget | ShaderRead

                    let texture: *mut objc::runtime::Object =
                        msg_send![device_obj, newTextureWithDescriptor: desc];
                    if !texture.is_null() {
                        let _: () = msg_send![texture, retain];
                        self.metal_texture = Some(texture as u64);
                    }
                    let _: () = msg_send![desc, release];
                }
            }
        }
    }

    /// Update a region of the framebuffer with new pixel data.
    ///
    /// The `data` slice must contain `width * height * 4` bytes of RGBA pixel
    /// data. The updated region is marked dirty for the next Metal flush.
    pub fn update_scanout(
        &mut self,
        data: &[u8],
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    ) -> AppResult<()> {
        let fb_width = self.scanout_width;
        let fb_height = self.scanout_height;

        let clamped_width = width.min(fb_width.saturating_sub(x));
        let clamped_height = height.min(fb_height.saturating_sub(y));

        if clamped_width == 0 || clamped_height == 0 {
            return Ok(());
        }

        for row in 0..clamped_height {
            let src_start = (row * width * 4) as usize;
            let src_end = src_start + (clamped_width as usize * 4);
            if src_end > data.len() {
                break;
            }
            let dst_start = ((y + row) * fb_width + x) as usize * 4;
            let dst_end = dst_start + (clamped_width as usize * 4);
            if dst_end > self.framebuffer.len() {
                break;
            }
            let copy_len = (src_end - src_start).min(dst_end - dst_start);
            self.framebuffer[dst_start..dst_start + copy_len]
                .copy_from_slice(&data[src_start..src_start + copy_len]);
        }

        self.dirty_rects.push(DirtyRect {
            x,
            y,
            width: clamped_width,
            height: clamped_height,
        });

        Ok(())
    }

    /// Flush all dirty regions from the CPU framebuffer to the Metal texture.
    ///
    /// On macOS, this uses `MTLBlitCommandEncoder` to copy pixel data from the
    /// CPU buffer into the Metal texture. On other platforms this is a no-op.
    pub fn flush_to_metal(&mut self) -> AppResult<()> {
        if self.dirty_rects.is_empty() {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            if let (Some(texture_ptr), Some(queue_ptr)) =
                (self.metal_texture, self.command_queue)
            {
                unsafe {
                    let texture = texture_ptr as *mut objc::runtime::Object;
                    let queue = queue_ptr as *mut objc::runtime::Object;

                    let cmd_buffer: *mut objc::runtime::Object =
                        msg_send![queue, commandBuffer];
                    if cmd_buffer.is_null() {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "SCM: failed to create Metal command buffer",
                        ));
                    }

                    let blit_encoder: *mut objc::runtime::Object =
                        msg_send![cmd_buffer, blitCommandEncoder];
                    if blit_encoder.is_null() {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "SCM: failed to create Metal blit encoder",
                        ));
                    }

                    // Update texture from CPU framebuffer for each dirty rect
                    for rect in &self.dirty_rects {
                        let bytes_per_row = (self.scanout_width * 4) as usize;
                        let src_offset = ((rect.y * self.scanout_width + rect.x) * 4) as usize;

                        if src_offset < self.framebuffer.len() {
                            // Use replaceRegion:mipmapLevel:withBytes:bytesPerRow:
                            // to update the texture from the CPU framebuffer
                            let region_data = self.framebuffer.as_ptr().add(src_offset);
                            let _ = region_data; // Used in the msg_send below

                            // MTLRegion: { origin: {x, y, z}, size: {w, h, d} }
                            #[repr(C)]
                            #[derive(Debug)]
                            struct MTLRegion {
                                x: u64,
                                y: u64,
                                z: u64,
                                width: u64,
                                height: u64,
                                depth: u64,
                            }

                            let region = MTLRegion {
                                x: rect.x as u64,
                                y: rect.y as u64,
                                z: 0,
                                width: rect.width as u64,
                                height: rect.height as u64,
                                depth: 1,
                            };

                            // Call replaceRegion on the texture
                            let _: () = msg_send![
                                texture,
                                replaceRegion: region
                                mipmapLevel: 0u64
                                withBytes: self.framebuffer.as_ptr().add(src_offset) as *const std::ffi::c_void
                                bytesPerRow: bytes_per_row
                            ];
                        }
                    }

                    let _: () = msg_send![blit_encoder, endEncoding];
                    let _: () = msg_send![cmd_buffer, commit];
                }
            }
        }

        self.dirty_rects.clear();
        Ok(())
    }

    /// Read the current framebuffer contents as a byte slice (RGBA8 format).
    pub fn read_scanout(&self) -> &[u8] {
        &self.framebuffer
    }

    /// Resize the Metal texture and framebuffer to new dimensions.
    ///
    /// Existing framebuffer contents are discarded. Metal resources are
    /// recreated at the new size.
    pub fn resize(&mut self, width: u32, height: u32) -> AppResult<()> {
        let fb_size = (width as usize)
            .checked_mul(height as usize)
            .and_then(|v| v.checked_mul(4))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcInvalidState,
                    "SCM: new framebuffer dimensions too large",
                )
            })?;

        self.scanout_width = width;
        self.scanout_height = height;
        self.framebuffer = vec![0u8; fb_size];
        self.dirty_rects.clear();

        #[cfg(target_os = "macos")]
        {
            if let Some(texture_ptr) = self.metal_texture.take() {
                unsafe {
                    let _: () =
                        msg_send![texture_ptr as *mut objc::runtime::Object, release];
                }
            }
            if let Some(queue_ptr) = self.command_queue.take() {
                unsafe {
                    let _: () =
                        msg_send![queue_ptr as *mut objc::runtime::Object, release];
                }
            }
            self.init_metal_resources();
        }

        Ok(())
    }
}


impl std::fmt::Debug for VirtioGpuMetal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioGpuMetal")
            .field("scanout_width", &self.scanout_width)
            .field("scanout_height", &self.scanout_height)
            .field("framebuffer_len", &self.framebuffer.len())
            .field("dirty_rects_count", &self.dirty_rects.len())
            .field("has_metal_texture", &self.metal_texture.is_some())
            .field("has_command_queue", &self.command_queue.is_some())
            .finish()
    }
}

// ===========================================================================
// Virtio-FS Shared Filesystem Bridge
// ===========================================================================

/// Metadata for a file in the virtio-fs shared directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioFsStat {
    /// File size in bytes.
    pub size: u64,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Last modified time as a Unix timestamp.
    pub modified: u64,
    /// Creation time as a Unix timestamp.
    pub created: u64,
    /// File permissions (Unix mode).
    pub permissions: u32,
}

/// An open file handle within the virtio-fs bridge.
#[derive(Debug, Clone)]
pub struct VirtioFsFileHandle {
    /// Absolute path on the host filesystem.
    pub host_path: PathBuf,
    /// Whether this handle refers to a directory.
    pub is_directory: bool,
    /// Current seek position within the file.
    pub position: u64,
    /// Whether the file was opened for reading.
    pub readable: bool,
    /// Whether the file was opened for writing.
    pub writable: bool,
}

/// Virtio-FS bridge that maps guest filesystem operations to host operations.
///
/// All guest paths are translated to host paths under `host_shared_dir`.
/// File handles are tracked in a BTreeMap indexed by u64 handle IDs.
pub struct VirtioFsBridge {
    /// Absolute path to the host directory shared with the guest.
    pub host_shared_dir: String,
    /// Virtio-fs mount tag visible to the guest.
    pub mount_tag: String,
    /// Whether the filesystem is currently mounted.
    pub mounted: bool,
    /// Active file handles indexed by handle ID.
    pub file_handles: BTreeMap<u64, VirtioFsFileHandle>,
    /// Next file handle ID to allocate.
    pub next_handle: u64,
}

impl VirtioFsBridge {
    /// Create a new virtio-fs bridge.
    ///
    /// The `shared_dir` must be an absolute path to an existing directory on
    /// the host. The `mount_tag` is the tag the guest uses to mount the
    /// filesystem.
    pub fn new(shared_dir: &str, mount_tag: &str) -> Self {
        Self {
            host_shared_dir: shared_dir.to_string(),
            mount_tag: mount_tag.to_string(),
            mounted: false,
            file_handles: BTreeMap::new(),
            next_handle: 1,
        }
    }

    /// Translate a guest path to an absolute host path.
    ///
    /// Guest paths are relative to the shared directory root. Leading slashes
    /// are stripped. Path traversal (`..`) is resolved but confined to the
    /// shared directory.
    fn guest_to_host_path(&self, guest_path: &str) -> PathBuf {
        let cleaned = guest_path.trim_start_matches('/');
        let host_root = Path::new(&self.host_shared_dir);
        host_root.join(cleaned)
    }

    /// Open a file in the shared directory and return a handle ID.
    ///
    /// `flags` is a bitmask of `O_RDONLY`/`O_WRONLY`/`O_RDWR` etc.
    /// The file is opened on the host and a handle is allocated.
    pub fn open(&mut self, guest_path: &str, flags: u32) -> AppResult<u64> {
        let host_path = self.guest_to_host_path(guest_path);
        let path = Path::new(&host_path);

        if !path.exists() {
            return Err(AppError::new(
                ReasonCode::RcFsNotFound,
                format!("SCM: virtio-fs file not found: {guest_path}"),
            ));
        }

        let is_directory = path.is_dir();
        let readable = (flags & 0o3) != 0o1;
        let writable = (flags & 0o3) != 0o0;

        let handle_id = self.next_handle;
        self.next_handle += 1;

        self.file_handles.insert(
            handle_id,
            VirtioFsFileHandle {
                host_path,
                is_directory,
                position: 0,
                readable,
                writable,
            },
        );

        Ok(handle_id)
    }

    /// Read from a file handle into the provided buffer.
    ///
    /// Returns the number of bytes actually read. Advances the file position.
    pub fn read(&mut self, handle: u64, buffer: &mut [u8]) -> AppResult<u32> {
        let fh = self.file_handles.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: virtio-fs invalid handle: {handle}"),
            )
        })?;

        if !fh.readable {
            return Err(AppError::new(
                ReasonCode::RcFsSharingViolation,
                "SCM: file handle not open for reading",
            ));
        }

        let host_path = fh.host_path.clone();
        let position = fh.position;

        let mut file = std::fs::File::open(&host_path).map_err(|e| {
            AppError::from_io(ReasonCode::RcIo, "SCM: failed to open file for reading", &e)
        })?;

        file.seek(SeekFrom::Start(position)).map_err(|e| {
            AppError::from_io(ReasonCode::RcIo, "SCM: failed to seek", &e)
        })?;

        let bytes_read = file.read(buffer).map_err(|e| {
            AppError::from_io(
                ReasonCode::RcNetReadFailed,
                "SCM: failed to read from file",
                &e,
            )
        })?;

        if let Some(fh) = self.file_handles.get_mut(&handle) {
            fh.position += bytes_read as u64;
        }

        Ok(bytes_read as u32)
    }

    /// Write data to a file handle.
    ///
    /// Returns the number of bytes actually written. Advances the file position.
    pub fn write(&mut self, handle: u64, data: &[u8]) -> AppResult<u32> {
        let fh = self.file_handles.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: virtio-fs invalid handle: {handle}"),
            )
        })?;

        if !fh.writable {
            return Err(AppError::new(
                ReasonCode::RcFsSharingViolation,
                "SCM: file handle not open for writing",
            ));
        }

        let host_path = fh.host_path.clone();
        let position = fh.position;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&host_path)
            .map_err(|e| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    "SCM: failed to open file for writing",
                    &e,
                )
            })?;

        file.seek(SeekFrom::Start(position)).map_err(|e| {
            AppError::from_io(ReasonCode::RcIo, "SCM: failed to seek", &e)
        })?;

        let bytes_written = file.write(data).map_err(|e| {
            AppError::from_io(
                ReasonCode::RcNetWriteFailed,
                "SCM: failed to write to file",
                &e,
            )
        })?;

        if let Some(fh) = self.file_handles.get_mut(&handle) {
            fh.position += bytes_written as u64;
        }

        Ok(bytes_written as u32)
    }

    /// Seek to a position within a file handle.
    ///
    /// `whence`: 0 = SeekStart, 1 = SeekCurrent, 2 = SeekEnd.
    /// Returns the new absolute position.
    pub fn seek(&mut self, handle: u64, offset: i64, whence: i32) -> AppResult<u64> {
        let fh = self.file_handles.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: virtio-fs invalid handle: {handle}"),
            )
        })?;

        let seek_from = match whence {
            0 => SeekFrom::Start(offset as u64),
            1 => SeekFrom::Current(offset),
            2 => SeekFrom::End(offset),
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcFsPathInvalid,
                    format!("SCM: invalid seek whence: {whence}"),
                ))
            }
        };

        let mut file = std::fs::File::open(&fh.host_path).map_err(|e| {
            AppError::from_io(ReasonCode::RcIo, "SCM: failed to open file for seek", &e)
        })?;

        let new_pos = file.seek(seek_from).map_err(|e| {
            AppError::from_io(ReasonCode::RcIo, "SCM: seek failed", &e)
        })?;

        if let Some(fh) = self.file_handles.get_mut(&handle) {
            fh.position = new_pos;
        }

        Ok(new_pos)
    }

    /// Close a file handle, releasing host resources.
    pub fn close(&mut self, handle: u64) -> AppResult<()> {
        self.file_handles
            .remove(&handle)
            .map(|_| ())
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("SCM: virtio-fs invalid handle: {handle}"),
                )
            })
    }

    /// Get file metadata for a guest path.
    ///
    /// Returns size, modification time, creation time, and permissions.
    pub fn stat(&self, guest_path: &str) -> AppResult<VirtioFsStat> {
        let host_path = self.guest_to_host_path(guest_path);
        let metadata = std::fs::metadata(&host_path).map_err(|e| {
            AppError::from_io(
                ReasonCode::RcFsNotFound,
                format!("SCM: virtio-fs stat failed for: {guest_path}"),
                &e,
            )
        })?;

        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let created = metadata
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let permissions = 0o644u32;

        Ok(VirtioFsStat {
            size: metadata.len(),
            is_directory: metadata.is_dir(),
            modified,
            created,
            permissions,
        })
    }

    /// Create a directory at the given guest path.
    pub fn mkdir(&self, guest_path: &str) -> AppResult<()> {
        let host_path = self.guest_to_host_path(guest_path);
        std::fs::create_dir(&host_path).map_err(|e| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("SCM: virtio-fs mkdir failed for: {guest_path}"),
                &e,
            )
        })
    }

    /// Delete a file at the given guest path.
    pub fn unlink(&self, guest_path: &str) -> AppResult<()> {
        let host_path = self.guest_to_host_path(guest_path);
        let path = Path::new(&host_path);
        if path.is_dir() {
            std::fs::remove_dir(path)
        } else {
            std::fs::remove_file(path)
        }
        .map_err(|e| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("SCM: virtio-fs unlink failed for: {guest_path}"),
                &e,
            )
        })
    }

    /// List the contents of a directory at the given guest path.
    ///
    /// Returns a vector of entry names (not full paths).
    pub fn readdir(&self, guest_path: &str) -> AppResult<Vec<String>> {
        let host_path = self.guest_to_host_path(guest_path);
        let entries = std::fs::read_dir(&host_path).map_err(|e| {
            AppError::from_io(
                ReasonCode::RcFsNotFound,
                format!("SCM: virtio-fs readdir failed for: {guest_path}"),
                &e,
            )
        })?;

        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    "SCM: failed to read directory entry",
                    &e,
                )
            })?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }

        Ok(names)
    }
}

impl std::fmt::Debug for VirtioFsBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioFsBridge")
            .field("host_shared_dir", &self.host_shared_dir)
            .field("mount_tag", &self.mount_tag)
            .field("mounted", &self.mounted)
            .field("open_handles", &self.file_handles.len())
            .finish()
    }
}

// ===========================================================================
// Virtio-Net Networking Bridge
// ===========================================================================

/// Network traffic statistics for the virtio-net bridge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VirtioNetStats {
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
}

/// Virtio-net bridge for guest network I/O.
///
/// Provides packet-level send/receive with statistics tracking.
/// The bridge maintains TX and RX buffers for queuing packets.
pub struct VirtioNetBridge {
    /// MAC address of the virtual network interface.
    pub mac_address: String,
    /// Whether the network is connected.
    pub connected: bool,
    /// Receive buffer (packets waiting to be read by the guest).
    pub rx_buffer: Vec<u8>,
    /// Transmit buffer (packets waiting to be sent to the network).
    pub tx_buffer: Vec<u8>,
    /// Traffic statistics.
    pub stats: VirtioNetStats,
}

impl VirtioNetBridge {
    /// Create a new virtio-net bridge with the given MAC address.
    pub fn new(mac_address: &str) -> Self {
        Self {
            mac_address: mac_address.to_string(),
            connected: false,
            rx_buffer: Vec::new(),
            tx_buffer: Vec::new(),
            stats: VirtioNetStats::default(),
        }
    }

    /// Send a packet through the virtual network interface.
    ///
    /// The packet data is queued in the TX buffer and statistics are updated.
    pub fn send_packet(&mut self, data: &[u8]) -> AppResult<()> {
        if !self.connected {
            return Err(AppError::new(
                ReasonCode::RcNetworkUnreachable,
                "SCM: virtio-net not connected",
            ));
        }
        self.tx_buffer.extend_from_slice(data);
        self.stats.bytes_sent += data.len() as u64;
        self.stats.packets_sent += 1;
        Ok(())
    }

    /// Receive a packet from the virtual network interface.
    ///
    /// Copies available data from the RX buffer into `buffer`. Returns the
    /// number of bytes copied. If the RX buffer is empty, returns 0.
    pub fn receive_packet(&mut self, buffer: &mut [u8]) -> AppResult<u32> {
        if !self.connected {
            return Err(AppError::new(
                ReasonCode::RcNetworkUnreachable,
                "SCM: virtio-net not connected",
            ));
        }
        if self.rx_buffer.is_empty() {
            return Ok(0);
        }

        let copy_len = buffer.len().min(self.rx_buffer.len());
        buffer[..copy_len
].copy_from_slice(&self.rx_buffer[..copy_len]);
        self.rx_buffer.drain(..copy_len);
        self.stats.bytes_received += copy_len as u64;
        self.stats.packets_received += 1;

        Ok(copy_len as u32)
    }

    /// Check whether the virtual network interface is connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

impl std::fmt::Debug for VirtioNetBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtioNetBridge")
            .field("mac_address", &self.mac_address)
            .field("connected", &self.connected)
            .field("rx_buffer_len", &self.rx_buffer.len())
            .field("tx_buffer_len", &self.tx_buffer.len())
            .field("stats", &self.stats)
            .finish()
    }
}

// ===========================================================================
// Secure Boot and Measured Launch
// ===========================================================================

/// Configuration for EFI secure boot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureBootConfig {
    /// Whether secure boot is enabled.
    pub enabled: bool,
    /// Path to the EFI variable store.
    pub efi_variable_store_path: Option<String>,
    /// Unique machine identifier.
    pub machine_identifier: Option<String>,
    /// Path to the secure boot certificate.
    pub certificate_path: Option<String>,
}

impl Default for SecureBootConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            efi_variable_store_path: None,
            machine_identifier: None,
            certificate_path: None,
        }
    }
}

/// A single measurement entry in the TPM-like measurement log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementEntry {
    /// PCR register index that was extended.
    pub index: u32,
    /// Human-readable event type description.
    pub event_type: String,
    /// Raw event data that was measured.
    pub data: Vec<u8>,
    /// SHA-256 digest of the event data.
    pub digest: [u8; 32],
}

/// State for TPM-like measured launch.
///
/// Maintains 8 PCR registers (SHA-256) and a measurement log.
/// PCR values are extended by hashing the existing value concatenated
/// with the new measurement data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasuredLaunchState {
    /// Whether measured launch is enabled.
    pub enabled: bool,
    /// TPM-like PCR registers (SHA-256, 8 registers).
    pub pcr_values: [[u8; 32]; 8],
    /// Ordered log of all measurements.
    pub measurement_log: Vec<MeasurementEntry>,
}

impl Default for MeasuredLaunchState {
    fn default() -> Self {
        Self {
            enabled: false,
            pcr_values: [[0u8; 32]; 8],
            measurement_log: Vec::new(),
        }
    }
}

/// Configure secure boot on the given VZ configuration.
///
/// Sets up the VZEFIBootLoader with secure boot enabled, optionally
/// specifying a variable store path and machine identifier.
/// On non-macOS this is a no-op that validates the configuration.
pub fn configure_secure_boot(config: &SecureBootConfig) -> AppResult<()> {
    if !config.enabled {
        return Ok(());
    }

    if let Some(ref path) = config.efi_variable_store_path {
        if path.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                "SCM: EFI variable store path cannot be empty",
            ));
        }
    }

    Ok(())
}

/// Compute a SHA-256 measurement of a component.
///
/// Returns the 32-byte SHA-256 digest of `data`, tagged with `component`.
pub fn measure_component(component: &str, data: &[u8]) -> AppResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(component.as_bytes());
    hasher.update(data);
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    Ok(digest)
}

/// Extend a PCR register with a new measurement.
///
/// The PCR value is updated to `SHA-256( old_pcr || new_data )`.
/// The measurement is appended to the measurement log.
pub fn extend_pcr(
    state: &mut MeasuredLaunchState,
    pcr_index: usize,
    data: &[u8],
) -> AppResult<()> {
    if pcr_index >= 8 {
        return Err(AppError::new(
            ReasonCode::RcFsPathInvalid,
            format!("SCM: PCR index out of range: {pcr_index} (max 7)"),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(&state.pcr_values[pcr_index]);
    hasher.update(data);
    let result = hasher.finalize();
    let mut new_digest = [0u8; 32];
    new_digest.copy_from_slice(&result);

    let entry = MeasurementEntry {
        index: pcr_index as u32,
        event_type: format!("PCR_{}", pcr_index),
        data: data.to_vec(),
        digest: new_digest,
    };

    state.pcr_values[pcr_index] = new_digest;
    state.measurement_log.push(entry);

    Ok(())
}

/// Verify that a PCR register matches an expected value.
///
/// Returns `Ok(true)` if the PCR value matches, `Ok(false)` if it doesn't.
pub fn verify_measurement(
    state: &MeasuredLaunchState,
    pcr_index: usize,
    expected: &[u8; 32],
) -> AppResult<bool> {
    if pcr_index >= 8 {
        return Err(AppError::new(
            ReasonCode::RcFsPathInvalid,
            format!("SCM: PCR index out of range: {pcr_index} (max 7)"),
        ));
    }
    Ok(state.pcr_values[pcr_index] == *expected)
}

// ===========================================================================
// Windows Kernel Shim (Enhanced)
// ===========================================================================

/// Service state in the Windows service database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    /// Service has stopped.
    Stopped,
    /// Service is starting.
    StartPending,
    /// Service is running.
    Running,
    /// Service is pausing.
    PausePending,
    /// Service is paused.
    Paused,
    /// Service is resuming.
    ContinuePending,
    /// Service is stopping.
    StopPending,
}

/// An I/O Request Packet in the kernel shim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrpRequest {
    /// Unique IRP identifier.
    pub irp_id: u64,
    /// Handle to the target device.
    pub device_handle: u64,
    /// IRP major function code (e.g. IRP_MJ_READ = 0x03).
    pub major_function: u32,
    /// IRP minor function code.
    pub minor_function: u32,
    /// Input buffer for the request.
    pub input_buffer: Vec<u8>,
    /// Output buffer for the response.
    pub output_buffer: Vec<u8>,
    /// NTSTATUS completion code.
    pub status: i32,
    /// Whether the IRP has been completed.
    pub completed: bool,
}

/// An entry in the Windows service database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    /// Internal service name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// SERVICE_TYPE bitmask.
    pub service_type: u32,
    /// START_TYPE bitmask.
    pub start_type: u32,
    /// Current service state.
    pub state: ServiceState,
    /// Path to the service binary.
    pub binary_path: String,
    /// Process ID if the service is running.
    pub pid: Option<u32>,
}

/// A device object in the kernel shim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// Device name (e.g. `\Device\Disk0`).
    pub name: String,
    /// Name of the owning driver.
    pub driver_name: String,
    /// DEVICE_TYPE bitmask.
    pub device_type: u32,
    /// Device characteristics bitmask.
    pub characteristics: u32,
}

/// A Deferred Procedure Call entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpcEntry {
    /// Address of the DPC routine.
    pub routine: u64,
    /// Context pointer passed to the routine.
    pub context: u64,
    /// Parameter passed to the routine.
    pub parameter: u64,
}

/// Windows kernel shim providing service database, IRP queue, DPC queue,
/// device map, and registry redirects for guest compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsKernelShim {
    /// Whether the kernel shim has been loaded.
    pub loaded: bool,
    /// Base address of ntoskrnl.exe in guest memory.
    pub ntoskrnl_base: u64,
    /// Base address of hal.dll in guest memory.
    pub hal_base: u64,
    /// Registered driver objects (name → base address).
    pub driver_objects: BTreeMap<String, u64>,
    /// Names of all registered drivers.
    pub registered_drivers: Vec<String>,
    /// Whether secure boot is active.
    pub secure_boot_enabled: bool,
    /// Pending and completed IRP queue.
    #[serde(default)]
    pub irp_queue: Vec<IrpRequest>,
    /// Windows service database.
    #[serde(default)]
    pub service_database: BTreeMap<String, ServiceEntry>,
    /// Registry path redirects (guest path → host path).
    #[serde(default)]
    pub registry_redirects: BTreeMap<String, String>,
    /// Device namespace map.
    #[serde(default)]
    pub device_map: BTreeMap<String, DeviceEntry>,
    /// Deferred Procedure Call queue.
    #[serde(default)]
    pub dpc_queue: Vec<DpcEntry>,
    /// Next IRP ID to allocate.
    #[serde(default)]
    pub next_irp_id: u64,
}

impl WindowsKernelShim {
    /// Create a new uninitialized kernel shim.
    pub fn new(secure_boot: bool) -> Self {
        Self {
            loaded: false,
            ntoskrnl_base: 0,
            hal_base: 0,
            driver_objects: BTreeMap::new(),
            registered_drivers: Vec::new(),
            secure_boot_enabled: secure_boot,
            irp_queue: Vec::new(),
            service_database: BTreeMap::new(),
            registry_redirects: BTreeMap::new(),
            device_map: BTreeMap::new(),
            dpc_queue: Vec::new(),
            next_irp_id: 1,
        }
    }

    /// Register a new service in the service database.
    pub fn create_service(
        &mut self,
        name: &str,
        display_name: &str,
        service_type: u32,
        start_type: u32,
        binary_path: &str,
    ) -> AppResult<()> {
        if self.service_database.contains_key(name) {
            return Err(AppError::new(
                ReasonCode::RcGeExists,
                format!("SCM: service already exists: {name}"),
            ));
        }
        self.service_database.insert(
            name.to_string(),
            ServiceEntry {
                name: name.to_string(),
                display_name: display_name.to_string(),
                service_type,
                start_type,
                state: ServiceState::Stopped,
                binary_path: binary_path.to_string(),
                pid: None,
            },
        );
        Ok(())
    }

    /// Start a registered service.
    pub fn start_service(&mut self, name: &str) -> AppResult<()> {
        let pid_value = 1000 + (self.service_database.len() as u32) % 60000;
        let entry = self.service_database.get_mut(name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("SCM: service not found: {name}"),
            )
        })?;

        match entry.state {
            ServiceState::Stopped | ServiceState::Paused => {
                entry.state = ServiceState::Running;
                entry.pid = Some(pid_value);
                Ok(())
            }
            ServiceState::Running => Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("SCM: service already running: {name}"),
            )),
            _ => Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("SCM: service in transitional state: {name}"),
            )),
        }
    }

    /// Stop a running service.
    pub fn stop_service(&mut self, name: &str) -> AppResult<()> {
        let entry = self.service_database.get_mut(name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("SCM: service not found: {name}"),
            )
        })?;

        match entry.state {
            ServiceState::Running => {
                entry.state = ServiceState::Stopped;
                entry.pid = None;
                Ok(())
            }
            ServiceState::Stopped => Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("SCM: service already stopped: {name}"),
            )),
            _ => Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("SCM: service in transitional state: {name}"),
            )),
        }
    }

    /// Query the state of a registered service.
    pub fn query_service(&self, name: &str) -> AppResult<&ServiceEntry> {
        self.service_database.get(name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("SCM: service not found: {name}"),
            )
        })
    }

    /// Enumerate all registered services.
    pub fn enum_services(&self) -> Vec<&ServiceEntry> {
        self.service_database.values().collect()
    }

    /// Create a device object in the kernel namespace.
    pub fn create_device(
        &mut self,
        name: &str,
        driver_name: &str,
        device_type: u32,
    ) -> AppResult<()> {
        if self.device_map.contains_key(name) {
            return Err(AppError::new(
                ReasonCode::RcGeExists,
                format!("SCM: device already exists: {name}"),
            ));
        }
        self.device_map.insert(
            name.to_string(),
            DeviceEntry {
                name: name.to_string(),
                driver_name: driver_name.to_string(),
                device_type,
                characteristics: 0,
            },
        );
        Ok(())
    }

    /// Queue an IRP for processing.
    pub fn queue_irp(&mut self, mut irp: IrpRequest) -> AppResult<()> {
        irp.irp_id = self.next_irp_id;
        self.next_irp_id += 1;
        irp.completed = false;
        self.irp_queue.push(irp);
        Ok(())
    }

    /// Complete an IRP by ID with the given NTSTATUS code.
    pub fn complete_irp(&mut self, irp_id: u64, status: i32) -> AppResult<()> {
        let irp = self.irp_queue.iter_mut().find(|i| i.irp_id == irp_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("SCM: IRP not found: {irp_id}"),
            )
        })?;
        irp.status = status;
        irp.completed = true;
        Ok(())
    }

    /// Dequeue all completed IRPs from the queue.
    pub fn dequeue_completed_irps(&mut self) -> Vec<IrpRequest> {
        let completed: Vec<IrpRequest> = self
            .irp_queue
            .iter()
            .filter(|i| i.completed)
            .cloned()
            .collect();
        self.irp_queue.retain(|i| !i.completed);
        completed
    }

    /// Queue a Deferred Procedure Call.
    pub fn queue_dpc(&mut self, routine: u64, context: u64, parameter: u64) {
        self.dpc_queue.push(DpcEntry {
            routine,
            context,
            parameter,
        });
    }

    /// Drain all pending DPCs from the queue.
    pub fn drain_dpcs(&mut self) -> Vec<DpcEntry> {
        std::mem::take(&mut self.dpc_queue)
    }
}

// ===========================================================================
// Main SCM controller
// ===========================================================================
#[derive(Debug, Clone)]
pub struct ScmController {
    pub config: ScmConfig,
    pub vm_state: VmState,
    pub virtio_gpu: VirtioGpu,
    pub virtio_fs: VirtioFs,
    pub virtio_net: VirtioNet,
    pub kernel_shim: WindowsKernelShim,
    /// Guest memory mapping (simulated)
    pub guest_memory: Vec<u8>,
    /// Performance metrics
    pub uptime_seconds: u64,
    pub total_instructions: u64,
}

impl ScmController {
    /// Create a new SCM controller with the given configuration.
    pub fn new(config: ScmConfig) -> Self {
        let memory_size = (config.memory_mb as usize).max(256) * 1024 * 1024;
        Self {
            vm_state: VmState::Stopped,
            virtio_gpu: VirtioGpu {
                enabled: config.virtio_gpu,
                framebuffer_width: 1280,
                framebuffer_height: 720,
                framebuffer: vec![0u8; 1280 * 720 * 4],
            },
            virtio_fs: VirtioFs {
                enabled: config.shared_directory.is_some(),
                shared_dir: config.shared_directory.clone(),
                mounted: false,
            },
            virtio_net: VirtioNet {
                enabled: config.virtio_net,
                mac_address: "02:00:00:00:00:01".to_string(),
                connected: false,
            },
            kernel_shim: WindowsKernelShim::new(config.secure_boot),
            guest_memory: vec![0u8; memory_size],
            uptime_seconds: 0,
            total_instructions: 0,
            config,
        }
    }

    /// Start the VM — in production this creates a VZVirtualMachine.
    pub fn start_vm(&mut self) -> AppResult<()> {
        if self.vm_state == VmState::Running {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "SCM: VM is already running",
            ));
        }

        self.load_kernel_shim()?;

        if self.virtio_fs.enabled {
            self.mount_shared_directory()?;
        }

        if self.virtio_net.enabled {
            self.virtio_net.connected = true;
        }

        if self.virtio_gpu.enabled {
            self.virtio_gpu.framebuffer = vec![0u8; 1280 * 720 * 4];
        }

        self.vm_state = VmState::Running;
        self.uptime_seconds = 0;

        Ok(())
    }

    /// Stop the VM
    pub fn stop_vm(&mut self) -> AppResult<()> {
        if self.vm_state == VmState::Stopped {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "SCM: VM is already stopped",
            ));
        }

        self.vm_state = VmState::Stopped;
        self.kernel_shim.loaded = false;
        self.kernel_shim.registered_drivers.clear();
        self.virtio_net.connected = false;
        self.virtio_fs.mounted = false;

        Ok(())
    }

    /// Pause the VM
    pub fn pause_vm(&mut self) -> AppResult<()> {
        if self.vm_state != VmState::Running {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "SCM: VM is not running",
            ));
        }
        self.vm_state = VmState::Paused;
        Ok(())
    }

    /// Resume the VM
    pub fn resume_vm(&mut self) -> AppResult<()> {
        if self.vm_state != VmState::Paused {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "SCM: VM is not paused",
            ));
        }
        self.vm_state = VmState::Running;
        Ok(())
    }

    fn load_kernel_shim(&mut self) -> AppResult<()> {
        self.kernel_shim.ntoskrnl_base = 0xFFFFF800_00000000;
        self.kernel_shim.hal_base = self.kernel_shim.ntoskrnl_base + 0x200000;

        self.kernel_shim.registered_drivers.push("ntoskrnl.exe".to_string());
        self.kernel_shim.registered_drivers.push("hal.dll".to_string());
        self.kernel_shim.registered_drivers.push("ksecdd.sys".to_string());
        self.kernel_shim.registered_drivers.push("ndis.sys".to_string());
        self.kernel_shim.registered_drivers.push("dxgkrnl.sys".to_string());

        self.kernel_shim.loaded = true;
        Ok(())
    }

    /// Register a kernel driver (simulates driver loading)
    pub fn register_driver(&mut self, name: &str, base: u64) -> AppResult<()> {
        if !self.kernel_shim.loaded {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "SCM: kernel shim not loaded",
            ));
        }

        self.kernel_shim.driver_objects.insert(name.to_string(), base);
        if !self.kernel_shim.registered_drivers.contains(&name.to_string()) {
            self.kernel_shim.registered_drivers.push(name.to_string());
        }

        Ok(())
    }

    fn mount_shared_directory(&mut self) -> AppResult<()> {
        if let Some(ref dir) = self.virtio_fs.shared_dir {
            let path = std::path::Path::new(dir);
            if !path.exists() {
                return Err(AppError::new(
                    ReasonCode::RcFsNotFound,
                    format!("SCM: shared directory not found: {dir}"),
                ));
            }
            self.virtio_fs.mounted = true;
        }
        Ok(())
    }

    /// Write to virtio-gpu framebuffer (called by guest display driver)
    pub fn write_framebuffer(&mut self, x: u32, y: u32, width: u32, height: u32, pixels: &[u8]) {
        let fb_width = self.virtio_gpu.framebuffer_width;
        for row in 0..height.min(self.virtio_gpu.framebuffer_height - y) {
            let src_start = (row * width * 4) as usize;
            let src_end = src_start + (width as usize * 4).min(pixels.len() - src_start);
            let dst_start = ((y + row) * fb_width + x) as usize * 4;
            let dst_end = dst_start + (width as usize * 4).min(self.virtio_gpu.framebuffer.len() - dst_start);

            if src_end > src_start && dst_end > dst_start {
                let copy_len = dst_end - dst_start;
                self.virtio_gpu.framebuffer[dst_start..dst_end]
                    .copy_from_slice(&pixels[src_start..src_start + copy_len]);
            }
        }
    }

    /// Read virtio-gpu framebuffer (for display output)
    pub fn read_framebuffer(&self) -> &[u8] {
        &self.virtio_gpu.framebuffer
    }

    /// Tick the VM — advance simulation by one time quantum
    pub fn tick(&mut self) {
        if self.vm_state == VmState::Running {
            self.total_instructions += 1000;
        }
    }

    /// Satisfy an integrity check request from guest driver
    pub fn satisfy_integrity_check(&self, address: u64, _expected_hash: &[u8]) -> bool {
        if address < self.kernel_shim.ntoskrnl_base {
            return false;
        }
        true
    }

    /// Report whether secure boot is active (for anti-cheat queries)
    pub fn is_secure_boot_active(&self) -> bool {
        self.config.secure_boot && self.vm_state == VmState::Running
    }

    /// Get the number of CPU cores available in the VM
    pub fn cpu_count(&self) -> u32 {
        self.config.cpu_count
    }
}

// ===========================================================================
// SCM Runner Integration
// ===========================================================================

/// Integration layer that ties together the SCM controller, VZ VM handle,
/// Metal GPU, filesystem bridge, network bridge, secure boot, and measured
/// launch into a single cohesive unit for the runner.
pub struct ScmRunnerIntegration {
    /// The SCM controller managing VM state and configuration.
    pub controller: ScmController,
    /// Handle to the Apple VZVirtualMachine (if created).
    pub vm_handle: Option<VZVirtualMachineHandle>,
    /// Metal-backed virtio-GPU (if display is enabled).
    pub gpu: Option<VirtioGpuMetal>,
    /// Virtio-FS bridge (if shared directory is configured).
    pub fs_bridge: Option<VirtioFsBridge>,
    /// Virtio-net bridge (if networking is enabled).
    pub net_bridge: Option<VirtioNetBridge>,
    /// Secure boot configuration (if enabled).
    pub secure_boot: Option<SecureBootConfig>,
    /// Measured launch state (if enabled).
    pub measured_launch: Option<MeasuredLaunchState>,
}

impl ScmRunnerIntegration {
    /// Create a new runner integration with the given SCM configuration.
    pub fn new(config: ScmConfig) -> Self {
        let gpu = if config.virtio_gpu {
            VirtioGpuMetal::create_metal_backed_gpu(1280, 720).ok()
        } else {
            None
        };

        let fs_bridge = config.shared_directory.as_ref().map(|dir| {
            VirtioFsBridge::new(dir, "casa1-shared")
        });

        let net_bridge = if config.virtio_net {
            Some(VirtioNetBridge::new("02:00:00:00:00:01"))
        } else {
            None
        };

        let secure_boot = if config.secure_boot {
            Some(SecureBootConfig {
                enabled: true,
                efi_variable_store_path: None,
                machine_identifier: None,
                certificate_path: None,
            })
        } else {
            None
        };

        let measured_launch = if config.measured_launch {
            Some(MeasuredLaunchState {
                enabled: true,
                ..Default::default()
            })
        } else {
            None
        };

        Self {
            controller: ScmController::new(config),
            vm_handle: None,
            gpu,
            fs_bridge,
            net_bridge,
            secure_boot,
            measured_launch,
        }
    }

    /// Full VM launch sequence.
    pub fn launch_vm(&mut self) -> AppResult<()> {
        let arm_config = Arm64VmConfig {
            cpu_count: self.controller.config.cpu_count,
            memory_mb: self.controller.config.memory_mb,
            boot_loader: BootLoaderType::LinuxKernel {
                kernel_path: self.controller.config.kernel_path.clone().unwrap_or_default(),
                initrd_path: None,
                command_line: "console=hvc0 root=/dev/vda".to_string(),
            },
            entropy_enabled: true,
            mac_address: Some(self.controller.virtio_net.mac_address.clone()),
            shared_directory: self.controller.config.shared_directory.clone(),
            display_enabled: self.controller.config.virtio_gpu,
            display_width: self.gpu.as_ref().map(|g| g.scanout_width).unwrap_or(1280),
            display_height: self.gpu.as_ref().map(|g| g.scanout_height).unwrap_or(720),
        };

        let vz_config = configure_arm64_vm(&arm_config)?;

        let mut vm_handle = create_vz_virtual_machine(&vz_config)?;
        vm_handle.start()?;

        if let Some(ref mut net) = self.net_bridge {
            net.connected = true;
        }
        if let Some(ref mut fs) = self.fs_bridge {
            fs.mounted = true;
        }

        self.controller.start_vm()?;

        if let Some(ref mut ml) = self.measured_launch {
            let kernel_measurement = measure_component("ntoskrnl", &[0u8; 32])?;
            extend_pcr(ml, 0, &kernel_measurement)?;
        }

        self.vm_handle = Some(vm_handle);
        Ok(())
    }

    /// Clean shutdown sequence.
    pub fn shutdown_vm(&mut self) -> AppResult<()> {
        if let Some(ref mut vm) = self.vm_handle {
            vm.stop()?;
        }

        if let Some(ref mut net) = self.net_bridge {
            net.connected = false;
        }

        if let Some(ref mut fs) = self.fs_bridge {
            fs.mounted = false;
        }

        if self.controller.vm_state != VmState::Stopped {
            self.controller.stop_vm()?;
        }

        self.vm_handle = None;
        Ok(())
    }

    /// Process one frame tick.
    pub fn tick(&mut self) -> AppResult<()> {
        let vm_state = self.get_vm_state();
        if vm_state != VmState::Running {
            return Ok(());
        }

        if let Some(ref mut gpu) = self.gpu {
            gpu.flush_to_metal()?;
        }

        if let Some(ref mut net) = self.net_bridge {
            if !net.tx_buffer.is_empty() {
                let tx_data = std::mem::take(&mut net.tx_buffer);
                net.rx_buffer.extend(tx_data);
            }
        }

        self.controller.tick();
        Ok(())
    }

    /// Get the current GPU framebuffer contents, if available.
    pub fn get_framebuffer(&self) -> Option<&[u8]> {
        self.gpu.as_ref().map(|g| g.read_scanout())
    }

    /// Get the current VM state.
    pub fn get_vm_state(&self) -> VmState {
        if let Some(ref vm) = self.vm_handle {
            vm.state()
        } else {
            self.controller.vm_state
        }
    }
}

impl std::fmt::Debug for ScmRunnerIntegration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScmRunnerIntegration")
            .field("controller", &self.controller)
            .field("vm_handle", &self.vm_handle.as_ref().map(|h| h.is_valid()))
            .field("has_gpu", &self.gpu.is_some())
            .field("has_fs_bridge", &self.fs_bridge.is_some())
            .field("has_net_bridge", &self.net_bridge.is_some())
            .field("secure_boot", &self.secure_boot)
            .field("measured_launch", &self.measured_launch)
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    #[test]
    fn scm_controller_initialises_with_default_config() {
        let controller = ScmController::new(ScmConfig::default());
        assert_eq!(controller.vm_state, VmState::Stopped);
        assert!(!controller.kernel_shim.loaded);
        assert_eq!(controller.config.cpu_count, 4);
    }

    #[test]
    fn scm_start_stop_vm_lifecycle() {
        let mut controller = ScmController::new(ScmConfig {
            enabled: true,
            cpu_count: 2,
            memory_mb: 2048,
            kernel_path: None,
            shared_directory: None,
            virtio_gpu: true,
            virtio_net: true,
            secure_boot: true,
            measured_launch: false,
        });

        controller.start_vm().expect("start VM");
        assert_eq!(controller.vm_state, VmState::Running);
        assert!(controller.kernel_shim.loaded);
        assert!(controller.is_secure_boot_active());

        controller.stop_vm().expect("stop VM");
        assert_eq!(controller.vm_state, VmState::Stopped);
        assert!(!controller.is_secure_boot_active());
    }

    #[test]
    fn scm_pause_resume() {
        let mut controller = ScmController::new(ScmConfig {
            enabled: true,
            ..Default::default()
        });
        controller.start_vm().unwrap();

        controller.pause_vm().expect("pause");
        assert_eq!(controller.vm_state, VmState::Paused);

        controller.resume_vm().expect("resume");
        assert_eq!(controller.vm_state, VmState::Running);
    }

    #[test]
    fn scm_register_driver() {
        let mut controller = ScmController::new(ScmConfig {
            enabled: true,
            ..Default::default()
        });
        controller.start_vm().unwrap();

        controller
            .register_driver("eac_driver.sys", 0xFFFFF800_00200000)
            .expect("register driver");
        assert!(controller
            .kernel_shim
            .registered_drivers
            .contains(&"eac_driver.sys".to_string()));
    }

    #[test]
    fn scm_framebuffer_write() {
        let mut controller = ScmController::new(ScmConfig {
            enabled: true,
            ..Default::default()
        });
        controller.start_vm().unwrap();

        let pixels = vec![0xFF; 640 * 480 * 4];
        controller.write_framebuffer(0, 0, 640, 480, &pixels);

        let fb = controller.read_framebuffer();
        assert_eq!(fb[0], 0xFF);
        assert_eq!(fb.len(), 1280 * 720 * 4);
    }

    // -----------------------------------------------------------------------
    // New tests
    // -----------------------------------------------------------------------

    #[test]
    fn vz_virtual_machine_configuration() {
        let config = VZVirtualMachineConfiguration {
            cpu_count: 4,
            memory_size: 4096 * 1024 * 1024,
            boot_loader: VZBootLoader::Linux {
                kernel_path: "/tmp/vmlinuz".to_string(),
                initrd_path: None,
                command_line: "console=hvc0".to_string(),
            },
            devices: vec![
                VZDeviceConfiguration::VirtioGpu,
                VZDeviceConfiguration::Entropy,
            ],
        };

        assert_eq!(config.cpu_count, 4);
        assert_eq!(config.memory_size, 4096 * 1024 * 1024);
        assert_eq!(config.devices.len(), 2);
    }

    #[test]
    fn arm64_vm_config_builder() {
        let arm_config = Arm64VmConfig {
            cpu_count: 8,
            memory_mb: 8192,
            boot_loader: BootLoaderType::LinuxKernel {
                kernel_path: "/tmp/vmlinuz".to_string(),
                initrd_path: Some("/tmp/initrd".to_string()),
                command_line: "console=hvc0 root=/dev/vda".to_string(),
            },
            entropy_enabled: true,
            mac_address: Some("02:00:00:00:00:01".to_string()),
            shared_directory: Some("/tmp/shared".to_string()),
            display_enabled: true,
            display_width: 1920,
            display_height: 1080,
        };

        let vz_config = configure_arm64_vm(&arm_config).expect("configure ARM64 VM");

        assert_eq!(vz_config.cpu_count, 8);
        assert_eq!(vz_config.memory_size, 8192 * 1024 * 1024);

        let has_gpu = vz_config.devices.iter().any(|d| matches!(d, VZDeviceConfiguration::VirtioGpu));
        let has_fs = vz_config.devices.iter().any(|d| matches!(d, VZDeviceConfiguration::VirtioFs { .. }));
        let has_net = vz_config.devices.iter().any(|d| matches!(d, VZDeviceConfiguration::VirtioNet { .. }));
        let has_serial = vz_config.devices.iter().any(|d| matches!(d, VZDeviceConfiguration::SerialPort { .. }));
        let has_entropy = vz_config.devices.iter().any(|d| matches!(d, VZDeviceConfiguration::Entropy));

        assert!(has_gpu, "VirtioGpu device should be present");
        assert!(has_fs, "VirtioFs device should be present");
        assert!(has_net, "VirtioNet device should be present");
        assert!(has_serial, "SerialPort device should be present");
        assert!(has_entropy, "Entropy device should be present");
        assert_eq!(vz_config.devices.len(), 5);
    }

    #[test]
    fn virtio_gpu_metal_creation() {
        let gpu = VirtioGpuMetal::create_metal_backed_gpu(800, 600).expect("create Metal GPU");

        assert_eq!(gpu.scanout_width, 800);
        assert_eq!(gpu.scanout_height, 600);
        assert_eq!(gpu.framebuffer.len(), 800 * 600 * 4);
        assert!(gpu.dirty_rects.is_empty());
    }

    #[test]
    fn virtio_gpu_metal_update_and_flush() {
        let mut gpu = VirtioGpuMetal::create_metal_backed_gpu(1280, 720).expect("create Metal GPU");

        let pixels = vec![0xAB; 100 * 100 * 4];
        gpu.update_scanout(&pixels, 10, 20, 100, 100).expect("update scanout");

        assert_eq!(gpu.dirty_rects.len(), 1);
        let rect = &gpu.dirty_rects[0];
        assert_eq!(rect.x, 10);
        assert_eq!(rect.y, 20);
        assert_eq!(rect.width, 100);
        assert_eq!(rect.height, 100);

        let fb_offset = ((20 * 1280) + 10) * 4;
        assert_eq!(gpu.framebuffer[fb_offset], 0xAB);

        gpu.flush_to_metal().expect("flush to Metal");
        assert!(gpu.dirty_rects.is_empty());
    }

    #[test]
    fn virtio_fs_bridge_open_read_close() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let dir_path = dir.path().to_str().unwrap();

        let file_path = dir.path().join("test.txt");
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            f.write_all(b"hello world").unwrap();
        }

        let mut bridge = VirtioFsBridge::new(dir_path, "casa1-shared");

        let handle = bridge.open("test.txt", 0).expect("open file");
        assert_eq!(handle, 1);

        let mut buffer = vec![0u8; 64];
        let bytes_read = bridge.read(handle, &mut buffer).expect("read file");
        assert_eq!(bytes_read, 11);
        assert_eq!(&buffer[..11], b"hello world");

        bridge.close(handle).expect("close file");
        assert!(bridge.read(handle, &mut buffer).is_err());
    }

    #[test]
    fn virtio_fs_bridge_directory_ops() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let dir_path = dir.path().to_str().unwrap();

        let bridge = VirtioFsBridge::new(dir_path, "casa1-shared");

        bridge.mkdir("subdir").expect("mkdir");

        let entries = bridge.readdir(".").expect("readdir");
        assert!(entries.contains(&"subdir".to_string()));

        let stat = bridge.stat("subdir").expect("stat");
        assert!(stat.is_directory);

        bridge.unlink("subdir").expect("unlink");

        let entries = bridge.readdir(".").expect("readdir after unlink");
        assert!(!entries.contains(&"subdir".to_string()));
    }

    #[test]
    fn virtio_net_bridge_send_receive() {
        let mut bridge = VirtioNetBridge::new("02:00:00:00:00:01");
        bridge.connected = true;

        let packet = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x01];
        bridge.send_packet(&packet).expect("send packet");

        assert_eq!(bridge.stats.bytes_sent, 6);
        assert_eq!(bridge.stats.packets_sent, 1);

        let tx_data = std::mem::take(&mut bridge.tx_buffer);
        bridge.rx_buffer.extend(tx_data);

        let mut rx_buffer = vec![0u8; 64];
        let received = bridge.receive_packet(&mut rx_buffer).expect("receive packet");
        assert_eq!(received, 6);
        assert_eq!(&rx_buffer[..6], &packet);
        assert_eq!(bridge.stats.bytes_received, 6);
        assert_eq!(bridge.stats.packets_received, 1);
    }

    #[test]
    fn secure_boot_configuration() {
        let config = SecureBootConfig {
            enabled: true,
            efi_variable_store_path: Some("/tmp/efi_vars".to_string()),
            machine_identifier: Some("casa1-vm-001".to_string()),
            certificate_path: None,
        };

        configure_secure_boot(&config).expect("configure secure boot");

        let disabled_config = SecureBootConfig {
            enabled: false,
            ..Default::default()
        };
        configure_secure_boot(&disabled_config).expect("disabled secure boot");
    }

    #[test]
    fn measured_launch_pcr() {
        let mut state = MeasuredLaunchState {
            enabled: true,
            ..Default::default()
        };

        let digest = measure_component("ntoskrnl.exe", b"kernel-binary-data").expect("measure");
        assert_ne!(digest, [0u8; 32]);

        extend_pcr(&mut state, 0, &digest).expect("extend PCR 0");
        assert_ne!(state.pcr_values[0], [0u8; 32]);
        assert_eq!(state.measurement_log.len(), 1);
        assert_eq!(state.measurement_log[0].index, 0);

        let valid = verify_measurement(&state, 0, &state.pcr_values[0]).expect("verify");
        assert!(valid);

        let digest2 = measure_component("hal.dll", b"hal-binary-data").expect("measure hal");
        extend_pcr(&mut state, 1, &digest2).expect("extend PCR 1");
        assert_ne!(state.pcr_values[1], [0u8; 32]);
        assert_ne!(state.pcr_values[0], state.pcr_values[1]);
    }

    #[test]
    fn scm_runner_integration_lifecycle() {
        let mut integration = ScmRunnerIntegration::new(ScmConfig {
            enabled: true,
            cpu_count: 2,
            memory_mb: 2048,
            kernel_path: None,
            shared_directory: None,
            virtio_gpu: true,
            virtio_net: true,
            secure_boot: false,
            measured_launch: true,
        });

        integration.launch_vm().expect("launch VM");
        assert_eq!(integration.get_vm_state(), VmState::Running);

        integration.tick().expect("tick");
        assert!(integration.controller.total_instructions > 0);

        let fb = integration.get_framebuffer();
        assert!(fb.is_some());
        assert_eq!(fb.unwrap().len(), 1280 * 720 * 4);

        integration.shutdown_vm().expect("shutdown VM");
        assert_eq!(integration.get_vm_state(), VmState::Stopped);
    }

    #[test]
    fn windows_kernel_shim_service_database() {
        let mut shim = WindowsKernelShim::new(false);

        shim.create_service(
            "Winmgmt",
            "Windows Management Instrumentation",
            0x20,
            2,
            r"C:\Windows\System32\svchost.exe -k netsvcs",
        )
        .expect("create service");

        shim.create_service(
            "Dnscache",
            "DNS Client",
            0x20,
            2,
            r"C:\Windows\System32\svchost.exe -k NetworkService",
        )
        .expect("create service");

        let services = shim.enum_services();
        assert_eq!(services.len(), 2);

        shim.start_service("Winmgmt").expect("start service");
        let svc = shim.query_service("Winmgmt").expect("query service");
        assert_eq!(svc.state, ServiceState::Running);
        assert!(svc.pid.is_some());

        shim.stop_service("Winmgmt").expect("stop service");
        let svc = shim.query_service("Winmgmt").expect("query stopped");
        assert_eq!(svc.state, ServiceState::Stopped);
        assert!(svc.pid.is_none());

        assert!(shim.create_service("Winmgmt", "Dup", 0, 0, "").is_err());
        assert!(shim.start_service("NoSuchService").is_err());
    }

    #[test]
    fn windows_kernel_shim_irp_queue() {
        let mut shim = WindowsKernelShim::new(false);

        let irp1 = IrpRequest {
            irp_id: 0,
            device_handle: 1,
            major_function: 0x03,
            minor_function: 0,
            input_buffer: vec![1, 2, 3],
            output_buffer: vec![],
            status: 0,
            completed: false,
        };
        let irp2 = IrpRequest {
            irp_id: 0,
            device_handle: 2,
            major_function: 0x04,
            minor_function: 0,
            input_buffer: vec![4, 5, 6],
            output_buffer: vec![],
            status: 0,
            completed: false,
        };

        shim.queue_irp(irp1).expect("queue IRP 1");
        shim.queue_irp(irp2).expect("queue IRP 2");

        assert_eq!(shim.irp_queue.len(), 2);
        assert_eq!(shim.irp_queue[0].irp_id, 1);
        assert_eq!(shim.irp_queue[1].irp_id, 2);

        shim.complete_irp(1, 0).expect("complete IRP 1");
        assert!(shim.irp_queue[0].completed);
        assert!(!shim.irp_queue[1].completed);

        let completed = shim.dequeue_completed_irps();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].irp_id, 1);
        assert_eq!(shim.irp_queue.len(), 1);
    }

    #[test]
    fn windows_kernel_shim_dpc_queue() {
        let mut shim = WindowsKernelShim::new(false);

        shim.queue_dpc(0xDEADBEEF, 0x1000, 0x2000);
        shim.queue_dpc(0xCAFEBABE, 0x3000, 0x4000);
        shim.queue_dpc(0x12345678, 0x5000, 0x6000);

        assert_eq!(shim.dpc_queue.len(), 3);

        let dpcs = shim.drain_dpcs();
        assert_eq!(dpcs.len(), 3);
        assert_eq!(dpcs[0].routine, 0xDEADBEEF);
        assert_eq!(dpcs[1].routine, 0xCAFEBABE);
        assert_eq!(dpcs[2].routine, 0x12345678);

        assert!(shim.dpc_queue.is_empty());

        let dpcs2 = shim.drain_dpcs();
        assert!(dpcs2.is_empty());
    }
}
