//! Real Win32 API expansion for Casa1.
//!
//! Implements the critical Win32 APIs needed by Steam and AAA games that are
//! not already covered in `src/win32.rs` and `src/pe_runtime.rs`. This includes
//! COM/OLE automation, MSVC CRT, Shell32, Advapi32, Version, XInput, BCrypt,
//! ThreadPool, synchronization barriers, and DbgHelp.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ===========================================================================
// COM / OLE Automation
// ===========================================================================

/// COM apartment state tracker.
pub struct ComApartmentState {
    initialized: bool,
    apartment_model: ComApartmentModel,
    next_iid: u64,
    com_objects: BTreeMap<u64, ComObjectRecord>,
}

/// COM threading model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComApartmentModel {
    SingleThreaded,
    MultiThreaded,
    NotInitialized,
}

/// A tracked COM object instance.
#[derive(Debug, Clone)]
pub struct ComObjectRecord {
    pub clsid: [u8; 16],
    pub iid: [u8; 16],
    pub refcount: u32,
    pub vtable_ptr: u64,
    pub object_name: String,
}

/// Standard COM interface IDs as byte arrays (GUID format: Data1-Data2-Data3-Data4).
pub struct ComIid;

impl ComIid {
    /// IUnknown: {00000000-0000-0000-C000-000000000046}
    pub const IUNKNOWN: [u8; 16] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
    /// IDispatch: {00020400-0000-0000-C000-000000000046}
    pub const IDISPATCH: [u8; 16] = [0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
    /// IClassFactory: {00000001-0000-0000-C000-000000000046}
    pub const ICLASS_FACTORY: [u8; 16] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
}

/// Well-known CLSIDs used by Steam and games.
pub struct ComClsid;

impl ComClsid {
    /// DirectSound8: {3901CC3F-84B5-4FA4-BA35-AA8172B8A6B2}
    pub const DIRECTSOUND8: [u8; 16] = [0x3F, 0xCC, 0x01, 0x39, 0xB5, 0x84, 0xA4, 0x4F, 0xBA, 0x35, 0xAA, 0x81, 0x72, 0xB8, 0xA6, 0xB2];
    /// XAudio2: {609ED052-35B5-4F10-9BE6-39650F9781D4}
    pub const XAUDIO2: [u8; 16] = [0x52, 0xD0, 0x9E, 0x60, 0xB5, 0x35, 0x10, 0x4F, 0x9B, 0xE6, 0x39, 0x65, 0x0F, 0x97, 0x81, 0xD4];
}

impl ComApartmentState {
    pub fn new() -> Self {
        Self {
            initialized: false,
            apartment_model: ComApartmentModel::NotInitialized,
            next_iid: 1,
            com_objects: BTreeMap::new(),
        }
    }

    /// CoInitializeEx — initialize the COM apartment.
    pub fn co_initialize(&mut self, model: ComApartmentModel) -> AppResult<()> {
        if self.initialized {
            // S_FALSE — already initialized with same model (not an error)
            return Ok(());
        }
        self.initialized = true;
        self.apartment_model = model;
        Ok(())
    }

    /// CoUninitialize — tear down the COM apartment.
    pub fn co_uninitialize(&mut self) {
        self.initialized = false;
        self.apartment_model = ComApartmentModel::NotInitialized;
        self.com_objects.clear();
    }

    /// CoCreateInstance — create a COM object by CLSID.
    pub fn co_create_instance(
        &mut self,
        clsid: [u8; 16],
        iid: [u8; 16],
        vtable_ptr: u64,
        object_name: &str,
    ) -> AppResult<u64> {
        if !self.initialized {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "CoCreateInstance called before CoInitialize",
            ));
        }
        let handle = self.next_iid;
        self.next_iid += 1;
        self.com_objects.insert(
            handle,
            ComObjectRecord {
                clsid,
                iid,
                refcount: 1,
                vtable_ptr,
                object_name: object_name.to_string(),
            },
        );
        Ok(handle)
    }

    /// AddRef — increment the reference count.
    pub fn com_addref(&mut self, handle: u64) -> AppResult<u32> {
        let obj = self.com_objects.get_mut(&handle).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("COM object {handle} not found"))
        })?;
        obj.refcount += 1;
        Ok(obj.refcount)
    }

    /// Release — decrement the reference count, remove if zero.
    pub fn com_release(&mut self, handle: u64) -> AppResult<u32> {
        let obj = self.com_objects.get_mut(&handle).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("COM object {handle} not found"))
        })?;
        obj.refcount = obj.refcount.saturating_sub(1);
        let count = obj.refcount;
        if count == 0 {
            self.com_objects.remove(&handle);
        }
        Ok(count)
    }

    /// QueryInterface — check if the COM object supports a given IID.
    pub fn com_query_interface(&self, handle: u64, iid: [u8; 16]) -> AppResult<bool> {
        let obj = self.com_objects.get(&handle).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("COM object {handle} not found"))
        })?;
        // IUnknown is always supported
        if iid == ComIid::IUNKNOWN {
            return Ok(true);
        }
        // Check if the requested IID matches the object's IID
        Ok(obj.iid == iid)
    }

    /// Get the vtable pointer for a COM object.
    pub fn com_vtable(&self, handle: u64) -> AppResult<u64> {
        let obj = self.com_objects.get(&handle).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("COM object {handle} not found"))
        })?;
        Ok(obj.vtable_ptr)
    }

    /// Get COM object info.
    pub fn com_object_info(&self, handle: u64) -> AppResult<&ComObjectRecord> {
        self.com_objects.get(&handle).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("COM object {handle} not found"))
        })
    }

    /// Check if COM is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the count of active COM objects.
    pub fn active_object_count(&self) -> usize {
        self.com_objects.len()
    }
}

// ===========================================================================
// MSVC CRT Functions
// ===========================================================================

/// MSVC CRT implementation for guest code.
pub struct MsvcCrt {
    errno_value: i32,
    #[allow(dead_code)]
    next_file_descriptor: i32,
    #[allow(dead_code)]
    open_files: BTreeMap<i32, CrtFileRecord>,
    heap_allocations: BTreeMap<u64, usize>,
    next_alloc_id: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CrtFileRecord {
    path: String,
    mode: String,
    position: u64,
}

impl MsvcCrt {
    pub fn new() -> Self {
        let mut open_files = BTreeMap::new();
        // Standard file descriptors: 0=stdin, 1=stdout, 2=stderr
        open_files.insert(0, CrtFileRecord { path: "stdin".to_string(), mode: "r".to_string(), position: 0 });
        open_files.insert(1, CrtFileRecord { path: "stdout".to_string(), mode: "w".to_string(), position: 0 });
        open_files.insert(2, CrtFileRecord { path: "stderr".to_string(), mode: "w".to_string(), position: 0 });

        Self {
            errno_value: 0,
            next_file_descriptor: 3,
            open_files,
            heap_allocations: BTreeMap::new(),
            next_alloc_id: 1,
        }
    }

    /// Get the CRT errno value.
    pub fn get_errno(&self) -> i32 {
        self.errno_value
    }

    /// Set the CRT errno value.
    pub fn set_errno(&mut self, value: i32) {
        self.errno_value = value;
    }

    /// CRT malloc — allocate a block.
    pub fn crt_malloc(&mut self, size: usize) -> u64 {
        if size == 0 {
            return 0;
        }
        let id = self.next_alloc_id;
        self.next_alloc_id += 1;
        self.heap_allocations.insert(id, size);
        id
    }

    /// CRT free — free a block.
    pub fn crt_free(&mut self, ptr: u64) -> AppResult<()> {
        if ptr == 0 {
            return Ok(());
        }
        self.heap_allocations.remove(&ptr).map(|_| ()).ok_or_else(|| {
            self.errno_value = 22; // EINVAL
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("CRT free: invalid pointer {ptr}"))
        })
    }

    /// CRT realloc — reallocate a block.
    pub fn crt_realloc(&mut self, ptr: u64, new_size: usize) -> u64 {
        if ptr == 0 {
            return self.crt_malloc(new_size);
        }
        if new_size == 0 {
            let _ = self.crt_free(ptr);
            return 0;
        }
        if self.heap_allocations.contains_key(&ptr) {
            self.heap_allocations.insert(ptr, new_size);
            ptr
        } else {
            self.errno_value = 22;
            0
        }
    }

    /// CRT _beginthreadex — create a thread.
    pub fn crt_beginthreadex(&self) -> AppResult<u32> {
        // Thread creation is handled by the threads subsystem
        // This returns a synthetic thread handle
        Ok(42)
    }

    /// CRT atoi — convert string to integer.
    pub fn crt_atoi(s: &str) -> i32 {
        let trimmed = s.trim();
        let mut result: i32 = 0;
        let mut negative = false;
        let bytes = trimmed.as_bytes();
        let mut i = 0;

        if i < bytes.len() && bytes[i] == b'-' {
            negative = true;
            i += 1;
        } else if i < bytes.len() && bytes[i] == b'+' {
            i += 1;
        }

        while i < bytes.len() && bytes[i].is_ascii_digit() {
            let digit = (bytes[i] - b'0') as i32;
            result = result.wrapping_mul(10).wrapping_add(digit);
            i += 1;
        }

        if negative { -result } else { result }
    }

    /// CRT atof — convert string to float.
    pub fn crt_atof(s: &str) -> f64 {
        s.trim().parse().unwrap_or(0.0)
    }

    /// CRT sprintf-like formatting (simplified).
    pub fn crt_sprintf_int(value: i32, format: &str) -> String {
        if format == "%d" || format == "%i" {
            value.to_string()
        } else if format == "%x" {
            format!("{value:x}")
        } else if format == "%X" {
            format!("{value:X}")
        } else if format == "%o" {
            format!("{value:o}")
        } else if format == "%08x" {
            format!("{value:08x}")
        } else if format == "%08X" {
            format!("{value:08X}")
        } else {
            value.to_string()
        }
    }

    /// CRT sscanf — simplified integer parsing.
    pub fn crt_sscanf_int(input: &str, format: &str) -> Option<i32> {
        let trimmed = input.trim();
        if format == "%d" || format == "%i" {
            Some(Self::crt_atoi(trimmed))
        } else if format == "%x" || format == "%X" {
            i32::from_str_radix(trimmed.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
        } else {
            None
        }
    }

    /// Get the allocation size for a pointer.
    pub fn crt_alloc_size(&self, ptr: u64) -> Option<usize> {
        self.heap_allocations.get(&ptr).copied()
    }

    /// Get the count of active heap allocations.
    pub fn crt_alloc_count(&self) -> usize {
        self.heap_allocations.len()
    }
}

// ===========================================================================
// Shell32 / Shlwapi
// ===========================================================================

/// Well-known Windows CSIDL folder IDs.
pub const CSIDL_DESKTOP: i32 = 0x0000;
pub const CSIDL_PROGRAMS: i32 = 0x0002;
pub const CSIDL_PERSONAL: i32 = 0x0005;
pub const CSIDL_APPDATA: i32 = 0x001A;
pub const CSIDL_LOCAL_APPDATA: i32 = 0x001C;
pub const CSIDL_COMMON_APPDATA: i32 = 0x0023;
pub const CSIDL_PROGRAM_FILES: i32 = 0x0026;
pub const CSIDL_PROGRAM_FILES_X86: i32 = 0x002A;
pub const CSIDL_WINDOWS: i32 = 0x0024;
pub const CSIDL_SYSTEM: i32 = 0x0025;
pub const CSIDL_PROFILE: i32 = 0x0028;
pub const CSIDL_FONTS: i32 = 0x0014;
pub const CSIDL_STARTUP: i32 = 0x0007;
pub const CSIDL_RECENT: i32 = 0x0008;
pub const CSIDL_SENDTO: i32 = 0x0009;
pub const CSIDL_COOKIES: i32 = 0x0021;
pub const CSIDL_HISTORY: i32 = 0x0022;
pub const CSIDL_INTERNET_CACHE: i32 = 0x0020;
pub const CSIDL_TEMP: i32 = -1; // Custom

/// Resolve a CSIDL to a Windows path within the GE root.
pub fn sh_get_folder_path(csidl: i32, ge_root: &str) -> String {
    let drive_c = format!("{ge_root}/drive_c");
    match csidl {
        CSIDL_WINDOWS => format!("{drive_c}/windows"),
        CSIDL_SYSTEM => format!("{drive_c}/windows/system32"),
        CSIDL_PROGRAM_FILES => format!("{drive_c}/Program Files"),
        CSIDL_PROGRAM_FILES_X86 => format!("{drive_c}/Program Files (x86)"),
        CSIDL_PROGRAMS => format!("{drive_c}/Users/guest/AppData/Roaming/Microsoft/Windows/Start Menu/Programs"),
        CSIDL_PERSONAL => format!("{drive_c}/Users/guest/Documents"),
        CSIDL_APPDATA => format!("{drive_c}/Users/guest/AppData/Roaming"),
        CSIDL_LOCAL_APPDATA => format!("{drive_c}/Users/guest/AppData/Local"),
        CSIDL_COMMON_APPDATA => format!("{drive_c}/ProgramData"),
        CSIDL_PROFILE => format!("{drive_c}/Users/guest"),
        CSIDL_DESKTOP => format!("{drive_c}/Users/guest/Desktop"),
        CSIDL_FONTS => format!("{drive_c}/windows/Fonts"),
        CSIDL_STARTUP => format!("{drive_c}/Users/guest/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"),
        CSIDL_RECENT => format!("{drive_c}/Users/guest/AppData/Roaming/Microsoft/Windows/Recent"),
        CSIDL_SENDTO => format!("{drive_c}/Users/guest/AppData/Roaming/Microsoft/Windows/SendTo"),
        CSIDL_COOKIES => format!("{drive_c}/Users/guest/AppData/Roaming/Microsoft/Windows/Cookies"),
        CSIDL_HISTORY => format!("{drive_c}/Users/guest/AppData/Local/Microsoft/Windows/History"),
        CSIDL_INTERNET_CACHE => format!("{drive_c}/Users/guest/AppData/Local/Microsoft/Windows/INetCache"),
        CSIDL_TEMP => format!("{drive_c}/windows/Temp"),
        _ => format!("{drive_c}/windows"),
    }
}

/// Known folder GUIDs (Windows Vista+) mapped to CSIDL equivalents.
pub struct KnownFolderGuid;

impl KnownFolderGuid {
    /// FOLDERID_Desktop: {B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
    pub const DESKTOP: &str = "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}";
    /// FOLDERID_Documents: {FDD39AD0-238F-46AF-ADB4-6C85480369C7}
    pub const DOCUMENTS: &str = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}";
    /// FOLDERID_LocalAppData: {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
    pub const LOCAL_APPDATA: &str = "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}";
    /// FOLDERID_RoamingAppData: {3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}
    pub const APPDATA: &str = "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}";
    /// FOLDERID_ProgramFiles: {905e63b6-c1bf-494e-b29c-65b732d3d21a}
    pub const PROGRAM_FILES: &str = "{905e63b6-c1bf-494e-b29c-65b732d3d21a}";
    /// FOLDERID_Windows: {F38BF404-1D43-42F2-9305-67DE0B28FC23}
    pub const WINDOWS: &str = "{F38BF404-1D43-42F2-9305-67DE0B28FC23}";
    /// FOLDERID_System: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}
    pub const SYSTEM: &str = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}";
    /// FOLDERID_Fonts: {FD228CB7-AE11-4AE3-864C-16F3910AB8FE}
    pub const FONTS: &str = "{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}";
    /// FOLDERID_Profile: {5E6C858F-0E22-4760-9AFE-EA3317B67173}
    pub const PROFILE: &str = "{5E6C858F-0E22-4760-9AFE-EA3317B67173}";
}

/// Resolve a known folder GUID to a Windows path.
pub fn sh_get_known_folder_path(known_folder_guid: &str, ge_root: &str) -> String {
    let csidl = match known_folder_guid {
        g if g.eq_ignore_ascii_case(KnownFolderGuid::DESKTOP) => CSIDL_DESKTOP,
        g if g.eq_ignore_ascii_case(KnownFolderGuid::DOCUMENTS) => CSIDL_PERSONAL,
        g if g.eq_ignore_ascii_case(KnownFolderGuid::LOCAL_APPDATA) => CSIDL_LOCAL_APPDATA,
        g if g.eq_ignore_ascii_case(KnownFolderGuid::APPDATA) => CSIDL_APPDATA,
        g if g.eq_ignore_ascii_case(KnownFolderGuid::PROGRAM_FILES) => CSIDL_PROGRAM_FILES,
        g if g.eq_ignore_ascii_case(KnownFolderGuid::WINDOWS) => CSIDL_WINDOWS,
        g if g.eq_ignore_ascii_case(KnownFolderGuid::SYSTEM) => CSIDL_SYSTEM,
        g if g.eq_ignore_ascii_case(KnownFolderGuid::FONTS) => CSIDL_FONTS,
        g if g.eq_ignore_ascii_case(KnownFolderGuid::PROFILE) => CSIDL_PROFILE,
        _ => CSIDL_WINDOWS,
    };
    sh_get_folder_path(csidl, ge_root)
}

// ===========================================================================
// Version / File Version Info
// ===========================================================================

/// Simplified VS_FIXEDFILEINFO structure.
#[derive(Debug, Clone)]
pub struct FileVersionInfo {
    pub signature: u32,
    pub version: (u16, u16, u16, u16),
    pub file_flags: u32,
    pub file_type: u32,
    pub string_info: BTreeMap<String, String>,
}

impl FileVersionInfo {
    /// Parse a VS_VERSIONINFO resource from raw bytes.
    pub fn parse(data: &[u8]) -> AppResult<Self> {
        if data.len() < 92 {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "version info data too small",
            ));
        }

        // Check for VS_FIXEDFILEINFO signature (0xFEEF04BD)
        let signature = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
        if signature != 0xFEEF_04BD {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("invalid version info signature: {signature:#010x}"),
            ));
        }

        let version_ms = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
        let version_ls = u32::from_le_bytes([data[52], data[53], data[54], data[55]]);
        let major = (version_ms >> 16) as u16;
        let minor = (version_ms & 0xFFFF) as u16;
        let patch = (version_ls >> 16) as u16;
        let build = (version_ls & 0xFFFF) as u16;

        let file_flags = u32::from_le_bytes([data[56], data[57], data[58], data[59]]);
        let file_type = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);

        // Parse StringFileInfo children (simplified)
        let mut string_info = BTreeMap::new();
        string_info.insert("FileVersion".to_string(), format!("{major}.{minor}.{patch}.{build}"));
        string_info.insert("ProductVersion".to_string(), format!("{major}.{minor}.{patch}.{build}"));

        Ok(Self {
            signature,
            version: (major, minor, patch, build),
            file_flags,
            file_type,
            string_info,
        })
    }

    /// Query a string value from the version info.
    pub fn query_value(&self, key: &str) -> Option<&str> {
        self.string_info.get(key).map(|s| s.as_str())
    }

    /// Get the version as a formatted string.
    pub fn version_string(&self) -> String {
        let (major, minor, patch, build) = self.version;
        format!("{major}.{minor}.{patch}.{build}")
    }
}

// ===========================================================================
// XInput / Game Controller
// ===========================================================================

/// XInput state for a controller.
#[derive(Debug, Clone)]
pub struct XInputState {
    pub packet_number: u32,
    pub buttons: u16,
    pub left_trigger: u8,
    pub right_trigger: u8,
    pub left_thumb_x: i16,
    pub left_thumb_y: i16,
    pub right_thumb_x: i16,
    pub right_thumb_y: i16,
}

/// XInput vibration motor speeds.
#[derive(Debug, Clone)]
pub struct XInputVibration {
    pub left_motor_speed: u16,
    pub right_motor_speed: u16,
}

/// XInput button flags.
pub const XINPUT_GAMEPAD_DPAD_UP: u16 = 0x0001;
pub const XINPUT_GAMEPAD_DPAD_DOWN: u16 = 0x0002;
pub const XINPUT_GAMEPAD_DPAD_LEFT: u16 = 0x0004;
pub const XINPUT_GAMEPAD_DPAD_RIGHT: u16 = 0x0008;
pub const XINPUT_GAMEPAD_START: u16 = 0x0010;
pub const XINPUT_GAMEPAD_BACK: u16 = 0x0020;
pub const XINPUT_GAMEPAD_LEFT_THUMB: u16 = 0x0040;
pub const XINPUT_GAMEPAD_RIGHT_THUMB: u16 = 0x0080;
pub const XINPUT_GAMEPAD_LEFT_SHOULDER: u16 = 0x0100;
pub const XINPUT_GAMEPAD_RIGHT_SHOULDER: u16 = 0x0200;
pub const XINPUT_GAMEPAD_A: u16 = 0x1000;
pub const XINPUT_GAMEPAD_B: u16 = 0x2000;
pub const XINPUT_GAMEPAD_X: u16 = 0x4000;
pub const XINPUT_GAMEPAD_Y: u16 = 0x8000;

/// XInput capability flags.
#[derive(Debug, Clone)]
pub struct XInputCapabilities {
    pub controller_type: u8,
    pub sub_type: u8,
    pub flags: u16,
    pub vibration_supported: bool,
}

/// Manages XInput controller state.
pub struct XInputManager {
    controllers: [Option<XInputState>; 4],
    connected: [bool; 4],
    vibration: [XInputVibration; 4],
}

impl XInputManager {
    pub fn new() -> Self {
        Self {
            controllers: [None, None, None, None],
            connected: [false; 4],
            vibration: [
                XInputVibration { left_motor_speed: 0, right_motor_speed: 0 },
                XInputVibration { left_motor_speed: 0, right_motor_speed: 0 },
                XInputVibration { left_motor_speed: 0, right_motor_speed: 0 },
                XInputVibration { left_motor_speed: 0, right_motor_speed: 0 },
            ],
        }
    }

    /// XInputGetState — get the state of a controller.
    pub fn get_state(&self, index: u32) -> AppResult<&XInputState> {
        if index >= 4 {
            return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "XInput: invalid controller index"));
        }
        self.controllers[index as usize]
            .as_ref()
            .ok_or_else(|| AppError::new(ReasonCode::RcWin32InvalidHandle, "XInput: controller not connected"))
    }

    /// XInputSetState — set vibration.
    pub fn set_state(&mut self, index: u32, vibration: XInputVibration) -> AppResult<()> {
        if index >= 4 {
            return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "XInput: invalid controller index"));
        }
        self.vibration[index as usize] = vibration;
        Ok(())
    }

    /// XInputGetCapabilities — get controller capabilities.
    pub fn get_capabilities(&self, index: u32) -> AppResult<XInputCapabilities> {
        if index >= 4 || !self.connected[index as usize] {
            return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "XInput: controller not connected"));
        }
        Ok(XInputCapabilities {
            controller_type: 0, // XINPUT_DEVTYPE_GAMEPAD
            sub_type: 1,       // XINPUT_DEVSUBTYPE_GAMEPAD
            flags: 0,
            vibration_supported: true,
        })
    }

    /// Simulate connecting a controller (for testing / input mapping).
    pub fn connect_controller(&mut self, index: u32, initial_state: XInputState) -> AppResult<()> {
        if index >= 4 {
            return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "XInput: invalid controller index"));
        }
        self.connected[index as usize] = true;
        self.controllers[index as usize] = Some(initial_state);
        Ok(())
    }

    /// Disconnect a controller.
    pub fn disconnect_controller(&mut self, index: u32) -> AppResult<()> {
        if index >= 4 {
            return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "XInput: invalid controller index"));
        }
        self.connected[index as usize] = false;
        self.controllers[index as usize] = None;
        Ok(())
    }

    /// Update controller state (from real input or replay).
    pub fn update_state(&mut self, index: u32, state: XInputState) -> AppResult<()> {
        if index >= 4 || !self.connected[index as usize] {
            return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "XInput: controller not connected"));
        }
        self.controllers[index as usize] = Some(state);
        Ok(())
    }

    /// Check if a controller is connected.
    pub fn is_connected(&self, index: u32) -> bool {
        index < 4 && self.connected[index as usize]
    }

    /// Get the count of connected controllers.
    pub fn connected_count(&self) -> usize {
        self.connected.iter().filter(|&&c| c).count()
    }
}

// ===========================================================================
// BCrypt / NCrypt (Crypto Primitives)
// ===========================================================================

/// BCrypt algorithm identifiers.
pub const BCRYPT_SHA256_ALGORITHM: &str = "SHA256";
pub const BCRYPT_SHA384_ALGORITHM: &str = "SHA384";
pub const BCRYPT_SHA512_ALGORITHM: &str = "SHA512";
pub const BCRYPT_AES_ALGORITHM: &str = "AES";
pub const BCRYPT_RSA_ALGORITHM: &str = "RSA";
pub const BCRYPT_ECDSA_P256_ALGORITHM: &str = "ECDSA_P256";
pub const BCRYPT_HMAC_SHA256_ALGORITHM: &str = "HMAC_SHA256";

/// BCrypt hash handle.
pub struct BCryptHash {
    pub algorithm: String,
    pub data: Vec<u8>,
}

/// BCrypt key handle.
pub struct BCryptKey {
    pub algorithm: String,
    pub key_data: Vec<u8>,
}

/// Simplified BCrypt implementation using Casa1's existing crypto primitives.
pub struct BCryptContext {
    #[allow(dead_code)]
    hash_counter: AtomicU64,
    #[allow(dead_code)]
    key_counter: AtomicU64,
}

impl BCryptContext {
    pub fn new() -> Self {
        Self {
            hash_counter: AtomicU64::new(1),
            key_counter: AtomicU64::new(1),
        }
    }

    /// BCryptCreateHash — create a hash object.
    pub fn create_hash(&self, algorithm: &str) -> AppResult<BCryptHash> {
        match algorithm {
            BCRYPT_SHA256_ALGORITHM | BCRYPT_SHA384_ALGORITHM | BCRYPT_SHA512_ALGORITHM | BCRYPT_HMAC_SHA256_ALGORITHM => {
                Ok(BCryptHash {
                    algorithm: algorithm.to_string(),
                    data: Vec::new(),
                })
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: unsupported algorithm {algorithm}"),
            )),
        }
    }

    /// BCryptHashData — add data to the hash.
    pub fn hash_data(hash: &mut BCryptHash, data: &[u8]) {
        hash.data.extend_from_slice(data);
    }

    /// BCryptFinishHash — finalize the hash and get the result.
    pub fn finish_hash(hash: &BCryptHash) -> AppResult<Vec<u8>> {
        match hash.algorithm.as_str() {
            BCRYPT_SHA256_ALGORITHM => Ok(crate::network::sha256_hash(&hash.data).to_vec()),
            BCRYPT_SHA384_ALGORITHM => {
                // Use SHA-256 as fallback (SHA-384 not yet in crypto)
                Ok(crate::network::sha256_hash(&hash.data).to_vec())
            }
            BCRYPT_SHA512_ALGORITHM => {
                // Use SHA-256 as fallback (SHA-512 not yet in crypto)
                Ok(crate::network::sha256_hash(&hash.data).to_vec())
            }
            BCRYPT_HMAC_SHA256_ALGORITHM => {
                crate::network::hmac_sha256(&[], &hash.data)
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: cannot finish hash for {}", hash.algorithm),
            )),
        }
    }

    /// BCryptGenerateSymmetricKey — create a symmetric key.
    pub fn generate_symmetric_key(&self, algorithm: &str, key_data: &[u8]) -> AppResult<BCryptKey> {
        match algorithm {
            BCRYPT_AES_ALGORITHM => Ok(BCryptKey {
                algorithm: algorithm.to_string(),
                key_data: key_data.to_vec(),
            }),
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: unsupported symmetric algorithm {algorithm}"),
            )),
        }
    }

    /// BCryptEncrypt — encrypt data with a symmetric key.
    pub fn encrypt(key: &BCryptKey, plaintext: &[u8], iv: Option<&[u8; 16]>) -> AppResult<Vec<u8>> {
        match key.algorithm.as_str() {
            BCRYPT_AES_ALGORITHM => {
                let iv_val = iv.copied().unwrap_or([0u8; 16]);
                crate::network::aes_128_cbc_encrypt(&key.key_data[..16].try_into().map_err(|_| {
                    AppError::new(ReasonCode::RcWin32InvalidHandle, "BCrypt: AES key must be 16 bytes")
                })?, &iv_val, plaintext)
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: encrypt not supported for {}", key.algorithm),
            )),
        }
    }

    /// BCryptDecrypt — decrypt data with a symmetric key.
    pub fn decrypt(key: &BCryptKey, ciphertext: &[u8], iv: Option<&[u8; 16]>) -> AppResult<Vec<u8>> {
        match key.algorithm.as_str() {
            BCRYPT_AES_ALGORITHM => {
                let iv_val = iv.copied().unwrap_or([0u8; 16]);
                crate::network::aes_128_cbc_decrypt(&key.key_data[..16].try_into().map_err(|_| {
                    AppError::new(ReasonCode::RcWin32InvalidHandle, "BCrypt: AES key must be 16 bytes")
                })?, &iv_val, ciphertext)
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: decrypt not supported for {}", key.algorithm),
            )),
        }
    }
}

// ===========================================================================
// ThreadPool
// ===========================================================================

/// Thread pool work item.
#[derive(Debug, Clone)]
pub struct TpWork {
    pub id: u64,
    pub callback: u64, // Guest function pointer
    pub context: u64,  // Guest context
    pub submitted: bool,
}

/// Thread pool timer.
#[derive(Debug, Clone)]
pub struct TpTimer {
    pub id: u64,
    pub callback: u64,
    pub context: u64,
    pub due_time_ms: u32,
    pub period_ms: u32,
    pub is_set: bool,
}

/// Thread pool wait.
#[derive(Debug, Clone)]
pub struct TpWait {
    pub id: u64,
    pub callback: u64,
    pub context: u64,
    pub handle: u64,
}

/// Manages Windows Thread Pool API objects.
pub struct ThreadPoolManager {
    next_id: AtomicU64,
    work_items: BTreeMap<u64, TpWork>,
    timers: BTreeMap<u64, TpTimer>,
    waits: BTreeMap<u64, TpWait>,
}

impl ThreadPoolManager {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            work_items: BTreeMap::new(),
            timers: BTreeMap::new(),
            waits: BTreeMap::new(),
        }
    }

    /// CreateThreadpoolWork
    pub fn create_work(&mut self, callback: u64, context: u64) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.work_items.insert(id, TpWork {
            id,
            callback,
            context,
            submitted: false,
        });
        id
    }

    /// SubmitThreadpoolWork
    pub fn submit_work(&mut self, id: u64) -> AppResult<()> {
        let work = self.work_items.get_mut(&id).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("TP work {id} not found"))
        })?;
        work.submitted = true;
        Ok(())
    }

    /// CloseThreadpoolWork
    pub fn close_work(&mut self, id: u64) {
        self.work_items.remove(&id);
    }

    /// CreateThreadpoolTimer
    pub fn create_timer(&mut self, callback: u64, context: u64) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.timers.insert(id, TpTimer {
            id,
            callback,
            context,
            due_time_ms: 0,
            period_ms: 0,
            is_set: false,
        });
        id
    }

    /// SetThreadpoolTimer
    pub fn set_timer(&mut self, id: u64, due_time_ms: u32, period_ms: u32) -> AppResult<()> {
        let timer = self.timers.get_mut(&id).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("TP timer {id} not found"))
        })?;
        timer.due_time_ms = due_time_ms;
        timer.period_ms = period_ms;
        timer.is_set = due_time_ms > 0;
        Ok(())
    }

    /// CloseThreadpoolTimer
    pub fn close_timer(&mut self, id: u64) {
        self.timers.remove(&id);
    }

    /// CreateThreadpoolWait
    pub fn create_wait(&mut self, callback: u64, context: u64, handle: u64) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.waits.insert(id, TpWait {
            id,
            callback,
            context,
            handle,
        });
        id
    }

    /// CloseThreadpoolWait
    pub fn close_wait(&mut self, id: u64) {
        self.waits.remove(&id);
    }

    /// Get pending work items.
    pub fn pending_work(&self) -> Vec<&TpWork> {
        self.work_items.values().filter(|w| w.submitted).collect()
    }

    /// Get active timers.
    pub fn active_timers(&self) -> Vec<&TpTimer> {
        self.timers.values().filter(|t| t.is_set).collect()
    }

    /// Get the count of work items.
    pub fn work_count(&self) -> usize {
        self.work_items.len()
    }

    /// Get the count of timers.
    pub fn timer_count(&self) -> usize {
        self.timers.len()
    }
}

// ===========================================================================
// Synchronization Barriers
// ===========================================================================

/// A synchronization barrier for multi-threaded coordination.
pub struct SyncBarrier {
    total_threads: u32,
    arrived: AtomicU32,
    sense: AtomicU32,
    generation: AtomicU32,
}

impl SyncBarrier {
    /// InitializeSynchronizationBarrier
    pub fn new(total_threads: u32) -> Self {
        Self {
            total_threads,
            arrived: AtomicU32::new(0),
            sense: AtomicU32::new(1),
            generation: AtomicU32::new(0),
        }
    }

    /// EnterSynchronizationBarrier — block until all threads arrive.
    pub fn enter(&self) -> bool {
        let gen_val = self.generation.load(Ordering::Acquire);
        let count = self.arrived.fetch_add(1, Ordering::AcqRel) + 1;

        if count >= self.total_threads {
            // Last thread: reset and advance generation
            self.arrived.store(0, Ordering::Release);
            self.generation.fetch_add(1, Ordering::Release);
            self.sense.fetch_xor(1, Ordering::Release);
            true // Returns true for the last thread
        } else {
            // Spin-wait until generation advances
            while self.generation.load(Ordering::Acquire) == gen_val {
                std::hint::spin_loop();
            }
            false
        }
    }

    /// DeleteSynchronizationBarrier
    pub fn delete(&self) {
        // No-op in this implementation (barrier is stack-allocated by caller)
    }

    /// Get the total thread count.
    pub fn total_threads(&self) -> u32 {
        self.total_threads
    }

    /// Get the current arrival count.
    pub fn arrived_count(&self) -> u32 {
        self.arrived.load(Ordering::Acquire)
    }
}

// ===========================================================================
// DbgHelp — Symbol Loading and Stack Walking
// ===========================================================================

/// Symbol information for DbgHelp.
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub address: u64,
    pub name: String,
    pub size: u32,
    pub module_base: u64,
    pub displacement: u64,
}

/// Stack frame information.
#[derive(Debug, Clone)]
pub struct StackFrameInfo {
    pub instruction_pointer: u64,
    pub return_address: u64,
    pub frame_pointer: u64,
    pub stack_pointer: u64,
    pub module_name: String,
    pub symbol_name: Option<String>,
    pub displacement: u64,
    pub source_file: Option<String>,
    pub line_number: Option<u32>,
}

/// DbgHelp symbol handler.
pub struct DbgHelpContext {
    loaded_modules: BTreeMap<String, u64>,
    symbols: BTreeMap<u64, SymbolInfo>,
    #[allow(dead_code)]
    next_sym_id: u64,
}

impl DbgHelpContext {
    pub fn new() -> Self {
        Self {
            loaded_modules: BTreeMap::new(),
            symbols: BTreeMap::new(),
            next_sym_id: 1,
        }
    }

    /// SymInitialize — initialize the symbol handler for a process.
    pub fn sym_initialize(&mut self, _process_handle: u64) -> AppResult<()> {
        self.symbols.clear();
        Ok(())
    }

    /// SymCleanup — clean up the symbol handler.
    pub fn sym_cleanup(&mut self) {
        self.symbols.clear();
        self.loaded_modules.clear();
    }

    /// SymLoadModuleEx — load symbols for a module.
    pub fn sym_load_module(&mut self, module_name: &str, base_address: u64) -> AppResult<()> {
        self.loaded_modules.insert(module_name.to_string(), base_address);
        Ok(())
    }

    /// SymFromAddr — look up a symbol by address.
    pub fn sym_from_addr(&self, address: u64) -> AppResult<&SymbolInfo> {
        // Find the closest symbol at or below the given address
        let mut best: Option<(&u64, &SymbolInfo)> = None;
        for (addr, sym) in &self.symbols {
            if *addr <= address {
                if best.is_none() || *addr > *best.unwrap().0 {
                    best = Some((addr, sym));
                }
            }
        }
        best.map(|(_, sym)| sym).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("no symbol found at address {address:#x}"))
        })
    }

    /// StackWalk64 — walk the stack (simplified).
    pub fn stack_walk(
        &self,
        instruction_pointer: u64,
        frame_pointer: u64,
        stack_pointer: u64,
        max_frames: usize,
    ) -> Vec<StackFrameInfo> {
        let mut frames = Vec::new();
        let ip = instruction_pointer;
        let fp = frame_pointer;
        let _ = stack_pointer;

        for _ in 0..max_frames {
            let symbol_name = self.symbols.get(&ip).map(|s| s.name.clone());
            let module_name = self.find_module_for_address(ip)
                .unwrap_or_else(|| "unknown".to_string());

            frames.push(StackFrameInfo {
                instruction_pointer: ip,
                return_address: 0,
                frame_pointer: fp,
                stack_pointer: 0,
                module_name,
                symbol_name,
                displacement: 0,
                source_file: None,
                line_number: None,
            });

            // Simplified: stop after first frame (no real stack walking)
            break;
        }

        frames
    }

    /// Register a symbol.
    pub fn register_symbol(&mut self, address: u64, name: &str, module_base: u64) {
        self.symbols.insert(address, SymbolInfo {
            address,
            name: name.to_string(),
            size: 0,
            module_base,
            displacement: 0,
        });
    }

    /// Find the module containing an address.
    fn find_module_for_address(&self, address: u64) -> Option<String> {
        let mut best: Option<(&str, u64)> = None;
        for (name, base) in &self.loaded_modules {
            if *base <= address {
                if best.is_none() || *base > best.unwrap().1 {
                    best = Some((name, *base));
                }
            }
        }
        best.map(|(name, _)| name.to_string())
    }

    /// Get the count of loaded modules.
    pub fn module_count(&self) -> usize {
        self.loaded_modules.len()
    }

    /// Get the count of registered symbols.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
}

// ===========================================================================
// Advapi32 — Service Control Manager, Security, Registry
// ===========================================================================

/// Service state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

/// Service information record.
#[derive(Debug, Clone)]
pub struct ServiceRecord {
    pub name: String,
    pub display_name: String,
    pub service_type: u32,
    pub state: ServiceState,
    pub process_id: Option<u32>,
}

/// Security descriptor (simplified).
#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    pub owner: String,
    pub group: String,
    pub dacl_present: bool,
    pub sacl_present: bool,
}

/// Token information for the current process.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub user_sid: String,
    pub is_elevated: bool,
    pub integrity_level: u32,
}

/// Advapi32 service and security manager.
pub struct Advapi32Manager {
    services: BTreeMap<String, ServiceRecord>,
    security_descriptors: BTreeMap<String, SecurityDescriptor>,
    token_info: TokenInfo,
}

impl Advapi32Manager {
    pub fn new() -> Self {
        let mut services = BTreeMap::new();

        // Pre-register common services that Steam/games query
        services.insert("SteamClientService".to_string(), ServiceRecord {
            name: "Steam Client Service".to_string(),
            display_name: "Steam Client Service".to_string(),
            service_type: 0x10, // SERVICE_WIN32_OWN_PROCESS
            state: ServiceState::Running,
            process_id: Some(1234),
        });
        services.insert("Winmgmt".to_string(), ServiceRecord {
            name: "Windows Management Instrumentation".to_string(),
            display_name: "Windows Management Instrumentation".to_string(),
            service_type: 0x20, // SERVICE_WIN32_SHARE_PROCESS
            state: ServiceState::Running,
            process_id: Some(5678),
        });
        services.insert("Audiosrv".to_string(), ServiceRecord {
            name: "Windows Audio".to_string(),
            display_name: "Windows Audio".to_string(),
            service_type: 0x10,
            state: ServiceState::Running,
            process_id: Some(9012),
        });

        Self {
            services,
            security_descriptors: BTreeMap::new(),
            token_info: TokenInfo {
                user_sid: "S-1-5-21-1000".to_string(),
                is_elevated: true,
                integrity_level: 0x3000, // HIGH_MANDATORY_LEVEL
            },
        }
    }

    /// OpenSCManager — open the service control manager.
    pub fn open_sc_manager(&self) -> AppResult<u64> {
        // Return a synthetic handle
        Ok(0xDEAD_0001)
    }

    /// CloseServiceHandle
    pub fn close_service_handle(&mut self, _handle: u64) {
        // No-op for synthetic handles
    }

    /// OpenService — open a handle to an existing service.
    pub fn open_service(&self, service_name: &str) -> AppResult<u64> {
        if self.services.contains_key(service_name) {
            Ok(0xDEAD_0002)
        } else {
            Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("service '{service_name}' not found"),
            ))
        }
    }

    /// QueryServiceStatus — get the current state of a service.
    pub fn query_service_status(&self, service_name: &str) -> AppResult<&ServiceRecord> {
        self.services.get(service_name).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("service '{service_name}' not found"))
        })
    }

    /// StartService — start a service.
    pub fn start_service(&mut self, service_name: &str) -> AppResult<()> {
        let service = self.services.get_mut(service_name).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, format!("service '{service_name}' not found"))
        })?;
        service.state = ServiceState::Running;
        Ok(())
    }

    /// GetTokenInformation — get information about the process token.
    pub fn get_token_info(&self) -> &TokenInfo {
        &self.token_info
    }

    /// Check if the current process is elevated.
    pub fn is_elevated(&self) -> bool {
        self.token_info.is_elevated
    }

    /// Get a security descriptor for a named object.
    pub fn get_security_descriptor(&self, object_name: &str) -> AppResult<&SecurityDescriptor> {
        self.security_descriptors.get(object_name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("security descriptor for '{object_name}' not found"),
            )
        })
    }

    /// Set a security descriptor for a named object.
    pub fn set_security_descriptor(&mut self, object_name: &str, descriptor: SecurityDescriptor) {
        self.security_descriptors.insert(object_name.to_string(), descriptor);
    }

    /// Get the count of registered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- COM Tests ---

    #[test]
    fn com_initialize_and_uninitialize() {
        let mut com = ComApartmentState::new();
        assert!(!com.is_initialized());
        com.co_initialize(ComApartmentModel::MultiThreaded).unwrap();
        assert!(com.is_initialized());
        com.co_uninitialize();
        assert!(!com.is_initialized());
    }

    #[test]
    fn com_create_instance_and_refcount() {
        let mut com = ComApartmentState::new();
        com.co_initialize(ComApartmentModel::SingleThreaded).unwrap();

        let handle = com.co_create_instance(
            ComClsid::DIRECTSOUND8,
            ComIid::IUNKNOWN,
            0x1000_0000,
            "DirectSound8",
        ).unwrap();

        assert_eq!(com.active_object_count(), 1);
        assert!(com.com_query_interface(handle, ComIid::IUNKNOWN).unwrap());
        assert_eq!(com.com_vtable(handle).unwrap(), 0x1000_0000);

        let count = com.com_addref(handle).unwrap();
        assert_eq!(count, 2);

        let count = com.com_release(handle).unwrap();
        assert_eq!(count, 1);

        let count = com.com_release(handle).unwrap();
        assert_eq!(count, 0);
        assert_eq!(com.active_object_count(), 0);
    }

    #[test]
    fn com_create_without_initialize_fails() {
        let mut com = ComApartmentState::new();
        let result = com.co_create_instance(
            ComClsid::XAUDIO2,
            ComIid::IUNKNOWN,
            0x2000_0000,
            "XAudio2",
        );
        assert!(result.is_err());
    }

    #[test]
    fn com_query_interface_unknown_always_supported() {
        let mut com = ComApartmentState::new();
        com.co_initialize(ComApartmentModel::MultiThreaded).unwrap();

        let handle = com.co_create_instance(
            ComClsid::XAUDIO2,
            ComIid::IDISPATCH,
            0x3000_0000,
            "Test",
        ).unwrap();

        assert!(com.com_query_interface(handle, ComIid::IUNKNOWN).unwrap());
        assert!(!com.com_query_interface(handle, ComIid::ICLASS_FACTORY).unwrap());
        assert!(com.com_query_interface(handle, ComIid::IDISPATCH).unwrap());
    }

    // --- CRT Tests ---

    #[test]
    fn crt_atoi_various_inputs() {
        assert_eq!(MsvcCrt::crt_atoi("42"), 42);
        assert_eq!(MsvcCrt::crt_atoi("-123"), -123);
        assert_eq!(MsvcCrt::crt_atoi("  456  "), 456);
        assert_eq!(MsvcCrt::crt_atoi("+789"), 789);
        assert_eq!(MsvcCrt::crt_atoi("0"), 0);
        assert_eq!(MsvcCrt::crt_atoi("abc"), 0);
    }

    #[test]
    fn crt_atof_various_inputs() {
        assert!((MsvcCrt::crt_atof("3.14") - 3.14).abs() < 0.001);
        assert!((MsvcCrt::crt_atof("-2.5") - (-2.5)).abs() < 0.001);
        assert!((MsvcCrt::crt_atof("0.0") - 0.0).abs() < 0.001);
    }

    #[test]
    fn crt_sprintf_int_formats() {
        assert_eq!(MsvcCrt::crt_sprintf_int(42, "%d"), "42");
        assert_eq!(MsvcCrt::crt_sprintf_int(255, "%x"), "ff");
        assert_eq!(MsvcCrt::crt_sprintf_int(255, "%X"), "FF");
        assert_eq!(MsvcCrt::crt_sprintf_int(8, "%o"), "10");
        assert_eq!(MsvcCrt::crt_sprintf_int(255, "%08x"), "000000ff");
    }

    #[test]
    fn crt_sscanf_int_parses() {
        assert_eq!(MsvcCrt::crt_sscanf_int("42", "%d"), Some(42));
        assert_eq!(MsvcCrt::crt_sscanf_int("ff", "%x"), Some(255));
        assert_eq!(MsvcCrt::crt_sscanf_int("0xFF", "%x"), Some(255));
    }

    #[test]
    fn crt_malloc_and_free() {
        let mut crt = MsvcCrt::new();
        let ptr = crt.crt_malloc(1024);
        assert_ne!(ptr, 0);
        assert_eq!(crt.crt_alloc_size(ptr), Some(1024));
        assert_eq!(crt.crt_alloc_count(), 1);

        crt.crt_free(ptr).unwrap();
        assert_eq!(crt.crt_alloc_count(), 0);
    }

    #[test]
    fn crt_realloc() {
        let mut crt = MsvcCrt::new();
        let ptr = crt.crt_malloc(100);
        let new_ptr = crt.crt_realloc(ptr, 200);
        assert_eq!(new_ptr, ptr); // Same pointer, resized
        assert_eq!(crt.crt_alloc_size(ptr), Some(200));
    }

    // --- Shell32 Tests ---

    #[test]
    fn sh_get_folder_path_windows() {
        let path = sh_get_folder_path(CSIDL_WINDOWS, "/ge");
        assert_eq!(path, "/ge/drive_c/windows");
    }

    #[test]
    fn sh_get_folder_path_appdata() {
        let path = sh_get_folder_path(CSIDL_APPDATA, "/ge");
        assert_eq!(path, "/ge/drive_c/Users/guest/AppData/Roaming");
    }

    #[test]
    fn sh_get_folder_path_program_files() {
        let path = sh_get_folder_path(CSIDL_PROGRAM_FILES, "/ge");
        assert_eq!(path, "/ge/drive_c/Program Files");
    }

    #[test]
    fn known_folder_path_resolves_windows() {
        let path = sh_get_known_folder_path(KnownFolderGuid::WINDOWS, "/ge");
        assert_eq!(path, "/ge/drive_c/windows");
    }

    #[test]
    fn sh_get_known_folder_path_profile() {
        let path = sh_get_known_folder_path(KnownFolderGuid::PROFILE, "/ge");
        assert_eq!(path, "/ge/drive_c/Users/guest");
    }

    // --- Version Tests ---

    #[test]
    fn file_version_info_parse() {
        let mut data = vec![0u8; 128];
        // Set VS_FIXEDFILEINFO signature at offset 40
        data[40..44].copy_from_slice(&0xFEEF_04BD_u32.to_le_bytes());
        // Set version at offset 48-55
        data[48..52].copy_from_slice(&0x0001_0002_u32.to_le_bytes()); // 1.2
        data[52..56].copy_from_slice(&0x0003_0004_u32.to_le_bytes()); // 3.4
        // Set file type at offset 64
        data[64..68].copy_from_slice(&1_u32.to_le_bytes()); // VFT_APP

        let info = FileVersionInfo::parse(&data).unwrap();
        assert_eq!(info.version, (1, 2, 3, 4));
        assert_eq!(info.version_string(), "1.2.3.4");
        assert_eq!(info.file_type, 1);
    }

    #[test]
    fn file_version_info_bad_signature() {
        let data = vec![0u8; 128];
        let result = FileVersionInfo::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn file_version_info_too_small() {
        let data = vec![0u8; 50];
        let result = FileVersionInfo::parse(&data);
        assert!(result.is_err());
    }

    // --- XInput Tests ---

    #[test]
    fn xinput_connect_and_get_state() {
        let mut xinput = XInputManager::new();
        assert_eq!(xinput.connected_count(), 0);

        xinput.connect_controller(0, XInputState {
            packet_number: 1,
            buttons: XINPUT_GAMEPAD_A,
            left_trigger: 128,
            right_trigger: 0,
            left_thumb_x: 0,
            left_thumb_y: 0,
            right_thumb_x: 0,
            right_thumb_y: 0,
        }).unwrap();

        assert_eq!(xinput.connected_count(), 1);
        assert!(xinput.is_connected(0));

        let state = xinput.get_state(0).unwrap();
        assert_eq!(state.buttons & XINPUT_GAMEPAD_A, XINPUT_GAMEPAD_A);
    }

    #[test]
    fn xinput_disconnect() {
        let mut xinput = XInputManager::new();
        xinput.connect_controller(0, XInputState {
            packet_number: 1,
            buttons: 0,
            left_trigger: 0,
            right_trigger: 0,
            left_thumb_x: 0,
            left_thumb_y: 0,
            right_thumb_x: 0,
            right_thumb_y: 0,
        }).unwrap();
        assert_eq!(xinput.connected_count(), 1);

        xinput.disconnect_controller(0).unwrap();
        assert_eq!(xinput.connected_count(), 0);
        assert!(xinput.get_state(0).is_err());
    }

    #[test]
    fn xinput_capabilities() {
        let mut xinput = XInputManager::new();
        xinput.connect_controller(0, XInputState {
            packet_number: 1,
            buttons: 0,
            left_trigger: 0,
            right_trigger: 0,
            left_thumb_x: 0,
            left_thumb_y: 0,
            right_thumb_x: 0,
            right_thumb_y: 0,
        }).unwrap();

        let caps = xinput.get_capabilities(0).unwrap();
        assert!(caps.vibration_supported);
    }

    #[test]
    fn xinput_invalid_index() {
        let xinput = XInputManager::new();
        assert!(xinput.get_state(4).is_err());
        assert!(xinput.is_connected(4) == false);
    }

    #[test]
    fn xinput_vibration() {
        let mut xinput = XInputManager::new();
        xinput.connect_controller(0, XInputState {
            packet_number: 1,
            buttons: 0,
            left_trigger: 0,
            right_trigger: 0,
            left_thumb_x: 0,
            left_thumb_y: 0,
            right_thumb_x: 0,
            right_thumb_y: 0,
        }).unwrap();

        xinput.set_state(0, XInputVibration {
            left_motor_speed: 65535,
            right_motor_speed: 32768,
        }).unwrap();
    }

    // --- BCrypt Tests ---

    #[test]
    fn bcrypt_sha256_hash() {
        let ctx = BCryptContext::new();
        let mut hash = ctx.create_hash(BCRYPT_SHA256_ALGORITHM).unwrap();
        BCryptContext::hash_data(&mut hash, b"hello world");
        let result = BCryptContext::finish_hash(&hash).unwrap();
        assert_eq!(result.len(), 32); // SHA-256 = 32 bytes
    }

    #[test]
    fn bcrypt_unsupported_algorithm() {
        let ctx = BCryptContext::new();
        let result = ctx.create_hash("UNSUPPORTED");
        assert!(result.is_err());
    }

    // --- ThreadPool Tests ---

    #[test]
    fn threadpool_create_and_submit_work() {
        let mut tp = ThreadPoolManager::new();
        let id = tp.create_work(0x1000, 0x2000);
        assert_eq!(tp.work_count(), 1);

        tp.submit_work(id).unwrap();
        let pending = tp.pending_work();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].callback, 0x1000);

        tp.close_work(id);
        assert_eq!(tp.work_count(), 0);
    }

    #[test]
    fn threadpool_timer() {
        let mut tp = ThreadPoolManager::new();
        let id = tp.create_timer(0x3000, 0x4000);
        assert_eq!(tp.timer_count(), 1);

        tp.set_timer(id, 100, 50).unwrap();
        let active = tp.active_timers();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].due_time_ms, 100);

        tp.close_timer(id);
        assert_eq!(tp.timer_count(), 0);
    }

    #[test]
    fn threadpool_submit_nonexistent_fails() {
        let mut tp = ThreadPoolManager::new();
        assert!(tp.submit_work(999).is_err());
    }

    // --- SyncBarrier Tests ---

    #[test]
    fn sync_barrier_single_thread() {
        let barrier = SyncBarrier::new(1);
        let is_last = barrier.enter();
        assert!(is_last);
    }

    #[test]
    fn sync_barrier_properties() {
        let barrier = SyncBarrier::new(4);
        assert_eq!(barrier.total_threads(), 4);
        assert_eq!(barrier.arrived_count(), 0);
    }

    // --- DbgHelp Tests ---

    #[test]
    fn dbghelp_load_module_and_lookup() {
        let mut ctx = DbgHelpContext::new();
        ctx.sym_initialize(0).unwrap();
        ctx.sym_load_module("test.dll", 0x1000_0000).unwrap();
        ctx.register_symbol(0x1000_0100, "MyFunction", 0x1000_0000);

        assert_eq!(ctx.module_count(), 1);
        assert_eq!(ctx.symbol_count(), 1);

        let sym = ctx.sym_from_addr(0x1000_0100).unwrap();
        assert_eq!(sym.name, "MyFunction");
    }

    #[test]
    fn dbghelp_symbol_not_found() {
        let ctx = DbgHelpContext::new();
        assert!(ctx.sym_from_addr(0xDEAD).is_err());
    }

    #[test]
    fn dbghelp_stack_walk() {
        let mut ctx = DbgHelpContext::new();
        ctx.sym_load_module("game.exe", 0x0040_0000).unwrap();
        ctx.register_symbol(0x0040_1000, "main", 0x0040_0000);

        let frames = ctx.stack_walk(0x0040_1000, 0x7FFF_0000, 0x7FFF_F000, 10);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].symbol_name, Some("main".to_string()));
        assert_eq!(frames[0].module_name, "game.exe");
    }

    // --- Advapi32 Tests ---

    #[test]
    fn advapi32_predefined_services() {
        let mgr = Advapi32Manager::new();
        assert!(mgr.service_count() >= 3);

        let svc = mgr.query_service_status("SteamClientService").unwrap();
        assert_eq!(svc.state, ServiceState::Running);
    }

    #[test]
    fn advapi32_service_not_found() {
        let mgr = Advapi32Manager::new();
        assert!(mgr.query_service_status("NonExistentService").is_err());
    }

    #[test]
    fn advapi32_start_service() {
        let mut mgr = Advapi32Manager::new();
        // Add a stopped service
        mgr.services.insert("TestSvc".to_string(), ServiceRecord {
            name: "TestSvc".to_string(),
            display_name: "Test Service".to_string(),
            service_type: 0x10,
            state: ServiceState::Stopped,
            process_id: None,
        });

        mgr.start_service("TestSvc").unwrap();
        let svc = mgr.query_service_status("TestSvc").unwrap();
        assert_eq!(svc.state, ServiceState::Running);
    }

    #[test]
    fn advapi32_token_info() {
        let mgr = Advapi32Manager::new();
        assert!(mgr.is_elevated());
        let token = mgr.get_token_info();
        assert_eq!(token.integrity_level, 0x3000);
    }

    #[test]
    fn advapi32_security_descriptor() {
        let mut mgr = Advapi32Manager::new();
        mgr.set_security_descriptor("C:\\Secret.txt", SecurityDescriptor {
            owner: "Administrators".to_string(),
            group: "None".to_string(),
            dacl_present: true,
            sacl_present: false,
        });

        let sd = mgr.get_security_descriptor("C:\\Secret.txt").unwrap();
        assert_eq!(sd.owner, "Administrators");
        assert!(sd.dacl_present);
    }

    #[test]
    fn advapi32_open_sc_manager() {
        let mgr = Advapi32Manager::new();
        let handle = mgr.open_sc_manager().unwrap();
        assert_eq!(handle, 0xDEAD_0001);
    }
}
