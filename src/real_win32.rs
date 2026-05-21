//! Real Win32 API expansion for Casa1.
//!
//! Implements the critical Win32 APIs needed by Steam and AAA games that are
//! not already covered in `src/win32.rs` and `src/pe_runtime.rs`. This includes
//! COM/OLE automation, MSVC CRT, Shell32, Advapi32, Version, XInput, BCrypt,
//! ThreadPool, synchronization barriers, and DbgHelp.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ===========================================================================
// COM / OLE Automation
// ===========================================================================

/// COM apartment state tracker.
pub struct ComApartmentState {
    initialized: bool,
    apartment_model: ComApartmentModel,
    next_iid: u64,
    com_objects: BTreeMap<u64, ComObjectRecord>,
    /// CLSID string → factory function mapping.
    class_factories: HashMap<String, Box<dyn Fn() -> Box<dyn ComObject> + Send>>,
    /// Per-thread apartment state tracking.
    thread_apartments: HashMap<u32, ComApartmentModel>,
    /// Registered class factories with their tokens (for CoRegisterClassObject).
    registered_factories: BTreeMap<u32, RegisteredFactoryEntry>,
    /// Next registration token value.
    next_token: u32,
}

/// COM threading model for apartments.
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

/// Trait for COM objects that can be created via IClassFactory.
pub trait ComObject: Send {
    /// Get the IIDs this object supports via QueryInterface.
    fn supported_iids(&self) -> Vec<[u8; 16]>;
    /// Get a debug name.
    fn debug_name(&self) -> &str;
}

/// A simple COM object that wraps a known CLSID→IID mapping.
pub struct SimpleComObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
}

impl SimpleComObject {
    pub fn new(clsid: [u8; 16], iid: [u8; 16], name: &str) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, iid],
            name: name.to_string(),
        }
    }
}

impl ComObject for SimpleComObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
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
    /// IID_IShellLinkW: {000214F9-0000-0000-C000-000000000046}
    pub const ISHELLLINKW: [u8; 16] = [0xF9, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
    /// IID_IPersistFile: {0000010B-0000-0000-C000-000000000046}
    pub const IPERSISTFILE: [u8; 16] = [0x0B, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
}

/// Well-known CLSIDs used by Steam and games.
pub struct ComClsid;

impl ComClsid {
    /// DirectSound8: {3901CC3F-84B5-4FA4-BA35-AA8172B8A6B2}
    pub const DIRECTSOUND8: [u8; 16] = [0x3F, 0xCC, 0x01, 0x39, 0xB5, 0x84, 0xA4, 0x4F, 0xBA, 0x35, 0xAA, 0x81, 0x72, 0xB8, 0xA6, 0xB2];
    /// XAudio2: {609ED052-35B5-4F10-9BE6-39650F9781D4}
    pub const XAUDIO2: [u8; 16] = [0x52, 0xD0, 0x9E, 0x60, 0xB5, 0x35, 0x10, 0x4F, 0x9B, 0xE6, 0x39, 0x65, 0x0F, 0x97, 0x81, 0xD4];
    /// CLSID_ShellLink: {00021401-0000-0000-C000-000000000046}
    pub const SHELL_LINK: [u8; 16] = [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
    /// CLSID_FileOpenDialog: {DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7}
    pub const FILE_OPEN_DIALOG: [u8; 16] = [0x9C, 0x5A, 0x1C, 0xDC, 0x8A, 0xE8, 0xDE, 0x4D, 0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7];
    /// CLSID_FileSaveDialog: {C0B4E2F3-BA21-4773-8DBA-335EC946EB8B}
    pub const FILE_SAVE_DIALOG: [u8; 16] = [0xF3, 0xE2, 0xB4, 0xC0, 0x21, 0xBA, 0x73, 0x47, 0x8D, 0xBA, 0x33, 0x5E, 0xC9, 0x46, 0xEB, 0x8B];
}

/// Convert a [u8; 16] GUID to a string like "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
pub fn guid_to_string(guid: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d1, d2, d3,
        guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )
}

/// Parse a GUID string like "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" into bytes.
pub fn guid_from_string(s: &str) -> Option<[u8; 16]> {
    let s = s.trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return None;
    }
    let d1 = u32::from_str_radix(parts[0], 16).ok()?;
    let d2 = u16::from_str_radix(parts[1], 16).ok()?;
    let d3 = u16::from_str_radix(parts[2], 16).ok()?;
    let d4 = u16::from_str_radix(parts[3], 16).ok()?;
    let d5 = u64::from_str_radix(parts[4], 16).ok()?;
    let mut guid = [0u8; 16];
    guid[0..4].copy_from_slice(&d1.to_le_bytes());
    guid[4..6].copy_from_slice(&d2.to_le_bytes());
    guid[6..8].copy_from_slice(&d3.to_le_bytes());
    guid[8..10].copy_from_slice(&((d4 >> 8) as u8).to_le_bytes());
    guid[10..12].copy_from_slice(&(d4 as u8).to_le_bytes());
    guid[12..16].copy_from_slice(&d5.to_le_bytes()[0..4]);
    // Fix byte order for the last parts
    guid[8] = (d4 >> 8) as u8;
    guid[9] = d4 as u8;
    guid[10] = (d5 >> 40) as u8;
    guid[11] = (d5 >> 32) as u8;
    guid[12] = (d5 >> 24) as u8;
    guid[13] = (d5 >> 16) as u8;
    guid[14] = (d5 >> 8) as u8;
    guid[15] = d5 as u8;
    Some(guid)
}

/// Compare two GUID byte arrays.
pub fn guid_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a == b
}

impl ComApartmentState {
    pub fn new() -> Self {
        Self {
            initialized: false,
            apartment_model: ComApartmentModel::NotInitialized,
            next_iid: 1,
            com_objects: BTreeMap::new(),
            class_factories: HashMap::new(),
            thread_apartments: HashMap::new(),
            registered_factories: BTreeMap::new(),
            next_token: 1,
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

    /// CoInitializeEx with per-thread tracking.
    pub fn co_initialize_ex(&mut self, thread_id: u32, model: ComApartmentModel) -> AppResult<()> {
        if self.thread_apartments.contains_key(&thread_id) {
            // Already initialized for this thread — S_OK (not an error in COM)
            return Ok(());
        }
        self.thread_apartments.insert(thread_id, model);
        if !self.initialized {
            self.initialized = true;
            self.apartment_model = model;
        }
        Ok(())
    }

    /// CoUninitialize with per-thread tracking.
    pub fn co_uninitialize(&mut self, thread_id: u32) {
        self.thread_apartments.remove(&thread_id);
        if self.thread_apartments.is_empty() {
            self.initialized = false;
            self.apartment_model = ComApartmentModel::NotInitialized;
            self.com_objects.clear();
        }
    }

    /// Get the apartment model for a thread.
    pub fn get_thread_apartment(&self, thread_id: u32) -> Option<ComApartmentModel> {
        self.thread_apartments.get(&thread_id).copied()
    }

    /// Register a class factory for a CLSID.
    pub fn register_class_object(
        &mut self,
        clsid: &[u8; 16],
        factory: Box<dyn Fn() -> Box<dyn ComObject> + Send>,
    ) {
        let guid_str = guid_to_string(clsid);
        self.class_factories.insert(guid_str, factory);
    }

    /// Revoke a class factory registration.
    pub fn revoke_class_object(&mut self, clsid: &[u8; 16]) -> bool {
        let guid_str = guid_to_string(clsid);
        self.class_factories.remove(&guid_str).is_some()
    }

    /// DllGetClassObject — resolve a CLSID to an IClassFactory-compatible object.
    pub fn dll_get_class_object(&self, clsid: &[u8; 16]) -> AppResult<Box<dyn ComObject>> {
        let guid_str = guid_to_string(clsid);
        if let Some(factory) = self.class_factories.get(&guid_str) {
            return Ok(factory());
        }
        // Check well-known CLSIDs
        if guid_eq(clsid, &ComClsid::DIRECTSOUND8) {
            return Ok(Box::new(SimpleComObject::new(*clsid, ComIid::IUNKNOWN, "DirectSound8")));
        }
        if guid_eq(clsid, &ComClsid::XAUDIO2) {
            return Ok(Box::new(SimpleComObject::new(*clsid, ComIid::IUNKNOWN, "XAudio2")));
        }
        if guid_eq(clsid, &ComClsid::SHELL_LINK) {
            return Ok(Box::new(SimpleComObject::new(*clsid, ComIid::ISHELLLINKW, "ShellLink")));
        }
        if guid_eq(clsid, &ComClsid::FILE_OPEN_DIALOG) {
            return Ok(Box::new(SimpleComObject::new(*clsid, ComIid::IUNKNOWN, "FileOpenDialog")));
        }
        if guid_eq(clsid, &ComClsid::FILE_SAVE_DIALOG) {
            return Ok(Box::new(SimpleComObject::new(*clsid, ComIid::IUNKNOWN, "FileSaveDialog")));
        }
        Err(AppError::new(
            ReasonCode::RcComClassNotRegistered,
            format!("CLSID {} not registered", guid_str),
        ))
    }

    /// CoCreateInstance — create a COM object by CLSID.
    ///
    /// Validates that COM is initialized and the CLSID is registered
    /// via a class factory or well-known CLSID, then creates a tracking
    /// record for the object.
    pub fn co_create_instance(
        &mut self,
        clsid: [u8; 16],
        iid: [u8; 16],
        vtable_ptr: u64,
        object_name: &str,
    ) -> AppResult<u64> {
        // COM must be initialized first
        if !self.initialized {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "CoCreateInstance called before CoInitialize",
            ));
        }
        // Validate that the CLSID is recognised via registered class factories
        // or well-known CLSIDs.  If not, return CLASS_E_CLASSNOTAVAILABLE.
        self.dll_get_class_object(&clsid).map_err(|_| {
            AppError::new(
                ReasonCode::RcComClassNotRegistered,
                format!(
                    "CLSID {} not available for CoCreateInstance",
                    guid_to_string(&clsid)
                ),
            )
        })?;
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

    /// CoCreateInstanceEx — create a COM object with multiple IIDs.
    pub fn co_create_instance_ex(
        &mut self,
        clsid: [u8; 16],
        iid: [u8; 16],
        vtable_ptr: u64,
        object_name: &str,
    ) -> AppResult<u64> {
        self.co_create_instance(clsid, iid, vtable_ptr, object_name)
    }

    /// CoGetClassObject — get an IClassFactory for a CLSID.
    pub fn co_get_class_object(&self, clsid: &[u8; 16], iid: &[u8; 16]) -> AppResult<Box<dyn ComObject>> {
        // IID check: must be IClassFactory or IUnknown
        if !guid_eq(iid, &ComIid::ICLASS_FACTORY) && !guid_eq(iid, &ComIid::IUNKNOWN) {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("CoGetClassObject: unsupported IID"),
            ));
        }
        self.dll_get_class_object(clsid)
    }

    /// CoCreateGuid — generate a new GUID.
    pub fn co_create_guid() -> [u8; 16] {
        let mut guid = [0u8; 16];
        let u = uuid::Uuid::new_v4();
        let bytes = u.as_bytes();
        guid.copy_from_slice(bytes);
        guid
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

    // -----------------------------------------------------------------------
    // CoRegisterClassObject / CoRevokeClassObject with token tracking
    // -----------------------------------------------------------------------

    /// Register a class object (factory) and return a registration token.
    pub fn register_class_object_with_token(
        &mut self,
        clsid: &[u8; 16],
        factory: Box<dyn Fn() -> Box<dyn ComObject> + Send>,
    ) -> u32 {
        let guid_str = guid_to_string(clsid);
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        self.class_factories.insert(guid_str.clone(), factory);
        self.registered_factories.insert(
            token,
            RegisteredFactoryEntry {
                clsid: *clsid,
                guid_str,
            },
        );
        token
    }

    /// Revoke a class factory by token.
    pub fn revoke_class_object_by_token(&mut self, token: u32) -> bool {
        if let Some(entry) = self.registered_factories.remove(&token) {
            self.class_factories.remove(&entry.guid_str);
            true
        } else {
            false
        }
    }

    /// Get the CLSID associated with a registration token.
    pub fn clsid_for_token(&self, token: u32) -> Option<[u8; 16]> {
        self.registered_factories.get(&token).map(|e| e.clsid)
    }
}

/// Entry for a registered class factory.
#[derive(Debug, Clone)]
struct RegisteredFactoryEntry {
    clsid: [u8; 16],
    guid_str: String,
}

// ===========================================================================
// IDispatch / OLE Automation Support
// ===========================================================================

/// Standard COM DISPID values.
pub const DISPID_UNKNOWN: i32 = -1;
pub const DISPID_VALUE: i32 = 0;
pub const DISPID_PROPERTYPUT: i32 = -3;
pub const DISPID_NEWENUM: i32 = -4;
pub const DISPID_EVALUATE: i32 = -5;
pub const DISPID_CONSTRUCTOR: i32 = -6;
pub const DISPID_DESTRUCTOR: i32 = -7;
pub const DISPID_COLLECT: i32 = -8;

/// IDispatch invoke flags.
pub const DISPATCH_METHOD: u16 = 0x0001;
pub const DISPATCH_PROPERTYGET: u16 = 0x0002;
pub const DISPATCH_PROPERTYPUT: u16 = 0x0004;
pub const DISPATCH_PROPERTYPUTREF: u16 = 0x0008;

/// Host-side result of IDispatch::GetIDsOfNames.
pub struct DispatchIds {
    pub rgdispid: Vec<i32>,
}

/// Host-side result of IDispatch::Invoke.
pub struct DispatchResult {
    pub result: Variant,
    pub excp_info: Option<String>,
    pub arg_err: u32,
}

/// Type-erased dispatch interface stored per COM object.
pub enum DispatchInterface {
    /// A simple property bag with named values.
    PropertyBag(BTreeMap<String, Variant>),
    /// A custom dispatch handler.
    Custom(Box<dyn Fn(&str, u16, &[Variant]) -> AppResult<Variant> + Send>),
}

/// GetIDsOfNames for a PropertyBag dispatch interface.
pub fn dispatch_get_ids_of_names(
    dispatch: &DispatchInterface,
    names: &[String],
) -> AppResult<DispatchIds> {
    match dispatch {
        DispatchInterface::PropertyBag(bag) => {
            let mut rgdispid = Vec::with_capacity(names.len());
            for (i, name) in names.iter().enumerate() {
                if bag.contains_key(name) {
                    rgdispid.push(i as i32 + 1); // DISPID = 1-based index
                } else if name.eq_ignore_ascii_case("") {
                    rgdispid.push(DISPID_VALUE);
                } else {
                    rgdispid.push(DISPID_UNKNOWN);
                }
            }
            Ok(DispatchIds { rgdispid })
        }
        DispatchInterface::Custom(_) => {
            // Custom dispatchers should implement their own name resolution
            // For now, return DISPID_UNKNOWN for all
            let rgdispid = names.iter().map(|_| DISPID_UNKNOWN).collect();
            Ok(DispatchIds { rgdispid })
        }
    }
}

/// Invoke for a PropertyBag dispatch interface.
pub fn dispatch_invoke(
    dispatch: &mut DispatchInterface,
    dispid: i32,
    lcid: u32,
    flags: u16,
    params: &[Variant],
) -> AppResult<DispatchResult> {
    match dispatch {
        DispatchInterface::PropertyBag(bag) => {
            // Find the property by DISPID (1-based index)
            let name = bag
                .keys()
                .nth(if dispid == DISPID_VALUE {
                    0
                } else if dispid > 0 {
                    (dispid - 1) as usize
                } else {
                    return Ok(DispatchResult {
                        result: Variant { vt: VT_EMPTY, w_reserved1: 0, w_reserved2: 0, w_reserved3: 0, data: 0 },
                        excp_info: Some(format!("invalid DISPID {dispid}")),
                        arg_err: 0,
                    });
                })
                .cloned();

            match name {
                Some(name) => {
                    if flags & (DISPATCH_PROPERTYGET | DISPATCH_METHOD) != 0 {
                        let val = bag.get(&name).cloned().unwrap_or(Variant {
                            vt: VT_EMPTY,
                            w_reserved1: 0,
                            w_reserved2: 0,
                            w_reserved3: 0,
                            data: 0,
                        });
                        Ok(DispatchResult {
                            result: val,
                            excp_info: None,
                            arg_err: 0,
                        })
                    } else if flags & DISPATCH_PROPERTYPUT != 0 {
                        if let Some(new_val) = params.first() {
                            bag.insert(name, new_val.clone());
                        }
                        Ok(DispatchResult {
                            result: Variant { vt: VT_EMPTY, w_reserved1: 0, w_reserved2: 0, w_reserved3: 0, data: 0 },
                            excp_info: None,
                            arg_err: 0,
                        })
                    } else {
                        Ok(DispatchResult {
                            result: Variant { vt: VT_EMPTY, w_reserved1: 0, w_reserved2: 0, w_reserved3: 0, data: 0 },
                            excp_info: None,
                            arg_err: 0,
                        })
                    }
                }
                None => Ok(DispatchResult {
                    result: Variant { vt: VT_EMPTY, w_reserved1: 0, w_reserved2: 0, w_reserved3: 0, data: 0 },
                    excp_info: Some("property not found".to_string()),
                    arg_err: 0,
                }),
            }
        }
        DispatchInterface::Custom(handler) => {
            // For custom dispatch, we don't have the name, just the dispid
            let result = handler("", flags, params)?;
            Ok(DispatchResult {
                result,
                excp_info: None,
                arg_err: 0,
            })
        }
    }
}

// ===========================================================================
// COM Apartment Message Pump (for STA threads)
// ===========================================================================

/// Simulate a single message pump iteration for an STA apartment.
/// Returns true if a message was processed.
pub fn apartment_message_pump() -> bool {
    // In a real COM implementation, this would process window messages
    // for the STA apartment thread. For now, it's a simple yield.
    false
}

/// Run the message pump until a quit condition is met.
pub fn apartment_message_pump_loop() {
    loop {
        if !apartment_message_pump() {
            break;
        }
    }
}

// ===========================================================================
// VARIANT / BSTR / SAFEARRAY Support
// ===========================================================================

/// VARIANT type codes (VT_*).
pub const VT_EMPTY: u16 = 0;
pub const VT_NULL: u16 = 1;
pub const VT_I2: u16 = 2;
pub const VT_I4: u16 = 3;
pub const VT_R4: u16 = 4;
pub const VT_R8: u16 = 5;
pub const VT_CY: u16 = 6;
pub const VT_DATE: u16 = 7;
pub const VT_BSTR: u16 = 8;
pub const VT_DISPATCH: u16 = 9;
pub const VT_ERROR: u16 = 10;
pub const VT_BOOL: u16 = 11;
pub const VT_VARIANT: u16 = 12;
pub const VT_UNKNOWN: u16 = 13;
pub const VT_DECIMAL: u16 = 14;
pub const VT_I1: u16 = 16;
pub const VT_UI1: u16 = 17;
pub const VT_UI2: u16 = 18;
pub const VT_UI4: u16 = 19;
pub const VT_I8: u16 = 20;
pub const VT_UI8: u16 = 21;
pub const VT_INT: u16 = 22;
pub const VT_UINT: u16 = 23;
pub const VT_VOID: u16 = 24;
pub const VT_HRESULT: u16 = 25;
pub const VT_PTR: u16 = 26;
pub const VT_SAFEARRAY: u16 = 27;
pub const VT_CARRAY: u16 = 28;
pub const VT_USERDEFINED: u16 = 29;
pub const VT_LPSTR: u16 = 30;
pub const VT_LPWSTR: u16 = 31;
pub const VT_RECORD: u16 = 36;
pub const VT_INT_PTR: u16 = 37;
pub const VT_UINT_PTR: u16 = 38;
pub const VT_FILETIME: u16 = 64;
pub const VT_BLOB: u16 = 65;
pub const VT_STREAM: u16 = 66;
pub const VT_STORAGE: u16 = 67;
pub const VT_STREAMED_OBJECT: u16 = 68;
pub const VT_STORED_OBJECT: u16 = 69;
pub const VT_BLOB_OBJECT: u16 = 70;
pub const VT_CF: u16 = 71;
pub const VT_CLSID: u16 = 72;
pub const VT_VERSIONED_STREAM: u16 = 73;
pub const VT_BSTR_BLOB: u16 = 0x0fff;
pub const VT_VECTOR: u16 = 0x1000;
pub const VT_ARRAY: u16 = 0x2000;
pub const VT_BYREF: u16 = 0x4000;
pub const VT_RESERVED: u16 = 0x8000;
pub const VT_ILLEGAL: u16 = 0xffff;
pub const VT_ILLEGALMASKED: u16 = 0x0fff;
pub const VT_TYPEMASK: u16 = 0x0fff;

/// VARIANT structure (16 bytes on x64 Windows).
/// Layout: vt (2) + reserved (6) + data (8) = 16 bytes.
#[repr(C, packed)]
#[derive(Clone)]
pub struct Variant {
    pub vt: u16,
    pub w_reserved1: u16,
    pub w_reserved2: u16,
    pub w_reserved3: u16,
    /// The data field (8 bytes) — interpretation depends on vt.
    pub data: u64,
}

/// BSTR structure in guest memory: [length: i32][char_data...][null_terminator]
/// The pointer returned by SysAllocString points to the char_data.

/// SysAllocString — allocate a BSTR from a wide string.
pub fn sys_alloc_string(src: &[u16]) -> Vec<u8> {
    if src.is_empty() {
        // Zero-length BSTR: length=0, null terminator
        let mut buf = vec![0u8; 4 + 2];
        buf[0..4].copy_from_slice(&0i32.to_le_bytes());
        buf
    } else {
        let byte_len = src.len() * 2; // byte count excluding null terminator
        let total_len = 4 + byte_len + 2; // length prefix + data + null terminator
        let mut buf = vec![0u8; total_len];
        buf[0..4].copy_from_slice(&(byte_len as i32).to_le_bytes());
        for (i, &ch) in src.iter().enumerate() {
            buf[4 + i * 2..4 + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
        }
        buf
    }
}

/// SysAllocStringLen — allocate a BSTR with a specific length.
pub fn sys_alloc_string_len(src: &[u16], len: u32) -> Vec<u8> {
    let actual_len = (src.len() as u32).min(len) as usize;
    let data = if actual_len > 0 {
        let mut d = vec![0u16; actual_len];
        for (i, &ch) in src.iter().take(actual_len).enumerate() {
            d[i] = ch;
        }
        d
    } else {
        Vec::new()
    };
    sys_alloc_string(&data)
}

/// SysReAllocString — reallocate a BSTR.
pub fn sys_realloc_string(existing: &[u8], new_src: &[u16]) -> Vec<u8> {
    // Just allocate a new one; the old one is freed by caller
    sys_alloc_string(new_src)
}

/// SysFreeString — free a BSTR (no-op in our model, memory managed by guest allocator).
pub fn sys_free_string(_bstr_ptr: u64) {}

/// SysStringLen — get the length of a BSTR in characters (excluding null terminator).
pub fn sys_string_len(bstr_data: &[u8]) -> u32 {
    if bstr_data.len() < 4 {
        return 0;
    }
    let byte_len = i32::from_le_bytes([bstr_data[0], bstr_data[1], bstr_data[2], bstr_data[3]]);
    if byte_len < 0 {
        0
    } else {
        (byte_len as u32) / 2
    }
}

/// VariantInit — initialize a VARIANT to VT_EMPTY.
pub fn variant_init() -> Variant {
    Variant {
        vt: VT_EMPTY,
        w_reserved1: 0,
        w_reserved2: 0,
        w_reserved3: 0,
        data: 0,
    }
}

/// VariantClear — clear a VARIANT (free BSTR if needed).
pub fn variant_clear(v: &mut Variant) {
    let vt = v.vt & VT_TYPEMASK;
    if vt == VT_BSTR || vt == VT_LPWSTR || vt == VT_LPSTR {
        // BSTR needs freeing — handled by caller
    }
    v.vt = VT_EMPTY;
    v.w_reserved1 = 0;
    v.w_reserved2 = 0;
    v.w_reserved3 = 0;
    v.data = 0;
}

/// VariantCopy — copy a VARIANT.
pub fn variant_copy(dst: &mut Variant, src: &Variant) {
    *dst = Variant {
        vt: src.vt,
        w_reserved1: src.w_reserved1,
        w_reserved2: src.w_reserved2,
        w_reserved3: src.w_reserved3,
        data: src.data,
    };
}

/// VariantChangeType — change the type of a VARIANT (simplified).
pub fn variant_change_type(dst: &mut Variant, src: &Variant, _flags: u16, new_vt: u16) -> AppResult<()> {
    let src_vt = src.vt & VT_TYPEMASK;
    let new_vt_base = new_vt & VT_TYPEMASK;

    if src_vt == new_vt_base {
        variant_copy(dst, src);
        return Ok(());
    }

    // Simple type conversions
    match (src_vt, new_vt_base) {
        (VT_I4, VT_BSTR) => {
            let val = src.data as i32;
            let s = val.to_string();
            let wide: Vec<u16> = s.encode_utf16().collect();
            let bstr = sys_alloc_string(&wide);
            // Store BSTR pointer in data
            dst.vt = VT_BSTR;
            dst.data = 0; // Caller must set pointer
        }
        (VT_BSTR, VT_I4) => {
            // For simplicity, return the pointer as-is
            dst.vt = VT_I4;
            dst.data = 0;
        }
        (VT_BOOL, VT_BSTR) => {
            let val = src.data != 0;
            let s = if val { "True" } else { "False" };
            let wide: Vec<u16> = s.encode_utf16().collect();
            let bstr = sys_alloc_string(&wide);
            dst.vt = VT_BSTR;
            dst.data = 0;
        }
        _ => {
            // Unsupported conversion; just copy vt and zero data
            dst.vt = new_vt_base;
            dst.data = 0;
        }
    }
    Ok(())
}

/// SAFEARRAYBOUND structure.
#[repr(C)]
pub struct SafeArrayBound {
    pub elements: u32,
    pub l_bound: i32,
}

/// SAFEARRAY descriptor (simplified — does not include all fields).
/// Full layout: [cbElements: u16, cDims: u16, fFeatures: u16, cbElements2: u16,
///               cLocks: u32, handle: u64, rgsabound: SafeArrayBound[cDims]]
#[repr(C)]
pub struct SafeArrayDescriptor {
    pub cb_elements: u16,
    pub c_dims: u16,
    pub f_features: u16,
    pub cb_elements2: u16, // duplicate of cb_elements in some layouts
    pub c_locks: u32,
    pub handle: u64,       // pointer to actual data
    // Followed by SafeArrayBound[c_dims]
}

/// SAFEARRAY feature flags.
pub const FADF_AUTO: u16 = 0x0001;
pub const FADF_STATIC: u16 = 0x0002;
pub const FADF_EMBEDDED: u16 = 0x0004;
pub const FADF_FIXEDSIZE: u16 = 0x0010;
pub const FADF_RECORD: u16 = 0x0020;
pub const FADF_HAVEIID: u16 = 0x0040;
pub const FADF_HAVEVARTYPE: u16 = 0x0080;
pub const FADF_BSTR: u16 = 0x0100;
pub const FADF_UNKNOWN: u16 = 0x0200;
pub const FADF_DISPATCH: u16 = 0x0400;
pub const FADF_VARIANT: u16 = 0x0800;
pub const FADF_RESERVED: u16 = 0xF000;

/// SafeArrayCreate — create a SAFEARRAY.
pub fn safe_array_create(vt: u16, c_dims: u32, bounds: &[SafeArrayBound]) -> Vec<u8> {
    let c_dims = c_dims as u16;
    let elem_size = element_size(vt);
    let mut total_elements: u32 = 1;
    for b in bounds {
        total_elements = total_elements.saturating_mul(b.elements);
    }
    let data_size = (elem_size as u64) * (total_elements as u64);

    // Calculate descriptor size: header (24 bytes?) + c_dims * 8 bytes for bounds
    let header_size = 24 + (c_dims as usize) * 8;
    let total_size = header_size + data_size as usize;

    let mut buf = vec![0u8; total_size];
    // Write header
    buf[0..2].copy_from_slice(&(elem_size as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&c_dims.to_le_bytes());
    buf[4..6].copy_from_slice(&FADF_AUTO.to_le_bytes());
    buf[6..8].copy_from_slice(&(elem_size as u16).to_le_bytes());
    // c_locks = 0
    buf[8..12].copy_from_slice(&0u32.to_le_bytes());
    // handle = pointer to data (offset header_size)
    buf[12..20].copy_from_slice(&(header_size as u64).to_le_bytes());
    // Write bounds
    for (i, b) in bounds.iter().enumerate() {
        let offset = 20 + i * 8;
        buf[offset..offset + 4].copy_from_slice(&b.elements.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&b.l_bound.to_le_bytes());
    }
    buf
}

/// SafeArrayDestroy — destroy a SAFEARRAY (no-op in our model).
pub fn safe_array_destroy(_sa_ptr: u64) {}

/// SafeArrayAccessData — get a pointer to the SAFEARRAY data.
pub fn safe_array_access_data(sa_data: &[u8]) -> AppResult<u64> {
    if sa_data.len() < 24 {
        return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY too small"));
    }
    let handle_offset = u64::from_le_bytes([
        sa_data[12], sa_data[13], sa_data[14], sa_data[15],
        sa_data[16], sa_data[17], sa_data[18], sa_data[19],
    ]);
    Ok(handle_offset)
}

/// SafeArrayUnaccessData — release access to SAFEARRAY data.
pub fn safe_array_unaccess_data(_sa_ptr: u64) {}

/// SafeArrayGetElement — get an element from a SAFEARRAY.
pub fn safe_array_get_element(sa_data: &[u8], indices: &[i32]) -> AppResult<Vec<u8>> {
    let c_dims = u16::from_le_bytes([sa_data[2], sa_data[3]]) as usize;
    if indices.len() != c_dims {
        return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "index count mismatch"));
    }
    let elem_size = u16::from_le_bytes([sa_data[0], sa_data[1]]) as usize;
    let base_offset = safe_array_access_data(sa_data)? as usize;

    // Calculate flat index
    let mut flat_index: i32 = 0;
    let mut stride: i32 = 1;
    for dim in (0..c_dims).rev() {
        let bound_offset = 20 + dim * 8;
        let elements = u32::from_le_bytes([
            sa_data[bound_offset], sa_data[bound_offset + 1],
            sa_data[bound_offset + 2], sa_data[bound_offset + 3],
        ]) as i32;
        let l_bound = i32::from_le_bytes([
            sa_data[bound_offset + 4], sa_data[bound_offset + 5],
            sa_data[bound_offset + 6], sa_data[bound_offset + 7],
        ]);
        let idx = indices[dim] - l_bound;
        if idx < 0 || idx >= elements {
            return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "index out of bounds"));
        }
        flat_index += idx * stride;
        stride *= elements;
    }

    let offset = base_offset + (flat_index as usize) * elem_size;
    Ok(sa_data[offset..offset + elem_size].to_vec())
}

/// SafeArrayPutElement — put an element into a SAFEARRAY.
pub fn safe_array_put_element(sa_data: &mut [u8], indices: &[i32], element_data: &[u8]) -> AppResult<()> {
    let c_dims = u16::from_le_bytes([sa_data[2], sa_data[3]]) as usize;
    if indices.len() != c_dims {
        return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "index count mismatch"));
    }
    let elem_size = u16::from_le_bytes([sa_data[0], sa_data[1]]) as usize;
    let base_offset = safe_array_access_data(sa_data)? as usize;

    let mut flat_index: i32 = 0;
    let mut stride: i32 = 1;
    for dim in (0..c_dims).rev() {
        let bound_offset = 20 + dim * 8;
        let elements = u32::from_le_bytes([
            sa_data[bound_offset], sa_data[bound_offset + 1],
            sa_data[bound_offset + 2], sa_data[bound_offset + 3],
        ]) as i32;
        let l_bound = i32::from_le_bytes([
            sa_data[bound_offset + 4], sa_data[bound_offset + 5],
            sa_data[bound_offset + 6], sa_data[bound_offset + 7],
        ]);
        let idx = indices[dim] - l_bound;
        if idx < 0 || idx >= elements {
            return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "index out of bounds"));
        }
        flat_index += idx * stride;
        stride *= elements;
    }

    let offset = base_offset + (flat_index as usize) * elem_size;
    let end = offset + element_data.len().min(elem_size);
    if end <= sa_data.len() {
        sa_data[offset..end].copy_from_slice(&element_data[..end - offset]);
    }
    Ok(())
}

/// SafeArrayGetLBound — get the lower bound of a SAFEARRAY dimension.
pub fn safe_array_get_lbound(sa_data: &[u8], dim: u32) -> AppResult<i32> {
    if sa_data.len() < 20 {
        return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY too small"));
    }
    let c_dims = u16::from_le_bytes([sa_data[2], sa_data[3]]) as u32;
    if dim == 0 || dim > c_dims {
        return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "invalid dimension"));
    }
    let bound_offset = 20 + (dim as usize - 1) * 8;
    Ok(i32::from_le_bytes([
        sa_data[bound_offset + 4], sa_data[bound_offset + 5],
        sa_data[bound_offset + 6], sa_data[bound_offset + 7],
    ]))
}

/// SafeArrayGetUBound — get the upper bound of a SAFEARRAY dimension.
pub fn safe_array_get_ubound(sa_data: &[u8], dim: u32) -> AppResult<i32> {
    if sa_data.len() < 20 {
        return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY too small"));
    }
    let c_dims = u16::from_le_bytes([sa_data[2], sa_data[3]]) as u32;
    if dim == 0 || dim > c_dims {
        return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "invalid dimension"));
    }
    let bound_offset = 20 + (dim as usize - 1) * 8;
    let elements = u32::from_le_bytes([
        sa_data[bound_offset], sa_data[bound_offset + 1],
        sa_data[bound_offset + 2], sa_data[bound_offset + 3],
    ]);
    let l_bound = i32::from_le_bytes([
        sa_data[bound_offset + 4], sa_data[bound_offset + 5],
        sa_data[bound_offset + 6], sa_data[bound_offset + 7],
    ]);
    Ok(l_bound + elements as i32 - 1)
}

/// Get the element size for a VARIANT type.
pub fn element_size(vt: u16) -> usize {
    match vt & VT_TYPEMASK {
        VT_EMPTY | VT_NULL => 0,
        VT_I1 | VT_UI1 => 1,
        VT_I2 | VT_UI2 | VT_BOOL => 2,
        VT_I4 | VT_UI4 | VT_R4 | VT_ERROR | VT_INT | VT_UINT => 4,
        VT_R8 | VT_CY | VT_DATE | VT_I8 | VT_UI8 => 8,
        VT_BSTR | VT_UNKNOWN | VT_DISPATCH => 8, // pointers
        VT_VARIANT => 16,
        VT_DECIMAL => 16,
        _ => 4, // default
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
    /// Gamepad state fields for capabilities query
    pub gamepad_buttons: u16,
    pub gamepad_left_trigger: u8,
    pub gamepad_right_trigger: u8,
    pub gamepad_thumb_lx: i16,
    pub gamepad_thumb_ly: i16,
    pub gamepad_thumb_rx: i16,
    pub gamepad_thumb_ry: i16,
    /// Vibration motor speeds
    pub vibration_left: u16,
    pub vibration_right: u16,
}

/// XInput battery information.
#[derive(Debug, Clone)]
pub struct BatteryInfo {
    pub battery_type: u8,  // 0=BATTERY_TYPE_WIRED, 1=ALKALINE, 2=NIMH, 3=UNKNOWN
    pub battery_level: u8,  // 0=EMPTY, 1=LOW, 2=MEDIUM, 3=FULL
}

/// XInput keystroke event.
#[derive(Debug, Clone)]
pub struct XInputKeystroke {
    pub virtual_key: u16,
    pub unicode: u16,
    pub flags: u16,
    pub user_index: u8,
    pub hid_code: u8,
}

/// Manages XInput controller state.
pub struct XInputManager {
    controllers: [Option<XInputState>; 4],
    connected: [bool; 4],
    vibration: [XInputVibration; 4],
    enabled: bool,
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
            enabled: true,
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
        let controller = &self.controllers[index as usize];
        let (buttons, lt, rt, lx, ly, rx, ry) = match controller {
            Some(state) => (state.buttons, state.left_trigger, state.right_trigger,
                state.left_thumb_x, state.left_thumb_y, state.right_thumb_x, state.right_thumb_y),
            None => (0u16, 0u8, 0u8, 0i16, 0i16, 0i16, 0i16),
        };
        Ok(XInputCapabilities {
            controller_type: 0, // XINPUT_DEVTYPE_GAMEPAD
            sub_type: 1,       // XINPUT_DEVSUBTYPE_GAMEPAD
            flags: 0,
            vibration_supported: true,
            gamepad_buttons: buttons,
            gamepad_left_trigger: lt,
            gamepad_right_trigger: rt,
            gamepad_thumb_lx: lx,
            gamepad_thumb_ly: ly,
            gamepad_thumb_rx: rx,
            gamepad_thumb_ry: ry,
            vibration_left: self.vibration[index as usize].left_motor_speed,
            vibration_right: self.vibration[index as usize].right_motor_speed,
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

    /// XInputGetBatteryInformation — get battery type and level.
    pub fn get_battery_information(&self, index: u32) -> AppResult<BatteryInfo> {
        if index >= 4 || !self.connected[index as usize] {
            return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "XInput: controller not connected"));
        }
        // Default: wired controller, full battery
        Ok(BatteryInfo {
            battery_type: 0,  // BATTERY_TYPE_WIRED
            battery_level: 3, // BATTERY_LEVEL_FULL
        })
    }

    /// XInputGetKeystroke — get the next pending keystroke event.
    /// Returns Ok(None) when no keystroke is pending (maps to ERROR_EMPTY).
    pub fn get_keystroke(&self, index: u32) -> AppResult<Option<XInputKeystroke>> {
        if index >= 4 {
            return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "XInput: invalid controller index"));
        }
        // No keyboard emulation yet — always return empty
        Ok(None)
    }

    /// XInputEnable — enable or disable XInput processing.
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
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
// Service Control Manager (SCM) API
// ===========================================================================

/// Service status code, matching Windows SERVICE_STATUS values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

impl ServiceStatus {
    /// Convert to the Windows SERVICE_STATUS.dwCurrentCode constant.
    pub fn to_win32_code(&self) -> u32 {
        match self {
            ServiceStatus::Stopped => 0x0001,
            ServiceStatus::StartPending => 0x0002,
            ServiceStatus::StopPending => 0x0003,
            ServiceStatus::Running => 0x0004,
            ServiceStatus::ContinuePending => 0x0005,
            ServiceStatus::PausePending => 0x0006,
            ServiceStatus::Paused => 0x0007,
        }
    }

    /// Convert from a Windows SERVICE_STATUS.dwCurrentCode constant.
    pub fn from_win32_code(code: u32) -> Self {
        match code {
            0x0001 => ServiceStatus::Stopped,
            0x0002 => ServiceStatus::StartPending,
            0x0003 => ServiceStatus::StopPending,
            0x0004 => ServiceStatus::Running,
            0x0005 => ServiceStatus::ContinuePending,
            0x0006 => ServiceStatus::PausePending,
            0x0007 => ServiceStatus::Paused,
            _ => ServiceStatus::Stopped,
        }
    }
}

/// A registered service record within the SCM.
#[derive(Debug, Clone)]
pub struct ScmServiceRecord {
    /// Short service name (e.g. "SteamClientService").
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Current service status.
    pub status: ServiceStatus,
    /// Synthetic handle assigned to this service.
    pub handle: u64,
    /// Path to the service executable.
    pub executable_path: PathBuf,
    /// Process ID if the service is running.
    pub pid: Option<u32>,
}

/// Service Control Manager — stub implementation that records service
/// registrations but does not interact with the macOS launchd or any
/// native service manager.
///
/// This provides the SCM API surface that SteamService.exe queries
/// during its startup and lifecycle (OpenSCManager, CreateService,
/// StartService, ControlService, QueryServiceStatus, etc.).
pub struct ServiceControlManager {
    /// Registered services indexed by name.
    services: BTreeMap<String, ScmServiceRecord>,
    /// Monotonically increasing handle counter.
    next_handle: u64,
}

impl ServiceControlManager {
    /// Create an empty Service Control Manager.
    pub fn new() -> Self {
        Self {
            services: BTreeMap::new(),
            next_handle: 1,
        }
    }

    /// OpenSCManagerW — open the service control manager.
    ///
    /// Returns a synthetic handle representing the SCM database. The
    /// `machine_name` and `database_name` parameters are accepted but
    /// ignored (local machine only).
    pub fn open_sc_manager(&mut self, _machine_name: Option<&str>, _database_name: Option<&str>) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 1;
        handle
    }

    /// CloseServiceHandle — close a handle obtained from OpenSCManagerW
    /// or OpenServiceW.
    ///
    /// Since handles are synthetic, this is a no-op that always succeeds.
    pub fn close_service_handle(&mut self, _handle: u64) -> AppResult<()> {
        Ok(())
    }

    /// CreateServiceW — register a new service with the SCM.
    ///
    /// Parameters follow the Windows `CreateServiceW` signature:
    /// - `sc_handle`: handle from OpenSCManagerW
    /// - `name`: short service name
    /// - `display_name`: display name
    /// - `_desired_access`, _service_type, _start_type, _error_control: standard flags (accepted but not enforced)
    /// - `executable_path`: path to the service binary
    /// - `_load_order_group`, _tag_id, _dependencies, _service_start_name, _password: optional params (accepted but not stored)
    ///
    /// Returns a synthetic service handle.
    #[allow(clippy::too_many_arguments)]
    pub fn create_service(
        &mut self,
        _sc_handle: u64,
        name: &str,
        display_name: &str,
        _desired_access: u32,
        _service_type: u32,
        _start_type: u32,
        _error_control: u32,
        executable_path: &str,
        _load_order_group: Option<&str>,
        _tag_id: Option<&mut u32>,
        _dependencies: Option<&[u8]>,
        _service_start_name: Option<&str>,
        _password: Option<&str>,
    ) -> AppResult<u64> {
        if self.services.contains_key(name) {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: service '{name}' already exists"),
            ));
        }

        let handle = self.next_handle;
        self.next_handle += 1;

        self.services.insert(
            name.to_string(),
            ScmServiceRecord {
                name: name.to_string(),
                display_name: display_name.to_string(),
                status: ServiceStatus::Stopped,
                handle,
                executable_path: PathBuf::from(executable_path),
                pid: None,
            },
        );

        Ok(handle)
    }

    /// OpenServiceW — open an existing service by name.
    ///
    /// Returns the service handle if found.
    pub fn open_service(&self, _sc_handle: u64, name: &str, _desired_access: u32) -> AppResult<u64> {
        self.services.get(name).map(|s| s.handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: service '{name}' not found"),
            )
        })
    }

    /// StartServiceW — start a registered service.
    ///
    /// Transitions the service state to Running and assigns a synthetic PID.
    pub fn start_service(
        &mut self,
        _svc_handle: u64,
        name: &str,
        _argc: u32,
        _argv: Option<&[&str]>,
    ) -> AppResult<()> {
        let record = self.services.get_mut(name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: service '{name}' not found"),
            )
        })?;

        match record.status {
            ServiceStatus::Running => {
                // Already running — return success (ERROR_SERVICE_ALREADY_RUNNING
                // is a warning, not a failure in most callers)
                return Ok(());
            }
            ServiceStatus::StartPending | ServiceStatus::StopPending | ServiceStatus::PausePending => {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    format!("SCM: service '{name}' is in transition state {:?}", record.status),
                ));
            }
            _ => {}
        }

        record.status = ServiceStatus::Running;
        record.pid = Some(42); // Synthetic PID for stub
        Ok(())
    }

    /// ControlService — send a control code to a service.
    ///
    /// Supported control codes:
    /// - 0x01 (SERVICE_CONTROL_STOP) → Stopped
    /// - 0x02 (SERVICE_CONTROL_PAUSE) → Paused
    /// - 0x03 (SERVICE_CONTROL_CONTINUE) → Running
    /// - 0x04 (SERVICE_CONTROL_INTERROGATE) → no state change
    pub fn control_service(&mut self, svc_handle: u64, control_code: u32) -> AppResult<()> {
        let record = self.services.values_mut().find(|s| s.handle == svc_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: no service with handle {svc_handle}"),
            )
        })?;

        match control_code {
            0x01 => {
                // SERVICE_CONTROL_STOP
                record.status = ServiceStatus::Stopped;
                record.pid = None;
            }
            0x02 => {
                // SERVICE_CONTROL_PAUSE
                if record.status == ServiceStatus::Running {
                    record.status = ServiceStatus::Paused;
                }
            }
            0x03 => {
                // SERVICE_CONTROL_CONTINUE
                if record.status == ServiceStatus::Paused {
                    record.status = ServiceStatus::Running;
                }
            }
            0x04 => {
                // SERVICE_CONTROL_INTERROGATE — no state change
            }
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("SCM: unsupported control code {control_code}"),
                ));
            }
        }

        Ok(())
    }

    /// QueryServiceStatus — query the current status of a service by handle.
    ///
    /// Returns the service status code and optional PID. This mirrors the
    /// Windows `QueryServiceStatusEx` / `QUERY_SERVICE_STATUS` structure.
    pub fn query_service_status(&self, svc_handle: u64) -> AppResult<(ServiceStatus, Option<u32>)> {
        let record = self.services.values().find(|s| s.handle == svc_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: no service with handle {svc_handle}"),
            )
        })?;
        Ok((record.status, record.pid))
    }

    /// Query service status by name (convenience wrapper).
    pub fn query_service_status_by_name(&self, name: &str) -> AppResult<(ServiceStatus, Option<u32>)> {
        let record = self.services.get(name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: service '{name}' not found"),
            )
        })?;
        Ok((record.status, record.pid))
    }

    /// DeleteService — remove a service from the SCM database.
    ///
    /// The service must be stopped before it can be deleted.
    pub fn delete_service(&mut self, svc_handle: u64) -> AppResult<()> {
        let name = {
            let record = self.services.values().find(|s| s.handle == svc_handle).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("SCM: no service with handle {svc_handle}"),
                )
            })?;

            if record.status != ServiceStatus::Stopped {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    format!(
                        "SCM: cannot delete service '{}' because it is {:?}",
                        record.name, record.status
                    ),
                ));
            }

            record.name.clone()
        };

        self.services.remove(&name);
        Ok(())
    }

    /// Get a reference to a service record by handle.
    pub fn get_service(&self, svc_handle: u64) -> AppResult<&ScmServiceRecord> {
        self.services.values().find(|s| s.handle == svc_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: no service with handle {svc_handle}"),
            )
        })
    }

    /// Get a reference to a service record by name.
    pub fn get_service_by_name(&self, name: &str) -> AppResult<&ScmServiceRecord> {
        self.services.get(name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: service '{name}' not found"),
            )
        })
    }

    /// Get the number of registered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// List all registered service names.
    pub fn list_services(&self) -> Vec<&str> {
        self.services.keys().map(|s| s.as_str()).collect()
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
        com.co_uninitialize(0);
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

    // --- ServiceControlManager Tests ---

    #[test]
    fn scm_open_and_close() {
        let mut scm = ServiceControlManager::new();
        let handle = scm.open_sc_manager(None, None);
        assert!(handle > 0);
        scm.close_service_handle(handle).unwrap();
    }

    #[test]
    fn scm_create_and_query_service() {
        let mut scm = ServiceControlManager::new();
        let sc_handle = scm.open_sc_manager(None, None);

        let svc_handle = scm
            .create_service(
                sc_handle,
                "TestSvc",
                "Test Service",
                0xF003F, // SERVICE_ALL_ACCESS
                0x10,    // SERVICE_WIN32_OWN_PROCESS
                2,       // SERVICE_AUTO_START
                0,       // SERVICE_ERROR_IGNORE
                "C:\\bin\\test_svc.exe",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        assert_eq!(scm.service_count(), 1);

        let (status, pid) = scm.query_service_status(svc_handle).unwrap();
        assert_eq!(status, ServiceStatus::Stopped);
        assert!(pid.is_none());
    }

    #[test]
    fn scm_start_and_stop_service() {
        let mut scm = ServiceControlManager::new();
        let sc_handle = scm.open_sc_manager(None, None);

        let svc_handle = scm
            .create_service(
                sc_handle,
                "MyService",
                "My Background Service",
                0xF003F,
                0x10,
                3, // SERVICE_DEMAND_START
                0,
                "/usr/local/bin/mysvc",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // Start the service
        scm.start_service(sc_handle, "MyService", 0, None).unwrap();
        let (status, pid) = scm.query_service_status(svc_handle).unwrap();
        assert_eq!(status, ServiceStatus::Running);
        assert_eq!(pid, Some(42));

        // Stop the service
        scm.control_service(svc_handle, 0x01).unwrap(); // SERVICE_CONTROL_STOP
        let (status, pid) = scm.query_service_status(svc_handle).unwrap();
        assert_eq!(status, ServiceStatus::Stopped);
        assert!(pid.is_none());
    }

    #[test]
    fn scm_pause_and_continue_service() {
        let mut scm = ServiceControlManager::new();
        let sc_handle = scm.open_sc_manager(None, None);

        let svc_handle = scm
            .create_service(
                sc_handle,
                "PausableSvc",
                "Pausable Service",
                0xF003F,
                0x10,
                3,
                0,
                "pausable.exe",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        scm.start_service(sc_handle, "PausableSvc", 0, None).unwrap();

        // Pause
        scm.control_service(svc_handle, 0x02).unwrap(); // SERVICE_CONTROL_PAUSE
        let (status, _) = scm.query_service_status(svc_handle).unwrap();
        assert_eq!(status, ServiceStatus::Paused);

        // Continue
        scm.control_service(svc_handle, 0x03).unwrap(); // SERVICE_CONTROL_CONTINUE
        let (status, _) = scm.query_service_status(svc_handle).unwrap();
        assert_eq!(status, ServiceStatus::Running);
    }

    #[test]
    fn scm_delete_service() {
        let mut scm = ServiceControlManager::new();
        let sc_handle = scm.open_sc_manager(None, None);

        let svc_handle = scm
            .create_service(
                sc_handle,
                "ToDelete",
                "To Delete",
                0xF003F,
                0x10,
                3,
                0,
                "delete_me.exe",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        assert_eq!(scm.service_count(), 1);

        // Must be stopped to delete
        scm.delete_service(svc_handle).unwrap();
        assert_eq!(scm.service_count(), 0);
    }

    #[test]
    fn scm_delete_running_service_fails() {
        let mut scm = ServiceControlManager::new();
        let sc_handle = scm.open_sc_manager(None, None);

        let svc_handle = scm
            .create_service(
                sc_handle,
                "RunningSvc",
                "Running Service",
                0xF003F,
                0x10,
                3,
                0,
                "running.exe",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        scm.start_service(sc_handle, "RunningSvc", 0, None).unwrap();
        assert!(scm.delete_service(svc_handle).is_err());
    }

    #[test]
    fn scm_open_nonexistent_service_fails() {
        let scm = ServiceControlManager::new();
        let result = scm.open_service(1, "NonExistent", 0);
        assert!(result.is_err());
    }

    #[test]
    fn scm_list_services() {
        let mut scm = ServiceControlManager::new();
        let sc_handle = scm.open_sc_manager(None, None);

        scm.create_service(sc_handle, "SvcA", "Service A", 0xF003F, 0x10, 3, 0, "a.exe", None, None, None, None, None)
            .unwrap();
        scm.create_service(sc_handle, "SvcB", "Service B", 0xF003F, 0x10, 3, 0, "b.exe", None, None, None, None, None)
            .unwrap();

        let names = scm.list_services();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"SvcA"));
        assert!(names.contains(&"SvcB"));
    }

    #[test]
    fn scm_service_status_conversion() {
        assert_eq!(ServiceStatus::Stopped.to_win32_code(), 0x0001);
        assert_eq!(ServiceStatus::Running.to_win32_code(), 0x0004);
        assert_eq!(ServiceStatus::from_win32_code(0x0004), ServiceStatus::Running);
        assert_eq!(ServiceStatus::from_win32_code(0x0001), ServiceStatus::Stopped);
        assert_eq!(ServiceStatus::from_win32_code(0xFFFF), ServiceStatus::Stopped);
    }
}
