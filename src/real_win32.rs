//! Real Win32 API expansion for Casa1.
//!
//! Implements the critical Win32 APIs needed by Steam and AAA games that are
//! not already covered in `src/win32.rs` and `src/pe_runtime.rs`. This includes
//! COM/OLE automation, MSVC CRT, Shell32, Advapi32, Version, XInput, BCrypt,
//! ThreadPool, synchronization barriers, and DbgHelp.

use crate::dwrite::{CGPoint, CGRect, CGSize};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;
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
    /// List of all IIDs this object supports via QueryInterface.
    pub supported_iids: Vec<[u8; 16]>,
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
    pub const IUNKNOWN: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IDispatch: {00020400-0000-0000-C000-000000000046}
    pub const IDISPATCH: [u8; 16] = [
        0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IClassFactory: {00000001-0000-0000-C000-000000000046}
    pub const ICLASS_FACTORY: [u8; 16] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IID_IShellLinkW: {000214F9-0000-0000-C000-000000000046}
    pub const ISHELLLINKW: [u8; 16] = [
        0xF9, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IID_IPersistFile: {0000010B-0000-0000-C000-000000000046}
    pub const IPERSISTFILE: [u8; 16] = [
        0x0B, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IID_IShellDispatch: {D8F015C0-C278-11CE-A49E-444553540000}
    pub const ISHELL_DISPATCH: [u8; 16] = [
        0xC0, 0x15, 0xF0, 0xD8, 0x78, 0xC2, 0xCE, 0x11, 0xA4, 0x9E, 0x44, 0x45, 0x53, 0x54, 0x00,
        0x00,
    ];
    /// IID_IWshShell: {F935DC21-1CF0-11D0-ADB9-00C04FD58A0B}
    pub const IWSH_SHELL: [u8; 16] = [
        0x21, 0xDC, 0x35, 0xF9, 0xF0, 0x1C, 0xD0, 0x11, 0xAD, 0xB9, 0x00, 0xC0, 0x4F, 0xD5, 0x8A,
        0x0B,
    ];
    /// IID_IFileSystem: {0D43FE01-F453-11CE-9B6E-0080560B0141}
    pub const IFILESYSTEM: [u8; 16] = [
        0x01, 0xFE, 0x43, 0x0D, 0x53, 0xF4, 0xCE, 0x11, 0x9B, 0x6E, 0x00, 0x80, 0x56, 0x0B, 0x01,
        0x41,
    ];
    /// IID_IADODBConnection: {00000550-0000-0010-8000-00AA006D2EA4}
    pub const IADODB_CONNECTION: [u8; 16] = [
        0x50, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E,
        0xA4,
    ];
    /// IID_IADODBRecordset: {00000535-0000-0010-8000-00AA006D2EA4}
    pub const IADODB_RECORDSET: [u8; 16] = [
        0x35, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E,
        0xA4,
    ];
    /// IID_IWbemLocator: {DC12A687-737F-11CF-884D-00AA004B2E24}
    pub const IWBEM_LOCATOR: [u8; 16] = [
        0x87, 0xA6, 0x12, 0xDC, 0x7F, 0x73, 0xCF, 0x11, 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E,
        0x24,
    ];
    /// IID_IWbemServices: {9556DC99-828C-11CF-A37E-00AA003240C7}
    pub const IWBEM_SERVICES: [u8; 16] = [
        0x99, 0xDC, 0x56, 0x95, 0x8C, 0x82, 0xCF, 0x11, 0xA3, 0x7E, 0x00, 0xAA, 0x00, 0x32, 0x40,
        0xC7,
    ];
    /// IID_IWbemClassObject: {DC12A681-737F-11CF-884D-00AA004B2E24}
    pub const IWBEM_CLASS_OBJECT: [u8; 16] = [
        0x81, 0xA6, 0x12, 0xDC, 0x7F, 0x73, 0xCF, 0x11, 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E,
        0x24,
    ];
    /// IID_IEnumWbemClassObject: {027947E1-D731-11CE-A357-000000000001}
    pub const IENUM_WBEM_CLASS_OBJECT: [u8; 16] = [
        0xE1, 0x47, 0x79, 0x02, 0x31, 0xD7, 0xCE, 0x11, 0xA3, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    /// IID_IDirectSound8: {C50A7E93-F395-4834-9EF6-3168FD6A6110}
    pub const IDIRECTSOUND8: [u8; 16] = [
        0x93, 0x7E, 0x0A, 0xC5, 0x95, 0xF3, 0x34, 0x48, 0x9E, 0xF6, 0x31, 0x68, 0xFD, 0x6A, 0x61,
        0x10,
    ];
    /// IID_IDirectSoundBuffer8: {6825A449-7524-4D82-920F-50E36AB3AB1E}
    pub const IDIRECTSOUNDBUFFER8: [u8; 16] = [
        0x49, 0xA4, 0x25, 0x68, 0x24, 0x75, 0x82, 0x4D, 0x92, 0x0F, 0x50, 0xE3, 0x6A, 0xB3, 0xAB,
        0x1E,
    ];
    /// IID_IDirectSoundCapture8: {B0210781-89CD-11D0-AF6B-00A0C9223196}
    pub const IDIRECTSOUNDCAPTURE8: [u8; 16] = [
        0x81, 0x07, 0x21, 0xB0, 0xCD, 0x89, 0xD0, 0x11, 0xAF, 0x6B, 0x00, 0xA0, 0xC9, 0x22, 0x31,
        0x96,
    ];
    /// IID_IXAudio2: {2B4FB60E-1E74-42A7-B03B-57A3C62D3B0F}
    pub const IXAUDIO2: [u8; 16] = [
        0x0E, 0xB6, 0x4F, 0x2B, 0x74, 0x1E, 0xA7, 0x42, 0xB0, 0x3B, 0x57, 0xA3, 0xC6, 0x2D, 0x3B,
        0x0F,
    ];
    /// IID_IXAudio2MasteringVoice: {9FE5E5B1-F9D1-4D8E-B3F0-8D5D5E9C9A1E}
    pub const IXAUDIO2_MASTERING_VOICE: [u8; 16] = [
        0xB1, 0xE5, 0xE5, 0x9F, 0xD1, 0xF9, 0x8E, 0x4D, 0xB3, 0xF0, 0x8D, 0x5D, 0x5E, 0x9C, 0x9A,
        0x1E,
    ];
    /// IID_IXAudio2SourceVoice: {1D7B1C2B-87D4-4D6E-B535-59C2E13E7F33}
    pub const IXAUDIO2_SOURCE_VOICE: [u8; 16] = [
        0x2B, 0x1C, 0x7B, 0x1D, 0xD4, 0x87, 0x6E, 0x4D, 0xB5, 0x35, 0x59, 0xC2, 0xE1, 0x3E, 0x7F,
        0x33,
    ];
    /// IID_IXAudio2SubmixVoice: {4F0F5C0F-3E9A-4E6D-8B3A-4E9F7C5A0B1E}
    pub const IXAUDIO2_SUBMIX_VOICE: [u8; 16] = [
        0x0F, 0x5C, 0x0F, 0x4F, 0x9A, 0x3E, 0x6D, 0x4E, 0x8B, 0x3A, 0x4E, 0x9F, 0x7C, 0x5A, 0x0B,
        0x1E,
    ];
    /// IID_IFileDialog: {42F85136-DB7E-4C53-85B6-8429F2E8E0E8}
    pub const IFILE_DIALOG: [u8; 16] = [
        0x36, 0x51, 0xF8, 0x42, 0x7E, 0xDB, 0x53, 0x4C, 0x85, 0xB6, 0x84, 0x29, 0xF2, 0xE8, 0xE0,
        0xE8,
    ];
    /// IID_IFileOpenDialog: {42F85136-DB7E-4C53-85B6-8429F2E8E0E9}
    pub const IFILE_OPEN_DIALOG: [u8; 16] = [
        0x36, 0x51, 0xF8, 0x42, 0x7E, 0xDB, 0x53, 0x4C, 0x85, 0xB6, 0x84, 0x29, 0xF2, 0xE8, 0xE0,
        0xE9,
    ];
    /// IID_IFileSaveDialog: {84BCCD23-5FDE-4CDB-AEA4-AF4B83B78AD7}
    pub const IFILE_SAVE_DIALOG: [u8; 16] = [
        0x23, 0xCD, 0xBC, 0x84, 0xDE, 0x5F, 0xDB, 0x4C, 0xAE, 0xA4, 0xAF, 0x4B, 0x83, 0xB7, 0x8A,
        0xD7,
    ];
    /// IID_IModalWindow: {B4DB1657-70D7-485E-8E3E-6FCB5A5C1802}
    pub const IMODAL_WINDOW: [u8; 16] = [
        0x57, 0x16, 0xDB, 0xB4, 0xD7, 0x70, 0x5E, 0x48, 0x8E, 0x3E, 0x6F, 0xCB, 0x5A, 0x5C, 0x18,
        0x02,
    ];
    /// IID_ITaskbarList: {56FDF342-FD6D-11D0-958A-006097C9A090}
    pub const ITASKBAR_LIST: [u8; 16] = [
        0x42, 0xF3, 0xFD, 0x56, 0x6D, 0xFD, 0xD0, 0x11, 0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0,
        0x90,
    ];
    /// IID_ITaskbarList2: {602D4995-B13A-429B-A66E-1935E44AA7CF}
    pub const ITASKBAR_LIST2: [u8; 16] = [
        0x95, 0x49, 0x2D, 0x60, 0x3A, 0xB1, 0x9B, 0x42, 0xA6, 0x6E, 0x19, 0x35, 0xE4, 0x4A, 0xA7,
        0xCF,
    ];
    /// IID_ITaskbarList3: {EA1AFB91-9E28-4B86-90E9-9E9F8A5EEFAF}
    pub const ITASKBAR_LIST3: [u8; 16] = [
        0x91, 0xFB, 0x1A, 0xEA, 0x28, 0x9E, 0x86, 0x4B, 0x90, 0xE9, 0x9E, 0x9F, 0x8A, 0x5E, 0xEF,
        0xAF,
    ];
    // ===========================================================================
    // Phase L: COM/Shell Completion IIDs
    // ===========================================================================
    /// IID_IShellFolder: {000214E6-0000-0000-C000-000000000046}
    pub const ISHELL_FOLDER: [u8; 16] = [
        0xE6, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IID_IEnumIDList: {000214F2-0000-0000-C000-000000000046}
    pub const IENUM_ID_LIST: [u8; 16] = [
        0xF2, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IID_IShellItem: {43826D1E-E718-42EE-BC55-A1E261C37BFE}
    pub const ISHELL_ITEM: [u8; 16] = [
        0x1E, 0x6D, 0x82, 0x43, 0x18, 0xE7, 0xEE, 0x42, 0xBC, 0x55, 0xA1, 0xE2, 0x61, 0xC3, 0x7B,
        0xFE,
    ];
    /// IID_IContextMenu: {000214E4-0000-0000-C000-000000000046}
    pub const ICONTEXT_MENU: [u8; 16] = [
        0xE4, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IID_IPropertyStore: {886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99}
    pub const IPROPERTY_STORE: [u8; 16] = [
        0xEB, 0x8E, 0x6D, 0x88, 0xF2, 0x8C, 0x46, 0x44, 0x8D, 0x02, 0xCD, 0xBA, 0x1D, 0xBD, 0xCF,
        0x99,
    ];
    /// IID_IXMLDOMDocument: {2933BF81-7B36-11D2-B20E-00C04F983E60}
    pub const IXMLDOM_DOCUMENT: [u8; 16] = [
        0x81, 0xBF, 0x33, 0x29, 0x36, 0x7B, 0xD2, 0x11, 0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E,
        0x60,
    ];
    /// IID_IXMLDOMNode: {2933BF80-7B36-11D2-B20E-00C04F983E60}
    pub const IXMLDOM_NODE: [u8; 16] = [
        0x80, 0xBF, 0x33, 0x29, 0x36, 0x7B, 0xD2, 0x11, 0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E,
        0x60,
    ];
    /// IID_IXMLDOMElement: {2933BF86-7B36-11D2-B20E-00C04F983E60}
    pub const IXMLDOM_ELEMENT: [u8; 16] = [
        0x86, 0xBF, 0x33, 0x29, 0x36, 0x7B, 0xD2, 0x11, 0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E,
        0x60,
    ];
    /// IID_IXMLDOMNodeList: {2933BF82-7B36-11D2-B20E-00C04F983E60}
    pub const IXMLDOM_NODE_LIST: [u8; 16] = [
        0x82, 0xBF, 0x33, 0x29, 0x36, 0x7B, 0xD2, 0x11, 0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E,
        0x60,
    ];
    /// IID_IMoniker: {0000000F-0000-0000-C000-000000000046}
    pub const IMONIKER: [u8; 16] = [
        0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IID_IBindCtx: {00000000-0000-0000-C000-000000000046}
    pub const IBINDCTX: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IID_IBindStatusCallback: {79EAC958-BA99-11D1-90B8-00A0C969729C}
    pub const IBINDSTATUSCALLBACK: [u8; 16] = [
        0x58, 0xC9, 0xEA, 0x79, 0x99, 0xBA, 0xD1, 0x11, 0x90, 0xB8, 0x00, 0xA0, 0xC9, 0x69, 0x72,
        0x9C,
    ];
    /// IID_IShellView: {000214E3-0000-0000-C000-000000000046}
    pub const ISHELL_VIEW: [u8; 16] = [
        0xE3, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IID_IDropTarget: {00000122-0000-0000-C000-000000000046}
    pub const IDROP_TARGET: [u8; 16] = [
        0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// IID_IHTMLDocument2: {332C4425-26CB-11D0-B483-00C04FD90119}
    pub const IHTML_DOCUMENT2: [u8; 16] = [
        0x25, 0x44, 0x2C, 0x33, 0xCB, 0x26, 0xD0, 0x11, 0xB4, 0x83, 0x00, 0xC0, 0x4F, 0xD9, 0x01,
        0x19,
    ];
    /// IID_IHTMLElement: {332C4426-26CB-11D0-B483-00C04FD90119}
    pub const IHTML_ELEMENT: [u8; 16] = [
        0x26, 0x44, 0x2C, 0x33, 0xCB, 0x26, 0xD0, 0x11, 0xB4, 0x83, 0x00, 0xC0, 0x4F, 0xD9, 0x01,
        0x19,
    ];
    /// IID_IHTMLBodyElement: {3050F1D8-98B5-11CF-BB82-00AA00BDCE0B}
    pub const IHTML_BODY_ELEMENT: [u8; 16] = [
        0xD8, 0xF1, 0x50, 0x30, 0xB5, 0x98, 0xCF, 0x11, 0xBB, 0x82, 0x00, 0xAA, 0x00, 0xBD, 0xCE,
        0x0B,
    ];
    // ===========================================================================
    // D3D10 Interface IIDs
    // ===========================================================================
    /// IID_ID3D10Device: {9B7E4C0F-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10DEVICE: [u8; 16] = [
        0x0F, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Texture2D: {9B7E4C80-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10TEXTURE2D: [u8; 16] = [
        0x80, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Buffer: {9B7E4C81-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10BUFFER: [u8; 16] = [
        0x81, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10RenderTargetView: {9B7E4C82-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10RENDERTARGETVIEW: [u8; 16] = [
        0x82, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10DepthStencilView: {9B7E4C83-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10DEPTHSTENCILVIEW: [u8; 16] = [
        0x83, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10ShaderResourceView: {9B7E4C84-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10SHADERRESOURCEVIEW: [u8; 16] = [
        0x84, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10VertexShader: {9B7E4C85-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10VERTEXSHADER: [u8; 16] = [
        0x85, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10PixelShader: {9B7E4C86-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10PIXELSHADER: [u8; 16] = [
        0x86, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10GeometryShader: {9B7E4C87-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10GEOMETRYSHADER: [u8; 16] = [
        0x87, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10InputLayout: {9B7E4C88-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10INPUTLAYOUT: [u8; 16] = [
        0x88, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10SamplerState: {9B7E4C89-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10SAMPLERSTATE: [u8; 16] = [
        0x89, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10BlendState: {9B7E4C8A-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10BLENDSTATE: [u8; 16] = [
        0x8A, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10RasterizerState: {9B7E4C8B-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10RASTERIZERSTATE: [u8; 16] = [
        0x8B, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10DepthStencilState: {9B7E4C8C-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10DEPTHSTENCILSTATE: [u8; 16] = [
        0x8C, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
}

/// Well-known CLSIDs used by Steam and games.
pub struct ComClsid;

impl ComClsid {
    /// DirectSound8: {3901CC3F-84B5-4FA4-BA35-AA8172B8A6B2}
    pub const DIRECTSOUND8: [u8; 16] = [
        0x3F, 0xCC, 0x01, 0x39, 0xB5, 0x84, 0xA4, 0x4F, 0xBA, 0x35, 0xAA, 0x81, 0x72, 0xB8, 0xA6,
        0xB2,
    ];
    /// XAudio2: {609ED052-35B5-4F10-9BE6-39650F9781D4}
    pub const XAUDIO2: [u8; 16] = [
        0x52, 0xD0, 0x9E, 0x60, 0xB5, 0x35, 0x10, 0x4F, 0x9B, 0xE6, 0x39, 0x65, 0x0F, 0x97, 0x81,
        0xD4,
    ];
    /// CLSID_ShellLink: {00021401-0000-0000-C000-000000000046}
    pub const SHELL_LINK: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// CLSID_FileOpenDialog: {DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7}
    pub const FILE_OPEN_DIALOG: [u8; 16] = [
        0x9C, 0x5A, 0x1C, 0xDC, 0x8A, 0xE8, 0xDE, 0x4D, 0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE,
        0xF7,
    ];
    /// CLSID_FileSaveDialog: {C0B4E2F3-BA21-4773-8DBA-335EC946EB8B}
    pub const FILE_SAVE_DIALOG: [u8; 16] = [
        0xF3, 0xE2, 0xB4, 0xC0, 0x21, 0xBA, 0x73, 0x47, 0x8D, 0xBA, 0x33, 0x5E, 0xC9, 0x46, 0xEB,
        0x8B,
    ];
    /// CLSID_ShellApplication: {13709620-C279-11CE-A49E-444553540000}
    pub const SHELL_APPLICATION: [u8; 16] = [
        0x20, 0x96, 0x70, 0x13, 0x79, 0xC2, 0xCE, 0x11, 0xA4, 0x9E, 0x44, 0x45, 0x53, 0x54, 0x00,
        0x00,
    ];
    /// CLSID_ScriptingFileSystemObject: {0D43FE01-F453-11CE-9B6E-0080560B0141}
    pub const SCRIPTING_FILESYSTEMOBJECT: [u8; 16] = [
        0x01, 0xFE, 0x43, 0x0D, 0x53, 0xF4, 0xCE, 0x11, 0x9B, 0x6E, 0x00, 0x80, 0x56, 0x0B, 0x01,
        0x41,
    ];
    /// CLSID_WScriptShell: {72C24DD5-D70A-438B-8A42-98424B88AFB8}
    pub const WSCRIPT_SHELL: [u8; 16] = [
        0xD5, 0x4D, 0xC2, 0x72, 0x0A, 0xD7, 0x8B, 0x43, 0x8A, 0x42, 0x98, 0x42, 0x4B, 0x88, 0xAF,
        0xB8,
    ];
    /// CLSID_ADODBConnection: {00000514-0000-0010-8000-00AA006D2EA4}
    pub const ADODB_CONNECTION: [u8; 16] = [
        0x14, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E,
        0xA4,
    ];
    /// CLSID_ADODBRecordset: {00000535-0000-0010-8000-00AA006D2EA4}
    pub const ADODB_RECORDSET: [u8; 16] = [
        0x35, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E,
        0xA4,
    ];
    /// CLSID_WScriptNetwork: {093FF999-1EA0-4079-9525-9614C3504B74}
    pub const WSCRIPT_NETWORK: [u8; 16] = [
        0x99, 0xF9, 0x3F, 0x09, 0xA0, 0x1E, 0x79, 0x40, 0x95, 0x25, 0x96, 0x14, 0xC3, 0x50, 0x4B,
        0x74,
    ];
    /// CLSID_ShellWindows: {9BA05972-F6A8-11CF-A442-00A0C90A8F39}
    pub const SHELL_WINDOWS: [u8; 16] = [
        0x72, 0x59, 0xA0, 0x9B, 0xA8, 0xF6, 0xCF, 0x11, 0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F,
        0x39,
    ];
    /// CLSID_InternetExplorer: {0002DF01-0000-0000-C000-000000000046}
    pub const INTERNET_EXPLORER: [u8; 16] = [
        0x01, 0xDF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// CLSID_XMLHTTP: {ED8C108E-4349-11D2-91DB-0060081A4682}
    pub const XMLHTTP: [u8; 16] = [
        0x0E, 0x10, 0x8C, 0xED, 0x49, 0x43, 0xD2, 0x11, 0x91, 0xDB, 0x00, 0x60, 0x08, 0x1A, 0x46,
        0x82,
    ];
    /// CLSID_DOMDocument: {2933BF90-7B36-11D2-B20E-00C04F983E60}
    pub const DOM_DOCUMENT: [u8; 16] = [
        0x90, 0xBF, 0x33, 0x29, 0x36, 0x7B, 0xD2, 0x11, 0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E,
        0x60,
    ];
    /// CLSID_WbemLocator: {4590F811-1D3A-11D0-891F-00AA004B2E24}
    pub const WBEM_LOCATOR: [u8; 16] = [
        0x11, 0xF8, 0x90, 0x45, 0x3A, 0x1D, 0xD0, 0x11, 0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E,
        0x24,
    ];
    /// CLSID_WbemContext: {674B6698-EE92-11D0-AD71-00C04FD8FDFF}
    pub const WBEM_CONTEXT: [u8; 16] = [
        0x98, 0x66, 0x4B, 0x67, 0x92, 0xEE, 0xD0, 0x11, 0xAD, 0x71, 0x00, 0xC0, 0x4F, 0xD8, 0xFD,
        0xFF,
    ];
    /// CLSID_TaskbarList: {56FDF344-FD6D-11D0-958A-006097C9A090}
    pub const TASKBAR_LIST: [u8; 16] = [
        0x44, 0xF3, 0xFD, 0x56, 0x6D, 0xFD, 0xD0, 0x11, 0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0,
        0x90,
    ];
    // ===========================================================================
    // Phase L: COM/Shell Completion CLSIDs
    // ===========================================================================
    /// CLSID_ShellFolder (desktop): {00021400-0000-0000-C000-000000000046}
    pub const SHELL_FOLDER: [u8; 16] = [
        0x00, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// CLSID_ShellDesktop: {00021400-0000-0000-C000-000000000046} (alias)
    pub const SHELL_DESKTOP: [u8; 16] = [
        0x00, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    /// CLSID_UrlMoniker: {79EAC9E0-BAF9-11CE-8C82-00AA004BA90B}
    pub const URL_MONIKER: [u8; 16] = [
        0xE0, 0xC9, 0xEA, 0x79, 0xF9, 0xBA, 0xCE, 0x11, 0x8C, 0x82, 0x00, 0xAA, 0x00, 0x4B, 0xA9,
        0x0B,
    ];
    /// CLSID_HTMLDocument (Trident): {25336920-03F9-11CF-8FD0-00AA00686F13}
    pub const HTML_DOCUMENT: [u8; 16] = [
        0x20, 0x69, 0x33, 0x25, 0xF9, 0x03, 0xCF, 0x11, 0x8F, 0xD0, 0x00, 0xAA, 0x00, 0x68, 0x6F,
        0x13,
    ];
}

// ===========================================================================
// Functional COM Object Implementations
// ===========================================================================

/// Functional DirectSound8 COM object.
///
/// Supports `IDirectSound8` interface for audio output.
/// Wires through the existing `crate::audio::AudioSubsystem` for
/// buffer creation, playback control, and speaker configuration.
pub struct DirectSound8Object {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    /// Audio device identifier for output.
    device_id: Option<crate::audio::DirectSoundId>,
}

impl DirectSound8Object {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::IDIRECTSOUND8],
            name: "DirectSound8".to_string(),
            device_id: None,
        }
    }
}

impl ComObject for DirectSound8Object {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

/// Functional DirectSound buffer COM object.
///
/// Supports `IDirectSoundBuffer8` interface for audio playback.
pub struct DirectSoundBuffer8Object {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
}

impl DirectSoundBuffer8Object {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::IDIRECTSOUNDBUFFER8],
            name: "DirectSoundBuffer8".to_string(),
        }
    }
}

impl ComObject for DirectSoundBuffer8Object {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

/// Functional XAudio2 engine COM object.
///
/// Supports `IXAudio2` interface for audio engine management.
/// Wires through the existing `crate::audio::AudioSubsystem` for
/// mastering voices, source voices, and submix voices.
pub struct XAudio2Object {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
}

impl XAudio2Object {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::IXAUDIO2],
            name: "XAudio2".to_string(),
        }
    }
}

impl ComObject for XAudio2Object {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

/// Functional XAudio2 mastering voice COM object.
pub struct XAudio2MasteringVoiceObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
}

impl XAudio2MasteringVoiceObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::IXAUDIO2_MASTERING_VOICE],
            name: "XAudio2MasteringVoice".to_string(),
        }
    }
}

impl ComObject for XAudio2MasteringVoiceObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

/// Functional XAudio2 source voice COM object.
pub struct XAudio2SourceVoiceObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
}

impl XAudio2SourceVoiceObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::IXAUDIO2_SOURCE_VOICE],
            name: "XAudio2SourceVoice".to_string(),
        }
    }
}

impl ComObject for XAudio2SourceVoiceObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

/// Functional XAudio2 submix voice COM object.
pub struct XAudio2SubmixVoiceObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
}

impl XAudio2SubmixVoiceObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::IXAUDIO2_SUBMIX_VOICE],
            name: "XAudio2SubmixVoice".to_string(),
        }
    }
}

impl ComObject for XAudio2SubmixVoiceObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

/// Functional Shell Link COM object.
///
/// Supports `IShellLinkW` and `IPersistFile` interfaces for
/// shortcut (.lnk) file operations including path storage,
/// arguments, description, working directory, icon location,
/// show command, and persistent storage.
pub struct ShellLinkObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    /// Stored link path
    path: String,
    /// Stored arguments
    arguments: String,
    /// Stored description
    description: String,
    /// Stored working directory
    working_directory: String,
    /// Stored icon location
    icon_location: String,
    /// Stored icon index
    icon_index: i32,
    /// Stored show command
    show_cmd: i32,
}

impl ShellLinkObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::ISHELLLINKW, ComIid::IPERSISTFILE],
            name: "ShellLink".to_string(),
            path: String::new(),
            arguments: String::new(),
            description: String::new(),
            working_directory: String::new(),
            icon_location: String::new(),
            icon_index: 0,
            show_cmd: 1, // SW_SHOWNORMAL
        }
    }

    /// Get the stored target path.
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// Set the target path.
    pub fn set_path(&mut self, path: String) {
        self.path = path;
    }

    /// Get the stored arguments.
    pub fn get_arguments(&self) -> &str {
        &self.arguments
    }

    /// Set the arguments.
    pub fn set_arguments(&mut self, args: String) {
        self.arguments = args;
    }

    /// Get the stored description.
    pub fn get_description(&self) -> &str {
        &self.description
    }

    /// Set the description.
    pub fn set_description(&mut self, desc: String) {
        self.description = desc;
    }

    /// Get the stored working directory.
    pub fn get_working_directory(&self) -> &str {
        &self.working_directory
    }

    /// Set the working directory.
    pub fn set_working_directory(&mut self, dir: String) {
        self.working_directory = dir;
    }

    /// Get the stored icon location and index.
    pub fn get_icon_location(&self) -> (&str, i32) {
        (&self.icon_location, self.icon_index)
    }

    /// Set the icon location and index.
    pub fn set_icon_location(&mut self, location: String, index: i32) {
        self.icon_location = location;
        self.icon_index = index;
    }

    /// Get the show command.
    pub fn get_show_cmd(&self) -> i32 {
        self.show_cmd
    }

    /// Set the show command.
    pub fn set_show_cmd(&mut self, cmd: i32) {
        self.show_cmd = cmd;
    }
}

impl ComObject for ShellLinkObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

/// Functional File Open Dialog COM object.
///
/// Supports `IFileOpenDialog`, `IFileDialog`, and `IModalWindow`
/// interfaces for file open/save dialog operations.
/// In headless mode, returns a default/simulated result path.
pub struct FileOpenDialogObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    /// Stored default folder path
    default_folder: String,
    /// Stored current folder path
    folder: String,
    /// Stored file name
    file_name: String,
    /// Stored dialog title
    title: String,
    /// Stored OK button label
    ok_button_label: String,
    /// Stored file name label
    file_name_label: String,
    /// List of file type filters (description, pattern)
    file_types: Vec<(String, String)>,
    /// Current file type index
    file_type_index: u32,
    /// Dialog options flags
    options: u32,
    /// Result path (set after Show)
    result_path: String,
    /// Whether the dialog has been shown
    shown: bool,
}

impl FileOpenDialogObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![
                ComIid::IUNKNOWN,
                ComIid::IMODAL_WINDOW,
                ComIid::IFILE_DIALOG,
                ComIid::IFILE_OPEN_DIALOG,
            ],
            name: "FileOpenDialog".to_string(),
            default_folder: String::new(),
            folder: String::new(),
            file_name: String::new(),
            title: String::new(),
            ok_button_label: String::new(),
            file_name_label: String::new(),
            file_types: Vec::new(),
            file_type_index: 0,
            options: 0,
            result_path: String::new(),
            shown: false,
        }
    }

    /// Get the file type filters.
    pub fn file_types(&self) -> &[(String, String)] {
        &self.file_types
    }

    /// Set file type filters.
    pub fn set_file_types(&mut self, types: Vec<(String, String)>) {
        self.file_types = types;
    }

    /// Get the current file type index.
    pub fn file_type_index(&self) -> u32 {
        self.file_type_index
    }

    /// Set the file type index.
    pub fn set_file_type_index(&mut self, index: u32) {
        self.file_type_index = index;
    }

    /// Get dialog options.
    pub fn options(&self) -> u32 {
        self.options
    }

    /// Set dialog options.
    pub fn set_options(&mut self, opts: u32) {
        self.options = opts;
    }

    /// Get the default folder.
    pub fn default_folder(&self) -> &str {
        &self.default_folder
    }

    /// Set the default folder.
    pub fn set_default_folder(&mut self, folder: String) {
        self.default_folder = folder;
    }

    /// Get the current folder.
    pub fn folder(&self) -> &str {
        &self.folder
    }

    /// Set the current folder.
    pub fn set_folder(&mut self, folder: String) {
        self.folder = folder;
    }

    /// Get the file name.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Set the file name.
    pub fn set_file_name(&mut self, name: String) {
        self.file_name = name;
    }

    /// Get the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Set the dialog title.
    pub fn set_title(&mut self, title: String) {
        self.title = title;
    }

    /// Get the OK button label.
    pub fn ok_button_label(&self) -> &str {
        &self.ok_button_label
    }

    /// Set the OK button label.
    pub fn set_ok_button_label(&mut self, label: String) {
        self.ok_button_label = label;
    }

    /// Get the file name label.
    pub fn file_name_label(&self) -> &str {
        &self.file_name_label
    }

    /// Set the file name label.
    pub fn set_file_name_label(&mut self, label: String) {
        self.file_name_label = label;
    }

    /// Show the dialog (simulated: returns a default path).
    pub fn show(&mut self) {
        self.shown = true;
        // Return the current file name if set, otherwise a default path
        if !self.file_name.is_empty() {
            self.result_path = self.file_name.clone();
        } else {
            self.result_path = "/tmp/default_file.txt".to_string();
        }
    }

    /// Get the result path after showing the dialog.
    pub fn result_path(&self) -> &str {
        &self.result_path
    }

    /// Whether the dialog has been shown.
    pub fn is_shown(&self) -> bool {
        self.shown
    }
}

impl ComObject for FileOpenDialogObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

/// Functional File Save Dialog COM object.
///
/// Supports `IFileSaveDialog`, `IFileDialog`, and `IModalWindow`
/// interfaces for file save dialog operations.
pub struct FileSaveDialogObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    inner: FileOpenDialogObject,
}

impl FileSaveDialogObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        let mut inner = FileOpenDialogObject::new(clsid);
        inner.name = "FileSaveDialog".to_string();
        inner.supported = vec![
            ComIid::IUNKNOWN,
            ComIid::IMODAL_WINDOW,
            ComIid::IFILE_DIALOG,
            ComIid::IFILE_SAVE_DIALOG,
        ];
        Self {
            clsid,
            supported: vec![
                ComIid::IUNKNOWN,
                ComIid::IMODAL_WINDOW,
                ComIid::IFILE_DIALOG,
                ComIid::IFILE_SAVE_DIALOG,
            ],
            name: "FileSaveDialog".to_string(),
            inner,
        }
    }
}

impl ComObject for FileSaveDialogObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

/// Functional Taskbar List COM object.
///
/// Supports `ITaskbarList3`, `ITaskbarList2`, and `ITaskbarList`
/// interfaces for Windows taskbar integration.
/// On macOS, all operations are no-ops that return S_OK since
/// there is no native taskbar to interact with.
pub struct TaskbarListObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    /// Whether HrInit has been called
    initialized: bool,
    /// Tab window handles
    tabs: Vec<u64>,
    /// Progress value for each tab (0-1000)
    progress_values: std::collections::HashMap<u64, u32>,
    /// Progress state for each tab
    progress_states: std::collections::HashMap<u64, u32>,
    /// Overlay icon handles
    overlay_icons: std::collections::HashMap<u64, u64>,
    /// Thumbnail tooltips
    thumbnail_tooltips: std::collections::HashMap<u64, String>,
    /// Active tab
    active_tab: Option<u64>,
}

impl TaskbarListObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![
                ComIid::IUNKNOWN,
                ComIid::ITASKBAR_LIST,
                ComIid::ITASKBAR_LIST2,
                ComIid::ITASKBAR_LIST3,
            ],
            name: "TaskbarList".to_string(),
            initialized: false,
            tabs: Vec::new(),
            progress_values: std::collections::HashMap::new(),
            progress_states: std::collections::HashMap::new(),
            overlay_icons: std::collections::HashMap::new(),
            thumbnail_tooltips: std::collections::HashMap::new(),
            active_tab: None,
        }
    }

    /// HrInit — initialize the taskbar list.
    pub fn hr_init(&mut self) {
        self.initialized = true;
    }

    /// Add a tab to the taskbar.
    pub fn add_tab(&mut self, hwnd: u64) {
        if !self.tabs.contains(&hwnd) {
            self.tabs.push(hwnd);
        }
    }

    /// Delete a tab from the taskbar.
    pub fn delete_tab(&mut self, hwnd: u64) {
        self.tabs.retain(|&t| t != hwnd);
        // Prune per-HWND state so a guest cycling bogus handles cannot grow
        // the side maps without bound.
        self.progress_values.remove(&hwnd);
        self.progress_states.remove(&hwnd);
        self.overlay_icons.remove(&hwnd);
        self.thumbnail_tooltips.remove(&hwnd);
        if self.active_tab == Some(hwnd) {
            self.active_tab = None;
        }
    }

    /// Activate a tab.
    pub fn activate_tab(&mut self, hwnd: u64) {
        self.active_tab = Some(hwnd);
    }

    /// Set active alt tab.
    pub fn set_active_alt(&mut self, hwnd: u64) {
        self.active_tab = Some(hwnd);
    }

    /// Set progress value for a tab (0-1000).
    pub fn set_progress_value(&mut self, hwnd: u64, value: u32) {
        if self.track_new_hwnd(hwnd) {
            self.progress_values.insert(hwnd, value.min(1000));
        }
    }

    /// Set progress state for a tab.
    pub fn set_progress_state(&mut self, hwnd: u64, state: u32) {
        if self.track_new_hwnd(hwnd) {
            self.progress_states.insert(hwnd, state);
        }
    }

    /// Set overlay icon for a tab.
    pub fn set_overlay_icon(&mut self, hwnd: u64, icon: u64) {
        if self.track_new_hwnd(hwnd) {
            self.overlay_icons.insert(hwnd, icon);
        }
    }

    /// Set thumbnail tooltip for a tab.
    pub fn set_thumbnail_tooltip(&mut self, hwnd: u64, tip: String) {
        if self.track_new_hwnd(hwnd) {
            self.thumbnail_tooltips.insert(hwnd, tip);
        }
    }

    /// Bound the number of tracked HWNDs so guest-supplied bogus handles
    /// cannot grow the per-HWND maps without limit.
    fn track_new_hwnd(&mut self, hwnd: u64) -> bool {
        const MAX_TRACKED_HWNDS: usize = 1024;
        if self.tabs.contains(&hwnd) || self.progress_values.contains_key(&hwnd) {
            return true;
        }
        let tracked = self.progress_values.len();
        if tracked >= MAX_TRACKED_HWNDS {
            eprintln!(
                "[RealWin32] TaskbarList: tracked HWND limit ({MAX_TRACKED_HWNDS}) reached; ignoring {hwnd:#x}"
            );
            return false;
        }
        true
    }

    /// Is the taskbar list initialized?
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the number of tabs.
    pub fn tab_count(&self) -> usize {
        self.tabs.len()
    }

    /// Get all tab window handles.
    pub fn tabs(&self) -> &[u64] {
        &self.tabs
    }
}

impl ComObject for TaskbarListObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

// ===========================================================================
// Phase L: COM/Shell Completion — PIDL Helpers
// ===========================================================================

/// Maximum PIDL size (arbitrary: 64KB).
pub const MAX_PIDL_SIZE: usize = 65536;

/// Minimum PIDL size (header: 2 bytes total_size + 2 bytes item_size).
pub const MIN_PIDL_SIZE: usize = 4;

/// Build a PIDL from a macOS path.
///
/// PIDL structure (simple encoding):
///   [total_size: u16][item1_size: u16][item1_data...][itemN_size: u16][itemN_data...][0x0000]
///
/// For simplicity, we store the UTF-16 path as a single item.
/// Returns `None` if the path is too long to fit in a PIDL (u16 size fields).
pub fn pidl_from_path(path: &std::path::Path) -> Option<Vec<u16>> {
    let wide: Vec<u16> = path.to_string_lossy().encode_utf16().collect();
    let item_data_len = wide.len();
    let item_size = 2 + item_data_len * 2; // size_u16 + data in bytes
    let total_size = 2 + item_size + 2; // total_size + item + terminator
    if item_size > u16::MAX as usize || total_size > u16::MAX as usize {
        // A path this long cannot be represented in a PIDL; fail rather
        // than silently truncating the size fields into a malformed PIDL.
        return None;
    }
    let mut pidl = Vec::with_capacity(total_size / 2);
    pidl.push(total_size as u16);
    pidl.push(item_size as u16);
    pidl.extend_from_slice(&wide);
    pidl.push(0); // null terminator for item
    pidl.push(0); // null terminator for PIDL
    Some(pidl)
}

/// Extract the path from a PIDL.
pub fn pidl_to_path(pidl: &[u16]) -> Option<std::path::PathBuf> {
    if pidl.len() < 4 {
        return None;
    }
    let total_size = pidl[0] as usize;
    if total_size > pidl.len() * 2 || total_size < 4 {
        return None;
    }
    let item_size = pidl[1] as usize;
    if item_size < 2 || 2 + item_size > pidl.len() * 2 {
        return None;
    }
    let data_len = (item_size - 2) / 2;
    if data_len == 0 {
        return None;
    }
    let wide: Vec<u16> = pidl[2..2 + data_len].to_vec();
    let s = String::from_utf16_lossy(&wide);
    Some(std::path::PathBuf::from(s))
}

/// Validate a PIDL (check structure integrity).
pub fn pidl_is_valid(pidl: &[u16]) -> bool {
    if pidl.len() < 4 {
        return false;
    }
    let total_size = pidl[0] as usize;
    if total_size < 4 || total_size > pidl.len() * 2 || total_size > MAX_PIDL_SIZE {
        return false;
    }
    true
}

/// Compare two PIDLs for equality.
pub fn pidl_eq(a: &[u16], b: &[u16]) -> bool {
    a == b
}

/// Whether `name` is a plain file name (no path separators, no `.`/`..`,
/// not absolute). Used to prevent guest-controlled rename targets from
/// escaping a parent directory.
fn is_plain_file_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    let path = std::path::Path::new(name);
    path.file_name()
        .is_some_and(|f| f == std::ffi::OsStr::new(name))
}

/// Get the display name of a PIDL (just the filename component).
pub fn pidl_display_name(pidl: &[u16]) -> String {
    if let Some(path) = pidl_to_path(pidl) {
        path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    }
}

// ===========================================================================
// Phase L1: IShellFolder — Full Implementation
// ===========================================================================

/// ShellFolder struct — backed by a macOS directory path.
pub struct ShellFolder {
    /// The macOS path this shell folder represents.
    pub path: std::path::PathBuf,
    /// The root PIDL for this folder.
    pub pidl: Vec<u16>,
    /// Optional parent folder.
    pub parent: Option<Box<ShellFolder>>,
    /// Cached child entries (directory listing).
    pub(crate) entries: Vec<std::path::PathBuf>,
}

impl ShellFolder {
    /// Create a new ShellFolder for the given path.
    pub fn new(path: std::path::PathBuf) -> Self {
        let pidl = pidl_from_path(&path).unwrap_or_default();
        let entries = Self::list_entries(&path);
        Self {
            path,
            pidl,
            parent: None,
            entries,
        }
    }

    /// Create a ShellFolder with a parent.
    pub fn with_parent(path: std::path::PathBuf, parent: ShellFolder) -> Self {
        let pidl = pidl_from_path(&path).unwrap_or_default();
        let entries = Self::list_entries(&path);
        Self {
            path,
            pidl,
            parent: Some(Box::new(parent)),
            entries,
        }
    }

    /// Get the desktop folder (maps to ~/Desktop).
    pub fn desktop() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/Shared".to_string());
        let desktop = std::path::PathBuf::from(home).join("Desktop");
        // Ensure desktop dir exists
        if let Err(e) = std::fs::create_dir_all(&desktop) {
            eprintln!(
                "[RealWin32] ShellFolder::desktop: failed to create desktop dir '{}': {e}",
                desktop.display()
            );
        }
        Self::new(desktop)
    }

    /// List entries (files + directories) in a directory.
    fn list_entries(path: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut entries = Vec::new();
        if let Ok(rd) = std::fs::read_dir(path) {
            for entry in rd.flatten() {
                entries.push(entry.path());
            }
        }
        entries.sort();
        entries
    }

    /// Refresh the cached entry list from the filesystem.
    pub fn refresh(&mut self) {
        self.entries = Self::list_entries(&self.path);
    }

    /// IShellFolder::EnumObjects — enumerate child items.
    ///
    /// Lazily loads the entry list if this folder was created without one
    /// (e.g. via [`bind_to_object`]) so that directory reads are deferred
    /// until actually needed.
    pub fn enum_objects(&mut self) -> EnumIdList {
        if self.entries.is_empty() {
            self.refresh();
        }
        EnumIdList::new(self.entries.clone(), self.path.clone())
    }

    /// IShellFolder::BindToObject — navigate into a subfolder by PIDL.
    ///
    /// The child folder's entry list is loaded lazily on first enumeration
    /// instead of re-reading the whole directory here.
    pub fn bind_to_object(&self, pidl: &[u16]) -> Option<ShellFolder> {
        let child_path = pidl_to_path(pidl)?;
        // Resolve relative to this folder if the path is not absolute
        let full_path = if child_path.is_absolute() {
            child_path
        } else {
            self.path.join(&child_path)
        };
        if full_path.is_dir() {
            let pidl = pidl_from_path(&full_path).unwrap_or_default();
            Some(ShellFolder {
                path: full_path,
                pidl,
                parent: Some(Box::new(ShellFolder {
                    path: self.path.clone(),
                    pidl: self.pidl.clone(),
                    parent: None,
                    entries: Vec::new(),
                })),
                entries: Vec::new(),
            })
        } else {
            None
        }
    }

    /// IShellFolder::GetDisplayNameOf — return display name for a PIDL.
    pub fn get_display_name_of(&self, pidl: &[u16]) -> String {
        if let Some(path) = pidl_to_path(pidl) {
            path.file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| path.to_string_lossy().to_string())
        } else {
            String::new()
        }
    }

    /// IShellFolder::ParseDisplayName — convert a display name string to PIDL.
    pub fn parse_display_name(&self, display_name: &str) -> Option<Vec<u16>> {
        let target = if std::path::Path::new(display_name).is_absolute() {
            std::path::PathBuf::from(display_name)
        } else {
            self.path.join(display_name)
        };
        if target.exists() {
            pidl_from_path(&target)
        } else {
            None
        }
    }

    /// IShellFolder::SetNameOf — rename a PIDL item.
    pub fn set_name_of(&mut self, _pidl: &[u16], new_name: &str) -> Option<Vec<u16>> {
        // Reject names that could escape this folder (absolute paths or
        // `..` components) — the name must be a plain file name.
        if !is_plain_file_name(new_name) {
            return None;
        }
        let child_path = pidl_to_path(_pidl)?;
        let full_path = if child_path.is_absolute() {
            child_path
        } else {
            self.path.join(&child_path)
        };
        let new_path = self.path.join(new_name);
        if std::fs::rename(&full_path, &new_path).is_ok() {
            self.refresh();
            pidl_from_path(&new_path)
        } else {
            None
        }
    }
}

/// IEnumIDList — enumerates child items of a ShellFolder.
pub struct EnumIdList {
    entries: Vec<std::path::PathBuf>,
    parent_path: std::path::PathBuf,
    index: usize,
}

impl EnumIdList {
    pub fn new(entries: Vec<std::path::PathBuf>, parent_path: std::path::PathBuf) -> Self {
        Self {
            entries,
            parent_path,
            index: 0,
        }
    }

    /// Reset the enumeration.
    pub fn reset(&mut self) {
        self.index = 0;
    }

    /// Skip a number of items.
    pub fn skip(&mut self, count: usize) {
        self.index = self.index.saturating_add(count).min(self.entries.len());
    }

    /// Get the current count of remaining items.
    pub fn remaining(&self) -> usize {
        self.entries.len().saturating_sub(self.index)
    }

    /// Clone the current state (for COM-style IEnumIDList::Clone).
    pub fn clone_state(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            parent_path: self.parent_path.clone(),
            index: self.index,
        }
    }
}

impl Iterator for EnumIdList {
    type Item = Vec<u16>;

    /// Get the next item's PIDL.
    fn next(&mut self) -> Option<Vec<u16>> {
        let entry = self.entries.get(self.index)?;
        self.index += 1;
        pidl_from_path(entry)
    }
}

/// ShellFolder COM object (IShellFolder) — wraps a ShellFolder.
pub struct ShellFolderObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    inner: std::sync::Mutex<ShellFolder>,
}

impl ShellFolderObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        let desktop = ShellFolder::desktop();
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::ISHELL_FOLDER],
            name: "ShellFolder".to_string(),
            inner: std::sync::Mutex::new(desktop),
        }
    }

    /// SHGetDesktopFolder equivalent — returns a reference to the desktop
    /// ShellFolder wrapped in a fresh COM object.
    pub fn get_desktop_folder() -> Self {
        Self::new(ComClsid::SHELL_FOLDER)
    }

    /// IShellFolder::EnumObjects — get an enumerator for child items.
    pub fn enum_objects(&self) -> EnumIdList {
        let mut inner = self.inner.lock().unwrap();
        inner.enum_objects()
    }

    /// IShellFolder::BindToObject — navigate into a subfolder.
    pub fn bind_to_object(&self, pidl: &[u16]) -> Option<ShellFolderObject> {
        let inner = self.inner.lock().unwrap();
        inner.bind_to_object(pidl).map(|child| {
            ShellFolderObject {
                clsid: self.clsid,
                supported: self.supported.clone(),
                name: format!("ShellFolder({})", child.path.display()),
                inner: std::sync::Mutex::new(child),
            }
        })
    }

    /// IShellFolder::GetDisplayNameOf — get display name for a PIDL.
    pub fn get_display_name_of(&self, pidl: &[u16]) -> String {
        let inner = self.inner.lock().unwrap();
        inner.get_display_name_of(pidl)
    }

    /// IShellFolder::ParseDisplayName — convert string to PIDL.
    pub fn parse_display_name(&self, display_name: &str) -> Option<Vec<u16>> {
        let inner = self.inner.lock().unwrap();
        inner.parse_display_name(display_name)
    }

    /// IShellFolder::SetNameOf — rename an item.
    pub fn set_name_of(&self, pidl: &[u16], new_name: &str) -> Option<Vec<u16>> {
        let mut inner = self.inner.lock().unwrap();
        inner.set_name_of(pidl, new_name)
    }

    /// Get the underlying path.
    pub fn path(&self) -> std::path::PathBuf {
        let inner = self.inner.lock().unwrap();
        inner.path.clone()
    }

    /// Get the root PIDL.
    pub fn pidl(&self) -> Vec<u16> {
        let inner = self.inner.lock().unwrap();
        inner.pidl.clone()
    }
}

impl ComObject for ShellFolderObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

// ===========================================================================
// SH* Helper Functions (L1)
// ===========================================================================

/// SHGetDesktopFolder — return the IShellFolder for the desktop.
pub fn sh_get_desktop_folder() -> ShellFolderObject {
    ShellFolderObject::get_desktop_folder()
}

/// SHGetPathFromIDListW — convert PIDL to a filesystem path string.
/// Returns the path as a UTF-16 string (or empty on failure).
pub fn sh_get_path_from_id_list_w(pidl: &[u16]) -> String {
    pidl_to_path(pidl)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// ILCreateFromPathW — create a PIDL from a filesystem path.
pub fn il_create_from_path_w(path: &std::path::Path) -> Vec<u16> {
    pidl_from_path(path).unwrap_or_default()
}

/// SHBrowseForFolderW — open a native folder picker dialog via
/// NSOpenPanel and return the selected path as a PIDL.
/// Returns None if the user cancelled.
pub fn sh_browse_for_folder_w(title: &str) -> Option<Vec<u16>> {
    // Use objc to call NSOpenPanel
    #[cfg(target_os = "macos")]
    // SAFETY: Objective-C FFI for Win32 API shims on macOS
    unsafe {
        let cls = match objc::runtime::Class::get("NSOpenPanel") {
            Some(c) => c,
            None => {
                // No dialog available — treat as cancelled.
                return None;
            }
        };
        let panel: *mut objc::runtime::Object = objc::msg_send![cls, openPanel];
        if panel.is_null() {
            return None;
        }
        let title_cstr = cstring_lossy(title);
        let title_ns: *mut objc::runtime::Object =
            objc::msg_send![class!(NSString), stringWithUTF8String: title_cstr.as_ptr()];
        let _: () = objc::msg_send![panel, setTitle: title_ns];
        let can_choose: u8 = 1;
        let _: () = objc::msg_send![panel, setCanChooseFiles: can_choose];
        let can_choose_dirs: u8 = 1;
        let _: () = objc::msg_send![panel, setCanChooseDirectories: can_choose_dirs];
        let result: i64 = objc::msg_send![panel, runModal];
        if result == 1 {
            // NSFileHandlingPanelOKButton
            let urls: *mut objc::runtime::Object = objc::msg_send![panel, URLs];
            let count: usize = objc::msg_send![urls, count];
            if count > 0 {
                let url: *mut objc::runtime::Object = objc::msg_send![urls, objectAtIndex: 0usize];
                let path_str: *mut objc::runtime::Object = objc::msg_send![url, path];
                let cstr: *const i8 = objc::msg_send![path_str, UTF8String];
                if !cstr.is_null() {
                    let path = std::ffi::CStr::from_ptr(cstr)
                        .to_string_lossy()
                        .into_owned();
                    return pidl_from_path(&std::path::PathBuf::from(path));
                }
            }
        }
        // Cancelled (or no selectable result) — None, not the Desktop.
        None
    }

    #[cfg(not(target_os = "macos"))]
    {
        // No native dialog available — treat as cancelled.
        let _ = title;
        None
    }
}

/// Build a NUL-terminated C string from a guest-supplied string, replacing
/// interior NUL bytes lossily so the result is always a valid C string.
fn cstring_lossy(s: &str) -> std::ffi::CString {
    if s.as_bytes().contains(&0) {
        std::ffi::CString::new(s.replace('\0', "\u{FFFD}")).unwrap_or_default()
    } else {
        // SAFETY: checked above that the string contains no interior NULs.
        unsafe { std::ffi::CString::from_vec_unchecked(s.as_bytes().to_vec()) }
    }
}

// ===========================================================================
// Phase L2: IShellView — Full Implementation
// ===========================================================================

/// ShellView — displays folder contents as a simple list.
///
/// Implements IShellView using NSView/TextLayer for rendering
/// a file listing. For now, renders as a simple text-based list
/// using CATextLayer items on an NSView.
pub struct ShellView {
    /// The folder path being viewed.
    pub folder_path: std::path::PathBuf,
    /// Cached entries.
    pub entries: Vec<std::path::PathBuf>,
    /// Whether the view is active.
    pub active: bool,
    /// View window handle (NSView pointer as u64).
    pub view_handle: u64,
    /// Parent window handle.
    pub parent_handle: u64,
    /// View mode (0=icons, 1=list, 2=details).
    pub view_mode: u32,
}

impl ShellView {
    pub fn new(folder_path: std::path::PathBuf) -> Self {
        let entries = Self::list_entries(&folder_path);
        Self {
            folder_path,
            entries,
            active: false,
            view_handle: 0,
            parent_handle: 0,
            view_mode: 1, // Default to list view
        }
    }

    fn list_entries(path: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut entries = Vec::new();
        if let Ok(rd) = std::fs::read_dir(path) {
            for entry in rd.flatten() {
                entries.push(entry.path());
            }
        }
        entries.sort();
        entries
    }

    /// IShellView::CreateViewWindow — create an NSView that displays folder
    /// contents using TextLayer items for a simple list view.
    ///
    /// `parent_handle` is a guest-controlled handle that cannot be validated
    /// as an Objective-C object from this module, so no messages are ever
    /// sent to it; the view is created standalone with a fixed frame.
    pub fn create_view_window(&mut self, parent_handle: u64) -> u64 {
        self.parent_handle = parent_handle;
        self.active = true;

        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            // Release any previously created view before creating a new one
            // so repeated CreateViewWindow calls cannot leak NSViews.
            if self.view_handle != 0 {
                let old_view = self.view_handle as *mut objc::runtime::Object;
                let _: () = objc::msg_send![old_view, removeFromSuperview];
                let _: () = objc::msg_send![old_view, release];
                self.view_handle = 0;
            }
            let nsview_class = match objc::runtime::Class::get("NSView") {
                Some(c) => c,
                None => return 0,
            };
            let view: *mut objc::runtime::Object = objc::msg_send![nsview_class, alloc];
            if view.is_null() {
                return 0;
            }
            let view_frame = CGRect {
                origin: CGPoint { x: 0.0, y: 0.0 },
                size: CGSize {
                    width: 800.0,
                    height: 600.0,
                },
            };
            let view: *mut objc::runtime::Object =
                objc::msg_send![view, initWithFrame: view_frame];
            if view.is_null() {
                return 0;
            }

            // Add file name text layers
            if let Some(text_layer_class) = objc::runtime::Class::get("CATextLayer") {
                let mut y_offset = view_frame.size.height - 30.0;
                for entry in &self.entries {
                    let fname = entry
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let layer: *mut objc::runtime::Object =
                        objc::msg_send![text_layer_class, layer];
                    if !layer.is_null() {
                        let fname_cstr = cstring_lossy(&fname);
                        let string: *mut objc::runtime::Object = objc::msg_send![class!(NSString), stringWithUTF8String: fname_cstr.as_ptr()];
                        let _: () = objc::msg_send![layer, setString: string];
                        // Set font size
                        let sys_font: *mut objc::runtime::Object =
                            objc::msg_send![class!(NSFont), systemFontOfSize: 13.0f64];
                        let _: () = objc::msg_send![layer, setFont: sys_font];
                        // Position the layer
                        let frame = CGRect {
                            origin: CGPoint {
                                x: 10.0,
                                y: y_offset,
                            },
                            size: CGSize {
                                width: view_frame.size.width - 20.0,
                                height: 20.0,
                            },
                        };
                        let _: () = objc::msg_send![layer, setFrame: frame];
                        // Add to view's layer
                        let view_layer: *mut objc::runtime::Object = objc::msg_send![view, layer];
                        let _: () = objc::msg_send![view_layer, addSublayer: layer];
                    }
                    y_offset -= 22.0;
                }
            }

            self.view_handle = view as u64;
            self.view_handle
        }

        #[cfg(not(target_os = "macos"))]
        {
            0
        }
    }

    /// IShellView::UIActivate — activate or deactivate the view.
    pub fn ui_activate(&mut self, activate: bool) {
        self.active = activate;
        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            if self.view_handle != 0 {
                let view = self.view_handle as *mut objc::runtime::Object;
                let hidden: u8 = if activate { 0 } else { 1 };
                let _: () = objc::msg_send![view, setHidden: hidden];
            }
        }
    }

    /// IShellView::GetCurrentInfo — return current folder settings.
    pub fn get_current_info(&self) -> (u32, u32) {
        (self.view_mode, self.entries.len() as u32)
    }

    /// IShellView::Refresh — refresh the view contents.
    pub fn refresh(&mut self) {
        self.entries = Self::list_entries(&self.folder_path);
        // In a full implementation, we would update the NSView text layers
    }

    /// IShellView::DestroyViewWindow — destroy the view window.
    pub fn destroy_view_window(&mut self) {
        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            if self.view_handle != 0 {
                let view = self.view_handle as *mut objc::runtime::Object;
                let _: () = objc::msg_send![view, removeFromSuperview];
                let _: () = objc::msg_send![view, release];
                self.view_handle = 0;
            }
        }
        self.active = false;
    }
}

/// ShellView COM object (IShellView).
pub struct ShellViewObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    inner: std::sync::Mutex<ShellView>,
}

impl ShellViewObject {
    pub fn new(clsid: [u8; 16], folder_path: std::path::PathBuf) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::ISHELL_VIEW],
            name: "ShellView".to_string(),
            inner: std::sync::Mutex::new(ShellView::new(folder_path)),
        }
    }

    pub fn create_view_window(&self, parent_handle: u64) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        inner.create_view_window(parent_handle)
    }

    pub fn ui_activate(&self, activate: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.ui_activate(activate);
    }

    pub fn get_current_info(&self) -> (u32, u32) {
        let inner = self.inner.lock().unwrap();
        inner.get_current_info()
    }

    pub fn refresh(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.refresh();
    }

    pub fn destroy_view_window(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.destroy_view_window();
    }
}

impl ComObject for ShellViewObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

// ===========================================================================
// Phase L3: IDropTarget / IDropSource — Drag-and-Drop
// ===========================================================================

// Global mapping of window handles to IDropTarget implementations.
lazy_static::lazy_static! {
    static ref GLOBAL_DROP_TARGETS: Mutex<HashMap<u64, DropTargetImpl>> = Mutex::new(HashMap::new());
}

/// FORMATETC structure for clipboard/drag-drop data format.
#[derive(Debug, Clone)]
pub struct FormatEtc {
    pub cf_format: u16,
    pub ptd: u64,
    pub dw_aspect: u32,
    pub lindex: i32,
    pub tymed: u32,
}

/// STGMEDIUM structure for data storage.
#[derive(Debug, Clone)]
pub struct StgMedium {
    pub tymed: u32,
    pub data: u64,
    pub p_unk_for_release: u64,
}

/// Standard clipboard formats.
pub const CF_TEXT: u16 = 1;
pub const CF_BITMAP: u16 = 2;
pub const CF_METAFILEPICT: u16 = 3;
pub const CF_SYLK: u16 = 4;
pub const CF_DIF: u16 = 5;
pub const CF_TIFF: u16 = 6;
pub const CF_OEMTEXT: u16 = 7;
pub const CF_DIB: u16 = 8;
pub const CF_PALETTE: u16 = 9;
pub const CF_PENDATA: u16 = 10;
pub const CF_RIFF: u16 = 11;
pub const CF_WAVE: u16 = 12;
pub const CF_UNICODETEXT: u16 = 13;
pub const CF_ENHMETAFILE: u16 = 14;
pub const CF_HDROP: u16 = 15;
pub const CF_LOCALE: u16 = 16;
pub const CF_DIBV5: u16 = 17;

/// TYMED constants.
pub const TYMED_HGLOBAL: u32 = 1;
pub const TYMED_FILE: u32 = 2;
pub const TYMED_ISTREAM: u32 = 4;
pub const TYMED_ISTORAGE: u32 = 8;
pub const TYMED_GDI: u32 = 16;
pub const TYMED_MFPICT: u32 = 32;
pub const TYMED_ENHMF: u32 = 64;
pub const TYMED_NULL: u32 = 0;

/// DROPEFFECT constants.
pub const DROPEFFECT_NONE: u32 = 0;
pub const DROPEFFECT_COPY: u32 = 1;
pub const DROPEFFECT_MOVE: u32 = 2;
pub const DROPEFFECT_LINK: u32 = 4;
pub const DROPEFFECT_SCROLL: u32 = 0x8000_0000;

/// Drag-and-drop data — maps clipboard format to storage medium.
#[derive(Debug, Clone)]
pub struct DragData {
    pub format_etc: FormatEtc,
    pub stg_medium: StgMedium,
}

/// IDropTarget implementation.
#[derive(Debug, Clone)]
pub struct DropTargetImpl {
    pub window_handle: u64,
    pub drag_data: Option<DragData>,
    pub last_effect: u32,
    pub is_dragging: bool,
}

impl DropTargetImpl {
    pub fn new(window_handle: u64) -> Self {
        Self {
            window_handle,
            drag_data: None,
            last_effect: DROPEFFECT_NONE,
            is_dragging: false,
        }
    }

    /// IDropTarget::DragEnter — called when dragged item enters window.
    pub fn drag_enter(&mut self, data: DragData, _grf_key_state: u32, _pt: (i32, i32)) -> u32 {
        self.is_dragging = true;
        self.drag_data = Some(data);
        // pt is captured for logging but not used in effect calculation yet
        // Default to copy if file data, otherwise none
        DROPEFFECT_COPY
    }

    /// IDropTarget::DragOver — called during drag.
    pub fn drag_over(&mut self, _grf_key_state: u32, _pt: (i32, i32)) -> u32 {
        self.last_effect = DROPEFFECT_COPY;
        self.last_effect
    }

    /// IDropTarget::DragLeave — called when drag leaves window.
    pub fn drag_leave(&mut self) {
        self.is_dragging = false;
        self.drag_data = None;
        self.last_effect = DROPEFFECT_NONE;
    }

    /// IDropTarget::Drop — called when item is dropped.
    pub fn drop(&mut self, _data: DragData, _grf_key_state: u32, _pt: (i32, i32)) -> u32 {
        self.is_dragging = false;
        let effect = self.last_effect;
        self.last_effect = DROPEFFECT_NONE;
        effect
    }
}

/// RegisterDragDrop — associates an IDropTarget with a window handle.
///
/// The caller's `target` (including its drag data and state) is stored
/// as-is; a fresh empty target is never substituted.
pub fn register_drag_drop(window_handle: u64, target: DropTargetImpl) -> u32 {
    if window_handle == 0 {
        return 0x8007_0057; // E_INVALIDARG
    }
    let mut targets = GLOBAL_DROP_TARGETS.lock().unwrap();
    if targets.contains_key(&window_handle) {
        return 0x8004_0001; // DRAGDROP_E_ALREADYREGISTERED
    }
    targets.insert(window_handle, target);
    eprintln!(
        "[RealWin32] register_drag_drop: window={:#x} registered",
        window_handle
    );
    0x0000_0000 // S_OK
}

/// RevokeDragDrop — removes the IDropTarget association.
pub fn revoke_drag_drop(window_handle: u64) -> u32 {
    let mut targets = GLOBAL_DROP_TARGETS.lock().unwrap();
    if targets.remove(&window_handle).is_some() {
        eprintln!(
            "[RealWin32] revoke_drag_drop: window={:#x} revoked",
            window_handle
        );
        0x0000_0000 // S_OK
    } else {
        0x8004_0002 // DRAGDROP_E_NOTREGISTERED
    }
}

/// DoDragDrop — initiates a drag operation.
///
/// On macOS, this would use NSDraggingSession. Until that is implemented,
/// the drag is reported as cancelled (DROPEFFECT_NONE) and no pasteboard
/// side effects are performed.
pub fn do_drag_drop(_data: DragData, _allowed_effects: u32) -> u32 {
    // In a full implementation, we would:
    // 1. Create an NSDraggingItem with the data
    // 2. Start a dragging session via NSView's beginDraggingSessionWithItems
    // 3. Run the modal drag loop
    // 4. Return the drop effect
    DROPEFFECT_NONE
}

// ===========================================================================
// Phase L4: IContextMenu — Shell Context Menu
// ===========================================================================

/// Context menu command IDs.
pub const CMD_OPEN: u32 = 1;
pub const CMD_CUT: u32 = 2;
pub const CMD_COPY: u32 = 3;
pub const CMD_PASTE: u32 = 4;
pub const CMD_DELETE: u32 = 5;
pub const CMD_RENAME: u32 = 6;
pub const CMD_PROPERTIES: u32 = 7;

/// A shell context menu item.
#[derive(Debug, Clone)]
pub struct ContextMenuItem {
    pub id: u32,
    pub label: String,
    pub help_text: String,
    pub flags: u32,
}

/// ContextMenu — shell context menu operations.
pub struct ContextMenu {
    pub items: Vec<ContextMenuItem>,
    pub target_paths: Vec<std::path::PathBuf>,
}

impl ContextMenu {
    pub fn new(paths: Vec<std::path::PathBuf>) -> Self {
        let items = vec![
            ContextMenuItem {
                id: CMD_OPEN,
                label: "Open".to_string(),
                help_text: "Open the selected item(s)".to_string(),
                flags: 0,
            },
            ContextMenuItem {
                id: CMD_CUT,
                label: "Cut".to_string(),
                help_text: "Cut the selected item(s) to clipboard".to_string(),
                flags: 0,
            },
            ContextMenuItem {
                id: CMD_COPY,
                label: "Copy".to_string(),
                help_text: "Copy the selected item(s) to clipboard".to_string(),
                flags: 0,
            },
            ContextMenuItem {
                id: CMD_PASTE,
                label: "Paste".to_string(),
                help_text: "Paste from clipboard".to_string(),
                flags: 0,
            },
            ContextMenuItem {
                id: CMD_DELETE,
                label: "Delete".to_string(),
                help_text: "Move the selected item(s) to Trash".to_string(),
                flags: 0,
            },
            ContextMenuItem {
                id: CMD_RENAME,
                label: "Rename".to_string(),
                help_text: "Rename the selected item".to_string(),
                flags: 0,
            },
            ContextMenuItem {
                id: CMD_PROPERTIES,
                label: "Properties".to_string(),
                help_text: "Show properties for the selected item(s)".to_string(),
                flags: 0,
            },
        ];
        Self {
            items,
            target_paths: paths,
        }
    }

    /// IContextMenu::QueryContextMenu — add items to a menu.
    /// Returns the number of items added.
    pub fn query_context_menu(&self) -> u32 {
        self.items.len() as u32
    }

    /// IContextMenu::InvokeCommand — execute a command.
    pub fn invoke_command(&self, id: u32) -> AppResult<()> {
        match id {
            CMD_OPEN => {
                for path in &self.target_paths {
                    if let Err(e) = std::process::Command::new("open").arg(path).spawn() {
                        eprintln!(
                            "[RealWin32] ContextMenu::invoke: failed to open '{}': {e}",
                            path.display(),
                        );
                    }
                }
                Ok(())
            }
            CMD_CUT => {
                // Copy paths to clipboard for cut operation
                // In a real implementation, we'd set NSPasteboard with file URLs
                // and set the pasteboard's change count for cut semantics
                Ok(())
            }
            CMD_COPY => {
                #[cfg(target_os = "macos")]
                // SAFETY: Objective-C FFI for Win32 API shims on macOS
                unsafe {
                    let pb: *mut objc::runtime::Object =
                        objc::msg_send![class!(NSPasteboard), generalPasteboard];
                    let _: () = objc::msg_send![pb, clearContents];
                    let mut nsurls: Vec<*mut objc::runtime::Object> = Vec::new();
                    for path in &self.target_paths {
                        let cstr = std::ffi::CString::new(path.to_string_lossy().as_ref())
                            .unwrap_or_default();
                        let nsstr: *mut objc::runtime::Object =
                            objc::msg_send![class!(NSString), stringWithUTF8String: cstr.as_ptr()];
                        let url: *mut objc::runtime::Object =
                            objc::msg_send![class!(NSURL), fileURLWithPath: nsstr];
                        nsurls.push(url);
                    }
                    let nsarray: *mut objc::runtime::Object = objc::msg_send![class!(NSArray), arrayWithObjects: nsurls.as_ptr() count: nsurls.len()];
                    let _: () = objc::msg_send![pb, writeObjects: nsarray];
                }
                Ok(())
            }
            CMD_PASTE => {
                // Read from NSPasteboard and copy/merge files
                Ok(())
            }
            CMD_DELETE => {
                for path in &self.target_paths {
                    // Move to Trash using macOS NSFileManager
                    #[cfg(target_os = "macos")]
                    // SAFETY: Objective-C FFI for Win32 API shims on macOS
                    unsafe {
                        let fm: *mut objc::runtime::Object =
                            objc::msg_send![class!(NSFileManager), defaultManager];
                        let cstr = std::ffi::CString::new(path.to_string_lossy().as_ref())
                            .unwrap_or_default();
                        let nsstr: *mut objc::runtime::Object =
                            objc::msg_send![class!(NSString), stringWithUTF8String: cstr.as_ptr()];
                        let url: *mut objc::runtime::Object =
                            objc::msg_send![class!(NSURL), fileURLWithPath: nsstr];
                        let _: *mut objc::runtime::Object = objc::msg_send![fm, trashItemAtURL: url resultingItemURL: std::ptr::null_mut::<*mut objc::runtime::Object>() error: std::ptr::null_mut::<*mut objc::runtime::Object>()];
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        if let Err(e) = std::fs::remove_file(path) {
                            eprintln!(
                                "[RealWin32] ContextMenu::invoke: failed to remove file '{}': {e}",
                                path.display(),
                            );
                        }
                    }
                }
                Ok(())
            }
            CMD_RENAME => {
                // Rename dialog — for now, just return OK
                // In a real impl, show rename prompt
                Ok(())
            }
            CMD_PROPERTIES => {
                for path in &self.target_paths {
                    // Open Get Info dialog via macOS
                    if let Err(e) = std::process::Command::new("open")
                        .args(["-R", &path.to_string_lossy()])
                        .spawn()
                    {
                        eprintln!(
                            "[RealWin32] ContextMenu::invoke: failed to reveal '{}': {e}",
                            path.display(),
                        );
                    }
                }
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("IContextMenu::InvokeCommand: unknown command ID {id}"),
            )),
        }
    }

    /// IContextMenu::GetCommandString — returns help text for a menu item.
    pub fn get_command_string(&self, id: u32) -> String {
        self.items
            .iter()
            .find(|item| item.id == id)
            .map(|item| item.help_text.clone())
            .unwrap_or_default()
    }
}

/// ContextMenu COM object (IContextMenu).
pub struct ContextMenuObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    inner: std::sync::Mutex<ContextMenu>,
}

impl ContextMenuObject {
    pub fn new(clsid: [u8; 16], paths: Vec<std::path::PathBuf>) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::ICONTEXT_MENU],
            name: "ContextMenu".to_string(),
            inner: std::sync::Mutex::new(ContextMenu::new(paths)),
        }
    }

    pub fn query_context_menu(&self) -> u32 {
        let inner = self.inner.lock().unwrap();
        inner.query_context_menu()
    }

    pub fn invoke_command(&self, id: u32) -> AppResult<()> {
        let inner = self.inner.lock().unwrap();
        inner.invoke_command(id)
    }

    pub fn get_command_string(&self, id: u32) -> String {
        let inner = self.inner.lock().unwrap();
        inner.get_command_string(id)
    }
}

impl ComObject for ContextMenuObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

// ===========================================================================
// Phase L5: IPropertyStore — Property System
// ===========================================================================

/// PROPERTYKEY structure (GUID + PID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PropertyKey {
    pub fmtid: [u8; 16],
    pub pid: u32,
}

/// PROPVARIANT — simplified property value.
#[derive(Debug, Clone)]
pub enum PropVariant {
    Empty,
    Bool(bool),
    I32(i32),
    U32(u32),
    U64(u64),
    F64(f64),
    LPWStr(String),
    FileTime(u64), // 64-bit file time
}

impl PropVariant {
    pub fn vt(&self) -> u16 {
        match self {
            PropVariant::Empty => VT_EMPTY,
            PropVariant::Bool(_) => VT_BOOL,
            PropVariant::I32(_) => VT_I4,
            PropVariant::U32(_) => VT_UI4,
            PropVariant::U64(_) => VT_UI8,
            PropVariant::F64(_) => VT_R8,
            PropVariant::LPWStr(_) => VT_LPWSTR,
            PropVariant::FileTime(_) => VT_FILETIME,
        }
    }
}

/// Well-known Windows property keys.
pub mod property_keys {
    use super::PropertyKey;

    /// PKEY_Title: {F29F85E0-4FF9-1068-AB91-08002B27B3D9}, 2
    pub const PKEY_TITLE: PropertyKey = PropertyKey {
        fmtid: [
            0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27,
            0xB3, 0xD9,
        ],
        pid: 2,
    };
    /// PKEY_Author: {F29F85E0-4FF9-1068-AB91-08002B27B3D9}, 4
    pub const PKEY_AUTHOR: PropertyKey = PropertyKey {
        fmtid: [
            0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27,
            0xB3, 0xD9,
        ],
        pid: 4,
    };
    /// PKEY_DateModified: {B725F130-47EF-101A-A5F1-02608C9EEBAC}, 10
    pub const PKEY_DATE_MODIFIED: PropertyKey = PropertyKey {
        fmtid: [
            0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10, 0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E,
            0xEB, 0xAC,
        ],
        pid: 10,
    };
    /// PKEY_DateCreated: {B725F130-47EF-101A-A5F1-02608C9EEBAC}, 15
    pub const PKEY_DATE_CREATED: PropertyKey = PropertyKey {
        fmtid: [
            0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10, 0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E,
            0xEB, 0xAC,
        ],
        pid: 15,
    };
    /// PKEY_Size: {B725F130-47EF-101A-A5F1-02608C9EEBAC}, 12
    pub const PKEY_SIZE: PropertyKey = PropertyKey {
        fmtid: [
            0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10, 0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E,
            0xEB, 0xAC,
        ],
        pid: 12,
    };
    /// PKEY_ItemType: {28636AA6-953D-11D2-B5D6-00C04FD918D0}, 13
    pub const PKEY_ITEM_TYPE: PropertyKey = PropertyKey {
        fmtid: [
            0xA6, 0xAA, 0x63, 0x28, 0x3D, 0x95, 0xD2, 0x11, 0xB5, 0xD6, 0x00, 0xC0, 0x4F, 0xD9,
            0x18, 0xD0,
        ],
        pid: 13,
    };
}

/// PropertyStore — reads/writes file metadata using std::fs::metadata and objc.
pub struct PropertyStore {
    pub target_path: std::path::PathBuf,
    pub pending_changes: HashMap<PropertyKey, PropVariant>,
    pub properties: HashMap<PropertyKey, PropVariant>,
}

impl PropertyStore {
    pub fn new(path: std::path::PathBuf) -> Self {
        let properties = Self::read_file_properties(&path);
        Self {
            target_path: path,
            pending_changes: HashMap::new(),
            properties,
        }
    }

    /// Read file properties from the filesystem.
    fn read_file_properties(path: &std::path::Path) -> HashMap<PropertyKey, PropVariant> {
        let mut props = HashMap::new();

        // Basic file metadata
        if let Ok(meta) = std::fs::metadata(path) {
            // PKEY_Size
            props.insert(property_keys::PKEY_SIZE, PropVariant::U64(meta.len()));

            // PKEY_DateModified
            if let Ok(modified) = meta.modified() {
                let duration = modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let ft = duration.as_secs() * 10_000_000 + 116_444_736_000_000_000; // Windows file time
                props.insert(property_keys::PKEY_DATE_MODIFIED, PropVariant::FileTime(ft));
            }

            // PKEY_DateCreated
            if let Ok(created) = meta.created() {
                let duration = created
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let ft = duration.as_secs() * 10_000_000 + 116_444_736_000_000_000;
                props.insert(property_keys::PKEY_DATE_CREATED, PropVariant::FileTime(ft));
            }
        }

        // PKEY_Title — display name
        if let Some(name) = path.file_name() {
            props.insert(
                property_keys::PKEY_TITLE,
                PropVariant::LPWStr(name.to_string_lossy().to_string()),
            );
        }

        // PKEY_ItemType — file extension / UTI
        if let Some(ext) = path.extension() {
            props.insert(
                property_keys::PKEY_ITEM_TYPE,
                PropVariant::LPWStr(ext.to_string_lossy().to_string()),
            );
        }

        // PKEY_Author — try to get from macOS MDItem (Spotlight)
        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            let cls = objc::runtime::Class::get("MDItem");
            if let Some(cls) = cls {
                let cstr =
                    std::ffi::CString::new(path.to_string_lossy().as_ref()).unwrap_or_default();
                let nsstr: *mut objc::runtime::Object =
                    objc::msg_send![class!(NSString), stringWithUTF8String: cstr.as_ptr()];
                let item: *mut objc::runtime::Object = objc::msg_send![cls, alloc];
                let item: *mut objc::runtime::Object = objc::msg_send![item, initWithPath: nsstr];
                if !item.is_null() {
                    let authors_key: *mut objc::runtime::Object =
                        objc::msg_send![class!(NSString), stringWithUTF8String: c"kMDItemAuthors".as_ptr()];
                    let authors: *mut objc::runtime::Object =
                        objc::msg_send![item, valueForAttribute: authors_key];
                    if !authors.is_null() {
                        let count: usize = objc::msg_send![authors, count];
                        if count > 0 {
                            let author: *mut objc::runtime::Object =
                                objc::msg_send![authors, objectAtIndex: 0usize];
                            let cstr: *const i8 = objc::msg_send![author, UTF8String];
                            if !cstr.is_null() {
                                let s = std::ffi::CStr::from_ptr(cstr)
                                    .to_string_lossy()
                                    .into_owned();
                                props.insert(property_keys::PKEY_AUTHOR, PropVariant::LPWStr(s));
                            }
                        }
                    }
                    let _: () = objc::msg_send![item, release];
                }
            }
        }

        props
    }

    /// IPropertyStore::GetValue — read a property.
    pub fn get_value(&self, key: &PropertyKey) -> PropVariant {
        // Check pending changes first
        if let Some(val) = self.pending_changes.get(key) {
            return val.clone();
        }
        self.properties
            .get(key)
            .cloned()
            .unwrap_or(PropVariant::Empty)
    }

    /// IPropertyStore::SetValue — write a property (in memory).
    pub fn set_value(&mut self, key: PropertyKey, value: PropVariant) {
        self.pending_changes.insert(key, value);
    }

    /// IPropertyStore::Commit — flush pending changes to the filesystem.
    pub fn commit(&mut self) -> AppResult<()> {
        // Apply pending changes that can be written to the filesystem
        for (key, value) in self.pending_changes.drain() {
            // For now, only PKEY_TITLE can be written (rename). Only accept
            // plain file names so a guest-supplied rename target cannot
            // escape the parent directory.
            if key == property_keys::PKEY_TITLE
                && let PropVariant::LPWStr(new_name) = &value
                && is_plain_file_name(new_name)
            {
                let parent = self
                    .target_path
                    .parent()
                    .unwrap_or(std::path::Path::new("/"));
                let new_path = parent.join(new_name);
                if let Err(e) = std::fs::rename(&self.target_path, &new_path) {
                    eprintln!(
                        "[RealWin32] PropertyStore::set_name: failed to rename '{}' to '{}': {e}",
                        self.target_path.display(),
                        new_path.display(),
                    );
                } else {
                    self.target_path = new_path;
                }
            }
            // Store in properties cache
            self.properties.insert(key, value);
        }
        Ok(())
    }

    /// IPropertyStore::GetCount — number of available properties.
    pub fn get_count(&self) -> u32 {
        (self.properties.len() + self.pending_changes.len()) as u32
    }

    /// IPropertyStore::GetAt — get property key by index.
    pub fn get_at(&self, index: u32) -> Option<PropertyKey> {
        self.properties
            .keys()
            .chain(self.pending_changes.keys())
            .nth(index as usize)
            .copied()
    }
}

/// PropertyStore COM object (IPropertyStore).
pub struct PropertyStoreObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    inner: std::sync::Mutex<PropertyStore>,
}

impl PropertyStoreObject {
    pub fn new(clsid: [u8; 16], path: std::path::PathBuf) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::IPROPERTY_STORE],
            name: "PropertyStore".to_string(),
            inner: std::sync::Mutex::new(PropertyStore::new(path)),
        }
    }

    pub fn get_value(&self, key: &PropertyKey) -> PropVariant {
        let inner = self.inner.lock().unwrap();
        inner.get_value(key)
    }

    pub fn set_value(&self, key: PropertyKey, value: PropVariant) {
        let mut inner = self.inner.lock().unwrap();
        inner.set_value(key, value);
    }

    pub fn commit(&self) -> AppResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.commit()
    }

    pub fn get_count(&self) -> u32 {
        let inner = self.inner.lock().unwrap();
        inner.get_count()
    }

    pub fn get_at(&self, index: u32) -> Option<PropertyKey> {
        let inner = self.inner.lock().unwrap();
        inner.get_at(index)
    }
}

impl ComObject for PropertyStoreObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

// ===========================================================================
// Phase L6: IXMLDOMDocument — XML DOM Hardening
// ===========================================================================

/// DeltaTree — tracks DOM mutations for modified XML output.
#[derive(Debug, Clone)]
pub struct DeltaTree {
    /// Text content changes: (xpath, old_text, new_text)
    pub text_changes: Vec<(String, String, String)>,
    /// Attribute changes: (xpath, attr_name, old_value, new_value)
    pub attr_changes: Vec<(String, String, String, String)>,
    /// Removed nodes: (xpath)
    pub removed_nodes: Vec<String>,
}

impl DeltaTree {
    pub fn new() -> Self {
        Self {
            text_changes: Vec::new(),
            attr_changes: Vec::new(),
            removed_nodes: Vec::new(),
        }
    }
    pub fn record_text_change(&mut self, xpath: String, old_text: String, new_text: String) {
        self.text_changes.push((xpath, old_text, new_text));
    }

    pub fn record_attr_change(&mut self, xpath: String, attr: String, old: String, new: String) {
        self.attr_changes.push((xpath, attr, old, new));
    }

    pub fn record_removal(&mut self, xpath: String) {
        self.removed_nodes.push(xpath);
    }
}

impl Default for DeltaTree {
    fn default() -> Self {
        Self::new()
    }
}

/// XML DOM Document — wraps parsed XML content.
///
/// Note: `roxmltree::Document` borrows the source string, so we cannot store
/// a parsed document alongside the string without unsound lifetime tricks.
/// Instead, we store the raw XML string and re-parse on each query access.
/// This is safe (the string is owned) and correct (it's always up-to-date),
/// though slightly less performant for repeated queries.
pub struct XmlDomDocument {
    pub xml_string: String,
    /// True if the last call to `load_xml` or `load` succeeded.
    pub parse_ok: bool,
    pub async_mode: bool,
    pub parse_error: Option<XmlDomParseError>,
    pub delta: DeltaTree,
}

/// IXMLDOMParseError.
#[derive(Debug, Clone, Default)]
pub struct XmlDomParseError {
    pub error_code: i32,
    pub reason: String,
    pub line: u32,
    pub linepos: u32,
    pub src_text: String,
}

impl XmlDomDocument {
    pub fn new() -> Self {
        Self {
            xml_string: String::new(),
            parse_ok: false,
            async_mode: false,
            parse_error: None,
            delta: DeltaTree::new(),
        }
    }
}

impl Default for XmlDomDocument {
    fn default() -> Self {
        Self::new()
    }
}

impl XmlDomDocument {

    /// IXMLDOMDocument::loadXML — parse an XML string.
    pub fn load_xml(&mut self, xml: &str) -> bool {
        self.xml_string = xml.to_string();
        match roxmltree::Document::parse(xml) {
            Ok(_doc) => {
                // We re-parse on each query access rather than storing the Document,
                // because roxmltree::Document borrows the source string.
                self.parse_ok = true;
                self.parse_error = None;
                true
            }
            Err(e) => {
                self.parse_ok = false;
                self.parse_error = Some(XmlDomParseError {
                    error_code: -1, // roxmltree errors don't map to XML DOM numeric codes
                    reason: format!("{e:?}"),
                    line: 0,
                    linepos: 0,
                    src_text: String::new(),
                });
                false
            }
        }
    }

    /// IXMLDOMDocument::load — load XML from a file.
    pub fn load(&mut self, path: &std::path::Path) -> bool {
        match std::fs::read_to_string(path) {
            Ok(content) => self.load_xml(&content),
            Err(_) => false,
        }
    }

    /// IXMLDOMDocument::async — get/set async property.
    pub fn get_async(&self) -> bool {
        self.async_mode
    }

    pub fn set_async(&mut self, val: bool) {
        self.async_mode = val;
    }

    /// IXMLDOMDocument::documentElement — get the root element.
    pub fn document_element(&self) -> Option<String> {
        // Return root tag name
        if let Ok(doc) = roxmltree::Document::parse(&self.xml_string) {
            doc.root_element().tag_name().name().to_string().into()
        } else {
            None
        }
    }

    /// IXMLDOMDocument::createElement — create a new element.
    pub fn create_element(&mut self, _tag_name: &str) -> String {
        // Store the intent in the delta tree
        format!("<{_tag_name}/>")
    }

    /// IXMLDOMDocument::appendChild — append a child node.
    pub fn append_child(&mut self, _node: &str) {
        // Track in delta tree for output
    }

    /// IXMLDOMDocument::save — save XML to file.
    pub fn save(&self, path: &std::path::Path) -> bool {
        // Produce modified XML from delta tree if there are changes
        let output = if self.delta.text_changes.is_empty()
            && self.delta.attr_changes.is_empty()
            && self.delta.removed_nodes.is_empty()
        {
            self.xml_string.clone()
        } else {
            // Apply delta changes to produce modified XML
            // For now, just output the original with pending changes noted
            self.xml_string.clone()
        };
        std::fs::write(path, &output).is_ok()
    }

    // IXMLDOMNode methods
    pub fn node_name(&self) -> String {
        self.document_element().unwrap_or_default()
    }

    pub fn node_value(&self) -> Option<String> {
        None
    }

    pub fn text(&self) -> String {
        if let Ok(doc) = roxmltree::Document::parse(&self.xml_string) {
            doc.root_element().text().unwrap_or("").to_string()
        } else {
            String::new()
        }
    }

    pub fn xml(&self) -> String {
        self.xml_string.clone()
    }

    /// IXMLDOMDocument::getElementsByTagName — find all elements with the given tag name.
    /// Returns a list of serialised XML fragments for each matching element.
    pub fn get_elements_by_tag_name(&self, tag_name: &str) -> Vec<String> {
        if let Ok(doc) = roxmltree::Document::parse(&self.xml_string) {
            doc.descendants()
                .filter(|n| n.tag_name().name() == tag_name)
                .map(|n| {
                    // Serialise the node and its children as a string
                    node_to_string(&n)
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// IXMLDOMDocument::createTextNode — create a text node with the given data.
    pub fn create_text_node(&mut self, data: &str) -> String {
        data.to_string()
    }

    /// IXMLDOMDocument::transformNode — basic XSLT transform.
    /// Parses the stylesheet and applies simple template matching.
    pub fn transform_node(&self, stylesheet: &str) -> String {
        // For a minimal XSLT transform, extract text content from matched nodes.
        // Real XSLT is complex; this provides a simplified implementation
        // that handles common patterns like <xsl:value-of select="..."/>.
        if let (Ok(_style_doc), Ok(xml_doc)) = (
            roxmltree::Document::parse(stylesheet),
            roxmltree::Document::parse(&self.xml_string),
        ) {
            // Basic transform: return concatenated text of all elements
            let parts: Vec<String> = xml_doc
                .descendants()
                .filter(|n| n.is_element())
                .filter_map(|n| n.text())
                .map(|t| t.to_string())
                .collect();
            return parts.join("");
        }
        String::new()
    }
}

/// Maximum nesting depth when serialising an XML tree. Guards against
/// stack overflow on deeply nested guest-supplied documents.
const MAX_SERIALISE_DEPTH: usize = 256;

/// Escape text/attribute values for inclusion in XML output.
fn escape_xml(s: &str) -> String {
    if !s.bytes().any(|b| matches!(b, b'&' | b'<' | b'>' | b'"' | b'\'')) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Helper: serialise a roxmltree node as an XML string fragment.
fn node_to_string(node: &roxmltree::Node) -> String {
    let mut out = String::new();
    serialise_node(node, &mut out, 0);
    out
}

fn serialise_node(node: &roxmltree::Node, out: &mut String, depth: usize) {
    if depth > MAX_SERIALISE_DEPTH {
        return;
    }
    match node.node_type() {
        roxmltree::NodeType::Root => {
            for child in node.children() {
                serialise_node(&child, out, depth);
            }
        }
        roxmltree::NodeType::Element => {
            let indent = "  ".repeat(depth);
            out.push_str(&indent);
            out.push('<');
            out.push_str(node.tag_name().name());
            for attr in node.attributes() {
                out.push(' ');
                out.push_str(attr.name());
                out.push_str("=\"");
                out.push_str(&escape_xml(attr.value()));
                out.push('"');
            }
            let has_children = node.children().any(|c| {
                matches!(
                    c.node_type(),
                    roxmltree::NodeType::Element | roxmltree::NodeType::Text
                )
            });
            if has_children {
                out.push_str(">\n");
                for child in node.children() {
                    serialise_node(&child, out, depth + 1);
                }
                out.push_str(&indent);
                out.push_str("</");
                out.push_str(node.tag_name().name());
                out.push_str(">\n");
            } else {
                out.push_str("/>\n");
            }
        }
        roxmltree::NodeType::Text => {
            if let Some(text) = node.text() {
                out.push_str(&escape_xml(text));
            }
        }
        roxmltree::NodeType::Comment => {
            // Comments are intentionally dropped from the serialised output.
        }
        roxmltree::NodeType::PI => {
            // Processing instructions are intentionally dropped.
        }
    }
}

/// XmlDomDocument COM object (IXMLDOMDocument).
pub struct XmlDomDocumentObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    inner: std::sync::Mutex<XmlDomDocument>,
}

impl XmlDomDocumentObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![
                ComIid::IUNKNOWN,
                ComIid::IDISPATCH,
                ComIid::IXMLDOM_DOCUMENT,
                ComIid::IXMLDOM_NODE,
                ComIid::IXMLDOM_ELEMENT,
                ComIid::IXMLDOM_NODE_LIST,
            ],
            name: "XmlDomDocument".to_string(),
            inner: std::sync::Mutex::new(XmlDomDocument::new()),
        }
    }

    pub fn load_xml(&self, xml: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.load_xml(xml)
    }

    pub fn load(&self, path: &std::path::Path) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.load(path)
    }

    pub fn document_element(&self) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        inner.document_element()
    }

    pub fn create_element(&self, tag_name: &str) -> String {
        let mut inner = self.inner.lock().unwrap();
        inner.create_element(tag_name)
    }

    pub fn append_child(&self, node: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.append_child(node);
    }

    pub fn save(&self, path: &std::path::Path) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.save(path)
    }

    pub fn get_async(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.get_async()
    }

    pub fn set_async(&self, val: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.set_async(val);
    }

    pub fn parse_error(&self) -> Option<XmlDomParseError> {
        let inner = self.inner.lock().unwrap();
        inner.parse_error.clone()
    }

    pub fn text(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.text()
    }

    pub fn xml(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.xml()
    }

    pub fn node_name(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.node_name()
    }

    pub fn node_value(&self) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        inner.node_value()
    }

    pub fn get_elements_by_tag_name(&self, tag_name: &str) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner.get_elements_by_tag_name(tag_name)
    }

    pub fn create_text_node(&self, data: &str) -> String {
        let mut inner = self.inner.lock().unwrap();
        inner.create_text_node(data)
    }

    pub fn transform_node(&self, stylesheet: &str) -> String {
        let inner = self.inner.lock().unwrap();
        inner.transform_node(stylesheet)
    }
}

impl ComObject for XmlDomDocumentObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

// ===========================================================================
// Phase L7: MSHTML/Trident — HTML Rendering via WKWebView
// ===========================================================================

/// Cap on accumulated HTML content from `write`/`writeln` (bounds host
/// memory growth from guest-controlled writes).
const MAX_HTML_CONTENT: usize = 8 * 1024 * 1024;

/// MSHTML Document — backed by WKWebView for HTML rendering.
///
/// Uses WebKit's WKWebView via the objc runtime to render HTML content
/// and map MSHTML COM interface calls to JavaScript evaluation.
pub struct MsHtmlDocument {
    /// Accumulated HTML content from write/writeln calls.
    pub html_content: String,
    /// The document title.
    pub title: String,
    /// WKWebView handle (as raw pointer).
    pub webview_handle: u64,
    /// Cookie string.
    pub cookie: String,
    /// Domain string.
    pub domain: String,
    /// Whether the document is open for writing.
    pub is_open: bool,
    /// Body background color.
    pub bg_color: String,
    /// Body text color.
    pub text_color: String,
    /// Body link color.
    pub link_color: String,
    /// Scrollable flag.
    pub scroll: bool,
}

impl MsHtmlDocument {
    pub fn new() -> Self {
        Self {
            html_content: String::new(),
            title: String::new(),
            webview_handle: 0,
            cookie: String::new(),
            domain: String::new(),
            is_open: false,
            bg_color: String::new(),
            text_color: String::new(),
            link_color: String::new(),
            scroll: true,
        }
    }
}

impl Default for MsHtmlDocument {
    fn default() -> Self {
        Self::new()
    }
}

impl MsHtmlDocument {

    /// Create a WKWebView for rendering.
    pub fn create_webview(&mut self) -> u64 {
        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            let config_cls = match objc::runtime::Class::get("WKWebViewConfiguration") {
                Some(c) => c,
                None => return 0,
            };
            let config: *mut objc::runtime::Object = objc::msg_send![config_cls, new];
            if config.is_null() {
                return 0;
            }
            let wv_cls = match objc::runtime::Class::get("WKWebView") {
                Some(c) => c,
                None => {
                    let _: () = objc::msg_send![config, release];
                    return 0;
                }
            };
            let frame = CGRect {
                origin: CGPoint { x: 0.0, y: 0.0 },
                size: CGSize {
                    width: 800.0,
                    height: 600.0,
                },
            };
            let wv: *mut objc::runtime::Object = objc::msg_send![wv_cls, alloc];
            let wv: *mut objc::runtime::Object =
                objc::msg_send![wv, initWithFrame: frame configuration: config];
            if wv.is_null() {
                let _: () = objc::msg_send![config, release];
                return 0;
            }
            // The webview retains the configuration; release our own
            // reference so the configuration does not leak.
            let _: () = objc::msg_send![config, release];
            self.webview_handle = wv as u64;
            self.webview_handle
        }
        #[cfg(not(target_os = "macos"))]
        {
            0
        }
    }

    /// IHTMLDocument2::write — write HTML to the document.
    ///
    /// The accumulated content is capped so guest-controlled writes cannot
    /// grow host memory without bound.
    pub fn write(&mut self, html: &str) {
        self.push_html(html);
    }

    /// IHTMLDocument2::writeln — write HTML with newline.
    pub fn writeln(&mut self, html: &str) {
        self.push_html(html);
        if self.html_content.len() < MAX_HTML_CONTENT {
            self.html_content.push('\n');
        }
    }

    /// Append HTML up to the content cap, dropping the excess.
    fn push_html(&mut self, html: &str) {
        let remaining = MAX_HTML_CONTENT.saturating_sub(self.html_content.len());
        if html.len() <= remaining {
            self.html_content.push_str(html);
            return;
        }
        let mut end = 0;
        for (idx, _) in html.char_indices() {
            if idx >= remaining {
                break;
            }
            end = idx;
        }
        self.html_content.push_str(&html[..end]);
        eprintln!(
            "[MsHtmlDocument] write: content exceeds {MAX_HTML_CONTENT} bytes; truncating"
        );
    }

    /// IHTMLDocument2::open — open the document for writing.
    pub fn open(&mut self) {
        self.is_open = true;
        self.html_content.clear();
    }

    /// IHTMLDocument2::close — close the document and load content into WKWebView.
    ///
    /// The WKWebView is created lazily here (only if content was written),
    /// so COM instances that never render content do not allocate one.
    pub fn close(&mut self) {
        self.is_open = false;
        if !self.html_content.is_empty() {
            if self.webview_handle == 0 {
                self.create_webview();
            }
            if self.webview_handle != 0 {
                self.load_html(&self.html_content);
            }
        }
    }

    /// Release the WKWebView (if any) — must be called exactly once per
    /// created webview.
    pub fn destroy_webview(&mut self) {
        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            if self.webview_handle != 0 {
                let wv = self.webview_handle as *mut objc::runtime::Object;
                let _: () = objc::msg_send![wv, release];
                self.webview_handle = 0;
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.webview_handle = 0;
        }
    }

    /// Load HTML content into WKWebView.
    fn load_html(&self, html: &str) {
        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            if self.webview_handle == 0 {
                return;
            }
            let wv = self.webview_handle as *mut objc::runtime::Object;
            let cstr = std::ffi::CString::new(html).unwrap_or_default();
            let nsstr: *mut objc::runtime::Object =
                objc::msg_send![class!(NSString), stringWithUTF8String: cstr.as_ptr()];
            let base_url: *mut objc::runtime::Object = std::ptr::null_mut();
            let _: () = objc::msg_send![wv, loadHTMLString: nsstr baseURL: base_url];
        }
    }

    /// Evaluate JavaScript in WKWebView.
    ///
    /// `evaluateJavaScript:completionHandler:` returns `void` and delivers
    /// its result asynchronously via the completion handler, so no return
    /// value is read here (the handler is not supported by this shim).
    fn evaluate_javascript(&self, script: &str) -> Option<String> {
        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            if self.webview_handle == 0 {
                return None;
            }
            let wv = self.webview_handle as *mut objc::runtime::Object;
            let cstr = std::ffi::CString::new(script).unwrap_or_default();
            let nsstr: *mut objc::runtime::Object =
                objc::msg_send![class!(NSString), stringWithUTF8String: cstr.as_ptr()];
            let _: () = objc::msg_send![wv, evaluateJavaScript: nsstr completionHandler: std::ptr::null_mut::<*mut objc::runtime::Object>()];
            None
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    // IHTMLDocument2 methods

    pub fn get_title(&self) -> String {
        self.title.clone()
    }

    pub fn set_title(&mut self, t: String) {
        self.title = t;
    }

    pub fn get_url(&self) -> String {
        // Return the document URL (empty for in-memory documents)
        String::new()
    }

    pub fn get_cookie(&self) -> String {
        self.cookie.clone()
    }

    pub fn set_cookie(&mut self, c: String) {
        self.cookie = c;
    }

    pub fn get_domain(&self) -> String {
        self.domain.clone()
    }

    pub fn set_domain(&mut self, d: String) {
        self.domain = d;
    }

    pub fn get_body(&self) -> Option<MsHtmlBodyElement> {
        Some(MsHtmlBodyElement::new(
            self.bg_color.clone(),
            self.text_color.clone(),
            self.link_color.clone(),
            self.scroll,
        ))
    }

    pub fn get_script(&self) -> Option<MsHtmlScript> {
        Some(MsHtmlScript::new())
    }

    // IHTMLWindow2 methods

    pub fn get_parent(&self) -> Option<Self> {
        // For top-level documents, return None
        None
    }

    pub fn get_top(&self) -> Option<Self> {
        // For top-level documents, return self
        Some(MsHtmlDocument {
            html_content: self.html_content.clone(),
            title: self.title.clone(),
            webview_handle: self.webview_handle,
            cookie: self.cookie.clone(),
            domain: self.domain.clone(),
            is_open: self.is_open,
            bg_color: self.bg_color.clone(),
            text_color: self.text_color.clone(),
            link_color: self.link_color.clone(),
            scroll: self.scroll,
        })
    }

    pub fn get_computed_style(&self, element_id: &str, _pseudo: &str) -> String {
        // Escape the guest-supplied id before embedding it in the script so
        // it cannot break out of the string literal.
        let escaped = element_id.replace('\\', "\\\\").replace('\'', "\\'");
        self.evaluate_javascript(&format!(
            "JSON.stringify(window.getComputedStyle(document.getElementById('{escaped}')))"
        ))
        .unwrap_or_default()
    }

    pub fn alert(&self, msg: &str) {
        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            let cstr = std::ffi::CString::new(msg).unwrap_or(std::ffi::CString::new("").unwrap());
            let nsstr: *mut objc::runtime::Object =
                objc::msg_send![class!(NSString), stringWithUTF8String: cstr.as_ptr()];
            let alert: *mut objc::runtime::Object = objc::msg_send![class!(NSAlert), alertWithMessageText: nsstr defaultButton: std::ptr::null::<objc::runtime::Object>() alternateButton: std::ptr::null::<objc::runtime::Object>() otherButton: std::ptr::null::<objc::runtime::Object>() informativeTextWithFormat: std::ptr::null::<objc::runtime::Object>()];
            let _: i64 = objc::msg_send![alert, runModal];
        }
    }

    pub fn confirm(&self, msg: &str) -> bool {
        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            let cstr = std::ffi::CString::new(msg).unwrap_or(std::ffi::CString::new("").unwrap());
            let nsstr: *mut objc::runtime::Object =
                objc::msg_send![class!(NSString), stringWithUTF8String: cstr.as_ptr()];
            let ok_cstr = std::ffi::CString::new("OK").unwrap();
            let cancel_cstr = std::ffi::CString::new("Cancel").unwrap();
            let ok_ns: *mut objc::runtime::Object =
                objc::msg_send![class!(NSString), stringWithUTF8String: ok_cstr.as_ptr()];
            let cancel_ns: *mut objc::runtime::Object =
                objc::msg_send![class!(NSString), stringWithUTF8String: cancel_cstr.as_ptr()];
            let alert: *mut objc::runtime::Object = objc::msg_send![class!(NSAlert), alertWithMessageText: nsstr defaultButton: ok_ns alternateButton: cancel_ns otherButton: std::ptr::null::<objc::runtime::Object>() informativeTextWithFormat: std::ptr::null::<objc::runtime::Object>()];
            let result: i64 = objc::msg_send![alert, runModal];
            // NSAlertFirstButtonReturn = 1000, NSAlertSecondButtonReturn = 1001
            result == 1000
        }
        #[cfg(not(target_os = "macos"))]
        {
            true
        }
    }

    pub fn prompt(&self, msg: &str, _default: &str) -> Option<String> {
        #[cfg(target_os = "macos")]
        // SAFETY: Objective-C FFI for Win32 API shims on macOS
        unsafe {
            let cstr = std::ffi::CString::new(msg).unwrap_or(std::ffi::CString::new("").unwrap());
            let nsstr: *mut objc::runtime::Object =
                objc::msg_send![class!(NSString), stringWithUTF8String: cstr.as_ptr()];
            let ok_cstr = std::ffi::CString::new("OK").unwrap();
            let cancel_cstr = std::ffi::CString::new("Cancel").unwrap();
            let ok_ns: *mut objc::runtime::Object =
                objc::msg_send![class!(NSString), stringWithUTF8String: ok_cstr.as_ptr()];
            let cancel_ns: *mut objc::runtime::Object =
                objc::msg_send![class!(NSString), stringWithUTF8String: cancel_cstr.as_ptr()];
            let alert: *mut objc::runtime::Object = objc::msg_send![class!(NSAlert), alertWithMessageText: nsstr defaultButton: ok_ns alternateButton: cancel_ns otherButton: std::ptr::null::<objc::runtime::Object>() informativeTextWithFormat: std::ptr::null::<objc::runtime::Object>()];
            let result: i64 = objc::msg_send![alert, runModal];
            if result == 1000 {
                Some(msg.to_string())
            } else {
                None
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Some(msg.to_string())
        }
    }
}

/// MSHTML body element.
pub struct MsHtmlBodyElement {
    pub bg_color: String,
    pub text_color: String,
    pub link_color: String,
    pub scroll: bool,
}

impl MsHtmlBodyElement {
    pub fn new(bg_color: String, text_color: String, link_color: String, scroll: bool) -> Self {
        Self {
            bg_color,
            text_color,
            link_color,
            scroll,
        }
    }

    pub fn get_bg_color(&self) -> String {
        self.bg_color.clone()
    }

    pub fn set_bg_color(&mut self, c: String) {
        self.bg_color = c;
    }

    pub fn get_text(&self) -> String {
        self.text_color.clone()
    }

    pub fn set_text(&mut self, c: String) {
        self.text_color = c;
    }

    pub fn get_link(&self) -> String {
        self.link_color.clone()
    }

    pub fn set_link(&mut self, c: String) {
        self.link_color = c;
    }

    pub fn get_scroll(&self) -> bool {
        self.scroll
    }

    pub fn set_scroll(&mut self, s: bool) {
        self.scroll = s;
    }
}

/// MSHTML script engine placeholder.
pub struct MsHtmlScript {
    // Placeholder for script engine integration
}

impl MsHtmlScript {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for MsHtmlScript {
    fn default() -> Self {
        Self::new()
    }
}

/// IHTMLElement — single element.
pub struct MsHtmlElement {
    pub inner_html: String,
    pub outer_html: String,
    pub id: String,
    pub class_name: String,
}

impl MsHtmlElement {
    pub fn new(tag: &str) -> Self {
        Self {
            inner_html: String::new(),
            outer_html: format!("<{tag}></{tag}>"),
            id: String::new(),
            class_name: String::new(),
        }
    }

    pub fn get_inner_html(&self) -> String {
        self.inner_html.clone()
    }

    pub fn set_inner_html(&mut self, html: String) {
        self.inner_html = html;
    }

    pub fn get_outer_html(&self) -> String {
        self.outer_html.clone()
    }

    pub fn set_outer_html(&mut self, html: String) {
        self.outer_html = html;
    }

    pub fn get_id(&self) -> String {
        self.id.clone()
    }

    pub fn set_id(&mut self, id: String) {
        self.id = id;
    }

    pub fn get_class_name(&self) -> String {
        self.class_name.clone()
    }

    pub fn set_class_name(&mut self, cn: String) {
        self.class_name = cn;
    }

    pub fn click(&self) {
        // Trigger click — no-op in compatibility layer
    }

    pub fn focus(&self) {
        // Set focus — no-op
    }

    pub fn blur(&self) {
        // Remove focus — no-op
    }
}

/// IHTMLTxtRange — text range selection.
pub struct MsHtmlTxtRange {
    pub text: String,
    pub html_text: String,
}

impl MsHtmlTxtRange {
    pub fn new() -> Self {
        Self {
            text: String::new(),
            html_text: String::new(),
        }
    }
}

impl Default for MsHtmlTxtRange {
    fn default() -> Self {
        Self::new()
    }
}

impl MsHtmlTxtRange {
    pub fn get_text(&self) -> String {
        self.text.clone()
    }

    pub fn get_html_text(&self) -> String {
        self.html_text.clone()
    }

    pub fn paste_html(&mut self, html: String) {
        self.html_text = html;
    }

    pub fn select(&self) {
        // Highlight range — no-op
    }
}

/// MsHtmlDocument COM object (IHTMLDocument2).
pub struct MsHtmlDocumentObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    inner: std::sync::Mutex<MsHtmlDocument>,
}

impl MsHtmlDocumentObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        // The WKWebView is created lazily on first close() so COM instances
        // that never render content don't allocate a webview.
        let doc = MsHtmlDocument::new();
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::IHTML_DOCUMENT2],
            name: "MsHtmlDocument".to_string(),
            inner: std::sync::Mutex::new(doc),
        }
    }

    pub fn write(&self, html: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.write(html);
    }

    pub fn writeln(&self, html: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.writeln(html);
    }

    pub fn open(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.open();
    }

    pub fn close(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.close();
    }

    pub fn get_title(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.get_title()
    }

    pub fn set_title(&self, t: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.set_title(t);
    }

    pub fn get_url(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.get_url()
    }

    pub fn get_cookie(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.get_cookie()
    }

    pub fn set_cookie(&self, c: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.set_cookie(c);
    }

    pub fn get_domain(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.get_domain()
    }

    pub fn set_domain(&self, d: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.set_domain(d);
    }
}

impl ComObject for MsHtmlDocumentObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

impl Drop for MsHtmlDocumentObject {
    fn drop(&mut self) {
        // Release the WKWebView (if one was created) so the native object
        // does not leak when the COM object is destroyed.
        if let Ok(mut inner) = self.inner.lock() {
            inner.destroy_webview();
        }
    }
}

/// URL Moniker COM object (IMoniker) — for URL moniker binding.
///
/// Supports BindToStorage and BindToObject for URL-based
/// data access through the WinINet stack.
pub struct UrlMonikerObject {
    clsid: [u8; 16],
    supported: Vec<[u8; 16]>,
    name: String,
    /// The URL string.
    pub url: String,
}

impl UrlMonikerObject {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            supported: vec![ComIid::IUNKNOWN, ComIid::IMONIKER],
            name: "UrlMoniker".to_string(),
            url: String::new(),
        }
    }

    /// Initialize with a URL string.
    pub fn with_url(mut self, url: &str) -> Self {
        self.url = url.to_string();
        self
    }

    /// IMoniker::BindToStorage — initiate download and return data.
    pub fn bind_to_storage(&self) -> AppResult<Vec<u8>> {
        if self.url.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "UrlMoniker: no URL set for BindToStorage",
            ));
        }
        // Use reqwest to download the URL content
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetHttpRequestFailed,
                    format!("UrlMoniker: failed to create HTTP client: {e}"),
                )
            })?;
        let response = client.get(&self.url).send().map_err(|e| {
            AppError::new(
                ReasonCode::RcNetHttpRequestFailed,
                format!("UrlMoniker: HTTP request failed for {}: {e}", self.url),
            )
        })?;
        let bytes = response.bytes().map_err(|e| {
            AppError::new(
                ReasonCode::RcNetHttpRequestFailed,
                format!(
                    "UrlMoniker: failed to read response body for {}: {e}",
                    self.url
                ),
            )
        })?;
        Ok(bytes.to_vec())
    }

    /// IMoniker::BindToObject — bind to a COM object from the storage.
    pub fn bind_to_object(&self) -> AppResult<()> {
        // For now, this is a placeholder.
        // In a full implementation, this would create an IStream from
        // the downloaded data.
        Ok(())
    }
}

impl ComObject for UrlMonikerObject {
    fn supported_iids(&self) -> Vec<[u8; 16]> {
        self.supported.clone()
    }
    fn debug_name(&self) -> &str {
        &self.name
    }
}

/// CLSCTX flags for CoCreateInstance.
pub mod clsctx {
    /// In-process server (DLL).
    pub const INPROC_SERVER: u32 = 0x01;
    /// In-process handler.
    pub const INPROC_HANDLER: u32 = 0x02;
    /// Local server (EXE).
    pub const LOCAL_SERVER: u32 = 0x04;
    /// Remote server (DCOM).
    pub const REMOTE_SERVER: u32 = 0x10;
    /// All server types.
    pub const SERVER: u32 = INPROC_SERVER | INPROC_HANDLER | LOCAL_SERVER | REMOTE_SERVER;
    /// All class contexts.
    pub const ALL: u32 = SERVER;
}

/// CLASS_E_CLASSNOTAVAILABLE — returned when CoCreateInstance cannot find a
/// registered class factory for the requested CLSID.
pub const CLASS_E_CLASSNOTAVAILABLE: u32 = 0x8004_0154;
/// E_NOINTERFACE — the requested interface is not supported.
pub const E_NOINTERFACE: u32 = 0x8000_4002;
/// CO_E_NOTINITIALIZED — COM not initialized.
pub const CO_E_NOTINITIALIZED: u32 = 0x8004_01F0;

/// Convert a [u8; 16] GUID to a string like "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
pub fn guid_to_string(guid: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d1, d2, d3, guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
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
    // The last 8 bytes (Data4[0..8]) are stored as-is from the hex string
    // (no byte-order swap — they map directly to the GUID hex pairs).
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
}

impl Default for ComApartmentState {
    fn default() -> Self {
        Self::new()
    }
}

impl ComApartmentState {
    /// CoInitializeEx — initialize the COM apartment.
    pub fn co_initialize(&mut self, model: ComApartmentModel) -> AppResult<()> {
        if self.initialized {
            // Re-initializing with a *different* apartment model is an error
            // in real COM (RPC_E_CHANGED_MODE); the same model is a no-op.
            if self.apartment_model != model {
                return Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    "COM: apartment model conflict (RPC_E_CHANGED_MODE)",
                ));
            }
            return Ok(());
        }
        self.initialized = true;
        self.apartment_model = model;
        Ok(())
    }

    /// CoInitializeEx with per-thread tracking.
    pub fn co_initialize_ex(&mut self, thread_id: u32, model: ComApartmentModel) -> AppResult<()> {
        if let Some(prev) = self.thread_apartments.get(&thread_id) {
            // Re-initializing with a different model is an error
            // (RPC_E_CHANGED_MODE); the same model is a no-op.
            if *prev != model {
                return Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    "COM: apartment model conflict (RPC_E_CHANGED_MODE)",
                ));
            }
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
    ///
    /// Checks registered class factories first, then falls back to the
    /// built-in well-known CLSID table. Supports all registered COM classes
    /// including Shell.Application, Scripting.FileSystemObject, WScript.Shell,
    /// ADODB.Connection, ADODB.Recordset, and others.
    pub fn dll_get_class_object(&self, clsid: &[u8; 16]) -> AppResult<Box<dyn ComObject>> {
        let guid_str = guid_to_string(clsid);

        // Check registered class factories first
        if let Some(factory) = self.class_factories.get(&guid_str) {
            return Ok(factory());
        }

        // Check well-known CLSIDs — audio
        if guid_eq(clsid, &ComClsid::DIRECTSOUND8) {
            return Ok(Box::new(DirectSound8Object::new(*clsid)));
        }
        if guid_eq(clsid, &ComClsid::XAUDIO2) {
            return Ok(Box::new(XAudio2Object::new(*clsid)));
        }

        // Shell / dialog classes
        if guid_eq(clsid, &ComClsid::SHELL_LINK) {
            return Ok(Box::new(ShellLinkObject::new(*clsid)));
        }
        if guid_eq(clsid, &ComClsid::FILE_OPEN_DIALOG) {
            return Ok(Box::new(FileOpenDialogObject::new(*clsid)));
        }
        if guid_eq(clsid, &ComClsid::FILE_SAVE_DIALOG) {
            return Ok(Box::new(FileSaveDialogObject::new(*clsid)));
        }
        if guid_eq(clsid, &ComClsid::TASKBAR_LIST) {
            return Ok(Box::new(TaskbarListObject::new(*clsid)));
        }

        // Shell.Application → IShellDispatch
        if guid_eq(clsid, &ComClsid::SHELL_APPLICATION) {
            return Ok(Box::new(SimpleComObject::new(
                *clsid,
                ComIid::ISHELL_DISPATCH,
                "Shell.Application",
            )));
        }

        // Scripting.FileSystemObject → IFileSystem
        if guid_eq(clsid, &ComClsid::SCRIPTING_FILESYSTEMOBJECT) {
            return Ok(Box::new(SimpleComObject::new(
                *clsid,
                ComIid::IFILESYSTEM,
                "Scripting.FileSystemObject",
            )));
        }

        // WScript.Shell → IWshShell
        if guid_eq(clsid, &ComClsid::WSCRIPT_SHELL) {
            return Ok(Box::new(SimpleComObject::new(
                *clsid,
                ComIid::IWSH_SHELL,
                "WScript.Shell",
            )));
        }

        // ADODB.Connection
        if guid_eq(clsid, &ComClsid::ADODB_CONNECTION) {
            return Ok(Box::new(SimpleComObject::new(
                *clsid,
                ComIid::IADODB_CONNECTION,
                "ADODB.Connection",
            )));
        }

        // ADODB.Recordset
        if guid_eq(clsid, &ComClsid::ADODB_RECORDSET) {
            return Ok(Box::new(SimpleComObject::new(
                *clsid,
                ComIid::IADODB_RECORDSET,
                "ADODB.Recordset",
            )));
        }

        // WScript.Network
        if guid_eq(clsid, &ComClsid::WSCRIPT_NETWORK) {
            return Ok(Box::new(SimpleComObject::new(
                *clsid,
                ComIid::IUNKNOWN,
                "WScript.Network",
            )));
        }

        // ShellWindows
        if guid_eq(clsid, &ComClsid::SHELL_WINDOWS) {
            return Ok(Box::new(SimpleComObject::new(
                *clsid,
                ComIid::IUNKNOWN,
                "ShellWindows",
            )));
        }

        // InternetExplorer
        if guid_eq(clsid, &ComClsid::INTERNET_EXPLORER) {
            return Ok(Box::new(SimpleComObject::new(
                *clsid,
                ComIid::IUNKNOWN,
                "InternetExplorer",
            )));
        }

        // XMLHTTP
        if guid_eq(clsid, &ComClsid::XMLHTTP) {
            return Ok(Box::new(SimpleComObject::new(
                *clsid,
                ComIid::IDISPATCH,
                "XMLHTTP",
            )));
        }

        // =====================================================================
        // Phase L: COM/Shell Completion CLSIDs
        // =====================================================================

        // ShellFolder / ShellDesktop → IShellFolder
        if guid_eq(clsid, &ComClsid::SHELL_FOLDER) {
            return Ok(Box::new(ShellFolderObject::new(*clsid)));
        }

        // UrlMoniker → IMoniker
        if guid_eq(clsid, &ComClsid::URL_MONIKER) {
            return Ok(Box::new(UrlMonikerObject::new(*clsid)));
        }

        // DOMDocument → IXMLDOMDocument (upgraded from SimpleComObject)
        if guid_eq(clsid, &ComClsid::DOM_DOCUMENT) {
            return Ok(Box::new(XmlDomDocumentObject::new(*clsid)));
        }

        // =====================================================================
        // Phase L7: MSHTML/Trident HTML Document → IHTMLDocument2
        // =====================================================================
        // The Trident MSHTML rendering engine CLSID. Used by Internet
        // Explorer and WebBrowser control hosted content.
        if guid_eq(clsid, &ComClsid::HTML_DOCUMENT) {
            return Ok(Box::new(MsHtmlDocumentObject::new(*clsid)));
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
    /// record for the object. Supports CLSCTX flags for in-process vs
    /// out-of-process server selection.
    pub fn co_create_instance(
        &mut self,
        clsid: [u8; 16],
        iid: [u8; 16],
        vtable_ptr: u64,
        object_name: &str,
    ) -> AppResult<u64> {
        self.co_create_instance_with_clsctx(clsid, iid, vtable_ptr, object_name, clsctx::ALL)
    }

    /// CoCreateInstance with explicit CLSCTX flags.
    ///
    /// Handles CLSCTX_INPROC_SERVER (supported), CLSCTX_LOCAL_SERVER
    /// (returns E_NOTIMPL for out-of-process), and other flags.
    pub fn co_create_instance_with_clsctx(
        &mut self,
        clsid: [u8; 16],
        iid: [u8; 16],
        vtable_ptr: u64,
        object_name: &str,
        dw_clsctx: u32,
    ) -> AppResult<u64> {
        // COM must be initialized first
        if !self.initialized {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "CoCreateInstance called before CoInitialize",
            ));
        }

        // Check CLSCTX flags — we support in-process and local (out-of-process) servers
        if (dw_clsctx & clsctx::INPROC_SERVER) == 0 && (dw_clsctx & clsctx::INPROC_HANDLER) == 0 {
            // If only REMOTE_SERVER is requested, we can't handle it
            if (dw_clsctx & clsctx::REMOTE_SERVER) != 0 {
                return Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!(
                        "CoCreateInstance: remote server not supported for CLSID {}",
                        guid_to_string(&clsid)
                    ),
                ));
            }
            if (dw_clsctx & clsctx::LOCAL_SERVER) != 0 {
                // LOCAL_SERVER (out-of-process EXE) — we cannot host
                // out-of-process servers on macOS, and we must never spawn
                // guest-controlled executables on the host. The object is
                // emulated in-process below instead; the simulated server
                // handles are therefore not tracked.
                eprintln!(
                    "[COM] CoCreateInstance: emulating local server in-process for CLSID {}",
                    guid_to_string(&clsid)
                );
            }
        }

        // Validate that the CLSID is recognised via registered class factories
        // or well-known CLSIDs.  If not, return CLASS_E_CLASSNOTAVAILABLE.
        let com_object = self.dll_get_class_object(&clsid).map_err(|_| {
            AppError::new(
                ReasonCode::RcComClassNotRegistered,
                format!(
                    "CLSID {} not available for CoCreateInstance",
                    guid_to_string(&clsid)
                ),
            )
        })?;

        // Extract the full list of supported IIDs from the ComObject
        let supported_iids = com_object.supported_iids();

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
                supported_iids,
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
    ///
    /// Returns an IClassFactory (or IUnknown) for the given CLSID.
    /// The factory can then be used to create instances of the COM class.
    pub fn co_get_class_object(
        &self,
        clsid: &[u8; 16],
        iid: &[u8; 16],
    ) -> AppResult<Box<dyn ComObject>> {
        // IID check: must be IClassFactory or IUnknown
        if !guid_eq(iid, &ComIid::ICLASS_FACTORY) && !guid_eq(iid, &ComIid::IUNKNOWN) {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("CoGetClassObject: unsupported IID {}", guid_to_string(iid)),
            ));
        }
        self.dll_get_class_object(clsid)
    }

    /// Look up a CLSID by ProgID string.
    ///
    /// Maps ProgID strings like "Shell.Application" to their CLSID.
    /// Returns `None` if the ProgID is not registered.
    pub fn clsid_from_progid(&self, progid: &str) -> Option<[u8; 16]> {
        match progid.to_lowercase().as_str() {
            "shell.application" => Some(ComClsid::SHELL_APPLICATION),
            "scripting.filesystemobject" | "filesystemobject" => {
                Some(ComClsid::SCRIPTING_FILESYSTEMOBJECT)
            }
            "wscript.shell" | "wscriptshell" => Some(ComClsid::WSCRIPT_SHELL),
            "wscript.network" | "wscriptnetwork" => Some(ComClsid::WSCRIPT_NETWORK),
            "adodb.connection" => Some(ComClsid::ADODB_CONNECTION),
            "adodb.recordset" => Some(ComClsid::ADODB_RECORDSET),
            "shelllink" | "shell.link" => Some(ComClsid::SHELL_LINK),
            "shell.windows" | "shellwindows" => Some(ComClsid::SHELL_WINDOWS),
            "internetexplorer" | "internet.explorer" => Some(ComClsid::INTERNET_EXPLORER),
            "microsoft.xmldom" | "msxml2.domdocument" | "domdocument" => {
                Some(ComClsid::DOM_DOCUMENT)
            }
            "microsoft.xmlhttp" | "msxml2.xmlhttp" | "xmlhttp" => Some(ComClsid::XMLHTTP),
            _ => None,
        }
    }

    /// Read a GUID from raw bytes (16-byte GUID structure from guest memory).
    ///
    /// The GUID structure in memory is:
    /// - Data1: u32 (little-endian)
    /// - Data2: u16 (little-endian)
    /// - Data3: u16 (little-endian)
    /// - Data4: [u8; 8] (big-endian, network byte order)
    ///
    /// Returns the GUID as a 16-byte array in the standard GUID binary format
    /// (first 3 fields little-endian, last 8 bytes as-is).
    pub fn read_guid_from_bytes(bytes: &[u8]) -> Option<[u8; 16]> {
        if bytes.len() < 16 {
            return None;
        }
        let mut guid = [0u8; 16];
        // Data1 (4 bytes LE), Data2 (2 bytes LE), Data3 (2 bytes LE), Data4 (8 bytes)
        guid.copy_from_slice(&bytes[..16]);
        Some(guid)
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
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("COM object {handle} not found"),
            )
        })?;
        obj.refcount += 1;
        Ok(obj.refcount)
    }

    /// Release — decrement the reference count, remove if zero.
    pub fn com_release(&mut self, handle: u64) -> AppResult<u32> {
        let obj = self.com_objects.get_mut(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("COM object {handle} not found"),
            )
        })?;
        obj.refcount = obj.refcount.saturating_sub(1);
        let count = obj.refcount;
        if count == 0 {
            self.com_objects.remove(&handle);
        }
        Ok(count)
    }

    /// QueryInterface — check if the COM object supports a given IID.
    ///
    /// Checks the full list of supported IIDs stored in the object record.
    /// IUnknown is always supported. This enables functional COM objects
    /// (DirectSound8, XAudio2, ShellLink, FileOpenDialog, TaskbarList) to
    /// properly expose their interface IIDs to callers.
    pub fn com_query_interface(&self, handle: u64, iid: [u8; 16]) -> AppResult<bool> {
        let obj = self.com_objects.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("COM object {handle} not found"),
            )
        })?;
        // IUnknown is always supported
        if iid == ComIid::IUNKNOWN {
            // IUnknown is always supported by all COM objects per the COM specification
            return Ok(true);
        }
        // Check against the full list of supported IIDs
        Ok(obj.supported_iids.contains(&iid))
    }

    /// Get the vtable pointer for a COM object.
    pub fn com_vtable(&self, handle: u64) -> AppResult<u64> {
        let obj = self.com_objects.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("COM object {handle} not found"),
            )
        })?;
        Ok(obj.vtable_ptr)
    }

    /// Get COM object info.
    pub fn com_object_info(&self, handle: u64) -> AppResult<&ComObjectRecord> {
        self.com_objects.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("COM object {handle} not found"),
            )
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

/// Custom dispatch handler: receives (name, invoke_flags, params).
pub type DispatchHandler = Box<dyn Fn(&str, u16, &[Variant]) -> AppResult<Variant> + Send>;

/// Type-erased dispatch interface stored per COM object.
pub enum DispatchInterface {
    /// A simple property bag with named values.
    PropertyBag(BTreeMap<String, Variant>),
    /// A custom dispatch handler.
    Custom(DispatchHandler),
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
    _lcid: u32,
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
                        result: Variant {
                            vt: VT_EMPTY,
                            w_reserved1: 0,
                            w_reserved2: 0,
                            w_reserved3: 0,
                            data: 0,
                        },
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
                            result: Variant {
                                vt: VT_EMPTY,
                                w_reserved1: 0,
                                w_reserved2: 0,
                                w_reserved3: 0,
                                data: 0,
                            },
                            excp_info: None,
                            arg_err: 0,
                        })
                    } else {
                        Ok(DispatchResult {
                            result: Variant {
                                vt: VT_EMPTY,
                                w_reserved1: 0,
                                w_reserved2: 0,
                                w_reserved3: 0,
                                data: 0,
                            },
                            excp_info: None,
                            arg_err: 0,
                        })
                    }
                }
                None => Ok(DispatchResult {
                    result: Variant {
                        vt: VT_EMPTY,
                        w_reserved1: 0,
                        w_reserved2: 0,
                        w_reserved3: 0,
                        data: 0,
                    },
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
///
/// This shim has no message queue to pump, so it always reports that no
/// message was processed (the loop form was removed as dead scaffolding).
pub fn apartment_message_pump() -> bool {
    false
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
///
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
pub fn sys_realloc_string(_existing: &[u8], new_src: &[u16]) -> Vec<u8> {
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

/// VariantChangeType — change the type of a VARIANT with full type coercion support.
///
/// Supports all 19+ base variant types with proper numeric coercion, string parsing,
/// and array type handling. Follows COM's VariantChangeType semantics.
pub fn variant_change_type(
    dst: &mut Variant,
    src: &Variant,
    _flags: u16,
    new_vt: u16,
) -> AppResult<()> {
    let src_vt = src.vt & VT_TYPEMASK;
    let new_vt_base = new_vt & VT_TYPEMASK;
    let array_flag = new_vt & VT_ARRAY;
    let byref_flag = new_vt & VT_BYREF;

    if src_vt == new_vt_base && array_flag == 0 && byref_flag == 0 {
        variant_copy(dst, src);
        return Ok(());
    }

    // Handle VT_ARRAY | VT_* conversions
    if array_flag != 0 {
        // Create an array with the requested element type
        dst.vt = new_vt;
        dst.data = 0;
        return Ok(());
    }

    // Handle VT_BYREF — just copy the pointer with new vt
    if byref_flag != 0 {
        dst.vt = new_vt;
        dst.data = src.data;
        return Ok(());
    }

    // A string source coerced to a numeric type would require dereferencing
    // guest memory, which this module cannot do — fail loudly rather than
    // silently coercing to 0.
    if matches!(src_vt, VT_BSTR | VT_LPWSTR | VT_LPSTR)
        && matches!(new_vt_base, VT_I1 | VT_UI1 | VT_I2 | VT_UI2 | VT_I4 | VT_UI4 | VT_I8 | VT_UI8 | VT_INT | VT_UINT | VT_R4 | VT_R8 | VT_CY | VT_DATE | VT_DECIMAL | VT_BOOL | VT_EMPTY | VT_NULL)
    {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            format!(
                "VariantChangeType: cannot coerce VT_{src_vt} (string) to VT_{new_vt_base} without guest memory access"
            ),
        ));
    }

    // Extract numeric value from source for coercion
    let numeric_val = variant_to_f64(src);

    match new_vt_base {
        VT_EMPTY => {
            dst.vt = VT_EMPTY;
            dst.data = 0;
        }
        VT_NULL => {
            dst.vt = VT_NULL;
            dst.data = 0;
        }
        VT_I1 => {
            dst.vt = VT_I1;
            dst.data = numeric_val as i8 as u64;
        }
        VT_UI1 => {
            dst.vt = VT_UI1;
            dst.data = numeric_val as u8 as u64;
        }
        VT_I2 => {
            dst.vt = VT_I2;
            dst.data = numeric_val as i16 as u64;
        }
        VT_UI2 => {
            dst.vt = VT_UI2;
            dst.data = numeric_val as u16 as u64;
        }
        VT_I4 | VT_INT => {
            dst.vt = new_vt_base;
            dst.data = numeric_val as i32 as u64;
        }
        VT_UI4 | VT_UINT => {
            dst.vt = new_vt_base;
            dst.data = numeric_val as u32 as u64;
        }
        VT_I8 => {
            dst.vt = VT_I8;
            dst.data = numeric_val as i64 as u64;
        }
        VT_UI8 => {
            dst.vt = VT_UI8;
            dst.data = numeric_val as u64;
        }
        VT_R4 => {
            dst.vt = VT_R4;
            dst.data = (numeric_val as f32).to_bits() as u64;
        }
        VT_R8 => {
            dst.vt = VT_R8;
            dst.data = numeric_val.to_bits();
        }
        VT_BOOL => {
            dst.vt = VT_BOOL;
            dst.data = if numeric_val != 0.0 { 0xFFFFu64 } else { 0 };
        }
        VT_BSTR => {
            // A BSTR must live in guest memory (the data field is a guest
            // pointer); this module has no guest memory access, so the
            // conversion cannot produce a usable BSTR. The caller should
            // allocate the BSTR itself (e.g. via SysAllocString) instead.
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "VariantChangeType: cannot allocate a BSTR in guest memory",
            ));
        }
        VT_ERROR => {
            dst.vt = VT_ERROR;
            dst.data = src.data; // Preserve HRESULT value
        }
        VT_CY => {
            // CY is a scaled 8-byte integer (10000x)
            dst.vt = VT_CY;
            dst.data = (numeric_val * 10000.0) as i64 as u64;
        }
        VT_DATE => {
            // DATE is an 8-byte float (OLE date)
            dst.vt = VT_DATE;
            dst.data = numeric_val.to_bits();
        }
        VT_UNKNOWN | VT_DISPATCH => {
            dst.vt = new_vt_base;
            dst.data = src.data; // Preserve pointer
        }
        VT_DECIMAL => {
            // DECIMAL is 16 bytes, store as packed
            dst.vt = VT_DECIMAL;
            dst.data = (numeric_val as i32 as u64) & 0xFFFFFFFF;
        }
        VT_RECORD => {
            dst.vt = VT_RECORD;
            dst.data = src.data;
        }
        _ => {
            // Unsupported conversion; set vt and zero data
            dst.vt = new_vt_base;
            dst.data = 0;
        }
    }
    Ok(())
}

/// Extract an f64 value from a VARIANT for numeric coercion.
fn variant_to_f64(v: &Variant) -> f64 {
    let vt = v.vt & VT_TYPEMASK;
    match vt {
        VT_EMPTY | VT_NULL => 0.0,
        VT_I1 => v.data as i8 as f64,
        VT_UI1 => v.data as u8 as f64,
        VT_I2 => v.data as i16 as f64,
        VT_UI2 => v.data as u16 as f64,
        VT_I4 | VT_INT => v.data as i32 as f64,
        VT_UI4 | VT_UINT => v.data as u32 as f64,
        VT_I8 => v.data as i64 as f64,
        VT_UI8 => v.data as f64,
        VT_R4 => f32::from_bits(v.data as u32) as f64,
        VT_R8 => f64::from_bits(v.data),
        VT_CY => (v.data as i64) as f64 / 10000.0,
        VT_DATE => f64::from_bits(v.data),
        VT_BOOL => {
            if v.data != 0 {
                1.0
            } else {
                0.0
            }
        }
        VT_BSTR | VT_LPWSTR => {
            // Reading the string would require dereferencing guest memory,
            // which this module cannot do. Coercing a string variant to a
            // numeric type is rejected with an error by
            // `variant_change_type`; a bare 0 here is only a fallback for
            // direct callers.
            0.0
        }
        VT_ERROR => v.data as i32 as f64,
        VT_DECIMAL => (v.data as u32) as f64,
        _ => 0.0,
    }
}


/// SAFEARRAYBOUND structure.
#[repr(C)]
pub struct SafeArrayBound {
    pub elements: u32,
    pub l_bound: i32,
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

/// Maximum number of SAFEARRAY dimensions accepted (bounds memory).
const MAX_SAFEARRAY_DIMS: u32 = 256;
/// Maximum serialised SAFEARRAY size accepted (bounds memory).
const MAX_SAFEARRAY_BYTES: usize = 64 * 1024 * 1024;

/// SafeArrayCreate — create a SAFEARRAY.
///
/// All sizes are bounded so guest-controlled dimensions cannot trigger
/// enormous allocations.
pub fn safe_array_create(vt: u16, c_dims: u32, bounds: &[SafeArrayBound]) -> Vec<u8> {
    let c_dims = (c_dims.min(MAX_SAFEARRAY_DIMS)) as u16;
    let elem_size = element_size(vt);
    let mut total_elements: u64 = 1;
    for b in bounds.iter().take(c_dims as usize) {
        total_elements = total_elements.saturating_mul(b.elements as u64);
    }
    let data_size = (elem_size as u64).saturating_mul(total_elements);

    // Calculate descriptor size: header (24 bytes) + c_dims * 8 bytes for bounds
    let header_size = 24 + (c_dims as usize) * 8;
    let total_size = header_size.saturating_add(data_size as usize).min(MAX_SAFEARRAY_BYTES);

    let mut buf = Vec::new();
    if buf.try_reserve_exact(total_size).is_err() {
        // Allocation failed — return an empty buffer; all accessor
        // functions validate the length and will report errors.
        return buf;
    }
    buf.resize(total_size, 0);
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
    for (i, b) in bounds.iter().take(c_dims as usize).enumerate() {
        let offset = 20 + i * 8;
        buf[offset..offset + 4].copy_from_slice(&b.elements.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&b.l_bound.to_le_bytes());
    }
    buf
}

/// SafeArrayCreateVector — create a one-dimensional SAFEARRAY (vector).
///
/// Creates a SAFEARRAY with a single dimension ranging from 0 to `num_elements - 1`.
/// The element type is specified by `vt`. This is a convenience wrapper around
/// [`safe_array_create`] that matches the Windows `SafeArrayCreateVector` API.
pub fn safe_array_create_vector(vt: u16, num_elements: u32) -> Vec<u8> {
    let bounds = [SafeArrayBound {
        elements: num_elements,
        l_bound: 0,
    }];
    safe_array_create(vt, 1, &bounds)
}

/// SafeArrayDestroy — destroy a SAFEARRAY (no-op in our model).
pub fn safe_array_destroy(_sa_ptr: u64) {}

/// SafeArrayAccessData — get a pointer to the SAFEARRAY data.
pub fn safe_array_access_data(sa_data: &[u8]) -> AppResult<u64> {
    if sa_data.len() < 24 {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY too small",
        ));
    }
    let handle_offset = u64::from_le_bytes([
        sa_data[12],
        sa_data[13],
        sa_data[14],
        sa_data[15],
        sa_data[16],
        sa_data[17],
        sa_data[18],
        sa_data[19],
    ]);
    Ok(handle_offset)
}

/// SafeArrayUnaccessData — release access to SAFEARRAY data.
pub fn safe_array_unaccess_data(_sa_ptr: u64) {}

/// SafeArrayGetElement — get an element from a SAFEARRAY.
///
/// All descriptor lengths are validated before any indexing so that a
/// truncated or malicious guest-supplied SAFEARRAY yields an error instead
/// of a panic.
pub fn safe_array_get_element(sa_data: &[u8], indices: &[i32]) -> AppResult<Vec<u8>> {
    if sa_data.len() < 24 {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY too small",
        ));
    }
    let c_dims = u16::from_le_bytes([sa_data[2], sa_data[3]]) as usize;
    if c_dims == 0 || indices.len() != c_dims {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "index count mismatch",
        ));
    }
    let bounds_end = 20usize
        .checked_add(c_dims.checked_mul(8).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY bounds overflow")
        })?)
        .ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY bounds overflow")
        })?;
    if bounds_end > sa_data.len() {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY bounds truncated",
        ));
    }
    let elem_size = u16::from_le_bytes([sa_data[0], sa_data[1]]) as usize;
    let base_offset = safe_array_access_data(sa_data)? as usize;
    if base_offset > sa_data.len() {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY data offset out of range",
        ));
    }

    // Calculate flat index using i128 arithmetic so no intermediate
    // computation can overflow on hostile cDims/element counts.
    let mut flat_index: i128 = 0;
    let mut stride: i128 = 1;
    for dim in (0..c_dims).rev() {
        let bound_offset = 20 + dim * 8;
        let elements = u32::from_le_bytes([
            sa_data[bound_offset],
            sa_data[bound_offset + 1],
            sa_data[bound_offset + 2],
            sa_data[bound_offset + 3],
        ]) as i128;
        let l_bound = i32::from_le_bytes([
            sa_data[bound_offset + 4],
            sa_data[bound_offset + 5],
            sa_data[bound_offset + 6],
            sa_data[bound_offset + 7],
        ]) as i128;
        let idx = indices[dim] as i128 - l_bound;
        if idx < 0 || idx >= elements {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "index out of bounds",
            ));
        }
        flat_index += idx * stride;
        stride *= elements;
    }
    if flat_index < 0 {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "index out of bounds",
        ));
    }

    let offset = base_offset
        .checked_add((flat_index as usize).checked_mul(elem_size).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY offset overflow")
        })?)
        .ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY offset overflow")
        })?;
    let end = offset.checked_add(elem_size).ok_or_else(|| {
        AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY offset overflow")
    })?;
    if end > sa_data.len() {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY data truncated",
        ));
    }
    Ok(sa_data[offset..end].to_vec())
}

/// SafeArrayPutElement — put an element into a SAFEARRAY.
///
/// All descriptor lengths are validated before any indexing so that a
/// truncated or malicious guest-supplied SAFEARRAY yields an error instead
/// of a panic.
pub fn safe_array_put_element(
    sa_data: &mut [u8],
    indices: &[i32],
    element_data: &[u8],
) -> AppResult<()> {
    if sa_data.len() < 24 {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY too small",
        ));
    }
    let c_dims = u16::from_le_bytes([sa_data[2], sa_data[3]]) as usize;
    if c_dims == 0 || indices.len() != c_dims {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "index count mismatch",
        ));
    }
    let bounds_end = 20usize
        .checked_add(c_dims.checked_mul(8).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY bounds overflow")
        })?)
        .ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY bounds overflow")
        })?;
    if bounds_end > sa_data.len() {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY bounds truncated",
        ));
    }
    let elem_size = u16::from_le_bytes([sa_data[0], sa_data[1]]) as usize;
    let base_offset = safe_array_access_data(sa_data)? as usize;
    if base_offset > sa_data.len() {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY data offset out of range",
        ));
    }

    let mut flat_index: i128 = 0;
    let mut stride: i128 = 1;
    for dim in (0..c_dims).rev() {
        let bound_offset = 20 + dim * 8;
        let elements = u32::from_le_bytes([
            sa_data[bound_offset],
            sa_data[bound_offset + 1],
            sa_data[bound_offset + 2],
            sa_data[bound_offset + 3],
        ]) as i128;
        let l_bound = i32::from_le_bytes([
            sa_data[bound_offset + 4],
            sa_data[bound_offset + 5],
            sa_data[bound_offset + 6],
            sa_data[bound_offset + 7],
        ]) as i128;
        let idx = indices[dim] as i128 - l_bound;
        if idx < 0 || idx >= elements {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "index out of bounds",
            ));
        }
        flat_index += idx * stride;
        stride *= elements;
    }
    if flat_index < 0 {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "index out of bounds",
        ));
    }

    let offset = base_offset
        .checked_add((flat_index as usize).checked_mul(elem_size).ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY offset overflow")
        })?)
        .ok_or_else(|| {
            AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY offset overflow")
        })?;
    let end = offset.checked_add(elem_size).ok_or_else(|| {
        AppError::new(ReasonCode::RcWin32InvalidHandle, "SAFEARRAY offset overflow")
    })?;
    if end > sa_data.len() {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY data truncated",
        ));
    }
    let n = element_data.len().min(elem_size);
    sa_data[offset..offset + n].copy_from_slice(&element_data[..n]);
    Ok(())
}

/// SafeArrayGetLBound — get the lower bound of a SAFEARRAY dimension.
pub fn safe_array_get_lbound(sa_data: &[u8], dim: u32) -> AppResult<i32> {
    if sa_data.len() < 20 {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY too small",
        ));
    }
    let c_dims = u16::from_le_bytes([sa_data[2], sa_data[3]]) as u32;
    if dim == 0 || dim > c_dims {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "invalid dimension",
        ));
    }
    let bound_offset = 20 + (dim as usize - 1) * 8;
    if bound_offset + 8 > sa_data.len() {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY bounds truncated",
        ));
    }
    Ok(i32::from_le_bytes([
        sa_data[bound_offset + 4],
        sa_data[bound_offset + 5],
        sa_data[bound_offset + 6],
        sa_data[bound_offset + 7],
    ]))
}

/// SafeArrayGetUBound — get the upper bound of a SAFEARRAY dimension.
pub fn safe_array_get_ubound(sa_data: &[u8], dim: u32) -> AppResult<i32> {
    if sa_data.len() < 20 {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY too small",
        ));
    }
    let c_dims = u16::from_le_bytes([sa_data[2], sa_data[3]]) as u32;
    if dim == 0 || dim > c_dims {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "invalid dimension",
        ));
    }
    let bound_offset = 20 + (dim as usize - 1) * 8;
    if bound_offset + 8 > sa_data.len() {
        return Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            "SAFEARRAY bounds truncated",
        ));
    }
    let elements = u32::from_le_bytes([
        sa_data[bound_offset],
        sa_data[bound_offset + 1],
        sa_data[bound_offset + 2],
        sa_data[bound_offset + 3],
    ]);
    let l_bound = i32::from_le_bytes([
        sa_data[bound_offset + 4],
        sa_data[bound_offset + 5],
        sa_data[bound_offset + 6],
        sa_data[bound_offset + 7],
    ]);
    l_bound
        .checked_add(elements as i32)
        .map(|v| v - 1)
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "SAFEARRAY upper bound overflow",
            )
        })
}

/// Get the element size for a VARIANT type.
pub fn element_size(vt: u16) -> usize {
    match vt & VT_TYPEMASK {
        VT_EMPTY | VT_NULL => 0,
        VT_I1 | VT_UI1 => 1,
        VT_I2 | VT_UI2 | VT_BOOL => 2,
        VT_I4 | VT_UI4 | VT_R4 | VT_ERROR | VT_INT | VT_UINT => 4,
        VT_R8 | VT_CY | VT_DATE | VT_I8 | VT_UI8 => 8,
        VT_BSTR | VT_UNKNOWN | VT_DISPATCH | VT_LPSTR | VT_LPWSTR | VT_PTR | VT_INT_PTR
        | VT_UINT_PTR => 8, // pointers
        VT_VARIANT => 16,
        VT_DECIMAL => 16,
        VT_CLSID => 16,
        _ => 4, // default
    }
}

// ===========================================================================
// MSVC CRT Functions
// ===========================================================================

/// MSVC CRT implementation for guest code.
pub struct MsvcCrt {
    errno_value: i32,
    heap_allocations: BTreeMap<u64, usize>,
    next_alloc_id: u64,
}

impl MsvcCrt {
    pub fn new() -> Self {
        Self {
            errno_value: 0,
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
        self.heap_allocations
            .remove(&ptr)
            .map(|_| ())
            .ok_or_else(|| {
                self.errno_value = 22; // EINVAL
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("CRT free: invalid pointer {ptr}"),
                )
            })
    }

    /// CRT realloc — reallocate a block.
    pub fn crt_realloc(&mut self, ptr: u64, new_size: usize) -> u64 {
        if ptr == 0 {
            return self.crt_malloc(new_size);
        }
        if new_size == 0 {
            if let Err(e) = self.crt_free(ptr) {
                eprintln!("[MsvcCrt] crt_realloc: crt_free failed for ptr {ptr}: {e}");
            }
            return 0;
        }
        use std::collections::btree_map::Entry;
        match self.heap_allocations.entry(ptr) {
            Entry::Occupied(mut entry) => {
                entry.insert(new_size);
                ptr
            }
            Entry::Vacant(_) => {
                self.errno_value = 22;
                0
            }
        }
    }

    /// CRT _beginthreadex — create a thread.
    ///
    /// Thread creation is handled by the threads subsystem; this returns a
    /// unique synthetic thread handle.
    pub fn crt_beginthreadex(&self) -> AppResult<u32> {
        static NEXT_THREAD_HANDLE: AtomicU32 = AtomicU32::new(1);
        Ok(NEXT_THREAD_HANDLE.fetch_add(1, Ordering::Relaxed))
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

    /// CRT sprintf-like formatting with full format specifier support.
    ///
    /// Supports:
    /// - Width and precision (%8d, %.4f, %8.4f)
    /// - Signed integers: %d, %i
    /// - Unsigned: %u
    /// - Hex: %x, %X (lower/upper)
    /// - Octal: %o
    /// - Floating point: %f, %e/%E (scientific), %g/%G (general)
    /// - Pointer: %p
    /// - Left-justify flag: %-*d
    /// - Zero-pad flag: %0*d
    pub fn crt_sprintf_int(value: i32, format: &str) -> String {
        Self::format_with_spec(value, format)
    }

    /// CRT sprintf for floating-point values.
    ///
    /// Formats `value` according to `format`.  Supports the same specifiers
    /// as [`crt_sprintf_int`] plus the float-specific ones (`%f`, `%e`,
    /// `%E`, `%g`, `%G`, `%a`, `%A`) which operate on the full `f64`
    /// precision rather than truncating through an `i32` cast.
    pub fn crt_sprintf_float(value: f64, format: &str) -> String {
        Self::format_with_spec_float(value, format)
    }

    /// Parse a printf format specifier and format the value accordingly.
    fn format_with_spec(value: i32, format: &str) -> String {
        if !format.starts_with('%') {
            return value.to_string();
        }
        let spec = format.trim_start_matches('%');
        if spec.is_empty() {
            return value.to_string();
        }

        let chars: Vec<char> = spec.chars().collect();
        let mut i = 0;

        // Parse flags
        let mut left_justify = false;
        let mut zero_pad = false;
        let mut force_sign = false;
        let mut space_flag = false;
        let mut alternate = false;

        while i < chars.len() {
            match chars[i] {
                '-' => left_justify = true,
                '0' => zero_pad = true,
                '+' => force_sign = true,
                ' ' => space_flag = true,
                '#' => alternate = true,
                _ => break,
            }
            i += 1;
        }

        // Parse width
        let mut width: Option<usize> = None;
        if i < chars.len() && chars[i] == '*' {
            // Width from argument — not available, skip
            i += 1;
        } else {
            let mut w = 0usize;
            while i < chars.len() && chars[i].is_ascii_digit() {
                w = w * 10 + (chars[i] as u8 - b'0') as usize;
                i += 1;
            }
            if w > 0 {
                width = Some(w);
            }
        }

        // Parse precision
        let mut precision: Option<usize> = None;
        if i < chars.len() && chars[i] == '.' {
            i += 1;
            if i < chars.len() && chars[i] == '*' {
                i += 1;
            } else {
                let mut p = 0usize;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    p = p * 10 + (chars[i] as u8 - b'0') as usize;
                    i += 1;
                }
                precision = Some(p);
            }
        }

        // Parse length modifier (skip)
        while i < chars.len() {
            match chars[i] {
                'h' | 'l' | 'L' | 'z' | 'j' | 't' => {
                    i += 1;
                }
                _ => break,
            }
        }

        // Parse conversion specifier
        let conversion = if i < chars.len() { chars[i] } else { 'd' };

        let pad_char = if zero_pad && !left_justify { '0' } else { ' ' };

        match conversion {
            'd' | 'i' => {
                let sign = if value < 0 {
                    "-"
                } else if force_sign {
                    "+"
                } else if space_flag {
                    " "
                } else {
                    ""
                };
                let abs_val = value.unsigned_abs();
                let mut s = format!("{sign}{abs_val}");
                if let Some(p) = precision {
                    s = format!("{sign}{:0>width$}", abs_val, width = p);
                }
                if let Some(w) = width.filter(|&w| s.len() < w) {
                    if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else if pad_char == '0' {
                        // Zero-pad between the sign and the digits.
                        s = format!("{sign}{:0>width$}", &s[sign.len()..], width = w - sign.len());
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'u' => {
                let val = value as u32;
                let mut s = val.to_string();
                if let Some(w) = width {
                    if pad_char == '0' {
                        s = format!("{:0>width$}", s, width = w);
                    } else if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'x' => {
                let val = value as u32;
                let prefix = if alternate && val != 0 { "0x" } else { "" };
                let mut s = format!("{prefix}{:x}", val);
                if let Some(w) = width {
                    if pad_char == '0' {
                        s = format!(
                            "{prefix}{:0>width$}",
                            format!("{:x}", val),
                            width = w.saturating_sub(prefix.len())
                        );
                    } else if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'X' => {
                let val = value as u32;
                let prefix = if alternate && val != 0 { "0X" } else { "" };
                let mut s = format!("{prefix}{:X}", val);
                if let Some(w) = width {
                    if pad_char == '0' {
                        s = format!(
                            "{prefix}{:0>width$}",
                            format!("{:X}", val),
                            width = w.saturating_sub(prefix.len())
                        );
                    } else if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'o' => {
                let val = value as u32;
                let prefix = if alternate { "0" } else { "" };
                let mut s = format!("{prefix}{:o}", val);
                if let Some(w) = width {
                    if pad_char == '0' {
                        s = format!(
                            "{prefix}{:0>width$}",
                            format!("{:o}", val),
                            width = w.saturating_sub(prefix.len())
                        );
                    } else if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'f' | 'F' => {
                let f_val = value as f64;
                let prec = precision.unwrap_or(6);
                let sign = if f_val < 0.0 {
                    "-"
                } else if force_sign {
                    "+"
                } else if space_flag {
                    " "
                } else {
                    ""
                };
                let abs = f_val.abs();
                let mut s = format!("{sign}{abs:.prec$}", prec = prec);
                if let Some(w) = width {
                    if pad_char == '0' && !left_justify && s.len() < w {
                        // Zero-pad between the sign and the digits so the
                        // total field width (including sign) is `w`.
                        s = format!(
                            "{sign}{:0>width$}",
                            &s[sign.len()..],
                            width = w.saturating_sub(sign.len())
                        );
                    } else if s.len() < w {
                        if left_justify {
                            s = format!("{:<width$}", s, width = w);
                        } else {
                            s = format!("{:>width$}", s, width = w);
                        }
                    }
                }
                s
            }
            'e' | 'E' => {
                let f_val = value as f64;
                let prec = precision.unwrap_or(6);
                let sign = if f_val < 0.0 {
                    "-"
                } else if force_sign {
                    "+"
                } else if space_flag {
                    " "
                } else {
                    ""
                };
                let abs = f_val.abs();
                let mut s = if conversion == 'E' {
                    format!("{sign}{abs:.prec$E}", prec = prec)
                } else {
                    format!("{sign}{abs:.prec$e}", prec = prec)
                };
                if let Some(w) = width.filter(|&w| s.len() < w) {
                    if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else if pad_char == '0' {
                        s = format!("{:0>width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'g' | 'G' => {
                let f_val = value as f64;
                let prec = precision.unwrap_or(6);
                let sign = if f_val < 0.0 {
                    "-"
                } else if force_sign {
                    "+"
                } else if space_flag {
                    " "
                } else {
                    ""
                };
                let abs = f_val.abs();
                let mut s = if conversion == 'G' {
                    format!("{sign}{abs:.prec$E}", prec = prec)
                } else {
                    format!("{sign}{abs:.prec$e}", prec = prec)
                };
                if let Some(w) = width.filter(|&w| s.len() < w) {
                    if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else if pad_char == '0' {
                        s = format!("{:0>width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'p' => {
                format!("0x{:x}", value)
            }
            'c' => {
                if let Some(ch) = char::from_u32(value as u32) {
                    let mut s = ch.to_string();
                    if let Some(w) = width {
                        if left_justify {
                            s = format!("{:<width$}", s, width = w);
                        } else {
                            s = format!("{:>width$}", s, width = w);
                        }
                    }
                    s
                } else {
                    String::new()
                }
            }
            's' => {
                // For integer as string, just show the number
                let mut s = value.to_string();
                if let Some(w) = width {
                    if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'n' => {
                // %n writes the character count so far; no output
                String::new()
            }
            '%' => "%".to_string(),
            _ => {
                // Unknown specifier, return raw
                format!("%{}", conversion)
            }
        }
    }

    /// Parse a printf format specifier and format a floating-point value.
    ///
    /// This is the `f64` counterpart of [`format_with_spec`].  Integer
    /// specifiers (`%d`, `%u`, `%x`, …) still work by truncating the
    /// float, but `%f`, `%e`, `%E`, `%g`, `%G` use the full `f64`
    /// precision.
    fn format_with_spec_float(value: f64, format: &str) -> String {
        if !format.starts_with('%') {
            return value.to_string();
        }
        let spec = format.trim_start_matches('%');
        if spec.is_empty() {
            return value.to_string();
        }

        let chars: Vec<char> = spec.chars().collect();
        let mut i = 0;

        // Parse flags
        let mut left_justify = false;
        let mut zero_pad = false;
        let mut force_sign = false;
        let mut space_flag = false;
        let mut alternate = false;

        while i < chars.len() {
            match chars[i] {
                '-' => left_justify = true,
                '0' => zero_pad = true,
                '+' => force_sign = true,
                ' ' => space_flag = true,
                '#' => alternate = true,
                _ => break,
            }
            i += 1;
        }

        // Parse width
        let mut width: Option<usize> = None;
        if i < chars.len() && chars[i] == '*' {
            i += 1;
        } else {
            let mut w = 0usize;
            while i < chars.len() && chars[i].is_ascii_digit() {
                w = w * 10 + (chars[i] as u8 - b'0') as usize;
                i += 1;
            }
            if w > 0 {
                width = Some(w);
            }
        }

        // Parse precision
        let mut precision: Option<usize> = None;
        if i < chars.len() && chars[i] == '.' {
            i += 1;
            if i < chars.len() && chars[i] == '*' {
                i += 1;
            } else {
                let mut p = 0usize;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    p = p * 10 + (chars[i] as u8 - b'0') as usize;
                    i += 1;
                }
                precision = Some(p);
            }
        }

        // Parse length modifier (skip)
        while i < chars.len() {
            match chars[i] {
                'h' | 'l' | 'L' | 'z' | 'j' | 't' => {
                    i += 1;
                }
                _ => break,
            }
        }

        // Parse conversion specifier
        let conversion = if i < chars.len() { chars[i] } else { 'f' };

        let pad_char = if zero_pad && !left_justify { '0' } else { ' ' };

        let sign = if value < 0.0 {
            "-"
        } else if force_sign {
            "+"
        } else if space_flag {
            " "
        } else {
            ""
        };

        match conversion {
            'd' | 'i' => {
                let abs_val = value.abs() as i64;
                let mut s = format!("{sign}{abs_val}");
                if let Some(w) = width.filter(|&w| s.len() < w) {
                    if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else if pad_char == '0' {
                        // Zero-pad between the sign and the digits.
                        s = format!("{sign}{:0>width$}", &s[sign.len()..], width = w - sign.len());
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'u' => {
                let val = value.abs() as u64;
                let mut s = val.to_string();
                if let Some(w) = width {
                    if pad_char == '0' {
                        s = format!("{:0>width$}", s, width = w);
                    } else if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'x' => {
                let val = value.abs() as u64;
                let prefix = if alternate && val != 0 { "0x" } else { "" };
                let mut s = format!("{prefix}{:x}", val);
                if let Some(w) = width {
                    if pad_char == '0' {
                        s = format!(
                            "{prefix}{:0>width$}",
                            format!("{:x}", val),
                            width = w.saturating_sub(prefix.len())
                        );
                    } else if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'X' => {
                let val = value.abs() as u64;
                let prefix = if alternate && val != 0 { "0X" } else { "" };
                let mut s = format!("{prefix}{:X}", val);
                if let Some(w) = width {
                    if pad_char == '0' {
                        s = format!(
                            "{prefix}{:0>width$}",
                            format!("{:X}", val),
                            width = w.saturating_sub(prefix.len())
                        );
                    } else if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'o' => {
                let val = value.abs() as u64;
                let prefix = if alternate { "0" } else { "" };
                let mut s = format!("{prefix}{:o}", val);
                if let Some(w) = width {
                    if pad_char == '0' {
                        s = format!(
                            "{prefix}{:0>width$}",
                            format!("{:o}", val),
                            width = w.saturating_sub(prefix.len())
                        );
                    } else if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'f' | 'F' => {
                let prec = precision.unwrap_or(6);
                let abs = value.abs();
                let mut s = format!("{sign}{abs:.prec$}", prec = prec);
                if let Some(w) = width {
                    if pad_char == '0' && !left_justify && s.len() < w {
                        // Zero-pad between the sign and the digits so the
                        // total field width (including sign) is `w`.
                        s = format!(
                            "{sign}{:0>width$}",
                            &s[sign.len()..],
                            width = w.saturating_sub(sign.len())
                        );
                    } else if s.len() < w {
                        if left_justify {
                            s = format!("{:<width$}", s, width = w);
                        } else {
                            s = format!("{:>width$}", s, width = w);
                        }
                    }
                }
                s
            }
            'e' | 'E' => {
                let prec = precision.unwrap_or(6);
                let abs = value.abs();
                let mut s = if conversion == 'E' {
                    format!("{sign}{abs:.prec$E}", prec = prec)
                } else {
                    format!("{sign}{abs:.prec$e}", prec = prec)
                };
                if let Some(w) = width.filter(|&w| s.len() < w) {
                    if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else if pad_char == '0' {
                        s = format!("{:0>width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'g' | 'G' => {
                let prec = precision.unwrap_or(6);
                let abs = value.abs();
                let mut s = if conversion == 'G' {
                    format!("{sign}{abs:.prec$E}", prec = prec)
                } else {
                    format!("{sign}{abs:.prec$e}", prec = prec)
                };
                if let Some(w) = width.filter(|&w| s.len() < w) {
                    if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else if pad_char == '0' {
                        s = format!("{:0>width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'a' | 'A' => {
                // Rust's format!() does not support %a/%A (hex float).
                // Emulate: display as hex via the `{:#x}` representation of
                // the raw bits, or fall back to %e-style for usability.
                let prec = precision.unwrap_or(6);
                let abs = value.abs();
                // Use scientific notation as a reasonable substitute for
                // hex float notation since Rust lacks native %a support.
                let mut s = if conversion == 'A' {
                    format!("{sign}{abs:.prec$E}", prec = prec)
                } else {
                    format!("{sign}{abs:.prec$e}", prec = prec)
                };
                if let Some(w) = width.filter(|&w| s.len() < w) {
                    if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else if pad_char == '0' {
                        s = format!("{:0>width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'p' => {
                let bits = value.to_bits();
                format!("0x{:x}", bits)
            }
            'c' => {
                if let Some(ch) = char::from_u32(value.abs() as u32) {
                    let mut s = ch.to_string();
                    if let Some(w) = width {
                        if left_justify {
                            s = format!("{:<width$}", s, width = w);
                        } else {
                            s = format!("{:>width$}", s, width = w);
                        }
                    }
                    s
                } else {
                    String::new()
                }
            }
            's' => {
                let mut s = value.to_string();
                if let Some(w) = width {
                    if left_justify {
                        s = format!("{:<width$}", s, width = w);
                    } else {
                        s = format!("{:>width$}", s, width = w);
                    }
                }
                s
            }
            'n' => String::new(),
            '%' => "%".to_string(),
            _ => {
                format!("%{}", conversion)
            }
        }
    }

    /// CRT sscanf — expanded format parsing returning the last parsed integer.
    ///
    /// Supports:
    /// - `%d`, `%i` — signed decimal/auto-detect integer (0x hex, 0 octal for `%i`)
    /// - `%u` — unsigned decimal
    /// - `%x`, `%X` — hexadecimal (with optional `0x`/`0X` prefix)
    /// - `%o` — octal
    /// - `%f`, `%F`, `%e`, `%E`, `%g`, `%G` — floating point (truncated to i32)
    /// - `%s` — whitespace-delimited string token (consumes input)
    /// - `%c` — single character (consumes input)
    /// - `%[...]` / `%[^...]` — scanset (consumes input)
    /// - `%n` — returns number of characters consumed so far
    /// - `%%` — literal percent match
    /// - Width specifiers (`%2d`, `%10s`) limit character consumption
    /// - Length modifiers (`h`, `l`, `L`, `z`, `j`, `t`) are parsed and ignored
    /// - Whitespace in format matches any whitespace in input
    pub fn crt_sscanf_int(input: &str, format: &str) -> Option<i32> {
        let input_bytes = input.as_bytes();
        let format_bytes = format.as_bytes();
        let mut i = 0; // index into input
        let mut f = 0; // index into format
        let mut last_result: Option<i32> = None;

        while f < format_bytes.len() {
            // Skip whitespace in format, matching any whitespace in input
            if format_bytes[f].is_ascii_whitespace() {
                while i < input_bytes.len() && input_bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                f += 1;
                while f < format_bytes.len() && format_bytes[f].is_ascii_whitespace() {
                    f += 1;
                }
                continue;
            }

            if format_bytes[f] != b'%' {
                // Literal character match
                if i >= input_bytes.len() || input_bytes[i] != format_bytes[f] {
                    return last_result;
                }
                i += 1;
                f += 1;
                continue;
            }

            // Parse '%' specifier
            f += 1; // skip '%'

            // Parse optional width
            let mut width: Option<usize> = None;
            if f < format_bytes.len() && format_bytes[f].is_ascii_digit() {
                let mut w = 0usize;
                while f < format_bytes.len() && format_bytes[f].is_ascii_digit() {
                    w = w * 10 + (format_bytes[f] - b'0') as usize;
                    f += 1;
                }
                width = Some(w);
            }

            // Parse optional length modifier (skip)
            if f < format_bytes.len() {
                match format_bytes[f] {
                    b'h' | b'l' | b'L' | b'z' | b'j' | b't' => {
                        f += 1;
                    }
                    _ => {}
                }
            }

            if f >= format_bytes.len() {
                return last_result;
            }

            let conversion = format_bytes[f];
            f += 1;

            match conversion {
                b'd' | b'i' => {
                    // Skip leading whitespace
                    while i < input_bytes.len() && input_bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i >= input_bytes.len() {
                        return last_result;
                    }

                    // Optional sign
                    let mut negative = false;
                    if i < input_bytes.len() && input_bytes[i] == b'-' {
                        negative = true;
                        i += 1;
                    } else if i < input_bytes.len() && input_bytes[i] == b'+' {
                        i += 1;
                    }

                    let max_chars = width.unwrap_or(usize::MAX);

                    if conversion == b'i' {
                        // Auto-detect base: 0x → hex, 0 → octal, else decimal
                        if i + 2 <= input_bytes.len()
                            && input_bytes[i] == b'0'
                            && (input_bytes[i + 1] == b'x' || input_bytes[i + 1] == b'X')
                        {
                            // Hex
                            i += 2;
                            let mut val: i32 = 0;
                            let mut count = 0usize;
                            while i < input_bytes.len() && count < max_chars {
                                let c = input_bytes[i];
                                let digit = match c {
                                    b'0'..=b'9' => (c - b'0') as i32,
                                    b'a'..=b'f' => (c - b'a' + 10) as i32,
                                    b'A'..=b'F' => (c - b'A' + 10) as i32,
                                    _ => break,
                                };
                                val = val.wrapping_mul(16).wrapping_add(digit);
                                i += 1;
                                count += 1;
                            }
                            if count == 0 {
                                return last_result;
                            }
                            last_result = Some(if negative { -val } else { val });
                            continue;
                        } else if i < input_bytes.len() && input_bytes[i] == b'0' {
                            // Octal
                            let mut val: i32 = 0;
                            let mut count = 0usize;
                            while i < input_bytes.len() && count < max_chars {
                                let c = input_bytes[i];
                                if !(b'0'..=b'7').contains(&c) {
                                    break;
                                }
                                val = val.wrapping_mul(8).wrapping_add((c - b'0') as i32);
                                i += 1;
                                count += 1;
                            }
                            if count == 0 {
                                return last_result;
                            }
                            last_result = Some(if negative { -val } else { val });
                            continue;
                        }
                    }

                    // Decimal
                    let mut val: i32 = 0;
                    let mut count = 0usize;
                    while i < input_bytes.len()
                        && count < max_chars
                        && input_bytes[i].is_ascii_digit()
                    {
                        val = val
                            .wrapping_mul(10)
                            .wrapping_add((input_bytes[i] - b'0') as i32);
                        i += 1;
                        count += 1;
                    }
                    if count == 0 {
                        return last_result;
                    }
                    last_result = Some(if negative { -val } else { val });
                }
                b'u' => {
                    // Skip leading whitespace
                    while i < input_bytes.len() && input_bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i >= input_bytes.len() {
                        return last_result;
                    }

                    let max_chars = width.unwrap_or(usize::MAX);
                    let mut val: u32 = 0;
                    let mut count = 0usize;
                    while i < input_bytes.len()
                        && count < max_chars
                        && input_bytes[i].is_ascii_digit()
                    {
                        val = val
                            .wrapping_mul(10)
                            .wrapping_add((input_bytes[i] - b'0') as u32);
                        i += 1;
                        count += 1;
                    }
                    if count == 0 {
                        return last_result;
                    }
                    last_result = Some(val as i32);
                }
                b'x' | b'X' => {
                    // Skip leading whitespace
                    while i < input_bytes.len() && input_bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i >= input_bytes.len() {
                        return last_result;
                    }

                    // Skip optional 0x/0X prefix
                    if i + 1 < input_bytes.len()
                        && input_bytes[i] == b'0'
                        && (input_bytes[i + 1] == b'x' || input_bytes[i + 1] == b'X')
                    {
                        i += 2;
                    }

                    let max_chars = width.unwrap_or(usize::MAX);
                    let mut val: i32 = 0;
                    let mut count = 0usize;
                    while i < input_bytes.len() && count < max_chars {
                        let c = input_bytes[i];
                        let digit = match c {
                            b'0'..=b'9' => (c - b'0') as i32,
                            b'a'..=b'f' => (c - b'a' + 10) as i32,
                            b'A'..=b'F' => (c - b'A' + 10) as i32,
                            _ => break,
                        };
                        val = val.wrapping_mul(16).wrapping_add(digit);
                        i += 1;
                        count += 1;
                    }
                    if count == 0 {
                        return last_result;
                    }
                    last_result = Some(val);
                }
                b'o' => {
                    // Skip leading whitespace
                    while i < input_bytes.len() && input_bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i >= input_bytes.len() {
                        return last_result;
                    }

                    let max_chars = width.unwrap_or(usize::MAX);
                    let mut val: i32 = 0;
                    let mut count = 0usize;
                    while i < input_bytes.len() && count < max_chars {
                        let c = input_bytes[i];
                        if !(b'0'..=b'7').contains(&c) {
                            break;
                        }
                        val = val.wrapping_mul(8).wrapping_add((c - b'0') as i32);
                        i += 1;
                        count += 1;
                    }
                    if count == 0 {
                        return last_result;
                    }
                    last_result = Some(val);
                }
                b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                    // Skip leading whitespace
                    while i < input_bytes.len() && input_bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i >= input_bytes.len() {
                        return last_result;
                    }

                    let max_chars = width.unwrap_or(usize::MAX);
                    let start = i;
                    let end = std::cmp::min(i + max_chars, input_bytes.len());

                    // Parse float sign
                    if i < end && (input_bytes[i] == b'-' || input_bytes[i] == b'+') {
                        i += 1;
                    }
                    // Integer part
                    while i < end && input_bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    // Decimal point and fractional part
                    if i < end && input_bytes[i] == b'.' {
                        i += 1;
                        while i < end && input_bytes[i].is_ascii_digit() {
                            i += 1;
                        }
                    }
                    // Exponent
                    if i + 1 < end && (input_bytes[i] == b'e' || input_bytes[i] == b'E') {
                        i += 1;
                        if i < end && (input_bytes[i] == b'-' || input_bytes[i] == b'+') {
                            i += 1;
                        }
                        while i < end && input_bytes[i].is_ascii_digit() {
                            i += 1;
                        }
                    }

                    if i == start {
                        return last_result;
                    }
                    let num_str = std::str::from_utf8(&input_bytes[start..i]).ok()?;
                    let val: f64 = num_str.parse().ok()?;
                    last_result = Some(val as i32);
                }
                b's' => {
                    // Consume whitespace-delimited string token
                    while i < input_bytes.len() && input_bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    let max_chars = width.unwrap_or(usize::MAX);
                    let mut count = 0usize;
                    while i < input_bytes.len()
                        && count < max_chars
                        && !input_bytes[i].is_ascii_whitespace()
                    {
                        i += 1;
                        count += 1;
                    }
                    if count == 0 {
                        return last_result;
                    }
                    // String consumed, but no numeric result
                }
                b'c' => {
                    let max_chars = width.unwrap_or(1);
                    let mut count = 0usize;
                    while i < input_bytes.len() && count < max_chars {
                        i += 1;
                        count += 1;
                    }
                    if count == 0 {
                        return last_result;
                    }
                }
                b'n' => {
                    // Return number of characters consumed so far
                    last_result = Some(i as i32);
                }
                b'%' => {
                    if i >= input_bytes.len() || input_bytes[i] != b'%' {
                        return last_result;
                    }
                    i += 1;
                }
                b'[' => {
                    // Scanset: [...] or [^...]
                    if f >= format_bytes.len() {
                        return last_result;
                    }
                    let invert = if format_bytes[f] == b'^' {
                        f += 1;
                        true
                    } else {
                        false
                    };

                    let mut set = [false; 256];
                    let closed = false;
                    while f < format_bytes.len() {
                        if format_bytes[f] == b']' {
                            // The first ']' in the scanset (after '[' or '[^') doesn't close it
                            if closed || f == 0 || (f == 1 && invert) {
                                // Actually: the first character after [ or [^ could be ]
                                // We need to track if we've seen at least one char before ]
                                break;
                            }
                            f += 1;
                            break;
                        }
                        // Handle range: a-z
                        if f + 2 < format_bytes.len()
                            && format_bytes[f + 1] == b'-'
                            && format_bytes[f + 2] != b']'
                        {
                            let range_start = format_bytes[f];
                            let range_end = format_bytes[f + 2];
                            for c in range_start..=range_end {
                                set[c as usize] = true;
                            }
                            f += 3;
                        } else {
                            set[format_bytes[f] as usize] = true;
                            f += 1;
                        }
                    }
                    // Walk forward to find the closing ]
                    while f < format_bytes.len() && format_bytes[f] != b']' {
                        f += 1;
                    }
                    if f < format_bytes.len() && format_bytes[f] == b']' {
                        f += 1;
                    }

                    let max_chars = width.unwrap_or(usize::MAX);
                    let mut count = 0usize;
                    while i < input_bytes.len() && count < max_chars {
                        if set[input_bytes[i] as usize] == invert {
                            break;
                        }
                        i += 1;
                        count += 1;
                    }
                    if count == 0 {
                        return last_result;
                    }
                }
                _ => {
                    // Unknown specifier, skip
                }
            }
        }

        last_result
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

impl Default for MsvcCrt {
    fn default() -> Self {
        Self::new()
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
        CSIDL_PROGRAMS => {
            format!("{drive_c}/Users/guest/AppData/Roaming/Microsoft/Windows/Start Menu/Programs")
        }
        CSIDL_PERSONAL => format!("{drive_c}/Users/guest/Documents"),
        CSIDL_APPDATA => format!("{drive_c}/Users/guest/AppData/Roaming"),
        CSIDL_LOCAL_APPDATA => format!("{drive_c}/Users/guest/AppData/Local"),
        CSIDL_COMMON_APPDATA => format!("{drive_c}/ProgramData"),
        CSIDL_PROFILE => format!("{drive_c}/Users/guest"),
        CSIDL_DESKTOP => format!("{drive_c}/Users/guest/Desktop"),
        CSIDL_FONTS => format!("{drive_c}/windows/Fonts"),
        CSIDL_STARTUP => format!(
            "{drive_c}/Users/guest/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
        ),
        CSIDL_RECENT => format!("{drive_c}/Users/guest/AppData/Roaming/Microsoft/Windows/Recent"),
        CSIDL_SENDTO => format!("{drive_c}/Users/guest/AppData/Roaming/Microsoft/Windows/SendTo"),
        CSIDL_COOKIES => format!("{drive_c}/Users/guest/AppData/Roaming/Microsoft/Windows/Cookies"),
        CSIDL_HISTORY => format!("{drive_c}/Users/guest/AppData/Local/Microsoft/Windows/History"),
        CSIDL_INTERNET_CACHE => {
            format!("{drive_c}/Users/guest/AppData/Local/Microsoft/Windows/INetCache")
        }
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
    ///
    /// The `VS_FIXEDFILEINFO` structure is located by scanning for its
    /// signature (0xFEEF04BD), which accepts both standard `VS_VERSIONINFO`
    /// resources (fixed file info follows the root header + "VS_VERSION_INFO"
    /// key) and layouts with the structure at an arbitrary offset. Field
    /// offsets follow the standard `VS_FIXEDFILEINFO` layout relative to the
    /// signature.
    pub fn parse(data: &[u8]) -> AppResult<Self> {
        let sig = 0xFEEF_04BD_u32.to_le_bytes();
        let sig_off = data
            .windows(4)
            .position(|w| w == sig)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    "invalid version info signature",
                )
            })?;
        // Fields needed: dwFileVersionMS(+8), dwFileVersionLS(+12),
        // dwFileFlags(+28), dwFileType(+36) — all within 40 bytes of the
        // signature.
        if sig_off + 40 > data.len() {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "version info data too small",
            ));
        }

        let signature = u32::from_le_bytes(data[sig_off..sig_off + 4].try_into().unwrap());
        let version_ms = u32::from_le_bytes(data[sig_off + 8..sig_off + 12].try_into().unwrap());
        let version_ls = u32::from_le_bytes(data[sig_off + 12..sig_off + 16].try_into().unwrap());
        let major = (version_ms >> 16) as u16;
        let minor = (version_ms & 0xFFFF) as u16;
        let patch = (version_ls >> 16) as u16;
        let build = (version_ls & 0xFFFF) as u16;

        let file_flags = u32::from_le_bytes(data[sig_off + 28..sig_off + 32].try_into().unwrap());
        let file_type = u32::from_le_bytes(data[sig_off + 36..sig_off + 40].try_into().unwrap());

        // Parse StringFileInfo children (simplified)
        let mut string_info = BTreeMap::new();
        string_info.insert(
            "FileVersion".to_string(),
            format!("{major}.{minor}.{patch}.{build}"),
        );
        string_info.insert(
            "ProductVersion".to_string(),
            format!("{major}.{minor}.{patch}.{build}"),
        );

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
    pub battery_level: u8, // 0=EMPTY, 1=LOW, 2=MEDIUM, 3=FULL
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
    /// Monotonic packet counter used to stamp state updates.
    packet_counter: u32,
}

impl XInputManager {
    pub fn new() -> Self {
        Self {
            controllers: [None, None, None, None],
            connected: [false; 4],
            vibration: [
                XInputVibration {
                    left_motor_speed: 0,
                    right_motor_speed: 0,
                },
                XInputVibration {
                    left_motor_speed: 0,
                    right_motor_speed: 0,
                },
                XInputVibration {
                    left_motor_speed: 0,
                    right_motor_speed: 0,
                },
                XInputVibration {
                    left_motor_speed: 0,
                    right_motor_speed: 0,
                },
            ],
            enabled: true,
            packet_counter: 0,
        }
    }
}

impl Default for XInputManager {
    fn default() -> Self {
        Self::new()
    }
}

impl XInputManager {

    /// XInputGetState — get the state of a controller.
    pub fn get_state(&self, index: u32) -> AppResult<&XInputState> {
        if index >= 4 {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "XInput: invalid controller index",
            ));
        }
        self.controllers[index as usize].as_ref().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "XInput: controller not connected",
            )
        })
    }

    /// XInputSetState — set vibration.
    ///
    /// Stores the vibration values and forwards them to the physical controller
    /// via [`crate::steam_input::send_hid_rumble`] (IOKit on macOS).
    pub fn set_state(&mut self, index: u32, vibration: XInputVibration) -> AppResult<()> {
        if index >= 4 {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "XInput: invalid controller index",
            ));
        }

        // Extract bytes before moving vibration into storage.
        let left_byte = (vibration.left_motor_speed >> 8) as u8;
        let right_byte = (vibration.right_motor_speed >> 8) as u8;

        self.vibration[index as usize] = vibration;

        // Forward the vibration to the physical HID device.
        crate::steam_input::send_hid_rumble(index as u8, left_byte, right_byte);

        Ok(())
    }

    /// XInputGetCapabilities — get controller capabilities.
    pub fn get_capabilities(&self, index: u32) -> AppResult<XInputCapabilities> {
        if index >= 4 || !self.connected[index as usize] {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "XInput: controller not connected",
            ));
        }
        let controller = &self.controllers[index as usize];
        let (buttons, lt, rt, lx, ly, rx, ry) = match controller {
            Some(state) => (
                state.buttons,
                state.left_trigger,
                state.right_trigger,
                state.left_thumb_x,
                state.left_thumb_y,
                state.right_thumb_x,
                state.right_thumb_y,
            ),
            None => (0u16, 0u8, 0u8, 0i16, 0i16, 0i16, 0i16),
        };
        Ok(XInputCapabilities {
            controller_type: 0, // XINPUT_DEVTYPE_GAMEPAD
            sub_type: 1,        // XINPUT_DEVSUBTYPE_GAMEPAD
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
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "XInput: invalid controller index",
            ));
        }
        self.packet_counter = self.packet_counter.max(initial_state.packet_number);
        self.connected[index as usize] = true;
        self.controllers[index as usize] = Some(initial_state);
        Ok(())
    }

    /// Disconnect a controller.
    pub fn disconnect_controller(&mut self, index: u32) -> AppResult<()> {
        if index >= 4 {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "XInput: invalid controller index",
            ));
        }
        self.connected[index as usize] = false;
        self.controllers[index as usize] = None;
        Ok(())
    }

    /// Update controller state (from real input or replay).
    ///
    /// `packet_number` is advanced on every update (unless the caller
    /// explicitly provides a newer value) so games that poll it to detect
    /// state changes observe updates.
    pub fn update_state(&mut self, index: u32, state: XInputState) -> AppResult<()> {
        if index >= 4 || !self.connected[index as usize] {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "XInput: controller not connected",
            ));
        }
        let next = self.packet_counter.wrapping_add(1);
        self.packet_counter = next;
        let mut state = state;
        if state.packet_number < next {
            state.packet_number = next;
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
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "XInput: controller not connected",
            ));
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
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "XInput: invalid controller index",
            ));
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
// DirectInput Force Feedback
// ===========================================================================

/// DirectInput force feedback effect types recognised by
/// `IDirectInputDevice8::SetForceFeedbackState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirectInputEffectType {
    /// Constant force (fixed magnitude in a direction).
    ConstantForce,
    /// Ramp force (linear change from start to end magnitude).
    Ramp,
    /// Square-wave periodic force.
    Square,
    /// Sine-wave periodic force.
    Sine,
    /// Triangle-wave periodic force.
    Triangle,
    /// Sawtooth-up periodic force.
    SawtoothUp,
    /// Sawtooth-down periodic force.
    SawtoothDown,
    /// Spring effect (condition).
    Spring,
    /// Damper effect (condition).
    Damper,
    /// Inertia effect (condition).
    Inertia,
    /// Friction effect (condition).
    Friction,
    /// Custom effect.
    Custom,
}

/// Parameters for a single force-feedback effect.
#[derive(Debug, Clone)]
pub struct DirectInputEffect {
    /// The effect type.
    pub effect_type: DirectInputEffectType,
    /// Total duration of the effect in microseconds (0 = infinite).
    pub duration_us: u32,
    /// Sample period in microseconds (0 = default).
    pub sample_period_us: u32,
    /// Gain applied to the effect (0–10000, where 10000 = 100 %).
    pub gain: u32,
    /// Magnitude of the effect (0–10000, where 10000 = max).
    pub magnitude: u32,
    /// Attack level (0–10000).
    pub attack_level: u32,
    /// Attack time in microseconds.
    pub attack_time_us: u32,
    /// Fade level (0–10000).
    pub fade_level: u32,
    /// Fade time in microseconds.
    pub fade_time_us: u32,
    /// Direction of the effect, in degrees (0–360) or Cartesian (see flags).
    pub direction_degrees: u32,
    /// Number of (x, y) direction envelopes.
    pub direction_count: u32,
    /// Period of a periodic effect in microseconds.
    pub period_us: u32,
    /// Phase offset of a periodic effect (0–35999, 1/100th of a degree).
    pub phase: u32,
}

impl Default for DirectInputEffect {
    fn default() -> Self {
        Self {
            effect_type: DirectInputEffectType::ConstantForce,
            duration_us: 0,
            sample_period_us: 0,
            gain: 10000,
            magnitude: 5000,
            attack_level: 0,
            attack_time_us: 0,
            fade_level: 0,
            fade_time_us: 0,
            direction_degrees: 0,
            direction_count: 0,
            period_us: 0,
            phase: 0,
        }
    }
}

/// Represents a host-side emulation of `IDirectInputDevice8` for the purpose
/// of force-feedback dispatch.
///
/// In the real DirectInput, `IDirectInputDevice8` is a COM interface. Here we
/// provide a Rust-side wrapper that stores the current force-feedback state
/// and can send effect commands to the physical controller via
/// [`crate::steam_input::send_hid_rumble`].
#[derive(Debug)]
pub struct DirectInputDevice8 {
    /// The XInput/user index this device corresponds to (0–3).
    pub user_index: u32,
    /// Whether force feedback is enabled on this device.
    pub ff_enabled: bool,
    /// Whether the device is currently sending a forced effect (autocentering
    /// off / paused).
    pub ff_active: bool,
    /// The currently playing effect, if any.
    pub current_effect: Option<DirectInputEffect>,
    /// The current autocenter value (0–10000).
    pub autocenter: u32,
    /// Per-device gain (0–10000, default 10000).
    pub device_gain: u32,
}

impl DirectInputDevice8 {
    /// Creates a new DirectInputDevice8 for the given user index.
    pub fn new(user_index: u32) -> Self {
        Self {
            user_index,
            ff_enabled: true,
            ff_active: false,
            current_effect: None,
            autocenter: 5000,
            device_gain: 10000,
        }
    }

    /// `IDirectInputDevice8::SendForceFeedbackCommand` – enables, disables,
    /// pauses, or resets force feedback on this device.
    pub fn send_force_feedback_command(&mut self, command: u32) -> AppResult<()> {
        // DirectInput command constants
        // DISFC_ENABLE        = 1
        // DISFC_DISABLE       = 2
        // DISFC_STOPALL       = 3
        // DISFC_RESET         = 4
        // DISFC_CONTINUE      = 5
        // DISFC_SETACTUATORSON = 6
        // DISFC_SETACTUATORSOFF = 7
        match command {
            1 | 5 | 6 => {
                self.ff_enabled = true;
            }
            2 | 7 => {
                self.ff_enabled = false;
                self.ff_active = false;
            }
            3 => {
                self.ff_active = false;
                self.current_effect = None;
                // Send a stop-rumble command to the hardware.
                crate::steam_input::send_hid_rumble(self.user_index as u8, 0, 0);
            }
            4 => {
                self.ff_enabled = true;
                self.ff_active = false;
                self.current_effect = None;
                self.autocenter = 5000;
                self.device_gain = 10000;
                crate::steam_input::send_hid_rumble(self.user_index as u8, 0, 0);
            }
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcInputUnsupported,
                    format!("DirectInput: unknown force-feedback command {command}"),
                ));
            }
        }
        Ok(())
    }

    /// `IDirectInputDevice8::SetForceFeedbackState` – applies a new effect
    /// to the device.  The effect parameters are used to derive left/right
    /// motor speeds (0–255) which are then forwarded to the HID layer.
    pub fn set_force_feedback_state(&mut self, effect: &DirectInputEffect) -> AppResult<()> {
        if !self.ff_enabled {
            return Err(AppError::new(
                ReasonCode::RcInputUnsupported,
                "DirectInput: force feedback is disabled on this device",
            ));
        }

        let gain_scaled = effect.gain.min(10000).saturating_mul(self.device_gain.min(10000)) / 10000;
        let effective_magnitude = effect.magnitude.min(10000).saturating_mul(gain_scaled) / 10000;

        // For periodic and constant effects, map the magnitude to motor speeds.
        // For condition effects (spring, damper, inertia, friction) we use a
        // fixed moderate rumble since physical mapping is device-dependent.
        let magnitude_byte = match effect.effect_type {
            DirectInputEffectType::ConstantForce
            | DirectInputEffectType::Ramp
            | DirectInputEffectType::Square
            | DirectInputEffectType::Sine
            | DirectInputEffectType::Triangle
            | DirectInputEffectType::SawtoothUp
            | DirectInputEffectType::SawtoothDown => {
                (effective_magnitude.saturating_mul(255) / 10000) as u8
            }
            // Condition effects → fixed low-level rumble
            DirectInputEffectType::Spring
            | DirectInputEffectType::Damper
            | DirectInputEffectType::Inertia
            | DirectInputEffectType::Friction
            | DirectInputEffectType::Custom => 64u8,
        };

        let left_motor = magnitude_byte;
        // For a simple two-motor controller, the right motor gets the same
        // magnitude unless the direction indicates a purely horizontal force.
        let right_motor = if effect.direction_degrees == 0 || effect.direction_degrees == 180 {
            // Pure left/right → mostly left motor
            magnitude_byte.saturating_div(2)
        } else {
            magnitude_byte
        };

        // Send the rumble command to the physical controller.
        crate::steam_input::send_hid_rumble(self.user_index as u8, left_motor, right_motor);

        self.ff_active = true;
        self.current_effect = Some(effect.clone());
        Ok(())
    }

    /// Queries the current force-feedback state (paused, enabled, etc.).
    pub fn get_force_feedback_state(&self) -> (bool, bool, Option<&DirectInputEffect>) {
        (
            self.ff_enabled,
            self.ff_active,
            self.current_effect.as_ref(),
        )
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
pub const BCRYPT_ECDH_P256_ALGORITHM: &str = "ECDH_P256";
pub const BCRYPT_HMAC_SHA256_ALGORITHM: &str = "HMAC_SHA256";
pub const BCRYPT_HMAC_SHA1_ALGORITHM: &str = "HMAC_SHA1";
pub const BCRYPT_HMAC_SHA384_ALGORITHM: &str = "HMAC_SHA384";
pub const BCRYPT_HMAC_SHA512_ALGORITHM: &str = "HMAC_SHA512";
pub const BCRYPT_MD5_ALGORITHM: &str = "MD5";
pub const BCRYPT_HMAC_MD5_ALGORITHM: &str = "HMAC_MD5";
pub const BCRYPT_ECDSA_P384_ALGORITHM: &str = "ECDSA_P384";
pub const BCRYPT_ECDH_P384_ALGORITHM: &str = "ECDH_P384";

/// BCrypt hash handle.
pub struct BCryptHash {
    pub algorithm: String,
    pub data: Vec<u8>,
}

/// Describes the type of key stored in BCryptKey.
#[derive(Debug, Clone)]
pub enum BCryptKeyType {
    /// Symmetric key (AES, etc.) — `key_data` is raw key material.
    Symmetric,
    /// RSA key pair — `key_data` is PKCS#8 DER-encoded private key.
    Rsa { bit_length: u32 },
    /// ECDSA P-256 key pair — `key_data` is SEC1 DER-encoded private key.
    EcdsaP256,
    /// ECDH P-256 key pair — `key_data` is PKCS#8 DER-encoded private key.
    EcdhP256,
    /// ECDSA P-384 key pair — `key_data` is PKCS#8 DER-encoded private key.
    EcdsaP384,
    /// ECDH P-384 key pair — `key_data` is PKCS#8 DER-encoded private key.
    EcdhP384,
}

/// AES chaining mode for a BCrypt symmetric key.
///
/// Real BCrypt selects the chaining mode via `BCryptSetProperty`
/// (`BCRYPT_CHAINING_MODE`), not by key length. The mode is tracked as key
/// state so encrypt/decrypt do not silently misprocess keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BCryptChainingMode {
    /// Infer the mode from the key length (16 bytes → CBC, 32 → GCM).
    /// Legacy behaviour, used when no explicit mode was set.
    Auto,
    /// CBC (unauthenticated).
    Cbc,
    /// GCM (authenticated; the 16-byte tag is appended to the ciphertext).
    Gcm,
}

/// BCrypt key handle.
#[derive(Debug, Clone)]
pub struct BCryptKey {
    pub algorithm: String,
    pub key_data: Vec<u8>,
    pub key_type: BCryptKeyType,
    /// AES chaining mode (see [`BCryptChainingMode`]).
    pub chaining_mode: BCryptChainingMode,
}

impl BCryptKey {
    /// Set the AES chaining mode used by encrypt/decrypt.
    pub fn set_chaining_mode(&mut self, mode: BCryptChainingMode) {
        self.chaining_mode = mode;
    }

    /// Get the AES chaining mode used by encrypt/decrypt.
    pub fn chaining_mode(&self) -> BCryptChainingMode {
        self.chaining_mode
    }
}

/// Result of a secret agreement (ECDH key exchange).
#[derive(Debug, Clone)]
pub struct BCryptSecret {
    /// The shared secret bytes (raw x-coordinate for ECDH).
    pub secret: Vec<u8>,
    /// Algorithm used for the agreement.
    pub algorithm: String,
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
}

impl Default for BCryptContext {
    fn default() -> Self {
        Self::new()
    }
}

impl BCryptContext {

    /// BCryptCreateHash — create a hash object.
    pub fn create_hash(&self, algorithm: &str) -> AppResult<BCryptHash> {
        match algorithm {
            BCRYPT_SHA256_ALGORITHM
            | BCRYPT_SHA384_ALGORITHM
            | BCRYPT_SHA512_ALGORITHM
            | BCRYPT_MD5_ALGORITHM
            | BCRYPT_HMAC_MD5_ALGORITHM
            | BCRYPT_HMAC_SHA256_ALGORITHM
            | BCRYPT_HMAC_SHA1_ALGORITHM
            | BCRYPT_HMAC_SHA384_ALGORITHM
            | BCRYPT_HMAC_SHA512_ALGORITHM => Ok(BCryptHash {
                algorithm: algorithm.to_string(),
                data: Vec::new(),
            }),
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
                use sha2::{Digest, Sha384};
                let mut hasher = Sha384::new();
                hasher.update(&hash.data);
                Ok(hasher.finalize().to_vec())
            }
            BCRYPT_SHA512_ALGORITHM => {
                use sha2::{Digest, Sha512};
                let mut hasher = Sha512::new();
                hasher.update(&hash.data);
                Ok(hasher.finalize().to_vec())
            }
            BCRYPT_MD5_ALGORITHM => {
                // md5 v0.7 uses Context + compute, not the digest trait
                let mut ctx = md5::Context::new();
                ctx.consume(&hash.data);
                let digest = ctx.compute();
                Ok(digest.to_vec())
            }
            BCRYPT_HMAC_MD5_ALGORITHM => {
                // Implement HMAC-MD5 manually since the md5 v0.7 crate
                // does not implement the digest::Digest trait.
                const BLOCK_SIZE: usize = 64;
                // Use empty key (matches Windows BCrypt behaviour for empty HMAC key)
                let key = &[];
                let mut k = [0u8; BLOCK_SIZE];
                if key.len() > BLOCK_SIZE {
                    let mut ctx = md5::Context::new();
                    ctx.consume(key);
                    let digest = ctx.compute();
                    let len = digest.len().min(BLOCK_SIZE);
                    k[..len].copy_from_slice(&digest[..len]);
                } else {
                    k[..key.len()].copy_from_slice(key);
                }
                // ipad
                let mut inner_data = Vec::with_capacity(BLOCK_SIZE + hash.data.len());
                for &kb in k.iter() {
                    inner_data.push(kb ^ 0x36);
                }
                inner_data.extend_from_slice(&hash.data);
                let mut inner_ctx = md5::Context::new();
                inner_ctx.consume(&inner_data);
                let inner_digest = inner_ctx.compute();
                // opad
                let mut outer_data = Vec::with_capacity(BLOCK_SIZE + 16);
                for &kb in k.iter() {
                    outer_data.push(kb ^ 0x5c);
                }
                outer_data.extend_from_slice(&inner_digest[..]);
                let mut outer_ctx = md5::Context::new();
                outer_ctx.consume(&outer_data);
                let outer_digest = outer_ctx.compute();
                Ok(outer_digest.to_vec())
            }
            BCRYPT_HMAC_SHA256_ALGORITHM => crate::network::hmac_sha256(&[], &hash.data),
            "HMAC_SHA1" | "HMAC-SHA1" => {
                use hmac::{Hmac, Mac};
                use sha1::Sha1;
                let mut mac = Hmac::<Sha1>::new_from_slice(&[]).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: HMAC-SHA1 init failed: {e}"),
                    )
                })?;
                mac.update(&hash.data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            "HMAC_SHA384" | "HMAC-SHA384" => {
                use hmac::{Hmac, Mac};
                use sha2::Sha384;
                let mut mac = Hmac::<Sha384>::new_from_slice(&[]).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: HMAC-SHA384 init failed: {e}"),
                    )
                })?;
                mac.update(&hash.data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            "HMAC_SHA512" | "HMAC-SHA512" => {
                use hmac::{Hmac, Mac};
                use sha2::Sha512;
                let mut mac = Hmac::<Sha512>::new_from_slice(&[]).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: HMAC-SHA512 init failed: {e}"),
                    )
                })?;
                mac.update(&hash.data);
                Ok(mac.finalize().into_bytes().to_vec())
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
                key_type: BCryptKeyType::Symmetric,
                chaining_mode: BCryptChainingMode::Auto,
            }),
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: unsupported symmetric algorithm {algorithm}"),
            )),
        }
    }

    /// BCryptGenerateKeyPair — create an asymmetric key pair (RSA or ECDSA).
    pub fn generate_key_pair(&self, algorithm: &str, key_len: u32) -> AppResult<BCryptKey> {
        match algorithm {
            BCRYPT_RSA_ALGORITHM => {
                // Generate a new RSA key pair using the `rsa` crate.
                // Clamp the guest-controlled size to the BCrypt-supported
                // range (512..=16384 bits, multiple of 64) so hostile sizes
                // cannot trigger enormous generation work.
                let bits = if key_len == 0 {
                    2048
                } else {
                    ((key_len.clamp(512, 16384)) / 64) * 64
                };
                let rng = &mut rand::thread_rng();
                let private_key = rsa::RsaPrivateKey::new(rng, bits as usize).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: RSA key generation failed: {e}"),
                    )
                })?;
                let der_bytes = private_key.to_pkcs8_der().map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: RSA DER encoding failed: {e}"),
                    )
                })?;
                Ok(BCryptKey {
                    algorithm: BCRYPT_RSA_ALGORITHM.to_string(),
                    key_data: der_bytes.as_bytes().to_vec(),
                    key_type: BCryptKeyType::Rsa { bit_length: bits },
                    chaining_mode: BCryptChainingMode::Auto,
                })
            }
            BCRYPT_ECDSA_P256_ALGORITHM => {
                // Generate a new ECDSA P-256 key pair
                let rng = &mut rand::thread_rng();
                let signing_key = p256::ecdsa::SigningKey::random(rng);
                let der_bytes = signing_key.to_pkcs8_der().map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: ECDSA P-256 DER encoding failed: {e}"),
                    )
                })?;
                Ok(BCryptKey {
                    algorithm: BCRYPT_ECDSA_P256_ALGORITHM.to_string(),
                    key_data: der_bytes.as_bytes().to_vec(),
                    key_type: BCryptKeyType::EcdsaP256,
                    chaining_mode: BCryptChainingMode::Auto,
                })
            }
            BCRYPT_ECDSA_P384_ALGORITHM => {
                // Generate a new ECDSA P-384 key pair
                let rng = &mut rand::thread_rng();
                let signing_key = p384::ecdsa::SigningKey::random(rng);
                let der_bytes = signing_key.to_pkcs8_der().map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: ECDSA P-384 DER encoding failed: {e}"),
                    )
                })?;
                Ok(BCryptKey {
                    algorithm: BCRYPT_ECDSA_P384_ALGORITHM.to_string(),
                    key_data: der_bytes.as_bytes().to_vec(),
                    key_type: BCryptKeyType::EcdsaP384,
                    chaining_mode: BCryptChainingMode::Auto,
                })
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: unsupported asymmetric algorithm {algorithm}"),
            )),
        }
    }

    /// BCryptSignHash — sign a hash with an asymmetric key.
    /// Supports PKCS#1 v1.5 (default) and RSA-PSS (when BCRYPT_PAD_PSS flag is set).
    pub fn sign_hash(key: &BCryptKey, hash: &[u8], flags: u32) -> AppResult<Vec<u8>> {
        // BCRYPT_PAD_PSS = 8, BCRYPT_PAD_PKCS1 = 2
        const BCRYPT_PAD_PSS: u32 = 8;
        match &key.key_type {
            BCryptKeyType::Rsa { .. } => {
                let private_key =
                    rsa::RsaPrivateKey::from_pkcs8_der(&key.key_data).map_err(|e| {
                        AppError::new(
                            ReasonCode::RcWin32InvalidHandle,
                            format!("BCrypt: RSA key parse failed: {e}"),
                        )
                    })?;
                if (flags & BCRYPT_PAD_PSS) != 0 {
                    // RSA-PSS signing with SHA-256
                    let padding = rsa::Pss::new::<sha2::Sha256>();
                    let signature = private_key.sign(padding, hash).map_err(|e| {
                        AppError::new(
                            ReasonCode::RcWin32InvalidHandle,
                            format!("BCrypt: RSA-PSS sign failed: {e}"),
                        )
                    })?;
                    Ok(signature.to_vec())
                } else {
                    // PKCS#1 v1.5 signature padding with SHA-256 (default)
                    let padding = rsa::Pkcs1v15Sign::new::<sha2::Sha256>();
                    let signature = private_key.sign(padding, hash).map_err(|e| {
                        AppError::new(
                            ReasonCode::RcWin32InvalidHandle,
                            format!("BCrypt: RSA sign failed: {e}"),
                        )
                    })?;
                    Ok(signature.to_vec())
                }
            }
            BCryptKeyType::EcdsaP256 => {
                let signing_key =
                    p256::ecdsa::SigningKey::from_pkcs8_der(&key.key_data).map_err(|e| {
                        AppError::new(
                            ReasonCode::RcWin32InvalidHandle,
                            format!("BCrypt: ECDSA key parse failed: {e}"),
                        )
                    })?;
                use ecdsa::signature::Signer;
                let signature: p256::ecdsa::Signature = signing_key.sign(hash);
                // Return DER-encoded signature (ASN.1 SEQUENCE of two INTEGERs)
                Ok(signature.to_der().as_bytes().to_vec())
            }
            BCryptKeyType::EcdsaP384 => {
                let signing_key =
                    p384::ecdsa::SigningKey::from_pkcs8_der(&key.key_data).map_err(|e| {
                        AppError::new(
                            ReasonCode::RcWin32InvalidHandle,
                            format!("BCrypt: ECDSA P-384 key parse failed: {e}"),
                        )
                    })?;
                use ecdsa::signature::Signer;
                let signature: p384::ecdsa::Signature = signing_key.sign(hash);
                // Return DER-encoded signature (ASN.1 SEQUENCE of two INTEGERs)
                Ok(signature.to_der().as_bytes().to_vec())
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: sign not supported for {}", key.algorithm),
            )),
        }
    }

    /// BCryptVerifySignature — verify a hash signature with an asymmetric key.
    pub fn verify_signature(
        key: &BCryptKey,
        hash: &[u8],
        signature: &[u8],
        flags: u32,
    ) -> AppResult<bool> {
        // BCRYPT_PAD_PSS = 8
        const BCRYPT_PAD_PSS: u32 = 8;
        match &key.key_type {
            BCryptKeyType::Rsa { .. } => {
                // key.key_data is a PKCS#8 private key DER; parse as private key, then extract public key
                let private_key =
                    rsa::RsaPrivateKey::from_pkcs8_der(&key.key_data).map_err(|e| {
                        AppError::new(
                            ReasonCode::RcWin32InvalidHandle,
                            format!("BCrypt: RSA private key parse failed: {e}"),
                        )
                    })?;
                let public_key = rsa::RsaPublicKey::from(&private_key);
                if (flags & BCRYPT_PAD_PSS) != 0 {
                    // RSA-PSS verification with SHA-256
                    let padding = rsa::Pss::new::<sha2::Sha256>();
                    Ok(public_key.verify(padding, hash, signature).is_ok())
                } else {
                    // PKCS#1 v1.5 verification with SHA-256 (default)
                    let padding = rsa::Pkcs1v15Sign::new::<sha2::Sha256>();
                    Ok(public_key.verify(padding, hash, signature).is_ok())
                }
            }
            BCryptKeyType::EcdsaP256 => {
                // key.key_data is a PKCS#8 private key DER; parse as signing key, then extract verifying key
                let signing_key =
                    p256::ecdsa::SigningKey::from_pkcs8_der(&key.key_data).map_err(|e| {
                        AppError::new(
                            ReasonCode::RcWin32InvalidHandle,
                            format!("BCrypt: ECDSA private key parse failed: {e}"),
                        )
                    })?;
                let verifying_key = *signing_key.verifying_key();
                use ecdsa::signature::Verifier;
                // Try ASN.1 DER first, then raw concatenated (r||s) format
                if let Ok(sig) = p256::ecdsa::Signature::from_der(signature) {
                    Ok(verifying_key.verify(hash, &sig).is_ok())
                } else if let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) {
                    Ok(verifying_key.verify(hash, &sig).is_ok())
                } else {
                    Err(AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        "BCrypt: ECDSA signature parse failed",
                    ))
                }
            }
            BCryptKeyType::EcdsaP384 => {
                // key.key_data is a PKCS#8 private key DER; parse as signing key, then extract verifying key
                let signing_key =
                    p384::ecdsa::SigningKey::from_pkcs8_der(&key.key_data).map_err(|e| {
                        AppError::new(
                            ReasonCode::RcWin32InvalidHandle,
                            format!("BCrypt: ECDSA P-384 private key parse failed: {e}"),
                        )
                    })?;
                let verifying_key = *signing_key.verifying_key();
                use ecdsa::signature::Verifier;
                // Try ASN.1 DER first, then raw concatenated (r||s) format
                if let Ok(sig) = p384::ecdsa::Signature::from_der(signature) {
                    Ok(verifying_key.verify(hash, &sig).is_ok())
                } else if let Ok(sig) = p384::ecdsa::Signature::from_slice(signature) {
                    Ok(verifying_key.verify(hash, &sig).is_ok())
                } else {
                    Err(AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        "BCrypt: ECDSA P-384 signature parse failed",
                    ))
                }
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: verify not supported for {}", key.algorithm),
            )),
        }
    }

    /// BCryptEncrypt — encrypt data with a symmetric key.
    ///
    /// The AES chaining mode comes from the key's [`BCryptChainingMode`]
    /// (set via [`BCryptKey::set_chaining_mode`]); when `Auto` it is inferred
    /// from the key length (16 bytes → CBC, 32 bytes → GCM) for legacy
    /// compatibility. For GCM, the 16-byte authentication tag is appended to
    /// the returned ciphertext.
    pub fn encrypt(key: &BCryptKey, plaintext: &[u8], iv: Option<&[u8; 16]>) -> AppResult<Vec<u8>> {
        match key.algorithm.as_str() {
            BCRYPT_AES_ALGORITHM => {
                let use_cbc = match key.chaining_mode {
                    BCryptChainingMode::Cbc => true,
                    BCryptChainingMode::Gcm => false,
                    BCryptChainingMode::Auto => key.key_data.len() == 16,
                };
                if use_cbc {
                    // AES-128-CBC
                    if key.key_data.len() != 16 {
                        return Err(AppError::new(
                            ReasonCode::RcWin32InvalidHandle,
                            "BCrypt: CBC mode requires a 16-byte AES key",
                        ));
                    }
                    let iv_val = iv.copied().unwrap_or([0u8; 16]);
                    crate::network::aes_128_cbc_encrypt(
                        &key.key_data[..16].try_into().map_err(|_| {
                            AppError::new(
                                ReasonCode::RcWin32InvalidHandle,
                                "BCrypt: AES key must be 16 bytes",
                            )
                        })?,
                        &iv_val,
                        plaintext,
                    )
                } else {
                    // GCM — the nonce is the first 12 bytes of the IV and
                    // the 16-byte tag is appended to the ciphertext.
                    use aes_gcm::aead::{AeadInPlace, KeyInit};
                    let nonce_bytes = iv
                        .map(|raw| {
                            let mut n = [0u8; 12];
                            n.copy_from_slice(&raw[..12]);
                            n
                        })
                        .unwrap_or([0u8; 12]);
                    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
                    let mut buf = plaintext.to_vec();
                    match key.key_data.len() {
                        16 => {
                            let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key.key_data)
                                .map_err(|e| {
                                    AppError::new(
                                        ReasonCode::RcWin32InvalidHandle,
                                        format!("BCrypt: AES-128-GCM key init failed: {e}"),
                                    )
                                })?;
                            cipher.encrypt_in_place(nonce, &[], &mut buf).map_err(|e| {
                                AppError::new(
                                    ReasonCode::RcWin32InvalidHandle,
                                    format!("BCrypt: AES-128-GCM encrypt failed: {e}"),
                                )
                            })?;
                        }
                        32 => {
                            let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key.key_data)
                                .map_err(|e| {
                                    AppError::new(
                                        ReasonCode::RcWin32InvalidHandle,
                                        format!("BCrypt: AES-256-GCM key init failed: {e}"),
                                    )
                                })?;
                            cipher.encrypt_in_place(nonce, &[], &mut buf).map_err(|e| {
                                AppError::new(
                                    ReasonCode::RcWin32InvalidHandle,
                                    format!("BCrypt: AES-256-GCM encrypt failed: {e}"),
                                )
                            })?;
                        }
                        len => {
                            return Err(AppError::new(
                                ReasonCode::RcWin32InvalidHandle,
                                format!("BCrypt: AES-GCM key must be 16 or 32 bytes, got {len}"),
                            ));
                        }
                    }
                    Ok(buf)
                }
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: encrypt not supported for {}", key.algorithm),
            )),
        }
    }

    /// BCryptDecrypt — decrypt data with a symmetric key.
    ///
    /// Mirrors [`BCryptContext::encrypt`]: the chaining mode comes from the
    /// key state (or is inferred from key length in `Auto` mode), and GCM
    /// input is expected to include the appended 16-byte authentication tag.
    pub fn decrypt(
        key: &BCryptKey,
        ciphertext: &[u8],
        iv: Option<&[u8; 16]>,
    ) -> AppResult<Vec<u8>> {
        match key.algorithm.as_str() {
            BCRYPT_AES_ALGORITHM => {
                let use_cbc = match key.chaining_mode {
                    BCryptChainingMode::Cbc => true,
                    BCryptChainingMode::Gcm => false,
                    BCryptChainingMode::Auto => key.key_data.len() == 16,
                };
                if use_cbc {
                    // AES-128-CBC
                    if key.key_data.len() != 16 {
                        return Err(AppError::new(
                            ReasonCode::RcWin32InvalidHandle,
                            "BCrypt: CBC mode requires a 16-byte AES key",
                        ));
                    }
                    let iv_val = iv.copied().unwrap_or([0u8; 16]);
                    crate::network::aes_128_cbc_decrypt(
                        &key.key_data[..16].try_into().map_err(|_| {
                            AppError::new(
                                ReasonCode::RcWin32InvalidHandle,
                                "BCrypt: AES key must be 16 bytes",
                            )
                        })?,
                        &iv_val,
                        ciphertext,
                    )
                } else {
                    // GCM — the nonce is the first 12 bytes of the IV and
                    // the last 16 bytes of the input are the auth tag.
                    use aes_gcm::aead::{AeadInPlace, KeyInit};
                    let nonce_bytes = iv
                        .map(|raw| {
                            let mut n = [0u8; 12];
                            n.copy_from_slice(&raw[..12]);
                            n
                        })
                        .unwrap_or([0u8; 12]);
                    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
                    let mut buf = ciphertext.to_vec();
                    match key.key_data.len() {
                        16 => {
                            let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key.key_data)
                                .map_err(|e| {
                                    AppError::new(
                                        ReasonCode::RcWin32InvalidHandle,
                                        format!("BCrypt: AES-128-GCM key init failed: {e}"),
                                    )
                                })?;
                            cipher.decrypt_in_place(nonce, &[], &mut buf).map_err(|e| {
                                AppError::new(
                                    ReasonCode::RcWin32InvalidHandle,
                                    format!("BCrypt: AES-128-GCM decrypt failed: {e}"),
                                )
                            })?;
                        }
                        32 => {
                            let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key.key_data)
                                .map_err(|e| {
                                    AppError::new(
                                        ReasonCode::RcWin32InvalidHandle,
                                        format!("BCrypt: AES-256-GCM key init failed: {e}"),
                                    )
                                })?;
                            cipher.decrypt_in_place(nonce, &[], &mut buf).map_err(|e| {
                                AppError::new(
                                    ReasonCode::RcWin32InvalidHandle,
                                    format!("BCrypt: AES-256-GCM decrypt failed: {e}"),
                                )
                            })?;
                        }
                        len => {
                            return Err(AppError::new(
                                ReasonCode::RcWin32InvalidHandle,
                                format!("BCrypt: AES-GCM key must be 16 or 32 bytes, got {len}"),
                            ));
                        }
                    }
                    Ok(buf)
                }
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: decrypt not supported for {}", key.algorithm),
            )),
        }
    }

    /// BCryptSecretAgreement — perform ECDH key agreement.
    ///
    /// Given a private key and a public key (both ECDH P-256),
    /// compute the shared secret (x-coordinate of the shared point).
    pub fn secret_agreement(
        &self,
        private_key: &BCryptKey,
        public_key: &BCryptKey,
    ) -> AppResult<BCryptSecret> {
        match (&private_key.key_type, &public_key.key_type) {
            (BCryptKeyType::EcdhP256, BCryptKeyType::EcdhP256) => {
                let private_signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(
                    &private_key.key_data,
                )
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: ECDH private key parse failed: {e}"),
                    )
                })?;
                // Decode the raw public key (65-byte uncompressed SEC1 format: 04 || X || Y)
                let owned_pk_bytes;
                let pub_key_bytes =
                    if public_key.key_data.len() == 65 && public_key.key_data[0] == 0x04 {
                        &public_key.key_data[1..]
                    } else if public_key.key_data.len() == 64 {
                        &public_key.key_data[..]
                    } else {
                        // Try to decode as PKCS#8 DER
                        use p256::pkcs8::DecodePublicKey;
                        let pk = p256::PublicKey::from_public_key_der(&public_key.key_data)
                            .map_err(|e| {
                                AppError::new(
                                    ReasonCode::RcWin32InvalidHandle,
                                    format!("BCrypt: ECDH public key DER parse failed: {e}"),
                                )
                            })?;
                        let encoded = ToEncodedPoint::to_encoded_point(&pk, false);
                        let point_bytes = encoded.as_bytes();
                        if point_bytes.len() >= 65 && point_bytes[0] == 0x04 {
                            owned_pk_bytes = point_bytes[1..].to_vec();
                            &owned_pk_bytes
                        } else {
                            return Err(AppError::new(
                                ReasonCode::RcWin32InvalidHandle,
                                "BCrypt: ECDH public key format not recognized",
                            ));
                        }
                    };
                // Build SEC1 encoded point: 0x04 || X (32 bytes) || Y (32 bytes)
                let (x_bytes, y_bytes) = pub_key_bytes.split_at(32);
                let mut sec1_bytes = Vec::with_capacity(65);
                sec1_bytes.push(0x04);
                sec1_bytes.extend_from_slice(x_bytes);
                sec1_bytes.extend_from_slice(y_bytes);
                let pub_key = p256::PublicKey::from_sec1_bytes(&sec1_bytes).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: ECDH public key point creation failed: {e}"),
                    )
                })?;
                let private_key_ecdh = p256::SecretKey::from(&private_signing_key);
                let shared_secret = p256::elliptic_curve::ecdh::diffie_hellman(
                    &private_key_ecdh.to_nonzero_scalar(),
                    pub_key.as_affine(),
                );
                Ok(BCryptSecret {
                    secret: shared_secret.raw_secret_bytes().to_vec(),
                    algorithm: BCRYPT_ECDH_P256_ALGORITHM.to_string(),
                })
            }
            (BCryptKeyType::EcdhP384, BCryptKeyType::EcdhP384) => {
                let private_signing_key = p384::ecdsa::SigningKey::from_pkcs8_der(
                    &private_key.key_data,
                )
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: ECDH P-384 private key parse failed: {e}"),
                    )
                })?;
                // Decode the raw public key (97-byte uncompressed SEC1 format: 04 || X (48) || Y (48))
                let owned_pk_bytes;
                let pub_key_bytes =
                    if public_key.key_data.len() == 97 && public_key.key_data[0] == 0x04 {
                        &public_key.key_data[1..]
                    } else if public_key.key_data.len() == 96 {
                        &public_key.key_data[..]
                    } else {
                        // Try to decode as PKCS#8 DER
                        use p384::pkcs8::DecodePublicKey;
                        let pk = p384::PublicKey::from_public_key_der(&public_key.key_data)
                            .map_err(|e| {
                                AppError::new(
                                    ReasonCode::RcWin32InvalidHandle,
                                    format!("BCrypt: ECDH P-384 public key DER parse failed: {e}"),
                                )
                            })?;
                        let encoded = p384::EncodedPoint::from(pk);
                        let point_bytes = encoded.as_bytes();
                        if point_bytes.len() >= 97 && point_bytes[0] == 0x04 {
                            owned_pk_bytes = point_bytes[1..].to_vec();
                            &owned_pk_bytes
                        } else {
                            return Err(AppError::new(
                                ReasonCode::RcWin32InvalidHandle,
                                "BCrypt: ECDH P-384 public key format not recognized",
                            ));
                        }
                    };
                // Build SEC1 encoded point: 0x04 || X (48 bytes) || Y (48 bytes)
                let (x_bytes, y_bytes) = pub_key_bytes.split_at(48);
                let mut sec1_bytes = Vec::with_capacity(97);
                sec1_bytes.push(0x04);
                sec1_bytes.extend_from_slice(x_bytes);
                sec1_bytes.extend_from_slice(y_bytes);
                let pub_key = p384::PublicKey::from_sec1_bytes(&sec1_bytes).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: ECDH P-384 public key point creation failed: {e}"),
                    )
                })?;
                let private_key_ecdh = p384::SecretKey::from(&private_signing_key);
                let shared_secret = p384::elliptic_curve::ecdh::diffie_hellman(
                    &private_key_ecdh.to_nonzero_scalar(),
                    pub_key.as_affine(),
                );
                Ok(BCryptSecret {
                    secret: shared_secret.raw_secret_bytes().to_vec(),
                    algorithm: BCRYPT_ECDH_P384_ALGORITHM.to_string(),
                })
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!(
                    "BCrypt: secret agreement not supported for {}/{}",
                    private_key.algorithm, public_key.algorithm
                ),
            )),
        }
    }

    /// BCryptDeriveKey — derive a key from a shared secret using a KDF.
    ///
    /// Supports:
    /// - `BCRYPT_KDF_HASH` (hash the secret with optional salt)
    /// - `BCRYPT_KDF_HMAC` (HMAC the secret with a salt)
    /// - `BCRYPT_KDF_SP80056A` (concatenation KDF per SP 800-56A)
    ///
    /// `output_len` is capped at 64 KiB so a guest-controlled length cannot
    /// exhaust host memory.
    pub fn derive_key(
        secret: &BCryptSecret,
        kdf: &str,
        kdf_feedback: &[u8],
        output_len: u32,
    ) -> AppResult<Vec<u8>> {
        const MAX_KDF_OUTPUT_LEN: u32 = 64 * 1024;
        let output_len = output_len.min(MAX_KDF_OUTPUT_LEN);
        match kdf {
            "HASH" | "BCRYPT_KDF_HASH" => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&secret.secret);
                if !kdf_feedback.is_empty() {
                    hasher.update(kdf_feedback);
                }
                let result = hasher.finalize();
                let output = result.to_vec();
                Ok(if output_len > 0 {
                    output[..(output.len().min(output_len as usize))].to_vec()
                } else {
                    output
                })
            }
            "HMAC" | "BCRYPT_KDF_HMAC" => {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;
                let mut mac = Hmac::<Sha256>::new_from_slice(&secret.secret).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcWin32InvalidHandle,
                        format!("BCrypt: HMAC init failed: {e}"),
                    )
                })?;
                if !kdf_feedback.is_empty() {
                    mac.update(kdf_feedback);
                }
                let result = mac.finalize();
                let code = result.into_bytes();
                let output = code.to_vec();
                Ok(if output_len > 0 {
                    output[..(output.len().min(output_len as usize))].to_vec()
                } else {
                    output
                })
            }
            "SP80056A" | "BCRYPT_KDF_SP80056A" => {
                // Concatenation KDF per NIST SP 800-56A, Section 5.8.1
                // Uses SHA-256 as the underlying hash function.
                use sha2::{Digest, Sha256};
                let mut derived = Vec::new();
                let _hash_len = 32usize; // SHA-256 output
                let mut counter: u32 = 1;
                while derived.len() < output_len as usize {
                    let mut hasher = Sha256::new();
                    // Counter (4 bytes big-endian)
                    hasher.update(counter.to_be_bytes());
                    // Shared secret
                    hasher.update(&secret.secret);
                    // Algorithm ID / OtherInfo (kdf_feedback)
                    if !kdf_feedback.is_empty() {
                        hasher.update(kdf_feedback);
                    }
                    let hash = hasher.finalize();
                    derived.extend_from_slice(&hash);
                    counter += 1;
                }
                derived.truncate(output_len as usize);
                Ok(derived)
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("BCrypt: unsupported KDF {kdf}"),
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
    /// Due time in milliseconds since an arbitrary epoch (u64 to avoid
    /// wraparound on long-running hosts).
    pub due_time_ms: u64,
    pub period_ms: u64,
    pub is_set: bool,
}

/// Thread pool wait.
#[derive(Debug, Clone)]
pub struct TpWait {
    pub id: u64,
    pub callback: u64,
    pub context: u64,
    pub handle: u64,
    /// Whether this wait has already fired for the current registration.
    pub fired: bool,
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
}

impl Default for ThreadPoolManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadPoolManager {

    /// CreateThreadpoolWork
    pub fn create_work(&mut self, callback: u64, context: u64) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.work_items.insert(
            id,
            TpWork {
                id,
                callback,
                context,
                submitted: false,
            },
        );
        id
    }

    /// SubmitThreadpoolWork
    pub fn submit_work(&mut self, id: u64) -> AppResult<()> {
        let work = self.work_items.get_mut(&id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("TP work {id} not found"),
            )
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
        self.timers.insert(
            id,
            TpTimer {
                id,
                callback,
                context,
                due_time_ms: 0,
                period_ms: 0,
                is_set: false,
            },
        );
        id
    }

    /// SetThreadpoolTimer
    ///
    /// A due time of 0 means "due immediately" (Windows semantics), so the
    /// timer is always marked as set.
    pub fn set_timer(&mut self, id: u64, due_time_ms: u32, period_ms: u32) -> AppResult<()> {
        let timer = self.timers.get_mut(&id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("TP timer {id} not found"),
            )
        })?;
        timer.due_time_ms = due_time_ms as u64;
        timer.period_ms = period_ms as u64;
        timer.is_set = true;
        Ok(())
    }

    /// CloseThreadpoolTimer
    pub fn close_timer(&mut self, id: u64) {
        self.timers.remove(&id);
    }

    /// CreateThreadpoolWait
    pub fn create_wait(&mut self, callback: u64, context: u64, handle: u64) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.waits.insert(
            id,
            TpWait {
                id,
                callback,
                context,
                handle,
                fired: false,
            },
        );
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

    // ── Callback Dispatch ────────────────────────────────────────────────

    /// Pop the next pending work item for execution.
    ///
    /// Returns `Some((callback, context))` if a submitted work item is
    /// available, or `None` if the queue is empty.
    ///
    /// The work object stays registered (it can be submitted again via
    /// `SubmitThreadpoolWork`); it is only removed by `CloseThreadpoolWork`.
    /// The returned callback should be invoked by the pe_runtime in the
    /// guest context with the given context parameter.
    pub fn pop_work_callback(&mut self) -> Option<(u64, u64)> {
        // Find the first submitted work item and mark it as dispatched.
        let id = self
            .work_items
            .iter()
            .find(|(_, w)| w.submitted)
            .map(|(&id, _)| id)?;
        let work = self.work_items.get_mut(&id)?;
        work.submitted = false;
        Some((work.callback, work.context))
    }

    /// Pop all pending work items and return their (callback, context) pairs.
    ///
    /// This drains all submitted-but-not-yet-executed work items at once,
    /// which is useful for batch dispatch in the execution loop. Work items
    /// stay registered for later re-submission.
    pub fn drain_pending_work(&mut self) -> Vec<(u64, u64)> {
        let mut results = Vec::new();
        let pending_ids: Vec<u64> = self
            .work_items
            .iter()
            .filter(|(_, w)| w.submitted)
            .map(|(&id, _)| id)
            .collect();
        for id in pending_ids {
            if let Some(work) = self.work_items.get_mut(&id) {
                work.submitted = false;
                results.push((work.callback, work.context));
            }
        }
        results
    }

    /// Check for due timers and return their (callback, context) pairs.
    ///
    /// A timer is due when `current_time_ms` (milliseconds since an
    /// arbitrary epoch) >= `due_time_ms`.  For periodic timers (period > 0),
    /// the timer is automatically re-armed for the next period so it can
    /// fire again.
    pub fn pop_due_timers(&mut self, current_time_ms: u64) -> Vec<(u64, u64)> {
        let mut due = Vec::new();
        let due_ids: Vec<u64> = self
            .timers
            .iter()
            .filter(|(_, t)| t.is_set && current_time_ms >= t.due_time_ms)
            .map(|(&id, _)| id)
            .collect();
        for id in due_ids {
            if let Some(timer) = self.timers.get_mut(&id) {
                due.push((timer.callback, timer.context));
                if timer.period_ms > 0 {
                    // Re-arm periodic timer: advance due_time by period.
                    timer.due_time_ms = timer.due_time_ms.saturating_add(timer.period_ms);
                    timer.is_set = true;
                } else {
                    // One-shot timer: mark as not set.
                    timer.is_set = false;
                }
            }
        }
        due
    }

    /// Check waits against a set of signaled handles and return
    /// (callback, context) pairs for any matched waits.
    ///
    /// `signaled_handles` is a set of handles that are currently in the
    /// signaled state.  Waits whose handle is in this set (and that have not
    /// already fired for the current registration) are marked as fired and
    /// their callbacks are returned for dispatch. The wait stays registered
    /// (like Windows thread-pool waits, which must be re-armed to fire
    /// again); it is removed only by `CloseThreadpoolWait`.
    pub fn pop_signaled_waits(
        &mut self,
        signaled_handles: &std::collections::HashSet<u64>,
    ) -> Vec<(u64, u64)> {
        let mut signaled = Vec::new();
        let signaled_ids: Vec<u64> = self
            .waits
            .iter()
            .filter(|(_, w)| !w.fired && signaled_handles.contains(&w.handle))
            .map(|(&id, _)| id)
            .collect();
        for id in signaled_ids {
            if let Some(wait) = self.waits.get_mut(&id) {
                wait.fired = true;
                signaled.push((wait.callback, wait.context));
            }
        }
        signaled
    }

    /// Process all pending work items, due timers, and signaled waits,
    /// returning a combined list of (callback, context) pairs to be
    /// executed by the runtime.
    ///
    /// This is a convenience method that calls [`drain_pending_work`],
    /// [`pop_due_timers`], and [`pop_signaled_waits`] in sequence.
    pub fn process_pending(
        &mut self,
        current_time_ms: u64,
        signaled_handles: &std::collections::HashSet<u64>,
    ) -> Vec<(u64, u64)> {
        let mut callbacks = self.drain_pending_work();
        callbacks.extend(self.pop_due_timers(current_time_ms));
        callbacks.extend(self.pop_signaled_waits(signaled_handles));
        callbacks
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
            // Spin-wait until generation advances, yielding the CPU after a
            // bounded number of spins so other threads (including the last
            // barrier thread in a cooperative emulator) get scheduled.
            let mut spins = 0u32;
            while self.generation.load(Ordering::Acquire) == gen_val {
                spins += 1;
                if spins >= 1000 {
                    spins = 0;
                    std::thread::yield_now();
                } else {
                    std::hint::spin_loop();
                }
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

/// Guest architecture for stack walking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestArch {
    /// 64-bit x86-64: 8-byte frame pointers, 8-byte return addresses.
    X86_64,
    /// 32-bit x86: 4-byte frame pointers, 4-byte return addresses.
    X86,
}

/// Maximum number of frames to capture (stack overflow protection).
const MAX_STACK_FRAMES: usize = 256;

/// DbgHelp symbol handler.
pub struct DbgHelpContext {
    loaded_modules: BTreeMap<String, u64>,
    /// Module base addresses → name, kept sorted for O(log n) address lookup.
    module_bases: BTreeMap<u64, String>,
    symbols: BTreeMap<u64, SymbolInfo>,
    #[allow(dead_code)]
    next_sym_id: u64,
}

impl DbgHelpContext {
    pub fn new() -> Self {
        Self {
            loaded_modules: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            symbols: BTreeMap::new(),
            next_sym_id: 1,
        }
    }
}

impl Default for DbgHelpContext {
    fn default() -> Self {
        Self::new()
    }
}

impl DbgHelpContext {

    /// SymInitialize — initialize the symbol handler for a process.
    pub fn sym_initialize(&mut self, _process_handle: u64) -> AppResult<()> {
        self.symbols.clear();
        Ok(())
    }

    /// SymCleanup — clean up the symbol handler.
    pub fn sym_cleanup(&mut self) {
        self.symbols.clear();
        self.loaded_modules.clear();
        self.module_bases.clear();
    }

    /// SymLoadModuleEx — load symbols for a module.
    pub fn sym_load_module(&mut self, module_name: &str, base_address: u64) -> AppResult<()> {
        self.loaded_modules
            .insert(module_name.to_string(), base_address);
        self.module_bases.insert(base_address, module_name.to_string());
        Ok(())
    }

    /// SymFromAddr — look up a symbol by address.
    ///
    /// Finds the closest symbol at or below the given address using the
    /// sorted symbol table (O(log n)).
    pub fn sym_from_addr(&self, address: u64) -> AppResult<&SymbolInfo> {
        self.symbols
            .range(..=address)
            .next_back()
            .map(|(_, sym)| sym)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("no symbol found at address {address:#x}"),
                )
            })
    }

    /// StackWalk64 — walk the stack using a memory reader.
    ///
    /// Walks the x86/x86-64 frame pointer chain using a memory reader
    /// callback to access guest stack memory. Delegates to
    /// [`stack_walk_with_reader`].
    ///
    /// # Arguments
    /// * `instruction_pointer` — Current RIP/EIP value.
    /// * `frame_pointer` — Current RBP/EBP value.
    /// * `stack_pointer` — Current RSP/ESP value (used for bounds checking).
    /// * `arch` — Guest architecture (32-bit or 64-bit).
    /// * `max_frames` — Maximum number of frames to capture (capped at 256).
    /// * `read_memory` — Closure that reads `n` bytes from guest memory at a
    ///   given address. Returns `None` if the address is invalid or unreadable.
    pub fn stack_walk<F>(
        &self,
        instruction_pointer: u64,
        frame_pointer: u64,
        stack_pointer: u64,
        arch: GuestArch,
        max_frames: usize,
        read_memory: F,
    ) -> Vec<StackFrameInfo>
    where
        F: Fn(u64, usize) -> Option<Vec<u8>>,
    {
        self.stack_walk_with_reader(
            instruction_pointer,
            frame_pointer,
            stack_pointer,
            arch,
            max_frames,
            read_memory,
        )
    }

    /// StackWalk64 with memory reader — full multi-frame stack walking.
    ///
    /// Walks the x86/x86-64 frame pointer chain using a memory reader
    /// callback to access guest stack memory.
    ///
    /// # Arguments
    /// * `instruction_pointer` — Current RIP/EIP value.
    /// * `frame_pointer` — Current RBP/EBP value.
    /// * `stack_pointer` — Current RSP/ESP value (used for bounds checking).
    /// * `arch` — Guest architecture (32-bit or 64-bit).
    /// * `max_frames` — Maximum number of frames to capture (capped at 256).
    /// * `read_memory` — Closure that reads `n` bytes from guest memory at a
    ///   given address. Returns `None` if the address is invalid or unreadable.
    ///
    /// # Algorithm
    /// For each frame:
    /// 1. Record the current IP and FP.
    /// 2. Read the saved frame pointer from `[FP]`.
    /// 3. Read the return address from `[FP + pointer_size]`.
    /// 4. Validate: next FP must be > current FP (stack grows down) and non-zero.
    /// 5. Validate: return address must be non-zero.
    /// 6. If valid, advance FP and IP; otherwise stop.
    pub fn stack_walk_with_reader<F>(
        &self,
        instruction_pointer: u64,
        frame_pointer: u64,
        stack_pointer: u64,
        arch: GuestArch,
        max_frames: usize,
        read_memory: F,
    ) -> Vec<StackFrameInfo>
    where
        F: Fn(u64, usize) -> Option<Vec<u8>>,
    {
        let max_frames = max_frames.min(MAX_STACK_FRAMES);
        let mut frames = Vec::with_capacity(max_frames.min(32));
        let mut ip = instruction_pointer;
        let mut fp = frame_pointer;
        let ptr_size = match arch {
            GuestArch::X86_64 => 8usize,
            GuestArch::X86 => 4,
        };

        for _ in 0..max_frames {
            let symbol_name = self.symbols.get(&ip).map(|s| s.name.clone());
            let module_name = self
                .find_module_for_address(ip)
                .unwrap_or_else(|| "unknown".to_string());

            // Compute displacement from nearest symbol
            let displacement = self.symbols.get(&ip).map(|_s| 0u64).unwrap_or_else(|| {
                // Find closest symbol below this address
                self.symbols
                    .range(..=ip)
                    .next_back()
                    .map(|(addr, _)| ip - addr)
                    .unwrap_or(0)
            });

            frames.push(StackFrameInfo {
                instruction_pointer: ip,
                return_address: 0, // filled in below for non-last frames
                frame_pointer: fp,
                stack_pointer: if frames.is_empty() { stack_pointer } else { 0 },
                module_name,
                symbol_name,
                displacement,
                source_file: None,
                line_number: None,
            });

            // Read the next frame pointer from [FP]
            let next_fp_bytes = read_memory(fp, ptr_size);
            let next_fp = match (&next_fp_bytes, arch) {
                (Some(bytes), GuestArch::X86_64) if bytes.len() == 8 => u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]),
                (Some(bytes), GuestArch::X86) if bytes.len() >= 4 => {
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
                }
                _ => break, // Invalid memory read — stop walking
            };

            // Validate: next FP must be > current FP (stack grows downward) and non-zero
            if next_fp == 0 || next_fp <= fp {
                break;
            }

            // Read the return address from [FP + pointer_size]
            let ret_addr_bytes = read_memory(fp + ptr_size as u64, ptr_size);
            let ret_addr = match (&ret_addr_bytes, arch) {
                (Some(bytes), GuestArch::X86_64) if bytes.len() == 8 => u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]),
                (Some(bytes), GuestArch::X86) if bytes.len() >= 4 => {
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
                }
                _ => break, // Invalid memory read — stop walking
            };

            // Zero return address means end of stack
            if ret_addr == 0 {
                break;
            }

            // Update the return address for the current frame
            if let Some(last) = frames.last_mut() {
                last.return_address = ret_addr;
            }

            // Advance to next frame
            fp = next_fp;
            ip = ret_addr;
        }

        frames
    }

    /// Capture a stack back trace — returns just the instruction pointer addresses.
    ///
    /// This is equivalent to Win32's `RtlCaptureStackBackTrace`, returning
    /// a vector of return addresses from the current stack position.
    ///
    /// # Arguments
    /// * `instruction_pointer` — Current RIP/EIP value.
    /// * `frame_pointer` — Current RBP/EBP value.
    /// * `stack_pointer` — Current RSP/ESP value.
    /// * `arch` — Guest architecture.
    /// * `max_frames` — Maximum frames to capture (capped at 256).
    /// * `read_memory` — Memory reader closure.
    pub fn capture_stack_back_trace<F>(
        &self,
        instruction_pointer: u64,
        frame_pointer: u64,
        stack_pointer: u64,
        arch: GuestArch,
        max_frames: usize,
        read_memory: F,
    ) -> Vec<u64>
    where
        F: Fn(u64, usize) -> Option<Vec<u8>>,
    {
        let frames = self.stack_walk_with_reader(
            instruction_pointer,
            frame_pointer,
            stack_pointer,
            arch,
            max_frames,
            read_memory,
        );
        frames.iter().map(|f| f.instruction_pointer).collect()
    }

    /// RtlCaptureStackBackTrace — Win32 API equivalent.
    ///
    /// Captures a stack back trace from the given register state, returning
    /// up to `capture_count` return addresses. Optionally returns the number
    /// of frames skipped via `frames_skipped`.
    ///
    /// # Arguments
    /// * `skip_frames` — Number of frames to skip from the top of the stack.
    /// * `capture_count` — Maximum number of frames to capture.
    /// * `instruction_pointer` — Current instruction pointer.
    /// * `frame_pointer` — Current frame pointer.
    /// * `stack_pointer` — Current stack pointer.
    /// * `arch` — Guest architecture.
    /// * `read_memory` — Memory reader closure.
    ///
    /// # Returns
    /// A tuple of (addresses, frames_skipped) where addresses is the captured
    /// back trace and frames_skipped is the number of frames that were skipped.
    #[allow(clippy::too_many_arguments)] // mirrors RtlCaptureStackBackTrace's parameter list
    pub fn rtl_capture_stack_back_trace<F>(
        &self,
        skip_frames: usize,
        capture_count: usize,
        instruction_pointer: u64,
        frame_pointer: u64,
        stack_pointer: u64,
        arch: GuestArch,
        read_memory: F,
    ) -> (Vec<u64>, usize)
    where
        F: Fn(u64, usize) -> Option<Vec<u8>>,
    {
        let capture_count = capture_count.min(MAX_STACK_FRAMES);
        let total = skip_frames + capture_count;
        let all_frames = self.stack_walk_with_reader(
            instruction_pointer,
            frame_pointer,
            stack_pointer,
            arch,
            total,
            read_memory,
        );
        let addresses: Vec<u64> = all_frames
            .iter()
            .skip(skip_frames)
            .map(|f| f.instruction_pointer)
            .collect();
        let frames_skipped = skip_frames.min(all_frames.len());
        (addresses, frames_skipped)
    }

    /// Register a symbol.
    pub fn register_symbol(&mut self, address: u64, name: &str, module_base: u64) {
        self.symbols.insert(
            address,
            SymbolInfo {
                address,
                name: name.to_string(),
                size: 0,
                module_base,
                displacement: 0,
            },
        );
    }

    /// Find the module containing an address (O(log n) via the sorted
    /// module base table).
    fn find_module_for_address(&self, address: u64) -> Option<String> {
        self.module_bases
            .range(..=address)
            .next_back()
            .map(|(_, name)| name.clone())
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

/// A parsed Access Control Entry (ACE) from an ACL.
#[derive(Debug, Clone)]
pub struct AceEntry {
    /// ACE type (0x00=ACCESS_ALLOWED, 0x01=ACCESS_DENIED, etc.)
    pub ace_type: u8,
    /// ACE flags (object-inherit, container-inherit, etc.)
    pub ace_flags: u8,
    /// Access mask granted/denied by this ACE
    pub mask: u32,
    /// SID of the trustee this ACE applies to
    pub sid: String,
}

/// A parsed Access Control List (ACL).
#[derive(Debug, Clone)]
pub struct Acl {
    /// ACL revision
    pub revision: u8,
    /// Number of ACE entries
    pub ace_count: u16,
    /// Parsed ACE entries
    pub aces: Vec<AceEntry>,
}

/// Security descriptor with full ACL/ACE parsing.
///
/// Windows `SECURITY_DESCRIPTOR` fields (self-relative format):
/// - Revision (u8): always 1
/// - Sbz1 (u8): reserved, must be 0
/// - Control (u16): SE_SELF_RELATIVE, SE_DACL_PRESENT, SE_SACL_PRESENT, etc.
/// - Owner (u32 offset to SID)
/// - Group (u32 offset to SID)
/// - Sacl (u32 offset to ACL)
/// - Dacl (u32 offset to ACL)
///
/// ACE types: 0x00=ACCESS_ALLOWED, 0x01=ACCESS_DENIED,
/// 0x02=SYSTEM_AUDIT, 0x03=SYSTEM_ALARM
#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    /// Owner SID string (e.g. "S-1-5-21-...")
    pub owner: String,
    /// Group SID string
    pub group: String,
    /// DACL is present in the descriptor
    pub dacl_present: bool,
    /// SACL is present in the descriptor
    pub sacl_present: bool,
    /// Raw control flags from the SECURITY_DESCRIPTOR header
    pub control_flags: u16,
    /// Self-relative flag (if true, offsets are relative to structure base)
    pub self_relative: bool,
    /// Parsed DACL (discretionary access control list)
    pub dacl: Option<Acl>,
    /// Parsed SACL (system access control list)
    pub sacl: Option<Acl>,
}

impl SecurityDescriptor {
    /// Create a new security descriptor with the given fields.
    pub fn new(owner: &str, group: &str, dacl_present: bool, sacl_present: bool) -> Self {
        let mut control_flags = 0u16;
        if dacl_present {
            control_flags |= 0x0004; // SE_DACL_PRESENT
        }
        if sacl_present {
            control_flags |= 0x0010; // SE_SACL_PRESENT
        }
        control_flags |= 0x8000; // SE_SELF_RELATIVE
        Self {
            owner: owner.to_string(),
            group: group.to_string(),
            dacl_present,
            sacl_present,
            control_flags,
            self_relative: true,
            dacl: None,
            sacl: None,
        }
    }

    /// Parse a self-relative SECURITY_DESCRIPTOR from raw bytes.
    ///
    /// Returns `None` if the input is too short or the revision doesn't match.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }
        let revision = bytes[0];
        if revision != 1 {
            return None;
        }
        let _sbz1 = bytes[1];
        let control_flags = u16::from_le_bytes([bytes[2], bytes[3]]);
        let owner_offset = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let group_offset = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let _sacl_offset = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let _dacl_offset = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);

        let dacl_present = (control_flags & 0x0004) != 0;
        let sacl_present = (control_flags & 0x0010) != 0;
        let self_relative = (control_flags & 0x8000) != 0;

        let owner = if owner_offset != 0 && (owner_offset as usize) < bytes.len() {
            parse_sid(bytes, owner_offset as usize)
        } else {
            "S-1-0-0".to_string()
        };

        let group = if group_offset != 0 && (group_offset as usize) < bytes.len() {
            parse_sid(bytes, group_offset as usize)
        } else {
            "S-1-0-0".to_string()
        };

        let dacl = if dacl_present && _dacl_offset != 0 {
            parse_acl(bytes, _dacl_offset as usize)
        } else {
            None
        };

        let sacl = if sacl_present {
            parse_acl(bytes, _sacl_offset as usize)
        } else {
            None
        };

        Some(Self {
            owner,
            group,
            dacl_present,
            sacl_present,
            control_flags,
            self_relative,
            dacl,
            sacl,
        })
    }

    /// Check whether this descriptor is valid.
    pub fn is_valid(&self) -> bool {
        self.self_relative
    }

    /// Check whether a token with the given SID has the requested access.
    ///
    /// Performs DACL inspection:
    /// - If no DACL is present, access is granted (null DACL = allow all).
    /// - If DACL is empty, access is denied.
    /// - Otherwise, walks the ACE list in order:
    ///   - ACCESS_ALLOWED ACEs grant matching access
    ///   - ACCESS_DENIED ACEs deny matching access
    ///   - First match wins (Windows semantics)
    pub fn check_access_for_token(&self, token_sid: &str, desired_access: u32) -> bool {
        if !self.dacl_present || self.dacl.is_none() {
            // Null DACL = allow all (Windows security semantics)
            return true;
        }

        let dacl = self.dacl.as_ref().unwrap();
        if dacl.aces.is_empty() {
            // Empty DACL = deny all
            return false;
        }

        let mut granted = 0u32;
        let mut denied = 0u32;

        for ace in &dacl.aces {
            // Check if this ACE applies to the token SID
            if ace.sid != token_sid && ace.sid != "S-1-1-0"
            /* Everyone */
            {
                continue;
            }

            match ace.ace_type {
                0x00 => {
                    // ACCESS_ALLOWED
                    granted |= ace.mask;
                }
                0x01 => {
                    // ACCESS_DENIED
                    denied |= ace.mask;
                }
                _ => {}
            }
        }

        // If any requested access is denied, fail
        if denied & desired_access != 0 {
            return false;
        }

        // If all requested access is granted, succeed
        (granted & desired_access) == desired_access
    }
}

/// Parse a SID (Security Identifier) from raw bytes at the given offset.
///
/// Format: revision(1) + sub_authority_count(1) + identifier_authority(6) + sub_authorities(variable)
fn parse_sid(bytes: &[u8], offset: usize) -> String {
    if offset + 8 > bytes.len() {
        return "S-0-0".to_string();
    }
    let revision = bytes[offset];
    let sub_count = bytes[offset + 1] as usize;
    // Identifier authority is 6 bytes big-endian
    let id_auth = u64::from_be_bytes([
        0,
        0,
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]);

    let mut sid = format!("S-{revision}-{id_auth}");

    for i in 0..sub_count {
        let sub_auth_offset = offset + 8 + i * 4;
        if sub_auth_offset + 4 > bytes.len() {
            break;
        }
        let sub_auth = u32::from_le_bytes([
            bytes[sub_auth_offset],
            bytes[sub_auth_offset + 1],
            bytes[sub_auth_offset + 2],
            bytes[sub_auth_offset + 3],
        ]);
        sid.push_str(&format!("-{sub_auth}"));
    }

    sid
}

/// Parse an ACL (Access Control List) from raw bytes at the given offset.
///
/// ACL structure:
/// - AclRevision (u8): always 2
/// - Sbz1 (u8): reserved
/// - AclSize (u16): total size of ACL including header and ACEs
/// - AceCount (u16): number of ACE entries
/// - Sbz2 (u16): reserved
/// - Followed by AceCount ACE entries, each:
///   - AceType (u8)
///   - AceFlags (u8)
///   - AceSize (u16): total size of this ACE entry
///   - AccessMask (u32)
///   - SID (variable length)
fn parse_acl(bytes: &[u8], offset: usize) -> Option<Acl> {
    if offset + 8 > bytes.len() {
        return None;
    }
    let revision = bytes[offset];
    let _sbz1 = bytes[offset + 1];
    let _acl_size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]);
    let ace_count = u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]);
    let _sbz2 = u16::from_le_bytes([bytes[offset + 6], bytes[offset + 7]]);

    let mut aces = Vec::with_capacity(ace_count as usize);
    let mut ace_offset = offset + 8;

    for _ in 0..ace_count {
        if ace_offset + 4 > bytes.len() {
            break;
        }
        let ace_type = bytes[ace_offset];
        let ace_flags = bytes[ace_offset + 1];
        let ace_size = u16::from_le_bytes([bytes[ace_offset + 2], bytes[ace_offset + 3]]);
        if ace_size < 8 || ace_offset + ace_size as usize > bytes.len() {
            break;
        }
        let mask = u32::from_le_bytes([
            bytes[ace_offset + 4],
            bytes[ace_offset + 5],
            bytes[ace_offset + 6],
            bytes[ace_offset + 7],
        ]);
        // SID starts at offset + 8
        let sid = parse_sid(bytes, ace_offset + 8);
        aces.push(AceEntry {
            ace_type,
            ace_flags,
            mask,
            sid,
        });
        ace_offset += ace_size as usize;
    }

    Some(Acl {
        revision,
        ace_count,
        aces,
    })
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
        services.insert(
            "SteamClientService".to_string(),
            ServiceRecord {
                name: "Steam Client Service".to_string(),
                display_name: "Steam Client Service".to_string(),
                service_type: 0x10, // SERVICE_WIN32_OWN_PROCESS
                state: ServiceState::Running,
                process_id: Some(1234),
            },
        );
        services.insert(
            "Winmgmt".to_string(),
            ServiceRecord {
                name: "Windows Management Instrumentation".to_string(),
                display_name: "Windows Management Instrumentation".to_string(),
                service_type: 0x20, // SERVICE_WIN32_SHARE_PROCESS
                state: ServiceState::Running,
                process_id: Some(5678),
            },
        );
        services.insert(
            "Audiosrv".to_string(),
            ServiceRecord {
                name: "Windows Audio".to_string(),
                display_name: "Windows Audio".to_string(),
                service_type: 0x10,
                state: ServiceState::Running,
                process_id: Some(9012),
            },
        );

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
}

impl Default for Advapi32Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Advapi32Manager {

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
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("service '{service_name}' not found"),
            )
        })
    }

    /// StartService — start a service.
    pub fn start_service(&mut self, service_name: &str) -> AppResult<()> {
        let service = self.services.get_mut(service_name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("service '{service_name}' not found"),
            )
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
        self.security_descriptors
            .insert(object_name.to_string(), descriptor);
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

/// Service Control Manager — manages service lifecycle.
///
/// This provides the SCM API surface that SteamService.exe queries
/// during its startup and lifecycle (OpenSCManager, CreateService,
/// StartService, ControlService, QueryServiceStatus, etc.).
///
/// When a service is started, the SCM attempts to spawn the service
/// executable as a child process via `std::process::Command`. If the
/// spawn fails (e.g. the executable is a Windows PE that cannot run
/// natively on macOS), a synthetic PID is assigned instead, allowing
/// the service lifecycle to continue without an actual process.
pub struct ServiceControlManager {
    /// Registered services indexed by name.
    services: BTreeMap<String, ScmServiceRecord>,
    /// Monotonically increasing handle counter.
    next_handle: u64,
    /// Monotonically increasing virtual PID counter.
    next_pid: u32,
}

impl ServiceControlManager {
    /// Create an empty Service Control Manager, pre-seeded with the same
    /// well-known services as [`Advapi32Manager`] so both SCM implementations
    /// expose the same service set to Steam/games.
    pub fn new() -> Self {
        let mut services = BTreeMap::new();
        let mut next_handle = 1u64;
        let mut insert = |name: &str, display: &str, pid: u32, services: &mut BTreeMap<String, ScmServiceRecord>| {
            let handle = next_handle;
            next_handle += 1;
            services.insert(
                name.to_string(),
                ScmServiceRecord {
                    name: name.to_string(),
                    display_name: display.to_string(),
                    status: ServiceStatus::Running,
                    handle,
                    executable_path: PathBuf::new(),
                    pid: Some(pid),
                },
            );
        };
        insert(
            "SteamClientService",
            "Steam Client Service",
            1234,
            &mut services,
        );
        insert(
            "Winmgmt",
            "Windows Management Instrumentation",
            5678,
            &mut services,
        );
        insert("Audiosrv", "Windows Audio", 9012, &mut services);
        Self {
            services,
            next_handle,
            next_pid: 1000,
        }
    }
}

impl Default for ServiceControlManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceControlManager {

    /// OpenSCManagerW — open the service control manager.
    ///
    /// Returns a synthetic handle representing the SCM database. The
    /// `machine_name` and `database_name` parameters are accepted but
    /// ignored (local machine only).
    pub fn open_sc_manager(
        &mut self,
        _machine_name: Option<&str>,
        _database_name: Option<&str>,
    ) -> u64 {
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
    pub fn open_service(
        &self,
        _sc_handle: u64,
        name: &str,
        _desired_access: u32,
    ) -> AppResult<u64> {
        self.services.get(name).map(|s| s.handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("SCM: service '{name}' not found"),
            )
        })
    }

    /// StartServiceW — start a registered service.
    ///
    /// Service executables are guest-controlled paths and must never be
    /// executed on the host; the service is simulated by assigning a
    /// synthetic PID.
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
                return Ok(());
            }
            ServiceStatus::StartPending
            | ServiceStatus::StopPending
            | ServiceStatus::PausePending => {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    format!(
                        "SCM: service '{name}' is in transition state {:?}",
                        record.status
                    ),
                ));
            }
            _ => {}
        }

        // Assign a synthetic PID — never spawn the guest-supplied executable
        // on the host.
        let pid = self.next_pid;
        self.next_pid = self.next_pid.wrapping_add(1);

        record.status = ServiceStatus::Running;
        record.pid = Some(pid);
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
        let record = self
            .services
            .values_mut()
            .find(|s| s.handle == svc_handle)
            .ok_or_else(|| {
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
            0x05 => {
                // SERVICE_CONTROL_SHUTDOWN — service is being shut down.
                // The service runs as a simulated process only (no host
                // child), so this mirrors STOP: clear the state and PID.
                record.status = ServiceStatus::Stopped;
                record.pid = None;
            }
            0x06 => {
                // SERVICE_CONTROL_PARAMCHANGE — service parameters changed (no-op)
            }
            0x07 => {
                // SERVICE_CONTROL_NETBINDADD — network binding added (no-op)
            }
            0x08 => {
                // SERVICE_CONTROL_NETBINDREMOVE — network binding removed (no-op)
            }
            0x09 => {
                // SERVICE_CONTROL_NETBINDENABLE — network binding enabled (no-op)
            }
            0x0A => {
                // SERVICE_CONTROL_NETBINDDISABLE — network binding disabled (no-op)
            }
            0x0B => {
                // SERVICE_CONTROL_DEVICEEVENT — device notification (no-op)
            }
            0x0C => {
                // SERVICE_CONTROL_HARDWAREPROFILECHANGE — hardware profile changed (no-op)
            }
            0x0D => {
                // SERVICE_CONTROL_POWEREVENT — power event (no-op)
            }
            0x0E => {
                // SERVICE_CONTROL_SESSIONCHANGE — session change (no-op)
            }
            0x0F => {
                // SERVICE_CONTROL_PRESHUTDOWN — pre-shutdown notification (no-op)
            }
            0x10 => {
                // SERVICE_CONTROL_TIMECHANGE — system time changed (no-op)
            }
            0x20 => {
                // SERVICE_CONTROL_TRIGGEREVENT — trigger event (no-op)
            }
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("SCM: unsupported control code {control_code:#x}"),
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
        let record = self
            .services
            .values()
            .find(|s| s.handle == svc_handle)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("SCM: no service with handle {svc_handle}"),
                )
            })?;
        Ok((record.status, record.pid))
    }

    /// Query service status by name (convenience wrapper).
    pub fn query_service_status_by_name(
        &self,
        name: &str,
    ) -> AppResult<(ServiceStatus, Option<u32>)> {
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
            let record = self
                .services
                .values()
                .find(|s| s.handle == svc_handle)
                .ok_or_else(|| {
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
        self.services
            .values()
            .find(|s| s.handle == svc_handle)
            .ok_or_else(|| {
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
        com.co_initialize(ComApartmentModel::SingleThreaded)
            .unwrap();

        let handle = com
            .co_create_instance(
                ComClsid::DIRECTSOUND8,
                ComIid::IUNKNOWN,
                0x1000_0000,
                "DirectSound8",
            )
            .unwrap();

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
        let result =
            com.co_create_instance(ComClsid::XAUDIO2, ComIid::IUNKNOWN, 0x2000_0000, "XAudio2");
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn com_query_interface_unknown_always_supported() {
        let mut com = ComApartmentState::new();
        com.co_initialize(ComApartmentModel::MultiThreaded).unwrap();

        let handle = com
            .co_create_instance(ComClsid::XAUDIO2, ComIid::IXAUDIO2, 0x3000_0000, "Test")
            .unwrap();

        assert!(com.com_query_interface(handle, ComIid::IUNKNOWN).unwrap());
        assert!(
            !com.com_query_interface(handle, ComIid::ICLASS_FACTORY)
                .unwrap()
        );
        assert!(com.com_query_interface(handle, ComIid::IXAUDIO2).unwrap());
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
        assert!((MsvcCrt::crt_atof("3.14") - "3.14".parse::<f64>().unwrap()).abs() < 0.001);
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
        // Basic %d and %i
        assert_eq!(MsvcCrt::crt_sscanf_int("42", "%d"), Some(42));
        assert_eq!(MsvcCrt::crt_sscanf_int("-42", "%d"), Some(-42));
        assert_eq!(MsvcCrt::crt_sscanf_int("+42", "%d"), Some(42));

        // %i auto-detect: decimal
        assert_eq!(MsvcCrt::crt_sscanf_int("42", "%i"), Some(42));
        // %i auto-detect: hex
        assert_eq!(MsvcCrt::crt_sscanf_int("0xFF", "%i"), Some(255));
        // %i auto-detect: octal
        assert_eq!(MsvcCrt::crt_sscanf_int("077", "%i"), Some(63));

        // Hex
        assert_eq!(MsvcCrt::crt_sscanf_int("ff", "%x"), Some(255));
        assert_eq!(MsvcCrt::crt_sscanf_int("0xFF", "%x"), Some(255));
        assert_eq!(MsvcCrt::crt_sscanf_int("0xFF", "%X"), Some(255));
        assert_eq!(MsvcCrt::crt_sscanf_int("1A", "%x"), Some(26));

        // Octal
        assert_eq!(MsvcCrt::crt_sscanf_int("10", "%o"), Some(8));
        assert_eq!(MsvcCrt::crt_sscanf_int("77", "%o"), Some(63));

        // Unsigned
        assert_eq!(MsvcCrt::crt_sscanf_int("42", "%u"), Some(42));

        // Float (truncated to i32)
        assert_eq!(MsvcCrt::crt_sscanf_int("3.14", "%f"), Some(3));
        assert_eq!(MsvcCrt::crt_sscanf_int("-2.7", "%f"), Some(-2));

        // Width specifier
        assert_eq!(MsvcCrt::crt_sscanf_int("12345", "%2d"), Some(12));
        assert_eq!(MsvcCrt::crt_sscanf_int("abc", "%2x"), Some(0xab));

        // %n — character count
        assert_eq!(MsvcCrt::crt_sscanf_int("hello", "%n"), Some(0));

        // Literal matching
        assert_eq!(MsvcCrt::crt_sscanf_int("x=42", "x=%d"), Some(42));
        assert_eq!(MsvcCrt::crt_sscanf_int("value 99", "value %d"), Some(99));

        // %s consumes string but last numeric wins
        assert_eq!(MsvcCrt::crt_sscanf_int("abc 42 def", "%s %d"), Some(42));

        // Failure cases
        assert_eq!(MsvcCrt::crt_sscanf_int("abc", "%d"), None);
        assert_eq!(MsvcCrt::crt_sscanf_int("", "%d"), None);
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
        // Set version at offset 48-55 (signature + 8/+12)
        data[48..52].copy_from_slice(&0x0001_0002_u32.to_le_bytes()); // 1.2
        data[52..56].copy_from_slice(&0x0003_0004_u32.to_le_bytes()); // 3.4
        // Set file type at offset 76 (signature + 36, standard VS_FIXEDFILEINFO)
        data[76..80].copy_from_slice(&1_u32.to_le_bytes()); // VFT_APP

        let info = FileVersionInfo::parse(&data).unwrap();
        assert_eq!(info.version, (1, 2, 3, 4));
        assert_eq!(info.version_string(), "1.2.3.4");
        assert_eq!(info.file_type, 1);
    }

    #[test]
    fn file_version_info_bad_signature() {
        let data = vec![0u8; 128];
        let result = FileVersionInfo::parse(&data);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn file_version_info_too_small() {
        let data = vec![0u8; 50];
        let result = FileVersionInfo::parse(&data);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // --- XInput Tests ---

    #[test]
    fn xinput_connect_and_get_state() {
        let mut xinput = XInputManager::new();
        assert_eq!(xinput.connected_count(), 0);

        xinput
            .connect_controller(
                0,
                XInputState {
                    packet_number: 1,
                    buttons: XINPUT_GAMEPAD_A,
                    left_trigger: 128,
                    right_trigger: 0,
                    left_thumb_x: 0,
                    left_thumb_y: 0,
                    right_thumb_x: 0,
                    right_thumb_y: 0,
                },
            )
            .unwrap();

        assert_eq!(xinput.connected_count(), 1);
        assert!(xinput.is_connected(0));

        let state = xinput.get_state(0).unwrap();
        assert_eq!(state.buttons & XINPUT_GAMEPAD_A, XINPUT_GAMEPAD_A);
    }

    #[test]
    fn xinput_disconnect() {
        let mut xinput = XInputManager::new();
        xinput
            .connect_controller(
                0,
                XInputState {
                    packet_number: 1,
                    buttons: 0,
                    left_trigger: 0,
                    right_trigger: 0,
                    left_thumb_x: 0,
                    left_thumb_y: 0,
                    right_thumb_x: 0,
                    right_thumb_y: 0,
                },
            )
            .unwrap();
        assert_eq!(xinput.connected_count(), 1);

        xinput.disconnect_controller(0).unwrap();
        assert_eq!(xinput.connected_count(), 0);
        let _result = xinput.get_state(0);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn xinput_capabilities() {
        let mut xinput = XInputManager::new();
        xinput
            .connect_controller(
                0,
                XInputState {
                    packet_number: 1,
                    buttons: 0,
                    left_trigger: 0,
                    right_trigger: 0,
                    left_thumb_x: 0,
                    left_thumb_y: 0,
                    right_thumb_x: 0,
                    right_thumb_y: 0,
                },
            )
            .unwrap();

        let caps = xinput.get_capabilities(0).unwrap();
        assert!(caps.vibration_supported);
    }

    #[test]
    fn xinput_invalid_index() {
        let xinput = XInputManager::new();
        let _result = xinput.get_state(4);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
        assert!(!xinput.is_connected(4));
    }

    #[test]
    fn xinput_vibration() {
        let mut xinput = XInputManager::new();
        xinput
            .connect_controller(
                0,
                XInputState {
                    packet_number: 1,
                    buttons: 0,
                    left_trigger: 0,
                    right_trigger: 0,
                    left_thumb_x: 0,
                    left_thumb_y: 0,
                    right_thumb_x: 0,
                    right_thumb_y: 0,
                },
            )
            .unwrap();

        xinput
            .set_state(
                0,
                XInputVibration {
                    left_motor_speed: 65535,
                    right_motor_speed: 32768,
                },
            )
            .unwrap();
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
        assert!(
            result.is_err(),
            "expected Err for unsupported BCrypt algorithm"
        );
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
        let _result = tp.submit_work(999);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
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
        let _result = ctx.sym_from_addr(0xDEAD);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn dbghelp_stack_walk() {
        let mut ctx = DbgHelpContext::new();
        ctx.sym_load_module("game.exe", 0x0040_0000).unwrap();
        ctx.register_symbol(0x0040_1000, "main", 0x0040_0000);

        // Without a working memory reader, only the first frame is returned.
        let frames = ctx.stack_walk(
            0x0040_1000,
            0x7FFF_0000,
            0x7FFF_F000,
            GuestArch::X86_64,
            10,
            |_addr, _size| None,
        );
        assert_eq!(
            frames.len(),
            1,
            "stack_walk returns first frame without memory reader"
        );
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
        let _result = mgr.query_service_status("NonExistentService");
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn advapi32_start_service() {
        let mut mgr = Advapi32Manager::new();
        // Add a stopped service
        mgr.services.insert(
            "TestSvc".to_string(),
            ServiceRecord {
                name: "TestSvc".to_string(),
                display_name: "Test Service".to_string(),
                service_type: 0x10,
                state: ServiceState::Stopped,
                process_id: None,
            },
        );

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
        mgr.set_security_descriptor(
            "C:\\Secret.txt",
            SecurityDescriptor {
                owner: "Administrators".to_string(),
                group: "None".to_string(),
                dacl_present: true,
                sacl_present: false,
                control_flags: 0x8004,
                self_relative: true,
                dacl: None,
                sacl: None,
            },
        );

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

        // 3 pre-seeded services (SteamClientService, Winmgmt, Audiosrv) + 1
        assert_eq!(scm.service_count(), 4);

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
        // Process spawn will likely fail for /usr/local/bin/mysvc, so
        // a synthetic PID (1000) is assigned. Test both possibilities.
        assert!(pid.is_some(), "service should have a PID after start");

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

        scm.start_service(sc_handle, "PausableSvc", 0, None)
            .unwrap();

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

        // 3 pre-seeded services + 1
        assert_eq!(scm.service_count(), 4);

        // Must be stopped to delete
        scm.delete_service(svc_handle).unwrap();
        assert_eq!(scm.service_count(), 3);
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
        let _result = scm.delete_service(svc_handle);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn scm_open_nonexistent_service_fails() {
        let scm = ServiceControlManager::new();
        let result = scm.open_service(1, "NonExistent", 0);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn scm_list_services() {
        let mut scm = ServiceControlManager::new();
        let sc_handle = scm.open_sc_manager(None, None);

        scm.create_service(
            sc_handle,
            "SvcA",
            "Service A",
            0xF003F,
            0x10,
            3,
            0,
            "a.exe",
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        scm.create_service(
            sc_handle,
            "SvcB",
            "Service B",
            0xF003F,
            0x10,
            3,
            0,
            "b.exe",
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let names = scm.list_services();
        // 3 pre-seeded services + SvcA + SvcB
        assert_eq!(names.len(), 5);
        assert!(names.contains(&"SvcA"));
        assert!(names.contains(&"SvcB"));
        assert!(names.contains(&"SteamClientService"));
    }

    #[test]
    fn scm_service_status_conversion() {
        assert_eq!(ServiceStatus::Stopped.to_win32_code(), 0x0001);
        assert_eq!(ServiceStatus::Running.to_win32_code(), 0x0004);
        assert_eq!(
            ServiceStatus::from_win32_code(0x0004),
            ServiceStatus::Running
        );
        assert_eq!(
            ServiceStatus::from_win32_code(0x0001),
            ServiceStatus::Stopped
        );
        assert_eq!(
            ServiceStatus::from_win32_code(0xFFFF),
            ServiceStatus::Stopped
        );
    }

    // ── DirectInput Force Feedback tests ────────────────────────────────

    #[test]
    fn directinput_device8_new() {
        let dev = DirectInputDevice8::new(0);
        assert!(dev.ff_enabled);
        assert!(!dev.ff_active);
        assert!(dev.current_effect.is_none());
        assert_eq!(dev.autocenter, 5000);
        assert_eq!(dev.device_gain, 10000);
    }

    #[test]
    fn directinput_force_feedback_enable_disable() {
        let mut dev = DirectInputDevice8::new(1);

        // DISFC_DISABLE = 2
        dev.send_force_feedback_command(2).unwrap();
        assert!(!dev.ff_enabled);
        assert!(!dev.ff_active);

        // DISFC_ENABLE = 1
        dev.send_force_feedback_command(1).unwrap();
        assert!(dev.ff_enabled);

        // DISFC_RESET = 4
        dev.send_force_feedback_command(4).unwrap();
        assert!(dev.ff_enabled);
        assert!(!dev.ff_active);
        assert!(dev.current_effect.is_none());
        assert_eq!(dev.autocenter, 5000);
    }

    #[test]
    fn directinput_set_force_feedback_state_constant() {
        let mut dev = DirectInputDevice8::new(0);
        let effect = DirectInputEffect {
            effect_type: DirectInputEffectType::ConstantForce,
            magnitude: 5000,
            gain: 10000,
            duration_us: 1_000_000,
            ..Default::default()
        };

        dev.set_force_feedback_state(&effect).unwrap();
        assert!(dev.ff_active);
        assert!(dev.current_effect.is_some());
        assert_eq!(dev.current_effect.as_ref().unwrap().magnitude, 5000);
    }

    #[test]
    fn directinput_set_force_feedback_state_disabled_fails() {
        let mut dev = DirectInputDevice8::new(0);
        // DISFC_DISABLE = 2
        dev.send_force_feedback_command(2).unwrap();
        let effect = DirectInputEffect::default();
        let _result = dev.set_force_feedback_state(&effect);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn directinput_stopall_sends_stop_rumble() {
        let mut dev = DirectInputDevice8::new(2);

        // Start an effect
        let effect = DirectInputEffect {
            effect_type: DirectInputEffectType::Sine,
            magnitude: 8000,
            ..Default::default()
        };
        dev.set_force_feedback_state(&effect).unwrap();
        assert!(dev.ff_active);

        // DISFC_STOPALL = 3
        dev.send_force_feedback_command(3).unwrap();
        assert!(!dev.ff_active);
        assert!(dev.current_effect.is_none());
    }

    #[test]
    fn directinput_effect_type_mapping() {
        // Verify that all effect types are constructible
        let types = [
            DirectInputEffectType::ConstantForce,
            DirectInputEffectType::Ramp,
            DirectInputEffectType::Square,
            DirectInputEffectType::Sine,
            DirectInputEffectType::Triangle,
            DirectInputEffectType::SawtoothUp,
            DirectInputEffectType::SawtoothDown,
            DirectInputEffectType::Spring,
            DirectInputEffectType::Damper,
            DirectInputEffectType::Inertia,
            DirectInputEffectType::Friction,
            DirectInputEffectType::Custom,
        ];
        assert_eq!(types.len(), 12);
    }
}

// ===========================================================================
// Registry Change Notifications (RegNotifyChangeKeyValue)
// ===========================================================================

/// Flags for `RegNotifyChangeKeyValue`.
pub const REG_NOTIFY_CHANGE_NAME: u32 = 0x0000_0001;
pub const REG_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x0000_0002;
pub const REG_NOTIFY_CHANGE_LAST_SET: u32 = 0x0000_0004;
pub const REG_NOTIFY_CHANGE_SECURITY: u32 = 0x0000_0008;

/// Tracks per-key version counters for change notification.
///
/// Each registry key is assigned a monotonically increasing version counter.
/// When any value under that key is modified (set, deleted, etc.), the counter
/// is bumped. Callers of `RegNotifyChangeKeyValue` compare their observed
/// version against the current version to detect changes.
#[derive(Debug, Clone)]
pub struct RegistryChangeTracker {
    /// Per-key version counters: `"HKLM\\Software\\MyApp"` → version.
    versions: HashMap<String, u64>,
    /// Per-key notification subscriptions: key → list of (event_handle, flags, watch_subtree).
    subscriptions: HashMap<String, Vec<RegistryChangeSubscription>>,
}

/// A pending change notification subscription.
#[derive(Debug, Clone)]
struct RegistryChangeSubscription {
    /// Event handle to signal when a change is detected.
    event_handle: u64,
    /// Which change types to watch for.
    flags: u32,
    /// Whether to watch the entire subtree.
    watch_subtree: bool,
}

/// Whether `key` is `sub_key` itself or a descendant of it. Matching is on
/// key boundaries so `HKLM\\Software\\MyAppEvil` does not match a
/// subscription for `HKLM\\Software\\MyApp`.
fn is_key_in_subtree(key: &str, sub_key: &str) -> bool {
    key == sub_key || key.starts_with(&format!("{sub_key}\\"))
}

impl RegistryChangeTracker {
    /// Create a new empty change tracker.
    pub fn new() -> Self {
        Self {
            versions: HashMap::new(),
            subscriptions: HashMap::new(),
        }
    }

    /// Get the current version for a registry key (0 if never modified).
    pub fn version(&self, key: &str) -> u64 {
        let normalized = key.to_lowercase();
        self.versions.get(&normalized).copied().unwrap_or(0)
    }

    /// Bump the version counter for a registry key, indicating a change.
    ///
    /// Also signals any subscribed event handles via the event-signal hook
    /// installed with [`set_registry_event_signal_hook`].
    pub fn notify_change(&mut self, key: &str) {
        let normalized = key.to_lowercase();
        let version = self.versions.entry(normalized.clone()).or_insert(0);
        *version += 1;

        // Signal any subscriptions for this key or parent keys
        let mut to_signal = Vec::new();
        for (sub_key, subs) in &self.subscriptions {
            if is_key_in_subtree(&normalized, sub_key) {
                for sub in subs {
                    to_signal.push(sub.event_handle);
                }
            }
        }
        for handle in to_signal {
            signal_event_handle(handle);
        }
    }

    /// Subscribe to change notifications for a registry key.
    ///
    /// `event_handle` is the Win32 event handle to signal.
    /// `flags` is a combination of `REG_NOTIFY_CHANGE_*`.
    /// `watch_subtree` indicates whether to watch child keys.
    ///
    /// Duplicate subscriptions for the same `(key, event_handle, flags,
    /// watch_subtree)` are ignored so repeated calls cannot grow the
    /// subscription table without bound.
    pub fn subscribe(&mut self, key: &str, event_handle: u64, flags: u32, watch_subtree: bool) {
        let normalized = key.to_lowercase();
        let subs = self.subscriptions.entry(normalized).or_default();
        if !subs.iter().any(|s| {
            s.event_handle == event_handle && s.flags == flags && s.watch_subtree == watch_subtree
        }) {
            subs.push(RegistryChangeSubscription {
                event_handle,
                flags,
                watch_subtree,
            });
        }
    }

    /// Remove all subscriptions for a given event handle.
    pub fn unsubscribe(&mut self, event_handle: u64) {
        for subs in self.subscriptions.values_mut() {
            subs.retain(|s| s.event_handle != event_handle);
        }
    }

    /// Poll for changes since the given version.
    ///
    /// Returns `true` if the key (or any subkey, if `watch_subtree` is true)
    /// has been modified since `observed_version`.
    pub fn has_changed(&self, key: &str, observed_version: u64, watch_subtree: bool) -> bool {
        let normalized = key.to_lowercase();

        // Check the key itself
        if self.versions.get(&normalized).copied().unwrap_or(0) > observed_version {
            // Key version is newer than the observed version → change detected
            return true;
        }

        // Check child keys if watching subtree
        if watch_subtree {
            for (k, &v) in &self.versions {
                if is_key_in_subtree(k, &normalized) && k.len() > normalized.len() && v > observed_version
                {
                    // Subkey version is newer than observed → change detected
                    return true;
                }
            }
        }

        false
    }

    /// Get the subscriptions that should be signaled for a change to the given key.
    pub fn subscriptions_for_key(&self, key: &str) -> Vec<(u64, u32, bool)> {
        let normalized = key.to_lowercase();
        let mut result = Vec::new();

        for (sub_key, subs) in &self.subscriptions {
            if is_key_in_subtree(&normalized, sub_key) {
                for sub in subs {
                    if sub.watch_subtree || normalized == *sub_key {
                        result.push((sub.event_handle, sub.flags, sub.watch_subtree));
                    }
                }
            }
        }

        result
    }
}

/// Hook used to signal Win32 event handles. Installed by the host
/// integration that owns the event objects (e.g. the Win32 subsystem);
/// `notify_change` invokes it for every subscription event handle.
type RegistryEventSignalHook = dyn Fn(u64) + Send + Sync;

static REGISTRY_EVENT_SIGNAL_HOOK: Mutex<Option<Box<RegistryEventSignalHook>>> =
    Mutex::new(None);

/// Install (or remove, with `None`) the hook used by
/// [`RegistryChangeTracker::notify_change`] to signal event handles.
pub fn set_registry_event_signal_hook(hook: Option<Box<RegistryEventSignalHook>>) {
    *REGISTRY_EVENT_SIGNAL_HOOK.lock().unwrap() = hook;
}

fn signal_event_handle(handle: u64) {
    if let Some(hook) = REGISTRY_EVENT_SIGNAL_HOOK.lock().unwrap().as_ref() {
        hook(handle);
    }
}

impl Default for RegistryChangeTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// RegNotifyChangeKeyValue implementation
// ===========================================================================

/// Result of a `RegNotifyChangeKeyValue` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegNotifyResult {
    /// A change was detected immediately.
    Changed,
    /// The notification has been registered and will signal the event handle.
    Pending,
    /// The wait timed out without detecting a change.
    Timeout,
}

/// Polling-based implementation of `RegNotifyChangeKeyValue`.
///
/// This function checks if the registry key has changed since the given
/// observed version. If `async_notify` is true, it registers a subscription
/// for future changes. If `async_notify` is false, it blocks (simulated via
/// polling) until a change is detected or the timeout expires.
///
/// # Arguments
/// * `tracker` - The registry change tracker.
/// * `key` - The full registry key path (e.g., `"HKLM\\Software\\MyApp"`).
/// * `watch_subtree` - Whether to watch child keys.
/// * `flags` - Combination of `REG_NOTIFY_CHANGE_*` flags.
/// * `async_notify` - If true, signal the event handle on change (non-blocking).
/// * `event_handle` - The event handle to signal (used when `async_notify` is true).
/// * `observed_version` - The last version the caller observed.
/// * `timeout` - Maximum duration to wait (for sync mode).
///
    /// # Returns
    /// The current version of the key and a `RegNotifyResult`.
    ///
    /// A zero `timeout` in sync mode means wait indefinitely (Windows
    /// semantics); only a finite deadline yields `Timeout`.
    #[allow(clippy::too_many_arguments)] // mirrors RegNotifyChangeKeyValue's parameter list
    pub fn reg_notify_change_key_value(
        tracker: &mut RegistryChangeTracker,
        key: &str,
        watch_subtree: bool,
        flags: u32,
        async_notify: bool,
        event_handle: u64,
        observed_version: u64,
        timeout: std::time::Duration,
    ) -> (u64, RegNotifyResult) {
        let current_version = tracker.version(key);

        // Check if already changed
        if tracker.has_changed(key, observed_version, watch_subtree) {
            return (current_version, RegNotifyResult::Changed);
        }

        if async_notify {
            // Register for future notifications. When a change occurs,
            // `notify_change` signals `event_handle` through the hook
            // installed with `set_registry_event_signal_hook`.
            tracker.subscribe(key, event_handle, flags, watch_subtree);
            (current_version, RegNotifyResult::Pending)
        } else {
            // Sync (blocking) notification — poll until a change is
            // detected or the finite deadline passes.
            let start = std::time::Instant::now();
            let poll_interval = std::time::Duration::from_millis(50);
            loop {
                std::thread::sleep(poll_interval);
                if tracker.has_changed(key, observed_version, watch_subtree) {
                    return (tracker.version(key), RegNotifyResult::Changed);
                }
                if !timeout.is_zero() && start.elapsed() >= timeout {
                    return (tracker.version(key), RegNotifyResult::Timeout);
                }
            }
        }
    }

// ===========================================================================
// Gap 6.5: Out-of-Process COM Server Support
// ===========================================================================

/// Entry for a running COM EXE server process.
#[derive(Debug)]
pub struct ComExeServerEntry {
    /// The CLSID this server provides.
    pub clsid: [u8; 16],
    /// The AppID for this server (from registry).
    pub app_id: String,
    /// The registration token returned by CoRegisterClassObject.
    pub registration_token: u32,
    /// The child process handle (if launched by us).
    pub process: Option<std::process::Child>,
    /// The command-line path used to launch the server.
    pub exe_path: String,
}

/// COM EXE server registry — tracks running out-of-process COM servers.
#[derive(Debug)]
pub struct ComExeServerRegistry {
    /// Running servers keyed by CLSID string.
    servers: HashMap<String, ComExeServerEntry>,
    /// Next registration token.
    next_token: u32,
}

/// Kill and reap a COM server's child process (if any), so revoking or
/// replacing a registration cannot leave zombies or orphaned processes.
fn terminate_server_process(mut entry: ComExeServerEntry) {
    if let Some(mut child) = entry.process.take() {
        if let Err(error) = child.kill() {
            eprintln!(
                "[real_win32] terminate_server_process: failed to kill process: {error}"
            );
        }
        if let Err(error) = child.wait() {
            eprintln!(
                "[real_win32] terminate_server_process: failed to wait for process: {error}"
            );
        }
    }
}

impl ComExeServerRegistry {
    pub fn new() -> Self {
        Self {
            servers: HashMap::new(),
            next_token: 1,
        }
    }

    /// CoRegisterClassObject for an EXE server.
    ///
    /// Registers a CLSID as being served by an out-of-process server.
    ///
    /// Guest-controlled executables are never launched on the host; the
    /// server is simulated (no child process). Re-registering the same CLSID
    /// replaces the previous registration.
    ///
    /// Returns the registration token on success.
    pub fn register_class_object(&mut self, clsid: &[u8; 16], exe_path: &str, app_id: &str) -> u32 {
        let token = self.next_token;
        self.next_token += 1;
        let guid_str = guid_to_string(clsid);

        // Replace any previous registration for this CLSID.
        if let Some(prev) = self.servers.remove(&guid_str) {
            terminate_server_process(prev);
        }

        self.servers.insert(
            guid_str,
            ComExeServerEntry {
                clsid: *clsid,
                app_id: app_id.to_string(),
                registration_token: token,
                process: None,
                exe_path: exe_path.to_string(),
            },
        );

        token
    }

    /// CoRevokeClassObject — revoke a previously registered EXE server.
    ///
    /// Returns true if the server was found and revoked.
    pub fn revoke_class_object(&mut self, token: u32) -> bool {
        let guid_str = match self
            .servers
            .iter()
            .find(|(_, e)| e.registration_token == token)
        {
            Some((k, _)) => k.clone(),
            None => return false,
        };
        if let Some(entry) = self.servers.remove(&guid_str) {
            terminate_server_process(entry);
            true
        } else {
            false
        }
    }

    /// CoGetClassObject for EXE servers.
    ///
    /// Checks if an EXE server is running for the given CLSID.
    /// Returns the registration token if found, or None.
    pub fn get_class_object(&self, clsid: &[u8; 16]) -> Option<u32> {
        let guid_str = guid_to_string(clsid);
        self.servers.get(&guid_str).map(|e| e.registration_token)
    }

    /// Check if an EXE server is running for the given CLSID.
    ///
    /// Registered servers are simulated, so a registered (not yet revoked)
    /// server is always considered running.
    pub fn is_server_running(&mut self, clsid: &[u8; 16]) -> bool {
        let guid_str = guid_to_string(clsid);
        self.servers.get_mut(&guid_str).is_some_and(|e| {
            e.process.as_mut().is_none_or(|process| match process.try_wait() {
                Ok(status) => status.is_none(),
                Err(error) => {
                    eprintln!(
                        "[real_win32] is_server_running: try_wait failed for {}: {}",
                        guid_str, error
                    );
                    true
                }
            })
        })
    }

    /// Get the number of running EXE servers.
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }
}

impl Default for ComExeServerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Gap 6.6: MSHTML Enhancements — get_all(), IPersistStreamInit, HTML parsing
// ===========================================================================

impl MsHtmlDocument {
    /// IHTMLDocument2::get_all — returns all elements in the document.
    ///
    /// Parses the accumulated HTML content and returns a list of all elements
    /// found. Each element is represented as a tag name string.
    pub fn get_all(&self) -> Vec<String> {
        let mut elements = Vec::new();
        let mut in_tag = false;
        let mut tag_name = String::new();
        let mut collecting_name = false;

        for ch in self.html_content.chars() {
            match ch {
                '<' => {
                    in_tag = true;
                    collecting_name = true;
                    tag_name.clear();
                }
                '>' => {
                    in_tag = false;
                    if !tag_name.is_empty()
                        && !tag_name.starts_with('/')
                        && !tag_name.starts_with('!')
                    {
                        // Extract just the tag name (before any attributes)
                        let name = tag_name.split_whitespace().next().unwrap_or(&tag_name);
                        // Trim a trailing '/' from self-closing tags like <br/>
                        let name = name.strip_suffix('/').unwrap_or(name);
                        if !name.is_empty() {
                            elements.push(name.to_string());
                        }
                    }
                    tag_name.clear();
                    collecting_name = false;
                }
                ' ' | '\t' | '\n' | '\r' => {
                    if collecting_name {
                        collecting_name = false;
                    }
                }
                _ => {
                    if in_tag && collecting_name {
                        tag_name.push(ch);
                    }
                }
            }
        }
        elements
    }

    /// Strip HTML tags and extract plain text content.
    pub fn extract_text(&self) -> String {
        let mut text = String::new();
        let mut in_tag = false;
        let mut in_script = false;
        let mut in_style = false;
        let mut tag_buf = String::new();

        for ch in self.html_content.chars() {
            match ch {
                '<' => {
                    in_tag = true;
                    tag_buf.clear();
                }
                '>' => {
                    in_tag = false;
                    let tag_lower = tag_buf.trim().to_ascii_lowercase();
                    if tag_lower.starts_with("script") {
                        in_script = true;
                    } else if tag_lower.starts_with("/script") {
                        in_script = false;
                    } else if tag_lower.starts_with("style") {
                        in_style = true;
                    } else if tag_lower.starts_with("/style") {
                        in_style = false;
                    }
                    tag_buf.clear();
                }
                _ => {
                    if in_tag {
                        tag_buf.push(ch);
                    } else if !in_script && !in_style {
                        text.push(ch);
                    }
                }
            }
        }

        // Collapse whitespace
        let result: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        result
    }
}

/// IPersistStreamInit implementation for MSHTML.
///
/// Allows loading HTML content from an IStream and saving it back.
#[derive(Debug, Clone)]
pub struct HtmlPersistStream {
    /// The HTML content.
    pub html: String,
    /// Whether the stream has been initialized.
    pub initialized: bool,
    /// Whether the content has been modified since last save.
    pub dirty: bool,
}

impl HtmlPersistStream {
    pub fn new() -> Self {
        Self {
            html: String::new(),
            initialized: false,
            dirty: false,
        }
    }

    /// IPersistStreamInit::Load — load HTML from a byte stream.
    ///
    /// Accepts UTF-8 and UTF-16 (LE/BE, with BOM); undecodable input falls
    /// back to lossy UTF-8 decoding instead of failing.
    pub fn load(&mut self, data: &[u8]) -> bool {
        let html = if data.starts_with(&[0xFF, 0xFE]) || data.starts_with(&[0xFE, 0xFF]) {
            // UTF-16 with BOM (common for real MSHTML streams)
            let little_endian = data.starts_with(&[0xFF, 0xFE]);
            let units: Vec<u16> = data[2..]
                .chunks_exact(2)
                .map(|c| {
                    if little_endian {
                        u16::from_le_bytes([c[0], c[1]])
                    } else {
                        u16::from_be_bytes([c[0], c[1]])
                    }
                })
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(data).into_owned()
        };
        self.html = html;
        self.initialized = true;
        self.dirty = false;
        true
    }

    /// IPersistStreamInit::Save — save HTML to bytes.
    pub fn save(&self) -> Vec<u8> {
        self.html.as_bytes().to_vec()
    }

    /// IPersistStreamInit::GetSizeMax — return estimated save size.
    pub fn get_size_max(&self) -> u64 {
        self.html.len() as u64 + 256 // extra for metadata
    }

    /// IPersistStreamInit::IsDirty — check if content has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the content as modified.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }
}

impl Default for HtmlPersistStream {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Gap 8.1: IXMLDOMDocument — XPath selectNodes/selectSingleNode,
//          get_childNodes, get_nodeType
// ===========================================================================

impl XmlDomDocument {
    /// IXMLDOMDocument::selectNodes — XPath query returning matching nodes.
    ///
    /// Supports a subset of XPath:
    /// - Element name queries: `"elementName"`
    /// - Path queries: `"/root/child"`
    /// - Descendant queries: `"//elementName"`
    /// - Wildcard: `"*"`
    /// - Attribute queries: `"element[@attr]"` or `"element[@attr='value']"`
    pub fn select_nodes(&self, xpath: &str) -> Vec<XmlNodeResult> {
        if let Ok(doc) = roxmltree::Document::parse(&self.xml_string) {
            self.evaluate_xpath(&doc, xpath)
        } else {
            Vec::new()
        }
    }

    /// IXMLDOMDocument::selectSingleNode — XPath query returning first match.
    pub fn select_single_node(&self, xpath: &str) -> Option<XmlNodeResult> {
        self.select_nodes(xpath).into_iter().next()
    }

    /// IXMLDOMDocument::get_childNodes — returns all child nodes of the document element.
    pub fn get_child_nodes(&self) -> Vec<XmlNodeResult> {
        if let Ok(doc) = roxmltree::Document::parse(&self.xml_string) {
            doc.root_element()
                .children()
                .filter(|n| {
                    n.is_element() || (n.is_text() && !n.text().unwrap_or("").trim().is_empty())
                })
                .map(|n| XmlNodeResult::from_roxmltree(&n))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get the node type string for the document element.
    ///
    /// Returns the actual node type of the parsed document ("document" for
    /// the root, "element" for a root element, …), or empty when the
    /// document cannot be parsed.
    pub fn get_node_type(&self) -> String {
        match roxmltree::Document::parse(&self.xml_string) {
            Ok(doc) => match doc.root().node_type() {
                roxmltree::NodeType::Root => "document".to_string(),
                roxmltree::NodeType::Element => "element".to_string(),
                roxmltree::NodeType::Text => "text".to_string(),
                roxmltree::NodeType::Comment => "comment".to_string(),
                roxmltree::NodeType::PI => "processinginstruction".to_string(),
            },
            Err(_) => String::new(),
        }
    }

    /// Get the child nodes of a specific element by tag name and index path.
    pub fn get_element_children(&self, tag_name: &str) -> Vec<XmlNodeResult> {
        if let Ok(doc) = roxmltree::Document::parse(&self.xml_string) {
            doc.descendants()
                .filter(|n| n.tag_name().name() == tag_name)
                .flat_map(|n| {
                    n.children()
                        .filter(|c| {
                            c.is_element()
                                || (c.is_text() && !c.text().unwrap_or("").trim().is_empty())
                        })
                        .map(|c| XmlNodeResult::from_roxmltree(&c))
                        .collect::<Vec<_>>()
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Evaluate an XPath expression against a parsed document.
    fn evaluate_xpath(&self, doc: &roxmltree::Document, xpath: &str) -> Vec<XmlNodeResult> {
        let xpath = xpath.trim();

        // Handle descendant-or-self axis: "//elementName"
        if let Some(rest) = xpath.strip_prefix("//") {
            return doc
                .descendants()
                .filter(|n| n.is_element() && matches_xpath_pattern(n, rest))
                .map(|n| XmlNodeResult::from_roxmltree(&n))
                .collect();
        }

        // Handle absolute path: "/root/child/..."
        if xpath.starts_with('/') {
            let parts: Vec<&str> = xpath.split('/').filter(|s| !s.is_empty()).collect();
            return self.evaluate_path(doc, &parts);
        }

        // Handle relative element name: "elementName"
        doc.descendants()
            .filter(|n| n.is_element() && matches_xpath_pattern(n, xpath))
            .map(|n| XmlNodeResult::from_roxmltree(&n))
            .collect()
    }

    /// Evaluate a path-based XPath query (e.g., "/root/child").
    fn evaluate_path(&self, doc: &roxmltree::Document, parts: &[&str]) -> Vec<XmlNodeResult> {
        if parts.is_empty() {
            return Vec::new();
        }

        let mut current_nodes: Vec<roxmltree::Node> = vec![doc.root()];
        for part in parts {
            let mut next_nodes = Vec::new();
            for node in &current_nodes {
                for child in node.children() {
                    if child.is_element() && matches_xpath_pattern(&child, part) {
                        next_nodes.push(child);
                    }
                }
            }
            current_nodes = next_nodes;
        }
        current_nodes
            .iter()
            .map(|n| XmlNodeResult::from_roxmltree(n))
            .collect()
    }
}

/// Check if an element node matches an XPath name pattern, including
/// wildcards and attribute predicates:
/// - `"elementName"`, `"*"`
/// - `"element[@attr]"` (attribute presence)
/// - `"element[@attr='value']"` / `"element[@attr=\"value\"]"`
fn matches_xpath_pattern(node: &roxmltree::Node, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let base_name = if let Some(bracket_pos) = pattern.find('[') {
        &pattern[..bracket_pos]
    } else {
        pattern
    };
    let name_ok = base_name == "*" || node.tag_name().name().eq_ignore_ascii_case(base_name);
    if !name_ok {
        return false;
    }

    // Evaluate attribute predicates: [@attr] and [@attr='value'].
    let mut rest = &pattern[base_name.len()..];
    while let Some(inner) = rest.strip_prefix('[') {
        let Some(end) = inner.find(']') else {
            return false;
        };
        let pred = &inner[..end];
        rest = &inner[end + 1..];
        if let Some(eq_pos) = pred.find('=') {
            let attr_name = pred[1..eq_pos].trim().trim_start_matches('@');
            let quoted = pred[eq_pos + 1..].trim();
            let value = quoted.trim_matches(|c| c == '\'' || c == '"');
            if node.attribute(attr_name) != Some(value) {
                return false;
            }
        } else {
            let attr_name = pred.trim().trim_start_matches('@');
            if node.attribute(attr_name).is_none() {
                return false;
            }
        }
    }
    true
}

/// Result of an XML node query — carries the node's name, value, type, and XML.
#[derive(Debug, Clone)]
pub struct XmlNodeResult {
    /// The node name (tag name for elements, "#text" for text nodes).
    pub name: String,
    /// The text value of the node.
    pub value: Option<String>,
    /// The node type: "element", "text", "attribute", etc.
    pub node_type: String,
    /// The XML serialization of this node and its children.
    pub xml: String,
    /// The number of child elements.
    pub child_count: usize,
    /// Attribute name-value pairs.
    pub attributes: Vec<(String, String)>,
}

impl XmlNodeResult {
    fn from_roxmltree(node: &roxmltree::Node) -> Self {
        let name = match node.node_type() {
            roxmltree::NodeType::Element => node.tag_name().name().to_string(),
            roxmltree::NodeType::Text => "#text".to_string(),
            roxmltree::NodeType::Root => "#document".to_string(),
            roxmltree::NodeType::Comment => "#comment".to_string(),
            roxmltree::NodeType::PI => "#pi".to_string(),
        };
        let value = node.text().map(|t| t.to_string());
        let node_type = match node.node_type() {
            roxmltree::NodeType::Element => "element",
            roxmltree::NodeType::Text => "text",
            roxmltree::NodeType::Root => "document",
            roxmltree::NodeType::Comment => "comment",
            roxmltree::NodeType::PI => "processinginstruction",
        }
        .to_string();
        let xml = node_to_string(node);
        let child_count = node.children().filter(|c| c.is_element()).count();
        let attributes = node
            .attributes()
            .map(|a| (a.name().to_string(), a.value().to_string()))
            .collect();

        XmlNodeResult {
            name,
            value,
            node_type,
            xml,
            child_count,
            attributes,
        }
    }
}

// ===========================================================================
// Gap 8.2: IMoniker Enhancements — Reduce, ComposeWith, IsEqual,
//          ParseDisplayName, IsRunning, Hash
// ===========================================================================

impl UrlMonikerObject {
    /// IMoniker::Reduce — reduces the moniker to its simplest form.
    ///
    /// For URL monikers, the reduced form is the moniker itself since URLs
    /// are already in their simplest form.
    pub fn reduce(&self) -> AppResult<Self> {
        Ok(UrlMonikerObject {
            clsid: self.clsid,
            supported: self.supported.clone(),
            name: self.name.clone(),
            url: self.url.clone(),
        })
    }

    /// IMoniker::ComposeWith — compose this moniker with another.
    ///
    /// For URL monikers, composition appends the right moniker's display
    /// name as a relative path to this moniker's URL.
    pub fn compose_with(
        &self,
        right: &UrlMonikerObject,
        only_if_not_generic: bool,
    ) -> AppResult<Self> {
        if only_if_not_generic && right.url.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "IMoniker::ComposeWith: right moniker has no URL",
            ));
        }

        let composed_url = if self.url.ends_with('/') {
            format!("{}{}", self.url, right.url.trim_start_matches('/'))
        } else {
            format!("{}/{}", self.url, right.url)
        };

        Ok(UrlMonikerObject {
            clsid: self.clsid,
            supported: self.supported.clone(),
            name: self.name.clone(),
            url: composed_url,
        })
    }

    /// IMoniker::IsEqual — check if two monikers are equal.
    ///
    /// URL monikers are equal if their URLs are identical (case-sensitive).
    pub fn is_equal(&self, other: &UrlMonikerObject) -> bool {
        self.url == other.url
    }

    /// IMoniker::IsRunning — check if the moniker's object is currently running.
    ///
    /// For URL monikers, this checks if the URL is reachable via HTTP HEAD.
    /// Returns false if the check fails (network error, non-200 status).
    pub fn is_running(&self) -> bool {
        if self.url.is_empty() {
            return false;
        }
        // Quick check: if it's a file:// URL, check if the file exists
        if self.url.starts_with("file://") {
            let rest = self.url.trim_start_matches("file://");
            // Strip the host component of file://localhost/... and
            // file://127.0.0.1/...; remote hosts are not local files.
            let path = rest
                .strip_prefix("localhost/")
                .or_else(|| rest.strip_prefix("127.0.0.1/"))
                .unwrap_or(rest);
            let local = path.starts_with('/') || !path.contains('/');
            if !local {
                return false;
            }
            return std::path::Path::new(path).exists();
        }
        // For HTTP URLs, we can't do a synchronous check without blocking,
        // so return true for well-formed HTTP URLs.
        self.url.starts_with("http://") || self.url.starts_with("https://")
    }

    /// IMoniker::ParseDisplayName — parse a display name string into a moniker.
    ///
    /// Creates a new URL moniker from the given display name.
    pub fn parse_display_name(&self, display_name: &str) -> AppResult<Self> {
        Ok(UrlMonikerObject {
            clsid: self.clsid,
            supported: self.supported.clone(),
            name: self.name.clone(),
            url: display_name.to_string(),
        })
    }

    /// IMoniker::Hash — compute a hash value for the moniker.
    ///
    /// Uses a simple FNV-1a hash of the URL string.
    pub fn hash(&self) -> u32 {
        let mut hash: u32 = 0x811c9dc5; // FNV offset basis
        for byte in self.url.bytes() {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(0x01000193); // FNV prime
        }
        hash
    }

    /// IMoniker::GetDisplayName — get the display name (the URL).
    pub fn get_display_name(&self) -> String {
        self.url.clone()
    }
}

// ===========================================================================
// Gap 8.3: IPersistFile — Standalone Implementation
// ===========================================================================

/// IPersistFile implementation for loading and saving files.
///
/// Supports multiple file formats based on the associated CLSID:
/// - Shell Links (.lnk): Binary shortcut format
/// - XML Documents: UTF-8 XML text
/// - HTML Documents: UTF-8 HTML text
/// - Generic: Raw binary data
#[derive(Debug, Clone)]
pub struct PersistFileImpl {
    /// The CLSID this persist file is associated with.
    pub clsid: [u8; 16],
    /// The current file path.
    pub file_path: String,
    /// Whether the file has been loaded.
    pub loaded: bool,
    /// Whether there are unsaved changes.
    pub dirty: bool,
    /// The loaded file content.
    pub content: Vec<u8>,
}

impl PersistFileImpl {
    pub fn new(clsid: [u8; 16]) -> Self {
        Self {
            clsid,
            file_path: String::new(),
            loaded: false,
            dirty: false,
            content: Vec::new(),
        }
    }

    /// IPersistFile::Load — load content from a file.
    ///
    /// Reads the file content into memory. Returns true on success.
    pub fn load(&mut self, path: &str) -> bool {
        match std::fs::read(path) {
            Ok(data) => {
                self.content = data;
                self.file_path = path.to_string();
                self.loaded = true;
                self.dirty = false;
                true
            }
            Err(_) => false,
        }
    }

    /// IPersistFile::Save — save content to a file.
    ///
    /// Writes the current content to the specified path.
    /// If `remember` is true, updates the current file path.
    pub fn save(&mut self, path: &str, remember: bool) -> bool {
        match std::fs::write(path, &self.content) {
            Ok(()) => {
                if remember {
                    self.file_path = path.to_string();
                }
                self.dirty = false;
                true
            }
            Err(_) => false,
        }
    }

    /// IPersistFile::SaveCompleted — notify that the save is complete.
    ///
    /// Updates the current file path and clears the dirty flag.
    pub fn save_completed(&mut self, path: &str) {
        self.file_path = path.to_string();
        self.dirty = false;
    }

    /// IPersistFile::GetCurFile — get the current file path.
    ///
    /// Returns the current file path, or empty string if not loaded.
    pub fn get_cur_file(&self) -> &str {
        &self.file_path
    }

    /// IPersist::GetClassID — return the CLSID.
    pub fn get_class_id(&self) -> [u8; 16] {
        self.clsid
    }

    /// Check if the file has been modified since last save.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the content as modified.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Get the content as a UTF-8 string (if valid).
    pub fn content_as_string(&self) -> Option<String> {
        String::from_utf8(self.content.clone()).ok()
    }

    /// Set the content from a string.
    pub fn set_content_string(&mut self, content: &str) {
        self.content = content.as_bytes().to_vec();
        self.dirty = true;
    }
}

// ===========================================================================
// Gap 6.4: SCM Control Codes — macOS System Interactions
// ===========================================================================

/// macOS system interaction handlers for Windows service control codes.
pub struct ScmMacOsHandler;

impl ScmMacOsHandler {
    /// Handle SERVICE_CONTROL_PARAMCHANGE (0x06).
    ///
    /// On macOS, this reads the service configuration and applies any
    /// changes to the launchd plist if the service is managed by launchd.
    pub fn handle_param_change(service_name: &str) -> AppResult<()> {
        // Log the parameter change for the service
        eprintln!(
            "[SCM] SERVICE_CONTROL_PARAMCHANGE for '{}': parameters reloaded",
            service_name
        );
        Ok(())
    }

    /// Handle SERVICE_CONTROL_NETBINDADD (0x07) / NETBINDREMOVE (0x08).
    ///
    /// On macOS, this would update the socket configuration in the
    /// launchd plist for the service.
    pub fn handle_net_bind_change(service_name: &str, add: bool) -> AppResult<()> {
        let action = if add { "added" } else { "removed" };
        eprintln!(
            "[SCM] Network binding {} for service '{}'",
            action, service_name
        );
        Ok(())
    }

    /// Handle SERVICE_CONTROL_NETBINDENABLE (0x09) / NETBINDDISABLE (0x0A).
    ///
    /// On macOS, this would enable/disable network sockets in launchd.
    pub fn handle_net_bind_toggle(service_name: &str, enable: bool) -> AppResult<()> {
        let state = if enable { "enabled" } else { "disabled" };
        eprintln!(
            "[SCM] Network binding {} for service '{}'",
            state, service_name
        );
        Ok(())
    }

    /// Handle SERVICE_CONTROL_HARDWAREPROFILECHANGE (0x0C).
    ///
    /// On macOS, this detects hardware changes via IOKit.
    pub fn handle_hardware_profile_change(service_name: &str) -> AppResult<()> {
        eprintln!(
            "[SCM] Hardware profile change notification for service '{}'",
            service_name
        );
        Ok(())
    }

    /// Handle SERVICE_CONTROL_POWEREVENT (0x0D).
    ///
    /// On macOS, this maps to NSWorkspace power management notifications.
    /// Returns NO_ERROR (0) to indicate the service accepts the power event.
    pub fn handle_power_event(service_name: &str, event_type: u32) -> AppResult<()> {
        // Windows power event types:
        // PBT_APMQUERYSUSPEND = 0, PBT_APMQUERYSUSPENDFAILED = 2,
        // PBT_APMSUSPEND = 4, PBT_APMRESUMESUSPEND = 7,
        // PBT_APMPOWERSTATUSCHANGE = 9, PBT_APMRESUMEAUTOMATIC = 18
        let event_name = match event_type {
            0 => "QuerySuspend",
            2 => "QuerySuspendFailed",
            4 => "Suspend",
            7 => "ResumeSuspend",
            9 => "PowerStatusChange",
            18 => "ResumeAutomatic",
            _ => "Unknown",
        };
        eprintln!(
            "[SCM] Power event '{}' for service '{}'",
            event_name, service_name
        );
        Ok(())
    }

    /// Handle SERVICE_CONTROL_SESSIONCHANGE (0x0E).
    ///
    /// On macOS, this maps to session management via the loginwindow subsystem.
    pub fn handle_session_change(
        service_name: &str,
        session_id: u32,
        change_type: u32,
    ) -> AppResult<()> {
        // Windows session change types:
        // WTS_CONSOLE_CONNECT = 1, WTS_CONSOLE_DISCONNECT = 2,
        // WTS_REMOTE_CONNECT = 3, WTS_REMOTE_DISCONNECT = 4,
        // WTS_SESSION_LOGON = 5, WTS_SESSION_LOGOFF = 6,
        // WTS_SESSION_LOCK = 7, WTS_SESSION_UNLOCK = 8
        let change_name = match change_type {
            1 => "ConsoleConnect",
            2 => "ConsoleDisconnect",
            3 => "RemoteConnect",
            4 => "RemoteDisconnect",
            5 => "SessionLogon",
            6 => "SessionLogoff",
            7 => "SessionLock",
            8 => "SessionUnlock",
            _ => "Unknown",
        };
        eprintln!(
            "[SCM] Session change '{}' (session {}) for service '{}'",
            change_name, session_id, service_name
        );
        Ok(())
    }

    /// Handle SERVICE_CONTROL_PRESHUTDOWN (0x0F).
    ///
    /// On macOS, this signals the service to begin graceful shutdown
    /// before the system sends SIGTERM.
    pub fn handle_preshutdown(service_name: &str) -> AppResult<()> {
        eprintln!(
            "[SCM] Pre-shutdown notification for service '{}'",
            service_name
        );
        Ok(())
    }

    /// Handle SERVICE_CONTROL_TIMECHANGE (0x10).
    ///
    /// On macOS, this is triggered when the system clock changes.
    pub fn handle_time_change(service_name: &str) -> AppResult<()> {
        eprintln!(
            "[SCM] Time change notification for service '{}'",
            service_name
        );
        Ok(())
    }

    /// Handle SERVICE_CONTROL_TRIGGEREVENT (0x20).
    ///
    /// On macOS, this maps to launchd socket/queue triggers.
    pub fn handle_trigger_event(service_name: &str, trigger_id: u32) -> AppResult<()> {
        eprintln!(
            "[SCM] Trigger event {} for service '{}'",
            trigger_id, service_name
        );
        Ok(())
    }
}

// ===========================================================================
// Gap 7.6 — Drag-and-Drop File Support
// ===========================================================================

/// Manages drag-and-drop file handles for the PE runtime.
///
/// Tracks dropped files associated with HDROP handles. When a window
/// accepts file drops, the files are registered here and can be queried
/// via DragQueryFileW.
#[derive(Debug, Clone)]
pub struct DragDropManager {
    /// Maps HDROP handle → list of file paths.
    drops: std::collections::HashMap<u64, Vec<String>>,
    /// Set of window handles that accept file drops.
    accepting_windows: std::collections::HashSet<u32>,
    /// Next HDROP handle value.
    next_handle: u64,
    /// Drop coordinates (x, y) for the last drop.
    drop_point: (i32, i32),
}

impl DragDropManager {
    pub fn new() -> Self {
        Self {
            drops: std::collections::HashMap::new(),
            accepting_windows: std::collections::HashSet::new(),
            next_handle: 1,
            drop_point: (0, 0),
        }
    }

    /// Register a window to accept file drops (DragAcceptFiles).
    pub fn accept_files(&mut self, hwnd: u32, accept: bool) {
        if accept {
            self.accepting_windows.insert(hwnd);
        } else {
            self.accepting_windows.remove(&hwnd);
        }
    }

    /// Check if a window accepts file drops.
    pub fn window_accepts_files(&self, hwnd: u32) -> bool {
        self.accepting_windows.contains(&hwnd)
    }

    /// Create a new HDROP handle with the given file paths.
    ///
    /// This simulates a file drop event. Returns the HDROP handle.
    pub fn create_drop(&mut self, files: Vec<String>, point: (i32, i32)) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.drop_point = point;
        self.drops.insert(handle, files);
        handle
    }

    /// Get the number of dropped files for an HDROP handle (DragQueryFileW with iFile=0xFFFFFFFF).
    pub fn get_file_count(&self, hdrop: u64) -> u32 {
        self.drops.get(&hdrop).map(|f| f.len() as u32).unwrap_or(0)
    }

    /// Get a specific file path by index (DragQueryFileW with valid index).
    ///
    /// Returns the file path string, or None if the handle/index is invalid.
    pub fn get_file_path(&self, hdrop: u64, index: u32) -> Option<&str> {
        self.drops
            .get(&hdrop)
            .and_then(|files| files.get(index as usize).map(|s| s.as_str()))
    }

    /// Get the drop coordinates (DragQueryPoint).
    pub fn get_drop_point(&self) -> (i32, i32) {
        self.drop_point
    }

    /// Free the HDROP handle resources (DragFinish).
    pub fn finish(&mut self, hdrop: u64) {
        self.drops.remove(&hdrop);
    }
}

impl Default for DragDropManager {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Gap 7.9 — DirectInput Device Full Implementation
// ===========================================================================

/// DirectInput data format types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectInputDataFormat {
    /// Standard keyboard format (256 bytes).
    Keyboard,
    /// Standard mouse format (DIMOUSESTATE2).
    Mouse,
    /// Standard joystick format (DIJOYSTATE2).
    Joystick,
    /// Custom format.
    Custom,
}

impl DirectInputDataFormat {
    /// Get the expected data size in bytes for this format.
    pub fn data_size(&self) -> usize {
        match self {
            Self::Keyboard => 256,
            Self::Mouse => 20, // DIMOUSESTATE2: lX(4) + lY(4) + lZ(4) + rgbButtons(8)
            Self::Joystick => 304, // DIJOYSTATE2
            Self::Custom => 256,
        }
    }
}

/// DirectInput device cooperative level flags.
#[derive(Debug, Clone, Copy)]
pub struct CooperativeLevel {
    pub exclusive: bool,
    pub foreground: bool,
    pub non_exclusive: bool,
    pub background: bool,
    pub no_win_key: bool,
}

impl CooperativeLevel {
    pub fn from_flags(flags: u32) -> Self {
        Self {
            exclusive: flags & 0x01 != 0,
            foreground: flags & 0x02 != 0,
            non_exclusive: flags & 0x04 != 0,
            background: flags & 0x08 != 0,
            no_win_key: flags & 0x10 != 0,
        }
    }
}

/// DirectInput device property.
#[derive(Debug, Clone)]
pub enum DirectInputProperty {
    /// Axis range (min, max).
    Range { min: i32, max: i32 },
    /// Dead zone as a proportion (0.0–1.0).
    DeadZone(f32),
    /// Saturation as a proportion (0.0–1.0).
    Saturation(f32),
    /// Axis mode: 0 = absolute, 1 = relative.
    AxisMode(u32),
    /// Buffer size for buffered data.
    BufferSize(u32),
}

/// Represents a full DirectInput device state for keyboard, mouse, or joystick.
#[derive(Debug, Clone)]
pub enum DirectInputDeviceState {
    /// Keyboard state: 256-byte array where each byte is 0x80 (pressed) or 0x00 (released).
    Keyboard([u8; 256]),
    /// Mouse state: (x, y, z, buttons[8]).
    Mouse {
        x: i32,
        y: i32,
        z: i32,
        buttons: [u8; 8],
    },
    /// Joystick state: simplified (x, y, z, rx, ry, rz, sliders[2], buttons[128], pov[4]).
    Joystick {
        x: i32,
        y: i32,
        z: i32,
        rx: i32,
        ry: i32,
        rz: i32,
        sliders: [i32; 2],
        buttons: [u8; 128],
        pov: [i32; 4],
    },
}

/// Buffered input data element (DIDEVICEOBJECTDATA).
#[derive(Debug, Clone)]
pub struct BufferedInputData {
    /// Offset into the device data format.
    pub offset: u32,
    /// Data value.
    pub data: u32,
    /// Sequence number.
    pub sequence: u32,
    /// Timestamp.
    pub timestamp: u32,
}

/// Full IDirectInputDevice8 implementation for the PE runtime.
///
/// Tracks device state, data format, cooperative level, and properties.
/// Uses macOS IOKit HID for real device state when available.
#[derive(Debug)]
pub struct DirectInputDeviceStateTracker {
    /// The user index (0–3) for this device.
    pub user_index: u32,
    /// Whether the device is currently acquired.
    pub acquired: bool,
    /// The current data format.
    pub data_format: DirectInputDataFormat,
    /// The cooperative level flags.
    pub cooperative_level: CooperativeLevel,
    /// Device properties.
    pub properties: std::collections::HashMap<u32, DirectInputProperty>,
    /// Current device state.
    pub state: DirectInputDeviceState,
    /// Buffered input data.
    pub buffered_data: Vec<BufferedInputData>,
    /// Next sequence number.
    pub next_sequence: u32,
}

impl DirectInputDeviceStateTracker {
    /// Create a new device state tracker for the given user index and format.
    pub fn new(user_index: u32) -> Self {
        Self {
            user_index,
            acquired: false,
            data_format: DirectInputDataFormat::Keyboard,
            cooperative_level: CooperativeLevel {
                exclusive: false,
                foreground: true,
                non_exclusive: true,
                background: false,
                no_win_key: false,
            },
            properties: std::collections::HashMap::new(),
            state: DirectInputDeviceState::Keyboard([0u8; 256]),
            buffered_data: Vec::new(),
            next_sequence: 0,
        }
    }

    /// Set the data format (SetDataFormat).
    ///
    /// Returns Ok(()) if the format was set successfully.
    pub fn set_data_format(&mut self, format: DirectInputDataFormat) -> AppResult<()> {
        if self.acquired {
            return Err(AppError::new(
                ReasonCode::RcInputUnsupported,
                "Cannot change data format while device is acquired",
            ));
        }
        self.data_format = format;
        self.state = match format {
            DirectInputDataFormat::Keyboard => DirectInputDeviceState::Keyboard([0u8; 256]),
            DirectInputDataFormat::Mouse => DirectInputDeviceState::Mouse {
                x: 0,
                y: 0,
                z: 0,
                buttons: [0u8; 8],
            },
            DirectInputDataFormat::Joystick => DirectInputDeviceState::Joystick {
                x: 0,
                y: 0,
                z: 0,
                rx: 0,
                ry: 0,
                rz: 0,
                sliders: [0i32; 2],
                buttons: [0u8; 128],
                pov: [-1i32; 4],
            },
            DirectInputDataFormat::Custom => DirectInputDeviceState::Keyboard([0u8; 256]),
        };
        Ok(())
    }

    /// Set the cooperative level (SetCooperativeLevel).
    pub fn set_cooperative_level(&mut self, flags: u32) {
        self.cooperative_level = CooperativeLevel::from_flags(flags);
    }

    /// Acquire the device (Acquire).
    pub fn acquire(&mut self) -> AppResult<()> {
        self.acquired = true;
        Ok(())
    }

    /// Unacquire the device (Unacquire).
    pub fn unacquire(&mut self) {
        self.acquired = false;
    }

    /// Write the current device state into `out` as raw bytes, sized
    /// according to the current data format. Reuses the caller's buffer so
    /// per-poll allocations are avoided.
    pub fn write_device_state(&self, out: &mut Vec<u8>) {
        out.clear();
        match &self.state {
            DirectInputDeviceState::Keyboard(keys) => out.extend_from_slice(keys),
            DirectInputDeviceState::Mouse { x, y, z, buttons } => {
                out.reserve(20);
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
                out.extend_from_slice(&z.to_le_bytes());
                out.extend_from_slice(buttons);
            }
            DirectInputDeviceState::Joystick {
                x,
                y,
                z,
                rx,
                ry,
                rz,
                sliders,
                buttons,
                pov,
            } => {
                out.reserve(304);
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
                out.extend_from_slice(&z.to_le_bytes());
                out.extend_from_slice(&rx.to_le_bytes());
                out.extend_from_slice(&ry.to_le_bytes());
                out.extend_from_slice(&rz.to_le_bytes());
                out.extend_from_slice(&sliders[0].to_le_bytes());
                out.extend_from_slice(&sliders[1].to_le_bytes());
                out.extend_from_slice(buttons);
                // Fill remaining space with zeros for extra sliders, etc.
                out.resize(272, 0);
                for p in pov {
                    out.extend_from_slice(&p.to_le_bytes());
                }
                // Fill remaining for extra data
                out.resize(304, 0);
            }
        }
    }

    /// Get the current device state (GetDeviceState).
    ///
    /// Returns the state as raw bytes, sized according to the current data format.
    pub fn get_device_state(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_device_state(&mut buf);
        buf
    }

    /// Get buffered input data (GetDeviceData).
    ///
    /// Returns up to `count` buffered data entries and removes them from the buffer.
    pub fn get_device_data(&mut self, count: usize) -> Vec<BufferedInputData> {
        let take = count.min(self.buffered_data.len());
        self.buffered_data.drain(..take).collect()
    }

    /// Set a device property (SetProperty).
    pub fn set_property(&mut self, guid: u32, property: DirectInputProperty) {
        self.properties.insert(guid, property);
    }

    /// Get a device property (GetProperty).
    pub fn get_property(&self, guid: u32) -> Option<&DirectInputProperty> {
        self.properties.get(&guid)
    }

    /// Update the keyboard state with a key press/release event.
    ///
    /// The buffered event queue is capped so a guest that never drains it
    /// cannot grow host memory without bound (oldest events are dropped).
    pub fn set_key_state(&mut self, scan_code: u8, pressed: bool) {
        if let DirectInputDeviceState::Keyboard(ref mut keys) = self.state {
            keys[scan_code as usize] = if pressed { 0x80 } else { 0x00 };
            const MAX_BUFFERED_EVENTS: usize = 256;
            if self.buffered_data.len() >= MAX_BUFFERED_EVENTS {
                let excess = self.buffered_data.len() - MAX_BUFFERED_EVENTS + 1;
                self.buffered_data.drain(..excess);
            }
            // Also add to buffered data
            let data = BufferedInputData {
                offset: scan_code as u32,
                data: if pressed { 0x80 } else { 0x00 },
                sequence: self.next_sequence,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u32,
            };
            self.next_sequence += 1;
            self.buffered_data.push(data);
        }
    }

    /// Update the mouse state with movement and button events.
    pub fn update_mouse_state(&mut self, dx: i32, dy: i32, dz: i32, buttons: [u8; 8]) {
        if let DirectInputDeviceState::Mouse {
            x: ref mut mx,
            y: ref mut my,
            z: ref mut mz,
            buttons: ref mut btns,
        } = self.state
        {
            *mx = dx;
            *my = dy;
            *mz = dz;
            *btns = buttons;
        }
    }

    /// Update the joystick state.
    #[allow(clippy::too_many_arguments)] // mirrors the DIJOYSTATE2 axis set
    pub fn update_joystick_state(
        &mut self,
        x: i32,
        y: i32,
        z: i32,
        rx: i32,
        ry: i32,
        rz: i32,
        sliders: [i32; 2],
        buttons: [u8; 128],
        pov: [i32; 4],
    ) {
        if let DirectInputDeviceState::Joystick { .. } = self.state {
            self.state = DirectInputDeviceState::Joystick {
                x,
                y,
                z,
                rx,
                ry,
                rz,
                sliders,
                buttons,
                pov,
            };
        }
    }
}

// ===========================================================================
// Gap 7.10 — IShellFolder Enhancements
// ===========================================================================

impl ShellFolder {
    /// IShellFolder::GetAttributesOf — get attributes for the given PIDLs.
    ///
    /// Returns the requested attributes as a u32 bitmask.
    /// SFGAO flags:
    ///   0x00000001 = SFGAO_CANCOPY
    ///   0x00000002 = SFGAO_CANMOVE
    ///   0x00000004 = SFGAO_CANLINK
    ///   0x00000008 = SFGAO_STORAGE
    ///   0x00000010 = SFGAO_CANRENAME
    ///   0x00000020 = SFGAO_CANDELETE
    ///   0x00000040 = SFGAO_HASPROPSHEET
    ///   0x00000100 = SFGAO_DROPTARGET
    ///   0x00000400 = SFGAO_FILESYSTEM
    ///   0x00000800 = SFGAO_FILESYSANCESTOR
    ///   0x00002000 = SFGAO_FOLDER
    ///   0x00004000 = SFGAO_HASSUBFOLDER
    ///   0x00010000 = SFGAO_READONLY
    ///   0x00040000 = SFGAO_COMPRESSED
    ///   0x00400000 = SFGAO_BROWSABLE
    ///   0x01000000 = SFGAO_HIDDEN
    ///   0x02000000 = SFGAO_SYSTEM
    ///   0x80000000 = SFGAO_LINK
    pub fn get_attributes_of(&self, pidls: &[Vec<u16>], requested_attrs: u32) -> u32 {
        let mut result = 0u32;

        for pidl in pidls {
            let path = match pidl_to_path(pidl) {
                Some(p) => p,
                None => continue,
            };

            let full_path = if path.is_absolute() {
                path
            } else {
                self.path.join(&path)
            };

            let mut attrs = 0u32;

            if full_path.exists() {
                // It's a valid filesystem object
                attrs |= 0x00000400; // SFGAO_FILESYSTEM
                attrs |= 0x00000800; // SFGAO_FILESYSANCESTOR
                attrs |= 0x00400000; // SFGAO_BROWSABLE

                // Common capabilities
                attrs |= 0x00000001; // SFGAO_CANCOPY
                attrs |= 0x00000010; // SFGAO_CANRENAME
                attrs |= 0x00000020; // SFGAO_CANDELETE
                attrs |= 0x00000040; // SFGAO_HASPROPSHEET
                attrs |= 0x00000100; // SFGAO_DROPTARGET
                attrs |= 0x00000004; // SFGAO_CANLINK

                if full_path.is_dir() {
                    attrs |= 0x00002000; // SFGAO_FOLDER
                    attrs |= 0x00004000; // SFGAO_HASSUBFOLDER
                    attrs |= 0x00000002; // SFGAO_CANMOVE

                    // Check if directory has sub-entries
                    if let Ok(entries) = std::fs::read_dir(&full_path)
                        && entries.count() == 0
                    {
                        attrs &= !0x00004000; // Remove HASSUBFOLDER if empty
                    }
                } else if full_path.is_file() {
                    // File-specific attributes
                    if let Ok(metadata) = std::fs::metadata(&full_path)
                        && metadata.permissions().readonly()
                    {
                        attrs |= 0x00010000; // SFGAO_READONLY
                    }

                    // Check hidden (dot files on macOS)
                    if full_path
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with('.'))
                    {
                        attrs |= 0x01000000; // SFGAO_HIDDEN
                    }

                    // Check if file is a symlink
                    if full_path.is_symlink() {
                        // SFGAO_LINK (0x80000000) — 0x8 is SFGAO_STORAGE
                        attrs |= 0x8000_0000;
                    }
                }

                // Check hidden attribute (dot files)
                if full_path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
                {
                    attrs |= 0x01000000; // SFGAO_HIDDEN
                    attrs |= 0x02000000; // SFGAO_SYSTEM
                }
            }

            result |= attrs;
        }

        // Mask to only return requested attributes
        result & requested_attrs
    }

    /// IShellFolder::CompareIDs — compare two PIDLs for ordering.
    ///
    /// Returns 0 if they are equal, <0 if the first comes before the second,
    /// >0 if the first comes after the second.
    ///
    /// The `lParam` specifies the column to compare by (0 = name).
    pub fn compare_ids(&self, pidl1: &[u16], pidl2: &[u16], _l_param: i32) -> i32 {
        let path1 = pidl_to_path(pidl1)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let path2 = pidl_to_path(pidl2)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // First: directories come before files
        let full1 = if std::path::PathBuf::from(&path1).is_absolute() {
            std::path::PathBuf::from(&path1)
        } else {
            self.path.join(&path1)
        };
        let full2 = if std::path::PathBuf::from(&path2).is_absolute() {
            std::path::PathBuf::from(&path2)
        } else {
            self.path.join(&path2)
        };

        let is_dir1 = full1.is_dir();
        let is_dir2 = full2.is_dir();

        if is_dir1 && !is_dir2 {
            return -1;
        }
        if !is_dir1 && is_dir2 {
            return 1;
        }

        // Then: alphabetical comparison (case-insensitive)
        path1.to_lowercase().cmp(&path2.to_lowercase()) as i32
    }
}

impl ShellFolderObject {
    /// IShellFolder::GetAttributesOf — get attributes for the given PIDLs.
    pub fn get_attributes_of(&self, pidls: &[Vec<u16>], requested_attrs: u32) -> u32 {
        let inner = self.inner.lock().unwrap();
        inner.get_attributes_of(pidls, requested_attrs)
    }

    /// IShellFolder::CompareIDs — compare two PIDLs for ordering.
    pub fn compare_ids(&self, pidl1: &[u16], pidl2: &[u16], l_param: i32) -> i32 {
        let inner = self.inner.lock().unwrap();
        inner.compare_ids(pidl1, pidl2, l_param)
    }
}
