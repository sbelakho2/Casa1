use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::real_hid::{HostController, HidMonitor};
use crate::util;
use serde::{Deserialize, Serialize};

// ── macOS CoreGraphics FFI for real keyboard state ──────────────────────
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn CGEventSourceFlagsState(sourceStateID: i32) -> u64;
}

#[cfg(target_os = "macos")]
const kCGEventSourceStatePrivate: i32 = -1;
#[cfg(target_os = "macos")]
const kCGEventSourceStateCombinedSessionState: i32 = 0;
#[cfg(target_os = "macos")]
const kCGEventSourceStateHIDSystemState: i32 = 1;

#[cfg(target_os = "macos")]
const kCGEventFlagMaskShift: u64 = 0x0002_0000;
#[cfg(target_os = "macos")]
const kCGEventFlagMaskControl: u64 = 0x0004_0000;
#[cfg(target_os = "macos")]
const kCGEventFlagMaskAlternate: u64 = 0x0008_0000;
#[cfg(target_os = "macos")]
const kCGEventFlagMaskCommand: u64 = 0x0010_0000;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

// ── Window style constants ──────────────────────────────────────────────
pub const WS_OVERLAPPED: u32 = 0x0000_0000;
pub const WS_POPUP: u32 = 0x8000_0000;
pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_MINIMIZE: u32 = 0x2000_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_DISABLED: u32 = 0x0800_0000;
pub const WS_CLIPSIBLINGS: u32 = 0x0400_0000;
pub const WS_CLIPCHILDREN: u32 = 0x0200_0000;
pub const WS_MAXIMIZE: u32 = 0x0100_0000;
pub const WS_CAPTION: u32 = 0x00C0_0000;
pub const WS_BORDER: u32 = 0x0080_0000;
pub const WS_DLGFRAME: u32 = 0x0040_0000;
pub const WS_VSCROLL: u32 = 0x0020_0000;
pub const WS_HSCROLL: u32 = 0x0010_0000;
pub const WS_SYSMENU: u32 = 0x0008_0000;
pub const WS_THICKFRAME: u32 = 0x0004_0000;
pub const WS_GROUP: u32 = 0x0002_0000;
pub const WS_TABSTOP: u32 = 0x0001_0000;
pub const WS_MINIMIZEBOX: u32 = 0x0002_0000;
pub const WS_MAXIMIZEBOX: u32 = 0x0001_0000;

// ── Extended window style constants ────────────────────────────────────
pub const WS_EX_DLGMODALFRAME: u32 = 0x0000_0001;
pub const WS_EX_NOPARENTNOTIFY: u32 = 0x0000_0004;
pub const WS_EX_TOPMOST: u32 = 0x0000_0008;
pub const WS_EX_ACCEPTFILES: u32 = 0x0000_0010;
pub const WS_EX_TRANSPARENT: u32 = 0x0000_0020;
pub const WS_EX_MDICHILD: u32 = 0x0000_0040;
pub const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
pub const WS_EX_WINDOWEDGE: u32 = 0x0000_0100;
pub const WS_EX_CLIENTEDGE: u32 = 0x0000_0200;
pub const WS_EX_OVERLAPPEDWINDOW: u32 = 0x0000_0300;
pub const WS_EX_CONTEXTHELP: u32 = 0x0000_0400;
pub const WS_EX_RIGHT: u32 = 0x0000_1000;
pub const WS_EX_LEFT: u32 = 0x0000_0000;
pub const WS_EX_RTLREADING: u32 = 0x0000_2000;
pub const WS_EX_LEFTSCROLLBAR: u32 = 0x0000_4000;
pub const WS_EX_CONTROLPARENT: u32 = 0x0001_0000;
pub const WS_EX_STATICEDGE: u32 = 0x0002_0000;
pub const WS_EX_APPWINDOW: u32 = 0x0004_0000;
pub const WS_EX_LAYERED: u32 = 0x0008_0000;
pub const WS_EX_NOINHERITLAYOUT: u32 = 0x0010_0000;
pub const WS_EX_NOREDIRECTIONBITMAP: u32 = 0x0020_0000;
pub const WS_EX_LAYOUTRTL: u32 = 0x0040_0000;
pub const WS_EX_COMPOSITED: u32 = 0x0200_0000;
pub const WS_EX_NOACTIVATE: u32 = 0x0800_0000;

// ── Virtual Key Code constants ───────────────────────────────────────────
pub const VK_LBUTTON: i32 = 0x01;
pub const VK_RBUTTON: i32 = 0x02;
pub const VK_CANCEL: i32 = 0x03;
pub const VK_MBUTTON: i32 = 0x04;
pub const VK_XBUTTON1: i32 = 0x05;
pub const VK_XBUTTON2: i32 = 0x06;
pub const VK_BACK: i32 = 0x08;
pub const VK_TAB: i32 = 0x09;
pub const VK_CLEAR: i32 = 0x0C;
pub const VK_RETURN: i32 = 0x0D;
pub const VK_SHIFT: i32 = 0x10;
pub const VK_CONTROL: i32 = 0x11;
pub const VK_MENU: i32 = 0x12;
pub const VK_PAUSE: i32 = 0x13;
pub const VK_CAPITAL: i32 = 0x14;
pub const VK_KANA: i32 = 0x15;
pub const VK_ESCAPE: i32 = 0x1B;
pub const VK_CONVERT: i32 = 0x1C;
pub const VK_NONCONVERT: i32 = 0x1D;
pub const VK_SPACE: i32 = 0x20;
pub const VK_PRIOR: i32 = 0x21;       // Page Up
pub const VK_NEXT: i32 = 0x22;        // Page Down
pub const VK_END: i32 = 0x23;
pub const VK_HOME: i32 = 0x24;
pub const VK_LEFT: i32 = 0x25;
pub const VK_UP: i32 = 0x26;
pub const VK_RIGHT: i32 = 0x27;
pub const VK_DOWN: i32 = 0x28;
pub const VK_SELECT: i32 = 0x29;
pub const VK_PRINT: i32 = 0x2A;
pub const VK_EXECUTE: i32 = 0x2B;
pub const VK_SNAPSHOT: i32 = 0x2C;     // Print Screen
pub const VK_INSERT: i32 = 0x2D;
pub const VK_DELETE: i32 = 0x2E;
pub const VK_HELP: i32 = 0x2F;
pub const VK_0: i32 = 0x30;
pub const VK_1: i32 = 0x31;
pub const VK_2: i32 = 0x32;
pub const VK_3: i32 = 0x33;
pub const VK_4: i32 = 0x34;
pub const VK_5: i32 = 0x35;
pub const VK_6: i32 = 0x36;
pub const VK_7: i32 = 0x37;
pub const VK_8: i32 = 0x38;
pub const VK_9: i32 = 0x39;
pub const VK_A: i32 = 0x41;
pub const VK_B: i32 = 0x42;
pub const VK_C: i32 = 0x43;
pub const VK_D: i32 = 0x44;
pub const VK_E: i32 = 0x45;
pub const VK_F: i32 = 0x46;
pub const VK_G: i32 = 0x47;
pub const VK_H: i32 = 0x48;
pub const VK_I: i32 = 0x49;
pub const VK_J: i32 = 0x4A;
pub const VK_K: i32 = 0x4B;
pub const VK_L: i32 = 0x4C;
pub const VK_M: i32 = 0x4D;
pub const VK_N: i32 = 0x4E;
pub const VK_O: i32 = 0x4F;
pub const VK_P: i32 = 0x50;
pub const VK_Q: i32 = 0x51;
pub const VK_R: i32 = 0x52;
pub const VK_S: i32 = 0x53;
pub const VK_T: i32 = 0x54;
pub const VK_U: i32 = 0x55;
pub const VK_V: i32 = 0x56;
pub const VK_W: i32 = 0x57;
pub const VK_X: i32 = 0x58;
pub const VK_Y: i32 = 0x59;
pub const VK_Z: i32 = 0x5A;
pub const VK_LWIN: i32 = 0x5B;
pub const VK_RWIN: i32 = 0x5C;
pub const VK_APPS: i32 = 0x5D;
pub const VK_SLEEP: i32 = 0x5F;
pub const VK_NUMPAD0: i32 = 0x60;
pub const VK_NUMPAD1: i32 = 0x61;
pub const VK_NUMPAD2: i32 = 0x62;
pub const VK_NUMPAD3: i32 = 0x63;
pub const VK_NUMPAD4: i32 = 0x64;
pub const VK_NUMPAD5: i32 = 0x65;
pub const VK_NUMPAD6: i32 = 0x66;
pub const VK_NUMPAD7: i32 = 0x67;
pub const VK_NUMPAD8: i32 = 0x68;
pub const VK_NUMPAD9: i32 = 0x69;
pub const VK_MULTIPLY: i32 = 0x6A;
pub const VK_ADD: i32 = 0x6B;
pub const VK_SEPARATOR: i32 = 0x6C;
pub const VK_SUBTRACT: i32 = 0x6D;
pub const VK_DECIMAL: i32 = 0x6E;
pub const VK_DIVIDE: i32 = 0x6F;
pub const VK_F1: i32 = 0x70;
pub const VK_F2: i32 = 0x71;
pub const VK_F3: i32 = 0x72;
pub const VK_F4: i32 = 0x73;
pub const VK_F5: i32 = 0x74;
pub const VK_F6: i32 = 0x75;
pub const VK_F7: i32 = 0x76;
pub const VK_F8: i32 = 0x77;
pub const VK_F9: i32 = 0x78;
pub const VK_F10: i32 = 0x79;
pub const VK_F11: i32 = 0x7A;
pub const VK_F12: i32 = 0x7B;
pub const VK_F13: i32 = 0x7C;
pub const VK_F14: i32 = 0x7D;
pub const VK_F15: i32 = 0x7E;
pub const VK_F16: i32 = 0x7F;
pub const VK_F17: i32 = 0x80;
pub const VK_F18: i32 = 0x81;
pub const VK_F19: i32 = 0x82;
pub const VK_F20: i32 = 0x83;
pub const VK_F21: i32 = 0x84;
pub const VK_F22: i32 = 0x85;
pub const VK_F23: i32 = 0x86;
pub const VK_F24: i32 = 0x87;
pub const VK_NUMLOCK: i32 = 0x90;
pub const VK_SCROLL: i32 = 0x91;
pub const VK_LSHIFT: i32 = 0xA0;
pub const VK_RSHIFT: i32 = 0xA1;
pub const VK_LCONTROL: i32 = 0xA2;
pub const VK_RCONTROL: i32 = 0xA3;
pub const VK_LMENU: i32 = 0xA4;
pub const VK_RMENU: i32 = 0xA5;
pub const VK_OEM_1: i32 = 0xBA;       // ;:
pub const VK_OEM_PLUS: i32 = 0xBB;    // =+
pub const VK_OEM_COMMA: i32 = 0xBC;   // ,<
pub const VK_OEM_MINUS: i32 = 0xBD;   // -_
pub const VK_OEM_PERIOD: i32 = 0xBE;  // .>
pub const VK_OEM_2: i32 = 0xBF;       // /?
pub const VK_OEM_3: i32 = 0xC0;       // `~
pub const VK_OEM_4: i32 = 0xDB;       // [{
pub const VK_OEM_5: i32 = 0xDC;       // \|
pub const VK_OEM_6: i32 = 0xDD;       // ]}
pub const VK_OEM_7: i32 = 0xDE;       // '"
pub const VK_OEM_8: i32 = 0xDF;

// ── MapVirtualKeyW map type constants ────────────────────────────────────
pub const MAPVK_VK_TO_VSC: u32 = 0;
pub const MAPVK_VSC_TO_VK: u32 = 1;
pub const MAPVK_VK_TO_CHAR: u32 = 2;
pub const MAPVK_VSC_TO_VK_EX: u32 = 3;
pub const MAPVK_VK_TO_VSC_EX: u32 = 4;

// ── Windows Hook constants ───────────────────────────────────────────────
pub const WH_JOURNALRECORD: i32 = 0;
pub const WH_JOURNALPLAYBACK: i32 = 1;
pub const WH_KEYBOARD: i32 = 2;
pub const WH_GETMESSAGE: i32 = 3;
pub const WH_CALLWNDPROC: i32 = 4;
pub const WH_CBT: i32 = 5;
pub const WH_SYSMSGFILTER: i32 = 6;
pub const WH_MOUSE: i32 = 7;
pub const WH_HARDWARE: i32 = 8;
pub const WH_DEBUG: i32 = 9;
pub const WH_SHELL: i32 = 10;
pub const WH_FOREGROUNDIDLE: i32 = 11;
pub const WH_CALLWNDPROCRET: i32 = 12;
pub const WH_KEYBOARD_LL: i32 = 13;
pub const WH_MOUSE_LL: i32 = 14;

// ── GW_* constants for GetWindow ────────────────────────────────────────
pub const GW_HWNDNEXT: u32 = 2;
pub const GW_HWNDPREV: u32 = 3;
pub const GW_OWNER: u32 = 4;
pub const GW_CHILD: u32 = 5;
pub const GW_ENABLEDPOPUP: u32 = 6;
pub const GW_MAX: u32 = 6;

// ── SWP flags for SetWindowPos ──────────────────────────────────────────
pub const SWP_NOSIZE: u32 = 0x0001;
pub const SWP_NOMOVE: u32 = 0x0002;
pub const SWP_NOZORDER: u32 = 0x0004;
pub const SWP_NOREDRAW: u32 = 0x0008;
pub const SWP_NOACTIVATE: u32 = 0x0010;
pub const SWP_FRAMECHANGED: u32 = 0x0020;
pub const SWP_SHOWWINDOW: u32 = 0x0040;
pub const SWP_HIDEWINDOW: u32 = 0x0080;
pub const SWP_NOCOPYBITS: u32 = 0x0100;
pub const SWP_NOOWNERZORDER: u32 = 0x0200;
pub const SWP_NOSENDCHANGING: u32 = 0x0400;
pub const SWP_DRAWFRAME: u32 = SWP_FRAMECHANGED;
pub const SWP_NOREPOSITION: u32 = SWP_NOOWNERZORDER;
pub const SWP_DEFERERASE: u32 = 0x2000;
pub const SWP_ASYNCWINDOWPOS: u32 = 0x4000;

// ── Special HWND values for SetWindowPos insert_after ───────────────────
pub const HWND_TOP: u32 = 0;
pub const HWND_BOTTOM: u32 = 1;
pub const HWND_TOPMOST: u32 = !0u32;  // -1 as u32
pub const HWND_NOTOPMOST: u32 = !1u32; // -2 as u32

// ── Tray icon / Shell_NotifyIcon constants ──────────────────────────────
pub const NIM_ADD: u32 = 0;
pub const NIM_MODIFY: u32 = 1;
pub const NIM_DELETE: u32 = 2;
pub const NIF_MESSAGE: u32 = 0x0001;
pub const NIF_ICON: u32 = 0x0002;
pub const NIF_TIP: u32 = 0x0004;
pub const NIF_STATE: u32 = 0x0008;
pub const NIF_INFO: u32 = 0x0010;
pub const NIF_GUID: u32 = 0x0020;
pub const NIF_REALTIME: u32 = 0x0040;
pub const NIF_SHOWTIP: u32 = 0x0080;

// ── NOTIFYICONDATAW structure version constants ─────────────────────────
pub const NOTIFYICON_VERSION: u32 = 3;
pub const NOTIFYICON_VERSION_4: u32 = 4;

pub type Atom = u16;
pub type Hwnd = u32;

pub const GWL_WNDPROC: i32 = -4;
pub const GWL_HWNDPARENT: i32 = -8;

// ── Touch window styles (RegisterTouchWindow flags) ──────────────────────
pub const TWF_FINETOUCH: u32 = 0x00000001;
pub const TWF_WANTPALM: u32 = 0x00000002;

// ── Touch input flags (TouchInput.flags) ─────────────────────────────────
pub const TOUCHEVENTF_MOVE: u32 = 0x0001;
pub const TOUCHEVENTF_DOWN: u32 = 0x0002;
pub const TOUCHEVENTF_UP: u32 = 0x0004;
pub const TOUCHEVENTF_INRANGE: u32 = 0x0008;
pub const TOUCHEVENTF_PRIMARY: u32 = 0x0010;
pub const TOUCHEVENTF_NOCOALESCE: u32 = 0x0020;
pub const TOUCHEVENTF_PEN: u32 = 0x0040;
pub const TOUCHEVENTF_PALM: u32 = 0x0080;

// ── Touch input mask flags (TouchInput.mask) ─────────────────────────────
pub const TOUCHINPUTMASKF_CONTACTAREA: u32 = 0x0004;
pub const TOUCHINPUTMASKF_ORIENTATION: u32 = 0x0008;
pub const TOUCHINPUTMASKF_PRESSURE: u32 = 0x0002;

// ── WM_TOUCH / WM_POINTER message IDs ────────────────────────────────────
pub const WM_TOUCH: u32 = 0x0240;
pub const WM_TOUCHDOWN: u32 = 0x0240;
pub const WM_TOUCHUP: u32 = 0x0240;
pub const WM_TOUCHMOVE: u32 = 0x0240;

pub const WM_POINTERDOWN: u32 = 0x0246;
pub const WM_POINTERUP: u32 = 0x0247;
pub const WM_POINTERUPDATE: u32 = 0x0245;
pub const WM_POINTERENTER: u32 = 0x0249;
pub const WM_POINTERLEAVE: u32 = 0x024A;
pub const WM_POINTERACTIVATE: u32 = 0x024B;

pub const POINTER_FLAG_NEW: u32 = 0x00000001;
pub const POINTER_FLAG_INRANGE: u32 = 0x00000002;
pub const POINTER_FLAG_INCONTACT: u32 = 0x00000004;
pub const POINTER_FLAG_FIRSTBUTTON: u32 = 0x00000010;
pub const POINTER_FLAG_SECONDBUTTON: u32 = 0x00000020;
pub const POINTER_FLAG_PRIMARY: u32 = 0x00000040;
pub const POINTER_FLAG_CONFIDENCE: u32 = 0x00000080;
pub const POINTER_FLAG_CANCELED: u32 = 0x00000100;

pub const PEN_FLAG_NONE: u32 = 0;
pub const PEN_FLAG_BARREL: u32 = 0x00000001;
pub const PEN_FLAG_INVERTED: u32 = 0x00000002;
pub const PEN_FLAG_ERASER: u32 = 0x00000004;

// ── Touch Input structure (96 bytes on x64) ──────────────────────────────
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct TouchInput {
    pub x: i32,
    pub y: i32,
    pub source: u32,       // 0=unspecified, 1=touch, 2=pen
    pub id: u32,
    pub flags: u32,
    pub mask: u32,
    pub time: u32,
    pub extra_info: usize,
    pub cx: u32,           // contact area width
    pub cy: u32,           // contact area height
}

// ── Pointer Info structure ───────────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PointerInfo {
    pub pointer_type: u32, // 1=touch, 2=pen, 3=mouse
    pub pointer_id: u32,
    pub frame_id: u32,
    pub pointer_flags: u32,
    pub source_device: isize,
    pub hwnd_target: isize,
    pub pt_pixel_x: i32,
    pub pt_pixel_y: i32,
    pub pt_hic_res_x: i32,
    pub pt_hic_res_y: i32,
    pub pt_pixel_z: i32,
    pub display_time: u32,
    pub key_state: u32,
    pub performance_count: u64,
}

// ── Pointer Pen Info structure ───────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PointerPenInfo {
    pub pointer_type: u32,
    pub pointer_id: u32,
    pub frame_id: u32,
    pub pointer_flags: u32,
    pub source_device: isize,
    pub hwnd_target: isize,
    pub pt_pixel_x: i32,
    pub pt_pixel_y: i32,
    pub pt_hic_res_x: i32,
    pub pt_hic_res_y: i32,
    pub pt_pixel_z: i32,
    pub display_time: u32,
    pub key_state: u32,
    pub performance_count: u64,
    pub pen_flags: u32,
    pub pen_mask: u32,
    pub pressure: u32,
    pub rotation: u32,
    pub tilt_x: i32,
    pub tilt_y: i32,
}

// ── Touch state tracking ─────────────────────────────────────────────────
/// Tracks windows that have called RegisterTouchWindow, pending touch
/// inputs, and initialized pointer devices.
#[derive(Debug, Clone, Default)]
pub struct TouchState {
    /// HWNDs that called RegisterTouchWindow
    pub registered_windows: Vec<u32>,
    /// (hwnd, TouchInput) pairs pending retrieval by GetTouchInputInfo
    pub touch_inputs: Vec<(u32, TouchInput)>,
    /// Handle → touch inputs stored for GetTouchInputInfo
    pub touch_handles: BTreeMap<u32, Vec<TouchInput>>,
    /// Next handle value for touch input storage
    pub next_touch_handle: u32,
    /// Initialized pointer device handles
    pub pointer_devices: Vec<u32>,
    /// Stored PointerInfo indexed by pointer_id
    pub pointer_infos: BTreeMap<u32, PointerInfo>,
    /// Stored PointerPenInfo indexed by pointer_id
    pub pointer_pen_infos: BTreeMap<u32, PointerPenInfo>,
}

// ── macOS touch event types (macOS only) ─────────────────────────────────
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPhase {
    Began,
    Moved,
    Ended,
    Cancelled,
    Stationary,
}

/// Represents a single touch point from macOS NSTouch.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct TouchPoint {
    pub id: u32,
    pub x: f64,
    pub y: f64,
    pub pressure: f64,
    pub is_pen: bool,
    pub phase: TouchPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowClassInfo {
    pub style: u32,
    pub wnd_proc: u64,
    pub cls_extra: i32,
    pub wnd_extra: i32,
    pub instance: u64,
    pub icon: u64,
    pub cursor: u64,
    pub background: u64,
    pub menu_name: u64,
    pub class_name_ptr: u64,
    pub icon_small: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    pub fn confine(&self, x: i32, y: i32) -> (i32, i32) {
        (
            x.clamp(self.left, self.right),
            y.clamp(self.top, self.bottom),
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    NcCreate,
    Create,
    Paint,
    ShowWindow,
    WindowPosChanging,
    Size,
    Activate,
    SetFocus,
    KillFocus,
    Command,
    Input,
    KeyDown,
    KeyUp,
    Char,
    DeadChar,
    RawInput,
    MouseMove,
    LButtonDown,
    LButtonUp,
    MouseWheel,
    MouseHWheel,
    XButtonDown,
    InputDeviceChange,
    Destroy,
    NcDestroy,
    Quit,
    Other(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub hwnd: Option<Hwnd>,
    pub kind: MessageKind,
    pub wparam: i64,
    pub lparam: i64,
    pub translated: bool,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DpiAwarenessContext {
    Unaware,
    SystemAware,
    PerMonitorAwareV2,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FullscreenMode {
    Windowed,
    Borderless,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FullscreenState {
    pub mode: FullscreenMode,
    pub requested_exclusive: bool,
    pub shim_applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitorInfo {
    pub id: u32,
    pub name: String,
    pub dpi_x: u32,
    pub dpi_y: u32,
    pub bounds: Rect,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum KeyboardLayoutId {
    Us,
    Uk,
    Fr,
    De,
    Es,
    It,
    Arabic,
    Turkish,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyModifiers {
    pub shift: bool,
    pub altgr: bool,
}

impl KeyModifiers {
    pub fn to_bits(self) -> i64 {
        (self.shift as i64) | ((self.altgr as i64) << 1)
    }

    pub fn from_bits(bits: i64) -> Self {
        Self {
            shift: bits & 1 != 0,
            altgr: bits & 2 != 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VirtualKey {
    A,
    E,
    O,
    Q,
    Y,
    Z,
    Oem3,
    Oem4,
    Oem7,
    Space,
    XButton1,
    XButton2,
    Unknown(u16),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyTranslation {
    pub vk: VirtualKey,
    pub output_char: Option<char>,
    pub dead_char: Option<char>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyboardDevice {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRepeatConfig {
    pub delay_ms: u32,
    pub rate_hz: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MouseDevice {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MouseButtonEvent {
    pub button: MouseButton,
    pub pressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MousePacket {
    pub raw_dx: i32,
    pub raw_dy: i32,
    pub cursor_x: i32,
    pub cursor_y: i32,
    pub wheel_delta: i32,
    pub hwheel_delta: i32,
    pub buttons: Vec<MouseButtonEvent>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowPlacement {
    pub show_cmd: u32,
    pub pt_min_position: (i32, i32),
    pub pt_max_position: (i32, i32),
    pub rc_normal_position: Rect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputReplayEvent {
    Keyboard {
        hwnd: Hwnd,
        device_id: String,
        scancode: u16,
        modifiers: KeyModifiers,
    },
    Mouse {
        hwnd: Hwnd,
        device_id: String,
        raw_dx: i32,
        raw_dy: i32,
        buttons: Vec<MouseButtonEvent>,
        wheel_delta: i32,
        hwheel_delta: i32,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ControllerTransport {
    Usb,
    Bluetooth,
    Hid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ControllerKind {
    Xbox,
    ThirdPartyXInput,
    HidGamepad,
    Hotas,
    WheelPedals,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAxis {
    X,
    Y,
    Z,
    Rx,
    Ry,
    Rz,
    Slider0,
    Slider1,
    Pov0,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AxisCalibration {
    pub min: i32,
    pub center: i32,
    pub max: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatteryInfo {
    pub level_percent: u8,
    pub wired: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ForceFeedbackEffect {
    Constant,
    Ramp,
    Periodic,
    Spring,
    Damper,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControllerSpec {
    pub name: String,
    pub kind: ControllerKind,
    pub transport: ControllerTransport,
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: String,
    pub xinput_capable: bool,
    pub battery: BatteryInfo,
    pub axes: BTreeMap<DeviceAxis, i32>,
    pub calibrations: BTreeMap<DeviceAxis, AxisCalibration>,
    pub buttons: BTreeSet<String>,
    pub supported_effects: BTreeSet<ForceFeedbackEffect>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XInputState {
    pub packet_number: u32,
    pub buttons: BTreeSet<String>,
    pub axes: BTreeMap<DeviceAxis, i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XInputCapabilities {
    pub kind: ControllerKind,
    pub transport: ControllerTransport,
    pub supports_rumble: bool,
    pub battery: BatteryInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RumbleState {
    pub left_motor: u16,
    pub right_motor: u16,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectInputDataFormat {
    Gamepad,
    Hotas,
    Wheel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectInputDeviceInfo {
    pub guid: String,
    pub name: String,
    pub axes: Vec<DeviceAxis>,
    pub xinput_slot: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectInputState {
    pub axes: BTreeMap<DeviceAxis, i32>,
    pub buttons: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectInputEvent {
    pub sequence: u64,
    pub object: String,
    pub value: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForceFeedbackPlan {
    pub effect: ForceFeedbackEffect,
    pub magnitude: i32,
    pub duration_ms: u32,
}

/// Registration entry for raw input devices.
#[derive(Debug, Clone)]
pub struct RawInputRegistration {
    pub usage_page: u16,
    pub usage: u16,
    pub flags: u32,
    pub target_hwnd: Option<Hwnd>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowState {
    pub hwnd: Hwnd,
    pub class_name: String,
    pub title: String,
    pub width: u32,
    pub height: u32,
    pub visible: bool,
    pub fullscreen: FullscreenState,
    pub monitor_id: u32,
    pub dpi: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowPreview {
    pub hwnd: Hwnd,
    pub parent: Option<Hwnd>,
    pub class_name: String,
    pub title: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub visible: bool,
    pub enabled: bool,
    pub control_id: u32,
}

#[derive(Debug, Clone)]
struct WindowClass {
    atom: Atom,
    #[allow(dead_code)]
    name: String,
    info: WindowClassInfo,
}

#[derive(Debug, Clone)]
struct WindowRecord {
    hwnd: Hwnd,
    parent: Option<Hwnd>,
    owner: Option<Hwnd>,
    class_name: String,
    title: String,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    visible: bool,
    enabled: bool,
    style: u32,
    ex_style: u32,
    control_id: u32,
    fullscreen: FullscreenState,
    monitor_id: u32,
    dpi: u32,
    destroyed: bool,
    /// Layered window alpha (0–255), set by SetLayeredWindowAttributes
    alpha: u8,
    /// Layered window flags (LWA_ALPHA, LWA_COLORKEY), set by SetLayeredWindowAttributes
    layered_flags: u32,
    /// Window region handle set by SetWindowRgn
    region_handle: u32,
    /// Window placement cached for GetWindowPlacement/SetWindowPlacement
    placement: WindowPlacement,
}

#[derive(Debug, Clone, Copy)]
struct LayoutEntry {
    vk: VirtualKey,
    plain: Option<char>,
    shifted: Option<char>,
    altgr: Option<char>,
    dead: Option<char>,
}

#[derive(Debug, Clone)]
struct ControllerRecord {
    spec: ControllerSpec,
    guid: String,
    xinput_slot: Option<u8>,
    packet_number: u32,
    rumble: RumbleState,
    directinput_format: Option<DirectInputDataFormat>,
    acquired: bool,
}

/// Information about a registered Windows hook.
#[derive(Debug, Clone)]
struct HookInfo {
    id: i32,
    hook_type: i32,
    callback: u64,
    module: u64,
    thread_id: u32,
}

// ── US keyboard layout VK↔scancode lookup tables ─────────────────────────
/// Maps scancode (index) to Windows VK code for US layout.
/// Indexed by scancode (0..=0x7F).
const SCANCODE_TO_VK_US: [u16; 128] = {
    let mut table = [0u16; 128];
    table[0x01] = 0x1B;  // Escape
    table[0x02] = 0x31;  // 1
    table[0x03] = 0x32;  // 2
    table[0x04] = 0x33;  // 3
    table[0x05] = 0x34;  // 4
    table[0x06] = 0x35;  // 5
    table[0x07] = 0x36;  // 6
    table[0x08] = 0x37;  // 7
    table[0x09] = 0x38;  // 8
    table[0x0A] = 0x39;  // 9
    table[0x0B] = 0x30;  // 0
    table[0x0C] = 0xBD;  // -_
    table[0x0D] = 0xBB;  // =+
    table[0x0E] = 0x08;  // Backspace
    table[0x0F] = 0x09;  // Tab
    table[0x10] = 0x51;  // Q
    table[0x11] = 0x57;  // W
    table[0x12] = 0x45;  // E
    table[0x13] = 0x52;  // R
    table[0x14] = 0x54;  // T
    table[0x15] = 0x59;  // Y
    table[0x16] = 0x55;  // U
    table[0x17] = 0x49;  // I
    table[0x18] = 0x4F;  // O
    table[0x19] = 0x50;  // P
    table[0x1A] = 0xDB;  // [{
    table[0x1B] = 0xDD;  // ]}
    table[0x1C] = 0x0D;  // Enter
    table[0x1D] = 0x11;  // Ctrl
    table[0x1E] = 0x41;  // A
    table[0x1F] = 0x53;  // S
    table[0x20] = 0x44;  // D
    table[0x21] = 0x46;  // F
    table[0x22] = 0x47;  // G
    table[0x23] = 0x48;  // H
    table[0x24] = 0x4A;  // J
    table[0x25] = 0x4B;  // K
    table[0x26] = 0x4C;  // L
    table[0x27] = 0xBA;  // ;:
    table[0x28] = 0xDE;  // '"
    table[0x29] = 0xC0;  // `~
    table[0x2A] = 0x10;  // LShift
    table[0x2B] = 0xDC;  // \|
    table[0x2C] = 0x5A;  // Z
    table[0x2D] = 0x58;  // X
    table[0x2E] = 0x43;  // C
    table[0x2F] = 0x56;  // V
    table[0x30] = 0x42;  // B
    table[0x31] = 0x4E;  // N
    table[0x32] = 0x4D;  // M
    table[0x33] = 0xBC;  // ,<
    table[0x34] = 0xBE;  // .>
    table[0x35] = 0xBF;  // /?
    table[0x36] = 0xA1;  // RShift
    table[0x37] = 0x6A;  // * (Numpad Multiply)
    table[0x38] = 0x12;  // Alt/Menu
    table[0x39] = 0x20;  // Space
    table[0x3A] = 0x14;  // Caps Lock
    table[0x3B] = 0x70;  // F1
    table[0x3C] = 0x71;  // F2
    table[0x3D] = 0x72;  // F3
    table[0x3E] = 0x73;  // F4
    table[0x3F] = 0x74;  // F5
    table[0x40] = 0x75;  // F6
    table[0x41] = 0x76;  // F7
    table[0x42] = 0x77;  // F8
    table[0x43] = 0x78;  // F9
    table[0x44] = 0x79;  // F10
    table[0x45] = 0x13;  // Pause
    table[0x46] = 0x91;  // Scroll Lock
    table[0x47] = 0x24;  // Home
    table[0x48] = 0x26;  // Up
    table[0x49] = 0x21;  // Page Up
    table[0x4A] = 0x6B;  // Numpad -
    table[0x4B] = 0x25;  // Left
    table[0x4C] = 0x2C;  // Numpad 5 / keypad center
    table[0x4D] = 0x27;  // Right
    table[0x4E] = 0x6D;  // Numpad +
    table[0x4F] = 0x23;  // End
    table[0x50] = 0x28;  // Down
    table[0x51] = 0x22;  // Page Down
    table[0x52] = 0x2D;  // Insert
    table[0x53] = 0x2E;  // Delete
    table[0x57] = 0x7A;  // F11
    table[0x58] = 0x7B;  // F12
    table
};

/// Maps E0-prefixed extended scancode (low 7 bits as index) to VK for US layout.
const SCANCODE_TO_VK_US_EXT: [u16; 128] = {
    let mut table = [0u16; 128];
    table[0x1C] = 0x0D;  // Numpad Enter
    table[0x1D] = 0xA3;  // RCtrl
    table[0x35] = 0x6F;  // Numpad /
    table[0x38] = 0xA5;  // RAlt
    table[0x47] = 0x67;  // Numpad 7 (Home)
    table[0x48] = 0x68;  // Numpad 8 (Up)
    table[0x49] = 0x69;  // Numpad 9 (PgUp)
    table[0x4B] = 0x64;  // Numpad 4 (Left)
    table[0x4C] = 0x65;  // Numpad 5
    table[0x4D] = 0x66;  // Numpad 6 (Right)
    table[0x4F] = 0x61;  // Numpad 1 (End)
    table[0x50] = 0x62;  // Numpad 2 (Down)
    table[0x51] = 0x63;  // Numpad 3 (PgDn)
    table[0x52] = 0x60;  // Numpad 0 (Ins)
    table[0x53] = 0x6E;  // Numpad . (Del)
    table[0x5B] = 0x5B;  // LWin
    table[0x5C] = 0x5C;  // RWin
    table[0x5D] = 0x5D;  // Apps
    table
};

#[derive(Debug, Clone)]
pub struct User32Subsystem {
    next_atom: Atom,
    next_hwnd: Hwnd,
    next_image_handle: u32,
    layout: KeyboardLayoutId,
    key_repeat: KeyRepeatConfig,
    dpi_context: DpiAwarenessContext,
    classes: BTreeMap<String, WindowClass>,
    windows: BTreeMap<Hwnd, WindowRecord>,
    dialog_items: BTreeMap<(Hwnd, i32), Hwnd>,
    dialog_results: BTreeMap<Hwnd, i64>,
    window_longs: BTreeMap<(Hwnd, i32), u64>,
    message_queue: VecDeque<Message>,
    thread_message_queues: BTreeMap<u32, VecDeque<Message>>,
    message_log: Vec<Message>,
    capture: Option<Hwnd>,
    foreground: Option<Hwnd>,
    focus: Option<Hwnd>,
    cursor_pos: (i32, i32),
    clip_rect: Option<Rect>,
    monitors: BTreeMap<u32, MonitorInfo>,
    keyboard_devices: BTreeSet<String>,
    mouse_devices: BTreeSet<String>,
    recorded_input: Vec<InputReplayEvent>,
    pending_dead_key: BTreeMap<String, char>,
    controllers: BTreeMap<String, ControllerRecord>,
    input_owner: Option<String>,
    next_sequence: u64,
    input_queue_capacity: usize,
    fullscreen_shims: BTreeSet<String>,
    /// Active tray icon IDs managed by Shell_NotifyIconW
    pub tray_icon_ids: BTreeSet<u32>,
    /// Z-order tracking — windows in front-to-back order
    z_order: Vec<Hwnd>,
    /// CEF browser handle associated with each HWND (if any)
    pub cef_browser_handles: BTreeMap<Hwnd, u64>,
    /// Per-UID tray icon callback data: uid → (hwnd, callback_message)
    pub tray_icon_callbacks: BTreeMap<u32, (u32, u32)>,
    /// Registered raw input devices
    raw_input_devices: Vec<RawInputRegistration>,
    /// HID monitor for game controller hotplug detection (Phase 5.3.2).
    hid_monitor: HidMonitor,
    /// Touch and pen input state (WM_TOUCH / WM_POINTER).
    touch_state: TouchState,
    /// GDI+ subsystem state (Phase 2.7).
    pub gdiplus_state: GdiplusState,
    /// Key state array indexed by VK (1–254). Bit 7 = key down, bit 0 = toggle.
    key_state: [u8; 256],
    /// Toggle state for keys like CapsLock, NumLock, ScrollLock. Bit 0 = on.
    toggle_state: [u8; 256],
    /// Keys toggled (pressed) since last GetAsyncKeyState call for that VK.
    async_toggle: [u8; 256],
    /// Registered Windows hooks: hook_id → HookInfo.
    hooks: HashMap<i32, HookInfo>,
    /// Next hook ID to assign.
    next_hook_id: i32,
}

/// Per-icon data extracted from NOTIFYICONDATAW.
#[derive(Debug, Clone, Copy)]
pub struct TrayIconEntry {
    pub hwnd: u32,
    pub uid: u32,
    pub callback_message: u32,
}

/// Manages macOS system tray (NSStatusItem) equivalents for Win32 tray icons.
/// Each tray icon is mapped to a menu-bar status item on macOS.
#[derive(Debug, Clone, Default)]
pub struct TrayIconManager {
    /// Maps Win32 tray UID → per-icon data
    pub items: BTreeMap<u32, TrayIconEntry>,
}

impl Default for User32Subsystem {
    fn default() -> Self {
        Self::new(KeyboardLayoutId::Us)
    }
}

impl User32Subsystem {
    pub fn new(layout: KeyboardLayoutId) -> Self {
        let monitors = BTreeMap::from([
            (
                1,
                MonitorInfo {
                    id: 1,
                    name: "Built-in Retina".to_string(),
                    dpi_x: 144,
                    dpi_y: 144,
                    bounds: Rect {
                        left: 0,
                        top: 0,
                        right: 2560,
                        bottom: 1600,
                    },
                },
            ),
            (
                2,
                MonitorInfo {
                    id: 2,
                    name: "External Display".to_string(),
                    dpi_x: 110,
                    dpi_y: 110,
                    bounds: Rect {
                        left: 2560,
                        top: 0,
                        right: 5120,
                        bottom: 1440,
                    },
                },
            ),
        ]);
        Self {
            next_atom: 1,
            next_hwnd: 1,
            next_image_handle: 0x1_0000,
            layout,
            key_repeat: KeyRepeatConfig {
                delay_ms: 250,
                rate_hz: 31,
            },
            dpi_context: DpiAwarenessContext::SystemAware,
            classes: BTreeMap::new(),
            windows: BTreeMap::new(),
            dialog_items: BTreeMap::new(),
            dialog_results: BTreeMap::new(),
            window_longs: BTreeMap::new(),
            message_queue: VecDeque::new(),
            thread_message_queues: BTreeMap::new(),
            message_log: Vec::new(),
            capture: None,
            foreground: None,
            focus: None,
            cursor_pos: (0, 0),
            clip_rect: None,
            monitors,
            keyboard_devices: BTreeSet::new(),
            mouse_devices: BTreeSet::new(),
            recorded_input: Vec::new(),
            pending_dead_key: BTreeMap::new(),
            controllers: BTreeMap::new(),
            input_owner: None,
            next_sequence: 1,
            input_queue_capacity: 8192,
            fullscreen_shims: BTreeSet::new(),
            tray_icon_ids: BTreeSet::new(),
            tray_icon_callbacks: BTreeMap::new(),
            z_order: Vec::new(),
            cef_browser_handles: BTreeMap::new(),
            raw_input_devices: Vec::new(),
            hid_monitor: HidMonitor::new(),
            touch_state: TouchState::default(),
            gdiplus_state: GdiplusState::default(),
            key_state: [0u8; 256],
            toggle_state: [0u8; 256],
            async_toggle: [0u8; 256],
            hooks: HashMap::new(),
            next_hook_id: 1,
        }
    }

    pub fn register_class_ex_w(&mut self, class_name: &str) -> Atom {
        self.register_class_info(
            class_name,
            WindowClassInfo {
                style: 0,
                wnd_proc: 0,
                cls_extra: 0,
                wnd_extra: 0,
                instance: 0,
                icon: 0,
                cursor: 0,
                background: 0,
                menu_name: 0,
                class_name_ptr: 0,
                icon_small: 0,
            },
        )
    }

    pub fn register_common_control_classes(&mut self) {
        for class_name in [
            "toolbarwindow32",
            "tooltips_class32",
            "statusclass32",
            "syslistview32",
            "systreeview32",
            "sysheader32",
            "systabcontrol32",
            "msctls_updown32",
            "msctls_progress32",
            "msctls_hotkey32",
            "sysanimate32",
            "sysmonthcal32",
            "sysdatetimepick32",
            "rebarwindow32",
            "comboboxex32",
            "syspager",
            "syslink",
        ] {
            self.register_class_ex_w(class_name);
        }
    }

    pub fn register_class_info(&mut self, class_name: &str, info: WindowClassInfo) -> Atom {
        if let Some(existing) = self.classes.get(class_name) {
            return existing.atom;
        }
        let atom = self.next_atom;
        self.next_atom += 1;
        self.classes.insert(
            class_name.to_string(),
            WindowClass {
                atom,
                name: class_name.to_string(),
                info,
            },
        );
        atom
    }

    pub fn class_info(&self, class_name: &str) -> Option<WindowClassInfo> {
        self.classes.get(class_name).map(|class| class.info)
    }

    pub fn ensure_class_available(&mut self, class_name: &str) -> Option<Atom> {
        if let Some(existing) = self.classes.get(class_name) {
            return Some(existing.atom);
        }
        if is_builtin_window_class(class_name) {
            return Some(self.register_class_ex_w(class_name));
        }
        None
    }

    pub fn create_window_ex_w(
        &mut self,
        class_name: &str,
        title: &str,
        width: u32,
        height: u32,
        visible: bool,
        requested_exclusive_fullscreen: bool,
        parent: Option<Hwnd>,
        monitor_id: u32,
    ) -> AppResult<Hwnd> {
        self.create_window_ex_styled(class_name, title, width, height, visible, requested_exclusive_fullscreen, parent, monitor_id, 0, 0, None)
    }

    pub fn create_window_ex_styled(
        &mut self,
        class_name: &str,
        title: &str,
        width: u32,
        height: u32,
        visible: bool,
        requested_exclusive_fullscreen: bool,
        parent: Option<Hwnd>,
        monitor_id: u32,
        style: u32,
        ex_style: u32,
        owner: Option<Hwnd>,
    ) -> AppResult<Hwnd> {
        let atom = self.ensure_class_available(class_name).ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, format!("unregistered class {class_name}"))
        })?;
        let class_info = self.classes.get(class_name).map(|class| class.info);
        let _ = atom;
        let hwnd = self.next_hwnd;
        self.next_hwnd += 1;
        let fullscreen = self.map_fullscreen_state(title, requested_exclusive_fullscreen);
        let dpi = self.effective_dpi(monitor_id)?;
        self.windows.insert(
            hwnd,
            WindowRecord {
                hwnd,
                parent,
                owner,
                class_name: class_name.to_string(),
                title: title.to_string(),
                x: 0,
                y: 0,
                width,
                height,
                visible,
                enabled: true,
                style,
                ex_style,
                control_id: 0,
                fullscreen,
                monitor_id,
                dpi,
                destroyed: false,
                alpha: 255,
                layered_flags: 0,
                region_handle: 0,
                placement: WindowPlacement {
                    show_cmd: if visible { 1 } else { 0 },
                    pt_min_position: (-1, -1),
                    pt_max_position: (-1, -1),
                    rc_normal_position: Rect {
                        left: 0,
                        top: 0,
                        right: width as i32,
                        bottom: height as i32,
                    },
                },
            },
        );
        // Add to z-order: topmost layered windows go at the front
        if ex_style & WS_EX_TOPMOST != 0 {
            self.z_order.insert(0, hwnd);
        } else {
            self.z_order.push(hwnd);
        }
        if let Some(class_info) = class_info {
            if class_info.wnd_proc != 0 {
                self.window_longs.insert((hwnd, GWL_WNDPROC), class_info.wnd_proc);
            }
        }
        // Associate owner window
        if let Some(owner_hwnd) = owner {
            if !self.windows.contains_key(&owner_hwnd) {
                if let Some(window) = self.windows.get_mut(&hwnd) {
                    window.owner = None;
                }
            }
        }
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::NcCreate,
            wparam: 0,
            lparam: 0,
            translated: false,
            device_id: None,
        })?;
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::Create,
            wparam: 0,
            lparam: 0,
            translated: false,
            device_id: None,
        })?;
        if visible {
            self.enqueue(Message {
                hwnd: Some(hwnd),
                kind: MessageKind::ShowWindow,
                wparam: 1,
                lparam: 0,
                translated: false,
                device_id: None,
            })?;
            self.queue_resize(hwnd, width, height)?;
            if self.foreground.is_none() {
                self.foreground = Some(hwnd);
                self.focus = Some(hwnd);
                self.enqueue(Message {
                    hwnd: Some(hwnd),
                    kind: MessageKind::Activate,
                    wparam: 1,
                    lparam: 0,
                    translated: false,
                    device_id: None,
                })?;
                self.enqueue(Message {
                    hwnd: Some(hwnd),
                    kind: MessageKind::SetFocus,
                    wparam: 0,
                    lparam: 0,
                    translated: false,
                    device_id: None,
                })?;
            }
        }
        Ok(hwnd)
    }

    pub fn show_window(&mut self, hwnd: Hwnd, command: i32) -> AppResult<bool> {
        let Some(existing) = self.windows.get(&hwnd) else {
            return Ok(false);
        };
        let was_visible = existing.visible;
        let should_show = command != 0;
        if was_visible == should_show {
            return Ok(was_visible);
        }

        {
            let window = self.window_mut(hwnd)?;
            window.visible = should_show;
        }

        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::ShowWindow,
            wparam: i64::from(should_show),
            lparam: 0,
            translated: false,
            device_id: None,
        })?;

        if should_show {
            let (width, height) = {
                let window = self.window(hwnd)?;
                (window.width, window.height)
            };
            self.queue_resize(hwnd, width, height)?;
            if self.foreground.is_none() {
                self.foreground = Some(hwnd);
                self.focus = Some(hwnd);
                self.enqueue(Message {
                    hwnd: Some(hwnd),
                    kind: MessageKind::Activate,
                    wparam: 1,
                    lparam: 0,
                    translated: false,
                    device_id: None,
                })?;
                self.enqueue(Message {
                    hwnd: Some(hwnd),
                    kind: MessageKind::SetFocus,
                    wparam: 0,
                    lparam: 0,
                    translated: false,
                    device_id: None,
                })?;
            }
        } else {
            if self.focus == Some(hwnd) {
                self.focus = None;
                self.enqueue(Message {
                    hwnd: Some(hwnd),
                    kind: MessageKind::KillFocus,
                    wparam: 0,
                    lparam: 0,
                    translated: false,
                    device_id: None,
                })?;
            }
            if self.foreground == Some(hwnd) {
                self.foreground = None;
            }
        }

        Ok(was_visible)
    }

    pub fn enable_window(&mut self, hwnd: Hwnd, enabled: bool) -> AppResult<bool> {
        let window = self.window_mut(hwnd)?;
        let was_enabled = window.enabled;
        window.enabled = enabled;
        Ok(was_enabled)
    }

    pub fn is_window_enabled(&self, hwnd: Hwnd) -> bool {
        self.window(hwnd).map(|window| window.enabled).unwrap_or(false)
    }

    // ── Parent / Child relationship management ─────────────────────────────

    /// Get the parent HWND of a window (if any). Returns 0 if no parent.
    pub fn get_parent(&self, hwnd: Hwnd) -> Hwnd {
        self.windows
            .get(&hwnd)
            .and_then(|w| w.parent)
            .unwrap_or(0)
    }

    /// Set the parent HWND of a window. Updates the internal parent field.
    /// Returns the previous parent HWND (0 if none).
    pub fn set_parent(&mut self, hwnd: Hwnd, parent_hwnd: Hwnd) -> AppResult<Hwnd> {
        // Validate parent window exists BEFORE the mutable borrow.
        if parent_hwnd != 0 && !self.windows.contains_key(&parent_hwnd) {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("set_parent: unknown parent window {parent_hwnd:#x}"),
            ));
        }
        let window = self.window_mut(hwnd)?;
        let previous = window.parent;
        window.parent = if parent_hwnd == 0 { None } else { Some(parent_hwnd) };
        Ok(previous.unwrap_or(0))
    }

    pub fn set_window_text_w(&mut self, hwnd: Hwnd, title: &str) -> bool {
        let Some(window) = self.windows.get_mut(&hwnd) else {
            return false;
        };
        window.title = title.to_string();
        true
    }

    pub fn load_image_w(
        &mut self,
        _source: &str,
        _image_type: u32,
        _width: i32,
        _height: i32,
        _flags: u32,
    ) -> u32 {
        let handle = self.next_image_handle;
        self.next_image_handle += 4;
        handle
    }

    pub fn destroy_window(&mut self, hwnd: Hwnd) -> AppResult<bool> {
        if !self.windows.contains_key(&hwnd) {
            return Ok(false);
        }
        if self.focus == Some(hwnd) {
            self.focus = None;
            self.enqueue(Message {
                hwnd: Some(hwnd),
                kind: MessageKind::KillFocus,
                wparam: 0,
                lparam: 0,
                translated: false,
                device_id: None,
            })?;
        }
        if self.foreground == Some(hwnd) {
            self.foreground = None;
        }
        if self.capture == Some(hwnd) {
            self.capture = None;
        }
        // Clean up CEF browser association
        self.cef_browser_handles.remove(&hwnd);
        if let Some(window) = self.windows.get_mut(&hwnd) {
            window.destroyed = true;
        }
        self.z_order.retain(|h| *h != hwnd);
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::Destroy,
            wparam: 0,
            lparam: 0,
            translated: false,
            device_id: None,
        })?;
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::NcDestroy,
            wparam: 0,
            lparam: 0,
            translated: false,
            device_id: None,
        })?;
        Ok(true)
    }

    pub fn def_window_proc_w(&mut self, message: &Message) -> AppResult<i64> {
        if let Some(hwnd) = message.hwnd.filter(|hwnd| self.windows.contains_key(hwnd)) {
            let window = self.window(hwnd)?.clone();
            match message.kind {
                MessageKind::LButtonDown => {
                    let _ = self.set_focus(hwnd)?;
                    self.capture = Some(hwnd);
                }
                MessageKind::LButtonUp => {
                    if self.capture == Some(hwnd) {
                        self.capture = None;
                    }
                    if window.enabled && window.class_name.eq_ignore_ascii_case("button") {
                        if let Some(parent) = window.parent {
                            self.enqueue(Message {
                                hwnd: Some(parent),
                                kind: MessageKind::Command,
                                wparam: i64::from(window.control_id),
                                lparam: i64::from(window.hwnd),
                                translated: false,
                                device_id: message.device_id.clone(),
                            })?;
                        }
                    }
                }
                _ => {
                    let _ = self.window(hwnd)?;
                }
            }
        }
        Ok(0)
    }

    pub fn has_window(&self, hwnd: Hwnd) -> bool {
        self.windows.contains_key(&hwnd)
    }

    pub fn set_layered_window_attributes(&mut self, hwnd: Hwnd, alpha: u8, flags: u32) -> AppResult<()> {
        let window = self.window_mut(hwnd)?;
        window.alpha = alpha;
        window.layered_flags = flags;
        Ok(())
    }

    pub fn layered_window_attributes(&self, hwnd: Hwnd) -> AppResult<(u8, u32)> {
        let window = self.window(hwnd)?;
        Ok((window.alpha, window.layered_flags))
    }

    pub fn set_window_region(&mut self, hwnd: Hwnd, region_handle: u32) -> AppResult<()> {
        let window = self.window_mut(hwnd)?;
        window.region_handle = region_handle;
        Ok(())
    }

    pub fn set_window_placement(&mut self, hwnd: Hwnd, placement: WindowPlacement) -> AppResult<()> {
        let window = self.window_mut(hwnd)?;
        window.placement = placement;
        Ok(())
    }

    pub fn get_window_placement(&self, hwnd: Hwnd) -> AppResult<WindowPlacement> {
        let window = self.window(hwnd)?;
        Ok(window.placement)
    }

    pub fn dpi_for_window(&self, hwnd: Hwnd) -> AppResult<u32> {
        let window = self.window(hwnd)?;
        Ok(window.dpi)
    }

    pub fn trigger_repaint(&mut self, hwnd: Hwnd) -> AppResult<()> {
        self.queue_paint(hwnd)
    }

    pub fn find_window_ex_w(
        &self,
        parent: Hwnd,
        after: Hwnd,
        class_name: Option<&str>,
        title: Option<&str>,
    ) -> Option<Hwnd> {
        let mut handles = self.windows.keys().copied().collect::<Vec<_>>();
        handles.sort_unstable();
        let mut after_seen = after == 0;
        for hwnd in handles {
            let window = self.windows.get(&hwnd)?;
            if window.destroyed {
                continue;
            }
            if parent == 0 {
                if window.parent.is_some() {
                    continue;
                }
            } else if window.parent != Some(parent) {
                continue;
            }
            if !after_seen {
                if hwnd == after {
                    after_seen = true;
                }
                continue;
            }
            if let Some(expected) = class_name {
                if !window.class_name.eq_ignore_ascii_case(expected) {
                    continue;
                }
            }
            if let Some(expected) = title {
                if window.title != expected {
                    continue;
                }
            }
            return Some(hwnd);
        }
        None
    }

    pub fn get_dlg_item(&mut self, parent: Hwnd, item_id: i32) -> AppResult<Option<Hwnd>> {
        let Some(parent_window) = self.windows.get(&parent).cloned() else {
            return Ok(None);
        };
        if item_id <= 0 {
            return Ok(None);
        }
        if let Some(existing) = self.dialog_items.get(&(parent, item_id)) {
            return Ok(Some(*existing));
        }

        let hwnd = self.next_hwnd;
        self.next_hwnd += 1;
        self.windows.insert(
            hwnd,
            WindowRecord {
                hwnd,
                parent: Some(parent),
                owner: None,
                class_name: "static".to_string(),
                title: format!("dlg-item-{item_id}"),
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                visible: true,
                enabled: true,
                style: 0,
                ex_style: 0,
                control_id: item_id as u32,
                fullscreen: parent_window.fullscreen,
                monitor_id: parent_window.monitor_id,
                dpi: parent_window.dpi,
                destroyed: false,
                alpha: 255,
                layered_flags: 0,
                region_handle: 0,
                placement: WindowPlacement {
                    show_cmd: 1,
                    pt_min_position: (-1, -1),
                    pt_max_position: (-1, -1),
                    rc_normal_position: Rect {
                        left: 0,
                        top: 0,
                        right: 1,
                        bottom: 1,
                    },
                },
            },
        );
        self.dialog_items.insert((parent, item_id), hwnd);
        Ok(Some(hwnd))
    }

    pub fn end_dialog(&mut self, hwnd: Hwnd, result: i64) -> AppResult<bool> {
        if !self.windows.contains_key(&hwnd) {
            return Ok(false);
        }
        self.dialog_results.insert(hwnd, result);
        self.destroy_window(hwnd)
    }

    pub fn take_dialog_result(&mut self, hwnd: Hwnd) -> Option<i64> {
        self.dialog_results.remove(&hwnd)
    }

    pub fn set_window_long_w(&mut self, hwnd: Hwnd, index: i32, value: u64) -> Option<u64> {
        if !self.windows.contains_key(&hwnd) {
            return None;
        }
        // GWL_HWNDPARENT (-8): delegate to set_parent so the window hierarchy stays
        // consistent with the parent field in WindowRecord.
        if index == GWL_HWNDPARENT {
            let previous = self.get_parent(hwnd);
            let _ = self.set_parent(hwnd, value as Hwnd);
            return Some(previous as u64);
        }
        Some(self.window_longs.insert((hwnd, index), value).unwrap_or(0))
    }

    pub fn get_window_long_w(&self, hwnd: Hwnd, index: i32) -> Option<u64> {
        if !self.windows.contains_key(&hwnd) {
            return None;
        }
        // GWL_HWNDPARENT (-8): return the current parent HWND from the window record.
        if index == GWL_HWNDPARENT {
            return Some(self.get_parent(hwnd) as u64);
        }
        Some(*self.window_longs.get(&(hwnd, index)).unwrap_or(&0))
    }

    pub fn post_message_w(
        &mut self,
        hwnd: Hwnd,
        kind: MessageKind,
        wparam: i64,
        lparam: i64,
    ) -> AppResult<()> {
        self.window(hwnd)?;
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind,
            wparam,
            lparam,
            translated: false,
            device_id: None,
        })
    }

    pub fn invalidate_window(&mut self, hwnd: Option<Hwnd>, _erase: bool) -> AppResult<bool> {
        match hwnd {
            Some(hwnd) => {
                if !self.has_window(hwnd) {
                    return Ok(false);
                }
                self.queue_paint(hwnd)?;
            }
            None => {
                let hwnds = self
                    .windows
                    .iter()
                    .filter_map(|(hwnd, window)| (!window.destroyed && window.visible).then_some(*hwnd))
                    .collect::<Vec<_>>();
                for hwnd in hwnds {
                    self.queue_paint(hwnd)?;
                }
            }
        }
        Ok(true)
    }

    pub fn send_message_w(
        &mut self,
        hwnd: Hwnd,
        kind: MessageKind,
        wparam: i64,
        lparam: i64,
    ) -> AppResult<i64> {
        self.window(hwnd)?;
        let message = Message {
            hwnd: Some(hwnd),
            kind,
            wparam,
            lparam,
            translated: false,
            device_id: None,
        };
        self.dispatch_message_w(&message)
    }

    pub fn post_quit_message(&mut self, exit_code: i32) -> AppResult<()> {
        self.enqueue(Message {
            hwnd: None,
            kind: MessageKind::Quit,
            wparam: exit_code as i64,
            lparam: 0,
            translated: false,
            device_id: None,
        })
    }

    pub fn post_thread_message_w(
        &mut self,
        thread_id: u32,
        kind: MessageKind,
        wparam: i64,
        lparam: i64,
    ) -> AppResult<()> {
        self.enqueue_thread_message(
            thread_id,
            Message {
                hwnd: None,
                kind,
                wparam,
                lparam,
                translated: false,
                device_id: None,
            },
        )
    }

    pub fn peek_message_w(&mut self, remove: bool) -> Option<Message> {
        self.peek_message_for_thread(1, remove)
    }

    pub fn peek_message_for_thread(&mut self, thread_id: u32, remove: bool) -> Option<Message> {
        if let Some(message) = self
            .thread_message_queues
            .get(&thread_id)
            .and_then(|queue| queue.front())
            .cloned()
        {
            if remove {
                if let Some(queue) = self.thread_message_queues.get_mut(&thread_id) {
                    queue.pop_front();
                }
            }
            return Some(message);
        }
        let message = self.message_queue.front()?.clone();
        if remove {
            self.message_queue.pop_front();
        }
        Some(message)
    }

    pub fn get_message_w(&mut self) -> Option<Message> {
        self.get_message_for_thread(1)
    }

    pub fn get_message_for_thread(&mut self, thread_id: u32) -> Option<Message> {
        if let Some(queue) = self.thread_message_queues.get_mut(&thread_id) {
            if let Some(message) = queue.pop_front() {
                return Some(message);
            }
        }
        self.message_queue.pop_front()
    }

    pub fn translate_message(&mut self, message: &Message) -> AppResult<Vec<Message>> {
        if message.kind != MessageKind::KeyDown {
            return Ok(Vec::new());
        }
        let modifiers = KeyModifiers::from_bits(message.wparam);
        let scancode = message.lparam as u16;
        let translation = self.translate_scancode(scancode, modifiers)?;
        let device_id = message
            .device_id
            .clone()
            .unwrap_or_else(|| "keyboard-default".to_string());
        let mut translated = Vec::new();
        if let Some(dead_char) = translation.dead_char {
            self.pending_dead_key.insert(device_id.clone(), dead_char);
            translated.push(Message {
                hwnd: message.hwnd,
                kind: MessageKind::DeadChar,
                wparam: dead_char as i64,
                lparam: scancode as i64,
                translated: true,
                device_id: Some(device_id.clone()),
            });
        } else if let Some(base_char) = translation.output_char {
            let output = match self.pending_dead_key.remove(&device_id) {
                Some(dead) => compose_dead_char(dead, base_char).unwrap_or(base_char),
                None => base_char,
            };
            translated.push(Message {
                hwnd: message.hwnd,
                kind: MessageKind::Char,
                wparam: output as i64,
                lparam: scancode as i64,
                translated: true,
                device_id: Some(device_id),
            });
        }
        for message in &translated {
            self.enqueue(message.clone())?;
        }
        Ok(translated)
    }

    pub fn dispatch_message_w(&mut self, message: &Message) -> AppResult<i64> {
        let result = self.def_window_proc_w(message)?;
        self.message_log.push(message.clone());
        if message.kind == MessageKind::NcDestroy {
            if let Some(hwnd) = message.hwnd {
                self.windows.remove(&hwnd);
                self.z_order.retain(|h| *h != hwnd);
                self.cef_browser_handles.remove(&hwnd);
            }
        }
        Ok(result)
    }

    pub fn message_log(&self) -> &[Message] {
        &self.message_log
    }

    pub fn resize_window(&mut self, hwnd: Hwnd, width: u32, height: u32) -> AppResult<()> {
        let window = self.window_mut(hwnd)?;
        window.width = width;
        window.height = height;
        self.queue_resize(hwnd, width, height)
    }

    pub fn set_capture(&mut self, hwnd: Hwnd) -> AppResult<Option<Hwnd>> {
        self.window(hwnd)?;
        let previous = self.capture;
        self.capture = Some(hwnd);
        Ok(previous)
    }

    pub fn release_capture(&mut self) -> Option<Hwnd> {
        self.capture.take()
    }

    pub fn get_capture(&self) -> Option<Hwnd> {
        self.capture
    }

    pub fn clip_cursor(&mut self, rect: Option<Rect>) {
        self.clip_rect = rect;
        if let Some(rect) = self.clip_rect {
            self.cursor_pos = rect.confine(self.cursor_pos.0, self.cursor_pos.1);
        }
    }

    pub fn set_cursor_pos(&mut self, x: i32, y: i32) {
        self.cursor_pos = self.confine_cursor(x, y);
    }

    pub fn set_window_position(&mut self, hwnd: Hwnd, x: i32, y: i32) -> AppResult<()> {
        let window = self.window_mut(hwnd)?;
        window.x = x;
        window.y = y;
        Ok(())
    }

    pub fn set_window_control_id(&mut self, hwnd: Hwnd, control_id: u32) -> AppResult<()> {
        self.window_mut(hwnd)?.control_id = control_id;
        Ok(())
    }

    // ── Style / Extended Style accessors ──────────────────────────────────────

    pub fn get_window_style(&self, hwnd: Hwnd) -> Option<u32> {
        self.windows.get(&hwnd).map(|w| w.style)
    }

    pub fn set_window_style(&mut self, hwnd: Hwnd, style: u32) -> AppResult<()> {
        self.window_mut(hwnd)?.style = style;
        Ok(())
    }

    pub fn get_window_ex_style(&self, hwnd: Hwnd) -> Option<u32> {
        self.windows.get(&hwnd).map(|w| w.ex_style)
    }

    pub fn set_window_ex_style(&mut self, hwnd: Hwnd, ex_style: u32) -> AppResult<()> {
        self.window_mut(hwnd)?.ex_style = ex_style;
        Ok(())
    }

    // ── CEF Browser Association ──────────────────────────────────────────────

    /// Associate a CEF browser handle with an HWND so that WM_PAINT dispatch
    /// can submit the correct WKWebView frame to the Metal compositor.
    pub fn associate_cef_browser(&mut self, hwnd: Hwnd, cef_handle: u64) -> AppResult<()> {
        self.window(hwnd)?;
        self.cef_browser_handles.insert(hwnd, cef_handle);
        Ok(())
    }

    /// Look up the CEF browser handle (if any) previously associated with `hwnd`.
    pub fn cef_browser_for_window(&self, hwnd: Hwnd) -> Option<u64> {
        self.cef_browser_handles.get(&hwnd).copied()
    }

    // ── Z-Order Management ────────────────────────────────────────────────────

    /// Rebuild the z-order list from scratch based on window creation order
    /// (front-to-back: last created is on top, except topmost windows first).
    fn rebuild_z_order(&mut self) {
        let mut topmost: Vec<Hwnd> = Vec::new();
        let mut normal: Vec<Hwnd> = Vec::new();
        let mut hwnds: Vec<Hwnd> = self.windows.keys().copied().filter(|h| !self.windows[h].destroyed).collect();
        hwnds.sort();
        for hwnd in hwnds {
            if let Some(w) = self.windows.get(&hwnd) {
                if w.ex_style & WS_EX_TOPMOST != 0 {
                    topmost.push(hwnd);
                } else {
                    normal.push(hwnd);
                }
            }
        }
        topmost.extend(normal);
        self.z_order = topmost;
    }

    /// Bring a window to the top of the z-order.
    pub fn bring_window_to_top(&mut self, hwnd: Hwnd) -> AppResult<()> {
        self.window(hwnd)?;
        self.z_order.retain(|h| *h != hwnd);
        self.z_order.insert(0, hwnd);
        // If the window has an owner, bring the owner to top too
        if let Some(owner) = self.windows.get(&hwnd).and_then(|w| w.owner) {
            self.z_order.retain(|h| *h != owner);
            self.z_order.insert(0, owner);
        }
        self.foreground = Some(hwnd);
        Ok(())
    }

    /// Get the topmost (front-most) window in the z-order.
    pub fn get_top_window(&self, hwnd: Option<Hwnd>) -> Option<Hwnd> {
        if let Some(parent) = hwnd {
            // Return topmost child of parent
            self.z_order.iter().copied().find(|h| {
                self.windows.get(h).map_or(false, |w| w.parent == Some(parent) && !w.destroyed)
            })
        } else {
            self.z_order.first().copied().filter(|h| !self.windows[h].destroyed)
        }
    }

    /// Get the next/previous window in the z-order (GW_HWNDNEXT / GW_HWNDPREV).
    pub fn get_next_window(&self, hwnd: Hwnd, direction: u32) -> Option<Hwnd> {
        let pos = self.z_order.iter().position(|h| *h == hwnd)?;
        match direction {
            GW_HWNDNEXT => {
                // GW_HWNDNEXT (2): window below in z-order
                self.z_order.get(pos + 1).copied().filter(|h| !self.windows[h].destroyed)
            }
            GW_HWNDPREV => {
                // GW_HWNDPREV (3): window above in z-order
                if pos > 0 {
                    self.z_order.get(pos - 1).copied().filter(|h| !self.windows[h].destroyed)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Get a related window by relationship (GW_CHILD, GW_OWNER, GW_HWNDNEXT, GW_HWNDPREV).
    pub fn get_window(&self, hwnd: Hwnd, cmd: u32) -> Option<Hwnd> {
        match cmd {
            GW_CHILD => {
                // Return the topmost child window
                self.z_order.iter().copied().find(|h| {
                    self.windows.get(h).map_or(false, |w| w.parent == Some(hwnd) && !w.destroyed)
                })
            }
            GW_OWNER => {
                self.windows.get(&hwnd).and_then(|w| w.owner).filter(|h| !self.windows[h].destroyed)
            }
            GW_HWNDNEXT | GW_HWNDPREV => self.get_next_window(hwnd, cmd),
            GW_ENABLEDPOPUP => {
                // Return the topmost enabled popup owned by hwnd
                self.z_order.iter().copied().find(|h| {
                    self.windows.get(h).map_or(false, |w| {
                        !w.destroyed && w.enabled && w.owner == Some(hwnd) && w.style & WS_POPUP != 0
                    })
                })
            }
            _ => None,
        }
    }

    // ── SetWindowPos with full z-order support ────────────────────────────────

    pub fn set_window_pos(
        &mut self,
        hwnd: Hwnd,
        insert_after: u32,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        flags: u32,
    ) -> AppResult<bool> {
        if !self.has_window(hwnd) {
            return Ok(false);
        }
        if flags & SWP_NOMOVE == 0 {
            if let Ok(window) = self.window_mut(hwnd) {
                window.x = x;
                window.y = y;
            }
        }
        if flags & SWP_NOSIZE == 0 && cx > 0 && cy > 0 {
            self.resize_window(hwnd, cx as u32, cy as u32)?;
        }
        if flags & SWP_SHOWWINDOW != 0 {
            let _ = self.show_window(hwnd, 1)?;
        }
        if flags & SWP_HIDEWINDOW != 0 {
            let _ = self.show_window(hwnd, 0)?;
        }
        // Z-order management
        if flags & SWP_NOZORDER == 0 {
            match insert_after {
                HWND_TOP => {
                    self.bring_window_to_top(hwnd)?;
                }
                HWND_BOTTOM => {
                    self.z_order.retain(|h| *h != hwnd);
                    self.z_order.push(hwnd);
                }
                HWND_TOPMOST => {
                    // Make the window topmost and bring to front
                    if let Ok(window) = self.window_mut(hwnd) {
                        window.ex_style |= WS_EX_TOPMOST;
                    }
                    self.bring_window_to_top(hwnd)?;
                }
                HWND_NOTOPMOST => {
                    // Remove topmost style
                    if let Ok(window) = self.window_mut(hwnd) {
                        window.ex_style &= !WS_EX_TOPMOST;
                    }
                    self.rebuild_z_order();
                }
                other_hwnd => {
                    // Place after the given window in z-order
                    if self.has_window(other_hwnd) {
                        self.z_order.retain(|h| *h == hwnd || *h != other_hwnd);
                        if let Some(pos) = self.z_order.iter().position(|h| *h == other_hwnd) {
                            self.z_order.insert(pos + 1, hwnd);
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    // ── Window text management ────────────────────────────────────────────────

    pub fn get_window_text_w(&self, hwnd: Hwnd) -> Option<String> {
        self.windows.get(&hwnd).map(|w| w.title.clone())
    }

    pub fn get_window_text_length_w(&self, hwnd: Hwnd) -> Option<i32> {
        self.windows.get(&hwnd).map(|w| w.title.len() as i32)
    }

    // ── Update rectangle management ───────────────────────────────────────────

    /// Simulate GetUpdateRect — reports whether the window has a pending paint.
    /// Returns (has_update, rect) where rect is the client area.
    pub fn get_update_rect(&self, hwnd: Hwnd) -> AppResult<(bool, Rect)> {
        let window = self.window(hwnd)?;
        let has_paint = self.message_queue.iter().any(|m| {
            m.hwnd == Some(hwnd) && m.kind == MessageKind::Paint
        });
        let rect = Rect {
            left: 0,
            top: 0,
            right: window.width as i32,
            bottom: window.height as i32,
        };
        Ok((has_paint, rect))
    }

    /// ValidateRect — removes pending paint messages for the window.
    pub fn validate_rect(&mut self, hwnd: Hwnd) -> AppResult<()> {
        self.window(hwnd)?;
        self.message_queue.retain(|m| !(m.hwnd == Some(hwnd) && m.kind == MessageKind::Paint));
        Ok(())
    }

    /// InvalidateRgn — queues a paint for the window (simplified: ignores region).
    pub fn invalidate_rgn(&mut self, hwnd: Hwnd) -> AppResult<bool> {
        if !self.has_window(hwnd) {
            return Ok(false);
        }
        self.queue_paint(hwnd)?;
        Ok(true)
    }

    pub fn get_cursor_pos(&self) -> (i32, i32) {
        self.cursor_pos
    }

    pub fn set_foreground_window(&mut self, hwnd: Hwnd) -> AppResult<()> {
        self.window(hwnd)?;
        self.foreground = Some(hwnd);
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::Activate,
            wparam: 1,
            lparam: 0,
            translated: false,
            device_id: None,
        })
    }

    pub fn get_foreground_window(&self) -> Option<Hwnd> {
        self.foreground
    }

    pub fn get_focus(&self) -> Option<Hwnd> {
        self.focus
    }

    pub fn set_focus(&mut self, hwnd: Hwnd) -> AppResult<Option<Hwnd>> {
        self.window(hwnd)?;
        let previous = self.focus;
        if let Some(previous_hwnd) = previous.filter(|previous_hwnd| *previous_hwnd != hwnd) {
            self.enqueue(Message {
                hwnd: Some(previous_hwnd),
                kind: MessageKind::KillFocus,
                wparam: 0,
                lparam: 0,
                translated: false,
                device_id: None,
            })?;
        }
        self.focus = Some(hwnd);
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::SetFocus,
            wparam: 0,
            lparam: 0,
            translated: false,
            device_id: None,
        })?;
        Ok(previous)
    }

    pub fn set_process_dpi_awareness_context(
        &mut self,
        context: DpiAwarenessContext,
    ) -> DpiAwarenessContext {
        let previous = self.dpi_context;
        self.dpi_context = context;
        previous
    }

    pub fn get_dpi_for_monitor(&self, monitor_id: u32) -> AppResult<(u32, u32)> {
        let monitor = self.monitor(monitor_id)?;
        Ok((monitor.dpi_x, monitor.dpi_y))
    }

    pub fn primary_monitor_id(&self) -> u32 {
        self.monitors.keys().next().copied().unwrap_or(0)
    }

    pub fn monitor_info(&self, monitor_id: u32) -> Option<MonitorInfo> {
        self.monitors.get(&monitor_id).cloned()
    }

    pub fn monitor_from_window(&self, hwnd: Option<Hwnd>, flags: u32) -> u32 {
        const MONITOR_DEFAULTTOPRIMARY: u32 = 0x0000_0001;
        const MONITOR_DEFAULTTONEAREST: u32 = 0x0000_0002;

        hwnd.and_then(|handle| self.windows.get(&handle))
            .filter(|window| !window.destroyed)
            .map(|window| window.monitor_id)
            .or_else(|| {
                ((flags & (MONITOR_DEFAULTTOPRIMARY | MONITOR_DEFAULTTONEAREST)) != 0)
                    .then(|| self.primary_monitor_id())
            })
            .unwrap_or(0)
    }

    pub fn register_keyboard_device(&mut self, device: &KeyboardDevice) -> String {
        let identifier = stable_device_id(
            "kbd",
            &format!(
                "{:04x}:{:04x}:{}",
                device.vendor_id, device.product_id, device.serial
            ),
        );
        self.keyboard_devices.insert(identifier.clone());
        identifier
    }

    pub fn register_mouse_device(&mut self, device: &MouseDevice) -> String {
        let identifier = stable_device_id(
            "mouse",
            &format!(
                "{:04x}:{:04x}:{}",
                device.vendor_id, device.product_id, device.serial
            ),
        );
        self.mouse_devices.insert(identifier.clone());
        identifier
    }

    pub fn recorded_input_stream(&self) -> &[InputReplayEvent] {
        &self.recorded_input
    }

    pub fn replay_input_stream(&mut self, events: &[InputReplayEvent]) -> AppResult<()> {
        for event in events {
            match event {
                InputReplayEvent::Keyboard {
                    hwnd,
                    device_id,
                    scancode,
                    modifiers,
                } => self.inject_keyboard_input_internal(
                    *hwnd,
                    device_id,
                    *scancode,
                    *modifiers,
                    MessageKind::KeyDown,
                    false,
                )?,
                InputReplayEvent::Mouse {
                    hwnd,
                    device_id,
                    raw_dx,
                    raw_dy,
                    buttons,
                    wheel_delta,
                    hwheel_delta,
                } => {
                    self.inject_mouse_input_internal(
                        *hwnd,
                        device_id,
                        *raw_dx,
                        *raw_dy,
                        buttons,
                        *wheel_delta,
                        *hwheel_delta,
                        false,
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn translate_scancode(&self, scancode: u16, modifiers: KeyModifiers) -> AppResult<KeyTranslation> {
        let entry = layout_tables()
            .get(&self.layout)
            .and_then(|table| table.get(&scancode))
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("no keyboard mapping for layout {:?} scancode {scancode:#x}", self.layout),
                )
            })?;
        Ok(KeyTranslation {
            vk: entry.vk,
            output_char: if modifiers.altgr {
                entry.altgr.or(entry.plain)
            } else if modifiers.shift {
                entry.shifted.or(entry.plain)
            } else {
                entry.plain
            },
            dead_char: entry.dead,
        })
    }

    pub fn set_key_repeat_config(&mut self, config: KeyRepeatConfig) {
        self.key_repeat = config;
    }

    pub fn synthesize_key_repeats(
        &self,
        hwnd: Hwnd,
        device_id: &str,
        scancode: u16,
        modifiers: KeyModifiers,
        held_ms: u32,
    ) -> AppResult<Vec<Message>> {
        self.window(hwnd)?;
        if !self.keyboard_devices.contains(device_id) {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unknown keyboard device {device_id}"),
            ));
        }
        if held_ms <= self.key_repeat.delay_ms || self.key_repeat.rate_hz == 0 {
            return Ok(Vec::new());
        }
        let repeat_window_ms = held_ms - self.key_repeat.delay_ms;
        let count = (repeat_window_ms as u64 * self.key_repeat.rate_hz as u64 / 1000) as usize;
        Ok((0..count)
            .map(|_| Message {
                hwnd: Some(hwnd),
                kind: MessageKind::KeyDown,
                wparam: modifiers.to_bits(),
                lparam: scancode as i64,
                translated: false,
                device_id: Some(device_id.to_string()),
            })
            .collect())
    }

    pub fn inject_keyboard_input(
        &mut self,
        hwnd: Hwnd,
        device_id: &str,
        scancode: u16,
        modifiers: KeyModifiers,
    ) -> AppResult<()> {
        self.inject_keyboard_input_internal(hwnd, device_id, scancode, modifiers, MessageKind::KeyDown, true)
    }

    pub fn inject_keyboard_input_up(
        &mut self,
        hwnd: Hwnd,
        device_id: &str,
        scancode: u16,
        modifiers: KeyModifiers,
    ) -> AppResult<()> {
        self.inject_keyboard_input_internal(hwnd, device_id, scancode, modifiers, MessageKind::KeyUp, false)
    }

    fn inject_keyboard_input_internal(
        &mut self,
        hwnd: Hwnd,
        device_id: &str,
        scancode: u16,
        modifiers: KeyModifiers,
        kind: MessageKind,
        record: bool,
    ) -> AppResult<()> {
        self.window(hwnd)?;
        if !self.keyboard_devices.contains(device_id) {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unknown keyboard device {device_id}"),
            ));
        }
        if record && kind == MessageKind::KeyDown {
            self.recorded_input.push(InputReplayEvent::Keyboard {
                hwnd,
                device_id: device_id.to_string(),
                scancode,
                modifiers,
            });
        }

        // ── Update key state tracking ──────────────────────────────────
        let is_down = matches!(kind, MessageKind::KeyDown);
        self.update_key_state_for_scancode(scancode as u8, is_down);
        if modifiers.shift {
            self.update_single_key_state(VK_SHIFT as u8, is_down);
            self.update_single_key_state(VK_LSHIFT as u8, is_down);
        }
        if modifiers.altgr {
            self.update_single_key_state(VK_MENU as u8, is_down);
            self.update_single_key_state(VK_RMENU as u8, is_down);
        }

        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind,
            wparam: modifiers.to_bits(),
            lparam: scancode as i64,
            translated: false,
            device_id: Some(device_id.to_string()),
        })
    }

    /// Update key_state for a given scancode (maps scancode → VK internally).
    fn update_key_state_for_scancode(&mut self, scancode: u8, down: bool) {
        let vk = self.scancode_to_vk_code(scancode);
        if vk < 256 {
            self.update_single_key_state(vk as u8, down);
        }
    }

    /// Update key_state for a single VK and track async toggle.
    fn update_single_key_state(&mut self, vk: u8, down: bool) {
        let idx = vk as usize;
        if down {
            let was_down = self.key_state[idx] & 0x80 != 0;
            self.key_state[idx] |= 0x80;
            self.async_toggle[idx] |= 0x01;
            // Toggle keys: change toggle state on key-down transition
            if !was_down && is_toggle_key(vk) {
                self.toggle_state[idx] ^= 0x01;
            }
        } else {
            self.key_state[idx] &= 0x01; // Preserve toggle bit, clear bit 7
        }
    }

    /// Convert a scancode to its Windows VK code using the current layout.
    fn scancode_to_vk_code(&self, scancode: u8) -> u32 {
        // Determine if extended (E0-prefixed)
        if scancode & 0x80 != 0 {
            let idx = (scancode & 0x7F) as usize;
            if idx < 128 && SCANCODE_TO_VK_US_EXT[idx] != 0 {
                return SCANCODE_TO_VK_US_EXT[idx] as u32;
            }
        }
        let idx = scancode as usize;
        if idx < 128 {
            let vk = SCANCODE_TO_VK_US[idx];
            if vk != 0 {
                return vk as u32;
            }
        }
        // Fallback: try the layout table
        if let Some(entry) = layout_tables()
            .get(&self.layout)
            .and_then(|table| table.get(&(scancode as u16)))
        {
            return virtual_key_to_win32_vk(&entry.vk);
        }
        0
    }

    /// Convert a Windows VK code to a scancode (US layout fallback).
    fn vk_code_to_scancode(&self, vk: u32) -> Option<u8> {
        // Check the main table first
        for (sc, &v) in SCANCODE_TO_VK_US.iter().enumerate() {
            if v as u32 == vk {
                return Some(sc as u8);
            }
        }
        // Check extended table (returns scancode | 0x80)
        for (sc, &v) in SCANCODE_TO_VK_US_EXT.iter().enumerate() {
            if v as u32 == vk {
                return Some(sc as u8 | 0x80);
            }
        }
        None
    }

    /// Get a character for a VK code under the current layout (lowercase / unshifted).
    fn vk_code_to_char(&self, vk: u32) -> Option<char> {
        // Search the layout tables for a matching VK with a plain (unshifted) char
        for table in layout_tables().values() {
            for entry in table.values() {
                if virtual_key_to_win32_vk(&entry.vk) == vk {
                    return entry.plain;
                }
            }
        }
        None
    }

    /// Query modifier key state from macOS CoreGraphics (modifier keys only).
    #[cfg(target_os = "macos")]
    fn query_modifier_key_state(&self, vk: u32) -> bool {
        // Use CGEventSourceFlagsState to check physical modifier key state
        let flags = unsafe { CGEventSourceFlagsState(kCGEventSourceStateCombinedSessionState) };
        match vk as i32 {
            VK_SHIFT | VK_LSHIFT | VK_RSHIFT => {
                (flags & kCGEventFlagMaskShift as u64) != 0
            }
            VK_CONTROL | VK_LCONTROL | VK_RCONTROL => {
                (flags & kCGEventFlagMaskControl as u64) != 0
            }
            VK_MENU | VK_LMENU | VK_RMENU => {
                (flags & kCGEventFlagMaskAlternate as u64) != 0
            }
            VK_LWIN | VK_RWIN => {
                (flags & kCGEventFlagMaskCommand as u64) != 0
            }
            _ => false,
        }
    }

    /// Non-macOS fallback — just use simulated state.
    #[cfg(not(target_os = "macos"))]
    fn query_modifier_key_state(&self, vk: u32) -> bool {
        let idx = vk as usize;
        idx < 256 && (self.key_state[idx] & 0x80) != 0
    }

    // ── GetKeyState ─────────────────────────────────────────────────────
    /// Retrieves the status of the specified virtual key.
    /// Returns SHORT where:
    ///   - Bit 15 (0x8000): key is down
    ///   - Bit 0  (0x0001): key is toggled (CapsLock, NumLock, ScrollLock)
    pub fn get_key_state(&self, n_virt_key: i32) -> i16 {
        let vk = n_virt_key as usize;
        if vk >= 256 {
            return 0;
        }
        let mut result: i16 = 0;
        if self.key_state[vk] & 0x80 != 0 {
            result |= (0x8000u16 as i16);
        }
        if self.toggle_state[vk] & 0x01 != 0 {
            result |= 0x0001;
        }
        result
    }

    // ── GetAsyncKeyState ────────────────────────────────────────────────
    /// Determines whether a key is up or down at the time the function is
    /// called, and whether it was pressed since the previous call.
    /// Returns SHORT where:
    ///   - Bit 15 (0x8000): key is currently down
    ///   - Bit 0  (0x0001): key was pressed since last call (auto-resets)
    ///
    /// On macOS, modifier keys (Shift, Ctrl, Alt, Win) use CGEventSourceFlagsState
    /// for real physical state. Non-modifier keys use simulated state.
    pub fn get_async_key_state(&mut self, v_key: i32) -> i16 {
        let vk = v_key as usize;
        if vk >= 256 {
            return 0;
        }
        let mut result: i16 = 0;

        // Bit 15: currently down
        // For modifier keys on macOS, query CGEventSource for real state
        #[cfg(target_os = "macos")]
        {
            if self.query_modifier_key_state(v_key as u32) {
                result |= (0x8000u16 as i16);
            } else if self.key_state[vk] & 0x80 != 0 {
                result |= (0x8000u16 as i16);
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            if self.key_state[vk] & 0x80 != 0 {
                result |= (0x8000u16 as i16);
            }
        }

        // Bit 0: toggled since last call (auto-reset)
        if self.async_toggle[vk] & 0x01 != 0 {
            result |= 0x0001;
            self.async_toggle[vk] &= !0x01;
        }

        result
    }

    // ── GetKeyboardState ────────────────────────────────────────────────
    /// Copies the status of the 256 virtual keys into the specified buffer.
    /// `lp_key_state` must point to at least 256 bytes.
    /// Returns true on success.
    pub fn get_keyboard_state(&self, lp_key_state: &mut [u8]) -> bool {
        if lp_key_state.len() < 256 {
            return false;
        }
        lp_key_state[..256].copy_from_slice(&self.key_state[..256]);
        true
    }

    // ── MapVirtualKeyW ──────────────────────────────────────────────────
    /// Translates (maps) a virtual-key code, scan code, or character value
    /// according to the specified map type.
    ///
    /// Map types:
    ///   MAPVK_VK_TO_VSC    (0): uCode is VK → returns scancode
    ///   MAPVK_VSC_TO_VK    (1): uCode is scancode → returns VK
    ///   MAPVK_VK_TO_CHAR   (2): uCode is VK → returns lowercase character
    ///   MAPVK_VSC_TO_VK_EX (3): uCode is scancode (extended) → returns VK
    ///   MAPVK_VK_TO_VSC_EX (4): uCode is VK → returns extended scancode
    pub fn map_virtual_key_w(&self, code: u32, map_type: u32) -> u32 {
        match map_type {
            MAPVK_VK_TO_VSC => {
                // VK → scancode (low byte)
                self.vk_code_to_scancode(code)
                    .map(|sc| (sc & 0x7F) as u32)
                    .unwrap_or(0)
            }
            MAPVK_VSC_TO_VK => {
                // scancode → VK
                self.scancode_to_vk_code(code as u8)
            }
            MAPVK_VK_TO_CHAR => {
                // VK → lowercase character
                self.vk_code_to_char(code)
                    .map(|c| c as u32)
                    .unwrap_or(0)
            }
            MAPVK_VSC_TO_VK_EX => {
                // Extended scancode → VK
                let scancode = (code as u8) | 0x80; // Mark as extended
                self.scancode_to_vk_code(scancode)
            }
            MAPVK_VK_TO_VSC_EX => {
                // VK → extended scancode
                self.vk_code_to_scancode(code)
                    .filter(|sc| *sc & 0x80 != 0)
                    .map(|sc| (sc & 0x7F) as u32)
                    .unwrap_or(0)
            }
            _ => 0,
        }
    }

    // ── VkKeyScanW ──────────────────────────────────────────────────────
    /// Translates a character to the corresponding virtual-key code and
    /// shift state. Returns a SHORT where:
    ///   - Low byte  = virtual-key code (scancode)
    ///   - High byte = shift state (bit 0 = shift, bit 1 = ctrl, bit 2 = alt)
    /// Returns -1 if no character value can be found.
    pub fn vk_key_scan_w(&self, ch: u16) -> i16 {
        let ch_char = char::from_u32(ch as u32).unwrap_or('\0');
        let tables = layout_tables();
        let table = match tables.get(&self.layout) {
            Some(t) => t,
            None => return -1,
        };
        for (scancode, entry) in table.iter() {
            if entry.plain == Some(ch_char) {
                return *scancode as i16; // no shift
            }
            if entry.shifted == Some(ch_char) {
                return *scancode as i16 | 0x0100; // shift pressed
            }
            if entry.altgr == Some(ch_char) {
                return *scancode as i16 | 0x0200; // altgr/ctrl+alt pressed
            }
        }
        -1
    }

    // ── SetWindowsHookExW / CallNextHookEx ─────────────────────────────
    /// Installs a hook procedure into the hook chain.
    /// Returns the hook handle (id) on success, or 0 on failure.
    pub fn set_windows_hook_ex_w(
        &mut self,
        hook_type: i32,
        callback: u64,
        module: u64,
        thread_id: u32,
    ) -> i32 {
        let id = self.next_hook_id;
        self.next_hook_id += 1;
        self.hooks.insert(
            id,
            HookInfo {
                id,
                hook_type,
                callback,
                module,
                thread_id,
            },
        );
        id
    }

    /// Passes the hook information to the next hook procedure in the
    /// current hook chain. Returns the value returned by the next hook,
    /// or 0 if no next hook exists.
    pub fn call_next_hook_ex(&self, _id: i32, _n_code: i32, _wparam: usize, _lparam: isize) -> usize {
        // Simplified: return 0 to indicate no further processing needed.
        // In a full implementation this would chain to the next hook.
        0
    }

    /// Unhook a previously installed hook.
    pub fn unhook_windows_hook_ex(&mut self, id: i32) -> bool {
        self.hooks.remove(&id).is_some()
    }

    pub fn inject_mouse_input(
        &mut self,
        hwnd: Hwnd,
        device_id: &str,
        raw_dx: i32,
        raw_dy: i32,
        buttons: &[MouseButtonEvent],
        wheel_delta: i32,
        hwheel_delta: i32,
    ) -> AppResult<MousePacket> {
        self.inject_mouse_input_internal(
            hwnd,
            device_id,
            raw_dx,
            raw_dy,
            buttons,
            wheel_delta,
            hwheel_delta,
            true,
        )
    }

    fn inject_mouse_input_internal(
        &mut self,
        hwnd: Hwnd,
        device_id: &str,
        raw_dx: i32,
        raw_dy: i32,
        buttons: &[MouseButtonEvent],
        wheel_delta: i32,
        hwheel_delta: i32,
        record: bool,
    ) -> AppResult<MousePacket> {
        self.window(hwnd)?;
        if !self.mouse_devices.contains(device_id) {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unknown mouse device {device_id}"),
            ));
        }
        if record {
            self.recorded_input.push(InputReplayEvent::Mouse {
                hwnd,
                device_id: device_id.to_string(),
                raw_dx,
                raw_dy,
                buttons: buttons.to_vec(),
                wheel_delta,
                hwheel_delta,
            });
        }
        let (cursor_x, cursor_y) = self.confine_cursor(self.cursor_pos.0 + raw_dx, self.cursor_pos.1 + raw_dy);
        self.cursor_pos = (cursor_x, cursor_y);
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::RawInput,
            wparam: raw_dx as i64,
            lparam: raw_dy as i64,
            translated: false,
            device_id: Some(device_id.to_string()),
        })?;
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::MouseMove,
            wparam: cursor_x as i64,
            lparam: cursor_y as i64,
            translated: false,
            device_id: Some(device_id.to_string()),
        })?;
        if wheel_delta != 0 {
            self.enqueue(Message {
                hwnd: Some(hwnd),
                kind: MessageKind::MouseWheel,
                wparam: wheel_delta as i64,
                lparam: 0,
                translated: false,
                device_id: Some(device_id.to_string()),
            })?;
        }
        if hwheel_delta != 0 {
            self.enqueue(Message {
                hwnd: Some(hwnd),
                kind: MessageKind::MouseHWheel,
                wparam: hwheel_delta as i64,
                lparam: 0,
                translated: false,
                device_id: Some(device_id.to_string()),
            })?;
        }
        for button in buttons {
            match (button.button, button.pressed) {
                (MouseButton::Left, true) => {
                    self.enqueue(Message {
                        hwnd: Some(hwnd),
                        kind: MessageKind::LButtonDown,
                        wparam: cursor_x as i64,
                        lparam: cursor_y as i64,
                        translated: false,
                        device_id: Some(device_id.to_string()),
                    })?;
                }
                (MouseButton::Left, false) => {
                    self.enqueue(Message {
                        hwnd: Some(hwnd),
                        kind: MessageKind::LButtonUp,
                        wparam: cursor_x as i64,
                        lparam: cursor_y as i64,
                        translated: false,
                        device_id: Some(device_id.to_string()),
                    })?;
                }
                (MouseButton::X1 | MouseButton::X2, true) => {
                    let wparam = match button.button {
                        MouseButton::X1 => 1,
                        MouseButton::X2 => 2,
                        _ => 0,
                    };
                    self.enqueue(Message {
                        hwnd: Some(hwnd),
                        kind: MessageKind::XButtonDown,
                        wparam,
                        lparam: 0,
                        translated: false,
                        device_id: Some(device_id.to_string()),
                    })?;
                }
                _ => {}
            }
        }
        Ok(MousePacket {
            raw_dx,
            raw_dy,
            cursor_x,
            cursor_y,
            wheel_delta,
            hwheel_delta,
            buttons: buttons.to_vec(),
        })
    }

    pub fn add_controller(
        &mut self,
        target_window: Option<Hwnd>,
        spec: ControllerSpec,
    ) -> AppResult<String> {
        let guid = util::deterministic_guid(
            &format!(
                "{:04x}:{:04x}:{}:{}:{:?}",
                spec.vendor_id, spec.product_id, spec.serial, spec.name, spec.kind
            ),
            true,
        );
        let record = ControllerRecord {
            spec,
            guid: guid.clone(),
            xinput_slot: None,
            packet_number: 1,
            rumble: RumbleState {
                left_motor: 0,
                right_motor: 0,
            },
            directinput_format: None,
            acquired: false,
        };
        self.controllers.insert(guid.clone(), record);
        self.reassign_xinput_slots();
        if let Some(hwnd) = target_window.or(self.foreground) {
            self.enqueue(Message {
                hwnd: Some(hwnd),
                kind: MessageKind::InputDeviceChange,
                wparam: 1,
                lparam: 0,
                translated: false,
                device_id: Some(guid.clone()),
            })?;
        }
        Ok(guid)
    }

    pub fn remove_controller(&mut self, target_window: Option<Hwnd>, guid: &str) -> AppResult<()> {
        self.controllers.remove(guid).ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, format!("unknown controller {guid}"))
        })?;
        self.reassign_xinput_slots();
        if let Some(hwnd) = target_window.or(self.foreground) {
            self.enqueue(Message {
                hwnd: Some(hwnd),
                kind: MessageKind::InputDeviceChange,
                wparam: 0,
                lparam: 0,
                translated: false,
                device_id: Some(guid.to_string()),
            })?;
        }
        Ok(())
    }

    pub fn xinput_get_state(&self, slot: u8) -> AppResult<XInputState> {
        let controller = self.controller_by_xinput_slot(slot)?;
        Ok(XInputState {
            packet_number: controller.packet_number,
            buttons: controller.spec.buttons.clone(),
            axes: controller.spec.axes.clone(),
        })
    }

    pub fn xinput_get_capabilities(&self, slot: u8) -> AppResult<XInputCapabilities> {
        let controller = self.controller_by_xinput_slot(slot)?;
        Ok(XInputCapabilities {
            kind: controller.spec.kind,
            transport: controller.spec.transport,
            supports_rumble: !controller.spec.supported_effects.is_empty(),
            battery: controller.spec.battery.clone(),
        })
    }

    pub fn xinput_get_battery_information(&self, slot: u8) -> AppResult<BatteryInfo> {
        Ok(self.controller_by_xinput_slot(slot)?.spec.battery.clone())
    }

    pub fn xinput_get_keystroke(&self, slot: u8) -> AppResult<Option<String>> {
        let controller = self.controller_by_xinput_slot(slot)?;
        Ok(controller.spec.buttons.iter().next().cloned())
    }

    pub fn xinput_set_state(&mut self, slot: u8, left_motor: u16, right_motor: u16) -> AppResult<()> {
        let guid = self.controller_guid_by_xinput_slot(slot)?;
        let controller = self.controller_mut(&guid)?;
        controller.rumble = RumbleState {
            left_motor,
            right_motor,
        };
        controller.packet_number += 1;
        Ok(())
    }

    pub fn xinput_rumble_state(&self, slot: u8) -> AppResult<RumbleState> {
        Ok(self.controller_by_xinput_slot(slot)?.rumble.clone())
    }

    pub fn enum_directinput_devices(&self) -> Vec<DirectInputDeviceInfo> {
        let mut devices = self.controllers.values().collect::<Vec<_>>();
        devices.sort_by(|left, right| left.guid.cmp(&right.guid));
        devices
            .into_iter()
            .map(|controller| DirectInputDeviceInfo {
                guid: controller.guid.clone(),
                name: controller.spec.name.clone(),
                axes: controller.spec.axes.keys().copied().collect(),
                xinput_slot: controller.xinput_slot,
            })
            .collect()
    }

    pub fn create_directinput_device(&mut self, guid: &str) -> AppResult<String> {
        let controller = self.controller(guid)?;
        Ok(controller.guid.clone())
    }

    pub fn set_data_format(&mut self, guid: &str, format: DirectInputDataFormat) -> AppResult<()> {
        self.controller_mut(guid)?.directinput_format = Some(format);
        Ok(())
    }

    pub fn acquire_device(&mut self, guid: &str) -> AppResult<()> {
        self.controller_mut(guid)?.acquired = true;
        Ok(())
    }

    pub fn unacquire_device(&mut self, guid: &str) -> AppResult<()> {
        self.controller_mut(guid)?.acquired = false;
        Ok(())
    }

    pub fn get_device_state(&self, guid: &str) -> AppResult<DirectInputState> {
        let controller = self.controller(guid)?;
        if !controller.acquired {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("controller {guid} not acquired"),
            ));
        }
        let axes = controller
            .spec
            .axes
            .iter()
            .map(|(axis, raw)| {
                let normalized = controller
                    .spec
                    .calibrations
                    .get(axis)
                    .map(|calibration| normalize_axis(*raw, *calibration))
                    .unwrap_or(*raw);
                (*axis, normalized)
            })
            .collect();
        Ok(DirectInputState {
            axes,
            buttons: controller.spec.buttons.clone(),
        })
    }

    pub fn get_device_data(&mut self, guid: &str) -> AppResult<Vec<DirectInputEvent>> {
        let controller = self.controller(guid)?;
        if !controller.acquired {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("controller {guid} not acquired"),
            ));
        }
        let mut events = Vec::new();
        for (axis, raw) in &controller.spec.axes {
            let value = controller
                .spec
                .calibrations
                .get(axis)
                .map(|calibration| normalize_axis(*raw, *calibration))
                .unwrap_or(*raw);
            events.push(DirectInputEvent {
                sequence: self.next_sequence + events.len() as u64,
                object: format!("axis::{axis:?}"),
                value,
            });
        }
        for button in &controller.spec.buttons {
            events.push(DirectInputEvent {
                sequence: self.next_sequence + events.len() as u64,
                object: format!("button::{button}"),
                value: 1,
            });
        }
        self.next_sequence += events.len() as u64;
        Ok(events)
    }

    pub fn apply_force_feedback(
        &mut self,
        guid: &str,
        effect: ForceFeedbackEffect,
        magnitude: i32,
        duration_ms: u32,
    ) -> AppResult<ForceFeedbackPlan> {
        let controller = self.controller(guid)?;
        if !controller.spec.supported_effects.contains(&effect) {
            return Err(AppError::new(
                ReasonCode::RcInputUnsupported,
                format!("{effect:?} force feedback is unsupported for {guid}"),
            ));
        }
        Ok(ForceFeedbackPlan {
            effect,
            magnitude,
            duration_ms,
        })
    }

    pub fn claim_input_owner(&mut self, owner: &str) -> bool {
        match &self.input_owner {
            None => {
                self.input_owner = Some(owner.to_string());
                true
            }
            Some(existing) if existing == owner => true,
            Some(_) => false,
        }
    }

    pub fn release_input_owner(&mut self, owner: &str) -> bool {
        if self.input_owner.as_deref() == Some(owner) {
            self.input_owner = None;
            true
        } else {
            false
        }
    }

    pub fn input_owner(&self) -> Option<&str> {
        self.input_owner.as_deref()
    }

    /// Register raw input devices.
    pub fn register_raw_input_devices(&mut self, devices: &[RawInputRegistration]) -> AppResult<()> {
        for device in devices {
            // Replace existing registration with same (usage_page, usage, target_hwnd)
            self.raw_input_devices.retain(|d| {
                !(d.usage_page == device.usage_page
                    && d.usage == device.usage
                    && d.target_hwnd == device.target_hwnd)
            });
            self.raw_input_devices.push(device.clone());
        }
        Ok(())
    }

    /// Return the number of bytes needed for a RAWINPUT structure matching
    /// the given command (RID_HEADER, RID_INPUT, or RID_DEVICE_INFO).
    pub fn raw_input_data_size(&self, command: u32) -> AppResult<u32> {
        match command {
            // RID_HEADER → sizeof(RAWINPUTHEADER) = 24 (x64) / 20 (x86)
            0x10000001 => Ok(24),
            // RID_INPUT → sizeof(RAWINPUT) = 40+ for mouse/keyboard/HID
            0x10000002 => Ok(48),
            // RID_DEVICE_INFO → sizeof(RID_DEVICE_INFO) = 24
            0x10000003 => Ok(24),
            _ => Err(AppError::new(
                crate::reason::ReasonCode::RcInputUnsupported,
                format!("unknown raw input command {command:#x}"),
            )),
        }
    }

    /// Get registered raw input devices count.
    pub fn raw_input_device_count(&self) -> u32 {
        self.raw_input_devices.len() as u32
    }

    /// Copy registered raw input devices into the output slice, returning the
    /// number written (or the required count if output is too small).
    pub fn get_registered_raw_input_devices(&self, output: &mut [RawInputRegistration]) -> usize {
        let count = output.len().min(self.raw_input_devices.len());
        for (i, dev) in self.raw_input_devices.iter().enumerate().take(count) {
            output[i] = dev.clone();
        }
        count
    }

    /// Return the number of bytes needed for a RID_DEVICE_INFO structure for
    /// the given device handle (or the default size if unknown).
    pub fn raw_input_device_info_size(&self, _handle: u64, command: u32) -> AppResult<u32> {
        match command {
            // RIDI_DEVICENAME → wide-char string length in bytes
            0x20000001 => {
                // Return size of "\\??\\HID#default#col01" (approx 28 wide chars = 56 bytes)
                Ok(56)
            }
            // RIDI_DEVICEINFO → sizeof(RID_DEVICE_INFO) = 24
            0x20000002 => Ok(24),
            // RIDI_PREPARSEDDATA → not supported
            0x20000003 => Ok(0),
            _ => Err(AppError::new(
                crate::reason::ReasonCode::RcInputUnsupported,
                format!("unknown raw input device info command {command:#x}"),
            )),
        }
    }

    pub fn window_state(&self, hwnd: Hwnd) -> AppResult<WindowState> {
        let window = self.window(hwnd)?;
        Ok(WindowState {
            hwnd: window.hwnd,
            class_name: window.class_name.clone(),
            title: window.title.clone(),
            width: window.width,
            height: window.height,
            visible: window.visible,
            fullscreen: window.fullscreen.clone(),
            monitor_id: window.monitor_id,
            dpi: window.dpi,
        })
    }

    pub fn window_previews(&self) -> Vec<WindowPreview> {
        self.windows
            .values()
            .filter(|window| !window.destroyed)
            .map(|window| WindowPreview {
                hwnd: window.hwnd,
                parent: window.parent,
                class_name: window.class_name.clone(),
                title: window.title.clone(),
                x: window.x,
                y: window.y,
                width: window.width,
                height: window.height,
                visible: window.visible,
                enabled: window.enabled,
                control_id: window.control_id,
            })
            .collect()
    }

    fn queue_resize(&mut self, hwnd: Hwnd, width: u32, height: u32) -> AppResult<()> {
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::WindowPosChanging,
            wparam: width as i64,
            lparam: height as i64,
            translated: false,
            device_id: None,
        })?;
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::Size,
            wparam: width as i64,
            lparam: height as i64,
            translated: false,
            device_id: None,
        })?;
        self.queue_paint(hwnd)
    }

    fn queue_paint(&mut self, hwnd: Hwnd) -> AppResult<()> {
        let Some(window) = self.windows.get(&hwnd) else {
            return Ok(());
        };
        if window.destroyed || !window.visible {
            return Ok(());
        }
        let already_queued = self
            .message_queue
            .iter()
            .any(|message| message.hwnd == Some(hwnd) && message.kind == MessageKind::Paint);
        if already_queued {
            return Ok(());
        }
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::Paint,
            wparam: 0,
            lparam: 0,
            translated: false,
            device_id: None,
        })
    }

    fn enqueue(&mut self, message: Message) -> AppResult<()> {
        if self.total_queued_messages() >= self.input_queue_capacity {
            return Err(AppError::new(
                ReasonCode::RcInputUnsupported,
                "input queue overflow",
            ));
        }
        self.message_queue.push_back(message);
        Ok(())
    }

    fn enqueue_thread_message(&mut self, thread_id: u32, message: Message) -> AppResult<()> {
        if self.total_queued_messages() >= self.input_queue_capacity {
            return Err(AppError::new(
                ReasonCode::RcInputUnsupported,
                "input queue overflow",
            ));
        }
        self.thread_message_queues
            .entry(thread_id)
            .or_default()
            .push_back(message);
        Ok(())
    }

    fn total_queued_messages(&self) -> usize {
        self.message_queue.len()
            + self
                .thread_message_queues
                .values()
                .map(VecDeque::len)
                .sum::<usize>()
    }

    fn map_fullscreen_state(&mut self, title: &str, requested_exclusive: bool) -> FullscreenState {
        if requested_exclusive {
            self.fullscreen_shims.insert(title.to_string());
            FullscreenState {
                mode: FullscreenMode::Borderless,
                requested_exclusive,
                shim_applied: true,
            }
        } else {
            FullscreenState {
                mode: FullscreenMode::Windowed,
                requested_exclusive,
                shim_applied: false,
            }
        }
    }

    fn effective_dpi(&self, monitor_id: u32) -> AppResult<u32> {
        let monitor = self.monitor(monitor_id)?;
        Ok(match self.dpi_context {
            DpiAwarenessContext::Unaware => 96,
            DpiAwarenessContext::SystemAware => self.monitors.get(&1).map(|primary| primary.dpi_x).unwrap_or(96),
            DpiAwarenessContext::PerMonitorAwareV2 => monitor.dpi_x,
        })
    }

    fn confine_cursor(&self, x: i32, y: i32) -> (i32, i32) {
        self.clip_rect
            .map(|rect| rect.confine(x, y))
            .unwrap_or((x, y))
    }

    fn monitor(&self, monitor_id: u32) -> AppResult<&MonitorInfo> {
        self.monitors.get(&monitor_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, format!("unknown monitor {monitor_id}"))
        })
    }

    fn window(&self, hwnd: Hwnd) -> AppResult<&WindowRecord> {
        self.windows.get(&hwnd).ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, format!("unknown window {hwnd}"))
        })
    }

    fn window_mut(&mut self, hwnd: Hwnd) -> AppResult<&mut WindowRecord> {
        self.windows.get_mut(&hwnd).ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, format!("unknown window {hwnd}"))
        })
    }

    fn controller(&self, guid: &str) -> AppResult<&ControllerRecord> {
        self.controllers.get(guid).ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, format!("unknown controller {guid}"))
        })
    }

    fn controller_mut(&mut self, guid: &str) -> AppResult<&mut ControllerRecord> {
        self.controllers.get_mut(guid).ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, format!("unknown controller {guid}"))
        })
    }

    fn controller_by_xinput_slot(&self, slot: u8) -> AppResult<&ControllerRecord> {
        self.controllers
            .values()
            .find(|controller| controller.xinput_slot == Some(slot))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("no XInput controller in slot {slot}"),
                )
            })
    }

    fn controller_guid_by_xinput_slot(&self, slot: u8) -> AppResult<String> {
        Ok(self.controller_by_xinput_slot(slot)?.guid.clone())
    }

    /// Polls for game controller hotplug events (connections/disconnections).
    ///
    /// Uses the macOS HID monitor to detect newly connected or disconnected
    /// game controllers and updates the internal controller state accordingly.
    ///
    /// New controllers are added with a standard gamepad layout (six axes,
    /// ten buttons) and appropriate XInput classification. Disconnected
    /// controllers are removed from the controller map.
    ///
    /// This method is polling-based and should be called regularly from the
    /// main input loop (e.g., [`poll_live_input`](crate::pe_runtime::PeHostRuntime::poll_live_input)).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying HID scan (`ioreg`) fails
    /// critically. Temporary failures (e.g., `ioreg` not available) are
    /// handled gracefully and return `Ok(())`.
    pub fn poll_controller_hotplug(&mut self) -> AppResult<()> {
        let (added, removed) = self.hid_monitor.poll_for_changes()?;

        for controller in added {
            // Build a standard ControllerSpec from the detected host controller.
            let spec = ControllerSpec {
                name: controller.name.clone(),
                kind: if controller.xinput_capable {
                    ControllerKind::Xbox
                } else {
                    ControllerKind::ThirdPartyXInput
                },
                transport: ControllerTransport::Hid,
                vendor_id: controller.vendor_id,
                product_id: controller.product_id,
                serial: controller.identifier.clone(),
                xinput_capable: controller.xinput_capable,
                battery: BatteryInfo {
                    level_percent: 100,
                    wired: true,
                },
                axes: BTreeMap::from([
                    (DeviceAxis::X, 0),
                    (DeviceAxis::Y, 0),
                    (DeviceAxis::Z, 0),
                    (DeviceAxis::Rx, 0),
                    (DeviceAxis::Ry, 0),
                    (DeviceAxis::Rz, 0),
                ]),
                calibrations: BTreeMap::from([
                    (
                        DeviceAxis::X,
                        AxisCalibration {
                            min: -32768,
                            center: 0,
                            max: 32767,
                        },
                    ),
                    (
                        DeviceAxis::Y,
                        AxisCalibration {
                            min: -32768,
                            center: 0,
                            max: 32767,
                        },
                    ),
                    (
                        DeviceAxis::Z,
                        AxisCalibration {
                            min: -32768,
                            center: 0,
                            max: 32767,
                        },
                    ),
                    (
                        DeviceAxis::Rx,
                        AxisCalibration {
                            min: -32768,
                            center: 0,
                            max: 32767,
                        },
                    ),
                    (
                        DeviceAxis::Ry,
                        AxisCalibration {
                            min: -32768,
                            center: 0,
                            max: 32767,
                        },
                    ),
                    (
                        DeviceAxis::Rz,
                        AxisCalibration {
                            min: -32768,
                            center: 0,
                            max: 32767,
                        },
                    ),
                ]),
                buttons: BTreeSet::from([
                    "A".to_string(),
                    "B".to_string(),
                    "X".to_string(),
                    "Y".to_string(),
                    "LB".to_string(),
                    "RB".to_string(),
                    "BACK".to_string(),
                    "START".to_string(),
                    "LTHUMB".to_string(),
                    "RTHUMB".to_string(),
                ]),
                supported_effects: BTreeSet::new(),
            };

            // Use the existing add_controller infrastructure.
            let target_window = self.foreground;
            self.add_controller(target_window, spec)?;
        }

        for controller in removed {
            self.remove_controller(self.foreground, &controller.identifier)?;
        }

        Ok(())
    }

    fn reassign_xinput_slots(&mut self) {
        let mut guids = self
            .controllers
            .iter()
            .filter(|(_, controller)| controller.spec.xinput_capable)
            .map(|(guid, _)| guid.clone())
            .collect::<Vec<_>>();
        guids.sort();
        for controller in self.controllers.values_mut() {
            controller.xinput_slot = None;
        }
        for (index, guid) in guids.into_iter().take(4).enumerate() {
            if let Some(controller) = self.controllers.get_mut(&guid) {
                controller.xinput_slot = Some(index as u8);
            }
        }
    }

    // ── Touch / Pointer API ──────────────────────────────────────────────

    /// Register a window for touch input (RegisterTouchWindow).
    /// Adds the HWND to the registered windows set and stores the flags.
    pub fn register_touch_window(&mut self, hwnd: u32, _flags: u32) -> AppResult<()> {
        if !self.registered_windows().contains(&hwnd) {
            self.touch_state.registered_windows.push(hwnd);
        }
        Ok(())
    }

    /// Unregister a window from touch input (UnregisterTouchWindow).
    pub fn unregister_touch_window(&mut self, hwnd: u32) -> AppResult<()> {
        self.touch_state.registered_windows.retain(|h| *h != hwnd);
        Ok(())
    }

    /// Check if a window is registered for touch.
    pub fn is_touch_window(&self, hwnd: u32) -> bool {
        self.touch_state.registered_windows.contains(&hwnd)
    }

    /// Get registered touch windows.
    pub fn registered_windows(&self) -> &[u32] {
        &self.touch_state.registered_windows
    }

    /// Store touch inputs under a handle for later retrieval by GetTouchInputInfo.
    /// Returns the handle that was allocated.
    pub fn store_touch_inputs(&mut self, hwnd: u32, inputs: Vec<TouchInput>) -> u32 {
        let handle = self.touch_state.next_touch_handle;
        self.touch_state.next_touch_handle += 1;
        self.touch_state
            .touch_handles
            .insert(handle, inputs);
        // Also store as pending
        for input in &self.touch_state.touch_handles[&handle] {
            self.touch_state.touch_inputs.push((hwnd, *input));
        }
        handle
    }

    /// Retrieve stored touch inputs by handle (GetTouchInputInfo).
    pub fn get_touch_input_info(&self, handle: u32) -> AppResult<Vec<TouchInput>> {
        self.touch_state
            .touch_handles
            .get(&handle)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    crate::reason::ReasonCode::RcUnimplInsn,
                    format!("GetTouchInputInfo: invalid handle {handle}"),
                )
            })
    }

    /// Close a touch input handle (CloseTouchInputHandle).
    pub fn close_touch_input_handle(&mut self, handle: u32) -> AppResult<()> {
        self.touch_state.touch_handles.remove(&handle);
        self.touch_state
            .touch_inputs
            .retain(|(_, ti)| ti.id != handle);
        Ok(())
    }

    /// Initialize a pointer device (InitializePointerDevice stub).
    pub fn initialize_pointer_device(&mut self, hwnd: u32) -> AppResult<()> {
        if !self.touch_state.pointer_devices.contains(&hwnd) {
            self.touch_state.pointer_devices.push(hwnd);
        }
        Ok(())
    }

    /// Retrieve PointerInfo by pointer_id (GetPointerInfo).
    pub fn get_pointer_info(&self, pointer_id: u32) -> AppResult<PointerInfo> {
        self.touch_state
            .pointer_infos
            .get(&pointer_id)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    crate::reason::ReasonCode::RcUnimplInsn,
                    format!("GetPointerInfo: unknown pointer_id {pointer_id}"),
                )
            })
    }

    /// Retrieve PointerPenInfo by pointer_id (GetPointerPenInfo).
    pub fn get_pointer_pen_info(&self, pointer_id: u32) -> AppResult<PointerPenInfo> {
        self.touch_state
            .pointer_pen_infos
            .get(&pointer_id)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    crate::reason::ReasonCode::RcUnimplInsn,
                    format!("GetPointerPenInfo: unknown pointer_id {pointer_id}"),
                )
            })
    }

    /// Skip a pointer frame (SkipPointerFrame stub).
    pub fn skip_pointer_frame(&mut self, _pointer_id: u32) -> AppResult<()> {
        // No-op: we don't batch pointer frames.
        Ok(())
    }

    /// Store a PointerInfo for later retrieval.
    pub fn store_pointer_info(&mut self, pointer_id: u32, info: PointerInfo) {
        self.touch_state.pointer_infos.insert(pointer_id, info);
    }

    /// Store a PointerPenInfo for later retrieval.
    pub fn store_pointer_pen_info(&mut self, pointer_id: u32, info: PointerPenInfo) {
        self.touch_state.pointer_pen_infos.insert(pointer_id, info);
    }

    /// Dispatch macOS touch points as Win32 WM_TOUCH messages.
    /// Each touch point is mapped to the appropriate TOUCHEVENTF_* flags
    /// and the corresponding WM_TOUCHDOWN/UP/MOVE message is posted.
    #[cfg(target_os = "macos")]
    pub fn dispatch_macos_touch_event(
        &mut self,
        target_hwnd: u32,
        touch_points: &[TouchPoint],
    ) -> AppResult<()> {
        let mut touch_inputs: Vec<TouchInput> = Vec::new();
        for tp in touch_points {
            let flags = match tp.phase {
                TouchPhase::Began => TOUCHEVENTF_DOWN,
                TouchPhase::Moved => TOUCHEVENTF_MOVE,
                TouchPhase::Ended => TOUCHEVENTF_UP,
                TouchPhase::Cancelled => TOUCHEVENTF_UP,
                TouchPhase::Stationary => 0,
            };
            let flags = flags
                | TOUCHEVENTF_INRANGE
                | if tp.is_pen {
                    TOUCHEVENTF_PEN
                } else {
                    0
                };
            let source = if tp.is_pen { 2u32 } else { 1u32 };
            // Convert f64 coordinates to i32 (in hundredths of a pixel, per TouchInput spec)
            let x = (tp.x * 100.0) as i32;
            let y = (tp.y * 100.0) as i32;
            let pressure = (tp.pressure.min(1.0).max(0.0) * 1024.0) as u32;
            touch_inputs.push(TouchInput {
                x,
                y,
                source,
                id: tp.id,
                flags,
                mask: TOUCHINPUTMASKF_PRESSURE | TOUCHINPUTMASKF_CONTACTAREA,
                time: 0,
                extra_info: 0,
                cx: 10, // default contact area
                cy: 10,
            });
            // Also store PointerInfo for WM_POINTER dispatch
            let pointer_flags = POINTER_FLAG_INRANGE
                | POINTER_FLAG_INCONTACT
                | if matches!(tp.phase, TouchPhase::Cancelled) {
                    POINTER_FLAG_CANCELED
                } else {
                    POINTER_FLAG_CONFIDENCE
                };
            let pointer_info = PointerInfo {
                pointer_type: if tp.is_pen { 2 } else { 1 },
                pointer_id: tp.id,
                frame_id: 0,
                pointer_flags,
                source_device: 0,
                hwnd_target: target_hwnd as isize,
                pt_pixel_x: (tp.x) as i32,
                pt_pixel_y: (tp.y) as i32,
                pt_hic_res_x: 0,
                pt_hic_res_y: 0,
                pt_pixel_z: 0,
                display_time: 0,
                key_state: 0,
                performance_count: 0,
            };
            self.store_pointer_info(tp.id, pointer_info);
        }
        if !touch_inputs.is_empty() {
            // Compute lparam before moving touch_inputs into store_touch_inputs
            let lparam = touch_inputs
                .iter()
                .fold(0u32, |acc, ti| acc | ti.flags);
            let handle = self.store_touch_inputs(target_hwnd, touch_inputs);
            // wParam = touch handle, lParam = flags (TOUCHEVENTF_* packed)
            self.post_message_w(
                target_hwnd,
                MessageKind::Other(WM_TOUCH),
                handle as i64,
                lparam as i64,
            )?;
        }
        Ok(())
    }

    /// Access the touch state (for inspection/testing).
    pub fn touch_state(&self) -> &TouchState {
        &self.touch_state
    }
}

fn is_builtin_window_class(class_name: &str) -> bool {
    matches!(
        class_name.to_ascii_lowercase().as_str(),
        "#32770"
            | "button"
            | "edit"
            | "static"
            | "richedit"
            | "riched20w"
            | "riched32"
            | "msctls_progress32"
    )
}

fn stable_device_id(prefix: &str, source: &str) -> String {
    let hash = util::sha256_bytes(source.as_bytes());
    format!("{prefix}-{}", &hash[..16])
}

fn normalize_axis(raw: i32, calibration: AxisCalibration) -> i32 {
    let value = if raw >= calibration.center {
        let span = (calibration.max - calibration.center).max(1) as i64;
        ((raw - calibration.center) as i64 * 1000 / span) as i32
    } else {
        let span = (calibration.center - calibration.min).max(1) as i64;
        -((calibration.center - raw) as i64 * 1000 / span) as i32
    };
    value.clamp(-1000, 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_window_queues_paint_message() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, false, false, None, 1)
            .expect("create window");

        assert_eq!(user32.get_message_w().expect("nc create").kind, MessageKind::NcCreate);
        assert_eq!(user32.get_message_w().expect("create").kind, MessageKind::Create);

        user32.show_window(hwnd, 1).expect("show window");
        let kinds = std::iter::from_fn(|| user32.get_message_w().map(|message| message.kind))
            .collect::<Vec<_>>();

        assert!(kinds.contains(&MessageKind::ShowWindow));
        assert!(kinds.contains(&MessageKind::Size));
        assert!(kinds.contains(&MessageKind::Paint));
    }

    #[test]
    fn invalidate_window_queues_paint_once() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, true, false, None, 1)
            .expect("create window");

        let _ = std::iter::from_fn(|| user32.get_message_w()).collect::<Vec<_>>();

        assert!(user32.invalidate_window(Some(hwnd), false).expect("invalidate window"));
        assert!(user32.invalidate_window(Some(hwnd), false).expect("invalidate window"));

        let kinds = std::iter::from_fn(|| user32.get_message_w().map(|message| message.kind))
            .collect::<Vec<_>>();

        assert_eq!(
            kinds.iter().filter(|kind| **kind == MessageKind::Paint).count(),
            1
        );
    }

    #[test]
    fn post_thread_message_queues_message_for_target_thread() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);

        user32
            .post_thread_message_w(7, MessageKind::Other(0x0400), 11, 22)
            .expect("post thread message");

        assert!(user32.get_message_for_thread(1).is_none());
        let message = user32.get_message_for_thread(7).expect("target thread message");
        assert_eq!(message.hwnd, None);
        assert_eq!(message.kind, MessageKind::Other(0x0400));
        assert_eq!(message.wparam, 11);
        assert_eq!(message.lparam, 22);
    }

    #[test]
    fn monitor_from_window_returns_window_monitor_or_primary_fallback() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, false, false, None, 2)
            .expect("create window");

        assert_eq!(user32.monitor_from_window(Some(hwnd), 0), 2);
        assert_eq!(user32.monitor_from_window(None, 0x1), 1);
        assert_eq!(user32.monitor_from_window(Some(0xdead_beef), 0x2), 1);
        assert_eq!(user32.monitor_from_window(None, 0), 0);
    }

    #[test]
    fn us_layout_supports_live_session_control_keys() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let modifiers = KeyModifiers {
            shift: false,
            altgr: false,
        };

        for (scancode, output_char) in [
            (0x11, 'w'),
            (0x13, 'r'),
            (0x19, 'p'),
            (0x1c, '\r'),
            (0x1f, 's'),
            (0x20, 'd'),
            (0x2e, 'c'),
            (0x31, 'n'),
            (0x39, ' '),
        ] {
            let translation = user32
                .translate_scancode(scancode, modifiers)
                .unwrap_or_else(|_| panic!("missing live-session scancode {scancode:#x}"));
            assert_eq!(translation.output_char, Some(output_char));
            assert_eq!(translation.dead_char, None);
        }
    }

    // ── Touch / Pointer tests ────────────────────────────────────────────

    #[test]
    fn register_touch_window_creates_entry() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert!(!user32.is_touch_window(0x1234));
        user32
            .register_touch_window(0x1234, TWF_FINETOUCH)
            .expect("register touch window");
        assert!(user32.is_touch_window(0x1234));
        assert_eq!(user32.registered_windows(), &[0x1234]);
    }

    #[test]
    fn unregister_touch_window_removes_entry() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32
            .register_touch_window(0x1234, TWF_FINETOUCH)
            .expect("register touch window");
        assert!(user32.is_touch_window(0x1234));
        user32
            .unregister_touch_window(0x1234)
            .expect("unregister touch window");
        assert!(!user32.is_touch_window(0x1234));
    }

    #[test]
    fn get_touch_input_info_returns_stored_data() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let inputs = vec![TouchInput {
            x: 100,
            y: 200,
            source: 1,
            id: 42,
            flags: TOUCHEVENTF_DOWN | TOUCHEVENTF_INRANGE | TOUCHEVENTF_PRIMARY,
            mask: TOUCHINPUTMASKF_PRESSURE,
            time: 0,
            extra_info: 0,
            cx: 10,
            cy: 10,
        }];
        let handle = user32.store_touch_inputs(0x1234, inputs.clone());
        let retrieved = user32
            .get_touch_input_info(handle)
            .expect("get touch input info");
        assert_eq!(retrieved.len(), 1);
        let ti = retrieved[0];
        let (tid, tx, ty) = (ti.id, ti.x, ti.y);
        assert_eq!(tid, 42);
        assert_eq!(tx, 100);
        assert_eq!(ty, 200);
        assert!(ti.flags & TOUCHEVENTF_DOWN != 0);
    }

    #[test]
    fn get_touch_input_info_invalid_handle_returns_error() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let result = user32.get_touch_input_info(999);
        assert!(result.is_err());
    }

    #[test]
    fn close_touch_input_handle_removes_entry() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let inputs = vec![TouchInput {
            x: 0,
            y: 0,
            source: 1,
            id: 1,
            flags: TOUCHEVENTF_DOWN,
            mask: 0,
            time: 0,
            extra_info: 0,
            cx: 10,
            cy: 10,
        }];
        let handle = user32.store_touch_inputs(0x1234, inputs);
        assert!(user32.get_touch_input_info(handle).is_ok());
        user32
            .close_touch_input_handle(handle)
            .expect("close touch input handle");
        assert!(user32.get_touch_input_info(handle).is_err());
    }

    #[test]
    fn touch_input_struct_size() {
        // With #[repr(C, packed)], TouchInput has no padding.
        // Fields: x(4) + y(4) + source(4) + id(4) + flags(4) + mask(4) + time(4) + extra_info(8) + cx(4) + cy(4) = 44
        assert_eq!(std::mem::size_of::<TouchInput>(), 44);
    }

    #[test]
    fn pointer_info_struct_layout() {
        let info = PointerInfo {
            pointer_type: 1,
            pointer_id: 5,
            frame_id: 0,
            pointer_flags: POINTER_FLAG_INRANGE | POINTER_FLAG_CONFIDENCE,
            source_device: 0,
            hwnd_target: 0x1234isize,
            pt_pixel_x: 100,
            pt_pixel_y: 200,
            pt_hic_res_x: 0,
            pt_hic_res_y: 0,
            pt_pixel_z: 0,
            display_time: 0,
            key_state: 0,
            performance_count: 0,
        };
        assert_eq!(info.pointer_type, 1);
        assert_eq!(info.pointer_id, 5);
        assert_eq!(info.pt_pixel_x, 100);
        assert_eq!(info.pt_pixel_y, 200);
    }

    #[test]
    fn store_and_retrieve_pointer_info() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let info = PointerInfo {
            pointer_type: 2,
            pointer_id: 7,
            frame_id: 1,
            pointer_flags: POINTER_FLAG_INRANGE | POINTER_FLAG_INCONTACT | POINTER_FLAG_PRIMARY,
            source_device: 0,
            hwnd_target: 0x5678isize,
            pt_pixel_x: 300,
            pt_pixel_y: 400,
            pt_hic_res_x: 0,
            pt_hic_res_y: 0,
            pt_pixel_z: 0,
            display_time: 0,
            key_state: 0,
            performance_count: 0,
        };
        user32.store_pointer_info(7, info);
        let retrieved = user32.get_pointer_info(7).expect("get pointer info");
        assert_eq!(retrieved.pointer_type, 2);
        assert_eq!(retrieved.pointer_id, 7);
        assert_eq!(retrieved.pt_pixel_x, 300);
        assert_eq!(retrieved.pt_pixel_y, 400);
    }

    #[test]
    fn initialize_pointer_device_tracks_hwnd() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32
            .initialize_pointer_device(0xABCD)
            .expect("initialize pointer device");
        assert!(user32.touch_state().pointer_devices.contains(&0xABCD));
    }

    #[test]
    fn pointer_pen_info_storage() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let pen_info = PointerPenInfo {
            pointer_type: 2,
            pointer_id: 10,
            frame_id: 0,
            pointer_flags: POINTER_FLAG_INRANGE | POINTER_FLAG_INCONTACT | POINTER_FLAG_CONFIDENCE,
            source_device: 0,
            hwnd_target: 0x9876isize,
            pt_pixel_x: 500,
            pt_pixel_y: 600,
            pt_hic_res_x: 0,
            pt_hic_res_y: 0,
            pt_pixel_z: 0,
            display_time: 0,
            key_state: 0,
            performance_count: 0,
            pen_flags: PEN_FLAG_BARREL,
            pen_mask: 0,
            pressure: 512,
            rotation: 0,
            tilt_x: 10,
            tilt_y: -5,
        };
        user32.store_pointer_pen_info(10, pen_info);
        let retrieved = user32
            .get_pointer_pen_info(10)
            .expect("get pointer pen info");
        assert_eq!(retrieved.pointer_id, 10);
        assert_eq!(retrieved.pressure, 512);
        assert_eq!(retrieved.pen_flags, PEN_FLAG_BARREL);
        assert_eq!(retrieved.tilt_x, 10);
        assert_eq!(retrieved.tilt_y, -5);
    }

    // ── Key State API tests ──────────────────────────────────────────────

    /// Helper: set up a subsystem with a registered keyboard device and a window.
    fn setup_keyboard_test() -> (User32Subsystem, Hwnd, String) {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, false, false, None, 1)
            .expect("create window");
        let _ = std::iter::from_fn(|| user32.get_message_w()).collect::<Vec<_>>();
        let device_id = user32.register_keyboard_device(&KeyboardDevice {
            vendor_id: 0x1234,
            product_id: 0x5678,
            serial: "test-serial".to_string(),
        });
        (user32, hwnd, device_id)
    }

    #[test]
    fn test_get_key_state() {
        let (mut user32, hwnd, device_id) = setup_keyboard_test();

        // Initially all keys are up → bit 15 clear
        assert_eq!(user32.get_key_state(VK_SPACE), 0, "space should be up initially");
        assert_eq!(user32.get_key_state(VK_A), 0, "A should be up initially");

        // Inject a key-down for scancode 0x39 (Space, VK=0x20)
        user32
            .inject_keyboard_input(
                hwnd,
                &device_id,
                0x39, // Space scancode
                KeyModifiers {
                    shift: false,
                    altgr: false,
                },
            )
            .expect("inject space down");

        // Space should now show bit 15 set
        let state = user32.get_key_state(VK_SPACE);
        assert_ne!(state & (0x8000u16 as i16), 0, "space should be down (bit 15 set)");
        // Toggle bit should still be 0 for non-toggle keys
        assert_eq!(state & 0x0001, 0, "space should not have toggle bit");

        // Inject key-up for space
        user32
            .inject_keyboard_input_up(
                hwnd,
                &device_id,
                0x39,
                KeyModifiers {
                    shift: false,
                    altgr: false,
                },
            )
            .expect("inject space up");

        // Space should now be up
        assert_eq!(user32.get_key_state(VK_SPACE) & (0x8000u16 as i16), 0, "space should be up after release");
    }

    #[test]
    fn test_map_virtual_key() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);

        // VK_A (0x41) → scancode 0x1E (US layout)
        let sc = user32.map_virtual_key_w(VK_A as u32, MAPVK_VK_TO_VSC);
        assert_eq!(sc, 0x1E, "VK_A should map to scancode 0x1E on US layout");

        // Scancode 0x1E → VK_A (0x41)
        let vk = user32.map_virtual_key_w(0x1E, MAPVK_VSC_TO_VK);
        assert_eq!(vk, VK_A as u32, "scancode 0x1E should map to VK_A");

        // VK_RETURN (0x0D) → scancode 0x1C
        let sc = user32.map_virtual_key_w(VK_RETURN as u32, MAPVK_VK_TO_VSC);
        assert_eq!(sc, 0x1C, "VK_RETURN should map to scancode 0x1C");

        // VK_SPACE (0x20) → scancode 0x39
        let sc = user32.map_virtual_key_w(VK_SPACE as u32, MAPVK_VK_TO_VSC);
        assert_eq!(sc, 0x39, "VK_SPACE should map to scancode 0x39");

        // Unknown VK → 0
        let sc = user32.map_virtual_key_w(0xFF, MAPVK_VK_TO_VSC);
        assert_eq!(sc, 0, "unknown VK should return 0");
    }

    #[test]
    fn test_keyboard_state() {
        let (mut user32, hwnd, device_id) = setup_keyboard_test();

        // GetKeyboardState should return 256 bytes
        let mut state = vec![0u8; 256];
        assert!(user32.get_keyboard_state(&mut state), "get_keyboard_state should succeed");
        assert_eq!(state.len(), 256, "state buffer should be 256 bytes");

        // Initially all bytes should be 0
        for (vk, &val) in state.iter().enumerate() {
            assert_eq!(val, 0, "initial state byte {vk} should be 0");
        }

        // Inject a key-down
        user32
            .inject_keyboard_input(
                hwnd,
                &device_id,
                0x39, // Space scancode
                KeyModifiers {
                    shift: false,
                    altgr: false,
                },
            )
            .expect("inject space down");

        // Now query state again — space (VK=0x20) should have bit 7 set
        let mut state2 = vec![0u8; 256];
        assert!(user32.get_keyboard_state(&mut state2));
        assert_ne!(state2[VK_SPACE as usize] & 0x80, 0, "VK_SPACE should have bit 7 set");
        assert_eq!(state2[VK_A as usize] & 0x80, 0, "VK_A should still be clear");

        // Releasing the key should clear bit 7
        user32
            .inject_keyboard_input_up(
                hwnd,
                &device_id,
                0x39,
                KeyModifiers {
                    shift: false,
                    altgr: false,
                },
            )
            .expect("inject space up");

        let mut state3 = vec![0u8; 256];
        assert!(user32.get_keyboard_state(&mut state3));
        assert_eq!(state3[VK_SPACE as usize] & 0x80, 0, "VK_SPACE bit 7 should be clear after release");

        // Buffer too small → return false
        let mut small = [0u8; 10];
        assert!(!user32.get_keyboard_state(&mut small), "buffer < 256 should return false");
    }

    #[test]
    fn test_vk_key_scan() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);

        // 'q' (0x71) → scancode 0x10, no shift
        let result = user32.vk_key_scan_w('q' as u16);
        assert_eq!(result & 0x00FF, 0x10, "'q' should map to scancode 0x10");
        assert_eq!(result >> 8, 0, "'q' should not require shift");

        // 'Q' → scancode 0x10, shift bit set
        let result = user32.vk_key_scan_w('Q' as u16);
        assert_eq!(result & 0x00FF, 0x10, "'Q' should map to scancode 0x10");
        assert_ne!(result >> 8 & 0x01, 0, "'Q' should require shift");

        // Unknown character → -1
        let result = user32.vk_key_scan_w('©' as u16);
        assert_eq!(result, -1, "unknown char should return -1");
    }

    #[test]
    fn test_get_async_key_state() {
        let (mut user32, hwnd, device_id) = setup_keyboard_test();

        // Initially async state should show nothing toggled
        let initial = user32.get_async_key_state(VK_SPACE);
        assert_eq!(initial & 0x0001, 0, "no async toggle initially");
        assert_eq!(initial & (0x8000u16 as i16), 0, "key not down initially");

        // Inject a key-down
        user32
            .inject_keyboard_input(
                hwnd,
                &device_id,
                0x39,
                KeyModifiers {
                    shift: false,
                    altgr: false,
                },
            )
            .expect("inject space down");

        // GetAsyncKeyState should see bit 0 set (toggled since last call)
        let after_down = user32.get_async_key_state(VK_SPACE);
        assert_ne!(after_down & 0x0001, 0, "async toggle bit should be set after key down");

        // Second call should have bit 0 cleared (auto-reset)
        let after_read = user32.get_async_key_state(VK_SPACE);
        assert_eq!(after_read & 0x0001, 0, "async toggle bit should auto-reset");
    }

    #[test]
    fn test_hooks() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);

        // Install a keyboard hook
        let hook_id = user32.set_windows_hook_ex_w(
            WH_KEYBOARD,
            0x1234_5678, // dummy callback address
            0,            // module
            0,            // thread_id (0 = global)
        );
        assert_ne!(hook_id, 0, "hook ID should be non-zero");

        // CallNextHookEx should return 0 (no next hook in chain)
        let result = user32.call_next_hook_ex(hook_id, 0, 0, 0);
        assert_eq!(result, 0, "call_next_hook_ex should return 0");

        // Unhook
        assert!(user32.unhook_windows_hook_ex(hook_id), "unhook should succeed");
        assert!(!user32.unhook_windows_hook_ex(hook_id), "unhook again should fail");
    }
}

fn compose_dead_char(dead: char, base: char) -> Option<char> {
    match (dead, base) {
        ('´', 'e') => Some('é'),
        ('´', 'E') => Some('É'),
        ('`', 'e') => Some('è'),
        ('`', 'E') => Some('È'),
        ('^', 'e') => Some('ê'),
        ('^', 'E') => Some('Ê'),
        _ => None,
    }
}

/// Returns true if the given VK code is a toggle key (CapsLock, NumLock, ScrollLock).
fn is_toggle_key(vk: u8) -> bool {
    matches!(
        vk as i32,
        VK_CAPITAL | VK_NUMLOCK | VK_SCROLL
    )
}

/// Map a `VirtualKey` enum variant to its Windows virtual-key code.
fn virtual_key_to_win32_vk(vk: &VirtualKey) -> u32 {
    match vk {
        VirtualKey::A => VK_A as u32,
        VirtualKey::E => VK_E as u32,
        VirtualKey::O => VK_O as u32,
        VirtualKey::Q => VK_Q as u32,
        VirtualKey::Y => VK_Y as u32,
        VirtualKey::Z => VK_Z as u32,
        VirtualKey::Oem3 => VK_OEM_3 as u32,
        VirtualKey::Oem4 => VK_OEM_4 as u32,
        VirtualKey::Oem7 => VK_OEM_7 as u32,
        VirtualKey::Space => VK_SPACE as u32,
        VirtualKey::XButton1 => VK_XBUTTON1 as u32,
        VirtualKey::XButton2 => VK_XBUTTON2 as u32,
        VirtualKey::Unknown(code) => *code as u32,
    }
}

fn layout_tables() -> BTreeMap<KeyboardLayoutId, BTreeMap<u16, LayoutEntry>> {
    BTreeMap::from([
        (
            KeyboardLayoutId::Us,
            BTreeMap::from([
                (0x10, LayoutEntry { vk: VirtualKey::Q, plain: Some('q'), shifted: Some('Q'), altgr: None, dead: None }),
                (0x11, LayoutEntry { vk: VirtualKey::Unknown(0x57), plain: Some('w'), shifted: Some('W'), altgr: None, dead: None }),
                (0x12, LayoutEntry { vk: VirtualKey::E, plain: Some('e'), shifted: Some('E'), altgr: None, dead: None }),
                (0x13, LayoutEntry { vk: VirtualKey::Unknown(0x52), plain: Some('r'), shifted: Some('R'), altgr: None, dead: None }),
                (0x19, LayoutEntry { vk: VirtualKey::Unknown(0x50), plain: Some('p'), shifted: Some('P'), altgr: None, dead: None }),
                (0x1c, LayoutEntry { vk: VirtualKey::Unknown(0x0d), plain: Some('\r'), shifted: Some('\r'), altgr: Some('\r'), dead: None }),
                (0x1e, LayoutEntry { vk: VirtualKey::A, plain: Some('a'), shifted: Some('A'), altgr: None, dead: None }),
                (0x1f, LayoutEntry { vk: VirtualKey::Unknown(0x53), plain: Some('s'), shifted: Some('S'), altgr: None, dead: None }),
                (0x20, LayoutEntry { vk: VirtualKey::Unknown(0x44), plain: Some('d'), shifted: Some('D'), altgr: None, dead: None }),
                (0x2e, LayoutEntry { vk: VirtualKey::Unknown(0x43), plain: Some('c'), shifted: Some('C'), altgr: None, dead: None }),
                (0x31, LayoutEntry { vk: VirtualKey::Unknown(0x4e), plain: Some('n'), shifted: Some('N'), altgr: None, dead: None }),
                (0x39, LayoutEntry { vk: VirtualKey::Space, plain: Some(' '), shifted: Some(' '), altgr: None, dead: None }),
            ]),
        ),
        (
            KeyboardLayoutId::Uk,
            BTreeMap::from([
                (0x10, LayoutEntry { vk: VirtualKey::Q, plain: Some('q'), shifted: Some('Q'), altgr: None, dead: None }),
                (0x28, LayoutEntry { vk: VirtualKey::Oem7, plain: Some('\''), shifted: Some('@'), altgr: None, dead: None }),
                (0x12, LayoutEntry { vk: VirtualKey::E, plain: Some('e'), shifted: Some('E'), altgr: None, dead: None }),
            ]),
        ),
        (
            KeyboardLayoutId::Fr,
            BTreeMap::from([
                (0x10, LayoutEntry { vk: VirtualKey::A, plain: Some('a'), shifted: Some('A'), altgr: None, dead: None }),
                (0x1e, LayoutEntry { vk: VirtualKey::Q, plain: Some('q'), shifted: Some('Q'), altgr: None, dead: None }),
                (0x1a, LayoutEntry { vk: VirtualKey::Oem4, plain: None, shifted: None, altgr: None, dead: Some('^') }),
                (0x12, LayoutEntry { vk: VirtualKey::E, plain: Some('e'), shifted: Some('E'), altgr: Some('€'), dead: None }),
            ]),
        ),
        (
            KeyboardLayoutId::De,
            BTreeMap::from([
                (0x15, LayoutEntry { vk: VirtualKey::Z, plain: Some('z'), shifted: Some('Z'), altgr: None, dead: None }),
                (0x2c, LayoutEntry { vk: VirtualKey::Y, plain: Some('y'), shifted: Some('Y'), altgr: None, dead: None }),
                (0x12, LayoutEntry { vk: VirtualKey::E, plain: Some('e'), shifted: Some('E'), altgr: None, dead: None }),
            ]),
        ),
        (
            KeyboardLayoutId::Es,
            BTreeMap::from([
                (0x10, LayoutEntry { vk: VirtualKey::Q, plain: Some('q'), shifted: Some('Q'), altgr: None, dead: None }),
                (0x1a, LayoutEntry { vk: VirtualKey::Oem4, plain: None, shifted: None, altgr: None, dead: Some('´') }),
                (0x12, LayoutEntry { vk: VirtualKey::E, plain: Some('e'), shifted: Some('E'), altgr: Some('€'), dead: None }),
            ]),
        ),
        (
            KeyboardLayoutId::It,
            BTreeMap::from([
                (0x10, LayoutEntry { vk: VirtualKey::Q, plain: Some('q'), shifted: Some('Q'), altgr: None, dead: None }),
                (0x1a, LayoutEntry { vk: VirtualKey::Oem4, plain: None, shifted: None, altgr: None, dead: Some('`') }),
                (0x12, LayoutEntry { vk: VirtualKey::E, plain: Some('e'), shifted: Some('E'), altgr: None, dead: None }),
            ]),
        ),
        (
            KeyboardLayoutId::Arabic,
            BTreeMap::from([
                (0x10, LayoutEntry { vk: VirtualKey::Q, plain: Some('ض'), shifted: Some('َ'), altgr: None, dead: None }),
                (0x12, LayoutEntry { vk: VirtualKey::E, plain: Some('ث'), shifted: Some('ُ'), altgr: None, dead: None }),
                (0x39, LayoutEntry { vk: VirtualKey::Space, plain: Some(' '), shifted: Some(' '), altgr: None, dead: None }),
            ]),
        ),
        (
            KeyboardLayoutId::Turkish,
            BTreeMap::from([
                (0x10, LayoutEntry { vk: VirtualKey::Q, plain: Some('q'), shifted: Some('Q'), altgr: None, dead: None }),
                (0x1a, LayoutEntry { vk: VirtualKey::Oem4, plain: None, shifted: None, altgr: None, dead: Some('^') }),
                (0x12, LayoutEntry { vk: VirtualKey::E, plain: Some('e'), shifted: Some('E'), altgr: Some('€'), dead: None }),
            ]),
        ),
    ])
}

// ── GDI+ Status Codes ────────────────────────────────────────────────────
/// Status codes returned by GDI+ functions (GdiplusStatus enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GdiplusStatus {
    Ok = 0,
    GenericError = 1,
    InvalidParameter = 2,
    OutOfMemory = 3,
    ObjectBusy = 4,
    InsufficientBuffer = 5,
    NotImplemented = 6,
    Win32Error = 7,
    WrongState = 8,
    Aborted = 9,
    FileNotFound = 10,
    ValueOverflow = 11,
    AccessDenied = 12,
    UnknownImageFormat = 13,
    FontFamilyNotFound = 14,
    FontStyleNotFound = 15,
    NotTrueTypeFont = 16,
    UnsupportedGdiplusVersion = 17,
    PropertyNotFound = 19,
    PropertyNotSupported = 20,
    ProfileNotFound = 21,
}

impl GdiplusStatus {
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

// ── GDI+ Unit constants ──────────────────────────────────────────────────
pub const GDIPLUS_UNIT_WORLD: u32 = 0;
pub const GDIPLUS_UNIT_DISPLAY: u32 = 1;
pub const GDIPLUS_UNIT_PIXEL: u32 = 2;
pub const GDIPLUS_UNIT_POINT: u32 = 3;
pub const GDIPLUS_UNIT_INCH: u32 = 4;
pub const GDIPLUS_UNIT_DOCUMENT: u32 = 5;
pub const GDIPLUS_UNIT_MILLIMETER: u32 = 6;

// ── GDI+ SmoothingMode ───────────────────────────────────────────────────
pub const GDIPLUS_SMOOTHING_MODE_DEFAULT: u32 = 0;
pub const GDIPLUS_SMOOTHING_MODE_HIGH_SPEED: u32 = 1;
pub const GDIPLUS_SMOOTHING_MODE_HIGH_QUALITY: u32 = 2;
pub const GDIPLUS_SMOOTHING_MODE_NONE: u32 = 3;
pub const GDIPLUS_SMOOTHING_MODE_ANTI_ALIAS: u32 = 4;

// ── GDI+ CompositingMode ─────────────────────────────────────────────────
pub const GDIPLUS_COMPOSITING_MODE_SOURCE_OVER: u32 = 0;
pub const GDIPLUS_COMPOSITING_MODE_SOURCE_COPY: u32 = 1;

// ── GDI+ CompositingQuality ──────────────────────────────────────────────
pub const GDIPLUS_COMPOSITING_QUALITY_DEFAULT: u32 = 0;
pub const GDIPLUS_COMPOSITING_QUALITY_HIGH_SPEED: u32 = 1;
pub const GDIPLUS_COMPOSITING_QUALITY_HIGH_QUALITY: u32 = 2;
pub const GDIPLUS_COMPOSITING_QUALITY_GAMMA_CORRECTED: u32 = 3;
pub const GDIPLUS_COMPOSITING_QUALITY_ASSUME_LINEAR: u32 = 4;

// ── GDI+ InterpolationMode ───────────────────────────────────────────────
pub const GDIPLUS_INTERPOLATION_DEFAULT: u32 = 0;
pub const GDIPLUS_INTERPOLATION_LOW_QUALITY: u32 = 1;
pub const GDIPLUS_INTERPOLATION_HIGH_QUALITY: u32 = 2;
pub const GDIPLUS_INTERPOLATION_BILINEAR: u32 = 3;
pub const GDIPLUS_INTERPOLATION_BICUBIC: u32 = 4;
pub const GDIPLUS_INTERPOLATION_NEAREST_NEIGHBOR: u32 = 5;
pub const GDIPLUS_INTERPOLATION_HIGH_QUALITY_BILINEAR: u32 = 6;
pub const GDIPLUS_INTERPOLATION_HIGH_QUALITY_BICUBIC: u32 = 7;

// ── GDI+ PixelOffsetMode ─────────────────────────────────────────────────
pub const GDIPLUS_PIXEL_OFFSET_DEFAULT: u32 = 0;
pub const GDIPLUS_PIXEL_OFFSET_HIGH_SPEED: u32 = 1;
pub const GDIPLUS_PIXEL_OFFSET_HIGH_QUALITY: u32 = 2;
pub const GDIPLUS_PIXEL_OFFSET_NONE: u32 = 3;
pub const GDIPLUS_PIXEL_OFFSET_HALF: u32 = 4;

// ── GDI+ DashStyle ───────────────────────────────────────────────────────
pub const GDIPLUS_DASH_STYLE_SOLID: u32 = 0;
pub const GDIPLUS_DASH_STYLE_DASH: u32 = 1;
pub const GDIPLUS_DASH_STYLE_DOT: u32 = 2;
pub const GDIPLUS_DASH_STYLE_DASH_DOT: u32 = 3;
pub const GDIPLUS_DASH_STYLE_DASH_DOT_DOT: u32 = 4;
pub const GDIPLUS_DASH_STYLE_CUSTOM: u32 = 5;

// ── GDI+ LineJoin ────────────────────────────────────────────────────────
pub const GDIPLUS_LINE_JOIN_MITER: u32 = 0;
pub const GDIPLUS_LINE_JOIN_BEVEL: u32 = 1;
pub const GDIPLUS_LINE_JOIN_ROUND: u32 = 2;
pub const GDIPLUS_LINE_JOIN_MITER_CLIPPED: u32 = 3;

// ── GDI+ LineCap ─────────────────────────────────────────────────────────
pub const GDIPLUS_LINE_CAP_FLAT: u32 = 0;
pub const GDIPLUS_LINE_CAP_SQUARE: u32 = 1;
pub const GDIPLUS_LINE_CAP_ROUND: u32 = 2;
pub const GDIPLUS_LINE_CAP_TRIANGLE: u32 = 3;
pub const GDIPLUS_LINE_CAP_NO_ANCHOR: u32 = 16;
pub const GDIPLUS_LINE_CAP_SQUARE_ANCHOR: u32 = 17;
pub const GDIPLUS_LINE_CAP_ROUND_ANCHOR: u32 = 18;
pub const GDIPLUS_LINE_CAP_DIAMOND_ANCHOR: u32 = 19;
pub const GDIPLUS_LINE_CAP_ARROW_ANCHOR: u32 = 20;

// ── GDI+ FillMode ────────────────────────────────────────────────────────
pub const GDIPLUS_FILL_MODE_ALTERNATE: u32 = 0;
pub const GDIPLUS_FILL_MODE_WINDING: u32 = 1;

// ── GDI+ PixelFormat flags ───────────────────────────────────────────────
pub const GDIPLUS_PIXEL_FORMAT_INDEXED: u32 = 0x00010000;
pub const GDIPLUS_PIXEL_FORMAT_GDI: u32 = 0x00020000;
pub const GDIPLUS_PIXEL_FORMAT_ALPHA: u32 = 0x00040000;
pub const GDIPLUS_PIXEL_FORMAT_PREMULTIPLIED: u32 = 0x00080000;
pub const GDIPLUS_PIXEL_FORMAT_16BPP_RGB555: u32 = 0x00021005;
pub const GDIPLUS_PIXEL_FORMAT_16BPP_RGB565: u32 = 0x00021006;
pub const GDIPLUS_PIXEL_FORMAT_24BPP_RGB: u32 = 0x00021808;
pub const GDIPLUS_PIXEL_FORMAT_32BPP_ARGB: u32 = 0x00262009;
pub const GDIPLUS_PIXEL_FORMAT_32BPP_PARGB: u32 = 0x0026200b;
pub const GDIPLUS_PIXEL_FORMAT_48BPP_RGB: u32 = 0x00033010;
pub const GDIPLUS_PIXEL_FORMAT_64BPP_ARGB: u32 = 0x0034401a;
pub const GDIPLUS_PIXEL_FORMAT_64BPP_PARGB: u32 = 0x0034401c;

// ── GDI+ TextRenderingHint ───────────────────────────────────────────────
pub const GDIPLUS_TEXT_RENDERING_HINT_SYSTEM_DEFAULT: u32 = 0;
pub const GDIPLUS_TEXT_RENDERING_HINT_SINGLE_BIT_PER_PIXEL_GRID_FIT: u32 = 1;
pub const GDIPLUS_TEXT_RENDERING_HINT_SINGLE_BIT_PER_PIXEL: u32 = 2;
pub const GDIPLUS_TEXT_RENDERING_HINT_ANTI_ALIAS_GRID_FIT: u32 = 3;
pub const GDIPLUS_TEXT_RENDERING_HINT_ANTI_ALIAS: u32 = 4;
pub const GDIPLUS_TEXT_RENDERING_HINT_CLEAR_TYPE_GRID_FIT: u32 = 5;

// ── GDI+ ColorMatrix type ────────────────────────────────────────────────
#[derive(Debug, Clone)]
#[repr(C)]
pub struct GdiplusColorMatrix {
    pub m: [[f32; 5]; 5],
}

// ── GDI+ BitmapData (for LockBits) ───────────────────────────────────────
#[derive(Debug, Clone)]
#[repr(C)]
pub struct GdiplusBitmapData {
    pub width: u32,
    pub height: u32,
    pub stride: i32,
    pub pixel_format: u32,
    pub scan0: u64,
    pub reserved: u64,
}

// ── GDI+ RectF ───────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GdiplusRectF {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

// ── GDI+ PointF ──────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GdiplusPointF {
    pub x: f32,
    pub y: f32,
}

// ── GDI+ CharacterRange ──────────────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GdiplusCharacterRange {
    pub first: u32,
    pub length: u32,
}

// ── GDI+ StringFormat flags ──────────────────────────────────────────────
pub const GDIPLUS_STRING_FORMAT_FLAG_DIRECTION_RIGHT_TO_LEFT: u32 = 0x00000001;
pub const GDIPLUS_STRING_FORMAT_FLAG_DIRECTION_VERTICAL: u32 = 0x00000002;
pub const GDIPLUS_STRING_FORMAT_FLAG_NO_FIT_BLACK_BOX: u32 = 0x00000004;
pub const GDIPLUS_STRING_FORMAT_FLAG_DISPLAY_FORMAT_CONTROL: u32 = 0x00000020;
pub const GDIPLUS_STRING_FORMAT_FLAG_MEASURE_TRAILING_SPACES: u32 = 0x00000800;
pub const GDIPLUS_STRING_FORMAT_FLAG_NO_WRAP: u32 = 0x00001000;
pub const GDIPLUS_STRING_FORMAT_FLAG_LINE_LIMIT: u32 = 0x00002000;
pub const GDIPLUS_STRING_FORMAT_FLAG_NO_CLIP: u32 = 0x00004000;
pub const GDIPLUS_STRING_FORMAT_FLAG_BYPASS_GRAPHICS: u32 = 0x00008000;

// ── GDI+ ImageAttributes ColorAdjustType ─────────────────────────────────
pub const GDIPLUS_COLOR_ADJUST_TYPE_DEFAULT: u32 = 0;
pub const GDIPLUS_COLOR_ADJUST_TYPE_BITMAP: u32 = 1;
pub const GDIPLUS_COLOR_ADJUST_TYPE_BRUSH: u32 = 2;
pub const GDIPLUS_COLOR_ADJUST_TYPE_PEN: u32 = 3;
pub const GDIPLUS_COLOR_ADJUST_TYPE_TEXT: u32 = 4;

// ── GDI+ WrapMode ────────────────────────────────────────────────────────
pub const GDIPLUS_WRAP_MODE_TILE: u32 = 0;
pub const GDIPLUS_WRAP_MODE_TILE_FLIP_X: u32 = 1;
pub const GDIPLUS_WRAP_MODE_TILE_FLIP_Y: u32 = 2;
pub const GDIPLUS_WRAP_MODE_TILE_FLIP_XY: u32 = 3;
pub const GDIPLUS_WRAP_MODE_CLAMP: u32 = 4;

// ── GDI+ FontStyle flags ─────────────────────────────────────────────────
pub const GDIPLUS_FONT_STYLE_REGULAR: u32 = 0;
pub const GDIPLUS_FONT_STYLE_BOLD: u32 = 1;
pub const GDIPLUS_FONT_STYLE_ITALIC: u32 = 2;
pub const GDIPLUS_FONT_STYLE_BOLD_ITALIC: u32 = 3;
pub const GDIPLUS_FONT_STYLE_UNDERLINE: u32 = 4;
pub const GDIPLUS_FONT_STYLE_STRIKEOUT: u32 = 8;

// ── GDI+ ImageLockMode flags ─────────────────────────────────────────────
pub const GDIPLUS_IMAGE_LOCK_MODE_READ: u32 = 0x0001;
pub const GDIPLUS_IMAGE_LOCK_MODE_WRITE: u32 = 0x0002;
pub const GDIPLUS_IMAGE_LOCK_MODE_USER_INPUT_BUF: u32 = 0x0004;

// ── GDI+ state objects ───────────────────────────────────────────────────

/// A GDI+ graphics context wrapping an HDC.
#[derive(Debug, Clone)]
pub struct GdiplusGraphics {
    pub hdc: u64,
    pub smoothing_mode: u32,
    pub compositing_mode: u32,
    pub compositing_quality: u32,
    pub interpolation_mode: u32,
    pub pixel_offset_mode: u32,
    pub text_rendering_hint: u32,
    pub clip_rect: Option<(f32, f32, f32, f32)>,
    pub world_transform: Option<u64>,
    pub container_stack: Vec<GdiplusContainer>,
    pub next_container: u32,
    /// If set, drawing operations render into this bitmap's pixel buffer.
    pub target_bitmap: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct GdiplusContainer {
    pub id: u32,
    pub saved_state: Box<GdiplusGraphicsState>,
}

#[derive(Debug, Clone)]
pub struct GdiplusGraphicsState {
    pub smoothing_mode: u32,
    pub compositing_mode: u32,
    pub compositing_quality: u32,
    pub interpolation_mode: u32,
    pub pixel_offset_mode: u32,
    pub text_rendering_hint: u32,
    pub clip_rect: Option<(f32, f32, f32, f32)>,
    pub world_transform: Option<u64>,
}

/// A GDI+ solid brush.
#[derive(Debug, Clone)]
pub struct GdiplusSolidFill {
    pub color: u32,
}

/// A GDI+ linear gradient brush.
#[derive(Debug, Clone)]
pub struct GdiplusLineBrush {
    pub point1: (f32, f32),
    pub point2: (f32, f32),
    pub color1: u32,
    pub color2: u32,
    pub wrap_mode: u32,
}

/// A GDI+ texture brush.
#[derive(Debug, Clone)]
pub struct GdiplusTextureBrush {
    pub image_handle: u64,
    pub wrap_mode: u32,
}

/// A GDI+ brush (any kind).
#[derive(Debug, Clone)]
pub enum GdiplusBrush {
    SolidFill(GdiplusSolidFill),
    LineBrush(GdiplusLineBrush),
    Texture(GdiplusTextureBrush),
}

/// A GDI+ pen.
#[derive(Debug, Clone)]
pub struct GdiplusPen {
    pub width: f32,
    pub color: u32,
    pub brush_handle: Option<u64>,
    pub dash_style: u32,
    pub line_join: u32,
    pub start_cap: u32,
    pub end_cap: u32,
    pub alignment: u32,
}

/// A GDI+ path figure element.
#[derive(Debug, Clone)]
pub enum GdiplusPathElement {
    StartFigure,
    CloseFigure,
    Line { x1: f32, y1: f32, x2: f32, y2: f32 },
    Lines { points: Vec<GdiplusPointF> },
    Rectangle { x: f32, y: f32, w: f32, h: f32 },
    Ellipse { x: f32, y: f32, w: f32, h: f32 },
    Arc { x: f32, y: f32, w: f32, h: f32, start_angle: f32, sweep_angle: f32 },
    Bezier { points: [GdiplusPointF; 4] },
    Curve { points: Vec<GdiplusPointF>, tension: f32 },
    ClosedCurve { points: Vec<GdiplusPointF>, tension: f32 },
    Polygon { points: Vec<GdiplusPointF> },
    Pie { x: f32, y: f32, w: f32, h: f32, start_angle: f32, sweep_angle: f32 },
    String { text: String, font_handle: u64, layout_rect: GdiplusRectF, format_flags: u32 },
}

/// A GDI+ path.
#[derive(Debug, Clone)]
pub struct GdiplusPath {
    pub fill_mode: u32,
    pub elements: Vec<GdiplusPathElement>,
}

/// A GDI+ matrix (3x3 affine transform).
#[derive(Debug, Clone)]
pub struct GdiplusMatrix {
    pub elements: [f32; 6],
}

impl GdiplusMatrix {
    pub fn identity() -> Self {
        Self { elements: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0] }
    }
}

/// A GDI+ font.
#[derive(Debug, Clone)]
pub struct GdiplusFont {
    pub family_handle: u64,
    pub em_size: f32,
    pub style: u32,
    pub unit: u32,
}

/// A GDI+ font family.
#[derive(Debug, Clone)]
pub struct GdiplusFontFamily {
    pub name: String,
}

/// A GDI+ image (bitmap or metafile).
#[derive(Debug, Clone)]
pub enum GdiplusImage {
    Bitmap(GdiplusBitmap),
    Metafile,
}

/// A GDI+ bitmap.
#[derive(Debug, Clone)]
pub struct GdiplusBitmap {
    pub width: u32,
    pub height: u32,
    pub pixel_format: u32,
    pub stride: i32,
    pub pixels: Vec<u8>,
    pub locked: bool,
}

/// A GDI+ image attributes object.
#[derive(Debug, Clone)]
pub struct GdiplusImageAttributes {
    pub color_keys: BTreeMap<u32, (u32, u32)>,
    pub color_matrix: Option<(u32, GdiplusColorMatrix)>,
}

/// Handle types for GDI+ object tracking.
#[derive(Debug, Clone)]
pub enum GdiplusObject {
    Graphics(Box<GdiplusGraphics>),
    Brush(Box<GdiplusBrush>),
    Pen(Box<GdiplusPen>),
    Path(Box<GdiplusPath>),
    Matrix(Box<GdiplusMatrix>),
    Font(Box<GdiplusFont>),
    FontFamily(Box<GdiplusFontFamily>),
    Image(Box<GdiplusImage>),
    ImageAttributes(Box<GdiplusImageAttributes>),
}

/// GDI+ startup input structure.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GdiplusStartupInput {
    pub gdiplus_version: u32,
    pub debug_event_callback: u64,
    pub suppress_background_thread: bool,
    pub suppress_external_codecs: bool,
}

impl Default for GdiplusStartupInput {
    fn default() -> Self {
        Self {
            gdiplus_version: 1,
            debug_event_callback: 0,
            suppress_background_thread: false,
            suppress_external_codecs: false,
        }
    }
}

/// Complete GDI+ subsystem state.
#[derive(Debug, Clone)]
pub struct GdiplusState {
    pub initialized: bool,
    pub startup_input: GdiplusStartupInput,
    pub token: u64,
    pub next_handle: u64,
    pub objects: BTreeMap<u64, GdiplusObject>,
    pub graphics_from_hdc: BTreeMap<u64, u64>,
    pub hdc_to_graphics: BTreeMap<u64, u64>,
}

impl Default for GdiplusState {
    fn default() -> Self {
        Self {
            initialized: false,
            startup_input: GdiplusStartupInput::default(),
            token: 0,
            next_handle: 0xDD010000,
            objects: BTreeMap::new(),
            graphics_from_hdc: BTreeMap::new(),
            hdc_to_graphics: BTreeMap::new(),
        }
    }
}

impl GdiplusState {
    pub fn alloc_handle(&mut self, obj: GdiplusObject) -> u64 {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        self.objects.insert(handle, obj);
        handle
    }

    pub fn get(&self, handle: u64) -> Option<&GdiplusObject> {
        self.objects.get(&handle)
    }

    pub fn get_mut(&mut self, handle: u64) -> Option<&mut GdiplusObject> {
        self.objects.get_mut(&handle)
    }

    pub fn remove(&mut self, handle: u64) -> Option<GdiplusObject> {
        self.objects.remove(&handle)
    }

    pub fn create_graphics_from_hdc(&mut self, hdc: u64) -> u64 {
        if let Some(&g) = self.hdc_to_graphics.get(&hdc) {
            return g;
        }
        let g = GdiplusGraphics {
            hdc,
            smoothing_mode: GDIPLUS_SMOOTHING_MODE_DEFAULT,
            compositing_mode: GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
            compositing_quality: GDIPLUS_COMPOSITING_QUALITY_DEFAULT,
            interpolation_mode: GDIPLUS_INTERPOLATION_DEFAULT,
            pixel_offset_mode: GDIPLUS_PIXEL_OFFSET_DEFAULT,
            text_rendering_hint: GDIPLUS_TEXT_RENDERING_HINT_SYSTEM_DEFAULT,
            clip_rect: None,
            world_transform: None,
            container_stack: Vec::new(),
            next_container: 1,
            target_bitmap: None,
        };
        let handle = self.alloc_handle(GdiplusObject::Graphics(Box::new(g)));
        self.graphics_from_hdc.insert(handle, hdc);
        self.hdc_to_graphics.insert(hdc, handle);
        handle
    }
}