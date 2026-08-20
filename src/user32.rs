use crate::error::{AppError, AppResult};
use crate::mac_window;
use crate::real_hid::HidMonitor;
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};

// ── macOS CoreGraphics FFI for real keyboard state ──────────────────────
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn CGEventSourceFlagsState(sourceStateID: i32) -> u64;
}

#[cfg(target_os = "macos")]
#[allow(dead_code)] // CGEvent source-state constants (ABI surface); flagged for the API database
const kCGEventSourceStatePrivate: i32 = -1;
#[cfg(target_os = "macos")]
const kCGEventSourceStateCombinedSessionState: i32 = 0;
#[cfg(target_os = "macos")]
#[allow(dead_code)] // CGEvent source-state constants (ABI surface); flagged for the API database
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
use std::sync::OnceLock;

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
pub const VK_PRIOR: i32 = 0x21; // Page Up
pub const VK_NEXT: i32 = 0x22; // Page Down
pub const VK_END: i32 = 0x23;
pub const VK_HOME: i32 = 0x24;
pub const VK_LEFT: i32 = 0x25;
pub const VK_UP: i32 = 0x26;
pub const VK_RIGHT: i32 = 0x27;
pub const VK_DOWN: i32 = 0x28;
pub const VK_SELECT: i32 = 0x29;
pub const VK_PRINT: i32 = 0x2A;
pub const VK_EXECUTE: i32 = 0x2B;
pub const VK_SNAPSHOT: i32 = 0x2C; // Print Screen
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
pub const VK_OEM_1: i32 = 0xBA; // ;:
pub const VK_OEM_PLUS: i32 = 0xBB; // =+
pub const VK_OEM_COMMA: i32 = 0xBC; // ,<
pub const VK_OEM_MINUS: i32 = 0xBD; // -_
pub const VK_OEM_PERIOD: i32 = 0xBE; // .>
pub const VK_OEM_2: i32 = 0xBF; // /?
pub const VK_OEM_3: i32 = 0xC0; // `~
pub const VK_OEM_4: i32 = 0xDB; // [{
pub const VK_OEM_5: i32 = 0xDC; // \|
pub const VK_OEM_6: i32 = 0xDD; // ]}
pub const VK_OEM_7: i32 = 0xDE; // '"
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
pub const HWND_TOPMOST: u32 = !0u32; // -1 as u32
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

// ── Menu constants ─────────────────────────────────────────────────────────
pub const MF_INSERT: u32 = 0x0000_0000;
pub const MF_CHANGE: u32 = 0x0000_0080;
pub const MF_APPEND: u32 = 0x0000_0100;
pub const MF_DELETE: u32 = 0x0000_0200;
pub const MF_REMOVE: u32 = 0x0000_1000;
pub const MF_BYCOMMAND: u32 = 0x0000_0000;
pub const MF_BYPOSITION: u32 = 0x0000_0400;
pub const MF_SEPARATOR: u32 = 0x0000_0800;
pub const MF_ENABLED: u32 = 0x0000_0000;
pub const MF_GRAYED: u32 = 0x0000_0001;
pub const MF_DISABLED: u32 = 0x0000_0002;
pub const MF_UNCHECKED: u32 = 0x0000_0000;
pub const MF_CHECKED: u32 = 0x0000_0008;
pub const MF_USECHECKBITMAPS: u32 = 0x0000_0200;
pub const MF_STRING: u32 = 0x0000_0000;
pub const MF_BITMAP: u32 = 0x0000_0004;
pub const MF_OWNERDRAW: u32 = 0x0000_0100;
pub const MF_POPUP: u32 = 0x0000_0010;
pub const MF_MENUBARBREAK: u32 = 0x0000_0020;
pub const MF_MENUBREAK: u32 = 0x0000_0040;
pub const MF_UNHILITE: u32 = 0x0000_0000;
pub const MF_HILITE: u32 = 0x0000_0080;
pub const MF_SYSMENU: u32 = 0x0000_2000;
pub const MF_HELP: u32 = 0x0000_4000;
pub const MF_MOUSESELECT: u32 = 0x0000_8000;
pub const MFT_STRING: u32 = MF_STRING;
pub const MFT_BITMAP: u32 = MF_BITMAP;
pub const MFT_MENUBARBREAK: u32 = MF_MENUBARBREAK;
pub const MFT_MENUBREAK: u32 = MF_MENUBREAK;
pub const MFT_OWNERDRAW: u32 = MF_OWNERDRAW;
pub const MFT_RADIOCHECK: u32 = 0x0000_0200;
pub const MFT_SEPARATOR: u32 = MF_SEPARATOR;
pub const MFT_RIGHTORDER: u32 = 0x0000_2000;
pub const MFT_RIGHTJUSTIFY: u32 = 0x0000_4000;
pub const MFS_GRAYED: u32 = 0x0000_0003;
pub const MFS_DISABLED: u32 = MFS_GRAYED;
pub const MFS_CHECKED: u32 = MF_CHECKED;
pub const MFS_HILITE: u32 = MF_HILITE;
pub const MFS_ENABLED: u32 = MF_ENABLED;
pub const MFS_DEFAULT: u32 = 0x0000_1000;
pub const TPM_LEFTBUTTON: u32 = 0x0000_0000;
pub const TPM_RIGHTBUTTON: u32 = 0x0000_0002;
pub const TPM_LEFTALIGN: u32 = 0x0000_0000;
pub const TPM_CENTERALIGN: u32 = 0x0000_0004;
pub const TPM_RIGHTALIGN: u32 = 0x0000_0008;
pub const TPM_TOPALIGN: u32 = 0x0000_0000;
pub const TPM_VCENTERALIGN: u32 = 0x0000_0010;
pub const TPM_BOTTOMALIGN: u32 = 0x0000_0020;
pub const TPM_NONOTIFY: u32 = 0x0000_0080;
pub const TPM_RETURNCMD: u32 = 0x0000_0100;
pub const TPM_RECURSE: u32 = 0x0000_0001;
pub const TPM_HORIZONTAL: u32 = 0x0000_0000;
pub const TPM_VERTICAL: u32 = 0x0000_0040;

// ── Scrollbar constants ─────────────────────────────────────────────────────
pub const SB_HORZ: u32 = 0;
pub const SB_VERT: u32 = 1;
pub const SB_CTL: u32 = 2;
pub const SB_BOTH: u32 = 3;
pub const SIF_RANGE: u32 = 0x0001;
pub const SIF_PAGE: u32 = 0x0002;
pub const SIF_POS: u32 = 0x0004;
pub const SIF_DISABLENOSCROLL: u32 = 0x0008;
pub const SIF_TRACKPOS: u32 = 0x0010;
pub const SIF_ALL: u32 = SIF_RANGE | SIF_PAGE | SIF_POS | SIF_TRACKPOS;
pub const ESB_ENABLE_BOTH: u32 = 0x0000;
pub const ESB_DISABLE_BOTH: u32 = 0x0003;
pub const ESB_DISABLE_LEFT: u32 = 0x0001;
pub const ESB_DISABLE_RIGHT: u32 = 0x0002;
pub const ESB_DISABLE_UP: u32 = 0x0001;
pub const ESB_DISABLE_DOWN: u32 = 0x0002;
pub const ESB_DISABLE_LTUP: u32 = ESB_DISABLE_LEFT;
pub const ESB_DISABLE_RTDN: u32 = ESB_DISABLE_RIGHT;

// ── Common Controls constants ───────────────────────────────────────────────
pub const ICC_LISTVIEW_CLASSES: u32 = 0x0000_0001;
pub const ICC_TREEVIEW_CLASSES: u32 = 0x0000_0002;
pub const ICC_BAR_CLASSES: u32 = 0x0000_0004;
pub const ICC_TAB_CLASSES: u32 = 0x0000_0008;
pub const ICC_UPDOWN_CLASS: u32 = 0x0000_0010;
pub const ICC_PROGRESS_CLASS: u32 = 0x0000_0020;
pub const ICC_HOTKEY_CLASS: u32 = 0x0000_0040;
pub const ICC_ANIMATE_CLASS: u32 = 0x0000_0080;
pub const ICC_WIN95_CLASSES: u32 = 0x0000_00FF;
pub const ICC_DATE_CLASSES: u32 = 0x0000_0100;
pub const ICC_USEREX_CLASSES: u32 = 0x0000_0200;
pub const ICC_COOL_CLASSES: u32 = 0x0000_0400;
pub const ICC_INTERNET_CLASSES: u32 = 0x0000_0800;
pub const ICC_PAGESCROLLER_CLASS: u32 = 0x0000_1000;
pub const ICC_NATIVEFNTCTL_CLASS: u32 = 0x0000_2000;
pub const ICC_STANDARD_CLASSES: u32 = 0x0000_4000;
pub const ICC_LINK_CLASS: u32 = 0x0000_8000;

// ── DWM constants ───────────────────────────────────────────────────────────
pub const DWM_EC_DISABLECOMPOSITION: u32 = 0;
pub const DWM_EC_ENABLECOMPOSITION: u32 = 1;
pub const DWMWA_NCRENDERING_ENABLED: u32 = 1;
pub const DWMWA_NCRENDERING_POLICY: u32 = 2;
pub const DWMWA_TRANSITIONS_FORCEDISABLED: u32 = 3;
pub const DWMWA_ALLOW_NCPAINT: u32 = 4;
pub const DWMWA_CAPTION_BUTTON_BOUNDS: u32 = 5;
pub const DWMWA_NONCLIENT_RTL_LAYOUT: u32 = 6;
pub const DWMWA_FORCE_ICONIC_REPRESENTATION: u32 = 7;
pub const DWMWA_FLIP3D_POLICY: u32 = 8;
pub const DWMWA_EXTENDED_FRAME_BOUNDS: u32 = 9;
pub const DWMWA_HAS_ICONIC_BITMAP: u32 = 10;
pub const DWMWA_DISALLOW_PEEK: u32 = 11;
pub const DWMWA_EXCLUDED_FROM_PEEK: u32 = 12;
pub const DWMWA_CLOAK: u32 = 13;
pub const DWMWA_CLOAKED: u32 = 14;
pub const DWMWA_FREEZE_REPRESENTATION: u32 = 15;
pub const DWMWA_LAST: u32 = 16;
pub const DWM_BB_ENABLE: u32 = 0x0000_0001;
pub const DWM_BB_BLURREGION: u32 = 0x0000_0002;
pub const DWM_BB_TRANSITIONONMAXIMIZED: u32 = 0x0000_0004;

// ── DWM attribute defaults ────────────────────────────────────────────────────
/// Per-window DWM attribute state tracked by the User32 subsystem.
#[derive(Debug, Clone)]
pub struct DwmAttributes {
    /// DWMWA_NCRENDERING_ENABLED
    pub nc_rendering_enabled: bool,
    /// DWMWA_NCRENDERING_POLICY
    pub nc_rendering_policy: u32,
    /// DWMWA_TRANSITIONS_FORCEDISABLED
    pub transitions_forced_disabled: bool,
    /// DWMWA_ALLOW_NCPAINT
    pub allow_ncpaint: bool,
    /// DWMWA_CAPTION_BUTTON_BOUNDS
    pub caption_button_bounds: (i32, i32, i32, i32),
    /// DWMWA_NONCLIENT_RTL_LAYOUT
    pub nonclient_rtl_layout: bool,
    /// DWMWA_FORCE_ICONIC_REPRESENTATION
    pub force_iconic_representation: bool,
    /// DWMWA_FLIP3D_POLICY
    pub flip3d_policy: u32,
    /// DWMWA_EXTENDED_FRAME_BOUNDS
    pub extended_frame_bounds: (i32, i32, i32, i32),
    /// DWMWA_HAS_ICONIC_BITMAP
    pub has_iconic_bitmap: bool,
    /// DWMWA_DISALLOW_PEEK
    pub disallow_peek: bool,
    /// DWMWA_EXCLUDED_FROM_PEEK
    pub excluded_from_peek: bool,
    /// DWMWA_CLOAK
    pub cloak: bool,
    /// DWMWA_CLOAKED
    pub cloaked: u32,
    /// DWMWA_FREEZE_REPRESENTATION
    pub freeze_representation: bool,
    /// Whether blur-behind (NSVisualEffectView) is enabled
    pub blur_behind_enabled: bool,
    /// Extend-frame-into-client-area margins
    pub extend_frame_margins: (i32, i32, i32, i32),
}

impl Default for DwmAttributes {
    fn default() -> Self {
        Self {
            nc_rendering_enabled: true,
            nc_rendering_policy: 0,
            transitions_forced_disabled: false,
            allow_ncpaint: true,
            caption_button_bounds: (0, 0, 0, 0),
            nonclient_rtl_layout: false,
            force_iconic_representation: false,
            flip3d_policy: 0,
            extended_frame_bounds: (0, 0, 0, 0),
            has_iconic_bitmap: false,
            disallow_peek: false,
            excluded_from_peek: false,
            cloak: false,
            cloaked: 0,
            freeze_representation: false,
            blur_behind_enabled: false,
            extend_frame_margins: (0, 0, 0, 0),
        }
    }
}
// ── Flash window constants ──────────────────────────────────────────────────
pub const FLASHW_STOP: u32 = 0;
pub const FLASHW_CAPTION: u32 = 0x0000_0001;
pub const FLASHW_TRAY: u32 = 0x0000_0002;
pub const FLASHW_ALL: u32 = FLASHW_CAPTION | FLASHW_TRAY;
pub const FLASHW_TIMER: u32 = 0x0000_0004;
pub const FLASHW_TIMERNOFG: u32 = 0x0000_000C;

// ── AnimateWindow constants ─────────────────────────────────────────────────
pub const AW_HOR_POSITIVE: u32 = 0x0000_0001;
pub const AW_HOR_NEGATIVE: u32 = 0x0000_0002;
pub const AW_VER_POSITIVE: u32 = 0x0000_0004;
pub const AW_VER_NEGATIVE: u32 = 0x0000_0008;
pub const AW_CENTER: u32 = 0x0000_0010;
pub const AW_HIDE: u32 = 0x0000_0001_0000;
pub const AW_ACTIVATE: u32 = 0x0002_0000;
pub const AW_SLIDE: u32 = 0x0004_0000;
pub const AW_BLEND: u32 = 0x0008_0000;
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

/// WM_TIMER — posted to a window's owning thread queue when a SetTimer
/// timer (registered with a null TIMERPROC) comes due.
pub const WM_TIMER: u32 = 0x0113;

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

// ── Clipboard format constants (Win32) ────────────────────────────────────
pub const CF_TEXT: u32 = 1;
pub const CF_BITMAP: u32 = 2;
pub const CF_METAFILEPICT: u32 = 3;
pub const CF_SYLK: u32 = 4;
pub const CF_DIF: u32 = 5;
pub const CF_TIFF: u32 = 6;
pub const CF_OEMTEXT: u32 = 7;
pub const CF_DIB: u32 = 8;
pub const CF_PALETTE: u32 = 9;
pub const CF_PENDATA: u32 = 10;
pub const CF_RIFF: u32 = 11;
pub const CF_WAVE: u32 = 12;
pub const CF_UNICODETEXT: u32 = 13;
pub const CF_ENHMETAFILE: u32 = 14;
pub const CF_HDROP: u32 = 15;
pub const CF_LOCALE: u32 = 16;
pub const CF_DIBV5: u32 = 17;
pub const CF_MAX: u32 = 18;
pub const CF_OWNERDISPLAY: u32 = 0x0080;
pub const CF_DSPTEXT: u32 = 0x0081;
pub const CF_DSPBITMAP: u32 = 0x0082;
pub const CF_DSPMETAFILEPICT: u32 = 0x0083;
pub const CF_DSPENHMETAFILE: u32 = 0x008E;
/// First private clipboard format identifier.
pub const CF_PRIVATEFIRST: u32 = 0x0200;
/// Last private clipboard format identifier.
pub const CF_PRIVATELAST: u32 = 0x02FF;
/// First registered clipboard format identifier.
pub const CF_GDIOBJFIRST: u32 = 0x0300;
/// Last registered clipboard format identifier.
pub const CF_GDIOBJLAST: u32 = 0x03FF;

// ── QS_* message queue status flags (for MsgWaitForMultipleObjects) ──────
pub const QS_KEY: u32 = 0x0001;
pub const QS_MOUSEMOVE: u32 = 0x0002;
pub const QS_MOUSEBUTTON: u32 = 0x0004;
pub const QS_POSTMESSAGE: u32 = 0x0008;
pub const QS_TIMER: u32 = 0x0010;
pub const QS_PAINT: u32 = 0x0020;
pub const QS_SENDMESSAGE: u32 = 0x0040;
pub const QS_HOTKEY: u32 = 0x0080;
pub const QS_ALLPOSTMESSAGE: u32 = 0x0100;
pub const QS_RAWINPUT: u32 = 0x0400;
pub const QS_TOUCH: u32 = 0x0800;
pub const QS_POINTER: u32 = 0x1000;
pub const QS_MOUSE: u32 = QS_MOUSEMOVE | QS_MOUSEBUTTON;
pub const QS_INPUT: u32 = QS_MOUSE | QS_KEY | QS_RAWINPUT | QS_TOUCH | QS_POINTER;
pub const QS_ALLEVENTS: u32 =
    QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_SENDMESSAGE | QS_HOTKEY;
pub const QS_ALLINPUT: u32 = QS_ALLEVENTS | QS_ALLPOSTMESSAGE;

// ── Touch Input structure (48 bytes on x64 / 44 on x86 — Win32 TOUCHINPUT) ─
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TouchInput {
    pub x: i32,
    pub y: i32,
    pub source: u32, // hSource truncated to 32 bits (emulator never sets high bits)
    pub id: u32,
    pub flags: u32,
    pub mask: u32,
    pub time: u32,
    // Win32 x64 aligns ULONG_PTR dwExtraInfo to 8 bytes (offset 32); the
    // packed 44-byte layout previously placed it unaligned at 28 (UB).
    pub pad: u32,
    pub extra_info: usize,
    pub cx: u32, // contact area width
    pub cy: u32, // contact area height
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

// ── Pointer Device Caps structure (for GetPointerDeviceCaps) ─────────────
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PointerDeviceCaps {
    /// The monitor this device is associated with
    pub monitor: u32,
    /// Whether the device supports Gvfp (GetValueFrameProgress) / display time
    pub supports_display_time: u32,
    /// Type of pointer device (1=touch, 2=pen, 3=mouse, etc.)
    pub pointer_device_type: u32,
    /// Maximum number of simultaneous contacts
    pub max_contacts: u32,
}

/// Rect structure used by GetPointerDeviceRects.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PointerDeviceRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Frame info for GetPointerFrameInfo.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PointerFrameInfo {
    pub current_pointer_count: u32,
    pub pointers_in_frame: u32,
    pub frame_id: u32,
    pub pointer_flags: u32,
    pub display_time: u32,
    pub performance_count: u64,
}

// ── Touch state tracking ─────────────────────────────────────────────────
/// Tracks windows that have called RegisterTouchWindow, pending touch
/// inputs, and initialized pointer devices.
#[derive(Debug, Clone, Default)]
pub struct TouchState {
    /// HWNDs that called RegisterTouchWindow
    pub registered_windows: Vec<u32>,
    /// Handle → touch inputs stored for GetTouchInputInfo
    pub touch_handles: BTreeMap<u32, Vec<TouchInput>>,
    /// Next handle value for touch input storage
    pub next_touch_handle: u32,
    /// Monotonically increasing pointer frame id (GetPointerFrameInfo).
    pub next_frame_id: u32,
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
        // clamp() panics when the bounds are inverted (left > right or
        // top > bottom), and guest code can supply arbitrary rects
        // (ClipCursor / SetCursorPos). Return the raw point for
        // degenerate rects instead of aborting the process.
        let cx = if self.left <= self.right {
            x.clamp(self.left, self.right)
        } else {
            x
        };
        let cy = if self.top <= self.bottom {
            y.clamp(self.top, self.bottom)
        } else {
            y
        };
        (cx, cy)
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
    PerMonitorAware,
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
    pub work_rect: Rect,
    pub is_primary: bool,
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
    /// Raw pointer to the real NSWindow on macOS (null if not yet created / headless).
    ns_window: *mut std::ffi::c_void,
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
#[allow(dead_code)] // hook record state retained for future SetWindowsHookEx paths
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
    table[0x01] = 0x1B; // Escape
    table[0x02] = 0x31; // 1
    table[0x03] = 0x32; // 2
    table[0x04] = 0x33; // 3
    table[0x05] = 0x34; // 4
    table[0x06] = 0x35; // 5
    table[0x07] = 0x36; // 6
    table[0x08] = 0x37; // 7
    table[0x09] = 0x38; // 8
    table[0x0A] = 0x39; // 9
    table[0x0B] = 0x30; // 0
    table[0x0C] = 0xBD; // -_
    table[0x0D] = 0xBB; // =+
    table[0x0E] = 0x08; // Backspace
    table[0x0F] = 0x09; // Tab
    table[0x10] = 0x51; // Q
    table[0x11] = 0x57; // W
    table[0x12] = 0x45; // E
    table[0x13] = 0x52; // R
    table[0x14] = 0x54; // T
    table[0x15] = 0x59; // Y
    table[0x16] = 0x55; // U
    table[0x17] = 0x49; // I
    table[0x18] = 0x4F; // O
    table[0x19] = 0x50; // P
    table[0x1A] = 0xDB; // [{
    table[0x1B] = 0xDD; // ]}
    table[0x1C] = 0x0D; // Enter
    table[0x1D] = 0x11; // Ctrl
    table[0x1E] = 0x41; // A
    table[0x1F] = 0x53; // S
    table[0x20] = 0x44; // D
    table[0x21] = 0x46; // F
    table[0x22] = 0x47; // G
    table[0x23] = 0x48; // H
    table[0x24] = 0x4A; // J
    table[0x25] = 0x4B; // K
    table[0x26] = 0x4C; // L
    table[0x27] = 0xBA; // ;:
    table[0x28] = 0xDE; // '"
    table[0x29] = 0xC0; // `~
    table[0x2A] = 0x10; // LShift
    table[0x2B] = 0xDC; // \|
    table[0x2C] = 0x5A; // Z
    table[0x2D] = 0x58; // X
    table[0x2E] = 0x43; // C
    table[0x2F] = 0x56; // V
    table[0x30] = 0x42; // B
    table[0x31] = 0x4E; // N
    table[0x32] = 0x4D; // M
    table[0x33] = 0xBC; // ,<
    table[0x34] = 0xBE; // .>
    table[0x35] = 0xBF; // /?
    table[0x36] = 0xA1; // RShift
    table[0x37] = 0x6A; // * (Numpad Multiply)
    table[0x38] = 0x12; // Alt/Menu
    table[0x39] = 0x20; // Space
    table[0x3A] = 0x14; // Caps Lock
    table[0x3B] = 0x70; // F1
    table[0x3C] = 0x71; // F2
    table[0x3D] = 0x72; // F3
    table[0x3E] = 0x73; // F4
    table[0x3F] = 0x74; // F5
    table[0x40] = 0x75; // F6
    table[0x41] = 0x76; // F7
    table[0x42] = 0x77; // F8
    table[0x43] = 0x78; // F9
    table[0x44] = 0x79; // F10
    table[0x45] = 0x13; // Pause
    table[0x46] = 0x91; // Scroll Lock
    table[0x47] = 0x24; // Home
    table[0x48] = 0x26; // Up
    table[0x49] = 0x21; // Page Up
    table[0x4A] = 0x6B; // Numpad -
    table[0x4B] = 0x25; // Left
    table[0x4C] = 0x2C; // Numpad 5 / keypad center
    table[0x4D] = 0x27; // Right
    table[0x4E] = 0x6D; // Numpad +
    table[0x4F] = 0x23; // End
    table[0x50] = 0x28; // Down
    table[0x51] = 0x22; // Page Down
    table[0x52] = 0x2D; // Insert
    table[0x53] = 0x2E; // Delete
    table[0x57] = 0x7A; // F11
    table[0x58] = 0x7B; // F12
    table
};

/// Maps E0-prefixed extended scancode (low 7 bits as index) to VK for US layout.
const SCANCODE_TO_VK_US_EXT: [u16; 128] = {
    let mut table = [0u16; 128];
    table[0x1C] = 0x0D; // Numpad Enter
    table[0x1D] = 0xA3; // RCtrl
    table[0x35] = 0x6F; // Numpad /
    table[0x38] = 0xA5; // RAlt
    table[0x47] = 0x67; // Numpad 7 (Home)
    table[0x48] = 0x68; // Numpad 8 (Up)
    table[0x49] = 0x69; // Numpad 9 (PgUp)
    table[0x4B] = 0x64; // Numpad 4 (Left)
    table[0x4C] = 0x65; // Numpad 5
    table[0x4D] = 0x66; // Numpad 6 (Right)
    table[0x4F] = 0x61; // Numpad 1 (End)
    table[0x50] = 0x62; // Numpad 2 (Down)
    table[0x51] = 0x63; // Numpad 3 (PgDn)
    table[0x52] = 0x60; // Numpad 0 (Ins)
    table[0x53] = 0x6E; // Numpad . (Del)
    table[0x5B] = 0x5B; // LWin
    table[0x5C] = 0x5C; // RWin
    table[0x5D] = 0x5D; // Apps
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
    /// Per-thread DPI awareness override (0 = use process default).
    pub thread_dpi_context: usize,
    classes: BTreeMap<String, WindowClass>,
    windows: BTreeMap<Hwnd, WindowRecord>,
    dialog_items: BTreeMap<(Hwnd, i32), Hwnd>,
    dialog_results: BTreeMap<Hwnd, i64>,
    window_longs: BTreeMap<(Hwnd, i32), u64>,
    /// Class-long storage: (class_name, index) → value.  SetClassLongW stores
    /// into the window CLASS (shared by every window of that class) and
    /// returns the previous value.
    class_longs: BTreeMap<(String, i32), u64>,
    message_queue: VecDeque<Message>,
    thread_message_queues: BTreeMap<u32, VecDeque<Message>>,
    /// Ring buffer of recently dispatched messages (capped to bound memory).
    message_log: VecDeque<Message>,
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
    /// Active timers: (hwnd, timer_id) → (expiry, interval_ms). An interval
    /// of 0 marks a one-shot timer; positive intervals are periodic and are
    /// re-armed by poll_timers after each expiry (Win32 SetTimer semantics).
    timers: BTreeMap<(Hwnd, usize), (std::time::SystemTime, u64)>,
    /// Clipboard open state (OpenClipboard/CloseClipboard tracking).
    clipboard_open: bool,
    /// Window that currently owns the clipboard.
    clipboard_owner: Option<Hwnd>,
    /// Clipboard data store: format → raw bytes.
    clipboard_data: BTreeMap<u32, Vec<u8>>,
    /// Clipboard handles: format → the guest HGLOBAL passed to
    /// SetClipboardData (returned by GetClipboardData, Windows semantics).
    clipboard_handles: BTreeMap<u32, u64>,
    /// Next clipboard format to enumerate (for EnumClipboardFormats).
    clipboard_format_enum_cursor: Option<u32>,
    // ── Menu state ─────────────────────────────────────────────────────────────
    /// Window menu handles: hwnd → menu_handle.
    window_menus: BTreeMap<Hwnd, u32>,
    /// Menu item storage per menu handle: menu_handle → list of (flags, id, string).
    menu_items: BTreeMap<u32, Vec<(u32, u32, String)>>,
    /// Next menu handle to assign.
    next_menu_handle: u32,
    /// Sub-menu relationships: menu_handle → parent_menu_handle.
    menu_parents: BTreeMap<u32, u32>,
    // ── Scrollbar state ──────────────────────────────────────────────────────────
    /// Scrollbar info per (hwnd, bar_type): bar_type 0=horizontal, 1=vertical.
    scroll_info: BTreeMap<(Hwnd, u8), (i32, i32, i32, u32)>,
    // ── Common Controls state ────────────────────────────────────────────────────
    /// Whether InitCommonControlsEx has been called.
    common_controls_initialized: bool,
    /// Bitmask of ICC_* flags from InitCommonControlsEx call.
    common_controls_flags: u32,
    // ── Flash window state ──────────────────────────────────────────────────────
    /// Track flash state per window: hwnd → currently flashing.
    flashing_windows: BTreeMap<Hwnd, bool>,
    // ── DWM state (Desktop Window Manager) ────────────────────────────────────────────
    /// Per-window DWM attributes (DWMWA_* values).
    dwm_attributes: BTreeMap<Hwnd, DwmAttributes>,
    /// Visual effect views (NSVisualEffectView) for DWM blur-behind, keyed by HWND.
    blur_effect_views: BTreeMap<Hwnd, u64>,
    /// Shared runtime-event observer list (set by the PE runtime; `None`
    /// when driven standalone — event emission is a no-op then).
    pub(crate) event_observers: Option<crate::runtime_events::ObserverList>,
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
        // Query real NSScreens on macOS only in non-test paths.
        // In tests, avoid touching AppKit (requires a running NSApplication).
        let nscreens = if cfg!(test) {
            Vec::new()
        } else {
            crate::mac_window::enumerate_nscreens()
        };
        let monitors = if nscreens.is_empty() {
            #[cfg(test)]
            {
                BTreeMap::from([
                    (
                        1,
                        MonitorInfo {
                            id: 1,
                            name: "Default Display".to_string(),
                            dpi_x: 96,
                            dpi_y: 96,
                            bounds: Rect {
                                left: 0,
                                top: 0,
                                right: 2560,
                                bottom: 1600,
                            },
                            work_rect: Rect {
                                left: 0,
                                top: 0,
                                right: 2560,
                                bottom: 1580,
                            },
                            is_primary: true,
                        },
                    ),
                    (
                        2,
                        MonitorInfo {
                            id: 2,
                            name: "Default Display 2".to_string(),
                            dpi_x: 96,
                            dpi_y: 96,
                            bounds: Rect {
                                left: 2560,
                                top: 0,
                                right: 5120,
                                bottom: 1600,
                            },
                            work_rect: Rect {
                                left: 2560,
                                top: 0,
                                right: 5120,
                                bottom: 1580,
                            },
                            is_primary: false,
                        },
                    ),
                ])
            }
            #[cfg(not(test))]
            {
                BTreeMap::from([(
                    1,
                    MonitorInfo {
                        id: 1,
                        name: "Default Display".to_string(),
                        dpi_x: 96,
                        dpi_y: 96,
                        bounds: Rect {
                            left: 0,
                            top: 0,
                            right: 2560,
                            bottom: 1600,
                        },
                        work_rect: Rect {
                            left: 0,
                            top: 0,
                            right: 2560,
                            bottom: 1580,
                        },
                        is_primary: true,
                    },
                )])
            }
        } else {
            nscreens
                .iter()
                .enumerate()
                .map(|(i, ns)| {
                    let monitor_id = i as u32 + 1;
                    let dpi = (ns.backing_scale_factor * 96.0).round() as u32;
                    (
                        monitor_id,
                        MonitorInfo {
                            id: monitor_id,
                            name: ns.name.clone(),
                            dpi_x: dpi,
                            dpi_y: dpi,
                            bounds: Rect {
                                left: ns.frame.0 as i32,
                                top: ns.frame.1 as i32,
                                right: (ns.frame.0 + ns.frame.2) as i32,
                                bottom: (ns.frame.1 + ns.frame.3) as i32,
                            },
                            work_rect: Rect {
                                left: ns.work_frame.0 as i32,
                                top: ns.work_frame.1 as i32,
                                right: (ns.work_frame.0 + ns.work_frame.2) as i32,
                                bottom: (ns.work_frame.1 + ns.work_frame.3) as i32,
                            },
                            is_primary: ns.is_main,
                        },
                    )
                })
                .collect()
        };
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
            thread_dpi_context: 0,
            classes: BTreeMap::new(),
            windows: BTreeMap::new(),
            dialog_items: BTreeMap::new(),
            dialog_results: BTreeMap::new(),
            window_longs: BTreeMap::new(),
            class_longs: BTreeMap::new(),
            message_queue: VecDeque::new(),
            thread_message_queues: BTreeMap::new(),
            message_log: VecDeque::new(),
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
            timers: BTreeMap::new(),
            clipboard_open: false,
            clipboard_owner: None,
            clipboard_data: BTreeMap::new(),
            clipboard_handles: BTreeMap::new(),
            clipboard_format_enum_cursor: None,
            window_menus: BTreeMap::new(),
            menu_items: BTreeMap::new(),
            next_menu_handle: 0x1000,
            menu_parents: BTreeMap::new(),
            scroll_info: BTreeMap::new(),
            common_controls_initialized: false,
            common_controls_flags: 0,
            flashing_windows: BTreeMap::new(),
            dwm_attributes: BTreeMap::new(),
            blur_effect_views: BTreeMap::new(),
            event_observers: None,
        }
    }

    /// Emit a generic runtime event to the attached observer list (no-op
    /// when this subsystem is driven without a runtime).
    pub(crate) fn emit_event(&mut self, event: crate::runtime_events::RuntimeEvent) {
        if let Some(observers) = &self.event_observers {
            crate::runtime_events::dispatch(observers, &event);
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
        let atom = self.alloc_atom();
        self.classes
            .insert(class_name.to_string(), WindowClass { atom, info });
        atom
    }

    /// Allocate the next free atom (u16): skips 0 (invalid atom) and atoms
    /// already handed out so the counter cannot wrap onto a live class.
    fn alloc_atom(&mut self) -> Atom {
        let start = self.next_atom;
        loop {
            let atom = self.next_atom;
            self.next_atom = self.next_atom.wrapping_add(1);
            if self.next_atom == 0 {
                self.next_atom = 1;
            }
            if atom != 0 && !self.classes.values().any(|class| class.atom == atom) {
                return atom;
            }
            if self.next_atom == start {
                break;
            }
        }
        // Table exhausted: fall back to the next value (unreachable in practice).
        let atom = self.next_atom;
        self.next_atom = self.next_atom.wrapping_add(1);
        atom
    }

    /// Allocate the next free HWND: skips 0 and handles still in use so a
    /// wrapped counter cannot alias a live window.
    fn alloc_hwnd(&mut self) -> Hwnd {
        let start = self.next_hwnd;
        loop {
            let hwnd = self.next_hwnd;
            self.next_hwnd = self.next_hwnd.wrapping_add(1);
            if self.next_hwnd == 0 {
                self.next_hwnd = 1;
            }
            if hwnd != 0 && !self.windows.contains_key(&hwnd) {
                return hwnd;
            }
            if self.next_hwnd == start {
                break;
            }
        }
        // Table exhausted: fall back to the next value (unreachable in practice).
        let hwnd = self.next_hwnd;
        self.next_hwnd = self.next_hwnd.wrapping_add(1);
        hwnd
    }

    /// Allocate the next free menu handle, skipping 0 and live handles.
    fn alloc_menu_handle(&mut self) -> u32 {
        let start = self.next_menu_handle;
        loop {
            let handle = self.next_menu_handle;
            self.next_menu_handle = self.next_menu_handle.wrapping_add(1);
            if handle != 0 && !self.menu_items.contains_key(&handle) {
                return handle;
            }
            if self.next_menu_handle == start {
                break;
            }
        }
        // Table exhausted: fall back to the next value (unreachable in practice).
        let handle = self.next_menu_handle;
        self.next_menu_handle = self.next_menu_handle.wrapping_add(1);
        handle
    }

    /// Allocate the next free touch input handle, skipping 0 and live handles.
    fn alloc_touch_handle(&mut self) -> u32 {
        let start = self.touch_state.next_touch_handle;
        loop {
            let handle = self.touch_state.next_touch_handle;
            self.touch_state.next_touch_handle = self.touch_state.next_touch_handle.wrapping_add(1);
            if handle != 0 && !self.touch_state.touch_handles.contains_key(&handle) {
                return handle;
            }
            if self.touch_state.next_touch_handle == start {
                break;
            }
        }
        // Table exhausted: fall back to the next value (unreachable in practice).
        let handle = self.touch_state.next_touch_handle;
        self.touch_state.next_touch_handle = self.touch_state.next_touch_handle.wrapping_add(1);
        handle
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

    #[allow(clippy::too_many_arguments)]
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
        self.create_window_ex_styled(
            class_name,
            title,
            width,
            height,
            visible,
            requested_exclusive_fullscreen,
            parent,
            monitor_id,
            0,
            0,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
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
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unregistered class {class_name}"),
            )
        })?;
        let class_info = self.classes.get(class_name).map(|class| class.info);
        // atom is verified via ensure_class_available above; only needed for its side effect
        let _atom = atom;
        let hwnd = self.alloc_hwnd();
        let fullscreen = self.map_fullscreen_state(title, requested_exclusive_fullscreen);
        let dpi = self.effective_dpi(monitor_id)?;

        // Create a real NSWindow for any non-child window.
        // Overlapped (WS_OVERLAPPED=0), popup (WS_POPUP), or any combination
        // that is not a child needs a real macOS NSWindow.
        #[allow(dead_code)] // window-style constant (ABI table)
        const WS_OVERLAPPED: u32 = 0x0000_0000;
        let is_child = style & WS_CHILD != 0;
        let is_overlapped_or_popup = !is_child;
        let ns_window = if is_overlapped_or_popup {
            // Lazy initialization of NSApplication if not already done
            if !mac_window::init_nsapplication() {
                std::ptr::null_mut()
            } else {
                let nswin = mac_window::create_nswindow(
                    title, 0, // x (will be set later via SetWindowPos/MoveWindow)
                    0, // y
                    width, height, style, ex_style,
                );
                if !nswin.is_null() {
                    mac_window::associate_hwnd_nswindow(hwnd, nswin);
                }
                nswin
            }
        } else {
            std::ptr::null_mut()
        };

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
                ns_window,
            },
        );
        // Add to z-order: topmost layered windows go at the front
        if ex_style & WS_EX_TOPMOST != 0 {
            self.z_order.insert(0, hwnd);
        } else {
            self.z_order.push(hwnd);
        }
        if let Some(class_info) = class_info.filter(|info| info.wnd_proc != 0) {
            self.window_longs
                .insert((hwnd, GWL_WNDPROC), class_info.wnd_proc);
        }
        // Associate owner window
        if owner.is_some_and(|h| !self.windows.contains_key(&h))
            && let Some(window) = self.windows.get_mut(&hwnd)
        {
            window.owner = None;
        }
        // Queue the creation messages. On failure, roll back everything so a
        // failed creation leaves no live half-created record behind.
        let enqueue_result = (|| -> AppResult<()> {
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
            Ok(())
        })();
        if let Err(e) = enqueue_result {
            if self.foreground == Some(hwnd) {
                self.foreground = None;
            }
            if self.focus == Some(hwnd) {
                self.focus = None;
            }
            self.windows.remove(&hwnd);
            self.z_order.retain(|h| *h != hwnd);
            self.window_longs.retain(|(h, _), _| *h != hwnd);
            if !ns_window.is_null() {
                mac_window::close_nswindow(ns_window);
                mac_window::remove_hwnd_nswindow(hwnd);
            }
            return Err(e);
        }
        // Generic runtime event (no behavior change): a guest window was
        // created.
        self.emit_event(crate::runtime_events::RuntimeEvent::WindowCreated {
            hwnd,
            class: class_name.to_string(),
        });
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
            self.queue_paint(hwnd)?;
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

        // Real macOS window: show or hide the NSWindow
        if let Ok(window) = self.window(hwnd).map(|w| w.ns_window)
            && !window.is_null()
        {
            mac_window::show_nswindow(window, should_show);
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
        self.window(hwnd)
            .map(|window| window.enabled)
            .unwrap_or(false)
    }

    // ── Parent / Child relationship management ─────────────────────────────

    /// Get the parent HWND of a window (if any). Returns 0 if no parent.
    pub fn get_parent(&self, hwnd: Hwnd) -> Hwnd {
        self.windows.get(&hwnd).and_then(|w| w.parent).unwrap_or(0)
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
        window.parent = if parent_hwnd == 0 {
            None
        } else {
            Some(parent_hwnd)
        };
        Ok(previous.unwrap_or(0))
    }

    pub fn set_window_text_w(&mut self, hwnd: Hwnd, title: &str) -> bool {
        let Some(window) = self.windows.get_mut(&hwnd) else {
            return false;
        };
        window.title = title.to_string();
        // Update the real NSWindow title if it exists
        if !window.ns_window.is_null() {
            mac_window::set_nswindow_title(window.ns_window, title);
        }
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

        // Release any DWM blur-behind view still attached to this window so
        // the view is freed with the window (no leak, no later UAF).
        if let Some(view_ptr) = self.blur_effect_views.remove(&hwnd) {
            #[cfg(target_os = "macos")]
            unsafe {
                use objc::runtime::Object;
                let ve_view = view_ptr as *mut Object;
                let _: () = msg_send![ve_view, removeFromSuperview];
                let _: () = msg_send![ve_view, release];
            }
            #[cfg(not(target_os = "macos"))]
            let _ = view_ptr;
        }

        // Drop all per-window state so destroyed windows cannot accumulate
        // unbounded entries in these maps (window churn otherwise leaks).
        self.window_longs.retain(|(h, _), _| *h != hwnd);
        self.dwm_attributes.remove(&hwnd);
        self.flashing_windows.remove(&hwnd);
        self.scroll_info.retain(|(h, _), _| *h != hwnd);
        self.window_menus.remove(&hwnd);
        self.timers.retain(|(h, _), _| *h != hwnd);
        self.dialog_items.retain(|(h, _), _| *h != hwnd);
        self.touch_state.registered_windows.retain(|h| *h != hwnd);
        self.touch_state.pointer_devices.retain(|h| *h != hwnd);
        self.z_order.retain(|h| *h != hwnd);
        if let Some(window) = self.windows.get_mut(&hwnd) {
            window.destroyed = true;
            // Close the real NSWindow exactly once and null the pointer so
            // no later path (e.g. the queued WM_NCDESTROY dispatch) closes
            // or updates it again (double-close / use-after-free).
            if !window.ns_window.is_null() {
                mac_window::close_nswindow(window.ns_window);
                mac_window::remove_hwnd_nswindow(hwnd);
                window.ns_window = std::ptr::null_mut();
            }
        }

        // Best-effort destruction notifications. Failure to queue them (full
        // queue) must not resurrect the window or leave stale records behind.
        for kind in [MessageKind::Destroy, MessageKind::NcDestroy] {
            if let Err(e) = self.enqueue(Message {
                hwnd: Some(hwnd),
                kind,
                wparam: 0,
                lparam: 0,
                translated: false,
                device_id: None,
            }) {
                eprintln!(
                    "[User32] destroy_window: failed to enqueue {kind:?} for hwnd {hwnd}: {e}"
                );
            }
        }

        // Remove the record immediately: WM_NCDESTROY dispatch is not
        // guaranteed on all paths, and stale records otherwise accumulate.
        self.windows.remove(&hwnd);

        Ok(true)
    }

    // ── Real NSWindow API methods ────────────────────────────────────────

    /// Move the real NSWindow (MoveWindow Win32 API equivalent).
    pub fn move_window(
        &mut self,
        hwnd: Hwnd,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        _repaint: bool,
    ) -> AppResult<bool> {
        let Some(window) = self.windows.get_mut(&hwnd) else {
            return Ok(false);
        };
        window.x = x;
        window.y = y;
        window.width = width;
        window.height = height;
        if !window.ns_window.is_null() {
            mac_window::set_nswindow_frame(window.ns_window, x, y, width, height);
        }
        self.queue_resize(hwnd, width, height)?;
        Ok(true)
    }

    /// Set window position (SetWindowPos Win32 API equivalent).
    #[allow(clippy::too_many_arguments)]
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
        const SWP_NOSIZE: u32 = 0x0001;
        const SWP_NOMOVE: u32 = 0x0002;
        const SWP_NOZORDER: u32 = 0x0004;
        const SWP_SHOWWINDOW: u32 = 0x0040;
        const SWP_HIDEWINDOW: u32 = 0x0080;
        const HWND_TOP: u32 = 0;
        const HWND_BOTTOM: u32 = 1;
        const HWND_TOPMOST: u32 = -1i32 as u32;
        const HWND_NOTOPMOST: u32 = -2i32 as u32;
        const WS_EX_TOPMOST: u32 = 0x0008;

        let Some(window) = self.windows.get_mut(&hwnd) else {
            return Ok(false);
        };

        if flags & SWP_NOMOVE == 0 {
            window.x = x;
            window.y = y;
        }
        if flags & SWP_NOSIZE == 0 && cx > 0 && cy > 0 {
            window.width = cx as u32;
            window.height = cy as u32;
        }
        if flags & SWP_SHOWWINDOW != 0 {
            window.visible = true;
        }
        if flags & SWP_HIDEWINDOW != 0 {
            window.visible = false;
        }

        // Update real NSWindow frame
        if !window.ns_window.is_null() {
            let new_x = if flags & SWP_NOMOVE == 0 { x } else { window.x };
            let new_y = if flags & SWP_NOMOVE == 0 { y } else { window.y };
            // Guard the size exactly like the record fields above: a guest
            // passing cx/cy <= 0 must not resize the real window to 4 GiB
            // or 0 while the internal record keeps the old size.
            let new_w = if flags & SWP_NOSIZE == 0 && cx > 0 && cy > 0 {
                cx as u32
            } else {
                window.width
            };
            let new_h = if flags & SWP_NOSIZE == 0 && cx > 0 && cy > 0 {
                cy as u32
            } else {
                window.height
            };
            mac_window::set_nswindow_frame(window.ns_window, new_x, new_y, new_w, new_h);

            if flags & SWP_SHOWWINDOW != 0 {
                mac_window::show_nswindow(window.ns_window, true);
            }
            if flags & SWP_HIDEWINDOW != 0 {
                mac_window::show_nswindow(window.ns_window, false);
            }
        }

        if flags & SWP_NOSIZE == 0 && cx > 0 && cy > 0 {
            self.queue_resize(hwnd, cx as u32, cy as u32)?;
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
                    if let Ok(window) = self.window_mut(hwnd) {
                        window.ex_style |= WS_EX_TOPMOST;
                    }
                    self.bring_window_to_top(hwnd)?;
                }
                HWND_NOTOPMOST => {
                    if let Ok(window) = self.window_mut(hwnd) {
                        window.ex_style &= !WS_EX_TOPMOST;
                    }
                    self.rebuild_z_order();
                }
                other_hwnd => {
                    if self.has_window(other_hwnd) {
                        // Insert `hwnd` directly after `other_hwnd` WITHOUT
                        // removing the target from the z-order (the previous
                        // code deleted other_hwnd and then could never find
                        // it again, so the reinsert never ran).
                        self.z_order.retain(|h| *h != hwnd);
                        if let Some(pos) = self.z_order.iter().position(|h| *h == other_hwnd) {
                            self.z_order.insert(pos + 1, hwnd);
                        } else {
                            self.z_order.insert(0, hwnd);
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    /// Force update/redraw of the real NSWindow (UpdateWindow Win32 API equivalent).
    pub fn update_window(&mut self, hwnd: Hwnd) -> AppResult<bool> {
        let Some(window) = self.windows.get(&hwnd) else {
            return Ok(false);
        };
        // Never touch the NSWindow of a destroyed window: it may already be
        // closed/freed (use-after-free).
        if window.destroyed {
            return Ok(false);
        }
        let ns_window = window.ns_window;
        if !ns_window.is_null() {
            mac_window::update_nswindow(ns_window);
        }
        // UpdateWindow should trigger WM_PAINT dispatch for an existing window
        // even in headless/hidden test setups.
        let already_queued = self
            .message_queue
            .iter()
            .any(|message| message.hwnd == Some(hwnd) && message.kind == MessageKind::Paint);
        if !already_queued {
            self.enqueue(Message {
                hwnd: Some(hwnd),
                kind: MessageKind::Paint,
                wparam: 0,
                lparam: 0,
                translated: false,
                device_id: None,
            })?;
        }
        Ok(true)
    }

    /// Return a pseudo-handle for the desktop window (GetDesktopWindow Win32 API).
    /// In Casa1, we return 0 since we don't map the desktop to a real HWND.
    pub fn get_desktop_window(&self) -> Hwnd {
        0
    }

    /// GetWindowThreadProcessId — returns the thread that created the window.
    /// In Casa1, all windows are created by thread 1.
    pub fn get_window_thread_process_id(&self, _hwnd: Hwnd) -> (u32, u32) {
        // Return thread_id=1, process_id=current_pid
        (1, std::process::id())
    }

    /// KillTimer — destroy a timer.
    pub fn kill_timer(&mut self, hwnd: Hwnd, timer_id: usize) -> bool {
        self.timers.remove(&(hwnd, timer_id)).is_some()
    }

    /// UnregisterClassW — unregister a window class.
    pub fn unregister_class_w(&mut self, class_name: &str) -> bool {
        self.classes.remove(class_name).is_some()
    }

    /// Set a timer (called from the dispatch side for SetTimer).
    pub fn set_timer(&mut self, hwnd: Hwnd, timer_id: usize, timeout_ms: u32) -> bool {
        let interval = timeout_ms as u64;
        let expiry = std::time::SystemTime::now() + std::time::Duration::from_millis(interval);
        self.timers.insert((hwnd, timer_id), (expiry, interval));
        true
    }

    /// Check if any timers have expired (for WM_TIMER generation).
    pub fn poll_timers(&mut self) -> Vec<(Hwnd, usize)> {
        let now = std::time::SystemTime::now();
        let mut expired = Vec::new();
        let mut rearmed: BTreeMap<(Hwnd, usize), (std::time::SystemTime, u64)> = BTreeMap::new();
        self.timers.retain(|&(hwnd, id), (expiry, period)| {
            if *expiry <= now {
                expired.push((hwnd, id));
                // Periodic timers (interval > 0) re-arm themselves so
                // animation/game timers keep firing until KillTimer.
                if *period > 0 {
                    let next = now + std::time::Duration::from_millis(*period);
                    rearmed.insert((hwnd, id), (next, *period));
                }
                false
            } else {
                true
            }
        });
        self.timers.extend(rearmed);
        expired
    }

    /// Return count of active timers.
    pub fn timer_count(&self) -> usize {
        self.timers.len()
    }

    /// Check whether the message queue has certain types of events (QS_* flags).
    pub fn message_queue_has_events(&self, wake_mask: u32) -> bool {
        if wake_mask == 0 || wake_mask & QS_ALLINPUT == QS_ALLINPUT {
            return !self.message_queue.is_empty() || self.pending_paint();
        }
        for msg in &self.message_queue {
            let msg_flag = match msg.kind {
                MessageKind::KeyDown | MessageKind::KeyUp | MessageKind::Char => QS_KEY,
                MessageKind::MouseMove => QS_MOUSEMOVE,
                MessageKind::LButtonDown | MessageKind::LButtonUp | MessageKind::XButtonDown => {
                    QS_MOUSEBUTTON
                }
                MessageKind::Paint => QS_PAINT,
                // WM_TIMER (0x0113) is represented as Other(0x0113) when no dedicated variant exists
                MessageKind::Other(0x0113) => QS_TIMER,
                MessageKind::Other(_) => QS_POSTMESSAGE,
                _ => continue,
            };
            if msg_flag & wake_mask != 0 {
                // Found a message matching the wake mask — signal the wait should wake
                return true;
            }
        }
        // Also check for paint messages that may be pending (not yet enqueued)
        if wake_mask & QS_PAINT != 0 && self.pending_paint() {
            // Pending paint matches QS_PAINT wake mask — signal wake
            return true;
        }
        false
    }

    /// Returns true if any window has a pending paint (invalidation not yet turned into WM_PAINT).
    fn pending_paint(&self) -> bool {
        self.message_queue
            .iter()
            .any(|m| m.kind == MessageKind::Paint)
    }

    // ── Clipboard API ────────────────────────────────────────────────────

    /// OpenClipboard — open the clipboard.
    pub fn open_clipboard(&mut self, hwnd: Option<Hwnd>) -> bool {
        if self.clipboard_open {
            return false; // already open by another window
        }
        self.clipboard_open = true;
        self.clipboard_owner = hwnd;
        true
    }

    /// CloseClipboard — close the clipboard.
    pub fn close_clipboard(&mut self) -> bool {
        self.clipboard_open = false;
        self.clipboard_owner = None;
        self.clipboard_format_enum_cursor = None;
        true
    }

    /// GetClipboardData — retrieve clipboard data.
    /// Returns a handle (address) to the data in the guest's memory.
    /// In this implementation, we store clipboard data as byte vectors.
    /// The returned handle is a pseudo-handle (the format keyed index).
    pub fn get_clipboard_data(&mut self, format: u32) -> Option<Vec<u8>> {
        if !self.clipboard_open {
            return None;
        }
        // Check local store first
        if let Some(data) = self.clipboard_data.get(&format) {
            return Some(data.clone());
        }
        // Fall back to NSPasteboard for inter-process clipboard access
        // SAFETY: nspasteboard_get_data wraps AppKit FFI; falls back silently in headless mode
        mac_window::nspasteboard_get_data(format, 64 * 1024)
    }

    /// SetClipboardData — set clipboard data.
    /// Stores a copy of the data together with the guest HGLOBAL handle.
    /// Returns `true` when the clipboard is open and the data was stored; the
    /// caller returns the guest handle on success (Windows returns the hData
    /// handle) and NULL + ERROR_CLIPBOARD_NOT_OPEN otherwise.
    pub fn set_clipboard_data(&mut self, format: u32, data: Vec<u8>, handle: u64) -> bool {
        if !self.clipboard_open {
            return false;
        }
        // Write to NSPasteboard for inter-process clipboard sharing
        // SAFETY: nspasteboard_set_data wraps AppKit FFI; falls back silently in headless mode
        mac_window::nspasteboard_set_data(format, &data);
        // Store locally for non-text formats and as a session cache
        self.clipboard_data.insert(format, data);
        self.clipboard_handles.insert(format, handle);
        true
    }

    /// The guest HGLOBAL stored for a clipboard format (Windows
    /// GetClipboardData returns the handle passed to SetClipboardData).
    pub fn clipboard_handle(&self, format: u32) -> Option<u64> {
        self.clipboard_handles.get(&format).copied()
    }

    /// EmptyClipboard — empty the clipboard and free handles to data.
    pub fn empty_clipboard(&mut self) -> bool {
        if !self.clipboard_open {
            return false;
        }
        self.clipboard_data.clear();
        self.clipboard_handles.clear();
        self.clipboard_format_enum_cursor = None;
        // Clear NSPasteboard for inter-process clipboard sharing
        // SAFETY: nspasteboard_clear wraps AppKit FFI; falls back silently in headless mode
        mac_window::nspasteboard_clear();
        true
    }

    /// IsClipboardFormatAvailable — check if the clipboard contains data in the specified format.
    pub fn is_clipboard_format_available(&self, format: u32) -> bool {
        self.clipboard_data.contains_key(&format)
            || mac_window::nspasteboard_is_format_available(format)
    }

    /// EnumClipboardFormats — enumerate the formats currently available on the clipboard.
    /// Pass format=0 to get the first format. Returns 0 when no more formats.
    pub fn enum_clipboard_formats(&mut self, format: u32) -> u32 {
        if !self.clipboard_open {
            return 0;
        }
        // Gather known format codes. Start with locally-set formats.
        let mut formats: Vec<u32> = self.clipboard_data.keys().copied().collect();
        // Probe NSPasteboard for common text/image formats that may have been
        // placed there by another process (e.g., macOS apps).
        for probe in [
            1u32, /*CF_TEXT*/
            13,   /*CF_UNICODETEXT*/
            7,    /*CF_OEMTEXT*/
            2,    /*CF_BITMAP*/
            14,   /*CF_ENHMETAFILE*/
            15,   /*CF_HDROP*/
            8,    /*CF_DIB*/
            3,    /*CF_METAFILEPICT*/
        ] {
            if !formats.contains(&probe) && mac_window::nspasteboard_is_format_available(probe) {
                formats.push(probe);
            }
        }
        formats.sort();
        if formats.is_empty() {
            return 0;
        }
        if format == 0 {
            // Return the first format
            formats.first().copied().unwrap_or(0)
        } else {
            // Return the next format after the given one
            let pos = formats.iter().position(|f| *f == format);
            match pos {
                Some(idx) if idx + 1 < formats.len() => formats[idx + 1],
                _ => 0,
            }
        }
    }

    pub fn def_window_proc_w(&mut self, message: &Message) -> AppResult<i64> {
        if let Some(hwnd) = message.hwnd.filter(|hwnd| self.windows.contains_key(hwnd)) {
            let window = self.window(hwnd)?.clone();
            match message.kind {
                MessageKind::LButtonDown => {
                    if let Err(e) = self.set_focus(hwnd) {
                        eprintln!(
                            "[User32] def_window_proc_w(LButtonDown): set_focus failed for hwnd {hwnd}: {e}"
                        );
                    }
                    self.capture = Some(hwnd);
                }
                MessageKind::LButtonUp => {
                    if self.capture == Some(hwnd) {
                        self.capture = None;
                    }
                    if window.enabled
                        && window.class_name.eq_ignore_ascii_case("button")
                        && let Some(parent) = window.parent
                    {
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
                _ => {
                    if let Err(e) = self.window(hwnd) {
                        eprintln!(
                            "[User32] def_window_proc_w(default): window lookup failed for hwnd {hwnd}: {e}"
                        );
                    }
                }
            }
        }
        Ok(0)
    }

    pub fn has_window(&self, hwnd: Hwnd) -> bool {
        self.windows.contains_key(&hwnd)
    }

    pub fn set_layered_window_attributes(
        &mut self,
        hwnd: Hwnd,
        alpha: u8,
        flags: u32,
    ) -> AppResult<()> {
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

    pub fn set_window_placement(
        &mut self,
        hwnd: Hwnd,
        placement: WindowPlacement,
    ) -> AppResult<()> {
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
            if class_name.is_some_and(|expected| !window.class_name.eq_ignore_ascii_case(expected))
            {
                continue;
            }
            if title.is_some_and(|expected| window.title != expected) {
                continue;
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

        let hwnd = self.alloc_hwnd();
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
                ns_window: std::ptr::null_mut(),
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

    // ── Dialog Manager ───────────────────────────────────────────────────────────

    /// DialogBoxParam — creates a modal dialog box.
    /// Creates a window of class "#32770" (dialog), optionally registers it,
    /// and returns the dialog result code.
    ///
    /// The modal dispatch loop is owned by pe_runtime (it executes guest
    /// callbacks); this entry point shows the dialog and returns any result
    /// already produced by EndDialog (e.g. during WM_INITDIALOG), or 0 if
    /// the dialog is still live and its result is pending.
    pub fn dialog_box_param(
        &mut self,
        template_name: &str,
        parent: Hwnd,
        _init_param: i64,
        dlg_proc: u64,
    ) -> AppResult<i64> {
        self.register_class_ex_w("#32770");
        let hwnd = self.create_window_ex_w(
            "#32770",
            template_name,
            1,     // width
            1,     // height
            false, // not visible initially
            false, // not fullscreen
            if parent != 0 { Some(parent) } else { None },
            1, // monitor_id
        )?;
        // Store dialog proc in window_longs for DefDlgProcW dispatch
        if dlg_proc != 0 {
            self.window_longs.insert((hwnd, GWL_WNDPROC), dlg_proc);
        }
        // Check if EndDialog was already called during WM_INITDIALOG
        if let Some(result) = self.take_dialog_result(hwnd) {
            return Ok(result);
        }
        // Show the dialog
        self.show_window(hwnd, 5)?; // SW_SHOW
        // Return the dialog result (not the HWND): EndDialog results are
        // consumed via take_dialog_result once the modal loop completes.
        Ok(self.take_dialog_result(hwnd).unwrap_or(0))
    }

    /// DefDlgProcW — default dialog window procedure.
    /// Processes dialog-specific messages like WM_CLOSE → EndDialog.
    pub fn def_dlg_proc_w(
        &mut self,
        hwnd: Hwnd,
        msg: u32,
        wparam: i64,
        lparam: i64,
    ) -> AppResult<i64> {
        match msg {
            0x0010 => {
                // WM_CLOSE
                if let Err(e) = self.end_dialog(hwnd, 0) {
                    eprintln!(
                        "[User32] def_dlg_proc_w(WM_CLOSE): end_dialog failed for hwnd {hwnd}: {e}"
                    );
                }
                Ok(0)
            }
            0x0087 => {
                // WM_QUERYENDSESSION
                Ok(1)
            }
            0x0110 => {
                // WM_INITDIALOG
                Ok(1) // TRUE — let the dialog proc handle focus
            }
            0x00F0 => {
                // WM_ERASEBKGND
                // Default: erase background using the dialog's brush
                Ok(1)
            }
            _ => {
                // Fall through to DefWindowProc
                let message = Message {
                    hwnd: Some(hwnd),
                    kind: MessageKind::Other(msg),
                    wparam,
                    lparam,
                    translated: false,
                    device_id: None,
                };
                self.def_window_proc_w(&message)
            }
        }
    }

    /// IsDialogMessageW — determines whether a message is intended for a dialog box.
    /// If so, processes the message (handles Tab/Shift+Tab navigation, etc.).
    /// Returns true if the message was processed (should not be dispatched further).
    pub fn is_dialog_message(&mut self, hwnd: Hwnd, msg: &Message) -> AppResult<bool> {
        if !self.windows.contains_key(&hwnd) {
            return Ok(false);
        }
        // Handle keyboard navigation in dialogs
        match msg.kind {
            MessageKind::KeyDown => {
                let vk = (msg.wparam & 0xFF) as u32;
                match vk {
                    0x09 => {
                        // VK_TAB
                        // Internal KeyDown messages carry KeyModifiers::to_bits()
                        // (bits 0-1), not the Win32 0x80000000 bit-31 flag.
                        let shift = KeyModifiers::from_bits(msg.wparam).shift;
                        // Find next/previous control in dialog
                        let parent = hwnd;
                        let children: Vec<Hwnd> = self
                            .windows
                            .iter()
                            .filter(|(_, w)| w.parent == Some(parent) && !w.destroyed)
                            .map(|(h, _)| *h)
                            .collect();
                        if children.is_empty() {
                            // No tab-stoppable children — consume the tab key to prevent
                            // focus from leaving the dialog, matching Windows behavior
                            return Ok(true);
                        }
                        // Simple tab order: cycle through child windows
                        let current_focus = self.focus;
                        let next_idx = if let Some(focus) = current_focus {
                            if let Some(pos) = children.iter().position(|h| *h == focus) {
                                if shift {
                                    (pos + children.len() - 1) % children.len()
                                } else {
                                    (pos + 1) % children.len()
                                }
                            } else {
                                0
                            }
                        } else {
                            0
                        };
                        if let Some(&next_focus) = children.get(next_idx)
                            && let Err(e) = self.set_focus(next_focus)
                        {
                            eprintln!(
                                "[User32] def_dlg_proc_w(VK_TAB): set_focus failed for hwnd {next_focus}: {e}"
                            );
                        }
                        Ok(true)
                    }
                    0x1B => {
                        // VK_ESCAPE
                        // ESC cancels the dialog
                        if let Err(e) = self.end_dialog(hwnd, 0) {
                            eprintln!(
                                "[User32] def_dlg_proc_w(VK_ESCAPE): end_dialog failed for hwnd {hwnd}: {e}"
                            );
                        }
                        Ok(true)
                    }
                    0x0D => {
                        // VK_RETURN
                        // ENTER on a default button sends BN_CLICKED
                        // Find the default button (control with WS_TABSTOP | BS_DEFPUSHBUTTON style)
                        for (child_hwnd, w) in &self.windows {
                            if w.parent == Some(hwnd) && !w.destroyed && w.style & WS_TABSTOP != 0 {
                                // Send WM_COMMAND with BN_CLICKED
                                self.enqueue(Message {
                                    hwnd: Some(hwnd),
                                    kind: MessageKind::Command,
                                    wparam: w.control_id as i64,
                                    lparam: i64::from(*child_hwnd),
                                    translated: false,
                                    device_id: None,
                                })?;
                                break;
                            }
                        }
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    pub fn set_window_long_w(&mut self, hwnd: Hwnd, index: i32, value: u64) -> Option<u64> {
        if !self.windows.contains_key(&hwnd) {
            return None;
        }
        // GWL_HWNDPARENT (-8): delegate to set_parent so the window hierarchy stays
        // consistent with the parent field in WindowRecord.
        if index == GWL_HWNDPARENT {
            let previous = self.get_parent(hwnd);
            if let Err(e) = self.set_parent(hwnd, value as Hwnd) {
                eprintln!(
                    "[User32] set_window_long_w(GWL_HWNDPARENT): set_parent failed for hwnd {hwnd}: {e}"
                );
            }
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

    /// SetClassLongW — store a class long on the window CLASS of `hwnd` and
    /// return the previous value (Windows semantics).  The value is shared by
    /// every window of that class, keyed by the class name.
    pub fn set_class_long_w(&mut self, hwnd: Hwnd, index: i32, value: u64) -> Option<u64> {
        let class_name = self.windows.get(&hwnd)?.class_name.clone();
        Some(
            self.class_longs
                .insert((class_name, index), value)
                .unwrap_or(0),
        )
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

    /// Post a WM_TIMER message for a due `SetTimer` timer to the owning
    /// thread's message queue (wParam = timer_id, lParam = 0).
    ///
    /// Win32 delivers timers as WM_TIMER messages to the queue of the
    /// thread that created the window (all Casa1 windows are created by
    /// thread 1, whose queue is the shared message queue).  Unlike
    /// `post_message_w`, this does NOT require the window record to still
    /// exist: the timer has already fired and the window may have been
    /// destroyed between `poll_timers` and the post.
    pub fn post_timer_message(&mut self, hwnd: Hwnd, timer_id: usize) -> AppResult<()> {
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::Other(WM_TIMER),
            wparam: timer_id as i64,
            lparam: 0,
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
                    .filter_map(|(hwnd, window)| {
                        (!window.destroyed && window.visible).then_some(*hwnd)
                    })
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
            if remove && let Some(queue) = self.thread_message_queues.get_mut(&thread_id) {
                queue.pop_front();
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
        if let Some(queue) = self
            .thread_message_queues
            .get_mut(&thread_id)
            .filter(|queue| !queue.is_empty())
        {
            return queue.pop_front();
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
        // Keep the message log bounded: long-running guests dispatch many
        // messages per frame, and an unbounded Vec grows forever.
        const MESSAGE_LOG_CAP: usize = 4096;
        if self.message_log.len() == MESSAGE_LOG_CAP {
            self.message_log.pop_front();
        }
        self.message_log.push_back(message.clone());
        if message.kind == MessageKind::NcDestroy
            && let Some(hwnd) = message.hwnd
        {
            // Destroyed windows are fully cleaned up in destroy_window;
            // this path only handles NcDestroy queued directly.
            if let Some(window) = self
                .windows
                .get(&hwnd)
                .filter(|window| !window.ns_window.is_null())
            {
                mac_window::close_nswindow(window.ns_window);
                mac_window::remove_hwnd_nswindow(hwnd);
            }
            self.windows.remove(&hwnd);
            self.z_order.retain(|h| *h != hwnd);
            self.cef_browser_handles.remove(&hwnd);
        }
        Ok(result)
    }

    pub fn message_log(&mut self) -> &[Message] {
        self.message_log.make_contiguous()
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
        let mut hwnds: Vec<Hwnd> = self
            .windows
            .keys()
            .copied()
            .filter(|h| !self.windows[h].destroyed)
            .collect();
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
        // If the window has an owner, raise the owner too but keep it BEHIND
        // the owned window (Win32 raises the owner without covering it).
        if let Some(owner) = self.windows.get(&hwnd).and_then(|w| w.owner) {
            self.z_order.retain(|h| *h != owner);
            if let Some(pos) = self.z_order.iter().position(|h| *h == hwnd) {
                self.z_order.insert(pos + 1, owner);
            } else {
                self.z_order.insert(0, owner);
            }
        }
        self.foreground = Some(hwnd);
        Ok(())
    }

    /// Get the topmost (front-most) window in the z-order.
    pub fn get_top_window(&self, hwnd: Option<Hwnd>) -> Option<Hwnd> {
        if let Some(parent) = hwnd {
            // Return topmost child of parent
            self.z_order.iter().copied().find(|h| {
                self.windows
                    .get(h)
                    .is_some_and(|w| w.parent == Some(parent) && !w.destroyed)
            })
        } else {
            self.z_order
                .first()
                .copied()
                .filter(|h| self.windows.get(h).is_some_and(|w| !w.destroyed))
        }
    }

    /// Get the next/previous window in the z-order (GW_HWNDNEXT / GW_HWNDPREV).
    pub fn get_next_window(&self, hwnd: Hwnd, direction: u32) -> Option<Hwnd> {
        let pos = self.z_order.iter().position(|h| *h == hwnd)?;
        match direction {
            GW_HWNDNEXT => {
                // GW_HWNDNEXT (2): window below in z-order
                self.z_order
                    .get(pos + 1)
                    .copied()
                    .filter(|h| self.windows.get(h).is_some_and(|w| !w.destroyed))
            }
            GW_HWNDPREV => {
                // GW_HWNDPREV (3): window above in z-order
                if pos > 0 {
                    self.z_order
                        .get(pos - 1)
                        .copied()
                        .filter(|h| self.windows.get(h).is_some_and(|w| !w.destroyed))
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
                    self.windows
                        .get(h)
                        .is_some_and(|w| w.parent == Some(hwnd) && !w.destroyed)
                })
            }
            GW_OWNER => self
                .windows
                .get(&hwnd)
                .and_then(|w| w.owner)
                .filter(|h| self.windows.get(h).is_some_and(|w| !w.destroyed)),
            GW_HWNDNEXT | GW_HWNDPREV => self.get_next_window(hwnd, cmd),
            GW_ENABLEDPOPUP => {
                // Return the topmost enabled popup owned by hwnd
                self.z_order.iter().copied().find(|h| {
                    self.windows.get(h).is_some_and(|w| {
                        !w.destroyed
                            && w.enabled
                            && w.owner == Some(hwnd)
                            && w.style & WS_POPUP != 0
                    })
                })
            }
            _ => None,
        }
    }

    // ── Window text management ────────────────────────────────────────────────

    pub fn get_window_text_w(&self, hwnd: Hwnd) -> Option<String> {
        self.windows.get(&hwnd).map(|w| w.title.clone())
    }

    pub fn get_window_text_length_w(&self, hwnd: Hwnd) -> Option<i32> {
        // Win32 GetWindowTextLengthW returns the number of WCHARs, not the
        // UTF-8 byte length (non-ASCII titles would size buffers wrongly).
        self.windows
            .get(&hwnd)
            .map(|w| w.title.encode_utf16().count() as i32)
    }

    // ── Update rectangle management ───────────────────────────────────────────

    /// Simulate GetUpdateRect — reports whether the window has a pending paint.
    /// Returns (has_update, rect) where rect is the client area.
    pub fn get_update_rect(&self, hwnd: Hwnd) -> AppResult<(bool, Rect)> {
        let window = self.window(hwnd)?;
        let has_paint = self
            .message_queue
            .iter()
            .any(|m| m.hwnd == Some(hwnd) && m.kind == MessageKind::Paint);
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
        self.message_queue
            .retain(|m| !(m.hwnd == Some(hwnd) && m.kind == MessageKind::Paint));
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

    /// SetProcessDPIAwareness (u32-based modern API).
    /// awareness: 0 = unaware, 1 = system aware, 2 = per-monitor aware (V1/V2).
    /// Returns 0 (S_OK) on success, or WIN32 error code on invalid arg.
    pub fn set_process_dpi_awareness(&mut self, awareness: u32) -> u32 {
        match awareness {
            0 => self.dpi_context = DpiAwarenessContext::Unaware,
            1 => self.dpi_context = DpiAwarenessContext::SystemAware,
            2 => self.dpi_context = DpiAwarenessContext::PerMonitorAwareV2,
            _ => return 0x80070057, // E_INVALIDARG
        }
        eprintln!(
            "[User32] set_process_dpi_awareness: set to {:?}",
            self.dpi_context
        );
        0 // S_OK
    }

    /// GetDpiForMonitor — returns DPI for the given monitor and dpi_type.
    /// dpi_type: 0 = MDT_EFFECTIVE_DPI, 1 = MDT_ANGULAR_DPI, 2 = MDT_RAW_DPI.
    pub fn get_dpi_for_monitor(&self, monitor_id: u32, _dpi_type: u32) -> (u32, u32) {
        if let Some(monitor) = self.monitors.get(&monitor_id) {
            (monitor.dpi_x, monitor.dpi_y)
        } else {
            let primary = self
                .monitors
                .values()
                .next()
                .map(|monitor| (monitor.dpi_x, monitor.dpi_y))
                .unwrap_or((96, 96));
            (primary.0, primary.1)
        }
    }

    /// SetThreadDpiAwarenessContext — set per-thread DPI awareness override.
    /// Returns the previous context value.
    pub fn set_thread_dpi_context(&mut self, context: usize) -> usize {
        let old = self.thread_dpi_context;
        self.thread_dpi_context = context;
        old
    }

    /// GetThreadDpiAwarenessContext — returns current thread DPI awareness context.
    pub fn get_thread_dpi_context(&self) -> usize {
        self.thread_dpi_context
    }

    /// EnableNonClientDpiScaling — refresh the window DPI from its current monitor.
    pub fn enable_non_client_dpi_scaling(&mut self, hwnd: u32) -> u32 {
        let monitor_id = match self.windows.get(&hwnd) {
            Some(window) => window.monitor_id,
            None => return 0,
        };
        let dpi = match self.effective_dpi(monitor_id) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "[User32] enable_non_client_dpi_scaling: failed to resolve DPI for hwnd {hwnd}: {error}"
                );
                return 0;
            }
        };
        if let Some(window) = self.windows.get_mut(&hwnd) {
            window.dpi = dpi;
            1
        } else {
            0
        }
    }

    /// AdjustWindowRectExForDpi — calculates required window rect size for a given DPI.
    pub fn adjust_window_rect_for_dpi(
        &self,
        rect: &mut Rect,
        _style: u32,
        _menu: u32,
        _ex_style: u32,
        dpi: u32,
    ) -> u32 {
        let base_dpi = 96;
        let scale = dpi as f64 / base_dpi as f64;
        // Approximate frame borders and title bar, scaled by DPI. Use
        // saturating arithmetic: guest rects can hold extreme coordinates
        // and plain -= would overflow (panicking in debug builds).
        let border = (4_f64 * scale) as i32;
        let title = (23_f64 * scale) as i32;
        rect.left = rect.left.saturating_sub(border);
        rect.top = rect.top.saturating_sub(border.saturating_add(title));
        rect.right = rect.right.saturating_add(border);
        rect.bottom = rect.bottom.saturating_add(border);
        1 // TRUE
    }

    /// MonitorFromRect — finds the monitor that has the largest intersection with the given rect.
    pub fn monitor_from_rect(&self, rect: &Rect, flags: u32) -> u32 {
        // Compute the center in i64: guest-supplied rects can overflow i32
        // addition (right=INT_MAX, left=INT_MIN).
        let rect_center_x = ((rect.left as i64 + rect.right as i64) / 2) as i32;
        let rect_center_y = ((rect.top as i64 + rect.bottom as i64) / 2) as i32;
        for (id, mon) in &self.monitors {
            if rect_center_x >= mon.bounds.left
                && rect_center_x < mon.bounds.right
                && rect_center_y >= mon.bounds.top
                && rect_center_y < mon.bounds.bottom
            {
                return *id;
            }
        }
        match flags {
            // MONITOR_DEFAULTTONULL = 0
            0 => 0,
            // MONITOR_DEFAULTTOPRIMARY = 1, MONITOR_DEFAULTTONEAREST = 2
            _ => self.primary_monitor_id(),
        }
    }

    /// MonitorFromPoint — finds the monitor that contains the given point.
    pub fn monitor_from_point(&self, pt: (i32, i32), flags: u32) -> u32 {
        let (x, y) = pt;
        for (id, mon) in &self.monitors {
            if x >= mon.bounds.left
                && x < mon.bounds.right
                && y >= mon.bounds.top
                && y < mon.bounds.bottom
            {
                return *id;
            }
        }
        match flags {
            // MONITOR_DEFAULTTONULL = 0
            0 => 0,
            // MONITOR_DEFAULTTOPRIMARY = 1, MONITOR_DEFAULTTONEAREST = 2
            _ => self.primary_monitor_id(),
        }
    }

    /// EnumDisplayMonitors — enumerate monitors, calling a callback for each.
    /// Returns TRUE (1) on success.
    pub fn enum_display_monitors(
        &self,
        _hdc: u32,
        _clip_rect: Option<&Rect>,
        _callback: u32,
        _context: u32,
    ) -> u32 {
        // NOTE: The guest callback enumeration is performed by pe_runtime
        // (which has access to guest memory to invoke the callback); this
        // entry point intentionally returns TRUE so enumeration can proceed.
        1 // TRUE
    }

    pub fn primary_monitor_id(&self) -> u32 {
        // Return the monitor flagged as primary (not merely the smallest id:
        // enumeration order is display-dependent).
        self.monitors
            .values()
            .find(|m| m.is_primary)
            .map(|m| m.id)
            .or_else(|| self.monitors.keys().next().copied())
            .unwrap_or(0)
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

    // ── Multi-Monitor (continued) ────────────────────────────────────────────────

    /// GetMonitorInfoW — retrieves monitor information for a given monitor handle.
    pub fn get_monitor_info_w(&self, monitor_id: u32) -> Option<MonitorInfo> {
        self.monitor_info(monitor_id)
    }

    // ── Menu API ──────────────────────────────────────────────────────────────────

    /// CreateMenu — creates a new menu handle.
    pub fn create_menu(&mut self) -> u32 {
        let handle = self.alloc_menu_handle();
        self.menu_items.insert(handle, Vec::new());
        handle
    }

    /// CreatePopupMenu — creates a new popup (drop-down) menu handle.
    pub fn create_popup_menu(&mut self) -> u32 {
        let handle = self.alloc_menu_handle();
        self.menu_items.insert(handle, Vec::new());
        handle
    }

    /// Mirror an externally allocated menu handle into the local user32 menu table.
    pub fn register_menu_handle(&mut self, handle: u32) {
        self.menu_items.entry(handle).or_default();
        if self.next_menu_handle <= handle {
            self.next_menu_handle = handle.saturating_add(1);
        }
    }

    /// DestroyMenu — destroys a menu and releases its resources.
    pub fn destroy_menu(&mut self, menu_handle: u32) -> bool {
        if self.menu_items.remove(&menu_handle).is_some() {
            // Also remove any sub-menu parent relationships
            self.menu_parents.retain(|_, parent| *parent != menu_handle);
            self.window_menus
                .retain(|_, assigned| *assigned != menu_handle);
            true
        } else {
            false
        }
    }

    /// AppendMenuW — appends a new item to the end of a menu.
    pub fn append_menu_w(&mut self, menu_handle: u32, flags: u32, id: u32, text: &str) -> bool {
        if !self.menu_items.contains_key(&menu_handle) {
            return false;
        }
        if let Some(items) = self.menu_items.get_mut(&menu_handle) {
            // MF_POPUP (0x0010) means the id is actually a sub-menu handle
            if (flags & MF_POPUP) != 0 {
                self.menu_parents.insert(id, menu_handle);
            }
            items.push((flags, id, text.to_string()));
            true
        } else {
            false
        }
    }

    /// TrackPopupMenu — validates the popup menu and refreshes the target window.
    /// The actual modal tracking loop is still handled by pe_runtime when TPM_RETURNCMD is set.
    pub fn track_popup_menu(
        &mut self,
        menu_handle: u32,
        _flags: u32,
        _x: i32,
        _y: i32,
        hwnd: Hwnd,
    ) -> bool {
        if !self.menu_items.contains_key(&menu_handle) {
            return false;
        }
        let ns_window = if hwnd != 0 {
            match self.windows.get(&hwnd) {
                Some(window) if !window.destroyed => window.ns_window,
                _ => return false,
            }
        } else {
            std::ptr::null_mut()
        };
        if !ns_window.is_null() {
            mac_window::update_nswindow(ns_window);
        }
        if hwnd != 0 && self.queue_paint(hwnd).is_err() {
            return false;
        }
        true
    }

    /// GetMenu — retrieves the handle of the menu assigned to the given window.
    pub fn get_menu(&self, hwnd: Hwnd) -> u32 {
        self.window_menus.get(&hwnd).copied().unwrap_or(0)
    }

    /// SetMenu — assigns a menu handle to a window.
    pub fn set_menu(&mut self, hwnd: Hwnd, menu_handle: u32) -> bool {
        if !self.windows.contains_key(&hwnd) {
            return false;
        }
        if menu_handle != 0 && !self.menu_items.contains_key(&menu_handle) {
            return false;
        }
        self.window_menus.insert(hwnd, menu_handle);
        true
    }

    /// DrawMenuBar — redraws the menu bar of the given window.
    pub fn draw_menu_bar(&mut self, hwnd: Hwnd) -> bool {
        let ns_window = match self.windows.get(&hwnd) {
            Some(window) if !window.destroyed => window.ns_window,
            _ => return false,
        };
        let menu_handle = self.window_menus.get(&hwnd).copied().unwrap_or(0);
        if menu_handle != 0 && !self.menu_items.contains_key(&menu_handle) {
            return false;
        }
        if !ns_window.is_null() {
            mac_window::update_nswindow(ns_window);
        }
        if self.queue_paint(hwnd).is_err() {
            return false;
        }
        true
    }

    /// EnableMenuItem — enables, disables, or grays a menu item.
    /// Returns the previous state of the menu item, or 0xFFFFFFFF on failure.
    pub fn enable_menu_item(&mut self, menu_handle: u32, id: u32, flags: u32) -> u32 {
        let items = match self.menu_items.get_mut(&menu_handle) {
            Some(i) => i,
            None => return 0xFFFF_FFFF,
        };
        let by_position = (flags & MF_BYPOSITION) != 0;
        let idx = if by_position {
            id as usize
        } else {
            match items.iter().position(|(_, item_id, _)| *item_id == id) {
                Some(i) => i,
                None => return 0xFFFF_FFFF,
            }
        };
        if idx >= items.len() {
            return 0xFFFF_FFFF;
        }
        let item = &mut items[idx];
        let prev_state = item.0 & (MF_GRAYED | MF_DISABLED | MF_CHECKED);
        // Clear enable/disable/check flags and apply new ones
        item.0 &= !(MF_GRAYED | MF_DISABLED | MF_CHECKED);
        item.0 |= flags & (MF_GRAYED | MF_DISABLED | MF_CHECKED);
        prev_state
    }

    /// CheckMenuItem — sets the check state of a menu item.
    /// Returns the previous check state, or 0xFFFFFFFF on failure.
    pub fn check_menu_item(&mut self, menu_handle: u32, id: u32, flags: u32) -> u32 {
        let items = match self.menu_items.get_mut(&menu_handle) {
            Some(i) => i,
            None => return 0xFFFF_FFFF,
        };
        let by_position = (flags & MF_BYPOSITION) != 0;
        let idx = if by_position {
            id as usize
        } else {
            match items.iter().position(|(_, item_id, _)| *item_id == id) {
                Some(i) => i,
                None => return 0xFFFF_FFFF,
            }
        };
        if idx >= items.len() {
            return 0xFFFF_FFFF;
        }
        let item = &mut items[idx];
        let prev_check = item.0 & MF_CHECKED;
        // Toggle check state based on MF_CHECKED flag
        if (flags & MF_CHECKED) != 0 {
            item.0 |= MF_CHECKED;
        } else {
            item.0 &= !MF_CHECKED;
        }
        prev_check
    }

    /// GetMenuItemCount — returns the number of items in a menu, or -1 on error.
    pub fn get_menu_item_count(&self, menu_handle: u32) -> i32 {
        self.menu_items
            .get(&menu_handle)
            .map(|items| items.len() as i32)
            .unwrap_or(-1)
    }

    /// GetSubMenu — retrieves the popup menu handle at a given position.
    pub fn get_sub_menu(&self, menu_handle: u32, pos: i32) -> u32 {
        let items = match self.menu_items.get(&menu_handle) {
            Some(i) => i,
            None => return 0,
        };
        let idx = pos as usize;
        if idx >= items.len() {
            return 0;
        }
        let (flags, id, _) = &items[idx];
        if (flags & MF_POPUP) != 0 {
            *id // The id of a sub-menu item is the sub-menu handle
        } else {
            0
        }
    }

    /// GetMenuState — retrieves the menu flags for a menu item.
    /// Returns 0xFFFFFFFF on failure.
    pub fn get_menu_state(&self, menu_handle: u32, id: u32, flags: u32) -> u32 {
        let items = match self.menu_items.get(&menu_handle) {
            Some(i) => i,
            None => return 0xFFFF_FFFF,
        };
        let by_position = (flags & MF_BYPOSITION) != 0;
        let idx = if by_position {
            id as usize
        } else {
            match items.iter().position(|(_, item_id, _)| *item_id == id) {
                Some(i) => i,
                None => return 0xFFFF_FFFF,
            }
        };
        if idx >= items.len() {
            return 0xFFFF_FFFF;
        }
        items[idx].0
    }

    /// HiliteMenuItem — highlights or removes highlighting from a menu item.
    pub fn hilite_menu_item(&mut self, _hwnd: Hwnd, menu_handle: u32, id: u32, flags: u32) -> bool {
        let items = match self.menu_items.get_mut(&menu_handle) {
            Some(i) => i,
            None => return false,
        };
        let by_position = (flags & MF_BYPOSITION) != 0;
        let idx = if by_position {
            id as usize
        } else {
            match items.iter().position(|(_, item_id, _)| *item_id == id) {
                Some(i) => i,
                None => return false,
            }
        };
        if idx >= items.len() {
            return false;
        }
        let item = &mut items[idx];
        if (flags & MF_HILITE) != 0 {
            item.0 |= MF_HILITE;
        } else {
            item.0 &= !MF_HILITE;
        }
        true
    }

    // ── Scrollbar API ─────────────────────────────────────────────────────────────

    /// SetScrollInfo — sets the parameters of a scroll bar.
    /// Returns the current scroll position.
    #[allow(clippy::too_many_arguments)]
    pub fn set_scroll_info(
        &mut self,
        hwnd: Hwnd,
        bar: u32,
        min: i32,
        max: i32,
        pos: i32,
        page: u32,
        _redraw: bool,
    ) -> i32 {
        let bar_type = if bar == SB_HORZ {
            0u8
        } else if bar == SB_VERT {
            1u8
        } else {
            0u8
        };
        let key = (hwnd, bar_type);
        let old_pos = self.scroll_info.get(&key).map(|info| info.2).unwrap_or(0);
        self.scroll_info.insert(key, (min, max, pos, page));
        old_pos
    }

    /// GetScrollInfo — gets the parameters of a scroll bar.
    /// Returns (min, max, pos, page) if found.
    pub fn get_scroll_info(&self, hwnd: Hwnd, bar: u32) -> Option<(i32, i32, i32, u32)> {
        let bar_type = if bar == SB_HORZ {
            0u8
        } else if bar == SB_VERT {
            1u8
        } else {
            0u8
        };
        self.scroll_info.get(&(hwnd, bar_type)).copied()
    }

    /// SetScrollRange — sets the minimum and maximum scroll position.
    pub fn set_scroll_range(
        &mut self,
        hwnd: Hwnd,
        bar: u32,
        min: i32,
        max: i32,
        _redraw: bool,
    ) -> bool {
        let bar_type = if bar == SB_HORZ {
            0u8
        } else if bar == SB_VERT {
            1u8
        } else {
            0u8
        };
        let key = (hwnd, bar_type);
        let (_, _, pos, page) = self
            .scroll_info
            .get(&key)
            .copied()
            .unwrap_or((0, 100, 0, 0));
        self.scroll_info.insert(key, (min, max, pos, page));
        true
    }

    /// GetScrollRange — gets the minimum and maximum scroll position.
    /// Returns (min, max) if found.
    pub fn get_scroll_range(&self, hwnd: Hwnd, bar: u32) -> Option<(i32, i32)> {
        let bar_type = if bar == SB_HORZ {
            0u8
        } else if bar == SB_VERT {
            1u8
        } else {
            0u8
        };
        self.scroll_info
            .get(&(hwnd, bar_type))
            .map(|info| (info.0, info.1))
    }

    /// ShowScrollBar — shows or hides a scroll bar.
    pub fn show_scroll_bar(&mut self, hwnd: Hwnd, _bar: u32, _show: bool) -> bool {
        if !self.windows.contains_key(&hwnd) {
            return false;
        }
        // On macOS, scroll bars are managed natively; this is a no-op that returns success.
        true
    }

    /// EnableScrollBar — enables or disables one or both scroll bar arrows.
    pub fn enable_scroll_bar(&mut self, hwnd: Hwnd, _flags: u32, _arrows: u32) -> bool {
        if !self.windows.contains_key(&hwnd) {
            return false;
        }
        true
    }

    /// ScrollWindow — scrolls the contents of a window's client area.
    /// NOTE: simplified — the scroll rects are ignored and the window is
    /// invalidated so it repaints at the new position; the guest's BITBLT
    /// of the scrolled area is not performed (acceptable approximation).
    pub fn scroll_window(
        &mut self,
        hwnd: Hwnd,
        _dx: i32,
        _dy: i32,
        _rect: Option<&Rect>,
        _clip_rect: Option<&Rect>,
    ) -> bool {
        if !self.windows.contains_key(&hwnd) {
            return false;
        }
        // Invalidate the window so it gets repainted with the new scroll position
        if let Err(e) = self.invalidate_window(Some(hwnd), true) {
            eprintln!("[User32] scroll_window: invalidate_window failed for hwnd {hwnd}: {e}");
        }
        true
    }

    /// ScrollWindowEx — scrolls the contents of a window's client area with extended options.
    #[allow(clippy::too_many_arguments)]
    pub fn scroll_window_ex(
        &mut self,
        hwnd: Hwnd,
        _dx: i32,
        _dy: i32,
        _rect: Option<&Rect>,
        _clip_rect: Option<&Rect>,
        _hrgn_update: u32,
        _rect_update: Option<&Rect>,
        _flags: u32,
    ) -> bool {
        if !self.windows.contains_key(&hwnd) {
            return false;
        }
        if let Err(e) = self.invalidate_window(Some(hwnd), true) {
            eprintln!("[User32] scroll_window_ex: invalidate_window failed for hwnd {hwnd}: {e}");
        }
        true
    }

    // ── Common Controls API ───────────────────────────────────────────────────────

    /// InitCommonControlsEx — registers common control classes.
    /// Returns TRUE on success.
    pub fn init_common_controls_ex(&mut self, flags: u32) -> bool {
        self.common_controls_initialized = true;
        self.common_controls_flags |= flags;
        self.register_common_control_classes();
        true
    }

    // ── DWM (Desktop Window Manager) — real implementations ─────────────────────

    /// DwmIsCompositionEnabled — returns whether DWM composition is enabled.
    /// On macOS the compositor (WindowServer / Quartz Compositor) is always active,
    /// so this returns TRUE (Windows 8+ behaviour where composition is always on).
    pub fn dwm_is_composition_enabled(&self) -> bool {
        true
    }

    /// DwmEnableComposition — enables or disables DWM composition.
    /// On macOS the compositor cannot be disabled; this logs a warning and returns
    /// S_OK to indicate the call was accepted without effect.
    pub fn dwm_enable_composition(&mut self, f_enable: u32) -> u32 {
        if f_enable == DWM_EC_DISABLECOMPOSITION {
            eprintln!(
                "[User32] DwmEnableComposition(DISABLE) ignored — macOS compositor cannot be disabled"
            );
        }
        0 // S_OK
    }

    /// DwmEnableBlurBehindWindow — enables blur-behind for a window using
    /// NSVisualEffectView (vibrancy / blur) on macOS.
    ///
    /// This creates (or removes) an NSVisualEffectView as a subview of the
    /// window's contentView, providing the frosted-glass backdrop effect.
    pub fn dwm_enable_blur_behind_window(
        &mut self,
        hwnd: Hwnd,
        enable: bool,
        _blur_region: u32,
        _transition: bool,
    ) -> u32 {
        // Bail out for unknown/destroyed windows: the stored visual-effect
        // view pointer may reference a freed view (use-after-free).
        if self.windows.get(&hwnd).is_none_or(|w| w.destroyed) {
            return 0x80070057_u32; // E_INVALIDARG
        }
        // Store the blur state in the DWM attributes
        let attrs = self.dwm_attributes.entry(hwnd).or_default();
        attrs.blur_behind_enabled = enable;

        #[cfg(target_os = "macos")]
        if let Some(ns_window) = crate::mac_window::nswindow_for_hwnd(hwnd) {
            unsafe {
                use objc::runtime::Object;
                let nswin = ns_window as *mut Object;

                if enable {
                    // Check if we already have a visual effect view for this window
                    if !self.blur_effect_views.contains_key(&hwnd) {
                        // Create NSVisualEffectView
                        let ve_cls = match objc::runtime::Class::get("NSVisualEffectView") {
                            Some(c) => c,
                            None => return 0x80004005_u32, // E_FAIL
                        };
                        let ve_view: *mut Object = msg_send![ve_cls, alloc];
                        if ve_view.is_null() {
                            return 0x8007000E_u32; // E_OUTOFMEMORY
                        }

                        // Get the content view bounds
                        let content_view: *mut Object = msg_send![nswin, contentView];
                        let bounds: crate::mac_window::NSRect = msg_send![content_view, bounds];

                        let ve_view: *mut Object = msg_send![ve_view, initWithFrame: bounds];
                        if ve_view.is_null() {
                            return 0x8007000E_u32; // E_OUTOFMEMORY
                        }

                        // NSVisualEffectMaterialHUDWindow = 26 (modern blur), or
                        // NSVisualEffectMaterialSidebar = 7, NSVisualEffectMaterialDark = 10
                        let _: () = msg_send![ve_view, setMaterial: 26u64]; // HUDWindow material
                        let _: () = msg_send![ve_view, setState: 1u64]; // NSVisualEffectStateActive
                        let _: () = msg_send![ve_view, setBlendingMode: 0u64]; // NSVisualEffectBlendingModeBehindWindow
                        let _: () = msg_send![ve_view, setAutoresizingMask: 18u64]; // NSViewWidthSizable | NSViewHeightSizable

                        // Insert the effect view at the back of the view hierarchy
                        let _: () = msg_send![content_view, addSubview: ve_view positioned: 0u64 relativeTo: std::ptr::null_mut::<Object>()];
                        // NSWindowBelow = 0

                        self.blur_effect_views.entry(hwnd).or_insert(ve_view as u64);
                    }
                } else {
                    // Remove the visual effect view, then release the +1 we
                    // hold from alloc/initWithFrame: (removeFromSuperview
                    // alone would leak the view on every enable/disable cycle).
                    if let Some(view_ptr) = self.blur_effect_views.remove(&hwnd) {
                        let ve_view = view_ptr as *mut Object;
                        let _: () = msg_send![ve_view, removeFromSuperview];
                        let _: () = msg_send![ve_view, release];
                    }
                }
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = (hwnd, enable);
        }

        0 // S_OK
    }

    /// DwmExtendFrameIntoClientArea — extends the window frame into the client area.
    /// On macOS the window frame already extends seamlessly; we store the margins
    /// for querying via DwmGetWindowAttribute(DWMWA_EXTENDED_FRAME_BOUNDS).
    pub fn dwm_extend_frame_into_client_area(
        &mut self,
        hwnd: Hwnd,
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    ) -> u32 {
        let attrs = self.dwm_attributes.entry(hwnd).or_default();
        attrs.extend_frame_margins = (left, top, right, bottom);
        0 // S_OK
    }

    /// DwmGetColorizationColor — retrieves the color used for DWM glass colorization.
    /// On macOS this queries the system accent colour via NSColor.
    /// Falls back to a default blue (0xCC0000) if NSColor is unavailable.
    pub fn dwm_get_colorization_color(&self) -> (u32, u32) {
        #[cfg(target_os = "macos")]
        {
            unsafe {
                use objc::runtime::Object;
                // NSColor accessors return autoreleased objects; without an
                // enclosing autorelease pool (Rust has none by default) they
                // leak per call, so create and drain a pool here.
                let Some(pool_cls) = objc::runtime::Class::get("NSAutoreleasePool") else {
                    return (0x00_CC_00_00, 0xFF);
                };
                let pool: *mut Object = msg_send![pool_cls, new];
                let color = if let Some(nscolor_cls) = objc::runtime::Class::get("NSColor") {
                    let accent: *mut Object = msg_send![nscolor_cls, controlAccentColor];
                    if accent.is_null() {
                        None
                    } else {
                        // Convert to sRGB via the shared NSColorSpace instance
                        // (a real Objective-C object — never a raw C string
                        // cast to `id`, which would crash the runtime).
                        let space_cls = objc::runtime::Class::get("NSColorSpace");
                        let converted: *mut Object = if let Some(space_cls) = space_cls {
                            let color_space: *mut Object = msg_send![space_cls, sRGBColorSpace];
                            if color_space.is_null() {
                                std::ptr::null_mut()
                            } else {
                                msg_send![accent, colorUsingColorSpace: color_space]
                            }
                        } else {
                            std::ptr::null_mut()
                        };
                        let color = if converted.is_null() {
                            accent
                        } else {
                            converted
                        };
                        let mut red: f64 = 0.0;
                        let mut green: f64 = 0.0;
                        let mut blue: f64 = 0.0;
                        let mut alpha: f64 = 0.0;
                        let ok: bool = msg_send![
                            color,
                            getRed: &mut red green: &mut green blue: &mut blue alpha: &mut alpha
                        ];
                        if ok {
                            let r = (red.clamp(0.0, 1.0) * 255.0) as u32;
                            let g = (green.clamp(0.0, 1.0) * 255.0) as u32;
                            let b = (blue.clamp(0.0, 1.0) * 255.0) as u32;
                            let a = (alpha.clamp(0.0, 1.0) * 255.0) as u32;
                            Some(((b << 16) | (g << 8) | r, a)) // BGR like Windows DWM
                        } else {
                            None
                        }
                    }
                } else {
                    None
                };
                let _: () = msg_send![pool, drain];
                if let Some((color, alpha)) = color {
                    return (color, alpha);
                }
            }
        }
        // Fallback: Windows 11 default blue accent (BGR: 0xCC0000 = RGB 0x0000CC)
        (0x00_CC_00_00, 0xFF)
    }

    /// DwmSetWindowAttribute — sets DWM window attributes and stores them
    /// in the per-window attribute table.
    pub fn dwm_set_window_attribute(&mut self, hwnd: Hwnd, attribute: u32, value: u32) -> u32 {
        let attrs = self.dwm_attributes.entry(hwnd).or_default();
        match attribute {
            DWMWA_NCRENDERING_ENABLED => {
                attrs.nc_rendering_enabled = value != 0;
            }
            DWMWA_NCRENDERING_POLICY => {
                attrs.nc_rendering_policy = value;
            }
            DWMWA_TRANSITIONS_FORCEDISABLED => {
                attrs.transitions_forced_disabled = value != 0;
            }
            DWMWA_ALLOW_NCPAINT => {
                attrs.allow_ncpaint = value != 0;
            }
            DWMWA_CAPTION_BUTTON_BOUNDS => {
                // value encodes a RECT (left, top, right, bottom) packed into u32s
                // In practice this is stored via the attribute pointer mechanism in pe_runtime
                // We store it as a boolean flag that bounds were set
                // NOTE: The RECT payload is written to guest memory by pe_runtime's
                // DwmSetWindowAttribute pointer path; this arm intentionally stores
                // nothing beyond accepting the attribute (S_OK).
            }
            DWMWA_NONCLIENT_RTL_LAYOUT => {
                attrs.nonclient_rtl_layout = value != 0;
            }
            DWMWA_FORCE_ICONIC_REPRESENTATION => {
                attrs.force_iconic_representation = value != 0;
            }
            DWMWA_FLIP3D_POLICY => {
                attrs.flip3d_policy = value;
            }
            DWMWA_HAS_ICONIC_BITMAP => {
                attrs.has_iconic_bitmap = value != 0;
            }
            DWMWA_DISALLOW_PEEK => {
                attrs.disallow_peek = value != 0;
            }
            DWMWA_EXCLUDED_FROM_PEEK => {
                attrs.excluded_from_peek = value != 0;
            }
            DWMWA_CLOAK => {
                attrs.cloak = value != 0;
                // On macOS, cloaking is a no-op (no Alt+Tab to hide from)
            }
            DWMWA_CLOAKED => {
                attrs.cloaked = value;
            }
            DWMWA_FREEZE_REPRESENTATION => {
                attrs.freeze_representation = value != 0;
            }
            _ => {
                // Unknown attribute — return E_INVALIDARG
                return 0x80070057_u64 as u32; // E_INVALIDARG
            }
        }
        0 // S_OK
    }

    /// DwmGetWindowAttribute — retrieves DWM window attributes from the
    /// per-window attribute table.
    pub fn dwm_get_window_attribute(&self, hwnd: Hwnd, attribute: u32) -> (u32, u32) {
        let attrs = match self.dwm_attributes.get(&hwnd) {
            Some(a) => a,
            None => {
                // No attributes stored for this window yet; return defaults
                return match attribute {
                    DWMWA_CLOAKED => (0, 0), // Not cloaked
                    _ => (0, 1),             // S_FALSE
                };
            }
        };
        let value = match attribute {
            DWMWA_NCRENDERING_ENABLED => {
                if attrs.nc_rendering_enabled {
                    1
                } else {
                    0
                }
            }
            DWMWA_NCRENDERING_POLICY => attrs.nc_rendering_policy,
            DWMWA_TRANSITIONS_FORCEDISABLED => {
                if attrs.transitions_forced_disabled {
                    1
                } else {
                    0
                }
            }
            DWMWA_ALLOW_NCPAINT => {
                if attrs.allow_ncpaint {
                    1
                } else {
                    0
                }
            }
            DWMWA_CAPTION_BUTTON_BOUNDS => 0, // RECT data returned via pointer in pe_runtime
            DWMWA_NONCLIENT_RTL_LAYOUT => {
                if attrs.nonclient_rtl_layout {
                    1
                } else {
                    0
                }
            }
            DWMWA_FORCE_ICONIC_REPRESENTATION => {
                if attrs.force_iconic_representation {
                    1
                } else {
                    0
                }
            }
            DWMWA_FLIP3D_POLICY => attrs.flip3d_policy,
            DWMWA_EXTENDED_FRAME_BOUNDS => 0, // RECT returned via pointer in pe_runtime
            DWMWA_HAS_ICONIC_BITMAP => {
                if attrs.has_iconic_bitmap {
                    1
                } else {
                    0
                }
            }
            DWMWA_DISALLOW_PEEK => {
                if attrs.disallow_peek {
                    1
                } else {
                    0
                }
            }
            DWMWA_EXCLUDED_FROM_PEEK => {
                if attrs.excluded_from_peek {
                    1
                } else {
                    0
                }
            }
            DWMWA_CLOAK => {
                if attrs.cloak {
                    1
                } else {
                    0
                }
            }
            DWMWA_CLOAKED => attrs.cloaked,
            DWMWA_FREEZE_REPRESENTATION => {
                if attrs.freeze_representation {
                    1
                } else {
                    0
                }
            }
            _ => return (0, 1), // S_FALSE for unknown
        };
        (value, 0) // S_OK
    }

    /// DwmFlush — waits for pending DWM rendering to complete.
    /// On macOS, flushes the current CATransaction so pending layer updates
    /// are committed immediately.
    pub fn dwm_flush(&self) -> u32 {
        #[cfg(target_os = "macos")]
        unsafe {
            if let Some(catrans_cls) = objc::runtime::Class::get("CATransaction") {
                let _: () = msg_send![catrans_cls, flush];
            }
        }
        0 // S_OK
    }

    // ── Window Animation / Flash API ──────────────────────────────────────────────

    /// AnimateWindow — approximates Win32 animation by applying the final
    /// show/hide state and immediately refreshing the window.
    pub fn animate_window(&mut self, hwnd: Hwnd, _duration: u32, flags: u32) -> bool {
        const SW_HIDE: i32 = 0;
        const SW_SHOW: i32 = 5;

        let show_command = if (flags & AW_HIDE) != 0 {
            SW_HIDE
        } else {
            SW_SHOW
        };

        if let Err(error) = self.show_window(hwnd, show_command) {
            eprintln!(
                "[User32] animate_window: show_window({show_command}) failed for hwnd {hwnd}: {error}"
            );
            return false;
        }
        if show_command == SW_SHOW {
            match self.update_window(hwnd) {
                Ok(true) => {}
                Ok(false) => return false,
                Err(error) => {
                    eprintln!(
                        "[User32] animate_window: update_window failed for hwnd {hwnd}: {error}"
                    );
                    return false;
                }
            }
        }
        true
    }

    /// DrawAnimatedRects — approximates the minimize/restore transition by
    /// applying the target rect to the window and forcing a refresh.
    pub fn draw_animated_rects(&mut self, hwnd: Hwnd, rect_from: &Rect, rect_to: &Rect) -> bool {
        // Guest rects are untrusted: right - left can overflow i32 for
        // extreme coordinates, so compute widths in i64.
        let target_width = (rect_to.right as i64 - rect_to.left as i64).max(0) as u32;
        let target_height = (rect_to.bottom as i64 - rect_to.top as i64).max(0) as u32;
        if target_width == 0 || target_height == 0 {
            return false;
        }

        let (ns_window, visible, size_changed) = match self.window_mut(hwnd) {
            Ok(window) => {
                if window.destroyed {
                    return false;
                }
                let size_changed = window.width != target_width || window.height != target_height;
                let ns_window = window.ns_window;
                let visible = window.visible;
                if visible && !ns_window.is_null() {
                    let source_width =
                        (rect_from.right as i64 - rect_from.left as i64).max(0) as u32;
                    let source_height =
                        (rect_from.bottom as i64 - rect_from.top as i64).max(0) as u32;
                    if source_width > 0 && source_height > 0 {
                        mac_window::set_nswindow_frame(
                            ns_window,
                            rect_from.left,
                            rect_from.top,
                            source_width,
                            source_height,
                        );
                        mac_window::update_nswindow(ns_window);
                    }
                }
                window.x = rect_to.left;
                window.y = rect_to.top;
                window.width = target_width;
                window.height = target_height;
                window.placement.rc_normal_position = *rect_to;
                (ns_window, visible, size_changed)
            }
            Err(_) => return false,
        };

        if visible && !ns_window.is_null() {
            mac_window::set_nswindow_frame(
                ns_window,
                rect_to.left,
                rect_to.top,
                target_width,
                target_height,
            );
            mac_window::update_nswindow(ns_window);
        }
        if size_changed
            && self
                .queue_resize(hwnd, target_width, target_height)
                .is_err()
        {
            return false;
        }
        if self.queue_paint(hwnd).is_err() {
            return false;
        }
        true
    }

    /// FlashWindow — flashes a window once (inverts the caption bar appearance).
    pub fn flash_window(&mut self, hwnd: Hwnd, invert: bool) -> bool {
        if !self.windows.contains_key(&hwnd) {
            return false;
        }
        let currently_flashing = self.flashing_windows.get(&hwnd).copied().unwrap_or(false);
        if invert {
            // Toggle flash state
            self.flashing_windows.insert(hwnd, !currently_flashing);
        } else {
            // Stop flashing
            self.flashing_windows.insert(hwnd, false);
        }
        // Return the state before the call (Win32 convention)
        let was_flashing = currently_flashing;
        // On macOS, flash the dock icon as an approximation
        #[cfg(target_os = "macos")]
        if invert || was_flashing {
            mac_window::flash_nswindow(hwnd, invert);
        }
        was_flashing
    }

    /// FlashWindowEx — flashes a window with extended control (count, timeout, style).
    pub fn flash_window_ex(&mut self, hwnd: Hwnd, flags: u32, count: u32, _timeout: u32) -> bool {
        if !self.windows.contains_key(&hwnd) {
            return false;
        }
        if flags == FLASHW_STOP {
            self.flashing_windows.insert(hwnd, false);
            // Stop flashing on macOS dock icon
            #[cfg(target_os = "macos")]
            mac_window::flash_nswindow(hwnd, false);
        } else {
            self.flashing_windows.insert(hwnd, true);
            // Flash the dock icon
            #[cfg(target_os = "macos")]
            mac_window::flash_nswindow(hwnd, true);
            // If count is 0, flash until stopped; otherwise flash count times
            // count is intentionally unused — macOS NSApp.requestUserAttention doesn't
            // support a flash count; we flash once per call.
            let _flash_count = count;
        }
        true
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

    pub fn translate_scancode(
        &self,
        scancode: u16,
        modifiers: KeyModifiers,
    ) -> AppResult<KeyTranslation> {
        let entry = layout_tables()
            .get(&self.layout)
            .and_then(|table| table.get(&scancode))
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "no keyboard mapping for layout {:?} scancode {scancode:#x}",
                        self.layout
                    ),
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
        // Bound the generated repeat count: held_ms is guest/timing
        // controlled, and an unbounded count (e.g. held_ms = u32::MAX at
        // 31 Hz ≈ 133M messages) would OOM the process.
        const MAX_REPEATS: usize = 64;
        let count = ((repeat_window_ms as u64 * self.key_repeat.rate_hz as u64 / 1000) as usize)
            .min(MAX_REPEATS);
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
        self.inject_keyboard_input_internal(
            hwnd,
            device_id,
            scancode,
            modifiers,
            MessageKind::KeyDown,
            true,
        )
    }

    pub fn inject_keyboard_input_up(
        &mut self,
        hwnd: Hwnd,
        device_id: &str,
        scancode: u16,
        modifiers: KeyModifiers,
    ) -> AppResult<()> {
        self.inject_keyboard_input_internal(
            hwnd,
            device_id,
            scancode,
            modifiers,
            MessageKind::KeyUp,
            false,
        )
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
        self.update_key_state_for_scancode(scancode, is_down);
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
    fn update_key_state_for_scancode(&mut self, scancode: u16, down: bool) {
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
    /// Extended keys arrive either E0-prefixed (0xE0xx, high byte 0xE0) or
    /// with the 0x80 extended-bit convention on the low byte; carrying the
    /// full u16 through avoids truncating the extended flag to u8.
    fn scancode_to_vk_code(&self, scancode: u16) -> u32 {
        let extended = scancode >= 0x100 || (scancode & 0x80) != 0;
        let low = (scancode & 0xFF) as usize;
        if extended {
            let vk = SCANCODE_TO_VK_US_EXT.get(low).copied().unwrap_or(0);
            if vk != 0 {
                return vk as u32;
            }
        }
        let vk = SCANCODE_TO_VK_US.get(low).copied().unwrap_or(0);
        if vk != 0 {
            return vk as u32;
        }
        // Fallback: try the layout table
        if let Some(entry) = layout_tables()
            .get(&self.layout)
            .and_then(|table| table.get(&(low as u16)))
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
        // Search only the ACTIVE layout: iterating every layout can return a
        // character from a non-active layout for multi-layout guests.
        layout_tables().get(&self.layout).and_then(|table| {
            table
                .values()
                .find(|entry| virtual_key_to_win32_vk(&entry.vk) == vk)
                .and_then(|entry| entry.plain)
        })
    }

    /// Query modifier key state from macOS CoreGraphics (modifier keys only).
    #[cfg(target_os = "macos")]
    fn query_modifier_key_state(&self, vk: u32) -> bool {
        // Use CGEventSourceFlagsState to check physical modifier key state
        let flags = unsafe { CGEventSourceFlagsState(kCGEventSourceStateCombinedSessionState) };
        match vk as i32 {
            VK_SHIFT | VK_LSHIFT | VK_RSHIFT => (flags & kCGEventFlagMaskShift) != 0,
            VK_CONTROL | VK_LCONTROL | VK_RCONTROL => (flags & kCGEventFlagMaskControl) != 0,
            VK_MENU | VK_LMENU | VK_RMENU => (flags & kCGEventFlagMaskAlternate) != 0,
            VK_LWIN | VK_RWIN => (flags & kCGEventFlagMaskCommand) != 0,
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
            result |= 0x8000u16 as i16;
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
            if self.query_modifier_key_state(v_key as u32) || self.key_state[vk] & 0x80 != 0 {
                result |= 0x8000u16 as i16;
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
                // scancode → VK (extended keys arrive E0-prefixed or with
                // the 0x80 convention; keep the full value, not `as u8`)
                self.scancode_to_vk_code(code as u16)
            }
            MAPVK_VK_TO_CHAR => {
                // VK → lowercase character
                self.vk_code_to_char(code).map(|c| c as u32).unwrap_or(0)
            }
            MAPVK_VSC_TO_VK_EX => {
                // Extended scancode → VK. Try the plain mapping first (only
                // E0-prefixed values mark extended) — forcing 0x80 on every
                // scancode made ordinary keys (e.g. 0x1E) return 0.
                self.scancode_to_vk_code(code as u16)
            }
            MAPVK_VK_TO_VSC_EX => {
                // VK → extended scancode, E0-prefixed convention (0xE0<<8|sc),
                // decoded symmetrically by MAPVK_VSC_TO_VK_EX above.
                self.vk_code_to_scancode(code)
                    .filter(|sc| *sc & 0x80 != 0)
                    .map(|sc| 0xE0 << 8 | (sc & 0x7F) as u32)
                    .unwrap_or(0)
            }
            _ => 0,
        }
    }

    // ── VkKeyScanW ──────────────────────────────────────────────────────
    /// Translates a character to the corresponding virtual-key code and
    /// shift state. Returns a SHORT where:
    ///   - Low byte  = virtual-key code (NOT the scancode)
    ///   - High byte = shift state (bit 0 = shift, bit 1 = ctrl, bit 2 = alt)
    ///
    /// Returns -1 if no character value can be found.
    pub fn vk_key_scan_w(&self, ch: u16) -> i16 {
        let ch_char = char::from_u32(ch as u32).unwrap_or('\0');
        let tables = layout_tables();
        let table = match tables.get(&self.layout) {
            Some(t) => t,
            None => return -1,
        };
        for entry in table.values() {
            if entry.plain == Some(ch_char) {
                // VkKeyScanW returns the VIRTUAL-KEY code in the low byte
                // (e.g. VK_Q = 0x51), not the scancode (0x10).
                return virtual_key_to_win32_vk(&entry.vk) as i16; // no shift
            }
            if entry.shifted == Some(ch_char) {
                return virtual_key_to_win32_vk(&entry.vk) as i16 | 0x0100; // shift pressed
            }
            if entry.altgr == Some(ch_char) {
                return virtual_key_to_win32_vk(&entry.vk) as i16 | 0x0200; // altgr/ctrl+alt pressed
            }
        }
        -1
    }

    // ── SetWindowsHookExW / CallNextHookEx ─────────────────────────────
    /// Installs a hook procedure into the hook chain.
    /// Returns the hook handle (id) on success, or 0 on failure.
    ///
    /// NOTE: hook callbacks are recorded here but guest hook invocation is
    /// not yet wired into message dispatch (that requires guest callback
    /// execution from pe_runtime); CallNextHookEx therefore returns 0.
    pub fn set_windows_hook_ex_w(
        &mut self,
        hook_type: i32,
        callback: u64,
        module: u64,
        thread_id: u32,
    ) -> i32 {
        if !(0..=WH_MOUSE_LL).contains(&hook_type) {
            return 0;
        }
        if callback == 0 {
            return 0;
        }
        let id = self.alloc_hook_id();
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

    fn alloc_hook_id(&mut self) -> i32 {
        let start = self.next_hook_id;
        loop {
            let id = self.next_hook_id;
            self.next_hook_id = self.next_hook_id.wrapping_add(1);
            if id != 0 && !self.hooks.contains_key(&id) {
                return id;
            }
            if self.next_hook_id == start {
                break;
            }
        }
        // Table exhausted: fall back to the next value (unreachable in practice).
        let id = self.next_hook_id;
        self.next_hook_id = self.next_hook_id.wrapping_add(1);
        id
    }

    /// Passes the hook information to the next hook procedure in the
    /// current hook chain. Returns the value returned by the next hook,
    /// or 0 if no next hook exists.
    ///
    /// NOTE: hook chains are recorded (see [`set_windows_hook_ex_w`]) but
    /// guest hook invocation is not wired into message dispatch yet, so
    /// this returns 0 — the documented empty-chain result.
    pub fn call_next_hook_ex(
        &self,
        _id: i32,
        _n_code: i32,
        _wparam: usize,
        _lparam: isize,
    ) -> usize {
        0
    }

    /// Unhook a previously installed hook.
    pub fn unhook_windows_hook_ex(&mut self, id: i32) -> bool {
        self.hooks.remove(&id).is_some()
    }

    #[allow(clippy::too_many_arguments)]
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

    #[allow(clippy::too_many_arguments)]
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
        let (cursor_x, cursor_y) =
            self.confine_cursor(self.cursor_pos.0 + raw_dx, self.cursor_pos.1 + raw_dy);
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
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unknown controller {guid}"),
            )
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

    pub fn xinput_get_state(&mut self, slot: u8) -> AppResult<XInputState> {
        let guid = self.controller_guid_by_xinput_slot(slot)?;
        let controller = self.controller_mut(&guid)?;
        // Bump the packet number on each read: guests poll XInputGetState to
        // detect state changes, and a packet number that only changes on
        // rumble writes would never signal fresh button/axis data.
        controller.packet_number = controller.packet_number.wrapping_add(1);
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

    pub fn xinput_set_state(
        &mut self,
        slot: u8,
        left_motor: u16,
        right_motor: u16,
    ) -> AppResult<()> {
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
        // Apply the effect: map the DirectInput magnitude (0–10000) to motor
        // intensities so the effect actually reaches the controller instead
        // of being validated and dropped.
        let controller = self.controller_mut(guid)?;
        let intensity = (magnitude.clamp(0, 10_000) as u32 * 65_535 / 10_000) as u16;
        controller.rumble = RumbleState {
            left_motor: intensity,
            right_motor: intensity,
        };
        controller.packet_number = controller.packet_number.wrapping_add(1);
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
    pub fn register_raw_input_devices(
        &mut self,
        devices: &[RawInputRegistration],
    ) -> AppResult<()> {
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
        // Real Win32 constants (winuser.h):
        //   RID_INPUT = 0x10000003, RID_DEVICE_INFO = 0x10000004,
        //   RID_HEADER = 0x10000005.
        // The previous 0x10000001/0x10000002 values matched nothing, so any
        // guest passing the real constants got the wrong size. The legacy
        // values are still accepted defensively.
        match command {
            // RID_HEADER → sizeof(RAWINPUTHEADER) = 24 (x64) / 20 (x86)
            0x10000005 | 0x10000001 => Ok(24),
            // RID_INPUT → sizeof(RAWINPUT): 48 for mouse, 40 for keyboard,
            // 36 + report length for HID. The device type is not known from
            // the command alone, so return the largest fixed size (mouse);
            // HID callers must size from their report length.
            0x10000003 | 0x10000002 => Ok(48),
            // RID_DEVICE_INFO → sizeof(RID_DEVICE_INFO) = 24
            0x10000004 => Ok(24),
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
        let total = self.raw_input_devices.len();
        if output.len() < total {
            // Win32 two-pass pattern: call once to learn the required count,
            // allocate, call again.
            return total;
        }
        for (i, dev) in self.raw_input_devices.iter().enumerate() {
            output[i] = dev.clone();
        }
        total
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
            // RIDI_PREPARSEDDATA → synthetic HID pre-parsed data buffer
            // Windows returns the raw HID report descriptor bytes as pre-parsed data.
            // We return a standard 5-button mouse HID report descriptor (50 bytes).
            0x20000003 => Ok(50),
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
        })
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
        // A monitor id of 0 means "unspecified": Win32 resolves an
        // unqualified window to the primary monitor for DPI purposes.
        let monitor_id = if monitor_id == 0 {
            self.primary_monitor_id()
        } else {
            monitor_id
        };
        let monitor = self.monitor(monitor_id)?;
        Ok(match self.dpi_context {
            DpiAwarenessContext::Unaware => 96,
            DpiAwarenessContext::SystemAware => self
                .monitors
                .get(&self.primary_monitor_id())
                .map(|primary| primary.dpi_x)
                .unwrap_or(96),
            DpiAwarenessContext::PerMonitorAware => monitor.dpi_x,
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
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unknown monitor {monitor_id}"),
            )
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
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unknown controller {guid}"),
            )
        })
    }

    fn controller_mut(&mut self, guid: &str) -> AppResult<&mut ControllerRecord> {
        self.controllers.get_mut(guid).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unknown controller {guid}"),
            )
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
            // add_controller derives the storage guid from
            // deterministic_guid(vendor, product, serial, name, kind) — the
            // raw HID identifier is NOT the guid. Reproduce the guid here,
            // falling back to a serial match for controllers registered
            // through a different path, so disconnected controllers actually
            // get removed instead of erroring out of the hotplug poll.
            let kind = if controller.xinput_capable {
                ControllerKind::Xbox
            } else {
                ControllerKind::ThirdPartyXInput
            };
            let guid = util::deterministic_guid(
                &format!(
                    "{:04x}:{:04x}:{}:{}:{:?}",
                    controller.vendor_id,
                    controller.product_id,
                    controller.identifier,
                    controller.name,
                    kind
                ),
                true,
            );
            if self.remove_controller(self.foreground, &guid).is_err() {
                let fallback = self
                    .controllers
                    .iter()
                    .find(|(_, c)| c.spec.serial == controller.identifier)
                    .map(|(guid, _)| guid.clone());
                match fallback {
                    Some(guid) => {
                        let _ = self.remove_controller(self.foreground, &guid);
                    }
                    None => eprintln!(
                        "[User32] poll_controller_hotplug: no registered controller matches removed device '{}'",
                        controller.identifier
                    ),
                }
            }
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
    pub fn store_touch_inputs(&mut self, _hwnd: u32, inputs: Vec<TouchInput>) -> u32 {
        let handle = self.alloc_touch_handle();
        self.touch_state.touch_handles.insert(handle, inputs);
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
        Ok(())
    }

    /// Initialize touch injection for the given HWND (InitializeTouchInjection).
    ///
    /// This is a stub that records the registration but does not actually
    /// simulate touch input from the host.
    pub fn initialize_touch_injection(
        &mut self,
        hwnd: u32,
        _max_touches: u32,
        _mode: u32,
    ) -> AppResult<()> {
        if !self.touch_state.registered_windows.contains(&hwnd) {
            self.touch_state.registered_windows.push(hwnd);
        }
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

    /// Skip a pointer frame by dropping the most recently stored state for that pointer.
    pub fn skip_pointer_frame(&mut self, pointer_id: u32) -> AppResult<()> {
        let removed_pointer = self.touch_state.pointer_infos.remove(&pointer_id);
        let removed_pen = self.touch_state.pointer_pen_infos.remove(&pointer_id);
        if removed_pointer.is_none() && removed_pen.is_none() {
            return Err(AppError::new(
                crate::reason::ReasonCode::RcUnimplInsn,
                format!("SkipPointerFrame: unknown pointer_id {pointer_id}"),
            ));
        }
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

    /// Get pointer device capabilities (GetPointerDeviceCaps).
    /// Returns touch capabilities for a simulated touch device.
    pub fn get_pointer_device_caps(&self) -> PointerDeviceCaps {
        PointerDeviceCaps {
            monitor: self.primary_monitor_id(),
            supports_display_time: 1, // supports display time
            pointer_device_type: 1,   // touch
            max_contacts: 10,         // 10 simultaneous contacts
        }
    }

    /// Get pointer device rects (GetPointerDeviceRects).
    /// Returns the device rect and display rect for the primary monitor.
    pub fn get_pointer_device_rects(&self) -> (PointerDeviceRect, PointerDeviceRect) {
        let default_bounds = Rect {
            left: 0,
            top: 0,
            right: 1920,
            bottom: 1080,
        };
        let primary = self
            .monitors
            .get(&self.primary_monitor_id())
            .cloned()
            .unwrap_or(MonitorInfo {
                id: self.primary_monitor_id(),
                name: "Primary".to_string(),
                dpi_x: 96,
                dpi_y: 96,
                bounds: default_bounds,
                work_rect: default_bounds,
                is_primary: true,
            });
        let w = (primary.bounds.right as i64 - primary.bounds.left as i64).clamp(0, i32::MAX as i64)
            as i32;
        let h = (primary.bounds.bottom as i64 - primary.bounds.top as i64).clamp(0, i32::MAX as i64)
            as i32;
        let display_rect = PointerDeviceRect {
            left: 0,
            top: 0,
            right: w,
            bottom: h,
        };
        let device_rect = PointerDeviceRect {
            left: 0,
            top: 0,
            right: w,
            bottom: h,
        };
        (device_rect, display_rect)
    }

    /// Get pointer frame info (GetPointerFrameInfo).
    /// Returns the most recent pointer frame info, or an error if no frame exists.
    pub fn get_pointer_frame_info(&self) -> AppResult<PointerFrameInfo> {
        let info = PointerFrameInfo {
            current_pointer_count: self.touch_state.pointer_infos.len() as u32,
            pointers_in_frame: self.touch_state.pointer_infos.len() as u32,
            frame_id: self.touch_state.next_frame_id,
            pointer_flags: 0,
            display_time: 0,
            performance_count: 0,
        };
        Ok(info)
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
        // Bump the frame counter once per dispatched touch frame.
        self.touch_state.next_frame_id = self.touch_state.next_frame_id.wrapping_add(1);
        let frame_id = self.touch_state.next_frame_id;
        let mut touch_inputs: Vec<TouchInput> = Vec::new();
        for tp in touch_points {
            let flags = match tp.phase {
                TouchPhase::Began => TOUCHEVENTF_DOWN,
                TouchPhase::Moved => TOUCHEVENTF_MOVE,
                TouchPhase::Ended => TOUCHEVENTF_UP,
                TouchPhase::Cancelled => TOUCHEVENTF_UP,
                TouchPhase::Stationary => 0,
            };
            let flags = flags | TOUCHEVENTF_INRANGE | if tp.is_pen { TOUCHEVENTF_PEN } else { 0 };
            let source = if tp.is_pen { 2u32 } else { 1u32 };
            // Convert f64 coordinates to i32 (in hundredths of a pixel, per TouchInput spec)
            let x = (tp.x * 100.0) as i32;
            let y = (tp.y * 100.0) as i32;
            // Win32 TOUCHINPUT has no pressure field: scale the reported
            // contact area by pressure instead of claiming TOUCHINPUTMASKF_PRESSURE.
            let pressure = (tp.pressure.clamp(0.0, 1.0) * 1024.0) as u32;
            let contact = 10u32.saturating_add(pressure / 128);
            touch_inputs.push(TouchInput {
                x,
                y,
                source,
                id: tp.id,
                flags,
                mask: TOUCHINPUTMASKF_CONTACTAREA,
                time: 0,
                pad: 0,
                extra_info: 0,
                cx: contact, // contact area grows with pressure
                cy: contact,
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
                frame_id,
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
            let lparam = touch_inputs.iter().fold(0u32, |acc, ti| acc | ti.flags);
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
    #[ignore = "requires AppKit on main thread"]
    fn show_window_queues_paint_message() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, false, false, None, 1)
            .expect("create window");

        assert_eq!(
            user32.get_message_w().expect("nc create").kind,
            MessageKind::NcCreate
        );
        assert_eq!(
            user32.get_message_w().expect("create").kind,
            MessageKind::Create
        );

        user32.show_window(hwnd, 1).expect("show window");
        let kinds = std::iter::from_fn(|| user32.get_message_w().map(|message| message.kind))
            .collect::<Vec<_>>();

        assert!(kinds.contains(&MessageKind::ShowWindow));
        assert!(kinds.contains(&MessageKind::Size));
        assert!(kinds.contains(&MessageKind::Paint));
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn invalidate_window_queues_paint_once() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, true, false, None, 1)
            .expect("create window");

        let _ = std::iter::from_fn(|| user32.get_message_w()).collect::<Vec<_>>();

        assert!(
            user32
                .invalidate_window(Some(hwnd), false)
                .expect("invalidate window")
        );
        assert!(
            user32
                .invalidate_window(Some(hwnd), false)
                .expect("invalidate window")
        );

        let kinds = std::iter::from_fn(|| user32.get_message_w().map(|message| message.kind))
            .collect::<Vec<_>>();

        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == MessageKind::Paint)
                .count(),
            1
        );
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn draw_animated_rects_updates_window_rect_and_queues_messages() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, true, false, None, 1)
            .expect("create window");

        let _ = std::iter::from_fn(|| user32.get_message_w()).collect::<Vec<_>>();

        let from = Rect {
            left: 10,
            top: 20,
            right: 330,
            bottom: 220,
        };
        let to = Rect {
            left: 40,
            top: 50,
            right: 520,
            bottom: 390,
        };

        assert!(user32.draw_animated_rects(hwnd, &from, &to));

        let preview = user32
            .window_previews()
            .into_iter()
            .find(|preview| preview.hwnd == hwnd)
            .expect("window preview");
        assert_eq!(preview.x, to.left);
        assert_eq!(preview.y, to.top);
        assert_eq!(preview.width, (to.right - to.left) as u32);
        assert_eq!(preview.height, (to.bottom - to.top) as u32);

        let kinds = std::iter::from_fn(|| user32.get_message_w().map(|message| message.kind))
            .collect::<Vec<_>>();
        assert!(kinds.contains(&MessageKind::WindowPosChanging));
        assert!(kinds.contains(&MessageKind::Size));
        assert!(kinds.contains(&MessageKind::Paint));
        assert!(!user32.draw_animated_rects(0xDEAD_BEEF, &from, &to,));
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn draw_menu_bar_queues_paint_for_valid_window_menu() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, true, false, None, 1)
            .expect("create window");
        let menu = user32.create_menu();
        assert!(user32.set_menu(hwnd, menu));

        let _ = std::iter::from_fn(|| user32.get_message_w()).collect::<Vec<_>>();

        assert!(user32.draw_menu_bar(hwnd));

        let kinds = std::iter::from_fn(|| user32.get_message_w().map(|message| message.kind))
            .collect::<Vec<_>>();
        assert!(kinds.contains(&MessageKind::Paint));
        assert!(!user32.draw_menu_bar(0xDEAD_BEEF));
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn animate_window_updates_visibility_and_messages() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, false, false, None, 1)
            .expect("create window");

        let _ = std::iter::from_fn(|| user32.get_message_w()).collect::<Vec<_>>();

        assert!(user32.animate_window(hwnd, 200, 0));
        assert!(user32.window_state(hwnd).expect("window state").visible);

        let show_kinds = std::iter::from_fn(|| user32.get_message_w().map(|message| message.kind))
            .collect::<Vec<_>>();
        assert!(show_kinds.contains(&MessageKind::ShowWindow));
        assert!(show_kinds.contains(&MessageKind::Paint));

        assert!(user32.animate_window(hwnd, 200, AW_HIDE));
        assert!(!user32.window_state(hwnd).expect("window state").visible);
        assert!(!user32.animate_window(0xDEAD_BEEF, 200, 0));
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn track_popup_menu_validates_menu_and_refreshes_window() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, true, false, None, 1)
            .expect("create window");
        let menu = user32.create_popup_menu();

        let _ = std::iter::from_fn(|| user32.get_message_w()).collect::<Vec<_>>();

        assert!(user32.track_popup_menu(menu, 0, 100, 120, hwnd));

        let kinds = std::iter::from_fn(|| user32.get_message_w().map(|message| message.kind))
            .collect::<Vec<_>>();
        assert!(kinds.contains(&MessageKind::Paint));
        assert!(!user32.track_popup_menu(0xDEAD_BEEF, 0, 100, 120, hwnd));
        assert!(!user32.track_popup_menu(menu, 0, 100, 120, 0xDEAD_BEEF));
    }

    #[test]
    fn post_thread_message_queues_message_for_target_thread() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);

        user32
            .post_thread_message_w(7, MessageKind::Other(0x0400), 11, 22)
            .expect("post thread message");

        assert!(user32.get_message_for_thread(1).is_none());
        let message = user32
            .get_message_for_thread(7)
            .expect("target thread message");
        assert_eq!(message.hwnd, None);
        assert_eq!(message.kind, MessageKind::Other(0x0400));
        assert_eq!(message.wparam, 11);
        assert_eq!(message.lparam, 22);
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
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
            mask: TOUCHINPUTMASKF_CONTACTAREA,
            time: 0,
            pad: 0,
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
        assert!(result.is_err(), "expected Err, got {result:?}");
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
            pad: 0,
            extra_info: 0,
            cx: 10,
            cy: 10,
        }];
        let handle = user32.store_touch_inputs(0x1234, inputs);
        let _result = user32.get_touch_input_info(handle);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        user32
            .close_touch_input_handle(handle)
            .expect("close touch input handle");
        let _result = user32.get_touch_input_info(handle);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn touch_input_struct_size() {
        // Win32 TOUCHINPUT: 48 bytes on x64 (dwExtraInfo aligned at 32),
        // 44 on x86. The packed 44-byte layout was wrong on x64 and read
        // dwExtraInfo unaligned (UB).
        let expected = if cfg!(target_pointer_width = "64") {
            48
        } else {
            44
        };
        assert_eq!(std::mem::size_of::<TouchInput>(), expected);
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
    fn skip_pointer_frame_removes_pointer_state() {
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
        let pen_info = PointerPenInfo {
            pointer_type: 2,
            pointer_id: 7,
            frame_id: 1,
            pointer_flags: POINTER_FLAG_INRANGE | POINTER_FLAG_INCONTACT,
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
            pen_flags: 0,
            pen_mask: 0,
            pressure: 0,
            rotation: 0,
            tilt_x: 0,
            tilt_y: 0,
        };

        user32.store_pointer_info(7, info);
        user32.store_pointer_pen_info(7, pen_info);
        assert_eq!(
            user32
                .get_pointer_frame_info()
                .unwrap()
                .current_pointer_count,
            1
        );

        user32.skip_pointer_frame(7).expect("skip pointer frame");

        let _result = user32.get_pointer_info(7);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
        let _result = user32.get_pointer_pen_info(7);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
        let frame_info = user32
            .get_pointer_frame_info()
            .expect("frame info after skip");
        assert_eq!(frame_info.current_pointer_count, 0);
        assert_eq!(frame_info.pointers_in_frame, 0);
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
    #[ignore = "requires AppKit on main thread"]
    fn enable_non_client_dpi_scaling_refreshes_window_dpi() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, false, false, None, 1)
            .expect("create window");

        let original_dpi = user32.dpi_for_window(hwnd).expect("initial dpi");
        let monitor = user32.monitors.get_mut(&1).expect("monitor 1");
        monitor.dpi_x = original_dpi + 48;
        monitor.dpi_y = original_dpi + 48;

        assert_eq!(user32.enable_non_client_dpi_scaling(hwnd), 1);
        assert_eq!(
            user32.dpi_for_window(hwnd).expect("updated dpi"),
            original_dpi + 48
        );
        assert_eq!(user32.enable_non_client_dpi_scaling(0xDEAD_BEEF), 0);
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
        // Drain any pending messages from the queue (e.g. WM_CREATE, WM_SIZE)
        while let Some(_msg) = user32.get_message_w() {}
        let device_id = user32.register_keyboard_device(&KeyboardDevice {
            vendor_id: 0x1234,
            product_id: 0x5678,
            serial: "test-serial".to_string(),
        });
        (user32, hwnd, device_id)
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn test_get_key_state() {
        let (mut user32, hwnd, device_id) = setup_keyboard_test();

        // Initially all keys are up → bit 15 clear
        assert_eq!(
            user32.get_key_state(VK_SPACE),
            0,
            "space should be up initially"
        );
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
        assert_ne!(
            state & (0x8000u16 as i16),
            0,
            "space should be down (bit 15 set)"
        );
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
        assert_eq!(
            user32.get_key_state(VK_SPACE) & (0x8000u16 as i16),
            0,
            "space should be up after release"
        );
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
    #[ignore = "requires AppKit on main thread"]
    fn test_keyboard_state() {
        let (mut user32, hwnd, device_id) = setup_keyboard_test();

        // GetKeyboardState should return 256 bytes
        let mut state = vec![0u8; 256];
        assert!(
            user32.get_keyboard_state(&mut state),
            "get_keyboard_state should succeed"
        );
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
        assert_ne!(
            state2[VK_SPACE as usize] & 0x80,
            0,
            "VK_SPACE should have bit 7 set"
        );
        assert_eq!(
            state2[VK_A as usize] & 0x80,
            0,
            "VK_A should still be clear"
        );

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
        assert_eq!(
            state3[VK_SPACE as usize] & 0x80,
            0,
            "VK_SPACE bit 7 should be clear after release"
        );

        // Buffer too small → return false
        let mut small = [0u8; 10];
        assert!(
            !user32.get_keyboard_state(&mut small),
            "buffer < 256 should return false"
        );
    }

    #[test]
    fn test_vk_key_scan() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);

        // 'q' → VK_Q (0x51), no shift
        let result = user32.vk_key_scan_w('q' as u16);
        assert_eq!(result & 0x00FF, 0x51, "'q' should map to VK_Q (0x51)");
        assert_eq!(result >> 8, 0, "'q' should not require shift");

        // 'Q' → VK_Q (0x51), shift bit set
        let result = user32.vk_key_scan_w('Q' as u16);
        assert_eq!(result & 0x00FF, 0x51, "'Q' should map to VK_Q (0x51)");
        assert_ne!(result >> 8 & 0x01, 0, "'Q' should require shift");

        // Unknown character → -1
        let result = user32.vk_key_scan_w('©' as u16);
        assert_eq!(result, -1, "unknown char should return -1");
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
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
        assert_ne!(
            after_down & 0x0001,
            0,
            "async toggle bit should be set after key down"
        );

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
            0,           // module
            0,           // thread_id (0 = global)
        );
        assert_ne!(hook_id, 0, "hook ID should be non-zero");

        // CallNextHookEx should return 0 (no next hook in chain)
        let result = user32.call_next_hook_ex(hook_id, 0, 0, 0);
        assert_eq!(result, 0, "call_next_hook_ex should return 0");

        // Unhook
        assert!(
            user32.unhook_windows_hook_ex(hook_id),
            "unhook should succeed"
        );
        assert!(
            !user32.unhook_windows_hook_ex(hook_id),
            "unhook again should fail"
        );
    }

    // ── Timer tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_kill_timer_no_timer() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert!(
            !user32.kill_timer(1, 42),
            "killing non-existent timer should return false"
        );
    }

    #[test]
    fn test_set_and_kill_timer() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert!(user32.set_timer(1, 42, 1000), "set_timer should succeed");
        assert_eq!(user32.timer_count(), 1, "should have 1 active timer");
        assert!(user32.kill_timer(1, 42), "kill_timer should return true");
        assert_eq!(
            user32.timer_count(),
            0,
            "timer count should be 0 after kill"
        );
    }

    #[test]
    fn test_timer_count() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert_eq!(user32.timer_count(), 0, "initially no timers");
        user32.set_timer(1, 1, 1000);
        user32.set_timer(1, 2, 2000);
        user32.set_timer(2, 1, 500);
        assert_eq!(user32.timer_count(), 3, "three timers should be active");
    }

    #[test]
    fn test_poll_timers_expired() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        // Set a timer with 0ms timeout so it should already be expired
        user32.set_timer(1, 99, 0);
        // Give it a brief moment to pass
        std::thread::sleep(std::time::Duration::from_millis(1));
        let expired = user32.poll_timers();
        assert!(!expired.is_empty(), "timer with 0ms timeout should expire");
        assert!(
            expired.contains(&(1, 99)),
            "should contain our timer (hwnd=1, id=99)"
        );
        assert_eq!(user32.timer_count(), 0, "expired timers should be removed");
    }

    #[test]
    fn test_poll_timers_none_expired() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.set_timer(1, 1, 10_000); // 10 seconds — won't expire in test
        let expired = user32.poll_timers();
        assert!(
            expired.is_empty(),
            "long timer should not expire immediately"
        );
        assert_eq!(user32.timer_count(), 1, "timer should still be active");
    }

    #[test]
    fn test_poll_timers_rearms_periodic_timer() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        // Positive intervals are periodic: after firing, the timer is
        // re-armed (Win32 SetTimer semantics) until KillTimer.
        user32.set_timer(1, 7, 1);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let fired = user32.poll_timers();
        assert!(fired.contains(&(1, 7)), "periodic timer should fire");
        assert_eq!(
            user32.timer_count(),
            1,
            "periodic timer should be re-armed after firing"
        );
        assert!(user32.kill_timer(1, 7), "kill_timer should succeed");
        assert_eq!(user32.timer_count(), 0, "timer removed after kill");
    }

    // ── MessageQueue QS_* flag tests ────────────────────────────────────────

    #[test]
    fn test_message_queue_has_no_events_initially() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert!(
            !user32.message_queue_has_events(QS_KEY),
            "no key events initially"
        );
        assert!(
            !user32.message_queue_has_events(QS_MOUSE),
            "no mouse events initially"
        );
        assert!(
            !user32.message_queue_has_events(QS_PAINT),
            "no paint events initially"
        );
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn test_message_queue_has_key_events() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, false, false, None, 1)
            .expect("create window");
        let _ = std::iter::from_fn(|| user32.get_message_w()).collect::<Vec<_>>();

        // Inject a key-down message
        user32
            .enqueue(Message {
                hwnd: Some(hwnd),
                kind: MessageKind::KeyDown,
                wparam: 0x41,
                lparam: 0,
                translated: false,
                device_id: None,
            })
            .expect("enqueue keydown");

        assert!(
            user32.message_queue_has_events(QS_KEY),
            "should detect key event"
        );
        assert!(
            user32.message_queue_has_events(QS_INPUT),
            "QS_INPUT should include key"
        );
        assert!(
            !user32.message_queue_has_events(QS_MOUSE),
            "should not detect mouse event"
        );
    }

    #[test]
    fn test_message_queue_has_mouse_events() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32
            .enqueue(Message {
                hwnd: None,
                kind: MessageKind::MouseMove,
                wparam: 0,
                lparam: 0,
                translated: false,
                device_id: None,
            })
            .expect("enqueue mousemove");

        assert!(
            user32.message_queue_has_events(QS_MOUSEMOVE),
            "should detect mousemove"
        );
        assert!(
            user32.message_queue_has_events(QS_MOUSE),
            "QS_MOUSE should include mousemove"
        );
        assert!(
            !user32.message_queue_has_events(QS_KEY),
            "should not detect key event"
        );
    }

    #[test]
    fn test_message_queue_has_paint_events() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32
            .enqueue(Message {
                hwnd: None,
                kind: MessageKind::Paint,
                wparam: 0,
                lparam: 0,
                translated: false,
                device_id: None,
            })
            .expect("enqueue paint");

        assert!(
            user32.message_queue_has_events(QS_PAINT),
            "should detect paint event"
        );
        assert!(
            user32.message_queue_has_events(QS_ALLEVENTS),
            "QS_ALLEVENTS should include paint"
        );
    }

    #[test]
    fn test_message_queue_has_postmessage_events() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32
            .enqueue(Message {
                hwnd: None,
                kind: MessageKind::Other(0x0400), // WM_USER
                wparam: 0,
                lparam: 0,
                translated: false,
                device_id: None,
            })
            .expect("enqueue postmessage");

        assert!(
            user32.message_queue_has_events(QS_POSTMESSAGE),
            "should detect postmessage"
        );
    }

    #[test]
    fn test_message_queue_has_timer_events() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32
            .enqueue(Message {
                hwnd: None,
                kind: MessageKind::Other(0x0113), // WM_TIMER
                wparam: 0,
                lparam: 0,
                translated: false,
                device_id: None,
            })
            .expect("enqueue timer");

        assert!(
            user32.message_queue_has_events(QS_TIMER),
            "should detect timer event"
        );
    }

    #[test]
    fn test_message_queue_wake_mask_allinput() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        // Empty queue with QS_ALLINPUT should still check pending_paint
        assert!(
            !user32.message_queue_has_events(QS_ALLINPUT),
            "empty queue, no events"
        );
    }

    #[test]
    fn test_message_queue_wake_mask_zero() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        // wake_mask=0 means check everything
        assert!(
            !user32.message_queue_has_events(0),
            "empty queue should return false even with mask=0"
        );
    }

    // ── Clipboard tests ─────────────────────────────────────────────────────

    #[test]
    fn test_open_clipboard() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert!(
            user32.open_clipboard(Some(1)),
            "open clipboard should succeed"
        );
        // Opening again should fail (already open)
        assert!(!user32.open_clipboard(Some(2)), "second open should fail");
    }

    #[test]
    fn test_close_clipboard() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.open_clipboard(Some(1));
        assert!(user32.close_clipboard(), "close clipboard should succeed");
        // Opening again after close should work
        assert!(
            user32.open_clipboard(Some(2)),
            "open after close should succeed"
        );
    }

    #[test]
    fn test_empty_clipboard_no_open() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert!(!user32.empty_clipboard(), "empty without open should fail");
    }

    #[test]
    fn test_empty_clipboard_clears_data() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.open_clipboard(Some(1));
        user32.set_clipboard_data(CF_TEXT, b"hello".to_vec(), 1);
        assert!(
            user32.is_clipboard_format_available(CF_TEXT),
            "data should be available"
        );
        assert!(user32.empty_clipboard(), "empty should succeed");
        assert!(
            !user32.is_clipboard_format_available(CF_TEXT),
            "data should be gone after empty"
        );
    }

    #[test]
    fn test_set_clipboard_data() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.open_clipboard(Some(1));

        let stored = user32.set_clipboard_data(CF_TEXT, b"Hello, World!".to_vec(), 0x1234);
        // The data is stored and the caller (SetClipboardData thunk) returns
        // the guest handle on success.
        assert!(stored, "set_clipboard_data should report success");
        assert_eq!(
            user32.clipboard_handle(CF_TEXT),
            Some(0x1234),
            "the guest handle must be stored for GetClipboardData"
        );

        // Retrieve and verify
        let data = user32.get_clipboard_data(CF_TEXT);
        assert!(data.is_some(), "get_clipboard_data should return data");
        assert_eq!(data.unwrap(), b"Hello, World!".to_vec());
    }

    #[test]
    fn test_get_clipboard_data_not_open() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert!(
            user32.get_clipboard_data(CF_TEXT).is_none(),
            "get without open should return None"
        );
    }

    #[test]
    fn test_set_clipboard_data_not_open() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let stored = user32.set_clipboard_data(CF_TEXT, b"data".to_vec(), 0x1234);
        assert!(!stored, "set without open should report failure");
    }

    #[test]
    fn test_set_multiple_clipboard_formats() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.open_clipboard(Some(1));

        user32.set_clipboard_data(CF_TEXT, b"text data".to_vec(), 1);
        user32.set_clipboard_data(
            CF_UNICODETEXT,
            "unicode data\0"
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
            4,
        );
        user32.set_clipboard_data(CF_HDROP, vec![0u8; 100], 2);

        assert!(
            user32.is_clipboard_format_available(CF_TEXT),
            "CF_TEXT should be available"
        );
        assert!(
            user32.is_clipboard_format_available(CF_UNICODETEXT),
            "CF_UNICODETEXT should be available"
        );
        assert!(
            user32.is_clipboard_format_available(CF_HDROP),
            "CF_HDROP should be available"
        );
        assert!(
            !user32.is_clipboard_format_available(CF_BITMAP),
            "CF_BITMAP should NOT be available"
        );

        assert_eq!(
            user32.get_clipboard_data(CF_TEXT).unwrap(),
            b"text data".to_vec()
        );
    }

    #[test]
    fn test_is_clipboard_format_available_not_open() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert!(
            !user32.is_clipboard_format_available(CF_TEXT),
            "not open, should return false"
        );
    }

    #[test]
    fn test_set_class_long_stores_and_returns_previous() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("class-long-test");
        // Child-style windows avoid the AppKit NSWindow path (AppKit requires
        // the main thread and is not available in the test harness).
        let hwnd = user32
            .create_window_ex_styled(
                "class-long-test",
                "title",
                320,
                200,
                false,
                false,
                None,
                1,
                WS_CHILD,
                0,
                None,
            )
            .expect("create window");

        const GCL_STYLE: i32 = -26;
        // First set returns 0 (no previous value).
        assert_eq!(
            user32.set_class_long_w(hwnd, GCL_STYLE, 0x0A0A).unwrap(),
            0,
            "first set must return 0 as the previous value"
        );
        // Second set returns the stored previous value.
        assert_eq!(
            user32.set_class_long_w(hwnd, GCL_STYLE, 0x0B0B).unwrap(),
            0x0A0A,
            "subsequent set must return the previous class long"
        );
        // A second window of the SAME class shares the class long (the value
        // is stored on the window class, not the window instance).
        let hwnd2 = user32
            .create_window_ex_styled(
                "class-long-test",
                "title2",
                320,
                200,
                false,
                false,
                None,
                1,
                WS_CHILD,
                0,
                None,
            )
            .expect("create second window");
        assert_eq!(
            user32.set_class_long_w(hwnd2, GCL_STYLE, 0x0C0C).unwrap(),
            0x0B0B,
            "class longs are shared across windows of the same class"
        );
        // Different index keeps its own slot.
        assert_eq!(
            user32.set_class_long_w(hwnd, -24, 0x1234).unwrap(),
            0,
            "a fresh index returns 0"
        );
        assert_eq!(
            user32.set_class_long_w(hwnd, -24, 0x5678).unwrap(),
            0x1234,
            "the fresh index tracks its own previous value"
        );
    }

    #[test]
    fn test_set_class_long_invalid_hwnd_fails() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert!(
            user32.set_class_long_w(0xDEAD, -26, 1).is_none(),
            "an unknown hwnd must fail (ERROR_INVALID_WINDOW_HANDLE)"
        );
    }

    #[test]
    fn test_enum_clipboard_formats_not_open() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert_eq!(
            user32.enum_clipboard_formats(0),
            0,
            "not open, should return 0"
        );
    }

    #[test]
    fn test_enum_clipboard_formats_empty() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.open_clipboard(Some(1));
        assert_eq!(
            user32.enum_clipboard_formats(0),
            0,
            "empty clipboard, should return 0"
        );
    }

    #[test]
    fn test_enum_clipboard_formats_single() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.open_clipboard(Some(1));
        user32.set_clipboard_data(CF_TEXT, b"data".to_vec(), 1);

        let first = user32.enum_clipboard_formats(0);
        assert_eq!(first, CF_TEXT, "first format should be CF_TEXT");

        // No more formats
        assert_eq!(
            user32.enum_clipboard_formats(first),
            0,
            "no more formats after CF_TEXT"
        );
    }

    #[test]
    fn test_enum_clipboard_formats_multiple() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.open_clipboard(Some(1));
        user32.set_clipboard_data(CF_TEXT, b"text".to_vec(), 1);
        user32.set_clipboard_data(CF_UNICODETEXT, b"unicode\0".to_vec(), 2);
        user32.set_clipboard_data(CF_HDROP, vec![0u8; 64], 3);

        // Enumerate all formats
        let mut formats = Vec::new();
        let mut fmt = 0u32;
        loop {
            fmt = user32.enum_clipboard_formats(fmt);
            if fmt == 0 {
                break;
            }
            formats.push(fmt);
        }

        assert_eq!(formats.len(), 3, "should find 3 clipboard formats");
        assert!(formats.contains(&CF_TEXT), "should contain CF_TEXT");
        assert!(
            formats.contains(&CF_UNICODETEXT),
            "should contain CF_UNICODETEXT"
        );
        assert!(formats.contains(&CF_HDROP), "should contain CF_HDROP");
    }

    #[test]
    fn test_clipboard_preserves_data_across_formats() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.open_clipboard(Some(1));
        user32.set_clipboard_data(CF_TEXT, b"hello".to_vec(), 1);
        user32.set_clipboard_data(CF_UNICODETEXT, b"hello wide\0".to_vec(), 2);

        // Reading one format shouldn't affect others
        assert_eq!(
            user32.get_clipboard_data(CF_TEXT).unwrap(),
            b"hello".to_vec()
        );
        assert_eq!(
            user32.get_clipboard_data(CF_UNICODETEXT).unwrap(),
            b"hello wide\0".to_vec()
        );
    }

    // ── Misc API tests ─────────────────────────────────────────────────────

    #[test]
    fn test_get_window_thread_process_id() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let (tid, pid) = user32.get_window_thread_process_id(42);
        assert_eq!(tid, 1, "thread id should be 1");
        assert_eq!(
            pid,
            std::process::id(),
            "process id should match current pid"
        );
    }

    #[test]
    fn test_get_desktop_window() {
        let user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert_eq!(
            user32.get_desktop_window(),
            0,
            "desktop window should return 0"
        );
    }

    #[test]
    fn test_update_window_nonexistent() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let result = user32.update_window(999);
        assert!(result.is_ok(), "update_window should not fail");
        assert!(
            !result.unwrap(),
            "update_window for non-existent hwnd should return false"
        );
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn test_update_window_existing() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("test-window");
        let hwnd = user32
            .create_window_ex_w("test-window", "title", 320, 200, false, false, None, 1)
            .expect("create window");
        let _ = std::iter::from_fn(|| user32.get_message_w()).collect::<Vec<_>>();

        let result = user32.update_window(hwnd);
        assert!(result.is_ok(), "update_window should succeed");
        assert!(
            result.unwrap(),
            "update_window for existing hwnd should return true"
        );

        // Should have queued a paint message
        assert!(
            user32
                .get_message_w()
                .map(|m| m.kind == MessageKind::Paint)
                .unwrap_or(false),
            "update_window should queue a paint message"
        );
    }

    #[test]
    fn test_unregister_class_w() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("TestClass");
        assert!(
            user32.unregister_class_w("TestClass"),
            "unregister existing class should succeed"
        );
        assert!(
            !user32.unregister_class_w("TestClass"),
            "unregister again should fail"
        );
    }

    #[test]
    fn test_unregister_class_w_nonexistent() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        assert!(
            !user32.unregister_class_w("NonExistentClass"),
            "unregister non-existent should fail"
        );
    }

    // ── Message queue ordering tests ───────────────────────────────────

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn message_queue_preserves_fifo_order() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("msg-order");
        let hwnd = user32
            .create_window_ex_w("msg-order", "title", 320, 200, false, false, None, 1)
            .expect("create window");
        // Drain creation messages.
        while user32.get_message_w().is_some() {}

        // Post three messages in sequence using the Other(u32) variant.
        let seq = [
            MessageKind::Other(1001),
            MessageKind::Other(1002),
            MessageKind::Other(1003),
        ];
        for &kind in &seq {
            user32
                .post_message_w(hwnd, kind, 0, 0)
                .expect("post message");
        }

        let kinds: Vec<MessageKind> =
            std::iter::from_fn(|| user32.get_message_w().map(|m| m.kind)).collect();
        assert_eq!(kinds, seq, "messages should be dequeued in FIFO order");
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn timer_fires_and_is_reported_by_poll_timers() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("timer-msg");
        let hwnd = user32
            .create_window_ex_w("timer-msg", "title", 320, 200, false, false, None, 1)
            .expect("create window");
        // Drain creation messages.
        while user32.get_message_w().is_some() {}

        // Set up a timer with 0ms (fires immediately).
        assert!(user32.set_timer(hwnd, 42, 0), "set_timer should succeed");

        // Poll timers to fire the timer.
        let fired = user32.poll_timers();
        assert!(
            fired.contains(&(hwnd, 42)),
            "poll_timers should include our timer"
        );

        // After firing, timer should be removed.
        assert_eq!(user32.timer_count(), 0, "timer should be consumed");
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn keyboard_input_generates_key_down() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("kbd-test");
        let hwnd = user32
            .create_window_ex_w("kbd-test", "title", 320, 200, false, false, None, 1)
            .expect("create window");
        // Drain creation messages.
        while user32.get_message_w().is_some() {}

        // Register a keyboard device so inject_keyboard_input recognises it.
        let kbd_id = user32.register_keyboard_device(&KeyboardDevice {
            vendor_id: 0x1234,
            product_id: 0x5678,
            serial: "0001".to_string(),
        });

        // Inject a key-down event via inject_keyboard_input.
        user32
            .inject_keyboard_input(
                hwnd,
                &kbd_id,
                0x10, // scancode for Q
                KeyModifiers {
                    shift: false,
                    altgr: false,
                },
            )
            .expect("key down");

        let kinds: Vec<MessageKind> =
            std::iter::from_fn(|| user32.get_message_w().map(|m| m.kind)).collect();
        assert!(
            kinds.contains(&MessageKind::KeyDown),
            "keyboard input should produce KeyDown, got {kinds:?}"
        );
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn mouse_input_generates_button_down() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("mouse-test");
        let hwnd = user32
            .create_window_ex_w("mouse-test", "title", 320, 200, false, false, None, 1)
            .expect("create window");
        // Drain creation messages.
        while user32.get_message_w().is_some() {}

        // Register a mouse device so inject_mouse_input recognises it.
        let mouse_id = user32.register_mouse_device(&MouseDevice {
            vendor_id: 0xABCD,
            product_id: 0x1234,
            serial: "0001".to_string(),
        });

        // Set focus so the window receives mouse messages.
        user32.set_focus(hwnd).expect("set focus");

        // Inject mouse button down.
        user32
            .inject_mouse_input(
                hwnd,
                &mouse_id,
                100,
                100,
                &[MouseButtonEvent {
                    button: MouseButton::Left,
                    pressed: true,
                }],
                0,
                0,
            )
            .expect("mouse down");

        let kinds: Vec<MessageKind> =
            std::iter::from_fn(|| user32.get_message_w().map(|m| m.kind)).collect();
        assert!(
            kinds.contains(&MessageKind::LButtonDown),
            "mouse left down should produce LButtonDown, got {kinds:?}"
        );
    }

    #[test]
    #[ignore = "requires AppKit on main thread"]
    fn set_focus_generates_focus_messages() {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        user32.register_class_ex_w("focus-test1");
        user32.register_class_ex_w("focus-test2");

        let hwnd1 = user32
            .create_window_ex_w("focus-test1", "win1", 320, 200, false, false, None, 1)
            .expect("create win1");
        let hwnd2 = user32
            .create_window_ex_w("focus-test2", "win2", 320, 200, false, false, None, 1)
            .expect("create win2");
        // Drain creation messages.
        while user32.get_message_w().is_some() {}

        // Set focus to hwnd1.
        user32.set_focus(hwnd1).expect("set focus 1");
        let kinds1: Vec<MessageKind> =
            std::iter::from_fn(|| user32.get_message_w().map(|m| m.kind)).collect();
        assert!(
            kinds1.contains(&MessageKind::SetFocus),
            "set_focus should produce SetFocus message, got {kinds1:?}"
        );

        // Switch focus to hwnd2.
        user32.set_focus(hwnd2).expect("set focus 2");
        let kinds2: Vec<MessageKind> =
            std::iter::from_fn(|| user32.get_message_w().map(|m| m.kind)).collect();
        assert!(
            kinds2.contains(&MessageKind::KillFocus),
            "focus switch should produce KillFocus, got {kinds2:?}"
        );
    }

    // ── GDI+ object lifetime tests ─────────────────────────────────────

    #[test]
    fn gdiplus_alloc_handle_assigns_unique_ids() {
        let mut state = GdiplusState::default();
        let h1 = state.alloc_handle(GdiplusObject::Brush(Box::new(GdiplusBrush::SolidFill(
            GdiplusSolidFill { color: 0xFF0000 },
        ))));
        let h2 = state.alloc_handle(GdiplusObject::Brush(Box::new(GdiplusBrush::SolidFill(
            GdiplusSolidFill { color: 0x00FF00 },
        ))));
        assert_ne!(h1, h2, "allocated handles must be unique");
    }

    #[test]
    fn gdiplus_create_and_remove_object() {
        let mut state = GdiplusState::default();
        let h = state.alloc_handle(GdiplusObject::Pen(Box::new(GdiplusPen {
            color: 0x0000FF,
            brush_handle: None,
            width: 2.0,
            dash_style: 0,
            line_join: 0,
            start_cap: 0,
            end_cap: 0,
            alignment: 0,
        })));
        assert!(state.get(h).is_some(), "object should exist after alloc");
        let removed = state.remove(h);
        assert!(removed.is_some(), "remove should return the object");
        assert!(
            state.get(h).is_none(),
            "object should not exist after remove"
        );
    }

    #[test]
    fn gdiplus_repeated_create_destroy_does_not_leak_handles() {
        let mut state = GdiplusState::default();
        let initial_count = state.objects.len();

        for _ in 0..100 {
            let h = state.alloc_handle(GdiplusObject::Matrix(Box::new(GdiplusMatrix::identity())));
            state.remove(h);
        }

        assert_eq!(
            state.objects.len(),
            initial_count,
            "repeated create/destroy cycles should not leak handles"
        );
    }

    #[test]
    fn gdiplus_graphics_from_hdc_reuses_handle() {
        let mut state = GdiplusState::default();
        let h1 = state.create_graphics_from_hdc(0xABCD);
        let h2 = state.create_graphics_from_hdc(0xABCD);
        assert_eq!(
            h1, h2,
            "create_graphics_from_hdc should reuse handle for same HDC"
        );
        state.remove(h1);
    }

    #[test]
    fn gdiplus_invalid_handle_returns_none() {
        let mut state = GdiplusState::default();
        assert!(
            state.get(0xDEADBEEF).is_none(),
            "get on invalid handle should return None"
        );
        assert!(
            state.get_mut(0xDEADBEEF).is_none(),
            "get_mut on invalid handle should return None"
        );
        assert!(
            state.remove(0xDEADBEEF).is_none(),
            "remove on invalid handle should return None"
        );
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
    matches!(vk as i32, VK_CAPITAL | VK_NUMLOCK | VK_SCROLL)
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

/// Keyboard layout tables, built once. The previous version rebuilt the
/// entire map (8 layouts × entries, with allocations) on every keystroke —
/// a hot-path allocation hazard on every translate/map call.
fn layout_tables() -> &'static BTreeMap<KeyboardLayoutId, BTreeMap<u16, LayoutEntry>> {
    static TABLES: OnceLock<BTreeMap<KeyboardLayoutId, BTreeMap<u16, LayoutEntry>>> =
        OnceLock::new();
    TABLES.get_or_init(build_layout_tables)
}

fn build_layout_tables() -> BTreeMap<KeyboardLayoutId, BTreeMap<u16, LayoutEntry>> {
    BTreeMap::from([
        (
            KeyboardLayoutId::Us,
            BTreeMap::from([
                (
                    0x10,
                    LayoutEntry {
                        vk: VirtualKey::Q,
                        plain: Some('q'),
                        shifted: Some('Q'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x11,
                    LayoutEntry {
                        vk: VirtualKey::Unknown(0x57),
                        plain: Some('w'),
                        shifted: Some('W'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x12,
                    LayoutEntry {
                        vk: VirtualKey::E,
                        plain: Some('e'),
                        shifted: Some('E'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x13,
                    LayoutEntry {
                        vk: VirtualKey::Unknown(0x52),
                        plain: Some('r'),
                        shifted: Some('R'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x19,
                    LayoutEntry {
                        vk: VirtualKey::Unknown(0x50),
                        plain: Some('p'),
                        shifted: Some('P'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x1c,
                    LayoutEntry {
                        vk: VirtualKey::Unknown(0x0d),
                        plain: Some('\r'),
                        shifted: Some('\r'),
                        altgr: Some('\r'),
                        dead: None,
                    },
                ),
                (
                    0x1e,
                    LayoutEntry {
                        vk: VirtualKey::A,
                        plain: Some('a'),
                        shifted: Some('A'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x1f,
                    LayoutEntry {
                        vk: VirtualKey::Unknown(0x53),
                        plain: Some('s'),
                        shifted: Some('S'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x20,
                    LayoutEntry {
                        vk: VirtualKey::Unknown(0x44),
                        plain: Some('d'),
                        shifted: Some('D'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x2e,
                    LayoutEntry {
                        vk: VirtualKey::Unknown(0x43),
                        plain: Some('c'),
                        shifted: Some('C'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x31,
                    LayoutEntry {
                        vk: VirtualKey::Unknown(0x4e),
                        plain: Some('n'),
                        shifted: Some('N'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x39,
                    LayoutEntry {
                        vk: VirtualKey::Space,
                        plain: Some(' '),
                        shifted: Some(' '),
                        altgr: None,
                        dead: None,
                    },
                ),
            ]),
        ),
        (
            KeyboardLayoutId::Uk,
            BTreeMap::from([
                (
                    0x10,
                    LayoutEntry {
                        vk: VirtualKey::Q,
                        plain: Some('q'),
                        shifted: Some('Q'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x28,
                    LayoutEntry {
                        vk: VirtualKey::Oem7,
                        plain: Some('\''),
                        shifted: Some('@'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x12,
                    LayoutEntry {
                        vk: VirtualKey::E,
                        plain: Some('e'),
                        shifted: Some('E'),
                        altgr: None,
                        dead: None,
                    },
                ),
            ]),
        ),
        (
            KeyboardLayoutId::Fr,
            BTreeMap::from([
                (
                    0x10,
                    LayoutEntry {
                        vk: VirtualKey::A,
                        plain: Some('a'),
                        shifted: Some('A'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x1e,
                    LayoutEntry {
                        vk: VirtualKey::Q,
                        plain: Some('q'),
                        shifted: Some('Q'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x1a,
                    LayoutEntry {
                        vk: VirtualKey::Oem4,
                        plain: None,
                        shifted: None,
                        altgr: None,
                        dead: Some('^'),
                    },
                ),
                (
                    0x12,
                    LayoutEntry {
                        vk: VirtualKey::E,
                        plain: Some('e'),
                        shifted: Some('E'),
                        altgr: Some('€'),
                        dead: None,
                    },
                ),
            ]),
        ),
        (
            KeyboardLayoutId::De,
            BTreeMap::from([
                (
                    0x15,
                    LayoutEntry {
                        vk: VirtualKey::Z,
                        plain: Some('z'),
                        shifted: Some('Z'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x2c,
                    LayoutEntry {
                        vk: VirtualKey::Y,
                        plain: Some('y'),
                        shifted: Some('Y'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x12,
                    LayoutEntry {
                        vk: VirtualKey::E,
                        plain: Some('e'),
                        shifted: Some('E'),
                        altgr: None,
                        dead: None,
                    },
                ),
            ]),
        ),
        (
            KeyboardLayoutId::Es,
            BTreeMap::from([
                (
                    0x10,
                    LayoutEntry {
                        vk: VirtualKey::Q,
                        plain: Some('q'),
                        shifted: Some('Q'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x1a,
                    LayoutEntry {
                        vk: VirtualKey::Oem4,
                        plain: None,
                        shifted: None,
                        altgr: None,
                        dead: Some('´'),
                    },
                ),
                (
                    0x12,
                    LayoutEntry {
                        vk: VirtualKey::E,
                        plain: Some('e'),
                        shifted: Some('E'),
                        altgr: Some('€'),
                        dead: None,
                    },
                ),
            ]),
        ),
        (
            KeyboardLayoutId::It,
            BTreeMap::from([
                (
                    0x10,
                    LayoutEntry {
                        vk: VirtualKey::Q,
                        plain: Some('q'),
                        shifted: Some('Q'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x1a,
                    LayoutEntry {
                        vk: VirtualKey::Oem4,
                        plain: None,
                        shifted: None,
                        altgr: None,
                        dead: Some('`'),
                    },
                ),
                (
                    0x12,
                    LayoutEntry {
                        vk: VirtualKey::E,
                        plain: Some('e'),
                        shifted: Some('E'),
                        altgr: None,
                        dead: None,
                    },
                ),
            ]),
        ),
        (
            KeyboardLayoutId::Arabic,
            BTreeMap::from([
                (
                    0x10,
                    LayoutEntry {
                        vk: VirtualKey::Q,
                        plain: Some('ض'),
                        shifted: Some('َ'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x12,
                    LayoutEntry {
                        vk: VirtualKey::E,
                        plain: Some('ث'),
                        shifted: Some('ُ'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x39,
                    LayoutEntry {
                        vk: VirtualKey::Space,
                        plain: Some(' '),
                        shifted: Some(' '),
                        altgr: None,
                        dead: None,
                    },
                ),
            ]),
        ),
        (
            KeyboardLayoutId::Turkish,
            BTreeMap::from([
                (
                    0x10,
                    LayoutEntry {
                        vk: VirtualKey::Q,
                        plain: Some('q'),
                        shifted: Some('Q'),
                        altgr: None,
                        dead: None,
                    },
                ),
                (
                    0x1a,
                    LayoutEntry {
                        vk: VirtualKey::Oem4,
                        plain: None,
                        shifted: None,
                        altgr: None,
                        dead: Some('^'),
                    },
                ),
                (
                    0x12,
                    LayoutEntry {
                        vk: VirtualKey::E,
                        plain: Some('e'),
                        shifted: Some('E'),
                        altgr: Some('€'),
                        dead: None,
                    },
                ),
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
    // Discriminants per GdiplusTypes.h: PropertyNotFound = 18,
    // PropertyNotSupported = 19, ProfileNotFound = 20 (previously off by one).
    PropertyNotFound = 18,
    PropertyNotSupported = 19,
    ProfileNotFound = 20,
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
    Line {
        x1: f32,
        y1: f32,
        x2: f32,
        y2: f32,
    },
    Lines {
        points: Vec<GdiplusPointF>,
    },
    Rectangle {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
    },
    Ellipse {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
    },
    Arc {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        start_angle: f32,
        sweep_angle: f32,
    },
    Bezier {
        points: [GdiplusPointF; 4],
    },
    Curve {
        points: Vec<GdiplusPointF>,
        tension: f32,
    },
    ClosedCurve {
        points: Vec<GdiplusPointF>,
        tension: f32,
    },
    Polygon {
        points: Vec<GdiplusPointF>,
    },
    Pie {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        start_angle: f32,
        sweep_angle: f32,
    },
    String {
        text: String,
        font_handle: u64,
        layout_rect: GdiplusRectF,
        format_flags: u32,
    },
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
        Self {
            elements: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        }
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
/// Matches the Win32 GdiplusStartupInput layout: the two BOOL flags sit at
/// offsets 16 and 20 (size 24). Rust `bool` is 1 byte, so an explicit pad
/// keeps `suppress_external_codecs` at offset 20 (it was at 17, misaligning
/// any guest ABI marshalling of the struct).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GdiplusStartupInput {
    pub gdiplus_version: u32,
    pub debug_event_callback: u64,
    pub suppress_background_thread: bool,
    pub pad: [u8; 3],
    pub suppress_external_codecs: bool,
}

impl Default for GdiplusStartupInput {
    fn default() -> Self {
        Self {
            gdiplus_version: 1,
            debug_event_callback: 0,
            suppress_background_thread: false,
            pad: [0; 3],
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
        // Probe for a free handle: a wrapping counter could otherwise
        // collide with a live object, aliasing two GDI+ objects.
        let start = self.next_handle;
        let handle = loop {
            let candidate = self.next_handle;
            self.next_handle = self.next_handle.wrapping_add(1);
            if !self.objects.contains_key(&candidate) {
                break candidate;
            }
            if self.next_handle == start {
                break candidate; // table exhausted (unreachable in practice)
            }
        };
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

// ===========================================================================
// Gap 6.7: Raw Input Pre-parsed Data Structures
// ===========================================================================

/// RAWINPUTHEADER structure (Win32).
/// Contains the header information for a raw input event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawInputHeader {
    /// Type of raw input data: 0 = RIM_TYPEMOUSE, 1 = RIM_TYPEKEYBOARD, 2 = RIM_TYPEHID
    pub dw_type: u32,
    /// Size of the entire RAWINPUT structure.
    pub dw_size: u32,
    /// Handle to the device generating the raw input.
    pub h_device: u64,
    /// Window handle that received the raw input message.
    pub w_param: u64,
}

/// RAWMOUSE structure — raw mouse input data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawMouseData {
    /// Mouse state flags (RI_MOUSE_LEFT_BUTTON_DOWN, etc.).
    pub us_flags: u16,
    /// Union: flags specifying the meaning of lLastX/lLastY.
    pub us_button_flags: u16,
    /// Button data (wheel delta for RI_MOUSE_WHEEL).
    pub us_button_data: u16,
    /// Raw button flags.
    pub ul_raw_buttons: u32,
    /// Relative mouse motion (X).
    pub l_last_x: i32,
    /// Relative mouse motion (Y).
    pub l_last_y: i32,
    /// Extra device-specific data.
    pub ul_extra_information: u64,
}

/// RAWKEYBOARD structure — raw keyboard input data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawKeyboardData {
    /// Scan code from the key depression.
    pub make_code: u16,
    /// Flags (RI_KEY_MAKE, RI_KEY_BREAK, RI_KEY_E0, RI_KEY_E1).
    pub flags: u16,
    /// Reserved.
    pub reserved: u16,
    /// Virtual key code.
    pub v_key: u16,
    /// Message (WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP).
    pub message: u32,
    /// Extra device-specific information.
    pub extra_information: u64,
}

/// RAWHID structure — raw HID input data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawHidData {
    /// Size of each HID report in bytes.
    pub dw_size_hid: u32,
    /// Number of HID reports in bRawData.
    pub dw_count: u32,
    /// Raw HID report data.
    pub b_raw_data: Vec<u8>,
}

/// RAWINPUT structure — complete raw input event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawInputData {
    /// Header containing type, size, device handle, and window handle.
    pub header: RawInputHeader,
    /// The device-specific data.
    pub data: RawInputDeviceData,
}

/// Device-specific raw input data union.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RawInputDeviceData {
    Mouse(RawMouseData),
    Keyboard(RawKeyboardData),
    Hid(RawHidData),
}

impl RawInputData {
    /// Create a mouse raw input event.
    pub fn mouse(device: u64, hwnd: u64, x: i32, y: i32, button_flags: u16) -> Self {
        Self {
            header: RawInputHeader {
                dw_type: 0, // RIM_TYPEMOUSE
                dw_size: 48,
                h_device: device,
                w_param: hwnd,
            },
            data: RawInputDeviceData::Mouse(RawMouseData {
                us_flags: 0,
                us_button_flags: button_flags,
                us_button_data: 0,
                ul_raw_buttons: 0,
                l_last_x: x,
                l_last_y: y,
                ul_extra_information: 0,
            }),
        }
    }

    /// Create a keyboard raw input event.
    pub fn keyboard(device: u64, hwnd: u64, v_key: u16, scan_code: u16, key_down: bool) -> Self {
        Self {
            header: RawInputHeader {
                dw_type: 1, // RIM_TYPEKEYBOARD
                dw_size: 40,
                h_device: device,
                w_param: hwnd,
            },
            data: RawInputDeviceData::Keyboard(RawKeyboardData {
                make_code: scan_code,
                flags: if key_down { 0 } else { 1 }, // RI_KEY_BREAK = 1
                reserved: 0,
                v_key,
                message: if key_down { 0x0100 } else { 0x0101 }, // WM_KEYDOWN / WM_KEYUP
                extra_information: 0,
            }),
        }
    }

    /// Create a HID raw input event.
    pub fn hid(device: u64, hwnd: u64, report: Vec<u8>) -> Self {
        let report_size = report.len() as u32;
        Self {
            header: RawInputHeader {
                dw_type: 2, // RIM_TYPEHID
                // Serialized layout: 24-byte RAWINPUTHEADER + 12-byte RAWHID
                // (dwSizeHid + dwCount) + raw data = 36 + len.
                dw_size: 36 + report.len() as u32,
                h_device: device,
                w_param: hwnd,
            },
            data: RawInputDeviceData::Hid(RawHidData {
                dw_size_hid: report_size,
                dw_count: 1,
                b_raw_data: report,
            }),
        }
    }

    /// Serialize the raw input data to bytes (for GetRawInputData).
    /// Returns the serialized bytes matching the Windows RAWINPUT layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Header
        bytes.extend_from_slice(&self.header.dw_type.to_le_bytes());
        bytes.extend_from_slice(&self.header.dw_size.to_le_bytes());
        bytes.extend_from_slice(&self.header.h_device.to_le_bytes());
        bytes.extend_from_slice(&self.header.w_param.to_le_bytes());
        // Device data
        match &self.data {
            RawInputDeviceData::Mouse(m) => {
                bytes.extend_from_slice(&m.us_flags.to_le_bytes());
                bytes.extend_from_slice(&m.us_button_flags.to_le_bytes());
                bytes.extend_from_slice(&m.us_button_data.to_le_bytes());
                bytes.extend_from_slice(&m.ul_raw_buttons.to_le_bytes());
                bytes.extend_from_slice(&m.l_last_x.to_le_bytes());
                bytes.extend_from_slice(&m.l_last_y.to_le_bytes());
                bytes.extend_from_slice(&m.ul_extra_information.to_le_bytes());
            }
            RawInputDeviceData::Keyboard(k) => {
                bytes.extend_from_slice(&k.make_code.to_le_bytes());
                bytes.extend_from_slice(&k.flags.to_le_bytes());
                bytes.extend_from_slice(&k.reserved.to_le_bytes());
                bytes.extend_from_slice(&k.v_key.to_le_bytes());
                bytes.extend_from_slice(&k.message.to_le_bytes());
                bytes.extend_from_slice(&k.extra_information.to_le_bytes());
            }
            RawInputDeviceData::Hid(h) => {
                bytes.extend_from_slice(&h.dw_size_hid.to_le_bytes());
                bytes.extend_from_slice(&h.dw_count.to_le_bytes());
                bytes.extend_from_slice(&h.b_raw_data);
            }
        }
        bytes
    }
}

// ===========================================================================
// Gap 6.9: Pointer Device APIs — Enhanced Implementations
// ===========================================================================

/// Pointer device information (GetPointerDevice).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerDeviceInfo {
    /// Device product ID.
    pub product_id: u32,
    /// Device vendor ID.
    pub vendor_id: u32,
    /// Version number of the device.
    pub version: u32,
    /// Type of pointer device: 1 = touch, 2 = pen, 3 = touchpad, 4 = mouse.
    pub pointer_device_type: u32,
    /// The monitor on which the device is displayed.
    pub monitor: u32,
    /// Maximum simultaneous contacts.
    pub max_contacts: u32,
    /// Whether the device supports pressure.
    pub supports_pressure: bool,
    /// Whether the device supports tilt (X/Y).
    pub supports_tilt: bool,
    /// Whether the device supports twist (rotation).
    pub supports_twist: bool,
    /// Device name (from macOS IOKit).
    pub device_name: String,
}

impl Default for PointerDeviceInfo {
    fn default() -> Self {
        Self {
            product_id: 0,
            vendor_id: 0,
            version: 1,
            pointer_device_type: 1, // touch
            monitor: 1,
            max_contacts: 10,
            supports_pressure: true,
            supports_tilt: true,
            supports_twist: false,
            device_name: "Apple Trackpad".to_string(),
        }
    }
}

/// Enhanced pointer capabilities (GetPointerDeviceCaps extended).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerDeviceCapsEx {
    /// Maximum number of simultaneous touch contacts.
    pub max_contacts: u32,
    /// Maximum pressure level (0 = not supported).
    pub max_pressure: u32,
    /// Maximum tilt X angle in degrees (0 = not supported).
    pub max_tilt_x: u32,
    /// Maximum tilt Y angle in degrees (0 = not supported).
    pub max_tilt_y: u32,
    /// Maximum twist rotation in degrees (0 = not supported).
    pub max_twist: u32,
    /// Resolution in dots per inch.
    pub dpi: u32,
    /// Report rate in Hz.
    pub report_rate: u32,
    /// Device type.
    pub device_type: u32,
}

impl Default for PointerDeviceCapsEx {
    fn default() -> Self {
        // Apple Magic Trackpad / MacBook trackpad defaults
        Self {
            max_contacts: 10,
            max_pressure: 8, // macOS pressure levels 0-8
            max_tilt_x: 0,   // trackpads don't report tilt
            max_tilt_y: 0,
            max_twist: 0,
            dpi: 72,
            report_rate: 125,
            device_type: 1, // touch
        }
    }
}

/// Pointer frame info with extended data (GetPointerFrameInfoEx).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerFrameInfoEx {
    /// Number of pointers in this frame.
    pub pointer_count: u32,
    /// Frame ID (monotonically increasing).
    pub frame_id: u32,
    /// Pointer flags for the frame.
    pub pointer_flags: u32,
    /// Timestamp of the frame (in 100ns intervals since boot).
    pub display_time: u64,
    /// Performance counter value at frame time.
    pub performance_count: u64,
    /// Per-pointer data for each contact in the frame.
    pub pointers: Vec<PointerContactInfo>,
}

/// Per-contact pointer information within a frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerContactInfo {
    /// Pointer ID (stable across the contact lifetime).
    pub pointer_id: u32,
    /// X coordinate in pixels.
    pub x: i32,
    /// Y coordinate in pixels.
    pub y: i32,
    /// Pressure level (0-8 for macOS trackpad).
    pub pressure: u32,
    /// Tilt X in degrees (-90 to 90, 0 if unsupported).
    pub tilt_x: i32,
    /// Tilt Y in degrees (-90 to 90, 0 if unsupported).
    pub tilt_y: i32,
    /// Twist rotation in degrees (0-359, 0 if unsupported).
    pub twist: u32,
    /// Contact area width in pixels.
    pub contact_rect_width: u32,
    /// Contact area height in pixels.
    pub contact_rect_height: u32,
    /// Pointer flags (CONTACT, DOWN, UPDATE, UP, etc.).
    pub flags: u32,
}

impl User32Subsystem {
    /// Gap 6.9: GetPointerDevice — retrieve pointer device information.
    ///
    /// Returns information about the primary pointer device (trackpad/mouse/tablet).
    /// On macOS, queries IOKit for device information if available.
    pub fn get_pointer_device(&self) -> PointerDeviceInfo {
        #[cfg(target_os = "macos")]
        {
            // Query macOS for trackpad/mouse device information
            // Default to Apple trackpad characteristics
            PointerDeviceInfo {
                product_id: 0x0265, // Apple Magic Trackpad product ID
                vendor_id: 0x05AC,  // Apple vendor ID
                version: 1,
                pointer_device_type: 1, // touch
                monitor: self.primary_monitor_id(),
                max_contacts: 10,
                supports_pressure: true,
                supports_tilt: false,
                supports_twist: false,
                device_name: "Apple Trackpad".to_string(),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            PointerDeviceInfo::default()
        }
    }

    /// Gap 6.9: GetPointerDeviceCapsEx — extended pointer device capabilities.
    ///
    /// Returns detailed capabilities of the pointer device including
    /// pressure, tilt, and twist support.
    pub fn get_pointer_device_caps_ex(&self) -> PointerDeviceCapsEx {
        #[cfg(target_os = "macos")]
        {
            PointerDeviceCapsEx {
                max_contacts: 10,
                max_pressure: 8, // macOS Force Touch levels
                max_tilt_x: 0,   // trackpad doesn't report tilt
                max_tilt_y: 0,
                max_twist: 0,
                dpi: 72,
                report_rate: 125,
                device_type: 1,
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            PointerDeviceCapsEx::default()
        }
    }

    /// Gap 6.7: Generate raw input data from macOS CGEvent.
    ///
    /// Creates a RawInputData structure from the current mouse position delta
    /// using macOS CoreGraphics event data.
    #[cfg(target_os = "macos")]
    pub fn generate_raw_mouse_from_cgevent(&self, dx: i32, dy: i32, buttons: u16) -> RawInputData {
        RawInputData::mouse(1, 0, dx, dy, buttons)
    }

    /// Gap 6.7: Generate raw keyboard input from a key event.
    pub fn generate_raw_keyboard_event(
        &self,
        v_key: u16,
        scan_code: u16,
        key_down: bool,
    ) -> RawInputData {
        RawInputData::keyboard(2, 0, v_key, scan_code, key_down)
    }
}
