use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::real_hid::{HostController, HidMonitor};
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind,
            wparam: modifiers.to_bits(),
            lparam: scancode as i64,
            translated: false,
            device_id: Some(device_id.to_string()),
        })
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