use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type Atom = u16;
pub type Hwnd = u32;

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
    ShowWindow,
    WindowPosChanging,
    Size,
    Activate,
    SetFocus,
    KillFocus,
    Input,
    KeyDown,
    KeyUp,
    Char,
    DeadChar,
    RawInput,
    MouseMove,
    MouseWheel,
    MouseHWheel,
    XButtonDown,
    InputDeviceChange,
    Destroy,
    NcDestroy,
    Quit,
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

#[derive(Debug, Clone)]
struct WindowClass {
    atom: Atom,
    name: String,
}

#[derive(Debug, Clone)]
struct WindowRecord {
    hwnd: Hwnd,
    class_name: String,
    title: String,
    width: u32,
    height: u32,
    visible: bool,
    fullscreen: FullscreenState,
    monitor_id: u32,
    dpi: u32,
    destroyed: bool,
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
    layout: KeyboardLayoutId,
    key_repeat: KeyRepeatConfig,
    dpi_context: DpiAwarenessContext,
    classes: BTreeMap<String, WindowClass>,
    windows: BTreeMap<Hwnd, WindowRecord>,
    message_queue: VecDeque<Message>,
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
            layout,
            key_repeat: KeyRepeatConfig {
                delay_ms: 250,
                rate_hz: 31,
            },
            dpi_context: DpiAwarenessContext::SystemAware,
            classes: BTreeMap::new(),
            windows: BTreeMap::new(),
            message_queue: VecDeque::new(),
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
        }
    }

    pub fn register_class_ex_w(&mut self, class_name: &str) -> Atom {
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
            },
        );
        atom
    }

    pub fn create_window_ex_w(
        &mut self,
        class_name: &str,
        title: &str,
        width: u32,
        height: u32,
        visible: bool,
        requested_exclusive_fullscreen: bool,
        monitor_id: u32,
    ) -> AppResult<Hwnd> {
        let class = self.classes.get(class_name).ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, format!("unregistered class {class_name}"))
        })?;
        let _ = (&class.atom, &class.name);
        let hwnd = self.next_hwnd;
        self.next_hwnd += 1;
        let fullscreen = self.map_fullscreen_state(title, requested_exclusive_fullscreen);
        let dpi = self.effective_dpi(monitor_id)?;
        self.windows.insert(
            hwnd,
            WindowRecord {
                hwnd,
                class_name: class_name.to_string(),
                title: title.to_string(),
                width,
                height,
                visible,
                fullscreen,
                monitor_id,
                dpi,
                destroyed: false,
            },
        );
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

    pub fn destroy_window(&mut self, hwnd: Hwnd) -> AppResult<()> {
        self.window(hwnd)?;
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
        if let Some(window) = self.windows.get_mut(&hwnd) {
            window.destroyed = true;
        }
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
        Ok(())
    }

    pub fn def_window_proc_w(&mut self, message: &Message) -> AppResult<i64> {
        if let Some(hwnd) = message.hwnd {
            let _ = self.window(hwnd)?;
        }
        Ok(0)
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

    pub fn peek_message_w(&mut self, remove: bool) -> Option<Message> {
        let message = self.message_queue.front()?.clone();
        if remove {
            self.message_queue.pop_front();
        }
        Some(message)
    }

    pub fn get_message_w(&mut self) -> Option<Message> {
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
                } => self.inject_keyboard_input_internal(*hwnd, device_id, *scancode, *modifiers, false)?,
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
        self.inject_keyboard_input_internal(hwnd, device_id, scancode, modifiers, true)
    }

    fn inject_keyboard_input_internal(
        &mut self,
        hwnd: Hwnd,
        device_id: &str,
        scancode: u16,
        modifiers: KeyModifiers,
        record: bool,
    ) -> AppResult<()> {
        self.window(hwnd)?;
        if !self.keyboard_devices.contains(device_id) {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("unknown keyboard device {device_id}"),
            ));
        }
        if record {
            self.recorded_input.push(InputReplayEvent::Keyboard {
                hwnd,
                device_id: device_id.to_string(),
                scancode,
                modifiers,
            });
        }
        self.enqueue(Message {
            hwnd: Some(hwnd),
            kind: MessageKind::KeyDown,
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
            if button.pressed && matches!(button.button, MouseButton::X1 | MouseButton::X2) {
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

    pub fn attach_controller(&mut self, target_window: Option<Hwnd>, spec: ControllerSpec) -> AppResult<String> {
        let guid = stable_device_id(
            "di",
            &format!(
                "{:04x}:{:04x}:{}:{}:{:?}",
                spec.vendor_id, spec.product_id, spec.serial, spec.name, spec.kind
            ),
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

    fn enqueue(&mut self, message: Message) -> AppResult<()> {
        if self.message_queue.len() >= self.input_queue_capacity {
            return Err(AppError::new(
                ReasonCode::RcInputUnsupported,
                "input queue overflow",
            ));
        }
        self.message_queue.push_back(message);
        Ok(())
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
                (0x12, LayoutEntry { vk: VirtualKey::E, plain: Some('e'), shifted: Some('E'), altgr: None, dead: None }),
                (0x1e, LayoutEntry { vk: VirtualKey::A, plain: Some('a'), shifted: Some('A'), altgr: None, dead: None }),
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