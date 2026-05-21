//! Steam Input API emulation layer (ISteamInput / ISteamController).
//!
//! Provides a host-side implementation of the Steam Input API that translates
//! Steam Input action queries into XInput-style raw gamepad state lookups.
//! This allows games using `SteamAPI_ISteamInput_*` calls to read controller
//! input without a real Steam client.
//!
//! # Handle allocation
//! - Controller handles: `0x1000 + XInput slot index` (fixed per slot 0–3)
//! - Action set handles: auto-incrementing starting at `0x2000`
//! - Digital action handles: auto-incrementing starting at `0x3000`
//! - Analog action handles: auto-incrementing starting at `0x4000`
//!
//! # Default action mapping
//! When no Steam Controller configuration (VDF) is loaded, a built-in table
//! maps common action names (e.g. `"menu_accept"`, `"jump"`, `"move"`) to
//! the corresponding XInput button / axis reads.

use std::collections::HashMap;

// ── XInput button bitmask constants ──────────────────────────────────────
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

// ── Handle types ─────────────────────────────────────────────────────────

/// Opaque handle for a connected controller.
pub type ControllerHandle = u64;

/// Opaque handle for an action set.
pub type ActionSetHandle = u64;

/// Opaque handle for a digital action.
pub type DigitalActionHandle = u64;

/// Opaque handle for an analog action.
pub type AnalogActionHandle = u64;

// ── Controller input type (matches Steamworks SDK ESteamInputType) ───────

/// Known controller models, as reported by `GetControllerInputType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ControllerInputType {
    Unknown = 0,
    SteamController = 1,
    Xbox360 = 2,
    XboxOne = 3,
    GenericGamepad = 4,
    PS4 = 5,
    AppleMFi = 6,
    PS5 = 7,
    SwitchPro = 8,
    SwitchJoycon = 9,
    SwitchJoyconLeft = 10,
    SwitchJoyconRight = 11,
}

// ── Action data structures ───────────────────────────────────────────────

/// Data returned by `GetDigitalActionData`.
#[derive(Debug, Clone, Copy)]
pub struct DigitalActionData {
    /// Whether the action belongs to the currently active action set.
    pub active: bool,
    /// Whether the action is currently pressed (true) or released (false).
    pub state: bool,
}

/// Data returned by `GetAnalogActionData`.
#[derive(Debug, Clone, Copy)]
pub struct AnalogActionData {
    /// Whether the action belongs to the currently active action set.
    pub active: bool,
    /// X axis value, normalized to [-1.0, 1.0].
    pub x: f32,
    /// Y axis value, normalized to [-1.0, 1.0].
    pub y: f32,
    /// Z axis value (e.g. trigger depth), normalized to [-1.0, 1.0].
    pub z: f32,
    /// The input mode (joystick, trigger, touch pad, gyro).
    pub mode: AnalogActionMode,
}

/// Describes the physical input that sources an analog action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AnalogActionMode {
    None = 0,
    Joystick = 1,
    Trigger = 2,
    TouchPad = 3,
    Gyro = 4,
}

/// Motion data returned by `GetMotionData` (gyroscope + accelerometer).
#[derive(Debug, Clone, Copy)]
pub struct MotionData {
    /// Rotation quaternion (x, y, z, w).
    pub rot_quat: [f32; 4],
    /// Linear acceleration in m/s² (x, y, z).
    pub pos_accel: [f32; 3],
    /// Angular velocity in rad/s (x, y, z).
    pub rot_vel: [f32; 3],
}

/// Haptic pulse target (SteamControllerPad).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HapticTarget {
    Left = 0,
    Right = 1,
    Both = 2,
}

// ── Raw gamepad snapshot ─────────────────────────────────────────────────

/// Snapshot of raw gamepad state at a point in time, derived from XInput.
#[derive(Debug, Clone, Default)]
pub struct RawGamepadState {
    /// XINPUT_GAMEPAD_* bitmask.
    pub buttons: u16,
    /// Left trigger value (0–255).
    pub left_trigger: u8,
    /// Right trigger value (0–255).
    pub right_trigger: u8,
    /// Left thumb stick X (-32768–32767).
    pub thumb_lx: i16,
    /// Left thumb stick Y (-32768–32767).
    pub thumb_ly: i16,
    /// Right thumb stick X (-32768–32767).
    pub thumb_rx: i16,
    /// Right thumb stick Y (-32768–32767).
    pub thumb_ry: i16,
}

// ── Controller tracking record ───────────────────────────────────────────

/// Internal record for a controller tracked by the Steam Input subsystem.
#[derive(Debug, Clone)]
pub struct SteamInputController {
    pub handle: ControllerHandle,
    pub active_action_set: Option<ActionSetHandle>,
    pub gamepad_index: i32,
    pub input_type: ControllerInputType,
}

// ── Handle allocation constants ──────────────────────────────────────────

const CONTROLLER_HANDLE_BASE: u64 = 0x1000;
const ACTION_SET_HANDLE_BASE: u64 = 0x2000;
const DIGITAL_ACTION_HANDLE_BASE: u64 = 0x3000;
const ANALOG_ACTION_HANDLE_BASE: u64 = 0x4000;

// ── SteamInput state machine ─────────────────────────────────────────────

/// Main state machine for Steam Input API emulation.
///
/// Manages controller handles, action set/action registrations, and provides
/// default action mappings that translate Steam Input action queries into
/// XInput-style raw gamepad reads.
pub struct SteamInput {
    /// Whether `init()` has been called successfully.
    initialized: bool,
    /// Next action set handle (auto-incrementing).
    next_action_set_handle: u64,
    /// Next digital action handle (auto-incrementing).
    next_digital_action_handle: u64,
    /// Next analog action handle (auto-incrementing).
    next_analog_action_handle: u64,
    /// Connected controllers indexed by XInput slot (0..4).
    controllers: Vec<SteamInputController>,
    /// Registered action sets: name → handle.
    action_sets: HashMap<String, ActionSetHandle>,
    /// Registered digital actions: name → handle.
    digital_actions: HashMap<String, DigitalActionHandle>,
    /// Registered analog actions: name → handle.
    analog_actions: HashMap<String, AnalogActionHandle>,
    /// Currently active action set per controller.
    controller_action_sets: HashMap<ControllerHandle, ActionSetHandle>,
    /// Last frame's raw input snapshot per controller.
    last_raw_state: HashMap<ControllerHandle, RawGamepadState>,
}

impl SteamInput {
    /// Creates a new uninitialized Steam Input state machine.
    ///
    /// Call [`init()`](Self::init) before issuing any other commands.
    pub fn new() -> Self {
        let controllers = (0..4)
            .map(|i| SteamInputController {
                handle: CONTROLLER_HANDLE_BASE + i as u64,
                active_action_set: None,
                gamepad_index: i as i32,
                input_type: ControllerInputType::Xbox360,
            })
            .collect();

        Self {
            initialized: false,
            next_action_set_handle: ACTION_SET_HANDLE_BASE,
            next_digital_action_handle: DIGITAL_ACTION_HANDLE_BASE,
            next_analog_action_handle: ANALOG_ACTION_HANDLE_BASE,
            controllers,
            action_sets: HashMap::new(),
            digital_actions: HashMap::new(),
            analog_actions: HashMap::new(),
            controller_action_sets: HashMap::new(),
            last_raw_state: HashMap::new(),
        }
    }

    /// Returns the controller handle for a given XInput slot (0..3).
    pub fn handle_for_slot(slot: u8) -> ControllerHandle {
        CONTROLLER_HANDLE_BASE + slot as u64
    }

    /// Returns the XInput slot index for a controller handle, or `None`.
    pub fn slot_for_handle(handle: ControllerHandle) -> Option<u8> {
        if handle >= CONTROLLER_HANDLE_BASE && handle < CONTROLLER_HANDLE_BASE + 4 {
            Some((handle - CONTROLLER_HANDLE_BASE) as u8)
        } else {
            None
        }
    }

    // ── Core Steam Input API methods ──────────────────────────────────────

    /// `SteamAPI_ISteamInput_Init` — initialises the Steam Input subsystem.
    ///
    /// Returns `true` on success.
    pub fn init(&mut self) -> bool {
        self.initialized = true;
        true
    }

    /// `SteamAPI_ISteamInput_Shutdown` — shuts down the subsystem.
    pub fn shutdown(&mut self) {
        self.initialized = false;
        self.last_raw_state.clear();
        self.controller_action_sets.clear();
    }

    /// `SteamAPI_ISteamInput_RunFrame` — per-frame update.
    ///
    /// Synchronises the internal raw state snapshot with the current controller
    /// state provided via `raw_states`. Call this once per frame.
    pub fn run_frame(&mut self, raw_states: Vec<(ControllerHandle, RawGamepadState)>) {
        for (handle, state) in raw_states {
            self.last_raw_state.insert(handle, state);
        }
    }

    /// `SteamAPI_ISteamInput_GetConnectedControllers` — returns the handles
    /// of all connected controllers.
    ///
    /// Returns up to 4 handles (one per XInput slot).
    pub fn get_connected_controllers(&self) -> Vec<ControllerHandle> {
        self.controllers
            .iter()
            .map(|c| c.handle)
            .collect()
    }

    /// `SteamAPI_ISteamInput_GetActionSetHandle` — resolves an action set
    /// name to a handle, registering it if not already known.
    pub fn get_action_set_handle(&mut self, name: &str) -> ActionSetHandle {
        if let Some(&handle) = self.action_sets.get(name) {
            return handle;
        }
        let handle = self.next_action_set_handle;
        self.next_action_set_handle += 1;
        self.action_sets.insert(name.to_string(), handle);
        handle
    }

    /// `SteamAPI_ISteamInput_GetDigitalActionHandle` — resolves a digital
    /// action name to a handle, registering it if not already known.
    pub fn get_digital_action_handle(&mut self, name: &str) -> DigitalActionHandle {
        if let Some(&handle) = self.digital_actions.get(name) {
            return handle;
        }
        let handle = self.next_digital_action_handle;
        self.next_digital_action_handle += 1;
        self.digital_actions.insert(name.to_string(), handle);
        handle
    }

    /// `SteamAPI_ISteamInput_GetAnalogActionHandle` — resolves an analog
    /// action name to a handle, registering it if not already known.
    pub fn get_analog_action_handle(&mut self, name: &str) -> AnalogActionHandle {
        if let Some(&handle) = self.analog_actions.get(name) {
            return handle;
        }
        let handle = self.next_analog_action_handle;
        self.next_analog_action_handle += 1;
        self.analog_actions.insert(name.to_string(), handle);
        handle
    }

    /// `SteamAPI_ISteamInput_ActivateActionSet` — sets the active action set
    /// for a given controller.
    pub fn activate_action_set(&mut self, controller: ControllerHandle, handle: ActionSetHandle) {
        self.controller_action_sets.insert(controller, handle);
    }

    /// `SteamAPI_ISteamInput_GetCurrentActionSet` — returns the active action
    /// set for a controller, or 0 if none has been set.
    pub fn get_current_action_set(&self, controller: ControllerHandle) -> ActionSetHandle {
        self.controller_action_sets.get(&controller).copied().unwrap_or(0)
    }

    /// `SteamAPI_ISteamInput_GetDigitalActionData` — reads the current state
    /// of a digital action for a controller.
    ///
    /// Returns active state based on the default action mapping table.
    pub fn get_digital_action_data(&self, controller: ControllerHandle, action: DigitalActionHandle) -> DigitalActionData {
        let raw = match self.last_raw_state.get(&controller) {
            Some(r) => r,
            None => {
                return DigitalActionData {
                    active: false,
                    state: false,
                };
            }
        };

        // Resolve action name from handle
        let action_name = self.digital_actions
            .iter()
            .find(|(_, h)| **h == action)
            .map(|(name, _)| name.as_str())
            .unwrap_or("");

        // Check if action belongs to active action set
        let active = self.is_action_active(controller, action_name);

        DigitalActionData {
            active,
            state: active && self.map_digital_action(raw, action_name),
        }
    }

    /// `SteamAPI_ISteamInput_GetAnalogActionData` — reads the current analog
    /// (axis) state of an action for a controller.
    pub fn get_analog_action_data(&self, controller: ControllerHandle, action: AnalogActionHandle) -> AnalogActionData {
        let raw = match self.last_raw_state.get(&controller) {
            Some(r) => r,
            None => {
                return AnalogActionData {
                    active: false,
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                    mode: AnalogActionMode::None,
                };
            }
        };

        let action_name = self.analog_actions
            .iter()
            .find(|(_, h)| **h == action)
            .map(|(name, _)| name.as_str())
            .unwrap_or("");

        let active = self.is_action_active(controller, action_name);
        let (x, y, z) = self.map_analog_action(raw, action_name);
        let mode = match action_name.to_lowercase().as_str() {
            n if n.contains("trigger") || n.contains("lt") || n.contains("rt")
                || n.contains("brake") || n.contains("accelerate") || n.contains("throttle") => {
                AnalogActionMode::Trigger
            }
            n if n.contains("gyro") || n.contains("motion") => AnalogActionMode::Gyro,
            n if n.contains("touch") || n.contains("pad") => AnalogActionMode::TouchPad,
            _ => AnalogActionMode::Joystick,
        };

        AnalogActionData {
            active,
            x: x.clamp(-1.0, 1.0),
            y: y.clamp(-1.0, 1.0),
            z: z.clamp(-1.0, 1.0),
            mode,
        }
    }

    /// `SteamAPI_ISteamInput_TriggerRepeatedHapticPulse` — triggers haptic
    /// feedback. Currently a no-op (no haptics support in the emulator).
    pub fn trigger_repeated_haptic_pulse(
        &self,
        _controller: ControllerHandle,
        _target: HapticTarget,
        _pulse_count: u32,
        _duration_ms: u32,
        _interval_ms: u32,
        _flags: u32,
    ) {
        // No haptics emulation — silently ignore.
    }

    /// `SteamAPI_ISteamInput_GetControllerInputType` — returns the
    /// controller model (always Xbox 360 in emulation).
    pub fn get_controller_input_type(&self, controller: ControllerHandle) -> ControllerInputType {
        self.controllers
            .iter()
            .find(|c| c.handle == controller)
            .map(|c| c.input_type)
            .unwrap_or(ControllerInputType::Unknown)
    }

    /// `SteamAPI_ISteamInput_GetMotionData` — reads motion sensor data.
    ///
    /// Returns zeroed data since no actual IMU is available in emulation.
    pub fn get_motion_data(&self, _controller: ControllerHandle) -> MotionData {
        MotionData {
            rot_quat: [0.0, 0.0, 0.0, 1.0],
            pos_accel: [0.0, 0.0, 0.0],
            rot_vel: [0.0, 0.0, 0.0],
        }
    }

    /// `SteamAPI_ISteamInput_ShowBindingPanel` — shows the binding config UI.
    ///
    /// Returns `false` (no UI available in the emulator).
    pub fn show_binding_panel(&self, _controller: ControllerHandle) -> bool {
        false
    }

    /// `SteamAPI_ISteamInput_GetGlyphForActionHandle` — returns a glyph
    /// string for an action handle.
    ///
    /// Returns an empty string (no glyph data available).
    pub fn get_glyph_for_action_handle(&self, _action: ActionSetHandle) -> Option<&str> {
        None
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Returns the raw state snapshot for a controller, if available.
    pub fn get_raw_state(&self, controller: ControllerHandle) -> Option<&RawGamepadState> {
        self.last_raw_state.get(&controller)
    }

    /// Returns whether the named action is in the currently active action set.
    fn is_action_active(&self, controller: ControllerHandle, action_name: &str) -> bool {
        let Some(_current_set) = self.controller_action_sets.get(&controller) else {
            // No active action set → default to active for all actions
            return true;
        };
        // If an active action set is configured, check that the action belongs to it.
        // With the default flat mapping, we consider all actions as part of any set.
        // A full VDF-based implementation would do a proper membership check here.
        true
    }

    /// Maps a digital action name to its XInput button state.
    ///
    /// This is the default mapping used when no Steam Controller VDF
    /// configuration has been loaded.
    fn map_digital_action(&self, raw: &RawGamepadState, action_name: &str) -> bool {
        match action_name.to_lowercase().as_str() {
            // Face buttons
            "menu_accept" | "accept" | "a" | "jump" | "confirm" | "select" => {
                (raw.buttons & XINPUT_GAMEPAD_A) != 0
            }
            "menu_cancel" | "cancel" | "b" | "back" | "decline" | "exit" => {
                (raw.buttons & XINPUT_GAMEPAD_B) != 0
            }
            "menu_extra_1" | "x" | "reload" | "interact" | "use" => {
                (raw.buttons & XINPUT_GAMEPAD_X) != 0
            }
            "menu_extra_2" | "y" | "weapon_switch" | "melee" | "swap_weapon" => {
                (raw.buttons & XINPUT_GAMEPAD_Y) != 0
            }
            // Shoulder buttons
            "shoulder_left" | "lb" | "left_bumper" | "aim" | "focus" | "aim_down_sight" => {
                (raw.buttons & XINPUT_GAMEPAD_LEFT_SHOULDER) != 0
            }
            "shoulder_right" | "rb" | "right_bumper" | "fire" | "shoot" | "attack" => {
                (raw.buttons & XINPUT_GAMEPAD_RIGHT_SHOULDER) != 0
            }
            // D-pad
            "dpad_up" | "up" | "navigate_up" => {
                (raw.buttons & XINPUT_GAMEPAD_DPAD_UP) != 0
            }
            "dpad_down" | "down" | "navigate_down" => {
                (raw.buttons & XINPUT_GAMEPAD_DPAD_DOWN) != 0
            }
            "dpad_left" | "left" | "navigate_left" => {
                (raw.buttons & XINPUT_GAMEPAD_DPAD_LEFT) != 0
            }
            "dpad_right" | "right" | "navigate_right" => {
                (raw.buttons & XINPUT_GAMEPAD_DPAD_RIGHT) != 0
            }
            // Start / Select
            "start" | "pause" | "menu" | "options" => {
                (raw.buttons & XINPUT_GAMEPAD_START) != 0
            }
            "select" | "view" | "share" => {
                (raw.buttons & XINPUT_GAMEPAD_BACK) != 0
            }
            // Thumbstick clicks
            "left_stick_click" | "ls" | "left_thumbstick" | "sprint" | "run" => {
                (raw.buttons & XINPUT_GAMEPAD_LEFT_THUMB) != 0
            }
            "right_stick_click" | "rs" | "right_thumbstick" | "crouch" | "toggle_crouch" => {
                (raw.buttons & XINPUT_GAMEPAD_RIGHT_THUMB) != 0
            }
            // Additional common action names
            "left_trigger" | "lt" | "left_trigger_edge" => {
                raw.left_trigger > 0
            }
            "right_trigger" | "rt" | "right_trigger_edge" => {
                raw.right_trigger > 0
            }
            // Unknown → inactive
            _ => false,
        }
    }

    /// Maps an analog action name to its XInput axis values.
    ///
    /// Returns `(x, y, z)` where:
    /// - `x`, `y` are from the relevant thumb stick (-1.0 to 1.0)
    /// - `z` is from the relevant trigger (0.0 to 1.0)
    fn map_analog_action(&self, raw: &RawGamepadState, action_name: &str) -> (f32, f32, f32) {
        match action_name.to_lowercase().as_str() {
            // Left stick
            "move" | "left_stick" | "movement" | "left_joystick" | "walk" => (
                normalize_axis(raw.thumb_lx),
                normalize_axis(raw.thumb_ly),
                0.0,
            ),
            // Right stick
            "look" | "right_stick" | "camera" | "aim" | "right_joystick" | "view" => (
                normalize_axis(raw.thumb_rx),
                normalize_axis(raw.thumb_ry),
                0.0,
            ),
            // Triggers (z axis = trigger depth)
            "left_trigger" | "lt" | "brake" | "accelerate" | "left_trigger_analog" => (
                0.0,
                0.0,
                normalize_trigger(raw.left_trigger),
            ),
            "right_trigger" | "rt" | "throttle" | "fire" | "right_trigger_analog" => (
                0.0,
                0.0,
                normalize_trigger(raw.right_trigger),
            ),
            // Unknown → zero
            _ => (0.0, 0.0, 0.0),
        }
    }
}

impl Default for SteamInput {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ─────────────────────────────────────────────────────

/// Normalises a 16-bit signed axis value to `[-1.0, 1.0]`.
fn normalize_axis(value: i16) -> f32 {
    if value == 0 {
        return 0.0;
    }
    let val = value as f32 / i16::MAX as f32;
    val.clamp(-1.0, 1.0)
}

/// Normalises an 8-bit trigger value to `[0.0, 1.0]`.
fn normalize_trigger(value: u8) -> f32 {
    value as f32 / 255.0
}
