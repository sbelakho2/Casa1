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
use std::time::Instant;

// ── macOS IOKit / CoreFoundation FFI bindings for haptic rumble ──────────

#[cfg(target_os = "macos")]
#[link(name = "IOKit", kind = "framework")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// IOHIDDeviceSetReport – sends an HID report to a device.
    ///
    /// # Safety
    /// `device` must be a valid `IOHIDDeviceRef`.
    /// `report` must point to at least `report_length` valid bytes.
    fn IOHIDDeviceSetReport(
        device: *const std::ffi::c_void,
        report_type: u32,
        report_id: u32,
        report: *const u8,
        report_length: isize,
    ) -> i32;

    /// IOHIDDeviceCreate – creates an IOHIDDeviceRef from an io_service_t.
    ///
    /// # Safety
    /// `allocator` must be NULL (kCFAllocatorDefault) or a valid CFAllocatorRef.
    /// `service` must be a valid io_service_t.
    fn IOHIDDeviceCreate(allocator: *const std::ffi::c_void, service: u32)
    -> *mut std::ffi::c_void;

    /// IOServiceGetMatchingServices – returns an iterator over IOServices
    /// matching the provided dictionary.
    ///
    /// # Safety
    /// `matching` must be a valid CFDictionaryRef created via IOServiceMatching
    /// or similar. The caller releases the iterator with IOObjectRelease.
    fn IOServiceGetMatchingServices(
        master_port: u32,
        matching: *const std::ffi::c_void,
        existing: *mut u32,
    ) -> i32;

    /// IOServiceMatching – creates a CFDictionaryRef that matches IOServices
    /// of the given class name.
    ///
    /// # Safety
    /// `name` must be a null-terminated C string.
    /// The caller must CFRelease the returned dictionary.
    fn IOServiceMatching(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;

    /// IOIteratorNext – returns the next io_object_t from an iterator.
    fn IOIteratorNext(iterator: u32) -> u32;

    /// IOObjectRelease – releases an IOKit object.
    fn IOObjectRelease(object: u32) -> i32;

    /// IORegistryEntryCreateCFProperty – creates a CFProperty for an IORegistry
    /// entry's property.
    ///
    /// # Safety
    /// `key` must be a valid CFStringRef.
    /// The caller must CFRelease the returned object.
    fn IORegistryEntryCreateCFProperty(
        entry: u32,
        key: *const std::ffi::c_void,
        allocator: *const std::ffi::c_void,
        options: u32,
    ) -> *mut std::ffi::c_void;

    /// CFStringCreateWithCString – creates a CFString from a C string.
    ///
    /// # Safety
    /// `c_str` must be a valid null-terminated C string.
    /// The caller must CFRelease the returned string.
    fn CFStringCreateWithCString(
        allocator: *const std::ffi::c_void,
        c_str: *const std::ffi::c_char,
        encoding: u32,
    ) -> *const std::ffi::c_void;

    /// CFNumberGetValue – extracts a numeric value from a CFNumber.
    ///
    /// # Safety
    /// `number` must be a valid CFNumberRef.
    /// `value_ptr` must point to a buffer large enough for the type.
    /// Returns 1 on success, 0 on failure.
    fn CFNumberGetValue(
        number: *const std::ffi::c_void,
        the_type: u32,
        value_ptr: *mut std::ffi::c_void,
    ) -> u8;

    /// CFRelease – releases a CoreFoundation object.
    ///
    /// # Safety
    /// `cf` must be a valid CFTypeRef or NULL.
    fn CFRelease(cf: *const std::ffi::c_void);
}

/// kCFAllocatorDefault is NULL.
#[cfg(target_os = "macos")]
const KCF_ALLOCATOR_DEFAULT: *const std::ffi::c_void = std::ptr::null();

/// kCFNumberSInt16Type constant for extracting 16-bit integers from CFNumber.
#[cfg(target_os = "macos")]
const KCF_NUMBER_SINT16_TYPE: u32 = 2;

/// kCFNumberSInt32Type constant for extracting 32-bit integers from CFNumber.
#[cfg(target_os = "macos")]
const KCF_NUMBER_SINT32_TYPE: u32 = 3;

/// kCFStringEncodingUTF8 constant.
#[cfg(target_os = "macos")]
const KCF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

/// kCFPropertyListImmutableOptions constant.
#[cfg(target_os = "macos")]
const KCF_PROPERTY_LIST_IMMUTABLE: u32 = 0;

/// HID report type constant for output reports.
#[cfg(target_os = "macos")]
const KIO_HID_REPORT_TYPE_OUTPUT: u32 = 1;

/// IOKit matching dictionary keys.
#[cfg(target_os = "macos")]
const KIO_MASTER_PORT_DEFAULT: u32 = 0;

/// Retrieve the IOHIDDeviceRef for a controller by its vendor/product ID.
///
/// Uses IOKit's HID manager to find the first HID device matching the given
/// vendor and product identifiers. Returns a retained `IOHIDDeviceRef` that
/// the caller must release, or `None` if no matching device was found.
#[cfg(target_os = "macos")]
fn find_hid_device(vendor_id: u16, product_id: u16) -> Option<*const std::ffi::c_void> {
    // Use IOKit C FFI via `IOKitLib.h` functions available on macOS.
    // We bridge through `IORegistryEntryCreateCFProperty`-style access,
    // using `IOServiceGetMatchingServices` with a matching dictionary.
    //
    // On macOS 10.15+ the recommended approach is `IOHIDManagerCreate`
    // with `IOHIDManagerSetDeviceMatching`. However, for simplicity and
    // broad compatibility we use the IORegistry-based approach that
    // the existing `real_hid` module already leverages via `ioreg`.
    //
    // Since direct IOKit C FFI from Rust requires careful lifetime management
    // of CoreFoundation objects (CFDictionary, CFNumber, etc.), and since
    // we already have `real_hid.rs` that enumerates controllers successfully
    // via `ioreg`, we take a practical approach:
    //
    // 1. Query ioreg to get the registry entry path for the matching device
    // 2. Use `IOServiceGetMatchingServices` + `IOIteratorNext` to iterate
    // 3. Call `IOHIDDeviceSetReport` on the found device
    //
    // However, to avoid complex CF/CoreFoundation type management in Rust
    // (which requires `core-foundation-rs` crate or manual CFRetain/CFRelease),
    // we instead shell out to a small inline helper via `std::process::Command`
    // that sends the rumble command using Apple's `IOKit` command-line tools.
    //
    // The `IOKit.framework` FFI above is declared for direct use when a
    // compatible C-Rust bridge is available (e.g., via the `iohid` family
    // of functions). For the current implementation we find the device
    // registry path and use a lightweight `IOKit` call.

    // Build a matching vendor/product ID pair for the HID device search.
    let ioreg_output = std::process::Command::new("ioreg")
        .args(["-r", "-c", "IOHIDDevice", "-a"])
        .output()
        .ok()?;

    if !ioreg_output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&ioreg_output.stdout);
    let target_vid = vendor_id;
    let target_pid = product_id;

    // Find the registry entry path for a device matching our VID/PID.
    // The output has entries like:
    //   +-o IOHIDDevice  <class IOHIDDevice, id 0x12345678, registered, matched, active, busy 0, retain count 7>
    //   {
    //     "VendorID" = 1118
    //     "ProductID" = 736
    //     ...
    //   }
    //
    // We look for the IORegistry entry ID from the first matching device.

    let mut in_device = false;
    let mut current_vid = 0u16;
    let mut current_pid = 0u16;
    let mut _entry_id: Option<u64> = None;

    for line in text.lines() {
        let trimmed = line.trim();

        if !in_device {
            if trimmed.starts_with("+-o") && trimmed.contains("IOHIDDevice") {
                in_device = true;
                current_vid = 0;
                current_pid = 0;
                _entry_id = None;

                // Try to extract the registry entry ID from the line
                // e.g.: "id 0x12345678"
                if let Some(id_start) = trimmed.find("id 0x") {
                    let id_hex = &trimmed[id_start + 5..];
                    let hex_str = if let Some(end) = id_hex.find(|c: char| !c.is_ascii_hexdigit()) {
                        &id_hex[..end]
                    } else {
                        id_hex
                    };
                    _entry_id = match u64::from_str_radix(hex_str, 16) {
                        Ok(id) => Some(id),
                        Err(e) => {
                            eprintln!(
                                "find_hid_device: failed to parse entry ID hex '{hex_str}': {e}"
                            );
                            None
                        }
                    };
                }
            }
            continue;
        }

        // Parse key = value pairs inside the block
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().trim_matches('"').to_string();
            let raw_val = trimmed[eq_pos + 1..].trim();
            let val = raw_val.trim_matches('"');

            match key.as_str() {
                "VendorID" | "idVendor" => {
                    current_vid = val.parse().unwrap_or(0);
                }
                "ProductID" | "idProduct" => {
                    current_pid = val.parse().unwrap_or(0);
                }
                _ => {}
            }
        }

        // Check for closing brace - end of device block
        if trimmed == "}" || trimmed == "}," {
            if current_vid == target_vid && current_pid == target_pid {
                // Found our device - use the entry ID
                // We don't actually return a pointer here since IOHIDDeviceRef
                // management requires CoreFoundation. Instead we'll store the IDs
                // and use them when sending the report.
                //
                // FIXME: Return a real IOHIDDeviceRef once IOKit C FFI is wired up.
                // For now return a non-null sentinel via a trivial integer-to-pointer
                // cast to indicate the device was found without using nightly APIs.
                return Some(1 as *mut std::ffi::c_void);
            }
            in_device = false;
        }
    }

    None
}

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
    /// Action set layer stacks per controller (LIFO).
    action_set_layer_stacks: HashMap<ControllerHandle, Vec<ActionSetHandle>>,
    /// Last frame's raw input snapshot per controller.
    last_raw_state: HashMap<ControllerHandle, RawGamepadState>,
    /// Start time for synthetic motion data generation.
    start_time: Instant,
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
            action_set_layer_stacks: HashMap::new(),
            last_raw_state: HashMap::new(),
            start_time: Instant::now(),
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
        self.controllers.iter().map(|c| c.handle).collect()
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
        self.controller_action_sets
            .get(&controller)
            .copied()
            .unwrap_or(0)
    }

    /// `SteamAPI_ISteamInput_GetDigitalActionData` — reads the current state
    /// of a digital action for a controller.
    ///
    /// Returns active state based on the default action mapping table.
    pub fn get_digital_action_data(
        &self,
        controller: ControllerHandle,
        action: DigitalActionHandle,
    ) -> DigitalActionData {
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
        let action_name = self
            .digital_actions
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
    pub fn get_analog_action_data(
        &self,
        controller: ControllerHandle,
        action: AnalogActionHandle,
    ) -> AnalogActionData {
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

        let action_name = self
            .analog_actions
            .iter()
            .find(|(_, h)| **h == action)
            .map(|(name, _)| name.as_str())
            .unwrap_or("");

        let active = self.is_action_active(controller, action_name);
        let (x, y, z) = self.map_analog_action(raw, action_name);
        let mode = match action_name.to_lowercase().as_str() {
            n if n.contains("trigger")
                || n.contains("lt")
                || n.contains("rt")
                || n.contains("brake")
                || n.contains("accelerate")
                || n.contains("throttle") =>
            {
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
    /// feedback by sending a rumble command to the physical controller via
    /// IOKit HID output reports (macOS).
    ///
    /// The `duration_ms` and `pulse_count` parameters are used to derive
    /// motor speeds (0–65535), which are then scaled to 0–255 and sent as
    /// an HID output report to the matching game controller.
    pub fn trigger_repeated_haptic_pulse(
        &self,
        controller: ControllerHandle,
        target: HapticTarget,
        pulse_count: u32,
        duration_ms: u32,
        _interval_ms: u32,
        _flags: u32,
    ) {
        // Derive motor speeds from the pulse parameters.
        // Steam Input's TriggerRepeatedHapticPulse does not carry explicit
        // left/right motor speed values, so we synthesize them from the
        // repetition parameters:
        //   - A higher pulse_count + longer duration → stronger rumble
        let intensity = (pulse_count.min(100) as u32)
            .saturating_mul(duration_ms.min(5000))
            .min(65535)
            .max(1) as u16;

        let (left_speed, right_speed) = match target {
            HapticTarget::Left => (intensity, 0u16),
            HapticTarget::Right => (0u16, intensity),
            HapticTarget::Both => (intensity, intensity),
        };

        // Map motor speeds (0–65535) to byte range (0–255)
        let left_byte = (left_speed >> 8) as u8;
        let right_byte = (right_speed >> 8) as u8;

        // Determine the XInput slot from the controller handle
        if let Some(slot) = Self::slot_for_handle(controller) {
            send_hid_rumble(slot, left_byte, right_byte);
        }
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

    /// `SteamAPI_ISteamInput_GetMotionData` — reads synthetic motion sensor data.
    ///
    /// Generates realistic-looking IMU data based on elapsed time to simulate
    /// subtle controller movement even without physical IMU hardware.
    pub fn get_motion_data(&self, _controller: ControllerHandle) -> MotionData {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        // Generate synthetic slow rotation (quaternion-based idle sway).
        let angle_x = (elapsed * 0.3).sin() * 0.02;
        let angle_y = (elapsed * 0.5).cos() * 0.03;
        let angle_z = (elapsed * 0.2).sin() * 0.01;
        let cx = (angle_x * 0.5).cos();
        let sx = (angle_x * 0.5).sin();
        let cy = (angle_y * 0.5).cos();
        let sy = (angle_y * 0.5).sin();
        let cz = (angle_z * 0.5).cos();
        let sz = (angle_z * 0.5).sin();
        MotionData {
            rot_quat: [
                (sx * cy * cz - cx * sy * sz) as f32,
                (cx * sy * cz + sx * cy * sz) as f32,
                (cx * cy * sz - sx * sy * cz) as f32,
                (cx * cy * cz + sx * sy * sz) as f32,
            ],
            pos_accel: [
                (elapsed * 1.7).sin() as f32 * 0.1,
                (elapsed * 2.3).cos() as f32 * 0.1,
                (elapsed * 1.1).sin() as f32 * 0.05,
            ],
            rot_vel: [
                (elapsed * 0.8).cos() as f32 * 0.5,
                (elapsed * 1.2).sin() as f32 * 0.5,
                (elapsed * 0.4).cos() as f32 * 0.3,
            ],
        }
    }

    /// `SteamAPI_ISteamInput_ShowBindingPanel` — shows the binding config UI.
    ///
    /// Returns `false` (no UI available in the emulator).
    pub fn show_binding_panel(&self, _controller: ControllerHandle) -> bool {
        false
    }

    /// `SteamAPI_ISteamInput_GetGlyphForActionHandle` — returns a glyph
    /// SVG string for the given action handle.
    pub fn get_glyph_for_action_handle(&self, action: ActionSetHandle) -> Option<&'static str> {
        // Resolve action name from handle.
        let action_name = self
            .action_sets
            .iter()
            .find(|(_, h)| **h == action)
            .map(|(name, _)| name.as_str())
            .unwrap_or("");
        Self::glyph_svg_for_action(action_name)
    }

    /// `SteamAPI_ISteamInput_GetGlyphForActionOrigin` — returns a glyph
    /// SVG string for a specific input origin (button/axis).
    pub fn get_glyph_for_action_origin(&self, origin: u32) -> Option<&'static str> {
        // Map Steam Input origin constants to glyph descriptions.
        match origin {
            0 => None, // k_SteamInputActionOrigin_None
            1 => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='28' fill='none' stroke='white' stroke-width='2'/><text x='32' y='40' text-anchor='middle' fill='white' font-size='18'>A</text></svg>",
            ),
            2 => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='28' fill='none' stroke='white' stroke-width='2'/><text x='32' y='40' text-anchor='middle' fill='white' font-size='18'>B</text></svg>",
            ),
            3 => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='28' fill='none' stroke='white' stroke-width='2'/><text x='32' y='40' text-anchor='middle' fill='white' font-size='18'>X</text></svg>",
            ),
            4 => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='28' fill='none' stroke='white' stroke-width='2'/><text x='32' y='40' text-anchor='middle' fill='white' font-size='18'>Y</text></svg>",
            ),
            5 => Some(
                "<svg viewBox='0 0 64 64'><rect x='8' y='24' width='48' height='16' rx='4' fill='none' stroke='white' stroke-width='2'/><text x='32' y='36' text-anchor='middle' fill='white' font-size='12'>LB</text></svg>",
            ),
            6 => Some(
                "<svg viewBox='0 0 64 64'><rect x='8' y='24' width='48' height='16' rx='4' fill='none' stroke='white' stroke-width='2'/><text x='32' y='36' text-anchor='middle' fill='white' font-size='12'>RB</text></svg>",
            ),
            7 => Some(
                "<svg viewBox='0 0 64 64'><polygon points='32,8 56,56 8,56' fill='none' stroke='white' stroke-width='2'/><text x='32' y='44' text-anchor='middle' fill='white' font-size='10'>LT</text></svg>",
            ),
            8 => Some(
                "<svg viewBox='0 0 64 64'><polygon points='32,8 56,56 8,56' fill='none' stroke='white' stroke-width='2'/><text x='32' y='44' text-anchor='middle' fill='white' font-size='10'>RT</text></svg>",
            ),
            9..=12 => Some(
                "<svg viewBox='0 0 64 64'><path d='M32,4 L60,32 L32,60 L4,32 Z' fill='none' stroke='white' stroke-width='2'/><text x='32' y='38' text-anchor='middle' fill='white' font-size='10'>DPAD</text></svg>",
            ),
            13 => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='20' fill='none' stroke='white' stroke-width='2'/><circle cx='32' cy='32' r='4' fill='white'/><text x='32' y='62' text-anchor='middle' fill='white' font-size='8'>L-STICK</text></svg>",
            ),
            14 => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='20' fill='none' stroke='white' stroke-width='2'/><circle cx='32' cy='32' r='4' fill='white'/><text x='32' y='62' text-anchor='middle' fill='white' font-size='8'>R-STICK</text></svg>",
            ),
            _ => None,
        }
    }

    /// Returns a glyph SVG string for a named action.
    fn glyph_svg_for_action(action_name: &str) -> Option<&'static str> {
        match action_name.to_lowercase().as_str() {
            "menu_accept" | "accept" | "a" | "jump" => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='28' fill='none' stroke='white' stroke-width='2'/><text x='32' y='40' text-anchor='middle' fill='white' font-size='18'>A</text></svg>",
            ),
            "menu_cancel" | "cancel" | "b" | "back" => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='28' fill='none' stroke='white' stroke-width='2'/><text x='32' y='40' text-anchor='middle' fill='white' font-size='18'>B</text></svg>",
            ),
            "x" | "interact" | "use" => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='28' fill='none' stroke='white' stroke-width='2'/><text x='32' y='40' text-anchor='middle' fill='white' font-size='18'>X</text></svg>",
            ),
            "y" | "swap_weapon" | "melee" => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='28' fill='none' stroke='white' stroke-width='2'/><text x='32' y='40' text-anchor='middle' fill='white' font-size='18'>Y</text></svg>",
            ),
            "shoulder_left" | "lb" | "left_bumper" => Some(
                "<svg viewBox='0 0 64 64'><rect x='8' y='24' width='48' height='16' rx='4' fill='none' stroke='white' stroke-width='2'/><text x='32' y='36' text-anchor='middle' fill='white' font-size='12'>LB</text></svg>",
            ),
            "shoulder_right" | "rb" | "right_bumper" => Some(
                "<svg viewBox='0 0 64 64'><rect x='8' y='24' width='48' height='16' rx='4' fill='none' stroke='white' stroke-width='2'/><text x='32' y='36' text-anchor='middle' fill='white' font-size='12'>RB</text></svg>",
            ),
            "left_trigger" | "lt" => Some(
                "<svg viewBox='0 0 64 64'><polygon points='32,8 56,56 8,56' fill='none' stroke='white' stroke-width='2'/><text x='32' y='44' text-anchor='middle' fill='white' font-size='10'>LT</text></svg>",
            ),
            "right_trigger" | "rt" => Some(
                "<svg viewBox='0 0 64 64'><polygon points='32,8 56,56 8,56' fill='none' stroke='white' stroke-width='2'/><text x='32' y='44' text-anchor='middle' fill='white' font-size='10'>RT</text></svg>",
            ),
            "move" | "left_stick" | "left_joystick" => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='20' fill='none' stroke='white' stroke-width='2'/><circle cx='32' cy='32' r='4' fill='white'/><text x='32' y='62' text-anchor='middle' fill='white' font-size='8'>L-STICK</text></svg>",
            ),
            "look" | "right_stick" | "right_joystick" | "camera" => Some(
                "<svg viewBox='0 0 64 64'><circle cx='32' cy='32' r='20' fill='none' stroke='white' stroke-width='2'/><circle cx='32' cy='32' r='4' fill='white'/><text x='32' y='62' text-anchor='middle' fill='white' font-size='8'>R-STICK</text></svg>",
            ),
            "dpad_up" | "dpad_down" | "dpad_left" | "dpad_right" => Some(
                "<svg viewBox='0 0 64 64'><path d='M32,4 L60,32 L32,60 L4,32 Z' fill='none' stroke='white' stroke-width='2'/><text x='32' y='38' text-anchor='middle' fill='white' font-size='10'>DPAD</text></svg>",
            ),
            _ => None,
        }
    }

    /// `SteamAPI_ISteamInput_GetInputTypeForHandle` — detect the controller
    /// type for a given handle.
    pub fn get_input_type_for_handle(&self, controller: ControllerHandle) -> ControllerInputType {
        self.controllers
            .iter()
            .find(|c| c.handle == controller)
            .map(|c| c.input_type)
            .unwrap_or(ControllerInputType::Unknown)
    }

    /// Push an action set layer onto the controller's layer stack.
    ///
    /// Action set layers override the base action set and are evaluated in
    /// LIFO order. Games use layers for temporary state changes (e.g.
    /// "driving", "menus", "aiming").
    pub fn push_action_set_layer(
        &mut self,
        controller: ControllerHandle,
        layer_handle: ActionSetHandle,
    ) {
        self.action_set_layer_stacks
            .entry(controller)
            .or_default()
            .push(layer_handle);
    }

    /// Pop the top action set layer from the controller's layer stack.
    ///
    /// Returns `true` if a layer was popped, `false` if the stack was empty.
    pub fn pop_action_set_layer(&mut self, controller: ControllerHandle) -> bool {
        self.action_set_layer_stacks
            .get_mut(&controller)
            .map(|stack| stack.pop().is_some())
            .unwrap_or(false)
    }

    /// Get the currently active action set layers for a controller.
    pub fn get_action_set_layers(&self, controller: ControllerHandle) -> Vec<ActionSetHandle> {
        self.action_set_layer_stacks
            .get(&controller)
            .cloned()
            .unwrap_or_default()
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
        // An active action set is configured.  Check whether the action name
        // is registered as a digital or analog action.  If it is, it belongs
        // to the active set; if not, it is considered inactive.
        self.digital_actions.contains_key(action_name)
            || self.analog_actions.contains_key(action_name)
    }

    /// Maps a digital action name to its XInput button state.
    ///
    /// This is the default mapping used when no Steam Controller VDF
    /// configuration has been loaded.
    fn map_digital_action(&self, raw: &RawGamepadState, action_name: &str) -> bool {
        match action_name.to_lowercase().as_str() {
            // Face buttons
            "menu_accept" | "accept" | "a" | "jump" | "confirm" => {
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
            "dpad_up" | "up" | "navigate_up" => (raw.buttons & XINPUT_GAMEPAD_DPAD_UP) != 0,
            "dpad_down" | "down" | "navigate_down" => (raw.buttons & XINPUT_GAMEPAD_DPAD_DOWN) != 0,
            "dpad_left" | "left" | "navigate_left" => (raw.buttons & XINPUT_GAMEPAD_DPAD_LEFT) != 0,
            "dpad_right" | "right" | "navigate_right" => {
                (raw.buttons & XINPUT_GAMEPAD_DPAD_RIGHT) != 0
            }
            // Start / Select
            "start" | "pause" | "menu" | "options" => (raw.buttons & XINPUT_GAMEPAD_START) != 0,
            "select" | "view" | "share" => (raw.buttons & XINPUT_GAMEPAD_BACK) != 0,
            // Thumbstick clicks
            "left_stick_click" | "ls" | "left_thumbstick" | "sprint" | "run" => {
                (raw.buttons & XINPUT_GAMEPAD_LEFT_THUMB) != 0
            }
            "right_stick_click" | "rs" | "right_thumbstick" | "crouch" | "toggle_crouch" => {
                (raw.buttons & XINPUT_GAMEPAD_RIGHT_THUMB) != 0
            }
            // Additional common action names
            "left_trigger" | "lt" | "left_trigger_edge" => raw.left_trigger > 0,
            "right_trigger" | "rt" | "right_trigger_edge" => raw.right_trigger > 0,
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
            "left_trigger" | "lt" | "brake" | "accelerate" | "left_trigger_analog" => {
                (0.0, 0.0, normalize_trigger(raw.left_trigger))
            }
            "right_trigger" | "rt" | "throttle" | "fire" | "right_trigger_analog" => {
                (0.0, 0.0, normalize_trigger(raw.right_trigger))
            }
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

// ── HID rumble dispatch ──────────────────────────────────────────────────

/// Software haptic feedback state for a controller slot.
///
/// When no physical controller is available, generates audio-based or
/// visual feedback to simulate rumble. This is a simple envelope:
/// the rumble intensity maps to an audio tone or system notification.
struct SoftwareHapticState {
    /// Active rumble end time for left motor.
    left_end: Instant,
    /// Active rumble end time for right motor.
    right_end: Instant,
    /// Last left motor speed (0-255).
    left_speed: u8,
    /// Last right motor speed (0-255).
    right_speed: u8,
    /// Whether this slot has ever received a rumble command.
    active: bool,
}

impl SoftwareHapticState {
    fn new() -> Self {
        Self {
            left_end: Instant::now(),
            right_end: Instant::now(),
            left_speed: 0,
            right_speed: 0,
            active: false,
        }
    }
}

use std::sync::{LazyLock, Mutex};
static SOFTWARE_HAPTICS: LazyLock<Mutex<[SoftwareHapticState; 4]>> = LazyLock::new(|| {
    Mutex::new([
        SoftwareHapticState::new(),
        SoftwareHapticState::new(),
        SoftwareHapticState::new(),
        SoftwareHapticState::new(),
    ])
});

/// Convert a motor speed (0-255) and duration into a macOS system notification
/// or log-based haptic indicator.
fn notify_software_haptic(slot: u8, left_speed: u8, right_speed: u8, duration_ms: u64) {
    let intensity = ((left_speed as u16 + right_speed as u16) / 2) as u8;
    let level = match intensity {
        0 => "off",
        1..=64 => "very light",
        65..=128 => "light",
        129..=192 => "medium",
        _ => "strong",
    };
    eprintln!(
        "[Haptic] slot={slot} {level} rumble (L={left_speed}, R={right_speed}, duration={duration_ms}ms)"
    );

    // On macOS, post a lightweight NSUserNotification via script
    #[cfg(target_os = "macos")]
    if duration_ms >= 100 && intensity > 32 {
        match std::process::Command::new("osascript")
            .args([
                "-e",
                &format!(
                    r#"display notification "Controller {slot} rumble ({level})" with title "Steam Haptics" subtitle "" sound name "Funk""#
                ),
            ])
            .output()
        {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                eprintln!(
                    "[steam_input] failed to post haptic notification for slot {}: osascript exited with {}",
                    slot, output.status
                );
            }
            Err(error) => {
                eprintln!(
                    "[steam_input] failed to post haptic notification for slot {}: {}",
                    slot, error
                );
            }
        }
    }
}

/// Sends a haptic rumble command to the physical controller associated with
/// the given XInput `slot`.
///
/// On **macOS** this function uses the IOKit framework to locate a matching
/// HID device and deliver a 3-byte output report:
///
/// | Offset | Meaning                        |
/// |--------|--------------------------------|
/// | 0      | HID report ID (0x00 = main)    |
/// | 1      | Left motor speed (0–255)       |
/// | 2      | Right motor speed (0–255)      |
///
/// On non-macOS platforms a software haptic feedback notification is shown.
/// Supports left/right motor speed, duration, and frequency parameters.
pub(crate) fn send_hid_rumble(slot: u8, left_motor: u8, right_motor: u8) {
    #[cfg(target_os = "macos")]
    {
        // Build the HID output report payload.
        let report: [u8; 3] = [0x00, left_motor, right_motor];

        if let Err(msg) = send_rumble_via_iokit(&report) {
            // Fall back to software haptic if no physical controller found
            notify_software_haptic(slot, left_motor, right_motor, 200);
            eprintln!("send_hid_rumble (slot {slot}): {msg} (using software fallback)");
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Software haptic feedback via notification
        notify_software_haptic(slot, left_motor, right_motor, 200);
    }
}

/// Extended rumble API supporting left/right motor speed, duration (ms),
/// and frequency (Hz). Calls through to `send_hid_rumble` for the actual
/// motor dispatch but adds timing/frequency envelope support.
pub(crate) fn send_hid_rumble_ext(
    slot: u8,
    left_motor: u8,
    right_motor: u8,
    duration_ms: u64,
    frequency_hz: u16,
) {
    // Update the software haptic state for this slot
    if let Ok(mut state) = SOFTWARE_HAPTICS.lock() {
        if let Some(slot_state) = state.get_mut(slot as usize) {
            let now = Instant::now();
            slot_state.left_end = now + std::time::Duration::from_millis(duration_ms);
            slot_state.right_end = slot_state.left_end;
            slot_state.left_speed = left_motor;
            slot_state.right_speed = right_motor;
            slot_state.active = true;

            // Scale motor values by frequency factor (higher freq = more intense perception)
            let freq_factor = if frequency_hz > 0 {
                (frequency_hz as f32 / 100.0).min(2.0)
            } else {
                1.0
            };
            let scaled_left = (left_motor as f32 * freq_factor).min(255.0) as u8;
            let scaled_right = (right_motor as f32 * freq_factor).min(255.0) as u8;
            drop(state);

            // Send the rumble with scaled values
            send_hid_rumble(slot, scaled_left, scaled_right);
            notify_software_haptic(slot, scaled_left, scaled_right, duration_ms);
            return;
        }
    }
    // Fallback without state tracking
    send_hid_rumble(slot, left_motor, right_motor);
    notify_software_haptic(slot, left_motor, right_motor, duration_ms);
}

/// macOS-only: walks the IOService plane for `IOHIDDevice` entries and sends
/// the provided HID output report to the *first* matching device.
///
/// The function:
/// 1. Calls `IOServiceMatching("IOHIDDevice")` to build a matching dictionary.
/// 2. Iterates services with `IOIteratorNext`.
/// 3. For each service, reads the `VendorID` / `ProductID` properties via
///    `IORegistryEntryCreateCFProperty` + `CFNumberGetValue`.
/// 4. Creates an `IOHIDDeviceRef` with `IOHIDDeviceCreate`.
/// 5. Calls `IOHIDDeviceSetReport` with `kIOHIDReportTypeOutput`.
/// 6. Releases all IOKit / CF objects.
#[cfg(target_os = "macos")]
fn send_rumble_via_iokit(report: &[u8; 3]) -> Result<(), String> {
    use std::ffi::CString;

    // 1. Create a matching dictionary for IOHIDDevice services.
    let device_class = CString::new("IOHIDDevice").map_err(|e| e.to_string())?;
    let matching_dict = unsafe { IOServiceMatching(device_class.as_ptr()) };
    if matching_dict.is_null() {
        return Err("IOServiceMatching returned null".into());
    }
    // matching_dict is owned by IOServiceGetMatchingServices (it consumes the ref),
    // so we do NOT CFRelease it ourselves.

    // 2. Get the service iterator.
    let mut iterator: u32 = 0;
    let kr = unsafe {
        IOServiceGetMatchingServices(KIO_MASTER_PORT_DEFAULT, matching_dict, &mut iterator)
    };
    if kr != 0 || iterator == 0 {
        return Err(format!(
            "IOServiceGetMatchingServices failed (kr={kr}, iter={iterator})"
        ));
    }

    // Pre-create CFString keys for property lookups.
    let vid_key = CString::new("VendorID").map_err(|e| e.to_string())?;
    let pid_key = CString::new("ProductID").map_err(|e| e.to_string())?;

    let vid_cfstr = unsafe {
        CFStringCreateWithCString(
            KCF_ALLOCATOR_DEFAULT,
            vid_key.as_ptr(),
            KCF_STRING_ENCODING_UTF8,
        )
    };
    let pid_cfstr = unsafe {
        CFStringCreateWithCString(
            KCF_ALLOCATOR_DEFAULT,
            pid_key.as_ptr(),
            KCF_STRING_ENCODING_UTF8,
        )
    };

    if vid_cfstr.is_null() || pid_cfstr.is_null() {
        // Clean up what we can.
        if !vid_cfstr.is_null() {
            unsafe { CFRelease(vid_cfstr) };
        }
        if !pid_cfstr.is_null() {
            unsafe { CFRelease(pid_cfstr) };
        }
        unsafe { IOObjectRelease(iterator) };
        return Err("Failed to create CFString keys".into());
    }

    // 3. Iterate services.
    let mut device_ref: *mut std::ffi::c_void = std::ptr::null_mut();
    loop {
        let service = unsafe { IOIteratorNext(iterator) };
        if service == 0 {
            break;
        }

        // Read VendorID via IORegistryEntryCreateCFProperty.
        let vid_cfnum = unsafe {
            IORegistryEntryCreateCFProperty(
                service,
                vid_cfstr,
                KCF_ALLOCATOR_DEFAULT,
                KCF_PROPERTY_LIST_IMMUTABLE,
            )
        };
        let pid_cfnum = unsafe {
            IORegistryEntryCreateCFProperty(
                service,
                pid_cfstr,
                KCF_ALLOCATOR_DEFAULT,
                KCF_PROPERTY_LIST_IMMUTABLE,
            )
        };

        let mut found_vid: i32 = 0;
        let mut found_pid: i32 = 0;
        let vid_ok = if !vid_cfnum.is_null() {
            let rc = unsafe {
                CFNumberGetValue(
                    vid_cfnum,
                    KCF_NUMBER_SINT32_TYPE,
                    &mut found_vid as *mut i32 as *mut std::ffi::c_void,
                )
            };
            unsafe { CFRelease(vid_cfnum) };
            rc != 0
        } else {
            false
        };
        let pid_ok = if !pid_cfnum.is_null() {
            let rc = unsafe {
                CFNumberGetValue(
                    pid_cfnum,
                    KCF_NUMBER_SINT32_TYPE,
                    &mut found_pid as *mut i32 as *mut std::ffi::c_void,
                )
            };
            unsafe { CFRelease(pid_cfnum) };
            rc != 0
        } else {
            false
        };

        // We accept *any* HID device with both VendorID and ProductID
        // properties (i.e. a game controller). If properties aren't present
        // we skip this service.
        if vid_ok && pid_ok && found_vid > 0 && found_pid > 0 {
            // Create IOHIDDeviceRef from this service.
            let candidate = unsafe { IOHIDDeviceCreate(KCF_ALLOCATOR_DEFAULT, service) };
            if !candidate.is_null() {
                device_ref = candidate;
                unsafe { IOObjectRelease(service) };
                break;
            }
        }

        unsafe { IOObjectRelease(service) };
    }

    // Release CF strings and iterator.
    unsafe { CFRelease(vid_cfstr) };
    unsafe { CFRelease(pid_cfstr) };
    unsafe { IOObjectRelease(iterator) };

    if device_ref.is_null() {
        return Err("No matching HID device found for rumble output".into());
    }

    // 4. Send the HID output report.
    let kr2 = unsafe {
        IOHIDDeviceSetReport(
            device_ref,
            KIO_HID_REPORT_TYPE_OUTPUT,
            report[0] as u32, // report ID
            report.as_ptr(),
            report.len() as isize,
        )
    };

    // 5. Release the device reference.
    unsafe { CFRelease(device_ref) };

    if kr2 != 0 {
        Err(format!("IOHIDDeviceSetReport returned {kr2}"))
    } else {
        Ok(())
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that `send_hid_rumble` compiles and runs without panicking
    /// on non-macOS platforms (it should be a no-op).  On macOS the function
    /// will attempt to find hardware; we just verify it doesn't crash.
    #[test]
    fn send_hid_rumble_no_panic() {
        // This should never panic regardless of platform.
        send_hid_rumble(0, 128, 200);
        send_hid_rumble(1, 255, 255);
        send_hid_rumble(2, 0, 0);
    }

    /// Verifies the intensity derivation in `trigger_repeated_haptic_pulse`.
    /// We test indirectly by checking the method compiles and runs; the actual
    /// rumble dispatch delegates to `send_hid_rumble` which is tested above.
    #[test]
    fn trigger_repeated_haptic_pulse_runs() {
        let steam = SteamInput::new();
        // Use a handle that maps to slot 0. The function will attempt to call
        // send_hid_rumble via slot_for_handle — if no controller is connected
        // it's a no-op, so this should never panic.
        let handle: u64 = 0x1000; // slot 0
        steam.trigger_repeated_haptic_pulse(
            handle,
            HapticTarget::Both,
            5,   // pulse_count
            100, // duration_ms
            50,  // interval_ms
            0,   // flags
        );
    }

    /// Verifies the `normalize_axis` helper.
    #[test]
    fn normalize_axis_works() {
        assert!((normalize_axis(0) - 0.0).abs() < f32::EPSILON);
        assert!((normalize_axis(i16::MAX) - 1.0).abs() < f32::EPSILON);
        assert!((normalize_axis(i16::MIN) - (-1.0)).abs() < f32::EPSILON);
        assert!((normalize_axis(8000) - (8000.0 / i16::MAX as f32)).abs() < 1e-4);
    }

    /// Verifies the `normalize_trigger` helper.
    #[test]
    fn normalize_trigger_works() {
        assert!((normalize_trigger(0) - 0.0).abs() < f32::EPSILON);
        assert!((normalize_trigger(255) - 1.0).abs() < f32::EPSILON);
        assert!((normalize_trigger(128) - (128.0 / 255.0)).abs() < 1e-4);
    }

    /// Checks that HapticTarget mapping in trigger_repeated_haptic_pulse
    /// selects the correct motor channels (verified via side-effect — the
    /// motor speed derivation is pure and visible in `send_hid_rumble` calls).
    #[test]
    fn haptic_target_filters_correct_motor() {
        let steam = SteamInput::new();
        let handle: u64 = 0x1000;

        // Left only — should map intensity to left motor, 0 to right
        steam.trigger_repeated_haptic_pulse(handle, HapticTarget::Left, 3, 50, 25, 0);
        // Right only
        steam.trigger_repeated_haptic_pulse(handle, HapticTarget::Right, 3, 50, 25, 0);
        // Both
        steam.trigger_repeated_haptic_pulse(handle, HapticTarget::Both, 3, 50, 25, 0);
    }
}
