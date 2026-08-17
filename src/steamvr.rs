//! SteamVR / OpenVR API emulation layer (openvr_api.dll bridge).
//!
//! Provides a virtual HMD implementation so guest games using SteamVR can
//! interact with a stationary virtual headset at the world origin.
//!
//! # Design constraints
//! - **Virtual HMD only** — no actual VR headset connected
//! - **Valve Index specs**: 1512×1680 per eye, 90 Hz, ~0.063 m IPD
//! - **IOSurface texture sharing** (macOS native GPU memory)
//! - **Static poses**: HMD at origin facing −Z, no motion controllers
//!
//! # Key constants
//! | Constant | Value |
//! |---|---|
//! | `k_unTrackedDeviceIndex_Hmd` | 0 |
//! | `k_unMaxTrackedDeviceCount` | 16 |
//! | `ETrackingResult_Running_OK` | 200 |
//! | `ETextureType_IOSurface` | 5 |
//! | `VR_InitError_None` | 0 |
//! | `TrackedDeviceClass_HMD` | 0 |
//! | `TrackedDeviceClass_Invalid` | 5 |

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use serde_json::Value;

// ── OpenVR constants ──────────────────────────────────────────────────────

/// Maximum number of tracked devices (OpenVR constant).
pub const K_UN_MAX_TRACKED_DEVICE_COUNT: usize = 16;

/// HMD tracked device index.
pub const K_UN_TRACKED_DEVICE_INDEX_HMD: u32 = 0;

/// Tracking result: running OK.
pub const E_TRACKING_RESULT_RUNNING_OK: u32 = 200;

/// Tracking result: uninitialized.
pub const E_TRACKING_RESULT_UNINITIALIZED: u32 = 1;

/// Texture type: IOSurface (macOS native GPU memory sharing).
pub const E_TEXTURE_TYPE_IOSURFACE: u32 = 5;

/// Color space: auto.
pub const E_COLOR_SPACE_AUTO: u32 = 0;

/// VR init error: none (success).
pub const VR_INIT_ERROR_NONE: u32 = 0;

/// VR init error: HMD not found.
pub const VR_INIT_ERROR_INIT_HMD_NOT_FOUND: u32 = 101;

/// Tracked device class: HMD.
pub const TRACKED_DEVICE_CLASS_HMD: u32 = 0;

/// Tracked device class: controller.
pub const TRACKED_DEVICE_CLASS_CONTROLLER: u32 = 1;

/// Tracked device class: invalid.
pub const TRACKED_DEVICE_CLASS_INVALID: u32 = 5;

/// IVRSystem interface version string.
pub const IVR_SYSTEM_VERSION: &str = "IVRSystem_019";

/// IVRCompositor interface version string.
pub const IVR_COMPOSITOR_VERSION: &str = "IVRCompositor_022";

/// IVRChaperone interface version string.
pub const IVR_CHAPERONE_VERSION: &str = "IVRChaperone_003";

/// Recommended render target width (Valve Index: 1512 per eye).
pub const RENDER_TARGET_WIDTH: u32 = 1512;

/// Recommended render target height (Valve Index: 1680 per eye).
pub const RENDER_TARGET_HEIGHT: u32 = 1680;

/// Inter-pupillary distance in meters (Valve Index default ~63 mm).
pub const IPD: f32 = 0.063;

/// Half IPD for eye offset.
pub const HALF_IPD: f32 = IPD / 2.0;

/// Refresh rate in Hz.
pub const REFRESH_RATE_HZ: f32 = 90.0;

/// Frame duration in seconds.
pub const FRAME_DURATION_SECS: f32 = 1.0 / REFRESH_RATE_HZ;

/// Approximate projection half-width/height (symmetric frustum).
pub const PROJECTION_HALF: f32 = 0.07;

// ── TrackedDeviceProperty enum values ─────────────────────────────────────

/// Prop: manufacturer name (string).
pub const PROP_MANUFACTURER_NAME: u32 = 1000;
/// Prop: model number (string).
pub const PROP_MODEL_NUMBER: u32 = 1001;
/// Prop: serial number (string).
pub const PROP_SERIAL_NUMBER: u32 = 1002;
/// Prop: tracking system name (string).
pub const PROP_TRACKING_SYSTEM_NAME: u32 = 1004;
/// Prop: render model name (string).
pub const PROP_RENDER_MODEL_NAME: u32 = 1003;
/// Prop: reported IPD (float, metres).
pub const PROP_USER_IPD_M: u32 = 1005;
/// Prop: vertical FOV (float, degrees).
pub const PROP_FIELD_OF_VIEW_TOP_DEGREES: u32 = 1014;
/// Prop: vertical FOV bottom (float, degrees).
pub const PROP_FIELD_OF_VIEW_BOTTOM_DEGREES: u32 = 1015;
/// Prop: horizontal FOV left (float, degrees).
pub const PROP_FIELD_OF_VIEW_LEFT_DEGREES: u32 = 1016;
/// Prop: horizontal FOV right (float, degrees).
pub const PROP_FIELD_OF_VIEW_RIGHT_DEGREES: u32 = 1017;
/// Prop: refresh rate (float, Hz).
pub const PROP_DISPLAY_REFRESH_RATE: u32 = 1018;
/// Prop: will drift in yaw (bool).
pub const PROP_WILL_DRIFT_IN_YAW: u32 = 1019;
/// Prop: display width (float, metres).
pub const PROP_DISPLAY_WIDTH: u32 = 1020;
/// Prop: display height (float, metres).
pub const PROP_DISPLAY_HEIGHT: u32 = 1021;
/// Prop: display frequency (float).
pub const PROP_DISPLAY_FREQUENCY: u32 = 1026;
/// Prop: adapter index (int32).
pub const PROP_ADAPTER_INDEX: u32 = 1030;
/// Prop: supported graphics APIs (string).
pub const PROP_SUPPORTED_GRAPHICS_API: u32 = 1031;
/// Prop: driver version (string).
pub const PROP_DRIVER_VERSION: u32 = 1027;
/// Prop: device is wireless (bool).
pub const PROP_DEVICE_IS_WIRELESS: u32 = 1050;
/// Prop: device provides battery status (bool).
pub const PROP_DEVICE_PROVIDES_BATTERY_STATUS: u32 = 1051;
/// Prop: device can power off (bool).
pub const PROP_DEVICE_CAN_POWER_OFF: u32 = 1052;
/// Prop: device battery percentage (float).
pub const PROP_DEVICE_BATTERY_PERCENTAGE: u32 = 1053;
/// Prop: firmware update available (bool).
pub const PROP_FIRMWARE_UPDATE_AVAILABLE: u32 = 1054;
/// Prop: firmware manual update (bool).
pub const PROP_FIRMWARE_MANUAL_UPDATE: u32 = 1055;
/// Prop: tracking result (int32).
pub const PROP_TRACKING_RESULT: u32 = 1100;
/// Prop: controller role hint (int32).
pub const PROP_CONTROLLER_ROLE_HINT: u32 = 1500;
/// Prop: device class (int32).
pub const PROP_DEVICE_CLASS: u32 = 1501;

// ── Tracked device pose ──────────────────────────────────────────────────

// ── Controller state ─────────────────────────────────────────────────────

/// Controller state returned via `GetControllerState`.
///
/// The serialized form matches `vr::VRControllerState_t`:
/// `{ u32 unPacketNum; u64 ulButtonPressed; u64 ulButtonTouched;
///    VRControllerAxis_t rAxis[5]; }` (60 bytes) where `VRControllerAxis_t`
/// is `{ f32 x; f32 y; }`. The real struct has **no** axis-type array, so
/// `ul_axis_type` is kept only as internal bookkeeping and is not serialized.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct ControllerState {
    /// Packet number, incremented on each state change.
    pub packet_num: u32,
    /// Bitmask of currently pressed buttons (`ButtonMaskFromId`).
    pub ul_button_pressed: u64,
    /// Bitmask of currently touched buttons.
    pub ul_button_touched: u64,
    /// Analog axis positions: 5 axes (joystick X/Y, trigger, etc.). Axes are
    /// stored one `f32` per component; `to_bytes` interleaves them as
    /// `(x, y)` pairs to match `VRControllerAxis_t[5]`.
    pub r_axis: [f32; 5],
    /// Axis type identifiers (e.g. `k_eControllerAxis_Joystick`,
    /// `k_eControllerAxis_Trigger`). Internal bookkeeping only — not part of
    /// the guest-visible struct.
    pub ul_axis_type: [u32; 5],
}

impl ControllerState {
    /// Size in bytes when serialized to guest memory
    /// (4 + 8 + 8 + 5 * (4 + 4) = 60).
    pub fn guest_size() -> usize {
        4 + 8 + 8 + 5 * 4 * 2
    }

    /// Serialize to bytes for guest memory write.
    ///
    /// Emits the real `VRControllerState_t` layout: the 20-byte header,
    /// then 5 `VRControllerAxis_t` `(x, y)` float pairs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::guest_size());
        bytes.extend_from_slice(&self.packet_num.to_le_bytes());
        bytes.extend_from_slice(&self.ul_button_pressed.to_le_bytes());
        bytes.extend_from_slice(&self.ul_button_touched.to_le_bytes());
        // 5 axes × (x, y): axis 0 = (r_axis[0], r_axis[1]), axis 1 =
        // (r_axis[2], r_axis[3]), axis 2 = (r_axis[4], 0.0) etc.
        for axis_index in 0..5 {
            let x = self.r_axis.get(axis_index * 2).copied().unwrap_or(0.0);
            let y = self.r_axis.get(axis_index * 2 + 1).copied().unwrap_or(0.0);
            bytes.extend_from_slice(&x.to_le_bytes());
            bytes.extend_from_slice(&y.to_le_bytes());
        }
        bytes
    }
}

/// Raw controller input snapshot for one hand, driving the VR controller
/// emulation from Steam Input / XInput-style data.
#[derive(Clone, Copy, Debug, Default)]
pub struct ControllerInputSnapshot {
    /// XInput-style button bitmask.
    pub buttons: u16,
    /// Analog trigger value (0–255).
    pub trigger: u8,
    /// Thumb stick X (-32768–32767).
    pub thumb_lx: i16,
    /// Thumb stick Y (-32768–32767).
    pub thumb_ly: i16,
}

// ── OpenVR axis type constants ───────────────────────────────────────────
/// Axis type: joystick or thumbstick.
pub const CONTROLLER_AXIS_JOYSTICK: u32 = 0;
/// Axis type: trigger.
pub const CONTROLLER_AXIS_TRIGGER: u32 = 2;

// ── OpenVR controller button mask constants ──────────────────────────────

/// System button (Steam button).
pub const BUTTON_SYSTEM: u64 = 0x001;
/// Application menu button.
pub const BUTTON_APPLICATION_MENU: u64 = 0x002;
/// Grip button (left/right).
pub const BUTTON_GRIP: u64 = 0x004;
/// D-pad left.
pub const BUTTON_DPAD_LEFT: u64 = 0x008;
/// D-pad up.
pub const BUTTON_DPAD_UP: u64 = 0x010;
/// D-pad right.
pub const BUTTON_DPAD_RIGHT: u64 = 0x020;
/// D-pad down.
pub const BUTTON_DPAD_DOWN: u64 = 0x040;
/// A button (Vive controller).
pub const BUTTON_A: u64 = 0x080;
/// Touchpad / joystick click (real `k_EButton_SteamVR_Touchpad` mask).
pub const BUTTON_TOUCHPAD: u64 = 0x1000;
/// Axis 0 (joystick X).
pub const BUTTON_AXIS0: u64 = 0x200;
/// Axis 1 (joystick Y).
pub const BUTTON_AXIS1: u64 = 0x400;
/// Axis 2 (trigger).
pub const BUTTON_AXIS2: u64 = 0x800;
/// Axis 3.
pub const BUTTON_AXIS3: u64 = 0x2000;

/// VREvent type: button press.
pub const VREVENT_BUTTON_PRESS: u32 = 200;
/// VREvent type: button unpress (release).
pub const VREVENT_BUTTON_UNPRESS: u32 = 201;

// ── OpenVR interface version strings for IVRController and IVRInput ──────

/// IVRController interface version string.
pub const IVR_CONTROLLER_VERSION: &str = "IVRController_002";
/// IVRInput interface version string.
pub const IVR_INPUT_VERSION: &str = "IVRInput_003";
/// IVRRenderModels interface version string.
pub const IVR_RENDER_MODELS_VERSION: &str = "IVRRenderModels_005";

// ── Action manifest types ─────────────────────────────────────────────────

/// Cached action manifest entry (from `SetActionManifestPath`).
#[derive(Clone, Debug)]
pub struct ActionManifestEntry {
    pub handle: u64,
    pub kind: ActionKind,
    pub name: String,
    pub path: String,
}

/// Type of action in the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionKind {
    Digital,
    Analog,
    Other,
}

// ── Tracked device pose ──────────────────────────────────────────────────

/// Tracked device pose returned to guest (matches `vr::TrackedDevicePose_t` layout).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TrackedDevicePose {
    /// 3×4 row-major device-to-absolute-tracking matrix.
    pub device_to_absolute_tracking: [f32; 12],
    /// Linear velocity (m/s).
    pub velocity: [f32; 3],
    /// Angular velocity (rad/s).
    pub angular_velocity: [f32; 3],
    /// `ETrackingResult` enum value.
    pub tracking_result: u32,
    /// Whether the pose is valid (non-zero = true).
    pub pose_is_valid: u32,
    /// Device pose index.
    pub pose_index: u32,
    /// Raw device-to-absolute-tracking (before driver processing).
    pub raw_device_to_absolute_tracking: [f32; 12],
}

impl Default for TrackedDevicePose {
    fn default() -> Self {
        Self {
            device_to_absolute_tracking: [0.0; 12],
            velocity: [0.0; 3],
            angular_velocity: [0.0; 3],
            tracking_result: E_TRACKING_RESULT_UNINITIALIZED,
            pose_is_valid: 0,
            pose_index: 0,
            raw_device_to_absolute_tracking: [0.0; 12],
        }
    }
}

impl TrackedDevicePose {
    /// Returns the size of this struct in bytes when serialized to guest memory.
    /// 12*4 + 3*4 + 3*4 + 4 + 4 + 4 + 12*4 = 48 + 12 + 12 + 4 + 4 + 4 + 48 = 132 bytes.
    pub fn guest_size() -> usize {
        132
    }

    /// Creates a valid stationary HMD pose at the world origin facing −Z.
    pub fn stationary_hmd() -> Self {
        let mut pose = Self::default();
        // Identity 3×4 matrix (row-major): [[1,0,0,0],[0,1,0,0],[0,0,1,0]]
        pose.device_to_absolute_tracking[0] = 1.0; // m[0][0]
        pose.device_to_absolute_tracking[5] = 1.0; // m[1][1]
        pose.device_to_absolute_tracking[10] = 1.0; // m[2][2]
        pose.raw_device_to_absolute_tracking = pose.device_to_absolute_tracking;
        pose.tracking_result = E_TRACKING_RESULT_RUNNING_OK;
        pose.pose_is_valid = 1;
        pose
    }

    /// Default left controller pose: position (-0.25, -0.5, -0.3), identity
    /// rotation, relative to HMD space.
    pub fn default_controller_left() -> Self {
        let mut pose = Self::default();
        // Identity 3×3 rotation + translation (-0.25, -0.5, -0.3)
        pose.device_to_absolute_tracking[0] = 1.0; // m[0][0]
        pose.device_to_absolute_tracking[3] = -0.25; // m[0][3] = x
        pose.device_to_absolute_tracking[5] = 1.0; // m[1][1]
        pose.device_to_absolute_tracking[7] = -0.5; // m[1][3] = y
        pose.device_to_absolute_tracking[10] = 1.0; // m[2][2]
        pose.device_to_absolute_tracking[11] = -0.3; // m[2][3] = z
        pose.raw_device_to_absolute_tracking = pose.device_to_absolute_tracking;
        pose.tracking_result = E_TRACKING_RESULT_RUNNING_OK;
        pose.pose_is_valid = 1;
        pose.pose_index = 1;
        pose
    }

    /// Default right controller pose: position (0.25, -0.5, -0.3), identity
    /// rotation, relative to HMD space.
    pub fn default_controller_right() -> Self {
        let mut pose = Self::default();
        // Identity 3×3 rotation + translation (0.25, -0.5, -0.3)
        pose.device_to_absolute_tracking[0] = 1.0; // m[0][0]
        pose.device_to_absolute_tracking[3] = 0.25; // m[0][3] = x
        pose.device_to_absolute_tracking[5] = 1.0; // m[1][1]
        pose.device_to_absolute_tracking[7] = -0.5; // m[1][3] = y
        pose.device_to_absolute_tracking[10] = 1.0; // m[2][2]
        pose.device_to_absolute_tracking[11] = -0.3; // m[2][3] = z
        pose.raw_device_to_absolute_tracking = pose.device_to_absolute_tracking;
        pose.tracking_result = E_TRACKING_RESULT_RUNNING_OK;
        pose.pose_is_valid = 1;
        pose.pose_index = 2;
        pose
    }

    /// Writes the pose to a byte slice for guest memory.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::guest_size());
        for &f in &self.device_to_absolute_tracking {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
        for &f in &self.velocity {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
        for &f in &self.angular_velocity {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
        bytes.extend_from_slice(&self.tracking_result.to_le_bytes());
        bytes.extend_from_slice(&self.pose_is_valid.to_le_bytes());
        bytes.extend_from_slice(&self.pose_index.to_le_bytes());
        for &f in &self.raw_device_to_absolute_tracking {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
        bytes
    }
}

// ── Texture structure ────────────────────────────────────────────────────

/// Texture structure passed to `Submit` (matches `vr::Texture_t` layout).
#[derive(Clone, Debug)]
#[repr(C)]
pub struct VRTexture {
    /// IOSurface ID or texture handle.
    pub handle: u64,
    /// `ETextureType` (5 = IOSurface on macOS).
    pub e_type: u32,
    /// `EColorSpace`.
    pub e_color_space: u32,
}

// ── Compositor frame timing ──────────────────────────────────────────────

/// Compositor frame timing returned via `GetFrameTiming`.
///
/// NOTE: the real OpenVR `Compositor_FrameTiming` (a long sequence of
/// `m_n...`/`m_fl...` counters, `m_nSize` first) is not mirrored here — the
/// dispatch layer (pe_runtime.rs) serializes this struct field-by-field into
/// guest memory, so changing the layout requires a coordinated change there.
/// `size` still carries `sizeof(CompositorFrameTiming)` per the OpenVR
/// convention so guests can version-check the struct.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct CompositorFrameTiming {
    /// `sizeof(CompositorFrameTiming)`.
    pub size: u32,
    /// Frame identifier.
    pub frame_id: u32,
    /// Frame index.
    pub frame_index: u32,
    /// Total frame count.
    pub num_frames: u32,
    /// CPU frame count.
    pub num_frames_cpu: u32,
    /// GPU frame count.
    pub num_frames_gpu: u32,
    /// Early frame count.
    pub num_frames_early: u32,
    /// Idle frame count.
    pub num_frames_idle: u32,
    /// Minimum frame count.
    pub num_frames_min: u32,
    /// Maximum frame count.
    pub num_frames_max: u32,
    /// Dropped frame count.
    pub num_frames_dropped: u32,
    /// Total frame time in milliseconds.
    pub total_milliseconds: f32,
    /// Milliseconds per frame.
    pub milliseconds_per_frame: f32,
    /// Per-frame GPU timing (up to 8 frames).
    pub milliseconds_gpu: [f32; 8],
    /// Per-frame CPU timing (up to 8 frames).
    pub milliseconds_cpu: [f32; 8],
    /// Per-frame idle timing (up to 8 frames).
    pub milliseconds_idle: [f32; 8],
}

impl Default for CompositorFrameTiming {
    fn default() -> Self {
        Self {
            size: std::mem::size_of::<CompositorFrameTiming>() as u32,
            frame_id: 0,
            frame_index: 0,
            num_frames: 0,
            num_frames_cpu: 0,
            num_frames_gpu: 0,
            num_frames_early: 0,
            num_frames_idle: 0,
            num_frames_min: 0,
            num_frames_max: 0,
            num_frames_dropped: 0,
            total_milliseconds: FRAME_DURATION_SECS * 1000.0,
            milliseconds_per_frame: FRAME_DURATION_SECS * 1000.0,
            milliseconds_gpu: [0.0; 8],
            milliseconds_cpu: [0.0; 8],
            milliseconds_idle: [0.0; 8],
        }
    }
}

// ── Compositor cumulative stats ──────────────────────────────────────────

/// Compositor cumulative statistics returned via `GetCumulativeStats`.
///
/// NOTE: as with [`CompositorFrameTiming`], the real OpenVR
/// `Compositor_CumulativeStats` layout is not mirrored here because the
/// dispatch layer (pe_runtime.rs) serializes this struct field-by-field;
/// mirroring it requires a coordinated change there.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct CompositorCumulativeStats {
    /// `sizeof(CompositorCumulativeStats)`.
    pub size: u32,
    /// Total number of frames presented.
    pub num_frames: u32,
    /// Frames rendered on CPU.
    pub num_frames_cpu: u32,
    /// Frames rendered on GPU.
    pub num_frames_gpu: u32,
    /// Frames submitted early.
    pub num_frames_early: u32,
    /// Frames spent idle.
    pub num_frames_idle: u32,
    /// Minimum frame count.
    pub num_frames_min: u32,
    /// Maximum frame count.
    pub num_frames_max: u32,
    /// Dropped frames.
    pub num_frames_dropped: u32,
    /// Total time in milliseconds.
    pub total_milliseconds: f32,
    /// Average milliseconds per frame.
    pub milliseconds_per_frame: f32,
    /// Padding to 64+ bytes.
    pub _padding: [u8; 20],
}

impl Default for CompositorCumulativeStats {
    fn default() -> Self {
        Self {
            size: std::mem::size_of::<CompositorCumulativeStats>() as u32,
            num_frames: 0,
            num_frames_cpu: 0,
            num_frames_gpu: 0,
            num_frames_early: 0,
            num_frames_idle: 0,
            num_frames_min: 0,
            num_frames_max: 0,
            num_frames_dropped: 0,
            total_milliseconds: 0.0,
            milliseconds_per_frame: 0.0,
            _padding: [0; 20],
        }
    }
}

// ── VR event ─────────────────────────────────────────────────────────────

/// `VREvent` structure (mirrors `vr::VREvent_t` layout).
///
/// The real `VREvent_Data_t` union is 64 bytes (`VREvent_Reserved_t` is the
/// largest member), making `VREvent_t` 80 bytes with 8-byte alignment. The
/// button mask for button events lives at `data[0..4]` (`VREvent_Controller_t
/// .button`).
#[derive(Clone, Debug)]
#[repr(C)]
pub struct VREvent {
    /// Event type enum value.
    pub event_type: u32,
    /// Index of the tracked device that generated the event.
    pub tracked_device_index: u32,
    /// Age of the event in seconds.
    pub event_age_seconds: f32,
    /// Raw event data union (`VREvent_Data_t`, 64 bytes).
    pub data: [u8; 64],
}

impl Default for VREvent {
    fn default() -> Self {
        Self {
            event_type: 0,
            tracked_device_index: 0,
            event_age_seconds: 0.0,
            data: [0; 64],
        }
    }
}

impl VREvent {
    /// Sets the button mask carried by `VREvent_ButtonPress` /
    /// `VREvent_ButtonUnpress` events, i.e. the `data.controller.button`
    /// member of the real union.
    pub fn set_button_mask(&mut self, mask: u64) {
        self.data[..8].copy_from_slice(&mask.to_le_bytes());
    }

    /// Reads the button mask from `data.controller.button`.
    pub fn button_mask(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[..8]);
        u64::from_le_bytes(bytes)
    }
}

// ── HMD tracking state ──────────────────────────────────────────────────

/// HMD tracking state for all tracked devices.
#[derive(Default)]
pub struct VRTrackingState {
    /// Poses for up to `k_unMaxTrackedDeviceCount` devices.
    pub poses: [TrackedDevicePose; K_UN_MAX_TRACKED_DEVICE_COUNT],
}

// ── Compositor state ────────────────────────────────────────────────────

/// Compositor internal state.
#[derive(Default)]
pub struct VRCompositorState {
    /// Last submitted frame index.
    pub last_frame_index: u32,
    /// Frame timing data.
    pub frame_timing: CompositorFrameTiming,
    /// Cumulative statistics.
    pub cumulative_stats: CompositorCumulativeStats,
    /// Last `Submit` result (`EVRCompositorError`).
    pub last_submit_result: u32,
    /// Explicit timing mode (0 = disabled).
    pub explicit_timing_mode: u32,
    /// Last pose used for explicit timing.
    pub explicit_timing_last_pose: TrackedDevicePose,
}

// ── Chaperone state ─────────────────────────────────────────────────────

/// Chaperone (play area) state.
pub struct VRChaperoneState {
    /// Calibration state (0 = OK / Calibrated).
    pub calibration_state: u32,
    /// Play area size in metres: [width, depth].
    pub play_area_size: [f32; 2],
    /// Play area rectangle corners: [x0, z0, x1, z1] (4 values).
    pub play_area_rect: [f32; 4],
}

impl Default for VRChaperoneState {
    fn default() -> Self {
        Self {
            calibration_state: 0,
            play_area_size: [2.0, 1.5],
            play_area_rect: [1.0, 0.75, -1.0, -0.75],
        }
    }
}

// ── Controller properties constants ──────────────────────────────────────
//
// NOTE: no `Prop_FirmwareVersion` / `Prop_HardwareRevision` constants exist
// in real OpenVR — property IDs 1054/1055 are `Prop_Firmware_UpdateAvailable`
// / `Prop_Firmware_ManualUpdate` (bools). The invented int32 properties were
// removed so guests querying the real IDs get consistent answers.

// ── Main SteamVR state container ────────────────────────────────────────

/// Main SteamVR state container.
pub struct SteamVR {
    /// Whether VR has been initialized.
    pub initialized: bool,
    /// Whether the virtual HMD is enabled.
    pub hmd_enabled: bool,
    /// Monotonically increasing frame index.
    pub frame_index: u64,
    /// VSync timestamp in nanoseconds.
    pub vsync_time_ns: u64,
    /// Timestamp of the last frame.
    pub last_frame_time: Instant,
    /// Compositor state.
    pub compositor_state: VRCompositorState,
    /// Tracking state.
    pub tracking_state: VRTrackingState,
    /// Chaperone state.
    pub chaperone_state: VRChaperoneState,
    /// Left controller pose (device index 1).
    pub left_controller: Option<TrackedDevicePose>,
    /// Right controller pose (device index 2).
    pub right_controller: Option<TrackedDevicePose>,
    /// Left controller state.
    pub left_controller_state: ControllerState,
    /// Right controller state.
    pub right_controller_state: ControllerState,
    /// Previous left controller button mask for VREvent generation.
    pub prev_left_buttons: u64,
    /// Previous right controller button mask for VREvent generation.
    pub prev_right_buttons: u64,
    /// Pending VR events queue (FIFO).
    pub pending_events: VecDeque<VREvent>,
    /// Controller serial number for device index 1.
    pub left_serial: String,
    /// Controller serial number for device index 2.
    pub right_serial: String,
    /// Cached action manifest entries (persisted across dispatch calls).
    pub action_manifest: Vec<ActionManifestEntry>,
    /// Next available action handle.
    pub next_handle: u64,
    /// Loaded render models: handle -> (model_name, model_data).
    pub loaded_render_models: BTreeMap<u64, (String, Vec<u8>)>,
    /// Render model texture data: handle -> (width, height, rgba_data).
    pub loaded_render_model_textures: BTreeMap<u64, (u32, u32, Vec<u8>)>,
    /// Next render model handle.
    pub next_render_model_handle: u64,
    /// Last submitted texture handle per eye (index 0 = left, 1 = right).
    pub last_submitted_texture_per_eye: [u64; 2],
}

impl SteamVR {
    /// Creates a new uninitialized SteamVR state.
    pub fn new() -> Self {
        Self {
            initialized: false,
            hmd_enabled: false,
            frame_index: 0,
            vsync_time_ns: 0,
            last_frame_time: Instant::now(),
            compositor_state: VRCompositorState::default(),
            tracking_state: VRTrackingState::default(),
            chaperone_state: VRChaperoneState::default(),
            left_controller: Some(TrackedDevicePose::default_controller_left()),
            right_controller: Some(TrackedDevicePose::default_controller_right()),
            left_controller_state: ControllerState::default(),
            right_controller_state: ControllerState::default(),
            prev_left_buttons: 0,
            prev_right_buttons: 0,
            pending_events: VecDeque::new(),
            left_serial: "LHR00000001".to_string(),
            right_serial: "LHR00000002".to_string(),
            action_manifest: Vec::new(),
            next_handle: 0x5000,
            loaded_render_models: BTreeMap::new(),
            loaded_render_model_textures: BTreeMap::new(),
            next_render_model_handle: 0x6000,
            last_submitted_texture_per_eye: [0; 2],
        }
    }

    // ── Lifecycle ────────────────────────────────────────────────────────

    /// Initializes the virtual HMD. Returns `VR_InitError_None` (0) on success.
    pub fn init(&mut self) -> u32 {
        if self.initialized {
            return VR_INIT_ERROR_NONE;
        }
        self.initialized = true;
        self.hmd_enabled = true;
        self.frame_index = 0;
        self.last_frame_time = Instant::now();

        // Set up the HMD pose at index 0.
        self.tracking_state.poses[K_UN_TRACKED_DEVICE_INDEX_HMD as usize] =
            TrackedDevicePose::stationary_hmd();

        VR_INIT_ERROR_NONE
    }

    /// Shuts down the virtual HMD.
    pub fn shutdown(&mut self) {
        self.initialized = false;
        self.hmd_enabled = false;
    }

    /// Returns `true` if the virtual HMD is present (initialized).
    pub fn is_hmd_present(&self) -> bool {
        self.initialized && self.hmd_enabled
    }

    /// Returns `true` — the runtime is always "installed" (it's emulated).
    pub fn is_runtime_installed(&self) -> bool {
        true
    }

    /// Returns a static error string for the given VR init error code.
    pub fn get_string_for_hmd_error(&self, error: u32) -> &'static str {
        match error {
            VR_INIT_ERROR_NONE => "None",
            VR_INIT_ERROR_INIT_HMD_NOT_FOUND => "Hmd Not Found",
            _ => "Unknown Error",
        }
    }

    /// Returns the stub runtime path.
    pub fn runtime_path(&self) -> &'static str {
        "/usr/local/share/steamvr"
    }

    /// Returns a generic interface pointer (conceptual — the actual vtable
    /// allocation happens in the dispatch layer). Returns 0 for unknown
    /// interface versions.
    pub fn get_generic_interface(
        &mut self,
        pch_interface_version: &str,
        _pe_error: Option<&mut u32>,
    ) -> u64 {
        match pch_interface_version {
            IVR_SYSTEM_VERSION
            | IVR_COMPOSITOR_VERSION
            | IVR_CHAPERONE_VERSION
            | IVR_CONTROLLER_VERSION
            | IVR_INPUT_VERSION => {
                if !self.initialized {
                    return 0;
                }
                // The actual vtable allocation and guest object creation happens
                // in the dispatch layer. This method is kept for completeness.
                1 // Non-zero = success
            }
            _ => 0,
        }
    }

    // ── Controller state helper ─────────────────────────────────────────

    /// Returns the controller state for a given device index (1 = left, 2 = right).
    pub fn get_controller_state(&self, device_index: u32) -> ControllerState {
        match device_index {
            1 => self.left_controller_state.clone(),
            2 => self.right_controller_state.clone(),
            _ => ControllerState::default(),
        }
    }

    /// Updates controller state from Steam Input data.
    /// Maps Steam Input button/axis state to VR controller button/axis masks.
    pub fn update_controllers_from_steam_input(
        &mut self,
        left: ControllerInputSnapshot,
        right: ControllerInputSnapshot,
    ) {
        // Save previous button states for VREvent generation
        self.prev_left_buttons = self.left_controller_state.ul_button_pressed;
        self.prev_right_buttons = self.right_controller_state.ul_button_pressed;

        // Map XInput buttons to VR controller button mask
        let xinput_to_vr = |xbtn: u16| -> u64 {
            let mut vr_btn = 0u64;
            if (xbtn & 0x1000) != 0 {
                vr_btn |= BUTTON_A;
            } // A
            if (xbtn & 0x2000) != 0 {
                vr_btn |= BUTTON_APPLICATION_MENU;
            } // B → menu
            if (xbtn & 0x0001) != 0 {
                vr_btn |= BUTTON_DPAD_UP;
            }
            if (xbtn & 0x0002) != 0 {
                vr_btn |= BUTTON_DPAD_DOWN;
            }
            if (xbtn & 0x0004) != 0 {
                vr_btn |= BUTTON_DPAD_LEFT;
            }
            if (xbtn & 0x0008) != 0 {
                vr_btn |= BUTTON_DPAD_RIGHT;
            }
            if (xbtn & 0x0010) != 0 {
                vr_btn |= BUTTON_SYSTEM;
            } // Start → System
            if (xbtn & 0x0040) != 0 {
                vr_btn |= BUTTON_TOUCHPAD;
            } // L thumb → touchpad
            if (xbtn & 0x0080) != 0 {
                vr_btn |= BUTTON_TOUCHPAD;
            } // R thumb → touchpad
            if (xbtn & 0x0100) != 0 {
                vr_btn |= BUTTON_GRIP;
            } // L shoulder → grip
            if (xbtn & 0x0200) != 0 {
                vr_btn |= BUTTON_GRIP;
            } // R shoulder → grip
            vr_btn
        };

        // Left controller
        self.left_controller_state.packet_num += 1;
        self.left_controller_state.ul_button_pressed = xinput_to_vr(left.buttons);
        self.left_controller_state.ul_button_touched = self.left_controller_state.ul_button_pressed;
        // Axis 0: joystick X/Y
        self.left_controller_state.r_axis[0] = normalize_axis_i16(left.thumb_lx);
        self.left_controller_state.r_axis[1] = normalize_axis_i16(left.thumb_ly);
        // Axis 2: trigger
        self.left_controller_state.r_axis[2] = left.trigger as f32 / 255.0;
        // Axis types
        self.left_controller_state.ul_axis_type[0] = CONTROLLER_AXIS_JOYSTICK;
        self.left_controller_state.ul_axis_type[2] = CONTROLLER_AXIS_TRIGGER;

        // Right controller
        self.right_controller_state.packet_num += 1;
        self.right_controller_state.ul_button_pressed = xinput_to_vr(right.buttons);
        self.right_controller_state.ul_button_touched =
            self.right_controller_state.ul_button_pressed;
        self.right_controller_state.r_axis[0] = normalize_axis_i16(right.thumb_lx);
        self.right_controller_state.r_axis[1] = normalize_axis_i16(right.thumb_ly);
        self.right_controller_state.r_axis[2] = right.trigger as f32 / 255.0;
        self.right_controller_state.ul_axis_type[0] = CONTROLLER_AXIS_JOYSTICK;
        self.right_controller_state.ul_axis_type[2] = CONTROLLER_AXIS_TRIGGER;

        // Generate VREvent_ButtonPress/ButtonUnpress for changed button states
        self.enqueue_button_events(
            1,
            self.prev_left_buttons,
            self.left_controller_state.ul_button_pressed,
        );
        self.enqueue_button_events(
            2,
            self.prev_right_buttons,
            self.right_controller_state.ul_button_pressed,
        );
    }

    /// Enqueues VREvent_ButtonPress / VREvent_ButtonUnpress events when button
    /// state changes.
    fn enqueue_button_events(&mut self, device_index: u32, prev: u64, current: u64) {
        let changed = prev ^ current;
        if changed == 0 {
            return;
        }
        // Events are enqueued at the moment the button state changes, so the
        // real OpenVR "seconds since the event occurred" is ~0.
        // Pressed bits
        let pressed = current & changed;
        // Released bits
        let released = prev & changed;

        if pressed != 0 {
            let mut event = VREvent {
                event_type: VREVENT_BUTTON_PRESS,
                tracked_device_index: device_index,
                event_age_seconds: 0.0,
                data: [0; 64],
            };
            // Store the button mask in the data union
            event.set_button_mask(pressed);
            self.pending_events.push_back(event);
        }
        if released != 0 {
            let mut event = VREvent {
                event_type: VREVENT_BUTTON_UNPRESS,
                tracked_device_index: device_index,
                event_age_seconds: 0.0,
                data: [0; 64],
            };
            event.set_button_mask(released);
            self.pending_events.push_back(event);
        }
    }

    // ── IVRInput methods ──────────────────────────────────────────────────

    /// `SetActionManifestPath(path)` — parse and cache action manifest.
    ///
    /// Tries to read the guest's `action_manifest.json` (an array of actions
    /// with `name`/`type` fields, optionally grouped into `action_sets`).
    /// When the path is not host-readable or yields no actions, falls back to
    /// the built-in default action table so `GetActionHandle` keeps working.
    /// Returns 0 on success (matching the real API's error code for
    /// `VRInputError_None`).
    pub fn set_action_manifest_path(&mut self, path: &str) -> u32 {
        if !self.action_manifest.is_empty() {
            return 0; // Already loaded
        }

        let mut registered: u32 = 0;
        if let Ok(contents) = std::fs::read_to_string(path)
            && let Ok(manifest) = serde_json::from_str::<Value>(&contents)
        {
            let actions = manifest
                .get("actions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for action in actions {
                let Some(name) = action.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                let kind = match action.get("type").and_then(Value::as_str) {
                    Some("boolean") => ActionKind::Digital,
                    Some("vector1") | Some("vector2") | Some("scalar") => ActionKind::Analog,
                    Some("pose") | Some("skeleton") | Some("vibration") => ActionKind::Other,
                    _ => ActionKind::Other,
                };
                let handle = self.next_handle;
                self.next_handle += 1;
                self.action_manifest.push(ActionManifestEntry {
                    handle,
                    kind,
                    name: name.to_string(),
                    path: name.to_string(),
                });
                registered += 1;
            }
        }

        if registered == 0 {
            let default_actions = [
                ("system_button", ActionKind::Digital),
                ("application_menu", ActionKind::Digital),
                ("grip", ActionKind::Digital),
                ("touchpad_press", ActionKind::Digital),
                ("touchpad_touch", ActionKind::Digital),
                ("trigger_press", ActionKind::Digital),
                ("a_button", ActionKind::Digital),
                ("joystick", ActionKind::Analog),
                ("trigger", ActionKind::Analog),
                ("hand_pose", ActionKind::Other),
            ];
            for (name, kind) in &default_actions {
                let handle = self.next_handle;
                self.next_handle += 1;
                self.action_manifest.push(ActionManifestEntry {
                    handle,
                    kind: kind.clone(),
                    name: name.to_string(),
                    path: format!("/actions/{name}"),
                });
            }
        }
        0
    }

    /// `GetActionHandle(action_name)` — return handle from cached manifest.
    pub fn get_action_handle(&self, action_name: &str) -> u64 {
        for entry in &self.action_manifest {
            if entry.name == action_name {
                return entry.handle;
            }
        }
        0
    }

    /// `GetActionSetHandle(action_set)` — return handle (auto-register).
    pub fn get_action_set_handle(&self, _action_set: &str) -> u64 {
        0x2000
    }

    /// `GetDigitalActionData(action_handle, pActionData)` — query current
    /// Steam Input button state mapped to VR action.
    pub fn get_digital_action_data(&self, action_handle: u64, buffer: &mut [u8]) -> u32 {
        let action_name = self
            .action_manifest
            .iter()
            .find(|e| e.handle == action_handle)
            .map(|e| e.name.as_str())
            .unwrap_or("");

        let left_state = self.get_controller_state(1);
        let right_state = self.get_controller_state(2);

        let (active, pressed) = match action_name {
            "system_button" => (
                true,
                (left_state.ul_button_pressed & BUTTON_SYSTEM) != 0
                    || (right_state.ul_button_pressed & BUTTON_SYSTEM) != 0,
            ),
            "application_menu" => (
                true,
                (left_state.ul_button_pressed & BUTTON_APPLICATION_MENU) != 0
                    || (right_state.ul_button_pressed & BUTTON_APPLICATION_MENU) != 0,
            ),
            "grip" => (
                true,
                (left_state.ul_button_pressed & BUTTON_GRIP) != 0
                    || (right_state.ul_button_pressed & BUTTON_GRIP) != 0,
            ),
            "touchpad_press" => (
                true,
                (left_state.ul_button_pressed & BUTTON_TOUCHPAD) != 0
                    || (right_state.ul_button_pressed & BUTTON_TOUCHPAD) != 0,
            ),
            "touchpad_touch" => (
                true,
                (left_state.ul_button_touched & BUTTON_TOUCHPAD) != 0
                    || (right_state.ul_button_touched & BUTTON_TOUCHPAD) != 0,
            ),
            "trigger_press" => (
                true,
                (left_state.ul_button_pressed & BUTTON_AXIS2) != 0
                    || (right_state.ul_button_pressed & BUTTON_AXIS2) != 0,
            ),
            "a_button" => (
                true,
                (left_state.ul_button_pressed & BUTTON_A) != 0
                    || (right_state.ul_button_pressed & BUTTON_A) != 0,
            ),
            _ => (false, false),
        };

        // Write InputDigitalActionData_t to guest buffer (20 bytes):
        // bool bState; bool bActive; VRInputOrigin_t activeOrigin (u64);
        // u32 updateTime. `bState` (pressed) comes first in the real struct.
        if buffer.len() >= 20 {
            let active_u32: u32 = if active { 1 } else { 0 };
            let pressed_u32: u32 = if pressed { 1 } else { 0 };
            buffer[..4].copy_from_slice(&pressed_u32.to_le_bytes());
            buffer[4..8].copy_from_slice(&active_u32.to_le_bytes());
            buffer[8..16].copy_from_slice(&0u64.to_le_bytes());
            buffer[16..20].copy_from_slice(&0u32.to_le_bytes());
        }
        0
    }

    /// `GetAnalogActionData(action_handle, pActionData)` — query current
    /// Steam Input axis state mapped to VR action.
    pub fn get_analog_action_data(&self, action_handle: u64, buffer: &mut [u8]) -> u32 {
        let action_name = self
            .action_manifest
            .iter()
            .find(|e| e.handle == action_handle)
            .map(|e| e.name.as_str())
            .unwrap_or("");

        let left_state = self.get_controller_state(1);
        let right_state = self.get_controller_state(2);

        let (x, y, active) = match action_name {
            "joystick" => {
                let lx = left_state.r_axis[0];
                let ly = left_state.r_axis[1];
                let rx = right_state.r_axis[0];
                let ry = right_state.r_axis[1];
                if rx != 0.0 || ry != 0.0 {
                    (rx, ry, true)
                } else {
                    (lx, ly, lx != 0.0 || ly != 0.0)
                }
            }
            "trigger" => {
                let lt = left_state.r_axis[2];
                let rt = right_state.r_axis[2];
                let val = if rt > 0.0 { rt } else { lt };
                (val, 0.0, val > 0.0)
            }
            _ => (0.0, 0.0, false),
        };

        // Write InputAnalogActionData_t to guest buffer (40 bytes):
        // float x, y, z; float deltaX, deltaY, deltaZ; bool bActive;
        // VRInputOrigin_t activeOrigin (u64); u32 updateTime.
        // The analog values come first in the real struct.
        if buffer.len() >= 40 {
            let active_u32: u32 = if active { 1 } else { 0 };
            buffer[..4].copy_from_slice(&x.to_le_bytes());
            buffer[4..8].copy_from_slice(&y.to_le_bytes());
            buffer[8..12].copy_from_slice(&0.0f32.to_le_bytes());
            buffer[12..16].copy_from_slice(&0.0f32.to_le_bytes());
            buffer[16..20].copy_from_slice(&0.0f32.to_le_bytes());
            buffer[20..24].copy_from_slice(&0.0f32.to_le_bytes());
            buffer[24..28].copy_from_slice(&active_u32.to_le_bytes());
            buffer[28..36].copy_from_slice(&0u64.to_le_bytes());
            buffer[36..40].copy_from_slice(&0u32.to_le_bytes());
        }
        0
    }

    /// `ActivateActionSet(action_set_handle)` — activate the given action set.
    pub fn activate_action_set(&mut self, _handle: u64) {
        // No-op in emulation.
    }

    /// `GetCurrentActionSet()` — returns the current action set handle.
    pub fn get_current_action_set(&self) -> u64 {
        0x2000
    }

    // ── IVRSystem methods ────────────────────────────────────────────────

    /// Returns the tracked device class for the given device index.
    pub fn get_tracked_device_class(&self, device_index: u32) -> u32 {
        if !self.is_hmd_present() {
            TRACKED_DEVICE_CLASS_INVALID
        } else if device_index == K_UN_TRACKED_DEVICE_INDEX_HMD {
            TRACKED_DEVICE_CLASS_HMD
        } else if device_index == 1 || device_index == 2 {
            TRACKED_DEVICE_CLASS_CONTROLLER
        } else {
            TRACKED_DEVICE_CLASS_INVALID
        }
    }

    /// Returns whether a tracked device is connected.
    ///
    /// Devices are only reported connected while the virtual HMD is enabled;
    /// after `shutdown()` everything reports disconnected, matching the real
    /// runtime's behavior once the compositor stops.
    pub fn is_tracked_device_connected(&self, device_index: u32) -> bool {
        self.is_hmd_present() && matches!(device_index, 0..=2)
    }

    /// Reads a string tracked device property and writes it into `buffer` as
    /// UTF-16LE.
    ///
    /// Follows the OpenVR size contract: returns the **required** buffer size
    /// in bytes (including the null terminator) so callers can retry with a
    /// larger buffer; returns 0 if the property is not found. When the buffer
    /// is large enough the string is copied including its terminator.
    pub fn get_prop_string(
        &self,
        device_index: u32,
        prop: u32,
        buffer: &mut [u16],
        buffer_len: u32,
    ) -> u32 {
        let value: &str = match (device_index, prop) {
            (0, PROP_MANUFACTURER_NAME) => "Valve",
            (0, PROP_MODEL_NUMBER) => "Index",
            (0, PROP_SERIAL_NUMBER) => "CASA1-VR-001",
            (0, PROP_TRACKING_SYSTEM_NAME) => "lighthouse",
            (0, PROP_RENDER_MODEL_NAME) => "generic_hmd",
            (0, PROP_DRIVER_VERSION) => "1.0.0",
            (0, PROP_SUPPORTED_GRAPHICS_API) => "Metal",
            (1, PROP_MANUFACTURER_NAME) | (2, PROP_MANUFACTURER_NAME) => "Valve",
            (1, PROP_MODEL_NUMBER) | (2, PROP_MODEL_NUMBER) => "Vive Controller MV",
            (1, PROP_SERIAL_NUMBER) => &self.left_serial,
            (2, PROP_SERIAL_NUMBER) => &self.right_serial,
            (1, PROP_TRACKING_SYSTEM_NAME) | (2, PROP_TRACKING_SYSTEM_NAME) => "lighthouse",
            (1, PROP_RENDER_MODEL_NAME) | (2, PROP_RENDER_MODEL_NAME) => "vr_controller_vive_1_5",
            (1, PROP_DRIVER_VERSION) | (2, PROP_DRIVER_VERSION) => "1.0.0",
            _ => return 0,
        };
        let encoded: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let required = encoded.len();
        let capacity = (buffer_len as usize / 2).min(buffer.len());
        if capacity >= required {
            buffer[..required].copy_from_slice(&encoded);
        }
        (required * 2) as u32
    }

    /// Reads a bool tracked device property.
    pub fn get_prop_bool(&self, device_index: u32, prop: u32) -> bool {
        if device_index == K_UN_TRACKED_DEVICE_INDEX_HMD {
            match prop {
                PROP_DEVICE_IS_WIRELESS => false,
                PROP_DEVICE_PROVIDES_BATTERY_STATUS => false,
                PROP_DEVICE_CAN_POWER_OFF => false,
                PROP_FIRMWARE_UPDATE_AVAILABLE => false,
                PROP_FIRMWARE_MANUAL_UPDATE => false,
                PROP_WILL_DRIFT_IN_YAW => false,
                _ => false,
            }
        } else if device_index == 1 || device_index == 2 {
            // Controller properties
            match prop {
                PROP_DEVICE_IS_WIRELESS => true,
                PROP_DEVICE_PROVIDES_BATTERY_STATUS => true,
                PROP_DEVICE_CAN_POWER_OFF => true,
                PROP_FIRMWARE_UPDATE_AVAILABLE => false,
                PROP_FIRMWARE_MANUAL_UPDATE => false,
                PROP_WILL_DRIFT_IN_YAW => false,
                _ => false,
            }
        } else {
            false
        }
    }

    /// Reads a float tracked device property.
    pub fn get_prop_float(&self, device_index: u32, prop: u32) -> f32 {
        if device_index == K_UN_TRACKED_DEVICE_INDEX_HMD {
            match prop {
                PROP_USER_IPD_M => IPD,
                PROP_DISPLAY_REFRESH_RATE => REFRESH_RATE_HZ,
                PROP_DISPLAY_FREQUENCY => REFRESH_RATE_HZ,
                PROP_FIELD_OF_VIEW_TOP_DEGREES => 70.0,
                PROP_FIELD_OF_VIEW_BOTTOM_DEGREES => 70.0,
                PROP_FIELD_OF_VIEW_LEFT_DEGREES => 70.0,
                PROP_FIELD_OF_VIEW_RIGHT_DEGREES => 70.0,
                PROP_DISPLAY_WIDTH => 0.109,
                PROP_DISPLAY_HEIGHT => 0.121,
                PROP_DEVICE_BATTERY_PERCENTAGE => 1.0,
                _ => 0.0,
            }
        } else if device_index == 1 || device_index == 2 {
            // Controller floats
            match prop {
                PROP_DEVICE_BATTERY_PERCENTAGE => 0.8,
                _ => 0.0,
            }
        } else {
            0.0
        }
    }

    /// Reads an int32 tracked device property.
    pub fn get_prop_int32(&self, device_index: u32, prop: u32) -> i32 {
        if device_index == K_UN_TRACKED_DEVICE_INDEX_HMD {
            match prop {
                PROP_ADAPTER_INDEX => 0,
                PROP_TRACKING_RESULT => E_TRACKING_RESULT_RUNNING_OK as i32,
                PROP_DEVICE_CLASS => TRACKED_DEVICE_CLASS_HMD as i32,
                PROP_CONTROLLER_ROLE_HINT => 0,
                _ => 0,
            }
        } else if device_index == 1 || device_index == 2 {
            match prop {
                PROP_TRACKING_RESULT => E_TRACKING_RESULT_RUNNING_OK as i32,
                PROP_DEVICE_CLASS => TRACKED_DEVICE_CLASS_CONTROLLER as i32,
                PROP_CONTROLLER_ROLE_HINT => {
                    if device_index == 1 {
                        1
                    } else {
                        2
                    }
                } // left=1, right=2
                PROP_ADAPTER_INDEX => 0,
                _ => 0,
            }
        } else {
            0
        }
    }

    /// Reads a uint64 tracked device property.
    pub fn get_prop_uint64(&self, _device_index: u32, _prop: u32) -> u64 {
        0
    }

    /// Returns the recommended render target size (1512 × 1680).
    pub fn get_recommended_render_target_size(&self) -> (u32, u32) {
        (RENDER_TARGET_WIDTH, RENDER_TARGET_HEIGHT)
    }

    /// Builds an OpenVR-style projection matrix for the given eye.
    ///
    /// Returns a column-major 4×4 matrix as 16 floats.
    pub fn get_projection_matrix(&self, _eye: u32, near_z: f32, far_z: f32) -> [f32; 16] {
        let left = -PROJECTION_HALF;
        let right = PROJECTION_HALF;
        let top = PROJECTION_HALF;
        let bottom = -PROJECTION_HALF;

        let idx = 1.0 / (right - left);
        let idy = 1.0 / (top - bottom);
        let idz = 1.0 / (far_z - near_z);

        // Column-major (OpenGL / OpenVR convention)
        [
            2.0 * near_z * idx,          // m00
            0.0,                         // m10
            0.0,                         // m20
            0.0,                         // m30
            0.0,                         // m01
            2.0 * near_z * idy,          // m11
            0.0,                         // m21
            0.0,                         // m31
            (right + left) * idx,        // m02
            (top + bottom) * idy,        // m12
            -(far_z + near_z) * idz,     // m22
            -1.0,                        // m32
            0.0,                         // m03
            0.0,                         // m13
            -2.0 * far_z * near_z * idz, // m23
            0.0,                         // m33
        ]
    }

    /// Returns raw projection frustum bounds (left, right, top, bottom).
    pub fn get_projection_raw(&self, _eye: u32) -> (f64, f64, f64, f64) {
        (
            -PROJECTION_HALF as f64,
            PROJECTION_HALF as f64,
            PROJECTION_HALF as f64,
            -PROJECTION_HALF as f64,
        )
    }

    /// Returns the eye-to-head transform as a 3×4 row-major matrix.
    ///
    /// Left eye translates by −IPD/2, right eye by +IPD/2.
    pub fn get_eye_to_head_transform(&self, eye: u32) -> [f32; 12] {
        let mut m = [0.0f32; 12];
        // Identity 3×3
        m[0] = 1.0;
        m[5] = 1.0;
        m[10] = 1.0;
        // Translation: column 3
        m[3] = if eye == 0 { -HALF_IPD } else { HALF_IPD };
        m
    }

    /// Returns the device-to-absolute tracking pose for a single device.
    pub fn get_device_to_absolute_tracking_pose(
        &self,
        _origin: u32,
        _pred_seconds: f32,
        device_index: u32,
    ) -> TrackedDevicePose {
        if device_index == K_UN_TRACKED_DEVICE_INDEX_HMD && self.initialized {
            self.tracking_state.poses[device_index as usize]
        } else if device_index == 1 && self.initialized {
            self.left_controller.unwrap_or_default()
        } else if device_index == 2 && self.initialized {
            self.right_controller.unwrap_or_default()
        } else {
            TrackedDevicePose::default()
        }
    }

    /// Polls for the next VR event. Returns `false` if no events are pending.
    /// Dequeues events from the internal `pending_events` queue (populated by
    /// `update_controllers_from_steam_input`) in FIFO order, matching real
    /// OpenVR event ordering.
    pub fn poll_next_event(&mut self, event: &mut VREvent, _size: u32) -> bool {
        if let Some(ev) = self.pending_events.pop_front() {
            *event = ev;
            true
        } else {
            false
        }
    }

    // ── IVRCompositor methods ────────────────────────────────────────────

    /// Submits a texture for the given eye. Returns `EVRCompositorError`.
    pub fn submit(
        &mut self,
        eye: u32,
        texture: &VRTexture,
        _bounds: Option<&[f32; 4]>,
        _gl_arg: u32,
    ) -> u32 {
        if !self.initialized {
            return 1; // VRCompositorError_RequestFailed
        }
        self.frame_index += 1;
        self.compositor_state.last_frame_index = self.frame_index as u32;
        self.compositor_state.last_submit_result = 0;

        // Track which texture was submitted per eye
        if eye == 0 || eye == 1 {
            self.last_submitted_texture_per_eye[eye as usize] = texture.handle;
        }

        // Track per-eye submission in cumulative stats
        self.compositor_state.cumulative_stats.num_frames += 1;
        match eye {
            0 => self.compositor_state.cumulative_stats.num_frames_cpu += 1,
            1 => self.compositor_state.cumulative_stats.num_frames_gpu += 1,
            _ => {}
        }

        // Update frame timing
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_frame_time).as_secs_f32();
        self.compositor_state.frame_timing.frame_index = self.frame_index as u32;
        self.compositor_state.frame_timing.total_milliseconds = elapsed * 1000.0;
        self.compositor_state.frame_timing.num_frames += 1;
        self.last_frame_time = now;

        0 // Success
    }

    /// Waits for poses and returns render/game pose arrays.
    /// Returns `EVRCompositorError` (0 = None).
    ///
    /// Returns 3 tracked device poses:
    /// - Index 0: HMD (stationary at origin)
    /// - Index 1: Left controller (default pose or Steam Input-driven)
    /// - Index 2: Right controller (default pose or Steam Input-driven)
    pub fn wait_get_poses(
        &mut self,
        render_poses: &mut [TrackedDevicePose; K_UN_MAX_TRACKED_DEVICE_COUNT],
        game_poses: &mut [TrackedDevicePose; K_UN_MAX_TRACKED_DEVICE_COUNT],
    ) -> u32 {
        if !self.initialized {
            return 1; // VRCompositorError_RequestFailed
        }

        let now = Instant::now();

        // Compute a synthetic time-based offset for natural head sway.
        let t = self.frame_index as f64 * 0.016; // ~16 ms per frame
        let sway_x = (t * 0.5).sin() * 0.002; // ±2 mm lateral sway
        let sway_y = (t * 0.7).sin() * 0.001; // ±1 mm vertical bob
        let sway_z = (t * 0.3).sin() * 0.001; // ±1 mm forward/back

        // Build HMD pose with synthetic tracking and velocity prediction.
        let mut hmd_pose = TrackedDevicePose::stationary_hmd();
        // Apply subtle positional sway to simulate natural head motion.
        hmd_pose.device_to_absolute_tracking[3] += sway_x as f32; // x offset
        hmd_pose.device_to_absolute_tracking[7] += sway_y as f32; // y offset
        hmd_pose.device_to_absolute_tracking[11] += sway_z as f32; // z offset
        // Set velocity based on displacement per second.
        hmd_pose.velocity[0] = sway_x as f32 * 60.0;
        hmd_pose.velocity[1] = sway_y as f32 * 60.0;
        hmd_pose.velocity[2] = sway_z as f32 * 60.0;
        // Predict angular velocity (very slow yaw rotation for subtle motion).
        hmd_pose.angular_velocity[1] = (t * 0.1).cos() as f32 * 0.01;

        self.tracking_state.poses[K_UN_TRACKED_DEVICE_INDEX_HMD as usize] = hmd_pose;

        // Controller poses are static in emulation (no motion controllers are
        // tracked), so their velocity is genuinely zero; copying the stored
        // pose directly avoids dead per-frame displacement math.
        if let Some(pose) = self.left_controller {
            self.tracking_state.poses[1] = pose;
        }
        if let Some(pose) = self.right_controller {
            self.tracking_state.poses[2] = pose;
        }

        // Mark devices 0 (HMD), 1 (left controller), 2 (right controller) as
        // connected. `tracking_result` must be `ETrackingResult_Running_OK`
        // (200); 0 is not a valid `ETrackingResult` value and makes
        // spec-compliant guests treat every pose as untracked.
        self.tracking_state.poses[0].pose_is_valid = 1u32;
        self.tracking_state.poses[0].tracking_result = E_TRACKING_RESULT_RUNNING_OK;
        if self.left_controller.is_some() {
            self.tracking_state.poses[1].pose_is_valid = 1u32;
            self.tracking_state.poses[1].tracking_result = E_TRACKING_RESULT_RUNNING_OK;
        }
        if self.right_controller.is_some() {
            self.tracking_state.poses[2].pose_is_valid = 1u32;
            self.tracking_state.poses[2].tracking_result = E_TRACKING_RESULT_RUNNING_OK;
        }

        // Copy poses to output arrays.
        *render_poses = self.tracking_state.poses;
        *game_poses = self.tracking_state.poses;

        // Update compositor frame timing with predicted vsync.
        self.vsync_time_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        self.compositor_state.frame_timing.frame_index = self.frame_index as u32;

        self.frame_index += 1;
        self.last_frame_time = now;

        0
    }

    /// Gets frame timing data. Returns `true` on success.
    pub fn get_frame_timing(&self, timing: &mut CompositorFrameTiming, _frames_ahead: u32) -> bool {
        *timing = self.compositor_state.frame_timing.clone();
        timing.size = std::mem::size_of::<CompositorFrameTiming>() as u32;
        true
    }

    /// Returns the time remaining in the current frame (always a full frame
    /// duration since we're virtual).
    pub fn get_frame_time_remaining(&self) -> f32 {
        FRAME_DURATION_SECS
    }

    /// Gets cumulative compositor stats.
    pub fn get_cumulative_stats(&self, stats: &mut CompositorCumulativeStats) {
        *stats = self.compositor_state.cumulative_stats.clone();
    }

    /// Returns `true` — the compositor can always render.
    pub fn can_render_scene(&self) -> bool {
        self.initialized
    }

    /// Sets explicit timing mode.
    pub fn set_explicit_timing_mode(&mut self, mode: u32) {
        self.compositor_state.explicit_timing_mode = mode;
    }

    /// Sets the last pose for explicit timing mode.
    pub fn set_explicit_timing_last_pose(&mut self, pose: &TrackedDevicePose) {
        self.compositor_state.explicit_timing_last_pose = *pose;
    }

    // ── IVRChaperone methods ─────────────────────────────────────────────

    /// Returns the chaperone calibration state (0 = Calibrated).
    pub fn get_calibration_state(&self) -> u32 {
        self.chaperone_state.calibration_state
    }

    /// Returns the play area size in metres (2.0 × 1.5 for standing).
    pub fn get_play_area_size(&self) -> (f32, f32) {
        (
            self.chaperone_state.play_area_size[0],
            self.chaperone_state.play_area_size[1],
        )
    }

    /// Returns the play area rectangle corners.
    pub fn get_play_area_rect(&self) -> [f32; 4] {
        self.chaperone_state.play_area_rect
    }

    // ── IVRRenderModels methods ───────────────────────────────────────────

    /// Load a render model synchronously.
    ///
    /// `buffer` will receive the model data; returns the total size on success,
    /// or 0 if the model name is unknown. Uses the data cached by
    /// `load_render_model_async` when available, falling back to the built-in
    /// generated meshes.
    pub fn load_render_model(&self, model_name: &str, buffer: &mut [u8]) -> u32 {
        let cached = self
            .loaded_render_models
            .values()
            .find(|(name, _)| name == model_name)
            .map(|(_, data)| data.as_slice());
        let model_data = match cached {
            Some(data) => data,
            None => match model_name {
                "generic_hmd" => generate_hmd_render_model(),
                "vr_controller_vive_1_5" => generate_controller_render_model(),
                _ => return 0,
            },
        };
        let len = model_data.len().min(buffer.len());
        buffer[..len].copy_from_slice(&model_data[..len]);
        model_data.len() as u32
    }

    /// Queue an async render model load.
    ///
    /// Stores the model data internally and returns a non-zero handle.
    /// The caller can later use `load_render_model` with the same name
    /// to retrieve the data, or use the handle with `get_render_model_name`.
    pub fn load_render_model_async(&mut self, model_name: &str) -> u64 {
        let model_data: Vec<u8> = match model_name {
            "generic_hmd" => generate_hmd_render_model().to_vec(),
            "vr_controller_vive_1_5" => generate_controller_render_model().to_vec(),
            _ => return 0,
        };
        let handle = self.next_render_model_handle;
        self.next_render_model_handle += 1;
        self.loaded_render_models
            .insert(handle, (model_name.to_string(), model_data));
        handle
    }

    /// Free a render model previously loaded.
    ///
    /// Removes the model data and any associated texture from internal storage.
    pub fn free_render_model(&mut self, handle: u64) {
        self.loaded_render_models.remove(&handle);
        self.loaded_render_model_textures.remove(&handle);
    }

    /// Get the data for a loaded render model by handle.
    pub fn get_render_model_data(&self, handle: u64) -> Option<&[u8]> {
        self.loaded_render_models
            .get(&handle)
            .map(|(_, data)| data.as_slice())
    }

    /// Check if a render model is currently loaded.
    pub fn is_render_model_loaded(&self, handle: u64) -> bool {
        self.loaded_render_models.contains_key(&handle)
    }

    /// Load a texture for a render model (generates a simple placeholder texture).
    ///
    /// Returns a non-zero texture handle on success, 0 on failure.
    pub fn load_render_model_texture(&mut self, _handle: u64) -> u64 {
        // Generate a simple 64×64 checkerboard placeholder texture (RGBA).
        const TEX_SIZE: u32 = 64;
        let mut pixels = Vec::with_capacity((TEX_SIZE * TEX_SIZE * 4) as usize);
        for y in 0..TEX_SIZE {
            for x in 0..TEX_SIZE {
                let is_white = (x / 8 + y / 8) % 2 == 0;
                if is_white {
                    pixels.extend_from_slice(&[200, 200, 200, 255]);
                } else {
                    pixels.extend_from_slice(&[100, 100, 100, 255]);
                }
            }
        }
        let tex_handle = self.next_render_model_handle;
        self.next_render_model_handle += 1;
        self.loaded_render_model_textures
            .insert(tex_handle, (TEX_SIZE, TEX_SIZE, pixels));
        tex_handle
    }

    /// Get the dimensions and pixel data for a loaded render model texture.
    pub fn get_render_model_texture_data(&self, tex_handle: u64) -> Option<(u32, u32, &[u8])> {
        self.loaded_render_model_textures
            .get(&tex_handle)
            .map(|(w, h, data)| (*w, *h, data.as_slice()))
    }

    /// Get the render model name for a tracked device.
    pub fn get_render_model_name(&self, device_index: u32) -> &'static str {
        match device_index {
            0 => "generic_hmd",
            1 | 2 => "vr_controller_vive_1_5",
            _ => "",
        }
    }

    /// Get the number of available render models.
    pub fn get_render_model_count(&self) -> u32 {
        2 // generic_hmd + vr_controller_vive_1_5
    }

    /// Get the render model name by index.
    pub fn get_render_model_name_by_index(&self, index: u32) -> &'static str {
        match index {
            0 => "generic_hmd",
            1 => "vr_controller_vive_1_5",
            _ => "",
        }
    }

    /// Get the thumbnail path for a render model.
    ///
    /// Returns a virtual path that the host can map to a real thumbnail
    /// resource, or an empty string if no thumbnail is available.
    pub fn get_render_model_thumbnail(&self, model_name: &str) -> &'static str {
        match model_name {
            "generic_hmd" => "thumbnails/generic_hmd.png",
            "vr_controller_vive_1_5" => "thumbnails/vr_controller_vive_1_5.png",
            _ => "",
        }
    }

    /// Get all loaded render model handles.
    pub fn get_loaded_render_model_handles(&self) -> Vec<u64> {
        self.loaded_render_models.keys().copied().collect()
    }
}

impl Default for SteamVR {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper: normalise i16 axis value to [-1.0, 1.0] ──────────────────────

/// Normalises a 16-bit signed axis value to `[-1.0, 1.0]`.
fn normalize_axis_i16(value: i16) -> f32 {
    if value == 0 {
        return 0.0;
    }
    let val = value as f32 / i16::MAX as f32;
    val.clamp(-1.0, 1.0)
}

// ── Render model data generation ─────────────────────────────────────────

/// Generate a minimal cube mesh for the HMD render model.
///
/// Format: version(u32) | vertex_count(u32) | vertex_stride(u32) |
///         vertex_data[vertex_count] (16 bytes each: 3xf32 position + 1x u32 normal_packed)
///
/// The cube has 6 faces × 2 triangles × 3 vertices = 36 vertices.
fn generate_hmd_render_model() -> &'static [u8] {
    use std::sync::OnceLock;
    static DATA: OnceLock<Vec<u8>> = OnceLock::new();
    DATA.get_or_init(|| {
        let mut data = Vec::with_capacity(4 + 4 + 4 + 16 * 36);
        // Header: version=1, vertex_count=36, vertex_stride=16
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&36u32.to_le_bytes());
        data.extend_from_slice(&16u32.to_le_bytes());

        // Cube half-extent and vertex positions (centered at origin)
        let h = 0.1f32; // 10 cm half-extent
        // 8 corners of the cube
        let corners: [(f32, f32, f32); 8] = [
            (-h, -h, -h),
            (h, -h, -h),
            (h, h, -h),
            (-h, h, -h), // back face
            (-h, -h, h),
            (h, -h, h),
            (h, h, h),
            (-h, h, h), // front face
        ];
        // 6 face definitions: (corner_indices, normal)
        let faces: [([usize; 4], (f32, f32, f32)); 6] = [
            ([0, 1, 2, 3], (0.0, 0.0, -1.0)), // back
            ([5, 4, 7, 6], (0.0, 0.0, 1.0)),  // front
            ([4, 0, 3, 7], (-1.0, 0.0, 0.0)), // left
            ([1, 5, 6, 2], (1.0, 0.0, 0.0)),  // right
            ([3, 2, 6, 7], (0.0, 1.0, 0.0)),  // top
            ([4, 5, 1, 0], (0.0, -1.0, 0.0)), // bottom
        ];
        let pack_normal = |nx: f32, ny: f32, nz: f32| -> u32 {
            let ix = (nx * 127.0) as i8;
            let iy = (ny * 127.0) as i8;
            let iz = (nz * 127.0) as i8;
            // Use i8::MAX (127) for the sign component to indicate a valid packed normal
            let iw: i8 = 127;
            u32::from_le_bytes([ix as u8, iy as u8, iz as u8, iw as u8])
        };
        for &(quad, normal) in &faces {
            let (nx, ny, nz) = normal;
            let packed = pack_normal(nx, ny, nz);
            // Triangle 1: indices 0,1,2
            for &ci in &[quad[0], quad[1], quad[2]] {
                let (x, y, z) = corners[ci];
                data.extend_from_slice(&x.to_le_bytes());
                data.extend_from_slice(&y.to_le_bytes());
                data.extend_from_slice(&z.to_le_bytes());
                data.extend_from_slice(&packed.to_le_bytes());
            }
            // Triangle 2: indices 0,2,3
            for &ci in &[quad[0], quad[2], quad[3]] {
                let (x, y, z) = corners[ci];
                data.extend_from_slice(&x.to_le_bytes());
                data.extend_from_slice(&y.to_le_bytes());
                data.extend_from_slice(&z.to_le_bytes());
                data.extend_from_slice(&packed.to_le_bytes());
            }
        }
        data
    })
}

/// Generate a simplified controller mesh.
///
/// Format: version(u32) | vertex_count(u32) | vertex_stride(u32) |
///         vertex_data[vertex_count] (8 bytes each: 2xf32 position)
///
/// 36 vertices forming a simple rectangular prism approximation.
fn generate_controller_render_model() -> &'static [u8] {
    use std::sync::OnceLock;
    static DATA: OnceLock<Vec<u8>> = OnceLock::new();
    DATA.get_or_init(|| {
        let mut data = Vec::with_capacity(4 + 4 + 4 + 8 * 36);
        // Header: version=1, vertex_count=36, vertex_stride=8
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&36u32.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes());

        // 2D rectangle approximation (controller body silhouette)
        let hw = 0.04f32; // half-width 4 cm
        let hh = 0.12f32; // half-height 12 cm
        let corners: [(f32, f32); 4] = [(-hw, -hh), (hw, -hh), (hw, hh), (-hw, hh)];
        // 2 triangles forming the quad, repeated for 36 vertices (12 triangles)
        // to fill the 36-vertex slot with a consistent shape
        for _ in 0..6 {
            // Triangle 1: 0,1,2
            for &ci in &[0, 1, 2] {
                let (x, y) = corners[ci];
                data.extend_from_slice(&x.to_le_bytes());
                data.extend_from_slice(&y.to_le_bytes());
            }
            // Triangle 2: 0,2,3
            for &ci in &[0, 2, 3] {
                let (x, y) = corners[ci];
                data.extend_from_slice(&x.to_le_bytes());
                data.extend_from_slice(&y.to_le_bytes());
            }
        }
        data
    })
}

// ── fn_tables: IVRController and IVRInput function pointer tables ────────

/// One vtable entry: `(thunk_name_or_stub, stack_cleanup_bytes)` for x86
/// stdcall-style cleanup (arguments cleaned by the callee; `this` is passed
/// as a regular stack argument in the dispatch convention used here).
pub type FnTableEntry = (&'static str, u32);
/// IVRController vtable (10 methods).
pub type ControllerFnTable = [FnTableEntry; 10];
/// IVRInput vtable (20 methods).
pub type InputFnTable = [FnTableEntry; 20];

/// Returns (controller_vtable, input_vtable) function tables matching the
/// real OpenVR ABI at the given offsets.
///
/// Each entry is `(thunk_variant_name_or_stub, stack_cleanup_bytes)`. Cleanup
/// sizes are derived from the real x86 signatures:
/// - `Release()` → 4 (`this`),
/// - `TriggerHapticPulse(u32 axis, u16 duration)` → 12 (4 + 4 + 2 → 16-byte
///   alignment),
/// - `GetControllerState(u32 device, VRControllerState_t*)` → 8.
pub fn controller_fn_tables() -> (ControllerFnTable, InputFnTable) {
    // IVRController_002 vtable (10 methods, offset 0 = Release)
    let controller_vtable: [FnTableEntry; 5] = [
        ("Release", 4),               // 0: void Release()
        ("TriggerHapticPulse", 12),   // 1: bool TriggerHapticPulse(u32 axis, u16 duration)
        ("TriggerHapticPulseV2", 12), // 2: (unused)
        ("GetControllerState", 8), // 3: bool GetControllerState(u32 device, VRControllerState_t*)
        ("GetControllerStateForNextFrame", 8), // 4: same with predicted
                                   // Remaining slots = unsupported
    ];
    // Pad to 10 entries
    let mut controller_full: ControllerFnTable = [("unsupported", 4); 10];
    for (i, entry) in controller_vtable.iter().enumerate() {
        controller_full[i] = *entry;
    }

    // IVRInput_003 vtable (20 methods, offset 0 = Release)
    let input_vtable: [FnTableEntry; 11] = [
        ("Release", 4),                // 0
        ("SetActionManifestPath", 8),  // 1
        ("GetDigitalActionHandle", 8), // 2: u64 GetDigitalActionHandle(str name)
        ("GetAnalogActionHandle", 8),  // 3
        ("GetActionHandle", 8),        // 4
        ("GetActionSetHandle", 8),     // 5
        ("GetDigitalActionData", 16),  // 6
        ("GetAnalogActionData", 16),   // 7
        ("GetDigitalActionData", 16),  // 8: real slot 8 is GetDigitalActionData
        ("ActivateActionSet", 12),     // 9
        ("GetCurrentActionSet", 12),   // 10
                                       // Remaining = unsupported
    ];
    let mut input_full: InputFnTable = [("unsupported", 4); 20];
    for (i, entry) in input_vtable.iter().enumerate() {
        input_full[i] = *entry;
    }

    (controller_full, input_full)
}
