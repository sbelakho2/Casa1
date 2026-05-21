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

use std::time::Instant;

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

/// Compositor frame timing (matches `vr::Compositor_FrameTiming` layout).
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

/// Compositor cumulative statistics (matches OpenVR struct layout).
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

/// `VREvent` structure (matches `vr::VREvent_t` layout).
#[derive(Clone, Debug)]
#[repr(C)]
pub struct VREvent {
    /// Event type enum value.
    pub event_type: u32,
    /// Index of the tracked device that generated the event.
    pub tracked_device_index: u32,
    /// Age of the event in seconds.
    pub event_age_seconds: f32,
    /// Raw event data union (simplified as byte array).
    pub data: [u8; 40],
}

impl Default for VREvent {
    fn default() -> Self {
        Self {
            event_type: 0,
            tracked_device_index: 0,
            event_age_seconds: 0.0,
            data: [0; 40],
        }
    }
}

// ── HMD tracking state ──────────────────────────────────────────────────

/// HMD tracking state for all tracked devices.
pub struct VRTrackingState {
    /// Poses for up to `k_unMaxTrackedDeviceCount` devices.
    pub poses: [TrackedDevicePose; K_UN_MAX_TRACKED_DEVICE_COUNT],
}

impl Default for VRTrackingState {
    fn default() -> Self {
        Self {
            poses: Default::default(),
        }
    }
}

// ── Compositor state ────────────────────────────────────────────────────

/// Compositor internal state.
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

impl Default for VRCompositorState {
    fn default() -> Self {
        Self {
            last_frame_index: 0,
            frame_timing: CompositorFrameTiming::default(),
            cumulative_stats: CompositorCumulativeStats::default(),
            last_submit_result: 0,
            explicit_timing_mode: 0,
            explicit_timing_last_pose: TrackedDevicePose::default(),
        }
    }
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
            IVR_SYSTEM_VERSION | IVR_COMPOSITOR_VERSION | IVR_CHAPERONE_VERSION => {
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

    // ── IVRSystem methods ────────────────────────────────────────────────

    /// Returns the tracked device class for the given device index.
    pub fn get_tracked_device_class(&self, device_index: u32) -> u32 {
        if device_index == K_UN_TRACKED_DEVICE_INDEX_HMD && self.initialized {
            TRACKED_DEVICE_CLASS_HMD
        } else {
            TRACKED_DEVICE_CLASS_INVALID
        }
    }

    /// Returns whether a tracked device is connected.
    pub fn is_tracked_device_connected(&self, device_index: u32) -> bool {
        device_index == K_UN_TRACKED_DEVICE_INDEX_HMD && self.initialized
    }

    /// Reads a string tracked device property and writes it into `buffer` as
    /// UTF-16LE. Returns the number of bytes written (including null terminator),
    /// or 0 if the property is not found.
    pub fn get_prop_string(
        &self,
        device_index: u32,
        prop: u32,
        buffer: &mut [u16],
        buffer_len: u32,
    ) -> u32 {
        if device_index != K_UN_TRACKED_DEVICE_INDEX_HMD {
            return 0;
        }
        let value: &str = match prop {
            PROP_MANUFACTURER_NAME => "Valve",
            PROP_MODEL_NUMBER => "Index",
            PROP_SERIAL_NUMBER => "CASA1-VR-001",
            PROP_TRACKING_SYSTEM_NAME => "lighthouse",
            PROP_RENDER_MODEL_NAME => "generic_hmd",
            PROP_DRIVER_VERSION => "1.0.0",
            PROP_SUPPORTED_GRAPHICS_API => "Metal",
            _ => return 0,
        };
        let encoded: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let max_chars = (buffer_len as usize / 2).min(buffer.len()).min(encoded.len());
        buffer[..max_chars].copy_from_slice(&encoded[..max_chars]);
        (max_chars * 2) as u32
    }

    /// Reads a bool tracked device property.
    pub fn get_prop_bool(&self, device_index: u32, prop: u32) -> bool {
        if device_index != K_UN_TRACKED_DEVICE_INDEX_HMD {
            return false;
        }
        match prop {
            PROP_DEVICE_IS_WIRELESS => false,
            PROP_DEVICE_PROVIDES_BATTERY_STATUS => false,
            PROP_DEVICE_CAN_POWER_OFF => false,
            PROP_FIRMWARE_UPDATE_AVAILABLE => false,
            PROP_FIRMWARE_MANUAL_UPDATE => false,
            PROP_WILL_DRIFT_IN_YAW => false,
            _ => false,
        }
    }

    /// Reads a float tracked device property.
    pub fn get_prop_float(&self, device_index: u32, prop: u32) -> f32 {
        if device_index != K_UN_TRACKED_DEVICE_INDEX_HMD {
            return 0.0;
        }
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
    }

    /// Reads an int32 tracked device property.
    pub fn get_prop_int32(&self, device_index: u32, prop: u32) -> i32 {
        if device_index != K_UN_TRACKED_DEVICE_INDEX_HMD {
            return 0;
        }
        match prop {
            PROP_ADAPTER_INDEX => 0,
            PROP_TRACKING_RESULT => E_TRACKING_RESULT_RUNNING_OK as i32,
            PROP_DEVICE_CLASS => TRACKED_DEVICE_CLASS_HMD as i32,
            PROP_CONTROLLER_ROLE_HINT => 0,
            _ => 0,
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
            2.0 * near_z * idx,  // m00
            0.0,                  // m10
            0.0,                  // m20
            0.0,                  // m30
            0.0,                  // m01
            2.0 * near_z * idy,  // m11
            0.0,                  // m21
            0.0,                  // m31
            (right + left) * idx, // m02
            (top + bottom) * idy, // m12
            -(far_z + near_z) * idz, // m22
            -1.0,                 // m32
            0.0,                  // m03
            0.0,                  // m13
            -2.0 * far_z * near_z * idz, // m23
            0.0,                  // m33
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
            self.tracking_state.poses[device_index as usize].clone()
        } else {
            TrackedDevicePose::default()
        }
    }

    /// Polls for the next VR event. Returns `false` (no events in virtual mode).
    pub fn poll_next_event(&mut self, _event: &mut VREvent, _size: u32) -> bool {
        false
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

        // Update cumulative stats
        self.compositor_state.cumulative_stats.num_frames += 1;

        // Update frame timing
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_frame_time).as_secs_f32();
        self.compositor_state.frame_timing.frame_index = self.frame_index as u32;
        self.compositor_state.frame_timing.total_milliseconds = elapsed * 1000.0;
        self.compositor_state.frame_timing.num_frames += 1;
        self.last_frame_time = now;

        let _ = (eye, texture);
        0 // Success
    }

    /// Waits for poses and returns render/game pose arrays.
    /// Returns `EVRCompositorError` (0 = None).
    pub fn wait_get_poses(
        &mut self,
        render_poses: &mut [TrackedDevicePose; K_UN_MAX_TRACKED_DEVICE_COUNT],
        game_poses: &mut [TrackedDevicePose; K_UN_MAX_TRACKED_DEVICE_COUNT],
    ) -> u32 {
        if !self.initialized {
            return 1; // VRCompositorError_RequestFailed
        }

        // Update HMD pose (stationary at origin).
        self.tracking_state.poses[K_UN_TRACKED_DEVICE_INDEX_HMD as usize] =
            TrackedDevicePose::stationary_hmd();

        // Copy poses to output arrays.
        *render_poses = self.tracking_state.poses.clone();
        *game_poses = self.tracking_state.poses.clone();

        self.frame_index += 1;
        self.last_frame_time = Instant::now();

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
        self.compositor_state.explicit_timing_last_pose = pose.clone();
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
}

impl Default for SteamVR {
    fn default() -> Self {
        Self::new()
    }
}
