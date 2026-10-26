//! Real, opt-in MetalFX acceleration.
//!
//! `metal` 0.31 has no MetalFX bindings, so this module resolves the
//! `MTLFXSpatialScalerDescriptor` / `MTLFXTemporalScalerDescriptor` classes at
//! runtime. The framework is loaded with `dlopen` and every scaler is created
//! and driven through Objective-C message sends, which keeps the feature
//! optional: hosts without MetalFX get an exact unsupported error instead of a
//! link failure or a simulated scaler.
//!
//! The wrappers own a real `MTLFXSpatialScaler` / `MTLFXTemporalScaler`
//! (`+1` reference, released on drop). They encode on a caller-supplied
//! `MTLCommandBuffer`; no command queue or frame is created here. Temporal
//! history is owned by MetalFX itself, so the caller invalidates it through
//! [`TemporalScaler::reset`] (MetalFX exposes no history texture).

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use metal::foreign_types::ForeignTypeRef;
use std::sync::OnceLock;

const SPATIAL_DESCRIPTOR_CLASS: &str = "MTLFXSpatialScalerDescriptor";
const TEMPORAL_DESCRIPTOR_CLASS: &str = "MTLFXTemporalScalerDescriptor";

/// The colour-processing mode configured on a MetalFX scaler descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum MetalFxColorProcessingMode {
    /// sRGB/perceptual input and output.
    Perceptual = 0,
    /// Linear input and output in the `[0,1]` range.
    Linear = 1,
    /// HDR input and output (MetalFX tone maps reversibly).
    Hdr = 2,
}

/// Configuration for a spatial scaler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpatialScalerConfig {
    pub input_width: u32,
    pub input_height: u32,
    pub output_width: u32,
    pub output_height: u32,
    pub color_format: metal::MTLPixelFormat,
    pub output_format: metal::MTLPixelFormat,
    pub color_processing_mode: MetalFxColorProcessingMode,
}

/// Configuration for a temporal scaler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporalScalerConfig {
    pub input_width: u32,
    pub input_height: u32,
    pub output_width: u32,
    pub output_height: u32,
    pub color_format: metal::MTLPixelFormat,
    pub depth_format: metal::MTLPixelFormat,
    pub motion_format: metal::MTLPixelFormat,
    pub output_format: metal::MTLPixelFormat,
    /// Reactive-mask format, or `None` when the scaler was created without a
    /// reactive mask.
    pub reactive_mask_format: Option<metal::MTLPixelFormat>,
    /// Whether the depth texture uses zero for the farthest distance.
    pub depth_reversed: bool,
}

/// Inputs for one temporal encode.
pub struct TemporalInputs<'a> {
    pub color: &'a metal::TextureRef,
    pub output: &'a metal::TextureRef,
    /// Required; a `None` depth texture is rejected with an exact error.
    pub depth: Option<&'a metal::TextureRef>,
    /// Required; a `None` motion texture is rejected with an exact error.
    pub motion: Option<&'a metal::TextureRef>,
    /// Required only when the descriptor enabled a reactive mask.
    pub reactive_mask: Option<&'a metal::TextureRef>,
}

// ---------------------------------------------------------------------------
// Runtime framework / class detection
// ---------------------------------------------------------------------------

struct MetalFxFramework {
    _handle: *mut std::ffi::c_void,
}

// SAFETY: `dlopen` handles are process-wide and may be used from any thread.
// The handle is never closed.
unsafe impl Send for MetalFxFramework {}
unsafe impl Sync for MetalFxFramework {}

static FRAMEWORK: OnceLock<Option<MetalFxFramework>> = OnceLock::new();

fn framework() -> Option<&'static MetalFxFramework> {
    #[cfg(test)]
    if test_faults::force_unavailable() {
        return None;
    }
    FRAMEWORK
        .get_or_init(|| {
            // SAFETY: `dlopen` is a process-wide call; the handle is retained
            // for the lifetime of the process and never closed.
            let handle = unsafe {
                libc::dlopen(
                    c"/System/Library/Frameworks/MetalFX.framework/MetalFX".as_ptr(),
                    libc::RTLD_NOW | libc::RTLD_LOCAL,
                )
            };
            if handle.is_null() {
                None
            } else {
                Some(MetalFxFramework { _handle: handle })
            }
        })
        .as_ref()
}

fn descriptor_class(name: &str) -> Option<&'static objc::runtime::Class> {
    framework()?;
    objc::runtime::Class::get(name)
}

fn unavailable_error(class_name: &str) -> AppError {
    AppError::new(
        ReasonCode::RcUnsupportedPlatformApi,
        format!(
            "MetalFX is unavailable: MetalFX.framework did not expose {class_name} on this host"
        ),
    )
}

fn device_unsupported_error(kind: &str) -> AppError {
    AppError::new(
        ReasonCode::RcD3dFeatureUnsupported,
        format!("MetalFX {kind} scaling is not supported by this Metal device"),
    )
}

#[rustfmt::skip]
fn unreachable_alloc_error(kind: &str) -> AppError { AppError::new(ReasonCode::RcOutOfMemory, format!("MetalFX {kind}: descriptor allocation returned nil")) } // coverage: unreachable — +[NSObject alloc] always returns an object
#[rustfmt::skip]
fn unreachable_init_error(kind: &str) -> AppError { AppError::new(ReasonCode::RcOutOfMemory, format!("MetalFX {kind}: descriptor initialization returned nil")) } // coverage: unreachable — -[NSObject init] on an allocated descriptor cannot fail
#[rustfmt::skip]
fn unreachable_nil_scaler_error(kind: &str) -> AppError { AppError::new(ReasonCode::RcD3dFeatureUnsupported, format!("MetalFX {kind}: scaler factory returned nil")) } // coverage: unreachable — supportsDevice: returned YES for this validated descriptor

fn supports_device(name: &str, device: &metal::DeviceRef) -> bool {
    #[cfg(test)]
    if test_faults::force_device_unsupported() {
        return false;
    }
    let Some(class) = descriptor_class(name) else {
        return false;
    };
    let device_object = device.as_ptr() as *mut objc::runtime::Object;
    // SAFETY: `supportsDevice:` is a class method of every MetalFX descriptor
    // class (introduced together with the class in macOS 13).
    let supported: objc::runtime::BOOL = unsafe { msg_send![class, supportsDevice: device_object] };
    supported == objc::runtime::YES
}

/// Whether this Metal device can create a real spatial scaler.
pub fn spatial_supported(device: &metal::DeviceRef) -> bool {
    supports_device(SPATIAL_DESCRIPTOR_CLASS, device)
}

/// Whether this Metal device can create a real temporal scaler.
pub fn temporal_supported(device: &metal::DeviceRef) -> bool {
    supports_device(TEMPORAL_DESCRIPTOR_CLASS, device)
}

/// Whether MetalFX.framework and its descriptor classes are present.
pub fn metal_fx_available() -> bool {
    descriptor_class(SPATIAL_DESCRIPTOR_CLASS).is_some()
        && descriptor_class(TEMPORAL_DESCRIPTOR_CLASS).is_some()
}

/// The colour formats this module exposes to the scalers.
pub fn is_supported_color_format(format: metal::MTLPixelFormat) -> bool {
    matches!(
        format,
        metal::MTLPixelFormat::BGRA8Unorm | metal::MTLPixelFormat::RGBA8Unorm
    )
}

/// The subset of colour formats the DXGI present path can alias through an
/// IOSurface (the output of the scaler is blitted into that surface).
pub fn is_supported_present_format(format: metal::MTLPixelFormat) -> bool {
    is_supported_color_format(format)
}

fn validate_common(
    kind: &str,
    input_width: u32,
    input_height: u32,
    output_width: u32,
    output_height: u32,
    color_format: metal::MTLPixelFormat,
    output_format: metal::MTLPixelFormat,
) -> AppResult<()> {
    if input_width == 0 || input_height == 0 {
        return Err(AppError::new(
            ReasonCode::RcInvalidParameter,
            format!("MetalFX {kind}: input size {input_width}x{input_height} must be non-zero"),
        ));
    }
    if output_width == 0 || output_height == 0 {
        return Err(AppError::new(
            ReasonCode::RcInvalidParameter,
            format!("MetalFX {kind}: output size {output_width}x{output_height} must be non-zero"),
        ));
    }
    if output_width < input_width || output_height < input_height {
        return Err(AppError::new(
            ReasonCode::RcInvalidParameter,
            format!(
                "MetalFX {kind}: output {output_width}x{output_height} must be at least input \
                 {input_width}x{input_height}"
            ),
        ));
    }
    if !is_supported_color_format(color_format) {
        return Err(AppError::new(
            ReasonCode::RcGfxFormatUnsupported,
            format!(
                "MetalFX {kind}: unsupported color format {color_format:?} (supported: \
                 BGRA8Unorm, RGBA8Unorm)"
            ),
        ));
    }
    if !is_supported_color_format(output_format) {
        return Err(AppError::new(
            ReasonCode::RcGfxFormatUnsupported,
            format!(
                "MetalFX {kind}: unsupported output format {output_format:?} (supported: \
                 BGRA8Unorm, RGBA8Unorm)"
            ),
        ));
    }
    if color_format != output_format {
        return Err(AppError::new(
            ReasonCode::RcGfxFormatUnsupported,
            format!(
                "MetalFX {kind}: color format {color_format:?} and output format \
                 {output_format:?} must match"
            ),
        ));
    }
    Ok(())
}

fn validate_content(
    kind: &str,
    width: u32,
    height: u32,
    max_width: u32,
    max_height: u32,
) -> AppResult<()> {
    if width == 0 || height == 0 {
        return Err(AppError::new(
            ReasonCode::RcInvalidParameter,
            format!("MetalFX {kind}: input content size {width}x{height} must be non-zero"),
        ));
    }
    if width > max_width || height > max_height {
        return Err(AppError::new(
            ReasonCode::RcInvalidParameter,
            format!(
                "MetalFX {kind}: input content {width}x{height} exceeds input texture \
                 {max_width}x{max_height}"
            ),
        ));
    }
    Ok(())
}

fn check_texture(
    kind: &str,
    role: &str,
    texture: &metal::TextureRef,
    expected_format: metal::MTLPixelFormat,
    expected_width: u32,
    expected_height: u32,
) -> AppResult<()> {
    if texture.pixel_format() != expected_format {
        return Err(AppError::new(
            ReasonCode::RcGfxFormatUnsupported,
            format!(
                "MetalFX {kind}: {role} texture format {:?} does not match descriptor {:?}",
                texture.pixel_format(),
                expected_format
            ),
        ));
    }
    if texture.width() != expected_width as u64 || texture.height() != expected_height as u64 {
        return Err(AppError::new(
            ReasonCode::RcInvalidParameter,
            format!(
                "MetalFX {kind}: {role} texture {}x{} does not match expected {}x{}",
                texture.width(),
                texture.height(),
                expected_width,
                expected_height
            ),
        ));
    }
    Ok(())
}

fn set_descriptor_sizes(
    descriptor: *mut objc::runtime::Object,
    input_width: u32,
    input_height: u32,
    output_width: u32,
    output_height: u32,
    color_processing_mode: Option<MetalFxColorProcessingMode>,
) {
    // SAFETY: `descriptor` is a live MetalFX descriptor.
    unsafe {
        let _: () = msg_send![descriptor, setInputWidth: input_width as u64];
        let _: () = msg_send![descriptor, setInputHeight: input_height as u64];
        let _: () = msg_send![descriptor, setOutputWidth: output_width as u64];
        let _: () = msg_send![descriptor, setOutputHeight: output_height as u64];
        if let Some(color_processing_mode) = color_processing_mode {
            let _: () = msg_send![descriptor, setColorProcessingMode: color_processing_mode as i64];
        }
    }
}

// ---------------------------------------------------------------------------
// Spatial scaler
// ---------------------------------------------------------------------------

/// A real `MTLFXSpatialScaler`.
pub struct SpatialScaler {
    object: *mut objc::runtime::Object,
    config: SpatialScalerConfig,
    input_content_width: u32,
    input_content_height: u32,
    fence: Option<metal::Fence>,
}

impl std::fmt::Debug for SpatialScaler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpatialScaler")
            .field("config", &self.config)
            .field("input_content_width", &self.input_content_width)
            .field("input_content_height", &self.input_content_height)
            .finish()
    }
}

impl SpatialScaler {
    /// Validate `config` and create a real spatial scaler for `device`.
    pub fn new(device: &metal::DeviceRef, config: SpatialScalerConfig) -> AppResult<Self> {
        validate_common(
            "spatial",
            config.input_width,
            config.input_height,
            config.output_width,
            config.output_height,
            config.color_format,
            config.output_format,
        )?;
        let Some(class) = descriptor_class(SPATIAL_DESCRIPTOR_CLASS) else {
            return Err(unavailable_error(SPATIAL_DESCRIPTOR_CLASS));
        };
        if !supports_device(SPATIAL_DESCRIPTOR_CLASS, device) {
            return Err(device_unsupported_error("spatial"));
        }
        // SAFETY: the class and device are live; the descriptor is released
        // after the factory call, and the scaler is a `+1` reference owned by
        // this wrapper.
        unsafe {
            let descriptor: *mut objc::runtime::Object = msg_send![class, alloc];
            if descriptor.is_null() {
                // coverage: unreachable — `+[NSObject alloc]` always returns an object.
                return Err(unreachable_alloc_error("spatial")); // coverage: unreachable — +[NSObject alloc] always returns an object
            }
            let descriptor: *mut objc::runtime::Object = msg_send![descriptor, init];
            if descriptor.is_null() {
                // coverage: unreachable — `-[NSObject init]` on an allocated descriptor cannot fail.
                return Err(unreachable_init_error("spatial")); // coverage: unreachable — -[NSObject init] cannot fail
            }
            let _: () = msg_send![
                descriptor,
                setColorTextureFormat: config.color_format as u64
            ];
            let _: () = msg_send![
                descriptor,
                setOutputTextureFormat: config.output_format as u64
            ];
            set_descriptor_sizes(
                descriptor,
                config.input_width,
                config.input_height,
                config.output_width,
                config.output_height,
                Some(config.color_processing_mode),
            );
            let device_object = device.as_ptr() as *mut objc::runtime::Object;
            let object: *mut objc::runtime::Object =
                msg_send![descriptor, newSpatialScalerWithDevice: device_object];
            let _: () = msg_send![descriptor, release];
            if object.is_null() {
                // coverage: unreachable — `supportsDevice:` returned YES and the validated descriptor is supported.
                return Err(unreachable_nil_scaler_error("spatial")); // coverage: unreachable — supportsDevice: returned YES
            }
            Ok(Self {
                object,
                config,
                input_content_width: config.input_width,
                input_content_height: config.input_height,
                fence: None,
            })
        }
    }

    pub fn config(&self) -> &SpatialScalerConfig {
        &self.config
    }

    pub fn input_content_size(&self) -> (u32, u32) {
        (self.input_content_width, self.input_content_height)
    }

    /// Restrict the region of the input texture that MetalFX reads.
    pub fn set_input_content_size(&mut self, width: u32, height: u32) -> AppResult<()> {
        validate_content(
            "spatial",
            width,
            height,
            self.config.input_width,
            self.config.input_height,
        )?;
        self.input_content_width = width;
        self.input_content_height = height;
        Ok(())
    }

    /// Attach (or clear) the fence MetalFX signals/waits on.
    pub fn set_fence(&mut self, fence: Option<metal::Fence>) {
        self.fence = fence;
    }

    /// Encode the spatial upscale on an existing command buffer.
    pub fn encode(
        &self,
        command_buffer: &metal::CommandBufferRef,
        color: &metal::TextureRef,
        output: &metal::TextureRef,
    ) -> AppResult<()> {
        check_texture(
            "spatial",
            "color",
            color,
            self.config.color_format,
            self.config.input_width,
            self.config.input_height,
        )?;
        check_texture(
            "spatial",
            "output",
            output,
            self.config.output_format,
            self.config.output_width,
            self.config.output_height,
        )?;
        let command_buffer_object =
            command_buffer as *const metal::CommandBufferRef as *mut objc::runtime::Object;
        let color_object = color.as_ptr() as *mut objc::runtime::Object;
        let output_object = output.as_ptr() as *mut objc::runtime::Object;
        // SAFETY: all objects are live for the duration of the encode.
        unsafe {
            let _: () = msg_send![self.object, setColorTexture: color_object];
            let _: () = msg_send![self.object, setOutputTexture: output_object];
            let _: () =
                msg_send![self.object, setInputContentWidth: self.input_content_width as u64];
            let _: () =
                msg_send![self.object, setInputContentHeight: self.input_content_height as u64];
            match self.fence.as_ref() {
                Some(fence) => {
                    let fence_object = fence.as_ref().as_ptr() as *mut objc::runtime::Object;
                    let _: () = msg_send![self.object, setFence: fence_object];
                }
                None => {
                    let _: () = msg_send![
                        self.object,
                        setFence: std::ptr::null::<objc::runtime::Object>()
                    ];
                }
            }
            let _: () = msg_send![self.object, encodeToCommandBuffer: command_buffer_object];
        }
        Ok(())
    }
}

// SAFETY: a MetalFX scaler object is a reference-counted Metal object. Access
// is serialized by the owner (the DXGI path holds it behind a Mutex); moving
// the wrapper between threads does not race an encode.
unsafe impl Send for SpatialScaler {}

impl Drop for SpatialScaler {
    fn drop(&mut self) {
        // SAFETY: `object` is a `+1` MetalFX scaler owned by this wrapper.
        unsafe {
            let _: () = msg_send![self.object, release];
        }
    }
}

// ---------------------------------------------------------------------------
// Temporal scaler
// ---------------------------------------------------------------------------

/// A real `MTLFXTemporalScaler`.
pub struct TemporalScaler {
    object: *mut objc::runtime::Object,
    config: TemporalScalerConfig,
    input_content_width: u32,
    input_content_height: u32,
    history_valid: bool,
    reset_pending: bool,
    resets_applied: u64,
    encode_count: u64,
    jitter_offset: (f32, f32),
    motion_vector_scale: (f32, f32),
    pre_exposure: f32,
    depth_reversed: bool,
    fence: Option<metal::Fence>,
}

impl std::fmt::Debug for TemporalScaler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemporalScaler")
            .field("config", &self.config)
            .field("input_content_width", &self.input_content_width)
            .field("input_content_height", &self.input_content_height)
            .field("history_valid", &self.history_valid)
            .field("reset_pending", &self.reset_pending)
            .field("resets_applied", &self.resets_applied)
            .field("encode_count", &self.encode_count)
            .field("jitter_offset", &self.jitter_offset)
            .field("motion_vector_scale", &self.motion_vector_scale)
            .field("pre_exposure", &self.pre_exposure)
            .field("depth_reversed", &self.depth_reversed)
            .finish()
    }
}

impl TemporalScaler {
    /// Validate `config` and create a real temporal scaler for `device`.
    pub fn new(device: &metal::DeviceRef, config: TemporalScalerConfig) -> AppResult<Self> {
        validate_common(
            "temporal",
            config.input_width,
            config.input_height,
            config.output_width,
            config.output_height,
            config.color_format,
            config.output_format,
        )?;
        if config.input_width < 16 || config.input_height < 16 {
            return Err(AppError::new(
                ReasonCode::RcInvalidParameter,
                format!(
                    "MetalFX temporal: input size {}x{} is below the 16x16 minimum required by \
                     MetalFX",
                    config.input_width, config.input_height
                ),
            ));
        }
        if config.depth_format != metal::MTLPixelFormat::Depth32Float {
            return Err(AppError::new(
                ReasonCode::RcGfxFormatUnsupported,
                format!(
                    "MetalFX temporal: unsupported depth format {:?} (supported: Depth32Float)",
                    config.depth_format
                ),
            ));
        }
        if config.motion_format != metal::MTLPixelFormat::RG16Float {
            return Err(AppError::new(
                ReasonCode::RcGfxFormatUnsupported,
                format!(
                    "MetalFX temporal: unsupported motion format {:?} (supported: RG16Float)",
                    config.motion_format
                ),
            ));
        }
        if let Some(format) = config.reactive_mask_format {
            if format != metal::MTLPixelFormat::R8Unorm {
                return Err(AppError::new(
                    ReasonCode::RcGfxFormatUnsupported,
                    format!(
                        "MetalFX temporal: unsupported reactive mask format {format:?} \
                         (supported: R8Unorm)"
                    ),
                ));
            }
        }
        let Some(class) = descriptor_class(TEMPORAL_DESCRIPTOR_CLASS) else {
            return Err(unavailable_error(TEMPORAL_DESCRIPTOR_CLASS));
        };
        if !supports_device(TEMPORAL_DESCRIPTOR_CLASS, device) {
            return Err(device_unsupported_error("temporal"));
        }
        // SAFETY: the class and device are live; the descriptor is released
        // after the factory call, and the scaler is a `+1` reference owned by
        // this wrapper.
        unsafe {
            let descriptor: *mut objc::runtime::Object = msg_send![class, alloc];
            if descriptor.is_null() {
                // coverage: unreachable — `+[NSObject alloc]` always returns an object.
                return Err(unreachable_alloc_error("temporal")); // coverage: unreachable — +[NSObject alloc] always returns an object
            }
            let descriptor: *mut objc::runtime::Object = msg_send![descriptor, init];
            if descriptor.is_null() {
                // coverage: unreachable — `-[NSObject init]` on an allocated descriptor cannot fail.
                return Err(unreachable_init_error("temporal")); // coverage: unreachable — -[NSObject init] cannot fail
            }
            let _: () = msg_send![
                descriptor,
                setColorTextureFormat: config.color_format as u64
            ];
            let _: () = msg_send![
                descriptor,
                setDepthTextureFormat: config.depth_format as u64
            ];
            let _: () = msg_send![
                descriptor,
                setMotionTextureFormat: config.motion_format as u64
            ];
            let _: () = msg_send![
                descriptor,
                setOutputTextureFormat: config.output_format as u64
            ];
            set_descriptor_sizes(
                descriptor,
                config.input_width,
                config.input_height,
                config.output_width,
                config.output_height,
                None,
            );
            if let Some(format) = config.reactive_mask_format {
                #[cfg(test)]
                let responds: objc::runtime::BOOL = if test_faults::force_reactive_unsupported() {
                    objc::runtime::NO
                } else {
                    msg_send![descriptor, respondsToSelector: sel!(setReactiveMaskTextureEnabled:)]
                };
                #[cfg(not(test))]
                let responds: objc::runtime::BOOL =
                    msg_send![descriptor, respondsToSelector: sel!(setReactiveMaskTextureEnabled:)];
                if responds == objc::runtime::NO {
                    let _: () = msg_send![descriptor, release];
                    return Err(AppError::new(
                        ReasonCode::RcUnsupportedPlatformApi,
                        "MetalFX temporal: reactive masks require macOS 14.4 \
                         (setReactiveMaskTextureEnabled: is unavailable)",
                    ));
                }
                let _: () =
                    msg_send![descriptor, setReactiveMaskTextureEnabled: objc::runtime::YES];
                let _: () = msg_send![descriptor, setReactiveMaskTextureFormat: format as u64];
            }
            let device_object = device.as_ptr() as *mut objc::runtime::Object;
            let object: *mut objc::runtime::Object =
                msg_send![descriptor, newTemporalScalerWithDevice: device_object];
            let _: () = msg_send![descriptor, release];
            if object.is_null() {
                // coverage: unreachable — `supportsDevice:` returned YES and the validated descriptor is supported.
                return Err(unreachable_nil_scaler_error("temporal")); // coverage: unreachable — supportsDevice: returned YES
            }
            Ok(Self {
                object,
                config,
                input_content_width: config.input_width,
                input_content_height: config.input_height,
                history_valid: false,
                reset_pending: false,
                resets_applied: 0,
                encode_count: 0,
                jitter_offset: (0.0, 0.0),
                motion_vector_scale: (1.0, 1.0),
                pre_exposure: 1.0,
                depth_reversed: config.depth_reversed,
                fence: None,
            })
        }
    }

    pub fn config(&self) -> &TemporalScalerConfig {
        &self.config
    }

    pub fn input_content_size(&self) -> (u32, u32) {
        (self.input_content_width, self.input_content_height)
    }

    /// True after a successful encode (MetalFX has history for the next frame).
    pub fn history_valid(&self) -> bool {
        self.history_valid
    }

    /// True when the next encode will discard the scaler's internal history.
    pub fn reset_pending(&self) -> bool {
        self.reset_pending
    }

    /// Number of encodes that consumed a pending reset.
    pub fn resets_applied(&self) -> u64 {
        self.resets_applied
    }

    /// Number of successful encodes.
    pub fn encode_count(&self) -> u64 {
        self.encode_count
    }

    /// Invalidate MetalFX's internal history before the next encode.
    ///
    /// Calling this repeatedly before an encode still applies exactly one
    /// reset; a reset is consumed by the encode, so the following frame keeps
    /// its history unless `reset` is called again.
    pub fn reset(&mut self) {
        self.reset_pending = true;
    }

    /// Restrict the region of the input texture that MetalFX reads.
    pub fn set_input_content_size(&mut self, width: u32, height: u32) -> AppResult<()> {
        validate_content(
            "temporal",
            width,
            height,
            self.config.input_width,
            self.config.input_height,
        )?;
        self.input_content_width = width;
        self.input_content_height = height;
        Ok(())
    }

    pub fn set_jitter(&mut self, x: f32, y: f32) {
        self.jitter_offset = (x, y);
    }

    pub fn set_motion_vector_scale(&mut self, x: f32, y: f32) {
        self.motion_vector_scale = (x, y);
    }

    pub fn set_pre_exposure(&mut self, value: f32) {
        self.pre_exposure = value;
    }

    pub fn set_depth_reversed(&mut self, reversed: bool) {
        self.depth_reversed = reversed;
    }

    /// Attach (or clear) the fence MetalFX signals/waits on.
    pub fn set_fence(&mut self, fence: Option<metal::Fence>) {
        self.fence = fence;
    }

    /// Encode one temporal upscale on an existing command buffer.
    pub fn encode(
        &mut self,
        command_buffer: &metal::CommandBufferRef,
        inputs: TemporalInputs<'_>,
    ) -> AppResult<()> {
        if !self.history_valid && !self.reset_pending {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "MetalFX temporal: no history is available; call reset() before the first encode",
            ));
        }
        check_texture(
            "temporal",
            "color",
            inputs.color,
            self.config.color_format,
            self.config.input_width,
            self.config.input_height,
        )?;
        let depth = inputs.depth.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidParameter,
                "MetalFX temporal: depth texture is required",
            )
        })?;
        check_texture(
            "temporal",
            "depth",
            depth,
            self.config.depth_format,
            self.config.input_width,
            self.config.input_height,
        )?;
        let motion = inputs.motion.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidParameter,
                "MetalFX temporal: motion texture is required",
            )
        })?;
        check_texture(
            "temporal",
            "motion",
            motion,
            self.config.motion_format,
            self.config.input_width,
            self.config.input_height,
        )?;
        check_texture(
            "temporal",
            "output",
            inputs.output,
            self.config.output_format,
            self.config.output_width,
            self.config.output_height,
        )?;
        let reactive = match self.config.reactive_mask_format {
            Some(format) => {
                let reactive = inputs.reactive_mask.ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcInvalidParameter,
                        "MetalFX temporal: reactive mask texture is required when the descriptor \
                         enables a reactive mask",
                    )
                })?;
                check_texture(
                    "temporal",
                    "reactive mask",
                    reactive,
                    format,
                    self.config.input_width,
                    self.config.input_height,
                )?;
                Some(reactive)
            }
            None => {
                if inputs.reactive_mask.is_some() {
                    return Err(AppError::new(
                        ReasonCode::RcInvalidParameter,
                        "MetalFX temporal: reactive mask texture supplied but the descriptor did \
                         not enable a reactive mask",
                    ));
                }
                None
            }
        };

        let command_buffer_object =
            command_buffer as *const metal::CommandBufferRef as *mut objc::runtime::Object;
        let color_object = inputs.color.as_ptr() as *mut objc::runtime::Object;
        let depth_object = depth.as_ptr() as *mut objc::runtime::Object;
        let motion_object = motion.as_ptr() as *mut objc::runtime::Object;
        let output_object = inputs.output.as_ptr() as *mut objc::runtime::Object;
        let encode_reset = self.reset_pending;
        // SAFETY: all objects are live for the duration of the encode.
        unsafe {
            let _: () = msg_send![self.object, setColorTexture: color_object];
            let _: () = msg_send![self.object, setDepthTexture: depth_object];
            let _: () = msg_send![self.object, setMotionTexture: motion_object];
            let _: () = msg_send![self.object, setOutputTexture: output_object];
            let _: () =
                msg_send![self.object, setInputContentWidth: self.input_content_width as u64];
            let _: () =
                msg_send![self.object, setInputContentHeight: self.input_content_height as u64];
            let _: () = msg_send![
                self.object,
                setReset: if encode_reset {
                    objc::runtime::YES
                } else {
                    objc::runtime::NO
                }
            ];
            let _: () = msg_send![self.object, setJitterOffsetX: self.jitter_offset.0];
            let _: () = msg_send![self.object, setJitterOffsetY: self.jitter_offset.1];
            let _: () = msg_send![
                self.object,
                setMotionVectorScaleX: self.motion_vector_scale.0
            ];
            let _: () = msg_send![
                self.object,
                setMotionVectorScaleY: self.motion_vector_scale.1
            ];
            let _: () = msg_send![self.object, setPreExposure: self.pre_exposure];
            let _: () = msg_send![
                self.object,
                setDepthReversed: if self.depth_reversed {
                    objc::runtime::YES
                } else {
                    objc::runtime::NO
                }
            ];
            match reactive {
                Some(reactive) => {
                    let reactive_object = reactive.as_ptr() as *mut objc::runtime::Object;
                    let _: () = msg_send![self.object, setReactiveMaskTexture: reactive_object];
                }
                None => {
                    let _: () = msg_send![
                        self.object,
                        setReactiveMaskTexture: std::ptr::null::<objc::runtime::Object>()
                    ];
                }
            }
            match self.fence.as_ref() {
                Some(fence) => {
                    let fence_object = fence.as_ref().as_ptr() as *mut objc::runtime::Object;
                    let _: () = msg_send![self.object, setFence: fence_object];
                }
                None => {
                    let _: () = msg_send![
                        self.object,
                        setFence: std::ptr::null::<objc::runtime::Object>()
                    ];
                }
            }
            let _: () = msg_send![self.object, encodeToCommandBuffer: command_buffer_object];
        }
        self.history_valid = true;
        self.reset_pending = false;
        self.encode_count += 1;
        if encode_reset {
            self.resets_applied += 1;
        }
        Ok(())
    }
}

// SAFETY: see `SpatialScaler`; temporal encodes require `&mut self`.
unsafe impl Send for TemporalScaler {}

impl Drop for TemporalScaler {
    fn drop(&mut self) {
        // SAFETY: `object` is a `+1` MetalFX scaler owned by this wrapper.
        unsafe {
            let _: () = msg_send![self.object, release];
        }
    }
}

// ---------------------------------------------------------------------------
// Test-only capability overrides
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_faults {
    use std::cell::Cell;

    thread_local! {
        static FORCE_UNAVAILABLE: Cell<bool> = const { Cell::new(false) };
        static FORCE_DEVICE_UNSUPPORTED: Cell<bool> = const { Cell::new(false) };
        static FORCE_REACTIVE_UNSUPPORTED: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn set_force_unavailable(value: bool) {
        FORCE_UNAVAILABLE.with(|fault| fault.set(value));
    }

    pub(super) fn force_unavailable() -> bool {
        FORCE_UNAVAILABLE.with(Cell::get)
    }

    pub(super) fn set_force_device_unsupported(value: bool) {
        FORCE_DEVICE_UNSUPPORTED.with(|fault| fault.set(value));
    }

    pub(super) fn force_device_unsupported() -> bool {
        FORCE_DEVICE_UNSUPPORTED.with(Cell::get)
    }

    pub(super) fn set_force_reactive_unsupported(value: bool) {
        FORCE_REACTIVE_UNSUPPORTED.with(|fault| fault.set(value));
    }

    pub(super) fn force_reactive_unsupported() -> bool {
        FORCE_REACTIVE_UNSUPPORTED.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> metal::Device {
        metal::Device::system_default().expect("Metal device")
    }

    fn temporal_inputs<'a>(
        color: &'a metal::TextureRef,
        output: &'a metal::TextureRef,
        depth: Option<&'a metal::TextureRef>,
        motion: Option<&'a metal::TextureRef>,
        reactive: Option<&'a metal::TextureRef>,
    ) -> TemporalInputs<'a> {
        TemporalInputs {
            color,
            output,
            depth,
            motion,
            reactive_mask: reactive,
        }
    }

    fn texture(
        device: &metal::Device,
        width: u32,
        height: u32,
        format: metal::MTLPixelFormat,
        usage: metal::MTLTextureUsage,
        storage: metal::MTLStorageMode,
    ) -> metal::Texture {
        let descriptor = metal::TextureDescriptor::new();
        descriptor.set_texture_type(metal::MTLTextureType::D2);
        descriptor.set_pixel_format(format);
        descriptor.set_width(width as u64);
        descriptor.set_height(height as u64);
        descriptor.set_usage(usage);
        descriptor.set_storage_mode(storage);
        descriptor.set_sample_count(1);
        device.new_texture(&descriptor)
    }

    fn spatial_config() -> SpatialScalerConfig {
        SpatialScalerConfig {
            input_width: 4,
            input_height: 4,
            output_width: 8,
            output_height: 8,
            color_format: metal::MTLPixelFormat::RGBA8Unorm,
            output_format: metal::MTLPixelFormat::RGBA8Unorm,
            color_processing_mode: MetalFxColorProcessingMode::Perceptual,
        }
    }

    fn temporal_config(reactive: bool) -> TemporalScalerConfig {
        TemporalScalerConfig {
            input_width: 16,
            input_height: 16,
            output_width: 32,
            output_height: 32,
            color_format: metal::MTLPixelFormat::RGBA8Unorm,
            depth_format: metal::MTLPixelFormat::Depth32Float,
            motion_format: metal::MTLPixelFormat::RG16Float,
            output_format: metal::MTLPixelFormat::RGBA8Unorm,
            reactive_mask_format: reactive.then_some(metal::MTLPixelFormat::R8Unorm),
            depth_reversed: false,
        }
    }

    #[test]
    fn metalfx_unavailable_reports_exact_unsupported_error() {
        let device = device();
        test_faults::set_force_unavailable(true);
        let spatial = SpatialScaler::new(device.as_ref(), spatial_config())
            .expect_err("forced missing MetalFX must reject spatial creation");
        let temporal = TemporalScaler::new(device.as_ref(), temporal_config(false))
            .expect_err("forced missing MetalFX must reject temporal creation");
        test_faults::set_force_unavailable(false);
        assert_eq!(spatial.code, ReasonCode::RcUnsupportedPlatformApi);
        assert_eq!(
            spatial.message,
            "MetalFX is unavailable: MetalFX.framework did not expose \
             MTLFXSpatialScalerDescriptor on this host"
        );
        assert_eq!(temporal.code, ReasonCode::RcUnsupportedPlatformApi);
        assert_eq!(
            temporal.message,
            "MetalFX is unavailable: MetalFX.framework did not expose \
             MTLFXTemporalScalerDescriptor on this host"
        );
    }

    #[test]
    fn metalfx_unsupported_device_and_reactive_selector_report_exact_errors() {
        let device = device();
        test_faults::set_force_device_unsupported(true);
        let spatial = SpatialScaler::new(device.as_ref(), spatial_config())
            .expect_err("forced unsupported device must reject spatial creation");
        test_faults::set_force_device_unsupported(false);
        assert_eq!(spatial.code, ReasonCode::RcD3dFeatureUnsupported);
        assert_eq!(
            spatial.message,
            "MetalFX spatial scaling is not supported by this Metal device"
        );

        test_faults::set_force_device_unsupported(true);
        let temporal_device = TemporalScaler::new(device.as_ref(), temporal_config(false))
            .expect_err("forced unsupported device must reject temporal creation");
        test_faults::set_force_device_unsupported(false);
        assert_eq!(temporal_device.code, ReasonCode::RcD3dFeatureUnsupported);
        assert_eq!(
            temporal_device.message,
            "MetalFX temporal scaling is not supported by this Metal device"
        );

        test_faults::set_force_reactive_unsupported(true);
        let temporal = TemporalScaler::new(device.as_ref(), temporal_config(true))
            .expect_err("forced missing reactive selector must be rejected");
        test_faults::set_force_reactive_unsupported(false);
        assert_eq!(temporal.code, ReasonCode::RcUnsupportedPlatformApi);
        assert_eq!(
            temporal.message,
            "MetalFX temporal: reactive masks require macOS 14.4 \
             (setReactiveMaskTextureEnabled: is unavailable)"
        );
    }

    #[test]
    fn metalfx_spatial_rejects_bad_sizes_and_mismatched_formats() {
        let device = device();
        let mut config = spatial_config();
        config.input_width = 0;
        let error = SpatialScaler::new(device.as_ref(), config)
            .expect_err("zero input width must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX spatial: input size 0x4 must be non-zero"
        );

        let mut config = spatial_config();
        config.output_height = 0;
        let error = SpatialScaler::new(device.as_ref(), config)
            .expect_err("zero output height must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX spatial: output size 8x0 must be non-zero"
        );

        let mut config = spatial_config();
        config.output_width = 2;
        let error = SpatialScaler::new(device.as_ref(), config)
            .expect_err("output smaller than input must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX spatial: output 2x8 must be at least input 4x4"
        );

        let mut config = spatial_config();
        config.color_format = metal::MTLPixelFormat::RGBA8Uint;
        let error = SpatialScaler::new(device.as_ref(), config)
            .expect_err("unsupported color format must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX spatial: unsupported color format RGBA8Uint (supported: BGRA8Unorm, RGBA8Unorm)"
        );

        let mut config = spatial_config();
        config.output_format = metal::MTLPixelFormat::R8Unorm;
        let error = SpatialScaler::new(device.as_ref(), config)
            .expect_err("unsupported output format must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX spatial: unsupported output format R8Unorm (supported: BGRA8Unorm, RGBA8Unorm)"
        );

        let mut config = spatial_config();
        config.output_format = metal::MTLPixelFormat::BGRA8Unorm;
        let error = SpatialScaler::new(device.as_ref(), config)
            .expect_err("mismatched input/output formats must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX spatial: color format RGBA8Unorm and output format BGRA8Unorm must match"
        );
    }

    #[test]
    fn metalfx_spatial_known_pattern_readback_and_lifecycle() {
        let device = device();
        if !spatial_supported(device.as_ref()) {
            return;
        }
        let mut config = spatial_config();
        let mut scaler = SpatialScaler::new(device.as_ref(), config).expect("spatial scaler");
        assert_eq!(scaler.config(), &config);
        assert_eq!(scaler.input_content_size(), (4, 4));
        assert_eq!(format!("{scaler:?}").contains("SpatialScaler"), true);

        let error = scaler
            .set_input_content_size(0, 4)
            .expect_err("zero content width must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX spatial: input content size 0x4 must be non-zero"
        );
        let error = scaler
            .set_input_content_size(5, 4)
            .expect_err("content larger than the texture must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX spatial: input content 5x4 exceeds input texture 4x4"
        );
        scaler
            .set_input_content_size(4, 3)
            .expect("valid cropped content height");
        assert_eq!(scaler.input_content_size(), (4, 3));
        config.input_height = 4;
        assert_eq!(scaler.config(), &config);

        let input = texture(
            &device,
            4,
            4,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let mut pixels = vec![0u8; 4 * 4 * 4];
        for y in 0..4 {
            for x in 0..4 {
                let offset = (y * 4 + x) * 4;
                let color = match (x < 2, y < 2) {
                    (true, true) => [255u8, 0, 0, 255],
                    (false, true) => [0, 255, 0, 255],
                    (true, false) => [0, 0, 255, 255],
                    (false, false) => [255, 255, 255, 255],
                };
                pixels[offset..offset + 4].copy_from_slice(&color);
            }
        }
        input.replace_region(
            metal::MTLRegion::new_2d(0, 0, 4, 4),
            0,
            pixels.as_ptr() as *const std::ffi::c_void,
            4 * 4,
        );
        let output = texture(
            &device,
            8,
            8,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderWrite | metal::MTLTextureUsage::RenderTarget,
            metal::MTLStorageMode::Private,
        );
        let readback = texture(
            &device,
            8,
            8,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderRead | metal::MTLTextureUsage::RenderTarget,
            metal::MTLStorageMode::Shared,
        );
        let queue = device.new_command_queue();
        let fence = device.new_fence();
        scaler.set_fence(Some(fence));

        let command_buffer = queue.new_command_buffer();
        scaler
            .encode(command_buffer, &input, &output)
            .expect("spatial encode");
        let blit = command_buffer.new_blit_command_encoder();
        blit.copy_from_texture(
            &output,
            0,
            0,
            metal::MTLOrigin { x: 0, y: 0, z: 0 },
            metal::MTLSize::new(8, 8, 1),
            &readback,
            0,
            0,
            metal::MTLOrigin { x: 0, y: 0, z: 0 },
        );
        blit.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();
        assert_eq!(
            command_buffer.status(),
            metal::MTLCommandBufferStatus::Completed
        );

        let mut output_pixels = vec![0u8; 8 * 8 * 4];
        readback.get_bytes(
            output_pixels.as_mut_ptr() as *mut std::ffi::c_void,
            8 * 4,
            metal::MTLRegion::new_2d(0, 0, 8, 8),
            0,
        );
        for (x, y, channel) in [(2usize, 2usize, 0usize), (5, 2, 1), (2, 5, 2)] {
            let offset = (y * 8 + x) * 4;
            let pixel = &output_pixels[offset..offset + 4];
            assert_ne!(pixel[3], 0, "alpha must be preserved at ({x},{y})");
            assert_eq!(
                pixel[channel] > pixel[(channel + 1) % 3],
                true,
                "known quadrant colour must dominate at ({x},{y}): {pixel:?}"
            );
        }

        let error = scaler
            .encode(queue.new_command_buffer(), &output, &output)
            .expect_err("a texture wider than the descriptor input must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX spatial: color texture 8x8 does not match expected 4x4"
        );

        let wrong_output = texture(
            &device,
            8,
            8,
            metal::MTLPixelFormat::BGRA8Unorm,
            metal::MTLTextureUsage::ShaderWrite,
            metal::MTLStorageMode::Private,
        );
        let error = scaler
            .encode(queue.new_command_buffer(), &input, &wrong_output)
            .expect_err("output format mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX spatial: output texture format BGRA8Unorm does not match descriptor RGBA8Unorm"
        );

        let short_output = texture(
            &device,
            8,
            4,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderWrite,
            metal::MTLStorageMode::Private,
        );
        let mut second =
            SpatialScaler::new(device.as_ref(), spatial_config()).expect("second scaler");
        let error = second
            .encode(queue.new_command_buffer(), &input, &short_output)
            .expect_err("output dimension mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX spatial: output texture 8x4 does not match expected 8x8"
        );
        second.set_fence(None);
        second
            .encode(queue.new_command_buffer(), &input, &output)
            .expect("a cleared fence encodes normally");
    }

    #[test]
    fn metalfx_temporal_rejects_missing_history_inputs_and_double_reset_lifecycle() {
        let device = device();
        if !temporal_supported(device.as_ref()) {
            return;
        }
        assert_eq!(spatial_supported(device.as_ref()), true);
        assert_eq!(metal_fx_available(), true);

        let config = temporal_config(false);
        let mut scaler = TemporalScaler::new(device.as_ref(), config).expect("temporal scaler");
        assert_eq!(scaler.config(), &config);
        assert_eq!(scaler.input_content_size(), (16, 16));
        assert_eq!(format!("{scaler:?}").contains("TemporalScaler"), true);
        assert_eq!(scaler.history_valid(), false);
        assert_eq!(scaler.reset_pending(), false);
        assert_eq!(scaler.resets_applied(), 0);
        assert_eq!(scaler.encode_count(), 0);

        let color = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let output = texture(
            &device,
            32,
            32,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderWrite | metal::MTLTextureUsage::RenderTarget,
            metal::MTLStorageMode::Private,
        );
        let depth = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::Depth32Float,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let motion = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::RG16Float,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let reactive = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::R8Unorm,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let queue = device.new_command_queue();
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                temporal_inputs(&color, &output, Some(&depth), Some(&motion), None),
            )
            .expect_err("the first temporal encode without a reset has no history");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "MetalFX temporal: no history is available; call reset() before the first encode"
        );

        let error = scaler
            .set_input_content_size(0, 16)
            .expect_err("zero temporal content width must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: input content size 0x16 must be non-zero"
        );
        let error = scaler
            .set_input_content_size(17, 16)
            .expect_err("temporal content larger than the input must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: input content 17x16 exceeds input texture 16x16"
        );
        scaler
            .set_input_content_size(16, 15)
            .expect("valid temporal content size");

        scaler.reset();
        scaler.reset();
        assert_eq!(scaler.reset_pending(), true);
        scaler.set_jitter(0.25, -0.25);
        scaler.set_motion_vector_scale(2.0, 2.0);
        scaler.set_pre_exposure(1.5);
        scaler.set_depth_reversed(true);
        scaler.set_fence(Some(device.new_fence()));

        let error = scaler
            .encode(
                queue.new_command_buffer(),
                temporal_inputs(&color, &output, Some(&depth), None, None),
            )
            .expect_err("a temporal encode without motion vectors must fail");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: motion texture is required"
        );
        assert_eq!(
            scaler.reset_pending(),
            true,
            "a rejected encode must not consume the reset"
        );

        let error = scaler
            .encode(
                queue.new_command_buffer(),
                temporal_inputs(&color, &output, None, Some(&motion), None),
            )
            .expect_err("a temporal encode without depth must fail");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(error.message, "MetalFX temporal: depth texture is required");

        let error = scaler
            .encode(
                queue.new_command_buffer(),
                temporal_inputs(
                    &color,
                    &output,
                    Some(&depth),
                    Some(&motion),
                    Some(&reactive),
                ),
            )
            .expect_err("a reactive mask without descriptor support must fail");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: reactive mask texture supplied but the descriptor did not enable a reactive mask"
        );

        let command_buffer = queue.new_command_buffer();
        scaler
            .encode(
                command_buffer,
                temporal_inputs(&color, &output, Some(&depth), Some(&motion), None),
            )
            .expect("temporal encode consumes one reset");
        command_buffer.commit();
        command_buffer.wait_until_completed();
        assert_eq!(
            command_buffer.status(),
            metal::MTLCommandBufferStatus::Completed
        );
        assert_eq!(scaler.history_valid(), true);
        assert_eq!(scaler.reset_pending(), false);
        assert_eq!(scaler.resets_applied(), 1);
        assert_eq!(scaler.encode_count(), 1);

        scaler
            .encode(
                queue.new_command_buffer(),
                temporal_inputs(&color, &output, Some(&depth), Some(&motion), None),
            )
            .expect("second temporal encode reuses history");
        assert_eq!(scaler.resets_applied(), 1);
        assert_eq!(scaler.encode_count(), 2);

        scaler.reset();
        scaler.set_fence(None);
        scaler
            .encode(
                queue.new_command_buffer(),
                temporal_inputs(&color, &output, Some(&depth), Some(&motion), None),
            )
            .expect("explicit reset after a frame");
        assert_eq!(scaler.resets_applied(), 2);
        assert_eq!(scaler.encode_count(), 3);

        let bgra = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::BGRA8Unorm,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let wide_color = texture(
            &device,
            32,
            32,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                TemporalInputs {
                    color: &bgra,
                    output: &output,
                    depth: Some(&depth),
                    motion: Some(&motion),
                    reactive_mask: None,
                },
            )
            .expect_err("color format mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX temporal: color texture format BGRA8Unorm does not match descriptor RGBA8Unorm"
        );
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                TemporalInputs {
                    color: &wide_color,
                    output: &output,
                    depth: Some(&depth),
                    motion: Some(&motion),
                    reactive_mask: None,
                },
            )
            .expect_err("color dimension mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: color texture 32x32 does not match expected 16x16"
        );

        let bad_depth = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                temporal_inputs(&color, &output, Some(&bad_depth), Some(&motion), None),
            )
            .expect_err("depth format mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX temporal: depth texture format RGBA8Unorm does not match descriptor Depth32Float"
        );
        let wide_depth = texture(
            &device,
            32,
            32,
            metal::MTLPixelFormat::Depth32Float,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                temporal_inputs(&color, &output, Some(&wide_depth), Some(&motion), None),
            )
            .expect_err("depth dimension mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: depth texture 32x32 does not match expected 16x16"
        );

        let bad_motion = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                temporal_inputs(&color, &output, Some(&depth), Some(&bad_motion), None),
            )
            .expect_err("motion format mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX temporal: motion texture format RGBA8Unorm does not match descriptor RG16Float"
        );
        let wide_motion = texture(
            &device,
            32,
            32,
            metal::MTLPixelFormat::RG16Float,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                temporal_inputs(&color, &output, Some(&depth), Some(&wide_motion), None),
            )
            .expect_err("motion dimension mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: motion texture 32x32 does not match expected 16x16"
        );

        let bad_output = texture(
            &device,
            32,
            32,
            metal::MTLPixelFormat::BGRA8Unorm,
            metal::MTLTextureUsage::ShaderWrite,
            metal::MTLStorageMode::Private,
        );
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                TemporalInputs {
                    color: &color,
                    output: &bad_output,
                    depth: Some(&depth),
                    motion: Some(&motion),
                    reactive_mask: None,
                },
            )
            .expect_err("output format mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX temporal: output texture format BGRA8Unorm does not match descriptor RGBA8Unorm"
        );
        let short_output = texture(
            &device,
            32,
            16,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderWrite,
            metal::MTLStorageMode::Private,
        );
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                TemporalInputs {
                    color: &color,
                    output: &short_output,
                    depth: Some(&depth),
                    motion: Some(&motion),
                    reactive_mask: None,
                },
            )
            .expect_err("output dimension mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: output texture 32x16 does not match expected 32x32"
        );
    }

    #[test]
    fn metalfx_temporal_reactive_mask_requires_enabled_and_matching_texture() {
        let device = device();
        if !temporal_supported(device.as_ref()) {
            return;
        }
        let config = temporal_config(true);
        let mut scaler = TemporalScaler::new(device.as_ref(), config).expect("reactive scaler");
        let color = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let output = texture(
            &device,
            32,
            32,
            metal::MTLPixelFormat::RGBA8Unorm,
            metal::MTLTextureUsage::ShaderWrite,
            metal::MTLStorageMode::Private,
        );
        let depth = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::Depth32Float,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let motion = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::RG16Float,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let reactive = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::R8Unorm,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let wrong_reactive = texture(
            &device,
            16,
            16,
            metal::MTLPixelFormat::RG16Float,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let wide_reactive = texture(
            &device,
            32,
            32,
            metal::MTLPixelFormat::R8Unorm,
            metal::MTLTextureUsage::ShaderRead,
            metal::MTLStorageMode::Shared,
        );
        let queue = device.new_command_queue();
        scaler.reset();
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                TemporalInputs {
                    color: &color,
                    output: &output,
                    depth: Some(&depth),
                    motion: Some(&motion),
                    reactive_mask: None,
                },
            )
            .expect_err("an enabled reactive mask is required");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: reactive mask texture is required when the descriptor enables a reactive mask"
        );

        let error = scaler
            .encode(
                queue.new_command_buffer(),
                TemporalInputs {
                    color: &color,
                    output: &output,
                    depth: Some(&depth),
                    motion: Some(&motion),
                    reactive_mask: Some(&wrong_reactive),
                },
            )
            .expect_err("reactive mask format mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX temporal: reactive mask texture format RG16Float does not match descriptor R8Unorm"
        );
        let error = scaler
            .encode(
                queue.new_command_buffer(),
                TemporalInputs {
                    color: &color,
                    output: &output,
                    depth: Some(&depth),
                    motion: Some(&motion),
                    reactive_mask: Some(&wide_reactive),
                },
            )
            .expect_err("reactive mask dimension mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: reactive mask texture 32x32 does not match expected 16x16"
        );

        let command_buffer = queue.new_command_buffer();
        scaler
            .encode(
                command_buffer,
                TemporalInputs {
                    color: &color,
                    output: &output,
                    depth: Some(&depth),
                    motion: Some(&motion),
                    reactive_mask: Some(&reactive),
                },
            )
            .expect("matching reactive mask encodes");
        command_buffer.commit();
        command_buffer.wait_until_completed();
        assert_eq!(
            command_buffer.status(),
            metal::MTLCommandBufferStatus::Completed
        );
        assert_eq!(scaler.encode_count(), 1);
        assert_eq!(scaler.resets_applied(), 1);
    }

    #[test]
    fn metalfx_temporal_rejects_unsupported_depth_motion_and_reactive_formats() {
        let device = device();
        let mut config = temporal_config(false);
        config.input_width = 8;
        config.input_height = 8;
        config.output_width = 16;
        config.output_height = 16;
        let error = TemporalScaler::new(device.as_ref(), config)
            .expect_err("temporal inputs below the MetalFX minimum must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: input size 8x8 is below the 16x16 minimum required by MetalFX"
        );

        let mut config = temporal_config(false);
        config.output_width = 8;
        config.output_height = 8;
        let error = TemporalScaler::new(device.as_ref(), config)
            .expect_err("temporal output smaller than the input must be rejected");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX temporal: output 8x8 must be at least input 16x16"
        );

        let mut config = temporal_config(false);
        config.depth_format = metal::MTLPixelFormat::Depth24Unorm_Stencil8;
        let error = TemporalScaler::new(device.as_ref(), config)
            .expect_err("unsupported depth format must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX temporal: unsupported depth format Depth24Unorm_Stencil8 (supported: Depth32Float)"
        );

        let mut config = temporal_config(false);
        config.motion_format = metal::MTLPixelFormat::RGBA8Unorm;
        let error = TemporalScaler::new(device.as_ref(), config)
            .expect_err("unsupported motion format must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX temporal: unsupported motion format RGBA8Unorm (supported: RG16Float)"
        );

        let mut config = temporal_config(false);
        config.reactive_mask_format = Some(metal::MTLPixelFormat::RG8Unorm);
        let error = TemporalScaler::new(device.as_ref(), config)
            .expect_err("unsupported reactive mask format must be rejected");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            error.message,
            "MetalFX temporal: unsupported reactive mask format RG8Unorm (supported: R8Unorm)"
        );
    }
}
