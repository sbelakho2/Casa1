#!/usr/bin/env python3
"""Add G10: CVPixelBuffer→MTLTexture zero-copy in video_decoder.rs."""
with open('src/video_decoder.rs', 'r') as f:
    content = f.read()

# 1. Add CVMetalTextureCache FFI to vt_ffi module, before the closing brace
old_ffi_end = "    pub const kCFStringEncodingUTF8: u32 = 0x08000100;\n}"
new_ffi_end = """    pub const kCFStringEncodingUTF8: u32 = 0x08000100;

    // ---- CVMetalTextureCache (G10: GPU-side texture from CVPixelBuffer) ----

    /// Opaque type for a Metal texture cache.
    pub type CVMetalTextureCacheRef = *mut c_void;
    /// Opaque type for a CVMetalTexture (wraps MTLTexture + CVPixelBuffer).
    pub type CVMetalTextureRef = *mut c_void;

    #[link(name = "CoreVideo", kind = "framework")]
    unsafe extern "C" {
        /// `CVMetalTextureCacheCreate(allocator, cacheAttributes, mtlDevice, textureAttributes, cacheOut)`
        pub fn CVMetalTextureCacheCreate(
            allocator: CFAllocatorRef,
            cacheAttributes: CFDictionaryRef,
            mtlDevice: *mut c_void,
            textureAttributes: CFDictionaryRef,
            cacheOut: *mut CVMetalTextureCacheRef,
        ) -> i32;

        /// `CVMetalTextureCacheCreateTextureFromImage(cache, sourceImage, textureAttributes, pixelFormat, width, height, planeIndex, textureOut)`
        pub fn CVMetalTextureCacheCreateTextureFromImage(
            cache: CVMetalTextureCacheRef,
            sourceImage: CVPixelBufferRef,
            textureAttributes: CFDictionaryRef,
            pixelFormat: u32,
            width: usize,
            height: usize,
            planeIndex: usize,
            textureOut: *mut CVMetalTextureRef,
        ) -> i32;

        /// `CVMetalTextureGetTexture(texture) -> MTLTextureRef`
        pub fn CVMetalTextureGetTexture(texture: CVMetalTextureRef) -> *mut c_void;

        /// Retain a CVMetalTextureCache.
        pub fn CVMetalTextureCacheRetain(cache: CVMetalTextureCacheRef);
        /// Release a CVMetalTextureCache.
        pub fn CVMetalTextureCacheRelease(cache: CVMetalTextureCacheRef);
        /// Retain a CVMetalTexture.
        pub fn CVMetalTextureRetain(texture: CVMetalTextureRef);
        /// Release a CVMetalTexture.
        pub fn CVMetalTextureRelease(texture: CVMetalTextureRef);
    }

    /// 32-bit BGRA pixel format for Metal (kCVPixelFormatType_32BGRA).
    pub const kCVMetalTexturePixelFormatBGRA: u32 = 0x42475241;
}"""

content = content.replace(old_ffi_end, new_ffi_end, 1)

# 2. Add mtl_device and texture_cache fields to DecoderContext
old_decoder_ctx = """#[cfg(target_os = "macos")]
struct DecoderContext {
    /// Queue of decoded video frames.
    frames: Mutex<VecDeque<VideoFrame>>,
    /// Output width in pixels (may differ from encoded width after cropping).
    output_width: u32,
    /// Output height in pixels.
    output_height: u32,
    /// FPS for computing PTS/duration.
    fps: f64,
    /// Running frame counter.
    frame_number: Mutex<u64>,
}"""

new_decoder_ctx = """#[cfg(target_os = "macos")]
struct DecoderContext {
    /// Queue of decoded video frames.
    frames: Mutex<VecDeque<VideoFrame>>,
    /// Output width in pixels (may differ from encoded width after cropping).
    output_width: u32,
    /// Output height in pixels.
    output_height: u32,
    /// FPS for computing PTS/duration.
    fps: f64,
    /// Running frame counter.
    frame_number: Mutex<u64>,
    /// G10: MTLDevice pointer for creating Metal textures from CVPixelBuffers.
    mtl_device: Option<*mut std::ffi::c_void>,
    /// G10: CVMetalTextureCache for zero-copy CVPixelBuffer→MTLTexture conversion.
    texture_cache: Option<vt_ffi::CVMetalTextureCacheRef>,
}"""

content = content.replace(old_decoder_ctx, new_decoder_ctx, 1)

# 3. Add texture_cache init in VideoDecoder::new for macOS path
# Find the constructor section and add texture_cache initialization
old_new_body_macos = """            #[cfg(target_os = "macos")]
            session: None,
            #[cfg(target_os = "macos")]
            format_desc: None,
            #[cfg(target_os = "macos")]
            context: None,"""

new_new_body_macos = """            #[cfg(target_os = "macos")]
            session: None,
            #[cfg(target_os = "macos")]
            format_desc: None,
            #[cfg(target_os = "macos")]
            context: None, // mtl_device and texture_cache initialized in configure_video_toolbox"""

content = content.replace(old_new_body_macos, new_new_body_macos, 1)

# 4. In the decompression callback, when frame_data is Some, also create a Metal texture
# Find the frame creation in the callback and add MTLTexture path
old_frame_creation = """        let frame = VideoFrame {
            width: ctx.output_width.max(width),
            height: ctx.output_height.max(height),
            data,
            pts,
            duration,
            texture_id: None,
            color_space: ColorSpace::Rec709,
        };

        let mut frames = ctx.frames.lock().unwrap();
        frames.push_back(frame);"""

new_frame_creation = """        let mtl_texture = ctx.create_metal_texture_from_cvpixelbuffer(imageBuffer, width, height);
        let texture_id = mtl_texture.as_ref().map(|t| t as *const _ as u64);

        let frame = VideoFrame {
            width: ctx.output_width.max(width),
            height: ctx.output_height.max(height),
            data,
            pts,
            duration,
            texture_id,
            color_space: ColorSpace::Rec709,
        };

        let mut frames = ctx.frames.lock().unwrap();
        frames.push_back(frame);"""

content = content.replace(old_frame_creation, new_frame_creation, 1)

# 5. Add create_metal_texture_from_cvpixelbuffer method to DecoderContext
# Find the drop impl or the end of the cfg section above VideoDecoder
old_before_videodecoder = """// ===========================================================================
// VideoDecoder
// ==========================================================================="""

new_impl_decoder_ctx = """// G10: Create a Metal texture wrapping a CVPixelBuffer via CVMetalTextureCache.
#[cfg(target_os = "macos")]
impl DecoderContext {
    /// Create (or retrieve from cache) a Metal texture that shares storage with
    /// the given CVPixelBuffer. Returns None if the device or cache is not set,
    /// or if the MTLDevice/MTLTexture API is unavailable.
    fn create_metal_texture_from_cvpixelbuffer(
        &self,
        image_buffer: vt_ffi::CVPixelBufferRef,
        width: u32,
        height: u32,
    ) -> Option<metal::Texture> {
        use self::vt_ffi::*;

        let mtl_device_ptr = self.mtl_device?;
        let texture_cache = self.texture_cache?;

        if image_buffer.is_null() || width == 0 || height == 0 {
            return None;
        }

        unsafe {
            // Create a CVMetalTexture from the CVPixelBuffer (no copy)
            let mut cv_texture: CVMetalTextureRef = std::ptr::null_mut();
            let status = CVMetalTextureCacheCreateTextureFromImage(
                texture_cache,
                image_buffer,
                std::ptr::null_mut(), // textureAttributes
                kCVMetalTexturePixelFormatBGRA,
                width as usize,
                height as usize,
                0, // planeIndex
                &mut cv_texture,
            );

            if status != 0 || cv_texture.is_null() {
                return None;
            }

            // Get the underlying MTLTexture
            let mtl_texture_ptr = CVMetalTextureGetTexture(cv_texture);
            if mtl_texture_ptr.is_null() {
                CVMetalTextureRelease(cv_texture);
                return None;
            }

            // Wrap in metal::Texture (which retains the texture)
            let texture = metal::Texture::from_ptr(mtl_texture_ptr as *mut metal::MTLTexture);
            CVMetalTextureRelease(cv_texture); // Release our reference
            Some(texture)
        }
    }
}

// ===========================================================================
// VideoDecoder
// ==========================================================================="""

content = content.replace(old_before_videodecoder, new_impl_decoder_ctx, 1)

# 6. Add set_metal_device method to VideoDecoder
old_videodecoder_new_end = """            frame_number: 0,
        }
    }"""

new_videodecoder_new_end = """            frame_number: 0,
        }
    }

    /// G10: Set the Metal device for GPU-side texture creation.
    /// Must be called before decoding starts to enable zero-copy
    /// CVPixelBuffer→MTLTexture conversion in the decoder callback.
    ///
    /// Creates a CVMetalTextureCache for the given Metal device.
    #[cfg(target_os = "macos")]
    pub fn set_metal_device(&mut self, device: &metal::DeviceRef) -> AppResult<()> {
        use self::vt_ffi::*;

        let device_ptr = device.as_ptr() as *mut std::ffi::c_void;

        // Create CVMetalTextureCache
        let mut texture_cache: CVMetalTextureCacheRef = std::ptr::null_mut();
        let status = unsafe {
            CVMetalTextureCacheCreate(
                std::ptr::null_mut(), // allocator
                std::ptr::null_mut(), // cacheAttributes
                device_ptr,
                std::ptr::null_mut(), // textureAttributes
                &mut texture_cache,
            )
        };
        if status != 0 || texture_cache.is_null() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("set_metal_device: CVMetalTextureCacheCreate failed with status {status}"),
            ));
        }

        // Store the device and cache in the decoder context
        if let Some(ref ctx) = self.context {
            // We need to update the context - this is a bit tricky since it's Box<DecoderContext>
            // Use unsafe to modify via pointer
            let ctx_ptr = ctx as *const DecoderContext as *mut DecoderContext;
            unsafe {
                (*ctx_ptr).mtl_device = Some(device_ptr);
                (*ctx_ptr).texture_cache = Some(texture_cache);
            }
        }

        Ok(())
    }"""

content = content.replace(old_videodecoder_new_end, new_videodecoder_new_end, 1)

with open('src/video_decoder.rs', 'w') as f:
    f.write(content)
print("G10 applied to video_decoder.rs")
