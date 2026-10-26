use super::support::*;
use super::*;

#[test]
fn redraw_window_queues_paint_like_invalidate_rect() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "redraw-window", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime.user32.register_class_ex_w("test-window");
        let hwnd = runtime
            .user32
            .create_window_ex_w("test-window", "title", 320, 200, true, false, None, 1)
            .expect("create window");
        let _ = std::iter::from_fn(|| runtime.user32.get_message_w()).collect::<Vec<_>>();

        let redraw_window = runtime.alloc_host_thunk(HostThunk::RedrawWindow);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            redraw_window,
            &[hwnd, 0, 0, 0x0001],
        );

        assert_eq!(result, 1);
        assert_eq!(runtime.last_error, 0);
        let kinds =
            std::iter::from_fn(|| runtime.user32.get_message_w().map(|message| message.kind))
                .collect::<Vec<_>>();
        assert!(kinds.contains(&MessageKind::Paint));
    })
}

#[test]
fn create_icw_tracks_an_information_context_and_delete_dc_frees_it() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("create-ic");
        let mut memory = MemoryImage::default();
        let create_ic = runtime.alloc_host_thunk(HostThunk::CreateICW);
        let delete_dc = runtime.alloc_host_thunk(HostThunk::DeleteDC);

        let hdc = dispatch_x86_thunk(&mut runtime, &mut memory, create_ic, &[0, 0, 0, 0]);
        assert_ne!(hdc, 0, "CreateICW must return a valid HDC");
        assert!(
            runtime.device_contexts.contains_key(&hdc),
            "the information context must be a tracked device context"
        );
        // DeleteDC frees the tracked DC.
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, delete_dc, &[hdc as u32]);
        assert_eq!(result, 1);
        assert!(!runtime.device_contexts.contains_key(&hdc));
        // Deleting an unknown DC fails.
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, delete_dc, &[hdc as u32]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
    })
}

#[test]
fn gdiplus_startup_shutdown_dispatch() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "gdiplus-startup",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let token_slot = 0x30_000_u64;
        write_u64(&mut memory, token_slot, 0);
        let startup = runtime.alloc_host_thunk(HostThunk::GdiplusStartup);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                startup,
                &[token_slot as u32, 0, 0]
            ),
            0,
            "GdiplusStartup returns Ok"
        );
        let token = memory.read_u64(token_slot).expect("token");
        assert_eq!(token, 0xABCD_0001, "the GDI+ token is written");
        assert!(
            runtime.user32.gdiplus_state.initialized,
            "the GDI+ state is initialized"
        );

        let shutdown = runtime.alloc_host_thunk(HostThunk::GdiplusShutdown);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, shutdown, &[token as u32]),
            0,
            "GdiplusShutdown returns Ok"
        );
        assert!(
            !runtime.user32.gdiplus_state.initialized,
            "shutdown clears the initialized flag"
        );
        assert!(
            runtime.user32.gdiplus_state.objects.is_empty(),
            "shutdown clears the object table"
        );
    })
}

#[test]
fn gdiplus_create_hicon_from_bitmap_dispatch() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "gdiplus-hicon", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // A 3×2 bitmap built from real guest Scan0 bytes.
        let scan0 = 0x30_000_u64;
        memory.map_bytes(scan0, &[0_u8; 24]);
        let bmp_out = 0x30_100_u64;
        let from_scan0 = runtime.alloc_host_thunk(HostThunk::GdipCreateBitmapFromScan0);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            from_scan0,
            &[3, 2, 12, 0x0026_2009, scan0 as u32, bmp_out as u32],
        );
        let bmp = read_u64(&memory, bmp_out).expect("bitmap");
        let set_pixel = runtime.alloc_host_thunk(HostThunk::GdipBitmapSetPixel);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_pixel,
            &[bmp as u32, 0, 0, 0xFF00_00FF],
        );
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_pixel,
            &[bmp as u32, 2, 1, 0xFFFF_0000],
        );

        let hicon = runtime.alloc_host_thunk(HostThunk::GdipCreateHICONFromBitmap);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, hicon, &[0xDEAD, 0]),
            2,
            "an invalid bitmap reports InvalidParameter"
        );
        let hicon_out = 0x30_200_u64;
        memory.map_bytes(hicon_out, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                hicon,
                &[bmp as u32, hicon_out as u32]
            ),
            0,
            "GdipCreateHICONFromBitmap returns Ok"
        );
        let handle = read_u64(&memory, hicon_out).expect("hicon");
        assert_ne!(handle, 0);
        let icon = runtime.icons.get(&handle).expect("registry entry");
        assert_eq!((icon.width, icon.height, icon.bpp), (3, 2, 32));
        assert_eq!(icon.data.len(), 24);
        // Pixel (0, 0) is blue, pixel (2, 1) is red: top-down BGRA.
        assert_eq!(&icon.data[0..4], &[255, 0, 0, 255]);
        let red = ((1 * 3) + 2) * 4;
        assert_eq!(&icon.data[red..red + 4], &[0, 0, 255, 255]);

        // A second creation mints a distinct handle over the same pixels.
        let hicon_out2 = 0x30_208_u64;
        memory.map_bytes(hicon_out2, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                hicon,
                &[bmp as u32, hicon_out2 as u32]
            ),
            0,
            "a second HICON creation returns Ok"
        );
        let handle2 = read_u64(&memory, hicon_out2).expect("hicon 2");
        assert_ne!(handle2, handle);
        assert!(runtime.icons.contains_key(&handle2));

        // DestroyIcon has no dispatch surface: destroying drops the
        // registry entry, releasing the pixels.
        assert!(runtime.icons.remove(&handle).is_some());
        assert!(!runtime.icons.contains_key(&handle));
        assert!(runtime.icons.remove(&handle2).is_some());
    })
}

#[test]
fn gdiplus_image_attributes_and_stub_ops_dispatch() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "gdiplus-attrs", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let attrs_out = 0x30_000_u64;
        let create_attrs = runtime.alloc_host_thunk(HostThunk::GdipCreateImageAttributes);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, create_attrs, &[attrs_out as u32]),
            0,
            "GdipCreateImageAttributes returns Ok"
        );
        let attrs = read_u64(&memory, attrs_out).expect("attributes");
        assert_ne!(attrs, 0);

        let set_keys = runtime.alloc_host_thunk(HostThunk::GdipSetImageAttributesColorKeys);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_keys,
                &[attrs as u32, 0, 1, 0x0000_0000, 0x00FF_FFFF]
            ),
            0,
            "GdipSetImageAttributesColorKeys returns Ok"
        );

        let matrix = 0x30_100_u64;
        memory.map_bytes(matrix, &[0_u8; 100]);
        let set_matrix = runtime.alloc_host_thunk(HostThunk::GdipSetImageAttributesColorMatrix);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_matrix,
                &[attrs as u32, 0, 1, matrix as u32, 0, 0]
            ),
            0,
            "GdipSetImageAttributesColorMatrix returns Ok"
        );

        let dispose_attrs = runtime.alloc_host_thunk(HostThunk::GdipDisposeImageAttributes);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, dispose_attrs, &[attrs as u32]),
            0,
            "GdipDisposeImageAttributes returns Ok"
        );

        // A 2x2 red bitmap for the save/export interop checks.
        let scan0 = 0x30_200_u64;
        memory.map_bytes(scan0, &[0_u8; 16]);
        let bmp_out = 0x30_210_u64;
        let from_scan0 = runtime.alloc_host_thunk(HostThunk::GdipCreateBitmapFromScan0);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            from_scan0,
            &[2, 2, 8, 0x0026_2009, scan0 as u32, bmp_out as u32],
        );
        let bmp = read_u64(&memory, bmp_out).expect("bitmap");
        let set_pixel = runtime.alloc_host_thunk(HostThunk::GdipBitmapSetPixel);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_pixel,
            &[bmp as u32, 1, 1, 0xFFFF_0000],
        );

        // HICON-from-bitmap registers a real pixel-backed icon at the
        // bitmap's size; a null out pointer is InvalidParameter.
        let hicon = runtime.alloc_host_thunk(HostThunk::GdipCreateHICONFromBitmap);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, hicon, &[bmp as u32, 0]),
            2,
            "GdipCreateHICONFromBitmap with a null out pointer reports InvalidParameter"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, hicon, &[0xDEAD, 0]),
            2,
            "GdipCreateHICONFromBitmap with an invalid bitmap reports InvalidParameter"
        );
        let hicon_out = 0x30_218_u64;
        memory.map_bytes(hicon_out, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                hicon,
                &[bmp as u32, hicon_out as u32]
            ),
            0,
            "GdipCreateHICONFromBitmap returns Ok"
        );
        let hicon_handle = read_u64(&memory, hicon_out).expect("hicon");
        let pixel_icon = runtime.icons.get(&hicon_handle).expect("pixel HICON");
        assert_eq!((pixel_icon.width, pixel_icon.height), (2, 2));
        assert_eq!(pixel_icon.bpp, 32);
        let red_index = (2 + 1) * 4; // pixel (1, 1), top-down
        assert_eq!(
            &pixel_icon.data[red_index..red_index + 4],
            &[0, 0, 255, 255],
            "the HICON carries the bitmap's real BGRA pixels"
        );
        // DestroyIcon has no dispatch surface here; dropping the registry
        // entry releases the HICON.
        assert!(runtime.icons.remove(&hicon_handle).is_some());
        assert!(!runtime.icons.contains_key(&hicon_handle));

        // HBITMAP-from-bitmap mints a real GDI HBITMAP in the GDI bitmap
        // table (usable with SelectObject/BitBlt afterwards).
        let hbitmap = runtime.alloc_host_thunk(HostThunk::GdipCreateHBITMAPFromBitmap);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, hbitmap, &[0, 0, 0]),
            2,
            "GdipCreateHBITMAPFromBitmap with a null bitmap reports InvalidParameter"
        );
        let hbm_out = 0x30_220_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                hbitmap,
                &[bmp as u32, 0, hbm_out as u32]
            ),
            0,
            "GdipCreateHBITMAPFromBitmap returns Ok"
        );
        let hbm = read_u64(&memory, hbm_out).expect("hbm");
        let exported = runtime
            .gdi_bitmaps
            .get(&hbm)
            .expect("exported HBITMAP is registered");
        assert_eq!(exported.width, 2);
        assert_eq!(exported.height, 2);
        assert_eq!(exported.bpp, 4);

        // SaveImageToFile: PNG encoder round-trips through a real file.
        let save_file = runtime.alloc_host_thunk(HostThunk::GdipSaveImageToFile);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, save_file, &[0, 0, 0, 0]),
            2,
            "GdipSaveImageToFile with a null image reports InvalidParameter"
        );
        let png_clsid = 0x30_230_u64;
        memory.map_bytes(
            png_clsid,
            &gdiplus_guid_bytes("557cf406-1a04-11d3-9a73-0000f81ef32e"),
        );
        let host_dir = runtime
            .win32
            .guest_path_to_host_path(r"C:\images")
            .expect("host dir");
        std::fs::create_dir_all(&host_dir).expect("mkdir");
        let out_name = 0x30_240_u64;
        memory.map_bytes(out_name, &utf16_bytes(r"C:\images\roundtrip.png"));
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                save_file,
                &[bmp as u32, out_name as u32, png_clsid as u32, 0]
            ),
            0,
            "GdipSaveImageToFile encodes the PNG"
        );
        assert!(
            host_dir.join("roundtrip.png").exists(),
            "the PNG file is written"
        );
        let from_file = runtime.alloc_host_thunk(HostThunk::GdipCreateBitmapFromFile);
        let reload_out = 0x30_250_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                from_file,
                &[out_name as u32, reload_out as u32]
            ),
            0,
            "the saved PNG reloads"
        );
        let reloaded = read_u64(&memory, reload_out).expect("reloaded");
        assert_eq!(
            gdiplus_pixel(&runtime, reloaded, 1, 1),
            0xFFFF_0000,
            "the saved pixel round-trips"
        );
        // Unsupported encoders (JPEG/GIF/TIFF) report NotImplemented.
        let jpeg_clsid = 0x30_260_u64;
        memory.map_bytes(
            jpeg_clsid,
            &gdiplus_guid_bytes("557cf401-1a04-11d3-9a73-0000f81ef32e"),
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                save_file,
                &[bmp as u32, out_name as u32, jpeg_clsid as u32, 0]
            ),
            6,
            "GdipSaveImageToFile with the JPEG encoder reports NotImplemented"
        );

        // SaveImageToStream writes the encoded payload into the IStream.
        let save_stream = runtime.alloc_host_thunk(HostThunk::GdipSaveImageToStream);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, save_stream, &[0, 0, 0, 0]),
            2,
            "GdipSaveImageToStream with a null image reports InvalidParameter"
        );
        let stream_handle = 0x60_007_u64;
        runtime.com_streams.insert(
            stream_handle,
            ComStreamState {
                data: Vec::new(),
                ..Default::default()
            },
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                save_stream,
                &[bmp as u32, stream_handle as u32, png_clsid as u32, 0]
            ),
            0,
            "GdipSaveImageToStream encodes into the stream"
        );
        let stream_data = &runtime
            .com_streams
            .get(&stream_handle)
            .expect("stream")
            .data;
        assert_eq!(
            &stream_data[0..8],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
            "the stream holds PNG bytes"
        );
        assert!(stream_data.len() > 60, "the stream holds a PNG payload");

        let dispose_bmp = runtime.alloc_host_thunk(HostThunk::GdipDisposeImage);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, dispose_bmp, &[reloaded as u32]),
            0,
            "dispose of the reloaded image"
        );
    })
}

// ── Evidence-ui-gdi-sys: user32 focus/message/ANSI surface ───────────────
#[test]
fn evidence_ui_gdi_focus_and_message_a_thunks() {
    with_big_stack(|| {
        const WS_CHILD: u32 = 0x4000_0000;
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "ui-gdi-focus", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime.user32.register_class_ex_w("focus-window");
        let hwnd_a = runtime
            .user32
            .create_window_ex_styled(
                "focus-window",
                "focus-a",
                64,
                32,
                true,
                false,
                None,
                1,
                WS_CHILD,
                0,
                None,
            )
            .expect("create focus window a");
        let hwnd_b = runtime
            .user32
            .create_window_ex_styled(
                "focus-window",
                "focus-b",
                64,
                32,
                true,
                false,
                None,
                1,
                WS_CHILD,
                0,
                None,
            )
            .expect("create focus window b");
        while runtime.user32.get_message_w().is_some() {}

        // GetFocus: the first visible window creation focuses the window
        // (the focus-tracking state machine).
        let get_focus = runtime.alloc_host_thunk(HostThunk::GetFocus);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_focus, &[]),
            u64::from(hwnd_a),
            "GetFocus reflects the first visible window"
        );

        // SetFocus: returns the previous focus (the focus state machine),
        // tracks the new one, and queues the focus-transition messages.
        let set_focus = runtime.alloc_host_thunk(HostThunk::SetFocus);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_focus, &[hwnd_b]),
            u64::from(hwnd_a),
            "SetFocus returns the previous focus window"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_focus, &[]),
            u64::from(hwnd_b),
            "GetFocus reflects the SetFocus window"
        );
        // The WM_KILLFOCUS (old window) + WM_SETFOCUS (new window) pair
        // is queued in order.
        let peek = runtime.alloc_host_thunk(HostThunk::PeekMessageW);
        let msg_ptr = 0x61_000;
        memory.map_bytes(msg_ptr, &[0; 28]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                peek,
                &[msg_ptr as u32, 0, 0, 0, 1]
            ),
            1,
            "SetFocus queues WM_KILLFOCUS for the old window"
        );
        let queued = read_win32_msg(&memory, msg_ptr).expect("queued msg");
        assert_eq!(message_id(queued.kind), 0x0008, "WM_KILLFOCUS queued");
        assert_eq!(queued.hwnd, Some(hwnd_a));
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                peek,
                &[msg_ptr as u32, 0, 0, 0, 1]
            ),
            1,
            "SetFocus queues WM_SETFOCUS for the new window"
        );
        let queued = read_win32_msg(&memory, msg_ptr).expect("setfocus msg");
        assert_eq!(message_id(queued.kind), 0x0007, "WM_SETFOCUS queued");
        assert_eq!(queued.hwnd, Some(hwnd_b));

        // Switching focus back queues the reverse pair.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_focus, &[hwnd_a]),
            u64::from(hwnd_b),
            "SetFocus returns the previous focus window"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                peek,
                &[msg_ptr as u32, 0, 0, 0, 1]
            ),
            1,
            "WM_KILLFOCUS queued for the old window"
        );
        let queued = read_win32_msg(&memory, msg_ptr).expect("killfocus msg");
        assert_eq!(message_id(queued.kind), 0x0008, "WM_KILLFOCUS");
        assert_eq!(queued.hwnd, Some(hwnd_b));
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                peek,
                &[msg_ptr as u32, 0, 0, 0, 1]
            ),
            1,
            "WM_SETFOCUS queued for the new window"
        );
        let queued = read_win32_msg(&memory, msg_ptr).expect("setfocus msg");
        assert_eq!(message_id(queued.kind), 0x0007);
        assert_eq!(queued.hwnd, Some(hwnd_a));

        // Invalid window: SetFocus fails with ERROR_INVALID_WINDOW_HANDLE.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_focus, &[0xDEAD]),
            0,
            "SetFocus on an unknown window returns NULL"
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_WINDOW_HANDLE);

        // PostMessageW: posts into the queue of the window's thread with
        // the target hwnd recorded; GetMessageW retrieves it.
        let post_w = runtime.alloc_host_thunk(HostThunk::PostMessageW);
        let get_message = runtime.alloc_host_thunk(HostThunk::GetMessageW);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, post_w, &[hwnd_a, 0x0111, 42, 0]),
            1,
            "PostMessageW posts to the window's thread queue"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_message,
                &[msg_ptr as u32, 0, 0, 0]
            ),
            1,
            "GetMessageW retrieves the posted message"
        );
        let posted = read_win32_msg(&memory, msg_ptr).expect("posted msg");
        assert_eq!(
            posted.hwnd,
            Some(hwnd_a),
            "posted message targets the window"
        );
        assert_eq!(message_id(posted.kind), 0x0111);
        assert_eq!(posted.wparam, 42);

        // PostMessageW on an unknown window fails honestly.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, post_w, &[0xDEAD, 0x0111, 1, 0]),
            0,
            "PostMessageW on an unknown window returns FALSE"
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_WINDOW_HANDLE);

        // PostMessageA: identical plumbing, retrievable via GetMessageA.
        let post_a = runtime.alloc_host_thunk(HostThunk::PostMessageA);
        let get_message_a = runtime.alloc_host_thunk(HostThunk::GetMessageA);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, post_a, &[hwnd_b, 0x0112, 7, 8]),
            1,
            "PostMessageA posts to the window's thread queue"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_message_a,
                &[msg_ptr as u32, 0, 0, 0]
            ),
            1,
            "GetMessageA retrieves the ANSI-posted message"
        );
        let posted = read_win32_msg(&memory, msg_ptr).expect("posted msg a");
        assert_eq!(posted.hwnd, Some(hwnd_b));
        assert_eq!(message_id(posted.kind), 0x0112);
        assert_eq!(posted.wparam, 7);

        // GetMessageA: WM_QUIT returns 0 (the loop-termination contract).
        let post_thread = runtime.alloc_host_thunk(HostThunk::PostThreadMessageW);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, post_thread, &[1, 0x0012, 0, 0]),
            1,
            "PostThreadMessageW(WM_QUIT)"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_message_a,
                &[msg_ptr as u32, 0, 0, 0]
            ),
            0,
            "GetMessageA returns 0 for WM_QUIT"
        );

        // GetWindowTextA: the wide title converted to ANSI (CP1252).
        assert!(
            runtime
                .user32
                .set_window_text_w(hwnd_a, "Caf\u{e9} \u{2013} x"),
            "set window text"
        );
        let text_buffer = 0x62_000;
        memory.map_bytes(text_buffer, &[0; 32]);
        let get_text_a = runtime.alloc_host_thunk(HostThunk::GetWindowTextA);
        let copied = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_text_a,
            &[hwnd_a, text_buffer as u32, 32],
        );
        assert_eq!(copied, 8, "GetWindowTextA copies the ANSI byte count");
        let ansi = memory.read_bytes(text_buffer, 9).expect("ansi text");
        // "Café – x": C,a,f,0xE9,space,0x96(–),space,x + NUL
        assert_eq!(
            &ansi[..],
            &[0x43, 0x61, 0x66, 0xE9, 0x20, 0x96, 0x20, 0x78, 0x00]
        );
    })
}

#[test]
fn evidence_ui_gdi_bitmap_dc_object_thunks() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "ui-gdi-bitmap", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // CreateCompatibleBitmap: a 16x8 32-bpp bitmap, readable via
        // GetObjectW as a BITMAP.
        let create_bitmap = runtime.alloc_host_thunk(HostThunk::CreateCompatibleBitmap);
        let bitmap = dispatch_x86_thunk(&mut runtime, &mut memory, create_bitmap, &[0, 16, 8]);
        assert_ne!(bitmap, 0, "CreateCompatibleBitmap returns an HBITMAP");
        let object_buffer = 0x61_000;
        memory.map_bytes(object_buffer, &[0; 64]);
        let get_object = runtime.alloc_host_thunk(HostThunk::GetObjectW);
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_object,
            &[bitmap as u32, 64, object_buffer as u32],
        );
        assert_eq!(written, 24, "BITMAP layout on x86 is 24 bytes");
        assert_eq!(read_u32(&memory, object_buffer).expect("bmType"), 0);
        assert_eq!(read_u32(&memory, object_buffer + 4).expect("bmWidth"), 16);
        assert_eq!(read_u32(&memory, object_buffer + 8).expect("bmHeight"), 8);
        assert_eq!(
            read_u32(&memory, object_buffer + 12).expect("bmWidthBytes"),
            64
        );
        assert_eq!(
            read_u32(&memory, object_buffer + 18).expect("bmBitsPixel"),
            32
        );

        // CreateDCW: "DISPLAY" creates a screen DC; unknown drivers fail
        // with NULL + ERROR_INVALID_PARAMETER.
        let display = runtime
            .alloc_utf16_string(&mut memory, "DISPLAY")
            .expect("display name");
        let bogus = runtime
            .alloc_utf16_string(&mut memory, "BOGUSDRV")
            .expect("bogus driver");
        let create_dc = runtime.alloc_host_thunk(HostThunk::CreateDCW);
        let screen_dc = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_dc,
            &[display as u32, 0, 0, 0],
        );
        assert_ne!(screen_dc, 0, "CreateDCW(DISPLAY) creates a screen DC");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_dc,
                &[bogus as u32, 0, 0, 0]
            ),
            0,
            "CreateDCW with an unknown driver returns NULL"
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        // GetObjectW on a brush returns LOGBRUSH with the color.
        let create_brush = runtime.alloc_host_thunk(HostThunk::CreateSolidBrush);
        let brush = dispatch_x86_thunk(&mut runtime, &mut memory, create_brush, &[0x00FF_0000]);
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_object,
            &[brush as u32, 16, object_buffer as u32],
        );
        assert_eq!(written, 12, "LOGBRUSH on x86 is 12 bytes");
        assert_eq!(read_u32(&memory, object_buffer).expect("lbStyle"), 0);
        assert_eq!(
            read_u32(&memory, object_buffer + 4).expect("lbColor"),
            0x00FF_0000
        );

        // GetObjectW on a region returns the RECT geometry.
        let create_rgn = runtime.alloc_host_thunk(HostThunk::CreateRectRgn);
        let region = dispatch_x86_thunk(&mut runtime, &mut memory, create_rgn, &[1, 2, 9, 10]);
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_object,
            &[region as u32, 16, object_buffer as u32],
        );
        assert_eq!(written, 16, "RECT is 16 bytes");
        assert_eq!(read_u32(&memory, object_buffer).expect("left"), 1);
        assert_eq!(read_u32(&memory, object_buffer + 4).expect("top"), 2);
        assert_eq!(read_u32(&memory, object_buffer + 8).expect("right"), 9);
        assert_eq!(read_u32(&memory, object_buffer + 12).expect("bottom"), 10);

        // GetObjectW on an unknown object fails with 0.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_object,
                &[0x7BAD, 16, object_buffer as u32]
            ),
            0,
            "GetObjectW on an unknown object returns 0"
        );

        // GetRgnBox reports the region's bounding rectangle.
        let rgn_box = runtime.alloc_host_thunk(HostThunk::GetRgnBox);
        let rect_out = 0x61_100;
        memory.map_bytes(rect_out, &[0; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                rgn_box,
                &[region as u32, rect_out as u32]
            ),
            2,
            "GetRgnBox returns SIMPLEREGION"
        );
        assert_eq!(read_u32(&memory, rect_out).expect("left"), 1);
        assert_eq!(read_u32(&memory, rect_out + 8).expect("right"), 9);

        // GetCharWidthW: the glyph widths from the text-metrics machinery.
        let create_dc_thunk = runtime.alloc_host_thunk(HostThunk::CreateCompatibleDC);
        let mem_dc = dispatch_x86_thunk(&mut runtime, &mut memory, create_dc_thunk, &[0]);
        let widths = 0x61_200;
        memory.map_bytes(widths, &[0; 16]);
        let get_char_width = runtime.alloc_host_thunk(HostThunk::GetCharWidthW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_char_width,
                &[
                    mem_dc as u32,
                    u32::from(b'A'),
                    u32::from(b'C'),
                    widths as u32
                ]
            ),
            1,
            "GetCharWidthW succeeds"
        );
        for index in 0..3 {
            assert_eq!(
                read_u32(&memory, widths + index as u64 * 4).expect("width"),
                5,
                "5x7 glyph advance width (measure_text_bgra subtracts the trailing advance) at scale 1"
            );
        }

        // GetGlyphOutlineW: bitmap fonts fail with GDI_ERROR +
        // ERROR_CANNOT_COMPLETE (the documented error).
        let glyph_outline = runtime.alloc_host_thunk(HostThunk::GetGlyphOutlineW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                glyph_outline,
                &[mem_dc as u32, u32::from(b'A'), 0, 0, 0, 0, 0]
            ),
            GDI_ERROR as u64,
            "GetGlyphOutlineW returns GDI_ERROR for the bitmap font"
        );
        assert_eq!(runtime.last_error, ERROR_CANNOT_COMPLETE);

        // GdiFlush is an unconditional success (drawing is synchronous).
        let gdi_flush = runtime.alloc_host_thunk(HostThunk::GdiFlush);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, gdi_flush, &[]),
            1
        );

        // GdiComment: valid DC accepts; invalid DC fails.
        let gdi_comment = runtime.alloc_host_thunk(HostThunk::GdiComment);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                gdi_comment,
                &[mem_dc as u32, 4, 0x61_300_u32]
            ),
            1,
            "GdiComment succeeds on a valid DC"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, gdi_comment, &[0x7BAD, 4, 0]),
            0,
            "GdiComment fails on an invalid DC"
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        // GetPixel/SetPixel on a window DC round trip.
        runtime.user32.register_class_ex_w("pixel-window");
        let hwnd = runtime
            .user32
            .create_window_ex_styled(
                "pixel-window",
                "pixel",
                16,
                16,
                true,
                false,
                None,
                1,
                0x4000_0000,
                0,
                None,
            )
            .expect("create pixel window");
        while runtime.user32.get_message_w().is_some() {}
        let get_dc_thunk = runtime.alloc_host_thunk(HostThunk::GetDC);
        let win_dc = dispatch_x86_thunk(&mut runtime, &mut memory, get_dc_thunk, &[hwnd]);
        let set_pixel = runtime.alloc_host_thunk(HostThunk::SetPixel);
        let get_pixel = runtime.alloc_host_thunk(HostThunk::GetPixel);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_pixel,
                &[win_dc as u32, 3, 4, 0x00A1_B2C3]
            ),
            0x00A1_B2C3,
            "SetPixel returns the set COLORREF"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_pixel, &[win_dc as u32, 3, 4]),
            0x00A1_B2C3,
            "GetPixel reads back the set COLORREF"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_pixel,
                &[win_dc as u32, 99, 4]
            ),
            0xFFFF_FFFF,
            "GetPixel out of bounds returns CLR_INVALID"
        );
    })
}

#[test]
fn evidence_ui_gdi_draw_region_and_blend_thunks() {
    with_big_stack(|| {
        const WS_CHILD: u32 = 0x4000_0000;
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "ui-gdi-draw", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime.user32.register_class_ex_w("draw-window");
        let hwnd = runtime
            .user32
            .create_window_ex_styled(
                "draw-window",
                "draw",
                32,
                24,
                true,
                false,
                None,
                1,
                WS_CHILD,
                0,
                None,
            )
            .expect("create draw window");
        while runtime.user32.get_message_w().is_some() {}
        let get_dc_thunk = runtime.alloc_host_thunk(HostThunk::GetDC);
        let win_dc = dispatch_x86_thunk(&mut runtime, &mut memory, get_dc_thunk, &[hwnd]);

        // Ellipse: the interior is filled with the default white brush
        // and the outline is drawn with the default black pen.
        let ellipse = runtime.alloc_host_thunk(HostThunk::Ellipse);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                ellipse,
                &[win_dc as u32, 0, 0, 8, 8]
            ),
            1,
            "Ellipse draws into the window surface"
        );
        let surface = runtime
            .window_surfaces
            .get(&hwnd)
            .expect("window surface after Ellipse");
        let pixel = |x: usize, y: usize| {
            let index = (y * 32 + x) * 4;
            surface.bytes[index..index + 4].to_vec()
        };
        assert_eq!(
            pixel(4, 4),
            vec![0xff, 0xff, 0xff, 0xff],
            "ellipse interior uses the brush color (white)"
        );
        assert_eq!(
            pixel(0, 4),
            vec![0x00, 0x00, 0x00, 0xff],
            "ellipse boundary uses the pen color (black)"
        );

        // InvertRect: DSTINVERT (NOT all channels) on the rect.
        let set_pixel = runtime.alloc_host_thunk(HostThunk::SetPixel);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_pixel,
            &[win_dc as u32, 2, 2, 0x00FF_0000],
        );
        let rect_ptr = 0x61_000;
        memory.map_bytes(rect_ptr, &[0; 16]);
        write_u32(&mut memory, rect_ptr, 0);
        write_u32(&mut memory, rect_ptr + 4, 0);
        write_u32(&mut memory, rect_ptr + 8, 4);
        write_u32(&mut memory, rect_ptr + 12, 4);
        let invert = runtime.alloc_host_thunk(HostThunk::InvertRect);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                invert,
                &[win_dc as u32, rect_ptr as u32]
            ),
            1,
            "InvertRect inverts the rectangle pixels"
        );
        let get_pixel = runtime.alloc_host_thunk(HostThunk::GetPixel);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_pixel, &[win_dc as u32, 2, 2]),
            0x0000_FFFF,
            "DSTINVERT turns COLORREF 0x00FF0000 (blue) into 0x0000FFFF"
        );

        // CombineRgn: the RGN_* modes over region geometry.
        let create_rgn = runtime.alloc_host_thunk(HostThunk::CreateRectRgn);
        let a = dispatch_x86_thunk(&mut runtime, &mut memory, create_rgn, &[0, 0, 10, 10]);
        let b = dispatch_x86_thunk(&mut runtime, &mut memory, create_rgn, &[5, 5, 15, 15]);
        let c = dispatch_x86_thunk(&mut runtime, &mut memory, create_rgn, &[0, 0, 2, 2]);
        let combine = runtime.alloc_host_thunk(HostThunk::CombineRgn);
        let rgn_box = runtime.alloc_host_thunk(HostThunk::GetRgnBox);
        let rect_out = 0x61_100;
        memory.map_bytes(rect_out, &[0; 16]);
        // RGN_AND: [5,10)x[5,10) — a simple region.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                combine,
                &[c as u32, a as u32, b as u32, 1]
            ),
            2,
            "RGN_AND of overlapping regions is SIMPLEREGION"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                rgn_box,
                &[c as u32, rect_out as u32]
            ),
            2,
            "the combined region's bounding box"
        );
        assert_eq!(read_u32(&memory, rect_out).expect("left"), 5);
        assert_eq!(read_u32(&memory, rect_out + 4).expect("top"), 5);
        assert_eq!(read_u32(&memory, rect_out + 8).expect("right"), 10);
        assert_eq!(read_u32(&memory, rect_out + 12).expect("bottom"), 10);
        // Disjoint RGN_AND → NULLREGION.
        let far = dispatch_x86_thunk(&mut runtime, &mut memory, create_rgn, &[50, 50, 60, 60]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                combine,
                &[c as u32, a as u32, far as u32, 1]
            ),
            1,
            "disjoint RGN_AND is NULLREGION"
        );
        // RGN_OR → the union box.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                combine,
                &[c as u32, a as u32, b as u32, 2]
            ),
            2,
            "RGN_OR is SIMPLEREGION"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                rgn_box,
                &[c as u32, rect_out as u32]
            ),
            2
        );
        assert_eq!(read_u32(&memory, rect_out + 8).expect("right"), 15);
        // RGN_XOR with overlap → COMPLEXREGION.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                combine,
                &[c as u32, a as u32, b as u32, 3]
            ),
            3,
            "overlapping RGN_XOR is COMPLEXREGION"
        );
        // RGN_DIFF where b covers nothing of a → SIMPLEREGION of a.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                combine,
                &[c as u32, a as u32, far as u32, 4]
            ),
            2,
            "disjoint RGN_DIFF keeps the source region"
        );
        // Invalid handles → ERROR.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                combine,
                &[c as u32, a as u32, 0x7BAD_u32, 2]
            ),
            0,
            "CombineRgn with an invalid region returns ERROR"
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        // AlphaBlend: a memory-DC bitmap with a 50% source alpha over a
        // white destination follows the documented blend formula.
        let create_dc_thunk = runtime.alloc_host_thunk(HostThunk::CreateCompatibleDC);
        let mem_dc = dispatch_x86_thunk(&mut runtime, &mut memory, create_dc_thunk, &[0]);
        let bitmap_thunk = runtime.alloc_host_thunk(HostThunk::CreateCompatibleBitmap);
        let src_bitmap = dispatch_x86_thunk(&mut runtime, &mut memory, bitmap_thunk, &[0, 2, 2]);
        let select_thunk = runtime.alloc_host_thunk(HostThunk::SelectObject);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            select_thunk,
            &[mem_dc as u32, src_bitmap as u32],
        );
        // Solid opaque red BGRA [0,0,255,255] in the source bitmap.
        {
            let bitmap = runtime
                .gdi_bitmaps
                .get_mut(&src_bitmap)
                .expect("source bitmap");
            for pixel_bytes in bitmap.bytes.chunks_mut(4) {
                pixel_bytes.copy_from_slice(&[0, 0, 255, 255]);
            }
        }
        // White destination pixel.
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_pixel,
            &[win_dc as u32, 1, 1, 0x00FF_FFFF],
        );
        // BLENDFUNCTION: blendOp=0, flags=0, SourceConstantAlpha=0x80.
        let alpha_blend = runtime.alloc_host_thunk(HostThunk::AlphaBlend);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                alpha_blend,
                &[
                    win_dc as u32,
                    1,
                    1,
                    1,
                    1,
                    mem_dc as u32,
                    0,
                    0,
                    1,
                    1,
                    0x0080_0000
                ]
            ),
            1,
            "AlphaBlend composites the source over the destination"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_pixel, &[win_dc as u32, 1, 1]),
            0x007F_7FFF,
            "50% red over white: B=0x7F, G=0x7F, R=0xFF (COLORREF 0x007F7FFF)"
        );

        // TransparentBlt: the transparent color is skipped.
        let bitmap2_thunk = runtime.alloc_host_thunk(HostThunk::CreateCompatibleBitmap);
        let src_bitmap2 = dispatch_x86_thunk(&mut runtime, &mut memory, bitmap2_thunk, &[0, 2, 1]);
        {
            let bitmap = runtime
                .gdi_bitmaps
                .get_mut(&src_bitmap2)
                .expect("second source bitmap");
            bitmap.bytes[0..4].copy_from_slice(&[0, 0, 255, 255]); // red
            bitmap.bytes[4..8].copy_from_slice(&[0, 255, 0, 255]); // green
        }
        let select2_thunk = runtime.alloc_host_thunk(HostThunk::SelectObject);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            select2_thunk,
            &[mem_dc as u32, src_bitmap2 as u32],
        );
        // White destination pixels.
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_pixel,
            &[win_dc as u32, 5, 5, 0x00FF_FFFF],
        );
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_pixel,
            &[win_dc as u32, 6, 5, 0x00FF_FFFF],
        );
        let transparent_blt = runtime.alloc_host_thunk(HostThunk::TransparentBlt);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                transparent_blt,
                &[
                    win_dc as u32,
                    5,
                    5,
                    2,
                    1,
                    mem_dc as u32,
                    0,
                    0,
                    2,
                    1,
                    0x0000_FF00
                ]
            ),
            1,
            "TransparentBlt copies the non-transparent pixels"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_pixel, &[win_dc as u32, 5, 5]),
            0x0000_00FF,
            "red pixel copied"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_pixel, &[win_dc as u32, 6, 5]),
            0x00FF_FFFF,
            "green (transparent) pixel skipped — destination kept"
        );

        // DrawTextExW: DT_CALCRECT reports the measured metrics through
        // the same machinery as DrawTextW.
        let text_ptr = runtime.alloc_utf16_string(&mut memory, "Hi").expect("text");
        let draw_rect = 0x61_200;
        memory.map_bytes(draw_rect, &[0; 16]);
        write_u32(&mut memory, draw_rect, 0);
        write_u32(&mut memory, draw_rect + 4, 0);
        write_u32(&mut memory, draw_rect + 8, 100);
        write_u32(&mut memory, draw_rect + 12, 100);
        let draw_text_ex = runtime.alloc_host_thunk(HostThunk::DrawTextExW);
        let height = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            draw_text_ex,
            &[
                win_dc as u32,
                text_ptr as u32,
                2,
                draw_rect as u32,
                0x0400,
                0,
            ],
        );
        assert_eq!(height, 8, "DT_CALCRECT returns the measured line height");
        assert_eq!(
            read_u32(&memory, draw_rect + 8).expect("right"),
            11,
            "DT_CALCRECT tightens the rect width to the text width"
        );
    })
}

#[test]
fn evidence_ui_gdi_setupapi_device_info_sets() {
    with_big_stack(|| {
        const CLASS_GUID: &str = "{6BDD1FC1-810F-11D0-BEC7-08002BE2092F}";
        const SPDRP_DEVICEDESC: u32 = 0;
        const SPDRP_FRIENDLYNAME: u32 = 12;
        const DIF_INSTALLDEVICE: u32 = 0x0000_0002;
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "ui-gdi-setupapi",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        // Seed the guest registry device store: two ROOT devices with a
        // class GUID, plus the class database entry.
        for instance in ["0000", "0001"] {
            let key = format!("SYSTEM\\CurrentControlSet\\Enum\\ROOT\\SYSTEM\\{instance}");
            ge.registry_set_value(
                "HKLM",
                &key,
                "DeviceDesc",
                "REG_SZ",
                json!("Fake Display Adapter"),
                RegistryView::Native,
            )
            .expect("seed DeviceDesc");
            ge.registry_set_value(
                "HKLM",
                &key,
                "ClassGUID",
                "REG_SZ",
                json!(CLASS_GUID),
                RegistryView::Native,
            )
            .expect("seed ClassGUID");
        }
        ge.registry_set_value(
            "HKLM",
            &format!("SYSTEM\\CurrentControlSet\\Control\\Class\\{CLASS_GUID}"),
            "",
            "REG_SZ",
            json!("Display adapters"),
            RegistryView::Native,
        )
        .expect("seed class description");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // The class GUID struct bytes for
        // {6BDD1FC1-810F-11D0-BEC7-08002BE2092F}.
        let guid_ptr = 0x61_000;
        memory.map_bytes(
            guid_ptr,
            &[
                0xC1, 0x1F, 0xDD, 0x6B, // Data1 LE
                0x0F, 0x81, // Data2 LE
                0xD0, 0x11, // Data3 LE
                0xBE, 0xC7, 0x08, 0x00, 0x2B, 0xE2, 0x09, 0x2F, // Data4
            ],
        );

        // SetupDiGetClassDevsW: the device info set from the guest
        // registry device store, filtered by class.
        let get_class_devs = runtime.alloc_host_thunk(HostThunk::SetupDiGetClassDevsW);
        let dev_info_set = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_class_devs,
            &[guid_ptr as u32, 0, 0, 0],
        );
        assert_ne!(
            dev_info_set,
            u32::MAX as u64,
            "SetupDiGetClassDevsW for an installed class succeeds"
        );
        assert_ne!(dev_info_set, 0, "the device info set handle is valid");

        // Unknown class GUID → INVALID_HANDLE_VALUE + ERROR_INVALID_PARAMETER.
        let bogus_guid_ptr = 0x61_010;
        memory.map_bytes(bogus_guid_ptr, &[0x11; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_class_devs,
                &[bogus_guid_ptr as u32, 0, 0, 0]
            ),
            u32::MAX as u64,
            "an unknown class GUID returns INVALID_HANDLE_VALUE"
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        // SetupDiEnumDeviceInfo: fills SP_DEVINFO_DATA, then the
        // enumeration ends with ERROR_NO_MORE_ITEMS.
        let dev_data = 0x61_020;
        memory.map_bytes(dev_data, &[0; 28]);
        write_u32(&mut memory, dev_data, 28); // cbSize
        let enum_device = runtime.alloc_host_thunk(HostThunk::SetupDiEnumDeviceInfo);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_device,
                &[dev_info_set as u32, 0, dev_data as u32]
            ),
            1,
            "SetupDiEnumDeviceInfo enumerates device 0"
        );
        assert_eq!(read_u32(&memory, dev_data + 20).expect("devinst"), 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_device,
                &[dev_info_set as u32, 1, dev_data as u32]
            ),
            1,
            "SetupDiEnumDeviceInfo enumerates device 1"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_device,
                &[dev_info_set as u32, 2, dev_data as u32]
            ),
            0,
            "SetupDiEnumDeviceInfo past the end fails"
        );
        assert_eq!(runtime.last_error, ERROR_NO_MORE_ITEMS);

        // SetupDiGetDeviceInstanceIdW: "ROOT\\SYSTEM\\0001" (devinst 1 is
        // the last enumerated element).
        let id_buffer = 0x61_040;
        memory.map_bytes(id_buffer, &[0; 64]);
        let required = 0x61_080;
        memory.map_bytes(required, &[0; 4]);
        let get_instance_id = runtime.alloc_host_thunk(HostThunk::SetupDiGetDeviceInstanceIdW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_instance_id,
                &[
                    dev_info_set as u32,
                    dev_data as u32,
                    id_buffer as u32,
                    32,
                    required as u32
                ]
            ),
            1,
            "SetupDiGetDeviceInstanceIdW succeeds"
        );
        assert_eq!(
            read_utf16_string(&memory, id_buffer).expect("instance id"),
            "ROOT\\SYSTEM\\0001"
        );
        assert_eq!(read_u32(&memory, required).expect("required"), 17);

        // SetupDiGetDeviceRegistryPropertyW: reads DeviceDesc from the
        // device's guest-registry key.
        let property_buffer = 0x61_0A0;
        memory.map_bytes(property_buffer, &[0; 64]);
        let data_type = 0x61_100;
        memory.map_bytes(data_type, &[0; 4]);
        let required = 0x61_110;
        memory.map_bytes(required, &[0; 4]);
        let get_property = runtime.alloc_host_thunk(HostThunk::SetupDiGetDeviceRegistryPropertyW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_property,
                &[
                    dev_info_set as u32,
                    dev_data as u32,
                    SPDRP_DEVICEDESC,
                    data_type as u32,
                    property_buffer as u32,
                    64,
                    required as u32
                ]
            ),
            1,
            "SetupDiGetDeviceRegistryPropertyW reads the device property"
        );
        assert_eq!(read_u32(&memory, data_type).expect("reg type"), 1, "REG_SZ");
        assert_eq!(
            read_utf16_string(&memory, property_buffer).expect("description"),
            "Fake Display Adapter"
        );
        // Missing property → ERROR_INVALID_DATA (documented).
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_property,
                &[
                    dev_info_set as u32,
                    dev_data as u32,
                    SPDRP_FRIENDLYNAME,
                    data_type as u32,
                    property_buffer as u32,
                    64,
                    required as u32
                ]
            ),
            0,
            "a missing property fails"
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_DATA);

        // SetupDiOpenDeviceInfoW: opens the second device instance.
        let instance2_ptr = runtime
            .alloc_utf16_string(&mut memory, "ROOT\\SYSTEM\\0001")
            .expect("instance 2");
        let open_device = runtime.alloc_host_thunk(HostThunk::SetupDiOpenDeviceInfoW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_device,
                &[
                    dev_info_set as u32,
                    instance2_ptr as u32,
                    0,
                    0,
                    dev_data as u32
                ]
            ),
            1,
            "SetupDiOpenDeviceInfoW opens ROOT\\SYSTEM\\0001"
        );
        assert_eq!(read_u32(&memory, dev_data + 20).expect("devinst"), 1);
        let missing_instance = runtime
            .alloc_utf16_string(&mut memory, "ROOT\\MISSING\\0000")
            .expect("missing instance");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_device,
                &[
                    dev_info_set as u32,
                    missing_instance as u32,
                    0,
                    0,
                    dev_data as u32
                ]
            ),
            0,
            "opening an unknown instance fails"
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_DEVINST);

        // SetupDiSetDeviceRegistryPropertyW: writes into the guest
        // registry; SetupDiGetDeviceRegistryPropertyW reads it back.
        let set_property = runtime.alloc_host_thunk(HostThunk::SetupDiSetDeviceRegistryPropertyW);
        let friendly = runtime
            .alloc_utf16_string(&mut memory, "My Fancy Device")
            .expect("friendly name");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_property,
                &[
                    dev_info_set as u32,
                    dev_data as u32,
                    SPDRP_FRIENDLYNAME,
                    friendly as u32,
                    32
                ]
            ),
            1,
            "SetupDiSetDeviceRegistryPropertyW writes the property"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_property,
                &[
                    dev_info_set as u32,
                    dev_data as u32,
                    SPDRP_FRIENDLYNAME,
                    data_type as u32,
                    property_buffer as u32,
                    64,
                    required as u32
                ]
            ),
            1,
            "the written property reads back"
        );
        assert_eq!(
            read_utf16_string(&memory, property_buffer).expect("friendly name"),
            "My Fancy Device"
        );

        // SetupDiGetClassDescriptionW: from the class database.
        let class_desc = 0x61_140;
        memory.map_bytes(class_desc, &[0; 64]);
        let get_class_desc = runtime.alloc_host_thunk(HostThunk::SetupDiGetClassDescriptionW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_class_desc,
                &[guid_ptr as u32, class_desc as u32, 32, required as u32]
            ),
            1,
            "SetupDiGetClassDescriptionW succeeds"
        );
        assert_eq!(
            read_utf16_string(&memory, class_desc).expect("class description"),
            "Display adapters"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_class_desc,
                &[
                    bogus_guid_ptr as u32,
                    class_desc as u32,
                    32,
                    required as u32
                ]
            ),
            0,
            "an unknown class fails"
        );
        assert_eq!(runtime.last_error, ERROR_CLASS_DOES_NOT_EXIST);

        // SetupDiCallClassInstaller: standard DIF codes are handled by
        // the default installer; unknown codes fail.
        let call_installer = runtime.alloc_host_thunk(HostThunk::SetupDiCallClassInstaller);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                call_installer,
                &[DIF_INSTALLDEVICE, dev_info_set as u32, dev_data as u32]
            ),
            1,
            "DIF_INSTALLDEVICE is handled by the default installer"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                call_installer,
                &[0x7FFF, dev_info_set as u32, dev_data as u32]
            ),
            0,
            "an unknown DIF code fails"
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        // Driver lists: building succeeds with an empty database;
        // enumeration ends with ERROR_NO_MORE_ITEMS and selection fails
        // with ERROR_NO_DEVICE_SELECTED.
        let build_drivers = runtime.alloc_host_thunk(HostThunk::SetupDiBuildDriverInfoList);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                build_drivers,
                &[dev_info_set as u32, dev_data as u32, 1]
            ),
            1,
            "SetupDiBuildDriverInfoList succeeds (empty driver database)"
        );
        let enum_drivers = runtime.alloc_host_thunk(HostThunk::SetupDiEnumDriverInfoW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_drivers,
                &[dev_info_set as u32, dev_data as u32, 1, 0, 0]
            ),
            0,
            "SetupDiEnumDriverInfoW reports the exhausted empty list"
        );
        assert_eq!(runtime.last_error, ERROR_NO_MORE_ITEMS);
        let selected_driver = runtime.alloc_host_thunk(HostThunk::SetupDiGetSelectedDriverW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                selected_driver,
                &[dev_info_set as u32, dev_data as u32, 0]
            ),
            0,
            "SetupDiGetSelectedDriverW fails with no selected driver"
        );
        assert_eq!(runtime.last_error, ERROR_NO_DEVICE_SELECTED);
        let destroy_drivers = runtime.alloc_host_thunk(HostThunk::SetupDiDestroyDriverInfoList);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                destroy_drivers,
                &[dev_info_set as u32, dev_data as u32, 1]
            ),
            1,
            "SetupDiDestroyDriverInfoList frees the list"
        );

        // SetupDiInstallDevice / SetupDiUninstallDevice: the device's
        // guest-registry InstallState flips between PRESENT and
        // NOTPRESENT.
        let install = runtime.alloc_host_thunk(HostThunk::SetupDiInstallDevice);
        let uninstall = runtime.alloc_host_thunk(HostThunk::SetupDiUninstallDevice);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                install,
                &[dev_info_set as u32, dev_data as u32]
            ),
            1,
            "SetupDiInstallDevice succeeds"
        );
        assert_eq!(
            runtime
                .win32
                .ge()
                .registry_get_value(
                    "HKLM",
                    "SYSTEM\\CurrentControlSet\\Enum\\ROOT\\SYSTEM\\0001",
                    "InstallState",
                    RegistryView::Native,
                )
                .expect("read InstallState")
                .expect("InstallState value")
                .data
                .as_u64(),
            Some(0),
            "install marks DEVINST_STATE_PRESENT"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                uninstall,
                &[dev_info_set as u32, dev_data as u32]
            ),
            1,
            "SetupDiUninstallDevice succeeds"
        );
        assert_eq!(
            runtime
                .win32
                .ge()
                .registry_get_value(
                    "HKLM",
                    "SYSTEM\\CurrentControlSet\\Enum\\ROOT\\SYSTEM\\0001",
                    "InstallState",
                    RegistryView::Native,
                )
                .expect("read InstallState")
                .expect("InstallState value")
                .data
                .as_u64(),
            Some(1),
            "uninstall marks DEVINST_STATE_NOTPRESENT"
        );

        // SetupDiDestroyDeviceInfoList: frees the set; a second destroy
        // fails.
        let destroy_list = runtime.alloc_host_thunk(HostThunk::SetupDiDestroyDeviceInfoList);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                destroy_list,
                &[dev_info_set as u32]
            ),
            1,
            "SetupDiDestroyDeviceInfoList frees the set"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                destroy_list,
                &[dev_info_set as u32]
            ),
            0,
            "destroying an unknown set fails"
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
    })
}

// ── evidence-mid: shell32 icon extraction from a real PE resource ─────
#[test]
fn evidence_mid_shell32_extract_icon_resource_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mid-shell-icon");
        let mut memory = MemoryImage::default();

        // A PE with an RT_ICON resource tree (16×16 32-bpp icon).
        let icon_pe = build_test_pe_with_icon();
        let guest_path = r"C:\game\app.exe";
        let host_path = runtime
            .win32
            .guest_path_to_host_path(guest_path)
            .expect("host path");
        if let Some(parent) = host_path.parent() {
            std::fs::create_dir_all(parent).expect("parent dir");
        }
        std::fs::write(&host_path, &icon_pe).expect("write icon PE");

        // ExtractIconW returns a HICON handle backed by the resource.
        let file_ptr = runtime
            .alloc_utf16_string(&mut memory, guest_path)
            .expect("file");
        let extract_icon = runtime.alloc_host_thunk(HostThunk::ExtractIconW);
        let icon_handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            extract_icon,
            &[0, file_ptr as u32, 0],
        );
        assert_ne!(icon_handle, 0, "the icon resource yields a HICON");
        let icon = runtime.icons.get(&icon_handle).expect("icon image");
        assert_eq!(icon.width, 16);
        assert_eq!(icon.height, 16);
        assert!(!icon.data.is_empty());

        // ExtractIconExW extracts the icon into the large/small arrays.
        let large_out = 0x66_000;
        let small_out = 0x66_100;
        memory.map_bytes(large_out, &[0; 16]);
        memory.map_bytes(small_out, &[0; 16]);
        let extract_ex = runtime.alloc_host_thunk(HostThunk::ExtractIconExW);
        let extracted = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            extract_ex,
            &[file_ptr as u32, 0, large_out as u32, small_out as u32, 1],
        );
        assert_eq!(extracted, 1, "one icon is extracted");
        let large_icon = read_u32(&memory, large_out).expect("large icon");
        let small_icon = read_u32(&memory, small_out).expect("small icon");
        assert_ne!(large_icon, 0);
        assert_ne!(small_icon, 0);
        assert!(
            runtime.icons.contains_key(&u64::from(large_icon)),
            "the large HICON is registered"
        );
        assert!(
            runtime.icons.contains_key(&u64::from(small_icon)),
            "the small HICON is registered"
        );
    })
}

#[test]
fn evidence_wic_imaging_factory_and_bitmap_pipeline() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-wic");
        let mut memory = MemoryImage::default();
        let factory_thunk: u64 = runtime.alloc_host_thunk(HostThunk::WicCreateImagingFactory);
        let create_bitmap: u64 =
            runtime.alloc_host_thunk(HostThunk::WicFactoryCreateBitmapFromMemory);
        let get_size: u64 = runtime.alloc_host_thunk(HostThunk::WicSourceGetSize);
        let copy_pixels: u64 = runtime.alloc_host_thunk(HostThunk::WicSourceCopyPixels);
        let create_scaler: u64 = runtime.alloc_host_thunk(HostThunk::WicFactoryCreateBitmapScaler);
        let scaler_initialize: u64 = runtime.alloc_host_thunk(HostThunk::WicScalerInitialize);
        let create_palette: u64 = runtime.alloc_host_thunk(HostThunk::WicFactoryCreatePalette);
        let palette_custom: u64 = runtime.alloc_host_thunk(HostThunk::WicPaletteInitializeCustom);
        let palette_colors: u64 = runtime.alloc_host_thunk(HostThunk::WicPaletteGetColors);
        let map_schema: u64 = runtime.alloc_host_thunk(HostThunk::WicMapSchemaToName);
        let decoder: u64 = runtime.alloc_host_thunk(HostThunk::WicFactoryCreateDecoderFromFilename);

        let factory_out = 0x41_000_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                factory_thunk,
                &[0, factory_out as u32]
            ),
            0
        );
        let factory = read_guest_pointer(&memory, factory_out, GuestArch::X86).unwrap();
        assert_ne!(factory, 0);

        // GUID_WICPixelFormat32bppBGRA {6fddc344-4e03-4bfe-b185-3d77768dc90f}
        let format = 0x41_100_u64;
        memory.map_bytes(
            format,
            &[
                0x44, 0xc3, 0xdd, 0x6f, 0x03, 0x4e, 0xfe, 0x4b, 0xb1, 0x85, 0x3d, 0x77, 0x76, 0x8d,
                0xc9, 0x0f,
            ],
        );
        let texels = 0x41_200_u64;
        memory.map_bytes(
            texels,
            &[
                0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255,
            ],
        );
        let bitmap_out = 0x41_300_u64;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_bitmap,
            &[
                factory as u32,
                2,
                2,
                format as u32,
                8,
                16,
                texels as u32,
                1,
                bitmap_out as u32,
            ],
        );
        assert_eq!(hr, 0, "CreateBitmapFromMemory");
        let bitmap = read_guest_pointer(&memory, bitmap_out, GuestArch::X86).unwrap();
        assert_ne!(bitmap, 0);

        let width_out = 0x41_400_u64;
        let height_out = 0x41_410_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_size,
                &[bitmap as u32, width_out as u32, height_out as u32]
            ),
            0
        );
        assert_eq!(read_guest_u32(&memory, width_out).unwrap(), 2);
        assert_eq!(read_guest_u32(&memory, height_out).unwrap(), 2);

        let pixels_out = 0x41_500_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                copy_pixels,
                &[bitmap as u32, 0, 8, 16, pixels_out as u32]
            ),
            0
        );
        let pixels = memory.read_bytes(pixels_out, 16).unwrap();
        assert_eq!(
            &pixels[..4],
            &[0, 0, 255, 255],
            "first texel got {pixels:?}"
        );

        // The scaler chain: scale the 2x2 to 1x1.
        let scaler_out = 0x41_600_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_scaler,
                &[factory as u32, scaler_out as u32]
            ),
            0
        );
        let scaler = read_guest_pointer(&memory, scaler_out, GuestArch::X86).unwrap();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                scaler_initialize,
                &[scaler as u32, bitmap as u32, 1, 1, 0]
            ),
            0
        );
        let scaled_out = 0x41_700_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                copy_pixels,
                &[scaler as u32, 0, 4, 4, scaled_out as u32]
            ),
            0
        );
        let scaled = memory.read_bytes(scaled_out, 4).unwrap();
        assert_eq!(&scaled[..4], &[0, 0, 255, 255], "scaled texel");

        // Palette round trip.
        let palette_out = 0x41_800_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_palette,
                &[factory as u32, palette_out as u32]
            ),
            0
        );
        let palette = read_guest_pointer(&memory, palette_out, GuestArch::X86).unwrap();
        let colors_in = 0x41_900_u64;
        memory.map_bytes(colors_in, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                palette_custom,
                &[palette as u32, colors_in as u32, 2]
            ),
            0
        );
        let colors_out = 0x41_a00_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                palette_colors,
                &[palette as u32, 2, colors_out as u32, 0x41_b00]
            ),
            0
        );
        assert_eq!(read_guest_u32(&memory, colors_out).unwrap(), 0x0403_0201);

        // The schema mapping helper.
        let schema = 0x41_c00_u64;
        memory.map_bytes(
            schema,
            &[0x45, 0x00, 0x78, 0x00, 0x69, 0x00, 0x66, 0x00, 0x00, 0x00],
        );
        // GUID_MetadataFormatExif {1c4ad97e-2b73-4b3a-9238-0265d443a65c}
        memory.map_bytes(
            0x41_e00_u64,
            &[
                0x7e, 0xd9, 0x4a, 0x1c, 0x73, 0x2b, 0x3a, 0x4b, 0x92, 0x38, 0x02, 0x65, 0xd4, 0x43,
                0xa6, 0x5c,
            ],
        );
        let name_out = 0x41_d00_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                map_schema,
                &[0x41_e00, schema as u32, 64, name_out as u32, 0x41_f00]
            ),
            0
        );
        let name_bytes = memory.read_bytes(name_out, 10).unwrap();
        let name = String::from_utf16_lossy(
            &name_bytes
                .as_chunks::<2>()
                .0
                .iter()
                .take_while(|c| c[0] != 0 || c[1] != 0)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        assert_eq!(name, "Exif");

        // No codecs: the decoder entry point answers WIC_E_CODECNOTFOUND.
        let decoder_out = 0x41_f10_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                decoder,
                &[factory as u32, 0x41_f20, 0, 0, decoder_out as u32]
            ),
            0x8898_2f02
        );
        assert_eq!(
            read_guest_pointer(&memory, decoder_out, GuestArch::X86).unwrap(),
            0
        );
    })
}

#[test]
fn evidence_theme_imagehlp_hid_acm_msi_surfaces() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-extras");
        let mut memory = MemoryImage::default();

        // ── uxtheme ──
        let is_app_themed: u64 = runtime.alloc_host_thunk(HostThunk::IsAppThemed);
        let open_theme: u64 = runtime.alloc_host_thunk(HostThunk::OpenThemeData);
        let theme_color: u64 = runtime.alloc_host_thunk(HostThunk::GetThemeColor);
        let theme_sys_color: u64 = runtime.alloc_host_thunk(HostThunk::GetThemeSysColor);
        let close_theme: u64 = runtime.alloc_host_thunk(HostThunk::CloseThemeData);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, is_app_themed, &[]),
            1
        );
        let class_ptr = 0x41_000_u64;
        let class_wide: Vec<u16> = "BUTTON".encode_utf16().chain([0]).collect();
        for (i, unit) in class_wide.iter().enumerate() {
            write_guest_u16(&mut memory, class_ptr + (i as u64 * 2), *unit).ok();
        }
        let theme = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_theme,
            &[0x1000, class_ptr as u32],
        );
        assert_ne!(theme, 0);
        let color_out = 0x41_100_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                theme_color,
                &[theme as u32, 0, 0, 0x0d00, color_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, color_out).unwrap(),
            0,
            "TMT_TEXTCOLOR"
        );
        let sys_out = 0x41_110_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                theme_sys_color,
                &[theme as u32, 4, sys_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, sys_out).unwrap(),
            0x00ff_ffff,
            "COLOR_BTNFACE"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close_theme, &[theme as u32]),
            0
        );
        assert!(!runtime.theme_handles.contains_key(&theme));

        // ── imagehlp: MapAndLoad a real PE-ish image + checksum ──
        let map_and_load: u64 = runtime.alloc_host_thunk(HostThunk::MapAndLoad);
        let checksum: u64 = runtime.alloc_host_thunk(HostThunk::CheckSumMappedFile);
        let mut pe = vec![0_u8; 0x200];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(&0x4550_u32.to_le_bytes());
        pe[0x90..0x94].copy_from_slice(&0x1000_u32.to_le_bytes()); // SizeOfImage
        pe[0x94..0x98].copy_from_slice(&0x200_u32.to_le_bytes()); // SizeOfHeaders
        pe[0x80..0x84].copy_from_slice(&[1, 0, 0, 0]); // Magic PE32
        let pe_path = std::env::temp_dir().join("casa1-evidence-pe.bin");
        std::fs::write(&pe_path, &pe).unwrap();
        let name_ptr = 0x41_200_u64;
        let wide: Vec<u16> = pe_path
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect();
        for (i, unit) in wide.iter().enumerate() {
            write_guest_u16(&mut memory, name_ptr + (i as u64 * 2), *unit).ok();
        }
        let loaded_out = 0x41_300_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                map_and_load,
                &[name_ptr as u32, 0, loaded_out as u32, 0, 0]
            ),
            1
        );
        let mapped = read_guest_pointer(&memory, loaded_out + 16, GuestArch::X86).unwrap();
        assert_ne!(mapped, 0);
        assert_eq!(
            read_guest_u32(&memory, loaded_out + 24).unwrap(),
            0x1000,
            "SizeOfImage"
        );
        let sum_out = 0x41_400_u64;
        let checksum_value = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            checksum,
            &[mapped as u32, 0x200, 0, sum_out as u32],
        );
        assert_ne!(checksum_value, 0);
        assert_eq!(
            read_guest_u32(&memory, sum_out).unwrap(),
            checksum_value as u32
        );
        std::fs::remove_file(&pe_path).ok();

        // ── hid: the preparsed-data descriptor parse ──
        let get_guid: u64 = runtime.alloc_host_thunk(HostThunk::HidDGetHidGuid);
        let get_caps: u64 = runtime.alloc_host_thunk(HostThunk::HidPGetCaps);
        let guid_out = 0x41_500_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_guid, &[guid_out as u32]),
            1
        );
        assert_eq!(
            memory.read_bytes(guid_out, 16).unwrap()[0],
            0xb2,
            "HID GUID"
        );
        // A 3-button mouse descriptor: usage page 1, usage 2, one input
        // report with 3 buttons (1 bit each) + x/y (8 bits each).
        let descriptor: Vec<u8> = vec![
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x02, // Usage (Mouse)
            0xa1, 0x01, // Collection (Application)
            0x09, 0x01, // Usage (Pointer)
            0xa1, 0x00, // Collection (Physical)
            0x05, 0x09, // Usage Page (Button)
            0x19, 0x01, // Usage Minimum (1)
            0x29, 0x03, // Usage Maximum (3)
            0x15, 0x00, // Logical Minimum (0)
            0x25, 0x01, // Logical Maximum (1)
            0x95, 0x03, // Report Count (3)
            0x75, 0x01, // Report Size (1)
            0x81, 0x02, // Input (Data,Var,Abs)
            0x95, 0x01, // Report Count (1)
            0x75, 0x05, // Report Size (5)
            0x81, 0x03, // Input (Const,Var,Abs) — padding
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x30, // Usage (X)
            0x09, 0x31, // Usage (Y)
            0x15, 0x81, // Logical Minimum (-127)
            0x25, 0x7f, // Logical Maximum (127)
            0x75, 0x08, // Report Size (8)
            0x95, 0x02, // Report Count (2)
            0x81, 0x06, // Input (Data,Var,Rel)
            0xc0, // End Collection
            0xc0, // End Collection
        ];
        let preparsed = 0x41_600_u64;
        runtime.hid_preparsed.insert(preparsed, descriptor);
        let caps_out = 0x41_700_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_caps,
                &[preparsed as u32, caps_out as u32]
            ),
            0x0011_0000
        );
        assert_eq!(
            read_guest_u16(&memory, caps_out + 2).unwrap(),
            1,
            "usage page"
        );
        assert_eq!(
            read_guest_u16(&memory, caps_out + 4).unwrap(),
            3,
            "input report bytes (3 buttons + 5 pad + 16 = 24 bits = 3 bytes)"
        );
        assert_eq!(
            read_guest_u16(&memory, caps_out + 14).unwrap(),
            1,
            "button caps (the 3 buttons)"
        );
        assert_eq!(
            read_guest_u16(&memory, caps_out + 16).unwrap(),
            1,
            "value caps (x/y)"
        );

        // ── msacm: the no-driver surface ──
        let driver_enum: u64 = runtime.alloc_host_thunk(HostThunk::AcmDriverEnum);
        let metrics: u64 = runtime.alloc_host_thunk(HostThunk::AcmMetrics);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, driver_enum, &[0, 0, 0]),
            0
        );
        let count_out = 0x41_800_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                metrics,
                &[0, 1, count_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, count_out).unwrap(),
            0,
            "no ACM drivers"
        );

        // ── msi: the database surface ──
        let open_db: u64 = runtime.alloc_host_thunk(HostThunk::MsiOpenDatabaseW);
        let enum_products: u64 = runtime.alloc_host_thunk(HostThunk::MsiEnumProductsW);
        let open_view: u64 = runtime.alloc_host_thunk(HostThunk::MsiDatabaseOpenViewW);
        let view_fetch: u64 = runtime.alloc_host_thunk(HostThunk::MsiViewFetch);
        let close_handle: u64 = runtime.alloc_host_thunk(HostThunk::MsiCloseHandle);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, enum_products, &[0, 0]),
            259,
            "no products"
        );
        let msi_path = std::env::temp_dir().join("casa1-evidence.msi");
        let mut msi = vec![0_u8; 512];
        msi[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
        std::fs::write(&msi_path, &msi).unwrap();
        let msi_name = 0x41_900_u64;
        let wide: Vec<u16> = msi_path
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect();
        for (i, unit) in wide.iter().enumerate() {
            write_guest_u16(&mut memory, msi_name + (i as u64 * 2), *unit).ok();
        }
        let db_out = 0x41_a00_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_db,
                &[msi_name as u32, 0, db_out as u32]
            ),
            0
        );
        let db = read_guest_pointer(&memory, db_out, GuestArch::X86).unwrap();
        assert_ne!(db, 0);
        let query_ptr = 0x41_b00_u64;
        let query_wide: Vec<u16> = "SELECT * FROM `_Columns`"
            .encode_utf16()
            .chain([0])
            .collect();
        for (i, unit) in query_wide.iter().enumerate() {
            write_guest_u16(&mut memory, query_ptr + (i as u64 * 2), *unit).ok();
        }
        let view_out = 0x41_c00_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_view,
                &[db as u32, query_ptr as u32, view_out as u32]
            ),
            0
        );
        let view = read_guest_pointer(&memory, view_out, GuestArch::X86).unwrap();
        assert_ne!(view, 0);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, view_fetch, &[view as u32, 0]),
            259,
            "no records"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close_handle, &[db as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close_handle, &[view as u32]),
            0
        );
        std::fs::remove_file(&msi_path).ok();

        // ── ole32: the interface-IID export ──
        let iid_moniker: u64 = runtime.alloc_host_thunk(HostThunk::OleIidMoniker);
        let iid_ptr = dispatch_x86_thunk(&mut runtime, &mut memory, iid_moniker, &[]);
        assert_ne!(iid_ptr, 0);
        assert_eq!(
            memory.read_bytes(iid_ptr, 16).unwrap(),
            vec![
                0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46
            ],
            "IID_IMoniker"
        );
    })
}
