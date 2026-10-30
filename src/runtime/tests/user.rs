use super::support::*;
use super::*;

#[test]
fn set_timer_reports_invalid_windows_and_dispatches_a_guest_timer_proc() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("timer-proc");
        let mut memory = MemoryImage::default();

        let set_timer = runtime.alloc_host_thunk(HostThunk::SetTimer);
        let timer_proc = 0x41_000_u32;
        // A non-existent window: SetTimer returns the timer id but reports
        // ERROR_INVALID_WINDOW_HANDLE (Windows semantics).
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_timer,
            &[0x1234, 77, 1000, timer_proc],
        );
        assert_eq!(result, 77, "SetTimer returns the timer id");
        assert_eq!(runtime.last_error, ERROR_INVALID_WINDOW_HANDLE);

        // DispatchMessage semantics: WM_TIMER with a TIMERPROC in lParam
        // invokes the proc instead of the window proc.
        let invocation_log = 0x42_000_u32;
        memory.map_bytes(invocation_log as u64, &[0; 16]);
        // stdcall TIMERPROC(hwnd, WM_TIMER, idTimer, time): log arg3
        // (idTimer) to invocation_log and return 0.
        memory.map_bytes(
            timer_proc as u64,
            &[
                0x8B, 0x44, 0x24, 0x0C, // mov eax, [esp+0x0C]
                0xA3, 0x00, 0x00, 0x00, 0x00, // mov [invocation_log], eax
                0x31, 0xC0, // xor eax, eax
                0xC2, 0x10, 0x00, // ret 16
            ],
        );
        write_u32(&mut memory, timer_proc as u64 + 5, invocation_log);
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, 0x50_000);
        memory.map_bytes(0x50_000, &[0_u8; 0x200]);
        let dispatched = runtime
            .dispatch_window_message(
                &mut state,
                &mut memory,
                0x1234,
                crate::user32::WM_TIMER,
                77,
                timer_proc as i64,
                "test timer dispatch",
            )
            .expect("dispatch WM_TIMER with timer proc");
        assert_eq!(dispatched, 0, "the timer proc returned 0");
        assert_eq!(
            read_u32(&memory, invocation_log as u64).expect("invocation log"),
            77,
            "the timer proc must receive idTimer = wParam"
        );
        // A WM_TIMER without a proc falls through to the window-proc path.
        let dispatched = runtime
            .dispatch_window_message(
                &mut state,
                &mut memory,
                0x1234,
                crate::user32::WM_TIMER,
                77,
                0,
                "test timer dispatch",
            )
            .expect("dispatch WM_TIMER without timer proc");
        assert_eq!(dispatched, 0, "no window proc — default result");
    })
}

#[test]
fn enum_windows_requires_a_callback_and_succeeds_without_windows() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("enum-windows");
        let mut memory = MemoryImage::default();

        let enum_windows = runtime.alloc_host_thunk(HostThunk::EnumWindows);
        let enum_child = runtime.alloc_host_thunk(HostThunk::EnumChildWindows);
        // A NULL callback fails with ERROR_INVALID_PARAMETER.
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, enum_windows, &[0, 0]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, enum_child, &[0, 0, 0]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        // An unknown parent fails with ERROR_INVALID_WINDOW_HANDLE.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            enum_child,
            &[0x1234, 0x41_000, 0],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_WINDOW_HANDLE);
        // With no top-level windows the enumeration succeeds without
        // invoking the callback.
        let callback = 0x41_000_u32;
        memory.map_bytes(callback as u64, &[0x31, 0xC0, 0xC2, 0x08, 0x00]);
        let result =
            dispatch_x86_thunk(&mut runtime, &mut memory, enum_windows, &[callback, 0x1234]);
        assert_eq!(result, 1, "EnumWindows succeeds");
    })
}

#[test]
fn map_window_points_validates_handles_and_identity_maps_screen_space() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("map-window-points");
        let mut memory = MemoryImage::default();

        let thunk = runtime.alloc_host_thunk(HostThunk::MapWindowPoints);
        let points_ptr = 0x41_000_u32;
        memory.map_bytes(points_ptr as u64, &[0; 32]);
        write_u32(&mut memory, points_ptr as u64, 10);
        write_u32(&mut memory, points_ptr as u64 + 4, 20);

        // Screen-to-screen mapping (both handles NULL) is the identity and
        // returns the packed "pixels added" (0).
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[0, 0, points_ptr, 1]);
        assert_eq!(result, 0, "no pixels added between same-origin spaces");
        assert_eq!(read_u32(&memory, points_ptr as u64).expect("x"), 10);
        assert_eq!(read_u32(&memory, points_ptr as u64 + 4).expect("y"), 20);

        // Unknown window handles fail with ERROR_INVALID_WINDOW_HANDLE.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[0, 0xDEAD, points_ptr, 1],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_WINDOW_HANDLE);
        // NULL points fail with ERROR_INVALID_PARAMETER.
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[0, 0, 0, 1]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
    })
}

#[test]
fn set_clipboard_data_reads_exact_block_and_returns_handle() {
    with_big_stack(|| {
        let (mut runtime, _temp_dir) = test_runtime("clipboard-exact");
        let mut memory = MemoryImage::default();

        // Open the clipboard first (OpenClipboard(0)).
        let open_clipboard = runtime.alloc_host_thunk(HostThunk::OpenClipboard);
        let opened = dispatch_x86_thunk(&mut runtime, &mut memory, open_clipboard, &[0]);
        assert_eq!(opened, 1, "OpenClipboard must succeed");

        // Allocate a guest heap block larger than the old 64 KB cap and fill
        // it with a recognizable pattern.
        let block_size = 128 * 1024usize;
        let block = runtime
            .alloc_heap(&mut memory, block_size, true)
            .expect("heap block");
        for i in 0..block_size {
            memory.write_u8(block + i as u64, (i % 251) as u8);
        }

        let set_clipboard_data = runtime.alloc_host_thunk(HostThunk::SetClipboardData);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_clipboard_data,
            &[1 /* CF_TEXT */, block as u32],
        );
        assert_eq!(
            result, block,
            "SetClipboardData must return the passed handle on success"
        );

        // The full 128 KB block must have been stored — no truncation within
        // the 1 MiB bound.
        let stored = runtime
            .user32
            .get_clipboard_data(crate::user32::CF_TEXT)
            .expect("stored clipboard data");
        assert_eq!(stored.len(), block_size, "no data may be truncated");
        assert_eq!(stored[0], 0, "first byte of the stored block");
        assert_eq!(
            stored[block_size - 1],
            ((block_size - 1) % 251) as u8,
            "last byte of the stored block"
        );

        // GetClipboardData returns the same guest handle (Windows hData
        // contract), not a synthetic pseudo-handle.
        let get_clipboard_data = runtime.alloc_host_thunk(HostThunk::GetClipboardData);
        let got_handle = dispatch_x86_thunk(&mut runtime, &mut memory, get_clipboard_data, &[1]);
        assert_eq!(
            got_handle, block,
            "GetClipboardData must return the handle SetClipboardData stored"
        );

        // Clipboard closed: SetClipboardData fails with NULL +
        // ERROR_CLIPBOARD_NOT_OPEN (1418).
        let close_clipboard = runtime.alloc_host_thunk(HostThunk::CloseClipboard);
        dispatch_x86_thunk(&mut runtime, &mut memory, close_clipboard, &[]);
        let failed = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_clipboard_data,
            &[1, block as u32],
        );
        assert_eq!(
            failed, 0,
            "SetClipboardData with a closed clipboard must fail"
        );
        assert_eq!(
            runtime.last_error, ERROR_CLIPBOARD_NOT_OPEN,
            "closed clipboard must set ERROR_CLIPBOARD_NOT_OPEN (1418)"
        );
    })
}

#[test]
fn set_class_long_w_dispatch_returns_previous_value() {
    with_big_stack(|| {
        let (mut runtime, _temp_dir) = test_runtime("class-long");
        let mut memory = MemoryImage::default();

        let class_name = runtime
            .alloc_utf16_string(&mut memory, "class-long-dispatch")
            .expect("class name");
        let title = runtime
            .alloc_utf16_string(&mut memory, "title")
            .expect("title");
        runtime.user32.register_class_ex_w("class-long-dispatch");

        // CreateWindowExW(class, title, style, x, y, w, h, parent, menu, instance, param).
        // WS_CHILD (0x4000_0000) avoids the AppKit NSWindow path so the test
        // runs without a main-thread NSApplication.
        let create_window = runtime.alloc_host_thunk(HostThunk::CreateWindowExW);
        let hwnd = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_window,
            &[
                0,
                class_name as u32,
                title as u32,
                0x4000_0000,
                0,
                0,
                320,
                200,
                0,
                0,
                0,
                0,
            ],
        );
        assert_ne!(hwnd, 0, "window must be created");

        const GCL_STYLE: i32 = -26;
        let set_class_long = runtime.alloc_host_thunk(HostThunk::SetClassLongW);
        let first = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_class_long,
            &[hwnd as u32, GCL_STYLE as u32, 0x1111],
        );
        assert_eq!(first, 0, "first set returns 0");
        let second = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_class_long,
            &[hwnd as u32, GCL_STYLE as u32, 0x2222],
        );
        assert_eq!(second, 0x1111, "second set returns the previous value");

        // Invalid hwnd: 0 + ERROR_INVALID_WINDOW_HANDLE.
        let invalid = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_class_long,
            &[0xDEAD, GCL_STYLE as u32, 1],
        );
        assert_eq!(invalid, 0);
        assert_eq!(
            runtime.last_error, ERROR_INVALID_WINDOW_HANDLE,
            "invalid hwnd must set ERROR_INVALID_WINDOW_HANDLE"
        );
    })
}

#[test]
fn advapi32_user_name_security_descriptor_and_event_log() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "advapi32-thunks",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // GetUserNameW writes the account name and required size.
        let get_user_name = runtime.alloc_host_thunk(HostThunk::GetUserNameW);
        let buffer = 0x61_000;
        let size = 0x61_100;
        memory.map_bytes(buffer, &[0_u8; 64]);
        memory.map_bytes(size, &64_u32.to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_user_name,
                &[buffer as u32, size as u32],
            ),
            1
        );
        assert_eq!(
            read_utf16_string(&memory, buffer).expect("user name"),
            "user"
        );
        assert_eq!(read_u32(&memory, size).expect("size"), 5);
        // A too-small buffer fails with ERROR_MORE_DATA.
        memory.map_bytes(size, &1_u32.to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_user_name,
                &[buffer as u32, size as u32],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_MORE_DATA);

        // InitializeSecurityDescriptor writes the revision and clears
        // the owner/group/sacl/dacl pointers; bad revisions fail.
        let init_sd = runtime.alloc_host_thunk(HostThunk::InitializeSecurityDescriptor);
        let descriptor = 0x62_000;
        memory.map_bytes(descriptor, &[0_u8; 64]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, init_sd, &[descriptor as u32, 1]),
            1
        );
        assert_eq!(memory.read_u8(descriptor).expect("revision"), 1);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, init_sd, &[descriptor as u32, 2]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_UNKNOWN_REVISION);

        // SetSecurityDescriptorDacl toggles SE_DACL_PRESENT (0x0004) and
        // SE_DACL_DEFAULTED (0x0008) in the control word.
        let set_dacl = runtime.alloc_host_thunk(HostThunk::SetSecurityDescriptorDacl);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_dacl,
                &[descriptor as u32, 1, 0x12_34, 1],
            ),
            1
        );
        assert_eq!(
            read_u16(&memory, descriptor + 2).expect("control"),
            0x0004 | 0x0008
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_dacl,
                &[descriptor as u32, 0, 0, 0],
            ),
            1
        );
        assert_eq!(read_u16(&memory, descriptor + 2).expect("control"), 0);

        // ReportEventW logs and returns TRUE.
        let report_event = runtime.alloc_host_thunk(HostThunk::ReportEventW);
        let msg = runtime
            .alloc_utf16_string(&mut memory, "hello")
            .expect("msg");
        let strings = 0x63_000;
        memory.map_bytes(strings, &[0_u8; 16]);
        write_u32(&mut memory, strings, msg as u32);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                report_event,
                &[0, 1, 0, 0x1001, 0, 1, 0, strings as u32, 0],
            ),
            1
        );
    })
}

// ── Evidence-ui-mm: user32 window-class round trip (WS_CHILD path) ──────
#[test]
fn message_pump_peek_get_dispatch_send_and_def_window_proc() {
    with_big_stack(|| {
        // The UI message pump through the real thunks: PostThreadMessageW →
        // GetMessageW → PeekMessageW → DispatchMessageW, plus SendMessageW,
        // DefWindowProcW and EndDialog against a live WS_CHILD window.
        const WS_CHILD: u32 = 0x4000_0000;
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "message-pump", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime.user32.register_class_ex_w("pump-window");
        let hwnd = runtime
            .user32
            .create_window_ex_styled(
                "pump-window",
                "pump",
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
            .expect("create pump window");
        while runtime.user32.get_message_w().is_some() {}

        let msg_ptr = 0x41_300_u64;
        memory.map_bytes(msg_ptr, &[0; 28]);
        let post = runtime.alloc_host_thunk(HostThunk::PostThreadMessageW);
        let get_message = runtime.alloc_host_thunk(HostThunk::GetMessageW);

        // GetMessageW with a queued PostThreadMessageW round trip.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, post, &[1, 0x0400, 11, 22]),
            1
        );
        let got = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_message,
            &[msg_ptr as u32, 0, 0, 0],
        );
        assert_eq!(got, 1, "GetMessageW returns 1 for a non-quit message");
        let message = read_win32_msg(&memory, msg_ptr).expect("read msg");
        assert_eq!(message_id(message.kind), 0x0400);
        assert_eq!(message.wparam, 11);
        assert_eq!(message.lparam, 22);

        // PeekMessageW: empty queue → 0; queued message → 1.
        let peek = runtime.alloc_host_thunk(HostThunk::PeekMessageW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                peek,
                &[msg_ptr as u32, 0, 0, 0, 0]
            ),
            0,
            "PeekMessageW with an empty queue returns 0"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, post, &[1, 0x0401, 7, 8]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                peek,
                &[msg_ptr as u32, 0, 0, 0, 1]
            ),
            1,
            "PeekMessageW with PM_REMOVE returns 1"
        );
        let peeked = read_win32_msg(&memory, msg_ptr).expect("peeked msg");
        assert_eq!(message_id(peeked.kind), 0x0401);
        assert_eq!(peeked.wparam, 7);

        // DispatchMessageW runs the message through the window proc path
        // (no guest wnd proc → default handling, observable result).
        let dispatch = runtime.alloc_host_thunk(HostThunk::DispatchMessageW);
        let dispatched = dispatch_x86_thunk(&mut runtime, &mut memory, dispatch, &[msg_ptr as u32]);
        assert_eq!(dispatched, 0, "default dispatch result for WM_USER+1");

        // SendMessageW delivers into the message log of a live window.
        let send = runtime.alloc_host_thunk(HostThunk::SendMessageW);
        let sent = dispatch_x86_thunk(&mut runtime, &mut memory, send, &[hwnd, 0x0402, 3, 4]);
        assert_eq!(sent, 0);
        let log = runtime.user32.message_log();
        assert_eq!(
            log.last().expect("log tail").kind,
            MessageKind::Other(0x0402)
        );
        assert_eq!(log.last().expect("log tail").wparam, 3);

        // DefWindowProcW: WM_PAINT (0x000F) on the live window.
        let def = runtime.alloc_host_thunk(HostThunk::DefWindowProcW);
        let def_result = dispatch_x86_thunk(&mut runtime, &mut memory, def, &[hwnd, 0x000F, 0, 0]);
        assert_eq!(def_result, 0);

        // EndDialog destroys the window and records the dialog result.
        let end_dialog = runtime.alloc_host_thunk(HostThunk::EndDialog);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, end_dialog, &[hwnd, 7]),
            1,
            "EndDialog must close the dialog window"
        );
        assert!(
            !runtime
                .user32
                .window_state(hwnd)
                .map(|_| true)
                .unwrap_or(false),
            "EndDialog destroys the window record"
        );
    })
}

// ── Evidence-ui-mm: gdi32 bitmap-draw dispatch ─────────────────────────
// ── Evidence-ui-mm: shell32 PIDL/folder/drag dispatch ──────────────────
#[test]
fn shell32_pidl_folder_and_drag_dispatch() {
    with_big_stack(|| {
        // The shell32 surface through the host thunks: special-folder paths,
        // PIDL create/parse/round-trip, shell-item creation, ShellExecuteExW
        // and the drag-and-drop API family.
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "shell32", GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let path_buf = 0x43_000_u64;
        memory.map_bytes(path_buf, &[0; 520]);

        // SHGetFolderPathW / SHGetSpecialFolderPathW: CSIDL_PROGRAM_FILES.
        let sh_get_folder = runtime.alloc_host_thunk(HostThunk::SHGetFolderPathW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sh_get_folder,
                &[0, 0x0026, 0, 0, path_buf as u32]
            ),
            0,
            "SHGetFolderPathW succeeds"
        );
        assert_eq!(
            read_guest_utf16_string(&memory, path_buf, 260),
            "C:\\Program Files (x86)"
        );
        let sh_get_special = runtime.alloc_host_thunk(HostThunk::SHGetSpecialFolderPathW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sh_get_special,
                &[0, path_buf as u32, 0x0026, 0]
            ),
            1
        );
        assert_eq!(
            read_guest_utf16_string(&memory, path_buf, 260),
            "C:\\Program Files (x86)"
        );

        // ILCreateFromPathW → SHGetPathFromIDListW round trip + ILFree.
        let dir_ptr = runtime
            .alloc_utf16_string(&mut memory, "C:\\Steam")
            .expect("dir path");
        let il_create = runtime.alloc_host_thunk(HostThunk::ILCreateFromPathW);
        let pidl = dispatch_x86_thunk(&mut runtime, &mut memory, il_create, &[dir_ptr as u32]);
        assert_ne!(pidl, 0, "ILCreateFromPathW must allocate a PIDL");
        memory.map_bytes(path_buf, &[0; 520]);
        let sh_get_path = runtime.alloc_host_thunk(HostThunk::SHGetPathFromIDListW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sh_get_path,
                &[pidl as u32, path_buf as u32]
            ),
            1
        );
        assert_eq!(read_guest_utf16_string(&memory, path_buf, 260), "C:\\Steam");
        let il_free = runtime.alloc_host_thunk(HostThunk::ILFree);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, il_free, &[pidl as u32]),
            0
        );

        // SHSimpleIDListFromPath, SHParseDisplayName, SHCreateItemFromParsingName,
        // SHCreateItemFromIDList, SHBindToParent, SHGetDataFromIDListW.
        let sh_simple = runtime.alloc_host_thunk(HostThunk::SHSimpleIDListFromPath);
        let pidl2 = dispatch_x86_thunk(&mut runtime, &mut memory, sh_simple, &[dir_ptr as u32]);
        assert_ne!(pidl2, 0, "SHSimpleIDListFromPath must allocate a PIDL");
        let pidl_out = 0x43_100_u64;
        memory.map_bytes(pidl_out, &[0; 4]);
        let sh_parse = runtime.alloc_host_thunk(HostThunk::SHParseDisplayName);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sh_parse,
                &[dir_ptr as u32, 0, pidl_out as u32, 0]
            ),
            0
        );
        assert_ne!(
            read_u32(&memory, pidl_out).expect("pidl out"),
            0,
            "SHParseDisplayName must write the parsed PIDL"
        );
        let item_out = 0x43_110_u64;
        memory.map_bytes(item_out, &[0; 4]);
        let sh_create_item = runtime.alloc_host_thunk(HostThunk::SHCreateItemFromParsingName);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sh_create_item,
                &[dir_ptr as u32, 0, 0, item_out as u32]
            ),
            0
        );
        assert_ne!(
            read_u32(&memory, item_out).expect("item out"),
            0,
            "SHCreateItemFromParsingName must write the item"
        );
        let item_out2 = 0x43_120_u64;
        memory.map_bytes(item_out2, &[0; 4]);
        let sh_create_idlist = runtime.alloc_host_thunk(HostThunk::SHCreateItemFromIDList);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sh_create_idlist,
                &[pidl as u32, 0, item_out2 as u32]
            ),
            0
        );
        assert_ne!(
            read_u32(&memory, item_out2).expect("item out 2"),
            0,
            "SHCreateItemFromIDList must write the item"
        );
        let parent_out = 0x43_130_u64;
        let child_out = 0x43_140_u64;
        memory.map_bytes(parent_out, &[0; 4]);
        memory.map_bytes(child_out, &[0; 4]);
        let sh_bind_parent = runtime.alloc_host_thunk(HostThunk::SHBindToParent);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sh_bind_parent,
                &[pidl as u32, 0, parent_out as u32, child_out as u32]
            ),
            0
        );
        assert_ne!(
            read_u32(&memory, parent_out).expect("parent out"),
            0,
            "SHBindToParent must write the parent folder"
        );
        let data_buf = 0x43_150_u64;
        memory.map_bytes(data_buf, &[0; 16]);
        let sh_get_data = runtime.alloc_host_thunk(HostThunk::SHGetDataFromIDListW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sh_get_data,
                &[pidl as u32, 0, 0, data_buf as u32, 16]
            ),
            0
        );
        let desktop_out = 0x43_160_u64;
        memory.map_bytes(desktop_out, &[0; 4]);
        let sh_desktop = runtime.alloc_host_thunk(HostThunk::SHGetDesktopFolder);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, sh_desktop, &[desktop_out as u32]),
            0
        );
        assert_ne!(
            read_u32(&memory, desktop_out).expect("desktop pidl"),
            0,
            "SHGetDesktopFolder must write a desktop PIDL"
        );

        // SHGetKnownFolderPath: FOLDERID_ProgramFilesX86 → the x86 path.
        let guid_ptr = 0x43_180_u64;
        write_u32(&mut memory, guid_ptr, 0x7C5A_40EF);
        memory.map_bytes(guid_ptr + 4, &0xA0FB_u16.to_le_bytes());
        memory.map_bytes(guid_ptr + 6, &0x4BFC_u16.to_le_bytes());
        memory.map_bytes(
            guid_ptr + 8,
            &[0xB7, 0x4B, 0xC3, 0xF8, 0xE2, 0xF4, 0x4B, 0x6E],
        );
        let known_out = 0x43_190_u64;
        memory.map_bytes(known_out, &[0; 4]);
        let sh_known = runtime.alloc_host_thunk(HostThunk::SHGetKnownFolderPath);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sh_known,
                &[guid_ptr as u32, 0, 0, known_out as u32]
            ),
            0,
            "SHGetKnownFolderPath succeeds for a known folder"
        );
        let known_path_ptr = read_u32(&memory, known_out).expect("known path ptr") as u64;
        assert_ne!(known_path_ptr, 0, "SHGetKnownFolderPath must write a path");
        assert_eq!(
            read_guest_utf16_string(&memory, known_path_ptr, 260),
            "C:\\Program Files (x86)"
        );

        // ShellExecuteExW: valid SHELLEXECUTEINFOW (x86 cbSize=60) with an
        // empty file — success without spawning a host app; undersized
        // struct → ERROR_ACCESS_DENIED.
        let exec_info = 0x43_200_u64;
        let mut info = vec![0_u8; 60];
        info[0..4].copy_from_slice(&60_u32.to_le_bytes()); // cbSize
        memory.map_bytes(exec_info, &info);
        let shell_execute = runtime.alloc_host_thunk(HostThunk::ShellExecuteExW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                shell_execute,
                &[exec_info as u32]
            ),
            1
        );
        assert_eq!(
            read_u32(&memory, exec_info + 0x20).expect("hInstApp"),
            42,
            "ShellExecuteExW must write hInstApp > 32 on success"
        );
        let tiny = 0x43_210_u64;
        let mut tiny_bytes = vec![0_u8; 8];
        tiny_bytes[0..4].copy_from_slice(&8_u32.to_le_bytes());
        memory.map_bytes(tiny, &tiny_bytes);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, shell_execute, &[tiny as u32]),
            0,
            "undersized SHELLEXECUTEINFOW must fail"
        );
        assert_eq!(runtime.last_error, ERROR_ACCESS_DENIED);

        // Drag-and-drop family.
        runtime.user32.register_class_ex_w("drop-window");
        let hwnd = runtime
            .user32
            .create_window_ex_styled(
                "drop-window",
                "drop",
                64,
                16,
                false,
                false,
                None,
                1,
                0x4000_0000,
                0,
                None,
            )
            .expect("create drop window");
        let register_drag_drop = runtime.alloc_host_thunk(HostThunk::RegisterDragDrop);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, register_drag_drop, &[hwnd, 1]),
            0,
            "RegisterDragDrop returns S_OK"
        );
        let effect_out = 0x43_300_u64;
        memory.map_bytes(effect_out, &[0; 4]);
        let do_drag_drop = runtime.alloc_host_thunk(HostThunk::DoDragDrop);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                do_drag_drop,
                &[0, 0, 1, effect_out as u32]
            ),
            0,
            "DoDragDrop returns S_OK"
        );
        assert_eq!(
            read_u32(&memory, effect_out).expect("effect"),
            1,
            "DoDragDrop writes DROPEFFECT_COPY"
        );
        let drag_accept = runtime.alloc_host_thunk(HostThunk::DragAcceptFiles);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, drag_accept, &[hwnd, 1]),
            0
        );
        let drag_buf = 0x43_310_u64;
        memory.map_bytes(drag_buf, &[0; 520]);
        let drag_query = runtime.alloc_host_thunk(HostThunk::DragQueryFileW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                drag_query,
                &[0, 0, drag_buf as u32, 260]
            ),
            0,
            "DragQueryFileW with a null HDROP returns 0"
        );
        let drag_finish = runtime.alloc_host_thunk(HostThunk::DragFinish);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, drag_finish, &[0]),
            0
        );
    })
}

// ── Evidence-ui-mm: comctl32 image-list dispatch ───────────────────────
#[test]
fn comctl32_imagelist_dispatch() {
    with_big_stack(|| {
        // InitCommonControlsEx plus the full ImageList_* family through the
        // host thunks: create/add/replace/remove/count, drag state machine
        // and draw entry points.
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "comctl32", GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // InitCommonControlsEx(ICC_WIN95_CLASSES) → TRUE + classes registered.
        let icc = 0x44_000_u64;
        memory.map_bytes(icc, &[0; 8]);
        write_u32(&mut memory, icc, 8); // dwSize
        write_u32(&mut memory, icc + 4, 0x0FFF); // dwICC
        let init_common = runtime.alloc_host_thunk(HostThunk::InitCommonControlsEx);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, init_common, &[icc as u32]),
            1
        );
        assert!(
            runtime.common_controls_initialized,
            "InitCommonControlsEx must flag the runtime"
        );

        // ImageList_Create → Add → GetImageCount → ReplaceIcon.
        let create = runtime.alloc_host_thunk(HostThunk::ImageList_Create);
        let himl = dispatch_x86_thunk(&mut runtime, &mut memory, create, &[16, 16, 0x0020, 4, 4]);
        assert_ne!(himl, 0, "ImageList_Create must allocate an image list");
        let add = runtime.alloc_host_thunk(HostThunk::ImageList_Add);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, add, &[himl as u32, 0x1000, 0]),
            0,
            "first ImageList_Add returns index 0"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, add, &[himl as u32, 0x1001, 0]),
            1,
            "second ImageList_Add returns index 1"
        );
        let get_count = runtime.alloc_host_thunk(HostThunk::ImageList_GetImageCount);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_count, &[himl as u32]),
            2
        );
        let replace_icon = runtime.alloc_host_thunk(HostThunk::ImageList_ReplaceIcon);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                replace_icon,
                &[himl as u32, 0xFFFF_FFFF, 0x2000]
            ),
            2,
            "ImageList_ReplaceIcon(-1) appends"
        );

        // SetImageCount/Remove are observable through GetImageCount.
        let set_count = runtime.alloc_host_thunk(HostThunk::ImageList_SetImageCount);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_count, &[himl as u32, 5]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_count, &[himl as u32]),
            5
        );
        let remove = runtime.alloc_host_thunk(HostThunk::ImageList_Remove);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                remove,
                &[himl as u32, 0xFFFF_FFFF]
            ),
            1,
            "ImageList_Remove(-1) clears the list"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_count, &[himl as u32]),
            0
        );

        // Drag state machine.
        let begin_drag = runtime.alloc_host_thunk(HostThunk::ImageList_BeginDrag);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                begin_drag,
                &[himl as u32, 0, 0, 0]
            ),
            1
        );
        let drag_enter = runtime.alloc_host_thunk(HostThunk::ImageList_DragEnter);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, drag_enter, &[0, 1, 1]),
            1
        );
        let drag_move = runtime.alloc_host_thunk(HostThunk::ImageList_DragMove);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, drag_move, &[2, 3]),
            1
        );
        let drag_leave = runtime.alloc_host_thunk(HostThunk::ImageList_DragLeave);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, drag_leave, &[0]),
            1
        );
        let end_drag = runtime.alloc_host_thunk(HostThunk::ImageList_EndDrag);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, end_drag, &[]),
            0
        );
        let set_drag_cursor = runtime.alloc_host_thunk(HostThunk::ImageList_SetDragCursorImage);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_drag_cursor,
                &[himl as u32, 0, 0, 0]
            ),
            0
        );

        // Draw entry points.
        let draw = runtime.alloc_host_thunk(HostThunk::ImageList_Draw);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                draw,
                &[himl as u32, 0, 0, 0, 0, 0]
            ),
            1
        );
        let draw_ex = runtime.alloc_host_thunk(HostThunk::ImageList_DrawEx);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                draw_ex,
                &[himl as u32, 0, 0, 0, 0, 16, 16, 0, 0, 0]
            ),
            1
        );

        // Destroy tears the list down.
        let destroy = runtime.alloc_host_thunk(HostThunk::ImageList_Destroy);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, destroy, &[himl as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_count, &[himl as u32]),
            0,
            "ImageList_GetImageCount on a destroyed list returns 0"
        );
    })
}

// -- usp10: Uniscribe dispatch -------------------------------------------
// -- dwmapi dispatch ------------------------------------------------------
#[test]
fn dwm_window_attribute_dispatch() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "dwm-attrs", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let get = runtime.alloc_host_thunk(HostThunk::DwmGetWindowAttribute);
        let value = 0x30_000_u64;
        write_u32(&mut memory, value, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get,
                &[
                    0x10_000,
                    0, /* DWMWA_NCRENDERING_ENABLED */
                    value as u32,
                    4
                ]
            ),
            0,
            "DwmGetWindowAttribute(DWMWA_NCRENDERING_ENABLED) returns S_OK"
        );
        assert_eq!(
            memory.read_u32(value).expect("nc rendering"),
            1,
            "non-client rendering is enabled"
        );

        let policy = 0x30_100_u64;
        write_u32(&mut memory, policy, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get,
                &[
                    0x10_000,
                    1, /* DWMWA_NCRENDERING_POLICY */
                    policy as u32,
                    4
                ]
            ),
            0,
            "DwmGetWindowAttribute(DWMWA_NCRENDERING_POLICY) returns S_OK"
        );
        assert_eq!(
            memory.read_u32(policy).expect("policy"),
            2,
            "the non-client rendering policy is DWMNCRP_ENABLED"
        );

        let bounds = 0x30_200_u64;
        memory.map_bytes(bounds, &[0xFF_u8; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get,
                &[
                    0x10_000,
                    4, /* DWMWA_CAPTION_BUTTON_BOUNDS */
                    bounds as u32,
                    16
                ]
            ),
            0,
            "DwmGetWindowAttribute(DWMWA_CAPTION_BUTTON_BOUNDS) returns S_OK"
        );
        assert_eq!(
            memory.read_u32(bounds).expect("rect left"),
            0,
            "the caption bounds rect is written"
        );

        let cloaked = 0x30_300_u64;
        write_u32(&mut memory, cloaked, 0xFF);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get,
                &[0x10_000, 14 /* DWMWA_CLOAKED */, cloaked as u32, 4]
            ),
            0,
            "DwmGetWindowAttribute(DWMWA_CLOAKED) returns S_OK"
        );
        assert_eq!(
            memory.read_u32(cloaked).expect("cloaked"),
            0,
            "the window is not cloaked"
        );

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get,
                &[0x10_000, 99 /* unknown */, value as u32, 4]
            ),
            0x8007_0057,
            "unknown attributes report E_INVALIDARG"
        );

        let set = runtime.alloc_host_thunk(HostThunk::DwmSetWindowAttribute);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set,
                &[
                    0x10_000,
                    1, /* DWMWA_NCRENDERING_POLICY */
                    value as u32,
                    4
                ]
            ),
            0,
            "DwmSetWindowAttribute with a known attribute returns S_OK"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set,
                &[0x10_000, 99 /* unknown */, value as u32, 4]
            ),
            0x8007_0057,
            "DwmSetWindowAttribute with an unknown attribute reports E_INVALIDARG"
        );
    })
}

#[test]
fn evidence_shlwapi_string_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-shlwapi-string");
        let mut memory = MemoryImage::default();
        let str_chr = runtime.alloc_host_thunk(HostThunk::StrChrW);
        let str_chr_i = runtime.alloc_host_thunk(HostThunk::StrChrIW);
        let str_r_chr = runtime.alloc_host_thunk(HostThunk::StrRChrW);
        let str_str = runtime.alloc_host_thunk(HostThunk::StrStrW);
        let str_str_i = runtime.alloc_host_thunk(HostThunk::StrStrIW);
        let str_cmp_i = runtime.alloc_host_thunk(HostThunk::StrCmpIW);
        let str_cmp = runtime.alloc_host_thunk(HostThunk::StrCmpW);
        let str_cmp_ni = runtime.alloc_host_thunk(HostThunk::StrCmpNIW);
        let str_cmp_n = runtime.alloc_host_thunk(HostThunk::StrCmpNW);
        let str_cpy_n = runtime.alloc_host_thunk(HostThunk::StrCpyNW);
        let str_cpy = runtime.alloc_host_thunk(HostThunk::StrCpyW);
        let str_cat = runtime.alloc_host_thunk(HostThunk::StrCatW);
        let str_to_int = runtime.alloc_host_thunk(HostThunk::StrToIntW);

        let text = runtime
            .alloc_utf16_string(&mut memory, "The Quick Brown Fox")
            .expect("wide text");

        // StrChrW: first occurrence (case-sensitive).
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            str_chr,
            &[text as u32, 'Q' as u32],
        );
        assert_eq!(
            read_guest_utf16_string(&memory, result, 64),
            "Quick Brown Fox"
        );
        // StrChrIW: case-insensitive first occurrence.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            str_chr_i,
            &[text as u32, 'q' as u32],
        );
        assert_eq!(
            read_guest_utf16_string(&memory, result, 64),
            "Quick Brown Fox"
        );
        // Missing character → NULL.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_chr,
                &[text as u32, 'z' as u32]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_chr_i,
                &[text as u32, 'z' as u32]
            ),
            0
        );

        // StrRChrW: LAST occurrence at or before chStart.
        let repeated = runtime
            .alloc_utf16_string(&mut memory, "a.b.c.d")
            .expect("wide repeated");
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            str_r_chr,
            &[repeated as u32, 0, '.' as u32],
        );
        assert_eq!(read_guest_utf16_string(&memory, result, 64), ".d");
        let start = repeated + 4; // inside ".b.c.d" → the dot after "b"
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            str_r_chr,
            &[repeated as u32, start as u32, '.' as u32],
        );
        assert_eq!(read_guest_utf16_string(&memory, result, 64), ".c.d");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_r_chr,
                &[repeated as u32, 0, 'x' as u32]
            ),
            0
        );

        // StrStrW: substring (case-sensitive); StrStrIW folds case.
        let needle = runtime
            .alloc_utf16_string(&mut memory, "Quick")
            .expect("wide needle");
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            str_str,
            &[text as u32, needle as u32],
        );
        assert_eq!(
            read_guest_utf16_string(&memory, result, 64),
            "Quick Brown Fox"
        );
        let needle_lower = runtime
            .alloc_utf16_string(&mut memory, "quick")
            .expect("wide needle lower");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_str,
                &[text as u32, needle_lower as u32]
            ),
            0
        );
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            str_str_i,
            &[text as u32, needle_lower as u32],
        );
        assert_eq!(
            read_guest_utf16_string(&memory, result, 64),
            "Quick Brown Fox"
        );

        // StrCmpW / StrCmpIW: 0 when equal, nonzero otherwise.
        let hello = runtime
            .alloc_utf16_string(&mut memory, "Hello")
            .expect("wide hello");
        let hello_lower = runtime
            .alloc_utf16_string(&mut memory, "hello")
            .expect("wide lower");
        let world = runtime
            .alloc_utf16_string(&mut memory, "World")
            .expect("wide world");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_cmp,
                &[hello as u32, hello as u32]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_cmp,
                &[hello as u32, hello_lower as u32]
            ),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_cmp_i,
                &[hello as u32, hello_lower as u32]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_cmp_i,
                &[hello as u32, world as u32]
            ),
            1
        );

        // StrCmpNW / StrCmpNIW compare up to nChar characters.
        let longer = runtime
            .alloc_utf16_string(&mut memory, "HelloWorld")
            .expect("wide longer");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_cmp_n,
                &[hello as u32, longer as u32, 5]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_cmp_n,
                &[hello as u32, longer as u32, 6]
            ),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_cmp_ni,
                &[hello as u32, hello_lower as u32, 5]
            ),
            0
        );

        // StrCpyNW copies at most count characters INCLUDING the NUL.
        let dest = 0x43_300;
        memory.map_bytes(dest, &[0xEE; 0x100]);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            str_cpy_n,
            &[dest as u32, hello as u32, 3],
        );
        assert_eq!(result, dest);
        assert_eq!(read_guest_utf16_string(&memory, dest, 8), "He");
        // StrCpyW copies the full string.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            str_cpy,
            &[dest as u32, hello as u32],
        );
        assert_eq!(result, dest);
        assert_eq!(read_guest_utf16_string(&memory, dest, 16), "Hello");

        // StrCatW concatenates onto the destination.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            str_cat,
            &[dest as u32, world as u32],
        );
        assert_eq!(result, dest);
        assert_eq!(read_guest_utf16_string(&memory, dest, 16), "HelloWorld");

        // StrToIntW parses sign + digits and stops at the first non-digit.
        let int_cases: &[(&str, i32)] = &[
            ("123", 123),
            ("-42", -42),
            ("+7", 7),
            ("12x", 12),
            ("abc", 0),
            ("-abc", 0),
            ("", 0),
            ("007", 7),
        ];
        for (input, expected) in int_cases {
            let ptr = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide int");
            let result = dispatch_x86_thunk(&mut runtime, &mut memory, str_to_int, &[ptr as u32]);
            let expected = if *expected < 0 {
                u64::from(*expected as u32)
            } else {
                *expected as u64
            };
            assert_eq!(result, expected, "StrToIntW({input:?})");
        }
    })
}

#[test]
fn evidence_shlwapi_char_class_and_url_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-shlwapi-charurl");
        let mut memory = MemoryImage::default();
        let chr_cmp_i = runtime.alloc_host_thunk(HostThunk::ChrCmpIW);
        let str_eq_worker = runtime.alloc_host_thunk(HostThunk::IntlStrEqWorkerW);
        let is_alpha = runtime.alloc_host_thunk(HostThunk::IsCharAlphaW);
        let is_alnum = runtime.alloc_host_thunk(HostThunk::IsCharAlphaNumericW);
        let is_lower = runtime.alloc_host_thunk(HostThunk::IsCharLowerW);
        let is_upper = runtime.alloc_host_thunk(HostThunk::IsCharUpperW);
        let is_space = runtime.alloc_host_thunk(HostThunk::IsCharSpaceW);
        let parse_url = runtime.alloc_host_thunk(HostThunk::ParseURLW);
        let time_interval = runtime.alloc_host_thunk(HostThunk::StrFromTimeIntervalW);

        // ChrCmpIW: case-insensitive character equality.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                chr_cmp_i,
                &['a' as u32, 'A' as u32]
            ),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                chr_cmp_i,
                &['a' as u32, 'b' as u32]
            ),
            0
        );

        // IntlStrEqWorkerW: prefix equality over nChar, case-insensitive by
        // default, case-sensitive when bCaseSensitive is set.
        let alpha = runtime
            .alloc_utf16_string(&mut memory, "AlphaBeta")
            .expect("wide alpha");
        let alpha_lower = runtime
            .alloc_utf16_string(&mut memory, "alphabeta")
            .expect("wide lower");
        let gamma = runtime
            .alloc_utf16_string(&mut memory, "Gamma")
            .expect("wide gamma");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_eq_worker,
                &[0, alpha as u32, alpha_lower as u32, 5]
            ),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_eq_worker,
                &[1, alpha as u32, alpha_lower as u32, 5]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_eq_worker,
                &[0, alpha as u32, gamma as u32, 5]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                str_eq_worker,
                &[0, alpha as u32, alpha as u32, 100]
            ),
            1
        );

        // IsChar* classification follows the Unicode character classes.
        let char_cases: &[(&str, u32, bool)] = &[
            ("IsCharAlphaW", 'A' as u32, true),
            ("IsCharAlphaW", '1' as u32, false),
            ("IsCharAlphaNumericW", 'A' as u32, true),
            ("IsCharAlphaNumericW", '5' as u32, true),
            ("IsCharAlphaNumericW", '_' as u32, false),
            ("IsCharLowerW", 'a' as u32, true),
            ("IsCharLowerW", 'A' as u32, false),
            ("IsCharUpperW", 'A' as u32, true),
            ("IsCharUpperW", 'a' as u32, false),
            ("IsCharSpaceW", ' ' as u32, true),
            ("IsCharSpaceW", '\t' as u32, true),
            ("IsCharSpaceW", 'x' as u32, false),
        ];
        for (thunk_name, ch, expected) in char_cases {
            let thunk = match *thunk_name {
                "IsCharAlphaW" => is_alpha,
                "IsCharAlphaNumericW" => is_alnum,
                "IsCharLowerW" => is_lower,
                "IsCharUpperW" => is_upper,
                "IsCharSpaceW" => is_space,
                _ => unreachable!(),
            };
            let result = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[*ch]);
            assert_eq!(result, *expected as u64, "{thunk_name}({ch:#x})");
        }

        // ParseURLW: PARSEDURLW (24 bytes on x86) gets the scheme, suffix
        // and scheme code; invalid syntax reports URL_E_INVALID_SYNTAX.
        let parsed = 0x43_400;
        memory.map_bytes(parsed, &[0_u8; 0x40]);
        write_u32(&mut memory, parsed, 24);
        let url = runtime
            .alloc_utf16_string(&mut memory, "https://example.com/a?b")
            .expect("wide url");
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            parse_url,
            &[url as u32, parsed as u32],
        );
        assert_eq!(result, 0, "ParseURLW succeeds");
        assert_eq!(memory.read_u32(parsed).unwrap(), 24, "cbSize echoed");
        assert_eq!(
            read_guest_pointer(&memory, parsed + 4, GuestArch::X86).unwrap(),
            url,
            "pszProtocol points at the URL"
        );
        assert_eq!(memory.read_u32(parsed + 8).unwrap(), 5, "cchProtocol");
        assert_eq!(
            memory.read_u32(parsed + 0x14).unwrap(),
            12,
            "URL_SCHEME_HTTPS"
        );
        let suffix = read_guest_pointer(&memory, parsed + 12, GuestArch::X86).unwrap();
        assert_eq!(
            read_guest_utf16_string(&memory, suffix, 64),
            "//example.com/a?b"
        );
        assert_eq!(memory.read_u32(parsed + 16).unwrap(), 17, "cchSuffix");

        // A URL without a valid scheme fails with URL_E_INVALID_SYNTAX and
        // clears pszProtocol.
        let bad = runtime
            .alloc_utf16_string(&mut memory, "no-scheme")
            .expect("wide bad");
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            parse_url,
            &[bad as u32, parsed as u32],
        );
        assert_eq!(result, 0x8004_1001);
        assert_eq!(
            read_guest_pointer(&memory, parsed + 4, GuestArch::X86).unwrap(),
            0
        );

        // A wrong cbSize fails with E_INVALIDARG.
        memory.map_bytes(parsed, &[0_u8; 0x40]);
        write_u32(&mut memory, parsed, 0x40);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            parse_url,
            &[url as u32, parsed as u32],
        );
        assert_eq!(result, 0x8007_0057);

        // StrFromTimeIntervalW formats rounded whole seconds with
        // significant digits and the " hr"/" min"/" sec" units.
        let buffer = 0x43_500;
        memory.map_bytes(buffer, &[0_u8; 0x100]);
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            time_interval,
            &[
                buffer as u32,
                0x100,
                138 * 3_600_000 + 43 * 60_000 + 15_000,
                5,
            ],
        );
        assert_eq!(written, 14);
        assert_eq!(
            read_guest_utf16_string(&memory, buffer, 64),
            " 138 hr 43 min"
        );
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            time_interval,
            &[buffer as u32, 0x100, 61_500, 2],
        );
        assert_eq!(written, 12);
        assert_eq!(read_guest_utf16_string(&memory, buffer, 64), " 1 min 2 sec");
        // digits == 0 → empty output.
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            time_interval,
            &[buffer as u32, 0x100, 5000, 0],
        );
        assert_eq!(written, 0);
        assert_eq!(read_guest_utf16_string(&memory, buffer, 64), "");
    })
}

#[test]
fn xinput_exports_dispatch_roundtrip() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("xinput-exports");
        let mut memory = MemoryImage::default();
        let get_state = runtime.alloc_host_thunk(HostThunk::XInputGetState);
        let set_state = runtime.alloc_host_thunk(HostThunk::XInputSetState);
        let caps = runtime.alloc_host_thunk(HostThunk::XInputGetCapabilities);
        let battery = runtime.alloc_host_thunk(HostThunk::XInputGetBatteryInformation);
        let keystroke = runtime.alloc_host_thunk(HostThunk::XInputGetKeystroke);
        let enable = runtime.alloc_host_thunk(HostThunk::XInputEnable);
        let dsound = runtime.alloc_host_thunk(HostThunk::XInputGetDSoundAudioDeviceGuids);

        // Disconnected controller: XInputGetState reports
        // ERROR_DEVICE_NOT_CONNECTED; NULL state pointer reports E_POINTER.
        let state_ptr = 0x41_000;
        memory.map_bytes(state_ptr as u64, &[0; 24]);
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            get_state,
            &[(Register::Rcx, 0), (Register::Rdx, state_ptr as u64)],
        );
        assert_eq!(
            result, 0x48F,
            "disconnected slot reports ERROR_DEVICE_NOT_CONNECTED"
        );
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            get_state,
            &[(Register::Rcx, 0), (Register::Rdx, 0)],
        );
        assert_eq!(result, 0x8000_4003, "NULL state pointer reports E_POINTER");

        runtime
            .xinput_manager
            .connect_controller(
                0,
                crate::real_win32::XInputState {
                    packet_number: 1,
                    buttons: crate::real_win32::XINPUT_GAMEPAD_A,
                    left_trigger: 128,
                    right_trigger: 0,
                    left_thumb_x: 0,
                    left_thumb_y: 0,
                    right_thumb_x: 0,
                    right_thumb_y: 0,
                },
            )
            .expect("connect controller");

        // XInputGetState writes XINPUT_STATE (packet + gamepad) to guest memory.
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            get_state,
            &[(Register::Rcx, 0), (Register::Rdx, state_ptr as u64)],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, 0);
        assert_eq!(memory.read_u32(state_ptr as u64).expect("packet"), 1);
        assert_eq!(
            memory.read_u16(state_ptr as u64 + 4).expect("buttons"),
            crate::real_win32::XINPUT_GAMEPAD_A
        );
        assert_eq!(
            memory.read_u8(state_ptr as u64 + 6).expect("left trigger"),
            128
        );

        // XInputSetState stores the vibration speeds on the controller (the
        // stored values are pinned by the real_win32 unit tests).
        let vibration_ptr = 0x41_100;
        memory.map_bytes(vibration_ptr as u64, &[0; 4]);
        write_u16(&mut memory, vibration_ptr as u64, 65535);
        write_u16(&mut memory, vibration_ptr as u64 + 2, 32768);
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            set_state,
            &[(Register::Rcx, 0), (Register::Rdx, vibration_ptr as u64)],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, 0);
        // A NULL vibration pointer reports E_POINTER.
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            set_state,
            &[(Register::Rcx, 0), (Register::Rdx, 0)],
        );
        assert_eq!(result, 0x8000_4003);

        // XInputGetCapabilities writes XINPUT_CAPABILITIES (28 bytes).
        let caps_ptr = 0x41_200;
        memory.map_bytes(caps_ptr as u64, &[0; 28]);
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            caps,
            &[
                (Register::Rcx, 0),
                (Register::Rdx, 0),
                (Register::R8, caps_ptr as u64),
            ],
        );
        assert_eq!(result, 0);
        let caps_from_guest = runtime.xinput_manager.get_capabilities(0).expect("caps");
        assert_eq!(
            memory.read_u8(caps_ptr as u64).expect("controller type"),
            caps_from_guest.controller_type
        );
        assert_eq!(
            memory
                .read_u16(caps_ptr as u64 + 24)
                .expect("vibration left"),
            caps_from_guest.vibration_left
        );

        // XInputGetBatteryInformation: wired + full for a connected slot,
        // ERROR_DEVICE_NOT_CONNECTED for a disconnected slot.
        let battery_ptr = 0x41_300;
        memory.map_bytes(battery_ptr as u64, &[0; 2]);
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            battery,
            &[
                (Register::Rcx, 0),
                (Register::Rdx, 0),
                (Register::R8, battery_ptr as u64),
            ],
        );
        assert_eq!(result, 0);
        assert_eq!(memory.read_u8(battery_ptr as u64).expect("battery type"), 0);
        assert_eq!(
            memory
                .read_u8(battery_ptr as u64 + 1)
                .expect("battery level"),
            3
        );
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            battery,
            &[
                (Register::Rcx, 1),
                (Register::Rdx, 0),
                (Register::R8, battery_ptr as u64),
            ],
        );
        assert_eq!(result, 0x48F);

        // XInputGetKeystroke with no pending events reports ERROR_EMPTY.
        let keystroke_ptr = 0x41_400;
        memory.map_bytes(keystroke_ptr as u64, &[0; 8]);
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            keystroke,
            &[
                (Register::Rcx, 0),
                (Register::Rdx, 0),
                (Register::R8, keystroke_ptr as u64),
            ],
        );
        assert_eq!(result, 1, "no pending keystroke reports ERROR_EMPTY");

        // XInputEnable flips the manager's processing switch (the flag
        // round-trip itself is pinned by the real_win32 unit tests).
        let result =
            dispatch_x86_thunk_regs(&mut runtime, &mut memory, enable, &[(Register::Rcx, 0)]);
        assert_eq!(result, 0);
        let result =
            dispatch_x86_thunk_regs(&mut runtime, &mut memory, enable, &[(Register::Rcx, 1)]);
        assert_eq!(result, 0);

        // XInputGetDSoundAudioDeviceGuids zeroes both GUID outputs.
        let render_ptr = 0x41_500;
        let capture_ptr = 0x41_510;
        memory.map_bytes(render_ptr as u64, &[0xFF; 16]);
        memory.map_bytes(capture_ptr as u64, &[0xFF; 16]);
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            dsound,
            &[
                (Register::Rcx, 0),
                (Register::Rdx, render_ptr as u64),
                (Register::R8, capture_ptr as u64),
            ],
        );
        assert_eq!(result, 0);
        assert_eq!(
            read_u64(&memory, render_ptr as u64).expect("render guid"),
            0
        );
        assert_eq!(
            read_u64(&memory, capture_ptr as u64).expect("capture guid"),
            0
        );
    })
}

#[test]
fn direct_input8_create_writes_a_managed_device_object() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("dinput8-create");
        let mut memory = MemoryImage::default();
        let create = runtime.alloc_host_thunk(HostThunk::DirectInput8Create);
        let riid_ptr = 0x41_000;
        let out_ptr = 0x41_010;
        memory.map_bytes(riid_ptr as u64, &[0; 16]);
        memory.map_bytes(out_ptr as u64, &[0; 8]);

        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            create,
            &[
                (Register::Rcx, 0x1400_0000),
                (Register::Rdx, 0x0800),
                (Register::R8, riid_ptr as u64),
                (Register::R9, out_ptr as u64),
            ],
        );
        assert_eq!(result, 0, "DirectInput8Create returns DI_OK");
        let dinput_object = memory.read_u64(out_ptr as u64).expect("dinput object");
        assert_ne!(dinput_object, 0, "a DirectInput8 object must be produced");
        assert_eq!(
            runtime.guest_object_kind(dinput_object).expect("kind"),
            GuestObjectKind::DirectInput8
        );

        // NULL out / NULL riid fail with E_INVALIDARG.
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            create,
            &[
                (Register::Rcx, 0x1400_0000),
                (Register::Rdx, 0x0800),
                (Register::R8, riid_ptr as u64),
                (Register::R9, 0),
            ],
        );
        assert_eq!(result, 0x8007_0057);
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            create,
            &[
                (Register::Rcx, 0x1400_0000),
                (Register::Rdx, 0x0800),
                (Register::R8, 0),
                (Register::R9, out_ptr as u64),
            ],
        );
        assert_eq!(result, 0x8007_0057);
    })
}

// ── evidence-mid: advapi32 token machinery ─────────────────────────────
#[test]
fn evidence_mid_advapi32_token_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mid-token");
        let mut memory = MemoryImage::default();

        // OpenProcessToken mints the process token lazily.
        let token_out = 0x61_000;
        memory.map_bytes(token_out, &[0; 4]);
        let open_process_token = runtime.alloc_host_thunk(HostThunk::OpenProcessToken);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_process_token,
                &[0xFFFF_FFFF, 0x20008, token_out as u32]
            ),
            1
        );
        let token_handle = read_u32(&memory, token_out).expect("token handle");
        assert_ne!(token_handle, 0);
        assert_eq!(
            runtime
                .tokens
                .get(&u64::from(token_handle))
                .map(|token| token.user_name.as_str()),
            Some("user")
        );

        // GetTokenInformation(TokenUser): the guest user SID.
        let info = 0x61_100;
        memory.map_bytes(info, &[0; 128]);
        let ret_len = 0x61_200;
        memory.map_bytes(ret_len, &[0; 4]);
        let get_token_info = runtime.alloc_host_thunk(HostThunk::GetTokenInformation);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_token_info,
                &[token_handle, 1, info as u32, 128, ret_len as u32]
            ),
            1
        );
        let user_sid_ptr = read_guest_pointer(&memory, info, GuestArch::X86).expect("user psid");
        let user_sid = memory
            .read_bytes(user_sid_ptr, 8 + 5 * 4)
            .expect("user sid bytes");
        assert_eq!(
            crate::advapi32::decode_sid(&user_sid).expect("decode sid"),
            "S-1-5-21-3654781254-1934577812-2019068222-1001"
        );

        // GetTokenInformation(TokenPrivileges): SeChangeNotifyPrivilege
        // is present and enabled; SeShutdownPrivilege disabled.
        let priv_info = 0x61_300;
        memory.map_bytes(priv_info, &[0; 256]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_token_info,
                &[token_handle, 3, priv_info as u32, 256, ret_len as u32]
            ),
            1
        );
        let privilege_count = read_u32(&memory, priv_info).expect("privilege count");
        assert!(privilege_count >= 10);
        let mut seen_change_notify = false;
        let mut seen_shutdown = false;
        for index in 0..privilege_count as u64 {
            let slot = priv_info + 8 + index * 16;
            let luid = read_u64(&memory, slot).expect("luid");
            let attributes = read_u32(&memory, slot + 8).expect("attributes");
            if luid == 23 {
                seen_change_notify = true;
                assert_eq!(attributes & 2, 2, "SeChangeNotifyPrivilege enabled");
            }
            if luid == 19 {
                seen_shutdown = true;
                assert_eq!(attributes & 2, 0, "SeShutdownPrivilege disabled");
            }
        }
        assert!(seen_change_notify && seen_shutdown);

        // GetTokenInformation(TokenType/TokenElevation/TokenIntegrityLevel).
        let word = 0x61_400;
        memory.map_bytes(word, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_token_info,
                &[token_handle, 8, word as u32, 4, ret_len as u32]
            ),
            1
        );
        assert_eq!(read_u32(&memory, word).expect("token type"), 1); // TokenPrimary
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_token_info,
                &[token_handle, 20, word as u32, 4, ret_len as u32]
            ),
            1
        );
        assert_eq!(read_u32(&memory, word).expect("elevation"), 0);
        let il_info = 0x61_500;
        memory.map_bytes(il_info, &[0; 64]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_token_info,
                &[token_handle, 25, il_info as u32, 64, ret_len as u32]
            ),
            1
        );
        let il_sid_ptr = read_guest_pointer(&memory, il_info, GuestArch::X86).expect("il sid");
        let il_sid = memory.read_bytes(il_sid_ptr, 12).expect("il sid bytes");
        assert_eq!(
            crate::advapi32::decode_sid(&il_sid).expect("decode il sid"),
            "S-1-16-8192"
        );

        // LookupPrivilegeValueW: the documented LUID constants.
        let name_ptr = runtime
            .alloc_utf16_string(&mut memory, "SeDebugPrivilege")
            .expect("name");
        let luid_out = 0x61_600;
        memory.map_bytes(luid_out, &[0; 8]);
        let lookup_privilege = runtime.alloc_host_thunk(HostThunk::LookupPrivilegeValueW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                lookup_privilege,
                &[0, name_ptr as u32, luid_out as u32]
            ),
            1
        );
        assert_eq!(read_u64(&memory, luid_out).expect("luid"), 20);
        let bad_name_ptr = runtime
            .alloc_utf16_string(&mut memory, "SeNoSuchPrivilege")
            .expect("name");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                lookup_privilege,
                &[0, bad_name_ptr as u32, luid_out as u32]
            ),
            0
        );
        assert_eq!(runtime.last_error, crate::advapi32::ERROR_NO_SUCH_PRIVILEGE);

        // AdjustTokenPrivileges enables SeShutdownPrivilege; the change
        // is visible through GetTokenInformation.
        let new_state = 0x61_700;
        memory.map_bytes(new_state, &[0; 32]);
        write_u32(&mut memory, new_state, 1);
        write_u64(&mut memory, new_state + 8, 19);
        write_u32(&mut memory, new_state + 16, 2); // SE_PRIVILEGE_ENABLED
        let adjust = runtime.alloc_host_thunk(HostThunk::AdjustTokenPrivileges);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                adjust,
                &[token_handle, 0, new_state as u32, 0, 0, 0]
            ),
            1
        );
        assert_eq!(runtime.last_error, 0);
        assert!(
            runtime
                .tokens
                .get(&u64::from(token_handle))
                .expect("token")
                .privilege_enabled(19),
            "SeShutdownPrivilege is enabled after AdjustTokenPrivileges"
        );
        // An unknown LUID reports ERROR_NOT_ALL_ASSIGNED (still TRUE).
        let unknown_state = 0x61_720;
        memory.map_bytes(unknown_state, &[0; 32]);
        write_u32(&mut memory, unknown_state, 1);
        write_u64(&mut memory, unknown_state + 8, 9999);
        write_u32(&mut memory, unknown_state + 16, 2);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                adjust,
                &[token_handle, 0, unknown_state as u32, 0, 0, 0]
            ),
            1
        );
        assert_eq!(runtime.last_error, crate::advapi32::ERROR_NOT_ALL_ASSIGNED);

        // AllocateAndInitializeSid → CheckTokenMembership → FreeSid.
        let sid_out = 0x61_800;
        memory.map_bytes(sid_out, &[0; 4]);
        let alloc_sid = runtime.alloc_host_thunk(HostThunk::AllocateAndInitializeSid);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                alloc_sid,
                &[
                    0,
                    0,
                    0,
                    5,
                    21,
                    0x1111_1111,
                    0x2222_2222,
                    0x3333_3333,
                    sid_out as u32
                ]
            ),
            1
        );
        let sid_handle = read_u32(&memory, sid_out).expect("sid handle");
        let sid_bytes = runtime
            .allocated_sids
            .get(&u64::from(sid_handle))
            .cloned()
            .expect("sid");
        assert_eq!(
            crate::advapi32::decode_sid(&sid_bytes).expect("decode"),
            "S-1-5-21-286331153-572662306-858993459"
        );
        let check = runtime.alloc_host_thunk(HostThunk::CheckTokenMembership);
        let member_out = 0x61_900;
        memory.map_bytes(member_out, &[0; 4]);
        let guest_sid = crate::advapi32::guest_user_sid();
        let sid_storage = runtime
            .alloc_heap(&mut memory, guest_sid.len(), true)
            .expect("sid heap");
        memory.map_bytes(sid_storage, &guest_sid);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                check,
                &[token_handle, sid_storage as u32, member_out as u32]
            ),
            1
        );
        assert_eq!(read_u32(&memory, member_out).expect("member"), 1);
        // A SID outside the token is not a member.
        let system_sid = crate::advapi32::encode_sid("S-1-5-18").expect("system sid");
        let system_storage = runtime
            .alloc_heap(&mut memory, system_sid.len(), true)
            .expect("sid heap");
        memory.map_bytes(system_storage, &system_sid);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                check,
                &[token_handle, system_storage as u32, member_out as u32]
            ),
            1
        );
        assert_eq!(read_u32(&memory, member_out).expect("member"), 0);
        let free_sid = runtime.alloc_host_thunk(HostThunk::FreeSid);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, free_sid, &[sid_handle]),
            0,
            "FreeSid returns NULL on success"
        );
        assert!(!runtime.allocated_sids.contains_key(&u64::from(sid_handle)));

        // DuplicateTokenEx copies the token into a new handle.
        let dup_out = 0x61_A00;
        memory.map_bytes(dup_out, &[0; 4]);
        let duplicate = runtime.alloc_host_thunk(HostThunk::DuplicateTokenEx);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                duplicate,
                &[token_handle, 0x20008, 0, 2, 1, dup_out as u32]
            ),
            1
        );
        let duplicated = read_u32(&memory, dup_out).expect("dup handle");
        assert_ne!(duplicated, token_handle);

        // ImpersonateLoggedOnUser → OpenThreadToken succeeds; RevertToSelf
        // → OpenThreadToken reports ERROR_NO_TOKEN.
        let impersonate = runtime.alloc_host_thunk(HostThunk::ImpersonateLoggedOnUser);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, impersonate, &[duplicated]),
            1
        );
        let thread_token_out = 0x61_B00;
        memory.map_bytes(thread_token_out, &[0; 4]);
        let open_thread_token = runtime.alloc_host_thunk(HostThunk::OpenThreadToken);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_thread_token,
                &[0xFFFF_FFFF, 0x20008, 0, thread_token_out as u32]
            ),
            1
        );
        assert_eq!(
            read_u32(&memory, thread_token_out).expect("thread token"),
            duplicated
        );
        let revert = runtime.alloc_host_thunk(HostThunk::RevertToSelf);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, revert, &[]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_thread_token,
                &[0xFFFF_FFFF, 0x20008, 0, thread_token_out as u32]
            ),
            0
        );
        assert_eq!(runtime.last_error, crate::advapi32::ERROR_NO_TOKEN);

        // GetUserNameA: the ANSI user name with the size contract.
        let ansi_buf = 0x61_C00;
        memory.map_bytes(ansi_buf, &[0; 32]);
        let ansi_size = 0x61_D00;
        memory.map_bytes(ansi_size, &32_u32.to_le_bytes());
        let get_user_name_a = runtime.alloc_host_thunk(HostThunk::GetUserNameA);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_user_name_a,
                &[ansi_buf as u32, ansi_size as u32]
            ),
            1
        );
        let name = memory.read_bytes(ansi_buf, 32).expect("ansi name");
        let name = String::from_utf8_lossy(&name);
        assert!(name.starts_with("user\0"), "ANSI user name: {name:?}");

        // LogonUserW: the guest user logs on; unknown users fail.
        let logon_user = runtime.alloc_host_thunk(HostThunk::LogonUserW);
        let logon_name = runtime
            .alloc_utf16_string(&mut memory, "user")
            .expect("logon name");
        let logon_password = runtime
            .alloc_utf16_string(&mut memory, "pw")
            .expect("password");
        let logon_out = 0x61_E00;
        memory.map_bytes(logon_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                logon_user,
                &[
                    logon_name as u32,
                    0,
                    logon_password as u32,
                    2,
                    0,
                    logon_out as u32
                ]
            ),
            1
        );
        assert_ne!(read_u32(&memory, logon_out).expect("logon token"), 0);
        let bad_name = runtime
            .alloc_utf16_string(&mut memory, "admin")
            .expect("bad name");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                logon_user,
                &[
                    bad_name as u32,
                    0,
                    logon_password as u32,
                    2,
                    0,
                    logon_out as u32
                ]
            ),
            0
        );
        assert_eq!(runtime.last_error, crate::advapi32::ERROR_LOGON_FAILURE);
    })
}

#[test]
fn evidence_dialogs_profiles_netprov_tsf_vb_surfaces() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-dialog-sys");
        let mut memory = MemoryImage::default();

        // ── comdlg32: the dialog failure + error reporting ──
        let open_file: u64 = runtime.alloc_host_thunk(HostThunk::GetOpenFileNameW);
        let dialog_error: u64 = runtime.alloc_host_thunk(HostThunk::CommDlgExtendedError);
        let open_struct = 0x41_000_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, open_file, &[open_struct as u32]),
            0,
            "no dialog host"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, dialog_error, &[]),
            0x0004,
            "CDERR_INITIALIZATION"
        );

        // ── userenv: the profile directory + environment block ──
        let profiles_dir: u64 = runtime.alloc_host_thunk(HostThunk::GetProfilesDirectoryW);
        let create_block: u64 = runtime.alloc_host_thunk(HostThunk::CreateEnvironmentBlock);
        let destroy_block: u64 = runtime.alloc_host_thunk(HostThunk::DestroyEnvironmentBlock);
        let dir_out = 0x41_100_u64;
        let dir_size_ptr = 0x41_0f0_u64;
        memory.map_bytes(dir_size_ptr, &512_u32.to_le_bytes());
        let dir_len = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            profiles_dir,
            &[dir_out as u32, dir_size_ptr as u32],
        );
        assert_eq!(dir_len, 1, "GetProfilesDirectoryW returns TRUE");
        let path = read_utf16_string(&memory, dir_out).unwrap();
        assert_eq!(path, "C:\\Users");
        let block_out = 0x41_200_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_block,
                &[block_out as u32, 0, 0]
            ),
            1
        );
        let block = read_guest_pointer(&memory, block_out, GuestArch::X86).unwrap();
        assert_ne!(block, 0);
        let first = read_utf16_string(&memory, block).unwrap();
        assert!(first.contains('='), "environment entry {first}");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, destroy_block, &[block as u32]),
            1
        );

        // ── mpr: the no-network answers ──
        let get_connection: u64 = runtime.alloc_host_thunk(HostThunk::WNetGetConnectionW);
        let open_enum: u64 = runtime.alloc_host_thunk(HostThunk::WNetOpenEnumW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_connection,
                &[0x41_300, 0x41_310, 0x41_320]
            ),
            0x0248,
            "WN_NOT_CONNECTED"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_enum,
                &[0, 0, 0, 0, 0x41_330]
            ),
            0x0249,
            "WN_NO_NETWORK"
        );

        // ── msctf: the TSF manager round trip ──
        let init_system: u64 = runtime.alloc_host_thunk(HostThunk::TfInitSystem);
        let create_mgr: u64 = runtime.alloc_host_thunk(HostThunk::TfCreateThreadMgr);
        let get_mgr: u64 = runtime.alloc_host_thunk(HostThunk::TfGetThreadMgr);
        let create_category: u64 = runtime.alloc_host_thunk(HostThunk::TfCreateCategoryMgr);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, init_system, &[0]),
            0
        );
        let mgr_out = 0x41_400_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, create_mgr, &[mgr_out as u32]),
            0
        );
        let manager = read_guest_pointer(&memory, mgr_out, GuestArch::X86).unwrap();
        assert_ne!(manager, 0);
        let fetched_out = 0x41_410_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_mgr, &[fetched_out as u32]),
            0
        );
        assert_eq!(
            read_guest_pointer(&memory, fetched_out, GuestArch::X86).unwrap(),
            manager
        );
        let category_out = 0x41_420_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_category,
                &[category_out as u32]
            ),
            0
        );
        assert_ne!(
            read_guest_pointer(&memory, category_out, GuestArch::X86).unwrap(),
            0
        );

        // ── msvbvm60: the reference-counting pair ──
        let vb_addref: u64 = runtime.alloc_host_thunk(HostThunk::BasicClassAddRef);
        let vb_release: u64 = runtime.alloc_host_thunk(HostThunk::BasicClassRelease);
        let vb_invoke: u64 = runtime.alloc_host_thunk(HostThunk::BasicClassInvoke);
        let obj = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::ComStream, 0)
            .unwrap();
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, vb_addref, &[obj as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, vb_release, &[obj as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                vb_invoke,
                &[obj as u32, 0, 0, 0, 0, 0, 0, 0]
            ),
            0x8002_0003,
            "no members"
        );
    })
}

#[test]
fn rich_edit_register_entries_create_real_windows() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("rte-register");
        let mut memory = MemoryImage::default();
        let msft = runtime.alloc_host_thunk(HostThunk::MsftEditRegisterClass);
        let riched = runtime.alloc_host_thunk(HostThunk::RichEditAnsiWndClass);

        // Both entries register real classes (zero-argument exports).
        let msft_atom = dispatch_x86_thunk(&mut runtime, &mut memory, msft, &[]);
        assert_ne!(msft_atom, 0, "MsftEditRegisterClass returns a real atom");
        let riched_atom = dispatch_x86_thunk(&mut runtime, &mut memory, riched, &[]);
        assert_ne!(riched_atom, 0, "RichEditANSIWndClass returns a real atom");
        assert_ne!(msft_atom, riched_atom, "two distinct class entries");

        // The atoms round-trip through the user32 class registry.
        assert_eq!(
            runtime.user32.class_atom("RICHEDIT50W"),
            Some(msft_atom as u16),
            "MSFTEDIT_CLASS registered under its Windows name"
        );
        assert_eq!(
            runtime.user32.class_atom("richedit"),
            Some(riched_atom as u16),
            "the ANSI class registers as RICHEDIT"
        );
        // Re-registration is idempotent (same class → same atom).
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, msft, &[]),
            msft_atom
        );

        // A guest can now create windows of both classes through the
        // real CreateWindowExW dispatch path (WS_CHILD keeps the test
        // headless), and the control text path works on them exactly
        // like on the built-in rich-edit class.
        let create_window = runtime.alloc_host_thunk(HostThunk::CreateWindowExW);
        for (class, atom) in [
            ("RICHEDIT50W", msft_atom),
            ("RICHEDIT", riched_atom),
            ("richedit", riched_atom),
        ] {
            let class_ptr = runtime
                .alloc_utf16_string(&mut memory, class)
                .expect("class name");
            let title_ptr = runtime
                .alloc_utf16_string(&mut memory, "rich text")
                .expect("title");
            let hwnd = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_window,
                &[
                    0,
                    class_ptr as u32,
                    title_ptr as u32,
                    0x4000_0000, // WS_CHILD
                    0,
                    0,
                    320,
                    200,
                    0,
                    0,
                    0,
                    0,
                ],
            );
            assert_ne!(hwnd, 0, "windows of the {class} class must be creatable");
            assert!(
                runtime
                    .user32
                    .set_window_text_w(hwnd as u32, "control text")
            );
            assert_eq!(
                runtime.user32.get_window_text_w(hwnd as u32).as_deref(),
                Some("control text"),
                "the {class} control answers WM_SETTEXT/WM_GETTEXT-style text"
            );
            let _ = atom;
        }
    })
}

// ── SHNavigateToFavorite: the real favorites store ────────────────────
#[test]
fn sh_navigate_to_favorite_adds_lists_and_removes_real_records() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("sh-favorites");
        let mut memory = MemoryImage::default();
        let navigate = runtime.alloc_host_thunk(HostThunk::ShNavigateToFavorite);
        let user = runtime.win32.ge().config.user_name.clone();
        let favorites_dir = format!("C:\\Users\\{user}\\Favorites");
        assert!(runtime.favorite_records().is_empty());

        let url = "https://example.com/game";
        let title = "Casa1 Game";
        let url_ptr = runtime.alloc_utf16_string(&mut memory, url).expect("ptr");
        let title_ptr = runtime.alloc_utf16_string(&mut memory, title).expect("ptr");

        // Add: S_OK + one real record + a real persisted .url file.
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            navigate,
            &[url_ptr as u32, title_ptr as u32, 0],
        );
        assert_eq!(ret, 0, "adding a favorite returns S_OK");
        assert_eq!(runtime.last_error, 0);
        let records = runtime.favorite_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].url, url);
        assert_eq!(records[0].title, title);
        assert_eq!(records[0].user, user);
        assert!(records[0].added_at_ms > 0);
        assert_eq!(records[0].updated_at_ms, records[0].added_at_ms);

        let favorite_file = format!("{favorites_dir}\\{title}.url");
        let host_file = runtime
            .win32
            .guest_path_to_host_path(&favorite_file)
            .expect("favorite host path");
        assert_eq!(
            fs::read_to_string(&host_file).expect("read favorite file"),
            format!("[InternetShortcut]\r\nURL={url}\r\n"),
            "the favorite persists as a real Windows .url file"
        );

        // The same URL again updates the title and keeps one record.
        let title2 = "Casa1 Game Renamed";
        let title2_ptr = runtime
            .alloc_utf16_string(&mut memory, title2)
            .expect("ptr");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            navigate,
            &[url_ptr as u32, title2_ptr as u32, 0],
        );
        assert_eq!(ret, 0);
        let records = runtime.favorite_records();
        assert_eq!(records.len(), 1, "one record per URL");
        assert_eq!(records[0].title, title2);
        assert!(records[0].updated_at_ms >= records[0].added_at_ms);
        assert!(!host_file.exists(), "the old .url is removed on rename");
        let renamed_file = format!("{favorites_dir}\\{title2}.url");
        assert!(
            runtime
                .win32
                .guest_path_to_host_path(&renamed_file)
                .expect("renamed host path")
                .exists()
        );

        // A title-less add stores the URL as the display title.
        let bare_url = "https://example.org/plain";
        let bare_ptr = runtime
            .alloc_utf16_string(&mut memory, bare_url)
            .expect("ptr");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            navigate,
            &[bare_ptr as u32, 0, 0],
        );
        assert_eq!(ret, 0);
        let records = runtime.favorite_records();
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .any(|record| record.url == bare_url && record.title == bare_url)
        );

        // Remove: S_OK + the record and file are gone.
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, navigate, &[url_ptr as u32, 0, 1]);
        assert_eq!(ret, 0, "removing an existing favorite returns S_OK");
        let records = runtime.favorite_records();
        assert_eq!(records.len(), 1);
        assert!(!records.iter().any(|record| record.url == url));

        // Removing again: nothing existed → S_FALSE (not an error).
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, navigate, &[url_ptr as u32, 0, 1]);
        assert_eq!(ret, 1, "removing a missing favorite answers S_FALSE");
        assert_eq!(runtime.last_error, 0);

        // Real argument failures: null URL, unknown flag bits.
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, navigate, &[0, 0, 0]);
        assert_eq!(ret, 0x8007_0057);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            navigate,
            &[bare_ptr as u32, 0, 0x2],
        );
        assert_eq!(ret, 0x8007_0057, "unknown action flags are E_INVALIDARG");
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
    })
}

// ── SHOpenFolderWindow: the folder-window session registry ────────────
#[test]
fn sh_open_folder_window_opens_and_closes_real_window_sessions() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("sh-folder-window");
        let mut memory = MemoryImage::default();
        let open_window = runtime.alloc_host_thunk(HostThunk::ShOpenFolderWindow);
        let user = runtime.win32.ge().config.user_name.clone();
        let desktop = format!("C:\\Users\\{user}\\Desktop");
        runtime
            .win32
            .create_directory_w(&desktop)
            .expect("create desktop");
        let other = format!("C:\\Users\\{user}\\Documents");
        let _ = runtime.win32.create_directory_w(&other);

        // Open the first folder window session.
        let folder_ptr = runtime
            .alloc_utf16_string(&mut memory, &desktop)
            .expect("ptr");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_window,
            &[folder_ptr as u32, 0, 0],
        );
        assert_eq!(ret, 0, "SHOpenFolderWindow returns S_OK");
        assert_eq!(runtime.last_error, 0);
        let windows = runtime.folder_window_records();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].folder.to_lowercase(), desktop.to_lowercase());
        assert!(windows[0].visible);
        assert!(windows[0].closed_at_ms.is_none());
        assert_eq!(windows[0].events.len(), 1);
        assert_eq!(windows[0].events[0].kind, "open");
        let first_id = windows[0].id;

        // A second folder opens a second, distinct session.
        let other_ptr = runtime
            .alloc_utf16_string(&mut memory, &other)
            .expect("ptr");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_window,
            &[other_ptr as u32, 0, 0],
        );
        assert_eq!(ret, 0);
        let windows = runtime.folder_window_records();
        assert_eq!(windows.len(), 2);
        assert_ne!(windows[1].id, first_id, "monotonic session ids");
        assert!(windows.iter().all(|window| window.visible));

        // Close one session: real close transition, hidden window.
        assert!(runtime.close_folder_window(first_id));
        let windows = runtime.folder_window_records();
        let closed = windows
            .iter()
            .find(|window| window.id == first_id)
            .expect("window");
        assert!(!closed.visible);
        assert!(closed.closed_at_ms.is_some());
        assert_eq!(closed.events.len(), 2);
        assert_eq!(closed.events[1].kind, "close");
        assert!(closed.events[1].at_ms >= closed.events[0].at_ms);
        assert!(!runtime.close_folder_window(first_id), "already closed");

        // Real failure modes: nonexistent folder (file-not-found when
        // the parent exists), missing parent (path-not-found), null
        // folder and reserved flags.
        let missing = format!("C:\\Users\\{user}\\NoSuchFolder");
        let missing_ptr = runtime
            .alloc_utf16_string(&mut memory, &missing)
            .expect("ptr");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_window,
            &[missing_ptr as u32, 0, 0],
        );
        assert_eq!(ret, 0x8007_0002, "missing folder → ERROR_FILE_NOT_FOUND");
        let deep_missing = "C:\\Missing\\X\\Y";
        let deep_ptr = runtime
            .alloc_utf16_string(&mut memory, deep_missing)
            .expect("ptr");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_window,
            &[deep_ptr as u32, 0, 0],
        );
        assert_eq!(ret, 0x8007_0003, "missing parent → ERROR_PATH_NOT_FOUND");
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, open_window, &[0, 0, 0]);
        assert_eq!(ret, 0x8007_0057, "null folder is E_INVALIDARG");
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_window,
            &[folder_ptr as u32, 0, 1],
        );
        assert_eq!(ret, 0x8007_0057, "reserved flags are E_INVALIDARG");

        // A file is not a folder window target.
        let file_path = format!("{desktop}\\plain.txt");
        runtime
            .win32
            .write_file_overwrite_w(&file_path, b"x")
            .expect("target file");
        let file_ptr = runtime
            .alloc_utf16_string(&mut memory, &file_path)
            .expect("ptr");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_window,
            &[file_ptr as u32, 0, 0],
        );
        assert_eq!(ret, 0x8007_010b, "a file is not a folder → ERROR_DIRECTORY");
    })
}

// ── SHCreateExplorerTaskband: the taskband session ────────────────────
#[test]
fn sh_create_explorer_taskband_creates_one_real_taskband_session() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("sh-taskband");
        let mut memory = MemoryImage::default();
        let taskband = runtime.alloc_host_thunk(HostThunk::ShCreateExplorerTaskband);
        assert!(runtime.explorer_taskband().is_none());

        let first = "C:\\Games\\steam.exe -silent";
        let second = "notepad.exe";
        let first_ptr = runtime.alloc_utf16_string(&mut memory, first).expect("ptr");
        let second_ptr = runtime
            .alloc_utf16_string(&mut memory, second)
            .expect("ptr");
        let array = 0x60_200_u64;
        memory.map_bytes(array, &[0; 8]);
        write_u32(&mut memory, array, first_ptr as u32);
        write_u32(&mut memory, array + 4, second_ptr as u32);

        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, taskband, &[array as u32, 2, 0]);
        assert_eq!(ret, 0, "the taskband session is created (S_OK)");
        assert_eq!(runtime.last_error, 0);
        let band = runtime.explorer_taskband().expect("taskband exists");
        assert_eq!(band.tasks.len(), 2);
        assert_eq!(band.tasks[0].command_line, first);
        assert_eq!(band.tasks[0].display_name, "steam");
        assert_eq!(band.tasks[1].command_line, second);
        assert_eq!(band.tasks[1].display_name, "notepad");
        assert!(band.created_at_ms > 0);

        // One taskband per shell session: a second creation is S_FALSE
        // and changes nothing.
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, taskband, &[array as u32, 2, 0]);
        assert_eq!(ret, 1, "the existing session answers S_FALSE");
        assert_eq!(runtime.last_error, 0);
        assert_eq!(
            runtime.explorer_taskband().expect("taskband").tasks.len(),
            2
        );

        // A taskband with no tasks is a valid (empty) session on a
        // fresh runtime.
        let (mut empty_runtime, _tmp2) = test_runtime("sh-taskband-empty");
        let mut empty_memory = MemoryImage::default();
        let empty_thunk = empty_runtime.alloc_host_thunk(HostThunk::ShCreateExplorerTaskband);
        let ret = dispatch_x86_thunk(
            &mut empty_runtime,
            &mut empty_memory,
            empty_thunk,
            &[0, 0, 0],
        );
        assert_eq!(ret, 0, "an empty task list creates an empty taskband");
        assert!(empty_runtime.explorer_taskband().is_some());
        assert!(
            empty_runtime
                .explorer_taskband()
                .expect("taskband")
                .tasks
                .is_empty()
        );

        // Real argument failures on a fresh runtime.
        let (mut bad_runtime, _tmp3) = test_runtime("sh-taskband-bad");
        let mut bad_memory = MemoryImage::default();
        let bad_thunk = bad_runtime.alloc_host_thunk(HostThunk::ShCreateExplorerTaskband);
        let ret = dispatch_x86_thunk(&mut bad_runtime, &mut bad_memory, bad_thunk, &[0, 1, 0]);
        assert_eq!(ret, 0x8007_0057, "count without an array is E_INVALIDARG");
        let null_entry = 0x60_300_u64;
        bad_memory.map_bytes(null_entry, &[0; 4]);
        let ret = dispatch_x86_thunk(
            &mut bad_runtime,
            &mut bad_memory,
            bad_thunk,
            &[null_entry as u32, 1, 0],
        );
        assert_eq!(ret, 0x8007_0057, "null entries are E_INVALIDARG");
        let empty = "";
        let empty_ptr = bad_runtime
            .alloc_utf16_string(&mut bad_memory, empty)
            .expect("ptr");
        let array = 0x60_400_u64;
        bad_memory.map_bytes(array, &[0; 4]);
        write_u32(&mut bad_memory, array, empty_ptr as u32);
        let ret = dispatch_x86_thunk(
            &mut bad_runtime,
            &mut bad_memory,
            bad_thunk,
            &[array as u32, 1, 0],
        );
        assert_eq!(ret, 0x8007_0057, "empty command lines are E_INVALIDARG");
        assert_eq!(bad_runtime.last_error, ERROR_INVALID_PARAMETER);
        let ret = dispatch_x86_thunk(&mut bad_runtime, &mut bad_memory, bad_thunk, &[0, 0, 1]);
        assert_eq!(ret, 0x8007_0057, "reserved flags are E_INVALIDARG");
        assert!(bad_runtime.explorer_taskband().is_none());
    })
}
