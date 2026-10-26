use super::support::*;
use super::*;

// ── Steam API flat export (Phase B3) tests ─────────────────────────────
#[test]
fn steam_api_shutdown_clears_state() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "steam-api-shutdown",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
        let mut memory = MemoryImage::default();

        // Set up some state
        runtime.steam_api_initialized = true;
        runtime.steam_callbacks.insert(123, 0x1000);
        runtime.steam_call_results.insert(456, 0x2000);

        let thunk = runtime.alloc_host_thunk(HostThunk::SteamAPI_Shutdown);
        let mut state = CpuState::new(GuestArch::X64);
        runtime
            .dispatch_import(thunk, &mut state, &mut memory)
            .expect("dispatch SteamAPI_Shutdown");

        assert!(
            !runtime.steam_api_initialized,
            "steam_api_initialized should be cleared"
        );
        assert!(
            runtime.steam_callbacks.is_empty(),
            "callbacks should be cleared"
        );
        assert!(
            runtime.steam_call_results.is_empty(),
            "call results should be cleared"
        );
    })
}

#[test]
fn steam_api_context_init_initialises_context() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "steam-api-ctx-init",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
        let mut memory = MemoryImage::default();

        // Allocate a context structure in guest memory
        let context_ptr = runtime
            .alloc_zeroed(&mut memory, 16, 8)
            .expect("alloc context");

        let thunk = runtime.alloc_host_thunk(HostThunk::SteamInternal_ContextInit);
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rcx, context_ptr);
        runtime
            .dispatch_import(thunk, &mut state, &mut memory)
            .expect("dispatch ContextInit");

        let result = state.get(Register::Rax);
        assert_ne!(
            result, 0,
            "ContextInit should return non-null context pointer"
        );

        // The context pointer should now store the allocated address
        let stored = memory.read_u64(context_ptr).expect("read context ptr");
        assert_eq!(stored, result, "context should store the returned pointer");
    })
}

// ── Phase M4: SxS Activation Context tests ─────────────────────────────
#[test]
fn test_sxs_activation_context_create_and_release() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "sxs-create-release",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
        let mut memory = MemoryImage::default();
        let thunk = runtime.alloc_host_thunk(HostThunk::CreateActCtxW);

        // Build a minimal ACTCTXW structure in guest memory
        // PE32+ layout: cbSize=48, dwFlags=0, lpSource=ptr-to-source-string,
        // wProcessorArchitecture=0, wLangId=0, lpAssemblyDirectory=0,
        // lpResourceName=0, lpApplicationName=0, hModule=0
        let ctx_addr = 0x100_000;
        let source_str_addr = 0x200_000;
        let source_utf16: Vec<u16> = "C:\\test\\app.exe.manifest".encode_utf16().collect();

        memory.map_bytes(source_str_addr, &u16_bytes(&source_utf16));
        memory.map_bytes(source_str_addr + (source_utf16.len() * 2) as u64, &[0, 0]); // null terminator
        // Write ACTCTXW
        write_u32(&mut memory, ctx_addr, 48); // cbSize (u32)
        write_u32(&mut memory, ctx_addr + 4, 0); // dwFlags (u32)
        write_u64(&mut memory, ctx_addr + 8, source_str_addr); // lpSource (pointer)
        write_u16(&mut memory, ctx_addr + 16, 0); // wProcessorArchitecture
        write_u16(&mut memory, ctx_addr + 18, 0); // wLangId
        write_u64(&mut memory, ctx_addr + 24, 0); // lpAssemblyDirectory
        write_u64(&mut memory, ctx_addr + 32, 0); // lpResourceName
        write_u64(&mut memory, ctx_addr + 40, 0); // lpApplicationName
        write_u64(&mut memory, ctx_addr + 48, 0); // hModule

        let mut state = CpuState::new(GuestArch::X64);
        let stack = 0x50_000;
        memory.map_bytes(stack, &[0_u8; 0x200]);
        write_u64(&mut memory, stack, 0xDEAD_BEEF); // return address
        state.set(Register::Rsp, stack);
        state.set(Register::Rcx, ctx_addr); // arg(0) = pActCtx
        runtime
            .dispatch_import(thunk, &mut state, &mut memory)
            .expect("dispatch CreateActCtxW");

        let handle = state.get(Register::Rax);
        assert_ne!(handle, 0, "CreateActCtxW should return a valid handle");
        assert_ne!(
            handle,
            u64::MAX,
            "CreateActCtxW should not return INVALID_HANDLE_VALUE"
        );

        // Verify the activation context was stored
        assert!(
            runtime.activation_contexts.contains_key(&handle),
            "activation context should be stored"
        );

        // Now release it
        let release_thunk = runtime.alloc_host_thunk(HostThunk::ReleaseActCtx);
        let stack2 = 0x51_000;
        memory.map_bytes(stack2, &vec![0_u8; 0x200]);
        write_u64(&mut memory, stack2, 0xDEAD_BEEF); // return address
        state.set(Register::Rsp, stack2);
        state.set(Register::Rcx, handle); // arg(0) = handle
        runtime
            .dispatch_import(release_thunk, &mut state, &mut memory)
            .expect("dispatch ReleaseActCtx");
        assert_eq!(
            state.get(Register::Rax),
            1,
            "ReleaseActCtx should return TRUE"
        );
        assert!(
            !runtime.activation_contexts.contains_key(&handle),
            "activation context should be removed after release"
        );
    })
}

#[test]
fn test_sxs_comctl32_v6_state() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "sxs-comctl32", GeArch::X64, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        assert!(
            !runtime.is_comctl32_v6_active(),
            "comctl32 v6 should not be active by default"
        );
        runtime.comctl32_v6_active = true;
        assert!(
            runtime.is_comctl32_v6_active(),
            "comctl32 v6 should be active after setting"
        );
    })
}

#[test]
fn test_sxs_check_local_redirection_no_file() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "sxs-local-redir",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        // A non-existent path should not activate .local redirection
        let result = runtime.check_local_redirection(Path::new("/nonexistent/path.exe"));
        assert!(
            !result,
            ".local redirection should be false for non-existent path"
        );
        assert!(
            !runtime.local_redirect_active,
            "local_redirect_active should be false"
        );
    })
}

// -----------------------------------------------------------------------
// Item 113: Tests for TLS callbacks, process attach/detach ordering
// -----------------------------------------------------------------------
// -----------------------------------------------------------------------
// Items 114-115: COM object lifetime and reference counting tests
// -----------------------------------------------------------------------
#[test]
fn test_com_object_release_to_zero_frees() {
    with_big_stack(|| {
        let mut runtime = make_test_runtime();
        let mut memory = MemoryImage::default();

        let vtable_addr = 0x10_000;
        memory.map_bytes(vtable_addr, &[0u8; 64]);
        let obj_addr = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::DirectSound8, vtable_addr)
            .expect("alloc COM object");

        // Release to zero
        let count = runtime.release_guest_object(obj_addr).expect("Release");
        assert_eq!(count, 0);

        // Object should be freed
        assert!(!runtime.guest_objects.contains_key(&obj_addr));
    })
}

#[test]
fn test_com_object_release_saturating() {
    with_big_stack(|| {
        let mut runtime = make_test_runtime();
        let mut memory = MemoryImage::default();

        let vtable_addr = 0x10_000;
        memory.map_bytes(vtable_addr, &[0u8; 64]);
        let obj_addr = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::FileDialog, vtable_addr)
            .expect("alloc COM object");

        // Release should not underflow
        let count = runtime.release_guest_object(obj_addr).expect("Release");
        assert_eq!(count, 0);
        assert!(!runtime.guest_objects.contains_key(&obj_addr));
    })
}

#[test]
fn test_com_object_release_unknown_address_fails() {
    with_big_stack(|| {
        let mut runtime = make_test_runtime();
        let result = runtime.release_guest_object(0xDEAD_BEEF);
        assert!(result.is_err(), "expected Err, got {result:?}");
    })
}

#[test]
fn test_com_object_addref_unknown_address_fails() {
    with_big_stack(|| {
        let mut runtime = make_test_runtime();
        let result = runtime.add_ref_guest_object(0xDEAD_BEEF);
        assert!(result.is_err(), "expected Err, got {result:?}");
    })
}

#[test]
fn test_com_object_create_and_release_cycle() {
    with_big_stack(|| {
        let mut runtime = make_test_runtime();
        let mut memory = MemoryImage::default();

        let vtable_addr = 0x10_000;
        memory.map_bytes(vtable_addr, &[0u8; 64]);

        // Simulate a typical COM lifecycle: Create -> QI -> Release -> Release
        let obj_addr = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::DirectSound8, vtable_addr)
            .expect("alloc");

        // Simulate QueryInterface (AddRef)
        let count = runtime.add_ref_guest_object(obj_addr).expect("QI AddRef");
        assert_eq!(count, 2);

        // Release the QI reference
        let count = runtime.release_guest_object(obj_addr).expect("QI Release");
        assert_eq!(count, 1);
        assert!(runtime.guest_objects.contains_key(&obj_addr));

        // Release the original reference
        let count = runtime
            .release_guest_object(obj_addr)
            .expect("Final Release");
        assert_eq!(count, 0);
        assert!(!runtime.guest_objects.contains_key(&obj_addr));
    })
}

#[test]
fn test_com_multiple_objects_independent_lifetimes() {
    with_big_stack(|| {
        let mut runtime = make_test_runtime();
        let mut memory = MemoryImage::default();

        let vtable_addr = 0x10_000;
        memory.map_bytes(vtable_addr, &[0u8; 64]);

        let obj1 = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::DirectSound8, vtable_addr)
            .expect("alloc1");
        let obj2 = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::FileDialog, vtable_addr)
            .expect("alloc2");

        // Release obj1
        runtime.release_guest_object(obj1).expect("release1");
        assert!(!runtime.guest_objects.contains_key(&obj1));
        assert!(runtime.guest_objects.contains_key(&obj2));

        // Release obj2
        runtime.release_guest_object(obj2).expect("release2");
        assert!(!runtime.guest_objects.contains_key(&obj2));
    })
}

// == evidence-gfx-tail dispatch tests ==
// Guest-API dispatch coverage for the evidence-gfx-tail pass:
// gdiplus/cef/oleaut32/wininet/steam/usp10/dwmapi/winspool/version/psapi
// families.  Each test drives the HostThunk arms (the exact code the
// exported thunk dispatches into) and asserts observable behavior.
//
// -- steam_api / steam_api64: remaining flat exports ---------------------
#[test]
fn steam_api_write_mini_dump_writes_dump_file_dispatch() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "steam-write-minidump",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
        runtime.current_directory = temp_dir.path().to_string_lossy().to_string();
        let mut memory = MemoryImage::default();

        let thunk = runtime.alloc_host_thunk(HostThunk::SteamAPI_WriteMiniDump);
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rcx, 0xC0000005); // EXCEPTION_ACCESS_VIOLATION
        state.set(Register::Rdx, 0); // exception info
        state.set(Register::R8, 480); // build id
        runtime
            .dispatch_import(thunk, &mut state, &mut memory)
            .expect("dispatch WriteMiniDump");

        assert_eq!(state.get(Register::Rax), 0, "WriteMiniDump is void");
        let dumps: Vec<_> = std::fs::read_dir(temp_dir.path())
            .expect("read dump dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("steam_crash_")
                    && entry.file_name().to_string_lossy().ends_with(".mdmp")
            })
            .collect();
        assert!(
            !dumps.is_empty(),
            "WriteMiniDump must produce a steam_crash_*.mdmp file"
        );
        let data = std::fs::read(dumps[0].path()).expect("read dump");
        assert!(
            data.starts_with(b"MDMP"),
            "the dump file must be a valid minidump (MDMP magic)"
        );
    })
}

// -- ole32: OleInitialize / OleUninitialize / CoCreateInstanceEx ---------
#[test]
fn ole32_ole_initialize_uninitialize_dispatch() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "ole-init", GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // Register a COM class so apartment state is observable through the
        // public Win32Subsystem activation API.
        runtime
            .win32
            .register_com_class(
                SHELL_LINK_CLSID,
                "C:\\shell32.dll",
                crate::win32::ComThreadingModel::Sta,
            )
            .expect("register com class");
        let thread_handle = runtime.win32.current_thread_handle();
        assert!(
            runtime
                .win32
                .co_create_instance(thread_handle, SHELL_LINK_CLSID)
                .is_err(),
            "before OleInitialize the thread has no apartment"
        );

        let init = runtime.alloc_host_thunk(HostThunk::OleInitialize);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, init, &[0, 0]),
            0,
            "OleInitialize returns S_OK"
        );
        assert!(
            runtime
                .win32
                .co_create_instance(thread_handle, SHELL_LINK_CLSID)
                .is_ok(),
            "after OleInitialize the thread runs an STA apartment"
        );

        let uninit = runtime.alloc_host_thunk(HostThunk::OleUninitialize);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, uninit, &[0]),
            0,
            "OleUninitialize returns S_OK"
        );
        assert!(
            runtime
                .win32
                .co_create_instance(thread_handle, SHELL_LINK_CLSID)
                .is_err(),
            "after OleUninitialize the apartment is gone"
        );
    })
}

// -- oleaut32: BSTR / Variant / SafeArray dispatch round trips -----------
#[test]
fn oleaut32_null_arguments_report_e_invalidarg_dispatch() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "oleaut-invalid",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let clear = runtime.alloc_host_thunk(HostThunk::VariantClear);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, clear, &[0]),
            0x8007_0057,
            "VariantClear(NULL) reports E_INVALIDARG"
        );

        let init = runtime.alloc_host_thunk(HostThunk::VariantInit);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, init, &[0]),
            0x8007_0057,
            "VariantInit(NULL) reports E_INVALIDARG"
        );
    })
}

#[test]
fn evidence_com_guid_string_conversions_and_task_allocator() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-com-guid");
        let mut memory = MemoryImage::default();
        let clsid_from_string: u64 = runtime.alloc_host_thunk(HostThunk::ClsidFromString);
        let task_alloc: u64 = runtime.alloc_host_thunk(HostThunk::CoTaskMemAlloc);
        let task_free: u64 = runtime.alloc_host_thunk(HostThunk::CoTaskMemFree);

        let text_ptr = 0x41_000;
        let out_ptr = 0x41_100;
        write_utf16_fixed_buffer(
            &mut memory,
            text_ptr,
            64,
            "{12345678-1234-1234-1234-123456789ABC}",
        );
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            clsid_from_string,
            &[text_ptr as u32, out_ptr as u32],
        );
        assert_eq!(memory.read_u8(out_ptr).unwrap(), 0x78);
        assert_eq!(memory.read_u8(out_ptr + 1).unwrap(), 0x56);
        assert_eq!(memory.read_u8(out_ptr + 3).unwrap(), 0x12);

        let ptr = dispatch_x86_thunk(&mut runtime, &mut memory, task_alloc, &[64]);
        assert_ne!(ptr, 0);
        assert!(runtime.com_task_allocations.contains_key(&ptr));
        dispatch_x86_thunk(&mut runtime, &mut memory, task_free, &[ptr as u32]);
        assert!(!runtime.com_task_allocations.contains_key(&ptr));
    })
}

#[test]
fn evidence_com_server_lock_and_time_helpers() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-com-server");
        let mut memory = MemoryImage::default();
        let add_ref: u64 = runtime.alloc_host_thunk(HostThunk::CoAddRefServerProcess);
        let release: u64 = runtime.alloc_host_thunk(HostThunk::CoReleaseServerProcess);
        let file_time_now: u64 = runtime.alloc_host_thunk(HostThunk::CoFileTimeNow);

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, add_ref, &[]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, add_ref, &[]),
            2
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release, &[]),
            1
        );

        let ft_ptr = 0x41_200;
        dispatch_x86_thunk(&mut runtime, &mut memory, file_time_now, &[ft_ptr as u32]);
        let low = memory.read_u32(ft_ptr).unwrap();
        let high = memory.read_u32(ft_ptr + 4).unwrap();
        assert!(
            ((high as u64) << 32 | low as u64) > 0,
            "FILETIME must be nonzero"
        );
    })
}

#[test]
fn evidence_com_marshal_stream_round_trip() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-com-marshal");
        let mut memory = MemoryImage::default();
        let marshal: u64 =
            runtime.alloc_host_thunk(HostThunk::CoMarshalInterThreadInterfaceInStream);
        let unmarshal: u64 = runtime.alloc_host_thunk(HostThunk::CoGetInterfaceAndReleaseStream);

        let iid_ptr = 0x41_000;
        let object = 0x42_000_u64;
        let stream_out = 0x41_100;
        let iface_out = 0x41_200;
        for (index, byte) in [0x11u8, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            .iter()
            .enumerate()
        {
            memory.write_u8(iid_ptr + index as u64, *byte);
        }
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            marshal,
            &[iid_ptr as u32, object as u32, stream_out as u32],
        );
        let stream = read_guest_pointer(&memory, stream_out, GuestArch::X86).unwrap();
        assert_ne!(stream, 0);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            unmarshal,
            &[stream as u32, 0, iface_out as u32],
        );
        let recovered = read_guest_pointer(&memory, iface_out, GuestArch::X86).unwrap();
        assert_eq!(recovered, object, "the marshaled interface round-trips");
    })
}
