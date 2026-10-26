use super::support::*;
use super::*;

#[test]
fn get_exit_code_thread_reports_active_exited_and_closed_handles() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "get-exit-code-thread",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let get_exit_code_thread = runtime.alloc_host_thunk(HostThunk::GetExitCodeThread);
        let exit_code_ptr = 0x41_000_u32;
        memory.map_bytes(exit_code_ptr as u64, &[0; 4]);

        let thread_handle = runtime.win32.create_thread(
            crate::win32::ThreadPlan {
                exit_code: None,
                priority: 0,
                signaled: false,
            },
            false,
        );

        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_exit_code_thread,
            &[thread_handle, exit_code_ptr],
        );
        assert_eq!(result, 1);
        assert_eq!(
            read_u32(&memory, exit_code_ptr as u64).expect("active exit code"),
            STILL_ACTIVE
        );
        assert_eq!(runtime.last_error, 0);

        runtime
            .win32
            .set_thread_exit_code(thread_handle, 7)
            .expect("set thread exit code");
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_exit_code_thread,
            &[thread_handle, exit_code_ptr],
        );
        assert_eq!(result, 1);
        assert_eq!(
            read_u32(&memory, exit_code_ptr as u64).expect("finished exit code"),
            7
        );
        assert_eq!(runtime.last_error, 0);

        runtime
            .win32
            .close_handle(thread_handle)
            .expect("close thread handle");
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_exit_code_thread,
            &[thread_handle, exit_code_ptr],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
    })
}

#[test]
fn get_process_affinity_mask_validates_the_process_handle() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("affinity-mask");
        let mut memory = MemoryImage::default();
        let thunk = runtime.alloc_host_thunk(HostThunk::GetProcessAffinityMask);
        let affinity_ptr = 0x41_000_u32;
        let system_ptr = 0x41_008_u32;
        memory.map_bytes(affinity_ptr as u64, &[0; 16]);

        // The current-process handle reports the fixed 8-core virtual
        // topology mask (0xFF) for both the process and system mask.
        let current = runtime.win32.current_process_handle();
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[current, affinity_ptr, system_ptr],
        );
        assert_eq!(result, 1);
        assert_eq!(
            memory.read_u32(affinity_ptr as u64).expect("process mask"),
            0xFF
        );
        assert_eq!(
            memory.read_u32(system_ptr as u64).expect("system mask"),
            0xFF
        );
        assert_eq!(runtime.last_error, 0);

        // An invalid handle fails with ERROR_INVALID_HANDLE.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[0xDEAD, affinity_ptr, system_ptr],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);

        // A NULL out pointer fails with ERROR_INVALID_PARAMETER.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[current, affinity_ptr, 0],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
    })
}

#[test]
fn pumped_guest_thread_real_steam_midfunction_start_reports_fault() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "steam-boot-thread",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let steam_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("ges")
            .join("steam")
            .join("drive_c")
            .join("Steam")
            .join("Steam.exe");
        if !steam_path.exists() {
            return;
        }
        let bytes = fs::read(&steam_path).expect("read real steam exe");
        let image = crate::pe::parse_from_file(&steam_path).expect("parse steam exe");
        let image_hash = util::sha256_bytes(&bytes);
        let mapped =
            crate::pe::map_image(&bytes, &image, &image_hash, true).expect("map steam exe");
        memory.map_bytes(mapped.selected_base, &mapped.memory);
        let thread_start = mapped.selected_base + 0xdcee0;

        runtime
            .seed_process_state(
                &mut memory,
                "C:\\Steam\\Steam.exe",
                &[],
                mapped.selected_base,
                image.size_of_image as u64,
            )
            .expect("seed process state");

        let resolver = ApiSetResolver::new();
        let resolved_imports = resolve_imports_for_runtime(&image, &resolver);
        runtime
            .bind_imports(mapped.selected_base, &mut memory, &resolved_imports)
            .expect("bind imports");
        runtime.record_iat_bindings(mapped.selected_base, &mut memory, &resolved_imports);

        let create_thread = runtime.alloc_host_thunk(HostThunk::CreateThread);
        let param = runtime
            .alloc_heap(&mut memory, 0x40, true)
            .expect("alloc param block");
        let thread_handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_thread,
            &[0, 0, thread_start as u32, param as u32, 0, 0],
        );
        assert_ne!(thread_handle, 0);
        assert_eq!(runtime.pending_guest_threads.len(), 1);

        let pumped = runtime.pump_pending_guest_thread(&mut memory);
        let error = match pumped {
            Ok(_) => panic!("pumped thread should derail into a guest fault, not succeed"),
            Err(error) => error,
        };
        // The thread starts at a mid-function label (RVA 0xdcee0 = byte 0x70,
        // the trailing byte of `pushl 0x54(%eax)` at 0x4dcedf). It can never
        // run to completion, but the initial EBP frame must keep [ebp±x]
        // accesses inside the thread's own stack: the derailment must be the
        // ESI-relative fetch at 0x4dceeb/0x4dcf7c (`mov 0xcc(%esi),%eax` with
        // ESI unset → address 0xcc), not an [ebp-x] access at 0xffffffb4.
        let message = format!("{error}");
        assert!(
            message.contains("unmapped guest memory at 0xcc"),
            "unexpected derailment: {message}"
        );
        assert!(message.contains("rbp=0x7"), "EBP frame missing: {message}");
    })
}

#[test]
fn terminate_thread_forces_exit_with_code() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "terminate-thread",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        // TLS callback recording the reason code, to verify TerminateThread
        // does NOT fire DLL_THREAD_DETACH.
        let callback_address = 0x1001_0000_u64;
        let detach_flag = 0x41_300_u32;
        let mut callback_bytes = Vec::new();
        callback_bytes.extend(&[0x8B, 0x44, 0x24, 0x08]); // mov eax, [esp+8]
        callback_bytes.extend(&[0xA3]); // mov [flag], eax
        callback_bytes.extend(&detach_flag.to_le_bytes());
        callback_bytes.push(0xC3); // ret
        memory.map_bytes(callback_address, &callback_bytes);
        runtime.dll_info_table.insert(
            0x1000_0000,
            DllInfo {
                handle: 0x1000_0000,
                image_size: 0x10000,
                entry_point_rva: 0,
                load_count: 1,
                module_name: "test.dll".to_string(),
                host_path: String::new(),
                tls_callbacks: vec![callback_address - 0x1000_0000],
            },
        );
        memory.map_bytes(detach_flag as u64, &[0; 4]);

        let get_current_thread = runtime.alloc_host_thunk(HostThunk::GetCurrentThread);
        let terminate_thread = runtime.alloc_host_thunk(HostThunk::TerminateThread);
        let create_thread = runtime.alloc_host_thunk(HostThunk::CreateThread);
        let get_ct_slot = 0x41_000_u64;
        let terminate_slot = 0x41_010_u64;
        let entrypoint = 0x41_100_u64;
        let thread_id_ptr = 0x41_204_u64;
        // call [GetCurrentThread]; push eax; push 4; call [TerminateThread];
        // mov eax,9; ret 4 — the mov/ret must never execute.
        let mut entrypoint_bytes = vec![0x90; 0x30];
        entrypoint_bytes[..25].copy_from_slice(&[
            0xFF, 0x15, 0x00, 0x10, 0x04, 0x00, 0x50, 0x6A, 0x04, 0xFF, 0x15, 0x10, 0x10, 0x04,
            0x00, 0xB8, 0x09, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00, 0x90, 0x90,
        ]);
        write_u32(&mut memory, get_ct_slot, get_current_thread as u32);
        write_u32(&mut memory, terminate_slot, terminate_thread as u32);
        memory.map_bytes(entrypoint, &entrypoint_bytes);

        let thread_handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_thread,
            &[0, 0, entrypoint as u32, 0, 0, thread_id_ptr as u32],
        );
        assert_ne!(thread_handle, 0);

        // Terminate the CURRENT pumped thread: it must end with the code,
        // without DLL_THREAD_DETACH.
        assert!(
            runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump terminate-self thread")
                .did_work
        );
        assert!(runtime.pending_guest_threads.is_empty());
        assert_eq!(
            runtime
                .win32
                .get_exit_code_thread(thread_handle as u32)
                .expect("exit code after terminate-self"),
            Some(4)
        );
        assert_eq!(
            read_u32(&memory, detach_flag as u64).expect("tls flag after terminate-self"),
            DLL_THREAD_ATTACH
        );

        // Terminate a queued (never-run) thread: it must never run, and the
        // exit code is recorded.
        let terminate_target = 0x41_200_u64;
        let target_id_ptr = 0x41_214_u64;
        let mut target_bytes = vec![0x90; 0x10];
        target_bytes[..8].copy_from_slice(&[0xB8, 0x0B, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00]);
        memory.map_bytes(terminate_target, &target_bytes);
        let target_handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_thread,
            &[0, 0, terminate_target as u32, 0, 0, target_id_ptr as u32],
        );
        assert_ne!(target_handle, 0);
        assert_eq!(runtime.pending_guest_threads.len(), 1);

        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            terminate_thread,
            &[target_handle as u32, 3],
        );
        assert_eq!(result, 1); // TRUE
        assert_eq!(runtime.last_error, 0);
        assert!(
            runtime.pending_guest_threads.is_empty(),
            "terminated thread removed"
        );
        assert_eq!(
            runtime
                .win32
                .get_exit_code_thread(target_handle as u32)
                .expect("exit code after terminate"),
            Some(3)
        );
        // Nothing left to pump.
        assert!(
            !runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump after terminate")
                .did_work
        );
    })
}

#[test]
fn state_machine_controls_pump_readiness() {
    // The pump's ready predicate is driven by the state machine:
    // `Waiting` with a future wake_tick is not ready, `Exiting` is never
    // pumped, and `Waiting` with an expired wake_tick / `Runnable` is
    // ready.
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "state-machine-ready",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        let entrypoint = 0x41_100_u64;
        let mut entry_bytes = vec![0x90; 0x10];
        entry_bytes[..8].copy_from_slice(&[0xB8, 0x07, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00]);
        memory.map_bytes(entrypoint, &entry_bytes);

        // Waiting with a future wake_tick: not ready.
        let handle_a = runtime.win32.create_thread(
            crate::win32::ThreadPlan {
                exit_code: None,
                priority: 0,
                signaled: false,
            },
            false,
        );
        let mut pending = runtime
            .prepare_guest_thread_entry(&mut memory, handle_a, 0x1000, entrypoint, 0)
            .expect("prepare waiting thread");
        pending.state_machine = GuestThreadState::Waiting;
        pending.wake_tick = runtime.win32.get_tick_count64() + 100_000;
        runtime.pending_guest_threads.push_back(pending);
        assert!(
            !runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump waiting thread")
                .did_work,
            "a Waiting thread with a future wake_tick must not be pumped"
        );
        assert_eq!(runtime.pending_guest_threads.len(), 1);

        // Exiting: never pumped (mid-teardown state).
        let handle_b = runtime.win32.create_thread(
            crate::win32::ThreadPlan {
                exit_code: None,
                priority: 0,
                signaled: false,
            },
            false,
        );
        let mut pending = runtime
            .prepare_guest_thread_entry(&mut memory, handle_b, 0x1000, entrypoint, 0)
            .expect("prepare exiting thread");
        pending.state_machine = GuestThreadState::Exiting;
        runtime.pending_guest_threads.push_back(pending);
        assert!(
            !runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump exiting thread")
                .did_work,
            "an Exiting thread must never be pumped"
        );
        assert_eq!(runtime.pending_guest_threads.len(), 2);

        // Waiting with an expired wake_tick: ready and pumped to completion.
        let handle_c = runtime.win32.create_thread(
            crate::win32::ThreadPlan {
                exit_code: None,
                priority: 0,
                signaled: false,
            },
            false,
        );
        let mut pending = runtime
            .prepare_guest_thread_entry(&mut memory, handle_c, 0x1000, entrypoint, 0)
            .expect("prepare ready thread");
        pending.state_machine = GuestThreadState::Waiting;
        pending.wake_tick = runtime.win32.get_tick_count64();
        runtime.pending_guest_threads.push_back(pending);
        assert!(
            runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump ready thread")
                .did_work
        );
        assert_eq!(
            runtime
                .win32
                .get_exit_code_thread(handle_c)
                .expect("ready thread exit code"),
            Some(7)
        );
    })
}

#[test]
fn join_of_active_pumped_thread_returns_timeout_without_hang() {
    // Nested-pump indirect self-join: pumped thread B (active) dispatches
    // thread A, and A waits INFINITE on B's handle.  B is not in
    // `pending_guest_threads` (removed when its pump began) and cannot
    // reach `Exited` while dispatching A, so the wait can never make
    // progress.  On Windows this resolves via preemptive scheduling; in
    // the cooperative model we return WAIT_TIMEOUT immediately
    // (documented divergence) so the guest can retry the join.
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "active-join-timeout",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        let create_thread = runtime.alloc_host_thunk(HostThunk::CreateThread);
        let wait_for_single_object = runtime.alloc_host_thunk(HostThunk::WaitForSingleObject);
        let entrypoint = 0x41_100_u64;
        let thread_id_ptr = 0x41_204_u64;
        let mut entry_bytes = vec![0x90; 0x10];
        entry_bytes[..8].copy_from_slice(&[0xB8, 0x07, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00]);
        memory.map_bytes(entrypoint, &entry_bytes);

        let worker_handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_thread,
            &[0, 0, entrypoint as u32, 0, 0, thread_id_ptr as u32],
        );
        assert_ne!(worker_handle, 0);
        assert_eq!(runtime.pending_guest_threads.len(), 1);

        // Simulate the nested-pump cycle: the worker handle is the currently
        // ACTIVE pumped thread while the caller waits INFINITE on it.
        runtime.active_pumped_guest_thread = Some(worker_handle as u32);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wait_for_single_object,
            &[worker_handle as u32, u32::MAX],
        );
        assert_eq!(
            result,
            crate::win32::WAIT_TIMEOUT as u64,
            "joining the active pumped thread must return WAIT_TIMEOUT immediately (documented divergence)"
        );
        assert_eq!(
            runtime.pending_guest_threads.len(),
            1,
            "the target thread stays queued for a later retry"
        );

        // A zero-timeout poll is unaffected (non-blocking by definition).
        runtime.active_pumped_guest_thread = None;
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wait_for_single_object,
            &[worker_handle as u32, 0],
        );
        assert_eq!(result, crate::win32::WAIT_TIMEOUT as u64);
    })
}

#[test]
fn wait_for_single_object_on_file_handle_is_wait_failed() {
    // WaitForSingleObject(file) must NOT succeed: WAIT_FAILED
    // (0xFFFFFFFF) with ERROR_INVALID_HANDLE, not WAIT_OBJECT_0.
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "wfs-file", GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        runtime
            .win32
            .create_directory_w("C:\\logs")
            .expect("create log dir");
        let path = runtime
            .win32
            .write_file_overwrite_w("C:\\logs\\probe.txt", b"x")
            .expect("seed file");
        let file = runtime
            .win32
            .create_file_w(
                &path,
                crate::ge::FileAccess::read_only(),
                crate::ge::ShareMode::all(),
                crate::win32::CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("open file");

        let wait_thunk = runtime.alloc_host_thunk(HostThunk::WaitForSingleObject);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, wait_thunk, &[file, 0]);
        assert_eq!(result, u32::MAX as u64, "WAIT_FAILED");
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
    })
}

#[test]
fn wait_for_multiple_objects_with_file_handle_is_wait_failed() {
    // A file handle inside the array poisons the whole wait:
    // WAIT_FAILED + ERROR_INVALID_HANDLE.
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "wfm-file", GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        runtime
            .win32
            .create_directory_w("C:\\logs")
            .expect("create log dir");
        let path = runtime
            .win32
            .write_file_overwrite_w("C:\\logs\\probe2.txt", b"x")
            .expect("seed file");
        let file = runtime
            .win32
            .create_file_w(
                &path,
                crate::ge::FileAccess::read_only(),
                crate::ge::ShareMode::all(),
                crate::win32::CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("open file");
        let (event, _) = runtime.win32.create_event(true, false, false, None);
        let handles_ptr = 0x82_000_u64;
        write_u32(&mut memory, handles_ptr, file);
        write_u32(&mut memory, handles_ptr + 4, event);

        let wait_thunk = runtime.alloc_host_thunk(HostThunk::WaitForMultipleObjects);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wait_thunk,
            &[2, handles_ptr as u32, 0, 0],
        );
        assert_eq!(result, u32::MAX as u64, "WAIT_FAILED");
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
    })
}

#[test]
fn wait_for_single_object_on_socket_handle_is_wait_failed() {
    // Sockets are not waitable through WaitForSingleObject: WAIT_FAILED
    // + ERROR_INVALID_HANDLE.
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "wfs-socket", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        let socket = runtime.win32.insert_socket();
        runtime.network.wsa_startup();
        runtime
            .network
            .socket_register(u64::from(socket), crate::network::AddressFamily::Ipv4)
            .expect("register socket");

        let wait_thunk = runtime.alloc_host_thunk(HostThunk::WaitForSingleObject);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, wait_thunk, &[socket, 0]);
        assert_eq!(result, u32::MAX as u64, "WAIT_FAILED");
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);

        // CloseHandle(socket) is also ERROR_INVALID_HANDLE, and the
        // socket remains alive afterwards.
        let close_thunk = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, close_thunk, &[socket]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
        assert_eq!(
            runtime.win32.socket_id(socket).expect("socket still alive"),
            u64::from(socket)
        );

        // closesocket(file) is WSAENOTSOCK (via the win32 type check).
        runtime
            .win32
            .create_directory_w("C:\\logs")
            .expect("create log dir");
        let path = runtime
            .win32
            .write_file_overwrite_w("C:\\logs\\probe3.txt", b"x")
            .expect("seed file");
        let file = runtime
            .win32
            .create_file_w(
                &path,
                crate::ge::FileAccess::read_only(),
                crate::ge::ShareMode::all(),
                crate::win32::CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("open file");
        let close_socket_thunk = runtime.alloc_host_thunk(HostThunk::Closesocket);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, close_socket_thunk, &[file]);
        assert_eq!(result, u32::MAX as u64, "SOCKET_ERROR");
        assert_eq!(runtime.network.wsa_get_last_error(), WSAENOTSOCK);
        // The file handle is untouched.
        assert!(runtime.win32.file_type(file).is_ok());

        runtime.win32.close_socket(socket).expect("close socket");
    })
}

#[test]
fn open_thread_returns_thread_handle() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "open-thread", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let open_thread = runtime.alloc_host_thunk(HostThunk::OpenThread);
        let get_exit_code_thread = runtime.alloc_host_thunk(HostThunk::GetExitCodeThread);
        let exit_code_ptr = 0x41_000_u32;
        memory.map_bytes(exit_code_ptr as u64, &[0; 4]);

        // OpenThread on the main thread (tid 1) yields a real thread handle
        // that GetExitCodeThread can query.
        let handle = dispatch_x86_thunk(&mut runtime, &mut memory, open_thread, &[0x1F_03FF, 0, 1]);
        assert_ne!(handle, 0);
        assert_eq!(runtime.last_error, 0);
        assert!(matches!(
            runtime.win32.handle_object_type(handle as u32),
            Ok(crate::win32::ObjectType::Thread)
        ));
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_exit_code_thread,
            &[handle as u32, exit_code_ptr],
        );
        assert_eq!(result, 1);
        assert_eq!(
            read_u32(&memory, exit_code_ptr as u64).expect("main thread exit code"),
            STILL_ACTIVE
        );

        // A non-existent thread ID fails with ERROR_INVALID_PARAMETER.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_thread,
            &[0x1F_03FF, 0, 0xDEAD_BEEF],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
    })
}

#[test]
fn crt_beginthreadex_suspended_starts_on_resume() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "thread-suspended",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        let beginthreadex = runtime.alloc_host_thunk(HostThunk::Beginthreadex);
        let resume_thread = runtime.alloc_host_thunk(HostThunk::ResumeThread);
        let suspend_thread = runtime.alloc_host_thunk(HostThunk::SuspendThread);
        let entrypoint = 0x41_100_u64;
        let flag_ptr = 0x41_200_u64;
        let thread_id_ptr = 0x41_204_u64;
        // mov eax, flag_ptr; mov dword ptr [eax], 1; ret
        let mut entrypoint_bytes = vec![0x90; 0x40];
        entrypoint_bytes[..12].copy_from_slice(&[
            0xB8, 0x00, 0x12, 0x04, 0x00, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0xC3,
        ]);
        memory.map_bytes(entrypoint, &entrypoint_bytes);
        memory.map_bytes(flag_ptr, &[0_u8; 8]);

        // CREATE_SUSPENDED (0x4): queued with suspend count 1.
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            beginthreadex,
            &[
                0,
                0,
                entrypoint as u32,
                0,
                CREATE_SUSPENDED,
                thread_id_ptr as u32,
            ],
        );
        assert_ne!(handle, 0);
        assert_eq!(runtime.pending_guest_threads.len(), 1);
        assert_eq!(runtime.pending_guest_threads[0].suspended, 1);

        // Pump: the suspended thread must NOT run.
        assert!(
            !runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump while suspended")
                .did_work
        );
        assert_eq!(read_u32(&memory, flag_ptr).expect("flag"), 0);
        assert_eq!(runtime.pending_guest_threads.len(), 1);

        // SuspendThread again → previous count 1, count now 2.
        let prev = dispatch_x86_thunk(&mut runtime, &mut memory, suspend_thread, &[handle as u32]);
        assert_eq!(prev, 1);
        assert_eq!(runtime.pending_guest_threads[0].suspended, 2);
        assert!(
            !runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump while double-suspended")
                .did_work
        );

        // One resume → still suspended (counted semantics).
        let prev = dispatch_x86_thunk(&mut runtime, &mut memory, resume_thread, &[handle as u32]);
        assert_eq!(prev, 2);
        assert_eq!(runtime.pending_guest_threads[0].suspended, 1);
        assert!(
            !runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump after one resume")
                .did_work
        );

        // Final resume → thread runs to completion.
        let prev = dispatch_x86_thunk(&mut runtime, &mut memory, resume_thread, &[handle as u32]);
        assert_eq!(prev, 1);
        assert_eq!(runtime.pending_guest_threads[0].suspended, 0);
        assert!(
            runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump after final resume")
                .did_work
        );
        assert_eq!(read_u32(&memory, flag_ptr).expect("flag"), 1);
        assert!(runtime.pending_guest_threads.is_empty());
    })
}

#[test]
fn wfso_infinite_reports_signal_set_by_pumped_worker() {
    // WfSO(INFINITE) on an auto-reset event: a pumped worker sets the
    // event DURING the wait; the scheduler must resume the waiter with
    // WAIT_OBJECT_0 and the signal must be consumed.
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "wfso-infinite-signal",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        let (event_handle, _created) = runtime.win32.create_event(false, false, false, None);
        assert!(
            !runtime
                .win32
                .wait_for_single_object(event_handle, 0, false, None)
                .expect("initial poll")
                .eq(&crate::win32::WaitStatus::Object0),
            "auto-reset event starts unsignaled"
        );

        let set_event = runtime.alloc_host_thunk(HostThunk::SetEvent);
        let wait_for_single_object = runtime.alloc_host_thunk(HostThunk::WaitForSingleObject);
        let create_thread = runtime.alloc_host_thunk(HostThunk::CreateThread);
        let set_slot = 0x41_000_u64;
        let wfso_slot = 0x41_010_u64;
        let worker_entry = 0x41_100_u64;
        let waiter_entry = 0x41_200_u64;
        let result_ptr = 0x41_300_u64;
        let worker_tid_ptr = 0x41_304_u64;
        let waiter_tid_ptr = 0x41_308_u64;
        write_u32(&mut memory, set_slot, set_event as u32);
        memory.map_bytes(result_ptr, &[0_u8; 4]);

        // Worker: push event_handle; call [slot]; mov eax, 1; ret 4 —
        // sets the event and exits.
        let mut worker_bytes = vec![0x90; 0x20];
        worker_bytes[0] = 0x68; // push imm32
        worker_bytes[1..5].copy_from_slice(&event_handle.to_le_bytes());
        worker_bytes[5..11].copy_from_slice(&[0xFF, 0x15, 0x00, 0x10, 0x04, 0x00]);
        worker_bytes[11..16].copy_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
        worker_bytes[16..19].copy_from_slice(&[0xC2, 0x04, 0x00]);
        memory.map_bytes(worker_entry, &worker_bytes);

        // Waiter: push INFINITE; push event_handle; call [WfSO];
        // mov [result], eax; ret
        let mut waiter_bytes = vec![0x90; 0x20];
        waiter_bytes[..22].copy_from_slice(&[
            0x68, 0xFF, 0xFF, 0xFF, 0xFF, // push INFINITE
            0x68, 0x00, 0x00, 0x00, 0x00, // push event_handle (patched)
            0xFF, 0x15, 0x10, 0x10, 0x04, 0x00, // call [WfSO]
            0xA3, 0x00, 0x23, 0x04, 0x00, // mov [result], eax
            0xC3,
        ]);
        waiter_bytes[6..10].copy_from_slice(&event_handle.to_le_bytes());
        write_u32(&mut memory, wfso_slot, wait_for_single_object as u32);
        memory.map_bytes(waiter_entry, &waiter_bytes);
        // The waiter's `mov [0x42300], eax` stores the wait result into
        // guest memory; the destination must be loader-mapped (guest CPU
        // stores never materialize pages).
        memory.map_zeroed_if_unmapped(0x42_300, 4);

        let worker_handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_thread,
            &[0, 0, worker_entry as u32, 0, 0, worker_tid_ptr as u32],
        );
        assert_ne!(worker_handle, 0);
        let waiter_handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_thread,
            &[0, 0, waiter_entry as u32, 0, 0, waiter_tid_ptr as u32],
        );
        assert_ne!(waiter_handle, 0);

        for _ in 0..500 {
            let _outcome = runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump pending thread");
            if runtime.pending_guest_threads.is_empty() {
                break;
            }
        }
        assert!(
            runtime.pending_guest_threads.is_empty(),
            "both threads must complete"
        );
        assert_eq!(
            read_u32(&memory, result_ptr).expect("wait result"),
            crate::win32::WAIT_OBJECT_0,
            "pump-phase signal must be reported as WAIT_OBJECT_0"
        );
        // The signal was consumed by the wait (auto-reset).
        assert!(
            !runtime
                .win32
                .wait_for_single_object(event_handle, 0, false, None)
                .expect("post-wait poll")
                .eq(&crate::win32::WaitStatus::Object0),
            "auto-reset signal must be consumed"
        );
    })
}

#[test]
fn nt_test_alert_returns_user_apc_only_when_delivered() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("nt-test-alert");
        let mut memory = MemoryImage::default();
        let test_alert = runtime.alloc_host_thunk(HostThunk::NtTestAlert);
        let queue_apc = runtime.alloc_host_thunk(HostThunk::QueueUserAPC);
        let apc_callback = 0x43_000_u64;
        let apc_flag = 0x43_100_u64;
        // mov eax, 0xABCD; mov [apc_flag], eax; ret
        memory.map_bytes(
            apc_callback,
            &[
                0xB8, 0xCD, 0xAB, 0x00, 0x00, 0xA3, 0x00, 0x31, 0x04, 0x00, 0xC3,
            ],
        );
        memory.map_bytes(apc_flag, &[0u8; 4]);

        // Empty queue: STATUS_SUCCESS.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, test_alert, &[]),
            0
        );

        let thread_handle = runtime.win32.current_thread_handle();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                queue_apc,
                &[apc_callback as u32, thread_handle, 0],
            ),
            1
        );
        // A queued APC is delivered immediately: STATUS_USER_APC.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, test_alert, &[]),
            u64::from(crate::win32::STATUS_USER_APC),
            "NtTestAlert reports STATUS_USER_APC when it delivered"
        );
        assert_eq!(memory.read_u32(apc_flag).unwrap(), 0xABCD, "APC ran");
        // Queue drained: the next call reports STATUS_SUCCESS.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, test_alert, &[]),
            0,
            "NtTestAlert reports STATUS_SUCCESS with an empty queue"
        );

        // The ntdll import maps to the host thunk.
        let import = ResolvedImport {
            requested_module: "ntdll.dll".to_string(),
            resolved_module: "ntdll.dll".to_string(),
            symbol: ImportSymbol::ByName {
                hint: 0,
                name: "NtTestAlert".to_string(),
            },
            iat_rva: 0x4000,
            export: ExportSymbol {
                ordinal: 0,
                name: Some("NtTestAlert".to_string()),
                target: ExportTarget::Rva(0x5000),
            },
        };
        assert!(matches!(
            HostThunk::from_import(&import),
            HostThunk::NtTestAlert
        ));
    })
}

#[test]
fn evidence_core_loader_and_process_info_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-loader");
        let mut memory = MemoryImage::default();
        runtime.command_line = "evidence.exe -flag".to_string();
        let load_a = runtime.alloc_host_thunk(HostThunk::LoadLibraryA);
        let load_w = runtime.alloc_host_thunk(HostThunk::LoadLibraryW);
        let load_ex_a = runtime.alloc_host_thunk(HostThunk::LoadLibraryExA);
        let load_ex_w = runtime.alloc_host_thunk(HostThunk::LoadLibraryExW);
        let handle_ex_a = runtime.alloc_host_thunk(HostThunk::GetModuleHandleExA);
        let handle_ex_w = runtime.alloc_host_thunk(HostThunk::GetModuleHandleExW);
        let startup_info = runtime.alloc_host_thunk(HostThunk::GetStartupInfoW);
        let std_handle = runtime.alloc_host_thunk(HostThunk::GetStdHandle);
        let command_line_a = runtime.alloc_host_thunk(HostThunk::GetCommandLineA);
        let command_line_w = runtime.alloc_host_thunk(HostThunk::GetCommandLineW);
        let free_env = runtime.alloc_host_thunk(HostThunk::FreeEnvironmentStringsW);

        // LoadLibrary resolves the synthetic module surface and returns a
        // real module handle.  The module is pre-registered (the same
        // get_or_create_module_handle machinery the dispatch uses) so the
        // dispatch's name resolution short-circuits on the module table.
        let user32_a = runtime
            .alloc_c_string(&mut memory, "user32.dll")
            .expect("ansi name");
        let user32_w = runtime
            .alloc_utf16_string(&mut memory, "user32.dll")
            .expect("wide name");
        let kernel32_w = runtime
            .alloc_utf16_string(&mut memory, "kernel32.dll")
            .expect("wide name");
        let user32_handle = runtime.get_or_create_module_handle("user32.dll");
        let kernel32_handle = runtime.get_or_create_module_handle("kernel32.dll");
        runtime.ensure_synthetic_module_image(&mut memory, user32_handle);
        runtime.ensure_synthetic_module_image(&mut memory, kernel32_handle);

        let handle = dispatch_x86_thunk(&mut runtime, &mut memory, load_a, &[user32_a as u32]);
        assert_eq!(handle, user32_handle);
        assert_eq!(runtime.last_error, 0);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, load_w, &[user32_w as u32]),
            user32_handle
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                load_ex_a,
                &[user32_a as u32, 0, 0]
            ),
            user32_handle
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                load_ex_w,
                &[user32_w as u32, 0, 0]
            ),
            user32_handle
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, load_w, &[kernel32_w as u32]),
            kernel32_handle
        );

        // GetModuleHandleExA/W resolve an api-set name (the api-ms-*
        // short-circuit never consults the full export table) into a real
        // module handle; unsupported flag bits are rejected with
        // ERROR_INVALID_PARAMETER.
        let api_set_w = runtime
            .alloc_utf16_string(&mut memory, "api-ms-win-core-filesystem-l1-1-0.dll")
            .expect("wide name");
        let api_set_a = runtime
            .alloc_c_string(&mut memory, "api-ms-win-core-filesystem-l1-1-0.dll")
            .expect("ansi name");
        let module_handle_ptr = 0x41_000;
        memory.map_bytes(module_handle_ptr as u64, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                handle_ex_a,
                &[0, api_set_a as u32, module_handle_ptr as u32]
            ),
            1
        );
        assert_ne!(memory.read_u32(module_handle_ptr as u64).unwrap(), 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                handle_ex_w,
                &[0, api_set_w as u32, module_handle_ptr as u32]
            ),
            1
        );
        assert_ne!(memory.read_u32(module_handle_ptr as u64).unwrap(), 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                handle_ex_w,
                &[0x8000_0000, api_set_w as u32, module_handle_ptr as u32]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        // FROM_ADDRESS with an unknown address fails with ERROR_MOD_NOT_FOUND.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                handle_ex_w,
                &[
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    0x1234_5678,
                    module_handle_ptr as u32
                ]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_MOD_NOT_FOUND);

        // GetStartupInfoW zero-fills the x86 STARTUPINFO with cbSize first.
        let startup_ptr = 0x41_100;
        memory.map_bytes(startup_ptr as u64, &[0xFF; 68]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                startup_info,
                &[startup_ptr as u32]
            ),
            0
        );
        assert_eq!(memory.read_u32(startup_ptr as u64).unwrap(), 68);

        // GetStdHandle maps the standard handles through.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, std_handle, &[STD_OUTPUT_HANDLE]),
            STD_OUTPUT_HANDLE as u64
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, std_handle, &[0xBAD]),
            u32::MAX as u64
        );

        // GetCommandLineA/W return the runtime's command line.
        let cl_a = dispatch_x86_thunk(&mut runtime, &mut memory, command_line_a, &[]);
        assert_ne!(cl_a, 0);
        assert_eq!(read_c_string(&memory, cl_a).unwrap(), "evidence.exe -flag");
        let cl_w = dispatch_x86_thunk(&mut runtime, &mut memory, command_line_w, &[]);
        assert_ne!(cl_w, 0);
        assert_eq!(
            read_utf16_string(&memory, cl_w).unwrap(),
            "evidence.exe -flag"
        );

        // FreeEnvironmentStringsW releases an environment block handle.
        let env_block = runtime
            .alloc_utf16_environment_block(&mut memory, &runtime.process_environment.clone())
            .expect("env block");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, free_env, &[env_block as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, free_env, &[0]),
            1
        );
    })
}

#[test]
fn evidence_core_kernel32_disable_thread_library_calls_thunk() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "evidence-disable-tlc",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let disable = runtime.alloc_host_thunk(HostThunk::DisableThreadLibraryCalls);
        let handle_a = runtime.get_or_create_module_handle("first.dll");
        let handle_b = runtime.get_or_create_module_handle("second.dll");
        assert_ne!(handle_a, 0);
        assert_ne!(handle_b, 0);
        if let Some(info) = runtime.dll_info_table.get_mut(&handle_a) {
            info.entry_point_rva = 0x1000;
        }
        if let Some(info) = runtime.dll_info_table.get_mut(&handle_b) {
            info.entry_point_rva = 0x2000;
        }

        // DisableThreadLibraryCalls marks the module (by handle).
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, disable, &[handle_b as u32]),
            1
        );

        // Thread attach/detach notifications skip the marked module but
        // still reach the other DLLs.
        runtime.call_dll_entry_points(&[handle_a, handle_b], DllReason::ThreadAttach);
        assert_eq!(runtime.pending_dll_main_calls.len(), 1);
        assert_eq!(runtime.pending_dll_main_calls[0].0, handle_a);
        assert_eq!(runtime.pending_dll_main_calls[0].2, DLL_THREAD_ATTACH);
        runtime.pending_dll_main_calls.clear();

        // Process-level notifications are unaffected by the flag.
        runtime.call_dll_entry_points(&[handle_a, handle_b], DllReason::ProcessAttach);
        assert_eq!(runtime.pending_dll_main_calls.len(), 2);

        // hModule == 0 marks the CALLING module (resolved from the return
        // address that dispatch popped).
        let mapped = runtime.mapped_image_base;
        let disable_stack = 0x50_000;
        memory.map_bytes(disable_stack, &[0_u8; 0x200]);
        write_u32(&mut memory, disable_stack, mapped as u32);
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, disable_stack);
        runtime
            .dispatch_import(disable, &mut state, &mut memory)
            .expect("dispatch disable");
        assert_eq!(state.get(Register::Rax), 1);
        assert!(
            runtime
                .disabled_thread_library_calls
                .contains(&runtime.module_handle_containing(mapped)),
            "NULL handle marks the calling module"
        );
    })
}

#[test]
fn evidence_core_nt_thread_and_process_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-nt-thread");
        let mut memory = MemoryImage::default();
        let create_thread = runtime.alloc_host_thunk(HostThunk::NtCreateThreadEx);
        let get_context = runtime.alloc_host_thunk(HostThunk::NtGetContextThread);
        let set_context = runtime.alloc_host_thunk(HostThunk::NtSetContextThread);
        let terminate_process = runtime.alloc_host_thunk(HostThunk::NtTerminateProcess);
        let terminate_thread = runtime.alloc_host_thunk(HostThunk::NtTerminateThread);

        // NtCreateThreadEx mints a real thread handle.
        let handle_ptr = 0x41_000;
        memory.map_bytes(handle_ptr as u64, &[0; 4]);
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_thread,
            &[
                handle_ptr as u32,
                0x1F03FF,
                0,
                0,
                0x40_000,
                0,
                0,
                0,
                0,
                0x1000,
            ],
        );
        assert_eq!(status, 0, "STATUS_SUCCESS");
        let thread_handle = memory.read_u32(handle_ptr as u64).unwrap();
        assert_ne!(thread_handle, 0);
        assert_ne!(thread_handle, u32::MAX);

        // NtGetContextThread captures the live CONTEXT: the current-thread
        // path snapshots the dispatch state, so the EAX the thunk observed
        // round-trips into the guest CONTEXT.
        let ctx = 0x41_100;
        let mut ctx_bytes = vec![0_u8; 0x300];
        ctx_bytes[0..4].copy_from_slice(&0x10007_u32.to_le_bytes());
        memory.map_bytes(ctx as u64, &ctx_bytes);
        let current_thread_handle = runtime.win32.current_thread_handle();
        let mut state = evidence_x86_state(&mut memory, &[current_thread_handle, ctx as u32]);
        state.gpr[0] = 0xDEAD_BEEF;
        runtime
            .dispatch_import(get_context, &mut state, &mut memory)
            .expect("nt get context");
        assert_eq!(state.get(Register::Rax), 0, "STATUS_SUCCESS");
        assert_eq!(
            memory
                .read_u32(ctx as u64 + crate::ntdll::thread::X86_CONTEXT_EAX_OFFSET)
                .unwrap(),
            0xDEAD_BEEF
        );
        // A NULL context pointer is STATUS_INVALID_PARAMETER.
        let mut null_state = evidence_x86_state(&mut memory, &[current_thread_handle, 0]);
        runtime
            .dispatch_import(get_context, &mut null_state, &mut memory)
            .expect("nt get context null");
        assert_eq!(null_state.get(Register::Rax), 0xC000_000D);

        // NtSetContextThread applies the CONTEXT to the current thread:
        // the guest-provided register values become live in the dispatch
        // state (EDX is caller-saved, so it survives the status write to
        // RAX).
        memory.write_u32(
            ctx as u64 + crate::ntdll::thread::X86_CONTEXT_EDX_OFFSET,
            0x2222,
        );
        let mut state = evidence_x86_state(&mut memory, &[current_thread_handle, ctx as u32]);
        runtime
            .dispatch_import(set_context, &mut state, &mut memory)
            .expect("nt set context");
        assert_eq!(state.get(Register::Rax), 0, "STATUS_SUCCESS");
        assert_eq!(state.gpr[2], 0x2222, "the applied context is live");
        // NtSetContextThread on an unknown handle is STATUS_INVALID_HANDLE.
        let mut state2 = evidence_x86_state(&mut memory, &[0xBAD, ctx as u32]);
        runtime
            .dispatch_import(set_context, &mut state2, &mut memory)
            .expect("nt set context bad handle");
        assert_eq!(state2.get(Register::Rax), 0xC000_0008);

        // NtTerminateProcess on the current process requests the exit code.
        let mut state = evidence_x86_state(&mut memory, &[u32::MAX, 42]);
        let result = runtime
            .dispatch_import(terminate_process, &mut state, &mut memory)
            .expect("nt terminate process");
        assert_eq!(result, Some(42));
        assert_eq!(runtime.process_exit_requested, Some(42));

        // NtTerminateThread on the current thread requests the exit.
        let mut state = evidence_x86_state(&mut memory, &[u32::MAX, 5]);
        let result = runtime
            .dispatch_import(terminate_thread, &mut state, &mut memory)
            .expect("nt terminate thread");
        assert_eq!(result, Some(5));
    })
}

// -----------------------------------------------------------------------
// Evidence tail-final: the last implemented-without-evidence exports
// (kernel32 SetThreadPriority, kernelbase GetFileInformationByHandle,
// urlmon bind-ctx/moniker/status-callback, xinput export surface,
// d3d9 factory creation, dinput8 creation, dxgi factory2 creation).
// -----------------------------------------------------------------------
#[test]
fn set_thread_priority_applies_the_priority_domain_and_roundtrips() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("thread-priority");
        let mut memory = MemoryImage::default();
        let set = runtime.alloc_host_thunk(HostThunk::SetThreadPriority);
        let get = runtime.alloc_host_thunk(HostThunk::GetThreadPriority);
        let handle = runtime.win32.current_thread_handle();

        // A valid thread handle: SetThreadPriority succeeds and the value
        // round-trips through GetThreadPriority (the SAME storage the Nt
        // SetInformationThread(ThreadPriority) surface queries).
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, set, &[handle, 2]);
        assert_eq!(result, 1);
        assert_eq!(runtime.last_error, 0);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, get, &[handle]);
        assert_eq!(result, 2, "priority must round-trip through the domain");

        // A NULL handle fails with ERROR_INVALID_HANDLE.
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, set, &[0, 2]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);

        // An unknown handle fails with ERROR_INVALID_HANDLE.
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, set, &[0xDEAD, 2]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
    })
}

#[test]
fn evidence_ui_gdi_psapi_guest_process_thunks() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "ui-gdi-psapi", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        runtime.main_module_path = "C:\\game\\app.exe".to_string();
        runtime.main_module_name = "app.exe".to_string();

        // EnumProcesses: the GUEST process list (the guest pid, never
        // the host pid), with the Windows size contract.
        let ids_ptr = 0x61_000;
        memory.map_bytes(ids_ptr, &[0; 64]);
        let needed_ptr = 0x61_100;
        memory.map_bytes(needed_ptr, &[0; 4]);
        let enum_processes = runtime.alloc_host_thunk(HostThunk::EnumProcesses);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_processes,
                &[ids_ptr as u32, 64, needed_ptr as u32]
            ),
            1,
            "EnumProcesses succeeds"
        );
        let count = read_u32(&memory, needed_ptr).expect("bytes needed") / 4;
        assert!(count >= 1, "at least the guest process is enumerated");
        let guest_pid = runtime.win32.current_process_id();
        let ids = (0..count)
            .map(|index| read_u32(&memory, ids_ptr + index as u64 * 4).expect("pid"))
            .collect::<Vec<_>>();
        assert!(
            ids.contains(&guest_pid),
            "the guest pid is in the enumeration (never the host pid)"
        );
        assert!(
            !ids.contains(&std::process::id()),
            "the host pid must never leak into EnumProcesses"
        );

        // GetModuleBaseNameW: resolves the module base name as UTF-16.
        let base_buffer = 0x61_200;
        memory.map_bytes(base_buffer, &[0; 64]);
        let base_name = runtime.alloc_host_thunk(HostThunk::GetModuleBaseNameW);
        let process_handle = u64::from(runtime.win32.current_process_handle());
        let image_base = runtime.mapped_image_base;
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            base_name,
            &[
                process_handle as u32,
                image_base as u32,
                base_buffer as u32,
                32,
            ],
        );
        assert_eq!(written, 7, "GetModuleBaseNameW returns the char count");
        let name = read_utf16_string(&memory, base_buffer).expect("base name");
        assert_eq!(name, "app.exe");

        // GetModuleFileNameExW: the full module path.
        let path_buffer = 0x61_300;
        memory.map_bytes(path_buffer, &[0; 128]);
        let module_file_name = runtime.alloc_host_thunk(HostThunk::GetModuleFileNameExW);
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            module_file_name,
            &[
                process_handle as u32,
                image_base as u32,
                path_buffer as u32,
                64,
            ],
        );
        assert_eq!(written, 15, "GetModuleFileNameExW returns the char count");
        let path = read_utf16_string(&memory, path_buffer).expect("path");
        assert_eq!(path, "C:\\game\\app.exe");

        // GetProcessMemoryInfo: PROCESS_MEMORY_COUNTERS from the guest
        // address space (committed pages + live heap).
        let heap_ptr = runtime.alloc_heap(&mut memory, 256, true).expect("heap");
        assert_ne!(heap_ptr, 0);
        memory.map_bytes(0x70_000, &[0_u8; 0x1000]);
        let counters = 0x61_400;
        memory.map_bytes(counters, &[0; 72]);
        let memory_info = runtime.alloc_host_thunk(HostThunk::GetProcessMemoryInfo);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                memory_info,
                &[process_handle as u32, counters as u32, 72]
            ),
            1,
            "GetProcessMemoryInfo succeeds"
        );
        assert_eq!(read_u32(&memory, counters).expect("cb"), 72);
        let working_set =
            read_guest_pointer(&memory, counters + 16, GuestArch::X86).expect("working set");
        assert!(
            working_set >= 0x1000,
            "WorkingSetSize reflects the committed guest pages"
        );
        let pagefile =
            read_guest_pointer(&memory, counters + 56, GuestArch::X86).expect("pagefile usage");
        assert_eq!(pagefile, working_set);
        // Small buffer: fails honestly with ERROR_INVALID_PARAMETER.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                memory_info,
                &[process_handle as u32, counters as u32, 8]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
    })
}

#[test]
fn nt_create_process_creates_real_native_child() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("nt-create-process");
        runtime.main_module_path = "C:\\Games\\NativeDemo\\native.exe".to_string();
        let mut memory = MemoryImage::default();
        let nt_create_process = runtime.alloc_host_thunk(HostThunk::NtCreateProcess);
        let handle_out = 0x41_000_u64;

        // NtCreateProcess(&handle, PROCESS_ALL_ACCESS, NULL, NULL
        // parent, FALSE, NULL section, NULL, NULL).
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_process,
            &[handle_out as u32, 0x1F1FFF, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(status, 0, "STATUS_SUCCESS");
        let child = read_guest_pointer(&memory, handle_out, GuestArch::X86).unwrap() as u32;
        assert_ne!(child, 0, "a real process handle must be returned");
        let state = runtime
            .win32
            .process_state(child)
            .expect("child process record exists");
        assert_eq!(
            state.executable, "C:\\Games\\NativeDemo\\native.exe",
            "the child is born from the parent's image"
        );
        assert_ne!(state.process_id, runtime.win32.current_process_id());
        assert_eq!(state.exit_code, None, "the child is running");

        // Termination works through the runtime's standard process path.
        runtime
            .win32
            .terminate_process(child, 5)
            .expect("terminate child");
        assert_eq!(
            runtime
                .win32
                .get_exit_code_process(child)
                .expect("exit code"),
            Some(5),
            "termination must set the child's exit code"
        );

        // ── native threads: NtCreateThreadEx lifts the record-only child
        //    (the old documented limitation) ──
        // The child record still carries no primary thread, but a real
        // thread object can now be created on it: real client id, real
        // process-targeted record, full lifecycle semantics.
        let nt_create_thread = runtime.alloc_host_thunk(HostThunk::NtCreateThreadEx);
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_process,
            &[handle_out as u32, 0x1F1FFF, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(status, 0, "STATUS_SUCCESS");
        let child2 = read_guest_pointer(&memory, handle_out, GuestArch::X86).unwrap() as u32;
        assert_ne!(child2, 0);
        let child2_state = runtime
            .win32
            .process_state(child2)
            .expect("second child record");
        assert_ne!(child2_state.process_id, state.process_id);

        let thread_handle_ptr = 0x42_000_u64;
        // NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, child,
        // start, param, create_suspended=FALSE, 0, 0, stack_reserve).
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_thread,
            &[
                thread_handle_ptr as u32,
                0x1F03FF,
                0,
                child2,
                0x40_200,
                0x1234,
                0,
                0,
                0,
                0x1000,
            ],
        );
        assert_eq!(status, 0, "STATUS_SUCCESS");
        assert_eq!(runtime.last_error, 0);
        let thread_handle =
            read_guest_pointer(&memory, thread_handle_ptr, GuestArch::X86).unwrap() as u32;
        assert_ne!(thread_handle, 0, "a real thread handle must be returned");
        let thread_id = runtime
            .win32
            .thread_id_for_handle(thread_handle)
            .expect("thread record exists in the runtime thread tables");
        assert_ne!(thread_id, runtime.win32.current_thread_id());
        assert_eq!(
            runtime.win32.get_exit_code_thread(thread_handle).unwrap(),
            None,
            "the new thread is running"
        );

        // The host image does not exist on this host (the test image is a
        // guest path only), so the host run cannot start and the start
        // routine is scheduled through the runtime's guest thread
        // scheduler as the bare-entry fallback.
        let scheduled = runtime
            .pending_guest_threads
            .iter()
            .find(|thread| thread.handle == thread_handle)
            .expect("the native child thread is scheduled in the runtime");
        assert_eq!(scheduled.start_address, 0x40_200);
        assert_eq!(scheduled.parameter, 0x1234);
        assert_ne!(scheduled.initial_rsp, 0, "a real guest stack is allocated");
        assert_ne!(scheduled.teb_base, 0, "a real guest TEB is allocated");

        // Lifecycle: suspend / resume / terminate all operate on the real
        // thread object and its client id.
        assert_eq!(runtime.win32.thread_suspend_count(thread_id).unwrap(), 0);
        assert_eq!(runtime.win32.suspend_thread(thread_handle).unwrap(), 0);
        assert_eq!(runtime.win32.thread_suspend_count(thread_id).unwrap(), 1);
        assert_eq!(runtime.win32.resume_thread(thread_handle).unwrap(), 1);
        assert_eq!(runtime.win32.thread_suspend_count(thread_id).unwrap(), 0);
        runtime
            .win32
            .terminate_thread(thread_handle, 7)
            .expect("terminate native child thread");
        assert_eq!(
            runtime.win32.get_exit_code_thread(thread_handle).unwrap(),
            Some(7)
        );

        // ── thread-creation failure paths return real NTSTATUSes ──
        // Invalid process handle → STATUS_INVALID_HANDLE.
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_thread,
            &[
                thread_handle_ptr as u32,
                0x1F03FF,
                0,
                0xDEAD,
                0x40_200,
                0,
                0,
                0,
                0,
                0x1000,
            ],
        );
        assert_eq!(status, 0xC000_0008);
        assert_eq!(runtime.last_error, 0xC000_0008);
        // NULL start routine → STATUS_INVALID_PARAMETER.
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_thread,
            &[
                thread_handle_ptr as u32,
                0x1F03FF,
                0,
                child2,
                0,
                0,
                0,
                0,
                0,
                0x1000,
            ],
        );
        assert_eq!(status, 0xC000_000D);
        // A live handle of the wrong object type → STATUS_OBJECT_TYPE_MISMATCH.
        let (event_handle, _) = runtime.win32.create_event(false, false, false, None);
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_thread,
            &[
                thread_handle_ptr as u32,
                0x1F03FF,
                0,
                event_handle,
                0x40_200,
                0,
                0,
                0,
                0,
                0x1000,
            ],
        );
        assert_eq!(status, 0xC000_0024);
        // A restricted process handle without PROCESS_CREATE_THREAD →
        // STATUS_ACCESS_DENIED.
        let restricted = runtime
            .win32
            .open_process(0x1000, false, child2_state.process_id)
            .expect("open restricted process handle");
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_thread,
            &[
                thread_handle_ptr as u32,
                0x1F03FF,
                0,
                restricted,
                0x40_200,
                0,
                0,
                0,
                0,
                0x1000,
            ],
        );
        assert_eq!(status, 0xC000_0022);
        // A terminated process → STATUS_PROCESS_IS_TERMINATING.
        runtime
            .win32
            .terminate_process(child2, 3)
            .expect("terminate second child");
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_thread,
            &[
                thread_handle_ptr as u32,
                0x1F03FF,
                0,
                child2,
                0x40_200,
                0,
                0,
                0,
                0,
                0x1000,
            ],
        );
        assert_eq!(status, 0xC000_010A);

        // ── failure paths return real NTSTATUSes ──
        // Null process-handle pointer → STATUS_INVALID_PARAMETER.
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_process,
            &[0, 0x1F1FFF, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(status, 0xC000_000D);
        // Invalid parent handle → STATUS_INVALID_CID.
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_process,
            &[handle_out as u32, 0x1F1FFF, 0, 0xDEAD, 0, 0, 0, 0],
        );
        assert_eq!(status, 0xC000_000B);
        assert_eq!(runtime.last_error, 0xC000_000B);
        // Garbage section handle → STATUS_INVALID_HANDLE.
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_process,
            &[handle_out as u32, 0x1F1FFF, 0, 0, 0, 0xDEAD, 0, 0],
        );
        assert_eq!(status, 0xC000_0008);
        // A live-but-data section → STATUS_INVALID_IMAGE_FORMAT (the
        // section is not an executable image).
        let section = runtime
            .win32
            .create_section(
                0x1000,
                crate::win32::MemoryProtection {
                    read: true,
                    write: true,
                    execute: false,
                },
                false,
            )
            .expect("create section");
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_process,
            &[handle_out as u32, 0x1F1FFF, 0, 0, 0, section, 0, 0],
        );
        assert_eq!(status, 0xC000_007B);
        // A debug port is not modelable → STATUS_INVALID_PARAMETER.
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_process,
            &[handle_out as u32, 0x1F1FFF, 0, 0, 0, 0, 0x1234, 0],
        );
        assert_eq!(status, 0xC000_000D);
    })
}

#[cfg(unix)]
#[test]
fn nt_create_thread_ex_spawns_the_native_child_for_real() {
    with_big_stack(|| {
        use std::os::unix::fs::PermissionsExt;

        let (mut runtime, temp) = test_runtime("nt-native-child-spawn");
        let image = "C:\\Games\\NativeDemo\\native-child.sh";
        runtime.main_module_path = image.to_string();
        let mut memory = MemoryImage::default();
        let nt_create_process = runtime.alloc_host_thunk(HostThunk::NtCreateProcess);
        let nt_create_thread = runtime.alloc_host_thunk(HostThunk::NtCreateThreadEx);
        let handle_out = 0x41_000_u64;

        // Stage the guest image as a real host executable: a tiny shell
        // script that records its own execution and exits 0.
        let host_program = runtime
            .win32
            .guest_path_to_host_path(image)
            .expect("resolve guest image");
        std::fs::create_dir_all(host_program.parent().expect("image parent"))
            .expect("create image dirs");
        let marker = temp.path().join("native-child-ran.txt");
        std::fs::write(
            &host_program,
            format!("#!/bin/sh\necho ran > '{}'\nexit 0\n", marker.display()),
        )
        .expect("write child image");
        let mut permissions = std::fs::metadata(&host_program)
            .expect("child image metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&host_program, permissions).expect("make child executable");

        // NtCreateProcess(&handle, PROCESS_ALL_ACCESS, NULL, NULL parent,
        // FALSE, NULL section, NULL, NULL).
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_process,
            &[handle_out as u32, 0x1F1FFF, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(status, 0, "STATUS_SUCCESS");
        let child = read_guest_pointer(&memory, handle_out, GuestArch::X86).unwrap() as u32;
        assert!(!marker.exists(), "a record-only child runs nothing yet");

        let thread_handle_ptr = 0x42_000_u64;
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            nt_create_thread,
            &[
                thread_handle_ptr as u32,
                0x1F03FF,
                0,
                child,
                0x40_200,
                0,
                0,
                0,
                0,
                0x1000,
            ],
        );
        assert_eq!(status, 0, "STATUS_SUCCESS");
        let thread_handle =
            read_guest_pointer(&memory, thread_handle_ptr, GuestArch::X86).unwrap() as u32;
        assert!(runtime.win32.thread_id_for_handle(thread_handle).is_ok());

        // The real child exits and signals the NtCreateProcess handle
        // through its exit-sync pair (instead of waiting forever) …
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut signaled = false;
        while std::time::Instant::now() < deadline {
            if let Ok(crate::win32::WaitStatus::Object0) =
                runtime.win32.wait_for_single_object(child, 50, false, None)
            {
                signaled = true;
                break;
            }
        }
        assert!(
            signaled,
            "the spawned child must exit and signal the process handle"
        );
        // … and the image genuinely ran on the host.
        assert_eq!(
            std::fs::read_to_string(&marker).expect("child ran marker"),
            "ran\n"
        );

        // The host-launched thread did not double-run in this runtime:
        // its real TEB/stack record lives in the native-child thread table
        // instead of the pending scheduler queue.
        assert!(
            !runtime
                .pending_guest_threads
                .iter()
                .any(|thread| thread.handle == thread_handle),
            "a host-launched child thread must not also run in this runtime"
        );
    })
}

#[cfg(unix)]
#[test]
fn nt_create_thread_ex_create_suspended_defers_host_launch() {
    with_big_stack(|| {
        let (mut runtime, temp) = test_runtime("nt-create-suspended");
        let image = "C:\\Games\\NativeDemo\\suspended-child.sh";
        runtime.main_module_path = image.to_string();
        let marker = temp.path().join("deferred-child-ran.txt");
        stage_guest_script(
            &runtime,
            image,
            &format!("#!/bin/sh\necho ran > '{}'\nexit 0\n", marker.display()),
        );
        let never_image = "C:\\Games\\NativeDemo\\terminated-child.sh";
        let never = temp.path().join("suspended-terminated-ran.txt");
        stage_guest_script(
            &runtime,
            never_image,
            &format!("#!/bin/sh\necho ran > '{}'\nexit 0\n", never.display()),
        );

        let mut memory = MemoryImage::default();
        let nt_create_process = runtime.alloc_host_thunk(HostThunk::NtCreateProcess);
        let nt_create_thread = runtime.alloc_host_thunk(HostThunk::NtCreateThreadEx);
        let nt_resume = runtime.alloc_host_thunk(HostThunk::NtResumeThread);
        let nt_terminate_process = runtime.alloc_host_thunk(HostThunk::NtTerminateProcess);
        let handle_out = 0x41_000_u64;
        let thread_ptr = 0x42_000_u64;

        // Child A: suspended, then resumed → the host run starts.
        memory.map_bytes(handle_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                nt_create_process,
                &[handle_out as u32, 0x1F1FFF, 0, 0, 0, 0, 0, 0],
            ),
            0
        );
        let child = read_guest_pointer(&memory, handle_out, GuestArch::X86).unwrap() as u32;
        let child_pid = runtime
            .win32
            .process_state(child)
            .expect("child process")
            .process_id;
        memory.map_bytes(thread_ptr, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                nt_create_thread,
                &[
                    thread_ptr as u32,
                    0x1F03FF,
                    0,
                    child,
                    0x40_200,
                    0,
                    1, // create_suspended = TRUE
                    0,
                    0,
                    0x1000,
                ],
            ),
            0
        );
        let thread = read_guest_pointer(&memory, thread_ptr, GuestArch::X86).unwrap() as u32;
        let launch = runtime
            .trace_events
            .iter()
            .rev()
            .find(|event| event.call_id == "NtCreateThreadEx")
            .expect("NtCreateThreadEx trace");
        assert_eq!(
            launch
                .parameters
                .get("deferred")
                .and_then(|value| value.as_bool()),
            Some(true),
            "CREATE_SUSPENDED must defer the host launch"
        );
        assert_eq!(
            launch
                .parameters
                .get("host_launched")
                .and_then(|value| value.as_bool()),
            Some(false)
        );
        assert!(
            crate::runtime::dispatch::final_scraps::native_child_host_pid(
                runtime.guest_pid,
                child_pid
            )
            .is_none(),
            "no host child exists before the resume"
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            !marker.exists(),
            "a CREATE_SUSPENDED child must not run before resume"
        );
        let thread_id = runtime
            .win32
            .thread_id_for_handle(thread)
            .expect("thread record");
        assert_eq!(runtime.win32.thread_suspend_count(thread_id).unwrap(), 1);

        // Resume → the host run starts and genuinely executes the image.
        let prev_ptr = 0x43_000_u64;
        memory.map_bytes(prev_ptr, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                nt_resume,
                &[thread, prev_ptr as u32]
            ),
            0
        );
        assert_eq!(
            read_u32(&memory, prev_ptr).unwrap(),
            1,
            "the previous suspend count"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !marker.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(marker.exists(), "the resumed child must run its image");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut exit = None;
        while std::time::Instant::now() < deadline {
            if let Ok(crate::win32::WaitStatus::Object0) =
                runtime.win32.wait_for_single_object(child, 50, false, None)
            {
                exit = runtime.win32.get_exit_code_process(child).unwrap();
                break;
            }
        }
        assert_eq!(exit, Some(0));

        // Child B: suspended, terminated before resume → never launches.
        runtime.main_module_path = never_image.to_string();
        memory.map_bytes(handle_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                nt_create_process,
                &[handle_out as u32, 0x1F1FFF, 0, 0, 0, 0, 0, 0],
            ),
            0
        );
        let child_b = read_guest_pointer(&memory, handle_out, GuestArch::X86).unwrap() as u32;
        memory.map_bytes(thread_ptr, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                nt_create_thread,
                &[
                    thread_ptr as u32,
                    0x1F03FF,
                    0,
                    child_b,
                    0x40_200,
                    0,
                    1,
                    0,
                    0,
                    0x1000,
                ],
            ),
            0
        );
        let thread_b = read_guest_pointer(&memory, thread_ptr, GuestArch::X86).unwrap() as u32;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                nt_terminate_process,
                &[child_b, 9],
            ),
            0
        );
        assert_eq!(
            runtime.win32.get_exit_code_process(child_b).unwrap(),
            Some(9)
        );
        // A resume after the termination cannot launch anything.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, nt_resume, &[thread_b, 0]),
            0xC000_004A,
            "STATUS_THREAD_IS_TERMINATING"
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            !never.exists(),
            "a child terminated before resume must never launch"
        );
    })
}

#[test]
fn evidence_core_fiber_thunks_round_trip() {
    // The merged dispatch match (2000+ HostThunk arms) has a debug-build
    // stack frame larger than the default test-thread stack; run on the
    // 8 MiB big-stack thread like the other dispatch-heavy tests.
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-fibers");
        let mut memory = MemoryImage::default();
        let convert_thread = runtime.alloc_host_thunk(HostThunk::ConvertThreadToFiber);
        let switch_fiber = runtime.alloc_host_thunk(HostThunk::SwitchToFiber);
        let convert_fiber = runtime.alloc_host_thunk(HostThunk::ConvertFiberToThread);
        let delete_fiber = runtime.alloc_host_thunk(HostThunk::DeleteFiber);

        // ConvertThreadToFiber mints the primary fiber handle and tracks it
        // as the current fiber of this thread.
        let primary = dispatch_x86_thunk(&mut runtime, &mut memory, convert_thread, &[]);
        assert_ne!(primary, 0);
        // Switching to the current fiber round-trips (the manager records
        // the previous-fiber chain and the runtime saves/restores state).
        dispatch_x86_thunk(&mut runtime, &mut memory, switch_fiber, &[primary as u32]);
        assert_eq!(runtime.last_error, 0);
        // ConvertFiberToThread detaches the current fiber.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, convert_fiber, &[]),
            1
        );
        // DeleteFiber removes the current fiber (the thread-local tracker is
        // cleared so a stale handle can never be saved into).
        dispatch_x86_thunk(&mut runtime, &mut memory, delete_fiber, &[primary as u32]);
        assert_eq!(runtime.last_error, 0);
    })
}

#[test]
fn extended_process_information_reports_real_stack_bounds_and_refuses_short_or_unbacked() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("extended-process-info");
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
        let mut memory = MemoryImage::default();
        let teb = 0x69_000u64;
        let stack_limit = stack_base_for_arch(GuestArch::X64);
        let stack_base = stack_limit + STACK_SIZE as u64;
        memory.map_bytes(teb, &[0u8; 0x100]);
        write_u64(&mut memory, teb + 0x08, stack_base);
        write_u64(&mut memory, teb + 0x10, stack_limit);
        runtime.teb_base = teb;

        let query = runtime.alloc_host_thunk(HostThunk::NtQuerySystemInformation);
        let buffer = 0x6A_000u64;
        let length_ptr = 0x6B_000u64;
        memory.map_bytes(buffer, &[0u8; 0x2000]);
        memory.map_bytes(length_ptr, &[0u8; 8]);
        let status = dispatch_x64_thunk(
            &mut runtime,
            &mut memory,
            query,
            &[57, buffer, 0x2000, length_ptr],
        );
        assert_eq!(status, u64::from(crate::ntdll::STATUS_SUCCESS.raw()));
        let returned = memory.read_u64(length_ptr).expect("returned") as usize;
        assert!(returned >= 0x100 + 0x88);
        let mut entry = 0u64;
        loop {
            if memory.read_u64(buffer + entry + 0x50).expect("pid") == u64::from(runtime.guest_pid)
            {
                break;
            }
            let next = memory.read_u32(buffer + entry).expect("next") as u64;
            assert_ne!(next, 0, "the guest process must be in the array");
            entry += next;
        }
        assert_eq!(
            u32::from_le_bytes(
                memory
                    .read_bytes(buffer + entry + 4, 4)
                    .expect("thread count")
                    .try_into()
                    .unwrap()
            ),
            1,
            "the real thread table has one thread"
        );
        assert_eq!(
            memory
                .read_u64(buffer + entry + 0x100 + 0x50)
                .expect("stack base"),
            stack_base
        );
        assert_eq!(
            memory
                .read_u64(buffer + entry + 0x100 + 0x58)
                .expect("stack limit"),
            stack_limit
        );
        assert_eq!(
            memory.read_u64(buffer + entry + 0x100 + 0x68).expect("teb"),
            teb
        );
        assert_eq!(
            memory
                .read_u32(buffer + entry + 0x100 + 0x30)
                .expect("thread id"),
            runtime.win32.current_thread_id()
        );

        // A short buffer reports the exact requirement (extended thread
        // records, not the plain class-5 size).
        assert_eq!(
            dispatch_x64_thunk(
                &mut runtime,
                &mut memory,
                query,
                &[57, buffer, 0x100, length_ptr]
            ),
            u64::from(crate::ntdll::STATUS_INFO_LENGTH_MISMATCH.raw())
        );
        assert_eq!(
            memory.read_u64(length_ptr).expect("required"),
            returned as u64
        );

        // Without a backed StackLimit the query is refused, never zeroed.
        write_u64(&mut memory, teb + 0x10, 0);
        assert_eq!(
            dispatch_x64_thunk(
                &mut runtime,
                &mut memory,
                query,
                &[57, buffer, 0x2000, length_ptr]
            ),
            0xC000_00BB,
            "an unbacked extended field is STATUS_NOT_SUPPORTED"
        );
        write_u64(&mut memory, teb + 0x10, stack_limit);

        // The x86 guest uses the real 32-bit extended layout (verified
        // below), never the x64 layout with truncated pointers.
        let (mut x86, _temp_two) = test_runtime("extended-process-info-x86");
        let mut x86_memory = MemoryImage::default();
        let x86_query = x86.alloc_host_thunk(HostThunk::NtQuerySystemInformation);

        // The plain class still reports the x86 TEB stack bounds and the
        // real pending-thread table (both x86 and pending branches).
        let x86_teb = 0x70_000u64;
        let main_limit = 0x8000u64;
        let main_base = 0x9000u64;
        x86_memory.map_bytes(x86_teb, &[0u8; 0x100]);
        write_u32(&mut x86_memory, x86_teb + 0x04, main_base as u32);
        write_u32(&mut x86_memory, x86_teb + 0x08, main_limit as u32);
        x86.teb_base = x86_teb;
        let pending_teb = 0x71_000u64;
        x86_memory.map_bytes(pending_teb, &[0u8; 0x100]);
        write_u32(&mut x86_memory, pending_teb + 0x04, 0xA000);
        write_u32(&mut x86_memory, pending_teb + 0x08, 0x9000);
        let mut pending_state = CpuState::new(GuestArch::X86);
        pending_state.set(Register::Rsp, 0x9F00);
        x86.pending_guest_threads.push_back(PendingGuestThread {
            handle: 0x44,
            thread_id: 2,
            start_address: 0x401000,
            parameter: 0,
            initial_rsp: 0x9F00,
            started: false,
            suspended: 0,
            wake_tick: 0,
            teb_base: pending_teb,
            tls_vector_ptr: 0,
            tls_slots: BTreeMap::new(),
            fls_slots: BTreeMap::new(),
            state: pending_state,
            state_machine: GuestThreadState::Runnable,
            exit_code_override: None,
            wait: None,
            wait_resume: None,
        });
        x86_memory.map_bytes(buffer, &[0u8; 0x2000]);
        x86_memory.map_bytes(length_ptr, &[0u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut x86,
                &mut x86_memory,
                x86_query,
                &[5, buffer as u32, 0x2000, length_ptr as u32]
            ),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        let mut entry = 0u64;
        loop {
            if x86_memory.read_u64(buffer + entry + 0x50).expect("pid") == u64::from(x86.guest_pid)
            {
                break;
            }
            let next = x86_memory.read_u32(buffer + entry).expect("next") as u64;
            assert_ne!(next, 0, "the guest process must be in the array");
            entry += next;
        }
        assert_eq!(
            x86_memory
                .read_u32(buffer + entry + 4)
                .expect("thread count"),
            2,
            "the main and pending threads are both real"
        );

        // SystemExtendedProcessInformation(57) on x86: the 32-bit ABI has
        // a 0xB8-byte fixed process record and 0x60-byte extended thread
        // records; the extended tail carries the real x86 stack bounds and
        // TEB, and the ImageName pointer is a 32-bit guest pointer.
        x86_memory.map_bytes(buffer, &[0u8; 0x2000]);
        x86_memory.map_bytes(length_ptr, &[0u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut x86,
                &mut x86_memory,
                x86_query,
                &[57, buffer as u32, 0x2000, length_ptr as u32]
            ),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        let extended_len = x86_memory.read_u32(length_ptr).expect("required") as usize;
        assert!(extended_len >= 0xB8 + 2 * 0x60);
        let mut entry = 0u64;
        loop {
            if x86_memory.read_u32(buffer + entry + 0x44).expect("pid") == x86.guest_pid {
                break;
            }
            let next = x86_memory.read_u32(buffer + entry).expect("next") as u64;
            assert_ne!(next, 0, "the guest process must be in the x86 array");
            entry += next;
        }
        assert_eq!(
            x86_memory
                .read_u32(buffer + entry + 4)
                .expect("thread count"),
            2
        );
        assert_eq!(
            x86_memory
                .read_u32(buffer + entry + 0xB8 + 0x40)
                .expect("stack base"),
            main_base as u32
        );
        assert_eq!(
            x86_memory
                .read_u32(buffer + entry + 0xB8 + 0x44)
                .expect("stack limit"),
            main_limit as u32
        );
        assert_eq!(
            x86_memory
                .read_u32(buffer + entry + 0xB8 + 0x4C)
                .expect("teb"),
            x86_teb as u32
        );
        assert_eq!(
            x86_memory
                .read_u32(buffer + entry + 0xB8 + 0x24)
                .expect("thread id"),
            x86.win32.current_thread_id()
        );
        assert_eq!(
            x86_memory
                .read_u32(buffer + entry + 0xB8 + 0x60 + 0x40)
                .expect("pending stack base"),
            0xA000
        );
        assert_eq!(
            x86_memory
                .read_u32(buffer + entry + 0xB8 + 0x60 + 0x44)
                .expect("pending stack limit"),
            0x9000
        );
        assert_eq!(
            x86_memory
                .read_u32(buffer + entry + 0xB8 + 0x60 + 0x4C)
                .expect("pending teb"),
            pending_teb as u32
        );
        let name_len = x86_memory
            .read_u16(buffer + entry + 0x38)
            .expect("name length");
        let name_ptr = x86_memory
            .read_u32(buffer + entry + 0x3C)
            .expect("name ptr");
        assert_eq!(
            name_ptr as u64,
            buffer + entry + 0xB8 + 2 * 0x60,
            "the x86 ImageName.Buffer is the 32-bit in-buffer pointer"
        );
        assert_eq!(
            name_len as usize,
            x86.main_module_name.encode_utf16().count() * 2
        );

        // A short x86 buffer reports the exact 32-bit requirement.
        assert_eq!(
            dispatch_x86_thunk(
                &mut x86,
                &mut x86_memory,
                x86_query,
                &[57, buffer as u32, 0xB7, length_ptr as u32]
            ),
            u64::from(crate::ntdll::STATUS_INFO_LENGTH_MISMATCH.raw())
        );
        assert_eq!(
            x86_memory.read_u32(length_ptr).expect("required"),
            extended_len as u32
        );

        // An unbacked extended field is refused, never zeroed.
        write_u32(&mut x86_memory, x86_teb + 0x08, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut x86,
                &mut x86_memory,
                x86_query,
                &[57, buffer as u32, 0x2000, length_ptr as u32]
            ),
            0xC000_00BB,
            "an unbacked x86 extended field is STATUS_NOT_SUPPORTED"
        );
    })
}
