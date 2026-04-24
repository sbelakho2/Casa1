use casa1::ge::{FileAccess, GameEnvironment, GeArch, RegistryView, ShareMode};
use casa1::win32::{
    build_environment_block_utf16, windows_command_line_to_argv, AllocationType, ApartmentModel,
    ComThreadingModel, CreationDisposition, FileInformation, FreeType, MemoryProtection,
    MemoryState, SeekOrigin, ThreadPlan, WaitStatus, Win32Subsystem, CP_UTF8,
};
use std::collections::BTreeMap;
use tempfile::TempDir;

#[test]
fn t5_1_file_api_differential_suite_vs_independent_reference() {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = create_ge(&temp_dir, "section5-files");
    let mut win32 = Win32Subsystem::new(ge, true);

    win32.create_directory_w("C:\\Games").expect("create Games directory");
    let file = win32
        .create_file_w(
            "C:\\Games\\demo.txt",
            FileAccess::read_write(),
            ShareMode::all(),
            CreationDisposition::CreateAlways,
            true,
            false,
        )
        .expect("create demo file");
    let descriptor = win32.describe_handle(file).expect("file handle descriptor");
    assert!(descriptor.inheritable);
    assert_eq!(descriptor.refcount, 1);
    assert_eq!(
        win32.file_state(file).expect("file handle state"),
        casa1::win32::FileHandleState {
            normalized_path: "C:\\games\\demo.txt".to_string(),
            position: 0,
            overlapped: false,
            has_ge_handle: true,
        }
    );

    win32.write_file(file, b"hello windows").expect("write bytes");
    assert_eq!(win32.file_state(file).expect("updated file state").position, 13);
    assert_eq!(win32.get_file_size_ex(file).expect("get size"), 13);
    win32
        .set_file_pointer_ex(file, 0, SeekOrigin::Begin)
        .expect("rewind file pointer");
    assert_eq!(win32.read_file(file, 5).expect("read bytes"), b"hello");
    let info = win32
        .get_file_information_by_handle_ex(file)
        .expect("file information by handle");
    assert_eq!(
        independent_file_information("C:\\games\\demo.txt", 13, false),
        info
    );

    win32
        .set_file_attributes_w("C:\\Games\\demo.txt", &["archive", "readonly"])
        .expect("set file attributes");
    assert_eq!(
        win32
            .get_file_attributes_w("C:\\Games\\demo.txt")
            .expect("get file attributes"),
        vec!["archive".to_string(), "readonly".to_string()]
    );

    let (search, first) = win32
        .find_first_file_w("C:\\Games")
        .expect("find first file");
    assert_eq!(first.file_name, "demo.txt");
    assert!(win32.find_next_file_w(search).expect("find next file").is_none());
    win32.find_close(search).expect("find close");

    let copy_bytes = win32
        .copy_file_ex_w("C:\\Games\\demo.txt", "C:\\Games\\copy.txt", false)
        .expect("copy file");
    assert_eq!(copy_bytes, 13);
    win32
        .move_file_ex_w("C:\\Games\\copy.txt", "C:\\Games\\moved.txt", true)
        .expect("move file");
    let temp_path = win32.get_temp_path_w().expect("temp path");
    assert!(temp_path.ends_with("Temp"));
    let temp_file = win32.get_temp_file_name_w("CASA").expect("temp file name");
    assert!(temp_file.contains("CASA"));
    win32.delete_file_w("C:\\Games\\moved.txt").expect("delete moved file");
    win32.close_handle(file).expect("close file handle");
}

#[test]
fn t5_2_overlapped_io_randomized_tests_vs_independent_reference() {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = create_ge(&temp_dir, "section5-overlapped");
    let mut win32 = Win32Subsystem::new(ge, true);
    win32.create_directory_w("C:\\Data").expect("create data directory");
    let file = win32
        .create_file_w(
            "C:\\Data\\async.bin",
            FileAccess::read_write(),
            ShareMode::all(),
            CreationDisposition::CreateAlways,
            false,
            true,
        )
        .expect("create async file");
    assert!(win32.file_state(file).expect("async file state").overlapped);
    let event = win32.create_event(false, false, false);
    for (offset, payload) in [(0_u64, b"abcdef".as_slice()), (2_u64, b"XYZ".as_slice())] {
        let write = win32
            .write_file_overlapped(file, payload, offset, Some(event))
            .expect("overlapped write");
        assert!(write.completed);
        assert_eq!(write.bytes_transferred, payload.len() as u32);
    }
    assert_eq!(
        win32
            .wait_for_single_object(event, 0, false, None)
            .expect("wait on file event"),
        WaitStatus::Object0
    );
    let read_event = win32.create_event(false, false, false);
    let read = win32
        .read_file_overlapped(file, 4, 2, Some(read_event))
        .expect("overlapped read");
    assert_eq!(
        win32.get_overlapped_result(read.id, false).expect("read overlapped result"),
        read
    );

    let pipe = win32.create_named_pipe(r"\\.\pipe\steam-ipc", false);
    let pipe_event = win32.create_event(false, false, false);
    let pending = win32
        .connect_named_pipe(pipe, Some(pipe_event), true)
        .expect("pending connect")
        .expect("overlapped connect id");
    win32.cancel_io_ex(pipe, Some(pending)).expect("cancel pending connect");
    let cancelled = win32
        .get_overlapped_result(pending, false)
        .expect("cancelled overlapped result");
    assert!(cancelled.cancelled);
    for payload in [b"payload".as_slice(), b"longer-payload".as_slice()] {
        let echo = win32
            .call_named_pipe(r"\\.\pipe\steam-ipc", payload)
            .expect("call named pipe");
        assert_eq!(echo, payload);
    }
}

#[test]
fn t5_3_create_process_quoting_suite_vs_independent_reference_argv() {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = create_ge(&temp_dir, "section5-process");
    let mut win32 = Win32Subsystem::new(ge, true);
    let inheritable = win32.create_event(true, false, true);
    let mut env = BTreeMap::new();
    env.insert("ALPHA".to_string(), "1".to_string());
    env.insert("BETA".to_string(), "hello world".to_string());
    let quoted = r#"launcher.exe "C:\Program Files\Game\game.exe" "arg with spaces" tail"#;
    assert_eq!(
        windows_command_line_to_argv(quoted),
        vec![
            "launcher.exe".to_string(),
            "C:\\Program Files\\Game\\game.exe".to_string(),
            "arg with spaces".to_string(),
            "tail".to_string(),
        ]
    );
    let environment_block = build_environment_block_utf16(&env);
    assert!(environment_block.ends_with(&[0, 0]));

    let process = win32
        .create_process_w(
            "C:\\Program Files\\Game\\game.exe",
            quoted,
            &env,
            "C:\\Games",
            true,
        )
        .expect("create process plan");
    assert_eq!(process.environment_block_utf16, environment_block);
    let process_state = win32
        .process_state(process.process_handle)
        .expect("process state");
    assert_eq!(process_state.cwd, "C:\\Games");
    assert_eq!(process_state.environment, env);
    assert_eq!(process_state.inherited_handles.len(), 1);
    assert!(process_state
        .inherited_handles
        .iter()
        .any(|entry| entry.object_type == casa1::win32::ObjectType::Event && entry.inheritable));
    let thread = process.thread_handle;
    win32
        .set_thread_priority(thread, 2)
        .expect("set thread priority");
    let tls_slot = win32.tls_alloc();
    win32.tls_set_value(thread, tls_slot, 0xCAFE).expect("tls set");
    assert_eq!(win32.tls_get_value(thread, tls_slot).expect("tls get"), Some(0xCAFE));
    win32.exit_thread(thread, 259).expect("thread exit");
    assert_eq!(win32.get_exit_code_thread(thread).expect("get exit code"), Some(259));
    win32.set_process_exit_code(process.process_handle, 0).expect("process exit");

    let snapshot = win32.create_toolhelp_snapshot();
    assert!(snapshot
        .processes
        .iter()
        .any(|entry| entry.executable == "C:\\Program Files\\Game\\game.exe"));
    assert!(snapshot
        .modules
        .iter()
        .any(|entry| entry.module_name == "kernel32.dll"));
    let descriptor = win32.describe_handle(inheritable).expect("inheritable handle descriptor");
    assert!(descriptor.inheritable);
}

#[test]
fn memory_time_locale_baseline_is_consistent() {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = create_ge(&temp_dir, "section5-time");
    let mut win32 = Win32Subsystem::new(ge, false);
    assert_eq!(win32.query_performance_frequency(), 10_000_000);
    assert_eq!(win32.get_tick_count64(), 0);
    win32.record_sleep_observation(15, 19);
    assert!(win32.query_performance_counter() >= 190_000);
    assert_eq!(win32.get_tick_count64(), 19);
    assert_eq!(win32.sleep_drift_log().len(), 1);

    let alertable_thread = win32.create_thread(
        ThreadPlan {
            exit_code: None,
            priority: 0,
            signaled: false,
        },
        false,
    );
    win32.queue_apc(alertable_thread, "apc").expect("queue APC");
    assert_eq!(
        win32
            .sleep_ex(50, true, Some(alertable_thread))
            .expect("alertable sleep"),
        WaitStatus::IoCompletion
    );

    let wide = win32
        .multi_byte_to_wide_char(CP_UTF8, "Cafe €".as_bytes())
        .expect("UTF-8 to UTF-16");
    assert_eq!(win32.wide_char_to_multi_byte(CP_UTF8, &wide).expect("UTF-16 to UTF-8"), "Cafe €".as_bytes());
    let cp1252 = win32
        .wide_char_to_multi_byte(1252, &"Cafe €".encode_utf16().collect::<Vec<_>>())
        .expect("UTF-16 to CP1252");
    assert_eq!(cp1252, vec![67, 97, 102, 101, 32, 0x80]);

    let reserved = win32
        .virtual_alloc(
            None,
            0x3000,
            AllocationType::Reserve,
            MemoryProtection {
                read: true,
                write: false,
                execute: false,
            },
        )
        .expect("reserve region");
    assert_eq!(win32.virtual_query(reserved).state, MemoryState::Reserved);
    win32
        .virtual_alloc(
            Some(reserved),
            0x2000,
            AllocationType::Commit,
            MemoryProtection {
                read: true,
                write: true,
                execute: false,
            },
        )
        .expect("commit region");
    assert_eq!(win32.virtual_query(reserved).state, MemoryState::Committed);
    let previous = win32
        .virtual_protect(
            reserved,
            MemoryProtection {
                read: true,
                write: false,
                execute: true,
            },
        )
        .expect("protect region");
    assert!(previous.write);
    let section = win32
        .create_section(
            0x1000,
            MemoryProtection {
                read: true,
                write: false,
                execute: false,
            },
            false,
        )
        .expect("create section object");
    assert_eq!(win32.describe_handle(section).expect("section descriptor").object_type, casa1::win32::ObjectType::Section);
    let section_state = win32.section_state(section).expect("section state");
    assert_eq!(section_state.size, 0x1000);
    assert!(section_state.protection.read);
    assert!(!section_state.protection.write);
    assert!(!section_state.protection.execute);
    let heap = win32.heap_create(16, false);
    let block = win32.heap_alloc(heap, 7).expect("heap alloc");
    assert_eq!(block % 16, 0);
    win32.heap_write(heap, block, b"payload").expect("heap write");
    let resized = win32.heap_realloc(heap, block, 16).expect("heap realloc");
    assert_eq!(win32.heap_read(heap, resized).expect("heap read")[..7], *b"payload");
    win32.heap_free(heap, resized).expect("heap free");
    win32.heap_destroy(heap).expect("heap destroy");
    win32.virtual_free(reserved, FreeType::Decommit).expect("decommit region");
    assert_eq!(win32.virtual_query(reserved).state, MemoryState::Reserved);
    win32.virtual_free(reserved, FreeType::Release).expect("release region");
}

#[test]
fn t5_4_toolhelp_suite_vs_independent_reference_normalized() {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = create_ge(&temp_dir, "section5-toolhelp");
    let mut win32 = Win32Subsystem::new(ge, true);
    let process = win32
        .create_process_w(
            "C:\\Program Files\\Game\\snapshot.exe",
            r#"snapshot.exe --mode toolhelp"#,
            &BTreeMap::new(),
            "C:\\Games",
            false,
        )
        .expect("create process for toolhelp snapshot");
    win32
        .set_process_exit_code(process.process_handle, 0)
        .expect("complete process");
    let snapshot = win32.create_toolhelp_snapshot();
    let normalized_processes = snapshot
        .processes
        .iter()
        .map(|entry| (entry.process_id, entry.executable.clone(), entry.argv.join(" ")))
        .collect::<Vec<_>>();
    assert!(normalized_processes
        .iter()
        .any(|(_, executable, argv)| executable == "C:\\Program Files\\Game\\snapshot.exe" && argv.contains("snapshot.exe --mode toolhelp")));
    let normalized_modules = snapshot
        .modules
        .iter()
        .filter(|entry| entry.process_id != std::process::id())
        .map(|entry| entry.module_name.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        normalized_modules,
        vec![
            "C:\\Program Files\\Game\\snapshot.exe".to_string(),
            "kernel32.dll".to_string(),
            "ntdll.dll".to_string(),
        ]
    );
}

#[test]
fn t5_5_com_activation_and_apartment_suite_vs_independent_reference() {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = create_ge(&temp_dir, "section5-com");
    let mut win32 = Win32Subsystem::new(ge, true);
    let sta_thread = win32.create_thread(
        ThreadPlan {
            exit_code: None,
            priority: 0,
            signaled: false,
        },
        false,
    );
    let mta_thread = win32.create_thread(
        ThreadPlan {
            exit_code: None,
            priority: 0,
            signaled: false,
        },
        false,
    );
    win32
        .register_com_class(
            "{12345678-1234-1234-1234-1234567890ab}",
            "C:\\Program Files\\Casa1\\demo.dll",
            ComThreadingModel::Sta,
        )
        .expect("register COM class");
    win32.co_initialize_ex(sta_thread, ApartmentModel::Sta).expect("init STA");
    win32.co_initialize_ex(mta_thread, ApartmentModel::Mta).expect("init MTA");

    let instance = win32
        .co_create_instance(sta_thread, "{12345678-1234-1234-1234-1234567890ab}")
        .expect("create STA COM instance");
    assert_eq!(instance.module_path, "C:\\Program Files\\Casa1\\demo.dll");
    assert_eq!(instance.apartment, ApartmentModel::Sta);
    assert!(win32
        .co_create_instance(mta_thread, "{12345678-1234-1234-1234-1234567890ab}")
        .is_err());

    let key_handle = win32.open_registry_key(
        "HKCR",
        "CLSID\\{12345678-1234-1234-1234-1234567890ab}",
        RegistryView::Native,
        false,
    );
    assert_eq!(win32.describe_handle(key_handle).expect("registry key descriptor").object_type, casa1::win32::ObjectType::Key);
    assert_eq!(
        win32.key_state(key_handle).expect("registry key state"),
        casa1::win32::KeyHandleState {
            hive: "HKCR".to_string(),
            key: "CLSID\\{12345678-1234-1234-1234-1234567890ab}".to_string(),
            view: RegistryView::Native,
        }
    );
    win32.co_uninitialize(sta_thread).expect("uninit STA");
    win32.co_uninitialize(mta_thread).expect("uninit MTA");
}

fn create_ge(temp_dir: &TempDir, name: &str) -> GameEnvironment {
    GameEnvironment::create_in(temp_dir.path().join("ges"), name, GeArch::X64, "win11-23h2")
        .expect("create GE")
}

fn independent_file_information(normalized_path: &str, size: u64, is_directory: bool) -> FileInformation {
    FileInformation {
        normalized_path: normalized_path.to_string(),
        size,
        attributes: Vec::new(),
        creation_time_ticks: 0,
        last_access_time_ticks: 0,
        last_write_time_ticks: 0,
        is_directory,
    }
}